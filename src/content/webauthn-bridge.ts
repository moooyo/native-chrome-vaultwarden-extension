// Runs in the isolated content-script world. This module owns one long-lived, document-bound runtime
// Port and relays only canonical public WebAuthn data between the MAIN-world shim and the background
// coordinator. It never calls vault request APIs and never renders page-hosted consent UI.

import browser from 'webextension-polyfill';
import {
  parsePasskeyCeremonyResultSnapshot,
  parseWebsitePasskeyConfigChangedMessage,
  parseWebsitePasskeyClientMessage,
  parseWebsitePasskeyServerMessage,
  serializeCanonicalWebsitePasskeyRequest,
  WEBSITE_PASSKEY_PORT_NAME,
  WEBSITE_PASSKEY_PORT_VERSION,
  type CanonicalWebsitePasskeyRequest,
  type WebsitePasskeyAcceptedMessage,
  type WebsitePasskeyClientMessage,
  type WebsitePasskeyConditionalActiveMessage,
  type WebsitePasskeyConfigChangedAck,
  type WebsitePasskeyOutcomeMessage,
  type WebsitePasskeyPreflightOutcomeMessage,
  type WebsitePasskeyServerMessage,
  type WebsitePasskeyUnlockPendingMessage,
} from '../messaging/website-passkey-port.js';
import {
  createWebsitePasskeyConditionalUi,
  type WebsitePasskeyConditionalUi,
} from './conditional-passkey-ui.js';
import {
  WEBSITE_PASSKEY_BRIDGE_SOURCE,
  WEBSITE_PASSKEY_PAGE_SOURCE,
  WEBSITE_PASSKEY_WINDOW_VERSION,
  type WebsitePasskeyBridgeConfigMessage,
} from './website-passkey-feature.js';
import { WebsitePasskeyIframeReporter } from './website-passkey-iframe-reporter.js';
import {
  answerWebsitePasskeyFeaturePolicyProbe,
  type WebsitePasskeyFeaturePolicyResponder,
} from './website-passkey-feature-policy.js';
import type {
  WebsitePasskeyFeaturePolicyProbeResponse,
} from '../messaging/website-passkey-feature-policy.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BRIDGE_SENTINEL = Symbol.for('miyu.websitePasskey.isolatedBridge.v1');
const INITIAL_RECONNECT_DELAY_MS = 250;
const MAX_RECONNECT_DELAY_MS = 5_000;
const DELIVERY_TOMBSTONE_MS = 120_000;
const MAX_ACTIVE_REQUESTS = 16;
const MAX_TRACKED_REQUESTS = 64;

export interface WebsitePasskeyPortEvent<Listener> {
  addListener(listener: Listener): void;
  removeListener?(listener: Listener): void;
}

export interface WebsitePasskeyPort {
  readonly onMessage: WebsitePasskeyPortEvent<(message: unknown) => void>;
  readonly onDisconnect: WebsitePasskeyPortEvent<() => void>;
  postMessage(message: WebsitePasskeyClientMessage): void;
  disconnect(): void;
}

export interface WebsitePasskeyBridgeTimers {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface WebsitePasskeyBridgeDependencies {
  connectPort(name: typeof WEBSITE_PASSKEY_PORT_NAME): WebsitePasskeyPort;
  subscribeRuntimeMessages?(
    listener: (message: unknown) => WebsitePasskeyRuntimeResponse | undefined,
  ): () => void;
  timers?: WebsitePasskeyBridgeTimers;
  now?: () => number;
  conditionalUi?: WebsitePasskeyConditionalUi;
  reportIframeInventory?(request: unknown): unknown | PromiseLike<unknown>;
  answerFeaturePolicyProbe?: WebsitePasskeyFeaturePolicyResponder;
}

export type WebsitePasskeyRuntimeResponse =
  | WebsitePasskeyConfigChangedAck
  | WebsitePasskeyFeaturePolicyProbeResponse;

interface ActivePort {
  readonly port: WebsitePasskeyPort;
  readonly generation: number;
  readonly onMessage: (message: unknown) => void;
  readonly onDisconnect: () => void;
  configured: boolean;
}

interface PendingBridgeRequest {
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly serialized: string;
  readonly deadlineAt: number;
  readonly expiresAt: number;
  accepted?: WebsitePasskeyAcceptedMessage;
  unlockPending?: WebsitePasskeyUnlockPendingMessage;
  conditionalSerialized?: string;
  preflight?: WebsitePasskeyPreflightOutcomeMessage;
  preflightSerialized?: string;
  outcome?: WebsitePasskeyOutcomeMessage;
  outcomeSerialized?: string;
  boundGeneration?: number;
  beginSent: boolean;
  cancelled: boolean;
  pageSettled: boolean;
  delivered: boolean;
  cleanupTimer?: unknown;
  conditionalUiTimer?: unknown;
}

type ParsedPageMessage =
  | { readonly type: 'begin'; readonly request: CanonicalWebsitePasskeyRequest }
  | { readonly type: 'cancel'; readonly bridgeRequestId: string; readonly settled: boolean }
  | {
      readonly type: 'delivered';
      readonly ceremonyId: string;
      readonly bridgeRequestId: string;
      readonly outcomeId: string;
    };

const DEFAULT_TIMERS: WebsitePasskeyBridgeTimers = Object.freeze({
  setTimeout(callback: () => void, delayMs: number): unknown {
    return globalThis.setTimeout(callback, delayMs);
  },
  clearTimeout(handle: unknown): void {
    globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
});

export class WebsitePasskeyBridge {
  readonly #timers: WebsitePasskeyBridgeTimers;
  readonly #now: () => number;
  readonly #conditionalUi: WebsitePasskeyConditionalUi;
  readonly #iframeReporter: WebsitePasskeyIframeReporter | undefined;
  readonly #requests = new Map<string, PendingBridgeRequest>();
  readonly #onWindowMessage = (event: MessageEvent): void => this.#handleWindowMessage(event);
  readonly #onRuntimeMessage = (message: unknown): WebsitePasskeyRuntimeResponse | undefined => {
    if (isConfigChangedMessage(message)) {
      this.refreshConfig();
      return { websitePasskey: true };
    }
    return (this.dependencies.answerFeaturePolicyProbe
      ?? answerWebsitePasskeyFeaturePolicyProbe)(message);
  };
  #activePort: ActivePort | undefined;
  #reconnectTimer: unknown;
  #reconnectDelay = INITIAL_RECONNECT_DELAY_MS;
  #generation = 0;
  #started = false;
  #disposed = false;
  #enabled = false;
  #unsubscribeRuntimeMessages: (() => void) | undefined;

  constructor(private readonly dependencies: WebsitePasskeyBridgeDependencies) {
    this.#timers = dependencies.timers ?? DEFAULT_TIMERS;
    this.#now = dependencies.now ?? Date.now;
    this.#conditionalUi = dependencies.conditionalUi ?? createWebsitePasskeyConditionalUi();
    this.#iframeReporter = dependencies.reportIframeInventory
      ? new WebsitePasskeyIframeReporter({ report: dependencies.reportIframeInventory })
      : undefined;
  }

  start(): void {
    if (this.#started || this.#disposed) return;
    this.#started = true;
    window.addEventListener('message', this.#onWindowMessage);
    this.#iframeReporter?.start();
    try {
      this.#unsubscribeRuntimeMessages = this.dependencies.subscribeRuntimeMessages?.(
        this.#onRuntimeMessage,
      );
    } catch {
      this.#unsubscribeRuntimeMessages = undefined;
    }
    if (!isSupportedDocument()) {
      this.#postConfig(false);
      return;
    }
    this.#connect();
  }

  stop(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#enabled = false;
    window.removeEventListener('message', this.#onWindowMessage);
    try { this.#unsubscribeRuntimeMessages?.(); } catch { /* Subscription teardown is best effort. */ }
    this.#unsubscribeRuntimeMessages = undefined;
    if (this.#reconnectTimer !== undefined) this.#timers.clearTimeout(this.#reconnectTimer);
    this.#reconnectTimer = undefined;
    const active = this.#activePort;
    this.#activePort = undefined;
    if (active) {
      removePortListener(active.port.onMessage, active.onMessage);
      removePortListener(active.port.onDisconnect, active.onDisconnect);
      try { active.port.disconnect(); } catch { /* The Port may already be closed. */ }
    }
    for (const request of this.#requests.values()) {
      this.#clearConditionalUi(request);
      this.#clearRequestTimer(request);
    }
    this.#requests.clear();
    this.#conditionalUi.dispose();
    this.#iframeReporter?.stop();
    this.#postConfig(false);
    clearBridgeSentinel(this);
  }

  refreshConfig(): void {
    if (this.#disposed) return;
    this.#iframeReporter?.forceRefresh();
    const active = this.#activePort;
    if (active) {
      this.#postPort(active, { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' });
      return;
    }
    this.#connect();
  }

  #connect(): void {
    if (this.#disposed || !this.#started || this.#activePort || !isSupportedDocument()) return;
    if (this.#reconnectTimer !== undefined) {
      this.#timers.clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = undefined;
    }

    let port: WebsitePasskeyPort;
    try {
      port = this.dependencies.connectPort(WEBSITE_PASSKEY_PORT_NAME);
    } catch {
      this.#scheduleReconnect();
      return;
    }
    const generation = ++this.#generation;
    const onMessage = (message: unknown): void => this.#handlePortMessage(generation, message);
    const onDisconnect = (): void => this.#handleDisconnect(generation);
    const active: ActivePort = { port, generation, onMessage, onDisconnect, configured: false };
    this.#activePort = active;
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    if (!this.#postPort(active, { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' })) {
      this.#losePort(active);
    }
  }

  #handlePortMessage(generation: number, value: unknown): void {
    const active = this.#activePort;
    if (!active || active.generation !== generation || this.#disposed) return;
    let message: WebsitePasskeyServerMessage;
    try { message = parseWebsitePasskeyServerMessage(value); } catch {
      this.#failPort(active);
      return;
    }
    if (!hasStrictServerIds(message)) {
      this.#failPort(active);
      return;
    }

    if (message.type === 'config') {
      active.configured = true;
      this.#reconnectDelay = INITIAL_RECONNECT_DELAY_MS;
      this.#enabled = message.enabled;
      this.#iframeReporter?.forceRefresh();
      this.#postConfig(message.enabled);
      this.#recoverRequests(active, message.enabled);
      return;
    }
    if (!active.configured) {
      this.#failPort(active);
      return;
    }
    if (message.type === 'preflightOutcome') this.#handlePreflightOutcome(active, message);
    else if (message.type === 'unlockPending') this.#handleUnlockPending(active, message);
    else if (message.type === 'accepted') this.#handleAccepted(active, message);
    else if (message.type === 'conditionalActive') this.#handleConditionalActive(active, message);
    else this.#handleOutcome(active, message);
  }

  #handlePreflightOutcome(
    active: ActivePort,
    message: WebsitePasskeyPreflightOutcomeMessage,
  ): void {
    const request = this.#requests.get(message.bridgeRequestId);
    if (!request) return;
    const serialized = JSON.stringify(message);
    if (request.preflight && request.preflightSerialized !== serialized) {
      this.#failPort(active);
      return;
    }
    request.preflight = message;
    request.preflightSerialized = serialized;
    delete request.unlockPending;
    delete request.boundGeneration;
    this.#clearConditionalUi(request);
    this.#postToPage(message);
    this.#scheduleTombstoneCleanup(request);
  }

  #handleUnlockPending(
    active: ActivePort,
    message: WebsitePasskeyUnlockPendingMessage,
  ): void {
    const request = this.#requests.get(message.bridgeRequestId);
    if (!request || request.preflight || request.accepted || request.outcome) {
      this.#failPort(active);
      return;
    }
    if (request.unlockPending
        && (request.unlockPending.continuationId !== message.continuationId
          || request.unlockPending.deadlineAt !== message.deadlineAt)) {
      this.#failPort(active);
      return;
    }
    request.unlockPending = message;
    request.boundGeneration = active.generation;
    if (request.cancelled) {
      if (!request.pageSettled && !request.delivered) this.#postToPage(message);
      this.#postCancel(active, request);
      return;
    }
    if (!request.delivered) this.#postToPage(message);
  }

  #handleAccepted(active: ActivePort, message: WebsitePasskeyAcceptedMessage): void {
    const request = this.#requests.get(message.bridgeRequestId);
    if (!request) return;
    if (request.preflight) {
      this.#failPort(active);
      return;
    }
    if (request.unlockPending) {
      if (request.unlockPending.continuationId !== message.ceremonyId
          || request.unlockPending.deadlineAt !== message.deadlineAt) {
        this.#failPort(active);
        return;
      }
      delete request.unlockPending;
    }
    if (request.accepted) {
      if (
        request.accepted.ceremonyId !== message.ceremonyId
        || request.accepted.deadlineAt !== message.deadlineAt
      ) {
        this.#failPort(active);
        return;
      }
    } else {
      request.accepted = message;
    }
    request.boundGeneration = active.generation;
    if (request.outcome && request.outcome.ceremonyId !== message.ceremonyId) {
      this.#failPort(active);
      return;
    }
    if (request.cancelled) {
      if (!request.pageSettled && !request.outcome && !request.delivered) this.#postToPage(message);
      this.#postCancel(active, request);
      return;
    }
    if (!request.outcome && !request.delivered) this.#postToPage(message);
  }

  #handleConditionalActive(
    active: ActivePort,
    message: WebsitePasskeyConditionalActiveMessage,
  ): void {
    const request = this.#requests.get(message.bridgeRequestId);
    if (!request
        || request.request.kind !== 'get'
        || request.request.mediation !== 'conditional') {
      this.#failPort(active);
      return;
    }
    const serialized = JSON.stringify(message);
    if (request.conditionalSerialized && request.conditionalSerialized !== serialized) {
      this.#failPort(active);
      return;
    }
    request.conditionalSerialized = serialized;
    this.#handleAccepted(active, {
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'accepted',
      ceremonyId: message.ceremonyId,
      bridgeRequestId: message.bridgeRequestId,
      deadlineAt: message.deadlineAt,
    });
    if (this.#activePort !== active || request.cancelled || request.outcome || request.delivered) return;
    this.#scheduleConditionalUiTimeout(request, message.deadlineAt);
    this.#conditionalUi.activate(message, (credentialId) => {
      const current = this.#requests.get(message.bridgeRequestId);
      const port = this.#activePort;
      if (current !== request
          || current.cancelled
          || current.outcome
          || current.delivered
          || !port?.configured
          || current.boundGeneration !== port.generation
          || !message.candidates.some((candidate) => candidate.id === credentialId)) return;
      this.#clearConditionalUi(request);
      this.#postPort(port, {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'conditionalSelect',
        ceremonyId: message.ceremonyId,
        bridgeRequestId: message.bridgeRequestId,
        credentialId,
      });
    });
  }

  #handleOutcome(active: ActivePort, message: WebsitePasskeyOutcomeMessage): void {
    const request = this.#requests.get(message.bridgeRequestId);
    if (!request || (request.accepted && request.accepted.ceremonyId !== message.ceremonyId)) return;
    try {
      if (message.outcome.status === 'success') {
        parsePasskeyCeremonyResultSnapshot(message.outcome.result, request.request.kind);
      }
    } catch {
      this.#failPort(active);
      return;
    }

    const serialized = JSON.stringify(message);
    if (request.outcome) {
      if (request.outcomeSerialized !== serialized) {
        this.#failPort(active);
        return;
      }
    } else {
      request.outcome = message;
      request.outcomeSerialized = serialized;
    }
    request.boundGeneration = active.generation;
    this.#clearConditionalUi(request);

    if (request.pageSettled || request.delivered) {
      request.delivered = true;
      this.#postAck(active, request);
      this.#scheduleTombstoneCleanup(request);
      return;
    }
    this.#postToPage(message);
  }

  #handleDisconnect(generation: number): void {
    const active = this.#activePort;
    if (!active || active.generation !== generation) return;
    this.#losePort(active);
  }

  #losePort(active: ActivePort): void {
    if (this.#activePort !== active) return;
    this.#detachPort(active);
    this.#scheduleReconnect();
  }

  #failPort(active: ActivePort): void {
    if (this.#activePort !== active) return;
    this.#detachPort(active);
    this.#enabled = false;
    this.#postConfig(false);
    try { active.port.disconnect(); } catch { /* Teardown above is authoritative. */ }
    this.#scheduleReconnect();
  }

  #detachPort(active: ActivePort): void {
    if (this.#activePort !== active) return;
    this.#activePort = undefined;
    for (const request of this.#requests.values()) this.#clearConditionalUi(request);
    removePortListener(active.port.onMessage, active.onMessage);
    removePortListener(active.port.onDisconnect, active.onDisconnect);
  }

  #scheduleReconnect(): void {
    if (this.#disposed || this.#reconnectTimer !== undefined || !isSupportedDocument()) return;
    const delay = this.#reconnectDelay;
    this.#reconnectDelay = Math.min(MAX_RECONNECT_DELAY_MS, delay * 2);
    this.#reconnectTimer = this.#timers.setTimeout(() => {
      this.#reconnectTimer = undefined;
      this.#connect();
    }, delay);
  }

  #recoverRequests(active: ActivePort, enabled: boolean): void {
    const now = this.#now();
    for (const [bridgeRequestId, request] of this.#requests) {
      if (request.expiresAt <= now) {
        this.#deleteRequest(bridgeRequestId, request);
        continue;
      }
      if (request.preflight) {
        this.#postToPage(request.preflight);
      } else if (request.outcome && request.boundGeneration === active.generation) {
        if (request.delivered || request.pageSettled) this.#postAck(active, request);
        else this.#postToPage(request.outcome);
      } else if (request.beginSent) {
        this.#postResume(active, request);
      } else if (Math.min(request.deadlineAt, request.accepted?.deadlineAt ?? Infinity) <= now) {
        this.#deleteRequest(bridgeRequestId, request);
      } else if (!enabled) {
        this.#postResume(active, request);
      } else {
        this.#postBegin(active, request);
      }
    }
  }

  #handleWindowMessage(event: MessageEvent): void {
    if (this.#disposed || event.source !== window || event.origin !== location.origin) return;
    const message = parsePageMessage(event.data);
    if (!message) return;
    const active = this.#activePort;

    if (message.type === 'begin') {
      if (!this.#enabled) return;
      if (!isWebAuthnFeatureAllowed(message.request.kind)) {
        this.#postToPage(permissionPolicyDenied(message.request));
        return;
      }
      const serialized = serializeCanonicalWebsitePasskeyRequest(message.request);
      const existing = this.#requests.get(message.request.bridgeRequestId);
      if (existing) {
        // A page can forge this routing channel. Never let a conflicting duplicate tear down the
        // authenticated runtime Port; only the original canonical request remains authoritative.
        return;
      }
      if (!this.#makeRequestRoom()) return;
      const now = this.#now();
      const request: PendingBridgeRequest = {
        request: message.request,
        serialized,
        deadlineAt: now + message.request.timeout,
        expiresAt: now + message.request.timeout + DELIVERY_TOMBSTONE_MS,
        beginSent: false,
        cancelled: false,
        pageSettled: false,
        delivered: false,
      };
      request.cleanupTimer = this.#timers.setTimeout(() => {
        this.#deleteRequest(message.request.bridgeRequestId, request);
      }, message.request.timeout + DELIVERY_TOMBSTONE_MS);
      this.#requests.set(message.request.bridgeRequestId, request);
      if (active?.configured) this.#postBegin(active, request);
      return;
    }

    const request = this.#requests.get(message.bridgeRequestId);
    if (!request) return;
    if (message.type === 'cancel') {
      request.cancelled = true;
      request.pageSettled ||= message.settled;
      this.#clearConditionalUi(request);
      if (request.outcome && request.pageSettled) {
        request.delivered = true;
        if (active?.configured && request.boundGeneration === active.generation) {
          this.#postAck(active, request);
        }
        this.#scheduleTombstoneCleanup(request);
      } else if (request.outcome && !request.delivered) {
        this.#postToPage(request.outcome);
      } else if (
        active?.configured
        && (request.accepted || request.unlockPending)
        && request.boundGeneration === active.generation
      ) {
        this.#postCancel(active, request);
      }
      return;
    }
    if (
      !request.outcome
      || request.outcome.ceremonyId !== message.ceremonyId
      || request.outcome.outcomeId !== message.outcomeId
    ) return;
    request.delivered = true;
    if (active?.configured && request.boundGeneration === active.generation) {
      this.#postAck(active, request);
    }
    this.#scheduleTombstoneCleanup(request);
  }

  #postBegin(active: ActivePort, request: PendingBridgeRequest): void {
    request.beginSent = true;
    this.#postPort(active, {
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request.request,
    });
  }

  #postResume(active: ActivePort, request: PendingBridgeRequest): void {
    this.#postPort(active, {
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'resume',
      request: request.request,
    });
  }

  #postCancel(active: ActivePort, request: PendingBridgeRequest): void {
    const ceremonyId = request.accepted?.ceremonyId ?? request.unlockPending?.continuationId;
    if (!ceremonyId || request.boundGeneration !== active.generation) return;
    this.#postPort(active, {
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId,
      bridgeRequestId: request.request.bridgeRequestId,
    });
  }

  #postAck(active: ActivePort, request: PendingBridgeRequest): void {
    if (!request.outcome || request.boundGeneration !== active.generation) return;
    this.#postPort(active, {
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: request.outcome.ceremonyId,
      bridgeRequestId: request.request.bridgeRequestId,
      outcomeId: request.outcome.outcomeId,
    });
  }

  #postPort(active: ActivePort, message: WebsitePasskeyClientMessage): boolean {
    if (this.#activePort !== active) return false;
    try {
      active.port.postMessage(message);
      return true;
    } catch {
      this.#losePort(active);
      return false;
    }
  }

  #postConfig(enabled: boolean): void {
    const message: WebsitePasskeyBridgeConfigMessage = {
      source: WEBSITE_PASSKEY_BRIDGE_SOURCE,
      version: WEBSITE_PASSKEY_WINDOW_VERSION,
      type: 'config',
      enabled,
    };
    this.#postToPage(message);
  }

  #postToPage(
    message: Exclude<WebsitePasskeyServerMessage, WebsitePasskeyConditionalActiveMessage>
      | WebsitePasskeyBridgeConfigMessage,
  ): void {
    try {
      window.postMessage(
        'source' in message ? message : { source: WEBSITE_PASSKEY_BRIDGE_SOURCE, ...message },
        location.origin,
      );
    } catch {
      // Missing page delivery intentionally leaves the worker outcome unacknowledged.
    }
  }

  #scheduleTombstoneCleanup(request: PendingBridgeRequest): void {
    this.#clearRequestTimer(request);
    request.cleanupTimer = this.#timers.setTimeout(() => {
      this.#deleteRequest(request.request.bridgeRequestId, request);
    }, DELIVERY_TOMBSTONE_MS);
  }

  #makeRequestRoom(): boolean {
    let activeRequests = 0;
    for (const request of this.#requests.values()) {
      if (!request.delivered && !request.preflight) activeRequests += 1;
    }
    if (activeRequests >= MAX_ACTIVE_REQUESTS) return false;
    if (this.#requests.size < MAX_TRACKED_REQUESTS) return true;
    for (const [bridgeRequestId, request] of this.#requests) {
      if (!request.delivered && !request.preflight) continue;
      this.#deleteRequest(bridgeRequestId, request);
      if (this.#requests.size < MAX_TRACKED_REQUESTS) return true;
    }
    return false;
  }

  #deleteRequest(bridgeRequestId: string, request: PendingBridgeRequest): void {
    if (this.#requests.get(bridgeRequestId) !== request) return;
    this.#clearConditionalUi(request);
    this.#clearRequestTimer(request);
    this.#requests.delete(bridgeRequestId);
  }

  #clearRequestTimer(request: PendingBridgeRequest): void {
    if (request.cleanupTimer !== undefined) this.#timers.clearTimeout(request.cleanupTimer);
    request.cleanupTimer = undefined;
  }

  #scheduleConditionalUiTimeout(request: PendingBridgeRequest, deadlineAt: number): void {
    if (request.conditionalUiTimer !== undefined) {
      this.#timers.clearTimeout(request.conditionalUiTimer);
    }
    request.conditionalUiTimer = this.#timers.setTimeout(() => {
      request.conditionalUiTimer = undefined;
      this.#conditionalUi.clear(request.accepted?.ceremonyId, request.request.bridgeRequestId);
    }, Math.max(0, deadlineAt - this.#now()));
  }

  #clearConditionalUi(request: PendingBridgeRequest): void {
    if (request.conditionalUiTimer !== undefined) {
      this.#timers.clearTimeout(request.conditionalUiTimer);
      request.conditionalUiTimer = undefined;
    }
    this.#conditionalUi.clear(request.accepted?.ceremonyId, request.request.bridgeRequestId);
  }
}

function parsePageMessage(value: unknown): ParsedPageMessage | undefined {
  if (!isPlainDataRecord(value)) return undefined;
  if (
    ownData(value, 'source') !== WEBSITE_PASSKEY_PAGE_SOURCE
    || ownData(value, 'version') !== WEBSITE_PASSKEY_WINDOW_VERSION
  ) return undefined;
  const type = ownData(value, 'type');
  try {
    if (type === 'begin') {
      if (!hasExactKeys(value, ['source', 'version', 'type', 'request'])) return undefined;
      const decision = parseWebsitePasskeyClientMessage({
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'begin',
        request: ownData(value, 'request'),
      });
      if (decision.status !== 'accepted' || decision.message.type !== 'begin') return undefined;
      if (!isUuidV4(decision.message.request.bridgeRequestId)) return undefined;
      return { type: 'begin', request: decision.message.request };
    }
    if (type === 'cancel') {
      if (!hasExactKeys(value, ['source', 'version', 'type', 'bridgeRequestId', 'settled'])) {
        return undefined;
      }
      const bridgeRequestId = ownData(value, 'bridgeRequestId');
      const settled = ownData(value, 'settled');
      if (
        !isUuidV4(bridgeRequestId)
        || typeof settled !== 'boolean'
      ) return undefined;
      return { type: 'cancel', bridgeRequestId, settled };
    }
    if (type === 'delivered') {
      if (!hasExactKeys(value, [
        'source', 'version', 'type', 'ceremonyId', 'bridgeRequestId', 'outcomeId',
      ])) return undefined;
      const decision = parseWebsitePasskeyClientMessage({
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'ack',
        ceremonyId: ownData(value, 'ceremonyId'),
        bridgeRequestId: ownData(value, 'bridgeRequestId'),
        outcomeId: ownData(value, 'outcomeId'),
      });
      if (decision.status !== 'accepted' || decision.message.type !== 'ack') return undefined;
      if (
        !isUuidV4(decision.message.ceremonyId)
        || !isUuidV4(decision.message.bridgeRequestId)
        || !isUuidV4(decision.message.outcomeId)
      ) return undefined;
      return {
        type: 'delivered',
        ceremonyId: decision.message.ceremonyId,
        bridgeRequestId: decision.message.bridgeRequestId,
        outcomeId: decision.message.outcomeId,
      };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function isSupportedDocument(): boolean {
  if (!window.isSecureContext) return false;
  let url: URL;
  try { url = new URL(location.href); } catch { return false; }
  if (url.protocol === 'https:') return true;
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return url.protocol === 'http:' && (
    hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname === '127.0.0.1'
    || hostname === '::1'
  );
}

function isWebAuthnFeatureAllowed(kind: CanonicalWebsitePasskeyRequest['kind']): boolean {
  const feature = kind === 'get' ? 'publickey-credentials-get' : 'publickey-credentials-create';
  const policyHolder = document as Document & {
    permissionsPolicy?: { allowsFeature(name: string): boolean };
    featurePolicy?: { allowsFeature(name: string): boolean };
  };
  try {
    const policy = policyHolder.permissionsPolicy ?? policyHolder.featurePolicy;
    if (policy && typeof policy.allowsFeature === 'function') return policy.allowsFeature(feature);
  } catch {
    return false;
  }
  // Absence is not proof of denial. The worker validates response and container policy against the
  // browser-owned frame tree before any ceremony can access vault material.
  return true;
}

function permissionPolicyDenied(
  request: CanonicalWebsitePasskeyRequest,
): WebsitePasskeyPreflightOutcomeMessage {
  const feature = request.kind === 'get'
    ? 'publickey-credentials-get'
    : 'publickey-credentials-create';
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'preflightOutcome',
    bridgeRequestId: request.bridgeRequestId,
    outcome: {
      status: 'error',
      error: {
        name: 'NotAllowedError',
        message: `The '${feature}' feature is not enabled in this document.`,
      },
    },
  };
}

function hasStrictServerIds(message: WebsitePasskeyServerMessage): boolean {
  switch (message.type) {
    case 'config':
      return true;
    case 'preflightOutcome':
      return isUuidV4(message.bridgeRequestId);
    case 'accepted':
      return isUuidV4(message.bridgeRequestId) && isUuidV4(message.ceremonyId);
    case 'unlockPending':
      return isUuidV4(message.bridgeRequestId) && isUuidV4(message.continuationId);
    case 'conditionalActive':
      return isUuidV4(message.bridgeRequestId) && isUuidV4(message.ceremonyId);
    case 'outcome':
      return isUuidV4(message.bridgeRequestId)
        && isUuidV4(message.ceremonyId)
        && isUuidV4(message.outcomeId);
  }
}

function isUuidV4(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID_V4.test(value);
}

function isPlainDataRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value !== undefined);
  });
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length
    && expected.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function ownData(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function removePortListener<Listener>(event: WebsitePasskeyPortEvent<Listener>, listener: Listener): void {
  try { event.removeListener?.(listener); } catch { /* The disconnected Port owns final teardown. */ }
}

function isConfigChangedMessage(value: unknown): boolean {
  try {
    parseWebsitePasskeyConfigChangedMessage(value);
    return true;
  } catch {
    return false;
  }
}

const productionDependencies: WebsitePasskeyBridgeDependencies = {
  connectPort(name) {
    return browser.runtime.connect({ name }) as unknown as WebsitePasskeyPort;
  },
  subscribeRuntimeMessages(listener) {
    const runtimeListener = (message: unknown): Promise<WebsitePasskeyRuntimeResponse> | undefined => {
      const response = listener(message);
      return response ? Promise.resolve(response) : undefined;
    };
    browser.runtime.onMessage.addListener(runtimeListener);
    return () => browser.runtime.onMessage.removeListener(runtimeListener);
  },
  reportIframeInventory(request) {
    return browser.runtime.sendMessage(request);
  },
};

export function installWebsitePasskeyBridge(
  dependencies: WebsitePasskeyBridgeDependencies = productionDependencies,
): WebsitePasskeyBridge {
  const existing = readBridgeSentinel();
  if (existing) {
    existing.refreshConfig();
    return existing;
  }
  const bridge = new WebsitePasskeyBridge(dependencies);
  try {
    Object.defineProperty(globalThis, BRIDGE_SENTINEL, {
      configurable: true,
      value: Object.freeze({ version: 1, bridge }),
    });
  } catch {
    // A page cannot access this isolated-world sentinel; failure only loses duplicate suppression.
  }
  bridge.start();
  return bridge;
}

function readBridgeSentinel(): WebsitePasskeyBridge | undefined {
  let value: unknown;
  try { value = (globalThis as unknown as Record<PropertyKey, unknown>)[BRIDGE_SENTINEL]; } catch {
    return undefined;
  }
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (record.version !== 1) return undefined;
  const bridge = record.bridge as Partial<WebsitePasskeyBridge> | undefined;
  return bridge && typeof bridge.refreshConfig === 'function' && typeof bridge.stop === 'function'
    ? bridge as WebsitePasskeyBridge
    : undefined;
}

function clearBridgeSentinel(bridge: WebsitePasskeyBridge): void {
  if (readBridgeSentinel() !== bridge) return;
  try { delete (globalThis as unknown as Record<PropertyKey, unknown>)[BRIDGE_SENTINEL]; } catch {
    // The bridge is stopped even if the isolated global was unexpectedly frozen.
  }
}

export const websitePasskeyBridge = installWebsitePasskeyBridge();
