import {
  WEBSITE_PASSKEY_PORT_VERSION,
  createWebsitePasskeyPreflightOutcomeMessage,
  serializeCanonicalWebsitePasskeyRequest,
  type CanonicalWebsitePasskeyCreateRequest,
  type CanonicalWebsitePasskeyGetRequest,
  type CanonicalWebsitePasskeyRequest,
  type PasskeyAssertionResultSnapshot,
  type PasskeyRegistrationResultSnapshot,
  type WebsitePasskeyAcceptedMessage,
  type WebsitePasskeyApprovalModel,
  type WebsitePasskeyConditionalActiveMessage,
  type WebsitePasskeyDecisionOutcome,
  type WebsitePasskeyDisplayChoice,
  type WebsitePasskeyFallbackReason,
  type WebsitePasskeyOutcome,
  type WebsitePasskeyOutcomeMessage,
  type WebsitePasskeyServerMessage,
  type WebsitePasskeySelection,
  type WebsitePasskeyUnsupportedReason,
  type WebsitePasskeyUnlockPendingMessage,
} from '../messaging/website-passkey-port.js';
import type {
  AwaitingPasskeyCeremony,
  CompletedPasskeyCeremony,
  ExecutingPasskeyCeremony,
  PasskeyCeremonyCandidateSnapshot,
  PasskeyCeremonyRecord,
  PasskeyCeremonyRegistry,
  PasskeyCeremonyTerminalReason,
  TerminalPasskeyCeremony,
} from './passkey-ceremony-registry.js';
import type {
  WebsitePasskeyLockedContinuationEnvelope,
  WebsitePasskeyLockedContinuationStore,
} from './website-passkey-locked-continuation-store.js';

export const WEBSITE_PASSKEY_POPUP_PATH = '/ui/popup/popup.html';

export type {
  WebsitePasskeyApprovalModel,
  WebsitePasskeyDecisionOutcome,
  WebsitePasskeyDisplayChoice,
  WebsitePasskeySelection,
} from '../messaging/website-passkey-port.js';

export interface WebsitePasskeyDocumentContext {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly origin: string;
}

export interface WebsitePasskeySecurityBinding {
  readonly sessionBindingId: string;
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly rawGeneration: string;
  readonly snapshotGeneration?: string;
  readonly policyGeneration: number;
}

export interface WebsitePasskeySecuritySnapshot<Proof = unknown> extends WebsitePasskeySecurityBinding {
  readonly proof: Proof;
}

export interface WebsitePasskeySecurityAssertOptions {
  readonly allowVaultGenerationChange?: boolean;
  readonly operation?: CanonicalWebsitePasskeyRequest['kind'];
}

export interface WebsitePasskeySecurityAdapter<Proof = unknown> {
  capture(
    context: WebsitePasskeyDocumentContext,
    operation?: CanonicalWebsitePasskeyRequest['kind'],
  ): Promise<WebsitePasskeySecuritySnapshot<Proof>>;
  assertCurrent(
    snapshot: WebsitePasskeySecuritySnapshot<Proof>,
    options?: WebsitePasskeySecurityAssertOptions,
  ): void | Promise<void>;
  assertBindingCurrent(
    binding: WebsitePasskeySecurityBinding,
    document: WebsitePasskeyDocumentContext,
    options?: WebsitePasskeySecurityAssertOptions,
  ): Promise<WebsitePasskeySecuritySnapshot<Proof>>;
  assertDeliveryCurrent(
    snapshot: WebsitePasskeySecuritySnapshot<Proof>,
    options?: WebsitePasskeySecurityAssertOptions,
  ): void;
}

export interface WebsitePasskeyAvailabilitySnapshot<Proof = unknown> {
  readonly proof: Proof;
  readonly sessionState: 'locked' | 'unlocked';
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly policyGeneration: number;
}

export interface WebsitePasskeyAvailabilityAdapter<Proof = unknown> {
  capture(
    context: WebsitePasskeyDocumentContext,
    operation: CanonicalWebsitePasskeyRequest['kind'],
  ): Promise<WebsitePasskeyAvailabilitySnapshot<Proof>>;
  assertCurrent(snapshot: WebsitePasskeyAvailabilitySnapshot<Proof>): void | Promise<void>;
}

export type WebsitePasskeyCreateExecutionResult =
  | { readonly status: 'committed' | 'committed_unsynced'; readonly result: PasskeyRegistrationResultSnapshot }
  | { readonly status: 'not_committed'; readonly reason: 'invalid_state' | 'not_allowed' | 'not_supported' | 'operation_failed' }
  | { readonly status: 'outcome_unknown' };

export interface WebsitePasskeyVaultAdapter<Proof = unknown> {
  prepareGet(
    request: CanonicalWebsitePasskeyGetRequest,
    origin: string,
    snapshot: WebsitePasskeySecuritySnapshot<Proof>,
    signal: AbortSignal,
  ): Promise<readonly WebsitePasskeyDisplayChoice[]>;
  prepareCreate(
    request: CanonicalWebsitePasskeyCreateRequest,
    origin: string,
    snapshot: WebsitePasskeySecuritySnapshot<Proof>,
    signal: AbortSignal,
  ): Promise<readonly WebsitePasskeyDisplayChoice[]>;
  executeGet(
    request: CanonicalWebsitePasskeyGetRequest,
    origin: string,
    credentialId: string,
    snapshot: WebsitePasskeySecuritySnapshot<Proof>,
    signal: AbortSignal,
  ): Promise<PasskeyAssertionResultSnapshot | undefined>;
  executeCreate(
    request: CanonicalWebsitePasskeyCreateRequest,
    origin: string,
    selection: Extract<WebsitePasskeySelection, { kind: 'new' | 'target' }>,
    snapshot: WebsitePasskeySecuritySnapshot<Proof>,
    signal: AbortSignal,
  ): Promise<WebsitePasskeyCreateExecutionResult>;
}

export interface WebsitePasskeyWindowAdapter {
  open(url: string): Promise<number>;
  close?(windowId: number): Promise<void>;
  isOpen?(windowId: number): Promise<boolean>;
}

export interface WebsitePasskeyTimerAdapter {
  set(callback: () => void, delayMs: number): unknown;
  clear(handle: unknown): void;
}

export interface WebsitePasskeyDocumentConnection {
  getConfig(): Promise<boolean>;
  begin(
    request: CanonicalWebsitePasskeyRequest,
    unsupportedReason?: WebsitePasskeyUnsupportedReason,
    receivedDeadlineAt?: number,
  ): Promise<WebsitePasskeyServerMessage | undefined>;
  resume(request: CanonicalWebsitePasskeyRequest): Promise<WebsitePasskeyServerMessage | undefined>;
  selectConditional(
    ceremonyId: string,
    bridgeRequestId: string,
    credentialId: string,
  ): Promise<boolean>;
  cancel(ceremonyId: string, bridgeRequestId: string): Promise<void>;
  acknowledge(ceremonyId: string, bridgeRequestId: string, outcomeId: string): Promise<boolean>;
  close(): void;
}

type Registry = Pick<
  PasskeyCeremonyRegistry,
  | 'recoverStartup'
  | 'begin'
  | 'claim'
  | 'complete'
  | 'markFailed'
  | 'markUncertain'
  | 'markFallback'
  | 'abort'
  | 'invalidateContext'
  | 'cancel'
  | 'acknowledge'
  | 'get'
  | 'listAwaitingApproval'
  | 'listRedeliverable'
>;

export interface WebsitePasskeyCoordinatorOptions<Proof = unknown> {
  readonly registry: Registry;
  readonly security: WebsitePasskeySecurityAdapter<Proof>;
  readonly availability?: WebsitePasskeyAvailabilityAdapter;
  readonly lockedContinuations?: WebsitePasskeyLockedContinuationStore;
  readonly vault: WebsitePasskeyVaultAdapter<Proof>;
  readonly windows: WebsitePasskeyWindowAdapter;
  readonly extensionBaseUrl: string;
  readonly excludeOrigin?: (origin: string, rpId: string) => void | Promise<void>;
  readonly now?: () => number;
  readonly timers?: WebsitePasskeyTimerAdapter;
}

export type WebsitePasskeyLockedContinuationStatus =
  | Readonly<{ status: 'none' }>
  | Readonly<{ status: 'unlock_required'; continuationId: string; expiresAt: number }>;

export type WebsitePasskeyLockedResumeStatus = 'started' | 'stale';

interface Channel {
  readonly token: object;
  readonly document: WebsitePasskeyDocumentContext;
  readonly deliver: (
    message: WebsitePasskeyOutcomeMessage,
    assertCurrent?: () => void,
  ) => void | Promise<void>;
  readonly deliverControl?: (
    message: Exclude<WebsitePasskeyServerMessage,
      { readonly type: 'config' } | WebsitePasskeyOutcomeMessage>,
  ) => void | Promise<void>;
}

interface Execution {
  readonly id: string;
  readonly controller: AbortController;
  deadlineFired: boolean;
}

interface CeremonyRuntime<Proof> {
  record: PasskeyCeremonyRecord;
  readonly security: WebsitePasskeySecuritySnapshot<Proof>;
  /** Audit-only provenance for future UV work; it is never treated as user verification. */
  readonly unlockedFromLocked: boolean;
  channel: Channel;
  windowId?: number;
  execution?: Execution;
  timer?: unknown;
}

interface LockedPromotionResult {
  readonly status: WebsitePasskeyLockedResumeStatus;
  readonly response: WebsitePasskeyServerMessage;
}

const DEFAULT_TIMERS: WebsitePasskeyTimerAdapter = {
  set: (callback, delayMs) => setTimeout(callback, delayMs),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export class WebsitePasskeyCoordinator<Proof = unknown> {
  readonly #registry: Registry;
  readonly #security: WebsitePasskeySecurityAdapter<Proof>;
  readonly #availability: WebsitePasskeyAvailabilityAdapter | undefined;
  readonly #lockedContinuations: WebsitePasskeyLockedContinuationStore | undefined;
  readonly #vault: WebsitePasskeyVaultAdapter<Proof>;
  readonly #windows: WebsitePasskeyWindowAdapter;
  readonly #excludeOrigin: ((origin: string, rpId: string) => void | Promise<void>) | undefined;
  readonly #now: () => number;
  readonly #timers: WebsitePasskeyTimerAdapter;
  readonly #popupBaseUrl: URL;
  readonly #ready: Promise<void>;
  readonly #channels = new Map<string, Channel>();
  readonly #runtimes = new Map<string, CeremonyRuntime<Proof>>();
  readonly #preparing = new Map<string, {
    readonly requestKey: string;
    readonly serializedRequest: string;
    resumeRequested: boolean;
    task: Promise<WebsitePasskeyServerMessage | undefined>;
  }>();
  readonly #ceremonyByWindow = new Map<number, string>();
  readonly #lockedTimerByContinuation = new Map<string, unknown>();
  readonly #lockedContinuationByWindow = new Map<number, string>();
  readonly #lockedPromotions = new Map<string, {
    readonly serializedRequest: string;
    readonly task: Promise<WebsitePasskeyServerMessage | undefined>;
  }>();

  constructor(options: WebsitePasskeyCoordinatorOptions<Proof>) {
    this.#registry = options.registry;
    this.#security = options.security;
    this.#availability = options.availability;
    this.#lockedContinuations = options.lockedContinuations;
    this.#vault = options.vault;
    this.#windows = options.windows;
    this.#excludeOrigin = options.excludeOrigin;
    this.#now = options.now ?? Date.now;
    this.#timers = options.timers ?? DEFAULT_TIMERS;
    const extensionBase = new URL(options.extensionBaseUrl);
    this.#popupBaseUrl = new URL(WEBSITE_PASSKEY_POPUP_PATH, extensionBase);
    if (this.#popupBaseUrl.protocol !== extensionBase.protocol || this.#popupBaseUrl.host !== extensionBase.host) {
      throw new TypeError('Invalid extension popup URL');
    }
    this.#ready = this.#recover();
  }

  connect(
    document: WebsitePasskeyDocumentContext,
    deliver: (
      message: WebsitePasskeyOutcomeMessage,
      assertCurrent?: () => void,
    ) => void | Promise<void>,
    deliverControl?: (
      message: Exclude<WebsitePasskeyServerMessage,
        { readonly type: 'config' } | WebsitePasskeyOutcomeMessage>,
    ) => void | Promise<void>,
  ): WebsitePasskeyDocumentConnection {
    const frozenDocument = Object.freeze({ ...document });
    const key = documentKey(frozenDocument);
    const channel: Channel = {
      token: {},
      document: frozenDocument,
      deliver,
      ...(deliverControl ? { deliverControl } : {}),
    };
    this.#channels.set(key, channel);
    let active = true;
    const assertActive = (): void => {
      if (!active || this.#channels.get(key)?.token !== channel.token) {
        throw new Error('Website passkey connection is closed');
      }
    };
    const connection: WebsitePasskeyDocumentConnection = {
      getConfig: async () => {
        await this.#ready;
        assertActive();
        for (const operation of ['get', 'create'] as const) {
          try {
            if (this.#availability) {
              const availability = await this.#availability.capture(frozenDocument, operation);
              assertActive();
              await this.#availability.assertCurrent(availability);
            } else {
              const security = await this.#security.capture(frozenDocument, operation);
              assertActive();
              await this.#security.assertCurrent(security, { operation });
            }
            assertActive();
            return true;
          } catch {
            // Config is document-wide; either independently delegated feature can enable the bridge.
          }
        }
        return false;
      },
      begin: async (
        request: CanonicalWebsitePasskeyRequest,
        unsupportedReason?: WebsitePasskeyUnsupportedReason,
        receivedDeadlineAt?: number,
      ) => {
        const requestDeadlineAt = boundedDeadline(
          this.#now(), request.timeout, receivedDeadlineAt,
        );
        await this.#ready;
        assertActive();
        return this.#begin(channel, request, requestDeadlineAt, unsupportedReason);
      },
      resume: async (request: CanonicalWebsitePasskeyRequest) => {
        await this.#ready;
        assertActive();
        const promotion = this.#lockedPromotions.get(key);
        if (promotion) {
          if (promotion.serializedRequest !== serializeCanonicalWebsitePasskeyRequest(request)) {
            return undefined;
          }
          return promotion.task;
        }
        const preparing = this.#preparing.get(key);
        if (preparing) {
          if (preparing.serializedRequest !== serializeCanonicalWebsitePasskeyRequest(request)) {
            return undefined;
          }
          preparing.resumeRequested = true;
          return preparing.task;
        }
        const existing = await this.#findExisting(channel.document, request);
        assertActive();
        if (existing) return this.#messageForExisting(existing, channel);
        return this.#messageForLockedExisting(channel.document, request);
      },
      selectConditional: async (ceremonyId, bridgeRequestId, credentialId) => {
        await this.#ready;
        assertActive();
        return this.#selectConditional(channel, ceremonyId, bridgeRequestId, credentialId);
      },
      cancel: async (ceremonyId: string, bridgeRequestId: string) => {
        await this.#ready;
        assertActive();
        await this.#cancelFromDocument(channel, ceremonyId, bridgeRequestId);
      },
      acknowledge: async (ceremonyId: string, bridgeRequestId: string, outcomeId: string) => {
        await this.#ready;
        assertActive();
        return this.#acknowledge(channel, ceremonyId, bridgeRequestId, outcomeId);
      },
      close: () => {
        if (!active) return;
        active = false;
        if (this.#channels.get(key)?.token === channel.token) this.#channels.delete(key);
      },
    };
    return Object.freeze(connection);
  }

  async getApproval(ceremonyId: string): Promise<WebsitePasskeyApprovalModel | undefined> {
    await this.#ready;
    const record = await this.#registry.get(ceremonyId);
    const runtime = this.#runtimes.get(ceremonyId);
    if (!record) {
      this.#removeRuntime(ceremonyId);
      return undefined;
    }
    if (isTerminal(record)) {
      if (runtime) await this.#finish(runtime, record);
      else await this.#deliverTerminal(record);
      return undefined;
    }
    if (!runtime) return undefined;
    try {
      await this.#security.assertCurrent(runtime.security, {
        allowVaultGenerationChange: record.state === 'executing' && record.request.kind === 'create',
      });
    } catch {
      await this.#abortCeremony(record);
      return undefined;
    }
    return approvalModel(record);
  }

  async approve(ceremonyId: string, selection: WebsitePasskeySelection): Promise<WebsitePasskeyDecisionOutcome> {
    await this.#ready;
    const initial = await this.#registry.get(ceremonyId);
    const runtime = this.#runtimes.get(ceremonyId);
    if (!initial || initial.state !== 'awaitingApproval' || !runtime) return terminalDecision(initial);
    try {
      await this.#security.assertCurrent(runtime.security);
    } catch {
      return this.#abortCeremony(initial);
    }

    const executing = await this.#registry.claim(ceremonyId, initial.request.bridgeRequestId);
    if (!executing) return terminalDecision(await this.#registry.get(ceremonyId));
    runtime.record = executing;
    const controller = new AbortController();
    runtime.execution = { id: executing.executionId, controller, deadlineFired: false };
    this.#schedule(runtime);

    if (!selectionMatches(executing, selection)) {
      const terminal = await this.#registry.markFailed(ceremonyId, executing.executionId, 'execution_failed');
      if (terminal) await this.#finish(runtime, terminal);
      return terminal ? 'failed' : terminalDecision(await this.#registry.get(ceremonyId));
    }
    return this.#execute(runtime, executing, selection);
  }

  async fallbackOnce(ceremonyId: string): Promise<WebsitePasskeyDecisionOutcome> {
    await this.#ready;
    return this.#fallbackPopupCeremony(ceremonyId, 'user_selected_browser');
  }

  async fallbackAlways(ceremonyId: string): Promise<WebsitePasskeyDecisionOutcome> {
    await this.#ready;
    const record = await this.#registry.get(ceremonyId);
    if (!record || record.state !== 'awaitingApproval') return terminalDecision(record);
    if (!this.#excludeOrigin) return 'unavailable';
    try {
      await this.#excludeOrigin(record.origin, rpIdOf(record.request));
    } catch {
      return 'failed';
    }
    return this.#fallbackPopupCeremony(ceremonyId, 'excluded_domain');
  }

  async cancel(ceremonyId: string): Promise<WebsitePasskeyDecisionOutcome> {
    await this.#ready;
    return this.#abortPopupCeremony(ceremonyId);
  }

  async getLockedContinuation(
    continuationId: string | undefined,
    popupDocumentId: string,
  ): Promise<WebsitePasskeyLockedContinuationStatus> {
    await this.#ready;
    if (!this.#lockedContinuations) return Object.freeze({ status: 'none' as const });
    let pending: WebsitePasskeyLockedContinuationEnvelope | undefined;
    try {
      const current = continuationId === undefined
        ? await this.#lockedContinuations.readPending()
        : undefined;
      const expectedId = continuationId
        ?? (current && isConditionalGet(current.request) ? current.continuationId : undefined);
      pending = expectedId
        ? await this.#lockedContinuations.claimPopup(expectedId, popupDocumentId)
        : undefined;
    } catch {
      return Object.freeze({ status: 'none' as const });
    }
    if (!pending) return Object.freeze({ status: 'none' as const });
    this.#scheduleLocked(pending);
    return Object.freeze({
      status: 'unlock_required' as const,
      continuationId: pending.continuationId,
      expiresAt: pending.deadlineAt,
    });
  }

  async resumeLockedContinuation(
    continuationId: string,
    popupDocumentId: string,
  ): Promise<WebsitePasskeyLockedResumeStatus> {
    await this.#ready;
    const pending = await this.#lockedContinuations?.readPending();
    if (!pending || pending.continuationId !== continuationId) return 'stale';
    return this.#runLockedPromotion(pending, async () => {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId,
        workerGeneration: pending.workerGeneration,
        reason: 'resumed',
        popupDocumentId,
      });
      return consumed ? this.#promoteLocked(consumed) : this.#staleLockedPromotion(pending);
    });
  }

  /** Refresh a passive conditional request after the same account is unlocked elsewhere. */
  async resumeConditionalAfterUnlock(): Promise<WebsitePasskeyLockedResumeStatus> {
    await this.#ready;
    const pending = await this.#lockedContinuations?.readPending();
    if (!pending || !isConditionalGet(pending.request)) return 'stale';
    return this.#runLockedPromotion(pending, async () => {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: pending.continuationId,
        workerGeneration: pending.workerGeneration,
        reason: 'resumed',
        document: pending.document,
        bridgeRequestId: pending.request.bridgeRequestId,
      });
      return consumed ? this.#promoteLocked(consumed) : this.#staleLockedPromotion(pending);
    });
  }

  async #promoteLocked(
    consumed: WebsitePasskeyLockedContinuationEnvelope,
  ): Promise<LockedPromotionResult> {
    await this.#finishLocked(consumed, 'unavailable', false);

    let response: WebsitePasskeyServerMessage | undefined;
    try {
      if (this.#now() >= consumed.deadlineAt) throw new Error('Continuation expired');
      const availability = await this.#captureAvailability(consumed.document, consumed.operation);
      await this.#assertLockedBinding(consumed, availability);
      if (availability.sessionState !== 'unlocked') throw new Error('Vault is not unlocked');
      const current = this.#channels.get(documentKey(consumed.document));
      const channel = current ?? detachedChannel(consumed.document);
      response = await this.#beginUnlockedPrepared(
        channel,
        consumed.request,
        consumed.deadlineAt,
        consumed.unsupportedReason,
        consumed.continuationId,
        consumed,
      );
      response ??= createWebsitePasskeyPreflightOutcomeMessage(
        consumed.request.bridgeRequestId,
        'unavailable',
      );
      if (current && this.#channels.get(documentKey(consumed.document))?.token === current.token) {
        if (response.type === 'config') throw new Error('Invalid website passkey continuation response');
        await deliverServerMessage(current, response);
      }
      return Object.freeze({
        status: response.type === 'preflightOutcome' ? 'stale' as const : 'started' as const,
        response,
      });
    } catch {
      const active = await this.#registry.get(consumed.continuationId).catch(() => undefined);
      if (active && !isTerminal(active)) await this.#abortCeremony(active).catch(() => undefined);
      const failure = createWebsitePasskeyPreflightOutcomeMessage(
        consumed.request.bridgeRequestId,
        'unavailable',
      );
      const channel = this.#channels.get(documentKey(consumed.document));
      if (channel) await Promise.resolve(deliverServerMessage(channel, failure)).catch(() => undefined);
      return Object.freeze({ status: 'stale' as const, response: failure });
    }
  }

  async #runLockedPromotion(
    pending: WebsitePasskeyLockedContinuationEnvelope,
    operation: () => Promise<LockedPromotionResult>,
  ): Promise<WebsitePasskeyLockedResumeStatus> {
    const key = documentKey(pending.document);
    if (this.#lockedPromotions.has(key)) return 'stale';
    const promotion = operation();
    const task = promotion.then((result) => result.response);
    const flight = {
      serializedRequest: serializeCanonicalWebsitePasskeyRequest(pending.request),
      task,
    };
    this.#lockedPromotions.set(key, flight);
    try { return (await promotion).status; }
    finally {
      if (this.#lockedPromotions.get(key) === flight) this.#lockedPromotions.delete(key);
    }
  }

  #staleLockedPromotion(
    pending: WebsitePasskeyLockedContinuationEnvelope,
  ): LockedPromotionResult {
    const response = createWebsitePasskeyPreflightOutcomeMessage(
      pending.request.bridgeRequestId,
      'unavailable',
    );
    return Object.freeze({ status: 'stale' as const, response });
  }

  async cancelLockedContinuation(
    continuationId: string,
    popupDocumentId: string,
  ): Promise<boolean> {
    await this.#ready;
    const pending = await this.#lockedContinuations?.readPending();
    if (!pending || pending.continuationId !== continuationId) return false;
    const consumed = await this.#lockedContinuations!.consume({
      continuationId,
      workerGeneration: pending.workerGeneration,
      reason: 'cancelled',
      popupDocumentId,
    });
    if (!consumed) return false;
    await this.#finishLocked(consumed, 'cancelled', true);
    return true;
  }

  /** Recheck a pending public continuation after policy, permission, or account invalidation. */
  async handleAuthorizationChange(): Promise<void> {
    await this.#ready;
    const pending = await this.#lockedContinuations?.readPending();
    if (!pending) return;
    try {
      const availability = await this.#captureAvailability(pending.document, pending.operation);
      await this.#assertLockedBinding(pending, availability);
    } catch {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: pending.continuationId,
        workerGeneration: pending.workerGeneration,
        reason: 'authorization_changed',
        document: pending.document,
        bridgeRequestId: pending.request.bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'unavailable', true);
    }
  }

  async handleWindowClosed(windowId: number): Promise<void> {
    await this.#ready;
    const ceremonyId = this.#ceremonyByWindow.get(windowId);
    if (ceremonyId) {
      this.#ceremonyByWindow.delete(windowId);
      const runtime = this.#runtimes.get(ceremonyId);
      if (runtime?.windowId === windowId) delete runtime.windowId;
      await this.#abortPopupCeremony(ceremonyId);
      return;
    }
    const pending = await this.#lockedContinuations?.readPending();
    if (!pending || pending.windowId !== windowId) return;
    const consumed = await this.#lockedContinuations!.consume({
      continuationId: pending.continuationId,
      workerGeneration: pending.workerGeneration,
      reason: 'cancelled',
      windowId,
    });
    if (consumed) await this.#finishLocked(consumed, 'cancelled', true);
  }

  /** Revalidate active ceremonies after a browser-owned frame or tab lifecycle event. */
  async handleBrowserDocumentChange(tabId: number): Promise<void> {
    await this.#ready;
    if (!Number.isSafeInteger(tabId) || tabId < 0) return;
    const runtimes = [...this.#runtimes.values()]
      .filter((runtime) => runtime.record.tabId === tabId);
    for (const runtime of runtimes) {
      const record = await this.#registry.get(runtime.record.ceremonyId);
      if (!record || isTerminal(record)) {
        if (record && isTerminal(record)) await this.#finish(runtime, record);
        else this.#removeRuntime(runtime.record.ceremonyId);
        continue;
      }
      runtime.record = record;
      try {
        await this.#security.assertCurrent(runtime.security, {
          allowVaultGenerationChange: record.state === 'executing' && record.request.kind === 'create',
        });
      } catch {
        await this.#invalidateCeremony(record);
      }
    }
    const locked = await this.#lockedContinuations?.readPending();
    if (!locked || locked.document.tabId !== tabId) return;
    try {
      const availability = await this.#captureAvailability(locked.document, locked.operation);
      await this.#assertLockedBinding(locked, availability);
    } catch {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: locked.continuationId,
        workerGeneration: locked.workerGeneration,
        reason: 'context_changed',
        document: locked.document,
        bridgeRequestId: locked.request.bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'cancelled', true);
    }
  }

  async #recover(): Promise<void> {
    await Promise.all([
      this.#registry.recoverStartup(),
      this.#lockedContinuations?.recoverWorker(),
    ]);
    const pending = await this.#lockedContinuations?.readPending();
    if (pending) this.#scheduleLocked(pending);
  }

  async #begin(
    channel: Channel,
    request: CanonicalWebsitePasskeyRequest,
    requestDeadlineAt: number,
    unsupportedReason?: WebsitePasskeyUnsupportedReason,
  ): Promise<WebsitePasskeyServerMessage | undefined> {
    const key = documentKey(channel.document);
    const serializedRequest = serializeCanonicalWebsitePasskeyRequest(request);
    const requestKey = `${unsupportedReason ?? ''}\n${serializedRequest}`;
    const preparing = this.#preparing.get(key);
    if (preparing) {
      return preparing.requestKey === requestKey
        ? preparing.task
        : createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    }
    const entry = {
      requestKey,
      serializedRequest,
      resumeRequested: false,
      task: Promise.resolve<WebsitePasskeyServerMessage | undefined>(undefined),
    };
    this.#preparing.set(key, entry);
    entry.task = this.#beginPrepared(channel, request, requestDeadlineAt, unsupportedReason);
    try {
      return await entry.task;
    } finally {
      if (this.#preparing.get(key) === entry) this.#preparing.delete(key);
    }
  }

  async #beginPrepared(
    channel: Channel,
    request: CanonicalWebsitePasskeyRequest,
    requestDeadlineAt: number,
    unsupportedReason?: WebsitePasskeyUnsupportedReason,
  ): Promise<WebsitePasskeyServerMessage | undefined> {
    const existing = await this.#findExisting(channel.document, request);
    if (existing) return this.#messageForExisting(existing, channel);
    const lockedExisting = await this.#messageForLockedExisting(channel.document, request);
    if (lockedExisting) return lockedExisting;
    if (this.#now() >= requestDeadlineAt) {
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    }

    if (this.#availability) {
      let availability: WebsitePasskeyAvailabilitySnapshot;
      try {
        availability = await this.#availability.capture(channel.document, request.kind);
        await this.#availability.assertCurrent(availability);
      } catch {
        return undefined;
      }
      if (availability.sessionState === 'locked') {
        if (unsupportedReason !== undefined || !this.#lockedContinuations) return undefined;
        return this.#stageLocked(
          channel,
          request,
          requestDeadlineAt,
          availability,
        );
      }
    }

    return this.#beginUnlockedPrepared(
      channel,
      request,
      requestDeadlineAt,
      unsupportedReason,
    );
  }

  async #beginUnlockedPrepared(
    channel: Channel,
    request: CanonicalWebsitePasskeyRequest,
    requestDeadlineAt: number,
    unsupportedReason?: WebsitePasskeyUnsupportedReason,
    requestedCeremonyId?: string,
    expectedLocked?: WebsitePasskeyLockedContinuationEnvelope,
  ): Promise<WebsitePasskeyServerMessage | undefined> {

    let security: WebsitePasskeySecuritySnapshot<Proof>;
    try {
      security = await this.#security.capture(channel.document, request.kind);
      await this.#security.assertCurrent(security);
      if (expectedLocked
          && (security.accountIdentity !== expectedLocked.accountIdentity
            || security.serverUrl !== expectedLocked.serverUrl
            || security.policyGeneration !== expectedLocked.policyGeneration)) {
        throw new Error('Website passkey locked binding changed before vault access');
      }
    } catch {
      return undefined;
    }
    if (this.#now() >= requestDeadlineAt) {
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    }

    const controller = new AbortController();
    const discoveryTimer = this.#timers.set(
      () => controller.abort(),
      Math.max(0, requestDeadlineAt - this.#now()),
    );
    let choices: readonly WebsitePasskeyDisplayChoice[] = [];
    const nativeFallback = unsupportedReason !== undefined || requiresUserVerification(request);
    try {
      if (!nativeFallback) {
        choices = request.kind === 'get'
          ? await abortable(this.#vault.prepareGet(request, channel.document.origin, security, controller.signal), controller.signal)
          : await abortable(this.#vault.prepareCreate(request, channel.document.origin, security, controller.signal), controller.signal);
        await this.#security.assertCurrent(security);
        if (this.#now() >= requestDeadlineAt) {
          return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
        }
      }
    } catch {
      return undefined;
    } finally {
      this.#timers.clear(discoveryTimer);
    }

    const candidates = choices.map((choice): PasskeyCeremonyCandidateSnapshot => ({
      kind: request.kind === 'get' ? 'credential' : 'target',
      id: choice.id,
      name: choice.name,
      ...(choice.username === undefined ? {} : { username: choice.username }),
    }));
    let begun;
    try {
      begun = await this.#registry.begin({
        tabId: channel.document.tabId,
        frameId: channel.document.frameId,
        documentId: channel.document.documentId,
        frameUrl: channel.document.url,
        origin: channel.document.origin,
        request,
        sessionBindingId: security.sessionBindingId,
        accountIdentity: security.accountIdentity,
        serverUrl: security.serverUrl,
        rawGeneration: security.rawGeneration,
        ...(security.snapshotGeneration === undefined ? {} : { snapshotGeneration: security.snapshotGeneration }),
        policyGeneration: security.policyGeneration,
        candidates,
        ...(requestedCeremonyId === undefined ? {} : { requestedCeremonyId }),
        requestedDeadlineAt: requestDeadlineAt,
      });
    } catch {
      return undefined;
    }
    try {
      await this.#security.assertCurrent(security);
    } catch {
      if (!('ceremony' in begun)) return undefined;
      if (isTerminal(begun.ceremony)) {
        return this.#messageForTerminal(
          begun.ceremony,
          this.#runtimes.get(begun.ceremony.ceremonyId),
        );
      }
      if (begun.ceremony.state !== 'awaitingApproval') return undefined;
      const terminal = await this.#registry.abort(
        begun.ceremony.ceremonyId,
        begun.ceremony.request.bridgeRequestId,
      );
      const settled = terminal ?? asTerminal(
        await this.#registry.get(begun.ceremony.ceremonyId),
      );
      return settled
        ? this.#messageForTerminal(settled, this.#runtimes.get(settled.ceremonyId))
        : undefined;
    }
    if (!('ceremony' in begun)) {
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, begun.status);
    }
    if (begun.status === 'fallback') return this.#outcomeMessage(begun.ceremony);

    if (isTerminal(begun.ceremony)) {
      return this.#messageForTerminal(
        begun.ceremony,
        this.#runtimes.get(begun.ceremony.ceremonyId),
      );
    }
    const runtime: CeremonyRuntime<Proof> = {
      record: begun.ceremony,
      security,
      channel,
      unlockedFromLocked: expectedLocked !== undefined,
    };
    this.#runtimes.set(begun.ceremony.ceremonyId, runtime);
    if (begun.ceremony.state === 'executing') return acceptedMessage(begun.ceremony);

    if (nativeFallback || (request.kind === 'get' && candidates.length === 0)) {
      const reason: WebsitePasskeyFallbackReason = nativeFallback ? 'unsupported' : 'no_match';
      const terminal = await this.#registry.markFallback(
        begun.ceremony.ceremonyId,
        request.bridgeRequestId,
        reason,
      );
      if (!terminal) {
        const settled = asTerminal(await this.#registry.get(begun.ceremony.ceremonyId));
        return settled
          ? this.#messageForTerminal(settled, runtime)
          : undefined;
      }
      return this.#messageForTerminal(terminal, runtime);
    }

    this.#schedule(runtime);
    if (!this.#shouldOpenApproval(channel, request)) return activeMessage(begun.ceremony);
    const terminal = await this.#openApproval(runtime, begun.ceremony);
    if (!terminal) return acceptedMessage(begun.ceremony);
    return this.#messageForTerminal(terminal, runtime);
  }

  async #stageLocked(
    channel: Channel,
    request: CanonicalWebsitePasskeyRequest,
    requestDeadlineAt: number,
    availability: WebsitePasskeyAvailabilitySnapshot,
  ): Promise<WebsitePasskeyServerMessage | undefined> {
    const staged = await this.#lockedContinuations!.stage({
      document: channel.document,
      request,
      accountIdentity: availability.accountIdentity,
      serverUrl: availability.serverUrl,
      policyGeneration: availability.policyGeneration,
      deadlineAt: requestDeadlineAt,
    });
    if (staged.status === 'busy') {
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    }
    try {
      await this.#availability!.assertCurrent(availability);
      await this.#assertLockedBinding(staged.envelope, availability);
      if (availability.sessionState !== 'locked') throw new Error('Vault state changed');
    } catch {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: staged.envelope.continuationId,
        workerGeneration: staged.envelope.workerGeneration,
        reason: 'authorization_changed',
        document: staged.envelope.document,
        bridgeRequestId: staged.envelope.request.bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'unavailable', false);
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'unavailable');
    }
    if (isConditionalGet(request)) {
      this.#scheduleLocked(staged.envelope);
      return unlockPendingMessage(staged.envelope);
    }
    const opened = await this.#ensureLockedWindow(staged.envelope);
    if (!opened) {
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'unavailable');
    }
    try {
      await this.#availability!.assertCurrent(availability);
      await this.#assertLockedBinding(opened, availability);
      if (availability.sessionState !== 'locked') throw new Error('Vault state changed');
    } catch {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: opened.continuationId,
        workerGeneration: opened.workerGeneration,
        reason: 'authorization_changed',
        document: opened.document,
        bridgeRequestId: opened.request.bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'unavailable', false);
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'unavailable');
    }
    this.#scheduleLocked(opened);
    return unlockPendingMessage(opened);
  }

  async #messageForLockedExisting(
    document: WebsitePasskeyDocumentContext,
    request: CanonicalWebsitePasskeyRequest,
  ): Promise<WebsitePasskeyServerMessage | undefined> {
    const found = await this.#lockedContinuations?.find(document, request);
    if (!found) return undefined;
    if (found.state === 'retired') {
      const admission = found.terminal.reason === 'expired' ? 'expired'
        : found.terminal.reason === 'cancelled' ? 'cancelled' : 'unavailable';
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, admission);
    }
    try {
      const availability = await this.#captureAvailability(found.envelope.document, found.envelope.operation);
      await this.#assertLockedBinding(found.envelope, availability);
    } catch {
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: found.envelope.continuationId,
        workerGeneration: found.envelope.workerGeneration,
        reason: 'authorization_changed',
        document: found.envelope.document,
        bridgeRequestId: found.envelope.request.bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'unavailable', false);
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'unavailable');
    }
    if (isConditionalGet(request)) {
      this.#scheduleLocked(found.envelope);
      return unlockPendingMessage(found.envelope);
    }
    const opened = await this.#ensureLockedWindow(found.envelope);
    if (!opened) {
      return createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'cancelled');
    }
    this.#scheduleLocked(opened);
    return unlockPendingMessage(opened);
  }

  async #ensureLockedWindow(
    envelope: WebsitePasskeyLockedContinuationEnvelope,
  ): Promise<WebsitePasskeyLockedContinuationEnvelope | undefined> {
    if (envelope.windowId !== undefined) {
      const open = this.#windows.isOpen
        ? await this.#windows.isOpen(envelope.windowId).catch(() => false)
        : true;
      if (!open) {
        const consumed = await this.#lockedContinuations!.consume({
          continuationId: envelope.continuationId,
          workerGeneration: envelope.workerGeneration,
          reason: 'cancelled',
          windowId: envelope.windowId,
        });
        if (consumed) await this.#finishLocked(consumed, 'cancelled', false);
        return undefined;
      }
      this.#lockedContinuationByWindow.set(envelope.windowId, envelope.continuationId);
      return envelope;
    }

    let windowId: number | undefined;
    try {
      const popupUrl = new URL(this.#popupBaseUrl);
      popupUrl.searchParams.set('websitePasskeyUnlock', envelope.continuationId);
      windowId = await this.#windows.open(popupUrl.toString());
      if (!Number.isSafeInteger(windowId) || windowId < 0) throw new Error('Invalid unlock window');
      const attached = await this.#lockedContinuations!.attachWindow(
        envelope.continuationId,
        envelope.workerGeneration,
        windowId,
      );
      if (!attached) throw new Error('Locked continuation changed while opening the window');
      this.#lockedContinuationByWindow.set(windowId, attached.continuationId);
      return attached;
    } catch {
      if (windowId !== undefined) await this.#windows.close?.(windowId).catch(() => undefined);
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: envelope.continuationId,
        workerGeneration: envelope.workerGeneration,
        reason: 'open_failed',
        document: envelope.document,
        bridgeRequestId: envelope.request.bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'unavailable', false);
      return undefined;
    }
  }

  async #captureAvailability(
    document: WebsitePasskeyDocumentContext,
    operation: CanonicalWebsitePasskeyRequest['kind'],
  ): Promise<WebsitePasskeyAvailabilitySnapshot> {
    if (!this.#availability) throw new Error('Website passkey availability is unavailable');
    const snapshot = await this.#availability.capture(document, operation);
    await this.#availability.assertCurrent(snapshot);
    return snapshot;
  }

  async #assertLockedBinding(
    envelope: WebsitePasskeyLockedContinuationEnvelope,
    availability: WebsitePasskeyAvailabilitySnapshot,
  ): Promise<void> {
    if (!this.#availability
        || envelope.accountIdentity !== availability.accountIdentity
        || envelope.serverUrl !== availability.serverUrl
        || envelope.policyGeneration !== availability.policyGeneration) {
      throw new Error('Website passkey locked continuation authorization changed');
    }
    await this.#availability.assertCurrent(availability);
  }

  #scheduleLocked(envelope: WebsitePasskeyLockedContinuationEnvelope): void {
    const previous = this.#lockedTimerByContinuation.get(envelope.continuationId);
    if (previous !== undefined) this.#timers.clear(previous);
    const timer = this.#timers.set(() => {
      void this.#expireLocked(envelope).catch(() => undefined);
    }, Math.max(0, envelope.deadlineAt - this.#now()));
    this.#lockedTimerByContinuation.set(envelope.continuationId, timer);
  }

  async #expireLocked(envelope: WebsitePasskeyLockedContinuationEnvelope): Promise<void> {
    if (this.#now() < envelope.deadlineAt) {
      this.#scheduleLocked(envelope);
      return;
    }
    const consumed = await this.#lockedContinuations?.consume({
      continuationId: envelope.continuationId,
      workerGeneration: envelope.workerGeneration,
      reason: 'expired',
      document: envelope.document,
      bridgeRequestId: envelope.request.bridgeRequestId,
    });
    if (consumed) {
      await this.#finishLocked(consumed, 'expired', true);
      return;
    }
    const current = await this.#lockedContinuations?.find(envelope.document, envelope.request);
    if (current?.state === 'retired' && current.terminal.reason === 'expired') {
      await this.#finishLocked(current.terminal.envelope, 'expired', true);
    }
  }

  async #finishLocked(
    envelope: WebsitePasskeyLockedContinuationEnvelope,
    admission: 'cancelled' | 'expired' | 'unavailable',
    deliver: boolean,
  ): Promise<void> {
    const timer = this.#lockedTimerByContinuation.get(envelope.continuationId);
    if (timer !== undefined) {
      this.#timers.clear(timer);
      this.#lockedTimerByContinuation.delete(envelope.continuationId);
    }
    if (envelope.windowId !== undefined) {
      this.#lockedContinuationByWindow.delete(envelope.windowId);
      await this.#windows.close?.(envelope.windowId).catch(() => undefined);
    }
    if (!deliver) return;
    const channel = this.#channels.get(documentKey(envelope.document));
    if (!channel || !sameDocumentContext(envelope.document, channel.document)) return;
    const message = createWebsitePasskeyPreflightOutcomeMessage(
      envelope.request.bridgeRequestId,
      admission,
    );
    await Promise.resolve(deliverServerMessage(channel, message)).catch(() => undefined);
  }

  async #findExisting(
    document: WebsitePasskeyDocumentContext,
    request: CanonicalWebsitePasskeyRequest,
  ): Promise<PasskeyCeremonyRecord | undefined> {
    const serialized = serializeCanonicalWebsitePasskeyRequest(request);
    for (const runtime of this.#runtimes.values()) {
      if (!sameDocument(runtime.record, document)
          || serializeCanonicalWebsitePasskeyRequest(runtime.record.request) !== serialized) continue;
      const current = await this.#registry.get(runtime.record.ceremonyId);
      if (!current) {
        this.#removeRuntime(runtime.record.ceremonyId);
        continue;
      }
      runtime.record = current;
      return current;
    }
    const terminals = await this.#registry.listRedeliverable();
    const terminal = terminals.find((entry) => sameDocument(entry, document)
      && serializeCanonicalWebsitePasskeyRequest(entry.request) === serialized);
    if (terminal) return terminal;
    const awaiting = await this.#registry.listAwaitingApproval();
    return awaiting.find((entry) => sameDocument(entry, document)
      && serializeCanonicalWebsitePasskeyRequest(entry.request) === serialized);
  }

  async #messageForExisting(
    record: PasskeyCeremonyRecord,
    channel: Channel,
  ): Promise<WebsitePasskeyServerMessage | undefined> {
    const { document } = channel;
    let runtime = this.#runtimes.get(record.ceremonyId);
    if (isTerminal(record)) {
      return this.#messageForTerminal(record, runtime);
    }
    const options = {
      allowVaultGenerationChange: record.state === 'executing' && record.request.kind === 'create',
    };
    try {
      let activeRuntime = runtime;
      if (activeRuntime) {
        await this.#security.assertCurrent(activeRuntime.security, options);
      } else {
        const security = await this.#security.assertBindingCurrent(
          bindingOf(record),
          document,
          { ...options, operation: record.request.kind },
        );
        await this.#security.assertCurrent(security, options);
        if (!sameRecoveredBinding(record, security, options.allowVaultGenerationChange === true)) {
          throw new Error('Website passkey binding changed');
        }
        activeRuntime = { record, security, channel, unlockedFromLocked: false };
        this.#runtimes.set(record.ceremonyId, activeRuntime);
        runtime = activeRuntime;
        this.#schedule(activeRuntime);
      }
      if (record.state === 'awaitingApproval'
          && activeRuntime.windowId === undefined
          && !isConditionalGet(record.request)
          && this.#channels.has(recordDocumentKey(record))) {
        const terminal = await this.#openApproval(activeRuntime, record);
        if (terminal) {
          return this.#messageForTerminal(terminal, activeRuntime);
          }
      }
      activeRuntime.channel = channel;
      return activeMessage(record);
    } catch {
      const terminal = await this.#registry.abort(record.ceremonyId, record.request.bridgeRequestId);
      if (!terminal) {
        const current = await this.#registry.get(record.ceremonyId);
        return isTerminal(current)
          ? this.#messageForTerminal(current, runtime)
          : acceptedMessage(record);
      }
      return this.#messageForTerminal(terminal, runtime);
    }
  }

  async #messageForTerminal(
    terminal: TerminalPasskeyCeremony,
    runtime: CeremonyRuntime<Proof> | undefined,
  ): Promise<WebsitePasskeyOutcomeMessage | undefined> {
    if (terminal.state === 'completed') {
      if (runtime) await this.#finish(runtime, terminal);
      else await this.#deliverTerminal(terminal);
      return undefined;
    }
    if (runtime) await this.#finish(runtime, terminal, false);
    return outcomeMessage(terminal);
  }

  async #openApproval(
    runtime: CeremonyRuntime<Proof>,
    ceremony: AwaitingPasskeyCeremony,
  ): Promise<TerminalPasskeyCeremony | undefined> {
    if (runtime.windowId !== undefined) return undefined;
    let openedWindowId: number | undefined;
    try {
      const popupUrl = new URL(this.#popupBaseUrl);
      popupUrl.searchParams.set('websitePasskey', ceremony.ceremonyId);
      const windowId = await this.#windows.open(popupUrl.toString());
      if (!Number.isSafeInteger(windowId) || windowId < 0) throw new Error('Invalid approval window');
      openedWindowId = windowId;
      await this.#security.assertCurrent(runtime.security);
      const current = await this.#registry.get(ceremony.ceremonyId);
      await this.#security.assertCurrent(runtime.security);
      if (!current || current.state !== 'awaitingApproval') {
        await this.#windows.close?.(windowId).catch(() => undefined);
        return isTerminal(current) ? current : undefined;
      }
      runtime.windowId = windowId;
      runtime.record = current;
      this.#ceremonyByWindow.set(windowId, ceremony.ceremonyId);
      return undefined;
    } catch {
      if (openedWindowId !== undefined) {
        await this.#windows.close?.(openedWindowId).catch(() => undefined);
      }
      const terminal = await this.#registry.abort(
        ceremony.ceremonyId,
        ceremony.request.bridgeRequestId,
      );
      const settled = terminal ?? asTerminal(await this.#registry.get(ceremony.ceremonyId));
      if (settled) runtime.record = settled;
      return settled;
    }
  }

  async #execute(
    runtime: CeremonyRuntime<Proof>,
    executing: ExecutingPasskeyCeremony,
    selection: WebsitePasskeySelection,
  ): Promise<WebsitePasskeyDecisionOutcome> {
    const execution = runtime.execution!;
    let privateCallStarted = false;
    let terminal: TerminalPasskeyCeremony | undefined;
    try {
      await this.#security.assertCurrent(runtime.security);
      const current = await this.#registry.get(executing.ceremonyId);
      await this.#security.assertCurrent(runtime.security);
      if (!current || current.state !== 'executing' || current.executionId !== executing.executionId) {
        return terminalDecision(current);
      }
      privateCallStarted = true;
      if (executing.request.kind === 'get' && selection.kind === 'credential') {
        const result = await abortable(this.#vault.executeGet(
          executing.request,
          executing.origin,
          selection.credentialId,
          runtime.security,
          execution.controller.signal,
        ), execution.controller.signal);
        await this.#security.assertCurrent(runtime.security);
        if (!result) {
          terminal = await this.#registry.markFailed(executing.ceremonyId, executing.executionId, 'no_match');
        } else {
          await this.#security.assertCurrent(runtime.security);
          terminal = await this.#registry.complete(executing.ceremonyId, executing.executionId, result);
        }
      } else if (executing.request.kind === 'create' && (selection.kind === 'new' || selection.kind === 'target')) {
        const result = await abortable(this.#vault.executeCreate(
          executing.request,
          executing.origin,
          selection,
          runtime.security,
          execution.controller.signal,
        ), execution.controller.signal);
        if (result.status === 'outcome_unknown') {
          terminal = await this.#registry.markUncertain(executing.ceremonyId, executing.executionId, 'execution_failed');
        } else if (result.status === 'not_committed') {
          terminal = await this.#registry.markFailed(executing.ceremonyId, executing.executionId, result.reason);
        } else {
          terminal = await this.#registry.complete(executing.ceremonyId, executing.executionId, result.result);
        }
      }
    } catch {
      const reason: PasskeyCeremonyTerminalReason = execution.deadlineFired ? 'expired' : 'execution_failed';
      terminal = executing.request.kind === 'create' && privateCallStarted
        ? await this.#registry.markUncertain(executing.ceremonyId, executing.executionId, reason)
        : await this.#registry.markFailed(executing.ceremonyId, executing.executionId, reason);
    }
    if (!terminal) terminal = asTerminal(await this.#registry.get(executing.ceremonyId));
    if (!terminal) return 'unavailable';
    await this.#finish(runtime, terminal);
    return terminalDecision(terminal);
  }

  async #cancelFromDocument(channel: Channel, ceremonyId: string, bridgeRequestId: string): Promise<void> {
    const record = await this.#registry.get(ceremonyId);
    if (!record) {
      const pending = await this.#lockedContinuations?.readPending();
      if (!pending || pending.continuationId !== ceremonyId) return;
      const consumed = await this.#lockedContinuations!.consume({
        continuationId: ceremonyId,
        workerGeneration: pending.workerGeneration,
        reason: 'cancelled',
        document: channel.document,
        bridgeRequestId,
      });
      if (consumed) await this.#finishLocked(consumed, 'cancelled', false);
      return;
    }
    if (!sameDocument(record, channel.document) || record.request.bridgeRequestId !== bridgeRequestId) return;
    const runtime = this.#runtimes.get(ceremonyId);
    const terminal = await this.#registry.abort(ceremonyId, bridgeRequestId);
    runtime?.execution?.controller.abort();
    if (terminal && runtime) await this.#finish(runtime, terminal);
    else if (terminal) await this.#deliverTerminal(terminal);
  }

  async #selectConditional(
    channel: Channel,
    ceremonyId: string,
    bridgeRequestId: string,
    credentialId: string,
  ): Promise<boolean> {
    const record = await this.#registry.get(ceremonyId);
    const runtime = this.#runtimes.get(ceremonyId);
    const selection: WebsitePasskeySelection = { kind: 'credential', credentialId };
    if (!record
        || record.state !== 'awaitingApproval'
        || !isConditionalGet(record.request)
        || !sameDocument(record, channel.document)
        || record.request.bridgeRequestId !== bridgeRequestId
        || !runtime
        || !selectionMatches(record, selection)) return false;
    runtime.channel = channel;
    try {
      await this.#security.assertCurrent(runtime.security);
    } catch {
      await this.#abortCeremony(record);
      return true;
    }
    await this.approve(ceremonyId, selection);
    return true;
  }

  async #acknowledge(
    channel: Channel,
    ceremonyId: string,
    bridgeRequestId: string,
    outcomeId: string,
  ): Promise<boolean> {
    const record = await this.#registry.get(ceremonyId);
    if (!record || !isTerminal(record) || !sameDocument(record, channel.document)) return false;
    if (record.request.bridgeRequestId !== bridgeRequestId || record.outcomeId !== outcomeId) return false;
    const acknowledged = await this.#registry.acknowledge(ceremonyId, bridgeRequestId, outcomeId);
    if (acknowledged) this.#removeRuntime(ceremonyId);
    return acknowledged;
  }

  async #fallbackPopupCeremony(
    ceremonyId: string,
    reason: Extract<WebsitePasskeyFallbackReason, 'user_selected_browser' | 'excluded_domain'>,
  ): Promise<WebsitePasskeyDecisionOutcome> {
    const record = await this.#registry.get(ceremonyId);
    if (!record || record.state !== 'awaitingApproval') return terminalDecision(record);
    const terminal = await this.#registry.markFallback(ceremonyId, record.request.bridgeRequestId, reason);
    if (!terminal) return terminalDecision(await this.#registry.get(ceremonyId));
    const runtime = this.#runtimes.get(ceremonyId);
    if (runtime) await this.#finish(runtime, terminal);
    else await this.#deliverTerminal(terminal);
    return 'fallback';
  }

  async #abortPopupCeremony(ceremonyId: string): Promise<WebsitePasskeyDecisionOutcome> {
    const record = await this.#registry.get(ceremonyId);
    if (!record || isTerminal(record)) return terminalDecision(record);
    return this.#abortCeremony(record);
  }

  async #abortCeremony(record: AwaitingPasskeyCeremony | ExecutingPasskeyCeremony): Promise<WebsitePasskeyDecisionOutcome> {
    const runtime = this.#runtimes.get(record.ceremonyId);
    const terminal = await this.#registry.abort(record.ceremonyId, record.request.bridgeRequestId);
    runtime?.execution?.controller.abort();
    if (!terminal) return terminalDecision(await this.#registry.get(record.ceremonyId));
    if (runtime) await this.#finish(runtime, terminal);
    else await this.#deliverTerminal(terminal);
    return terminalDecision(terminal);
  }

  async #invalidateCeremony(
    record: AwaitingPasskeyCeremony | ExecutingPasskeyCeremony,
  ): Promise<WebsitePasskeyDecisionOutcome> {
    const runtime = this.#runtimes.get(record.ceremonyId);
    const terminal = await this.#registry.invalidateContext(record.ceremonyId);
    runtime?.execution?.controller.abort();
    if (!terminal) return terminalDecision(await this.#registry.get(record.ceremonyId));
    if (runtime) await this.#finish(runtime, terminal);
    else await this.#deliverTerminal(terminal);
    return terminalDecision(terminal);
  }

  #schedule(runtime: CeremonyRuntime<Proof>): void {
    if (runtime.timer !== undefined) this.#timers.clear(runtime.timer);
    const delay = Math.max(0, runtime.record.deadlineAt - this.#now());
    runtime.timer = this.#timers.set(() => {
      void this.#deadline(runtime.record.ceremonyId).catch(() => undefined);
    }, delay);
  }

  async #deadline(ceremonyId: string): Promise<void> {
    const runtime = this.#runtimes.get(ceremonyId);
    if (runtime && this.#now() < runtime.record.deadlineAt) {
      this.#schedule(runtime);
      return;
    }
    if (runtime?.execution) {
      runtime.execution.deadlineFired = true;
    }
    const record = await this.#registry.get(ceremonyId);
    if (!record) {
      this.#removeRuntime(ceremonyId);
      return;
    }
    if (!isTerminal(record)) {
      if (runtime) {
        runtime.record = record;
        if (runtime.execution) runtime.execution.deadlineFired = false;
        this.#schedule(runtime);
      }
      return;
    }
    runtime?.execution?.controller.abort();
    if (runtime) await this.#finish(runtime, record);
    else await this.#deliverTerminal(record);
  }

  async #finish(
    runtime: CeremonyRuntime<Proof>,
    terminal: TerminalPasskeyCeremony,
    deliver = true,
  ): Promise<void> {
    if (this.#runtimes.get(terminal.ceremonyId) !== runtime) return;
    this.#runtimes.delete(terminal.ceremonyId);
    runtime.record = terminal;
    if (runtime.timer !== undefined) {
      this.#timers.clear(runtime.timer);
      delete runtime.timer;
    }
    const execution = runtime.execution;
    delete runtime.execution;
    execution?.controller.abort();
    if (runtime.windowId !== undefined) {
      const windowId = runtime.windowId;
      this.#ceremonyByWindow.delete(windowId);
      delete runtime.windowId;
      await this.#windows.close?.(windowId).catch(() => undefined);
    }
    if (!deliver) return;
    if (terminal.state === 'completed') {
      await this.#deliverCompletedTerminal(runtime, terminal);
      return;
    }
    await this.#deliverTerminal(terminal);
  }

  async #deliverCompletedTerminal(
    runtime: CeremonyRuntime<Proof>,
    terminal: CompletedPasskeyCeremony,
  ): Promise<boolean> {
    try {
      const options = { allowVaultGenerationChange: terminal.request.kind === 'create' };
      await this.#security.assertCurrent(runtime.security, options);
      await this.#deliverToExactChannel(
        runtime.channel,
        terminal,
        () => this.#security.assertDeliveryCurrent(runtime.security, options),
      );
      return true;
    } catch {
      await this.#retireUndeliverableTerminal(terminal);
      return false;
    }
  }

  async #deliverRecoveredCompletedTerminal(terminal: CompletedPasskeyCeremony): Promise<boolean> {
    const channel = this.#channels.get(recordDocumentKey(terminal));
    if (!channel || !sameDocument(terminal, channel.document)) return false;
    try {
      const options = { allowVaultGenerationChange: terminal.request.kind === 'create' };
      const security = await this.#security.assertBindingCurrent(
        bindingOf(terminal),
        channel.document,
        { ...options, operation: terminal.request.kind },
      );
      await this.#deliverToExactChannel(
        channel,
        terminal,
        () => this.#security.assertDeliveryCurrent(security, options),
      );
      return true;
    } catch {
      await this.#retireUndeliverableTerminal(terminal);
      return false;
    }
  }

  async #deliverToExactChannel(
    channel: Channel,
    terminal: CompletedPasskeyCeremony,
    assertCurrent: () => void,
  ): Promise<void> {
    const key = recordDocumentKey(terminal);
    if (this.#channels.get(key)?.token !== channel.token
        || documentKey(channel.document) !== key
        || !sameDocument(terminal, channel.document)) {
      throw new Error('Website passkey document binding changed');
    }
    await channel.deliver(outcomeMessage(terminal), assertCurrent);
  }

  async #retireUndeliverableTerminal(terminal: TerminalPasskeyCeremony): Promise<void> {
    try {
      await this.#registry.acknowledge(
        terminal.ceremonyId,
        terminal.request.bridgeRequestId,
        terminal.outcomeId,
      );
    } catch {
      // Storage recovery will retain the terminal if the exact acknowledgement cannot be persisted.
    }
  }

  async #deliverTerminal(terminal: TerminalPasskeyCeremony): Promise<boolean> {
    if (terminal.state === 'completed') return this.#deliverRecoveredCompletedTerminal(terminal);
    const channel = this.#channels.get(recordDocumentKey(terminal));
    if (!channel || !sameDocument(terminal, channel.document)) return false;
    const message = outcomeMessage(terminal);
    try {
      await channel.deliver(message);
      return true;
    } catch {
      return false;
    }
  }

  #outcomeMessage(terminal: TerminalPasskeyCeremony): WebsitePasskeyOutcomeMessage {
    return outcomeMessage(terminal);
  }

  #removeRuntime(ceremonyId: string): void {
    const runtime = this.#runtimes.get(ceremonyId);
    if (!runtime) return;
    if (runtime.timer !== undefined) this.#timers.clear(runtime.timer);
    if (runtime.windowId !== undefined) this.#ceremonyByWindow.delete(runtime.windowId);
    runtime.execution?.controller.abort();
    this.#runtimes.delete(ceremonyId);
  }

  #shouldOpenApproval(channel: Channel, request: CanonicalWebsitePasskeyRequest): boolean {
    if (isConditionalGet(request)) return false;
    const key = documentKey(channel.document);
    const current = this.#channels.get(key);
    if (!current) return false;
    if (current.token === channel.token) return true;
    const preparing = this.#preparing.get(key);
    return preparing?.resumeRequested === true
      && preparing.serializedRequest === serializeCanonicalWebsitePasskeyRequest(request);
  }
}

function activeMessage(
  record: AwaitingPasskeyCeremony | ExecutingPasskeyCeremony,
): WebsitePasskeyAcceptedMessage | WebsitePasskeyConditionalActiveMessage {
  if (record.state === 'awaitingApproval' && isConditionalGet(record.request)) {
    return {
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'conditionalActive',
      ceremonyId: record.ceremonyId,
      bridgeRequestId: record.request.bridgeRequestId,
      deadlineAt: record.deadlineAt,
      candidates: record.candidates.map(({ id, name, username }) => ({
        id,
        name,
        ...(username === undefined ? {} : { username }),
      })),
    };
  }
  return acceptedMessage(record);
}

function unlockPendingMessage(
  envelope: WebsitePasskeyLockedContinuationEnvelope,
): WebsitePasskeyUnlockPendingMessage {
  return Object.freeze({
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'unlockPending',
    continuationId: envelope.continuationId,
    bridgeRequestId: envelope.request.bridgeRequestId,
    deadlineAt: envelope.deadlineAt,
  });
}

function detachedChannel(document: WebsitePasskeyDocumentContext): Channel {
  return Object.freeze({
    token: Object.freeze({}),
    document,
    deliver: () => { throw new Error('Website passkey document is disconnected'); },
    deliverControl: () => { throw new Error('Website passkey document is disconnected'); },
  });
}

function deliverServerMessage(
  channel: Channel,
  message: Exclude<WebsitePasskeyServerMessage, { readonly type: 'config' }>,
): void | Promise<void> {
  if (message.type === 'outcome') return channel.deliver(message);
  if (!channel.deliverControl) throw new Error('Website passkey control delivery is unavailable');
  return channel.deliverControl(message);
}

function acceptedMessage(record: AwaitingPasskeyCeremony | ExecutingPasskeyCeremony): WebsitePasskeyAcceptedMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'accepted',
    ceremonyId: record.ceremonyId,
    bridgeRequestId: record.request.bridgeRequestId,
    deadlineAt: record.deadlineAt,
  };
}

function outcomeMessage(record: TerminalPasskeyCeremony): WebsitePasskeyOutcomeMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: record.ceremonyId,
    bridgeRequestId: record.request.bridgeRequestId,
    outcomeId: record.outcomeId,
    outcome: outcomeOf(record),
  };
}

function outcomeOf(record: TerminalPasskeyCeremony): WebsitePasskeyOutcome {
  if (record.state === 'completed') return { status: 'success', result: record.result };
  if (record.state === 'fallback') return { status: 'fallback', reason: fallbackReason(record.reason) };
  if (record.state === 'uncertain') return fixedError('UnknownError');
  if (record.reason === 'cancelled') return fixedError('AbortError');
  if (record.reason === 'expired') return fixedError('NotAllowedError', 'The operation timed out.');
  if (record.reason === 'invalid_state') return fixedError('InvalidStateError');
  if (record.reason === 'not_allowed') return fixedError('NotAllowedError');
  if (record.reason === 'not_supported') return fixedError('NotSupportedError');
  if (record.reason === 'operation_failed') return fixedError('UnknownError');
  if (record.reason === 'context_changed'
      || record.reason === 'session_changed'
      || record.reason === 'account_changed'
      || record.reason === 'cache_changed') {
    return fixedError('NotAllowedError');
  }
  return fixedError('UnknownError');
}

function fixedError(
  name: 'AbortError' | 'InvalidStateError' | 'NotAllowedError' | 'NotSupportedError' | 'UnknownError',
  message = name === 'AbortError'
    ? 'The operation was aborted.'
    : name === 'InvalidStateError'
      ? 'The request conflicts with an existing credential.'
      : name === 'NotAllowedError'
        ? 'The request is no longer valid.'
        : name === 'NotSupportedError'
          ? 'The requested operation is not supported.'
          : 'The operation could not be completed.',
): WebsitePasskeyOutcome {
  return { status: 'error', error: { name, message } };
}

function fallbackReason(reason: WebsitePasskeyFallbackReason): WebsitePasskeyFallbackReason {
  switch (reason) {
    case 'unsupported':
    case 'no_match':
    case 'excluded_domain':
    case 'user_selected_browser':
      return reason;
  }
}

function approvalModel(record: AwaitingPasskeyCeremony | ExecutingPasskeyCeremony): WebsitePasskeyApprovalModel {
  const choices = record.candidates.map(({ id, name, username }) => ({
    id,
    name,
    ...(username === undefined ? {} : { username }),
  }));
  const base = {
    ceremonyId: record.ceremonyId,
    origin: record.origin,
    rpId: rpIdOf(record.request),
    state: record.state === 'executing' ? 'executing' as const : 'awaiting' as const,
  };
  return record.request.kind === 'get'
    ? { ...base, kind: 'get', candidates: choices }
    : { ...base, kind: 'create', targets: choices };
}

function selectionMatches(
  record: AwaitingPasskeyCeremony | ExecutingPasskeyCeremony,
  selection: WebsitePasskeySelection,
): boolean {
  if (record.request.kind === 'get') {
    return selection.kind === 'credential'
      && record.candidates.some((candidate) => candidate.kind === 'credential' && candidate.id === selection.credentialId);
  }
  if (selection.kind === 'new') return true;
  return selection.kind === 'target'
    && record.candidates.some((candidate) => candidate.kind === 'target' && candidate.id === selection.cipherId);
}

function isConditionalGet(
  request: CanonicalWebsitePasskeyRequest,
): request is CanonicalWebsitePasskeyGetRequest & { readonly mediation: 'conditional' } {
  return request.kind === 'get' && request.mediation === 'conditional';
}

function terminalDecision(record: PasskeyCeremonyRecord | undefined): WebsitePasskeyDecisionOutcome {
  if (!record) return 'unavailable';
  switch (record.state) {
    case 'completed': return 'completed';
    case 'fallback': return 'fallback';
    case 'failed': return 'failed';
    case 'uncertain': return 'uncertain';
    default: return 'unavailable';
  }
}

function sameDocument(record: PasskeyCeremonyRecord, document: WebsitePasskeyDocumentContext): boolean {
  return record.tabId === document.tabId
    && record.frameId === document.frameId
    && record.documentId === document.documentId
    && record.frameUrl === document.url
    && record.origin === document.origin;
}

function sameDocumentContext(
  left: WebsitePasskeyDocumentContext,
  right: WebsitePasskeyDocumentContext,
): boolean {
  return documentKey(left) === documentKey(right);
}

function sameRecoveredBinding<Proof>(
  record: PasskeyCeremonyRecord,
  security: WebsitePasskeySecuritySnapshot<Proof>,
  allowVaultGenerationChange: boolean,
): boolean {
  return record.sessionBindingId === security.sessionBindingId
    && record.accountIdentity === security.accountIdentity
    && record.serverUrl === security.serverUrl
    && record.policyGeneration === security.policyGeneration
    && (allowVaultGenerationChange || (
      record.rawGeneration === security.rawGeneration
      && record.snapshotGeneration === security.snapshotGeneration
    ));
}

function documentKey(value: Pick<WebsitePasskeyDocumentContext, 'tabId' | 'frameId' | 'documentId' | 'url' | 'origin'>): string {
  return JSON.stringify([value.tabId, value.frameId, value.documentId, value.url, value.origin]);
}

function recordDocumentKey(value: PasskeyCeremonyRecord): string {
  return JSON.stringify([value.tabId, value.frameId, value.documentId, value.frameUrl, value.origin]);
}

function rpIdOf(request: CanonicalWebsitePasskeyRequest): string {
  return request.kind === 'get' ? request.rpId : request.rp.id;
}

function requiresUserVerification(request: CanonicalWebsitePasskeyRequest): boolean {
  return request.kind === 'get'
    ? request.userVerification === 'required'
    : request.authenticatorSelection.userVerification === 'required';
}

function bindingOf(record: PasskeyCeremonyRecord): WebsitePasskeySecurityBinding {
  return {
    sessionBindingId: record.sessionBindingId,
    accountIdentity: record.accountIdentity,
    serverUrl: record.serverUrl,
    rawGeneration: record.rawGeneration,
    ...(record.snapshotGeneration === undefined ? {} : { snapshotGeneration: record.snapshotGeneration }),
    policyGeneration: record.policyGeneration,
  };
}

function isTerminal(value: PasskeyCeremonyRecord | undefined): value is TerminalPasskeyCeremony {
  return value !== undefined
    && value.state !== 'awaitingApproval'
    && value.state !== 'executing';
}

function asTerminal(value: PasskeyCeremonyRecord | undefined): TerminalPasskeyCeremony | undefined {
  return isTerminal(value) ? value : undefined;
}

function abortable<Value>(promise: Promise<Value>, signal: AbortSignal): Promise<Value> {
  if (signal.aborted) return Promise.reject(new DOMException('The operation was aborted.', 'AbortError'));
  return new Promise<Value>((resolve, reject) => {
    const abort = () => reject(new DOMException('The operation was aborted.', 'AbortError'));
    signal.addEventListener('abort', abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

function absoluteDeadline(now: number, timeout: number): number {
  const deadline = now + timeout;
  return Number.isSafeInteger(deadline) ? deadline : Number.MAX_SAFE_INTEGER;
}

function boundedDeadline(now: number, timeout: number, receivedDeadlineAt: number | undefined): number {
  const localDeadlineAt = absoluteDeadline(now, timeout);
  return receivedDeadlineAt !== undefined
    && Number.isSafeInteger(receivedDeadlineAt)
    && receivedDeadlineAt > 0
    ? Math.min(localDeadlineAt, receivedDeadlineAt)
    : localDeadlineAt;
}
