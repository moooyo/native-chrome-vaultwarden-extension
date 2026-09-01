import {
  WEBSITE_PASSKEY_PORT_NAME,
  WEBSITE_PASSKEY_PORT_VERSION,
  createWebsitePasskeyPreflightOutcomeMessage,
  parseWebsitePasskeyClientMessage,
  parseWebsitePasskeyServerMessage,
  serializeCanonicalWebsitePasskeyRequest,
  type CanonicalWebsitePasskeyRequest,
  type WebsitePasskeyClientMessage,
  type WebsitePasskeyServerMessage,
  type WebsitePasskeyUnsupportedReason,
} from '../messaging/website-passkey-port.js';
import { createRequestContext, type MessageSenderInfo } from './sender-guard.js';
import type {
  WebsitePasskeyCoordinator,
  WebsitePasskeyDocumentConnection,
  WebsitePasskeyDocumentContext,
} from './website-passkey-coordinator.js';
import type { VaultReleaseGate, VaultReleaseLease } from './vault-release-gate.js';

const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_PORT_BINDINGS = 16;
const MAX_QUEUED_MESSAGES = 32;

export interface WebsitePasskeyPortEvent<Listener> {
  addListener(listener: Listener): void;
  removeListener?(listener: Listener): void;
}

export interface WebsitePasskeyPortLike {
  readonly name: string;
  readonly sender?: MessageSenderInfo;
  readonly onMessage: WebsitePasskeyPortEvent<(message: unknown) => void>;
  readonly onDisconnect: WebsitePasskeyPortEvent<() => void>;
  postMessage(message: WebsitePasskeyServerMessage): void;
  disconnect(): void;
}

type Coordinator = Pick<WebsitePasskeyCoordinator<unknown>, 'connect'>;

interface BoundRequest {
  readonly bridgeRequestId: string;
  readonly serializedRequest: string;
  ceremonyId?: string;
  unlockContinuationId?: string;
  outcomeId?: string;
  releaseLease: VaultReleaseLease | undefined;
}

interface AcknowledgedOutcome {
  readonly ceremonyId: string;
  readonly outcomeId: string;
}

interface PortState {
  active: boolean;
  generation: number;
  configured: boolean;
  enabled: boolean;
  queued: number;
  readonly bindings: Map<string, BoundRequest>;
  readonly acknowledged: Map<string, AcknowledgedOutcome>;
  tail: Promise<void>;
  controlTail: Promise<void>;
}

class PortBindingError extends Error {}

export class WebsitePasskeyPortHandler {
  constructor(
    private readonly coordinator: Coordinator,
    private readonly ready: PromiseLike<void> = Promise.resolve(),
    private readonly now: () => number = Date.now,
    private readonly onDocumentDisconnected?: (
      document: WebsitePasskeyDocumentContext,
    ) => void | Promise<void>,
    private readonly vaultReleaseGate?: Pick<
      VaultReleaseGate,
      'capture' | 'checkpoint' | 'assertAuthorities' | 'assert'
    > & Partial<Pick<VaultReleaseGate, 'settlePendingAction'>>,
  ) {}

  handle(port: WebsitePasskeyPortLike, extensionBaseUrl: string, extensionId: string): boolean {
    const document = trustedDocument(port, extensionBaseUrl, extensionId);
    if (!document) {
      safeDisconnect(port);
      return false;
    }

    const state: PortState = {
      active: true,
      generation: 1,
      configured: false,
      enabled: false,
      queued: 0,
      bindings: new Map(),
      acknowledged: new Map(),
      tail: Promise.resolve(this.ready),
      controlTail: Promise.resolve(this.ready),
    };
    let connection: WebsitePasskeyDocumentConnection | undefined;

    const onMessage = (value: unknown): void => {
      if (!state.active || !connection) return;
      let decision;
      try {
        decision = parseWebsitePasskeyClientMessage(value);
      } catch {
        this.close(port, state, connection, onMessage, onDisconnect, true);
        return;
      }
      const receivedDeadlineAt = decision.status === 'fallback'
        ? absoluteDeadline(this.now(), decision.request.timeout)
        : decision.message.type === 'begin'
          ? absoluteDeadline(this.now(), decision.message.request.timeout)
          : undefined;
      if (state.queued >= MAX_QUEUED_MESSAGES) {
        this.close(port, state, connection, onMessage, onDisconnect, true);
        return;
      }
      const generation = state.generation;
      state.queued += 1;
      const control = decision.status === 'accepted'
        && (decision.message.type === 'cancel' || decision.message.type === 'ack');
      const previous = control ? state.controlTail : state.tail;
      const next = previous.then(async () => {
        if (!isCurrent(state, generation) || !connection) return;
        if (decision.status === 'fallback') {
          await this.handleBegin(
            port,
            state,
            connection,
            decision.request,
            decision.reason,
            receivedDeadlineAt,
            generation,
            onMessage,
            onDisconnect,
          );
          return;
        }
        await this.handleMessage(
          port,
          state,
          connection,
          decision.message,
          receivedDeadlineAt,
          generation,
          onMessage,
          onDisconnect,
        );
      });
      const settled = next.then(
        () => { if (state.queued > 0) state.queued -= 1; },
        async () => {
          await this.vaultReleaseGate?.settlePendingAction?.();
          if (state.queued > 0) state.queued -= 1;
          if (isCurrent(state, generation) && connection) {
            this.close(port, state, connection, onMessage, onDisconnect, true);
          }
        },
      );
      if (control) state.controlTail = settled;
      else state.tail = settled;
    };

    const onDisconnect = (): void => {
      if (!connection) return;
      this.close(port, state, connection, onMessage, onDisconnect, false);
      void Promise.resolve(this.onDocumentDisconnected?.(document)).catch(() => undefined);
    };

    try {
      const deliver = async (
        message: Exclude<WebsitePasskeyServerMessage, { readonly type: 'config' }>,
        assertCurrent?: () => void,
      ): Promise<void> => {
        const binding = state.bindings.get(message.bridgeRequestId);
        if (!state.active || !binding || !bindServerResponse(binding, message)) return;
        try {
          if ((message.type === 'accepted' || message.type === 'conditionalActive')
              && this.vaultReleaseGate && !binding.releaseLease) {
            binding.releaseLease = this.vaultReleaseGate.capture();
          }
          if (message.type === 'outcome'
              && message.outcome.status === 'success'
              && this.vaultReleaseGate) {
            binding.releaseLease ??= this.vaultReleaseGate.capture();
            const releaseProof = await this.vaultReleaseGate.checkpoint(binding.releaseLease);
            if (!state.active) throw new PortBindingError('port disconnected during release');
            this.vaultReleaseGate.assertAuthorities(releaseProof, () => assertCurrent?.());
            this.vaultReleaseGate.assert(releaseProof);
          } else assertCurrent?.();
        } catch (error) {
          await this.vaultReleaseGate?.settlePendingAction?.();
          if (connection) this.close(port, state, connection, onMessage, onDisconnect, true);
          throw error;
        }
        if (!safePost(port, message) && connection) {
          this.close(port, state, connection, onMessage, onDisconnect, true);
        }
        if (message.type === 'preflightOutcome') state.bindings.delete(message.bridgeRequestId);
      };
      connection = this.coordinator.connect(document, deliver, deliver);
      port.onMessage.addListener(onMessage);
      port.onDisconnect.addListener(onDisconnect);
    } catch {
      connection?.close();
      safeDisconnect(port);
      return false;
    }
    return true;
  }

  private async handleMessage(
    port: WebsitePasskeyPortLike,
    state: PortState,
    connection: WebsitePasskeyDocumentConnection,
    message: WebsitePasskeyClientMessage,
    receivedDeadlineAt: number | undefined,
    generation: number,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): Promise<void> {
    switch (message.type) {
      case 'hello': {
        const enabled = await connection.getConfig();
        if (!isCurrent(state, generation)) return;
        state.configured = true;
        state.enabled = enabled;
        if (!safePost(port, {
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: 'config',
          enabled,
        })) this.close(port, state, connection, onMessage, onDisconnect, true);
        return;
      }
      case 'begin':
        await this.handleBegin(
          port,
          state,
          connection,
          message.request,
          undefined,
          receivedDeadlineAt,
          generation,
          onMessage,
          onDisconnect,
        );
        return;
      case 'resume':
        await this.handleResume(
          port, state, connection, message.request, generation, onMessage, onDisconnect,
        );
        return;
      case 'cancel': {
        requireConfigured(state);
        requireExactBinding(state, message.ceremonyId, message.bridgeRequestId);
        await connection.cancel(message.ceremonyId, message.bridgeRequestId);
        return;
      }
      case 'conditionalSelect': {
        requireConfigured(state);
        requireExactBinding(state, message.ceremonyId, message.bridgeRequestId);
        const selected = await connection.selectConditional(
          message.ceremonyId,
          message.bridgeRequestId,
          message.credentialId,
        );
        if (!selected) throw new PortBindingError('conditional selection is not active');
        return;
      }
      case 'ack': {
        requireConfigured(state);
        const previous = state.acknowledged.get(message.bridgeRequestId);
        if (previous) {
          if (previous.ceremonyId !== message.ceremonyId || previous.outcomeId !== message.outcomeId) {
            throw new PortBindingError('acknowledgement binding changed');
          }
          return;
        }
        requireExactBinding(state, message.ceremonyId, message.bridgeRequestId, message.outcomeId);
        const acknowledged = await connection.acknowledge(
          message.ceremonyId,
          message.bridgeRequestId,
          message.outcomeId,
        );
        if (!isCurrent(state, generation)) return;
        if (acknowledged) {
          state.bindings.delete(message.bridgeRequestId);
          rememberAcknowledged(state, message.bridgeRequestId, {
            ceremonyId: message.ceremonyId,
            outcomeId: message.outcomeId,
          });
        }
      }
    }
  }

  private async handleBegin(
    port: WebsitePasskeyPortLike,
    state: PortState,
    connection: WebsitePasskeyDocumentConnection,
    request: CanonicalWebsitePasskeyRequest,
    unsupportedReason: WebsitePasskeyUnsupportedReason | undefined,
    receivedDeadlineAt: number | undefined,
    generation: number,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): Promise<void> {
    requireConfigured(state);
    const binding = bindBegin(state, request);
    let response: WebsitePasskeyServerMessage | undefined;
    if (!state.enabled) {
      response = createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    } else {
      response = await connection.begin(request, unsupportedReason, receivedDeadlineAt);
    }
    if (!isCurrent(state, generation) || state.bindings.get(request.bridgeRequestId) !== binding) return;
    response ??= createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    if ((response.type === 'accepted' || response.type === 'conditionalActive')
        && this.vaultReleaseGate && !binding.releaseLease) {
      binding.releaseLease = this.vaultReleaseGate.capture();
    }
    this.postBoundResponse(port, state, connection, request, binding, response, onMessage, onDisconnect);
  }

  private async handleResume(
    port: WebsitePasskeyPortLike,
    state: PortState,
    connection: WebsitePasskeyDocumentConnection,
    request: CanonicalWebsitePasskeyRequest,
    generation: number,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): Promise<void> {
    requireConfigured(state);
    const binding = bindBegin(state, request);
    const response = await connection.resume(request)
      ?? createWebsitePasskeyPreflightOutcomeMessage(request.bridgeRequestId, 'busy');
    if ((response.type === 'accepted' || response.type === 'conditionalActive')
        && this.vaultReleaseGate && !binding.releaseLease) {
      binding.releaseLease = this.vaultReleaseGate.capture();
    }
    if (!isCurrent(state, generation) || state.bindings.get(request.bridgeRequestId) !== binding) return;
    this.postBoundResponse(port, state, connection, request, binding, response, onMessage, onDisconnect);
  }

  private postBoundResponse(
    port: WebsitePasskeyPortLike,
    state: PortState,
    connection: WebsitePasskeyDocumentConnection,
    request: CanonicalWebsitePasskeyRequest,
    binding: BoundRequest,
    response: WebsitePasskeyServerMessage | undefined,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): void {
    if (!response || response.type === 'config' || !bindServerResponse(binding, response)) {
      this.close(port, state, connection, onMessage, onDisconnect, true);
      return;
    }
    if (!safePost(port, response)) {
      this.close(port, state, connection, onMessage, onDisconnect, true);
      return;
    }
    if (response.type === 'preflightOutcome') state.bindings.delete(request.bridgeRequestId);
  }

  private close(
    port: WebsitePasskeyPortLike,
    state: PortState,
    connection: WebsitePasskeyDocumentConnection,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
    disconnect: boolean,
  ): void {
    if (!state.active) return;
    state.active = false;
    state.generation += 1;
    state.bindings.clear();
    state.acknowledged.clear();
    removeListener(port.onMessage, onMessage);
    removeListener(port.onDisconnect, onDisconnect);
    try { connection.close(); } catch { /* already closed */ }
    if (disconnect) safeDisconnect(port);
  }
}

function trustedDocument(
  port: WebsitePasskeyPortLike,
  extensionBaseUrl: string,
  extensionId: string,
): WebsitePasskeyDocumentContext | undefined {
  if (port.name !== WEBSITE_PASSKEY_PORT_NAME) return undefined;
  const context = createRequestContext(port.sender, extensionBaseUrl, extensionId);
  if (context?.kind !== 'content' || !validDocumentId(context.documentId)) return undefined;
  let url: URL;
  try { url = new URL(context.url); } catch { return undefined; }
  if (url.username || url.password || !secureWebsiteUrl(url)) return undefined;
  return Object.freeze({
    tabId: context.tabId,
    frameId: context.frameId,
    documentId: context.documentId,
    url: context.url,
    origin: context.origin,
  });
}

function secureWebsiteUrl(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  if (url.hostname === 'localhost' || url.hostname === '[::1]') return true;
  const octets = url.hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function validDocumentId(value: unknown): value is string {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > MAX_DOCUMENT_ID_LENGTH
      || value.trim() !== value) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}

function absoluteDeadline(now: number, timeout: number): number {
  const sum = now + timeout;
  return Number.isSafeInteger(sum) ? sum : Number.MAX_SAFE_INTEGER;
}

function requireConfigured(state: PortState): void {
  if (!state.configured) throw new PortBindingError('port is not configured');
}

function bindBegin(state: PortState, request: CanonicalWebsitePasskeyRequest): BoundRequest {
  if (state.acknowledged.has(request.bridgeRequestId)) {
    throw new PortBindingError('acknowledged request identifier was reused');
  }
  const serializedRequest = serializeCanonicalWebsitePasskeyRequest(request);
  const existing = state.bindings.get(request.bridgeRequestId);
  if (existing) {
    if (existing.serializedRequest !== serializedRequest) throw new PortBindingError('request binding changed');
    return existing;
  }
  if (state.bindings.size >= MAX_PORT_BINDINGS) throw new PortBindingError('too many passkey requests');
  const binding: BoundRequest = {
    bridgeRequestId: request.bridgeRequestId,
    serializedRequest,
    releaseLease: undefined,
  };
  state.bindings.set(request.bridgeRequestId, binding);
  return binding;
}

function rememberAcknowledged(
  state: PortState,
  bridgeRequestId: string,
  outcome: AcknowledgedOutcome,
): void {
  if (state.acknowledged.size >= MAX_PORT_BINDINGS) {
    const oldest = state.acknowledged.keys().next().value as string | undefined;
    if (oldest !== undefined) state.acknowledged.delete(oldest);
  }
  state.acknowledged.set(bridgeRequestId, outcome);
}

function bindServerResponse(
  binding: BoundRequest,
  message: Exclude<WebsitePasskeyServerMessage, { type: 'config' }>,
): boolean {
  if (binding.bridgeRequestId !== message.bridgeRequestId) return false;
  if (message.type === 'preflightOutcome') return binding.ceremonyId === undefined;
  if (message.type === 'unlockPending') {
    if (binding.ceremonyId !== undefined) return false;
    if (binding.unlockContinuationId !== undefined
        && binding.unlockContinuationId !== message.continuationId) return false;
    binding.unlockContinuationId = message.continuationId;
    return true;
  }
  if (binding.unlockContinuationId !== undefined
      && binding.unlockContinuationId !== message.ceremonyId) return false;
  if (binding.ceremonyId !== undefined && binding.ceremonyId !== message.ceremonyId) return false;
  binding.ceremonyId = message.ceremonyId;
  if (message.type === 'outcome') binding.outcomeId = message.outcomeId;
  return true;
}

function requireExactBinding(
  state: PortState,
  ceremonyId: string,
  bridgeRequestId: string,
  outcomeId?: string,
): void {
  const bound = state.bindings.get(bridgeRequestId);
  if (!bound || (bound.ceremonyId !== ceremonyId
      && bound.unlockContinuationId !== ceremonyId)) throw new PortBindingError('binding mismatch');
  if (outcomeId !== undefined && bound.outcomeId !== outcomeId) throw new PortBindingError('outcome mismatch');
}

function safePost(port: WebsitePasskeyPortLike, message: WebsitePasskeyServerMessage): boolean {
  try {
    port.postMessage(parseWebsitePasskeyServerMessage(message));
    return true;
  } catch {
    return false;
  }
}

function isCurrent(state: PortState, generation: number): boolean {
  return state.active && state.generation === generation;
}

function removeListener<Listener>(event: WebsitePasskeyPortEvent<Listener>, listener: Listener): void {
  try { event.removeListener?.(listener); } catch { /* best effort */ }
}

function safeDisconnect(port: WebsitePasskeyPortLike): void {
  try { port.disconnect(); } catch { /* already disconnected */ }
}
