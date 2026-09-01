// Runs in the page's MAIN world at document_start. The only always-on behavior is the small,
// versioned window-message listener below; navigator.credentials is wrapped only after the isolated
// bridge reports an authoritative enabled configuration for this document.

import { base64UrlToBytes, bytesToBase64Url } from '../core/crypto/encoding.js';
import {
  decideWebsitePasskeySupport,
  parsePasskeyCeremonyResultSnapshot,
  parseWebsitePasskeyServerMessage,
  WEBSITE_PASSKEY_PORT_VERSION,
  type CanonicalWebsitePasskeyCreateRequest,
  type CanonicalWebsitePasskeyDescriptor,
  type CanonicalWebsitePasskeyRequest,
  type PasskeyAssertionResultSnapshot,
  type PasskeyRegistrationResultSnapshot,
  type WebsitePasskeyAcceptedMessage,
  type WebsitePasskeyOutcomeMessage,
  type WebsitePasskeyPreflightOutcomeMessage,
  type WebsitePasskeyServerMessage,
  type WebsitePasskeyTransport,
  type WebsitePasskeyUnlockPendingMessage,
} from '../messaging/website-passkey-port.js';
import {
  WEBSITE_PASSKEY_BRIDGE_SOURCE,
  WEBSITE_PASSKEY_PAGE_SOURCE,
  WEBSITE_PASSKEY_WINDOW_VERSION,
  type WebsitePasskeyPageCancelMessage,
  type WebsitePasskeyPageDeliveredMessage,
} from './website-passkey-feature.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PAGE_CONTROLLER_SENTINEL = Symbol.for('miyu.websitePasskey.pageController.v1');
const MAX_RECENT_DELIVERIES = 64;
const MAX_PENDING_REQUESTS = 16;
const ABORT_MESSAGE = 'The operation was aborted.';
const TIMEOUT_MESSAGE = 'The operation timed out.';
const FAILURE_MESSAGE = 'The passkey request could not be completed safely.';

type NativeGet = (options?: CredentialRequestOptions) => Promise<Credential | null>;
type NativeCreate = (options?: CredentialCreationOptions) => Promise<Credential | null>;

interface NativeMethods {
  readonly credentials: CredentialsContainer;
  readonly get?: NativeGet;
  readonly create?: NativeCreate;
  readonly getDescriptor?: PropertyDescriptor;
  readonly createDescriptor?: PropertyDescriptor;
}

interface InterceptPlan {
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly nativeTimeout: number;
}

interface PendingRequest {
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly options: CredentialRequestOptions | CredentialCreationOptions;
  readonly native: NativeGet | NativeCreate;
  readonly allowNativeFallback: boolean;
  readonly startedAt: number;
  readonly nativeTimeout: number;
  readonly resolve: (value: Credential | null | PromiseLike<Credential | null>) => void;
  readonly reject: (reason: unknown) => void;
  readonly signal?: AbortSignal;
  onAbort?: () => void;
  unlockPending?: WebsitePasskeyUnlockPendingMessage;
  accepted?: WebsitePasskeyAcceptedMessage;
  timer?: ReturnType<typeof setTimeout> | undefined;
  settled: boolean;
}

interface RecentDelivery {
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly outcomeId: string;
}

export interface PageWebAuthnController {
  readonly active: boolean;
  dispose(): void;
}

class PageWebAuthnControllerImpl implements PageWebAuthnController {
  #active = false;
  #disposed = false;
  #native: NativeMethods | undefined;
  readonly #pending = new Map<string, PendingRequest>();
  readonly #recent = new Map<string, RecentDelivery>();
  readonly #onMessage = (event: MessageEvent): void => this.#handleMessage(event);

  constructor(private readonly onDispose: () => void) {
    window.addEventListener('message', this.#onMessage);
  }

  get active(): boolean {
    return this.#active;
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    window.removeEventListener('message', this.#onMessage);
    this.#disable(true);
    for (const pending of [...this.#pending.values()]) {
      this.#reject(pending, terminalConnectionError(pending.request.kind));
    }
    this.onDispose();
  }

  #handleMessage(event: MessageEvent): void {
    if (this.#disposed || event.source !== window || event.origin !== location.origin) return;
    const protocol = readBridgeProtocolMessage(event.data);
    if (!protocol) return;

    if (protocol.type === 'config') {
      if (protocol.enabled) this.#activate();
      else this.#disable(false);
      return;
    }
    // Candidate-bearing messages are private to the isolated world and are never page protocol.
    if (protocol.type === 'conditionalActive') return;
    if (protocol.type === 'preflightOutcome') this.#handlePreflightOutcome(protocol);
    else if (protocol.type === 'unlockPending') this.#handleUnlockPending(protocol);
    else if (protocol.type === 'accepted') this.#handleAccepted(protocol);
    else this.#handleOutcome(protocol);
  }

  #activate(): void {
    if (this.#active || !isWebsitePasskeyDocumentSupported()) return;
    const credentials = navigator.credentials;
    if (!credentials) return;
    const get = typeof credentials.get === 'function'
      ? credentials.get.bind(credentials) as NativeGet
      : undefined;
    const create = typeof credentials.create === 'function'
      ? credentials.create.bind(credentials) as NativeCreate
      : undefined;
    if (!get && !create) return;

    const getDescriptor = Object.prototype.hasOwnProperty.call(credentials, 'get')
      ? Object.getOwnPropertyDescriptor(credentials, 'get')
      : undefined;
    const createDescriptor = Object.prototype.hasOwnProperty.call(credentials, 'create')
      ? Object.getOwnPropertyDescriptor(credentials, 'create')
      : undefined;
    const native: NativeMethods = {
      credentials,
      ...(get ? { get } : {}),
      ...(create ? { create } : {}),
      ...(getDescriptor ? { getDescriptor } : {}),
      ...(createDescriptor ? { createDescriptor } : {}),
    };

    try {
      if (get) {
        Object.defineProperty(credentials, 'get', {
          configurable: true,
          writable: true,
          value: (options?: CredentialRequestOptions) => this.#get(options, get),
        });
      }
      if (create) {
        Object.defineProperty(credentials, 'create', {
          configurable: true,
          writable: true,
          value: (options?: CredentialCreationOptions) => this.#create(options, create),
        });
      }
    } catch {
      restoreNativeMethods(native);
      return;
    }
    this.#native = native;
    this.#active = true;
  }

  #disable(pageSettled: boolean): void {
    if (!this.#active) return;
    this.#active = false;
    const native = this.#native;
    this.#native = undefined;
    if (native) restoreNativeMethods(native);

    for (const pending of [...this.#pending.values()]) {
      this.#postCancel(pending.request.bridgeRequestId, pageSettled);
    }
  }

  #get(options: CredentialRequestOptions | undefined, native: NativeGet): Promise<Credential | null> {
    const plan = createGetPlan(options);
    if (!plan) return native(options);
    if (plan.request.kind === 'get' && plan.request.mediation === 'conditional') {
      return this.#conditionalGet(plan, options!, native);
    }
    return this.#begin(plan, options!, native);
  }

  async #conditionalGet(
    plan: InterceptPlan,
    options: CredentialRequestOptions,
    native: NativeGet,
  ): Promise<Credential | null> {
    const callerSignal = options.signal;
    if (callerSignal?.aborted) throw domException(ABORT_MESSAGE, 'AbortError');

    const extensionController = new AbortController();
    const nativeController = new AbortController();
    const abortProviders = (): void => {
      extensionController.abort();
      nativeController.abort();
    };
    let rejectCallerAbort: ((reason: DOMException) => void) | undefined;
    const callerAbort = callerSignal
      ? new Promise<never>((_resolve, reject) => { rejectCallerAbort = reject; })
      : undefined;
    const onCallerAbort = (): void => {
      abortProviders();
      rejectCallerAbort?.(domException(ABORT_MESSAGE, 'AbortError'));
    };
    callerSignal?.addEventListener('abort', onCallerAbort, { once: true });

    const extensionOptions: CredentialRequestOptions = {
      ...options,
      signal: extensionController.signal,
    };
    let nativeRejected = false;
    let nativeError: unknown;
    const extensionResult = this.#begin(plan, extensionOptions, native, false);
    let nativeAttempt: Promise<Credential | null>;
    try {
      nativeAttempt = native({ ...options, signal: nativeController.signal });
    } catch (error) {
      nativeAttempt = Promise.reject(error);
    }
    const nativeResult = nativeAttempt.catch((error: unknown) => {
      nativeRejected = true;
      nativeError = error;
      throw error;
    });
    const firstCredential = Promise.any([extensionResult, nativeResult]);

    try {
      return await (callerAbort
        ? Promise.race([firstCredential, callerAbort])
        : firstCredential);
    } catch {
      if (callerSignal?.aborted) throw domException(ABORT_MESSAGE, 'AbortError');
      if (nativeRejected) throw nativeError;
      throw terminalConnectionError('get');
    } finally {
      callerSignal?.removeEventListener('abort', onCallerAbort);
      abortProviders();
    }
  }

  #create(options: CredentialCreationOptions | undefined, native: NativeCreate): Promise<Credential | null> {
    const plan = createCreatePlan(options);
    if (!plan) return native(options);
    return this.#begin(plan, options!, native);
  }

  #begin(
    plan: InterceptPlan,
    options: CredentialRequestOptions | CredentialCreationOptions,
    native: NativeGet | NativeCreate,
    allowNativeFallback = true,
  ): Promise<Credential | null> {
    const signal = options.signal;
    if (signal?.aborted) return Promise.reject(domException(ABORT_MESSAGE, 'AbortError'));
    if (this.#pending.size >= MAX_PENDING_REQUESTS) {
      return Promise.reject(terminalConnectionError(plan.request.kind));
    }

    return new Promise<Credential | null>((resolve, reject) => {
      const pending: PendingRequest = {
        request: plan.request,
        options,
        native,
        allowNativeFallback,
        startedAt: performance.now(),
        nativeTimeout: plan.nativeTimeout,
        resolve,
        reject,
        ...(signal ? { signal } : {}),
        settled: false,
      };
      const onAbort = (): void => {
        this.#postCancel(plan.request.bridgeRequestId, true);
        this.#reject(pending, domException(ABORT_MESSAGE, 'AbortError'));
      };
      if (signal) {
        pending.onAbort = onAbort;
        signal.addEventListener('abort', onAbort, { once: true });
      }
      pending.timer = setTimeout(() => {
        this.#postCancel(plan.request.bridgeRequestId, true);
        this.#reject(pending, timeoutError(plan.request.kind));
      }, plan.nativeTimeout);
      this.#pending.set(plan.request.bridgeRequestId, pending);

      try {
        window.postMessage({
          source: WEBSITE_PASSKEY_PAGE_SOURCE,
          version: WEBSITE_PASSKEY_WINDOW_VERSION,
          type: 'begin',
          request: plan.request,
        }, location.origin);
      } catch {
        this.#reject(pending, domException(FAILURE_MESSAGE, 'UnknownError'));
      }
    });
  }

  #handleAccepted(message: WebsitePasskeyAcceptedMessage): void {
    const pending = this.#pending.get(message.bridgeRequestId);
    if (!pending || pending.settled) return;
    if (pending.unlockPending) {
      if (pending.unlockPending.continuationId !== message.ceremonyId
          || pending.unlockPending.deadlineAt !== message.deadlineAt) {
        this.#postCancel(pending.request.bridgeRequestId, true);
        this.#reject(pending, domException(FAILURE_MESSAGE, 'UnknownError'));
        return;
      }
      delete pending.unlockPending;
    }
    if (pending.accepted) {
      if (
        pending.accepted.ceremonyId !== message.ceremonyId
        || pending.accepted.deadlineAt !== message.deadlineAt
      ) {
        this.#postCancel(pending.request.bridgeRequestId, true);
        this.#reject(pending, domException(FAILURE_MESSAGE, 'UnknownError'));
      }
      return;
    }
    pending.accepted = message;
    const remaining = Math.max(0, message.deadlineAt - Date.now());
    const localRemaining = Math.max(0, pending.nativeTimeout - elapsedSince(pending.startedAt));
    clearPendingTimer(pending);
    pending.timer = setTimeout(() => {
      this.#postCancel(pending.request.bridgeRequestId, true);
      this.#reject(pending, timeoutError(pending.request.kind));
    }, Math.min(remaining, localRemaining));
  }

  #handleUnlockPending(message: WebsitePasskeyUnlockPendingMessage): void {
    const pending = this.#pending.get(message.bridgeRequestId);
    if (!pending || pending.settled || pending.accepted) return;
    if (pending.unlockPending
        && (pending.unlockPending.continuationId !== message.continuationId
          || pending.unlockPending.deadlineAt !== message.deadlineAt)) {
      this.#postCancel(pending.request.bridgeRequestId, true);
      this.#reject(pending, domException(FAILURE_MESSAGE, 'UnknownError'));
      return;
    }
    pending.unlockPending = message;
    const remaining = Math.max(0, message.deadlineAt - Date.now());
    const localRemaining = Math.max(0, pending.nativeTimeout - elapsedSince(pending.startedAt));
    clearPendingTimer(pending);
    pending.timer = setTimeout(() => {
      this.#postCancel(pending.request.bridgeRequestId, true);
      this.#reject(pending, timeoutError(pending.request.kind));
    }, Math.min(remaining, localRemaining));
  }

  #handlePreflightOutcome(message: WebsitePasskeyPreflightOutcomeMessage): void {
    const pending = this.#pending.get(message.bridgeRequestId);
    if (!pending || pending.settled) return;
    if (message.outcome.status === 'fallback') this.#fallback(pending);
    else {
      this.#reject(
        pending,
        domException(message.outcome.error.message, message.outcome.error.name),
      );
    }
  }

  #handleOutcome(message: WebsitePasskeyOutcomeMessage): void {
    const pending = this.#pending.get(message.bridgeRequestId);
    if (!pending || pending.settled) {
      const recent = this.#recent.get(deliveryKey(message));
      if (recent) this.#postDelivered(recent);
      return;
    }
    if (pending.accepted && pending.accepted.ceremonyId !== message.ceremonyId) return;

    try {
      if (message.outcome.status === 'success') {
        const result = parsePasskeyCeremonyResultSnapshot(
          message.outcome.result,
          pending.request.kind,
        );
        const credential = result.kind === 'get'
          ? buildAssertionCredential(result)
          : buildRegistrationCredential(result);
        this.#resolve(pending, credential);
      } else if (message.outcome.status === 'error') {
        this.#reject(
          pending,
          domException(message.outcome.error.message, message.outcome.error.name),
        );
      } else {
        this.#fallback(pending);
      }
    } catch {
      this.#reject(pending, domException(FAILURE_MESSAGE, 'UnknownError'));
    }
    this.#rememberDelivered(message);
    this.#postDelivered(message);
  }

  #fallback(pending: PendingRequest): void {
    if (pending.settled) return;
    if (!pending.allowNativeFallback) {
      this.#cleanup(pending);
      pending.reject(new Error('Conditional passkey provider is unavailable.'));
      return;
    }
    this.#cleanup(pending);
    try {
      pending.resolve(callNativeWithRemainingTimeout(pending));
    } catch (error) {
      pending.reject(error);
    }
  }

  #resolve(pending: PendingRequest, value: Credential | null): void {
    if (pending.settled) return;
    this.#cleanup(pending);
    pending.resolve(value);
  }

  #reject(pending: PendingRequest, error: unknown): void {
    if (pending.settled) return;
    this.#cleanup(pending);
    pending.reject(error);
  }

  #cleanup(pending: PendingRequest): void {
    pending.settled = true;
    clearPendingTimer(pending);
    if (pending.signal && pending.onAbort) {
      pending.signal.removeEventListener('abort', pending.onAbort);
    }
    this.#pending.delete(pending.request.bridgeRequestId);
  }

  #postCancel(bridgeRequestId: string, settled: boolean): void {
    const message: WebsitePasskeyPageCancelMessage = {
      source: WEBSITE_PASSKEY_PAGE_SOURCE,
      version: WEBSITE_PASSKEY_WINDOW_VERSION,
      type: 'cancel',
      bridgeRequestId,
      settled,
    };
    try { window.postMessage(message, location.origin); } catch { /* Local settlement still wins. */ }
  }

  #postDelivered(delivery: RecentDelivery): void {
    const message: WebsitePasskeyPageDeliveredMessage = {
      source: WEBSITE_PASSKEY_PAGE_SOURCE,
      version: WEBSITE_PASSKEY_WINDOW_VERSION,
      type: 'delivered',
      ceremonyId: delivery.ceremonyId,
      bridgeRequestId: delivery.bridgeRequestId,
      outcomeId: delivery.outcomeId,
    };
    try { window.postMessage(message, location.origin); } catch { /* The worker retains the outcome. */ }
  }

  #rememberDelivered(message: WebsitePasskeyOutcomeMessage): void {
    const delivery = {
      ceremonyId: message.ceremonyId,
      bridgeRequestId: message.bridgeRequestId,
      outcomeId: message.outcomeId,
    };
    this.#recent.set(deliveryKey(delivery), delivery);
    while (this.#recent.size > MAX_RECENT_DELIVERIES) {
      const oldest = this.#recent.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#recent.delete(oldest);
    }
  }
}

/** Install the activation listener without intercepting WebAuthn until a config message enables it. */
export function installPageWebAuthnInterception(): PageWebAuthnController {
  const existing = readPageControllerSentinel();
  if (existing) return existing;
  const controller = new PageWebAuthnControllerImpl(() => clearPageControllerSentinel(controller));
  try {
    Object.defineProperty(globalThis, PAGE_CONTROLLER_SENTINEL, {
      configurable: true,
      value: Object.freeze({ version: 1, controller }),
    });
  } catch {
    // A page can only deny interception in its own realm; background authorization remains intact.
  }
  return controller;
}

export const pageWebAuthnController = installPageWebAuthnInterception();

function readPageControllerSentinel(): PageWebAuthnController | undefined {
  let value: unknown;
  try { value = (globalThis as unknown as Record<PropertyKey, unknown>)[PAGE_CONTROLLER_SENTINEL]; } catch {
    return undefined;
  }
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (record.version !== 1) return undefined;
  const controller = record.controller as Partial<PageWebAuthnController> | undefined;
  return controller && typeof controller.dispose === 'function' ? controller as PageWebAuthnController : undefined;
}

function clearPageControllerSentinel(controller: PageWebAuthnController): void {
  const current = readPageControllerSentinel();
  if (current !== controller) return;
  try { delete (globalThis as unknown as Record<PropertyKey, unknown>)[PAGE_CONTROLLER_SENTINEL]; } catch {
    // The controller is disposed even if a page froze the sentinel property.
  }
}

function createGetPlan(options: CredentialRequestOptions | undefined): InterceptPlan | undefined {
  try {
    if (!options || !hasOnlyOwnKeys(options, ['publicKey', 'signal', 'mediation'])) return undefined;
    const publicKey = options.publicKey;
    if (!publicKey || !hasOnlyOwnKeys(publicKey, [
      'challenge', 'timeout', 'rpId', 'allowCredentials', 'userVerification', 'extensions',
    ])) return undefined;
    if (options.mediation === 'silent') return undefined;
    if (options.mediation !== undefined
      && options.mediation !== 'conditional'
      && options.mediation !== 'optional'
      && options.mediation !== 'required') {
      return undefined;
    }
    if (publicKey.userVerification === 'required') return undefined;
    if (publicKey.extensions !== undefined && !hasOnlyOwnKeys(publicKey.extensions, [])) return undefined;

    const rpId = publicKey.rpId ?? location.hostname;
    if (!isLocalRpId(rpId, location.hostname)) return undefined;
    const descriptorsFromPage = descriptors(publicKey.allowCredentials ?? []);
    if (!descriptorsFromPage) return undefined;
    const allowCredentials = descriptorsFromPage.filter((descriptor) => !hasHardwareOnlyTransport(descriptor));
    if (descriptorsFromPage.length > 0 && allowCredentials.length === 0) return undefined;
    const bridgeRequestId = freshBridgeRequestId();
    const decision = decideWebsitePasskeySupport({
      bridgeRequestId,
      kind: 'get',
      rpId,
      challenge: bytesToBase64Url(bufferSourceBytes(publicKey.challenge)),
      allowCredentials,
      ...(publicKey.userVerification === undefined ? {} : { userVerification: publicKey.userVerification }),
      ...(options.mediation === undefined ? {} : { mediation: options.mediation }),
      ...(publicKey.timeout === undefined ? {} : { timeout: publicKey.timeout }),
    });
    if (decision.status !== 'accepted' || decision.request.kind !== 'get') return undefined;
    return {
      request: decision.request,
      nativeTimeout: decision.request.timeout,
    };
  } catch {
    return undefined;
  }
}

function createCreatePlan(options: CredentialCreationOptions | undefined): InterceptPlan | undefined {
  try {
    if (!options || !hasOnlyOwnKeys(options, ['publicKey', 'signal'])) return undefined;
    const publicKey = options.publicKey;
    if (!publicKey || !hasOnlyOwnKeys(publicKey, [
      'rp', 'user', 'challenge', 'pubKeyCredParams', 'timeout', 'excludeCredentials',
      'authenticatorSelection', 'attestation', 'extensions',
    ])) return undefined;
    if (!hasOnlyOwnKeys(publicKey.rp, ['id', 'name'])) return undefined;
    if (!hasOnlyOwnKeys(publicKey.user, ['id', 'name', 'displayName'])) return undefined;
    if (!Array.isArray(publicKey.pubKeyCredParams) || publicKey.pubKeyCredParams.length === 0) return undefined;
    if (!publicKey.pubKeyCredParams.every((entry) => hasOnlyOwnKeys(entry, ['type', 'alg']))) return undefined;
    if (!publicKey.pubKeyCredParams.some((entry) => entry.type === 'public-key' && entry.alg === -7)) {
      return undefined;
    }

    const selection = publicKey.authenticatorSelection;
    if (selection !== undefined && !hasOnlyOwnKeys(selection, [
      'authenticatorAttachment', 'residentKey', 'requireResidentKey', 'userVerification',
    ])) return undefined;
    if (selection?.authenticatorAttachment === 'cross-platform') return undefined;
    if (selection?.userVerification === 'required') return undefined;
    if (selection?.authenticatorAttachment !== undefined && selection.authenticatorAttachment !== 'platform') {
      return undefined;
    }
    const extensionInput = createExtensions(publicKey.extensions);
    if (!extensionInput) return undefined;
    const rpId = publicKey.rp.id ?? location.hostname;
    if (!isLocalRpId(rpId, location.hostname)) return undefined;
    const excludeCredentials = descriptors(publicKey.excludeCredentials ?? []);
    if (!excludeCredentials || excludeCredentials.some(hasHardwareOnlyTransport)) return undefined;

    const candidate = {
      bridgeRequestId: freshBridgeRequestId(),
      kind: 'create',
      rp: { id: rpId, name: publicKey.rp.name },
      user: {
        id: bytesToBase64Url(bufferSourceBytes(publicKey.user.id)),
        name: publicKey.user.name,
        displayName: publicKey.user.displayName,
      },
      challenge: bytesToBase64Url(bufferSourceBytes(publicKey.challenge)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials,
      ...(selection === undefined ? {} : {
        authenticatorSelection: {
          ...(selection.authenticatorAttachment === undefined
            ? {}
            : { authenticatorAttachment: selection.authenticatorAttachment }),
          ...(selection.residentKey === undefined ? {} : { residentKey: selection.residentKey }),
          ...(selection.requireResidentKey === undefined
            ? {}
            : { requireResidentKey: selection.requireResidentKey }),
          ...(selection.userVerification === undefined
            ? {}
            : { userVerification: selection.userVerification }),
        },
      }),
      ...(publicKey.attestation === undefined ? {} : { attestation: publicKey.attestation }),
      extensions: extensionInput,
      ...(publicKey.timeout === undefined ? {} : { timeout: publicKey.timeout }),
    };
    const decision = decideWebsitePasskeySupport(candidate);
    if (decision.status !== 'accepted' || decision.request.kind !== 'create') return undefined;
    return {
      request: decision.request,
      nativeTimeout: decision.request.timeout,
    };
  } catch {
    return undefined;
  }
}

function createExtensions(
  value: AuthenticationExtensionsClientInputs | undefined,
): CanonicalWebsitePasskeyCreateRequest['extensions'] | undefined {
  if (value === undefined) return { credProps: false };
  if (!hasOnlyOwnKeys(value, ['credProps'])) return undefined;
  const credProps = (value as AuthenticationExtensionsClientInputs & { credProps?: unknown }).credProps;
  if (credProps !== undefined && typeof credProps !== 'boolean') return undefined;
  return { credProps: credProps ?? false };
}

function descriptors(
  values: readonly PublicKeyCredentialDescriptor[],
): CanonicalWebsitePasskeyDescriptor[] | undefined {
  if (!Array.isArray(values)) return undefined;
  const result: CanonicalWebsitePasskeyDescriptor[] = [];
  for (const value of values) {
    if (!hasOnlyOwnKeys(value, ['id', 'type', 'transports']) || value.type !== 'public-key') return undefined;
    if (value.transports !== undefined && !Array.isArray(value.transports)) return undefined;
    result.push({
      id: bytesToBase64Url(bufferSourceBytes(value.id)),
      type: 'public-key',
      transports: [...(value.transports ?? [])] as WebsitePasskeyTransport[],
    });
  }
  return result;
}

function hasHardwareOnlyTransport(descriptor: CanonicalWebsitePasskeyDescriptor): boolean {
  return descriptor.transports.length > 0 && !descriptor.transports.includes('internal');
}

function readBridgeProtocolMessage(data: unknown): WebsitePasskeyServerMessage | undefined {
  if (!isPlainDataRecord(data)) return undefined;
  const source = ownData(data, 'source');
  if (source !== WEBSITE_PASSKEY_BRIDGE_SOURCE) return undefined;
  const copy: Record<string, unknown> = {};
  for (const key of Object.keys(data)) {
    if (key !== 'source') copy[key] = ownData(data, key);
  }
  try {
    const parsed = parseWebsitePasskeyServerMessage(copy);
    return parsed.version === WEBSITE_PASSKEY_PORT_VERSION && hasStrictServerIds(parsed)
      ? parsed
      : undefined;
  } catch {
    return undefined;
  }
}

export function isWebsitePasskeyDocumentSupported(
  context: Readonly<{ isSecureContext: boolean; href: string }> = {
    isSecureContext: window.isSecureContext,
    href: location.href,
  },
): boolean {
  if (!context.isSecureContext) return false;
  let url: URL;
  try { url = new URL(context.href); } catch { return false; }
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && isLoopbackHostname(url.hostname);
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === 'localhost'
    || normalized.endsWith('.localhost')
    || normalized === '127.0.0.1'
    || normalized === '::1';
}

function isLocalRpId(rpId: unknown, hostname: string): rpId is string {
  if (typeof rpId !== 'string' || rpId.length === 0 || rpId.length > 253 || rpId.trim() !== rpId) {
    return false;
  }
  const canonicalRpId = rpId.toLowerCase();
  const canonicalHost = hostname.toLowerCase();
  if (
    /[^a-z0-9.-]/.test(canonicalRpId)
    || canonicalRpId.startsWith('.')
    || canonicalRpId.endsWith('.')
    || canonicalRpId.includes('..')
  ) return false;
  return canonicalHost === canonicalRpId || canonicalHost.endsWith(`.${canonicalRpId}`);
}

function freshBridgeRequestId(): string {
  const id = crypto.randomUUID();
  if (!isUuidV4(id)) throw new Error('Invalid bridge request id');
  return id;
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
      return false;
    case 'outcome':
      return isUuidV4(message.bridgeRequestId)
        && isUuidV4(message.ceremonyId)
        && isUuidV4(message.outcomeId);
  }
}

function isUuidV4(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID_V4.test(value);
}

function bufferSourceBytes(value: BufferSource): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (!ArrayBuffer.isView(value)) throw new Error('Invalid BufferSource');
  return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
}

function callNativeWithRemainingTimeout(pending: PendingRequest): Promise<Credential | null> {
  const remaining = Math.max(1, Math.floor(pending.nativeTimeout - elapsedSince(pending.startedAt)));
  const options = pending.options;
  const adjusted = {
    ...options,
    publicKey: { ...options.publicKey, timeout: remaining },
  };
  return pending.native(adjusted as never);
}

function elapsedSince(startedAt: number): number {
  return Math.max(0, performance.now() - startedAt);
}

function restoreNativeMethods(native: NativeMethods): void {
  restoreMethod(native.credentials, 'get', native.getDescriptor);
  restoreMethod(native.credentials, 'create', native.createDescriptor);
}

function restoreMethod(
  credentials: CredentialsContainer,
  key: 'get' | 'create',
  descriptor: PropertyDescriptor | undefined,
): void {
  try {
    if (descriptor) Object.defineProperty(credentials, key, descriptor);
    else delete (credentials as unknown as Record<string, unknown>)[key];
  } catch {
    // The document is leaving; pending requests are still settled below.
  }
}

function clearPendingTimer(pending: PendingRequest): void {
  if (pending.timer !== undefined) clearTimeout(pending.timer);
  pending.timer = undefined;
}

function domException(message: string, name: string): DOMException {
  return new DOMException(message, name);
}

function timeoutError(kind: CanonicalWebsitePasskeyRequest['kind']): DOMException {
  return kind === 'create'
    ? domException(FAILURE_MESSAGE, 'UnknownError')
    : domException(TIMEOUT_MESSAGE, 'NotAllowedError');
}

function terminalConnectionError(kind: CanonicalWebsitePasskeyRequest['kind']): DOMException {
  return kind === 'create'
    ? domException(FAILURE_MESSAGE, 'UnknownError')
    : domException(FAILURE_MESSAGE, 'NotAllowedError');
}

function deliveryKey(value: RecentDelivery): string {
  return `${value.bridgeRequestId}\0${value.ceremonyId}\0${value.outcomeId}`;
}

function hasOnlyOwnKeys(value: unknown, allowed: readonly string[]): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const allowedSet = new Set(allowed);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowedSet.has(key)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) return false;
  }
  return true;
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

function ownData(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function buildAssertionCredential(result: PasskeyAssertionResultSnapshot): PublicKeyCredential {
  const rawId = toArrayBuffer(base64UrlToBytes(result.credentialId));
  const clientDataJSON = toArrayBuffer(base64UrlToBytes(result.clientDataJSON));
  const authenticatorData = toArrayBuffer(base64UrlToBytes(result.authenticatorData));
  const signature = toArrayBuffer(base64UrlToBytes(result.signature));
  const userHandle = result.userHandle === undefined
    ? null
    : toArrayBuffer(base64UrlToBytes(result.userHandle));
  const response = createWithPrototype<AuthenticatorAssertionResponse>('AuthenticatorAssertionResponse');
  defineValues(response, { clientDataJSON, authenticatorData, signature, userHandle });

  const credential = createWithPrototype<PublicKeyCredential>('PublicKeyCredential');
  const extensionResults = {};
  defineValues(credential, {
    id: result.credentialId,
    rawId,
    response,
    type: 'public-key',
    authenticatorAttachment: result.authenticatorAttachment,
    getClientExtensionResults: () => ({ ...extensionResults }),
    toJSON: () => ({
      id: result.credentialId,
      rawId: result.credentialId,
      response: {
        clientDataJSON: result.clientDataJSON,
        authenticatorData: result.authenticatorData,
        signature: result.signature,
        userHandle: result.userHandle ?? null,
      },
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: result.authenticatorAttachment,
    }),
  });
  return credential;
}

function buildRegistrationCredential(result: PasskeyRegistrationResultSnapshot): PublicKeyCredential {
  const rawId = toArrayBuffer(base64UrlToBytes(result.credentialId));
  const clientDataJSON = toArrayBuffer(base64UrlToBytes(result.clientDataJSON));
  const attestationObject = toArrayBuffer(base64UrlToBytes(result.attestationObject));
  const authenticatorData = toArrayBuffer(base64UrlToBytes(result.authData));
  const publicKey = toArrayBuffer(base64UrlToBytes(result.publicKeySpki));
  const transports = [...result.transports];
  const response = createWithPrototype<AuthenticatorAttestationResponse>('AuthenticatorAttestationResponse');
  defineValues(response, {
    clientDataJSON,
    attestationObject,
    getAuthenticatorData: () => authenticatorData.slice(0),
    getPublicKey: () => publicKey.slice(0),
    getPublicKeyAlgorithm: () => result.publicKeyAlgorithm,
    getTransports: () => [...transports],
  });

  const extensionResults = result.credProps === null
    ? {}
    : { credProps: { rk: result.credProps.rk } };
  const credential = createWithPrototype<PublicKeyCredential>('PublicKeyCredential');
  defineValues(credential, {
    id: result.credentialId,
    rawId,
    response,
    type: 'public-key',
    authenticatorAttachment: result.authenticatorAttachment,
    getClientExtensionResults: () => cloneExtensionResults(extensionResults),
    toJSON: () => ({
      id: result.credentialId,
      rawId: result.credentialId,
      response: {
        clientDataJSON: result.clientDataJSON,
        attestationObject: result.attestationObject,
        authenticatorData: result.authData,
        publicKey: result.publicKeySpki,
        publicKeyAlgorithm: result.publicKeyAlgorithm,
        transports: [...transports],
      },
      type: 'public-key',
      clientExtensionResults: cloneExtensionResults(extensionResults),
      authenticatorAttachment: result.authenticatorAttachment,
    }),
  });
  return credential;
}

function cloneExtensionResults(
  value: { readonly credProps?: { readonly rk: boolean } },
): AuthenticationExtensionsClientOutputs {
  return value.credProps ? { credProps: { rk: value.credProps.rk } } : {};
}

function createWithPrototype<T extends object>(constructorName: string): T {
  const constructor = (globalThis as unknown as Record<string, unknown>)[constructorName];
  const prototype = typeof constructor === 'function'
    ? (constructor as { prototype?: unknown }).prototype
    : undefined;
  return Object.create(
    typeof prototype === 'object' && prototype !== null ? prototype : Object.prototype,
  ) as T;
}

function defineValues(target: object, values: Record<string, unknown>): void {
  const descriptors: PropertyDescriptorMap = {};
  for (const [key, value] of Object.entries(values)) {
    descriptors[key] = { configurable: true, enumerable: true, value, writable: false };
  }
  Object.defineProperties(target, descriptors);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
