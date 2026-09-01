import {
  canonicalizeServerCapabilityUrl,
  normalizeServerEnvironmentUrl,
} from '../core/api/server-capabilities.js';
import {
  normalizeSsoEmail,
  parseSsoCallbackUrl,
  parseSsoPkceVerifier,
  parseSsoState,
  type ParsedSsoCallback,
} from '../core/session/sso-login.js';
import type { KeyValueStore } from '../platform/store.js';

export const SSO_ATTEMPT_STORAGE_KEY = 'ssoLoginAttempt';
export const SSO_ATTEMPT_SCHEMA_VERSION = 1 as const;
export const SSO_ATTEMPT_TTL_MS = 5 * 60_000;
export const SSO_OUTCOME_UNKNOWN_TTL_MS = 5 * 60_000;
export const SSO_ATTEMPT_MAX_UTF8_BYTES = 64 * 1024;

const MAX_STORAGE_KEY_LENGTH = 256;
const MAX_DOCUMENT_ID_LENGTH = 512;
const MAX_REDIRECT_URI_LENGTH = 16 * 1024;
const MAX_CONNECTOR_PATH_LENGTH = 2_048;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type SsoAttemptStoreErrorCode =
  | 'busy'
  | 'generation_exhausted'
  | 'invalid_configuration'
  | 'invalid_input'
  | 'storage_capacity';

export class SsoAttemptStoreError extends Error {
  constructor(
    readonly code: SsoAttemptStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'SsoAttemptStoreError';
  }
}

export interface SsoAttemptOwner {
  readonly generation: number;
  readonly attemptGeneration: number;
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly serverGeneration: number;
  readonly capabilityGeneration: number;
  readonly emailIntent: string;
}

export interface SsoAttemptBinding {
  readonly attemptId: string;
  readonly generation: number;
}

export interface SsoSourceDocument {
  readonly tabId: number;
  readonly windowId: number;
  readonly documentId: string;
  readonly url: string;
}

export interface SsoSourceContext {
  readonly popupDocumentId: string;
  readonly windowId: number;
  readonly document?: SsoSourceDocument;
}

interface SsoBrowserAttemptBinding {
  readonly tabId: number;
  readonly callbackDocumentId?: string;
  readonly connectorOrigin: string;
  readonly connectorPath: string;
  readonly state: string;
  readonly verifier: string;
  readonly redirectUri: string;
  readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  readonly organizationIdentifier?: string;
  readonly source: SsoSourceContext;
}

export interface WaitingSsoAttempt extends SsoBrowserAttemptBinding {
  readonly status: 'waiting';
  readonly owner: SsoAttemptOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ClaimedSsoAttempt extends Omit<SsoBrowserAttemptBinding, 'callbackDocumentId'> {
  readonly status: 'claimed';
  readonly owner: SsoAttemptOwner;
  readonly callbackDocumentId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly workerId: string;
  readonly claimedAt: number;
}

export interface SubmittingSsoAttempt extends Omit<ClaimedSsoAttempt, 'status'> {
  readonly status: 'submitting';
}

export interface UnknownSsoAttempt {
  readonly status: 'outcome_unknown';
  readonly owner: SsoAttemptOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
  readonly claimGeneration: number;
  readonly tabId: number;
  readonly callbackDocumentId: string;
  readonly redirectUri: string;
  readonly source: SsoSourceContext;
}

export type SsoAttempt = WaitingSsoAttempt | ClaimedSsoAttempt | SubmittingSsoAttempt | UnknownSsoAttempt;

export interface SsoRestartCleanup {
  readonly attempt: SsoAttempt;
  readonly expired: boolean;
}

export interface CreateSsoAttemptInput {
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly serverGeneration: number;
  readonly capabilityGeneration: number;
  readonly emailIntent: string;
  readonly tabId: number;
  readonly connectorOrigin: string;
  readonly connectorPath: string;
  readonly state: string;
  readonly verifier: string;
  readonly redirectUri: string;
  readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  readonly organizationIdentifier?: string;
  readonly source: SsoSourceContext;
}

export interface BindSsoCallbackInput {
  readonly tabId: number;
  readonly documentId: string;
  readonly callbackUrl: string;
}

export interface SsoAttemptHandoff {
  readonly attemptId: string;
  readonly attemptGeneration: number;
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly email: string;
}

export interface BoundSsoCallback extends ParsedSsoCallback {
  readonly attempt: WaitingSsoAttempt & { readonly callbackDocumentId: string };
}

export interface SsoAttemptStoreOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly workerId?: string;
  readonly createAttemptId?: () => string;
}

interface WaitingEnvelope {
  readonly schemaVersion: typeof SSO_ATTEMPT_SCHEMA_VERSION;
  readonly generation: number;
  readonly attemptGeneration: number;
  readonly status: 'waiting';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly serverGeneration: number;
  readonly capabilityGeneration: number;
  readonly emailIntent: string;
  readonly tabId: number;
  readonly callbackDocumentId?: string;
  readonly connectorOrigin: string;
  readonly connectorPath: string;
  readonly state: string;
  readonly verifier: string;
  readonly redirectUri: string;
  readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  readonly organizationIdentifier?: string;
  readonly source: SsoSourceContext;
  readonly createdAt: number;
  readonly expiresAt: number;
}

interface ClaimedEnvelope extends Omit<WaitingEnvelope, 'status' | 'callbackDocumentId'> {
  readonly status: 'claimed' | 'submitting';
  readonly callbackDocumentId: string;
  readonly workerId: string;
  readonly claimedAt: number;
}

interface UnknownEnvelope {
  readonly schemaVersion: typeof SSO_ATTEMPT_SCHEMA_VERSION;
  readonly generation: number;
  readonly attemptGeneration: number;
  readonly status: 'outcome_unknown';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly serverGeneration: number;
  readonly capabilityGeneration: number;
  readonly emailIntent: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
  readonly claimGeneration: number;
  readonly tabId: number;
  readonly callbackDocumentId: string;
  readonly redirectUri: string;
  readonly source: SsoSourceContext;
}

type Envelope = WaitingEnvelope | ClaimedEnvelope | UnknownEnvelope;

interface OperationQueue { tail: Promise<void> }
interface SharedCoordinator { highWaterGeneration: number; readonly queue: OperationQueue }

const COORDINATORS = new WeakMap<KeyValueStore, Map<string, SharedCoordinator>>();

/** Owns one restart-resilient, one-shot browser SSO authorization-code attempt. */
export class SsoAttemptStore {
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #workerId: string;
  readonly #createAttemptId: () => string;
  readonly #coordinator: SharedCoordinator;

  constructor(
    private readonly sessionStore: KeyValueStore,
    options: SsoAttemptStoreOptions = {},
  ) {
    if (!sessionStore) throw storeError('invalid_configuration', 'sessionStore is required');
    this.#storageKey = parseStorageKey(options.storageKey ?? SSO_ATTEMPT_STORAGE_KEY);
    this.#now = options.now ?? Date.now;
    this.#workerId = parseUuid(options.workerId ?? crypto.randomUUID(), 'workerId');
    this.#createAttemptId = options.createAttemptId ?? (() => crypto.randomUUID());
    this.#coordinator = sharedCoordinator(sessionStore, this.#storageKey);
  }

  read(): Promise<SsoAttempt | undefined> {
    return this.#serialize(async () => {
      let envelope = await this.#readEnvelope(this.#currentTime());
      if ((envelope?.status === 'claimed' || envelope?.status === 'submitting')
          && envelope.workerId !== this.#workerId) {
        envelope = await this.#toOutcomeUnknown(envelope, this.#currentTime());
      }
      return envelope ? snapshot(envelope) : undefined;
    });
  }

  /** Read only attempts that restart may scrub/close without authorizing a fresh exchange. */
  claimRestartCleanup(): Promise<SsoRestartCleanup | undefined> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const envelope = await this.#readEnvelopeForCleanup(now);
      if (!envelope) return undefined;
      const expired = now >= envelope.expiresAt;
      const priorWorkerClaim = (envelope.status === 'claimed' || envelope.status === 'submitting')
        && envelope.workerId !== this.#workerId;
      return expired || priorWorkerClaim
        ? Object.freeze({ attempt: snapshot(envelope), expired })
        : undefined;
    });
  }

  clearRestartCleanup(expectedOwner: SsoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelopeForCleanup(this.#currentTime());
      if (!current || !sameOwner(current, owner)) return false;
      await this.sessionStore.remove(this.#storageKey);
      return true;
    });
  }

  create(input: CreateSsoAttemptInput): Promise<WaitingSsoAttempt> {
    return this.#serialize(async () => {
      const parsed = parseCreateInput(input);
      const now = this.#currentTime();
      if (await this.#readEnvelope(now)) {
        throw storeError('busy', 'An SSO attempt is already active.');
      }
      const attemptId = parseUuid(this.#createAttemptId(), 'attemptId');
      const generation = this.#nextGeneration();
      const envelope: WaitingEnvelope = {
        schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
        generation,
        attemptGeneration: generation,
        status: 'waiting',
        attemptId,
        ...parsed,
        createdAt: now,
        expiresAt: safeAdd(now, SSO_ATTEMPT_TTL_MS),
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as WaitingSsoAttempt;
    });
  }

  /** Validate the exact callback and atomically bind its browser-owned top-level document. */
  bindCallbackDocument(
    expectedOwner: SsoAttemptOwner,
    input: BindSsoCallbackInput,
  ): Promise<BoundSsoCallback | undefined> {
    const owner = parseOwner(expectedOwner);
    const callbackInput = parseCallbackInput(input);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (
        !current
        || current.status !== 'waiting'
        || !sameOwner(current, owner)
        || current.tabId !== callbackInput.tabId
      ) return undefined;
      if (
        current.callbackDocumentId !== undefined
        && current.callbackDocumentId !== callbackInput.documentId
      ) return undefined;
      const callback = parseSsoCallbackUrl(callbackInput.callbackUrl, {
        redirectUri: current.redirectUri,
        state: current.state,
      });
      assertTrustedIssuer(callback.iss, current.serverUrl, current.identityUrl);
      if (
        current.organizationIdentifier !== undefined
        && callback.organizationIdentifier !== undefined
        && callback.organizationIdentifier !== current.organizationIdentifier
      ) invalidInput('callback organization identifier');
      const organizationIdentifier = current.organizationIdentifier
        ?? callback.organizationIdentifier;
      if (current.callbackDocumentId !== undefined) {
        const attempt = snapshot(current) as WaitingSsoAttempt & {
          readonly callbackDocumentId: string;
        };
        return Object.freeze({ attempt, ...callback });
      }
      const envelope: WaitingEnvelope = {
        ...current,
        generation: this.#nextGeneration(),
        callbackDocumentId: callbackInput.documentId,
        ...(organizationIdentifier === undefined ? {} : { organizationIdentifier }),
      };
      await this.#writeEnvelope(envelope);
      const attempt = snapshot(envelope) as WaitingSsoAttempt & {
        readonly callbackDocumentId: string;
      };
      return Object.freeze({ attempt, ...callback });
    });
  }

  /** Claim the exact bound generation once before exchanging its authorization code. */
  claim(expectedOwner: SsoAttemptOwner): Promise<ClaimedSsoAttempt | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (
        !current
        || current.status !== 'waiting'
        || current.callbackDocumentId === undefined
        || !sameOwner(current, owner)
      ) return undefined;
      const envelope: ClaimedEnvelope = {
        ...current,
        generation: this.#nextGeneration(),
        status: 'claimed',
        callbackDocumentId: current.callbackDocumentId,
        workerId: this.#workerId,
        claimedAt: now,
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as ClaimedSsoAttempt;
    });
  }

  startSubmission(expectedOwner: SsoAttemptOwner): Promise<SubmittingSsoAttempt | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current || current.status !== 'claimed' || !sameOwner(current, owner)
          || current.workerId !== this.#workerId) return undefined;
      const envelope: ClaimedEnvelope = {
        ...current,
        generation: this.#nextGeneration(),
        status: 'submitting',
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as SubmittingSsoAttempt;
    });
  }

  /** Drop only a stale return-document proof without changing the authentication attempt owner. */
  dropSourceDocument(expectedOwner: SsoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current || current.status === 'outcome_unknown' || !sameOwner(current, owner)
          || !current.source.document) return false;
      await this.#writeEnvelope({
        ...current,
        source: Object.freeze({
          popupDocumentId: current.source.popupDocumentId,
          windowId: current.source.windowId,
        }),
      });
      return true;
    });
  }

  /** Retire an ambiguous claimed exchange and erase every replayable credential. */
  markOutcomeUnknown(
    expectedOwner: SsoAttemptOwner,
  ): Promise<UnknownSsoAttempt | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (!current || (current.status !== 'claimed' && current.status !== 'submitting')
          || !sameOwner(current, owner)) return undefined;
      return snapshot(await this.#toOutcomeUnknown(current, now)) as UnknownSsoAttempt;
    });
  }

  clear(expectedOwner: SsoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current || !sameOwner(current, owner)) return false;
      await this.sessionStore.remove(this.#storageKey);
      return true;
    });
  }

  /** Cancel only before callback claim; serialized ownership makes cancel-vs-claim single-winner. */
  cancelWaiting(expectedOwner: SsoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current || current.status !== 'waiting' || !sameOwner(current, owner)) return false;
      await this.sessionStore.remove(this.#storageKey);
      return true;
    });
  }

  /** Retire only the exact outer claim proven to have become a durable SSO 2FA continuation. */
  completeHandoff(input: SsoAttemptHandoff): Promise<boolean> {
    const handoff = parseHandoff(input);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      const handoffGeneration = current?.status === 'outcome_unknown'
        ? current.claimGeneration
        : current?.generation;
      if (
        !current
        || current.status === 'waiting'
        || current.attemptId !== handoff.attemptId
        || handoffGeneration !== handoff.attemptGeneration
        || current.serverUrl !== handoff.serverUrl
        || current.identityUrl !== handoff.identityUrl
        || current.emailIntent !== handoff.email
      ) return false;
      await this.sessionStore.remove(this.#storageKey);
      return true;
    });
  }

  #currentTime(): number {
    return parseTimestamp(this.#now(), 'current time');
  }

  #nextGeneration(): number {
    if (this.#coordinator.highWaterGeneration >= Number.MAX_SAFE_INTEGER) {
      throw storeError('generation_exhausted', 'SSO attempt generation is exhausted.');
    }
    return ++this.#coordinator.highWaterGeneration;
  }

  async #readEnvelope(now: number): Promise<Envelope | undefined> {
    const envelope = await this.#readEnvelopeForCleanup(now);
    if (!envelope) return undefined;
    if (now >= envelope.expiresAt) {
      await this.sessionStore.remove(this.#storageKey);
      return undefined;
    }
    return envelope;
  }

  async #readEnvelopeForCleanup(now: number): Promise<Envelope | undefined> {
    const raw = await this.sessionStore.get<unknown>(this.#storageKey);
    if (raw === undefined) return undefined;
    const generation = readGeneration(raw);
    if (generation !== undefined) {
      this.#coordinator.highWaterGeneration = Math.max(
        this.#coordinator.highWaterGeneration,
        generation,
      );
    }
    if (!hasBoundedSize(this.#storageKey, raw)) return this.#purgeInvalid();
    let envelope: Envelope;
    try {
      envelope = parseEnvelope(raw, now);
    } catch {
      return this.#purgeInvalid();
    }
    return envelope;
  }

  async #toOutcomeUnknown(
    envelope: ClaimedEnvelope,
    terminalAt: number,
  ): Promise<UnknownEnvelope> {
    const unknown: UnknownEnvelope = {
      schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
      generation: this.#nextGeneration(),
      attemptGeneration: envelope.attemptGeneration,
      status: 'outcome_unknown',
      attemptId: envelope.attemptId,
      serverUrl: envelope.serverUrl,
      identityUrl: envelope.identityUrl,
      serverGeneration: envelope.serverGeneration,
      capabilityGeneration: envelope.capabilityGeneration,
      emailIntent: envelope.emailIntent,
      createdAt: envelope.createdAt,
      expiresAt: safeAdd(terminalAt, SSO_OUTCOME_UNKNOWN_TTL_MS),
      terminalAt,
      claimGeneration: envelope.generation,
      tabId: envelope.tabId,
      callbackDocumentId: envelope.callbackDocumentId,
      redirectUri: envelope.redirectUri,
      source: envelope.source,
    };
    await this.#writeEnvelope(unknown);
    return unknown;
  }

  async #writeEnvelope(envelope: Envelope): Promise<void> {
    if (!hasBoundedSize(this.#storageKey, envelope)) {
      throw storeError('storage_capacity', 'SSO attempt exceeds the storage limit.');
    }
    await this.sessionStore.set(this.#storageKey, envelope);
  }

  async #purgeInvalid(): Promise<undefined> {
    await this.sessionStore.remove(this.#storageKey);
    return undefined;
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.#coordinator.queue.tail.then(operation, operation);
    this.#coordinator.queue.tail = run.then(() => undefined, () => undefined);
    return run;
  }
}

function parseCreateInput(input: CreateSsoAttemptInput): Omit<
  WaitingEnvelope,
  'schemaVersion' | 'generation' | 'attemptGeneration' | 'status' | 'attemptId' | 'createdAt' | 'expiresAt'
> {
  const hasOrganizationIdentifier = Object.hasOwn(input, 'organizationIdentifier');
  const record = strictRecord(input, [
    'serverUrl', 'identityUrl', 'serverGeneration', 'emailIntent', 'tabId', 'connectorOrigin',
    'capabilityGeneration', 'connectorPath', 'state', 'verifier', 'redirectUri', 'emailTwoFactorMode',
    'source',
    ...(hasOrganizationIdentifier ? ['organizationIdentifier'] : []),
  ], 'SSO attempt input');
  const serverUrl = canonicalizeServerCapabilityUrl(boundedString(
    record.serverUrl,
    'serverUrl',
    2_048,
  ));
  const identityUrl = canonicalIdentityBase(record.identityUrl, false);
  const serverGeneration = nonNegativeInteger(record.serverGeneration, 'serverGeneration');
  const capabilityGeneration = positiveGeneration(record.capabilityGeneration);
  const emailIntent = normalizeSsoEmail(record.emailIntent);
  const tabId = nonNegativeInteger(record.tabId, 'tabId');
  const connector = parseConnectorBinding(
    record.connectorOrigin,
    record.connectorPath,
    record.redirectUri,
  );
  return {
    serverUrl,
    identityUrl,
    serverGeneration,
    capabilityGeneration,
    emailIntent,
    tabId,
    ...connector,
    state: parseSsoState(record.state),
    verifier: parseSsoPkceVerifier(record.verifier),
    emailTwoFactorMode: parseEmailTwoFactorMode(record.emailTwoFactorMode),
    source: parseSourceContext(record.source),
    ...(hasOrganizationIdentifier
      ? { organizationIdentifier: parseOrganizationIdentifier(record.organizationIdentifier) }
      : {}),
  };
}

function parseCallbackInput(input: BindSsoCallbackInput): BindSsoCallbackInput {
  const record = strictRecord(input, ['tabId', 'documentId', 'callbackUrl'], 'SSO callback input');
  return Object.freeze({
    tabId: nonNegativeInteger(record.tabId, 'tabId'),
    documentId: documentId(record.documentId),
    callbackUrl: boundedString(record.callbackUrl, 'callbackUrl', MAX_REDIRECT_URI_LENGTH),
  });
}

function parseEnvelope(input: unknown, now: number): Envelope {
  const record = strictRecord(input, undefined, 'SSO attempt envelope');
  if (record.schemaVersion !== SSO_ATTEMPT_SCHEMA_VERSION) invalidInput('schemaVersion');
  const status = record.status;
  if (status === 'outcome_unknown') {
    strictKeys(record, [
      'schemaVersion', 'generation', 'attemptGeneration', 'status', 'attemptId', 'serverUrl', 'identityUrl', 'serverGeneration',
      'capabilityGeneration', 'emailIntent', 'createdAt', 'expiresAt', 'terminalAt',
      'claimGeneration', 'tabId', 'callbackDocumentId', 'redirectUri', 'source',
    ], 'SSO outcome envelope');
    const envelope: UnknownEnvelope = {
      schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
      generation: positiveGeneration(record.generation),
      attemptGeneration: positiveGeneration(record.attemptGeneration),
      status,
      attemptId: parseUuid(record.attemptId, 'attemptId'),
      serverUrl: canonicalStoredServer(record.serverUrl),
      identityUrl: canonicalIdentityBase(record.identityUrl, true),
      serverGeneration: nonNegativeInteger(record.serverGeneration, 'serverGeneration'),
      capabilityGeneration: positiveGeneration(record.capabilityGeneration),
      emailIntent: canonicalStoredEmail(record.emailIntent),
      createdAt: parseTimestamp(record.createdAt, 'createdAt'),
      expiresAt: parseTimestamp(record.expiresAt, 'expiresAt'),
      terminalAt: parseTimestamp(record.terminalAt, 'terminalAt'),
      claimGeneration: positiveGeneration(record.claimGeneration),
      tabId: nonNegativeInteger(record.tabId, 'tabId'),
      callbackDocumentId: documentId(record.callbackDocumentId),
      redirectUri: canonicalCallbackRedirect(record.redirectUri),
      source: parseSourceContext(record.source),
    };
    validateUnknownLifetime(envelope, now);
    return envelope;
  }
  if (status !== 'waiting' && status !== 'claimed' && status !== 'submitting') invalidInput('status');
  const hasDocument = Object.hasOwn(record, 'callbackDocumentId');
  const hasOrganizationIdentifier = Object.hasOwn(record, 'organizationIdentifier');
  strictKeys(record, [
    'schemaVersion', 'generation', 'attemptGeneration', 'status', 'attemptId', 'serverUrl', 'identityUrl', 'serverGeneration',
    'capabilityGeneration', 'emailIntent', 'tabId', 'connectorOrigin', 'connectorPath', 'state', 'verifier',
    'redirectUri', 'emailTwoFactorMode', 'source', 'createdAt', 'expiresAt',
    ...(hasDocument ? ['callbackDocumentId'] : []),
    ...(hasOrganizationIdentifier ? ['organizationIdentifier'] : []),
    ...(status === 'claimed' || status === 'submitting' ? ['workerId', 'claimedAt'] : []),
  ], 'SSO active envelope');
  if ((status === 'claimed' || status === 'submitting') && !hasDocument) invalidInput('callbackDocumentId');
  const connector = parseConnectorBinding(
    record.connectorOrigin,
    record.connectorPath,
    record.redirectUri,
  );
  const common = {
    schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
    generation: positiveGeneration(record.generation),
    attemptGeneration: positiveGeneration(record.attemptGeneration),
    attemptId: parseUuid(record.attemptId, 'attemptId'),
    serverUrl: canonicalStoredServer(record.serverUrl),
    identityUrl: canonicalIdentityBase(record.identityUrl, true),
    serverGeneration: nonNegativeInteger(record.serverGeneration, 'serverGeneration'),
    capabilityGeneration: positiveGeneration(record.capabilityGeneration),
    emailIntent: canonicalStoredEmail(record.emailIntent),
    tabId: nonNegativeInteger(record.tabId, 'tabId'),
    ...(hasDocument ? { callbackDocumentId: documentId(record.callbackDocumentId) } : {}),
    ...connector,
    state: parseSsoState(record.state),
    verifier: parseSsoPkceVerifier(record.verifier),
    emailTwoFactorMode: parseEmailTwoFactorMode(record.emailTwoFactorMode),
    source: parseSourceContext(record.source),
    ...(hasOrganizationIdentifier
      ? { organizationIdentifier: parseOrganizationIdentifier(record.organizationIdentifier) }
      : {}),
    createdAt: parseTimestamp(record.createdAt, 'createdAt'),
    expiresAt: parseTimestamp(record.expiresAt, 'expiresAt'),
  };
  if (status === 'waiting') {
    const envelope: WaitingEnvelope = { ...common, status };
    validateActiveLifetime(envelope, now);
    return envelope;
  }
  const envelope: ClaimedEnvelope = {
    ...common,
    status,
    callbackDocumentId: documentId(record.callbackDocumentId),
    workerId: parseUuid(record.workerId, 'workerId'),
    claimedAt: parseTimestamp(record.claimedAt, 'claimedAt'),
  };
  validateActiveLifetime(envelope, now);
  if (envelope.claimedAt < envelope.createdAt || envelope.claimedAt > now) {
    invalidInput('claimedAt');
  }
  return envelope;
}

function parseConnectorBinding(
  originInput: unknown,
  pathInput: unknown,
  redirectInput: unknown,
): Pick<WaitingEnvelope, 'connectorOrigin' | 'connectorPath' | 'redirectUri'> {
  const connectorOrigin = canonicalOrigin(originInput);
  const connectorPath = boundedString(pathInput, 'connectorPath', MAX_CONNECTOR_PATH_LENGTH);
  if (
    !connectorPath.startsWith('/')
    || !connectorPath.endsWith('/sso-connector.html')
    || connectorPath.includes('?')
    || connectorPath.includes('#')
  ) {
    invalidInput('connectorPath');
  }
  const redirectUri = boundedString(redirectInput, 'redirectUri', MAX_REDIRECT_URI_LENGTH);
  let redirect: URL;
  try { redirect = new URL(redirectUri); } catch { return invalidInput('redirectUri'); }
  if (
    (redirect.protocol !== 'https:' && !isLoopbackHttp(redirect))
    || redirect.username
    || redirect.password
    || redirect.search
    || redirect.hash
    || redirect.origin !== connectorOrigin
    || redirect.pathname !== connectorPath
    || redirect.toString() !== redirectUri
  ) invalidInput('redirectUri');
  return Object.freeze({ connectorOrigin, connectorPath, redirectUri });
}

function parseEmailTwoFactorMode(
  input: unknown,
): 'vaultwarden-device' | 'bitwarden-session' {
  if (input !== 'vaultwarden-device' && input !== 'bitwarden-session') {
    invalidInput('emailTwoFactorMode');
  }
  return input;
}

function parseOrganizationIdentifier(input: unknown): string {
  const value = boundedString(input, 'organizationIdentifier', 256);
  if (!/^[A-Za-z0-9._~-]+$/u.test(value)) invalidInput('organizationIdentifier');
  return value;
}

function assertTrustedIssuer(
  issuer: string | undefined,
  serverUrl: string,
  identityUrl: string,
): void {
  if (issuer === undefined) return;
  const actual = withoutTrailingSlash(new URL(issuer));
  const allowed = [
    withoutTrailingSlash(new URL(serverUrl)),
    withoutTrailingSlash(new URL(identityUrl)),
  ];
  if (!allowed.includes(actual)) invalidInput('callback issuer');
}

function withoutTrailingSlash(url: URL): string {
  url.pathname = url.pathname.replace(/\/+$/u, '');
  return url.toString();
}

function canonicalOrigin(input: unknown): string {
  const value = boundedString(input, 'connectorOrigin', 2_048);
  let url: URL;
  try { url = new URL(value); } catch { return invalidInput('connectorOrigin'); }
  if (
    (url.protocol !== 'https:' && !isLoopbackHttp(url))
    || url.username
    || url.password
    || url.origin !== value
  ) invalidInput('connectorOrigin');
  return value;
}

function parseOwner(input: SsoAttemptOwner): SsoAttemptOwner {
  const record = strictRecord(input, [
    'generation', 'attemptGeneration', 'attemptId', 'serverUrl', 'identityUrl', 'serverGeneration', 'emailIntent',
    'capabilityGeneration',
  ], 'SSO attempt owner');
  return Object.freeze({
    generation: positiveGeneration(record.generation),
    attemptGeneration: positiveGeneration(record.attemptGeneration),
    attemptId: parseUuid(record.attemptId, 'attemptId'),
    serverUrl: canonicalStoredServer(record.serverUrl),
    identityUrl: canonicalIdentityBase(record.identityUrl, true),
    serverGeneration: nonNegativeInteger(record.serverGeneration, 'serverGeneration'),
    capabilityGeneration: positiveGeneration(record.capabilityGeneration),
    emailIntent: canonicalStoredEmail(record.emailIntent),
  });
}

function parseHandoff(input: SsoAttemptHandoff): SsoAttemptHandoff {
  const record = strictRecord(input, [
    'attemptId', 'attemptGeneration', 'serverUrl', 'identityUrl', 'email',
  ], 'SSO handoff');
  return Object.freeze({
    attemptId: parseUuid(record.attemptId, 'attemptId'),
    attemptGeneration: positiveGeneration(record.attemptGeneration),
    serverUrl: canonicalStoredServer(record.serverUrl),
    identityUrl: canonicalIdentityBase(record.identityUrl, true),
    email: canonicalStoredEmail(record.email),
  });
}

function snapshot(envelope: Envelope): SsoAttempt {
  const owner = Object.freeze({
    generation: envelope.generation,
    attemptGeneration: envelope.attemptGeneration,
    attemptId: envelope.attemptId,
    serverUrl: envelope.serverUrl,
    identityUrl: envelope.identityUrl,
    serverGeneration: envelope.serverGeneration,
    capabilityGeneration: envelope.capabilityGeneration,
    emailIntent: envelope.emailIntent,
  });
  if (envelope.status === 'outcome_unknown') {
    return Object.freeze({
      status: envelope.status,
      owner,
      createdAt: envelope.createdAt,
      expiresAt: envelope.expiresAt,
      terminalAt: envelope.terminalAt,
      claimGeneration: envelope.claimGeneration,
      tabId: envelope.tabId,
      callbackDocumentId: envelope.callbackDocumentId,
      redirectUri: envelope.redirectUri,
      source: envelope.source,
    });
  }
  const common = {
    owner,
    tabId: envelope.tabId,
    ...(envelope.callbackDocumentId === undefined
      ? {}
      : { callbackDocumentId: envelope.callbackDocumentId }),
    connectorOrigin: envelope.connectorOrigin,
    connectorPath: envelope.connectorPath,
    state: envelope.state,
    verifier: envelope.verifier,
    redirectUri: envelope.redirectUri,
    emailTwoFactorMode: envelope.emailTwoFactorMode,
    source: envelope.source,
    ...(envelope.organizationIdentifier === undefined
      ? {}
      : { organizationIdentifier: envelope.organizationIdentifier }),
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
  };
  return envelope.status === 'waiting'
    ? Object.freeze({ status: envelope.status, ...common }) as WaitingSsoAttempt
    : Object.freeze({
        status: envelope.status,
        ...common,
        callbackDocumentId: envelope.callbackDocumentId,
        workerId: envelope.workerId,
        claimedAt: envelope.claimedAt,
      }) as ClaimedSsoAttempt | SubmittingSsoAttempt;
}

function sameOwner(envelope: Envelope, owner: SsoAttemptOwner): boolean {
  return envelope.generation === owner.generation
    && envelope.attemptGeneration === owner.attemptGeneration
    && envelope.attemptId === owner.attemptId
    && envelope.serverUrl === owner.serverUrl
    && envelope.identityUrl === owner.identityUrl
    && envelope.serverGeneration === owner.serverGeneration
    && envelope.capabilityGeneration === owner.capabilityGeneration
    && envelope.emailIntent === owner.emailIntent;
}

function validateActiveLifetime(
  envelope: Pick<WaitingEnvelope, 'generation' | 'attemptGeneration' | 'createdAt' | 'expiresAt'>,
  now: number,
): void {
  if (
    envelope.attemptGeneration > envelope.generation
    ||
    envelope.createdAt > now
    || envelope.expiresAt !== safeAdd(envelope.createdAt, SSO_ATTEMPT_TTL_MS)
  ) invalidInput('lifetime');
}

function validateUnknownLifetime(envelope: UnknownEnvelope, now: number): void {
  if (
    envelope.attemptGeneration > envelope.claimGeneration
    ||
    envelope.createdAt > envelope.terminalAt
    || envelope.terminalAt > now
    || envelope.claimGeneration >= envelope.generation
    || envelope.expiresAt !== safeAdd(envelope.terminalAt, SSO_OUTCOME_UNKNOWN_TTL_MS)
  ) invalidInput('lifetime');
}

function canonicalStoredServer(input: unknown): string {
  const value = boundedString(input, 'serverUrl', 2_048);
  let canonical: string;
  try { canonical = canonicalizeServerCapabilityUrl(value); } catch { return invalidInput('serverUrl'); }
  if (canonical !== value) invalidInput('serverUrl');
  return value;
}

function canonicalIdentityBase(input: unknown, requireCanonical: boolean): string {
  const value = boundedString(input, 'identityUrl', 2_048);
  const normalized = normalizeServerEnvironmentUrl(value);
  if (!normalized || (requireCanonical && normalized !== value)) invalidInput('identityUrl');
  return normalized;
}

function canonicalStoredEmail(input: unknown): string {
  const value = boundedString(input, 'emailIntent', 254);
  let canonical: string;
  try { canonical = normalizeSsoEmail(value); } catch { return invalidInput('emailIntent'); }
  if (canonical !== value) invalidInput('emailIntent');
  return value;
}

function documentId(input: unknown): string {
  return boundedString(input, 'documentId', MAX_DOCUMENT_ID_LENGTH);
}

function parseSourceContext(input: unknown): SsoSourceContext {
  const record = strictRecord(input, undefined, 'SSO source context');
  const hasDocument = Object.hasOwn(record, 'document');
  strictKeys(
    record,
    hasDocument ? ['popupDocumentId', 'windowId', 'document'] : ['popupDocumentId', 'windowId'],
    'SSO source context',
  );
  const popupDocumentId = documentId(record.popupDocumentId);
  const windowId = nonNegativeInteger(record.windowId, 'source windowId');
  const document = hasDocument ? parseSourceDocument(record.document) : undefined;
  if (document && document.windowId !== windowId) invalidInput('source window binding');
  return Object.freeze({
    popupDocumentId,
    windowId,
    ...(document ? { document } : {}),
  });
}

function parseSourceDocument(input: unknown): SsoSourceDocument {
  const record = strictRecord(
    input,
    ['tabId', 'windowId', 'documentId', 'url'],
    'SSO source document',
  );
  return Object.freeze({
    tabId: nonNegativeInteger(record.tabId, 'source tabId'),
    windowId: nonNegativeInteger(record.windowId, 'source windowId'),
    documentId: documentId(record.documentId),
    url: canonicalSourceUrl(record.url),
  });
}

function canonicalSourceUrl(input: unknown): string {
  const value = boundedString(input, 'source URL', MAX_REDIRECT_URI_LENGTH);
  let url: URL;
  try { url = new URL(value); } catch { return invalidInput('source URL'); }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.toString() !== value
  ) invalidInput('source URL');
  return value;
}

function canonicalCallbackRedirect(input: unknown): string {
  const value = boundedString(input, 'redirectUri', MAX_REDIRECT_URI_LENGTH);
  let url: URL;
  try { url = new URL(value); } catch { return invalidInput('redirectUri'); }
  if (
    (url.protocol !== 'https:' && !isLoopbackHttp(url))
    || url.username
    || url.password
    || url.search
    || url.hash
    || !url.pathname.endsWith('/sso-connector.html')
    || url.toString() !== value
  ) invalidInput('redirectUri');
  return value;
}

function parseUuid(input: unknown, name: string): string {
  const value = boundedString(input, name, 36);
  if (value.length !== 36 || !UUID_V4_PATTERN.test(value)) invalidInput(name);
  return value;
}

function positiveGeneration(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) <= 0) invalidInput('generation');
  return input as number;
}

function nonNegativeInteger(input: unknown, name: string): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0 || Object.is(input, -0)) {
    invalidInput(name);
  }
  return input as number;
}

function parseTimestamp(input: unknown, name: string): number {
  return nonNegativeInteger(input, name);
}

function boundedString(input: unknown, name: string, maximum: number): string {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > maximum
    || input.trim() !== input
    || containsAsciiControl(input)
  ) invalidInput(name);
  return input;
}

function strictRecord(
  input: unknown,
  keys: readonly string[] | undefined,
  name: string,
): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) invalidInput(name);
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) invalidInput(name);
  const record = input as Record<string, unknown>;
  for (const key of Reflect.ownKeys(record)) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor)) {
      invalidInput(name);
    }
  }
  if (keys) strictKeys(record, keys, name);
  return record;
}

function strictKeys(record: Record<string, unknown>, keys: readonly string[], name: string): void {
  const actual = Object.keys(record);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) {
    invalidInput(name);
  }
}

function readGeneration(input: unknown): number | undefined {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(input, 'generation');
  return descriptor && 'value' in descriptor && Number.isSafeInteger(descriptor.value)
    && (descriptor.value as number) > 0
    ? descriptor.value as number
    : undefined;
}

function parseStorageKey(input: unknown): string {
  const key = boundedString(input, 'storageKey', MAX_STORAGE_KEY_LENGTH);
  if (/\s/u.test(key)) throw storeError('invalid_configuration', 'storageKey is invalid.');
  return key;
}

function sharedCoordinator(store: KeyValueStore, key: string): SharedCoordinator {
  let stores = COORDINATORS.get(store);
  if (!stores) {
    stores = new Map();
    COORDINATORS.set(store, stores);
  }
  const existing = stores.get(key);
  if (existing) return existing;
  const created: SharedCoordinator = {
    highWaterGeneration: 0,
    queue: { tail: Promise.resolve() },
  };
  stores.set(key, created);
  return created;
}

function hasBoundedSize(key: string, value: unknown): boolean {
  try {
    const serialized = JSON.stringify({ [key]: value });
    return typeof serialized === 'string'
      && new TextEncoder().encode(serialized).byteLength <= SSO_ATTEMPT_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}

function safeAdd(value: number, increment: number): number {
  const result = value + increment;
  if (!Number.isSafeInteger(result)) invalidInput('lifetime');
  return result;
}

function isLoopbackHttp(url: URL): boolean {
  if (url.protocol !== 'http:') return false;
  const hostname = url.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;
  if (hostname === '[::1]' || hostname === '::1') return true;
  const octets = hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function invalidInput(field: string): never {
  throw storeError('invalid_input', `SSO attempt ${field} is invalid.`);
}

function storeError(code: SsoAttemptStoreErrorCode, message: string): SsoAttemptStoreError {
  return new SsoAttemptStoreError(code, message);
}
