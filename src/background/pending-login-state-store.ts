import {
  canonicalizeServerCapabilityUrl,
  normalizeServerEnvironmentUrl,
} from '../core/api/server-capabilities.js';
import { base64ToBytes, bytesToBase64 } from '../core/crypto/encoding.js';
import { parseKdfConfig, type KdfConfig } from '../core/crypto/kdf.js';
import {
  parseMasterPasswordEvidence,
  parseMasterPasswordPolicy,
} from '../core/policy/master-password-policy.js';
import {
  PENDING_LOGIN_CONTINUATION_TTL_MS,
  type ActivePendingLoginContinuation,
  type ClaimedPendingLoginContinuation,
  type PendingLoginContinuationData,
  type PendingLoginContinuationOwner,
  type PendingLoginContinuationSnapshot,
  type PendingLoginContinuationStore,
  type PendingLoginFido2Metadata,
  type PendingSsoLoginGrant,
  type UnknownPendingLoginOutcome,
} from '../core/session/pending-login-continuation.js';
import { interactiveTwoFactorConnectorUrl } from '../core/session/interactive-two-factor.js';
import {
  duoProviderMetadata,
  extractDuoProviderSeed,
  type DuoProviderSeed,
} from '../core/session/duo-two-factor.js';
import type { KeyValueStore } from '../platform/store.js';

export const PENDING_LOGIN_CONTINUATION_STORAGE_KEY = 'pendingLoginContinuation';
export const PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX = 'pending-login-continuation-expiry:';
export const PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION = 1 as const;
export const PENDING_LOGIN_CONTINUATION_MAX_UTF8_BYTES = 64 * 1024;

const MAX_STORAGE_KEY_LENGTH = 256;
const MAX_EMAIL_LENGTH = 254;
const MAX_MASTER_PASSWORD_HASH_LENGTH = 1_024;
const MAX_TWO_FACTOR_PROVIDERS = 32;
const MAX_TWO_FACTOR_TOKEN_LENGTH = 32 * 1024;
const MAX_CONNECTOR_DATA_LENGTH = 32 * 1024;
const MAX_CONNECTOR_URL_LENGTH = 4_096;
const MAX_SSO_CODE_LENGTH = 64 * 1024;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type PendingLoginStateStoreErrorCode =
  | 'busy'
  | 'generation_exhausted'
  | 'invalid_configuration'
  | 'invalid_transition'
  | 'storage_capacity';

export class PendingLoginStateStoreError extends Error {
  constructor(
    readonly code: PendingLoginStateStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'PendingLoginStateStoreError';
  }
}

export interface PendingLoginStateStoreOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly workerId?: string;
  readonly createAttemptId?: () => string;
  readonly alarms?: {
    create(name: string, options: { readonly when: number }): void | PromiseLike<void>;
    clear(name: string): boolean | void | PromiseLike<boolean | void>;
  };
}

interface ActiveEnvelopeBase {
  readonly schemaVersion: typeof PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION;
  readonly generation: number;
  readonly status: 'active';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

type ActiveEnvelope = ActiveEnvelopeBase & (
  | { readonly data: PendingLoginContinuationData }
  | { readonly memoryOnly: true }
);

interface ClaimedEnvelopeBase {
  readonly schemaVersion: typeof PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION;
  readonly generation: number;
  readonly status: 'claimed';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly workerId: string;
  readonly claimedAt: number;
}

type ClaimedEnvelope = ClaimedEnvelopeBase & (
  | { readonly data: PendingLoginContinuationData }
  | { readonly memoryOnly: true }
);

interface OutcomeUnknownEnvelope {
  readonly schemaVersion: typeof PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION;
  readonly generation: number;
  readonly status: 'outcome_unknown';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly email: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

type StoredEnvelope = ActiveEnvelope | ClaimedEnvelope | OutcomeUnknownEnvelope;

interface SharedCoordinator {
  highWaterGeneration: number;
  readonly queue: OperationQueue;
}

interface OperationQueue {
  tail: Promise<void>;
}

const COORDINATORS = new WeakMap<KeyValueStore, Map<string, SharedCoordinator>>();
const FALLBACK_QUEUES = new Map<string, OperationQueue>();

export class PendingLoginStateStore implements PendingLoginContinuationStore {
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #workerId: string;
  readonly #createAttemptId: () => string;
  readonly #alarms: PendingLoginStateStoreOptions['alarms'];
  readonly #coordinator: SharedCoordinator;

  constructor(
    private readonly sessionStore: KeyValueStore,
    options: PendingLoginStateStoreOptions = {},
  ) {
    if (!sessionStore) throw storeError('invalid_configuration', 'sessionStore is required');
    this.#storageKey = parseStorageKey(
      options.storageKey ?? PENDING_LOGIN_CONTINUATION_STORAGE_KEY,
    );
    this.#now = options.now ?? Date.now;
    this.#workerId = parseUuid(options.workerId ?? crypto.randomUUID(), 'workerId');
    this.#createAttemptId = options.createAttemptId ?? (() => crypto.randomUUID());
    this.#alarms = options.alarms;
    this.#coordinator = sharedCoordinator(sessionStore, this.#storageKey);
  }

  read(): Promise<PendingLoginContinuationSnapshot | undefined> {
    return this.#serialize(async () => {
      let envelope = await this.#readEnvelope(this.#currentTime());
      if (envelope?.status === 'claimed' && envelope.workerId !== this.#workerId) {
        envelope = await this.#toOutcomeUnknown(envelope, this.#currentTime());
      }
      return envelope ? snapshot(envelope) : undefined;
    });
  }

  write(
    serverUrl: string,
    data: PendingLoginContinuationData,
  ): Promise<ActivePendingLoginContinuation> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      if (await this.#readEnvelope(now)) {
        throw storeError('busy', 'A pending login continuation is already active.');
      }
      const parsedServerUrl = canonicalizeServer(serverUrl);
      const parsedData = parseContinuationData(data, parsedServerUrl);
      const attemptId = parseUuid(this.#createAttemptId(), 'attemptId');
      const expiresAt = safeAdd(now, PENDING_LOGIN_CONTINUATION_TTL_MS);
      const envelope: ActiveEnvelope = {
        schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
        generation: this.#nextGeneration(),
        status: 'active',
        attemptId,
        serverUrl: parsedServerUrl,
        email: parsedData.email,
        createdAt: now,
        expiresAt,
        data: parsedData,
      };
      const alarmName = expirationAlarmName(attemptId);
      await this.#armExpiration(alarmName, expiresAt);
      try {
        await this.#writeEnvelope(envelope);
      } catch (error) {
        await this.#clearExpirationAlarm(alarmName);
        throw error;
      }
      return snapshot(envelope) as ActivePendingLoginContinuation;
    });
  }

  claim(
    expectedOwner: PendingLoginContinuationOwner,
  ): Promise<ClaimedPendingLoginContinuation | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (!current || current.status !== 'active' || !sameOwner(current, owner)) return undefined;
      const envelope: ClaimedEnvelope = {
        ...current,
        generation: this.#nextGeneration(),
        status: 'claimed',
        workerId: this.#workerId,
        claimedAt: now,
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as ClaimedPendingLoginContinuation;
    });
  }

  release(
    expectedOwner: PendingLoginContinuationOwner,
    data: PendingLoginContinuationData,
  ): Promise<ActivePendingLoginContinuation | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (!current || current.status !== 'claimed' || !('data' in current)
          || !sameOwner(current, owner)) return undefined;
      const parsedData = parseContinuationData(data, current.serverUrl);
      if (parsedData.email !== current.email) {
        throw storeError('invalid_transition', 'Continuation identity changed during release.');
      }
      const envelope: ActiveEnvelope = {
        schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
        generation: this.#nextGeneration(),
        status: 'active',
        attemptId: current.attemptId,
        serverUrl: current.serverUrl,
        email: current.email,
        createdAt: current.createdAt,
        expiresAt: current.expiresAt,
        data: parsedData,
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as ActivePendingLoginContinuation;
    });
  }

  redact(
    expectedOwner: PendingLoginContinuationOwner,
  ): Promise<ActivePendingLoginContinuation | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (!current || current.status === 'outcome_unknown' || !sameOwner(current, owner)) return undefined;
      const envelope = this.#activeMarker(current);
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as ActivePendingLoginContinuation;
    });
  }

  releaseMarker(
    expectedOwner: PendingLoginContinuationOwner,
  ): Promise<ActivePendingLoginContinuation | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (!current || current.status !== 'claimed' || !('memoryOnly' in current)
          || !sameOwner(current, owner)) return undefined;
      const envelope = this.#activeMarker(current);
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as ActivePendingLoginContinuation;
    });
  }

  markOutcomeUnknown(
    expectedOwner: PendingLoginContinuationOwner,
  ): Promise<UnknownPendingLoginOutcome | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (!current || !sameOwner(current, owner)) return undefined;
      return snapshot(await this.#toOutcomeUnknown(current, now)) as UnknownPendingLoginOutcome;
    });
  }

  clear(expectedOwner: PendingLoginContinuationOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current || !sameOwner(current, owner)) return false;
      await this.sessionStore.remove(this.#storageKey);
      await this.#clearExpirationAlarm(expirationAlarmName(current.attemptId));
      return true;
    });
  }

  clearAttempt(expectedOwner: PendingLoginContinuationOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current
          || current.attemptId !== owner.attemptId
          || current.serverUrl !== owner.serverUrl
          || current.email !== owner.email) return false;
      await this.sessionStore.remove(this.#storageKey);
      await this.#clearExpirationAlarm(expirationAlarmName(current.attemptId));
      return true;
    });
  }

  ensureExpirationAlarm(): Promise<void> {
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (!current) return;
      try {
        await this.#armExpiration(expirationAlarmName(current.attemptId), current.expiresAt);
      } catch (error) {
        await this.sessionStore.remove(this.#storageKey);
        throw error;
      }
    });
  }

  handleExpirationAlarm(name: string): Promise<boolean> {
    const attemptId = parseExpirationAlarmAttemptId(name);
    if (!attemptId) return Promise.resolve(false);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (current?.attemptId === attemptId) {
        await this.#armExpiration(name, current.expiresAt);
      } else {
        await this.#clearExpirationAlarm(name);
      }
      return true;
    });
  }

  #currentTime(): number {
    const value = this.#now();
    if (!isTimestamp(value)) {
      throw storeError('invalid_configuration', 'now must return a non-negative safe integer.');
    }
    return value;
  }

  #nextGeneration(): number {
    const next = this.#coordinator.highWaterGeneration + 1;
    if (!Number.isSafeInteger(next) || next <= 0) {
      throw storeError('generation_exhausted', 'Pending login generation is exhausted.');
    }
    this.#coordinator.highWaterGeneration = next;
    return next;
  }

  #activeMarker(current: ActiveEnvelope | ClaimedEnvelope): ActiveEnvelope {
    return {
      schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
      generation: this.#nextGeneration(),
      status: 'active',
      attemptId: current.attemptId,
      serverUrl: current.serverUrl,
      email: current.email,
      createdAt: current.createdAt,
      expiresAt: current.expiresAt,
      memoryOnly: true,
    };
  }

  async #readEnvelope(now: number): Promise<StoredEnvelope | undefined> {
    const raw = await this.sessionStore.get<unknown>(this.#storageKey);
    if (raw === undefined) return undefined;
    const rawGeneration = readGeneration(raw);
    if (rawGeneration !== undefined) {
      this.#coordinator.highWaterGeneration = Math.max(
        this.#coordinator.highWaterGeneration,
        rawGeneration,
      );
    }
    if (!hasBoundedSize(this.#storageKey, raw)) return this.#purgeInvalid();
    let parsed: StoredEnvelope;
    try {
      parsed = parseEnvelope(raw);
    } catch {
      return this.#purgeInvalid();
    }
    this.#coordinator.highWaterGeneration = Math.max(
      this.#coordinator.highWaterGeneration,
      parsed.generation,
    );
    if (now >= parsed.expiresAt) return this.#purgeInvalid();
    return parsed;
  }

  async #purgeInvalid(): Promise<undefined> {
    await this.sessionStore.remove(this.#storageKey);
    return undefined;
  }

  async #armExpiration(name: string, when: number): Promise<void> {
    await Promise.resolve(this.#alarms?.create(
      name,
      { when },
    ));
  }

  async #clearExpirationAlarm(name: string): Promise<void> {
    await Promise.resolve(
      this.#alarms?.clear(name),
    ).catch(() => undefined);
  }

  async #toOutcomeUnknown(
    current: StoredEnvelope,
    now: number,
  ): Promise<OutcomeUnknownEnvelope> {
    const envelope: OutcomeUnknownEnvelope = {
      schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
      generation: this.#nextGeneration(),
      status: 'outcome_unknown',
      attemptId: current.attemptId,
      serverUrl: current.serverUrl,
      email: current.email,
      createdAt: current.createdAt,
      expiresAt: current.expiresAt,
      terminalAt: now,
    };
    await this.#writeEnvelope(envelope);
    return envelope;
  }

  async #writeEnvelope(envelope: StoredEnvelope): Promise<void> {
    if (!hasBoundedSize(this.#storageKey, envelope)) {
      throw storeError('storage_capacity', 'Pending login continuation exceeds its size limit.');
    }
    await this.sessionStore.set(this.#storageKey, envelope);
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#coordinator.queue.tail.then(operation, operation);
    this.#coordinator.queue.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

function parseEnvelope(input: unknown): StoredEnvelope {
  const record = strictRecord(input, 'pending login envelope');
  const status = own(record, 'status');
  const baseFields = [
    'schemaVersion', 'generation', 'status', 'attemptId', 'serverUrl', 'email',
    'createdAt', 'expiresAt',
  ];
  const memoryOnly = ownOptional(record, 'memoryOnly') === true;
  const expectedFields = status === 'active'
    ? [...baseFields, memoryOnly ? 'memoryOnly' : 'data']
    : status === 'claimed'
      ? [...baseFields, memoryOnly ? 'memoryOnly' : 'data', 'workerId', 'claimedAt']
      : status === 'outcome_unknown'
        ? [...baseFields, 'terminalAt']
        : [];
  if (expectedFields.length === 0 || !hasExactKeys(record, expectedFields)) {
    throw new Error('Invalid pending login envelope fields');
  }
  if (own(record, 'schemaVersion') !== PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION) {
    throw new Error('Unsupported pending login envelope version');
  }
  const generation = parseGeneration(own(record, 'generation'));
  const attemptId = parseUuid(own(record, 'attemptId'), 'attemptId');
  const serverUrl = canonicalizeServer(own(record, 'serverUrl'));
  const email = normalizeEmail(own(record, 'email'));
  const createdAt = parseTimestamp(own(record, 'createdAt'), 'createdAt');
  const expiresAt = parseTimestamp(own(record, 'expiresAt'), 'expiresAt');
  if (
    expiresAt <= createdAt
    || expiresAt - createdAt !== PENDING_LOGIN_CONTINUATION_TTL_MS
  ) throw new Error('Invalid pending login TTL');

  if (status === 'active') {
    if (memoryOnly) {
      return {
        schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
        generation,
        status,
        attemptId,
        serverUrl,
        email,
        createdAt,
        expiresAt,
        memoryOnly: true,
      };
    }
    const data = parseContinuationData(own(record, 'data'), serverUrl);
    if (data.email !== email) throw new Error('Pending login identity mismatch');
    return {
      schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
      generation,
      status,
      attemptId,
      serverUrl,
      email,
      createdAt,
      expiresAt,
      data,
    };
  }
  if (status === 'claimed') {
    const workerId = parseUuid(own(record, 'workerId'), 'workerId');
    const claimedAt = parseTimestamp(own(record, 'claimedAt'), 'claimedAt');
    if (claimedAt < createdAt || claimedAt >= expiresAt) {
      throw new Error('Invalid pending login claim time');
    }
    const claimedBase: ClaimedEnvelopeBase = {
      schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
      generation,
      status,
      attemptId,
      serverUrl,
      email,
      createdAt,
      expiresAt,
      workerId,
      claimedAt,
    };
    if (memoryOnly) return { ...claimedBase, memoryOnly: true };
    const data = parseContinuationData(own(record, 'data'), serverUrl);
    if (data.email !== email) throw new Error('Pending login identity mismatch');
    return { ...claimedBase, data };
  }
  const terminalAt = parseTimestamp(own(record, 'terminalAt'), 'terminalAt');
  if (terminalAt < createdAt || terminalAt >= expiresAt) {
    throw new Error('Invalid pending login terminal time');
  }
  return {
    schemaVersion: PENDING_LOGIN_CONTINUATION_SCHEMA_VERSION,
    generation,
    status: 'outcome_unknown',
    attemptId,
    serverUrl,
    email,
    createdAt,
    expiresAt,
    terminalAt,
  };
}

function parseContinuationData(
  input: unknown,
  expectedServerUrl: string,
): PendingLoginContinuationData {
  const record = strictRecord(input, 'pending login continuation');
  const hasToken = Object.hasOwn(record, 'twoFactorToken');
  const hasFido2 = Object.hasOwn(record, 'fido2');
  const hasDuo = Object.hasOwn(record, 'duo');
  const hasEvidence = Object.hasOwn(record, 'passwordEvidence');
  const hasPolicy = Object.hasOwn(record, 'masterPasswordPolicy');
  const hasForce = Object.hasOwn(record, 'forcePasswordReset');
  const hasPasswordGrant = Object.hasOwn(record, 'masterPasswordHash');
  const hasSsoGrant = Object.hasOwn(record, 'sso');
  if (hasPasswordGrant === hasSsoGrant) {
    throw new Error('Pending login continuation must contain exactly one grant');
  }
  if (!hasExactKeys(record, [
    'stage', 'email', 'kdf', 'providers',
    ...(hasPasswordGrant ? ['masterPasswordHash'] : ['sso']),
    ...(hasToken ? ['twoFactorToken'] : []),
    ...(hasFido2 ? ['fido2'] : []),
    ...(hasDuo ? ['duo'] : []),
    ...(hasEvidence ? ['passwordEvidence'] : []),
    ...(hasPolicy ? ['masterPasswordPolicy'] : []),
    ...(hasForce ? ['forcePasswordReset'] : []),
  ])) throw new Error('Invalid pending login continuation fields');
  const stage = own(record, 'stage');
  if (stage !== 'newDeviceVerification' && stage !== 'twoFactor') {
    throw new Error('Invalid pending login stage');
  }
  const email = normalizeEmail(own(record, 'email'));
  const masterPasswordHash = hasPasswordGrant
    ? parseMasterPasswordHash(own(record, 'masterPasswordHash'))
    : undefined;
  const sso = hasSsoGrant ? parseSsoGrant(own(record, 'sso')) : undefined;
  const kdf = parseStrictKdf(own(record, 'kdf'));
  const providers = parseProviders(own(record, 'providers'), stage);
  const twoFactorToken = hasToken
    ? boundedString(own(record, 'twoFactorToken'), 'twoFactorToken', MAX_TWO_FACTOR_TOKEN_LENGTH)
    : undefined;
  const fido2 = hasFido2
    ? parseFido2Metadata(own(record, 'fido2'), expectedServerUrl)
    : undefined;
  const duo = hasDuo ? parseDuoSeeds(own(record, 'duo')) : undefined;
  const passwordEvidence = hasEvidence
    ? parseMasterPasswordEvidence(own(record, 'passwordEvidence'))
    : undefined;
  const masterPasswordPolicy = hasPolicy
    ? parseMasterPasswordPolicy(own(record, 'masterPasswordPolicy'))
    : undefined;
  if (hasPolicy && !masterPasswordPolicy) {
    throw new Error('Pending login continuation has no master password policy');
  }
  if (hasForce && own(record, 'forcePasswordReset') !== true) {
    throw new Error('Pending login continuation has an invalid force password reset flag');
  }
  if (stage === 'newDeviceVerification' && (twoFactorToken !== undefined || fido2 !== undefined)) {
    throw new Error('New-device verification continuation contains two-factor state');
  }
  if (stage === 'newDeviceVerification' && sso) {
    throw new Error('SSO new-device verification is unsupported');
  }
  if (fido2 && !providers.includes(7)) {
    throw new Error('FIDO2 metadata is not associated with provider 7');
  }
  if (
    duo?.some((entry) => !providers.includes(entry.provider))
    || providers.some((provider) => (provider === 2 || provider === 6)
      && !duo?.some((entry) => entry.provider === provider))
  ) throw new Error('Duo metadata is not associated with its provider');
  if (sso && passwordEvidence) {
    throw new Error('SSO continuation must not contain password evidence');
  }
  return Object.freeze({
    stage,
    email,
    ...(masterPasswordHash ? { masterPasswordHash } : {}),
    ...(sso ? { sso } : {}),
    kdf,
    providers,
    ...(twoFactorToken !== undefined ? { twoFactorToken } : {}),
    ...(fido2 !== undefined ? { fido2 } : {}),
    ...(duo !== undefined ? { duo } : {}),
    ...(passwordEvidence ? { passwordEvidence } : {}),
    ...(masterPasswordPolicy ? { masterPasswordPolicy } : {}),
    ...(hasForce ? { forcePasswordReset: true as const } : {}),
  });
}

function parseDuoSeeds(input: unknown): readonly DuoProviderSeed[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > 2) {
    throw new Error('Invalid pending Duo metadata');
  }
  const seeds = input.map((candidate) => {
    const record = strictRecord(candidate, 'pending Duo provider');
    const hasHost = Object.hasOwn(record, 'host');
    if (!hasExactKeys(record, ['provider', 'authUrl', ...(hasHost ? ['host'] : [])])) {
      throw new Error('Invalid pending Duo provider fields');
    }
    const provider = own(record, 'provider');
    if (provider !== 2 && provider !== 6) throw new Error('Invalid pending Duo provider');
    const seed = {
      provider,
      authUrl: boundedString(own(record, 'authUrl'), 'Duo AuthUrl', 16 * 1024),
      ...(hasHost ? { host: boundedString(own(record, 'host'), 'Duo Host', 253) } : {}),
    } as const;
    return extractDuoProviderSeed(duoProviderMetadata(seed), provider);
  });
  if (new Set(seeds.map((entry) => entry.provider)).size !== seeds.length) {
    throw new Error('Duplicate pending Duo provider');
  }
  return Object.freeze(seeds);
}

function parseSsoGrant(input: unknown): PendingSsoLoginGrant {
  const record = strictRecord(input, 'pending SSO grant');
  const hasEmailToken = Object.hasOwn(record, 'emailTwoFactorSessionToken');
  if (!hasExactKeys(record, [
    'ssoAttemptId', 'ssoAttemptGeneration', 'code', 'codeVerifier', 'redirectUri', 'identityUrl',
    'emailTwoFactorMode',
    ...(hasEmailToken ? ['emailTwoFactorSessionToken'] : []),
  ])) throw new Error('Invalid pending SSO grant fields');
  const ssoAttemptId = parseUuid(own(record, 'ssoAttemptId'), 'SSO attempt id');
  const ssoAttemptGeneration = parseGeneration(own(record, 'ssoAttemptGeneration'));
  const code = boundedString(own(record, 'code'), 'SSO authorization code', MAX_SSO_CODE_LENGTH);
  if (/\s/u.test(code)) throw new Error('Invalid pending SSO authorization code');
  const codeVerifier = boundedString(own(record, 'codeVerifier'), 'SSO code verifier', 128);
  if (codeVerifier.length < 43 || !/^[A-Za-z0-9._~-]+$/u.test(codeVerifier)) {
    throw new Error('Invalid pending SSO code verifier');
  }
  const identityUrl = normalizeServerEnvironmentUrl(own(record, 'identityUrl'));
  if (!identityUrl || identityUrl !== own(record, 'identityUrl')) {
    throw new Error('Invalid pending SSO identity URL');
  }
  const redirectUri = parseSsoRedirectUri(own(record, 'redirectUri'));
  const emailTwoFactorMode = own(record, 'emailTwoFactorMode');
  if (emailTwoFactorMode !== 'vaultwarden-device' && emailTwoFactorMode !== 'bitwarden-session') {
    throw new Error('Invalid pending SSO email two-factor mode');
  }
  const emailTwoFactorSessionToken = hasEmailToken
    ? boundedString(
        own(record, 'emailTwoFactorSessionToken'),
        'SSO email two-factor session token',
        MAX_TWO_FACTOR_TOKEN_LENGTH,
      )
    : undefined;
  if (emailTwoFactorMode === 'vaultwarden-device' && emailTwoFactorSessionToken !== undefined) {
    throw new Error('Vaultwarden SSO continuation contains a Bitwarden email session token');
  }
  return Object.freeze({
    ssoAttemptId,
    ssoAttemptGeneration,
    code,
    codeVerifier,
    redirectUri,
    identityUrl,
    emailTwoFactorMode,
    ...(emailTwoFactorSessionToken ? { emailTwoFactorSessionToken } : {}),
  });
}

function parseSsoRedirectUri(input: unknown): string {
  const value = boundedString(input, 'SSO redirect URI', MAX_CONNECTOR_URL_LENGTH);
  const url = new URL(value);
  const loopback = url.hostname === 'localhost'
    || url.hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/u.test(url.hostname);
  if (
    url.toString() !== value
    || url.username
    || url.password
    || url.search
    || url.hash
    || !url.pathname.endsWith('/sso-connector.html')
    || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
  ) throw new Error('Invalid pending SSO redirect URI');
  return value;
}

function parseStrictKdf(input: unknown): KdfConfig {
  const record = strictRecord(input, 'pending login KDF');
  const type = own(record, 'kdf');
  const expected = type === 0
    ? ['kdf', 'kdfIterations']
    : type === 1
      ? ['kdf', 'kdfIterations', 'kdfMemory', 'kdfParallelism']
      : [];
  if (expected.length === 0 || !hasExactKeys(record, expected)) {
    throw new Error('Invalid pending login KDF fields');
  }
  return Object.freeze(parseKdfConfig(record));
}

function parseProviders(input: unknown, stage: string): readonly number[] {
  if (!Array.isArray(input) || input.length > MAX_TWO_FACTOR_PROVIDERS) {
    throw new Error('Invalid pending login providers');
  }
  if (stage === 'twoFactor' && input.length === 0) {
    throw new Error('Two-factor continuation has no providers');
  }
  if (stage === 'newDeviceVerification' && input.length !== 0) {
    throw new Error('New-device verification continuation has providers');
  }
  const providers = input.map((value) => {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new Error('Invalid pending login provider');
    }
    return value as number;
  });
  if (new Set(providers).size !== providers.length) {
    throw new Error('Duplicate pending login provider');
  }
  providers.sort((left, right) => left - right);
  return Object.freeze(providers);
}

function parseFido2Metadata(input: unknown, serverUrl: string): PendingLoginFido2Metadata {
  const record = strictRecord(input, 'pending FIDO2 metadata');
  if (!hasExactKeys(record, ['connectorData', 'connectorUrl'])) {
    throw new Error('Invalid pending FIDO2 metadata fields');
  }
  const connectorData = boundedString(
    own(record, 'connectorData'),
    'connectorData',
    MAX_CONNECTOR_DATA_LENGTH,
  );
  let providerOptions: unknown;
  try {
    providerOptions = JSON.parse(connectorData);
  } catch {
    throw new Error('Invalid pending FIDO2 connector data');
  }
  strictRecord(providerOptions, 'pending FIDO2 provider options');
  if (JSON.stringify(providerOptions) !== connectorData) {
    throw new Error('Pending FIDO2 connector data is not canonical JSON');
  }
  const connectorUrl = boundedString(
    own(record, 'connectorUrl'),
    'connectorUrl',
    MAX_CONNECTOR_URL_LENGTH,
  );
  const expected = expectedConnectorUrl(serverUrl);
  if (connectorUrl !== expected) throw new Error('Pending FIDO2 connector URL changed');
  return Object.freeze({ connectorData, connectorUrl });
}

function expectedConnectorUrl(serverUrl: string): string {
  return interactiveTwoFactorConnectorUrl(serverUrl);
}

function parseMasterPasswordHash(input: unknown): string {
  const value = boundedString(input, 'masterPasswordHash', MAX_MASTER_PASSWORD_HASH_LENGTH);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new Error('Invalid masterPasswordHash base64');
  }
  const bytes = base64ToBytes(value);
  try {
    if (bytes.byteLength !== 32 || bytesToBase64(bytes) !== value) {
      throw new Error('Invalid masterPasswordHash length');
    }
  } finally {
    bytes.fill(0);
  }
  return value;
}

function parseOwner(input: unknown): PendingLoginContinuationOwner {
  const record = strictRecord(input, 'pending login owner');
  if (!hasExactKeys(record, ['generation', 'attemptId', 'serverUrl', 'email'])) {
    throw storeError('invalid_transition', 'Invalid pending login owner.');
  }
  return Object.freeze({
    generation: parseGeneration(own(record, 'generation')),
    attemptId: parseUuid(own(record, 'attemptId'), 'attemptId'),
    serverUrl: canonicalizeServer(own(record, 'serverUrl')),
    email: normalizeEmail(own(record, 'email')),
  });
}

function snapshot(envelope: StoredEnvelope): PendingLoginContinuationSnapshot {
  const owner = Object.freeze({
    generation: envelope.generation,
    attemptId: envelope.attemptId,
    serverUrl: envelope.serverUrl,
    email: envelope.email,
  });
  if (envelope.status === 'active') {
    return Object.freeze({
      status: envelope.status,
      owner,
      createdAt: envelope.createdAt,
      expiresAt: envelope.expiresAt,
      ...('data' in envelope ? { data: envelope.data } : { memoryOnly: true as const }),
    });
  }
  if (envelope.status === 'claimed') {
    return Object.freeze({
      status: envelope.status,
      owner,
      createdAt: envelope.createdAt,
      expiresAt: envelope.expiresAt,
      claimedAt: envelope.claimedAt,
      ...('data' in envelope ? { data: envelope.data } : { memoryOnly: true as const }),
    });
  }
  return Object.freeze({
    status: envelope.status,
    owner,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
    terminalAt: envelope.terminalAt,
  });
}

function sameOwner(
  envelope: StoredEnvelope,
  owner: PendingLoginContinuationOwner,
): boolean {
  return envelope.generation === owner.generation
    && envelope.attemptId === owner.attemptId
    && envelope.serverUrl === owner.serverUrl
    && envelope.email === owner.email;
}

function strictRecord(input: unknown, label: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new Error(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(input)) {
    if (typeof key !== 'string') throw new Error(`${label} contains a symbol key`);
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw new Error(`${label} contains an unsafe property`);
    }
    output[key] = descriptor.value;
  }
  return output;
}

function own(record: Record<string, unknown>, key: string): unknown {
  if (!Object.hasOwn(record, key)) throw new Error(`Missing pending login field: ${key}`);
  return record[key];
}

function ownOptional(record: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

function hasExactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(record);
  const allowed = new Set(expected);
  return keys.length === allowed.size && keys.every((key) => allowed.has(key));
}

function boundedString(input: unknown, label: string, maximum: number): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > maximum) {
    throw new Error(`Invalid ${label}`);
  }
  for (let index = 0; index < input.length; index++) {
    const code = input.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) throw new Error(`Invalid ${label}`);
  }
  return input;
}

function normalizeEmail(input: unknown): string {
  const value = boundedString(input, 'email', MAX_EMAIL_LENGTH);
  const normalized = value.trim().toLowerCase();
  if (value !== normalized || !normalized.includes('@') || /\s/u.test(normalized)) {
    throw new Error('Invalid pending login email');
  }
  return normalized;
}

function canonicalizeServer(input: unknown): string {
  if (typeof input !== 'string') throw new Error('Invalid pending login server URL');
  return canonicalizeServerCapabilityUrl(input);
}

function parseUuid(input: unknown, label: string): string {
  if (typeof input !== 'string') throw new Error(`Invalid ${label}`);
  const value = input.toLowerCase();
  if (input !== value || !UUID_PATTERN.test(value)) throw new Error(`Invalid ${label}`);
  return value;
}

function expirationAlarmName(attemptId: string): string {
  return `${PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX}${attemptId}`;
}

function parseExpirationAlarmAttemptId(name: string): string | undefined {
  if (!name.startsWith(PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX)) return undefined;
  try {
    return parseUuid(name.slice(PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX.length), 'alarm attemptId');
  } catch {
    return undefined;
  }
}

export function isPendingLoginContinuationExpirationAlarm(name: string): boolean {
  return parseExpirationAlarmAttemptId(name) !== undefined;
}

export function pendingLoginContinuationExpirationAttemptId(
  name: string,
): string | undefined {
  return parseExpirationAlarmAttemptId(name);
}

function parseGeneration(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) <= 0) {
    throw new Error('Invalid pending login generation');
  }
  return input as number;
}

function parseTimestamp(input: unknown, label: string): number {
  if (!isTimestamp(input)) throw new Error(`Invalid ${label}`);
  return input;
}

function isTimestamp(input: unknown): input is number {
  return Number.isSafeInteger(input) && (input as number) >= 0;
}

function safeAdd(value: number, increment: number): number {
  const result = value + increment;
  if (!Number.isSafeInteger(result)) {
    throw storeError('invalid_configuration', 'Pending login deadline exceeds safe range.');
  }
  return result;
}

function readGeneration(input: unknown): number | undefined {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(input, 'generation');
  return descriptor?.enumerable && 'value' in descriptor && Number.isSafeInteger(descriptor.value)
    ? descriptor.value as number
    : undefined;
}

function hasBoundedSize(key: string, value: unknown): boolean {
  try {
    return new TextEncoder().encode(JSON.stringify({ [key]: value })).byteLength
      <= PENDING_LOGIN_CONTINUATION_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}

function parseStorageKey(input: string): string {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > MAX_STORAGE_KEY_LENGTH
    || input.trim() !== input
  ) throw storeError('invalid_configuration', 'Invalid pending login storage key.');
  return input;
}

function sharedCoordinator(store: KeyValueStore, key: string): SharedCoordinator {
  let byKey = COORDINATORS.get(store);
  if (!byKey) {
    byKey = new Map();
    COORDINATORS.set(store, byKey);
  }
  let coordinator = byKey.get(key);
  if (!coordinator) {
    const queueKey = `${key}\n${crypto.randomUUID()}`;
    const queue = FALLBACK_QUEUES.get(queueKey) ?? { tail: Promise.resolve() };
    FALLBACK_QUEUES.set(queueKey, queue);
    coordinator = { highWaterGeneration: 0, queue };
    byKey.set(key, coordinator);
  }
  return coordinator;
}

function storeError(
  code: PendingLoginStateStoreErrorCode,
  message: string,
): PendingLoginStateStoreError {
  return new PendingLoginStateStoreError(code, message);
}
