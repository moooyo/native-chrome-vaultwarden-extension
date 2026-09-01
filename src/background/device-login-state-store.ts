import type { KeyValueStore } from '../platform/store.js';
import { canonicalizeServerCapabilityUrl } from '../core/api/server-capabilities.js';
import {
  parseMasterPasswordPolicy,
  type MasterPasswordPolicy,
} from '../core/policy/master-password-policy.js';
import {
  restoreDeviceLoginState,
  type DeviceLoginBoundState,
  type DeviceLoginPendingState,
  type DeviceLoginState,
} from '../core/session/device-login.js';
import { parseFido2TwoFactorRequest } from '../core/session/fido2-two-factor.js';
import { interactiveTwoFactorConnectorUrl } from '../core/session/interactive-two-factor.js';
import {
  duoProviderMetadata,
  extractDuoProviderSeed,
  type DuoProviderSeed,
} from '../core/session/duo-two-factor.js';

export const DEVICE_LOGIN_STATE_STORAGE_KEY = 'deviceLoginState';
export const DEVICE_LOGIN_STATE_ENVELOPE_VERSION = 1 as const;
export const DEVICE_LOGIN_STATE_ENVELOPE_MAX_UTF8_BYTES = 4 * 1024 * 1024;

const MAX_STORAGE_KEY_LENGTH = 256;
const MAX_TWO_FACTOR_PROVIDERS = 256;
const MAX_TWO_FACTOR_TOKEN_LENGTH = 32 * 1024;
const MAX_CONNECTOR_DATA_LENGTH = 32 * 1024;
const REQUEST_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type DeviceLoginStateStoreErrorCode =
  | 'invalid_configuration'
  | 'invalid_generation'
  | 'busy'
  | 'invalid_transition'
  | 'storage_capacity'
  | 'generation_exhausted';

export class DeviceLoginStateStoreError extends Error {
  constructor(
    readonly code: DeviceLoginStateStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'DeviceLoginStateStoreError';
  }
}

export interface DeviceLoginStateStoreOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
  /** Stable only for this service-worker lifetime. Tests may inject it to model a restart. */
  readonly workerId?: string;
}

export interface DeviceLoginStateOwner {
  readonly generation: number;
  readonly serverUrl: string;
  readonly requestId?: string;
}

export interface DeviceLoginStoredTwoFactorChallenge {
  readonly providers: readonly number[];
  readonly token?: string;
  readonly fido2?: DeviceLoginStoredFido2Challenge;
  readonly duo?: readonly DuoProviderSeed[];
  readonly forcePasswordReset?: true;
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
}

export interface DeviceLoginStoredFido2Challenge {
  readonly connectorData: string;
  readonly connectorUrl: string;
}

export interface DeviceLoginReleaseState {
  readonly twoFactor?: DeviceLoginStoredTwoFactorChallenge;
  readonly retryRequired?: true;
}

export interface ActiveDeviceLoginStateSnapshot {
  readonly owner: DeviceLoginStateOwner;
  readonly claimed: false;
  readonly state: DeviceLoginState;
  readonly twoFactor?: DeviceLoginStoredTwoFactorChallenge;
  readonly retryRequired?: true;
}

export type ActiveDeviceLoginBoundStateSnapshot =
  Omit<ActiveDeviceLoginStateSnapshot, 'state'>
  & { readonly state: DeviceLoginBoundState };

export interface ClaimedDeviceLoginStateSnapshot {
  readonly owner: DeviceLoginStateOwner & { readonly requestId: string };
  readonly claimed: true;
  readonly state: DeviceLoginBoundState;
  readonly twoFactor?: DeviceLoginStoredTwoFactorChallenge;
  readonly retryRequired?: true;
}

export type DeviceLoginStateSnapshot =
  | ActiveDeviceLoginStateSnapshot
  | ClaimedDeviceLoginStateSnapshot;

export interface DeviceLoginOutcomeUnknownSnapshot {
  readonly owner: DeviceLoginStateOwner;
  readonly status: 'outcome_unknown';
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

export type DeviceLoginStateReadResult =
  | DeviceLoginStateSnapshot
  | DeviceLoginOutcomeUnknownSnapshot;

export interface ActiveDeviceLoginStateMetadata {
  readonly generation: number;
  readonly claimed: boolean;
  readonly phase: DeviceLoginState['phase'];
  readonly email: string;
  readonly serverOrigin: string;
  readonly device: Readonly<Pick<DeviceLoginState['device'], 'type' | 'name'>>;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface DeviceLoginOutcomeUnknownMetadata {
  readonly generation: number;
  readonly status: 'outcome_unknown';
  readonly serverOrigin: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

export type DeviceLoginStateMetadata =
  | ActiveDeviceLoginStateMetadata
  | DeviceLoginOutcomeUnknownMetadata;

interface EmptyEnvelope {
  readonly schemaVersion: typeof DEVICE_LOGIN_STATE_ENVELOPE_VERSION;
  readonly generation: number;
  readonly status: 'empty';
}

interface ActiveEnvelope {
  readonly schemaVersion: typeof DEVICE_LOGIN_STATE_ENVELOPE_VERSION;
  readonly generation: number;
  readonly status: 'active';
  readonly serverUrl: string;
  readonly state: DeviceLoginState;
  readonly twoFactor?: DeviceLoginStoredTwoFactorChallenge;
  readonly retryRequired?: true;
}

interface ClaimedEnvelope {
  readonly schemaVersion: typeof DEVICE_LOGIN_STATE_ENVELOPE_VERSION;
  readonly generation: number;
  readonly status: 'claimed';
  readonly serverUrl: string;
  readonly state: DeviceLoginBoundState;
  readonly twoFactor?: DeviceLoginStoredTwoFactorChallenge;
  readonly retryRequired?: true;
  readonly workerId: string;
  readonly claimedAt: number;
}

interface OutcomeUnknownEnvelope {
  readonly schemaVersion: typeof DEVICE_LOGIN_STATE_ENVELOPE_VERSION;
  readonly generation: number;
  readonly status: 'outcome_unknown';
  readonly serverUrl: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

type StoredEnvelope =
  | EmptyEnvelope
  | ActiveEnvelope
  | ClaimedEnvelope
  | OutcomeUnknownEnvelope;

interface SharedCoordinator {
  highWaterGeneration: number;
  readonly workerId: string;
  readonly queue: OperationQueue;
}

interface OperationQueue {
  tail: Promise<void>;
}

const COORDINATORS = new WeakMap<KeyValueStore, Map<string, SharedCoordinator>>();
const OPERATION_QUEUES = new Map<string, OperationQueue>();
let defaultWorkerId: string | undefined;

/**
 * Owns the single requester-side device-login ceremony in storage.session. Sensitive state is
 * returned only to background callers; UI callers receive projectDeviceLoginStateMetadata output.
 */
export class DeviceLoginStateStore {
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #coordinator: SharedCoordinator;

  constructor(
    private readonly sessionStore: KeyValueStore,
    options: DeviceLoginStateStoreOptions = {},
  ) {
    if (!sessionStore) throw configurationError('sessionStore is required');
    this.#storageKey = validateStorageKey(
      options.storageKey ?? DEVICE_LOGIN_STATE_STORAGE_KEY,
    );
    this.#now = options.now ?? Date.now;
    this.#coordinator = sharedCoordinator(
      sessionStore,
      this.#storageKey,
      options.workerId,
    );
  }

  /** Restore the current secret-bearing snapshot after complete shape and cryptographic validation. */
  read(): Promise<DeviceLoginStateReadResult | undefined> {
    return this.#serialize(async () => {
      const envelope = await this.#readEnvelope(this.#currentTime());
      return snapshotFromEnvelope(envelope);
    });
  }

  /** Read the UI-safe projection; privateKeyPkcs8, accessCode, and device identifier are omitted. */
  async readMetadata(): Promise<DeviceLoginStateMetadata | undefined> {
    const snapshot = await this.read();
    return snapshot ? projectDeviceLoginStateMetadata(snapshot) : undefined;
  }

  /** Begin one ceremony. An existing pending, bound, or claimed ceremony must be cleared first. */
  write(
    serverUrl: string,
    state: DeviceLoginPendingState,
  ): Promise<ActiveDeviceLoginStateSnapshot> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const canonicalServerUrl = canonicalizeStoredServerUrl(serverUrl);
      const current = await this.#readEnvelope(now);
      if (current.status !== 'empty') {
        throw new DeviceLoginStateStoreError(
          'busy',
          'A device-login ceremony is already active.',
        );
      }
      const restored = await restoreDeviceLoginState(state, now);
      if (restored.phase !== 'pending') {
        throw new DeviceLoginStateStoreError(
          'invalid_transition',
          'A new device-login ceremony must begin in the pending phase.',
        );
      }
      const commitTime = this.#currentTime();
      if (restored.createdAt > commitTime || commitTime >= restored.expiresAt) {
        throw new DeviceLoginStateStoreError(
          'invalid_transition',
          'The device-login ceremony expired before it could be stored.',
        );
      }
      const envelope: ActiveEnvelope = {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: this.#nextGeneration(),
        status: 'active',
        serverUrl: canonicalServerUrl,
        state: restored,
      };
      await this.#writeEnvelope(envelope);
      return activeSnapshot(envelope);
    });
  }

  /** Replace the exact pending generation with its server-bound continuation. */
  async replace(
    expectedOwner: DeviceLoginStateOwner,
    state: DeviceLoginBoundState,
  ): Promise<ActiveDeviceLoginBoundStateSnapshot | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (
        current.status !== 'active'
        || !sameOwner(current, owner)
        || current.state.phase !== 'pending'
      ) return undefined;

      const restored = await restoreDeviceLoginState(state, now);
      if (restored.phase !== 'bound' || !sameCeremony(current.state, restored)) {
        throw new DeviceLoginStateStoreError(
          'invalid_transition',
          'The replacement does not belong to the current device-login ceremony.',
        );
      }
      if (this.#currentTime() >= restored.expiresAt) {
        await this.#eraseEnvelope();
        return undefined;
      }
      const envelope: ActiveEnvelope = {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: this.#nextGeneration(),
        status: 'active',
        serverUrl: current.serverUrl,
        state: restored,
      };
      await this.#writeEnvelope(envelope);
      return activeSnapshot(envelope) as ActiveDeviceLoginBoundStateSnapshot;
    });
  }

  /** Atomically claim one bound generation. Only the returned generation may settle or cancel it. */
  async claim(
    expectedOwner: DeviceLoginStateOwner,
  ): Promise<ClaimedDeviceLoginStateSnapshot | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (
        current.status !== 'active'
        || !sameOwner(current, owner)
        || current.state.phase !== 'bound'
      ) return undefined;

      const claimedAt = this.#currentTime();
      if (claimedAt >= current.state.expiresAt) {
        await this.#eraseEnvelope();
        return undefined;
      }

      const envelope: ClaimedEnvelope = {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: this.#nextGeneration(),
        status: 'claimed',
        serverUrl: current.serverUrl,
        state: current.state,
        ...(current.twoFactor ? { twoFactor: current.twoFactor } : {}),
        ...(current.retryRequired ? { retryRequired: true as const } : {}),
        workerId: this.#coordinator.workerId,
        claimedAt,
      };
      await this.#writeEnvelope(envelope);
      return claimedSnapshot(envelope);
    });
  }

  /** Release a non-terminal 2FA challenge back to resumable bound state under a fresh generation. */
  async release(
    expectedClaimOwner: DeviceLoginStateOwner,
    releaseState: DeviceLoginReleaseState = {},
  ): Promise<ActiveDeviceLoginBoundStateSnapshot | undefined> {
    const owner = parseOwner(expectedClaimOwner);
    const continuation = parseReleaseState(releaseState, owner.serverUrl);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (current.status !== 'claimed' || !sameOwner(current, owner)) return undefined;
      if (this.#currentTime() >= current.state.expiresAt) {
        await this.#eraseEnvelope();
        return undefined;
      }
      const envelope: ActiveEnvelope = {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: this.#nextGeneration(),
        status: 'active',
        serverUrl: current.serverUrl,
        state: current.state,
        ...(continuation.twoFactor ? { twoFactor: continuation.twoFactor } : {}),
        ...(continuation.retryRequired ? { retryRequired: true as const } : {}),
      };
      await this.#writeEnvelope(envelope);
      return activeSnapshot(envelope) as ActiveDeviceLoginBoundStateSnapshot;
    });
  }

  /** Retire an unresolved token-grant claim without retaining replayable request credentials. */
  async markOutcomeUnknown(
    expectedClaimOwner: DeviceLoginStateOwner,
  ): Promise<DeviceLoginOutcomeUnknownSnapshot | undefined> {
    const owner = parseOwner(expectedClaimOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (current.status !== 'claimed' || !sameOwner(current, owner)) return undefined;
      return snapshotFromEnvelope(
        await this.#markOutcomeUnknown(current.serverUrl, current.state, now),
      ) as DeviceLoginOutcomeUnknownSnapshot;
    });
  }

  /** Retire an active request whose remote creation or redemption outcome cannot be determined. */
  async retireOutcomeUnknown(
    expectedOwner: DeviceLoginStateOwner,
  ): Promise<DeviceLoginOutcomeUnknownSnapshot | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const current = await this.#readEnvelope(now);
      if (
        (current.status !== 'active' && current.status !== 'claimed')
        || !sameOwner(current, owner)
      ) return undefined;
      return snapshotFromEnvelope(
        await this.#markOutcomeUnknown(current.serverUrl, current.state, now),
      ) as DeviceLoginOutcomeUnknownSnapshot;
    });
  }

  /** Erase terminal or cancelled state only when the caller still owns the exact generation. */
  async clear(expectedOwner: DeviceLoginStateOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope(this.#currentTime());
      if (current.status === 'empty' || !sameOwner(current, owner)) return false;
      await this.#eraseEnvelope();
      return true;
    });
  }

  #currentTime(): number {
    const now = this.#now();
    if (!isTimestamp(now)) {
      throw new DeviceLoginStateStoreError(
        'invalid_configuration',
        'now must return a non-negative safe integer.',
      );
    }
    return now;
  }

  async #readEnvelope(now: number): Promise<StoredEnvelope> {
    const raw = await this.sessionStore.get<unknown>(this.#storageKey);
    if (raw === undefined) {
      return {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: this.#coordinator.highWaterGeneration,
        status: 'empty',
      };
    }

    const rawGeneration = extractGeneration(raw);
    if (rawGeneration !== undefined) {
      this.#coordinator.highWaterGeneration = Math.max(
        this.#coordinator.highWaterGeneration,
        rawGeneration,
      );
    }
    if (!hasBoundedEnvelopeSize(this.#storageKey, raw)) return this.#purgeInvalid();

    const record = strictRecord(raw);
    if (!record) return this.#purgeInvalid();
    const schemaVersion = ownValue(record, 'schemaVersion');
    const generation = ownValue(record, 'generation');
    const status = ownValue(record, 'status');
    if (
      schemaVersion !== DEVICE_LOGIN_STATE_ENVELOPE_VERSION
      || !isGeneration(generation)
      || (status !== 'empty'
        && status !== 'active'
        && status !== 'claimed'
        && status !== 'outcome_unknown')
    ) return this.#purgeInvalid();
    this.#coordinator.highWaterGeneration = Math.max(
      this.#coordinator.highWaterGeneration,
      generation,
    );

    if (status === 'empty') {
      if (!hasExactKeys(record, ['schemaVersion', 'generation', 'status'])) {
        return this.#purgeInvalid();
      }
      return { schemaVersion, generation, status };
    }
    if (status === 'outcome_unknown') {
      if (!hasExactKeys(record, [
        'schemaVersion', 'generation', 'status', 'serverUrl', 'createdAt', 'expiresAt',
        'terminalAt',
      ])) return this.#purgeInvalid();
      const serverUrl = parseStoredServerUrl(ownValue(record, 'serverUrl'));
      const createdAt = ownValue(record, 'createdAt');
      const expiresAt = ownValue(record, 'expiresAt');
      const terminalAt = ownValue(record, 'terminalAt');
      if (
        !serverUrl
        || !isTimestamp(createdAt)
        || !isTimestamp(expiresAt)
        || !isTimestamp(terminalAt)
        || expiresAt <= createdAt
        || terminalAt < createdAt
        || terminalAt > now
      ) return this.#purgeInvalid();
      if (now >= expiresAt) return this.#purgeInvalid();
      return {
        schemaVersion,
        generation,
        status,
        serverUrl,
        createdAt,
        expiresAt,
        terminalAt,
      };
    }
    if (status === 'active') {
      const hasTwoFactor = Object.hasOwn(record, 'twoFactor');
      const hasRetryRequired = Object.hasOwn(record, 'retryRequired');
      if (!hasExactKeys(record, [
        'schemaVersion', 'generation', 'status', 'serverUrl', 'state',
        ...(hasTwoFactor ? ['twoFactor'] : []),
        ...(hasRetryRequired ? ['retryRequired'] : []),
      ])) {
        return this.#purgeInvalid();
      }
      const serverUrl = parseStoredServerUrl(ownValue(record, 'serverUrl'));
      if (!serverUrl) return this.#purgeInvalid();
      const state = await restoreOrUndefined(ownValue(record, 'state'), now);
      const validatedAt = this.#currentTime();
      if (
        !state
        || state.createdAt > validatedAt
        || validatedAt >= state.expiresAt
      ) return this.#purgeInvalid();
      const twoFactor = hasTwoFactor
        ? parseTwoFactorChallengeOrUndefined(ownValue(record, 'twoFactor'), serverUrl)
        : undefined;
      if (
        (hasTwoFactor && !twoFactor)
        || (hasRetryRequired && ownValue(record, 'retryRequired') !== true)
      ) return this.#purgeInvalid();
      return {
        schemaVersion,
        generation,
        status,
        serverUrl,
        state,
        ...(twoFactor ? { twoFactor } : {}),
        ...(hasRetryRequired ? { retryRequired: true as const } : {}),
      };
    }

    const hasTwoFactor = Object.hasOwn(record, 'twoFactor');
    const hasRetryRequired = Object.hasOwn(record, 'retryRequired');
    if (!hasExactKeys(record, [
      'schemaVersion', 'generation', 'status', 'serverUrl', 'state', 'workerId', 'claimedAt',
      ...(hasTwoFactor ? ['twoFactor'] : []),
      ...(hasRetryRequired ? ['retryRequired'] : []),
    ])) return this.#purgeInvalid();
    const serverUrl = parseStoredServerUrl(ownValue(record, 'serverUrl'));
    const workerId = ownValue(record, 'workerId');
    const claimedAt = ownValue(record, 'claimedAt');
    if (
      !serverUrl
      || !isTimestamp(claimedAt)
      || claimedAt > now
    ) return this.#purgeInvalid();
    const state = await restoreOrUndefined(ownValue(record, 'state'), now);
    const validatedAt = this.#currentTime();
    if (
      !state
      || state.phase !== 'bound'
      || claimedAt < state.createdAt
      || state.createdAt > validatedAt
      || validatedAt >= state.expiresAt
    ) {
      return this.#purgeInvalid();
    }
    if (workerId !== this.#coordinator.workerId) {
      return this.#markOutcomeUnknown(serverUrl, state, now);
    }
    const twoFactor = hasTwoFactor
      ? parseTwoFactorChallengeOrUndefined(ownValue(record, 'twoFactor'), serverUrl)
      : undefined;
    if (
      (hasTwoFactor && !twoFactor)
      || (hasRetryRequired && ownValue(record, 'retryRequired') !== true)
    ) return this.#purgeInvalid();
    return {
      schemaVersion,
      generation,
      status,
      serverUrl,
      state,
      ...(twoFactor ? { twoFactor } : {}),
      ...(hasRetryRequired ? { retryRequired: true as const } : {}),
      workerId,
      claimedAt,
    };
  }

  async #purgeInvalid(): Promise<EmptyEnvelope> {
    if (this.#coordinator.highWaterGeneration === Number.MAX_SAFE_INTEGER) {
      await this.sessionStore.remove(this.#storageKey);
      return {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: Number.MAX_SAFE_INTEGER,
        status: 'empty',
      };
    }
    const empty = this.#emptyEnvelope();
    await this.#writeEnvelope(empty);
    return empty;
  }

  async #markOutcomeUnknown(
    serverUrl: string,
    state: DeviceLoginState,
    terminalAt: number,
  ): Promise<OutcomeUnknownEnvelope> {
    if (this.#coordinator.highWaterGeneration === Number.MAX_SAFE_INTEGER) {
      await this.sessionStore.remove(this.#storageKey);
      return {
        schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
        generation: Number.MAX_SAFE_INTEGER,
        status: 'outcome_unknown',
        serverUrl,
        createdAt: state.createdAt,
        expiresAt: state.expiresAt,
        terminalAt,
      };
    }
    const envelope: OutcomeUnknownEnvelope = {
      schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
      generation: this.#nextGeneration(),
      status: 'outcome_unknown',
      serverUrl,
      createdAt: state.createdAt,
      expiresAt: state.expiresAt,
      terminalAt,
    };
    await this.#writeEnvelope(envelope);
    return envelope;
  }

  async #eraseEnvelope(): Promise<void> {
    if (this.#coordinator.highWaterGeneration === Number.MAX_SAFE_INTEGER) {
      await this.sessionStore.remove(this.#storageKey);
      return;
    }
    await this.#writeEnvelope(this.#emptyEnvelope());
  }

  #emptyEnvelope(): EmptyEnvelope {
    return {
      schemaVersion: DEVICE_LOGIN_STATE_ENVELOPE_VERSION,
      generation: this.#nextGeneration(),
      status: 'empty',
    };
  }

  #nextGeneration(): number {
    if (this.#coordinator.highWaterGeneration >= Number.MAX_SAFE_INTEGER) {
      throw new DeviceLoginStateStoreError(
        'generation_exhausted',
        'The device-login state generation is exhausted.',
      );
    }
    this.#coordinator.highWaterGeneration += 1;
    return this.#coordinator.highWaterGeneration;
  }

  async #writeEnvelope(envelope: StoredEnvelope): Promise<void> {
    if (!hasBoundedEnvelopeSize(this.#storageKey, envelope)) {
      throw new DeviceLoginStateStoreError(
        'storage_capacity',
        'The device-login state exceeds the session-storage byte limit.',
      );
    }
    await this.sessionStore.set(this.#storageKey, envelope);
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const queue = this.#coordinator.queue;
    const result = queue.tail.then(operation, operation);
    queue.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export function projectDeviceLoginStateMetadata(
  snapshot: DeviceLoginStateReadResult,
): DeviceLoginStateMetadata {
  if ('status' in snapshot) {
    return Object.freeze({
      generation: snapshot.owner.generation,
      status: 'outcome_unknown',
      serverOrigin: new URL(snapshot.owner.serverUrl).origin,
      createdAt: snapshot.createdAt,
      expiresAt: snapshot.expiresAt,
      terminalAt: snapshot.terminalAt,
    });
  }
  const { state } = snapshot;
  const metadata: ActiveDeviceLoginStateMetadata = {
    generation: snapshot.owner.generation,
    claimed: snapshot.claimed,
    phase: state.phase,
    email: state.email,
    serverOrigin: new URL(snapshot.owner.serverUrl).origin,
    device: Object.freeze({ type: state.device.type, name: state.device.name }),
    createdAt: state.createdAt,
    expiresAt: state.expiresAt,
  };
  return Object.freeze(metadata);
}

function snapshotFromEnvelope(envelope: StoredEnvelope): DeviceLoginStateReadResult | undefined {
  if (envelope.status === 'empty') return undefined;
  if (envelope.status === 'outcome_unknown') {
    return Object.freeze({
      owner: Object.freeze({
        generation: envelope.generation,
        serverUrl: envelope.serverUrl,
      }),
      status: 'outcome_unknown',
      createdAt: envelope.createdAt,
      expiresAt: envelope.expiresAt,
      terminalAt: envelope.terminalAt,
    });
  }
  return envelope.status === 'claimed'
    ? claimedSnapshot(envelope)
    : activeSnapshot(envelope);
}

function activeSnapshot(envelope: ActiveEnvelope): ActiveDeviceLoginStateSnapshot {
  return Object.freeze({
    owner: ownerFromEnvelope(envelope),
    claimed: false,
    state: envelope.state,
    ...(envelope.twoFactor ? { twoFactor: envelope.twoFactor } : {}),
    ...(envelope.retryRequired ? { retryRequired: true as const } : {}),
  });
}

function claimedSnapshot(envelope: ClaimedEnvelope): ClaimedDeviceLoginStateSnapshot {
  return Object.freeze({
    owner: Object.freeze({
      generation: envelope.generation,
      serverUrl: envelope.serverUrl,
      requestId: envelope.state.requestId,
    }),
    claimed: true,
    state: envelope.state,
    ...(envelope.twoFactor ? { twoFactor: envelope.twoFactor } : {}),
    ...(envelope.retryRequired ? { retryRequired: true as const } : {}),
  });
}

function ownerFromEnvelope(envelope: ActiveEnvelope | ClaimedEnvelope): DeviceLoginStateOwner {
  return Object.freeze({
    generation: envelope.generation,
    serverUrl: envelope.serverUrl,
    ...(envelope.state.phase === 'bound' ? { requestId: envelope.state.requestId } : {}),
  });
}

function sameOwner(
  envelope: ActiveEnvelope | ClaimedEnvelope | OutcomeUnknownEnvelope,
  owner: DeviceLoginStateOwner,
): boolean {
  const current = envelope.status === 'outcome_unknown'
    ? Object.freeze({ generation: envelope.generation, serverUrl: envelope.serverUrl })
    : ownerFromEnvelope(envelope);
  const currentRequestId = 'requestId' in current ? current.requestId : undefined;
  return current.generation === owner.generation
    && current.serverUrl === owner.serverUrl
    && currentRequestId === owner.requestId;
}

function sameCeremony(pending: DeviceLoginPendingState, bound: DeviceLoginBoundState): boolean {
  return pending.email === bound.email
    && pending.publicKey === bound.publicKey
    && pending.privateKeyPkcs8 === bound.privateKeyPkcs8
    && pending.accessCode === bound.accessCode
    && pending.createdAt === bound.createdAt
    && pending.device.type === bound.device.type
    && pending.device.name === bound.device.name
    && pending.device.identifier === bound.device.identifier
    && bound.expiresAt <= pending.expiresAt;
}

async function restoreOrUndefined(
  value: unknown,
  now: number,
): Promise<DeviceLoginState | undefined> {
  try {
    return await restoreDeviceLoginState(value, now);
  } catch {
    return undefined;
  }
}

function sharedCoordinator(
  store: KeyValueStore,
  storageKey: string,
  requestedWorkerId: string | undefined,
): SharedCoordinator {
  let stores = COORDINATORS.get(store);
  if (!stores) {
    stores = new Map();
    COORDINATORS.set(store, stores);
  }
  const existing = stores.get(storageKey);
  if (existing) {
    if (requestedWorkerId !== undefined && validateWorkerId(requestedWorkerId) !== existing.workerId) {
      throw configurationError('workerId conflicts with the active storage coordinator');
    }
    return existing;
  }
  const workerId = validateWorkerId(requestedWorkerId ?? currentWorkerId());
  const coordinator: SharedCoordinator = {
    highWaterGeneration: 0,
    workerId,
    queue: operationQueue(storageKey),
  };
  stores.set(storageKey, coordinator);
  return coordinator;
}

function operationQueue(storageKey: string): OperationQueue {
  const existing = OPERATION_QUEUES.get(storageKey);
  if (existing) return existing;
  const queue: OperationQueue = { tail: Promise.resolve() };
  OPERATION_QUEUES.set(storageKey, queue);
  return queue;
}

function currentWorkerId(): string {
  defaultWorkerId ??= crypto.randomUUID();
  return defaultWorkerId;
}

function validateStorageKey(value: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_STORAGE_KEY_LENGTH
    || value !== value.trim()
    || hasControlCharacters(value)
  ) throw configurationError('storageKey must be a bounded non-empty string');
  return value;
}

function hasControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function validateWorkerId(value: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 128
    || !/^[A-Za-z0-9_-]+$/u.test(value)
  ) throw configurationError('workerId must be a bounded opaque identifier');
  return value;
}

function assertGeneration(value: number): void {
  if (!isGeneration(value)) {
    throw new DeviceLoginStateStoreError(
      'invalid_generation',
      'Device-login generation must be a positive safe integer.',
    );
  }
}

function parseOwner(value: DeviceLoginStateOwner): DeviceLoginStateOwner {
  const record = strictRecord(value);
  if (!record || !hasExactKeys(
    record,
    ownValue(record, 'requestId') === undefined
      ? ['generation', 'serverUrl']
      : ['generation', 'serverUrl', 'requestId'],
  )) {
    throw new DeviceLoginStateStoreError(
      'invalid_generation',
      'Device-login owner is invalid.',
    );
  }
  const generation = ownValue(record, 'generation');
  assertGeneration(generation as number);
  const serverUrl = parseStoredServerUrl(ownValue(record, 'serverUrl'));
  const requestId = ownValue(record, 'requestId');
  if (
    !serverUrl
    || (requestId !== undefined
      && (
        typeof requestId !== 'string'
        || requestId.length !== 36
        || !REQUEST_ID_PATTERN.test(requestId)
      ))
  ) {
    throw new DeviceLoginStateStoreError(
      'invalid_generation',
      'Device-login owner is invalid.',
    );
  }
  return Object.freeze({
    generation: generation as number,
    serverUrl,
    ...(typeof requestId === 'string' ? { requestId } : {}),
  });
}

function canonicalizeStoredServerUrl(value: string): string {
  try {
    return canonicalizeServerCapabilityUrl(value);
  } catch {
    throw new DeviceLoginStateStoreError(
      'invalid_transition',
      'Device-login server URL is invalid.',
    );
  }
}

function parseStoredServerUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const canonical = canonicalizeServerCapabilityUrl(value);
    return canonical === value ? canonical : undefined;
  } catch {
    return undefined;
  }
}

function parseTwoFactorChallenge(
  value: DeviceLoginStoredTwoFactorChallenge,
  serverUrl: string,
): DeviceLoginStoredTwoFactorChallenge {
  const parsed = parseTwoFactorChallengeOrUndefined(value, serverUrl);
  if (!parsed) {
    throw new DeviceLoginStateStoreError(
      'invalid_transition',
      'Device-login two-factor state is invalid.',
    );
  }
  return parsed;
}

function parseReleaseState(value: DeviceLoginReleaseState, serverUrl: string): DeviceLoginReleaseState {
  const record = strictRecord(value);
  if (!record) {
    throw new DeviceLoginStateStoreError(
      'invalid_transition',
      'Device-login release state is invalid.',
    );
  }
  const hasTwoFactor = Object.hasOwn(record, 'twoFactor');
  const hasRetryRequired = Object.hasOwn(record, 'retryRequired');
  if (!hasExactKeys(record, [
    ...(hasTwoFactor ? ['twoFactor'] : []),
    ...(hasRetryRequired ? ['retryRequired'] : []),
  ])) {
    throw new DeviceLoginStateStoreError(
      'invalid_transition',
      'Device-login release state is invalid.',
    );
  }
  const twoFactor = hasTwoFactor
    ? parseTwoFactorChallenge(
        ownValue(record, 'twoFactor') as DeviceLoginStoredTwoFactorChallenge,
        serverUrl,
      )
    : undefined;
  if (hasRetryRequired && ownValue(record, 'retryRequired') !== true) {
    throw new DeviceLoginStateStoreError(
      'invalid_transition',
      'Device-login release state is invalid.',
    );
  }
  return Object.freeze({
    ...(twoFactor ? { twoFactor } : {}),
    ...(hasRetryRequired ? { retryRequired: true as const } : {}),
  });
}

function parseTwoFactorChallengeOrUndefined(
  value: unknown,
  serverUrl: string,
): DeviceLoginStoredTwoFactorChallenge | undefined {
  const record = strictRecord(value);
  if (!record) return undefined;
  const hasToken = Object.hasOwn(record, 'token');
  const hasFido2 = Object.hasOwn(record, 'fido2');
  const hasDuo = Object.hasOwn(record, 'duo');
  const hasForce = Object.hasOwn(record, 'forcePasswordReset');
  const hasPolicy = Object.hasOwn(record, 'masterPasswordPolicy');
  if (!hasExactKeys(record, [
    'providers',
    ...(hasToken ? ['token'] : []),
    ...(hasFido2 ? ['fido2'] : []),
    ...(hasDuo ? ['duo'] : []),
    ...(hasForce ? ['forcePasswordReset'] : []),
    ...(hasPolicy ? ['masterPasswordPolicy'] : []),
  ])) return undefined;
  const providers = ownValue(record, 'providers');
  if (
    !Array.isArray(providers)
    || providers.length === 0
    || providers.length > MAX_TWO_FACTOR_PROVIDERS
  ) return undefined;
  const canonicalProviders: number[] = [];
  let previous = -1;
  for (const provider of providers) {
    if (!Number.isInteger(provider) || provider < 0 || provider > 255 || provider <= previous) {
      return undefined;
    }
    previous = provider;
    canonicalProviders.push(provider);
  }
  const token = ownValue(record, 'token');
  if (
    hasToken
    && (
      typeof token !== 'string'
      || token.length === 0
      || token.length > MAX_TWO_FACTOR_TOKEN_LENGTH
      || hasControlCharacters(token)
    )
  ) return undefined;
  if (hasForce && ownValue(record, 'forcePasswordReset') !== true) return undefined;
  const fido2 = hasFido2
    ? parseFido2ChallengeOrUndefined(ownValue(record, 'fido2'), serverUrl)
    : undefined;
  const duo = hasDuo ? parseDuoSeedsOrUndefined(ownValue(record, 'duo')) : undefined;
  if (
    (hasFido2 && !fido2)
    || canonicalProviders.includes(7) !== Boolean(fido2)
    || (hasDuo && !duo)
    || canonicalProviders.some((provider) => (provider === 2 || provider === 6)
      && !duo?.some((entry) => entry.provider === provider))
  ) return undefined;
  let masterPasswordPolicy: MasterPasswordPolicy | undefined;
  if (hasPolicy) {
    try {
      masterPasswordPolicy = parseMasterPasswordPolicy(ownValue(record, 'masterPasswordPolicy'));
    } catch {
      return undefined;
    }
    if (!masterPasswordPolicy) return undefined;
  }
  return Object.freeze({
    providers: Object.freeze(canonicalProviders),
    ...(typeof token === 'string' ? { token } : {}),
    ...(fido2 ? { fido2 } : {}),
    ...(duo ? { duo } : {}),
    ...(hasForce ? { forcePasswordReset: true as const } : {}),
    ...(masterPasswordPolicy ? { masterPasswordPolicy } : {}),
  });
}

function parseDuoSeedsOrUndefined(value: unknown): readonly DuoProviderSeed[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 2) return undefined;
  try {
    const seeds = value.map((candidate) => {
      const record = strictRecord(candidate);
      if (!record) throw new Error('invalid Duo seed');
      const hasHost = Object.hasOwn(record, 'host');
      if (!hasExactKeys(record, ['provider', 'authUrl', ...(hasHost ? ['host'] : [])])) {
        throw new Error('invalid Duo seed');
      }
      const provider = ownValue(record, 'provider');
      if (provider !== 2 && provider !== 6) throw new Error('invalid Duo provider');
      const authUrl = ownValue(record, 'authUrl');
      const host = ownValue(record, 'host');
      if (typeof authUrl !== 'string' || authUrl.length === 0 || authUrl.length > 16 * 1024
          || (hasHost && (typeof host !== 'string' || host.length === 0 || host.length > 253))) {
        throw new Error('invalid Duo metadata');
      }
      return extractDuoProviderSeed(duoProviderMetadata({
        provider,
        authUrl,
        ...(typeof host === 'string' ? { host } : {}),
      }), provider);
    });
    if (new Set(seeds.map((entry) => entry.provider)).size !== seeds.length) return undefined;
    return Object.freeze(seeds);
  } catch {
    return undefined;
  }
}

function parseFido2ChallengeOrUndefined(
  value: unknown,
  serverUrl: string,
): DeviceLoginStoredFido2Challenge | undefined {
  const record = strictRecord(value);
  if (!record || !hasExactKeys(record, ['connectorData', 'connectorUrl'])) return undefined;
  const connectorData = ownValue(record, 'connectorData');
  const connectorUrl = ownValue(record, 'connectorUrl');
  if (
    typeof connectorData !== 'string'
    || connectorData.length === 0
    || connectorData.length > MAX_CONNECTOR_DATA_LENGTH
    || typeof connectorUrl !== 'string'
  ) return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(connectorData) as unknown;
  } catch {
    return undefined;
  }
  const expectedUrl = interactiveTwoFactorConnectorUrl(serverUrl);
  if (connectorUrl !== expectedUrl) return undefined;
  try {
    const connector = new URL(connectorUrl);
    const request = parseFido2TwoFactorRequest(raw, {
      origin: connector.origin,
      rpId: connector.hostname,
    });
    if (request.connectorData !== connectorData) return undefined;
  } catch {
    return undefined;
  }
  return Object.freeze({ connectorData, connectorUrl });
}

function isGeneration(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function configurationError(message: string): DeviceLoginStateStoreError {
  return new DeviceLoginStateStoreError('invalid_configuration', message);
}

function strictRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) return undefined;
  }
  return value as Record<string, unknown>;
}

function ownValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function hasExactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

function extractGeneration(value: unknown): number | undefined {
  const record = strictRecord(value);
  if (!record) return undefined;
  const generation = ownValue(record, 'generation');
  return isGeneration(generation) ? generation : undefined;
}

function hasBoundedEnvelopeSize(storageKey: string, envelope: unknown): boolean {
  try {
    const serialized = JSON.stringify({ [storageKey]: envelope });
    if (typeof serialized !== 'string') return false;
    return new TextEncoder().encode(serialized).byteLength
      <= DEVICE_LOGIN_STATE_ENVELOPE_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}
