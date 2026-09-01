import type { KeyValueStore } from '../platform/store.js';
import { isRegistrableRpId } from '../core/vault/domain.js';
import {
  MAX_WEBSITE_PASSKEY_ATTESTATION_OBJECT_BYTES,
  MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES,
  MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES,
  MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_WEBSITE_PASSKEY_PUBLIC_KEY_SPKI_BYTES,
  MAX_WEBSITE_PASSKEY_SIGNATURE_BYTES,
  MAX_WEBSITE_PASSKEY_USER_HANDLE_BYTES,
  WebsitePasskeyPortProtocolError,
  decideWebsitePasskeySupport,
  parsePasskeyCeremonyResultSnapshot,
  serializeCanonicalWebsitePasskeyRequest,
  type CanonicalWebsitePasskeyRequest,
  type PasskeyCeremonyResultSnapshot,
  type WebsitePasskeyFallbackReason,
  type WebsitePasskeyUnsupportedReason,
} from '../messaging/website-passkey-port.js';

export type {
  CanonicalWebsitePasskeyRequest,
  PasskeyAssertionResultSnapshot,
  PasskeyCeremonyResultSnapshot,
  PasskeyRegistrationResultSnapshot,
} from '../messaging/website-passkey-port.js';

export const PASSKEY_CEREMONY_STORAGE_KEY = 'passkey.websiteCeremonies';
export const PASSKEY_CEREMONY_SCHEMA_VERSION = 2 as const;
export const DEFAULT_PASSKEY_CEREMONY_TTL_MS = 120_000;
/** Delivery and deduplication grace after the later of the request deadline or terminal transition. */
export const DEFAULT_PASSKEY_CEREMONY_TERMINAL_TTL_MS = 120_000;
export const DEFAULT_PASSKEY_CEREMONY_CAPACITY = 16;
export const MAX_PASSKEY_CEREMONY_TTL_MS = 600_000;
export const MAX_PASSKEY_CEREMONY_TERMINAL_TTL_MS = 120_000;
export const MAX_PASSKEY_CEREMONY_CAPACITY = 128;
/** A deliberately small share of Chrome's storage.session quota, leaving room for other state. */
export const PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET = 4 * 1_024 * 1_024;

const TERMINAL_FIXED_GROWTH_RESERVE_BYTES = 1_024;
/**
 * Worst-case growth from an active record to its largest canonical terminal result. The fixed
 * allowance covers terminal identifiers, timestamps, JSON property names, and punctuation.
 */
export const PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES = Object.freeze({
  get: TERMINAL_FIXED_GROWTH_RESERVE_BYTES
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_SIGNATURE_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_USER_HANDLE_BYTES),
  create: TERMINAL_FIXED_GROWTH_RESERVE_BYTES
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_ATTESTATION_OBJECT_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES)
    + maximumBase64UrlLength(MAX_WEBSITE_PASSKEY_PUBLIC_KEY_SPKI_BYTES),
} as const);

const REQUEST_DIGEST_DOMAIN = 'miyu.website-passkey.request.v2\0';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_OPAQUE_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 16_384;
const MAX_DISPLAY_LENGTH = 4_096;
const MAX_CANDIDATES = 128;
const MAX_CLOCK_SKEW_MS = 300_000;
const RMW_TAILS = new WeakMap<object, Promise<void>>();

export type PasskeyCeremonyState =
  | 'awaitingApproval'
  | 'executing'
  | 'completed'
  | 'failed'
  | 'uncertain'
  | 'fallback';

export type PasskeyCeremonyTerminalReason =
  | WebsitePasskeyFallbackReason
  | 'account_changed'
  | 'cache_changed'
  | 'cancelled'
  | 'context_changed'
  | 'expired'
  | 'feature_disabled'
  | 'session_changed'
  | 'vault_locked'
  | 'worker_restart'
  | 'invalid_state'
  | 'not_allowed'
  | 'not_supported'
  | 'operation_failed'
  | 'execution_failed'
  | 'delivery_failed';

/** Public metadata shown only in an extension-owned approval surface. */
export interface PasskeyCeremonyCandidateSnapshot {
  readonly kind: 'credential' | 'target';
  readonly id: string;
  readonly name: string;
  readonly username?: string;
}

interface PasskeyCeremonyBase {
  readonly schemaVersion: typeof PASSKEY_CEREMONY_SCHEMA_VERSION;
  readonly ceremonyId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly frameUrl: string;
  readonly origin: string;
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly requestDigest: string;
  readonly sessionBindingId: string;
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly rawGeneration: string;
  readonly snapshotGeneration?: string;
  readonly policyGeneration: number;
  readonly candidates: readonly PasskeyCeremonyCandidateSnapshot[];
  readonly createdAt: number;
  /** One absolute deadline for approval and execution. Claiming never extends it. */
  readonly deadlineAt: number;
}

export interface AwaitingPasskeyCeremony extends PasskeyCeremonyBase {
  readonly state: 'awaitingApproval';
}

export interface ExecutingPasskeyCeremony extends PasskeyCeremonyBase {
  readonly state: 'executing';
  readonly executionId: string;
  readonly startedAt: number;
}

interface TerminalPasskeyCeremonyBase extends PasskeyCeremonyBase {
  readonly outcomeId: string;
  readonly terminalAt: number;
  readonly retireAt: number;
}

interface ExecutedTerminalPasskeyCeremonyBase extends TerminalPasskeyCeremonyBase {
  readonly executionId: string;
  readonly startedAt: number;
}

export interface CompletedPasskeyCeremony extends ExecutedTerminalPasskeyCeremonyBase {
  readonly state: 'completed';
  readonly result: PasskeyCeremonyResultSnapshot;
}

export interface PreExecutionFailedPasskeyCeremony extends TerminalPasskeyCeremonyBase {
  readonly state: 'failed';
  readonly reason: PasskeyCeremonyTerminalReason;
}

export interface ExecutedFailedPasskeyCeremony extends ExecutedTerminalPasskeyCeremonyBase {
  readonly state: 'failed';
  readonly reason: PasskeyCeremonyTerminalReason;
}

export type FailedPasskeyCeremony =
  | PreExecutionFailedPasskeyCeremony
  | ExecutedFailedPasskeyCeremony;

export interface UncertainPasskeyCeremony extends ExecutedTerminalPasskeyCeremonyBase {
  readonly state: 'uncertain';
  readonly reason: PasskeyCeremonyTerminalReason;
}

export interface FallbackPasskeyCeremony extends TerminalPasskeyCeremonyBase {
  readonly state: 'fallback';
  readonly reason: WebsitePasskeyFallbackReason;
}

export type TerminalPasskeyCeremony =
  | CompletedPasskeyCeremony
  | FailedPasskeyCeremony
  | UncertainPasskeyCeremony
  | FallbackPasskeyCeremony;

export type PasskeyCeremonyRecord = AwaitingPasskeyCeremony | ExecutingPasskeyCeremony | TerminalPasskeyCeremony;

export interface BeginPasskeyCeremonyInput {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly frameUrl: string;
  readonly origin: string;
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly sessionBindingId: string;
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly rawGeneration: string;
  readonly snapshotGeneration?: string;
  readonly policyGeneration: number;
  readonly candidates: readonly PasskeyCeremonyCandidateSnapshot[];
  /** Reserved continuation id promoted after a locked vault is successfully unlocked. */
  readonly requestedCeremonyId?: string;
  /** Original coordinator deadline so discovery never extends the WebAuthn timeout. */
  readonly requestedDeadlineAt?: number;
}

export type BeginPasskeyCeremonyResult =
  | { readonly status: 'created' | 'existing'; readonly ceremony: PasskeyCeremonyRecord }
  | { readonly status: 'busy' | 'capacity' }
  | {
      readonly status: 'fallback';
      readonly reason: WebsitePasskeyUnsupportedReason;
      readonly bridgeRequestId: string;
      readonly ceremony: FallbackPasskeyCeremony;
    };

export interface PasskeyCeremonyRecovery {
  readonly redeliverable: readonly TerminalPasskeyCeremony[];
}

export interface PasskeyCeremonyRegistryOptions {
  readonly store: KeyValueStore;
  /** Policy cap applied to the canonical request timeout without ever extending that timeout. */
  readonly ttlMs?: number;
  readonly terminalTtlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly createId?: () => string;
}

export type PasskeyCeremonyRegistryErrorCode =
  | 'invalid_configuration'
  | 'invalid_input'
  | 'id_generation'
  | 'id_collision'
  | 'storage_capacity';

export class PasskeyCeremonyRegistryError extends Error {
  constructor(readonly code: PasskeyCeremonyRegistryErrorCode, message: string) {
    super(message);
    this.name = 'PasskeyCeremonyRegistryError';
  }
}

interface PersistedPasskeyCeremonies {
  readonly schemaVersion: typeof PASSKEY_CEREMONY_SCHEMA_VERSION;
  readonly entries: readonly PasskeyCeremonyRecord[];
}

function maximumBase64UrlLength(byteLength: number): number {
  return Math.floor(((byteLength * 4) + 2) / 3);
}

function persistedEnvelopeUtf8Bytes(envelope: PersistedPasskeyCeremonies): number | undefined {
  try {
    // Chrome quota accounting includes the storage item key, not only the value envelope.
    const serialized = JSON.stringify({ [PASSKEY_CEREMONY_STORAGE_KEY]: envelope });
    if (typeof serialized !== 'string' || !Number.isSafeInteger(serialized.length)) return undefined;
    const byteLength = new TextEncoder().encode(serialized).byteLength;
    return Number.isSafeInteger(byteLength) ? byteLength : undefined;
  } catch {
    return undefined;
  }
}

function hasReservedStorageCapacity(entries: readonly PasskeyCeremonyRecord[]): boolean {
  const envelope: PersistedPasskeyCeremonies = {
    schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
    entries,
  };
  let committedBytes = persistedEnvelopeUtf8Bytes(envelope);
  if (committedBytes === undefined) return false;
  for (const entry of entries) {
    if (!isActive(entry)) continue;
    committedBytes += PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES[entry.request.kind];
    if (!Number.isSafeInteger(committedBytes)
      || committedBytes > PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET) return false;
  }
  return committedBytes <= PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET;
}

/** Durable, bounded website-Passkey state. It persists public request data, never vault secrets. */
export class PasskeyCeremonyRegistry {
  readonly #store: KeyValueStore;
  readonly #ttlMs: number;
  readonly #terminalTtlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #createId: () => string;

  constructor(options: PasskeyCeremonyRegistryOptions) {
    if (!options?.store) throw invalidConfiguration('store is required');
    this.#store = options.store;
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_PASSKEY_CEREMONY_TTL_MS,
      MAX_PASSKEY_CEREMONY_TTL_MS,
      'ttlMs',
    );
    this.#terminalTtlMs = boundedPositiveInteger(
      options.terminalTtlMs ?? DEFAULT_PASSKEY_CEREMONY_TERMINAL_TTL_MS,
      MAX_PASSKEY_CEREMONY_TERMINAL_TTL_MS,
      'terminalTtlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_PASSKEY_CEREMONY_CAPACITY,
      MAX_PASSKEY_CEREMONY_CAPACITY,
      'maxEntries',
    );
    this.#now = options.now ?? Date.now;
    this.#createId = options.createId ?? (() => crypto.randomUUID());
  }

  /** A restarted worker never resumes an approval or replays an executing mutation. */
  recoverStartup(): Promise<PasskeyCeremonyRecovery> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const recovered: PasskeyCeremonyRecord[] = [];
      for (const entry of entries) {
        const known = [...entries, ...recovered];
        if (entry.state === 'awaitingApproval') {
          recovered.push(this.#preExecutionFailedRecord(entry, 'worker_restart', now, known));
        } else if (entry.state === 'executing') {
          recovered.push(entry.request.kind === 'get'
            ? this.#failedRecord(entry, 'worker_restart', now, known)
            : this.#uncertainRecord(entry, 'worker_restart', now, known));
        } else {
          recovered.push(entry);
        }
      }
      await this.#write(recovered);
      return { redeliverable: recovered.filter(isTerminal).map(cloneRecord) };
    });
  }

  /** Register a canonical request and derive its digest and absolute deadline inside the registry. */
  begin(input: BeginPasskeyCeremonyInput): Promise<BeginPasskeyCeremonyResult> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const { requestedCeremonyId, requestedDeadlineAt, ...canonical } = canonicalizeBeginInput(input);
      const requestDigest = await digestRequest(canonical.request);
      const entries = await this.#readAndNormalize(now);
      const { unsupportedReason, ...canonicalRecord } = canonical;
      const pending = { ...canonicalRecord, requestDigest };
      const exact = entries.find((entry) => sameRequest(entry, pending));
      if (exact) {
        if (requestedCeremonyId !== undefined && exact.ceremonyId !== requestedCeremonyId) {
          throw registryError('id_collision', 'Reserved ceremony id does not match existing request');
        }
        await this.#write(entries);
        return { status: 'existing', ceremony: cloneRecord(exact) };
      }
      if (entries.some((entry) => sameDocument(entry, pending) && isActive(entry))) {
        await this.#write(entries);
        return { status: 'busy' };
      }
      if (entries.length >= this.#maxEntries) {
        await this.#write(entries);
        return { status: 'capacity' };
      }

      const ceremonyId = requestedCeremonyId ?? this.#freshId(entries);
      if (requestedCeremonyId && entries.some((entry) => recordHasId(entry, requestedCeremonyId))) {
        throw registryError('id_collision', 'Reserved ceremony id collision');
      }
      const base = {
        schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
        ceremonyId,
        ...pending,
        createdAt: now,
        deadlineAt: Math.min(
          this.#deadline(now, Math.min(this.#ttlMs, canonical.request.timeout)),
          requestedDeadlineAt ?? Number.MAX_SAFE_INTEGER,
        ),
      };
      if (base.deadlineAt <= now) throw invalidInput('requestedDeadlineAt');
      if (unsupportedReason !== undefined) {
        const awaiting: AwaitingPasskeyCeremony = { ...base, state: 'awaitingApproval' };
        const fallback = this.#fallbackRecord(awaiting, 'unsupported', now, [...entries, awaiting]);
        const nextEntries = [...entries, fallback];
        if (!hasReservedStorageCapacity(nextEntries)) return { status: 'capacity' };
        await this.#write(nextEntries);
        return {
          status: 'fallback',
          reason: unsupportedReason,
          bridgeRequestId: canonical.request.bridgeRequestId,
          ceremony: cloneRecord(fallback),
        };
      }

      const ceremony: AwaitingPasskeyCeremony = { ...base, state: 'awaitingApproval' };
      const nextEntries = [...entries, ceremony];
      if (!hasReservedStorageCapacity(nextEntries)) return { status: 'capacity' };
      await this.#write(nextEntries);
      return { status: 'created', ceremony: cloneRecord(ceremony) };
    });
  }

  /** Atomically claim an unexpired approval with its exact bridge binding. */
  claim(ceremonyId: string, bridgeId: string): Promise<ExecutingPasskeyCeremony | undefined> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const index = entries.findIndex((entry) => entry.ceremonyId === ceremonyId);
      const current = entries[index];
      if (
        !current
        || current.state !== 'awaitingApproval'
        || current.request.bridgeRequestId !== bridgeId
        || current.deadlineAt <= now
      ) {
        await this.#write(entries);
        return undefined;
      }
      const executing: ExecutingPasskeyCeremony = {
        ...current,
        state: 'executing',
        executionId: this.#freshId(entries),
        startedAt: now,
      };
      entries[index] = executing;
      await this.#write(entries);
      return cloneRecord(executing);
    });
  }

  /** Persist success before any document-scoped delivery is attempted. */
  complete(
    ceremonyId: string,
    executionId: string,
    result: PasskeyCeremonyResultSnapshot,
  ): Promise<CompletedPasskeyCeremony | undefined> {
    return this.#settleExecution(ceremonyId, executionId, (current, now, entries) => ({
      ...current,
      state: 'completed',
      outcomeId: this.#freshId(entries),
      terminalAt: now,
      retireAt: this.#retireAt(current, now),
      result: canonicalResult(result, current.request),
    }));
  }

  markFailed(
    ceremonyId: string,
    executionId: string,
    reason: PasskeyCeremonyTerminalReason = 'execution_failed',
  ): Promise<FailedPasskeyCeremony | undefined> {
    return this.#settleExecution(ceremonyId, executionId, (current, now, entries) => ({
      ...current,
      state: 'failed',
      outcomeId: this.#freshId(entries),
      terminalAt: now,
      retireAt: this.#retireAt(current, now),
      reason: canonicalReason(reason),
    }));
  }

  markUncertain(
    ceremonyId: string,
    executionId: string,
    reason: PasskeyCeremonyTerminalReason = 'delivery_failed',
  ): Promise<FailedPasskeyCeremony | UncertainPasskeyCeremony | undefined> {
    return this.#settleExecution(ceremonyId, executionId, (current, now, entries) => (
      current.request.kind === 'get'
        ? this.#failedRecord(current, canonicalReason(reason), now, entries)
        : this.#uncertainRecord(current, canonicalReason(reason), now, entries)
    ));
  }

  markFallback(
    ceremonyId: string,
    bridgeId: string,
    reason: WebsitePasskeyFallbackReason,
  ): Promise<FallbackPasskeyCeremony | undefined> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const index = entries.findIndex((entry) => entry.ceremonyId === ceremonyId);
      const current = entries[index];
      if (
        !current
        || current.state !== 'awaitingApproval'
        || current.request.bridgeRequestId !== bridgeId
      ) {
        await this.#write(entries);
        return undefined;
      }
      const fallback = this.#fallbackRecord(current, canonicalFallbackReason(reason), now, entries);
      entries[index] = fallback;
      await this.#write(entries);
      return cloneRecord(fallback);
    });
  }

  /** Abort is terminal: pre-execution/get aborts fail, while an executing create is uncertain. */
  abort(
    ceremonyId: string,
    bridgeId: string,
  ): Promise<FailedPasskeyCeremony | UncertainPasskeyCeremony | undefined> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const index = entries.findIndex((entry) => entry.ceremonyId === ceremonyId);
      const current = entries[index];
      if (!current || current.request.bridgeRequestId !== bridgeId) {
        await this.#write(entries);
        return undefined;
      }
      const terminal = current.state === 'awaitingApproval'
        ? this.#preExecutionFailedRecord(current, 'cancelled', now, entries)
        : current.state === 'executing'
          ? current.request.kind === 'get'
            ? this.#failedRecord(current, 'cancelled', now, entries)
            : this.#uncertainRecord(current, 'context_changed', now, entries)
          : undefined;
      if (!terminal) {
        await this.#write(entries);
        return undefined;
      }
      entries[index] = terminal;
      await this.#write(entries);
      return cloneRecord(terminal);
    });
  }

  /** Browser navigation or frame removal invalidates the exact document without implying user abort. */
  invalidateContext(
    ceremonyId: string,
  ): Promise<FailedPasskeyCeremony | UncertainPasskeyCeremony | undefined> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const index = entries.findIndex((entry) => entry.ceremonyId === ceremonyId);
      const current = entries[index];
      if (!current) {
        await this.#write(entries);
        return undefined;
      }
      const terminal = current.state === 'awaitingApproval'
        ? this.#preExecutionFailedRecord(current, 'context_changed', now, entries)
        : current.state === 'executing'
          ? current.request.kind === 'get'
            ? this.#failedRecord(current, 'context_changed', now, entries)
            : this.#uncertainRecord(current, 'context_changed', now, entries)
          : undefined;
      if (!terminal) {
        await this.#write(entries);
        return undefined;
      }
      entries[index] = terminal;
      await this.#write(entries);
      return cloneRecord(terminal);
    });
  }

  /** @deprecated Use abort. */
  cancel(
    ceremonyId: string,
    bridgeId: string,
  ): Promise<FailedPasskeyCeremony | UncertainPasskeyCeremony | undefined> {
    return this.abort(ceremonyId, bridgeId);
  }

  /** Remove a terminal outcome only after the exact bridge and outcome tokens acknowledge it. */
  acknowledge(ceremonyId: string, bridgeId: string, outcomeId: string): Promise<boolean> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const index = entries.findIndex((entry) => entry.ceremonyId === ceremonyId);
      const current = entries[index];
      if (
        !current
        || !isTerminal(current)
        || current.request.bridgeRequestId !== bridgeId
        || current.outcomeId !== outcomeId
      ) {
        await this.#write(entries);
        return false;
      }
      entries.splice(index, 1);
      await this.#write(entries);
      return true;
    });
  }

  get(ceremonyId: string): Promise<PasskeyCeremonyRecord | undefined> {
    return this.#serialize(async () => {
      const entries = await this.#readAndNormalize(this.#currentTime());
      await this.#write(entries);
      const found = entries.find((entry) => entry.ceremonyId === ceremonyId);
      return found ? cloneRecord(found) : undefined;
    });
  }

  listAwaitingApproval(): Promise<readonly AwaitingPasskeyCeremony[]> {
    return this.#serialize(async () => {
      const entries = await this.#readAndNormalize(this.#currentTime());
      await this.#write(entries);
      return entries
        .filter((entry): entry is AwaitingPasskeyCeremony => entry.state === 'awaitingApproval')
        .map(cloneRecord);
    });
  }

  listRedeliverable(): Promise<readonly TerminalPasskeyCeremony[]> {
    return this.#serialize(async () => {
      const entries = await this.#readAndNormalize(this.#currentTime());
      await this.#write(entries);
      return entries.filter(isTerminal).map(cloneRecord);
    });
  }

  #settleExecution<Terminal extends TerminalPasskeyCeremony>(
    ceremonyId: string,
    executionId: string,
    settle: (
      current: ExecutingPasskeyCeremony,
      now: number,
      entries: readonly PasskeyCeremonyRecord[],
    ) => Terminal,
  ): Promise<Terminal | undefined> {
    return this.#serialize(async () => {
      const now = this.#currentTime();
      const entries = await this.#readAndNormalize(now);
      const index = entries.findIndex((entry) => entry.ceremonyId === ceremonyId);
      const current = entries[index];
      if (!current || current.state !== 'executing' || current.executionId !== executionId) {
        await this.#write(entries);
        return undefined;
      }
      const terminal = settle(current, now, entries);
      entries[index] = terminal;
      await this.#write(entries);
      return cloneRecord(terminal);
    });
  }

  #fallbackRecord(
    current: AwaitingPasskeyCeremony,
    reason: WebsitePasskeyFallbackReason,
    now: number,
    entries: readonly PasskeyCeremonyRecord[] = [current],
  ): FallbackPasskeyCeremony {
    return {
      ...current,
      state: 'fallback',
      outcomeId: this.#freshId(entries),
      terminalAt: now,
      retireAt: this.#retireAt(current, now),
      reason,
    };
  }

  #uncertainRecord(
    current: ExecutingPasskeyCeremony,
    reason: PasskeyCeremonyTerminalReason,
    now: number,
    entries: readonly PasskeyCeremonyRecord[] = [current],
  ): UncertainPasskeyCeremony {
    return {
      ...current,
      state: 'uncertain',
      outcomeId: this.#freshId(entries),
      terminalAt: now,
      retireAt: this.#retireAt(current, now),
      reason,
    };
  }

  #failedRecord(
    current: ExecutingPasskeyCeremony,
    reason: PasskeyCeremonyTerminalReason,
    now: number,
    entries: readonly PasskeyCeremonyRecord[] = [current],
  ): FailedPasskeyCeremony {
    return {
      ...current,
      state: 'failed',
      outcomeId: this.#freshId(entries),
      terminalAt: now,
      retireAt: this.#retireAt(current, now),
      reason,
    };
  }

  #preExecutionFailedRecord(
    current: AwaitingPasskeyCeremony,
    reason: PasskeyCeremonyTerminalReason,
    now: number,
    entries: readonly PasskeyCeremonyRecord[] = [current],
  ): PreExecutionFailedPasskeyCeremony {
    return {
      ...current,
      state: 'failed',
      outcomeId: this.#freshId(entries),
      terminalAt: now,
      retireAt: this.#retireAt(current, now),
      reason,
    };
  }

  async #readAndNormalize(now: number): Promise<PasskeyCeremonyRecord[]> {
    const raw = await this.#store.get<unknown>(PASSKEY_CEREMONY_STORAGE_KEY);
    const entries = await parseEnvelope(raw, now, this.#ttlMs, this.#terminalTtlMs);
    if (!entries) {
      if (raw !== undefined) await this.#store.remove(PASSKEY_CEREMONY_STORAGE_KEY);
      return [];
    }
    const normalized: PasskeyCeremonyRecord[] = [];
    for (const entry of entries) {
      if (entry.state === 'awaitingApproval' && entry.deadlineAt <= now) {
        normalized.push(this.#preExecutionFailedRecord(entry, 'expired', now, [...entries, ...normalized]));
      } else if (entry.state === 'executing' && entry.deadlineAt <= now) {
        normalized.push(entry.request.kind === 'get'
          ? this.#failedRecord(entry, 'expired', now, [...entries, ...normalized])
          : this.#uncertainRecord(entry, 'expired', now, [...entries, ...normalized]));
      } else if (isTerminal(entry) && entry.retireAt <= now) {
        // A terminal outcome is retained only for its bounded document-redelivery window.
      } else {
        normalized.push(entry);
      }
    }
    return normalized;
  }

  async #write(entries: readonly PasskeyCeremonyRecord[]): Promise<void> {
    const value: PersistedPasskeyCeremonies = {
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries,
    };
    const bytes = persistedEnvelopeUtf8Bytes(value);
    if (bytes === undefined || bytes > PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET) {
      throw registryError('storage_capacity', 'Passkey ceremony storage budget exceeded');
    }
    await this.#store.set(PASSKEY_CEREMONY_STORAGE_KEY, value);
  }

  #freshId(entries: readonly PasskeyCeremonyRecord[]): string {
    const maximumAttempts = (MAX_PASSKEY_CEREMONY_CAPACITY * 3) + 1;
    for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
      let id: string;
      try { id = this.#createId(); } catch { throw registryError('id_generation', 'Could not create a ceremony id'); }
      if (typeof id !== 'string' || id.length !== 36 || !UUID_V4.test(id)) {
        throw registryError('id_generation', 'Ceremony ids must be lowercase UUID v4 values');
      }
      if (!entries.some((entry) => recordHasId(entry, id))) return id;
    }
    throw registryError('id_collision', 'Passkey ceremony id collision');
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0 || Object.is(now, -0)) {
      throw invalidConfiguration('clock is invalid');
    }
    return now;
  }

  #deadline(now: number, duration: number): number {
    const deadline = now + duration;
    if (!Number.isSafeInteger(deadline) || deadline <= now) {
      throw invalidConfiguration('ceremony deadline is invalid');
    }
    return deadline;
  }

  #retireAt(current: Pick<PasskeyCeremonyBase, 'deadlineAt'>, terminalAt: number): number {
    return this.#deadline(Math.max(current.deadlineAt, terminalAt), this.#terminalTtlMs);
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const owner = this.#store as object;
    const previous = RMW_TAILS.get(owner) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const tail = result.then(() => undefined, () => undefined);
    RMW_TAILS.set(owner, tail);
    void tail.finally(() => {
      if (RMW_TAILS.get(owner) === tail) RMW_TAILS.delete(owner);
    });
    return result;
  }
}

interface CanonicalBeginInput {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly frameUrl: string;
  readonly origin: string;
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly sessionBindingId: string;
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly rawGeneration: string;
  readonly snapshotGeneration?: string;
  readonly policyGeneration: number;
  readonly candidates: readonly PasskeyCeremonyCandidateSnapshot[];
  readonly requestedCeremonyId?: string;
  readonly requestedDeadlineAt?: number;
  readonly unsupportedReason?: WebsitePasskeyUnsupportedReason;
}

function canonicalizeBeginInput(value: unknown): CanonicalBeginInput {
  const input = strictRecord(value);
  exactKeys(
    input,
    [
      'tabId', 'frameId', 'documentId', 'frameUrl', 'origin', 'request', 'sessionBindingId',
      'accountIdentity', 'serverUrl', 'rawGeneration', 'policyGeneration', 'candidates',
    ],
    ['snapshotGeneration', 'requestedCeremonyId', 'requestedDeadlineAt'],
  );
  const tabId = boundedInteger(dataProperty(input, 'tabId'), 0, Number.MAX_SAFE_INTEGER, 'tabId');
  const frameId = boundedInteger(dataProperty(input, 'frameId'), 0, Number.MAX_SAFE_INTEGER, 'frameId');
  const frameUrl = canonicalSecureUrl(dataProperty(input, 'frameUrl'), 'frameUrl', true);
  const origin = canonicalOrigin(dataProperty(input, 'origin'));
  if (new URL(frameUrl).origin !== origin) invalidInput('origin does not match frameUrl');

  let decision;
  try {
    decision = decideWebsitePasskeySupport(dataProperty(input, 'request'));
  } catch (error) {
    if (error instanceof WebsitePasskeyPortProtocolError) invalidInput('request');
    throw error;
  }
  const rpId = decision.request.kind === 'get' ? decision.request.rpId : decision.request.rp.id;
  if (!isRegistrableRpId(rpId, new URL(frameUrl).hostname)) invalidInput('request rpId');
  const candidates = canonicalCandidates(dataProperty(input, 'candidates'));
  const expectedCandidateKind = decision.request.kind === 'get' ? 'credential' : 'target';
  if (candidates.some((candidate) => candidate.kind !== expectedCandidateKind)) {
    invalidInput('candidate kind');
  }
  return Object.freeze({
    tabId,
    frameId,
    documentId: opaqueId(dataProperty(input, 'documentId'), 'documentId'),
    frameUrl,
    origin,
    request: decision.request,
    sessionBindingId: opaqueId(dataProperty(input, 'sessionBindingId'), 'sessionBindingId'),
    accountIdentity: canonicalAccountIdentity(dataProperty(input, 'accountIdentity')),
    serverUrl: canonicalSecureUrl(dataProperty(input, 'serverUrl'), 'serverUrl', true),
    rawGeneration: opaqueId(dataProperty(input, 'rawGeneration'), 'rawGeneration'),
    ...(hasOwn(input, 'snapshotGeneration')
      ? { snapshotGeneration: opaqueId(dataProperty(input, 'snapshotGeneration'), 'snapshotGeneration') }
      : {}),
    policyGeneration: boundedInteger(
      dataProperty(input, 'policyGeneration'), 0, Number.MAX_SAFE_INTEGER, 'policyGeneration',
    ),
    candidates,
    ...(hasOwn(input, 'requestedCeremonyId')
      ? { requestedCeremonyId: uuid(dataProperty(input, 'requestedCeremonyId'), 'requestedCeremonyId') }
      : {}),
    ...(hasOwn(input, 'requestedDeadlineAt')
      ? {
          requestedDeadlineAt: boundedInteger(
            dataProperty(input, 'requestedDeadlineAt'), 1, Number.MAX_SAFE_INTEGER, 'requestedDeadlineAt',
          ),
        }
      : {}),
    ...(decision.status === 'fallback' ? { unsupportedReason: decision.reason } : {}),
  });
}

function canonicalCandidates(value: unknown): readonly PasskeyCeremonyCandidateSnapshot[] {
  const entries = strictArray(value, MAX_CANDIDATES);
  const ids = new Set<string>();
  return Object.freeze(entries.map((entry) => {
    const candidate = strictRecord(entry);
    exactKeys(candidate, ['kind', 'id', 'name'], ['username']);
    const kind = dataProperty(candidate, 'kind');
    if (kind !== 'credential' && kind !== 'target') invalidInput('candidate kind');
    const id = opaqueId(dataProperty(candidate, 'id'), 'candidate id');
    if (ids.has(id)) invalidInput('candidate id');
    ids.add(id);
    return Object.freeze({
      kind,
      id,
      name: displayString(dataProperty(candidate, 'name'), 'candidate name'),
      ...(hasOwn(candidate, 'username')
        ? { username: displayString(dataProperty(candidate, 'username'), 'candidate username') }
        : {}),
    });
  }));
}

async function digestRequest(request: CanonicalWebsitePasskeyRequest): Promise<string> {
  const serialized = serializeCanonicalWebsitePasskeyRequest(request);
  const bytes = new TextEncoder().encode(`${REQUEST_DIGEST_DOMAIN}${serialized}`);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function parseEnvelope(
  value: unknown,
  now: number,
  ttlMs: number,
  terminalTtlMs: number,
): Promise<PasskeyCeremonyRecord[] | undefined> {
  if (value === undefined) return [];
  try {
    const envelope = strictRecord(value);
    exactKeys(envelope, ['schemaVersion', 'entries']);
    if (dataProperty(envelope, 'schemaVersion') !== PASSKEY_CEREMONY_SCHEMA_VERSION) return undefined;
    const rawEntries = strictArray(dataProperty(envelope, 'entries'), MAX_PASSKEY_CEREMONY_CAPACITY);
    const entries: PasskeyCeremonyRecord[] = [];
    const ids = new Set<string>();
    const activeDocuments = new Set<string>();
    for (const raw of rawEntries) {
      const entry = await parseRecord(raw, now, ttlMs, terminalTtlMs);
      for (const id of recordIds(entry)) {
        if (ids.has(id)) return undefined;
        ids.add(id);
      }
      if (isActive(entry)) {
        const key = JSON.stringify([entry.tabId, entry.frameId, entry.documentId]);
        if (activeDocuments.has(key)) return undefined;
        activeDocuments.add(key);
      }
      entries.push(entry);
    }
    const byteLength = persistedEnvelopeUtf8Bytes({
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries,
    });
    if (byteLength === undefined || byteLength > PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET) {
      return undefined;
    }
    return entries;
  } catch {
    return undefined;
  }
}

async function parseRecord(
  value: unknown,
  now: number,
  ttlMs: number,
  terminalTtlMs: number,
): Promise<PasskeyCeremonyRecord> {
  const record = strictRecord(value);
  const state = dataProperty(record, 'state');
  const baseKeys = [
    'schemaVersion', 'ceremonyId', 'tabId', 'frameId', 'documentId', 'frameUrl', 'origin',
    'request', 'requestDigest', 'sessionBindingId', 'accountIdentity', 'serverUrl',
    'rawGeneration', 'policyGeneration', 'candidates', 'createdAt', 'deadlineAt', 'state',
  ] as const;
  const optionalBase = ['snapshotGeneration'] as const;
  switch (state) {
    case 'awaitingApproval':
      exactKeys(record, baseKeys, optionalBase);
      break;
    case 'executing':
      exactKeys(record, [...baseKeys, 'executionId', 'startedAt'], optionalBase);
      break;
    case 'completed':
      exactKeys(record, [
        ...baseKeys, 'executionId', 'startedAt', 'outcomeId', 'terminalAt', 'retireAt', 'result',
      ], optionalBase);
      break;
    case 'failed': {
      const hasExecutionId = hasOwn(record, 'executionId');
      const hasStartedAt = hasOwn(record, 'startedAt');
      if (hasExecutionId !== hasStartedAt) invalidInput('failed execution shape');
      exactKeys(record, [
        ...baseKeys,
        ...(hasExecutionId ? ['executionId', 'startedAt'] as const : []),
        'outcomeId', 'terminalAt', 'retireAt', 'reason',
      ], optionalBase);
      break;
    }
    case 'uncertain':
      exactKeys(record, [
        ...baseKeys, 'executionId', 'startedAt', 'outcomeId', 'terminalAt', 'retireAt', 'reason',
      ], optionalBase);
      break;
    case 'fallback':
      exactKeys(record, [...baseKeys, 'outcomeId', 'terminalAt', 'retireAt', 'reason'], optionalBase);
      break;
    default:
      return invalidInput('stored state');
  }
  if (dataProperty(record, 'schemaVersion') !== PASSKEY_CEREMONY_SCHEMA_VERSION) {
    invalidInput('stored schemaVersion');
  }

  const canonical = canonicalizeBeginInput({
    tabId: dataProperty(record, 'tabId'),
    frameId: dataProperty(record, 'frameId'),
    documentId: dataProperty(record, 'documentId'),
    frameUrl: dataProperty(record, 'frameUrl'),
    origin: dataProperty(record, 'origin'),
    request: dataProperty(record, 'request'),
    sessionBindingId: dataProperty(record, 'sessionBindingId'),
    accountIdentity: dataProperty(record, 'accountIdentity'),
    serverUrl: dataProperty(record, 'serverUrl'),
    rawGeneration: dataProperty(record, 'rawGeneration'),
    ...(hasOwn(record, 'snapshotGeneration')
      ? { snapshotGeneration: dataProperty(record, 'snapshotGeneration') }
      : {}),
    policyGeneration: dataProperty(record, 'policyGeneration'),
    candidates: dataProperty(record, 'candidates'),
  });
  const requestDigest = lowercaseDigest(dataProperty(record, 'requestDigest'));
  if (requestDigest !== await digestRequest(canonical.request)) invalidInput('requestDigest');
  const createdAt = timestamp(dataProperty(record, 'createdAt'), 'createdAt');
  const deadlineAt = timestamp(dataProperty(record, 'deadlineAt'), 'deadlineAt');
  if (
    createdAt > now + MAX_CLOCK_SKEW_MS
    || deadlineAt <= createdAt
    || deadlineAt - createdAt > Math.min(ttlMs, canonical.request.timeout)
  ) invalidInput('stored deadline');

  const base: PasskeyCeremonyBase = {
    schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
    ceremonyId: uuid(dataProperty(record, 'ceremonyId'), 'ceremonyId'),
    tabId: canonical.tabId,
    frameId: canonical.frameId,
    documentId: canonical.documentId,
    frameUrl: canonical.frameUrl,
    origin: canonical.origin,
    request: canonical.request,
    requestDigest,
    sessionBindingId: canonical.sessionBindingId,
    accountIdentity: canonical.accountIdentity,
    serverUrl: canonical.serverUrl,
    rawGeneration: canonical.rawGeneration,
    ...(canonical.snapshotGeneration === undefined
      ? {}
      : { snapshotGeneration: canonical.snapshotGeneration }),
    policyGeneration: canonical.policyGeneration,
    candidates: canonical.candidates,
    createdAt,
    deadlineAt,
  };
  if (state === 'awaitingApproval') return { ...base, state };

  if (state === 'executing') {
    const startedAt = parseStartedAt(record, createdAt, deadlineAt, now);
    return {
      ...base,
      state,
      executionId: uuid(dataProperty(record, 'executionId'), 'executionId'),
      startedAt,
    };
  }

  const outcomeId = uuid(dataProperty(record, 'outcomeId'), 'outcomeId');
  const terminal = parseTerminalTimes(record, createdAt, deadlineAt, now, terminalTtlMs);
  if (state === 'fallback') {
    return {
      ...base,
      state,
      outcomeId,
      ...terminal,
      reason: canonicalFallbackReason(dataProperty(record, 'reason')),
    };
  }
  if (state === 'failed' && !hasOwn(record, 'executionId')) {
    return {
      ...base,
      state,
      outcomeId,
      ...terminal,
      reason: canonicalReason(dataProperty(record, 'reason')),
    };
  }
  const executionId = uuid(dataProperty(record, 'executionId'), 'executionId');
  const startedAt = parseStartedAt(record, createdAt, deadlineAt, now);
  if (terminal.terminalAt < startedAt) invalidInput('terminalAt');
  if (state === 'completed') {
    if (terminal.terminalAt >= deadlineAt) invalidInput('completed after deadline');
    return {
      ...base,
      state,
      executionId,
      startedAt,
      outcomeId,
      ...terminal,
      result: canonicalResult(dataProperty(record, 'result'), canonical.request),
    };
  }
  if (state === 'uncertain' && canonical.request.kind === 'get') {
    invalidInput('get ceremony uncertainty');
  }
  const reason = canonicalReason(dataProperty(record, 'reason'));
  return state === 'failed'
    ? { ...base, state, executionId, startedAt, outcomeId, ...terminal, reason }
    : { ...base, state, executionId, startedAt, outcomeId, ...terminal, reason };
}

function parseStartedAt(
  record: Record<string, unknown>,
  createdAt: number,
  deadlineAt: number,
  now: number,
): number {
  const startedAt = timestamp(dataProperty(record, 'startedAt'), 'startedAt');
  if (startedAt < createdAt || startedAt >= deadlineAt || startedAt > now + MAX_CLOCK_SKEW_MS) {
    invalidInput('startedAt');
  }
  return startedAt;
}

function parseTerminalTimes(
  record: Record<string, unknown>,
  createdAt: number,
  deadlineAt: number,
  now: number,
  terminalTtlMs: number,
): Pick<TerminalPasskeyCeremonyBase, 'terminalAt' | 'retireAt'> {
  const terminalAt = timestamp(dataProperty(record, 'terminalAt'), 'terminalAt');
  const retireAt = timestamp(dataProperty(record, 'retireAt'), 'retireAt');
  const retirementBase = Math.max(deadlineAt, terminalAt);
  const expectedRetireAt = retirementBase + terminalTtlMs;
  if (
    terminalAt < createdAt
    || terminalAt > now + MAX_CLOCK_SKEW_MS
    || !Number.isSafeInteger(expectedRetireAt)
    || retireAt !== expectedRetireAt
  ) invalidInput('stored terminal lifetime');
  return { terminalAt, retireAt };
}

function canonicalResult(
  value: unknown,
  request: CanonicalWebsitePasskeyRequest,
): PasskeyCeremonyResultSnapshot {
  try {
    const result = parsePasskeyCeremonyResultSnapshot(value, request.kind);
    if (
      request.kind === 'create'
      && result.kind === 'create'
      && (result.credProps !== null) !== request.extensions.credProps
    ) invalidInput('result credProps');
    return result;
  } catch (error) {
    if (error instanceof WebsitePasskeyPortProtocolError) invalidInput('result');
    throw error;
  }
}

function sameRequest(
  entry: PasskeyCeremonyRecord,
  input: CanonicalBeginInput & { readonly requestDigest: string },
): boolean {
  return sameDocument(entry, input)
    && entry.request.bridgeRequestId === input.request.bridgeRequestId
    && entry.requestDigest === input.requestDigest
    && entry.frameUrl === input.frameUrl
    && entry.origin === input.origin
    && entry.sessionBindingId === input.sessionBindingId
    && entry.accountIdentity === input.accountIdentity
    && entry.serverUrl === input.serverUrl
    && entry.rawGeneration === input.rawGeneration
    && entry.snapshotGeneration === input.snapshotGeneration
    && entry.policyGeneration === input.policyGeneration
    && sameCandidates(entry.candidates, input.candidates);
}

function sameCandidates(
  left: readonly PasskeyCeremonyCandidateSnapshot[],
  right: readonly PasskeyCeremonyCandidateSnapshot[],
): boolean {
  return left.length === right.length && left.every((candidate, index) => {
    const other = right[index];
    return other !== undefined
      && candidate.kind === other.kind
      && candidate.id === other.id
      && candidate.name === other.name
      && candidate.username === other.username;
  });
}

function sameDocument(
  entry: Pick<PasskeyCeremonyBase, 'tabId' | 'frameId' | 'documentId'>,
  input: Pick<PasskeyCeremonyBase, 'tabId' | 'frameId' | 'documentId'>,
): boolean {
  return entry.tabId === input.tabId
    && entry.frameId === input.frameId
    && entry.documentId === input.documentId;
}

function isActive(entry: PasskeyCeremonyRecord): entry is AwaitingPasskeyCeremony | ExecutingPasskeyCeremony {
  return entry.state === 'awaitingApproval' || entry.state === 'executing';
}

function isTerminal(entry: PasskeyCeremonyRecord): entry is TerminalPasskeyCeremony {
  return !isActive(entry);
}

function recordIds(entry: PasskeyCeremonyRecord): string[] {
  return [
    entry.ceremonyId,
    ...(entry.state === 'executing' || entry.state === 'completed'
      || (entry.state === 'failed' && 'executionId' in entry) || entry.state === 'uncertain'
      ? [entry.executionId]
      : []),
    ...(isTerminal(entry) ? [entry.outcomeId] : []),
  ];
}

function recordHasId(entry: PasskeyCeremonyRecord, id: string): boolean {
  return recordIds(entry).includes(id);
}

function cloneRecord<RecordType extends PasskeyCeremonyRecord>(record: RecordType): RecordType {
  return structuredClone(record);
}

function canonicalReason(value: unknown): PasskeyCeremonyTerminalReason {
  switch (value) {
    case 'cancelled':
    case 'expired':
    case 'unsupported':
    case 'no_match':
    case 'context_changed':
    case 'session_changed':
    case 'account_changed':
    case 'cache_changed':
    case 'excluded_domain':
    case 'feature_disabled':
    case 'execution_failed':
    case 'worker_restart':
    case 'delivery_failed':
    case 'vault_locked':
    case 'user_selected_browser':
    case 'invalid_state':
    case 'not_allowed':
    case 'not_supported':
    case 'operation_failed':
      return value;
    default:
      return invalidInput('terminal reason');
  }
}

function canonicalFallbackReason(value: unknown): WebsitePasskeyFallbackReason {
  switch (value) {
    case 'excluded_domain':
    case 'no_match':
    case 'unsupported':
    case 'user_selected_browser':
      return value;
    default:
      return invalidInput('fallback reason');
  }
}

function canonicalSecureUrl(value: unknown, field: string, allowLoopbackIp = false): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LENGTH) {
    invalidInput(field);
  }
  let parsed: URL;
  try { parsed = new URL(value); } catch { return invalidInput(field); }
  const loopback = parsed.hostname === 'localhost'
    || (allowLoopbackIp && (parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]'));
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) || parsed.username || parsed.password) {
    invalidInput(field);
  }
  if (parsed.href.length > MAX_URL_LENGTH) invalidInput(field);
  return parsed.href;
}

function canonicalOrigin(value: unknown): string {
  const parsed = canonicalSecureUrl(value, 'origin', true);
  const url = new URL(parsed);
  if (url.origin !== value || (url.pathname !== '/' && url.pathname !== '')) invalidInput('origin');
  return url.origin;
}

function canonicalAccountIdentity(value: unknown): string {
  if (typeof value !== 'string') invalidInput('accountIdentity');
  const canonical = value.trim().toLowerCase();
  if (!canonical || canonical.length > MAX_DISPLAY_LENGTH || canonical !== value) {
    invalidInput('accountIdentity');
  }
  return canonical;
}

function opaqueId(value: unknown, field: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_OPAQUE_ID_LENGTH
    || value.trim() !== value
  ) invalidInput(field);
  return value;
}

function displayString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_DISPLAY_LENGTH) {
    invalidInput(field);
  }
  return value;
}

function lowercaseDigest(value: unknown): string {
  if (typeof value !== 'string' || !SHA256_HEX.test(value)) invalidInput('requestDigest');
  return value;
}

function uuid(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length !== 36 || !UUID_V4.test(value)) invalidInput(field);
  return value;
}

function timestamp(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) invalidInput(field);
  return value as number;
}

function boundedInteger(value: unknown, minimum: number, maximum: number, field: string): number {
  if (
    !Number.isSafeInteger(value)
    || Object.is(value, -0)
    || (value as number) < minimum
    || (value as number) > maximum
  ) invalidInput(field);
  return value as number;
}

function strictRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalidInput('record');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidInput('record');
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') invalidInput('record');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidInput('record');
    }
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const keys = Reflect.ownKeys(value);
  const allowed = new Set([...required, ...optional]);
  if (keys.length < required.length || keys.length > allowed.size) invalidInput('record');
  for (const key of required) if (!hasOwn(value, key)) invalidInput('record');
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key)) invalidInput('record');
  }
}

function strictArray(value: unknown, maximumLength: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximumLength) {
    invalidInput('array');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !hasOwn(value, 'length')) invalidInput('array');
  const entries: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidInput('array');
    }
    entries.push(descriptor.value);
  }
  for (const key of keys) {
    if (key !== 'length' && (typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/.test(key))) {
      invalidInput('array');
    }
  }
  return entries;
}

function dataProperty(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
    invalidInput(key);
  }
  return descriptor.value;
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function boundedPositiveInteger(value: number, maximum: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw invalidConfiguration(`${field} must be a positive integer no greater than ${maximum}`);
  }
  return value;
}

function invalidConfiguration(message: string): PasskeyCeremonyRegistryError {
  return registryError('invalid_configuration', message);
}

function invalidInput(field: string): never {
  throw registryError('invalid_input', `${field} is invalid`);
}

function registryError(
  code: PasskeyCeremonyRegistryErrorCode,
  message: string,
): PasskeyCeremonyRegistryError {
  return new PasskeyCeremonyRegistryError(code, message);
}
