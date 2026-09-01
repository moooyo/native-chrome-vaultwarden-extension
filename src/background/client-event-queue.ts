import {
  MAX_CLIENT_EVENT_BATCH_EVENTS,
  MAX_CLIENT_EVENT_BATCH_UTF8_BYTES,
  clientEventBatchUtf8Bytes,
  parseClientEvent,
  type ClientEvent,
} from '../core/events/client-event.js';
import { canonicalizeServerCapabilityUrl } from '../core/api/server-capabilities.js';
import { bytesToHex, utf8ToBytes } from '../core/crypto/encoding.js';
import type { KeyValueStore } from '../platform/store.js';

export const CLIENT_EVENT_QUEUE_STORAGE_KEY = 'enterpriseClientEvents.v1';
export const CLIENT_EVENT_QUEUE_SCHEMA_VERSION = 1 as const;
export const MAX_CLIENT_EVENT_QUEUE_EVENTS = 2_048;
export const MAX_CLIENT_EVENT_QUEUE_UTF8_BYTES = 1024 * 1024;
export const MAX_CLIENT_EVENT_QUEUE_SCOPES = 32;
export const CLIENT_EVENT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
export const CLIENT_EVENT_CLAIM_TTL_MS = 2 * 60 * 1000;
export const CLIENT_EVENT_BACKOFF_BASE_MS = 5_000;
export const CLIENT_EVENT_BACKOFF_MAX_MS = 60 * 60 * 1000;
export const CLIENT_EVENT_RETRY_AFTER_MAX_MS = 24 * 60 * 60 * 1000;

const MAX_ACCOUNT_ID_LENGTH = 512;
const MAX_STORAGE_KEY_LENGTH = 256;
const MAX_FAILURE_COUNT = 30;
const MAX_ID_GENERATION_ATTEMPTS = 32;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SCOPE_KEY_PATTERN = /^[0-9a-f]{64}$/u;
const SCOPE_DIGEST_DOMAIN = 'miyu/enterprise-client-events/scope/v1\0';

export interface ClientEventQueueScope {
  readonly serverUrl: string;
  /** Stable authoritative account ID, such as the access-token subject or sync profile ID. */
  readonly accountId: string;
}

export interface QueuedClientEvent {
  readonly id: string;
  readonly event: ClientEvent;
  readonly enqueuedAt: number;
}

export type ClientEventClaimEntry = QueuedClientEvent;

export interface ClientEventClaim {
  readonly scope: ClientEventQueueScope;
  readonly token: string;
  readonly claimedAt: number;
  readonly entries: readonly ClientEventClaimEntry[];
}

export type ClientEventClaimResult =
  | { readonly kind: 'empty' }
  | { readonly kind: 'deferred'; readonly retryAt: number }
  | { readonly kind: 'busy'; readonly retryAt: number }
  | { readonly kind: 'claimed'; readonly claim: ClientEventClaim };

export type ClientEventSendFailure =
  | { readonly kind: 'network' }
  | { readonly kind: 'http'; readonly status: number; readonly retryAfter?: string };

export interface ClientEventRetryState {
  readonly released: number;
  readonly failureCount: number;
  readonly retryAt: number;
  readonly batchLimit: number;
}

export interface ClientEventQueueStatus {
  readonly queued: number;
  readonly claimed: number;
  readonly retryAt?: number;
  readonly batchLimit: number;
}

export interface ClientEventQueueOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly random?: () => number;
  readonly createId?: () => string;
  readonly maxEvents?: number;
  readonly maxStoredBytes?: number;
  readonly maxScopes?: number;
  readonly maxBatchEvents?: number;
  readonly maxBatchBytes?: number;
  readonly eventMaxAgeMs?: number;
  readonly claimTtlMs?: number;
}

export type ClientEventQueueErrorCode =
  | 'capacity'
  | 'corrupt_state'
  | 'unsupported_schema'
  | 'resource_limit'
  | 'invalid_claim';

export class ClientEventQueueError extends Error {
  constructor(readonly code: ClientEventQueueErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ClientEventQueueError';
  }
}

interface StoredEvent {
  id: string;
  event: ClientEvent;
  enqueuedAt: number;
  claimToken: string | null;
  claimedAt: number | null;
}

interface StoredScope {
  failureCount: number;
  retryAt: number;
  batchLimit: number;
  events: StoredEvent[];
}

interface StoredEnvelope {
  schemaVersion: typeof CLIENT_EVENT_QUEUE_SCHEMA_VERSION;
  scopes: Record<string, StoredScope>;
}

interface SharedQueue {
  tail: Promise<void>;
}

type ClaimSettlementState = 'active' | 'settling' | 'settled';

const SHARED_QUEUES = new Map<string, SharedQueue>();

/** Durable at-least-once queue for client-generated enterprise audit events. */
export class ClientEventQueue {
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #random: () => number;
  readonly #createId: () => string;
  readonly #maxEvents: number;
  readonly #maxStoredBytes: number;
  readonly #maxScopes: number;
  readonly #maxBatchEvents: number;
  readonly #maxBatchBytes: number;
  readonly #eventMaxAgeMs: number;
  readonly #claimTtlMs: number;
  readonly #sharedQueue: SharedQueue;
  readonly #claimStates = new WeakMap<object, ClaimSettlementState>();
  readonly #claimScopeKeys = new WeakMap<object, string>();

  constructor(
    private readonly store: Pick<KeyValueStore, 'get' | 'set'>,
    options: ClientEventQueueOptions = {},
  ) {
    if (!store || typeof store.get !== 'function' || typeof store.set !== 'function') {
      throw new TypeError('Client event queue requires a key-value store');
    }
    this.#storageKey = options.storageKey ?? CLIENT_EVENT_QUEUE_STORAGE_KEY;
    if (!this.#storageKey || this.#storageKey.length > MAX_STORAGE_KEY_LENGTH) {
      throw new TypeError('Client event queue storage key is invalid');
    }
    this.#now = options.now ?? Date.now;
    this.#random = options.random ?? Math.random;
    this.#createId = options.createId ?? (() => crypto.randomUUID());
    this.#maxEvents = boundedPositiveInteger(
      options.maxEvents ?? MAX_CLIENT_EVENT_QUEUE_EVENTS,
      MAX_CLIENT_EVENT_QUEUE_EVENTS,
      'maxEvents',
    );
    this.#maxStoredBytes = boundedPositiveInteger(
      options.maxStoredBytes ?? MAX_CLIENT_EVENT_QUEUE_UTF8_BYTES,
      MAX_CLIENT_EVENT_QUEUE_UTF8_BYTES,
      'maxStoredBytes',
    );
    this.#maxScopes = boundedPositiveInteger(
      options.maxScopes ?? MAX_CLIENT_EVENT_QUEUE_SCOPES,
      MAX_CLIENT_EVENT_QUEUE_SCOPES,
      'maxScopes',
    );
    this.#maxBatchEvents = boundedPositiveInteger(
      options.maxBatchEvents ?? MAX_CLIENT_EVENT_BATCH_EVENTS,
      MAX_CLIENT_EVENT_BATCH_EVENTS,
      'maxBatchEvents',
    );
    this.#maxBatchBytes = boundedPositiveInteger(
      options.maxBatchBytes ?? MAX_CLIENT_EVENT_BATCH_UTF8_BYTES,
      MAX_CLIENT_EVENT_BATCH_UTF8_BYTES,
      'maxBatchBytes',
    );
    this.#eventMaxAgeMs = boundedPositiveInteger(
      options.eventMaxAgeMs ?? CLIENT_EVENT_MAX_AGE_MS,
      CLIENT_EVENT_MAX_AGE_MS,
      'eventMaxAgeMs',
    );
    this.#claimTtlMs = boundedPositiveInteger(
      options.claimTtlMs ?? CLIENT_EVENT_CLAIM_TTL_MS,
      CLIENT_EVENT_CLAIM_TTL_MS,
      'claimTtlMs',
    );
    this.#sharedQueue = sharedQueue(this.#storageKey);
  }

  enqueue(scopeInput: ClientEventQueueScope, eventInput: ClientEvent): Promise<QueuedClientEvent> {
    const scope = parseScope(scopeInput);
    const event = parseClientEvent(eventInput);
    return deriveScopeKey(scope).then((key) => this.#serialize(async () => {
      const now = this.#currentTime();
      const envelope = await this.#readEnvelope();
      cleanupEnvelope(envelope, now, this.#eventMaxAgeMs, this.#claimTtlMs);
      let storedScope = envelope.scopes[key];
      if (!storedScope) {
        if (Object.keys(envelope.scopes).length >= this.#maxScopes) {
          throw new ClientEventQueueError('capacity', 'Client event queue scope capacity was reached');
        }
        storedScope = {
          failureCount: 0,
          retryAt: 0,
          batchLimit: this.#maxBatchEvents,
          events: [],
        };
        envelope.scopes[key] = storedScope;
      }
      if (countEvents(envelope) >= this.#maxEvents) {
        throw new ClientEventQueueError('capacity', 'Client event queue event capacity was reached');
      }
      const id = this.#newUniqueId(envelope);
      const stored: StoredEvent = {
        id,
        event,
        enqueuedAt: now,
        claimToken: null,
        claimedAt: null,
      };
      storedScope.events.push(stored);
      await this.#writeEnvelope(envelope);
      return freezeQueued(stored);
    }));
  }

  claim(scopeInput: ClientEventQueueScope): Promise<ClientEventClaimResult> {
    const scope = parseScope(scopeInput);
    return deriveScopeKey(scope).then((key) => this.#serialize(async () => {
      const now = this.#currentTime();
      const envelope = await this.#readEnvelope();
      const changed = cleanupEnvelope(envelope, now, this.#eventMaxAgeMs, this.#claimTtlMs);
      const storedScope = envelope.scopes[key];
      if (!storedScope) {
        if (changed) await this.#writeEnvelope(envelope);
        return Object.freeze({ kind: 'empty' as const });
      }
      if (storedScope.retryAt > now) {
        if (changed) await this.#writeEnvelope(envelope);
        return Object.freeze({ kind: 'deferred' as const, retryAt: storedScope.retryAt });
      }

      const claimedEvents = storedScope.events.filter((event) => event.claimToken !== null);
      if (claimedEvents.length > 0) {
        if (changed) await this.#writeEnvelope(envelope);
        const retryAt = Math.min(...claimedEvents.map((event) => (
          safeAdd(event.claimedAt ?? now, this.#claimTtlMs)
        )));
        return Object.freeze({ kind: 'busy' as const, retryAt });
      }

      const available = storedScope.events;

      const selected: StoredEvent[] = [];
      const limit = Math.min(storedScope.batchLimit, this.#maxBatchEvents);
      for (const event of available) {
        if (selected.length >= limit) break;
        const candidate = [...selected, event];
        if (clientEventBatchUtf8Bytes(candidate.map((entry) => entry.event)) > this.#maxBatchBytes) {
          break;
        }
        selected.push(event);
      }
      if (selected.length === 0) {
        throw new ClientEventQueueError(
          'resource_limit',
          'One client event cannot fit within the upload byte limit',
        );
      }

      const token = this.#newUniqueId(envelope);
      const selectedIds = new Set(selected.map((event) => event.id));
      for (const event of storedScope.events) {
        if (!selectedIds.has(event.id)) continue;
        event.claimToken = token;
        event.claimedAt = now;
      }
      await this.#writeEnvelope(envelope);

      const claim = Object.freeze({
        scope,
        token,
        claimedAt: now,
        entries: Object.freeze(selected.map((event) => freezeQueued(event))),
      });
      this.#registerClaim(claim, key);
      return Object.freeze({ kind: 'claimed' as const, claim });
    }));
  }

  /** Delete only IDs proven sent; events enqueued after the claim remain untouched. */
  acknowledge(claimInput: ClientEventClaim): Promise<number> {
    return this.#settle(claimInput, async (claim) => {
      const now = this.#currentTime();
      const envelope = await this.#readEnvelope();
      const changed = cleanupEnvelope(envelope, now, this.#eventMaxAgeMs, this.#claimTtlMs);
      const key = this.#claimScopeKey(claim);
      const storedScope = envelope.scopes[key];
      if (!storedScope) {
        if (changed) await this.#writeEnvelope(envelope);
        return 0;
      }
      const ids = new Set(claim.entries.map((entry) => entry.id));
      const before = storedScope.events.length;
      storedScope.events = storedScope.events.filter((event) => (
        !ids.has(event.id) || event.claimToken !== claim.token
      ));
      const removed = before - storedScope.events.length;
      if (removed > 0) {
        storedScope.failureCount = 0;
        storedScope.retryAt = 0;
      }
      if (storedScope.events.length === 0) delete envelope.scopes[key];
      if (changed || removed > 0) await this.#writeEnvelope(envelope);
      return removed;
    });
  }

  /** Release only this token's claims and compute a durable retry policy from the latest state. */
  release(
    claimInput: ClientEventClaim,
    failureInput: ClientEventSendFailure,
  ): Promise<ClientEventRetryState | undefined> {
    const failure = parseFailure(failureInput);
    return this.#settle(claimInput, async (claim) => {
      const now = this.#currentTime();
      const envelope = await this.#readEnvelope();
      const changed = cleanupEnvelope(envelope, now, this.#eventMaxAgeMs, this.#claimTtlMs);
      const storedScope = envelope.scopes[this.#claimScopeKey(claim)];
      if (!storedScope) {
        if (changed) await this.#writeEnvelope(envelope);
        return undefined;
      }

      const ids = new Set(claim.entries.map((entry) => entry.id));
      let released = 0;
      for (const event of storedScope.events) {
        if (!ids.has(event.id) || event.claimToken !== claim.token) continue;
        event.claimToken = null;
        event.claimedAt = null;
        released += 1;
      }
      if (released === 0) {
        if (changed) await this.#writeEnvelope(envelope);
        return undefined;
      }

      storedScope.failureCount = Math.min(MAX_FAILURE_COUNT, storedScope.failureCount + 1);
      if (failure.kind === 'http' && failure.status === 413) {
        storedScope.batchLimit = Math.max(
          1,
          Math.floor(Math.min(storedScope.batchLimit, claim.entries.length) / 2),
        );
      }
      const backoff = calculateBackoff(storedScope.failureCount, this.#nextRandom());
      const retryAfter = failure.kind === 'http'
        ? parseRetryAfterHeader(failure.retryAfter, now)
        : undefined;
      storedScope.retryAt = safeAdd(now, Math.max(backoff, retryAfter ?? 0));
      await this.#writeEnvelope(envelope);
      return Object.freeze({
        released,
        failureCount: storedScope.failureCount,
        retryAt: storedScope.retryAt,
        batchLimit: storedScope.batchLimit,
      });
    });
  }

  inspect(scopeInput: ClientEventQueueScope): Promise<ClientEventQueueStatus> {
    const scope = parseScope(scopeInput);
    return deriveScopeKey(scope).then((key) => this.#serialize(async () => {
      const now = this.#currentTime();
      const envelope = await this.#readEnvelope();
      const changed = cleanupEnvelope(envelope, now, this.#eventMaxAgeMs, this.#claimTtlMs);
      const storedScope = envelope.scopes[key];
      if (changed) await this.#writeEnvelope(envelope);
      if (!storedScope) {
        return Object.freeze({ queued: 0, claimed: 0, batchLimit: this.#maxBatchEvents });
      }
      return Object.freeze({
        queued: storedScope.events.length,
        claimed: storedScope.events.filter((event) => event.claimToken !== null).length,
        ...(storedScope.retryAt > now ? { retryAt: storedScope.retryAt } : {}),
        batchLimit: storedScope.batchLimit,
      });
    }));
  }

  discardScope(scopeInput: ClientEventQueueScope): Promise<number> {
    const scope = parseScope(scopeInput);
    return deriveScopeKey(scope).then((key) => this.#serialize(async () => {
      const envelope = await this.#readEnvelope();
      const removed = envelope.scopes[key]?.events.length ?? 0;
      if (removed > 0) {
        delete envelope.scopes[key];
        await this.#writeEnvelope(envelope);
      }
      return removed;
    }));
  }

  /** Explicitly replace an unreadable current-schema queue; future schemas always remain untouched. */
  recoverCorruptState(): Promise<boolean> {
    return this.#serialize(async () => {
      const raw = await this.store.get<unknown>(this.#storageKey);
      if (raw === undefined) return false;
      try {
        parseEnvelope(
          raw,
          this.#maxScopes,
          this.#maxEvents,
          this.#maxStoredBytes,
          this.#maxBatchEvents,
          this.#maxBatchBytes,
        );
        return false;
      } catch (error) {
        if (error instanceof ClientEventQueueError && error.code === 'unsupported_schema') {
          throw error;
        }
        await this.store.set(this.#storageKey, emptyEnvelope());
        return true;
      }
    });
  }

  async #readEnvelope(): Promise<StoredEnvelope> {
    const raw = await this.store.get<unknown>(this.#storageKey);
    if (raw === undefined) return emptyEnvelope();
    try {
      return parseEnvelope(
        raw,
        this.#maxScopes,
        this.#maxEvents,
        this.#maxStoredBytes,
        this.#maxBatchEvents,
        this.#maxBatchBytes,
      );
    } catch (error) {
      if (error instanceof ClientEventQueueError) throw error;
      throw new ClientEventQueueError('corrupt_state', 'Client event queue storage is corrupt', {
        cause: error,
      });
    }
  }

  async #writeEnvelope(envelope: StoredEnvelope): Promise<void> {
    if (Object.keys(envelope.scopes).length > this.#maxScopes
      || countEvents(envelope) > this.#maxEvents) {
      throw new ClientEventQueueError('capacity', 'Client event queue capacity was exceeded');
    }
    const bytes = envelopeUtf8Bytes(envelope);
    if (bytes > this.#maxStoredBytes) {
      throw new ClientEventQueueError('resource_limit', 'Client event queue byte capacity was reached');
    }
    await this.store.set(this.#storageKey, envelope);
  }

  #beginSettlement(value: ClientEventClaim): ClientEventClaim {
    if (typeof value !== 'object' || value === null || this.#claimStates.get(value) !== 'active') {
      throw new ClientEventQueueError('invalid_claim', 'Client event claim was not issued by this queue');
    }
    this.#claimStates.set(value, 'settling');
    return value;
  }

  #settle<Result>(
    claimInput: ClientEventClaim,
    operation: (claim: ClientEventClaim) => Promise<Result>,
  ): Promise<Result> {
    const claim = this.#beginSettlement(claimInput);
    const result = this.#serialize(() => operation(claim));
    return result.then(
      (value) => {
        this.#finishSettlement(claim);
        return value;
      },
      (error: unknown) => {
        this.#claimStates.set(claim, 'active');
        throw error;
      },
    );
  }

  #registerClaim(claim: ClientEventClaim, scopeKeyValue: string): void {
    this.#claimStates.set(claim, 'active');
    this.#claimScopeKeys.set(claim, scopeKeyValue);
  }

  #finishSettlement(claim: ClientEventClaim): void {
    this.#claimStates.set(claim, 'settled');
    this.#claimScopeKeys.delete(claim);
  }

  #claimScopeKey(claim: ClientEventClaim): string {
    const key = this.#claimScopeKeys.get(claim);
    if (!key) throw new ClientEventQueueError('invalid_claim', 'Client event claim scope is unavailable');
    return key;
  }

  #newUniqueId(envelope: StoredEnvelope): string {
    const ids = new Set<string>();
    for (const scope of Object.values(envelope.scopes)) {
      for (const event of scope.events) {
        ids.add(event.id);
        if (event.claimToken) ids.add(event.claimToken);
      }
    }
    for (let attempt = 0; attempt < MAX_ID_GENERATION_ATTEMPTS; attempt += 1) {
      const id = requireUuidV4(this.#createId());
      if (!ids.has(id)) return id;
    }
    throw new ClientEventQueueError('resource_limit', 'Unable to allocate a unique client event ID');
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Client event clock is invalid');
    return now;
  }

  #nextRandom(): number {
    const random = this.#random();
    if (!Number.isFinite(random) || random < 0 || random >= 1) {
      throw new TypeError('Client event jitter source is invalid');
    }
    return random;
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#sharedQueue.tail.then(operation, operation);
    this.#sharedQueue.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export function createClientEventQueueScope(
  serverUrl: string,
  accountId: string,
): ClientEventQueueScope {
  return parseScope({ serverUrl, accountId });
}

export function parseRetryAfterHeader(value: string | undefined, now: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(now) || now < 0 || value.length === 0 || value.length > 128
    || value.trim() !== value || containsControl(value)) return undefined;

  let delay: number;
  if (/^\d+$/u.test(value)) {
    const seconds = Number(value);
    if (!Number.isSafeInteger(seconds)) return CLIENT_EVENT_RETRY_AFTER_MAX_MS;
    delay = seconds * 1000;
  } else {
    const deadline = Date.parse(value);
    if (!Number.isFinite(deadline)) return undefined;
    delay = Math.max(0, deadline - now);
  }
  if (!Number.isFinite(delay)) return CLIENT_EVENT_RETRY_AFTER_MAX_MS;
  return Math.min(CLIENT_EVENT_RETRY_AFTER_MAX_MS, Math.max(0, Math.round(delay)));
}

function calculateBackoff(failureCount: number, random: number): number {
  const exponent = Math.min(MAX_FAILURE_COUNT - 1, Math.max(0, failureCount - 1));
  const nominal = Math.min(
    CLIENT_EVENT_BACKOFF_MAX_MS,
    CLIENT_EVENT_BACKOFF_BASE_MS * (2 ** exponent),
  );
  const jittered = nominal * (0.5 + random);
  return Math.max(1, Math.min(CLIENT_EVENT_BACKOFF_MAX_MS, Math.round(jittered)));
}

function parseFailure(value: ClientEventSendFailure): ClientEventSendFailure {
  if (!isPlainRecord(value)) throw new TypeError('Client event failure is invalid');
  if (value.kind === 'network') {
    requireExactDataKeys(value, ['kind']);
    return Object.freeze({ kind: 'network' });
  }
  if (value.kind !== 'http') throw new TypeError('Client event failure is invalid');
  const expected = value.retryAfter === undefined
    ? ['kind', 'status']
    : ['kind', 'status', 'retryAfter'];
  requireExactDataKeys(value, expected);
  if (!Number.isSafeInteger(value.status) || value.status < 100 || value.status > 599) {
    throw new TypeError('Client event HTTP status is invalid');
  }
  if (value.retryAfter !== undefined && typeof value.retryAfter !== 'string') {
    throw new TypeError('Client event Retry-After value is invalid');
  }
  return Object.freeze({
    kind: 'http',
    status: value.status,
    ...(value.retryAfter === undefined ? {} : { retryAfter: value.retryAfter }),
  });
}

function parseEnvelope(
  value: unknown,
  maxScopes: number,
  maxEvents: number,
  maxStoredBytes: number,
  maxBatchEvents: number,
  maxBatchBytes: number,
): StoredEnvelope {
  if (!isPlainRecord(value)) {
    throw corruptState();
  }
  const schemaDescriptor = Object.getOwnPropertyDescriptor(value, 'schemaVersion');
  const schemaVersion = schemaDescriptor?.enumerable === true && 'value' in schemaDescriptor
    ? schemaDescriptor.value
    : undefined;
  if (Number.isSafeInteger(schemaVersion)
    && (schemaVersion as number) > CLIENT_EVENT_QUEUE_SCHEMA_VERSION) {
    throw new ClientEventQueueError(
      'unsupported_schema',
      'Client event queue uses an unsupported schema version',
    );
  }
  if (!hasExactDataKeys(value, ['schemaVersion', 'scopes'])) throw corruptState();
  const rawScopes = dataValue(value, 'scopes');
  if (schemaVersion !== CLIENT_EVENT_QUEUE_SCHEMA_VERSION || !isPlainRecord(rawScopes)) {
    throw corruptState();
  }
  const keys = Reflect.ownKeys(rawScopes);
  if (keys.length > maxScopes || keys.some((key) => typeof key !== 'string')) {
    throw corruptState();
  }

  const scopes: Record<string, StoredScope> = Object.create(null) as Record<string, StoredScope>;
  const ids = new Set<string>();
  const claimTokens = new Set<string>();
  const claimGroups = new Map<string, {
    readonly scopeKey: string;
    readonly claimedAt: number;
    readonly events: ClientEvent[];
  }>();
  let eventCount = 0;
  for (const key of keys as string[]) {
    if (!SCOPE_KEY_PATTERN.test(key)) throw corruptState();
    const rawScope = dataValue(rawScopes, key);
    const scope = parseStoredScope(rawScope, maxBatchEvents, maxBatchBytes);
    eventCount += scope.events.length;
    if (eventCount > maxEvents) throw new ClientEventQueueError('capacity', 'Stored event capacity was exceeded');
    for (const event of scope.events) {
      if (ids.has(event.id) || claimTokens.has(event.id)) throw corruptState();
      ids.add(event.id);
      if (event.claimToken) {
        if (ids.has(event.claimToken)) throw corruptState();
        claimTokens.add(event.claimToken);
        const group = claimGroups.get(event.claimToken);
        if (group) {
          if (group.scopeKey !== key || group.claimedAt !== event.claimedAt) throw corruptState();
          group.events.push(event.event);
        } else {
          claimGroups.set(event.claimToken, {
            scopeKey: key,
            claimedAt: event.claimedAt!,
            events: [event.event],
          });
        }
      }
    }
    scopes[key] = scope;
  }
  for (const group of claimGroups.values()) {
    if (group.events.length > maxBatchEvents
      || clientEventBatchUtf8Bytes(group.events) > maxBatchBytes) {
      throw corruptState();
    }
  }
  const envelope: StoredEnvelope = {
    schemaVersion: CLIENT_EVENT_QUEUE_SCHEMA_VERSION,
    scopes,
  };
  if (envelopeUtf8Bytes(envelope) > maxStoredBytes) {
    throw new ClientEventQueueError('resource_limit', 'Stored client events exceed the byte limit');
  }
  return envelope;
}

function parseStoredScope(
  value: unknown,
  maxBatchEvents: number,
  maxBatchBytes: number,
): StoredScope {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, [
    'failureCount', 'retryAt', 'batchLimit', 'events',
  ])) throw corruptState();
  const failureCount = requireInteger(dataValue(value, 'failureCount'), 0, MAX_FAILURE_COUNT);
  const retryAt = requireInteger(dataValue(value, 'retryAt'), 0, Number.MAX_SAFE_INTEGER);
  if ((failureCount === 0) !== (retryAt === 0)) throw corruptState();
  const batchLimit = requireInteger(dataValue(value, 'batchLimit'), 1, maxBatchEvents);
  const rawEvents = dataValue(value, 'events');
  if (!Array.isArray(rawEvents) || rawEvents.length > MAX_CLIENT_EVENT_QUEUE_EVENTS
    || !hasDenseArrayShape(rawEvents) || rawEvents.length === 0) {
    throw corruptState();
  }
  const events = rawEvents.map(parseStoredEvent);
  const claimedEvents = events.filter((event) => event.claimToken !== null);
  if (new Set(claimedEvents.map((event) => event.claimToken)).size > 1
    || claimedEvents.length > batchLimit
    || (claimedEvents.length > 0
      && clientEventBatchUtf8Bytes(claimedEvents.map((event) => event.event)) > maxBatchBytes)) {
    throw corruptState();
  }
  return {
    failureCount,
    retryAt,
    batchLimit,
    events,
  };
}

function parseStoredEvent(value: unknown): StoredEvent {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, [
    'id', 'event', 'enqueuedAt', 'claimToken', 'claimedAt',
  ])) throw corruptState();
  const id = requireUuidV4(dataValue(value, 'id'));
  const event = parseClientEvent(dataValue(value, 'event'));
  const enqueuedAt = requireInteger(dataValue(value, 'enqueuedAt'), 0, Number.MAX_SAFE_INTEGER);
  const rawClaimToken = dataValue(value, 'claimToken');
  const rawClaimedAt = dataValue(value, 'claimedAt');
  if (rawClaimToken === null && rawClaimedAt === null) {
    return { id, event, enqueuedAt, claimToken: null, claimedAt: null };
  }
  const claimToken = requireUuidV4(rawClaimToken);
  const claimedAt = requireInteger(rawClaimedAt, enqueuedAt, Number.MAX_SAFE_INTEGER);
  return { id, event, enqueuedAt, claimToken, claimedAt };
}

function cleanupEnvelope(
  envelope: StoredEnvelope,
  now: number,
  eventMaxAgeMs: number,
  claimTtlMs: number,
): boolean {
  let changed = false;
  for (const [key, scope] of Object.entries(envelope.scopes)) {
    const retained: StoredEvent[] = [];
    for (const event of scope.events) {
      if (now >= safeAdd(event.enqueuedAt, eventMaxAgeMs)) {
        changed = true;
        continue;
      }
      if (event.claimedAt !== null && now >= safeAdd(event.claimedAt, claimTtlMs)) {
        event.claimToken = null;
        event.claimedAt = null;
        changed = true;
      }
      retained.push(event);
    }
    scope.events = retained;
    if (retained.length === 0) {
      delete envelope.scopes[key];
      changed = true;
    }
  }
  return changed;
}

function parseScope(value: { readonly serverUrl: unknown; readonly accountId: unknown }): ClientEventQueueScope {
  if (typeof value?.serverUrl !== 'string' || typeof value.accountId !== 'string') {
    throw new TypeError('Client event scope requires a server URL and stable account ID');
  }
  const serverUrl = canonicalizeServerCapabilityUrl(value.serverUrl);
  const accountId = value.accountId;
  if (!accountId || accountId.length > MAX_ACCOUNT_ID_LENGTH
    || accountId.trim() !== accountId || containsControl(accountId)
    || /[@\s]/u.test(accountId)) {
    throw new TypeError('Client event account ID is invalid');
  }
  return Object.freeze({ serverUrl, accountId });
}

async function deriveScopeKey(scope: ClientEventQueueScope): Promise<string> {
  const input = utf8ToBytes(`${SCOPE_DIGEST_DOMAIN}${JSON.stringify([
    scope.serverUrl,
    scope.accountId,
  ])}`);
  try {
    const digest = await crypto.subtle.digest('SHA-256', input as BufferSource);
    return bytesToHex(new Uint8Array(digest));
  } finally {
    input.fill(0);
  }
}

function freezeQueued(event: StoredEvent): QueuedClientEvent {
  return Object.freeze({ id: event.id, event: event.event, enqueuedAt: event.enqueuedAt });
}

function emptyEnvelope(): StoredEnvelope {
  return {
    schemaVersion: CLIENT_EVENT_QUEUE_SCHEMA_VERSION,
    scopes: Object.create(null) as Record<string, StoredScope>,
  };
}

function countEvents(envelope: StoredEnvelope): number {
  return Object.values(envelope.scopes).reduce((total, scope) => total + scope.events.length, 0);
}

function envelopeUtf8Bytes(envelope: StoredEnvelope): number {
  return new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
}

function sharedQueue(storageKey: string): SharedQueue {
  let queue = SHARED_QUEUES.get(storageKey);
  if (!queue) {
    queue = { tail: Promise.resolve() };
    SHARED_QUEUES.set(storageKey, queue);
  }
  return queue;
}

function requireUuidV4(value: unknown): string {
  if (typeof value !== 'string' || !UUID_V4_PATTERN.test(value)) {
    throw new TypeError('Client event queue ID must be a canonical UUID v4');
  }
  return value;
}

function requireInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw corruptState();
  }
  return value as number;
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be a positive integer no greater than ${maximum}`);
  }
  return value;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  return Number.isSafeInteger(result) ? result : Number.MAX_SAFE_INTEGER;
}

function corruptState(): ClientEventQueueError {
  return new ClientEventQueueError('corrupt_state', 'Client event queue storage is corrupt');
}

function containsControl(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 31 || code === 127;
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function requireExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  if (!hasExactDataKeys(record, expected)) throw new TypeError('Unexpected client event fields');
}

function hasExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  const expectedSet = new Set(expected);
  if (keys.length !== expected.length
    || keys.some((key) => typeof key !== 'string' || !expectedSet.has(key))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor?.enumerable || !('value' in descriptor)) throw corruptState();
  return descriptor.value;
}

function hasDenseArrayShape(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return true;
}
