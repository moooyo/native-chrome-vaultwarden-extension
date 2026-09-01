import type { KeyValueStore } from '../platform/store.js';

export const HTTP_AUTH_TOMBSTONE_STORAGE_KEY = 'httpAuth.tombstones';
export const HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION = 1 as const;
export const DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS = 5 * 60_000;
export const MAX_HTTP_AUTH_TOMBSTONE_TTL_MS = DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS;
export const DEFAULT_HTTP_AUTH_TOMBSTONE_CAPACITY = 512;
export const MAX_HTTP_AUTH_TOMBSTONE_CAPACITY = DEFAULT_HTTP_AUTH_TOMBSTONE_CAPACITY;
export const HTTP_AUTH_TOMBSTONE_ENVELOPE_MAX_UTF8_BYTES = 128 * 1_024;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_STORAGE_KEY_LENGTH = 256;

export interface HttpAuthTombstoneStoreOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set'>;
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
}

interface StoredHttpAuthTombstone {
  readonly fingerprint: string;
  readonly claimedAt: number;
  readonly expiresAt: number;
}

interface HttpAuthTombstoneEnvelope {
  readonly schemaVersion: typeof HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION;
  readonly entries: readonly StoredHttpAuthTombstone[];
}

/**
 * A persistent, short-lived replay barrier for HTTP authentication attempts. Callers provide only
 * a SHA-256 fingerprint; request URLs, request identifiers, and credentials never enter storage.
 */
export class HttpAuthTombstoneStore {
  readonly #store: HttpAuthTombstoneStoreOptions['store'];
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  #tail: Promise<void> = Promise.resolve();

  constructor(options: HttpAuthTombstoneStoreOptions) {
    if (
      !options?.store
      || typeof options.store.get !== 'function'
      || typeof options.store.set !== 'function'
    ) {
      throw new TypeError('A session store with get and set is required');
    }
    this.#store = options.store;
    this.#storageKey = boundedStorageKey(
      options.storageKey ?? HTTP_AUTH_TOMBSTONE_STORAGE_KEY,
    );
    this.#now = options.now ?? Date.now;
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS,
      MAX_HTTP_AUTH_TOMBSTONE_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_HTTP_AUTH_TOMBSTONE_CAPACITY,
      MAX_HTTP_AUTH_TOMBSTONE_CAPACITY,
      'maxEntries',
    );
  }

  /**
   * Claim an opaque fingerprint until its TTL expires. Storage ambiguity always returns false, and
   * a corrupt envelope is deliberately left untouched for conservative recovery by the caller.
   */
  async claim(fingerprint: string): Promise<boolean> {
    if (!isSha256Fingerprint(fingerprint)) return false;

    const operation = this.#tail.then(
      () => this.#claim(fingerprint),
      () => this.#claim(fingerprint),
    );
    this.#tail = operation.then(() => undefined, () => undefined);
    try {
      return await operation;
    } catch {
      return false;
    }
  }

  async #claim(fingerprint: string): Promise<boolean> {
    const claimedAt = this.#currentTime();
    if (claimedAt === undefined) return false;

    const raw = await this.#store.get<unknown>(this.#storageKey);
    const current = raw === undefined
      ? emptyEnvelope()
      : parseEnvelope(raw, this.#storageKey, claimedAt);
    if (!current) return false;

    const liveEntries = current.entries.filter((entry) => entry.expiresAt > claimedAt);
    if (liveEntries.some((entry) => entry.fingerprint === fingerprint)) return false;

    const expiresAt = safeExpiry(claimedAt, this.#ttlMs);
    if (expiresAt === undefined) return false;

    const retained = [...liveEntries].sort(compareOldestFirst);
    const retainedLimit = this.#maxEntries - 1;
    if (retained.length > retainedLimit) {
      retained.splice(0, retained.length - retainedLimit);
    }
    const expected: HttpAuthTombstoneEnvelope = {
      schemaVersion: HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION,
      entries: [
        ...retained,
        { fingerprint, claimedAt, expiresAt },
      ],
    };
    if (!hasBoundedEnvelopeSize(this.#storageKey, expected)) return false;

    await this.#store.set(this.#storageKey, expected);

    const verifiedAt = this.#currentTime();
    if (verifiedAt === undefined || expiresAt <= verifiedAt) return false;
    const persisted = await this.#store.get<unknown>(this.#storageKey);
    if (persisted === undefined) return false;
    const verified = parseEnvelope(persisted, this.#storageKey, verifiedAt);
    return verified !== undefined && sameEnvelope(verified, expected);
  }

  #currentTime(): number | undefined {
    const now = this.#now();
    return isTimestamp(now) ? now : undefined;
  }
}

function emptyEnvelope(): HttpAuthTombstoneEnvelope {
  return { schemaVersion: HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION, entries: [] };
}

function parseEnvelope(
  value: unknown,
  storageKey: string,
  observedAt: number,
): HttpAuthTombstoneEnvelope | undefined {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, ['schemaVersion', 'entries'])) {
    return undefined;
  }
  if (
    value.schemaVersion !== HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION
    || !Array.isArray(value.entries)
    || value.entries.length > MAX_HTTP_AUTH_TOMBSTONE_CAPACITY
    || !hasDenseArrayShape(value.entries)
  ) {
    return undefined;
  }

  const entries: StoredHttpAuthTombstone[] = [];
  const fingerprints = new Set<string>();
  for (const candidate of value.entries) {
    if (
      !isPlainRecord(candidate)
      || !hasExactDataKeys(candidate, ['fingerprint', 'claimedAt', 'expiresAt'])
      || !isSha256Fingerprint(candidate.fingerprint)
      || !isTimestamp(candidate.claimedAt)
      || !isTimestamp(candidate.expiresAt)
      || candidate.claimedAt > observedAt
      || candidate.expiresAt <= candidate.claimedAt
      || candidate.expiresAt - candidate.claimedAt > MAX_HTTP_AUTH_TOMBSTONE_TTL_MS
      || fingerprints.has(candidate.fingerprint)
    ) {
      return undefined;
    }
    fingerprints.add(candidate.fingerprint);
    entries.push({
      fingerprint: candidate.fingerprint,
      claimedAt: candidate.claimedAt,
      expiresAt: candidate.expiresAt,
    });
  }

  const envelope: HttpAuthTombstoneEnvelope = {
    schemaVersion: HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION,
    entries,
  };
  return hasBoundedEnvelopeSize(storageKey, envelope) ? envelope : undefined;
}

function sameEnvelope(
  left: HttpAuthTombstoneEnvelope,
  right: HttpAuthTombstoneEnvelope,
): boolean {
  if (left.schemaVersion !== right.schemaVersion || left.entries.length !== right.entries.length) {
    return false;
  }
  return left.entries.every((entry, index) => {
    const expected = right.entries[index];
    return expected !== undefined
      && entry.fingerprint === expected.fingerprint
      && entry.claimedAt === expected.claimedAt
      && entry.expiresAt === expected.expiresAt;
  });
}

function compareOldestFirst(
  left: StoredHttpAuthTombstone,
  right: StoredHttpAuthTombstone,
): number {
  return left.claimedAt - right.claimedAt
    || left.expiresAt - right.expiresAt
    || left.fingerprint.localeCompare(right.fingerprint);
}

function hasBoundedEnvelopeSize(
  storageKey: string,
  envelope: HttpAuthTombstoneEnvelope,
): boolean {
  try {
    const serialized = JSON.stringify({ [storageKey]: envelope });
    return typeof serialized === 'string'
      && new TextEncoder().encode(serialized).byteLength
        <= HTTP_AUTH_TOMBSTONE_ENVELOPE_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}

function isSha256Fingerprint(value: unknown): value is string {
  return typeof value === 'string'
    && value.length === 64
    && SHA256_HEX.test(value);
}

function safeExpiry(claimedAt: number, ttlMs: number): number | undefined {
  const expiresAt = claimedAt + ttlMs;
  return Number.isSafeInteger(expiresAt) && expiresAt > claimedAt ? expiresAt : undefined;
}

function boundedStorageKey(value: unknown): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_STORAGE_KEY_LENGTH
    || value.trim() !== value
    || containsControlCharacter(value)
  ) {
    throw new TypeError('storageKey must be a bounded canonical string');
  }
  return value;
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function boundedPositiveInteger(value: unknown, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new TypeError(`${name} must be a positive integer no greater than ${maximum}`);
  }
  return value as number;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= 0
    && !Object.is(value, -0);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedSet = new Set(expected);
  if (keys.some((key) => !expectedSet.has(key as string))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function hasDenseArrayShape(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) return false;
  }
  return keys.every((key) => key === 'length'
    || (typeof key === 'string'
      && /^(0|[1-9]\d*)$/.test(key)
      && Number(key) < value.length));
}
