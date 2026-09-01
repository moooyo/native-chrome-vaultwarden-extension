import { canonicalizeServerCapabilityUrl } from '../core/api/server-capabilities.js';
import { bytesToBase64Url } from '../core/crypto/encoding.js';
import type { GeneratorHistoryCrypto } from '../core/generator/history-crypto.js';
import { isGeneratorHistoryEntryType } from '../core/generator/history.js';
import type {
  GeneratorHistoryEntry,
  GeneratorHistoryTrackInput,
} from '../core/generator/history.js';
import type { KeyValueStore } from '../platform/store.js';

export type {
  GeneratorHistoryEntry,
  GeneratorHistoryEntryType,
  GeneratorHistoryTrackInput,
} from '../core/generator/history.js';

export const GENERATOR_HISTORY_SCHEMA_VERSION = 1 as const;
export const MAX_GENERATOR_HISTORY_ENTRIES = 200;
export const MAX_GENERATOR_HISTORY_VALUE_UTF8_BYTES = 32 * 1_024;
export const MAX_GENERATOR_HISTORY_PAYLOAD_UTF8_BYTES = 512 * 1_024;
export const GENERATOR_HISTORY_PADDING_FRAME_BYTES = 2_048;

const GENERATOR_HISTORY_STORAGE_PREFIX = 'generatorHistory.v1.';
const GENERATOR_HISTORY_SCOPE_DOMAIN = 'miyu.generator-history.scope.v1';
const MAX_GENERATOR_HISTORY_CIPHERTEXT_CHARS = 1_048_576;
const MAX_GENERATOR_HISTORY_STORAGE_BYTES = 1_100_000;
const MAX_GENERATOR_HISTORY_PACKED_BYTES = Math.ceil(
  (MAX_GENERATOR_HISTORY_PAYLOAD_UTF8_BYTES + 4) / GENERATOR_HISTORY_PADDING_FRAME_BYTES,
) * GENERATOR_HISTORY_PADDING_FRAME_BYTES;
const MAX_TIMESTAMP = 8_640_000_000_000_000;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const SCOPE_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const ENCODER = new TextEncoder();

export interface GeneratorHistoryScope {
  readonly digest: string;
  readonly storageKey: string;
}

export type GeneratorHistoryTrackResult =
  | { readonly added: false }
  | {
      readonly added: true;
      readonly entry: GeneratorHistoryEntry;
      readonly evicted: number;
    };

export type GeneratorHistoryRepositoryErrorCode =
  | 'corrupt_storage'
  | 'crypto_failure'
  | 'invalid_entry'
  | 'rollback_failed'
  | 'scope_locked'
  | 'scope_unavailable'
  | 'storage_capacity'
  | 'unsupported_schema';

export class GeneratorHistoryRepositoryError extends Error {
  constructor(
    readonly code: GeneratorHistoryRepositoryErrorCode,
    message: string,
    readonly scopeDigest?: string,
  ) {
    super(message);
    this.name = 'GeneratorHistoryRepositoryError';
  }
}

export interface GeneratorHistoryRepositoryOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly now?: () => number;
}

interface StoredGeneratorHistoryEnvelope {
  readonly schemaVersion: typeof GENERATOR_HISTORY_SCHEMA_VERSION;
  readonly scopeDigest: string;
  readonly payload: string;
}

interface GeneratorHistoryPayload {
  readonly schemaVersion: typeof GENERATOR_HISTORY_SCHEMA_VERSION;
  readonly scopeDigest: string;
  readonly entries: readonly GeneratorHistoryEntry[];
}

interface LoadedHistory {
  readonly envelope?: StoredGeneratorHistoryEnvelope;
  readonly payload: GeneratorHistoryPayload;
}

interface SharedScopeCoordinator {
  tail: Promise<void>;
  generation: number;
  locked: boolean;
  unavailable: boolean;
}

interface AccessSnapshot {
  readonly generation: number;
  readonly allowUnavailable: boolean;
}

/** Same-realm repository instances using the same store object share one FIFO per opaque scope. */
const COORDINATORS = new WeakMap<object, Map<string, SharedScopeCoordinator>>();

/**
 * Derive the only persistent account identifier used by generator history. The digest input is
 * length-framed and domain separated, and every temporary byte buffer is cleared before returning.
 */
export async function createGeneratorHistoryScope(
  serverUrlInput: string,
  accountIdInput: string,
): Promise<GeneratorHistoryScope> {
  const serverUrl = canonicalizeServerCapabilityUrl(serverUrlInput);
  const accountId = canonicalAccountId(accountIdInput);
  const domainBytes = ENCODER.encode(GENERATOR_HISTORY_SCOPE_DOMAIN);
  const serverBytes = ENCODER.encode(serverUrl);
  const accountBytes = ENCODER.encode(accountId);
  const material = new Uint8Array(
    4 + domainBytes.byteLength + 4 + serverBytes.byteLength + 4 + accountBytes.byteLength,
  );
  let digest: Uint8Array | undefined;
  try {
    const view = new DataView(material.buffer);
    let offset = 0;
    offset = writeLengthPrefixed(material, view, offset, domainBytes);
    offset = writeLengthPrefixed(material, view, offset, serverBytes);
    writeLengthPrefixed(material, view, offset, accountBytes);
    digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material as BufferSource));
    const encoded = bytesToBase64Url(digest);
    return Object.freeze({
      digest: encoded,
      storageKey: `${GENERATOR_HISTORY_STORAGE_PREFIX}${encoded}`,
    });
  } finally {
    domainBytes.fill(0);
    serverBytes.fill(0);
    accountBytes.fill(0);
    material.fill(0);
    digest?.fill(0);
  }
}

/**
 * Persistent, per-account generated credential history. Plaintext is never cached on the instance;
 * decrypted and serialized byte buffers are owned only by one FIFO operation and cleared in finally.
 */
export class GeneratorHistoryRepository {
  readonly #store: GeneratorHistoryRepositoryOptions['store'];
  readonly #now: () => number;

  constructor(options: GeneratorHistoryRepositoryOptions) {
    if (!options || !isFunction(options.store?.get)
      || !isFunction(options.store?.set) || !isFunction(options.store?.remove)) {
      throw new TypeError('Generator history requires a key-value store');
    }
    if (options.now !== undefined && !isFunction(options.now)) {
      throw new TypeError('Generator history now must be a function');
    }
    this.#store = options.store;
    this.#now = options.now ?? Date.now;
  }

  read(
    scopeInput: GeneratorHistoryScope,
    cryptoBoundary: GeneratorHistoryCrypto,
  ): Promise<readonly GeneratorHistoryEntry[]> {
    const scope = parseScope(scopeInput);
    const crypto = parseCrypto(cryptoBoundary);
    const coordinator = this.#coordinator(scope);
    const access = captureAccess(coordinator, scope.digest);
    return serialize(coordinator, async () => {
      assertAccess(coordinator, access, scope.digest);
      const loaded = await this.#load(scope, crypto, coordinator, access);
      assertAccess(coordinator, access, scope.digest);
      return publicEntries(loaded.payload.entries);
    });
  }

  track(
    scopeInput: GeneratorHistoryScope,
    cryptoBoundary: GeneratorHistoryCrypto,
    input: GeneratorHistoryTrackInput,
  ): Promise<GeneratorHistoryTrackResult> {
    const scope = parseScope(scopeInput);
    const crypto = parseCrypto(cryptoBoundary);
    const entry = parseTrackInput(input, this.#currentTime(), scope.digest);
    const coordinator = this.#coordinator(scope);
    const access = captureAccess(coordinator, scope.digest);
    return serialize(coordinator, async () => {
      assertAccess(coordinator, access, scope.digest);
      const loaded = await this.#load(scope, crypto, coordinator, access);
      if (loaded.payload.entries.some((candidate) => candidate.value === entry.value)) {
        assertAccess(coordinator, access, scope.digest);
        return Object.freeze({ added: false as const });
      }

      const entries = [entry, ...loaded.payload.entries].slice(0, MAX_GENERATOR_HISTORY_ENTRIES);
      let serialized = encodePayload(scope.digest, entries);
      try {
        while (serialized.byteLength > MAX_GENERATOR_HISTORY_PAYLOAD_UTF8_BYTES && entries.length > 1) {
          serialized.fill(0);
          entries.pop();
          serialized = encodePayload(scope.digest, entries);
        }
        if (serialized.byteLength > MAX_GENERATOR_HISTORY_PAYLOAD_UTF8_BYTES) {
          throw repositoryError('storage_capacity', 'Generator history payload is too large', scope.digest);
        }

        const plaintext = packPayload(serialized, scope.digest);
        try {
          let ciphertext: string;
          try {
            ciphertext = await crypto.encrypt(scope.digest, plaintext);
          } catch {
            assertAccess(coordinator, access, scope.digest);
            throw repositoryError('crypto_failure', 'Generator history encryption failed', scope.digest);
          }
          assertAccess(coordinator, access, scope.digest);
          const envelope = createStoredEnvelope(scope, ciphertext);
          await this.#writeWithRollback(scope, loaded.envelope, envelope, coordinator, access);
          return Object.freeze({
            added: true as const,
            entry,
            evicted: loaded.payload.entries.length + 1 - entries.length,
          });
        } finally {
          plaintext.fill(0);
        }
      } finally {
        serialized.fill(0);
      }
    });
  }

  /** Validate and atomically clear one unlocked scope without changing its access state. */
  clear(
    scopeInput: GeneratorHistoryScope,
    cryptoBoundary: GeneratorHistoryCrypto,
  ): Promise<boolean> {
    const scope = parseScope(scopeInput);
    const crypto = parseCrypto(cryptoBoundary);
    const coordinator = this.#coordinator(scope);
    const access = captureAccess(coordinator, scope.digest);
    return serialize(coordinator, async () => {
      assertAccess(coordinator, access, scope.digest);
      const loaded = await this.#load(scope, crypto, coordinator, access);
      assertAccess(coordinator, access, scope.digest);
      if (!loaded.envelope) return false;
      await this.#clearWithRollback(scope, loaded.envelope, coordinator, access);
      return true;
    });
  }

  /** Invalidate in-flight access and preserve the encrypted record for a later unlock. */
  lock(scopeInput: GeneratorHistoryScope): void {
    const scope = parseScope(scopeInput);
    const coordinator = this.#coordinator(scope);
    coordinator.locked = true;
    coordinator.generation += 1;
  }

  /** Re-enable access after the caller has established a fresh unlocked UserKey context. */
  unlock(scopeInput: GeneratorHistoryScope): void {
    const scope = parseScope(scopeInput);
    const coordinator = this.#coordinator(scope);
    coordinator.locked = false;
    coordinator.generation += 1;
  }

  /** Logout/account removal: revoke immediately, then remove only this opaque account scope. */
  remove(scopeInput: GeneratorHistoryScope): Promise<boolean> {
    const scope = parseScope(scopeInput);
    const coordinator = this.#coordinator(scope);
    coordinator.locked = true;
    coordinator.generation += 1;
    return serialize(coordinator, async () => {
      const existing = await this.#store.get<unknown>(scope.storageKey);
      await this.#store.remove(scope.storageKey);
      coordinator.unavailable = false;
      return existing !== undefined;
    });
  }

  /**
   * Explicitly discard a corrupt current-schema record. A valid record is retained; any future outer
   * or encrypted schema is reported and retained so an older client can never destroy newer data.
   */
  recoverCorrupt(
    scopeInput: GeneratorHistoryScope,
    cryptoBoundary: GeneratorHistoryCrypto,
  ): Promise<boolean> {
    const scope = parseScope(scopeInput);
    const crypto = parseCrypto(cryptoBoundary);
    const coordinator = this.#coordinator(scope);
    const access = captureAccess(coordinator, scope.digest, true);
    return serialize(coordinator, async () => {
      assertAccess(coordinator, access, scope.digest);
      try {
        const loaded = await this.#load(scope, crypto, coordinator, access);
        if (!loaded.envelope) return false;
        coordinator.unavailable = false;
        return false;
      } catch (error) {
        assertAccess(coordinator, access, scope.digest);
        if (!(error instanceof GeneratorHistoryRepositoryError)
          || error.code !== 'corrupt_storage') throw error;
        await this.#store.remove(scope.storageKey);
        assertAccess(coordinator, access, scope.digest);
        coordinator.unavailable = false;
        return true;
      }
    });
  }

  async #load(
    scope: GeneratorHistoryScope,
    crypto: GeneratorHistoryCrypto,
    coordinator: SharedScopeCoordinator,
    access: AccessSnapshot,
  ): Promise<LoadedHistory> {
    const raw = await this.#store.get<unknown>(scope.storageKey);
    assertAccess(coordinator, access, scope.digest);
    if (raw === undefined) return { payload: emptyPayload(scope.digest) };

    const envelope = parseStoredEnvelope(raw, scope);
    let plaintext: Uint8Array | undefined;
    try {
      const decrypted = await crypto.decrypt(scope.digest, envelope.payload);
      if (!(decrypted instanceof Uint8Array)) throw new TypeError('Decrypted history must be bytes');
      plaintext = decrypted;
    } catch {
      assertAccess(coordinator, access, scope.digest);
      throw corruptStorage(scope.digest);
    }
    try {
      assertAccess(coordinator, access, scope.digest);
      return {
        envelope,
        payload: parsePayload(plaintext, scope.digest),
      };
    } finally {
      plaintext.fill(0);
    }
  }

  async #writeWithRollback(
    scope: GeneratorHistoryScope,
    previous: StoredGeneratorHistoryEnvelope | undefined,
    next: StoredGeneratorHistoryEnvelope,
    coordinator: SharedScopeCoordinator,
    access: AccessSnapshot,
  ): Promise<void> {
    let error: unknown;
    try {
      assertAccess(coordinator, access, scope.digest);
      await this.#store.set(scope.storageKey, next);
      assertAccess(coordinator, access, scope.digest);
      return;
    } catch (caught) {
      error = caught;
    }

    try {
      const current = await this.#store.get<unknown>(scope.storageKey);
      if (sameStoredEnvelope(current, next)) {
        if (previous) await this.#store.set(scope.storageKey, previous);
        else await this.#store.remove(scope.storageKey);
      } else if (!sameOptionalStoredEnvelope(current, previous)) {
        throw new Error('Generator history storage changed outside its shared FIFO');
      }
      const restored = await this.#store.get<unknown>(scope.storageKey);
      if (!sameOptionalStoredEnvelope(restored, previous)) {
        throw new Error('Generator history rollback could not be verified');
      }
    } catch {
      coordinator.unavailable = true;
      throw repositoryError(
        'rollback_failed',
        'Generator history became unavailable after a failed write',
        scope.digest,
      );
    }
    throw error;
  }

  async #clearWithRollback(
    scope: GeneratorHistoryScope,
    previous: StoredGeneratorHistoryEnvelope,
    coordinator: SharedScopeCoordinator,
    access: AccessSnapshot,
  ): Promise<void> {
    let error: unknown;
    try {
      assertAccess(coordinator, access, scope.digest);
      await this.#store.remove(scope.storageKey);
      assertAccess(coordinator, access, scope.digest);
      const cleared = await this.#store.get<unknown>(scope.storageKey);
      assertAccess(coordinator, access, scope.digest);
      if (cleared !== undefined) {
        throw new Error('Generator history storage changed outside its shared FIFO');
      }
      return;
    } catch (caught) {
      error = caught;
    }

    try {
      const current = await this.#store.get<unknown>(scope.storageKey);
      if (current === undefined) {
        await this.#store.set(scope.storageKey, previous);
      } else if (!sameStoredEnvelope(current, previous)) {
        throw new Error('Generator history storage changed outside its shared FIFO');
      }
      const restored = await this.#store.get<unknown>(scope.storageKey);
      if (!sameStoredEnvelope(restored, previous)) {
        throw new Error('Generator history clear rollback could not be verified');
      }
    } catch {
      coordinator.unavailable = true;
      throw repositoryError(
        'rollback_failed',
        'Generator history became unavailable after a failed clear',
        scope.digest,
      );
    }
    throw error;
  }

  #coordinator(scope: GeneratorHistoryScope): SharedScopeCoordinator {
    let byScope = COORDINATORS.get(this.#store as object);
    if (!byScope) {
      byScope = new Map();
      COORDINATORS.set(this.#store as object, byScope);
    }
    let coordinator = byScope.get(scope.storageKey);
    if (!coordinator) {
      coordinator = {
        tail: Promise.resolve(),
        generation: 0,
        locked: false,
        unavailable: false,
      };
      byScope.set(scope.storageKey, coordinator);
    }
    return coordinator;
  }

  #currentTime(): number {
    const value = this.#now();
    if (!isTimestamp(value)) {
      throw repositoryError('invalid_entry', 'Generator history clock is invalid');
    }
    return value;
  }
}

function parseTrackInput(
  input: GeneratorHistoryTrackInput,
  now: number,
  scopeDigest: string,
): GeneratorHistoryEntry {
  if (!isPlainRecord(input) || !hasExactDataKeys(input, ['type', 'value', ...(hasOwn(input, 'generatedAt') ? ['generatedAt'] : [])])) {
    throw repositoryError('invalid_entry', 'Generated credential metadata is invalid', scopeDigest);
  }
  const generatedAt = hasOwn(input, 'generatedAt') ? dataValue(input, 'generatedAt') : now;
  const type = dataValue(input, 'type');
  const value = dataValue(input, 'value');
  if (!isTimestamp(generatedAt) || !isGeneratorHistoryEntryType(type) || !isBoundedSecret(value)) {
    throw repositoryError('invalid_entry', 'Generated credential metadata is invalid', scopeDigest);
  }
  return Object.freeze({ generatedAt, type, value });
}

function createStoredEnvelope(
  scope: GeneratorHistoryScope,
  ciphertext: string,
): StoredGeneratorHistoryEnvelope {
  if (!isBoundedCiphertext(ciphertext)) {
    throw repositoryError('storage_capacity', 'Generator history ciphertext is invalid or too large', scope.digest);
  }
  const envelope = Object.freeze({
    schemaVersion: GENERATOR_HISTORY_SCHEMA_VERSION,
    scopeDigest: scope.digest,
    payload: ciphertext,
  });
  if (encodedStorageBytes(scope.storageKey, envelope) > MAX_GENERATOR_HISTORY_STORAGE_BYTES) {
    throw repositoryError('storage_capacity', 'Generator history envelope is too large', scope.digest);
  }
  return envelope;
}

function parseStoredEnvelope(
  input: unknown,
  scope: GeneratorHistoryScope,
): StoredGeneratorHistoryEnvelope {
  if (!isPlainRecord(input)) throw corruptStorage(scope.digest);
  const schemaVersion = ownData(input, 'schemaVersion');
  if (isFutureSchema(schemaVersion)) throw unsupportedSchema(scope.digest);
  if (schemaVersion !== GENERATOR_HISTORY_SCHEMA_VERSION
    || !hasExactDataKeys(input, ['schemaVersion', 'scopeDigest', 'payload'])) {
    throw corruptStorage(scope.digest);
  }
  const scopeDigest = dataValue(input, 'scopeDigest');
  const payload = dataValue(input, 'payload');
  if (scopeDigest !== scope.digest || !isBoundedCiphertext(payload)) {
    throw corruptStorage(scope.digest);
  }
  const envelope = Object.freeze({ schemaVersion, scopeDigest, payload });
  if (encodedStorageBytes(scope.storageKey, envelope) > MAX_GENERATOR_HISTORY_STORAGE_BYTES) {
    throw corruptStorage(scope.digest);
  }
  return envelope;
}

function parsePayload(bytes: Uint8Array, scopeDigest: string): GeneratorHistoryPayload {
  if (!(bytes instanceof Uint8Array)
    || bytes.byteLength < GENERATOR_HISTORY_PADDING_FRAME_BYTES
    || bytes.byteLength > MAX_GENERATOR_HISTORY_PACKED_BYTES
    || bytes.byteLength % GENERATOR_HISTORY_PADDING_FRAME_BYTES !== 0) {
    throw corruptStorage(scopeDigest);
  }
  const serialized = unpackPayload(bytes, scopeDigest);
  let text: string;
  let input: unknown;
  try {
    text = STRICT_UTF8_DECODER.decode(serialized);
    input = JSON.parse(text) as unknown;
  } catch {
    throw corruptStorage(scopeDigest);
  }
  if (!isPlainRecord(input)) throw corruptStorage(scopeDigest);
  const schemaVersion = ownData(input, 'schemaVersion');
  if (isFutureSchema(schemaVersion)) throw unsupportedSchema(scopeDigest);
  if (schemaVersion !== GENERATOR_HISTORY_SCHEMA_VERSION
    || !hasExactDataKeys(input, ['schemaVersion', 'scopeDigest', 'entries'])
    || dataValue(input, 'scopeDigest') !== scopeDigest) {
    throw corruptStorage(scopeDigest);
  }
  const rawEntries = dataValue(input, 'entries');
  if (!Array.isArray(rawEntries)
    || !hasDenseArrayShape(rawEntries)
    || rawEntries.length > MAX_GENERATOR_HISTORY_ENTRIES) {
    throw corruptStorage(scopeDigest);
  }
  const entries: GeneratorHistoryEntry[] = [];
  const values = new Set<string>();
  for (const rawEntry of rawEntries) {
    const entry = parseStoredEntry(rawEntry, scopeDigest);
    if (values.has(entry.value)) throw corruptStorage(scopeDigest);
    values.add(entry.value);
    entries.push(entry);
  }
  const payload = Object.freeze({
    schemaVersion: GENERATOR_HISTORY_SCHEMA_VERSION,
    scopeDigest,
    entries: Object.freeze(entries),
  });
  if (JSON.stringify(payload) !== text) throw corruptStorage(scopeDigest);
  return payload;
}

function parseStoredEntry(input: unknown, scopeDigest: string): GeneratorHistoryEntry {
  if (!isPlainRecord(input)
    || !hasExactDataKeys(input, ['generatedAt', 'type', 'value'])) {
    throw corruptStorage(scopeDigest);
  }
  const generatedAt = dataValue(input, 'generatedAt');
  const type = dataValue(input, 'type');
  const value = dataValue(input, 'value');
  if (!isTimestamp(generatedAt) || !isGeneratorHistoryEntryType(type) || !isBoundedSecret(value)) {
    throw corruptStorage(scopeDigest);
  }
  return Object.freeze({ generatedAt, type, value });
}

function encodePayload(scopeDigest: string, entries: readonly GeneratorHistoryEntry[]): Uint8Array {
  return ENCODER.encode(JSON.stringify({
    schemaVersion: GENERATOR_HISTORY_SCHEMA_VERSION,
    scopeDigest,
    entries,
  }));
}

function packPayload(serialized: Uint8Array, scopeDigest: string): Uint8Array {
  if (serialized.byteLength === 0 || serialized.byteLength > MAX_GENERATOR_HISTORY_PAYLOAD_UTF8_BYTES) {
    throw repositoryError('storage_capacity', 'Generator history payload is too large', scopeDigest);
  }
  const packedLength = Math.ceil(
    (serialized.byteLength + 4) / GENERATOR_HISTORY_PADDING_FRAME_BYTES,
  ) * GENERATOR_HISTORY_PADDING_FRAME_BYTES;
  if (packedLength > MAX_GENERATOR_HISTORY_PACKED_BYTES) {
    throw repositoryError('storage_capacity', 'Generator history payload is too large', scopeDigest);
  }
  const packed = new Uint8Array(packedLength);
  new DataView(packed.buffer).setUint32(0, serialized.byteLength, false);
  packed.set(serialized, 4);
  return packed;
}

function unpackPayload(packed: Uint8Array, scopeDigest: string): Uint8Array {
  const length = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  ).getUint32(0, false);
  if (length === 0
    || length > MAX_GENERATOR_HISTORY_PAYLOAD_UTF8_BYTES
    || length + 4 > packed.byteLength) throw corruptStorage(scopeDigest);
  for (let index = length + 4; index < packed.byteLength; index += 1) {
    if (packed[index] !== 0) throw corruptStorage(scopeDigest);
  }
  return packed.subarray(4, length + 4);
}

function emptyPayload(scopeDigest: string): GeneratorHistoryPayload {
  return Object.freeze({
    schemaVersion: GENERATOR_HISTORY_SCHEMA_VERSION,
    scopeDigest,
    entries: Object.freeze([]),
  });
}

function publicEntries(entries: readonly GeneratorHistoryEntry[]): readonly GeneratorHistoryEntry[] {
  return Object.freeze(entries.map((entry) => Object.freeze({ ...entry })));
}

function captureAccess(
  coordinator: SharedScopeCoordinator,
  scopeDigest: string,
  allowUnavailable = false,
): AccessSnapshot {
  if (coordinator.locked) throw repositoryError('scope_locked', 'Generator history is locked', scopeDigest);
  if (coordinator.unavailable && !allowUnavailable) {
    throw repositoryError('scope_unavailable', 'Generator history scope is unavailable', scopeDigest);
  }
  return Object.freeze({ generation: coordinator.generation, allowUnavailable });
}

function assertAccess(
  coordinator: SharedScopeCoordinator,
  access: AccessSnapshot,
  scopeDigest: string,
): void {
  if (coordinator.locked || coordinator.generation !== access.generation) {
    throw repositoryError('scope_locked', 'Generator history access changed during operation', scopeDigest);
  }
  if (coordinator.unavailable && !access.allowUnavailable) {
    throw repositoryError('scope_unavailable', 'Generator history scope is unavailable', scopeDigest);
  }
}

function serialize<Result>(
  coordinator: SharedScopeCoordinator,
  operation: () => Promise<Result>,
): Promise<Result> {
  const result = coordinator.tail.then(operation, operation);
  coordinator.tail = result.then(() => undefined, () => undefined);
  return result;
}

function parseScope(input: GeneratorHistoryScope): GeneratorHistoryScope {
  if (!isPlainRecord(input)
    || !hasExactDataKeys(input, ['digest', 'storageKey'])) throw new TypeError('Generator history scope is invalid');
  const digest = dataValue(input, 'digest');
  const storageKey = dataValue(input, 'storageKey');
  if (typeof digest !== 'string'
    || !SCOPE_DIGEST_PATTERN.test(digest)
    || storageKey !== `${GENERATOR_HISTORY_STORAGE_PREFIX}${digest}`) {
    throw new TypeError('Generator history scope is invalid');
  }
  return Object.freeze({ digest, storageKey });
}

function parseCrypto(input: GeneratorHistoryCrypto): GeneratorHistoryCrypto {
  if (!input || !isFunction(input.encrypt) || !isFunction(input.decrypt)) {
    throw new TypeError('Generator history crypto boundary is invalid');
  }
  return input;
}

function canonicalAccountId(input: string): string {
  if (typeof input !== 'string') throw new TypeError('Generator history account id is invalid');
  const value = input.trim().toLowerCase();
  if (!UUID_PATTERN.test(value)) throw new TypeError('Generator history account id is invalid');
  return value;
}

function writeLengthPrefixed(
  target: Uint8Array,
  view: DataView,
  offset: number,
  value: Uint8Array,
): number {
  view.setUint32(offset, value.byteLength, false);
  target.set(value, offset + 4);
  return offset + 4 + value.byteLength;
}

function isTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= MAX_TIMESTAMP;
}

function isBoundedSecret(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || containsControlCharacter(value)) return false;
  const bytes = ENCODER.encode(value);
  try {
    return bytes.byteLength <= MAX_GENERATOR_HISTORY_VALUE_UTF8_BYTES
      && STRICT_UTF8_DECODER.decode(bytes) === value;
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

function isBoundedCiphertext(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_GENERATOR_HISTORY_CIPHERTEXT_CHARS
    && value.trim() === value
    && !containsControlCharacter(value);
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function encodedStorageBytes(key: string, value: unknown): number {
  const bytes = ENCODER.encode(JSON.stringify({ [key]: value }));
  try {
    return bytes.byteLength;
  } finally {
    bytes.fill(0);
  }
}

function isFutureSchema(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) > GENERATOR_HISTORY_SCHEMA_VERSION;
}

function sameOptionalStoredEnvelope(
  input: unknown,
  expected: StoredGeneratorHistoryEnvelope | undefined,
): boolean {
  return expected === undefined ? input === undefined : sameStoredEnvelope(input, expected);
}

function sameStoredEnvelope(input: unknown, expected: StoredGeneratorHistoryEnvelope): boolean {
  return isPlainRecord(input)
    && hasExactDataKeys(input, ['schemaVersion', 'scopeDigest', 'payload'])
    && ownData(input, 'schemaVersion') === expected.schemaVersion
    && ownData(input, 'scopeDigest') === expected.scopeDigest
    && ownData(input, 'payload') === expected.payload;
}

function repositoryError(
  code: GeneratorHistoryRepositoryErrorCode,
  message: string,
  scopeDigest?: string,
): GeneratorHistoryRepositoryError {
  return new GeneratorHistoryRepositoryError(code, message, scopeDigest);
}

function corruptStorage(scopeDigest: string): GeneratorHistoryRepositoryError {
  return repositoryError('corrupt_storage', 'Generator history storage is corrupt', scopeDigest);
}

function unsupportedSchema(scopeDigest: string): GeneratorHistoryRepositoryError {
  return repositoryError('unsupported_schema', 'Generator history uses an unsupported schema', scopeDigest);
}

function isFunction(value: unknown): value is (...args: never[]) => unknown {
  return typeof value === 'function';
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactDataKeys(record: object, expected: readonly string[]): boolean {
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
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return true;
}

function dataValue(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !('value' in descriptor)) throw new TypeError(`Missing data property: ${key}`);
  return descriptor.value;
}

function ownData(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function hasOwn(record: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}
