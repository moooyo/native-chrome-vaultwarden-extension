import { normalizeServerEnvironmentUrl } from '../api/server-capabilities.js';
import { normalizeSsoEmail } from './sso-login.js';
import type { KeyValueStore } from '../../platform/store.js';

export const SSO_REQUIRED_CACHE_KEY = 'ssoRequiredCache';
export const MAX_SSO_REQUIRED_CACHE_ENTRIES = 128;

const MAX_STORAGE_KEY_LENGTH = 256;

export interface SsoRequiredCacheEntry {
  readonly email: string;
  readonly webVaultUrl: string;
}

export interface SsoRequiredCacheOptions {
  readonly storageKey?: string;
  readonly maxEntries?: number;
}

interface OperationQueue {
  tail: Promise<void>;
}

type ParsedEntries =
  | { readonly kind: 'valid'; readonly entries: readonly SsoRequiredCacheEntry[]; readonly deduplicated: boolean }
  | { readonly kind: 'invalid' };

const OPERATION_QUEUES = new WeakMap<KeyValueStore, Map<string, OperationQueue>>();

/**
 * Device-local memory of exact account/Web Vault pairs that are subject to RequireSso. Callers
 * must supply the Web Vault URL projected from a trusted server environment document.
 */
export class SsoRequiredCache {
  readonly #storageKey: string;
  readonly #maxEntries: number;
  readonly #queue: OperationQueue;

  constructor(
    private readonly store: KeyValueStore,
    options: SsoRequiredCacheOptions = {},
  ) {
    this.#storageKey = canonicalStorageKey(options.storageKey ?? SSO_REQUIRED_CACHE_KEY);
    this.#maxEntries = boundedMaxEntries(options.maxEntries ?? MAX_SSO_REQUIRED_CACHE_ENTRIES);
    this.#queue = operationQueue(store, this.#storageKey);
  }

  list(): Promise<readonly SsoRequiredCacheEntry[]> {
    return this.#serialize(async () => freezeEntries(await this.#readEntries()));
  }

  has(input: SsoRequiredCacheEntry): Promise<boolean> {
    const entry = canonicalEntry(input);
    return this.#serialize(async () => (
      await this.#readEntries()
    ).some((candidate) => entriesMatch(candidate, entry)));
  }

  async add(input: SsoRequiredCacheEntry): Promise<void> {
    const entry = canonicalEntry(input);
    await this.#serialize(async () => {
      const entries = await this.#readEntries();
      if (entries.some((candidate) => entriesMatch(candidate, entry))) return;
      if (entries.length >= this.#maxEntries) {
        throw new RangeError(`SSO required cache cannot exceed ${this.#maxEntries} entries`);
      }
      await this.#writeEntries([...entries, entry]);
    });
  }

  async remove(input: SsoRequiredCacheEntry): Promise<void> {
    const entry = canonicalEntry(input);
    await this.#serialize(async () => {
      const entries = await this.#readEntries();
      const retained = entries.filter((candidate) => !entriesMatch(candidate, entry));
      if (retained.length === entries.length) return;
      await this.#writeEntries(retained);
    });
  }

  async reconcile(input: SsoRequiredCacheEntry, requireSso: boolean): Promise<void> {
    if (typeof requireSso !== 'boolean') throw new TypeError('requireSso must be a boolean');
    const entry = canonicalEntry(input);
    await this.#serialize(async () => {
      const entries = await this.#readEntries();
      const present = entries.some((candidate) => entriesMatch(candidate, entry));
      if (requireSso) {
        if (present) return;
        if (entries.length >= this.#maxEntries) {
          throw new RangeError(`SSO required cache cannot exceed ${this.#maxEntries} entries`);
        }
        await this.#writeEntries([...entries, entry]);
        return;
      }
      if (!present) return;
      await this.#writeEntries(entries.filter((candidate) => !entriesMatch(candidate, entry)));
    });
  }

  async clear(): Promise<void> {
    await this.#serialize(() => this.store.remove(this.#storageKey));
  }

  async #readEntries(): Promise<readonly SsoRequiredCacheEntry[]> {
    const stored = await this.store.get<unknown>(this.#storageKey);
    if (stored === undefined) return [];
    const parsed = parseEntries(stored, this.#maxEntries);
    if (parsed.kind === 'invalid') {
      await this.store.remove(this.#storageKey);
      return [];
    }
    if (parsed.deduplicated) await this.#writeEntries(parsed.entries);
    return parsed.entries;
  }

  async #writeEntries(entries: readonly SsoRequiredCacheEntry[]): Promise<void> {
    await this.store.set(this.#storageKey, entries.map((entry) => ({
      email: entry.email,
      webVaultUrl: entry.webVaultUrl,
    })));
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#queue.tail.then(operation, operation);
    this.#queue.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

function parseEntries(value: unknown, maxEntries: number): ParsedEntries {
  if (!Array.isArray(value) || value.length > maxEntries) return { kind: 'invalid' };
  const entries: SsoRequiredCacheEntry[] = [];
  let deduplicated = false;
  for (const candidate of value) {
    if (!isExactEntryRecord(candidate)) return { kind: 'invalid' };
    let entry: SsoRequiredCacheEntry;
    try {
      entry = canonicalEntry({
        email: ownDataProperty(candidate, 'email'),
        webVaultUrl: ownDataProperty(candidate, 'webVaultUrl'),
      });
    } catch {
      return { kind: 'invalid' };
    }
    if (entry.email !== ownDataProperty(candidate, 'email')
      || entry.webVaultUrl !== ownDataProperty(candidate, 'webVaultUrl')) {
      return { kind: 'invalid' };
    }
    if (entries.some((existing) => entriesMatch(existing, entry))) {
      deduplicated = true;
      continue;
    }
    entries.push(entry);
  }
  return { kind: 'valid', entries, deduplicated };
}

function canonicalEntry(input: unknown): SsoRequiredCacheEntry {
  if (!isPlainRecord(input)) throw new TypeError('SSO required cache entry must be a plain object');
  const emailValue = ownDataProperty(input, 'email');
  const webVaultUrlValue = ownDataProperty(input, 'webVaultUrl');
  if (typeof emailValue !== 'string' || typeof webVaultUrlValue !== 'string') {
    throw new TypeError('SSO required cache entry fields must be strings');
  }
  const email = normalizeSsoEmail(emailValue);
  const webVaultUrl = normalizeServerEnvironmentUrl(webVaultUrlValue);
  if (!webVaultUrl) {
    throw new TypeError('webVaultUrl must be a trusted HTTP(S) server environment URL');
  }
  return Object.freeze({ email, webVaultUrl });
}

function isExactEntryRecord(value: unknown): value is Record<string, unknown> {
  if (!isPlainRecord(value)) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 2 || !keys.includes('email') || !keys.includes('webVaultUrl')) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === 'string'
      && descriptor !== undefined
      && descriptor.enumerable
      && 'value' in descriptor;
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function ownDataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function entriesMatch(left: SsoRequiredCacheEntry, right: SsoRequiredCacheEntry): boolean {
  return left.email === right.email && left.webVaultUrl === right.webVaultUrl;
}

function freezeEntries(entries: readonly SsoRequiredCacheEntry[]): readonly SsoRequiredCacheEntry[] {
  return Object.freeze(entries.map((entry) => Object.freeze({ ...entry })));
}

function hasAsciiControlOrSpace(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

function canonicalStorageKey(value: string): string {
  if (
    typeof value !== 'string'
    || !value
    || value.length > MAX_STORAGE_KEY_LENGTH
    || value.trim() !== value
    || hasAsciiControlOrSpace(value)
  ) throw new TypeError('storageKey must be a bounded canonical string');
  return value;
}

function boundedMaxEntries(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_SSO_REQUIRED_CACHE_ENTRIES) {
    throw new RangeError(
      `maxEntries must be between 1 and ${MAX_SSO_REQUIRED_CACHE_ENTRIES}`,
    );
  }
  return value;
}

function operationQueue(store: KeyValueStore, storageKey: string): OperationQueue {
  let stores = OPERATION_QUEUES.get(store);
  if (!stores) {
    stores = new Map();
    OPERATION_QUEUES.set(store, stores);
  }
  let queue = stores.get(storageKey);
  if (!queue) {
    queue = { tail: Promise.resolve() };
    stores.set(storageKey, queue);
  }
  return queue;
}
