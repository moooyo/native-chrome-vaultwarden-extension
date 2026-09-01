import type { KeyValueStore } from '../platform/store.js';

export const DEFAULT_PAGE_LOAD_CLAIM_TTL_MS = 60_000;
export const DEFAULT_PAGE_LOAD_CLAIM_CAPACITY = 1_024;
export const MAX_PAGE_LOAD_CLAIM_TTL_MS = 300_000;
export const MAX_PAGE_LOAD_CLAIM_CAPACITY = 4_096;
const MAX_PAGE_LOAD_FRAME_URL_LENGTH = 8_192;
const MAX_PERSISTED_CLAIM_KEY_LENGTH = 4_128;
const FNV64_OFFSET_BASIS = 0xcbf29ce484222325n;
const FNV64_PRIME = 0x100000001b3n;

export interface PageLoadFillClaim {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly frameUrl: string;
}

export interface PageLoadFillDeduperOptions {
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly store?: KeyValueStore;
}

interface StoredClaim {
  readonly expiresAt: number;
}

interface PersistedClaim extends StoredClaim {
  readonly key: string;
}

const STORAGE_KEY = 'autofill.pageLoadClaims';

/**
 * Short-lived browser-document-and-URL replay protection for automatic page-load fills. Content
 * enforces one attempt per exact SPA URL; this worker-side fence also covers duplicate injections and
 * concurrent messages before either caller receives a response.
 */
export class PageLoadFillDeduper {
  readonly #claims = new Map<string, StoredClaim>();
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #store: KeyValueStore | undefined;
  #persistentTail = Promise.resolve();

  constructor(options: PageLoadFillDeduperOptions = {}) {
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_PAGE_LOAD_CLAIM_TTL_MS,
      MAX_PAGE_LOAD_CLAIM_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_PAGE_LOAD_CLAIM_CAPACITY,
      MAX_PAGE_LOAD_CLAIM_CAPACITY,
      'maxEntries',
    );
    this.#now = options.now ?? Date.now;
    this.#store = options.store;
  }

  /** Atomically claim one exact document URL. Invalid, duplicate, or exhausted claims fail closed. */
  claim(context: PageLoadFillClaim): boolean {
    if (!isValidContext(context)) return false;
    const now = this.#now();
    if (!Number.isFinite(now) || now < 0) return false;
    this.#prune(now);
    const key = claimKey(context);
    if (this.#claims.has(key) || this.#claims.size >= this.#maxEntries) return false;
    const expiresAt = safeExpiry(now, this.#ttlMs);
    if (expiresAt === undefined) return false;
    this.#claims.set(key, Object.freeze({ expiresAt }));
    return true;
  }

  /** Persist the claimed document so a service-worker restart cannot immediately fill it again. */
  async persist(context: PageLoadFillClaim): Promise<boolean> {
    if (!this.#store || !isValidContext(context)) return this.#store === undefined;
    let allowed = false;
    const operation = async (): Promise<void> => {
      const now = this.#now();
      if (!Number.isFinite(now) || now < 0) return;
      const raw = await this.#store!.get<unknown>(STORAGE_KEY);
      const claims = sanitizePersistedClaims(raw, now, this.#maxEntries);
      if (!claims) return;
      const key = claimKey(context);
      const legacyKey = legacyClaimKey(context);
      if (claims.some((claim) => claim.key === key || claim.key === legacyKey)
          || claims.length >= this.#maxEntries) return;
      const expiresAt = safeExpiry(now, this.#ttlMs);
      if (expiresAt === undefined) return;
      await this.#store!.set(STORAGE_KEY, [...claims, { key, expiresAt }]);
      allowed = true;
    };
    const run = this.#persistentTail.then(operation, operation);
    this.#persistentTail = run.then(() => undefined, () => undefined);
    try { await run; } catch { return false; }
    return allowed;
  }

  #prune(now: number): void {
    for (const [key, claim] of this.#claims) {
      if (claim.expiresAt <= now) this.#claims.delete(key);
    }
  }
}

function claimKey(context: PageLoadFillClaim): string {
  return `v2:${context.tabId}:${context.frameId}:${hashClaimComponent(context.documentId)}:${hashClaimComponent(context.frameUrl)}`;
}

function legacyClaimKey(context: PageLoadFillClaim): string {
  return `${context.tabId}:${context.frameId}:${context.documentId.length}:${context.documentId}`;
}

/** A collision only suppresses an additional fill opportunity, so this compact non-secret key fails
 * closed while keeping the persistent replay directory well below storage quotas. */
function hashClaimComponent(value: string): string {
  let hash = FNV64_OFFSET_BASIS;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= BigInt(value.charCodeAt(index));
    hash = BigInt.asUintN(64, hash * FNV64_PRIME);
  }
  return hash.toString(16).padStart(16, '0');
}

function sanitizePersistedClaims(value: unknown, now: number, maxEntries: number): PersistedClaim[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maxEntries) return undefined;
  const claims: PersistedClaim[] = [];
  for (const entry of value) {
    if (
      typeof entry !== 'object'
      || entry === null
      || typeof (entry as { key?: unknown }).key !== 'string'
      || (entry as { key: string }).key.length > MAX_PERSISTED_CLAIM_KEY_LENGTH
      || typeof (entry as { expiresAt?: unknown }).expiresAt !== 'number'
      || !Number.isSafeInteger((entry as { expiresAt: number }).expiresAt)
    ) return undefined;
    const claim = entry as PersistedClaim;
    if (claim.expiresAt > now) claims.push({ key: claim.key, expiresAt: claim.expiresAt });
  }
  return claims;
}

function isValidContext(context: PageLoadFillClaim): boolean {
  return Number.isSafeInteger(context?.tabId)
    && context.tabId >= 0
    && Number.isSafeInteger(context.frameId)
    && context.frameId >= 0
    && typeof context.documentId === 'string'
    && context.documentId.length > 0
    && context.documentId.length <= 4_096
    && context.documentId.trim() === context.documentId
    && typeof context.frameUrl === 'string'
    && context.frameUrl.length > 0
    && context.frameUrl.length <= MAX_PAGE_LOAD_FRAME_URL_LENGTH
    && context.frameUrl.trim() === context.frameUrl
    && isHttpUrl(context.frameUrl)
    && !hasControlCharacter(context.frameUrl);
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') && url.href === value;
  } catch {
    return false;
  }
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function safeExpiry(now: number, ttlMs: number): number | undefined {
  const expiresAt = now + ttlMs;
  return Number.isSafeInteger(expiresAt) && expiresAt > now ? expiresAt : undefined;
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new Error(`${name} must be a positive integer no greater than ${maximum}`);
  }
  return value;
}
