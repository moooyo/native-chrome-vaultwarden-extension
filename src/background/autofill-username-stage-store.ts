import { bytesToBase64, bytesToUtf8, base64ToBytes, utf8ToBytes } from '../core/crypto/encoding.js';
import { serializeSymmetricKey, type SymmetricKey } from '../core/crypto/keys.js';
import { hkdfExpandSha256 } from '../core/crypto/primitives.js';
import type { KeyValueStore } from '../platform/store.js';

export const AUTOFILL_USERNAME_STAGE_KEY = 'autofillUsernameStages';
export const DEFAULT_AUTOFILL_USERNAME_STAGE_TTL_MS = 5 * 60_000;
export const DEFAULT_AUTOFILL_USERNAME_STAGE_CAPACITY = 64;

const MAX_TTL_MS = 15 * 60_000;
const MAX_CAPACITY = 128;
const MAX_USERNAME_LENGTH = 4_096;
const MAX_IDENTITY_LENGTH = 4_096;
/** Leave almost all of Chrome's shared storage.session quota to passkey and device-login state. */
export const AUTOFILL_USERNAME_STAGE_ENVELOPE_MAX_UTF8_BYTES = 256 * 1024;
const MAX_CIPHERTEXT_BYTES = 16 * 1024;
const AES_GCM_IV_BYTES = 12;
const KEY_INFO = 'miyu/autofill/username-stage/v4';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export interface AutofillUsernameStageBinding {
  readonly sessionGeneration: number;
  readonly sessionBindingId: string;
  readonly serverGeneration: number;
  readonly accountGeneration: number;
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly policyGeneration: number;
  readonly enterprisePolicyGeneration: number;
  readonly enterprisePolicyRawGeneration: string;
}

export interface AutofillUsernameStageContext extends AutofillUsernameStageBinding {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly origin: string;
}

export interface AutofillUsernameStageInput extends AutofillUsernameStageContext {
  readonly username: string;
}

export interface AutofillUsernameStageStoreOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  /** Returns an owned key copy. The store zeroes both halves after deriving its storage key. */
  readonly loadUserKey: () => Promise<SymmetricKey | undefined>;
  readonly now?: () => number;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
}

interface StoredUsernameStage extends AutofillUsernameStageContext {
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly iv: string;
  readonly ciphertext: string;
}

interface UsernameStageEnvelope {
  readonly schemaVersion: 4;
  readonly revision: number;
  readonly entries: readonly StoredUsernameStage[];
}

/** Short-lived, one-shot username continuity for multi-page login flows. The username is encrypted
 * in storage.session and authenticated against its exact browser and security-generation context. */
export class AutofillUsernameStageStore {
  readonly #store: AutofillUsernameStageStoreOptions['store'];
  readonly #loadUserKey: AutofillUsernameStageStoreOptions['loadUserKey'];
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  #tail: Promise<void> = Promise.resolve();

  constructor(options: AutofillUsernameStageStoreOptions) {
    if (!options?.store || typeof options.loadUserKey !== 'function') {
      throw new TypeError('A session store and UserKey loader are required');
    }
    this.#store = options.store;
    this.#loadUserKey = options.loadUserKey;
    this.#now = options.now ?? Date.now;
    this.#ttlMs = boundedPositiveInteger(options.ttlMs ?? DEFAULT_AUTOFILL_USERNAME_STAGE_TTL_MS, MAX_TTL_MS, 'ttlMs');
    this.#maxEntries = boundedPositiveInteger(options.maxEntries ?? DEFAULT_AUTOFILL_USERNAME_STAGE_CAPACITY, MAX_CAPACITY, 'maxEntries');
  }

  async stage(input: AutofillUsernameStageInput): Promise<void> {
    const canonical = canonicalizeStage(input);
    await this.#serialize(async () => {
      const now = this.#readClock();
      const expiresAt = now + this.#ttlMs;
      if (!Number.isSafeInteger(expiresAt)) throw new Error('Username stage expiry is invalid');
      const metadata = Object.freeze({ ...canonical.context, createdAt: now, expiresAt });
      const sealed = await sealText(canonical.username, metadata, this.#loadUserKey);
      const current = await this.#read(now);
      const next = current.entries.filter((entry) => contextKey(entry) !== contextKey(metadata));
      next.push(Object.freeze({ ...metadata, ...sealed }));
      if (next.length > this.#maxEntries) next.splice(0, next.length - this.#maxEntries);
      await this.#write(next, nextRevision(current.revision));
    });
  }

  async consume(context: AutofillUsernameStageContext): Promise<string | undefined> {
    const canonical = canonicalizeContext(context);
    return await this.#serialize(async () => {
      const current = await this.#read(this.#readClock());
      const index = current.entries.findIndex((entry) => sameBrowserContext(entry, canonical));
      if (index < 0) {
        await this.#write(current.entries, nextRevision(current.revision));
        return undefined;
      }
      const [entry] = current.entries.splice(index, 1);
      await this.#write(current.entries, nextRevision(current.revision));
      if (!entry || !sameSecurityBinding(entry, canonical)) return undefined;
      try {
        const username = await openText(entry, entry, this.#loadUserKey);
        return validUsername(username) ? username : undefined;
      } catch {
        return undefined;
      }
    });
  }

  async clearTab(tabId: number): Promise<void> {
    const canonicalTabId = boundedNonNegativeInteger(tabId, 'tabId');
    await this.#serialize(async () => {
      const current = await this.#read(this.#readClock());
      await this.#write(
        current.entries.filter((entry) => entry.tabId !== canonicalTabId),
        nextRevision(current.revision),
      );
    });
  }

  async clearRuntime(
    tabId: number,
    frameId: number,
    documentId: string,
    runtimeIncarnation: string,
  ): Promise<void> {
    const expected = {
      tabId: boundedNonNegativeInteger(tabId, 'tabId'),
      frameId: boundedNonNegativeInteger(frameId, 'frameId'),
      documentId: boundedIdentity(documentId, 'documentId'),
      runtimeIncarnation: runtimeId(runtimeIncarnation),
    };
    await this.#serialize(async () => {
      const current = await this.#read(this.#readClock());
      await this.#write(current.entries.filter((entry) => !(
        entry.tabId === expected.tabId
        && entry.frameId === expected.frameId
        && entry.documentId === expected.documentId
        && entry.runtimeIncarnation === expected.runtimeIncarnation
      )), nextRevision(current.revision));
    });
  }

  async clear(): Promise<void> {
    await this.#serialize(() => this.#store.remove(AUTOFILL_USERNAME_STAGE_KEY));
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  #readClock(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('Username stage clock is invalid');
    return now;
  }

  async #read(now: number): Promise<{ revision: number; entries: StoredUsernameStage[] }> {
    const stored = await this.#store.get<unknown>(AUTOFILL_USERNAME_STAGE_KEY);
    if (stored === undefined) return { revision: 0, entries: [] };
    const parsed = parseEnvelope(stored);
    if (!parsed) {
      await this.#store.remove(AUTOFILL_USERNAME_STAGE_KEY);
      return { revision: 0, entries: [] };
    }
    return { revision: parsed.revision, entries: parsed.entries.filter((entry) => entry.expiresAt > now) };
  }

  async #write(entries: readonly StoredUsernameStage[], revision: number): Promise<void> {
    if (entries.length === 0) {
      await this.#store.remove(AUTOFILL_USERNAME_STAGE_KEY);
      return;
    }
    const envelope: UsernameStageEnvelope = Object.freeze({
      schemaVersion: 4,
      revision,
      entries: Object.freeze([...entries]),
    });
    if (utf8ToBytes(JSON.stringify(envelope)).byteLength > AUTOFILL_USERNAME_STAGE_ENVELOPE_MAX_UTF8_BYTES) {
      throw new Error('Username stage storage budget exceeded');
    }
    await this.#store.set(AUTOFILL_USERNAME_STAGE_KEY, envelope);
  }
}

function parseEnvelope(value: unknown): UsernameStageEnvelope | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ['schemaVersion', 'revision', 'entries'])) return undefined;
  if (value.schemaVersion !== 4 || !Number.isSafeInteger(value.revision) || (value.revision as number) < 0
      || !Array.isArray(value.entries) || value.entries.length > MAX_CAPACITY) return undefined;
  if (utf8ToBytes(JSON.stringify(value)).byteLength > AUTOFILL_USERNAME_STAGE_ENVELOPE_MAX_UTF8_BYTES) return undefined;
  const entries: StoredUsernameStage[] = [];
  const keys = new Set<string>();
  for (const candidate of value.entries) {
    if (!isRecord(candidate) || !hasOnlyKeys(candidate, [
      'tabId', 'frameId', 'documentId', 'runtimeIncarnation', 'origin', 'sessionGeneration', 'sessionBindingId', 'serverGeneration',
      'accountGeneration', 'serverUrl', 'accountIdentity', 'policyGeneration',
      'enterprisePolicyGeneration', 'enterprisePolicyRawGeneration', 'createdAt', 'expiresAt',
      'iv', 'ciphertext',
    ])) return undefined;
    try {
      const context = canonicalizeContext(candidate as unknown as AutofillUsernameStageContext);
      const createdAt = boundedNonNegativeInteger(candidate.createdAt, 'createdAt');
      const expiresAt = boundedNonNegativeInteger(candidate.expiresAt, 'expiresAt');
      if (expiresAt <= createdAt) return undefined;
      const iv = canonicalBase64(candidate.iv, AES_GCM_IV_BYTES, AES_GCM_IV_BYTES, 'iv');
      const ciphertext = canonicalBase64(candidate.ciphertext, 17, MAX_CIPHERTEXT_BYTES, 'ciphertext');
      const entry = Object.freeze({ ...context, createdAt, expiresAt, iv, ciphertext });
      const key = contextKey(entry);
      if (keys.has(key)) return undefined;
      keys.add(key);
      entries.push(entry);
    } catch {
      return undefined;
    }
  }
  return Object.freeze({ schemaVersion: 4, revision: value.revision as number, entries: Object.freeze(entries) });
}

async function sealText(
  value: string,
  metadata: Omit<StoredUsernameStage, 'iv' | 'ciphertext'>,
  loadUserKey: () => Promise<SymmetricKey | undefined>,
): Promise<Pick<StoredUsernameStage, 'iv' | 'ciphertext'>> {
  const plaintext = new Uint8Array(utf8ToBytes(value));
  const aad = new Uint8Array(utf8ToBytes(stageAad(metadata)));
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  try {
    const ciphertext = await withStorageKey(loadUserKey, async (key) => new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext),
    ));
    try {
      return Object.freeze({ iv: bytesToBase64(iv), ciphertext: bytesToBase64(ciphertext) });
    } finally {
      ciphertext.fill(0);
    }
  } finally {
    plaintext.fill(0);
    aad.fill(0);
    iv.fill(0);
  }
}

async function openText(
  sealed: Pick<StoredUsernameStage, 'iv' | 'ciphertext'>,
  metadata: Omit<StoredUsernameStage, 'iv' | 'ciphertext'>,
  loadUserKey: () => Promise<SymmetricKey | undefined>,
): Promise<string> {
  const iv = new Uint8Array(base64ToBytes(sealed.iv));
  const ciphertext = new Uint8Array(base64ToBytes(sealed.ciphertext));
  const aad = new Uint8Array(utf8ToBytes(stageAad(metadata)));
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = await withStorageKey(loadUserKey, async (key) => new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext),
    ));
    return bytesToUtf8(plaintext);
  } finally {
    iv.fill(0);
    ciphertext.fill(0);
    aad.fill(0);
    plaintext?.fill(0);
  }
}

async function withStorageKey<T>(
  loadUserKey: () => Promise<SymmetricKey | undefined>,
  operation: (key: CryptoKey) => Promise<T>,
): Promise<T> {
  const userKey = await loadUserKey();
  if (!userKey) throw new Error('Vault is locked');
  let raw: Uint8Array | undefined;
  let derived: Uint8Array<ArrayBuffer> | undefined;
  try {
    raw = serializeSymmetricKey(userKey);
    derived = new Uint8Array(await hkdfExpandSha256(raw, KEY_INFO, 32));
    const key = await crypto.subtle.importKey('raw', derived, 'AES-GCM', false, ['encrypt', 'decrypt']);
    return await operation(key);
  } finally {
    raw?.fill(0);
    derived?.fill(0);
    userKey.encKey.fill(0);
    userKey.macKey.fill(0);
  }
}

function stageAad(value: Omit<StoredUsernameStage, 'iv' | 'ciphertext'>): string {
  return JSON.stringify([
    'username-stage-v4', value.tabId, value.frameId, value.documentId, value.runtimeIncarnation,
    value.origin, value.sessionGeneration,
    value.sessionBindingId, value.serverGeneration, value.accountGeneration, value.serverUrl,
    value.accountIdentity, value.policyGeneration, value.enterprisePolicyGeneration,
    value.enterprisePolicyRawGeneration, value.createdAt, value.expiresAt,
  ]);
}

function canonicalizeStage(input: AutofillUsernameStageInput): {
  readonly context: AutofillUsernameStageContext;
  readonly username: string;
} {
  const context = canonicalizeContext(input);
  if (typeof input.username !== 'string') throw new TypeError('username is invalid');
  const username = input.username.trim();
  if (!validUsername(username)) throw new TypeError('username is invalid');
  return Object.freeze({ context, username });
}

function validUsername(value: string): boolean {
  return value.length > 0 && value.length <= MAX_USERNAME_LENGTH && value.trim() === value;
}

function canonicalizeContext(input: AutofillUsernameStageContext): AutofillUsernameStageContext {
  if (!isRecord(input)) throw new TypeError('Username stage context is invalid');
  return Object.freeze({
    tabId: boundedNonNegativeInteger(input.tabId, 'tabId'),
    frameId: boundedNonNegativeInteger(input.frameId, 'frameId'),
    documentId: boundedIdentity(input.documentId, 'documentId'),
    runtimeIncarnation: runtimeId(input.runtimeIncarnation),
    origin: canonicalOrigin(input.origin),
    sessionGeneration: boundedNonNegativeInteger(input.sessionGeneration, 'sessionGeneration'),
    sessionBindingId: boundedIdentity(input.sessionBindingId, 'sessionBindingId'),
    serverGeneration: boundedNonNegativeInteger(input.serverGeneration, 'serverGeneration'),
    accountGeneration: boundedNonNegativeInteger(input.accountGeneration, 'accountGeneration'),
    serverUrl: canonicalServerUrl(input.serverUrl),
    accountIdentity: boundedIdentity(input.accountIdentity, 'accountIdentity'),
    policyGeneration: boundedNonNegativeInteger(input.policyGeneration, 'policyGeneration'),
    enterprisePolicyGeneration: boundedNonNegativeInteger(
      input.enterprisePolicyGeneration,
      'enterprisePolicyGeneration',
    ),
    enterprisePolicyRawGeneration: boundedIdentity(
      input.enterprisePolicyRawGeneration,
      'enterprisePolicyRawGeneration',
    ),
  });
}

function canonicalOrigin(value: unknown): string {
  if (typeof value !== 'string' || value.length > MAX_IDENTITY_LENGTH) throw new TypeError('origin is invalid');
  const url = new URL(value);
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || value !== url.origin || url.username || url.password) {
    throw new TypeError('origin is invalid');
  }
  return url.origin;
}

function canonicalServerUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length > MAX_IDENTITY_LENGTH) throw new TypeError('serverUrl is invalid');
  const url = new URL(value);
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash || url.href !== value) {
    throw new TypeError('serverUrl is not canonical');
  }
  return value;
}

function boundedIdentity(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value || value.length > MAX_IDENTITY_LENGTH) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function sameBrowserContext(left: AutofillUsernameStageContext, right: AutofillUsernameStageContext): boolean {
  return left.tabId === right.tabId && left.frameId === right.frameId && left.origin === right.origin;
}

function sameSecurityBinding(left: AutofillUsernameStageBinding, right: AutofillUsernameStageBinding): boolean {
  return left.sessionGeneration === right.sessionGeneration
    && left.sessionBindingId === right.sessionBindingId
    && left.serverGeneration === right.serverGeneration
    && left.accountGeneration === right.accountGeneration
    && left.serverUrl === right.serverUrl
    && left.accountIdentity === right.accountIdentity
    && left.policyGeneration === right.policyGeneration
    && left.enterprisePolicyGeneration === right.enterprisePolicyGeneration
    && left.enterprisePolicyRawGeneration === right.enterprisePolicyRawGeneration;
}

function contextKey(value: Pick<AutofillUsernameStageContext, 'tabId' | 'frameId' | 'origin'>): string {
  return JSON.stringify([value.tabId, value.frameId, value.origin]);
}

function runtimeId(value: unknown): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) {
    throw new TypeError('runtimeIncarnation is invalid');
  }
  return value;
}

function canonicalBase64(value: unknown, minBytes: number, maxBytes: number, name: string): string {
  if (typeof value !== 'string' || !BASE64.test(value)) throw new TypeError(`${name} is invalid`);
  const bytes = base64ToBytes(value);
  try {
    if (bytes.byteLength < minBytes || bytes.byteLength > maxBytes || bytesToBase64(bytes) !== value) {
      throw new TypeError(`${name} is invalid`);
    }
    return value;
  } finally {
    bytes.fill(0);
  }
}

function nextRevision(revision: number): number {
  if (!Number.isSafeInteger(revision) || revision < 0 || revision === Number.MAX_SAFE_INTEGER) {
    throw new Error('Username stage revision is exhausted');
  }
  return revision + 1;
}

function boundedPositiveInteger(value: unknown, maximum: number, name: string): number {
  const parsed = boundedNonNegativeInteger(value, name);
  if (parsed === 0 || parsed > maximum) throw new TypeError(`${name} is invalid`);
  return parsed;
}

function boundedNonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`${name} is invalid`);
  return value as number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(record).every((key) => allowed.has(key)) && keys.every((key) => key in record);
}
