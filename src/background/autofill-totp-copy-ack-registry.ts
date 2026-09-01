import { isContentTotpClipboardCode } from '../messaging/totp-clipboard-code.js';

export const AUTOFILL_TOTP_COPY_ACK_TTL_MS = 30_000;
export const MAX_AUTOFILL_TOTP_COPY_ACKS = 256;

const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_ID_ATTEMPTS = 32;

export interface AutofillTotpCopyContentOwner {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
}

declare const AUTOFILL_TOTP_COPY_RECEIPT_BRAND: unique symbol;
export interface AutofillTotpCopyReceipt {
  readonly [AUTOFILL_TOTP_COPY_RECEIPT_BRAND]: true;
}

export type AutofillTotpCopyResult =
  | { readonly kind: 'copied' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'failed' };

export interface AutofillTotpCopyAckRegistryOptions {
  readonly writer: {
    writeAndScheduleClear(value: string, assertCurrent: () => void): Promise<boolean>;
  };
  readonly now?: () => number;
  readonly createId?: () => string;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly onError?: (error: unknown) => void;
}

type StoredOwner =
  | { readonly kind: 'content'; readonly value: AutofillTotpCopyContentOwner }
  | { readonly kind: 'direct'; readonly tabId: number };

interface StoredCopy {
  readonly owner: StoredOwner;
  readonly code: Uint8Array;
  readonly assertCurrent: () => void;
  readonly expiresAt: number;
}

/** Keeps one-time TOTP copies in erasable worker memory until an exact DOM fill succeeds. */
export class AutofillTotpCopyAckRegistry {
  readonly #writer: AutofillTotpCopyAckRegistryOptions['writer'];
  readonly #now: () => number;
  readonly #createId: () => string;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #onError: AutofillTotpCopyAckRegistryOptions['onError'];
  readonly #entries = new Map<string, StoredCopy>();
  readonly #directReceipts = new WeakMap<object, string>();
  readonly #retired = new Map<string, number>();

  constructor(options: AutofillTotpCopyAckRegistryOptions) {
    if (!options || typeof options.writer?.writeAndScheduleClear !== 'function') {
      throw new TypeError('Autofill TOTP copy registry requires a clipboard writer');
    }
    this.#writer = options.writer;
    this.#now = options.now ?? Date.now;
    this.#createId = options.createId ?? (() => crypto.randomUUID());
    this.#ttlMs = positiveInteger(options.ttlMs ?? AUTOFILL_TOTP_COPY_ACK_TTL_MS, 300_000);
    this.#maxEntries = positiveInteger(options.maxEntries ?? MAX_AUTOFILL_TOTP_COPY_ACKS, 1_024);
    this.#onError = options.onError;
  }

  issueContent(
    ownerInput: AutofillTotpCopyContentOwner,
    code: string,
    assertCurrent: () => void,
  ): string {
    const owner = parseOwner(ownerInput);
    return this.#insert({ kind: 'content', value: owner }, code, assertCurrent);
  }

  prepareDirect(code: string, assertCurrent: () => void, tabIdInput: unknown): AutofillTotpCopyReceipt {
    const id = this.#insert({ kind: 'direct', tabId: browserId(tabIdInput, 'tabId') }, code, assertCurrent);
    const receipt = Object.freeze(Object.create(null)) as AutofillTotpCopyReceipt;
    this.#directReceipts.set(receipt, id);
    return receipt;
  }

  consumeContent(idInput: unknown, ownerInput: unknown): Promise<AutofillTotpCopyResult> {
    if (typeof idInput !== 'string' || !UUID_V4_PATTERN.test(idInput)) {
      return Promise.resolve(Object.freeze({ kind: 'rejected' }));
    }
    let owner: AutofillTotpCopyContentOwner | undefined;
    try { owner = parseOwner(ownerInput); } catch { /* Consume below before rejecting. */ }
    return this.#consume(idInput, owner ? { kind: 'content', value: owner } : undefined);
  }

  commitDirect(receipt: AutofillTotpCopyReceipt): Promise<AutofillTotpCopyResult> {
    if (!isObject(receipt)) return Promise.resolve(Object.freeze({ kind: 'rejected' }));
    const id = this.#directReceipts.get(receipt);
    this.#directReceipts.delete(receipt);
    const entry = id ? this.#entries.get(id) : undefined;
    return id && entry?.owner.kind === 'direct'
      ? this.#consume(id, entry.owner)
      : Promise.resolve(Object.freeze({ kind: 'rejected' }));
  }

  discardDirect(receipt: AutofillTotpCopyReceipt): boolean {
    if (!isObject(receipt)) return false;
    const id = this.#directReceipts.get(receipt);
    this.#directReceipts.delete(receipt);
    const entry = id ? this.#entries.get(id) : undefined;
    if (!id || !entry || entry.owner.kind !== 'direct') return false;
    this.#entries.delete(id);
    entry.code.fill(0);
    this.#retire(id, safeAdd(this.#time(), this.#ttlMs));
    return true;
  }

  revokeAll(): number {
    return this.#revoke(() => true);
  }

  revokeTab(tabIdInput: unknown): number {
    const tabId = browserId(tabIdInput, 'tabId');
    return this.#revoke((entry) => entry.owner.kind === 'direct'
      ? entry.owner.tabId === tabId
      : entry.owner.value.tabId === tabId);
  }

  revokeDocument(ownerInput: AutofillTotpCopyContentOwner): number {
    const owner = parseOwner(ownerInput);
    return this.#revoke((entry) => entry.owner.kind === 'content'
      && sameOwner(entry.owner.value, owner));
  }

  #insert(owner: StoredOwner, code: string, assertCurrent: () => void): string {
    if (typeof assertCurrent !== 'function') throw new TypeError('TOTP copy authority is invalid');
    const bytes = parseCode(code);
    const now = this.#time();
    this.#prune(now);
    if (this.#entries.size >= this.#maxEntries) {
      bytes.fill(0);
      throw new Error('Autofill TOTP copy acknowledgement capacity was reached');
    }
    const id = this.#newId();
    this.#entries.set(id, Object.freeze({
      owner,
      code: bytes,
      assertCurrent,
      expiresAt: safeAdd(now, this.#ttlMs),
    }));
    return id;
  }

  async #consume(id: string, expectedOwner: StoredOwner | undefined): Promise<AutofillTotpCopyResult> {
    const entry = this.#entries.get(id);
    if (!entry) return Object.freeze({ kind: 'rejected' });
    // Delete and retire before owner or authority validation so no failure can replay plaintext.
    this.#entries.delete(id);
    this.#retire(id, safeAdd(this.#time(), this.#ttlMs));
    try {
      if (!expectedOwner || !sameStoredOwner(entry.owner, expectedOwner)
          || entry.expiresAt <= this.#time()) return Object.freeze({ kind: 'rejected' });
      try { entry.assertCurrent(); } catch { return Object.freeze({ kind: 'rejected' }); }
      const value = codeString(entry.code);
      try {
        return await this.#writer.writeAndScheduleClear(value, entry.assertCurrent)
          ? Object.freeze({ kind: 'copied' })
          : Object.freeze({ kind: 'failed' });
      } catch (error) {
        this.#report(error);
        return Object.freeze({ kind: 'failed' });
      }
    } finally {
      entry.code.fill(0);
    }
  }

  #revoke(matches: (entry: StoredCopy) => boolean): number {
    const now = this.#time();
    let count = 0;
    for (const [id, entry] of this.#entries) {
      if (!matches(entry)) continue;
      this.#entries.delete(id);
      entry.code.fill(0);
      this.#retire(id, safeAdd(now, this.#ttlMs));
      count += 1;
    }
    return count;
  }

  #prune(now: number): void {
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt > now) continue;
      this.#entries.delete(id);
      entry.code.fill(0);
      this.#retire(id, safeAdd(now, this.#ttlMs));
    }
    for (const [id, expiresAt] of this.#retired) {
      if (expiresAt <= now) this.#retired.delete(id);
    }
  }

  #newId(): string {
    for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt += 1) {
      const id = this.#createId();
      if (typeof id !== 'string' || !UUID_V4_PATTERN.test(id)) {
        throw new TypeError('Autofill TOTP copy ID source returned an invalid UUID');
      }
      if (!this.#entries.has(id) && !this.#retired.has(id)) return id;
    }
    throw new Error('Unable to allocate an Autofill TOTP copy acknowledgement ID');
  }

  #retire(id: string, expiresAt: number): void {
    this.#retired.delete(id);
    this.#retired.set(id, expiresAt);
    while (this.#retired.size > this.#maxEntries * 2) {
      const oldest = this.#retired.keys().next().value as string | undefined;
      if (!oldest) break;
      this.#retired.delete(oldest);
    }
  }

  #time(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('TOTP copy clock is invalid');
    return now;
  }

  #report(error: unknown): void {
    try { this.#onError?.(error); } catch { /* Diagnostics never alter copy settlement. */ }
  }
}

function parseCode(value: unknown): Uint8Array {
  if (!isContentTotpClipboardCode(value)) {
    throw new TypeError('Autofill TOTP code is invalid');
  }
  return Uint8Array.from(value, (character) => character.charCodeAt(0));
}

function codeString(value: Uint8Array): string {
  return String.fromCharCode(...value);
}

function parseOwner(value: unknown): AutofillTotpCopyContentOwner {
  if (!isPlainRecord(value) || Reflect.ownKeys(value).length !== 3) {
    throw new TypeError('Autofill TOTP copy owner is invalid');
  }
  const keys = ['tabId', 'frameId', 'documentId'] as const;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError('Autofill TOTP copy owner is invalid');
    }
  }
  const tabId = browserId(dataValue(value, 'tabId'), 'tabId');
  const frameId = browserId(dataValue(value, 'frameId'), 'frameId');
  const documentId = dataValue(value, 'documentId');
  if (typeof documentId !== 'string' || !documentId || documentId.length > MAX_DOCUMENT_ID_LENGTH
      || documentId.trim() !== documentId || hasControlCharacter(documentId)) {
    throw new TypeError('Autofill TOTP copy owner is invalid');
  }
  return Object.freeze({ tabId, frameId, documentId });
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function sameStoredOwner(left: StoredOwner, right: StoredOwner): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'direct') return right.kind === 'direct' && left.tabId === right.tabId;
  return right.kind === 'content' && sameOwner(left.value, right.value);
}

function sameOwner(left: AutofillTotpCopyContentOwner, right: AutofillTotpCopyContentOwner): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId;
}

function browserId(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`Autofill TOTP copy ${name} is invalid`);
  }
  return value as number;
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function positiveInteger(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new RangeError('Autofill TOTP copy bound is invalid');
  }
  return value;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  return Number.isSafeInteger(result) ? result : Number.MAX_SAFE_INTEGER;
}
