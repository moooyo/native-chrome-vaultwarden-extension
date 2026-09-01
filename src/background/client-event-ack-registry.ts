import type {
  ClientEventCommitResult,
  ClientEventReceipt,
  ClientEventService,
} from './client-event-service.js';

export const CLIENT_EVENT_ACK_TTL_MS = 30_000;
export const MAX_CLIENT_EVENT_ACKS = 256;

const MAX_CLIENT_EVENT_ACK_TTL_MS = 5 * 60_000;
const MAX_CLIENT_EVENT_ACK_CAPACITY = 1_024;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_ID_GENERATION_ATTEMPTS = 32;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type ClientEventAckOwner =
  | {
      readonly kind: 'popup';
      readonly documentId: string;
    }
  | {
      readonly kind: 'options';
      readonly documentId: string;
    }
  | {
      readonly kind: 'content';
      readonly tabId: number;
      readonly frameId: number;
      readonly documentId: string;
    };

export type ClientEventAckConsumeResult =
  | { readonly kind: 'committed' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'failed' };

export type ClientEventAckRegistryErrorCode = 'capacity' | 'id_generation';

export class ClientEventAckRegistryError extends Error {
  constructor(readonly code: ClientEventAckRegistryErrorCode, message: string) {
    super(message);
    this.name = 'ClientEventAckRegistryError';
  }
}

export interface ClientEventAckRegistryOptions {
  readonly committer: Pick<ClientEventService, 'commit'>;
  readonly now?: () => number;
  readonly createId?: () => string;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly onError?: (error: unknown) => void;
}

interface StoredAck {
  readonly owner: ClientEventAckOwner;
  readonly receipt: ClientEventReceipt;
  readonly expiresAt: number;
  readonly assertCurrent?: () => void;
}

/**
 * In-memory bridge for actions whose final success acknowledgement crosses a document boundary.
 * Receipts never leave the worker, and every acknowledgement is consumed before owner validation.
 */
export class ClientEventAckRegistry {
  readonly #committer: ClientEventAckRegistryOptions['committer'];
  readonly #now: () => number;
  readonly #createId: () => string;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #onError: ClientEventAckRegistryOptions['onError'];
  readonly #entries = new Map<string, StoredAck>();
  readonly #retired = new Map<string, number>();

  constructor(options: ClientEventAckRegistryOptions) {
    if (!options || typeof options.committer?.commit !== 'function') {
      throw new TypeError('Client event acknowledgement registry requires a committer');
    }
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new TypeError('Client event acknowledgement clock is invalid');
    }
    if (options.createId !== undefined && typeof options.createId !== 'function') {
      throw new TypeError('Client event acknowledgement ID source is invalid');
    }
    if (options.onError !== undefined && typeof options.onError !== 'function') {
      throw new TypeError('Client event acknowledgement error observer is invalid');
    }
    this.#committer = options.committer;
    this.#now = options.now ?? Date.now;
    this.#createId = options.createId ?? (() => crypto.randomUUID());
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? CLIENT_EVENT_ACK_TTL_MS,
      MAX_CLIENT_EVENT_ACK_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? MAX_CLIENT_EVENT_ACKS,
      MAX_CLIENT_EVENT_ACK_CAPACITY,
      'maxEntries',
    );
    this.#onError = options.onError;
  }

  issue(
    ownerInput: ClientEventAckOwner,
    receipt: ClientEventReceipt,
    assertCurrent?: () => void,
  ): string {
    const owner = parseOwner(ownerInput);
    if (!isObject(receipt)) throw new TypeError('Client event acknowledgement receipt is invalid');
    if (assertCurrent !== undefined && typeof assertCurrent !== 'function') {
      throw new TypeError('Client event acknowledgement authority is invalid');
    }
    const now = this.#currentTime();
    this.#prune(now);
    if (this.#entries.size >= this.#maxEntries) {
      throw new ClientEventAckRegistryError(
        'capacity',
        'Client event acknowledgement capacity was reached',
      );
    }
    const id = this.#newId();
    this.#entries.set(id, Object.freeze({
      owner,
      receipt,
      expiresAt: safeAdd(now, this.#ttlMs),
      ...(assertCurrent ? { assertCurrent } : {}),
    }));
    return id;
  }

  async consume(
    idInput: unknown,
    ownerInput: unknown,
  ): Promise<ClientEventAckConsumeResult> {
    if (typeof idInput !== 'string' || !UUID_V4_PATTERN.test(idInput)) {
      return Object.freeze({ kind: 'rejected' });
    }
    const entry = this.#entries.get(idInput);
    if (!entry) return Object.freeze({ kind: 'rejected' });

    // Delete first so an invalid owner, clock failure, or throwing committer can never be retried.
    this.#entries.delete(idInput);
    this.#retire(idInput, entry.expiresAt);
    const now = this.#currentTime();
    this.#retire(idInput, safeAdd(now, this.#ttlMs));
    let owner: ClientEventAckOwner;
    try {
      owner = parseOwner(ownerInput);
    } catch {
      return Object.freeze({ kind: 'rejected' });
    }
    if (entry.expiresAt <= now || !sameOwner(entry.owner, owner)) {
      return Object.freeze({ kind: 'rejected' });
    }
    try {
      entry.assertCurrent?.();
    } catch {
      return Object.freeze({ kind: 'rejected' });
    }

    try {
      return consumeResult(await this.#committer.commit(entry.receipt));
    } catch (error) {
      this.#report(error);
      return Object.freeze({ kind: 'failed' });
    }
  }

  revokeAll(): number {
    const now = this.#currentTime();
    const count = this.#entries.size;
    for (const id of this.#entries.keys()) this.#retire(id, safeAdd(now, this.#ttlMs));
    this.#entries.clear();
    this.#pruneRetired(now);
    return count;
  }

  revokeTab(tabIdInput: unknown): number {
    const tabId = requireBrowserId(tabIdInput, 'tabId');
    return this.#revoke((owner) => owner.kind === 'content' && owner.tabId === tabId);
  }

  revokeDocument(ownerInput: ClientEventAckOwner): number {
    const expected = parseOwner(ownerInput);
    return this.#revoke((owner) => sameOwner(owner, expected));
  }

  #revoke(matches: (owner: ClientEventAckOwner) => boolean): number {
    const now = this.#currentTime();
    let count = 0;
    for (const [id, entry] of this.#entries) {
      if (!matches(entry.owner)) continue;
      this.#entries.delete(id);
      this.#retire(id, safeAdd(now, this.#ttlMs));
      count += 1;
    }
    this.#pruneRetired(now);
    return count;
  }

  #newId(): string {
    for (let attempt = 0; attempt < MAX_ID_GENERATION_ATTEMPTS; attempt += 1) {
      const id = this.#createId();
      if (typeof id !== 'string' || !UUID_V4_PATTERN.test(id)) {
        throw new ClientEventAckRegistryError(
          'id_generation',
          'Client event acknowledgement ID source returned an invalid UUID',
        );
      }
      if (!this.#entries.has(id) && !this.#retired.has(id)) return id;
    }
    throw new ClientEventAckRegistryError(
      'id_generation',
      'Unable to allocate a unique client event acknowledgement ID',
    );
  }

  #prune(now: number): void {
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt > now) continue;
      this.#entries.delete(id);
      this.#retire(id, safeAdd(now, this.#ttlMs));
    }
    this.#pruneRetired(now);
  }

  #retire(id: string, expiresAt: number): void {
    this.#retired.delete(id);
    this.#retired.set(id, expiresAt);
    while (this.#retired.size > this.#maxEntries * 2) {
      const oldest = this.#retired.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#retired.delete(oldest);
    }
  }

  #pruneRetired(now: number): void {
    for (const [id, expiresAt] of this.#retired) {
      if (expiresAt <= now) this.#retired.delete(id);
    }
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('Client event acknowledgement clock is invalid');
    }
    return now;
  }

  #report(error: unknown): void {
    try {
      this.#onError?.(error);
    } catch {
      // Diagnostics must never revive or replay a consumed acknowledgement.
    }
  }
}

function consumeResult(result: ClientEventCommitResult): ClientEventAckConsumeResult {
  if (result.kind === 'enqueued') return Object.freeze({ kind: 'committed' });
  if (result.kind === 'failed') return Object.freeze({ kind: 'failed' });
  return Object.freeze({ kind: 'rejected' });
}

function parseOwner(value: unknown): ClientEventAckOwner {
  if (!isPlainRecord(value)) throw new TypeError('Client event acknowledgement owner is invalid');
  const kind = dataValue(value, 'kind');
  if (kind === 'popup' || kind === 'options') {
    requireExactDataKeys(value, ['kind', 'documentId']);
    return Object.freeze({
      kind,
      documentId: requireDocumentId(dataValue(value, 'documentId')),
    });
  }
  if (kind === 'content') {
    requireExactDataKeys(value, ['kind', 'tabId', 'frameId', 'documentId']);
    return Object.freeze({
      kind,
      tabId: requireBrowserId(dataValue(value, 'tabId'), 'tabId'),
      frameId: requireBrowserId(dataValue(value, 'frameId'), 'frameId'),
      documentId: requireDocumentId(dataValue(value, 'documentId')),
    });
  }
  throw new TypeError('Client event acknowledgement owner is invalid');
}

function sameOwner(left: ClientEventAckOwner, right: ClientEventAckOwner): boolean {
  if (left.kind !== right.kind || left.documentId !== right.documentId) return false;
  return left.kind === 'popup' || left.kind === 'options'
    || (right.kind === 'content'
      && left.tabId === right.tabId
      && left.frameId === right.frameId);
}

function requireDocumentId(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_DOCUMENT_ID_LENGTH
      || value.trim() !== value || containsControl(value)) {
    throw new TypeError('Client event acknowledgement documentId is invalid');
  }
  return value;
}

function requireBrowserId(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`Client event acknowledgement ${name} is invalid`);
  }
  return value as number;
}

function requireExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Reflect.ownKeys(record);
  const expectedSet = new Set(expected);
  if (keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expectedSet.has(key))) {
    throw new TypeError('Client event acknowledgement owner has unexpected fields');
  }
  for (const key of expected) dataValue(record, key);
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor?.enumerable || !('value' in descriptor)) {
    throw new TypeError('Client event acknowledgement owner has invalid properties');
  }
  return descriptor.value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function containsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  return Number.isSafeInteger(result) ? result : Number.MAX_SAFE_INTEGER;
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new RangeError(`${name} must be a positive safe integer no greater than ${maximum}`);
  }
  return value;
}
