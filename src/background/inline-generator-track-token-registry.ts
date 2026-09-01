import {
  applyGeneratorPolicySnapshot,
  parseGeneratorPolicySnapshot,
  type GeneratorPolicySnapshot,
  type PasswordGeneratorOptions,
} from '../core/generator/enterprise-password-policy.js';
import { PASSPHRASE_WORDLIST } from '../core/generator/wordlist.js';
import type {
  GeneratorHistoryProductionService,
  GeneratorHistoryTrackRequest,
} from './generator-history-production.js';

export const INLINE_GENERATOR_TRACK_TOKEN_TTL_MS = 30_000;
export const MAX_INLINE_GENERATOR_TRACK_TOKENS = 256;
export const MAX_INLINE_GENERATED_VALUE_LENGTH = 128;

const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 8_192;
const MAX_ID_ATTEMPTS = 32;
const PASSWORD_SPECIAL = '!@#$%^&*';
const AMBIGUOUS_PASSWORD_CHARACTERS = new Set(['I', 'l', '1', 'O', '0']);

export interface InlineGeneratorTrackOwner {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
}

export type InlineGeneratorTrackResult =
  | { readonly kind: 'tracked'; readonly added: boolean }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'failed' };

export interface InlineGeneratorTrackTokenRegistryOptions {
  readonly history: Pick<GeneratorHistoryProductionService, 'track'>;
  readonly now?: () => number;
  readonly createId?: () => string;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
}

interface StoredToken {
  readonly owner: InlineGeneratorTrackOwner;
  readonly options: PasswordGeneratorOptions;
  readonly historyType: 'password' | 'passphrase';
  readonly policyRevision: number;
  readonly assertCurrent: () => void;
  readonly expiresAt: number;
}

/** Worker-memory-only one-shot authorization for recording an actually filled generated value. */
export class InlineGeneratorTrackTokenRegistry {
  readonly #history: InlineGeneratorTrackTokenRegistryOptions['history'];
  readonly #now: () => number;
  readonly #createId: () => string;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #entries = new Map<string, StoredToken>();
  readonly #retired = new Map<string, number>();

  constructor(options: InlineGeneratorTrackTokenRegistryOptions) {
    if (!options || typeof options.history?.track !== 'function') {
      throw new TypeError('Inline generator tracking requires encrypted history');
    }
    this.#history = options.history;
    this.#now = options.now ?? Date.now;
    this.#createId = options.createId ?? (() => crypto.randomUUID());
    this.#ttlMs = boundedPositiveInteger(options.ttlMs ?? INLINE_GENERATOR_TRACK_TOKEN_TTL_MS, 300_000);
    this.#maxEntries = boundedPositiveInteger(options.maxEntries ?? MAX_INLINE_GENERATOR_TRACK_TOKENS, 1_024);
  }

  issue(
    ownerInput: InlineGeneratorTrackOwner,
    rawPolicy: GeneratorPolicySnapshot,
    rawOptions: PasswordGeneratorOptions,
    assertCurrent: () => void,
  ): string {
    if (typeof assertCurrent !== 'function') throw new TypeError('Generator track authority is invalid');
    const owner = parseOwner(ownerInput);
    const policy = parseGeneratorPolicySnapshot(rawPolicy);
    if (!policy || policy.malformed) throw new TypeError('Generator policy is invalid');
    const evaluation = applyGeneratorPolicySnapshot(rawOptions, policy);
    if (!evaluation.allowed || evaluation.options.mode !== rawOptions.mode) {
      throw new TypeError('Generator options are not authorized');
    }
    const now = this.#time();
    this.#prune(now);
    if (this.#entries.size >= this.#maxEntries) {
      throw new Error('Inline generator track token capacity was reached');
    }
    assertCurrent();
    const id = this.#newId();
    this.#entries.set(id, Object.freeze({
      owner,
      options: evaluation.options,
      historyType: evaluation.options.mode === 'passphrase' ? 'passphrase' : 'password',
      policyRevision: policy.revision,
      assertCurrent,
      expiresAt: safeAdd(now, this.#ttlMs),
    }));
    return id;
  }

  async consume(
    tokenInput: unknown,
    ownerInput: unknown,
    valueInput: unknown,
  ): Promise<InlineGeneratorTrackResult> {
    if (typeof tokenInput !== 'string' || !UUID_V4_PATTERN.test(tokenInput)) {
      return Object.freeze({ kind: 'rejected' });
    }
    let owner: InlineGeneratorTrackOwner | undefined;
    try { owner = parseOwner(ownerInput); } catch { /* Consume below before rejecting. */ }
    const entry = this.#entries.get(tokenInput);
    if (!entry) return Object.freeze({ kind: 'rejected' });
    this.#entries.delete(tokenInput);
    this.#retire(tokenInput, safeAdd(this.#time(), this.#ttlMs));
    if (!owner || !sameOwner(owner, entry.owner) || entry.expiresAt <= this.#time()) {
      return Object.freeze({ kind: 'rejected' });
    }
    try {
      entry.assertCurrent();
    } catch {
      return Object.freeze({ kind: 'rejected' });
    }
    if (!generatedValueMatches(valueInput, entry.options)) {
      return Object.freeze({ kind: 'rejected' });
    }
    const request: GeneratorHistoryTrackRequest = Object.freeze({
      value: valueInput,
      type: entry.historyType,
      policyRevision: entry.policyRevision,
    });
    try {
      entry.assertCurrent();
      const result = await this.#history.track(request);
      return typeof result?.added === 'boolean'
        ? Object.freeze({ kind: 'tracked', added: result.added })
        : Object.freeze({ kind: 'failed' });
    } catch {
      return Object.freeze({ kind: 'failed' });
    }
  }

  revokeAll(): number {
    return this.#revoke(() => true);
  }

  revokeTab(tabIdInput: unknown): number {
    const tabId = browserId(tabIdInput, 'tabId');
    return this.#revoke((entry) => entry.owner.tabId === tabId);
  }

  revokeDocument(ownerInput: InlineGeneratorTrackOwner): number {
    const owner = parseOwner(ownerInput);
    return this.#revoke((entry) => sameOwner(entry.owner, owner));
  }

  #revoke(matches: (entry: StoredToken) => boolean): number {
    const now = this.#time();
    let count = 0;
    for (const [id, entry] of this.#entries) {
      if (!matches(entry)) continue;
      this.#entries.delete(id);
      this.#retire(id, safeAdd(now, this.#ttlMs));
      count += 1;
    }
    return count;
  }

  #prune(now: number): void {
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt > now) continue;
      this.#entries.delete(id);
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
        throw new TypeError('Generator track token source returned an invalid UUID');
      }
      if (!this.#entries.has(id) && !this.#retired.has(id)) return id;
    }
    throw new Error('Unable to allocate a generator track token');
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
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Generator track clock is invalid');
    return now;
  }
}

function generatedValueMatches(value: unknown, options: PasswordGeneratorOptions): value is string {
  if (typeof value !== 'string' || value.length === 0
      || value.length > MAX_INLINE_GENERATED_VALUE_LENGTH || hasControlCharacter(value)) return false;
  return options.mode === 'password'
    ? generatedPasswordMatches(value, options)
    : generatedPassphraseMatches(value, options);
}

function generatedPasswordMatches(value: string, options: PasswordGeneratorOptions): boolean {
  const expected = options.password;
  if (value.length !== expected.length) return false;
  let lowercase = 0;
  let uppercase = 0;
  let numbers = 0;
  let special = 0;
  for (const character of value) {
    if (character >= 'a' && character <= 'z') lowercase += 1;
    else if (character >= 'A' && character <= 'Z') uppercase += 1;
    else if (character >= '0' && character <= '9') numbers += 1;
    else if (PASSWORD_SPECIAL.includes(character)) special += 1;
    else return false;
    if (expected.avoidAmbiguous && AMBIGUOUS_PASSWORD_CHARACTERS.has(character)) return false;
  }
  return (expected.lowercase ? lowercase > 0 : lowercase === 0)
    && (expected.uppercase ? uppercase > 0 : uppercase === 0)
    && (expected.numbers ? numbers >= Math.max(1, expected.minNumbers) : numbers === 0)
    && (expected.special ? special >= Math.max(1, expected.minSpecial) : special === 0);
}

function generatedPassphraseMatches(value: string, options: PasswordGeneratorOptions): boolean {
  const expected = options.passphrase;
  if (expected.separator !== '-') return false;
  const words = value.split('-');
  if (words.length !== expected.numWords || words.some((word) => !word)) return false;
  let appendedNumbers = 0;
  for (const word of words) {
    const match = /^(.*?)([0-9]?)$/u.exec(word);
    if (!match) return false;
    const base = match[1]!;
    const digit = match[2]!;
    if (digit) appendedNumbers += 1;
    const normalized = expected.capitalize
      ? `${base.charAt(0).toUpperCase()}${base.slice(1).toLowerCase()}`
      : base.toLowerCase();
    if (base !== normalized || !PASSPHRASE_WORDLIST.includes(base.toLowerCase())) return false;
  }
  return expected.includeNumber ? appendedNumbers === 1 : appendedNumbers === 0;
}

function parseOwner(value: unknown): InlineGeneratorTrackOwner {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, ['tabId', 'frameId', 'documentId', 'url'])) {
    throw new TypeError('Generator track owner is invalid');
  }
  const tabId = browserId(ownData(value, 'tabId'), 'tabId');
  const frameId = browserId(ownData(value, 'frameId'), 'frameId');
  const documentId = ownData(value, 'documentId');
  const url = ownData(value, 'url');
  if (typeof documentId !== 'string' || !documentId || documentId.length > MAX_DOCUMENT_ID_LENGTH
      || documentId.trim() !== documentId || hasControlCharacter(documentId)
      || typeof url !== 'string' || !url || url.length > MAX_URL_LENGTH
      || url.trim() !== url || hasControlCharacter(url) || !isCanonicalHttpsUrl(url)) {
    throw new TypeError('Generator track owner is invalid');
  }
  return Object.freeze({ tabId, frameId, documentId, url });
}

function sameOwner(left: InlineGeneratorTrackOwner, right: InlineGeneratorTrackOwner): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.url === right.url;
}

function isCanonicalHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.href === value;
  } catch {
    return false;
  }
}

function browserId(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`Generator track ${name} is invalid`);
  }
  return value as number;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function hasExactDataKeys(record: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedSet = new Set(expected);
  return keys.every((key) => expectedSet.has(key as string)) && expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function ownData(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function boundedPositiveInteger(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new RangeError('Generator track token bound is invalid');
  }
  return value;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  return Number.isSafeInteger(result) ? result : Number.MAX_SAFE_INTEGER;
}
