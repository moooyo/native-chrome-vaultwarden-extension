import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';
import {
  createWebsitePasskeyFeaturePolicyProbeRequest,
  parseWebsitePasskeyFeaturePolicyProbeResponse,
  type WebsitePasskeyFeaturePolicyProbeRequest,
} from '../messaging/website-passkey-feature-policy.js';

export const DEFAULT_WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_TTL_MS = 5_000;
export const DEFAULT_WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_CAPACITY = 256;

const MAX_PROBE_TTL_MS = 30_000;
const MAX_PROBE_CAPACITY = 4_096;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 8_192;
const MAX_CHALLENGE_ATTEMPTS = 32;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface WebsitePasskeyFeaturePolicyProbeOwner {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
}

export interface WebsitePasskeyFeaturePolicyProbeReceipt {
  readonly challenge: string;
  readonly expiresAt: number;
}

export interface WebsitePasskeyFeaturePolicyProbeRegistryOptions {
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly createChallenge?: () => string;
}

interface StoredProbe {
  readonly owner: WebsitePasskeyFeaturePolicyProbeOwner;
  readonly expiresAt: number;
}

/** One-shot challenge ownership for exact-document isolated-world policy probes. */
export class WebsitePasskeyFeaturePolicyProbeRegistry {
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #createChallenge: () => string;
  readonly #active = new Map<string, StoredProbe>();
  readonly #retired = new Map<string, number>();

  constructor(options: WebsitePasskeyFeaturePolicyProbeRegistryOptions = {}) {
    this.#ttlMs = positiveInteger(
      options.ttlMs ?? DEFAULT_WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_TTL_MS,
      MAX_PROBE_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = positiveInteger(
      options.maxEntries ?? DEFAULT_WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_CAPACITY,
      MAX_PROBE_CAPACITY,
      'maxEntries',
    );
    this.#now = options.now ?? Date.now;
    this.#createChallenge = options.createChallenge ?? (() => crypto.randomUUID());
  }

  issue(ownerInput: WebsitePasskeyFeaturePolicyProbeOwner): WebsitePasskeyFeaturePolicyProbeReceipt {
    const owner = parseOwner(ownerInput);
    const now = this.#time();
    this.#prune(now);
    // Count retired challenges too: every active entry must be able to become a tombstone.
    if (this.#active.size + this.#retired.size >= this.#maxEntries) {
      throw new Error('Website passkey feature-policy probe capacity was reached');
    }
    const challenge = this.#newChallenge();
    const expiresAt = safeAdd(now, this.#ttlMs);
    this.#active.set(challenge, Object.freeze({ owner, expiresAt }));
    return Object.freeze({ challenge, expiresAt });
  }

  /** Delete and retire before checking time or owner so every failed claim burns the challenge. */
  consume(challenge: string, ownerInput: unknown): boolean {
    if (typeof challenge !== 'string' || !UUID_V4_PATTERN.test(challenge)) return false;
    const probe = this.#active.get(challenge);
    if (!probe) return false;
    this.#active.delete(challenge);
    const now = this.#timeOrUndefined();
    this.#retired.set(
      challenge,
      now === undefined ? Number.MAX_SAFE_INTEGER : safeAdd(now, this.#ttlMs),
    );
    if (now === undefined || probe.expiresAt <= now) return false;
    let owner: WebsitePasskeyFeaturePolicyProbeOwner;
    try { owner = parseOwner(ownerInput); } catch { return false; }
    return sameOwner(probe.owner, owner);
  }

  #newChallenge(): string {
    for (let attempt = 0; attempt < MAX_CHALLENGE_ATTEMPTS; attempt += 1) {
      const challenge = this.#createChallenge();
      if (typeof challenge !== 'string' || !UUID_V4_PATTERN.test(challenge)) {
        throw new TypeError('Website passkey feature-policy challenge source returned an invalid UUID');
      }
      if (!this.#active.has(challenge) && !this.#retired.has(challenge)) return challenge;
    }
    throw new Error('Website passkey feature-policy challenge collision');
  }

  #prune(now: number): void {
    for (const [challenge, probe] of this.#active) {
      if (probe.expiresAt > now) continue;
      this.#active.delete(challenge);
      this.#retired.set(challenge, safeAdd(now, this.#ttlMs));
    }
    for (const [challenge, expiresAt] of this.#retired) {
      if (expiresAt <= now) this.#retired.delete(challenge);
    }
  }

  #time(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('Website passkey feature-policy probe clock is invalid');
    }
    return now;
  }

  #timeOrUndefined(): number | undefined {
    try { return this.#time(); } catch { return undefined; }
  }
}

export type WebsitePasskeyFeaturePolicyProbeResult =
  | Readonly<{ status: 'available'; get: boolean; create: boolean }>
  | Readonly<{ status: 'unavailable' }>;

export interface WebsitePasskeyFeaturePolicyProbeBoundary {
  probe(
    context: WebsitePasskeyDocumentContext,
  ): PromiseLike<WebsitePasskeyFeaturePolicyProbeResult>;
}

export interface WebsitePasskeyFeaturePolicyProbeClientDeps {
  readonly tabs: {
    sendMessage(
      tabId: number,
      request: Readonly<WebsitePasskeyFeaturePolicyProbeRequest>,
      target: { readonly frameId: number; readonly documentId: string },
    ): Promise<unknown>;
  };
  readonly registry: WebsitePasskeyFeaturePolicyProbeRegistry;
  readonly now?: () => number;
  readonly timers?: {
    set(callback: () => void, delayMs: number): unknown;
    clear(handle: unknown): void;
  };
}

const DEFAULT_TIMERS = Object.freeze({
  set: (callback: () => void, delayMs: number): unknown => setTimeout(callback, delayMs),
  clear: (handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>),
});

interface ProbeTimeout {
  readonly promise: Promise<never>;
  readonly clear: () => void;
}

/** Sends one challenge to an exact browser document and consumes it before parsing the reply. */
export class WebsitePasskeyFeaturePolicyProbeClient
  implements WebsitePasskeyFeaturePolicyProbeBoundary {
  readonly #now: () => number;
  readonly #timers: NonNullable<WebsitePasskeyFeaturePolicyProbeClientDeps['timers']>;

  constructor(private readonly deps: WebsitePasskeyFeaturePolicyProbeClientDeps) {
    if (!deps || typeof deps.tabs?.sendMessage !== 'function'
        || !(deps.registry instanceof WebsitePasskeyFeaturePolicyProbeRegistry)) {
      throw new TypeError('Website passkey feature-policy probe dependencies are invalid');
    }
    this.#now = deps.now ?? Date.now;
    this.#timers = deps.timers ?? DEFAULT_TIMERS;
  }

  async probe(context: WebsitePasskeyDocumentContext): Promise<WebsitePasskeyFeaturePolicyProbeResult> {
    const owner = ownerFromContext(context);
    const receipt = this.deps.registry.issue(owner);
    const request = createWebsitePasskeyFeaturePolicyProbeRequest(receipt.challenge);
    let timeout: ProbeTimeout;
    try {
      timeout = this.#timeout(receipt.expiresAt);
    } catch (error) {
      this.deps.registry.consume(receipt.challenge, owner);
      throw error;
    }
    let response: unknown;
    let failed = false;
    try {
      response = await Promise.race([
        this.deps.tabs.sendMessage(owner.tabId, request, {
          frameId: owner.frameId,
          documentId: owner.documentId,
        }),
        timeout.promise,
      ]);
    } catch {
      failed = true;
    } finally {
      timeout.clear();
    }

    // Consume before inspecting transport errors or attacker-shaped response fields.
    const consumed = this.deps.registry.consume(receipt.challenge, owner);
    if (!consumed || failed) {
      throw new Error('Website passkey feature-policy probe failed');
    }
    if (response === undefined) return Object.freeze({ status: 'unavailable' as const });
    let parsed;
    try {
      parsed = parseWebsitePasskeyFeaturePolicyProbeResponse(response, receipt.challenge);
    } catch {
      throw new Error('Website passkey feature-policy probe returned an invalid response');
    }
    return Object.freeze({
      status: 'available' as const,
      get: parsed.get,
      create: parsed.create,
    });
  }

  #timeout(expiresAt: number): ProbeTimeout {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError('Website passkey feature-policy probe clock is invalid');
    }
    let handle: unknown;
    const promise = new Promise<never>((_resolve, reject) => {
      handle = this.#timers.set(
        () => reject(new Error('Website passkey feature-policy probe timed out')),
        Math.max(0, expiresAt - now),
      );
    });
    return Object.freeze({
      promise,
      clear: () => { if (handle !== undefined) this.#timers.clear(handle); },
    });
  }
}

function ownerFromContext(context: WebsitePasskeyDocumentContext): WebsitePasskeyFeaturePolicyProbeOwner {
  return parseOwner({
    tabId: context?.tabId,
    frameId: context?.frameId,
    documentId: context?.documentId,
    url: context?.url,
  });
}

function parseOwner(input: unknown): WebsitePasskeyFeaturePolicyProbeOwner {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) invalidOwner();
  const value = input as Record<string, unknown>;
  const expected = ['tabId', 'frameId', 'documentId', 'url'] as const;
  const keys = Reflect.ownKeys(value);
  const prototype = Object.getPrototypeOf(value) as unknown;
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string'
        || !expected.includes(key as typeof expected[number]))) invalidOwner();
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) invalidOwner();
  }
  const tabId = dataValue(value, 'tabId');
  const frameId = dataValue(value, 'frameId');
  const documentId = dataValue(value, 'documentId');
  const rawUrl = dataValue(value, 'url');
  if (!nonNegativeInteger(tabId) || !nonNegativeInteger(frameId)
      || typeof documentId !== 'string' || !documentId || documentId.length > MAX_DOCUMENT_ID_LENGTH
      || documentId.trim() !== documentId || containsAsciiControl(documentId)
      || typeof rawUrl !== 'string' || !rawUrl || rawUrl.length > MAX_URL_LENGTH
      || rawUrl.trim() !== rawUrl || containsAsciiControl(rawUrl)) invalidOwner();
  let url: URL;
  try { url = new URL(rawUrl); } catch { return invalidOwner(); }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:')
      || url.username || url.password || url.origin === 'null' || url.href !== rawUrl) invalidOwner();
  return Object.freeze({ tabId, frameId, documentId, url: rawUrl });
}

function dataValue(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function sameOwner(
  left: WebsitePasskeyFeaturePolicyProbeOwner,
  right: WebsitePasskeyFeaturePolicyProbeOwner,
): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.url === right.url;
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0);
}

function positiveInteger(value: unknown, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new TypeError(`Website passkey feature-policy probe ${name} is invalid`);
  }
  return value as number;
}

function safeAdd(left: number, right: number): number {
  const sum = left + right;
  if (!Number.isSafeInteger(sum)) {
    throw new TypeError('Website passkey feature-policy probe lifetime is invalid');
  }
  return sum;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function invalidOwner(): never {
  throw new TypeError('Website passkey feature-policy probe owner is invalid');
}
