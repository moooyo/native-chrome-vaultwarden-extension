import type { AutofillLoginData } from '../messaging/protocol.js';
import type { AccountLease } from '../core/session/account-gate.js';
import type { SessionLease } from '../core/session/session-manager.js';
import type { VaultReleaseGate, VaultReleaseLease } from './vault-release-gate.js';
import {
  isUriMatchStrategySetting,
  type UriMatchStrategySetting,
} from '../core/vault/uri-match.js';

export const HTTP_AUTH_CALLBACK_DEADLINE_MS = 2_000;
export const HTTP_AUTH_MEMORY_CLAIM_TTL_MS = 5 * 60_000;
export const HTTP_AUTH_MAX_MEMORY_CLAIMS = 512;

export interface HttpAuthChallengeDetails {
  readonly requestId: string;
  readonly url: string;
  readonly method: string;
  readonly frameId: number;
  readonly tabId: number;
  readonly type: string;
  readonly incognito?: boolean;
  readonly scheme: string;
  readonly challenger: {
    readonly host: string;
    readonly port: number;
  };
  readonly isProxy: boolean;
}

export interface HttpAuthBlockingResponse {
  readonly authCredentials?: {
    readonly username: string;
    readonly password: string;
  };
}

export interface HttpAuthSettingsSnapshot {
  readonly schemaVersion: 1;
  readonly enabled: boolean;
  readonly allowedOrigins: readonly string[];
}

export interface HttpAuthSettingsRead {
  readonly settings: HttpAuthSettingsSnapshot;
  readonly valid: boolean;
}

export interface HttpAuthTombstones {
  claim(fingerprint: string): Promise<boolean>;
}

export interface HttpAuthFrameAuthorization {
  readonly defaultStrategy: UriMatchStrategySetting;
  assertCurrent(): void;
}

export interface HttpAuthBrokerDeps {
  readonly ready: () => Promise<void>;
  readonly readHttpAuthSettings: () => Promise<HttpAuthSettingsRead>;
  readonly authorizeFrame: (
    url: string,
    action: 'intent',
  ) => Promise<HttpAuthFrameAuthorization>;
  readonly captureSessionLease: () => SessionLease;
  readonly assertSessionLease: (lease: SessionLease) => void;
  readonly captureAccountLease: () => AccountLease;
  readonly assertAccountLease: (lease: AccountLease) => void;
  readonly getHttpAuthLoginData: (
    url: string,
    defaultStrategy: UriMatchStrategySetting,
    bindFinalAuthority?: (assertCurrent: () => void) => void,
  ) => Promise<AutofillLoginData>;
  readonly tombstones: HttpAuthTombstones;
  readonly now?: () => number;
  readonly digestFingerprint?: (requestId: string) => Promise<string>;
  readonly deadlineMs?: number;
  readonly vaultReleaseGate?: Pick<
    VaultReleaseGate,
    'capture' | 'checkpoint' | 'assertAuthorities' | 'assert'
  > & Partial<Pick<VaultReleaseGate, 'settlePendingAction'>>;
}

interface EligibleChallenge {
  readonly requestId: string;
  readonly url: string;
  readonly origin: string;
}

interface OperationLeases {
  readonly session: SessionLease;
  readonly account: AccountLease;
  readonly release?: VaultReleaseLease;
}

interface HttpAuthResolution {
  readonly response: HttpAuthBlockingResponse;
  readonly assertCurrent?: () => void;
  readonly releaseLease?: VaultReleaseLease;
}

/**
 * Background-only HTTP authentication broker. It never sends credentials through extension
 * messaging and every asynchronous boundary is fenced by the original session/account/policy
 * generations.
 */
export class HttpAuthBroker {
  readonly #deps: HttpAuthBrokerDeps;
  readonly #memoryClaims = new Map<string, number>();

  constructor(deps: HttpAuthBrokerDeps) {
    this.#deps = deps;
  }

  /**
   * Claim synchronously, arm a callback-once deadline, and complete through Chrome's callback-style
   * asyncBlocking contract. This method intentionally returns void, never a Promise.
   */
  handle(
    details: HttpAuthChallengeDetails,
    callback: (response: HttpAuthBlockingResponse) => void,
  ): void {
    let settled = false;
    const respond = (
      response: HttpAuthBlockingResponse,
      assertCurrent?: () => void,
    ): 'delivered' | 'authority_failed' | 'settled' => {
      if (settled) return 'settled';
      let deliverable = response;
      let authorityFailed = false;
      try {
        assertCurrent?.();
      } catch {
        deliverable = {};
        authorityFailed = true;
      }
      settled = true;
      clearTimeout(timer);
      try {
        callback(deliverable);
      } catch {
        // A browser-owned callback failure cannot be recovered or retried safely.
      }
      return authorityFailed ? 'authority_failed' : 'delivered';
    };
    const deadlineMs = normalizeDeadline(this.#deps.deadlineMs);
    const timer = setTimeout(() => respond({}), deadlineMs);

    const challenge = parseEligibleChallenge(details);
    if (!challenge || !this.#claimMemory(challenge.requestId)) {
      respond({});
      return;
    }

    void this.#resolve(challenge, () => !settled)
      .then(async (resolution) => {
        let assertCurrent = resolution.assertCurrent;
        if (resolution.releaseLease && this.#deps.vaultReleaseGate) {
          const gate = this.#deps.vaultReleaseGate;
          const assertAuthorizationCurrent = assertCurrent;
          const proof = await gate.checkpoint(resolution.releaseLease);
          assertCurrent = () => {
            gate.assertAuthorities(proof, () => assertAuthorizationCurrent?.());
            gate.assert(proof);
          };
        }
        const outcome = respond(resolution.response, assertCurrent);
        if (outcome === 'authority_failed') {
          await this.#deps.vaultReleaseGate?.settlePendingAction?.();
        }
      })
      .catch(async () => {
        await this.#deps.vaultReleaseGate?.settlePendingAction?.();
        respond({});
      });
  }

  /** Clear only the process-local request claim. The persistent tombstone intentionally survives. */
  finishRequest(requestId: string): void {
    if (typeof requestId === 'string') this.#memoryClaims.delete(requestId);
  }

  #claimMemory(requestId: string): boolean {
    const now = this.#now();
    for (const [id, expiresAt] of this.#memoryClaims) {
      if (expiresAt <= now) this.#memoryClaims.delete(id);
    }
    if (this.#memoryClaims.has(requestId)) return false;
    if (this.#memoryClaims.size >= HTTP_AUTH_MAX_MEMORY_CLAIMS) {
      let oldest: string | undefined;
      let oldestExpiry = Number.POSITIVE_INFINITY;
      for (const [id, expiresAt] of this.#memoryClaims) {
        if (expiresAt < oldestExpiry) {
          oldest = id;
          oldestExpiry = expiresAt;
        }
      }
      if (oldest !== undefined) this.#memoryClaims.delete(oldest);
    }
    this.#memoryClaims.set(requestId, now + HTTP_AUTH_MEMORY_CLAIM_TTL_MS);
    return true;
  }

  async #resolve(
    challenge: EligibleChallenge,
    active: () => boolean,
  ): Promise<HttpAuthResolution> {
    await this.#deps.ready();
    assertActive(active);

    const session = this.#deps.captureSessionLease();
    const release = this.#deps.vaultReleaseGate?.capture(session);
    const leases: OperationLeases = {
      session,
      account: this.#deps.captureAccountLease(),
      ...(release ? { release } : {}),
    };
    this.#assertCurrent(leases, active);

    const httpAuthRead = await this.#deps.readHttpAuthSettings();
    this.#assertCurrent(leases, active);
    const settings = validateSettingsRead(httpAuthRead);
    if (!settings.enabled || !settings.allowedOrigins.includes(challenge.origin)) return { response: {} };

    const authorization = await this.#deps.authorizeFrame(challenge.url, 'intent');
    this.#assertCurrent(leases, active, authorization);
    if (!isUriMatchStrategySetting(authorization.defaultStrategy)) return { response: {} };

    const digest = await (this.#deps.digestFingerprint ?? digestHttpAuthRequestId)(
      challenge.requestId,
    );
    this.#assertCurrent(leases, active, authorization);
    if (!isSha256Hex(digest)) return { response: {} };
    if (!await this.#deps.tombstones.claim(digest)) return { response: {} };
    this.#assertCurrent(leases, active, authorization);

    // Candidate selection, exact-root validation, and decryption happen atomically against one
    // vault cache generation. No cipher identifier crosses that operation boundary.
    let assertVaultCurrent: (() => void) | undefined;
    const login = await this.#deps.getHttpAuthLoginData(
      challenge.url,
      authorization.defaultStrategy,
      (assertCurrent) => { assertVaultCurrent = assertCurrent; },
    );
    this.#assertCurrent(leases, active, authorization);
    if (!isNonEmptyCredential(login)) return { response: {} };
    return {
      response: {
        authCredentials: {
          username: login.username,
          password: login.password,
        },
      },
      assertCurrent: () => {
        this.#assertCurrent(leases, active, authorization);
        assertVaultCurrent?.();
      },
      ...(leases.release ? { releaseLease: leases.release } : {}),
    };
  }

  #assertCurrent(
    leases: OperationLeases,
    active: () => boolean,
    authorization?: HttpAuthFrameAuthorization,
  ): void {
    assertActive(active);
    this.#deps.assertAccountLease(leases.account);
    this.#deps.assertSessionLease(leases.session);
    authorization?.assertCurrent();
    assertActive(active);
  }

  #now(): number {
    const now = (this.#deps.now ?? Date.now)();
    return Number.isFinite(now) ? now : Date.now();
  }
}

export function parseEligibleChallenge(
  details: HttpAuthChallengeDetails,
): EligibleChallenge | undefined {
  if (
    !details
    || typeof details.requestId !== 'string'
    || details.requestId.length === 0
    || details.requestId.length > 1_024
    || details.type !== 'main_frame'
    || details.frameId !== 0
    || !Number.isInteger(details.tabId)
    || details.tabId < 0
    || details.incognito === true
    || details.isProxy !== false
    || typeof details.scheme !== 'string'
    || details.scheme.toLowerCase() !== 'basic'
    || (details.method !== 'GET' && details.method !== 'HEAD')
    || typeof details.url !== 'string'
    || details.url.length === 0
    || details.url.length > 8_192
    || !details.challenger
    || typeof details.challenger.host !== 'string'
    || !Number.isInteger(details.challenger.port)
  ) return undefined;

  let url: URL;
  try {
    url = new URL(details.url);
  } catch {
    return undefined;
  }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || !isAllowedHttpAuthTransport(url)
  ) return undefined;

  const challengerHost = canonicalComparableHost(details.challenger.host);
  const urlHost = canonicalComparableHost(url.hostname);
  const effectivePort = url.port
    ? Number(url.port)
    : (url.protocol === 'https:' ? 443 : 80);
  if (
    challengerHost === undefined
    || urlHost === undefined
    || challengerHost !== urlHost
    || details.challenger.port !== effectivePort
  ) return undefined;

  return Object.freeze({
    requestId: details.requestId,
    url: url.href,
    origin: url.origin,
  });
}

export async function digestHttpAuthRequestId(requestId: string): Promise<string> {
  const input = new TextEncoder().encode(`miyu-http-auth-request-v1\0${requestId}`);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  } finally {
    input.fill(0);
  }
}

function validateSettingsRead(read: HttpAuthSettingsRead): HttpAuthSettingsSnapshot {
  if (
    !read
    || read.valid !== true
    || !read.settings
    || read.settings.schemaVersion !== 1
    || typeof read.settings.enabled !== 'boolean'
    || !Array.isArray(read.settings.allowedOrigins)
    || read.settings.allowedOrigins.length > 256
    || read.settings.allowedOrigins.some((origin) => !isCanonicalAllowedOrigin(origin))
  ) throw new Error('HTTP authentication policy is unavailable');
  return read.settings;
}

function isCanonicalAllowedOrigin(value: string): boolean {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) return false;
  try {
    const parsed = new URL(value);
    return parsed.origin === value
      && parsed.pathname === '/'
      && parsed.search === ''
      && parsed.hash === ''
      && !parsed.username
      && !parsed.password
      && isAllowedHttpAuthTransport(parsed);
  } catch {
    return false;
  }
}

function isAllowedHttpAuthTransport(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  const hostname = canonicalComparableHost(url.hostname);
  if (hostname === 'localhost' || hostname === '::1') return true;
  if (!hostname) return false;
  const octets = hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function canonicalComparableHost(value: string): string | undefined {
  if (!value || value.length > 253 || /[\s/?#@*\\]/u.test(value)) return undefined;
  const unwrapped = value.startsWith('[') && value.endsWith(']')
    ? value.slice(1, -1)
    : value;
  if (!unwrapped || unwrapped.includes('[') || unwrapped.includes(']')) return undefined;
  return unwrapped.toLowerCase();
}

function isNonEmptyCredential(
  login: AutofillLoginData,
): login is { readonly username: string; readonly password: string } {
  return typeof login?.username === 'string'
    && login.username.trim().length > 0
    && typeof login.password === 'string'
    && login.password.length > 0;
}

function isSha256Hex(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function assertActive(active: () => boolean): void {
  if (!active()) throw new Error('HTTP authentication callback expired');
}

function normalizeDeadline(value: number | undefined): number {
  return Number.isFinite(value) && value! > 0 && value! <= HTTP_AUTH_CALLBACK_DEADLINE_MS
    ? Math.floor(value!)
    : HTTP_AUTH_CALLBACK_DEADLINE_MS;
}
