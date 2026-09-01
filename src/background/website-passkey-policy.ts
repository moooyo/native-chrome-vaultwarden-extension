import { AppError } from '../core/errors.js';
import {
  DEFAULT_WEBSITE_PASSKEY_SETTINGS,
  sanitizeWebsitePasskeySettings,
  type WebsitePasskeySettings,
} from './settings.js';
import {
  decideAutofillPolicy,
  normalizeAutofillBlocklist,
  type NormalizedAutofillBlocklist,
} from '../core/vault/autofill-policy.js';

const POLICY_LEASE_OWNER: unique symbol = Symbol('websitePasskeyPolicyLeaseOwner');

export interface WebsitePasskeyPolicyLease {
  readonly generation: number;
}

interface OwnedWebsitePasskeyPolicyLease extends WebsitePasskeyPolicyLease {
  readonly [POLICY_LEASE_OWNER]: symbol;
}

export interface WebsitePasskeyPolicySource {
  readonly settings: WebsitePasskeySettings;
  readonly configuredVaultUrl?: string;
  readonly blockedDomains?: readonly string[];
}

export interface WebsitePasskeyPolicyDecision {
  readonly enabled: boolean;
  readonly allowed: boolean;
  readonly host?: string;
}

export interface WebsitePasskeyPolicyGateDeps {
  /** Existing interaction policy. `true` means the browser-authoritative URL is blocked. */
  readonly isInteractionBlocked?: (browserUrl: string) => boolean;
}

interface WebsitePasskeyPolicySnapshot {
  readonly enabled: boolean;
  readonly excludedDomains: readonly string[];
  readonly configuredVaultOrigin?: string;
  readonly blockedInteractions: NormalizedAutofillBlocklist;
}

/** Revocable, fail-closed authorization fence for website WebAuthn interception. */
export class WebsitePasskeyPolicyGate {
  readonly #owner = Symbol('websitePasskeyPolicyGate');
  readonly #issued = new WeakSet<object>();
  readonly #deps: WebsitePasskeyPolicyGateDeps;
  #generation = 0;
  #snapshot: WebsitePasskeyPolicySnapshot | undefined;

  constructor(deps: WebsitePasskeyPolicyGateDeps = {}) {
    this.#deps = deps;
  }

  /** Publish one immutable settings/server snapshot and revoke every lease from the prior snapshot. */
  publish(source: WebsitePasskeyPolicySource): void {
    this.#generation += 1;
    this.#snapshot = undefined;

    const settings = sanitizeWebsitePasskeySettings(source.settings);
    const blockedInteractions = normalizeAutofillBlocklist(source.blockedDomains ?? []);
    if (!blockedInteractions.valid) {
      throw new AppError('denied', 'Website passkey interaction policy is invalid');
    }
    const configuredVaultOrigin = source.configuredVaultUrl === undefined
      ? undefined
      : parseStrictHttpUrl(source.configuredVaultUrl)?.origin;
    if (source.configuredVaultUrl !== undefined && configuredVaultOrigin === undefined) {
      throw new AppError('denied', 'Website passkey policy has an invalid vault URL');
    }
    this.#snapshot = Object.freeze({
      enabled: settings.enabled,
      excludedDomains: Object.freeze([...settings.excludedDomains]),
      blockedInteractions,
      ...(configuredVaultOrigin === undefined ? {} : { configuredVaultOrigin }),
    });
  }

  /** Revoke all issued leases and remove the active policy until a fresh snapshot is published. */
  invalidate(): void {
    this.#generation += 1;
    this.#snapshot = undefined;
  }

  capture(): WebsitePasskeyPolicyLease {
    const lease = Object.freeze({ generation: this.#generation, [POLICY_LEASE_OWNER]: this.#owner });
    this.#issued.add(lease);
    return lease;
  }

  assert(lease: WebsitePasskeyPolicyLease): void {
    const owned = lease as Partial<OwnedWebsitePasskeyPolicyLease>;
    if (
      typeof lease !== 'object'
      || lease === null
      || !this.#issued.has(lease)
      || owned[POLICY_LEASE_OWNER] !== this.#owner
      || lease.generation !== this.#generation
      || this.#snapshot === undefined
    ) {
      throw new AppError('denied', 'Website passkey policy changed during operation');
    }
  }

  /** Evaluate exactly one browser-owned URL and expose no raw policy or vault-origin data. */
  evaluate(lease: WebsitePasskeyPolicyLease, browserUrl: string): Readonly<WebsitePasskeyPolicyDecision> {
    this.assert(lease);
    const snapshot = this.#snapshot!;
    const parsed = parseStrictHttpUrl(browserUrl);
    if (!parsed) {
      return Object.freeze({ enabled: snapshot.enabled, allowed: false });
    }

    const host = parsed.hostname;
    const protocolAllowed = parsed.protocol === 'https:'
      || (parsed.protocol === 'http:' && isSupportedHttpLoopback(host));
    const excluded = snapshot.excludedDomains.includes(host);
    const isVaultOrigin = snapshot.configuredVaultOrigin === parsed.origin;
    const blockedByAutofillPolicy = !decideAutofillPolicy(snapshot.blockedInteractions, {
      action: 'candidate',
      url: parsed.href,
    }).allowed;
    let interactionBlocked = false;
    if (this.#deps.isInteractionBlocked) {
      try {
        interactionBlocked = this.#deps.isInteractionBlocked(parsed.href) !== false;
      } catch {
        interactionBlocked = true;
      }
    }

    // The injected decision may synchronously invalidate policy; never return an authorization then.
    this.assert(lease);
    return Object.freeze({
      enabled: snapshot.enabled,
      allowed: snapshot.enabled
        && protocolAllowed
        && !excluded
        && !isVaultOrigin
        && !blockedByAutofillPolicy
        && !interactionBlocked,
      host,
    });
  }

  /** Re-evaluate and assert immediately before an authorized action. */
  assertAllowed(
    lease: WebsitePasskeyPolicyLease,
    browserUrl: string,
  ): Readonly<WebsitePasskeyPolicyDecision & { allowed: true }> {
    const decision = this.evaluate(lease, browserUrl);
    if (!decision.allowed) throw new AppError('denied', 'Website passkey interaction is not allowed');
    this.assert(lease);
    return decision as Readonly<WebsitePasskeyPolicyDecision & { allowed: true }>;
  }
}

/** A disabled snapshot is useful for callers that want an explicit startup publication. */
export function defaultWebsitePasskeyPolicySource(): WebsitePasskeyPolicySource {
  return Object.freeze({ settings: DEFAULT_WEBSITE_PASSKEY_SETTINGS, blockedDomains: Object.freeze([]) });
}

interface ParsedPolicyUrl {
  readonly href: string;
  readonly origin: string;
  readonly protocol: 'http:' | 'https:';
  readonly hostname: string;
}

function parseStrictHttpUrl(value: string): ParsedPolicyUrl | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value || containsControlCharacter(value)) {
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
    return undefined;
  }
  const hostname = canonicalUrlHostname(url.hostname);
  if (!hostname) return undefined;
  const authority = url.port ? `${hostname}:${url.port}` : hostname;
  const origin = `${url.protocol}//${authority}`;
  return Object.freeze({
    href: `${origin}${url.pathname}${url.search}${url.hash}`,
    origin,
    protocol: url.protocol,
    hostname,
  });
}

function canonicalUrlHostname(hostname: string): string {
  const lowered = hostname.toLowerCase();
  return !lowered.startsWith('[') && lowered.endsWith('.') ? lowered.slice(0, -1) : lowered;
}

function isSupportedHttpLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1';
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}
