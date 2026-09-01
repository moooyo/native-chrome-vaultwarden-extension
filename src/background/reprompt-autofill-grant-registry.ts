export const DEFAULT_REPROMPT_AUTOFILL_GRANT_TTL_MS = 30_000;
export const MAX_REPROMPT_AUTOFILL_GRANT_TTL_MS = 60_000;
export const DEFAULT_REPROMPT_AUTOFILL_GRANT_CAPACITY = 32;
export const MAX_REPROMPT_AUTOFILL_GRANT_CAPACITY = 256;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_OPAQUE_ID_LENGTH = 4_096;
const MAX_TARGET_KEY_LENGTH = 16_384;
const MAX_URL_LENGTH = 16_384;

export interface RepromptAutofillGrantBinding {
  readonly popupDocumentId: string;
  readonly cipherId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly targetDocumentId: string;
  readonly topUrl: string;
  readonly frameUrl: string;
  readonly targetKey: string;
}

export interface RepromptAutofillGrantIssue<SessionLease, AccountLease, PolicyLease>
  extends RepromptAutofillGrantBinding {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
}

export interface RepromptAutofillGrantReceipt {
  readonly authorizationId: string;
  readonly expiresAt: number;
}

export interface RedeemedRepromptAutofillGrant<SessionLease, AccountLease, PolicyLease> {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly expiresAt: number;
  readonly isCurrent: () => boolean;
}

export interface RepromptAutofillGrantRegistryOptions<SessionLease, AccountLease, PolicyLease> {
  readonly isSessionLeaseCurrent: (lease: SessionLease) => boolean;
  readonly isAccountLeaseCurrent: (lease: AccountLease) => boolean;
  readonly isPolicyLeaseCurrent: (lease: PolicyLease) => boolean;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly createToken?: () => string;
}

export type RepromptAutofillGrantRegistryErrorCode =
  | 'capacity'
  | 'invalid_configuration'
  | 'invalid_grant'
  | 'token_collision'
  | 'token_generation';

export class RepromptAutofillGrantRegistryError extends Error {
  constructor(
    readonly code: RepromptAutofillGrantRegistryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'RepromptAutofillGrantRegistryError';
  }
}

type CanonicalGrantBinding = RepromptAutofillGrantBinding;

interface StoredRepromptAutofillGrant<SessionLease, AccountLease, PolicyLease>
  extends CanonicalGrantBinding {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly expiresAt: number;
  readonly revocationEpoch: symbol;
}

/**
 * In-memory, one-time authorization for one reprompt-cleared Popup login fill. Callers can only
 * issue or consume an opaque token for the exact Popup document, cipher, browser document, URL,
 * target snapshot, and current security leases. No password or key material is retained here.
 */
export class RepromptAutofillGrantRegistry<SessionLease, AccountLease, PolicyLease> {
  readonly #entries = new Map<string, StoredRepromptAutofillGrant<SessionLease, AccountLease, PolicyLease>>();
  readonly #isSessionLeaseCurrent: (lease: SessionLease) => boolean;
  readonly #isAccountLeaseCurrent: (lease: AccountLease) => boolean;
  readonly #isPolicyLeaseCurrent: (lease: PolicyLease) => boolean;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #createToken: () => string;
  #revocationEpoch = Symbol('repromptAutofillGrantEpoch');

  constructor(options: RepromptAutofillGrantRegistryOptions<SessionLease, AccountLease, PolicyLease>) {
    if (
      typeof options?.isSessionLeaseCurrent !== 'function'
      || typeof options.isAccountLeaseCurrent !== 'function'
      || typeof options.isPolicyLeaseCurrent !== 'function'
    ) {
      throw grantError('invalid_configuration', 'Reprompt autofill grant lease validators are required');
    }
    this.#isSessionLeaseCurrent = options.isSessionLeaseCurrent;
    this.#isAccountLeaseCurrent = options.isAccountLeaseCurrent;
    this.#isPolicyLeaseCurrent = options.isPolicyLeaseCurrent;
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_REPROMPT_AUTOFILL_GRANT_TTL_MS,
      MAX_REPROMPT_AUTOFILL_GRANT_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_REPROMPT_AUTOFILL_GRANT_CAPACITY,
      MAX_REPROMPT_AUTOFILL_GRANT_CAPACITY,
      'maxEntries',
    );
    this.#now = options.now ?? (() => performance.now());
    this.#createToken = options.createToken ?? (() => globalThis.crypto.randomUUID());
  }

  issue(
    input: RepromptAutofillGrantIssue<SessionLease, AccountLease, PolicyLease>,
  ): RepromptAutofillGrantReceipt {
    const now = this.#currentTime();
    const binding = canonicalizeBinding(input);
    if (!this.#leasesAreCurrent(input.sessionLease, input.accountLease, input.policyLease)) {
      throw grantError('invalid_grant', 'Reprompt autofill grant leases are not current');
    }
    this.#pruneExpired(now);
    if (this.#entries.size >= this.#maxEntries) {
      throw grantError('capacity', `Reprompt autofill grant capacity (${this.#maxEntries}) was reached`);
    }

    const authorizationId = this.#freshToken();
    const expiresAt = now + this.#ttlMs;
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      throw grantError('invalid_configuration', 'Reprompt autofill grant expiry is invalid');
    }
    this.#entries.set(authorizationId, Object.freeze({
      ...binding,
      sessionLease: input.sessionLease,
      accountLease: input.accountLease,
      policyLease: input.policyLease,
      expiresAt,
      revocationEpoch: this.#revocationEpoch,
    }));
    return Object.freeze({ authorizationId, expiresAt });
  }

  /** Consume before validation so no stale, mismatched, or malformed grant can be retried. */
  redeem(
    authorizationId: string,
    input: RepromptAutofillGrantBinding,
  ): RedeemedRepromptAutofillGrant<SessionLease, AccountLease, PolicyLease> | undefined {
    const issued = this.#entries.get(authorizationId);
    if (issued) this.#entries.delete(authorizationId);

    let now: number;
    let binding: CanonicalGrantBinding;
    try {
      now = this.#currentTime();
      binding = canonicalizeBinding(input);
    } catch {
      return undefined;
    }
    this.#pruneExpired(now);
    if (
      !issued
      || !UUID_V4.test(authorizationId)
      || issued.expiresAt <= now
      || !sameBinding(issued, binding)
      || !this.#leasesAreCurrent(issued.sessionLease, issued.accountLease, issued.policyLease)
    ) {
      return undefined;
    }
    return Object.freeze({
      sessionLease: issued.sessionLease,
      accountLease: issued.accountLease,
      policyLease: issued.policyLease,
      expiresAt: issued.expiresAt,
      isCurrent: () => this.#redeemedGrantIsCurrent(issued),
    });
  }

  /** Revoke outstanding authorizations synchronously when authentication state begins changing. */
  revokeAll(): void {
    this.#entries.clear();
    this.#revocationEpoch = Symbol('repromptAutofillGrantEpoch');
  }

  #redeemedGrantIsCurrent(
    grant: StoredRepromptAutofillGrant<SessionLease, AccountLease, PolicyLease>,
  ): boolean {
    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      return false;
    }
    return grant.revocationEpoch === this.#revocationEpoch
      && grant.expiresAt > now
      && this.#leasesAreCurrent(grant.sessionLease, grant.accountLease, grant.policyLease);
  }

  #leasesAreCurrent(
    sessionLease: SessionLease,
    accountLease: AccountLease,
    policyLease: PolicyLease,
  ): boolean {
    return safelyCurrent(this.#isSessionLeaseCurrent, sessionLease)
      && safelyCurrent(this.#isAccountLeaseCurrent, accountLease)
      && safelyCurrent(this.#isPolicyLeaseCurrent, policyLease);
  }

  #currentTime(): number {
    const value = this.#now();
    if (!Number.isFinite(value) || value < 0) {
      throw grantError('invalid_configuration', 'Reprompt autofill grant clock is invalid');
    }
    return value;
  }

  #pruneExpired(now: number): void {
    for (const [authorizationId, grant] of this.#entries) {
      if (grant.expiresAt <= now) this.#entries.delete(authorizationId);
    }
  }

  #freshToken(): string {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let token: string;
      try {
        token = this.#createToken();
      } catch {
        throw grantError('token_generation', 'Could not create a reprompt autofill grant');
      }
      if (!UUID_V4.test(token)) {
        throw grantError('token_generation', 'Reprompt autofill grant must be a canonical UUID v4');
      }
      if (!this.#entries.has(token)) return token;
    }
    throw grantError('token_collision', 'Reprompt autofill grant token collision');
  }
}

function canonicalizeBinding(value: RepromptAutofillGrantBinding): CanonicalGrantBinding {
  assertOpaqueId(value?.popupDocumentId, 'popupDocumentId');
  assertOpaqueId(value.cipherId, 'cipherId');
  if (!Number.isSafeInteger(value.tabId) || value.tabId < 0) invalidGrant('tabId');
  if (!Number.isSafeInteger(value.frameId) || value.frameId < 0) invalidGrant('frameId');
  assertOpaqueId(value.targetDocumentId, 'targetDocumentId');
  assertTargetKey(value.targetKey);
  return Object.freeze({
    popupDocumentId: value.popupDocumentId,
    cipherId: value.cipherId,
    tabId: value.tabId,
    frameId: value.frameId,
    targetDocumentId: value.targetDocumentId,
    topUrl: canonicalHttpUrl(value.topUrl),
    frameUrl: canonicalHttpUrl(value.frameUrl),
    targetKey: value.targetKey,
  });
}

function sameBinding(left: CanonicalGrantBinding, right: CanonicalGrantBinding): boolean {
  return left.popupDocumentId === right.popupDocumentId
    && left.cipherId === right.cipherId
    && left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.targetDocumentId === right.targetDocumentId
    && left.topUrl === right.topUrl
    && left.frameUrl === right.frameUrl
    && left.targetKey === right.targetKey;
}

function assertOpaqueId(value: unknown, field: string): asserts value is string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_OPAQUE_ID_LENGTH
    || value.trim() !== value
  ) invalidGrant(field);
}

function assertTargetKey(value: unknown): asserts value is string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_TARGET_KEY_LENGTH
    || value.trim() !== value
  ) invalidGrant('targetKey');
}

function canonicalHttpUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LENGTH) {
    invalidGrant('URL');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    invalidGrant('URL');
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
    invalidGrant('URL');
  }
  if (url.href.length > MAX_URL_LENGTH) invalidGrant('URL');
  return url.href;
}

function safelyCurrent<Lease>(validator: (lease: Lease) => boolean, lease: Lease): boolean {
  try {
    return validator(lease) === true;
  } catch {
    return false;
  }
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw grantError('invalid_configuration', `${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

function invalidGrant(field: string): never {
  throw grantError('invalid_grant', `Reprompt autofill grant ${field} is invalid`);
}

function grantError(
  code: RepromptAutofillGrantRegistryErrorCode,
  message: string,
): RepromptAutofillGrantRegistryError {
  return new RepromptAutofillGrantRegistryError(code, message);
}
