import { isLoginCustomPlanDigest } from '../core/vault/login-custom-fields.js';
import { isIsoTimestamp } from '../core/vault/iso-date.js';

export const DEFAULT_MANUAL_AUTOFILL_GRANT_TTL_MS = 30_000;
export const MAX_MANUAL_AUTOFILL_GRANT_TTL_MS = 60_000;
export const DEFAULT_MANUAL_AUTOFILL_GRANT_CAPACITY = 32;
export const MAX_MANUAL_AUTOFILL_GRANT_CAPACITY = 256;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUNTIME_INCARNATION = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 16_384;
const BINDING_KEYS = [
  'popupDocumentId', 'cipherId', 'tabId', 'topUrl', 'frameUrl', 'frameId',
  'targetDocumentId', 'runtimeIncarnation', 'formId', 'generation', 'customPlanDigest', 'cipherRevision',
  'uriDigest', 'risk', 'requiresReprompt',
] as const;
const ISSUE_KEYS = [
  ...BINDING_KEYS, 'allowedActions', 'sessionLease', 'accountLease',
  'autofillPolicyLease', 'enterprisePolicyLease', 'vaultAuthority',
] as const;
const CALLER_CONTEXT_KEYS = ['popupDocumentId'] as const;

export type ManualAutofillRisk = 'no_match' | 'never' | 'https_downgrade';
export type ManualAutofillGrantAction = 'fill_only' | 'fill_and_save';
export type ManualAutofillAllowedActions =
  | readonly ['fill_only']
  | readonly ['fill_only', 'fill_and_save'];

/** Metadata-only snapshot re-resolved by the worker immediately before grant redemption. */
export interface ManualAutofillGrantBinding {
  readonly popupDocumentId: string;
  readonly cipherId: string;
  readonly tabId: number;
  readonly topUrl: string;
  readonly frameUrl: string;
  readonly frameId: number;
  readonly targetDocumentId: string;
  readonly runtimeIncarnation: string;
  readonly formId: string;
  readonly generation: number;
  readonly customPlanDigest: string;
  readonly cipherRevision: string;
  readonly uriDigest: string;
  readonly risk: ManualAutofillRisk;
  readonly requiresReprompt: boolean;
}

export interface ManualAutofillGrantIssue<S, A, P, E, V> extends ManualAutofillGrantBinding {
  readonly allowedActions: ManualAutofillAllowedActions;
  readonly sessionLease: S;
  readonly accountLease: A;
  readonly autofillPolicyLease: P;
  readonly enterprisePolicyLease: E;
  readonly vaultAuthority: V;
}

/** The only serializable value returned to the Popup. It contains no vault data or leases. */
export interface ManualAutofillGrantReceipt {
  readonly grantId: string;
  readonly expiresAt: number;
}

/** Trusted sender context supplied by the worker, never by the Popup request payload. */
export interface ManualAutofillGrantCallerContext {
  readonly popupDocumentId: string;
}

/** Internal proof retained only for the one worker operation that consumed the Popup grant. */
export interface RedeemedManualAutofillGrant<S, A, P, E, V> {
  readonly action: ManualAutofillGrantAction;
  readonly expiresAt: number;
  readonly binding: ManualAutofillGrantBinding;
  readonly sessionLease: S;
  readonly accountLease: A;
  readonly autofillPolicyLease: P;
  readonly enterprisePolicyLease: E;
  readonly vaultAuthority: V;
  readonly isCurrent: () => boolean;
  readonly assertCurrent: () => void;
}

export interface ManualAutofillGrantRegistryOptions<S, A, P, E, V> {
  readonly isSessionLeaseCurrent: (lease: S) => boolean;
  readonly isAccountLeaseCurrent: (lease: A) => boolean;
  readonly isAutofillPolicyLeaseCurrent: (lease: P) => boolean;
  readonly isEnterprisePolicyLeaseCurrent: (lease: E) => boolean;
  readonly isVaultAuthorityCurrent: (authority: V) => boolean;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly createToken?: () => string;
}

export type ManualAutofillGrantRegistryErrorCode =
  | 'capacity'
  | 'invalid_configuration'
  | 'invalid_grant'
  | 'token_collision'
  | 'token_generation';

export class ManualAutofillGrantRegistryError extends Error {
  constructor(readonly code: ManualAutofillGrantRegistryErrorCode, message: string) {
    super(message);
    this.name = 'ManualAutofillGrantRegistryError';
  }
}

interface StoredGrant<S, A, P, E, V> {
  readonly binding: ManualAutofillGrantBinding;
  readonly allowedActions: ManualAutofillAllowedActions;
  readonly sessionLease: S;
  readonly accountLease: A;
  readonly autofillPolicyLease: P;
  readonly enterprisePolicyLease: E;
  readonly vaultAuthority: V;
  readonly expiresAt: number;
  readonly revocationEpoch: symbol;
}

interface CanonicalIssue<S, A, P, E, V> {
  readonly binding: ManualAutofillGrantBinding;
  readonly allowedActions: ManualAutofillAllowedActions;
  readonly sessionLease: S;
  readonly accountLease: A;
  readonly autofillPolicyLease: P;
  readonly enterprisePolicyLease: E;
  readonly vaultAuthority: V;
}

/**
 * One-time, in-memory authorization for a Popup-selected login whose URI does not match the page.
 * Only metadata digests and opaque leases are retained; plaintext vault secrets are never accepted.
 */
export class ManualAutofillGrantRegistry<S, A, P, E, V> {
  readonly #entries = new Map<string, StoredGrant<S, A, P, E, V>>();
  /** Recent ABA tombstones are TTL-pruned and capacity-bounded to avoid worker-lifetime growth. */
  readonly #retiredGrantIds = new Map<string, number>();
  readonly #options: ManualAutofillGrantRegistryOptions<S, A, P, E, V>;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  #revocationEpoch = Symbol('manualAutofillGrantEpoch');

  constructor(options: ManualAutofillGrantRegistryOptions<S, A, P, E, V>) {
    if (typeof options?.isSessionLeaseCurrent !== 'function'
      || typeof options.isAccountLeaseCurrent !== 'function'
      || typeof options.isAutofillPolicyLeaseCurrent !== 'function'
      || typeof options.isEnterprisePolicyLeaseCurrent !== 'function'
      || typeof options.isVaultAuthorityCurrent !== 'function') {
      throw error('invalid_configuration', 'Manual autofill grant lease validators are required');
    }
    this.#options = options;
    this.#ttlMs = boundedInteger(
      options.ttlMs ?? DEFAULT_MANUAL_AUTOFILL_GRANT_TTL_MS,
      MAX_MANUAL_AUTOFILL_GRANT_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedInteger(
      options.maxEntries ?? DEFAULT_MANUAL_AUTOFILL_GRANT_CAPACITY,
      MAX_MANUAL_AUTOFILL_GRANT_CAPACITY,
      'maxEntries',
    );
  }

  issue(input: ManualAutofillGrantIssue<S, A, P, E, V>): ManualAutofillGrantReceipt {
    const now = this.#time();
    const canonical = canonicalIssue<S, A, P, E, V>(input);
    if (!this.#leasesCurrent(canonical)) {
      throw error('invalid_grant', 'Manual autofill grant leases are not current');
    }
    this.#prune(now);
    if (this.#entries.size >= this.#maxEntries) {
      throw error('capacity', `Manual autofill grant capacity (${this.#maxEntries}) was reached`);
    }
    const grantId = this.#freshId();
    const expiresAt = now + this.#ttlMs;
    if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > Number.MAX_SAFE_INTEGER) {
      throw error('invalid_configuration', 'Manual autofill grant expiry is invalid');
    }
    this.#entries.set(grantId, Object.freeze({
      binding: canonical.binding,
      allowedActions: canonical.allowedActions,
      sessionLease: canonical.sessionLease,
      accountLease: canonical.accountLease,
      autofillPolicyLease: canonical.autofillPolicyLease,
      enterprisePolicyLease: canonical.enterprisePolicyLease,
      vaultAuthority: canonical.vaultAuthority,
      expiresAt,
      revocationEpoch: this.#revocationEpoch,
    }));
    return Object.freeze({ grantId, expiresAt });
  }

  /** Consume before validating any context field, selected action, deadline, or lease. */
  redeem(
    grantId: string,
    caller: ManualAutofillGrantCallerContext,
    action: ManualAutofillGrantAction,
  ): RedeemedManualAutofillGrant<S, A, P, E, V> | undefined {
    const grant = this.#consume(grantId, caller, action);
    if (!grant) return undefined;
    const proof = Object.create(null) as RedeemedManualAutofillGrant<S, A, P, E, V>;
    Object.defineProperties(proof, {
      action: property(action, true),
      expiresAt: property(grant.expiresAt, true),
      // Opaque leases and methods stay out of accidental JSON serialization.
      binding: property(grant.binding, false),
      sessionLease: property(grant.sessionLease, false),
      accountLease: property(grant.accountLease, false),
      autofillPolicyLease: property(grant.autofillPolicyLease, false),
      enterprisePolicyLease: property(grant.enterprisePolicyLease, false),
      vaultAuthority: property(grant.vaultAuthority, false),
      isCurrent: property(() => this.#redeemedCurrent(grant), false),
      assertCurrent: property(() => this.#assertRedeemedCurrent(grant), false),
    });
    return Object.freeze(proof);
  }

  /** Closing the confirmation consumes the grant too, including on a mismatched cancellation. */
  cancel(grantId: string, caller: ManualAutofillGrantCallerContext): boolean {
    return this.#consume(grantId, caller, null) !== undefined;
  }

  /** Revoke outstanding grants and already-redeemed proofs before any security-state transition. */
  revokeAll(): void {
    try {
      const now = this.#time();
      this.#prune(now);
      for (const [grantId, grant] of this.#entries) {
        this.#retiredGrantIds.set(grantId, grant.expiresAt);
      }
      this.#boundRetired();
    } catch {
      this.#retiredGrantIds.clear();
    }
    this.#entries.clear();
    this.#revocationEpoch = Symbol('manualAutofillGrantEpoch');
  }

  #consume(
    grantId: string,
    callerInput: ManualAutofillGrantCallerContext,
    unsafeAction: ManualAutofillGrantAction | null,
  ): StoredGrant<S, A, P, E, V> | undefined {
    const grant = typeof grantId === 'string' ? this.#entries.get(grantId) : undefined;
    if (grant) {
      this.#entries.delete(grantId);
      this.#retiredGrantIds.set(grantId, grant.expiresAt);
      this.#boundRetired();
    }

    let now: number | undefined;
    let caller: ManualAutofillGrantCallerContext | undefined;
    let action: ManualAutofillGrantAction | undefined;
    try { now = this.#time(); } catch { /* Fail closed below. */ }
    try { caller = canonicalCallerContext(callerInput); } catch { /* Fail closed below. */ }
    try { action = unsafeAction === null ? undefined : validAction(unsafeAction); } catch {
      // Fail closed below.
    }
    if (now !== undefined) this.#prune(now);
    const leasesCurrent = grant ? this.#leasesCurrent(grant) : false;
    if (!grant || now === undefined || !caller || !UUID_V4.test(grantId)
      || grant.expiresAt <= now || grant.revocationEpoch !== this.#revocationEpoch
      || grant.binding.popupDocumentId !== caller.popupDocumentId || !leasesCurrent
      || (unsafeAction !== null && (!action || !actionAllowed(grant.allowedActions, action)))) {
      return undefined;
    }
    return grant;
  }

  #leasesCurrent(value: Pick<StoredGrant<S, A, P, E, V>,
    | 'sessionLease' | 'accountLease' | 'autofillPolicyLease'
    | 'enterprisePolicyLease' | 'vaultAuthority'>): boolean {
    // Do not short-circuit the callbacks; all four security authorities are equally mandatory.
    const session = safeCurrent(this.#options.isSessionLeaseCurrent, value.sessionLease);
    const account = safeCurrent(this.#options.isAccountLeaseCurrent, value.accountLease);
    const autofill = safeCurrent(
      this.#options.isAutofillPolicyLeaseCurrent,
      value.autofillPolicyLease,
    );
    const enterprise = safeCurrent(
      this.#options.isEnterprisePolicyLeaseCurrent,
      value.enterprisePolicyLease,
    );
    const vault = safeCurrent(this.#options.isVaultAuthorityCurrent, value.vaultAuthority);
    return session && account && autofill && enterprise && vault;
  }

  #redeemedCurrent(grant: StoredGrant<S, A, P, E, V>): boolean {
    let now: number;
    try { now = this.#time(); } catch { return false; }
    return grant.revocationEpoch === this.#revocationEpoch
      && grant.expiresAt > now
      && this.#leasesCurrent(grant);
  }

  #assertRedeemedCurrent(grant: StoredGrant<S, A, P, E, V>): void {
    if (!this.#redeemedCurrent(grant)) {
      throw error('invalid_grant', 'Manual autofill grant is no longer current');
    }
  }

  #time(): number {
    const value = this.#options.now?.() ?? Date.now();
    if (!Number.isFinite(value) || value < 0) {
      throw error('invalid_configuration', 'Manual autofill grant clock is invalid');
    }
    return value;
  }

  #prune(now: number): void {
    for (const [grantId, grant] of this.#entries) {
      if (grant.expiresAt <= now) this.#entries.delete(grantId);
    }
    for (const [grantId, expiresAt] of this.#retiredGrantIds) {
      if (expiresAt <= now) this.#retiredGrantIds.delete(grantId);
    }
  }

  #boundRetired(): void {
    while (this.#retiredGrantIds.size > this.#maxEntries) {
      const oldest = this.#retiredGrantIds.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#retiredGrantIds.delete(oldest);
    }
  }

  #freshId(): string {
    const create = this.#options.createToken ?? (() => globalThis.crypto.randomUUID());
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let token: string;
      try { token = create(); } catch {
        throw error('token_generation', 'Could not create a manual autofill grant');
      }
      if (!UUID_V4.test(token)) {
        throw error('token_generation', 'Manual autofill grant must be a UUID v4');
      }
      if (!this.#entries.has(token) && !this.#retiredGrantIds.has(token)) return token;
    }
    throw error('token_collision', 'Manual autofill grant token collision');
  }
}

function canonicalIssue<S, A, P, E, V>(
  value: ManualAutofillGrantIssue<S, A, P, E, V>,
): CanonicalIssue<S, A, P, E, V> {
  const record = exactDataRecord(value, ISSUE_KEYS);
  const binding = canonicalBindingRecord(record);
  const actions = allowedActions(dataValue(record, 'allowedActions'));
  if (actions.length === 2 && binding.risk !== 'no_match') invalid('allowedActions');
  return Object.freeze({
    binding,
    allowedActions: actions,
    sessionLease: lease<S>(dataValue(record, 'sessionLease')),
    accountLease: lease<A>(dataValue(record, 'accountLease')),
    autofillPolicyLease: lease<P>(dataValue(record, 'autofillPolicyLease')),
    enterprisePolicyLease: lease<E>(dataValue(record, 'enterprisePolicyLease')),
    vaultAuthority: lease<V>(dataValue(record, 'vaultAuthority')),
  });
}

function canonicalCallerContext(value: ManualAutofillGrantCallerContext): ManualAutofillGrantCallerContext {
  const record = exactDataRecord(value, CALLER_CONTEXT_KEYS);
  return Object.freeze({
    popupDocumentId: opaqueId(dataValue(record, 'popupDocumentId'), 'popupDocumentId'),
  });
}

function canonicalBindingRecord(record: Record<string, unknown>): ManualAutofillGrantBinding {
  const popupDocumentId = opaqueId(dataValue(record, 'popupDocumentId'), 'popupDocumentId');
  const cipherId = opaqueId(dataValue(record, 'cipherId'), 'cipherId');
  const tabId = nonNegativeInteger(dataValue(record, 'tabId'), 'tabId');
  const topUrl = httpUrl(dataValue(record, 'topUrl'), 'topUrl');
  const frameUrl = httpUrl(dataValue(record, 'frameUrl'), 'frameUrl');
  const frameId = nonNegativeInteger(dataValue(record, 'frameId'), 'frameId');
  const targetDocumentId = opaqueId(dataValue(record, 'targetDocumentId'), 'targetDocumentId');
  const runtimeIncarnation = canonicalRuntimeIncarnation(dataValue(record, 'runtimeIncarnation'));
  const formId = opaqueId(dataValue(record, 'formId'), 'formId');
  const generation = nonNegativeInteger(dataValue(record, 'generation'), 'generation');
  const customPlanDigest = dataValue(record, 'customPlanDigest');
  if (!isLoginCustomPlanDigest(customPlanDigest)) invalid('customPlanDigest');
  const cipherRevision = dataValue(record, 'cipherRevision');
  if (!isIsoTimestamp(cipherRevision)) invalid('cipherRevision');
  const uriDigest = dataValue(record, 'uriDigest');
  if (typeof uriDigest !== 'string' || !SHA256_HEX.test(uriDigest)) invalid('uriDigest');
  const risk = validRisk(dataValue(record, 'risk'));
  const requiresReprompt = dataValue(record, 'requiresReprompt');
  if (typeof requiresReprompt !== 'boolean') invalid('requiresReprompt');
  return Object.freeze({
    popupDocumentId, cipherId, tabId, topUrl, frameUrl, frameId, targetDocumentId,
    runtimeIncarnation,
    formId, generation, customPlanDigest, cipherRevision, uriDigest, risk, requiresReprompt,
  });
}

function canonicalRuntimeIncarnation(value: unknown): string {
  if (typeof value !== 'string' || !RUNTIME_INCARNATION.test(value)) {
    invalid('runtimeIncarnation');
  }
  return value;
}

function allowedActions(value: unknown): ManualAutofillAllowedActions {
  if (!denseDataArray(value) || (value.length !== 1 && value.length !== 2)
    || value[0] !== 'fill_only' || (value.length === 2 && value[1] !== 'fill_and_save')) {
    invalid('allowedActions');
  }
  return value.length === 1
    ? Object.freeze(['fill_only'] as const)
    : Object.freeze(['fill_only', 'fill_and_save'] as const);
}

function validRisk(value: unknown): ManualAutofillRisk {
  if (value !== 'no_match' && value !== 'never' && value !== 'https_downgrade') invalid('risk');
  return value;
}

function validAction(value: unknown): ManualAutofillGrantAction {
  if (value !== 'fill_only' && value !== 'fill_and_save') invalid('action');
  return value;
}

function actionAllowed(
  allowed: ManualAutofillAllowedActions,
  action: ManualAutofillGrantAction,
): boolean {
  return action === 'fill_only' || (allowed.length === 2 && action === 'fill_and_save');
}

function lease<T>(value: unknown): T {
  if (value === null || value === undefined) invalid('lease');
  return value as T;
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) invalid(field);
  return value as number;
}

function opaqueId(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH
    || value.trim() !== value || hasControl(value)) invalid(field);
  return value;
}

function hasControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function httpUrl(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LENGTH) invalid(field);
  let url: URL;
  try { url = new URL(value); } catch { invalid(field); }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password
    || url.href.length > MAX_URL_LENGTH) invalid(field);
  return url.href;
}

function exactDataRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid('shape');
    prototype = Object.getPrototypeOf(value) as object | null;
    keys = Reflect.ownKeys(value);
  } catch {
    invalid('shape');
  }
  if (prototype !== Object.prototype && prototype !== null || keys.length !== expectedKeys.length) {
    invalid('shape');
  }
  const expected = new Set(expectedKeys);
  for (const key of keys) {
    if (typeof key !== 'string' || !expected.has(key)) invalid('shape');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) invalid('shape');
  }
  return value as Record<string, unknown>;
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !('value' in descriptor)) invalid('shape');
  return descriptor.value as unknown;
}

function denseDataArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return keys.every((key) => key === 'length'
    || (typeof key === 'string' && /^(0|[1-9]\d*)$/.test(key)));
}

function safeCurrent<T>(validator: (leaseValue: T) => boolean, value: T): boolean {
  try { return validator(value) === true; } catch { return false; }
}

function boundedInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw error('invalid_configuration', `${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

function property(value: unknown, enumerable: boolean): PropertyDescriptor {
  return { value, enumerable, writable: false, configurable: false };
}

function invalid(field: string): never {
  throw error('invalid_grant', `Manual autofill grant ${field} is invalid`);
}

function error(
  code: ManualAutofillGrantRegistryErrorCode,
  message: string,
): ManualAutofillGrantRegistryError {
  return new ManualAutofillGrantRegistryError(code, message);
}
