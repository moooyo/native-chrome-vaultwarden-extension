import type {
  AutofillSecretPurpose,
  ContentStructuredAutofillTarget,
} from '../messaging/protocol.js';
import { normalizeFillRoles, type FillKind, type FillRole } from '../core/vault/fill-roles.js';
import {
  isLoginCustomPlanDigest,
  parseLoginCustomTargetPlan,
  type LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';

export const DEFAULT_AUTOFILL_INTENT_TTL_MS = 30_000;
export const DEFAULT_AUTOFILL_INTENT_CAPACITY = 128;
export const MAX_AUTOFILL_INTENT_TTL_MS = 60_000;
export const MAX_AUTOFILL_INTENT_CAPACITY = 4_096;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUNTIME_INCARNATION_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_OPAQUE_ID_LENGTH = 4_096;
const MAX_FRAME_URL_LENGTH = 16_384;

export type AutofillIntentChannel = 'interactive' | 'keyboard' | 'page-load';

export interface AutofillRepromptAuthorization {
  readonly assertCurrent: () => void;
}

export interface AutofillIntentIssue<SessionLease, AccountLease, PolicyLease> {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly frameUrl: string;
  readonly cipherId: string;
  readonly purpose: AutofillSecretPurpose;
  readonly channel: AutofillIntentChannel;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly customPlan?: LoginCustomTargetPlan;
  readonly customPlanDigest?: string;
  readonly structuredTarget?: ContentStructuredAutofillTarget;
  readonly repromptAuthorization?: AutofillRepromptAuthorization;
}

export interface AutofillIntentRedemption {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly frameUrl: string;
  readonly purpose: AutofillSecretPurpose;
  readonly channel: AutofillIntentChannel;
  readonly structuredTarget?: ContentStructuredAutofillTarget;
}

export interface RedeemedAutofillIntent<SessionLease, AccountLease, PolicyLease> {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly canonicalFrameUrl: string;
  readonly cipherId: string;
  readonly purpose: AutofillSecretPurpose;
  readonly channel: AutofillIntentChannel;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly customPlan?: LoginCustomTargetPlan;
  readonly customPlanDigest?: string;
  readonly structuredTarget?: ContentStructuredAutofillTarget;
  readonly repromptAuthorization?: AutofillRepromptAuthorization;
}

export interface AutofillIntentRegistryOptions<SessionLease, AccountLease, PolicyLease> {
  readonly isSessionLeaseCurrent: (lease: SessionLease) => boolean;
  readonly isAccountLeaseCurrent: (lease: AccountLease) => boolean;
  readonly isPolicyLeaseCurrent: (lease: PolicyLease) => boolean;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly createToken?: () => string;
}

export type AutofillIntentRegistryErrorCode =
  | 'capacity'
  | 'invalid_configuration'
  | 'invalid_intent'
  | 'token_collision'
  | 'token_generation';

export class AutofillIntentRegistryError extends Error {
  constructor(
    readonly code: AutofillIntentRegistryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AutofillIntentRegistryError';
  }
}

interface StoredAutofillIntent<SessionLease, AccountLease, PolicyLease> {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly frameUrl: string;
  readonly cipherId: string;
  readonly purpose: AutofillSecretPurpose;
  readonly channel: AutofillIntentChannel;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly expiresAt: number;
  readonly customPlan?: LoginCustomTargetPlan;
  readonly customPlanDigest?: string;
  readonly structuredTarget?: ContentStructuredAutofillTarget;
  readonly repromptAuthorization?: AutofillRepromptAuthorization;
}

interface CanonicalRedemption {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly frameUrl: string;
  readonly purpose: AutofillSecretPurpose;
  readonly channel: AutofillIntentChannel;
  readonly structuredTarget?: ContentStructuredAutofillTarget;
}

/**
 * In-memory one-time capabilities for secret autofill redemption. The registry deliberately exposes
 * no lookup, size, list, or inspection API: a caller can only issue a fresh opaque token or redeem a
 * token once with the complete browser-owned document context and current session/account leases.
 */
export class AutofillIntentRegistry<SessionLease, AccountLease, PolicyLease> {
  readonly #entries = new Map<string, StoredAutofillIntent<SessionLease, AccountLease, PolicyLease>>();
  readonly #isSessionLeaseCurrent: AutofillIntentRegistryOptions<SessionLease, AccountLease, PolicyLease>['isSessionLeaseCurrent'];
  readonly #isAccountLeaseCurrent: AutofillIntentRegistryOptions<SessionLease, AccountLease, PolicyLease>['isAccountLeaseCurrent'];
  readonly #isPolicyLeaseCurrent: AutofillIntentRegistryOptions<SessionLease, AccountLease, PolicyLease>['isPolicyLeaseCurrent'];
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #createToken: () => string;

  constructor(options: AutofillIntentRegistryOptions<SessionLease, AccountLease, PolicyLease>) {
    if (
      typeof options?.isSessionLeaseCurrent !== 'function'
      || typeof options.isAccountLeaseCurrent !== 'function'
      || typeof options.isPolicyLeaseCurrent !== 'function'
    ) {
      throw new AutofillIntentRegistryError('invalid_configuration', 'Lease validators are required');
    }
    this.#isSessionLeaseCurrent = options.isSessionLeaseCurrent;
    this.#isAccountLeaseCurrent = options.isAccountLeaseCurrent;
    this.#isPolicyLeaseCurrent = options.isPolicyLeaseCurrent;
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_AUTOFILL_INTENT_TTL_MS,
      MAX_AUTOFILL_INTENT_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_AUTOFILL_INTENT_CAPACITY,
      MAX_AUTOFILL_INTENT_CAPACITY,
      'maxEntries',
    );
    this.#now = options.now ?? (() => performance.now());
    this.#createToken = options.createToken ?? (() => globalThis.crypto.randomUUID());
  }

  issue(intent: AutofillIntentIssue<SessionLease, AccountLease, PolicyLease>): string {
    const issuedAt = this.#currentTime();
    const canonical = canonicalizeIssue(intent);
    if (!this.#leasesAreCurrent(canonical.sessionLease, canonical.accountLease, canonical.policyLease)) {
      throw new AutofillIntentRegistryError('invalid_intent', 'Autofill intent leases are not current');
    }
    this.#pruneExpired(issuedAt);
    if (this.#entries.size >= this.#maxEntries) {
      throw new AutofillIntentRegistryError(
        'capacity',
        `Autofill intent capacity (${this.#maxEntries}) was reached`,
      );
    }

    const token = this.#freshToken();

    const expiresAt = issuedAt + this.#ttlMs;
    if (!Number.isFinite(expiresAt)) {
      throw new AutofillIntentRegistryError('invalid_configuration', 'Autofill intent expiry is invalid');
    }
    this.#entries.set(token, Object.freeze({ ...canonical, expiresAt }));
    return token;
  }

  /**
   * Atomically consumes `token` before validating it. Every failure is intentionally indistinguishable
   * and returns `undefined`, preventing callers from probing whether a capability existed.
   */
  redeem(
    token: string,
    redemption: AutofillIntentRedemption,
  ): RedeemedAutofillIntent<SessionLease, AccountLease, PolicyLease> | undefined {
    const issued = this.#entries.get(token);
    if (issued) this.#entries.delete(token);

    let now: number;
    try {
      now = this.#currentTime();
    } catch {
      return undefined;
    }
    this.#pruneExpired(now);
    if (!issued || issued.expiresAt <= now) return undefined;

    let canonical: CanonicalRedemption;
    try {
      canonical = canonicalizeRedemption(redemption);
    } catch {
      return undefined;
    }
    const sameTab = issued.tabId === canonical.tabId;
    const sameFrame = issued.frameId === canonical.frameId;
    const sameDocument = issued.documentId === canonical.documentId;
    const sameRuntime = issued.runtimeIncarnation === canonical.runtimeIncarnation;
    const sameUrl = issued.frameUrl === canonical.frameUrl;
    const samePurpose = issued.purpose === canonical.purpose;
    const sameChannel = issued.channel === canonical.channel;
    const sameStructuredTarget = equalStructuredTarget(issued.structuredTarget, canonical.structuredTarget);
    const contextMatches = sameTab && sameFrame && sameDocument && sameRuntime && sameUrl
      && samePurpose && sameChannel && sameStructuredTarget;
    const leasesCurrent = this.#leasesAreCurrent(issued.sessionLease, issued.accountLease, issued.policyLease);
    if (!contextMatches || !leasesCurrent) return undefined;
    return Object.freeze({
      tabId: issued.tabId,
      frameId: issued.frameId,
      documentId: issued.documentId,
      runtimeIncarnation: issued.runtimeIncarnation,
      canonicalFrameUrl: issued.frameUrl,
      cipherId: issued.cipherId,
      purpose: issued.purpose,
      channel: issued.channel,
      sessionLease: issued.sessionLease,
      accountLease: issued.accountLease,
      policyLease: issued.policyLease,
      ...(issued.customPlan === undefined ? {} : {
        customPlan: issued.customPlan,
        customPlanDigest: issued.customPlanDigest!,
      }),
      ...(issued.structuredTarget === undefined ? {} : {
        structuredTarget: issued.structuredTarget,
      }),
      ...(issued.repromptAuthorization === undefined ? {} : {
        repromptAuthorization: issued.repromptAuthorization,
      }),
    });
  }

  #freshToken(): string {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let token: string;
      try {
        token = this.#createToken();
      } catch {
        throw new AutofillIntentRegistryError('token_generation', 'Could not create an autofill intent token');
      }
      if (!UUID_V4.test(token)) {
        throw new AutofillIntentRegistryError('token_generation', 'Autofill intent token must be a UUID v4');
      }
      if (!this.#entries.has(token)) return token;
    }
    throw new AutofillIntentRegistryError('token_collision', 'Autofill intent token collision');
  }

  #leasesAreCurrent(sessionLease: SessionLease, accountLease: AccountLease, policyLease: PolicyLease): boolean {
    let sessionCurrent = false;
    let accountCurrent = false;
    let policyCurrent = false;
    try {
      sessionCurrent = this.#isSessionLeaseCurrent(sessionLease) === true;
    } catch {
      // A gate exception is the same fail-closed outcome as a stale lease.
    }
    try {
      accountCurrent = this.#isAccountLeaseCurrent(accountLease) === true;
    } catch {
      // A gate exception is the same fail-closed outcome as a stale lease.
    }
    try {
      policyCurrent = this.#isPolicyLeaseCurrent(policyLease) === true;
    } catch {
      // A gate exception is the same fail-closed outcome as a stale lease.
    }
    return sessionCurrent && accountCurrent && policyCurrent;
  }

  #currentTime(): number {
    const value = this.#now();
    if (!Number.isFinite(value) || value < 0) {
      throw new AutofillIntentRegistryError('invalid_configuration', 'Autofill intent clock is invalid');
    }
    return value;
  }

  #pruneExpired(now: number): void {
    for (const [token, intent] of this.#entries) {
      if (intent.expiresAt <= now) this.#entries.delete(token);
    }
  }
}

function canonicalizeIssue<SessionLease, AccountLease, PolicyLease>(
  intent: AutofillIntentIssue<SessionLease, AccountLease, PolicyLease>,
): Omit<StoredAutofillIntent<SessionLease, AccountLease, PolicyLease>, 'expiresAt'> {
  assertBrowserContext(intent);
  assertOpaqueId(intent.cipherId, 'cipherId');
  assertPurpose(intent.purpose);
  assertChannel(intent.channel);
  assertLease(intent.sessionLease, 'sessionLease');
  assertLease(intent.accountLease, 'accountLease');
  assertLease(intent.policyLease, 'policyLease');
  const purposeBinding = canonicalizePurposeBinding(
    intent.purpose,
    intent.channel,
    intent.customPlan,
    intent.customPlanDigest,
    intent.structuredTarget,
    intent.runtimeIncarnation,
  );
  const repromptAuthorization = canonicalizeRepromptAuthorization(
    intent.channel,
    intent.repromptAuthorization,
  );
  return Object.freeze({
    tabId: intent.tabId,
    frameId: intent.frameId,
    documentId: intent.documentId,
    runtimeIncarnation: intent.runtimeIncarnation,
    frameUrl: canonicalFrameUrl(intent.frameUrl),
    cipherId: intent.cipherId,
    purpose: intent.purpose,
    channel: intent.channel,
    sessionLease: intent.sessionLease,
    accountLease: intent.accountLease,
    policyLease: intent.policyLease,
    ...purposeBinding,
    ...(repromptAuthorization ? { repromptAuthorization } : {}),
  });
}

function canonicalizeRepromptAuthorization(
  channel: AutofillIntentChannel,
  value: AutofillRepromptAuthorization | undefined,
): AutofillRepromptAuthorization | undefined {
  if (value === undefined) return undefined;
  if (channel !== 'keyboard' || typeof value !== 'object' || value === null) {
    invalidIntent('repromptAuthorization');
  }
  const keys = Reflect.ownKeys(value);
  const descriptor = Object.getOwnPropertyDescriptor(value, 'assertCurrent');
  if (keys.length !== 1 || keys[0] !== 'assertCurrent' || !descriptor?.enumerable
      || !('value' in descriptor) || typeof descriptor.value !== 'function') {
    invalidIntent('repromptAuthorization');
  }
  return Object.freeze({ assertCurrent: descriptor.value as () => void });
}

function canonicalizePurposeBinding(
  purpose: AutofillSecretPurpose,
  channel: AutofillIntentChannel,
  unsafePlan: LoginCustomTargetPlan | undefined,
  digest: string | undefined,
  unsafeStructuredTarget: ContentStructuredAutofillTarget | undefined,
  runtimeIncarnation: string,
): Readonly<{
  customPlan: LoginCustomTargetPlan;
  customPlanDigest: string;
}> | Readonly<{
  structuredTarget: ContentStructuredAutofillTarget;
}> | Record<string, never> {
  if (channel === 'page-load') {
    if (purpose !== 'login' || unsafePlan !== undefined || digest !== undefined || unsafeStructuredTarget !== undefined) {
      invalidIntent('pageLoadBinding');
    }
    return Object.freeze({});
  }
  if (purpose === 'login') {
    if (unsafeStructuredTarget !== undefined) invalidIntent('structuredTarget');
    const customPlan = parseLoginCustomTargetPlan(unsafePlan);
    if (!customPlan || !isLoginCustomPlanDigest(digest)) invalidIntent('customPlan');
    return Object.freeze({ customPlan, customPlanDigest: digest });
  }
  if (purpose === 'card' || purpose === 'identity') {
    if (unsafePlan !== undefined || digest !== undefined) invalidIntent('customPlan');
    const structuredTarget = canonicalizeStructuredTarget(unsafeStructuredTarget);
    if (
      !structuredTarget
      || structuredTarget.kind !== purpose
      || structuredTarget.runtimeIncarnation !== runtimeIncarnation
    ) invalidIntent('structuredTarget');
    return Object.freeze({ structuredTarget });
  }
  if (unsafePlan !== undefined || digest !== undefined || unsafeStructuredTarget !== undefined) {
    invalidIntent('purposeBinding');
  }
  return Object.freeze({});
}

function canonicalizeRedemption(
  redemption: AutofillIntentRedemption,
): CanonicalRedemption {
  assertBrowserContext(redemption);
  assertPurpose(redemption.purpose);
  assertChannel(redemption.channel);
  const structuredTarget = redemption.purpose === 'card' || redemption.purpose === 'identity'
    ? canonicalizeStructuredTarget(redemption.structuredTarget)
    : undefined;
  if (
    (redemption.purpose === 'card' || redemption.purpose === 'identity')
    && (!structuredTarget || structuredTarget.runtimeIncarnation !== redemption.runtimeIncarnation)
  ) {
    invalidIntent('structuredTarget');
  }
  if (redemption.purpose !== 'card' && redemption.purpose !== 'identity'
      && redemption.structuredTarget !== undefined) invalidIntent('structuredTarget');
  return Object.freeze({
    tabId: redemption.tabId,
    frameId: redemption.frameId,
    documentId: redemption.documentId,
    runtimeIncarnation: redemption.runtimeIncarnation,
    frameUrl: canonicalFrameUrl(redemption.frameUrl),
    purpose: redemption.purpose,
    channel: redemption.channel,
    ...(structuredTarget === undefined ? {} : { structuredTarget }),
  });
}

function canonicalizeStructuredTarget(
  value: ContentStructuredAutofillTarget | undefined,
): ContentStructuredAutofillTarget | undefined {
  if (!value || (value.kind !== 'card' && value.kind !== 'identity')) return undefined;
  assertRuntimeIncarnation(value.runtimeIncarnation);
  assertOpaqueId(value.formId, 'formId');
  if (!Number.isSafeInteger(value.generation) || value.generation < 0) invalidIntent('generation');
  if (value.kind === 'card') {
    const roles = normalizeFillRoles('card', value.roles);
    if (!roles || roles.length !== value.roles.length
        || roles.some((role, index) => role !== value.roles[index])) return undefined;
    const selectedRoles = 'selectedRoles' in value
      ? canonicalizeSelectedRoles(value.kind, value.selectedRoles, roles)
      : undefined;
    if ('selectedRoles' in value && !selectedRoles) return undefined;
    return Object.freeze({
      kind: value.kind,
      runtimeIncarnation: value.runtimeIncarnation,
      formId: value.formId,
      generation: value.generation,
      roles: Object.freeze([...roles]),
      ...(selectedRoles === undefined ? {} : { selectedRoles }),
    });
  }
  const roles = normalizeFillRoles('identity', value.roles);
  if (!roles || roles.length !== value.roles.length
      || roles.some((role, index) => role !== value.roles[index])) return undefined;
  const selectedRoles = 'selectedRoles' in value
    ? canonicalizeSelectedRoles(value.kind, value.selectedRoles, roles)
    : undefined;
  if ('selectedRoles' in value && !selectedRoles) return undefined;
  return Object.freeze({
    kind: value.kind,
    runtimeIncarnation: value.runtimeIncarnation,
    formId: value.formId,
    generation: value.generation,
    roles: Object.freeze([...roles]),
    ...(selectedRoles === undefined ? {} : { selectedRoles }),
  });
}

function canonicalizeSelectedRoles<Role extends FillRole>(
  kind: FillKind,
  value: unknown,
  roles: readonly Role[],
): readonly Role[] | undefined {
  const selected = normalizeFillRoles(kind, value);
  if (!Array.isArray(value) || !selected || selected.length !== value.length
      || selected.some((role, index) => role !== value[index]
        || !roles.some((structuralRole) => structuralRole === role))) return undefined;
  return Object.freeze(roles.filter((role) => selected.includes(role)));
}

function equalStructuredTarget(
  first: ContentStructuredAutofillTarget | undefined,
  second: ContentStructuredAutofillTarget | undefined,
): boolean {
  if (first === undefined || second === undefined) return first === second;
  return first.kind === second.kind
    && first.runtimeIncarnation === second.runtimeIncarnation
    && first.formId === second.formId
    && first.generation === second.generation
    && first.roles.length === second.roles.length
    && first.roles.every((role, index) => role === second.roles[index])
    && (first.selectedRoles === undefined || second.selectedRoles === undefined
      ? first.selectedRoles === second.selectedRoles
      : first.selectedRoles.length === second.selectedRoles.length
        && first.selectedRoles.every((role, index) => role === second.selectedRoles?.[index]));
}

function assertBrowserContext(value: {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly frameUrl: string;
}): void {
  if (!Number.isSafeInteger(value.tabId) || value.tabId < 0) invalidIntent('tabId');
  if (!Number.isSafeInteger(value.frameId) || value.frameId < 0) invalidIntent('frameId');
  assertOpaqueId(value.documentId, 'documentId');
  assertRuntimeIncarnation(value.runtimeIncarnation);
}

function assertRuntimeIncarnation(value: string): void {
  if (typeof value !== 'string' || !RUNTIME_INCARNATION_UUID_V4.test(value)) {
    invalidIntent('runtimeIncarnation');
  }
}

function assertOpaqueId(value: string, field: string): void {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_OPAQUE_ID_LENGTH
    || value.trim() !== value
  ) invalidIntent(field);
}

function assertPurpose(value: AutofillSecretPurpose): void {
  if (value !== 'login' && value !== 'totp' && value !== 'card' && value !== 'identity') invalidIntent('purpose');
}

function assertChannel(value: AutofillIntentChannel): void {
  if (value !== 'interactive' && value !== 'keyboard' && value !== 'page-load') invalidIntent('channel');
}

function assertLease(value: unknown, field: string): void {
  if (value === null || value === undefined) invalidIntent(field);
}

function canonicalFrameUrl(value: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_FRAME_URL_LENGTH) {
    throw new AutofillIntentRegistryError('invalid_intent', 'frameUrl is invalid');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AutofillIntentRegistryError('invalid_intent', 'frameUrl is invalid');
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
    throw new AutofillIntentRegistryError('invalid_intent', 'frameUrl is invalid');
  }
  const canonical = url.href;
  if (canonical.length > MAX_FRAME_URL_LENGTH) {
    throw new AutofillIntentRegistryError('invalid_intent', 'frameUrl is invalid');
  }
  return canonical;
}

function invalidIntent(field: string): never {
  throw new AutofillIntentRegistryError('invalid_intent', `${field} is invalid`);
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new AutofillIntentRegistryError(
      'invalid_configuration',
      `${name} must be a positive integer no greater than ${maximum}`,
    );
  }
  return value;
}
