import type {
  AutofillSecretPurpose,
  ContentStructuredAutofillTarget,
} from '../messaging/protocol.js';
import { normalizeFillRoles } from '../core/vault/fill-roles.js';
import {
  isLoginCustomPlanDigest,
  parseLoginCustomTargetPlan,
  type LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';

export const DEFAULT_KEYBOARD_COMMAND_TTL_MS = 2_000;
export const DEFAULT_KEYBOARD_GRANT_TTL_MS = 30_000;
export const DEFAULT_KEYBOARD_COMMAND_CAPACITY = 32;
export const DEFAULT_KEYBOARD_GRANT_CAPACITY = 128;

const MAX_COMMAND_TTL_MS = 10_000;
const MAX_GRANT_TTL_MS = 60_000;
const MAX_CAPACITY = 4_096;
const MAX_OPAQUE_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 16_384;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUNTIME_INCARNATION_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface KeyboardCommandIssue<SessionLease = unknown> {
  readonly tabId: number;
  readonly topDocumentId: string;
  readonly topFrameUrl: string;
  readonly sessionLease: SessionLease;
}

export type KeyboardCommandClaim = Omit<KeyboardCommandIssue, 'sessionLease'>;

export type KeyboardGrantBinding =
  | {
      readonly purpose: 'login';
      readonly customPlan: LoginCustomTargetPlan;
      readonly customPlanDigest: string;
    }
  | { readonly purpose: 'totp' }
  | {
      readonly purpose: 'card' | 'identity';
      readonly structuredTarget: ContentStructuredAutofillTarget;
    };

export interface KeyboardGrantContext {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly runtimeIncarnation: string;
  readonly frameUrl: string;
}

export interface KeyboardGrantIssue<SessionLease, AccountLease, PolicyLease>
  extends KeyboardGrantContext {
  readonly topDocumentId: string;
  readonly topFrameUrl: string;
  readonly binding: KeyboardGrantBinding;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
}

export interface KeyboardGrant<SessionLease, AccountLease, PolicyLease>
  extends KeyboardGrantIssue<SessionLease, AccountLease, PolicyLease> {
  readonly purpose: AutofillSecretPurpose;
}

export interface AutofillKeyboardGrantRegistryOptions<SessionLease, AccountLease, PolicyLease> {
  readonly isSessionLeaseCurrent: (lease: SessionLease) => boolean;
  readonly isAccountLeaseCurrent: (lease: AccountLease) => boolean;
  readonly isPolicyLeaseCurrent: (lease: PolicyLease) => boolean;
  readonly commandTtlMs?: number;
  readonly grantTtlMs?: number;
  readonly maxCommands?: number;
  readonly maxGrants?: number;
  readonly now?: () => number;
  readonly createToken?: () => string;
}

interface StoredKeyboardCommand<SessionLease> extends KeyboardCommandIssue<SessionLease> {
  readonly expiresAt: number;
}

interface StoredKeyboardGrant<SessionLease, AccountLease, PolicyLease>
  extends KeyboardGrantIssue<SessionLease, AccountLease, PolicyLease> {
  readonly purpose: AutofillSecretPurpose;
  readonly expiresAt: number;
}

/**
 * Two-stage capabilities for the browser keyboard command. The browser event first issues a very
 * short-lived tab/top-document token. Exactly one focused content document may consume that token
 * and exchange it for a lease-bound grant. Candidate reads preserve a valid grant; issuing the final
 * one-time autofill intent consumes it.
 */
export class AutofillKeyboardGrantRegistry<SessionLease, AccountLease, PolicyLease> {
  readonly #commands = new Map<string, StoredKeyboardCommand<SessionLease>>();
  readonly #grants = new Map<string, StoredKeyboardGrant<SessionLease, AccountLease, PolicyLease>>();
  readonly #options: AutofillKeyboardGrantRegistryOptions<SessionLease, AccountLease, PolicyLease>;
  readonly #commandTtlMs: number;
  readonly #grantTtlMs: number;
  readonly #maxCommands: number;
  readonly #maxGrants: number;

  constructor(options: AutofillKeyboardGrantRegistryOptions<SessionLease, AccountLease, PolicyLease>) {
    if (
      typeof options?.isSessionLeaseCurrent !== 'function'
      || typeof options.isAccountLeaseCurrent !== 'function'
      || typeof options.isPolicyLeaseCurrent !== 'function'
    ) throw new TypeError('Keyboard grant lease validators are required');
    this.#options = options;
    this.#commandTtlMs = boundedPositiveInteger(
      options.commandTtlMs ?? DEFAULT_KEYBOARD_COMMAND_TTL_MS,
      MAX_COMMAND_TTL_MS,
      'commandTtlMs',
    );
    this.#grantTtlMs = boundedPositiveInteger(
      options.grantTtlMs ?? DEFAULT_KEYBOARD_GRANT_TTL_MS,
      MAX_GRANT_TTL_MS,
      'grantTtlMs',
    );
    this.#maxCommands = boundedPositiveInteger(
      options.maxCommands ?? DEFAULT_KEYBOARD_COMMAND_CAPACITY,
      MAX_CAPACITY,
      'maxCommands',
    );
    this.#maxGrants = boundedPositiveInteger(
      options.maxGrants ?? DEFAULT_KEYBOARD_GRANT_CAPACITY,
      MAX_CAPACITY,
      'maxGrants',
    );
  }

  issueCommand(input: KeyboardCommandIssue<SessionLease>): string {
    const now = this.#now();
    const command = canonicalCommand(input);
    this.#prune(now);
    if (this.#commands.size >= this.#maxCommands) throw new Error('Keyboard command capacity reached');
    const token = this.#freshToken();
    this.#commands.set(token, Object.freeze({ ...command, expiresAt: now + this.#commandTtlMs }));
    return token;
  }

  /** Consume before comparison so a wrong frame, document, URL, or replay cannot probe a token. */
  takeCommand(token: string, input: KeyboardCommandClaim): KeyboardCommandIssue<SessionLease> | undefined {
    if (typeof token !== 'string' || !UUID_V4.test(token)) return undefined;
    const command = this.#commands.get(token);
    if (!command) return undefined;
    const now = this.#nowOrUndefined();
    if (now === undefined || command.expiresAt <= now || !this.#sessionLeaseCurrent(command.sessionLease)) {
      this.#commands.delete(token);
      return undefined;
    }
    this.#commands.delete(token);
    let claim: KeyboardCommandClaim;
    try { claim = canonicalCommand(input); } catch { return undefined; }
    if (
      command.tabId !== claim.tabId
      || command.topDocumentId !== claim.topDocumentId
      || command.topFrameUrl !== claim.topFrameUrl
    ) return undefined;
    return Object.freeze({
      tabId: command.tabId,
      topDocumentId: command.topDocumentId,
      topFrameUrl: command.topFrameUrl,
      sessionLease: command.sessionLease,
    });
  }

  revokeAll(): void {
    this.#commands.clear();
    this.#grants.clear();
  }

  issueGrant(input: KeyboardGrantIssue<SessionLease, AccountLease, PolicyLease>): string {
    const now = this.#now();
    const grant = canonicalGrant(input);
    if (!this.#leasesCurrent(grant)) throw new Error('Keyboard grant leases are stale');
    this.#prune(now);
    if (this.#grants.size >= this.#maxGrants) throw new Error('Keyboard grant capacity reached');
    const token = this.#freshToken();
    this.#grants.set(token, Object.freeze({ ...grant, expiresAt: now + this.#grantTtlMs }));
    return token;
  }

  authorizeGrant(
    token: string,
    context: KeyboardGrantContext,
  ): KeyboardGrant<SessionLease, AccountLease, PolicyLease> | undefined {
    return this.#useGrant(token, context, false);
  }

  consumeGrant(
    token: string,
    context: KeyboardGrantContext,
  ): KeyboardGrant<SessionLease, AccountLease, PolicyLease> | undefined {
    return this.#useGrant(token, context, true);
  }

  #useGrant(
    token: string,
    unsafeContext: KeyboardGrantContext,
    consume: boolean,
  ): KeyboardGrant<SessionLease, AccountLease, PolicyLease> | undefined {
    if (typeof token !== 'string' || !UUID_V4.test(token)) return undefined;
    const grant = this.#grants.get(token);
    if (!grant) return undefined;
    if (consume) this.#grants.delete(token);
    const now = this.#nowOrUndefined();
    if (now === undefined || grant.expiresAt <= now) {
      this.#grants.delete(token);
      return undefined;
    }
    let context: KeyboardGrantContext;
    try { context = canonicalContext(unsafeContext); } catch {
      this.#grants.delete(token);
      return undefined;
    }
    if (
      grant.tabId !== context.tabId
      || grant.frameId !== context.frameId
      || grant.documentId !== context.documentId
      || grant.runtimeIncarnation !== context.runtimeIncarnation
      || grant.frameUrl !== context.frameUrl
      || !this.#leasesCurrent(grant)
    ) {
      this.#grants.delete(token);
      return undefined;
    }
    return copyGrant(grant);
  }

  #leasesCurrent(
    input: Pick<StoredKeyboardGrant<SessionLease, AccountLease, PolicyLease>, 'sessionLease' | 'accountLease' | 'policyLease'>,
  ): boolean {
    try {
      return this.#options.isSessionLeaseCurrent(input.sessionLease) === true
        && this.#options.isAccountLeaseCurrent(input.accountLease) === true
        && this.#options.isPolicyLeaseCurrent(input.policyLease) === true;
    } catch {
      return false;
    }
  }

  #sessionLeaseCurrent(lease: SessionLease): boolean {
    try { return this.#options.isSessionLeaseCurrent(lease) === true; }
    catch { return false; }
  }

  #freshToken(): string {
    const create = this.#options.createToken ?? (() => crypto.randomUUID());
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const token = create();
      if (!UUID_V4.test(token)) throw new Error('Keyboard capability token must be a UUID v4');
      if (!this.#commands.has(token) && !this.#grants.has(token)) return token;
    }
    throw new Error('Keyboard capability token collision');
  }

  #now(): number {
    const value = this.#options.now?.() ?? performance.now();
    if (!Number.isFinite(value) || value < 0) throw new Error('Keyboard capability clock is invalid');
    return value;
  }

  #nowOrUndefined(): number | undefined {
    try { return this.#now(); } catch { return undefined; }
  }

  #prune(now: number): void {
    for (const [token, command] of this.#commands) {
      if (command.expiresAt <= now) this.#commands.delete(token);
    }
    for (const [token, grant] of this.#grants) {
      if (grant.expiresAt <= now) this.#grants.delete(token);
    }
  }
}

function canonicalCommand<SessionLease>(input: KeyboardCommandIssue<SessionLease>): KeyboardCommandIssue<SessionLease>;
function canonicalCommand(input: KeyboardCommandClaim): KeyboardCommandClaim;
function canonicalCommand<SessionLease>(input: KeyboardCommandIssue<SessionLease> | KeyboardCommandClaim): KeyboardCommandIssue<SessionLease> | KeyboardCommandClaim {
  const tabId = nonNegativeInteger(input?.tabId, 'tabId');
  const topDocumentId = opaqueId(input.topDocumentId, 'topDocumentId');
  const topFrameUrl = canonicalHttpUrl(input.topFrameUrl, 'topFrameUrl');
  if ('sessionLease' in input) {
    if (input.sessionLease == null) throw new TypeError('Keyboard command session lease is invalid');
    return Object.freeze({ tabId, topDocumentId, topFrameUrl, sessionLease: input.sessionLease });
  }
  return Object.freeze({ tabId, topDocumentId, topFrameUrl });
}

function canonicalContext(input: KeyboardGrantContext): KeyboardGrantContext {
  return Object.freeze({
    tabId: nonNegativeInteger(input?.tabId, 'tabId'),
    frameId: nonNegativeInteger(input.frameId, 'frameId'),
    documentId: opaqueId(input.documentId, 'documentId'),
    runtimeIncarnation: canonicalRuntimeIncarnation(input.runtimeIncarnation, 'runtimeIncarnation'),
    frameUrl: canonicalHttpUrl(input.frameUrl, 'frameUrl'),
  });
}

function canonicalGrant<SessionLease, AccountLease, PolicyLease>(
  input: KeyboardGrantIssue<SessionLease, AccountLease, PolicyLease>,
): Omit<StoredKeyboardGrant<SessionLease, AccountLease, PolicyLease>, 'expiresAt'> {
  const context = canonicalContext(input);
  const topDocumentId = opaqueId(input.topDocumentId, 'topDocumentId');
  const topFrameUrl = canonicalHttpUrl(input.topFrameUrl, 'topFrameUrl');
  const binding = canonicalBinding(input.binding);
  if (context.frameId === 0 && (
    context.documentId !== topDocumentId
    || context.frameUrl !== topFrameUrl
  )) throw new TypeError('Keyboard top-frame grant context is invalid');
  if (
    (binding.purpose === 'card' || binding.purpose === 'identity')
    && binding.structuredTarget.runtimeIncarnation !== context.runtimeIncarnation
  ) throw new TypeError('Keyboard structured binding runtime is invalid');
  if (input.sessionLease == null || input.accountLease == null || input.policyLease == null) {
    throw new TypeError('Keyboard grant lease is invalid');
  }
  return Object.freeze({
    ...context,
    topDocumentId,
    topFrameUrl,
    binding,
    purpose: binding.purpose,
    sessionLease: input.sessionLease,
    accountLease: input.accountLease,
    policyLease: input.policyLease,
  });
}

function canonicalBinding(input: KeyboardGrantBinding): KeyboardGrantBinding {
  if (!input || typeof input !== 'object') throw new TypeError('Keyboard grant binding is invalid');
  if (input.purpose === 'login') {
    if (!hasExactOwnKeys(input, ['customPlan', 'customPlanDigest', 'purpose'])) {
      throw new TypeError('Keyboard login binding fields are invalid');
    }
    const customPlan = parseLoginCustomTargetPlan(input.customPlan);
    if (!customPlan || !isLoginCustomPlanDigest(input.customPlanDigest)) {
      throw new TypeError('Keyboard login binding is invalid');
    }
    return Object.freeze({ purpose: input.purpose, customPlan, customPlanDigest: input.customPlanDigest });
  }
  if (input.purpose === 'totp') {
    if (!hasExactOwnKeys(input, ['purpose'])) throw new TypeError('Keyboard TOTP binding fields are invalid');
    return Object.freeze({ purpose: input.purpose });
  }
  if (input.purpose === 'card' || input.purpose === 'identity') {
    if (!hasExactOwnKeys(input, ['purpose', 'structuredTarget'])) {
      throw new TypeError('Keyboard structured binding fields are invalid');
    }
    const structuredTarget = canonicalStructuredTarget(input.structuredTarget);
    if (!structuredTarget || structuredTarget.kind !== input.purpose) {
      throw new TypeError('Keyboard structured binding is invalid');
    }
    return Object.freeze({ purpose: input.purpose, structuredTarget });
  }
  throw new TypeError('Keyboard grant purpose is invalid');
}

export function parseKeyboardGrantBinding(value: unknown): KeyboardGrantBinding | undefined {
  try { return canonicalBinding(value as KeyboardGrantBinding); }
  catch { return undefined; }
}

function hasExactOwnKeys(value: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) {
    return false;
  }
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function canonicalStructuredTarget(value: ContentStructuredAutofillTarget): ContentStructuredAutofillTarget | undefined {
  if (!value || (value.kind !== 'card' && value.kind !== 'identity')) return undefined;
  const runtimeIncarnation = canonicalRuntimeIncarnation(value.runtimeIncarnation, 'runtimeIncarnation');
  const formId = opaqueId(value.formId, 'formId');
  const generation = nonNegativeInteger(value.generation, 'generation');
  if (value.kind === 'card') {
    const roles = normalizeFillRoles(value.kind, value.roles);
    if (!roles || roles.length !== value.roles.length
        || roles.some((role, index) => role !== value.roles[index])) return undefined;
    return Object.freeze({
      kind: value.kind,
      runtimeIncarnation,
      formId,
      generation,
      roles: Object.freeze([...roles]),
    });
  }
  const roles = normalizeFillRoles(value.kind, value.roles);
  if (!roles || roles.length !== value.roles.length
      || roles.some((role, index) => role !== value.roles[index])) return undefined;
  return Object.freeze({
    kind: value.kind,
    runtimeIncarnation,
    formId,
    generation,
    roles: Object.freeze([...roles]),
  });
}

function copyGrant<SessionLease, AccountLease, PolicyLease>(
  grant: StoredKeyboardGrant<SessionLease, AccountLease, PolicyLease>,
): KeyboardGrant<SessionLease, AccountLease, PolicyLease> {
  return Object.freeze({
    tabId: grant.tabId,
    frameId: grant.frameId,
    documentId: grant.documentId,
    runtimeIncarnation: grant.runtimeIncarnation,
    frameUrl: grant.frameUrl,
    topDocumentId: grant.topDocumentId,
    topFrameUrl: grant.topFrameUrl,
    binding: grant.binding,
    purpose: grant.purpose,
    sessionLease: grant.sessionLease,
    accountLease: grant.accountLease,
    policyLease: grant.policyLease,
  });
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`${field} is invalid`);
  return value as number;
}

function opaqueId(value: unknown, field: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_OPAQUE_ID_LENGTH
    || value.trim() !== value
  ) throw new TypeError(`${field} is invalid`);
  return value;
}

function canonicalRuntimeIncarnation(value: unknown, field: string): string {
  if (typeof value !== 'string' || !RUNTIME_INCARNATION_UUID_V4.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value;
}

function canonicalHttpUrl(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LENGTH) {
    throw new TypeError(`${field} is invalid`);
  }
  const url = new URL(value);
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
    throw new TypeError(`${field} is invalid`);
  }
  if (url.href.length > MAX_URL_LENGTH) throw new TypeError(`${field} is invalid`);
  return url.href;
}

function boundedPositiveInteger(value: unknown, maximum: number, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new TypeError(`${field} is invalid`);
  }
  return value as number;
}
