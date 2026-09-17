import type { AccountLease } from '../core/session/account-gate.js';
import type { FillKind, FillRole, TabSuggestionTarget } from '../messaging/protocol.js';
import type { KeyValueStore } from '../platform/store.js';
import type { AutofillAuthorizationPolicyLease } from './autofill-authorization-policy.js';
import type { DirectFillCommand, SecretExtensionCommand } from './commands.js';
import { normalizeFillRoles } from '../core/vault/fill-roles.js';

export const AUTOFILL_CONTINUATION_STORAGE_KEY = 'autofillContinuation.v1';
export const AUTOFILL_CONTINUATION_TTL_MS = 60_000;
const MAX_TTL_MS = 120_000;
const MAX_TEXT = 4_096;
const MAX_URL = 16_384;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CANONICAL_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const storageLanes = new WeakMap<object, Promise<void>>();

export interface AutofillContinuationAuthority {
  readonly workerInstanceId: string;
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly serverGeneration: number;
  readonly accountGeneration: number;
  readonly autofillPolicyGeneration: number;
  readonly autofillPolicyDigest: string;
  readonly enterprisePolicyGeneration: number;
  readonly rawPolicyGeneration: string;
}

export interface AutofillContinuationSource {
  readonly tabId: number;
  readonly windowId: number;
  readonly topDocumentId: string;
  readonly topRuntimeIncarnation: string | null;
  readonly topOrigin: string;
  readonly topUrlDigest: string;
  readonly frameId: number;
  readonly frameDocumentId: string;
  readonly frameRuntimeIncarnation: string | null;
  readonly frameOrigin: string;
  readonly frameUrlDigest: string;
}

export type AutofillContinuationAction =
  | { readonly kind: 'locked_context' }
  | { readonly kind: 'locked_keyboard' }
  | { readonly kind: 'locked_command'; readonly command: SecretExtensionCommand }
  | { readonly kind: 'context_login_reprompt'; readonly cipherId: string; readonly target: TabSuggestionTarget }
  | {
      readonly kind: 'command_fill_reprompt';
      readonly command: DirectFillCommand;
      readonly cipherId: string;
      readonly target: TabSuggestionTarget;
    }
  | {
      readonly kind: 'context_copy_reprompt';
      readonly cipherId: string;
      readonly field: 'password' | 'totp';
    }
  | {
      readonly kind: 'context_structured_reprompt';
      readonly cipherId: string;
      readonly holdId: string;
      readonly scope: 'form' | 'field';
      readonly fillKind: FillKind;
      readonly roles: readonly FillRole[];
      readonly runtimeIncarnation: string;
    }
  | {
      readonly kind: 'keyboard_reprompt';
      readonly cipherId: string;
      readonly binding:
        | {
            readonly purpose: 'login';
            readonly runtimeIncarnation: string;
            readonly customPlanDigest: string;
          }
        | { readonly purpose: 'totp'; readonly runtimeIncarnation: string }
        | {
            readonly purpose: 'card' | 'identity';
            readonly runtimeIncarnation: string;
            readonly formId: string;
            readonly generation: number;
            readonly roles: readonly FillRole[];
            readonly selectedRoles?: readonly FillRole[];
          };
    };

export interface AutofillContinuationEnvelope {
  readonly schemaVersion: 2;
  readonly continuationId: string;
  readonly source: AutofillContinuationSource;
  readonly authority: AutofillContinuationAuthority;
  readonly action: AutofillContinuationAction;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly popupDocumentId?: string;
}

type StoredRecord =
  | { readonly state: 'pending'; readonly envelope: AutofillContinuationEnvelope }
  | { readonly state: 'consumed'; readonly continuationId: string; readonly expiresAt: number };

/** Durable, secret-free continuation storage with a consume-before-validate tombstone. */
export class AutofillContinuationStore {
  readonly #store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #laneKey: object;

  constructor(options: {
    readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
    readonly now?: () => number;
    readonly ttlMs?: number;
  }) {
    if (!options?.store) throw new TypeError('Autofill continuation storage is required');
    this.#store = options.store;
    this.#laneKey = options.store;
    this.#now = options.now ?? (() => Date.now());
    this.#ttlMs = positiveInteger(options.ttlMs ?? AUTOFILL_CONTINUATION_TTL_MS, MAX_TTL_MS, 'ttlMs');
  }

  create(input: {
    readonly source: AutofillContinuationSource;
    readonly authority: AutofillContinuationAuthority;
    readonly action: AutofillContinuationAction;
  }): AutofillContinuationEnvelope {
    const now = this.#time();
    return canonicalEnvelope({
      schemaVersion: 2,
      continuationId: crypto.randomUUID(),
      source: input.source,
      authority: input.authority,
      action: input.action,
      createdAt: now,
      expiresAt: now + this.#ttlMs,
    }, now, this.#ttlMs);
  }

  async put(unsafeEnvelope: AutofillContinuationEnvelope): Promise<void> {
    await this.#run(async () => this.#putUnlocked(unsafeEnvelope));
  }

  async read(): Promise<AutofillContinuationEnvelope | undefined> {
    return this.#run(async () => this.#readUnlocked());
  }

  async claimPopup(popupDocumentId: string): Promise<AutofillContinuationEnvelope | undefined> {
    return this.#run(async () => {
      const envelope = await this.#readUnlocked();
      if (!envelope) return undefined;
      const documentId = text(popupDocumentId, 'popupDocumentId');
      if (envelope.popupDocumentId && envelope.popupDocumentId !== documentId) return undefined;
      if (envelope.popupDocumentId === documentId) return envelope;
      const claimed = canonicalEnvelope({ ...envelope, popupDocumentId: documentId }, this.#time(), this.#ttlMs);
      await this.#putUnlocked(claimed);
      return claimed;
    });
  }

  async take(popupDocumentId: string, continuationId: string): Promise<AutofillContinuationEnvelope | undefined> {
    return this.#run(async () => {
      const envelope = await this.#readUnlocked();
      if (!envelope) return undefined;
      const expectedDocumentId = text(popupDocumentId, 'popupDocumentId');
      const expectedContinuationId = uuid(continuationId, 'continuationId');
      if (envelope.popupDocumentId !== expectedDocumentId
          || envelope.continuationId !== expectedContinuationId) return undefined;
      await this.#writeAndConfirm(Object.freeze({
        state: 'consumed', continuationId: envelope.continuationId, expiresAt: envelope.expiresAt,
      }));
      return envelope;
    });
  }

  async clear(): Promise<void> {
    await this.#run(async () => this.#clearUnlocked());
  }

  async clearExact(continuationId: string): Promise<boolean> {
    const expectedContinuationId = uuid(continuationId, 'continuationId');
    return this.#run(async () => {
      const envelope = await this.#readUnlocked();
      if (!envelope || envelope.continuationId !== expectedContinuationId) return false;
      await this.#clearUnlocked();
      return true;
    });
  }

  async clearForTab(tabId: number): Promise<void> {
    await this.#run(async () => {
      const envelope = await this.#readUnlocked();
      if (envelope?.source.tabId === nonNegativeInteger(tabId, 'tabId')) await this.#clearUnlocked();
    });
  }

  async #putUnlocked(unsafeEnvelope: AutofillContinuationEnvelope): Promise<void> {
    const envelope = canonicalEnvelope(unsafeEnvelope, this.#time(), this.#ttlMs);
    await this.#writeAndConfirm(Object.freeze({ state: 'pending', envelope }));
  }

  async #readUnlocked(): Promise<AutofillContinuationEnvelope | undefined> {
    let value: unknown;
    try { value = await this.#store.get<unknown>(AUTOFILL_CONTINUATION_STORAGE_KEY); }
    catch { await this.#bestEffortRemove(); return undefined; }
    const now = this.#timeOrUndefined();
    if (now === undefined) { await this.#bestEffortRemove(); return undefined; }
    const parsed = parseRecord(value, now, this.#ttlMs);
    if (parsed === 'foreign' || (parsed && parsed.state === 'consumed')) return undefined;
    if (!parsed) {
      await this.#bestEffortRemove();
      return undefined;
    }
    return parsed.envelope;
  }

  async #clearUnlocked(): Promise<void> {
    try { await this.#store.remove(AUTOFILL_CONTINUATION_STORAGE_KEY); }
    catch {
      const current = await this.#store.get<unknown>(AUTOFILL_CONTINUATION_STORAGE_KEY).catch(() => Symbol('unknown'));
      if (current !== undefined) throw new Error('Autofill continuation could not be cleared');
    }
  }

  async #writeAndConfirm(record: StoredRecord): Promise<void> {
    try { await this.#store.set(AUTOFILL_CONTINUATION_STORAGE_KEY, record); }
    catch {
      const current = await this.#store.get<unknown>(AUTOFILL_CONTINUATION_STORAGE_KEY).catch(() => undefined);
      if (JSON.stringify(current) === JSON.stringify(record)) return;
      await this.#bestEffortRemove();
      throw new Error('Autofill continuation could not be persisted');
    }
  }

  async #bestEffortRemove(): Promise<void> {
    await this.#store.remove(AUTOFILL_CONTINUATION_STORAGE_KEY).catch(() => undefined);
  }

  async #run<T>(operation: () => Promise<T>): Promise<T> {
    const previous = storageLanes.get(this.#laneKey) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => { release = resolve; });
    storageLanes.set(this.#laneKey, previous.catch(() => undefined).then(() => next));
    await previous.catch(() => undefined);
    try { return await operation(); }
    finally { release(); }
  }

  #time(): number {
    const value = this.#now();
    if (!Number.isFinite(value) || value < 0) throw new Error('Autofill continuation clock is invalid');
    return value;
  }

  #timeOrUndefined(): number | undefined {
    try { return this.#time(); } catch { return undefined; }
  }
}

export function autofillContinuationAuthority(
  account: AccountLease,
  policy: AutofillAuthorizationPolicyLease,
  workerInstanceId: string,
  autofillPolicyDigest: string,
): AutofillContinuationAuthority {
  return Object.freeze({
    workerInstanceId: uuid(workerInstanceId, 'workerInstanceId'),
    serverUrl: httpUrl(account.serverUrl, 'serverUrl'),
    accountIdentity: text(account.accountIdentity, 'accountIdentity'),
    serverGeneration: nonNegativeInteger(account.serverGeneration, 'serverGeneration'),
    accountGeneration: nonNegativeInteger(account.accountGeneration, 'accountGeneration'),
    autofillPolicyGeneration: nonNegativeInteger(policy.autofill.generation, 'autofillPolicyGeneration'),
    autofillPolicyDigest: digest(autofillPolicyDigest, 'autofillPolicyDigest'),
    enterprisePolicyGeneration: nonNegativeInteger(policy.enterprise.generation, 'enterprisePolicyGeneration'),
    rawPolicyGeneration: text(policy.enterprise.rawGeneration, 'rawPolicyGeneration'),
  });
}

function parseRecord(value: unknown, now: number, ttlMs: number): StoredRecord | 'foreign' | undefined {
  if (!record(value)) return undefined;
  if (value.state === 'pending' && record(value.envelope)
      && typeof value.envelope.schemaVersion === 'number' && value.envelope.schemaVersion > 2) {
    return 'foreign';
  }
  if (value.state === 'consumed') {
    if (!keys(value, ['continuationId', 'expiresAt', 'state'])) return undefined;
    try {
      const parsed = Object.freeze({
        state: 'consumed' as const,
        continuationId: uuid(value.continuationId, 'continuationId'),
        expiresAt: number(value.expiresAt, 'expiresAt'),
      });
      return parsed.expiresAt > now ? parsed : undefined;
    } catch { return undefined; }
  }
  if (value.state !== 'pending' || !keys(value, ['envelope', 'state'])) return undefined;
  try { return Object.freeze({ state: 'pending', envelope: canonicalEnvelope(value.envelope, now, ttlMs) }); }
  catch { return undefined; }
}

function canonicalEnvelope(value: unknown, now: number, ttlMs: number): AutofillContinuationEnvelope {
  if (!record(value)) throw new TypeError('Autofill continuation is invalid');
  const base = ['action', 'authority', 'continuationId', 'createdAt', 'expiresAt', 'schemaVersion', 'source'];
  if (!keys(value, base) && !keys(value, [...base, 'popupDocumentId'])) {
    throw new TypeError('Autofill continuation fields are invalid');
  }
  if (value.schemaVersion !== 2) throw new TypeError('Autofill continuation schema is invalid');
  const createdAt = number(value.createdAt, 'createdAt');
  const expiresAt = number(value.expiresAt, 'expiresAt');
  if (createdAt > now || expiresAt <= now || expiresAt <= createdAt || expiresAt - createdAt > ttlMs) {
    throw new TypeError('Autofill continuation deadline is invalid');
  }
  const parsedSource = source(value.source);
  const parsedAction = action(value.action);
  if (!actionMatchesSource(parsedAction, parsedSource)) {
    throw new TypeError('Autofill continuation action source is invalid');
  }
  return Object.freeze({
    schemaVersion: 2,
    continuationId: uuid(value.continuationId, 'continuationId'),
    source: parsedSource,
    authority: authority(value.authority),
    action: parsedAction,
    createdAt,
    expiresAt,
    ...(value.popupDocumentId === undefined ? {} : { popupDocumentId: text(value.popupDocumentId, 'popupDocumentId') }),
  });
}

function source(value: unknown): AutofillContinuationSource {
  const wanted = [
    'frameDocumentId', 'frameId', 'frameOrigin', 'frameRuntimeIncarnation', 'frameUrlDigest', 'tabId',
    'topDocumentId', 'topOrigin', 'topRuntimeIncarnation', 'topUrlDigest', 'windowId',
  ];
  if (!record(value) || !keys(value, wanted)) throw new TypeError('Autofill continuation source is invalid');
  const parsed = Object.freeze({
    tabId: nonNegativeInteger(value.tabId, 'tabId'),
    windowId: nonNegativeInteger(value.windowId, 'windowId'),
    topDocumentId: text(value.topDocumentId, 'topDocumentId'),
    topRuntimeIncarnation: nullableRuntimeIncarnation(
      value.topRuntimeIncarnation,
      'topRuntimeIncarnation',
    ),
    topOrigin: httpOrigin(value.topOrigin, 'topOrigin'),
    topUrlDigest: digest(value.topUrlDigest, 'topUrlDigest'),
    frameId: nonNegativeInteger(value.frameId, 'frameId'),
    frameDocumentId: text(value.frameDocumentId, 'frameDocumentId'),
    frameRuntimeIncarnation: nullableRuntimeIncarnation(
      value.frameRuntimeIncarnation,
      'frameRuntimeIncarnation',
    ),
    frameOrigin: httpOrigin(value.frameOrigin, 'frameOrigin'),
    frameUrlDigest: digest(value.frameUrlDigest, 'frameUrlDigest'),
  });
  if (parsed.frameId === 0 && (
    parsed.frameDocumentId !== parsed.topDocumentId
    || parsed.frameRuntimeIncarnation !== parsed.topRuntimeIncarnation
    || parsed.frameOrigin !== parsed.topOrigin
    || parsed.frameUrlDigest !== parsed.topUrlDigest
  )) throw new TypeError('Autofill continuation top-frame source is invalid');
  return parsed;
}

function authority(value: unknown): AutofillContinuationAuthority {
  const wanted = [
    'accountGeneration', 'accountIdentity', 'autofillPolicyDigest', 'autofillPolicyGeneration',
    'enterprisePolicyGeneration', 'rawPolicyGeneration', 'serverGeneration', 'serverUrl',
    'workerInstanceId',
  ];
  if (!record(value) || !keys(value, wanted)) throw new TypeError('Autofill continuation authority is invalid');
  return Object.freeze({
    workerInstanceId: uuid(value.workerInstanceId, 'workerInstanceId'),
    serverUrl: httpUrl(value.serverUrl, 'serverUrl'),
    accountIdentity: text(value.accountIdentity, 'accountIdentity'),
    serverGeneration: nonNegativeInteger(value.serverGeneration, 'serverGeneration'),
    accountGeneration: nonNegativeInteger(value.accountGeneration, 'accountGeneration'),
    autofillPolicyGeneration: nonNegativeInteger(value.autofillPolicyGeneration, 'autofillPolicyGeneration'),
    autofillPolicyDigest: digest(value.autofillPolicyDigest, 'autofillPolicyDigest'),
    enterprisePolicyGeneration: nonNegativeInteger(value.enterprisePolicyGeneration, 'enterprisePolicyGeneration'),
    rawPolicyGeneration: text(value.rawPolicyGeneration, 'rawPolicyGeneration'),
  });
}

function action(value: unknown): AutofillContinuationAction {
  if (!record(value) || typeof value.kind !== 'string') throw new TypeError('Autofill continuation action is invalid');
  if (value.kind === 'locked_context' || value.kind === 'locked_keyboard') {
    if (!keys(value, ['kind'])) throw new TypeError('Autofill continuation action fields are invalid');
    return Object.freeze({ kind: value.kind });
  }
  if (value.kind === 'locked_command') {
    if (!keys(value, ['command', 'kind']) || !continuableCommand(value.command)) {
      throw new TypeError('Autofill continuation action fields are invalid');
    }
    return Object.freeze({ kind: value.kind, command: value.command });
  }
  if (value.kind === 'context_login_reprompt') {
    if (!keys(value, ['cipherId', 'kind', 'target'])) throw new TypeError('Autofill continuation action fields are invalid');
    return Object.freeze({ kind: value.kind, cipherId: text(value.cipherId, 'cipherId'), target: tabTarget(value.target) });
  }
  if (value.kind === 'command_fill_reprompt') {
    if (!keys(value, ['cipherId', 'command', 'kind', 'target']) || !directFillCommand(value.command)) {
      throw new TypeError('Autofill continuation action fields are invalid');
    }
    const target = tabTarget(value.target);
    if (!commandMatchesTarget(value.command, target)) {
      throw new TypeError('Autofill continuation command target is invalid');
    }
    return Object.freeze({
      kind: value.kind,
      command: value.command,
      cipherId: text(value.cipherId, 'cipherId'),
      target,
    });
  }
  if (value.kind === 'context_copy_reprompt') {
    if (!keys(value, ['cipherId', 'field', 'kind'])
        || (value.field !== 'password' && value.field !== 'totp')) {
      throw new TypeError('Autofill continuation action fields are invalid');
    }
    return Object.freeze({
      kind: value.kind,
      cipherId: text(value.cipherId, 'cipherId'),
      field: value.field,
    });
  }
  if (value.kind === 'context_structured_reprompt') {
    if (!keys(value, [
      'cipherId', 'fillKind', 'holdId', 'kind', 'roles', 'runtimeIncarnation', 'scope',
    ])) throw new TypeError('Autofill continuation action fields are invalid');
    if ((value.fillKind !== 'card' && value.fillKind !== 'identity') || (value.scope !== 'form' && value.scope !== 'field')) {
      throw new TypeError('Autofill continuation structured action is invalid');
    }
    const roles = normalizeFillRoles(value.fillKind, value.roles);
    if (!roles || (value.scope === 'field' && roles.length !== 1)) throw new TypeError('Autofill continuation roles are invalid');
    return Object.freeze({
      kind: value.kind,
      cipherId: text(value.cipherId, 'cipherId'),
      holdId: uuid(value.holdId, 'holdId'),
      scope: value.scope,
      fillKind: value.fillKind,
      roles: Object.freeze([...roles]),
      runtimeIncarnation: runtimeIncarnation(value.runtimeIncarnation, 'runtimeIncarnation'),
    });
  }
  if (value.kind === 'keyboard_reprompt') {
    if (!keys(value, ['binding', 'cipherId', 'kind'])) throw new TypeError('Keyboard action is invalid');
    const binding = safeKeyboardBinding(value.binding);
    return Object.freeze({
      kind: value.kind,
      cipherId: text(value.cipherId, 'cipherId'),
      binding,
    });
  }
  throw new TypeError('Autofill continuation action kind is invalid');
}

function continuableCommand(value: unknown): value is SecretExtensionCommand {
  return directFillCommand(value) || value === 'generate-password';
}

function directFillCommand(value: unknown): value is DirectFillCommand {
  return value === 'autofill-login' || value === 'autofill-card' || value === 'autofill-identity';
}

function commandMatchesTarget(command: DirectFillCommand, target: TabSuggestionTarget): boolean {
  return (command === 'autofill-login' && target.kind === 'login')
    || (command === 'autofill-card' && target.kind === 'card')
    || (command === 'autofill-identity' && target.kind === 'identity');
}

function safeKeyboardBinding(value: unknown): Extract<AutofillContinuationAction, { kind: 'keyboard_reprompt' }>['binding'] {
  if (!record(value) || typeof value.purpose !== 'string') throw new TypeError('Keyboard action binding is invalid');
  const incarnation = runtimeIncarnation(value.runtimeIncarnation, 'runtimeIncarnation');
  if (value.purpose === 'totp' && keys(value, ['purpose', 'runtimeIncarnation'])) {
    return Object.freeze({ purpose: value.purpose, runtimeIncarnation: incarnation });
  }
  if (value.purpose === 'login' && keys(value, ['customPlanDigest', 'purpose', 'runtimeIncarnation'])) {
    return Object.freeze({
      purpose: value.purpose,
      runtimeIncarnation: incarnation,
      customPlanDigest: text(value.customPlanDigest, 'customPlanDigest'),
    });
  }
  if ((value.purpose === 'card' || value.purpose === 'identity')
      && keys(value, ['formId', 'generation', 'purpose', 'roles', 'runtimeIncarnation',
        ...('selectedRoles' in value ? ['selectedRoles'] : [])])) {
    const roles = normalizeFillRoles(value.purpose, value.roles);
    if (!roles) throw new TypeError('Keyboard action roles are invalid');
    const selectedRoles = 'selectedRoles' in value
      ? selectedStructuredRoles(value.purpose, value.selectedRoles, roles)
      : undefined;
    return Object.freeze({
      purpose: value.purpose,
      runtimeIncarnation: incarnation,
      formId: text(value.formId, 'formId'),
      generation: nonNegativeInteger(value.generation, 'generation'),
      roles: Object.freeze([...roles]),
      ...(selectedRoles === undefined ? {} : { selectedRoles }),
    });
  }
  throw new TypeError('Keyboard action binding is invalid');
}

function tabTarget(value: unknown): TabSuggestionTarget {
  if (!record(value) || typeof value.kind !== 'string') throw new TypeError('Autofill target is invalid');
  const common = {
    frameId: nonNegativeInteger(value.frameId, 'frameId'),
    formId: text(value.formId, 'formId'),
    documentId: text(value.documentId, 'documentId'),
    runtimeIncarnation: runtimeIncarnation(value.runtimeIncarnation, 'runtimeIncarnation'),
    generation: nonNegativeInteger(value.generation, 'generation'),
  };
  if (value.kind === 'login' && keys(value, [
    'customPlanDigest', 'documentId', 'formId', 'frameId', 'generation', 'kind', 'runtimeIncarnation',
  ])) {
    return Object.freeze({ ...common, kind: value.kind, customPlanDigest: text(value.customPlanDigest, 'customPlanDigest') });
  }
  if ((value.kind === 'card' || value.kind === 'identity')
      && keys(value, ['documentId', 'formId', 'frameId', 'generation', 'kind', 'roles', 'runtimeIncarnation',
        ...('selectedRoles' in value ? ['selectedRoles'] : [])])
      && Array.isArray(value.roles) && value.roles.every((role) => typeof role === 'string')) {
    const roles = normalizeFillRoles(value.kind, value.roles);
    if (!roles) throw new TypeError('Autofill target roles are invalid');
    const selectedRoles = 'selectedRoles' in value
      ? selectedStructuredRoles(value.kind, value.selectedRoles, roles)
      : undefined;
    return Object.freeze({
      ...common,
      kind: value.kind,
      roles: Object.freeze([...roles]),
      ...(selectedRoles === undefined ? {} : { selectedRoles }),
    }) as TabSuggestionTarget;
  }
  throw new TypeError('Autofill target is invalid');
}

function selectedStructuredRoles(
  kind: FillKind,
  value: unknown,
  roles: readonly FillRole[],
): readonly FillRole[] {
  const selected = normalizeFillRoles(kind, value);
  if (!Array.isArray(value) || !selected || selected.length !== value.length
      || selected.some((role, index) => role !== value[index] || !roles.includes(role))) {
    throw new TypeError('Autofill selected roles are invalid');
  }
  return Object.freeze([...selected]);
}

function actionMatchesSource(action: AutofillContinuationAction, source: AutofillContinuationSource): boolean {
  if (action.kind === 'locked_keyboard') {
    return source.topRuntimeIncarnation === null
      && source.frameRuntimeIncarnation === null
      && source.frameId === 0
      && source.frameDocumentId === source.topDocumentId
      && source.frameOrigin === source.topOrigin
      && source.frameUrlDigest === source.topUrlDigest;
  }
  if (source.topRuntimeIncarnation === null || source.frameRuntimeIncarnation === null) return false;
  if (action.kind === 'context_login_reprompt' || action.kind === 'command_fill_reprompt') {
    return action.target.frameId === source.frameId
      && action.target.documentId === source.frameDocumentId
      && action.target.runtimeIncarnation === source.frameRuntimeIncarnation;
  }
  if (action.kind === 'keyboard_reprompt') {
    return action.binding.runtimeIncarnation === source.frameRuntimeIncarnation;
  }
  if (action.kind === 'context_structured_reprompt') {
    return action.runtimeIncarnation === source.frameRuntimeIncarnation;
  }
  return true;
}

function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function keys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function uuid(value: unknown, field: string): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function runtimeIncarnation(value: unknown, field: string): string {
  if (typeof value !== 'string' || !CANONICAL_UUID_V4.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function nullableRuntimeIncarnation(value: unknown, field: string): string | null {
  return value === null ? null : runtimeIncarnation(value, field);
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_TEXT
      || value.trim() !== value || containsControlCharacter(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function httpUrl(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL) throw new TypeError(`${field} is invalid`);
  const parsed = new URL(value);
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.username || parsed.password) throw new TypeError(`${field} is invalid`);
  return parsed.href;
}

function httpOrigin(value: unknown, field: string): string {
  const url = httpUrl(value, field);
  const parsed = new URL(url);
  if (parsed.href !== `${parsed.origin}/`) throw new TypeError(`${field} is invalid`);
  return parsed.origin;
}

function digest(value: unknown, field: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`${field} is invalid`);
  return value as number;
}

function positiveInteger(value: unknown, maximum: number, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) throw new TypeError(`${field} is invalid`);
  return value as number;
}

function number(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`${field} is invalid`);
  return value as number;
}

function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
