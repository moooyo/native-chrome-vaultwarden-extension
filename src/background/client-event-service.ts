import {
  ClientEventType,
  type CipherClientEventType,
  type ClientEvent,
} from '../core/events/client-event.js';
export type { ClientEventAuthorityProjection } from '../core/events/client-event.js';
import {
  createClientEventQueueScope,
  type ClientEventQueue,
  type ClientEventQueueScope,
} from './client-event-queue.js';
import {
  type ClientEventUploader,
  type ClientEventUploadResult,
} from './client-event-uploader.js';

export const CLIENT_EVENT_FLUSH_INTERVAL_MS = 60_000;

const CANONICAL_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const CIPHER_EVENT_TYPES = new Set<number>([
  ClientEventType.Cipher_ClientViewed,
  ClientEventType.Cipher_ClientToggledPasswordVisible,
  ClientEventType.Cipher_ClientToggledHiddenFieldVisible,
  ClientEventType.Cipher_ClientToggledCardCodeVisible,
  ClientEventType.Cipher_ClientCopiedPassword,
  ClientEventType.Cipher_ClientCopiedHiddenField,
  ClientEventType.Cipher_ClientCopiedCardCode,
  ClientEventType.Cipher_ClientAutofilled,
  ClientEventType.Cipher_ClientToggledCardNumberVisible,
  ClientEventType.Cipher_ClientToggledTOTPSeedVisible,
]);

const ORGANIZATION_EVENT_TYPES = new Set<number>([
  ClientEventType.Organization_ClientExportedVault,
  ClientEventType.Organization_ItemOrganization_Accepted,
  ClientEventType.Organization_ItemOrganization_Declined,
]);

export interface ClientEventAuthorityAdapter {
  captureActive(): unknown | PromiseLike<unknown>;
}

export type ClientEventPreparationRequest =
  | { readonly type: typeof ClientEventType.User_ClientExportedVault }
  | { readonly type: CipherClientEventType; readonly cipherId: string }
  | {
      readonly type:
        | typeof ClientEventType.Organization_ClientExportedVault
        | typeof ClientEventType.Organization_ItemOrganization_Accepted
        | typeof ClientEventType.Organization_ItemOrganization_Declined;
      /** This value must come from the worker operation that just succeeded, never from a message. */
      readonly organizationId: string;
    };

declare const CLIENT_EVENT_RECEIPT_BRAND: unique symbol;

/** Opaque, same-worker proof that event scope and ownership were captured before an action. */
export interface ClientEventReceipt {
  readonly [CLIENT_EVENT_RECEIPT_BRAND]: true;
}

export interface ClientEventAlarmSchedule {
  readonly scope: ClientEventQueueScope;
  readonly when: number;
  readonly reason: 'periodic' | 'retry';
}

export interface ClientEventAlarmScheduler {
  schedule(request: ClientEventAlarmSchedule): void | PromiseLike<void>;
  cancel?(scope: ClientEventQueueScope): void | PromiseLike<void>;
}

export type ClientEventServiceOperation =
  | 'authority'
  | 'enqueue'
  | 'flush'
  | 'discard'
  | 'schedule';

export type ClientEventCommitResult =
  | { readonly kind: 'enqueued' }
  | { readonly kind: 'failed' }
  | { readonly kind: 'not_pending' };

export type ClientEventServiceFlushResult =
  | ClientEventUploadResult
  | { readonly kind: 'failed' };

export type ClientEventDiscardResult =
  | { readonly kind: 'discarded'; readonly count: number }
  | { readonly kind: 'failed' };

export interface ClientEventServiceOptions {
  readonly authority: ClientEventAuthorityAdapter;
  readonly queue: Pick<ClientEventQueue, 'enqueue' | 'discardScope'>;
  readonly uploader: Pick<ClientEventUploader, 'flush'>;
  readonly alarm?: ClientEventAlarmScheduler;
  readonly now?: () => number;
  readonly onError?: (operation: ClientEventServiceOperation, error: unknown) => void;
}

interface ParsedAuthority {
  readonly scope: ClientEventQueueScope;
  readonly useEventsOrganizations: ReadonlySet<string>;
  readonly cipherOwners: ReadonlyMap<string, string | null>;
}

type ParsedPreparation = ClientEventPreparationRequest;

type PreparedEvent =
  | {
      readonly scope: ClientEventQueueScope;
      readonly receiptEpoch: object;
      readonly type: typeof ClientEventType.User_ClientExportedVault;
    }
  | {
      readonly scope: ClientEventQueueScope;
      readonly receiptEpoch: object;
      readonly type: CipherClientEventType;
      readonly cipherId: string;
      readonly organizationId: string;
    }
  | {
      readonly scope: ClientEventQueueScope;
      readonly receiptEpoch: object;
      readonly type:
        | typeof ClientEventType.Organization_ClientExportedVault
        | typeof ClientEventType.Organization_ItemOrganization_Accepted
        | typeof ClientEventType.Organization_ItemOrganization_Declined;
      readonly organizationId: string;
    };

/**
 * Worker-owned coordination boundary between successful user actions and the durable event queue.
 * Preparation captures authority without writing; commit consumes an opaque receipt before writing.
 */
export class ClientEventService {
  readonly #authority: ClientEventAuthorityAdapter;
  readonly #queue: ClientEventServiceOptions['queue'];
  readonly #uploader: ClientEventServiceOptions['uploader'];
  readonly #alarm: ClientEventAlarmScheduler | undefined;
  readonly #now: () => number;
  readonly #onError: ClientEventServiceOptions['onError'];
  readonly #receipts = new WeakMap<object, PreparedEvent>();
  readonly #scopeTails = new Map<string, Promise<void>>();
  #receiptEpoch: object = Object.freeze(Object.create(null));

  constructor(options: ClientEventServiceOptions) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('Client event service options are required');
    }
    if (!options.authority || typeof options.authority.captureActive !== 'function') {
      throw new TypeError('Client event service requires an authority adapter');
    }
    if (!options.queue || typeof options.queue.enqueue !== 'function'
      || typeof options.queue.discardScope !== 'function') {
      throw new TypeError('Client event service requires a durable queue');
    }
    if (!options.uploader || typeof options.uploader.flush !== 'function') {
      throw new TypeError('Client event service requires an uploader');
    }
    if (options.alarm !== undefined && typeof options.alarm.schedule !== 'function') {
      throw new TypeError('Client event alarm scheduler is invalid');
    }
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new TypeError('Client event service clock is invalid');
    }
    if (options.onError !== undefined && typeof options.onError !== 'function') {
      throw new TypeError('Client event service error observer is invalid');
    }
    this.#authority = options.authority;
    this.#queue = options.queue;
    this.#uploader = options.uploader;
    this.#alarm = options.alarm;
    this.#now = options.now ?? Date.now;
    this.#onError = options.onError;
  }

  /** Capture a queue scope before logout or account removal so later transitions cannot retarget it. */
  async captureActiveScope(): Promise<ClientEventQueueScope | undefined> {
    return (await this.#captureAuthority())?.scope;
  }

  /**
   * Capture all event authority before a user action. Returning undefined means the event is not
   * enabled for the trusted organization; it is not an action failure.
   */
  async prepare(requestInput: ClientEventPreparationRequest): Promise<ClientEventReceipt | undefined> {
    const request = parsePreparationRequest(requestInput);
    const authority = await this.#captureAuthority();
    if (!authority) return undefined;

    let prepared: PreparedEvent;
    const receiptEpoch = this.#receiptEpoch;
    if (request.type === ClientEventType.User_ClientExportedVault) {
      if (authority.useEventsOrganizations.size === 0) return undefined;
      prepared = Object.freeze({ scope: authority.scope, receiptEpoch, type: request.type });
    } else if ('cipherId' in request) {
      const organizationId = authority.cipherOwners.get(request.cipherId);
      if (typeof organizationId !== 'string'
        || !authority.useEventsOrganizations.has(organizationId)) return undefined;
      prepared = Object.freeze({
        scope: authority.scope,
        receiptEpoch,
        type: request.type,
        cipherId: request.cipherId,
        organizationId,
      });
    } else {
      if (!authority.useEventsOrganizations.has(request.organizationId)) return undefined;
      prepared = Object.freeze({
        scope: authority.scope,
        receiptEpoch,
        type: request.type,
        organizationId: request.organizationId,
      });
    }

    const receipt = Object.freeze(Object.create(null)) as ClientEventReceipt;
    this.#receipts.set(receipt, prepared);
    return receipt;
  }

  /** Consume one preparation and enqueue only after the owning user action reports success. */
  async commit(receipt: ClientEventReceipt): Promise<ClientEventCommitResult> {
    if (!isObject(receipt)) return Object.freeze({ kind: 'not_pending' });
    const prepared = this.#receipts.get(receipt);
    if (!prepared) return Object.freeze({ kind: 'not_pending' });

    // Consume before any fallible work so retries and concurrent callers cannot duplicate the event.
    this.#receipts.delete(receipt);
    return this.#serializeScope(prepared.scope, async () => {
      if (this.#receiptEpoch !== prepared.receiptEpoch) {
        return Object.freeze({ kind: 'not_pending' as const });
      }
      try {
        await this.#queue.enqueue(prepared.scope, materializeEvent(prepared, this.#currentTime()));
        await this.#schedulePeriodic(prepared.scope);
        return Object.freeze({ kind: 'enqueued' as const });
      } catch (error) {
        this.#report('enqueue', error);
        await this.#schedulePeriodic(prepared.scope);
        return Object.freeze({ kind: 'failed' as const });
      }
    });
  }

  /** Flush a scope captured before a transition; the active account is deliberately not re-read. */
  async flush(scopeInput: ClientEventQueueScope): Promise<ClientEventServiceFlushResult> {
    const scope = parseCapturedScope(scopeInput);
    return this.#serializeScope(scope, () => this.#flushSerialized(scope));
  }

  flushBeforeLogout(scope: ClientEventQueueScope): Promise<ClientEventServiceFlushResult> {
    return this.flush(scope);
  }

  /** Remove exactly one captured account/server scope during account removal. */
  async discardRemovedAccount(scopeInput: ClientEventQueueScope): Promise<ClientEventDiscardResult> {
    const scope = parseCapturedScope(scopeInput);
    this.#receiptEpoch = Object.freeze(Object.create(null));
    return this.#serializeScope(scope, async () => {
      try {
        const count = await this.#queue.discardScope(scope);
        await this.#cancelSchedule(scope);
        return Object.freeze({ kind: 'discarded' as const, count });
      } catch (error) {
        this.#report('discard', error);
        return Object.freeze({ kind: 'failed' as const });
      }
    });
  }

  /**
   * Remove logout-owned plaintext immediately through the queue storage lane. This deliberately
   * bypasses the upload scope lane: a transport promise may never settle, while queue acknowledge
   * and release already treat a concurrently removed scope as superseded and cannot recreate it.
   */
  async discardLoggedOutScope(scopeInput: ClientEventQueueScope): Promise<ClientEventDiscardResult> {
    const scope = parseCapturedScope(scopeInput);
    this.#receiptEpoch = Object.freeze(Object.create(null));
    try {
      const count = await this.#queue.discardScope(scope);
      await this.#cancelSchedule(scope);
      return Object.freeze({ kind: 'discarded' as const, count });
    } catch (error) {
      this.#report('discard', error);
      return Object.freeze({ kind: 'failed' as const });
    }
  }

  async #captureAuthority(): Promise<ParsedAuthority | undefined> {
    try {
      return parseClientEventAuthorityProjection(await this.#authority.captureActive());
    } catch (error) {
      this.#report('authority', error);
      return undefined;
    }
  }

  async #flushSerialized(scope: ClientEventQueueScope): Promise<ClientEventServiceFlushResult> {
    try {
      const result = await this.#uploader.flush(scope);
      await this.#scheduleAfterFlush(scope, result);
      return result;
    } catch (error) {
      this.#report('flush', error);
      await this.#schedulePeriodic(scope);
      return Object.freeze({ kind: 'failed' });
    }
  }

  async #scheduleAfterFlush(
    scope: ClientEventQueueScope,
    result: ClientEventUploadResult,
  ): Promise<void> {
    if (result.kind === 'retry_scheduled') {
      await this.#schedule(scope, result.retry.retryAt, 'retry');
      return;
    }
    if (result.kind === 'busy' || result.kind === 'deferred') {
      await this.#schedule(scope, result.retryAt, 'retry');
      return;
    }
    if (result.kind === 'uploaded') {
      await this.#schedulePeriodic(scope);
      return;
    }
    await this.#cancelSchedule(scope);
  }

  async #schedule(
    scope: ClientEventQueueScope,
    when: number,
    reason: ClientEventAlarmSchedule['reason'],
  ): Promise<void> {
    if (!this.#alarm) return;
    try {
      await this.#alarm.schedule(Object.freeze({ scope, when, reason }));
    } catch (error) {
      this.#report('schedule', error);
    }
  }

  async #schedulePeriodic(scope: ClientEventQueueScope): Promise<void> {
    try {
      await this.#schedule(scope, this.#nextPeriodicTime(), 'periodic');
    } catch (error) {
      this.#report('schedule', error);
    }
  }

  async #cancelSchedule(scope: ClientEventQueueScope): Promise<void> {
    if (!this.#alarm?.cancel) return;
    try {
      await this.#alarm.cancel(scope);
    } catch (error) {
      this.#report('schedule', error);
    }
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Client event clock is invalid');
    return now;
  }

  #nextPeriodicTime(): number {
    const now = this.#currentTime();
    const next = now + CLIENT_EVENT_FLUSH_INTERVAL_MS;
    return Number.isSafeInteger(next) ? next : Number.MAX_SAFE_INTEGER;
  }

  #serializeScope<Result>(
    scope: ClientEventQueueScope,
    operation: () => Promise<Result>,
  ): Promise<Result> {
    const key = scopeKey(scope);
    const previous = this.#scopeTails.get(key) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const tail = result.then(() => undefined, () => undefined);
    this.#scopeTails.set(key, tail);
    void tail.finally(() => {
      if (this.#scopeTails.get(key) === tail) this.#scopeTails.delete(key);
    });
    return result;
  }

  #report(operation: ClientEventServiceOperation, error: unknown): void {
    try {
      this.#onError?.(operation, error);
    } catch {
      // Diagnostics must never affect the protected user action or durable queue settlement.
    }
  }
}

/** Strictly parse the worker adapter's bounded active-profile projection. */
export function parseClientEventAuthorityProjection(input: unknown): ParsedAuthority {
  const record = requirePlainRecord(input, 'Client event authority projection must be a plain object');
  requireExactDataKeys(record, ['serverUrl', 'userId', 'organizations', 'ciphers']);
  const serverUrl = requireStringData(record, 'serverUrl');
  const userId = requireCanonicalUuid(dataValue(record, 'userId'), 'userId');
  const scope = createClientEventQueueScope(serverUrl, userId);
  const organizations = requireDenseArray(dataValue(record, 'organizations'), 'organizations');
  const ciphers = requireDenseArray(dataValue(record, 'ciphers'), 'ciphers');

  const knownOrganizations = new Set<string>();
  const useEventsOrganizations = new Set<string>();
  for (const value of organizations) {
    const organization = requirePlainRecord(value, 'Client event organization projection is invalid');
    requireExactDataKeys(organization, ['id', 'useEvents']);
    const id = requireCanonicalUuid(dataValue(organization, 'id'), 'organizationId');
    const useEvents = dataValue(organization, 'useEvents');
    if (typeof useEvents !== 'boolean' || knownOrganizations.has(id)) {
      throw new TypeError('Client event organization projection is invalid');
    }
    knownOrganizations.add(id);
    if (useEvents) useEventsOrganizations.add(id);
  }

  const cipherOwners = new Map<string, string | null>();
  for (const value of ciphers) {
    const cipher = requirePlainRecord(value, 'Client event cipher projection is invalid');
    requireExactDataKeys(cipher, ['id', 'organizationId']);
    const id = requireCanonicalUuid(dataValue(cipher, 'id'), 'cipherId');
    const rawOrganizationId = dataValue(cipher, 'organizationId');
    const organizationId = rawOrganizationId === null
      ? null
      : requireCanonicalUuid(rawOrganizationId, 'organizationId');
    if (cipherOwners.has(id)) throw new TypeError('Client event cipher projection is invalid');
    cipherOwners.set(id, organizationId);
  }

  return Object.freeze({ scope, useEventsOrganizations, cipherOwners });
}

function parsePreparationRequest(input: unknown): ParsedPreparation {
  const record = requirePlainRecord(input, 'Client event preparation must be a plain object');
  const type = dataValue(record, 'type');
  if (type === ClientEventType.User_ClientExportedVault) {
    requireExactDataKeys(record, ['type']);
    return Object.freeze({ type });
  }
  if (typeof type === 'number' && CIPHER_EVENT_TYPES.has(type)) {
    requireExactDataKeys(record, ['type', 'cipherId']);
    return Object.freeze({
      type: type as CipherClientEventType,
      cipherId: requireCanonicalUuid(dataValue(record, 'cipherId'), 'cipherId'),
    });
  }
  if (typeof type === 'number' && ORGANIZATION_EVENT_TYPES.has(type)) {
    requireExactDataKeys(record, ['type', 'organizationId']);
    const organizationType = type as
      | typeof ClientEventType.Organization_ClientExportedVault
      | typeof ClientEventType.Organization_ItemOrganization_Accepted
      | typeof ClientEventType.Organization_ItemOrganization_Declined;
    return Object.freeze({
      type: organizationType,
      organizationId: requireCanonicalUuid(dataValue(record, 'organizationId'), 'organizationId'),
    });
  }
  throw new TypeError('Client event preparation type is unsupported');
}

function materializeEvent(prepared: PreparedEvent, now: number): ClientEvent {
  const date = new Date(now).toISOString();
  if (prepared.type === ClientEventType.User_ClientExportedVault) {
    return Object.freeze({ type: prepared.type, date });
  }
  if ('cipherId' in prepared) {
    return Object.freeze({
      type: prepared.type,
      date,
      cipherId: prepared.cipherId,
      organizationId: prepared.organizationId,
    });
  }
  return Object.freeze({
    type: prepared.type,
    date,
    organizationId: prepared.organizationId,
  });
}

function parseCapturedScope(input: ClientEventQueueScope): ClientEventQueueScope {
  if (!isObject(input)) throw new TypeError('Client event captured scope is invalid');
  return createClientEventQueueScope(input.serverUrl, input.accountId);
}

function scopeKey(scope: ClientEventQueueScope): string {
  return JSON.stringify([scope.serverUrl, scope.accountId]);
}

function requireCanonicalUuid(value: unknown, field: string): string {
  if (typeof value !== 'string' || !CANONICAL_UUID_PATTERN.test(value)) {
    throw new TypeError(`Client event ${field} must be a canonical UUID`);
  }
  return value;
}

function requireStringData(record: Record<string, unknown>, key: string): string {
  const value = dataValue(record, key);
  if (typeof value !== 'string') throw new TypeError(`Client event ${key} must be a string`);
  return value;
}

function requireDenseArray(value: unknown, field: string): readonly unknown[] {
  if (!Array.isArray(value) || !hasDenseArrayShape(value)) {
    throw new TypeError(`Client event ${field} must be a dense array`);
  }
  return value;
}

function requirePlainRecord(value: unknown, message: string): Record<string, unknown> {
  if (!isPlainRecord(value)) throw new TypeError(message);
  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function isObject(value: unknown): value is object & Record<PropertyKey, unknown> {
  return typeof value === 'object' && value !== null;
}

function requireExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Reflect.ownKeys(record);
  const expectedSet = new Set(expected);
  if (keys.length !== expected.length
    || keys.some((key) => typeof key !== 'string' || !expectedSet.has(key))) {
    throw new TypeError('Client event input has unexpected fields');
  }
  for (const key of expected) dataValue(record, key);
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor?.enumerable || !('value' in descriptor)) {
    throw new TypeError(`Client event input is missing ${key}`);
  }
  return descriptor.value;
}

function hasDenseArrayShape(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return true;
}
