import { canonicalizeServerCapabilityUrl } from '../core/api/server-capabilities.js';
import type { ClientEventWire } from '../core/events/client-event.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  ClientEventQueue,
  MAX_CLIENT_EVENT_QUEUE_SCOPES,
  createClientEventQueueScope,
  type ClientEventQueueOptions,
  type ClientEventQueueScope,
} from './client-event-queue.js';
import {
  ClientEventService,
  parseClientEventAuthorityProjection,
  type ClientEventAlarmSchedule,
  type ClientEventAuthorityAdapter,
  type ClientEventCommitResult,
  type ClientEventPreparationRequest,
  type ClientEventReceipt,
  type ClientEventServiceFlushResult,
  type ClientEventServiceOperation,
} from './client-event-service.js';
import {
  ClientEventUploader,
  type ClientEventTransport,
  type ClientEventTransportResult,
} from './client-event-uploader.js';

export const CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY = 'enterpriseClientEventScopes.v1';
export const CLIENT_EVENT_LOGOUT_MARKER_STORAGE_KEY = 'enterpriseClientEventLogoutScopes.v1';
export const CLIENT_EVENT_LOGOUT_SUCCEEDED_MARKER_STORAGE_KEY =
  'enterpriseClientEventLogoutSucceededScopes.v1';
export const CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION = 1 as const;
export const MAX_CLIENT_EVENT_SCOPE_DIRECTORY_ENTRIES = MAX_CLIENT_EVENT_QUEUE_SCOPES;
export const MAX_CLIENT_EVENT_SCOPE_DIRECTORY_UTF8_BYTES = 256 * 1024;
export const CLIENT_EVENT_UPLOAD_ALARM = 'enterprise-client-events-upload-v1';

const MAX_SERVER_URL_LENGTH = 2_048;
const MAX_ACCOUNT_IDENTITY_LENGTH = 254;
const MAX_DIRECTORY_UTF8_BYTES = 1024 * 1024;
const MAX_DIRECTORY_STORAGE_KEY_LENGTH = 256;
const CANONICAL_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface ClientEventAccountIdentity {
  readonly serverUrl: string;
  readonly accountIdentity: string;
}

export interface ClientEventScopeBinding extends ClientEventAccountIdentity {
  readonly accountId: string;
  readonly scope: ClientEventQueueScope;
}

declare const CLIENT_EVENT_SCOPE_CAPTURE_BRAND: unique symbol;

/** Opaque proof that one exact directory binding was current when captured. */
export interface ClientEventScopeCapture {
  readonly binding: ClientEventScopeBinding;
  readonly [CLIENT_EVENT_SCOPE_CAPTURE_BRAND]: true;
}

export type ClientEventScopeDirectoryErrorCode =
  | 'capacity'
  | 'corrupt_state'
  | 'unsupported_schema'
  | 'changed'
  | 'persistence_failed'
  | 'outcome_unknown'
  | 'rollback_failed';

export class ClientEventScopeDirectoryError extends Error {
  constructor(
    readonly code: ClientEventScopeDirectoryErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'ClientEventScopeDirectoryError';
  }
}

export interface ClientEventScopeDirectoryOptions {
  readonly maxEntries?: number;
  readonly maxStoredBytes?: number;
}

interface StoredScopeBinding {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly accountId: string;
}

interface StoredScopeDirectory {
  readonly schemaVersion: typeof CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION;
  readonly entries: Readonly<Record<string, StoredScopeBinding>>;
}

interface SharedDirectoryState {
  tail: Promise<void>;
  epoch: number;
  pendingMutations: number;
  unavailable: boolean;
}

interface CapturedDirectoryState {
  readonly epoch: number;
  readonly key: string;
}

const SHARED_DIRECTORY_STATES = new WeakMap<object, Map<string, SharedDirectoryState>>();

/** Strict persistent mapping from the account registry identity to its canonical profile UUID. */
export class ClientEventScopeDirectory {
  readonly #storageKey: string;
  readonly #maxEntries: number;
  readonly #maxStoredBytes: number;
  readonly #shared: SharedDirectoryState;
  readonly #captures = new WeakMap<object, CapturedDirectoryState>();

  constructor(
    private readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>,
    options: ClientEventScopeDirectoryOptions = {},
    storageKey = CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY,
  ) {
    if (!store || typeof store.get !== 'function'
        || typeof store.set !== 'function' || typeof store.remove !== 'function') {
      throw new TypeError('Client event scope directory requires a key-value store');
    }
    if (!storageKey || storageKey.length > MAX_DIRECTORY_STORAGE_KEY_LENGTH) {
      throw new TypeError('Client event scope directory storage key is invalid');
    }
    this.#storageKey = storageKey;
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? MAX_CLIENT_EVENT_SCOPE_DIRECTORY_ENTRIES,
      MAX_CLIENT_EVENT_SCOPE_DIRECTORY_ENTRIES,
      'maxEntries',
    );
    this.#maxStoredBytes = boundedPositiveInteger(
      options.maxStoredBytes ?? MAX_CLIENT_EVENT_SCOPE_DIRECTORY_UTF8_BYTES,
      MAX_DIRECTORY_UTF8_BYTES,
      'maxStoredBytes',
    );
    this.#shared = sharedDirectoryState(store, this.#storageKey);
  }

  async capture(
    identityInput: ClientEventAccountIdentity,
  ): Promise<ClientEventScopeCapture | undefined> {
    const identity = parseAccountIdentity(identityInput);
    const key = identityKey(identity);
    return this.#serialize(async () => {
      this.#assertNoPendingMutation();
      const epoch = this.#shared.epoch;
      const directory = await this.#read();
      this.#assertStableRead(epoch);
      const stored = directory.entries[key];
      if (!stored) return undefined;
      const binding = freezeBinding(stored);
      const capture = Object.freeze({ binding }) as ClientEventScopeCapture;
      this.#captures.set(capture, Object.freeze({ epoch, key }));
      return capture;
    });
  }

  assertCurrent(capture: ClientEventScopeCapture): void {
    const issued = isObject(capture) ? this.#captures.get(capture) : undefined;
    if (!issued || this.#shared.pendingMutations !== 0 || issued.epoch !== this.#shared.epoch
        || issued.key !== identityKey(capture.binding)) {
      throw new ClientEventScopeDirectoryError(
        'changed',
        'Client event scope directory changed during the operation',
      );
    }
  }

  async upsert(
    bindingInput: Omit<ClientEventScopeBinding, 'scope'>,
    assertCurrent?: () => void,
  ): Promise<ClientEventScopeBinding> {
    const binding = parseBinding(bindingInput);
    if (assertCurrent !== undefined && typeof assertCurrent !== 'function') {
      throw new TypeError('Client event scope directory guard is invalid');
    }
    const key = identityKey(binding);
    return this.#mutate(async () => {
      const { raw, directory } = await this.#readState();
      if (!Object.hasOwn(directory.entries, key)
          && Object.keys(directory.entries).length >= this.#maxEntries) {
        throw new ClientEventScopeDirectoryError(
          'capacity',
          'Client event scope directory capacity was reached',
        );
      }
      const entries = copyEntries(directory.entries);
      entries[key] = storedBinding(binding);
      await this.#replaceVerified({
        schemaVersion: CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION,
        entries,
      }, raw, directory, assertCurrent);
      return binding;
    });
  }

  async remove(
    identityInput: ClientEventAccountIdentity,
    expectedAccountId?: string,
  ): Promise<ClientEventScopeBinding | undefined> {
    const identity = parseAccountIdentity(identityInput);
    const expected = expectedAccountId === undefined
      ? undefined
      : requireCanonicalProfileId(expectedAccountId);
    const key = identityKey(identity);
    return this.#mutate(async () => {
      const { raw, directory } = await this.#readState();
      const current = directory.entries[key];
      if (!current || (expected !== undefined && current.accountId !== expected)) return undefined;
      const entries = copyEntries(directory.entries);
      delete entries[key];
      const next = Object.keys(entries).length === 0
        ? undefined
        : {
          schemaVersion: CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION,
          entries,
        } as const;
      await this.#replaceVerified(next, raw, directory);
      return freezeBinding(current);
    });
  }

  async listExact(): Promise<readonly ClientEventScopeBinding[]> {
    return this.#serialize(async () => {
      this.#assertNoPendingMutation();
      const epoch = this.#shared.epoch;
      const directory = await this.#read();
      this.#assertStableRead(epoch);
      return Object.freeze(Object.keys(directory.entries)
        .sort(compareAscii)
        .map((key) => freezeBinding(directory.entries[key]!)));
    });
  }

  async #read(): Promise<StoredScopeDirectory> {
    return (await this.#readState()).directory;
  }

  async #readState(): Promise<{ readonly raw: unknown; readonly directory: StoredScopeDirectory }> {
    this.#assertAvailable();
    const raw = await this.store.get<unknown>(this.#storageKey);
    return Object.freeze({
      raw,
      directory: parseDirectory(raw, this.#maxEntries, this.#maxStoredBytes),
    });
  }

  async #replaceVerified(
    next: StoredScopeDirectory | undefined,
    previousRaw: unknown,
    previous: StoredScopeDirectory,
    assertCurrent?: () => void,
  ): Promise<void> {
    if (next && directoryBytes(next) > this.#maxStoredBytes) {
      throw new ClientEventScopeDirectoryError(
        'capacity',
        'Client event scope directory byte capacity was reached',
      );
    }
    assertCurrent?.();
    let writeError: unknown;
    try {
      if (next) await this.store.set(this.#storageKey, next);
      else await this.store.remove(this.#storageKey);
    } catch (error) {
      writeError = error;
    }

    let guardError: unknown;
    try {
      assertCurrent?.();
    } catch (error) {
      guardError = error;
    }

    const observed = await this.#readBackOrFail(writeError, guardError);
    if (guardError === undefined) {
      try {
        assertCurrent?.();
      } catch (error) {
        guardError = error;
      }
    }
    const matchesNext = this.#matches(observed, next);
    const previousExpected = previousRaw === undefined ? undefined : previous;
    if (matchesNext && guardError === undefined) return;
    if (matchesNext) {
      await this.#restoreOwned(previousRaw, previousExpected, next, guardError);
      throw guardError;
    }
    if (this.#matches(observed, previousExpected)) {
      if (guardError !== undefined) throw guardError;
      if (writeError !== undefined) throw writeError;
      throw new ClientEventScopeDirectoryError(
        'persistence_failed',
        'Client event scope directory write was not committed',
      );
    }

    this.#shared.unavailable = true;
    throw new ClientEventScopeDirectoryError(
      'outcome_unknown',
      'Client event scope directory changed outside its serialized operation',
      aggregateCause(writeError, guardError),
    );
  }

  async #readBackOrFail(...causes: unknown[]): Promise<unknown> {
    try {
      return await this.store.get<unknown>(this.#storageKey);
    } catch (error) {
      this.#shared.unavailable = true;
      throw new ClientEventScopeDirectoryError(
        'outcome_unknown',
        'Client event scope directory write outcome could not be verified',
        { cause: new AggregateError([...causes.filter(defined), error]) },
      );
    }
  }

  async #restoreOwned(
    previousRaw: unknown,
    previous: StoredScopeDirectory | undefined,
    written: StoredScopeDirectory | undefined,
    primaryError: unknown,
  ): Promise<void> {
    const before = await this.#readBackOrFail(primaryError);
    if (this.#matches(before, previous)) return;
    if (!this.#matches(before, written)) {
      this.#shared.unavailable = true;
      throw new ClientEventScopeDirectoryError(
        'outcome_unknown',
        'Client event scope directory changed before rollback',
        { cause: primaryError },
      );
    }

    let rollbackError: unknown;
    try {
      if (previousRaw === undefined) {
        await this.store.remove(this.#storageKey);
      } else {
        await this.store.set(this.#storageKey, previousRaw);
      }
    } catch (error) {
      rollbackError = error;
    }
    const after = await this.#readBackOrFail(primaryError, rollbackError);
    if (this.#matches(after, previous)) return;
    this.#shared.unavailable = true;
    throw new ClientEventScopeDirectoryError(
      'rollback_failed',
      'Client event scope directory write could not be rolled back',
      { cause: new AggregateError([primaryError, rollbackError].filter(defined)) },
    );
  }

  #matches(raw: unknown, expected: StoredScopeDirectory | undefined): boolean {
    if (expected === undefined) return raw === undefined;
    try {
      const parsed = parseDirectory(raw, this.#maxEntries, this.#maxStoredBytes);
      return directoryFingerprint(parsed) === directoryFingerprint(expected);
    } catch {
      return false;
    }
  }

  #mutate<Result>(operation: () => Promise<Result>): Promise<Result> {
    this.#shared.epoch += 1;
    this.#shared.pendingMutations += 1;
    const result = this.#serialize(operation);
    return result.finally(() => {
      this.#shared.pendingMutations -= 1;
    });
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#shared.tail.then(operation, operation);
    this.#shared.tail = result.then(() => undefined, () => undefined);
    return result;
  }

  #assertNoPendingMutation(): void {
    this.#assertAvailable();
    if (this.#shared.pendingMutations !== 0) {
      throw new ClientEventScopeDirectoryError(
        'changed',
        'Client event scope directory mutation is pending',
      );
    }
  }

  #assertStableRead(epoch: number): void {
    this.#assertAvailable();
    if (this.#shared.pendingMutations !== 0 || this.#shared.epoch !== epoch) {
      throw new ClientEventScopeDirectoryError(
        'changed',
        'Client event scope directory changed during the operation',
      );
    }
  }

  #assertAvailable(): void {
    if (this.#shared.unavailable) {
      throw new ClientEventScopeDirectoryError(
        'rollback_failed',
        'Client event scope directory is unavailable after a failed rollback',
      );
    }
  }
}

export type ClientEventAccountLeaseLike = ClientEventAccountIdentity;

export interface ClientEventCollectClient {
  collectClientEvents(
    accessToken: string,
    events: readonly ClientEventWire[],
  ): PromiseLike<ClientEventTransportResult>;
}

export interface ClientEventProductionTransportDependencies<
  Lease extends ClientEventAccountLeaseLike,
> {
  readonly directory: ClientEventScopeDirectory;
  captureAccountLease(): Lease;
  assertAccountLease(lease: Lease): void;
  executeAuthenticatedRequest<Result>(
    lease: Lease,
    rebuildRequest: (accessToken: string) => Promise<Result>,
  ): Promise<Result>;
  /** Must return an ApiClient clone fixed to serverUrl and guarded by assertCurrent. */
  apiForServer(serverUrl: string, assertCurrent: () => void): ClientEventCollectClient;
}

export type ClientEventProductionErrorCode = 'scope_unavailable' | 'scope_mismatch';

export class ClientEventProductionError extends Error {
  constructor(readonly code: ClientEventProductionErrorCode, message: string) {
    super(message);
    this.name = 'ClientEventProductionError';
  }
}

/** Account-leased transport that lets AuthService own the sole 401 refresh and rebuilt retry. */
export class ClientEventProductionTransport<Lease extends ClientEventAccountLeaseLike>
implements ClientEventTransport {
  constructor(
    private readonly deps: ClientEventProductionTransportDependencies<Lease>,
  ) {
    if (!deps || !(deps.directory instanceof ClientEventScopeDirectory)
        || typeof deps.captureAccountLease !== 'function'
        || typeof deps.assertAccountLease !== 'function'
        || typeof deps.executeAuthenticatedRequest !== 'function'
        || typeof deps.apiForServer !== 'function') {
      throw new TypeError('Client event production transport dependencies are invalid');
    }
  }

  async upload(
    scopeInput: ClientEventQueueScope,
    events: readonly ClientEventWire[],
  ): Promise<ClientEventTransportResult> {
    const scope = parseProfileScope(scopeInput);
    const lease = this.deps.captureAccountLease();
    const capture = await this.deps.directory.capture(lease);
    this.deps.assertAccountLease(lease);
    if (!capture) {
      throw new ClientEventProductionError(
        'scope_unavailable',
        'Client event account scope is unavailable',
      );
    }
    const assertCurrent = (): void => {
      this.deps.assertAccountLease(lease);
      this.deps.directory.assertCurrent(capture);
    };
    assertCurrent();
    if (!sameScope(scope, capture.binding.scope)) {
      throw new ClientEventProductionError(
        'scope_mismatch',
        'Client event upload scope does not match the active account',
      );
    }
    const api = this.deps.apiForServer(capture.binding.serverUrl, assertCurrent);
    if (!api || typeof api.collectClientEvents !== 'function') {
      throw new TypeError('Client event collect client is invalid');
    }
    assertCurrent();
    const result = await this.deps.executeAuthenticatedRequest(lease, async (accessToken) => {
      assertCurrent();
      return api.collectClientEvents(accessToken, events);
    });
    // Prefer at-least-once duplication over acknowledging a response after its authority changed.
    assertCurrent();
    return result;
  }
}

export interface ClientEventAlarmApi {
  get(name: string): PromiseLike<{ readonly scheduledTime?: number } | undefined>;
  create(name: string, options: { readonly when: number }): void | PromiseLike<void>;
  clear(name: string): boolean | PromiseLike<boolean>;
}

export interface ClientEventFixedAlarmSchedulerDependencies<
  Lease extends ClientEventAccountLeaseLike,
> {
  readonly directory: ClientEventScopeDirectory;
  readonly alarms: ClientEventAlarmApi;
  captureAccountLease(): Lease;
  assertAccountLease(lease: Lease): void;
}

/** One PII-free alarm, arbitrated so an old account cannot replace or clear the active schedule. */
export class ClientEventFixedAlarmScheduler<Lease extends ClientEventAccountLeaseLike> {
  #tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly deps: ClientEventFixedAlarmSchedulerDependencies<Lease>,
  ) {
    if (!deps || !(deps.directory instanceof ClientEventScopeDirectory)
        || !deps.alarms || typeof deps.alarms.get !== 'function'
        || typeof deps.alarms.create !== 'function'
        || typeof deps.alarms.clear !== 'function'
        || typeof deps.captureAccountLease !== 'function'
        || typeof deps.assertAccountLease !== 'function') {
      throw new TypeError('Client event fixed alarm dependencies are invalid');
    }
  }

  schedule(request: ClientEventAlarmSchedule): Promise<void> {
    const scope = parseProfileScope(request.scope);
    if (!Number.isSafeInteger(request.when) || request.when < 0
        || (request.reason !== 'periodic' && request.reason !== 'retry')) {
      return Promise.reject(new TypeError('Client event alarm schedule is invalid'));
    }
    return this.#serialize(async () => {
      const active = await this.#captureActive();
      if (!active || !sameScope(active.capture.binding.scope, scope)) return;
      const assertCurrent = (): void => {
        this.deps.assertAccountLease(active.lease);
        this.deps.directory.assertCurrent(active.capture);
      };
      assertCurrent();
      const existing = await this.deps.alarms.get(CLIENT_EVENT_UPLOAD_ALARM);
      assertCurrent();
      if (existing && Number.isSafeInteger(existing.scheduledTime)
          && existing.scheduledTime! <= request.when) return;
      await this.deps.alarms.create(CLIENT_EVENT_UPLOAD_ALARM, { when: request.when });
      try {
        assertCurrent();
      } catch (error) {
        await this.deps.alarms.clear(CLIENT_EVENT_UPLOAD_ALARM);
        throw error;
      }
    });
  }

  cancel(scopeInput: ClientEventQueueScope): Promise<void> {
    const scope = parseProfileScope(scopeInput);
    return this.#serialize(async () => {
      const active = await this.#captureActive();
      if (!active || !sameScope(active.capture.binding.scope, scope)) return;
      this.deps.assertAccountLease(active.lease);
      this.deps.directory.assertCurrent(active.capture);
      await this.deps.alarms.clear(CLIENT_EVENT_UPLOAD_ALARM);
    });
  }

  async captureActiveScope(): Promise<ClientEventQueueScope | undefined> {
    return (await this.#captureActive())?.capture.binding.scope;
  }

  async #captureActive(): Promise<{
    readonly lease: Lease;
    readonly capture: ClientEventScopeCapture;
  } | undefined> {
    const lease = this.deps.captureAccountLease();
    const capture = await this.deps.directory.capture(lease);
    this.deps.assertAccountLease(lease);
    if (!capture) return undefined;
    this.deps.directory.assertCurrent(capture);
    return Object.freeze({ lease, capture });
  }

  #serialize(operation: () => Promise<void>): Promise<void> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export interface ClientEventProductionDependencies<Lease extends ClientEventAccountLeaseLike> {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly authority: ClientEventAuthorityAdapter;
  readonly alarms: ClientEventAlarmApi;
  captureAccountLease(): Lease;
  assertAccountLease(lease: Lease): void;
  executeAuthenticatedRequest<Result>(
    lease: Lease,
    rebuildRequest: (accessToken: string) => Promise<Result>,
  ): Promise<Result>;
  apiForServer(serverUrl: string, assertCurrent: () => void): ClientEventCollectClient;
}

export interface ClientEventProductionOptions {
  readonly directory?: ClientEventScopeDirectoryOptions;
  readonly queue?: ClientEventQueueOptions;
  readonly now?: () => number;
  readonly onServiceError?: (operation: ClientEventServiceOperation, error: unknown) => void;
  readonly onTransportError?: (error: unknown) => void;
}

declare const CLIENT_EVENT_ACCOUNT_REMOVAL_BRAND: unique symbol;
declare const CLIENT_EVENT_SERVER_CHANGE_BRAND: unique symbol;
declare const CLIENT_EVENT_LOGOUT_BRAND: unique symbol;
declare const CLIENT_EVENT_CONFIRMED_LOGOUT_BRAND: unique symbol;

export interface ClientEventAccountRemovalReceipt {
  readonly [CLIENT_EVENT_ACCOUNT_REMOVAL_BRAND]: true;
}

export interface ClientEventServerChangeReceipt {
  readonly [CLIENT_EVENT_SERVER_CHANGE_BRAND]: true;
}

export interface ClientEventLogoutReceipt {
  readonly [CLIENT_EVENT_LOGOUT_BRAND]: true;
}

export interface ClientEventConfirmedLogoutReceipt {
  readonly [CLIENT_EVENT_CONFIRMED_LOGOUT_BRAND]: true;
}

export interface ClientEventProductionRuntime<Lease extends ClientEventAccountLeaseLike> {
  readonly directory: ClientEventScopeDirectory;
  readonly logoutMarkers: ClientEventScopeDirectory;
  readonly logoutSucceededMarkers: ClientEventScopeDirectory;
  readonly queue: ClientEventQueue;
  readonly transport: ClientEventProductionTransport<Lease>;
  readonly uploader: ClientEventUploader;
  readonly alarm: ClientEventFixedAlarmScheduler<Lease>;
  readonly service: ClientEventService;
  /** Issue receipts only after the active account has one verified persistent scope binding. */
  prepare(request: ClientEventPreparationRequest): Promise<ClientEventReceipt | undefined>;
  commit(receipt: ClientEventReceipt): Promise<ClientEventCommitResult>;
  /** Persist the active profile UUID under one outer account lease for later alarms and removal. */
  synchronizeActiveBinding(): Promise<ClientEventScopeBinding>;
  flushActive(): Promise<ClientEventServiceFlushResult | undefined>;
  handleAlarm(name: string): Promise<boolean>;
  captureLogout(): Promise<ClientEventLogoutReceipt>;
  flushBeforeLogout(receipt: ClientEventLogoutReceipt): Promise<
    ClientEventServiceFlushResult | undefined
  >;
  confirmLogout(
    receipt: ClientEventLogoutReceipt,
  ): Promise<ClientEventConfirmedLogoutReceipt | undefined>;
  discardConfirmedLogout(receipt: ClientEventConfirmedLogoutReceipt): Promise<boolean>;
  completeLogout(receipt: ClientEventLogoutReceipt, succeeded: boolean): Promise<boolean>;
  reconcileLogoutDiscards(registeredAccounts: readonly ClientEventAccountIdentity[]): Promise<{
    readonly discarded: number;
    readonly preserved: number;
    readonly failed: number;
  }>;
  discardServerScopes(serverUrl: string): Promise<{
    readonly discarded: number;
    readonly failed: number;
  }>;
  captureAccountRemoval(accountIdentity: string): Promise<ClientEventAccountRemovalReceipt>;
  completeAccountRemoval(receipt: ClientEventAccountRemovalReceipt): Promise<boolean>;
  captureServerChange(serverUrl: string): Promise<ClientEventServerChangeReceipt>;
  completeServerChange(receipt: ClientEventServerChangeReceipt): Promise<{
    readonly discarded: number;
    readonly failed: number;
  }>;
}

/** Build the complete event pipeline without importing browser globals or production composition. */
export function createClientEventProduction<Lease extends ClientEventAccountLeaseLike>(
  deps: ClientEventProductionDependencies<Lease>,
  options: ClientEventProductionOptions = {},
): ClientEventProductionRuntime<Lease> {
  if (!deps || !deps.authority || typeof deps.authority.captureActive !== 'function') {
    throw new TypeError('Client event production authority is invalid');
  }
  const directory = new ClientEventScopeDirectory(deps.store, options.directory);
  const logoutMarkers = new ClientEventScopeDirectory(
    deps.store,
    options.directory,
    CLIENT_EVENT_LOGOUT_MARKER_STORAGE_KEY,
  );
  const logoutSucceededMarkers = new ClientEventScopeDirectory(
    deps.store,
    options.directory,
    CLIENT_EVENT_LOGOUT_SUCCEEDED_MARKER_STORAGE_KEY,
  );
  const queueOptions = {
    ...(options.queue ?? {}),
    ...(options.now ? { now: options.now } : {}),
  };
  const queue = new ClientEventQueue(deps.store, queueOptions);
  const transport = new ClientEventProductionTransport({
    directory,
    captureAccountLease: deps.captureAccountLease,
    assertAccountLease: deps.assertAccountLease,
    executeAuthenticatedRequest: deps.executeAuthenticatedRequest,
    apiForServer: deps.apiForServer,
  });
  const uploader = new ClientEventUploader(queue, transport, {
    ...(options.onTransportError ? { onTransportError: options.onTransportError } : {}),
  });
  const alarm = new ClientEventFixedAlarmScheduler({
    directory,
    alarms: deps.alarms,
    captureAccountLease: deps.captureAccountLease,
    assertAccountLease: deps.assertAccountLease,
  });
  const service = new ClientEventService({
    authority: deps.authority,
    queue,
    uploader,
    alarm,
    ...(options.now ? { now: options.now } : {}),
    ...(options.onServiceError ? { onError: options.onServiceError } : {}),
  });
  const logoutReceipts = new WeakMap<object, ClientEventScopeBinding | null>();
  const confirmedLogoutReceipts = new WeakMap<object, ClientEventScopeBinding | null>();
  const accountRemovalReceipts = new WeakMap<object, ClientEventScopeBinding | null>();
  const serverChangeReceipts = new WeakMap<object, readonly ClientEventScopeBinding[]>();

  const synchronizeBindingForLease = async (lease: Lease): Promise<ClientEventScopeBinding> => {
    await settleConfirmedLogoutForIdentity(lease);
    deps.assertAccountLease(lease);
    const projection = parseClientEventAuthorityProjection(await deps.authority.captureActive());
    deps.assertAccountLease(lease);
    const leaseServerUrl = canonicalServerUrl(lease.serverUrl);
    if (projection.scope.serverUrl !== leaseServerUrl) {
      throw new ClientEventProductionError(
        'scope_mismatch',
        'Client event authority scope does not match the active account server',
      );
    }
    const existing = await directory.capture(lease);
    deps.assertAccountLease(lease);
    if (existing && existing.binding.accountId === projection.scope.accountId) {
      directory.assertCurrent(existing);
      return existing.binding;
    }
    const stored = await directory.upsert({
      serverUrl: projection.scope.serverUrl,
      accountIdentity: lease.accountIdentity,
      accountId: projection.scope.accountId,
    }, () => deps.assertAccountLease(lease));
    deps.assertAccountLease(lease);
    return stored;
  };

  const discardBinding = async (binding: ClientEventScopeBinding): Promise<boolean> => {
    const result = await service.discardRemovedAccount(binding.scope);
    if (result.kind !== 'discarded') return false;
    await directory.remove(binding, binding.accountId);
    return true;
  };

  const markLogoutBinding = (
    binding: ClientEventScopeBinding,
    assertCurrent?: () => void,
  ): Promise<ClientEventScopeBinding> => logoutMarkers.upsert({
    serverUrl: binding.serverUrl,
    accountIdentity: binding.accountIdentity,
    accountId: binding.accountId,
  }, assertCurrent);

  const markLogoutSucceeded = async (binding: ClientEventScopeBinding): Promise<void> => {
    await logoutSucceededMarkers.upsert({
      serverUrl: binding.serverUrl,
      accountIdentity: binding.accountIdentity,
      accountId: binding.accountId,
    });
    await logoutMarkers.remove(binding, binding.accountId);
  };

  const discardLoggedOutBinding = async (binding: ClientEventScopeBinding): Promise<boolean> => {
    // Start both mutations before awaiting either. Their independent verified storage lanes then
    // order any same-account relogin writes after the old queue and directory removals.
    const queueDiscard = service.discardLoggedOutScope(binding.scope);
    const directoryRemoval = directory.remove(binding, binding.accountId);
    const [result] = await Promise.all([queueDiscard, directoryRemoval]);
    if (result.kind !== 'discarded') return false;
    await Promise.all([
      logoutMarkers.remove(binding, binding.accountId),
      logoutSucceededMarkers.remove(binding, binding.accountId),
    ]);
    return true;
  };

  const settleConfirmedLogoutForIdentity = async (
    identity: ClientEventAccountIdentity,
  ): Promise<void> => {
    const confirmed = await logoutSucceededMarkers.capture(identity);
    if (!confirmed) return;
    if (!await discardLoggedOutBinding(confirmed.binding)) {
      throw new ClientEventProductionError(
        'scope_unavailable',
        'Confirmed client event logout cleanup could not be completed',
      );
    }
  };

  return Object.freeze({
    directory,
    logoutMarkers,
    logoutSucceededMarkers,
    queue,
    transport,
    uploader,
    alarm,
    service,
    async prepare(
      request: ClientEventPreparationRequest,
    ): Promise<ClientEventReceipt | undefined> {
      const lease = deps.captureAccountLease();
      const binding = await synchronizeBindingForLease(lease);
      const receipt = await service.prepare(request);
      deps.assertAccountLease(lease);
      if (!receipt) return undefined;
      const verified = await directory.capture(lease);
      deps.assertAccountLease(lease);
      if (!verified || !sameScope(verified.binding.scope, binding.scope)) {
        throw new ClientEventProductionError(
          'scope_unavailable',
          'Client event account scope is unavailable',
        );
      }
      directory.assertCurrent(verified);
      return receipt;
    },
    commit: (receipt: ClientEventReceipt) => service.commit(receipt),
    async synchronizeActiveBinding(): Promise<ClientEventScopeBinding> {
      const lease = deps.captureAccountLease();
      return synchronizeBindingForLease(lease);
    },
    async flushActive(): Promise<ClientEventServiceFlushResult | undefined> {
      const scope = await alarm.captureActiveScope();
      return scope ? service.flush(scope) : undefined;
    },
    async handleAlarm(name: string): Promise<boolean> {
      if (name !== CLIENT_EVENT_UPLOAD_ALARM) return false;
      const scope = await alarm.captureActiveScope();
      if (scope) await service.flush(scope);
      return true;
    },
    async captureLogout(): Promise<ClientEventLogoutReceipt> {
      const lease = deps.captureAccountLease();
      await settleConfirmedLogoutForIdentity(lease);
      deps.assertAccountLease(lease);
      const captured = await directory.capture(lease);
      deps.assertAccountLease(lease);
      if (captured) {
        await markLogoutBinding(captured.binding, () => {
          deps.assertAccountLease(lease);
          directory.assertCurrent(captured);
        });
        deps.assertAccountLease(lease);
        directory.assertCurrent(captured);
      }
      const receipt = Object.freeze(Object.create(null)) as ClientEventLogoutReceipt;
      logoutReceipts.set(receipt, captured?.binding ?? null);
      return receipt;
    },
    async flushBeforeLogout(
      receipt: ClientEventLogoutReceipt,
    ): Promise<ClientEventServiceFlushResult | undefined> {
      if (!isObject(receipt) || !logoutReceipts.has(receipt)) return undefined;
      const binding = logoutReceipts.get(receipt) ?? null;
      return binding ? service.flushBeforeLogout(binding.scope) : undefined;
    },
    async completeLogout(
      receipt: ClientEventLogoutReceipt,
      succeeded: boolean,
    ): Promise<boolean> {
      if (!succeeded) {
        if (!isObject(receipt) || !logoutReceipts.has(receipt)) return false;
        const binding = logoutReceipts.get(receipt) ?? null;
        logoutReceipts.delete(receipt);
        if (binding) await logoutMarkers.remove(binding, binding.accountId);
        return true;
      }
      const confirmed = await this.confirmLogout(receipt);
      return confirmed ? this.discardConfirmedLogout(confirmed) : false;
    },
    async confirmLogout(
      receipt: ClientEventLogoutReceipt,
    ): Promise<ClientEventConfirmedLogoutReceipt | undefined> {
      if (!isObject(receipt) || !logoutReceipts.has(receipt)) return undefined;
      const binding = logoutReceipts.get(receipt) ?? null;
      logoutReceipts.delete(receipt);
      if (binding) await markLogoutSucceeded(binding);
      const confirmed = Object.freeze(Object.create(null)) as ClientEventConfirmedLogoutReceipt;
      confirmedLogoutReceipts.set(confirmed, binding);
      return confirmed;
    },
    async discardConfirmedLogout(receipt: ClientEventConfirmedLogoutReceipt): Promise<boolean> {
      if (!isObject(receipt) || !confirmedLogoutReceipts.has(receipt)) return false;
      const binding = confirmedLogoutReceipts.get(receipt) ?? null;
      confirmedLogoutReceipts.delete(receipt);
      return binding ? discardLoggedOutBinding(binding) : true;
    },
    async reconcileLogoutDiscards(
      registeredAccounts: readonly ClientEventAccountIdentity[],
    ): Promise<{ readonly discarded: number; readonly preserved: number; readonly failed: number }> {
      if (!Array.isArray(registeredAccounts)) {
        throw new TypeError('Client event registered accounts must be an array');
      }
      const registered = new Set(registeredAccounts.map((identity) => (
        identityKey(parseAccountIdentity(identity))
      )));
      const [preparedMarkers, succeededMarkers, bindings] = await Promise.all([
        logoutMarkers.listExact(),
        logoutSucceededMarkers.listExact(),
        directory.listExact(),
      ]);
      const currentByIdentity = new Map(bindings.map((binding) => [identityKey(binding), binding]));
      const confirmed = new Set(succeededMarkers.map((binding) => (
        `${identityKey(binding)}\0${binding.accountId}`
      )));
      let discarded = 0;
      let preserved = 0;
      let failed = 0;
      for (const marker of succeededMarkers) {
        try {
          if (await discardLoggedOutBinding(marker)) discarded += 1;
          else failed += 1;
        } catch {
          failed += 1;
        }
      }
      for (const marker of preparedMarkers) {
        if (confirmed.has(`${identityKey(marker)}\0${marker.accountId}`)) continue;
        try {
          const key = identityKey(marker);
          const current = currentByIdentity.get(key);
          if (registered.has(key) && (!current || current.accountId === marker.accountId)) {
            await logoutMarkers.remove(marker, marker.accountId);
            preserved += 1;
          } else {
            await markLogoutSucceeded(marker);
            if (await discardLoggedOutBinding(marker)) discarded += 1;
            else failed += 1;
          }
        } catch {
          failed += 1;
        }
      }
      return Object.freeze({ discarded, preserved, failed });
    },
    async discardServerScopes(
      serverUrl: string,
    ): Promise<{ readonly discarded: number; readonly failed: number }> {
      const canonicalServer = canonicalServerUrl(serverUrl);
      const [directoryBindings, markerBindings, succeededMarkerBindings] = await Promise.all([
        directory.listExact(),
        logoutMarkers.listExact(),
        logoutSucceededMarkers.listExact(),
      ]);
      const bindings = new Map<string, ClientEventScopeBinding>();
      for (const binding of [
        ...directoryBindings,
        ...markerBindings,
        ...succeededMarkerBindings,
      ]) {
        if (binding.serverUrl !== canonicalServer) continue;
        bindings.set(`${identityKey(binding)}\0${binding.accountId}`, binding);
      }
      let discarded = 0;
      let failed = 0;
      for (const binding of bindings.values()) {
        try {
          await markLogoutSucceeded(binding);
          if (await discardLoggedOutBinding(binding)) discarded += 1;
          else failed += 1;
        } catch {
          failed += 1;
        }
      }
      return Object.freeze({ discarded, failed });
    },
    async captureAccountRemoval(
      accountIdentity: string,
    ): Promise<ClientEventAccountRemovalReceipt> {
      const lease = deps.captureAccountLease();
      const captured = await directory.capture({
        serverUrl: lease.serverUrl,
        accountIdentity,
      });
      deps.assertAccountLease(lease);
      const receipt = Object.freeze(Object.create(null)) as ClientEventAccountRemovalReceipt;
      accountRemovalReceipts.set(receipt, captured?.binding ?? null);
      return receipt;
    },
    async completeAccountRemoval(receipt: ClientEventAccountRemovalReceipt): Promise<boolean> {
      if (!isObject(receipt) || !accountRemovalReceipts.has(receipt)) return false;
      const binding = accountRemovalReceipts.get(receipt) ?? null;
      accountRemovalReceipts.delete(receipt);
      return binding ? discardBinding(binding) : true;
    },
    async captureServerChange(serverUrl: string): Promise<ClientEventServerChangeReceipt> {
      const canonicalServer = canonicalServerUrl(serverUrl);
      const bindings = Object.freeze((await directory.listExact())
        .filter((binding) => binding.serverUrl === canonicalServer));
      const receipt = Object.freeze(Object.create(null)) as ClientEventServerChangeReceipt;
      serverChangeReceipts.set(receipt, bindings);
      return receipt;
    },
    async completeServerChange(receipt: ClientEventServerChangeReceipt): Promise<{
      readonly discarded: number;
      readonly failed: number;
    }> {
      if (!isObject(receipt) || !serverChangeReceipts.has(receipt)) {
        return Object.freeze({ discarded: 0, failed: 0 });
      }
      const bindings = serverChangeReceipts.get(receipt) ?? [];
      serverChangeReceipts.delete(receipt);
      let discarded = 0;
      let failed = 0;
      for (const binding of bindings) {
        try {
          if (await discardBinding(binding)) discarded += 1;
          else failed += 1;
        } catch {
          failed += 1;
        }
      }
      return Object.freeze({ discarded, failed });
    },
  });
}

function parseDirectory(
  value: unknown,
  maxEntries: number,
  maxStoredBytes: number,
): StoredScopeDirectory {
  if (value === undefined) return emptyDirectory();
  if (!isPlainRecord(value)) throw corruptDirectory();
  const schemaDescriptor = Object.getOwnPropertyDescriptor(value, 'schemaVersion');
  const schemaVersion = schemaDescriptor?.enumerable === true && 'value' in schemaDescriptor
    ? schemaDescriptor.value
    : undefined;
  if (Number.isSafeInteger(schemaVersion)
      && (schemaVersion as number) > CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION) {
    throw new ClientEventScopeDirectoryError(
      'unsupported_schema',
      'Client event scope directory uses an unsupported schema version',
    );
  }
  if (!hasExactDataKeys(value, ['schemaVersion', 'entries'])
      || schemaVersion !== CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION) {
    throw corruptDirectory();
  }
  const rawEntries = dataValue(value, 'entries');
  if (!isPlainRecord(rawEntries)) throw corruptDirectory();
  const keys = Reflect.ownKeys(rawEntries);
  if (keys.length > maxEntries || keys.some((key) => typeof key !== 'string')) {
    throw corruptDirectory();
  }
  const entries: Record<string, StoredScopeBinding> = Object.create(null) as Record<
    string,
    StoredScopeBinding
  >;
  for (const key of keys as string[]) {
    try {
      const descriptor = Object.getOwnPropertyDescriptor(rawEntries, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) throw corruptDirectory();
      const binding = parseBinding(descriptor.value);
      if (identityKey(binding) !== key
          || !isPlainRecord(descriptor.value)
          || dataValue(descriptor.value, 'serverUrl') !== binding.serverUrl
          || dataValue(descriptor.value, 'accountIdentity') !== binding.accountIdentity) {
        throw corruptDirectory();
      }
      entries[key] = storedBinding(binding);
    } catch (error) {
      if (error instanceof ClientEventScopeDirectoryError && error.code === 'corrupt_state') {
        throw error;
      }
      throw corruptDirectory();
    }
  }
  const directory = Object.freeze({
    schemaVersion: CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION,
    entries: Object.freeze(entries),
  });
  if (directoryBytes(directory) > maxStoredBytes) throw corruptDirectory();
  return directory;
}

function emptyDirectory(): StoredScopeDirectory {
  return Object.freeze({
    schemaVersion: CLIENT_EVENT_SCOPE_DIRECTORY_SCHEMA_VERSION,
    entries: Object.freeze(Object.create(null) as Record<string, StoredScopeBinding>),
  });
}

function parseBinding(value: unknown): ClientEventScopeBinding {
  if (!isPlainRecord(value)
      || !hasExactDataKeys(value, ['serverUrl', 'accountIdentity', 'accountId'])) {
    throw new TypeError('Client event scope binding is invalid');
  }
  const identity = parseAccountIdentity({
    serverUrl: dataValue(value, 'serverUrl'),
    accountIdentity: dataValue(value, 'accountIdentity'),
  });
  const accountId = requireCanonicalProfileId(dataValue(value, 'accountId'));
  return Object.freeze({
    ...identity,
    accountId,
    scope: createClientEventQueueScope(identity.serverUrl, accountId),
  });
}

function parseAccountIdentity(value: unknown): ClientEventAccountIdentity {
  if (!isPlainRecord(value)) throw new TypeError('Client event account identity is invalid');
  const serverUrl = canonicalServerUrl(dataValue(value, 'serverUrl'));
  const accountIdentity = canonicalAccountIdentity(dataValue(value, 'accountIdentity'));
  return Object.freeze({ serverUrl, accountIdentity });
}

function canonicalServerUrl(value: unknown): string {
  if (typeof value !== 'string' || value.length > MAX_SERVER_URL_LENGTH) {
    throw new TypeError('Client event server URL is invalid');
  }
  return canonicalizeServerCapabilityUrl(value);
}

function canonicalAccountIdentity(value: unknown): string {
  if (typeof value !== 'string') throw new TypeError('Client event account identity is invalid');
  const identity = value.trim().toLowerCase();
  if (identity.length < 3 || identity.length > MAX_ACCOUNT_IDENTITY_LENGTH
      || !/^[^@\s]+@[^@\s]+$/u.test(identity) || containsControl(identity)) {
    throw new TypeError('Client event account identity is invalid');
  }
  return identity;
}

function requireCanonicalProfileId(value: unknown): string {
  if (typeof value !== 'string' || !CANONICAL_UUID_PATTERN.test(value)) {
    throw new TypeError('Client event profile account ID must be a canonical UUID');
  }
  return value;
}

function parseProfileScope(value: ClientEventQueueScope): ClientEventQueueScope {
  const scope = createClientEventQueueScope(value?.serverUrl, value?.accountId);
  requireCanonicalProfileId(scope.accountId);
  return scope;
}

function freezeBinding(value: StoredScopeBinding): ClientEventScopeBinding {
  return parseBinding(value);
}

function storedBinding(value: ClientEventScopeBinding): StoredScopeBinding {
  return Object.freeze({
    serverUrl: value.serverUrl,
    accountIdentity: value.accountIdentity,
    accountId: value.accountId,
  });
}

function identityKey(value: ClientEventAccountIdentity): string {
  return JSON.stringify([value.serverUrl, value.accountIdentity]);
}

function sameScope(left: ClientEventQueueScope, right: ClientEventQueueScope): boolean {
  return left.serverUrl === right.serverUrl && left.accountId === right.accountId;
}

function copyEntries(
  value: Readonly<Record<string, StoredScopeBinding>>,
): Record<string, StoredScopeBinding> {
  const copy: Record<string, StoredScopeBinding> = Object.create(null) as Record<
    string,
    StoredScopeBinding
  >;
  for (const key of Object.keys(value)) copy[key] = value[key]!;
  return copy;
}

function directoryBytes(value: StoredScopeDirectory): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function directoryFingerprint(value: StoredScopeDirectory): string {
  return JSON.stringify(Object.keys(value.entries).sort(compareAscii).map((key) => {
    const entry = value.entries[key]!;
    return [key, entry.serverUrl, entry.accountIdentity, entry.accountId];
  }));
}

function sharedDirectoryState(store: object, key: string): SharedDirectoryState {
  let stores = SHARED_DIRECTORY_STATES.get(store);
  if (!stores) {
    stores = new Map<string, SharedDirectoryState>();
    SHARED_DIRECTORY_STATES.set(store, stores);
  }
  let shared = stores.get(key);
  if (!shared) {
    shared = { tail: Promise.resolve(), epoch: 0, pendingMutations: 0, unavailable: false };
    stores.set(key, shared);
  }
  return shared;
}

function corruptDirectory(): ClientEventScopeDirectoryError {
  return new ClientEventScopeDirectoryError(
    'corrupt_state',
    'Client event scope directory is corrupt',
  );
}

function aggregateCause(...causes: unknown[]): ErrorOptions | undefined {
  const present = causes.filter(defined);
  return present.length === 0 ? undefined : { cause: new AggregateError(present) };
}

function defined(value: unknown): boolean {
  return value !== undefined;
}

function hasExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  const expectedSet = new Set(expected);
  if (keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expectedSet.has(key))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor?.enumerable || !('value' in descriptor)) {
    throw new TypeError(`Client event scope directory is missing ${key}`);
  }
  return descriptor.value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function containsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new RangeError(`${name} must be a positive safe integer no greater than ${maximum}`);
  }
  return value;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
