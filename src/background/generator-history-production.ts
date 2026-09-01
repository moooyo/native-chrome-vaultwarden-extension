import { canonicalizeServerCapabilityUrl } from '../core/api/server-capabilities.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import { AppError } from '../core/errors.js';
import {
  createUserKeyGeneratorHistoryCrypto,
  type GeneratorHistoryCrypto,
} from '../core/generator/history-crypto.js';
import {
  isGeneratorHistoryEntryType,
  type GeneratorHistoryEntry,
  type GeneratorHistoryEntryType,
} from '../core/generator/history.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  GeneratorHistoryRepository,
  createGeneratorHistoryScope,
  type GeneratorHistoryRepositoryOptions,
  type GeneratorHistoryScope,
} from './generator-history-repository.js';

export const GENERATOR_HISTORY_SCOPE_INDEX_KEY = 'generatorHistoryScopeIndex.v1';
export const GENERATOR_HISTORY_SCOPE_INDEX_SCHEMA_VERSION = 1 as const;
export const MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES = 32;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const SCOPE_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const INDEX_REVISION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_TRACK_VALUE_UTF8_BYTES = 32 * 1_024;
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const ENCODER = new TextEncoder();

export interface GeneratorHistoryAuthority {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly userId: string;
  readonly policyRevision: number;
  readonly crypto: GeneratorHistoryCrypto;
  readonly assertCurrent: () => void;
}

export interface GeneratorHistoryProductionOptions {
  /** Production must pass the singleton localStore adapter; FIFO sharing is keyed by object identity. */
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly repository?: Pick<
    GeneratorHistoryRepository,
    'read' | 'track' | 'clear' | 'lock' | 'unlock' | 'remove'
  >;
  readonly withCurrentAuthority: <Result>(
    operation: (authority: GeneratorHistoryAuthority) => Promise<Result>,
  ) => Promise<Result>;
  readonly createIndexRevision?: () => string;
}

export interface GeneratorHistoryTrackRequest {
  readonly value: string;
  readonly type: GeneratorHistoryEntryType;
  readonly policyRevision: number;
}

export interface GeneratorHistoryListResult {
  readonly entries: readonly GeneratorHistoryEntry[];
}

export interface GeneratorHistoryTrackResponse {
  readonly added: boolean;
}

export interface GeneratorHistoryClearResponse {
  readonly cleared: boolean;
}

export interface GeneratorHistoryRegisteredAccount {
  readonly serverUrl: string;
  readonly accountIdentity: string;
}

export interface GeneratorHistoryIdentityProjection {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly userId: string;
}

export interface GeneratorHistorySecurityBinding<SessionLease, AccountLease, PolicyLease> {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly policyRevision: number;
}

export interface GeneratorHistoryAuthorityProviderOptions<SessionLease, AccountLease, PolicyLease> {
  /** Captures all three in-memory fences synchronously, before any secret-bearing await. */
  readonly captureSecurity: () => GeneratorHistorySecurityBinding<SessionLease, AccountLease, PolicyLease>;
  readonly assertSecurity: (
    binding: GeneratorHistorySecurityBinding<SessionLease, AccountLease, PolicyLease>,
  ) => void;
  readonly captureIdentity: () => Promise<GeneratorHistoryIdentityProjection>;
  /** Returns an owned key. The provider clears it after taking its own short-lived copy. */
  readonly loadUserKey: () => Promise<SymmetricKey | undefined>;
  readonly createCrypto?: (userKey: SymmetricKey) => GeneratorHistoryCrypto;
}

export interface GeneratorHistoryRotationRemovalReceipt {
  readonly kind: 'generatorHistoryRotationRemoval';
}

/**
 * Bind repository work to one session/account/policy generation without retaining UserKey material.
 * Every asynchronous boundary is fenced; both the loaded key and the provider-owned copy are cleared.
 */
export function createGeneratorHistoryAuthorityProvider<SessionLease, AccountLease, PolicyLease>(
  options: GeneratorHistoryAuthorityProviderOptions<SessionLease, AccountLease, PolicyLease>,
): GeneratorHistoryProductionOptions['withCurrentAuthority'] {
  if (!options || !isFunction(options.captureSecurity) || !isFunction(options.assertSecurity)
    || !isFunction(options.captureIdentity) || !isFunction(options.loadUserKey)
    || (options.createCrypto !== undefined && !isFunction(options.createCrypto))) {
    throw new TypeError('Generator history authority dependencies are invalid');
  }
  const createCrypto = options.createCrypto ?? createUserKeyGeneratorHistoryCrypto;
  return async <Result>(
    operation: (authority: GeneratorHistoryAuthority) => Promise<Result>,
  ): Promise<Result> => {
    const security = options.captureSecurity();
    const assertSecurity = (): void => options.assertSecurity(security);

    assertSecurity();
    const rawIdentity = await options.captureIdentity();
    assertSecurity();
    const identity = parseIdentityProjection(rawIdentity);
    const assertCurrent = (): void => {
      assertSecurity();
      if (identity.serverUrl !== security.serverUrl
        || identity.accountIdentity !== security.accountIdentity) {
        throw productionError('scope_mismatch', 'Generator history authority changed account');
      }
    };

    assertCurrent();
    if (!Number.isSafeInteger(security.policyRevision) || security.policyRevision < 0) {
      throw productionError('invalid_authority', 'Generator history policy revision is invalid');
    }

    assertCurrent();
    const loadedUserKey = await options.loadUserKey();
    let ownedUserKey: SymmetricKey | undefined;
    try {
      assertCurrent();
      if (!loadedUserKey) throw new AppError('locked', 'Vault is locked');
      ownedUserKey = copyUserKey(loadedUserKey);
    } finally {
      if (loadedUserKey) zeroSymmetricKey(loadedUserKey);
    }

    try {
      assertCurrent();
      const crypto = createCrypto(ownedUserKey);
      assertCurrent();
      const result = await operation(Object.freeze({
        serverUrl: identity.serverUrl,
        accountIdentity: identity.accountIdentity,
        userId: identity.userId,
        policyRevision: security.policyRevision,
        crypto,
        assertCurrent,
      }));
      assertCurrent();
      return result;
    } finally {
      zeroSymmetricKey(ownedUserKey);
    }
  };
}

export type GeneratorHistoryProductionErrorCode =
  | 'corrupt_index'
  | 'index_capacity'
  | 'index_rollback_failed'
  | 'index_unavailable'
  | 'history_rollback_failed'
  | 'invalid_authority'
  | 'invalid_request'
  | 'scope_mismatch'
  | 'stale_policy'
  | 'unsupported_index_schema';

export class GeneratorHistoryProductionError extends Error {
  constructor(
    readonly code: GeneratorHistoryProductionErrorCode,
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'GeneratorHistoryProductionError';
  }
}

interface StoredScopeIndexEntry {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly userId: string;
  readonly scopeDigest: string;
  readonly storageKey: string;
}

interface StoredScopeIndex {
  readonly schemaVersion: typeof GENERATOR_HISTORY_SCOPE_INDEX_SCHEMA_VERSION;
  readonly revision: string;
  readonly entries: readonly StoredScopeIndexEntry[];
}

interface LoadedScopeIndex {
  readonly envelope: StoredScopeIndex | undefined;
  readonly entries: readonly StoredScopeIndexEntry[];
}

interface SharedProductionCoordinator {
  tail: Promise<void>;
  unavailable: boolean;
  readonly unavailableScopes: Set<string>;
}

interface NormalizedAuthority extends GeneratorHistoryAuthority {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly userId: string;
}

const COORDINATORS = new WeakMap<object, SharedProductionCoordinator>();

/** Worker-owned bridge between current account authority and the encrypted history repository. */
export class GeneratorHistoryProductionService {
  readonly #store: GeneratorHistoryProductionOptions['store'];
  readonly #repository: NonNullable<GeneratorHistoryProductionOptions['repository']>;
  readonly #withCurrentAuthority: GeneratorHistoryProductionOptions['withCurrentAuthority'];
  readonly #createIndexRevision: () => string;
  readonly #coordinator: SharedProductionCoordinator;
  readonly #rotationReceipts = new WeakMap<object, StoredScopeIndexEntry>();
  readonly #claimedRotationReceipts = new WeakSet<object>();
  #active: { readonly accountKey: string; readonly scope: GeneratorHistoryScope } | undefined;

  constructor(options: GeneratorHistoryProductionOptions) {
    if (!options || !isFunction(options.store?.get)
      || !isFunction(options.store?.set) || !isFunction(options.store?.remove)
      || !isFunction(options.withCurrentAuthority)) {
      throw new TypeError('Generator history production dependencies are invalid');
    }
    this.#store = options.store;
    this.#repository = options.repository
      ?? new GeneratorHistoryRepository({ store: options.store } as GeneratorHistoryRepositoryOptions);
    this.#withCurrentAuthority = options.withCurrentAuthority;
    this.#createIndexRevision = options.createIndexRevision ?? (() => crypto.randomUUID());
    let coordinator = COORDINATORS.get(options.store as object);
    if (!coordinator) {
      coordinator = { tail: Promise.resolve(), unavailable: false, unavailableScopes: new Set() };
      COORDINATORS.set(options.store as object, coordinator);
    }
    this.#coordinator = coordinator;
  }

  list(bindFinalAuthority?: (assertCurrent: () => void) => void): Promise<GeneratorHistoryListResult> {
    return this.#serialize(() => this.#withAuthority(async (authority, scope) => {
      authority.assertCurrent();
      const entries = await this.#repository.read(scope, authority.crypto);
      authority.assertCurrent();
      bindFinalAuthority?.(authority.assertCurrent);
      authority.assertCurrent();
      return Object.freeze({
        entries: Object.freeze(entries.map((entry) => Object.freeze({
          generatedAt: entry.generatedAt,
          type: entry.type,
          value: entry.value,
        }))),
      });
    }));
  }

  track(input: GeneratorHistoryTrackRequest): Promise<GeneratorHistoryTrackResponse> {
    const request = parseTrackRequest(input);
    return this.#serialize(() => this.#withAuthority(async (authority, scope) => {
      authority.assertCurrent();
      const result = await this.#withHistoryRollback(scope, authority.assertCurrent, () => (
        this.#repository.track(scope, authority.crypto, { type: request.type, value: request.value })
      ));
      return Object.freeze({ added: result.added });
    }, (authority) => {
      if (request.policyRevision !== authority.policyRevision) {
        throw productionError('stale_policy', 'Generator policy changed before history tracking');
      }
    }));
  }

  clear(): Promise<GeneratorHistoryClearResponse> {
    return this.#serialize(() => this.#withAuthority(async (authority, scope) => {
      authority.assertCurrent();
      const cleared = await this.#withHistoryRollback(scope, authority.assertCurrent, () => (
        this.#repository.clear(scope, authority.crypto)
      ));
      return Object.freeze({ cleared });
    }));
  }

  /** Immediately revoke repository work for the active account without awaiting the production FIFO. */
  lockActiveScope(): void {
    const active = this.#active;
    if (!active) return;
    this.#repository.lock(active.scope);
    this.#active = undefined;
  }

  /** Re-establish the current scope after a fresh unlocked authority has been published. */
  unlockCurrent(): Promise<void> {
    return this.#serialize(() => this.#withAuthority(async (authority) => {
      authority.assertCurrent();
    }).then(() => undefined));
  }

  /** Logout or account removal: delete one indexed account without requiring its UserKey. */
  removeExactAccount(serverUrlInput: string, accountIdentityInput: string): Promise<boolean> {
    const serverUrl = canonicalServerUrl(serverUrlInput);
    const accountIdentity = normalizedAccountIdentity(accountIdentityInput);
    return this.#serialize(async () => (await this.#removeAccounts(
      (entry) => entry.serverUrl === serverUrl && entry.accountIdentity === accountIdentity,
    )) > 0);
  }

  /** Server reset: delete every indexed account belonging to that canonical server. */
  removeServerScopes(serverUrlInput: string): Promise<number> {
    const serverUrl = canonicalServerUrl(serverUrlInput);
    return this.#serialize(() => this.#removeAccounts((entry) => entry.serverUrl === serverUrl));
  }

  /** Startup repair: remove every indexed scope no longer present in the durable account registry. */
  reconcileRegisteredAccounts(accountsInput: readonly GeneratorHistoryRegisteredAccount[]): Promise<number> {
    const accounts = parseRegisteredAccounts(accountsInput);
    return this.#serialize(() => this.#removeAccounts((entry) => (
      !accounts.has(accountKey(entry.serverUrl, entry.accountIdentity))
    )));
  }

  /**
   * Capture only opaque deletion metadata before a rotation logs the account out. The receipt is
   * intentionally same-worker only. Startup recovery must use the durable rotation marker's server
   * with removeServerScopes because key rotation resets every account registered on that server.
   */
  captureRotationRemoval(): Promise<GeneratorHistoryRotationRemovalReceipt> {
    return this.#serialize(() => this.#withAuthority(async (authority, scope) => {
      authority.assertCurrent();
      const receipt = Object.freeze({ kind: 'generatorHistoryRotationRemoval' as const });
      this.#rotationReceipts.set(receipt, freezeIndexEntry({
        serverUrl: authority.serverUrl,
        accountIdentity: authority.accountIdentity,
        userId: authority.userId,
        scopeDigest: scope.digest,
        storageKey: scope.storageKey,
      }));
      return receipt;
    }));
  }

  /** Consume a same-worker receipt only after rotation succeeds; failed rotations retain history. */
  commitRotationRemoval(receipt: GeneratorHistoryRotationRemovalReceipt): Promise<boolean> {
    if (!isPlainRecord(receipt)) throw productionError('invalid_request', 'Rotation removal receipt is invalid');
    const expected = this.#rotationReceipts.get(receipt);
    if (!expected || this.#claimedRotationReceipts.has(receipt)) {
      throw productionError('invalid_request', 'Rotation removal receipt is invalid, consumed, or already claimed');
    }
    this.#claimedRotationReceipts.add(receipt);
    let operation: Promise<boolean>;
    try {
      operation = this.#serialize(async () => (await this.#removeAccounts((entry) => (
        entry.serverUrl === expected.serverUrl
        && entry.accountIdentity === expected.accountIdentity
        && entry.userId === expected.userId
        && entry.scopeDigest === expected.scopeDigest
        && entry.storageKey === expected.storageKey
      ))) > 0);
    } catch (error) {
      this.#claimedRotationReceipts.delete(receipt);
      throw error;
    }
    return operation.then((removed) => {
      this.#claimedRotationReceipts.delete(receipt);
      this.#rotationReceipts.delete(receipt);
      return removed;
    }, (error: unknown) => {
      this.#claimedRotationReceipts.delete(receipt);
      throw error;
    });
  }

  async #withAuthority<Result>(
    operation: (authority: NormalizedAuthority, scope: GeneratorHistoryScope) => Promise<Result>,
    preflight?: (authority: NormalizedAuthority) => void,
  ): Promise<Result> {
    return this.#withCurrentAuthority(async (rawAuthority) => {
      const authority = normalizeAuthority(rawAuthority);
      authority.assertCurrent();
      preflight?.(authority);
      authority.assertCurrent();
      const scope = await this.#ensureScope(authority);
      authority.assertCurrent();
      if (this.#coordinator.unavailableScopes.has(scope.storageKey)) {
        throw productionError('history_rollback_failed', 'Generator history scope is unavailable');
      }
      this.#repository.unlock(scope);
      this.#active = Object.freeze({ accountKey: accountKey(authority.serverUrl, authority.accountIdentity), scope });
      authority.assertCurrent();
      const result = await operation(authority, scope);
      authority.assertCurrent();
      return result;
    });
  }

  async #ensureScope(authority: NormalizedAuthority): Promise<GeneratorHistoryScope> {
    const loaded = await this.#readIndex(authority.assertCurrent);
    authority.assertCurrent();
    const key = accountKey(authority.serverUrl, authority.accountIdentity);
    const existing = loaded.entries.find((entry) => accountKey(entry.serverUrl, entry.accountIdentity) === key);
    const scope = await createGeneratorHistoryScope(authority.serverUrl, authority.userId);
    authority.assertCurrent();
    if (existing) {
      if (existing.userId !== authority.userId
        || existing.scopeDigest !== scope.digest
        || existing.storageKey !== scope.storageKey) {
        throw productionError('scope_mismatch', 'Generator history scope does not match the current account');
      }
      return scope;
    }
    const renamed = loaded.entries.find((entry) => (
      entry.serverUrl === authority.serverUrl
      && entry.userId === authority.userId
      && entry.scopeDigest === scope.digest
      && entry.storageKey === scope.storageKey
    ));
    if (renamed) {
      const entries = loaded.entries
        .map((entry) => entry === renamed
          ? freezeIndexEntry({ ...entry, accountIdentity: authority.accountIdentity })
          : entry)
        .sort(compareIndexEntries);
      const next = createStoredIndex(entries, this.#createIndexRevision);
      await this.#commitIndex(loaded.envelope, next, authority.assertCurrent);
      authority.assertCurrent();
      return scope;
    }
    if (loaded.entries.length >= MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES) {
      throw productionError('index_capacity', 'Generator history scope index is full');
    }
    const entry = freezeIndexEntry({
      serverUrl: authority.serverUrl,
      accountIdentity: authority.accountIdentity,
      userId: authority.userId,
      scopeDigest: scope.digest,
      storageKey: scope.storageKey,
    });
    const entries = [...loaded.entries, entry].sort(compareIndexEntries);
    const next = createStoredIndex(entries, this.#createIndexRevision);
    // Index-first prevents a worker crash from creating encrypted history that lifecycle cleanup
    // can no longer discover. A crash after this commit leaves only a harmless empty mapping.
    await this.#commitIndex(loaded.envelope, next, authority.assertCurrent);
    authority.assertCurrent();
    return scope;
  }

  async #removeAccounts(
    matches: (entry: StoredScopeIndexEntry) => boolean,
    assertCurrent: () => void = NOOP,
  ): Promise<number> {
    const loaded = await this.#readIndex(assertCurrent);
    assertCurrent();
    const removed = loaded.entries.filter(matches);
    if (removed.length === 0) return 0;
    // Secret-first removal prevents index loss from orphaning ciphertext. If the later index commit
    // fails, the retained mapping is a conservative, naturally retryable reconciliation marker.
    for (const entry of removed) {
      const scope = Object.freeze({ digest: entry.scopeDigest, storageKey: entry.storageKey });
      await this.#repository.remove(scope);
      this.#coordinator.unavailableScopes.delete(scope.storageKey);
      assertCurrent();
      if (this.#active?.accountKey === accountKey(entry.serverUrl, entry.accountIdentity)) {
        this.#active = undefined;
      }
    }
    const retained = loaded.entries.filter((entry) => !matches(entry));
    const next = createStoredIndex(retained, this.#createIndexRevision);
    await this.#commitIndex(loaded.envelope, next, assertCurrent);
    assertCurrent();
    return removed.length;
  }

  async #withHistoryRollback<Result>(
    scope: GeneratorHistoryScope,
    assertCurrent: () => void,
    operation: () => Promise<Result>,
  ): Promise<Result> {
    assertCurrent();
    const previous = await this.#store.get<unknown>(scope.storageKey);
    assertCurrent();
    try {
      const result = await operation();
      assertCurrent();
      return result;
    } catch (error) {
      this.#repository.lock(scope);
      try {
        const current = await this.#store.get<unknown>(scope.storageKey);
        if (!sameRawValue(current, previous)) {
          if (previous === undefined) await this.#store.remove(scope.storageKey);
          else await this.#store.set(scope.storageKey, previous);
        }
        const restored = await this.#store.get<unknown>(scope.storageKey);
        if (!sameRawValue(restored, previous)) {
          throw new Error('History rollback could not be verified', { cause: error });
        }
      } catch (rollbackError) {
        this.#coordinator.unavailableScopes.add(scope.storageKey);
        throw new GeneratorHistoryProductionError(
          'history_rollback_failed',
          'Generator history result could not be rolled back',
          rollbackError,
        );
      }
      throw error;
    }
  }

  async #readIndex(assertCurrent: () => void): Promise<LoadedScopeIndex> {
    this.#assertIndexAvailable();
    assertCurrent();
    const raw = await this.#store.get<unknown>(GENERATOR_HISTORY_SCOPE_INDEX_KEY);
    assertCurrent();
    if (raw === undefined) return Object.freeze({ envelope: undefined, entries: Object.freeze([]) });
    const envelope = parseStoredIndex(raw);
    const entries: StoredScopeIndexEntry[] = [];
    const accountKeys = new Set<string>();
    const userKeys = new Set<string>();
    const scopeDigests = new Set<string>();
    for (const entry of envelope.entries) {
      const scope = await createGeneratorHistoryScope(entry.serverUrl, entry.userId);
      assertCurrent();
      if (scope.digest !== entry.scopeDigest || scope.storageKey !== entry.storageKey) {
        throw productionError('corrupt_index', 'Generator history scope index contains a mismatched scope');
      }
      const key = accountKey(entry.serverUrl, entry.accountIdentity);
      if (accountKeys.has(key)) {
        throw productionError('corrupt_index', 'Generator history scope index contains a duplicate account');
      }
      const userKey = accountKey(entry.serverUrl, entry.userId);
      if (userKeys.has(userKey) || scopeDigests.has(entry.scopeDigest)) {
        throw productionError('corrupt_index', 'Generator history scope index contains an aliased scope');
      }
      accountKeys.add(key);
      userKeys.add(userKey);
      scopeDigests.add(entry.scopeDigest);
      entries.push(entry);
    }
    if (!isSorted(entries, compareIndexEntries)) {
      throw productionError('corrupt_index', 'Generator history scope index is not canonical');
    }
    return Object.freeze({ envelope, entries: Object.freeze(entries) });
  }

  async #commitIndex(
    previous: StoredScopeIndex | undefined,
    next: StoredScopeIndex,
    assertCurrent: () => void,
  ): Promise<void> {
    this.#assertIndexAvailable();
    assertCurrent();
    let writeAttempted = false;
    let error: unknown;
    try {
      writeAttempted = true;
      await this.#store.set(GENERATOR_HISTORY_SCOPE_INDEX_KEY, next);
      assertCurrent();
      const committed = await this.#store.get<unknown>(GENERATOR_HISTORY_SCOPE_INDEX_KEY);
      assertCurrent();
      if (!sameStoredIndex(committed, next)) {
        throw new Error('Generator history scope index commit could not be verified');
      }
      return;
    } catch (caught) {
      error = caught;
    }
    if (!writeAttempted) throw error;
    try {
      const current = await this.#store.get<unknown>(GENERATOR_HISTORY_SCOPE_INDEX_KEY);
      if (sameStoredIndex(current, next)) {
        if (previous) await this.#store.set(GENERATOR_HISTORY_SCOPE_INDEX_KEY, previous);
        else await this.#store.remove(GENERATOR_HISTORY_SCOPE_INDEX_KEY);
      } else if (!sameOptionalStoredIndex(current, previous)) {
        throw new Error('Generator history scope index changed outside its shared FIFO');
      }
      const restored = await this.#store.get<unknown>(GENERATOR_HISTORY_SCOPE_INDEX_KEY);
      if (!sameOptionalStoredIndex(restored, previous)) {
        throw new Error('Generator history scope index rollback could not be verified');
      }
    } catch {
      this.#coordinator.unavailable = true;
      throw productionError('index_rollback_failed', 'Generator history scope index became unavailable');
    }
    throw error;
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    this.#assertIndexAvailable();
    const result = this.#coordinator.tail.then(operation, operation);
    this.#coordinator.tail = result.then(() => undefined, () => undefined);
    return result;
  }

  #assertIndexAvailable(): void {
    if (this.#coordinator.unavailable) {
      throw productionError('index_unavailable', 'Generator history scope index is unavailable');
    }
  }
}

const NOOP = (): void => {};

function normalizeAuthority(authority: GeneratorHistoryAuthority): NormalizedAuthority {
  if (!isPlainRecord(authority)
    || !isFunction(authority.crypto?.encrypt)
    || !isFunction(authority.crypto?.decrypt)
    || !isFunction(authority.assertCurrent)
    || !Number.isSafeInteger(authority.policyRevision)
    || authority.policyRevision < 0) {
    throw productionError('invalid_authority', 'Generator history authority is invalid');
  }
  return Object.freeze({
    serverUrl: canonicalServerUrl(authority.serverUrl),
    accountIdentity: normalizedAccountIdentity(authority.accountIdentity),
    userId: canonicalUserId(authority.userId),
    policyRevision: authority.policyRevision,
    crypto: authority.crypto,
    assertCurrent: authority.assertCurrent,
  });
}

function parseIdentityProjection(value: unknown): GeneratorHistoryIdentityProjection {
  if (!isPlainRecord(value)
    || !hasExactDataKeys(value, ['serverUrl', 'accountIdentity', 'userId'])) {
    throw productionError('invalid_authority', 'Generator history identity is invalid');
  }
  const serverUrl = canonicalServerUrl(value.serverUrl);
  const accountIdentity = normalizedAccountIdentity(value.accountIdentity);
  const userId = canonicalUserId(value.userId);
  if (value.serverUrl !== serverUrl || value.accountIdentity !== accountIdentity || value.userId !== userId) {
    throw productionError('invalid_authority', 'Generator history identity is not canonical');
  }
  return Object.freeze({ serverUrl, accountIdentity, userId });
}

function parseRegisteredAccounts(value: unknown): ReadonlySet<string> {
  if (!Array.isArray(value) || !hasDenseArrayShape(value)
    || value.length > MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES) {
    throw productionError('invalid_request', 'Registered generator history accounts are invalid');
  }
  const accounts = new Set<string>();
  for (const raw of value) {
    if (!isPlainRecord(raw) || !hasExactDataKeys(raw, ['serverUrl', 'accountIdentity'])) {
      throw productionError('invalid_request', 'Registered generator history account is invalid');
    }
    const serverUrl = canonicalServerUrl(raw.serverUrl);
    const accountIdentity = normalizedAccountIdentity(raw.accountIdentity);
    if (raw.serverUrl !== serverUrl || raw.accountIdentity !== accountIdentity) {
      throw productionError('invalid_request', 'Registered generator history account is not canonical');
    }
    const key = accountKey(serverUrl, accountIdentity);
    if (accounts.has(key)) {
      throw productionError('invalid_request', 'Registered generator history account is duplicated');
    }
    accounts.add(key);
  }
  return accounts;
}

function copyUserKey(value: SymmetricKey): SymmetricKey {
  if (!(value?.encKey instanceof Uint8Array) || value.encKey.byteLength !== 32
    || !(value.macKey instanceof Uint8Array) || value.macKey.byteLength !== 32) {
    throw productionError('invalid_authority', 'Generator history UserKey is invalid');
  }
  return Object.freeze({ encKey: value.encKey.slice(), macKey: value.macKey.slice() });
}

function zeroSymmetricKey(value: SymmetricKey | undefined): void {
  value?.encKey.fill(0);
  value?.macKey.fill(0);
}

function parseTrackRequest(input: GeneratorHistoryTrackRequest): GeneratorHistoryTrackRequest {
  if (!isPlainRecord(input)
    || !hasExactDataKeys(input, ['value', 'type', 'policyRevision'])
    || !isBoundedTrackValue(input.value)
    || !isGeneratorHistoryEntryType(input.type)
    || !Number.isSafeInteger(input.policyRevision)
    || input.policyRevision < 0) {
    throw productionError('invalid_request', 'Generator history track request is invalid');
  }
  return Object.freeze({ value: input.value, type: input.type, policyRevision: input.policyRevision });
}

function parseStoredIndex(input: unknown): StoredScopeIndex {
  if (!isPlainRecord(input)) throw productionError('corrupt_index', 'Generator history scope index is corrupt');
  const schemaVersion = ownData(input, 'schemaVersion');
  if (Number.isSafeInteger(schemaVersion) && (schemaVersion as number) > GENERATOR_HISTORY_SCOPE_INDEX_SCHEMA_VERSION) {
    throw productionError('unsupported_index_schema', 'Generator history scope index uses a future schema');
  }
  if (schemaVersion !== GENERATOR_HISTORY_SCOPE_INDEX_SCHEMA_VERSION
    || !hasExactDataKeys(input, ['schemaVersion', 'revision', 'entries'])) {
    throw productionError('corrupt_index', 'Generator history scope index is corrupt');
  }
  const revision = ownData(input, 'revision');
  const rawEntries = ownData(input, 'entries');
  if (typeof revision !== 'string' || !INDEX_REVISION_PATTERN.test(revision)
    || !Array.isArray(rawEntries) || !hasDenseArrayShape(rawEntries)
    || rawEntries.length > MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES) {
    throw productionError('corrupt_index', 'Generator history scope index is corrupt');
  }
  const entries = rawEntries.map(parseStoredIndexEntry);
  return Object.freeze({ schemaVersion, revision, entries: Object.freeze(entries) });
}

function parseStoredIndexEntry(input: unknown): StoredScopeIndexEntry {
  if (!isPlainRecord(input)
    || !hasExactDataKeys(input, ['serverUrl', 'accountIdentity', 'userId', 'scopeDigest', 'storageKey'])) {
    throw productionError('corrupt_index', 'Generator history scope index entry is corrupt');
  }
  const serverUrl = ownData(input, 'serverUrl');
  const accountIdentity = ownData(input, 'accountIdentity');
  const userId = ownData(input, 'userId');
  const scopeDigest = ownData(input, 'scopeDigest');
  const storageKey = ownData(input, 'storageKey');
  let canonicalServer: string;
  let canonicalAccount: string;
  let canonicalUser: string;
  try {
    canonicalServer = canonicalServerUrl(serverUrl);
    canonicalAccount = normalizedAccountIdentity(accountIdentity);
    canonicalUser = canonicalUserId(userId);
  } catch {
    throw productionError('corrupt_index', 'Generator history scope index entry is corrupt');
  }
  if (serverUrl !== canonicalServer || accountIdentity !== canonicalAccount || userId !== canonicalUser
    || typeof scopeDigest !== 'string' || !SCOPE_DIGEST_PATTERN.test(scopeDigest)
    || storageKey !== `generatorHistory.v1.${scopeDigest}`) {
    throw productionError('corrupt_index', 'Generator history scope index entry is not canonical');
  }
  return freezeIndexEntry({ serverUrl, accountIdentity, userId, scopeDigest, storageKey });
}

function createStoredIndex(
  entries: readonly StoredScopeIndexEntry[],
  createRevision: () => string,
): StoredScopeIndex {
  const revision = createRevision();
  if (typeof revision !== 'string' || !INDEX_REVISION_PATTERN.test(revision)) {
    throw productionError('invalid_authority', 'Generator history scope index revision is invalid');
  }
  return Object.freeze({
    schemaVersion: GENERATOR_HISTORY_SCOPE_INDEX_SCHEMA_VERSION,
    revision,
    entries: Object.freeze(entries.map((entry) => freezeIndexEntry(entry))),
  });
}

function freezeIndexEntry(entry: StoredScopeIndexEntry): StoredScopeIndexEntry {
  return Object.freeze({ ...entry });
}

function sameOptionalStoredIndex(input: unknown, expected: StoredScopeIndex | undefined): boolean {
  return expected === undefined ? input === undefined : sameStoredIndex(input, expected);
}

function sameStoredIndex(input: unknown, expected: StoredScopeIndex): boolean {
  try {
    const parsed = parseStoredIndex(input);
    return JSON.stringify(parsed) === JSON.stringify(expected);
  } catch {
    return false;
  }
}

function canonicalServerUrl(value: unknown): string {
  if (typeof value !== 'string') throw productionError('invalid_authority', 'Generator history server is invalid');
  try {
    return canonicalizeServerCapabilityUrl(value);
  } catch {
    throw productionError('invalid_authority', 'Generator history server is invalid');
  }
}

function normalizedAccountIdentity(value: unknown): string {
  if (typeof value !== 'string') throw productionError('invalid_authority', 'Generator history account is invalid');
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > 320 || containsControlCharacter(normalized)
    || !/^[^@\s]+@[^@\s]+$/u.test(normalized)) {
    throw productionError('invalid_authority', 'Generator history account is invalid');
  }
  return normalized;
}

function canonicalUserId(value: unknown): string {
  if (typeof value !== 'string') throw productionError('invalid_authority', 'Generator history user id is invalid');
  const normalized = value.trim().toLowerCase();
  if (!UUID_PATTERN.test(normalized)) {
    throw productionError('invalid_authority', 'Generator history user id is invalid');
  }
  return normalized;
}

function accountKey(serverUrl: string, accountIdentity: string): string {
  return `${serverUrl}\n${accountIdentity}`;
}

function compareIndexEntries(first: StoredScopeIndexEntry, second: StoredScopeIndexEntry): number {
  const firstKey = accountKey(first.serverUrl, first.accountIdentity);
  const secondKey = accountKey(second.serverUrl, second.accountIdentity);
  return firstKey < secondKey ? -1 : firstKey > secondKey ? 1 : 0;
}

function isSorted<T>(values: readonly T[], compare: (first: T, second: T) => number): boolean {
  return values.every((value, index) => index === 0 || compare(values[index - 1]!, value) < 0);
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function isBoundedTrackValue(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || containsControlCharacter(value)) return false;
  const bytes = ENCODER.encode(value);
  try {
    return bytes.byteLength <= MAX_TRACK_VALUE_UTF8_BYTES && STRICT_UTF8_DECODER.decode(bytes) === value;
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

function hasDenseArrayShape(input: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(input);
  if (keys.length !== input.length + 1 || keys.at(-1) !== 'length') return false;
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (!length || !('value' in length) || length.value !== input.length || length.enumerable) return false;
  return Array.from({ length: input.length }, (_, index) => String(index)).every((key, index) => {
    if (keys[index] !== key) return false;
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function sameRawValue(first: unknown, second: unknown): boolean {
  if (first === undefined || second === undefined) return first === second;
  try {
    return JSON.stringify(first) === JSON.stringify(second);
  } catch {
    return false;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactDataKeys(record: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedSet = new Set(expected);
  if (keys.some((key) => !expectedSet.has(key as string))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function ownData(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function isFunction(value: unknown): value is (...args: never[]) => unknown {
  return typeof value === 'function';
}

function productionError(
  code: GeneratorHistoryProductionErrorCode,
  message: string,
  cause?: unknown,
): GeneratorHistoryProductionError {
  return new GeneratorHistoryProductionError(code, message, cause);
}
