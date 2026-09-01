import type { AccountLease } from '../core/session/account-gate.js';
import type { KeyValueStore } from '../platform/store.js';

export const ACCOUNT_SETTINGS_STORAGE_KEY = 'accountSettings.v1';
export const ACCOUNT_SETTINGS_SCHEMA_VERSION = 1 as const;
export const MAX_ACCOUNT_SETTINGS_ACCOUNTS = 5;

const MAX_SERVER_URL_LENGTH = 4_096;
const MAX_EMAIL_LENGTH = 254;

export type AccountSettingsParser<Value> = (value: unknown) => Value;

export interface AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth> {
  readonly autofill: Autofill;
  readonly websitePasskey: WebsitePasskey;
  readonly httpAuth: HttpAuth;
}

export interface AccountSettingsParsers<Autofill, WebsitePasskey, HttpAuth> {
  readonly autofill: AccountSettingsParser<Autofill>;
  readonly websitePasskey: AccountSettingsParser<WebsitePasskey>;
  readonly httpAuth: AccountSettingsParser<HttpAuth>;
}

export interface AccountSettingsRepositoryOptions<Autofill, WebsitePasskey, HttpAuth> {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly parsers: AccountSettingsParsers<Autofill, WebsitePasskey, HttpAuth>;
  /** Must return the project's canonical representation and be idempotent. */
  readonly canonicalizeServerUrl: (serverUrl: string) => string;
  /** Verifies that this exact, background-issued lease is still current. */
  readonly assertLease: (lease: AccountLease) => void;
}

export type AccountSettingsRepositoryErrorCode =
  | 'capacity'
  | 'corrupt_envelope'
  | 'unsupported_schema'
  | 'scope_unavailable'
  | 'invalid_records'
  | 'rollback_failed';

export class AccountSettingsRepositoryError extends Error {
  readonly scopeKey: string | undefined;

  constructor(
    readonly code: AccountSettingsRepositoryErrorCode,
    message: string,
    options: { readonly scopeKey?: string; readonly cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AccountSettingsRepositoryError';
    this.scopeKey = options.scopeKey;
  }
}

interface AccountSettingsScope {
  readonly key: string;
  readonly serverUrl: string;
  readonly email: string;
}

interface StoredAccountSettingsEntry {
  readonly serverUrl: string;
  readonly email: string;
  readonly autofill: unknown;
  readonly websitePasskey: unknown;
  readonly httpAuth: unknown;
}

interface AccountSettingsEnvelope {
  readonly schemaVersion: typeof ACCOUNT_SETTINGS_SCHEMA_VERSION;
  /** Values stay unknown until selected, so one bad account entry cannot poison its peers. */
  readonly accounts: Readonly<Record<string, unknown>>;
}

interface ParsedEnvelope {
  readonly raw: unknown;
  readonly accounts: Readonly<Record<string, unknown>>;
}

/**
 * Stores one complete local-policy record per canonical server/account pair. Every read and mutation
 * shares one FIFO so a rollback is never observable to another repository operation.
 */
export class AccountSettingsRepository<Autofill, WebsitePasskey, HttpAuth> {
  readonly #store: AccountSettingsRepositoryOptions<Autofill, WebsitePasskey, HttpAuth>['store'];
  readonly #parsers: AccountSettingsParsers<Autofill, WebsitePasskey, HttpAuth>;
  readonly #canonicalizeServerUrl: (serverUrl: string) => string;
  readonly #assertLease: (lease: AccountLease) => void;
  readonly #unavailableScopes = new Set<string>();
  #operationTail: Promise<void> = Promise.resolve();

  constructor(options: AccountSettingsRepositoryOptions<Autofill, WebsitePasskey, HttpAuth>) {
    if (!options || !isFunction(options.store?.get)
      || !isFunction(options.store?.set) || !isFunction(options.store?.remove)) {
      throw new TypeError('A key-value store with get, set, and remove is required');
    }
    if (!options.parsers || !isFunction(options.parsers.autofill)
      || !isFunction(options.parsers.websitePasskey) || !isFunction(options.parsers.httpAuth)) {
      throw new TypeError('All account settings parsers are required');
    }
    if (!isFunction(options.canonicalizeServerUrl) || !isFunction(options.assertLease)) {
      throw new TypeError('Server canonicalization and account lease assertion are required');
    }
    this.#store = options.store;
    this.#parsers = options.parsers;
    this.#canonicalizeServerUrl = options.canonicalizeServerUrl;
    this.#assertLease = options.assertLease;
  }

  read(lease: AccountLease): Promise<Readonly<AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>> | undefined> {
    this.#assertLease(lease);
    const scope = this.#scopeFromLease(lease);
    return this.#serialize(async () => {
      this.#assertScopeAvailable(scope);
      const envelope = await this.#readEnvelope(lease);
      if (!Object.hasOwn(envelope.accounts, scope.key)) return undefined;
      const parsed = this.#parseStoredEntry(envelope.accounts[scope.key], scope);
      this.#assertLease(lease);
      return parsed;
    });
  }

  update(
    lease: AccountLease,
    updater: (
      current: Readonly<AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>> | undefined,
    ) => AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>,
  ): Promise<Readonly<AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>>> {
    this.#assertLease(lease);
    if (!isFunction(updater)) throw new TypeError('An account settings updater is required');
    const scope = this.#scopeFromLease(lease);
    return this.#serialize(async () => {
      this.#assertScopeAvailable(scope);
      const envelope = await this.#readEnvelope(lease);
      const exists = Object.hasOwn(envelope.accounts, scope.key);
      const current = exists
        ? this.#parseStoredEntry(envelope.accounts[scope.key], scope)
        : undefined;
      if (!exists && Object.keys(envelope.accounts).length >= MAX_ACCOUNT_SETTINGS_ACCOUNTS) {
        throw new AccountSettingsRepositoryError(
          'capacity',
          `Account settings capacity (${MAX_ACCOUNT_SETTINGS_ACCOUNTS}) was reached`,
          { scopeKey: scope.key },
        );
      }

      const next = this.#parseInputRecords(updater(current), scope);
      const stored: StoredAccountSettingsEntry = {
        serverUrl: scope.serverUrl,
        email: scope.email,
        autofill: next.autofill,
        websitePasskey: next.websitePasskey,
        httpAuth: next.httpAuth,
      };
      const accounts = copyDataRecord(envelope.accounts);
      accounts[scope.key] = stored;
      const nextEnvelope: AccountSettingsEnvelope = {
        schemaVersion: ACCOUNT_SETTINGS_SCHEMA_VERSION,
        accounts,
      };

      this.#assertLease(lease);
      try {
        const write = this.#store.set(ACCOUNT_SETTINGS_STORAGE_KEY, nextEnvelope);
        this.#assertLease(lease);
        await write;
        this.#assertLease(lease);
      } catch (error) {
        try {
          // Compensation must run even when the lease is stale; the shared FIFO excludes peers.
          if (envelope.raw === undefined) {
            await this.#store.remove(ACCOUNT_SETTINGS_STORAGE_KEY);
          } else {
            await this.#store.set(ACCOUNT_SETTINGS_STORAGE_KEY, envelope.raw);
          }
        } catch (rollbackError) {
          this.#unavailableScopes.add(scope.key);
          throw new AccountSettingsRepositoryError(
            'rollback_failed',
            'Account settings became unavailable because a failed write could not be rolled back',
            {
              scopeKey: scope.key,
              cause: new AggregateError([error, rollbackError], 'Account settings write and rollback failed'),
            },
          );
        }
        throw error;
      }
      return next;
    });
  }

  async #readEnvelope(lease: AccountLease): Promise<ParsedEnvelope> {
    this.#assertLease(lease);
    const raw = await this.#store.get<unknown>(ACCOUNT_SETTINGS_STORAGE_KEY);
    this.#assertLease(lease);
    return this.#parseEnvelope(raw);
  }

  #parseEnvelope(raw: unknown): ParsedEnvelope {
    if (raw === undefined) return { raw, accounts: {} };
    try {
      if (!isPlainRecord(raw) || !hasExactDataKeys(raw, ['schemaVersion', 'accounts'])) {
        throw corruptEnvelope();
      }
      const schemaVersion = dataValue(raw, 'schemaVersion');
      if (Number.isSafeInteger(schemaVersion) && (schemaVersion as number) > ACCOUNT_SETTINGS_SCHEMA_VERSION) {
        throw new AccountSettingsRepositoryError(
          'unsupported_schema',
          'Account settings use an unsupported schema version',
        );
      }
      const rawAccounts = dataValue(raw, 'accounts');
      if (schemaVersion !== ACCOUNT_SETTINGS_SCHEMA_VERSION || !isPlainRecord(rawAccounts)) {
        throw corruptEnvelope();
      }
      const keys = Reflect.ownKeys(rawAccounts);
      if (keys.length > MAX_ACCOUNT_SETTINGS_ACCOUNTS
        || keys.some((key) => typeof key !== 'string')) throw corruptEnvelope();
      for (const key of keys as string[]) {
        const descriptor = Object.getOwnPropertyDescriptor(rawAccounts, key);
        if (!descriptor?.enumerable || !('value' in descriptor) || !this.#isCanonicalScopeKey(key)) {
          throw corruptEnvelope();
        }
      }
      return { raw, accounts: copyDataRecord(rawAccounts) };
    } catch (error) {
      if (error instanceof AccountSettingsRepositoryError) throw error;
      throw new AccountSettingsRepositoryError(
        'corrupt_envelope',
        'Account settings storage is corrupt',
        { cause: error },
      );
    }
  }

  #parseStoredEntry(
    value: unknown,
    scope: AccountSettingsScope,
  ): Readonly<AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>> {
    try {
      if (!isPlainRecord(value)
        || !hasExactDataKeys(value, ['serverUrl', 'email', 'autofill', 'websitePasskey', 'httpAuth'])
        || dataValue(value, 'serverUrl') !== scope.serverUrl
        || dataValue(value, 'email') !== scope.email) {
        throw new Error('Stored account settings entry does not match its scope');
      }
      return this.#parseRecords({
        autofill: dataValue(value, 'autofill'),
        websitePasskey: dataValue(value, 'websitePasskey'),
        httpAuth: dataValue(value, 'httpAuth'),
      });
    } catch (error) {
      throw new AccountSettingsRepositoryError(
        'scope_unavailable',
        'Account settings for this scope are corrupt or invalid',
        { scopeKey: scope.key, cause: error },
      );
    }
  }

  #parseInputRecords(
    value: unknown,
    scope: AccountSettingsScope,
  ): Readonly<AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>> {
    try {
      if (!isPlainRecord(value)
        || !hasExactDataKeys(value, ['autofill', 'websitePasskey', 'httpAuth'])) {
        throw new Error('Account settings updates require exactly three records');
      }
      return this.#parseRecords({
        autofill: dataValue(value, 'autofill'),
        websitePasskey: dataValue(value, 'websitePasskey'),
        httpAuth: dataValue(value, 'httpAuth'),
      });
    } catch (error) {
      throw new AccountSettingsRepositoryError(
        'invalid_records',
        'Account settings update records are invalid',
        { scopeKey: scope.key, cause: error },
      );
    }
  }

  #parseRecords(value: {
    readonly autofill: unknown;
    readonly websitePasskey: unknown;
    readonly httpAuth: unknown;
  }): Readonly<AccountSettingsRecords<Autofill, WebsitePasskey, HttpAuth>> {
    return Object.freeze({
      autofill: this.#parsers.autofill(value.autofill),
      websitePasskey: this.#parsers.websitePasskey(value.websitePasskey),
      httpAuth: this.#parsers.httpAuth(value.httpAuth),
    });
  }

  #assertScopeAvailable(scope: AccountSettingsScope): void {
    if (this.#unavailableScopes.has(scope.key)) {
      throw new AccountSettingsRepositoryError(
        'scope_unavailable',
        'Account settings for this scope are unavailable',
        { scopeKey: scope.key },
      );
    }
  }

  #scopeFromLease(lease: AccountLease): AccountSettingsScope {
    return this.#scope(lease.serverUrl, lease.accountIdentity);
  }

  #scope(serverUrlInput: unknown, emailInput: unknown): AccountSettingsScope {
    if (typeof serverUrlInput !== 'string' || typeof emailInput !== 'string') {
      throw new TypeError('Account settings scope requires a server URL and email');
    }
    const serverUrl = this.#canonicalizeServerUrl(serverUrlInput);
    if (!isBoundedCanonicalString(serverUrl, MAX_SERVER_URL_LENGTH)
      || this.#canonicalizeServerUrl(serverUrl) !== serverUrl) {
      throw new TypeError('Account settings server URL is not canonical');
    }
    const parsed = new URL(serverUrl);
    if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
      || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new TypeError('Account settings server URL is invalid');
    }
    const email = emailInput.trim().toLowerCase();
    if (!isBoundedCanonicalString(email, MAX_EMAIL_LENGTH)
      || !/^[^@\s]+@[^@\s]+$/u.test(email)) {
      throw new TypeError('Account settings email is invalid');
    }
    return Object.freeze({
      key: JSON.stringify([serverUrl, email]),
      serverUrl,
      email,
    });
  }

  #isCanonicalScopeKey(value: string): boolean {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (!Array.isArray(parsed) || !hasDenseArrayShape(parsed) || parsed.length !== 2) return false;
      const scope = this.#scope(parsed[0], parsed[1]);
      return scope.key === value;
    } catch {
      return false;
    }
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#operationTail.then(operation, operation);
    this.#operationTail = result.then(() => undefined, () => undefined);
    return result;
  }
}

function corruptEnvelope(): AccountSettingsRepositoryError {
  return new AccountSettingsRepositoryError(
    'corrupt_envelope',
    'Account settings storage is corrupt',
  );
}

function isFunction(value: unknown): value is (...args: never[]) => unknown {
  return typeof value === 'function';
}

function isBoundedCanonicalString(value: unknown, maximum: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maximum
    && value.trim() === value
    && !containsControlCharacter(value);
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedSet = new Set(expected);
  if (keys.some((key) => !expectedSet.has(key as string))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !('value' in descriptor)) throw new TypeError(`Missing data property: ${key}`);
  return descriptor.value;
}

function copyDataRecord(record: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !('value' in descriptor)) throw corruptEnvelope();
    copy[key] = descriptor.value;
  }
  return copy;
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
