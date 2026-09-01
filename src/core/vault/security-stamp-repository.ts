import type { KeyValueStore } from '../../platform/store.js';
import {
  MAX_SECURITY_STAMP_LENGTH,
  MAX_SYNC_PROFILE_ID_LENGTH,
} from '../api/sync-profile.js';
import { canonicalizeServerCapabilityUrl } from '../api/server-capabilities.js';

export const SECURITY_STAMP_STORAGE_KEY = 'securityStampBaselines.v1';
export const SECURITY_STAMP_SCHEMA_VERSION = 1 as const;
export const MAX_SECURITY_STAMP_BASELINES = 32;

const MAX_CREDENTIAL_ID_LENGTH = 1_024;
const MAX_REVISION_LENGTH = 128;
const EXCLUSIVE_LOCK_NAME = 'vaultwarden.securityStampBaselines.v1';
const STORE_TAILS = new WeakMap<object, Promise<void>>();

export interface SecurityStampScope {
  readonly serverUrl: string;
  readonly profileId: string;
  readonly credentialId: string;
}

export type SecurityStampComparison =
  | { readonly status: 'initialized' }
  | { readonly status: 'matched' }
  | { readonly status: 'compatible_missing' }
  | { readonly status: 'uninitialized' }
  | {
      readonly status: 'mismatch';
      readonly reason: 'profile_changed' | 'stamp_changed' | 'stamp_missing';
    };

export type SecurityStampRepositoryErrorCode =
  | 'capacity'
  | 'corrupt_envelope'
  | 'unsupported_schema'
  | 'invalid_scope'
  | 'write_unconfirmed'
  | 'rollback_failed';

export class SecurityStampRepositoryError extends Error {
  constructor(
    readonly code: SecurityStampRepositoryErrorCode,
    message: string,
    options: { readonly cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'SecurityStampRepositoryError';
  }
}

export interface SecurityStampRepositoryOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly createRevision?: () => string;
}

interface StoredSecurityStampBaseline extends SecurityStampScope {
  readonly securityStamp: string;
}

interface SecurityStampEnvelope {
  readonly schemaVersion: typeof SECURITY_STAMP_SCHEMA_VERSION;
  readonly revision: string;
  readonly baselines: readonly StoredSecurityStampBaseline[];
}

interface ParsedEnvelope {
  readonly raw: unknown;
  readonly envelope: SecurityStampEnvelope | undefined;
}

interface CompareOptions {
  /** Only a fresh authenticated server response may initialize a credential baseline. */
  readonly initialize: boolean;
  /** Complete credential set retained for the currently configured server. */
  readonly retainedCredentialIds: readonly string[];
  readonly assertCurrent: () => void | Promise<void>;
}

/** Durable compare-and-set storage for opaque per-credential security stamp baselines. */
export class SecurityStampRepository {
  readonly #store: SecurityStampRepositoryOptions['store'];
  readonly #createRevision: () => string;

  constructor(options: SecurityStampRepositoryOptions) {
    if (!options || !isFunction(options.store?.get)
      || !isFunction(options.store?.set) || !isFunction(options.store?.remove)) {
      throw new TypeError('A key-value store with get, set, and remove is required');
    }
    if (options.createRevision !== undefined && !isFunction(options.createRevision)) {
      throw new TypeError('createRevision must be a function');
    }
    this.#store = options.store;
    this.#createRevision = options.createRevision ?? (() => globalThis.crypto.randomUUID());
  }

  compareAndSet(
    scopeInput: SecurityStampScope,
    securityStampInput: string | undefined,
    options: CompareOptions,
  ): Promise<SecurityStampComparison> {
    if (!options || typeof options.initialize !== 'boolean' || !isFunction(options.assertCurrent)) {
      throw new TypeError('Security stamp comparison options are invalid');
    }
    const scope = parseScope(scopeInput);
    const retainedCredentialIds = parseRetainedCredentialIds(options.retainedCredentialIds);
    if (!retainedCredentialIds.has(scope.credentialId)) {
      throw new TypeError('The current credential must be retained during comparison');
    }
    const securityStamp = securityStampInput === undefined
      ? undefined
      : requireCanonicalString(
          securityStampInput,
          MAX_SECURITY_STAMP_LENGTH,
          'security stamp',
        );
    return this.#serialize(async () => {
      await assertAuthority(options.assertCurrent);
      const current = await this.#readEnvelope();
      await assertAuthority(options.assertCurrent);
      const baselines = current.envelope?.baselines ?? [];
      const credentialBaseline = baselines.find((entry) => (
        entry.serverUrl === scope.serverUrl && entry.credentialId === scope.credentialId
      ));
      if (credentialBaseline) {
        if (credentialBaseline.profileId !== scope.profileId) {
          return mismatch('profile_changed');
        }
        if (securityStamp === undefined) return mismatch('stamp_missing');
        return credentialBaseline.securityStamp === securityStamp
          ? Object.freeze({ status: 'matched' as const })
          : mismatch('stamp_changed');
      }
      if (securityStamp === undefined) {
        return Object.freeze({ status: 'compatible_missing' as const });
      }
      if (!options.initialize) return Object.freeze({ status: 'uninitialized' as const });
      const retainedProfileBaseline = baselines.find((entry) => (
        entry.serverUrl === scope.serverUrl
        && entry.profileId === scope.profileId
        && retainedCredentialIds.has(entry.credentialId)
      ));
      if (retainedProfileBaseline) return mismatch('profile_changed');

      const retained = baselines.filter((entry) => (
        entry.serverUrl === scope.serverUrl
        && retainedCredentialIds.has(entry.credentialId)
        && entry.profileId !== scope.profileId
      ));
      if (retained.length >= MAX_SECURITY_STAMP_BASELINES) {
        throw new SecurityStampRepositoryError(
          'capacity',
          `Security stamp baseline capacity (${MAX_SECURITY_STAMP_BASELINES}) was reached`,
        );
      }
      const revision = requireCanonicalString(
        this.#createRevision(),
        MAX_REVISION_LENGTH,
        'security stamp storage revision',
      );
      if (revision === current.envelope?.revision) {
        throw new SecurityStampRepositoryError(
          'write_unconfirmed',
          'Security stamp storage revision was not advanced',
        );
      }
      const next: SecurityStampEnvelope = Object.freeze({
        schemaVersion: SECURITY_STAMP_SCHEMA_VERSION,
        revision,
        baselines: Object.freeze([
          ...retained,
          Object.freeze({ ...scope, securityStamp }),
        ]),
      });
      await this.#commit(current, next, options.assertCurrent);
      return Object.freeze({ status: 'initialized' as const });
    });
  }

  /** Clear all baselines only as part of an explicit configured-server reset. */
  clear(): Promise<void> {
    return this.#serialize(async () => {
      await this.#store.remove(SECURITY_STAMP_STORAGE_KEY);
      if (await this.#store.get<unknown>(SECURITY_STAMP_STORAGE_KEY) !== undefined) {
        throw new SecurityStampRepositoryError(
          'write_unconfirmed',
          'Security stamp baseline reset could not be confirmed',
        );
      }
    });
  }

  async #commit(
    previous: ParsedEnvelope,
    next: SecurityStampEnvelope,
    assertCurrent: () => void | Promise<void>,
  ): Promise<void> {
    let writeAttempted = false;
    try {
      await assertAuthority(assertCurrent);
      writeAttempted = true;
      await this.#store.set(SECURITY_STAMP_STORAGE_KEY, next);
      await assertAuthority(assertCurrent);
      const confirmed = await this.#readEnvelope();
      await assertAuthority(assertCurrent);
      if (!confirmed.envelope || !sameEnvelope(confirmed.envelope, next)) {
        throw new SecurityStampRepositoryError(
          'write_unconfirmed',
          'Security stamp baseline write could not be confirmed',
        );
      }
    } catch (error) {
      if (writeAttempted) await this.#rollbackIfOwned(previous, next, error);
      throw error;
    }
  }

  async #rollbackIfOwned(
    previous: ParsedEnvelope,
    attempted: SecurityStampEnvelope,
    primaryError: unknown,
  ): Promise<void> {
    try {
      const raw = await this.#store.get<unknown>(SECURITY_STAMP_STORAGE_KEY);
      const current = this.#parseEnvelope(raw).envelope;
      if (current?.revision !== attempted.revision) return;
      if (previous.raw === undefined) {
        await this.#store.remove(SECURITY_STAMP_STORAGE_KEY);
      } else {
        await this.#store.set(SECURITY_STAMP_STORAGE_KEY, previous.raw);
      }
      const restoredRaw = await this.#store.get<unknown>(SECURITY_STAMP_STORAGE_KEY);
      if (previous.envelope === undefined) {
        if (restoredRaw !== undefined) throw new Error('Security stamp baseline removal was not confirmed');
      } else {
        const restored = this.#parseEnvelope(restoredRaw).envelope;
        if (!restored || !sameEnvelope(restored, previous.envelope)) {
          throw new Error('Security stamp baseline restoration was not confirmed');
        }
      }
    } catch (rollbackError) {
      throw new SecurityStampRepositoryError(
        'rollback_failed',
        'Security stamp baseline rollback failed',
        {
          cause: new AggregateError(
            [primaryError, rollbackError],
            'Security stamp baseline write and rollback failed',
          ),
        },
      );
    }
  }

  async #readEnvelope(): Promise<ParsedEnvelope> {
    const raw = await this.#store.get<unknown>(SECURITY_STAMP_STORAGE_KEY);
    return { raw, envelope: this.#parseEnvelope(raw).envelope };
  }

  #parseEnvelope(raw: unknown): ParsedEnvelope {
    if (raw === undefined) return { raw, envelope: undefined };
    try {
      const record = requirePlainRecord(raw, 'security stamp storage');
      if (!hasExactDataKeys(record, ['schemaVersion', 'revision', 'baselines'])) {
        throw corruptEnvelope();
      }
      const schemaVersion = dataValue(record, 'schemaVersion');
      if (Number.isSafeInteger(schemaVersion)
        && (schemaVersion as number) > SECURITY_STAMP_SCHEMA_VERSION) {
        throw new SecurityStampRepositoryError(
          'unsupported_schema',
          'Security stamp storage uses an unsupported schema version',
        );
      }
      if (schemaVersion !== SECURITY_STAMP_SCHEMA_VERSION) throw corruptEnvelope();
      const revision = requireCanonicalString(
        dataValue(record, 'revision'),
        MAX_REVISION_LENGTH,
        'security stamp storage revision',
      );
      const rawBaselines = dataValue(record, 'baselines');
      if (!Array.isArray(rawBaselines)
        || !hasDenseArrayShape(rawBaselines)
        || rawBaselines.length === 0
        || rawBaselines.length > MAX_SECURITY_STAMP_BASELINES) {
        throw corruptEnvelope();
      }
      const credentialScopes = new Set<string>();
      const profileScopes = new Set<string>();
      const baselines = rawBaselines.map((value) => {
        const baseline = parseBaseline(value);
        const credentialScope = JSON.stringify([baseline.serverUrl, baseline.credentialId]);
        const profileScope = JSON.stringify([baseline.serverUrl, baseline.profileId]);
        if (credentialScopes.has(credentialScope) || profileScopes.has(profileScope)) {
          throw corruptEnvelope();
        }
        credentialScopes.add(credentialScope);
        profileScopes.add(profileScope);
        return baseline;
      });
      return {
        raw,
        envelope: Object.freeze({
          schemaVersion: SECURITY_STAMP_SCHEMA_VERSION,
          revision,
          baselines: Object.freeze(baselines),
        }),
      };
    } catch (error) {
      if (error instanceof SecurityStampRepositoryError
        && (error.code === 'unsupported_schema' || error.code === 'corrupt_envelope')) throw error;
      throw new SecurityStampRepositoryError(
        'corrupt_envelope',
        'Security stamp storage is corrupt',
        { cause: error },
      );
    }
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const runForStore = (): Promise<Result> => {
      const owner = this.#store as object;
      const previous = STORE_TAILS.get(owner) ?? Promise.resolve();
      const result = previous.then(operation, operation);
      const tail = result.then(() => undefined, () => undefined);
      STORE_TAILS.set(owner, tail);
      void tail.finally(() => {
        if (STORE_TAILS.get(owner) === tail) STORE_TAILS.delete(owner);
      });
      return result;
    };
    const locks = (globalThis.navigator as unknown as {
      readonly locks?: {
        request<T>(name: string, callback: () => Promise<T>): Promise<T>;
      };
    } | undefined)?.locks;
    return locks?.request(EXCLUSIVE_LOCK_NAME, runForStore) ?? runForStore();
  }
}

function mismatch(reason: 'profile_changed' | 'stamp_changed' | 'stamp_missing') {
  return Object.freeze({ status: 'mismatch' as const, reason });
}

function parseRetainedCredentialIds(value: unknown): ReadonlySet<string> {
  if (!Array.isArray(value)
    || !hasDenseArrayShape(value)
    || value.length === 0
    || value.length > MAX_SECURITY_STAMP_BASELINES) {
    throw new TypeError('Retained security stamp credentials are invalid');
  }
  const result = new Set<string>();
  for (const entry of value) {
    const credentialId = requireCanonicalString(
      entry,
      MAX_CREDENTIAL_ID_LENGTH,
      'security stamp credential id',
    );
    if (result.has(credentialId)) {
      throw new TypeError('Retained security stamp credentials contain a duplicate');
    }
    result.add(credentialId);
  }
  return result;
}

async function assertAuthority(assertCurrent: () => void | Promise<void>): Promise<void> {
  await assertCurrent();
}

function parseBaseline(value: unknown): StoredSecurityStampBaseline {
  const record = requirePlainRecord(value, 'security stamp baseline');
  if (!hasExactDataKeys(record, ['serverUrl', 'profileId', 'credentialId', 'securityStamp'])) {
    throw corruptEnvelope();
  }
  const scope = parseScope({
    serverUrl: dataValue(record, 'serverUrl'),
    profileId: dataValue(record, 'profileId'),
    credentialId: dataValue(record, 'credentialId'),
  });
  const securityStamp = requireCanonicalString(
    dataValue(record, 'securityStamp'),
    MAX_SECURITY_STAMP_LENGTH,
    'security stamp',
  );
  return Object.freeze({ ...scope, securityStamp });
}

function parseScope(value: unknown): SecurityStampScope {
  try {
    const record = requirePlainRecord(value, 'security stamp scope');
    if (!hasExactDataKeys(record, ['serverUrl', 'profileId', 'credentialId'])) {
      throw new TypeError('Security stamp scope fields are invalid');
    }
    const serverUrl = requireCanonicalString(
      dataValue(record, 'serverUrl'),
      2_048,
      'security stamp server URL',
    );
    if (canonicalizeServerCapabilityUrl(serverUrl) !== serverUrl) {
      throw new TypeError('Security stamp server URL is invalid');
    }
    const profileId = requireCanonicalString(
      dataValue(record, 'profileId'),
      MAX_SYNC_PROFILE_ID_LENGTH,
      'security stamp profile id',
    );
    const credentialId = requireCanonicalString(
      dataValue(record, 'credentialId'),
      MAX_CREDENTIAL_ID_LENGTH,
      'security stamp credential id',
    );
    return Object.freeze({ serverUrl, profileId, credentialId });
  } catch (error) {
    if (error instanceof SecurityStampRepositoryError) throw error;
    throw new SecurityStampRepositoryError(
      'invalid_scope',
      'Security stamp scope is invalid',
      { cause: error },
    );
  }
}

function sameEnvelope(left: SecurityStampEnvelope, right: SecurityStampEnvelope): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.revision === right.revision
    && left.baselines.length === right.baselines.length
    && left.baselines.every((entry, index) => {
      const candidate = right.baselines[index];
      return candidate !== undefined
        && entry.serverUrl === candidate.serverUrl
        && entry.profileId === candidate.profileId
        && entry.credentialId === candidate.credentialId
        && entry.securityStamp === candidate.securityStamp;
    });
}

function requireCanonicalString(value: unknown, maximum: number, name: string): string {
  if (typeof value !== 'string'
    || value.length === 0
    || value.length > maximum
    || value.trim() !== value
    || containsControlCharacter(value)) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function corruptEnvelope(): SecurityStampRepositoryError {
  return new SecurityStampRepositoryError(
    'corrupt_envelope',
    'Security stamp storage is corrupt',
  );
}

function isFunction(value: unknown): value is (...args: never[]) => unknown {
  return typeof value === 'function';
}

function requirePlainRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${name} must be a plain object`);
  }
  return value as Record<string, unknown>;
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
  if (!descriptor || !('value' in descriptor)) throw corruptEnvelope();
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
