import type { KeyValueStore } from '../../platform/store.js';
import type { VaultMutationDirtyAdapter } from './vault-mutation-coordinator.js';

export const VAULT_DIRTY_STORE_KEY = 'vaultMutationDirty';
export const DEFAULT_MAX_DIRTY_IDENTITIES = 32;
export const MAX_VAULT_DIRTY_IDENTITY_LENGTH = 4_096;

const DIRTY_STORE_SCHEMA_VERSION = 1 as const;

export interface VaultDirtyEntry {
  readonly dirty: boolean;
  readonly updatedAt: number;
}

export interface VaultDirtyState {
  readonly schemaVersion: typeof DIRTY_STORE_SCHEMA_VERSION;
  readonly identities: Readonly<Record<string, VaultDirtyEntry>>;
}

export type VaultDirtyStoreErrorCode =
  | 'capacity'
  | 'corrupt_state'
  | 'unsupported_schema';

export class VaultDirtyStoreError extends Error {
  constructor(
    readonly code: VaultDirtyStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultDirtyStoreError';
  }
}

export interface VaultDirtyStoreOptions {
  readonly storageKey?: string;
  readonly maxIdentities?: number;
  readonly now?: () => number;
}

type ParsedState =
  | { readonly kind: 'empty'; readonly identities: Map<string, VaultDirtyEntry> }
  | { readonly kind: 'valid'; readonly identities: Map<string, VaultDirtyEntry> }
  | { readonly kind: 'corrupt' }
  | { readonly kind: 'unsupported' };

/**
 * Persists mutation write-ahead markers in local extension storage. Operations are linearized per
 * instance so concurrent account lanes cannot lose each other's read-modify-write updates.
 */
export class VaultDirtyStore implements VaultMutationDirtyAdapter<string> {
  private readonly storageKey: string;
  private readonly maxIdentities: number;
  private readonly now: () => number;
  private operationTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: KeyValueStore,
    options: VaultDirtyStoreOptions = {},
  ) {
    this.storageKey = options.storageKey ?? VAULT_DIRTY_STORE_KEY;
    this.maxIdentities = boundedPositiveInteger(
      options.maxIdentities ?? DEFAULT_MAX_DIRTY_IDENTITIES,
      'maxIdentities',
      DEFAULT_MAX_DIRTY_IDENTITIES,
    );
    this.now = options.now ?? (() => Date.now());
    if (this.storageKey.trim().length === 0) {
      throw new TypeError('storageKey must not be empty');
    }
  }

  async readDirty(identity: string): Promise<boolean> {
    assertCanonicalIdentity(identity);
    return this.serialize(async () => {
      const parsed = this.parse(await this.store.get<unknown>(this.storageKey));
      if (parsed.kind === 'empty') return false;
      if (parsed.kind !== 'valid') return true;
      return parsed.identities.get(identity)?.dirty ?? false;
    });
  }

  async markDirty(identity: string): Promise<void> {
    assertCanonicalIdentity(identity);
    await this.serialize(async () => {
      const identities = await this.readWritableIdentities();
      if (!identities.has(identity) && identities.size >= this.maxIdentities) {
        const cleanIdentity = oldestCleanIdentity(identities);
        if (cleanIdentity === undefined) {
          throw new VaultDirtyStoreError(
            'capacity',
            `Vault dirty marker capacity (${this.maxIdentities}) was reached`,
          );
        }
        identities.delete(cleanIdentity);
      }
      identities.set(identity, { dirty: true, updatedAt: this.currentTimestamp() });
      await this.store.set(this.storageKey, createStoredState(identities));
    });
  }

  async clearDirty(identity: string): Promise<void> {
    assertCanonicalIdentity(identity);
    await this.serialize(async () => {
      const identities = await this.readWritableIdentities();
      const current = identities.get(identity);
      if (!current || !current.dirty) return;
      identities.set(identity, { dirty: false, updatedAt: this.currentTimestamp() });
      await this.store.set(this.storageKey, createStoredState(identities));
    });
  }

  private async readWritableIdentities(): Promise<Map<string, VaultDirtyEntry>> {
    const parsed = this.parse(await this.store.get<unknown>(this.storageKey));
    if (parsed.kind === 'empty' || parsed.kind === 'valid') return parsed.identities;
    if (parsed.kind === 'unsupported') {
      throw new VaultDirtyStoreError(
        'unsupported_schema',
        'Vault dirty marker uses an unsupported schema version',
      );
    }
    throw new VaultDirtyStoreError('corrupt_state', 'Vault dirty marker storage is corrupt');
  }

  private parse(value: unknown): ParsedState {
    if (value === undefined) return { kind: 'empty', identities: new Map() };
    if (!isRecord(value)) return { kind: 'corrupt' };
    if (isFutureSchemaVersion(value.schemaVersion)) return { kind: 'unsupported' };
    if (value.schemaVersion !== DIRTY_STORE_SCHEMA_VERSION || !isRecord(value.identities)) {
      return { kind: 'corrupt' };
    }

    const entries = Object.entries(value.identities);
    if (entries.length > this.maxIdentities) return { kind: 'corrupt' };
    const identities = new Map<string, VaultDirtyEntry>();
    for (const [storedIdentity, candidate] of entries) {
      if (
        !isCanonicalIdentity(storedIdentity)
        || !isRecord(candidate)
        || typeof candidate.dirty !== 'boolean'
        || !isTimestamp(candidate.updatedAt)
      ) {
        return { kind: 'corrupt' };
      }
      identities.set(storedIdentity, {
        dirty: candidate.dirty,
        updatedAt: candidate.updatedAt,
      });
    }
    return { kind: 'valid', identities };
  }

  private currentTimestamp(): number {
    const timestamp = this.now();
    if (!isTimestamp(timestamp)) {
      throw new RangeError('now must return a non-negative safe integer');
    }
    return timestamp;
  }

  private serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.operationTail.then(operation);
    this.operationTail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export function createVaultDirtyStore(
  store: KeyValueStore,
  options?: VaultDirtyStoreOptions,
): VaultDirtyStore {
  return new VaultDirtyStore(store, options);
}

function createStoredState(identities: ReadonlyMap<string, VaultDirtyEntry>): VaultDirtyState {
  return {
    schemaVersion: DIRTY_STORE_SCHEMA_VERSION,
    identities: Object.fromEntries(identities),
  };
}

function oldestCleanIdentity(identities: ReadonlyMap<string, VaultDirtyEntry>): string | undefined {
  let oldest: readonly [identity: string, updatedAt: number] | undefined;
  for (const [identity, entry] of identities) {
    if (entry.dirty) continue;
    if (
      !oldest
      || entry.updatedAt < oldest[1]
      || (entry.updatedAt === oldest[1] && identity < oldest[0])
    ) {
      oldest = [identity, entry.updatedAt];
    }
  }
  return oldest?.[0];
}

function assertCanonicalIdentity(identity: string): void {
  if (!isCanonicalIdentity(identity)) {
    throw new TypeError(
      `identity must be canonical, non-empty, and at most ${MAX_VAULT_DIRTY_IDENTITY_LENGTH} characters`,
    );
  }
}

function isCanonicalIdentity(identity: unknown): identity is string {
  return typeof identity === 'string'
    && identity.length > 0
    && identity.length <= MAX_VAULT_DIRTY_IDENTITY_LENGTH
    && identity.trim() === identity;
}

function isFutureSchemaVersion(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) > DIRTY_STORE_SCHEMA_VERSION;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function boundedPositiveInteger(value: number, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}
