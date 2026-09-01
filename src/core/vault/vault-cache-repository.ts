import type { SyncResponse } from '../api/types.js';
import { isValidRawCipherType } from '../api/server-capabilities.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { CipherSummary, CollectionSummary, FolderSummary } from './models.js';
import type { OrgPermission } from './org-permissions.js';

export const RAW_VAULT_CACHE_KEY = 'vaultCache';
export const DERIVED_VAULT_CACHE_KEY = 'vaultDerivedSnapshot';
/** Reserved storage.session partition for the rebuildable plaintext vault snapshot. */
export const MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES = 4 * 1_024 * 1_024;

export const LEGACY_DERIVED_VAULT_CACHE_KEYS = [
  'vaultSummaries', 'vaultFolders', 'vaultCollections', 'vaultEquivalentDomains',
  'vaultExcludedDomains', 'vaultSkippedOrgCount', 'vaultOrgPermissions',
] as const;

const CACHE_SCHEMA_VERSION = 2 as const;
const WRITE_TAILS = new WeakMap<object, Promise<void>>();

export interface RawVaultEnvelope {
  schemaVersion: typeof CACHE_SCHEMA_VERSION;
  identity: string;
  rawGeneration: string;
  response: SyncResponse;
}

export interface VaultCacheListing {
  items: CipherSummary[];
  folders: FolderSummary[];
  collections: CollectionSummary[];
  orgPermissions: OrgPermission[];
  /** Consumers must require exact true; snapshots from older schemas fail closed. */
  personalCreationAllowed?: boolean;
}

export interface VaultDerivedData {
  listing: VaultCacheListing;
  equivalentDomains: string[][];
  excludedDomains: string[];
  skippedOrgCount: number;
}

export interface DerivedVaultSnapshot extends VaultDerivedData {
  schemaVersion: typeof CACHE_SCHEMA_VERSION;
  identity: string;
  rawGeneration: string;
  sessionBindingId: string;
  snapshotGeneration: string;
}

export interface VaultCacheState {
  raw: RawVaultEnvelope;
  derived?: DerivedVaultSnapshot;
}

export interface VaultCacheRepositoryDeps {
  localStore: KeyValueStore;
  sessionStore: KeyValueStore;
  getIdentity(): string | undefined | Promise<string | undefined>;
  getSessionBindingId(): string | undefined | Promise<string | undefined>;
  createGeneration?: () => string;
}

/** Stores encrypted raw sync data locally and one session-bound derived snapshot. */
export class VaultCacheRepository {
  private migration: Promise<void> | undefined;

  constructor(private readonly deps: VaultCacheRepositoryDeps) {}

  async initialize(): Promise<void> {
    await this.ensureMigrated();
  }

  async readRaw(): Promise<RawVaultEnvelope | undefined> {
    await this.ensureMigrated();
    const identity = await this.currentIdentity();
    if (!identity) return undefined;
    const stored = await this.deps.localStore.get<unknown>(RAW_VAULT_CACHE_KEY);
    if ((await this.currentIdentity()) !== identity) return undefined;
    return isRawVaultEnvelope(stored) && stored.identity === identity ? stored : undefined;
  }

  async readDerived(): Promise<DerivedVaultSnapshot | undefined> {
    return (await this.readCurrent())?.derived;
  }

  /** Read a generation-consistent pair and revalidate identity and session at the read boundary. */
  async readCurrent(): Promise<VaultCacheState | undefined> {
    await this.ensureMigrated();
    const [identity, sessionBindingId] = await Promise.all([
      this.currentIdentity(), this.currentSessionBindingId(),
    ]);
    if (!identity) return undefined;
    const [raw, derived] = await Promise.all([
      this.deps.localStore.get<unknown>(RAW_VAULT_CACHE_KEY),
      this.deps.sessionStore.get<unknown>(DERIVED_VAULT_CACHE_KEY),
    ]);
    const [finalIdentity, finalSessionBindingId] = await Promise.all([
      this.currentIdentity(), this.currentSessionBindingId(),
    ]);
    if (identity !== finalIdentity || sessionBindingId !== finalSessionBindingId) return undefined;
    if (!isRawVaultEnvelope(raw) || raw.identity !== identity) return undefined;
    if (
      sessionBindingId
      && isDerivedVaultSnapshot(derived)
      && derived.identity === identity
      && derived.rawGeneration === raw.rawGeneration
      && derived.sessionBindingId === sessionBindingId
    ) return { raw, derived };
    return { raw };
  }

  async assertCurrent(source: RawVaultEnvelope): Promise<void> {
    await this.ensureMigrated();
    const identity = await this.currentIdentity();
    const stored = await this.deps.localStore.get<unknown>(RAW_VAULT_CACHE_KEY);
    if (
      (await this.currentIdentity()) !== identity
      || !identity
      || identity !== source.identity
      || !isRawVaultEnvelope(stored)
      || stored.identity !== source.identity
      || stored.rawGeneration !== source.rawGeneration
    ) throw new Error('Vault cache changed during operation');
  }

  /** Persist raw and derived data under one cross-instance write turn. */
  async replace(response: SyncResponse, derived: VaultDerivedData): Promise<DerivedVaultSnapshot> {
    await this.ensureMigrated();
    return this.serializeWrite(async () => {
      const identity = await this.requireIdentity();
      const sessionBindingId = await this.requireSessionBindingId();
      const envelope = this.createEnvelope(identity, response);
      const snapshot = this.createSnapshot(envelope, sessionBindingId, derived);
      await this.deps.sessionStore.remove(DERIVED_VAULT_CACHE_KEY);
      await this.deps.localStore.set(RAW_VAULT_CACHE_KEY, envelope);
      await this.assertWriteContext(identity, sessionBindingId, envelope);
      await this.persistDerivedBestEffort(snapshot);
      await this.assertWriteContext(identity, sessionBindingId, envelope);
      return snapshot;
    });
  }

  /** Publish a rebuilt snapshot only while its raw source and unlocked session remain current. */
  async writeDerived(
    source: RawVaultEnvelope,
    derived: VaultDerivedData,
    expectedSessionBindingId?: string,
  ): Promise<DerivedVaultSnapshot> {
    await this.ensureMigrated();
    return this.serializeWrite(async () => {
      const identity = await this.requireIdentity();
      const sessionBindingId = await this.requireSessionBindingId();
      if (expectedSessionBindingId !== undefined && sessionBindingId !== expectedSessionBindingId) {
        throw new Error('Vault session changed while rebuilding derived data');
      }
      await this.assertWriteContext(identity, sessionBindingId, source);
      const snapshot = this.createSnapshot(source, sessionBindingId, derived);
      await this.persistDerivedBestEffort(snapshot);
      try {
        await this.assertWriteContext(identity, sessionBindingId, source);
      } catch (error) {
        await this.removeDerivedIfOwned(snapshot);
        throw error;
      }
      return snapshot;
    });
  }

  /** Replace encrypted raw data and invalidate derivatives of the previous generation. */
  async writeRaw(response: SyncResponse, expectedIdentity?: string): Promise<RawVaultEnvelope> {
    await this.ensureMigrated();
    return this.serializeWrite(async () => {
      const identity = await this.requireIdentity();
      if (expectedIdentity !== undefined && identity !== expectedIdentity) {
        throw new Error('Vault identity changed before raw cache write');
      }
      const envelope = this.createEnvelope(identity, response);
      await this.deps.sessionStore.remove(DERIVED_VAULT_CACHE_KEY);
      await this.deps.localStore.set(RAW_VAULT_CACHE_KEY, envelope);
      if ((await this.currentIdentity()) !== identity) {
        await this.removeRawIfOwned(envelope);
        throw new Error('Vault identity changed during raw cache write');
      }
      return envelope;
    });
  }

  async clearDerived(): Promise<void> {
    await this.ensureMigrated();
    await this.serializeWrite(() => this.deps.sessionStore.remove(DERIVED_VAULT_CACHE_KEY));
  }

  async clearAll(): Promise<void> {
    await this.ensureMigrated();
    await this.serializeWrite(async () => {
      await this.deps.sessionStore.remove(DERIVED_VAULT_CACHE_KEY);
      await this.deps.localStore.remove(RAW_VAULT_CACHE_KEY);
    });
  }

  private createEnvelope(identity: string, response: SyncResponse): RawVaultEnvelope {
    return {
      schemaVersion: CACHE_SCHEMA_VERSION,
      identity,
      rawGeneration: this.createGeneration(),
      response,
    };
  }

  private createSnapshot(
    source: RawVaultEnvelope,
    sessionBindingId: string,
    derived: VaultDerivedData,
  ): DerivedVaultSnapshot {
    return {
      schemaVersion: CACHE_SCHEMA_VERSION,
      identity: source.identity,
      rawGeneration: source.rawGeneration,
      sessionBindingId,
      snapshotGeneration: this.createGeneration(),
      ...derived,
    };
  }

  private createGeneration(): string {
    return this.deps.createGeneration?.() ?? globalThis.crypto.randomUUID();
  }

  private async persistDerivedBestEffort(snapshot: DerivedVaultSnapshot): Promise<void> {
    const storageBytes = derivedSnapshotStorageBytes(snapshot);
    if (
      storageBytes === undefined
      || storageBytes > MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES
    ) {
      try {
        await this.deps.sessionStore.remove(DERIVED_VAULT_CACHE_KEY);
      } catch {
        // The returned snapshot remains usable in memory even when stale session cleanup fails.
      }
      return;
    }
    try {
      await this.deps.sessionStore.set(DERIVED_VAULT_CACHE_KEY, snapshot);
    } catch {
      // A failed old write must never remove a newer snapshot.
      try {
        await this.removeDerivedIfOwned(snapshot);
      } catch {
        // Generation validation still rejects partial or stale data.
      }
    }
  }

  private async removeDerivedIfOwned(snapshot: DerivedVaultSnapshot): Promise<void> {
    const stored = await this.deps.sessionStore.get<unknown>(DERIVED_VAULT_CACHE_KEY);
    if (
      isDerivedVaultSnapshot(stored)
      && stored.snapshotGeneration === snapshot.snapshotGeneration
    ) await this.deps.sessionStore.remove(DERIVED_VAULT_CACHE_KEY);
  }

  private async removeRawIfOwned(envelope: RawVaultEnvelope): Promise<void> {
    const stored = await this.deps.localStore.get<unknown>(RAW_VAULT_CACHE_KEY);
    if (
      isRawVaultEnvelope(stored)
      && stored.identity === envelope.identity
      && stored.rawGeneration === envelope.rawGeneration
    ) await this.deps.localStore.remove(RAW_VAULT_CACHE_KEY);
  }

  private async assertWriteContext(
    identity: string,
    sessionBindingId: string,
    source: RawVaultEnvelope,
  ): Promise<void> {
    const [currentIdentity, currentSessionBindingId, current] = await Promise.all([
      this.currentIdentity(),
      this.currentSessionBindingId(),
      this.deps.localStore.get<unknown>(RAW_VAULT_CACHE_KEY),
    ]);
    if (
      currentIdentity !== identity
      || currentSessionBindingId !== sessionBindingId
      || source.identity !== identity
      || !isRawVaultEnvelope(current)
      || current.identity !== identity
      || current.rawGeneration !== source.rawGeneration
    ) throw new Error('Vault cache changed while rebuilding derived data');
  }

  private async currentIdentity(): Promise<string | undefined> {
    const identity = await this.deps.getIdentity();
    return identity && identity.length > 0 ? identity : undefined;
  }

  private async currentSessionBindingId(): Promise<string | undefined> {
    const binding = await this.deps.getSessionBindingId();
    return binding && binding.length > 0 ? binding : undefined;
  }

  private async requireIdentity(): Promise<string> {
    const identity = await this.currentIdentity();
    if (!identity) throw new Error('Vault cache identity is unavailable');
    return identity;
  }

  private async requireSessionBindingId(): Promise<string> {
    const binding = await this.currentSessionBindingId();
    if (!binding) throw new Error('Vault cache session binding is unavailable');
    return binding;
  }

  private serializeWrite<Result>(operation: () => Promise<Result>): Promise<Result> {
    const owner = this.deps.localStore as object;
    const previous = WRITE_TAILS.get(owner) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const tail = result.then(() => undefined, () => undefined);
    WRITE_TAILS.set(owner, tail);
    void tail.finally(() => {
      if (WRITE_TAILS.get(owner) === tail) WRITE_TAILS.delete(owner);
    });
    return result;
  }

  private ensureMigrated(): Promise<void> {
    this.migration ??= this.removeLegacyDerivedCaches().catch((error: unknown) => {
      this.migration = undefined;
      throw error;
    });
    return this.migration;
  }

  private async removeLegacyDerivedCaches(): Promise<void> {
    for (const key of LEGACY_DERIVED_VAULT_CACHE_KEYS) {
      await this.deps.localStore.remove(key);
    }
  }
}

function derivedSnapshotStorageBytes(snapshot: DerivedVaultSnapshot): number | undefined {
  try {
    // Chrome quota accounting includes the storage item key and JSON envelope around the value.
    const serialized = JSON.stringify({ [DERIVED_VAULT_CACHE_KEY]: snapshot });
    if (typeof serialized !== 'string') return undefined;
    const byteLength = new TextEncoder().encode(serialized).byteLength;
    return Number.isSafeInteger(byteLength) ? byteLength : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRawVaultEnvelope(value: unknown): value is RawVaultEnvelope {
  if (!isRecord(value) || value.schemaVersion !== CACHE_SCHEMA_VERSION) return false;
  if (typeof value.identity !== 'string' || typeof value.rawGeneration !== 'string') return false;
  if (!isRecord(value.response) || !isRecord(value.response.profile)) return false;
  if (typeof value.response.profile.id !== 'string' || typeof value.response.profile.email !== 'string') return false;
  return Array.isArray(value.response.ciphers) && value.response.ciphers.every(isCipherHeader);
}

function isDerivedVaultSnapshot(value: unknown): value is DerivedVaultSnapshot {
  if (!isRecord(value) || value.schemaVersion !== CACHE_SCHEMA_VERSION) return false;
  if (
    typeof value.identity !== 'string'
    || typeof value.rawGeneration !== 'string'
    || typeof value.sessionBindingId !== 'string'
    || typeof value.snapshotGeneration !== 'string'
  ) return false;
  if (!isRecord(value.listing) || typeof value.skippedOrgCount !== 'number') return false;
  return Array.isArray(value.listing.items)
    && Array.isArray(value.listing.folders)
    && Array.isArray(value.listing.collections)
    && Array.isArray(value.listing.orgPermissions)
    && isStringMatrix(value.equivalentDomains)
    && isStringArray(value.excludedDomains);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function isStringMatrix(value: unknown): value is string[][] {
  return Array.isArray(value) && value.every(isStringArray);
}

function isCipherHeader(value: unknown): boolean {
  return isRecord(value)
    && typeof value.id === 'string'
    && isValidRawCipherType(value.type);
}
