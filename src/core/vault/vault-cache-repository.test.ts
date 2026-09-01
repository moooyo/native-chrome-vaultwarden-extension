import { describe, expect, it } from 'vitest';
import type { SyncResponse } from '../api/types.js';
import type { KeyValueStore } from '../../platform/store.js';
import {
  DERIVED_VAULT_CACHE_KEY,
  LEGACY_DERIVED_VAULT_CACHE_KEYS,
  MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES,
  RAW_VAULT_CACHE_KEY,
  VaultCacheRepository,
  type DerivedVaultSnapshot,
  type VaultDerivedData,
} from './vault-cache-repository.js';

function memoryStore(): { store: KeyValueStore; values: Map<string, unknown> } {
  const values = new Map<string, unknown>();
  return {
    values,
    store: {
      async get<T>(key: string): Promise<T | undefined> {
        const value = values.get(key);
        return value === undefined ? undefined : structuredClone(value) as T;
      },
      async set(key: string, value: unknown): Promise<void> {
        values.set(key, structuredClone(value));
      },
      async setMany(entries: Readonly<Record<string, unknown>>): Promise<void> {
        for (const [key, value] of Object.entries(entries)) values.set(key, structuredClone(value));
      },
      async remove(key: string): Promise<void> {
        values.delete(key);
      },
      async clear(): Promise<void> {
        values.clear();
      },
    },
  };
}

const syncResponse: SyncResponse = {
  profile: { id: 'user-1', email: 'user@example.com' },
  ciphers: [{ id: 'cipher-1', type: 1, name: '2.encrypted' }],
};

const derived: VaultDerivedData = {
  listing: {
    items: [{ id: 'cipher-1', type: 1, name: 'Example', favorite: false, uris: [], loginUris: [] }],
    folders: [{ id: 'folder-1', name: 'Personal' }],
    collections: [],
    orgPermissions: [],
  },
  equivalentDomains: [['example.com', 'example.net']],
  excludedDomains: ['disabled.example'],
  skippedOrgCount: 2,
};

function storageItemBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify({ [DERIVED_VAULT_CACHE_KEY]: value })).byteLength;
}

function derivedWithExcludedDomain(domain: string): VaultDerivedData {
  return {
    ...derived,
    excludedDomains: [domain],
  };
}

function makeRepository() {
  const local = memoryStore();
  const session = memoryStore();
  let identity = 'https://vault.example\nuser-1';
  let sessionBindingId = 'session-1';
  let generation = 0;
  const repository = new VaultCacheRepository({
    localStore: local.store,
    sessionStore: session.store,
    getIdentity: () => identity,
    getSessionBindingId: () => sessionBindingId,
    createGeneration: () => `generation-${++generation}`,
  });
  return {
    repository,
    local,
    session,
    setIdentity: (value: string) => { identity = value; },
    setSessionBindingId: (value: string) => { sessionBindingId = value; },
  };
}

describe('VaultCacheRepository', () => {
  it('stores an identity-bound raw envelope locally and one derived snapshot in session storage', async () => {
    const { repository, local, session } = makeRepository();

    const snapshot = await repository.replace(syncResponse, derived);

    expect(await local.store.get(RAW_VAULT_CACHE_KEY)).toEqual({
      schemaVersion: 2,
      identity: 'https://vault.example\nuser-1',
      rawGeneration: 'generation-1',
      response: syncResponse,
    });
    expect(await session.store.get(DERIVED_VAULT_CACHE_KEY)).toEqual(snapshot);
    await expect(repository.readCurrent()).resolves.toEqual({
      raw: await local.store.get(RAW_VAULT_CACHE_KEY),
      derived: snapshot,
    });
    expect(snapshot).toMatchObject({
      schemaVersion: 2,
      identity: 'https://vault.example\nuser-1',
      rawGeneration: 'generation-1',
      sessionBindingId: 'session-1',
      snapshotGeneration: 'generation-2',
      ...derived,
    });
    for (const key of LEGACY_DERIVED_VAULT_CACHE_KEYS) {
      expect(await local.store.get(key)).toBeUndefined();
    }
  });

  it('removes every legacy local derived key during the first operation', async () => {
    const { repository, local } = makeRepository();
    for (const key of LEGACY_DERIVED_VAULT_CACHE_KEYS) await local.store.set(key, { plaintext: key });

    await repository.readRaw();

    for (const key of LEGACY_DERIVED_VAULT_CACHE_KEYS) {
      expect(await local.store.get(key)).toBeUndefined();
    }
  });

  it('rejects a snapshot whose source generation does not match without mutating a read path', async () => {
    const { repository, session } = makeRepository();
    const current = await repository.replace(syncResponse, derived);
    const stale: DerivedVaultSnapshot = { ...current, rawGeneration: 'stale-generation' };
    await session.store.set(DERIVED_VAULT_CACHE_KEY, stale);

    await expect(repository.readDerived()).resolves.toBeUndefined();
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toEqual(stale);
  });

  it('does not expose or delete another identity raw or derived cache from a read path', async () => {
    const { repository, local, session, setIdentity } = makeRepository();
    await repository.replace(syncResponse, derived);

    setIdentity('https://vault.example\nuser-2');

    await expect(repository.readRaw()).resolves.toBeUndefined();
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toBeDefined();
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeDefined();
  });

  it('invalidates the derived snapshot when replacing only the raw response', async () => {
    const { repository, session } = makeRepository();
    const first = await repository.replace(syncResponse, derived);

    const updated = structuredClone(syncResponse);
    updated.ciphers.push({ id: 'cipher-2', type: 2, name: '2.more-encrypted' });
    const envelope = await repository.writeRaw(updated);

    expect(envelope.rawGeneration).not.toBe(first.rawGeneration);
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    await expect(repository.readDerived()).resolves.toBeUndefined();
  });

  it.each(['writeRaw', 'replace'] as const)(
    'keeps the current raw envelope when %s cannot persist its replacement',
    async (operation) => {
      const local = memoryStore();
      const session = memoryStore();
      let rejectRawWrites = false;
      let generation = 0;
      const failingLocalStore: KeyValueStore = {
        ...local.store,
        async set(key, value) {
          if (rejectRawWrites && key === RAW_VAULT_CACHE_KEY) {
            throw new Error('QUOTA_BYTES exceeded');
          }
          await local.store.set(key, value);
        },
      };
      const repository = new VaultCacheRepository({
        localStore: failingLocalStore,
        sessionStore: session.store,
        getIdentity: () => 'identity',
        getSessionBindingId: () => 'session-1',
        createGeneration: () => `generation-${++generation}`,
      });
      await repository.replace(syncResponse, derived);
      const current = await local.store.get(RAW_VAULT_CACHE_KEY);
      const updated = structuredClone(syncResponse);
      updated.ciphers.push({ id: 'cipher-2', type: 2, name: '2.more-encrypted' });
      rejectRawWrites = true;

      const write = operation === 'writeRaw'
        ? repository.writeRaw(updated)
        : repository.replace(updated, derived);
      await expect(write).rejects.toThrow('QUOTA_BYTES exceeded');

      await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toEqual(current);
      await expect(repository.readRaw()).resolves.toEqual(current);
      await expect(repository.readCurrent()).resolves.toEqual({ raw: current });
    },
  );

  it('refuses to publish a rebuild from an obsolete raw generation', async () => {
    const { repository } = makeRepository();
    await repository.replace(syncResponse, derived);
    const oldSource = (await repository.readRaw())!;
    await repository.writeRaw({ ...syncResponse, ciphers: [] });

    await expect(repository.assertCurrent(oldSource)).rejects.toThrow(/cache changed/i);
    await expect(repository.writeDerived(oldSource, derived)).rejects.toThrow(/changed while rebuilding/i);
  });

  it('clears only derived data for a lock purge and clears both areas for an explicit reset', async () => {
    const { repository, local, session } = makeRepository();
    await repository.replace(syncResponse, derived);

    await repository.clearDerived();
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toBeDefined();
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();

    await repository.clearAll();
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
  });

  it('keeps the raw envelope without falling back to local plaintext when session writes fail', async () => {
    const local = memoryStore();
    const session = memoryStore();
    const quotaSession: KeyValueStore = {
      ...session.store,
      set: async () => { throw new Error('QUOTA_BYTES exceeded'); },
    };
    const repository = new VaultCacheRepository({
      localStore: local.store,
      sessionStore: quotaSession,
      getIdentity: () => 'identity',
      getSessionBindingId: () => 'session-1',
      createGeneration: () => 'generation',
    });

    await expect(repository.replace(syncResponse, derived)).resolves.toMatchObject({ listing: derived.listing });
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toMatchObject({ response: syncResponse });
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    for (const key of LEGACY_DERIVED_VAULT_CACHE_KEYS) {
      expect(await local.store.get(key)).toBeUndefined();
    }
  });

  it('persists a derived snapshot whose storage item is exactly at the byte budget', async () => {
    const { repository, session } = makeRepository();
    const raw = await repository.writeRaw(syncResponse);
    const emptySnapshot: DerivedVaultSnapshot = {
      schemaVersion: 2,
      identity: raw.identity,
      rawGeneration: raw.rawGeneration,
      sessionBindingId: 'session-1',
      snapshotGeneration: 'generation-2',
      ...derivedWithExcludedDomain(''),
    };
    const fillerLength = MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES - storageItemBytes(emptySnapshot);
    expect(fillerLength).toBeGreaterThan(0);

    const snapshot = await repository.writeDerived(
      raw,
      derivedWithExcludedDomain('x'.repeat(fillerLength)),
    );

    expect(storageItemBytes(snapshot)).toBe(MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES);
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toEqual(snapshot);
  });

  it('counts multi-byte UTF-8 data and skips an oversized derived session write', async () => {
    const local = memoryStore();
    const session = memoryStore();
    let derivedSetCalls = 0;
    let generation = 0;
    const repository = new VaultCacheRepository({
      localStore: local.store,
      sessionStore: {
        ...session.store,
        async set(key, value) {
          if (key === DERIVED_VAULT_CACHE_KEY) derivedSetCalls += 1;
          await session.store.set(key, value);
        },
      },
      getIdentity: () => 'identity',
      getSessionBindingId: () => 'session-1',
      createGeneration: () => `generation-${++generation}`,
    });
    const raw = await repository.writeRaw(syncResponse);
    const emptySnapshot: DerivedVaultSnapshot = {
      schemaVersion: 2,
      identity: 'identity',
      rawGeneration: raw.rawGeneration,
      sessionBindingId: 'session-1',
      snapshotGeneration: 'generation-2',
      ...derivedWithExcludedDomain(''),
    };
    const characters = Math.floor(
      (MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES - storageItemBytes(emptySnapshot)) / 3,
    ) + 1;
    const domain = '界'.repeat(characters);
    expect(JSON.stringify({ [DERIVED_VAULT_CACHE_KEY]: {
      ...emptySnapshot,
      ...derivedWithExcludedDomain(domain),
    } }).length).toBeLessThan(MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES);

    const snapshot = await repository.writeDerived(raw, derivedWithExcludedDomain(domain));

    expect(storageItemBytes(snapshot)).toBeGreaterThan(MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES);
    expect(derivedSetCalls).toBe(0);
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
  });

  it('clears an old derived snapshot and keeps raw local data when the replacement is oversized', async () => {
    const local = memoryStore();
    const session = memoryStore();
    let derivedSetCalls = 0;
    let generation = 0;
    const repository = new VaultCacheRepository({
      localStore: local.store,
      sessionStore: {
        ...session.store,
        async set(key, value) {
          if (key === DERIVED_VAULT_CACHE_KEY) derivedSetCalls += 1;
          await session.store.set(key, value);
        },
      },
      getIdentity: () => 'identity',
      getSessionBindingId: () => 'session-1',
      createGeneration: () => `generation-${++generation}`,
    });
    await repository.replace(syncResponse, derived);
    const raw = (await repository.readRaw())!;
    expect(derivedSetCalls).toBe(1);

    await expect(repository.writeDerived(
      raw,
      derivedWithExcludedDomain('x'.repeat(MAX_DERIVED_VAULT_CACHE_STORAGE_BYTES)),
    )).resolves.toMatchObject({ rawGeneration: raw.rawGeneration });

    expect(derivedSetCalls).toBe(1);
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toEqual(raw);
    await expect(repository.readCurrent()).resolves.toEqual({ raw });
  });

  it('clears an old derived snapshot without calling set when serialization fails', async () => {
    const local = memoryStore();
    const session = memoryStore();
    let derivedSetCalls = 0;
    let generation = 0;
    const repository = new VaultCacheRepository({
      localStore: local.store,
      sessionStore: {
        ...session.store,
        async set(key, value) {
          if (key === DERIVED_VAULT_CACHE_KEY) derivedSetCalls += 1;
          await session.store.set(key, value);
        },
      },
      getIdentity: () => 'identity',
      getSessionBindingId: () => 'session-1',
      createGeneration: () => `generation-${++generation}`,
    });
    await repository.replace(syncResponse, derived);
    const raw = (await repository.readRaw())!;
    const unserializable = derivedWithExcludedDomain('unserializable') as VaultDerivedData & {
      unsupported: bigint;
    };
    unserializable.unsupported = 1n;

    await expect(repository.writeDerived(raw, unserializable)).resolves.toMatchObject({
      unsupported: 1n,
    });

    expect(derivedSetCalls).toBe(1);
    await expect(session.store.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toEqual(raw);
  });

  it('round-trips an unknown positive cipher type and its opaque encrypted payload', async () => {
    const { repository } = makeRepository();
    const response: SyncResponse = {
      profile: { id: 'user-1', email: 'user@example.com' },
      ciphers: [
        { id: 'known', type: 1, name: '2.known' },
        {
          id: 'future',
          type: 6,
          name: '2.future-name',
          bankAccount: {
            accountNumber: '2.future-account',
            routingNumber: '2.future-routing',
          },
        },
      ],
    };

    await repository.writeRaw(response);
    const raw = await repository.readRaw();

    expect(raw?.response).toEqual(response);
    expect(raw?.response.ciphers).toHaveLength(2);
    expect(raw?.response.ciphers[1]?.bankAccount).toEqual(response.ciphers[1]?.bankAccount);
  });

  it('round-trips policy, membership, provider, and future sync fields without projection', async () => {
    const { repository } = makeRepository();
    const response: SyncResponse = {
      profile: {
        id: 'user-1',
        email: 'user@example.com',
        organizationsNew: [{
          id: 'org-1',
          key: null,
          status: 1,
          type: 2,
          enabled: true,
          usePolicies: true,
          futureOrganizationField: { retained: true },
        }],
        providerOrganizations: [{
          id: 'provider-org',
          key: '4.provider-key',
          status: 2,
          type: 0,
          enabled: true,
          usePolicies: true,
          futureProviderOrganizationField: ['retained'],
        }],
        providers: [{ id: 'provider-1', futureProviderField: 42 }],
      },
      ciphers: [],
      policiesNew: [{
        id: 'future-policy',
        organizationId: 'org-1',
        type: 99,
        enabled: true,
        data: { futureControl: ['retained'] },
        futurePolicyField: { retained: true },
      }],
      futureSyncField: { retained: true },
    };

    await repository.writeRaw(response);
    const raw = await repository.readRaw();

    expect(raw?.response).toEqual(response);
    expect(raw?.response.policiesNew?.[0]?.futurePolicyField).toEqual({ retained: true });
    expect(raw?.response.profile.organizationsNew?.[0]?.futureOrganizationField)
      .toEqual({ retained: true });
    expect(raw?.response.futureSyncField).toEqual({ retained: true });
  });

  it.each([-1, 0, 1.5, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an envelope containing invalid cipher type %s without deleting it',
    async (type) => {
      const { repository, local } = makeRepository();
      const stored = {
        schemaVersion: 2,
        identity: 'https://vault.example\nuser-1',
        rawGeneration: 'invalid-generation',
        response: {
          profile: { id: 'user-1', email: 'user@example.com' },
          ciphers: [{ id: 'invalid', type, opaque: 'must-remain-encrypted' }],
        },
      };
      await local.store.set(RAW_VAULT_CACHE_KEY, stored);

      await expect(repository.readRaw()).resolves.toBeUndefined();
      await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toEqual(stored);
    },
  );

  it('ignores an unversioned raw cache instead of assigning it to the current identity', async () => {
    const { repository, local } = makeRepository();
    await local.store.set(RAW_VAULT_CACHE_KEY, syncResponse);

    await expect(repository.readRaw()).resolves.toBeUndefined();
    await expect(local.store.get(RAW_VAULT_CACHE_KEY)).resolves.toEqual(syncResponse);
  });
});
