import { describe, expect, it, vi } from 'vitest';
import type { KeyValueStore } from '../../platform/store.js';
import {
  MAX_SSO_REQUIRED_CACHE_ENTRIES,
  SSO_REQUIRED_CACHE_KEY,
  SsoRequiredCache,
  type SsoRequiredCacheEntry,
} from './sso-required-cache.js';

function memoryStore(initial?: unknown): {
  readonly store: KeyValueStore;
  readonly values: Map<string, unknown>;
  readonly get: ReturnType<typeof vi.fn>;
  readonly set: ReturnType<typeof vi.fn>;
  readonly remove: ReturnType<typeof vi.fn>;
} {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set(SSO_REQUIRED_CACHE_KEY, initial);
  const get = vi.fn(async (key: string): Promise<unknown> => {
    await Promise.resolve();
    return values.get(key);
  });
  const set = vi.fn(async (key: string, value: unknown): Promise<void> => {
    await Promise.resolve();
    values.set(key, value);
  });
  const remove = vi.fn(async (key: string): Promise<void> => {
    await Promise.resolve();
    values.delete(key);
  });
  return {
    values,
    get,
    set,
    remove,
    store: {
      async get<T>(key: string): Promise<T | undefined> {
        return await get(key) as T | undefined;
      },
      set,
      remove,
      async clear(): Promise<void> {
        values.clear();
      },
    },
  };
}

const ALICE_A: SsoRequiredCacheEntry = {
  email: 'alice@example.test',
  webVaultUrl: 'https://vault-a.example.test/',
};

describe('SsoRequiredCache', () => {
  it('normalizes caller input and persists only the exact official entry shape', async () => {
    const memory = memoryStore();
    const cache = new SsoRequiredCache(memory.store);

    await cache.add({
      email: ' Alice@Example.TEST ',
      webVaultUrl: 'https://VAULT-A.example.test',
    });

    expect(memory.values.get(SSO_REQUIRED_CACHE_KEY)).toEqual([ALICE_A]);
    await expect(cache.has(ALICE_A)).resolves.toBe(true);
    const entries = await cache.list();
    expect(entries).toEqual([ALICE_A]);
    expect(Object.isFrozen(entries)).toBe(true);
    expect(Object.isFrozen(entries[0])).toBe(true);
  });

  it('uses the normalized email and Web Vault URL together as the cache key', async () => {
    const memory = memoryStore();
    const cache = new SsoRequiredCache(memory.store);
    const aliceB = { ...ALICE_A, webVaultUrl: 'https://vault-b.example.test/' };
    const bobA = { ...ALICE_A, email: 'bob@example.test' };

    await cache.add(ALICE_A);
    await cache.add(aliceB);
    await cache.add(bobA);
    await cache.remove(ALICE_A);

    await expect(cache.has(ALICE_A)).resolves.toBe(false);
    await expect(cache.has(aliceB)).resolves.toBe(true);
    await expect(cache.has(bobA)).resolves.toBe(true);
    await expect(cache.list()).resolves.toEqual([aliceB, bobA]);
  });

  it('deduplicates add and reconciles both policy directions idempotently', async () => {
    const memory = memoryStore();
    const cache = new SsoRequiredCache(memory.store);

    await cache.add(ALICE_A);
    await cache.add({ email: 'ALICE@EXAMPLE.TEST', webVaultUrl: 'https://vault-a.example.test' });
    await cache.reconcile(ALICE_A, true);
    expect(memory.set).toHaveBeenCalledOnce();
    await expect(cache.list()).resolves.toEqual([ALICE_A]);

    await cache.reconcile(ALICE_A, false);
    await cache.reconcile(ALICE_A, false);
    await cache.remove(ALICE_A);
    expect(memory.set).toHaveBeenCalledTimes(2);
    expect(memory.values.get(SSO_REQUIRED_CACHE_KEY)).toEqual([]);
  });

  it('repairs duplicate persisted entries without changing first-seen order', async () => {
    const bobA = { ...ALICE_A, email: 'bob@example.test' };
    const memory = memoryStore([ALICE_A, bobA, ALICE_A]);
    const cache = new SsoRequiredCache(memory.store);

    await expect(cache.list()).resolves.toEqual([ALICE_A, bobA]);
    expect(memory.set).toHaveBeenCalledOnce();
    expect(memory.values.get(SSO_REQUIRED_CACHE_KEY)).toEqual([ALICE_A, bobA]);
  });

  it.each([
    ['legacy email array', ['alice@example.test']],
    ['non-array state', { email: ALICE_A.email, webVaultUrl: ALICE_A.webVaultUrl }],
    ['extra entry field', [{ ...ALICE_A, userId: 'legacy-id' }]],
    ['non-canonical email', [{ ...ALICE_A, email: 'Alice@Example.test' }]],
    ['non-canonical URL', [{ ...ALICE_A, webVaultUrl: 'https://vault-a.example.test' }]],
    ['unsafe URL', [{ ...ALICE_A, webVaultUrl: 'http://vault-a.example.test/' }]],
    ['oversized list', Array.from({ length: 3 }, (_value, index) => ({
      email: `user-${index}@example.test`,
      webVaultUrl: ALICE_A.webVaultUrl,
    }))],
  ])('clears %s instead of trusting or partially preserving it', async (_label, stored) => {
    const memory = memoryStore(stored);
    const cache = new SsoRequiredCache(memory.store, { maxEntries: 2 });

    await expect(cache.list()).resolves.toEqual([]);
    expect(memory.remove).toHaveBeenCalledWith(SSO_REQUIRED_CACHE_KEY);
    expect(memory.values.has(SSO_REQUIRED_CACHE_KEY)).toBe(false);
  });

  it('clears accessor-bearing entries without invoking their getters', async () => {
    let reads = 0;
    const entry = { webVaultUrl: ALICE_A.webVaultUrl } as Record<string, unknown>;
    Object.defineProperty(entry, 'email', {
      enumerable: true,
      get: () => {
        reads += 1;
        return ALICE_A.email;
      },
    });
    const memory = memoryStore([entry]);
    const cache = new SsoRequiredCache(memory.store);

    await expect(cache.list()).resolves.toEqual([]);
    expect(reads).toBe(0);
    expect(memory.remove).toHaveBeenCalledOnce();
  });

  it('clears custom-prototype entries', async () => {
    const entry = Object.assign(
      Object.create({ inherited: true }) as Record<string, unknown>,
      ALICE_A,
    );
    const memory = memoryStore([entry]);
    const cache = new SsoRequiredCache(memory.store);

    await expect(cache.list()).resolves.toEqual([]);
    expect(memory.remove).toHaveBeenCalledOnce();
  });

  it('serializes read-modify-write operations across cache instances sharing one store', async () => {
    const memory = memoryStore();
    const first = new SsoRequiredCache(memory.store);
    const second = new SsoRequiredCache(memory.store);
    const bobA = { ...ALICE_A, email: 'bob@example.test' };

    await Promise.all([first.add(ALICE_A), second.add(bobA)]);

    await expect(first.list()).resolves.toEqual([ALICE_A, bobA]);
  });

  it('continues the serialized queue after a storage failure', async () => {
    const memory = memoryStore();
    const failure = new Error('set failed');
    memory.set.mockRejectedValueOnce(failure);
    const cache = new SsoRequiredCache(memory.store);
    const bobA = { ...ALICE_A, email: 'bob@example.test' };

    const failed = cache.add(ALICE_A);
    const succeeding = cache.add(bobA);

    await expect(failed).rejects.toBe(failure);
    await expect(succeeding).resolves.toBeUndefined();
    await expect(cache.list()).resolves.toEqual([bobA]);
  });

  it('rejects invalid caller entries before storage access', async () => {
    const memory = memoryStore();
    const cache = new SsoRequiredCache(memory.store);
    const customPrototype = Object.assign(
      Object.create({ inherited: true }) as SsoRequiredCacheEntry,
      ALICE_A,
    );
    let reads = 0;
    const accessor = { webVaultUrl: ALICE_A.webVaultUrl } as unknown as SsoRequiredCacheEntry;
    Object.defineProperty(accessor, 'email', {
      enumerable: true,
      get: () => {
        reads += 1;
        return ALICE_A.email;
      },
    });

    await expect(cache.add({ ...ALICE_A, email: '' })).rejects.toThrow(TypeError);
    await expect(cache.add({ ...ALICE_A, email: 'alice @example.test' })).rejects.toThrow(TypeError);
    await expect(cache.add({ ...ALICE_A, webVaultUrl: 'javascript:alert(1)' }))
      .rejects.toThrow(TypeError);
    await expect(cache.add(customPrototype)).rejects.toThrow(TypeError);
    await expect(cache.add(accessor)).rejects.toThrow(TypeError);
    expect(reads).toBe(0);
    expect(memory.get).not.toHaveBeenCalled();
  });

  it('bounds capacity and configuration without evicting another required account', async () => {
    const memory = memoryStore([ALICE_A]);
    const cache = new SsoRequiredCache(memory.store, { maxEntries: 1 });

    await expect(cache.add({ ...ALICE_A, email: 'bob@example.test' })).rejects.toThrow(RangeError);
    expect(memory.values.get(SSO_REQUIRED_CACHE_KEY)).toEqual([ALICE_A]);
    expect(() => new SsoRequiredCache(memory.store, { maxEntries: 0 })).toThrow(RangeError);
    expect(() => new SsoRequiredCache(memory.store, {
      maxEntries: MAX_SSO_REQUIRED_CACHE_ENTRIES + 1,
    })).toThrow(RangeError);
    expect(() => new SsoRequiredCache(memory.store, { storageKey: ' invalid' }))
      .toThrow(TypeError);
  });

  it('clears every cached identity explicitly', async () => {
    const memory = memoryStore([ALICE_A]);
    const cache = new SsoRequiredCache(memory.store);

    await cache.clear();

    expect(memory.remove).toHaveBeenCalledWith(SSO_REQUIRED_CACHE_KEY);
    await expect(cache.list()).resolves.toEqual([]);
  });
});
