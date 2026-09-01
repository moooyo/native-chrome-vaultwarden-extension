import { describe, expect, it, vi } from 'vitest';
import type { KeyValueStore } from '../../platform/store.js';
import {
  DEFAULT_MAX_DIRTY_IDENTITIES,
  MAX_VAULT_DIRTY_IDENTITY_LENGTH,
  VAULT_DIRTY_STORE_KEY,
  VaultDirtyStore,
  type VaultDirtyState,
} from './vault-dirty-store.js';

function memoryStore(initial?: unknown): {
  readonly store: KeyValueStore;
  readonly values: Map<string, unknown>;
  readonly set: ReturnType<typeof vi.fn>;
} {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set(VAULT_DIRTY_STORE_KEY, structuredClone(initial));
  const set = vi.fn(async (key: string, value: unknown): Promise<void> => {
    await Promise.resolve();
    values.set(key, structuredClone(value));
  });
  return {
    values,
    set,
    store: {
      async get<T>(key: string): Promise<T | undefined> {
        const value = values.get(key);
        await Promise.resolve();
        return value === undefined ? undefined : structuredClone(value) as T;
      },
      set,
      async remove(key: string): Promise<void> {
        values.delete(key);
      },
      async clear(): Promise<void> {
        values.clear();
      },
    },
  };
}

function state(entries: Array<readonly [string, boolean, number]>): VaultDirtyState {
  return {
    schemaVersion: 1,
    identities: Object.fromEntries(entries.map(([identity, dirty, updatedAt]) => [
      identity,
      { dirty, updatedAt },
    ])),
  };
}

describe('VaultDirtyStore', () => {
  it('persists dirty state across service-worker adapter instances', async () => {
    const memory = memoryStore();
    const first = new VaultDirtyStore(memory.store, { now: () => 10 });

    await expect(first.readDirty('account-a')).resolves.toBe(false);
    await first.markDirty('account-a');

    const restarted = new VaultDirtyStore(memory.store, { now: () => 20 });
    await expect(restarted.readDirty('account-a')).resolves.toBe(true);
    await expect(restarted.readDirty('account-b')).resolves.toBe(false);
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(state([
      ['account-a', true, 10],
    ]));
  });

  it('serializes concurrent mark and clear operations for different identities', async () => {
    const memory = memoryStore(state([
      ['account-a', true, 1],
      ['account-c', true, 2],
    ]));
    let now = 10;
    const dirty = new VaultDirtyStore(memory.store, { now: () => now++ });

    await Promise.all([
      dirty.clearDirty('account-a'),
      dirty.markDirty('account-b'),
      dirty.clearDirty('account-c'),
    ]);

    await expect(dirty.readDirty('account-a')).resolves.toBe(false);
    await expect(dirty.readDirty('account-b')).resolves.toBe(true);
    await expect(dirty.readDirty('account-c')).resolves.toBe(false);
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(state([
      ['account-a', false, 10],
      ['account-c', false, 12],
      ['account-b', true, 11],
    ]));
  });

  it('preserves call order for concurrent operations on the same identity', async () => {
    const memory = memoryStore();
    let now = 1;
    const dirty = new VaultDirtyStore(memory.store, { now: () => now++ });

    await Promise.all([
      dirty.markDirty('account-a'),
      dirty.clearDirty('account-a'),
      dirty.markDirty('account-a'),
    ]);

    await expect(dirty.readDirty('account-a')).resolves.toBe(true);
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(state([
      ['account-a', true, 3],
    ]));
  });

  it('orders reads after an earlier in-flight marker write', async () => {
    const memory = memoryStore();
    const dirty = new VaultDirtyStore(memory.store, { now: () => 1 });

    const marking = dirty.markDirty('account-a');
    const reading = dirty.readDirty('account-a');

    await expect(reading).resolves.toBe(true);
    await expect(marking).resolves.toBeUndefined();
  });

  it('makes clearing a missing or already-clean identity idempotent', async () => {
    const memory = memoryStore(state([['account-a', false, 1]]));
    const dirty = new VaultDirtyStore(memory.store, { now: () => 2 });

    await dirty.clearDirty('missing-account');
    await dirty.clearDirty('account-a');

    expect(memory.set).not.toHaveBeenCalled();
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(state([
      ['account-a', false, 1],
    ]));
  });

  it.each([
    null,
    true,
    {},
    { schemaVersion: 1, identities: [] },
    { schemaVersion: 1, identities: new Map([['account-a', { dirty: false, updatedAt: 1 }]]) },
    { schemaVersion: 1, identities: { 'account-a': { dirty: 'yes', updatedAt: 1 } } },
    { schemaVersion: 1, identities: { ' account-a': { dirty: false, updatedAt: 1 } } },
    { schemaVersion: 1, identities: { 'account-a': { dirty: false, updatedAt: -1 } } },
  ])('fails closed for malformed stored state without replacing it: %j', async (stored) => {
    const memory = memoryStore(stored);
    const dirty = new VaultDirtyStore(memory.store);

    await expect(dirty.readDirty('account-a')).resolves.toBe(true);
    await expect(dirty.markDirty('account-a')).rejects.toMatchObject({ code: 'corrupt_state' });
    await expect(dirty.clearDirty('account-a')).rejects.toMatchObject({ code: 'corrupt_state' });
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(stored);
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('fails closed and preserves a newer schema it cannot interpret', async () => {
    const future = {
      schemaVersion: 2,
      identities: { 'account-a': { dirty: false, updatedAt: 1, futureField: true } },
    };
    const memory = memoryStore(future);
    const dirty = new VaultDirtyStore(memory.store);

    await expect(dirty.readDirty('account-a')).resolves.toBe(true);
    await expect(dirty.markDirty('account-a')).rejects.toMatchObject({
      code: 'unsupported_schema',
    });
    await expect(dirty.clearDirty('account-a')).rejects.toMatchObject({
      code: 'unsupported_schema',
    });
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(future);
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('evicts the oldest clean identity without evicting dirty markers', async () => {
    const memory = memoryStore(state([
      ['dirty-oldest', true, 1],
      ['clean-newer', false, 3],
      ['clean-oldest', false, 2],
    ]));
    const dirty = new VaultDirtyStore(memory.store, { maxIdentities: 3, now: () => 4 });

    await dirty.markDirty('new-account');

    await expect(dirty.readDirty('dirty-oldest')).resolves.toBe(true);
    await expect(dirty.readDirty('clean-oldest')).resolves.toBe(false);
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(state([
      ['dirty-oldest', true, 1],
      ['clean-newer', false, 3],
      ['new-account', true, 4],
    ]));
  });

  it('rejects a new marker when every capacity slot is dirty', async () => {
    const stored = state([
      ['account-a', true, 1],
      ['account-b', true, 2],
    ]);
    const memory = memoryStore(stored);
    const dirty = new VaultDirtyStore(memory.store, { maxIdentities: 2 });

    await expect(dirty.markDirty('account-c')).rejects.toMatchObject({ code: 'capacity' });
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(stored);
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('fails closed when the stored map exceeds the configured capacity', async () => {
    const stored = state([
      ['account-a', false, 1],
      ['account-b', false, 2],
      ['account-c', false, 3],
    ]);
    const memory = memoryStore(stored);
    const dirty = new VaultDirtyStore(memory.store, { maxIdentities: 2 });

    await expect(dirty.readDirty('account-a')).resolves.toBe(true);
    await expect(dirty.clearDirty('account-a')).rejects.toMatchObject({ code: 'corrupt_state' });
    expect(memory.values.get(VAULT_DIRTY_STORE_KEY)).toEqual(stored);
  });

  it('validates canonical identity and configured bounds before storage access', async () => {
    const memory = memoryStore();
    const dirty = new VaultDirtyStore(memory.store);
    const get = vi.spyOn(memory.store, 'get');

    await expect(dirty.readDirty('')).rejects.toThrow(TypeError);
    await expect(dirty.markDirty(' account-a')).rejects.toThrow(TypeError);
    await expect(dirty.clearDirty('x'.repeat(MAX_VAULT_DIRTY_IDENTITY_LENGTH + 1)))
      .rejects.toThrow(TypeError);
    expect(get).not.toHaveBeenCalled();

    const surrogatePair = '\u{1F600}';
    await expect(dirty.readDirty(surrogatePair.repeat(2_048))).resolves.toBe(false);
    await expect(dirty.readDirty(surrogatePair.repeat(2_049))).rejects.toThrow(TypeError);
    expect(get).toHaveBeenCalledOnce();

    expect(() => new VaultDirtyStore(memory.store, { maxIdentities: 0 })).toThrow(RangeError);
    expect(() => new VaultDirtyStore(memory.store, {
      maxIdentities: DEFAULT_MAX_DIRTY_IDENTITIES + 1,
    })).toThrow(RangeError);
  });

  it('propagates get and set failures and continues serializing later operations', async () => {
    const memory = memoryStore();
    const getError = new Error('storage get failed');
    const setError = new Error('storage set failed');
    const get = vi.spyOn(memory.store, 'get');
    get.mockRejectedValueOnce(getError);
    memory.set.mockRejectedValueOnce(setError);
    const dirty = new VaultDirtyStore(memory.store, { now: () => 1 });

    const failedRead = dirty.readDirty('account-a');
    const failedWrite = dirty.markDirty('account-a');
    const succeedingWrite = dirty.markDirty('account-b');

    await expect(failedRead).rejects.toBe(getError);
    await expect(failedWrite).rejects.toBe(setError);
    await expect(succeedingWrite).resolves.toBeUndefined();
    await expect(dirty.readDirty('account-b')).resolves.toBe(true);
  });

  it('propagates a failed clear write and leaves the durable marker dirty', async () => {
    const memory = memoryStore(state([['account-a', true, 1]]));
    const setError = new Error('storage set failed');
    memory.set.mockRejectedValueOnce(setError);
    const dirty = new VaultDirtyStore(memory.store, { now: () => 2 });

    await expect(dirty.clearDirty('account-a')).rejects.toBe(setError);
    const restarted = new VaultDirtyStore(memory.store);
    await expect(restarted.readDirty('account-a')).resolves.toBe(true);
  });
});
