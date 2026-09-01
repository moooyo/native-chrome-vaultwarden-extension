import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { createMemoryStore, type KeyValueStore } from '../../platform/store.js';
import {
  ROTATION_PENDING_STORE_KEY,
  RotationPendingStore,
  initializeAfterPendingRotationRecovery,
  recoverPendingRotationOnStartup,
  type RotationPendingMarker,
} from './rotation-pending-store.js';

const ALICE = {
  serverUrl: 'https://vault.example/',
  accountId: 'alice@example.com',
} as const;

function marker(overrides: Partial<RotationPendingMarker> = {}): RotationPendingMarker {
  return {
    schemaVersion: 1,
    ...ALICE,
    startedAt: 10,
    ...overrides,
  };
}

describe('RotationPendingStore', () => {
  it('persists only a canonical identity and timestamp before reporting success', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 123 });

    const saved = await pending.markBeforeRotation({
      serverUrl: '  HTTPS://VAULT.EXAMPLE  ',
      accountId: '  Alice@Example.COM ',
    });

    expect(saved).toEqual(marker({ startedAt: 123 }));
    expect(await storage.get(ROTATION_PENDING_STORE_KEY)).toEqual(marker({ startedAt: 123 }));
    expect(Object.keys(saved).sort()).toEqual([
      'accountId', 'schemaVersion', 'serverUrl', 'startedAt',
    ]);
  });

  it('exposes a fail-closed startup signal across store instances', async () => {
    const storage = createMemoryStore();
    const first = new RotationPendingStore(storage, { now: () => 10 });
    expect(await first.inspectForStartup()).toEqual({ kind: 'none', requiresAccountReset: false });
    await first.markBeforeRotation(ALICE);

    const restarted = new RotationPendingStore(storage);
    expect(await restarted.inspectForStartup()).toEqual({
      kind: 'pending',
      requiresAccountReset: true,
      marker: marker(),
    });
  });

  it('uses one non-replaceable slot and serializes concurrent mark attempts', async () => {
    const storage = createMemoryStore();
    let now = 1;
    const pending = new RotationPendingStore(storage, { now: () => now++ });

    const [first, second] = await Promise.allSettled([
      pending.markBeforeRotation(ALICE),
      pending.markBeforeRotation({ serverUrl: 'https://other.example/', accountId: 'bob@example.com' }),
    ]);

    expect(first).toMatchObject({ status: 'fulfilled', value: marker({ startedAt: 1 }) });
    expect(second).toMatchObject({
      status: 'rejected',
      reason: { code: 'pending_exists' },
    });
    expect(await storage.get(ROTATION_PENDING_STORE_KEY)).toEqual(marker({ startedAt: 1 }));
  });

  it.each([
    null,
    true,
    {},
    { schemaVersion: 1, ...ALICE, startedAt: -1 },
    { schemaVersion: 1, ...ALICE, startedAt: 10, protectedKey: 'must-not-be-accepted' },
    { schemaVersion: 1, serverUrl: 'https://VAULT.example/', accountId: ALICE.accountId, startedAt: 10 },
    { schemaVersion: 1, serverUrl: ALICE.serverUrl, accountId: ' Alice@example.com', startedAt: 10 },
    { schemaVersion: 1, serverUrl: 'javascript:alert(1)', accountId: ALICE.accountId, startedAt: 10 },
  ])('fails startup closed for malformed state without exposing or replacing it: %j', async (stored) => {
    const storage = createMemoryStore();
    await storage.set(ROTATION_PENDING_STORE_KEY, stored);
    const set = vi.spyOn(storage, 'set');
    const pending = new RotationPendingStore(storage);

    expect(await pending.inspectForStartup()).toEqual({
      kind: 'invalid',
      requiresAccountReset: true,
      reason: 'corrupt_state',
    });
    await expect(pending.markBeforeRotation(ALICE)).rejects.toMatchObject({ code: 'corrupt_state' });
    expect(set).not.toHaveBeenCalled();
    expect(await storage.get(ROTATION_PENDING_STORE_KEY)).toEqual(stored);
  });

  it('fails closed for a future schema without returning its unknown fields', async () => {
    const storage = createMemoryStore();
    const future = {
      schemaVersion: 2,
      ...ALICE,
      startedAt: 10,
      futureSecret: 'opaque',
    };
    await storage.set(ROTATION_PENDING_STORE_KEY, future);
    const pending = new RotationPendingStore(storage);

    expect(await pending.inspectForStartup()).toEqual({
      kind: 'invalid',
      requiresAccountReset: true,
      reason: 'unsupported_schema',
    });
    await expect(pending.markBeforeRotation(ALICE)).rejects.toMatchObject({
      code: 'unsupported_schema',
    });
  });

  it('clears pending or invalid state only through the explicit clear operation', async () => {
    const storage = createMemoryStore();
    await storage.set(ROTATION_PENDING_STORE_KEY, { malformed: true });
    const pending = new RotationPendingStore(storage);

    await pending.clear();

    expect(await pending.inspectForStartup()).toEqual({ kind: 'none', requiresAccountReset: false });
  });

  it('preserves operation order across mark, startup inspection, and clear', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });

    const marking = pending.markBeforeRotation(ALICE);
    const inspecting = pending.inspectForStartup();
    const clearing = pending.clear();

    await expect(marking).resolves.toEqual(marker());
    await expect(inspecting).resolves.toMatchObject({ kind: 'pending', requiresAccountReset: true });
    await expect(clearing).resolves.toBeUndefined();
    await expect(pending.inspectForStartup()).resolves.toEqual({
      kind: 'none',
      requiresAccountReset: false,
    });
  });

  it('propagates storage failures unchanged and keeps the queue usable', async () => {
    const base = createMemoryStore();
    const writeFailure = new Error('local storage write failed');
    let failWrite = true;
    const storage: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      async set(key, value) {
        if (failWrite) {
          failWrite = false;
          throw writeFailure;
        }
        await base.set(key, value);
      },
      setMany: (values) => base.setMany(values),
      remove: (key) => base.remove(key),
      clear: () => base.clear(),
    };
    const pending = new RotationPendingStore(storage, { now: () => 10 });

    await expect(pending.markBeforeRotation(ALICE)).rejects.toBe(writeFailure);
    await expect(pending.markBeforeRotation(ALICE)).resolves.toEqual(marker());
  });

  it('retains a fail-closed marker when storage commits and then rejects ambiguously', async () => {
    const base = createMemoryStore();
    const ambiguousFailure = new Error('storage result is unknown');
    const storage: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      async set(key, value) {
        await base.set(key, value);
        throw ambiguousFailure;
      },
      setMany: (values) => base.setMany(values),
      remove: (key) => base.remove(key),
      clear: () => base.clear(),
    };
    const pending = new RotationPendingStore(storage, { now: () => 10 });

    await expect(pending.markBeforeRotation(ALICE)).rejects.toBe(ambiguousFailure);
    await expect(pending.inspectForStartup()).resolves.toEqual({
      kind: 'pending',
      requiresAccountReset: true,
      marker: marker(),
    });
    await expect(pending.markBeforeRotation(ALICE)).rejects.toMatchObject({
      code: 'pending_exists',
    });
  });

  it('propagates startup reads and explicit clear failures unchanged', async () => {
    const readFailure = new Error('local storage read failed');
    const removeFailure = new Error('local storage remove failed');
    const storage: KeyValueStore = {
      async get() { throw readFailure; },
      async set() {},
      async remove() { throw removeFailure; },
      async clear() {},
    };
    const pending = new RotationPendingStore(storage);

    await expect(pending.inspectForStartup()).rejects.toBe(readFailure);
    await expect(pending.clear()).rejects.toBe(removeFailure);
  });

  it('rejects invalid identities and timestamps before writing a marker', async () => {
    const storage = createMemoryStore();
    const set = vi.spyOn(storage, 'set');
    const pending = new RotationPendingStore(storage, { now: () => Number.NaN });

    await expect(pending.markBeforeRotation({
      serverUrl: 'https://vault.example/?tenant=a',
      accountId: ALICE.accountId,
    })).rejects.toThrow(TypeError);
    await expect(pending.markBeforeRotation({
      serverUrl: ALICE.serverUrl,
      accountId: '   ',
    })).rejects.toThrow(TypeError);
    await expect(pending.markBeforeRotation(ALICE)).rejects.toThrow(RangeError);
    expect(set).not.toHaveBeenCalled();
  });

  it('resets accounts and cache before clearing a pending marker during startup', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    const events: string[] = [];

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: async () => { events.push('reset'); },
      clearVaultCache: async () => { events.push('cache'); },
      clearGeneratorHistoryForServer: async (serverUrl) => {
        expect(serverUrl).toBe(ALICE.serverUrl);
        events.push('history');
      },
    })).resolves.toBe(true);

    expect(events).toEqual(['reset', 'cache', 'history']);
    expect(await pending.inspectForStartup()).toEqual({ kind: 'none', requiresAccountReset: false });
  });

  it('applies the same startup cleanup to corrupt state without exposing its contents', async () => {
    const storage = createMemoryStore();
    await storage.set(ROTATION_PENDING_STORE_KEY, { schemaVersion: 99, secret: 'unknown' });
    const pending = new RotationPendingStore(storage);
    const reset = vi.fn(async () => {});
    const clearCache = vi.fn(async () => {});
    const clearHistory = vi.fn(async () => {});

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: reset,
      clearVaultCache: clearCache,
      clearGeneratorHistoryForServer: clearHistory,
    })).resolves.toBe(true);

    expect(reset).toHaveBeenCalledOnce();
    expect(clearCache).toHaveBeenCalledOnce();
    expect(clearHistory).not.toHaveBeenCalled();
    expect(await storage.get(ROTATION_PENDING_STORE_KEY)).toBeUndefined();
  });

  it('retains the marker and attempts cache cleanup when startup account reset fails', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    const resetFailure = new Error('account reset failed');
    const clearCache = vi.fn(async () => {});

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: async () => { throw resetFailure; },
      clearVaultCache: clearCache,
    })).rejects.toBe(resetFailure);

    expect(clearCache).toHaveBeenCalledOnce();
    expect(await pending.inspectForStartup()).toMatchObject({
      kind: 'pending',
      requiresAccountReset: true,
    });
  });

  it('rejects startup and retains the marker when final marker clearing fails', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    const clearFailure = new Error('marker clear failed');
    vi.spyOn(pending, 'clear').mockRejectedValue(clearFailure);

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: async () => {},
      clearVaultCache: async () => {},
    })).rejects.toBe(clearFailure);

    expect(await pending.inspectForStartup()).toMatchObject({
      kind: 'pending',
      requiresAccountReset: true,
    });
  });

  it('retains the durable marker when server-wide generator-history cleanup needs retry', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    const failure = new Error('history cleanup failed');

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: async () => {},
      clearVaultCache: async () => {},
      clearGeneratorHistoryForServer: async (serverUrl) => {
        expect(serverUrl).toBe(ALICE.serverUrl);
        throw failure;
      },
    })).rejects.toBe(failure);

    expect(await pending.inspectForStartup()).toMatchObject({
      kind: 'pending', requiresAccountReset: true, marker: ALICE,
    });
  });

  it('retains the durable marker when client-event cleanup needs retry', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    const failure = new Error('client event cleanup failed');

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: async () => {},
      clearVaultCache: async () => {},
      clearClientEvents: async (identity) => {
        expect(identity).toMatchObject(ALICE);
        throw failure;
      },
    })).rejects.toBe(failure);

    expect(await pending.inspectForStartup()).toMatchObject({
      kind: 'pending', requiresAccountReset: true, marker: ALICE,
    });
  });

  it('keeps privileged initialization closed until reset, cache purge, and marker clear finish', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    let releaseReset!: () => void;
    const resetGate = new Promise<void>((resolve) => { releaseReset = resolve; });
    const events: string[] = [];
    const initialize = vi.fn(async () => {
      events.push('initialize');
      return 'ready';
    });
    const originalClear = pending.clear.bind(pending);
    vi.spyOn(pending, 'clear').mockImplementation(async () => {
      await originalClear();
      events.push('marker');
    });

    const startup = initializeAfterPendingRotationRecovery(pending, {
      resetAllAccounts: async () => {
        events.push('reset');
        await resetGate;
      },
      clearVaultCache: async () => { events.push('cache'); },
      clearGeneratorHistoryForServer: async () => { events.push('history'); },
      clearClientEvents: async () => { events.push('events'); },
    }, initialize);

    await vi.waitFor(() => expect(events).toEqual(['reset']));
    expect(initialize).not.toHaveBeenCalled();
    releaseReset();
    await expect(startup).resolves.toBe('ready');
    expect(events).toEqual(['reset', 'cache', 'history', 'events', 'marker', 'initialize']);
    expect(await pending.inspectForStartup()).toEqual({
      kind: 'none', requiresAccountReset: false,
    });
  });

  it('never opens privileged initialization when startup recovery is uncertain', async () => {
    const storage = createMemoryStore();
    const pending = new RotationPendingStore(storage, { now: () => 10 });
    await pending.markBeforeRotation(ALICE);
    const failure = new Error('cache purge failed');
    const initialize = vi.fn(async () => 'must-not-open');

    await expect(initializeAfterPendingRotationRecovery(pending, {
      resetAllAccounts: async () => {},
      clearVaultCache: async () => { throw failure; },
    }, initialize)).rejects.toBe(failure);

    expect(initialize).not.toHaveBeenCalled();
    expect(await pending.inspectForStartup()).toMatchObject({
      kind: 'pending', requiresAccountReset: true,
    });
  });
});
