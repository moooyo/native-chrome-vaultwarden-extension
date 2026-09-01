import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_NOTIFICATION_BURST_MS,
  DEFAULT_POPUP_SYNC_STALE_MS,
  DEFAULT_VAULT_SYNC_STALE_MS,
  VAULT_SYNC_ALARM,
  VAULT_SYNC_ALARM_PERIOD_MINUTES,
  VAULT_SYNC_METADATA_KEY,
  createVaultSyncScheduler,
  ensureVaultSyncAlarm,
  type VaultSyncMetadata,
  type VaultSyncMetadataStore,
  type VaultSyncSchedulerDeps,
  type VaultSyncSessionContext,
} from './vault-sync-scheduler.js';

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createStore(initial?: unknown): VaultSyncMetadataStore & { read(): VaultSyncMetadata | undefined } {
  let value = initial;
  return {
    async get<T>(key: string): Promise<T | undefined> {
      return key === VAULT_SYNC_METADATA_KEY ? value as T | undefined : undefined;
    },
    async set(key: string, next: unknown): Promise<void> {
      if (key === VAULT_SYNC_METADATA_KEY) value = next;
    },
    read(): VaultSyncMetadata | undefined {
      return value as VaultSyncMetadata | undefined;
    },
  };
}

interface Harness {
  deps: VaultSyncSchedulerDeps;
  store: ReturnType<typeof createStore>;
  requestSync: ReturnType<typeof vi.fn>;
  rebuildCache: ReturnType<typeof vi.fn>;
  createAlarm: ReturnType<typeof vi.fn>;
  setContext(context: VaultSyncSessionContext | undefined): void;
  setNow(now: number): void;
}

function makeHarness(overrides: Partial<VaultSyncSchedulerDeps> = {}): Harness {
  let context: VaultSyncSessionContext | undefined = { state: 'unlocked', identity: 'account-a' };
  let now = 1_000;
  const store = createStore();
  const requestSync = vi.fn(async () => undefined);
  const rebuildCache = vi.fn(async () => undefined);
  const createAlarm = vi.fn();
  const deps: VaultSyncSchedulerDeps = {
    getSessionContext: async () => context,
    requestSync,
    rebuildCache,
    isDirty: async () => false,
    metadataStore: store,
    alarms: { get: async () => ({ name: VAULT_SYNC_ALARM }), create: createAlarm },
    now: () => now,
    ...overrides,
  };
  return {
    deps,
    store,
    requestSync,
    rebuildCache,
    createAlarm,
    setContext: (next) => { context = next; },
    setNow: (next) => { now = next; },
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('ensureVaultSyncAlarm', () => {
  it('creates the five-minute alarm only when it is missing', async () => {
    const create = vi.fn();
    await ensureVaultSyncAlarm({ get: async () => undefined, create });
    expect(create).toHaveBeenCalledWith(
      VAULT_SYNC_ALARM,
      { periodInMinutes: VAULT_SYNC_ALARM_PERIOD_MINUTES },
    );

    create.mockClear();
    await ensureVaultSyncAlarm({
      get: async () => ({ name: VAULT_SYNC_ALARM }),
      create,
    });
    expect(create).not.toHaveBeenCalled();
  });
});

describe('VaultSyncScheduler trigger policy', () => {
  it('never schedules sync for a restricted authenticated account', async () => {
    vi.useFakeTimers();
    const harness = makeHarness();
    harness.setContext({ state: 'restricted', identity: 'account-a' });
    const scheduler = createVaultSyncScheduler(harness.deps);

    await scheduler.startup();
    await scheduler.manual();
    await scheduler.popupOpened();
    await scheduler.handleAlarm(VAULT_SYNC_ALARM);
    scheduler.notification();
    await vi.advanceTimersByTimeAsync(DEFAULT_NOTIFICATION_BURST_MS);

    expect(harness.requestSync).not.toHaveBeenCalled();
  });

  it('uses the five-minute success age for periodic coalescing', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();
    harness.requestSync.mockClear();

    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS - 1);
    await scheduler.handleAlarm({ name: VAULT_SYNC_ALARM });
    expect(harness.requestSync).not.toHaveBeenCalled();

    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS);
    await scheduler.handleAlarm(VAULT_SYNC_ALARM);
    expect(harness.requestSync).toHaveBeenCalledOnce();
    expect(harness.requestSync).toHaveBeenCalledWith('alarm', 'coalesce');

    await scheduler.handleAlarm('another-alarm');
    expect(harness.requestSync).toHaveBeenCalledOnce();
  });

  it('forces successful login and manual triggers', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);

    await scheduler.sessionSettled({ reason: 'login', state: 'unlocked', succeeded: true });
    await scheduler.manual();

    expect(harness.requestSync.mock.calls).toEqual([
      ['login', 'force'],
      ['manual', 'force'],
    ]);
  });

  it('rebuilds unlocked cache before applying the stale policy', async () => {
    const order: string[] = [];
    const harness = makeHarness({
      rebuildCache: async () => { order.push('rebuild'); },
      requestSync: async (reason, policy) => { order.push(`${reason}:${policy}`); },
    });
    const scheduler = createVaultSyncScheduler(harness.deps);

    await scheduler.sessionSettled({ reason: 'unlock', state: 'unlocked', succeeded: true });

    expect(order).toEqual(['rebuild', 'unlock:coalesce']);
  });

  it('still rebuilds a fresh cache but skips its network refresh', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();
    harness.requestSync.mockClear();

    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS - 1);
    await scheduler.sessionSettled({ reason: 'pinUnlock', state: 'unlocked', succeeded: true });

    expect(harness.rebuildCache).toHaveBeenCalledWith('account-a');
    expect(harness.requestSync).not.toHaveBeenCalled();
  });

  it('falls back to a coalesced refresh when cache rebuild fails', async () => {
    const rebuildError = new Error('cache unavailable');
    const onBackgroundError = vi.fn();
    const harness = makeHarness({
      rebuildCache: async () => { throw rebuildError; },
      onBackgroundError,
    });

    await createVaultSyncScheduler(harness.deps).sessionSettled({
      reason: 'unlock', state: 'unlocked', succeeded: true,
    });

    expect(onBackgroundError).toHaveBeenCalledWith(rebuildError);
    expect(harness.requestSync).toHaveBeenCalledWith('unlock', 'coalesce');
  });

  it('ignores failed, non-activation, logged-out, and identity-less events but permits locked raw sync', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);

    await scheduler.sessionSettled({ reason: 'login', state: 'unlocked', succeeded: false });
    await scheduler.sessionSettled({ reason: 'lock', state: 'locked', succeeded: true });
    harness.setContext({ state: 'loggedOut' });
    await scheduler.manual();
    await scheduler.handleAlarm(VAULT_SYNC_ALARM);
    harness.setContext({ state: 'locked', identity: 'account-a' });
    await scheduler.manual();
    harness.setContext({ state: 'unlocked' });
    await scheduler.sessionSettled({ reason: 'login', state: 'unlocked', succeeded: true });

    expect(harness.requestSync).toHaveBeenCalledOnce();
    expect(harness.requestSync).toHaveBeenCalledWith('manual', 'force');
    expect(harness.rebuildCache).not.toHaveBeenCalled();
  });
});

describe('VaultSyncScheduler lifecycle timing', () => {
  it('forces dirty alarm, popup, and unlock reconciliation even while metadata is fresh', async () => {
    const harness = makeHarness({ isDirty: async () => true });
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();
    harness.requestSync.mockClear();

    await scheduler.handleAlarm(VAULT_SYNC_ALARM);
    await scheduler.popupOpened();
    await scheduler.sessionSettled({ reason: 'unlock', state: 'unlocked', succeeded: true });

    expect(harness.requestSync.mock.calls).toEqual([
      ['alarm', 'force'],
      ['popup', 'force'],
      ['unlock', 'force'],
    ]);
  });

  it('restores a missing alarm and forces startup reconciliation when dirty', async () => {
    const createAlarm = vi.fn();
    const harness = makeHarness({
      isDirty: async () => true,
      alarms: { get: async () => undefined, create: createAlarm },
    });

    await createVaultSyncScheduler(harness.deps).startup();

    expect(createAlarm).toHaveBeenCalledWith(
      VAULT_SYNC_ALARM,
      { periodInMinutes: VAULT_SYNC_ALARM_PERIOD_MINUTES },
    );
    expect(harness.requestSync).toHaveBeenCalledWith('startup', 'force');
  });

  it('uses normal freshness on a clean startup', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();
    harness.requestSync.mockClear();

    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS - 1);
    await scheduler.startup();
    expect(harness.requestSync).not.toHaveBeenCalled();

    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS);
    await scheduler.startup();
    expect(harness.requestSync).toHaveBeenCalledWith('startup', 'coalesce');
  });

  it('launches popup refresh after 45 seconds without awaiting the network', async () => {
    const pending = deferred<void>();
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();
    harness.requestSync.mockClear();
    harness.requestSync.mockImplementation(() => pending.promise);

    harness.setNow(1_000 + DEFAULT_POPUP_SYNC_STALE_MS - 1);
    await scheduler.popupOpened();
    expect(harness.requestSync).not.toHaveBeenCalled();

    harness.setNow(1_000 + DEFAULT_POPUP_SYNC_STALE_MS);
    await expect(scheduler.popupOpened()).resolves.toBeUndefined();
    expect(harness.requestSync).toHaveBeenCalledWith('popup', 'coalesce');
    expect(harness.rebuildCache).not.toHaveBeenCalled();

    pending.resolve(undefined);
    await Promise.resolve();
  });

  it('coalesces a notification burst into one trailing request', async () => {
    vi.useFakeTimers();
    const setTimer = vi.fn((callback: () => void, delayMs: number) => setTimeout(callback, delayMs));
    const clearTimer = vi.fn((handle: unknown) => clearTimeout(handle as ReturnType<typeof setTimeout>));
    const harness = makeHarness({ timers: { setTimeout: setTimer, clearTimeout: clearTimer } });
    const scheduler = createVaultSyncScheduler(harness.deps);

    scheduler.notification();
    await vi.advanceTimersByTimeAsync(DEFAULT_NOTIFICATION_BURST_MS - 50);
    scheduler.notification();
    expect(clearTimer).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(DEFAULT_NOTIFICATION_BURST_MS - 1);
    expect(harness.requestSync).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(harness.requestSync).toHaveBeenCalledOnce();
    expect(harness.requestSync).toHaveBeenCalledWith('notification', 'coalesce');
    expect(setTimer).toHaveBeenLastCalledWith(expect.any(Function), DEFAULT_NOTIFICATION_BURST_MS);
  });

  it('cancels a pending notification when disposed', async () => {
    vi.useFakeTimers();
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    scheduler.notification();
    scheduler.dispose();

    await vi.advanceTimersByTimeAsync(DEFAULT_NOTIFICATION_BURST_MS);

    expect(harness.requestSync).not.toHaveBeenCalled();
  });
});

describe('VaultSyncScheduler metadata', () => {
  it('reports identity-scoped freshness, dirty state, and an in-flight sync', async () => {
    const pending = deferred<void>();
    const harness = makeHarness({ isDirty: async () => true });
    harness.requestSync.mockImplementationOnce(() => pending.promise);
    const scheduler = createVaultSyncScheduler(harness.deps);

    const operation = scheduler.manual();
    await expect(scheduler.getSyncStatus()).resolves.toEqual({
      identity: 'account-a', dirty: true, syncing: true,
    });
    pending.resolve(undefined);
    await operation;
    await expect(scheduler.getSyncStatus()).resolves.toEqual({
      identity: 'account-a',
      lastSuccessfulSyncAt: 1_000,
      dirty: true,
      syncing: false,
    });
  });

  it('records attempts before completion and never turns a failure into success', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();

    harness.setNow(2_000);
    const failure = new Error('offline');
    harness.requestSync.mockRejectedValueOnce(failure);
    await expect(scheduler.manual()).rejects.toBe(failure);

    expect(harness.store.read()?.identities['account-a']).toEqual({
      lastAttempt: 2_000,
      lastSuccess: 1_000,
    });
  });

  it('advances lastSuccess strictly when two syncs finish in the same millisecond', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);

    await scheduler.manual();
    await scheduler.manual();

    expect(harness.store.read()?.identities['account-a']).toEqual({
      lastAttempt: 1_000,
      lastSuccess: 1_001,
    });
  });

  it('keeps successful freshness isolated across identity changes', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);
    await scheduler.manual();

    harness.setContext({ state: 'unlocked', identity: 'account-b' });
    harness.setNow(2_000);
    await scheduler.manual();
    expect(harness.store.read()?.identities).toEqual({
      'account-b': { lastAttempt: 2_000, lastSuccess: 2_000 },
      'account-a': { lastAttempt: 1_000, lastSuccess: 1_000 },
    });

    harness.requestSync.mockClear();
    harness.setContext({ state: 'unlocked', identity: 'account-a' });
    harness.setNow(1_000 + DEFAULT_POPUP_SYNC_STALE_MS - 1);
    await scheduler.popupOpened();
    expect(harness.requestSync).not.toHaveBeenCalled();

    harness.setContext({ state: 'unlocked', identity: 'account-c' });
    await scheduler.popupOpened();
    expect(harness.requestSync).toHaveBeenCalledWith('popup', 'coalesce');
  });

  it('attributes a delayed success to the identity that started it', async () => {
    const pending = deferred<void>();
    const started = deferred<void>();
    const harness = makeHarness();
    harness.requestSync.mockImplementationOnce(() => {
      started.resolve(undefined);
      return pending.promise;
    });
    const scheduler = createVaultSyncScheduler(harness.deps);

    const operation = scheduler.manual();
    await started.promise;
    harness.setContext({ state: 'unlocked', identity: 'account-b' });
    harness.setNow(2_000);
    pending.resolve(undefined);
    await operation;

    expect(harness.store.read()?.identities['account-a']).toEqual({
      lastAttempt: 1_000,
      lastSuccess: 2_000,
    });
    expect(harness.store.read()?.identities['account-b']).toBeUndefined();

    await scheduler.popupOpened();
    expect(harness.requestSync).toHaveBeenLastCalledWith('popup', 'coalesce');
  });

  it('retains at most 32 identities and evicts the least recently attempted', async () => {
    const harness = makeHarness();
    const scheduler = createVaultSyncScheduler(harness.deps);

    for (let index = 0; index < 33; index++) {
      harness.setContext({ state: 'unlocked', identity: `account-${index}` });
      harness.setNow(index + 1);
      await scheduler.manual();
    }

    const identities = harness.store.read()?.identities ?? {};
    expect(Object.keys(identities)).toHaveLength(32);
    expect(identities['account-0']).toBeUndefined();
    expect(identities['account-32']).toEqual({ lastAttempt: 33, lastSuccess: 33 });
  });

  it('reuses persisted freshness after a worker restart and restores a lost alarm', async () => {
    const harness = makeHarness();
    await createVaultSyncScheduler(harness.deps).manual();
    harness.requestSync.mockClear();

    const createAlarm = vi.fn();
    harness.deps.alarms = { get: async () => undefined, create: createAlarm };
    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS - 1);
    const restarted = createVaultSyncScheduler(harness.deps);
    await restarted.startup();

    expect(createAlarm).toHaveBeenCalledOnce();
    expect(harness.requestSync).not.toHaveBeenCalled();

    harness.setNow(1_000 + DEFAULT_VAULT_SYNC_STALE_MS);
    await restarted.handleAlarm(VAULT_SYNC_ALARM);
    expect(harness.requestSync).toHaveBeenCalledWith('alarm', 'coalesce');
  });
});
