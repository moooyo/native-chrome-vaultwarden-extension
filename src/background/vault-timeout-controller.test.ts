import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { createMemoryStore } from '../platform/store.js';
import {
  initializeVaultTimeoutAndReadFreshState,
  VaultTimeoutController,
  VAULT_TIMEOUT_ALARM,
  type VaultTimeoutContext,
} from './vault-timeout-controller.js';
import { recoverVaultTimeoutBrowserSession, VaultTimeoutStateStore } from './vault-timeout-state.js';
import type { EffectiveVaultTimeoutSettings } from './vault-timeout-policy.js';

const accountKey = 'https://vault.example/\na@example.com';
const numericConfig: EffectiveVaultTimeoutSettings = {
  lockTimeout: '1',
  onIdleAction: 'lock',
  idleSeconds: 60,
  lockOnSystemLock: false,
  logoutOnBrowserClose: false,
  closeLogoutActionProvenance: null,
  closeLogoutTimeoutProvenance: null,
  mode: 'local',
  managed: false,
  failClosed: false,
};

function harness(input: {
  now?: number;
  monotonicNow?: number;
  context?: VaultTimeoutContext;
  config?: EffectiveVaultTimeoutSettings;
  localStore?: ReturnType<typeof createMemoryStore>;
  sessionStore?: ReturnType<typeof createMemoryStore>;
} = {}) {
  let now = input.now ?? 1_000;
  let monotonicNow = input.monotonicNow ?? now;
  let context: VaultTimeoutContext = input.context ?? {
    state: 'unlocked', accountKey, email: 'a@example.com', sessionBindingId: 'binding-a',
  };
  let config = input.config ?? numericConfig;
  const localStore = input.localStore ?? createMemoryStore();
  const sessionStore = input.sessionStore ?? createMemoryStore();
  const state = new VaultTimeoutStateStore({ localStore, sessionStore, createId: () => 'browser-session' });
  const createAlarm = vi.fn();
  const clearAlarm = vi.fn(async () => true);
  const applyAction = vi.fn(async () => undefined);
  const reconcileTokenStorage = vi.fn(async () => undefined);
  const controller = new VaultTimeoutController({
    state,
    alarms: { create: createAlarm, clear: clearAlarm },
    getContext: async () => context,
    getConfig: async () => config,
    reconcileTokenStorage,
    applyAction,
    now: () => now,
    monotonicNow: () => monotonicNow,
  });
  return {
    controller, state, localStore, sessionStore, createAlarm, clearAlarm, applyAction,
    reconcileTokenStorage,
    setNow: (value: number) => { now = value; },
    setMonotonicNow: (value: number) => { monotonicNow = value; },
    setContext: (value: VaultTimeoutContext) => { context = value; },
    setConfig: (value: EffectiveVaultTimeoutSettings) => { config = value; },
  };
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

describe('VaultTimeoutController', () => {
  it('reads fresh auth state after startup timeout hydration completes', async () => {
    let state: 'unlocked' | 'locked' = 'unlocked';
    const initialize = vi.fn(async () => { state = 'locked'; });
    const getState = vi.fn(async () => state);

    await expect(initializeVaultTimeoutAndReadFreshState({ initialize }, getState))
      .resolves.toBe('locked');
    expect(initialize).toHaveBeenCalledOnce();
    expect(getState).toHaveBeenCalledOnce();
  });

  it('reconciles token storage from the effective timeout action before arming enforcement', async () => {
    const h = harness({
      config: {
        ...numericConfig,
        onIdleAction: 'logout',
        logoutOnBrowserClose: true,
        closeLogoutActionProvenance: 'local',
        closeLogoutTimeoutProvenance: 'local',
      },
    });
    await h.state.initializeBrowserSession();

    await h.controller.initialize();

    expect(h.reconcileTokenStorage).toHaveBeenCalledWith({
      accountKey,
      email: 'a@example.com',
      sessionBindingId: 'binding-a',
    }, 'session', 'localLogout');
    expect(await h.localStore.get<{ owners: Record<string, unknown> }>('vaultTimeoutCloseLogout'))
      .toMatchObject({ owners: { [accountKey]: expect.any(Object) } });
  });

  it('uses an absolute activity deadline and synchronously blocks delayed secret entry', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    expect(h.createAlarm).toHaveBeenLastCalledWith(VAULT_TIMEOUT_ALARM, { when: 61_000 });

    h.setNow(60_999);
    expect(() => h.controller.preflight()).not.toThrow();
    h.setNow(61_000);
    expect(() => h.controller.preflight()).toThrow('Vault session timed out');
    await h.controller.settlePendingAction();
    expect(h.applyAction).toHaveBeenCalledWith({
      accountKey, email: 'a@example.com', sessionBindingId: 'binding-a',
    }, 'lock');
  });

  it('keeps an alarm event alive until one concurrent timeout action completes and clears recovery', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const action = deferred();
    h.applyAction.mockImplementationOnce(async () => {
      await action.promise;
      return undefined;
    });
    h.setNow(61_000);
    h.setMonotonicNow(61_000);

    const alarm = h.controller.handleAlarm(VAULT_TIMEOUT_ALARM);
    await vi.waitFor(() => expect(h.applyAction).toHaveBeenCalledOnce());
    expect(() => h.controller.preflight()).toThrow('Vault session timed out');
    expect(() => h.controller.preflight()).toThrow('Vault session timed out');
    let completed = false;
    void alarm.finally(() => { completed = true; });
    await Promise.resolve();
    expect(completed).toBe(false);
    expect(h.applyAction).toHaveBeenCalledOnce();

    action.resolve();
    await expect(alarm).resolves.toBeUndefined();
    await expect(h.localStore.get('vaultTimeoutBrowserSessionRecovery')).resolves.toBeUndefined();
  });

  it('retains durable reset recovery when a normal timeout action fails', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    h.applyAction.mockRejectedValueOnce(new Error('lock unavailable'));
    h.setNow(61_000);
    h.setMonotonicNow(61_000);

    await expect(h.controller.handleAlarm(VAULT_TIMEOUT_ALARM)).resolves.toBeUndefined();
    await expect(h.localStore.get('vaultTimeoutBrowserSessionRecovery')).resolves.toEqual({
      schemaVersion: 1,
      kind: 'resetAll',
    });
  });

  it('does not deadlock when a timeout action settles its own session transition', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    h.applyAction.mockImplementationOnce(async () => {
      h.controller.transitionStarted();
      h.setContext({ state: 'locked', accountKey, email: 'a@example.com', sessionBindingId: 'binding-a' });
      await h.controller.transitionSettled(true, 'locked');
    });
    h.setNow(61_000);
    h.setMonotonicNow(61_000);

    await expect(h.controller.handleAlarm(VAULT_TIMEOUT_ALARM)).resolves.toBeUndefined();
    expect(h.applyAction).toHaveBeenCalledOnce();
    await expect(h.localStore.get('vaultTimeoutBrowserSessionRecovery')).resolves.toBeUndefined();
  });

  it('awaits the terminal action when alarm observation persistence throws', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    vi.spyOn(h.sessionStore, 'set').mockRejectedValueOnce(new Error('observation unavailable'));
    const action = deferred();
    h.applyAction.mockImplementationOnce(async () => {
      await action.promise;
      return undefined;
    });
    h.setNow(2_000);
    h.setMonotonicNow(2_000);

    const alarm = h.controller.handleAlarm(VAULT_TIMEOUT_ALARM);
    await vi.waitFor(() => expect(h.applyAction).toHaveBeenCalledOnce());
    let completed = false;
    void alarm.finally(() => { completed = true; }).catch(() => undefined);
    await Promise.resolve();
    expect(completed).toBe(false);

    action.resolve();
    await expect(alarm).rejects.toThrow('observation unavailable');
  });

  it('does not extend the deadline when an MV3 worker hydrates the same session activity', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const first = harness({ now: 1_000, localStore, sessionStore });
    await first.state.initializeBrowserSession();
    await first.controller.initialize();
    const lease = first.controller.captureActivity();
    first.setNow(5_000);
    await first.controller.recordActivity(lease);

    const restarted = harness({ now: 20_000, localStore, sessionStore });
    await restarted.state.initializeBrowserSession();
    await restarted.controller.initialize();
    expect(restarted.createAlarm).toHaveBeenLastCalledWith(VAULT_TIMEOUT_ALARM, { when: 65_000 });
  });

  it('detects an A-H-R rollback across two MV3 worker restarts using the durable observation high-water', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const active = harness({ now: 1_000, localStore, sessionStore });
    await active.state.initializeBrowserSession();
    await active.controller.initialize();
    const lease = active.controller.captureActivity();
    active.setNow(2_000);
    await active.controller.recordActivity(lease);

    const hydrated = harness({ now: 5_000, localStore, sessionStore });
    await hydrated.state.initializeBrowserSession();
    await hydrated.controller.initialize();
    await expect(hydrated.state.getActivity()).resolves.toMatchObject({
      lastVaultActivityAt: 2_000,
      lastObservedAt: 5_000,
    });
    expect(hydrated.createAlarm).toHaveBeenLastCalledWith(VAULT_TIMEOUT_ALARM, { when: 62_000 });

    const rolledBack = harness({ now: 3_000, localStore, sessionStore });
    await rolledBack.state.initializeBrowserSession();
    await rolledBack.controller.initialize();

    expect(() => rolledBack.controller.preflight()).toThrow('Vault session timed out');
    await rolledBack.controller.settlePendingAction();
    expect(rolledBack.applyAction).toHaveBeenCalledOnce();
  });

  it('does not raise the durable wall-clock high-water during synchronous preflight', async () => {
    const h = harness({ now: 10_000 });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    h.setNow(20_000);
    expect(() => h.controller.preflight()).not.toThrow();

    h.setNow(15_000);
    expect(() => h.controller.preflight()).not.toThrow();
    h.setNow(9_000);
    expect(() => h.controller.preflight()).toThrow('Vault session timed out');
    await h.controller.settlePendingAction();
    expect(h.applyAction).toHaveBeenCalledOnce();
  });

  it('persists a release observation and does not sample a later wall clock in final proof assertion', async () => {
    const h = harness({ now: 1_000 });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const lease = h.controller.captureRelease();
    h.setNow(2_000);
    const proof = await h.controller.checkpointRelease(lease);
    await expect(h.state.getActivity()).resolves.toMatchObject({
      lastVaultActivityAt: 1_000,
      lastObservedAt: 2_000,
    });

    h.controller.assertRelease(proof);
    h.setNow(2_500);

    expect(() => h.controller.preflight()).not.toThrow();
  });

  it.each(['deadline', 'rollback'] as const)(
    'rejects a release when storage latency crosses a wall-clock %s',
    async (caseName) => {
      const h = harness({ now: caseName === 'deadline' ? 2_000 : 5_000 });
      await h.state.initializeBrowserSession();
      await h.controller.initialize();
      const lease = h.controller.captureRelease();
      const pending = deferred();
      vi.spyOn(h.state, 'setActivity').mockImplementationOnce(() => pending.promise);
      const checkpoint = h.controller.checkpointRelease(lease);
      await vi.waitFor(() => expect(h.state.setActivity).toHaveBeenCalled());
      if (caseName === 'deadline') {
        h.setNow(62_000);
        h.setMonotonicNow(62_000);
      } else {
        h.setNow(4_000);
        h.setMonotonicNow(6_000);
      }
      pending.resolve();

      await expect(checkpoint).rejects.toThrow('Vault session timed out');
      expect(() => h.controller.preflight()).toThrow('Vault session timed out');
    },
  );

  it('rejects a release when monotonic elapsed time crosses the deadline during storage', async () => {
    const h = harness({ now: 2_000, monotonicNow: 2_000 });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const lease = h.controller.captureRelease();
    const pending = deferred();
    vi.spyOn(h.state, 'setActivity').mockImplementationOnce(() => pending.promise);
    const checkpoint = h.controller.checkpointRelease(lease);
    await vi.waitFor(() => expect(h.state.setActivity).toHaveBeenCalled());
    h.setMonotonicNow(62_000);
    pending.resolve();

    await expect(checkpoint).rejects.toThrow('Vault session timed out');
  });

  it('binds a one-shot proof to the monotonic deadline', async () => {
    const h = harness({ now: 1_000, monotonicNow: 1_000 });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const lease = h.controller.captureRelease();
    h.setNow(2_000);
    h.setMonotonicNow(2_000);
    const proof = await h.controller.checkpointRelease(lease);
    h.setMonotonicNow(61_000);

    expect(() => h.controller.assertRelease(proof)).toThrow('Vault release proof is stale');
    await h.controller.settlePendingAction();
    expect(h.applyAction).toHaveBeenCalledOnce();
  });

  it('blocks a page-load-style release after P-kill-R rollback in the next worker', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const releasingWorker = harness({ now: 1_000, localStore, sessionStore });
    await releasingWorker.state.initializeBrowserSession();
    await releasingWorker.controller.initialize();
    const lease = releasingWorker.controller.captureRelease();
    releasingWorker.setNow(5_000);
    const proof = await releasingWorker.controller.checkpointRelease(lease);
    releasingWorker.controller.assertRelease(proof);

    const restartedWorker = harness({ now: 3_000, localStore, sessionStore });
    await restartedWorker.state.initializeBrowserSession();
    await restartedWorker.controller.initialize();

    expect(() => restartedWorker.controller.preflight()).toThrow('Vault session timed out');
    await restartedWorker.controller.settlePendingAction();
    expect(restartedWorker.applyAction).toHaveBeenCalledOnce();
  });

  it('persists an early alarm observation before rescheduling', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const first = harness({ now: 1_000, localStore, sessionStore });
    await first.state.initializeBrowserSession();
    await first.controller.initialize();
    first.setNow(5_000);
    await first.controller.handleAlarm(VAULT_TIMEOUT_ALARM);
    await expect(first.state.getActivity()).resolves.toMatchObject({
      lastVaultActivityAt: 1_000,
      lastObservedAt: 5_000,
    });

    const rolledBack = harness({ now: 4_000, localStore, sessionStore });
    await rolledBack.state.initializeBrowserSession();
    await rolledBack.controller.initialize();
    expect(() => rolledBack.controller.preflight()).toThrow('Vault session timed out');
  });

  it.each(['activity', 'alarm'] as const)(
    'fails closed when the %s observation checkpoint cannot be persisted',
    async (entry) => {
      const h = harness({ now: 1_000 });
      await h.state.initializeBrowserSession();
      await h.controller.initialize();
      const lease = h.controller.captureActivity();
      vi.spyOn(h.sessionStore, 'set').mockRejectedValueOnce(new Error('storage unavailable'));
      h.setNow(2_000);

      if (entry === 'activity') await h.controller.recordActivity(lease);
      else await expect(h.controller.handleAlarm(VAULT_TIMEOUT_ALARM)).rejects.toThrow('storage unavailable');

      expect(() => h.controller.preflight()).toThrow('Vault session timed out');
      await h.controller.settlePendingAction();
      expect(h.applyAction).toHaveBeenCalledOnce();
    },
  );

  it('seeds a fresh activity record for a new session binding', async () => {
    const h = harness({ now: 10_000 });
    await h.state.initializeBrowserSession();
    await h.state.setActivity({
      accountKey,
      email: 'a@example.com',
      sessionBindingId: 'old',
      lastVaultActivityAt: 1_000,
      lastObservedAt: 1_000,
    });
    await h.controller.initialize();
    await expect(h.state.getActivity()).resolves.toMatchObject({
      sessionBindingId: 'binding-a', lastVaultActivityAt: 10_000,
    });
  });

  it('rejects stale activity after an A-B-A session transition', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const stale = h.controller.captureActivity();
    h.controller.transitionStarted();
    h.setNow(2_000);
    h.setContext({ state: 'unlocked', accountKey, email: 'a@example.com', sessionBindingId: 'binding-b' });
    await h.controller.transitionSettled(true, 'unlocked');
    await h.controller.recordActivity(stale);
    await expect(h.state.getActivity()).resolves.toMatchObject({
      sessionBindingId: 'binding-b', lastVaultActivityAt: 2_000,
    });
  });

  it('rehydrates after a failed transition without resetting the prior activity', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const before = await h.state.getActivity();
    h.controller.transitionStarted();
    h.setNow(20_000);
    await h.controller.transitionSettled(false, 'unlocked');

    await expect(h.state.getActivity()).resolves.toMatchObject({
      lastVaultActivityAt: before?.lastVaultActivityAt,
      lastObservedAt: 20_000,
    });
    expect(() => h.controller.preflight()).not.toThrow();
  });

  it('arms close/logout for the exact account owner without depending on rotating tokens', async () => {
    const localStore = createMemoryStore();
    const h = harness({
      localStore,
      config: {
        ...numericConfig,
        lockTimeout: 'onClose',
        onIdleAction: 'logout',
        idleSeconds: null,
        logoutOnBrowserClose: true,
        closeLogoutActionProvenance: 'local',
        closeLogoutTimeoutProvenance: 'local',
      },
    });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'next-browser-session',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [{
        accountKey,
        email: 'a@example.com',
        actionProvenance: 'local',
        timeoutProvenance: 'local',
      }],
    });
  });

  it('treats a future activity timestamp as expired instead of extending the session', async () => {
    const h = harness({ now: 10_000 });
    await h.state.initializeBrowserSession();
    await h.state.setActivity({
      accountKey,
      email: 'a@example.com',
      sessionBindingId: 'binding-a',
      lastVaultActivityAt: 20_000,
      lastObservedAt: 20_000,
    });
    await h.controller.initialize();
    expect(() => h.controller.preflight()).toThrow('Vault session timed out');
    await h.controller.settlePendingAction();
    expect(h.applyAction).toHaveBeenCalledOnce();
  });

  it.each(['preflight', 'activity', 'alarm'] as const)(
    'fails closed on clock rollback during %s',
    async (entry) => {
      const h = harness({ now: 10_000 });
      await h.state.initializeBrowserSession();
      await h.controller.initialize();
      const lease = h.controller.captureActivity();
      h.setNow(9_999);

      if (entry === 'preflight') {
        expect(() => h.controller.preflight()).toThrow('Vault session timed out');
      } else if (entry === 'activity') {
        await h.controller.recordActivity(lease);
      } else {
        await h.controller.handleAlarm(VAULT_TIMEOUT_ALARM);
      }

      expect(() => h.controller.preflight()).toThrow('Vault session timed out');
      await h.controller.settlePendingAction();
      expect(h.applyAction).toHaveBeenCalledOnce();
    },
  );

  it('preserves inactive close/logout owners during ordinary reconfiguration', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const h = harness({
      localStore,
      sessionStore,
      config: {
        ...numericConfig,
        onIdleAction: 'logout',
        logoutOnBrowserClose: true,
        closeLogoutActionProvenance: 'local',
        closeLogoutTimeoutProvenance: 'local',
      },
    });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const inactive = {
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy',
      timeoutProvenance: 'policy',
    } as const;
    await h.state.armCloseLogout(inactive);
    h.setConfig(numericConfig);

    await h.controller.reconfigure();

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'next-browser-session',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [inactive],
    });
  });

  it('clears local owners after a persisted setting change without dropping an inactive policy owner', async () => {
    const localStore = createMemoryStore();
    const h = harness({
      localStore,
      config: {
        ...numericConfig,
        onIdleAction: 'logout',
        logoutOnBrowserClose: true,
        closeLogoutActionProvenance: 'local',
        closeLogoutTimeoutProvenance: 'local',
      },
    });
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    const policyOwner = {
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'local',
      timeoutProvenance: 'policy',
    } as const;
    await h.state.armCloseLogout(policyOwner);
    h.setConfig(numericConfig);

    await h.controller.reconfigure({ clearLocalTimeoutOwners: true });

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'next-browser-session',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [policyOwner],
    });
  });

  it('uses system locked only when the effective policy explicitly enables it', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    await h.controller.handleSystemLocked();
    expect(h.applyAction).not.toHaveBeenCalled();

    h.setConfig({ ...numericConfig, idleSeconds: null, lockOnSystemLock: true, mode: 'systemLock' });
    await h.controller.reconfigure();
    await h.controller.handleSystemLocked();
    expect(h.applyAction).toHaveBeenCalledOnce();
  });

  it.each(['state', 'alarm'] as const)(
    'fails closed when %s reconfiguration fails and permits an explicit retry',
    async (failure) => {
      const h = harness();
      await h.state.initializeBrowserSession();
      await h.controller.initialize();
      const options = failure === 'state' ? { clearLocalActionOwners: true } : {};
      if (failure === 'state') {
        vi.spyOn(h.state, 'clearCloseLogoutProvenance')
          .mockRejectedValueOnce(new Error('state unavailable'));
      } else {
        h.createAlarm.mockRejectedValueOnce(new Error('alarm unavailable'));
      }
      let actionCompleted = false;
      h.applyAction.mockImplementationOnce(async () => {
        await Promise.resolve();
        actionCompleted = true;
      });

      await expect(h.controller.reconfigure(options)).rejects.toThrow(`${failure} unavailable`);
      expect(h.controller.needsReconfigure()).toBe(true);
      expect(() => h.controller.preflight()).toThrow('Vault timeout state is unavailable');
      expect(actionCompleted).toBe(true);
      expect(h.applyAction).toHaveBeenCalledWith({
        accountKey,
        email: 'a@example.com',
        sessionBindingId: 'binding-a',
      }, 'logout');

      await expect(h.controller.reconfigure(options)).resolves.toBeUndefined();
      expect(h.controller.needsReconfigure()).toBe(false);
      expect(() => h.controller.preflight()).not.toThrow();
    },
  );

  it('awaits fail-closed logout using the new transition context before a run exists', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    h.controller.transitionStarted();
    h.setContext({
      state: 'unlocked',
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      sessionBindingId: 'binding-b',
    });
    vi.spyOn(h.state, 'getActivity').mockRejectedValueOnce(new Error('activity unavailable'));
    const terminal = deferred();
    h.applyAction.mockImplementationOnce(async () => {
      await terminal.promise;
      return undefined;
    });

    const settled = h.controller.transitionSettled(true, 'unlocked');
    await vi.waitFor(() => expect(h.applyAction).toHaveBeenCalledWith({
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      sessionBindingId: 'binding-b',
    }, 'logout'));
    let completed = false;
    void settled.finally(() => { completed = true; }).catch(() => undefined);
    await Promise.resolve();
    expect(completed).toBe(false);

    terminal.resolve();
    await expect(settled).rejects.toThrow('activity unavailable');
  });

  it('leaves durable reset-all recovery when terminal logout fails', async () => {
    const h = harness();
    await h.state.initializeBrowserSession();
    await h.controller.initialize();
    h.createAlarm.mockRejectedValueOnce(new Error('alarm unavailable'));
    h.applyAction.mockRejectedValueOnce(new Error('logout unavailable'));

    await expect(h.controller.reconfigure()).rejects.toThrow('alarm unavailable');
    await expect(h.localStore.get('vaultTimeoutBrowserSessionRecovery')).resolves.toEqual({
      schemaVersion: 1,
      kind: 'resetAll',
    });

    const resetAllAccounts = vi.fn(async () => undefined);
    const restarted = new VaultTimeoutStateStore({
      localStore: h.localStore,
      sessionStore: h.sessionStore,
      createId: () => 'restarted-session',
    });
    await expect(recoverVaultTimeoutBrowserSession(restarted, {
      getServerUrl: vi.fn(async () => undefined),
      listAccountEmails: vi.fn(async () => []),
      removeAccount: vi.fn(async () => undefined),
      resetAllAccounts,
      clearDerivedState: vi.fn(async () => undefined),
    })).resolves.toBe(true);
    expect(resetAllAccounts).toHaveBeenCalledOnce();
  });
});
