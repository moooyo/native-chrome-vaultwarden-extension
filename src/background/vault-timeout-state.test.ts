import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { createMemoryStore } from '../platform/store.js';
import { recoverVaultTimeoutBrowserSession, VaultTimeoutStateStore } from './vault-timeout-state.js';

const owner = {
  accountKey: 'https://vault.example/\na@example.com',
  email: 'a@example.com',
  actionProvenance: 'local' as const,
  timeoutProvenance: 'local' as const,
};

describe('VaultTimeoutStateStore', () => {
  it('distinguishes a worker restart from a new browser session', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const first = new VaultTimeoutStateStore({ localStore, sessionStore, createId: () => 'session-a' });
    await expect(first.initializeBrowserSession()).resolves.toEqual({ kind: 'continued' });
    await first.armCloseLogout(owner);

    const workerRestart = new VaultTimeoutStateStore({ localStore, sessionStore, createId: () => 'unused' });
    await expect(workerRestart.initializeBrowserSession()).resolves.toEqual({ kind: 'continued' });

    const browserRestart = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-b',
    });
    await expect(browserRestart.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [owner],
    });
  });

  it('keeps close/logout intent stable across token rotation because it binds the account owner', async () => {
    const localStore = createMemoryStore();
    const state = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-a',
    });
    await state.initializeBrowserSession();
    await state.armCloseLogout(owner);

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-b',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toMatchObject({
      kind: 'expired',
      owners: [owner],
    });
  });

  it('retains multiple exact account owners and disarms only the requested owner', async () => {
    const localStore = createMemoryStore();
    const state = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-a',
    });
    await state.initializeBrowserSession();
    await state.armCloseLogout(owner);
    await state.armCloseLogout({
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy',
      timeoutProvenance: 'policy',
    });
    await state.disarmCloseLogout(owner.accountKey);

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-b',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [{
        accountKey: 'https://vault.example/\nb@example.com',
        email: 'b@example.com',
        actionProvenance: 'policy',
        timeoutProvenance: 'policy',
      }],
    });
  });

  it('arms every logged-in account for a newly enabled global local close/logout setting', async () => {
    const localStore = createMemoryStore();
    const firstSession = createMemoryStore();
    const state = new VaultTimeoutStateStore({
      localStore, sessionStore: firstSession, createId: () => 'session-a',
    });
    await state.initializeBrowserSession();
    await state.reconcileLocalCloseLogoutOwners({
      serverUrl: 'https://vault.example/',
      emails: ['a@example.com', 'b@example.com'],
      enabled: true,
    });
    const removeAccount = vi.fn(async () => undefined);
    const restarted = new VaultTimeoutStateStore({
      localStore, sessionStore: createMemoryStore(), createId: () => 'session-b',
    });

    await expect(recoverVaultTimeoutBrowserSession(restarted, {
      getServerUrl: async () => 'https://vault.example/',
      listAccountEmails: async () => ['a@example.com', 'b@example.com'],
      removeAccount,
      resetAllAccounts: vi.fn(async () => undefined),
      clearDerivedState: vi.fn(async () => undefined),
    })).resolves.toBe(true);
    expect(removeAccount).toHaveBeenCalledTimes(2);
    expect(removeAccount).toHaveBeenCalledWith('a@example.com');
    expect(removeAccount).toHaveBeenCalledWith('b@example.com');
  });

  it('does not overwrite another account policy owner and prunes accounts after removal', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const state = new VaultTimeoutStateStore({
      localStore, sessionStore, createId: () => 'session-a',
    });
    await state.initializeBrowserSession();
    const policyOwner = {
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy' as const,
      timeoutProvenance: 'policy' as const,
    };
    await state.armCloseLogout(policyOwner);
    await state.reconcileLocalCloseLogoutOwners({
      serverUrl: 'https://vault.example/',
      emails: ['a@example.com', 'b@example.com'],
      enabled: true,
    });
    await state.reconcileLocalCloseLogoutOwners({
      serverUrl: 'https://vault.example/',
      emails: ['b@example.com'],
      enabled: false,
    });

    const restarted = new VaultTimeoutStateStore({
      localStore, sessionStore: createMemoryStore(), createId: () => 'session-b',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [policyOwner],
    });
  });

  it.each(['get', 'set'] as const)(
    'surfaces a local owner reconcile storage %s failure and permits a retry',
    async (stage) => {
      const backing = createMemoryStore();
      let fail = false;
      const localStore = {
        ...backing,
        async get<T>(key: string): Promise<T | undefined> {
          if (fail && stage === 'get' && key === 'vaultTimeoutCloseLogout') {
            throw new Error('owner get failed');
          }
          return backing.get<T>(key);
        },
        async set(key: string, value: unknown): Promise<void> {
          if (fail && stage === 'set' && key === 'vaultTimeoutCloseLogout') {
            throw new Error('owner set failed');
          }
          await backing.set(key, value);
        },
      };
      const state = new VaultTimeoutStateStore({
        localStore, sessionStore: createMemoryStore(), createId: () => 'session-a',
      });
      await state.initializeBrowserSession();
      fail = true;
      const reconcile = () => state.reconcileLocalCloseLogoutOwners({
        serverUrl: 'https://vault.example/',
        emails: ['a@example.com'],
        enabled: true,
      });

      await expect(reconcile()).rejects.toThrow(`owner ${stage} failed`);
      fail = false;
      await expect(reconcile()).resolves.toBeUndefined();

      const restarted = new VaultTimeoutStateStore({
        localStore, sessionStore: createMemoryStore(), createId: () => 'session-b',
      });
      await expect(restarted.initializeBrowserSession()).resolves.toMatchObject({
        kind: 'expired',
        owners: [owner],
      });
    },
  );

  it('clears only local owners while preserving policy, fail-closed, and unknown accounts', async () => {
    const localStore = createMemoryStore();
    const state = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-a',
    });
    await state.initializeBrowserSession();
    const policyOwner = {
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'local' as const,
      timeoutProvenance: 'policy' as const,
    };
    const failClosedOwner = {
      accountKey: 'https://vault.example/\nc@example.com',
      email: 'c@example.com',
      actionProvenance: 'fail_closed' as const,
      timeoutProvenance: 'fail_closed' as const,
    };
    const unknownOwner = {
      accountKey: 'https://vault.example/\nd@example.com',
      email: 'd@example.com',
      actionProvenance: 'unknown' as const,
      timeoutProvenance: 'unknown' as const,
    };
    await state.armCloseLogout(owner);
    await state.armCloseLogout(policyOwner);
    await state.armCloseLogout(failClosedOwner);
    await state.armCloseLogout(unknownOwner);

    await state.clearCloseLogoutProvenance({ timeout: 'local' });

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-b',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [policyOwner, failClosedOwner, unknownOwner],
    });
  });

  it('filters local action provenance independently from timeout provenance', async () => {
    const localStore = createMemoryStore();
    const state = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-a',
    });
    await state.initializeBrowserSession();
    const policyActionOwner = {
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy' as const,
      timeoutProvenance: 'local' as const,
    };
    await state.armCloseLogout(owner);
    await state.armCloseLogout(policyActionOwner);

    await state.clearCloseLogoutProvenance({ action: 'local' });

    const restarted = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-b',
    });
    await expect(restarted.initializeBrowserSession()).resolves.toEqual({
      kind: 'expired',
      owners: [policyActionOwner],
    });
  });

  it('strictly migrates legacy owners to unknown provenance before the next write', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    await sessionStore.set('vaultTimeoutBrowserSession', { schemaVersion: 1, id: 'session-a' });
    await localStore.set('vaultTimeoutCloseLogout', {
      schemaVersion: 1,
      browserSessionId: 'session-a',
      owners: {
        [owner.accountKey]: { accountKey: owner.accountKey, email: owner.email },
      },
    });
    const state = new VaultTimeoutStateStore({ localStore, sessionStore });
    await expect(state.initializeBrowserSession()).resolves.toEqual({ kind: 'continued' });

    await state.armCloseLogout({
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy',
      timeoutProvenance: 'policy',
    });

    await expect(localStore.get('vaultTimeoutCloseLogout')).resolves.toEqual({
      schemaVersion: 3,
      browserSessionId: 'session-a',
      owners: {
        [owner.accountKey]: {
          accountKey: owner.accountKey,
          email: owner.email,
          actionProvenance: 'unknown',
          timeoutProvenance: 'unknown',
        },
        'https://vault.example/\nb@example.com': {
          accountKey: 'https://vault.example/\nb@example.com',
          email: 'b@example.com',
          actionProvenance: 'policy',
          timeoutProvenance: 'policy',
        },
      },
    });
  });

  it('strictly migrates old schema-v2 provenance to two unknown dimensions', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    await sessionStore.set('vaultTimeoutBrowserSession', { schemaVersion: 1, id: 'session-a' });
    await localStore.set('vaultTimeoutCloseLogout', {
      schemaVersion: 2,
      browserSessionId: 'session-a',
      owners: {
        [owner.accountKey]: {
          accountKey: owner.accountKey,
          email: owner.email,
          provenance: 'local',
        },
      },
    });
    const state = new VaultTimeoutStateStore({ localStore, sessionStore });
    await expect(state.initializeBrowserSession()).resolves.toEqual({ kind: 'continued' });

    await state.armCloseLogout({
      accountKey: 'https://vault.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy',
      timeoutProvenance: 'policy',
    });

    const stored = await localStore.get<{ owners: Record<string, unknown> }>('vaultTimeoutCloseLogout');
    expect(stored?.owners[owner.accountKey]).toEqual({
      accountKey: owner.accountKey,
      email: owner.email,
      actionProvenance: 'unknown',
      timeoutProvenance: 'unknown',
    });
  });

  it('fails closed for malformed durable close/logout state', async () => {
    const localStore = createMemoryStore();
    await localStore.set('vaultTimeoutCloseLogout', { malformed: true });
    const state = new VaultTimeoutStateStore({
      localStore,
      sessionStore: createMemoryStore(),
      createId: () => 'session-a',
    });
    await expect(state.initializeBrowserSession()).resolves.toEqual({ kind: 'corrupt' });
  });

  it.each(['reset', 'derived cleanup', 'recovery commit'] as const)(
    'keeps corrupt-session recovery pending when %s is interrupted and retries after worker restart',
    async (failureStage) => {
      const localBacking = createMemoryStore();
      let commitInterrupted = false;
      const localStore = {
        ...localBacking,
        async remove(key: string): Promise<void> {
          if (failureStage === 'recovery commit'
              && key === 'vaultTimeoutBrowserSessionRecovery'
              && !commitInterrupted) {
            commitInterrupted = true;
            throw new Error('recovery commit interrupted');
          }
          await localBacking.remove(key);
        },
      };
      const sessionStore = createMemoryStore();
      await sessionStore.set('vaultTimeoutBrowserSession', { malformed: true });
      const resetAllAccounts = vi.fn(async () => {
        if (failureStage === 'reset' && resetAllAccounts.mock.calls.length === 1) {
          throw new Error('reset interrupted');
        }
      });
      const clearDerivedState = vi.fn(async () => {
        if (failureStage === 'derived cleanup' && clearDerivedState.mock.calls.length === 1) {
          throw new Error('cleanup interrupted');
        }
      });
      const recover = (state: VaultTimeoutStateStore) => recoverVaultTimeoutBrowserSession(state, {
        getServerUrl: vi.fn(async () => undefined),
        listAccountEmails: vi.fn(async () => []),
        removeAccount: vi.fn(async () => undefined),
        resetAllAccounts,
        clearDerivedState,
      });
      const first = new VaultTimeoutStateStore({
        localStore, sessionStore, createId: () => 'repaired-session',
      });

      await expect(recover(first)).rejects.toThrow('interrupted');
      await expect(localStore.get('vaultTimeoutBrowserSessionRecovery')).resolves.toEqual({
        schemaVersion: 1,
        kind: 'resetAll',
      });

      const restartedWorker = new VaultTimeoutStateStore({ localStore, sessionStore });
      await expect(recover(restartedWorker)).resolves.toBe(true);
      expect(resetAllAccounts).toHaveBeenCalledTimes(2);
      await expect(localStore.get('vaultTimeoutBrowserSessionRecovery')).resolves.toBeUndefined();
      const settledWorker = new VaultTimeoutStateStore({ localStore, sessionStore });
      await expect(settledWorker.initializeBrowserSession()).resolves.toEqual({ kind: 'continued' });
    },
  );

  it('round-trips only strictly validated session activity', async () => {
    const sessionStore = createMemoryStore();
    const state = new VaultTimeoutStateStore({ localStore: createMemoryStore(), sessionStore });
    const activity = {
      accountKey: owner.accountKey,
      email: owner.email,
      sessionBindingId: 'binding-a',
      lastVaultActivityAt: 123,
      lastObservedAt: 456,
    };
    await state.setActivity(activity);
    await expect(state.getActivity()).resolves.toEqual({ schemaVersion: 2, ...activity });
    await sessionStore.set('vaultTimeoutActivity', {
      schemaVersion: 1,
      accountKey: owner.accountKey,
      email: owner.email,
      sessionBindingId: 'binding-a',
      lastVaultActivityAt: 123,
    });
    await expect(state.getActivity()).resolves.toEqual({
      schemaVersion: 2,
      accountKey: owner.accountKey,
      email: owner.email,
      sessionBindingId: 'binding-a',
      lastVaultActivityAt: 123,
      lastObservedAt: 123,
    });
    await sessionStore.set('vaultTimeoutActivity', {
      ...activity,
      schemaVersion: 2,
      lastObservedAt: 122,
    });
    await expect(state.getActivity()).rejects.toThrow('Invalid vault timeout activity state');
    await sessionStore.set('vaultTimeoutActivity', { ...activity, schemaVersion: 3 });
    await expect(state.getActivity()).rejects.toThrow('Invalid vault timeout activity state');
  });

  it('removes only matching account owners before admitting a new browser session', async () => {
    const localStore = createMemoryStore();
    const first = new VaultTimeoutStateStore({
      localStore, sessionStore: createMemoryStore(), createId: () => 'session-a',
    });
    await first.initializeBrowserSession();
    await first.armCloseLogout(owner);
    await first.armCloseLogout({
      accountKey: 'https://other.example/\nb@example.com',
      email: 'b@example.com',
      actionProvenance: 'policy',
      timeoutProvenance: 'policy',
    });
    const removeAccount = vi.fn(async () => undefined);
    const clearDerivedState = vi.fn(async () => undefined);
    const restarted = new VaultTimeoutStateStore({
      localStore, sessionStore: createMemoryStore(), createId: () => 'session-b',
    });

    await expect(recoverVaultTimeoutBrowserSession(restarted, {
      getServerUrl: async () => 'https://vault.example/',
      listAccountEmails: async () => ['a@example.com', 'b@example.com'],
      removeAccount,
      resetAllAccounts: vi.fn(async () => undefined),
      clearDerivedState,
    })).resolves.toBe(true);
    expect(removeAccount).toHaveBeenCalledExactlyOnceWith('a@example.com');
    expect(clearDerivedState).toHaveBeenCalledOnce();
  });

  it('keeps the owner marker when startup account removal fails so the next start retries', async () => {
    const localStore = createMemoryStore();
    const first = new VaultTimeoutStateStore({
      localStore, sessionStore: createMemoryStore(), createId: () => 'session-a',
    });
    await first.initializeBrowserSession();
    await first.armCloseLogout(owner);
    const restartedSession = createMemoryStore();
    const restarted = new VaultTimeoutStateStore({
      localStore, sessionStore: restartedSession, createId: () => 'session-b',
    });
    await expect(recoverVaultTimeoutBrowserSession(restarted, {
      getServerUrl: async () => 'https://vault.example/',
      listAccountEmails: async () => ['a@example.com'],
      removeAccount: async () => { throw new Error('storage failed'); },
      resetAllAccounts: vi.fn(async () => undefined),
      clearDerivedState: vi.fn(async () => undefined),
    })).rejects.toThrow('storage failed');

    const retry = new VaultTimeoutStateStore({ localStore, sessionStore: restartedSession });
    await expect(retry.initializeBrowserSession()).resolves.toMatchObject({ kind: 'expired', owners: [owner] });
  });
});
