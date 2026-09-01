import { describe, expect, it, vi } from 'vitest';
import type { ServerConfigResponse } from '../core/api/client.js';
import type { AccountLease, ServerLease } from '../core/session/account-gate.js';
import {
  ServerCapabilityManager,
} from './server-capability-manager.js';
import {
  PRODUCTION_SERVER_CAPABILITY_DECLARATION,
  fetchFixedServerConfig,
} from './server-capability-production.js';
import { VAULT_NOTIFICATION_TYPE } from './vault-notification-lifecycle.js';
import {
  VAULT_NOTIFICATIONS_RECONNECT_ALARM,
  type NotificationsConnectionOptions,
  type NotificationsHubConnection,
} from './vault-notifications.js';
import {
  DeviceLoginApprovalBadgeController,
  createVaultNotificationProductionRuntime,
  deviceLoginApprovalTransitionAction,
  hasActiveNotificationAccount,
  isDeviceLoginAlarmName,
  resolveDeviceLoginNotificationsUrl,
  restoreDeviceLoginProductionRuntime,
  type VaultNotificationProductionDeps,
} from './vault-notification-production.js';
import { DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM } from './device-login-approval-notifications.js';

type HubHandler = (...args: unknown[]) => unknown;

class FakeConnection implements NotificationsHubConnection {
  readonly handlers = new Map<string, HubHandler>();
  readonly start = vi.fn(async () => undefined);
  readonly stop = vi.fn(async () => undefined);
  private closeHandler: ((error?: Error) => void) | undefined;

  on(methodName: string, handler: HubHandler): void {
    this.handlers.set(methodName, handler);
  }

  onclose(handler: (error?: Error) => void): void {
    this.closeHandler = handler;
  }

  emit(methodName: string, message?: unknown): void {
    this.handlers.get(methodName)?.(message);
  }

  close(): void {
    this.closeHandler?.();
  }
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept;
    reject = decline;
  });
  return { promise, resolve, reject };
}

function accountLease(generation = 1, identity = 'alice@example.test'): AccountLease {
  return Object.freeze({
    serverGeneration: generation,
    accountGeneration: generation,
    serverUrl: 'https://vault.example/tenant/',
    accountIdentity: identity,
  });
}

interface Harness {
  readonly runtime: ReturnType<typeof createVaultNotificationProductionRuntime>;
  readonly capabilities: ServerCapabilityManager<AccountLease>;
  readonly forServer: ReturnType<typeof vi.fn>;
  readonly getServerConfig: ReturnType<typeof vi.fn>;
  readonly sync: ReturnType<typeof vi.fn>;
  readonly notification: ReturnType<typeof vi.fn>;
  readonly getAccountAccessToken: ReturnType<typeof vi.fn>;
  readonly logout: ReturnType<typeof vi.fn>;
  readonly createAlarm: ReturnType<typeof vi.fn>;
  readonly connections: FakeConnection[];
  readonly connectionOptions: NotificationsConnectionOptions[];
  setAccountLease(account: AccountLease): void;
}

function makeHarness(
  overrides: Partial<VaultNotificationProductionDeps> = {},
  config: unknown = { version: '2026.8.0', server: {}, featureStates: {} },
  configFetch?: (maxResponseBytes: number) => PromiseLike<ServerConfigResponse>,
  capabilityNow?: () => number,
): Harness {
  let currentAccount = accountLease();
  const getServerConfig = vi.fn(configFetch ?? (async () => ({ body: config, responseBytes: 256 })));
  const forServer = vi.fn(() => ({ getServerConfig }));
  const sync = vi.fn(async () => undefined);
  const notification = vi.fn();
  const getAccountAccessToken = vi.fn(async () => 'access-token');
  const logout = vi.fn(async () => undefined);
  const createAlarm = vi.fn(async () => undefined);
  const connections: FakeConnection[] = [];
  const connectionOptions: NotificationsConnectionOptions[] = [];
  const api = overrides.api ?? {
    getDeviceIdentifier: async () => 'device-a',
  };
  const capabilityApi = { forServer };
  const captureAccountLease = overrides.captureAccountLease ?? (() => currentAccount);
  const assertAccountLease = overrides.assertAccountLease ?? ((lease: AccountLease) => {
    if (lease !== currentAccount) throw new Error('stale account');
  });
  const capabilities = overrides.capabilities ?? new ServerCapabilityManager<AccountLease>({
    captureIdentity: () => {
      const lease = captureAccountLease();
      return {
        identity: {
          serverUrl: lease.serverUrl,
          accountIdentity: lease.accountIdentity,
        },
        lease,
      };
    },
    assertIdentityCurrent: assertAccountLease,
    fetchConfig: (request) => fetchFixedServerConfig(capabilityApi, request),
    clientDeclaration: PRODUCTION_SERVER_CAPABILITY_DECLARATION,
    ...(capabilityNow ? { now: capabilityNow } : {}),
  });
  const defaults: VaultNotificationProductionDeps = {
    capabilities,
    api,
    auth: {
      getAccountAccessToken,
      logout,
    },
    vault: { sync },
    syncScheduler: { notification },
    captureAccountLease,
    assertAccountLease,
    alarms: { create: createAlarm, clear: async () => true },
    logger: { warn: vi.fn() },
    createConnection: (options) => {
      connectionOptions.push(options);
      const connection = new FakeConnection();
      connections.push(connection);
      return connection;
    },
  };
  const runtime = createVaultNotificationProductionRuntime({ ...defaults, ...overrides });
  return {
    runtime,
    capabilities,
    forServer,
    getServerConfig,
    sync,
    notification,
    getAccountAccessToken,
    logout,
    createAlarm,
    connections,
    connectionOptions,
    setAccountLease: (nextAccount) => { currentAccount = nextAccount; },
  };
}

async function flushMicrotasks(): Promise<void> {
  for (let index = 0; index < 12; index++) await Promise.resolve();
}

describe('vault notification production capability boundary', () => {
  it('reuses the injected production singleton for notification routing', async () => {
    const harness = makeHarness();

    expect(harness.runtime.capabilities).toBe(harness.capabilities);
    await harness.capabilities.resolve();
    await harness.runtime.lifecycle.start();

    expect(harness.getServerConfig).toHaveBeenCalledOnce();
  });

  it('uses a current dedicated service and falls back to the account server on failure', async () => {
    const dedicated = makeHarness({}, {
      version: '2026.8.0',
      server: {},
      environment: { notifications: 'https://push.example/tenant/notifications' },
      featureStates: {},
    });
    await dedicated.runtime.lifecycle.start();
    expect(dedicated.connectionOptions[0]?.hubUrl).toBe(
      'https://push.example/tenant/notifications/hub',
    );

    const getServerConfig = async (): Promise<ServerConfigResponse> => {
      throw new Error('private transport failure');
    };
    const fallback = makeHarness({
      api: {
        getDeviceIdentifier: async () => 'device-a',
      },
    }, undefined, getServerConfig);
    await fallback.runtime.lifecycle.start();
    expect(fallback.connectionOptions[0]?.hubUrl).toBe(
      'https://vault.example/tenant/notifications/hub',
    );
  });

  it('retries a temporary capability fallback after its TTL on reconnect', async () => {
    let now = 0;
    let attempt = 0;
    const harness = makeHarness({}, undefined, async () => {
      attempt += 1;
      if (attempt === 1) throw new Error('temporary config failure');
      return {
        body: {
          version: '2026.8.0',
          environment: { notifications: 'https://push.example/tenant' },
        },
        responseBytes: 256,
      };
    }, () => now);
    await harness.runtime.lifecycle.start();
    expect(harness.connectionOptions[0]?.hubUrl).toBe(
      'https://vault.example/tenant/notifications/hub',
    );

    harness.connections[0]?.close();
    await flushMicrotasks();
    now = 30_000;
    await harness.runtime.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);

    expect(harness.connectionOptions[1]?.hubUrl).toBe('https://push.example/tenant/hub');
    expect(attempt).toBe(2);
  });

  it('does not publish a delayed capability result through stale leases', async () => {
    const pending = deferred<{ body: unknown; responseBytes: number }>();
    const harness = makeHarness({
      api: {
        getDeviceIdentifier: async () => 'device-a',
      },
    }, undefined, () => pending.promise);
    const starting = harness.runtime.lifecycle.start();
    await flushMicrotasks();

    harness.runtime.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'switchAccount', identityChanged: true,
    });
    harness.setAccountLease(accountLease(2, 'bob@example.test'));
    pending.resolve({
      body: {
        version: '2026.8.0',
        environment: { notifications: 'https://stale-push.example/private' },
      },
      responseBytes: 256,
    });
    await starting;

    expect(harness.connections).toHaveLength(0);
    expect(harness.runtime.capabilities.current()).toBeUndefined();
  });
});

describe('vault notification production lifecycle', () => {
  it('awaits a forced authoritative catch-up before a cold-start connection', async () => {
    const catchUp = deferred<void>();
    const events: string[] = [];
    const sync = vi.fn(() => {
      events.push('sync');
      return sync.mock.calls.length === 1 ? catchUp.promise : Promise.resolve();
    });
    const connection = new FakeConnection();
    const harness = makeHarness({
      vault: { sync },
      createConnection: () => {
        events.push('connection');
        return connection;
      },
    });

    const startup = harness.runtime.startup('unlocked');
    await flushMicrotasks();
    expect(events).toEqual(['sync']);

    catchUp.resolve(undefined);
    await startup;
    expect(events.slice(0, 2)).toEqual(['sync', 'connection']);
    expect(sync).toHaveBeenNthCalledWith(1, 'notification', 'force');
  });

  it('starts the account notification transport while the vault is locked', async () => {
    const harness = makeHarness();

    await harness.runtime.startup('locked');

    expect(harness.sync).toHaveBeenCalledWith('notification', 'force');
    expect(harness.connections).toHaveLength(1);
    await expect(harness.connectionOptions[0]?.accessTokenFactory()).resolves.toBe('access-token');
    expect(harness.getAccountAccessToken).toHaveBeenCalledWith(accountLease());
  });

  it.each(['loggedOut', 'restricted'] as const)(
    'stops an existing account notification transport for %s',
    async (state) => {
      const harness = makeHarness();
      await harness.runtime.lifecycle.start();
      const existing = harness.connections[0];

      await harness.runtime.startup(state);

      expect(existing?.stop).toHaveBeenCalledOnce();
      expect(harness.connections).toHaveLength(1);
    },
  );

  it('keeps the connection and capability generation through lock and unlock', async () => {
    const authRequest = vi.fn(async () => undefined);
    const harness = makeHarness({ authRequest });
    await harness.runtime.lifecycle.start();
    const oldConnection = harness.connections[0];
    const capability = harness.runtime.capabilities.capture();
    oldConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.SyncVault });
    expect(harness.notification).toHaveBeenCalledOnce();

    harness.runtime.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
    });
    oldConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.SyncVault });
    expect(oldConnection?.stop).not.toHaveBeenCalled();
    expect(harness.notification).toHaveBeenCalledTimes(2);
    expect(harness.runtime.capabilities.assert(capability)).toBeDefined();

    harness.runtime.handleSessionTransition({
      phase: 'settled', transitionId: 1, reason: 'lock', identityChanged: false,
      state: 'locked', succeeded: true,
    });
    oldConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.AuthRequest });
    await flushMicrotasks();
    expect(authRequest).toHaveBeenCalledOnce();
    oldConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    await flushMicrotasks();
    expect(harness.logout).toHaveBeenCalledOnce();

    harness.runtime.handleSessionTransition({
      phase: 'start', transitionId: 2, reason: 'unlock', identityChanged: false,
    });
    harness.runtime.handleSessionTransition({
      phase: 'settled', transitionId: 2, reason: 'unlock', identityChanged: false,
      state: 'unlocked', succeeded: true,
    });
    expect(harness.connections).toHaveLength(1);
  });

  it('routes vault changes to coalesced sync and logout to lease-bound auth', async () => {
    const harness = makeHarness();
    await harness.runtime.lifecycle.start();

    harness.connections[0]?.emit('ReceiveMessage', {
      Type: VAULT_NOTIFICATION_TYPE.SyncCipherUpdate,
      Payload: { secret: 'not-forwarded' },
    });
    harness.connections[0]?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    await flushMicrotasks();

    expect(harness.notification).toHaveBeenCalledOnce();
    expect(harness.notification.mock.calls).toEqual([[]]);
    expect(harness.logout).toHaveBeenCalledOnce();
  });

  it('routes only the reconnect alarm through the current lifecycle', async () => {
    const harness = makeHarness();
    await harness.runtime.lifecycle.start();
    harness.connections[0]?.close();
    await flushMicrotasks();
    expect(harness.createAlarm).toHaveBeenCalledWith(
      VAULT_NOTIFICATIONS_RECONNECT_ALARM,
      expect.objectContaining({ when: expect.any(Number) }),
    );

    await harness.runtime.handleAlarm('unrelated-alarm');
    expect(harness.connections).toHaveLength(1);
    await harness.runtime.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
    expect(harness.connections).toHaveLength(2);
  });

  it('does not let a reconnect alarm independently create a cold lifecycle', async () => {
    const harness = makeHarness();

    await harness.runtime.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);

    expect(harness.connections).toHaveLength(0);
    expect(harness.sync).not.toHaveBeenCalled();
  });

  it('does not let a delivered alarm consume a pending session settlement', async () => {
    const harness = makeHarness();
    await harness.runtime.lifecycle.start();
    harness.runtime.handleSessionTransition({
      phase: 'start', transitionId: 8, reason: 'switchAccount', identityChanged: true,
    });

    await harness.runtime.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
    harness.setAccountLease(accountLease(2, 'bob@example.test'));
    harness.runtime.handleSessionTransition({
      phase: 'settled', transitionId: 8, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });

    await vi.waitFor(() => expect(harness.connections).toHaveLength(2));
  });

  it('uses the payload-free authenticated notification hook for approval refresh', async () => {
    const authRequest = vi.fn(async () => undefined);
    const harness = makeHarness({ authRequest });
    await harness.runtime.lifecycle.start();

    harness.connections[0]?.emit('ReceiveMessage', {
      Type: VAULT_NOTIFICATION_TYPE.AuthRequest,
      Payload: { requestId: 'must-not-cross' },
    });
    await flushMicrotasks();

    expect(authRequest).toHaveBeenCalledOnce();
    expect(JSON.stringify(authRequest.mock.calls)).not.toContain('must-not-cross');
  });
});

describe('device login production adapters', () => {
  it.each(['locked', 'unlocked'] as const)(
    'treats %s as an active notification account',
    (state) => {
      expect(hasActiveNotificationAccount(state)).toBe(true);
    },
  );

  it.each(['loggedOut', 'restricted'] as const)(
    'treats %s as inactive for notification delivery',
    (state) => {
      expect(hasActiveNotificationAccount(state)).toBe(false);
    },
  );

  it.each(['lock', 'unlock', 'pinUnlock'] as const)(
    'preserves active-account approval delivery when %s starts',
    (reason) => {
      expect(deviceLoginApprovalTransitionAction({
        phase: 'start', transitionId: 1, reason, identityChanged: false,
      })).toBe('preserve');
    },
  );

  it.each([
    'login',
    'logout',
    'switchAccount',
    'removeAccount',
    'serverChange',
    'keyRotation',
  ] as const)('clears active-account approval delivery when %s starts', (reason) => {
    expect(deviceLoginApprovalTransitionAction({
      phase: 'start', transitionId: 1, reason, identityChanged: true,
    })).toBe('clear');
  });

  it.each([
    ['locked', 'refresh'],
    ['unlocked', 'refresh'],
    ['loggedOut', 'clear'],
    ['restricted', 'clear'],
  ] as const)('uses %s settlement to %s approvals', (state, action) => {
    expect(deviceLoginApprovalTransitionAction({
      phase: 'settled',
      transitionId: 1,
      reason: 'lock',
      identityChanged: false,
      state,
      succeeded: true,
    })).toBe(action);
  });

  it('routes only requester, approval-expiry, and anonymous reconnect alarms', () => {
    expect(isDeviceLoginAlarmName('device-login-status:4')).toBe(true);
    expect(isDeviceLoginAlarmName('device-login-deadline:4')).toBe(true);
    expect(isDeviceLoginAlarmName('device-login-notifications-reconnect:worker:4')).toBe(true);
    expect(isDeviceLoginAlarmName(DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM)).toBe(true);
    expect(isDeviceLoginAlarmName('vault-notifications-reconnect')).toBe(false);
    expect(isDeviceLoginAlarmName('device-login-unknown:4')).toBe(false);
  });

  it('resolves a normalized dedicated anonymous-notification base under a fixed server guard', async () => {
    const lease: ServerLease = Object.freeze({
      serverGeneration: 4,
      serverUrl: 'https://vault.example/tenant/',
    });
    const assertServer = vi.fn();
    const getServerConfig = vi.fn(async () => ({
      body: {
        version: '2026.8.0',
        environment: { notifications: 'https://push.example/tenant/notifications' },
      },
      responseBytes: 256,
    }));
    const withRequestGuard = vi.fn(() => ({ getServerConfig }));
    const forServer = vi.fn(() => ({ withRequestGuard }));

    await expect(resolveDeviceLoginNotificationsUrl(
      { forServer }, { assertServer }, lease,
    )).resolves.toBe('https://push.example/tenant/notifications/');
    expect(forServer).toHaveBeenCalledWith(lease.serverUrl);
    expect(withRequestGuard).toHaveBeenCalledWith(expect.any(Function));
    expect(getServerConfig).toHaveBeenCalledWith(65_536);
    expect(assertServer).toHaveBeenCalledTimes(2);
  });

  it('falls back on config failure but refuses fallback after the server lease becomes stale', async () => {
    const lease: ServerLease = Object.freeze({
      serverGeneration: 1,
      serverUrl: 'https://vault.example/tenant/',
    });
    let currentGeneration = 1;
    const assertServer = (candidate: ServerLease): void => {
      if (candidate.serverGeneration !== currentGeneration) throw new Error('stale server');
    };
    const unavailable = {
      forServer: () => ({
        withRequestGuard: () => ({
          getServerConfig: async () => { throw new Error('private config failure'); },
        }),
      }),
    };
    await expect(resolveDeviceLoginNotificationsUrl(
      unavailable, { assertServer }, lease,
    )).resolves.toBeUndefined();

    const pending = deferred<ServerConfigResponse>();
    const delayed = {
      forServer: () => ({
        withRequestGuard: () => ({ getServerConfig: () => pending.promise }),
      }),
    };
    const resolving = resolveDeviceLoginNotificationsUrl(delayed, { assertServer }, lease);
    currentGeneration = 2;
    pending.resolve({ body: {}, responseBytes: 2 });
    await expect(resolving).rejects.toThrow('stale server');
  });

  it('publishes the raw approval contribution and suppresses a stale list after clear', async () => {
    const first = deferred<readonly unknown[]>();
    const listPending = vi.fn()
      .mockImplementationOnce(() => first.promise)
      .mockResolvedValueOnce(Array.from({ length: 120 }));
    const publish = vi.fn(async () => undefined);
    const badge = new DeviceLoginApprovalBadgeController({ listPending, publish });

    const stale = badge.refresh();
    badge.clear();
    await flushMicrotasks();
    expect(publish).toHaveBeenCalledWith({ pendingCount: 0 });
    first.resolve([{}, {}]);
    await stale;
    expect(publish).not.toHaveBeenCalledWith({ pendingCount: 2 });

    await badge.refresh();
    expect(publish).toHaveBeenLastCalledWith({ pendingCount: 120 });
  });

  it('serializes an in-flight badge write so a later clear is always final', async () => {
    const firstWrite = deferred<void>();
    const applied: number[] = [];
    const publish = vi.fn((contribution: { pendingCount: number }) => {
      if (contribution.pendingCount === 1) {
        return firstWrite.promise.then(() => { applied.push(contribution.pendingCount); });
      }
      applied.push(contribution.pendingCount);
      return Promise.resolve();
    });
    const badge = new DeviceLoginApprovalBadgeController({
      listPending: async () => [{}],
      publish,
    });

    const refresh = badge.refresh();
    await vi.waitFor(() => expect(publish).toHaveBeenCalledWith({ pendingCount: 1 }));
    badge.clear();
    expect(publish).toHaveBeenCalledTimes(2);

    firstWrite.resolve(undefined);
    await refresh;
    await vi.waitFor(() => expect(publish).toHaveBeenCalledTimes(3));
    expect(applied).toEqual([0, 1, 0]);
  });

  it('clears the badge and emits only a fixed code when authority refresh fails', async () => {
    const logger = { warn: vi.fn() };
    const publish = vi.fn(async () => undefined);
    const badge = new DeviceLoginApprovalBadgeController({
      listPending: async () => { throw new Error('secret request data'); },
      publish,
      logger,
    });

    await badge.refresh();

    expect(publish).toHaveBeenCalledWith({ pendingCount: 0 });
    expect(logger.warn).toHaveBeenCalledWith('approval_badge_refresh_failed');
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain('secret request data');
  });

  it('rechecks auth state after requester restoration before refreshing approvals', async () => {
    const startupRequester = vi.fn(async () => undefined);
    const cancelRequester = vi.fn(async () => true);
    const refresh = vi.fn(async () => undefined);
    const clear = vi.fn();
    const notificationRefresh = vi.fn(async () => undefined);
    const notificationClear = vi.fn(async () => undefined);
    const getLoggedOutThenUnlocked = vi.fn()
      .mockResolvedValueOnce('loggedOut')
      .mockResolvedValueOnce('unlocked');

    await restoreDeviceLoginProductionRuntime('loggedOut', {
      getAuthState: getLoggedOutThenUnlocked,
      startupRequester,
      cancelRequester,
      badge: { refresh, clear },
      systemNotifications: { refresh: notificationRefresh, clear: notificationClear },
    });
    expect(startupRequester).toHaveBeenCalledOnce();
    expect(cancelRequester).not.toHaveBeenCalled();
    expect(refresh).toHaveBeenCalledOnce();
    expect(notificationRefresh).toHaveBeenCalledOnce();
    expect(clear).not.toHaveBeenCalled();
    expect(notificationClear).not.toHaveBeenCalled();
  });

  it.each(['locked', 'unlocked'] as const)(
    'keeps active-account approval polling and reminders while %s',
    async (state) => {
      const startupRequester = vi.fn(async () => undefined);
      const cancelRequester = vi.fn(async () => true);
      const refresh = vi.fn(async () => undefined);
      const clear = vi.fn();
      const notificationRefresh = vi.fn(async () => undefined);
      const notificationClear = vi.fn(async () => undefined);

      await restoreDeviceLoginProductionRuntime(state, {
        getAuthState: async () => state,
        startupRequester,
        cancelRequester,
        badge: { refresh, clear },
        systemNotifications: { refresh: notificationRefresh, clear: notificationClear },
      });

      expect(startupRequester).not.toHaveBeenCalled();
      expect(cancelRequester).toHaveBeenCalledOnce();
      expect(refresh).toHaveBeenCalledOnce();
      expect(notificationRefresh).toHaveBeenCalledOnce();
      expect(clear).not.toHaveBeenCalled();
      expect(notificationClear).not.toHaveBeenCalled();
    },
  );

  it.each(['loggedOut', 'restricted'] as const)(
    'clears active-account approval state when the final state is %s',
    async (state) => {
      const startupRequester = vi.fn(async () => undefined);
      const cancelRequester = vi.fn(async () => true);
      const refresh = vi.fn(async () => undefined);
      const clear = vi.fn();
      const notificationRefresh = vi.fn(async () => undefined);
      const notificationClear = vi.fn(async () => undefined);

      await restoreDeviceLoginProductionRuntime(state, {
        getAuthState: async () => state,
        startupRequester,
        cancelRequester,
        badge: { refresh, clear },
        systemNotifications: { refresh: notificationRefresh, clear: notificationClear },
      });

      if (state === 'loggedOut') expect(startupRequester).toHaveBeenCalledOnce();
      else expect(cancelRequester).toHaveBeenCalledOnce();
      expect(refresh).not.toHaveBeenCalled();
      expect(notificationRefresh).not.toHaveBeenCalled();
      expect(clear).toHaveBeenCalledOnce();
      expect(notificationClear).toHaveBeenCalledOnce();
    },
  );

  it('keeps requester restoration independent from system-notification adapter failures', async () => {
    const startupRequester = vi.fn(async () => undefined);
    const refresh = vi.fn(async () => undefined);

    await expect(restoreDeviceLoginProductionRuntime('unlocked', {
      getAuthState: async () => 'unlocked',
      startupRequester,
      cancelRequester: async () => true,
      badge: { refresh, clear: vi.fn() },
      systemNotifications: {
        refresh: () => { throw new Error('private notification failure'); },
        clear: vi.fn(),
      },
    })).resolves.toBeUndefined();

    expect(refresh).toHaveBeenCalledOnce();
    expect(startupRequester).not.toHaveBeenCalled();
  });
});
