import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AccountLease } from '../core/session/account-gate.js';
import {
  VAULT_NOTIFICATIONS_RECONNECT_ALARM,
  type NotificationsConnectionOptions,
  type NotificationsHubConnection,
} from './vault-notifications.js';
import {
  VAULT_NOTIFICATION_TYPE,
  createVaultNotificationLifecycle,
  type VaultNotificationLifecycleDeps,
  type VaultNotificationLeases,
} from './vault-notification-lifecycle.js';

type HubHandler = (...args: unknown[]) => unknown;

class FakeConnection implements NotificationsHubConnection {
  readonly handlers = new Map<string, HubHandler>();
  readonly start = vi.fn<() => Promise<void>>(async () => undefined);
  readonly stop = vi.fn<() => Promise<void>>(async () => undefined);
  private closeHandler: ((error?: Error) => void) | undefined;

  on(methodName: string, handler: HubHandler): void {
    this.handlers.set(methodName, handler);
  }

  onclose(handler: (error?: Error) => void): void {
    this.closeHandler = handler;
  }

  emit(methodName: string, ...args: unknown[]): void {
    this.handlers.get(methodName)?.(...args);
  }

  close(error?: Error): void {
    this.closeHandler?.(error);
  }
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function accountLease(
  accountGeneration: number,
  accountIdentity = 'account-a@example.com',
  serverUrl = 'https://vault.example/',
): AccountLease {
  return Object.freeze({
    serverGeneration: accountGeneration,
    accountGeneration,
    accountIdentity,
    serverUrl,
  });
}

interface TimerRecord {
  readonly callback: () => void;
  readonly delayMs: number;
}

interface Harness {
  readonly lifecycle: ReturnType<typeof createVaultNotificationLifecycle>;
  readonly connections: FakeConnection[];
  readonly connectionOptions: NotificationsConnectionOptions[];
  readonly notification: ReturnType<typeof vi.fn>;
  readonly catchUp: ReturnType<typeof vi.fn>;
  readonly getAccessToken: ReturnType<typeof vi.fn>;
  readonly getServerUrls: ReturnType<typeof vi.fn>;
  readonly getDeviceIdentifier: ReturnType<typeof vi.fn>;
  readonly logout: ReturnType<typeof vi.fn>;
  readonly authRequest: ReturnType<typeof vi.fn>;
  readonly createAlarm: ReturnType<typeof vi.fn>;
  readonly clearAlarm: ReturnType<typeof vi.fn>;
  readonly logger: { warn: ReturnType<typeof vi.fn> };
  readonly timers: Map<number, TimerRecord>;
  readonly current: () => VaultNotificationLeases;
  setCurrent(account: AccountLease): void;
  queueStart(implementation: () => Promise<void>): void;
}

function makeHarness(overrides: Partial<VaultNotificationLifecycleDeps> = {}): Harness {
  let currentAccount = accountLease(1);
  let nextTimerId = 0;
  const timers = new Map<number, TimerRecord>();
  const connections: FakeConnection[] = [];
  const connectionOptions: NotificationsConnectionOptions[] = [];
  const startImplementations: Array<() => Promise<void>> = [];
  const notification = vi.fn();
  const catchUp = vi.fn(async () => undefined);
  const getAccessToken = vi.fn(async () => 'access-token');
  const getServerUrls = vi.fn(async (leases: VaultNotificationLeases) => ({
    serverUrl: leases.accountLease.serverUrl,
  }));
  const getDeviceIdentifier = vi.fn(async (leases: VaultNotificationLeases) => (
    `device-${leases.accountLease.accountGeneration}`
  ));
  const logout = vi.fn(async () => undefined);
  const authRequest = vi.fn(async () => undefined);
  const createAlarm = vi.fn(async () => undefined);
  const clearAlarm = vi.fn(async () => true);
  const logger = { warn: vi.fn() };
  const defaults: VaultNotificationLifecycleDeps = {
    captureAccountLease: () => currentAccount,
    assertAccountLease: (lease) => {
      if (lease !== currentAccount) throw new Error('stale account');
    },
    getServerUrls,
    getDeviceIdentifier,
    getAccessToken,
    logout,
    authRequest,
    scheduler: { notification, catchUp },
    alarms: { create: createAlarm, clear: clearAlarm },
    timers: {
      setTimeout: (callback, delayMs) => {
        const id = ++nextTimerId;
        timers.set(id, { callback, delayMs });
        return id;
      },
      clearTimeout: (handle) => {
        timers.delete(handle as number);
      },
    },
    logger,
    now: () => 10_000,
    random: () => 0,
    createConnection: (options) => {
      const connection = new FakeConnection();
      const startImplementation = startImplementations.shift();
      if (startImplementation) connection.start.mockImplementation(startImplementation);
      connections.push(connection);
      connectionOptions.push(options);
      return connection;
    },
  };
  const lifecycle = createVaultNotificationLifecycle({ ...defaults, ...overrides });
  return {
    lifecycle,
    connections,
    connectionOptions,
    notification,
    catchUp,
    getAccessToken,
    getServerUrls,
    getDeviceIdentifier,
    logout,
    authRequest,
    createAlarm,
    clearAlarm,
    logger,
    timers,
    current: () => ({ accountLease: currentAccount }),
    setCurrent: (account) => {
      currentAccount = account;
    },
    queueStart: (implementation) => {
      startImplementations.push(implementation);
    },
  };
}

async function flushMicrotasks(): Promise<void> {
  for (let index = 0; index < 12; index++) await Promise.resolve();
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('VaultNotificationLifecycle startup and transitions', () => {
  it('finishes an authoritative startup catch-up before creating the SignalR connection', async () => {
    const preflight = deferred<void>();
    const harness = makeHarness();
    harness.catchUp.mockImplementationOnce(() => preflight.promise);

    const startup = harness.lifecycle.startup();
    await flushMicrotasks();

    expect(harness.catchUp).toHaveBeenCalledOnce();
    expect(harness.catchUp).toHaveBeenCalledWith(harness.current());
    expect(harness.connections).toHaveLength(0);

    preflight.resolve(undefined);
    await startup;
    expect(harness.connections).toHaveLength(1);
    expect(harness.connections[0]?.start).toHaveBeenCalledOnce();
    expect(harness.connectionOptions[0]?.hubUrl).toBe(
      'https://vault.example/notifications/hub',
    );

    await flushMicrotasks();
    expect(harness.catchUp).toHaveBeenCalledTimes(2);
  });

  it('does not let a concurrent reconnect alarm bypass the startup catch-up', async () => {
    const preflight = deferred<void>();
    const harness = makeHarness();
    harness.catchUp.mockImplementationOnce(() => preflight.promise);

    const startup = harness.lifecycle.startup();
    await flushMicrotasks();
    const alarm = harness.lifecycle.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
    await flushMicrotasks();
    expect(harness.connections).toHaveLength(0);

    preflight.resolve(undefined);
    await Promise.all([startup, alarm]);
    expect(harness.connections).toHaveLength(1);
    expect(harness.connections[0]?.start).toHaveBeenCalledOnce();
  });

  it('keeps the account transport through lock and unlock and handles logout while locked', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    const connection = harness.connections[0];

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
    });
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 1, reason: 'lock', identityChanged: false,
      state: 'locked', succeeded: true,
    });
    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.SyncVault });
    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    await flushMicrotasks();

    expect(harness.connections).toHaveLength(1);
    expect(connection?.stop).not.toHaveBeenCalled();
    expect(harness.notification).toHaveBeenCalledOnce();
    expect(harness.logout).toHaveBeenCalledOnce();

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 2, reason: 'unlock', identityChanged: false,
    });
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 2, reason: 'unlock', identityChanged: false,
      state: 'unlocked', succeeded: true,
    });
    expect(harness.connections).toHaveLength(1);
    expect(connection?.stop).not.toHaveBeenCalled();
  });

  it('restores the rolled-back unlocked session after a failed current transition', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    const first = harness.connections[0];

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 4, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(2));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 4, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: false,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(2));

    expect(first?.stop).toHaveBeenCalledOnce();
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 3, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: false,
    });
    await flushMicrotasks();
    expect(harness.connections).toHaveLength(2);
  });

  it('does not let a manual stop get undone by a later transition settlement', async () => {
    const harness = makeHarness();
    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'unlock', identityChanged: false,
    });
    await harness.lifecycle.stop();

    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 1, reason: 'unlock', identityChanged: false,
      state: 'unlocked', succeeded: true,
    });
    await flushMicrotasks();

    expect(harness.connections).toHaveLength(0);
  });

  it('preserves a dedicated notifications service base instead of treating it as a vault base', async () => {
    const harness = makeHarness({
      getServerUrls: async (leases) => ({
        serverUrl: leases.accountLease.serverUrl,
        notificationsUrl: 'https://push.example/tenant/',
      }),
    });

    await harness.lifecycle.start();

    expect(harness.connectionOptions[0]?.hubUrl).toBe('https://push.example/tenant/hub');
  });

  it('refreshes route capability on reconnect while reusing the stable device identifier', async () => {
    const getServerUrls = vi.fn()
      .mockImplementationOnce(async (leases: VaultNotificationLeases) => ({
        serverUrl: leases.accountLease.serverUrl,
      }))
      .mockImplementationOnce(async (leases: VaultNotificationLeases) => ({
        serverUrl: leases.accountLease.serverUrl,
        notificationsUrl: 'https://push.example/tenant/',
      }));
    const harness = makeHarness({ getServerUrls });
    await harness.lifecycle.start();
    expect(harness.connectionOptions[0]?.hubUrl).toBe(
      'https://vault.example/notifications/hub',
    );

    harness.connections[0]?.close();
    await flushMicrotasks();
    await harness.lifecycle.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);

    expect(harness.connectionOptions[1]?.hubUrl).toBe('https://push.example/tenant/hub');
    expect(getServerUrls).toHaveBeenCalledTimes(2);
    expect(harness.getDeviceIdentifier).toHaveBeenCalledOnce();
  });

  it('ignores stale settlements and prevents an A-B-A sequence from reviving old callbacks', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    await flushMicrotasks();
    const firstConnection = harness.connections[0];
    harness.catchUp.mockClear();

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 10, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(2, 'account-b@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 10, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(2));

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 11, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(3, 'account-a@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 11, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 10, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(3));

    expect(harness.connections).toHaveLength(3);
    firstConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.SyncVault });
    firstConnection?.close(new Error('late close'));
    await flushMicrotasks();

    expect(harness.notification).not.toHaveBeenCalled();
    expect(harness.createAlarm).not.toHaveBeenCalled();
    expect(harness.connections).toHaveLength(3);
  });

  it('drops an old asynchronous URL result after an A-B-A transition', async () => {
    const firstUrls = deferred<{ serverUrl: string; notificationsUrl: string }>();
    const firstAccount = accountLease(1);
    const getServerUrls = vi.fn((leases: VaultNotificationLeases) => {
      if (leases.accountLease === firstAccount) return firstUrls.promise;
      return Promise.resolve({
        serverUrl: leases.accountLease.serverUrl,
        notificationsUrl: leases.accountLease.serverUrl,
      });
    });
    const harness = makeHarness({ getServerUrls });
    harness.setCurrent(firstAccount);

    const oldStart = harness.lifecycle.start();
    await flushMicrotasks();
    expect(harness.connections).toHaveLength(0);

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(2, 'account-b@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 1, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(1));

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 2, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(3, 'account-a@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 2, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(2));
    expect(harness.connections).toHaveLength(2);

    firstUrls.resolve({
      serverUrl: firstAccount.serverUrl,
      notificationsUrl: firstAccount.serverUrl,
    });
    await oldStart;
    await flushMicrotasks();

    expect(harness.connections).toHaveLength(2);
    expect(harness.connections[1]?.stop).not.toHaveBeenCalled();
  });
});

describe('VaultNotificationLifecycle message policy', () => {
  it('routes official vault types to the scheduler debounce lane without forwarding payloads', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    await flushMicrotasks();
    harness.catchUp.mockClear();
    const connection = harness.connections[0];

    connection?.emit('ReceiveMessage', {
      Type: VAULT_NOTIFICATION_TYPE.SyncCipherUpdate,
      Payload: { secret: 'never-forward-this' },
    });
    connection?.emit('ReceiveMessage', { type: VAULT_NOTIFICATION_TYPE.SyncPolicy });
    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.AuthRequest });
    connection?.emit('ReceiveMessage', {
      Type: VAULT_NOTIFICATION_TYPE.SyncVault,
      ContextId: 'device-1',
    });

    expect(harness.notification).toHaveBeenCalledTimes(2);
    expect(harness.notification).toHaveBeenNthCalledWith(1, harness.current());
    expect(harness.notification).toHaveBeenNthCalledWith(2, harness.current());
    expect(harness.authRequest).toHaveBeenCalledOnce();
    expect(harness.authRequest).toHaveBeenCalledWith(harness.current());
    expect(harness.catchUp).not.toHaveBeenCalled();
    expect(JSON.stringify(harness.notification.mock.calls)).not.toContain('never-forward-this');
  });

  it('singleflights logout and rejects stale A-B-A logout callbacks', async () => {
    const firstLogout = deferred<void>();
    const harness = makeHarness();
    harness.logout.mockImplementationOnce(() => firstLogout.promise);
    await harness.lifecycle.start();
    await flushMicrotasks();
    const firstConnection = harness.connections[0];

    firstConnection?.emit('ReceiveMessage', {
      Type: VAULT_NOTIFICATION_TYPE.LogOut,
      Payload: { privateReason: 'do-not-forward' },
    });
    firstConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    expect(harness.logout).toHaveBeenCalledOnce();
    expect(harness.logout).toHaveBeenCalledWith(harness.current());

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(2, 'account-b@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 1, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(2));
    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 2, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(3, 'account-a@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 2, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await vi.waitFor(() => expect(harness.connections).toHaveLength(3));

    firstConnection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    harness.connections[2]?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    firstLogout.resolve(undefined);
    await flushMicrotasks();

    expect(harness.logout).toHaveBeenCalledTimes(2);
    expect(harness.logout).toHaveBeenLastCalledWith(harness.current());
    expect(JSON.stringify(harness.logout.mock.calls)).not.toContain('do-not-forward');
  });

  it('coalesces auth-request signals and treats premium changes as authoritative catch-ups', async () => {
    const firstAuthRequest = deferred<void>();
    const harness = makeHarness();
    harness.authRequest.mockImplementationOnce(() => firstAuthRequest.promise);
    await harness.lifecycle.start();
    await flushMicrotasks();
    harness.catchUp.mockClear();
    const connection = harness.connections[0];

    connection?.emit('ReceiveMessage', {
      Type: VAULT_NOTIFICATION_TYPE.AuthRequest,
      Payload: { id: 'must-not-be-forwarded' },
    });
    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.AuthRequestResponse });
    expect(harness.authRequest).toHaveBeenCalledOnce();
    firstAuthRequest.resolve(undefined);
    await flushMicrotasks();
    expect(harness.authRequest).toHaveBeenCalledTimes(2);

    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.PremiumStatusChanged });
    await flushMicrotasks();
    expect(harness.catchUp).toHaveBeenCalledOnce();
    expect(JSON.stringify(harness.authRequest.mock.calls)).not.toContain('must-not-be-forwarded');
  });

  it('sanitizes logout and auth-request callback failures', async () => {
    const harness = makeHarness();
    harness.logout.mockRejectedValueOnce(new Error('logout failed with secret reason'));
    harness.authRequest.mockRejectedValueOnce(new Error('request failed with secret payload'));
    await harness.lifecycle.start();
    const connection = harness.connections[0];

    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.LogOut });
    connection?.emit('ReceiveMessage', { Type: VAULT_NOTIFICATION_TYPE.AuthRequest });
    await flushMicrotasks();

    expect(harness.logger.warn).toHaveBeenCalledWith('logout_failed');
    expect(harness.logger.warn).toHaveBeenCalledWith('auth_request_failed');
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain('secret');
  });

  it('coalesces malformed and unknown messages into one leading and one trailing catch-up', async () => {
    const pending = deferred<void>();
    const harness = makeHarness();
    await harness.lifecycle.start();
    await flushMicrotasks();
    harness.catchUp.mockClear();
    harness.catchUp.mockImplementationOnce(() => pending.promise);
    const connection = harness.connections[0];

    connection?.emit('ReceiveMessage', { Type: 99 });
    connection?.emit('ReceiveMessage', 'malformed');
    connection?.emit('ReceiveMessage', { Type: 1.5 });
    connection?.emit('ReceiveMessage', { Type: 1, ContextId: 'x'.repeat(257) });

    expect(harness.catchUp).toHaveBeenCalledOnce();
    pending.resolve(undefined);
    await flushMicrotasks();
    expect(harness.catchUp).toHaveBeenCalledTimes(2);
    expect(harness.catchUp).toHaveBeenLastCalledWith(harness.current());
  });

  it('reads only bounded Type and ContextId fields and never evaluates or forwards the payload', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    const payloadGetter = vi.fn(() => {
      throw new Error('secret payload should not be read');
    });
    const message = { Type: VAULT_NOTIFICATION_TYPE.SyncVault } as Record<string, unknown>;
    Object.defineProperty(message, 'Payload', { enumerable: true, get: payloadGetter });

    harness.connections[0]?.emit('ReceiveMessage', message);

    expect(payloadGetter).not.toHaveBeenCalled();
    expect(harness.notification).toHaveBeenCalledOnce();
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain('secret payload');
  });

  it('treats hostile property descriptors and conflicting aliases as conservative catch-ups', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    await flushMicrotasks();
    harness.catchUp.mockClear();
    const hostile = new Proxy<Record<string, unknown>>({}, {
      getOwnPropertyDescriptor: () => {
        throw new Error('descriptor trap with private contents');
      },
    });

    expect(() => harness.connections[0]?.emit('ReceiveMessage', hostile)).not.toThrow();
    harness.connections[0]?.emit('ReceiveMessage', { Type: 5, type: 6 });
    await flushMicrotasks();

    expect(harness.catchUp).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain('private contents');
  });
});

describe('VaultNotificationLifecycle failure and retry boundaries', () => {
  it('does not fail authentication when connection startup fails and schedules the existing retry path', async () => {
    const harness = makeHarness();
    harness.queueStart(async () => {
      throw new Error('connection failed with access-token-in-error');
    });

    await expect(harness.lifecycle.start()).resolves.toBeUndefined();
    await flushMicrotasks();

    expect(harness.createAlarm).toHaveBeenCalledOnce();
    expect(harness.timers).toHaveLength(0);
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain('access-token-in-error');
    expect(harness.logger.warn).toHaveBeenCalledWith('connect_failed');
    expect(harness.logger.warn).toHaveBeenCalledWith('lifecycle_start_failed');
  });

  it('continues to connect after a failed startup catch-up without logging its error contents', async () => {
    const harness = makeHarness();
    harness.catchUp.mockRejectedValueOnce(new Error('sync failed with private message body'));

    await expect(harness.lifecycle.startup()).resolves.toBeUndefined();
    await flushMicrotasks();

    expect(harness.connections).toHaveLength(1);
    expect(harness.logger.warn).toHaveBeenCalledWith('lifecycle_catch_up_failed');
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain('private message body');
  });

  it('cancels a closed connection retry and prevents a delivered alarm from reviving it', async () => {
    const harness = makeHarness();
    await harness.lifecycle.start();
    const connection = harness.connections[0];
    connection?.close(new Error('offline'));
    await flushMicrotasks();
    expect(harness.createAlarm).toHaveBeenCalledOnce();
    expect(harness.timers).toHaveLength(0);

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'logout', identityChanged: true,
    });
    expect(harness.timers).toHaveLength(0);
    await harness.lifecycle.handleAlarm({ name: VAULT_NOTIFICATIONS_RECONNECT_ALARM });

    expect(harness.connections).toHaveLength(1);
    expect(harness.timers).toHaveLength(0);
  });

  it('rejects a token that resolves after the account generation changes, even when its name returns', async () => {
    const token = deferred<string>();
    const harness = makeHarness({ getAccessToken: () => token.promise });
    await harness.lifecycle.start();
    const tokenRequest = harness.connectionOptions[0]?.accessTokenFactory();
    expect(tokenRequest).toBeDefined();

    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 1, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(2, 'account-b@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 1, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    await flushMicrotasks();
    harness.lifecycle.handleSessionTransition({
      phase: 'start', transitionId: 2, reason: 'switchAccount', identityChanged: true,
    });
    harness.setCurrent(accountLease(3, 'account-a@example.com'));
    harness.lifecycle.handleSessionTransition({
      phase: 'settled', transitionId: 2, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });

    token.resolve('late-secret-token');
    await expect(tokenRequest).rejects.toThrow(/unavailable|changed/u);
  });
});
