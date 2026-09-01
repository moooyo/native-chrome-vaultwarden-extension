import {
  HttpTransportType,
  HubConnectionBuilder,
  LogLevel,
  type IHttpConnectionOptions,
} from '@microsoft/signalr';
import { MessagePackHubProtocol } from '@microsoft/signalr-protocol-msgpack';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AccountLease } from '../core/session/account-gate.js';
import {
  BASE_NOTIFICATIONS_RECONNECT_DELAY_MS,
  MAX_NOTIFICATIONS_RECONNECT_DELAY_MS,
  MIN_NOTIFICATIONS_RECONNECT_DELAY_MS,
  VAULT_NOTIFICATIONS_RECONNECT_ALARM,
  buildDedicatedNotificationsHubUrl,
  buildVaultNotificationsHubUrl,
  createSignalRNotificationsConnection,
  createVaultNotifications,
  type NotificationsConnectionOptions,
  type NotificationsHubConnection,
  type VaultNotificationsDeps,
} from './vault-notifications.js';

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

function makeLease(
  accountGeneration: number,
  accountIdentity = 'account-a@example.com',
  serverUrl = 'https://vault.example/base/',
): AccountLease {
  return Object.freeze({
    serverGeneration: 1,
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
  readonly adapter: ReturnType<typeof createVaultNotifications>;
  readonly connections: FakeConnection[];
  readonly connectionOptions: NotificationsConnectionOptions[];
  readonly notification: ReturnType<typeof vi.fn>;
  readonly catchUp: ReturnType<typeof vi.fn>;
  readonly getAccessToken: ReturnType<typeof vi.fn>;
  readonly createAlarm: ReturnType<typeof vi.fn>;
  readonly clearAlarm: ReturnType<typeof vi.fn>;
  readonly logger: { warn: ReturnType<typeof vi.fn> };
  readonly timers: Map<number, TimerRecord>;
  setLease(lease: AccountLease): void;
  queueStart(implementation: () => Promise<void>): void;
}

function makeHarness(overrides: Partial<VaultNotificationsDeps> = {}): Harness {
  let currentLease = makeLease(1);
  let nextTimerId = 0;
  const timers = new Map<number, TimerRecord>();
  const connections: FakeConnection[] = [];
  const connectionOptions: NotificationsConnectionOptions[] = [];
  const startImplementations: Array<() => Promise<void>> = [];
  const notification = vi.fn();
  const catchUp = vi.fn(async () => undefined);
  const getAccessToken = vi.fn(async (lease: AccountLease) => `token-${lease.accountGeneration}`);
  const createAlarm = vi.fn(async () => undefined);
  const clearAlarm = vi.fn(async () => true);
  const logger = { warn: vi.fn() };
  const defaults: VaultNotificationsDeps = {
    getServerUrl: async (lease) => lease.serverUrl,
    getAccessToken,
    captureAccountLease: () => currentLease,
    assertAccountLease: (lease) => {
      if (lease !== currentLease) throw new Error('The account lease is stale');
    },
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
    now: () => 1_000_000,
    random: () => 0.5,
    createConnection: (options) => {
      const connection = new FakeConnection();
      const startImplementation = startImplementations.shift();
      if (startImplementation) connection.start.mockImplementation(startImplementation);
      connections.push(connection);
      connectionOptions.push(options);
      return connection;
    },
  };
  const adapter = createVaultNotifications({ ...defaults, ...overrides });
  return {
    adapter,
    connections,
    connectionOptions,
    notification,
    catchUp,
    getAccessToken,
    createAlarm,
    clearAlarm,
    logger,
    timers,
    setLease: (lease) => { currentLease = lease; },
    queueStart: (implementation) => { startImplementations.push(implementation); },
  };
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('vault notifications transport', () => {
  it('preserves a self-hosted base path and only permits secure or loopback transport', () => {
    expect(buildVaultNotificationsHubUrl('https://vault.example/self-hosted/')).toBe(
      'https://vault.example/self-hosted/notifications/hub',
    );
    expect(buildVaultNotificationsHubUrl('http://localhost:8080/vault/')).toBe(
      'http://localhost:8080/vault/notifications/hub',
    );
    expect(buildVaultNotificationsHubUrl('http://127.0.0.42:8080/')).toBe(
      'http://127.0.0.42:8080/notifications/hub',
    );
    expect(() => buildVaultNotificationsHubUrl('http://vault.example/')).toThrow(/HTTPS/u);
    expect(() => buildVaultNotificationsHubUrl('https://vault.example/?token=secret')).toThrow(
      /query/u,
    );
    expect(buildDedicatedNotificationsHubUrl('https://push.example/tenant/')).toBe(
      'https://push.example/tenant/hub',
    );
    expect(() => buildDedicatedNotificationsHubUrl('http://push.example/')).toThrow(/HTTPS/u);
  });

  it('uses the official MessagePack protocol over WebSockets without negotiation or logging', () => {
    const configureLogging = vi.spyOn(HubConnectionBuilder.prototype, 'configureLogging');
    const withUrl = vi.spyOn(HubConnectionBuilder.prototype, 'withUrl');
    const withHubProtocol = vi.spyOn(HubConnectionBuilder.prototype, 'withHubProtocol');
    const withAutomaticReconnect = vi.spyOn(
      HubConnectionBuilder.prototype,
      'withAutomaticReconnect',
    );
    const tokenFactory = async () => 'access-token';

    createSignalRNotificationsConnection({
      hubUrl: 'https://vault.example/notifications/hub',
      accessTokenFactory: tokenFactory,
    });

    expect(configureLogging).toHaveBeenCalledWith(LogLevel.None);
    expect(withUrl).toHaveBeenCalledOnce();
    const [url, rawOptions] = withUrl.mock.calls[0] ?? [];
    expect(url).toBe('https://vault.example/notifications/hub');
    const options = rawOptions as IHttpConnectionOptions;
    expect(options).toMatchObject({
      accessTokenFactory: tokenFactory,
      logMessageContent: false,
      skipNegotiation: true,
      transport: HttpTransportType.WebSockets,
    });
    expect(withHubProtocol.mock.calls[0]?.[0]).toBeInstanceOf(MessagePackHubProtocol);
    expect(withAutomaticReconnect).not.toHaveBeenCalled();
  });
});

describe('VaultNotifications messages and credentials', () => {
  it('singleflights start, refreshes guarded tokens, and conservatively syncs every message', async () => {
    const serverUrl = deferred<string>();
    const getServerUrl = vi.fn(() => serverUrl.promise);
    const harness = makeHarness({ getServerUrl });

    const first = harness.adapter.start();
    const second = harness.adapter.start();
    expect(second).toBe(first);
    serverUrl.resolve('https://vault.example/base/');
    await first;

    expect(getServerUrl).toHaveBeenCalledOnce();
    expect(harness.connections).toHaveLength(1);
    expect(harness.connections[0]?.handlers.has('ReceiveMessage')).toBe(true);
    expect(harness.connections[0]?.handlers.has('Heartbeat')).toBe(true);
    expect(harness.catchUp).toHaveBeenCalledOnce();
    expect(harness.catchUp).toHaveBeenCalledWith(expect.objectContaining({ accountGeneration: 1 }));

    const tokenFactory = harness.connectionOptions[0]?.accessTokenFactory;
    expect(tokenFactory).toBeDefined();
    await expect(tokenFactory?.()).resolves.toBe('token-1');
    await expect(tokenFactory?.()).resolves.toBe('token-1');
    expect(harness.getAccessToken).toHaveBeenCalledTimes(2);

    const connection = harness.connections[0];
    connection?.emit('ReceiveMessage');
    connection?.emit('ReceiveMessage', { Type: 999, unknown: true });
    connection?.emit('ReceiveMessage', 'malformed');
    connection?.emit('Heartbeat', { ignored: true });
    expect(harness.notification).toHaveBeenCalledTimes(3);
    expect(harness.notification).toHaveBeenCalledWith(
      expect.objectContaining({ accountGeneration: 1 }),
      undefined,
    );
  });

  it('invalidates old callbacks and token factories when the account generation changes', async () => {
    const harness = makeHarness();
    await harness.adapter.start();
    const oldConnection = harness.connections[0];
    const oldTokenFactory = harness.connectionOptions[0]?.accessTokenFactory;

    harness.setLease(makeLease(2));
    await harness.adapter.start();
    await flushMicrotasks();
    expect(harness.connections).toHaveLength(2);
    expect(oldConnection?.stop).toHaveBeenCalled();

    oldConnection?.emit('ReceiveMessage', { Type: 1 });
    oldConnection?.close(new Error('late close'));
    await expect(oldTokenFactory?.()).rejects.toThrow(/connection changed/u);
    await flushMicrotasks();
    expect(harness.notification).not.toHaveBeenCalled();
    expect(harness.createAlarm).not.toHaveBeenCalled();

    harness.connections[1]?.emit('ReceiveMessage', { Type: 99 });
    expect(harness.notification).toHaveBeenCalledOnce();
    expect(harness.notification).toHaveBeenCalledWith(
      expect.objectContaining({ accountGeneration: 2 }),
      { Type: 99 },
    );
  });

  it('uses a lease-bound dedicated notifications origin without changing the account server', async () => {
    const getNotificationsUrl = vi.fn(async () => 'https://push.example/tenant/');
    const harness = makeHarness({ getNotificationsUrl });

    await harness.adapter.start();

    expect(getNotificationsUrl).toHaveBeenCalledWith(
      expect.objectContaining({ serverUrl: 'https://vault.example/base/' }),
    );
    expect(harness.connectionOptions[0]?.hubUrl).toBe(
      'https://push.example/tenant/hub',
    );
  });

  it('revalidates the lease after an asynchronous token refresh', async () => {
    const token = deferred<string>();
    const harness = makeHarness({ getAccessToken: () => token.promise });
    await harness.adapter.start();
    const tokenRequest = harness.connectionOptions[0]?.accessTokenFactory();
    expect(tokenRequest).toBeDefined();

    harness.setLease(makeLease(2));
    token.resolve('late-token-for-account-a');
    await expect(tokenRequest).rejects.toThrow(/connection changed/u);
  });

  it('sanitizes token-provider failures before they reach SignalR', async () => {
    const harness = makeHarness({
      getAccessToken: async () => {
        throw new Error('refresh failed for secret-token-value');
      },
    });
    await harness.adapter.start();

    await expect(harness.connectionOptions[0]?.accessTokenFactory()).rejects.toThrow(
      'The notifications access token is unavailable',
    );
  });
});

describe('VaultNotifications lifecycle', () => {
  it('lets a new account start without waiting for an old server lookup', async () => {
    const oldLookup = deferred<string>();
    const getServerUrl = vi.fn()
      .mockImplementationOnce(() => oldLookup.promise)
      .mockImplementation(async (lease: AccountLease) => lease.serverUrl);
    const harness = makeHarness({ getServerUrl });
    const oldStart = harness.adapter.start();
    await flushMicrotasks();

    harness.setLease(makeLease(2));
    await harness.adapter.start();
    expect(harness.connections).toHaveLength(1);
    expect(harness.catchUp).toHaveBeenCalledWith(
      expect.objectContaining({ accountGeneration: 2 }),
    );

    oldLookup.resolve('https://vault.example/base/');
    await expect(oldStart).rejects.toThrow('Vault notifications connection failed');
    expect(harness.connections).toHaveLength(1);
  });

  it('invalidates callbacks synchronously and interrupts a connection that is still starting', async () => {
    const pendingStart = deferred<void>();
    const harness = makeHarness();
    harness.queueStart(() => pendingStart.promise);
    const oldStart = harness.adapter.start();
    await flushMicrotasks();
    const oldConnection = harness.connections[0];
    expect(oldConnection?.start).toHaveBeenCalledOnce();

    const firstStop = harness.adapter.stop();
    const secondStop = harness.adapter.stop();
    expect(secondStop).toBe(firstStop);
    oldConnection?.emit('ReceiveMessage', { Type: 1 });
    expect(harness.notification).not.toHaveBeenCalled();
    expect(oldConnection?.stop).toHaveBeenCalledOnce();
    await firstStop;

    harness.setLease(makeLease(2));
    await harness.adapter.start();
    expect(harness.connections).toHaveLength(2);
    pendingStart.resolve(undefined);
    await oldStart;
    expect(harness.connections[1]?.stop).not.toHaveBeenCalled();
  });

  it('does not revive a stopped lifecycle from a delivered retry alarm', async () => {
    const harness = makeHarness();
    await harness.adapter.start();
    harness.connections[0]?.close();
    await flushMicrotasks();
    expect(harness.createAlarm).toHaveBeenCalledOnce();

    await harness.adapter.stop();
    await harness.adapter.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
    expect(harness.connections).toHaveLength(1);
    expect(harness.timers).toHaveLength(0);
  });

  it('lets a persisted one-shot alarm restore a cold worker', async () => {
    const harness = makeHarness();
    await harness.adapter.handleAlarm({ name: VAULT_NOTIFICATIONS_RECONNECT_ALARM });
    expect(harness.connections).toHaveLength(1);
    expect(harness.catchUp).toHaveBeenCalledOnce();

    await harness.adapter.handleAlarm('some-other-alarm');
    expect(harness.connections).toHaveLength(1);
  });
});

describe('VaultNotifications reconnect policy', () => {
  it.each([
    [0, MIN_NOTIFICATIONS_RECONNECT_DELAY_MS],
    [1, Math.round(BASE_NOTIFICATIONS_RECONNECT_DELAY_MS * 1.2)],
  ])('schedules one alarm and no timer at the first %s jitter boundary', async (random, delayMs) => {
    const harness = makeHarness({ random: () => random });
    await harness.adapter.start();
    harness.connections[0]?.close(new Error('offline'));
    await flushMicrotasks();

    expect(harness.timers).toHaveLength(0);
    expect(harness.createAlarm).toHaveBeenCalledOnce();
    expect(harness.createAlarm).toHaveBeenCalledWith(
      VAULT_NOTIFICATIONS_RECONNECT_ALARM,
      { when: 1_000_000 + delayMs },
    );
  });

  it('reconnects through the shared start path and runs a full catch-up after success', async () => {
    const harness = makeHarness();
    await harness.adapter.start();
    harness.connections[0]?.close();
    await flushMicrotasks();
    await harness.adapter.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);

    expect(harness.connections).toHaveLength(2);
    expect(harness.catchUp).toHaveBeenCalledTimes(2);
    expect(harness.clearAlarm).toHaveBeenCalled();
  });

  it('deduplicates a start rejection and close callback into one retry schedule', async () => {
    const createAlarm = vi.fn(async () => undefined);
    let connection: FakeConnection | undefined;
    const createConnection = vi.fn((_options: NotificationsConnectionOptions) => {
      connection = new FakeConnection();
      connection.start.mockImplementation(async () => {
        connection?.close(new Error('closed while starting'));
        throw new Error('start failed');
      });
      return connection;
    });
    const harness = makeHarness({
      alarms: { create: createAlarm, clear: async () => true },
      createConnection,
    });

    await expect(harness.adapter.start()).rejects.toThrow('Vault notifications connection failed');
    await flushMicrotasks();
    expect(createAlarm).toHaveBeenCalledOnce();
    expect(harness.timers).toHaveLength(0);
  });

  it('increases consecutive alarm retries exponentially and caps them at five minutes', async () => {
    const harness = makeHarness({ random: () => 0.5 });
    harness.queueStart(async () => { throw new Error('offline-1'); });
    await expect(harness.adapter.start()).rejects.toThrow();
    await flushMicrotasks();

    for (let attempt = 2; attempt <= 5; attempt++) {
      harness.queueStart(async () => { throw new Error(`offline-${attempt}`); });
      await expect(
        harness.adapter.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM),
      ).rejects.toThrow();
      await flushMicrotasks();
    }

    expect(harness.createAlarm.mock.calls.map(([, options]) => options.when - 1_000_000)).toEqual([
      30_000,
      60_000,
      120_000,
      240_000,
      MAX_NOTIFICATIONS_RECONNECT_DELAY_MS,
    ]);
    expect(harness.timers).toHaveLength(0);
  });

  it('resets the exponential attempt after a successful alarm reconnect', async () => {
    const harness = makeHarness({ random: () => 0.5 });
    harness.queueStart(async () => { throw new Error('offline'); });
    await expect(harness.adapter.start()).rejects.toThrow();
    await flushMicrotasks();

    await harness.adapter.handleAlarm(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
    harness.connections[1]?.close(new Error('offline again'));
    await flushMicrotasks();

    const delays = harness.createAlarm.mock.calls.map(([, options]) => options.when - 1_000_000);
    expect(delays).toEqual([BASE_NOTIFICATIONS_RECONNECT_DELAY_MS, BASE_NOTIFICATIONS_RECONNECT_DELAY_MS]);
  });

  it('never forwards token-bearing URL or errors to its logger', async () => {
    const secret = 'super-secret-access-token';
    const fullUrl = 'wss://vault.example/notifications/hub?access_token=' + secret;
    const harness = makeHarness({
      createConnection: () => {
        const connection = new FakeConnection();
        connection.start.mockRejectedValue(new Error('Could not connect to ' + fullUrl));
        return connection;
      },
    });

    await expect(harness.adapter.start()).rejects.toThrow('Vault notifications connection failed');
    await flushMicrotasks();
    const serializedLogs = JSON.stringify(harness.logger.warn.mock.calls);
    expect(serializedLogs).not.toContain(secret);
    expect(serializedLogs).not.toContain('vault.example');
    expect(harness.logger.warn).toHaveBeenCalledWith('connect_failed');
  });
});
