import {
  HttpTransportType,
  HubConnectionBuilder,
  LogLevel,
  type IHttpConnectionOptions,
} from '@microsoft/signalr';
import { MessagePackHubProtocol } from '@microsoft/signalr-protocol-msgpack';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BASE_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS,
  DEVICE_LOGIN_NOTIFICATION_METHOD,
  DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX,
  MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ATTEMPTS,
  buildDedicatedDeviceLoginAnonymousHubUrl,
  buildDeviceLoginAnonymousHubUrl,
  createDeviceLoginNotifications,
  createDeviceLoginSignalRConnection,
  type DeviceLoginNotificationRequest,
  type DeviceLoginNotificationsConnectionOptions,
  type DeviceLoginNotificationsDeps,
} from './device-login-notifications.js';
import type { NotificationsHubConnection } from './vault-notifications.js';

const REQUEST_A = '10000000-0000-4000-8000-000000000001';
const REQUEST_B = '10000000-0000-4000-8000-000000000002';
const NOW = 1_000_000;

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

interface TimerRecord {
  readonly callback: () => void;
  readonly delayMs: number;
}

interface Harness {
  readonly notifications: ReturnType<typeof createDeviceLoginNotifications>;
  readonly connections: FakeConnection[];
  readonly connectionOptions: DeviceLoginNotificationsConnectionOptions[];
  readonly onSignal: ReturnType<typeof vi.fn>;
  readonly createAlarm: ReturnType<typeof vi.fn>;
  readonly clearAlarm: ReturnType<typeof vi.fn>;
  readonly logger: { warn: ReturnType<typeof vi.fn> };
  readonly timers: Map<number, TimerRecord>;
  setNow(value: number): void;
  queueStart(implementation: () => Promise<void>): void;
}

function request(
  requestId = REQUEST_A,
  overrides: Partial<DeviceLoginNotificationRequest> = {},
): DeviceLoginNotificationRequest {
  return {
    serverUrl: 'https://vault.example/base/',
    requestId,
    expiresAt: NOW + 10 * 60_000,
    ...overrides,
  };
}

function makeHarness(overrides: Partial<DeviceLoginNotificationsDeps> = {}): Harness {
  let currentTime = NOW;
  let timerId = 0;
  const timers = new Map<number, TimerRecord>();
  const connections: FakeConnection[] = [];
  const connectionOptions: DeviceLoginNotificationsConnectionOptions[] = [];
  const startImplementations: Array<() => Promise<void>> = [];
  const onSignal = vi.fn(async () => undefined);
  const createAlarm = vi.fn(async () => undefined);
  const clearAlarm = vi.fn(async () => true);
  const logger = { warn: vi.fn() };
  const defaults: DeviceLoginNotificationsDeps = {
    onSignal,
    alarms: { create: createAlarm, clear: clearAlarm },
    timers: {
      setTimeout: (callback, delayMs) => {
        const id = ++timerId;
        timers.set(id, { callback, delayMs });
        return id;
      },
      clearTimeout: (handle) => {
        timers.delete(handle as number);
      },
    },
    logger,
    now: () => currentTime,
    createConnection: (options) => {
      const connection = new FakeConnection();
      const implementation = startImplementations.shift();
      if (implementation) connection.start.mockImplementation(implementation);
      connections.push(connection);
      connectionOptions.push(options);
      return connection;
    },
  };
  const notifications = createDeviceLoginNotifications({ ...defaults, ...overrides });
  return {
    notifications,
    connections,
    connectionOptions,
    onSignal,
    createAlarm,
    clearAlarm,
    logger,
    timers,
    setNow: (value) => { currentTime = value; },
    queueStart: (implementation) => { startImplementations.push(implementation); },
  };
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await Promise.resolve();
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('device login anonymous hub URL', () => {
  it('preserves server and dedicated base paths and encodes one exact Token query', () => {
    const selfHosted = buildDeviceLoginAnonymousHubUrl(
      'https://vault.example/self-hosted/',
      REQUEST_A,
    );
    const dedicated = buildDedicatedDeviceLoginAnonymousHubUrl(
      'https://push.example/tenant/',
      REQUEST_A,
    );

    expect(selfHosted).toBe(
      `https://vault.example/self-hosted/notifications/anonymous-hub?Token=${REQUEST_A}`,
    );
    expect(dedicated).toBe(
      `https://push.example/tenant/anonymous-hub?Token=${REQUEST_A}`,
    );
    const parsed = new URL(dedicated);
    expect([...parsed.searchParams.keys()]).toEqual(['Token']);
    expect(parsed.searchParams.get('Token')).toBe(REQUEST_A);
  });

  it.each([
    'http://localhost:8080/vault/',
    'http://127.0.0.1:8080/',
    'http://[::1]:8080/',
  ])('allows only an exact loopback HTTP base: %s', (base) => {
    expect(buildDedicatedDeviceLoginAnonymousHubUrl(base, REQUEST_A)).toContain(
      '/anonymous-hub?Token=',
    );
  });

  it.each([
    'http://vault.example/',
    'http://127.0.0.2/',
    'http://sub.localhost/',
    'file:///tmp/',
    'https://@push.example/',
    'https://user:password@push.example/',
    'https://push.example/?old=1',
    'https://push.example/?',
    'https://push.example/#fragment',
    'https://push.example/#',
    ' https://push.example/',
    'https://push.example/\u0000',
  ])('rejects an insecure or ambiguous base without echoing it: %s', (base) => {
    expect(() => buildDedicatedDeviceLoginAnonymousHubUrl(base, REQUEST_A)).toThrow(
      /device login notifications/iu,
    );
    try {
      buildDedicatedDeviceLoginAnonymousHubUrl(base, REQUEST_A);
    } catch (error) {
      expect(String(error)).not.toContain(base);
    }
  });

  it.each([
    '00000000-0000-0000-0000-000000000000',
    '10000000-0000-9000-8000-000000000001',
    'abcdefab-cdef-4abc-8def-abcdefabcdef'.toUpperCase(),
    `${REQUEST_A}0`,
    `${REQUEST_A}\n`,
    `${REQUEST_A}\r\n`,
    `${REQUEST_A}\u0000`,
    'not-a-request-id',
  ])('rejects a non-canonical request UUID without echoing it: %s', (requestId) => {
    expect(() => buildDeviceLoginAnonymousHubUrl('https://vault.example/', requestId)).toThrow(
      'The device login request id is invalid',
    );
  });

  it('uses MessagePack over WebSockets without negotiation, automatic reconnect, or logging', () => {
    const configureLogging = vi.spyOn(HubConnectionBuilder.prototype, 'configureLogging');
    const withUrl = vi.spyOn(HubConnectionBuilder.prototype, 'withUrl');
    const withHubProtocol = vi.spyOn(HubConnectionBuilder.prototype, 'withHubProtocol');
    const withAutomaticReconnect = vi.spyOn(
      HubConnectionBuilder.prototype,
      'withAutomaticReconnect',
    );
    const hubUrl = `https://push.example/anonymous-hub?Token=${REQUEST_A}`;

    createDeviceLoginSignalRConnection({ hubUrl });

    expect(configureLogging).toHaveBeenCalledWith(LogLevel.None);
    const [url, rawOptions] = withUrl.mock.calls[0] ?? [];
    expect(url).toBe(hubUrl);
    expect(rawOptions as IHttpConnectionOptions).toMatchObject({
      logMessageContent: false,
      skipNegotiation: true,
      transport: HttpTransportType.WebSockets,
    });
    expect((rawOptions as IHttpConnectionOptions).accessTokenFactory).toBeUndefined();
    expect(withHubProtocol.mock.calls[0]?.[0]).toBeInstanceOf(MessagePackHubProtocol);
    expect(withAutomaticReconnect).not.toHaveBeenCalled();
  });
});

describe('DeviceLoginNotifications request lifecycle', () => {
  it('singleflights start and listens only to the exact payload-free official method', async () => {
    const starting = deferred<void>();
    const harness = makeHarness();
    harness.queueStart(() => starting.promise);

    const first = harness.notifications.start(request());
    const second = harness.notifications.start(request());
    expect(second).toBe(first);
    expect(harness.connections).toHaveLength(1);
    const connection = harness.connections[0]!;
    expect([...connection.handlers.keys()]).toEqual([DEVICE_LOGIN_NOTIFICATION_METHOD]);

    starting.resolve(undefined);
    await first;
    await harness.notifications.start(request());
    expect(harness.connections).toHaveLength(1);

    connection.emit('AuthRequestResponseReceived', { token: 'must-not-be-read' });
    expect(harness.onSignal).not.toHaveBeenCalled();
    connection.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { token: 'must-not-be-forwarded' });
    await flush();
    expect(harness.onSignal).toHaveBeenCalledOnce();
    expect(harness.onSignal).toHaveBeenCalledWith();
    expect(JSON.stringify(harness.onSignal.mock.calls)).not.toContain('must-not-be-forwarded');
  });

  it('coalesces signal bursts into one active GET wake-up and one trailing wake-up', async () => {
    const firstSignal = deferred<void>();
    const onSignal = vi.fn()
      .mockImplementationOnce(() => firstSignal.promise)
      .mockResolvedValue(undefined);
    const harness = makeHarness({ onSignal });
    await harness.notifications.start(request());

    const connection = harness.connections[0]!;
    connection.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { ignored: 1 });
    connection.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { ignored: 2 });
    connection.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { ignored: 3 });
    expect(onSignal).toHaveBeenCalledOnce();

    firstSignal.resolve(undefined);
    await flush();
    expect(onSignal).toHaveBeenCalledTimes(2);
    expect(onSignal).toHaveBeenNthCalledWith(1);
    expect(onSignal).toHaveBeenNthCalledWith(2);
  });

  it('invalidates old callbacks synchronously across an A-B-A request replacement', async () => {
    const harness = makeHarness();
    await harness.notifications.start(request(REQUEST_A));
    const firstA = harness.connections[0]!;
    await harness.notifications.start(request(REQUEST_B));
    const connectionB = harness.connections[1]!;
    await harness.notifications.start(request(REQUEST_A));
    const secondA = harness.connections[2]!;

    expect(firstA.stop).toHaveBeenCalledOnce();
    expect(connectionB.stop).toHaveBeenCalledOnce();
    firstA.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { stale: 'first-a' });
    connectionB.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { stale: 'b' });
    firstA.close(new Error(`late close ${REQUEST_A}`));
    connectionB.close(new Error(`late close ${REQUEST_B}`));
    await flush();
    expect(harness.onSignal).not.toHaveBeenCalled();
    expect(harness.createAlarm).not.toHaveBeenCalled();

    secondA.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { current: true });
    await flush();
    expect(harness.onSignal).toHaveBeenCalledOnce();
  });

  it('drops a late signal completion after replacing the request', async () => {
    const oldSignal = deferred<void>();
    const onSignal = vi.fn()
      .mockImplementationOnce(() => oldSignal.promise)
      .mockResolvedValue(undefined);
    const harness = makeHarness({ onSignal });
    await harness.notifications.start(request(REQUEST_A));
    harness.connections[0]!.emit(DEVICE_LOGIN_NOTIFICATION_METHOD);
    harness.connections[0]!.emit(DEVICE_LOGIN_NOTIFICATION_METHOD);
    expect(onSignal).toHaveBeenCalledOnce();

    await harness.notifications.start(request(REQUEST_B));
    oldSignal.resolve(undefined);
    await flush();
    expect(onSignal).toHaveBeenCalledOnce();
    expect(harness.logger.warn).not.toHaveBeenCalledWith('signal_failed');
  });

  it('stops idempotently while start is pending and never revives the retired connection', async () => {
    const starting = deferred<void>();
    const harness = makeHarness();
    harness.queueStart(() => starting.promise);
    const start = harness.notifications.start(request());
    await flush();
    const connection = harness.connections[0]!;

    const firstStop = harness.notifications.stop();
    const secondStop = harness.notifications.stop();
    expect(secondStop).toBe(firstStop);
    await firstStop;
    expect(connection.stop).toHaveBeenCalledOnce();

    connection.emit(DEVICE_LOGIN_NOTIFICATION_METHOD);
    connection.close(new Error('late close'));
    starting.resolve(undefined);
    await start;
    await flush();
    expect(harness.onSignal).not.toHaveBeenCalled();
    expect(harness.createAlarm).not.toHaveBeenCalled();
    expect(connection.stop).toHaveBeenCalledOnce();
  });

  it('rejects extra start fields without replacing a valid current request', async () => {
    const harness = makeHarness();
    await harness.notifications.start(request());
    const current = harness.connections[0]!;
    const malformed = { ...request(REQUEST_B), extra: true } as DeviceLoginNotificationRequest;

    expect(() => harness.notifications.start(malformed)).toThrow(
      'The device login notification request is invalid',
    );
    expect(current.stop).not.toHaveBeenCalled();
    expect(harness.connections).toHaveLength(1);
  });

  it('rejects accessors and symbols without invoking caller code', () => {
    const harness = makeHarness();
    let getterCalls = 0;
    const accessor = request() as unknown as Record<PropertyKey, unknown>;
    Object.defineProperty(accessor, 'requestId', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return REQUEST_A;
      },
    });
    const symbol = request() as unknown as Record<PropertyKey, unknown>;
    symbol[Symbol('extra')] = true;

    expect(() => harness.notifications.start(accessor as unknown as DeviceLoginNotificationRequest))
      .toThrow('The device login notification request is invalid');
    expect(() => harness.notifications.start(symbol as unknown as DeviceLoginNotificationRequest))
      .toThrow('The device login notification request is invalid');
    expect(getterCalls).toBe(0);
    expect(harness.connections).toHaveLength(0);
  });

  it.each([
    `${REQUEST_A}\n`,
    `${REQUEST_A}\r\n`,
    `${REQUEST_A}\u0000`,
  ])('rejects a control-suffixed request id before start: %j', (requestId) => {
    const harness = makeHarness();
    expect(() => harness.notifications.start(request(requestId))).toThrow(
      'The device login request id is invalid',
    );
    expect(harness.connections).toHaveLength(0);
    expect(harness.timers).toHaveLength(0);
  });

  it('reports only fixed codes for connection, signal, and stop failures', async () => {
    const sensitiveText = `sensitive-${REQUEST_A}`;
    const failed = makeHarness();
    failed.queueStart(async () => { throw new Error(sensitiveText); });

    await expect(failed.notifications.start(request())).rejects.toThrow(
      'Device login notification connection failed',
    );
    await flush();
    expect(failed.logger.warn).toHaveBeenCalledWith('connect_failed');
    expect(JSON.stringify(failed.logger.warn.mock.calls)).not.toContain(sensitiveText);

    const onSignal = vi.fn(async () => { throw new Error(sensitiveText); });
    const running = makeHarness({ onSignal });
    await running.notifications.start(request());
    running.connections[0]!.emit(DEVICE_LOGIN_NOTIFICATION_METHOD, { sensitiveText });
    await flush();
    expect(running.logger.warn).toHaveBeenCalledWith('signal_failed');
    running.connections[0]!.stop.mockRejectedValueOnce(new Error(sensitiveText));
    await running.notifications.stop();
    expect(running.logger.warn).toHaveBeenCalledWith('stop_failed');
    expect(JSON.stringify(running.logger.warn.mock.calls)).not.toContain(sensitiveText);
  });

  it('does not let a throwing logger alter lifecycle behavior', async () => {
    const logger = { warn: vi.fn(() => { throw new Error('logger failed'); }) };
    const harness = makeHarness({ logger });
    harness.queueStart(async () => { throw new Error('connection failed'); });
    await expect(harness.notifications.start(request())).rejects.toThrow(
      'Device login notification connection failed',
    );
    expect(logger.warn).toHaveBeenCalledWith('connect_failed');
  });

  it('freezes a dedicated URL and rejects an already expired request before connection creation', async () => {
    const harness = makeHarness();
    await harness.notifications.start(request(REQUEST_A, {
      notificationsUrl: 'https://push.example/tenant/',
    }));
    expect(harness.connectionOptions[0]?.hubUrl).toBe(
      `https://push.example/tenant/anonymous-hub?Token=${REQUEST_A}`,
    );

    expect(() => harness.notifications.start(request(REQUEST_B, {
      expiresAt: NOW,
    }))).toThrow('The device login notification request is invalid');
    expect(harness.connections).toHaveLength(1);
    expect(harness.connections[0]?.stop).not.toHaveBeenCalled();
  });

});

describe('DeviceLoginNotifications MV3 reconnect alarms', () => {
  it('schedules a generation-specific one-shot alarm and reconnects only on its exact event', async () => {
    const harness = makeHarness();
    await harness.notifications.start(request());
    harness.connections[0]!.close(new Error('offline'));
    harness.connections[0]!.close(new Error('duplicate close'));
    await flush();

    expect(harness.logger.warn).toHaveBeenCalledWith('connection_closed');
    expect(harness.createAlarm).toHaveBeenCalledOnce();
    const [alarmName, options] = harness.createAlarm.mock.calls[0]!;
    expect(alarmName).toMatch(new RegExp(`^${DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX}`));
    expect(alarmName).not.toContain(REQUEST_A);
    expect(options).toEqual({ when: NOW + BASE_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS });

    await harness.notifications.handleAlarm(alarmName);
    await harness.notifications.handleAlarm({ name: alarmName, scheduledTime: options.when + 1 });
    expect(harness.connections).toHaveLength(1);
    await harness.notifications.handleAlarm({ name: alarmName, scheduledTime: options.when });
    expect(harness.connections).toHaveLength(2);
  });

  it('never lets an alarm from a replaced request revive the current lifecycle', async () => {
    const harness = makeHarness();
    harness.queueStart(async () => { throw new Error('request A offline'); });
    await expect(harness.notifications.start(request(REQUEST_A))).rejects.toThrow();
    await flush();
    const [oldName, oldOptions] = harness.createAlarm.mock.calls[0]!;

    await harness.notifications.start(request(REQUEST_B));
    expect(harness.connections).toHaveLength(2);
    await harness.notifications.handleAlarm({
      name: oldName,
      scheduledTime: oldOptions.when,
    });
    expect(harness.connections).toHaveLength(2);
    expect(harness.clearAlarm).toHaveBeenCalledWith(oldName);
    harness.connections[1]!.emit(DEVICE_LOGIN_NOTIFICATION_METHOD);
    await flush();
    expect(harness.onSignal).toHaveBeenCalledOnce();
  });

  it('never lets an alarm revive a stopped request', async () => {
    const harness = makeHarness();
    await harness.notifications.start(request());
    harness.connections[0]!.close();
    await flush();
    const [alarmName, options] = harness.createAlarm.mock.calls[0]!;

    await harness.notifications.stop();
    await harness.notifications.handleAlarm({ name: alarmName, scheduledTime: options.when });
    expect(harness.connections).toHaveLength(1);
    expect(harness.clearAlarm).toHaveBeenCalledWith(alarmName);
  });

  it('stops instead of reconnecting when a valid alarm is delivered after expiresAt', async () => {
    const harness = makeHarness();
    const expiresAt = NOW + 60_000;
    await harness.notifications.start(request(REQUEST_A, { expiresAt }));
    harness.connections[0]!.close();
    await flush();
    const [alarmName, options] = harness.createAlarm.mock.calls[0]!;

    harness.setNow(expiresAt);
    await harness.notifications.handleAlarm({ name: alarmName, scheduledTime: options.when });
    expect(harness.connections).toHaveLength(1);
    expect(harness.clearAlarm).toHaveBeenCalledWith(alarmName);
  });

  it('deduplicates close-during-start and start failure into one retry alarm', async () => {
    let connection: FakeConnection | undefined;
    const createConnection = vi.fn((_options: DeviceLoginNotificationsConnectionOptions) => {
      connection = new FakeConnection();
      connection.start.mockImplementation(async () => {
        connection?.close(new Error('closed while starting'));
        throw new Error('start failed');
      });
      return connection;
    });
    const harness = makeHarness({ createConnection });

    await expect(harness.notifications.start(request())).rejects.toThrow(
      'Device login notification connection failed',
    );
    await flush();
    expect(harness.createAlarm).toHaveBeenCalledOnce();
  });

  it('caps consecutive reconnect attempts and never schedules beyond expiration', async () => {
    const createConnection = vi.fn((_options: DeviceLoginNotificationsConnectionOptions) => {
      const connection = new FakeConnection();
      connection.start.mockRejectedValue(new Error('offline'));
      return connection;
    });
    const harness = makeHarness({ createConnection });
    await expect(harness.notifications.start(request())).rejects.toThrow();
    await flush();

    for (let attempt = 0; attempt < MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ATTEMPTS; attempt++) {
      const call = harness.createAlarm.mock.calls[attempt];
      expect(call).toBeDefined();
      const [name, options] = call!;
      harness.setNow(options.when);
      await harness.notifications.handleAlarm({ name, scheduledTime: options.when });
      await flush();
    }

    expect(createConnection).toHaveBeenCalledTimes(
      MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ATTEMPTS + 1,
    );
    expect(harness.createAlarm).toHaveBeenCalledTimes(
      MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ATTEMPTS,
    );
  });

  it('does not create an alarm whose first delay reaches the request deadline', async () => {
    const harness = makeHarness();
    harness.queueStart(async () => { throw new Error('offline'); });
    await expect(harness.notifications.start(request(REQUEST_A, {
      expiresAt: NOW + BASE_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS,
    }))).rejects.toThrow();
    await flush();
    expect(harness.createAlarm).not.toHaveBeenCalled();

    const active = makeHarness();
    await active.notifications.start(request(REQUEST_A, {
      expiresAt: NOW + BASE_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS - 1,
    }));
    active.connections[0]!.close();
    await flush();
    expect(active.createAlarm).not.toHaveBeenCalled();
  });

  it('stops an active connection at expiresAt and ignores later signals and alarms', async () => {
    const harness = makeHarness();
    const expiresAt = NOW + 60_000;
    await harness.notifications.start(request(REQUEST_A, { expiresAt }));
    expect(harness.timers.size).toBe(1);
    const expiry = [...harness.timers.values()][0]!;
    expect(expiry.delayMs).toBe(60_000);

    harness.setNow(expiresAt);
    expiry.callback();
    await flush();
    expect(harness.connections[0]!.stop).toHaveBeenCalledOnce();
    harness.connections[0]!.emit(DEVICE_LOGIN_NOTIFICATION_METHOD);
    harness.connections[0]!.close();
    await flush();
    expect(harness.onSignal).not.toHaveBeenCalled();
    expect(harness.createAlarm).not.toHaveBeenCalled();
  });

  it('reports alarm failures with fixed codes and does not leak request identity', async () => {
    const logger = { warn: vi.fn() };
    const createAlarm = vi.fn(async () => { throw new Error(`failed ${REQUEST_A}`); });
    const harness = makeHarness({
      alarms: { create: createAlarm, clear: async () => true },
      logger,
    });
    await harness.notifications.start(request());
    harness.connections[0]!.close();
    await flush();
    expect(logger.warn).toHaveBeenCalledWith('alarm_failed');
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain(REQUEST_A);
  });

  it('clears a late alarm creation after a request is replaced', async () => {
    const alarmCreated = deferred<void>();
    const createAlarm = vi.fn<(
      name: string,
      options: { when: number },
    ) => Promise<void>>((_name, _options) => alarmCreated.promise);
    const clearAlarm = vi.fn(async () => true);
    const harness = makeHarness({ alarms: { create: createAlarm, clear: clearAlarm } });
    await harness.notifications.start(request(REQUEST_A));
    harness.connections[0]!.close();
    await vi.waitFor(() => expect(createAlarm).toHaveBeenCalledOnce());
    const [oldName, oldOptions] = createAlarm.mock.calls[0]!;

    await harness.notifications.start(request(REQUEST_B));
    expect(harness.connections).toHaveLength(2);
    alarmCreated.resolve(undefined);
    await flush();
    await vi.waitFor(() => expect(clearAlarm).toHaveBeenCalledWith(oldName));

    await harness.notifications.handleAlarm({
      name: oldName,
      scheduledTime: oldOptions.when,
    });
    expect(harness.connections).toHaveLength(2);
  });

});
