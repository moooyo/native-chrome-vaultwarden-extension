import {
  HttpTransportType,
  HubConnectionBuilder,
  LogLevel,
} from '@microsoft/signalr';
import { MessagePackHubProtocol } from '@microsoft/signalr-protocol-msgpack';
import type {
  NotificationsHubConnection,
  VaultNotificationsAlarmScheduler,
  VaultNotificationsTimers,
} from './vault-notifications.js';

export const DEVICE_LOGIN_NOTIFICATION_METHOD = 'AuthRequestResponseRecieved';
export const DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX =
  'device-login-notifications-reconnect:';
export const BASE_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS = 5_000;
export const MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS = 60_000;
export const MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ATTEMPTS = 5;

const MAX_URL_LENGTH = 4_096;
const MAX_ALARM_NAME_LENGTH = 160;
const MAX_TIMER_DELAY_MS = 0x7fff_ffff;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type DeviceLoginNotificationsLogEvent =
  | 'alarm_failed'
  | 'connect_failed'
  | 'connection_closed'
  | 'signal_failed'
  | 'stop_failed';

export interface DeviceLoginNotificationsLogger {
  /** Fixed codes only: URL, request id, payload, and error text never cross this boundary. */
  warn(event: DeviceLoginNotificationsLogEvent): void;
}

export interface DeviceLoginNotificationRequest {
  readonly serverUrl: string;
  /** Dedicated notifications service base. Omit for self-hosted `{server}/notifications`. */
  readonly notificationsUrl?: string;
  readonly requestId: string;
  readonly expiresAt: number;
}

export interface DeviceLoginNotificationsConnectionOptions {
  readonly hubUrl: string;
}

export type DeviceLoginNotificationsConnectionFactory = (
  options: DeviceLoginNotificationsConnectionOptions,
) => NotificationsHubConnection;

export interface DeviceLoginNotificationsDeps {
  /** Payload-free wake-up. The owner performs the authoritative auth-request GET. */
  onSignal(): void | PromiseLike<void>;
  readonly alarms: VaultNotificationsAlarmScheduler;
  readonly timers?: VaultNotificationsTimers;
  readonly logger?: DeviceLoginNotificationsLogger;
  readonly now?: () => number;
  readonly createConnection?: DeviceLoginNotificationsConnectionFactory;
}

export interface DeviceLoginNotificationsAlarm {
  readonly name: string;
  /** Chrome supplies this for an alarms.onAlarm event. It binds one exact retry attempt. */
  readonly scheduledTime?: number;
}

interface CanonicalRequest {
  readonly requestId: string;
  readonly expiresAt: number;
  readonly hubUrl: string;
}

interface ExpectedAlarm {
  readonly when: number;
}

interface NotificationRun {
  readonly generation: number;
  readonly request: CanonicalRequest;
  readonly alarmName: string;
  connection?: NotificationsHubConnection;
  startFlight?: Promise<void>;
  expectedAlarm?: ExpectedAlarm;
  expiryTimer?: unknown;
  reconnectAttempt: number;
  signalFlight?: Promise<void>;
  signalPending: boolean;
}

const DEFAULT_TIMERS: VaultNotificationsTimers = Object.freeze({
  setTimeout(callback: () => void, delayMs: number): unknown {
    return globalThis.setTimeout(callback, delayMs);
  },
  clearTimeout(handle: unknown): void {
    globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
});

/** Build the self-hosted anonymous hub under the canonical server's notifications route. */
export function buildDeviceLoginAnonymousHubUrl(
  serverUrl: string,
  requestId: string,
): string {
  return buildAnonymousHubUrl(serverUrl, 'notifications/anonymous-hub', requestId);
}

/** Build the anonymous hub under a dedicated notifications service base URL. */
export function buildDedicatedDeviceLoginAnonymousHubUrl(
  notificationsUrl: string,
  requestId: string,
): string {
  return buildAnonymousHubUrl(notificationsUrl, 'anonymous-hub', requestId);
}

function buildAnonymousHubUrl(baseUrl: string, suffix: string, requestId: string): string {
  const canonicalRequestId = requireRequestId(requestId);
  const url = parseNotificationsBase(baseUrl);
  const basePath = url.pathname.replace(/\/+$/u, '');
  url.pathname = `${basePath}/${suffix}`;
  const query = new URLSearchParams();
  query.set('Token', canonicalRequestId);
  url.search = query.toString();
  return url.toString();
}

/** Official anonymous MessagePack SignalR transport with all client logging disabled. */
export const createDeviceLoginSignalRConnection: DeviceLoginNotificationsConnectionFactory = (
  options,
) => (
  new HubConnectionBuilder()
    .configureLogging(LogLevel.None)
    .withUrl(options.hubUrl, {
      logMessageContent: false,
      skipNegotiation: true,
      transport: HttpTransportType.WebSockets,
    })
    .withHubProtocol(new MessagePackHubProtocol())
    .build()
);

/**
 * Owns the anonymous notification connection for exactly one current device-login request.
 * Every async boundary rechecks a monotonic generation; SignalR payloads are never interpreted.
 */
export class DeviceLoginNotifications {
  private readonly now: () => number;
  private readonly timers: VaultNotificationsTimers;
  private readonly createConnection: DeviceLoginNotificationsConnectionFactory;
  private readonly instanceId: string;
  private readonly stopping = new WeakSet<NotificationsHubConnection>();
  private generation = 0;
  private run: NotificationRun | undefined;
  private stopFlight: Promise<void> | undefined;
  private alarmTail: Promise<void> = Promise.resolve();

  constructor(private readonly deps: DeviceLoginNotificationsDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.timers = deps.timers ?? DEFAULT_TIMERS;
    this.createConnection = deps.createConnection ?? createDeviceLoginSignalRConnection;
    this.instanceId = globalThis.crypto.randomUUID();
  }

  start(input: DeviceLoginNotificationRequest): Promise<void> {
    const request = canonicalizeRequest(input, this.now());
    const current = this.run;
    if (current && this.isCurrent(current) && sameRequest(current.request, request)) {
      if (current.startFlight) return current.startFlight;
      return Promise.resolve();
    }

    const generation = ++this.generation;
    this.run = undefined;
    if (current) this.retireRun(current);

    const run: NotificationRun = {
      generation,
      request,
      alarmName: `${DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX}${this.instanceId}:${generation}`,
      reconnectAttempt: 0,
      signalPending: false,
    };
    this.run = run;
    this.scheduleExpiry(run);
    return this.connect(run, true);
  }

  stop(): Promise<void> {
    const run = this.run;
    if (!run) return this.stopFlight ?? Promise.resolve();

    ++this.generation;
    this.run = undefined;
    this.cancelExpiry(run);
    const connection = run.connection;
    delete run.connection;
    delete run.expectedAlarm;
    run.signalPending = false;

    const operation = Promise.all([
      connection ? this.stopConnection(connection) : Promise.resolve(),
      this.clearAlarm(run.alarmName),
    ]).then(() => undefined);
    const tracked = operation.finally(() => {
      if (this.stopFlight === tracked) this.stopFlight = undefined;
    });
    this.stopFlight = tracked;
    return tracked;
  }

  async handleAlarm(alarm: string | DeviceLoginNotificationsAlarm): Promise<void> {
    const event = typeof alarm === 'string' ? { name: alarm } : alarm;
    if (
      typeof event?.name !== 'string'
      || event.name.length > MAX_ALARM_NAME_LENGTH
      || !event.name.startsWith(DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX)
    ) return;
    const run = this.run;
    if (!run || !this.isCurrent(run) || event.name !== run.alarmName) {
      await this.clearAlarm(event.name);
      return;
    }
    const expected = run.expectedAlarm;
    if (
      !expected
      || event.scheduledTime === undefined
      || event.scheduledTime !== expected.when
    ) return;

    delete run.expectedAlarm;
    if (this.hasExpired(run)) {
      await this.stopIfCurrent(run);
      return;
    }
    if (run.connection || run.startFlight) return;
    try {
      await this.connect(run, false);
    } catch {
      // connect() reports a fixed event and schedules the next bounded attempt.
    }
  }

  private connect(run: NotificationRun, resetBackoff: boolean): Promise<void> {
    if (!this.isCurrent(run)) return Promise.resolve();
    if (this.hasExpired(run)) {
      void this.stopIfCurrent(run);
      return Promise.reject(new Error('Device login notification request expired'));
    }
    if (run.startFlight) return run.startFlight;
    if (run.connection) return Promise.resolve();
    if (resetBackoff) run.reconnectAttempt = 0;

    const operation = this.connectRun(run);
    const tracked = operation.finally(() => {
      if (run.startFlight === tracked) delete run.startFlight;
    });
    run.startFlight = tracked;
    return tracked;
  }

  private async connectRun(run: NotificationRun): Promise<void> {
    let connection: NotificationsHubConnection | undefined;
    try {
      this.assertCurrent(run);
      connection = this.createConnection({ hubUrl: run.request.hubUrl });
      run.connection = connection;
      connection.on(DEVICE_LOGIN_NOTIFICATION_METHOD, (..._args: unknown[]) => {
        this.receiveSignal(run, connection!);
      });
      connection.onclose((_error?: Error) => {
        this.connectionClosed(run, connection!);
      });
      this.assertCurrent(run);
      await connection.start();
      if (!this.isConnectionCurrent(run, connection)) {
        if (run.connection === connection) delete run.connection;
        await this.stopConnection(connection);
        return;
      }
      run.reconnectAttempt = 0;
      delete run.expectedAlarm;
    } catch {
      if (connection && run.connection === connection) delete run.connection;
      if (connection) void this.stopConnection(connection);
      if (this.isCurrent(run) && !this.hasExpired(run)) {
        this.report('connect_failed');
        this.scheduleReconnect(run);
      }
      throw new Error('Device login notification connection failed');
    }
  }

  private receiveSignal(run: NotificationRun, connection: NotificationsHubConnection): void {
    if (!this.isConnectionCurrent(run, connection)) return;
    if (this.hasExpired(run)) {
      void this.stopIfCurrent(run);
      return;
    }
    if (run.signalFlight) {
      run.signalPending = true;
      return;
    }

    const operation = (async () => {
      try {
        this.assertCurrent(run);
        await this.deps.onSignal();
        this.assertCurrent(run);
      } catch {
        if (this.isCurrent(run) && !this.hasExpired(run)) this.report('signal_failed');
      }
    })();
    const tracked = operation.finally(() => {
      if (run.signalFlight !== tracked) return;
      delete run.signalFlight;
      if (!run.signalPending || !this.isConnectionCurrent(run, connection)) return;
      run.signalPending = false;
      this.receiveSignal(run, connection);
    });
    run.signalFlight = tracked;
  }

  private connectionClosed(
    run: NotificationRun,
    connection: NotificationsHubConnection,
  ): void {
    if (!this.isConnectionCurrent(run, connection)) return;
    delete run.connection;
    if (this.hasExpired(run)) {
      void this.stopIfCurrent(run);
      return;
    }
    this.report('connection_closed');
    this.scheduleReconnect(run);
  }

  private scheduleReconnect(run: NotificationRun): void {
    if (
      !this.isCurrent(run)
      || this.hasExpired(run)
      || run.expectedAlarm
      || run.reconnectAttempt >= MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ATTEMPTS
    ) return;

    const attempt = run.reconnectAttempt;
    const delay = Math.min(
      MAX_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS,
      BASE_DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_DELAY_MS * (2 ** attempt),
    );
    const when = this.now() + delay;
    if (!Number.isSafeInteger(when) || when >= run.request.expiresAt) return;

    run.reconnectAttempt = attempt + 1;
    const expected: ExpectedAlarm = Object.freeze({ when });
    run.expectedAlarm = expected;
    void this.queueAlarm(async () => {
      if (!this.isCurrent(run) || run.expectedAlarm !== expected) return;
      try {
        await this.deps.alarms.create(run.alarmName, { when });
      } catch {
        if (this.isCurrent(run) && run.expectedAlarm === expected) {
          delete run.expectedAlarm;
          this.report('alarm_failed');
        }
        return;
      }
      if (!this.isCurrent(run) || run.expectedAlarm !== expected) {
        try {
          await this.deps.alarms.clear(run.alarmName);
        } catch {
          this.report('alarm_failed');
        }
      }
    });
  }

  private scheduleExpiry(run: NotificationRun): void {
    const delay = Math.min(
      MAX_TIMER_DELAY_MS,
      Math.max(0, run.request.expiresAt - this.now()),
    );
    run.expiryTimer = this.timers.setTimeout(() => {
      delete run.expiryTimer;
      if (!this.isCurrent(run)) return;
      if (this.hasExpired(run)) void this.stopIfCurrent(run);
      else this.scheduleExpiry(run);
    }, delay);
  }

  private cancelExpiry(run: NotificationRun): void {
    if (run.expiryTimer === undefined) return;
    this.timers.clearTimeout(run.expiryTimer);
    delete run.expiryTimer;
  }

  private retireRun(run: NotificationRun): void {
    this.cancelExpiry(run);
    delete run.expectedAlarm;
    run.signalPending = false;
    const connection = run.connection;
    delete run.connection;
    if (connection) void this.stopConnection(connection);
    void this.clearAlarm(run.alarmName);
  }

  private async stopIfCurrent(run: NotificationRun): Promise<void> {
    if (!this.isCurrent(run)) return;
    await this.stop();
  }

  private stopConnection(connection: NotificationsHubConnection): Promise<void> {
    if (this.stopping.has(connection)) return Promise.resolve();
    this.stopping.add(connection);
    return connection.stop().catch(() => {
      this.report('stop_failed');
    });
  }

  private clearAlarm(name: string): Promise<void> {
    return this.queueAlarm(async () => {
      try {
        await this.deps.alarms.clear(name);
      } catch {
        this.report('alarm_failed');
      }
    });
  }

  private queueAlarm(operation: () => void | PromiseLike<void>): Promise<void> {
    const pending = this.alarmTail.then(operation, operation).then(() => undefined);
    this.alarmTail = pending.catch(() => undefined);
    return pending;
  }

  private assertCurrent(run: NotificationRun): void {
    if (!this.isCurrent(run) || this.hasExpired(run)) {
      throw new Error('Device login notification lifecycle changed');
    }
  }

  private isCurrent(run: NotificationRun): boolean {
    return this.run === run && run.generation === this.generation;
  }

  private isConnectionCurrent(
    run: NotificationRun,
    connection: NotificationsHubConnection,
  ): boolean {
    return this.isCurrent(run) && run.connection === connection;
  }

  private hasExpired(run: NotificationRun): boolean {
    return this.now() >= run.request.expiresAt;
  }

  private report(event: DeviceLoginNotificationsLogEvent): void {
    try {
      this.deps.logger?.warn(event);
    } catch {
      // Diagnostics never alter request lifecycle behavior.
    }
  }
}

export function createDeviceLoginNotifications(
  deps: DeviceLoginNotificationsDeps,
): DeviceLoginNotifications {
  return new DeviceLoginNotifications(deps);
}

function canonicalizeRequest(
  input: DeviceLoginNotificationRequest,
  now: number,
): CanonicalRequest {
  if (!isPlainRecord(input)) invalidRequest();
  const keys = Reflect.ownKeys(input);
  const allowed = new Set(['serverUrl', 'notificationsUrl', 'requestId', 'expiresAt']);
  if (
    keys.some((key) => typeof key !== 'string' || !allowed.has(key))
    || !Object.hasOwn(input, 'serverUrl')
    || !Object.hasOwn(input, 'requestId')
    || !Object.hasOwn(input, 'expiresAt')
  ) invalidRequest();
  const requestId = requireRequestId(input.requestId);
  if (!Number.isSafeInteger(now) || now < 0) invalidRequest();
  if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now) invalidRequest();
  const serverUrl = requireBaseString(input.serverUrl);
  parseNotificationsBase(serverUrl);
  const hubUrl = Object.hasOwn(input, 'notificationsUrl')
    ? buildDedicatedDeviceLoginAnonymousHubUrl(
        requireBaseString(input.notificationsUrl),
        requestId,
      )
    : buildDeviceLoginAnonymousHubUrl(serverUrl, requestId);
  return Object.freeze({ requestId, expiresAt: input.expiresAt, hubUrl });
}

function requireBaseString(value: unknown): string {
  if (typeof value !== 'string') invalidRequest();
  return value;
}

function requireRequestId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 36 || !UUID_PATTERN.test(value)) {
    throw new Error('The device login request id is invalid');
  }
  return value;
}

function parseNotificationsBase(value: string): URL {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_URL_LENGTH
    || value.trim() !== value
    || containsControlCharacter(value)
    || value.includes('?')
    || value.includes('#')
    || /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/iu.test(value)
  ) throw new Error('The device login notifications URL is invalid');

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('The device login notifications URL is invalid');
  }
  const secure = url.protocol === 'https:';
  const loopback = url.protocol === 'http:' && (
    url.hostname === 'localhost'
    || url.hostname === '127.0.0.1'
    || url.hostname === '[::1]'
  );
  if (!secure && !loopback) {
    throw new Error('Device login notifications require HTTPS or exact loopback HTTP');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('The device login notifications URL is ambiguous');
  }
  return url;
}

function sameRequest(left: CanonicalRequest, right: CanonicalRequest): boolean {
  return left.requestId === right.requestId
    && left.expiresAt === right.expiresAt
    && left.hubUrl === right.hubUrl;
}

function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value !== undefined);
  });
}

function invalidRequest(): never {
  throw new Error('The device login notification request is invalid');
}
