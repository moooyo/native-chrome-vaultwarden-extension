import {
  HttpTransportType,
  HubConnectionBuilder,
  LogLevel,
} from '@microsoft/signalr';
import { MessagePackHubProtocol } from '@microsoft/signalr-protocol-msgpack';
import type { AccountLease } from '../core/session/account-gate.js';

export const VAULT_NOTIFICATIONS_RECONNECT_ALARM = 'vault-notifications-reconnect';
export const BASE_NOTIFICATIONS_RECONNECT_DELAY_MS = 30_000;
export const MAX_NOTIFICATIONS_RECONNECT_DELAY_MS = 5 * 60_000;
export const NOTIFICATIONS_RECONNECT_JITTER_RATIO = 0.2;
export const MIN_NOTIFICATIONS_RECONNECT_DELAY_MS = Math.round(
  BASE_NOTIFICATIONS_RECONNECT_DELAY_MS * (1 - NOTIFICATIONS_RECONNECT_JITTER_RATIO),
);

export type VaultNotificationsLogEvent =
  | 'alarm_failed'
  | 'catch_up_failed'
  | 'connect_failed'
  | 'connection_closed'
  | 'notification_failed'
  | 'stop_failed';

export interface VaultNotificationsScheduler {
  notification(lease: AccountLease, message?: unknown): void;
  catchUp(lease: AccountLease): void | PromiseLike<void>;
}

export interface VaultNotificationsAlarmScheduler {
  create(name: string, options: { when: number }): void | PromiseLike<void>;
  clear(name: string): boolean | void | PromiseLike<boolean | void>;
}

export interface VaultNotificationsTimers {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface VaultNotificationsLogger {
  /** Only fixed event codes are accepted so URL and token-bearing errors cannot reach logs. */
  warn(event: VaultNotificationsLogEvent): void;
}

export interface NotificationsHubConnection {
  start(): Promise<void>;
  stop(): Promise<void>;
  on(methodName: string, handler: (...args: unknown[]) => unknown): void;
  onclose(handler: (error?: Error) => void): void;
}

export interface NotificationsConnectionOptions {
  readonly hubUrl: string;
  readonly accessTokenFactory: () => Promise<string>;
}

export type NotificationsConnectionFactory = (
  options: NotificationsConnectionOptions,
) => NotificationsHubConnection;

export interface VaultNotificationsDeps {
  getServerUrl(lease: AccountLease): string | PromiseLike<string>;
  /** Optional dedicated notifications origin, such as Bitwarden's cloud notifications host. */
  getNotificationsUrl?(lease: AccountLease): string | undefined | PromiseLike<string | undefined>;
  getAccessToken(lease: AccountLease): string | PromiseLike<string>;
  captureAccountLease(): AccountLease;
  assertAccountLease(lease: AccountLease): void;
  scheduler: VaultNotificationsScheduler;
  alarms: VaultNotificationsAlarmScheduler;
  timers?: VaultNotificationsTimers;
  logger?: VaultNotificationsLogger;
  now?: () => number;
  random?: () => number;
  createConnection?: NotificationsConnectionFactory;
}

interface ConnectionRun {
  readonly epoch: number;
  readonly lease: AccountLease;
  readonly connection: NotificationsHubConnection;
}

interface StartFlight {
  readonly epoch: number;
  readonly lease: AccountLease;
  readonly promise: Promise<void>;
}

/**
 * Build the HTTP(S) hub endpoint consumed by SignalR. With the WebSockets-only transport below,
 * SignalR upgrades HTTPS to WSS and loopback HTTP to WS without negotiating another transport.
 */
export function buildVaultNotificationsHubUrl(serverUrl: string): string {
  return buildHubUrl(serverUrl, 'notifications/hub');
}

/** Build a hub endpoint from an environment-provided notifications service base URL. */
export function buildDedicatedNotificationsHubUrl(notificationsUrl: string): string {
  return buildHubUrl(notificationsUrl, 'hub');
}

function buildHubUrl(baseUrl: string, suffix: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error('The notifications server URL is invalid');
  }

  const secure = url.protocol === 'https:';
  const loopback = url.protocol === 'http:' && isLoopbackHostname(url.hostname);
  if (!secure && !loopback) {
    throw new Error('Vault notifications require HTTPS or loopback HTTP');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('The notifications server URL must not contain credentials, query, or fragment');
  }

  const basePath = url.pathname.replace(/\/+$/u, '');
  url.pathname = `${basePath}/${suffix}`;
  return url.toString();
}

/** Create the production SignalR transport without exposing its protocol details to lifecycle code. */
export const createSignalRNotificationsConnection: NotificationsConnectionFactory = (options) => (
  new HubConnectionBuilder()
    .configureLogging(LogLevel.None)
    .withUrl(options.hubUrl, {
      accessTokenFactory: options.accessTokenFactory,
      logMessageContent: false,
      skipNegotiation: true,
      transport: HttpTransportType.WebSockets,
    })
    .withHubProtocol(new MessagePackHubProtocol())
    .build()
);

/**
 * Owns one account-bound notifications connection. Server messages remain opaque to the transport;
 * the account/session lifecycle above this adapter decides how each bounded message is handled.
 */
export class VaultNotifications {
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly createConnection: NotificationsConnectionFactory;
  private epoch = 0;
  private desired = false;
  private acceptAlarm = true;
  private active: ConnectionRun | undefined;
  private startFlight: StartFlight | undefined;
  private stopFlight: Promise<void> | undefined;
  private reconnectEpoch: number | undefined;
  private reconnectAttempt = 0;
  private alarmTail: Promise<void> = Promise.resolve();

  constructor(private readonly deps: VaultNotificationsDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.random = deps.random ?? (() => Math.random());
    this.createConnection = deps.createConnection ?? createSignalRNotificationsConnection;
  }

  start(): Promise<void> {
    return this.startAttempt(true);
  }

  private startAttempt(resetBackoff: boolean): Promise<void> {
    this.acceptAlarm = true;
    const currentFlight = this.startFlight;
    if (
      this.desired
      && currentFlight?.epoch === this.epoch
      && this.isAttemptCurrent(currentFlight.epoch, currentFlight.lease)
    ) {
      return currentFlight.promise;
    }
    if (this.desired && this.active && this.isRunCurrent(this.active)) return Promise.resolve();

    if (resetBackoff) this.reconnectAttempt = 0;
    this.desired = true;
    const epoch = ++this.epoch;
    const stale = this.active;
    this.active = undefined;
    if (stale) this.observeStop(stale.connection);
    this.cancelReconnect();
    this.queueAlarmClear();

    let lease: AccountLease;
    try {
      lease = this.deps.captureAccountLease();
    } catch {
      this.report('connect_failed');
      return Promise.reject(new Error('Vault notifications connection failed'));
    }

    const operation = this.startForEpoch(epoch, lease);
    const tracked: Promise<void> = operation.finally(() => {
      if (this.startFlight?.promise === tracked) this.startFlight = undefined;
    });
    this.startFlight = { epoch, lease, promise: tracked };
    return tracked;
  }

  stop(): Promise<void> {
    if (!this.desired && this.stopFlight) return this.stopFlight;

    this.desired = false;
    this.acceptAlarm = false;
    ++this.epoch;
    this.reconnectAttempt = 0;
    this.cancelReconnect();

    const run = this.active;
    this.active = undefined;
    const stopConnection = run ? this.stopConnection(run.connection) : Promise.resolve();
    const clearAlarm = this.queueAlarmClear();
    const operation = Promise.all([stopConnection, clearAlarm]).then(() => undefined);
    const tracked: Promise<void> = operation.finally(() => {
      if (this.stopFlight === tracked) this.stopFlight = undefined;
    });
    this.stopFlight = tracked;
    return tracked;
  }

  async handleAlarm(alarm: string | { name: string }): Promise<void> {
    const name = typeof alarm === 'string' ? alarm : alarm.name;
    if (name !== VAULT_NOTIFICATIONS_RECONNECT_ALARM) return;
    if (!this.acceptAlarm) {
      await this.queueAlarmClear();
      return;
    }

    this.cancelReconnect();
    this.reconnectEpoch = undefined;
    await this.queueAlarmClear();
    if (!this.acceptAlarm) return;
    await this.startAttempt(false);
  }

  private async startForEpoch(epoch: number, lease: AccountLease): Promise<void> {
    if (!this.isEpochCurrent(epoch)) return;

    let run: ConnectionRun | undefined;
    try {
      this.assertAttempt(epoch, lease);
      const serverUrl = await this.deps.getServerUrl(lease);
      this.assertAttempt(epoch, lease);
      if (serverUrl !== lease.serverUrl) {
        throw new Error('The notifications server does not match the account lease');
      }
      const notificationsUrlProvider = this.deps.getNotificationsUrl;
      const notificationsUrl = notificationsUrlProvider
        ? await notificationsUrlProvider(lease)
        : undefined;
      this.assertAttempt(epoch, lease);
      const hubUrl = notificationsUrl === undefined
        ? buildVaultNotificationsHubUrl(serverUrl)
        : buildDedicatedNotificationsHubUrl(notificationsUrl);
      const accessTokenFactory = async (): Promise<string> => {
        if (!run || !this.isRunCurrent(run)) {
          throw new Error('The notifications connection changed');
        }
        let token: string;
        try {
          token = await this.deps.getAccessToken(lease);
        } catch {
          throw new Error('The notifications access token is unavailable');
        }
        if (!this.isRunCurrent(run)) throw new Error('The notifications connection changed');
        if (!token.trim()) throw new Error('The notifications access token is empty');
        return token;
      };
      const connection = this.createConnection({ hubUrl, accessTokenFactory });
      const nextRun: ConnectionRun = { epoch, lease, connection };
      run = nextRun;
      connection.on('ReceiveMessage', (...args: unknown[]) => {
        this.receiveMessage(nextRun, args[0]);
      });
      connection.on('Heartbeat', (..._args: unknown[]) => undefined);
      connection.onclose((_error?: Error) => {
        this.connectionClosed(nextRun);
      });

      this.assertAttempt(epoch, lease);
      this.active = nextRun;
      await connection.start();
      if (!this.isRunCurrent(nextRun)) {
        if (this.active === nextRun) this.active = undefined;
        this.observeStop(connection);
        return;
      }

      this.cancelReconnect();
      this.reconnectEpoch = undefined;
      this.reconnectAttempt = 0;
      this.queueAlarmClear();
      void this.catchUp(nextRun);
    } catch {
      if (run && this.active === run) this.active = undefined;
      if (run) this.observeStop(run.connection);
      if (this.isAttemptCurrent(epoch, lease)) {
        this.report('connect_failed');
        this.scheduleReconnect(epoch, lease);
      }
      throw new Error('Vault notifications connection failed');
    }
  }

  private receiveMessage(run: ConnectionRun, message: unknown): void {
    if (!this.isRunCurrent(run)) return;
    try {
      this.deps.scheduler.notification(run.lease, message);
    } catch {
      this.report('notification_failed');
    }
  }

  private connectionClosed(run: ConnectionRun): void {
    if (!this.isRunCurrent(run)) return;
    this.active = undefined;
    if (this.startFlight?.epoch === run.epoch) this.startFlight = undefined;
    this.report('connection_closed');
    this.scheduleReconnect(run.epoch, run.lease);
  }

  private async catchUp(run: ConnectionRun): Promise<void> {
    if (!this.isRunCurrent(run)) return;
    try {
      await this.deps.scheduler.catchUp(run.lease);
    } catch {
      if (this.isRunCurrent(run)) this.report('catch_up_failed');
    }
  }

  private scheduleReconnect(epoch: number, lease: AccountLease): void {
    if (!this.isAttemptCurrent(epoch, lease) || this.reconnectEpoch === epoch) return;
    this.reconnectEpoch = epoch;
    const attempt = this.reconnectAttempt;
    this.reconnectAttempt = Math.min(attempt + 1, 31);
    const delayMs = reconnectDelay(attempt, this.random());
    const when = this.now() + delayMs;

    this.queueAlarm(async () => {
      if (!this.isAttemptCurrent(epoch, lease) || this.reconnectEpoch !== epoch) return;
      await this.deps.alarms.create(VAULT_NOTIFICATIONS_RECONNECT_ALARM, { when });
      if (!this.isAttemptCurrent(epoch, lease) || this.reconnectEpoch !== epoch) {
        await this.deps.alarms.clear(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
      }
    });
  }

  private cancelReconnect(): void {
    this.reconnectEpoch = undefined;
  }

  private queueAlarmClear(): Promise<void> {
    return this.queueAlarm(async () => {
      await this.deps.alarms.clear(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
    });
  }

  private queueAlarm(operation: () => void | PromiseLike<void>): Promise<void> {
    const pending = this.alarmTail.then(async () => {
      try {
        await operation();
      } catch {
        this.report('alarm_failed');
      }
    });
    this.alarmTail = pending;
    return pending;
  }

  private isEpochCurrent(epoch: number): boolean {
    return this.desired && this.epoch === epoch;
  }

  private assertAttempt(epoch: number, lease: AccountLease): void {
    if (!this.isEpochCurrent(epoch)) throw new Error('The notifications lifecycle changed');
    this.deps.assertAccountLease(lease);
  }

  private isAttemptCurrent(epoch: number, lease: AccountLease): boolean {
    if (!this.isEpochCurrent(epoch)) return false;
    try {
      this.deps.assertAccountLease(lease);
      return true;
    } catch {
      return false;
    }
  }

  private isRunCurrent(run: ConnectionRun): boolean {
    return this.active === run && this.isAttemptCurrent(run.epoch, run.lease);
  }

  private observeStop(connection: NotificationsHubConnection): void {
    void this.stopConnection(connection);
  }

  private async stopConnection(connection: NotificationsHubConnection): Promise<void> {
    try {
      await connection.stop();
    } catch {
      this.report('stop_failed');
    }
  }

  private report(event: VaultNotificationsLogEvent): void {
    try {
      this.deps.logger?.warn(event);
    } catch {
      // Logging must never interfere with connection recovery.
    }
  }
}

export function createVaultNotifications(deps: VaultNotificationsDeps): VaultNotifications {
  return new VaultNotifications(deps);
}

function reconnectDelay(attempt: number, random: number): number {
  const boundedAttempt = Number.isSafeInteger(attempt) ? Math.min(31, Math.max(0, attempt)) : 0;
  const bounded = Number.isFinite(random) ? Math.min(1, Math.max(0, random)) : 0.5;
  const nominal = Math.min(
    MAX_NOTIFICATIONS_RECONNECT_DELAY_MS,
    BASE_NOTIFICATIONS_RECONNECT_DELAY_MS * (2 ** boundedAttempt),
  );
  const jitter = 1 - NOTIFICATIONS_RECONNECT_JITTER_RATIO
    + (2 * NOTIFICATIONS_RECONNECT_JITTER_RATIO * bounded);
  return Math.min(MAX_NOTIFICATIONS_RECONNECT_DELAY_MS, Math.round(nominal * jitter));
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;
  if (normalized === '::1' || normalized === '[::1]') return true;
  const octets = normalized.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255);
}
