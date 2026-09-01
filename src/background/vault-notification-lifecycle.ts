import type { AccountLease } from '../core/session/account-gate.js';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';
import {
  createVaultNotifications,
  type NotificationsConnectionFactory,
  type VaultNotificationsAlarmScheduler,
  type VaultNotificationsLogEvent,
  type VaultNotificationsTimers,
} from './vault-notifications.js';

const MAX_NOTIFICATION_TYPE = 255;
const MAX_CONTEXT_ID_LENGTH = 256;
const MAX_CONNECTION_URL_LENGTH = 4_096;

export const VAULT_NOTIFICATION_TYPE = Object.freeze({
  SyncCipherUpdate: 0,
  SyncCipherCreate: 1,
  SyncLoginDelete: 2,
  SyncFolderDelete: 3,
  SyncCiphers: 4,
  SyncVault: 5,
  SyncOrgKeys: 6,
  SyncFolderCreate: 7,
  SyncFolderUpdate: 8,
  SyncCipherDelete: 9,
  SyncSettings: 10,
  LogOut: 11,
  SyncSendCreate: 12,
  SyncSendUpdate: 13,
  SyncSendDelete: 14,
  AuthRequest: 15,
  AuthRequestResponse: 16,
  SyncOrganizations: 17,
  SyncOrganizationStatusChanged: 18,
  SyncOrganizationCollectionSettingChanged: 19,
  Notification: 20,
  NotificationStatus: 21,
  RefreshSecurityTasks: 22,
  OrganizationBankAccountVerified: 23,
  ProviderBankAccountVerified: 24,
  SyncPolicy: 25,
  AutoConfirmMember: 26,
  PremiumStatusChanged: 27,
} as const);

// The extension uses a full coalesced sync instead of applying partially trusted incremental
// payloads for these official Bitwarden notification types.
const VAULT_NOTIFICATION_TYPES: ReadonlySet<number> = new Set([
  VAULT_NOTIFICATION_TYPE.SyncCipherUpdate,
  VAULT_NOTIFICATION_TYPE.SyncCipherCreate,
  VAULT_NOTIFICATION_TYPE.SyncLoginDelete,
  VAULT_NOTIFICATION_TYPE.SyncFolderDelete,
  VAULT_NOTIFICATION_TYPE.SyncCiphers,
  VAULT_NOTIFICATION_TYPE.SyncVault,
  VAULT_NOTIFICATION_TYPE.SyncOrgKeys,
  VAULT_NOTIFICATION_TYPE.SyncFolderCreate,
  VAULT_NOTIFICATION_TYPE.SyncFolderUpdate,
  VAULT_NOTIFICATION_TYPE.SyncCipherDelete,
  VAULT_NOTIFICATION_TYPE.SyncSettings,
  VAULT_NOTIFICATION_TYPE.SyncSendCreate,
  VAULT_NOTIFICATION_TYPE.SyncSendUpdate,
  VAULT_NOTIFICATION_TYPE.SyncSendDelete,
  VAULT_NOTIFICATION_TYPE.SyncOrganizations,
  VAULT_NOTIFICATION_TYPE.SyncOrganizationStatusChanged,
  VAULT_NOTIFICATION_TYPE.SyncOrganizationCollectionSettingChanged,
  VAULT_NOTIFICATION_TYPE.SyncPolicy,
]);
const KNOWN_NOTIFICATION_TYPES: ReadonlySet<number> = new Set(
  Object.values(VAULT_NOTIFICATION_TYPE),
);

export interface VaultNotificationLeases {
  readonly accountLease: AccountLease;
}

export interface VaultNotificationServerUrls {
  /** Canonical configured server URL; it must exactly match the captured account lease. */
  readonly serverUrl: string;
  /** A dedicated notifications origin when the deployment does not colocate notifications. */
  readonly notificationsUrl?: string;
}

export interface VaultNotificationLifecycleScheduler {
  notification(leases: VaultNotificationLeases): void;
  catchUp(leases: VaultNotificationLeases): void | PromiseLike<void>;
}

export type VaultNotificationLifecycleLogEvent =
  | VaultNotificationsLogEvent
  | 'auth_request_failed'
  | 'lifecycle_catch_up_failed'
  | 'lifecycle_start_failed'
  | 'logout_failed';

export interface VaultNotificationLifecycleLogger {
  /** Fixed event codes only. Errors, URLs, tokens, and server message bodies are never accepted. */
  warn(event: VaultNotificationLifecycleLogEvent): void;
}

export interface VaultNotificationLifecycleDeps {
  captureAccountLease(): AccountLease;
  assertAccountLease(lease: AccountLease): void;
  getServerUrls(leases: VaultNotificationLeases):
    | VaultNotificationServerUrls
    | PromiseLike<VaultNotificationServerUrls>;
  getDeviceIdentifier(leases: VaultNotificationLeases): string | PromiseLike<string>;
  getAccessToken(leases: VaultNotificationLeases): string | PromiseLike<string>;
  logout(leases: VaultNotificationLeases): void | PromiseLike<void>;
  /** Payload-free signal used by a future device-login service to fetch authoritative requests. */
  authRequest?(leases: VaultNotificationLeases): void | PromiseLike<void>;
  scheduler: VaultNotificationLifecycleScheduler;
  alarms: VaultNotificationsAlarmScheduler;
  timers?: VaultNotificationsTimers;
  logger?: VaultNotificationLifecycleLogger;
  now?: () => number;
  random?: () => number;
  createConnection?: NotificationsConnectionFactory;
}

interface ConnectionContext {
  readonly serverUrl: string;
  readonly notificationsUrl?: string;
  readonly deviceIdentifier: string;
}

interface LifecycleRun {
  readonly generation: number;
  readonly leases: VaultNotificationLeases;
  activation?: Promise<void>;
  deviceIdentifier?: string;
  deviceIdentifierFlight?: Promise<string>;
  connectionContext?: {
    readonly value: ConnectionContext;
    remainingReaders: number;
  };
  contextFlight?: Promise<ConnectionContext>;
  catchUpFlight?: Promise<void>;
  catchUpPending: boolean;
  logoutIssued: boolean;
  authRequestFlight?: Promise<void>;
  authRequestPending: boolean;
}

interface ParsedNotification {
  readonly type: number;
  readonly contextId?: string;
}

type OwnValue =
  | { readonly kind: 'absent' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'value'; readonly value: unknown };

/**
 * Binds the SignalR transport to one authenticated account generation. Vault lock state is
 * deliberately not part of this lease: encrypted sync and remote logout notifications must remain
 * available while secrets are locked. Identity transitions still invalidate callbacks synchronously,
 * and a monotonic generation prevents an A-B-A account or server sequence from reviving an old run.
 */
export class VaultNotificationLifecycle {
  private readonly notifications: ReturnType<typeof createVaultNotifications>;
  private generation = 0;
  private latestTransitionId = 0;
  private pendingTransition: { readonly id: number; readonly generation: number } | undefined;
  private run: LifecycleRun | undefined;

  constructor(private readonly deps: VaultNotificationLifecycleDeps) {
    this.notifications = createVaultNotifications({
      captureAccountLease: () => this.requireCurrentRun().leases.accountLease,
      assertAccountLease: (accountLease) => {
        const run = this.requireCurrentRun();
        if (run.leases.accountLease !== accountLease) {
          throw new Error('The notification account lease changed');
        }
        this.assertCurrent(run);
      },
      getServerUrl: async (accountLease) => (
        await this.contextForAccountLease(accountLease)
      ).serverUrl,
      getNotificationsUrl: async (accountLease) => (
        await this.contextForAccountLease(accountLease)
      ).notificationsUrl,
      getAccessToken: (accountLease) => this.accessTokenForAccountLease(accountLease),
      scheduler: {
        notification: (accountLease, message) => {
          this.receiveMessage(accountLease, message);
        },
        catchUp: (accountLease) => this.catchUpForAccountLease(accountLease),
      },
      alarms: deps.alarms,
      ...(deps.timers ? { timers: deps.timers } : {}),
      ...(deps.logger ? { logger: { warn: (event) => this.report(event) } } : {}),
      ...(deps.now ? { now: deps.now } : {}),
      ...(deps.random ? { random: deps.random } : {}),
      ...(deps.createConnection ? { createConnection: deps.createConnection } : {}),
    });
  }

  /** Restore a worker by reconciling authoritative state before opening the notification gap. */
  startup(): Promise<void> {
    return this.activate(true);
  }

  /** Start for the current authenticated account. Connection failures never reject auth. */
  start(): Promise<void> {
    return this.activate(false);
  }

  /** Invalidate callbacks immediately, then stop the account transport in the background. */
  stop(): Promise<void> {
    this.generation++;
    this.pendingTransition = undefined;
    this.run = undefined;
    return this.stopTransport();
  }

  /**
   * This hook is safe to invoke beside SessionGate.handleTransition. Identity-changing starts revoke
   * the account transport synchronously; lock and unlock transitions leave it connected.
   */
  handleSessionTransition(event: SessionTransitionEvent): void {
    if (event.phase === 'start') {
      if (!invalidatesNotificationAccount(event.reason)) return;
      if (event.transitionId <= this.latestTransitionId) return;
      this.latestTransitionId = event.transitionId;
      void this.stop();
      this.pendingTransition = { id: event.transitionId, generation: this.generation };
      return;
    }
    if (!invalidatesNotificationAccount(event.reason)) return;
    const pending = this.pendingTransition;
    if (
      event.transitionId !== this.latestTransitionId
      || pending?.id !== event.transitionId
      || pending.generation !== this.generation
    ) return;
    this.pendingTransition = undefined;
    if (event.state === 'loggedOut' || event.state === 'restricted') return;
    void this.start();
  }

  /** Route the persistent MV3 retry alarm only while the same authenticated account is current. */
  async handleAlarm(alarm: string | { readonly name: string }): Promise<void> {
    const run = this.run;
    if (!run || !this.isCurrent(run)) {
      await this.stopTransport();
      return;
    }
    try {
      await run.activation;
      this.assertCurrent(run);
      await this.notifications.handleAlarm(alarm);
    } catch {
      if (this.isCurrent(run)) this.report('lifecycle_start_failed');
    }
  }

  private activate(authoritativeCatchUpFirst: boolean): Promise<void> {
    const current = this.run;
    if (current && this.isCurrent(current)) {
      return current.activation ?? Promise.resolve();
    }

    this.generation++;
    this.run = undefined;
    void this.stopTransport();

    let leases: VaultNotificationLeases;
    try {
      // Capture the account synchronously before any provider or network work begins.
      const accountLease = this.deps.captureAccountLease();
      leases = Object.freeze({ accountLease });
    } catch {
      return Promise.resolve();
    }

    const run: LifecycleRun = {
      generation: this.generation,
      leases,
      catchUpPending: false,
      logoutIssued: false,
      authRequestPending: false,
    };
    this.run = run;
    const activation = this.activateRun(run, authoritativeCatchUpFirst);
    run.activation = activation;
    return activation;
  }

  private async activateRun(run: LifecycleRun, authoritativeCatchUpFirst: boolean): Promise<void> {
    try {
      if (authoritativeCatchUpFirst) await this.requestCatchUp(run);
      this.assertCurrent(run);
      await this.notifications.start();
      this.assertCurrent(run);
    } catch {
      if (this.isCurrent(run)) this.report('lifecycle_start_failed');
    }
  }

  private async stopTransport(): Promise<void> {
    try {
      await this.notifications.stop();
    } catch {
      // The transport reports its own fixed stop/alarm event codes.
    }
  }

  private requireCurrentRun(): LifecycleRun {
    const run = this.run;
    if (!run) throw new Error('No authenticated notification lifecycle is active');
    this.assertCurrent(run);
    return run;
  }

  private assertCurrent(run: LifecycleRun): void {
    if (this.run !== run || run.generation !== this.generation) {
      throw new Error('The notification lifecycle changed');
    }
    this.deps.assertAccountLease(run.leases.accountLease);
  }

  private isCurrent(run: LifecycleRun): boolean {
    try {
      this.assertCurrent(run);
      return true;
    } catch {
      return false;
    }
  }

  private async contextForAccountLease(accountLease: AccountLease): Promise<ConnectionContext> {
    const run = this.requireCurrentRun();
    if (run.leases.accountLease !== accountLease) {
      throw new Error('The notification account lease changed');
    }
    const cached = run.connectionContext;
    if (cached) return consumeConnectionContext(run, cached);

    let flight = run.contextFlight;
    if (!flight) {
      const operation = (async () => {
        const [urls, deviceIdentifier] = await Promise.all([
          this.deps.getServerUrls(run.leases),
          this.deviceIdentifierForRun(run),
        ]);
        this.assertCurrent(run);
        const context = validateConnectionContext(urls, deviceIdentifier, accountLease);
        run.connectionContext = { value: context, remainingReaders: 2 };
        return context;
      })();
      const tracked = operation.finally(() => {
        if (run.contextFlight === tracked) delete run.contextFlight;
      });
      run.contextFlight = tracked;
      flight = tracked;
    }
    const context = await flight;
    this.assertCurrent(run);
    const entry = run.connectionContext;
    if (!entry || entry.value !== context) throw new Error('The notification context changed');
    return consumeConnectionContext(run, entry);
  }

  private async deviceIdentifierForRun(run: LifecycleRun): Promise<string> {
    if (run.deviceIdentifier) return run.deviceIdentifier;
    if (run.deviceIdentifierFlight) return run.deviceIdentifierFlight;
    const operation = (async () => {
      const identifier = await this.deps.getDeviceIdentifier(run.leases);
      this.assertCurrent(run);
      run.deviceIdentifier = identifier;
      return identifier;
    })();
    const tracked = operation.finally(() => {
      if (run.deviceIdentifierFlight === tracked) delete run.deviceIdentifierFlight;
    });
    run.deviceIdentifierFlight = tracked;
    return tracked;
  }

  private async accessTokenForAccountLease(accountLease: AccountLease): Promise<string> {
    const run = this.requireCurrentRun();
    if (run.leases.accountLease !== accountLease) {
      throw new Error('The notification account lease changed');
    }
    const token = await this.deps.getAccessToken(run.leases);
    this.assertCurrent(run);
    return token;
  }

  private receiveMessage(accountLease: AccountLease, message: unknown): void {
    const run = this.run;
    if (
      !run
      || run.leases.accountLease !== accountLease
      || !this.isCurrent(run)
    ) return;

    let parsed: ParsedNotification | undefined;
    try {
      parsed = parseNotification(message);
    } catch {
      parsed = undefined;
    }
    if (!parsed) {
      void this.requestCatchUp(run);
      return;
    }
    const deviceIdentifier = run.deviceIdentifier;
    if (!deviceIdentifier) {
      void this.requestCatchUp(run);
      return;
    }
    if (parsed.contextId === deviceIdentifier) return;

    if (parsed.type === VAULT_NOTIFICATION_TYPE.LogOut) {
      this.requestLogout(run);
      return;
    }
    if (
      parsed.type === VAULT_NOTIFICATION_TYPE.AuthRequest
      || parsed.type === VAULT_NOTIFICATION_TYPE.AuthRequestResponse
    ) {
      void this.requestAuthRequest(run);
      return;
    }
    if (parsed.type === VAULT_NOTIFICATION_TYPE.PremiumStatusChanged) {
      void this.requestCatchUp(run);
      return;
    }
    if (VAULT_NOTIFICATION_TYPES.has(parsed.type)) {
      try {
        this.deps.scheduler.notification(run.leases);
      } catch {
        if (this.isCurrent(run)) this.report('notification_failed');
      }
      return;
    }
    if (!KNOWN_NOTIFICATION_TYPES.has(parsed.type)) void this.requestCatchUp(run);
  }

  private requestLogout(run: LifecycleRun): void {
    if (!this.isCurrent(run) || run.logoutIssued) return;
    run.logoutIssued = true;
    void (async () => {
      try {
        this.assertCurrent(run);
        await this.deps.logout(run.leases);
      } catch {
        if (this.isCurrent(run)) this.report('logout_failed');
      }
    })();
  }

  private requestAuthRequest(run: LifecycleRun): Promise<void> {
    const callback = this.deps.authRequest;
    if (!callback || !this.isCurrent(run)) return Promise.resolve();
    if (run.authRequestFlight) {
      run.authRequestPending = true;
      return run.authRequestFlight;
    }

    const operation = (async () => {
      try {
        this.assertCurrent(run);
        await callback(run.leases);
      } catch {
        if (this.isCurrent(run)) this.report('auth_request_failed');
      }
    })();
    const tracked = operation.finally(() => {
      if (run.authRequestFlight !== tracked) return;
      delete run.authRequestFlight;
      if (!run.authRequestPending || !this.isCurrent(run)) return;
      run.authRequestPending = false;
      void this.requestAuthRequest(run);
    });
    run.authRequestFlight = tracked;
    return tracked;
  }

  private catchUpForAccountLease(accountLease: AccountLease): Promise<void> {
    const run = this.run;
    if (
      !run
      || run.leases.accountLease !== accountLease
      || !this.isCurrent(run)
    ) return Promise.resolve();
    return this.requestCatchUp(run);
  }

  private requestCatchUp(run: LifecycleRun): Promise<void> {
    if (!this.isCurrent(run)) return Promise.resolve();
    if (run.catchUpFlight) {
      run.catchUpPending = true;
      return run.catchUpFlight;
    }

    const operation = (async () => {
      try {
        this.assertCurrent(run);
        await this.deps.scheduler.catchUp(run.leases);
      } catch {
        if (this.isCurrent(run)) this.report('lifecycle_catch_up_failed');
      }
    })();
    const tracked = operation.finally(() => {
      if (run.catchUpFlight !== tracked) return;
      delete run.catchUpFlight;
      if (!run.catchUpPending || !this.isCurrent(run)) return;
      run.catchUpPending = false;
      void this.requestCatchUp(run);
    });
    run.catchUpFlight = tracked;
    return tracked;
  }

  private report(event: VaultNotificationLifecycleLogEvent): void {
    try {
      this.deps.logger?.warn(event);
    } catch {
      // Diagnostics must never alter authentication or notification lifecycle behavior.
    }
  }
}

const IDENTITY_NOTIFICATION_TRANSITIONS: ReadonlySet<SessionTransitionEvent['reason']> = new Set([
  'login',
  'logout',
  'switchAccount',
  'removeAccount',
  'serverChange',
  'keyRotation',
]);

export function invalidatesNotificationAccount(reason: SessionTransitionEvent['reason']): boolean {
  return IDENTITY_NOTIFICATION_TRANSITIONS.has(reason);
}

function consumeConnectionContext(
  run: LifecycleRun,
  entry: NonNullable<LifecycleRun['connectionContext']>,
): ConnectionContext {
  entry.remainingReaders -= 1;
  if (entry.remainingReaders <= 0 && run.connectionContext === entry) {
    delete run.connectionContext;
  }
  return entry.value;
}

export function createVaultNotificationLifecycle(
  deps: VaultNotificationLifecycleDeps,
): VaultNotificationLifecycle {
  return new VaultNotificationLifecycle(deps);
}

function validateConnectionContext(
  urls: VaultNotificationServerUrls,
  deviceIdentifier: string,
  accountLease: AccountLease,
): ConnectionContext {
  if (!isBoundedString(urls.serverUrl, MAX_CONNECTION_URL_LENGTH)) {
    throw new Error('The configured server URL is invalid');
  }
  if (urls.serverUrl !== accountLease.serverUrl) {
    throw new Error('The configured server changed during notification startup');
  }
  const notificationsUrl = urls.notificationsUrl;
  if (
    notificationsUrl !== undefined
    && !isBoundedString(notificationsUrl, MAX_CONNECTION_URL_LENGTH)
  ) {
    throw new Error('The notifications server URL is invalid');
  }
  if (!isBoundedString(deviceIdentifier, MAX_CONTEXT_ID_LENGTH)) {
    throw new Error('The device identifier is invalid');
  }
  return Object.freeze({
    serverUrl: urls.serverUrl,
    ...(notificationsUrl === undefined ? {} : { notificationsUrl }),
    deviceIdentifier,
  });
}

function parseNotification(message: unknown): ParsedNotification | undefined {
  if (!isRecord(message)) return undefined;
  const rawType = readAliasedOwnValue(message, 'Type', 'type');
  if (
    rawType.kind !== 'value'
    || typeof rawType.value !== 'number'
    || !Number.isSafeInteger(rawType.value)
    || rawType.value < 0
    || rawType.value > MAX_NOTIFICATION_TYPE
  ) return undefined;

  const rawContextId = readAliasedOwnValue(message, 'ContextId', 'contextId');
  if (rawContextId.kind === 'invalid') return undefined;
  if (rawContextId.kind === 'absent' || rawContextId.value == null || rawContextId.value === '') {
    return Object.freeze({ type: rawType.value });
  }
  if (
    typeof rawContextId.value !== 'string'
    || rawContextId.value.length > MAX_CONTEXT_ID_LENGTH
  ) return undefined;
  return Object.freeze({ type: rawType.value, contextId: rawContextId.value });
}

function readAliasedOwnValue(
  value: Record<string, unknown>,
  canonical: string,
  camelCase: string,
): OwnValue {
  const first = readOwnValue(value, canonical);
  const second = readOwnValue(value, camelCase);
  if (first.kind === 'invalid' || second.kind === 'invalid') return { kind: 'invalid' };
  if (first.kind === 'absent') return second;
  if (second.kind === 'absent') return first;
  if (!Object.is(first.value, second.value)) return { kind: 'invalid' };
  return first;
}

function readOwnValue(value: Record<string, unknown>, key: string): OwnValue {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor) return { kind: 'absent' };
  if (!('value' in descriptor)) return { kind: 'invalid' };
  return { kind: 'value', value: descriptor.value };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}
