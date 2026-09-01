import { normalizeServerConfig } from '../core/api/server-capabilities.js';
import type { ServerConfigResponse } from '../core/api/client.js';
import type { AccountLease, ServerLease } from '../core/session/account-gate.js';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';
import type { SessionState } from '../core/session/session-manager.js';
import type {
  ServerCapabilityLease,
  ServerCapabilityManager,
} from './server-capability-manager.js';
import {
  createVaultNotificationLifecycle,
  invalidatesNotificationAccount,
  type VaultNotificationLifecycleLogEvent,
  type VaultNotificationLeases,
} from './vault-notification-lifecycle.js';
import {
  VAULT_NOTIFICATIONS_RECONNECT_ALARM,
  type NotificationsConnectionFactory,
  type VaultNotificationsAlarmScheduler,
} from './vault-notifications.js';
import { DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX } from './device-login-notifications.js';
import { DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM } from './device-login-approval-notifications.js';
import {
  DEVICE_LOGIN_DEADLINE_ALARM_PREFIX,
  DEVICE_LOGIN_STATUS_ALARM_PREFIX,
} from './device-login-coordinator.js';

export interface VaultNotificationProductionApi {
  getDeviceIdentifier(): string | PromiseLike<string>;
}

interface DeviceLoginServerConfigApi {
  getServerConfig(maxResponseBytes: number): PromiseLike<ServerConfigResponse>;
}

export interface DeviceLoginCapabilityApi {
  forServer(serverUrl: string): {
    withRequestGuard(assertCurrent: () => void): DeviceLoginServerConfigApi;
  };
}

export type DeviceLoginProductionLogEvent =
  | 'approval_badge_refresh_failed'
  | 'approval_badge_publish_failed'
  | 'badge_state_failed'
  | 'requester_startup_failed';

export interface DeviceLoginApprovalBadgeDeps {
  listPending(): PromiseLike<readonly unknown[]>;
  publish(contribution: DeviceLoginApprovalContribution): void | PromiseLike<void>;
  logger?: { warn(event: DeviceLoginProductionLogEvent): void };
}

export interface DeviceLoginApprovalContribution {
  readonly pendingCount: number;
}

/** Maintains a count-only badge without letting a stale approval read survive a session change. */
export class DeviceLoginApprovalBadgeController {
  private generation = 0;
  private desiredCount = 0;
  private writeTail: Promise<void> = Promise.resolve();

  constructor(private readonly deps: DeviceLoginApprovalBadgeDeps) {}

  clear(): void {
    const generation = ++this.generation;
    this.desiredCount = 0;
    void this.enqueuePublish(0, generation);
  }

  async refresh(): Promise<void> {
    const generation = ++this.generation;
    this.desiredCount = 0;
    const clearWrite = this.enqueuePublish(0, generation);
    let pending: readonly unknown[];
    try {
      pending = await this.deps.listPending();
    } catch {
      if (generation === this.generation) {
        this.report('approval_badge_refresh_failed');
      }
      await clearWrite;
      return;
    }
    if (generation !== this.generation) return;
    await clearWrite;
    if (generation !== this.generation) return;
    const count = pending.length;
    this.desiredCount = count;
    await this.enqueuePublish(count, generation);
  }

  private enqueuePublish(count: number, generation: number): Promise<void> {
    const operation = this.writeTail.then(async () => {
      if (generation !== this.generation || count !== this.desiredCount) return;
      try {
        await this.deps.publish(Object.freeze({ pendingCount: count }));
      } catch {
        if (generation === this.generation) this.report('approval_badge_publish_failed');
      }
    });
    this.writeTail = operation.catch(() => undefined);
    return operation;
  }

  private report(event: DeviceLoginProductionLogEvent): void {
    try {
      this.deps.logger?.warn(event);
    } catch {
      // Diagnostics cannot alter badge or authentication lifecycle behavior.
    }
  }
}

export interface DeviceLoginRuntimeRestoreDeps {
  getAuthState(): PromiseLike<SessionState>;
  startupRequester(): PromiseLike<unknown>;
  cancelRequester(): PromiseLike<unknown>;
  badge: Pick<DeviceLoginApprovalBadgeController, 'clear' | 'refresh'>;
  systemNotifications?: {
    clear(): void | PromiseLike<void>;
    refresh(): void | PromiseLike<void>;
  };
  logger?: { warn(event: DeviceLoginProductionLogEvent): void };
}

export function hasActiveNotificationAccount(state: SessionState): boolean {
  return state === 'locked' || state === 'unlocked';
}

export type DeviceLoginApprovalTransitionAction = 'preserve' | 'refresh' | 'clear';

/** Keep same-account delivery alive across lock boundaries and revoke it on identity changes. */
export function deviceLoginApprovalTransitionAction(
  event: SessionTransitionEvent,
): DeviceLoginApprovalTransitionAction {
  if (event.phase === 'start') {
    return invalidatesNotificationAccount(event.reason) ? 'clear' : 'preserve';
  }
  return hasActiveNotificationAccount(event.state) ? 'refresh' : 'clear';
}

/** Restore requester state only while logged out; an existing account owns the active session. */
export async function restoreDeviceLoginProductionRuntime(
  initialState: SessionState,
  deps: DeviceLoginRuntimeRestoreDeps,
): Promise<void> {
  const report = (event: DeviceLoginProductionLogEvent): void => {
    try { deps.logger?.warn(event); } catch { /* diagnostics are isolated */ }
  };
  let state = initialState;
  try {
    state = await deps.getAuthState();
  } catch {
    report('badge_state_failed');
  }
  try {
    if (state === 'loggedOut') await deps.startupRequester();
    else await deps.cancelRequester();
  } catch {
    report('requester_startup_failed');
  }
  try {
    state = await deps.getAuthState();
  } catch {
    report('badge_state_failed');
  }
  if (hasActiveNotificationAccount(state)) {
    await Promise.allSettled([
      deps.badge.refresh(),
      Promise.resolve().then(() => deps.systemNotifications?.refresh()),
    ]);
  } else {
    deps.badge.clear();
    await Promise.resolve().then(() => deps.systemNotifications?.clear()).catch(() => undefined);
  }
}

export function isDeviceLoginAlarmName(name: string): boolean {
  return name === DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM
    || name.startsWith(DEVICE_LOGIN_STATUS_ALARM_PREFIX)
    || name.startsWith(DEVICE_LOGIN_DEADLINE_ALARM_PREFIX)
    || name.startsWith(DEVICE_LOGIN_NOTIFICATIONS_RECONNECT_ALARM_PREFIX);
}

export interface VaultNotificationProductionAuth {
  getAccountAccessToken(accountLease: AccountLease): PromiseLike<string>;
  logout(): void | PromiseLike<void>;
}

export interface VaultNotificationProductionVault {
  sync(reason: 'notification', policy: 'force'): PromiseLike<unknown>;
}

export interface VaultNotificationProductionSyncScheduler {
  notification(): void;
}

export interface VaultNotificationProductionDeps {
  capabilities: ServerCapabilityManager<AccountLease>;
  api: VaultNotificationProductionApi;
  auth: VaultNotificationProductionAuth;
  vault: VaultNotificationProductionVault;
  syncScheduler: VaultNotificationProductionSyncScheduler;
  captureAccountLease(): AccountLease;
  assertAccountLease(lease: AccountLease): void;
  alarms: VaultNotificationsAlarmScheduler;
  authRequest?: (leases: VaultNotificationLeases) => void | PromiseLike<void>;
  logger?: { warn(event: VaultNotificationLifecycleLogEvent): void };
  createConnection?: NotificationsConnectionFactory;
}

export interface VaultNotificationProductionRuntime {
  readonly capabilities: ServerCapabilityManager<AccountLease>;
  readonly lifecycle: ReturnType<typeof createVaultNotificationLifecycle>;
  startup(state: SessionState): Promise<void>;
  handleSessionTransition(event: SessionTransitionEvent): void;
  handleAlarm(alarm: string | { readonly name: string }): Promise<void>;
}

const DEVICE_LOGIN_CONFIG_MAX_RESPONSE_BYTES = 64 * 1_024;

/** Resolve a requester's dedicated notification base while the exact server lease remains valid. */
export async function resolveDeviceLoginNotificationsUrl(
  api: DeviceLoginCapabilityApi,
  serverGate: { assertServer(lease: ServerLease): void },
  lease: ServerLease,
): Promise<string | undefined> {
  const assertCurrent = (): void => serverGate.assertServer(lease);
  try {
    assertCurrent();
    const fixed = api.forServer(lease.serverUrl).withRequestGuard(assertCurrent);
    const response = await fixed.getServerConfig(DEVICE_LOGIN_CONFIG_MAX_RESPONSE_BYTES);
    assertCurrent();
    return normalizeServerConfig(response.body).environment.notifications;
  } catch {
    // Invalid or unavailable config uses the coordinator's same-server route. A stale lease still
    // throws, so a server transition can never inherit this fallback.
    assertCurrent();
    return undefined;
  }
}

/** Compose capability discovery and SignalR notifications around one exact authenticated account. */
export function createVaultNotificationProductionRuntime(
  deps: VaultNotificationProductionDeps,
): VaultNotificationProductionRuntime {
  const capabilities = deps.capabilities;

  const assertLeases = (leases: VaultNotificationLeases): void => {
    deps.assertAccountLease(leases.accountLease);
  };

  const getServerUrls = async (leases: VaultNotificationLeases) => {
    assertLeases(leases);
    const fallback = Object.freeze({ serverUrl: leases.accountLease.serverUrl });
    try {
      await capabilities.resolve();
      assertLeases(leases);
      const capabilityLease: ServerCapabilityLease = capabilities.capture();
      const current = capabilities.assert(capabilityLease);
      assertLeases(leases);
      const notificationsUrl = current.availability === 'available'
        ? current.capabilities.config.environment.notifications
        : undefined;
      return notificationsUrl
        ? Object.freeze({ ...fallback, notificationsUrl })
        : fallback;
    } catch {
      // A capability transport or validation failure is not an authentication failure. A stale
      // account still throws here and therefore cannot fall back into a different account.
      assertLeases(leases);
      return fallback;
    }
  };

  const lifecycle = createVaultNotificationLifecycle({
    captureAccountLease: deps.captureAccountLease,
    assertAccountLease: deps.assertAccountLease,
    getServerUrls,
    getDeviceIdentifier: async (leases) => {
      assertLeases(leases);
      const identifier = await deps.api.getDeviceIdentifier();
      assertLeases(leases);
      return identifier;
    },
    getAccessToken: async (leases) => {
      assertLeases(leases);
      return deps.auth.getAccountAccessToken(leases.accountLease);
    },
    logout: async (leases) => {
      assertLeases(leases);
      await deps.auth.logout();
    },
    authRequest: async (leases) => {
      assertLeases(leases);
      await deps.authRequest?.(leases);
      assertLeases(leases);
    },
    scheduler: {
      notification: (leases) => {
        assertLeases(leases);
        deps.syncScheduler.notification();
      },
      catchUp: async (leases) => {
        assertLeases(leases);
        await deps.vault.sync('notification', 'force');
        assertLeases(leases);
      },
    },
    alarms: deps.alarms,
    ...(deps.logger ? { logger: deps.logger } : {}),
    ...(deps.createConnection ? { createConnection: deps.createConnection } : {}),
  });

  const report = (event: VaultNotificationLifecycleLogEvent): void => {
    try {
      deps.logger?.warn(event);
    } catch {
      // Diagnostics never alter authentication or notification lifecycle behavior.
    }
  };

  return Object.freeze({
    capabilities,
    lifecycle,
    async startup(state: SessionState): Promise<void> {
      try {
        if (hasActiveNotificationAccount(state)) await lifecycle.startup();
        else await lifecycle.stop();
      } catch {
        report('lifecycle_start_failed');
      }
    },
    handleSessionTransition(event: SessionTransitionEvent): void {
      if (event.phase === 'start' && invalidatesNotificationAccount(event.reason)) {
        capabilities.invalidate();
      }
      try {
        lifecycle.handleSessionTransition(event);
      } catch {
        report('lifecycle_start_failed');
      }
    },
    async handleAlarm(alarm: string | { readonly name: string }): Promise<void> {
      const name = typeof alarm === 'string' ? alarm : alarm.name;
      if (name !== VAULT_NOTIFICATIONS_RECONNECT_ALARM) return;
      try {
        await lifecycle.handleAlarm(alarm);
      } catch {
        report('lifecycle_start_failed');
      }
    },
  });
}
