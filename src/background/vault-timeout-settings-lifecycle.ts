import type {
  VaultTimeoutController,
  VaultTimeoutReconfigureOptions,
} from './vault-timeout-controller.js';
import {
  didLocalVaultTimeoutSettingsChange,
  localCloseLogoutOwnerClear,
  type LocalVaultTimeoutSettings,
} from './vault-timeout-policy.js';

export interface VaultTimeoutSettingsRefresh {
  readonly settingsChanged: boolean;
  readonly timeoutSettingsRequest: boolean;
  readonly reconfigureOptions: VaultTimeoutReconfigureOptions;
}

/** Apply an already-persisted timeout setting, failing closed across every post-write side effect. */
export async function refreshVaultTimeoutSettings(
  deps: {
    readonly reconcileOwners: () => Promise<void>;
    readonly controller: Pick<
      VaultTimeoutController,
      'needsReconfigure' | 'reconfigure' | 'failClosed'
    >;
    readonly applyIdleDetection: () => Promise<void>;
  },
  refresh: VaultTimeoutSettingsRefresh,
): Promise<boolean> {
  if (!refresh.settingsChanged
      && !(refresh.timeoutSettingsRequest && deps.controller.needsReconfigure())) return false;
  try {
    await deps.reconcileOwners();
    await deps.controller.reconfigure(refresh.reconfigureOptions);
    await deps.applyIdleDetection();
    return true;
  } catch (error) {
    await deps.controller.failClosed();
    throw error;
  }
}

export async function refreshVaultTimeoutSettingsAfterWrite(
  deps: {
    readonly readPersistedSettings: () => Promise<LocalVaultTimeoutSettings>;
    readonly reconcileOwners: () => Promise<void>;
    readonly controller: Pick<
      VaultTimeoutController,
      'needsReconfigure' | 'reconfigure' | 'failClosed'
    >;
    readonly applyIdleDetection: () => Promise<void>;
  },
  input: {
    readonly before: LocalVaultTimeoutSettings | undefined;
    readonly timeoutSettingsRequest: boolean;
  },
): Promise<boolean> {
  if (!input.before) return false;
  try {
    const after = await deps.readPersistedSettings();
    const clear = localCloseLogoutOwnerClear(input.before, after);
    return await refreshVaultTimeoutSettings(deps, {
      settingsChanged: didLocalVaultTimeoutSettingsChange(input.before, after),
      timeoutSettingsRequest: input.timeoutSettingsRequest,
      reconfigureOptions: {
        ...(clear.action ? { clearLocalActionOwners: true } : {}),
        ...(clear.timeout ? { clearLocalTimeoutOwners: true } : {}),
      },
    });
  } catch (error) {
    await deps.controller.failClosed();
    throw error;
  }
}
