import type { KeyValueStore } from '../../platform/store.js';
import {
  RotationPendingStore,
  type RotationPendingIdentity,
  type RotationPendingStartupInspection,
} from './rotation-pending-store.js';

export const PASSWORD_CHANGE_PENDING_KEY = 'passwordChangePending';

/**
 * Durable claim written immediately before any password-change request. The payload contains only
 * account identity metadata; a surviving valid claim makes startup retire only that account rather
 * than replay the request. Corrupt or unsupported claims still require a full fail-closed reset.
 */
export class PasswordChangePendingStore {
  readonly #pending: RotationPendingStore;

  constructor(store: KeyValueStore, now?: () => number) {
    this.#pending = new RotationPendingStore(store, {
      storageKey: PASSWORD_CHANGE_PENDING_KEY,
      ...(now ? { now } : {}),
    });
  }

  markBeforeChange(identity: RotationPendingIdentity): Promise<unknown> {
    return this.#pending.markBeforeRotation(identity);
  }

  inspectForStartup(): Promise<RotationPendingStartupInspection> {
    return this.#pending.inspectForStartup();
  }

  clear(): Promise<void> {
    return this.#pending.clear();
  }
}

export async function recoverPendingPasswordChangeOnStartup(
  pending: Pick<PasswordChangePendingStore, 'inspectForStartup' | 'clear'>,
  cleanup: {
    readonly removeAccount?: (identity: RotationPendingIdentity) => Promise<void>;
    readonly resetAllAccounts: () => Promise<void>;
    readonly clearVaultCache: () => Promise<void>;
  },
): Promise<boolean> {
  const inspection = await pending.inspectForStartup();
  if (!inspection.requiresAccountReset) return false;

  const failures: unknown[] = [];
  try {
    if (inspection.kind === 'pending' && cleanup.removeAccount) {
      await cleanup.removeAccount({
        serverUrl: inspection.marker.serverUrl,
        accountId: inspection.marker.accountId,
      });
    } else {
      await cleanup.resetAllAccounts();
    }
  } catch (error) {
    failures.push(error);
  }
  try {
    await cleanup.clearVaultCache();
  } catch (error) {
    failures.push(error);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, 'Pending password-change startup cleanup failed');
  }
  await pending.clear();
  return true;
}

/** Compatibility names for callers written before ordinary password changes joined the same WAL. */
export class ForcedPasswordChangePendingStore extends PasswordChangePendingStore {}
export const FORCED_PASSWORD_CHANGE_PENDING_KEY = PASSWORD_CHANGE_PENDING_KEY;
export const recoverPendingForcedPasswordChangeOnStartup = recoverPendingPasswordChangeOnStartup;
