import { describe, expect, it, vi } from 'vitest';
import {
  refreshVaultTimeoutSettings,
  refreshVaultTimeoutSettingsAfterWrite,
} from './vault-timeout-settings-lifecycle.js';

describe('vault timeout settings lifecycle', () => {
  it.each(['get', 'set'] as const)(
    'fails closed after an owner reconcile %s failure and retries the same persisted value',
    async (stage) => {
      let failed = false;
      let needsRecovery = false;
      const reconcileOwners = vi.fn()
        .mockRejectedValueOnce(new Error(`owner ${stage} failed`))
        .mockResolvedValue(undefined);
      const controller = {
        needsReconfigure: vi.fn(() => needsRecovery),
        reconfigure: vi.fn(async () => { needsRecovery = false; }),
        failClosed: vi.fn(async () => { failed = true; needsRecovery = true; }),
      };
      const deps = {
        reconcileOwners,
        controller,
        applyIdleDetection: vi.fn(async () => undefined),
      };

      await expect(refreshVaultTimeoutSettings(deps, {
        settingsChanged: true,
        timeoutSettingsRequest: true,
        reconfigureOptions: {},
      })).rejects.toThrow(`owner ${stage} failed`);
      expect(failed).toBe(true);
      expect(controller.failClosed).toHaveBeenCalledOnce();
      expect(controller.reconfigure).not.toHaveBeenCalled();

      await expect(refreshVaultTimeoutSettings(deps, {
        settingsChanged: false,
        timeoutSettingsRequest: true,
        reconfigureOptions: {},
      })).resolves.toBe(true);
      expect(reconcileOwners).toHaveBeenCalledTimes(2);
      expect(controller.reconfigure).toHaveBeenCalledOnce();
    },
  );

  it('does not reconfigure an unchanged healthy timeout request', async () => {
    const controller = {
      needsReconfigure: vi.fn(() => false),
      reconfigure: vi.fn(async () => undefined),
      failClosed: vi.fn(async () => undefined),
    };
    await expect(refreshVaultTimeoutSettings({
      reconcileOwners: vi.fn(async () => undefined),
      controller,
      applyIdleDetection: vi.fn(async () => undefined),
    }, {
      settingsChanged: false,
      timeoutSettingsRequest: true,
      reconfigureOptions: {},
    })).resolves.toBe(false);
    expect(controller.reconfigure).not.toHaveBeenCalled();
  });

  it.each(['getLockTimeout', 'getOnIdleAction'] as const)(
    'fails closed when the post-write %s read fails',
    async (failure) => {
      const getLockTimeout = vi.fn(async () => {
        if (failure === 'getLockTimeout') throw new Error('post-write lock read failed');
        return '15' as const;
      });
      const getOnIdleAction = vi.fn(async () => {
        if (failure === 'getOnIdleAction') throw new Error('post-write action read failed');
        return 'logout' as const;
      });
      let terminalCompleted = false;
      const controller = {
        needsReconfigure: vi.fn(() => false),
        reconfigure: vi.fn(async () => undefined),
        failClosed: vi.fn(async () => {
          await Promise.resolve();
          terminalCompleted = true;
        }),
      };

      await expect(refreshVaultTimeoutSettingsAfterWrite({
        readPersistedSettings: () => Promise.all([getLockTimeout(), getOnIdleAction()]),
        reconcileOwners: vi.fn(async () => undefined),
        controller,
        applyIdleDetection: vi.fn(async () => undefined),
      }, {
        before: ['never', 'lock'],
        timeoutSettingsRequest: true,
      })).rejects.toThrow(/post-write/);

      expect(controller.failClosed).toHaveBeenCalledOnce();
      expect(terminalCompleted).toBe(true);
      expect(controller.reconfigure).not.toHaveBeenCalled();
    },
  );
});
