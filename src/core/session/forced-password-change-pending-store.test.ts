import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { createMemoryStore } from '../../platform/store.js';
import { SessionManager } from './session-manager.js';
import {
  PasswordChangePendingStore,
  recoverPendingPasswordChangeOnStartup,
} from './forced-password-change-pending-store.js';

describe('PasswordChangePendingStore', () => {
  it('removes only the claimed account after a worker dies with a valid password request', async () => {
    const pending = new PasswordChangePendingStore(createMemoryStore(), () => 123);
    await pending.markBeforeChange({
      serverUrl: 'https://vault.example/',
      accountId: 'user@example.com',
    });
    const resetAllAccounts = vi.fn(async () => {});
    const removeAccount = vi.fn(async () => {});
    const clearVaultCache = vi.fn(async () => {});

    await expect(recoverPendingPasswordChangeOnStartup(pending, {
      removeAccount,
      resetAllAccounts,
      clearVaultCache,
    })).resolves.toBe(true);

    expect(removeAccount).toHaveBeenCalledOnce();
    expect(removeAccount).toHaveBeenCalledWith({
      serverUrl: 'https://vault.example/',
      accountId: 'user@example.com',
    });
    expect(resetAllAccounts).not.toHaveBeenCalled();
    expect(clearVaultCache).toHaveBeenCalledOnce();
    await expect(pending.inspectForStartup()).resolves.toMatchObject({ kind: 'none' });
  });

  it('retains a pending marker when recovery is incomplete', async () => {
    const pending = new PasswordChangePendingStore(createMemoryStore(), () => 123);
    await pending.markBeforeChange({
      serverUrl: 'https://vault.example/',
      accountId: 'user@example.com',
    });
    const removeAccount = vi.fn().mockRejectedValue(new Error('unavailable'));
    await expect(recoverPendingPasswordChangeOnStartup(pending, {
      removeAccount,
      resetAllAccounts: vi.fn(async () => {}),
      clearVaultCache: vi.fn(async () => {}),
    })).rejects.toThrow('unavailable');
    await expect(pending.inspectForStartup()).resolves.toMatchObject({ kind: 'pending' });
  });

  it('recovers a changed account without removing a remaining account', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const session = new SessionManager({ localStore, sessionStore });
    const auth = (email: string, suffix: string) => ({
      email,
      accessToken: `access-${suffix}`,
      refreshToken: `refresh-${suffix}`,
      expiresAt: 10_000,
      protectedKey: `2.protected-${suffix}`,
      kdf: 0 as const,
      kdfIterations: 600_000,
    });
    await session.saveLockedAuthenticated(auth('remaining@example.com', 'remaining'));
    await session.saveLockedAuthenticated(auth('changed@example.com', 'changed'));
    const pending = new PasswordChangePendingStore(localStore, () => 123);
    await pending.markBeforeChange({
      serverUrl: 'https://vault.example/',
      accountId: 'changed@example.com',
    });

    const restarted = new SessionManager({ localStore, sessionStore });
    await recoverPendingPasswordChangeOnStartup(pending, {
      removeAccount: (identity) => restarted.removeAccount(identity.accountId),
      resetAllAccounts: () => restarted.resetAllAccounts(),
      clearVaultCache: vi.fn(async () => {}),
    });

    expect(await restarted.getState()).toBe('locked');
    expect(await restarted.listAccounts()).toEqual([{
      email: 'remaining@example.com',
      active: true,
    }]);
    await expect(pending.inspectForStartup()).resolves.toMatchObject({ kind: 'none' });
  });
});
