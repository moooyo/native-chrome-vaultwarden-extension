import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { AuthService } from './auth-service.js';
import { SessionManager } from './session-manager.js';
import { createMemoryStore } from '../../platform/store.js';
import type { ApiClient } from '../api/client.js';
import { KDF_VECTOR, USER_KEY_VECTOR } from '../../../test/vectors.js';

function makeService(api: Partial<ApiClient>) {
  const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
  return { sm, auth: new AuthService({ api: api as ApiClient, session: sm, now: () => 1000 }) };
}

describe('AuthService', () => {
  it('logs in and stores unlocked session when password grant succeeds', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'success' as const,
      data: {
        access_token: 'access',
        expires_in: 3600,
        refresh_token: 'refresh',
        token_type: 'Bearer',
        Key: USER_KEY_VECTOR.akey,
        Kdf: 0 as const,
        KdfIterations: KDF_VECTOR.iterations,
      },
    });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getState()).toBe('unlocked');
    const calls = passwordLogin.mock.calls as Array<[{ masterPasswordHash: string }]>;
    expect(calls[0]?.[0].masterPasswordHash).toBe(KDF_VECTOR.masterPasswordHashB64);
  });

  it('keeps pending login in memory when 2FA is required', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0, 1, 7], token: 'tf' }),
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password }))
      .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1], token: 'tf' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('unlock derives key from persisted auth without calling prelogin', async () => {
    const { auth, sm } = makeService({});
    await sm.saveUnlocked({
      email: KDF_VECTOR.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await sm.lock();
    await expect(auth.unlock(KDF_VECTOR.password)).resolves.toBeUndefined();
    expect(await sm.getState()).toBe('unlocked');
  });
});
