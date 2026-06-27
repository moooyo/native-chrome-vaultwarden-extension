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
import type { ApiClient, PasswordLoginInput } from '../api/client.js';
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

  // --- TDD: RED first for Kdf hardening (finding 1) ---
  it('rejects login when server success response contains Kdf: 1 (Argon2id)', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR.akey,
          Kdf: 1 as const,
          KdfIterations: KDF_VECTOR.iterations,
        },
      }),
    };
    const { auth } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password }),
    ).rejects.toThrow('Argon2id accounts are not supported in this MVP');
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

  // --- Finding 4: Argon2id prelogin guard ---
  it('rejects login when prelogin reports kdf: 1 (Argon2id)', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 1 as const, kdfIterations: 3 }),
    };
    const { auth } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password }),
    ).rejects.toThrow('Argon2id accounts are not supported in this MVP');
  });

  // --- Finding 2: sendEmailCode ---
  it('sendEmailCode calls api.sendEmailLogin with normalized email and stored token', async () => {
    const sendEmailLogin = vi.fn().mockResolvedValue(undefined);
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'twoFactor' as const,
        providers: [1],
        token: 'email-tf-token',
      }),
      sendEmailLogin,
    };
    const { auth } = makeService(api);
    await auth.login({ email: '  User@Example.COM  ', masterPassword: KDF_VECTOR.password });
    await auth.sendEmailCode();
    expect(sendEmailLogin).toHaveBeenCalledWith({
      email: 'user@example.com',
      twoFactorToken: 'email-tf-token',
    });
  });

  it('sendEmailCode rejects when there is no pending 2FA token (fresh instance)', async () => {
    const { auth } = makeService({});
    await expect(auth.sendEmailCode()).rejects.toThrow('no pending 2FA token');
  });

  it('sendEmailCode rejects when pending login has no twoFactorToken', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'twoFactor' as const,
        providers: [0],
        // no token property
      }),
    };
    const { auth } = makeService(api);
    await auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password });
    await expect(auth.sendEmailCode()).rejects.toThrow('no pending 2FA token');
  });

  // --- Finding 3: submitTwoFactor success path ---
  it('submitTwoFactor completes login after 2FA-required flow and unlocks session', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf-tok' })
      .mockResolvedValueOnce({
        kind: 'success' as const,
        data: {
          access_token: 'access2',
          expires_in: 3600,
          refresh_token: 'refresh2',
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
    await auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password });
    await expect(
      auth.submitTwoFactor({ provider: 0, code: '123456', remember: true }),
    ).resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getState()).toBe('unlocked');
    const calls = passwordLogin.mock.calls as Array<[PasswordLoginInput]>;
    const secondCall = calls[1]?.[0];
    expect(secondCall?.email).toBe(KDF_VECTOR.email);
    expect(secondCall?.masterPasswordHash).toBe(KDF_VECTOR.masterPasswordHashB64);
    expect(secondCall?.twoFactorProvider).toBe(0);
    expect(secondCall?.twoFactorToken).toBe('123456');
    expect(secondCall?.remember).toBe(true);
  });

  // --- Finding 5: logout clears pending login ---
  it('logout clears pending login so subsequent submitTwoFactor rejects', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0], token: 'tf' }),
    };
    const { auth } = makeService(api);
    await auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password });
    await auth.logout();
    await expect(
      auth.submitTwoFactor({ provider: 0, code: '000000' }),
    ).rejects.toThrow('no pending 2FA login');
  });
});
