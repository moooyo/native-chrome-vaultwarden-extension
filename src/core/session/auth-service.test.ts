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
import { base64ToBytes, bytesToHex } from '../crypto/encoding.js';
import { KDF_VECTOR, KDF_VECTOR_600K, USER_KEY_VECTOR, USER_KEY_VECTOR_600K, RSA_PRIVATE_KEY_VECTOR } from '../../../test/vectors.js';

function makeService(api: Partial<ApiClient>) {
  const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
  return { sm, auth: new AuthService({ api: api as ApiClient, session: sm, now: () => 1000 }) };
}

// Happy-path login tests use the 600000-iteration vector because the KDF floor (5000) forbids
// the 1000-iteration KDF_VECTOR. USER_KEY_VECTOR_600K.akey wraps the same userKey at 600k.

describe('AuthService', () => {
  it('logs in and stores unlocked session when password grant succeeds', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'success' as const,
      data: {
        access_token: 'access',
        expires_in: 3600,
        refresh_token: 'refresh',
        token_type: 'Bearer',
        Key: USER_KEY_VECTOR_600K.akey,
        Kdf: 0 as const,
        KdfIterations: KDF_VECTOR_600K.iterations,
      },
    });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getState()).toBe('unlocked');
    const calls = passwordLogin.mock.calls as Array<[{ masterPasswordHash: string }]>;
    expect(calls[0]?.[0].masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);
  });

  it('keeps pending login in memory when 2FA is required', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0, 1, 7], token: 'tf' }),
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1], token: 'tf' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  // --- KDF iteration floor (audit finding ①) ---
  it('rejects login when prelogin reports kdfIterations below the floor and sends no hash', async () => {
    const passwordLogin = vi.fn();
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: 4999 }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }),
    ).rejects.toThrow(/unsafe KDF iteration count/);
    // No MasterPasswordHash was transmitted to the server on rejection.
    expect(passwordLogin).not.toHaveBeenCalled();
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('accepts a login whose prelogin iterations are exactly at the floor (5000)', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0], token: 'tf' });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: 5000 }),
      passwordLogin,
    };
    const { auth } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toEqual({ kind: 'twoFactor', providers: [0], token: 'tf' });
    expect(passwordLogin).toHaveBeenCalledTimes(1);
  });

  it('rejects when the success response KdfIterations is below the floor', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey,
          Kdf: 0 as const,
          KdfIterations: 100,
        },
      }),
    };
    const { auth, sm } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }),
    ).rejects.toThrow(/unsafe KDF iteration count/);
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('rejects when the success response KdfIterations differs from prelogin (downgrade)', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey,
          Kdf: 0 as const,
          KdfIterations: 200000,
        },
      }),
    };
    const { auth, sm } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }),
    ).rejects.toThrow(/changed KDF settings/);
    expect(await sm.getState()).toBe('loggedOut');
  });

  // --- Kdf hardening (finding 1): Argon2id in the success response ---
  it('rejects login when server success response contains Kdf: 1 (Argon2id)', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey,
          Kdf: 1 as const,
          KdfIterations: KDF_VECTOR_600K.iterations,
        },
      }),
    };
    const { auth } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }),
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

  // --- RSA private key path (tech debt ②) ---
  it('decrypts the PrivateKey on successful login and stores PKCS8 only in session', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey,
          PrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
          Kdf: 0 as const,
          KdfIterations: KDF_VECTOR_600K.iterations,
        },
      }),
    };
    const { auth, sm } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    const pk = await sm.loadPrivateKey();
    expect(pk && bytesToHex(pk)).toBe(bytesToHex(base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64)));
  });

  it('leaves the privateKey undefined when the login response carries no PrivateKey', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey,
          Kdf: 0 as const,
          KdfIterations: KDF_VECTOR_600K.iterations,
        },
      }),
    };
    const { auth, sm } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    expect(await sm.loadPrivateKey()).toBeUndefined();
  });

  it('re-decrypts the PrivateKey from the persisted encrypted blob on unlock', async () => {
    const { auth, sm } = makeService({});
    await sm.saveUnlocked({
      email: KDF_VECTOR_600K.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR_600K.iterations,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await sm.lock();
    await auth.unlock(KDF_VECTOR_600K.password);
    const pk = await sm.loadPrivateKey();
    expect(pk && bytesToHex(pk)).toBe(bytesToHex(base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64)));
  });

  // --- Finding 4: Argon2id prelogin guard (runs before the floor) ---
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
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'twoFactor' as const,
        providers: [1],
        token: 'email-tf-token',
      }),
      sendEmailLogin,
    };
    const { auth } = makeService(api);
    await auth.login({ email: '  User@Example.COM  ', masterPassword: KDF_VECTOR_600K.password });
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
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'twoFactor' as const,
        providers: [0],
        // no token property
      }),
    };
    const { auth } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
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
          Key: USER_KEY_VECTOR_600K.akey,
          Kdf: 0 as const,
          KdfIterations: KDF_VECTOR_600K.iterations,
        },
      });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await expect(
      auth.submitTwoFactor({ provider: 0, code: '123456', remember: true }),
    ).resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getState()).toBe('unlocked');
    const calls = passwordLogin.mock.calls as Array<[PasswordLoginInput]>;
    const secondCall = calls[1]?.[0];
    expect(secondCall?.email).toBe(KDF_VECTOR_600K.email);
    expect(secondCall?.masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(secondCall?.twoFactorProvider).toBe(0);
    expect(secondCall?.twoFactorToken).toBe('123456');
    expect(secondCall?.remember).toBe(true);
  });

  // Coverage-only branch tests: production guards already exist; these tests cannot be
  // made RED without deleting production code, so RED evidence is documented as N/A.

  it('refreshIfNeeded does not call api.refresh when there is no persisted auth', async () => {
    const api = { refresh: vi.fn() };
    const { auth } = makeService(api);
    // No saveUnlocked call → getPersistedAuth() returns undefined
    await auth.refreshIfNeeded(5000);
    expect(api.refresh).not.toHaveBeenCalled();
  });

  it('refreshIfNeeded does not call api.refresh when token is not near expiry', async () => {
    const api = { refresh: vi.fn() };
    const { auth, sm } = makeService(api);
    // now() = 1000, expiresAt = 10000, skewMs = 5000 → expiresAt - now() = 9000 > 5000 → skip
    await sm.saveUnlocked({
      email: KDF_VECTOR.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 10000,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await auth.refreshIfNeeded(5000);
    expect(api.refresh).not.toHaveBeenCalled();
  });

  it('refreshIfNeeded refreshes expiring tokens and persists the replacements', async () => {
    const api = {
      refresh: vi.fn(async () => ({
        access_token: 'new-access',
        expires_in: 3600,
        refresh_token: 'new-refresh',
        token_type: 'Bearer',
      })),
    };
    const { auth, sm } = makeService(api);
    await sm.saveUnlocked({
      email: KDF_VECTOR.email,
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await auth.refreshIfNeeded(5000);
    expect(api.refresh).toHaveBeenCalledWith('old-refresh');
    expect((await sm.getPersistedAuth())?.accessToken).toBe('new-access');
  });

  // --- Finding 5: logout clears pending login ---
  it('logout clears pending login so subsequent submitTwoFactor rejects', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0], token: 'tf' }),
    };
    const { auth } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await auth.logout();
    await expect(
      auth.submitTwoFactor({ provider: 0, code: '000000' }),
    ).rejects.toThrow('no pending 2FA login');
  });
});
