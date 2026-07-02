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
import { base64ToBytes, bytesToHex, hexToBytes } from '../crypto/encoding.js';
import { symmetricKeyFromBytes, unwrapSymmetricKey } from '../crypto/keys.js';
import { deriveMasterKey, stretchMasterKey } from '../crypto/kdf.js';
import { KDF_VECTOR, KDF_VECTOR_600K, USER_KEY_VECTOR, USER_KEY_VECTOR_600K, RSA_PRIVATE_KEY_VECTOR } from '../../../test/vectors.js';

function makeService(
  api: Partial<ApiClient>,
  serverUrlProvider: () => Promise<string | undefined> = async () => 'https://vault.example',
) {
  const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
  return { sm, auth: new AuthService({ api: api as ApiClient, session: sm, now: () => 1000, serverUrlProvider }) };
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

  it('registers with client-derived key material, then auto-logs-in', async () => {
    const register = vi.fn().mockResolvedValue(undefined);
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'success' as const,
      data: {
        access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
        Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
      },
    });
    const api: Partial<ApiClient> = {
      register,
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    await expect(auth.register({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password, name: 'Tester' }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(register).toHaveBeenCalledTimes(1);
    const payload = (register.mock.calls[0] as [{ masterPasswordHash: string; key: string; keys: { publicKey: string }; name?: string }])[0];
    expect(payload.masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(payload.key.startsWith('2.')).toBe(true);
    expect(payload.keys.publicKey.length).toBeGreaterThan(0);
    expect(payload.name).toBe('Tester');
    expect(await sm.getState()).toBe('unlocked');
  });

  it('keeps pending login in memory and surfaces every advertised 2FA provider', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0, 1, 3, 7], token: 'tf' }),
    };
    const { auth, sm } = makeService(api);
    // All providers pass through (Authenticator, Email, YubiKey, FIDO2); the UI decides how to collect each.
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1, 3, 7], token: 'tf' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('submitTwoFactor forwards an arbitrary provider id and trims the code', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0, 3], token: 'tf' })
      .mockResolvedValueOnce({
        kind: 'success' as const,
        data: {
          access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
        },
      });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await auth.submitTwoFactor({ provider: 3, code: '  ccccccmyotp  ' }); // YubiKey OTP
    expect(passwordLogin.mock.calls[1]![0]).toMatchObject({ twoFactorProvider: 3, twoFactorToken: 'ccccccmyotp' });
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

  describe('verifyMasterPassword (reprompt)', () => {
    const persist = async (sm: SessionManager) => sm.saveUnlocked({
      email: KDF_VECTOR.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    it('returns true for the correct master password without changing lock state', async () => {
      const { auth, sm } = makeService({});
      await persist(sm);
      await expect(auth.verifyMasterPassword(KDF_VECTOR.password)).resolves.toBe(true);
      expect(await sm.getState()).toBe('unlocked'); // verification must not lock/unlock
    });

    it('returns false for a wrong master password (MAC failure), never throwing', async () => {
      const { auth, sm } = makeService({});
      await persist(sm);
      await expect(auth.verifyMasterPassword('not-the-password')).resolves.toBe(false);
      await expect(auth.verifyMasterPassword('')).resolves.toBe(false);
    });

    it('returns false when no account is persisted', async () => {
      const { auth } = makeService({});
      await expect(auth.verifyMasterPassword(KDF_VECTOR.password)).resolves.toBe(false);
    });
  });

  describe('changeMasterPassword / changeKdfIterations', () => {
    const persist600k = (sm: SessionManager) => sm.saveUnlocked({
      email: KDF_VECTOR_600K.email,
      accessToken: 'access', refreshToken: 'refresh', expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations,
      userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
    });
    const keyHex = (k: { encKey: Uint8Array; macKey: Uint8Array }) => bytesToHex(new Uint8Array([...k.encKey, ...k.macKey]));

    it('re-wraps the UserKey under the new password and updates the server + local material', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const { auth, sm } = makeService({ changePassword });
      await persist600k(sm);
      await auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master');
      const [accessToken, body] = changePassword.mock.calls[0]!;
      expect(accessToken).toBe('access');
      expect(body.masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64); // proves the current pw
      // The new protectedKey unwraps the SAME UserKey under the new password (vault is not re-encrypted).
      const newStretched = await stretchMasterKey(await deriveMasterKey('a-brand-new-master', KDF_VECTOR_600K.email, KDF_VECTOR_600K.iterations));
      expect(keyHex(await unwrapSymmetricKey(body.key, newStretched))).toBe(USER_KEY_VECTOR.userKeyHex);
      expect((await sm.getPersistedAuth())!.protectedKey).toBe(body.key); // local material updated
    });

    it('rejects a wrong current password and makes no server call', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const { auth, sm } = makeService({ changePassword });
      await persist600k(sm);
      await expect(auth.changeMasterPassword('wrong-current', 'whatever-new')).rejects.toThrow(/incorrect/i);
      expect(changePassword).not.toHaveBeenCalled();
    });

    it('changeKdfIterations re-wraps under the new iteration count and persists it', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {});
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      const newIters = 800_000;
      await auth.changeKdfIterations(KDF_VECTOR_600K.password, newIters);
      const [, body] = changeKdf.mock.calls[0]!;
      expect(body.kdfIterations).toBe(newIters);
      const newStretched = await stretchMasterKey(await deriveMasterKey(KDF_VECTOR_600K.password, KDF_VECTOR_600K.email, newIters));
      expect(keyHex(await unwrapSymmetricKey(body.key, newStretched))).toBe(USER_KEY_VECTOR.userKeyHex);
      expect((await sm.getPersistedAuth())!.kdfIterations).toBe(newIters);
    });

    it('changeKdfIterations refuses an unsafe iteration count', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {});
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      await expect(auth.changeKdfIterations(KDF_VECTOR_600K.password, 1000)).rejects.toThrow(/unsafe KDF/);
      expect(changeKdf).not.toHaveBeenCalled();
    });
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

  // PIN unlock tests use a 5000-iteration KDF so the PBKDF2 derivation stays fast.
  async function makeUnlocked() {
    const { auth, sm } = makeService({});
    const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    await sm.saveUnlocked({
      email: 'u@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });
    return { auth, sm, userKey };
  }

  it('sets a PIN and unlocks with it after locking', async () => {
    const { auth, sm, userKey } = await makeUnlocked();
    await auth.setPin('1357');
    expect(await auth.isPinEnabled()).toBe(true);
    await sm.lock();
    expect(await sm.getState()).toBe('locked');
    await auth.unlockWithPin('1357');
    expect(await sm.getState()).toBe('unlocked');
    expect(bytesToHex((await sm.loadUserKey())!.encKey)).toBe(bytesToHex(userKey.encKey));
  });

  it('rejects unlock with the wrong PIN', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('1357');
    await sm.lock();
    await expect(auth.unlockWithPin('0000')).rejects.toThrow();
    expect(await sm.getState()).toBe('locked');
  });

  it('disablePin removes the PIN-protected key', async () => {
    const { auth } = await makeUnlocked();
    await auth.setPin('1357');
    await auth.disablePin();
    expect(await auth.isPinEnabled()).toBe(false);
  });

  describe('remember-device: capture on success', () => {
    const SERVER_URL = 'https://vault.example';
    const email = KDF_VECTOR_600K.email.trim().toLowerCase();

    function successData(twoFactorToken?: string) {
      return {
        kind: 'success' as const,
        data: {
          access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
          ...(twoFactorToken ? { TwoFactorToken: twoFactorToken } : {}),
        },
      };
    }

    it('saves the token when a 2FA success returns TwoFactorToken (remember opt-in)', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData('remember-tok-1'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await auth.submitTwoFactor({ provider: 0, code: '123456', remember: true });
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBe('remember-tok-1');
    });

    it('does NOT save when the success response carries no TwoFactorToken', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await auth.submitTwoFactor({ provider: 0, code: '123456', remember: false });
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBeUndefined();
    });

    it('does not save when no serverUrl is configured', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData('remember-tok-1'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api, async () => undefined);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await auth.submitTwoFactor({ provider: 0, code: '123456', remember: true });
      expect(await sm.getRememberDeviceToken('https://vault.example', email)).toBeUndefined();
    });

    it('a failed token save does NOT fail an already-unlocked login', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData('remember-tok-1'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      vi.spyOn(sm, 'saveRememberDeviceToken').mockRejectedValue(new Error('storage write failed'));
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await expect(auth.submitTwoFactor({ provider: 0, code: '123456', remember: true }))
        .resolves.toEqual({ kind: 'unlocked' });
      expect(await sm.getState()).toBe('unlocked');
    });
  });

  describe('remember-device: reuse on login', () => {
    const SERVER_URL = 'https://vault.example';
    const email = KDF_VECTOR_600K.email.trim().toLowerCase();

    function successData(twoFactorToken?: string) {
      return {
        kind: 'success' as const,
        data: {
          access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
          ...(twoFactorToken ? { TwoFactorToken: twoFactorToken } : {}),
        },
      };
    }

    it('valid stored token → sends provider=5 and skips the 2FA screen; captures the rotated token', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce(successData('rotated-T2'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stored-T1');
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'unlocked' });
      // Exactly one passwordLogin call, and it carried the Remember provider + stored token.
      expect(passwordLogin).toHaveBeenCalledTimes(1);
      expect(passwordLogin.mock.calls[0]![0]).toMatchObject({
        twoFactorProvider: 5, twoFactorToken: 'stored-T1', remember: true,
      });
      // Rotation synced: the stored token is now the server's new one.
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBe('rotated-T2');
    });

    it('stale stored token → clears it and drives 2FA from the SAME result (no re-send)', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0, 1], token: 'tf' });
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stale-T1');
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1], token: 'tf' });
      // Only ONE passwordLogin call — the stale-token attempt already returned the real providers.
      expect(passwordLogin).toHaveBeenCalledTimes(1);
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBeUndefined();
    });

    it('reuse attempt throws → clears the token and retries once WITHOUT it', async () => {
      const passwordLogin = vi.fn()
        .mockRejectedValueOnce(new Error('boom 500'))
        .mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stale-T1');
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'unlocked' });
      expect(passwordLogin).toHaveBeenCalledTimes(2);
      // First call carried provider=5; the retry carried no 2FA fields.
      expect(passwordLogin.mock.calls[0]![0]).toMatchObject({ twoFactorProvider: 5 });
      expect(passwordLogin.mock.calls[1]![0].twoFactorProvider).toBeUndefined();
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBeUndefined();
    });

    it('no stored token → ordinary login (no provider=5 attempt)', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth } = makeService(api);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      expect(passwordLogin).toHaveBeenCalledTimes(1);
      expect(passwordLogin.mock.calls[0]![0].twoFactorProvider).toBeUndefined();
    });
  });

  describe('remember-device: forget / query / removeAccount cleanup', () => {
    const SERVER_URL = 'https://vault.example';

    async function persist(sm: SessionManager, email: string) {
      await sm.saveUnlocked({
        email, accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000,
        userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
      });
    }

    it('isDeviceRemembered(email) reflects whether a token is stored', async () => {
      const { auth, sm } = makeService({});
      expect(await auth.isDeviceRemembered('u@x.com')).toBe(false);
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      expect(await auth.isDeviceRemembered('u@x.com')).toBe(true);
    });

    it('isDeviceRemembered() defaults to the current account', async () => {
      const { auth, sm } = makeService({});
      await persist(sm, 'active@x.com');
      expect(await auth.isDeviceRemembered()).toBe(false);
      await sm.saveRememberDeviceToken(SERVER_URL, 'active@x.com', 'tok');
      expect(await auth.isDeviceRemembered()).toBe(true);
    });

    it('forgetDevice(email) removes the stored token', async () => {
      const { auth, sm } = makeService({});
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      await auth.forgetDevice('u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBeUndefined();
    });

    it('forgetDevice() defaults to the current account', async () => {
      const { auth, sm } = makeService({});
      await persist(sm, 'active@x.com');
      await sm.saveRememberDeviceToken(SERVER_URL, 'active@x.com', 'tok');
      await auth.forgetDevice();
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'active@x.com')).toBeUndefined();
    });

    it('forgetDevice normalizes the email', async () => {
      const { auth, sm } = makeService({});
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      await auth.forgetDevice('  U@X.COM  ');
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBeUndefined();
    });

    it('removeAccount clears that account’s remember token', async () => {
      const { auth, sm } = makeService({});
      await persist(sm, 'u@x.com');
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      await auth.removeAccount('u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBeUndefined();
      expect((await sm.listAccounts()).map((a) => a.email)).toEqual([]);
    });

    it('query methods return false / no-op when no server is configured', async () => {
      const { auth, sm } = makeService({}, async () => undefined);
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      expect(await auth.isDeviceRemembered('u@x.com')).toBe(false);
      await auth.forgetDevice('u@x.com'); // no throw
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBe('tok'); // untouched
    });
  });
});
