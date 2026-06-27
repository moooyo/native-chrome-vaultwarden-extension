import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));
import { SessionManager } from './session-manager.js';
import { createMemoryStore } from '../../platform/store.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes, bytesToHex } from '../crypto/encoding.js';
import { USER_KEY_VECTOR } from '../../../test/vectors.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

describe('SessionManager', () => {
  it('starts loggedOut when no persisted auth exists', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('saveUnlocked persists tokens locally and userKey only in session storage', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: session });
    await sm.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });
    expect(await sm.getState()).toBe('unlocked');
    expect((await local.get<Record<string, unknown>>('auth'))?.accessToken).toBe('access');
    expect(await local.get('userKey')).toBeUndefined();
    const loaded = (await sm.loadUserKey())!;
    expect(bytesToHex(loaded.encKey)).toBe(bytesToHex(userKey.encKey));
    expect(bytesToHex(loaded.macKey)).toBe(bytesToHex(userKey.macKey));
  });

  it('lock removes only session key and leaves persisted auth', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: session });
    await sm.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });
    await sm.lock();
    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect((await sm.getPersistedAuth())?.refreshToken).toBe('refresh');
  });

  describe('saveTokens', () => {
    it('updates token fields while preserving non-token auth fields', async () => {
      const local = createMemoryStore();
      const session = createMemoryStore();
      const sm = new SessionManager({ localStore: local, sessionStore: session });
      await sm.saveUnlocked({
        email: 'user@example.com',
        accessToken: 'old-access',
        refreshToken: 'old-refresh',
        expiresAt: 100,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 600000,
        userKey,
      });

      await sm.saveTokens({ accessToken: 'new-access', refreshToken: 'new-refresh', expiresAt: 999 });

      const auth = await sm.getPersistedAuth();
      expect(auth?.accessToken).toBe('new-access');
      expect(auth?.refreshToken).toBe('new-refresh');
      expect(auth?.expiresAt).toBe(999);
      // non-token fields must be preserved
      expect(auth?.email).toBe('user@example.com');
      expect(auth?.protectedKey).toBe(USER_KEY_VECTOR.akey);
      expect(auth?.kdf).toBe(0);
      expect(auth?.kdfIterations).toBe(600000);
    });

    it('rejects with an error when no persisted auth exists', async () => {
      const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
      await expect(
        sm.saveTokens({ accessToken: 'a', refreshToken: 'r', expiresAt: 1 }),
      ).rejects.toThrow('cannot save tokens without persisted auth');
      // must not silently create auth
      expect(await sm.getPersistedAuth()).toBeUndefined();
    });
  });

  it('logout removes both persisted auth and session key', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });
    await sm.logout();
    expect(await sm.getState()).toBe('loggedOut');
  });
});
