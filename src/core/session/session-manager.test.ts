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
    expect(bytesToHex((await sm.loadUserKey())!.encKey)).toBe(bytesToHex(userKey.encKey));
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
