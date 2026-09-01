import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));
import { MAX_ACCOUNT_COUNT, SessionManager, type PersistedAuth } from './session-manager.js';
import { createMemoryStore, type AtomicKeyValueStore, type KeyValueStore } from '../../platform/store.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes, bytesToHex, base64ToBytes } from '../crypto/encoding.js';
import { USER_KEY_VECTOR, RSA_PRIVATE_KEY_VECTOR } from '../../../test/vectors.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
const privateKeyBytes = base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64);

function persistedAuth(email: string): PersistedAuth {
  return {
    email,
    accessToken: `access-${email}`,
    refreshToken: `refresh-${email}`,
    expiresAt: 999_999,
    protectedKey: USER_KEY_VECTOR.akey,
    kdf: 0,
    kdfIterations: 600_000,
  };
}

function persistedAccountRegistry(count: number): Record<string, PersistedAuth> {
  return Object.fromEntries(Array.from({ length: count }, (_, index) => {
    const email = index === 0 ? 'active@example.com' : `account-${index}@example.com`;
    return [email, persistedAuth(email)];
  }));
}

async function snapshotAccountState(local: KeyValueStore, session: KeyValueStore) {
  const [auth, accounts, pinConfigurations, sessionSecrets, pinEnvelopes, pinFailures] = await Promise.all([
    local.get<unknown>('auth'),
    local.get<unknown>('accounts'),
    local.get<unknown>('pinConfigurations'),
    session.get<unknown>('sessionSecrets'),
    session.get<unknown>('pinEphemeralEnvelopes'),
    session.get<unknown>('pinFailures'),
  ]);
  return { auth, accounts, pinConfigurations, sessionSecrets, pinEnvelopes, pinFailures };
}

function failAfterAwait(
  store: AtomicKeyValueStore,
  target: number,
  counter: { value: number },
): AtomicKeyValueStore {
  const after = <T>(value: T): T => {
    counter.value++;
    if (counter.value === target) throw new Error(`simulated interruption ${target}`);
    return value;
  };
  return {
    async get<T>(key: string) { return after(await store.get<T>(key)); },
    async set(key: string, value: unknown) { await store.set(key, value); after(undefined); },
    async setMany(values: Readonly<Record<string, unknown>>) {
      await store.setMany(values);
      after(undefined);
    },
    async remove(key: string) { await store.remove(key); after(undefined); },
    async clear() { await store.clear(); after(undefined); },
  };
}

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

  it('keeps a logout-mode login and refresh tokens only in browser session storage', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({
      localStore: local,
      sessionStore: browserSession,
      defaultTokenStorage: 'session',
    });
    await sm.saveUnlocked({
      ...persistedAuth('session@example.com'),
      accessToken: 'session-access',
      refreshToken: 'session-refresh',
      userKey,
    });
    const beforeRefresh = (await sm.getActiveAuth())!;

    expect(JSON.stringify(await local.get('auth'))).not.toContain('session-access');
    expect(JSON.stringify(await local.get('accounts'))).not.toContain('session-refresh');
    expect(JSON.stringify(await browserSession.get('authTokens'))).toContain('session-access');
    expect(await sm.getState()).toBe('unlocked');

    await expect(sm.saveTokensFor({
      email: beforeRefresh.email,
      refreshToken: beforeRefresh.refreshToken,
    }, {
      accessToken: 'rotated-access',
      refreshToken: 'rotated-refresh',
      expiresAt: 1_234_567,
    })).resolves.toBe(true);
    await sm.lock();

    expect(JSON.stringify(await local.get('auth'))).not.toContain('rotated-access');
    expect(JSON.stringify(await local.get('accounts'))).not.toContain('rotated-refresh');
    expect(JSON.stringify(await browserSession.get('authTokens'))).toContain('rotated-refresh');
    expect((await sm.getActiveAuth())?.accessToken).toBe('rotated-access');
    expect(await sm.getState()).toBe('locked');
  });

  it('moves the active token bundle between timeout-policy storage tiers without changing its session binding', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({ ...persistedAuth('move@example.com'), userKey });
    const binding = (await sm.getActiveAuth())!.sessionBindingId;
    if (!binding) throw new Error('expected unlocked session binding');

    await expect(sm.reconcileActiveTokenStorage({
      email: 'move@example.com',
      sessionBindingId: binding,
    }, 'session')).resolves.toBe(true);
    expect(JSON.stringify(await local.get('auth'))).not.toContain('access-move@example.com');
    expect(JSON.stringify(await local.get('accounts'))).not.toContain('refresh-move@example.com');
    expect((await sm.getActiveAuth())?.sessionBindingId).toBe(binding);

    await expect(sm.reconcileActiveTokenStorage({
      email: 'move@example.com',
      sessionBindingId: binding,
    }, 'local')).resolves.toBe(true);
    expect(JSON.stringify(await local.get('auth'))).toContain('access-move@example.com');
    expect(await browserSession.get('authTokens')).toBeUndefined();
    expect((await sm.getActiveAuth())?.sessionBindingId).toBe(binding);
  });

  it('preserves local accounts while retiring session-token accounts after a browser restart', async () => {
    const local = createMemoryStore();
    const firstBrowserSession = createMemoryStore();
    const localManager = new SessionManager({ localStore: local, sessionStore: firstBrowserSession });
    await localManager.saveUnlocked({ ...persistedAuth('local@example.com'), userKey });
    const sessionManager = new SessionManager({
      localStore: local,
      sessionStore: firstBrowserSession,
      defaultTokenStorage: 'session',
    });
    await sessionManager.saveUnlocked({ ...persistedAuth('session@example.com'), userKey });

    const restarted = new SessionManager({
      localStore: local,
      sessionStore: createMemoryStore(),
      defaultTokenStorage: 'session',
    });
    await expect(restarted.recoverInvalidAccountRegistry()).resolves.toBe(true);

    expect(await restarted.listAccounts()).toEqual([{ email: 'local@example.com', active: true }]);
    expect((await restarted.getPersistedAuth())?.email).toBe('local@example.com');
    expect(await restarted.getState()).toBe('locked');
  });

  it('commits a rotated token to its inactive owner and rejects remove-relogin ABA', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({
      localStore: local,
      sessionStore: browserSession,
      defaultTokenStorage: 'session',
    });
    await sm.saveUnlocked({ ...persistedAuth('a@example.com'), userKey });
    const original = (await sm.getActiveAuthSnapshot())!;
    const permit = (await sm.prepareTokenRefresh({
      ...original.tokenLease,
      serverUrl: 'https://vault.example/',
    }))!;
    await sm.saveUnlocked({ ...persistedAuth('b@example.com'), userKey });

    await expect(sm.commitTokenRefresh(permit, {
      accessToken: 'a-access-2', refreshToken: 'a-refresh-2', expiresAt: 2_000_000,
    })).resolves.toMatchObject({
      email: 'a@example.com',
      credentialId: original.tokenLease.credentialId,
      tokenRevision: permit.nextTokenRevision,
    });
    await sm.switchAccount('a@example.com');
    expect(await sm.getPersistedAuth()).toMatchObject({
      accessToken: 'a-access-2', refreshToken: 'a-refresh-2',
    });

    const rotated = (await sm.getActiveAuthSnapshot())!;
    const stalePermit = (await sm.prepareTokenRefresh({
      ...rotated.tokenLease,
      serverUrl: 'https://vault.example/',
    }))!;
    await sm.removeAccount('a@example.com');
    await sm.saveUnlocked({ ...persistedAuth('a@example.com'), userKey });
    const replacement = (await sm.getActiveAuthSnapshot())!;
    expect(replacement.tokenLease.credentialId).not.toBe(rotated.tokenLease.credentialId);
    await expect(sm.commitTokenRefresh(stalePermit, {
      accessToken: 'stale', refreshToken: 'stale', expiresAt: 3_000_000,
    })).resolves.toBeUndefined();
    expect((await sm.getPersistedAuth())?.accessToken).toBe('access-a@example.com');
    expect(JSON.stringify(await local.get('accounts'))).not.toContain('a-refresh-2');
  });

  it('recovers a committed session refresh intent and retires an ambiguous one', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({
      localStore: local,
      sessionStore: browserSession,
      defaultTokenStorage: 'session',
    });
    await sm.saveUnlocked({ ...persistedAuth('recover@example.com'), userKey });
    const snapshot = (await sm.getActiveAuthSnapshot())!;
    const permit = (await sm.prepareTokenRefresh({
      ...snapshot.tokenLease,
      serverUrl: 'https://vault.example/',
    }))!;
    const tokens = (await browserSession.get<Record<string, Record<string, unknown>>>('authTokens'))!;
    const [bindingId, token] = Object.entries(tokens)[0]!;
    await browserSession.set('authTokens', {
      ...tokens,
      [bindingId]: {
        ...token,
        tokenRevision: permit.nextTokenRevision,
        accessToken: 'recovered-access',
        refreshToken: 'recovered-refresh',
      },
    });

    const restarted = new SessionManager({
      localStore: local,
      sessionStore: browserSession,
      defaultTokenStorage: 'session',
    });
    await expect(restarted.recoverInvalidAccountRegistry()).resolves.toBe(true);
    expect(await restarted.getPersistedAuth()).toMatchObject({
      accessToken: 'recovered-access', refreshToken: 'recovered-refresh',
    });

    const current = (await restarted.getActiveAuthSnapshot())!;
    await restarted.prepareTokenRefresh({
      ...current.tokenLease,
      serverUrl: 'https://vault.example/',
    });
    const interrupted = new SessionManager({
      localStore: local,
      sessionStore: browserSession,
      defaultTokenStorage: 'session',
    });
    await expect(interrupted.recoverInvalidAccountRegistry()).resolves.toBe(true);
    await expect(interrupted.getState()).resolves.toBe('loggedOut');
  });

  it('rolls back a rejected global tightening and restores all local-logout owners', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({ ...persistedAuth('a@example.com'), userKey });
    await sm.saveUnlocked({ ...persistedAuth('b@example.com'), userKey });

    const receipt = await sm.moveAllTokensToSession();
    expect(receipt.moved).toHaveLength(2);
    await sm.rollbackTokenStorageMove(receipt);
    expect(await browserSession.get('authTokens')).toBeUndefined();
    expect(JSON.stringify(await local.get('accounts'))).toContain('refresh-a@example.com');

    await sm.moveAllTokensToSession();
    await sm.restoreLocalLogoutTokensToLocal();
    expect(await browserSession.get('authTokens')).toBeUndefined();
    expect(JSON.stringify(await local.get('accounts'))).toContain('refresh-b@example.com');
  });

  it('fails closed when legacy auth and account token generations disagree', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({ ...persistedAuth('legacy-mismatch@example.com'), userKey });
    await local.set('accounts', {
      'legacy-mismatch@example.com': {
        ...persistedAuth('legacy-mismatch@example.com'),
        accessToken: 'stale-access',
        refreshToken: 'stale-refresh',
      },
    });

    await expect(sm.recoverInvalidAccountRegistry()).resolves.toBe(true);
    await expect(sm.getState()).resolves.toBe('loggedOut');
    expect(JSON.stringify(await local.get('auth')) ?? '').not.toContain('stale-refresh');
  });

  it('fails closed without restoring local tokens when a tightening session write fails', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const failingSession: AtomicKeyValueStore = {
      get: (key) => browserSession.get(key),
      set: async (key, value) => {
        if (key === 'authTokens') throw new Error('session write failed');
        await browserSession.set(key, value);
      },
      setMany: (values) => browserSession.setMany(values),
      remove: (key) => browserSession.remove(key),
      clear: () => browserSession.clear(),
    };
    const seed = new SessionManager({ localStore: local, sessionStore: browserSession });
    await seed.saveUnlocked({ ...persistedAuth('tighten@example.com'), userKey });
    const interrupted = new SessionManager({ localStore: local, sessionStore: failingSession });

    await expect(interrupted.moveAllTokensToSession()).rejects.toThrow('session write failed');

    expect(JSON.stringify(await local.get('auth')) ?? '').not.toContain('access-tighten@example.com');
    expect(JSON.stringify(await local.get('accounts')) ?? '').not.toContain('refresh-tighten@example.com');
    expect(await interrupted.getState()).toBe('loggedOut');
  });

  it('does not retain an older local token when a session-tier re-login cannot publish its slot', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const seed = new SessionManager({ localStore: local, sessionStore: browserSession });
    await seed.saveUnlocked({ ...persistedAuth('relogin@example.com'), userKey });
    const failingSession: AtomicKeyValueStore = {
      async get<T>(key: string) { return browserSession.get<T>(key); },
      async set(key, value) {
        if (key === 'authTokens') throw new Error('slot unavailable');
        await browserSession.set(key, value);
      },
      setMany: (values) => browserSession.setMany(values),
      remove: (key) => browserSession.remove(key),
      clear: () => browserSession.clear(),
    };
    const relogin = new SessionManager({
      localStore: local,
      sessionStore: failingSession,
      defaultTokenStorage: 'session',
    });

    await expect(relogin.saveUnlocked({
      ...persistedAuth('relogin@example.com'),
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      userKey,
    })).rejects.toThrow('slot unavailable');

    const localState = JSON.stringify({
      auth: await local.get('auth'),
      accounts: await local.get('accounts'),
    });
    expect(localState).not.toContain('access-relogin@example.com');
    expect(localState).not.toContain('refresh-relogin@example.com');
    expect(localState).not.toContain('new-access');
    expect(localState).not.toContain('new-refresh');
    expect(await relogin.getState()).toBe('loggedOut');
  });

  it('finishes a tightening move when the tokenless local batch commits before rejecting', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const seed = new SessionManager({ localStore: local, sessionStore: browserSession });
    await seed.saveUnlocked({ ...persistedAuth('commit-then-reject@example.com'), userKey });
    let rejectBatch = true;
    const uncertainLocal: AtomicKeyValueStore = {
      async get<T>(key: string) { return local.get<T>(key); },
      set: (key, value) => local.set(key, value),
      async setMany(values) {
        await local.setMany(values);
        if (rejectBatch) {
          rejectBatch = false;
          throw new Error('uncertain local batch');
        }
      },
      remove: (key) => local.remove(key),
      clear: () => local.clear(),
    };
    const manager = new SessionManager({ localStore: uncertainLocal, sessionStore: browserSession });

    await expect(manager.moveAllTokensToSession()).resolves.toMatchObject({
      moved: [expect.objectContaining({ email: 'commit-then-reject@example.com' })],
    });

    expect(JSON.stringify(await local.get('auth'))).not.toContain('access-commit-then-reject');
    expect(JSON.stringify(await browserSession.get('authTokens'))).toContain('access-commit-then-reject');
    expect(await manager.getState()).toBe('unlocked');
  });

  it('saveLockedAuthenticated atomically publishes auth without any session secrets', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: session });
    await sm.saveLockedAuthenticated({
      email: 'passkey@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      kdf: 0,
      kdfIterations: 600_000,
    });

    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(await sm.loadPrivateKey()).toBeUndefined();
    expect(await local.get('auth')).toEqual(expect.objectContaining({
      email: 'passkey@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
    }));
    expect(await local.get<Record<string, unknown>>('accounts')).toHaveProperty(
      'passkey@example.com',
    );
    expect(await session.get('sessionSecrets')).toBeUndefined();
  });

  it('persists a restricted account without a session binding or decrypted secrets', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: session });
    await sm.saveRestrictedAuthenticated({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600_000,
      restriction: {
        schemaVersion: 1,
        reason: 'adminForcePasswordReset',
      },
    });

    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(await sm.loadPrivateKey()).toBeUndefined();
    expect(await session.get('sessionSecrets')).toBeUndefined();
    expect(await local.get<Record<string, unknown>>('auth')).not.toHaveProperty('sessionBindingId');
  });

  it('purges forged matching secrets and binding when restricted state is restored', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const first = new SessionManager({
      localStore: local,
      sessionStore: session,
      createSessionBindingId: () => 'forged-binding',
    });
    await first.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600_000,
      userKey,
      privateKey: privateKeyBytes,
    });
    const forged = await local.get<Record<string, unknown>>('auth');
    await local.set('auth', {
      ...forged,
      restriction: { schemaVersion: 1, reason: 'adminForcePasswordReset' },
    });

    const restarted = new SessionManager({ localStore: local, sessionStore: session });
    await restarted.initialize();

    expect(await restarted.getState()).toBe('restricted');
    expect(await restarted.loadUserKey()).toBeUndefined();
    expect(await restarted.loadPrivateKey()).toBeUndefined();
    expect(await session.get('sessionSecrets')).toBeUndefined();
    expect(await local.get<Record<string, unknown>>('auth')).not.toHaveProperty('sessionBindingId');
  });

  it('never exposes old session secrets during an interrupted locked-authenticated commit', async () => {
    // Await 1 is the read-only account-admission preflight. Once the first write begins, every
    // interruption must leave the previous secret bundle unusable.
    for (let failAt = 3; failAt <= 8; failAt++) {
      const local = createMemoryStore();
      const session = createMemoryStore();
      const first = new SessionManager({
        localStore: local,
        sessionStore: session,
        createSessionBindingId: () => 'old-binding',
      });
      await first.saveUnlocked({
        email: 'old@example.com',
        accessToken: 'old-access',
        refreshToken: 'old-refresh',
        expiresAt: 100,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 600_000,
        userKey,
      });
      const counter = { value: 0 };
      const interrupted = new SessionManager({
        localStore: failAfterAwait(local, failAt, counter),
        sessionStore: failAfterAwait(session, failAt, counter),
      });

      await expect(interrupted.saveLockedAuthenticated({
        email: 'new@example.com',
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
        expiresAt: 200,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 600_000,
      })).rejects.toThrow(`simulated interruption ${failAt}`);

      const restarted = new SessionManager({ localStore: local, sessionStore: session });
      expect(await restarted.getState()).not.toBe('unlocked');
      expect(await restarted.loadUserKey()).toBeUndefined();
    }
  });

  it('binds active auth and one versioned secret bundle while keeping the registry unbound', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({
      localStore: local,
      sessionStore: session,
      createSessionBindingId: () => 'binding-1',
    });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'access', refreshToken: 'refresh', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      privateKey: privateKeyBytes,
    });

    expect(await local.get('auth')).toMatchObject({
      email: 'user@example.com', sessionBindingId: 'binding-1',
    });
    expect(await session.get('sessionSecrets')).toMatchObject({
      schemaVersion: 1,
      owner: 'user@example.com',
      sessionBindingId: 'binding-1',
      userKey: expect.any(String),
      privateKey: expect.any(String),
    });
    expect(await session.get('userKey')).toBeUndefined();
    expect(await session.get('privateKey')).toBeUndefined();
    const accounts = await local.get<Record<string, Record<string, unknown>>>('accounts');
    expect(accounts?.['user@example.com']?.sessionBindingId).toBeUndefined();
  });

  it('never exposes one account key under another auth after any interrupted save await', async () => {
    const keyB = symmetricKeyFromBytes(new Uint8Array(64).fill(7));
    for (let failAt = 1; failAt <= 6; failAt++) {
      const local = createMemoryStore();
      const session = createMemoryStore();
      const first = new SessionManager({
        localStore: local,
        sessionStore: session,
        createSessionBindingId: () => 'binding-a',
      });
      await first.saveUnlocked({
        email: 'a@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 100,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      });

      const counter = { value: 0 };
      const interrupted = new SessionManager({
        localStore: failAfterAwait(local, failAt, counter),
        sessionStore: failAfterAwait(session, failAt, counter),
        createSessionBindingId: () => 'binding-b',
      });
      await expect(interrupted.saveUnlocked({
        email: 'b@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 200,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey: keyB,
      })).rejects.toThrow(`simulated interruption ${failAt}`);

      const restarted = new SessionManager({ localStore: local, sessionStore: session });
      const state = await restarted.getState();
      const auth = await restarted.getPersistedAuth();
      const loaded = await restarted.loadUserKey();
      if (state === 'unlocked') {
        expect(loaded).toBeDefined();
        const expected = auth?.email === 'b@example.com' ? keyB : userKey;
        expect(bytesToHex(loaded!.encKey)).toBe(bytesToHex(expected.encKey));
      } else {
        expect(loaded).toBeUndefined();
      }
    }
  });

  it('fails closed when the active owner or binding does not match the secret bundle', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({
      localStore: local,
      sessionStore: session,
      createSessionBindingId: () => 'binding-a',
    });
    await sm.saveUnlocked({
      email: 'a@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    const auth = await local.get<Record<string, unknown>>('auth');
    await local.set('auth', { ...auth, email: 'b@example.com' });

    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(await sm.loadPrivateKey()).toBeUndefined();
  });

  it('revalidates the binding after reading secrets, including same-owner ABA changes', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const first = new SessionManager({
      localStore: local,
      sessionStore: session,
      createSessionBindingId: () => 'binding-a',
    });
    await first.saveUnlocked({
      email: 'same@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    const firstAuth = await local.get<unknown>('auth');
    const firstSecrets = await session.get<unknown>('sessionSecrets');
    const second = new SessionManager({
      localStore: local,
      sessionStore: session,
      createSessionBindingId: () => 'binding-b',
    });
    await second.saveUnlocked({
      email: 'same@example.com', accessToken: 'b', refreshToken: 'r2', expiresAt: 200,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    const secondAuth = await local.get<unknown>('auth');
    await local.set('auth', firstAuth);
    await session.set('sessionSecrets', firstSecrets);

    let authReads = 0;
    const racingLocal: KeyValueStore = {
      async get<T>(key: string) {
        const value = await local.get<T>(key);
        if (key === 'auth' && ++authReads === 2) return secondAuth as T;
        return value;
      },
      set: (key, value) => local.set(key, value),
      setMany: (values) => local.setMany(values),
      remove: (key) => local.remove(key),
      clear: () => local.clear(),
    };
    const racing = new SessionManager({ localStore: racingLocal, sessionStore: session });
    expect(await racing.loadUserKey()).toBeUndefined();
  });

  it('cleans legacy secret slots during startup migration and leaves the account locked', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    await local.set('auth', {
      email: 'legacy@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000,
    });
    await session.set('userKey', 'legacy-user-key');
    await session.set('privateKey', 'legacy-private-key');
    const sm = new SessionManager({ localStore: local, sessionStore: session });

    await sm.initialize();

    expect(await sm.getState()).toBe('locked');
    expect(await session.get('userKey')).toBeUndefined();
    expect(await session.get('privateKey')).toBeUndefined();
    expect((await sm.getPersistedAuth())?.email).toBe('legacy@example.com');
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

  describe('saveTokensFor', () => {
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

      await expect(sm.saveTokensFor(
        { email: 'user@example.com', refreshToken: 'old-refresh' },
        { accessToken: 'new-access', refreshToken: 'new-refresh', expiresAt: 999 },
      )).resolves.toBe(true);

      const auth = await sm.getPersistedAuth();
      expect(auth?.accessToken).toBe('new-access');
      expect(auth?.refreshToken).toBe('new-refresh');
      expect(auth?.expiresAt).toBe(999);
      // non-token fields must be preserved
      expect(auth?.email).toBe('user@example.com');
      expect(auth?.protectedKey).toBe(USER_KEY_VECTOR.akey);
      expect(auth?.kdf).toBe(0);
      expect(auth?.kdfIterations).toBe(600000);
      expect(await sm.getState()).toBe('unlocked');
    });

    it('returns false when no persisted auth exists', async () => {
      const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
      await expect(sm.saveTokensFor(
        { email: 'user@example.com', refreshToken: 'old-refresh' },
        { accessToken: 'a', refreshToken: 'r', expiresAt: 1 },
      )).resolves.toBe(false);
      expect(await sm.getPersistedAuth()).toBeUndefined();
    });

    it('does not apply refreshed tokens to a different active account', async () => {
      const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
      await sm.saveUnlocked({
        email: 'active@example.com', accessToken: 'active', refreshToken: 'active-refresh', expiresAt: 100,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      });

      await expect(sm.saveTokensFor(
        { email: 'stale@example.com', refreshToken: 'stale-refresh' },
        { accessToken: 'wrong', refreshToken: 'wrong-refresh', expiresAt: 999 },
      )).resolves.toBe(false);
      expect(await sm.getPersistedAuth()).toMatchObject({
        email: 'active@example.com',
        accessToken: 'active',
        refreshToken: 'active-refresh',
      });
    });

    it('does not overwrite a newer access token when the refresh token did not rotate', async () => {
      const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
      await sm.saveUnlocked({
        email: 'user@example.com', accessToken: 'newer-access', refreshToken: 'same-refresh', expiresAt: 500,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      });

      await expect(sm.saveTokensFor(
        { email: 'user@example.com', accessToken: 'rejected-access', refreshToken: 'same-refresh' },
        { accessToken: 'late-access', refreshToken: 'same-refresh', expiresAt: 999 },
      )).resolves.toBe(false);

      expect(await sm.getPersistedAuth()).toMatchObject({
        accessToken: 'newer-access',
        refreshToken: 'same-refresh',
        expiresAt: 500,
      });
    });

    it('updates the same account after its ephemeral session binding changes', async () => {
      const local = createMemoryStore();
      const session = createMemoryStore();
      let binding = 0;
      const sm = new SessionManager({
        localStore: local,
        sessionStore: session,
        createSessionBindingId: () => `binding-${++binding}`,
      });
      const input = {
        email: 'user@example.com', accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 100,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0 as const, kdfIterations: 600000, userKey,
      };
      await sm.saveUnlocked(input);
      await sm.lock();
      await sm.saveUnlocked(input);

      await expect(sm.saveTokensFor(
        { email: 'user@example.com', refreshToken: 'old-refresh' },
        { accessToken: 'new-access', refreshToken: 'new-refresh', expiresAt: 999 },
      )).resolves.toBe(true);

      expect(await sm.getActiveAuth()).toMatchObject({
        sessionBindingId: 'binding-2',
        refreshToken: 'new-refresh',
      });
      expect(await sm.getState()).toBe('unlocked');
    });

    it.each(['before', 'after'] as const)(
      'keeps auth and the account registry on the same token generation when the bulk write fails %s commit',
      async (failurePoint) => {
        const local = createMemoryStore();
        const session = createMemoryStore();
        const initial = new SessionManager({
          localStore: local,
          sessionStore: session,
          createSessionBindingId: () => 'binding-1',
        });
        await initial.saveUnlocked({
          email: 'user@example.com', accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 100,
          protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
        });
        const failingLocal: KeyValueStore = {
          get: <T>(key: string) => local.get<T>(key),
          set: (key, value) => local.set(key, value),
          async setMany(values) {
            if (failurePoint === 'after') await local.setMany(values);
            throw new Error(`bulk write failed ${failurePoint}`);
          },
          remove: (key) => local.remove(key),
          clear: () => local.clear(),
        };
        const updating = new SessionManager({ localStore: failingLocal, sessionStore: session });

        await expect(updating.saveTokensFor(
          { email: 'user@example.com', refreshToken: 'old-refresh' },
          { accessToken: 'new-access', refreshToken: 'new-refresh', expiresAt: 999 },
        )).rejects.toThrow(`bulk write failed ${failurePoint}`);

        const restarted = new SessionManager({ localStore: local, sessionStore: session });
        const expectedToken = failurePoint === 'before' ? 'old-refresh' : 'new-refresh';
        expect((await restarted.getPersistedAuth())?.refreshToken).toBe(expectedToken);
        expect((await local.get<Record<string, PersistedAuth>>('accounts'))?.['user@example.com']?.refreshToken)
          .toBe(expectedToken);
        expect(await restarted.getState()).toBe('unlocked');
      },
    );
  });

  it('logs out only when the optional access-token expectation is still current', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'current-access', refreshToken: 'same-refresh', expiresAt: 500,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });

    await expect(sm.logoutIfCurrent({
      email: 'user@example.com', accessToken: 'stale-access', refreshToken: 'same-refresh',
    })).resolves.toBe(false);
    await expect(sm.getState()).resolves.toBe('unlocked');

    await expect(sm.logoutIfCurrent({
      email: 'user@example.com', accessToken: 'current-access', refreshToken: 'same-refresh',
    })).resolves.toBe(true);
    await expect(sm.getState()).resolves.toBe('loggedOut');
  });

  it('normalizes a legacy PBKDF2 auth record that predates the kdf discriminator', async () => {
    const localStore = createMemoryStore();
    await localStore.set('auth', {
      email: 'user@example.com', accessToken: 'access', refreshToken: 'refresh', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdfIterations: 600_000,
    });
    const sm = new SessionManager({ localStore, sessionStore: createMemoryStore() });
    expect(await sm.getPersistedAuth()).toMatchObject({ kdf: 0, kdfIterations: 600_000 });
  });

  it('persists complete Argon2id settings and rejects incomplete persisted settings', async () => {
    const localStore = createMemoryStore();
    const sm = new SessionManager({ localStore, sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'access', refreshToken: 'refresh', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 1, kdfIterations: 4, kdfMemory: 32, kdfParallelism: 2,
      userKey,
    });
    expect(await sm.getPersistedAuth()).toMatchObject({
      kdf: 1, kdfIterations: 4, kdfMemory: 32, kdfParallelism: 2,
    });

    await localStore.set('auth', {
      email: 'user@example.com', accessToken: 'access', refreshToken: 'refresh', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 1, kdfIterations: 4,
    });
    await expect(sm.getPersistedAuth()).rejects.toThrow(/Argon2 memory/);
  });

  it('refuses to apply master-key material to a different active account', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'active@example.com',
      accessToken: 'active-access',
      refreshToken: 'active-refresh',
      expiresAt: 999,
      protectedKey: 'active-protected-key',
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });

    await expect(sm.updateMasterKeyMaterialFor({
      email: 'stale@example.com',
      protectedKey: 'stale-protected-key',
      kdf: 0,
      kdfIterations: 5000,
    }, { protectedKey: 'new-stale-protected-key' })).rejects.toThrow('active account key material changed');

    expect(await sm.getPersistedAuth()).toMatchObject({
      email: 'active@example.com',
      protectedKey: 'active-protected-key',
      kdfIterations: 600000,
    });
  });

  it('logout removes both persisted auth and session key', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
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
    await sm.savePinProtectedUserKey('session-pin-envelope', { encryptedPin: 'encrypted-pin' });
    await sm.logout();
    expect(await sm.getState()).toBe('loggedOut');
    expect(await local.get('pinConfigurations')).toBeUndefined();
    expect(await browserSession.get('pinEphemeralEnvelopes')).toBeUndefined();
    expect(await browserSession.get('pinFailures')).toBeUndefined();
  });

  it('a KDF change removes both PIN storage tiers', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'access', refreshToken: 'refresh', expiresAt: 123,
      protectedKey: 'old-protected-key', kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('session-pin-envelope', { encryptedPin: 'encrypted-pin' });

    await sm.updateMasterKeyMaterialFor({
      email: 'user@example.com',
      protectedKey: 'old-protected-key',
      kdf: 0,
      kdfIterations: 600000,
    }, {
      protectedKey: 'new-protected-key',
      kdf: { kdf: 0, kdfIterations: 700000 },
    });

    expect(await local.get('pinConfigurations')).toBeUndefined();
    expect(await browserSession.get('pinEphemeralEnvelopes')).toBeUndefined();
    expect(await browserSession.get('pinFailures')).toBeUndefined();
  });

  it('resetAllAccounts clears accounts, PIN, and session keys but preserves remembered-device tokens', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'first@example.com', accessToken: 'a1', refreshToken: 'r1', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.saveUnlocked({
      email: 'second@example.com', accessToken: 'a2', refreshToken: 'r2', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('protected-pin-key', {
      requireMasterPasswordOnRestart: false,
    });
    await sm.saveRememberDeviceToken('https://old.example', 'first@example.com', 'remember-token');

    await sm.resetAllAccounts();

    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.listAccounts()).toEqual([]);
    expect(await sm.getPinProtectedUserKey()).toBeUndefined();
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(await sm.getRememberDeviceToken('https://old.example', 'first@example.com')).toBe('remember-token');
  });

  it.each([MAX_ACCOUNT_COUNT + 1, 33])(
    'recovers an existing %i-account registry by resetting it without trimming',
    async (count) => {
      const local = createMemoryStore();
      const browserSession = createMemoryStore();
      const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
      await sm.saveUnlocked({ ...persistedAuth('active@example.com'), userKey });
      await sm.savePinProtectedUserKey('active-pin-envelope', { encryptedPin: 'encrypted-pin' });
      await sm.saveRememberDeviceToken('https://server.example', 'active@example.com', 'remember-token');
      await local.set('accounts', persistedAccountRegistry(count));

      await expect(sm.recoverInvalidAccountRegistry()).resolves.toBe(true);

      expect(await local.get('auth')).toBeUndefined();
      expect(await local.get('accounts')).toBeUndefined();
      expect(await local.get('pinConfigurations')).toBeUndefined();
      expect(await browserSession.get('sessionSecrets')).toBeUndefined();
      expect(await browserSession.get('pinEphemeralEnvelopes')).toBeUndefined();
      expect(await browserSession.get('pinFailures')).toBeUndefined();
      expect(await sm.getRememberDeviceToken(
        'https://server.example',
        'active@example.com',
      )).toBe('remember-token');
      await expect(sm.initialize()).resolves.toBeUndefined();
      await expect(sm.recoverInvalidAccountRegistry()).resolves.toBe(false);
      expect(await sm.getState()).toBe('loggedOut');
      expect(await sm.listAccounts()).toEqual([]);
    },
  );

  it.each([
    ['non-record', ['invalid']],
    ['invalid entry', { 'active@example.com': { email: 'active@example.com' } }],
    ['mismatched owner', { 'registry@example.com': persistedAuth('auth@example.com') }],
  ])('recovers a malformed account registry boundary: %s', async (_name, accounts) => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({ ...persistedAuth('active@example.com'), userKey });
    await sm.savePinProtectedUserKey('active-pin-envelope', { encryptedPin: 'encrypted-pin' });
    await local.set('accounts', accounts);

    await expect(sm.recoverInvalidAccountRegistry()).resolves.toBe(true);

    expect(await local.get('auth')).toBeUndefined();
    expect(await local.get('accounts')).toBeUndefined();
    expect(await local.get('pinConfigurations')).toBeUndefined();
    expect(await browserSession.get('sessionSecrets')).toBeUndefined();
    expect(await browserSession.get('pinEphemeralEnvelopes')).toBeUndefined();
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('preserves a valid registry at the five-account boundary', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({ ...persistedAuth('active@example.com'), userKey });
    await sm.savePinProtectedUserKey('active-pin-envelope', { encryptedPin: 'encrypted-pin' });
    await local.set('accounts', persistedAccountRegistry(MAX_ACCOUNT_COUNT));

    await expect(sm.recoverInvalidAccountRegistry()).resolves.toBe(true);

    expect(await sm.getState()).toBe('unlocked');
    expect(await sm.listAccounts()).toHaveLength(MAX_ACCOUNT_COUNT);
    expect(await sm.getPinProtectedUserKey()).toBe('active-pin-envelope');
  });

  it('does not let an old PIN rollback delete a newer replacement blob', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('old-blob', { requireMasterPasswordOnRestart: false });
    await sm.savePinProtectedUserKey('new-blob', { requireMasterPasswordOnRestart: false });

    await expect(sm.removePinProtectedUserKeyIfCurrent('old-blob')).resolves.toBe(false);
    expect(await sm.getPinProtectedUserKey()).toBe('new-blob');
    await expect(sm.removePinProtectedUserKeyIfCurrent('new-blob')).resolves.toBe(true);
    expect(await sm.getPinProtectedUserKey()).toBeUndefined();
  });

  it('keeps the default PIN envelope in session storage across worker restarts only', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('session-pin-envelope', { encryptedPin: 'encrypted-pin' });

    expect(await local.get('pinProtectedUserKey')).toBeUndefined();
    expect(await local.get<Record<string, Record<string, unknown>>>('pinConfigurations'))
      .toMatchObject({
        'user@example.com': {
          lockType: 'afterFirstUnlock',
          encryptedPin: 'encrypted-pin',
        },
      });
    expect(await local.get<Record<string, Record<string, unknown>>>('pinConfigurations'))
      .not.toMatchObject({ 'user@example.com': { protectedUserKey: expect.anything() } });
    expect(await browserSession.get<Record<string, Record<string, unknown>>>('pinEphemeralEnvelopes'))
      .toMatchObject({ 'user@example.com': { protectedUserKey: 'session-pin-envelope' } });

    const restartedWorker = new SessionManager({ localStore: local, sessionStore: browserSession });
    expect(await restartedWorker.getPinProtectedUserKey()).toBe('session-pin-envelope');

    const restartedBrowser = new SessionManager({ localStore: local, sessionStore: createMemoryStore() });
    expect(await restartedBrowser.getPinProtectedUserKey()).toBeUndefined();
    expect(await restartedBrowser.getPinStateSummary()).toEqual({
      configured: true,
      available: false,
      requireMasterPasswordOnRestart: true,
    });
  });

  it('persists a restart-available PIN envelope only after explicit opt-out', async () => {
    const local = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('persistent-pin-envelope', {
      requireMasterPasswordOnRestart: false,
    });

    const restartedBrowser = new SessionManager({ localStore: local, sessionStore: createMemoryStore() });
    expect(await restartedBrowser.getPinProtectedUserKey()).toBe('persistent-pin-envelope');
    expect(await restartedBrowser.getPinStateSummary()).toEqual({
      configured: true,
      available: true,
      requireMasterPasswordOnRestart: false,
    });
  });

  it('migrates the legacy disk PIN into the current browser session before deleting it', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const seed = new SessionManager({ localStore: local, sessionStore: browserSession });
    await seed.saveUnlocked({
      email: 'user@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await local.set('pinProtectedUserKey', 'legacy-pin-envelope');

    const migrated = new SessionManager({ localStore: local, sessionStore: browserSession });
    await migrated.initialize();

    expect(await local.get('pinProtectedUserKey')).toBeUndefined();
    expect(await migrated.getPinUnlockState()).toMatchObject({
      protectedUserKey: 'legacy-pin-envelope',
      requireMasterPasswordOnRestart: true,
      legacy: true,
    });
  });

  it('persists failed attempts across workers and binds counters to their account', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const first = new SessionManager({ localStore: local, sessionStore: browserSession });
    await first.saveUnlocked({
      email: 'first@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await first.savePinProtectedUserKey('first-envelope', {
      requireMasterPasswordOnRestart: false,
    });
    const firstCredential = (await first.getPinUnlockState())!.credentialId;
    expect(await first.recordFailedPinAttempt('first@example.com', firstCredential)).toBe(1);

    const restartedWorker = new SessionManager({ localStore: local, sessionStore: browserSession });
    expect(await restartedWorker.recordFailedPinAttempt('first@example.com', firstCredential)).toBe(2);
    await restartedWorker.saveUnlocked({
      email: 'second@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
    });
    await restartedWorker.savePinProtectedUserKey('second-envelope', {
      requireMasterPasswordOnRestart: false,
    });
    const secondCredential = (await restartedWorker.getPinUnlockState())!.credentialId;
    expect(await restartedWorker.recordFailedPinAttempt('second@example.com', secondCredential)).toBe(1);
    expect(await browserSession.get<Record<string, unknown>>('pinFailures')).toEqual(expect.objectContaining({
      'second@example.com': expect.objectContaining({ attempts: 1 }),
    }));
    expect(await browserSession.get<Record<string, unknown>>('pinFailures'))
      .not.toHaveProperty('first@example.com');
  });

  it('clears the source PIN when a login activates a different account', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({
      email: 'first@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: 'first-key', kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('first-envelope', { encryptedPin: 'encrypted-pin' });

    await sm.saveUnlocked({
      email: 'second@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 123,
      protectedKey: 'second-key', kdf: 0, kdfIterations: 600000, userKey,
    });

    expect(await local.get('pinConfigurations')).toBeUndefined();
    expect(await browserSession.get('pinEphemeralEnvelopes')).toBeUndefined();
    expect(await browserSession.get('pinFailures')).toBeUndefined();
  });

  it('clears a same-account PIN when new login key material belongs to another generation', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
    await sm.saveUnlocked({
      email: 'user@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 123,
      protectedKey: 'first-key', kdf: 0, kdfIterations: 600000, userKey,
    });
    await sm.savePinProtectedUserKey('persistent-envelope', {
      requireMasterPasswordOnRestart: false,
    });

    await sm.saveLockedAuthenticated({
      email: 'user@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 456,
      protectedKey: 'second-key', kdf: 0, kdfIterations: 600000,
    });

    expect(await local.get('pinConfigurations')).toBeUndefined();
    expect(await browserSession.get('pinEphemeralEnvelopes')).toBeUndefined();
    expect(await browserSession.get('pinFailures')).toBeUndefined();
  });

  it('does not let an old unlock rollback clear a newer session binding', async () => {
    const ids = ['binding-a', 'binding-b'];
    const sm = new SessionManager({
      localStore: createMemoryStore(),
      sessionStore: createMemoryStore(),
      createSessionBindingId: () => ids.shift() ?? 'unexpected-binding',
    });
    const input = {
      email: 'user@example.com', accessToken: 'access', refreshToken: 'refresh', expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0 as const, kdfIterations: 600000, userKey,
    };
    await sm.saveUnlocked(input);
    await sm.saveUnlocked(input);

    await expect(sm.lockIfCurrentSessionBinding({
      email: input.email,
      sessionBindingId: 'binding-a',
    })).resolves.toBe(false);
    expect(await sm.getState()).toBe('unlocked');
    await expect(sm.lockIfCurrentSessionBinding({
      email: input.email,
      sessionBindingId: 'binding-b',
    })).resolves.toBe(true);
    expect(await sm.getState()).toBe('locked');
  });

  describe('privateKey (PKCS8) session slot', () => {
    it('saveUnlocked stores the decrypted privateKey only in session storage', async () => {
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
        privateKey: privateKeyBytes,
      });
      expect(await local.get('privateKey')).toBeUndefined();
      expect(bytesToHex((await sm.loadPrivateKey())!)).toBe(bytesToHex(privateKeyBytes));
    });

    it('lock and logout remove the privateKey from session', async () => {
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
        privateKey: privateKeyBytes,
      });
      await sm.lock();
      expect(await sm.loadPrivateKey()).toBeUndefined();
      await sm.saveUnlocked({
        email: 'user@example.com',
        accessToken: 'access',
        refreshToken: 'refresh',
        expiresAt: 123,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 600000,
        userKey,
        privateKey: privateKeyBytes,
      });
      await sm.logout();
      expect(await sm.loadPrivateKey()).toBeUndefined();
    });
  });

  describe('multi-account', () => {
    function newSm() {
      return new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    }
    async function addAccount(sm: SessionManager, email: string) {
      await sm.saveUnlocked({
        email, accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      });
    }
    const newAccountCommits: ReadonlyArray<readonly [
      string,
      (sm: SessionManager, email: string) => Promise<void>,
    ]> = [
      ['unlocked', (sm, email) => sm.saveUnlocked({ ...persistedAuth(email), userKey })],
      ['locked', (sm, email) => sm.saveLockedAuthenticated(persistedAuth(email))],
      ['restricted', (sm, email) => sm.saveRestrictedAuthenticated({
        ...persistedAuth(email),
        restriction: { schemaVersion: 1, reason: 'adminForcePasswordReset' },
      })],
    ];

    it('registers each logged-in account and flags the active one', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      await addAccount(sm, 'b@x.com');
      const accounts = await sm.listAccounts();
      expect(accounts.map((a) => a.email).sort()).toEqual(['a@x.com', 'b@x.com']);
      expect(accounts.find((a) => a.active)?.email).toBe('b@x.com');
    });

    it('lists stable credential generations for retained accounts without exposing tokens', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      const first = await sm.listAuthTokenLeases();
      await sm.saveTokensFor({ email: 'a@x.com', refreshToken: 'r' }, {
        accessToken: 'refreshed-access',
        refreshToken: 'refreshed-refresh',
        expiresAt: 1_000_000,
      });
      const refreshed = await sm.listAuthTokenLeases();
      await addAccount(sm, 'b@x.com');
      const both = await sm.listAuthTokenLeases();

      expect(first).toHaveLength(1);
      expect(refreshed[0]?.credentialId).toBe(first[0]?.credentialId);
      expect(refreshed[0]?.tokenRevision).not.toBe(first[0]?.tokenRevision);
      expect(both.map((lease) => lease.email).sort()).toEqual(['a@x.com', 'b@x.com']);
      expect(JSON.stringify(both)).not.toContain('refreshed-access');
      expect(Object.isFrozen(both)).toBe(true);
      expect(both.every(Object.isFrozen)).toBe(true);
    });

    it('keeps the active account when conditional credential logout/reset receives an old lease', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      const accountA = (await sm.getActiveAuthSnapshot())!.tokenLease;
      await addAccount(sm, 'b@x.com');

      await expect(sm.logoutIfTokenCurrent(accountA)).resolves.toBe(false);
      await expect(sm.resetAllAccountsIfTokenCurrent(accountA)).resolves.toBe(false);

      const accounts = await sm.listAccounts();
      expect(accounts.map((account) => account.email).sort()).toEqual(['a@x.com', 'b@x.com']);
      expect(accounts.find((account) => account.active)?.email).toBe('b@x.com');
    });

    it.each(newAccountCommits)(
      'rejects a sixth %s account before changing auth, registry, PIN, or session state',
      async (_kind, commit) => {
        const local = createMemoryStore();
        const browserSession = createMemoryStore();
        const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
        for (let index = 0; index < MAX_ACCOUNT_COUNT; index++) {
          await addAccount(sm, `account-${index}@example.com`);
        }
        await sm.savePinProtectedUserKey('fifth-account-envelope', {
          encryptedPin: 'encrypted-pin',
        });
        const pinState = (await sm.getPinUnlockState())!;
        await sm.recordFailedPinAttempt(
          `account-${MAX_ACCOUNT_COUNT - 1}@example.com`,
          pinState.credentialId,
        );
        const before = await snapshotAccountState(local, browserSession);

        await expect(commit(sm, 'sixth@example.com'))
          .rejects.toThrow(`Account limit of ${MAX_ACCOUNT_COUNT} reached`);

        expect(await snapshotAccountState(local, browserSession)).toEqual(before);
        expect(await sm.getState()).toBe('unlocked');
        expect(await sm.listAccounts()).toHaveLength(MAX_ACCOUNT_COUNT);
      },
    );

    it('allows an existing account update at the five-account boundary', async () => {
      const sm = newSm();
      for (let index = 0; index < MAX_ACCOUNT_COUNT; index++) {
        await addAccount(sm, `account-${index}@example.com`);
      }
      const activeEmail = `account-${MAX_ACCOUNT_COUNT - 1}@example.com`;

      await sm.saveUnlocked({
        ...persistedAuth(activeEmail),
        accessToken: 'updated-access-token',
        userKey,
      });

      expect(await sm.listAccounts()).toHaveLength(MAX_ACCOUNT_COUNT);
      expect((await sm.getPersistedAuth())?.accessToken).toBe('updated-access-token');
    });

    it('serializes concurrent admissions so only one fifth account is committed', async () => {
      const sm = newSm();
      for (let index = 0; index < MAX_ACCOUNT_COUNT - 1; index++) {
        await addAccount(sm, `account-${index}@example.com`);
      }

      const results = await Promise.allSettled([
        addAccount(sm, 'candidate-a@example.com'),
        addAccount(sm, 'candidate-b@example.com'),
      ]);

      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
      expect(await sm.listAccounts()).toHaveLength(MAX_ACCOUNT_COUNT);
      expect(await sm.getState()).toBe('unlocked');
    });

    it('switchAccount activates another account and locks the vault', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      await addAccount(sm, 'b@x.com');
      await sm.switchAccount('a@x.com');
      expect(await sm.getState()).toBe('locked');
      expect((await sm.getPersistedAuth())?.email).toBe('a@x.com');
    });

    it('preserves owner-keyed PIN state across an A to B to A switch', async () => {
      const local = createMemoryStore();
      const browserSession = createMemoryStore();
      const sm = new SessionManager({ localStore: local, sessionStore: browserSession });
      await addAccount(sm, 'b@x.com');
      await addAccount(sm, 'a@x.com');
      await sm.savePinProtectedUserKey('account-a-envelope', { encryptedPin: 'encrypted-pin' });
      const pinState = (await sm.getPinUnlockState())!;
      await sm.recordFailedPinAttempt('a@x.com', pinState.credentialId);

      await sm.switchAccount('b@x.com');

      expect(await sm.getState()).toBe('locked');
      expect(await sm.getPinProtectedUserKey()).toBeUndefined();
      expect(await sm.getPinStateSummary('a@x.com')).toEqual({
        configured: true,
        available: true,
        requireMasterPasswordOnRestart: true,
      });
      expect(await local.get<Record<string, unknown>>('pinConfigurations'))
        .toHaveProperty('a@x.com');
      expect(await browserSession.get<Record<string, unknown>>('pinEphemeralEnvelopes'))
        .toHaveProperty('a@x.com');
      expect(await browserSession.get<Record<string, unknown>>('pinFailures'))
        .toHaveProperty('a@x.com');

      await sm.switchAccount('a@x.com');

      expect((await sm.getPersistedAuth())?.email).toBe('a@x.com');
      expect(await sm.getState()).toBe('locked');
      expect(await sm.getPinProtectedUserKey()).toBe('account-a-envelope');
      expect(await browserSession.get<Record<string, unknown>>('pinFailures'))
        .toHaveProperty('a@x.com');
    });

    it('switchAccount rejects an unknown account', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      await expect(sm.switchAccount('nope@x.com')).rejects.toThrow('unknown account');
    });

    it('removeAccount drops a non-active account and keeps the active session', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      await addAccount(sm, 'b@x.com');
      await sm.removeAccount('a@x.com');
      expect((await sm.listAccounts()).map((a) => a.email)).toEqual(['b@x.com']);
      expect(await sm.getState()).toBe('unlocked');
    });

    it('logout drops the active account and falls back to a remaining one (locked)', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      await addAccount(sm, 'b@x.com');
      await sm.logout();
      expect((await sm.listAccounts()).map((a) => a.email)).toEqual(['a@x.com']);
      expect((await sm.getPersistedAuth())?.email).toBe('a@x.com');
      expect(await sm.getState()).toBe('locked');
    });

    it('logout with a single account clears everything', async () => {
      const sm = newSm();
      await addAccount(sm, 'a@x.com');
      await sm.logout();
      expect(await sm.listAccounts()).toEqual([]);
      expect(await sm.getState()).toBe('loggedOut');
    });
  });

  describe('remember-device tokens', () => {
    const SERVER_A = 'https://a.example';
    const SERVER_B = 'https://b.example';
    function newSm() {
      return new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    }

    it('saves, reads, and removes a token keyed by (server, email)', async () => {
      const sm = newSm();
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBeUndefined();
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-1');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-1');
      await sm.removeRememberDeviceToken(SERVER_A, 'u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBeUndefined();
    });

    it('isolates tokens by server and by email', async () => {
      const sm = newSm();
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-A');
      await sm.saveRememberDeviceToken(SERVER_B, 'u@x.com', 'tok-B');
      await sm.saveRememberDeviceToken(SERVER_A, 'other@x.com', 'tok-O');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-A');
      expect(await sm.getRememberDeviceToken(SERVER_B, 'u@x.com')).toBe('tok-B');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'other@x.com')).toBe('tok-O');
      // Removing one leaves the others intact.
      await sm.removeRememberDeviceToken(SERVER_A, 'u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBeUndefined();
      expect(await sm.getRememberDeviceToken(SERVER_B, 'u@x.com')).toBe('tok-B');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'other@x.com')).toBe('tok-O');
    });

    it('overwrites the token on re-save (rotation)', async () => {
      const sm = newSm();
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-old');
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-new');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-new');
    });

    it('serializes concurrent token mutations so updates for different accounts are not lost', async () => {
      const base = createMemoryStore();
      let rememberReads = 0;
      let releaseFirstWrite!: () => void;
      let markFirstWriteStarted!: () => void;
      const firstWriteStarted = new Promise<void>((resolve) => { markFirstWriteStarted = resolve; });
      const firstWriteGate = new Promise<void>((resolve) => { releaseFirstWrite = resolve; });
      let blockFirstWrite = true;
      const local: KeyValueStore = {
        async get<T>(key: string) {
          if (key === 'rememberDeviceTokens') rememberReads++;
          return base.get<T>(key);
        },
        async set(key, value) {
          if (key === 'rememberDeviceTokens' && blockFirstWrite) {
            blockFirstWrite = false;
            markFirstWriteStarted();
            await firstWriteGate;
          }
          await base.set(key, value);
        },
        setMany: (values) => base.setMany(values),
        remove: (key) => base.remove(key),
        clear: () => base.clear(),
      };
      const sm = new SessionManager({ localStore: local, sessionStore: createMemoryStore() });

      const first = sm.saveRememberDeviceToken(SERVER_A, 'first@example.com', 'first-token');
      await firstWriteStarted;
      const second = sm.saveRememberDeviceToken(SERVER_A, 'second@example.com', 'second-token');
      await Promise.resolve();
      expect(rememberReads).toBe(1);
      releaseFirstWrite();
      await Promise.all([first, second]);

      expect(await sm.getRememberDeviceToken(SERVER_A, 'first@example.com')).toBe('first-token');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'second@example.com')).toBe('second-token');
    });

    it('survives logout and lock (the token is not a session secret)', async () => {
      const sm = newSm();
      await sm.saveUnlocked({
        email: 'u@x.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      });
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-1');
      await sm.lock();
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-1');
      await sm.logout();
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-1');
    });

    it('removing a token that was never saved is a no-op', async () => {
      const sm = newSm();
      await expect(sm.removeRememberDeviceToken(SERVER_A, 'nobody@x.com')).resolves.toBeUndefined();
    });
  });
});
