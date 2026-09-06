import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { SessionManager, type PersistedAuth } from './session-manager.js';
import { AuthService } from './auth-service.js';
import { AccountLeaseGate } from './account-gate.js';
import type { ApiClient } from '../api/client.js';
import { EnterprisePolicyGate } from '../policy/effective-enterprise-policy.js';
import { createMemoryStore, type AtomicKeyValueStore } from '../../platform/store.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes } from '../crypto/encoding.js';
import { USER_KEY_VECTOR } from '../../../test/vectors.js';
import { SessionGate } from '../../background/session-gate.js';
import { VaultTimeoutController } from '../../background/vault-timeout-controller.js';
import { VaultTimeoutStateStore } from '../../background/vault-timeout-state.js';
import { createSettingsService } from '../../background/settings.js';
import { isLocalCloseLogoutEnabled, resolveEffectiveVaultTimeout } from '../../background/vault-timeout-policy.js';
import { refreshVaultTimeoutSettingsAfterWrite } from '../../background/vault-timeout-settings-lifecycle.js';
import { createRouter, type RouterDeps } from '../../background/router.js';

const owner = 'race@example.com';
const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
const credentials: PersistedAuth = {
  email: owner,
  accessToken: 'race-access-token',
  refreshToken: 'race-refresh-token',
  expiresAt: 999_999,
  protectedKey: USER_KEY_VECTOR.akey,
  kdf: 0,
  kdfIterations: 600_000,
};

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

function pauseAuthRead(backing: AtomicKeyValueStore) {
  const reached = deferred();
  const resume = deferred();
  let remainingReads = 0;
  const store: AtomicKeyValueStore = {
    ...backing,
    async get<T>(key: string): Promise<T | undefined> {
      const value = await backing.get<T>(key);
      if (key === 'auth' && remainingReads > 0 && --remainingReads === 0) {
        reached.resolve();
        await resume.promise;
      }
      return value;
    },
  };
  return { store, reached, resume, arm: (reads: number) => { remainingReads = reads; } };
}

// Memory-store operations settle through microtasks. Yield one task while the first read remains
// paused so an incorrectly unqueued writer can complete, without depending on machine speed.
async function allowConcurrentStorageWork(): Promise<void> {
  await new Promise<void>((resolve) => { setTimeout(resolve, 0); });
}

function unexpectedAutofillDependency(): never {
  throw new Error('Security settings must not access autofill dependencies');
}

async function expectTokenlessLockedAccount(local: AtomicKeyValueStore, session: SessionManager) {
  expect(await session.getState()).toBe('locked');
  const auth = await local.get<Record<string, unknown>>('auth');
  const accounts = await local.get<Record<string, unknown>>('accounts');
  expect(auth).toEqual(accounts?.[owner]);
  expect(auth).toMatchObject({ email: owner, tokenStorage: 'session' });
  expect(auth).not.toHaveProperty('accessToken');
  expect(auth).not.toHaveProperty('refreshToken');
  expect(auth).not.toHaveProperty('sessionBindingId');
  expect((await session.getActiveAuth())?.refreshToken).toBe(credentials.refreshToken);
  expect(await session.recoverInvalidAccountRegistry()).toBe(false);
}

describe('Session token storage and lock serialization', () => {
  it('keeps tokens out of local storage when a security setting save overlaps a lifecycle lock', async () => {
    const backing = createMemoryStore();
    const browserSession = createMemoryStore();
    const pause = pauseAuthRead(backing);
    const local = pause.store;
    const session = new SessionManager({ localStore: local, sessionStore: browserSession });
    const serverUrl = 'https://vault.example/';
    await session.saveUnlocked({ ...credentials, userKey });
    const settings = createSettingsService(local);
    await settings.saveLockTimeout('15');
    await settings.saveOnIdleAction('lock');
    const sessionGate = new SessionGate('unlocked');
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl, accountIdentity: owner });
    const enterprisePolicyGate = new EnterprisePolicyGate();
    enterprisePolicyGate.replace({
      response: { profile: { id: 'user', email: owner }, ciphers: [], policiesNew: [] },
      accountLease: accountGate.capture(), rawGeneration: 'raw-1',
    });
    const state = new VaultTimeoutStateStore({ localStore: local, sessionStore: browserSession });
    await state.initializeBrowserSession();
    const reconcileOwners = async () => {
      const [lockTimeout, onIdleAction] = await Promise.all([
        settings.getLockTimeout(), settings.getOnIdleAction(),
      ]);
      const enabled = isLocalCloseLogoutEnabled(lockTimeout, onIdleAction);
      if (enabled) await session.moveAllTokensToSession();
      else await session.restoreLocalLogoutTokensToLocal();
      const accounts = await session.listAccounts();
      await state.reconcileLocalCloseLogoutOwners({ serverUrl, emails: accounts.map((a) => a.email), enabled });
    };
    const auth = new AuthService({
      api: {} as ApiClient, session, sessionGate, accountGate,
      onSessionTransition: (event) => {
        if (event.phase === 'start') controller.transitionStarted();
        sessionGate.handleTransition(event);
      },
      onSerializedSessionTransition: async (event) => {
        if (event.phase !== 'settled') return;
        if (event.succeeded) await reconcileOwners();
        await controller.transitionSettled(event.succeeded, event.state);
      },
    });
    const controller: VaultTimeoutController = new VaultTimeoutController({
      state, alarms: { create: () => {}, clear: async () => true },
      getContext: async () => {
        const [authState, snapshot] = await Promise.all([auth.getState(), session.getActiveAuthSnapshot()]);
        if (!snapshot) return { state: authState };
        return {
          state: authState, accountKey: `${serverUrl}\n${owner}`, email: owner,
          credentialId: snapshot.tokenLease.credentialId, tokenRevision: snapshot.tokenLease.tokenRevision,
          ...(snapshot.auth.sessionBindingId ? { sessionBindingId: snapshot.auth.sessionBindingId } : {}),
        };
      },
      getConfig: async () => resolveEffectiveVaultTimeout(
        await settings.getLockTimeout(), await settings.getOnIdleAction(),
        { kind: 'available', policy: enterprisePolicyGate.assert(enterprisePolicyGate.capture()).maximumVaultTimeoutPolicy },
      ),
      reconcileTokenStorage: async (expected, target, reason) => {
        if (!await session.reconcileActiveTokenStorage(expected, target, reason)) throw new Error('Stale auth');
      },
      applyAction: async (_expected, action) => action === 'logout' ? auth.logout() : auth.lock(),
      now: () => 1_000, monotonicNow: () => 1_000,
    });
    await controller.initialize();
    sessionGate.setPreflight(() => controller.preflight());
    const router = createRouter({
      auth, vault: {}, settings, sessionGate, accountGate, enterprisePolicyGate, vaultTimeout: controller,
      autofillPolicyGate: {
        capture: unexpectedAutofillDependency,
        assert: unexpectedAutofillDependency,
        invalidate: unexpectedAutofillDependency,
      },
      autofillIntents: { issue: unexpectedAutofillDependency, redeem: unexpectedAutofillDependency },
      keyboardGrants: {
        takeCommand: unexpectedAutofillDependency,
        issueGrant: unexpectedAutofillDependency,
        authorizeGrant: unexpectedAutofillDependency,
        consumeGrant: unexpectedAutofillDependency,
      },
      getKeyboardTopDocument: unexpectedAutofillDependency,
      pageLoadFillDeduper: { claim: unexpectedAutofillDependency, persist: unexpectedAutofillDependency },
    } satisfies RouterDeps);

    pause.arm(2);
    const locking = auth.lock();
    await pause.reached.promise;
    const saving = (async () => {
      // Preserve the production order: tighten, route, then reconcile the saved timeout settings.
      const before = await Promise.all([settings.getLockTimeout(), settings.getOnIdleAction()]);
      await session.moveAllTokensToSession();
      const response = await router.handle(
        { type: 'settings.saveSecurity', onIdleAction: 'logout', clipboardClearSeconds: '60' },
        { kind: 'extensionPage', url: 'chrome-extension://test/ui/options/options.html', origin: 'chrome-extension://test' },
      );
      expect(response).toEqual({ ok: true, data: null });
      await refreshVaultTimeoutSettingsAfterWrite({
        readPersistedSettings: () => Promise.all([settings.getLockTimeout(), settings.getOnIdleAction()]),
        reconcileOwners, controller, applyIdleDetection: async () => {},
      }, { before, timeoutSettingsRequest: true });
    })();
    try {
      await allowConcurrentStorageWork();
    } finally {
      pause.resume.resolve();
    }
    await Promise.all([locking, saving]);

    expect(isLocalCloseLogoutEnabled(await settings.getLockTimeout(), await settings.getOnIdleAction())).toBe(true);
    await expectTokenlessLockedAccount(backing, session);
  });

  it('revokes the binding after a preceding migration publishes its session token slot', async () => {
    const local = createMemoryStore();
    const backingSession = createMemoryStore();
    const reached = deferred();
    const resume = deferred();
    const browserSession: AtomicKeyValueStore = {
      ...backingSession,
      async set(key, value) {
        if (key === 'authTokens') {
          reached.resolve();
          await resume.promise;
        }
        await backingSession.set(key, value);
      },
    };
    const session = new SessionManager({ localStore: local, sessionStore: browserSession });
    await session.saveUnlocked({ ...credentials, userKey });
    const moving = session.moveAllTokensToSession();
    await reached.promise;
    const locking = session.lock();
    try {
      await allowConcurrentStorageWork();
    } finally {
      resume.resolve();
    }
    await Promise.all([moving, locking]);

    await expectTokenlessLockedAccount(local, session);
  });

  it('does not restore a superseded token generation when a lock overlaps a refresh commit', async () => {
    const backing = createMemoryStore();
    const browserSession = createMemoryStore();
    const pause = pauseAuthRead(backing);
    const session = new SessionManager({ localStore: pause.store, sessionStore: browserSession });
    await session.saveUnlocked({ ...credentials, userKey });
    pause.arm(2);
    const locking = session.lock();
    await pause.reached.promise;
    const refreshing = session.saveTokensFor(credentials, {
      accessToken: 'rotated-access', refreshToken: 'rotated-refresh', expiresAt: 1_234_567,
    });
    try {
      await allowConcurrentStorageWork();
    } finally {
      pause.resume.resolve();
    }
    await Promise.all([locking, refreshing]);

    expect(await refreshing).toBe(true);
    expect(await session.getState()).toBe('locked');
    expect(await session.getActiveAuth()).toMatchObject({ accessToken: 'rotated-access', refreshToken: 'rotated-refresh' });
    expect(await session.recoverInvalidAccountRegistry()).toBe(false);
  });

  it('keeps the binding comparison and conditional lock in the same registry mutation', async () => {
    const backing = createMemoryStore();
    const browserSession = createMemoryStore();
    const pause = pauseAuthRead(backing);
    const session = new SessionManager({ localStore: pause.store, sessionStore: browserSession });
    await session.saveUnlocked({ ...credentials, userKey });
    const oldBinding = (await session.getActiveAuth())!.sessionBindingId!;
    pause.arm(1);
    const rollingBack = session.lockIfCurrentSessionBinding({ email: owner, sessionBindingId: oldBinding });
    await pause.reached.promise;
    const relogging = session.saveUnlocked({ ...credentials, userKey });
    try {
      await allowConcurrentStorageWork();
    } finally {
      pause.resume.resolve();
    }
    await Promise.all([rollingBack, relogging]);

    expect(await rollingBack).toBe(true);
    expect(await session.getState()).toBe('unlocked');
    expect((await session.getActiveAuth())?.sessionBindingId).not.toBe(oldBinding);
    expect(await session.recoverInvalidAccountRegistry()).toBe(false);
  });

  it('repairs an exact stale local copy when all account tokens are already session-backed', async () => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const session = new SessionManager({ localStore: local, sessionStore: browserSession });
    await session.saveUnlocked({ ...credentials, userKey });
    await session.lock();
    const staleAuth = await local.get('auth');
    await session.moveAllTokensToSession();
    await local.set('auth', staleAuth);

    expect(await session.moveAllTokensToSession()).toEqual({ moved: [], reclassified: [] });

    await expectTokenlessLockedAccount(local, session);
  });

  it.each([
    { field: 'credentialId', value: 'unrelated-credential' },
    { field: 'tokenRevision', value: 'unrelated-revision' },
    { field: 'protectedKey', value: 'unrelated-protected-key' },
    { field: 'refreshToken', value: 'unrelated-refresh-token' },
  ])('does not adopt active auth with a different $field during an idempotent migration', async ({ field, value }) => {
    const local = createMemoryStore();
    const browserSession = createMemoryStore();
    const session = new SessionManager({ localStore: local, sessionStore: browserSession });
    await session.saveUnlocked({ ...credentials, userKey });
    const staleAuth = await local.get<Record<string, unknown>>('auth');
    await session.moveAllTokensToSession();
    await local.set('auth', { ...staleAuth, [field]: value });

    await session.moveAllTokensToSession();

    expect(await session.recoverInvalidAccountRegistry()).toBe(true);
    expect(await session.getState()).toBe('loggedOut');
    expect(await local.get('auth')).toBeUndefined();
  });
});
