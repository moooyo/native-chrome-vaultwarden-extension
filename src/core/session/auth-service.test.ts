import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import {
  AuthService,
  GENERATOR_HISTORY_CLEANUP_WAIT_MS,
  type AuthServiceDeps,
  type DeviceLoginActivationStage,
  type Fido2TwoFactorChallenge,
  type SessionTransitionEvent,
} from './auth-service.js';
import { SessionManager, type SessionLeaseGate } from './session-manager.js';
import { SessionGate } from '../../background/session-gate.js';
import { AccountTransitionCoordinator } from '../../background/account-transition.js';
import {
  AccountLeaseGate,
  type AccountLease,
} from './account-gate.js';
import { createMemoryStore } from '../../platform/store.js';
import type { PasswordLoginInput, PasswordLoginResult } from '../api/client.js';
import { ApiClient, ApiHttpError } from '../api/client.js';
import { AppError } from '../errors.js';
import { base64ToBytes, bytesToBase64, bytesToBase64Url, bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from '../crypto/encoding.js';
import { serializeSymmetricKey, symmetricKeyFromBytes, unwrapSymmetricKey, type SymmetricKey } from '../crypto/keys.js';
import { deriveMasterKey, stretchMasterKey, type KdfConfig } from '../crypto/kdf.js';
import { EncStringMacError, encryptToBytes } from '../crypto/encstring.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { VaultMutationCoordinator } from '../vault/vault-mutation-coordinator.js';
import { RotationPendingStore } from './rotation-pending-store.js';
import {
  PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX,
  PendingLoginStateStore,
} from '../../background/pending-login-state-store.js';
import {
  PENDING_LOGIN_CONTINUATION_TTL_MS,
  type PendingLoginContinuationStore,
} from './pending-login-continuation.js';
import type { DeviceLoginBoundState } from './device-login.js';
import { MAX_PIN_UTF16_CODE_UNITS } from './pin-constraints.js';
import { deriveAccountPasskeyPrfKey } from './account-passkey-unlock.js';
import {
  parseFido2TwoFactorRequest,
  validateFido2TwoFactorSubmission,
} from './fido2-two-factor.js';
import { createInteractiveTwoFactorOwner } from './interactive-two-factor.js';
import type {
  EffectiveEnterprisePolicySnapshot,
  PolicyLease,
} from '../policy/effective-enterprise-policy.js';
import { ARGON2_KDF_VECTOR, KDF_VECTOR, KDF_VECTOR_600K, USER_KEY_VECTOR, USER_KEY_VECTOR_600K, RSA_PRIVATE_KEY_VECTOR } from '../../../test/vectors.js';

function mockApiClient(api: Partial<ApiClient>, guards: Array<() => void> = []): ApiClient {
  return new Proxy(api, {
    get(target, property) {
      if (property === 'withRequestGuard') {
        return (guard: () => void) => mockApiClient(api, [...guards, guard]);
      }
      if (property === 'forServer') {
        return () => mockApiClient(api, guards);
      }
      const value = Reflect.get(target, property) as unknown;
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        for (const guard of guards) guard();
        if (property === 'refresh') {
          const options = args[1] as { onGrantStarted?: () => void } | undefined;
          options?.onGrantStarted?.();
        }
        return Reflect.apply(value, target, args) as unknown;
      };
    },
  }) as ApiClient;
}

function makeService(
  api: Partial<ApiClient>,
  serverUrlProvider: () => Promise<string | undefined> = async () => 'https://vault.example',
  onIdentityChanged?: () => Promise<void>,
  onSessionTransition?: (event: SessionTransitionEvent) => void | Promise<void>,
  sessionGate: SessionLeaseGate = {
    capture: () => ({ generation: 0 }),
    assert: () => {},
  },
  onSerializedSessionTransition?: (event: SessionTransitionEvent) => void | Promise<void>,
  now: () => number = () => 1000,
  pendingLoginStore?: PendingLoginContinuationStore,
  closeInteractiveTwoFactorConnector?: AuthServiceDeps['closeInteractiveTwoFactorConnector'],
  assertPasswordLoginAllowed?: AuthServiceDeps['assertPasswordLoginAllowed'],
) {
  const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
  const passwordChangePending = {
    markBeforeChange: vi.fn(async () => ({})),
    clear: vi.fn(async () => {}),
  };
  return {
    sm,
    passwordChangePending,
    auth: new AuthService({
      api: mockApiClient(api),
      session: sm,
      sessionGate,
      passwordChangePending,
      now,
      serverUrlProvider,
      ...(pendingLoginStore ? { pendingLoginStore } : {}),
      ...(closeInteractiveTwoFactorConnector ? { closeInteractiveTwoFactorConnector } : {}),
      ...(assertPasswordLoginAllowed ? { assertPasswordLoginAllowed } : {}),
      ...(onIdentityChanged ? { onIdentityChanged } : {}),
      ...(onSessionTransition ? { onSessionTransition } : {}),
      ...(onSerializedSessionTransition ? { onSerializedSessionTransition } : {}),
    }),
  };
}

function accountLifecycleHook(
  gate: AccountLeaseGate,
  session: SessionManager,
  serverUrl = 'https://vault.example',
) {
  const coordinator = new AccountTransitionCoordinator(gate, async () => {
    const auth = await session.getPersistedAuth();
    return {
      serverUrl,
      ...(auth ? { accountIdentity: auth.email } : {}),
    };
  });
  return coordinator.handle;
}

async function makeAccessTokenHarness(options: {
  refresh?: () => Promise<{
    access_token: string;
    refresh_token: string;
    expires_in: number;
    token_type: string;
  }>;
  expiresAt?: number;
  serverUrl?: string;
  persistedEmail?: string;
  serverUrlProvider?: () => Promise<string | undefined>;
  onIdentityChanged?: () => Promise<void>;
} = {}) {
  const serverUrl = options.serverUrl ?? 'https://vault.example/tenant/';
  const accountIdentity = 'user@example.com';
  const currentServer = { value: serverUrl };
  const sm = new SessionManager({
    localStore: createMemoryStore(),
    sessionStore: createMemoryStore(),
  });
  await sm.saveUnlocked({
    email: options.persistedEmail ?? accountIdentity,
    accessToken: 'old-access-secret',
    refreshToken: 'old-refresh-secret',
    expiresAt: options.expiresAt ?? 999_999,
    protectedKey: USER_KEY_VECTOR.akey,
    kdf: 0,
    kdfIterations: 5_000,
    userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
  });
  const refresh = vi.fn(options.refresh ?? (async () => ({
    access_token: 'new-access-secret',
    refresh_token: 'new-refresh-secret',
    expires_in: 3_600,
    token_type: 'Bearer',
  })));
  const accountGate = new AccountLeaseGate();
  accountGate.initialize({ serverUrl, accountIdentity });
  const sessionGate = new SessionGate('unlocked');
  const transitionEvents: SessionTransitionEvent[] = [];
  const auth = new AuthService({
    api: mockApiClient({ refresh }),
    session: sm,
    sessionGate,
    accountGate,
    serverUrlProvider: options.serverUrlProvider ?? (async () => currentServer.value),
    ...(options.onIdentityChanged ? { onIdentityChanged: options.onIdentityChanged } : {}),
    now: () => 1_000,
    onSessionTransition: (event) => {
      transitionEvents.push(event);
      sessionGate.handleTransition(event);
    },
    onSerializedSessionTransition: accountLifecycleHook(accountGate, sm, serverUrl),
  });
  return {
    auth,
    sm,
    refresh,
    accountGate,
    sessionGate,
    currentServer,
    transitionEvents,
    sessionLease: sessionGate.capture(),
    accountLease: accountGate.capture(),
  };
}

function createPinPolicyControl(initiallyAllowed = true) {
  let generation = 0;
  let allowed = initiallyAllowed;
  let available = true;
  const snapshot = (): EffectiveEnterprisePolicySnapshot => ({
    unlockWithPinRemoved: !allowed,
  } as EffectiveEnterprisePolicySnapshot);
  const gate: NonNullable<AuthServiceDeps['enterprisePolicyGate']> = {
    capture: () => {
      if (!available) throw new AppError('sync_required', 'policy unavailable');
      return { generation } as PolicyLease;
    },
    assert: (lease) => {
      if (!available || lease.generation !== generation) {
        throw new AppError('denied', 'policy changed');
      }
      return snapshot();
    },
  };
  return {
    gate,
    deny() { allowed = false; generation += 1; },
    allow() { allowed = true; generation += 1; },
    invalidate() { generation += 1; },
    makeUnavailable() { available = false; generation += 1; },
  };
}

function successfulLogin(accessToken: string) {
  return {
    kind: 'success' as const,
    data: {
      access_token: accessToken,
      expires_in: 3600,
      refresh_token: `${accessToken}-refresh`,
      token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      Kdf: 0 as const,
      KdfIterations: KDF_VECTOR_600K.iterations,
    },
  };
}

function ssoAccessToken(email = KDF_VECTOR_600K.email): string {
  return [
    bytesToBase64Url(utf8ToBytes(JSON.stringify({ alg: 'none' }))),
    bytesToBase64Url(utf8ToBytes(JSON.stringify({
      sub: '11111111-1111-4111-8111-111111111111',
      email,
    }))),
    bytesToBase64Url(new Uint8Array([1])),
  ].join('.');
}

function successfulSsoLogin(email = KDF_VECTOR_600K.email) {
  return successfulLogin(ssoAccessToken(email));
}

function newDeviceVerificationRequired() {
  return { kind: 'newDeviceVerification' as const };
}

const DEVICE_LOGIN_SERVER = 'https://vault.example/';
const DEVICE_LOGIN_REQUEST_ID = '11111111-1111-4111-8111-111111111111';
const DEVICE_LOGIN_ACCESS_CODE = `Aa0${'b'.repeat(22)}`;

function deviceLoginBoundState(
  overrides: Partial<DeviceLoginBoundState> = {},
): DeviceLoginBoundState {
  return {
    version: 1,
    phase: 'bound',
    email: KDF_VECTOR_600K.email,
    device: { type: 2, name: 'chrome', identifier: 'device-123' },
    publicKey: 'cHVibGlj',
    privateKeyPkcs8: 'cHJpdmF0ZQ==',
    accessCode: DEVICE_LOGIN_ACCESS_CODE,
    createdAt: 0,
    expiresAt: 900_000,
    requestId: DEVICE_LOGIN_REQUEST_ID,
    serverCreationDate: '1970-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function deviceLoginSuccess(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'success' as const,
    data: {
      access_token: 'device-access',
      expires_in: 3_600,
      refresh_token: 'device-refresh',
      token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      PrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      Kdf: 0 as const,
      KdfIterations: KDF_VECTOR_600K.iterations,
      ...overrides,
    },
  };
}

function recoveredDeviceLoginUserKey(): SymmetricKey {
  return symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
}

function accountPasskeyAssertion() {
  const value = bytesToBase64Url(new Uint8Array(32).fill(1));
  return {
    id: value,
    rawId: value,
    type: 'public-key' as const,
    extensions: {},
    response: {
      authenticatorData: bytesToBase64Url(new Uint8Array(37).fill(2)),
      signature: bytesToBase64Url(new Uint8Array(64).fill(3)),
      clientDataJSON: bytesToBase64Url(utf8ToBytes('{}')),
      userHandle: bytesToBase64Url(new Uint8Array(16).fill(4)),
    },
  };
}

function accountPasskeySuccess(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'success' as const,
    data: {
      accessToken: 'passkey-access',
      refreshToken: 'passkey-refresh',
      expiresIn: 3_600,
      tokenType: 'Bearer' as const,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      kdf: { kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations },
      accountIdentity: KDF_VECTOR_600K.email,
      accountId: '11111111-1111-4111-8111-111111111111',
      ...overrides,
    },
  };
}

async function accountPasskeyPrfSuccess() {
  const prfOutput = new Uint8Array(32).fill(5);
  const prfKey = await deriveAccountPasskeyPrfKey(prfOutput);
  const rawUserKey = hexToBytes(USER_KEY_VECTOR.userKeyHex);
  let credentialPrivateKey: Uint8Array | undefined;
  let wrappedUserKey: Uint8Array | undefined;
  try {
    const pair = await crypto.subtle.generateKey({
      name: 'RSA-OAEP',
      modulusLength: 2_048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    }, true, ['encrypt', 'decrypt']);
    credentialPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    try {
      wrappedUserKey = await rsaOaepEncrypt(publicKey, rawUserKey, 'SHA-1');
    } finally {
      publicKey.fill(0);
    }
    if (!credentialPrivateKey || !wrappedUserKey) throw new Error('RSA fixture generation failed');
    const encryptedPrivateKey = await encryptToBytes(
      credentialPrivateKey,
      prfKey,
      new Uint8Array(16).fill(6),
    );
    const webAuthnPrfOption = {
      encryptedPrivateKey,
      encryptedUserKey: `4.${bytesToBase64(wrappedUserKey)}`,
      credentialId: accountPasskeyAssertion().id,
      transports: ['internal' as const],
    };
    return {
      prfOutput,
      webAuthnPrfOption,
      result: accountPasskeySuccess({
        webAuthnPrfOption,
      }),
    };
  } catch (error) {
    prfOutput.fill(0);
    throw error;
  } finally {
    prfKey.encKey.fill(0);
    prfKey.macKey.fill(0);
    rawUserKey.fill(0);
    credentialPrivateKey?.fill(0);
    wrappedUserKey?.fill(0);
  }
}

describe('AuthService password hint request', () => {
  it('pins the anonymous request and delegates normalization to ApiClient', async () => {
    const serverUrl = 'https://vault.example/base/';
    const ambientServer = vi.fn(async () => 'https://changed.example/');
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl });
    const session = new SessionManager({
      localStore: createMemoryStore(), sessionStore: createMemoryStore(),
    });
    const auth = new AuthService({
      api: new ApiClient({
        serverUrlProvider: ambientServer, fetchFn, localStore: createMemoryStore(),
      }),
      session,
      sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
      accountGate,
    });

    await expect(auth.requestPasswordHint('  USER@Example.COM  ')).resolves.toEqual({
      status: 'sent',
    });
    expect(ambientServer).not.toHaveBeenCalled();
    expect(fetchFn).toHaveBeenCalledOnce();
    expect(String(fetchFn.mock.calls.at(0)?.at(0)))
      .toBe('https://vault.example/base/api/accounts/password-hint');

    fetchFn.mockClear();
    await expect(auth.requestPasswordHint('not-an-email')).rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('withholds success after an in-flight server lease transition', async () => {
    let startRequest = (): void => {};
    let releaseResponse = (): void => {};
    const started = new Promise<void>((resolve) => { startRequest = resolve; });
    const responseGate = new Promise<void>((resolve) => { releaseResponse = resolve; });
    const fetchFn = vi.fn(async () => {
      startRequest();
      await responseGate;
      return new Response(null, { status: 204 });
    });
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example/' });
    const auth = new AuthService({
      api: new ApiClient({
        serverUrlProvider: async () => 'https://vault.example/',
        fetchFn,
        localStore: createMemoryStore(),
      }),
      session: new SessionManager({
        localStore: createMemoryStore(), sessionStore: createMemoryStore(),
      }),
      sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
      accountGate,
    });

    const request = auth.requestPasswordHint('user@example.com');
    await started;
    const transition = accountGate.beginServerTransition();
    accountGate.endServerTransition(transition, { serverUrl: 'https://next.example/' });
    releaseResponse();

    await expect(request).rejects.toMatchObject({ code: 'session_expired' });
    expect(fetchFn).toHaveBeenCalledOnce();
  });
});

describe('AuthService account passkey completion', () => {
  it('commits a successful grant as locked and the existing master-password unlock still works', async () => {
    const accountPasskeyLogin = vi.fn(async () => accountPasskeySuccess());
    const { auth, sm } = makeService({ accountPasskeyLogin });

    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).resolves.toEqual({ kind: 'locked' });

    expect(accountPasskeyLogin).toHaveBeenCalledOnce();
    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(await sm.loadPrivateKey()).toBeUndefined();
    expect(await sm.getPersistedAuth()).toMatchObject({
      email: KDF_VECTOR_600K.email,
      accessToken: 'passkey-access',
      refreshToken: 'passkey-refresh',
      protectedKey: USER_KEY_VECTOR_600K.akey,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
    });

    await auth.unlock(KDF_VECTOR_600K.password);
    expect(await sm.getState()).toBe('unlocked');
    expect(await sm.loadUserKey()).toBeDefined();
    expect(await sm.loadPrivateKey()).toBeDefined();
  });

  it('commits a forced account-passkey grant as restricted without recovered secrets', async () => {
    const { auth, sm } = makeService({
      accountPasskeyLogin: vi.fn(async () => accountPasskeySuccess({
        forcePasswordReset: true,
      })),
    });
    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).resolves.toMatchObject({
      kind: 'restricted',
      requirement: { reason: 'adminForcePasswordReset' },
    });
    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(await sm.loadPrivateKey()).toBeUndefined();
  });

  it('commits an exact matching PRF chain as authoritatively unlocked and clears recovered keys', async () => {
    const fixture = await accountPasskeyPrfSuccess();
    const { auth, sm } = makeService({
      accountPasskeyLogin: vi.fn(async () => fixture.result),
    });
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let transientUserKey: SymmetricKey | undefined;
    let transientPrivateKey: Uint8Array | undefined;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      transientUserKey = input.userKey;
      transientPrivateKey = input.privateKey;
      await saveUnlocked(input);
    });

    try {
      await expect(auth.completeAccountPasskeyLogin({
        serverUrl: 'https://vault.example/',
        token: 'signed-options-token',
        assertion: accountPasskeyAssertion(),
        prfOutput: fixture.prfOutput,
      })).resolves.toEqual({ kind: 'unlocked' });

      expect(await sm.getState()).toBe('unlocked');
      const committedUserKey = await sm.loadUserKey();
      const committedPrivateKey = await sm.loadPrivateKey();
      let rawCommittedUserKey: Uint8Array | undefined;
      try {
        rawCommittedUserKey = serializeSymmetricKey(committedUserKey!);
        expect(bytesToHex(rawCommittedUserKey))
          .toBe(USER_KEY_VECTOR.userKeyHex);
        expect(bytesToBase64(committedPrivateKey!)).toBe(RSA_PRIVATE_KEY_VECTOR.pkcs8B64);
      } finally {
        rawCommittedUserKey?.fill(0);
        committedUserKey?.encKey.fill(0);
        committedUserKey?.macKey.fill(0);
        committedPrivateKey?.fill(0);
      }
      expect(transientUserKey).toBeDefined();
      expect(transientUserKey!.encKey).toEqual(new Uint8Array(32));
      expect(transientUserKey!.macKey).toEqual(new Uint8Array(32));
      expect(transientPrivateKey).toBeDefined();
      expect(transientPrivateKey!.every((value) => value === 0)).toBe(true);
      expect(fixture.prfOutput).toEqual(new Uint8Array(32).fill(5));
    } finally {
      fixture.prfOutput.fill(0);
    }
  });

  it('keeps the locked fallback when the token PRF option belongs to another credential', async () => {
    const fixture = await accountPasskeyPrfSuccess();
    const result = accountPasskeySuccess({
      ...fixture.result.data,
      webAuthnPrfOption: {
        ...fixture.webAuthnPrfOption,
        credentialId: bytesToBase64Url(new Uint8Array(32).fill(9)),
      },
    });
    const { auth, sm } = makeService({ accountPasskeyLogin: vi.fn(async () => result) });
    try {
      await expect(auth.completeAccountPasskeyLogin({
        serverUrl: 'https://vault.example/',
        token: 'signed-options-token',
        assertion: accountPasskeyAssertion(),
        prfOutput: fixture.prfOutput,
      })).resolves.toEqual({ kind: 'locked' });
      expect(await sm.getState()).toBe('locked');
      expect(await sm.loadUserKey()).toBeUndefined();
    } finally {
      fixture.prfOutput.fill(0);
    }
  });

  it('keeps the locked fallback when the authenticator returns no PRF result', async () => {
    const result = accountPasskeySuccess({
      webAuthnPrfOption: {
        encryptedPrivateKey: USER_KEY_VECTOR_600K.akey,
        encryptedUserKey: `4.${bytesToBase64(new Uint8Array(256).fill(7))}`,
        credentialId: accountPasskeyAssertion().id,
        transports: ['internal'],
      },
    });
    const { auth, sm } = makeService({ accountPasskeyLogin: vi.fn(async () => result) });

    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).resolves.toEqual({ kind: 'locked' });
    expect(await sm.getState()).toBe('locked');
  });

  it('fails closed when a matching authoritative PRF key chain cannot be decrypted', async () => {
    const prfOutput = new Uint8Array(32).fill(5);
    const accountPasskeyLogin = vi.fn(async () => accountPasskeySuccess({
      webAuthnPrfOption: {
        encryptedPrivateKey: USER_KEY_VECTOR_600K.akey,
        encryptedUserKey: `4.${bytesToBase64(new Uint8Array(256).fill(7))}`,
        credentialId: accountPasskeyAssertion().id,
        transports: ['internal'],
      },
    }));
    const { auth, sm } = makeService({ accountPasskeyLogin });
    const saveLocked = vi.spyOn(sm, 'saveLockedAuthenticated');
    try {
      await expect(auth.completeAccountPasskeyLogin({
        serverUrl: 'https://vault.example/',
        token: 'signed-options-token',
        assertion: accountPasskeyAssertion(),
        prfOutput,
      })).rejects.toThrow();
      expect(accountPasskeyLogin).toHaveBeenCalledOnce();
      expect(saveLocked).not.toHaveBeenCalled();
      expect(await sm.getState()).toBe('loggedOut');
    } finally {
      prfOutput.fill(0);
    }
  });

  it('rejects the all-zero PRF sentinel before posting the grant', async () => {
    const accountPasskeyLogin = vi.fn(async () => accountPasskeySuccess());
    const { auth, sm } = makeService({ accountPasskeyLogin });

    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
      prfOutput: new Uint8Array(32),
    })).rejects.toThrow(/PRF output/u);
    expect(accountPasskeyLogin).not.toHaveBeenCalled();
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('rolls back an unlocked PRF commit when the published state is not authoritative', async () => {
    const fixture = await accountPasskeyPrfSuccess();
    const { auth, sm } = makeService({
      accountPasskeyLogin: vi.fn(async () => fixture.result),
    });
    vi.spyOn(sm, 'getState').mockResolvedValueOnce('locked');
    try {
      await expect(auth.completeAccountPasskeyLogin({
        serverUrl: 'https://vault.example/',
        token: 'signed-options-token',
        assertion: accountPasskeyAssertion(),
        prfOutput: fixture.prfOutput,
      })).rejects.toThrow(/not authoritative/u);
      expect(await sm.getState()).toBe('loggedOut');
      expect(await sm.getPersistedAuth()).toBeUndefined();
    } finally {
      fixture.prfOutput.fill(0);
    }
  });

  it('surfaces unsupported 2FA without creating an authenticated session', async () => {
    const { auth, sm } = makeService({
      accountPasskeyLogin: vi.fn(async () => ({
        kind: 'twoFactorUnsupported' as const,
        providers: [0, 7],
      })),
    });
    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).resolves.toEqual({ kind: 'twoFactorUnsupported', providers: [0, 7] });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('replaces an old unlocked account with the trusted token identity but never reuses its keys', async () => {
    const onIdentityChanged = vi.fn(async () => undefined);
    const { auth, sm } = makeService(
      { accountPasskeyLogin: vi.fn(async () => accountPasskeySuccess()) },
      async () => 'https://vault.example/',
      onIdentityChanged,
    );
    await sm.saveUnlocked({
      email: 'old@example.com',
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      expiresAt: 10_000,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 5_000,
      userKey: recoveredDeviceLoginUserKey(),
    });

    await auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    });

    expect(onIdentityChanged).toHaveBeenCalledOnce();
    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect((await sm.getPersistedAuth())?.email).toBe(KDF_VECTOR_600K.email);
  });

  it('rejects a non-canonical identity returned by a forged API adapter', async () => {
    const { auth, sm } = makeService({
      accountPasskeyLogin: vi.fn(async () => accountPasskeySuccess({
        accountIdentity: 'OTHER@EXAMPLE.COM',
      })),
    });
    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).rejects.toThrow(/identity/u);
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('rejects a forged adapter that changes the parsed token type', async () => {
    const { auth, sm } = makeService({
      accountPasskeyLogin: vi.fn(async () => accountPasskeySuccess({ tokenType: 'MAC' })),
    });
    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).rejects.toThrow(/token type/u);
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('rolls back an exact locked commit when post-write verification fails', async () => {
    const sm = new SessionManager({
      localStore: createMemoryStore(),
      sessionStore: createMemoryStore(),
    });
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example' });
    const sessionGate = new SessionGate('loggedOut');
    const transitionEvents: SessionTransitionEvent[] = [];
    const auth = new AuthService({
      api: mockApiClient({ accountPasskeyLogin: vi.fn(async () => accountPasskeySuccess()) }),
      session: sm,
      sessionGate,
      accountGate,
      now: () => 1_000,
      serverUrlProvider: async () => 'https://vault.example',
      onSessionTransition: (event) => {
        transitionEvents.push(event);
        sessionGate.handleTransition(event);
      },
      onSerializedSessionTransition: accountLifecycleHook(accountGate, sm),
    });
    vi.spyOn(sm, 'getState').mockResolvedValueOnce('unlocked');

    await expect(auth.completeAccountPasskeyLogin({
      serverUrl: 'https://vault.example/',
      token: 'signed-options-token',
      assertion: accountPasskeyAssertion(),
    })).rejects.toThrow(/not authoritative/u);
    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.getPersistedAuth()).toBeUndefined();
    expect(accountGate.current()).toEqual({ serverUrl: 'https://vault.example' });
    expect(() => accountGate.capture()).toThrow(/active account/u);
    expect(() => sessionGate.capture()).toThrow(/locked/u);
    expect(transitionEvents.at(-1)).toMatchObject({
      phase: 'settled',
      reason: 'login',
      state: 'loggedOut',
      succeeded: false,
    });
  });
});

describe('AuthService standard SSO completion', () => {
  const completeInput = {
    ssoAttemptId: '33333333-3333-4333-8333-333333333333',
    ssoAttemptGeneration: 3,
    serverUrl: 'https://vault.example/',
    identityUrl: 'https://vault.example/identity/',
    email: KDF_VECTOR_600K.email,
    code: 'authorization-code',
    codeVerifier: 'A'.repeat(43),
    redirectUri: 'https://vault.example/sso-connector.html',
    emailTwoFactorMode: 'bitwarden-session' as const,
    assertCurrent: () => {},
    onGrantStarted: async () => {},
    onGrantDispatched: () => {},
  } as const;
  const duoAuthUrl = 'https://api-example.duosecurity.com/oauth/v1/authorize'
    + '?response_type=code&client_id=client-id&request=header.payload.signature';
  const duoMetadata = Object.freeze({
    2: Object.freeze({ AuthUrl: duoAuthUrl }),
  });
  const duoLifecycle = Object.freeze({
    onGrantStarted: async () => {},
    onGrantDispatched: () => {},
  });

  function harness(
    api: Partial<ApiClient>,
    options: {
      readonly pendingLoginStore?: PendingLoginContinuationStore;
      readonly assertPasswordLoginAllowed?: AuthServiceDeps['assertPasswordLoginAllowed'];
      readonly authorizeSsoContinuation?: AuthServiceDeps['authorizeSsoContinuation'];
    } = {},
  ) {
    const sm = new SessionManager({
      localStore: createMemoryStore(),
      sessionStore: createMemoryStore(),
    });
    const auth = new AuthService({
      api: mockApiClient(api),
      session: sm,
      sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
      serverUrlProvider: async () => 'https://vault.example/',
      now: () => 1_000,
      ...(options.pendingLoginStore ? { pendingLoginStore: options.pendingLoginStore } : {}),
      ...(options.assertPasswordLoginAllowed
        ? { assertPasswordLoginAllowed: options.assertPasswordLoginAllowed }
        : {}),
      ...(options.authorizeSsoContinuation
        ? { authorizeSsoContinuation: options.authorizeSsoContinuation }
        : {}),
    });
    return { auth, sm };
  }

  it('commits an existing master-password SSO account as locked for the shared unlock path', async () => {
    const prelogin = vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 }));
    const ssoLogin = vi.fn(async () => ({
      ...successfulSsoLogin(),
      data: { ...successfulSsoLogin().data, MasterKeySalt: KDF_VECTOR_600K.email },
    }));
    const { auth, sm } = harness({ prelogin, ssoLogin });

    await expect(auth.completeSsoLogin(completeInput)).resolves.toEqual({ kind: 'locked' });
    expect(ssoLogin).toHaveBeenCalledWith(completeInput.identityUrl, {
      code: completeInput.code,
      codeVerifier: completeInput.codeVerifier,
      redirectUri: completeInput.redirectUri,
      onGrantStarted: expect.any(Function),
      onGrantDispatched: expect.any(Function),
    });
    expect(await sm.getState()).toBe('locked');
    expect(await sm.getPersistedAuth()).toMatchObject({
      email: KDF_VECTOR_600K.email,
      masterKeySalt: KDF_VECTOR_600K.email,
      accessToken: ssoAccessToken(),
      protectedKey: USER_KEY_VECTOR_600K.akey,
    });
  });

  it('persists and resumes the same SSO authorization grant for a 2FA challenge', async () => {
    const storage = createMemoryStore();
    const pendingLoginStore = new PendingLoginStateStore(storage, {
      now: () => 1_000,
      workerId: '11111111-1111-4111-8111-111111111111',
      createAttemptId: () => '22222222-2222-4222-8222-222222222222',
    });
    const ssoLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor',
        providers: [1],
        email: KDF_VECTOR_600K.email,
        ssoEmail2FaSessionToken: 'email-session-token',
      })
      .mockResolvedValueOnce(successfulSsoLogin());
    const sendSsoEmailLogin = vi.fn(async () => {});
    const { auth, sm } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin,
      sendSsoEmailLogin,
    }, { pendingLoginStore });

    const challenge = await auth.completeSsoLogin(completeInput);
    expect(challenge).toMatchObject({
      kind: 'twoFactor',
      providers: [1],
      continuationId: '22222222-2222-4222-8222-222222222222',
    });
    await expect(auth.getPendingSsoHandoff()).resolves.toEqual({
      attemptId: completeInput.ssoAttemptId,
      attemptGeneration: completeInput.ssoAttemptGeneration,
      serverUrl: completeInput.serverUrl,
      identityUrl: completeInput.identityUrl,
      email: completeInput.email,
    });
    const assertContinuationCurrent = vi.fn();
    const authorizeSsoContinuation = vi.fn(async () => ({
      assertCurrent: assertContinuationCurrent,
    }));
    const { auth: restarted, sm: restartedSm } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin,
      sendSsoEmailLogin,
    }, { pendingLoginStore, authorizeSsoContinuation });
    await expect(restarted.getPendingSsoHandoff()).resolves.toEqual({
      attemptId: completeInput.ssoAttemptId,
      attemptGeneration: completeInput.ssoAttemptGeneration,
      serverUrl: completeInput.serverUrl,
      identityUrl: completeInput.identityUrl,
      email: completeInput.email,
    });
    await expect(restarted.getPendingLoginStatus()).resolves.toMatchObject({
      status: 'twoFactor',
      continuationId: '22222222-2222-4222-8222-222222222222',
    });
    expect(authorizeSsoContinuation).toHaveBeenCalledWith({
      serverUrl: completeInput.serverUrl,
      identityUrl: completeInput.identityUrl,
      redirectUri: completeInput.redirectUri,
      emailTwoFactorMode: completeInput.emailTwoFactorMode,
    });
    const authorityChecksAfterRestore = assertContinuationCurrent.mock.calls.length;
    await expect(restarted.sendEmailCode({
      continuationId: '22222222-2222-4222-8222-222222222222',
    })).resolves.toBeUndefined();
    expect(sendSsoEmailLogin).toHaveBeenCalledWith({
      mode: 'bitwarden-session',
      email: KDF_VECTOR_600K.email,
      ssoEmail2FaSessionToken: 'email-session-token',
    });

    await expect(restarted.submitTwoFactor({
      provider: 1,
      code: '123456',
      continuationId: '22222222-2222-4222-8222-222222222222',
    })).resolves.toEqual({ kind: 'locked' });
    expect(assertContinuationCurrent.mock.calls.length).toBeGreaterThan(
      authorityChecksAfterRestore,
    );
    expect(ssoLogin).toHaveBeenLastCalledWith(completeInput.identityUrl, {
      code: completeInput.code,
      codeVerifier: completeInput.codeVerifier,
      redirectUri: completeInput.redirectUri,
      twoFactorProvider: 1,
      twoFactorToken: '123456',
    });
    expect(await sm.getState()).toBe('loggedOut');
    expect(await restartedSm.getState()).toBe('locked');
    expect(await pendingLoginStore.read()).toBeUndefined();
  });

  it('retains and completes Duo provider 2 through the same SSO continuation', async () => {
    const pendingLoginStore = new PendingLoginStateStore(createMemoryStore(), { now: () => 1_000 });
    const ssoLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor',
        providers: [2],
        providerMetadata: duoMetadata,
        email: completeInput.email,
      })
      .mockResolvedValueOnce(successfulSsoLogin());
    const { auth } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin,
    }, { pendingLoginStore });

    const challenge = await auth.completeSsoLogin(completeInput);
    expect(challenge).toMatchObject({ kind: 'twoFactor', providers: [2] });
    const prepared = await auth.prepareDuoTwoFactor({
      provider: 2,
      continuationId: (challenge as { continuationId: string }).continuationId,
    });
    expect(prepared).toMatchObject({
      owner: { flow: 'password', provider: 2, email: completeInput.email },
      seed: { provider: 2, authUrl: duoAuthUrl },
    });

    await expect(auth.completeDuoTwoFactor({
      owner: prepared.owner,
      token: 'authorization-code|server-state',
      remember: true,
      ...duoLifecycle,
    })).resolves.toEqual({ kind: 'locked' });
    expect(ssoLogin).toHaveBeenLastCalledWith(completeInput.identityUrl, expect.objectContaining({
      twoFactorProvider: 2,
      twoFactorToken: 'authorization-code|server-state',
      remember: true,
    }));
  });

  it('keeps the durable Duo owner generation stable across a worker restart', async () => {
    const pendingLoginStore = new PendingLoginStateStore(createMemoryStore(), {
      now: () => 1_000,
      createAttemptId: () => '22222222-2222-4222-8222-222222222222',
    });
    const ssoLogin = vi.fn(async () => ({
      kind: 'twoFactor' as const,
      providers: [2],
      providerMetadata: duoMetadata,
      email: completeInput.email,
    }));
    const api = {
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      passwordLogin: vi.fn(async () => { throw new ApiHttpError(400, { error: 'invalid_grant' }); }),
      ssoLogin,
    };
    const { auth } = harness(api, { pendingLoginStore });
    await expect(auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    })).rejects.toBeInstanceOf(ApiHttpError);
    const challenge = await auth.completeSsoLogin(completeInput);
    const continuationId = (challenge as { continuationId: string }).continuationId;
    const beforeRestart = await auth.prepareDuoTwoFactor({ provider: 2, continuationId });

    const { auth: restarted } = harness(api, {
      pendingLoginStore,
      authorizeSsoContinuation: async () => ({ assertCurrent: () => {} }),
    });
    await restarted.getPendingLoginStatus();
    const afterRestart = await restarted.prepareDuoTwoFactor({ provider: 2, continuationId });

    expect(afterRestart.owner).toEqual(beforeRestart.owner);
    expect(afterRestart.seed).toEqual(beforeRestart.seed);
  });

  it('retains and completes Organization Duo provider 6 for a password grant', async () => {
    const pendingLoginStore = new PendingLoginStateStore(createMemoryStore(), { now: () => 1_000 });
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor',
        providers: [6],
        providerMetadata: { 6: { Host: 'api-example.duosecurity.com', AuthUrl: duoAuthUrl } },
      })
      .mockResolvedValueOnce({ kind: 'success', data: successfulSsoLogin().data });
    const { auth } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      passwordLogin,
    }, { pendingLoginStore });

    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    const prepared = await auth.prepareDuoTwoFactor({
      provider: 6,
      continuationId: (challenge as { continuationId: string }).continuationId,
    });
    await expect(auth.completeDuoTwoFactor({
      owner: prepared.owner,
      token: 'authorization-code|server-state',
      remember: false,
      ...duoLifecycle,
    })).resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin).toHaveBeenLastCalledWith(expect.objectContaining({
      twoFactorProvider: 6,
      twoFactorToken: 'authorization-code|server-state',
      remember: false,
    }));
  });

  it('clears a definitely rejected remembered token without replaying the SSO code', async () => {
    const ssoLogin = vi.fn()
      .mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }))
      .mockResolvedValueOnce(successfulSsoLogin());
    const { auth, sm } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin,
    });
    await sm.saveRememberDeviceToken(
      completeInput.serverUrl,
      completeInput.email,
      'stale-remember-token',
    );

    await expect(auth.completeSsoLogin(completeInput)).rejects.toMatchObject({ status: 400 });
    expect(ssoLogin).toHaveBeenCalledTimes(1);
    expect(await sm.getRememberDeviceToken(completeInput.serverUrl, completeInput.email))
      .toBeUndefined();

    await expect(auth.completeSsoLogin({
      ...completeInput,
      ssoAttemptId: '44444444-4444-4444-8444-444444444444',
    })).resolves.toEqual({ kind: 'locked' });
    expect(ssoLogin).toHaveBeenCalledTimes(2);
    expect(ssoLogin.mock.calls[1]?.[1]).not.toHaveProperty('twoFactorProvider');
  });

  it('clears a restored SSO continuation when its fresh server authority no longer matches', async () => {
    const pendingLoginStore = new PendingLoginStateStore(createMemoryStore(), {
      now: () => 1_000,
      workerId: '11111111-1111-4111-8111-111111111111',
      createAttemptId: () => '22222222-2222-4222-8222-222222222222',
    });
    const first = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin: vi.fn(async () => ({
        kind: 'twoFactor' as const,
        providers: [1],
        email: completeInput.email,
      })),
    }, { pendingLoginStore }).auth;
    await expect(first.completeSsoLogin(completeInput)).resolves.toMatchObject({
      kind: 'twoFactor',
    });
    const restarted = harness({}, {
      pendingLoginStore,
      authorizeSsoContinuation: async () => {
        throw new AppError('session_expired', 'environment changed');
      },
    }).auth;

    await expect(restarted.getPendingLoginStatus()).rejects.toMatchObject({
      code: 'session_expired',
    });
    await expect(pendingLoginStore.read()).resolves.toBeUndefined();
  });

  it('keeps a remembered token after an uncertain SSO exchange failure without replaying', async () => {
    const failure = new ApiHttpError(503, { error: 'temporarily_unavailable' });
    const ssoLogin = vi.fn(async () => { throw failure; });
    const { auth, sm } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin,
    });
    await sm.saveRememberDeviceToken(
      completeInput.serverUrl,
      completeInput.email,
      'remember-token',
    );

    await expect(auth.completeSsoLogin(completeInput)).rejects.toBe(failure);
    expect(ssoLogin).toHaveBeenCalledOnce();
    expect(await sm.getRememberDeviceToken(completeInput.serverUrl, completeInput.email))
      .toBe('remember-token');
  });

  it('does not start the authorization-code grant when prelogin fails and permits a new attempt', async () => {
    const preloginFailure = new ApiHttpError(503, { error: 'temporarily_unavailable' });
    const prelogin = vi.fn()
      .mockRejectedValueOnce(preloginFailure)
      .mockResolvedValueOnce({ kdf: 0 as const, kdfIterations: 600_000 });
    const ssoLogin = vi.fn(async () => successfulSsoLogin());
    const { auth } = harness({ prelogin, ssoLogin });

    await expect(auth.completeSsoLogin(completeInput)).rejects.toBe(preloginFailure);
    expect(ssoLogin).not.toHaveBeenCalled();

    await expect(auth.completeSsoLogin({
      ...completeInput,
      ssoAttemptId: '55555555-5555-4555-8555-555555555555',
      ssoAttemptGeneration: 4,
    })).resolves.toEqual({ kind: 'locked' });
    expect(ssoLogin).toHaveBeenCalledOnce();
  });

  it('revalidates callback authority after the token response and before session commit', async () => {
    let current = true;
    const assertCurrent = vi.fn(() => {
      if (current === false) throw new AppError('session_expired', 'SSO capability changed');
    });
    const ssoLogin = vi.fn(async () => {
      current = false;
      return successfulSsoLogin();
    });
    const { auth, sm } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin,
    });

    await expect(auth.completeSsoLogin({
      ...completeInput,
      assertCurrent,
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(ssoLogin).toHaveBeenCalledOnce();
    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.getPersistedAuth()).toBeUndefined();
  });

  it('removes a locked SSO commit when final callback authority is lost', async () => {
    let current = true;
    const assertCurrent = vi.fn(() => {
      if (current === false) throw new AppError('session_expired', 'SSO capability changed');
    });
    const { auth, sm } = harness({
      prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
      ssoLogin: vi.fn(async () => successfulSsoLogin()),
    });
    const saveLocked = sm.saveLockedAuthenticated.bind(sm);
    vi.spyOn(sm, 'saveLockedAuthenticated').mockImplementation(async (input) => {
      await saveLocked(input);
      current = false;
    });

    await expect(auth.completeSsoLogin({
      ...completeInput,
      assertCurrent,
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.getPersistedAuth()).toBeUndefined();
  });

  it('rejects an account mismatch, master-key salt mismatch, and SSO NDV before session commit', async () => {
    for (const result of [
      successfulSsoLogin('other@example.com'),
      {
        ...successfulSsoLogin(),
        data: { ...successfulSsoLogin().data, MasterKeySalt: 'other@example.com' },
      },
      { kind: 'newDeviceVerification' as const },
    ]) {
      const pendingLoginStore = new PendingLoginStateStore(createMemoryStore(), {
        now: () => 1_000,
      });
      const { auth, sm } = harness({
        prelogin: vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 })),
        ssoLogin: vi.fn(async () => result),
      }, { pendingLoginStore });
      await expect(auth.completeSsoLogin(completeInput)).rejects.toBeInstanceOf(Error);
      expect(await sm.getState()).toBe('loggedOut');
      expect(await sm.getPersistedAuth()).toBeUndefined();
      expect(await pendingLoginStore.read()).toBeUndefined();
    }
  });

  it('enforces the persistent Require SSO gate before a password prelogin request', async () => {
    const denied = new AppError('denied', 'Your organization requires SSO sign-in.');
    const assertPasswordLoginAllowed = vi.fn(async () => { throw denied; });
    const prelogin = vi.fn(async () => ({ kdf: 0 as const, kdfIterations: 600_000 }));
    const { auth, sm } = harness({ prelogin }, { assertPasswordLoginAllowed });

    await expect(auth.login({
      email: ` ${KDF_VECTOR_600K.email.toUpperCase()} `,
      masterPassword: KDF_VECTOR_600K.password,
    })).rejects.toBe(denied);
    expect(assertPasswordLoginAllowed).toHaveBeenCalledWith(
      KDF_VECTOR_600K.email,
      'https://vault.example/',
    );
    expect(prelogin).not.toHaveBeenCalled();
    expect(await sm.getState()).toBe('loggedOut');
  });
});

describe('AuthService forced password change', () => {
  async function harness(
    reason: 'adminForcePasswordReset' | 'weakMasterPassword',
    minLength = 12,
  ) {
    const local = createMemoryStore();
    const sessionStore = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore });
    const policy = {
      minComplexity: 0,
      minLength,
      requireUpper: false,
      requireLower: false,
      requireNumbers: false,
      requireSpecial: false,
      enforceOnLogin: true,
    } as const;
    await sm.saveRestrictedAuthenticated({
      email: KDF_VECTOR_600K.email,
      accessToken: 'restricted-access',
      refreshToken: 'restricted-refresh',
      expiresAt: 999_999,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR_600K.iterations,
      restriction: {
        schemaVersion: 1,
        reason,
        policy,
      },
    });
    const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
    const updateTemporaryPassword = vi.fn<ApiClient['updateTemporaryPassword']>(async () => {});
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({
      serverUrl: 'https://vault.example/',
      accountIdentity: KDF_VECTOR_600K.email,
    });
    const sessionGate = new SessionGate('restricted');
    const marker = {
      markBeforeChange: vi.fn(async () => ({})),
      clear: vi.fn(async () => {}),
    };
    const auth = new AuthService({
      api: mockApiClient({ changePassword, updateTemporaryPassword }),
      session: sm,
      sessionGate,
      accountGate,
      passwordChangePending: marker,
      serverUrlProvider: async () => 'https://vault.example/',
      now: () => 1_000,
      onSessionTransition: sessionGate.handleTransition,
      onSerializedSessionTransition: accountLifecycleHook(
        accountGate,
        sm,
        'https://vault.example/',
      ),
    });
    return { auth, sm, marker, changePassword, updateTemporaryPassword };
  }

  it('uses the temporary-password endpoint for admin recovery and logs out on success', async () => {
    const test = await harness('adminForcePasswordReset');
    await test.auth.changeForcedMasterPassword(
      KDF_VECTOR_600K.password,
      'Correct-Horse-7!Battery',
    );
    expect(test.updateTemporaryPassword).toHaveBeenCalledOnce();
    expect(test.updateTemporaryPassword.mock.calls[0]?.[1]).toMatchObject({
      masterPasswordHint: '',
    });
    expect(test.changePassword).not.toHaveBeenCalled();
    expect(test.marker.markBeforeChange).toHaveBeenCalledBefore(test.updateTemporaryPassword);
    expect(test.marker.clear).toHaveBeenCalledOnce();
    expect(await test.sm.getState()).toBe('loggedOut');
  });

  it('uses the ordinary password endpoint for a weak-password restriction', async () => {
    const test = await harness('weakMasterPassword');
    await test.auth.changeForcedMasterPassword(
      KDF_VECTOR_600K.password,
      'Correct-Horse-7!Battery',
    );
    expect(test.changePassword).toHaveBeenCalledOnce();
    expect(test.changePassword.mock.calls[0]?.[1]).toMatchObject({
      masterPasswordHint: '',
    });
    expect(test.updateTemporaryPassword).not.toHaveBeenCalled();
    expect(await test.sm.getState()).toBe('loggedOut');
  });

  it('uses a stronger organization minimum instead of the 12-character default', async () => {
    const test = await harness('weakMasterPassword', 20);

    await expect(test.auth.changeForcedMasterPassword(
      KDF_VECTOR_600K.password,
      'a'.repeat(19),
    )).rejects.toMatchObject({ code: 'denied' });
    expect(test.changePassword).not.toHaveBeenCalled();

    await expect(test.auth.changeForcedMasterPassword(
      KDF_VECTOR_600K.password,
      'a'.repeat(20),
    )).resolves.toBeUndefined();
    expect(test.changePassword).toHaveBeenCalledOnce();
  });

  it('keeps a definite server rejection restricted and retryable', async () => {
    const test = await harness('adminForcePasswordReset');
    test.updateTemporaryPassword.mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid' }));
    await expect(test.auth.changeForcedMasterPassword(
      KDF_VECTOR_600K.password,
      'Correct-Horse-7!Battery',
    )).rejects.toBeInstanceOf(ApiHttpError);
    expect(test.marker.clear).toHaveBeenCalledOnce();
    expect(await test.sm.getState()).toBe('restricted');
  });

  it('logs out and reports outcome_unknown after an ambiguous transport failure', async () => {
    const test = await harness('adminForcePasswordReset');
    test.updateTemporaryPassword.mockRejectedValueOnce(new Error('connection lost'));
    await expect(test.auth.changeForcedMasterPassword(
      KDF_VECTOR_600K.password,
      'Correct-Horse-7!Battery',
    )).rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(test.marker.clear).toHaveBeenCalledOnce();
    expect(await test.sm.getState()).toBe('loggedOut');
  });
});

describe('password-login MV3 continuation', () => {
  const workerA = 'b67adad5-cf7e-4210-98ed-72017c81896c';
  const workerB = 'bc8e9781-a1d1-49a7-a944-e5d5ef48daf1';
  const continuationAttempt = 'c8882c32-17e1-4052-ac72-9b09f0bbb11d';

  function makeContinuationHarness(
    passwordLogin: (input: PasswordLoginInput) => Promise<PasswordLoginResult>,
    initialNow = 1_000,
    closeInteractiveTwoFactorConnector?: AuthServiceDeps['closeInteractiveTwoFactorConnector'],
  ) {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const pendingStorage = sessionStore;
    const sm = new SessionManager({ localStore, sessionStore });
    let now = initialNow;
    const api = mockApiClient({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
    });
    let firstPendingStore: PendingLoginStateStore | undefined;
    const makeAuth = (workerId: string) => {
      const pendingLoginStore = new PendingLoginStateStore(pendingStorage, {
        now: () => now,
        workerId,
        createAttemptId: () => continuationAttempt,
      });
      if (workerId === workerA) firstPendingStore = pendingLoginStore;
      return new AuthService({
        api,
        session: sm,
        sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
        serverUrlProvider: async () => FIDO_SERVER,
        now: () => now,
        pendingLoginStore,
        ...(closeInteractiveTwoFactorConnector ? { closeInteractiveTwoFactorConnector } : {}),
      });
    };
    const authA = makeAuth(workerA);
    return {
      sm,
      sessionStore,
      authA,
      restart: () => makeAuth(workerB),
      handleExpirationAlarm: (name: string) => firstPendingStore!.handleExpirationAlarm(name),
      setNow(value: number) { now = value; },
    };
  }

  it('restores 2FA after worker restart and commits success locked without persisting unlock material', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0, 1], token: 'email-token' })
      .mockResolvedValueOnce(successfulLogin('restored-access'));
    const harness = makeContinuationHarness(passwordLogin);

    await expect(harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    })).resolves.toMatchObject({ kind: 'twoFactor', providers: [0, 1] });
    const stored = JSON.stringify(await harness.sessionStore.get('pendingLoginContinuation'));
    expect(stored).toContain(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(stored).toContain('passwordEvidence');
    expect(stored).not.toContain(KDF_VECTOR_600K.password);
    expect(stored).not.toMatch(/stretchedMasterKey|masterKey|userKey|privateKey|assertion|newDeviceOtp/);

    const restarted = harness.restart();
    const restoredStatus = await restarted.getPendingLoginStatus();
    expect(restoredStatus).toMatchObject({
      status: 'twoFactor',
      providers: [0, 1],
    });
    expect(restoredStatus).not.toHaveProperty('fido2');
    if (restoredStatus.status !== 'twoFactor') throw new Error('Expected restored 2FA');
    await expect(restarted.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: restoredStatus.continuationId,
    }))
      .resolves.toEqual({ kind: 'locked' });
    expect(await harness.sm.getState()).toBe('locked');
    expect(await harness.sessionStore.get('pendingLoginContinuation')).toBeUndefined();

    await restarted.unlock(KDF_VECTOR_600K.password);
    expect(await harness.sm.getState()).toBe('unlocked');
  });

  it('fails closed when a restored legacy continuation lacks evidence and final policy enforces', async () => {
    const final = successfulLogin('missing-evidence-access');
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockResolvedValueOnce({
        ...final,
        data: {
          ...final.data,
          masterPasswordPolicy: {
            minComplexity: 0,
            minLength: 8,
            requireUpper: false,
            requireLower: false,
            requireNumbers: false,
            requireSpecial: false,
            enforceOnLogin: true,
          },
        },
      });
    const harness = makeContinuationHarness(passwordLogin);
    await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    const raw = await harness.sessionStore.get<Record<string, unknown>>('pendingLoginContinuation');
    const data = raw?.data as Record<string, unknown> | undefined;
    if (!raw || !data) throw new Error('Expected persisted continuation data');
    delete data.passwordEvidence;
    await harness.sessionStore.set('pendingLoginContinuation', raw);

    const restarted = harness.restart();
    const status = await restarted.getPendingLoginStatus();
    if (status.status !== 'twoFactor') throw new Error('Expected restored 2FA');
    await expect(restarted.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: status.continuationId,
    })).resolves.toMatchObject({
      kind: 'restricted',
      requirement: { reason: 'weakMasterPassword' },
    });
    expect(await harness.sm.getState()).toBe('restricted');
    expect(await harness.sm.loadUserKey()).toBeUndefined();
  });

  it('keeps the in-process path directly unlocked', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockResolvedValueOnce(successfulLogin('in-process-access'));
    const harness = makeContinuationHarness(passwordLogin);
    const challenge = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor') throw new Error('Expected 2FA');
    if (!challenge.continuationId) throw new Error('Expected continuation binding');

    await expect(harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: challenge.continuationId,
    }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(await harness.sm.getState()).toBe('unlocked');
  });

  it('releases an explicit HTTP 400 for retry but makes an unknown grant terminal and secret-free', async () => {
    const retryLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }))
      .mockResolvedValueOnce(successfulLogin('retried-access'));
    const retryHarness = makeContinuationHarness(retryLogin);
    await retryHarness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    const retryWorker = retryHarness.restart();
    const retryStatus = await retryWorker.getPendingLoginStatus();
    if (retryStatus.status !== 'twoFactor') throw new Error('Expected restored 2FA');
    await expect(retryWorker.submitTwoFactor({
      provider: 0,
      code: 'wrong',
      continuationId: retryStatus.continuationId,
    }))
      .rejects.toBeInstanceOf(ApiHttpError);
    await expect(retryWorker.getPendingLoginStatus()).resolves.toMatchObject({ status: 'twoFactor' });
    const releasedStatus = await retryWorker.getPendingLoginStatus();
    if (releasedStatus.status !== 'twoFactor') throw new Error('Expected released 2FA');
    await expect(retryWorker.submitTwoFactor({
      provider: 0,
      code: 'right',
      continuationId: releasedStatus.continuationId,
    }))
      .resolves.toEqual({ kind: 'locked' });

    const unknownLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockRejectedValueOnce(new Error('network unavailable'));
    const unknownHarness = makeContinuationHarness(unknownLogin);
    await unknownHarness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    const unknownWorker = unknownHarness.restart();
    const unknownStatus = await unknownWorker.getPendingLoginStatus();
    if (unknownStatus.status !== 'twoFactor') throw new Error('Expected restored 2FA');
    await expect(unknownWorker.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: unknownStatus.continuationId,
    }))
      .rejects.toMatchObject({ code: 'outcome_unknown' });
    await expect(unknownWorker.getPendingLoginStatus())
      .resolves.toMatchObject({ status: 'outcome_unknown' });
    const raw = JSON.stringify(await unknownHarness.sessionStore.get('pendingLoginContinuation'));
    expect(raw).not.toContain(KDF_VECTOR_600K.masterPasswordHashB64);
  });

  it('restores NDV but never persists its submitted OTP', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockResolvedValueOnce(successfulLogin('restored-ndv-access'));
    const harness = makeContinuationHarness(passwordLogin);
    await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    const restarted = harness.restart();
    const status = await restarted.getPendingLoginStatus();
    if (status.status !== 'newDeviceVerification') throw new Error('Expected restored NDV');

    await expect(restarted.submitNewDeviceVerification({
      attemptId: status.attemptId,
      code: '654321',
      continuationId: status.continuationId,
    })).resolves.toEqual({ kind: 'locked' });
    expect(passwordLogin.mock.calls[1]![0]).toMatchObject({ newDeviceOtp: '654321' });
    expect(await harness.sessionStore.get('pendingLoginContinuation')).toBeUndefined();
  });

  it('rebuilds FIDO metadata after restart and rejects the old connector tab binding', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata: FIDO_PROVIDER_METADATA,
    });
    const harness = makeContinuationHarness(passwordLogin);
    await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    const initial = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (initial.kind !== 'twoFactor' || !initial.fido2) throw new Error('Expected FIDO2');
    if (!initial.continuationId) throw new Error('Expected continuation binding');
    const oldLaunch = harness.authA.beginFido2({
      attemptId: initial.fido2.owner.generation,
      continuationId: initial.continuationId,
      parentUrl: FIDO_PARENT_URL,
      locale: 'en',
    });
    harness.authA.bindFido2Tab({
      attemptId: oldLaunch.attemptId,
      url: oldLaunch.url,
      tabId: 9,
      documentId: FIDO_DOCUMENT_ID,
    });

    const restarted = harness.restart();
    const status = await restarted.getPendingLoginStatus();
    expect(status).toMatchObject({
      status: 'twoFactor',
      providers: [7],
      fido2: { owner: initial.fido2.owner },
    });
    expect(() => restarted.assertFido2ConnectorCaller({
      url: oldLaunch.url,
      tabId: 9,
      documentId: FIDO_DOCUMENT_ID,
    }))
      .toThrow(/sender not permitted/);
    if (status.status !== 'twoFactor' || !status.fido2) throw new Error('Expected restored FIDO2');
    const fresh = restarted.beginFido2({
      attemptId: status.attemptId,
      continuationId: status.continuationId,
      parentUrl: FIDO_PARENT_URL,
      locale: 'en',
    });
    expect(fresh.url).toContain('webauthn-fallback-connector.html');
  });

  it('expires the exact in-memory FIDO owner before the durable alarm removes its store entry', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata: FIDO_PROVIDER_METADATA,
    });
    const closeConnector = vi.fn(async () => undefined);
    const harness = makeContinuationHarness(passwordLogin, 1_000, closeConnector);
    const challenge = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2 || !challenge.continuationId) {
      throw new Error('Expected persisted FIDO2 challenge');
    }
    const launch = harness.authA.beginFido2({
      attemptId: challenge.fido2.owner.generation,
      continuationId: challenge.continuationId,
      parentUrl: FIDO_PARENT_URL,
      locale: 'en',
    });
    harness.authA.bindFido2Tab({
      attemptId: launch.attemptId,
      url: launch.url,
      tabId: 91,
      documentId: 'password-expiry-document',
    });

    expect(harness.authA.expirePendingLoginContinuation(
      '11111111-1111-4111-8111-111111111111',
    )).toBe(false);
    harness.setNow(1_000 + PENDING_LOGIN_CONTINUATION_TTL_MS);
    expect(harness.authA.expirePendingLoginContinuation(challenge.continuationId)).toBe(true);
    await vi.waitFor(() => expect(closeConnector).toHaveBeenCalledWith({
      url: launch.url,
      tabId: 91,
      documentId: 'password-expiry-document',
    }));
    await expect(harness.handleExpirationAlarm(
      `${PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX}${challenge.continuationId}`,
    )).resolves.toBe(true);
    await expect(harness.authA.getPendingLoginStatus()).resolves.toEqual({ status: 'none' });
  });

  it('keeps a secret-free durable marker and the original deadline for NDV to 2FA', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf-token' })
      .mockResolvedValueOnce(successfulLogin('must-not-run'));
    const harness = makeContinuationHarness(passwordLogin);
    const first = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (first.kind !== 'newDeviceVerification' || !first.continuationId) {
      throw new Error('Expected bound NDV');
    }
    harness.setNow(2_000);
    const second = await harness.authA.submitNewDeviceVerification({
      attemptId: first.attemptId,
      continuationId: first.continuationId,
      code: '654321',
    });
    if (second.kind !== 'twoFactor' || !second.continuationId) throw new Error('Expected bound 2FA');
    const raw = JSON.stringify(await harness.sessionStore.get('pendingLoginContinuation'));
    expect(raw).toContain('"memoryOnly":true');
    expect(raw).not.toContain(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(raw).not.toContain('654321');
    expect(raw).not.toContain('tf-token');

    harness.setNow(1_000 + PENDING_LOGIN_CONTINUATION_TTL_MS);
    await expect(harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: second.continuationId,
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(passwordLogin).toHaveBeenCalledTimes(2);
  });

  it('does not extend the original deadline when 2FA advances to NDV', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf-token' })
      .mockResolvedValueOnce(newDeviceVerificationRequired());
    const harness = makeContinuationHarness(passwordLogin);
    const first = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (first.kind !== 'twoFactor' || !first.continuationId) throw new Error('Expected bound 2FA');
    harness.setNow(200_000);
    const second = await harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: first.continuationId,
    });

    expect(second).toMatchObject({
      kind: 'newDeviceVerification',
      continuationId: first.continuationId,
      expiresAt: 1_000 + PENDING_LOGIN_CONTINUATION_TTL_MS,
    });
    const raw = JSON.stringify(await harness.sessionStore.get('pendingLoginContinuation'));
    expect(raw).toContain('"memoryOnly":true');
    expect(raw).not.toContain(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(raw).not.toContain('123456');
  });

  it('does not let logout race a claimed grant into republishing a continuation', async () => {
    let rejectGrant!: (error: Error) => void;
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockImplementationOnce(() => new Promise<PasswordLoginResult>((_resolve, reject) => {
        rejectGrant = reject;
      }));
    const harness = makeContinuationHarness(passwordLogin);
    const challenge = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.continuationId) throw new Error('Expected bound 2FA');
    const submission = harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: challenge.continuationId,
    });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(2));

    await harness.authA.logout();
    rejectGrant(new ApiHttpError(400, { error: 'invalid_grant' }));
    await expect(submission).rejects.toMatchObject({ code: 'session_expired' });
    expect(await harness.sessionStore.get('pendingLoginContinuation')).toBeUndefined();
  });

  it('refuses a second password login while a claimed grant is in flight', async () => {
    let rejectGrant!: (error: Error) => void;
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockImplementationOnce(() => new Promise<PasswordLoginResult>((_resolve, reject) => {
        rejectGrant = reject;
      }));
    const harness = makeContinuationHarness(passwordLogin);
    const challenge = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.continuationId) throw new Error('Expected bound 2FA');
    const submission = harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: challenge.continuationId,
    });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(2));

    await expect(harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    })).rejects.toMatchObject({ code: 'outcome_unknown' });
    rejectGrant(new ApiHttpError(400, { error: 'invalid_grant' }));
    await expect(submission).rejects.toBeInstanceOf(ApiHttpError);
  });

  it('rejects a stale public binding without touching the current continuation', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] });
    const harness = makeContinuationHarness(passwordLogin);
    const challenge = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.continuationId) throw new Error('Expected bound 2FA');

    await expect(harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: '0b688c75-8429-4284-a908-5106d2258b7f',
    })).rejects.toMatchObject({ code: 'session_expired' });
    await expect(harness.authA.cancelPendingLogin({
      continuationId: '0b688c75-8429-4284-a908-5106d2258b7f',
    })).resolves.toBe(false);
    expect(passwordLogin).toHaveBeenCalledOnce();
    await expect(harness.authA.getPendingLoginStatus()).resolves.toMatchObject({
      status: 'twoFactor',
      continuationId: challenge.continuationId,
    });
  });

  it('falls back to a secret-free terminal marker when committed-login deletion fails', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockResolvedValueOnce(successfulLogin('cleanup-fallback-access'));
    const harness = makeContinuationHarness(passwordLogin);
    const challenge = await harness.authA.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.continuationId) throw new Error('Expected bound 2FA');
    const remove = harness.sessionStore.remove.bind(harness.sessionStore);
    let failPendingRemoval = true;
    vi.spyOn(harness.sessionStore, 'remove').mockImplementation(async (key) => {
      if (key === 'pendingLoginContinuation' && failPendingRemoval) {
        failPendingRemoval = false;
        throw new Error('transient storage remove failure');
      }
      await remove(key);
    });

    await expect(harness.authA.submitTwoFactor({
      provider: 0,
      code: '123456',
      continuationId: challenge.continuationId,
    })).resolves.toEqual({ kind: 'unlocked' });
    const raw = JSON.stringify(await harness.sessionStore.get('pendingLoginContinuation'));
    expect(raw).toContain('"status":"outcome_unknown"');
    expect(raw).not.toContain(KDF_VECTOR_600K.masterPasswordHashB64);
  });
});

describe('AuthService Login with device completion', () => {
  function apiForDeviceLogin(result: unknown = deviceLoginSuccess()) {
    return {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin: vi.fn(async () => result as Awaited<ReturnType<ApiClient['deviceLogin']>>),
    };
  }

  it('redeems the bound request and commits only ordinary auth fields plus the recovered UserKey', async () => {
    const api = apiForDeviceLogin();
    const { auth, sm } = makeService(api);
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let transientUserKey: SymmetricKey | undefined;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (saveInput) => {
      transientUserKey = saveInput.userKey;
      await saveUnlocked(saveInput);
    });
    const callerUserKey = recoveredDeviceLoginUserKey();
    const input = {
      state: deviceLoginBoundState(),
      userKey: callerUserKey,
      serverUrl: DEVICE_LOGIN_SERVER,
    };

    await expect(auth.completeDeviceLogin(input)).resolves.toEqual({ kind: 'unlocked' });

    expect(api.prelogin).toHaveBeenCalledWith(KDF_VECTOR_600K.email);
    expect(api.deviceLogin).toHaveBeenCalledWith({
      email: KDF_VECTOR_600K.email,
      accessCode: DEVICE_LOGIN_ACCESS_CODE,
      authRequestId: DEVICE_LOGIN_REQUEST_ID,
    });
    expect(await sm.getPersistedAuth()).toMatchObject({
      email: KDF_VECTOR_600K.email,
      accessToken: 'device-access',
      refreshToken: 'device-refresh',
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR_600K.iterations,
    });
    expect(bytesToHex(serializeSymmetricKey((await sm.loadUserKey())!)))
      .toBe(USER_KEY_VECTOR.userKeyHex);
    expect(bytesToHex((await sm.loadPrivateKey())!))
      .toBe(bytesToHex(base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64)));
    expect(bytesToHex(serializeSymmetricKey(callerUserKey))).toBe(USER_KEY_VECTOR.userKeyHex);
    expect(transientUserKey).toBeDefined();
    expect(Array.from(transientUserKey!.encKey)).toEqual(new Array(32).fill(0));
    expect(Array.from(transientUserKey!.macKey)).toEqual(new Array(32).fill(0));
    expect(JSON.stringify(await sm.getPersistedAuth())).not.toContain(DEVICE_LOGIN_ACCESS_CODE);
  });

  it('rolls back its unlocked binding when the requester owner is cancelled during save', async () => {
    const api = apiForDeviceLogin();
    const { auth, sm } = makeService(api);
    const state = deviceLoginBoundState();
    const transitionOwner = createInteractiveTwoFactorOwner({
      flow: 'deviceLogin',
      generation: 7,
      serverUrl: DEVICE_LOGIN_SERVER,
      bindingId: state.requestId,
    });
    let current = true;
    let resolveSaved!: () => void;
    const saved = new Promise<void>((resolve) => { resolveSaved = resolve; });
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      resolveSaved();
      await saveGate;
    });

    const completion = auth.completeDeviceLogin({
      state,
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      transitionOwner,
      assertTransitionOwnerCurrent: () => {
        if (!current) throw new Error('requester owner revoked');
      },
    });
    await saved;
    current = false;
    releaseSave();

    await expect(completion).rejects.toThrow(/owner revoked/);
    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('exactly removes a restricted session when requester cancellation lands during save', async () => {
    const api = apiForDeviceLogin(deviceLoginSuccess({ forcePasswordReset: true }));
    const { auth, sm } = makeService(api);
    const state = deviceLoginBoundState();
    const transitionOwner = createInteractiveTwoFactorOwner({
      flow: 'deviceLogin',
      generation: 8,
      serverUrl: DEVICE_LOGIN_SERVER,
      bindingId: state.requestId,
    });
    let current = true;
    let resolveSaved!: () => void;
    const saved = new Promise<void>((resolve) => { resolveSaved = resolve; });
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
    const saveRestricted = sm.saveRestrictedAuthenticated.bind(sm);
    vi.spyOn(sm, 'saveRestrictedAuthenticated').mockImplementationOnce(async (input) => {
      await saveRestricted(input);
      resolveSaved();
      await saveGate;
    });

    const completion = auth.completeDeviceLogin({
      state,
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      transitionOwner,
      assertTransitionOwnerCurrent: () => {
        if (!current) throw new Error('requester owner revoked');
      },
    });
    await saved;
    current = false;
    releaseSave();

    await expect(completion).rejects.toThrow(/owner revoked/);
    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.getPersistedAuth()).toBeUndefined();
  });

  it('never publishes the recovered UserKey when device login requires a password reset', async () => {
    const callerUserKey = recoveredDeviceLoginUserKey();
    const { auth, sm } = makeService(apiForDeviceLogin(deviceLoginSuccess({
      forcePasswordReset: true,
    })));
    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: callerUserKey,
      serverUrl: DEVICE_LOGIN_SERVER,
    })).resolves.toMatchObject({
      kind: 'restricted',
      requirement: { reason: 'adminForcePasswordReset' },
    });
    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(callerUserKey.encKey.some((value) => value !== 0)).toBe(true);
  });

  it('returns canonical 2FA providers without persisting the recovered key or creating password-login pending state', async () => {
    const api = apiForDeviceLogin({
      kind: 'twoFactor' as const,
      providers: [0, 7],
      token: 'email-challenge-token',
    });
    const { auth, sm } = makeService(api);

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).resolves.toEqual({
      kind: 'twoFactor',
      providers: [0, 7],
      token: 'email-challenge-token',
    });

    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect(() => auth.beginFido2({ attemptId: 1, parentUrl: FIDO_PARENT_URL, locale: 'en' }))
      .toThrowError(expect.objectContaining({ code: 'session_expired' }));
  });

  it('revalidates a bound request on 2FA retry and captures a returned remember token', async () => {
    const deviceLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf-token' })
      .mockResolvedValueOnce(deviceLoginSuccess({ TwoFactorToken: 'remember-device-token' }));
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(api);
    const base = {
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };

    await auth.completeDeviceLogin(base);
    expect(await sm.loadUserKey()).toBeUndefined();
    await expect(auth.completeDeviceLogin({
      ...base,
      twoFactor: { provider: 0, code: ' 123456 ', remember: true },
    })).resolves.toEqual({ kind: 'unlocked' });

    expect(deviceLogin).toHaveBeenLastCalledWith({
      email: KDF_VECTOR_600K.email,
      accessCode: DEVICE_LOGIN_ACCESS_CODE,
      authRequestId: DEVICE_LOGIN_REQUEST_ID,
      twoFactorProvider: 0,
      twoFactorToken: '123456',
      remember: true,
    });
    expect(await sm.getRememberDeviceToken(DEVICE_LOGIN_SERVER, KDF_VECTOR_600K.email))
      .toBe('remember-device-token');
  });

  it('preserves an early device-login force reset and combines policy across 2FA', async () => {
    const deviceLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [0],
        token: 'tf-token',
        forcePasswordReset: true as const,
        masterPasswordPolicy: {
          minComplexity: 1,
          minLength: 20,
          requireUpper: true,
          requireLower: false,
          requireNumbers: false,
          requireSpecial: false,
          enforceOnLogin: false,
        },
      })
      .mockResolvedValueOnce(deviceLoginSuccess({
        masterPasswordPolicy: {
          minComplexity: 3,
          minLength: 12,
          requireUpper: false,
          requireLower: true,
          requireNumbers: true,
          requireSpecial: true,
          enforceOnLogin: true,
        },
      }));
    const { auth, sm } = makeService({
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    });
    const base = {
      state: deviceLoginBoundState(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };

    const challenge = await auth.completeDeviceLogin({
      ...base,
      userKey: recoveredDeviceLoginUserKey(),
    });
    if (challenge.kind !== 'twoFactor') throw new Error('Expected device-login 2FA');
    await expect(auth.completeDeviceLogin({
      ...base,
      userKey: recoveredDeviceLoginUserKey(),
      twoFactor: { provider: 0, code: '123456' },
      ...(challenge.forcePasswordReset ? { forcePasswordReset: true as const } : {}),
      ...(challenge.masterPasswordPolicy
        ? { masterPasswordPolicy: challenge.masterPasswordPolicy }
        : {}),
    })).resolves.toMatchObject({
      kind: 'restricted',
      requirement: {
        reason: 'adminForcePasswordReset',
        policy: {
          minComplexity: 3,
          minLength: 20,
          requireUpper: true,
          requireLower: true,
          requireNumbers: true,
          requireSpecial: true,
          enforceOnLogin: true,
        },
      },
    });
    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('uses a remembered-device token on the first grant and captures its replacement', async () => {
    const api = apiForDeviceLogin(deviceLoginSuccess({ TwoFactorToken: 'rotated-remember-token' }));
    const { auth, sm } = makeService(api);
    await sm.saveRememberDeviceToken(
      DEVICE_LOGIN_SERVER,
      KDF_VECTOR_600K.email,
      'stored-remember-token',
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).resolves.toEqual({ kind: 'unlocked' });

    expect(api.deviceLogin).toHaveBeenCalledOnce();
    expect(api.deviceLogin).toHaveBeenCalledWith({
      email: KDF_VECTOR_600K.email,
      accessCode: DEVICE_LOGIN_ACCESS_CODE,
      authRequestId: DEVICE_LOGIN_REQUEST_ID,
      twoFactorProvider: 5,
      twoFactorToken: 'stored-remember-token',
      remember: true,
    });
    expect(await sm.getRememberDeviceToken(DEVICE_LOGIN_SERVER, KDF_VECTOR_600K.email))
      .toBe('rotated-remember-token');
  });

  it('clears a stale remembered token and retries once after a definite 2FA challenge', async () => {
    const deviceLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [0, 7],
        token: 'fresh-two-factor-token',
      });
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(api);
    await sm.saveRememberDeviceToken(
      DEVICE_LOGIN_SERVER,
      KDF_VECTOR_600K.email,
      'stale-remember-token',
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).resolves.toEqual({
      kind: 'twoFactor',
      providers: [0, 7],
      token: 'fresh-two-factor-token',
    });

    expect(deviceLogin).toHaveBeenCalledTimes(2);
    expect(deviceLogin.mock.calls[0]![0]).toMatchObject({ twoFactorProvider: 5 });
    expect(deviceLogin.mock.calls[1]![0]).toEqual({
      email: KDF_VECTOR_600K.email,
      accessCode: DEVICE_LOGIN_ACCESS_CODE,
      authRequestId: DEVICE_LOGIN_REQUEST_ID,
    });
    expect(await sm.getRememberDeviceToken(DEVICE_LOGIN_SERVER, KDF_VECTOR_600K.email))
      .toBeUndefined();
  });

  it('retries once without a remembered token after a definite HTTP 400 rejection', async () => {
    const deviceLogin = vi.fn()
      .mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }))
      .mockResolvedValueOnce(deviceLoginSuccess());
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(api);
    await sm.saveRememberDeviceToken(
      DEVICE_LOGIN_SERVER,
      KDF_VECTOR_600K.email,
      'stale-remember-token',
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).resolves.toEqual({ kind: 'unlocked' });
    expect(deviceLogin).toHaveBeenCalledTimes(2);
    expect(deviceLogin.mock.calls[1]![0]).not.toHaveProperty('twoFactorProvider');
    expect(await sm.getRememberDeviceToken(DEVICE_LOGIN_SERVER, KDF_VECTOR_600K.email))
      .toBeUndefined();
  });

  it('does not replay a one-time grant or clear the remembered token after an uncertain failure', async () => {
    const deviceLogin = vi.fn(async () => {
      throw new ApiHttpError(503, { error: 'temporarily_unavailable' });
    });
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(api);
    await sm.saveRememberDeviceToken(
      DEVICE_LOGIN_SERVER,
      KDF_VECTOR_600K.email,
      'stored-remember-token',
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).rejects.toMatchObject({ status: 503 });
    expect(deviceLogin).toHaveBeenCalledOnce();
    expect(await sm.getRememberDeviceToken(DEVICE_LOGIN_SERVER, KDF_VECTOR_600K.email))
      .toBe('stored-remember-token');
  });

  it('uses explicit 2FA directly instead of consulting a remembered-device token', async () => {
    const api = apiForDeviceLogin();
    const { auth, sm } = makeService(api);
    await sm.saveRememberDeviceToken(
      DEVICE_LOGIN_SERVER,
      KDF_VECTOR_600K.email,
      'stored-remember-token',
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      twoFactor: { provider: 0, code: ' 654321 ', remember: false },
    })).resolves.toEqual({ kind: 'unlocked' });
    expect(api.deviceLogin).toHaveBeenCalledOnce();
    expect(api.deviceLogin).toHaveBeenCalledWith({
      email: KDF_VECTOR_600K.email,
      accessCode: DEVICE_LOGIN_ACCESS_CODE,
      authRequestId: DEVICE_LOGIN_REQUEST_ID,
      twoFactorProvider: 0,
      twoFactorToken: '654321',
      remember: false,
    });
    expect(await sm.getRememberDeviceToken(DEVICE_LOGIN_SERVER, KDF_VECTOR_600K.email))
      .toBe('stored-remember-token');
  });

  it('returns bounded provider 7 metadata for strict requester-coordinator parsing', async () => {
    const providerMetadata = Object.freeze({
      '7': Object.freeze({ challenge: 'provider-owned-challenge' }),
    });
    const api = apiForDeviceLogin({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata,
    });
    const { auth, sm } = makeService(api);

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).resolves.toEqual({ kind: 'twoFactor', providers: [7], providerMetadata });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('accepts one branded provider 7 assertion without using password pending state', async () => {
    const api = apiForDeviceLogin();
    const { auth, sm } = makeService(api);
    const origin = new URL(DEVICE_LOGIN_SERVER).origin;
    const rpId = new URL(DEVICE_LOGIN_SERVER).hostname;
    const request = parseFido2TwoFactorRequest({
      '7': {
        challenge: FIDO_CHALLENGE,
        rpId,
        allowCredentials: [{ type: 'public-key', id: FIDO_CREDENTIAL_ID }],
        extensions: { appid: `${origin}/app-id.json` },
      },
    }, {
      origin,
      rpId,
    });
    const assertion = await validateFido2TwoFactorSubmission(
      await makeFidoConnectorToken({ origin, rpId }),
      request,
      true,
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      twoFactor: { provider: 7, assertion },
    })).resolves.toEqual({ kind: 'unlocked' });
    expect(api.deviceLogin).toHaveBeenCalledWith({
      email: KDF_VECTOR_600K.email,
      accessCode: DEVICE_LOGIN_ACCESS_CODE,
      authRequestId: DEVICE_LOGIN_REQUEST_ID,
      twoFactorProvider: 7,
      twoFactorToken: assertion.token,
      remember: true,
    });
    expect(await sm.getState()).toBe('unlocked');

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      twoFactor: { provider: 7, assertion },
    })).rejects.toThrow(/already consumed/);
  });

  it('rejects an unbranded provider 7 payload before prelogin', async () => {
    const api = apiForDeviceLogin();
    const { auth } = makeService(api);

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      twoFactor: {
        provider: 7,
        assertion: { token: '{}', remember: false, origin: new URL(DEVICE_LOGIN_SERVER).origin },
      },
    } as never)).rejects.toThrow(/not issued/);
    expect(api.prelogin).not.toHaveBeenCalled();
    expect(api.deviceLogin).not.toHaveBeenCalled();
  });

  it('rejects server, expiry, and device mismatches before prelogin', async () => {
    const cases: Array<{ state: DeviceLoginBoundState; serverUrl: string; currentServer?: string }> = [
      {
        state: deviceLoginBoundState(),
        serverUrl: 'https://old.example/',
        currentServer: 'https://new.example/',
      },
      {
        state: deviceLoginBoundState({ expiresAt: 1_000 }),
        serverUrl: DEVICE_LOGIN_SERVER,
      },
      {
        state: deviceLoginBoundState({
          device: { type: 2, name: 'chrome', identifier: 'other-device' },
        }),
        serverUrl: DEVICE_LOGIN_SERVER,
      },
      {
        state: deviceLoginBoundState({
          device: { type: 1, name: 'chrome', identifier: 'device-123' },
        }),
        serverUrl: DEVICE_LOGIN_SERVER,
      },
      {
        state: deviceLoginBoundState({
          device: { type: 2, name: 'other-client', identifier: 'device-123' },
        }),
        serverUrl: DEVICE_LOGIN_SERVER,
      },
    ];

    for (const testCase of cases) {
      const api = apiForDeviceLogin();
      const { auth } = makeService(
        api,
        async () => testCase.currentServer ?? DEVICE_LOGIN_SERVER,
      );
      await expect(auth.completeDeviceLogin({
        state: testCase.state,
        userKey: recoveredDeviceLoginUserKey(),
        serverUrl: testCase.serverUrl,
      })).rejects.toBeInstanceOf(AppError);
      expect(api.prelogin).not.toHaveBeenCalled();
      expect(api.deviceLogin).not.toHaveBeenCalled();
    }
  });

  it('reports only the pre-grant stage when device-login prelogin fails', async () => {
    const api = apiForDeviceLogin();
    api.prelogin.mockRejectedValueOnce(new Error('prelogin unavailable'));
    const { auth } = makeService(api);
    const stages: DeviceLoginActivationStage[] = [];

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      reportActivationStage: (stage) => stages.push(stage),
    })).rejects.toThrow('prelogin unavailable');

    expect(stages).toEqual(['pre_grant']);
    expect(api.deviceLogin).not.toHaveBeenCalled();
  });

  it('reports an uncertain token grant only when its request reaches the fetch guard', async () => {
    const api = apiForDeviceLogin();
    api.deviceLogin.mockRejectedValueOnce(new Error('token grant timed out'));
    const { auth } = makeService(api);
    const stages: DeviceLoginActivationStage[] = [];

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      reportActivationStage: (stage) => stages.push(stage),
    })).rejects.toThrow('token grant timed out');

    expect(stages).toEqual(['pre_grant', 'grant_started']);
  });

  it('reports a definite token rejection after the grant request receives a 4xx response', async () => {
    const api = apiForDeviceLogin();
    api.deviceLogin.mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }));
    const { auth } = makeService(api);
    const stages: DeviceLoginActivationStage[] = [];

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
      reportActivationStage: (stage) => stages.push(stage),
    })).rejects.toBeInstanceOf(ApiHttpError);

    expect(stages).toEqual(['pre_grant', 'grant_started', 'grant_rejected']);
  });

  it.each([408, 429])(
    'keeps HTTP %s device-login grant failures outcome-ambiguous',
    async (status) => {
      const api = apiForDeviceLogin();
      api.deviceLogin.mockRejectedValueOnce(new ApiHttpError(status, { error: 'retry later' }));
      const { auth } = makeService(api);
      const stages: DeviceLoginActivationStage[] = [];

      await expect(auth.completeDeviceLogin({
        state: deviceLoginBoundState(),
        userKey: recoveredDeviceLoginUserKey(),
        serverUrl: DEVICE_LOGIN_SERVER,
        reportActivationStage: (stage) => stages.push(stage),
      })).rejects.toBeInstanceOf(ApiHttpError);

      expect(stages).toEqual(['pre_grant', 'grant_started']);
    },
  );

  it('does not send the grant after a server transition starts during prelogin', async () => {
    let releasePrelogin!: () => void;
    const preloginGate = new Promise<void>((resolve) => { releasePrelogin = resolve; });
    const prelogin = vi.fn(async () => {
      await preloginGate;
      return { kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations };
    });
    const deviceLogin = vi.fn(async () => deviceLoginSuccess());
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const accountGate = new AccountLeaseGate();
    let serverUrl = DEVICE_LOGIN_SERVER;
    accountGate.initialize({ serverUrl });
    const sessionGate = new SessionGate('loggedOut');
    const coordinator = new AccountTransitionCoordinator(accountGate, async () => {
      const active = await sm.getPersistedAuth();
      return {
        serverUrl,
        ...(active ? { accountIdentity: active.email } : {}),
      };
    });
    const auth = new AuthService({
      api: mockApiClient({
        getDeviceIdentifier: vi.fn(async () => 'device-123'),
        prelogin,
        deviceLogin,
      }),
      session: sm,
      sessionGate,
      accountGate,
      serverUrlProvider: async () => serverUrl,
      now: () => 1_000,
      onSessionTransition: sessionGate.handleTransition,
      onSerializedSessionTransition: coordinator.handle,
    });

    const completion = auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    });
    await vi.waitFor(() => expect(prelogin).toHaveBeenCalledOnce());
    await auth.resetForServerChange(async () => { serverUrl = 'https://new.example/'; });
    releasePrelogin();

    await expect(completion).rejects.toMatchObject({ code: 'session_expired' });
    expect(deviceLogin).not.toHaveBeenCalled();
    expect(accountGate.current()).toEqual({ serverUrl: 'https://new.example/' });
  });

  it.each([
    ['access token', { access_token: '' }],
    ['refresh token', { refresh_token: undefined }],
    ['protected key', { Key: '' }],
    ['protected key encoding', { Key: '4.invalid' }],
    ['token lifetime', { expires_in: 0 }],
    ['token lifetime type', { expires_in: 3_600.5 }],
    ['token type', { token_type: 'MAC' }],
  ])('rejects an invalid device-login %s without committing a session', async (_label, override) => {
    const api = apiForDeviceLogin(deviceLoginSuccess(override));
    const { auth, sm } = makeService(api);

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).rejects.toBeTruthy();
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('rejects token KDF settings that differ from prelogin', async () => {
    const api = apiForDeviceLogin(deviceLoginSuccess({ KdfIterations: 600_001 }));
    const { auth, sm } = makeService(api);

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).rejects.toThrow(/changed KDF settings/u);
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('rejects an encrypted PrivateKey that cannot be opened by the recovered UserKey', async () => {
    const wrongKey = symmetricKeyFromBytes(new Uint8Array(64).fill(9));
    const api = apiForDeviceLogin(deviceLoginSuccess({
      PrivateKey: await encryptToBytes(base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64), wrongKey),
    }));
    const { auth, sm } = makeService(api);

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).rejects.toBeInstanceOf(EncStringMacError);
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('does not let a duplicate submission consume the same one-time auth request twice', async () => {
    let resolveDeviceLogin!: (result: ReturnType<typeof deviceLoginSuccess>) => void;
    const deviceLogin = vi.fn(() => new Promise<ReturnType<typeof deviceLoginSuccess>>((resolve) => {
      resolveDeviceLogin = resolve;
    }));
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth } = makeService(api);
    const input = {
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };

    const first = auth.completeDeviceLogin(input);
    await vi.waitFor(() => expect(deviceLogin).toHaveBeenCalledOnce());
    await expect(auth.completeDeviceLogin(input))
      .rejects.toThrow(/already being verified/u);
    expect(deviceLogin).toHaveBeenCalledOnce();
    resolveDeviceLogin(deviceLoginSuccess());
    await expect(first).resolves.toEqual({ kind: 'unlocked' });
  });

  it('lets a newer different device-login request own the session', async () => {
    let resolveOlder!: (result: ReturnType<typeof deviceLoginSuccess>) => void;
    const deviceLogin = vi.fn()
      .mockImplementationOnce(() => new Promise<ReturnType<typeof deviceLoginSuccess>>((resolve) => {
        resolveOlder = resolve;
      }))
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'new-device-access',
        refresh_token: 'new-device-refresh',
      }));
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(api);
    const input = {
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };

    const older = auth.completeDeviceLogin(input);
    await vi.waitFor(() => expect(deviceLogin).toHaveBeenCalledOnce());
    await expect(auth.completeDeviceLogin({
      ...input,
      state: deviceLoginBoundState({
        requestId: '22222222-2222-4222-8222-222222222222',
        accessCode: `Bb1${'c'.repeat(22)}`,
      }),
    })).resolves.toEqual({ kind: 'unlocked' });
    resolveOlder(deviceLoginSuccess({
      access_token: 'old-device-access',
      refresh_token: 'old-device-refresh',
    }));

    await expect(older).rejects.toMatchObject({ code: 'session_expired' });
    expect(await sm.getPersistedAuth()).toMatchObject({
      accessToken: 'new-device-access',
      refreshToken: 'new-device-refresh',
    });
  });

  it('keeps a committed grant successful when a newer activation starts during transition settlement', async () => {
    let releaseSettlement!: () => void;
    const settlementGate = new Promise<void>((resolve) => { releaseSettlement = resolve; });
    let settlementStarted = false;
    const deviceLogin = vi.fn()
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'committed-access',
        refresh_token: 'committed-refresh',
      }))
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'newer-access',
        refresh_token: 'newer-refresh',
      }));
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(
      api,
      async () => DEVICE_LOGIN_SERVER,
      undefined,
      async (event) => {
        if (event.phase === 'settled' && event.reason === 'login' && !settlementStarted) {
          settlementStarted = true;
          await settlementGate;
        }
      },
    );
    const firstInput = {
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };
    const first = auth.completeDeviceLogin(firstInput);
    await vi.waitFor(() => expect(settlementStarted).toBe(true));
    const second = auth.completeDeviceLogin({
      ...firstInput,
      state: deviceLoginBoundState({
        requestId: '22222222-2222-4222-8222-222222222222',
        accessCode: `Bb1${'c'.repeat(22)}`,
      }),
    });
    await vi.waitFor(() => expect(deviceLogin).toHaveBeenCalledTimes(2));
    releaseSettlement();

    await expect(first).resolves.toEqual({ kind: 'unlocked' });
    await expect(second).resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getPersistedAuth()).toMatchObject({
      accessToken: 'newer-access',
      refreshToken: 'newer-refresh',
    });
  });

  it('does not turn a committed login into failure when remember-token storage overlaps a newer activation', async () => {
    let releaseRememberSave!: () => void;
    const rememberSaveGate = new Promise<void>((resolve) => { releaseRememberSave = resolve; });
    const deviceLogin = vi.fn()
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'committed-access',
        refresh_token: 'committed-refresh',
        TwoFactorToken: 'committed-remember-token',
      }))
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'newer-access',
        refresh_token: 'newer-refresh',
      }));
    const api = {
      getDeviceIdentifier: vi.fn(async () => 'device-123'),
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      deviceLogin,
    };
    const { auth, sm } = makeService(api);
    const saveRememberToken = sm.saveRememberDeviceToken.bind(sm);
    let rememberSaveStarted = false;
    vi.spyOn(sm, 'saveRememberDeviceToken').mockImplementationOnce(async (...args) => {
      rememberSaveStarted = true;
      await rememberSaveGate;
      await saveRememberToken(...args);
    });
    const firstInput = {
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };
    const first = auth.completeDeviceLogin(firstInput);
    await vi.waitFor(() => expect(rememberSaveStarted).toBe(true));
    const second = auth.completeDeviceLogin({
      ...firstInput,
      state: deviceLoginBoundState({
        requestId: '22222222-2222-4222-8222-222222222222',
        accessCode: `Bb1${'c'.repeat(22)}`,
      }),
    });
    await expect(second).resolves.toEqual({ kind: 'unlocked' });
    releaseRememberSave();

    await expect(first).resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getPersistedAuth()).toMatchObject({
      accessToken: 'newer-access',
      refreshToken: 'newer-refresh',
    });
  });

  it('locks only its own published binding when saveUnlocked reports a post-commit failure', async () => {
    const api = apiForDeviceLogin();
    const { auth, sm } = makeService(api);
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      throw new Error('session storage acknowledgement failed');
    });

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).rejects.toThrow('session storage acknowledgement failed');
    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('falls back to clearing local accounts if exact-binding rollback storage fails', async () => {
    const api = apiForDeviceLogin();
    const { auth, sm } = makeService(api);
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      throw new Error('session storage acknowledgement failed');
    });
    vi.spyOn(sm, 'lockIfCurrentSessionBinding').mockRejectedValueOnce(
      new Error('binding rollback storage failed'),
    );

    await expect(auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    })).rejects.toThrow('session storage acknowledgement failed');
    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.getPersistedAuth()).toBeUndefined();
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('rolls back a superseded commit before failure settlement and restores production gates', async () => {
    const deviceLogin = vi.fn()
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'superseded-access',
        refresh_token: 'superseded-refresh',
      }))
      .mockResolvedValueOnce(deviceLoginSuccess({
        access_token: 'winning-access',
        refresh_token: 'winning-refresh',
      }));
    const sm = new SessionManager({
      localStore: createMemoryStore(),
      sessionStore: createMemoryStore(),
    });
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example' });
    const sessionGate = new SessionGate('loggedOut');
    const transitionEvents: SessionTransitionEvent[] = [];
    const auth = new AuthService({
      api: mockApiClient({
        getDeviceIdentifier: vi.fn(async () => 'device-123'),
        prelogin: vi.fn(async () => ({
          kdf: 0 as const,
          kdfIterations: KDF_VECTOR_600K.iterations,
        })),
        deviceLogin,
      }),
      session: sm,
      sessionGate,
      accountGate,
      now: () => 1_000,
      serverUrlProvider: async () => 'https://vault.example',
      onSessionTransition: (event) => {
        transitionEvents.push(event);
        sessionGate.handleTransition(event);
      },
      onSerializedSessionTransition: accountLifecycleHook(accountGate, sm),
    });
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let releaseFirstSave!: () => void;
    const firstSaveGate = new Promise<void>((resolve) => { releaseFirstSave = resolve; });
    let firstSaveCommitted = false;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      firstSaveCommitted = true;
      await firstSaveGate;
    });
    const firstInput = {
      state: deviceLoginBoundState(),
      userKey: recoveredDeviceLoginUserKey(),
      serverUrl: DEVICE_LOGIN_SERVER,
    };

    const superseded = auth.completeDeviceLogin(firstInput);
    await vi.waitFor(() => expect(firstSaveCommitted).toBe(true));
    const supersedingLock = auth.lock();
    releaseFirstSave();

    await expect(superseded).rejects.toMatchObject({ code: 'session_expired' });
    await expect(supersedingLock).resolves.toBeUndefined();
    const winning = auth.completeDeviceLogin({
      ...firstInput,
      userKey: recoveredDeviceLoginUserKey(),
      state: deviceLoginBoundState({
        requestId: '22222222-2222-4222-8222-222222222222',
        accessCode: `Bb1${'c'.repeat(22)}`,
      }),
    });
    await expect(winning).resolves.toEqual({ kind: 'unlocked' });
    expect(deviceLogin).toHaveBeenCalledTimes(2);
    const settled = transitionEvents.filter(
      (event) => event.phase === 'settled' && event.reason === 'login',
    );
    expect(settled[0]).toMatchObject({ state: 'locked', succeeded: false });
    expect(settled[1]).toMatchObject({ state: 'unlocked', succeeded: true });
    expect(await sm.getPersistedAuth()).toMatchObject({
      accessToken: 'winning-access',
      refreshToken: 'winning-refresh',
    });
    expect(() => sessionGate.capture()).not.toThrow();
    expect(accountGate.capture()).toMatchObject({
      accountIdentity: KDF_VECTOR_600K.email,
    });
  });

  it('invalidates an in-flight completion across an A-B-A account transition', async () => {
    let resolveDeviceLogin!: (result: ReturnType<typeof deviceLoginSuccess>) => void;
    const deviceLogin = vi.fn(() => new Promise<ReturnType<typeof deviceLoginSuccess>>((resolve) => {
      resolveDeviceLogin = resolve;
    }));
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const userKey = recoveredDeviceLoginUserKey();
    await sm.saveUnlocked({
      email: 'b@example.com', accessToken: 'b-access', refreshToken: 'b-refresh', expiresAt: 999_999,
      protectedKey: USER_KEY_VECTOR_600K.akey, kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations,
      userKey,
    });
    await sm.saveUnlocked({
      email: KDF_VECTOR_600K.email, accessToken: 'a-access', refreshToken: 'a-refresh', expiresAt: 999_999,
      protectedKey: USER_KEY_VECTOR_600K.akey, kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations,
      userKey,
    });
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: DEVICE_LOGIN_SERVER, accountIdentity: KDF_VECTOR_600K.email });
    const sessionGate = new SessionGate('unlocked');
    const auth = new AuthService({
      api: mockApiClient({
        getDeviceIdentifier: vi.fn(async () => 'device-123'),
        prelogin: vi.fn(async () => ({
          kdf: 0 as const,
          kdfIterations: KDF_VECTOR_600K.iterations,
        })),
        deviceLogin,
      }),
      session: sm,
      sessionGate,
      accountGate,
      serverUrlProvider: async () => DEVICE_LOGIN_SERVER,
      now: () => 1_000,
      onSessionTransition: sessionGate.handleTransition,
      onSerializedSessionTransition: accountLifecycleHook(accountGate, sm, DEVICE_LOGIN_SERVER),
    });

    const stale = auth.completeDeviceLogin({
      state: deviceLoginBoundState(),
      userKey,
      serverUrl: DEVICE_LOGIN_SERVER,
    });
    await vi.waitFor(() => expect(deviceLogin).toHaveBeenCalledOnce());
    await auth.switchAccount('b@example.com');
    await auth.switchAccount(KDF_VECTOR_600K.email);
    resolveDeviceLogin(deviceLoginSuccess({
      access_token: 'stale-device-access',
      refresh_token: 'stale-device-refresh',
    }));

    await expect(stale).rejects.toMatchObject({ code: 'session_expired' });
    expect(await sm.getPersistedAuth()).toMatchObject({
      email: KDF_VECTOR_600K.email,
      accessToken: 'a-access',
      refreshToken: 'a-refresh',
    });
  });
});

const FIDO_SERVER = 'https://vault.example.com/';
const FIDO_RP_ID = 'vault.example.com';
const FIDO_PARENT_URL = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/ui/popup/popup.html';
const FIDO_DOCUMENT_ID = 'fido-connector-document-1';
const FIDO_CHALLENGE = bytesToBase64Url(new Uint8Array(32).fill(7));
const FIDO_CREDENTIAL_BYTES = new Uint8Array(32).fill(9);
const FIDO_CREDENTIAL_ID = bytesToBase64Url(FIDO_CREDENTIAL_BYTES);
const FIDO_PROVIDER_METADATA = {
  '7': {
    challenge: FIDO_CHALLENGE,
    timeout: 60_000,
    rpId: FIDO_RP_ID,
    allowCredentials: [{ type: 'public-key', id: FIDO_CREDENTIAL_ID }],
    userVerification: 'discouraged',
    extensions: { appid: `${FIDO_SERVER}app-id.json` },
  },
};

async function makeFidoConnectorToken(options: {
  origin?: string;
  rpId?: string;
  challenge?: string;
} = {}): Promise<string> {
  const rpHash = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      'SHA-256',
      utf8ToBytes(options.rpId ?? FIDO_RP_ID) as BufferSource,
    ),
  );
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpHash);
  authenticatorData[32] = 0x01;
  return JSON.stringify({
    id: FIDO_CREDENTIAL_ID,
    rawId: FIDO_CREDENTIAL_ID,
    type: 'public-key',
    extensions: { appid: false },
    response: {
      authenticatorData: bytesToBase64Url(authenticatorData),
      clientDataJson: bytesToBase64Url(utf8ToBytes(JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge ?? FIDO_CHALLENGE,
        origin: options.origin ?? FIDO_SERVER.slice(0, -1),
        crossOrigin: false,
      }))),
      signature: bytesToBase64Url(new Uint8Array([1, 2, 3])),
    },
  });
}

function launchFidoConnector(
  auth: AuthService,
  owner: Fido2TwoFactorChallenge['owner'],
  tabId = 71,
  documentId = FIDO_DOCUMENT_ID,
) {
  const attemptId = owner.generation;
  const launch = auth.beginFido2({ attemptId, parentUrl: FIDO_PARENT_URL, locale: 'zh-CN' });
  auth.bindFido2Tab({ attemptId, url: launch.url, tabId, documentId });
  return { ...launch, owner, tabId, documentId };
}

const ROTATION_SERVER = 'https://vault.example/';
const ROTATION_EMAIL = 'rotation@example.com';
const ROTATION_PASSWORD = 'rotation-password';

async function makeRotationHarness(
  apiOverrides: Partial<ApiClient> = {},
  options: {
    addOtherAccount?: boolean;
    onIdentityChanged?: () => Promise<void>;
    clearGeneratorHistoryForServerAfterRotation?: (serverUrl: string) => Promise<void>;
    clearClientEventsAfterRotation?: (identity: {
      readonly serverUrl: string;
      readonly accountId: string;
    }) => Promise<void>;
  } = {},
) {
  const localStore = createMemoryStore();
  const sessionStore = createMemoryStore();
  const sm = new SessionManager({ localStore, sessionStore });
  const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
  const kdf = { kdf: 0 as const, kdfIterations: 5_000 };
  const stretched = await stretchMasterKey(await deriveMasterKey(
    ROTATION_PASSWORD,
    ROTATION_EMAIL,
    kdf,
  ));
  const protectedKey = await encryptToBytes(serializeSymmetricKey(userKey), stretched);
  if (options.addOtherAccount) {
    await sm.saveUnlocked({
      email: 'other@example.com', accessToken: 'other-access', refreshToken: 'other-refresh',
      expiresAt: 999_999, protectedKey: 'other-protected-key', ...kdf, userKey,
    });
  }
  await sm.saveUnlocked({
    email: ROTATION_EMAIL, accessToken: 'rotation-access', refreshToken: 'rotation-refresh',
    expiresAt: 999_999, protectedKey, ...kdf, userKey,
    privateKey: base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64),
  });

  const apiMethods: Partial<ApiClient> = {
    sync: vi.fn(async () => ({
      profile: { id: 'rotation-user', email: ROTATION_EMAIL, organizations: [] },
      ciphers: [], folders: [], sends: [],
    })),
    getTrustedEmergencyAccess: vi.fn(async () => []),
    getAccountPublicKey: vi.fn(async () => ({ publicKey: 'account-public-key' })),
    getKeyRotationUnlockRecordsStatus: vi.fn(async () => ({
      passkeyUnlockData: 'empty' as const,
      deviceKeyUnlockData: 'empty' as const,
    })),
    rotateAccountKey: vi.fn(async () => {}),
    ...apiOverrides,
  };
  const accountGate = new AccountLeaseGate();
  accountGate.initialize({ serverUrl: ROTATION_SERVER, accountIdentity: ROTATION_EMAIL });
  const sessionGate = new SessionGate('unlocked');
  const coordinator = new VaultMutationCoordinator<string, AccountLease, unknown, string, string>({
    captureLease: (account) => {
      const lease = accountGate.capture();
      expect(account).toBe(`${lease.serverUrl}\n${lease.accountIdentity}`);
      return lease;
    },
    assertLease: (_account, lease) => accountGate.assert(lease),
  });
  const pending = new RotationPendingStore(localStore, { now: () => 10 });
  const cacheClear = options.onIdentityChanged ?? vi.fn(async () => {});
  const historyClear = options.clearGeneratorHistoryForServerAfterRotation ?? vi.fn(async () => {});
  const clientEventsClear = options.clearClientEventsAfterRotation ?? vi.fn(async () => {});
  const auth = new AuthService({
    api: mockApiClient(apiMethods),
    session: sm,
    sessionGate,
    accountGate,
    rotationBarrier: {
      run: (account, task) => coordinator.forAccount(account).runTerminal(task),
    },
    rotationPending: pending,
    clearGeneratorHistoryForServerAfterRotation: historyClear,
    clearClientEventsAfterRotation: clientEventsClear,
    serverUrlProvider: async () => ROTATION_SERVER,
    now: () => 1_000,
    onIdentityChanged: cacheClear,
    onSessionTransition: sessionGate.handleTransition,
    onSerializedSessionTransition: accountLifecycleHook(accountGate, sm, ROTATION_SERVER),
  });
  return {
    auth,
    sm,
    api: apiMethods,
    pending,
    coordinator,
    accountGate,
    sessionGate,
    cacheClear,
    historyClear,
    clientEventsClear,
    accountKey: `${ROTATION_SERVER}\n${ROTATION_EMAIL}`,
  };
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
        PrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
        Kdf: 0 as const,
        KdfIterations: KDF_VECTOR_600K.iterations,
      },
    });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let transientUserKey: SymmetricKey | undefined;
    let transientPrivateKey: Uint8Array | undefined;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      transientUserKey = input.userKey;
      transientPrivateKey = input.privateKey;
      await saveUnlocked(input);
    });
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getState()).toBe('unlocked');
    const calls = passwordLogin.mock.calls as Array<[{ masterPasswordHash: string }]>;
    expect(calls[0]?.[0].masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(transientUserKey?.encKey).toEqual(new Uint8Array(32));
    expect(transientUserKey?.macKey).toEqual(new Uint8Array(32));
    expect(transientPrivateKey?.every((value) => value === 0)).toBe(true);
    expect(await sm.loadUserKey()).toBeDefined();
    expect(await sm.loadPrivateKey()).toBeDefined();
  });

  it('commits a force-reset password grant directly as restricted', async () => {
    const success = successfulLogin('forced-access');
    const forced = {
      ...success,
      data: { ...success.data, forcePasswordReset: true as const },
    };
    const { auth, sm } = makeService({
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      passwordLogin: vi.fn(async () => forced),
    });
    const saveUnlocked = vi.spyOn(sm, 'saveUnlocked');
    await expect(auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    })).resolves.toMatchObject({
      kind: 'restricted',
      requirement: { reason: 'adminForcePasswordReset' },
    });
    expect(saveUnlocked).not.toHaveBeenCalled();
    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('retains a weak-password decision across the two-factor continuation', async () => {
    const success = successfulLogin('two-factor-access');
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [0],
        masterPasswordPolicy: {
          minComplexity: 0,
          minLength: 100,
          requireUpper: false,
          requireLower: false,
          requireNumbers: false,
          requireSpecial: false,
          enforceOnLogin: true,
        },
      })
      .mockResolvedValueOnce(success);
    const { auth, sm } = makeService({
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      passwordLogin,
    });
    await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    await expect(auth.submitTwoFactor({ provider: 0, code: '123456' }))
      .resolves.toMatchObject({
        kind: 'restricted',
        requirement: { reason: 'weakMasterPassword' },
      });
    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('monotonically combines staged policy and preserves an early force reset', async () => {
    const final = successfulLogin('staged-force-access');
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [0],
        forcePasswordReset: true as const,
        masterPasswordPolicy: {
          minComplexity: 1,
          minLength: 20,
          requireUpper: true,
          requireLower: false,
          requireNumbers: false,
          requireSpecial: false,
          enforceOnLogin: false,
        },
      })
      .mockResolvedValueOnce({
        ...final,
        data: {
          ...final.data,
          masterPasswordPolicy: {
            minComplexity: 3,
            minLength: 12,
            requireUpper: false,
            requireLower: true,
            requireNumbers: true,
            requireSpecial: true,
            enforceOnLogin: true,
          },
        },
      });
    const { auth, sm } = makeService({
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      passwordLogin,
    });

    await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    await expect(auth.submitTwoFactor({ provider: 0, code: '123456' }))
      .resolves.toMatchObject({
        kind: 'restricted',
        requirement: {
          reason: 'adminForcePasswordReset',
          policy: {
            minComplexity: 3,
            minLength: 20,
            requireUpper: true,
            requireLower: true,
            requireNumbers: true,
            requireSpecial: true,
            enforceOnLogin: true,
          },
        },
      });
    expect(await sm.getState()).toBe('restricted');
    expect(await sm.loadUserKey()).toBeUndefined();
  });

  it('re-evaluates password evidence when enforce-on-login first appears in the final token', async () => {
    const final = successfulLogin('late-policy-access');
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0] })
      .mockResolvedValueOnce({
        ...final,
        data: {
          ...final.data,
          masterPasswordPolicy: {
            minComplexity: 0,
            minLength: 100,
            requireUpper: false,
            requireLower: false,
            requireNumbers: false,
            requireSpecial: false,
            enforceOnLogin: true,
          },
        },
      });
    const { auth, sm } = makeService({
      prelogin: vi.fn(async () => ({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      })),
      passwordLogin,
    });

    await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    await expect(auth.submitTwoFactor({ provider: 0, code: '123456' }))
      .resolves.toMatchObject({
        kind: 'restricted',
        requirement: { reason: 'weakMasterPassword' },
      });
    expect(await sm.getState()).toBe('restricted');
  });

  it.each([
    ['non-Bearer token type', { token_type: 'MAC' }],
    ['missing refresh token', { refresh_token: undefined }],
    ['overflowing lifetime', { expires_in: Number.MAX_SAFE_INTEGER }],
    ['malformed protected key', { Key: '2.invalid' }],
    ['malformed private key', { PrivateKey: '2.invalid' }],
    ['control character in remember token', { TwoFactorToken: 'remember\nheader' }],
    ['incomplete Argon2 KDF', { Kdf: 1, KdfIterations: 4, KdfMemory: 64 }],
  ])('rejects malformed login data from a forged API adapter before persistence: %s', async (_label, override) => {
    const valid = successfulLogin('access');
    const { auth, sm } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: { ...valid.data, ...override },
      } as never),
    });

    await expect(auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    })).rejects.toThrow();
    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.getPersistedAuth()).toBeUndefined();
  });

  it('lets the newest concurrent login response activate the session', async () => {
    type Success = ReturnType<typeof successfulLogin>;
    const resolvers: Array<(result: Success) => void> = [];
    const passwordLogin = vi.fn(() => new Promise<Success>((resolve) => resolvers.push(resolve)));
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);

    const older = auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(1));
    const newer = auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(2));

    resolvers[1]!(successfulLogin('newer-access'));
    await expect(newer).resolves.toEqual({ kind: 'unlocked' });
    resolvers[0]!(successfulLogin('older-access'));
    await expect(older).rejects.toMatchObject({ code: 'session_expired' });
    expect((await sm.getPersistedAuth())?.accessToken).toBe('newer-access');
  });

  it('settles a password commit as locked when a newer activation supersedes its storage write', async () => {
    const transitionEvents: SessionTransitionEvent[] = [];
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(successfulLogin('superseded-password-access'))
      .mockResolvedValueOnce(successfulLogin('winning-password-access'));
    const { auth, sm } = makeService(
      {
        prelogin: vi.fn().mockResolvedValue({
          kdf: 0 as const,
          kdfIterations: KDF_VECTOR_600K.iterations,
        }),
        passwordLogin,
      },
      undefined,
      undefined,
      (event) => { transitionEvents.push(event); },
    );
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let releaseFirstSave!: () => void;
    const firstSaveGate = new Promise<void>((resolve) => { releaseFirstSave = resolve; });
    let firstSaveCommitted = false;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      firstSaveCommitted = true;
      await firstSaveGate;
    });

    const superseded = auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    await vi.waitFor(() => expect(firstSaveCommitted).toBe(true));
    const winning = auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(2));
    releaseFirstSave();

    await expect(superseded).rejects.toMatchObject({ code: 'session_expired' });
    await expect(winning).resolves.toEqual({ kind: 'unlocked' });
    const settled = transitionEvents.filter(
      (event) => event.phase === 'settled' && event.reason === 'login',
    );
    expect(settled[0]).toMatchObject({ state: 'locked', succeeded: false });
    expect(settled[1]).toMatchObject({ state: 'unlocked', succeeded: true });
    expect((await sm.getPersistedAuth())?.accessToken).toBe('winning-password-access');
  });

  it('does not let an in-flight login unlock after an explicit lock', async () => {
    type Success = ReturnType<typeof successfulLogin>;
    let resolveLogin!: (result: Success) => void;
    const passwordLogin = vi.fn(() => new Promise<Success>((resolve) => { resolveLogin = resolve; }));
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);

    const login = auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(1));
    await auth.lock();
    resolveLogin(successfulLogin('late-access'));

    await expect(login).rejects.toMatchObject({ code: 'session_expired' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('serializes a lock behind an in-progress login commit while invalidating immediately', async () => {
    const events: SessionTransitionEvent[] = [];
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue(successfulLogin('access')),
    };
    const { auth, sm } = makeService(api, undefined, undefined, (event) => { events.push(event); });
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveGate;
      await saveUnlocked(input);
    });

    const login = auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    const rejected = expect(login).rejects.toMatchObject({ code: 'session_expired' });
    await vi.waitFor(() => expect(sm.saveUnlocked).toHaveBeenCalledTimes(1));
    const lock = auth.lock();

    expect(events.filter((event) => event.phase === 'start').map((event) => event.reason))
      .toEqual(['login', 'lock']);
    releaseSave();
    await rejected;
    await lock;
    expect(await sm.getState()).toBe('locked');
  });

  it('keeps serialized lifecycle starts behind the prior settlement while invalidating immediately', async () => {
    const immediate: string[] = [];
    const serialized: string[] = [];
    const { auth, sm } = makeService(
      {},
      undefined,
      undefined,
      (event) => { immediate.push(`${event.phase}:${event.reason}`); },
      undefined,
      (event) => { serialized.push(`${event.phase}:${event.reason}`); },
    );
    await sm.saveUnlocked({
      email: 'active@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    const originalLock = sm.lock.bind(sm);
    let releaseLock!: () => void;
    const lockGate = new Promise<void>((resolve) => { releaseLock = resolve; });
    vi.spyOn(sm, 'lock').mockImplementationOnce(async () => {
      await lockGate;
      await originalLock();
    });

    const locking = auth.lock();
    await vi.waitFor(() => expect(serialized).toEqual(['start:lock']));
    const loggingOut = auth.logout();
    expect(immediate).toEqual(['start:lock', 'start:logout']);
    expect(serialized).toEqual(['start:lock']);

    releaseLock();
    await Promise.all([locking, loggingOut]);
    expect(serialized).toEqual([
      'start:lock',
      'settled:lock',
      'start:logout',
      'settled:logout',
    ]);
  });

  it('serializes overlapping AccountLeaseGate transitions without cross-kind begin failures', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const key = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'b@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey: key,
    });
    await sm.saveUnlocked({
      email: 'a@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey: key,
    });
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example', accountIdentity: 'a@example.com' });
    const sessionGate = new SessionGate('unlocked');
    const auth = new AuthService({
      api: mockApiClient({}),
      session: sm,
      sessionGate,
      accountGate,
      serverUrlProvider: async () => 'https://vault.example',
      onSessionTransition: sessionGate.handleTransition,
      onSerializedSessionTransition: accountLifecycleHook(accountGate, sm),
    });
    const originalSwitch = sm.switchAccount.bind(sm);
    let releaseSwitch!: () => void;
    const switchGate = new Promise<void>((resolve) => { releaseSwitch = resolve; });
    vi.spyOn(sm, 'switchAccount').mockImplementationOnce(async (email) => {
      await switchGate;
      await originalSwitch(email);
    });

    const switching = auth.switchAccount('b@example.com');
    await vi.waitFor(() => expect(() => accountGate.capture()).toThrow());
    const loggingOut = auth.logout();
    releaseSwitch();

    await expect(Promise.all([switching, loggingOut])).resolves.toBeDefined();
    expect((await sm.getPersistedAuth())?.email).toBe('a@example.com');
    expect(accountGate.capture()).toMatchObject({
      accountGeneration: 2,
      accountIdentity: 'a@example.com',
    });
  });

  it('recovers both gates on the next transition after a settlement state read fails', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const key = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'a@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey: key,
    });
    await sm.saveUnlocked({
      email: 'b@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey: key,
    });
    await sm.switchAccount('a@example.com');
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example', accountIdentity: 'a@example.com' });
    const sessionGate = new SessionGate('locked');
    const coordinator = new AccountTransitionCoordinator(accountGate, async () => {
      const active = await sm.getPersistedAuth();
      return {
        serverUrl: 'https://vault.example',
        ...(active ? { accountIdentity: active.email } : {}),
      };
    });
    const auth = new AuthService({
      api: mockApiClient({}),
      session: sm,
      sessionGate,
      accountGate,
      serverUrlProvider: async () => 'https://vault.example',
      onSessionTransition: sessionGate.handleTransition,
      onSerializedSessionTransition: coordinator.handle,
    });
    const getState = sm.getState.bind(sm);
    vi.spyOn(sm, 'getState')
      .mockRejectedValueOnce(new Error('transient storage read failure'))
      .mockImplementation(getState);

    await expect(auth.switchAccount('b@example.com')).rejects.toThrow('transient storage read failure');
    expect(() => accountGate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));
    expect(() => sessionGate.capture()).toThrowError(expect.objectContaining({ code: 'locked' }));

    await expect(auth.logout()).resolves.toBeUndefined();
    expect(accountGate.capture()).toMatchObject({ accountIdentity: 'a@example.com' });
    expect(() => sessionGate.capture()).toThrowError(expect.objectContaining({ code: 'locked' }));
  });

  it('publishes a new unlocked session generation after login succeeds', async () => {
    const events: SessionTransitionEvent[] = [];
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue(successfulLogin('access')),
    };
    const { auth } = makeService(api, undefined, undefined, (event) => { events.push(event); });

    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });

    expect(events).toEqual([
      { phase: 'start', transitionId: 1, reason: 'login', identityChanged: true },
      {
        phase: 'settled', transitionId: 1, reason: 'login', identityChanged: true,
        state: 'unlocked', succeeded: true,
      },
    ]);
  });

  it('registers with client-derived key material, then auto-logs-in', async () => {
    const startRegistration = vi.fn().mockResolvedValue({
      kind: 'inline' as const,
      emailVerificationToken: 'registration-token',
    });
    const register = vi.fn().mockResolvedValue(undefined);
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'success' as const,
      data: {
        access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
        Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
      },
    });
    const api: Partial<ApiClient> = {
      startRegistration,
      register,
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    };
    const { auth, sm } = makeService(api);
    await expect(auth.startRegistration({ email: KDF_VECTOR_600K.email, name: 'Tester' }))
      .resolves.toEqual({
        kind: 'registrationFinish',
        attemptId: 1,
        email: KDF_VECTOR_600K.email,
        expiresAt: 601_000,
      });
    await expect(auth.register({
      attemptId: 1,
      masterPassword: KDF_VECTOR_600K.password,
      masterPasswordHint: 'memorable phrase',
    }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(startRegistration).toHaveBeenCalledWith({
      email: KDF_VECTOR_600K.email,
      name: 'Tester',
    });
    expect(register).toHaveBeenCalledTimes(1);
    const payload = (register.mock.calls[0] as [{ masterPasswordHash: string; masterPasswordHint: string; key: string; keys: { publicKey: string }; name?: string; emailVerificationToken?: string }])[0];
    expect(payload.masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(payload.key.startsWith('2.')).toBe(true);
    expect(payload.keys.publicKey.length).toBeGreaterThan(0);
    expect(payload.name).toBe('Tester');
    expect(payload.emailVerificationToken).toBe('registration-token');
    expect(payload.masterPasswordHint).toBe('memorable phrase');
    expect(await sm.getState()).toBe('unlocked');
  });

  it('returns a secret-free check-email result without generating account keys', async () => {
    const startRegistration = vi.fn().mockResolvedValue({ kind: 'email_required' as const });
    const register = vi.fn(async () => undefined);
    const { auth } = makeService({ startRegistration, register });

    await expect(auth.startRegistration({ email: ' New@Example.com ', name: '  Ada  ' }))
      .resolves.toEqual({ kind: 'registrationEmailSent', email: 'new@example.com' });
    expect(startRegistration).toHaveBeenCalledWith({ email: 'new@example.com', name: 'Ada' });
    expect(register).not.toHaveBeenCalled();
  });

  it('cancels only the exact bound registration attempt', async () => {
    const register = vi.fn(async () => undefined);
    const { auth } = makeService({
      startRegistration: vi.fn(async () => ({
        kind: 'inline' as const,
        emailVerificationToken: 'registration-token',
      })),
      register,
    });
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    await expect(auth.cancelRegistration(started.attemptId + 1)).resolves.toBe(false);
    await expect(auth.cancelRegistration(started.attemptId)).resolves.toBe(true);
    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: '',
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(register).not.toHaveBeenCalled();
  });

  it('expires an in-memory registration token before generating account keys', async () => {
    let now = 1_000;
    const register = vi.fn(async () => undefined);
    const { auth } = makeService({
      startRegistration: vi.fn(async () => ({
        kind: 'inline' as const,
        emailVerificationToken: 'registration-token',
      })),
      register,
    }, undefined, undefined, undefined, undefined, undefined, () => now);
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;
    now = started.expiresAt;

    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: '',
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(register).not.toHaveBeenCalled();
  });

  it('rejects an 11-character registration password at the worker boundary', async () => {
    const startRegistration = vi.fn(async () => ({ kind: 'legacy' as const }));
    const register = vi.fn(async () => undefined);
    const prelogin = vi.fn();
    const { auth } = makeService({ startRegistration, register, prelogin });
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'a'.repeat(11),
      masterPasswordHint: '',
    })).rejects.toMatchObject({ code: 'denied' });

    expect(register).not.toHaveBeenCalled();
    expect(prelogin).not.toHaveBeenCalled();
  });

  it('allows an exact 12-character registration password through to the API boundary', async () => {
    const stopAtApi = new ApiHttpError(400, { message: 'rejected' });
    const register = vi.fn(async () => { throw stopAtApi; });
    const { auth } = makeService({
      startRegistration: vi.fn(async () => ({ kind: 'legacy' as const })),
      register,
    });
    const password = 'TwelveChars!';
    expect(password).toHaveLength(12);
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: password,
      masterPasswordHint: '',
    })).rejects.toBe(stopAtApi);

    expect(register).toHaveBeenCalledOnce();
  });

  it.each([
    ['same as password', 'TwelveChars!'],
    ['over 50 characters', 'x'.repeat(51)],
  ])('rejects a registration hint that is %s before generating a request', async (_label, hint) => {
    const register = vi.fn(async () => undefined);
    const { auth } = makeService({
      startRegistration: vi.fn(async () => ({ kind: 'legacy' as const })),
      register,
    });
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: hint,
    })).rejects.toThrow(/hint/i);
    expect(register).not.toHaveBeenCalled();
  });

  it('reports a completed account without auto-login when logout supersedes registration', async () => {
    let finishRegistration!: () => void;
    const register = vi.fn(() => new Promise<void>((resolve) => { finishRegistration = resolve; }));
    const prelogin = vi.fn();
    const { auth, sm } = makeService({
      startRegistration: vi.fn(async () => ({
        kind: 'inline' as const,
        emailVerificationToken: 'registration-token',
      })),
      register,
      prelogin,
    });
    const started = await auth.startRegistration({ email: KDF_VECTOR_600K.email });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    const registration = auth.register({
      attemptId: started.attemptId,
      masterPassword: KDF_VECTOR_600K.password,
      masterPasswordHint: '',
    });
    await vi.waitFor(() => expect(register).toHaveBeenCalledTimes(1));
    await auth.logout();
    finishRegistration();

    await expect(registration).resolves.toEqual({
      kind: 'registrationComplete',
      email: KDF_VECTOR_600K.email,
    });
    expect(prelogin).not.toHaveBeenCalled();
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('does not expose a retryable registration token after an ambiguous finish failure', async () => {
    const register = vi.fn(async () => { throw new Error('network disconnected'); });
    const { auth } = makeService({
      startRegistration: vi.fn(async () => ({
        kind: 'inline' as const,
        emailVerificationToken: 'registration-token',
      })),
      register,
    });
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: '',
    })).rejects.toMatchObject({ code: 'outcome_unknown' });
    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: '',
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(register).toHaveBeenCalledOnce();
  });

  it('returns registrationComplete when post-registration auto-login fails', async () => {
    const { auth } = makeService({
      startRegistration: vi.fn(async () => ({ kind: 'legacy' as const })),
      register: vi.fn(async () => undefined),
      prelogin: vi.fn(async () => { throw new Error('login unavailable'); }),
    });
    const started = await auth.startRegistration({ email: 'new@example.com' });
    expect(started.kind).toBe('registrationFinish');
    if (started.kind !== 'registrationFinish') return;

    await expect(auth.register({
      attemptId: started.attemptId,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: '',
    })).resolves.toEqual({ kind: 'registrationComplete', email: 'new@example.com' });
  });

  it('binds new-device verification to the password attempt and submits the official OTP field', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockResolvedValueOnce(successfulLogin('verified-access'));
    const sendNewDeviceVerificationOtp = vi.fn(async () => undefined);
    const { auth, sm } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
      sendNewDeviceVerificationOtp,
    });

    const challenge = await auth.login({
      email: `  ${KDF_VECTOR_600K.email.toUpperCase()}  `,
      masterPassword: KDF_VECTOR_600K.password,
    });
    expect(challenge).toEqual({
      kind: 'newDeviceVerification',
      attemptId: 1,
      expiresAt: 301_000,
    });
    expect(JSON.stringify(challenge)).not.toContain(KDF_VECTOR_600K.password);
    expect(JSON.stringify(challenge)).not.toContain(KDF_VECTOR_600K.masterPasswordHashB64);
    expect(await sm.getState()).toBe('loggedOut');

    await auth.sendNewDeviceVerificationOtp({ attemptId: 1 });
    expect(sendNewDeviceVerificationOtp).toHaveBeenCalledWith({
      email: KDF_VECTOR_600K.email,
      masterPasswordHash: KDF_VECTOR_600K.masterPasswordHashB64,
    });
    await expect(auth.submitNewDeviceVerification({ attemptId: 1, code: ' 123456 ' }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin.mock.calls[1]![0]).toEqual({
      email: KDF_VECTOR_600K.email,
      masterPasswordHash: KDF_VECTOR_600K.masterPasswordHashB64,
      newDeviceOtp: '123456',
    });
    expect(await sm.getState()).toBe('unlocked');
  });

  it('keeps a rejected OTP retryable without exposing the server response', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockRejectedValueOnce(new ApiHttpError(400, {
        error_description: 'Invalid New Device OTP',
        privateDetail: 'must-not-leak',
      }))
      .mockResolvedValueOnce(successfulLogin('retried-verified-access'));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
    });
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'newDeviceVerification') throw new Error('Expected device verification');

    await expect(auth.submitNewDeviceVerification({
      attemptId: challenge.attemptId,
      code: '111111',
    })).rejects.toMatchObject({
      code: 'error',
      message: 'The verification code is invalid or expired.',
    });
    await expect(auth.submitNewDeviceVerification({
      attemptId: challenge.attemptId,
      code: '222222',
    })).resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin).toHaveBeenCalledTimes(3);
  });

  it('does not mislabel an unrelated HTTP 400 as an invalid OTP', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockRejectedValueOnce(new ApiHttpError(400, {
        error_description: 'Account access denied',
        privateDetail: 'must-not-leak',
      }));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
    });
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'newDeviceVerification') throw new Error('Expected device verification');

    await expect(auth.submitNewDeviceVerification({
      attemptId: challenge.attemptId,
      code: '111111',
    })).rejects.toMatchObject({
      code: 'error',
      message: 'Device verification was rejected by the server.',
    });
  });

  it('preserves newDeviceOtp when successful device verification advances to two-factor login', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf-token' })
      .mockResolvedValueOnce(successfulLogin('ndv-two-factor-access'));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
    });
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'newDeviceVerification') throw new Error('Expected device verification');

    await expect(auth.submitNewDeviceVerification({
      attemptId: challenge.attemptId,
      code: '654321',
    })).resolves.toEqual({ kind: 'twoFactor', providers: [0], token: 'tf-token' });
    await expect(auth.submitTwoFactor({ provider: 0, code: '112233' }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin.mock.calls[2]![0]).toMatchObject({
      newDeviceOtp: '654321',
      twoFactorProvider: 0,
      twoFactorToken: '112233',
    });
  });

  it('expires, supersedes, and explicitly cancels only the exact new-device attempt', async () => {
    let now = 1_000;
    const passwordLogin = vi.fn().mockResolvedValue(newDeviceVerificationRequired());
    const { auth } = makeService(
      {
        prelogin: vi.fn().mockResolvedValue({
          kdf: 0 as const,
          kdfIterations: KDF_VECTOR_600K.iterations,
        }),
        passwordLogin,
      },
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      () => now,
    );
    const first = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (first.kind !== 'newDeviceVerification') throw new Error('Expected device verification');
    await expect(auth.submitNewDeviceVerification({ attemptId: first.attemptId + 1, code: '123456' }))
      .rejects.toMatchObject({ code: 'session_expired' });
    now = first.expiresAt;
    await expect(auth.sendNewDeviceVerificationOtp({ attemptId: first.attemptId }))
      .rejects.toMatchObject({ code: 'session_expired' });
    expect(passwordLogin).toHaveBeenCalledOnce();

    now = 2_000;
    const second = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (second.kind !== 'newDeviceVerification') throw new Error('Expected device verification');
    await expect(auth.cancelNewDeviceVerification({ attemptId: first.attemptId })).resolves.toBe(false);
    await expect(auth.cancelNewDeviceVerification({ attemptId: second.attemptId })).resolves.toBe(true);
    await expect(auth.submitNewDeviceVerification({ attemptId: second.attemptId, code: '123456' }))
      .rejects.toMatchObject({ code: 'session_expired' });
  });

  it('allows only one in-flight new-device verification action', async () => {
    let resolveSubmission!: (result: ReturnType<typeof successfulLogin>) => void;
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce(newDeviceVerificationRequired())
      .mockImplementationOnce(() => new Promise<ReturnType<typeof successfulLogin>>((resolve) => {
        resolveSubmission = resolve;
      }));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
      sendNewDeviceVerificationOtp: vi.fn(async () => undefined),
    });
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'newDeviceVerification') throw new Error('Expected device verification');

    const submission = auth.submitNewDeviceVerification({
      attemptId: challenge.attemptId,
      code: '123456',
    });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(2));
    await expect(auth.sendNewDeviceVerificationOtp({ attemptId: challenge.attemptId }))
      .rejects.toMatchObject({ code: 'session_expired' });
    resolveSubmission(successfulLogin('single-flight-access'));
    await expect(submission).resolves.toEqual({ kind: 'unlocked' });
  });

  it('keeps pending login in memory and filters provider 7 without valid metadata', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0, 1, 3, 7], token: 'tf' }),
    };
    const { auth, sm } = makeService(api);
    // Code providers pass through; provider 7 is unavailable until its challenge is validated.
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1, 3], token: 'tf' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('submitTwoFactor forwards a supported direct-code provider and trims the code', async () => {
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

  it.each([2, 6])('submitTwoFactor rejects interactive Duo provider %s without consuming the challenge', async (provider) => {
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'twoFactor' as const,
      providers: [0, provider],
      token: 'tf',
    });
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({
        kdf: 0 as const,
        kdfIterations: KDF_VECTOR_600K.iterations,
      }),
      passwordLogin,
    });
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });

    await expect(auth.submitTwoFactor({ provider, code: 'not-a-duo-callback' }))
      .rejects.toMatchObject({ code: 'denied' });
    expect(passwordLogin).toHaveBeenCalledTimes(1);

    await expect(auth.submitTwoFactor({ provider: 0, code: '123456' }))
      .resolves.toMatchObject({ kind: 'twoFactor' });
    expect(passwordLogin).toHaveBeenCalledTimes(2);
  });

  it('allows only one in-flight submission to consume a pending two-factor challenge', async () => {
    let resolveSubmission!: (result: ReturnType<typeof successfulLogin>) => void;
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
      .mockImplementationOnce(() => new Promise<ReturnType<typeof successfulLogin>>((resolve) => {
        resolveSubmission = resolve;
      }));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    });
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });

    const first = auth.submitTwoFactor({ provider: 0, code: '111111' });
    await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledTimes(2));
    await expect(auth.submitTwoFactor({ provider: 0, code: '222222' }))
      .rejects.toMatchObject({ code: 'session_expired' });
    resolveSubmission(successfulLogin('two-factor-access'));

    await expect(first).resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin).toHaveBeenCalledTimes(2);
  });

  it('keeps an ordinary code challenge available after a rejected verification request', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
      .mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }))
      .mockResolvedValueOnce(successfulLogin('retried-two-factor-access'));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    });
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });

    await expect(auth.submitTwoFactor({ provider: 0, code: '111111' }))
      .rejects.toBeInstanceOf(ApiHttpError);
    await expect(auth.submitTwoFactor({ provider: 0, code: '222222' }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin.mock.calls[2]![0]).toMatchObject({
      twoFactorProvider: 0,
      twoFactorToken: '222222',
    });
  });

  it('does not cancel a pending challenge when a new activation cannot capture its server', async () => {
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example' });
    const captureServer = accountGate.captureServer.bind(accountGate);
    let captures = 0;
    vi.spyOn(accountGate, 'captureServer').mockImplementation(() => {
      if (++captures === 2) throw new AppError('session_expired', 'server transition in progress');
      return captureServer();
    });
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
      .mockResolvedValueOnce(successfulLogin('completed-access'));
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const auth = new AuthService({
      api: mockApiClient({
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      }),
      session: sm,
      sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
      accountGate,
      serverUrlProvider: async () => 'https://vault.example',
    });
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });

    await expect(auth.login({ email: 'other@example.com', masterPassword: 'unused' }))
      .rejects.toMatchObject({ code: 'session_expired' });
    await expect(auth.submitTwoFactor({ provider: 0, code: '111111' }))
      .resolves.toEqual({ kind: 'unlocked' });
  });

  it('does not send a pending old-server 2FA request to a newly configured server', async () => {
    const OLD_SERVER = 'https://old.example';
    const NEW_SERVER = 'https://new.example';
    let currentServer = OLD_SERVER;
    const serverUrlProvider = vi.fn(async () => currentServer);
    let resolveSubmission!: (response: Response) => void;
    const fetchFn = vi.fn(async (url: string | URL | Request) => {
      const value = String(url);
      if (value.includes('/identity/accounts/prelogin')) {
        return new Response(JSON.stringify({
          kdf: 0,
          kdfIterations: KDF_VECTOR_600K.iterations,
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (fetchFn.mock.calls.length >= 3) {
        return new Promise<Response>((resolve) => { resolveSubmission = resolve; });
      }
      return new Response(JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Two factor required',
        TwoFactorProviders: [0],
        TwoFactorToken: 'pending-token',
      }), { status: 400, headers: { 'content-type': 'application/json' } });
    });
    const localStore = createMemoryStore();
    const sm = new SessionManager({ localStore, sessionStore: createMemoryStore() });
    const sessionGate: SessionLeaseGate = { capture: () => ({ generation: 0 }), assert: () => {} };
    const api = new ApiClient({ serverUrlProvider, fetchFn, localStore });
    const auth = new AuthService({ api, session: sm, sessionGate, serverUrlProvider, now: () => 1000 });
    await expect(auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }))
      .resolves.toMatchObject({ kind: 'twoFactor' });
    expect(fetchFn).toHaveBeenCalledTimes(2);

    const submission = auth.submitTwoFactor({ provider: 0, code: '123456' });
    const rejected = expect(submission).rejects.toMatchObject({ code: 'session_expired' });
    await vi.waitFor(() => expect(fetchFn).toHaveBeenCalledTimes(3));
    await auth.resetForServerChange(async () => { currentServer = NEW_SERVER; });
    resolveSubmission(new Response(JSON.stringify({
      error: 'invalid_grant',
      error_description: 'Two factor required',
      TwoFactorProviders: [0],
      TwoFactorToken: 'late-token',
    }), { status: 400, headers: { 'content-type': 'application/json' } }));

    await rejected;
    expect(serverUrlProvider).toHaveBeenCalledOnce();
    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(fetchFn.mock.calls.every(([url]) => String(url).startsWith(OLD_SERVER))).toBe(true);
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
    ).rejects.toThrow(/PBKDF2 iteration count/);
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
    ).rejects.toThrow(/PBKDF2 iteration count/);
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

  it('rejects a token response that changes PBKDF2 to Argon2id after prelogin', async () => {
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
          KdfIterations: 4,
          KdfMemory: 32,
          KdfParallelism: 2,
        },
      }),
    };
    const { auth } = makeService(api);
    await expect(
      auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password }),
    ).rejects.toThrow(/changed KDF settings/);
  });

  it('logs in to an Argon2id account and persists every KDF parameter', async () => {
    const masterKey = await deriveMasterKey(
      ARGON2_KDF_VECTOR.password,
      ARGON2_KDF_VECTOR.email,
      ARGON2_KDF_VECTOR.config,
    );
    const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    const protectedKey = await encryptToBytes(
      serializeSymmetricKey(userKey),
      await stretchMasterKey(masterKey),
    );
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue(ARGON2_KDF_VECTOR.config),
      passwordLogin: vi.fn().mockResolvedValue({
        kind: 'success' as const,
        data: {
          access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
          Key: protectedKey,
          Kdf: 1 as const,
          KdfIterations: 4,
          KdfMemory: 32,
          KdfParallelism: 2,
        },
      }),
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({
      email: ARGON2_KDF_VECTOR.email,
      masterPassword: ARGON2_KDF_VECTOR.password,
    })).resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getPersistedAuth()).toMatchObject(ARGON2_KDF_VECTOR.config);
  });

  it('unlock derives key from persisted auth without calling prelogin', async () => {
    const events: SessionTransitionEvent[] = [];
    const { auth, sm } = makeService({}, undefined, undefined, (event) => { events.push(event); });
    await sm.saveUnlocked({
      email: KDF_VECTOR_600K.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      kdf: 0,
      kdfIterations: KDF_VECTOR_600K.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await sm.lock();
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let transientUserKey: SymmetricKey | undefined;
    let transientPrivateKey: Uint8Array | undefined;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      transientUserKey = input.userKey;
      transientPrivateKey = input.privateKey;
      await saveUnlocked(input);
    });
    await expect(auth.unlock(KDF_VECTOR_600K.password)).resolves.toBeUndefined();
    expect(await sm.getState()).toBe('unlocked');
    expect(events.map((event) => [event.phase, event.reason])).toEqual([
      ['start', 'unlock'],
      ['settled', 'unlock'],
    ]);
    expect(transientUserKey?.encKey).toEqual(new Uint8Array(32));
    expect(transientUserKey?.macKey).toEqual(new Uint8Array(32));
    expect(transientPrivateKey?.every((value) => value === 0)).toBe(true);
    expect(await sm.loadPrivateKey()).toBeDefined();
  });

  it('still unlocks an existing account whose master password is shorter than the new default', async () => {
    const password = 'old-pass';
    const email = 'legacy@example.com';
    const kdf = { kdf: 0 as const, kdfIterations: 5_000 };
    const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    const rawUserKey = serializeSymmetricKey(userKey);
    const masterKey = await deriveMasterKey(password, email, kdf);
    const stretched = await stretchMasterKey(masterKey);
    let protectedKey: string;
    try {
      protectedKey = await encryptToBytes(rawUserKey, stretched);
    } finally {
      rawUserKey.fill(0);
      masterKey.fill(0);
      stretched.encKey.fill(0);
      stretched.macKey.fill(0);
    }
    const { auth, sm } = makeService({});
    await sm.saveUnlocked({
      email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 999_999,
      protectedKey,
      ...kdf,
      userKey,
    });
    await sm.lock();

    await expect(auth.unlock(password)).resolves.toBeUndefined();
    expect(await sm.getState()).toBe('unlocked');
  });

  it('rolls back a master-password unlock superseded during its commit before settlement', async () => {
    const sm = new SessionManager({
      localStore: createMemoryStore(),
      sessionStore: createMemoryStore(),
    });
    await sm.saveUnlocked({
      email: KDF_VECTOR_600K.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1_000,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR_600K.iterations,
      userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
    });
    await sm.lock();
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({
      serverUrl: 'https://vault.example',
      accountIdentity: KDF_VECTOR_600K.email,
    });
    const sessionGate = new SessionGate('locked');
    const transitionEvents: SessionTransitionEvent[] = [];
    const auth = new AuthService({
      api: mockApiClient({}),
      session: sm,
      sessionGate,
      accountGate,
      serverUrlProvider: async () => 'https://vault.example',
      now: () => 1_000,
      onSessionTransition: (event) => {
        transitionEvents.push(event);
        sessionGate.handleTransition(event);
      },
      onSerializedSessionTransition: accountLifecycleHook(accountGate, sm),
    });
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
    let saveCommitted = false;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      saveCommitted = true;
      await saveGate;
    });

    const unlocking = auth.unlock(KDF_VECTOR_600K.password);
    const rejected = expect(unlocking).rejects.toMatchObject({ code: 'session_expired' });
    await vi.waitFor(() => expect(saveCommitted).toBe(true));
    const locking = auth.lock();
    releaseSave();

    await rejected;
    await expect(locking).resolves.toBeUndefined();
    expect(transitionEvents.find(
      (event) => event.phase === 'settled' && event.reason === 'unlock',
    )).toMatchObject({ state: 'locked', succeeded: false });
    expect(await sm.getState()).toBe('locked');
    expect(() => sessionGate.capture()).toThrow();
    expect(accountGate.capture()).toMatchObject({
      accountIdentity: KDF_VECTOR_600K.email,
    });
  });

  describe('verifyMasterPassword (reprompt)', () => {
    const persist = async (sm: SessionManager) => sm.saveUnlocked({
      email: KDF_VECTOR_600K.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR_600K.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    it('returns true for the correct master password without changing lock state', async () => {
      const { auth, sm } = makeService({});
      await persist(sm);
      await expect(auth.verifyMasterPassword(KDF_VECTOR_600K.password)).resolves.toBe(true);
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
      await expect(auth.verifyMasterPassword(KDF_VECTOR_600K.password)).resolves.toBe(false);
    });

    it('does not return a true verification from a superseded account session', async () => {
      const gate = new SessionGate('unlocked');
      const { auth, sm } = makeService({}, undefined, undefined, gate.handleTransition, gate);
      await sm.saveUnlocked({
        email: 'other@example.com', accessToken: 'other', refreshToken: 'other-refresh', expiresAt: 999999,
        protectedKey: 'other-protected-key', kdf: 0, kdfIterations: 5000,
        userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
      });
      await persist(sm);
      const loadUserKey = sm.loadUserKey.bind(sm);
      let releaseRead!: () => void;
      const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
      vi.spyOn(sm, 'loadUserKey').mockImplementationOnce(async () => {
        await readGate;
        return loadUserKey();
      });

      const verifying = auth.verifyMasterPassword(KDF_VECTOR_600K.password);
      await vi.waitFor(() => expect(sm.loadUserKey).toHaveBeenCalledTimes(1));
      await auth.switchAccount('other@example.com');
      releaseRead();

      await expect(verifying).resolves.toBe(false);
    });
  });

  describe('changeMasterPassword / changeKdf', () => {
    const persist600k = (sm: SessionManager) => sm.saveUnlocked({
      email: KDF_VECTOR_600K.email,
      accessToken: 'access', refreshToken: 'refresh', expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations,
      userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
    });
    const keyHex = (k: { encKey: Uint8Array; macKey: Uint8Array }) => bytesToHex(new Uint8Array([...k.encKey, ...k.macKey]));
    const persistOtherAccount = (sm: SessionManager) => sm.saveUnlocked({
      email: 'other@example.com',
      accessToken: 'other-access',
      refreshToken: 'other-refresh',
      expiresAt: 999999,
      protectedKey: 'other-protected-key',
      kdf: 0,
      kdfIterations: 5000,
      userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
    });

    it('re-wraps the UserKey for the server, then removes the changed account locally', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const { auth, sm, passwordChangePending } = makeService({ changePassword });
      await persist600k(sm);
      await auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master', 'phrase hint');
      const [accessToken, body] = changePassword.mock.calls[0]!;
      expect(accessToken).toBe('access');
      expect(body.masterPasswordHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64); // proves the current pw
      expect(body.masterPasswordHint).toBe('phrase hint');
      // The new protectedKey unwraps the SAME UserKey under the new password (vault is not re-encrypted).
      const newStretched = await stretchMasterKey(await deriveMasterKey(
        'a-brand-new-master',
        KDF_VECTOR_600K.email,
        { kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations },
      ));
      expect(keyHex(await unwrapSymmetricKey(body.key, newStretched))).toBe(USER_KEY_VECTOR.userKeyHex);
      expect(passwordChangePending.markBeforeChange).toHaveBeenCalledBefore(changePassword);
      expect(passwordChangePending.clear).toHaveBeenCalledOnce();
      expect(await sm.getState()).toBe('loggedOut');
      expect(await sm.listAccounts()).toEqual([]);
    });

    it('clears the WAL and keeps the session usable after a definite 4xx rejection', async () => {
      const rejection = new ApiHttpError(400, { error: 'invalid' });
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {
        throw rejection;
      });
      const { auth, sm, passwordChangePending } = makeService({ changePassword });
      await persist600k(sm);

      await expect(auth.changeMasterPassword(
        KDF_VECTOR_600K.password,
        'a-brand-new-master',
        '',
      )).rejects.toBe(rejection);
      expect(passwordChangePending.markBeforeChange).toHaveBeenCalledBefore(changePassword);
      expect(passwordChangePending.clear).toHaveBeenCalledOnce();
      expect(await sm.getState()).toBe('unlocked');
      expect((await sm.getPersistedAuth())?.protectedKey).toBe(USER_KEY_VECTOR_600K.akey);
    });

    it('preserves conservative startup recovery when WAL clearing fails after a definite rejection', async () => {
      const rejection = new ApiHttpError(400, { error: 'invalid' });
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => { throw rejection; });
      const { auth, sm, passwordChangePending } = makeService({ changePassword });
      const clearFailure = new Error('marker unavailable');
      passwordChangePending.clear.mockRejectedValueOnce(clearFailure);
      await persist600k(sm);

      await expect(auth.changeMasterPassword(
        KDF_VECTOR_600K.password,
        'a-brand-new-master',
        '',
      )).rejects.toBe(clearFailure);

      expect(changePassword).toHaveBeenCalledOnce();
      expect(passwordChangePending.clear).toHaveBeenCalledOnce();
      expect(await sm.getState()).toBe('unlocked');
    });

    it.each([
      ['network failure', new Error('connection lost')],
      ['HTTP 500', new ApiHttpError(500, {})],
      ['HTTP 408', new ApiHttpError(408, {})],
      ['HTTP 429', new ApiHttpError(429, {})],
    ])('logs out with outcome_unknown after %s', async (_label, failure) => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {
        throw failure;
      });
      const { auth, sm, passwordChangePending } = makeService({ changePassword });
      await persist600k(sm);

      await expect(auth.changeMasterPassword(
        KDF_VECTOR_600K.password,
        'a-brand-new-master',
        '',
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(passwordChangePending.markBeforeChange).toHaveBeenCalledBefore(changePassword);
      expect(passwordChangePending.clear).toHaveBeenCalledOnce();
      expect(await sm.getState()).toBe('loggedOut');
    });

    it('stays fail-closed with the WAL retained when local account retirement repeatedly fails', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const gate = new SessionGate('unlocked');
      const { auth, sm, passwordChangePending } = makeService(
        { changePassword }, undefined, undefined, gate.handleTransition, gate,
      );
      await persist600k(sm);
      vi.spyOn(sm, 'logout').mockRejectedValue(new Error('local retirement failed'));

      await expect(auth.changeMasterPassword(
        KDF_VECTOR_600K.password,
        'a-brand-new-master',
        '',
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(passwordChangePending.markBeforeChange).toHaveBeenCalledBefore(changePassword);
      expect(passwordChangePending.clear).not.toHaveBeenCalled();
      expect(await auth.getState()).toBe('loggedOut');
      expect(await sm.getState()).toBe('locked');
      expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'locked' }));
      await expect(auth.unlock(KDF_VECTOR_600K.password)).rejects.toMatchObject({
        code: 'outcome_unknown',
      });
    });

    it('rejects a wrong current password and makes no server call', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const { auth, sm } = makeService({ changePassword });
      await persist600k(sm);
      await expect(auth.changeMasterPassword('wrong-current', 'whatever-new', '')).rejects.toThrow(/incorrect/i);
      expect(changePassword).not.toHaveBeenCalled();
    });

    it.each([
      ['same as password', 'a-brand-new-master'],
      ['over 50 characters', 'x'.repeat(51)],
    ])('rejects a master-password hint that is %s before the WAL or server', async (_label, hint) => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const { auth, sm, passwordChangePending } = makeService({ changePassword });
      await persist600k(sm);

      await expect(auth.changeMasterPassword(
        KDF_VECTOR_600K.password,
        'a-brand-new-master',
        hint,
      )).rejects.toThrow(/hint/i);
      expect(passwordChangePending.markBeforeChange).not.toHaveBeenCalled();
      expect(changePassword).not.toHaveBeenCalled();
      expect(await sm.getState()).toBe('unlocked');
    });

    it('never retires account B when a switch starts during account A password change', async () => {
      let releaseRemote!: () => void;
      const remoteGate = new Promise<void>((resolve) => { releaseRemote = resolve; });
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => { await remoteGate; });
      const gate = new SessionGate('unlocked');
      const { auth, sm } = makeService(
        { changePassword }, undefined, undefined, gate.handleTransition, gate,
      );
      await persistOtherAccount(sm);
      await persist600k(sm);

      const changing = auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master', '');
      await vi.waitFor(() => expect(changePassword).toHaveBeenCalledTimes(1));
      const switching = auth.switchAccount('other@example.com');
      releaseRemote();

      await Promise.all([changing, switching]);
      expect(await sm.getPersistedAuth()).toMatchObject({
        email: 'other@example.com',
        protectedKey: 'other-protected-key',
        kdfIterations: 5000,
      });
      expect(await sm.listAccounts()).toEqual([{
        email: 'other@example.com',
        active: true,
      }]);
    });

    it('guards the password-change fetch after deferred server URL resolution', async () => {
      let resolveServerUrl!: (serverUrl: string) => void;
      const serverUrlProvider = vi.fn(() => new Promise<string>((resolve) => { resolveServerUrl = resolve; }));
      const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
      const localStore = createMemoryStore();
      const sm = new SessionManager({ localStore, sessionStore: createMemoryStore() });
      await persist600k(sm);
      const sessionGate = new SessionGate('unlocked');
      const api = new ApiClient({ serverUrlProvider, fetchFn, localStore });
      const auth = new AuthService({
        api,
        session: sm,
        sessionGate,
        passwordChangePending: {
          markBeforeChange: vi.fn(async () => ({})),
          clear: vi.fn(async () => {}),
        },
        serverUrlProvider,
        onSessionTransition: sessionGate.handleTransition,
        now: () => 1000,
      });

      const changing = auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master', '');
      const rejected = expect(changing).rejects.toMatchObject({ code: 'session_expired' });
      await vi.waitFor(() => expect(serverUrlProvider).toHaveBeenCalledTimes(1));
      const reset = auth.resetForServerChange();
      resolveServerUrl('https://new.example');

      await rejected;
      await reset;
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it('activates a remaining account in locked state after a successful password change', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const gate = new SessionGate('unlocked');
      const { auth, sm } = makeService(
        { changePassword }, undefined, undefined, gate.handleTransition, gate,
      );
      await persistOtherAccount(sm);
      await persist600k(sm);

      await auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master', '');

      expect(await sm.getState()).toBe('locked');
      expect(await sm.getPersistedAuth()).toMatchObject({
        email: 'other@example.com',
        protectedKey: 'other-protected-key',
        kdfIterations: 5000,
      });
      expect(await sm.listAccounts()).toEqual([{ email: 'other@example.com', active: true }]);
    });

    it('changeKdf re-wraps under the new PBKDF2 count and persists it', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {});
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      const newIters = 800_000;
      const newKdf = { kdf: 0, kdfIterations: newIters } as const;
      await auth.changeKdf(KDF_VECTOR_600K.password, newKdf);
      const [, body] = changeKdf.mock.calls[0]!;
      expect(body.unlockData.kdf).toEqual({
        kdfType: 0,
        iterations: newIters,
        memory: null,
        parallelism: null,
      });
      const newStretched = await stretchMasterKey(await deriveMasterKey(
        KDF_VECTOR_600K.password,
        KDF_VECTOR_600K.email,
        newKdf,
      ));
      expect(keyHex(await unwrapSymmetricKey(body.unlockData.masterKeyWrappedUserKey, newStretched)))
        .toBe(USER_KEY_VECTOR.userKeyHex);
      expect((await sm.getPersistedAuth())!.kdfIterations).toBe(newIters);
    });

    it('never commits account A KDF material after switching to account B', async () => {
      let releaseRemote!: () => void;
      const remoteGate = new Promise<void>((resolve) => { releaseRemote = resolve; });
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => { await remoteGate; });
      const gate = new SessionGate('unlocked');
      const { auth, sm } = makeService({ changeKdf }, undefined, undefined, gate.handleTransition, gate);
      await persistOtherAccount(sm);
      await persist600k(sm);

      const changing = auth.changeKdf(
        KDF_VECTOR_600K.password,
        { kdf: 0, kdfIterations: 800_000 },
      );
      const rejected = expect(changing).rejects.toMatchObject({ code: 'session_expired' });
      await vi.waitFor(() => expect(changeKdf).toHaveBeenCalledTimes(1));
      const switching = auth.switchAccount('other@example.com');
      releaseRemote();

      await rejected;
      await switching;
      expect(await sm.getPersistedAuth()).toMatchObject({
        email: 'other@example.com',
        protectedKey: 'other-protected-key',
        kdfIterations: 5000,
      });
      const changedKey = changeKdf.mock.calls[0]![1].unlockData.masterKeyWrappedUserKey;
      await sm.switchAccount(KDF_VECTOR_600K.email);
      expect(await sm.getPersistedAuth()).toMatchObject({
        protectedKey: changedKey,
        kdfIterations: 800_000,
      });
    });

    it('does not refresh or resurrect an account after password-change retirement', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const refresh = vi.fn<ApiClient['refresh']>(async () => ({
        access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3600, token_type: 'Bearer',
      }));
      const { auth, sm } = makeService({ changePassword, refresh });
      await persist600k(sm);

      await auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master', '');
      await auth.refreshIfNeeded(5000);

      expect(refresh).not.toHaveBeenCalled();
      expect(await sm.getPersistedAuth()).toBeUndefined();
    });

    it('removes the account after an already-started token refresh settles', async () => {
      const changePassword = vi.fn<ApiClient['changePassword']>(async () => {});
      const refresh = vi.fn<ApiClient['refresh']>(async () => ({
        access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3600, token_type: 'Bearer',
      }));
      const { auth, sm } = makeService({ changePassword, refresh });
      await persist600k(sm);
      const saveTokens = sm.commitTokenRefresh.bind(sm);
      let releaseTokens!: () => void;
      const tokenGate = new Promise<void>((resolve) => { releaseTokens = resolve; });
      vi.spyOn(sm, 'commitTokenRefresh').mockImplementationOnce(async (...args) => {
        await tokenGate;
        return saveTokens(...args);
      });

      const refreshing = auth.refreshIfNeeded(5000);
      await vi.waitFor(() => expect(sm.commitTokenRefresh).toHaveBeenCalledTimes(1));
      const changing = auth.changeMasterPassword(KDF_VECTOR_600K.password, 'a-brand-new-master', '');
      releaseTokens();
      await Promise.all([refreshing, changing]);

      expect(refresh).toHaveBeenCalledOnce();
      expect(changePassword).toHaveBeenCalledOnce();
      expect(await sm.getPersistedAuth()).toBeUndefined();
    });

    it('changeKdf refuses PBKDF2 settings below the current 600000 floor', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {});
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      await expect(auth.changeKdf(
        KDF_VECTOR_600K.password,
        { kdf: 0, kdfIterations: 5_000 },
      )).rejects.toThrow(/600000/);
      expect(changeKdf).not.toHaveBeenCalled();
    });

    it('changes from PBKDF2 to Argon2id, persists all settings, and clears PIN unlock', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {});
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      await auth.setPin('1357');
      expect(await sm.getPinProtectedUserKey()).toBeDefined();

      const argon = { kdf: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 1 } as const;
      await auth.changeKdf(KDF_VECTOR_600K.password, argon);

      const [, body] = changeKdf.mock.calls[0]!;
      const apiKdf = { kdfType: 1, iterations: 2, memory: 16, parallelism: 1 };
      expect(body).toMatchObject({
        kdf: 1,
        kdfIterations: 2,
        kdfMemory: 16,
        kdfParallelism: 1,
        key: body.unlockData.masterKeyWrappedUserKey,
        newMasterPasswordHash: body.authenticationData.masterPasswordAuthenticationHash,
      });
      expect(body.authenticationData).toMatchObject({
        salt: KDF_VECTOR_600K.email,
        kdf: apiKdf,
      });
      expect(body.unlockData).toMatchObject({
        salt: KDF_VECTOR_600K.email,
        kdf: apiKdf,
      });
      expect(body.authenticationData.kdf).toEqual(body.unlockData.kdf);
      expect(await sm.getPersistedAuth()).toMatchObject(argon);
      expect(await sm.getPinProtectedUserKey()).toBeUndefined();
      const stretched = await stretchMasterKey(await deriveMasterKey(
        KDF_VECTOR_600K.password,
        KDF_VECTOR_600K.email,
        argon,
      ));
      expect(keyHex(await unwrapSymmetricKey(body.unlockData.masterKeyWrappedUserKey, stretched)))
        .toBe(USER_KEY_VECTOR.userKeyHex);
    });

    it('disables PIN before sending an irreversible KDF change request', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {
        throw new Error('network unavailable');
      });
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      await auth.setPin('safe-pin');

      await expect(auth.changeKdf(
        KDF_VECTOR_600K.password,
        { kdf: 0, kdfIterations: 800_000 },
      )).rejects.toThrow('network unavailable');
      expect(changeKdf).toHaveBeenCalledOnce();
      expect(await sm.getPinProtectedUserKey()).toBeUndefined();
      expect(await auth.isPinEnabled()).toBe(false);
    });

    it('keeps PIN configured when current-password verification rejects before KDF revocation', async () => {
      const changeKdf = vi.fn<ApiClient['changeKdf']>(async () => {});
      const { auth, sm } = makeService({ changeKdf });
      await persist600k(sm);
      await auth.setPin('safe-pin');

      await expect(auth.changeKdf(
        'wrong-master-password',
        { kdf: 0, kdfIterations: 800_000 },
      )).rejects.toThrow('Current master password is incorrect');

      expect(changeKdf).not.toHaveBeenCalled();
      expect(await sm.getPinProtectedUserKey()).toBeDefined();
      expect(await auth.isPinEnabled()).toBe(true);
    });
  });

  describe('key rotation safety closure', () => {
    it('marks immediately before POST, resets every account, clears cache, then clears the marker', async () => {
      const harness = await makeRotationHarness();
      const mark = vi.spyOn(harness.pending, 'markBeforeRotation');
      const reset = vi.spyOn(harness.sm, 'resetAllAccounts');
      const clear = vi.spyOn(harness.pending, 'clear');
      const post = vi.mocked(harness.api.rotateAccountKey!);

      await expect(harness.auth.rotateAccountKey(ROTATION_PASSWORD)).resolves.toBeUndefined();

      expect(mark).toHaveBeenCalledWith({ serverUrl: ROTATION_SERVER, accountId: ROTATION_EMAIL });
      expect(mark.mock.invocationCallOrder[0]).toBeLessThan(post.mock.invocationCallOrder[0]!);
      expect(post.mock.invocationCallOrder[0]).toBeLessThan(reset.mock.invocationCallOrder[0]!);
      expect(reset.mock.invocationCallOrder[0]).toBeLessThan(
        vi.mocked(harness.cacheClear).mock.invocationCallOrder[0]!,
      );
      expect(vi.mocked(harness.cacheClear).mock.invocationCallOrder[0]).toBeLessThan(
        vi.mocked(harness.historyClear).mock.invocationCallOrder[0]!,
      );
      expect(vi.mocked(harness.historyClear).mock.invocationCallOrder[0]).toBeLessThan(
        vi.mocked(harness.clientEventsClear).mock.invocationCallOrder[0]!,
      );
      expect(vi.mocked(harness.clientEventsClear).mock.invocationCallOrder[0]).toBeLessThan(
        clear.mock.invocationCallOrder[0]!,
      );
      expect(harness.historyClear).toHaveBeenCalledWith(ROTATION_SERVER);
      expect(harness.clientEventsClear).toHaveBeenCalledWith({
        schemaVersion: 1,
        serverUrl: ROTATION_SERVER,
        accountId: ROTATION_EMAIL,
        startedAt: 10,
      });
      expect(await harness.sm.getState()).toBe('loggedOut');
      expect(await harness.sm.listAccounts()).toEqual([]);
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
      expect(() => harness.sessionGate.capture()).toThrow();
      expect(() => harness.accountGate.capture()).toThrow();
    });

    it.each([
      ['HTTP rejection', new ApiHttpError(400, { error: 'bad_request' })],
      ['transport timeout', new Error('request timed out')],
    ])('treats a %s as outcome_unknown after completing local cleanup', async (_name, failure) => {
      const post = vi.fn<ApiClient['rotateAccountKey']>(async () => { throw failure; });
      const harness = await makeRotationHarness({ rotateAccountKey: post });

      await expect(harness.auth.rotateAccountKey(ROTATION_PASSWORD)).rejects.toMatchObject({
        code: 'outcome_unknown',
        message: expect.stringMatching(/do not retry/i),
      });

      expect(post).toHaveBeenCalledOnce();
      expect(harness.historyClear).toHaveBeenCalledWith(ROTATION_SERVER);
      expect(harness.clientEventsClear).toHaveBeenCalledOnce();
      expect(await harness.sm.getState()).toBe('loggedOut');
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
    });

    it('waits for an earlier ordinary write and cancels a later write when rotation commits terminally', async () => {
      let releaseSync!: () => void;
      let markSyncStarted!: () => void;
      const syncStarted = new Promise<void>((resolve) => { markSyncStarted = resolve; });
      const syncGate = new Promise<void>((resolve) => { releaseSync = resolve; });
      const harness = await makeRotationHarness({
        sync: vi.fn(async () => {
          markSyncStarted();
          await syncGate;
          return {
            profile: { id: 'rotation-user', email: ROTATION_EMAIL, organizations: [] },
            ciphers: [], folders: [], sends: [],
          };
        }),
      });
      let releaseEarlier!: () => void;
      let markEarlierStarted!: () => void;
      const earlierStarted = new Promise<void>((resolve) => { markEarlierStarted = resolve; });
      const earlierGate = new Promise<void>((resolve) => { releaseEarlier = resolve; });
      const earlier = harness.coordinator.forAccount(harness.accountKey).runMutation('earlier', {
        commit: async () => {
          markEarlierStarted();
          await earlierGate;
          return 'receipt';
        },
        reconcile: async () => 'done',
      });
      await earlierStarted;

      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const rotationResult = expect(rotating).resolves.toBeUndefined();
      expect(harness.api.sync).not.toHaveBeenCalled();
      releaseEarlier();
      await syncStarted;
      const laterCommit = vi.fn(async () => 'must-not-commit');
      const later = harness.coordinator.forAccount(harness.accountKey).runMutation('later', {
        commit: laterCommit,
        reconcile: async () => 'must-not-run',
      });
      releaseSync();

      await expect(earlier).resolves.toEqual({ status: 'committed', value: 'done' });
      await rotationResult;
      await expect(later).resolves.toMatchObject({
        status: 'not_committed', error: { code: 'account_invalidated' },
      });
      expect(laterCommit).not.toHaveBeenCalled();
    });

    it('leaves the lane and session usable when rotation preflight fails', async () => {
      const harness = await makeRotationHarness({
        getTrustedEmergencyAccess: vi.fn(async () => [{ id: 'grant' }]),
      });
      const ordinaryCommit = vi.fn(async () => 'receipt');
      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const ordinary = harness.coordinator.forAccount(harness.accountKey).runMutation('ordinary', {
        commit: ordinaryCommit,
        reconcile: async () => 'updated',
      });

      await expect(rotating).rejects.toThrow(/emergency/i);
      await expect(ordinary).resolves.toEqual({ status: 'committed', value: 'updated' });
      expect(ordinaryCommit).toHaveBeenCalledOnce();
      expect(await harness.sm.getState()).toBe('unlocked');
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
    });

    it('does not seal the lane when the unlock-record inventory cannot prove emptiness', async () => {
      const inventoryFailure = new Error('unsupported unlock inventory schema');
      const harness = await makeRotationHarness({
        getKeyRotationUnlockRecordsStatus: vi.fn(async () => { throw inventoryFailure; }),
      });
      const ordinaryCommit = vi.fn(async () => 'receipt');
      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const ordinary = harness.coordinator.forAccount(harness.accountKey).runMutation('ordinary', {
        commit: ordinaryCommit,
        reconcile: async () => 'updated',
      });

      await expect(rotating).rejects.toBe(inventoryFailure);
      await expect(ordinary).resolves.toEqual({ status: 'committed', value: 'updated' });
      expect(ordinaryCommit).toHaveBeenCalledOnce();
      expect(harness.api.rotateAccountKey).not.toHaveBeenCalled();
      expect(await harness.sm.getState()).toBe('unlocked');
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
    });

    it.each(['reset', 'cache', 'history', 'events', 'marker'] as const)(
      'keeps gates closed and the marker durable when %s cleanup fails',
      async (failurePoint) => {
        const cleanupFailure = new Error(`${failurePoint} cleanup failed`);
        const onIdentityChanged = failurePoint === 'cache'
          ? vi.fn(async () => { throw cleanupFailure; })
          : vi.fn(async () => {});
        const clearGeneratorHistoryForServerAfterRotation = failurePoint === 'history'
          ? vi.fn(async () => { throw cleanupFailure; })
          : vi.fn(async () => {});
        const clearClientEventsAfterRotation = failurePoint === 'events'
          ? vi.fn(async () => { throw cleanupFailure; })
          : vi.fn(async () => {});
        const harness = await makeRotationHarness({}, {
          onIdentityChanged,
          clearGeneratorHistoryForServerAfterRotation,
          clearClientEventsAfterRotation,
        });
        if (failurePoint === 'reset') {
          vi.spyOn(harness.sm, 'resetAllAccounts').mockRejectedValue(cleanupFailure);
        }
        if (failurePoint === 'marker') {
          vi.spyOn(harness.pending, 'clear').mockRejectedValue(cleanupFailure);
        }

        await expect(harness.auth.rotateAccountKey(ROTATION_PASSWORD)).rejects.toMatchObject({
          code: 'outcome_unknown',
        });

        expect(harness.api.rotateAccountKey).toHaveBeenCalledOnce();
        if (failurePoint === 'history') {
          expect(harness.historyClear).toHaveBeenCalledWith(ROTATION_SERVER);
        }
        expect(await harness.pending.inspectForStartup()).toMatchObject({
          kind: 'pending', requiresAccountReset: true,
        });
        expect(() => harness.sessionGate.capture()).toThrow();
        expect(() => harness.accountGate.capture()).toThrow();
        expect(harness.coordinator.resumeAccount(harness.accountKey)).toBe(false);
        expect(harness.coordinator.trackedAccountCount).toBe(1);
        await expect(harness.auth.logout()).rejects.toMatchObject({ code: 'outcome_unknown' });
      },
    );

    it('does not seal the lane or invoke POST when durable marker persistence fails', async () => {
      const harness = await makeRotationHarness();
      const markerFailure = new Error('marker storage unavailable');
      vi.spyOn(harness.pending, 'markBeforeRotation').mockRejectedValue(
        markerFailure,
      );
      const ordinaryCommit = vi.fn(async () => 'receipt');
      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const ordinary = harness.coordinator.forAccount(harness.accountKey).runMutation('ordinary', {
        commit: ordinaryCommit,
        reconcile: async () => 'updated',
      });

      await expect(rotating).rejects.toBe(markerFailure);
      await expect(ordinary).resolves.toEqual({ status: 'committed', value: 'updated' });

      expect(harness.api.rotateAccountKey).not.toHaveBeenCalled();
      expect(ordinaryCommit).toHaveBeenCalledOnce();
      expect(() => harness.sessionGate.capture()).not.toThrow();
      expect(() => harness.accountGate.capture()).not.toThrow();
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
    });

    it('clears the marker and aborts before commit when an account switch wins during WAL persistence', async () => {
      const harness = await makeRotationHarness({}, { addOtherAccount: true });
      const originalMark = harness.pending.markBeforeRotation.bind(harness.pending);
      let releaseMark!: () => void;
      let markPersisted!: () => void;
      const markGate = new Promise<void>((resolve) => { releaseMark = resolve; });
      const markerWritten = new Promise<void>((resolve) => { markPersisted = resolve; });
      vi.spyOn(harness.pending, 'markBeforeRotation').mockImplementation(async (identity) => {
        const marker = await originalMark(identity);
        markPersisted();
        await markGate;
        return marker;
      });

      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const rejectedRotation = expect(rotating).rejects.toMatchObject({ code: 'session_expired' });
      await markerWritten;
      const switching = harness.auth.switchAccount('other@example.com');
      releaseMark();

      await rejectedRotation;
      await switching;
      expect(harness.api.rotateAccountKey).not.toHaveBeenCalled();
      expect((await harness.sm.getPersistedAuth())?.email).toBe('other@example.com');
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
      expect(harness.coordinator.trackedAccountCount).toBe(0);
      expect(harness.coordinator.resetTerminatedAccount(harness.accountKey)).toBe(false);
    });

    it('aborts before POST when an account switch wins during preflight', async () => {
      let releasePublicKey!: () => void;
      let markPublicKeyStarted!: () => void;
      const publicKeyStarted = new Promise<void>((resolve) => { markPublicKeyStarted = resolve; });
      const publicKeyGate = new Promise<void>((resolve) => { releasePublicKey = resolve; });
      const harness = await makeRotationHarness({
        getAccountPublicKey: vi.fn(async () => {
          markPublicKeyStarted();
          await publicKeyGate;
          return { publicKey: 'account-public-key' };
        }),
      }, { addOtherAccount: true });

      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const rejectedRotation = expect(rotating).rejects.toMatchObject({ code: 'session_expired' });
      await publicKeyStarted;
      const switching = harness.auth.switchAccount('other@example.com');
      releasePublicKey();

      await rejectedRotation;
      await switching;
      expect(harness.api.rotateAccountKey).not.toHaveBeenCalled();
      expect((await harness.sm.getPersistedAuth())?.email).toBe('other@example.com');
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
    });

    it('aborts before POST when a server reset wins during preflight', async () => {
      let releasePublicKey!: () => void;
      let markPublicKeyStarted!: () => void;
      const publicKeyStarted = new Promise<void>((resolve) => { markPublicKeyStarted = resolve; });
      const publicKeyGate = new Promise<void>((resolve) => { releasePublicKey = resolve; });
      const harness = await makeRotationHarness({
        getAccountPublicKey: vi.fn(async () => {
          markPublicKeyStarted();
          await publicKeyGate;
          return { publicKey: 'account-public-key' };
        }),
      });

      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      const rejectedRotation = expect(rotating).rejects.toMatchObject({ code: 'session_expired' });
      await publicKeyStarted;
      const resetting = harness.auth.resetForServerChange(async () => {});
      releasePublicKey();

      await rejectedRotation;
      await resetting;
      expect(harness.api.rotateAccountKey).not.toHaveBeenCalled();
      expect(await harness.sm.getState()).toBe('loggedOut');
      expect(await harness.pending.inspectForStartup()).toEqual({
        kind: 'none', requiresAccountReset: false,
      });
    });

    it('blocks account switching once POST has been invoked and resets all accounts afterward', async () => {
      let releasePost!: () => void;
      let markPostStarted!: () => void;
      const postStarted = new Promise<void>((resolve) => { markPostStarted = resolve; });
      const postGate = new Promise<void>((resolve) => { releasePost = resolve; });
      const harness = await makeRotationHarness({
        rotateAccountKey: vi.fn(async () => {
          markPostStarted();
          await postGate;
        }),
      }, { addOtherAccount: true });

      const rotating = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      await postStarted;
      await expect(harness.auth.switchAccount('other@example.com'))
        .rejects.toMatchObject({ code: 'outcome_unknown' });
      releasePost();

      await rotating;
      expect(await harness.sm.listAccounts()).toEqual([]);
    });

    it('allows at most one POST across concurrent rotation attempts', async () => {
      let releasePost!: () => void;
      let markPostStarted!: () => void;
      const postStarted = new Promise<void>((resolve) => { markPostStarted = resolve; });
      const postGate = new Promise<void>((resolve) => { releasePost = resolve; });
      const post = vi.fn(async () => {
        markPostStarted();
        await postGate;
      });
      const harness = await makeRotationHarness({ rotateAccountKey: post });

      const first = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      await postStarted;
      const second = harness.auth.rotateAccountKey(ROTATION_PASSWORD);
      await expect(second).rejects.toBeTruthy();
      releasePost();

      await first;
      expect(post).toHaveBeenCalledOnce();
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

  it('accepts Argon2id prelogin settings and sends the official master-password hash', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0] });
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue(ARGON2_KDF_VECTOR.config),
      passwordLogin,
    };
    const { auth } = makeService(api);
    await expect(
      auth.login({ email: ARGON2_KDF_VECTOR.email, masterPassword: ARGON2_KDF_VECTOR.password }),
    ).resolves.toEqual({ kind: 'twoFactor', providers: [0] });
    expect(passwordLogin.mock.calls[0]![0].masterPasswordHash)
      .toBe(ARGON2_KDF_VECTOR.masterPasswordHashB64);
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

  it('sendEmailCode rejects with session_expired when there is no pending 2FA token (fresh instance / SW teardown)', async () => {
    const { auth } = makeService({});
    await expect(auth.sendEmailCode()).rejects.toMatchObject({ code: 'session_expired' });
    await expect(auth.sendEmailCode()).rejects.toBeInstanceOf(AppError);
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
      kdfIterations: 5_000,
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
      kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await auth.refreshIfNeeded(5000);
    expect(api.refresh).toHaveBeenCalledWith('old-refresh', expect.objectContaining({
      onGrantStarted: expect.any(Function),
    }));
    expect((await sm.getPersistedAuth())?.accessToken).toBe('new-access');
  });

  it('coalesces concurrent refreshes that use the same refresh token', async () => {
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const refresh = vi.fn(async () => {
      await refreshGate;
      return {
        access_token: 'new-access',
        expires_in: 3600,
        refresh_token: 'new-refresh',
        token_type: 'Bearer',
      };
    });
    const { auth, sm } = makeService({ refresh });
    await sm.saveUnlocked({
      email: KDF_VECTOR.email,
      accessToken: 'old-access',
      refreshToken: 'old-refresh',
      expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    const first = auth.refreshIfNeeded(5000);
    const second = auth.refreshIfNeeded(5000);
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    releaseRefresh();
    await Promise.all([first, second]);

    expect(refresh).toHaveBeenCalledTimes(1);
    expect((await sm.getPersistedAuth())?.refreshToken).toBe('new-refresh');
  });

  it('coalesces and commits a refresh across a new ephemeral session binding', async () => {
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const refresh = vi.fn(async () => {
      await refreshGate;
      return {
        access_token: 'new-access', expires_in: 3600, refresh_token: 'new-refresh', token_type: 'Bearer',
      };
    });
    const { auth, sm } = makeService({ refresh });
    const input = {
      email: KDF_VECTOR.email, accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0 as const, kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    };
    await sm.saveUnlocked(input);
    const firstBinding = (await sm.getActiveAuth())?.sessionBindingId;

    const first = auth.refreshIfNeeded(5000);
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    await sm.lock();
    await sm.saveUnlocked(input);
    expect((await sm.getActiveAuth())?.sessionBindingId).not.toBe(firstBinding);
    const second = auth.refreshIfNeeded(5000);
    await Promise.resolve();
    expect(refresh).toHaveBeenCalledOnce();

    releaseRefresh();
    await Promise.all([first, second]);
    expect((await sm.getActiveAuth())?.refreshToken).toBe('new-refresh');
    expect(await sm.getState()).toBe('unlocked');
  });

  it('finishes an in-flight refresh before resetting accounts for a server change', async () => {
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const refresh = vi.fn(async () => {
      await refreshGate;
      return {
        access_token: 'stale-old-server-access',
        expires_in: 3600,
        refresh_token: 'stale-old-server-refresh',
        token_type: 'Bearer',
      };
    });
    let serverUrl = 'https://old.example';
    const { auth, sm } = makeService({ refresh }, async () => serverUrl);
    const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'same@example.com', accessToken: 'old-access', refreshToken: 'same-token', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });

    const pending = auth.refreshIfNeeded(5000);
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    let resetFinished = false;
    const reset = auth.resetForServerChange().then(() => { resetFinished = true; });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(resetFinished).toBe(false);

    releaseRefresh();
    await Promise.all([pending, reset]);
    serverUrl = 'https://new.example';
    await sm.saveUnlocked({
      email: 'same@example.com', accessToken: 'new-server-access', refreshToken: 'same-token', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });

    expect((await sm.getPersistedAuth())?.accessToken).toBe('new-server-access');
  });

  it('waits for a refresh attempt even before its network request starts', async () => {
    let releaseAuthRead!: () => void;
    const authReadGate = new Promise<void>((resolve) => { releaseAuthRead = resolve; });
    const { auth, sm } = makeService({
      refresh: vi.fn(async () => ({
        access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600, token_type: 'Bearer',
      })),
    });
    await sm.saveUnlocked({
      email: 'same@example.com', accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    const originalGetActiveAuth = sm.getActiveAuthSnapshot.bind(sm);
    vi.spyOn(sm, 'getActiveAuthSnapshot').mockImplementationOnce(async () => {
      await authReadGate;
      return originalGetActiveAuth();
    });

    const refresh = auth.refreshIfNeeded(5000);
    let resetFinished = false;
    const reset = auth.resetForServerChange().then(() => { resetFinished = true; });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(resetFinished).toBe(false);

    releaseAuthRead();
    await Promise.all([refresh, reset]);
  });

  it('does not deadlock a server reset when an in-flight refresh becomes invalid', async () => {
    let rejectRefresh!: (error: Error) => void;
    const refresh = vi.fn(() => new Promise<never>((_resolve, reject) => { rejectRefresh = reject; }));
    const { auth, sm } = makeService({ refresh });
    await sm.saveUnlocked({
      email: 'same@example.com', accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    const refreshing = auth.refreshIfNeeded(5000);
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
    const reset = auth.resetForServerChange();
    rejectRefresh(new ApiHttpError(400, { error: 'invalid_grant' }));

    await Promise.all([refreshing, reset]);
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('builds the official fallback connector URL from validated provider 7 metadata', async () => {
    const passwordLogin = vi.fn().mockResolvedValue({
      kind: 'twoFactor' as const,
      providers: [0, 7],
      providerMetadata: FIDO_PROVIDER_METADATA,
      token: 'tf',
    });
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);

    const result = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    expect(result).toMatchObject({
      kind: 'twoFactor',
      providers: [0, 7],
      fido2: {
        owner: {
          flow: 'password',
          generation: 1,
          serverUrl: FIDO_SERVER,
          bindingId: 'password-1',
        },
      },
    });
    if (result.kind !== 'twoFactor' || !result.fido2) throw new Error('missing FIDO2 challenge');
    const launch = auth.beginFido2({
      attemptId: result.fido2.owner.generation,
      parentUrl: FIDO_PARENT_URL,
      locale: 'zh-CN',
    });
    const url = new URL(launch.url);
    expect(url.origin + url.pathname).toBe(`${FIDO_SERVER}webauthn-fallback-connector.html`);
    expect(JSON.parse(bytesToUtf8(base64ToBytes(url.searchParams.get('data')!))))
      .toEqual(FIDO_PROVIDER_METADATA['7']);
    expect(decodeURIComponent(url.searchParams.get('parent')!)).toBe(FIDO_PARENT_URL);
    expect(url.searchParams.get('locale')).toBe('zh-CN');
    expect(url.searchParams.get('v')).toBe('1');
    expect([...url.searchParams.keys()].sort()).toEqual(['data', 'locale', 'parent', 'v']);
  });

  it('validates a claimed fallback result before forwarding provider 7', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [7],
        providerMetadata: FIDO_PROVIDER_METADATA,
      })
      .mockResolvedValueOnce(successfulLogin('fido-access'));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const launch = launchFidoConnector(auth, challenge.fido2.owner);
    const token = await makeFidoConnectorToken();

    await expect(auth.completeFido2({
      url: launch.url,
      tabId: launch.tabId,
      documentId: launch.documentId,
      token,
      remember: true,
    }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin).toHaveBeenCalledTimes(2);
    expect(passwordLogin.mock.calls[1]![0]).toMatchObject({
      twoFactorProvider: 7,
      twoFactorToken: token,
      remember: true,
    });
  });

  it('allows only one fallback result to consume the pending binding', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [7],
        providerMetadata: FIDO_PROVIDER_METADATA,
      })
      .mockResolvedValueOnce(successfulLogin('fido-once'));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const launch = launchFidoConnector(auth, challenge.fido2.owner);
    const token = await makeFidoConnectorToken();

    const first = auth.completeFido2({
      url: launch.url,
      tabId: launch.tabId,
      documentId: launch.documentId,
      token,
      remember: false,
    });
    await expect(auth.completeFido2({
      url: launch.url,
      tabId: launch.tabId,
      documentId: launch.documentId,
      token,
      remember: false,
    }))
      .rejects.toMatchObject({ code: 'session_expired' });
    await expect(first).resolves.toEqual({ kind: 'unlocked' });
    expect(passwordLogin).toHaveBeenCalledTimes(2);
  });

  it('consumes and rejects a fallback token with the wrong WebAuthn origin before network I/O', async () => {
    const passwordLogin = vi.fn().mockResolvedValueOnce({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata: FIDO_PROVIDER_METADATA,
    });
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const launch = launchFidoConnector(auth, challenge.fido2.owner);

    await expect(auth.completeFido2({
      url: launch.url,
      tabId: launch.tabId,
      documentId: launch.documentId,
      token: await makeFidoConnectorToken({ origin: 'https://evil.example' }),
      remember: false,
    })).rejects.toMatchObject({ code: 'session_expired' });
    expect(passwordLogin).toHaveBeenCalledTimes(1);
    await expect(auth.completeFido2({
      url: launch.url,
      tabId: launch.tabId,
      documentId: launch.documentId,
      token: await makeFidoConnectorToken(),
      remember: false,
    }))
      .rejects.toMatchObject({ code: 'session_expired' });
  });

  it('rejects a wrong fallback URL or tab without consuming the valid connector claim', async () => {
    const passwordLogin = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [7],
        providerMetadata: FIDO_PROVIDER_METADATA,
      })
      .mockResolvedValueOnce(successfulLogin('exact-fallback-caller'));
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const launch = launchFidoConnector(auth, challenge.fido2.owner);
    const token = await makeFidoConnectorToken();

    expect(() => auth.assertFido2ConnectorCaller({
      url: `${launch.url}#changed`,
      tabId: launch.tabId,
      documentId: launch.documentId,
    }))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
    expect(() => auth.assertFido2ConnectorCaller({
      url: launch.url,
      tabId: launch.tabId + 1,
      documentId: launch.documentId,
    }))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
    await expect(auth.completeFido2({
      url: launch.url,
      tabId: launch.tabId,
      documentId: launch.documentId,
      token,
      remember: false,
    })).resolves.toEqual({ kind: 'unlocked' });
  });

  it('relaunches provider 7 by invalidating and replacing the previous connector tab', async () => {
    const passwordLogin = vi.fn().mockResolvedValueOnce({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata: FIDO_PROVIDER_METADATA,
    });
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const owner = challenge.fido2.owner;
    const first = launchFidoConnector(auth, owner, 71);
    const second = auth.beginFido2({
      attemptId: owner.generation,
      parentUrl: FIDO_PARENT_URL,
      locale: 'en',
    });

    expect(second.replace).toEqual({
      tabId: 71,
      documentId: first.documentId,
      url: first.url,
    });
    expect(() => auth.assertFido2ConnectorCaller({
      url: first.url,
      tabId: 71,
      documentId: first.documentId,
    }))
      .toThrowError(expect.objectContaining({ code: 'denied' }));
  });

  it('safely closes the exact bound password connector when its continuation is cancelled', async () => {
    const passwordLogin = vi.fn().mockResolvedValueOnce({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata: FIDO_PROVIDER_METADATA,
    });
    const closeConnector = vi.fn(async () => undefined);
    const { auth } = makeService(
      {
        prelogin: vi.fn().mockResolvedValue({
          kdf: 0 as const,
          kdfIterations: KDF_VECTOR_600K.iterations,
        }),
        passwordLogin,
      },
      async () => FIDO_SERVER,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      closeConnector,
    );
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const launch = launchFidoConnector(auth, challenge.fido2.owner, 72, 'password-document-cleanup');

    await expect(auth.cancelPendingLogin()).resolves.toBe(true);
    await vi.waitFor(() => expect(closeConnector).toHaveBeenCalledWith({
      url: launch.url,
      tabId: 72,
      documentId: 'password-document-cleanup',
    }));
  });

  it('single-flights an unbound fallback launch and permits retry after cancellation', async () => {
    const passwordLogin = vi.fn().mockResolvedValueOnce({
      kind: 'twoFactor' as const,
      providers: [7],
      providerMetadata: FIDO_PROVIDER_METADATA,
    });
    const { auth } = makeService({
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin,
    }, async () => FIDO_SERVER);
    const challenge = await auth.login({
      email: KDF_VECTOR_600K.email,
      masterPassword: KDF_VECTOR_600K.password,
    });
    if (challenge.kind !== 'twoFactor' || !challenge.fido2) throw new Error('missing FIDO2 challenge');
    const attemptId = challenge.fido2.owner.generation;
    const first = auth.beginFido2({ attemptId, parentUrl: FIDO_PARENT_URL, locale: 'en' });

    expect(() => auth.beginFido2({ attemptId, parentUrl: FIDO_PARENT_URL, locale: 'en' }))
      .toThrowError(/already opening/);
    auth.cancelFido2Launch({ attemptId, url: first.url });
    expect(() => auth.beginFido2({ attemptId, parentUrl: FIDO_PARENT_URL, locale: 'en' }))
      .not.toThrow();
  });

  it('invalidates cached vault data when the active identity changes', async () => {
    const onIdentityChanged = vi.fn(async () => {});
    const { auth, sm } = makeService({}, async () => 'https://vault.example', onIdentityChanged);
    const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'a@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });
    await sm.saveUnlocked({
      email: 'b@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });

    await auth.switchAccount('a@example.com');
    expect(onIdentityChanged).toHaveBeenCalledTimes(1);

    await auth.logout();
    expect(onIdentityChanged).toHaveBeenCalledTimes(2);
  });

  it('keeps the active account cache when removing a different account', async () => {
    const onIdentityChanged = vi.fn(async () => {});
    const { auth, sm } = makeService({}, async () => 'https://vault.example', onIdentityChanged);
    const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'other@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });
    await sm.saveUnlocked({
      email: 'active@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });

    await auth.removeAccount('other@example.com');

    expect((await sm.getPersistedAuth())?.email).toBe('active@example.com');
    expect(onIdentityChanged).not.toHaveBeenCalled();
  });

  it('keeps cached vault data when switching to the already-active account', async () => {
    const onIdentityChanged = vi.fn(async () => {});
    const { auth, sm } = makeService({}, async () => 'https://vault.example', onIdentityChanged);
    await sm.saveUnlocked({
      email: 'active@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    await auth.switchAccount('active@example.com');

    expect((await sm.getPersistedAuth())?.email).toBe('active@example.com');
    expect(onIdentityChanged).not.toHaveBeenCalled();
  });

  it('invalidates old cache before activating a different account', async () => {
    const refs: { session?: SessionManager } = {};
    const activeDuringInvalidation: Array<string | undefined> = [];
    const made = makeService({}, async () => 'https://vault.example', async () => {
      activeDuringInvalidation.push((await refs.session!.getPersistedAuth())?.email);
    });
    refs.session = made.sm;
    const sm = made.sm;
    const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'old@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });
    await sm.saveUnlocked({
      email: 'current@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });

    await made.auth.switchAccount('old@example.com');

    expect(activeDuringInvalidation).toEqual(['current@example.com']);
    expect((await sm.getPersistedAuth())?.email).toBe('old@example.com');
  });

  it('uses exact committed identities for account and server generator-history cleanup', async () => {
    let serverUrl = 'https://vault.example/';
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    const save = (email: string) => sm.saveUnlocked({
      email,
      accessToken: `${email}-access`,
      refreshToken: `${email}-refresh`,
      expiresAt: 999_999,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 5_000,
      userKey,
    });
    await save('other@example.com');
    await save('active@example.com');
    const clearAccount = vi.fn(async () => {});
    const clearServer = vi.fn(async () => {});
    const auth = new AuthService({
      api: mockApiClient({}),
      session: sm,
      sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
      serverUrlProvider: async () => serverUrl,
      clearGeneratorHistoryForAccount: clearAccount,
      clearGeneratorHistoryForServer: clearServer,
    });

    await auth.removeAccount(' OTHER@example.com ');
    expect(clearAccount).toHaveBeenCalledWith({
      serverUrl: 'https://vault.example/', accountId: 'other@example.com',
    });

    await auth.resetForServerChange(async () => { serverUrl = 'https://new.example/'; });
    expect(clearServer).toHaveBeenCalledWith('https://vault.example/');

    await save('fresh@example.com');
    await auth.logout();
    expect(clearAccount).toHaveBeenLastCalledWith({
      serverUrl: 'https://new.example/', accountId: 'fresh@example.com',
    });
  });

  it('bounds normal logout history cleanup while continuously observing its late settlement', async () => {
    vi.useFakeTimers();
    try {
      const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
      await sm.saveUnlocked({
        email: 'active@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999_999,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5_000,
        userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
      });
      let markStarted!: () => void;
      const started = new Promise<void>((resolve) => { markStarted = resolve; });
      let rejectCleanup!: (error: Error) => void;
      const cleanup = new Promise<void>((_resolve, reject) => { rejectCleanup = reject; });
      const auth = new AuthService({
        api: mockApiClient({}),
        session: sm,
        sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
        serverUrlProvider: async () => 'https://vault.example/',
        clearGeneratorHistoryForAccount: async () => {
          markStarted();
          return cleanup;
        },
      });

      const loggingOut = auth.logout();
      await started;
      let settled = false;
      void loggingOut.then(() => { settled = true; });
      await Promise.resolve();
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(GENERATOR_HISTORY_CLEANUP_WAIT_MS);
      await expect(loggingOut).resolves.toBeUndefined();
      expect(await sm.getState()).toBe('loggedOut');
      rejectCleanup(new Error('late cleanup failure'));
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
  });

  it('starts every invalidating transition before changing the session state', async () => {
    const addAccount = (sm: SessionManager, email: string) => sm.saveUnlocked({
      email,
      accessToken: `${email}-access`,
      refreshToken: `${email}-refresh`,
      expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 5000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    const runCase = async (input: {
      reason: 'lock' | 'logout' | 'switchAccount' | 'removeAccount' | 'serverChange';
      identityChanged: boolean;
      prepare(sm: SessionManager): Promise<void>;
      act(auth: AuthService): Promise<void>;
      settledState: 'loggedOut' | 'locked';
    }) => {
      const observations: Array<{ event: SessionTransitionEvent; state: string }> = [];
      const refs: { session?: SessionManager } = {};
      const made = makeService({}, undefined, undefined, async (event) => {
        observations.push({ event, state: await refs.session!.getState() });
      });
      refs.session = made.sm;
      await input.prepare(made.sm);

      await input.act(made.auth);

      expect(observations).toHaveLength(2);
      expect(observations[0]).toMatchObject({
        event: { phase: 'start', reason: input.reason, identityChanged: input.identityChanged },
        state: 'unlocked',
      });
      expect(observations[1]).toMatchObject({
        event: {
          phase: 'settled', reason: input.reason, identityChanged: input.identityChanged,
          state: input.settledState, succeeded: true,
        },
        state: input.settledState,
      });
    };

    await runCase({
      reason: 'lock', identityChanged: false,
      prepare: (sm) => addAccount(sm, 'active@example.com'),
      act: (auth) => auth.lock(),
      settledState: 'locked',
    });
    await runCase({
      reason: 'logout', identityChanged: true,
      prepare: (sm) => addAccount(sm, 'active@example.com'),
      act: (auth) => auth.logout(),
      settledState: 'loggedOut',
    });
    await runCase({
      reason: 'switchAccount', identityChanged: true,
      prepare: async (sm) => {
        await addAccount(sm, 'other@example.com');
        await addAccount(sm, 'active@example.com');
      },
      act: (auth) => auth.switchAccount('other@example.com'),
      settledState: 'locked',
    });
    await runCase({
      reason: 'removeAccount', identityChanged: true,
      prepare: (sm) => addAccount(sm, 'active@example.com'),
      act: (auth) => auth.removeAccount('active@example.com'),
      settledState: 'loggedOut',
    });
    await runCase({
      reason: 'serverChange', identityChanged: true,
      prepare: (sm) => addAccount(sm, 'active@example.com'),
      act: (auth) => auth.resetForServerChange(),
      settledState: 'loggedOut',
    });
  });

  it('settles a failed transition with the still-authoritative session state', async () => {
    const events: SessionTransitionEvent[] = [];
    const { auth, sm } = makeService({}, undefined, undefined, (event) => { events.push(event); });
    await sm.saveUnlocked({
      email: 'active@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    await expect(auth.switchAccount('missing@example.com')).rejects.toThrow('unknown account');

    expect(events.at(-1)).toMatchObject({
      phase: 'settled', reason: 'switchAccount', state: 'unlocked', succeeded: false,
    });
  });

  describe('leased access tokens', () => {
    it('returns the current unexpired token without refreshing', async () => {
      const harness = await makeAccessTokenHarness();

      await expect(harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
      )).resolves.toBe('old-access-secret');
      expect(harness.refresh).not.toHaveBeenCalled();
    });

    it('returns the exact account token while the vault is locked', async () => {
      const harness = await makeAccessTokenHarness();
      await harness.auth.lock();

      await expect(harness.auth.getAccountAccessToken(
        harness.accountLease,
      )).resolves.toBe('old-access-secret');
      expect(harness.refresh).not.toHaveBeenCalled();
    });

    it('refreshes an expiring token and returns only the persisted replacement', async () => {
      const harness = await makeAccessTokenHarness({ expiresAt: 1_100 });

      await expect(harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      )).resolves.toBe('new-access-secret');
      expect(harness.refresh).toHaveBeenCalledOnce();
      expect(harness.refresh).toHaveBeenCalledWith(
        'old-refresh-secret',
        expect.objectContaining({ onGrantStarted: expect.any(Function) }),
      );
      expect((await harness.sm.getPersistedAuth())?.accessToken).toBe('new-access-secret');
    });

    it('refreshes and persists an expiring account token while locked', async () => {
      const harness = await makeAccessTokenHarness({ expiresAt: 1_100 });
      await harness.auth.lock();

      await expect(harness.auth.getAccountAccessToken(
        harness.accountLease,
        5_000,
      )).resolves.toBe('new-access-secret');
      expect(harness.refresh).toHaveBeenCalledOnce();
      expect(harness.refresh).toHaveBeenCalledWith(
        'old-refresh-secret',
        expect.objectContaining({ onGrantStarted: expect.any(Function) }),
      );
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'new-access-secret',
        refreshToken: 'new-refresh-secret',
      });
    });

    it('commits RT2 to the original inactive account after switching to another account', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });
      const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
      await harness.sm.saveUnlocked({
        email: 'other@example.com',
        accessToken: 'other-access',
        refreshToken: 'other-refresh',
        expiresAt: 999_999,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 5_000,
        userKey,
      });
      await harness.sm.switchAccount('user@example.com');

      const refreshing = harness.auth.refreshIfNeeded(5_000);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      const switching = harness.auth.switchAccount('other@example.com');
      await switching;
      resolveRefresh({
        access_token: 'inactive-access-2',
        refresh_token: 'inactive-refresh-2',
        expires_in: 3_600,
        token_type: 'Bearer',
      });
      await refreshing;

      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        email: 'other@example.com',
        accessToken: 'other-access',
      });
      await harness.auth.switchAccount('user@example.com');
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'inactive-access-2',
        refreshToken: 'inactive-refresh-2',
      });
    });

    it('keeps an account-scoped refresh current across an in-flight lock', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });
      const token = harness.auth.getAccountAccessToken(harness.accountLease, 5_000);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());

      const locking = harness.auth.lock();
      resolveRefresh({
        access_token: 'locked-access-secret',
        refresh_token: 'locked-refresh-secret',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await expect(token).resolves.toBe('locked-access-secret');
      await locking;
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'locked-access-secret',
        refreshToken: 'locked-refresh-secret',
      });
    });

    it('shares the existing refresh single-flight between leased token callers', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });

      const first = harness.auth.getAccessToken(harness.sessionLease, harness.accountLease, 5_000);
      const second = harness.auth.getAccessToken(harness.sessionLease, harness.accountLease, 5_000);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      resolveRefresh({
        access_token: 'shared-access-secret',
        refresh_token: 'shared-refresh-secret',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await expect(Promise.all([first, second])).resolves.toEqual([
        'shared-access-secret',
        'shared-access-secret',
      ]);
      expect(harness.refresh).toHaveBeenCalledOnce();
    });

    it('persists RT2 across lock-unlock while the stale caller fails its SessionLease', async () => {
      let resolveOldRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      let refreshCalls = 0;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => {
          refreshCalls += 1;
          if (refreshCalls === 1) {
            return new Promise((resolve) => { resolveOldRefresh = resolve; });
          }
          throw new Error('RT1 must never be submitted twice');
        },
      });
      const persisted = (await harness.sm.getPersistedAuth())!;
      const userKey = (await harness.sm.loadUserKey())!;
      const stale = harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      );
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      await harness.auth.lock();
      await harness.sm.saveUnlocked({ ...persisted, userKey }, { replaceCredential: false });
      harness.sessionGate.handleTransition({
        phase: 'start', transitionId: 2, reason: 'unlock', identityChanged: false,
      });
      harness.sessionGate.handleTransition({
        phase: 'settled', transitionId: 2, reason: 'unlock', identityChanged: false,
        state: 'unlocked', succeeded: true,
      });
      const currentSessionLease = harness.sessionGate.capture();
      const current = harness.auth.getAccessToken(
        currentSessionLease,
        harness.accountLease,
        5_000,
      );

      resolveOldRefresh({
        access_token: 'rotated-access',
        refresh_token: 'rotated-RT2',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await expect(stale).rejects.toMatchObject({ code: 'session_expired' });
      await expect(current).resolves.toBe('rotated-access');
      expect(harness.refresh).toHaveBeenCalledOnce();
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'rotated-access',
        refreshToken: 'rotated-RT2',
      });
    });

    it('retires the credential after a dispatched stale-session flight failure', async () => {
      let rejectOldRefresh!: (error: Error) => void;
      let refreshCalls = 0;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => {
          refreshCalls += 1;
          if (refreshCalls === 1) {
            return new Promise((_resolve, reject) => { rejectOldRefresh = reject; });
          }
          throw new Error('RT1 must never be submitted twice');
        },
      });
      const stale = harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      );
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      harness.sessionGate.handleTransition({
        phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
      });
      harness.sessionGate.handleTransition({
        phase: 'settled', transitionId: 1, reason: 'lock', identityChanged: false,
        state: 'locked', succeeded: true,
      });
      harness.sessionGate.handleTransition({
        phase: 'start', transitionId: 2, reason: 'unlock', identityChanged: false,
      });
      harness.sessionGate.handleTransition({
        phase: 'settled', transitionId: 2, reason: 'unlock', identityChanged: false,
        state: 'unlocked', succeeded: true,
      });
      const currentSessionLease = harness.sessionGate.capture();
      const current = harness.auth.getAccessToken(
        currentSessionLease,
        harness.accountLease,
        5_000,
      );
      const staleFailure = new Error('stale session request failed');
      await new Promise((resolve) => setTimeout(resolve, 0));

      rejectOldRefresh(staleFailure);

      await expect(stale).rejects.toMatchObject({ code: 'session_expired' });
      await expect(current).rejects.toMatchObject({ code: 'session_expired' });
      expect(harness.refresh).toHaveBeenCalledOnce();
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('persists a refresh result after lock but never returns it to the stale caller', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });
      const token = harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      );
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      const locking = harness.auth.lock();
      resolveRefresh({
        access_token: 'late-access-secret',
        refresh_token: 'late-refresh-secret',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await expect(token).rejects.toMatchObject({
        code: 'session_expired',
        message: 'A current access token is not available for this session.',
      });
      await locking;
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'late-access-secret',
        refreshToken: 'late-refresh-secret',
      });
    });

    it('does not resurrect a logged-out credential when its refresh completes late', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });
      const saveTokensFor = vi.spyOn(harness.sm, 'commitTokenRefresh');
      const token = harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      );
      const rejected = expect(token).rejects.toMatchObject({ code: 'session_expired' });
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());

      await harness.auth.logout();
      resolveRefresh({
        access_token: 'must-not-persist',
        refresh_token: 'must-not-persist-RT2',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await rejected;
      expect(saveTokensFor).toHaveBeenCalledOnce();
      expect(await harness.sm.getPersistedAuth()).toBeUndefined();
    });

    it('does not overwrite auth when the exact email-refresh-token CAS fails', async () => {
      const harness = await makeAccessTokenHarness({ expiresAt: 1_000 });
      const saveTokensFor = vi.spyOn(harness.sm, 'commitTokenRefresh').mockResolvedValue(undefined);

      await expect(harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      )).rejects.toMatchObject({ code: 'session_expired' });

      expect(saveTokensFor).toHaveBeenCalledWith(expect.objectContaining({
        email: 'user@example.com',
      }), {
        accessToken: 'new-access-secret',
        refreshToken: 'new-refresh-secret',
        expiresAt: 3_601_000,
      });
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'old-access-secret',
        refreshToken: 'old-refresh-secret',
      });
    });

    it('reasserts the session lease after an awaited auth read', async () => {
      const harness = await makeAccessTokenHarness();
      const read = harness.sm.getActiveAuth.bind(harness.sm);
      let releaseRead!: () => void;
      const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
      const getActiveAuth = vi.spyOn(harness.sm, 'getActiveAuth')
        .mockImplementationOnce(async () => {
          await readGate;
          return read();
        });
      const token = harness.auth.getAccessToken(harness.sessionLease, harness.accountLease);
      await vi.waitFor(() => expect(getActiveAuth).toHaveBeenCalledOnce());

      const locking = harness.auth.lock();
      releaseRead();

      await expect(token).rejects.toMatchObject({ code: 'session_expired' });
      await locking;
      expect(harness.refresh).not.toHaveBeenCalled();
    });

    it('reasserts the leases in the caller continuation after the final auth read resolves', async () => {
      const harness = await makeAccessTokenHarness();
      const internal = harness.auth as unknown as {
        readLeasedAuth(
          sessionLease: typeof harness.sessionLease,
          accountLease: typeof harness.accountLease,
        ): Promise<Awaited<ReturnType<typeof harness.sm.getActiveAuth>>>;
      };
      const read = internal.readLeasedAuth.bind(harness.auth);
      let reads = 0;
      let locking: Promise<void> | undefined;
      vi.spyOn(internal, 'readLeasedAuth').mockImplementation(async (sessionLease, accountLease) => {
        const result = await read(sessionLease, accountLease);
        reads += 1;
        if (reads === 2) {
          queueMicrotask(() => { locking = harness.auth.lock(); });
        }
        return result;
      });

      await expect(harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
      )).rejects.toMatchObject({ code: 'session_expired' });
      await vi.waitFor(() => expect(locking).toBeDefined());
      await locking;
    });

    it.each(['account', 'server'] as const)(
      'rejects an old token request after a same-identity %s ABA transition',
      async (transitionKind) => {
        let resolveRefresh!: (value: {
          access_token: string;
          refresh_token: string;
          expires_in: number;
          token_type: string;
        }) => void;
        const harness = await makeAccessTokenHarness({
          expiresAt: 1_100,
          refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
        });
        const token = harness.auth.getAccessToken(
          harness.sessionLease,
          harness.accountLease,
          5_000,
        );
        await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());

        if (transitionKind === 'account') {
          const away = harness.accountGate.beginAccountTransition();
          harness.accountGate.endAccountTransition(away, {
            serverUrl: 'https://vault.example/tenant/',
            accountIdentity: 'other@example.com',
          });
          const back = harness.accountGate.beginAccountTransition();
          harness.accountGate.endAccountTransition(back, {
            serverUrl: 'https://vault.example/tenant/',
            accountIdentity: 'user@example.com',
          });
        } else {
          const away = harness.accountGate.beginServerTransition();
          harness.accountGate.endServerTransition(away, {
            serverUrl: 'https://other.example/',
            accountIdentity: 'user@example.com',
          });
          const back = harness.accountGate.beginServerTransition();
          harness.accountGate.endServerTransition(back, {
            serverUrl: 'https://vault.example/tenant/',
            accountIdentity: 'user@example.com',
          });
        }
        resolveRefresh({
          access_token: 'aba-access-secret',
          refresh_token: 'aba-refresh-secret',
          expires_in: 3_600,
          token_type: 'Bearer',
        });

        await expect(token).rejects.toMatchObject({ code: 'session_expired' });
        expect((await harness.sm.getPersistedAuth())?.accessToken).toBe('aba-access-secret');
      },
    );

    it.each(['account', 'server'] as const)(
      'rejects an account-scoped token request after a same-identity %s ABA transition',
      async (transitionKind) => {
        let resolveRefresh!: (value: {
          access_token: string;
          refresh_token: string;
          expires_in: number;
          token_type: string;
        }) => void;
        const harness = await makeAccessTokenHarness({
          expiresAt: 1_100,
          refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
        });
        await harness.auth.lock();
        const token = harness.auth.getAccountAccessToken(harness.accountLease, 5_000);
        await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());

        if (transitionKind === 'account') {
          const away = harness.accountGate.beginAccountTransition();
          harness.accountGate.endAccountTransition(away, {
            serverUrl: 'https://vault.example/tenant/',
            accountIdentity: 'other@example.com',
          });
          const back = harness.accountGate.beginAccountTransition();
          harness.accountGate.endAccountTransition(back, {
            serverUrl: 'https://vault.example/tenant/',
            accountIdentity: 'user@example.com',
          });
        } else {
          const away = harness.accountGate.beginServerTransition();
          harness.accountGate.endServerTransition(away, {
            serverUrl: 'https://other.example/',
            accountIdentity: 'user@example.com',
          });
          const back = harness.accountGate.beginServerTransition();
          harness.accountGate.endServerTransition(back, {
            serverUrl: 'https://vault.example/tenant/',
            accountIdentity: 'user@example.com',
          });
        }
        resolveRefresh({
          access_token: 'aba-account-access-secret',
          refresh_token: 'aba-account-refresh-secret',
          expires_in: 3_600,
          token_type: 'Bearer',
        });

        await expect(token).rejects.toMatchObject({ code: 'session_expired' });
        expect((await harness.sm.getPersistedAuth())?.accessToken).toBe('aba-account-access-secret');
      },
    );

    it('rejects a persisted server or account that is not the exact normalized lease identity', async () => {
      const serverMismatch = await makeAccessTokenHarness();
      serverMismatch.currentServer.value = 'https://other.example/';
      await expect(serverMismatch.auth.getAccessToken(
        serverMismatch.sessionLease,
        serverMismatch.accountLease,
      )).rejects.toMatchObject({ code: 'session_expired' });
      await expect(serverMismatch.auth.getAccountAccessToken(
        serverMismatch.accountLease,
      )).rejects.toMatchObject({ code: 'session_expired' });

      const accountMismatch = await makeAccessTokenHarness({
        persistedEmail: ' User@Example.COM ',
      });
      await expect(accountMismatch.auth.getAccountAccessToken(
        accountMismatch.accountLease,
      )).rejects.toMatchObject({ code: 'session_expired' });
      let error: unknown;
      try {
        await accountMismatch.auth.getAccessToken(
          accountMismatch.sessionLease,
          accountMismatch.accountLease,
        );
      } catch (caught) {
        error = caught;
      }
      expect(error).toMatchObject({
        code: 'session_expired',
        message: 'A current access token is not available for this session.',
      });
      expect(String(error)).not.toContain('User@Example.COM');
      expect(String(error)).not.toContain('old-access-secret');
      expect(serverMismatch.refresh).not.toHaveBeenCalled();
      expect(accountMismatch.refresh).not.toHaveBeenCalled();
    });

    it('maps malformed lease identity and server-provider failures to the fixed token error', async () => {
      const nonCanonical = await makeAccessTokenHarness({
        serverUrl: 'https://vault.example/tenant',
      });
      await expect(nonCanonical.auth.getAccessToken(
        nonCanonical.sessionLease,
        nonCanonical.accountLease,
      )).rejects.toMatchObject({
        code: 'session_expired',
        message: 'A current access token is not available for this session.',
      });

      const providerFailure = await makeAccessTokenHarness({
        serverUrlProvider: async () => {
          throw new Error('old-access-secret user@example.com');
        },
      });
      let failure: unknown;
      try {
        await providerFailure.auth.getAccessToken(
          providerFailure.sessionLease,
          providerFailure.accountLease,
        );
      } catch (error) {
        failure = error;
      }
      expect(failure).toMatchObject({
        code: 'session_expired',
        message: 'A current access token is not available for this session.',
      });
      expect(String(failure)).not.toContain('old-access-secret');
      expect(String(failure)).not.toContain('user@example.com');
      expect(nonCanonical.refresh).not.toHaveBeenCalled();
      expect(providerFailure.refresh).not.toHaveBeenCalled();
    });

    it('turns a rejected refresh into a fixed lease failure without returning stale credentials', async () => {
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: async () => { throw new ApiHttpError(401, { error: 'invalid_grant' }); },
      });

      await expect(harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      )).rejects.toMatchObject({
        code: 'session_expired',
        message: 'A current access token is not available for this session.',
      });
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('retires the credential when a dispatched refresh returns malformed data', async () => {
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: async () => ({
          access_token: 'new-access-secret',
          refresh_token: undefined,
          expires_in: 3_600,
          token_type: 'Bearer',
        } as never),
      });

      await expect(harness.auth.refreshIfNeeded(5_000)).resolves.toBeUndefined();
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('does not log out when invalid_grant belongs to an RT that is no longer current', async () => {
      let rejectRefresh!: (error: Error) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((_resolve, reject) => { rejectRefresh = reject; }),
      });
      const token = harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      );
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      await expect(harness.sm.saveTokensFor({
        email: 'user@example.com',
        refreshToken: 'old-refresh-secret',
      }, {
        accessToken: 'concurrent-access',
        refreshToken: 'concurrent-RT2',
        expiresAt: 999_999,
      })).resolves.toBe(true);

      rejectRefresh(new ApiHttpError(401, { error: 'invalid_grant' }));

      await expect(token).resolves.toBe('concurrent-access');
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'concurrent-access',
        refreshToken: 'concurrent-RT2',
      });
      expect(harness.transitionEvents.some((event) => event.reason === 'logout')).toBe(false);
    });

    it('does not wait for transition-idle before scheduling an invalid-grant logout', async () => {
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: async () => { throw new ApiHttpError(401, { error: 'invalid_grant' }); },
      });
      const internal = harness.auth as unknown as { waitForTransitionIdle(): Promise<void> };
      const waitForTransitionIdle = vi.spyOn(internal, 'waitForTransitionIdle');

      await expect(harness.auth.getAccessToken(
        harness.sessionLease,
        harness.accountLease,
        5_000,
      )).rejects.toMatchObject({ code: 'session_expired' });

      expect(waitForTransitionIdle).not.toHaveBeenCalled();
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('avoids a refresh-transition lock inversion when server reset follows invalid_grant', async () => {
      let rejectRefresh!: (error: Error) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((_resolve, reject) => { rejectRefresh = reject; }),
      });
      const lock = harness.sm.lock.bind(harness.sm);
      let releaseLock!: () => void;
      const lockGate = new Promise<void>((resolve) => { releaseLock = resolve; });
      const lockSpy = vi.spyOn(harness.sm, 'lock').mockImplementationOnce(async () => {
        await lockGate;
        await lock();
      });

      const refreshing = harness.auth.refreshIfNeeded(5_000);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      const locking = harness.auth.lock();
      await vi.waitFor(() => expect(lockSpy).toHaveBeenCalledOnce());
      rejectRefresh(new ApiHttpError(401, { error: 'invalid_grant' }));
      await vi.waitFor(() => expect(harness.transitionEvents).toContainEqual(expect.objectContaining({
        phase: 'start',
        reason: 'removeAccount',
      })));
      const resetting = harness.auth.resetForServerChange();
      releaseLock();

      await expect(Promise.all([refreshing, locking, resetting])).resolves.toBeDefined();
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('serializes invalid-grant cleanup behind queued transitions and removes its original owner', async () => {
      let rejectRefresh!: (error: Error) => void;
      const harness = await makeAccessTokenHarness({
        expiresAt: 1_100,
        refresh: () => new Promise((_resolve, reject) => { rejectRefresh = reject; }),
      });
      const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
      await harness.sm.saveUnlocked({
        email: 'other@example.com',
        accessToken: 'other-access',
        refreshToken: 'other-refresh',
        expiresAt: 999_999,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 5_000,
        userKey,
      });
      await harness.sm.saveUnlocked({
        email: 'user@example.com',
        accessToken: 'old-access-secret',
        refreshToken: 'old-refresh-secret',
        expiresAt: 1_100,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 5_000,
        userKey,
      });
      const lock = harness.sm.lock.bind(harness.sm);
      let releaseLock!: () => void;
      const lockGate = new Promise<void>((resolve) => { releaseLock = resolve; });
      const lockSpy = vi.spyOn(harness.sm, 'lock').mockImplementationOnce(async () => {
        await lockGate;
        await lock();
      });

      const refreshing = harness.auth.refreshIfNeeded(5_000);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      const locking = harness.auth.lock();
      await vi.waitFor(() => expect(lockSpy).toHaveBeenCalledOnce());
      const toOther = harness.auth.switchAccount('other@example.com');
      const backToOriginal = harness.auth.switchAccount('user@example.com');
      rejectRefresh(new ApiHttpError(401, { error: 'invalid_grant' }));

      releaseLock();
      await expect(Promise.all([refreshing, locking, toOther, backToOriginal])).resolves.toBeDefined();
      expect((await harness.sm.getPersistedAuth())?.email).toBe('other@example.com');
      expect((await harness.sm.listAccounts()).map((account) => account.email)).toEqual([
        'other@example.com',
      ]);
    });

    it('forces one refresh after a 401 and rebuilds the request with the persisted token', async () => {
      const harness = await makeAccessTokenHarness();
      const bodies: Array<{ readonly token: string; readonly nonce: object }> = [];
      const request = vi.fn(async (token: string) => {
        const body = { token, nonce: {} };
        bodies.push(body);
        if (token === 'old-access-secret') throw new ApiHttpError(401, 'expired');
        return body;
      });

      await expect(harness.auth.executeAuthenticatedRequest(
        harness.accountLease,
        request,
      )).resolves.toMatchObject({ token: 'new-access-secret' });

      expect(request.mock.calls.map(([token]) => token)).toEqual([
        'old-access-secret',
        'new-access-secret',
      ]);
      expect(bodies[0]).not.toBe(bodies[1]);
      expect(harness.refresh).toHaveBeenCalledOnce();
    });

    it('coalesces concurrent 401 recovery into one forced refresh', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });
      const request = vi.fn(async (token: string) => {
        if (token === 'old-access-secret') throw new ApiHttpError(401, 'expired');
        return token;
      });

      const first = harness.auth.executeAuthenticatedRequest(harness.accountLease, request);
      const second = harness.auth.executeAuthenticatedRequest(harness.accountLease, request);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      resolveRefresh({
        access_token: 'shared-access',
        refresh_token: 'shared-refresh',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await expect(Promise.all([first, second])).resolves.toEqual([
        'shared-access',
        'shared-access',
      ]);
      expect(harness.refresh).toHaveBeenCalledOnce();
      expect(request).toHaveBeenCalledTimes(4);
    });

    it.each([
      ['403', new ApiHttpError(403, 'forbidden')],
      ['500', new ApiHttpError(500, 'server failure')],
      ['network failure', new Error('offline')],
    ])('does not refresh or replay an initial %s', async (_label, failure) => {
      const harness = await makeAccessTokenHarness();
      const request = vi.fn(async () => { throw failure; });

      await expect(harness.auth.executeAuthenticatedRequest(
        harness.accountLease,
        request,
      )).rejects.toBe(failure);

      expect(request).toHaveBeenCalledOnce();
      expect(harness.refresh).not.toHaveBeenCalled();
      await expect(harness.sm.getState()).resolves.toBe('unlocked');
    });

    it.each([
      ['500', new ApiHttpError(500, 'refresh server failure')],
      ['network failure', new Error('refresh offline')],
    ])('does not replay when the forced refresh ends in a %s', async (_label, refreshFailure) => {
      const harness = await makeAccessTokenHarness({
        refresh: async () => { throw refreshFailure; },
      });
      const request = vi.fn(async () => { throw new ApiHttpError(401, 'expired'); });

      await expect(harness.auth.executeAuthenticatedRequest(
        harness.accountLease,
        request,
      )).rejects.toMatchObject({ code: 'session_expired' });

      expect(request).toHaveBeenCalledOnce();
      expect(harness.refresh).toHaveBeenCalledOnce();
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('does not let a late forced refresh overwrite a newer access token with the same refresh token', async () => {
      let resolveRefresh!: (value: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
      }) => void;
      const harness = await makeAccessTokenHarness({
        refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
      });
      const request = vi.fn(async (token: string) => {
        if (token === 'old-access-secret') throw new ApiHttpError(401, 'expired');
        return token;
      });
      const executing = harness.auth.executeAuthenticatedRequest(harness.accountLease, request);
      await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());
      await expect(harness.sm.saveTokensFor({
        email: 'user@example.com',
        accessToken: 'old-access-secret',
        refreshToken: 'old-refresh-secret',
      }, {
        accessToken: 'concurrent-access',
        refreshToken: 'old-refresh-secret',
        expiresAt: 999_999,
      })).resolves.toBe(true);
      resolveRefresh({
        access_token: 'late-access',
        refresh_token: 'old-refresh-secret',
        expires_in: 3_600,
        token_type: 'Bearer',
      });

      await expect(executing).resolves.toBe('concurrent-access');
      expect(request.mock.calls.map(([token]) => token)).toEqual([
        'old-access-secret',
        'concurrent-access',
      ]);
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'concurrent-access',
        refreshToken: 'old-refresh-secret',
      });
    });

    it.each(['account', 'server'] as const)(
      'persists the same credential but rejects its stale caller after a %s gate ABA',
      async (transitionKind) => {
        let resolveRefresh!: (value: {
          access_token: string;
          refresh_token: string;
          expires_in: number;
          token_type: string;
        }) => void;
        const harness = await makeAccessTokenHarness({
          refresh: () => new Promise((resolve) => { resolveRefresh = resolve; }),
        });
        const request = vi.fn(async () => { throw new ApiHttpError(401, 'expired'); });
        const executing = harness.auth.executeAuthenticatedRequest(harness.accountLease, request);
        await vi.waitFor(() => expect(harness.refresh).toHaveBeenCalledOnce());

        if (transitionKind === 'account') {
          const away = harness.accountGate.beginAccountTransition();
          harness.accountGate.endAccountTransition(away, {
            serverUrl: 'https://vault.example/tenant/', accountIdentity: 'other@example.com',
          });
          const back = harness.accountGate.beginAccountTransition();
          harness.accountGate.endAccountTransition(back, {
            serverUrl: 'https://vault.example/tenant/', accountIdentity: 'user@example.com',
          });
        } else {
          const away = harness.accountGate.beginServerTransition();
          harness.accountGate.endServerTransition(away, {
            serverUrl: 'https://other.example/', accountIdentity: 'user@example.com',
          });
          const back = harness.accountGate.beginServerTransition();
          harness.accountGate.endServerTransition(back, {
            serverUrl: 'https://vault.example/tenant/', accountIdentity: 'user@example.com',
          });
        }
        resolveRefresh({
          access_token: 'must-not-persist',
          refresh_token: 'must-not-persist',
          expires_in: 3_600,
          token_type: 'Bearer',
        });

        await expect(executing).rejects.toMatchObject({ code: 'session_expired' });
        expect(request).toHaveBeenCalledOnce();
        expect((await harness.sm.getPersistedAuth())?.accessToken).toBe('must-not-persist');
        expect(harness.transitionEvents.some((event) => event.reason === 'logout')).toBe(false);
      },
    );

    it('logs out only the exact current account after the refreshed token also returns 401', async () => {
      const cleanup = vi.fn(async () => undefined);
      const harness = await makeAccessTokenHarness({ onIdentityChanged: cleanup });
      const request = vi.fn(async (_token: string) => {
        throw new ApiHttpError(401, 'still unauthorized');
      });

      await expect(harness.auth.executeAuthenticatedRequest(
        harness.accountLease,
        request,
      )).rejects.toMatchObject({ status: 401 });

      expect(request.mock.calls.map(([token]) => token)).toEqual([
        'old-access-secret',
        'new-access-secret',
      ]);
      expect(harness.refresh).toHaveBeenCalledOnce();
      expect(cleanup).toHaveBeenCalledOnce();
      await expect(harness.sm.getState()).resolves.toBe('loggedOut');
    });

    it('does not let a late second 401 log out a newer token generation', async () => {
      let rejectRetry!: (error: Error) => void;
      const cleanup = vi.fn(async () => undefined);
      const harness = await makeAccessTokenHarness({ onIdentityChanged: cleanup });
      const request = vi.fn((token: string): Promise<string> => {
        if (token === 'old-access-secret') {
          return Promise.reject(new ApiHttpError(401, 'expired'));
        }
        return new Promise((_resolve, reject) => { rejectRetry = reject; });
      });
      const executing = harness.auth.executeAuthenticatedRequest(harness.accountLease, request);
      await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(2));
      await expect(harness.sm.saveTokensFor({
        email: 'user@example.com',
        accessToken: 'new-access-secret',
        refreshToken: 'new-refresh-secret',
      }, {
        accessToken: 'newest-access',
        refreshToken: 'newest-refresh',
        expiresAt: 999_999,
      })).resolves.toBe(true);

      rejectRetry(new ApiHttpError(401, 'late unauthorized'));

      await expect(executing).rejects.toMatchObject({ status: 401 });
      expect(cleanup).not.toHaveBeenCalled();
      expect(await harness.sm.getPersistedAuth()).toMatchObject({
        accessToken: 'newest-access',
        refreshToken: 'newest-refresh',
      });
      await expect(harness.sm.getState()).resolves.toBe('unlocked');
    });

    it('does not log out when the rebuilt request returns 403', async () => {
      const cleanup = vi.fn(async () => undefined);
      const harness = await makeAccessTokenHarness({ onIdentityChanged: cleanup });
      const forbidden = new ApiHttpError(403, 'forbidden');
      const request = vi.fn(async (token: string) => {
        if (token === 'old-access-secret') throw new ApiHttpError(401, 'expired');
        throw forbidden;
      });

      await expect(harness.auth.executeAuthenticatedRequest(
        harness.accountLease,
        request,
      )).rejects.toBe(forbidden);

      expect(request).toHaveBeenCalledTimes(2);
      expect(cleanup).not.toHaveBeenCalled();
      await expect(harness.sm.getState()).resolves.toBe('unlocked');
    });

    it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])(
      'rejects an invalid refresh skew before reading credentials: %s',
      async (skewMs) => {
        const harness = await makeAccessTokenHarness();
        const read = vi.spyOn(harness.sm, 'getActiveAuth');
        await expect(harness.auth.getAccessToken(
          harness.sessionLease,
          harness.accountLease,
          skewMs,
        )).rejects.toBeInstanceOf(RangeError);
        await expect(harness.auth.getAccountAccessToken(
          harness.accountLease,
          skewMs,
        )).rejects.toBeInstanceOf(RangeError);
        expect(read).not.toHaveBeenCalled();
        expect(harness.refresh).not.toHaveBeenCalled();
      },
    );
  });

  // --- Finding 5: logout clears pending login ---
  it('logout clears pending login so subsequent submitTwoFactor rejects with session_expired', async () => {
    const api: Partial<ApiClient> = {
      prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
      passwordLogin: vi.fn().mockResolvedValue({ kind: 'twoFactor' as const, providers: [0], token: 'tf' }),
    };
    const { auth } = makeService(api);
    await auth.login({ email: KDF_VECTOR_600K.email, masterPassword: KDF_VECTOR_600K.password });
    await auth.logout();
    await expect(
      auth.submitTwoFactor({ provider: 0, code: '000000' }),
    ).rejects.toMatchObject({ code: 'session_expired' });
  });

  it.each([
    ['currentCredential' as const, ['a@example.com']],
    ['allAccounts' as const, []],
  ])('revokes %s through a serialized security-stamp transition', async (scope, remaining) => {
    const events: SessionTransitionEvent[] = [];
    const onIdentityChanged = vi.fn(async () => {});
    const { auth, sm } = makeService(
      {},
      undefined,
      onIdentityChanged,
      (event) => { events.push(event); },
    );
    const save = (email: string) => sm.saveUnlocked({
      email,
      accessToken: `access-${email}`,
      refreshToken: `refresh-${email}`,
      expiresAt: 999_999,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await save('a@example.com');
    await save('b@example.com');

    const expected = (await sm.getActiveAuthSnapshot())!.tokenLease;
    await expect(auth.revokeForSecurityStampFailure(expected, scope)).resolves.toBe(true);

    expect((await sm.listAccounts()).map((account) => account.email)).toEqual(remaining);
    expect(onIdentityChanged).toHaveBeenCalledOnce();
    expect(events).toMatchObject([
      { phase: 'start', reason: 'logout', identityChanged: true },
      { phase: 'settled', reason: 'logout', identityChanged: true, succeeded: true },
    ]);
  });

  it.each(['currentCredential', 'allAccounts'] as const)(
    'does not revoke account B when a delayed account-A stamp callback requests %s',
    async (scope) => {
      const { auth, sm } = makeService({});
      const save = (email: string) => sm.saveUnlocked({
        email,
        accessToken: `access-${email}`,
        refreshToken: `refresh-${email}`,
        expiresAt: 999_999,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 5_000,
        userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
      });
      await save('a@example.com');
      const accountA = (await sm.getActiveAuthSnapshot())!.tokenLease;
      await save('b@example.com');

      await expect(auth.revokeForSecurityStampFailure(accountA, scope)).resolves.toBe(false);

      const accounts = await sm.listAccounts();
      expect(accounts.map((account) => account.email).sort()).toEqual([
        'a@example.com',
        'b@example.com',
      ]);
      expect(accounts.find((account) => account.active)?.email).toBe('b@example.com');
    },
  );

  // --- #9: refresh with a permanently-invalid token clears the dead session ---
  it('refreshIfNeeded clears the session on a 400 invalid_grant (revoked refresh token)', async () => {
    const refresh = vi.fn(async () => { throw new ApiHttpError(400, { error: 'invalid_grant' }); });
    const { auth, sm } = makeService({ refresh });
    await sm.saveUnlocked({
      email: KDF_VECTOR.email, accessToken: 'old-access', refreshToken: 'dead-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await expect(auth.refreshIfNeeded(5000)).resolves.toBeUndefined();
    expect(await sm.getPersistedAuth()).toBeUndefined(); // session cleared, user driven to re-login
  });

  it('logs out the same account after invalid_grant even when its session binding changed', async () => {
    let rejectRefresh!: (error: Error) => void;
    const refresh = vi.fn(() => new Promise<never>((_resolve, reject) => { rejectRefresh = reject; }));
    const { auth, sm } = makeService({ refresh });
    const input = {
      email: KDF_VECTOR.email, accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0 as const, kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    };
    await sm.saveUnlocked(input);
    const refreshing = auth.refreshIfNeeded(5000);
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    await sm.lock();
    await sm.saveUnlocked(input, { replaceCredential: false });

    rejectRefresh(new ApiHttpError(400, { error: 'invalid_grant' }));

    await expect(refreshing).resolves.toBeUndefined();
    expect(await sm.getPersistedAuth()).toBeUndefined();
  });

  it('retires the credential for any dispatched structured refresh error', async () => {
    const error = new ApiHttpError(400, { error: 'invalid_request' });
    const refresh = vi.fn(async () => { throw error; });
    const { auth, sm } = makeService({ refresh });
    await sm.saveUnlocked({
      email: KDF_VECTOR.email, accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });

    await expect(auth.refreshIfNeeded(5000)).resolves.toBeUndefined();
    await expect(sm.getState()).resolves.toBe('loggedOut');
  });

  it('removes the original credential after invalid_grant across A-B-A switching', async () => {
    let rejectRefresh!: (error: Error) => void;
    const refresh = vi.fn(() => new Promise<never>((_resolve, reject) => {
      rejectRefresh = reject;
    }));
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const key = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({
      email: 'b@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey: key,
    });
    await sm.saveUnlocked({
      email: 'a@example.com', accessToken: 'a-old', refreshToken: 'ra', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey: key,
    });
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({ serverUrl: 'https://vault.example', accountIdentity: 'a@example.com' });
    const sessionGate = new SessionGate('unlocked');
    const auth = new AuthService({
      api: mockApiClient({ refresh }),
      session: sm,
      sessionGate,
      accountGate,
      serverUrlProvider: async () => 'https://vault.example',
      now: () => 1000,
      onSessionTransition: sessionGate.handleTransition,
      onSerializedSessionTransition: accountLifecycleHook(accountGate, sm),
    });
    const switchAccount = sm.switchAccount.bind(sm);
    let releaseFirstSwitch!: () => void;
    const firstSwitchGate = new Promise<void>((resolve) => { releaseFirstSwitch = resolve; });
    vi.spyOn(sm, 'switchAccount').mockImplementationOnce(async (email) => {
      await firstSwitchGate;
      await switchAccount(email);
    });

    const refreshing = auth.refreshIfNeeded(5000);
    await vi.waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    const toB = auth.switchAccount('b@example.com');
    await vi.waitFor(() => expect(sm.switchAccount).toHaveBeenCalledOnce());
    const backToA = auth.switchAccount('a@example.com');
    rejectRefresh(new ApiHttpError(401, { error: 'invalid_grant' }));
    releaseFirstSwitch();

    await expect(Promise.all([refreshing, toB, backToA])).resolves.toBeDefined();
    expect((await sm.getPersistedAuth())?.email).toBe('b@example.com');
    expect((await sm.listAccounts()).map((account) => account.email)).toEqual(['b@example.com']);
  });

  it('retires a credential after a dispatched transient refresh error', async () => {
    const refresh = vi.fn(async () => { throw new ApiHttpError(500, 'bad gateway'); });
    const { auth, sm } = makeService({ refresh });
    await sm.saveUnlocked({
      email: KDF_VECTOR.email, accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1100,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5_000,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await expect(auth.refreshIfNeeded(5000)).resolves.toBeUndefined();
    await expect(sm.getState()).resolves.toBe('loggedOut');
  });

  // --- #9: account email is normalized before it reaches the session store ---
  it('switchAccount and removeAccount normalize a mixed-case/whitespace email', async () => {
    const { auth, sm } = makeService({});
    const userKey = { encKey: new Uint8Array(32), macKey: new Uint8Array(32) };
    await sm.saveUnlocked({ email: 'active@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999, protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey });
    await sm.saveUnlocked({ email: 'other@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999, protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey });
    const switchSpy = vi.spyOn(sm, 'switchAccount');
    const removeSpy = vi.spyOn(sm, 'removeAccount');
    await auth.switchAccount('  ACTIVE@Example.com  ');
    expect(switchSpy).toHaveBeenCalledWith('active@example.com');
    await auth.removeAccount('  OTHER@Example.com  ');
    expect(removeSpy).toHaveBeenCalledWith('other@example.com');
  });

  // --- #lock-purge: lock runs the onLock hook, best-effort ---
  it('lock() runs the onLock hook and still succeeds when the hook throws', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    const sessionGate: SessionLeaseGate = { capture: () => ({ generation: 0 }), assert: () => {} };
    const onLock = vi.fn(async () => {});
    const auth = new AuthService({ api: {} as ApiClient, session: sm, sessionGate, now: () => 1000, onLock });
    await auth.lock();
    expect(onLock).toHaveBeenCalledTimes(1);

    const throwing = new AuthService({
      api: {} as ApiClient,
      session: sm,
      sessionGate,
      now: () => 1000,
      onLock: async () => { throw new Error('purge failed'); },
    });
    await expect(throwing.lock()).resolves.toBeUndefined();
  });

  // PIN unlock tests use a 5000-iteration KDF so the PBKDF2 derivation stays fast.
  async function makeUnlocked(onSessionTransition?: (event: SessionTransitionEvent) => void) {
    const { auth, sm } = makeService({}, undefined, undefined, onSessionTransition);
    const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    await sm.saveUnlocked({
      email: 'u@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      kdf: 0, kdfIterations: 5000, userKey,
    });
    return { auth, sm, userKey };
  }

  async function makePolicyUnlocked(control: ReturnType<typeof createPinPolicyControl>) {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const sm = new SessionManager({ localStore, sessionStore });
    const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    await sm.saveUnlocked({
      email: 'u@example.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      kdf: 0, kdfIterations: 5000, userKey,
    });
    const auth = new AuthService({
      api: mockApiClient({}),
      session: sm,
      sessionGate: { capture: () => ({ generation: 0 }), assert: () => {} },
      enterprisePolicyGate: control.gate,
      now: () => 1000,
    });
    return { auth, sm, userKey, localStore, sessionStore };
  }

  it('sets a PIN and unlocks with it after locking', async () => {
    const events: SessionTransitionEvent[] = [];
    const { auth, sm, userKey } = await makeUnlocked((event) => { events.push(event); });
    await auth.setPin('1357');
    expect(await auth.isPinEnabled()).toBe(true);
    await sm.lock();
    expect(await sm.getState()).toBe('locked');
    const saveUnlocked = sm.saveUnlocked.bind(sm);
    let transientUserKey: SymmetricKey | undefined;
    let transientPrivateKey: Uint8Array | undefined;
    vi.spyOn(sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      transientUserKey = input.userKey;
      transientPrivateKey = input.privateKey;
      await saveUnlocked(input);
    });
    await auth.unlockWithPin('1357');
    expect(await sm.getState()).toBe('unlocked');
    expect(bytesToHex((await sm.loadUserKey())!.encKey)).toBe(bytesToHex(userKey.encKey));
    expect(events.map((event) => [event.phase, event.reason])).toEqual([
      ['start', 'pinUnlock'],
      ['settled', 'pinUnlock'],
    ]);
    expect(transientUserKey?.encKey).toEqual(new Uint8Array(32));
    expect(transientUserKey?.macKey).toEqual(new Uint8Array(32));
    expect(transientPrivateKey?.every((value) => value === 0)).toBe(true);
    expect(await sm.loadPrivateKey()).toBeDefined();
  });

  it('uses the target account PIN state across an A to B to A switch', async () => {
    const { auth, sm } = makeService({});
    const accountUserKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    await sm.saveUnlocked({
      email: 'b@example.com', accessToken: 'b', refreshToken: 'rb', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: accountUserKey,
    });
    await sm.saveUnlocked({
      email: 'a@example.com', accessToken: 'a', refreshToken: 'ra', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000,
      userKey: accountUserKey,
    });
    await auth.setPin('1357');

    await auth.switchAccount('b@example.com');

    await expect(auth.getPinStatus()).resolves.toEqual({
      enabled: false,
      available: false,
      allowed: true,
      requireMasterPasswordOnRestart: true,
    });
    expect(await sm.getPinProtectedUserKey('a@example.com')).toBeDefined();

    await auth.switchAccount('a@example.com');

    await expect(auth.getPinStatus()).resolves.toEqual({
      enabled: true,
      available: true,
      allowed: true,
      requireMasterPasswordOnRestart: true,
    });
    await expect(auth.unlockWithPin('1357')).resolves.toBeUndefined();
    expect(await sm.getState()).toBe('unlocked');
  });

  it('does not let a PIN commit cross an account switch', async () => {
    const gate = new SessionGate('unlocked');
    const { auth, sm } = makeService({}, undefined, undefined, gate.handleTransition, gate);
    const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    await sm.saveUnlocked({
      email: 'other@example.com', accessToken: 'other', refreshToken: 'other-refresh', expiresAt: 999999,
      protectedKey: 'other-protected-key', kdf: 0, kdfIterations: 5000, userKey,
    });
    await sm.saveUnlocked({
      email: 'active@example.com', accessToken: 'active', refreshToken: 'active-refresh', expiresAt: 999999,
      protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 5000, userKey,
    });
    const savePin = sm.savePinProtectedUserKey.bind(sm);
    let releaseCommit!: () => void;
    const commitGate = new Promise<void>((resolve) => { releaseCommit = resolve; });
    vi.spyOn(sm, 'savePinProtectedUserKey').mockImplementationOnce(async (blob, options) => {
      await commitGate;
      await savePin(blob, options);
    });

    const setting = auth.setPin('1357');
    const rejected = expect(setting).rejects.toMatchObject({ code: 'session_expired' });
    await vi.waitFor(() => expect(sm.savePinProtectedUserKey).toHaveBeenCalledTimes(1));
    const switching = auth.switchAccount('other@example.com');
    releaseCommit();

    await rejected;
    await switching;
    expect((await sm.getPersistedAuth())?.email).toBe('other@example.com');
    expect(await sm.getPinProtectedUserKey()).toBeUndefined();
  });

  it('rejects unlock with the wrong PIN', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('1357');
    await sm.lock();
    await expect(auth.unlockWithPin('0000')).rejects.toMatchObject({ code: 'invalid_pin' });
    expect(await sm.getState()).toBe('locked');
  });

  it('accepts any non-blank PIN with at least four characters', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('a$ 1');
    await sm.lock();

    await expect(auth.unlockWithPin('a$ 1')).resolves.toBeUndefined();
    expect(await sm.getState()).toBe('unlocked');
  });

  it('rejects short and whitespace-only PINs before writing PIN state', async () => {
    const { auth, sm } = await makeUnlocked();
    const save = vi.spyOn(sm, 'savePinProtectedUserKey');

    await expect(auth.setPin('123')).rejects.toThrow('at least 4 characters');
    await expect(auth.setPin('    ')).rejects.toThrow('at least 4 characters');
    expect(save).not.toHaveBeenCalled();
  });

  it('rejects an oversized PIN before deriving or persisting set-PIN material', async () => {
    const { auth, sm } = await makeUnlocked();
    const save = vi.spyOn(sm, 'savePinProtectedUserKey');
    const internal = auth as unknown as {
      derivePinKey(pin: string, email: string, kdf: KdfConfig): Promise<SymmetricKey>;
    };
    const derive = vi.spyOn(internal, 'derivePinKey');

    await expect(auth.setPin('a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1)))
      .rejects.toThrow('at most');

    expect(derive).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
  });

  it('rejects an oversized unlock without KDF work or consuming a failed attempt', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('valid-pin');
    await sm.lock();
    const internal = auth as unknown as {
      derivePinKey(pin: string, email: string, kdf: KdfConfig): Promise<SymmetricKey>;
    };
    const derive = vi.spyOn(internal, 'derivePinKey');
    const recordFailure = vi.spyOn(sm, 'recordFailedPinAttempt');

    await expect(auth.unlockWithPin('a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1)))
      .rejects.toThrow('at most');

    expect(derive).not.toHaveBeenCalled();
    expect(recordFailure).not.toHaveBeenCalled();
    expect(await sm.getState()).toBe('locked');
  });

  it('logs out and clears local account state after five consecutive invalid PINs', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('correct horse');
    await sm.lock();

    for (let attempt = 1; attempt < 5; attempt++) {
      await expect(auth.unlockWithPin(`wrong-${attempt}`))
        .rejects.toMatchObject({ code: 'invalid_pin' });
      expect(await sm.getState()).toBe('locked');
    }
    await expect(auth.unlockWithPin('wrong-5'))
      .rejects.toMatchObject({ code: 'pin_attempts_exceeded' });

    expect(await sm.getState()).toBe('loggedOut');
    expect(await sm.listAccounts()).toEqual([]);
    expect(await sm.getPinProtectedUserKey('u@example.com')).toBeUndefined();
  });

  it('cannot cancel the owner-bound logout after the fifth failure is persisted', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('valid-pin');
    await sm.lock();
    const record = sm.recordFailedPinAttempt.bind(sm);
    const internal = auth as unknown as { beginActivationAttempt(): number };
    vi.spyOn(sm, 'recordFailedPinAttempt').mockImplementation(async (owner, credentialId) => {
      const attempts = await record(owner, credentialId);
      if (attempts === 5) internal.beginActivationAttempt();
      return attempts;
    });

    for (let attempt = 0; attempt < 4; attempt++) {
      await expect(auth.unlockWithPin('wrong-pin'))
        .rejects.toMatchObject({ code: 'invalid_pin' });
    }
    await expect(auth.unlockWithPin('wrong-pin'))
      .rejects.toMatchObject({ code: 'pin_attempts_exceeded' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('resets the consecutive failure count after a successful PIN unlock', async () => {
    const { auth, sm } = await makeUnlocked();
    await auth.setPin('valid-pin');
    await sm.lock();
    for (let attempt = 0; attempt < 4; attempt++) {
      await expect(auth.unlockWithPin('wrong-pin'))
        .rejects.toMatchObject({ code: 'invalid_pin' });
    }
    await auth.unlockWithPin('valid-pin');
    await auth.lock();
    for (let attempt = 0; attempt < 4; attempt++) {
      await expect(auth.unlockWithPin('wrong-again'))
        .rejects.toMatchObject({ code: 'invalid_pin' });
    }

    expect(await sm.getState()).toBe('locked');
    expect(await sm.listAccounts()).toEqual([{ email: 'u@example.com', active: true }]);
  });

  it('does not count malformed PIN state as an invalid credential attempt', async () => {
    const { auth, sm } = await makeUnlocked();
    await sm.savePinProtectedUserKey('not-an-enc-string', {
      requireMasterPasswordOnRestart: false,
    });
    await sm.lock();

    for (let attempt = 0; attempt < 5; attempt++) {
      await expect(auth.unlockWithPin('anything')).rejects.not.toMatchObject({
        code: 'invalid_pin',
      });
    }
    expect(await sm.getState()).toBe('locked');
    expect(await sm.listAccounts()).toEqual([{ email: 'u@example.com', active: true }]);
  });

  it('rearms the default PIN only after the first master-password unlock after browser restart', async () => {
    const localStore = createMemoryStore();
    const firstBrowserSession = createMemoryStore();
    const firstSession = new SessionManager({ localStore, sessionStore: firstBrowserSession });
    const email = 'restart@example.com';
    const password = 'master-password';
    const kdf = { kdf: 0 as const, kdfIterations: 5000 };
    const restartUserKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    const stretchedMasterKey = await stretchMasterKey(await deriveMasterKey(password, email, kdf));
    const rawUserKey = serializeSymmetricKey(restartUserKey);
    const protectedKey = await encryptToBytes(rawUserKey, stretchedMasterKey);
    stretchedMasterKey.encKey.fill(0);
    stretchedMasterKey.macKey.fill(0);
    rawUserKey.fill(0);
    await firstSession.saveUnlocked({
      email, accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
      protectedKey, ...kdf, userKey: restartUserKey,
    });
    const firstGate = new SessionGate('unlocked');
    const firstAuth = new AuthService({
      api: mockApiClient({}),
      session: firstSession,
      sessionGate: firstGate,
      onSessionTransition: firstGate.handleTransition,
    });
    await firstAuth.setPin('word-pin');

    const restartedSession = new SessionManager({
      localStore,
      sessionStore: createMemoryStore(),
    });
    await restartedSession.initialize();
    expect(await restartedSession.getPinStateSummary()).toEqual({
      configured: true,
      available: false,
      requireMasterPasswordOnRestart: true,
    });
    const restartedGate = new SessionGate('locked');
    const restartedAuth = new AuthService({
      api: mockApiClient({}),
      session: restartedSession,
      sessionGate: restartedGate,
      onSessionTransition: restartedGate.handleTransition,
    });

    await restartedAuth.unlock(password);
    expect(await restartedSession.getPinStateSummary()).toMatchObject({ available: true });
    await restartedAuth.lock();
    await expect(restartedAuth.unlockWithPin('word-pin')).resolves.toBeUndefined();
    expect(await restartedSession.getState()).toBe('unlocked');
  });

  it('disablePin removes the PIN-protected key', async () => {
    const { auth } = await makeUnlocked();
    await auth.setPin('1357');
    await auth.disablePin();
    expect(await auth.isPinEnabled()).toBe(false);
  });

  it('rejects setPin before PIN work when organization policy denies it', async () => {
    const control = createPinPolicyControl(false);
    const { auth, sm } = await makePolicyUnlocked(control);
    const save = vi.spyOn(sm, 'savePinProtectedUserKey');

    await expect(auth.setPin('1357')).rejects.toMatchObject({ code: 'denied' });
    expect(save).not.toHaveBeenCalled();
  });

  it('does not expose a stored PIN while the policy snapshot is unavailable', async () => {
    const control = createPinPolicyControl();
    const { auth, sm } = await makePolicyUnlocked(control);
    await sm.savePinProtectedUserKey('persisted-secret-blob', {
      requireMasterPasswordOnRestart: false,
    });
    control.makeUnavailable();

    await expect(auth.getPinStatus()).resolves.toEqual({
      enabled: false,
      available: false,
      allowed: false,
      requireMasterPasswordOnRestart: true,
    });
    await expect(auth.isPinEnabled()).resolves.toBe(false);
    expect(await sm.getPinProtectedUserKey()).toBe('persisted-secret-blob');
  });

  it('removes a PIN write when its policy lease becomes stale during persistence', async () => {
    const control = createPinPolicyControl();
    const { auth, sm } = await makePolicyUnlocked(control);
    const save = sm.savePinProtectedUserKey.bind(sm);
    vi.spyOn(sm, 'savePinProtectedUserKey').mockImplementationOnce(async (blob, options) => {
      await save(blob, options);
      control.deny();
    });

    await expect(auth.setPin('1357')).rejects.toMatchObject({ code: 'denied' });
    expect(await sm.getPinProtectedUserKey()).toBeUndefined();
  });

  it('rechecks policy after the asynchronous PIN KDF before persisting', async () => {
    const control = createPinPolicyControl();
    const { auth, sm } = await makePolicyUnlocked(control);
    const internal = auth as unknown as {
      derivePinKey(pin: string, email: string, kdf: KdfConfig): Promise<SymmetricKey>;
    };
    const derive = internal.derivePinKey.bind(auth);
    vi.spyOn(internal, 'derivePinKey').mockImplementationOnce(async (pin, email, kdf) => {
      const result = await derive(pin, email, kdf);
      control.deny();
      return result;
    });
    const save = vi.spyOn(sm, 'savePinProtectedUserKey');

    await expect(auth.setPin('1357')).rejects.toMatchObject({ code: 'denied' });
    expect(save).not.toHaveBeenCalled();
  });

  it('re-locks before failed settlement when PIN policy becomes stale during commit', async () => {
    const setupControl = createPinPolicyControl();
    const setup = await makePolicyUnlocked(setupControl);
    await setup.auth.setPin('1357');
    await setup.sm.lock();
    const control = createPinPolicyControl();
    const accountGate = new AccountLeaseGate();
    accountGate.initialize({
      serverUrl: 'https://vault.example',
      accountIdentity: 'u@example.com',
    });
    const sessionGate = new SessionGate('locked');
    const transitionEvents: SessionTransitionEvent[] = [];
    const auth = new AuthService({
      api: mockApiClient({}),
      session: setup.sm,
      sessionGate,
      accountGate,
      enterprisePolicyGate: control.gate,
      serverUrlProvider: async () => 'https://vault.example',
      now: () => 1000,
      onSessionTransition: (event) => {
        transitionEvents.push(event);
        sessionGate.handleTransition(event);
      },
      onSerializedSessionTransition: accountLifecycleHook(accountGate, setup.sm),
    });
    const saveUnlocked = setup.sm.saveUnlocked.bind(setup.sm);
    vi.spyOn(setup.sm, 'saveUnlocked').mockImplementationOnce(async (input) => {
      await saveUnlocked(input);
      control.deny();
    });

    await expect(auth.unlockWithPin('1357')).rejects.toMatchObject({ code: 'denied' });
    await expect(setup.sm.getState()).resolves.toBe('locked');
    expect(transitionEvents.at(-1)).toMatchObject({
      phase: 'settled',
      reason: 'pinUnlock',
      state: 'locked',
      succeeded: false,
    });
    expect(() => sessionGate.capture()).toThrow();
    expect(accountGate.capture()).toMatchObject({ accountIdentity: 'u@example.com' });
  });

  it('clears an existing PIN idempotently when RemoveUnlockWithPin takes effect', async () => {
    const control = createPinPolicyControl(false);
    const { auth, sm, localStore, sessionStore } = await makePolicyUnlocked(control);
    await sm.savePinProtectedUserKey('persisted-secret-blob', {
      encryptedPin: 'user-key-encrypted-pin',
    });
    const remove = vi.spyOn(sm, 'removePinProtectedUserKey');

    await auth.enforceCurrentEnterprisePolicy();
    await auth.enforceCurrentEnterprisePolicy();
    expect(await sm.getPinProtectedUserKey()).toBeUndefined();
    expect(await localStore.get('pinConfigurations')).toBeUndefined();
    expect(await sessionStore.get('pinEphemeralEnvelopes')).toBeUndefined();
    expect(await sessionStore.get('pinFailures')).toBeUndefined();
    expect(remove).toHaveBeenCalledTimes(2);
  });

  it('always allows disablePin even when PIN unlock is denied', async () => {
    const control = createPinPolicyControl(false);
    const { auth, sm } = await makePolicyUnlocked(control);
    await sm.savePinProtectedUserKey('persisted-secret-blob', {
      requireMasterPasswordOnRestart: false,
    });

    await expect(auth.disablePin()).resolves.toBeUndefined();
    expect(await sm.getPinProtectedUserKey()).toBeUndefined();
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

    it('does not save an old-server remember token after a server reset', async () => {
      const OLD_SERVER = 'https://old.example';
      const NEW_SERVER = 'https://new.example';
      let currentServer = OLD_SERVER;
      const serverUrlProvider = vi.fn(async () => currentServer);
      let resolveLogin!: (result: ReturnType<typeof successData>) => void;
      const passwordLogin = vi.fn(() => new Promise<ReturnType<typeof successData>>((resolve) => {
        resolveLogin = resolve;
      }));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api, serverUrlProvider);

      const login = auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      const rejected = expect(login).rejects.toMatchObject({ code: 'session_expired' });
      await vi.waitFor(() => expect(passwordLogin).toHaveBeenCalledOnce());
      await auth.resetForServerChange(async () => { currentServer = NEW_SERVER; });
      resolveLogin(successData('old-server-token'));

      await rejected;
      expect(serverUrlProvider).toHaveBeenCalledOnce();
      expect(await sm.getRememberDeviceToken(OLD_SERVER, email)).toBeUndefined();
      expect(await sm.getRememberDeviceToken(NEW_SERVER, email)).toBeUndefined();
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

    it('does not start authentication when no serverUrl is configured', async () => {
      const passwordLogin = vi.fn();
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api, async () => undefined);
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .rejects.toThrow('serverUrl is not configured');
      expect(passwordLogin).not.toHaveBeenCalled();
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

    it('keeps the stored token when a successful provider=5 reuse omits a replacement', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stored-T1');

      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'unlocked' });

      expect(passwordLogin).toHaveBeenCalledOnce();
      expect(passwordLogin).toHaveBeenCalledWith(expect.objectContaining({
        twoFactorProvider: 5,
        twoFactorToken: 'stored-T1',
      }));
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBe('stored-T1');
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

    it('definite HTTP 400 rejection clears the token and retries once without it', async () => {
      const passwordLogin = vi.fn()
        .mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }))
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

    it('outcome-unknown remember-token failure is neither replayed nor cleared', async () => {
      const failure = new ApiHttpError(503, { error: 'temporarily_unavailable' });
      const passwordLogin = vi.fn().mockRejectedValueOnce(failure);
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({
          kdf: 0 as const,
          kdfIterations: KDF_VECTOR_600K.iterations,
        }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stored-T1');

      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .rejects.toBe(failure);
      expect(passwordLogin).toHaveBeenCalledOnce();
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBe('stored-T1');
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
