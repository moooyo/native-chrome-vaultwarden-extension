import { describe, expect, it, vi } from 'vitest';
import { AppError } from '../core/errors.js';
import { ARCHIVE_FEATURE_FLAG } from '../core/api/server-capabilities.js';
import {
  ServerCapabilityManager,
  authorizeCipherArchive,
  authorizeCollectionNameOnlyUpdate,
  authorizeOrganizationDataOwnershipTransport,
  authorizeSshCipherType5Write,
  authorizeTwoFactorRecovery,
  type ServerCapabilityIdentity,
  type ServerCapabilityManagerDeps,
  type ServerConfigFetchRequest,
  type ServerConfigFetchResponse,
} from './server-capability-manager.js';

interface TestIdentityLease {
  readonly generation: number;
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
  readonly reject: (reason: unknown) => void;
}

type TestFetchConfig = (
  request: Readonly<ServerConfigFetchRequest>,
) => PromiseLike<ServerConfigFetchResponse>;

type TestFetchConfigMock = ReturnType<typeof vi.fn<TestFetchConfig>>;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept;
    reject = decline;
  });
  return { promise, resolve, reject };
}

function captureThrown(action: () => void): unknown {
  try {
    action();
  } catch (error) {
    return error;
  }
  throw new Error('Expected operation to throw');
}

function config(
  version = '2026.8.0',
  featureStates: Record<string, boolean | number | string> = {},
): ServerConfigFetchResponse {
  return {
    body: { version, server: { name: 'Vaultwarden' }, featureStates },
    responseBytes: 128,
  };
}

function makeHarness(
  overrides: Partial<ServerCapabilityManagerDeps<TestIdentityLease>> = {},
): {
  readonly manager: ServerCapabilityManager<TestIdentityLease>;
  readonly fetchConfig: TestFetchConfigMock;
  readonly setIdentity: (identity: ServerCapabilityIdentity) => void;
  readonly transition: (identity?: ServerCapabilityIdentity) => void;
} {
  let generation = 1;
  let identity: ServerCapabilityIdentity = {
    serverUrl: 'https://vault.example/base',
    accountIdentity: 'alice@example.test',
  };
  const fetchConfig = vi.fn<TestFetchConfig>(overrides.fetchConfig ?? (async () => config()));
  const deps: ServerCapabilityManagerDeps<TestIdentityLease> = {
    captureIdentity: () => ({ identity, lease: { generation } }),
    assertIdentityCurrent: (lease) => {
      if (lease.generation !== generation) throw new Error('stale identity');
    },
    ...overrides,
    fetchConfig,
  };
  return {
    manager: new ServerCapabilityManager(deps),
    fetchConfig,
    setIdentity: (next) => { identity = next; },
    transition: (next) => {
      generation += 1;
      if (next) identity = next;
    },
  };
}

describe('ServerCapabilityManager', () => {
  it('canonicalizes the full server base path and keeps anonymous and account caches distinct', async () => {
    const harness = makeHarness();
    harness.setIdentity({ serverUrl: ' HTTPS://Vault.Example:443/base ', accountIdentity: ' alice ' });

    const account = await harness.manager.resolve();
    expect(account.identity).toEqual({
      serverUrl: 'https://vault.example/base/',
      accountIdentity: 'alice',
    });
    expect(harness.fetchConfig).toHaveBeenCalledWith({
      serverUrl: 'https://vault.example/base/',
      configUrl: 'https://vault.example/base/api/config',
      maxResponseBytes: 65_536,
      credentials: 'omit',
    });
    expect(await harness.manager.resolve()).toBe(account);
    expect(harness.fetchConfig).toHaveBeenCalledOnce();

    harness.transition({ serverUrl: 'https://vault.example/base/' });
    const anonymous = await harness.manager.resolve();
    expect(anonymous.identity).toEqual({ serverUrl: 'https://vault.example/base/' });
    expect(harness.fetchConfig).toHaveBeenCalledTimes(2);
  });

  it('coalesces concurrent work for the same exact identity generation', async () => {
    const pending = deferred<ServerConfigFetchResponse>();
    const harness = makeHarness({ fetchConfig: vi.fn(() => pending.promise) });

    const first = harness.manager.resolve();
    const second = harness.manager.resolve();
    await vi.waitFor(() => expect(harness.fetchConfig).toHaveBeenCalledOnce());
    pending.resolve(config());

    const [left, right] = await Promise.all([first, second]);
    expect(left).toBe(right);
    expect(left.availability).toBe('available');
  });

  it('reuses an unexpired observation and refreshes at the TTL boundary', async () => {
    let now = 1_000;
    const harness = makeHarness({ now: () => now, ttlMs: 100 });

    const first = await harness.manager.resolve();
    now = 1_099;
    expect(await harness.manager.resolve()).toBe(first);
    expect(harness.fetchConfig).toHaveBeenCalledOnce();

    now = 1_100;
    const refreshed = await harness.manager.resolve();
    expect(refreshed).not.toBe(first);
    expect(refreshed.generation).toBeGreaterThan(first.generation);
    expect(harness.fetchConfig).toHaveBeenCalledTimes(2);
  });

  it('publishes a bounded fail-closed state for a transport failure and caches it briefly', async () => {
    const secretError = new Error('token=must-not-escape');
    const harness = makeHarness({ fetchConfig: vi.fn(async () => { throw secretError; }) });

    const snapshot = await harness.manager.resolve();
    expect(snapshot).toMatchObject({
      availability: 'unavailable',
      reason: 'fetch_failed',
      capabilities: {
        features: {
          fido2TwoFactor: 'unknown',
          loginWithDevice: 'unknown',
          accountPasskey: 'unavailable',
          sshCipherType5: 'unavailable',
          archive: 'unknown',
        },
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain('must-not-escape');
    expect(await harness.manager.resolve()).toBe(snapshot);
    expect(harness.fetchConfig).toHaveBeenCalledOnce();
  });

  it('retries an unavailable observation at its shorter TTL boundary', async () => {
    let now = 50;
    const fetchConfig = vi.fn<TestFetchConfig>(async () => { throw new Error('offline'); });
    const harness = makeHarness({ fetchConfig, now: () => now, unavailableTtlMs: 10 });
    const failed = await harness.manager.resolve();

    now = 59;
    expect(await harness.manager.resolve()).toBe(failed);
    now = 60;
    expect(await harness.manager.resolve()).not.toBe(failed);
    expect(harness.fetchConfig).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['non-object body', { body: [], responseBytes: 2 }],
    ['oversized body', { body: {}, responseBytes: 65_537 }],
    ['unmeasured body', { body: {}, responseBytes: Number.NaN }],
  ])('publishes invalid_response for a %s', async (_label, response) => {
    const harness = makeHarness({ fetchConfig: vi.fn(async () => response) });
    await expect(harness.manager.resolve()).resolves.toMatchObject({
      availability: 'unavailable', reason: 'invalid_response',
    });
  });

  it('does not publish a response after a server transition', async () => {
    const oldResponse = deferred<ServerConfigFetchResponse>();
    const fetchConfig = vi.fn()
      .mockImplementationOnce(() => oldResponse.promise)
      .mockResolvedValueOnce(config('2025.12.0'));
    const harness = makeHarness({ fetchConfig });

    const oldResolve = harness.manager.resolve();
    await vi.waitFor(() => expect(harness.fetchConfig).toHaveBeenCalledOnce());
    harness.transition({
      serverUrl: 'https://other.example/tenant',
      accountIdentity: 'alice@example.test',
    });
    const current = await harness.manager.resolve();
    oldResponse.resolve(config('2024.12.0'));

    await expect(oldResolve).rejects.toMatchObject({ code: 'denied' });
    expect(harness.manager.current()).toBe(current);
    expect(current.identity.serverUrl).toBe('https://other.example/tenant/');
  });

  it('detects account ABA and does not join or publish the first A request', async () => {
    const firstA = deferred<ServerConfigFetchResponse>();
    const secondA = deferred<ServerConfigFetchResponse>();
    const fetchConfig = vi.fn()
      .mockImplementationOnce(() => firstA.promise)
      .mockImplementationOnce(() => secondA.promise);
    const harness = makeHarness({ fetchConfig });

    const stale = harness.manager.resolve();
    await vi.waitFor(() => expect(harness.fetchConfig).toHaveBeenCalledOnce());
    harness.transition({
      serverUrl: 'https://vault.example/base',
      accountIdentity: 'bob@example.test',
    });
    harness.transition({
      serverUrl: 'https://vault.example/base',
      accountIdentity: 'alice@example.test',
    });

    const currentPromise = harness.manager.resolve();
    await vi.waitFor(() => expect(harness.fetchConfig).toHaveBeenCalledTimes(2));
    secondA.resolve(config('2026.8.0'));
    const current = await currentPromise;
    firstA.resolve(config('2024.12.0'));

    await expect(stale).rejects.toMatchObject({ code: 'denied' });
    expect(harness.manager.current()).toBe(current);
  });

  it('invalidates an in-flight publication and every previously issued capability lease', async () => {
    const pending = deferred<ServerConfigFetchResponse>();
    const harness = makeHarness({ fetchConfig: vi.fn(() => pending.promise) });
    const inFlight = harness.manager.resolve();
    await vi.waitFor(() => expect(harness.fetchConfig).toHaveBeenCalledOnce());
    harness.manager.invalidate();
    pending.resolve(config());
    await expect(inFlight).rejects.toMatchObject({ code: 'denied' });
    expect(harness.manager.current()).toBeUndefined();

    const resolved = await harness.manager.resolve();
    const lease = harness.manager.capture();
    expect(harness.manager.assert(lease)).toBe(resolved);
    harness.manager.invalidate();
    expect(() => harness.manager.assert(lease)).toThrow(AppError);
  });

  it('revokes a capability lease when its snapshot expires', async () => {
    let now = 10;
    const harness = makeHarness({ now: () => now, ttlMs: 5 });
    await harness.manager.resolve();
    const lease = harness.manager.capture();

    now = 15;
    expect(() => harness.manager.assert(lease)).toThrowError(
      'Server capability state changed during the operation.',
    );
    expect(harness.manager.current()).toBeUndefined();
  });

  it('rejects forged leases and invalid URL or account identity boundaries', async () => {
    const harness = makeHarness();
    await harness.manager.resolve();
    expect(() => harness.manager.assert({
      generation: harness.manager.current()!.generation,
      serverUrl: 'https://vault.example/base/',
      accountIdentity: 'alice@example.test',
    })).toThrowError('Server capability state changed during the operation.');

    harness.transition({ serverUrl: 'http://remote.example/base' });
    await expect(harness.manager.resolve()).rejects.toThrow('must use HTTPS');
    harness.transition({ serverUrl: 'https://vault.example/base', accountIdentity: 'a\nsecret' });
    await expect(harness.manager.resolve()).rejects.toThrow('account identity is invalid');
  });

  it('keeps old protocol versions unavailable', async () => {
    const harness = makeHarness({
      clientDeclaration: {
        advertisedProtocolVersion: '2026.8.0',
        supportedCipherTypes: [1, 2, 3, 4, 5],
      },
      fetchConfig: vi.fn(async () => config('2024.11.0')),
    });

    const snapshot = await harness.manager.resolve();
    expect(snapshot.availability).toBe('available');
    expect(snapshot.capabilities.config.protocolVersion).toBe('2024.11.0');
    expect(snapshot.capabilities.features.sshCipherType5).toBe('unavailable');
  });

  it('authorizes a type-5 write only for the current resolved capability generation', async () => {
    const harness = makeHarness({
      clientDeclaration: {
        advertisedProtocolVersion: '2024.12.0',
        supportedCipherTypes: [1, 2, 3, 4, 5],
      },
      fetchConfig: vi.fn(async () => config('2024.12.0', {
        'ssh-key-vault-item': false,
      })),
    });

    const authorization = await authorizeSshCipherType5Write(harness.manager);
    expect(Object.keys(authorization)).toEqual(['assertCurrent']);
    expect(() => authorization.assertCurrent()).not.toThrow();

    await harness.manager.resolve({ forceRefresh: true });
    expect(() => authorization.assertCurrent()).toThrowError(
      'Server capability state changed during the operation.',
    );
    const refreshedAuthorization = await authorizeSshCipherType5Write(harness.manager);

    harness.transition({
      serverUrl: 'https://vault.example/base',
      accountIdentity: 'bob@example.test',
    });
    harness.transition({
      serverUrl: 'https://vault.example/base',
      accountIdentity: 'alice@example.test',
    });
    expect(() => refreshedAuthorization.assertCurrent()).toThrowError(
      'Server capability state changed during the operation.',
    );
  });

  it.each([
    {
      label: 'a failed config fetch',
      declaration: { advertisedProtocolVersion: '2024.12.0', supportedCipherTypes: [1, 2, 3, 4, 5] },
      fetchConfig: async (): Promise<ServerConfigFetchResponse> => { throw new Error('offline'); },
    },
    {
      label: 'an old server protocol',
      declaration: { advertisedProtocolVersion: '2024.12.0', supportedCipherTypes: [1, 2, 3, 4, 5] },
      fetchConfig: async (): Promise<ServerConfigFetchResponse> => config('2024.11.0'),
    },
    {
      label: 'the production type 1-4 declaration',
      declaration: { advertisedProtocolVersion: '2024.11.0', supportedCipherTypes: [1, 2, 3, 4] },
      fetchConfig: async (): Promise<ServerConfigFetchResponse> => config('2026.8.0'),
    },
  ])('does not authorize a type-5 write with $label', async ({ declaration, fetchConfig }) => {
    const harness = makeHarness({ clientDeclaration: declaration, fetchConfig });

    await expect(authorizeSshCipherType5Write(harness.manager)).rejects.toMatchObject({
      code: 'denied',
    });
  });

  it('authorizes cipher archive on the GA protocol without the obsolete feature flag', async () => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => config('2026.8.0', {})),
    });

    const authorization = await authorizeCipherArchive(harness.manager);
    expect(Object.keys(authorization)).toEqual(['assertCurrent']);
    expect(Object.isFrozen(authorization)).toBe(true);
    expect(() => authorization.assertCurrent()).not.toThrow();
  });

  it('rejects cipher archive when an explicit feature flag disables it', async () => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => config('2026.8.0', {
        [ARCHIVE_FEATURE_FLAG]: false,
      })),
    });

    await expect(authorizeCipherArchive(harness.manager)).rejects.toMatchObject({
      code: 'denied',
      message: 'Cipher archiving is unavailable.',
    });
  });

  it.each([
    {
      label: 'an unavailable capability snapshot',
      fetchConfig: async (): Promise<ServerConfigFetchResponse> => {
        throw new Error('token=must-not-escape');
      },
    },
    {
      label: 'a pre-GA protocol',
      fetchConfig: async (): Promise<ServerConfigFetchResponse> => config('2026.3.99'),
    },
    {
      label: 'an unknown archive feature state',
      fetchConfig: async (): Promise<ServerConfigFetchResponse> => config('2026.8.0', {
        [ARCHIVE_FEATURE_FLAG]: 'true',
      }),
    },
  ])('returns one fixed archive denial for $label', async ({ fetchConfig }) => {
    const harness = makeHarness({ fetchConfig });

    await expect(authorizeCipherArchive(harness.manager)).rejects.toMatchObject({
      code: 'denied',
      message: 'Cipher archiving is unavailable.',
    });
  });

  it('revokes cipher archive authorization after capability or identity generation changes', async () => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => config('2026.8.0', {})),
    });

    const staleCapability = await authorizeCipherArchive(harness.manager);
    await harness.manager.resolve({ forceRefresh: true });
    const capabilityError = captureThrown(() => staleCapability.assertCurrent());
    expect(capabilityError).toBeInstanceOf(AppError);
    expect(capabilityError).toMatchObject({
      code: 'denied',
      message: 'Cipher archiving is unavailable.',
    });

    const staleIdentity = await authorizeCipherArchive(harness.manager);
    harness.transition({
      serverUrl: 'https://vault.example/base',
      accountIdentity: 'bob@example.test',
    });
    const identityError = captureThrown(() => staleIdentity.assertCurrent());
    expect(identityError).toBeInstanceOf(AppError);
    expect(identityError).toMatchObject({
      code: 'denied',
      message: 'Cipher archiving is unavailable.',
    });
  });

  it.each([
    ['vaultwarden', async (): Promise<ServerConfigFetchResponse> => config()],
    ['bitwarden', async (): Promise<ServerConfigFetchResponse> => ({
      body: { version: '2026.8.0', server: {}, featureStates: {} },
      responseBytes: 128,
    })],
  ] as const)('binds the %s ODO transport to one capability generation', async (serverKind, fetchConfig) => {
    const harness = makeHarness({ fetchConfig });
    const authorization = await authorizeOrganizationDataOwnershipTransport(harness.manager);

    expect(authorization.serverKind).toBe(serverKind);
    expect(() => authorization.assertCurrent()).not.toThrow();
    await harness.manager.resolve({ forceRefresh: true });
    expect(() => authorization.assertCurrent()).toThrowError(AppError);
  });

  it('authorizes name-only collection updates only on Bitwarden and revokes stale leases', async () => {
    const bitwarden = makeHarness({
      fetchConfig: vi.fn(async () => ({
        body: { version: '2026.8.0', server: {}, featureStates: {} },
        responseBytes: 128,
      })),
    });
    const authorization = await authorizeCollectionNameOnlyUpdate(bitwarden.manager);
    expect(() => authorization.assertCurrent()).not.toThrow();

    await bitwarden.manager.resolve({ forceRefresh: true });
    expect(() => authorization.assertCurrent()).toThrowError(AppError);

    const vaultwarden = makeHarness();
    await expect(authorizeCollectionNameOnlyUpdate(vaultwarden.manager)).rejects.toMatchObject({
      code: 'denied',
      message: 'Safe collection renaming is unavailable for this server.',
    });
  });

  it('binds the two-factor recovery route to the verified Web Vault base path', async () => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => ({
        body: {
          version: '2026.8.0',
          server: {},
          environment: { vault: 'https://web.example/tenant' },
          featureStates: {},
        },
        responseBytes: 256,
      })),
    });
    harness.setIdentity({ serverUrl: 'https://vault.example/base' });

    const authorization = await authorizeTwoFactorRecovery(harness.manager);

    expect(authorization.url).toBe('https://web.example/tenant/#/recover-2fa');
    expect(() => authorization.assertCurrent()).not.toThrow();
    await harness.manager.resolve({ forceRefresh: true });
    expect(() => authorization.assertCurrent()).toThrowError(expect.objectContaining({
      code: 'denied',
      message: 'Two-step recovery is unavailable for this server.',
    }));
  });

  it.each([
    ['missing Web Vault', { api: 'https://api.example/tenant' }],
    ['hostile Web Vault', { vault: 'javascript:alert(1)' }],
    ['Web Vault with query input', { vault: 'https://web.example/tenant?next=https://evil.example' }],
  ] as const)('denies recovery when config has a %s route', async (_label, environment) => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => ({
        body: { version: '2026.8.0', server: {}, environment, featureStates: {} },
        responseBytes: 256,
      })),
    });

    await expect(authorizeTwoFactorRecovery(harness.manager)).rejects.toMatchObject({
      code: 'denied',
      message: 'Two-step recovery is unavailable for this server.',
    });
  });

  it('revokes a recovery route across a server identity transition', async () => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => ({
        body: {
          version: '2026.8.0',
          server: {},
          environment: { vault: 'https://web.example/tenant' },
          featureStates: {},
        },
        responseBytes: 256,
      })),
    });
    const authorization = await authorizeTwoFactorRecovery(harness.manager);

    harness.transition({ serverUrl: 'https://other.example/' });

    expect(() => authorization.assertCurrent()).toThrowError(expect.objectContaining({
      code: 'denied',
      message: 'Two-step recovery is unavailable for this server.',
    }));
  });

  it('projects the real Bitwarden Lite config shape into bounded routing metadata', async () => {
    const harness = makeHarness({
      clientDeclaration: {
        advertisedProtocolVersion: '2026.8.0',
        supportedCipherTypes: [1, 2, 3, 4, 5],
      },
      fetchConfig: vi.fn(async () => ({
        body: {
          version: '2026.8.0',
          server: {},
          environment: {
            vault: 'http://127.0.0.1:18082',
            api: 'http://127.0.0.1:18082/base/api',
            identity: 'http://127.0.0.1:18082/base/identity',
            notifications: 'http://127.0.0.1:18082/base/notifications',
            sso: 'http://127.0.0.1:18082/base/sso',
            fillAssistRules: 'https://example.test/must-not-be-retained',
          },
          push: {
            pushTechnology: 0,
            vapidPublicKey: 'must-not-escape',
          },
          featureStates: {},
        },
        responseBytes: 1_024,
      })),
    });

    const snapshot = await harness.manager.resolve();
    expect(snapshot.availability).toBe('available');
    expect(snapshot.capabilities.config).toEqual({
      serverKind: 'unknown',
      protocolVersion: '2026.8.0',
      environment: {
        vault: 'http://127.0.0.1:18082/',
        api: 'http://127.0.0.1:18082/base/api/',
        identity: 'http://127.0.0.1:18082/base/identity/',
        notifications: 'http://127.0.0.1:18082/base/notifications/',
        sso: 'http://127.0.0.1:18082/base/sso/',
      },
      featureStates: {},
    });
    expect(snapshot.capabilities.features.sshCipherType5).toBe('available');
    expect(JSON.stringify(snapshot)).not.toContain('fillAssistRules');
    expect(JSON.stringify(snapshot)).not.toContain('must-not-escape');
  });

  it('drops hostile environment URLs while preserving valid service base paths', async () => {
    const harness = makeHarness({
      fetchConfig: vi.fn(async () => ({
        body: {
          version: '2026.8.0',
          server: {},
          environment: {
            vault: 'https://vault.example/base',
            api: 'https://user:secret@api.example/base/api',
            identity: 'https://identity.example/base?token=secret',
            notifications: 'http://push.example/base/notifications',
            sso: 'https://identity.example/base/../sso',
          },
          featureStates: {},
        },
        responseBytes: 512,
      })),
    });

    const snapshot = await harness.manager.resolve();
    expect(snapshot.capabilities.config.environment).toEqual({
      vault: 'https://vault.example/base/',
    });
    expect(JSON.stringify(snapshot)).not.toContain('secret');
  });

  it('does not expose an environment route through a stale capability lease', async () => {
    const fetchConfig = vi.fn<TestFetchConfig>()
      .mockResolvedValueOnce({
        body: {
          version: '2026.8.0',
          server: {},
          environment: { notifications: 'https://push-old.example/tenant' },
          featureStates: {},
        },
        responseBytes: 256,
      })
      .mockResolvedValueOnce({
        body: {
          version: '2026.8.0',
          server: {},
          environment: { notifications: 'https://push-new.example/other-tenant' },
          featureStates: {},
        },
        responseBytes: 256,
      });
    const harness = makeHarness({ fetchConfig });
    await harness.manager.resolve();
    const oldLease = harness.manager.capture();

    harness.transition({
      serverUrl: 'https://other.example/other-tenant',
      accountIdentity: 'alice@example.test',
    });
    const current = await harness.manager.resolve();

    expect(() => harness.manager.assert(oldLease)).toThrow(AppError);
    expect(current.capabilities.config.environment.notifications)
      .toBe('https://push-new.example/other-tenant/');
  });

  it('isolates two self-hosted base paths even when the origin is identical', async () => {
    const harness = makeHarness();
    const first = await harness.manager.resolve();
    const firstLease = harness.manager.capture();
    harness.transition({
      serverUrl: 'https://vault.example/other-base',
      accountIdentity: 'alice@example.test',
    });
    const second = await harness.manager.resolve();

    expect(first.capabilities.scope.serverUrl).toBe('https://vault.example/base/');
    expect(second.capabilities.scope.serverUrl).toBe('https://vault.example/other-base/');
    expect(() => harness.manager.assert(firstLease)).toThrow(AppError);
    expect(harness.fetchConfig.mock.calls.map(([request]) => request.configUrl)).toEqual([
      'https://vault.example/base/api/config',
      'https://vault.example/other-base/api/config',
    ]);
  });

  it('drops old identity caches instead of retaining an unbounded server/account history', async () => {
    const harness = makeHarness();
    const first = await harness.manager.resolve();
    for (let index = 0; index < 40; index++) {
      harness.transition({
        serverUrl: `https://vault-${index}.example/base`,
        accountIdentity: `account-${index}@example.test`,
      });
      await harness.manager.resolve();
    }
    harness.transition({
      serverUrl: 'https://vault.example/base',
      accountIdentity: 'alice@example.test',
    });

    const returned = await harness.manager.resolve();
    expect(returned).not.toBe(first);
    expect(harness.fetchConfig).toHaveBeenCalledTimes(42);
  });
});
