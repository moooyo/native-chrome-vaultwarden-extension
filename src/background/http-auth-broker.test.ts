import { afterEach, describe, expect, it, vi } from 'vitest';
import { AccountLeaseGate } from '../core/session/account-gate.js';
import { UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';
import { SessionGate } from './session-gate.js';
import {
  digestHttpAuthRequestId,
  HttpAuthBroker,
  parseEligibleChallenge,
  type HttpAuthBrokerDeps,
  type HttpAuthChallengeDetails,
} from './http-auth-broker.js';

const ORIGIN = 'http://127.0.0.1:18083';

function challenge(overrides: Partial<HttpAuthChallengeDetails> = {}): HttpAuthChallengeDetails {
  return {
    requestId: 'request-1',
    url: `${ORIGIN}/protected`,
    method: 'GET',
    frameId: 0,
    tabId: 4,
    type: 'main_frame',
    incognito: false,
    scheme: 'basic',
    challenger: { host: '127.0.0.1', port: 18083 },
    isProxy: false,
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function fixture(overrides: Partial<HttpAuthBrokerDeps> = {}) {
  const sessionGate = new SessionGate('unlocked');
  const accountGate = new AccountLeaseGate();
  accountGate.initialize({ serverUrl: 'https://vault.example/', accountIdentity: 'a@example.com' });
  const authorization = {
    defaultStrategy: UriMatchStrategy.Domain,
    assertCurrent: vi.fn(),
  };
  const claimed = new Set<string>();
  const deps: HttpAuthBrokerDeps = {
    ready: vi.fn(async () => undefined),
    readHttpAuthSettings: vi.fn(async () => ({
      valid: true,
      settings: { schemaVersion: 1 as const, enabled: true, allowedOrigins: [ORIGIN] },
    })),
    authorizeFrame: vi.fn(async () => authorization),
    captureSessionLease: () => sessionGate.capture(),
    assertSessionLease: (lease) => sessionGate.assert(lease),
    captureAccountLease: () => accountGate.capture(),
    assertAccountLease: (lease) => accountGate.assert(lease),
    getHttpAuthLoginData: vi.fn(async () => ({ username: 'alice', password: 'correct horse' })),
    tombstones: {
      claim: vi.fn(async (fingerprint) => {
        if (claimed.has(fingerprint)) return false;
        claimed.add(fingerprint);
        return true;
      }),
    },
    digestFingerprint: vi.fn(async () => 'a'.repeat(64)),
    deadlineMs: 100,
    ...overrides,
  };
  return { broker: new HttpAuthBroker(deps), deps, sessionGate, accountGate, authorization };
}

function invoke(broker: HttpAuthBroker, details = challenge()) {
  return new Promise<Record<string, unknown>>((resolve) => {
    broker.handle(details, (response) => resolve(response as Record<string, unknown>));
  });
}

afterEach(() => {
  vi.useRealTimers();
});

describe('HTTP authentication challenge validation', () => {
  it('accepts only an exact eligible top-frame Basic challenge', () => {
    expect(parseEligibleChallenge(challenge())).toEqual({
      requestId: 'request-1',
      url: `${ORIGIN}/protected`,
      origin: ORIGIN,
    });
  });

  it.each([
    ['proxy', { isProxy: true }],
    ['digest', { scheme: 'digest' }],
    ['sub-frame', { type: 'sub_frame', frameId: 2 }],
    ['incognito', { incognito: true }],
    ['background request', { tabId: -1 }],
    ['post', { method: 'POST' }],
    ['challenger host mismatch', { challenger: { host: 'localhost', port: 18083 } }],
    ['challenger port mismatch', { challenger: { host: '127.0.0.1', port: 80 } }],
    ['non-loopback HTTP', {
      url: 'http://example.com/protected',
      challenger: { host: 'example.com', port: 80 },
    }],
    ['URL credentials', { url: `http://alice:secret@127.0.0.1:18083/protected` }],
  ])('rejects %s', (_name, overrides) => {
    expect(parseEligibleChallenge(challenge(overrides))).toBeUndefined();
  });

  it('accepts HTTPS and exact effective default ports', () => {
    expect(parseEligibleChallenge(challenge({
      url: 'https://example.com/protected',
      challenger: { host: 'example.com', port: 443 },
    }))?.origin).toBe('https://example.com');
  });

});

describe('HttpAuthBroker', () => {
  it('releases one unique non-reprompt credential only to the browser callback', async () => {
    const { broker, deps } = fixture();
    await expect(invoke(broker)).resolves.toEqual({
      authCredentials: { username: 'alice', password: 'correct horse' },
    });
    expect(deps.getHttpAuthLoginData).toHaveBeenCalledWith(
      `${ORIGIN}/protected`,
      UriMatchStrategy.Domain,
      expect.any(Function),
    );
    expect(deps.authorizeFrame).toHaveBeenCalledOnce();
    expect(deps.authorizeFrame).toHaveBeenCalledWith(`${ORIGIN}/protected`, 'intent');
  });

  it.each([
    ['Host', UriMatchStrategy.Host],
    ['Exact', UriMatchStrategy.Exact],
    ['Never', UriMatchStrategy.Never],
  ] as const)('uses the effective %s URI match strategy from frame authorization', async (_name, strategy) => {
    const authorizeFrame = vi.fn(async () => ({ defaultStrategy: strategy, assertCurrent: vi.fn() }));
    const getHttpAuthLoginData = vi.fn(async () => strategy === UriMatchStrategy.Never
      ? {}
      : { username: 'alice', password: 'correct horse' });
    const { broker } = fixture({ authorizeFrame, getHttpAuthLoginData });

    const response = await invoke(broker);

    expect(authorizeFrame).toHaveBeenCalledOnce();
    expect(authorizeFrame).toHaveBeenCalledWith(`${ORIGIN}/protected`, 'intent');
    expect(getHttpAuthLoginData).toHaveBeenCalledWith(
      `${ORIGIN}/protected`, strategy, expect.any(Function),
    );
    expect(response).toEqual(strategy === UriMatchStrategy.Never
      ? {}
      : { authCredentials: { username: 'alice', password: 'correct horse' } });
  });

  it.each([
    ['invalid policy', { valid: false, settings: { schemaVersion: 1, enabled: false, allowedOrigins: [] } }],
    ['disabled policy', { valid: true, settings: { schemaVersion: 1, enabled: false, allowedOrigins: [ORIGIN] } }],
    ['different origin', { valid: true, settings: { schemaVersion: 1, enabled: true, allowedOrigins: ['https://elsewhere.example'] } }],
  ])('fails closed for %s', async (_name, read) => {
    const { broker, deps } = fixture({ readHttpAuthSettings: async () => read as never });
    await expect(invoke(broker)).resolves.toEqual({});
    expect(deps.authorizeFrame).not.toHaveBeenCalled();
    expect(deps.getHttpAuthLoginData).not.toHaveBeenCalled();
  });

  it('fails closed when global autofill policy blocks frame authorization', async () => {
    const authorizeFrame = vi.fn(async () => { throw new Error('blocked'); });
    const { broker, deps } = fixture({ authorizeFrame });

    await expect(invoke(broker)).resolves.toEqual({});

    expect(authorizeFrame).toHaveBeenCalledOnce();
    expect(deps.getHttpAuthLoginData).not.toHaveBeenCalled();
  });

  it('fails closed when the returned frame authorization is not current', async () => {
    const authorizeFrame = vi.fn(async () => ({
      defaultStrategy: UriMatchStrategy.Host,
      assertCurrent: () => { throw new Error('stale authorization'); },
    }));
    const { broker, deps } = fixture({ authorizeFrame });

    await expect(invoke(broker)).resolves.toEqual({});

    expect(authorizeFrame).toHaveBeenCalledOnce();
    expect(deps.getHttpAuthLoginData).not.toHaveBeenCalled();
  });

  it('fails closed when the durable tombstone cannot be written', async () => {
    const { broker, deps } = fixture({ tombstones: { claim: async () => false } });
    await expect(invoke(broker)).resolves.toEqual({});
    expect(deps.getHttpAuthLoginData).not.toHaveBeenCalled();
  });

  it.each([
    { username: '', password: 'secret' },
    { username: '   ', password: 'secret' },
    { username: 'alice', password: '' },
    { password: 'secret' },
    { username: 'alice' },
  ])('refuses incomplete credentials %#', async (login) => {
    const { broker } = fixture({ getHttpAuthLoginData: async () => login });
    await expect(invoke(broker)).resolves.toEqual({});
  });

  it('claims a request ID in memory before asynchronous work', async () => {
    const ready = deferred<void>();
    const { broker, deps } = fixture({ ready: () => ready.promise });
    const first = invoke(broker);
    await expect(invoke(broker)).resolves.toEqual({});
    ready.resolve(undefined);
    await expect(first).resolves.toHaveProperty('authCredentials');
    expect(deps.tombstones.claim).toHaveBeenCalledTimes(1);
  });

  it('keeps the durable tombstone after request completion', async () => {
    const { broker, deps } = fixture();
    await expect(invoke(broker)).resolves.toHaveProperty('authCredentials');
    broker.finishRequest('request-1');
    await expect(invoke(broker)).resolves.toEqual({});
    expect(deps.getHttpAuthLoginData).toHaveBeenCalledTimes(1);
  });

  it('rejects a frame authorization that becomes stale during the atomic vault read', async () => {
    let authorizationCurrent = true;
    const assertCurrent = vi.fn(() => {
      if (!authorizationCurrent) throw new Error('stale authorization');
    });
    const getHttpAuthLoginData = vi.fn(async () => {
      authorizationCurrent = false;
      return { username: 'alice', password: 'secret' };
    });
    const { broker } = fixture({
      authorizeFrame: async () => ({ defaultStrategy: UriMatchStrategy.Exact, assertCurrent }),
      getHttpAuthLoginData,
    });
    await expect(invoke(broker)).resolves.toEqual({});
    expect(getHttpAuthLoginData).toHaveBeenCalledOnce();
    expect(assertCurrent).toHaveBeenCalledTimes(4);
  });

  it('reasserts frame authorization immediately before the browser callback releases credentials', async () => {
    let authorizationAssertions = 0;
    const { broker } = fixture({
      authorizeFrame: async () => ({
        defaultStrategy: UriMatchStrategy.Host,
        assertCurrent: () => {
          authorizationAssertions += 1;
          if (authorizationAssertions === 5) throw new Error('stale at callback');
        },
      }),
    });

    await expect(invoke(broker)).resolves.toEqual({});
    expect(authorizationAssertions).toBe(5);
  });

  it('rejects a session transition that races the atomic vault read', async () => {
    const fixtureState = fixture();
    const getHttpAuthLoginData = vi.fn(async () => {
        fixtureState.sessionGate.handleTransition({
          phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
        });
        return { username: 'alice', password: 'secret' };
      });
    const { broker } = fixture({
      getHttpAuthLoginData,
      captureSessionLease: () => fixtureState.sessionGate.capture(),
      assertSessionLease: (lease) => fixtureState.sessionGate.assert(lease),
    });
    await expect(invoke(broker)).resolves.toEqual({});
    expect(getHttpAuthLoginData).toHaveBeenCalledOnce();
  });

  it('reasserts the original session lease at the browser callback boundary', async () => {
    const fixtureState = fixture();
    let sessionAssertions = 0;
    const { broker } = fixture({
      captureSessionLease: () => fixtureState.sessionGate.capture(),
      assertSessionLease: (lease) => {
        sessionAssertions += 1;
        fixtureState.sessionGate.assert(lease);
        if (sessionAssertions === 6) {
          fixtureState.sessionGate.handleTransition({
            phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
          });
        }
      },
    });

    await expect(invoke(broker)).resolves.toEqual({});
    expect(sessionAssertions).toBe(7);
  });

  it('withholds credentials when the callback release checkpoint cannot be persisted', async () => {
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(async () => { throw new Error('checkpoint unavailable'); }),
      assertAuthorities: vi.fn(),
      assert: vi.fn(),
      settlePendingAction: vi.fn(async () => undefined),
    };
    const { broker, deps } = fixture({ vaultReleaseGate: vaultReleaseGate as never });

    await expect(invoke(broker)).resolves.toEqual({});

    expect(deps.getHttpAuthLoginData).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
  });

  it('rechecks the original HTTP auth authority after the checkpoint await', async () => {
    const security = fixture();
    const pending = deferred<object>();
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(() => pending.promise),
      assertAuthorities: vi.fn((_proof: object, assertCurrent: () => void) => assertCurrent()),
      assert: vi.fn(),
      settlePendingAction: vi.fn(async () => undefined),
    };
    const { broker } = fixture({
      captureSessionLease: () => security.sessionGate.capture(),
      assertSessionLease: (lease) => security.sessionGate.assert(lease),
      vaultReleaseGate: vaultReleaseGate as never,
    });
    const response = invoke(broker);
    await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
    security.sessionGate.handleTransition({
      phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
    });
    pending.resolve({});

    await expect(response).resolves.toEqual({});
    expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
    await vi.waitFor(() => expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce());
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
  });

  it('rechecks the result-bound vault read authority after the checkpoint await', async () => {
    let current = true;
    const pending = deferred<object>();
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(() => pending.promise),
      assertAuthorities: vi.fn((_proof: object, assertCurrent: () => void) => assertCurrent()),
      assert: vi.fn(),
      settlePendingAction: vi.fn(async () => undefined),
    };
    const getHttpAuthLoginData = vi.fn(async (
      _url: string,
      _strategy: UriMatchStrategySetting,
      bindFinalAuthority?: (assertCurrent: () => void) => void,
    ) => {
      bindFinalAuthority?.(() => {
        if (!current) throw new Error('vault result changed');
      });
      return { username: 'alice', password: 'correct horse' };
    });
    const { broker } = fixture({
      getHttpAuthLoginData,
      vaultReleaseGate: vaultReleaseGate as never,
    });
    const response = invoke(broker);
    await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
    current = false;
    pending.resolve({});

    await expect(response).resolves.toEqual({});
    expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
    await vi.waitFor(() => expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce());
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
  });

  it('keeps frame authorization and the vault release proof live through the final callback', async () => {
    const events: string[] = [];
    const releaseProof = { id: 'release-proof' };
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(async () => releaseProof),
      assertAuthorities: vi.fn((_proof, assertCurrent: () => void) => { assertCurrent(); }),
      assert: vi.fn(() => { events.push('release'); }),
    };
    const { broker } = fixture({
      authorizeFrame: async () => ({
        defaultStrategy: UriMatchStrategy.Exact,
        assertCurrent: () => { events.push('authorization'); },
      }),
      vaultReleaseGate: vaultReleaseGate as never,
    });

    await expect(invoke(broker)).resolves.toHaveProperty('authCredentials');

    expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).toHaveBeenCalledOnce();
    expect(events.slice(-2)).toEqual(['authorization', 'release']);
  });

  it('rejects an account transition that races the atomic vault read', async () => {
    const fixtureState = fixture();
    const getHttpAuthLoginData = vi.fn(async () => {
      fixtureState.accountGate.beginAccountTransition();
      return { username: 'alice', password: 'secret' };
    });
    const { broker } = fixture({
      getHttpAuthLoginData,
      captureAccountLease: () => fixtureState.accountGate.capture(),
      assertAccountLease: (lease) => fixtureState.accountGate.assert(lease),
    });
    await expect(invoke(broker)).resolves.toEqual({});
    expect(getHttpAuthLoginData).toHaveBeenCalledOnce();
  });

  it('settles exactly once at the deadline and never releases a late atomic result', async () => {
    vi.useFakeTimers();
    const login = deferred<{ username: string; password: string }>();
    const callback = vi.fn();
    const getHttpAuthLoginData = vi.fn(() => login.promise);
    const { broker } = fixture({
      deadlineMs: 10,
      getHttpAuthLoginData,
    });
    broker.handle(challenge(), callback);
    await vi.advanceTimersByTimeAsync(10);
    expect(callback).toHaveBeenCalledOnce();
    expect(callback).toHaveBeenCalledWith({});
    login.resolve({ username: 'late', password: 'late-secret' });
    await vi.runAllTimersAsync();
    await Promise.resolve();
    expect(callback).toHaveBeenCalledOnce();
    expect(getHttpAuthLoginData).toHaveBeenCalledOnce();
  });

  it('does not release a credential whose decryption completes after the deadline', async () => {
    vi.useFakeTimers();
    const login = deferred<{ username: string; password: string }>();
    const callback = vi.fn();
    const getHttpAuthLoginData = vi.fn(() => login.promise);
    const { broker } = fixture({
      deadlineMs: 10,
      getHttpAuthLoginData,
    });
    broker.handle(challenge(), callback);
    await vi.advanceTimersByTimeAsync(0);
    expect(getHttpAuthLoginData).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(10);
    expect(callback).toHaveBeenCalledOnce();
    expect(callback).toHaveBeenCalledWith({});
    login.resolve({ username: 'late', password: 'late-secret' });
    await vi.runAllTimersAsync();
    await Promise.resolve();
    expect(callback).toHaveBeenCalledOnce();
  });

  it('uses a domain-separated SHA-256 request fingerprint', async () => {
    const first = await digestHttpAuthRequestId('1');
    const second = await digestHttpAuthRequestId('2');
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(second).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toBe(second);
  });
});
