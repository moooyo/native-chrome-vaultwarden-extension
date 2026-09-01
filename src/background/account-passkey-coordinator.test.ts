import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { ApiClient, ApiHttpError } from '../core/api/client.js';
import {
  parseAccountPasskeyAssertionOptions,
  type AccountPasskeyAssertionOptions,
} from '../core/api/account-passkey.js';
import { bytesToBase64Url, utf8ToBytes } from '../core/crypto/encoding.js';
import { AccountLeaseGate } from '../core/session/account-gate.js';
import {
  accountPasskeyConnectorUrl,
  deriveAccountPasskeyPrfSalt,
} from '../core/session/account-passkey.js';
import { createMemoryStore } from '../platform/store.js';
import { AccountPasskeyAttemptRegistry } from './account-passkey-attempt-registry.js';
import {
  AccountPasskeyCoordinator,
  AccountPasskeyCoordinatorError,
  type AccountPasskeyCoordinatorDeps,
} from './account-passkey-coordinator.js';

const SERVER = 'https://vault.example/';
const ATTEMPT = '11111111-1111-4111-8111-111111111111';
const CREDENTIAL_ID = bytesToBase64Url(new Uint8Array(32).fill(7));

function options(): AccountPasskeyAssertionOptions {
  return parseAccountPasskeyAssertionOptions({
    options: {
      challenge: '6CG3jqMCVASJVXySMi9KWw',
      timeout: 60_000,
      rpId: 'vault.example',
      allowCredentials: [],
      userVerification: 'required',
      status: 'ok',
      errorMessage: '',
    },
    token: 'server-signed-continuation',
    object: 'webAuthnLoginAssertionOptions',
  });
}

function connector(documentId = 'document-a') {
  return {
    tabId: 7,
    frameId: 0,
    documentId,
    url: accountPasskeyConnectorUrl(SERVER),
  };
}

async function connectorResult(
  assertionOptions: AccountPasskeyAssertionOptions,
  origin = 'https://vault.example',
) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      utf8ToBytes(assertionOptions.options.rpId) as BufferSource,
    ),
  ));
  authenticatorData[32] = 0x05;
  return {
    assertion: {
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key' as const,
      extensions: {},
      response: {
        authenticatorData: bytesToBase64Url(authenticatorData),
        signature: bytesToBase64Url(new Uint8Array(64).fill(3)),
        clientDataJSON: bytesToBase64Url(utf8ToBytes(JSON.stringify({
          type: 'webauthn.get',
          challenge: assertionOptions.options.challenge,
          origin,
          crossOrigin: false,
        }))),
        userHandle: bytesToBase64Url(new Uint8Array(16).fill(4)),
      },
    },
    prfOutput: Array.from(new Uint8Array(32).fill(5)),
  };
}

function mockApi(api: Partial<ApiClient>, guards: Array<() => void> = []): ApiClient {
  return new Proxy(api, {
    get(target, property) {
      if (property === 'forServer') return () => mockApi(api, guards);
      if (property === 'withRequestGuard') {
        return (guard: () => void) => mockApi(api, [...guards, guard]);
      }
      const value = Reflect.get(target, property) as unknown;
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        for (const guard of guards) guard();
        return Reflect.apply(value, target, args) as unknown;
      };
    },
  }) as ApiClient;
}

type ActivateMock = ReturnType<typeof vi.fn<AccountPasskeyCoordinatorDeps['activate']>>;

function harness(overrides: {
  activate?: ActivateMock;
  store?: ReturnType<typeof createMemoryStore>;
  gate?: AccountLeaseGate;
  workerId?: string;
} = {}) {
  const store = overrides.store ?? createMemoryStore();
  const gate = overrides.gate ?? new AccountLeaseGate();
  if (!gate.current()) gate.initialize({ serverUrl: SERVER });
  const getOptions = vi.fn(async () => options());
  const activate = overrides.activate
    ?? vi.fn<AccountPasskeyCoordinatorDeps['activate']>(async () => ({ kind: 'locked' as const }));
  const attempts = new AccountPasskeyAttemptRegistry(store, {
    now: () => 1_000,
    workerId: overrides.workerId ?? 'worker-a',
  });
  const coordinator = new AccountPasskeyCoordinator({
    api: mockApi({ getAccountPasskeyAssertionOptions: getOptions }),
    serverGate: gate,
    attempts,
    activate,
    now: () => 1_000,
    createAttemptId: () => ATTEMPT,
  });
  return { coordinator, attempts, store, gate, activate, getOptions };
}

describe('AccountPasskeyCoordinator', () => {
  it('returns connector-safe options and keeps the opaque token only in background state', async () => {
    const { coordinator, attempts, getOptions } = harness();
    const ceremony = await coordinator.begin(connector());

    expect(getOptions).toHaveBeenCalledOnce();
    expect(ceremony).toEqual({
      attemptId: ATTEMPT,
      options: options().options,
      prfSalt: await deriveAccountPasskeyPrfSalt(),
      expiresAt: 121_000,
    });
    expect(JSON.stringify(ceremony)).not.toContain('server-signed-continuation');
    expect((await attempts.read())?.status).toBe('waiting');
  });

  it('recovers waiting options after a worker restart without fetching or submitting again', async () => {
    const first = harness();
    const ceremony = await first.coordinator.begin(connector());
    const restarted = harness({ store: first.store, gate: first.gate, workerId: 'worker-b' });

    await expect(restarted.coordinator.startup()).resolves.toEqual({
      status: 'waiting',
      attemptId: ATTEMPT,
      expiresAt: 121_000,
    });
    await expect(restarted.coordinator.resume(connector())).resolves.toEqual(ceremony);
    expect(restarted.getOptions).not.toHaveBeenCalled();
    expect(restarted.activate).not.toHaveBeenCalled();
  });

  it('claims and redeems once, lends PRF bytes only for activation, clears them, and rejects replay', async () => {
    let observedPrf: Uint8Array | undefined;
    const activate = vi.fn<AccountPasskeyCoordinatorDeps['activate']>(async (input) => {
      observedPrf = input.prfOutput?.slice();
      return { kind: 'locked' as const };
    });
    const { coordinator } = harness({ activate });
    const ceremony = await coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });

    await expect(coordinator.submit(connector(), ATTEMPT, result)).resolves.toEqual({
      status: 'locked',
    });
    expect(activate).toHaveBeenCalledOnce();
    expect(activate.mock.calls[0]?.[0]).toEqual({
      serverUrl: SERVER,
      token: 'server-signed-continuation',
      assertion: result.assertion,
      prfOutput: new Uint8Array(32),
    });
    expect(observedPrf).toEqual(new Uint8Array(32).fill(5));
    expect(activate.mock.calls[0]?.[0].prfOutput).toEqual(new Uint8Array(32));
    expect(result.prfOutput).toEqual(new Array(32).fill(0));
    await expect(coordinator.submit(connector(), ATTEMPT, result)).resolves.toEqual({
      status: 'expired',
    });
    expect(activate).toHaveBeenCalledOnce();
  });

  it('projects an authoritative PRF unlock distinctly from locked fallback', async () => {
    const activate = vi.fn<AccountPasskeyCoordinatorDeps['activate']>(async () => ({
      kind: 'unlocked' as const,
    }));
    const { coordinator } = harness({ activate });
    const ceremony = await coordinator.begin(connector());

    await expect(coordinator.submit(
      connector(),
      ATTEMPT,
      await connectorResult({ options: ceremony.options, token: 'unused' }),
    )).resolves.toEqual({ status: 'unlocked' });
  });

  it('rejects an all-zero PRF result before claiming or posting the grant', async () => {
    const { coordinator, attempts, activate } = harness();
    const ceremony = await coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });
    result.prfOutput.fill(0);

    await expect(coordinator.submit(connector(), ATTEMPT, result)).rejects.toMatchObject({
      code: 'invalid_assertion',
    });
    expect((await attempts.read())?.status).toBe('waiting');
    expect(activate).not.toHaveBeenCalled();
    expect(result.prfOutput).toEqual(new Array(32).fill(0));
  });

  it('returns explicit unsupported 2FA and never retries the grant', async () => {
    const activate = vi.fn<AccountPasskeyCoordinatorDeps['activate']>(async () => ({
      kind: 'twoFactorUnsupported' as const,
      providers: [0, 7],
    }));
    const { coordinator } = harness({ activate });
    const ceremony = await coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });

    await expect(coordinator.submit(connector(), ATTEMPT, result)).resolves.toEqual({
      status: 'two_factor_unsupported',
      providers: [0, 7],
    });
    expect(activate).toHaveBeenCalledOnce();
  });

  it('marks a sent ambiguous grant outcome unknown and startup never replays it', async () => {
    const activate = vi.fn<AccountPasskeyCoordinatorDeps['activate']>(async () => {
      throw new TypeError('network disconnected');
    });
    const first = harness({ activate });
    const ceremony = await first.coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });

    const outcome = await first.coordinator.submit(connector(), ATTEMPT, result);
    expect(outcome).toMatchObject({ status: 'outcome_unknown', attemptId: ATTEMPT });
    expect(activate).toHaveBeenCalledOnce();
    expect(JSON.stringify(await first.attempts.read())).not.toContain('server-signed-continuation');

    const restarted = harness({ store: first.store, gate: first.gate, workerId: 'worker-b' });
    await expect(restarted.coordinator.startup()).resolves.toMatchObject({
      status: 'outcome_unknown',
      attemptId: ATTEMPT,
    });
    expect(restarted.activate).not.toHaveBeenCalled();
  });

  it('treats an explicit token 4xx as a definite failure and does not retain a replay token', async () => {
    const activate = vi.fn<AccountPasskeyCoordinatorDeps['activate']>(async () => {
      throw new ApiHttpError(400, { error: 'invalid_grant' });
    });
    const { coordinator, attempts } = harness({ activate });
    const ceremony = await coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });

    await expect(coordinator.submit(connector(), ATTEMPT, result)).resolves.toEqual({
      status: 'failed',
    });
    expect(await attempts.read()).toBeUndefined();
    expect(activate).toHaveBeenCalledOnce();
  });

  it('rejects connector document changes and malformed assertions before claiming', async () => {
    const { coordinator, attempts, activate } = harness();
    const ceremony = await coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });

    await expect(coordinator.submit(connector('document-b'), ATTEMPT, result)).rejects.toMatchObject({
      code: 'invalid_connector',
    });
    await expect(coordinator.submit(connector(), ATTEMPT, {
      ...result,
      assertion: {
        ...result.assertion,
        response: {
          ...result.assertion.response,
          clientDataJSON: bytesToBase64Url(utf8ToBytes(JSON.stringify({
            type: 'webauthn.get',
            challenge: 'wrong-challenge',
            origin: 'https://vault.example',
          }))),
        },
      },
    })).rejects.toMatchObject({ code: 'invalid_assertion' });
    expect((await attempts.read())?.status).toBe('waiting');
    expect(activate).not.toHaveBeenCalled();
  });

  it('detects same-runtime server ABA with the original server lease', async () => {
    const { coordinator, gate, activate } = harness();
    const ceremony = await coordinator.begin(connector());
    const result = await connectorResult({ options: ceremony.options, token: 'unused' });
    const toOther = gate.beginServerTransition();
    gate.endServerTransition(toOther, { serverUrl: 'https://other.example/' });
    const backToOriginal = gate.beginServerTransition();
    gate.endServerTransition(backToOriginal, { serverUrl: SERVER });

    await expect(coordinator.submit(connector(), ATTEMPT, result)).rejects.toMatchObject({
      code: 'server_changed',
    });
    expect(activate).not.toHaveBeenCalled();
  });

  it('retires a claim found after restart instead of automatically submitting it', async () => {
    const first = harness();
    await first.coordinator.begin(connector());
    const waiting = await first.attempts.read();
    expect(waiting?.status).toBe('waiting');
    await first.attempts.claim(waiting!.owner);
    const restarted = harness({ store: first.store, gate: first.gate, workerId: 'worker-b' });

    await expect(restarted.coordinator.startup()).resolves.toMatchObject({
      status: 'outcome_unknown',
      attemptId: ATTEMPT,
    });
    expect(restarted.activate).not.toHaveBeenCalled();
  });

  it('cancels only from the exact bound connector and attempt id', async () => {
    const { coordinator, attempts } = harness();
    await coordinator.begin(connector());

    await expect(coordinator.cancel(connector(), '22222222-2222-4222-8222-222222222222'))
      .resolves.toBe(false);
    await expect(coordinator.cancel(connector('document-b'), ATTEMPT)).rejects.toBeInstanceOf(
      AccountPasskeyCoordinatorError,
    );
    await expect(coordinator.cancel(connector(), ATTEMPT)).resolves.toBe(true);
    expect(await attempts.read()).toBeUndefined();
  });
});
