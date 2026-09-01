import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { ApiHttpError, type ApiClient, type AuthRequestCreateInput } from '../core/api/client.js';
import { AppError } from '../core/errors.js';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  utf8ToBytes,
} from '../core/crypto/encoding.js';
import { serializeSymmetricKey } from '../core/crypto/keys.js';
import { rsaOaepEncrypt } from '../core/crypto/primitives.js';
import type {
  DeviceLoginAuthResult,
  NewDeviceVerificationAuthResult,
} from '../core/session/auth-service.js';
import type { ServerLease } from '../core/session/account-gate.js';
import {
  bindDeviceLoginRequest,
  createDeviceLoginRequest,
  type DeviceLoginBoundState,
  type DeviceLoginPendingState,
} from '../core/session/device-login.js';
import { parseFido2TwoFactorRequest } from '../core/session/fido2-two-factor.js';
import {
  createInteractiveTwoFactorOwner,
  interactiveTwoFactorConnectorUrl,
  type InteractiveTwoFactorOwner,
} from '../core/session/interactive-two-factor.js';
import { createMemoryStore } from '../platform/store.js';
import {
  DEVICE_LOGIN_DEADLINE_ALARM_PREFIX,
  DEVICE_LOGIN_STATUS_ALARM_PREFIX,
  DEVICE_LOGIN_STATUS_POLL_INTERVAL_MS,
  DeviceLoginCoordinator,
  type DeviceLoginCoordinatorDeps,
} from './device-login-coordinator.js';
import type { DeviceLoginNotificationRequest } from './device-login-notifications.js';
import { DeviceLoginStateStore } from './device-login-state-store.js';

const NOW = Date.parse('2026-08-30T08:00:00.000Z');
const SERVER_CREATED_AT = NOW + 1_000;
const SERVER_URL = 'https://vault.example/tenant/';
const OTHER_SERVER_URL = 'https://other.example/';
const REQUEST_ID = 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34';
const DEVICE_IDENTIFIER = 'device-123';
const DEVICE = Object.freeze({ type: 2, name: 'chrome', identifier: DEVICE_IDENTIFIER });
const FIDO_CREDENTIAL_ID = bytesToBase64Url(new Uint8Array(32).fill(9));

function fidoProviderMetadata() {
  return Object.freeze({
    '7': Object.freeze({
      challenge: bytesToBase64Url(new Uint8Array(32).fill(7)),
      rpId: 'vault.example',
      allowCredentials: Object.freeze([Object.freeze({
        type: 'public-key',
        id: FIDO_CREDENTIAL_ID,
        transports: Object.freeze(['internal']),
      })]),
      userVerification: 'preferred',
    }),
  });
}

function duoProviderMetadata() {
  return Object.freeze({
    '2': Object.freeze({
      AuthUrl: 'https://api-example.duosecurity.com/oauth/v1/authorize'
        + '?response_type=code&client_id=client-id&request=header.payload.signature',
    }),
  });
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

interface TestApi {
  readonly getDeviceIdentifier: ReturnType<typeof vi.fn>;
  readonly isKnownDevice: ReturnType<typeof vi.fn>;
  readonly createAuthRequest: ReturnType<typeof vi.fn>;
  readonly getAuthRequestResponse: ReturnType<typeof vi.fn>;
  readonly sendEmailLogin: ReturnType<typeof vi.fn>;
}

interface Harness {
  readonly coordinator: DeviceLoginCoordinator;
  readonly stateStore: DeviceLoginStateStore;
  readonly api: TestApi;
  readonly activate: ReturnType<typeof vi.fn>;
  readonly notifications: {
    readonly start: ReturnType<typeof vi.fn>;
    readonly stop: ReturnType<typeof vi.fn>;
    readonly handleAlarm: ReturnType<typeof vi.fn>;
  };
  readonly createAlarm: ReturnType<typeof vi.fn>;
  readonly clearAlarm: ReturnType<typeof vi.fn>;
  readonly events: string[];
  readonly fixedServers: string[];
  readonly createdInputs: AuthRequestCreateInput[];
  readonly leaseControl: ReturnType<typeof serverLeaseControl>;
  readonly getResponses: Array<(input: AuthRequestCreateInput) => unknown | Promise<unknown>>;
  setNow(value: number): void;
}

function serverLeaseControl() {
  let generation = 1;
  let serverUrl = SERVER_URL;
  const captureServer = vi.fn(() => Object.freeze({ serverGeneration: generation, serverUrl }));
  const assertServer = vi.fn((lease: ServerLease) => {
    if (lease.serverGeneration !== generation || lease.serverUrl !== serverUrl) {
      throw new Error('server lease changed');
    }
  });
  return {
    captureServer,
    assertServer,
    change(next: string) {
      generation += 1;
      serverUrl = next;
    },
    current: () => ({ generation, serverUrl }),
  };
}

function scopedApi(
  methods: TestApi,
  fixedServers: string[],
  guards: Array<() => void> = [],
): ApiClient {
  return new Proxy(methods, {
    get(target, property) {
      if (property === 'forServer') {
        return (serverUrl: string) => {
          fixedServers.push(serverUrl);
          return scopedApi(methods, fixedServers, guards);
        };
      }
      if (property === 'withRequestGuard') {
        return (guard: () => void) => scopedApi(methods, fixedServers, [...guards, guard]);
      }
      const value = Reflect.get(target, property) as unknown;
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        for (const guard of guards) guard();
        return Reflect.apply(value, target, args) as unknown;
      };
    },
  }) as unknown as ApiClient;
}

let harnessSequence = 0;

function makeHarness(overrides: Partial<DeviceLoginCoordinatorDeps> & {
  readonly known?: boolean;
  readonly activate?: (
    input: Parameters<DeviceLoginCoordinatorDeps['activate']>[0]
  ) => Promise<DeviceLoginAuthResult | NewDeviceVerificationAuthResult>;
} = {}): Harness {
  let now = NOW + 2_000;
  const events: string[] = [];
  const fixedServers: string[] = [];
  const createdInputs: AuthRequestCreateInput[] = [];
  const getResponses: Array<(input: AuthRequestCreateInput) => unknown | Promise<unknown>> = [];
  const leaseControl = serverLeaseControl();
  const storage = createMemoryStore();
  const stateStore = overrides.stateStore ?? new DeviceLoginStateStore(storage, {
    now: () => now,
    workerId: `coordinator-worker-${++harnessSequence}`,
    storageKey: `device-login-coordinator-${harnessSequence}`,
  });
  const api: TestApi = {
    getDeviceIdentifier: vi.fn(async () => {
      events.push('device');
      return DEVICE_IDENTIFIER;
    }),
    isKnownDevice: vi.fn(async () => {
      events.push('known');
      return overrides.known ?? true;
    }),
    createAuthRequest: vi.fn(async (input: AuthRequestCreateInput) => {
      events.push('create');
      createdInputs.push(input);
      return creationResponseFromInput(input);
    }),
    getAuthRequestResponse: vi.fn(async () => {
      events.push('get');
      const input = createdInputs.at(-1);
      if (!input) throw new Error('request was not created');
      const response = getResponses.shift();
      return response ? response(input) : pendingResponseFromInput(input);
    }),
    sendEmailLogin: vi.fn(async () => { events.push('email'); }),
  };
  const notifications = {
    start: vi.fn(async (_request: DeviceLoginNotificationRequest) => { events.push('hub'); }),
    stop: vi.fn(async () => { events.push('stop'); }),
    handleAlarm: vi.fn(async () => { events.push('notification-alarm'); }),
  };
  const createAlarm = vi.fn(async () => { events.push('alarm'); });
  const clearAlarm = vi.fn(async () => true);
  const activate = vi.fn(overrides.activate ?? (async () => ({ kind: 'unlocked' as const })));
  const deps: DeviceLoginCoordinatorDeps = {
    api: scopedApi(api, fixedServers),
    serverGate: overrides.serverGate ?? leaseControl,
    stateStore,
    notifications: overrides.notifications ?? notifications,
    alarms: overrides.alarms ?? { create: createAlarm, clear: clearAlarm },
    activate,
    now: overrides.now ?? (() => now),
    ...(overrides.getNotificationsUrl
      ? { getNotificationsUrl: overrides.getNotificationsUrl }
      : {}),
    ...(overrides.closeInteractiveTwoFactorConnector
      ? { closeInteractiveTwoFactorConnector: overrides.closeInteractiveTwoFactorConnector }
      : {}),
  };
  return {
    coordinator: new DeviceLoginCoordinator(deps),
    stateStore,
    api,
    activate,
    notifications,
    createAlarm,
    clearAlarm,
    events,
    fixedServers,
    createdInputs,
    leaseControl,
    getResponses,
    setNow(value) { now = value; },
  };
}

function creationResponseFromInput(input: AuthRequestCreateInput) {
  return responseBase(input, { requestApproved: false, responseDate: null, key: null });
}

function pendingResponseFromInput(input: AuthRequestCreateInput) {
  return responseBase(input, { requestApproved: false, responseDate: null, key: null });
}

function deniedResponseFromInput(input: AuthRequestCreateInput) {
  return responseBase(input, {
    requestApproved: false,
    responseDate: new Date(SERVER_CREATED_AT + 5_000).toISOString(),
    key: null,
  });
}

async function approvedResponseFromInput(input: AuthRequestCreateInput) {
  const rawUserKey = Uint8Array.from({ length: 64 }, (_, index) => (index * 17) & 0xff);
  const encrypted = await rsaOaepEncrypt(base64ToBytes(input.publicKey), rawUserKey, 'SHA-1');
  return responseBase(input, {
    requestApproved: true,
    responseDate: new Date(SERVER_CREATED_AT + 5_000).toISOString(),
    key: `4.${bytesToBase64(encrypted)}`,
  });
}

function responseBase(
  input: AuthRequestCreateInput,
  response: { requestApproved: boolean; responseDate: string | null; key: string | null },
) {
  return {
    object: 'auth-request',
    id: REQUEST_ID,
    publicKey: input.publicKey,
    requestDeviceType: 'Chrome',
    requestDeviceTypeValue: DEVICE.type,
    requestDeviceIdentifier: input.deviceIdentifier,
    requestIpAddress: '203.0.113.7',
    requestCountryName: 'Test Country',
    key: response.key,
    masterPasswordHash: null,
    creationDate: new Date(SERVER_CREATED_AT).toISOString(),
    requestApproved: response.requestApproved,
    responseDate: response.responseDate,
    origin: 'Admin',
  };
}

async function seedBound(store: DeviceLoginStateStore): Promise<DeviceLoginBoundState> {
  const pending = (await createDeviceLoginRequest({
    email: 'user@example.com',
    device: DEVICE,
  }, NOW)).state;
  const bound = await bindDeviceLoginRequest(
    pending,
    creationResponse(pending),
    NOW + 2_000,
  );
  const written = await store.write(SERVER_URL, pending);
  await store.replace(written.owner, bound);
  return bound;
}

function creationResponse(state: DeviceLoginPendingState) {
  return responseBase({
    email: state.email,
    publicKey: state.publicKey,
    deviceIdentifier: state.device.identifier,
    accessCode: state.accessCode,
    type: 0,
  }, { requestApproved: false, responseDate: null, key: null });
}

async function currentInteractiveOwner(harness: Harness): Promise<InteractiveTwoFactorOwner> {
  const current = await harness.stateStore.read();
  if (!current || 'status' in current || current.claimed || current.state.phase !== 'bound') {
    throw new Error('Expected active bound device-login state');
  }
  return createInteractiveTwoFactorOwner({
    flow: 'deviceLogin',
    generation: current.owner.generation,
    serverUrl: current.owner.serverUrl,
    bindingId: current.state.requestId,
  });
}

async function connectorToken(connectorData: string): Promise<string> {
  const connectorUrl = interactiveTwoFactorConnectorUrl(SERVER_URL);
  const connector = new URL(connectorUrl);
  const request = parseFido2TwoFactorRequest(JSON.parse(connectorData) as unknown, {
    origin: connector.origin,
    rpId: connector.hostname,
  });
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', utf8ToBytes(request.rpId) as BufferSource),
  );
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpIdHash);
  authenticatorData[32] = 0x05;
  const clientDataJson = utf8ToBytes(JSON.stringify({
    type: 'webauthn.get',
    challenge: request.challenge,
    origin: request.origin,
    crossOrigin: false,
  }));
  return JSON.stringify({
    id: FIDO_CREDENTIAL_ID,
    rawId: FIDO_CREDENTIAL_ID,
    type: 'public-key',
    extensions: {},
    response: {
      authenticatorData: bytesToBase64Url(authenticatorData),
      clientDataJson: bytesToBase64Url(clientDataJson),
      signature: bytesToBase64Url(Uint8Array.from([1, 2, 3])),
    },
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('DeviceLoginCoordinator begin and observation', () => {
  it('requires a known device before generating or persisting request key material', async () => {
    const harness = makeHarness({ known: false });
    const generateKey = vi.spyOn(crypto.subtle, 'generateKey');

    await expect(harness.coordinator.begin(' User@Example.COM ')).resolves.toEqual({
      status: 'not_known_device',
    });

    expect(harness.events).toEqual(['device', 'known']);
    expect(generateKey).not.toHaveBeenCalled();
    expect(harness.api.createAuthRequest).not.toHaveBeenCalled();
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('persists pending before POST and closes the GET-hub-GET race window', async () => {
    const harness = makeHarness();
    harness.api.createAuthRequest.mockImplementation(async (input: AuthRequestCreateInput) => {
      harness.events.push('create');
      harness.createdInputs.push(input);
      const stored = await harness.stateStore.read();
      expect(stored && !('status' in stored) && stored.state.phase).toBe('pending');
      return creationResponseFromInput(input);
    });

    const result = await harness.coordinator.begin(' User@Example.COM ');

    expect(result).toMatchObject({
      status: 'pending',
      generation: expect.any(Number),
      serverOrigin: 'https://vault.example',
      email: 'user@example.com',
      deviceName: 'chrome',
    });
    expect((result as { fingerprint: string }).fingerprint.split('-')).toHaveLength(5);
    const serialized = JSON.stringify(result);
    const current = await harness.stateStore.read();
    expect(current && !('status' in current) && current.state.phase).toBe('bound');
    if (!current || 'status' in current) throw new Error('Expected bound state');
    expect(serialized).not.toContain(current.state.privateKeyPkcs8);
    expect(serialized).not.toContain(current.state.accessCode);
    expect(serialized).not.toContain(current.state.publicKey);
    expect(serialized).not.toContain(current.state.phase === 'bound' ? current.state.requestId : '');
    expect(harness.events.filter((event) => ['get', 'hub'].includes(event)))
      .toEqual(['get', 'hub', 'get']);
    expect(harness.createAlarm).toHaveBeenCalledTimes(2);
    const [alarmName, options] = harness.createAlarm.mock.calls[0]!;
    expect(alarmName).toBe(`${DEVICE_LOGIN_STATUS_ALARM_PREFIX}${current.owner.generation}`);
    expect(alarmName).not.toContain(REQUEST_ID);
    expect(options).toEqual({ when: NOW + 2_000 + DEVICE_LOGIN_STATUS_POLL_INTERVAL_MS });
    expect(harness.createAlarm.mock.calls[1]).toEqual([
      `${DEVICE_LOGIN_DEADLINE_ALARM_PREFIX}${current.owner.generation}`,
      { when: current.state.expiresAt },
    ]);
    expect(harness.fixedServers.every((server) => server === SERVER_URL)).toBe(true);
  });

  it('terminalizes an unbound startup request because creation may have committed before eviction', async () => {
    const harness = makeHarness();
    const pending = (await createDeviceLoginRequest({
      email: 'user@example.com',
      device: DEVICE,
    }, NOW)).state;
    await harness.stateStore.write(SERVER_URL, pending);

    await expect(harness.coordinator.startup()).resolves.toMatchObject({
      status: 'outcome_unknown',
      generation: expect.any(Number),
      serverOrigin: 'https://vault.example',
    });

    const stored = await harness.stateStore.read();
    expect(stored && 'status' in stored && stored.status).toBe('outcome_unknown');
    expect(stored).not.toHaveProperty('state');
    expect(harness.api.createAuthRequest).not.toHaveBeenCalled();
    expect(harness.api.getAuthRequestResponse).not.toHaveBeenCalled();
  });

  it('clears a definite create 4xx but terminalizes an ambiguous create failure', async () => {
    const rejected = makeHarness();
    rejected.api.createAuthRequest.mockRejectedValue(new ApiHttpError(400, { error: 'invalid' }));
    await expect(rejected.coordinator.begin('user@example.com')).rejects.toMatchObject({
      code: 'request_failed',
    });
    await expect(rejected.stateStore.read()).resolves.toBeUndefined();

    const ambiguous = makeHarness();
    ambiguous.api.createAuthRequest.mockRejectedValue(new Error('network outcome unknown'));
    const result = await ambiguous.coordinator.begin('user@example.com');
    expect(result).toMatchObject({ status: 'outcome_unknown', generation: expect.any(Number) });
    const stored = await ambiguous.stateStore.read();
    expect(stored && 'status' in stored && stored.status).toBe('outcome_unknown');
    expect(stored).not.toHaveProperty('state');
    expect(JSON.stringify(stored)).not.toContain('accessCode');
    expect(JSON.stringify(stored)).not.toContain('privateKeyPkcs8');
    expect(JSON.stringify(result)).not.toContain('network outcome unknown');
  });

  it('terminalizes a malformed successful creation response instead of inviting another POST', async () => {
    const harness = makeHarness();
    harness.api.createAuthRequest.mockImplementation(async (input: AuthRequestCreateInput) => {
      harness.createdInputs.push(input);
      return { ...creationResponseFromInput(input), id: 'not-a-request-id' };
    });

    await expect(harness.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'outcome_unknown',
      generation: expect.any(Number),
    });

    expect(harness.api.createAuthRequest).toHaveBeenCalledOnce();
    const stored = await harness.stateStore.read();
    expect(stored && 'status' in stored && stored.status).toBe('outcome_unknown');
    expect(stored).not.toHaveProperty('state');
  });

  it('converges from polling alone when no push arrives', async () => {
    const harness = makeHarness();
    harness.getResponses.push(
      (input) => pendingResponseFromInput(input),
      (input) => pendingResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    await harness.coordinator.begin('user@example.com');
    const [alarmName] = harness.createAlarm.mock.calls[0]!;

    await expect(harness.coordinator.handleAlarm(alarmName)).resolves.toEqual({
      status: 'unlocked',
    });

    expect(harness.activate).toHaveBeenCalledOnce();
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('clears a denied response and does not invoke activation', async () => {
    const harness = makeHarness();
    harness.getResponses.push((input) => deniedResponseFromInput(input));

    await expect(harness.coordinator.begin('user@example.com')).resolves.toEqual({
      status: 'denied',
    });

    expect(harness.activate).not.toHaveBeenCalled();
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('keeps polling after one malformed GET response and later converges', async () => {
    const harness = makeHarness();
    harness.getResponses.push(
      (input) => ({
        ...pendingResponseFromInput(input),
        id: 'c05e732e-77b1-457b-8f89-5b5ba1b4e1d2',
      }),
      (input) => pendingResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );

    await expect(harness.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'pending',
      generation: expect.any(Number),
    });
    const [alarmName] = harness.createAlarm.mock.calls[0]!;
    await expect(harness.coordinator.handleAlarm(alarmName)).resolves.toEqual({ status: 'unlocked' });
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });
});

describe('DeviceLoginCoordinator activation and two-factor state', () => {
  it('claims, recovers, activates, clears state, and zeroes the recovered key on success', async () => {
    let receivedKey: Parameters<DeviceLoginCoordinatorDeps['activate']>[0]['userKey'] | undefined;
    const harness = makeHarness({
      activate: async (input) => {
        receivedKey = input.userKey;
        expect(serializeSymmetricKey(input.userKey).some((byte) => byte !== 0)).toBe(true);
        expect(input.serverUrl).toBe(SERVER_URL);
        return { kind: 'unlocked' };
      },
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    await expect(harness.coordinator.begin('user@example.com')).resolves.toEqual({
      status: 'unlocked',
    });

    expect(receivedKey).toBeDefined();
    expect([...serializeSymmetricKey(receivedKey!)].every((byte) => byte === 0)).toBe(true);
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
    expect(harness.notifications.stop).toHaveBeenCalled();
  });

  it('persists a strict 2FA challenge, never repeats activation from status, and submits explicitly', async () => {
    const harness = makeHarness({
      activate: vi.fn()
        .mockResolvedValueOnce({
          kind: 'twoFactor',
          providers: [7, 1, 1],
          token: 'session-two-factor-token',
          forcePasswordReset: true,
          masterPasswordPolicy: {
            minComplexity: 2,
            minLength: 16,
            requireUpper: true,
            requireLower: false,
            requireNumbers: true,
            requireSpecial: false,
            enforceOnLogin: false,
          },
        })
        .mockResolvedValueOnce({ kind: 'unlocked' }),
    });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );

    const challenge = await harness.coordinator.begin('user@example.com');

    expect(challenge).toMatchObject({
      status: 'two_factor',
      generation: expect.any(Number),
      providers: [1],
    });
    if (challenge.status !== 'two_factor') throw new Error('Expected two-factor challenge');
    expect(JSON.stringify(challenge)).not.toContain('session-two-factor-token');
    const stored = await harness.stateStore.read();
    expect(stored && !('status' in stored) && stored.twoFactor).toEqual({
      providers: [1],
      token: 'session-two-factor-token',
      forcePasswordReset: true,
      masterPasswordPolicy: {
        minComplexity: 2,
        minLength: 16,
        requireUpper: true,
        requireLower: false,
        requireNumbers: true,
        requireSpecial: false,
        enforceOnLogin: false,
      },
    });
    if (!stored || 'status' in stored) throw new Error('Expected released two-factor state');
    expect(harness.createAlarm.mock.calls.at(-1)).toEqual([
      `${DEVICE_LOGIN_DEADLINE_ALARM_PREFIX}${stored.owner.generation}`,
      { when: stored.state.expiresAt },
    ]);
    const getCount = harness.api.getAuthRequestResponse.mock.calls.length;
    await expect(harness.coordinator.status()).resolves.toMatchObject({
      status: 'two_factor', generation: challenge.generation, providers: [1],
    });
    expect(harness.activate).toHaveBeenCalledOnce();
    expect(harness.api.getAuthRequestResponse).toHaveBeenCalledTimes(getCount);

    await expect(harness.coordinator.sendEmailCode(challenge.generation)).resolves.toBeUndefined();
    expect(harness.api.sendEmailLogin).toHaveBeenCalledWith({
      email: 'user@example.com',
      twoFactorToken: 'session-two-factor-token',
    });
    await expect(harness.coordinator.submitTwoFactor({
      generation: challenge.generation,
      provider: 1,
      code: ' 123456 ',
      remember: true,
    })).resolves.toEqual({ status: 'unlocked' });
    expect(harness.activate).toHaveBeenCalledTimes(2);
    expect(harness.activate.mock.calls[1]?.[0]).toMatchObject({
      twoFactor: { provider: 1, code: '123456', remember: true },
      forcePasswordReset: true,
      masterPasswordPolicy: { minComplexity: 2, minLength: 16 },
    });
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('rebuilds an owner-bound provider 7 request and consumes one exact connector callback', async () => {
    const activate = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [7],
        providerMetadata: fidoProviderMetadata(),
        token: 'server-two-factor-token',
      })
      .mockResolvedValueOnce({ kind: 'unlocked' as const });
    const harness = makeHarness({ activate });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );

    await expect(harness.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'two_factor', generation: expect.any(Number), providers: [7],
    });
    const current = await harness.stateStore.read();
    if (
      !current
      || 'status' in current
      || current.claimed
      || current.state.phase !== 'bound'
      || !current.twoFactor?.fido2
    ) {
      throw new Error('Expected persisted FIDO2 challenge');
    }
    const owner = await currentInteractiveOwner(harness);
    expect(owner).toEqual({
      flow: 'deviceLogin',
      generation: current.owner.generation,
      serverUrl: SERVER_URL,
      bindingId: current.state.requestId,
    });
    const broker = harness.coordinator.interactiveTwoFactor;
    const launch = await broker.begin({
      owner,
      parentUrl: 'chrome-extension://extension-id/ui/popup/popup.html',
      locale: 'en',
    });
    expect(broker.matchCaller({ url: launch.url, tabId: 44, documentId: 'document-a' }))
      .toBeUndefined();
    await broker.bindTab({ owner, url: launch.url, tabId: 44, documentId: 'document-a' });
    expect(broker.matchCaller({ url: launch.url, tabId: 44, documentId: 'document-a' }))
      .toEqual(owner);

    const token = await connectorToken(current.twoFactor.fido2.connectorData);
    await expect(broker.complete({
      owner: { ...owner, generation: owner.generation + 1 },
      url: launch.url,
      tabId: 44,
      documentId: 'document-a',
      token,
      remember: true,
    })).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(broker.complete({
      owner,
      url: `${launch.url}#stale`,
      tabId: 44,
      documentId: 'document-a',
      token,
      remember: true,
    })).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(broker.complete({
      owner,
      url: launch.url,
      tabId: 44,
      documentId: 'document-b',
      token,
      remember: true,
    })).rejects.toMatchObject({ code: 'invalid_input' });
    expect(broker.matchCaller({ url: launch.url, tabId: 44, documentId: 'document-a' }))
      .toEqual(owner);
    await expect(broker.complete({
      owner,
      url: launch.url,
      tabId: 44,
      documentId: 'document-a',
      token,
      remember: true,
    })).resolves.toEqual({ status: 'unlocked' });
    expect(activate).toHaveBeenCalledTimes(2);
    expect(activate.mock.calls[1]?.[0]).toMatchObject({
      twoFactor: {
        provider: 7,
        assertion: { token, remember: true, origin: 'https://vault.example' },
      },
    });
    expect(broker.matchCaller({ url: launch.url, tabId: 44, documentId: 'document-a' }))
      .toBeUndefined();
    await expect(broker.complete({
      owner,
      url: launch.url,
      tabId: 44,
      documentId: 'document-a',
      token,
      remember: true,
    })).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('burns an invalid connector callback without claiming durable state and permits a fresh launch', async () => {
    const harness = makeHarness({
      activate: async () => ({
        kind: 'twoFactor',
        providers: [7],
        providerMetadata: fidoProviderMetadata(),
      }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));
    await harness.coordinator.begin('user@example.com');
    const owner = await currentInteractiveOwner(harness);
    const broker = harness.coordinator.interactiveTwoFactor;
    const launch = await broker.begin({
      owner,
      parentUrl: 'chrome-extension://extension-id/popup.html',
      locale: 'zh-CN',
    });
    await broker.bindTab({ owner, url: launch.url, tabId: 45, documentId: 'document-a' });

    await expect(broker.complete({
      owner,
      url: launch.url,
      tabId: 45,
      documentId: 'document-a',
      token: '{}',
      remember: false,
    })).rejects.toMatchObject({ code: 'invalid_input' });
    expect(broker.matchCaller({ url: launch.url, tabId: 45, documentId: 'document-a' }))
      .toBeUndefined();
    const afterInvalid = await harness.stateStore.read();
    expect(afterInvalid).toMatchObject({ claimed: false, owner: { generation: owner.generation } });

    const fresh = await broker.begin({
      owner,
      parentUrl: 'chrome-extension://extension-id/popup.html',
      locale: 'zh-CN',
    });
    expect(fresh.url).toBe(launch.url);
    await expect(broker.cancelLaunch({ owner, url: fresh.url })).resolves.toBe(true);
  });

  it.each(['cancel', 'transition', 'deadline'] as const)(
    'safely closes an exact bound connector on device-login %s cleanup',
    async (cleanup) => {
      const closeConnector = vi.fn(async () => undefined);
      const harness = makeHarness({
        activate: async () => ({
          kind: 'twoFactor',
          providers: [7],
          providerMetadata: fidoProviderMetadata(),
        }),
        closeInteractiveTwoFactorConnector: closeConnector,
      });
      harness.getResponses.push((input) => approvedResponseFromInput(input));
      const challenge = await harness.coordinator.begin('user@example.com');
      if (challenge.status !== 'two_factor' || !challenge.fido2) {
        throw new Error('Expected FIDO2 challenge');
      }
      const broker = harness.coordinator.interactiveTwoFactor;
      const launch = await broker.begin({
        owner: challenge.fido2.owner,
        parentUrl: 'chrome-extension://extension-id/ui/popup/popup.html',
        locale: 'en',
      });
      const document = Object.freeze({
        owner: challenge.fido2.owner,
        url: launch.url,
        tabId: 44,
        documentId: 'document-cleanup',
      });
      await broker.bindTab(document);

      if (cleanup === 'cancel') {
        await expect(harness.coordinator.cancel(challenge.generation)).resolves.toBe(true);
      } else if (cleanup === 'transition') {
        await expect(harness.coordinator.revokeForSessionTransition({
          phase: 'start', transitionId: 81, reason: 'logout', identityChanged: true,
        })).resolves.toBeUndefined();
      } else {
        harness.setNow(challenge.expiresAt);
        await expect(harness.coordinator.handleAlarm(
          `${DEVICE_LOGIN_DEADLINE_ALARM_PREFIX}${challenge.generation}`,
        )).resolves.toEqual({ status: 'none' });
      }

      expect(closeConnector).toHaveBeenCalledWith({
        url: document.url,
        tabId: document.tabId,
        documentId: document.documentId,
      });
      await expect(harness.stateStore.read()).resolves.toBeUndefined();
    },
  );

  it('closes the old-generation connector before a claimed watchdog can fail', async () => {
    const closeConnector = vi.fn(async () => undefined);
    const activate = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor',
        providers: [0, 7],
        providerMetadata: fidoProviderMetadata(),
      })
      .mockResolvedValueOnce({ kind: 'unlocked' });
    const harness = makeHarness({
      activate,
      closeInteractiveTwoFactorConnector: closeConnector,
    });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    const challenge = await harness.coordinator.begin('user@example.com');
    if (challenge.status !== 'two_factor' || !challenge.fido2) {
      throw new Error('Expected FIDO2 challenge');
    }
    const launch = await harness.coordinator.interactiveTwoFactor.begin({
      owner: challenge.fido2.owner,
      parentUrl: 'chrome-extension://extension-id/ui/popup/popup.html',
      locale: 'en',
    });
    await harness.coordinator.interactiveTwoFactor.bindTab({
      owner: challenge.fido2.owner,
      url: launch.url,
      tabId: 49,
      documentId: 'document-before-watchdog',
    });
    harness.createAlarm.mockRejectedValueOnce(new Error('watchdog unavailable'));

    await expect(harness.coordinator.submitTwoFactor({
      generation: challenge.generation,
      provider: 0,
      code: '123456',
    })).resolves.toMatchObject({ status: 'outcome_unknown' });
    expect(closeConnector).toHaveBeenCalledWith({
      url: launch.url,
      tabId: 49,
      documentId: 'document-before-watchdog',
    });
    expect(activate).toHaveBeenCalledOnce();
  });

  it('rebuilds the one-shot FIDO2 request binding in a new coordinator instance', async () => {
    const first = makeHarness({
      activate: async () => ({
        kind: 'twoFactor',
        providers: [7],
        providerMetadata: fidoProviderMetadata(),
      }),
    });
    first.getResponses.push((input) => approvedResponseFromInput(input));
    await first.coordinator.begin('user@example.com');
    const stored = await first.stateStore.read();
    if (!stored || 'status' in stored || stored.claimed
        || stored.state.phase !== 'bound' || !stored.twoFactor?.fido2) {
      throw new Error('Expected persisted FIDO2 state');
    }

    const restarted = makeHarness({ stateStore: first.stateStore });
    restarted.createdInputs.push({
      email: stored.state.email,
      publicKey: stored.state.publicKey,
      deviceIdentifier: stored.state.device.identifier,
      accessCode: stored.state.accessCode,
      type: 0,
    });
    restarted.getResponses.push((input) => approvedResponseFromInput(input));
    const owner = await currentInteractiveOwner(restarted);
    const launch = await restarted.coordinator.interactiveTwoFactor.begin({
      owner,
      parentUrl: 'chrome-extension://extension-id/popup.html',
      locale: 'en',
    });
    await restarted.coordinator.interactiveTwoFactor.bindTab({
      owner, url: launch.url, tabId: 48, documentId: 'document-restarted',
    });
    const token = await connectorToken(stored.twoFactor.fido2.connectorData);

    await expect(restarted.coordinator.interactiveTwoFactor.complete({
      owner, url: launch.url, tabId: 48, documentId: 'document-restarted',
      token, remember: false,
    })).resolves.toEqual({ status: 'unlocked' });
    expect(restarted.activate).toHaveBeenCalledOnce();
    await expect(first.stateStore.read()).resolves.toBeUndefined();
  });

  it('releases a definitely rejected provider 7 grant under a fresh owner for a new assertion', async () => {
    let activation = 0;
    const harness = makeHarness({
      activate: async (input) => {
        activation += 1;
        if (activation === 1) {
          return {
            kind: 'twoFactor',
            providers: [7],
            providerMetadata: fidoProviderMetadata(),
          };
        }
        input.reportActivationStage('pre_grant');
        input.reportActivationStage('grant_started');
        input.reportActivationStage('grant_rejected');
        throw new ApiHttpError(400, { error: 'invalid_grant' });
      },
    });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    await harness.coordinator.begin('user@example.com');
    const before = await harness.stateStore.read();
    if (!before || 'status' in before || before.claimed || !before.twoFactor?.fido2) {
      throw new Error('Expected FIDO2 state');
    }
    const owner = await currentInteractiveOwner(harness);
    const launch = await harness.coordinator.interactiveTwoFactor.begin({
      owner,
      parentUrl: 'chrome-extension://extension-id/popup.html',
      locale: 'en',
    });
    await harness.coordinator.interactiveTwoFactor.bindTab({
      owner, url: launch.url, tabId: 46, documentId: 'document-retry',
    });
    const token = await connectorToken(before.twoFactor.fido2.connectorData);

    await expect(harness.coordinator.interactiveTwoFactor.complete({
      owner, url: launch.url, tabId: 46, documentId: 'document-retry',
      token, remember: false,
    })).resolves.toMatchObject({
      status: 'retry_required', generation: expect.any(Number), providers: [7],
    });
    const released = await harness.stateStore.read();
    expect(released).toMatchObject({
      claimed: false,
      retryRequired: true,
      twoFactor: { providers: [7], fido2: before.twoFactor.fido2 },
    });
    expect(released?.owner.generation).toBeGreaterThan(owner.generation);
    expect(harness.coordinator.interactiveTwoFactor.matchCaller({
      url: launch.url, tabId: 46, documentId: 'document-retry',
    })).toBeUndefined();
  });

  it('terminalizes an uncertain provider 7 grant and removes all replayable connector data', async () => {
    let activation = 0;
    const harness = makeHarness({
      activate: async (input) => {
        activation += 1;
        if (activation === 1) {
          return {
            kind: 'twoFactor',
            providers: [7],
            providerMetadata: fidoProviderMetadata(),
          };
        }
        input.reportActivationStage('pre_grant');
        input.reportActivationStage('grant_started');
        throw new Error('network outcome is unknown');
      },
    });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    await harness.coordinator.begin('user@example.com');
    const before = await harness.stateStore.read();
    if (!before || 'status' in before || before.claimed || !before.twoFactor?.fido2) {
      throw new Error('Expected FIDO2 state');
    }
    const owner = await currentInteractiveOwner(harness);
    const launch = await harness.coordinator.interactiveTwoFactor.begin({
      owner,
      parentUrl: 'chrome-extension://extension-id/popup.html',
      locale: 'en',
    });
    await harness.coordinator.interactiveTwoFactor.bindTab({
      owner, url: launch.url, tabId: 47, documentId: 'document-unknown',
    });
    const token = await connectorToken(before.twoFactor.fido2.connectorData);

    await expect(harness.coordinator.interactiveTwoFactor.complete({
      owner, url: launch.url, tabId: 47, documentId: 'document-unknown',
      token, remember: false,
    })).resolves.toMatchObject({ status: 'outcome_unknown', generation: expect.any(Number) });
    const terminal = await harness.stateStore.read();
    expect(terminal).toMatchObject({ status: 'outcome_unknown' });
    expect(JSON.stringify(terminal)).not.toContain('connectorData');
    expect(JSON.stringify(terminal)).not.toContain(token);
  });

  it('returns unsupported for Duo interactive providers and rejects them as direct codes', async () => {
    const harness = makeHarness({
      activate: async () => ({ kind: 'twoFactor', providers: [2, 6] }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    const unsupported = await harness.coordinator.begin('user@example.com');
    expect(unsupported).toMatchObject({
      status: 'two_factor_unsupported', generation: expect.any(Number), providers: [2, 6],
    });
    if (unsupported.status !== 'two_factor_unsupported') {
      throw new Error('Expected unsupported two-factor challenge');
    }
    await expect(harness.coordinator.submitTwoFactor({
      generation: unsupported.generation, provider: 2, code: 'duo-token',
    }))
      .rejects.toMatchObject({ code: 'invalid_input' });
    expect(harness.activate).toHaveBeenCalledOnce();
  });

  it('persists and completes an owner-bound Duo provider through device login', async () => {
    const onGrantStarted = vi.fn(async () => {});
    const onGrantDispatched = vi.fn();
    const activate = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [2],
        providerMetadata: duoProviderMetadata(),
      })
      .mockImplementationOnce(async (input) => {
        await input.onGrantStarted?.();
        input.onGrantDispatched?.();
        return { kind: 'unlocked' as const };
      });
    const harness = makeHarness({ activate });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );

    const challenge = await harness.coordinator.begin('user@example.com');
    expect(challenge).toMatchObject({ status: 'two_factor', providers: [2] });
    if (challenge.status !== 'two_factor') throw new Error('Expected Duo challenge');
    const prepared = await harness.coordinator.prepareDuoTwoFactor({
      generation: challenge.generation,
      provider: 2,
    });
    expect(prepared.owner).toMatchObject({
      flow: 'deviceLogin',
      provider: 2,
      email: 'user@example.com',
    });

    await expect(harness.coordinator.completeDuoTwoFactor({
      owner: prepared.owner,
      token: 'authorization-code|server-state',
      remember: true,
      onGrantStarted,
      onGrantDispatched,
    })).resolves.toEqual({ status: 'unlocked' });
    expect(activate).toHaveBeenLastCalledWith(expect.objectContaining({
      twoFactor: {
        provider: 2,
        code: 'authorization-code|server-state',
        remember: true,
      },
    }));
    expect(onGrantStarted).toHaveBeenCalledOnce();
    expect(onGrantDispatched).toHaveBeenCalledOnce();
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('releases a Duo device continuation when grant preparation fails before dispatch', async () => {
    const preGrantError = new AppError('session_expired', 'stale Duo grant');
    const activate = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [2],
        providerMetadata: duoProviderMetadata(),
      })
      .mockImplementationOnce(async (input) => {
        input.reportActivationStage?.('pre_grant');
        await input.onGrantStarted?.();
        throw new Error('unreachable');
      });
    const harness = makeHarness({ activate });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    const challenge = await harness.coordinator.begin('user@example.com');
    if (challenge.status !== 'two_factor') throw new Error('Expected Duo challenge');
    const prepared = await harness.coordinator.prepareDuoTwoFactor({
      generation: challenge.generation,
      provider: 2,
    });

    await expect(harness.coordinator.completeDuoTwoFactor({
      owner: prepared.owner,
      token: 'authorization-code|server-state',
      remember: false,
      onGrantStarted: async () => { throw preGrantError; },
      onGrantDispatched: () => {},
    })).rejects.toBe(preGrantError);
    await expect(harness.stateStore.read()).resolves.toMatchObject({
      claimed: false,
      twoFactor: { providers: [2] },
    });
  });

  it('keeps a dispatched Duo device grant network failure outcome-unknown', async () => {
    const networkError = new Error('network failed after dispatch');
    const activate = vi.fn()
      .mockResolvedValueOnce({
        kind: 'twoFactor' as const,
        providers: [2],
        providerMetadata: duoProviderMetadata(),
      })
      .mockImplementationOnce(async (input) => {
        input.reportActivationStage?.('pre_grant');
        await input.onGrantStarted?.();
        input.reportActivationStage?.('grant_started');
        input.onGrantDispatched?.();
        throw networkError;
      });
    const harness = makeHarness({ activate });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    const challenge = await harness.coordinator.begin('user@example.com');
    if (challenge.status !== 'two_factor') throw new Error('Expected Duo challenge');
    const prepared = await harness.coordinator.prepareDuoTwoFactor({
      generation: challenge.generation,
      provider: 2,
    });

    await expect(harness.coordinator.completeDuoTwoFactor({
      owner: prepared.owner,
      token: 'authorization-code|server-state',
      remember: false,
      onGrantStarted: async () => {},
      onGrantDispatched: () => {},
    })).rejects.toBe(networkError);
    await expect(harness.stateStore.read()).resolves.toMatchObject({ status: 'outcome_unknown' });
  });

  it('terminalizes a timed-out token grant and never replays it', async () => {
    const secretError = new Error('access-code-and-token-must-not-leak');
    const harness = makeHarness({
      activate: vi.fn(async (input) => {
        input.reportActivationStage('pre_grant');
        input.reportActivationStage('grant_started');
        throw secretError;
      }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    const first = await harness.coordinator.begin('user@example.com');
    expect(first).toMatchObject({ status: 'outcome_unknown', generation: expect.any(Number) });
    if (first.status !== 'outcome_unknown') throw new Error('Expected outcome-unknown result');
    expect(String(first)).not.toContain(secretError.message);
    await expect(harness.coordinator.status()).resolves.toMatchObject({
      status: 'outcome_unknown', generation: first.generation,
    });
    expect(harness.activate).toHaveBeenCalledOnce();
    await expect(harness.coordinator.retryActivation(first.generation)).resolves.toMatchObject({
      status: 'outcome_unknown',
      generation: first.generation,
    });
    expect(harness.activate).toHaveBeenCalledOnce();
  });

  it('releases a pre-grant activation failure for retry instead of marking it unknown', async () => {
    const harness = makeHarness({
      activate: vi.fn(async (input) => {
        input.reportActivationStage('pre_grant');
        throw new Error('prelogin unavailable');
      }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    await expect(harness.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'retry_required',
      generation: expect.any(Number),
    });
    await expect(harness.coordinator.status()).resolves.toMatchObject({
      status: 'retry_required',
      generation: expect.any(Number),
    });
    expect(harness.activate).toHaveBeenCalledOnce();
    const stored = await harness.stateStore.read();
    expect(stored && !('status' in stored) && stored.retryRequired).toBe(true);
  });

  it('lets a synchronous lifecycle revoke prevent retry before queued durable cleanup', async () => {
    const prelogin = deferred<DeviceLoginAuthResult | NewDeviceVerificationAuthResult>();
    const harness = makeHarness({
      activate: vi.fn((input) => {
        input.reportActivationStage('pre_grant');
        return prelogin.promise;
      }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    const activation = harness.coordinator.begin('user@example.com');
    await vi.waitFor(() => expect(harness.activate).toHaveBeenCalledOnce());
    const cancellation = harness.coordinator.cancelCurrent();
    prelogin.reject(new Error('prelogin unavailable'));

    await expect(activation).resolves.toMatchObject({
      status: 'outcome_unknown', generation: expect.any(Number),
    });
    await expect(cancellation).resolves.toBe(true);
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
    await expect(harness.coordinator.status()).resolves.toEqual({ status: 'none' });
  });

  it('synchronously revokes an exact visible generation while its grant is in flight', async () => {
    const remote = deferred<void>();
    let activationInput: Parameters<DeviceLoginCoordinatorDeps['activate']>[0] | undefined;
    let activation = 0;
    let committed = false;
    const harness = makeHarness({
      activate: async (input) => {
        activation += 1;
        if (activation === 1) return { kind: 'twoFactor', providers: [0] };
        activationInput = input;
        input.reportActivationStage('pre_grant');
        input.reportActivationStage('grant_started');
        await remote.promise;
        input.assertTransitionOwnerCurrent();
        committed = true;
        return { kind: 'unlocked' };
      },
    });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    const challenge = await harness.coordinator.begin('user@example.com');
    if (challenge.status !== 'two_factor') throw new Error('Expected two-factor challenge');

    const submission = harness.coordinator.submitTwoFactor({
      generation: challenge.generation,
      provider: 0,
      code: '123456',
    });
    await vi.waitFor(() => expect(activationInput).toBeDefined());
    const cancellation = harness.coordinator.cancel(challenge.generation);
    expect(() => activationInput!.assertTransitionOwnerCurrent()).toThrow(/authorization changed/);
    remote.resolve();

    await expect(submission).resolves.toMatchObject({ status: 'outcome_unknown' });
    await expect(cancellation).resolves.toBe(true);
    expect(committed).toBe(false);
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('revokes an in-flight remote grant before a foreign session transition can commit it', async () => {
    const remote = deferred<void>();
    let activationInput: Parameters<DeviceLoginCoordinatorDeps['activate']>[0] | undefined;
    let committed = false;
    const harness = makeHarness({
      activate: async (input) => {
        activationInput = input;
        input.reportActivationStage('pre_grant');
        input.reportActivationStage('grant_started');
        await remote.promise;
        input.assertTransitionOwnerCurrent();
        committed = true;
        return { kind: 'unlocked' };
      },
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    const activation = harness.coordinator.begin('user@example.com');
    await vi.waitFor(() => expect(activationInput).toBeDefined());
    const revocation = harness.coordinator.revokeForSessionTransition({
      phase: 'start', transitionId: 41, reason: 'logout', identityChanged: true,
    });
    expect(() => activationInput!.assertTransitionOwnerCurrent()).toThrow(/authorization changed/);
    remote.resolve();

    await expect(activation).resolves.toMatchObject({ status: 'outcome_unknown' });
    await expect(revocation).resolves.toBeUndefined();
    expect(committed).toBe(false);
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
    await expect(harness.coordinator.status()).resolves.toEqual({ status: 'none' });
  });

  it('recognizes its exact typed login transition owner without revoking itself', async () => {
    const remote = deferred<void>();
    let activationInput: Parameters<DeviceLoginCoordinatorDeps['activate']>[0] | undefined;
    const harness = makeHarness({
      activate: async (input) => {
        activationInput = input;
        input.reportActivationStage('pre_grant');
        input.reportActivationStage('grant_started');
        await remote.promise;
        input.assertTransitionOwnerCurrent();
        return { kind: 'unlocked' };
      },
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    const activation = harness.coordinator.begin('user@example.com');
    await vi.waitFor(() => expect(activationInput).toBeDefined());
    await expect(harness.coordinator.revokeForSessionTransition({
      phase: 'start',
      transitionId: 42,
      reason: 'login',
      identityChanged: true,
      owner: activationInput!.transitionOwner,
    })).resolves.toBeUndefined();
    expect(() => activationInput!.assertTransitionOwnerCurrent()).not.toThrow();
    remote.resolve();

    await expect(activation).resolves.toEqual({ status: 'unlocked' });
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it.each([408, 429])(
    'marks an explicit two-factor grant HTTP %s as outcome unknown instead of releasing it',
    async (status) => {
      const activate = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor', providers: [0] })
        .mockImplementationOnce(async (input: Parameters<DeviceLoginCoordinatorDeps['activate']>[0]) => {
          input.reportActivationStage('pre_grant');
          input.reportActivationStage('grant_started');
          throw new ApiHttpError(status, { error: 'temporarily unavailable' });
        });
      const harness = makeHarness({ activate });
      harness.getResponses.push(
        (input) => approvedResponseFromInput(input),
        (input) => approvedResponseFromInput(input),
      );
      const challenge = await harness.coordinator.begin('user@example.com');
      if (challenge.status !== 'two_factor') throw new Error('Expected two-factor challenge');

      await expect(harness.coordinator.submitTwoFactor({
        generation: challenge.generation,
        provider: 0,
        code: '123456',
      })).resolves.toMatchObject({
        status: 'outcome_unknown',
        generation: expect.any(Number),
      });
      const stored = await harness.stateStore.read();
      expect(stored && 'status' in stored && stored.status).toBe('outcome_unknown');
      expect(stored && 'status' in stored && stored.owner.generation)
        .toBeGreaterThan(challenge.generation);
    },
  );

  it.each([408, 429])(
    'marks auth-request creation HTTP %s as outcome unknown instead of starting a duplicate',
    async (status) => {
      const harness = makeHarness();
      harness.api.createAuthRequest.mockRejectedValueOnce(
        new ApiHttpError(status, { error: 'temporarily unavailable' }),
      );

      await expect(harness.coordinator.begin('user@example.com')).resolves.toMatchObject({
        status: 'outcome_unknown',
        generation: expect.any(Number),
      });
      expect(harness.api.createAuthRequest).toHaveBeenCalledOnce();
      const stored = await harness.stateStore.read();
      expect(stored && 'status' in stored && stored.status).toBe('outcome_unknown');
    },
  );

  it('clears a definite malformed two-factor response and reports invalid response', async () => {
    const harness = makeHarness({
      activate: async () => ({ kind: 'twoFactor', providers: [] }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    await expect(harness.coordinator.begin('user@example.com'))
      .rejects.toMatchObject({ code: 'invalid_response' });
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('clears a definitely rejected or unsupported device-login activation without uncertainty', async () => {
    const definiteRejection = vi.fn(async (input: Parameters<DeviceLoginCoordinatorDeps['activate']>[0]) => {
      input.reportActivationStage('pre_grant');
      input.reportActivationStage('grant_started');
      input.reportActivationStage('grant_rejected');
      throw new ApiHttpError(400, { error: 'invalid_grant' });
    });
    for (const activate of [
      definiteRejection,
      vi.fn().mockResolvedValue({
        kind: 'newDeviceVerification', attemptId: 7, expiresAt: 301_000,
      }),
    ]) {
      const harness = makeHarness({ activate });
      harness.getResponses.push((input) => approvedResponseFromInput(input));

      await expect(harness.coordinator.begin('user@example.com')).resolves.toEqual({ status: 'none' });
      expect(await harness.stateStore.read()).toBeUndefined();
      expect(activate).toHaveBeenCalledOnce();
    }
  });

  it('releases only an explicit 2FA HTTP 400 for a corrected user retry', async () => {
    const harness = makeHarness({
      activate: vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor', providers: [1], token: 'email-token' })
        .mockRejectedValueOnce(new ApiHttpError(400, { error: 'invalid_grant' }))
        .mockResolvedValueOnce({ kind: 'unlocked' }),
    });
    harness.getResponses.push(
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
      (input) => approvedResponseFromInput(input),
    );
    const challenge = await harness.coordinator.begin('user@example.com');
    if (challenge.status !== 'two_factor') throw new Error('Expected two-factor challenge');

    const retry = await harness.coordinator.submitTwoFactor({
      generation: challenge.generation, provider: 1, code: 'wrong',
    });
    expect(retry).toMatchObject({
      status: 'retry_required', generation: expect.any(Number), providers: [1],
    });
    if (retry.status !== 'retry_required') throw new Error('Expected two-factor retry');
    const before = harness.api.getAuthRequestResponse.mock.calls.length;
    await expect(harness.coordinator.status()).resolves.toMatchObject({
      status: 'retry_required', generation: retry.generation, providers: [1],
    });
    expect(harness.api.getAuthRequestResponse).toHaveBeenCalledTimes(before);

    await expect(harness.coordinator.submitTwoFactor({
      generation: retry.generation, provider: 1, code: 'correct',
    }))
      .resolves.toEqual({ status: 'unlocked' });
    expect(harness.activate).toHaveBeenCalledTimes(3);
  });

  it('returns explicit FIDO2 unsupported state without retaining a password pending flow', async () => {
    const harness = makeHarness({
      activate: async () => ({ kind: 'twoFactor', providers: [7], token: 'opaque' }),
    });
    harness.getResponses.push((input) => approvedResponseFromInput(input));

    await expect(harness.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'two_factor_unsupported', generation: expect.any(Number), providers: [7],
    });

    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });
});

describe('DeviceLoginCoordinator leases, alarms, and recovery', () => {
  it('terminalizes secret state when a required bound, claim, or release watchdog cannot persist', async () => {
    const boundCreate = vi.fn(async () => { throw new Error('alarm unavailable'); });
    const boundFailure = makeHarness({
      alarms: { create: boundCreate, clear: async () => true },
    });
    await expect(boundFailure.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'outcome_unknown',
      generation: expect.any(Number),
    });
    expect(boundFailure.api.getAuthRequestResponse).not.toHaveBeenCalled();
    expect(await boundFailure.stateStore.read()).not.toHaveProperty('state');

    const claimCreate = vi.fn(async (name: string) => {
      if (name.endsWith(':3')) throw new Error('claim watchdog unavailable');
    });
    const claimFailure = makeHarness({
      alarms: { create: claimCreate, clear: async () => true },
    });
    claimFailure.getResponses.push((input) => approvedResponseFromInput(input));
    await expect(claimFailure.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'outcome_unknown',
      generation: expect.any(Number),
    });
    expect(claimFailure.activate).not.toHaveBeenCalled();
    expect(await claimFailure.stateStore.read()).not.toHaveProperty('state');

    const releaseCreate = vi.fn(async (name: string) => {
      if (name === `${DEVICE_LOGIN_DEADLINE_ALARM_PREFIX}4`) {
        throw new Error('release deadline unavailable');
      }
    });
    const releaseFailure = makeHarness({
      alarms: { create: releaseCreate, clear: async () => true },
      activate: async () => ({ kind: 'twoFactor', providers: [1], token: 'secret-token' }),
    });
    releaseFailure.getResponses.push((input) => approvedResponseFromInput(input));
    await expect(releaseFailure.coordinator.begin('user@example.com')).resolves.toMatchObject({
      status: 'outcome_unknown',
      generation: expect.any(Number),
    });
    const terminal = await releaseFailure.stateStore.read();
    expect(terminal).not.toHaveProperty('state');
    expect(JSON.stringify(terminal)).not.toContain('secret-token');
  });

  it('revalidates the server lease after known-device and never posts to a changed server', async () => {
    const known = deferred<boolean>();
    const harness = makeHarness();
    harness.api.isKnownDevice.mockImplementation(() => known.promise);

    const beginning = harness.coordinator.begin('user@example.com');
    await vi.waitFor(() => expect(harness.api.isKnownDevice).toHaveBeenCalledOnce());
    harness.leaseControl.change(OTHER_SERVER_URL);
    known.resolve(true);

    await expect(beginning).rejects.toMatchObject({ code: 'server_changed' });
    expect(harness.api.createAuthRequest).not.toHaveBeenCalled();
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
    expect(harness.fixedServers).toEqual([SERVER_URL]);
  });

  it('retires a bound old-server request without fetching from either backend', async () => {
    const harness = makeHarness();
    await seedBound(harness.stateStore);
    harness.leaseControl.change(OTHER_SERVER_URL);

    await expect(harness.coordinator.status()).resolves.toEqual({ status: 'none' });

    expect(harness.api.getAuthRequestResponse).not.toHaveBeenCalled();
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
    expect(harness.fixedServers).toEqual([OTHER_SERVER_URL]);
  });

  it('does not revive an old request after a same-URL server ABA transition', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin('user@example.com');
    const before = harness.api.getAuthRequestResponse.mock.calls.length;
    harness.leaseControl.change(OTHER_SERVER_URL);
    harness.leaseControl.change(SERVER_URL);

    await expect(harness.coordinator.status()).resolves.toEqual({ status: 'none' });

    expect(harness.api.getAuthRequestResponse).toHaveBeenCalledTimes(before);
    await expect(harness.stateStore.read()).resolves.toBeUndefined();
  });

  it('ignores and clears an old generation poll alarm without reviving the current request', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin('user@example.com');
    const current = await harness.stateStore.read();
    if (!current || 'status' in current) throw new Error('Expected active state');
    const oldAlarm = `${DEVICE_LOGIN_STATUS_ALARM_PREFIX}${current.owner.generation - 1}`;
    const before = harness.api.getAuthRequestResponse.mock.calls.length;

    await harness.coordinator.handleAlarm(oldAlarm);

    expect(harness.api.getAuthRequestResponse).toHaveBeenCalledTimes(before);
    expect(harness.clearAlarm).toHaveBeenCalledWith(oldAlarm);
    await expect(harness.stateStore.read()).resolves.toEqual(current);
  });

  it('delegates anonymous reconnect alarms without treating them as status polls', async () => {
    const harness = makeHarness();

    await harness.coordinator.handleAlarm({
      name: 'device-login-notifications-reconnect:instance:1',
      scheduledTime: NOW,
    });

    expect(harness.notifications.handleAlarm).toHaveBeenCalledOnce();
    expect(harness.api.getAuthRequestResponse).not.toHaveBeenCalled();
  });

  it('singleflights concurrent status reads and schedules the final poll at the request deadline', async () => {
    const harness = makeHarness();
    const bound = await seedBound(harness.stateStore);
    harness.createdInputs.push({
      email: bound.email,
      publicKey: bound.publicKey,
      deviceIdentifier: bound.device.identifier,
      accessCode: bound.accessCode,
      type: 0,
    });
    harness.setNow(bound.expiresAt - 5_000);
    const response = deferred<unknown>();
    harness.api.getAuthRequestResponse.mockImplementationOnce(() => response.promise);

    const first = harness.coordinator.status();
    const second = harness.coordinator.status();
    expect(second).toBe(first);
    await vi.waitFor(() => expect(harness.api.getAuthRequestResponse).toHaveBeenCalledOnce());
    response.resolve(pendingResponseFromInput(harness.createdInputs[0]!));
    await expect(Promise.all([first, second])).resolves.toEqual([
      expect.objectContaining({ status: 'pending', generation: expect.any(Number) }),
      expect.objectContaining({ status: 'pending', generation: expect.any(Number) }),
    ]);

    const lastAlarm = harness.createAlarm.mock.calls.at(-1)!;
    expect(lastAlarm[1]).toEqual({ when: bound.expiresAt });
  });

  it('turns an unresolved same-worker claim into a secret-free outcome-unknown startup state', async () => {
    const harness = makeHarness();
    await seedBound(harness.stateStore);
    const active = await harness.stateStore.read();
    if (!active || 'status' in active || active.claimed) throw new Error('Expected active bound state');
    const claimed = await harness.stateStore.claim(active.owner);
    expect(claimed).toBeDefined();

    const result = await harness.coordinator.startup();

    expect(result).toMatchObject({
      status: 'outcome_unknown',
      generation: expect.any(Number),
      serverOrigin: 'https://vault.example',
    });
    expect(harness.activate).not.toHaveBeenCalled();
    expect(harness.api.getAuthRequestResponse).not.toHaveBeenCalled();
    const stored = await harness.stateStore.read();
    expect(stored && 'status' in stored && stored.status).toBe('outcome_unknown');
    expect(JSON.stringify(stored)).not.toContain(claimed!.state.accessCode);
    expect(JSON.stringify(stored)).not.toContain(claimed!.state.privateKeyPkcs8);
  });

  it('cancels the exact current owner, stops notifications, and clears its generation alarm', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin('user@example.com');
    const current = await harness.stateStore.read();
    if (!current || 'status' in current) throw new Error('Expected active state');

    await expect(harness.coordinator.cancel(current.owner.generation)).resolves.toBe(true);

    await expect(harness.stateStore.read()).resolves.toBeUndefined();
    expect(harness.notifications.stop).toHaveBeenCalled();
    expect(harness.clearAlarm).toHaveBeenCalledWith(
      `${DEVICE_LOGIN_STATUS_ALARM_PREFIX}${current.owner.generation}`,
    );
  });
});
