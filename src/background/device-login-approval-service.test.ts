import { beforeAll, describe, expect, it, vi } from 'vitest';

import type { ApiClient, AuthRequestUpdateInput } from '../core/api/client.js';
import { base64ToBytes, bytesToBase64 } from '../core/crypto/encoding.js';
import { parseRsaEncString } from '../core/crypto/encstring.js';
import { serializeSymmetricKey, symmetricKeyFromBytes, type SymmetricKey } from '../core/crypto/keys.js';
import { rsaOaepDecrypt } from '../core/crypto/primitives.js';
import { AppError } from '../core/errors.js';
import type { AccountLease } from '../core/session/account-gate.js';
import {
  DEVICE_LOGIN_REQUEST_TTL_MS,
  createDeviceLoginRequest,
  type DeviceLoginPendingState,
} from '../core/session/device-login.js';
import type { ActiveAuth, SessionLease } from '../core/session/session-manager.js';
import {
  DeviceLoginApprovalService,
  createDeviceLoginApprovalService,
  type DeviceLoginApprovalServiceDeps,
} from './device-login-approval-service.js';

const NOW = Date.parse('2026-08-30T08:00:00.000Z');
const CREATED_AT = NOW - 60_000;
const SERVER_URL = 'https://vault.example/base/';
const ACCOUNT_EMAIL = 'user@example.com';
const ACCESS_TOKEN = 'sensitive-access-token';
const APPROVAL_DEVICE_ID = 'approver-device-456';
const REQUEST_ID = 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34';
const REQUEST_DEVICE_ID = 'c05e732e-77b1-457b-8f89-5b5ba1b4e1d2';
const REQUEST_DEVICE = Object.freeze({
  type: 2,
  name: 'Chrome',
  identifier: 'requester-device-123',
});

let pending: DeviceLoginPendingState;
let otherPending: DeviceLoginPendingState;
let userKey: SymmetricKey;

beforeAll(async () => {
  pending = (await createDeviceLoginRequest(
    { email: ACCOUNT_EMAIL, device: REQUEST_DEVICE },
    CREATED_AT,
  )).state;
  otherPending = (await createDeviceLoginRequest(
    { email: ACCOUNT_EMAIL, device: REQUEST_DEVICE },
    CREATED_AT,
  )).state;
  userKey = symmetricKeyFromBytes(
    Uint8Array.from({ length: 64 }, (_, index) => (index * 23 + 11) & 0xff),
  );
});

describe('DeviceLoginApprovalService reads', () => {
  it('lists frozen redacted views through a fixed-server guarded client', async () => {
    const harness = makeHarness();
    const result = await harness.service.list();

    expect(result).toHaveLength(1);
    const candidate = result[0]!;
    expect(candidate.view).toMatchObject({
      id: REQUEST_ID,
      requestDeviceIdentifier: REQUEST_DEVICE.identifier,
      requestDeviceTypeValue: REQUEST_DEVICE.type,
    });
    expect(candidate.view.fingerprint.split('-')).toHaveLength(5);
    expect(candidate.decisionBinding).toMatchObject({
      version: 1,
      requestId: REQUEST_ID,
      requestDeviceIdentifier: REQUEST_DEVICE.identifier,
      creationDate: new Date(CREATED_AT).toISOString(),
      requestDeviceTypeValue: REQUEST_DEVICE.type,
      publicKeyDigest: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      nonce: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
      proof: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(candidate)).toBe(true);
    expect(Object.isFrozen(candidate.decisionBinding)).toBe(true);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(pending.publicKey);
    expect(serialized).not.toContain(ACCESS_TOKEN);
    expect(serialized).not.toContain(bytesToBase64(serializeSymmetricKey(userKey)));
    expect(harness.api.forServer).toHaveBeenCalledWith(SERVER_URL);
    expect(harness.fixedClients).toHaveLength(1);
    expect(harness.fixedClients[0]!.withRequestGuard).toHaveBeenCalledOnce();
    expect(harness.events).toContain('guard:list');
    expect(harness.events).toContain('fetch:list');
    expect(harness.events.indexOf('guard:list') + 1).toBe(harness.events.indexOf('fetch:list'));
  });

  it('ignores malformed list entries without exposing their contents', async () => {
    const secret = 'raw-response-secret';
    const harness = makeHarness();
    harness.pendingResponses = [
      { ...pendingResponse(), unexpected: secret },
      pendingResponse(),
      { ...pendingResponse(), publicKey: 'A'.repeat(392) },
    ];

    const result = await harness.service.list();
    expect(result).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it('gets one request by canonical id and rejects malformed ids before networking', async () => {
    const harness = makeHarness();
    const candidate = await harness.service.get(REQUEST_ID);
    expect(candidate.view.id).toBe(REQUEST_ID);
    expect(harness.events).toContain('fetch:get');

    const invalid = makeHarness();
    await expect(invalid.service.get(`${REQUEST_ID}\n`)).rejects.toMatchObject({
      code: 'denied',
    });
    expect(invalid.events).not.toContain('fetch:get');
    expect(invalid.accountGate.capture).toHaveBeenCalledOnce();
    expect(invalid.sessionGate.capture).toHaveBeenCalledOnce();
  });

  it('captures both leases synchronously at every public entry', () => {
    const harness = makeHarness();
    const calls = [
      harness.service.list(),
      harness.service.get(REQUEST_ID),
      harness.service.approve({}),
      harness.service.deny({}),
    ];

    expect(harness.accountGate.capture).toHaveBeenCalledTimes(4);
    expect(harness.sessionGate.capture).toHaveBeenCalledTimes(4);
    return Promise.allSettled(calls).then(() => undefined);
  });

  it('fails closed after a session transition at an awaited context read', async () => {
    const harness = makeHarness();
    const activeRead = deferred<ActiveAuth | undefined>();
    harness.session.getActiveAuth.mockImplementationOnce(() => activeRead.promise);

    const listing = harness.service.list();
    expect(harness.accountGate.capture).toHaveBeenCalledOnce();
    expect(harness.sessionGate.capture).toHaveBeenCalledOnce();
    harness.sessionCurrent = false;
    activeRead.resolve(harness.activeAuth());

    await expect(listing).rejects.toMatchObject({ code: 'locked' });
    expect(harness.events).not.toContain('fetch:list');
  });

  it('lets the request guard stop a transition immediately before fetch', async () => {
    const harness = makeHarness();
    harness.beforeRequest = (kind) => {
      if (kind === 'list') harness.accountGeneration += 1;
    };

    await expect(harness.service.list()).rejects.toMatchObject({ code: 'session_expired' });
    expect(harness.events).toContain('guard:list');
    expect(harness.events).not.toContain('fetch:list');
  });

  it('requires one bound active email, token, and device identity', async () => {
    const wrongEmail = makeHarness();
    wrongEmail.activeEmail = 'other@example.com';
    await expect(wrongEmail.service.list()).rejects.toMatchObject({ code: 'session_expired' });

    const changedToken = makeHarness();
    changedToken.auth.getAccessToken.mockImplementation(async () => {
      changedToken.accessToken = 'rotated-token';
      return 'different-token';
    });
    await expect(changedToken.service.list()).rejects.toMatchObject({ code: 'session_expired' });

    const badDevice = makeHarness();
    badDevice.deviceIdentifier = 'bad\u202edevice';
    await expect(badDevice.service.list()).rejects.toMatchObject({ code: 'session_expired' });
  });

  it('never reads UserKey for list, get, or deny, and reads it once only for approve', async () => {
    const listing = makeHarness();
    await listing.service.list();
    expect(listing.session.loadUserKey).not.toHaveBeenCalled();

    const getting = makeHarness();
    await getting.service.get(REQUEST_ID);
    expect(getting.session.loadUserKey).not.toHaveBeenCalled();

    const denying = makeHarness();
    const denyBinding = (await denying.service.list())[0]!.decisionBinding;
    await denying.service.deny(denyBinding);
    expect(denying.session.loadUserKey).not.toHaveBeenCalled();

    const approving = makeHarness();
    const approveBinding = (await approving.service.list())[0]!.decisionBinding;
    await approving.service.approve(approveBinding);
    expect(approving.session.loadUserKey).toHaveBeenCalledOnce();
  });

  it('fails approval before PUT when the late UserKey read is unavailable', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    harness.session.loadUserKey.mockResolvedValue(undefined);
    harness.events.length = 0;

    await expect(harness.service.approve(binding)).rejects.toMatchObject({ code: 'locked' });
    expect(harness.events).toContain('fetch:get');
    expect(harness.events).not.toContain('fetch:update');
    expect(harness.session.loadUserKey).toHaveBeenCalledOnce();
  });

  it('sanitizes read failures and never returns their raw payload', async () => {
    const harness = makeHarness();
    const secret = `${ACCESS_TOKEN}:raw-server-key`;
    harness.listImpl = async () => { throw new Error(secret); };

    let error: unknown;
    try {
      await harness.service.list();
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(AppError);
    expect(String(error)).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
  });
});

describe('DeviceLoginApprovalService locked discovery', () => {
  it('returns only a frozen id/expiry projection without session or key access', async () => {
    const harness = makeHarness();
    harness.sessionCurrent = false;

    await expect(harness.service.discover()).resolves.toEqual([{
      requestId: REQUEST_ID,
      expiresAt: CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS,
    }]);

    expect(harness.sessionGate.capture).not.toHaveBeenCalled();
    expect(harness.sessionGate.assert).not.toHaveBeenCalled();
    expect(harness.session.getActiveAuth).not.toHaveBeenCalled();
    expect(harness.session.loadUserKey).not.toHaveBeenCalled();
    expect(harness.auth.getAccessToken).not.toHaveBeenCalled();
    expect(harness.auth.getAccountAccessToken).toHaveBeenCalledOnce();
    const result = await harness.service.discover();
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result[0])).toBe(true);
    expect(JSON.stringify(result)).not.toContain(pending.publicKey);
    expect(JSON.stringify(result)).not.toContain(ACCESS_TOKEN);
  });

  it('filters answered, expired, malformed, and response-bearing requests', async () => {
    const harness = makeHarness();
    harness.pendingResponses = [
      pendingResponse(),
      { ...pendingResponse(), responseDate: new Date(NOW - 1).toISOString() },
      {
        ...pendingResponse(),
        creationDate: new Date(NOW - DEVICE_LOGIN_REQUEST_TTL_MS).toISOString(),
      },
      { ...pendingResponse(), key: '4.response-material' },
      { ...pendingResponse(), unexpected: 'private raw value' },
    ];

    await expect(harness.service.discover()).resolves.toEqual([{
      requestId: REQUEST_ID,
      expiresAt: CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS,
    }]);
  });

  it('rejects an account transition before the pending-request fetch', async () => {
    const harness = makeHarness();
    const token = deferred<string>();
    harness.auth.getAccountAccessToken.mockImplementationOnce(() => token.promise);

    const discovering = harness.service.discover();
    await vi.waitFor(() => expect(harness.auth.getAccountAccessToken).toHaveBeenCalledOnce());
    harness.accountGeneration += 1;
    token.resolve(ACCESS_TOKEN);

    await expect(discovering).rejects.toMatchObject({ code: 'session_expired' });
    expect(harness.events).not.toContain('fetch:list');
  });

  it('uses the exact leased server and sanitizes list transport failure', async () => {
    const harness = makeHarness();
    harness.listImpl = async () => { throw new Error(`${ACCESS_TOKEN}:${pending.publicKey}`); };

    let error: unknown;
    try { await harness.service.discover(); } catch (caught) { error = caught; }

    expect(error).toMatchObject({ code: 'error' });
    expect(String(error)).not.toContain(ACCESS_TOKEN);
    expect(JSON.stringify(error)).not.toContain(pending.publicKey);
    expect(harness.api.forServer).toHaveBeenCalledWith(SERVER_URL);
  });
});

describe('DeviceLoginApprovalService decision bindings', () => {
  it('rejects forged, cross-instance, cross-account, and cross-server bindings before GET', async () => {
    const forgedHarness = makeHarness();
    const issued = (await forgedHarness.service.list())[0]!.decisionBinding;
    const forged = { ...issued, requestDeviceIdentifier: 'attacker-device' };
    forgedHarness.events.length = 0;
    await expect(forgedHarness.service.approve(forged)).rejects.toMatchObject({ code: 'denied' });
    expect(forgedHarness.events).not.toContain('fetch:get');

    const secondInstance = new DeviceLoginApprovalService(forgedHarness.deps);
    forgedHarness.events.length = 0;
    await expect(secondInstance.approve(issued)).rejects.toMatchObject({ code: 'denied' });
    expect(forgedHarness.events).not.toContain('fetch:get');

    const changedAccount = makeHarness();
    const accountBinding = (await changedAccount.service.list())[0]!.decisionBinding;
    changedAccount.accountIdentity = 'other@example.com';
    changedAccount.activeEmail = 'other@example.com';
    changedAccount.accountGeneration += 1;
    changedAccount.events.length = 0;
    await expect(changedAccount.service.approve(accountBinding)).rejects.toMatchObject({
      code: 'denied',
    });
    expect(changedAccount.events).not.toContain('fetch:get');

    const changedServer = makeHarness();
    const serverBinding = (await changedServer.service.list())[0]!.decisionBinding;
    changedServer.serverUrl = 'https://other.example/';
    changedServer.serverGeneration += 1;
    changedServer.events.length = 0;
    await expect(changedServer.service.approve(serverBinding)).rejects.toMatchObject({
      code: 'denied',
    });
    expect(changedServer.events).not.toContain('fetch:get');
  });

  it('binds a decision to the exact session lease generation', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    harness.sessionGeneration += 1;
    harness.events.length = 0;

    await expect(harness.service.approve(binding)).rejects.toMatchObject({ code: 'denied' });
    expect(harness.events).not.toContain('fetch:get');
  });

  it('binds a decision to the exact session binding id independently of the lease generation', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    harness.sessionBindingId = 'replacement-session-binding';
    harness.events.length = 0;

    await expect(harness.service.approve(binding)).rejects.toMatchObject({ code: 'denied' });
    expect(harness.events).not.toContain('fetch:get');
  });

  it('rejects accessor and extra-field bindings without invoking caller code', async () => {
    const harness = makeHarness();
    const issued = (await harness.service.list())[0]!.decisionBinding;
    let getterCalls = 0;
    const accessor = { ...issued } as Record<string, unknown>;
    Object.defineProperty(accessor, 'proof', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return issued.proof;
      },
    });
    harness.events.length = 0;

    await expect(harness.service.approve(accessor)).rejects.toMatchObject({ code: 'denied' });
    await expect(harness.service.deny({ ...issued, extra: true })).rejects.toMatchObject({
      code: 'denied',
    });
    expect(getterCalls).toBe(0);
    expect(harness.events).not.toContain('fetch:get');
  });

  it.each([
    ['public key', (response: ReturnType<typeof pendingResponse>) => ({
      ...response,
      publicKey: otherPending.publicKey,
    })],
    ['request device', (response: ReturnType<typeof pendingResponse>) => ({
      ...response,
      requestDeviceIdentifier: 'replacement-device',
    })],
    ['creation date', (response: ReturnType<typeof pendingResponse>) => ({
      ...response,
      creationDate: new Date(CREATED_AT + 1).toISOString(),
    })],
    ['device type', (response: ReturnType<typeof pendingResponse>) => ({
      ...response,
      requestDeviceTypeValue: 3,
    })],
  ])('rejects a changed %s after the authoritative GET', async (_label, mutate) => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    harness.getResponse = mutate(pendingResponse());
    harness.events.length = 0;

    await expect(harness.service.approve(binding)).rejects.toMatchObject({ code: 'denied' });
    expect(harness.events).toContain('fetch:get');
    expect(harness.events).not.toContain('fetch:update');
  });

  it('consumes each binding once and blocks a replay before another GET or PUT', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    await harness.service.approve(binding);
    harness.events.length = 0;

    await expect(harness.service.approve(binding)).rejects.toMatchObject({ code: 'denied' });
    expect(harness.events).not.toContain('fetch:get');
    expect(harness.events).not.toContain('fetch:update');
  });

  it('blocks concurrent approve/deny use of one binding', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    const fetched = deferred<unknown>();
    harness.getImpl = () => fetched.promise;
    harness.events.length = 0;

    const first = harness.service.approve(binding);
    await vi.waitFor(() => expect(harness.events).toContain('fetch:get'));
    await expect(harness.service.deny(binding)).rejects.toMatchObject({ code: 'denied' });
    fetched.resolve(pendingResponse());
    await first;
    expect(harness.events.filter((event) => event === 'fetch:get')).toHaveLength(1);
    expect(harness.events.filter((event) => event === 'fetch:update')).toHaveLength(1);
  });

  it('blocks concurrent decisions made with two independently issued bindings for one request', async () => {
    const harness = makeHarness();
    const firstBinding = (await harness.service.list())[0]!.decisionBinding;
    const secondBinding = (await harness.service.list())[0]!.decisionBinding;
    expect(secondBinding.proof).not.toBe(firstBinding.proof);
    const fetched = deferred<unknown>();
    harness.getImpl = () => fetched.promise;
    harness.events.length = 0;

    const first = harness.service.approve(firstBinding);
    await vi.waitFor(() => expect(harness.events).toContain('fetch:get'));
    await expect(harness.service.deny(secondBinding)).rejects.toMatchObject({ code: 'denied' });
    fetched.resolve(pendingGetResponse());
    await first;
    expect(harness.events.filter((event) => event === 'fetch:get')).toHaveLength(1);
    expect(harness.events.filter((event) => event === 'fetch:update')).toHaveLength(1);
  });

  it('blocks another independently issued binding after the request write completes', async () => {
    const harness = makeHarness();
    const firstBinding = (await harness.service.list())[0]!.decisionBinding;
    const secondBinding = (await harness.service.list())[0]!.decisionBinding;

    await harness.service.approve(firstBinding);
    harness.events.length = 0;

    await expect(harness.service.deny(secondBinding)).rejects.toMatchObject({ code: 'denied' });
    expect(harness.events).not.toContain('fetch:get');
    expect(harness.events).not.toContain('fetch:update');
    expect(harness.updates).toHaveLength(1);
  });
});

describe('DeviceLoginApprovalService writes', () => {
  it('approves with one exact wrapped UserKey and validates the echoed response', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.get(REQUEST_ID)).decisionBinding;
    harness.events.length = 0;

    const receipt = await harness.service.approve(binding);
    expect(receipt).toEqual({
      requestId: REQUEST_ID,
      requestApproved: true,
      responseDate: new Date(NOW).toISOString(),
    });
    expect(Object.isFrozen(receipt)).toBe(true);
    expect(harness.updates).toHaveLength(1);
    const update = harness.updates[0]!;
    expect(update.accessToken).toBe(ACCESS_TOKEN);
    expect(update.requestId).toBe(REQUEST_ID);
    expect(update.body).toEqual({
      key: expect.stringMatching(/^4\./),
      deviceIdentifier: APPROVAL_DEVICE_ID,
      requestApproved: true,
    });
    expect(Object.keys(update.body)).toEqual(['key', 'deviceIdentifier', 'requestApproved']);
    const encrypted = parseRsaEncString(update.body.key!);
    const decrypted = await rsaOaepDecrypt(
      base64ToBytes(pending.privateKeyPkcs8),
      encrypted.data,
      'SHA-1',
    );
    expect(decrypted).toEqual(serializeSymmetricKey(userKey));
    expect(harness.events.indexOf('guard:update') + 1).toBe(
      harness.events.indexOf('fetch:update'),
    );
    expect(harness.events.indexOf('fetch:get')).toBeLessThan(
      harness.events.indexOf('read:userKey'),
    );
    expect(harness.events.indexOf('read:userKey')).toBeLessThan(
      harness.events.indexOf('fetch:update'),
    );
  });

  it('denies with a keyless semantic body and accepts a transport-level empty-key echo', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    const receipt = await harness.service.deny(binding);

    expect(receipt.requestApproved).toBe(false);
    const update = harness.updates[0]!;
    expect(update.body).toEqual({
      deviceIdentifier: APPROVAL_DEVICE_ID,
      requestApproved: false,
    });
    expect(Object.keys(update.body)).toEqual(['deviceIdentifier', 'requestApproved']);
    expect(JSON.stringify(update.body)).not.toContain('masterPasswordHash');
    expect(JSON.stringify(update.body)).not.toContain('key');
  });

  it('marks a PUT as outcome-unknown when its response or identity is invalid', async () => {
    const cases: Array<(response: ReturnType<typeof approvedResponse>) => unknown> = [
      (response) => ({ ...response, key: `4.${'A'.repeat(342)}==` }),
      (response) => ({ ...response, requestDeviceIdentifier: 'changed-device' }),
      (response) => ({ ...response, responseDate: null }),
      (response) => ({ ...response, requestApproved: false }),
    ];

    for (const mutate of cases) {
      const harness = makeHarness();
      const binding = (await harness.service.list())[0]!.decisionBinding;
      harness.updateImpl = async (_accessToken, _requestId, body) => (
        mutate(approvedResponse(body.key!))
      );
      await expect(harness.service.approve(binding)).rejects.toMatchObject({
        code: 'outcome_unknown',
      });
      expect(harness.updates).toHaveLength(1);
    }
  });

  it('rejects a non-empty key in a denial response as outcome-unknown', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    harness.updateImpl = async () => ({
      ...deniedResponse(),
      key: '4.c2VjcmV0',
    });

    await expect(harness.service.deny(binding)).rejects.toMatchObject({
      code: 'outcome_unknown',
    });
    expect(harness.updates).toHaveLength(1);
  });

  it('never retries a failed PUT and sanitizes the transport error', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    const secret = `${ACCESS_TOKEN}:${pending.publicKey}:raw-response`;
    harness.updateImpl = async () => { throw new Error(secret); };

    let error: unknown;
    try {
      await harness.service.approve(binding);
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({ code: 'outcome_unknown' });
    expect(String(error)).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
    expect(harness.updates).toHaveLength(1);
  });

  it('does not reach fetch when the final request guard sees a transition', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    harness.beforeRequest = (kind) => {
      if (kind === 'update') harness.sessionCurrent = false;
    };
    harness.events.length = 0;

    await expect(harness.service.approve(binding)).rejects.toMatchObject({
      code: 'outcome_unknown',
    });
    expect(harness.events).toContain('guard:update');
    expect(harness.events).not.toContain('fetch:update');
    expect(harness.updates).toHaveLength(0);
  });

  it('reports outcome-unknown when a session changes while PUT is in flight', async () => {
    const harness = makeHarness();
    const binding = (await harness.service.list())[0]!.decisionBinding;
    const response = deferred<unknown>();
    harness.updateImpl = () => response.promise;
    harness.events.length = 0;

    const approving = harness.service.approve(binding);
    await vi.waitFor(() => expect(harness.events).toContain('fetch:update'));
    harness.accountGeneration += 1;
    response.resolve(approvedResponse(harness.updates[0]!.body.key!));

    await expect(approving).rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(harness.updates).toHaveLength(1);
  });
});

type RequestKind = 'list' | 'get' | 'update';

interface UpdateCall {
  readonly accessToken: string;
  readonly requestId: string;
  readonly body: AuthRequestUpdateInput;
}

interface Harness {
  service: DeviceLoginApprovalService;
  deps: DeviceLoginApprovalServiceDeps;
  api: { forServer: ReturnType<typeof vi.fn> };
  fixedClients: Array<{ withRequestGuard: ReturnType<typeof vi.fn> }>;
  accountGate: {
    capture: ReturnType<typeof vi.fn>;
    assert: ReturnType<typeof vi.fn>;
  };
  sessionGate: {
    capture: ReturnType<typeof vi.fn>;
    assert: ReturnType<typeof vi.fn>;
  };
  session: {
    getActiveAuth: ReturnType<typeof vi.fn>;
    loadUserKey: ReturnType<typeof vi.fn>;
  };
  auth: {
    getAccessToken: ReturnType<typeof vi.fn>;
    getAccountAccessToken: ReturnType<typeof vi.fn>;
  };
  events: string[];
  updates: UpdateCall[];
  pendingResponses: unknown[];
  getResponse: unknown;
  accountIdentity: string;
  activeEmail: string;
  sessionBindingId: string;
  serverUrl: string;
  serverGeneration: number;
  accountGeneration: number;
  sessionGeneration: number;
  accountCurrent: boolean;
  sessionCurrent: boolean;
  accessToken: string;
  deviceIdentifier: string;
  beforeRequest?: (kind: RequestKind) => void;
  listImpl?: () => Promise<unknown[]>;
  getImpl?: () => Promise<unknown>;
  updateImpl?: (
    accessToken: string,
    requestId: string,
    body: AuthRequestUpdateInput,
  ) => Promise<unknown>;
  activeAuth(): ActiveAuth;
}

function makeHarness(): Harness {
  const events: string[] = [];
  const updates: UpdateCall[] = [];
  const fixedClients: Array<{ withRequestGuard: ReturnType<typeof vi.fn> }> = [];
  const harness = {} as Harness;
  harness.pendingResponses = [pendingResponse()];
  harness.getResponse = pendingGetResponse();
  harness.accountIdentity = ACCOUNT_EMAIL;
  harness.activeEmail = ACCOUNT_EMAIL;
  harness.sessionBindingId = 'active-session-binding';
  harness.serverUrl = SERVER_URL;
  harness.serverGeneration = 3;
  harness.accountGeneration = 7;
  harness.sessionGeneration = 9;
  harness.accountCurrent = true;
  harness.sessionCurrent = true;
  harness.accessToken = ACCESS_TOKEN;
  harness.deviceIdentifier = APPROVAL_DEVICE_ID;

  harness.accountGate = {
    capture: vi.fn(() => Object.freeze({
      serverGeneration: harness.serverGeneration,
      accountGeneration: harness.accountGeneration,
      serverUrl: harness.serverUrl,
      accountIdentity: harness.accountIdentity,
    } satisfies AccountLease)),
    assert: vi.fn((lease: AccountLease) => {
      if (
        !harness.accountCurrent
        || lease.serverGeneration !== harness.serverGeneration
        || lease.serverUrl !== harness.serverUrl
        || lease.accountGeneration !== harness.accountGeneration
        || lease.accountIdentity !== harness.accountIdentity
      ) {
        throw new AppError('session_expired', 'account changed');
      }
    }),
  };
  harness.sessionGate = {
    capture: vi.fn(() => Object.freeze({
      generation: harness.sessionGeneration,
    } satisfies SessionLease)),
    assert: vi.fn((lease: SessionLease) => {
      if (!harness.sessionCurrent || lease.generation !== harness.sessionGeneration) {
        throw new AppError('locked', 'session changed');
      }
    }),
  };
  harness.activeAuth = () => ({
    email: harness.activeEmail,
    accessToken: harness.accessToken,
    refreshToken: 'refresh-token',
    expiresAt: NOW + 60 * 60_000,
    protectedKey: '2.a|b|c',
    kdf: 0,
    kdfIterations: 600_000,
    sessionBindingId: harness.sessionBindingId,
  });
  harness.session = {
    getActiveAuth: vi.fn(async () => harness.activeAuth()),
    loadUserKey: vi.fn(async () => {
      events.push('read:userKey');
      return userKey;
    }),
  };
  harness.auth = {
    getAccessToken: vi.fn(async () => harness.accessToken),
    getAccountAccessToken: vi.fn(async () => harness.accessToken),
  };

  const forServer = vi.fn((_serverUrl: string) => {
    let guard: (() => void) | undefined;
    const fixed = {
      withRequestGuard: vi.fn((value: () => void) => {
        guard = value;
        return fixed as unknown as ApiClient;
      }),
      getDeviceIdentifier: vi.fn(async () => harness.deviceIdentifier),
      listPendingAuthRequests: vi.fn(async (_accessToken: string) => {
        harness.beforeRequest?.('list');
        events.push('guard:list');
        guard?.();
        events.push('fetch:list');
        return harness.listImpl ? harness.listImpl() : harness.pendingResponses;
      }),
      getAuthRequest: vi.fn(async (_accessToken: string, _requestId: string) => {
        harness.beforeRequest?.('get');
        events.push('guard:get');
        guard?.();
        events.push('fetch:get');
        return harness.getImpl ? harness.getImpl() : harness.getResponse;
      }),
      updateAuthRequest: vi.fn(async (
        accessToken: string,
        requestId: string,
        body: AuthRequestUpdateInput,
      ) => {
        harness.beforeRequest?.('update');
        events.push('guard:update');
        guard?.();
        events.push('fetch:update');
        updates.push({ accessToken, requestId, body });
        if (harness.updateImpl) return harness.updateImpl(accessToken, requestId, body);
        return body.requestApproved
          ? approvedResponse(body.key!)
          : deniedResponse();
      }),
    };
    fixedClients.push(fixed);
    return fixed as unknown as ApiClient;
  });
  harness.api = { forServer };
  harness.fixedClients = fixedClients;
  harness.events = events;
  harness.updates = updates;
  harness.deps = {
    api: harness.api as unknown as DeviceLoginApprovalServiceDeps['api'],
    session: harness.session as unknown as DeviceLoginApprovalServiceDeps['session'],
    auth: harness.auth as unknown as DeviceLoginApprovalServiceDeps['auth'],
    sessionGate: harness.sessionGate as unknown as DeviceLoginApprovalServiceDeps['sessionGate'],
    accountGate: harness.accountGate as unknown as DeviceLoginApprovalServiceDeps['accountGate'],
    now: () => NOW,
  };
  harness.service = createDeviceLoginApprovalService(harness.deps);
  return harness;
}

function pendingResponse() {
  return {
    object: 'auth-request',
    id: REQUEST_ID,
    publicKey: pending.publicKey,
    requestDeviceType: 'Chrome',
    requestDeviceTypeValue: REQUEST_DEVICE.type,
    requestDeviceIdentifier: REQUEST_DEVICE.identifier,
    requestIpAddress: '203.0.113.7',
    requestCountryName: 'Test Country',
    key: null,
    masterPasswordHash: null,
    creationDate: new Date(CREATED_AT).toISOString(),
    requestApproved: false,
    responseDate: null,
    requestDeviceId: REQUEST_DEVICE_ID,
    origin: 'vault.example.com',
  };
}

function approvedResponse(key: string) {
  return {
    ...pendingGetResponse(),
    key,
    requestApproved: true,
    responseDate: new Date(NOW).toISOString(),
  };
}

function deniedResponse() {
  return {
    ...pendingGetResponse(),
    key: '',
    requestApproved: false,
    responseDate: new Date(NOW).toISOString(),
  };
}

function pendingGetResponse() {
  const { requestDeviceId: _requestDeviceId, ...response } = pendingResponse();
  return response;
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
