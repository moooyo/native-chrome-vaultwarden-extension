// @vitest-environment node
// Live Login with device protocol test, hard-bound to the authorized test-env tunnel.
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { ApiClient, ApiHttpError, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import { base64ToBytes, constantTimeEqual } from '../../src/core/crypto/encoding.js';
import { deriveMasterKey, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey, type SymmetricKey } from '../../src/core/crypto/keys.js';
import { FINGERPRINT_WORDLIST } from '../../src/core/generator/wordlist.js';
import {
  inspectPendingDeviceLoginRequest,
  prepareDeviceLoginApproval,
  prepareDeviceLoginRejection,
} from '../../src/core/session/device-login-approval.js';
import {
  bindDeviceLoginRequest,
  createDeviceLoginRequest,
  deriveDeviceLoginFingerprint,
  parseAuthRequestResponse,
  recoverApprovedDeviceLogin,
  type DeviceLoginBoundState,
} from '../../src/core/session/device-login.js';
import { createMemoryStore } from '../../src/platform/store.js';
import {
  cleanupSshE2eAccount,
  createSshE2eIdentity,
  prepareSshE2eAccount,
  type PreparedSshE2eAccount,
} from '../support/ssh-e2e-account.js';

const LIVE = process.env.LIVE === '1';
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const SERVER = process.env.MIYU_SERVER;
const REQUEST_TIMEOUT_MS = 30_000;

if (LIVE && SERVER !== AUTHORIZED_SERVER) {
  throw new Error(`Device login live test is restricted to ${AUTHORIZED_SERVER}`);
}

interface WireObservations {
  deviceLoginGrants: number;
  approvedWithWrappedKey: boolean;
  deniedWithEmptyKey: boolean;
}

type LivePhase =
  | 'setup'
  | 'registration'
  | 'known-devices'
  | 'approval'
  | 'redemption'
  | 'denial'
  | 'cleanup';

function createApi(observations: WireObservations): ApiClient {
  return new ApiClient({
    serverUrlProvider: async () => AUTHORIZED_SERVER,
    fetchFn: createObservedFetch(observations),
    localStore: createMemoryStore(),
  });
}

function createObservedFetch(observations: WireObservations): typeof fetch {
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : undefined;
    const url = new URL(request?.url ?? input.toString());
    const method = init?.method ?? request?.method ?? 'GET';
    const body = init?.body;
    if (url.pathname.endsWith('/identity/connect/token') && typeof body === 'string') {
      const form = new URLSearchParams(body);
      if (form.has('AuthRequest')) observations.deviceLoginGrants += 1;
    }
    if (
      method === 'PUT'
      && /\/api\/auth-requests\/[0-9a-f-]{36}$/u.test(url.pathname)
      && typeof body === 'string'
    ) {
      const parsed = parseJsonRecord(body);
      if (parsed?.requestApproved === true) {
        observations.approvedWithWrappedKey = typeof parsed.key === 'string'
          && parsed.key.startsWith('4.')
          && parsed.deviceIdentifier !== '';
      }
      if (parsed?.requestApproved === false) {
        observations.deniedWithEmptyKey = parsed.key === ''
          && typeof parsed.deviceIdentifier === 'string'
          && Object.keys(parsed).sort().join(',') === 'deviceIdentifier,key,requestApproved';
      }
    }
    return globalThis.fetch(input, init);
  };
}

function parseJsonRecord(value: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

async function registerAccount(api: ApiClient, account: PreparedSshE2eAccount): Promise<void> {
  const emailVerificationToken = await requestRegistrationToken(account.email, account.name);
  await api.register({
    ...account.registration,
    masterPasswordHint: '',
    email: account.email,
    name: account.name,
    ...(emailVerificationToken ? { emailVerificationToken } : {}),
  });
}

async function requestRegistrationToken(email: string, name: string): Promise<string | undefined> {
  const response = await fetch(
    new URL('identity/accounts/register/send-verification-email', AUTHORIZED_SERVER),
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
      },
      body: JSON.stringify({ email, name }),
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    },
  );
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`Registration start failed with HTTP ${response.status}`);
  const text = (await response.text()).trim();
  if (!text) return undefined;
  let token: unknown = text;
  try { token = JSON.parse(text) as unknown; } catch { /* Some servers return the token raw. */ }
  if (
    typeof token !== 'string'
    || token.length === 0
    || token.length > 8_192
    || /\s/u.test(token)
  ) throw new Error('Registration start returned an invalid token');
  return token;
}

async function ordinaryLogin(api: ApiClient, account: PreparedSshE2eAccount): Promise<string> {
  const result = await api.passwordLogin({
    email: account.email,
    masterPasswordHash: account.masterPasswordHash,
  });
  if (result.kind !== 'success') {
    throw new Error('Disposable account unexpectedly requires two-factor authentication');
  }
  return result.data.access_token;
}

async function originalUserKey(
  account: PreparedSshE2eAccount,
  password: string,
): Promise<SymmetricKey> {
  const masterKey = await deriveMasterKey(password, account.email, account.registration);
  const stretched = await stretchMasterKey(masterKey);
  try {
    return await unwrapSymmetricKey(account.registration.key, stretched);
  } finally {
    masterKey.fill(0);
    clearKey(stretched);
  }
}

function clearKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}

function sameUserKey(left: SymmetricKey, right: SymmetricKey): boolean {
  return constantTimeEqual(left.encKey, right.encKey)
    && constantTimeEqual(left.macKey, right.macKey);
}

function sanitizeFailure(error: unknown, phase: LivePhase): Error {
  const status = error instanceof ApiHttpError ? `:http-${error.status}` : '';
  return new Error(`Device login live protocol failed during ${phase}${status}`);
}

function fiveWordFingerprint(value: string): boolean {
  let positions = new Set([0]);
  for (let wordIndex = 0; wordIndex < 5; wordIndex += 1) {
    const next = new Set<number>();
    for (const position of positions) {
      for (const word of FINGERPRINT_WORDLIST) {
        if (!value.startsWith(word, position)) continue;
        const end = position + word.length;
        if (wordIndex === 4) {
          if (end === value.length) next.add(end);
        } else if (value[end] === '-') {
          next.add(end + 1);
        }
      }
    }
    positions = next;
    if (positions.size === 0) return false;
  }
  return positions.has(value.length);
}

function findPendingRequest(
  responses: readonly unknown[],
  requestId: string,
): unknown {
  for (const response of responses) {
    try {
      if (parseAuthRequestResponse(response).id === requestId) return response;
    } catch {
      // Ignore an unrelated malformed response; the requested id must still be present below.
    }
  }
  throw new Error('The expected pending auth request is unavailable');
}

async function requesterFingerprint(
  email: string,
  state: DeviceLoginBoundState,
): Promise<string> {
  const publicKey = base64ToBytes(state.publicKey);
  try {
    return await deriveDeviceLoginFingerprint(email, publicKey, FINGERPRINT_WORDLIST);
  } finally {
    publicKey.fill(0);
  }
}

async function captureReplayStatus(operation: Promise<unknown>): Promise<number | undefined> {
  try {
    await operation;
    return undefined;
  } catch (error) {
    if (error instanceof ApiHttpError) return error.status;
    throw error;
  }
}

const liveDescribe = LIVE && SERVER === AUTHORIZED_SERVER ? describe : describe.skip;

liveDescribe('live Login with device protocol against test-env', () => {
  it('approves, redeems once, and semantically denies a second request', async () => {
    let phase: LivePhase = 'setup';
    let account: PreparedSshE2eAccount | undefined;
    let accountArmed = false;
    let cleanupToken: string | undefined;
    let expectedUserKey: SymmetricKey | undefined;
    let recoveredUserKey: SymmetricKey | undefined;
    let primaryFailure: Error | undefined;
    let cleanupFailure: Error | undefined;

    try {
      const identity = createSshE2eIdentity();
      account = await prepareSshE2eAccount(
        identity.email,
        identity.password,
        'MiYu Device Login Live',
      );
      accountArmed = true;
      const observations: WireObservations = {
        deviceLoginGrants: 0,
        approvedWithWrappedKey: false,
        deniedWithEmptyKey: false,
      };
      const requester = createApi(observations);
      const approver = createApi(observations);
      const unknownDevice = createApi(observations);
      expectedUserKey = await originalUserKey(account, identity.password);

      phase = 'registration';
      await registerAccount(requester, account);

      phase = 'known-devices';
      const requesterDeviceId = await requester.getDeviceIdentifier();
      const approverDeviceId = await approver.getDeviceIdentifier();
      const unknownDeviceId = await unknownDevice.getDeviceIdentifier();
      expect(new Set([requesterDeviceId, approverDeviceId, unknownDeviceId]).size).toBe(3);

      const requesterToken = await ordinaryLogin(requester, account);
      const approverToken = await ordinaryLogin(approver, account);
      cleanupToken = requesterToken;
      expect(await requester.isKnownDevice({ email: account.email })).toBe(true);
      expect(await approver.isKnownDevice({ email: account.email })).toBe(true);
      expect(await unknownDevice.isKnownDevice({ email: account.email })).toBe(false);

      phase = 'approval';
      const firstRequest = await createDeviceLoginRequest({
        email: account.email,
        device: { type: 2, name: 'chrome', identifier: requesterDeviceId },
      });
      const firstCreated = await requester.createAuthRequest(firstRequest.request);
      const firstBound = await bindDeviceLoginRequest(firstRequest.state, firstCreated);
      const firstRequesterFingerprint = await requesterFingerprint(account.email, firstBound);
      const firstPending = findPendingRequest(
        await approver.listPendingAuthRequests(approverToken),
        firstBound.requestId,
      );
      const firstInspected = await inspectPendingDeviceLoginRequest(firstPending, {
        accountEmail: account.email,
        approvalDeviceIdentifier: approverDeviceId,
      });
      const firstApproval = await prepareDeviceLoginApproval(firstPending, {
        accountEmail: account.email,
        approvalDeviceIdentifier: approverDeviceId,
        userKey: expectedUserKey,
      });
      expect(firstRequesterFingerprint === firstInspected.fingerprint).toBe(true);
      expect(firstRequesterFingerprint === firstApproval.request.fingerprint).toBe(true);
      expect(fiveWordFingerprint(firstRequesterFingerprint)).toBe(true);
      await approver.updateAuthRequest(
        approverToken,
        firstBound.requestId,
        firstApproval.body,
      );
      expect(observations.approvedWithWrappedKey).toBe(true);

      phase = 'redemption';
      const firstResponse = await requester.getAuthRequestResponse(
        firstBound.requestId,
        firstBound.accessCode,
      );
      const recovered = await recoverApprovedDeviceLogin(firstBound, firstResponse);
      recoveredUserKey = recovered.userKey;
      expect(sameUserKey(expectedUserKey, recoveredUserKey)).toBe(true);
      const grant = await requester.deviceLogin({
        email: account.email,
        accessCode: firstBound.accessCode,
        authRequestId: firstBound.requestId,
      });
      expect(grant.kind).toBe('success');
      if (grant.kind !== 'success') throw new Error('Device login grant unexpectedly requires 2FA');
      const sync = await requester.sync(grant.data.access_token);
      expect(Array.isArray(sync.ciphers)).toBe(true);
      expect(typeof sync.profile).toBe('object');
      const replayStatus = await captureReplayStatus(requester.deviceLogin({
        email: account.email,
        accessCode: firstBound.accessCode,
        authRequestId: firstBound.requestId,
      }));
      expect(replayStatus).toBe(400);
      expect(observations.deviceLoginGrants).toBe(2);

      phase = 'denial';
      const grantsBeforeDenial = observations.deviceLoginGrants;
      const secondRequest = await createDeviceLoginRequest({
        email: account.email,
        device: { type: 2, name: 'chrome', identifier: requesterDeviceId },
      });
      const secondCreated = await requester.createAuthRequest(secondRequest.request);
      const secondBound = await bindDeviceLoginRequest(secondRequest.state, secondCreated);
      const secondRequesterFingerprint = await requesterFingerprint(account.email, secondBound);
      const secondPending = findPendingRequest(
        await approver.listPendingAuthRequests(approverToken),
        secondBound.requestId,
      );
      const denial = await prepareDeviceLoginRejection(secondPending, {
        accountEmail: account.email,
        approvalDeviceIdentifier: approverDeviceId,
      });
      expect(secondRequesterFingerprint === denial.request.fingerprint).toBe(true);
      expect(fiveWordFingerprint(secondRequesterFingerprint)).toBe(true);
      await approver.updateAuthRequest(approverToken, secondBound.requestId, denial.body);
      expect(observations.deniedWithEmptyKey).toBe(true);
      const deniedResponse = await requester.getAuthRequestResponse(
        secondBound.requestId,
        secondBound.accessCode,
      );
      const denied = parseAuthRequestResponse(deniedResponse);
      expect(denied.answered).toBe(true);
      expect(denied.requestApproved).toBe(false);
      expect(observations.deviceLoginGrants).toBe(grantsBeforeDenial);
    } catch (error) {
      primaryFailure = sanitizeFailure(error, phase);
    } finally {
      clearKey(expectedUserKey);
      clearKey(recoveredUserKey);
      if (accountArmed && account) {
        phase = 'cleanup';
        try {
          const result = await cleanupSshE2eAccount(
            AUTHORIZED_SERVER,
            account,
            cleanupToken,
          );
          if (result !== 'deleted' && result !== 'absent') {
            cleanupFailure = new Error('Device login live cleanup returned an invalid result');
          }
        } catch (error) {
          cleanupFailure = sanitizeFailure(error, phase);
        }
      }
    }

    if (primaryFailure && cleanupFailure) {
      throw new AggregateError(
        [primaryFailure, cleanupFailure],
        'Device login live protocol and cleanup both failed',
      );
    }
    if (cleanupFailure) throw cleanupFailure;
    if (primaryFailure) throw primaryFailure;
  }, 120_000);
});
