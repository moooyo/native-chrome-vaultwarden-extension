import { describe, expect, it } from 'vitest';
import { bytesToBase64Url } from '../core/crypto/encoding.js';
import {
  MAX_WEBSITE_PASSKEY_CHALLENGE_BYTES,
  MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_WEBSITE_PASSKEY_DESCRIPTORS,
  MAX_WEBSITE_PASSKEY_RESULT_CHARS,
  MAX_ORDINARY_WEBSITE_PASSKEY_TIMEOUT_MS,
  MIN_WEBSITE_PASSKEY_TIMEOUT_MS,
  WebsitePasskeyPortProtocolError,
  canonicalizeWebsitePasskeyRequest,
  createWebsitePasskeyPreflightOutcomeMessage,
  decideWebsitePasskeySupport,
  parsePasskeyCeremonyResultSnapshot,
  parseWebsitePasskeyClientMessage,
  parseWebsitePasskeyServerMessage,
  serializeCanonicalWebsitePasskeyRequest,
} from './website-passkey-port.js';

const CEREMONY_ID = '11111111-1111-4111-8111-111111111111';
const OUTCOME_ID = '22222222-2222-4222-8222-222222222222';
const BRIDGE_REQUEST_ID = '33333333-3333-4333-8333-333333333333';

function getRequest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bridgeRequestId: BRIDGE_REQUEST_ID,
    kind: 'get',
    rpId: 'Example.COM',
    challenge: 'AQID',
    allowCredentials: [{
      id: 'BAUG',
      type: 'public-key',
      transports: ['usb', 'internal'],
    }],
    userVerification: 'discouraged',
    mediation: 'required',
    timeout: 1_000,
    ...overrides,
  };
}

function createRequest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bridgeRequestId: BRIDGE_REQUEST_ID,
    kind: 'create',
    rp: { id: 'Example.COM', name: 'Example' },
    user: { id: 'Bw', name: 'alice@example.com', displayName: 'Alice' },
    challenge: 'AQID',
    pubKeyCredParams: [
      { type: 'public-key', alg: -257 },
      { type: 'public-key', alg: -7 },
    ],
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'preferred',
      authenticatorAttachment: 'platform',
    },
    attestation: 'none',
    extensions: { credProps: true },
    timeout: 700_000,
    ...overrides,
  };
}

function assertionResult(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'get',
    authenticatorAttachment: 'platform',
    transports: ['internal'],
    credentialId: 'AQ',
    authenticatorData: 'Ag',
    clientDataJSON: 'Aw',
    signature: 'BA',
    userHandle: 'Bg',
    ...overrides,
  };
}

function registrationResult(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'create',
    authenticatorAttachment: 'platform',
    transports: ['internal'],
    credProps: { rk: true },
    credentialId: 'AQ',
    attestationObject: 'Ag',
    clientDataJSON: 'Aw',
    authData: 'BA',
    publicKeySpki: 'BQ',
    publicKeyAlgorithm: -7,
    ...overrides,
  };
}

function expectProtocolCode(action: () => unknown, code: 'invalid_message' | 'unsupported_version'): void {
  try {
    action();
    throw new Error('Expected protocol parsing to fail');
  } catch (error) {
    expect(error).toBeInstanceOf(WebsitePasskeyPortProtocolError);
    expect((error as WebsitePasskeyPortProtocolError).code).toBe(code);
  }
}

describe('website passkey request protocol', () => {
  it('accepts only the exact hello and config activation messages', () => {
    expect(parseWebsitePasskeyClientMessage({ version: 1, type: 'hello' })).toEqual({
      status: 'accepted',
      message: { version: 1, type: 'hello' },
    });
    expect(parseWebsitePasskeyServerMessage({ version: 1, type: 'config', enabled: true })).toEqual({
      version: 1,
      type: 'config',
      enabled: true,
    });

    expectProtocolCode(
      () => parseWebsitePasskeyClientMessage({ version: 1, type: 'hello', enabled: true }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseWebsitePasskeyServerMessage({ version: 1, type: 'config', enabled: 1 }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseWebsitePasskeyServerMessage({ version: 1, type: 'config', enabled: false, reason: 'private' }),
      'invalid_message',
    );
  });

  it('canonicalizes an accepted begin before returning it to the coordinator', () => {
    const transports = ['usb', 'internal'];
    const descriptors = [{ id: 'BAUG', type: 'public-key', transports }];
    const input = getRequest({ allowCredentials: descriptors });
    const parsed = parseWebsitePasskeyClientMessage({ version: 1, type: 'begin', request: input });

    expect(parsed).toEqual({
      status: 'accepted',
      message: {
        version: 1,
        type: 'begin',
        request: {
          bridgeRequestId: BRIDGE_REQUEST_ID,
          kind: 'get',
          rpId: 'example.com',
          challenge: 'AQID',
          allowCredentials: [{
            id: 'BAUG',
            type: 'public-key',
            transports: ['internal', 'usb'],
          }],
          userVerification: 'discouraged',
          mediation: 'required',
          timeout: MIN_WEBSITE_PASSKEY_TIMEOUT_MS,
        },
      },
    });
    if (parsed.status !== 'accepted' || parsed.message.type !== 'begin') {
      throw new Error('Unexpected begin decision');
    }
    if (parsed.message.request.kind !== 'get') throw new Error('Expected get request');
    expect(Object.isFrozen(parsed.message.request)).toBe(true);
    expect(Object.isFrozen(parsed.message.request.allowCredentials)).toBe(true);
    expect(parsed.message.request.allowCredentials[0]).not.toBe(descriptors[0]);

    input.rpId = 'attacker.example';
    descriptors[0]!.id = 'CA';
    transports.push('ble');
    expect(parsed.message.request.rpId).toBe('example.com');
    expect(parsed.message.request.allowCredentials[0]).toEqual({
      id: 'BAUG',
      type: 'public-key',
      transports: ['internal', 'usb'],
    });
  });

  it('canonicalizes a full resume request without accepting ceremony ids as capabilities', () => {
    const parsed = parseWebsitePasskeyClientMessage({
      version: 1,
      type: 'resume',
      request: getRequest(),
    });
    expect(parsed).toMatchObject({
      status: 'accepted',
      message: {
        version: 1,
        type: 'resume',
        request: {
          bridgeRequestId: BRIDGE_REQUEST_ID,
          kind: 'get',
          rpId: 'example.com',
        },
      },
    });
    expectProtocolCode(() => parseWebsitePasskeyClientMessage({
      version: 1,
      type: 'resume',
      ceremonyId: CEREMONY_ID,
    }), 'invalid_message');
  });

  it('preserves conditional mediation as a supported canonical get request', () => {
    const request = getRequest({ mediation: 'conditional' });
    const canonical = {
      bridgeRequestId: BRIDGE_REQUEST_ID,
      kind: 'get' as const,
      rpId: 'example.com',
      challenge: 'AQID',
      allowCredentials: [{
        id: 'BAUG',
        type: 'public-key' as const,
        transports: ['internal', 'usb'],
      }],
      userVerification: 'discouraged' as const,
      mediation: 'conditional' as const,
      timeout: MIN_WEBSITE_PASSKEY_TIMEOUT_MS,
    };

    expect(decideWebsitePasskeySupport(request)).toEqual({ status: 'accepted', request: canonical });
    expect(parseWebsitePasskeyClientMessage({ version: 1, type: 'begin', request })).toEqual({
      status: 'accepted',
      message: { version: 1, type: 'begin', request: canonical },
    });
  });

  it('keeps silent mediation as a durable native fallback', () => {
    const request = getRequest({ mediation: 'silent' });
    const decision = decideWebsitePasskeySupport(request);

    expect(decision).toMatchObject({
      status: 'fallback',
      bridgeRequestId: BRIDGE_REQUEST_ID,
      reason: 'silent_mediation',
      request: { kind: 'get', mediation: 'optional' },
    });
    expect(parseWebsitePasskeyClientMessage({ version: 1, type: 'begin', request }))
      .toEqual(decision);
  });

  it('falls back required user verification without erasing conditional mediation', () => {
    expect(decideWebsitePasskeySupport(getRequest({
      mediation: 'conditional',
      userVerification: 'required',
    }))).toMatchObject({
      status: 'fallback',
      reason: 'required_user_verification',
      request: { kind: 'get', mediation: 'conditional', userVerification: 'required' },
    });
  });

  it('keeps recognized unsupported create requests canonical for native fallback', () => {
    const algorithm = decideWebsitePasskeySupport(createRequest({
      pubKeyCredParams: [{ type: 'public-key', alg: -257 }],
    }));
    expect(algorithm).toMatchObject({
      status: 'fallback',
      bridgeRequestId: BRIDGE_REQUEST_ID,
      reason: 'unsupported_algorithm',
      request: {
        kind: 'create',
        rp: { id: 'example.com', name: 'Example' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: MAX_ORDINARY_WEBSITE_PASSKEY_TIMEOUT_MS,
      },
    });

    const attachment = decideWebsitePasskeySupport(createRequest({
      authenticatorSelection: {
        residentKey: 'discouraged',
        requireResidentKey: false,
        userVerification: 'preferred',
        authenticatorAttachment: 'cross-platform',
      },
    }));
    expect(attachment).toMatchObject({
      status: 'fallback',
      reason: 'unsupported_attachment',
      request: { authenticatorSelection: { authenticatorAttachment: 'cross-platform' } },
    });

    expect(decideWebsitePasskeySupport(createRequest({
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
        authenticatorAttachment: 'platform',
      },
    }))).toMatchObject({
      status: 'fallback',
      reason: 'required_user_verification',
      request: { authenticatorSelection: { userVerification: 'required' } },
    });
  });

  it('uses stable serialization of the rebuilt canonical request', () => {
    const source = getRequest();
    const canonical = canonicalizeWebsitePasskeyRequest(source);
    expect(serializeCanonicalWebsitePasskeyRequest(source)).toBe(JSON.stringify(canonical));
    expect(serializeCanonicalWebsitePasskeyRequest({ ...source, rpId: 'EXAMPLE.COM' }))
      .toBe(serializeCanonicalWebsitePasskeyRequest({ ...source, rpId: 'example.com' }));
  });

  it('rejects unknown, inherited, hidden, symbolic, undefined, and accessor fields', () => {
    const invalidRequests: unknown[] = [
      getRequest({ secret: 'must not cross the port' }),
      Object.create(getRequest()),
      getRequest({ timeout: undefined }),
    ];

    const hidden = getRequest();
    Object.defineProperty(hidden, 'secret', { enumerable: false, value: 'hidden' });
    invalidRequests.push(hidden);

    const symbolic = getRequest();
    Object.defineProperty(symbolic, Symbol('secret'), { enumerable: true, value: 'hidden' });
    invalidRequests.push(symbolic);

    let getterCalls = 0;
    const accessor = getRequest();
    Object.defineProperty(accessor, 'challenge', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 'AQID';
      },
    });
    invalidRequests.push(accessor);

    for (const request of invalidRequests) {
      expectProtocolCode(() => decideWebsitePasskeySupport(request), 'invalid_message');
    }
    expect(getterCalls).toBe(0);

    expectProtocolCode(() => parseWebsitePasskeyClientMessage({
      version: 1,
      type: 'begin',
      request: getRequest(),
      accountIdentityDigest: 'private',
    }), 'invalid_message');
  });

  it('requires dense bounded arrays without extra properties or duplicates', () => {
    const sparse = new Array(1) as unknown[];
    expectProtocolCode(
      () => decideWebsitePasskeySupport(getRequest({ allowCredentials: sparse })),
      'invalid_message',
    );

    const extraProperty: unknown[] = [];
    Object.assign(extraProperty, { privateValue: 'hidden from iteration' });
    expectProtocolCode(
      () => decideWebsitePasskeySupport(getRequest({ allowCredentials: extraProperty })),
      'invalid_message',
    );

    expectProtocolCode(() => decideWebsitePasskeySupport(getRequest({
      allowCredentials: Array.from({ length: MAX_WEBSITE_PASSKEY_DESCRIPTORS + 1 }, () => ({
        id: 'AQ',
        type: 'public-key',
      })),
    })), 'invalid_message');
    expectProtocolCode(() => decideWebsitePasskeySupport(getRequest({
      allowCredentials: [
        { id: 'AQ', type: 'public-key' },
        { id: 'AQ', type: 'public-key' },
      ],
    })), 'invalid_message');
    expectProtocolCode(() => decideWebsitePasskeySupport(getRequest({
      allowCredentials: [{ id: 'AQ', type: 'public-key', transports: ['usb', 'usb'] }],
    })), 'invalid_message');
    expectProtocolCode(() => decideWebsitePasskeySupport(getRequest({
      allowCredentials: [{ id: 'AQ', type: 'public-key', rawId: 'private' }],
    })), 'invalid_message');
  });

  it('enforces canonical base64url and byte ceilings before accepting request material', () => {
    const oversizedChallenge = bytesToBase64Url(
      new Uint8Array(MAX_WEBSITE_PASSKEY_CHALLENGE_BYTES + 1).fill(1),
    );
    const oversizedCredentialId = bytesToBase64Url(
      new Uint8Array(MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES + 1).fill(2),
    );
    const oversizedUserId = bytesToBase64Url(new Uint8Array(65).fill(3));

    for (const challenge of ['', 'AQ==', 'AQ ID', oversizedChallenge]) {
      expectProtocolCode(
        () => decideWebsitePasskeySupport(getRequest({ challenge })),
        'invalid_message',
      );
    }
    expectProtocolCode(() => decideWebsitePasskeySupport(getRequest({
      allowCredentials: [{ id: oversizedCredentialId, type: 'public-key' }],
    })), 'invalid_message');
    expectProtocolCode(() => decideWebsitePasskeySupport(createRequest({
      user: { id: '', name: 'Alice', displayName: 'Alice' },
    })), 'invalid_message');
    expectProtocolCode(() => decideWebsitePasskeySupport(createRequest({
      user: { id: oversizedUserId, name: 'Alice', displayName: 'Alice' },
    })), 'invalid_message');
  });
});

describe('website passkey result protocol', () => {
  it('accepts only a platform authenticator with the internal transport', () => {
    const transports = ['internal'];
    const source = assertionResult({ transports });
    const parsed = parsePasskeyCeremonyResultSnapshot(source, 'get');

    expect(parsed).toEqual({
      kind: 'get',
      authenticatorAttachment: 'platform',
      transports: ['internal'],
      credentialId: 'AQ',
      authenticatorData: 'Ag',
      clientDataJSON: 'Aw',
      signature: 'BA',
      userHandle: 'Bg',
    });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.transports)).toBe(true);
    expect(parsed.transports).not.toBe(transports);
    transports[0] = 'usb';
    expect(parsed.transports).toEqual(['internal']);

    for (const invalid of [
      assertionResult({ authenticatorAttachment: 'cross-platform' }),
      assertionResult({ transports: ['usb'] }),
      assertionResult({ transports: ['internal', 'usb'] }),
      assertionResult({ transports: [] }),
    ]) {
      expectProtocolCode(
        () => parsePasskeyCeremonyResultSnapshot(invalid, 'get'),
        'invalid_message',
      );
    }
  });

  it('requires an explicit create credProps snapshot and accepts null when it was not requested', () => {
    expect(parsePasskeyCeremonyResultSnapshot(registrationResult(), 'create')).toEqual({
      kind: 'create',
      authenticatorAttachment: 'platform',
      transports: ['internal'],
      credProps: { rk: true },
      credentialId: 'AQ',
      attestationObject: 'Ag',
      clientDataJSON: 'Aw',
      authData: 'BA',
      publicKeySpki: 'BQ',
      publicKeyAlgorithm: -7,
    });
    expect(parsePasskeyCeremonyResultSnapshot(registrationResult({ credProps: null }), 'create'))
      .toMatchObject({ credProps: null });

    const missingCredProps = registrationResult();
    delete missingCredProps.credProps;
    for (const invalid of [
      missingCredProps,
      registrationResult({ credProps: {} }),
      registrationResult({ credProps: { rk: 'true' } }),
      registrationResult({ credProps: { rk: true, credentialSecret: 'private' } }),
      registrationResult({ publicKeyAlgorithm: -0 }),
    ]) {
      expectProtocolCode(
        () => parsePasskeyCeremonyResultSnapshot(invalid, 'create'),
        'invalid_message',
      );
    }
  });

  it('rejects wrong kinds, non-dense transports, accessors, extras, and oversized result fields', () => {
    expectProtocolCode(
      () => parsePasskeyCeremonyResultSnapshot(assertionResult(), 'create'),
      'invalid_message',
    );
    expectProtocolCode(
      () => parsePasskeyCeremonyResultSnapshot(registrationResult(), 'get'),
      'invalid_message',
    );

    const sparse = new Array(1) as unknown[];
    expectProtocolCode(
      () => parsePasskeyCeremonyResultSnapshot(assertionResult({ transports: sparse })),
      'invalid_message',
    );

    const transportsWithExtra: unknown[] = ['internal'];
    Object.assign(transportsWithExtra, { secret: 'not an array element' });
    expectProtocolCode(
      () => parsePasskeyCeremonyResultSnapshot(assertionResult({ transports: transportsWithExtra })),
      'invalid_message',
    );

    let getterCalls = 0;
    const accessor = assertionResult();
    Object.defineProperty(accessor, 'signature', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 'BA';
      },
    });
    expectProtocolCode(
      () => parsePasskeyCeremonyResultSnapshot(accessor),
      'invalid_message',
    );
    expect(getterCalls).toBe(0);

    expectProtocolCode(() => parsePasskeyCeremonyResultSnapshot(assertionResult({
      privateKey: 'must not cross the port',
    })), 'invalid_message');
    expectProtocolCode(() => parsePasskeyCeremonyResultSnapshot(assertionResult({
      signature: 'A'.repeat(MAX_WEBSITE_PASSKEY_RESULT_CHARS + 1),
    })), 'invalid_message');
  });

  it('requires canonical base64url for every binary result field and uses absence for null userHandle', () => {
    const absentUserHandle = assertionResult();
    delete absentUserHandle.userHandle;
    expect(parsePasskeyCeremonyResultSnapshot(absentUserHandle, 'get'))
      .not.toHaveProperty('userHandle');

    for (const field of [
      'credentialId', 'authenticatorData', 'clientDataJSON', 'signature', 'userHandle',
    ]) {
      expectProtocolCode(() => parsePasskeyCeremonyResultSnapshot(assertionResult({
        [field]: 'A',
      }), 'get'), 'invalid_message');
    }
    for (const field of [
      'credentialId', 'attestationObject', 'clientDataJSON', 'authData', 'publicKeySpki',
    ]) {
      expectProtocolCode(() => parsePasskeyCeremonyResultSnapshot(registrationResult({
        [field]: 'A',
      }), 'create'), 'invalid_message');
    }
    for (const invalidUserHandle of ['', null, 'AQ==']) {
      expectProtocolCode(() => parsePasskeyCeremonyResultSnapshot(assertionResult({
        userHandle: invalidUserHandle,
      }), 'get'), 'invalid_message');
    }
    expectProtocolCode(() => parsePasskeyCeremonyResultSnapshot(registrationResult({
      publicKeyAlgorithm: -257,
    }), 'create'), 'invalid_message');
  });
});

describe('website passkey binding and envelope protocol', () => {
  it('maps pre-accept busy to NotAllowedError and capacity to native fallback without ceremony ids', () => {
    const busy = createWebsitePasskeyPreflightOutcomeMessage(BRIDGE_REQUEST_ID, 'busy');
    const capacity = createWebsitePasskeyPreflightOutcomeMessage(BRIDGE_REQUEST_ID, 'capacity');

    expect(busy).toEqual({
      version: 1,
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcome: {
        status: 'error',
        error: {
          name: 'NotAllowedError',
          message: 'Another passkey request is already in progress for this document.',
        },
      },
    });
    expect(capacity).toEqual({
      version: 1,
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcome: { status: 'fallback', reason: 'capacity' },
    });
    expect(parseWebsitePasskeyServerMessage(busy)).toEqual(busy);
    expect(parseWebsitePasskeyServerMessage(capacity)).toEqual(capacity);
    expect(busy).not.toHaveProperty('ceremonyId');
    expect(busy).not.toHaveProperty('outcomeId');
  });

  it('rejects success, post-accept reasons, ids, and other errors in preflight outcomes', () => {
    const invalidOutcomes: unknown[] = [
      { status: 'success', result: assertionResult() },
      { status: 'fallback', reason: 'busy' },
      { status: 'fallback', reason: 'no_match' },
      { status: 'error', error: { name: 'AbortError', message: 'Busy.' } },
    ];
    for (const outcome of invalidOutcomes) {
      expectProtocolCode(() => parseWebsitePasskeyServerMessage({
        version: 1,
        type: 'preflightOutcome',
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcome,
      }), 'invalid_message');
    }
    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_REQUEST_ID,
      ceremonyId: CEREMONY_ID,
      outcome: { status: 'fallback', reason: 'capacity' },
    }), 'invalid_message');
    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: { status: 'fallback', reason: 'capacity' },
    }), 'invalid_message');
  });

  it('round-trips exact cancel, ack, accepted, and success outcome bindings', () => {
    expect(parseWebsitePasskeyClientMessage({
      version: 1,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
    })).toEqual({
      status: 'accepted',
      message: {
        version: 1,
        type: 'cancel',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
      },
    });
    expect(parseWebsitePasskeyClientMessage({
      version: 1,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
    })).toEqual({
      status: 'accepted',
      message: {
        version: 1,
        type: 'ack',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: OUTCOME_ID,
      },
    });
    expect(parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'accepted',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
    })).toEqual({
      version: 1,
      type: 'accepted',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
    });
    expect(parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'unlockPending',
      continuationId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
    })).toEqual({
      version: 1,
      type: 'unlockPending',
      continuationId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
    });
    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'unlockPending',
      continuationId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
      candidates: [],
    }), 'invalid_message');

    expect(parseWebsitePasskeyClientMessage({
      version: 1,
      type: 'conditionalSelect',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      credentialId: 'Y3JlZGVudGlhbA',
    })).toMatchObject({
      status: 'accepted',
      message: { type: 'conditionalSelect', credentialId: 'Y3JlZGVudGlhbA' },
    });
    expect(parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'conditionalActive',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
      candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work', username: 'alice' }],
    })).toEqual({
      version: 1,
      type: 'conditionalActive',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      deadlineAt: 123_456,
      candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work', username: 'alice' }],
    });

    const outcome = parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: { status: 'success', result: assertionResult() },
    });
    expect(outcome).toMatchObject({
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: {
        status: 'success',
        result: {
          kind: 'get',
          authenticatorAttachment: 'platform',
          transports: ['internal'],
        },
      },
    });
  });

  it('accepts only exact fallback and DOMException outcome shapes', () => {
    for (const reason of ['excluded_domain', 'no_match', 'unsupported', 'user_selected_browser'] as const) {
      expect(parseWebsitePasskeyServerMessage({
        version: 1,
        type: 'outcome',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: OUTCOME_ID,
        outcome: { status: 'fallback', reason },
      })).toMatchObject({ outcome: { status: 'fallback', reason } });
    }
    expect(parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: { status: 'error', error: { name: 'NotAllowedError', message: 'Timed out.' } },
    })).toMatchObject({
      outcome: { status: 'error', error: { name: 'NotAllowedError', message: 'Timed out.' } },
    });

    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: { status: 'fallback', reason: 'conditional_mediation' },
    }), 'invalid_message');
    for (const reason of [
      'account_changed',
      'cache_changed',
      'cancelled',
      'context_changed',
      'expired',
      'feature_disabled',
      'session_changed',
      'vault_locked',
      'worker_restart',
    ]) {
      expectProtocolCode(() => parseWebsitePasskeyServerMessage({
        version: 1,
        type: 'outcome',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: OUTCOME_ID,
        outcome: { status: 'fallback', reason },
      }), 'invalid_message');
    }
    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: {
        status: 'error',
        error: { name: 'NotAllowedError', message: 'Timed out.', serverBody: 'private' },
      },
    }), 'invalid_message');
  });

  it('rejects missing, malformed, or unbound identifiers and deadlines', () => {
    const invalidClientMessages: unknown[] = [
      { version: 1, type: 'cancel', ceremonyId: CEREMONY_ID },
      {
        version: 1,
        type: 'cancel',
        ceremonyId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
        bridgeRequestId: BRIDGE_REQUEST_ID,
      },
      {
        version: 1,
        type: 'ack',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: 'not-a-uuid',
      },
      {
        version: 1,
        type: 'ack',
        ceremonyId: `${CEREMONY_ID}\n`,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: OUTCOME_ID,
      },
      {
        version: 1,
        type: 'ack',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: `${BRIDGE_REQUEST_ID}\r\n`,
        outcomeId: OUTCOME_ID,
      },
      {
        version: 1,
        type: 'ack',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: `${OUTCOME_ID}\n`,
      },
      {
        version: 1,
        type: 'ack',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        outcomeId: OUTCOME_ID,
        status: 'success',
      },
    ];
    for (const message of invalidClientMessages) {
      expectProtocolCode(() => parseWebsitePasskeyClientMessage(message), 'invalid_message');
    }

    for (const deadlineAt of [-1, -0, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      expectProtocolCode(() => parseWebsitePasskeyServerMessage({
        version: 1,
        type: 'accepted',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_REQUEST_ID,
        deadlineAt,
      }), 'invalid_message');
    }
    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcome: { status: 'fallback', reason: 'no_match' },
    }), 'invalid_message');
    expectProtocolCode(() => parseWebsitePasskeyServerMessage({
      version: 1,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_REQUEST_ID,
      outcomeId: OUTCOME_ID,
      outcome: { status: 'fallback', reason: 'no_match' },
      accountIdentityDigest: 'private',
    }), 'invalid_message');
  });

  it('distinguishes malformed envelopes from unsupported versions in both directions', () => {
    for (const parse of [parseWebsitePasskeyClientMessage, parseWebsitePasskeyServerMessage]) {
      expectProtocolCode(() => parse({ version: 2, type: 'hello' }), 'unsupported_version');
      expectProtocolCode(() => parse({ version: '1', type: 'hello' }), 'invalid_message');
      expectProtocolCode(() => parse({ version: -0, type: 'hello' }), 'invalid_message');
      expectProtocolCode(() => parse({ type: 'hello' }), 'invalid_message');
    }
  });
});
