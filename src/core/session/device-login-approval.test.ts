import { beforeAll, describe, expect, it } from 'vitest';

import { base64ToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { parseRsaEncString } from '../crypto/encstring.js';
import {
  serializeSymmetricKey,
  symmetricKeyFromBytes,
  type SymmetricKey,
} from '../crypto/keys.js';
import { rsaOaepDecrypt } from '../crypto/primitives.js';
import { FINGERPRINT_WORDLIST } from '../generator/wordlist.js';
import {
  inspectPendingDeviceLoginRequest,
  prepareDeviceLoginApproval,
  prepareDeviceLoginRejection,
} from './device-login-approval.js';
import {
  DEVICE_LOGIN_REQUEST_TTL_MS,
  createDeviceLoginRequest,
  deriveDeviceLoginFingerprint,
  type DeviceLoginPendingState,
} from './device-login.js';

const NOW = Date.parse('2026-08-30T08:00:00.000Z');
const CREATED_AT = NOW - 60_000;
const REQUEST_ID = 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34';
const REQUEST_DEVICE_ID = 'c05e732e-77b1-457b-8f89-5b5ba1b4e1d2';
const APPROVAL_DEVICE_IDENTIFIER = 'approver-device-456';
const ACCOUNT_EMAIL = 'user@example.com';
const REQUEST_DEVICE = Object.freeze({
  type: 2,
  name: 'Chrome',
  identifier: 'requester-device-123',
});

let pending: DeviceLoginPendingState;
let userKey: SymmetricKey;

beforeAll(async () => {
  pending = (await createDeviceLoginRequest(
    { email: ACCOUNT_EMAIL, device: REQUEST_DEVICE },
    CREATED_AT,
  )).state;
  userKey = symmetricKeyFromBytes(
    Uint8Array.from({ length: 64 }, (_, index) => (index * 19 + 7) & 0xff),
  );
});

describe('device-login approval inspection', () => {
  it('returns a frozen, display-safe pending request with the official fingerprint', async () => {
    const response = pendingResponse();
    const view = await inspectPendingDeviceLoginRequest(
      response,
      approvalContext(),
      NOW,
    );
    const expectedFingerprint = await deriveDeviceLoginFingerprint(
      ACCOUNT_EMAIL,
      base64ToBytes(pending.publicKey),
      FINGERPRINT_WORDLIST,
    );

    expect(view).toEqual({
      id: REQUEST_ID,
      fingerprint: expectedFingerprint,
      requestDeviceType: 'Chrome',
      requestDeviceTypeValue: REQUEST_DEVICE.type,
      requestDeviceIdentifier: REQUEST_DEVICE.identifier,
      requestIpAddress: '203.0.113.7',
      requestCountryName: 'Test Country',
      creationDate: new Date(CREATED_AT).toISOString(),
      creationTime: CREATED_AT,
      expiresAt: CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS,
      requestDeviceId: REQUEST_DEVICE_ID,
      origin: 'vault.example.com',
    });
    expect(view.fingerprint.split('-')).toHaveLength(5);
    expect(Object.isFrozen(view)).toBe(true);
  });

  it('accepts empty optional RequestDeviceId but never exposes it as display data', async () => {
    const view = await inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), requestDeviceId: '' },
      approvalContext(),
      NOW,
    );
    expect(view.requestDeviceId).toBeUndefined();
  });

  it.each([
    ['an answered request', () => ({
      ...pendingResponse(),
      responseDate: new Date(NOW).toISOString(),
    }), /no longer pending/],
    ['an approved request', () => ({
      ...pendingResponse(),
      requestApproved: true,
    }), /no longer pending/],
    ['a pre-populated key', () => ({
      ...pendingResponse(),
      key: '4.AA==',
    }), /response key material/],
    ['a pre-populated master-password hash', () => ({
      ...pendingResponse(),
      masterPasswordHash: 'sensitive-hash',
    }), /response key material/],
  ])('rejects %s before it can be displayed', async (_label, makeResponse, expected) => {
    await expect(inspectPendingDeviceLoginRequest(
      makeResponse(),
      approvalContext(),
      NOW,
    )).rejects.toThrow(expected);
  });

  it('enforces the official 15-minute expiration boundary', async () => {
    const response = pendingResponse();
    await expect(inspectPendingDeviceLoginRequest(
      response,
      approvalContext(),
      CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS - 1,
    )).resolves.toBeDefined();
    await expect(inspectPendingDeviceLoginRequest(
      response,
      approvalContext(),
      CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS,
    )).rejects.toThrow(/expired/);
  });

  it('rejects implausibly future and impossible calendar dates', async () => {
    await expect(inspectPendingDeviceLoginRequest(
      {
        ...pendingResponse(),
        creationDate: new Date(NOW + 5 * 60_000 + 1).toISOString(),
      },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/clock skew/);
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), creationDate: '2026-02-30T08:00:00.000Z' },
      approvalContext(),
      Date.parse('2026-03-02T08:01:00.000Z'),
    )).rejects.toThrow(/creationDate is invalid/);
  });

  it('requires canonical UUIDs for request identifiers', async () => {
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), id: `${REQUEST_ID.slice(0, -1)}z` },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/canonical UUID/);
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), id: `${REQUEST_ID}\n` },
      approvalContext(),
      NOW,
    )).rejects.toThrow();
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), requestDeviceId: 'not-a-uuid' },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/canonical UUID/);
  });

  it.each([
    ['requestDeviceType', 'Chrome\nSpoofed'],
    ['requestDeviceIdentifier', 'requester\u202eexe'],
    ['requestIpAddress', '203.0.113.7\u2066'],
    ['requestCountryName', 'Country\u0000Name'],
    ['origin', 'vault.example.com\u200f'],
    ['origin', 'vault.example\u200b.com'],
  ] as const)('rejects unsafe display text in %s', async (field, value) => {
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), [field]: value },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/(?:control|unsafe display) characters/);
  });

  it('rejects oversized fields and malformed account/device context', async () => {
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), requestCountryName: 'x'.repeat(513) },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/requestCountryName/);
    await expect(inspectPendingDeviceLoginRequest(
      pendingResponse(),
      { ...approvalContext(), accountEmail: 'not-an-email' },
      NOW,
    )).rejects.toThrow(/email is invalid/);
    await expect(inspectPendingDeviceLoginRequest(
      pendingResponse(),
      { ...approvalContext(), approvalDeviceIdentifier: 'x'.repeat(256) },
      NOW,
    )).rejects.toThrow(/approval device identifier/);
    await expect(inspectPendingDeviceLoginRequest(
      pendingResponse(),
      { ...approvalContext(), approvalDeviceIdentifier: 'device\u202eexe' },
      NOW,
    )).rejects.toThrow(/unsafe display/);
  });

  it('accepts only an RSA-2048 OAEP-SHA1 request key with exponent 65537', async () => {
    const generated = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 4_096,
        publicExponent: Uint8Array.from([1, 0, 1]),
        hash: 'SHA-1',
      },
      true,
      ['encrypt', 'decrypt'],
    );
    const wrongSizePublicKey = bytesToBase64(new Uint8Array(
      await crypto.subtle.exportKey('spki', generated.publicKey),
    ));

    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), publicKey: wrongSizePublicKey },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/RSA-2048 OAEP-SHA1/);
    await expect(inspectPendingDeviceLoginRequest(
      { ...pendingResponse(), publicKey: bytesToBase64(new Uint8Array(294)) },
      approvalContext(),
      NOW,
    )).rejects.toThrow(/not valid SPKI/);
  });
});

describe('device-login approval decision', () => {
  it('wraps exactly 64 UserKey bytes as a canonical encType=4 RSA-OAEP-SHA1 value', async () => {
    const originalUserKey = serializeSymmetricKey(userKey);
    const prepared = await prepareDeviceLoginApproval(
      pendingResponse(),
      { ...approvalContext(), userKey },
      NOW,
    );

    expect(prepared.body).toEqual({
      key: expect.stringMatching(/^4\.[A-Za-z0-9+/]+={0,2}$/),
      deviceIdentifier: APPROVAL_DEVICE_IDENTIFIER,
      requestApproved: true,
    });
    expect(Object.keys(prepared.body)).toEqual(['key', 'deviceIdentifier', 'requestApproved']);
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.body)).toBe(true);
    const wrapped = parseRsaEncString(prepared.body.key);
    expect(wrapped.encType).toBe(4);
    expect(wrapped.mac).toBeUndefined();
    expect(wrapped.data).toHaveLength(256);
    expect(`4.${bytesToBase64(wrapped.data)}`).toBe(prepared.body.key);
    await expect(rsaOaepDecrypt(
      base64ToBytes(pending.privateKeyPkcs8),
      wrapped.data,
      'SHA-1',
    )).resolves.toEqual(originalUserKey);
    expect(serializeSymmetricKey(userKey)).toEqual(originalUserKey);
  });

  it('uses fresh OAEP randomness for each approval body', async () => {
    const first = await prepareDeviceLoginApproval(
      pendingResponse(),
      { ...approvalContext(), userKey },
      NOW,
    );
    const second = await prepareDeviceLoginApproval(
      pendingResponse(),
      { ...approvalContext(), userKey },
      NOW,
    );
    expect(first.body.key).not.toBe(second.body.key);
  });

  it('rejects malformed UserKeys without leaking key bytes in the error', async () => {
    const secretMarker = 'ultra-sensitive-user-key-material';
    const invalid = {
      encKey: new Uint8Array(31),
      macKey: new Uint8Array(32),
      secretMarker,
    } as unknown as SymmetricKey;

    let message = '';
    try {
      await prepareDeviceLoginApproval(
        pendingResponse(),
        { ...approvalContext(), userKey: invalid },
        NOW,
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toMatch(/user key is invalid/);
    expect(message).not.toContain(secretMarker);
    expect(message).not.toContain(bytesToBase64(invalid.macKey));
  });

  it('emits a minimal denial body with no key or master-password material', async () => {
    const prepared = await prepareDeviceLoginRejection(
      pendingResponse(),
      approvalContext(),
      NOW,
    );

    expect(prepared.body).toEqual({
      deviceIdentifier: APPROVAL_DEVICE_IDENTIFIER,
      requestApproved: false,
    });
    expect(Object.keys(prepared.body)).toEqual(['deviceIdentifier', 'requestApproved']);
    const serialized = JSON.stringify(prepared.body);
    expect(serialized).not.toContain('key');
    expect(serialized).not.toContain('masterPasswordHash');
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.body)).toBe(true);
  });
});

function approvalContext() {
  return {
    accountEmail: ACCOUNT_EMAIL,
    approvalDeviceIdentifier: APPROVAL_DEVICE_IDENTIFIER,
  };
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
