import { beforeAll, describe, expect, it } from 'vitest';

import { bytesToBase64, base64ToBytes } from '../crypto/encoding.js';
import { serializeSymmetricKey } from '../crypto/keys.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { FINGERPRINT_WORDLIST, PASSPHRASE_WORDLIST } from '../generator/wordlist.js';
import {
  DEVICE_LOGIN_ACCESS_CODE_LENGTH,
  DEVICE_LOGIN_REQUEST_TTL_MS,
  bindDeviceLoginRequest,
  createDeviceLoginRequest,
  deriveDeviceLoginFingerprint,
  fingerprintPhraseFromEntropy,
  generateDeviceLoginAccessCode,
  isDeviceLoginStateExpired,
  parseAuthRequestResponse,
  recoverApprovedDeviceLogin,
  restoreDeviceLoginState,
  type DeviceLoginBoundState,
  type DeviceLoginPendingState,
} from './device-login.js';

const NOW = Date.parse('2026-08-30T08:00:00.000Z');
const SERVER_CREATED_AT = NOW + 1_000;
const REQUEST_ID = 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34';
const OTHER_REQUEST_ID = 'c05e732e-77b1-457b-8f89-5b5ba1b4e1d2';
const DEVICE = Object.freeze({ type: 2, name: 'chrome', identifier: 'device-123' });

let pending: DeviceLoginPendingState;
let otherPending: DeviceLoginPendingState;
let bound: DeviceLoginBoundState;

beforeAll(async () => {
  pending = (await createDeviceLoginRequest({ email: ' User@Example.COM ', device: DEVICE }, NOW)).state;
  otherPending = (await createDeviceLoginRequest({ email: 'user@example.com', device: DEVICE }, NOW)).state;
  bound = await bindDeviceLoginRequest(
    pending,
    creationResponse(pending),
    SERVER_CREATED_AT + 1_000,
  );
});

describe('device-login request creation', () => {
  it('generates an official-compatible RSA key pair, access code, and request body', async () => {
    const created = await createDeviceLoginRequest(
      { email: ' Alice@Example.COM ', device: DEVICE },
      NOW,
    );

    expect(created.request).toEqual({
      email: 'alice@example.com',
      deviceIdentifier: DEVICE.identifier,
      publicKey: created.state.publicKey,
      type: 0,
      accessCode: created.state.accessCode,
    });
    expect(created.state).toMatchObject({
      version: 1,
      phase: 'pending',
      email: 'alice@example.com',
      device: DEVICE,
      createdAt: NOW,
      expiresAt: NOW + DEVICE_LOGIN_REQUEST_TTL_MS,
    });
    expect(created.state.accessCode).toMatch(/^[A-Za-z0-9]{25}$/);
    expect(created.state.accessCode).toMatch(/[A-Z]/);
    expect(created.state.accessCode).toMatch(/[a-z]/);
    expect(created.state.accessCode).toMatch(/[0-9]/);
    expect(Object.isFrozen(created.request)).toBe(true);
    expect(Object.isFrozen(created.state)).toBe(true);

    const publicKey = await crypto.subtle.importKey(
      'spki',
      base64ToBytes(created.state.publicKey) as BufferSource,
      { name: 'RSA-OAEP', hash: 'SHA-1' },
      false,
      ['encrypt'],
    );
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      base64ToBytes(created.state.privateKeyPkcs8) as BufferSource,
      { name: 'RSA-OAEP', hash: 'SHA-1' },
      false,
      ['decrypt'],
    );
    expect(publicKey.algorithm).toMatchObject({
      name: 'RSA-OAEP',
      modulusLength: 2_048,
      hash: { name: 'SHA-1' },
    });
    expect(privateKey.algorithm).toMatchObject({
      name: 'RSA-OAEP',
      modulusLength: 2_048,
      hash: { name: 'SHA-1' },
    });
  });

  it('uses fresh cryptographic material for every request', async () => {
    const first = await createDeviceLoginRequest({ email: 'user@example.com', device: DEVICE }, NOW);
    const second = await createDeviceLoginRequest({ email: 'user@example.com', device: DEVICE }, NOW);

    expect(first.state.publicKey).not.toBe(second.state.publicKey);
    expect(first.state.privateKeyPkcs8).not.toBe(second.state.privateKeyPkcs8);
    expect(first.state.accessCode).not.toBe(second.state.accessCode);
  });

  it('generates bounded alphanumeric access codes with every required character class', () => {
    const values = Array.from({ length: 64 }, () => generateDeviceLoginAccessCode());
    for (const value of values) {
      expect(value).toHaveLength(DEVICE_LOGIN_ACCESS_CODE_LENGTH);
      expect(value).toMatch(/^[A-Za-z0-9]+$/);
      expect(value).toMatch(/[A-Z]/);
      expect(value).toMatch(/[a-z]/);
      expect(value).toMatch(/[0-9]/);
    }
    expect(new Set(values).size).toBe(values.length);
  });

  it('rejects malformed email and device identity inputs before key generation', async () => {
    for (const email of ['not-an-email', 'user@', '@example.com', 'user name@example.com']) {
      await expect(createDeviceLoginRequest({ email, device: DEVICE }, NOW))
        .rejects.toThrow(/email is invalid/);
    }
    await expect(createDeviceLoginRequest({
      email: 'user@example.com',
      device: { ...DEVICE, identifier: 'bad\nidentifier' },
    }, NOW)).rejects.toThrow(/control characters/);
    await expect(createDeviceLoginRequest({
      email: 'user@example.com',
      device: { ...DEVICE, extra: true } as never,
    }, NOW)).rejects.toThrow(/unsupported field/);
  });
});

describe('device-login fingerprint', () => {
  it('matches Bitwarden upstream five-word phrase mapping', async () => {
    const upstreamUserFingerprint = base64ToBytes(
      'V5AQSk83YXd6kZqCncC6d9J72R7UZ60Xl1eIoDoWgTc=',
    );

    await expect(fingerprintPhraseFromEntropy(upstreamUserFingerprint, FINGERPRINT_WORDLIST))
      .resolves.toBe('predefine-hunting-pastime-enrich-unhearing');
  });

  it('derives a stable, case-insensitive five-word phrase from the SPKI public key', async () => {
    const publicKey = base64ToBytes(pending.publicKey);
    const lower = await deriveDeviceLoginFingerprint(
      'user@example.com',
      publicKey,
      FINGERPRINT_WORDLIST,
    );
    const mixed = await deriveDeviceLoginFingerprint(
      ' User@Example.COM ',
      publicKey,
      FINGERPRINT_WORDLIST,
    );

    expect(mixed).toBe(lower);
    expect(lower.split('-')).toHaveLength(5);
  });

  it('refuses the repository passphrase list and any other fake ordering', async () => {
    const entropy = new Uint8Array(32);
    await expect(fingerprintPhraseFromEntropy(entropy, PASSPHRASE_WORDLIST))
      .rejects.toThrow(/exactly 7776/);
    const tampered = [...FINGERPRINT_WORDLIST];
    tampered[0] = 'notabacus';
    await expect(fingerprintPhraseFromEntropy(entropy, tampered))
      .rejects.toThrow(/not the official ordered EFF/);
  });
});

describe('parseAuthRequestResponse', () => {
  it('parses the bounded camel-case server response and derives status locally', () => {
    const parsed = parseAuthRequestResponse(creationResponse(pending), SERVER_CREATED_AT + 1_000);

    expect(parsed).toMatchObject({
      id: REQUEST_ID,
      publicKey: pending.publicKey,
      requestDeviceType: 'Chrome',
      requestDeviceTypeValue: DEVICE.type,
      requestDeviceIdentifier: DEVICE.identifier,
      requestIpAddress: '203.0.113.7',
      requestCountryName: 'Test Country',
      requestApproved: false,
      creationTime: SERVER_CREATED_AT,
      answered: false,
      expired: false,
    });
    expect(parsed.key).toBeUndefined();
    expect(parsed.responseDate).toBeUndefined();
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it('accepts the official Pascal-case aliases and rejects ambiguous aliases', () => {
    const camel = creationResponse(pending);
    const pascal = {
      Object: camel.object,
      Id: camel.id,
      PublicKey: camel.publicKey,
      RequestDeviceType: camel.requestDeviceType,
      RequestDeviceTypeValue: camel.requestDeviceTypeValue,
      RequestDeviceIdentifier: camel.requestDeviceIdentifier,
      RequestIpAddress: camel.requestIpAddress,
      RequestCountryName: camel.requestCountryName,
      Key: camel.key,
      MasterPasswordHash: camel.masterPasswordHash,
      CreationDate: camel.creationDate,
      RequestApproved: camel.requestApproved,
      ResponseDate: camel.responseDate,
      Origin: camel.origin,
    };
    expect(parseAuthRequestResponse(pascal, SERVER_CREATED_AT + 1_000).id).toBe(REQUEST_ID);
    expect(() => parseAuthRequestResponse({ ...camel, Id: REQUEST_ID }, SERVER_CREATED_AT))
      .toThrow(/ambiguous aliases for id/);
  });

  it('computes the official 15-minute expiration boundary', () => {
    const response = creationResponse(pending);
    expect(parseAuthRequestResponse(
      response,
      SERVER_CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS - 1,
    ).expired).toBe(false);
    expect(parseAuthRequestResponse(
      response,
      SERVER_CREATED_AT + DEVICE_LOGIN_REQUEST_TTL_MS,
    ).expired).toBe(true);
  });

  it.each([
    ['unknown field', () => ({ ...creationResponse(pending), unexpected: true }), /unsupported field/],
    ['non-UUID id', () => ({ ...creationResponse(pending), id: 'not-a-guid' }), /canonical UUID/],
    ['invalid public key base64', () => ({ ...creationResponse(pending), publicKey: '*'.repeat(300) }), /canonical base64/],
    ['oversized country', () => ({ ...creationResponse(pending), requestCountryName: 'x'.repeat(513) }), /requestCountryName/],
    ['non-integer device type', () => ({ ...creationResponse(pending), requestDeviceTypeValue: '2' }), /integer/],
    ['invalid creation date', () => ({ ...creationResponse(pending), creationDate: 'yesterday' }), /ISO-8601/],
    ['non-boolean approval', () => ({ ...creationResponse(pending), requestApproved: 1 }), /boolean/],
    ['wrong object discriminator', () => ({ ...creationResponse(pending), object: 'cipher' }), /not auth-request/],
  ])('rejects %s', (_label, makeResponse, expected) => {
    expect(() => parseAuthRequestResponse(makeResponse(), SERVER_CREATED_AT)).toThrow(expected);
  });

  it('rejects non-plain response objects', () => {
    expect(() => parseAuthRequestResponse(new Date(), SERVER_CREATED_AT)).toThrow(/plain object/);
  });
});

describe('device-login response binding', () => {
  it('binds the request id and clamps TTL to the earliest local/server deadline', () => {
    expect(bound).toMatchObject({
      phase: 'bound',
      requestId: REQUEST_ID,
      serverCreationDate: new Date(SERVER_CREATED_AT).toISOString(),
      expiresAt: NOW + DEVICE_LOGIN_REQUEST_TTL_MS,
    });
  });

  it('rejects an answered creation response', async () => {
    await expect(bindDeviceLoginRequest(pending, {
      ...creationResponse(pending),
      requestApproved: false,
      responseDate: new Date(SERVER_CREATED_AT + 100).toISOString(),
    }, SERVER_CREATED_AT + 1_000)).rejects.toThrow(/already answered/);
  });

  it('binds the server response to the locally derived public key and device', async () => {
    await expect(bindDeviceLoginRequest(pending, {
      ...creationResponse(pending),
      publicKey: otherPending.publicKey,
    }, SERVER_CREATED_AT + 1_000)).rejects.toThrow(/public key does not match/);
    await expect(bindDeviceLoginRequest(pending, {
      ...creationResponse(pending),
      requestDeviceIdentifier: 'other-device',
    }, SERVER_CREATED_AT + 1_000)).rejects.toThrow(/device identifier/);
    await expect(bindDeviceLoginRequest(pending, {
      ...creationResponse(pending),
      requestDeviceTypeValue: 3,
    }, SERVER_CREATED_AT + 1_000)).rejects.toThrow(/device type/);
  });

  it('rejects stale or implausibly future creation responses', async () => {
    await expect(bindDeviceLoginRequest(pending, {
      ...creationResponse(pending),
      creationDate: new Date(NOW - 5 * 60_000 - 1).toISOString(),
    }, SERVER_CREATED_AT + 1_000)).rejects.toThrow(/clock skew/);
    await expect(bindDeviceLoginRequest(pending, {
      ...creationResponse(pending),
      creationDate: new Date(SERVER_CREATED_AT + 5 * 60_000 + 1_001).toISOString(),
    }, SERVER_CREATED_AT + 1_000)).rejects.toThrow(/clock skew/);
  });
});

describe('approved device-login recovery', () => {
  it('decrypts an encType=4 RSA-OAEP-SHA1 response into a 64-byte UserKey', async () => {
    const rawUserKey = Uint8Array.from({ length: 64 }, (_, index) => (index * 17) & 0xff);
    const response = await approvedResponse(bound, rawUserKey);

    const recovered = await recoverApprovedDeviceLogin(
      bound,
      response,
      SERVER_CREATED_AT + 61_000,
    );

    expect(serializeSymmetricKey(recovered.userKey)).toEqual(rawUserKey);
    expect(recovered.response.requestApproved).toBe(true);
    expect(recovered.response.answered).toBe(true);
  });

  it('rejects mismatched request id, public key, and device binding', async () => {
    const response = await approvedResponse(bound, new Uint8Array(64).fill(7));
    await expect(recoverApprovedDeviceLogin(bound, {
      ...response,
      id: OTHER_REQUEST_ID,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/request id/);
    await expect(recoverApprovedDeviceLogin(bound, {
      ...response,
      publicKey: otherPending.publicKey,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/public key/);
    await expect(recoverApprovedDeviceLogin(bound, {
      ...response,
      requestDeviceIdentifier: 'other-device',
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/device identifier/);
  });

  it('requires an answered, approved, unexpired response from the original request', async () => {
    const response = await approvedResponse(bound, new Uint8Array(64).fill(8));
    await expect(recoverApprovedDeviceLogin(bound, {
      ...response,
      requestApproved: false,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/not approved/);
    await expect(recoverApprovedDeviceLogin(bound, {
      ...response,
      responseDate: null,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/not been answered/);
    await expect(recoverApprovedDeviceLogin(bound, {
      ...response,
      creationDate: new Date(SERVER_CREATED_AT + 1).toISOString(),
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/creation date/);
    await expect(recoverApprovedDeviceLogin(
      bound,
      response,
      bound.expiresAt,
    )).rejects.toThrow(/expired/);
  });

  it('accepts only canonical type-4 ciphertext and exactly 64 decrypted bytes', async () => {
    const valid = await approvedResponse(bound, new Uint8Array(64).fill(9));
    await expect(recoverApprovedDeviceLogin(bound, {
      ...valid,
      key: `3.${valid.key.slice(2)}`,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/encType=4/);
    await expect(recoverApprovedDeviceLogin(bound, {
      ...valid,
      key: `${valid.key}|AAAA`,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/encType=4/);

    const short = await approvedResponse(bound, new Uint8Array(32).fill(4));
    await expect(recoverApprovedDeviceLogin(
      bound,
      short,
      SERVER_CREATED_AT + 61_000,
    )).rejects.toThrow(/exactly 64 bytes/);

    const wrongRecipient = await encryptedUserKey(otherPending.publicKey, new Uint8Array(64));
    await expect(recoverApprovedDeviceLogin(bound, {
      ...valid,
      key: wrongRecipient,
    }, SERVER_CREATED_AT + 61_000)).rejects.toThrow(/could not be decrypted/);
  });
});

describe('device-login state', () => {
  it('restores pending and bound JSON snapshots after revalidating the RSA key binding', async () => {
    const pendingSnapshot = JSON.parse(JSON.stringify(pending)) as unknown;
    const boundSnapshot = JSON.parse(JSON.stringify(bound)) as unknown;

    await expect(restoreDeviceLoginState(pendingSnapshot, NOW + 1)).resolves.toEqual(pending);
    await expect(restoreDeviceLoginState(boundSnapshot, SERVER_CREATED_AT + 2_000))
      .resolves.toEqual(bound);
  });

  it('rejects forged, overlong, unknown, or expired cached state', async () => {
    const pendingSnapshot = JSON.parse(JSON.stringify(pending)) as Record<string, unknown>;
    await expect(restoreDeviceLoginState({
      ...pendingSnapshot,
      publicKey: otherPending.publicKey,
    }, NOW + 1)).rejects.toThrow(/public key does not match/);
    await expect(restoreDeviceLoginState({
      ...pendingSnapshot,
      expiresAt: NOW + DEVICE_LOGIN_REQUEST_TTL_MS + 1,
    }, NOW + 1)).rejects.toThrow(/TTL/);
    await expect(restoreDeviceLoginState({
      ...pendingSnapshot,
      globalStorage: true,
    }, NOW + 1)).rejects.toThrow(/unsupported field/);
    await expect(restoreDeviceLoginState(pendingSnapshot, pending.expiresAt))
      .rejects.toThrow(/expired/);
  });

  it('enforces the 15-minute state deadline', () => {
    expect(isDeviceLoginStateExpired(bound, bound.expiresAt - 1)).toBe(false);
    expect(isDeviceLoginStateExpired(bound, bound.expiresAt)).toBe(true);
  });

  it('rejects UUIDs with a trailing line terminator', async () => {
    const malformedId = `${REQUEST_ID}\n`;
    let message = '';
    try {
      await bindDeviceLoginRequest(
        pending,
        { ...creationResponse(pending), id: malformedId },
        SERVER_CREATED_AT + 2_000,
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toMatch(/id must be/);
    expect(message).not.toContain(malformedId);
  });
});

function creationResponse(state: DeviceLoginPendingState | DeviceLoginBoundState) {
  return {
    object: 'auth-request',
    id: REQUEST_ID,
    publicKey: state.publicKey,
    requestDeviceType: 'Chrome',
    requestDeviceTypeValue: DEVICE.type,
    requestDeviceIdentifier: DEVICE.identifier,
    requestIpAddress: '203.0.113.7',
    requestCountryName: 'Test Country',
    key: null,
    masterPasswordHash: null,
    creationDate: new Date(SERVER_CREATED_AT).toISOString(),
    requestApproved: false,
    responseDate: null,
    origin: 'vault.example.com',
  };
}

async function approvedResponse(state: DeviceLoginBoundState, rawUserKey: Uint8Array) {
  return {
    ...creationResponse(state),
    key: await encryptedUserKey(state.publicKey, rawUserKey),
    requestApproved: true,
    responseDate: new Date(SERVER_CREATED_AT + 60_000).toISOString(),
  };
}

async function encryptedUserKey(publicKeyBase64: string, rawUserKey: Uint8Array): Promise<string> {
  const ciphertext = await rsaOaepEncrypt(
    base64ToBytes(publicKeyBase64),
    rawUserKey,
    'SHA-1',
  );
  return `4.${bytesToBase64(ciphertext)}`;
}
