import { describe, expect, it } from 'vitest';
import { encryptToText } from '../crypto/encstring.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import {
  assertSshCipherPayloadExclusivity,
  parseCompleteDecryptedSshKey,
  parseDecryptedSshKey,
  parseSshKeyCipherData,
} from './ssh-key.js';

const key = symmetricKeyFromBytes(new Uint8Array(64).fill(7));

async function encryptedPayload() {
  return {
    privateKey: await encryptToText('PRIVATE', key),
    publicKey: await encryptToText('PUBLIC', key),
    keyFingerprint: await encryptToText('SHA256:fingerprint', key),
  };
}

describe('SSH key structural validation', () => {
  it('accepts and clones a complete three-field EncString payload', async () => {
    const payload = await encryptedPayload();
    const parsed = parseSshKeyCipherData(payload);
    expect(parsed).toEqual(payload);
    expect(parsed).not.toBe(payload);
  });

  it('accepts a read-side payload whose derivable public fields are absent', async () => {
    const payload = await encryptedPayload();
    expect(parseSshKeyCipherData({ privateKey: payload.privateKey, publicKey: null })).toEqual({
      privateKey: payload.privateKey,
    });
  });

  it.each([
    null,
    [],
    {},
    { privateKey: '2.bad', publicKey: '2.bad', keyFingerprint: '2.bad' },
    { privateKey: '2.bad', publicKey: '2.bad', keyFingerprint: '2.bad', futureField: '2.bad' },
  ])('rejects malformed encrypted payload %#', (payload) => {
    expect(() => parseSshKeyCipherData(payload)).toThrow(TypeError);
  });

  it('accepts opaque existing OpenSSH strings without parsing their key algorithm', () => {
    expect(parseDecryptedSshKey({
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nopaque\n-----END OPENSSH PRIVATE KEY-----\n',
      publicKey: 'ssh-future AAAAopaque comment',
      keyFingerprint: 'SHA256:opaque',
    })).toEqual({
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nopaque\n-----END OPENSSH PRIVATE KEY-----\n',
      publicKey: 'ssh-future AAAAopaque comment',
      keyFingerprint: 'SHA256:opaque',
    });
  });

  it.each([
    undefined,
    {},
    { privateKey: '', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
    { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x', extra: 'nope' },
    { privateKey: 'PRIVATE\0', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
  ])('rejects malformed decrypted payload %#', (payload) => {
    expect(() => parseDecryptedSshKey(payload)).toThrow(TypeError);
  });

  it('requires a complete triple on the write side', () => {
    expect(() => parseCompleteDecryptedSshKey({ privateKey: 'PRIVATE' })).toThrow(/writer requires/i);
    expect(parseCompleteDecryptedSshKey({
      privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x',
    })).toEqual({ privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' });
  });

  it('rejects conflicting legacy payloads on an SSH cipher', () => {
    expect(() => assertSshCipherPayloadExclusivity({ login: { username: '2.enc' } }))
      .toThrow(/must not contain login/i);
    expect(() => assertSshCipherPayloadExclusivity({ login: null, card: null, identity: null }))
      .not.toThrow();
    expect(() => assertSshCipherPayloadExclusivity({ data: '{"Name":"2.server-authority"}' }))
      .toThrow(/must not contain data/i);
  });
});
