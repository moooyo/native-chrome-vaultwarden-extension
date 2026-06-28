import { describe, it, expect } from 'vitest';
import { signFido2Assertion, buildAuthenticatorData, derToRawSignature } from './fido2.js';
import { base64UrlToBytes, bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';

const subtle = globalThis.crypto.subtle;

async function makeKeypair() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  return { pkcs8, publicKey: pair.publicKey };
}

describe('buildAuthenticatorData', () => {
  it('lays out rpIdHash (32) + flags (1) + signCount (4) big-endian', async () => {
    const data = await buildAuthenticatorData('example.com', 0x05, 7);
    expect(data.length).toBe(37);
    expect(data[32]).toBe(0x05);
    expect(Array.from(data.slice(33))).toEqual([0, 0, 0, 7]);
  });
});

describe('signFido2Assertion', () => {
  it('produces an assertion whose DER signature verifies against the public key', async () => {
    const { pkcs8, publicKey } = await makeKeypair();
    const challenge = bytesToBase64Url(utf8ToBytes('a-random-challenge'));
    const result = await signFido2Assertion(pkcs8, {
      rpId: 'example.com', origin: 'https://example.com', challenge, counter: 0, userVerified: true,
    });

    // clientDataJSON round-trips and binds the challenge + origin + type.
    const clientData = JSON.parse(new TextDecoder().decode(base64UrlToBytes(result.clientDataJSON)));
    expect(clientData).toMatchObject({ type: 'webauthn.get', challenge, origin: 'https://example.com', crossOrigin: false });

    // The signature is over authenticatorData ‖ SHA-256(clientDataJSON), ECDSA P-256 / SHA-256.
    const authData = base64UrlToBytes(result.authenticatorData);
    const clientHash = new Uint8Array(await subtle.digest('SHA-256', base64UrlToBytes(result.clientDataJSON) as BufferSource));
    const signedData = new Uint8Array([...authData, ...clientHash]);
    const rawSig = derToRawSignature(base64UrlToBytes(result.signature));
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, rawSig as BufferSource, signedData as BufferSource);
    expect(ok).toBe(true);
  });

  it('sets the user-present flag, and user-verified only when requested', async () => {
    const { pkcs8 } = await makeKeypair();
    const challenge = bytesToBase64Url(utf8ToBytes('c'));
    const withUv = await signFido2Assertion(pkcs8, { rpId: 'r', origin: 'https://r', challenge, userVerified: true });
    const noUv = await signFido2Assertion(pkcs8, { rpId: 'r', origin: 'https://r', challenge, userVerified: false });
    expect(base64UrlToBytes(withUv.authenticatorData)[32]! & 0x04).toBe(0x04);
    expect(base64UrlToBytes(noUv.authenticatorData)[32]! & 0x04).toBe(0);
    expect(base64UrlToBytes(noUv.authenticatorData)[32]! & 0x01).toBe(0x01); // UP always set
  });
});
