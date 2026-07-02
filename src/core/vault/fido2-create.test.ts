import { describe, it, expect } from 'vitest';
import { generateFido2Keypair, buildAttestationObject, buildCreateClientDataJSON } from './fido2-create.js';
import { cborDecode } from '../crypto/cbor.js';
import { signFido2Assertion, derToRawSignature } from './fido2.js';
import { base64UrlToBytes } from '../crypto/encoding.js';

const subtle = globalThis.crypto.subtle;

describe('fido2-create', () => {
  it('generates a P-256 keypair with a 16-byte credentialId and SPKI public key', async () => {
    const kp = await generateFido2Keypair();
    expect(kp.credentialId.length).toBe(16);
    expect(kp.pkcs8.length).toBeGreaterThan(0);
    // SPKI imports as an ECDSA P-256 public key.
    await expect(subtle.importKey('spki', kp.publicKeySpki as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])).resolves.toBeTruthy();
  });

  it('builds attestation authData with flags 0x5D (UP|AT|BE|BS|UV) and a decodable COSE key', async () => {
    const kp = await generateFido2Keypair();
    const { attestationObject, authData } = await buildAttestationObject({ rpId: 'example.com', coseKey: kp.coseKey, credentialId: kp.credentialId, userVerified: true });
    // authData: rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16) | credIdLen(2 BE) | credId | COSE
    expect(authData[32]).toBe(0x5d);
    expect([authData[33], authData[34], authData[35], authData[36]]).toEqual([0, 0, 0, 0]); // signCount 0
    expect(Array.from(authData.slice(37, 53))).toEqual(new Array(16).fill(0)); // AAGUID all-zero
    const credIdLen = (authData[53]! << 8) | authData[54]!;
    expect(credIdLen).toBe(16);
    expect(Array.from(authData.slice(55, 71))).toEqual(Array.from(kp.credentialId));
    // attestationObject decodes to {fmt:'none', attStmt:{}, authData}
    const att = cborDecode(attestationObject) as Map<string, unknown>;
    expect(att.get('fmt')).toBe('none');
    expect(att.get('attStmt')).toBeInstanceOf(Map);
    expect((att.get('attStmt') as Map<unknown, unknown>).size).toBe(0);
    expect(att.get('authData')).toEqual(authData);
    // COSE key inside authData decodes with the right params.
    const cose = cborDecode(authData.slice(71)) as Map<number, unknown>;
    expect(cose.get(1)).toBe(2); expect(cose.get(3)).toBe(-7); expect(cose.get(-1)).toBe(1);
    expect((cose.get(-2) as Uint8Array).length).toBe(32);
    expect((cose.get(-3) as Uint8Array).length).toBe(32);
  });

  it('sets flags 0x59 when userVerified is false', async () => {
    const kp = await generateFido2Keypair();
    const { authData } = await buildAttestationObject({ rpId: 'example.com', coseKey: kp.coseKey, credentialId: kp.credentialId, userVerified: false });
    expect(authData[32]).toBe(0x59);
  });

  it('KEYPAIR ROUND-TRIP: an assertion signed with the generated private key verifies under the attested public key', async () => {
    const kp = await generateFido2Keypair();
    const { authData } = await buildAttestationObject({ rpId: 'example.com', coseKey: kp.coseKey, credentialId: kp.credentialId, userVerified: true });
    // Recover the public key from the COSE key embedded in authData.
    const cose = cborDecode(authData.slice(71)) as Map<number, unknown>;
    const x = cose.get(-2) as Uint8Array, y = cose.get(-3) as Uint8Array;
    const rawPub = new Uint8Array([0x04, ...x, ...y]);
    const pubKey = await subtle.importKey('raw', rawPub as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    // Sign an assertion with the stored private key (the same keyValue path production stores).
    const assertion = await signFido2Assertion(kp.pkcs8, { rpId: 'example.com', origin: 'https://example.com', challenge: 'AAAA' });
    const signedData = new Uint8Array([
      ...base64UrlToBytes(assertion.authenticatorData),
      ...new Uint8Array(await subtle.digest('SHA-256', base64UrlToBytes(assertion.clientDataJSON) as BufferSource)),
    ]);
    const rawSig = derToRawSignature(base64UrlToBytes(assertion.signature));
    expect(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, rawSig as BufferSource, signedData as BufferSource)).toBe(true);
  });

  it('clientDataJSON has type webauthn.create and passes challenge/origin through', () => {
    const json = JSON.parse(buildCreateClientDataJSON('Y2hhbA', 'https://example.com'));
    expect(json).toEqual({ type: 'webauthn.create', challenge: 'Y2hhbA', origin: 'https://example.com', crossOrigin: false });
  });
});
