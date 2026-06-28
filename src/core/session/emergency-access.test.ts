import { describe, it, expect } from 'vitest';
import { grantEmergencyKey, recoverEmergencyKey } from './emergency-access.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { bytesToHex } from '../crypto/encoding.js';

const subtle = globalThis.crypto.subtle;

async function granteeKeypair() {
  const pair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt'],
  );
  return {
    publicKey: new Uint8Array(await subtle.exportKey('spki', pair.publicKey)),
    privateKey: new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)),
  };
}

describe('emergency access key grant', () => {
  it('grants the grantor user key to a grantee public key and the grantee recovers it', async () => {
    const { publicKey, privateKey } = await granteeKeypair();
    const userKeyBytes = Uint8Array.from({ length: 64 }, (_, i) => (i * 7) & 0xff);
    const userKey = symmetricKeyFromBytes(userKeyBytes);

    // Grantor wraps their UserKey to the grantee's public key (encType=4 EncString).
    const wrapped = await grantEmergencyKey(userKey, publicKey);
    expect(wrapped.startsWith('4.')).toBe(true);

    // Grantee recovers the UserKey with their private key.
    const recovered = await recoverEmergencyKey(wrapped, privateKey);
    expect(bytesToHex(recovered.encKey)).toBe(bytesToHex(userKey.encKey));
    expect(bytesToHex(recovered.macKey)).toBe(bytesToHex(userKey.macKey));
  });
});
