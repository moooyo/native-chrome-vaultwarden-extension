import { describe, it, expect } from 'vitest';
import { unwrapSymmetricKey, symmetricKeyFromBytes, decryptPrivateKey } from './keys.js';
import { hexToBytes, bytesToHex, bytesToBase64 } from './encoding.js';
import { USER_KEY_VECTOR, STRETCH_VECTOR, RSA_PRIVATE_KEY_VECTOR } from '../../../test/vectors.js';

describe('keys.unwrapSymmetricKey', () => {
  it('unwraps the protected UserKey using the stretched master key', async () => {
    const stretched = { encKey: hexToBytes(STRETCH_VECTOR.encKeyHex), macKey: hexToBytes(STRETCH_VECTOR.macKeyHex) };
    const userKey = await unwrapSymmetricKey(USER_KEY_VECTOR.akey, stretched);
    const expected = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    expect(bytesToHex(userKey.encKey)).toBe(bytesToHex(expected.encKey));
    expect(bytesToHex(userKey.macKey)).toBe(bytesToHex(expected.macKey));
  });
});

describe('keys.decryptPrivateKey', () => {
  it('decrypts the userKey-wrapped PrivateKey into importable PKCS8 bytes', async () => {
    const userKey = symmetricKeyFromBytes(hexToBytes(RSA_PRIVATE_KEY_VECTOR.userKeyHex));
    const pkcs8 = await decryptPrivateKey(RSA_PRIVATE_KEY_VECTOR.encPrivateKey, userKey);
    expect(bytesToBase64(pkcs8)).toBe(RSA_PRIVATE_KEY_VECTOR.pkcs8B64);
    await expect(
      crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt']),
    ).resolves.toBeTruthy();
  });
});
