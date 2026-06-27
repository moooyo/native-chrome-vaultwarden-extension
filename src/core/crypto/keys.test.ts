import { describe, it, expect } from 'vitest';
import { unwrapSymmetricKey, symmetricKeyFromBytes } from './keys.js';
import { hexToBytes, bytesToHex } from './encoding.js';
import { USER_KEY_VECTOR, STRETCH_VECTOR } from '../../../test/vectors.js';

describe('keys.unwrapSymmetricKey', () => {
  it('unwraps the protected UserKey using the stretched master key', async () => {
    const stretched = { encKey: hexToBytes(STRETCH_VECTOR.encKeyHex), macKey: hexToBytes(STRETCH_VECTOR.macKeyHex) };
    const userKey = await unwrapSymmetricKey(USER_KEY_VECTOR.akey, stretched);
    const expected = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    expect(bytesToHex(userKey.encKey)).toBe(bytesToHex(expected.encKey));
    expect(bytesToHex(userKey.macKey)).toBe(bytesToHex(expected.macKey));
  });
});
