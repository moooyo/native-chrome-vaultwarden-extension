import { describe, it, expect } from 'vitest';
import {
  parseEncString, decryptToBytes, decryptToText,
  EncStringMacError, UnsupportedEncTypeError,
} from './encstring.js';
import { symmetricKeyFromBytes } from './keys.js';
import { hexToBytes, bytesToHex } from './encoding.js';
import { USER_KEY_VECTOR, FIELD_VECTOR, TAMPERED_FIELD_ENCSTRING, STRETCH_VECTOR } from '../../../test/vectors.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

describe('encstring', () => {
  it('parses an encType=2 string into iv|ct|mac', () => {
    const p = parseEncString(FIELD_VECTOR.encString);
    expect(p.encType).toBe(2);
    expect(p.iv.length).toBe(16);
    expect(p.mac.length).toBe(32);
    expect(p.ct.length).toBeGreaterThan(0);
  });

  it('rejects unsupported encType', () => {
    expect(() => parseEncString('4.aGVsbG8=')).toThrow(UnsupportedEncTypeError);
  });

  it('decrypts a field to text', async () => {
    expect(await decryptToText(FIELD_VECTOR.encString, userKey)).toBe(FIELD_VECTOR.plaintext);
  });

  it('decrypts the wrapped UserKey to its 64 raw bytes (via stretched key)', async () => {
    const stretched = {
      encKey: hexToBytes(STRETCH_VECTOR.encKeyHex),
      macKey: hexToBytes(STRETCH_VECTOR.macKeyHex),
    };
    const raw = await decryptToBytes(USER_KEY_VECTOR.akey, stretched);
    expect(bytesToHex(raw)).toBe(USER_KEY_VECTOR.userKeyHex);
  });

  it('throws EncStringMacError when the mac is tampered', async () => {
    await expect(decryptToText(TAMPERED_FIELD_ENCSTRING, userKey)).rejects.toBeInstanceOf(EncStringMacError);
  });
});
