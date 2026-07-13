import { describe, it, expect } from 'vitest';
import {
  parseEncString, parseRsaEncString, decryptToBytes, decryptToText,
  encryptToBytes, encryptToText,
  EncStringMacError, UnsupportedEncTypeError,
} from './encstring.js';
import { symmetricKeyFromBytes } from './keys.js';
import { hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } from './encoding.js';
import { USER_KEY_VECTOR, FIELD_VECTOR, TAMPERED_FIELD_ENCSTRING, STRETCH_VECTOR, RSA_VECTOR, ORG_KEY_VECTOR } from '../../../test/vectors.js';

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

  it('parseRsaEncString parses an RSA encType=4 single-segment string', () => {
    const p = parseRsaEncString(RSA_VECTOR.encType4EncString);
    expect(p.encType).toBe(4);
    expect(p.data.length).toBe(256); // 2048-bit RSA ciphertext
    expect(p.mac).toBeUndefined();
  });

  it('parseRsaEncString parses an RSA encType=3 (SHA-256) single-segment string', () => {
    const p = parseRsaEncString(ORG_KEY_VECTOR.encOrgKeySha256);
    expect(p.encType).toBe(3);
    expect(p.data.length).toBe(256);
    expect(p.mac).toBeUndefined();
  });

  it('parseRsaEncString parses an encType=6 outer HMAC segment (without verifying it)', () => {
    const mac = new Uint8Array(32).fill(0xab);
    const p = parseRsaEncString(`6.${RSA_VECTOR.encType4EncString.slice(2)}|${bytesToBase64(mac)}`);
    expect(p.encType).toBe(6);
    expect(p.data.length).toBe(256);
    expect(p.mac && bytesToHex(p.mac)).toBe('ab'.repeat(32));
  });

  it('parseRsaEncString parses an encType=5 (SHA-256 + HMAC) string', () => {
    const mac = new Uint8Array(32).fill(0xcd);
    const p = parseRsaEncString(`5.${ORG_KEY_VECTOR.encOrgKeySha256.slice(2)}|${bytesToBase64(mac)}`);
    expect(p.encType).toBe(5);
    expect(p.mac && bytesToHex(p.mac)).toBe('cd'.repeat(32));
  });

  it('parseRsaEncString rejects a symmetric encType=2 string', () => {
    expect(() => parseRsaEncString(FIELD_VECTOR.encString)).toThrow(UnsupportedEncTypeError);
  });

  it('parseEncString still rejects RSA encType=4 (symmetric path untouched)', () => {
    expect(() => parseEncString(RSA_VECTOR.encType4EncString)).toThrow(UnsupportedEncTypeError);
  });

  it('encryptToText produces an encType=2 EncString that round-trips back to the plaintext', async () => {
    const enc = await encryptToText('secret value', userKey);
    expect(enc.startsWith('2.')).toBe(true);
    expect(parseEncString(enc).encType).toBe(2);
    expect(await decryptToText(enc, userKey)).toBe('secret value');
  });

  it('encryptToBytes round-trips raw bytes (used for wrapping keys)', async () => {
    const raw = hexToBytes('00112233445566778899aabbccddeeff'.repeat(2));
    const enc = await encryptToBytes(raw, userKey);
    expect(bytesToHex(await decryptToBytes(enc, userKey))).toBe(bytesToHex(raw));
  });

  it('uses a fresh random IV each call so identical plaintext yields different ciphertext', async () => {
    const a = await encryptToText('same', userKey);
    const b = await encryptToText('same', userKey);
    expect(a).not.toBe(b);
    expect(await decryptToText(a, userKey)).toBe('same');
    expect(await decryptToText(b, userKey)).toBe('same');
  });

  it('produces a MAC that fails verification if the ciphertext is tampered', async () => {
    const enc = await encryptToText('integrity', userKey);
    const [prefix, ctSeg, macSeg] = enc.split('|');
    const ctBytes = base64ToBytes(ctSeg!);
    ctBytes[0] = ctBytes[0]! ^ 0xff; // flip a byte while keeping valid base64
    const tampered = `${prefix}|${bytesToBase64(ctBytes)}|${macSeg}`;
    await expect(decryptToText(tampered, userKey)).rejects.toBeInstanceOf(EncStringMacError);
  });
});
