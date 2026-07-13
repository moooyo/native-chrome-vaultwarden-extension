import { describe, it, expect } from 'vitest';
import { pbkdf2Sha256, hkdfExpandSha256, hmacSha256, aesCbc256Decrypt, aesCbc256Encrypt, rsaOaepDecrypt, rsaOaepEncrypt } from './primitives.js';
import { utf8ToBytes, bytesToHex, hexToBytes, base64ToBytes, bytesToUtf8 } from './encoding.js';
import { RSA_VECTOR, ORG_KEY_VECTOR } from '../../../test/vectors.js';

describe('primitives', () => {
  it('PBKDF2-HMAC-SHA256 matches known answers', async () => {
    const p = utf8ToBytes('password');
    const s = utf8ToBytes('salt');
    expect(bytesToHex(await pbkdf2Sha256(p, s, 1, 32)))
      .toBe('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
    expect(bytesToHex(await pbkdf2Sha256(p, s, 4096, 32)))
      .toBe('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
  });

  it('HMAC-SHA256 matches RFC 4231 test case 1', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const mac = await hmacSha256(key, utf8ToBytes('Hi There'));
    expect(bytesToHex(mac)).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  });

  it('HKDF-Expand (single block) equals verified Bitwarden-style stretch vectors', async () => {
    const prk = hexToBytes('c6e36acf506a7d05ec07ebe2c4f8406ccb1b69e761e71e61e7e24edc0b7736bd');
    expect(bytesToHex(await hkdfExpandSha256(prk, 'enc', 32)))
      .toBe('d2425697ee6622bac49a08c019c169ad0aa04ccb08f1ec76b580938e5c4d71ac');
    expect(bytesToHex(await hkdfExpandSha256(prk, 'mac', 32)))
      .toBe('0586d3103bfe6a5e5c72ec94d05907bda43b6b26bafeb67e896885e5addab596');
  });

  it('HKDF-Expand multi-block (64B) follows RFC 5869 chaining (used for Send keys)', async () => {
    const prk = hexToBytes('c6e36acf506a7d05ec07ebe2c4f8406ccb1b69e761e71e61e7e24edc0b7736bd');
    const okm = await hkdfExpandSha256(prk, 'send', 64);
    expect(okm.length).toBe(64);
    // First block equals the single-block expansion.
    const t1 = await hkdfExpandSha256(prk, 'send', 32);
    expect(bytesToHex(okm.slice(0, 32))).toBe(bytesToHex(t1));
    // Second block = HMAC(PRK, T(1) ‖ info ‖ 0x02).
    const info = new TextEncoder().encode('send');
    const t2Input = new Uint8Array(t1.length + info.length + 1);
    t2Input.set(t1, 0); t2Input.set(info, t1.length); t2Input[t2Input.length - 1] = 0x02;
    expect(bytesToHex(okm.slice(32))).toBe(bytesToHex(await hmacSha256(prk, t2Input)));
  });

  it('AES-256-CBC decrypts what WebCrypto encrypts', async () => {
    const key = hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
    const iv = hexToBytes('0102030405060708090a0b0c0d0e0f10');
    const subtleKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
    const plaintext = utf8ToBytes('Hello, AES-CBC!');
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, subtleKey, plaintext as BufferSource));
    const out = await aesCbc256Decrypt(key, iv, ct);
    expect(bytesToHex(out)).toBe(bytesToHex(plaintext));
  });

  it('aesCbc256Encrypt round-trips through aesCbc256Decrypt', async () => {
    const key = hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
    const iv = hexToBytes('0102030405060708090a0b0c0d0e0f10');
    const plaintext = utf8ToBytes('round-trip me');
    const ct = await aesCbc256Encrypt(key, iv, plaintext);
    expect(bytesToHex(await aesCbc256Decrypt(key, iv, ct))).toBe(bytesToHex(plaintext));
  });

  it('RSA-OAEP-SHA1 decrypts what WebCrypto encrypted (round-trip vector)', async () => {
    const pkcs8 = base64ToBytes(RSA_VECTOR.privateKeyPkcs8B64);
    const ct = base64ToBytes(RSA_VECTOR.encType4EncString.slice(2));
    const out = await rsaOaepDecrypt(pkcs8, ct);
    expect(bytesToUtf8(out)).toBe(RSA_VECTOR.plaintext);
  });

  it('RSA-OAEP-SHA256 decrypts an encType=3 wrapped key when given the SHA-256 hash', async () => {
    const pkcs8 = base64ToBytes(RSA_VECTOR.privateKeyPkcs8B64);
    const ct = base64ToBytes(ORG_KEY_VECTOR.encOrgKeySha256.slice(2));
    const out = await rsaOaepDecrypt(pkcs8, ct, 'SHA-256');
    expect(bytesToHex(out)).toBe(ORG_KEY_VECTOR.orgKeyHex);
  });

  it('rsaOaepEncrypt round-trips through rsaOaepDecrypt with the matching private key', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt'],
    );
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const data = hexToBytes('00112233445566778899aabbccddeeff');
    const ct = await rsaOaepEncrypt(spki, data);
    expect(bytesToHex(await rsaOaepDecrypt(pkcs8, ct))).toBe(bytesToHex(data));
  });
});
