import { describe, it, expect } from 'vitest';
import { rewrapEncString, isEncString, rewrapDeep } from './rotate-crypto.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { encryptToText, decryptToBytes } from '../crypto/encstring.js';

const keyA = symmetricKeyFromBytes(new Uint8Array(64).fill(1));
const keyB = symmetricKeyFromBytes(new Uint8Array(64).fill(2));
const dec = new TextDecoder();

describe('isEncString', () => {
  it('recognizes EncStrings and rejects UUIDs/numbers/dates', () => {
    expect(isEncString('2.aQ==|Yg==|Yw==')).toBe(true);
    expect(isEncString('3.abcDEF+/=')).toBe(true);
    expect(isEncString('30b56400-e5a6-4901-b512-581293d1d43a')).toBe(false);
    expect(isEncString('600000')).toBe(false);
    expect(isEncString('2026-07-02T02:00:00Z')).toBe(false);
    expect(isEncString(5)).toBe(false);
  });
});

describe('rewrapEncString', () => {
  it('re-wraps ciphertext to a new key preserving plaintext', async () => {
    const enc = await encryptToText('hello secret', keyA);
    const rewrapped = await rewrapEncString(enc, keyA, keyB);
    expect(rewrapped).not.toBe(enc);
    expect(dec.decode(await decryptToBytes(rewrapped, keyB))).toBe('hello secret');
    await expect(decryptToBytes(rewrapped, keyA)).rejects.toBeTruthy(); // old key no longer works
  });
  it('throws when the input cannot be decrypted with the old key', async () => {
    const enc = await encryptToText('x', keyA);
    await expect(rewrapEncString(enc, keyB, keyA)).rejects.toBeTruthy();
  });
});

describe('rewrapDeep', () => {
  it('re-wraps every EncString leaf and leaves other values intact', async () => {
    const obj = { id: 'u-1', type: 1, name: await encryptToText('n', keyA), nested: { note: await encryptToText('note', keyA), count: 3 }, arr: [await encryptToText('a', keyA), 'plain'] };
    const out = await rewrapDeep(obj, keyA, keyB) as typeof obj;
    expect(out.id).toBe('u-1'); expect(out.type).toBe(1); expect(out.nested.count).toBe(3); expect(out.arr[1]).toBe('plain');
    expect(dec.decode(await decryptToBytes(out.name, keyB))).toBe('n');
    expect(dec.decode(await decryptToBytes(out.nested.note, keyB))).toBe('note');
    expect(dec.decode(await decryptToBytes(out.arr[0] as string, keyB))).toBe('a');
  });
});
