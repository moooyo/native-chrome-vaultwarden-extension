import { describe, it, expect } from 'vitest';
import { encryptAttachmentFile, decryptAttachmentFile, generateAttachmentKey, wrapAttachmentKey, decryptAttachmentKey } from './attachments.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';

const cipherKey = symmetricKeyFromBytes(new Uint8Array(64).fill(7));
const fixedKey = (fill: number) => generateAttachmentKey(() => new Uint8Array(64).fill(fill));

describe('attachment crypto', () => {
  it('round-trips file bytes through encrypt/decrypt (EncArrayBuffer encType=2)', async () => {
    const att = fixedKey(9);
    const data = new TextEncoder().encode('hello attachment 📎 with bytes');
    const blob = await encryptAttachmentFile(data, att);
    expect(blob[0]).toBe(2); // encType marker
    expect(await decryptAttachmentFile(blob, att)).toEqual(data);
  });

  it('round-trips a multi-AES-block payload (subarray views over the blob, not copies)', async () => {
    const att = fixedKey(5);
    // 200 bytes spans several 16-byte AES-CBC blocks, exercising the ciphertext subarray path.
    const data = new Uint8Array(200).map((_, i) => (i * 7) & 0xff);
    const blob = await encryptAttachmentFile(data, att);
    expect(await decryptAttachmentFile(blob, att)).toEqual(data);
  });

  it('rejects a tampered blob (MAC failure)', async () => {
    const att = fixedKey(9);
    const blob = await encryptAttachmentFile(new Uint8Array([1, 2, 3, 4]), att);
    const last = blob.length - 1;
    blob[last] = blob[last]! ^ 0xff;
    await expect(decryptAttachmentFile(blob, att)).rejects.toThrow(/MAC/);
  });

  it('rejects an unsupported encType byte', async () => {
    const att = fixedKey(9);
    const blob = await encryptAttachmentFile(new Uint8Array([1]), att);
    blob[0] = 0;
    await expect(decryptAttachmentFile(blob, att)).rejects.toThrow(/encType/);
  });

  it('wraps and unwraps the attachment key under the cipher key', async () => {
    const att = fixedKey(3);
    const wrapped = await wrapAttachmentKey(att, cipherKey);
    const unwrapped = await decryptAttachmentKey(wrapped, cipherKey);
    expect(unwrapped.encKey).toEqual(att.encKey);
    expect(unwrapped.macKey).toEqual(att.macKey);
  });

  it('generateAttachmentKey yields a 64-byte (enc+mac) key', () => {
    const att = generateAttachmentKey();
    expect(att.encKey.length).toBe(32);
    expect(att.macKey.length).toBe(32);
  });
});
