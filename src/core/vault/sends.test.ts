import { describe, it, expect } from 'vitest';
import { buildTextSendRequest, decryptSend, deriveSendKey, hashSendPassword, buildSendAccessUrl, buildFileSendRequest } from './sends.js';
import { decryptAttachmentFile } from './attachments.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { bytesToBase64Url } from '../crypto/encoding.js';
import type { SendResponse } from '../api/types.js';

const userKey = symmetricKeyFromBytes(new Uint8Array(64).map((_, i) => (i * 7) & 0xff));
const deps = { randomBytes: (n: number) => new Uint8Array(n).fill(0x2a), now: () => 1_700_000_000_000 };

describe('sends crypto', () => {
  it('build → decrypt round-trips name/text and yields a share URL carrying the send key', async () => {
    const { request, sendKey } = await buildTextSendRequest(
      { name: 'My Secret', text: 'hello world', hidden: true, deletionDays: 7 }, userKey, deps);
    expect(request.type).toBe(0);
    expect(request.name.startsWith('2.')).toBe(true);
    expect(request.text?.hidden).toBe(true);
    expect(JSON.stringify(request)).not.toContain('hello world'); // payload is encrypted

    const response = { id: 's1', accessId: 'acc1', ...request } as unknown as SendResponse;
    const summary = await decryptSend(response, userKey, 'https://vault.example/');
    expect(summary.name).toBe('My Secret');
    expect(summary.text).toBe('hello world');
    expect(summary.hidden).toBe(true);
    expect(summary.url).toBe(`https://vault.example/#/send/acc1/${bytesToBase64Url(sendKey)}`);
    expect(summary.passwordProtected).toBe(false);
  });

  it('sets the deletion date and honors expiration / maxAccess / password options', async () => {
    const { request, sendKey } = await buildTextSendRequest(
      { name: 'x', text: 't', deletionDays: 3, expirationDays: 2, maxAccessCount: 5, password: 'pw' }, userKey, deps);
    expect(request.deletionDate).toBe(new Date(1_700_000_000_000 + 3 * 86_400_000).toISOString());
    expect(request.expirationDate).toBe(new Date(1_700_000_000_000 + 2 * 86_400_000).toISOString());
    expect(request.maxAccessCount).toBe(5);
    expect(request.password).toBe(await hashSendPassword('pw', sendKey));
  });

  it('clamps the deletion window to a sane range', async () => {
    const { request } = await buildTextSendRequest({ name: 'x', text: 't', deletionDays: 999 }, userKey, deps);
    expect(request.deletionDate).toBe(new Date(1_700_000_000_000 + 31 * 86_400_000).toISOString());
  });

  it('deriveSendKey returns a 64-byte (enc+mac) key', async () => {
    const k = await deriveSendKey(new Uint8Array(16).fill(1));
    expect(k.encKey.length).toBe(32);
    expect(k.macKey.length).toBe(32);
  });

  it('buildSendAccessUrl normalizes a trailing slash', () => {
    const key = new Uint8Array([1, 2, 3]);
    expect(buildSendAccessUrl('https://v.example', 'a', key)).toBe(`https://v.example/#/send/a/${bytesToBase64Url(key)}`);
    expect(buildSendAccessUrl('https://v.example/', 'a', key)).toBe(`https://v.example/#/send/a/${bytesToBase64Url(key)}`);
  });
});

describe('file send', () => {
  const fileDeps = { randomBytes: (n: number) => new Uint8Array(n).fill(9), now: () => 0 };

  it('builds a type=1 request, encrypts the file (EncArrayBuffer round-trip) and file name', async () => {
    const fileBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const { request, sendKey, encryptedFile, encryptedFileName } = await buildFileSendRequest(
      { name: 'Doc', deletionDays: 7 }, 'secret.pdf', fileBytes, userKey, fileDeps);
    expect(request.type).toBe(1);
    expect(request.file?.fileName).toBe(encryptedFileName);
    expect(request.fileLength).toBe(encryptedFile.length);
    // the encrypted blob round-trips back to the original bytes under the derived send key
    const derived = await deriveSendKey(sendKey);
    expect(Array.from(await decryptAttachmentFile(encryptedFile, derived))).toEqual([1, 2, 3, 4, 5]);
  });

  it('decryptSend surfaces the file name for a type=1 send', async () => {
    const { request } = await buildFileSendRequest(
      { name: 'Doc', deletionDays: 7 }, 'secret.pdf', new Uint8Array([1, 2, 3]), userKey, fileDeps);
    const resp = {
      id: 's1', accessId: 'acc1', type: 1, name: request.name, key: request.key,
      file: { id: 'f1', fileName: request.file!.fileName, size: '3', sizeName: '3 Bytes' },
      deletionDate: new Date(0).toISOString(), accessCount: 0,
    } as unknown as SendResponse;
    const summary = await decryptSend(resp, userKey, 'http://localhost:8080');
    expect(summary.type).toBe(1);
    expect(summary.fileName).toBe('secret.pdf');
    expect(summary.sizeName).toBe('3 Bytes');
  });

  it('does not surface file fields on a text (type=0) send', async () => {
    const { request } = await buildTextSendRequest(
      { name: 'T', text: 'hi', deletionDays: 7 }, userKey, fileDeps);
    const resp = {
      id: 's2', accessId: 'acc2', type: 0, name: request.name, key: request.key,
      text: request.text, file: { sizeName: '9 Bytes' }, // spurious file on a text send
      deletionDate: new Date(0).toISOString(), accessCount: 0,
    } as unknown as SendResponse;
    const summary = await decryptSend(resp, userKey, 'http://localhost:8080');
    expect(summary.type).toBe(0);
    expect(summary.fileName).toBeUndefined();
    expect(summary.sizeName).toBeUndefined();
  });
});
