import { describe, it, expect } from 'vitest';
import { parseSendUrl, decryptAccessedSend, sendPasswordHash, accessSend, requestFileDownloadUrl, downloadAndDecryptFile } from './send-access.js';
import { deriveSendKey } from './sends.js';
import { encryptToText } from '../crypto/encstring.js';
import { bytesToBase64Url } from '../crypto/encoding.js';
import { encryptAttachmentFile } from './attachments.js';

const sendKey = new Uint8Array(16).fill(7);

describe('parseSendUrl', () => {
  it('parses server, accessId and send key from a share link', () => {
    const link = `https://vault.example/#/send/AbC123/${bytesToBase64Url(sendKey)}`;
    const parsed = parseSendUrl(link);
    expect(parsed.serverUrl).toBe('https://vault.example');
    expect(parsed.accessId).toBe('AbC123');
    expect(Array.from(parsed.sendKey)).toEqual(Array.from(sendKey));
  });
  it('rejects a non-send or malformed link', () => {
    expect(() => parseSendUrl('https://vault.example/#/login')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl('not a url')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl('https://vault.example/#/send/acc/')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://#/send/acc/${bytesToBase64Url(sendKey)}`)).toThrowError(/invalid_link/);
  });
  it('rejects a key that is not 16 bytes', () => {
    expect(() => parseSendUrl(`https://vault.example/#/send/acc/${bytesToBase64Url(new Uint8Array(8))}`)).toThrowError(/invalid_link/);
  });
  it('throws an error carrying code invalid_link', () => {
    const err = (() => { try { parseSendUrl('nope'); return null; } catch (e) { return e as { code?: string }; } })();
    expect(err?.code).toBe('invalid_link');
  });
});

describe('decryptAccessedSend', () => {
  it('decrypts a text send name + text', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-1', type: 0, name: await encryptToText('Greeting', derived), text: { text: await encryptToText('hello', derived) } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out).toMatchObject({ id: 'send-1', type: 0, name: 'Greeting', text: 'hello' });
  });
  it('decrypts a file send name + file name, keeping fileId/sizeName', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-2', type: 1, name: await encryptToText('Doc', derived), file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out).toMatchObject({ id: 'send-2', type: 1, name: 'Doc', fileName: 'secret.pdf', fileId: 'f1', sizeName: '3 KB' });
    expect(out.text).toBeUndefined();
  });
  it('degrades an undecryptable field to a placeholder rather than throwing', async () => {
    const raw = { id: 'send-x', type: 0, name: 'not-a-valid-encstring', text: { text: 'also-bad' } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out.name).toBe('(undecryptable)');
    expect(out.text).toBe('(undecryptable)');
  });
});

describe('sendPasswordHash', () => {
  it('derives a stable base64 hash for a password + send key', async () => {
    const a = await sendPasswordHash('pw', sendKey);
    const b = await sendPasswordHash('pw', sendKey);
    expect(a).toBe(b);
    expect(a).not.toContain('pw');
  });
});

function jsonRes(body: unknown, status = 200): Response { return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }); }

describe('accessSend', () => {
  it('POSTs the accessId (anonymous) and returns the JSON; sends password hash when given', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchFn = (async (u: string, init: RequestInit) => { calls.push([String(u), init]); return jsonRes({ id: 'send-1', type: 0 }); }) as unknown as typeof fetch;
    const res = await accessSend(fetchFn, 'https://vault.example', 'acc1', 'HASH');
    expect(String(calls[0]![0])).toBe('https://vault.example/api/sends/access/acc1');
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({ password: 'HASH' });
    expect(res).toMatchObject({ id: 'send-1' });
  });
  it('maps 401 to password_required', async () => {
    const fetchFn = (async () => new Response('', { status: 401 })) as unknown as typeof fetch;
    await expect(accessSend(fetchFn, 'https://vault.example', 'acc1')).rejects.toMatchObject({ code: 'password_required' });
  });
});

describe('requestFileDownloadUrl', () => {
  it('POSTs to /api/sends/{sendId}/access/file/{fileId} and returns the url', async () => {
    const calls: string[] = [];
    const fetchFn = (async (u: string) => { calls.push(String(u)); return jsonRes({ url: 'http://abs/url?t=jwt' }); }) as unknown as typeof fetch;
    const url = await requestFileDownloadUrl(fetchFn, 'https://vault.example', 'send-1', 'f1');
    expect(calls[0]).toBe('https://vault.example/api/sends/send-1/access/file/f1');
    expect(url).toBe('http://abs/url?t=jwt');
  });
});

describe('downloadAndDecryptFile', () => {
  it('GETs the absolute url and decrypts the EncArrayBuffer with the send key', async () => {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([9, 8, 7]), derived);
    const fetchFn = (async (u: string) => { expect(String(u)).toBe('http://abs/url?t=jwt'); return new Response(Buffer.from(blob)); }) as unknown as typeof fetch;
    const back = await downloadAndDecryptFile(fetchFn, 'http://abs/url?t=jwt', 'https://vault.example', sendKey);
    expect(Array.from(back)).toEqual([9, 8, 7]);
  });
  it('throws decrypt_failed on a corrupt blob', async () => {
    const fetchFn = (async () => new Response(Buffer.from(new Uint8Array([2, 0, 0])))) as unknown as typeof fetch;
    await expect(downloadAndDecryptFile(fetchFn, 'http://abs/x', 'https://vault.example', sendKey)).rejects.toMatchObject({ code: 'decrypt_failed' });
  });
});

