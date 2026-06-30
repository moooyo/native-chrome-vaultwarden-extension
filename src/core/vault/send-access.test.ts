import { describe, it, expect } from 'vitest';
import { parseSendUrl, decryptAccessedSend, sendPasswordHash } from './send-access.js';
import { deriveSendKey } from './sends.js';
import { encryptToText } from '../crypto/encstring.js';
import { bytesToBase64Url } from '../crypto/encoding.js';

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
