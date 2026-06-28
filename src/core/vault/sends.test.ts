import { describe, it, expect } from 'vitest';
import { buildTextSendRequest, decryptSend, deriveSendKey, hashSendPassword, buildSendAccessUrl } from './sends.js';
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
