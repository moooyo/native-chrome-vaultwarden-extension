import { describe, it, expect } from 'vitest';
import {
  SEND_DATE_PRESET_HOURS,
  buildTextSendRequest,
  decryptSend,
  deriveSendKey,
  deriveShareableKey,
  hashSendPassword,
  buildSendAccessUrl,
  buildFileSendRequest,
  buildUpdateSendRequest,
} from './sends.js';
import { decryptAttachmentFile } from './attachments.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { bytesToBase64, bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import type { SendResponse } from '../api/types.js';

// Cross-implementation known-answer vectors: Bitwarden SDK `derive_shareable_key`
// (bitwarden-crypto/src/keys/shareable_key.rs #[test] test_derive_shareable_key). The algorithm is
// PRK = HMAC-SHA256(key="bitwarden-"+name, msg=secret[16]); then HKDF-Expand(PRK, info, 64) = enc‖mac.
// SymmetricCryptoKey::to_base64() is standard base64 of the 64-byte enc‖mac buffer.
function serialize64(k: { encKey: Uint8Array; macKey: Uint8Array }): string {
  const raw = new Uint8Array(64);
  raw.set(k.encKey, 0);
  raw.set(k.macKey, 32);
  return bytesToBase64(raw);
}

describe('deriveShareableKey (Bitwarden derive_shareable_key parity)', () => {
  it('matches the SDK vector with info = None', async () => {
    const key = await deriveShareableKey(utf8ToBytes('&/$%F1a895g67HlX'), 'test_key');
    expect(serialize64(key)).toBe(
      '4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ==',
    );
  });

  it('matches the SDK vector with info = "test"', async () => {
    const key = await deriveShareableKey(utf8ToBytes('67t9b5g67$%Dh89n'), 'test_key', 'test');
    expect(serialize64(key)).toBe(
      'F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng==',
    );
  });

  it('deriveSendKey is derive_shareable_key(sendKey, "send", "send")', async () => {
    const sendKey = new Uint8Array(16).fill(1);
    const a = await deriveSendKey(sendKey);
    const b = await deriveShareableKey(sendKey, 'send', 'send');
    expect(serialize64(a)).toBe(serialize64(b));
  });
});

const userKey = symmetricKeyFromBytes(new Uint8Array(64).map((_, i) => (i * 7) & 0xff));
const deps = { randomBytes: (n: number) => new Uint8Array(n).fill(0x2a), now: () => 1_700_000_000_000 };

describe('sends crypto', () => {
  it('build → decrypt round-trips name/text and yields a share URL carrying the send key', async () => {
    const { request, sendKey } = await buildTextSendRequest(
      { name: 'My Secret', notes: 'private note', text: 'hello world', hidden: true, hideEmail: true, deletionDays: 7 }, userKey, deps);
    expect(request.type).toBe(0);
    expect(request.name.startsWith('2.')).toBe(true);
    expect(request.text?.hidden).toBe(true);
    expect(request.hideEmail).toBe(true);
    expect(JSON.stringify(request)).not.toContain('hello world'); // payload is encrypted

    const response = { id: 's1', accessId: 'acc1', ...request } as unknown as SendResponse;
    const summary = await decryptSend(response, userKey, 'https://vault.example/');
    expect(summary.name).toBe('My Secret');
    expect(summary.text).toBe('hello world');
    expect(summary.notes).toBe('private note');
    expect(summary.hidden).toBe(true);
    expect(summary.hideEmail).toBe(true);
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

  it('defaults hideEmail to false and rejects malformed runtime values', async () => {
    const { request } = await buildTextSendRequest(
      { name: 'x', text: 't', deletionDays: 1 },
      userKey,
      deps,
    );
    expect(request.hideEmail).toBe(false);
    await expect(buildTextSendRequest(
      { name: 'x', text: 't', deletionDays: 1, hideEmail: 'true' } as unknown as Parameters<typeof buildTextSendRequest>[0],
      userKey,
      deps,
    )).rejects.toThrow(/hideEmail must be a boolean/u);
  });

  it('uses one exact elapsed hour for the one-hour deletion and expiration preset', async () => {
    let nowCalls = 0;
    const baseTime = Date.parse('2026-11-01T05:30:00.000Z');
    const { request } = await buildTextSendRequest(
      { name: 'x', text: 't', deletionHours: 1, expirationHours: 1 },
      userKey,
      { ...deps, now: () => baseTime + nowCalls++ * 1_000 },
    );

    const expected = '2026-11-01T06:30:00.000Z';
    expect(request.deletionDate).toBe(expected);
    expect(request.expirationDate).toBe(expected);
    expect(request).not.toHaveProperty('deletionHours');
    expect(request).not.toHaveProperty('expirationHours');
    expect(nowCalls).toBe(1);
  });

  it.each([1, 2, 3, 7, 14, 30])('keeps the legacy %i-day preset wire-compatible', async (days) => {
    const { request } = await buildTextSendRequest(
      { name: 'x', text: 't', deletionDays: days, expirationDays: days },
      userKey,
      deps,
    );
    const expected = new Date(1_700_000_000_000 + days * 86_400_000).toISOString();
    expect(request.deletionDate).toBe(expected);
    expect(request.expirationDate).toBe(expected);
  });

  it('publishes the complete browser-v2026.8.0 hour preset set', () => {
    expect(Object.values(SEND_DATE_PRESET_HOURS)).toEqual([1, 24, 48, 72, 168, 336, 720]);
  });

  it('rejects ambiguous or fractional hour durations', async () => {
    await expect(buildTextSendRequest(
      { name: 'x', deletionHours: 1, deletionDays: 1 },
      userKey,
      deps,
    )).rejects.toThrow(/hours or legacy days/u);
    await expect(buildTextSendRequest(
      { name: 'x', deletionHours: 1.5 },
      userKey,
      deps,
    )).rejects.toThrow(/integer/u);
    await expect(buildTextSendRequest(
      { name: 'x', deletionHours: 745 },
      userKey,
      deps,
    )).rejects.toThrow(/between 1 and 744/u);
  });

  it('rejects an expiration date later than deletion but permits equality', async () => {
    await expect(buildTextSendRequest(
      { name: 'x', deletionHours: 1, expirationHours: 24 },
      userKey,
      deps,
    )).rejects.toThrow(/must not be later/u);
    await expect(buildTextSendRequest(
      { name: 'x', deletionHours: 1, expirationHours: 1 },
      userKey,
      deps,
    )).resolves.toMatchObject({
      request: {
        deletionDate: new Date(1_700_000_000_000 + 3_600_000).toISOString(),
        expirationDate: new Date(1_700_000_000_000 + 3_600_000).toISOString(),
      },
    });
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
    const key = new Uint8Array(16).fill(1);
    expect(buildSendAccessUrl('https://v.example', 'a', key)).toBe(`https://v.example/#/send/a/${bytesToBase64Url(key)}`);
    expect(buildSendAccessUrl('https://v.example/', 'a', key)).toBe(`https://v.example/#/send/a/${bytesToBase64Url(key)}`);
    expect(buildSendAccessUrl('https://v.example/base//', 'a', key)).toBe(`https://v.example/base/#/send/a/${bytesToBase64Url(key)}`);
  });

  it('buildSendAccessUrl rejects unsafe bases and malformed route material', () => {
    const key = new Uint8Array(16).fill(1);
    expect(() => buildSendAccessUrl('http://remote.example', 'a', key)).toThrow();
    expect(() => buildSendAccessUrl('http://dev.localhost', 'a', key)).toThrow();
    expect(() => buildSendAccessUrl('https://user@v.example', 'a', key)).toThrow();
    expect(() => buildSendAccessUrl('https://v.example/base?tenant=one', 'a', key)).toThrow();
    expect(() => buildSendAccessUrl('https:////v.example/base', 'a', key)).toThrow();
    expect(() => buildSendAccessUrl('https://v.example/base/../other', 'a', key)).toThrow();
    expect(() => buildSendAccessUrl('https://v.example/base/%2e%2e/other', 'a', key)).toThrow();
    expect(buildSendAccessUrl('https://v.example', '../escape', key)).toContain('/send/..%2Fescape/');
    expect(() => buildSendAccessUrl('https://v.example', 'a', new Uint8Array(15))).toThrow();
    expect(buildSendAccessUrl('http://127.0.0.1:8080/base', 'a-b_c', key))
      .toBe(`http://127.0.0.1:8080/base/#/send/a-b_c/${bytesToBase64Url(key)}`);
  });
});

describe('file send', () => {
  const fileDeps = { randomBytes: (n: number) => new Uint8Array(n).fill(9), now: () => 0 };

  it('builds a type=1 request, encrypts the file (EncArrayBuffer round-trip) and file name', async () => {
    const fileBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const { request, sendKey, encryptedFile, encryptedFileName } = await buildFileSendRequest(
      { name: 'Doc', hideEmail: true, deletionDays: 7 }, 'secret.pdf', fileBytes, userKey, fileDeps);
    expect(request.type).toBe(1);
    expect(request.hideEmail).toBe(true);
    expect(request.file?.fileName).toBe(encryptedFileName);
    expect(request.fileLength).toBe(encryptedFile.length);
    // the encrypted blob round-trips back to the original bytes under the derived send key
    const derived = await deriveSendKey(sendKey);
    expect(Array.from(await decryptAttachmentFile(encryptedFile, derived))).toEqual([1, 2, 3, 4, 5]);
  });

  it('builds a file Send with exact one-hour deletion and expiration dates', async () => {
    const { request } = await buildFileSendRequest(
      { name: 'Doc', deletionHours: 1, expirationHours: 1 },
      'secret.pdf',
      new Uint8Array([1]),
      userKey,
      fileDeps,
    );
    expect(request.deletionDate).toBe(new Date(3_600_000).toISOString());
    expect(request.expirationDate).toBe(new Date(3_600_000).toISOString());
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

describe('buildUpdateSendRequest', () => {
  const fileDeps = { randomBytes: (n: number) => new Uint8Array(n).fill(9), now: () => 0 };

  async function makeExisting(): Promise<SendResponse> {
    const { request } = await buildTextSendRequest({ name: 'Orig', text: 'orig', deletionDays: 7, password: 'pw' }, userKey, fileDeps);
    // SendResponse echoes the create request + server fields (password is the SERVER hash; here a placeholder).
    return { id: 's1', accessId: 'a1', type: 0, name: request.name, key: request.key, text: request.text,
      deletionDate: request.deletionDate, password: 'SERVER_HASH', accessCount: 0 } as unknown as SendResponse;
  }

  it('re-encrypts name + text under the existing send key, keeping key unchanged', async () => {
    const existing = await makeExisting();
    const req = await buildUpdateSendRequest(existing, { name: 'New', text: 'new text', passwordMode: 'keep' }, userKey, fileDeps);
    expect(req.key).toBe(existing.key);              // send key unchanged
    expect(req.password).toBeUndefined();            // keep → omit password
    // round-trip the new name/text by decrypting the resulting SendResponse
    const summary = await decryptSend({ ...existing, ...req } as unknown as SendResponse, userKey, 'https://x');
    expect(summary.name).toBe('New');
    expect(summary.text).toBe('new text');
  });

  it('set password uses a fresh client hash; remove omits password (handled separately)', async () => {
    const existing = await makeExisting();
    const setReq = await buildUpdateSendRequest(existing, { name: 'N', text: 't', passwordMode: 'set', newPassword: 'np' }, userKey, fileDeps);
    expect(typeof setReq.password).toBe('string');
    expect(setReq.password).not.toBe('SERVER_HASH');  // not the stored hash
    const rmReq = await buildUpdateSendRequest(existing, { name: 'N', text: 't', passwordMode: 'remove' }, userKey, fileDeps);
    expect(rmReq.password).toBeUndefined();           // remove → omit (vault-service calls removeSendPassword)
  });

  it('keeps the file name + key for a file send (file not re-uploaded), and keeps dates when days blank', async () => {
    const f = await buildFileSendRequest({ name: 'F', deletionDays: 7 }, 'doc.pdf', new Uint8Array([1]), userKey, fileDeps);
    const existing = { id: 's2', accessId: 'a2', type: 1, name: f.request.name, key: f.request.key,
      file: { fileName: f.request.file!.fileName, id: 'fid', sizeName: '1 B' }, deletionDate: f.request.deletionDate,
      expirationDate: null, accessCount: 0 } as unknown as SendResponse;
    const req = await buildUpdateSendRequest(existing, { name: 'F2', passwordMode: 'keep' }, userKey, fileDeps);
    expect(req.type).toBe(1);
    expect(req.file?.fileName).toBe(existing.file!.fileName);  // file name unchanged
    expect(req.deletionDate).toBe(existing.deletionDate);      // days blank → keep date
  });

  it('resets deletion and expiration by one exact elapsed hour from one captured time', async () => {
    const existing = await makeExisting();
    const req = await buildUpdateSendRequest(
      existing,
      { name: 'N', text: 't', deletionHours: 1, expirationHours: 1 },
      userKey,
      fileDeps,
    );
    expect(req.deletionDate).toBe(new Date(3_600_000).toISOString());
    expect(req.expirationDate).toBe(new Date(3_600_000).toISOString());
  });

  it('validates final update dates while preserving omitted server dates', async () => {
    const existing = {
      ...(await makeExisting()),
      deletionDate: new Date(7_200_000).toISOString(),
      expirationDate: new Date(3_600_000).toISOString(),
    } as SendResponse;
    const preserved = await buildUpdateSendRequest(
      existing,
      { name: 'N', text: 't' },
      userKey,
      fileDeps,
    );
    expect(preserved.deletionDate).toBe(existing.deletionDate);
    expect(preserved.expirationDate).toBe(existing.expirationDate);

    await expect(buildUpdateSendRequest(
      existing,
      { name: 'N', text: 't', expirationHours: 3 },
      userKey,
      fileDeps,
    )).rejects.toThrow(/must not be later/u);
  });

  it('preserves the existing disabled state when the input omits it', async () => {
    const existing = { ...(await makeExisting()), disabled: true } as SendResponse;
    const req = await buildUpdateSendRequest(existing, { name: 'N', text: 't', passwordMode: 'keep' }, userKey, fileDeps);
    expect(req.disabled).toBe(true); // omitted input.disabled must not silently re-publish the send
  });

  it('lets the input override the disabled state when provided', async () => {
    const existing = { ...(await makeExisting()), disabled: true } as SendResponse;
    const req = await buildUpdateSendRequest(existing, { name: 'N', text: 't', disabled: false, passwordMode: 'keep' }, userKey, fileDeps);
    expect(req.disabled).toBe(false);
  });

  it('preserves hideEmail when omitted and applies an explicit boolean override', async () => {
    const existing = { ...(await makeExisting()), hideEmail: true } as SendResponse;
    const preserved = await buildUpdateSendRequest(
      existing,
      { name: 'N', text: 't' },
      userKey,
      fileDeps,
    );
    expect(preserved.hideEmail).toBe(true);

    const visible = await buildUpdateSendRequest(
      existing,
      { name: 'N', text: 't', hideEmail: false },
      userKey,
      fileDeps,
    );
    expect(visible.hideEmail).toBe(false);
  });

  it('preserves encrypted notes and modern auth fields when notes are not edited', async () => {
    const { request } = await buildTextSendRequest(
      { name: 'Orig', notes: 'private note', text: 'orig', deletionDays: 7 },
      userKey,
      fileDeps,
    );
    const existing = {
      id: 's-notes',
      accessId: 'a-notes',
      ...request,
      accessCount: 0,
      authType: 2,
      emails: null,
    } as SendResponse;

    const preserved = await buildUpdateSendRequest(
      existing,
      { name: 'Renamed', text: 'updated', passwordMode: 'keep' },
      userKey,
      fileDeps,
    );

    expect(preserved.notes).toBe(existing.notes);
    expect(preserved.authType).toBe(2);
    expect(preserved.emails).toBeNull();
    await expect(decryptSend(
      { ...existing, ...preserved },
      userKey,
      'https://vault.example',
    )).resolves.toMatchObject({ notes: 'private note' });
  });

  it('re-encrypts changed notes, clears them explicitly, and marks a failed decrypt as unavailable', async () => {
    const existing = await makeExisting();
    const changed = await buildUpdateSendRequest(
      existing,
      { name: 'N', text: 't', notes: 'changed note' },
      userKey,
      fileDeps,
    );
    expect(changed.notes).not.toBe(existing.notes);
    await expect(decryptSend(
      { ...existing, ...changed },
      userKey,
      'https://vault.example',
    )).resolves.toMatchObject({ notes: 'changed note' });

    const cleared = await buildUpdateSendRequest(existing, { name: 'N', notes: '' }, userKey, fileDeps);
    expect(cleared.notes).toBeNull();
    await expect(decryptSend(
      { ...existing, notes: '2.invalid|invalid|invalid' },
      userKey,
      'https://vault.example',
    )).resolves.toMatchObject({ notesUnavailable: true });
  });
});
