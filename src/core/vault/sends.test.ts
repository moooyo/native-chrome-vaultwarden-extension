import { describe, it, expect } from 'vitest';
import { buildTextSendRequest, decryptSend, deriveSendKey, deriveShareableKey, hashSendPassword, buildSendAccessUrl, buildFileSendRequest, buildUpdateSendRequest } from './sends.js';
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
    const summary = await decryptSend({ ...existing, ...req } as unknown as SendResponse, userKey, 'http://x');
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
});
