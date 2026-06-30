// Live end-to-end for file Sends: create a file Send, then access + download it via the recipient path.
// Skipped unless LIVE=1. Run: LIVE=1 npx vitest run test/live/sends.live.test.ts
import { describe, it, expect, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey } from '../../src/core/crypto/keys.js';
import { buildFileSendRequest, buildTextSendRequest, buildUpdateSendRequest, hashSendPassword, buildSendAccessUrl } from '../../src/core/vault/sends.js';
import { parseSendUrl, accessSend, decryptAccessedSend, requestFileDownloadUrl, downloadAndDecryptFile } from '../../src/core/vault/send-access.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = 'http://10.0.1.20:8080';
const EMAIL = 'test@winvaultwarden.local';
const PASSWORD = 'Test-Master-Password-1!';
const LIVE = Boolean(process.env.LIVE);

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return { get: async <T>(k: string) => m.get(k) as T | undefined, set: async (k: string, v: unknown) => { m.set(k, v); }, remove: async (k: string) => { m.delete(k); } } as KeyValueStore;
}

(LIVE ? describe : describe.skip)('live file Send round-trip', () => {
  it('creates a file Send and receives it back via the access path', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const pre = await api.prelogin(EMAIL);
    const masterKey = await deriveMasterKey(PASSWORD, EMAIL, pre.kdfIterations);
    const login = await api.passwordLogin({ email: EMAIL, masterPasswordHash: await deriveMasterPasswordHash(masterKey, PASSWORD) });
    if (login.kind !== 'success') throw new Error('login failed');
    const token = login.data.access_token;
    const userKey = await unwrapSymmetricKey(login.data.Key, await stretchMasterKey(masterKey));

    const fileBytes = new Uint8Array([10, 20, 30, 40, 50]);
    const { request, sendKey, encryptedFile, encryptedFileName } = await buildFileSendRequest({ name: 'live', deletionDays: 1 }, 'live.bin', fileBytes, userKey);
    const created = await api.createSendFile(token, request);
    await api.uploadSendFileData(token, created.url, encryptedFile, encryptedFileName);

    // Recipient path: parse the share URL → access → download.
    const shareUrl = buildSendAccessUrl(SERVER, created.sendResponse.accessId, sendKey);
    const parsed = parseSendUrl(shareUrl);
    const raw = await accessSend(fetch, parsed.serverUrl, parsed.accessId);
    const send = await decryptAccessedSend(raw, parsed.sendKey);
    expect(send.type).toBe(1);
    expect(send.fileName).toBe('live.bin');
    const dl = await requestFileDownloadUrl(fetch, parsed.serverUrl, send.id, send.fileId!);
    const back = await downloadAndDecryptFile(fetch, dl, parsed.serverUrl, parsed.sendKey);
    expect(Array.from(back)).toEqual([10, 20, 30, 40, 50]);

    await api.deleteSend(token, created.sendResponse.id);
  }, 60_000);

  it('edits a text send: rename + keep password, then remove password', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const pre = await api.prelogin(EMAIL);
    const mk = await deriveMasterKey(PASSWORD, EMAIL, pre.kdfIterations);
    const login = await api.passwordLogin({ email: EMAIL, masterPasswordHash: await deriveMasterPasswordHash(mk, PASSWORD) });
    if (login.kind !== 'success') throw new Error('login failed');
    const token = login.data.access_token;
    const userKey = await unwrapSymmetricKey(login.data.Key, await stretchMasterKey(mk));

    const built = await buildTextSendRequest({ name: 'Before', text: 'before', deletionDays: 1, password: 'pw123' }, userKey);
    const created = await api.createSend(token, built.request);

    // EDIT: rename + new text, KEEP password (omit)
    const editReq = await buildUpdateSendRequest(created, { name: 'After', text: 'after', passwordMode: 'keep' }, userKey);
    await api.updateSend(token, created.id, editReq);

    // access with password → sees the new name/text
    const pwHash = await hashSendPassword('pw123', built.sendKey);
    const parsed = parseSendUrl(buildSendAccessUrl(SERVER, created.accessId, built.sendKey));
    const raw = await accessSend(fetch, parsed.serverUrl, parsed.accessId, pwHash);
    const send = await decryptAccessedSend(raw, parsed.sendKey);
    expect(send.name).toBe('After');
    expect(send.text).toBe('after');
    // access without password → rejected (still protected)
    await expect(accessSend(fetch, parsed.serverUrl, parsed.accessId)).rejects.toMatchObject({ code: 'password_required' });

    // REMOVE password
    await api.updateSend(token, created.id, await buildUpdateSendRequest(created, { name: 'After', text: 'after', passwordMode: 'remove' }, userKey));
    await api.removeSendPassword(token, created.id);
    const raw2 = await accessSend(fetch, parsed.serverUrl, parsed.accessId);  // no password now
    expect((await decryptAccessedSend(raw2, parsed.sendKey)).name).toBe('After');

    await api.deleteSend(token, created.id);
  }, 60_000);
});
