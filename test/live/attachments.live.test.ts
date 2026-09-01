// Live attachment v2 contract test against a disposable account on the configured test server.
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient } from '../../src/core/api/client.js';
import { bytesToBase64 } from '../../src/core/crypto/encoding.js';
import { encryptToText } from '../../src/core/crypto/encstring.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey } from '../../src/core/crypto/keys.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import {
  decryptAttachmentFile,
  decryptAttachmentKey,
  encryptAttachmentFile,
  generateAttachmentKey,
  wrapAttachmentKey,
} from '../../src/core/vault/attachments.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = process.env.MIYU_SERVER || 'http://localhost:8080';
const LIVE = process.env.LIVE === '1';

function memoryStore(): KeyValueStore {
  const values = new Map<string, unknown>();
  return {
    get: async <T>(key: string) => values.get(key) as T | undefined,
    set: async (key: string, value: unknown) => { values.set(key, value); },
    remove: async (key: string) => { values.delete(key); },
    clear: async () => { values.clear(); },
  };
}

async function deleteAccount(accessToken: string, masterPasswordHash: string): Promise<void> {
  try {
    await fetch(`${SERVER}/api/accounts`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ masterPasswordHash }),
    });
  } catch {
    // Cleanup must not replace the protocol assertion that failed.
  }
}

(LIVE ? describe : describe.skip)('live attachment v2 against the test server', () => {
  it('allocates, uploads, downloads, decrypts, and deletes a Direct attachment', async () => {
    const api = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: fetch,
      localStore: memoryStore(),
    });
    const email = `attachment-${Date.now()}@example.com`;
    const password = 'Attachment-Live-Test-1!';
    let accessToken: string | undefined;
    let masterPasswordHash: string | undefined;
    let cipherId: string | undefined;
    let attachmentId: string | undefined;

    try {
      const registration = await buildRegistration(email, password);
      const started = await api.startRegistration({ email, name: 'Attachment Live Test' });
      if (started.kind === 'email_required') {
        throw new Error('test server requires email verification; no inline token is available');
      }
      const emailVerificationToken = started.kind === 'inline'
        ? started.emailVerificationToken
        : undefined;
      await api.register({
        ...registration,
        masterPasswordHint: '',
        email,
        name: 'Attachment Live Test',
        ...(emailVerificationToken ? { emailVerificationToken } : {}),
      });

      const prelogin = await api.prelogin(email);
      const masterKey = await deriveMasterKey(password, email, prelogin);
      masterPasswordHash = await deriveMasterPasswordHash(masterKey, password);
      const login = await api.passwordLogin({ email, masterPasswordHash });
      expect(login.kind).toBe('success');
      if (login.kind !== 'success') return;
      accessToken = login.data.access_token;
      const userKey = await unwrapSymmetricKey(login.data.Key, await stretchMasterKey(masterKey));

      const created = await api.createCipher(accessToken, await encryptCipher({
        type: 1,
        name: 'Attachment v2 live item',
        login: { username: 'attachment-live' },
      }, userKey));
      cipherId = created.id;

      const plaintext = new TextEncoder().encode('attachment-v2-live-payload');
      const attachmentKey = generateAttachmentKey();
      const wrappedKey = await wrapAttachmentKey(attachmentKey, userKey);
      const encryptedFileName = await encryptToText('live.txt', userKey);
      const encrypted = await encryptAttachmentFile(plaintext, attachmentKey);
      const slot = await api.createAttachmentUploadSlot(accessToken, cipherId, {
        key: wrappedKey,
        fileName: encryptedFileName,
        fileSize: encrypted.byteLength,
        adminRequest: false,
        lastKnownRevisionDate: created.revisionDate ?? null,
      });
      attachmentId = slot.attachmentId;
      expect(slot.fileUploadType).toBe(0);

      await api.uploadAttachmentSlotData(
        accessToken,
        cipherId,
        slot,
        encryptedFileName,
        encrypted,
      );
      const synced = await api.sync(accessToken);
      const attachment = synced.ciphers
        .find((cipher) => cipher.id === cipherId)
        ?.attachments?.find((entry) => entry.id === attachmentId);
      expect(attachment).toMatchObject({
        id: attachmentId,
        key: wrappedKey,
        fileName: encryptedFileName,
        size: String(encrypted.byteLength),
      });

      const downloadUrl = await api.getAttachmentDownloadUrl(
        accessToken,
        cipherId,
        attachmentId,
      );
      const downloaded = await api.downloadAttachment(downloadUrl, accessToken);
      const downloadedKey = await decryptAttachmentKey(attachment!.key!, userKey);
      const roundTrip = await decryptAttachmentFile(downloaded, downloadedKey);
      expect(bytesToBase64(roundTrip)).toBe(bytesToBase64(plaintext));

      await api.deleteAttachment(accessToken, cipherId, attachmentId);
      attachmentId = undefined;
      const afterDelete = await api.sync(accessToken);
      expect(afterDelete.ciphers.find((cipher) => cipher.id === cipherId)?.attachments ?? [])
        .toHaveLength(0);

      plaintext.fill(0);
      encrypted.fill(0);
      downloaded.fill(0);
      roundTrip.fill(0);
      attachmentKey.encKey.fill(0);
      attachmentKey.macKey.fill(0);
      downloadedKey.encKey.fill(0);
      downloadedKey.macKey.fill(0);
      userKey.encKey.fill(0);
      userKey.macKey.fill(0);
    } finally {
      if (accessToken && cipherId && attachmentId) {
        try { await api.deleteAttachment(accessToken, cipherId, attachmentId); } catch { /* best effort */ }
      }
      if (accessToken && cipherId) {
        try { await api.deleteCipher(accessToken, cipherId); } catch { /* best effort */ }
      }
      if (accessToken && masterPasswordHash) {
        await deleteAccount(accessToken, masterPasswordHash);
      }
    }
  }, 60_000);
});
