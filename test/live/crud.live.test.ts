// Live end-to-end test against the disposable test Vaultwarden server documented in CLAUDE.md.
// Skipped by default; run with: LIVE=1 npx vitest run test/live/crud.live.test.ts
// Exercises the real server contract: login -> create -> sync -> decrypt -> update -> delete.
import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey } from '../../src/core/crypto/keys.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import { decryptCipher } from '../../src/core/vault/decrypt.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = 'http://10.0.1.20:8080';
const EMAIL = 'test@winvaultwarden.local';
const PASSWORD = 'Test-Master-Password-1!';

const LIVE = Boolean(process.env.LIVE);

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return {
    get: async <T>(k: string) => m.get(k) as T | undefined,
    set: async (k: string, v: unknown) => { m.set(k, v); },
    remove: async (k: string) => { m.delete(k); },
  } as KeyValueStore;
}

(LIVE ? describe : describe.skip)('live cipher CRUD against the test server', () => {
  it('logs in, creates, updates, and deletes a cipher with full round-trip', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });

    const pre = await api.prelogin(EMAIL);
    const masterKey = await deriveMasterKey(PASSWORD, EMAIL, pre.kdfIterations);
    const hash = await deriveMasterPasswordHash(masterKey, PASSWORD);
    const login = await api.passwordLogin({ email: EMAIL, masterPasswordHash: hash });
    expect(login.kind).toBe('success');
    if (login.kind !== 'success') return;
    const token = login.data.access_token;
    const stretched = await stretchMasterKey(masterKey);
    const userKey = await unwrapSymmetricKey(login.data.Key, stretched);

    const marker = `CRUD-${Date.now()}`;
    // CREATE
    await api.createCipher(token, await encryptCipher({
      type: 1, name: marker, login: { username: 'octo', password: 'p@ssw0rd!', uris: [{ uri: 'https://example.com' }] },
    }, userKey));

    let sync = await api.sync(token);
    const created = (await Promise.all(sync.ciphers.map(async (c) => ({ c, d: await decryptCipher(c, userKey) }))))
      .find((x) => x.d?.name === marker);
    expect(created, 'created cipher found in sync').toBeTruthy();
    expect(created!.d).toMatchObject({ name: marker, username: 'octo', password: 'p@ssw0rd!', uris: ['https://example.com'] });
    const id = created!.c.id;

    // UPDATE
    await api.updateCipher(token, id, await encryptCipher({
      type: 1, name: `${marker}-renamed`, login: { username: 'octo', password: 'new-p@ss' },
    }, userKey));
    sync = await api.sync(token);
    const row = sync.ciphers.find((c) => c.id === id);
    expect(row).toBeTruthy();
    expect((await decryptCipher(row!, userKey))).toMatchObject({ name: `${marker}-renamed`, password: 'new-p@ss' });

    // DELETE
    await api.deleteCipher(token, id);
    sync = await api.sync(token);
    expect(sync.ciphers.find((c) => c.id === id)).toBeUndefined();
  }, 30_000);
});
