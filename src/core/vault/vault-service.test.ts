import { describe, it, expect, vi } from 'vitest';
import { VaultService } from './vault-service.js';

// webextension-polyfill is imported transitively by platform/store.ts at module
// level. Without this mock the import fails in the node (vitest) environment
// because the browser global `chrome` is absent. See store.test.ts for the
// same pattern used across the test suite.
vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));
import { createMemoryStore } from '../../platform/store.js';
import { SessionManager } from '../session/session-manager.js';
import type { ApiClient } from '../api/client.js';
import type { AuthService } from '../session/auth-service.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes } from '../crypto/encoding.js';
import { FIELD_VECTOR, USER_KEY_VECTOR } from '../../../test/vectors.js';
import type { SyncResponse } from '../api/types.js';

function makeSync(): SyncResponse {
  return {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'cipher-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: null,
      login: { username: FIELD_VECTOR.encString, password: FIELD_VECTOR.encString, uris: [{ uri: FIELD_VECTOR.encString }] },
    }],
  };
}

async function makeService(syncResponse = makeSync()) {
  const localStore = createMemoryStore();
  const sm = new SessionManager({ localStore, sessionStore: createMemoryStore() });
  await sm.saveUnlocked({
    email: 'u@example.com',
    accessToken: 'access',
    refreshToken: 'refresh',
    expiresAt: 999999,
    protectedKey: USER_KEY_VECTOR.akey,
    kdf: 0,
    kdfIterations: 1000,
    userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
  });
  const api = { sync: vi.fn(async () => syncResponse) } as unknown as ApiClient;
  const auth = { refreshIfNeeded: vi.fn(async () => {}) } as unknown as AuthService;
  return { service: new VaultService({ api, auth, session: sm, localStore }), api };
}

describe('VaultService', () => {
  it('syncs, caches encrypted response, and returns summaries without password', async () => {
    const { service, api } = await makeService();
    const list = await service.sync();
    expect(api.sync).toHaveBeenCalledWith('access');
    expect(list).toEqual([{ id: 'cipher-1', type: 1, favorite: false, name: FIELD_VECTOR.plaintext, username: FIELD_VECTOR.plaintext, uris: [FIELD_VECTOR.plaintext], loginUris: [{ uri: FIELD_VECTOR.plaintext }] }]);
  });

  it('getField decrypts the requested field on demand from encrypted cache', async () => {
    const { service } = await makeService();
    await service.sync();
    await expect(service.getField('cipher-1', 'password')).resolves.toBe(FIELD_VECTOR.plaintext);
  });

  it('marks undecryptable ciphers without failing the whole list', async () => {
    const bad = makeSync();
    bad.ciphers[0]!.name = '2.bad|bad|bad';
    const { service } = await makeService(bad);
    const list = await service.sync();
    expect(list).toEqual([{ id: 'cipher-1', type: 1, favorite: false, name: '(undecryptable)', uris: [], loginUris: [], undecryptable: true }]);
  });

  // Coverage-only: public method listItems() — not exercised by the sync test above.
  it('listItems returns [] before sync and cached summaries after sync without calling api.sync again', async () => {
    const { service, api } = await makeService();

    // Before any sync the cache is empty — listItems returns [].
    await expect(service.listItems()).resolves.toEqual([]);

    // After sync the summaries are cached.
    const synced = await service.sync();
    expect(api.sync).toHaveBeenCalledTimes(1);

    // listItems must return the cached summaries without calling api.sync a second time.
    const listed = await service.listItems();
    expect(listed).toEqual(synced);
    expect(api.sync).toHaveBeenCalledTimes(1);
  });

  // Coverage-only: public method clearCache() — removes cached data.
  it('clearCache removes cached summaries so listItems returns [] again', async () => {
    const { service } = await makeService();
    await service.sync();
    expect(await service.listItems()).not.toEqual([]);

    await service.clearCache();
    await expect(service.listItems()).resolves.toEqual([]);
  });

  it('clearCache removes vault cache so getField rejects with "vault is not synced"', async () => {
    const { service } = await makeService();
    await service.sync();
    await service.clearCache();
    await expect(service.getField('cipher-1', 'password')).rejects.toThrow('vault is not synced');
  });

  // Coverage for undecryptable-cipher path through getField: decryptCipher returns a
  // result where some fields may be undefined (e.g. when the cipher is undecryptable
  // the returned object has undecryptable:true and no password). getField should return
  // undefined rather than throwing in that case.
  it('getField returns undefined for a field that is not present on an undecryptable cipher', async () => {
    const bad = makeSync();
    bad.ciphers[0]!.name = '2.bad|bad|bad';
    const { service } = await makeService(bad);
    await service.sync();
    // password is undefined on an undecryptable cipher — should not throw.
    await expect(service.getField('cipher-1', 'password')).resolves.toBeUndefined();
  });
});
