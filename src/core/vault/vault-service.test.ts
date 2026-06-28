import { describe, it, expect, vi } from 'vitest';
import { VaultService } from './vault-service.js';
import { UriMatchStrategy } from './uri-match.js';

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
import { FIELD_VECTOR, URL_VECTOR, USER_KEY_VECTOR } from '../../../test/vectors.js';
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

function makeSyncUrl(): SyncResponse {
  return {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'cipher-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: null,
      login: { username: FIELD_VECTOR.encString, password: FIELD_VECTOR.encString, uris: [{ uri: URL_VECTOR.encString }] },
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
  return { service: new VaultService({ api, auth, session: sm, localStore }), api, session: sm };
}

describe('VaultService', () => {
  it('syncs, caches encrypted response, and returns summaries without password', async () => {
    const { service, api } = await makeService();
    const list = await service.sync();
    expect(api.sync).toHaveBeenCalledWith('access');
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: FIELD_VECTOR.plaintext, username: FIELD_VECTOR.plaintext, uris: [FIELD_VECTOR.plaintext], loginUris: [{ uri: FIELD_VECTOR.plaintext }] }], folders: [] });
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
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: '(undecryptable)', uris: [], loginUris: [], undecryptable: true }], folders: [] });
  });

  // Coverage-only: public method listItems() — not exercised by the sync test above.
  it('listItems returns empty envelope before sync and cached summaries after sync without calling api.sync again', async () => {
    const { service, api } = await makeService();

    // Before any sync the cache is empty.
    await expect(service.listItems()).resolves.toEqual({ items: [], folders: [] });

    // After sync the summaries are cached.
    const synced = await service.sync();
    expect(api.sync).toHaveBeenCalledTimes(1);

    // listItems must return the cached envelope without calling api.sync a second time.
    const listed = await service.listItems();
    expect(listed).toEqual(synced);
    expect(api.sync).toHaveBeenCalledTimes(1);
  });

  // Coverage-only: public method clearCache() — removes cached data.
  it('clearCache removes cached summaries so listItems returns the empty envelope again', async () => {
    const { service } = await makeService();
    await service.sync();
    expect((await service.listItems()).items).not.toEqual([]);

    await service.clearCache();
    await expect(service.listItems()).resolves.toEqual({ items: [], folders: [] });
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

  it('findAutofillCandidates returns sorted matching summaries without passwords', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.id = 'domain';
    sync.ciphers[0]!.favorite = false;
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      uris: [{ uri: URL_VECTOR.encString, match: UriMatchStrategy.Domain }],
    };
    const { service } = await makeService(sync);
    await service.sync();

    const candidates = await service.findAutofillCandidates(URL_VECTOR.plaintext, UriMatchStrategy.Domain);

    expect(candidates).toEqual([{
      id: 'domain',
      name: FIELD_VECTOR.plaintext,
      username: FIELD_VECTOR.plaintext,
      matchedUri: URL_VECTOR.plaintext,
      matchType: UriMatchStrategy.Domain,
      favorite: false,
    }]);
    expect(JSON.stringify(candidates)).not.toContain('password');
  });

  it('findAutofillCandidates rejects when vault is locked', async () => {
    const { service } = await makeService();
    await expect(service.findAutofillCandidates('https://example.com', UriMatchStrategy.Domain))
      .rejects.toMatchObject({ code: 'sync_required' });
  });

  it('findAutofillCandidates rejects locked when summaries exist but user key is unavailable', async () => {
    const { service, session } = await makeService();
    await service.sync();
    await session.lock();
    await expect(service.findAutofillCandidates(FIELD_VECTOR.plaintext, UriMatchStrategy.Domain))
      .rejects.toMatchObject({ code: 'locked' });
  });

  it('getAutofillCredentials re-checks URI match before decrypting credentials', async () => {
    const { service } = await makeService(makeSyncUrl());
    await service.sync();

    await expect(service.getAutofillCredentials('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain))
      .resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext });

    await expect(service.getAutofillCredentials('cipher-1', 'https://not-matching.example.org', UriMatchStrategy.Domain))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('decrypts folders, attaches folderId, and counts skipped org ciphers', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      folders: [{ id: 'folder-1', name: FIELD_VECTOR.encString }],
      ciphers: [
        { id: 'personal', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: null, folderId: 'folder-1', login: { username: FIELD_VECTOR.encString } },
        { id: 'orgitem', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: 'org-1', login: null },
      ],
    };
    const { service } = await makeService(sync);
    const result = await service.sync();
    expect(result.folders).toEqual([{ id: 'folder-1', name: FIELD_VECTOR.plaintext }]);
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toMatchObject({ id: 'personal', folderId: 'folder-1' });
    await expect(service.getSkippedOrgCount()).resolves.toBe(1);
  });

  it('decrypts and reveals card.number on demand while keeping it out of the summary', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'card-1', type: 3, name: FIELD_VECTOR.encString, favorite: false, organizationId: null,
        card: { brand: FIELD_VECTOR.encString, number: FIELD_VECTOR.encString, code: FIELD_VECTOR.encString },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    // The list summary carries only a non-sensitive brand subtitle, never the number/code.
    const { items } = await service.listItems();
    expect(items[0]).toMatchObject({ id: 'card-1', type: 3, subtitle: FIELD_VECTOR.plaintext });
    expect(JSON.stringify(items)).not.toContain('number');
    // The number is fetchable on demand.
    await expect(service.getField('card-1', 'card.number')).resolves.toBe(FIELD_VECTOR.plaintext);
    await expect(service.getField('card-1', 'card.code')).resolves.toBe(FIELD_VECTOR.plaintext);
  });

  it('getCipherDetail strips card.number and code from the cross-boundary payload', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'card-1', type: 3, name: FIELD_VECTOR.encString, favorite: false, organizationId: null,
        card: { brand: FIELD_VECTOR.encString, number: FIELD_VECTOR.encString, code: FIELD_VECTOR.encString },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const detail = await service.getCipherDetail('card-1');
    expect(detail?.card?.brand).toBe(FIELD_VECTOR.plaintext);
    expect(detail?.card?.number).toBeUndefined();
    expect(detail?.card?.code).toBeUndefined();
  });

  it('getCipherDetail strips password and totp from a login cipher payload', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'login-1', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: null,
        login: { username: FIELD_VECTOR.encString, password: FIELD_VECTOR.encString, totp: FIELD_VECTOR.encString },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const detail = await service.getCipherDetail('login-1');
    expect(detail?.username).toBe(FIELD_VECTOR.plaintext);
    expect(detail?.password).toBeUndefined();
    expect(detail?.totp).toBeUndefined();
  });

  it('masks identity ssn/passport/license in getCipherDetail and reveals them via getField', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'id-1', type: 4, name: FIELD_VECTOR.encString, favorite: false, organizationId: null,
        identity: {
          firstName: FIELD_VECTOR.encString, lastName: FIELD_VECTOR.encString,
          ssn: FIELD_VECTOR.encString, passportNumber: FIELD_VECTOR.encString, licenseNumber: FIELD_VECTOR.encString,
        },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const detail = await service.getCipherDetail('id-1');
    // Non-sensitive identity fields ride along; national-ID secrets are stripped from the payload.
    expect(detail?.identity?.firstName).toBe(FIELD_VECTOR.plaintext);
    expect(detail?.identity?.ssn).toBeUndefined();
    expect(detail?.identity?.passportNumber).toBeUndefined();
    expect(detail?.identity?.licenseNumber).toBeUndefined();
    // They remain fetchable on demand.
    await expect(service.getField('id-1', 'identity.ssn')).resolves.toBe(FIELD_VECTOR.plaintext);
    await expect(service.getField('id-1', 'identity.passportNumber')).resolves.toBe(FIELD_VECTOR.plaintext);
    await expect(service.getField('id-1', 'identity.licenseNumber')).resolves.toBe(FIELD_VECTOR.plaintext);
  });

  it('getSkippedOrgCount defaults to 0 before any sync', async () => {
    const { service } = await makeService();
    await expect(service.getSkippedOrgCount()).resolves.toBe(0);
  });
});
