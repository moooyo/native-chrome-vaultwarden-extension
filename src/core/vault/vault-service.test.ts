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
import type { SymmetricKey } from '../crypto/keys.js';
import { hexToBytes, base64ToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { hmacSha256 } from '../crypto/primitives.js';
import { FIELD_VECTOR, URL_VECTOR, USER_KEY_VECTOR, RSA_VECTOR, ORG_KEY_VECTOR } from '../../../test/vectors.js';
import type { SyncResponse } from '../api/types.js';

const orgKey = symmetricKeyFromBytes(hexToBytes(ORG_KEY_VECTOR.orgKeyHex));
const privateKeyBytes = base64ToBytes(RSA_VECTOR.privateKeyPkcs8B64);
const testUserKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
// RFC 6238 SHA1 seed as base32; at 1111111109s the 6-digit code is 081804.
const TOTP_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// Test-only encType=2 EncString encryptor (fixed IV) for building org-key-protected fixtures.
async function encUnder(plaintext: string, key: SymmetricKey): Promise<string> {
  const subtle = globalThis.crypto.subtle;
  const iv = new Uint8Array(16).fill(0x07);
  const cryptoKey = await subtle.importKey('raw', key.encKey as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, cryptoKey, new TextEncoder().encode(plaintext) as BufferSource));
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const mac = await hmacSha256(key.macKey, macData);
  return `2.${bytesToBase64(iv)}|${bytesToBase64(ct)}|${bytesToBase64(mac)}`;
}

async function makeOrgSync(): Promise<SyncResponse> {
  return {
    profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }] },
    ciphers: [{
      id: 'org-login',
      type: 1,
      name: await encUnder('Org Login', orgKey),
      favorite: false,
      organizationId: 'org-1',
      login: {
        username: await encUnder('alice@org.example', orgKey),
        password: await encUnder('org-s3cret', orgKey),
        uris: [{ uri: await encUnder('https://org.example', orgKey), match: 0 }],
      },
    }],
  };
}

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

async function makeService(syncResponse = makeSync(), opts: { privateKey?: Uint8Array; now?: () => number } = {}) {
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
    ...(opts.privateKey ? { privateKey: opts.privateKey } : {}),
  });
  const api = { sync: vi.fn(async () => syncResponse) } as unknown as ApiClient;
  const auth = { refreshIfNeeded: vi.fn(async () => {}) } as unknown as AuthService;
  const deps = { api, auth, session: sm, localStore, ...(opts.now ? { now: opts.now } : {}) };
  return { service: new VaultService(deps), api, session: sm };
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

  it('decrypts organization ciphers with the account private key and counts none as skipped', async () => {
    const { service } = await makeService(await makeOrgSync(), { privateKey: privateKeyBytes });
    const { items } = await service.sync();
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      id: 'org-login',
      type: 1,
      organizationId: 'org-1',
      name: 'Org Login',
      username: 'alice@org.example',
      uris: ['https://org.example'],
    });
    expect(JSON.stringify(items)).not.toContain('org-s3cret');
    await expect(service.getSkippedOrgCount()).resolves.toBe(0);
  });

  it('counts organization ciphers as skipped when the private key is unavailable', async () => {
    const { service } = await makeService(await makeOrgSync());
    const { items } = await service.sync();
    expect(items).toEqual([]);
    await expect(service.getSkippedOrgCount()).resolves.toBe(1);
  });

  it('getField decrypts an organization cipher password on demand', async () => {
    const { service } = await makeService(await makeOrgSync(), { privateKey: privateKeyBytes });
    await service.sync();
    await expect(service.getField('org-login', 'password')).resolves.toBe('org-s3cret');
  });

  it('autofills organization login credentials after re-checking the URI match', async () => {
    const { service } = await makeService(await makeOrgSync(), { privateKey: privateKeyBytes });
    await service.sync();

    const candidates = await service.findAutofillCandidates('https://org.example/login', UriMatchStrategy.Domain);
    expect(candidates).toMatchObject([{ id: 'org-login', username: 'alice@org.example' }]);

    await expect(service.getAutofillCredentials('org-login', 'https://org.example/login', UriMatchStrategy.Domain))
      .resolves.toEqual({ username: 'alice@org.example', password: 'org-s3cret' });
  });

  it('marks a login summary with hasTotp without leaking the secret', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = { username: FIELD_VECTOR.encString, totp: await encUnder(TOTP_SECRET_B32, testUserKey) };
    const { service } = await makeService(sync);
    const { items } = await service.sync();
    expect(items[0]).toMatchObject({ id: 'cipher-1', hasTotp: true });
    expect(JSON.stringify(items)).not.toContain(TOTP_SECRET_B32);
    expect(JSON.stringify(items)).not.toContain('totp');
  });

  it('getTotpCode generates the current code in the worker for a login with a TOTP secret', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = { username: FIELD_VECTOR.encString, totp: await encUnder(TOTP_SECRET_B32, testUserKey) };
    const { service } = await makeService(sync, { now: () => 1111111109_000 });
    await service.sync();
    await expect(service.getTotpCode('cipher-1')).resolves.toEqual({ code: '081804', period: 30, remaining: 1 });
  });

  it('getTotpCode returns undefined for a login without a TOTP secret or a missing cipher', async () => {
    const { service } = await makeService();
    await service.sync();
    await expect(service.getTotpCode('cipher-1')).resolves.toBeUndefined();
    await expect(service.getTotpCode('nope')).resolves.toBeUndefined();
  });
});
