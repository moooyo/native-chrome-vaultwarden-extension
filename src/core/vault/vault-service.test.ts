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
import { hexToBytes, base64ToBytes, bytesToBase64, bytesToBase64Url, base64UrlToBytes } from '../crypto/encoding.js';
import { hmacSha256 } from '../crypto/primitives.js';
import { decryptToText } from '../crypto/encstring.js';
import { derToRawSignature } from './fido2.js';
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
  const api = {
    sync: vi.fn(async () => syncResponse),
    createFolder: vi.fn(async () => ({ id: 'new-folder', name: '2.enc' })),
    updateFolder: vi.fn(async () => ({ id: 'f1', name: '2.enc' })),
    deleteFolder: vi.fn(async () => {}),
    createCipher: vi.fn(async () => ({ id: 'new-cipher', type: 1, name: '2.enc' })),
    updateCipher: vi.fn(async () => ({ id: 'cipher-1', type: 1, name: '2.enc' })),
    deleteCipher: vi.fn(async () => {}),
    softDeleteCipher: vi.fn(async () => {}),
    restoreCipher: vi.fn(async () => {}),
  } as unknown as ApiClient;
  const auth = {
    refreshIfNeeded: vi.fn(async () => {}),
    // Reprompt verification: only 'correct-master' is accepted, like a real master-password check.
    verifyMasterPassword: vi.fn(async (pw: string) => pw === 'correct-master'),
  } as unknown as AuthService;
  const deps = { api, auth, session: sm, localStore, ...(opts.now ? { now: opts.now } : {}) };
  return { service: new VaultService(deps), api, session: sm, auth };
}

describe('VaultService', () => {
  it('syncs, caches encrypted response, and returns summaries without password', async () => {
    const { service, api } = await makeService();
    const list = await service.sync();
    expect(api.sync).toHaveBeenCalledWith('access');
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: FIELD_VECTOR.plaintext, username: FIELD_VECTOR.plaintext, uris: [FIELD_VECTOR.plaintext], loginUris: [{ uri: FIELD_VECTOR.plaintext }] }], folders: [], collections: [] });
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
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: '(undecryptable)', uris: [], loginUris: [], undecryptable: true }], folders: [], collections: [] });
  });

  // Coverage-only: public method listItems() — not exercised by the sync test above.
  it('listItems returns empty envelope before sync and cached summaries after sync without calling api.sync again', async () => {
    const { service, api } = await makeService();

    // Before any sync the cache is empty.
    await expect(service.listItems()).resolves.toEqual({ items: [], folders: [], collections: [] });

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
    await expect(service.listItems()).resolves.toEqual({ items: [], folders: [], collections: [] });
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

  it('matches equivalent domains in autofill candidates (a google.com login fills youtube.com)', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      uris: [{ uri: await encUnder('https://google.com', testUserKey), match: UriMatchStrategy.Domain }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const candidates = await service.findAutofillCandidates('https://youtube.com/watch', UriMatchStrategy.Domain);
    expect(candidates.map((c) => c.id)).toEqual(['cipher-1']);
  });

  it('honors a server-excluded global equivalent-domain group (google login no longer fills youtube)', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      uris: [{ uri: await encUnder('https://google.com', testUserKey), match: UriMatchStrategy.Domain }],
    };
    sync.domains = { globalEquivalentDomains: [{ type: 1, domains: ['google.com', 'youtube.com', 'gmail.com'], excluded: true }] };
    const { service } = await makeService(sync);
    await service.sync();
    const candidates = await service.findAutofillCandidates('https://youtube.com/watch', UriMatchStrategy.Domain);
    expect(candidates.map((c) => c.id)).toEqual([]);
  });

  it('consumes user-defined equivalent domains from sync (a custom group links two domains)', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      uris: [{ uri: await encUnder('https://corp-a.example', testUserKey), match: UriMatchStrategy.Domain }],
    };
    sync.domains = { equivalentDomains: [['corp-a.example', 'corp-b.example']] };
    const { service } = await makeService(sync);
    await service.sync();
    const candidates = await service.findAutofillCandidates('https://corp-b.example/login', UriMatchStrategy.Domain);
    expect(candidates.map((c) => c.id)).toEqual(['cipher-1']);
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

  it('getAutofillCredentials includes the current TOTP code when the login carries a TOTP secret', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      totp: await encUnder(TOTP_SECRET_B32, testUserKey),
      uris: [{ uri: URL_VECTOR.encString, match: UriMatchStrategy.Domain }],
    };
    const { service } = await makeService(sync, { now: () => 1111111109_000 });
    await service.sync();
    await expect(service.getAutofillCredentials('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain))
      .resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext, totp: '081804' });
  });

  describe('master-password reprompt enforcement', () => {
    it('sync surfaces the reprompt flag on the summary', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      const list = await service.sync();
      expect(list.items[0]!.reprompt).toBe(true);
    });

    it('getField refuses a reprompt item without the master password', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service, auth } = await makeService(sync);
      await service.sync();
      await expect(service.getField('cipher-1', 'password'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      expect(auth.verifyMasterPassword).not.toHaveBeenCalled();
    });

    it('getField refuses a reprompt item with the wrong master password', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getField('cipher-1', 'password', 'wrong'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
    });

    it('getField releases a reprompt item once the master password verifies', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service, auth } = await makeService(sync);
      await service.sync();
      await expect(service.getField('cipher-1', 'password', 'correct-master'))
        .resolves.toBe(FIELD_VECTOR.plaintext);
      expect(auth.verifyMasterPassword).toHaveBeenCalledWith('correct-master');
    });

    it('does not require the master password for a non-reprompt item', async () => {
      const { service, auth } = await makeService();
      await service.sync();
      await expect(service.getField('cipher-1', 'password')).resolves.toBe(FIELD_VECTOR.plaintext);
      expect(auth.verifyMasterPassword).not.toHaveBeenCalled();
    });

    it('getCipherInput gates a reprompt item and round-trips the flag once verified', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getCipherInput('cipher-1')).rejects.toMatchObject({ code: 'reprompt_required' });
      const input = await service.getCipherInput('cipher-1', 'correct-master');
      expect(input?.reprompt).toBe(true);
    });

    it('getAutofillCredentials never releases a reprompt item into the page', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getAutofillCredentials('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain))
        .rejects.toMatchObject({ code: 'reprompt_required' });
    });
  });

  describe('custom fields', () => {
    it('getCipherDetail masks Hidden values but keeps Text inline; getCustomField reveals on demand', async () => {
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [{
          id: 'cf', type: 1, favorite: false, organizationId: null,
          name: await encUnder('Item', testUserKey),
          fields: [
            { type: 0, name: await encUnder('Text', testUserKey), value: await encUnder('shown', testUserKey) },
            { type: 1, name: await encUnder('Secret', testUserKey), value: await encUnder('hidden-val', testUserKey) },
          ],
        }],
      };
      const { service } = await makeService(sync);
      await service.sync();
      const detail = await service.getCipherDetail('cf');
      expect(detail?.fields).toEqual([
        { type: 0, name: 'Text', value: 'shown' },
        { type: 1, name: 'Secret' }, // Hidden value omitted from the detail payload
      ]);
      await expect(service.getCustomField('cf', 1)).resolves.toBe('hidden-val');
    });

    it('getCustomField on a reprompt item requires the master password', async () => {
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [{
          id: 'cf', type: 1, favorite: false, organizationId: null, reprompt: 1,
          name: await encUnder('Item', testUserKey),
          fields: [{ type: 1, name: await encUnder('Secret', testUserKey), value: await encUnder('hidden-val', testUserKey) }],
        }],
      };
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getCustomField('cf', 0)).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.getCustomField('cf', 0, 'correct-master')).resolves.toBe('hidden-val');
    });

    it('getCipherInput round-trips custom fields for the editor', async () => {
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [{
          id: 'cf', type: 1, favorite: false, organizationId: null,
          name: await encUnder('Item', testUserKey),
          fields: [{ type: 0, name: await encUnder('Text', testUserKey), value: await encUnder('shown', testUserKey) }],
        }],
      };
      const { service } = await makeService(sync);
      await service.sync();
      const input = await service.getCipherInput('cf');
      expect(input?.fields).toEqual([{ type: 0, name: 'Text', value: 'shown' }]);
    });
  });

  describe('save / update login capture', () => {
    const SITE = URL_VECTOR.plaintext;                 // https://example.com
    const USER = FIELD_VECTOR.plaintext;               // matches the cached cipher's username
    const PASS = FIELD_VECTOR.plaintext;               // matches the cached cipher's password

    it('checkSaveLogin returns none when the same credential is already stored', async () => {
      const { service } = await makeService(makeSyncUrl());
      await service.sync();
      await expect(service.checkSaveLogin(SITE, { username: USER, password: PASS }, UriMatchStrategy.Domain))
        .resolves.toEqual({ action: 'none' });
    });

    it('checkSaveLogin returns update when the username matches but the password changed', async () => {
      const { service } = await makeService(makeSyncUrl());
      await service.sync();
      await expect(service.checkSaveLogin(SITE, { username: USER, password: 'changed-pass' }, UriMatchStrategy.Domain))
        .resolves.toEqual({ action: 'update', cipherId: 'cipher-1', name: FIELD_VECTOR.plaintext });
    });

    it('checkSaveLogin returns save for a new username on the site', async () => {
      const { service } = await makeService(makeSyncUrl());
      await service.sync();
      await expect(service.checkSaveLogin(SITE, { username: 'someone-else@example.com', password: 'x' }, UriMatchStrategy.Domain))
        .resolves.toEqual({ action: 'save', suggestedName: 'example.com' });
    });

    it('checkSaveLogin never reveals or matches reprompt-protected items', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      await service.sync();
      // Even the identical stored credential is treated as new, because protected items are skipped.
      await expect(service.checkSaveLogin(SITE, { username: USER, password: PASS }, UriMatchStrategy.Domain))
        .resolves.toEqual({ action: 'save', suggestedName: 'example.com' });
    });

    it('saveLogin creates an encrypted login cipher and re-syncs', async () => {
      const { service, api } = await makeService(makeSyncUrl());
      await service.sync();
      await service.saveLogin('https://example.com/login', 'new@example.com', 'secret-pass');
      const [token, req] = (api.createCipher as ReturnType<typeof vi.fn>).mock.calls.at(-1)!;
      expect(token).toBe('access');
      expect((req as { type: number }).type).toBe(1);
      expect(JSON.stringify(req)).not.toContain('secret-pass'); // password is encrypted, never plaintext
      expect(api.sync).toHaveBeenCalled();
    });

    it('updateLoginPassword re-encrypts the password for a matching item and re-syncs', async () => {
      const { service, api } = await makeService(makeSyncUrl());
      await service.sync();
      await service.updateLoginPassword('cipher-1', 'rotated-pass', SITE, UriMatchStrategy.Domain);
      const [, id, req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls.at(-1)!;
      expect(id).toBe('cipher-1');
      expect(JSON.stringify(req)).not.toContain('rotated-pass');
      expect(api.sync).toHaveBeenCalled();
    });

    it('updateLoginPassword refuses a reprompt-protected item', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      const { service, api } = await makeService(sync);
      await service.sync();
      await expect(service.updateLoginPassword('cipher-1', 'x', SITE, UriMatchStrategy.Domain))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      expect(api.updateCipher).not.toHaveBeenCalled();
    });

    it('updateLoginPassword refuses an item that does not match the submitting page', async () => {
      const { service, api } = await makeService(makeSyncUrl());
      await service.sync();
      await expect(service.updateLoginPassword('cipher-1', 'x', 'https://evil.example.org', UriMatchStrategy.Domain))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.updateCipher).not.toHaveBeenCalled();
    });
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

  it('decrypts collections and attaches collectionIds to organization cipher summaries', async () => {
    const sync = await makeOrgSync();
    sync.collections = [{ id: 'col-1', organizationId: 'org-1', name: await encUnder('Engineering', orgKey) }];
    sync.ciphers[0]!.collectionIds = ['col-1'];
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    const result = await service.sync();
    expect(result.collections).toEqual([{ id: 'col-1', organizationId: 'org-1', name: 'Engineering' }]);
    expect(result.items[0]).toMatchObject({ id: 'org-login', collectionIds: ['col-1'] });
    // Cached collections survive a listItems round-trip.
    await expect(service.listItems()).resolves.toMatchObject({ collections: [{ id: 'col-1', name: 'Engineering' }] });
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

  it('createFolder encrypts the name under the user key, calls the API, and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.createFolder('Work');
    expect(api.createFolder).toHaveBeenCalledTimes(1);
    const [token, enc] = (api.createFolder as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(token).toBe('access');
    expect((enc as string).startsWith('2.')).toBe(true);
    await expect(decryptToText(enc as string, testUserKey)).resolves.toBe('Work');
    expect(api.sync).toHaveBeenCalled();
  });

  it('renameFolder encrypts the new name and updates the folder by id', async () => {
    const { service, api } = await makeService();
    await service.renameFolder('f1', 'Personal');
    const [token, id, enc] = (api.updateFolder as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect([token, id]).toEqual(['access', 'f1']);
    await expect(decryptToText(enc as string, testUserKey)).resolves.toBe('Personal');
  });

  it('deleteFolder calls the API by id and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.deleteFolder('f1');
    expect(api.deleteFolder).toHaveBeenCalledWith('access', 'f1');
    expect(api.sync).toHaveBeenCalled();
  });

  it('createFolder rejects when the vault is locked', async () => {
    const { service, session } = await makeService();
    await session.lock();
    await expect(service.createFolder('X')).rejects.toThrow();
  });

  it('createCipher encrypts the cipher under the user key, POSTs it, and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.createCipher({ type: 1, name: 'New Login', login: { password: 'p@ssw0rd' } });
    expect(api.createCipher).toHaveBeenCalledTimes(1);
    const [token, req] = (api.createCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(token).toBe('access');
    expect((req as { name: string }).name.startsWith('2.')).toBe(true);
    expect(JSON.stringify(req)).not.toContain('p@ssw0rd');
    expect(api.sync).toHaveBeenCalled();
  });

  it('updateCipher encrypts and PUTs by id', async () => {
    const { service, api } = await makeService();
    await service.updateCipher('cipher-1', { type: 1, name: 'Renamed' });
    const [token, id, req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect([token, id]).toEqual(['access', 'cipher-1']);
    expect((req as { name: string }).name.startsWith('2.')).toBe(true);
  });

  it('updateCipher preserves the passkey and cipher key the editor does not model, and writes editor-controlled reprompt/fields', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      fido2Credentials: [{ credentialId: '2.cid==', keyValue: '2.kv==', rpId: '2.rp==', counter: '2.ct==' }],
    };
    sync.ciphers[0]!.key = '2.cipherkey==';
    const { service, api } = await makeService(sync);
    await service.sync(); // populate the raw cache the merge reads from
    // reprompt + custom fields are now editor-controlled, so the editor round-trips them in the input.
    await service.updateCipher('cipher-1', {
      type: 1, name: 'Renamed', reprompt: true,
      fields: [{ type: 0, name: 'Note', value: 'kept' }],
      login: { password: 'newpass' },
    });
    const [, id, req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(id).toBe('cipher-1');
    const r = req as { login?: { fido2Credentials?: unknown }; fields?: { type: number }[]; reprompt?: number; key?: string };
    // Passkey + per-cipher key still ride along (the editor doesn't model them).
    expect(r.login?.fido2Credentials).toEqual(sync.ciphers[0]!.login!.fido2Credentials);
    expect(r.key).toBe('2.cipherkey==');
    // Editor-modeled fields/reprompt come from the input, encrypted (never plaintext).
    expect(r.reprompt).toBe(1);
    expect(r.fields?.length).toBe(1);
    expect(JSON.stringify(r)).not.toContain('newpass');
    expect(JSON.stringify(r)).not.toContain('"kept"');
  });

  describe('password history', () => {
    it('archives the prior password and stamps the revision date when the password changes', async () => {
      const sync = makeSync(); // cipher-1 password = FIELD_VECTOR (plaintext "Hello, Vault!")
      const { service, api } = await makeService(sync, { now: () => 1_700_000_000_000 });
      await service.sync();
      await service.updateCipher('cipher-1', { type: 1, name: 'X', login: { password: 'a-new-password' } });
      const [, , req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
      const r = req as { passwordHistory?: Array<{ password: string; lastUsedDate?: string }>; login?: { passwordRevisionDate?: string } };
      expect(r.passwordHistory?.length).toBe(1);
      expect(r.passwordHistory![0]!.password).toBe(FIELD_VECTOR.encString); // the prior EncString, verbatim
      expect(r.passwordHistory![0]!.lastUsedDate).toBe(new Date(1_700_000_000_000).toISOString());
      expect(r.login?.passwordRevisionDate).toBe(new Date(1_700_000_000_000).toISOString());
    });

    it('does not add a history entry when the password is unchanged', async () => {
      const { service, api } = await makeService(makeSync());
      await service.sync();
      // Same plaintext as the cached cipher's password.
      await service.updateCipher('cipher-1', { type: 1, name: 'X', login: { password: FIELD_VECTOR.plaintext } });
      const [, , req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect((req as { passwordHistory?: unknown }).passwordHistory).toBeUndefined();
    });

    it('sync surfaces the password-history count on the summary', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.passwordHistory = [
        { password: await encUnder('old1', testUserKey), lastUsedDate: '2020-01-01T00:00:00.000Z' },
        { password: await encUnder('old2', testUserKey) },
      ];
      const { service } = await makeService(sync);
      const { items } = await service.sync();
      expect(items[0]!.passwordHistoryCount).toBe(2);
    });

    it('getPasswordHistory decrypts entries most-recent first, reprompt-gated', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.passwordHistory = [
        { password: await encUnder('old1', testUserKey), lastUsedDate: '2020-01-01T00:00:00.000Z' },
        { password: await encUnder('old2', testUserKey) },
      ];
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getPasswordHistory('cipher-1')).resolves.toEqual([
        { password: 'old1', lastUsedDate: '2020-01-01T00:00:00.000Z' },
        { password: 'old2' },
      ]);
    });

    it('getPasswordHistory requires the master password for a reprompt item', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      sync.ciphers[0]!.passwordHistory = [{ password: await encUnder('old1', testUserKey) }];
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getPasswordHistory('cipher-1')).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.getPasswordHistory('cipher-1', 'correct-master')).resolves.toEqual([{ password: 'old1' }]);
    });
  });

  it('deleteCipher calls the API by id and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.deleteCipher('cipher-1');
    expect(api.deleteCipher).toHaveBeenCalledWith('access', 'cipher-1');
    expect(api.sync).toHaveBeenCalled();
  });

  it('softDeleteCipher moves the cipher to trash via the API and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.softDeleteCipher('cipher-1');
    expect(api.softDeleteCipher).toHaveBeenCalledWith('access', 'cipher-1');
    expect(api.deleteCipher).not.toHaveBeenCalled();
    expect(api.sync).toHaveBeenCalled();
  });

  it('restoreCipher restores from trash via the API and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.restoreCipher('cipher-1');
    expect(api.restoreCipher).toHaveBeenCalledWith('access', 'cipher-1');
    expect(api.sync).toHaveBeenCalled();
  });

  it('tags soft-deleted ciphers with deletedDate and keeps active ones in autofill', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.deletedDate = '2026-01-01T00:00:00.000Z';
    const { service } = await makeService(sync);
    await service.sync();
    // The trashed cipher is tagged so the UI can build a trash view…
    const listing = await service.listItems();
    expect(listing.items.find((i) => i.id === 'cipher-1')?.deletedDate).toBe('2026-01-01T00:00:00.000Z');
    // …and it is NOT offered as an autofill candidate for its own URL.
    const candidates = await service.findAutofillCandidates(URL_VECTOR.plaintext, UriMatchStrategy.Domain);
    expect(candidates.find((c) => c.id === 'cipher-1')).toBeUndefined();
  });

  it('getCipherInput returns the editable plaintext including secrets', async () => {
    const { service } = await makeService();
    await service.sync();
    const input = await service.getCipherInput('cipher-1');
    expect(input).toMatchObject({
      type: 1, name: FIELD_VECTOR.plaintext,
      login: { username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext },
    });
  });

  it('createCipher rejects when the vault is locked', async () => {
    const { service, session } = await makeService();
    await session.lock();
    await expect(service.createCipher({ type: 1, name: 'x' })).rejects.toThrow();
  });

  it('exportVault serializes the decrypted vault to Bitwarden JSON', async () => {
    const { service } = await makeService();
    await service.sync();
    const parsed = JSON.parse(await service.exportVault());
    expect(parsed.encrypted).toBe(false);
    expect(parsed.items[0]).toMatchObject({ name: FIELD_VECTOR.plaintext, type: 1 });
  });

  it('importVault creates a cipher per parsed item and re-syncs once', async () => {
    const { service, api } = await makeService();
    const json = JSON.stringify({ items: [{ type: 1, name: 'Imported', login: { password: 'p' } }, { type: 2, name: 'Note', notes: 'n' }] });
    await expect(service.importVault(json)).resolves.toBe(2);
    expect(api.createCipher).toHaveBeenCalledTimes(2);
    expect(api.sync).toHaveBeenCalled();
  });

  it('importVault rejects malformed JSON', async () => {
    const { service } = await makeService();
    await expect(service.importVault('nope')).rejects.toThrow();
  });

  it('signs a passkey assertion in the worker without leaking the private key', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    const keyValueB64url = bytesToBase64Url(pkcs8);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'pk', type: 1, name: await encUnder('Acme', testUserKey), favorite: false, organizationId: null,
        login: { fido2Credentials: [{
          credentialId: await encUnder('cred-1', testUserKey),
          keyValue: await encUnder(keyValueB64url, testUserKey),
          rpId: await encUnder('acme.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }] },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    expect((await service.listItems()).items[0]).toMatchObject({ id: 'pk', hasPasskey: true });

    const challenge = bytesToBase64Url(new TextEncoder().encode('chal'));
    const assertion = await service.getPasskeyAssertion({ rpId: 'acme.com', origin: 'https://acme.com', challenge });
    expect(assertion?.credentialId).toBe('cred-1');
    expect(JSON.stringify(assertion)).not.toContain(keyValueB64url);

    // The returned signature verifies against the credential's public key.
    const authData = base64UrlToBytes(assertion!.authenticatorData);
    const clientHash = new Uint8Array(await subtle.digest('SHA-256', base64UrlToBytes(assertion!.clientDataJSON) as BufferSource));
    const signedData = new Uint8Array([...authData, ...clientHash]);
    const rawSig = derToRawSignature(base64UrlToBytes(assertion!.signature));
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, rawSig as BufferSource, signedData as BufferSource);
    expect(ok).toBe(true);
  });

  it('passkey assertion reports user-verification honestly (default false; true only when asserted)', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = bytesToBase64Url(new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)));
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'pk', type: 1, name: await encUnder('Acme', testUserKey), favorite: false, organizationId: null,
        login: { fido2Credentials: [{
          credentialId: await encUnder('cred-1', testUserKey),
          keyValue: await encUnder(pkcs8, testUserKey),
          rpId: await encUnder('acme.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }] },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const challenge = bytesToBase64Url(new TextEncoder().encode('chal'));
    // authData flags live at byte 32: UP=0x01, UV=0x04.
    const flags = async (uv?: boolean) => {
      const a = await service.getPasskeyAssertion({ rpId: 'acme.com', origin: 'https://acme.com', challenge, ...(uv === undefined ? {} : { userVerified: uv }) });
      return base64UrlToBytes(a!.authenticatorData)[32]!;
    };
    expect(await flags()).toBe(0x01);       // default: present, NOT verified (no silent UV)
    expect(await flags(false)).toBe(0x01);  // explicit false
    expect(await flags(true)).toBe(0x05);   // UP | UV when the user was actually verified
  });

  it('hasMatchingPasskey reports whether a stored passkey matches the rpId / allowed credential', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'pk', type: 1, name: await encUnder('Acme', testUserKey), favorite: false, organizationId: null,
        login: { fido2Credentials: [{
          credentialId: await encUnder('cred-1', testUserKey),
          keyValue: await encUnder('2.kv==', testUserKey),
          rpId: await encUnder('acme.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }] },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    expect(await service.hasMatchingPasskey({ rpId: 'acme.com' })).toBe(true);
    expect(await service.hasMatchingPasskey({ rpId: 'other.com' })).toBe(false);
    expect(await service.hasMatchingPasskey({ rpId: 'acme.com', allowedCredentialIds: ['cred-1'] })).toBe(true);
    expect(await service.hasMatchingPasskey({ rpId: 'acme.com', allowedCredentialIds: ['nope'] })).toBe(false);
  });

  it('reports weak and reused passwords without leaking the passwords', async () => {
    const weak = await encUnder('weakpass', testUserKey);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await encUnder('A', testUserKey), favorite: false, organizationId: null, login: { password: weak } },
        { id: 'b', type: 1, name: await encUnder('B', testUserKey), favorite: false, organizationId: null, login: { password: weak } },
        { id: 'c', type: 1, name: await encUnder('C', testUserKey), favorite: false, organizationId: null, login: { password: await encUnder('Str0ng&Unique!pass', testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const entries = await service.getPasswordHealth();
    // 'a' and 'b' share a weak password (reused + weak); 'c' is strong and unique → not reported.
    expect(entries.map((e) => e.id).sort()).toEqual(['a', 'b']);
    expect(entries.every((e) => e.weak && e.reuseCount === 2)).toBe(true);
    expect(JSON.stringify(entries)).not.toContain('weakpass');
  });
});
