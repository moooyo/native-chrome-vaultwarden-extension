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
// HIBP lookups are network calls; stub the module so getPwnedReport tests never hit the network.
vi.mock('./pwned.js', () => ({
  pwnedCount: vi.fn(async (pw: string) => (pw === 'reused-weak' ? 42 : 0)),
}));
import { createMemoryStore } from '../../platform/store.js';
import { SessionManager } from '../session/session-manager.js';
import type { ApiClient } from '../api/client.js';
import type { AuthService } from '../session/auth-service.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { hexToBytes, base64ToBytes, bytesToBase64, bytesToBase64Url, base64UrlToBytes } from '../crypto/encoding.js';
import { hmacSha256 } from '../crypto/primitives.js';
import { decryptToText, EncStringMacError } from '../crypto/encstring.js';
import { derToRawSignature } from './fido2.js';
import { encryptAttachmentFile, generateAttachmentKey, wrapAttachmentKey } from './attachments.js';
import { buildTextSendRequest } from './sends.js';
import { FIELD_VECTOR, URL_VECTOR, USER_KEY_VECTOR, RSA_VECTOR, ORG_KEY_VECTOR } from '../../../test/vectors.js';
import type { CipherRequest, CipherResponse, SyncResponse } from '../api/types.js';

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

/** Exposes a mocked ApiClient's methods as writable, loosely-typed slots so a test can stub the few
 *  methods the base `makeService` mock omits without matching each response's full type. Behaviour is
 *  identical to the object it wraps — this is only a type view over the same mock instance. */
function stubApi(api: ApiClient): Record<string, (...args: never[]) => unknown> {
  return api as unknown as Record<string, (...args: never[]) => unknown>;
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
    shareCipher: vi.fn(async () => ({ id: 'mine', type: 1, name: '2.enc' })),
    createCollection: vi.fn(async () => ({ id: 'new-collection', name: '2.enc' })),
    getCollectionDetails: vi.fn(async () => ({ groups: [], users: [] })),
    updateCollection: vi.fn(async () => ({ id: 'c1', name: '2.enc' })),
    deleteCollection: vi.fn(async () => {}),
    updateCipherCollections: vi.fn(async () => {}),
    deleteCipher: vi.fn(async () => {}),
    softDeleteCipher: vi.fn(async () => {}),
    restoreCipher: vi.fn(async () => {}),
    downloadAttachment: vi.fn(async () => new Uint8Array()),
    uploadAttachment: vi.fn(async () => ({ id: 'cipher-1', type: 1, name: '2.enc' })),
    deleteAttachment: vi.fn(async () => {}),
    listSends: vi.fn(async () => []),
    createSend: vi.fn(async (_t: string, send: unknown) => ({ id: 's1', accessId: 'acc1', ...(send as object) })),
    deleteSend: vi.fn(async () => {}),
  } as unknown as ApiClient;
  const auth = {
    refreshIfNeeded: vi.fn(async () => {}),
    // Reprompt verification: only 'correct-master' is accepted, like a real master-password check.
    verifyMasterPassword: vi.fn(async (pw: string) => pw === 'correct-master'),
  } as unknown as AuthService;
  const deps = { api, auth, session: sm, localStore, ...(opts.now ? { now: opts.now } : {}) };
  return { service: new VaultService(deps), api, session: sm, auth };
}

/** Seeds a personal login cipher with one fido2Credential at `opts.rpId`, backed by a real ECDSA
 *  key pair so a signing test can verify the returned assertion. Mirrors the fixture used by the
 *  existing "signs a passkey assertion" test above. */
async function makeServiceWithPasskey(opts: { rpId: string }) {
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
        rpId: await encUnder(opts.rpId, testUserKey),
        counter: await encUnder('0', testUserKey),
      }] },
    }],
  };
  const { service } = await makeService(sync);
  await service.sync();
  return { service };
}

/** Seeds one personal login cipher per entry (encrypted name/username/uris under the account key),
 *  syncs so both VAULT_CACHE_KEY and SUMMARY_CACHE_KEY are populated, and returns the service. */
async function makeServiceWithLogins(logins: Array<{ id: string; name: string; username?: string; uris: string[] }>) {
  const ciphers = await Promise.all(logins.map(async (l) => ({
    id: l.id, type: 1 as const, favorite: false, organizationId: null,
    name: await encUnder(l.name, testUserKey),
    login: {
      ...(l.username ? { username: await encUnder(l.username, testUserKey) } : {}),
      uris: await Promise.all(l.uris.map(async (u) => ({ uri: await encUnder(u, testUserKey) }))),
    },
  })));
  const sync: SyncResponse = { profile: { id: 'u', email: 'u@example.com' }, ciphers };
  const { service, api } = await makeService(sync);
  await service.sync();
  return { service, api };
}

/** An already-unlocked service with no vault synced yet (for createPasskey 'new item' tests). Lets the
 *  caller override individual api methods (e.g. createCipher) to capture the request shape. */
async function makeUnlockedService(opts: { api?: Record<string, unknown> } = {}) {
  const { service, api } = await makeService();
  if (opts.api) Object.assign(api, opts.api);
  return { service, api };
}

/** A locked service (persisted auth exists, but the session UserKey has been cleared). */
async function makeLockedService() {
  const { service, session } = await makeService();
  await session.lock();
  return { service };
}

/** Seeds a personal login cipher (id `opts.id`) that already carries one encrypted fido2Credential at
 *  `opts.rpId`, plus a password/uri, and syncs so the raw CipherResponse is cached. Returns the service
 *  and a snapshot of the fixture's own EncStrings to compare the PUT request against verbatim. */
async function makeServiceWithExistingPasskeyLogin(opts: { id: string; rpId: string; api?: Record<string, unknown> }) {
  const subtle = globalThis.crypto.subtle;
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  const keyValueB64url = bytesToBase64Url(pkcs8);
  const existingCred = {
    credentialId: await encUnder('old-cred', testUserKey),
    keyType: await encUnder('public-key', testUserKey),
    keyAlgorithm: await encUnder('ECDSA', testUserKey),
    keyCurve: await encUnder('P-256', testUserKey),
    keyValue: await encUnder(keyValueB64url, testUserKey),
    rpId: await encUnder(opts.rpId, testUserKey),
    counter: await encUnder('0', testUserKey),
  };
  const cipher = {
    id: opts.id, type: 1 as const, favorite: false, organizationId: null,
    name: await encUnder('Existing Login', testUserKey),
    login: {
      password: await encUnder('old-pass', testUserKey),
      uris: [{ uri: await encUnder(`https://${opts.rpId}`, testUserKey) }],
      fido2Credentials: [existingCred],
    },
  };
  const sync: SyncResponse = { profile: { id: 'u', email: 'u@example.com' }, ciphers: [cipher] };
  const { service, api } = await makeService(sync);
  if (opts.api) Object.assign(api, opts.api);
  await service.sync();
  const originalRequestSnapshot = {
    name: cipher.name,
    login: { password: cipher.login.password, fido2Credentials: cipher.login.fido2Credentials },
  };
  return { service, originalRequestSnapshot };
}

describe('VaultService', () => {
  it('syncs, caches encrypted response, and returns summaries without password', async () => {
    const { service, api } = await makeService();
    const list = await service.sync();
    expect(api.sync).toHaveBeenCalledWith('access');
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: FIELD_VECTOR.plaintext, username: FIELD_VECTOR.plaintext, uris: [FIELD_VECTOR.plaintext], loginUris: [{ uri: FIELD_VECTOR.plaintext }] }], folders: [], collections: [], orgPermissions: [] });
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
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: '(undecryptable)', uris: [], loginUris: [], undecryptable: true }], folders: [], collections: [], orgPermissions: [] });
  });

  // Coverage-only: public method listItems() — not exercised by the sync test above.
  it('listItems returns empty envelope before sync and cached summaries after sync without calling api.sync again', async () => {
    const { service, api } = await makeService();

    // Before any sync the cache is empty.
    await expect(service.listItems()).resolves.toEqual({ items: [], folders: [], collections: [], orgPermissions: [] });

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
    await expect(service.listItems()).resolves.toEqual({ items: [], folders: [], collections: [], orgPermissions: [] });
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

  describe('attachments', () => {
    async function syncWithAttachment(extra: { reprompt?: number } = {}): Promise<{ sync: SyncResponse; blob: Uint8Array }> {
      const attKey = generateAttachmentKey(() => new Uint8Array(64).fill(5));
      const wrapped = await wrapAttachmentKey(attKey, testUserKey);
      const blob = await encryptAttachmentFile(new TextEncoder().encode('secret-file-contents'), attKey);
      return {
        sync: {
          profile: { id: 'u', email: 'u@example.com' },
          ciphers: [{
            id: 'cipher-1', type: 1, favorite: false, organizationId: null, ...(extra.reprompt ? { reprompt: extra.reprompt } : {}),
            name: await encUnder('Item', testUserKey),
            attachments: [{ id: 'att-1', url: 'https://files.example/att-1', key: wrapped, fileName: await encUnder('report.pdf', testUserKey), size: '20', sizeName: '20 B' }],
          }],
        } as SyncResponse,
        blob,
      };
    }

    it('getCipherDetail surfaces attachment metadata without url/key', async () => {
      const { sync } = await syncWithAttachment();
      const { service } = await makeService(sync);
      await service.sync();
      const detail = await service.getCipherDetail('cipher-1');
      expect(detail?.attachments).toEqual([{ id: 'att-1', fileName: 'report.pdf', size: '20', sizeName: '20 B' }]);
    });

    it('getAttachment downloads and decrypts the file inside the worker', async () => {
      const { sync, blob } = await syncWithAttachment();
      const { service, api } = await makeService(sync);
      (api.downloadAttachment as ReturnType<typeof vi.fn>).mockResolvedValue(blob);
      await service.sync();
      const result = await service.getAttachment('cipher-1', 'att-1');
      expect(api.downloadAttachment).toHaveBeenCalledWith('https://files.example/att-1', 'access');
      expect(result.fileName).toBe('report.pdf');
      expect(result.dataB64).toBe(bytesToBase64(new TextEncoder().encode('secret-file-contents')));
    });

    it('getAttachment requires the master password for a reprompt item', async () => {
      const { sync, blob } = await syncWithAttachment({ reprompt: 1 });
      const { service, api } = await makeService(sync);
      (api.downloadAttachment as ReturnType<typeof vi.fn>).mockResolvedValue(blob);
      await service.sync();
      await expect(service.getAttachment('cipher-1', 'att-1')).rejects.toMatchObject({ code: 'reprompt_required' });
    });

    it('addAttachment uploads an encrypted blob + wrapped key and re-syncs', async () => {
      const { service, api } = await makeService();
      await service.sync();
      await service.addAttachment('cipher-1', 'notes.txt', bytesToBase64(new TextEncoder().encode('plain text body')));
      const [token, cipherId, params] = (api.uploadAttachment as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(token).toBe('access');
      expect(cipherId).toBe('cipher-1');
      expect(params.key.startsWith('2.')).toBe(true);            // wrapped attachment key
      expect(params.encryptedFileName.startsWith('2.')).toBe(true); // encrypted file name
      expect(params.data[0]).toBe(2);                            // EncArrayBuffer encType marker
      expect(JSON.stringify([...params.data])).not.toContain('plain'); // never plaintext
      expect(api.sync).toHaveBeenCalled();
    });

    it('deleteAttachment calls the API and re-syncs', async () => {
      const { service, api } = await makeService();
      await service.deleteAttachment('cipher-1', 'att-1');
      expect(api.deleteAttachment).toHaveBeenCalledWith('access', 'cipher-1', 'att-1');
      expect(api.sync).toHaveBeenCalled();
    });
  });

  describe('sends', () => {
    it('listSends decrypts each send for display with its share URL', async () => {
      const { request } = await buildTextSendRequest({ name: 'Shared note', text: 'body', deletionDays: 7 }, testUserKey);
      const { service, api } = await makeService();
      (api.listSends as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: 's1', accessId: 'acc1', ...request }]);
      const sends = await service.listSends('https://vault.example');
      expect(sends).toHaveLength(1);
      expect(sends[0]).toMatchObject({ id: 's1', name: 'Shared note', text: 'body' });
      expect(sends[0]!.url).toContain('https://vault.example/#/send/acc1/');
    });

    it('createTextSend posts an encrypted send and returns it with a share URL', async () => {
      const { service, api } = await makeService();
      const summary = await service.createTextSend({ name: 'Hi', text: 'secret-body', deletionDays: 7 }, 'https://vault.example');
      const [token, body] = (api.createSend as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(token).toBe('access');
      expect(JSON.stringify(body)).not.toContain('secret-body'); // text is encrypted
      expect(summary.name).toBe('Hi');
      expect(summary.url).toContain('https://vault.example/#/send/acc1/');
    });

    it('deleteSend calls the API by id', async () => {
      const { service, api } = await makeService();
      await service.deleteSend('s1');
      expect(api.deleteSend).toHaveBeenCalledWith('access', 's1');
    });

    it('createFileSend encrypts the file, uploads via v2, and returns a decrypted summary', async () => {
      const { service, api } = await makeService();
      stubApi(api).createSendFile = vi.fn(async (_t: string, req: { file: { fileName: string } }) => ({ url: '/sends/s1/file/f1', sendResponse: { ...req, id: 's1', accessId: 'acc1', file: { id: 'f1', fileName: req.file.fileName, sizeName: '3 Bytes' } } }));
      stubApi(api).uploadSendFileData = vi.fn(async () => {});
      const dataB64 = btoa(String.fromCharCode(1, 2, 3));
      const summary = await service.createFileSend({ name: 'Doc', deletionDays: 7 }, dataB64, 'secret.pdf', 'http://localhost:8080');
      expect(stubApi(api).createSendFile).toHaveBeenCalled();
      expect(stubApi(api).uploadSendFileData).toHaveBeenCalledWith('access', '/sends/s1/file/f1', expect.any(Uint8Array), expect.any(String));
      expect(summary.type).toBe(1);
      expect(summary.fileName).toBe('secret.pdf');
      expect(summary.url).toContain('/#/send/acc1/');
    });

    it('createFileSend deletes the orphan send if the blob upload fails', async () => {
      const { service, api } = await makeService();
      stubApi(api).createSendFile = vi.fn(async () => ({ url: '/sends/s9/file/f9', sendResponse: { id: 's9', accessId: 'a9', type: 1, file: { fileName: '2.enc' } } }));
      stubApi(api).uploadSendFileData = vi.fn(async () => { throw new Error('upload boom'); });
      stubApi(api).deleteSend = vi.fn(async () => {});
      const dataB64 = btoa(String.fromCharCode(1, 2, 3));
      await expect(service.createFileSend({ name: 'Doc', deletionDays: 7 }, dataB64, 'f.pdf', 'http://localhost:8080')).rejects.toThrow('upload boom');
      expect(stubApi(api).deleteSend).toHaveBeenCalledWith('access', 's9');
    });

    it('updateSend re-fetches the existing send, PUTs the rebuilt request, and returns the decrypted summary', async () => {
      const { service, api } = await makeService();
      const existing = { id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString, key: FIELD_VECTOR.encString, text: { text: FIELD_VECTOR.encString }, deletionDate: new Date(0).toISOString(), accessCount: 0 };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async () => existing);
      stubApi(api).removeSendPassword = vi.fn(async () => {});
      const summary = await service.updateSend('s1', { name: 'New', text: 'x', passwordMode: 'keep' }, 'http://localhost:8080');
      expect(stubApi(api).updateSend).toHaveBeenCalledWith('access', 's1', expect.objectContaining({ key: existing.key }));
      expect(stubApi(api).removeSendPassword).not.toHaveBeenCalled();
      expect(summary.id).toBe('s1');
    });

    it('updateSend calls removeSendPassword when passwordMode is remove, and throws when the send is gone', async () => {
      const { service, api } = await makeService();
      const existing = { id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString, key: FIELD_VECTOR.encString, text: { text: FIELD_VECTOR.encString }, deletionDate: new Date(0).toISOString(), accessCount: 0 };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async () => existing);
      stubApi(api).removeSendPassword = vi.fn(async () => {});
      await service.updateSend('s1', { name: 'N', passwordMode: 'remove' }, 'http://x');
      expect(stubApi(api).removeSendPassword).toHaveBeenCalledWith('access', 's1');
      stubApi(api).listSends = vi.fn(async () => []);
      await expect(service.updateSend('missing', { name: 'N' }, 'http://x')).rejects.toMatchObject({ code: 'error' });
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

  it('sync computes orgPermissions only for orgs whose key is available and caches them', async () => {
    const sync = await makeOrgSync();
    // Two orgs: 'org-1' has an unwrappable key (buildOrgKeys yields a key for it); 'org-nokey' has a
    // key that fails to unwrap (garbage), so it must be excluded — this falsifies the orgKeys filter.
    // type: 0 (Owner), status: 2 (Confirmed) => canManageCollections is true for the included org.
    sync.profile!.organizations = [
      { id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey, name: 'Org One', type: 0, status: 2 },
      { id: 'org-nokey', key: '4.not-a-real-wrapped-key', name: 'Org No Key', type: 0, status: 2 },
    ];
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    const listing = await service.sync();
    expect(listing.orgPermissions).toEqual([{ id: 'org-1', name: 'Org One', canManageCollections: true }]);
    expect(listing.orgPermissions.some((p) => p.id === 'org-nokey')).toBe(false);
    // listItems() reads it back from cache without a network sync.
    const cached = await service.listItems();
    expect(cached.orgPermissions).toEqual(listing.orgPermissions);
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

  it('updateCipher re-encrypts an org cipher under the ORG key and keeps it org-owned (not corrupted)', async () => {
    const { service, api } = await makeService(await makeOrgSync(), { privateKey: privateKeyBytes });
    await service.sync();
    await service.updateCipher('org-login', { type: 1, name: 'Renamed Org Item', login: { username: 'alice@org.example', password: 'rotated-org-pass' } });
    const [, id, req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(id).toBe('org-login');
    const r = req as { name: string; organizationId?: string; login?: { password?: string } };
    expect(r.organizationId).toBe('org-1');
    // The fields decrypt under the ORG key — proving they were NOT re-encrypted under the account key.
    await expect(decryptToText(r.name, orgKey)).resolves.toBe('Renamed Org Item');
    await expect(decryptToText(r.login!.password!, orgKey)).resolves.toBe('rotated-org-pass');
    await expect(decryptToText(r.name, testUserKey)).rejects.toBeTruthy(); // wrong key cannot read it
  });

  it('shareCipher moves a personal cipher under the org key and assigns collections', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }] },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('My Login', testUserKey),
        login: { username: await encUnder('me@example.com', testUserKey), password: await encUnder('p@ss', testUserKey) },
      }],
    };
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();
    await service.shareCipher('mine', 'org-1', ['col-9']);
    const [, id, body] = (api.shareCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(id).toBe('mine');
    const b = body as { cipher: { name: string; organizationId?: string }; collectionIds: string[] };
    expect(b.collectionIds).toEqual(['col-9']);
    expect(b.cipher.organizationId).toBe('org-1');
    await expect(decryptToText(b.cipher.name, orgKey)).resolves.toBe('My Login'); // re-encrypted under org key
  });

  it('shareCipher refuses items with a passkey or password history to avoid data loss', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }] },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('My Login', testUserKey),
        login: { password: await encUnder('p', testUserKey), fido2Credentials: [{ credentialId: '2.c==', keyValue: '2.k==', rpId: '2.r==' }] },
      }],
    };
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();
    await expect(service.shareCipher('mine', 'org-1', ['col-9'])).rejects.toMatchObject({ code: 'error' });
    expect(api.shareCipher).not.toHaveBeenCalled();
  });

  describe('collection CRUD + membership', () => {
    // Seeds a synced cache with: an org cipher ('orgCipherId', org 'o1'), a personal cipher
    // ('personalCipherId'), a profile org 'o1' the fake private key can unwrap, and cached
    // collections for org 'o1' (sameOrgCollection) and a different org 'o2' (collectionFromOtherOrg).
    async function makeCollectionSync(): Promise<SyncResponse> {
      return {
        profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'o1', key: ORG_KEY_VECTOR.encOrgKey }] },
        ciphers: [
          {
            id: 'orgCipherId', type: 1, favorite: false, organizationId: 'o1',
            name: await encUnder('Org Item', orgKey),
            login: { username: await encUnder('alice@org.example', orgKey), password: await encUnder('org-s3cret', orgKey) },
          },
          {
            id: 'personalCipherId', type: 1, favorite: false, organizationId: null,
            name: await encUnder('Personal Item', testUserKey),
            login: { username: await encUnder('me@example.com', testUserKey), password: await encUnder('p@ss', testUserKey) },
          },
        ],
        collections: [
          { id: 'sameOrgCollection', organizationId: 'o1', name: await encUnder('C', orgKey) },
          { id: 'collectionFromOtherOrg', organizationId: 'o2', name: await encUnder('D', orgKey) },
        ],
      };
    }

    it('createCollection encrypts the name under the org key and re-syncs', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await service.createCollection('o1', 'Shared');
      expect(api.createCollection).toHaveBeenCalledTimes(1);
      const [, orgId, encName] = (api.createCollection as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(orgId).toBe('o1');
      expect(encName).toMatch(/^2\./); // encType=2 EncString
      await expect(decryptToText(encName, orgKey)).resolves.toBe('Shared');
      expect(api.sync).toHaveBeenCalled(); // re-sync after write
    });

    it('renameCollection fetches details then resends preserved access', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      (api.getCollectionDetails as ReturnType<typeof vi.fn>).mockResolvedValue({ groups: [{ id: 'g' }], users: [{ id: 'u' }] });
      await service.renameCollection('o1', 'sameOrgCollection', 'New');
      expect(api.getCollectionDetails).toHaveBeenCalledWith(expect.any(String), 'o1', 'sameOrgCollection');
      const call = (api.updateCollection as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(call[4]).toEqual({ groups: [{ id: 'g' }], users: [{ id: 'u' }] });
      await expect(decryptToText(call[3], orgKey)).resolves.toBe('New');
    });

    it('createCollection throws when the org key is unavailable', async () => {
      const { service } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await expect(service.createCollection('unknown-org', 'X')).rejects.toMatchObject({ message: 'Organization key unavailable' });
    });

    it('deleteCollection calls the API and re-syncs', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await service.deleteCollection('o1', 'sameOrgCollection');
      expect(api.deleteCollection).toHaveBeenCalledWith(expect.any(String), 'o1', 'sameOrgCollection');
      expect(api.sync).toHaveBeenCalled();
    });

    it('setCipherCollections rejects a personal item and a cross-org collection', async () => {
      const { service } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      // personal cipher (no organizationId) in cache:
      await expect(service.setCipherCollections('personalCipherId', ['sameOrgCollection']))
        .rejects.toMatchObject({ message: 'Only organization items can be assigned to collections' });
      // org cipher but a collectionId from another org:
      await expect(service.setCipherCollections('orgCipherId', ['collectionFromOtherOrg']))
        .rejects.toMatchObject({ message: 'Invalid collection for this item' });
    });

    it('setCipherCollections PUTs collectionIds for a valid org item and re-syncs', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await service.setCipherCollections('orgCipherId', ['sameOrgCollection']);
      expect(api.updateCipherCollections).toHaveBeenCalledWith(expect.any(String), 'orgCipherId', ['sameOrgCollection']);
      expect(api.sync).toHaveBeenCalled();
    });
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

  it('updateCipher preserves the passkey the editor does not model, and writes editor-controlled reprompt/fields', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      fido2Credentials: [{ credentialId: '2.cid==', keyValue: '2.kv==', rpId: '2.rp==', counter: '2.ct==' }],
    };
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
    const r = req as { login?: { fido2Credentials?: unknown }; fields?: { type: number }[]; reprompt?: number };
    // Passkey still rides along (the editor doesn't model it).
    expect(r.login?.fido2Credentials).toEqual(sync.ciphers[0]!.login!.fido2Credentials);
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
    await expect(service.importVault('{ not valid json')).rejects.toThrow();
  });

  it('importVault parses a CSV export (logins) and creates a cipher per row', async () => {
    const { service, api } = await makeService();
    const csv = 'name,login_username,login_password,login_uri\nGitHub,octocat,s3cret,https://github.com\nGmail,me@example.com,hunter2,https://mail.google.com\n';
    await expect(service.importVault(csv)).resolves.toBe(2);
    expect(api.createCipher).toHaveBeenCalledTimes(2);
  });

  it('importVault requires a password for an encrypted export', async () => {
    const { service } = await makeService();
    const encrypted = JSON.stringify({ encrypted: true, passwordProtected: true, salt: 'x', kdfIterations: 600000, data: '2.a|b|c' });
    await expect(service.importVault(encrypted)).rejects.toThrow(/password-protected/);
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
    // authData flags live at byte 32: UP=0x01, UV=0x04, BE=0x08, BS=0x10 (vault passkeys are
    // cloud-synced, so BE|BS are always set alongside UP).
    const flags = async (uv?: boolean) => {
      const a = await service.getPasskeyAssertion({ rpId: 'acme.com', origin: 'https://acme.com', challenge, ...(uv === undefined ? {} : { userVerified: uv }) });
      return base64UrlToBytes(a!.authenticatorData)[32]!;
    };
    expect(await flags()).toBe(0x19);       // default: present + BE|BS, NOT verified (no silent UV)
    expect(await flags(false)).toBe(0x19);  // explicit false
    expect(await flags(true)).toBe(0x1d);   // UP | UV | BE | BS when the user was actually verified
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
    const origin = 'https://acme.com';
    expect(await service.hasMatchingPasskey({ rpId: 'acme.com', origin })).toBe(true);
    // 'other.com' is a registrable rpId valid for its own origin, but has no stored passkey.
    expect(await service.hasMatchingPasskey({ rpId: 'other.com', origin: 'https://other.com' })).toBe(false);
    expect(await service.hasMatchingPasskey({ rpId: 'acme.com', allowedCredentialIds: ['cred-1'], origin })).toBe(true);
    expect(await service.hasMatchingPasskey({ rpId: 'acme.com', allowedCredentialIds: ['nope'], origin })).toBe(false);
  });

  describe('passkey rpId/origin trust boundary', () => {
    it('getPasskeyAssertion rejects an rpId that is not valid for the origin', async () => {
      const { service } = await makeServiceWithPasskey({ rpId: 'example.com' });
      await expect(service.getPasskeyAssertion({ rpId: 'example.com', origin: 'https://evil.com', challenge: 'AAAA' }))
        .rejects.toThrow(/rpId is not valid/i);
    });

    it('hasMatchingPasskey rejects a public-suffix rpId', async () => {
      const { service } = await makeServiceWithPasskey({ rpId: 'github.io' });
      await expect(service.hasMatchingPasskey({ rpId: 'github.io', origin: 'https://a.github.io' }))
        .rejects.toThrow(/rpId is not valid/i);
    });

    it('getPasskeyAssertion still signs for a valid rpId/origin', async () => {
      const { service } = await makeServiceWithPasskey({ rpId: 'example.com' });
      const res = await service.getPasskeyAssertion({ rpId: 'example.com', origin: 'https://app.example.com', challenge: 'AAAA' });
      expect(res?.credentialId).toBeTruthy();
    });
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

  it('getPwnedReport dedupes by password, maps counts back per id, and returns no passwords', async () => {
    const enc = async (s: string) => encUnder(s, testUserKey); // existing helper
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await enc('A'), favorite: false, organizationId: null, login: { password: await enc('reused-weak') } },
        { id: 'b', type: 1, name: await enc('B'), favorite: false, organizationId: null, login: { password: await enc('reused-weak') } },
        { id: 'c', type: 1, name: await enc('C'), favorite: false, organizationId: null, login: { password: await enc('unique-safe') } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const entries = await service.getPwnedReport();
    expect(entries).toEqual([{ id: 'a', pwnedCount: 42 }, { id: 'b', pwnedCount: 42 }, { id: 'c', pwnedCount: 0 }]);
    const { pwnedCount } = await import('./pwned.js');
    expect(vi.mocked(pwnedCount).mock.calls.length).toBe(2); // deduped: 'reused-weak' + 'unique-safe'
    expect(JSON.stringify(entries)).not.toContain('reused-weak'); // no password crosses the boundary
  });

  it('findFillItems lists all cards (no URL match), sorted favorite-then-name, without secrets', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'card-b', type: 3, name: await encUnder('Visa B', testUserKey), favorite: false, organizationId: null,
          card: { brand: await encUnder('Visa', testUserKey), number: await encUnder('4111', testUserKey), code: await encUnder('123', testUserKey) } },
        { id: 'card-a', type: 3, name: await encUnder('Amex A', testUserKey), favorite: true, organizationId: null,
          card: { brand: await encUnder('Amex', testUserKey), number: await encUnder('3782', testUserKey), code: await encUnder('999', testUserKey) } },
        { id: 'login-x', type: 1, name: await encUnder('Login', testUserKey), favorite: false, organizationId: null,
          login: { username: await encUnder('u', testUserKey), password: await encUnder('p', testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const items = await service.findFillItems('card');
    expect(items.map((i) => i.id)).toEqual(['card-a', 'card-b']); // favorite first
    expect(items[0]).toMatchObject({ id: 'card-a', name: 'Amex A', subtitle: 'Amex', favorite: true });
    expect(JSON.stringify(items)).not.toContain('3782');
  });

  it('findFillItems throws locked when the vault is locked', async () => {
    const { service, session } = await makeService();
    await service.sync();
    await session.lock();
    await expect(service.findFillItems('identity')).rejects.toMatchObject({ code: 'locked' });
  });

  it('getFillData returns card fields including number/code on explicit fetch', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null,
        card: { number: await encUnder('4111111111111111', testUserKey), code: await encUnder('123', testUserKey), expMonth: await encUnder('9', testUserKey), expYear: await encUnder('2030', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    await expect(service.getFillData('card-1', 'card')).resolves.toEqual({ number: '4111111111111111', code: '123', expMonth: '9', expYear: '2030' });
  });

  it('getFillData omits identity national-ID secrets (ssn/passport/license)', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'id-1', type: 4, name: await encUnder('Me', testUserKey), favorite: false, organizationId: null,
        identity: { firstName: await encUnder('Ada', testUserKey), lastName: await encUnder('Lovelace', testUserKey),
          ssn: await encUnder('999-99-9999', testUserKey), passportNumber: await encUnder('P123', testUserKey), licenseNumber: await encUnder('L123', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const data = await service.getFillData('id-1', 'identity');
    expect(data).toMatchObject({ firstName: 'Ada', lastName: 'Lovelace' });
    expect(JSON.stringify(data)).not.toContain('999-99-9999');
    expect(JSON.stringify(data)).not.toContain('P123');
    expect(JSON.stringify(data)).not.toContain('L123');
  });

  it('getFillData rejects a kind/type mismatch and reprompt items', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null, reprompt: 1,
          card: { number: await encUnder('4111', testUserKey) } },
        { id: 'login-1', type: 1, name: await encUnder('L', testUserKey), favorite: false, organizationId: null,
          login: { password: await encUnder('p', testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const repromptErr = await service.getFillData('card-1', 'card').then(() => null, (e) => e);
    expect(repromptErr).toMatchObject({ code: 'reprompt_required' });
    expect(JSON.stringify(repromptErr)).not.toContain('4111'); // no card number leaks via the thrown value
    await expect(service.getFillData('login-1', 'card')).rejects.toMatchObject({ code: 'denied' });
  });

  describe('passkey registration', () => {
    it('getPasskeyTargets returns same-domain personal logins as {id,name,username} only', async () => {
      const { service } = await makeServiceWithLogins([
        { id: 'c1', name: 'Example', username: 'me', uris: ['https://example.com/login'] },
        { id: 'c2', name: 'Other', username: 'x', uris: ['https://other.com'] },
      ]);
      const targets = await service.getPasskeyTargets({ rpId: 'example.com', origin: 'https://example.com' });
      expect(targets).toEqual([{ id: 'c1', name: 'Example', username: 'me' }]);
    });

    it('getPasskeyTargets rejects a cross-origin rpId', async () => {
      const { service } = await makeServiceWithLogins([]);
      await expect(service.getPasskeyTargets({ rpId: 'example.com', origin: 'https://evil.com' })).rejects.toThrow(/rpId is not valid/i);
    });

    it('createPasskey (new item) POSTs a login with an encrypted fido2Credential and returns an attestation', async () => {
      const createCipher = vi.fn(async (_t: string, req: CipherRequest): Promise<CipherResponse> => ({ id: 'new1', ...req }));
      const { service } = await makeUnlockedService({ api: { createCipher } });
      const reg = await service.createPasskey({ rpId: 'example.com', rpName: 'Example', userHandle: 'dXNlcg', userName: 'me', challenge: 'AAAA', origin: 'https://example.com', userVerified: true });
      expect(reg.publicKeyAlgorithm).toBe(-7);
      expect(reg.credentialId && reg.attestationObject && reg.clientDataJSON && reg.authData && reg.publicKeySpki).toBeTruthy();
      const [, req] = createCipher.mock.calls[0]!;
      expect(req.type).toBe(1);
      expect(req.login?.fido2Credentials).toHaveLength(1);
      expect(req.login?.fido2Credentials?.[0]?.keyValue).toMatch(/^2\./); // an EncString
    });

    it('createPasskey (append) PUTs the original cipher verbatim + [old, new] passkeys, without re-encrypting old fields', async () => {
      const updateCipher = vi.fn(async (_t: string, id: string, req: CipherRequest): Promise<CipherResponse> => ({ id, ...req }));
      const { service, originalRequestSnapshot } = await makeServiceWithExistingPasskeyLogin({ id: 'c1', rpId: 'example.com', api: { updateCipher } });
      const reg = await service.createPasskey({ rpId: 'example.com', userHandle: 'dXNlcg', userName: 'me', challenge: 'AAAA', origin: 'https://example.com', targetCipherId: 'c1' });
      expect(reg.credentialId).toBeTruthy();
      const [, id, req] = updateCipher.mock.calls[0]!;
      expect(id).toBe('c1');
      expect(req.login?.fido2Credentials).toHaveLength(2);
      // old passkey EncStrings are byte-identical to the original (no re-encryption)
      expect(req.login?.fido2Credentials?.[0]).toEqual(originalRequestSnapshot.login.fido2Credentials[0]);
      // other fields carried verbatim from the original CipherResponse
      expect(req.name).toBe(originalRequestSnapshot.name);
      expect(req.login?.password).toBe(originalRequestSnapshot.login.password);
    });

    it('createPasskey (append) encrypts the NEW passkey under the target cipher\'s own per-cipher key (cipherFieldKey), not the raw account UserKey', async () => {
      // Regression coverage for the append branch's key choice. The existing append test above uses a
      // KEYLESS personal cipher, where cipherFieldKey(original) and the account UserKey are the SAME
      // key — it cannot distinguish "encrypted under cipherFieldKey" from "encrypted under UserKey".
      // This fixture gives the target cipher its OWN wrapped per-cipher key, so the assertion below
      // actually pins that cipherFieldKey (the unwrapped per-cipher key), not the raw UserKey, was used.
      const subtle = globalThis.crypto.subtle;
      const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
      const keyValueB64url = bytesToBase64Url(pkcs8);

      // c2's own per-cipher key: a random 64-byte symmetric key, wrapped under the account UserKey the
      // same way a cipher's `key` field is wrapped by its owning key (decrypt.ts:
      // `cipher.key ? unwrapSymmetricKey(cipher.key, baseKey) : baseKey`). wrapAttachmentKey is just
      // `encryptToBytes(raw64Bytes, wrappingKey)` — the same generic wrap operation, reused verbatim.
      const perCipherKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x42));
      const wrappedCipherKey = await wrapAttachmentKey(perCipherKey, testUserKey);

      const existingCred = {
        credentialId: await encUnder('old-cred', perCipherKey),
        keyType: await encUnder('public-key', perCipherKey),
        keyAlgorithm: await encUnder('ECDSA', perCipherKey),
        keyCurve: await encUnder('P-256', perCipherKey),
        keyValue: await encUnder(keyValueB64url, perCipherKey),
        rpId: await encUnder('example.com', perCipherKey),
        counter: await encUnder('0', perCipherKey),
      };
      const cipher = {
        id: 'c2', type: 1 as const, favorite: false, organizationId: null,
        key: wrappedCipherKey,
        name: await encUnder('Keyed Login', perCipherKey),
        login: {
          uris: [{ uri: await encUnder('https://example.com', perCipherKey) }],
          fido2Credentials: [existingCred],
        },
      };
      const updateCipher = vi.fn(async (_t: string, id: string, req: CipherRequest): Promise<CipherResponse> => ({ id, ...req }));
      const sync: SyncResponse = { profile: { id: 'u', email: 'u@example.com' }, ciphers: [cipher] };
      const { service, api } = await makeService(sync);
      Object.assign(api, { updateCipher });
      // sync() populates both VAULT_CACHE_KEY (raw, read by cipherFieldKey) and SUMMARY_CACHE_KEY
      // (decrypted, read by getPasskeyTargets) for c2 — decryption succeeds because decryptCipher
      // itself unwraps cipher.key with the owning (User) key, exactly mirroring what this test seeds.
      await service.sync();

      const reg = await service.createPasskey({ rpId: 'example.com', userHandle: 'dXNlcg', challenge: 'AAAA', origin: 'https://example.com', targetCipherId: 'c2' });
      expect(reg.credentialId).toBeTruthy();

      const [, id, req] = updateCipher.mock.calls[0]!;
      expect(id).toBe('c2');
      expect(req.login?.fido2Credentials).toHaveLength(2);
      // The old credential rides along byte-identical (verbatim carry, no re-encryption).
      expect(req.login?.fido2Credentials?.[0]).toEqual(existingCred);

      const newCred = req.login!.fido2Credentials![1]!;
      // Pins cipherFieldKey: the NEW credential decrypts under the unwrapped per-cipher key...
      await expect(decryptToText(newCred.keyValue!, perCipherKey)).resolves.toMatch(/^[A-Za-z0-9_-]+$/); // base64url PKCS#8
      // ...and FAILS to decrypt under the raw account UserKey — proving the append path did NOT fall
      // back to (or accidentally use) the account key, which would silently corrupt this item.
      await expect(decryptToText(newCred.keyValue!, testUserKey)).rejects.toThrow(EncStringMacError);
    });

    it('createPasskey rejects a targetCipherId that is not a same-domain personal login', async () => {
      const { service } = await makeServiceWithLogins([{ id: 'c2', name: 'Other', username: 'x', uris: ['https://other.com'] }]);
      await expect(service.createPasskey({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com', targetCipherId: 'c2' })).rejects.toThrow(/not a valid target/i);
    });

    it('createPasskey throws when locked', async () => {
      const { service } = await makeLockedService();
      await expect(service.createPasskey({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com' })).rejects.toThrow();
    });

    it('after createPasskey the new passkey is immediately assertable (cache merged, not full sync)', async () => {
      const createCipher = vi.fn(async (_t: string, req: CipherRequest): Promise<CipherResponse> => ({ id: 'new1', ...req }));
      const { service, api } = await makeUnlockedService({ api: { createCipher } });
      await service.sync(); // seed VAULT_CACHE_KEY, as a real caller would have done before offering to register
      const syncCallsBefore = (api.sync as ReturnType<typeof vi.fn>).mock.calls.length;
      await service.createPasskey({ rpId: 'example.com', userHandle: 'dXNlcg', challenge: 'AAAA', origin: 'https://example.com', userVerified: true });
      expect((api.sync as ReturnType<typeof vi.fn>).mock.calls.length).toBe(syncCallsBefore); // no re-sync
      expect(await service.hasMatchingPasskey({ rpId: 'example.com', origin: 'https://example.com' })).toBe(true);
    });
  });
});
