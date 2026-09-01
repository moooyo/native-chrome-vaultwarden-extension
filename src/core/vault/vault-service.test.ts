import { describe, it, expect, vi } from 'vitest';
import type { Mock } from 'vitest';
import { VaultService, type VaultServiceDeps } from './vault-service.js';
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
  pwnedCount: vi.fn(async (pw: string) => {
    if (pw === 'reused-weak') return 42;
    if (pw === 'strong-pwned') return 17;
    return 0;
  }),
}));
import { createMemoryStore, type KeyValueStore } from '../../platform/store.js';
import { SessionManager, type SessionLeaseGate } from '../session/session-manager.js';
import { ApiHttpError, type ApiClient } from '../api/client.js';
import type { AuthService } from '../session/auth-service.js';
import { serializeSymmetricKey, symmetricKeyFromBytes, unwrapSymmetricKey } from '../crypto/keys.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { hexToBytes, base64ToBytes, bytesToBase64, bytesToBase64Url, base64UrlToBytes } from '../crypto/encoding.js';
import { hmacSha256 } from '../crypto/primitives.js';
import { decryptToText, EncStringMacError } from '../crypto/encstring.js';
import * as encstringNs from '../crypto/encstring.js';
import { derToRawSignature } from './fido2.js';
import { generateFido2Keypair, type GeneratedFido2Keypair } from './fido2-create.js';
import { decryptAttachmentFile, encryptAttachmentFile, generateAttachmentKey, wrapAttachmentKey } from './attachments.js';
import { buildTextSendRequest } from './sends.js';
import { FIELD_VECTOR, URL_VECTOR, USER_KEY_VECTOR, RSA_VECTOR, ORG_KEY_VECTOR } from '../../../test/vectors.js';
import type { AttachmentUploadRequest, CipherBulkShareRequest, CipherRequest, CipherResponse, Fido2CredentialData, SendRequest, SyncResponse } from '../api/types.js';
import {
  DERIVED_VAULT_CACHE_KEY,
  RAW_VAULT_CACHE_KEY,
  type RawVaultEnvelope,
} from './vault-cache-repository.js';
import { SECURITY_STAMP_STORAGE_KEY } from './security-stamp-repository.js';
import type { CipherInput, CompleteDecryptedSshKey } from './models.js';
import { AccountLeaseGate, type AccountLease } from '../session/account-gate.js';
import { VaultMutationCoordinator } from './vault-mutation-coordinator.js';
import type { VaultListing } from './vault-service.js';
import { AppError } from '../errors.js';
import { EMPTY_LOGIN_CUSTOM_PLAN } from './login-custom-fields.js';
import { computeLoginUriChecksum } from './login-uri-checksum.js';
import {
  EnterprisePolicyGate,
  EnterprisePolicyType,
} from '../policy/effective-enterprise-policy.js';

const orgKey = symmetricKeyFromBytes(hexToBytes(ORG_KEY_VECTOR.orgKeyHex));
const privateKeyBytes = base64ToBytes(RSA_VECTOR.privateKeyPkcs8B64);
const testUserKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
// RFC 6238 SHA1 seed as base32; at 1111111109s the 6-digit code is 081804.
const TOTP_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// Test-only encType=2 EncString encryptor (fixed IV) for building org-key-protected fixtures.
async function encUnder(plaintext: string, key: SymmetricKey): Promise<string> {
  return encBytesUnder(new TextEncoder().encode(plaintext), key, 0x07);
}

async function encBytesUnder(
  plaintext: Uint8Array,
  key: SymmetricKey,
  ivByte: number,
): Promise<string> {
  const subtle = globalThis.crypto.subtle;
  const iv = new Uint8Array(16).fill(ivByte);
  const cryptoKey = await subtle.importKey('raw', key.encKey as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, cryptoKey, plaintext as BufferSource));
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const mac = await hmacSha256(key.macKey, macData);
  return `2.${bytesToBase64(iv)}|${bytesToBase64(ct)}|${bytesToBase64(mac)}`;
}

async function validSendKeyEncString(): Promise<string> {
  return encUnder('0123456789abcdef', testUserKey);
}

async function completeFido2Credential(
  partial: Fido2CredentialData,
  key: SymmetricKey,
): Promise<Fido2CredentialData> {
  const [keyType, keyAlgorithm, keyCurve, discoverable] = await Promise.all([
    encUnder('public-key', key),
    encUnder('ECDSA', key),
    encUnder('P-256', key),
    encUnder('true', key),
  ]);
  return {
    keyType,
    keyAlgorithm,
    keyCurve,
    discoverable,
    creationDate: '2026-08-30T00:00:00Z',
    ...partial,
  };
}

async function makeOrgSync(): Promise<SyncResponse> {
  return {
    profile: {
      id: 'u',
      email: 'u@example.com',
      organizations: [{
        id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey, status: 2, type: 2, enabled: true,
      }],
    },
    ciphers: [{
      id: 'org-login',
      type: 1,
      name: await encUnder('Org Login', orgKey),
      favorite: false,
      organizationId: 'org-1',
      edit: true,
      viewPassword: true,
      organizationUseTotp: true,
      permissions: { delete: true, restore: true },
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

interface MakeServiceOptions {
  privateKey?: Uint8Array;
  now?: () => number;
  getIdentityEpoch?: () => number;
  rejectDerivedWrites?: boolean;
  beforeDerivedWrite?: () => Promise<void>;
  beforeRequestGuard?: (method: string) => Promise<void>;
  rejectRawWrite?: () => boolean;
  onPolicySnapshotPublished?: () => Promise<void>;
  sessionGate?: SessionLeaseGate;
  parseImport?: (content: string, password?: string) => Promise<CipherInput[]>;
  authorizeSshCipherType5Write?: () => PromiseLike<{ assertCurrent(): void }>;
  authorizeCipherArchive?: () => { assertCurrent(): void } | PromiseLike<{ assertCurrent(): void }>;
  generateSshKey?: () => CompleteDecryptedSshKey;
  importSshPrivateKey?: (privateKey: string) => Promise<CompleteDecryptedSshKey>;
  generateFido2Keypair?: () => Promise<GeneratedFido2Keypair>;
  beforeHttpAuthCredentialDecrypt?: () => Promise<void>;
  onManualAutofillFieldKeyDisposed?: (zeroized: boolean) => void;
  organizationDataOwnershipServerKind?: 'bitwarden' | 'vaultwarden';
  authorizeCollectionNameOnlyUpdate?: () => PromiseLike<{ assertCurrent(): void }>;
  accountGate?: AccountLeaseGate;
  executeAuthenticatedRequest?: AuthService['executeAuthenticatedRequest'];
  onSecurityStampMismatch?: VaultServiceDeps['onSecurityStampMismatch'];
  localStore?: KeyValueStore;
  sessionStore?: KeyValueStore;
}

async function makeOrganizationCreateSync(): Promise<SyncResponse> {
  return {
    profile: {
      id: 'u',
      email: 'u@example.com',
      premium: true,
      organizations: [
        { id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey },
        { id: 'org-2', key: ORG_KEY_VECTOR.encOrgKey },
      ],
      organizationsNew: [
        { id: 'org-1', name: 'Engineering', status: 2, type: 2, enabled: true },
        { id: 'org-2', name: 'Operations', status: 2, type: 2, enabled: true },
      ],
    },
    collections: [
      {
        id: 'collection-1',
        organizationId: 'org-1',
        name: await encUnder('Engineering shared', orgKey),
        assigned: true,
        readOnly: false,
      },
      {
        id: 'collection-read-only',
        organizationId: 'org-1',
        name: await encUnder('Read only', orgKey),
        assigned: true,
        readOnly: true,
      },
      {
        id: 'collection-unassigned',
        organizationId: 'org-1',
        name: await encUnder('Unassigned', orgKey),
        assigned: false,
        readOnly: false,
      },
      {
        id: 'collection-2',
        organizationId: 'org-2',
        name: await encUnder('Operations shared', orgKey),
        assigned: true,
        readOnly: false,
      },
    ],
    ciphers: [],
  };
}

async function makeInteractiveCustomLoginSync(): Promise<SyncResponse> {
  return {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'custom-login',
      type: 1,
      name: await encUnder('Custom login', testUserKey),
      favorite: false,
      organizationId: null,
      login: {
        username: await encUnder('ada', testUserKey),
        password: await encUnder('secret', testUserKey),
        totp: await encUnder(TOTP_SECRET_B32, testUserKey),
        uris: [{ uri: await encUnder('https://example.com/login', testUserKey), match: UriMatchStrategy.Domain }],
      },
      fields: [
        { type: 0, name: await encUnder('department', testUserKey), value: await encUnder('engineering', testUserKey) },
        { type: 1, name: await encUnder('access-code', testUserKey), value: await encUnder('hidden-value', testUserKey) },
        { type: 2, name: await encUnder('enabled', testUserKey), value: await encUnder('true', testUserKey) },
        { type: 3, name: await encUnder('login-alias', testUserKey), value: null, linkedId: 100 },
        { type: 3, name: await encUnder('password-alias', testUserKey), value: null, linkedId: 101 },
        { type: 3, name: await encUnder('unknown-link', testUserKey), value: null, linkedId: 999 },
        { type: 0, name: await encUnder('duplicate', testUserKey), value: await encUnder('first', testUserKey) },
        { type: 0, name: await encUnder('duplicate', testUserKey), value: await encUnder('second', testUserKey) },
        { type: 0, name: await encUnder('ID=employee-code', testUserKey), value: await encUnder('E-42', testUserKey) },
        { type: 0, name: await encUnder('label=Tenant', testUserKey), value: await encUnder('north', testUserKey) },
        { type: 0, name: await encUnder('placeholder=Workspace', testUserKey), value: await encUnder('platform', testUserKey) },
        { type: 1, name: await encUnder('regex=.*', testUserKey), value: await encUnder('must-not-fill', testUserKey) },
        { type: 0, name: await encUnder('unused', testUserKey), value: await encUnder('must-not-decrypt', testUserKey) },
      ],
    }],
  };
}

function withEnterprisePolicies(
  response: SyncResponse,
  policies: Array<{
    type: number;
    data?: unknown;
    organizationId?: string;
    revisionDate?: string;
  }>,
): SyncResponse {
  return {
    ...response,
    profile: {
      ...response.profile,
      organizationsNew: [{
        id: 'policy-org',
        key: null,
        status: 2,
        type: 2,
        enabled: true,
        usePolicies: true,
      }],
    },
    policiesNew: policies.map((entry, index) => ({
      id: `policy-${index}`,
      organizationId: entry.organizationId ?? 'policy-org',
      type: entry.type,
      enabled: true,
      ...(entry.data === undefined ? {} : { data: entry.data }),
      ...(entry.revisionDate === undefined ? {} : { revisionDate: entry.revisionDate }),
    })),
  };
}

async function makeService(syncResponse = makeSync(), opts: MakeServiceOptions = {}) {
  const baseLocalStore = opts.localStore ?? createMemoryStore();
  const localStore = opts.rejectRawWrite ? {
    ...baseLocalStore,
    async set(key: string, value: unknown): Promise<void> {
      if (key === RAW_VAULT_CACHE_KEY && opts.rejectRawWrite?.()) {
        throw new Error('raw cache write failed');
      }
      await baseLocalStore.set(key, value);
    },
  } : baseLocalStore;
  const baseSessionStore = opts.sessionStore ?? createMemoryStore();
  const sessionStore = opts.rejectDerivedWrites || opts.beforeDerivedWrite ? {
    ...baseSessionStore,
    async set(key: string, value: unknown): Promise<void> {
      if (key === DERIVED_VAULT_CACHE_KEY && opts.rejectDerivedWrites) throw new Error('QUOTA_BYTES exceeded');
      if (key === DERIVED_VAULT_CACHE_KEY && opts.beforeDerivedWrite) await opts.beforeDerivedWrite();
      await baseSessionStore.set(key, value);
    },
  } : baseSessionStore;
  const sm = new SessionManager({ localStore, sessionStore });
  await sm.saveUnlocked({
    email: 'u@example.com',
    accessToken: 'access',
    refreshToken: 'refresh',
    expiresAt: 999999,
    protectedKey: USER_KEY_VECTOR.akey,
    kdf: 0,
    kdfIterations: 5000,
    userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
    ...(opts.privateKey ? { privateKey: opts.privateKey } : {}),
  });
  let attachmentSequence = 0;
  const api = {
    sync: vi.fn(async () => syncResponse),
    createFolder: vi.fn(async () => ({ id: 'new-folder', name: '2.enc' })),
    updateFolder: vi.fn(async () => ({ id: 'f1', name: '2.enc' })),
    deleteFolder: vi.fn(async () => {}),
    createCipher: vi.fn(async () => ({ id: 'new-cipher', type: 1, name: '2.enc' })),
    createOrganizationCipher: vi.fn(async (_token: string, cipher: CipherRequest) => ({
      id: 'new-org-cipher',
      ...cipher,
    })),
    updateCipher: vi.fn(async () => ({ id: 'cipher-1', type: 1, name: '2.enc' })),
    updateCipherPartial: vi.fn(async (
      _token: string,
      id: string,
      partial: { folderId: string | null; favorite: boolean },
    ) => {
      const matches = syncResponse.ciphers.filter((cipher) => cipher.id === id);
      if (matches.length !== 1) throw new Error('partial-update fixture cipher is unavailable');
      matches[0]!.folderId = partial.folderId;
      matches[0]!.favorite = partial.favorite;
      return { ...matches[0]! };
    }),
    shareCipher: vi.fn(async (
      _token: string,
      id: string,
      body: { cipher: CipherRequest; collectionIds: string[] },
    ) => {
      const index = syncResponse.ciphers.findIndex((cipher) => cipher.id === id);
      if (index < 0) throw new Error('share fixture cipher is missing');
      const original = syncResponse.ciphers[index]!;
      const { attachments2, lastKnownRevisionDate: _lastKnownRevisionDate, ...cipher } = body.cipher;
      const attachments = original.attachments?.map((attachment) => {
        const updated = attachments2?.[attachment.id];
        return updated ? { ...attachment, ...updated } : attachment;
      });
      const shared: CipherResponse = {
        ...original,
        ...cipher,
        id,
        organizationId: body.cipher.organizationId ?? null,
        collectionIds: [...body.collectionIds],
        edit: true,
        viewPassword: true,
        ...(attachments === undefined ? {} : { attachments }),
      };
      delete shared.data;
      syncResponse.ciphers[index] = shared;
      const { collectionIds: _collectionIds, ...receipt } = shared;
      return receipt as CipherResponse;
    }),
    shareCiphers: vi.fn(async (_token: string, body: CipherBulkShareRequest) => {
      for (const requested of body.ciphers) {
        const index = syncResponse.ciphers.findIndex((cipher) => cipher.id === requested.id);
        if (index < 0) throw new Error('bulk-share fixture cipher is missing');
        const original = syncResponse.ciphers[index]!;
        const {
          id,
          encryptedFor: _encryptedFor,
          attachments2,
          lastKnownRevisionDate: _lastKnownRevisionDate,
          ...cipher
        } = requested;
        const attachments = original.attachments?.map((attachment) => {
          const updated = attachments2?.[attachment.id];
          return updated ? { ...attachment, ...updated } : attachment;
        });
        const shared: CipherResponse = {
          ...original,
          ...cipher,
          id,
          organizationId: requested.organizationId,
          collectionIds: [...body.collectionIds],
          edit: true,
          viewPassword: true,
          ...(attachments === undefined ? {} : { attachments }),
        };
        delete shared.data;
        syncResponse.ciphers[index] = shared;
      }
      return undefined;
    }),
    revokeCurrentOrganizationMembership: vi.fn(async (_token: string, organizationId: string) => {
      syncResponse.profile.organizations = (syncResponse.profile.organizations ?? [])
        .filter((organization) => organization.id !== organizationId);
      syncResponse.profile.organizationsNew = (syncResponse.profile.organizationsNew ?? [])
        .filter((organization) => organization.id !== organizationId);
      syncResponse.profile.providerOrganizations = (syncResponse.profile.providerOrganizations ?? [])
        .filter((organization) => organization.id !== organizationId);
      syncResponse.policiesNew = (syncResponse.policiesNew ?? [])
        .filter((policy) => policy.organizationId !== organizationId);
      syncResponse.policies = (syncResponse.policies ?? [])
        .filter((policy) => policy.organizationId !== organizationId);
    }),
    createCollection: vi.fn(async () => ({ id: 'new-collection', name: '2.enc' })),
    getCollectionDetails: vi.fn(async (_token: string, organizationId: string, id: string) => ({
      id,
      organizationId,
      groups: [],
      users: [],
      externalId: syncResponse.collections?.find((collection) => collection.id === id)?.externalId ?? null,
    })),
    updateCollection: vi.fn(async (
      _token: string,
      organizationId: string,
      id: string,
      name: string,
      access: { externalId: string | null },
    ) => {
      const collection = syncResponse.collections?.find((entry) => entry.id === id);
      if (collection) Object.assign(collection, { organizationId, name, externalId: access.externalId });
      return { id, organizationId, name, externalId: access.externalId };
    }),
    updateCollectionName: vi.fn(async (
      _token: string,
      organizationId: string,
      id: string,
      name: string,
      externalId: string | null,
    ) => {
      const collection = syncResponse.collections?.find((entry) => entry.id === id);
      if (collection) Object.assign(collection, { organizationId, name, externalId });
      return { id, organizationId, name, externalId };
    }),
    deleteCollection: vi.fn(async (_token: string, _organizationId: string, id: string) => {
      syncResponse.collections = (syncResponse.collections ?? []).filter((entry) => entry.id !== id);
    }),
    updateCipherCollections: vi.fn(async (_token: string, id: string, collectionIds: string[]) => {
      const cipher = syncResponse.ciphers.find((entry) => entry.id === id);
      if (cipher) cipher.collectionIds = [...collectionIds];
    }),
    deleteCipher: vi.fn(async () => {}),
    softDeleteCipher: vi.fn(async () => {}),
    restoreCipher: vi.fn(async () => {}),
    archiveCiphers: vi.fn(async () => []),
    unarchiveCiphers: vi.fn(async () => []),
    getAttachmentDownloadUrl: vi.fn(async (_token: string, _cipherId: string, attachmentId: string) => (
      `https://files.example/${attachmentId}`
    )),
    downloadAttachment: vi.fn(async () => new Uint8Array()),
    createAttachmentUploadSlot: vi.fn(async (
      _token: string,
      cipherId: string,
      request: AttachmentUploadRequest,
    ) => {
      const cipher = syncResponse.ciphers.find((entry) => entry.id === cipherId);
      if (!cipher) throw new Error('attachment fixture cipher is missing');
      const attachmentId = `new-attachment-${++attachmentSequence}`;
      const attachment = {
        id: attachmentId,
        key: request.key,
        fileName: request.fileName,
        size: String(request.fileSize),
      };
      cipher.attachments = [...(cipher.attachments ?? []), attachment];
      return {
        attachmentId,
        fileUploadType: 0 as const,
        cipherResponse: { ...cipher, attachments: [...cipher.attachments] },
      };
    }),
    uploadAttachmentSlotData: vi.fn(async () => {}),
    uploadAttachment: vi.fn(async () => ({ id: 'cipher-1', type: 1, name: '2.enc' })),
    deleteAttachment: vi.fn(async (_token: string, cipherId: string, attachmentId: string) => {
      const cipher = syncResponse.ciphers.find((entry) => entry.id === cipherId);
      if (cipher?.attachments) {
        cipher.attachments = cipher.attachments.filter((attachment) => attachment.id !== attachmentId);
      }
    }),
    listSends: vi.fn(async () => []),
    createSend: vi.fn(async (_t: string, send: unknown) => ({ id: 's1', accessId: 'acc1', ...(send as object) })),
    deleteSend: vi.fn(async () => {}),
  } as unknown as ApiClient;
  stubApi(api).forServer = vi.fn(() => api);
  stubApi(api).withRequestGuard = vi.fn((assertCurrent: () => void) => new Proxy(api, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown;
      if (typeof value !== 'function' || property === 'withRequestGuard') return value;
      return async (...args: unknown[]) => {
        if (opts.beforeRequestGuard) await opts.beforeRequestGuard(String(property));
        assertCurrent();
        return Reflect.apply(value, target, args);
      };
    },
  }));
  const auth = {
    refreshIfNeeded: vi.fn(async () => {}),
    executeAuthenticatedRequest: opts.executeAuthenticatedRequest ?? (async <Result>(
      _accountLease: AccountLease,
      rebuildRequest: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      const current = await sm.getActiveAuth();
      if (!current) throw new Error('test auth is unavailable');
      return rebuildRequest(current.accessToken);
    }),
    // Reprompt verification: only 'correct-master' is accepted, like a real master-password check.
    verifyMasterPassword: vi.fn(async (pw: string) => pw === 'correct-master'),
  } as unknown as AuthService;
  const deps = {
    api, auth, session: sm, localStore, sessionStore,
    getVaultIdentity: () => 'https://vault.example\nu@example.com',
    accountGate: opts.accountGate ?? (() => {
      const gate = new AccountLeaseGate();
      gate.initialize({ serverUrl: 'https://vault.example', accountIdentity: 'u@example.com' });
      return gate;
    })(),
    sessionGate: opts.sessionGate ?? {
      capture: () => ({ generation: 0 }),
      assert: () => {},
    },
    getIdentityEpoch: opts.getIdentityEpoch ?? (() => 0),
    policyGate: new EnterprisePolicyGate(),
    authorizeOrganizationDataOwnershipTransport: async () => ({
      serverKind: opts.organizationDataOwnershipServerKind ?? 'bitwarden',
      assertCurrent: vi.fn(),
    }),
    authorizeCollectionNameOnlyUpdate: opts.authorizeCollectionNameOnlyUpdate
      ?? (async () => ({ assertCurrent: vi.fn() })),
    onSecurityStampMismatch: opts.onSecurityStampMismatch ?? vi.fn(async () => {}),
    ...(opts.onPolicySnapshotPublished
      ? { onPolicySnapshotPublished: opts.onPolicySnapshotPublished }
      : {}),
    ...(opts.parseImport ? { parseImport: opts.parseImport } : {}),
    ...(opts.now ? { now: opts.now } : {}),
    ...(opts.authorizeSshCipherType5Write
      ? { authorizeSshCipherType5Write: opts.authorizeSshCipherType5Write }
      : {}),
    ...(opts.authorizeCipherArchive
      ? { authorizeCipherArchive: opts.authorizeCipherArchive }
      : {}),
    ...(opts.generateSshKey ? { generateSshKey: opts.generateSshKey } : {}),
    ...(opts.importSshPrivateKey ? { importSshPrivateKey: opts.importSshPrivateKey } : {}),
    ...(opts.generateFido2Keypair ? { generateFido2Keypair: opts.generateFido2Keypair } : {}),
    ...(opts.beforeHttpAuthCredentialDecrypt
      ? { beforeHttpAuthCredentialDecrypt: opts.beforeHttpAuthCredentialDecrypt }
      : {}),
    ...(opts.onManualAutofillFieldKeyDisposed
      ? { onManualAutofillFieldKeyDisposed: opts.onManualAutofillFieldKeyDisposed }
      : {}),
  };
  const accountGate = deps.accountGate;
  const coordinator = new VaultMutationCoordinator<string, AccountLease, VaultListing, string, string>({
    captureLease: () => accountGate.capture(),
    assertLease: (_account, lease) => accountGate.assert(lease),
  });
  return {
    service: new VaultService({ ...deps, coordinator }),
    api,
    session: sm,
    auth,
    localStore,
    sessionStore,
    policyGate: deps.policyGate,
  };
}

function commitCipherUpdatesToSync(api: ApiClient, syncResponse: SyncResponse): void {
  vi.mocked(api.updateCipher).mockImplementation(async (_token, id, request) => {
    const index = syncResponse.ciphers.findIndex((cipher) => cipher.id === id);
    if (index < 0) throw new Error('update fixture cipher is missing');
    const existing = syncResponse.ciphers[index]!;
    const { lastKnownRevisionDate: _lastKnownRevisionDate, ...updatedFields } = request;
    const parsedRevision = Date.parse(existing.revisionDate ?? '');
    const revisionDate = Number.isFinite(parsedRevision)
      ? new Date(parsedRevision + 1_000).toISOString()
      : '2026-09-01T00:00:00.000Z';
    const updated: CipherResponse = { ...existing, ...updatedFields, id, revisionDate };
    delete updated.data;
    syncResponse.ciphers[index] = updated;
    return { ...updated };
  });
}

const ODO_POPUP_DOCUMENT_ID = 'odo-popup-document';
const ODO_AUTHORIZATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function dataOwnershipBinding(
  service: VaultService,
  operation: 'migrate' | 'leave' = 'migrate',
): Promise<string> {
  const status = await service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID);
  if (status.status !== 'migration_available' && status.status !== 'blocked') {
    throw new Error('Expected an actionable organization data ownership status');
  }
  if (operation === 'leave') return status.leaveAuthorization.authorizationId;
  if (status.status !== 'migration_available') throw new Error('Expected a migration authorization');
  return status.migrateAuthorization.authorizationId;
}

async function addWritableShareTarget(
  sync: SyncResponse,
  organizationId = 'org-1',
  collectionId = 'col-9',
): Promise<void> {
  const existing = sync.profile.organizations?.find((organization) => (
    organization.id === organizationId
  ));
  sync.profile.organizations = [{
    ...existing,
    id: organizationId,
    key: existing?.key ?? ORG_KEY_VECTOR.encOrgKey,
    status: 2,
    type: existing?.type ?? 2,
    enabled: true,
  }];
  sync.collections = [
    ...(sync.collections ?? []).filter((collection) => collection.id !== collectionId),
    {
      id: collectionId,
      organizationId,
      name: await encUnder(`Collection ${collectionId}`, orgKey),
      readOnly: false,
      assigned: true,
    },
  ];
}

async function addDataOwnershipTransfer(
  sync: SyncResponse,
  organizationId = 'org-1',
  collectionId = 'default-collection',
): Promise<void> {
  for (const cipher of sync.ciphers) {
    if (cipher.organizationId == null && !cipher.revisionDate) {
      cipher.revisionDate = '2026-08-30T00:00:00.000Z';
    }
  }
  await addWritableShareTarget(sync, organizationId, collectionId);
  const collection = sync.collections?.find((entry) => entry.id === collectionId);
  if (!collection) throw new Error('Expected data-ownership collection fixture');
  collection.type = 1;
  sync.profile.organizationsNew = [{
    id: organizationId,
    name: 'Engineering',
    status: 2,
    type: 2,
    enabled: true,
    usePolicies: true,
  }];
  sync.policiesNew = [{
    id: 'data-ownership-transfer',
    organizationId,
    type: EnterprisePolicyType.OrganizationDataOwnership,
    enabled: true,
    data: { enableIndividualItemsTransfer: true },
    revisionDate: '2026-08-30T00:00:00.000Z',
  }];
}

interface KeyedShareFixture {
  sync: SyncResponse;
  perCipherKey: SymmetricKey;
  wrappedCipherKey: string;
  passkey: Fido2CredentialData;
  history: NonNullable<CipherResponse['passwordHistory']>;
  attachmentFileName: string;
  wrappedAttachmentKey: string;
}

async function makeKeyedAdvancedShareSync(): Promise<KeyedShareFixture> {
  const perCipherKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x53));
  const wrappedCipherKey = await wrapAttachmentKey(perCipherKey, testUserKey);
  const attachmentKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x72));
  const attachmentFileName = await encUnder('passkey-backup.txt', perCipherKey);
  const wrappedAttachmentKey = await wrapAttachmentKey(attachmentKey, perCipherKey);
  const passkey = await completeFido2Credential({
    credentialId: await encUnder('credential-id', perCipherKey),
    keyValue: await encUnder('private-key', perCipherKey),
    rpId: await encUnder('example.com', perCipherKey),
    counter: await encUnder('0', perCipherKey),
  }, perCipherKey);
  const history = [{
    password: await encUnder('old-password', perCipherKey),
    lastUsedDate: '2025-01-01T00:00:00.000Z',
  }];
  const sync: SyncResponse = {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'mine', type: 1, favorite: false, organizationId: null,
      key: wrappedCipherKey,
      name: await encUnder('My Login', perCipherKey),
      login: { password: await encUnder('p', perCipherKey), fido2Credentials: [passkey] },
      passwordHistory: history,
      attachments: [{
        id: 'attachment-1',
        fileName: attachmentFileName,
        key: wrappedAttachmentKey,
        size: '42',
      }],
    }],
  };
  await addWritableShareTarget(sync);
  return {
    sync,
    perCipherKey,
    wrappedCipherKey,
    passkey,
    history,
    attachmentFileName,
    wrappedAttachmentKey,
  };
}

/** Simulates a cold worker start with an encrypted raw sync envelope but no derived snapshot. */
async function makeServiceWithRaw(
  syncResponse = makeSync(),
  opts: MakeServiceOptions = {},
) {
  const setup = await makeService(syncResponse, opts);
  await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
    schemaVersion: 2,
    identity: 'https://vault.example\nu@example.com',
    rawGeneration: 'preloaded-raw-generation',
    response: syncResponse,
  });
  await setup.service.initializeCache();
  return setup;
}

const EVENT_USER_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const EVENT_LEGACY_ORG_ID = '11111111-1111-4111-8111-111111111111';
const EVENT_ENABLED_ORG_ID = '22222222-2222-4222-8222-222222222222';
const EVENT_OPT_OUT_ORG_ID = '33333333-3333-4333-8333-333333333333';
const EVENT_ACCEPTED_ORG_ID = '44444444-4444-4444-8444-444444444444';
const EVENT_DISABLED_ORG_ID = '55555555-5555-4555-8555-555555555555';
const EVENT_PROVIDER_ORG_ID = '66666666-6666-4666-8666-666666666666';
const EVENT_ENABLED_CIPHER_ID = '77777777-7777-4777-8777-777777777777';
const EVENT_PROVIDER_CIPHER_ID = '88888888-8888-4888-8888-888888888888';
const EVENT_PERSONAL_CIPHER_ID = '99999999-9999-4999-8999-999999999999';

function makeClientEventAuthoritySync(): SyncResponse {
  return {
    profile: {
      id: EVENT_USER_ID,
      email: 'u@example.com',
      organizations: [{
        id: EVENT_LEGACY_ORG_ID,
        status: 2,
        enabled: true,
        useEvents: true,
      }],
      organizationsNew: [
        { id: EVENT_ENABLED_ORG_ID, status: 2, enabled: true, useEvents: true },
        { id: EVENT_OPT_OUT_ORG_ID, status: 2, enabled: true, useEvents: false },
        { id: EVENT_ACCEPTED_ORG_ID, status: 1, enabled: true, useEvents: true },
        { id: EVENT_DISABLED_ORG_ID, status: 2, enabled: false, useEvents: true },
      ],
      providerOrganizations: [
        { id: EVENT_PROVIDER_ORG_ID, status: 2, enabled: true, useEvents: true },
        { id: EVENT_ENABLED_ORG_ID, status: 2, enabled: true, useEvents: false },
      ],
    },
    ciphers: [
      { id: EVENT_ENABLED_CIPHER_ID, type: 1, organizationId: EVENT_ENABLED_ORG_ID },
      { id: EVENT_PROVIDER_CIPHER_ID, type: 1, organizationId: EVENT_PROVIDER_ORG_ID },
      { id: EVENT_PERSONAL_CIPHER_ID, type: 2, organizationId: null },
    ],
  };
}

function replacePolicyGate(
  gate: EnterprisePolicyGate,
  response: SyncResponse,
  rawGeneration: string,
): void {
  const current = gate.capture();
  gate.replace({
    response,
    accountLease: {
      serverGeneration: current.serverGeneration,
      accountGeneration: current.accountGeneration,
      serverUrl: current.serverUrl,
      accountIdentity: current.accountIdentity,
    },
    rawGeneration,
  });
}

function makeUnknownCipherSync(): SyncResponse {
  return {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'future-6',
      type: 6,
      name: '2.opaque-name',
      favorite: false,
      organizationId: null,
      fields: [{ type: 1, name: '2.opaque-field-name', value: '2.opaque-field-value' }],
      passwordHistory: [{ password: '2.opaque-history' }],
      attachments: [{
        id: 'future-attachment',
        url: 'https://files.example/future',
        key: '2.opaque-attachment-key',
        fileName: '2.opaque-file-name',
      }],
      bankAccount: { accountNumber: '2.opaque-account-number' },
    }],
  };
}

/** Seeds a personal login cipher with one fido2Credential at `opts.rpId`, backed by a real ECDSA
 *  key pair so a signing test can verify the returned assertion. Mirrors the fixture used by the
 *  existing "signs a passkey assertion" test above. */
async function makeServiceWithPasskey(opts: {
  rpId: string;
  counter?: string | null;
  omitCounter?: boolean;
  rawCounter?: string;
  revisionDate?: string;
}) {
  const subtle = globalThis.crypto.subtle;
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  const keyValueB64url = bytesToBase64Url(pkcs8);
  const sync: SyncResponse = {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'pk', type: 1, name: await encUnder('Acme', testUserKey), favorite: false, organizationId: null,
      login: { fido2Credentials: [await completeFido2Credential({
        credentialId: await encUnder('cred-1', testUserKey),
        keyValue: await encUnder(keyValueB64url, testUserKey),
        rpId: await encUnder(opts.rpId, testUserKey),
        ...(opts.omitCounter
          ? {}
          : {
              counter: opts.rawCounter
                ?? (opts.counter === null ? null : await encUnder(opts.counter ?? '0', testUserKey)),
            }),
      }, testUserKey)] },
      ...(opts.revisionDate ? { revisionDate: opts.revisionDate } : {}),
    }],
  };
  const setup = await makeService(sync);
  await setup.service.sync();
  return { ...setup, pair, sync };
}

/** Seeds one personal login cipher per entry and syncs the raw plus derived cache snapshots. */
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
  const setup = await makeService(sync);
  await setup.service.sync();
  return { ...setup, sync };
}

/** An already-unlocked service with no vault synced yet (for createPasskey 'new item' tests). Lets the
 *  caller override individual api methods (e.g. createCipher) to capture the request shape. */
async function makeUnlockedService(opts: {
  api?: Record<string, unknown>;
  now?: () => number;
} = {}) {
  const { service, api } = await makeServiceWithRaw(
    makeSync(),
    opts.now ? { now: opts.now } : {},
  );
  if (opts.api) Object.assign(api, opts.api);
  return { service, api };
}

/** A locked service (persisted auth exists, but the session UserKey has been cleared). */
async function makeLockedService() {
  const { service, session } = await makeService();
  await session.lock();
  return { service };
}

function pauseNextPrivateKeyLoad(session: SessionManager): { started: Promise<void>; release(): void } {
  const original = session.loadPrivateKey.bind(session);
  let first = true;
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(session, 'loadPrivateKey').mockImplementation(async () => {
    if (first) {
      first = false;
      markStarted();
      await gate;
    }
    return original();
  });
  return { started, release };
}

function pauseNextUserKeyLoad(session: SessionManager): { started: Promise<void>; release(): void } {
  const original = session.loadUserKey.bind(session);
  let first = true;
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(session, 'loadUserKey').mockImplementation(async () => {
    if (first) {
      first = false;
      markStarted();
      await gate;
    }
    return original();
  });
  return { started, release };
}

/** Seeds a personal login cipher (id `opts.id`) that already carries one encrypted fido2Credential at
 *  `opts.rpId`, plus a password/uri, and syncs so the raw CipherResponse is cached. Returns the service
 *  and a snapshot of the fixture's own EncStrings to compare the PUT request against verbatim. */
async function makeServiceWithExistingPasskeyLogin(opts: { id: string; rpId: string; api?: Record<string, unknown> }) {
  const subtle = globalThis.crypto.subtle;
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  const keyValueB64url = bytesToBase64Url(pkcs8);
  const existingCred = await completeFido2Credential({
    credentialId: await encUnder('old-cred', testUserKey),
    keyType: await encUnder('public-key', testUserKey),
    keyAlgorithm: await encUnder('ECDSA', testUserKey),
    keyCurve: await encUnder('P-256', testUserKey),
    keyValue: await encUnder(keyValueB64url, testUserKey),
    rpId: await encUnder(opts.rpId, testUserKey),
    counter: await encUnder('0', testUserKey),
  }, testUserKey);
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
  return { service, api, sync, existingCred, originalRequestSnapshot };
}

describe('VaultService', () => {
  describe('security stamp revocation guard', () => {
    it('durably seeds a fresh response baseline before publishing raw or derived cache data', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = 'stamp-a';
      const baseStore = createMemoryStore();
      const writes: string[] = [];
      const localStore: KeyValueStore = {
        ...baseStore,
        async set(key, value) {
          writes.push(key);
          await baseStore.set(key, value);
        },
      };
      const { service, sessionStore } = await makeService(sync, { localStore });

      await service.sync();

      expect(writes.indexOf(SECURITY_STAMP_STORAGE_KEY)).toBeGreaterThanOrEqual(0);
      expect(writes.indexOf(SECURITY_STAMP_STORAGE_KEY)).toBeLessThan(
        writes.indexOf(RAW_VAULT_CACHE_KEY),
      );
      await expect(localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toMatchObject({
        schemaVersion: 1,
        baselines: [{
          serverUrl: 'https://vault.example/',
          profileId: 'u',
          securityStamp: 'stamp-a',
        }],
      });
      await expect(localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeDefined();
      await expect(sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeDefined();
    });

    it('rejects a changed stamp without overwriting its baseline or cache generation', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = 'stamp-a';
      const onSecurityStampMismatch = vi.fn(async (
        _authority: Parameters<VaultServiceDeps['onSecurityStampMismatch']>[0],
      ) => {});
      const setup = await makeService(sync, { onSecurityStampMismatch });
      await setup.service.sync();
      const baseline = await setup.localStore.get(SECURITY_STAMP_STORAGE_KEY);
      const raw = await setup.localStore.get(RAW_VAULT_CACHE_KEY);
      const derived = await setup.sessionStore.get(DERIVED_VAULT_CACHE_KEY);
      sync.profile.securityStamp = 'stamp-b';
      sync.ciphers = [];

      await expect(setup.service.sync()).rejects.toMatchObject({ code: 'session_expired' });

      expect(onSecurityStampMismatch).toHaveBeenCalledOnce();
      expect(JSON.stringify(onSecurityStampMismatch.mock.calls[0]?.[0])).not.toContain('stamp-');
      await expect(setup.localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toEqual(baseline);
      await expect(setup.localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toEqual(raw);
      await expect(setup.sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toEqual(derived);
    });

    it.each([
      ['a missing stamp', (sync: SyncResponse) => { delete sync.profile.securityStamp; }],
      ['a changed immutable profile id', (sync: SyncResponse) => { sync.profile.id = 'other-profile'; }],
    ])('revokes an established credential after %s', async (_label, mutate) => {
      const sync = makeSync();
      sync.profile.securityStamp = 'stamp-a';
      const onSecurityStampMismatch = vi.fn(async () => {});
      const setup = await makeService(sync, { onSecurityStampMismatch });
      await setup.service.sync();
      mutate(sync);

      await expect(setup.service.sync()).rejects.toMatchObject({ code: 'session_expired' });
      expect(onSecurityStampMismatch).toHaveBeenCalledOnce();
    });

    it('accepts a changed stamp after a legitimate same-account login replaces credentialId', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = 'old-stamp';
      const setup = await makeService(sync);
      await setup.service.sync();
      const firstCredential = (await setup.session.getActiveAuthSnapshot())!.tokenLease.credentialId;
      await setup.session.saveUnlocked({
        email: 'u@example.com',
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
        expiresAt: 1_999_999,
        protectedKey: USER_KEY_VECTOR.akey,
        kdf: 0,
        kdfIterations: 5000,
        userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
      });
      const secondCredential = (await setup.session.getActiveAuthSnapshot())!.tokenLease.credentialId;
      sync.profile.securityStamp = 'new-stamp';

      await expect(setup.service.sync()).resolves.toBeDefined();

      expect(secondCredential).not.toBe(firstCredential);
      await expect(setup.localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toMatchObject({
        baselines: [{ credentialId: secondCredential, securityStamp: 'new-stamp' }],
      });
    });

    it('does not seed a new credential from pre-existing raw cache data during startup', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = 'cached-stamp';
      const setup = await makeService(sync);
      await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
        schemaVersion: 2,
        identity: 'https://vault.example\nu@example.com',
        rawGeneration: 'old-generation',
        response: sync,
      });

      await setup.service.initializeCache();

      await expect(setup.localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toBeUndefined();
      expect(() => setup.policyGate.capture()).toThrow();
      await expect(setup.service.sync()).resolves.toBeDefined();
      await expect(setup.localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toBeDefined();
    });

    it.each([
      ['corrupt', { malformed: true }],
      ['future', { schemaVersion: 2, revision: 'future', baselines: [] }],
    ])('revokes the affected startup account for %s stamp state without bricking initialization', async (
      _label,
      storedStampState,
    ) => {
      const sync = makeSync();
      sync.profile.securityStamp = 'stamp-a';
      const runtime: { setup?: Awaited<ReturnType<typeof makeService>> } = {};
      const onSecurityStampMismatch = vi.fn(async (authority: Parameters<
        VaultServiceDeps['onSecurityStampMismatch']
      >[0]) => {
        const setup = runtime.setup;
        if (!setup) throw new Error('Test runtime is unavailable');
        expect(authority.failure).toMatchObject({
          kind: 'state_unavailable',
          reason: _label === 'future' ? 'unsupported_schema' : 'corrupt_envelope',
        });
        await setup.session.resetAllAccounts();
        await setup.service.clearCache();
        await setup.service.resetSecurityStampBaselines();
      });
      const setup = await makeService(sync, { onSecurityStampMismatch });
      runtime.setup = setup;
      await setup.localStore.set(SECURITY_STAMP_STORAGE_KEY, storedStampState);
      await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
        schemaVersion: 2,
        identity: 'https://vault.example\nu@example.com',
        rawGeneration: 'old-generation',
        response: sync,
      });

      await expect(setup.service.initializeCache()).resolves.toBeUndefined();

      expect(onSecurityStampMismatch).toHaveBeenCalledOnce();
      await expect(setup.session.getActiveAuth()).resolves.toBeUndefined();
      await expect(setup.localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeUndefined();
      await expect(setup.sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
      await expect(setup.localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toBeUndefined();
    });

    it('recovers startup from an invalid cached sync profile without publishing it', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = '';
      const runtime: { setup?: Awaited<ReturnType<typeof makeService>> } = {};
      const onSecurityStampMismatch = vi.fn(async (authority: Parameters<
        VaultServiceDeps['onSecurityStampMismatch']
      >[0]) => {
        const setup = runtime.setup;
        if (!setup) throw new Error('Test runtime is unavailable');
        expect(authority.failure).toEqual({
          kind: 'state_unavailable',
          reason: 'invalid_sync_profile',
        });
        await setup.session.resetAllAccounts();
        await setup.service.clearCache();
        await setup.service.resetSecurityStampBaselines();
      });
      const setup = await makeService(sync, { onSecurityStampMismatch });
      runtime.setup = setup;
      await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
        schemaVersion: 2,
        identity: 'https://vault.example\nu@example.com',
        rawGeneration: 'invalid-generation',
        response: sync,
      });

      await expect(setup.service.initializeCache()).resolves.toBeUndefined();

      expect(onSecurityStampMismatch).toHaveBeenCalledOnce();
      expect(() => setup.policyGate.capture()).toThrow();
      await expect(setup.session.getActiveAuth()).resolves.toBeUndefined();
      await expect(setup.localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    });

    it('aborts cache publication when the first baseline cannot be persisted', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = 'stamp-a';
      const baseStore = createMemoryStore();
      let rejectBaseline = false;
      const localStore: KeyValueStore = {
        ...baseStore,
        async set(key, value) {
          if (rejectBaseline && key === SECURITY_STAMP_STORAGE_KEY) {
            throw new Error('baseline storage failed');
          }
          await baseStore.set(key, value);
        },
      };
      const setup = await makeService(sync, { localStore });
      rejectBaseline = true;

      await expect(setup.service.sync()).rejects.toThrow('baseline storage failed');
      await expect(localStore.get(SECURITY_STAMP_STORAGE_KEY)).resolves.toBeUndefined();
      await expect(localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeUndefined();
      await expect(setup.sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
      expect(() => setup.policyGate.capture()).toThrow();
    });

    it('unwinds the mutation lane before a mismatch callback clears vault state', async () => {
      const sync = makeSync();
      sync.profile.securityStamp = 'stamp-a';
      const runtime: { setup?: Awaited<ReturnType<typeof makeService>> } = {};
      const onSecurityStampMismatch = vi.fn(async () => {
        const setup = runtime.setup;
        if (!setup) throw new Error('Test runtime is unavailable');
        await setup.session.logout();
        await setup.service.clearCache();
      });
      const setup = await makeService(sync, { onSecurityStampMismatch });
      runtime.setup = setup;
      await setup.service.sync();
      sync.profile.securityStamp = 'stamp-b';

      await expect(setup.service.createFolder('Committed remotely')).rejects.toMatchObject({
        code: 'session_expired',
      });

      expect(setup.api.createFolder).toHaveBeenCalledOnce();
      expect(onSecurityStampMismatch).toHaveBeenCalledOnce();
      await expect(setup.session.getActiveAuth()).resolves.toBeUndefined();
      await expect(setup.localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeUndefined();
      await expect(setup.sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    });
  });

  describe('client event authority projection', () => {
    it('uses organizationsNew and excludes accepted, disabled, legacy, and provider-only organizations', async () => {
      const { service } = await makeServiceWithRaw(makeClientEventAuthoritySync());

      const projection = await service.captureClientEventAuthorityProjection();

      expect(projection).toEqual({
        serverUrl: 'https://vault.example',
        userId: EVENT_USER_ID,
        organizations: [
          { id: EVENT_ENABLED_ORG_ID, useEvents: true },
          { id: EVENT_OPT_OUT_ORG_ID, useEvents: false },
        ],
        ciphers: [
          { id: EVENT_ENABLED_CIPHER_ID, organizationId: EVENT_ENABLED_ORG_ID },
          { id: EVENT_PROVIDER_CIPHER_ID, organizationId: EVENT_PROVIDER_ORG_ID },
          { id: EVENT_PERSONAL_CIPHER_ID, organizationId: null },
        ],
      });
      expect(Object.isFrozen(projection)).toBe(true);
      expect(Object.isFrozen(projection.organizations)).toBe(true);
      expect(projection.organizations.every(Object.isFrozen)).toBe(true);
      expect(projection.ciphers.every(Object.isFrozen)).toBe(true);
    });

    it('falls back to confirmed enabled direct organizations when organizationsNew is absent', async () => {
      const sync = makeClientEventAuthoritySync();
      delete sync.profile.organizationsNew;
      const { service } = await makeServiceWithRaw(sync);

      await expect(service.captureClientEventAuthorityProjection()).resolves.toMatchObject({
        organizations: [{ id: EVENT_LEGACY_ORG_ID, useEvents: true }],
      });
    });

    it.each([
      {
        name: 'non-canonical profile user id',
        mutate(sync: SyncResponse) { sync.profile.id = EVENT_USER_ID.toUpperCase(); },
      },
      {
        name: 'duplicate direct organization id',
        mutate(sync: SyncResponse) {
          sync.profile.organizationsNew!.push({ ...sync.profile.organizationsNew![0]! });
        },
      },
      {
        name: 'malformed direct organization id',
        mutate(sync: SyncResponse) { sync.profile.organizationsNew![0]!.id = 'not-an-organization-id'; },
      },
      {
        name: 'duplicate cipher id',
        mutate(sync: SyncResponse) { sync.ciphers.push({ ...sync.ciphers[0]! }); },
      },
      {
        name: 'malformed cipher organization id',
        mutate(sync: SyncResponse) { sync.ciphers[0]!.organizationId = 'not-an-organization-id'; },
      },
      {
        name: 'sparse direct organization array',
        mutate(sync: SyncResponse) {
          const organizations = new Array<NonNullable<SyncResponse['profile']['organizationsNew']>[number]>(2);
          organizations[0] = sync.profile.organizationsNew![0]!;
          sync.profile.organizationsNew = organizations;
        },
      },
    ])('fails closed for $name', async ({ mutate }) => {
      const sync = makeClientEventAuthoritySync();
      mutate(sync);
      const { service } = await makeServiceWithRaw(sync);

      await expect(service.captureClientEventAuthorityProjection())
        .rejects.toMatchObject({ code: 'denied' });
    });

    it.each([
      {
        name: 'account A-B-A',
        transition(gate: AccountLeaseGate) {
          const away = gate.beginAccountTransition();
          gate.endAccountTransition(away, {
            serverUrl: 'https://vault.example',
            accountIdentity: 'other@example.com',
          });
          const back = gate.beginAccountTransition();
          gate.endAccountTransition(back, {
            serverUrl: 'https://vault.example',
            accountIdentity: 'u@example.com',
          });
        },
      },
      {
        name: 'server A-B-A',
        transition(gate: AccountLeaseGate) {
          const away = gate.beginServerTransition();
          gate.endServerTransition(away, {
            serverUrl: 'https://other.example',
            accountIdentity: 'u@example.com',
          });
          const back = gate.beginServerTransition();
          gate.endServerTransition(back, {
            serverUrl: 'https://vault.example',
            accountIdentity: 'u@example.com',
          });
        },
      },
    ])('rejects an in-flight projection after a $name transition', async ({ transition }) => {
      const accountGate = new AccountLeaseGate();
      accountGate.initialize({
        serverUrl: 'https://vault.example',
        accountIdentity: 'u@example.com',
      });
      const { service, session } = await makeServiceWithRaw(makeClientEventAuthoritySync(), {
        accountGate,
      });
      const activeAuth = await session.getActiveAuth();
      let markStarted!: () => void;
      const started = new Promise<void>((resolve) => { markStarted = resolve; });
      let release!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      vi.spyOn(session, 'getActiveAuth').mockImplementationOnce(async () => {
        markStarted();
        await gate;
        return activeAuth;
      });

      const pending = service.captureClientEventAuthorityProjection();
      await started;
      transition(accountGate);
      release();

      await expect(pending).rejects.toThrow(/account changed/i);
    });

    it('rejects a projection when the raw cache generation changes before the final fence', async () => {
      const baseStore = createMemoryStore();
      let replaceAfterRead = false;
      const localStore: KeyValueStore = {
        ...baseStore,
        async get<T>(key: string): Promise<T | undefined> {
          const value = await baseStore.get<T>(key);
          if (replaceAfterRead && key === RAW_VAULT_CACHE_KEY && value) {
            replaceAfterRead = false;
            const source = value as unknown as RawVaultEnvelope;
            await baseStore.set(RAW_VAULT_CACHE_KEY, {
              ...source,
              rawGeneration: `${source.rawGeneration}-changed`,
            });
          }
          return value;
        },
      };
      const { service } = await makeServiceWithRaw(makeClientEventAuthoritySync(), { localStore });
      replaceAfterRead = true;

      await expect(service.captureClientEventAuthorityProjection())
        .rejects.toThrow(/vault changed during operation/i);
    });
  });

  describe('generator history identity projection', () => {
    it('returns only canonical account identity and clears its internal UserKey', async () => {
      const { service, session } = await makeServiceWithRaw(makeClientEventAuthoritySync());
      const loaded = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
      vi.spyOn(session, 'loadUserKey').mockResolvedValueOnce(loaded);

      await expect(service.captureGeneratorHistoryIdentity()).resolves.toEqual({
        serverUrl: 'https://vault.example',
        accountIdentity: 'u@example.com',
        userId: EVENT_USER_ID,
      });
      expect([...loaded.encKey, ...loaded.macKey].every((byte) => byte === 0)).toBe(true);
    });

    it('fails closed for a malformed or non-canonical profile UUID', async () => {
      const sync = makeClientEventAuthoritySync();
      sync.profile.id = EVENT_USER_ID.toUpperCase();
      const { service } = await makeServiceWithRaw(sync);

      await expect(service.captureGeneratorHistoryIdentity())
        .rejects.toMatchObject({ code: 'denied' });
    });
  });

  it('projects only exact interactive custom targets and keeps page secrets narrow', async () => {
    const sync = await makeInteractiveCustomLoginSync();
    const { service } = await makeService(sync);
    await service.sync();
    const unusedValue = sync.ciphers[0]!.fields!.at(-1)!.value!;
    const decryptText = vi.spyOn(encstringNs, 'decryptToText');
    const plan = {
      version: 2 as const,
      generation: 7,
      targets: [
        { fieldId: 'f1', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'Department' }, { kind: 'id' as const, value: 'department-id' }] },
        { fieldId: 'f2', controlType: 'select' as const, hints: [{ kind: 'id' as const, value: 'department' }] },
        { fieldId: 'f3', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'access-code' }] },
        { fieldId: 'f4', controlType: 'checkbox' as const, hints: [{ kind: 'name' as const, value: 'enabled' }] },
        { fieldId: 'f5', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'login-alias' }] },
        { fieldId: 'f6', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'password-alias' }] },
        { fieldId: 'f7', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'unknown-link' }] },
        { fieldId: 'f8', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'duplicate' }] },
        { fieldId: 'f9', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'employee' }, { kind: 'id' as const, value: 'employee-code' }] },
        { fieldId: 'f10', controlType: 'text' as const, hints: [{ kind: 'label' as const, value: 'TENANT' }] },
        { fieldId: 'f11', controlType: 'text' as const, hints: [{ kind: 'placeholder' as const, value: 'workspace' }] },
        { fieldId: 'f12', controlType: 'text' as const, hints: [{ kind: 'name' as const, value: 'anything' }] },
      ],
    };

    const projection = await service.getInteractiveAutofillLoginData(
      'custom-login',
      'https://example.com/login',
      UriMatchStrategy.Domain,
      plan,
    );

    expect(projection).toEqual({
      login: { username: 'ada', password: 'secret' },
      customAssignments: [
        { fieldId: 'f1', value: 'engineering' },
        { fieldId: 'f2', value: 'engineering' },
        { fieldId: 'f3', value: 'hidden-value' },
        { fieldId: 'f4', checked: true },
        { fieldId: 'f5', value: 'ada' },
        { fieldId: 'f6', value: 'secret' },
        { fieldId: 'f9', value: 'E-42' },
        { fieldId: 'f10', value: 'north' },
        { fieldId: 'f11', value: 'platform' },
      ],
    });
    expect(JSON.stringify(projection)).not.toContain('totp');
    expect(JSON.stringify(projection)).not.toContain('department');
    expect(JSON.stringify(projection)).not.toContain('custom-login');
    expect(decryptText.mock.calls.some(([encrypted]) => encrypted === unusedValue)).toBe(false);
    decryptText.mockRestore();
  });

  it('releases a reprompt login only while the background grant assertion remains current', async () => {
    const sync = await makeInteractiveCustomLoginSync();
    sync.ciphers[0]!.reprompt = 1;
    const { service } = await makeService(sync);
    await service.sync();
    const plan = {
      version: 2 as const,
      generation: 7,
      targets: [] as const,
    };

    await expect(service.getInteractiveAutofillLoginData(
      'custom-login',
      'https://example.com/login',
      UriMatchStrategy.Domain,
      plan,
    )).rejects.toMatchObject({ code: 'reprompt_required' });

    const assertCurrent = vi.fn();
    await expect(service.getInteractiveAutofillLoginData(
      'custom-login',
      'https://example.com/login',
      UriMatchStrategy.Domain,
      plan,
      assertCurrent,
    )).resolves.toMatchObject({ login: { username: 'ada', password: 'secret' } });
    expect(assertCurrent.mock.calls.length).toBeGreaterThanOrEqual(3);

    let calls = 0;
    const revoked = vi.fn(() => {
      calls += 1;
      if (calls >= 3) throw new AppError('reprompt_required', 'grant revoked');
    });
    await expect(service.getInteractiveAutofillLoginData(
      'custom-login',
      'https://example.com/login',
      UriMatchStrategy.Domain,
      plan,
      revoked,
    )).rejects.toMatchObject({ code: 'reprompt_required' });
  });

  it('syncs, caches encrypted response, and returns summaries without password', async () => {
    const { service, api } = await makeService();
    const list = await service.sync();
    expect(api.sync).toHaveBeenCalledWith('access');
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: FIELD_VECTOR.plaintext, username: FIELD_VECTOR.plaintext, uris: [FIELD_VECTOR.plaintext], loginUris: [{ uri: FIELD_VECTOR.plaintext }] }], folders: [], collections: [], orgPermissions: [], personalCreationAllowed: true });
  });

  it('refreshes encrypted raw data while locked without publishing a derived snapshot', async () => {
    const { service, api, session, localStore, sessionStore } = await makeService();
    await session.lock();

    await expect(service.sync()).resolves.toEqual({
      items: [], folders: [], collections: [], orgPermissions: [], personalCreationAllowed: false,
    });
    expect(api.sync).toHaveBeenCalledWith('access');
    await expect(localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toMatchObject({
      schemaVersion: 2,
      identity: 'https://vault.example\nu@example.com',
    });
    await expect(sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
  });

  it('stores raw sync data as an identity envelope locally and decrypted data only in session', async () => {
    const { service, localStore, sessionStore } = await makeService();
    const listing = await service.sync();

    await expect(localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toMatchObject({
      schemaVersion: 2,
      identity: 'https://vault.example\nu@example.com',
      response: makeSync(),
    });
    await expect(sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toMatchObject({
      schemaVersion: 2,
      identity: 'https://vault.example\nu@example.com',
      listing,
    });
    await expect(localStore.get('vaultSummaries')).resolves.toBeUndefined();
    await expect(localStore.get('vaultFolders')).resolves.toBeUndefined();
  });

  it('returns the computed listing and rebuilds from raw when the session snapshot exceeds quota', async () => {
    const { service, localStore, sessionStore } = await makeService(makeSync(), { rejectDerivedWrites: true });

    const synced = await service.sync();

    expect(synced.items).toHaveLength(1);
    await expect(localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeDefined();
    await expect(localStore.get('vaultSummaries')).resolves.toBeUndefined();
    await expect(sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    await expect(service.listItems()).resolves.toEqual(synced);
  });

  it('eagerly removes legacy local derived caches during worker initialization', async () => {
    const { service, localStore } = await makeService();
    await localStore.set('vaultSummaries', [{ name: 'plaintext' }]);
    await localStore.set('vaultFolders', [{ name: 'plaintext' }]);

    await service.initializeCache();

    await expect(localStore.get('vaultSummaries')).resolves.toBeUndefined();
    await expect(localStore.get('vaultFolders')).resolves.toBeUndefined();
  });

  it('removes a derived snapshot when the session changes during its storage write', async () => {
    let generation = 0;
    let unlocked = true;
    const sessionGate: SessionLeaseGate = {
      capture: () => ({ generation }),
      assert: (lease) => {
        if (!unlocked || lease.generation !== generation) throw new Error('Vault session changed');
      },
    };
    let markWriteStarted!: () => void;
    const writeStarted = new Promise<void>((resolve) => { markWriteStarted = resolve; });
    let releaseWrite!: () => void;
    const writeGate = new Promise<void>((resolve) => { releaseWrite = resolve; });
    const { service, sessionStore } = await makeService(makeSync(), {
      sessionGate,
      beforeDerivedWrite: async () => {
        markWriteStarted();
        await writeGate;
      },
    });

    const pendingSync = service.sync();
    await writeStarted;
    unlocked = false;
    generation++;
    const pendingPurge = service.purgeDecryptedCaches();
    releaseWrite();

    await expect(pendingSync).rejects.toThrow(/session changed/i);
    await pendingPurge;
    await expect(sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
  });

  it('getField decrypts the requested field on demand from encrypted cache', async () => {
    const { service } = await makeService();
    await service.sync();
    await expect(service.getField('cipher-1', 'password')).resolves.toBe(FIELD_VECTOR.plaintext);
  });

  it('binds a decrypted result to the exact cache generation used to produce it', async () => {
    const { service, api } = await makeService();
    await service.sync();
    let assertResultCurrent: (() => void) | undefined;
    await expect(service.getField(
      'cipher-1',
      'password',
      undefined,
      (assertCurrent) => { assertResultCurrent = assertCurrent; },
    )).resolves.toBe(FIELD_VECTOR.plaintext);
    expect(assertResultCurrent).toBeTypeOf('function');

    stubApi(api).sync = vi.fn(async () => ({
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [],
    }));
    await service.sync();

    expect(() => assertResultCurrent?.()).toThrow(/vault changed|policy/i);
  });

  it('binds a decrypted result to the enterprise item policy used to authorize it', async () => {
    const response = makeSync();
    const { service, policyGate } = await makeService(response);
    await service.sync();
    let assertResultCurrent: (() => void) | undefined;
    await service.getField(
      'cipher-1',
      'password',
      undefined,
      (assertCurrent) => { assertResultCurrent = assertCurrent; },
    );

    replacePolicyGate(policyGate, withEnterprisePolicies(response, [{
      type: EnterprisePolicyType.RestrictedItemTypes,
      data: [1],
    }]), 'policy-after-result');

    expect(() => assertResultCurrent?.()).toThrow(/policy|restricted/i);
  });

  it('marks undecryptable ciphers without failing the whole list', async () => {
    const bad = makeSync();
    bad.ciphers[0]!.name = '2.bad|bad|bad';
    const { service } = await makeService(bad);
    const list = await service.sync();
    expect(list).toEqual({ items: [{ id: 'cipher-1', type: 1, favorite: false, name: '(undecryptable)', uris: [], loginUris: [], undecryptable: true }], folders: [], collections: [], orgPermissions: [], personalCreationAllowed: true });
  });

  // Coverage-only: public method listItems() — not exercised by the sync test above.
  it('listItems requires a policy-bearing raw sync before returning cached summaries', async () => {
    const { service, api } = await makeService();

    await expect(service.listItems()).rejects.toMatchObject({ code: 'sync_required' });

    // After sync the summaries are cached.
    const synced = await service.sync();
    expect(api.sync).toHaveBeenCalledTimes(1);

    // listItems must return the cached envelope without calling api.sync a second time.
    const listed = await service.listItems();
    expect(listed).toEqual(synced);
    expect(api.sync).toHaveBeenCalledTimes(1);
  });

  it('does not cache a sync response after the active identity changes', async () => {
    let epoch = 0;
    let releaseSync!: () => void;
    const syncGate = new Promise<void>((resolve) => { releaseSync = resolve; });
    const { service, api } = await makeService(makeSync(), { getIdentityEpoch: () => epoch });
    stubApi(api).sync = vi.fn(async () => {
      await syncGate;
      return makeSync();
    });

    const pending = service.sync();
    await vi.waitFor(() => expect(api.sync).toHaveBeenCalledTimes(1));
    epoch++;
    releaseSync();

    await expect(pending).rejects.toThrow(/account changed/i);
    await expect(service.listItems()).rejects.toMatchObject({ code: 'sync_required' });
  });

  it('does not create a cipher with one account key and another account token', async () => {
    let identityEpoch = 0;
    let sessionGeneration = 0;
    const sessionGate: SessionLeaseGate = {
      capture: () => ({ generation: sessionGeneration }),
      assert: (lease) => {
        if (lease.generation !== sessionGeneration) throw new Error('Vault session changed');
      },
    };
    const { service, api, session } = await makeService(makeSync(), {
      sessionGate,
      getIdentityEpoch: () => identityEpoch,
    });
    const accountAKey = (await session.loadUserKey())!;
    const accountAAuth = (await session.getActiveAuth())!;
    let keyRead = false;
    vi.spyOn(session, 'loadUserKey').mockImplementation(async () => {
      keyRead = true;
      return accountAKey;
    });
    let markAuthReadStarted!: () => void;
    const authReadStarted = new Promise<void>((resolve) => { markAuthReadStarted = resolve; });
    let releaseAuthRead!: () => void;
    const authReadGate = new Promise<void>((resolve) => { releaseAuthRead = resolve; });
    vi.spyOn(session, 'getActiveAuth').mockImplementation(async () => {
      markAuthReadStarted();
      await authReadGate;
      return { ...accountAAuth, email: 'b@example.com', accessToken: 'account-b-token' };
    });

    const pending = service.createCipher({ type: 1, name: 'Must not be written' });
    await authReadStarted;
    expect(keyRead).toBe(true);
    identityEpoch++;
    sessionGeneration++;
    releaseAuthRead();

    await expect(pending).rejects.toThrow(/session changed|account changed/i);
    expect(api.createCipher).not.toHaveBeenCalled();
  });

  // Coverage-only: public method clearCache() — removes cached data and its policy snapshot.
  it('clearCache makes listing fail closed until another sync', async () => {
    const { service } = await makeService();
    await service.sync();
    expect((await service.listItems()).items).not.toEqual([]);

    await service.clearCache();
    await expect(service.listItems()).rejects.toMatchObject({ code: 'sync_required' });
  });

  it('clearCache removes vault cache so getField requires sync', async () => {
    const { service } = await makeService();
    await service.sync();
    await service.clearCache();
    await expect(service.getField('cipher-1', 'password')).rejects.toMatchObject({ code: 'sync_required' });
  });

  // Lock-time metadata purge: decrypted item names / login URIs must not linger in storage.local after
  // lock, but the list must rebuild locally (no re-sync) on the next unlocked read.
  it('purgeDecryptedCaches drops the plaintext summaries but keeps them rebuildable while unlocked', async () => {
    const { service, localStore, sessionStore } = await makeService();
    const synced = await service.sync();
    expect(synced.items).not.toEqual([]);

    await service.purgeDecryptedCaches();
    await expect(sessionStore.get(DERIVED_VAULT_CACHE_KEY)).resolves.toBeUndefined();
    await expect(localStore.get(RAW_VAULT_CACHE_KEY)).resolves.toBeDefined();
    // Still unlocked → the next read rebuilds the identical listing from the encrypted vault cache.
    await expect(service.listItems()).resolves.toEqual(synced);
  });

  it('refuses to rebuild the vault list after purge while locked', async () => {
    const { service, session } = await makeService();
    await service.sync();
    await service.purgeDecryptedCaches();
    await session.lock();
    await expect(service.listItems()).rejects.toMatchObject({ code: 'locked' });
  });

  it('decryptCipherById rejects with an AppError code the router can map (sync_required / locked)', async () => {
    // Not synced → sync_required (not the generic 'error') so the UI prompts a sync, not a failure toast.
    const notSynced = await makeService();
    await notSynced.service.sync();
    await notSynced.service.clearCache();
    await expect(notSynced.service.getField('cipher-1', 'password')).rejects.toMatchObject({ code: 'sync_required' });

    // Synced then locked → locked, so the UI prompts an unlock.
    const { service, session } = await makeService();
    await service.sync();
    await session.lock();
    await expect(service.getField('cipher-1', 'password')).rejects.toMatchObject({ code: 'locked' });
  });

  describe('enterprise policy lifecycle', () => {
    it('publishes the exact persisted raw generation and revokes it on the next sync', async () => {
      const { service, policyGate, localStore } = await makeService();

      await service.sync();
      const first = policyGate.capture();
      const storedFirst = await localStore.get<{ rawGeneration: string }>(RAW_VAULT_CACHE_KEY);
      expect(first.rawGeneration).toBe(storedFirst?.rawGeneration);

      await service.sync();
      const second = policyGate.capture();
      const storedSecond = await localStore.get<{ rawGeneration: string }>(RAW_VAULT_CACHE_KEY);
      expect(second.rawGeneration).toBe(storedSecond?.rawGeneration);
      expect(second.rawGeneration).not.toBe(first.rawGeneration);
      expect(policyGate.isCurrent(first)).toBe(false);
    });

    it('leaves policy unavailable when a replacement raw write fails', async () => {
      let rejectRawWrite = false;
      const { service, policyGate, api } = await makeService(makeSync(), {
        rejectRawWrite: () => rejectRawWrite,
      });
      await service.sync();
      const previous = policyGate.capture();
      rejectRawWrite = true;

      await expect(service.sync()).rejects.toThrow(/raw cache write failed/i);

      expect(policyGate.isCurrent(previous)).toBe(false);
      expect(() => policyGate.capture()).toThrowError(/unavailable/i);
      await expect(service.createCipher({ type: 1, name: 'Must wait for sync' }))
        .rejects.toMatchObject({ code: 'sync_required' });
      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('restores a policy snapshot from a cold-start raw envelope', async () => {
      const { policyGate } = await makeServiceWithRaw();
      const lease = policyGate.capture();

      expect(lease).toMatchObject({
        serverUrl: 'https://vault.example',
        accountIdentity: 'u@example.com',
        rawGeneration: 'preloaded-raw-generation',
      });
    });

    it('awaits the enterprise enforcement hook after cold restore and every raw sync publish', async () => {
      const enforced = vi.fn(async () => {});
      const cold = await makeServiceWithRaw(makeSync(), { onPolicySnapshotPublished: enforced });
      expect(enforced).toHaveBeenCalledTimes(1);

      await cold.service.sync();
      expect(enforced).toHaveBeenCalledTimes(2);
    });

    it('revokes policy state when the post-publication enforcement hook fails', async () => {
      const { service, policyGate } = await makeService(makeSync(), {
        onPolicySnapshotPublished: async () => { throw new Error('policy enforcement failed'); },
      });

      await expect(service.sync()).rejects.toThrow(/policy enforcement failed/i);
      expect(() => policyGate.capture()).toThrowError(/unavailable/i);
      await expect(service.createCipher({ type: 1, name: 'Blocked after failure' }))
        .rejects.toMatchObject({ code: 'sync_required' });
    });

    it('publishes policy state even when a locked sync cannot build plaintext derivatives', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.DisablePersonalVaultExport,
      }]);
      const { service, session, policyGate } = await makeService(response);
      await session.lock();

      await service.sync();

      expect(policyGate.allows(policyGate.capture(), 'exportPersonalVault')).toBe(false);
    });

    it('revokes the policy snapshot before clearing raw cache', async () => {
      const { service, policyGate } = await makeServiceWithRaw();
      const lease = policyGate.capture();

      await service.clearCache();

      expect(policyGate.isCurrent(lease)).toBe(false);
      expect(() => policyGate.capture()).toThrowError(/unavailable/i);
    });

    it('revokes an in-flight secret read when policy changes during reprompt verification', async () => {
      const response = makeSync();
      response.ciphers[0]!.reprompt = 1;
      const { service, auth, policyGate } = await makeService(response);
      await service.sync();
      let release!: (value: boolean) => void;
      const verification = new Promise<boolean>((resolve) => { release = resolve; });
      (auth.verifyMasterPassword as ReturnType<typeof vi.fn>).mockImplementation(() => verification);

      const pending = service.getField('cipher-1', 'password', 'correct-master');
      await vi.waitFor(() => expect(auth.verifyMasterPassword).toHaveBeenCalledOnce());
      replacePolicyGate(policyGate, withEnterprisePolicies(response, [{
        type: EnterprisePolicyType.RestrictedItemTypes,
        data: [1],
      }]), 'policy-changed');
      release(true);

      await expect(pending).rejects.toMatchObject({ code: 'denied' });
    });

    it('stops a policy-invalidated mutation before the guarded request leaves the worker', async () => {
      let guardStarted!: () => void;
      const started = new Promise<void>((resolve) => { guardStarted = resolve; });
      let releaseGuard!: () => void;
      const guard = new Promise<void>((resolve) => { releaseGuard = resolve; });
      const setup = await makeServiceWithRaw(makeSync(), {
        beforeRequestGuard: async (method) => {
          if (method !== 'createCipher') return;
          guardStarted();
          await guard;
        },
      });

      const pending = setup.service.createCipher({ type: 1, name: 'Blocked' });
      await started;
      replacePolicyGate(setup.policyGate, withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.OrganizationDataOwnership,
      }]), 'policy-changed');
      releaseGuard();

      await expect(pending).rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.createCipher).not.toHaveBeenCalled();
    });

    it('classifies a policy change after a remote response as committed but unsynced', async () => {
      const setup = await makeServiceWithRaw();
      (setup.api.createCipher as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        replacePolicyGate(setup.policyGate, withEnterprisePolicies(makeSync(), [{
          type: EnterprisePolicyType.OrganizationDataOwnership,
        }]), 'policy-changed-after-commit');
        return { id: 'created', type: 1, name: '2.enc' };
      });

      await expect(setup.service.createCipher({ type: 1, name: 'Maybe committed' }))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(setup.api.createCipher).toHaveBeenCalledOnce();
    });
  });

  describe('enterprise restricted item enforcement', () => {
    function restrictedLoginSync(): SyncResponse {
      return withEnterprisePolicies(makeSyncUrl(), [{
        type: EnterprisePolicyType.RestrictedItemTypes,
        data: [1],
      }]);
    }

    it('filters restricted items before summary decryption while retaining encrypted raw data', async () => {
      const response = restrictedLoginSync();
      const { service, localStore } = await makeService(response);

      const listing = await service.sync();
      const raw = await localStore.get<{ response: SyncResponse }>(RAW_VAULT_CACHE_KEY);

      expect(listing.items).toEqual([]);
      expect(raw?.response.ciphers).toEqual(response.ciphers);
      expect(raw?.response.ciphers[0]?.login?.password).toBe(FIELD_VECTOR.encString);
    });

    it('rejects direct secret, detail, attachment, history, and autofill reads', async () => {
      const { service, api } = await makeService(restrictedLoginSync());
      await service.sync();

      const reads = [
        () => service.getField('cipher-1', 'password'),
        () => service.getCipherDetail('cipher-1'),
        () => service.getCipherInput('cipher-1'),
        () => service.getCustomField('cipher-1', 0),
        () => service.getPasswordHistory('cipher-1'),
        () => service.getTotpCode('cipher-1'),
        () => service.getAttachment('cipher-1', 'attachment'),
        () => service.getAutofillLoginData(
          'cipher-1',
          URL_VECTOR.plaintext,
          UriMatchStrategy.Domain,
        ),
        () => service.getAutofillTotpData(
          'cipher-1',
          URL_VECTOR.plaintext,
          UriMatchStrategy.Domain,
        ),
      ];
      for (const read of reads) await expect(read()).rejects.toMatchObject({ code: 'denied' });

      expect(api.downloadAttachment).not.toHaveBeenCalled();
      await expect(service.findAutofillCandidates(
        URL_VECTOR.plaintext,
        UriMatchStrategy.Domain,
      )).resolves.toEqual([]);
      await expect(service.listTotpCodes()).resolves.toEqual([]);
      await expect(service.getPasswordHealth()).resolves.toEqual([]);
      await expect(service.getPwnedReport()).resolves.toEqual([]);
      await expect(service.getPasskeyTargets({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toEqual([]);
      await expect(service.exportVault()).rejects.toMatchObject({ code: 'denied' });
    });

    it('rejects every direct mutation of a restricted item before remote I/O', async () => {
      const { service, api } = await makeService(restrictedLoginSync());
      await service.sync();

      const mutations = [
        () => service.updateCipher('cipher-1', { type: 1, name: 'Blocked' }),
        () => service.updateCipherLocalMetadata('cipher-1', { folderId: null, favorite: true }),
        () => service.setCipherCollections('cipher-1', ['collection']),
        () => service.shareCipher('cipher-1', 'org', ['collection']),
        () => service.deleteCipher('cipher-1'),
        () => service.softDeleteCipher('cipher-1'),
        () => service.restoreCipher('cipher-1'),
        () => service.archiveCipher('cipher-1'),
        () => service.unarchiveCipher('cipher-1'),
        () => service.addAttachment('cipher-1', 'file.txt', 'AA=='),
        () => service.deleteAttachment('cipher-1', 'attachment'),
        () => service.updateLoginPassword(
          'cipher-1',
          'replacement',
          URL_VECTOR.plaintext,
          UriMatchStrategy.Domain,
        ),
      ];
      for (const mutation of mutations) {
        await expect(mutation()).rejects.toMatchObject({ code: 'denied' });
      }

      for (const remote of [
        api.updateCipher,
        api.updateCipherPartial,
        api.updateCipherCollections,
        api.shareCipher,
        api.deleteCipher,
        api.softDeleteCipher,
        api.restoreCipher,
        api.archiveCiphers,
        api.unarchiveCiphers,
        api.uploadAttachment,
        api.deleteAttachment,
      ]) expect(remote).not.toHaveBeenCalled();
    });

    it('rejects restricted personal creates, imports, and new passkeys', async () => {
      const { service, api } = await makeService(restrictedLoginSync());
      await service.sync();

      await expect(service.createCipher({ type: 1, name: 'Blocked' }))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.saveLogin('https://example.com', 'user', 'password'))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.importVault(JSON.stringify({ items: [{ type: 1, name: 'Blocked' }] })))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.createPasskey({
        rpId: 'example.com',
        origin: 'https://example.com',
        challenge: 'AAAA',
      })).rejects.toMatchObject({ code: 'denied' });

      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('does not expose or use passkeys stored on a restricted login', async () => {
      const response = restrictedLoginSync();
      response.ciphers[0]!.login!.fido2Credentials = [{
        credentialId: await encUnder('credential-1', testUserKey),
        keyValue: await encUnder('private-key-material', testUserKey),
        rpId: await encUnder('example.com', testUserKey),
        counter: await encUnder('0', testUserKey),
      }];
      const { service } = await makeService(response);
      await service.sync();

      await expect(service.listPasskeyCandidates({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toEqual([]);
      await expect(service.hasMatchingPasskey({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toBe(false);
      await expect(service.getPasskeyAssertion({
        rpId: 'example.com',
        origin: 'https://example.com',
        challenge: 'AAAA',
      })).resolves.toBeUndefined();
    });

    it('rejects structured card fill for a restricted Card item', async () => {
      const response = withEnterprisePolicies({
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [{
          id: 'card-1',
          type: 3,
          name: await encUnder('Corporate Card', testUserKey),
          organizationId: null,
          card: { number: await encUnder('4111111111111111', testUserKey) },
        }],
      }, [{ type: EnterprisePolicyType.RestrictedItemTypes, data: [3] }]);
      const { service } = await makeService(response);
      await service.sync();

      const decryptText = vi.spyOn(encstringNs, 'decryptToText');
      decryptText.mockClear();
      await expect(service.getFillData('card-1', 'card', ['number'])).rejects.toMatchObject({ code: 'denied' });
      expect(decryptText).not.toHaveBeenCalled();
      await expect(service.findFillItems('card')).resolves.toEqual([]);
    });
  });

  describe('organization ownership and export policies', () => {
    it('blocks new personal items for a member while allowing maintenance of existing items', async () => {
      const response = withEnterprisePolicies(makeSyncUrl(), [{
        type: EnterprisePolicyType.OrganizationDataOwnership,
      }]);
      const { service, api } = await makeService(response);
      const listing = await service.sync();

      expect(listing.personalCreationAllowed).toBe(false);

      await expect(service.getField('cipher-1', 'password')).resolves.toBe(FIELD_VECTOR.plaintext);
      await expect(service.createCipher({ type: 1, name: 'Blocked' }))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.saveLogin('https://example.com', 'user', 'password'))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.importVault(JSON.stringify({ items: [{ type: 2, name: 'Blocked' }] })))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.createPasskey({
        rpId: 'example.com',
        origin: 'https://example.com',
        challenge: 'AAAA',
      })).rejects.toMatchObject({ code: 'denied' });

      await expect(service.updateCipher('cipher-1', { type: 1, name: 'Maintained item' }))
        .resolves.toBeDefined();
      await expect(service.updateLoginPassword(
        'cipher-1',
        'replacement-password',
        URL_VECTOR.plaintext,
        UriMatchStrategy.Domain,
      )).resolves.toBeDefined();
      await expect(service.addAttachment('cipher-1', 'allowed.txt', 'AA=='))
        .resolves.toBeDefined();
      await expect(service.deleteAttachment('cipher-1', 'attachment-id'))
        .resolves.toBeDefined();
      await expect(service.createPasskey({
        rpId: 'example.com',
        origin: 'https://example.com',
        challenge: 'AAAA',
        targetCipherId: 'cipher-1',
      })).resolves.toMatchObject({ publicKeyAlgorithm: -7 });

      expect(api.createCipher).not.toHaveBeenCalled();
      expect(api.updateCipher).toHaveBeenCalled();
      expect(api.createAttachmentUploadSlot).toHaveBeenCalled();
      expect(api.uploadAttachmentSlotData).toHaveBeenCalled();
      expect(api.deleteAttachment).toHaveBeenCalled();
      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({ status: 'not_required' });
      await expect(service.exportVault()).rejects.toMatchObject({ code: 'denied' });
    });

    it('keeps an Owner exempt from new-item ownership enforcement', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.OrganizationDataOwnership,
      }]);
      response.profile.organizationsNew![0]!.type = 0;
      const { service, api } = await makeService(response);
      const listing = await service.sync();

      expect(listing.personalCreationAllowed).toBe(true);

      await expect(service.createCipher({ type: 1, name: 'Owner personal item' }))
        .resolves.toBeDefined();
      expect(api.createCipher).toHaveBeenCalledOnce();
    });

    it('rejects personal export before serializing vault secrets', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.DisablePersonalVaultExport,
      }]);
      const { service } = await makeService(response);
      await service.sync();

      await expect(service.exportVault()).rejects.toMatchObject({ code: 'denied' });
    });

    it('fails closed when an apparent transfer policy is malformed', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.OrganizationDataOwnership,
        data: { enableIndividualItemsTransfer: 'true' },
        revisionDate: '2026-08-30T00:00:00.000Z',
      }]);
      const { service } = await makeService(response);
      await service.sync();

      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({ status: 'unavailable' });
      await expect(service.getField('cipher-1', 'password'))
        .rejects.toMatchObject({ code: 'denied' });
    });

    it('blocks migration when a personal cipher has no concurrency revision', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      response.ciphers[0]!.revisionDate = null;
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID)).resolves.toMatchObject({
        status: 'blocked',
        organizationId: 'org-1',
        personalItemCount: 1,
        reason: 'unsupported_items',
        leaveAuthorization: {
          authorizationId: expect.stringMatching(ODO_AUTHORIZATION_ID),
          expiresAt: expect.any(Number),
        },
      });
      await expect(service.getField('cipher-1', 'password'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.shareCiphers).not.toHaveBeenCalled();
    });

    it('moves active, archived, and trashed personal items in one bulk request', async () => {
      const response = makeSync();
      response.ciphers[0]!.deletedDate = '2026-08-29T00:00:00.000Z';
      response.ciphers[0]!.revisionDate = '2026-08-30T00:00:00.000Z';
      response.ciphers.push({
        id: 'archived-note',
        type: 2,
        name: await encUnder('Archived note', testUserKey),
        favorite: true,
        organizationId: null,
        archivedDate: '2026-08-28T00:00:00.000Z',
        revisionDate: '2026-08-30T00:00:00.000Z',
        secureNote: { type: 0 },
      });
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID)).resolves.toMatchObject({
        status: 'migration_available',
        organizationId: 'org-1',
        collectionId: 'default-collection',
        personalItemCount: 2,
        migrateAuthorization: {
          authorizationId: expect.stringMatching(ODO_AUTHORIZATION_ID),
          expiresAt: expect.any(Number),
        },
        leaveAuthorization: {
          authorizationId: expect.stringMatching(ODO_AUTHORIZATION_ID),
          expiresAt: expect.any(Number),
        },
      });
      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).resolves.toBeDefined();

      expect(api.shareCipher).not.toHaveBeenCalled();
      expect(api.shareCiphers).toHaveBeenCalledOnce();
      const request = vi.mocked(api.shareCiphers).mock.calls[0]![1];
      expect(request.encryptedFor).toBe('u');
      expect(request.collectionIds).toEqual(['default-collection']);
      expect(request.ciphers.map((cipher) => cipher.id).sort())
        .toEqual(['archived-note', 'cipher-1']);
      expect(request.ciphers.every((cipher) => (
        cipher.organizationId === 'org-1' && cipher.encryptedFor === 'u'
      ))).toBe(true);
      const archivedRequest = request.ciphers.find((cipher) => cipher.id === 'archived-note')!;
      await expect(decryptToText(archivedRequest.name, orgKey)).resolves.toBe('Archived note');
      expect(response.ciphers.find((cipher) => cipher.id === 'cipher-1')?.deletedDate)
        .toBe('2026-08-29T00:00:00.000Z');
      expect(response.ciphers.find((cipher) => cipher.id === 'archived-note')?.archivedDate)
        .toBe('2026-08-28T00:00:00.000Z');
      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({ status: 'compliant' });
    });

    it('accepts the official minimal bulk-share receipt and verifies content after sync', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      const implementation = vi.mocked(api.shareCiphers).getMockImplementation()!;
      vi.mocked(api.shareCiphers).mockImplementationOnce(async (token, request) => {
        await implementation(token, request);
        return request.ciphers.map((cipher) => ({
          id: cipher.id,
          type: cipher.type,
          organizationId: cipher.organizationId,
          revisionDate: '2026-08-31T00:00:00.000Z',
        }));
      });
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).resolves.toBeDefined();
      expect(api.shareCiphers).toHaveBeenCalledOnce();
    });

    it('uses revision-checked single shares on Vaultwarden instead of its OCC-skipping bulk route', async () => {
      const response = makeSync();
      response.ciphers.push({
        id: 'personal-note',
        type: 2,
        name: await encUnder('Personal note', testUserKey),
        organizationId: null,
        archivedDate: '2026-08-29T00:00:00.000Z',
        secureNote: { type: 0 },
      });
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, {
        privateKey: privateKeyBytes,
        organizationDataOwnershipServerKind: 'vaultwarden',
      });
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).resolves.toBeDefined();
      expect(api.shareCiphers).not.toHaveBeenCalled();
      expect(api.shareCipher).toHaveBeenCalledTimes(2);
      expect(vi.mocked(api.shareCipher).mock.calls.every((call) => (
        typeof call[2].cipher.lastKnownRevisionDate === 'string'
      ))).toBe(true);
      expect(response.ciphers.every((cipher) => cipher.organizationId === 'org-1')).toBe(true);
    });

    it('reconciles a partial Vaultwarden sequence and can safely retry the remaining item', async () => {
      const response = makeSync();
      response.ciphers.push({
        id: 'personal-note',
        type: 2,
        name: await encUnder('Personal note', testUserKey),
        organizationId: null,
        secureNote: { type: 0 },
      });
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, {
        privateKey: privateKeyBytes,
        organizationDataOwnershipServerKind: 'vaultwarden',
      });
      const implementation = vi.mocked(api.shareCipher).getMockImplementation()!;
      vi.mocked(api.shareCipher)
        .mockImplementationOnce(implementation)
        .mockRejectedValueOnce(new ApiHttpError(409, 'stale revision'));
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'conflict' });
      expect(response.ciphers.filter((cipher) => cipher.organizationId == null)).toHaveLength(1);
      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).resolves.toBeDefined();
      expect(response.ciphers.filter((cipher) => cipher.organizationId == null)).toHaveLength(0);
      expect(api.shareCiphers).not.toHaveBeenCalled();
    });

    it('upgrades a legacy attachment on a trashed item before the bulk move', async () => {
      const response = makeSync();
      const plaintext = new TextEncoder().encode('legacy trashed attachment');
      const encrypted = await encryptAttachmentFile(plaintext, testUserKey);
      response.ciphers[0]!.deletedDate = '2026-08-29T00:00:00.000Z';
      response.ciphers[0]!.revisionDate = '2026-08-30T00:00:00.000Z';
      response.ciphers[0]!.attachments = [{
        id: 'legacy-attachment',
        fileName: await encUnder('legacy.txt', testUserKey),
        key: null,
        size: String(encrypted.byteLength),
        url: '/legacy-attachment',
      }];
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      vi.mocked(api.downloadAttachment).mockResolvedValue(new Uint8Array(encrypted));
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).resolves.toBeDefined();

      expect(api.createAttachmentUploadSlot).toHaveBeenCalledOnce();
      expect(api.deleteAttachment).toHaveBeenCalledWith(
        expect.any(String),
        'cipher-1',
        'legacy-attachment',
      );
      expect(api.shareCiphers).toHaveBeenCalledOnce();
      const migrated = response.ciphers.find((cipher) => cipher.id === 'cipher-1')!;
      expect(migrated.organizationId).toBe('org-1');
      expect(migrated.deletedDate).toBe('2026-08-29T00:00:00.000Z');
      expect(migrated.attachments).toHaveLength(1);
      expect(migrated.attachments?.[0]?.key).toMatch(/^2\./);
      plaintext.fill(0);
      encrypted.fill(0);
    });

    it('treats any bulk request failure as outcome unknown', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      vi.mocked(api.shareCiphers).mockRejectedValueOnce(new ApiHttpError(400, 'second item failed'));
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(api.shareCiphers).toHaveBeenCalledOnce();
    });

    it('treats the first dispatched Vaultwarden share rejection as outcome unknown', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, {
        privateKey: privateKeyBytes,
        organizationDataOwnershipServerKind: 'vaultwarden',
      });
      vi.mocked(api.shareCipher).mockRejectedValueOnce(new ApiHttpError(400, 'late validation failed'));
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(api.shareCipher).toHaveBeenCalledOnce();
      expect(api.shareCiphers).not.toHaveBeenCalled();
    });

    it('keeps high-frequency status grants bounded without reviving an evicted authorization', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();

      const statuses = [];
      for (let index = 0; index < 40; index += 1) {
        statuses.push(await service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID));
      }
      const first = statuses[0]!;
      const latest = statuses.at(-1)!;
      if (first.status !== 'migration_available' || latest.status !== 'migration_available') {
        throw new Error('Expected migration authorizations');
      }
      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        first.migrateAuthorization.authorizationId,
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'conflict' });
      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        latest.migrateAuthorization.authorizationId,
        ODO_POPUP_DOCUMENT_ID,
        'wrong-master',
      )).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        latest.migrateAuthorization.authorizationId,
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'denied' });
      expect(api.shareCiphers).not.toHaveBeenCalled();
    });

    it('consumes a grant before rejecting its Popup document or operation binding', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();
      const first = await service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID);
      const second = await service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID);
      if (first.status !== 'migration_available' || second.status !== 'migration_available') {
        throw new Error('Expected migration authorizations');
      }

      await expect(service.migrateOrganizationDataOwnership(
        'org-1', 'default-collection', first.migrateAuthorization.authorizationId,
        'other-popup-document', 'correct-master',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.migrateOrganizationDataOwnership(
        'org-1', 'default-collection', first.migrateAuthorization.authorizationId,
        ODO_POPUP_DOCUMENT_ID, 'correct-master',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.leaveOrganizationDataOwnership(
        'org-1', second.migrateAuthorization.authorizationId, ODO_POPUP_DOCUMENT_ID,
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.leaveOrganizationDataOwnership(
        'org-1', second.leaveAuthorization.authorizationId, ODO_POPUP_DOCUMENT_ID,
      )).resolves.toBeDefined();
      expect(api.shareCiphers).not.toHaveBeenCalled();
      expect(api.revokeCurrentOrganizationMembership).toHaveBeenCalledOnce();
    });

    it('persists unknown-result reconciliation across a worker restart until full sync succeeds', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const first = await makeService(response, { privateKey: privateKeyBytes });
      vi.mocked(first.api.shareCiphers).mockRejectedValueOnce(new Error('connection lost'));
      await first.service.sync();
      await expect(first.service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(first.service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
      await expect(first.service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({
          status: 'reconciliation_required',
          operation: 'migrate',
          reason: 'outcome_unknown',
        });

      const restarted = await makeService(response, {
        privateKey: privateKeyBytes,
        localStore: first.localStore,
        sessionStore: first.sessionStore,
      });
      await expect(restarted.service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({
          status: 'reconciliation_required',
          operation: 'migrate',
          reason: 'outcome_unknown',
        });
      vi.mocked(first.api.sync).mockClear();
      await first.service.sync('odo-reconcile', 'coalesce');
      expect(first.api.sync).toHaveBeenCalledOnce();
      await expect(first.service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toMatchObject({ status: 'migration_available' });
    });

    it('accepts a commit-then-reject marker write only after exact read-back proves persistence', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const durable = createMemoryStore();
      const commitThenReject: KeyValueStore = {
        ...durable,
        async set(key, value) {
          await durable.set(key, value);
          if (key.startsWith('organizationDataOwnershipReconciliation:v1:')) {
            throw new Error('storage response lost');
          }
        },
      };
      const first = await makeService(response, {
        privateKey: privateKeyBytes,
        localStore: commitThenReject,
      });
      vi.mocked(first.api.shareCiphers).mockRejectedValueOnce(new Error('connection lost'));
      await first.service.sync();
      await expect(first.service.migrateOrganizationDataOwnership(
        'org-1', 'default-collection', await dataOwnershipBinding(first.service),
        ODO_POPUP_DOCUMENT_ID, 'correct-master',
      )).rejects.toMatchObject({ code: 'outcome_unknown' });

      const restarted = await makeService(response, {
        privateKey: privateKeyBytes,
        localStore: durable,
        sessionStore: first.sessionStore,
      });
      await expect(restarted.service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toMatchObject({
          status: 'reconciliation_required',
          operation: 'migrate',
          reason: 'outcome_unknown',
        });
    });

    it('rejects a stale authorization when the personal item identity set changes', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api, auth } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();
      const staleBinding = await dataOwnershipBinding(service);
      response.ciphers.push({
        id: 'new-personal-item',
        type: 2,
        name: await encUnder('New personal item', testUserKey),
        organizationId: null,
        revisionDate: '2026-08-31T01:00:00.000Z',
        secureNote: { type: 0 },
      });
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        staleBinding,
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'conflict' });
      expect(auth.verifyMasterPassword).not.toHaveBeenCalled();
      expect(api.shareCiphers).not.toHaveBeenCalled();
      expect(await dataOwnershipBinding(service)).not.toBe(staleBinding);
    });

    it('gates autofill and passkey discovery while ownership migration is pending', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.findAutofillCandidates(
        'https://example.com/login',
        UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.findFillItems('card')).rejects.toMatchObject({ code: 'denied' });
      await expect(service.getPasskeyTargets({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).rejects.toMatchObject({ code: 'denied' });
      await expect(service.hasMatchingPasskey({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).rejects.toMatchObject({ code: 'denied' });
      await expect(service.listPasskeyCandidates({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).rejects.toMatchObject({ code: 'denied' });
      await expect(service.getPasskeyAssertion({
        rpId: 'example.com',
        origin: 'https://example.com',
        challenge: 'AAAA',
      })).rejects.toMatchObject({ code: 'denied' });
    });

    it('rejects a successful bulk response when the authoritative sync shows a partial move', async () => {
      const response = makeSync();
      response.ciphers.push({
        id: 'personal-note',
        type: 2,
        name: await encUnder('Personal note', testUserKey),
        organizationId: null,
        secureNote: { type: 0 },
      });
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      const bulkImplementation = vi.mocked(api.shareCiphers).getMockImplementation()!;
      vi.mocked(api.shareCiphers).mockImplementationOnce(async (token, request) => bulkImplementation(token, {
        ...request,
        ciphers: [request.ciphers[0]!],
      }));
      await service.sync();

      await expect(service.migrateOrganizationDataOwnership(
        'org-1',
        'default-collection',
        await dataOwnershipBinding(service),
        ODO_POPUP_DOCUMENT_ID,
        'correct-master',
      )).rejects.toMatchObject({ code: 'conflict' });
      expect(response.ciphers.filter((cipher) => cipher.organizationId === 'org-1')).toHaveLength(1);
      expect(response.ciphers.filter((cipher) => cipher.organizationId == null)).toHaveLength(1);
    });

    it('leaves only the currently enforcing organization and proves removal with a sync', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();

      const wrongAuthorization = await dataOwnershipBinding(service, 'leave');
      await expect(service.leaveOrganizationDataOwnership(
        'other-org', wrongAuthorization, ODO_POPUP_DOCUMENT_ID,
      ))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.revokeCurrentOrganizationMembership).not.toHaveBeenCalled();
      await expect(service.leaveOrganizationDataOwnership(
        'org-1', await dataOwnershipBinding(service, 'leave'), ODO_POPUP_DOCUMENT_ID,
      )).resolves.toBeDefined();
      expect(api.revokeCurrentOrganizationMembership).toHaveBeenCalledWith(
        expect.any(String),
        'org-1',
      );
      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({ status: 'not_required' });
    });

    it('treats an absence-like self-revoke rejection as idempotent only after sync proves removal', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      const implementation = vi.mocked(api.revokeCurrentOrganizationMembership).getMockImplementation()!;
      vi.mocked(api.revokeCurrentOrganizationMembership).mockImplementationOnce(async (...args) => {
        await implementation(...args);
        throw new ApiHttpError(403, 'already removed');
      });
      await service.sync();

      await expect(service.leaveOrganizationDataOwnership(
        'org-1',
        await dataOwnershipBinding(service, 'leave'),
        ODO_POPUP_DOCUMENT_ID,
      )).resolves.toBeDefined();
      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toEqual({ status: 'not_required' });
    });

    it('preserves an authoritative membership after a genuine self-revoke rejection', async () => {
      const response = makeSync();
      await addDataOwnershipTransfer(response);
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      vi.mocked(api.revokeCurrentOrganizationMembership)
        .mockRejectedValueOnce(new ApiHttpError(403, 'last owner'));
      await service.sync();

      await expect(service.leaveOrganizationDataOwnership(
        'org-1',
        await dataOwnershipBinding(service, 'leave'),
        ODO_POPUP_DOCUMENT_ID,
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.getOrganizationDataOwnershipStatus(ODO_POPUP_DOCUMENT_ID))
        .resolves.toMatchObject({ status: 'migration_available', organizationId: 'org-1' });
    });
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

  it('counts only top-level URL login matches without returning cipher metadata', async () => {
    const sync = makeSyncUrl();
    const first = sync.ciphers[0]!;
    first.id = 'first-match';
    first.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      uris: [{ uri: URL_VECTOR.encString, match: UriMatchStrategy.Domain }],
    };
    sync.ciphers.push({ ...first, id: 'second-match', reprompt: 1 });
    sync.ciphers.push({
      ...first,
      id: 'other-host',
      login: {
        ...first.login,
        uris: [{ uri: await encUnder('https://other.example/', testUserKey), match: UriMatchStrategy.Domain }],
      },
    });
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.countAutofillLoginMatches(
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
    )).resolves.toBe(2);
  });

  it('binds a login-match count to the exact vault generation', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login = {
      ...sync.ciphers[0]!.login,
      uris: [{ uri: URL_VECTOR.encString, match: UriMatchStrategy.Domain }],
    };
    const { service, api } = await makeService(sync);
    await service.sync();
    let assertFinal: (() => void) | undefined;
    await service.countAutofillLoginMatches(
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      (assertCurrent) => { assertFinal = assertCurrent; },
    );

    stubApi(api).sync = vi.fn(async () => ({
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [],
    }));
    await service.sync();
    expect(() => assertFinal?.()).toThrow(/vault changed|policy/i);
  });

  it('applies the per-login page-load tri-state only to automatic candidates', async () => {
    const sync = makeSyncUrl();
    const base = sync.ciphers[0]!;
    base.id = 'inherit-missing';
    base.login = { ...base.login, uris: [{ uri: URL_VECTOR.encString, match: UriMatchStrategy.Domain }] };
    sync.ciphers.push(
      {
        ...base,
        id: 'inherit-null',
        login: { ...base.login, autofillOnPageLoad: null },
      },
      {
        ...base,
        id: 'explicit-on',
        login: { ...base.login, autofillOnPageLoad: true },
      },
      {
        ...base,
        id: 'explicit-off',
        login: { ...base.login, autofillOnPageLoad: false },
      },
    );
    const { service } = await makeService(sync);
    await service.sync();

    const interactive = await service.findAutofillCandidates(
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      'login',
      'interactive',
    );
    const automaticDefaultOn = await service.findAutofillCandidates(
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      'login',
      'page-load',
    );
    const automaticDefaultOff = await service.findAutofillCandidates(
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      'login',
      'page-load',
      false,
    );

    expect(interactive.map((candidate) => candidate.id).sort()).toEqual([
      'explicit-off', 'explicit-on', 'inherit-missing', 'inherit-null',
    ]);
    expect(automaticDefaultOn.map((candidate) => candidate.id).sort()).toEqual([
      'explicit-on', 'inherit-missing', 'inherit-null',
    ]);
    expect(automaticDefaultOff.map((candidate) => candidate.id)).toEqual(['explicit-on']);
    const listing = await service.listItems();
    expect(listing.items.find((item) => item.id === 'inherit-null')).toHaveProperty('autofillOnPageLoad', null);
    expect(listing.items.find((item) => item.id === 'explicit-off')).toHaveProperty('autofillOnPageLoad', false);
    expect(listing.items.find((item) => item.id === 'inherit-missing')).not.toHaveProperty('autofillOnPageLoad');
    await expect(service.getCipherInput('explicit-off')).resolves.toMatchObject({
      login: { autofillOnPageLoad: false },
    });
    await expect(service.getAutofillLoginData(
      'explicit-off',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      { channel: 'page-load' },
    )).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillLoginData(
      'inherit-null',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      { channel: 'page-load', pageLoadFillDefault: false },
    )).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillLoginData(
      'inherit-missing',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      { channel: 'page-load', pageLoadFillDefault: false },
    )).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillLoginData(
      'explicit-on',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      { channel: 'page-load', pageLoadFillDefault: false, requireUnique: true },
    )).resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext });
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

  it('filters TOTP candidate queries to logins that actually have a TOTP seed', async () => {
    const sync = makeSyncUrl();
    sync.ciphers.push({
      id: 'totp-login',
      type: 1,
      name: await encUnder('TOTP Login', testUserKey),
      favorite: false,
      organizationId: null,
      login: {
        username: await encUnder('totp@example.com', testUserKey),
        totp: await encUnder(TOTP_SECRET_B32, testUserKey),
        uris: [{ uri: URL_VECTOR.encString }],
      },
    });
    const { service } = await makeService(sync);
    await service.sync();

    const candidates = await service.findAutofillCandidates(
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      'totp',
    );

    expect(candidates.map((candidate) => candidate.id)).toEqual(['totp-login']);
    expect(candidates[0]).toMatchObject({ hasTotp: true });
  });

  it('decrypts login intent data without touching a malformed TOTP ciphertext', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login!.totp = '2.bad|bad|bad';
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getAutofillLoginData(
      'cipher-1',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
    )).resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext });
  });

  it('decrypts TOTP intent data without touching a malformed password ciphertext', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login!.password = '2.bad|bad|bad';
    sync.ciphers[0]!.login!.totp = await encUnder(TOTP_SECRET_B32, testUserKey);
    const { service } = await makeService(sync, { now: () => 1111111109_000 });
    await service.sync();

    await expect(service.getAutofillTotpData(
      'cipher-1',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
    )).resolves.toEqual({ code: '081804', period: 30, remaining: 1 });
  });

  it('releases a reprompt-protected TOTP only with a live internal authorization', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.reprompt = 1;
    sync.ciphers[0]!.login!.totp = await encUnder(TOTP_SECRET_B32, testUserKey);
    const { service } = await makeService(sync, { now: () => 1111111109_000 });
    await service.sync();
    const assertRepromptAuthorized = vi.fn();

    await expect(service.getAutofillTotpData(
      'cipher-1',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
    )).rejects.toMatchObject({ code: 'reprompt_required' });
    await expect(service.getAutofillTotpData(
      'cipher-1',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      undefined,
      assertRepromptAuthorized,
    )).resolves.toEqual({ code: '081804', period: 30, remaining: 1 });
    expect(assertRepromptAuthorized).toHaveBeenCalled();
  });

  it('rechecks URI and purpose eligibility before narrow intent decryption', async () => {
    const { service } = await makeService(makeSyncUrl());
    await service.sync();

    await expect(service.getAutofillLoginData(
      'cipher-1',
      'https://not-matching.example.org',
      UriMatchStrategy.Domain,
    )).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillTotpData(
      'cipher-1',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
    )).rejects.toMatchObject({ code: 'denied' });
  });

  it('requires the same sole matching cipher for page-load login decryption', async () => {
    const sync = makeSyncUrl();
    sync.ciphers.push({
      ...structuredClone(sync.ciphers[0]!),
      id: 'cipher-2',
    });
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getAutofillLoginData(
      'cipher-1',
      URL_VECTOR.plaintext,
      UriMatchStrategy.Domain,
      { requireUnique: true },
    )).rejects.toMatchObject({ code: 'denied' });
  });

  it('getAutofillLoginData re-checks URI match before decrypting login data', async () => {
    const { service } = await makeService(makeSyncUrl());
    await service.sync();

    await expect(service.getAutofillLoginData('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain))
      .resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext });

    await expect(service.getAutofillLoginData('cipher-1', 'https://not-matching.example.org', UriMatchStrategy.Domain))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('getAutofillLoginData rejects when sync replaces its source cipher during decryption', async () => {
    const { service, api, session } = await makeService(makeSyncUrl());
    await service.sync();
    const pause = pauseNextUserKeyLoad(session);
    stubApi(api).sync = vi.fn(async () => ({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));

    const pending = service.getAutofillLoginData('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain);
    await pause.started;
    await service.sync();
    pause.release();

    await expect(pending).rejects.toMatchObject({ code: 'denied' });
  });

  it('getAutofillLoginData never returns TOTP when the login carries a TOTP secret', async () => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      totp: await encUnder(TOTP_SECRET_B32, testUserKey),
      uris: [{ uri: URL_VECTOR.encString, match: UriMatchStrategy.Domain }],
    };
    const { service } = await makeService(sync, { now: () => 1111111109_000 });
    await service.sync();
    await expect(service.getAutofillLoginData('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain))
      .resolves.toEqual({ username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext });
  });

  it('atomically resolves one exact-origin HTTP auth login without exposing a cipher selection', async () => {
    const { service } = await makeService(makeSyncUrl());
    await service.sync();

    await expect(service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).resolves.toEqual({
      username: FIELD_VECTOR.plaintext,
      password: FIELD_VECTOR.plaintext,
    });
  });

  it.each([
    ['path', 'https://example.com/login', UriMatchStrategy.Exact],
    ['query and fragment', 'https://example.com/login?next=%2F#step', UriMatchStrategy.StartsWith],
    ['explicit default port', 'https://example.com:443/login', UriMatchStrategy.Host],
  ] as const)('accepts a same-origin stored URI with a %s', async (_label, storedUri, match) => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login!.uris = [{
      uri: await encUnder(storedUri, testUserKey),
      match,
    }];
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).resolves.toEqual({
      username: FIELD_VECTOR.plaintext,
      password: FIELD_VECTOR.plaintext,
    });
  });

  it.each([
    ['scheme', 'http://example.com/login'],
    ['host', 'https://other.example.com/login'],
    ['port', 'https://example.com:8443/login'],
  ] as const)('rejects an HTTP auth stored URI with a different %s', async (_label, storedUri) => {
    const sync = makeSyncUrl();
    sync.ciphers[0]!.login!.uris = [{
      uri: await encUnder(storedUri, testUserKey),
      match: UriMatchStrategy.Host,
    }];
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).rejects.toMatchObject({ code: 'denied' });
  });

  it('rejects ambiguous, reprompt, never-match, and incomplete HTTP auth logins', async () => {
    const ambiguous = makeSyncUrl();
    ambiguous.ciphers.push({ ...structuredClone(ambiguous.ciphers[0]!), id: 'cipher-2' });
    const ambiguousService = await makeService(ambiguous);
    await ambiguousService.service.sync();
    await expect(ambiguousService.service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).rejects.toMatchObject({ code: 'denied' });

    const reprompt = makeSyncUrl();
    reprompt.ciphers[0]!.reprompt = 1;
    const repromptService = await makeService(reprompt);
    await repromptService.service.sync();
    await expect(repromptService.service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).rejects.toMatchObject({ code: 'denied' });

    const neverMatch = makeSyncUrl();
    neverMatch.ciphers[0]!.login!.uris = [{
      uri: await encUnder('https://example.com/login', testUserKey),
      match: UriMatchStrategy.Never,
    }];
    const neverMatchService = await makeService(neverMatch);
    await neverMatchService.service.sync();
    await expect(neverMatchService.service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).rejects.toMatchObject({ code: 'denied' });

    const incomplete = makeSyncUrl();
    delete incomplete.ciphers[0]!.login!.username;
    const incompleteService = await makeService(incomplete);
    await incompleteService.service.sync();
    await expect(incompleteService.service.getHttpAuthLoginData(
      'https://example.com/protected',
      UriMatchStrategy.Host,
    )).rejects.toMatchObject({ code: 'denied' });
  });

  it('rejects when a concurrent sync changes the selected URI within the same origin', async () => {
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const { service, api } = await makeService(makeSyncUrl(), {
      beforeHttpAuthCredentialDecrypt: async () => {
        markStarted();
        await gate;
      },
    });
    await service.sync();
    const replacement = makeSyncUrl();
    replacement.ciphers[0]!.login!.uris = [{
      uri: await encUnder('https://example.com/login', testUserKey),
      match: UriMatchStrategy.Host,
    }];
    stubApi(api).sync = vi.fn(async () => replacement);
    try {
      const pending = service.getHttpAuthLoginData(
        'https://example.com/protected',
        UriMatchStrategy.Host,
      );
      await started;
      await service.sync();
      release();
      await expect(pending).rejects.toMatchObject({
        code: expect.stringMatching(/^(?:denied|error)$/),
      });
    } finally {
      release();
    }
  });

  it('rejects when a concurrent sync replaces the selected candidate', async () => {
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const { service, api } = await makeService(makeSyncUrl(), {
      beforeHttpAuthCredentialDecrypt: async () => {
        markStarted();
        await gate;
      },
    });
    await service.sync();
    const replacement = makeSyncUrl();
    replacement.ciphers[0]!.id = 'cipher-2';
    replacement.ciphers[0]!.login!.username = await encUnder('replacement-user', testUserKey);
    replacement.ciphers[0]!.login!.password = await encUnder('replacement-secret', testUserKey);
    stubApi(api).sync = vi.fn(async () => replacement);
    try {
      const pending = service.getHttpAuthLoginData(
        'https://example.com/protected',
        UriMatchStrategy.Host,
      );
      await started;
      await service.sync();
      release();
      await expect(pending).rejects.toMatchObject({
        code: expect.stringMatching(/^(?:denied|error)$/),
      });
    } finally {
      release();
    }
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

    it('releases a reprompt password only through a live internal authorization proof', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service, auth } = await makeService(sync);
      await service.sync();
      let current = true;
      const proof = vi.fn(() => {
        if (!current) throw new Error('reprompt grant revoked');
      });
      let assertFinal: (() => void) | undefined;

      await expect(service.getField(
        'cipher-1',
        'password',
        undefined,
        (assertCurrent) => { assertFinal = assertCurrent; },
        proof,
      )).resolves.toBe(FIELD_VECTOR.plaintext);
      expect(auth.verifyMasterPassword).not.toHaveBeenCalled();
      expect(proof).toHaveBeenCalled();
      current = false;
      expect(() => assertFinal?.()).toThrow('reprompt grant revoked');
    });

    it('copies the visible login username without weakening reprompt for secret fields', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service, auth } = await makeService(sync);
      await service.sync();
      let assertFinal: (() => void) | undefined;

      await expect(service.getLoginUsernameForCopy(
        'cipher-1',
        (assertCurrent) => { assertFinal = assertCurrent; },
      )).resolves.toBe(FIELD_VECTOR.plaintext);
      expect(auth.verifyMasterPassword).not.toHaveBeenCalled();
      expect(() => assertFinal?.()).not.toThrow();
      await expect(service.getField('cipher-1', 'password'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
    });

    it('getCipherDetail enforces reprompt even though secret fields are stripped', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      await service.sync();

      await expect(service.getCipherDetail('cipher-1'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.getCipherDetail('cipher-1', 'correct-master'))
        .resolves.toMatchObject({ id: 'cipher-1', reprompt: true });
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

    it('getAutofillLoginData never releases a reprompt item into the page', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getAutofillLoginData('cipher-1', URL_VECTOR.plaintext, UriMatchStrategy.Domain))
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
          login: {},
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
          login: {},
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
          login: {},
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
            login: {},
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
      (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>)
        .mockResolvedValue('https://fresh-files.example/att-1?signature=current');
      (api.downloadAttachment as ReturnType<typeof vi.fn>).mockResolvedValue(blob);
      await service.sync();
      const result = await service.getAttachment('cipher-1', 'att-1');
      expect(api.getAttachmentDownloadUrl)
        .toHaveBeenCalledWith('access', 'cipher-1', 'att-1');
      expect(api.downloadAttachment)
        .toHaveBeenCalledWith('https://fresh-files.example/att-1?signature=current', 'access');
      expect(result.fileName).toBe('report.pdf');
      expect(result.dataB64).toBe(bytesToBase64(new TextEncoder().encode('secret-file-contents')));
      expect(blob.every((byte) => byte === 0)).toBe(true);
    });

    it('decrypts a personal legacy attachment directly with the UserKey', async () => {
      const plain = new TextEncoder().encode('legacy-personal-contents');
      const blob = await encryptAttachmentFile(plain, testUserKey);
      const sync = makeSync();
      sync.ciphers[0]!.attachments = [{
        id: 'legacy-personal',
        url: 'https://files.example/legacy-personal',
        key: null,
        fileName: await encUnder('legacy-personal.txt', testUserKey),
      }];
      const { service, api } = await makeService(sync);
      vi.mocked(api.downloadAttachment).mockResolvedValue(blob);
      await service.sync();

      await expect(service.getAttachment('cipher-1', 'legacy-personal')).resolves.toEqual({
        fileName: 'legacy-personal.txt',
        dataB64: bytesToBase64(plain),
      });
      expect(blob.every((byte) => byte === 0)).toBe(true);
    });

    it('uses the owning UserKey for a legacy attachment on a later keyed cipher', async () => {
      const perCipherKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x61));
      const plain = new TextEncoder().encode('legacy-on-keyed-cipher');
      const blob = await encryptAttachmentFile(plain, testUserKey);
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [{
          id: 'keyed-cipher',
          type: 1,
          key: await wrapAttachmentKey(perCipherKey, testUserKey),
          name: await encUnder('Keyed item', perCipherKey),
          favorite: false,
          organizationId: null,
          login: {},
          attachments: [{
            id: 'legacy-keyed',
            key: null,
            fileName: await encUnder('legacy-keyed.txt', perCipherKey),
          }],
        }],
      };
      const { service, api } = await makeService(sync);
      vi.mocked(api.downloadAttachment).mockResolvedValue(blob);
      await service.sync();

      await expect(service.getAttachment('keyed-cipher', 'legacy-keyed')).resolves.toEqual({
        fileName: 'legacy-keyed.txt',
        dataB64: bytesToBase64(plain),
      });
    });

    it('decrypts an organization legacy attachment directly with the OrgKey', async () => {
      const plain = new TextEncoder().encode('legacy-organization-contents');
      const blob = await encryptAttachmentFile(plain, orgKey);
      const sync = await makeOrgSync();
      sync.ciphers[0]!.attachments = [{
        id: 'legacy-org',
        key: null,
        fileName: await encUnder('legacy-org.txt', orgKey),
      }];
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      vi.mocked(api.downloadAttachment).mockResolvedValue(blob);
      await service.sync();

      await expect(service.getAttachment('org-login', 'legacy-org')).resolves.toEqual({
        fileName: 'legacy-org.txt',
        dataB64: bytesToBase64(plain),
      });
    });

    it('upgrades a personal legacy attachment before deleting the old copy', async () => {
      const plain = new TextEncoder().encode('legacy-upgrade-contents');
      const legacyBlob = await encryptAttachmentFile(plain, testUserKey);
      const sync = makeSync();
      sync.ciphers[0]!.attachments = [{
        id: 'legacy-old',
        key: null,
        fileName: await encUnder('legacy.txt', testUserKey),
      }];
      const { service, api } = await makeService(sync);
      vi.mocked(api.downloadAttachment).mockResolvedValue(legacyBlob);
      let uploaded: Uint8Array | undefined;
      vi.mocked(api.uploadAttachmentSlotData).mockImplementation(async (
        _token,
        _cipherId,
        _receipt,
        _encryptedFileName,
        data,
      ) => { uploaded = new Uint8Array(data); });
      await service.sync();

      await expect(service.upgradeLegacyAttachment('cipher-1', 'legacy-old'))
        .resolves.toBeDefined();

      const slotRequest = vi.mocked(api.createAttachmentUploadSlot).mock.calls[0]![2];
      const attachmentKey = await unwrapSymmetricKey(slotRequest.key, testUserKey);
      const upgradedPlaintext = await decryptAttachmentFile(uploaded!, attachmentKey);
      expect(new TextDecoder().decode(upgradedPlaintext)).toBe('legacy-upgrade-contents');
      expect(await decryptToText(slotRequest.fileName, testUserKey)).toBe('legacy.txt');
      expect(api.deleteAttachment).toHaveBeenCalledWith('access', 'cipher-1', 'legacy-old');
      expect(vi.mocked(api.uploadAttachmentSlotData).mock.invocationCallOrder[0])
        .toBeLessThan(vi.mocked(api.deleteAttachment).mock.invocationCallOrder[0]!);
      expect(sync.ciphers[0]!.attachments).toEqual([
        expect.objectContaining({ id: 'new-attachment-1', key: slotRequest.key }),
      ]);
      expect(legacyBlob.every((byte) => byte === 0)).toBe(true);
      expect(vi.mocked(api.uploadAttachmentSlotData).mock.calls[0]![4]
        .every((byte) => byte === 0)).toBe(true);
      upgradedPlaintext.fill(0);
      attachmentKey.encKey.fill(0);
      attachmentKey.macKey.fill(0);
    });

    it('keeps the old legacy attachment when the replacement upload is rolled back', async () => {
      const plain = new TextEncoder().encode('legacy-preserved');
      const sync = makeSync();
      sync.ciphers[0]!.attachments = [{
        id: 'legacy-old',
        key: null,
        fileName: await encUnder('legacy.txt', testUserKey),
      }];
      const { service, api } = await makeService(sync);
      vi.mocked(api.downloadAttachment).mockResolvedValue(
        await encryptAttachmentFile(plain, testUserKey),
      );
      const uploadError = new ApiHttpError(503, { message: 'upload failed' });
      vi.mocked(api.uploadAttachmentSlotData).mockRejectedValueOnce(uploadError);
      await service.sync();

      await expect(service.upgradeLegacyAttachment('cipher-1', 'legacy-old'))
        .rejects.toBe(uploadError);
      expect(api.deleteAttachment).toHaveBeenCalledTimes(1);
      expect(api.deleteAttachment).toHaveBeenCalledWith(
        'access', 'cipher-1', 'new-attachment-1',
      );
      expect(sync.ciphers[0]!.attachments).toEqual([
        expect.objectContaining({ id: 'legacy-old', key: null }),
      ]);
    });

    it('keeps both copies and requires reconciliation when deleting the old copy fails', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.attachments = [{
        id: 'legacy-old',
        key: null,
        fileName: await encUnder('legacy.txt', testUserKey),
      }];
      const { service, api } = await makeService(sync);
      vi.mocked(api.downloadAttachment).mockResolvedValue(
        await encryptAttachmentFile(new TextEncoder().encode('legacy-preserved'), testUserKey),
      );
      vi.mocked(api.deleteAttachment).mockImplementation(async (_token, _cipherId, attachmentId) => {
        if (attachmentId === 'legacy-old') {
          throw new ApiHttpError(503, { message: 'delete outcome unknown' });
        }
      });
      await service.sync();

      await expect(service.upgradeLegacyAttachment('cipher-1', 'legacy-old'))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(sync.ciphers[0]!.attachments).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: 'legacy-old', key: null }),
        expect.objectContaining({ id: 'new-attachment-1' }),
      ]));
      expect(api.deleteAttachment).toHaveBeenCalledTimes(1);
    });

    it('refuses to upgrade a modern attachment or one with an undecryptable name', async () => {
      const modern = await syncWithAttachment();
      const modernService = await makeService(modern.sync);
      await modernService.service.sync();
      await expect(modernService.service.upgradeLegacyAttachment('cipher-1', 'att-1'))
        .rejects.toMatchObject({ code: 'conflict' });
      expect(modernService.api.createAttachmentUploadSlot).not.toHaveBeenCalled();

      const corrupt = makeSync();
      corrupt.ciphers[0]!.attachments = [{
        id: 'legacy-corrupt',
        key: null,
        fileName: '2.invalid',
      }];
      const corruptService = await makeService(corrupt);
      await corruptService.service.sync();
      await expect(corruptService.service.upgradeLegacyAttachment('cipher-1', 'legacy-corrupt'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(corruptService.api.downloadAttachment).not.toHaveBeenCalled();
      expect(corruptService.api.createAttachmentUploadSlot).not.toHaveBeenCalled();
    });

    it('uses the cached attachment URL only when the fresh-URL endpoint returns 404', async () => {
      const { sync, blob } = await syncWithAttachment();
      const { service, api } = await makeService(sync);
      (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>)
        .mockRejectedValue(new ApiHttpError(404, { message: 'unsupported' }));
      (api.downloadAttachment as ReturnType<typeof vi.fn>).mockResolvedValue(blob);
      await service.sync();

      await expect(service.getAttachment('cipher-1', 'att-1')).resolves.toMatchObject({
        fileName: 'report.pdf',
      });
      expect(api.downloadAttachment).toHaveBeenCalledWith('https://files.example/att-1', 'access');
    });

    it('does not hide a fresh-URL 404 when no cached URL is available', async () => {
      const { sync } = await syncWithAttachment();
      delete sync.ciphers[0]!.attachments![0]!.url;
      const { service, api } = await makeService(sync);
      const missing = new ApiHttpError(404, { message: 'unsupported' });
      (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>).mockRejectedValue(missing);
      await service.sync();

      await expect(service.getAttachment('cipher-1', 'att-1')).rejects.toBe(missing);
      expect(api.downloadAttachment).not.toHaveBeenCalled();
    });

    it('does not fall back to a cached attachment URL for non-404 or invalid fresh responses', async () => {
      const { sync } = await syncWithAttachment();
      const { service, api } = await makeService(sync);
      await service.sync();

      for (const error of [
        new ApiHttpError(503, { message: 'unavailable' }),
        new Error('attachment download response is invalid'),
      ]) {
        (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>).mockRejectedValueOnce(error);
        await expect(service.getAttachment('cipher-1', 'att-1')).rejects.toBe(error);
      }
      expect(api.downloadAttachment).not.toHaveBeenCalled();
    });

    it('downloads with a fresh URL when the sync snapshot has no cached URL', async () => {
      const { sync, blob } = await syncWithAttachment();
      delete sync.ciphers[0]!.attachments![0]!.url;
      const { service, api } = await makeService(sync);
      (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>)
        .mockResolvedValue('https://fresh-files.example/att-1');
      (api.downloadAttachment as ReturnType<typeof vi.fn>).mockResolvedValue(blob);
      await service.sync();

      await expect(service.getAttachment('cipher-1', 'att-1')).resolves.toMatchObject({
        fileName: 'report.pdf',
      });
      expect(api.downloadAttachment).toHaveBeenCalledWith('https://fresh-files.example/att-1', 'access');
    });

    it('rechecks the cache lease after resolving the fresh URL and before downloading bytes', async () => {
      const { sync } = await syncWithAttachment();
      const { service, api } = await makeService(sync);
      await service.sync();
      (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        await service.sync();
        return 'https://fresh-files.example/att-1';
      });

      await expect(service.getAttachment('cipher-1', 'att-1')).rejects.toThrow();
      expect(api.downloadAttachment).not.toHaveBeenCalled();
    });

    it('rechecks the session lease after resolving the fresh URL', async () => {
      const { sync } = await syncWithAttachment();
      let generation = 0;
      const sessionGate: SessionLeaseGate = {
        capture: () => ({ generation }),
        assert: (lease) => {
          if (lease.generation !== generation) throw new Error('session changed');
        },
      };
      const { service, api } = await makeService(sync, { sessionGate });
      await service.sync();
      (api.getAttachmentDownloadUrl as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        generation++;
        return 'https://fresh-files.example/att-1';
      });

      await expect(service.getAttachment('cipher-1', 'att-1')).rejects.toThrow('session changed');
      expect(api.downloadAttachment).not.toHaveBeenCalled();
    });

    it('getAttachment requires the master password for a reprompt item', async () => {
      const { sync, blob } = await syncWithAttachment({ reprompt: 1 });
      const { service, api } = await makeService(sync);
      (api.downloadAttachment as ReturnType<typeof vi.fn>).mockResolvedValue(blob);
      await service.sync();
      await expect(service.getAttachment('cipher-1', 'att-1')).rejects.toMatchObject({ code: 'reprompt_required' });
    });

    it('addAttachment allocates a v2 slot, uploads encrypted bytes, zeroes buffers, and re-syncs', async () => {
      const { service, api } = await makeService();
      let encryptedSnapshot: Uint8Array | undefined;
      vi.mocked(api.uploadAttachmentSlotData).mockImplementation(async (
        _token,
        _cipherId,
        _receipt,
        _encryptedFileName,
        data,
      ) => {
        encryptedSnapshot = new Uint8Array(data);
      });
      await service.sync();
      await service.addAttachment('cipher-1', 'notes.txt', bytesToBase64(new TextEncoder().encode('plain text body')));
      const [token, cipherId, request] = (api.createAttachmentUploadSlot as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(token).toBe('access');
      expect(cipherId).toBe('cipher-1');
      expect(request.key.startsWith('2.')).toBe(true);
      expect(request.fileName.startsWith('2.')).toBe(true);
      expect(request.fileSize).toBe(encryptedSnapshot!.byteLength);
      expect(request.adminRequest).toBe(false);
      const uploadArgs = (api.uploadAttachmentSlotData as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(uploadArgs[0]).toBe('access');
      expect(uploadArgs[1]).toBe('cipher-1');
      expect(uploadArgs[2].attachmentId).toBe('new-attachment-1');
      expect(uploadArgs[3]).toBe(request.fileName);
      expect(encryptedSnapshot![0]).toBe(2);
      expect(JSON.stringify([...encryptedSnapshot!])).not.toContain('plain');
      expect((uploadArgs[4] as Uint8Array).every((byte) => byte === 0)).toBe(true);
      expect(api.uploadAttachment).not.toHaveBeenCalled();
      expect(api.sync).toHaveBeenCalled();
    });

    it('rejects an exact duplicate of a decrypted attachment file name before remote I/O', async () => {
      const { sync } = await syncWithAttachment();
      const { service, api } = await makeService(sync);
      await service.sync();

      await expect(service.addAttachment('cipher-1', 'report.pdf', 'AA=='))
        .rejects.toMatchObject({
          code: 'conflict',
          message: 'An attachment with this file name already exists.',
        });
      expect(api.createAttachmentUploadSlot).not.toHaveBeenCalled();
      expect(api.uploadAttachmentSlotData).not.toHaveBeenCalled();
      expect(api.deleteAttachment).not.toHaveBeenCalled();
    });

    it('rechecks the raw cache generation before allocating a duplicate-free attachment slot', async () => {
      const setup = await makeService();
      await setup.service.sync();
      const originalEncryptToText = encstringNs.encryptToText;
      let markEncryptStarted!: () => void;
      const encryptStarted = new Promise<void>((resolve) => { markEncryptStarted = resolve; });
      let releaseEncrypt!: () => void;
      const encryptGate = new Promise<void>((resolve) => { releaseEncrypt = resolve; });
      const encryptText = vi.spyOn(encstringNs, 'encryptToText').mockImplementationOnce(async (...args) => {
        markEncryptStarted();
        await encryptGate;
        return originalEncryptToText(...args);
      });

      const pending = setup.service.addAttachment('cipher-1', 'cache-race.txt', 'AA==');
      await encryptStarted;
      const raw = await setup.localStore.get<{
        schemaVersion: 2;
        identity: string;
        rawGeneration: string;
        response: SyncResponse;
      }>(RAW_VAULT_CACHE_KEY);
      if (!raw) throw new Error('test cache was not initialized');
      await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
        ...raw,
        rawGeneration: 'attachment-cache-race',
      });
      releaseEncrypt();

      await expect(pending).rejects.toThrow(/vault changed/i);
      encryptText.mockRestore();
      expect(setup.api.createAttachmentUploadSlot).not.toHaveBeenCalled();
      expect(setup.api.uploadAttachmentSlotData).not.toHaveBeenCalled();
    });

    it('rechecks the session lease at the final attachment-slot request guard', async () => {
      let generation = 0;
      const sessionGate: SessionLeaseGate = {
        capture: () => ({ generation }),
        assert: (lease) => {
          if (lease.generation !== generation) throw new AppError('locked', 'Session changed.');
        },
      };
      const { service, api } = await makeService(makeSync(), {
        sessionGate,
        beforeRequestGuard: async (method) => {
          if (method === 'createAttachmentUploadSlot') generation += 1;
        },
      });
      await service.sync();

      await expect(service.addAttachment('cipher-1', 'session-race.txt', 'AA=='))
        .rejects.toMatchObject({ code: 'locked' });
      expect(api.createAttachmentUploadSlot).not.toHaveBeenCalled();
      expect(api.uploadAttachmentSlotData).not.toHaveBeenCalled();
    });

    it('rechecks the account lease at the final attachment-slot request guard', async () => {
      const accountGate = new AccountLeaseGate();
      accountGate.initialize({ serverUrl: 'https://vault.example', accountIdentity: 'u@example.com' });
      const { service, api } = await makeService(makeSync(), {
        accountGate,
        beforeRequestGuard: async (method) => {
          if (method === 'createAttachmentUploadSlot') accountGate.beginAccountTransition();
        },
      });
      await service.sync();

      await expect(service.addAttachment('cipher-1', 'account-race.txt', 'AA=='))
        .rejects.toMatchObject({ code: 'session_expired' });
      expect(api.createAttachmentUploadSlot).not.toHaveBeenCalled();
      expect(api.uploadAttachmentSlotData).not.toHaveBeenCalled();
    });

    it('rolls back an allocated slot, verifies absence, and clears the mutation barrier', async () => {
      const { service, api } = await makeService();
      await service.sync();
      const uploadError = new ApiHttpError(503, { message: 'blob unavailable' });
      vi.mocked(api.uploadAttachmentSlotData).mockRejectedValueOnce(uploadError);

      await expect(service.addAttachment('cipher-1', 'failed.txt', 'AA=='))
        .rejects.toBe(uploadError);
      expect(api.deleteAttachment).toHaveBeenCalledWith(
        'access',
        'cipher-1',
        'new-attachment-1',
      );
      expect(api.sync).toHaveBeenCalledTimes(2);

      await expect(service.addAttachment('cipher-1', 'retry.txt', 'AQ=='))
        .resolves.toBeDefined();
      expect(api.createAttachmentUploadSlot).toHaveBeenCalledTimes(2);
    });

    it('retains the dirty barrier when slot rollback cannot be proven', async () => {
      const { service, api } = await makeService();
      await service.sync();
      vi.mocked(api.uploadAttachmentSlotData).mockRejectedValueOnce(
        new ApiHttpError(503, { message: 'blob unavailable' }),
      );
      vi.mocked(api.deleteAttachment).mockRejectedValueOnce(
        new ApiHttpError(503, { message: 'rollback unavailable' }),
      );

      await expect(service.addAttachment('cipher-1', 'failed.txt', 'AA=='))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      await expect(service.addAttachment('cipher-1', 'blocked.txt', 'AQ=='))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(api.createAttachmentUploadSlot).toHaveBeenCalledOnce();
    });

    it('does not upload or roll back when slot allocation is definitely rejected', async () => {
      const { service, api } = await makeService();
      await service.sync();
      vi.mocked(api.createAttachmentUploadSlot).mockRejectedValueOnce(
        new ApiHttpError(422, { message: 'invalid attachment' }),
      );

      await expect(service.addAttachment('cipher-1', 'rejected.txt', 'AA==')).rejects.toBeTruthy();
      expect(api.uploadAttachmentSlotData).not.toHaveBeenCalled();
      expect(api.deleteAttachment).not.toHaveBeenCalled();

      await expect(service.addAttachment('cipher-1', 'retry.txt', 'AQ=='))
        .resolves.toBeDefined();
    });

    it('keeps the mutation dirty when the authoritative sync omits the uploaded attachment', async () => {
      const { service, api } = await makeService();
      await service.sync();
      stubApi(api).sync = vi.fn(async () => makeSync());

      await expect(service.addAttachment('cipher-1', 'unverified.txt', 'AA=='))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(api.uploadAttachmentSlotData).toHaveBeenCalledOnce();
      expect(api.deleteAttachment).not.toHaveBeenCalled();
    });

    it.each([
      ['', 'AA=='],
      ['bad\nname.txt', 'AA=='],
      ['valid.txt', 'not-base64'],
      ['valid.txt', 'A==='],
    ])('rejects invalid attachment input before allocating a slot', async (fileName, dataB64) => {
      const { service, api } = await makeService();
      await service.sync();

      await expect(service.addAttachment('cipher-1', fileName, dataB64))
        .rejects.toMatchObject({ code: 'error' });
      expect(api.createAttachmentUploadSlot).not.toHaveBeenCalled();
    });

    it('keeps a concurrent sync behind attachment preparation and reconciliation', async () => {
      const { service, api, session } = await makeService();
      await service.sync();
      const pause = pauseNextPrivateKeyLoad(session);

      const pending = service.addAttachment(
        'cipher-1',
        'stale.txt',
        bytesToBase64(new TextEncoder().encode('must not upload')),
      );
      await pause.started;
      const trailingSync = service.sync();
      pause.release();

      await expect(pending).resolves.toBeDefined();
      await trailingSync;
      expect(api.createAttachmentUploadSlot).toHaveBeenCalledOnce();
      expect(api.uploadAttachmentSlotData).toHaveBeenCalledOnce();
    });

    it('deleteAttachment calls the API and re-syncs', async () => {
      const { service, api } = await makeService();
      await service.sync();
      await service.deleteAttachment('cipher-1', 'att-1');
      expect(api.deleteAttachment).toHaveBeenCalledWith('access', 'cipher-1', 'att-1');
      expect(api.sync).toHaveBeenCalled();
    });

    it('allows archived attachment changes but keeps trashed attachments read-only', async () => {
      const archivedFixture = await syncWithAttachment();
      archivedFixture.sync.ciphers[0]!.archivedDate = '2026-08-29T00:00:00.000Z';
      const archived = await makeService(archivedFixture.sync);
      await archived.service.sync();
      await expect(archived.service.addAttachment('cipher-1', 'new.txt', ''))
        .resolves.toBeDefined();
      await expect(archived.service.deleteAttachment('cipher-1', 'att-1'))
        .resolves.toBeDefined();
      expect(archived.api.createAttachmentUploadSlot).toHaveBeenCalledOnce();
      expect(archived.api.uploadAttachmentSlotData).toHaveBeenCalledOnce();
      expect(archived.api.deleteAttachment).toHaveBeenCalledOnce();

      const deletedFixture = await syncWithAttachment();
      deletedFixture.sync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
      const deleted = await makeService(deletedFixture.sync);
      vi.mocked(deleted.api.downloadAttachment).mockResolvedValue(deletedFixture.blob);
      await deleted.service.sync();
      await expect(deleted.service.getAttachment('cipher-1', 'att-1'))
        .resolves.toMatchObject({ fileName: 'report.pdf' });
      await expect(deleted.service.addAttachment('cipher-1', 'forbidden.txt', ''))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(deleted.service.deleteAttachment('cipher-1', 'att-1'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(deleted.api.createAttachmentUploadSlot).not.toHaveBeenCalled();
      expect(deleted.api.uploadAttachmentSlotData).not.toHaveBeenCalled();
      expect(deleted.api.deleteAttachment).not.toHaveBeenCalled();
    });
  });

  describe('sends', () => {
    it('listSends decrypts each send for display with its share URL', async () => {
      const { request } = await buildTextSendRequest({ name: 'Shared note', text: 'body', deletionDays: 7 }, testUserKey);
      const { service, api } = await makeServiceWithRaw();
      (api.listSends as ReturnType<typeof vi.fn>).mockResolvedValue([{ id: 's1', accessId: 'acc1', ...request }]);
      const sends = await service.listSends('https://vault.example');
      expect(sends).toHaveLength(1);
      expect(sends[0]).toMatchObject({ id: 's1', name: 'Shared note', text: 'body' });
      expect(sends[0]!.url).toContain('https://vault.example/#/send/acc1/');
    });

    it('createTextSend posts an encrypted send and returns it with a share URL', async () => {
      const { service, api } = await makeServiceWithRaw();
      const summary = await service.createTextSend(
        { name: 'Hi', text: 'secret-body', hideEmail: true, deletionDays: 7 },
        'https://vault.example',
      );
      const [token, body] = (api.createSend as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(token).toBe('access');
      expect(JSON.stringify(body)).not.toContain('secret-body'); // text is encrypted
      expect((body as SendRequest).hideEmail).toBe(true);
      expect(summary.name).toBe('Hi');
      expect(summary.hideEmail).toBe(true);
      expect(summary.url).toContain('https://vault.example/#/send/acc1/');
    });

    it('uses authoritative dates from the create receipt instead of the requested dates', async () => {
      const { service, api } = await makeServiceWithRaw(makeSync(), { now: () => 0 });
      const receiptDeletionDate = new Date(3_599_000).toISOString();
      const receiptExpirationDate = new Date(3_598_000).toISOString();
      stubApi(api).createSend = vi.fn(async (_token: string, request: SendRequest) => ({
        ...request,
        id: 's-receipt',
        accessId: 'a-receipt',
        deletionDate: receiptDeletionDate,
        expirationDate: receiptExpirationDate,
      }));

      const summary = await service.createTextSend(
        { name: 'Receipt', text: 'body', deletionHours: 1, expirationHours: 1 },
        'https://vault.example',
      );
      expect(summary.deletionDate).toBe(receiptDeletionDate);
      expect(summary.expirationDate).toBe(receiptExpirationDate);
    });

    it('deleteSend calls the API by id', async () => {
      const { service, api } = await makeServiceWithRaw();
      await service.deleteSend('s1');
      expect(api.deleteSend).toHaveBeenCalledWith('access', 's1');
    });

    it('createFileSend encrypts the file, uploads via v2, and returns a decrypted summary', async () => {
      const { service, api } = await makeServiceWithRaw();
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
      const { service, api } = await makeServiceWithRaw();
      stubApi(api).createSendFile = vi.fn(async () => ({ url: '/sends/s9/file/f9', sendResponse: { id: 's9', accessId: 'a9', type: 1, file: { fileName: '2.enc' } } }));
      stubApi(api).uploadSendFileData = vi.fn(async () => { throw new Error('upload boom'); });
      stubApi(api).deleteSend = vi.fn(async () => {});
      const dataB64 = btoa(String.fromCharCode(1, 2, 3));
      await expect(service.createFileSend({ name: 'Doc', deletionDays: 7 }, dataB64, 'f.pdf', 'http://localhost:8080'))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(stubApi(api).deleteSend).toHaveBeenCalledWith('access', 's9');
    });

    it('keeps an off-origin Send blob 401 on the single-attempt path without refreshing', async () => {
      let forcedRefreshes = 0;
      const executeAuthenticatedRequest: AuthService['executeAuthenticatedRequest'] = async (
        _lease,
        rebuildRequest,
      ) => {
        try {
          return await rebuildRequest('access');
        } catch (error) {
          if (error instanceof ApiHttpError && error.status === 401) {
            forcedRefreshes += 1;
            return rebuildRequest('refreshed-access');
          }
          throw error;
        }
      };
      const { service, api } = await makeServiceWithRaw(makeSync(), { executeAuthenticatedRequest });
      stubApi(api).createSendFile = vi.fn(async () => ({
        url: 'https://cdn.example/upload',
        sendResponse: { id: 's-cdn', accessId: 'a-cdn', type: 1, file: { fileName: '2.enc' } },
      }));
      stubApi(api).uploadSendFileData = vi.fn(async () => {
        throw new ApiHttpError(401, 'external unauthorized');
      });
      stubApi(api).deleteSend = vi.fn(async () => {});
      const dataB64 = btoa(String.fromCharCode(1, 2, 3));

      await expect(service.createFileSend(
        { name: 'CDN', deletionDays: 7 },
        dataB64,
        'f.pdf',
        'http://localhost:8080',
      )).rejects.toMatchObject({ code: 'committed_unsynced' });

      expect(stubApi(api).uploadSendFileData).toHaveBeenCalledOnce();
      expect(forcedRefreshes).toBe(0);
      expect(stubApi(api).deleteSend).toHaveBeenCalledWith('access', 's-cdn');
    });

    it('createFileSend compensates its exact orphan when the session changes before blob upload', async () => {
      let generation = 0;
      const sessionGate: SessionLeaseGate = {
        capture: () => ({ generation }),
        assert: (lease) => {
          if (lease.generation !== generation) throw new Error('Vault session changed');
        },
      };
      const { service, api } = await makeServiceWithRaw(makeSync(), { sessionGate });
      stubApi(api).createSendFile = vi.fn(async () => {
        generation++;
        return { url: '/sends/s10/file/f10', sendResponse: { id: 's10', accessId: 'a10', type: 1, file: { fileName: '2.enc' } } };
      });
      stubApi(api).uploadSendFileData = vi.fn(async () => {});
      stubApi(api).deleteSend = vi.fn(async () => {});
      const dataB64 = btoa(String.fromCharCode(1, 2, 3));

      await expect(service.createFileSend({ name: 'Doc', deletionDays: 7 }, dataB64, 'f.pdf', 'http://localhost:8080'))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(stubApi(api).uploadSendFileData).not.toHaveBeenCalled();
      expect(stubApi(api).deleteSend).toHaveBeenCalledWith('access', 's10');
    });

    it('updateSend re-fetches the existing send, PUTs the rebuilt request, and returns the decrypted summary', async () => {
      const { service, api } = await makeServiceWithRaw();
      const existing = { id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString, key: await validSendKeyEncString(), text: { text: FIELD_VECTOR.encString }, deletionDate: new Date(0).toISOString(), accessCount: 0 };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async (_token: string, _id: string, request: SendRequest) => ({
        ...existing,
        ...request,
      }));
      stubApi(api).removeSendPassword = vi.fn(async () => {});
      const summary = await service.updateSend(
        's1',
        { name: 'New', text: 'x', hideEmail: true, passwordMode: 'keep' },
        'http://localhost:8080',
      );
      expect(stubApi(api).updateSend).toHaveBeenCalledWith(
        'access',
        's1',
        expect.objectContaining({ key: existing.key, hideEmail: true }),
      );
      expect(stubApi(api).removeSendPassword).not.toHaveBeenCalled();
      expect(summary.id).toBe('s1');
      expect(summary.hideEmail).toBe(true);
    });

    it('updateSend preserves private notes and modern auth metadata on whole-object PUT', async () => {
      const { service, api } = await makeServiceWithRaw();
      const built = await buildTextSendRequest({
        name: 'Original',
        notes: 'private note',
        text: 'body',
        deletionDays: 7,
      }, testUserKey);
      const existing = {
        id: 's-notes',
        accessId: 'a-notes',
        ...built.request,
        authType: 2,
        emails: null,
        accessCount: 0,
      };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async (_token: string, _id: string, request: SendRequest) => ({
        ...existing,
        ...request,
      }));

      const summary = await service.updateSend(
        's-notes',
        { name: 'Renamed', text: 'updated', passwordMode: 'keep' },
        'https://vault.example',
      );
      const sent = (stubApi(api).updateSend as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[2] as SendRequest;
      expect(sent.notes).toBe(existing.notes);
      expect(sent.authType).toBe(2);
      expect(sent.emails).toBeNull();
      expect(summary.notes).toBe('private note');
    });

    it('updateSend calls removeSendPassword when passwordMode is remove, and throws when the send is gone', async () => {
      const { service, api } = await makeServiceWithRaw();
      const existing = { id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString, key: await validSendKeyEncString(), text: { text: FIELD_VECTOR.encString }, deletionDate: new Date(0).toISOString(), accessCount: 0 };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async () => existing);
      stubApi(api).removeSendPassword = vi.fn(async () => {});
      await service.updateSend('s1', { name: 'N', passwordMode: 'remove' }, 'https://x');
      expect(stubApi(api).removeSendPassword).toHaveBeenCalledWith('access', 's1');
      stubApi(api).listSends = vi.fn(async () => []);
      await expect(service.updateSend('missing', { name: 'N' }, 'https://x')).rejects.toMatchObject({ code: 'error' });
    });
    it('updateSend uses the PUT response and does not list sends a second time', async () => {
      const { service, api } = await makeServiceWithRaw();
      const existing = { id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString, key: await validSendKeyEncString(), text: { text: FIELD_VECTOR.encString }, deletionDate: new Date(0).toISOString(), accessCount: 3 };
      const receiptDeletionDate = new Date(8_000_000).toISOString();
      const putResponse = { ...existing, accessCount: 9, deletionDate: receiptDeletionDate };
      const listSends = vi.fn(async () => [existing]);
      stubApi(api).listSends = listSends;
      stubApi(api).updateSend = vi.fn(async () => putResponse);
      stubApi(api).removeSendPassword = vi.fn(async () => {});
      const summary = await service.updateSend('s1', { name: 'New', text: 'x', passwordMode: 'keep' }, 'http://localhost:8080');
      expect(listSends).toHaveBeenCalledTimes(1); // only the pre-PUT read; the PUT response is reused
      expect(summary.accessCount).toBe(9); // comes from the PUT response, not a re-list
      expect(summary.deletionDate).toBe(receiptDeletionDate);
    });

    it('updateSend reflects password removal in the returned summary (passwordProtected false)', async () => {
      const { service, api } = await makeServiceWithRaw();
      // The PUT response still carries the pre-removal password hash; removeSendPassword clears it after.
      const existing = { id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString, key: await validSendKeyEncString(), text: { text: FIELD_VECTOR.encString }, deletionDate: new Date(0).toISOString(), accessCount: 0, password: 'still-hashed' };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async () => existing);
      stubApi(api).removeSendPassword = vi.fn(async () => {});
      const summary = await service.updateSend('s1', { name: 'N', passwordMode: 'remove' }, 'https://x');
      expect(stubApi(api).removeSendPassword).toHaveBeenCalledWith('access', 's1');
      expect(summary.passwordProtected).toBe(false);
    });

    it('DisableSend blocks create and update while preserving list and delete access', async () => {
      const response = withEnterprisePolicies(makeSync(), [{ type: EnterprisePolicyType.DisableSend }]);
      const { service, api } = await makeService(response);
      await service.sync();
      const { request } = await buildTextSendRequest(
        { name: 'Existing', text: 'body', deletionDays: 7 },
        testUserKey,
      );
      stubApi(api).listSends = vi.fn(async () => [{ id: 's1', accessId: 'a1', ...request }]);
      stubApi(api).updateSend = vi.fn(async () => ({ id: 's1', accessId: 'a1', ...request }));

      await expect(service.listSends('https://vault.example')).resolves.toHaveLength(1);
      await expect(service.createTextSend(
        { name: 'Blocked', deletionDays: 7 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.updateSend(
        's1',
        { name: 'Blocked' },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.deleteSend('s1')).resolves.toBeUndefined();

      expect(api.createSend).not.toHaveBeenCalled();
      expect(stubApi(api).updateSend).not.toHaveBeenCalled();
      expect(api.deleteSend).toHaveBeenCalledWith('access', 's1');
    });

    it('enforces allowed Send types without confusing text hidden with hideEmail', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.SendControls,
        data: { allowedSendTypes: [0], disableHideEmail: true },
      }]);
      const { service, api } = await makeService(response);
      await service.sync();

      await expect(service.createTextSend(
        { name: 'Allowed', text: 'secret', hidden: true, deletionDays: 7 },
        'https://vault.example',
      )).resolves.toMatchObject({ type: 0, hidden: true });
      await expect(service.createTextSend(
        { name: 'Hidden sender', text: 'secret', hideEmail: true, deletionDays: 7 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.createFileSend(
        { name: 'Blocked file', deletionDays: 7 },
        'AA==',
        'file.bin',
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });

      const sent = (api.createSend as ReturnType<typeof vi.fn>).mock.calls[0]?.[1] as SendRequest;
      expect(sent.hideEmail).toBe(false);
      expect(sent.text?.hidden).toBe(true);
    });

    it('requires a non-blank password when Send policy mandates password protection', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.SendControls,
        data: { whoCanAccess: 1 },
      }]);
      const { service, api } = await makeService(response);
      await service.sync();

      await expect(service.createTextSend(
        { name: 'No password', deletionDays: 7 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.createTextSend(
        { name: 'Blank password', password: '   ', deletionDays: 7 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.createTextSend(
        { name: 'Protected', password: 'valid-password', deletionDays: 7 },
        'https://vault.example',
      )).resolves.toMatchObject({ type: 0 });

      expect(api.createSend).toHaveBeenCalledTimes(1);
    });

    it('fails closed when SpecificPeople Send controls cannot be represented', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.SendControls,
        data: { whoCanAccess: 2, allowedDomains: 'example.com' },
      }]);
      const { service, api } = await makeService(response);
      await service.sync();

      await expect(service.createTextSend(
        { name: 'Blocked', deletionDays: 7 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      expect(api.createSend).not.toHaveBeenCalled();
    });

    it('forces the exact creation deletionHours and rejects a later expiration', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.SendControls,
        data: { deletionHours: 72 },
      }]);
      const { service, api } = await makeService(response, { now: () => 0 });
      await service.sync();

      await service.createTextSend(
        { name: 'Bounded', deletionDays: 30 },
        'https://vault.example',
      );
      const request = (api.createSend as ReturnType<typeof vi.fn>).mock.calls[0]?.[1] as SendRequest;
      expect(request.deletionDate).toBe(new Date(72 * 3_600_000).toISOString());

      (api.createSend as ReturnType<typeof vi.fn>).mockClear();
      await expect(service.createTextSend(
        { name: 'Expiration too late', deletionDays: 7, expirationDays: 7 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      expect(api.createSend).not.toHaveBeenCalled();
    });

    it('preserves an existing deletion date and rejects an explicit edit under deletionHours', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.SendControls,
        data: { deletionHours: 24 },
      }]);
      const { service, api } = await makeService(response, { now: () => 1_000_000 });
      await service.sync();
      const existing = {
        id: 's1',
        accessId: 'a1',
        type: 0,
        name: FIELD_VECTOR.encString,
        key: await validSendKeyEncString(),
        text: { text: FIELD_VECTOR.encString },
        deletionDate: new Date(5_000_000).toISOString(),
      };
      stubApi(api).listSends = vi.fn(async () => [existing]);
      stubApi(api).updateSend = vi.fn(async (_token: string, _id: string, request: SendRequest) => ({
        ...existing,
        ...request,
      }));

      await service.updateSend('s1', { name: 'Metadata only' }, 'https://vault.example');
      const request = (stubApi(api).updateSend as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[2] as SendRequest;
      expect(request.deletionDate).toBe(existing.deletionDate);

      (stubApi(api).updateSend as unknown as ReturnType<typeof vi.fn>).mockClear();
      await expect(service.updateSend(
        's1',
        { name: 'Blocked date', deletionDays: 2 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(service.updateSend(
        's1',
        { name: 'Blocked hour date', deletionHours: 1 },
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'denied' });
      expect(stubApi(api).updateSend).not.toHaveBeenCalled();
    });

    it('refuses Email-auth, policy-forbidden hidden-email, and unknown-auth updates instead of losing controls', async () => {
      const response = withEnterprisePolicies(makeSync(), [{
        type: EnterprisePolicyType.SendControls,
        data: { disableHideEmail: true },
      }]);
      const { service, api } = await makeService(response);
      await service.sync();
      const base = {
        id: 's1', accessId: 'a1', type: 0, name: FIELD_VECTOR.encString,
        key: FIELD_VECTOR.encString, text: { text: FIELD_VECTOR.encString },
        deletionDate: new Date(0).toISOString(),
      };
      const variants = [
        { ...base, authType: 0, emails: 'person@example.com' },
        { ...base, hideEmail: true, authType: 2 },
        { ...base, authType: 99 },
      ];
      stubApi(api).updateSend = vi.fn(async () => base);

      for (const existing of variants) {
        stubApi(api).listSends = vi.fn(async () => [existing]);
        await expect(service.updateSend('s1', { name: 'Blocked' }, 'https://vault.example'))
          .rejects.toMatchObject({ code: 'denied' });
      }
      expect(stubApi(api).updateSend).not.toHaveBeenCalled();
    });

    it('compensates a file Send when policy changes after metadata commit', async () => {
      const setup = await makeServiceWithRaw();
      stubApi(setup.api).createSendFile = vi.fn(async () => {
        replacePolicyGate(setup.policyGate, withEnterprisePolicies(makeSync(), [{
          type: EnterprisePolicyType.DisableSend,
        }]), 'policy-changed-after-send-metadata');
        return {
          url: '/sends/s1/file/f1',
          sendResponse: { id: 's1', accessId: 'a1', type: 1, key: FIELD_VECTOR.encString, deletionDate: new Date(0).toISOString() },
        };
      });
      stubApi(setup.api).uploadSendFileData = vi.fn(async () => {});
      stubApi(setup.api).deleteSend = vi.fn(async () => {});

      await expect(setup.service.createFileSend(
        { name: 'Policy race', deletionDays: 7 },
        'AA==',
        'file.bin',
        'https://vault.example',
      )).rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(stubApi(setup.api).uploadSendFileData).not.toHaveBeenCalled();
      expect(stubApi(setup.api).deleteSend).toHaveBeenCalledWith('access', 's1');
    });
  });

  describe('save / update login capture', () => {
    const SITE = URL_VECTOR.plaintext;                 // https://example.com
    const USER = FIELD_VECTOR.plaintext;               // matches the cached cipher's username
    const PASS = FIELD_VECTOR.plaintext;               // matches the cached cipher's password

    async function offsiteLoginSync(): Promise<SyncResponse> {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.revisionDate = '2026-08-30T00:00:00.0000001Z';
      sync.ciphers[0]!.login!.uris = [{
        uri: await encUnder('https://old.example/login', testUserKey),
        match: UriMatchStrategy.Host,
      }];
      return sync;
    }

    it('prepares, decrypts, and saves one manual URI with OCC and checksum', async () => {
      const response = await offsiteLoginSync();
      const { service, api } = await makeService(response);
      commitCipherUpdatesToSync(api, response);
      await service.sync();
      const frameUrl = 'https://new.example/embedded-login';
      const tabUrl = 'https://new.example/account/login?step=2#form';
      const prepared = await service.prepareManualAutofill(
        'cipher-1', frameUrl, UriMatchStrategy.Domain, tabUrl,
      );
      expect(prepared).toMatchObject({
        cipherRevision: '2026-08-30T00:00:00.0000001Z',
        risk: 'no_match',
        requiresReprompt: false,
        canSave: true,
      });
      expect(prepared.uriDigest).toMatch(/^[0-9a-f]{64}$/);
      await expect(service.getManualAutofillLoginData(
        'cipher-1',
        frameUrl,
        UriMatchStrategy.Domain,
        EMPTY_LOGIN_CUSTOM_PLAN,
        prepared,
      )).resolves.toMatchObject({ login: { username: USER, password: PASS } });

      await expect(service.saveManualAutofillUri(
        'cipher-1',
        frameUrl,
        tabUrl,
        UriMatchStrategy.Domain,
        prepared,
        () => {},
      )).resolves.toBeDefined();
      const request = (api.updateCipher as Mock).mock.calls.at(-1)![2] as CipherRequest;
      expect(request.lastKnownRevisionDate).toBe(prepared.cipherRevision);
      const added = request.login!.uris!.at(-1)!;
      expect(added.match).toBeUndefined();
      await expect(decryptToText(added.uri!, testUserKey)).resolves.toBe(tabUrl);
      await expect(decryptToText(added.uriChecksum!, testUserKey))
        .resolves.toBe(await computeLoginUriChecksum(tabUrl));
    });

    it('fails manual metadata and secret access closed for a restricted organization password', async () => {
      const response = await makeOrgSync();
      response.ciphers[0]!.revisionDate = '2026-08-30T00:00:00.0000001Z';
      response.ciphers[0]!.viewPassword = false;
      response.ciphers[0]!.edit = true;
      response.ciphers[0]!.login!.uris = [{ uri: await encUnder('https://old.example', orgKey) }];
      const { service } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();
      await expect(service.prepareManualAutofill(
        'org-login', 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
    });

    it('requires a non-empty ISO revision before issuing a manual save authority', async () => {
      const response = await offsiteLoginSync();
      delete response.ciphers[0]!.revisionDate;
      const { service } = await makeService(response);
      await service.sync();
      await expect(service.prepareManualAutofill(
        'cipher-1', 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
    });

    it('accepts a 100ns revision advance that remains within the same JavaScript millisecond', async () => {
      const response = await offsiteLoginSync();
      const { service, api } = await makeService(response);
      await service.sync();
      const prepared = await service.prepareManualAutofill(
        'cipher-1', 'https://new.example/login', UriMatchStrategy.Domain,
      );
      (api.updateCipher as Mock).mockImplementationOnce(async (
        _token: string,
        id: string,
        request: CipherRequest,
      ) => {
        const { lastKnownRevisionDate: _lastKnownRevisionDate, ...fields } = request;
        const updated: CipherResponse = {
          ...response.ciphers[0]!,
          ...fields,
          id,
          revisionDate: '2026-08-30T00:00:00.0000002Z',
        };
        delete updated.data;
        response.ciphers[0] = updated;
        return updated;
      });
      await expect(service.saveManualAutofillUri(
        'cipher-1',
        'https://new.example/login',
        'https://new.example/login',
        UriMatchStrategy.Domain,
        prepared,
        () => {},
      )).resolves.toBeDefined();
    });

    it('reports an unknown save outcome when authoritative sync changes an old encrypted leaf', async () => {
      const response = await offsiteLoginSync();
      const { service, api } = await makeService(response);
      await service.sync();
      const prepared = await service.prepareManualAutofill(
        'cipher-1', 'https://new.example/login', UriMatchStrategy.Domain,
      );
      (api.updateCipher as Mock).mockImplementationOnce(async (
        _token: string,
        id: string,
        request: CipherRequest,
      ) => {
        const { lastKnownRevisionDate: _lastKnownRevisionDate, ...fields } = request;
        const updated: CipherResponse = {
          ...response.ciphers[0]!,
          ...fields,
          id,
          revisionDate: '2026-08-30T00:00:01.0000001Z',
          login: {
            ...fields.login,
            password: await encUnder('server-replaced-password', testUserKey),
          },
        };
        delete updated.data;
        response.ciphers[0] = updated;
        return updated;
      });
      await expect(service.saveManualAutofillUri(
        'cipher-1',
        'https://new.example/login',
        'https://new.example/login',
        UriMatchStrategy.Domain,
        prepared,
        () => {},
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
    });

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

    it('atomically rechecks an update after an earlier queued sync changes the username', async () => {
      const initial = makeSyncUrl();
      const { service, api } = await makeService(initial);
      await service.sync();
      const changed = structuredClone(initial);
      changed.ciphers[0]!.login!.username = await encUnder('bob@example.com', testUserKey);
      stubApi(api).sync = vi.fn(async () => changed);

      const refresh = service.sync('captured-login-race', 'force');
      const commit = service.commitCapturedLogin(
        SITE,
        { username: USER, password: 'new-password' },
        UriMatchStrategy.Domain,
        { action: 'update', cipherId: 'cipher-1', name: FIELD_VECTOR.plaintext },
      );

      await refresh;
      await expect(commit).rejects.toMatchObject({ code: 'denied' });
      expect(api.updateCipher).not.toHaveBeenCalled();
      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('atomically suppresses a duplicate create introduced by an earlier queued sync', async () => {
      const empty: SyncResponse = { profile: { id: 'u', email: 'u@example.com' }, ciphers: [] };
      const { service, api } = await makeService(empty);
      await service.sync();
      const duplicate: SyncResponse = {
        profile: empty.profile,
        ciphers: [{
          id: 'remote-login',
          type: 1,
          name: await encUnder('Remote login', testUserKey),
          favorite: false,
          organizationId: null,
          login: {
            username: await encUnder('new@example.com', testUserKey),
            password: await encUnder('new-password', testUserKey),
            uris: [{ uri: await encUnder(SITE, testUserKey) }],
          },
        }],
      };
      stubApi(api).sync = vi.fn(async () => duplicate);

      const refresh = service.sync('captured-login-race', 'force');
      const commit = service.commitCapturedLogin(
        SITE,
        { username: 'new@example.com', password: 'new-password' },
        UriMatchStrategy.Domain,
        { action: 'save', suggestedName: 'example.com' },
      );

      await refresh;
      await expect(commit).rejects.toMatchObject({ code: 'denied' });
      expect(api.createCipher).not.toHaveBeenCalled();
      expect(api.updateCipher).not.toHaveBeenCalled();
    });

    it('commits a still-current captured update through the atomic mutation method', async () => {
      const { service, api } = await makeService(makeSyncUrl());
      await service.sync();

      await expect(service.commitCapturedLogin(
        SITE,
        { username: USER, password: 'rotated-password' },
        UriMatchStrategy.Domain,
        { action: 'update', cipherId: 'cipher-1', name: FIELD_VECTOR.plaintext },
      )).resolves.toBeDefined();

      expect(api.updateCipher).toHaveBeenCalledOnce();
      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('never chooses a current-site password update by candidate order', async () => {
      const makeCandidate = async (id: string, name: string, password: string): Promise<CipherResponse> => ({
        id,
        type: 1,
        name: await encUnder(name, testUserKey),
        favorite: false,
        organizationId: null,
        login: {
          username: await encUnder('same-user@example.com', testUserKey),
          password: await encUnder(password, testUserKey),
          uris: [{ uri: await encUnder('https://example.com', testUserKey) }],
        },
      });
      const different = await makeCandidate('different', 'Different', 'old-password');
      const exact = await makeCandidate('exact', 'Exact', 'submitted-password');
      for (const ciphers of [[different, exact], [exact, different]]) {
        const { service } = await makeService({ profile: { id: 'u', email: 'u@example.com' }, ciphers });
        await service.sync();
        await expect(service.checkSaveLogin(
          'https://example.com/login',
          { username: 'same-user@example.com', password: 'submitted-password' },
          UriMatchStrategy.Domain,
        )).resolves.toEqual({ action: 'none' });
      }

      const secondDifferent = await makeCandidate('different-2', 'Different 2', 'another-old-password');
      const ambiguous = await makeService({
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [different, secondDifferent],
      });
      await ambiguous.service.sync();
      await expect(ambiguous.service.checkSaveLogin(
        'https://example.com/login',
        { username: 'same-user@example.com', password: 'submitted-password' },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });
    });

    it('checkSaveLogin returns save for a new username on the site', async () => {
      const { service } = await makeService(makeSyncUrl());
      await service.sync();
      await expect(service.checkSaveLogin(SITE, { username: 'someone-else@example.com', password: 'x' }, UriMatchStrategy.Domain))
        .resolves.toEqual({ action: 'save', suggestedName: 'example.com' });
    });

    it('checkSaveLogin offers addUri only for one exact personal credential match', async () => {
      const unique = await makeService(await offsiteLoginSync());
      await unique.service.sync();
      await expect(unique.service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: `  ${USER.toUpperCase()}  `, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'addUri', cipherId: 'cipher-1', name: FIELD_VECTOR.plaintext });

      const ambiguousSync = await offsiteLoginSync();
      ambiguousSync.ciphers.push({ ...structuredClone(ambiguousSync.ciphers[0]!), id: 'cipher-2' });
      const ambiguous = await makeService(ambiguousSync);
      await ambiguous.service.sync();
      await expect(ambiguous.service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'save', suggestedName: 'new.example' });

      await expect(unique.service.checkSaveLogin(
        'https://new.example/sign-in',
        { password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'save', suggestedName: 'new.example' });
    });

    it('allows addUri for one username when another username already matches the site', async () => {
      const bob = await offsiteLoginSync();
      bob.ciphers[0]!.login!.username = await encUnder('bob@example.com', testUserKey);
      bob.ciphers[0]!.login!.password = await encUnder('shared-password', testUserKey);
      bob.ciphers.push({
        id: 'alice',
        type: 1,
        name: await encUnder('Alice', testUserKey),
        favorite: false,
        organizationId: null,
        login: {
          username: await encUnder('alice@example.com', testUserKey),
          password: await encUnder('shared-password', testUserKey),
          uris: [{ uri: await encUnder('https://new.example', testUserKey) }],
        },
      });
      const { service, api } = await makeService(bob);
      commitCipherUpdatesToSync(api, bob);
      await service.sync();

      await expect(service.checkSaveLogin(
        'https://new.example/login',
        { username: 'bob@example.com', password: 'shared-password' },
        UriMatchStrategy.Domain,
      )).resolves.toMatchObject({ action: 'addUri', cipherId: 'cipher-1' });
      await expect(service.addLoginUri(
        'cipher-1',
        'bob@example.com',
        'shared-password',
        'https://new.example/login',
        UriMatchStrategy.Domain,
      )).resolves.toBeDefined();
    });

    it('does not override an explicit Never rule for the current origin', async () => {
      const sync = await offsiteLoginSync();
      sync.ciphers[0]!.login!.uris = [{
        uri: await encUnder('https://new.example/disabled', testUserKey),
        match: UriMatchStrategy.Never,
      }];
      const { service } = await makeService(sync);
      await service.sync();

      await expect(service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });
    });

    it('allows addUri maintenance under DataOwnership but suppresses a forbidden create prompt', async () => {
      const response = withEnterprisePolicies(await offsiteLoginSync(), [{
        type: EnterprisePolicyType.OrganizationDataOwnership,
      }]);
      const { service, api } = await makeService(response);
      commitCipherUpdatesToSync(api, response);
      await service.sync();

      await expect(service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toMatchObject({ action: 'addUri', cipherId: 'cipher-1' });
      await expect(service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: 'new-user', password: 'new-password' },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });
      await expect(service.addLoginUri(
        'cipher-1',
        USER,
        PASS,
        'https://new.example/sign-in',
        UriMatchStrategy.Domain,
      )).resolves.toBeDefined();
      expect(api.updateCipher).toHaveBeenCalledOnce();
    });

    it('never selects a restricted or organization-owned login as an addUri target', async () => {
      const restricted = withEnterprisePolicies(await offsiteLoginSync(), [{
        type: EnterprisePolicyType.RestrictedItemTypes,
        data: [1],
      }]);
      const restrictedService = await makeService(restricted);
      await restrictedService.service.sync();
      await expect(restrictedService.service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });
      await expect(restrictedService.service.addLoginUri(
        'cipher-1',
        USER,
        PASS,
        'https://new.example/sign-in',
        UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(restrictedService.api.updateCipher).not.toHaveBeenCalled();

      const orgSync = await makeOrgSync();
      orgSync.ciphers[0]!.login!.uris = [{ uri: await encUnder('https://old.example', orgKey) }];
      const organization = await makeService(orgSync, { privateKey: privateKeyBytes });
      await organization.service.sync();
      await expect(organization.service.checkSaveLogin(
        'https://new.example/sign-in',
        { username: 'alice@org.example', password: 'org-s3cret' },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'save', suggestedName: 'new.example' });
      await expect(organization.service.addLoginUri(
        'org-login',
        'alice@org.example',
        'org-s3cret',
        'https://new.example/sign-in',
        UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
    });

    it('appends one Host URI while preserving every existing encrypted field byte-for-byte', async () => {
      const perCipherKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x53));
      const wrappedCipherKey = await wrapAttachmentKey(perCipherKey, testUserKey);
      const oldUri = { uri: await encUnder('https://old.example/login', perCipherKey), match: UriMatchStrategy.Exact };
      const linkedField = { type: 3, name: await encUnder('Linked user', perCipherKey), value: null, linkedId: 100 };
      const oldPasskey = await completeFido2Credential({
        credentialId: await encUnder('credential-id', perCipherKey),
        keyValue: await encUnder('private-key', perCipherKey),
        rpId: await encUnder('old.example', perCipherKey),
        counter: await encUnder('0', perCipherKey),
      }, perCipherKey);
      const cipher: CipherResponse = {
        id: 'keyed-login',
        type: 1,
        name: await encUnder('Keyed Login', perCipherKey),
        notes: await encUnder('notes', perCipherKey),
        favorite: true,
        organizationId: null,
        folderId: 'folder-1',
        key: wrappedCipherKey,
        revisionDate: '2026-08-30T01:02:03.000Z',
        reprompt: 0,
        login: {
          username: await encUnder('alice@example.com', perCipherKey),
          password: await encUnder('exact-password', perCipherKey),
          totp: await encUnder(TOTP_SECRET_B32, perCipherKey),
          uris: [oldUri],
          fido2Credentials: [oldPasskey],
          passwordRevisionDate: '2026-01-01T00:00:00.000Z',
        },
        fields: [linkedField],
        passwordHistory: [{ password: await encUnder('old-password', perCipherKey), lastUsedDate: '2025-01-01T00:00:00.000Z' }],
        attachments: [{
          id: 'attachment-1',
          url: 'https://files.example/attachment-1',
          fileName: await encUnder('report.pdf', perCipherKey),
          key: await encUnder('wrapped-attachment-key', perCipherKey),
        }],
      };
      const sync: SyncResponse = { profile: { id: 'u', email: 'u@example.com' }, ciphers: [cipher] };
      const disposed = vi.fn();
      const { service, api } = await makeService(sync, {
        onManualAutofillFieldKeyDisposed: disposed,
      });
      commitCipherUpdatesToSync(api, sync);
      await service.sync();

      const manual = await service.prepareManualAutofill(
        cipher.id,
        'https://new.example/path',
        UriMatchStrategy.Domain,
      );
      expect(disposed).not.toHaveBeenCalled();
      await expect(service.getManualAutofillLoginData(
        cipher.id,
        'https://new.example/path',
        UriMatchStrategy.Domain,
        EMPTY_LOGIN_CUSTOM_PLAN,
        manual,
      )).resolves.toMatchObject({ login: { password: 'exact-password' } });
      expect(disposed).toHaveBeenCalledWith(true);

      await service.addLoginUri(
        cipher.id,
        'alice@example.com',
        'exact-password',
        'https://new.example/path?token=discarded#fragment',
        UriMatchStrategy.Domain,
      );

      const [, id, request] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls.at(-1)!;
      const written = request as CipherRequest;
      expect(id).toBe(cipher.id);
      expect(written).toMatchObject({
        name: cipher.name,
        notes: cipher.notes,
        favorite: true,
        folderId: 'folder-1',
        key: wrappedCipherKey,
        fields: cipher.fields,
        passwordHistory: cipher.passwordHistory,
        reprompt: 0,
        lastKnownRevisionDate: cipher.revisionDate,
      });
      expect(written.login).toMatchObject({
        username: cipher.login!.username,
        password: cipher.login!.password,
        totp: cipher.login!.totp,
        fido2Credentials: cipher.login!.fido2Credentials,
        passwordRevisionDate: cipher.login!.passwordRevisionDate,
      });
      expect(written.login!.uris?.[0]).toEqual(oldUri);
      expect(written.login!.uris?.[1]?.match).toBe(UriMatchStrategy.Host);
      await expect(decryptToText(written.login!.uris![1]!.uri!, perCipherKey))
        .resolves.toBe('https://new.example');
      await expect(decryptToText(written.login!.uris![1]!.uri!, testUserKey))
        .rejects.toThrow(EncStringMacError);
      expect('attachments' in written).toBe(false);
      expect(cipher.attachments?.[0]?.id).toBe('attachment-1');
    });

    it('rejects credential, uniqueness, duplicate-origin, Never, and cache-generation changes', async () => {
      const base = await offsiteLoginSync();
      const setup = await makeService(base);
      await setup.service.sync();

      await expect(setup.service.addLoginUri(
        'cipher-1', USER, 'wrong-password', 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      await expect(setup.service.addLoginUri(
        'cipher-1', 'wrong-user', PASS, 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.updateCipher).not.toHaveBeenCalled();

      const duplicate = await offsiteLoginSync();
      duplicate.ciphers[0]!.login!.uris = [{
        uri: await encUnder('https://new.example', testUserKey),
        match: UriMatchStrategy.Exact,
      }];
      const duplicateSetup = await makeService(duplicate);
      await duplicateSetup.service.sync();
      await expect(duplicateSetup.service.addLoginUri(
        'cipher-1', USER, PASS, 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(duplicateSetup.api.updateCipher).not.toHaveBeenCalled();

      const never = await offsiteLoginSync();
      never.ciphers[0]!.login!.uris = [{
        uri: await encUnder('https://new.example/disabled', testUserKey),
        match: UriMatchStrategy.Never,
      }];
      const neverSetup = await makeService(never);
      await neverSetup.service.sync();
      await expect(neverSetup.service.addLoginUri(
        'cipher-1', USER, PASS, 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(neverSetup.api.updateCipher).not.toHaveBeenCalled();

      const ambiguous = await offsiteLoginSync();
      ambiguous.ciphers.push({ ...structuredClone(ambiguous.ciphers[0]!), id: 'cipher-2' });
      const ambiguousSetup = await makeService(ambiguous);
      await ambiguousSetup.service.sync();
      await expect(ambiguousSetup.service.addLoginUri(
        'cipher-1', USER, PASS, 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(ambiguousSetup.api.updateCipher).not.toHaveBeenCalled();

      const changed = await offsiteLoginSync();
      changed.ciphers[0]!.login!.password = await encUnder('changed-after-check', testUserKey);
      stubApi(setup.api).sync = vi.fn(async () => changed);
      await setup.service.sync();
      await expect(setup.service.addLoginUri(
        'cipher-1', USER, PASS, 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.updateCipher).not.toHaveBeenCalled();
    });

    it('rechecks the autofill policy immediately before addUri remote I/O', async () => {
      const { service, api } = await makeService(await offsiteLoginSync());
      await service.sync();
      const policyGuard = vi.fn(() => { throw new AppError('denied', 'policy changed'); });

      await expect(service.addLoginUri(
        'cipher-1', USER, PASS, 'https://new.example/login', UriMatchStrategy.Domain, policyGuard,
      )).rejects.toMatchObject({ code: 'denied' });
      expect(policyGuard).toHaveBeenCalled();
      expect(api.updateCipher).not.toHaveBeenCalled();
    });

    it('classifies an uncertain addUri response as outcome_unknown without retrying', async () => {
      const { service, api } = await makeService(await offsiteLoginSync());
      await service.sync();
      (api.updateCipher as Mock).mockRejectedValueOnce(new Error('connection dropped'));

      await expect(service.addLoginUri(
        'cipher-1', USER, PASS, 'https://new.example/login', UriMatchStrategy.Domain,
      )).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(api.updateCipher).toHaveBeenCalledOnce();
    });

    it('fails closed for a same-site, same-username reprompt login without decrypting its password', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      const protectedPassword = sync.ciphers[0]!.login!.password!;
      const { service } = await makeService(sync);
      await service.sync();
      const spy = vi.spyOn(encstringNs, 'decryptToText');
      const priorCallCount = spy.mock.calls.length;
      try {
        await expect(service.checkSaveLogin(
          SITE,
          { username: `  ${USER.toUpperCase()}  `, password: PASS },
          UriMatchStrategy.Domain,
        )).resolves.toEqual({ action: 'none' });
        expect(spy.mock.calls.slice(priorCallCount).map((call) => call[0])).not.toContain(protectedPassword);
      } finally {
        spy.mockRestore();
      }
    });

    it('fails closed when either side of a same-site reprompt username is unknown', async () => {
      const missingStoredUsername = makeSyncUrl();
      missingStoredUsername.ciphers[0]!.reprompt = 1;
      delete missingStoredUsername.ciphers[0]!.login!.username;
      const missingStored = await makeService(missingStoredUsername);
      await missingStored.service.sync();
      await expect(missingStored.service.checkSaveLogin(
        SITE,
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });

      const missingSubmittedUsername = makeSyncUrl();
      missingSubmittedUsername.ciphers[0]!.reprompt = 1;
      const missingSubmitted = await makeService(missingSubmittedUsername);
      await missingSubmitted.service.sync();
      await expect(missingSubmitted.service.checkSaveLogin(
        SITE,
        { password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });
    });

    it('does not let a reprompt login on an unrelated origin suppress a valid save', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      sync.ciphers[0]!.login!.uris = [{ uri: await encUnder('https://other.example', testUserKey) }];
      const { service } = await makeService(sync);
      await service.sync();

      await expect(service.checkSaveLogin(
        SITE,
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'save', suggestedName: 'example.com' });
    });

    it('does not let a known different reprompt username suppress a valid save', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.reprompt = 1;
      sync.ciphers[0]!.login!.username = await encUnder('other@example.com', testUserKey);
      const { service } = await makeService(sync);
      await service.sync();

      await expect(service.checkSaveLogin(
        SITE,
        { username: USER, password: PASS },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'save', suggestedName: 'example.com' });
    });

    it('fails closed when a reprompt candidate makes an unprotected update ambiguous', async () => {
      const sync = makeSyncUrl();
      sync.ciphers[0]!.login!.password = await encUnder('old-password', testUserKey);
      const protectedCipher = structuredClone(sync.ciphers[0]!);
      protectedCipher.id = 'protected';
      protectedCipher.reprompt = 1;
      protectedCipher.login!.password = await encUnder('protected-password', testUserKey);
      sync.ciphers.push(protectedCipher);
      const { service } = await makeService(sync);
      await service.sync();

      await expect(service.checkSaveLogin(
        SITE,
        { username: USER, password: 'submitted-password' },
        UriMatchStrategy.Domain,
      )).resolves.toEqual({ action: 'none' });
    });

    it('checkSaveLogin does not decrypt secrets of ciphers that do not match the page (summary pre-filter)', async () => {
      const otherPassEnc = await encUnder('other-secret', testUserKey);
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [
          // Non-matching item is scanned FIRST: the old path fully decrypts it (revealing its password)
          // before reaching the match; the summary pre-filter skips it without touching secrets.
          { id: 'other', type: 1, favorite: false, organizationId: null,
            name: await encUnder('Other', testUserKey),
            login: { username: await encUnder('me@other.test', testUserKey), password: otherPassEnc,
              uris: [{ uri: await encUnder('https://other.test', testUserKey) }] } },
          { id: 'match', type: 1, favorite: false, organizationId: null,
            name: await encUnder('Match', testUserKey),
            login: { username: await encUnder('me@example.com', testUserKey), password: await encUnder('match-pass', testUserKey),
              uris: [{ uri: await encUnder('https://example.com', testUserKey) }] } },
        ],
      };
      const { service } = await makeService(sync);
      await service.sync();
      const spy = vi.spyOn(encstringNs, 'decryptToText');
      try {
        // Correctness is unchanged: a new username on example.com still yields 'save'.
        await expect(service.checkSaveLogin('https://example.com', { username: 'me@example.com', password: 'x' }, UriMatchStrategy.Domain))
          .resolves.toMatchObject({ action: 'update', cipherId: 'match' });
        // The non-matching item's password is never fed to decryptToText — it was filtered by summary.
        expect(spy.mock.calls.map((c) => c[0])).not.toContain(otherPassEnc);
      } finally {
        spy.mockRestore();
      }
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

    it('saveLogin rechecks the caller policy immediately before the remote create', async () => {
      const { service, api } = await makeService(makeSyncUrl());
      await service.sync();
      const policyGuard = vi.fn(() => { throw new AppError('denied', 'policy changed'); });

      await expect(service.saveLogin(
        'https://example.com/login',
        'new@example.com',
        'secret-pass',
        policyGuard,
      )).rejects.toBeTruthy();
      expect(policyGuard).toHaveBeenCalled();
      expect(api.createCipher).not.toHaveBeenCalled();
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

    it('updateLoginPassword rechecks the caller policy immediately before the remote update', async () => {
      const { service, api } = await makeService(makeSyncUrl());
      await service.sync();
      const policyGuard = vi.fn(() => { throw new AppError('denied', 'policy changed'); });

      await expect(service.updateLoginPassword(
        'cipher-1',
        'rotated-pass',
        SITE,
        UriMatchStrategy.Domain,
        policyGuard,
      )).rejects.toBeTruthy();
      expect(policyGuard).toHaveBeenCalled();
      expect(api.updateCipher).not.toHaveBeenCalled();
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
        { id: 'orgitem', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: 'org-1', login: {} },
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

  it('getCipherDetail never sends decrypted SSH key material across the worker boundary', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'ssh-1',
        type: 5,
        name: await encUnder('Deploy key', testUserKey),
        sshKey: {
          privateKey: await encUnder('PRIVATE', testUserKey),
          publicKey: await encUnder('PUBLIC', testUserKey),
          keyFingerprint: await encUnder('SHA256:fingerprint', testUserKey),
        },
      }],
    };
    const { service } = await makeService(sync);
    const listing = await service.sync();

    expect(listing.items[0]).toMatchObject({ type: 5, subtitle: 'SHA256:fingerprint' });
    const detail = await service.getCipherDetail('ssh-1');
    expect(detail).toMatchObject({ id: 'ssh-1', type: 5, name: 'Deploy key' });
    expect(detail?.sshKey).toBeUndefined();
    expect(JSON.stringify(detail)).not.toContain('PRIVATE');
    expect(JSON.stringify(detail)).not.toContain('PUBLIC');
    await expect(service.exportVault()).rejects.toMatchObject({ code: 'denied' });
  });

  describe('dedicated SSH key command boundary', () => {
    const metadata = {
      name: 'Deploy key',
      notes: 'Production access',
      favorite: true,
      reprompt: false,
      folderId: null,
      fields: [
        { type: 0 as const, name: 'environment', value: 'production' },
        { type: 1 as const, name: 'deployment token', value: 'hidden-value' },
      ],
    };
    const generatedKey = {
      privateKey: 'PRIVATE-KEY-MATERIAL',
      publicKey: 'ssh-ed25519 AAAATEST generated',
      keyFingerprint: 'SHA256:generated-fingerprint',
    } as const;

    async function makeSshSync(reprompt = false): Promise<SyncResponse> {
      return {
        profile: { id: 'u', email: 'u@example.com' },
        folders: [{ id: 'folder-1', name: await encUnder('SSH keys', testUserKey) }],
        ciphers: [{
          id: 'ssh-1',
          type: 5,
          name: await encUnder('Original key', testUserKey),
          notes: await encUnder('Original notes', testUserKey),
          favorite: false,
          folderId: 'folder-1',
          reprompt: reprompt ? 1 : 0,
          revisionDate: '2026-08-30T00:00:00.000Z',
          fields: [{
            type: 0,
            name: await encUnder('owner', testUserKey),
            value: await encUnder('infra', testUserKey),
          }],
          sshKey: {
            privateKey: await encUnder('PRIVATE-SECRET', testUserKey),
            publicKey: await encUnder('ssh-ed25519 AAAATEST original', testUserKey),
            keyFingerprint: await encUnder('SHA256:original-fingerprint', testUserKey),
          },
        }],
      };
    }

    it('reports only a boolean SSH write availability from a freshly asserted authorization', async () => {
      const missing = await makeService(makeSync());
      await missing.service.sync();
      await expect(missing.service.getSshKeyWriteAvailability()).resolves.toEqual({ available: false });

      const assertCurrent = vi.fn();
      const available = await makeService(makeSync(), {
        authorizeSshCipherType5Write: async () => ({ assertCurrent }),
      });
      await available.service.sync();
      await expect(available.service.getSshKeyWriteAvailability()).resolves.toEqual({ available: true });
      expect(assertCurrent).toHaveBeenCalledOnce();

      const stale = await makeService(makeSync(), {
        authorizeSshCipherType5Write: async () => ({
          assertCurrent() { throw new Error('stale capability'); },
        }),
      });
      await stale.service.sync();
      await expect(stale.service.getSshKeyWriteAvailability()).resolves.toEqual({ available: false });
    });

    it.each([
      [EnterprisePolicyType.OrganizationDataOwnership, undefined],
      [EnterprisePolicyType.RestrictedItemTypes, [5]],
    ])('hides SSH create availability when enterprise policy %s denies it', async (type, data) => {
      const response = withEnterprisePolicies(makeSync(), [{ type, data }]);
      const authorize = vi.fn(async () => ({ assertCurrent: vi.fn() }));
      const { service } = await makeService(response, {
        authorizeSshCipherType5Write: authorize,
      });
      await service.sync();

      await expect(service.getSshKeyWriteAvailability()).resolves.toEqual({ available: false });
      expect(authorize).not.toHaveBeenCalled();
    });

    it('keeps SSH creation available under data ownership when a writable org target exists', async () => {
      const response = await makeOrganizationCreateSync();
      response.policiesNew = [{
        id: 'odo-policy',
        organizationId: 'org-1',
        type: EnterprisePolicyType.OrganizationDataOwnership,
        enabled: true,
      }];
      const authorize = vi.fn(async () => ({ assertCurrent: vi.fn() }));
      const { service } = await makeService(response, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: authorize,
      });
      await service.sync();

      await expect(service.getSshKeyWriteAvailability()).resolves.toEqual({ available: true });
      expect(authorize).toHaveBeenCalledOnce();
    });

    it('creates a generated SSH key atomically in the selected organization collection', async () => {
      const response = await makeOrganizationCreateSync();
      response.folders = [{ id: 'folder-1', name: await encUnder('Infrastructure', testUserKey) }];
      const { service, api } = await makeService(response, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        generateSshKey: () => generatedKey,
      });
      await service.sync();

      await service.createGeneratedSshKey({ ...metadata, folderId: 'folder-1' }, {
        kind: 'organization',
        organizationId: 'org-1',
        collectionIds: ['collection-1'],
      });

      expect(api.createCipher).not.toHaveBeenCalled();
      expect(api.createOrganizationCipher).toHaveBeenCalledOnce();
      const [, request, collectionIds] = vi.mocked(api.createOrganizationCipher).mock.calls[0]!;
      expect(collectionIds).toEqual(['collection-1']);
      expect(request).toMatchObject({ type: 5, organizationId: 'org-1', folderId: 'folder-1' });
      expect(await decryptToText(request.name, orgKey)).toBe(metadata.name);
      expect(await decryptToText(request.sshKey!.privateKey, orgKey)).toBe(generatedKey.privateKey);
      expect(await decryptToText(request.sshKey!.publicKey, orgKey)).toBe(generatedKey.publicKey);
    });

    it('rejects unknown or duplicate SSH folders before personal and organization writes', async () => {
      const response = await makeOrganizationCreateSync();
      response.folders = [
        { id: 'duplicate-folder', name: await encUnder('First', testUserKey) },
        { id: 'duplicate-folder', name: await encUnder('Second', testUserKey) },
      ];
      const { service, api } = await makeService(response, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        generateSshKey: () => generatedKey,
      });
      await service.sync();

      await expect(service.createGeneratedSshKey({ ...metadata, folderId: 'missing-folder' }))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(service.createGeneratedSshKey({ ...metadata, folderId: 'duplicate-folder' }, {
        kind: 'organization', organizationId: 'org-1', collectionIds: ['collection-1'],
      })).rejects.toMatchObject({ code: 'denied' });
      expect(api.createCipher).not.toHaveBeenCalled();
      expect(api.createOrganizationCipher).not.toHaveBeenCalled();
    });

    it('returns a public-only DTO and reveals the private key only through its dedicated method', async () => {
      const { service } = await makeService(await makeSshSync());
      await service.sync();

      const details = await service.getSshKeyDetails('ssh-1');
      expect(details).toEqual({
        publicKey: 'ssh-ed25519 AAAATEST original',
        keyFingerprint: 'SHA256:original-fingerprint',
        hasPrivateKey: true,
      });
      expect(JSON.stringify(details)).not.toContain('PRIVATE-SECRET');
      await expect(service.revealSshPrivateKey('ssh-1')).resolves.toBe('PRIVATE-SECRET');
    });

    it('shares a complete SSH item by re-encrypting its key and common metadata under the org key', async () => {
      const sync = await makeSshSync();
      await addWritableShareTarget(sync, 'org-1', 'collection-1');
      const assertCurrent = vi.fn();
      const { service, api } = await makeService(sync, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: async () => ({ assertCurrent }),
      });
      await service.sync();

      await service.shareCipher('ssh-1', 'org-1', ['collection-1']);

      const body = vi.mocked(api.shareCipher).mock.calls.at(-1)?.[2];
      expect(body?.collectionIds).toEqual(['collection-1']);
      expect(body?.cipher).toMatchObject({ type: 5, organizationId: 'org-1', reprompt: 0 });
      expect(await decryptToText(body!.cipher.name, orgKey)).toBe('Original key');
      expect(await decryptToText(body!.cipher.notes!, orgKey)).toBe('Original notes');
      expect(await decryptToText(body!.cipher.sshKey!.privateKey, orgKey)).toBe('PRIVATE-SECRET');
      expect(await decryptToText(body!.cipher.sshKey!.publicKey, orgKey)).toBe('ssh-ed25519 AAAATEST original');
      expect(await decryptToText(body!.cipher.sshKey!.keyFingerprint, orgKey)).toBe('SHA256:original-fingerprint');
      expect(await decryptToText(body!.cipher.fields![0]!.name!, orgKey)).toBe('owner');
      expect(await decryptToText(body!.cipher.fields![0]!.value!, orgKey)).toBe('infra');
      expect(assertCurrent.mock.calls.length).toBeGreaterThanOrEqual(2);
    });

    it('blocks SSH sharing when capability is revoked at the final share request guard', async () => {
      const sync = await makeSshSync();
      await addWritableShareTarget(sync, 'org-1', 'collection-1');
      let current = true;
      const { service, api } = await makeService(sync, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: async () => ({
          assertCurrent() {
            if (!current) throw new Error('capability changed');
          },
        }),
        beforeRequestGuard: async (method) => {
          if (method === 'shareCipher') current = false;
        },
      });
      await service.sync();

      await expect(service.shareCipher('ssh-1', 'org-1', ['collection-1']))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.shareCipher).not.toHaveBeenCalled();
    });

    it('fails SSH sharing cleanly for reprompt-protected and sparse legacy items', async () => {
      const protectedSync = await makeSshSync(true);
      await addWritableShareTarget(protectedSync, 'org-1', 'collection-1');
      const protectedFixture = await makeService(protectedSync, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
      });
      await protectedFixture.service.sync();
      await expect(protectedFixture.service.shareCipher('ssh-1', 'org-1', ['collection-1']))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      expect(protectedFixture.api.shareCipher).not.toHaveBeenCalled();

      const sparseSync = await makeSshSync();
      await addWritableShareTarget(sparseSync, 'org-1', 'collection-1');
      sparseSync.ciphers[0]!.sshKey = { privateKey: sparseSync.ciphers[0]!.sshKey!.privateKey };
      const sparseFixture = await makeService(sparseSync, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
      });
      await sparseFixture.service.sync();
      await expect(sparseFixture.service.shareCipher('ssh-1', 'org-1', ['collection-1']))
        .rejects.toEqual(expect.objectContaining({
          code: 'denied', message: 'This item cannot be moved without losing encrypted data.',
        }));
      expect(sparseFixture.api.shareCipher).not.toHaveBeenCalled();
    });

    it('enforces restricted-item policy before SSH share capability authorization', async () => {
      const base = await makeSshSync();
      base.profile!.organizations = [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }];
      const sync = withEnterprisePolicies(base, [{
        type: EnterprisePolicyType.RestrictedItemTypes,
        data: [5],
      }]);
      const authorize = vi.fn(async () => ({ assertCurrent: vi.fn() }));
      const { service, api } = await makeService(sync, {
        privateKey: privateKeyBytes,
        authorizeSshCipherType5Write: authorize,
      });
      await service.sync();

      await expect(service.shareCipher('ssh-1', 'org-1', ['collection-1']))
        .rejects.toMatchObject({ code: 'denied' });
      expect(authorize).not.toHaveBeenCalled();
      expect(api.shareCipher).not.toHaveBeenCalled();
    });

    it('enforces master-password reprompt for public detail, private reveal, replace, and metadata update', async () => {
      const assertCurrent = vi.fn();
      const { service, api } = await makeService(await makeSshSync(true), {
        authorizeSshCipherType5Write: async () => ({ assertCurrent }),
        importSshPrivateKey: async () => generatedKey,
      });
      await service.sync();

      await expect(service.getSshKeyDetails('ssh-1')).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.revealSshPrivateKey('ssh-1', 'wrong')).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.replaceSshKey('ssh-1', 'PRIVATE')).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.updateSshKeyMetadata('ssh-1', metadata)).rejects.toMatchObject({ code: 'reprompt_required' });
      expect(api.updateCipher).not.toHaveBeenCalled();

      await expect(service.getSshKeyDetails('ssh-1', 'correct-master')).resolves.toMatchObject({ hasPrivateKey: true });
      await expect(service.revealSshPrivateKey('ssh-1', 'correct-master')).resolves.toBe('PRIVATE-SECRET');
    });

    it('rejects crafted type-5 writes through both generic create and generic update paths', async () => {
      const { service, api } = await makeService(await makeSshSync());
      await service.sync();
      const crafted = { type: 5, name: 'Bypass', sshKey: generatedKey } as never;

      await expect(service.createCipher(crafted)).rejects.toMatchObject({ code: 'denied' });
      await expect(service.updateCipher('ssh-1', crafted)).rejects.toMatchObject({ code: 'denied' });
      await expect(service.updateCipher('ssh-1', { type: 1, name: 'Downgrade' }))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.createCipher).not.toHaveBeenCalled();
      expect(api.updateCipher).not.toHaveBeenCalled();
    });

    it('creates a generated key only through a current capability authorization', async () => {
      const assertCurrent = vi.fn();
      const generate = vi.fn(() => generatedKey);
      const { service, api } = await makeService(makeSync(), {
        authorizeSshCipherType5Write: async () => ({ assertCurrent }),
        generateSshKey: generate,
      });
      await service.sync();

      await service.createGeneratedSshKey({ ...metadata, name: `  ${metadata.name}  ` });

      expect(generate).toHaveBeenCalledOnce();
      expect(assertCurrent.mock.calls.length).toBeGreaterThanOrEqual(2);
      const request = vi.mocked(api.createCipher).mock.calls.at(-1)?.[1] as CipherRequest;
      expect(request.type).toBe(5);
      expect(await decryptToText(request.name, testUserKey)).toBe(metadata.name);
      expect(await decryptToText(request.notes!, testUserKey)).toBe(metadata.notes);
      expect(await decryptToText(request.sshKey!.privateKey, testUserKey)).toBe(generatedKey.privateKey);
      expect(await decryptToText(request.sshKey!.publicKey, testUserKey)).toBe(generatedKey.publicKey);
      expect(await decryptToText(request.sshKey!.keyFingerprint, testUserKey)).toBe(generatedKey.keyFingerprint);
      expect(await decryptToText(request.fields![0]!.name!, testUserKey)).toBe('environment');
      expect(await decryptToText(request.fields![0]!.value!, testUserKey)).toBe('production');
    });

    it('fails closed when capability authorization is missing or revoked at the final request guard', async () => {
      const generate = vi.fn(() => generatedKey);
      const missing = await makeService(makeSync(), { generateSshKey: generate });
      await missing.service.sync();
      await expect(missing.service.createGeneratedSshKey(metadata)).rejects.toMatchObject({ code: 'denied' });
      expect(generate).not.toHaveBeenCalled();
      expect(missing.api.createCipher).not.toHaveBeenCalled();

      let current = true;
      const revoked = await makeService(makeSync(), {
        generateSshKey: generate,
        authorizeSshCipherType5Write: async () => ({
          assertCurrent() {
            if (!current) throw new AppError('denied', 'capability changed');
          },
        }),
        beforeRequestGuard: async (method) => {
          if (method === 'createCipher') current = false;
        },
      });
      await revoked.service.sync();
      await expect(revoked.service.createGeneratedSshKey(metadata)).rejects.toMatchObject({ code: 'denied' });
      expect(revoked.api.createCipher).not.toHaveBeenCalled();
    });

    it('updates metadata without rewriting the encrypted SSH triple or unrelated fields', async () => {
      const sync = await makeSshSync();
      const original = sync.ciphers[0]!;
      const assertCurrent = vi.fn();
      const { service, api } = await makeService(sync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent }),
      });
      await service.sync();

      await service.updateSshKeyMetadata('ssh-1', metadata);

      const request = vi.mocked(api.updateCipher).mock.calls.at(-1)?.[2] as CipherRequest;
      expect(request.sshKey).toEqual(original.sshKey);
      expect(request.lastKnownRevisionDate).toBe(original.revisionDate);
      expect(await decryptToText(request.name, testUserKey)).toBe(metadata.name);
      expect(await decryptToText(request.notes!, testUserKey)).toBe(metadata.notes);
      expect(request.favorite).toBe(true);
      expect(request.reprompt).toBe(0);
      expect(request.folderId).toBeNull();
      expect(await decryptToText(request.fields![0]!.name!, testUserKey)).toBe('environment');
      expect(await decryptToText(request.fields![0]!.value!, testUserKey)).toBe('production');
      expect(request.fields![1]).toMatchObject({ type: 1 });
      expect(await decryptToText(request.fields![1]!.name!, testUserKey)).toBe('deployment token');
      expect(await decryptToText(request.fields![1]!.value!, testUserKey)).toBe('hidden-value');
      expect(assertCurrent.mock.calls.length).toBeGreaterThanOrEqual(2);
    });

    it('allows reprompt-cleared archived SSH edits but rejects trashed SSH edits', async () => {
      const archivedDate = '2026-08-30T00:00:00.000Z';
      const archivedSync = await makeSshSync(true);
      archivedSync.ciphers[0]!.archivedDate = archivedDate;
      const archived = await makeService(archivedSync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        importSshPrivateKey: async () => generatedKey,
      });
      await archived.service.sync();

      await expect(archived.service.updateSshKeyMetadata('ssh-1', metadata))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(archived.service.updateSshKeyMetadata('ssh-1', metadata, 'correct-master'))
        .resolves.toBeDefined();
      expect(vi.mocked(archived.api.updateCipher).mock.calls[0]![2].archivedDate)
        .toBe(archivedDate);

      const deletedSync = await makeSshSync();
      deletedSync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
      const deleted = await makeService(deletedSync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        importSshPrivateKey: async () => generatedKey,
      });
      await deleted.service.sync();
      await expect(deleted.service.updateSshKeyMetadata('ssh-1', metadata))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(deleted.service.replaceSshKey('ssh-1', 'PRIVATE'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(deleted.api.updateCipher).not.toHaveBeenCalled();
    });

    it('replaces only the key triple and sanitizes unexpected codec errors', async () => {
      const sync = await makeSshSync();
      const original = sync.ciphers[0]!;
      const { service, api } = await makeService(sync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        importSshPrivateKey: async (value) => {
          expect(value).toBe('IMPORTED-PRIVATE');
          return generatedKey;
        },
      });
      await service.sync();
      await service.replaceSshKey('ssh-1', 'IMPORTED-PRIVATE');

      const request = vi.mocked(api.updateCipher).mock.calls.at(-1)?.[2] as CipherRequest;
      expect(request.name).toBe(original.name);
      expect(request.notes).toBe(original.notes);
      expect(request.favorite).toBe(original.favorite);
      expect(request.folderId).toBe(original.folderId);
      expect(request.fields).toEqual(original.fields);
      expect(await decryptToText(request.sshKey!.privateKey, testUserKey)).toBe(generatedKey.privateKey);
      expect(await decryptToText(request.sshKey!.publicKey, testUserKey)).toBe(generatedKey.publicKey);
      expect(await decryptToText(request.sshKey!.keyFingerprint, testUserKey)).toBe(generatedKey.keyFingerprint);

      const secret = 'PRIVATE-SHOULD-NOT-APPEAR';
      const failed = await makeService(sync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        importSshPrivateKey: async () => { throw new Error(secret); },
      });
      await failed.service.sync();
      const error = await failed.service.importSshKey(metadata, secret).catch((cause: unknown) => cause);
      expect(error).toMatchObject({ code: 'error' });
      expect(String((error as Error).message)).not.toContain(secret);
      expect(failed.api.createCipher).not.toHaveBeenCalled();
    });

    it('allows whole-key replacement for a sparse legacy SSH payload but fails metadata update cleanly', async () => {
      const sync = await makeSshSync();
      sync.ciphers[0]!.sshKey = { privateKey: sync.ciphers[0]!.sshKey!.privateKey };
      const { service, api } = await makeService(sync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        importSshPrivateKey: async () => generatedKey,
      });
      await service.sync();

      await expect(service.getSshKeyDetails('ssh-1')).resolves.toEqual({ hasPrivateKey: true });
      await expect(service.replaceSshKey('ssh-1', 'IMPORTED-PRIVATE')).resolves.toBeDefined();
      const replacement = vi.mocked(api.updateCipher).mock.calls.at(-1)?.[2] as CipherRequest;
      expect(await decryptToText(replacement.sshKey!.privateKey, testUserKey)).toBe(generatedKey.privateKey);
      expect(await decryptToText(replacement.sshKey!.publicKey, testUserKey)).toBe(generatedKey.publicKey);

      vi.mocked(api.updateCipher).mockClear();
      await expect(service.updateSshKeyMetadata('ssh-1', metadata)).rejects.toEqual(
        expect.objectContaining({ code: 'denied', message: 'SSH key item cannot be safely updated.' }),
      );
      expect(api.updateCipher).not.toHaveBeenCalled();
    });

    it('validates decrypted SSH text and bounds forged metadata before any write', async () => {
      const sync = await makeSshSync();
      sync.ciphers[0]!.sshKey!.publicKey = await encUnder('invalid\0public-key', testUserKey);
      const { service, api } = await makeService(sync, {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        generateSshKey: () => generatedKey,
      });
      await service.sync();
      await expect(service.getSshKeyDetails('ssh-1')).rejects.toEqual(
        expect.objectContaining({ code: 'denied', message: 'SSH key item cannot be safely read.' }),
      );

      await expect(service.createGeneratedSshKey({
        ...metadata,
        name: `  ${'x'.repeat(1_001)}  `,
      })).rejects.toEqual(
        expect.objectContaining({ code: 'error', message: 'SSH key metadata is invalid.' }),
      );
      await expect(service.createGeneratedSshKey({
        ...metadata,
        fields: [{ type: 2, name: 'enabled', value: 'maybe' }],
      })).rejects.toMatchObject({ code: 'error' });
      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('rejects Linked custom fields with a stable metadata error', async () => {
      const { service, api } = await makeService(makeSync(), {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        generateSshKey: () => generatedKey,
      });

      await expect(service.createGeneratedSshKey({
        ...metadata,
        fields: [{ type: 3, name: 'username alias', linkedId: 100 }],
      } as never)).rejects.toEqual(
        expect.objectContaining({ code: 'error', message: 'SSH key metadata is invalid.' }),
      );
      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('requires an exact native dense array for SSH custom fields', async () => {
      const { service, api } = await makeService(makeSync(), {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        generateSshKey: () => generatedKey,
      });
      const sparse = new Array<unknown>(1);
      const extraProperty: unknown[] = [];
      Object.defineProperty(extraProperty, 'extra', { value: true, enumerable: true });
      const getter = vi.fn(() => ({ type: 0, name: 'must not run' }));
      const accessor: unknown[] = [{ type: 0, name: 'placeholder' }];
      Object.defineProperty(accessor, '0', { get: getter, enumerable: true, configurable: true });
      const customPrototype: unknown[] = [];
      Object.setPrototypeOf(customPrototype, Object.create(Array.prototype));

      for (const fields of [sparse, extraProperty, accessor, customPrototype]) {
        await expect(service.createGeneratedSshKey({ ...metadata, fields } as never)).rejects.toEqual(
          expect.objectContaining({ code: 'error', message: 'SSH key metadata is invalid.' }),
        );
      }
      expect(getter).not.toHaveBeenCalled();
      expect(api.createCipher).not.toHaveBeenCalled();
    });

    it('rejects metadata objects carrying extra key material', async () => {
      const { service, api } = await makeService(makeSync(), {
        authorizeSshCipherType5Write: async () => ({ assertCurrent: vi.fn() }),
        generateSshKey: () => generatedKey,
      });
      await service.sync();
      await expect(service.createGeneratedSshKey({
        ...metadata,
        privateKey: 'must-not-be-accepted',
      } as never)).rejects.toMatchObject({ code: 'error' });
      expect(api.createCipher).not.toHaveBeenCalled();
    });
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

  it('getSkippedOrgCount requires a policy-bearing raw sync', async () => {
    const { service } = await makeService();
    await expect(service.getSkippedOrgCount()).rejects.toMatchObject({ code: 'sync_required' });
  });

  it('decrypts collections and attaches collectionIds to organization cipher summaries', async () => {
    const sync = await makeOrgSync();
    sync.collections = [{ id: 'col-1', organizationId: 'org-1', name: await encUnder('Engineering', orgKey) }];
    sync.ciphers[0]!.collectionIds = ['col-1'];
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    const result = await service.sync();
    expect(result.collections).toEqual([{
      id: 'col-1',
      organizationId: 'org-1',
      name: 'Engineering',
      canRename: false,
      canDelete: false,
      canAssignItems: false,
    }]);
    expect(result.items[0]).toMatchObject({ id: 'org-login', collectionIds: ['col-1'] });
    // Cached collections survive a listItems round-trip.
    await expect(service.listItems()).resolves.toMatchObject({ collections: [{ id: 'col-1', name: 'Engineering' }] });
  });

  it('sync keeps authoritative organization metadata and projects key availability into permissions', async () => {
    const sync = await makeOrgSync();
    // Two orgs: 'org-1' has an unwrappable key (buildOrgKeys yields a key for it); 'org-nokey' has a
    // key that fails to unwrap (garbage), so its contextual capabilities must fail closed.
    // type: 0 (Owner), status: 2 (Confirmed) => collection management also requires enabled + key.
    sync.profile!.organizations = [
      {
        id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey, name: 'Org One', type: 0, status: 2,
        enabled: true, organizationUserId: 'membership-org-1',
      },
      {
        id: 'org-nokey', key: '4.not-a-real-wrapped-key', name: 'Org No Key', type: 0, status: 2,
        enabled: true, organizationUserId: 'membership-org-nokey',
      },
    ];
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    const listing = await service.sync();
    expect(listing.orgPermissions).toEqual([{
      id: 'org-1',
      name: 'Org One',
      canManageCollections: true,
      canCreateCollections: true,
      canEditCollections: true,
      canDeleteCollections: true,
      isMember: true,
      isProviderUser: false,
      canCreateItems: true,
    }, {
      id: 'org-nokey',
      name: 'Org No Key',
      canManageCollections: false,
      canCreateCollections: false,
      canEditCollections: false,
      canDeleteCollections: false,
      isMember: true,
      isProviderUser: false,
      canCreateItems: false,
    }]);
    // listItems() reads it back from cache without a network sync.
    const cached = await service.listItems();
    expect(cached.orgPermissions).toEqual(listing.orgPermissions);
  });

  it('treats a present empty organizationsNew collection as authoritative metadata', async () => {
    const sync = await makeOrgSync();
    sync.profile.organizations![0] = {
      id: 'legacy-org',
      key: ORG_KEY_VECTOR.encOrgKey,
      name: 'Legacy metadata must not leak through',
      status: 2,
      type: 0,
      enabled: true,
    };
    sync.profile.organizationsNew = [];
    sync.ciphers = [];

    const { service } = await makeService(sync, { privateKey: privateKeyBytes });

    await expect(service.sync()).resolves.toMatchObject({ orgPermissions: [] });
  });

  it('merges direct and provider identities while keeping provider-only organizations out of create targets', async () => {
    const providerWrappedOrgKey = await encBytesUnder(
      serializeSymmetricKey(testUserKey),
      orgKey,
      0x09,
    );
    const sync: SyncResponse = {
      profile: {
        id: 'u',
        email: 'u@example.com',
        organizations: [{ id: 'shared-org', key: ORG_KEY_VECTOR.encOrgKey }],
        organizationsNew: [{
          id: 'shared-org', name: 'Shared direct', status: 2, type: 2, enabled: true,
        }],
        providers: [{ id: 'provider-1', key: ORG_KEY_VECTOR.encOrgKey }],
        providerOrganizations: [{
          id: 'shared-org',
          name: 'Provider duplicate',
          status: 2,
          type: 2,
          enabled: true,
          providerId: 'provider-1',
          key: providerWrappedOrgKey,
        }, {
          id: 'provider-only',
          name: 'Provider only',
          status: 2,
          type: 2,
          enabled: true,
          providerId: 'provider-1',
          key: providerWrappedOrgKey,
        }],
      },
      ciphers: [],
    };
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });

    const listing = await service.sync();

    expect(listing.orgPermissions).toEqual([
      expect.objectContaining({
        id: 'shared-org',
        name: 'Shared direct',
        isMember: true,
        isProviderUser: true,
        canCreateItems: true,
        canManageCollections: true,
      }),
      expect.objectContaining({
        id: 'provider-only',
        isMember: false,
        isProviderUser: true,
        canCreateItems: false,
        canManageCollections: true,
      }),
    ]);
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
      access: {
        edit: true,
        viewPassword: true,
        delete: true,
        restore: true,
        autofillTotp: true,
        viewTotp: true,
      },
    });
    expect(JSON.stringify(items)).not.toContain('org-s3cret');
    await expect(service.getSkippedOrgCount()).resolves.toBe(0);
  });

  it('projects and releases an organization clone draft only from a current manage grant', async () => {
    const sync = await makeOrgSync();
    sync.ciphers[0]!.collectionIds = ['managed'];
    sync.collections = [{
      id: 'managed', organizationId: 'org-1', name: await encUnder('Managed', orgKey),
      assigned: true, readOnly: false, manage: true,
    }];
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    const listing = await service.sync();

    expect(listing.items[0]?.access?.clone).toBe(true);
    await expect(service.getCipherInput('org-login', undefined, 'clone'))
      .resolves.toMatchObject({ type: 1, name: 'Org Login' });
  });

  it('keeps edit available but rejects organization clone drafts without manage authority', async () => {
    const sync = await makeOrgSync();
    sync.ciphers[0]!.collectionIds = ['editable'];
    sync.collections = [{
      id: 'editable', organizationId: 'org-1', name: await encUnder('Editable', orgKey),
      assigned: true, readOnly: false, manage: false,
    }];
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    const listing = await service.sync();

    expect(listing.items[0]?.access?.clone).toBe(false);
    await expect(service.getCipherInput('org-login')).resolves.toMatchObject({ name: 'Org Login' });
    await expect(service.getCipherInput('org-login', undefined, 'clone'))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('invalidates an organization clone draft when its manage snapshot changes during reprompt', async () => {
    const sync = await makeOrgSync();
    sync.ciphers[0]!.reprompt = 1;
    sync.ciphers[0]!.collectionIds = ['managed'];
    sync.collections = [{
      id: 'managed', organizationId: 'org-1', name: await encUnder('Managed', orgKey),
      assigned: true, readOnly: false, manage: true,
    }];
    const setup = await makeService(sync, { privateKey: privateKeyBytes });
    await setup.service.sync();
    vi.mocked(setup.auth.verifyMasterPassword).mockImplementation(async () => {
      sync.collections![0]!.manage = false;
      await setup.service.sync();
      return true;
    });

    await expect(setup.service.getCipherInput(
      'org-login', 'correct-master', 'clone',
    )).rejects.toMatchObject({ code: 'denied' });
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

    await expect(service.getAutofillLoginData('org-login', 'https://org.example/login', UriMatchStrategy.Domain))
      .resolves.toEqual({ username: 'alice@org.example', password: 'org-s3cret' });
  });

  it('fails closed on missing organization grants while preserving controlled login autofill', async () => {
    const sync = await makeOrgSync();
    const cipher = sync.ciphers[0]!;
    delete cipher.edit;
    delete cipher.viewPassword;
    delete cipher.organizationUseTotp;
    delete cipher.permissions;
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });

    const listing = await service.sync();
    expect(listing.items[0]).toMatchObject({
      organizationId: 'org-1',
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    await expect(service.getField('org-login', 'password')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillLoginData(
      'org-login',
      'https://org.example/login',
      UriMatchStrategy.Domain,
    )).resolves.toEqual({ username: 'alice@org.example', password: 'org-s3cret' });
  });

  it('enforces organization password-view grants at every direct secret boundary', async () => {
    const sync = await makeOrgSync();
    const cipher = sync.ciphers[0]!;
    cipher.viewPassword = false;
    cipher.fields = [{
      type: 1,
      name: await encUnder('Recovery code', orgKey),
      value: await encUnder('hidden', orgKey),
    }];
    cipher.passwordHistory = [{
      password: await encUnder('old-secret', orgKey),
      lastUsedDate: '2026-08-30T00:00:00.000Z',
    }];
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.getField('org-login', 'password')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getCustomField('org-login', 0)).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getPasswordHistory('org-login')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getCipherInput('org-login')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.updateCipher('org-login', {
      type: 1,
      name: 'Denied edit',
      login: { username: 'alice@org.example', password: 'replacement' },
    })).rejects.toMatchObject({ code: 'denied' });
    await expect(service.setCipherCollections('org-login', [])).rejects.toMatchObject({ code: 'denied' });
    await expect(service.addAttachment('org-login', 'denied.txt', '')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.deleteAttachment('org-login', 'attachment-1')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillLoginData(
      'org-login',
      'https://org.example/login',
      UriMatchStrategy.Domain,
    )).resolves.toEqual({ username: 'alice@org.example', password: 'org-s3cret' });
    expect(api.updateCipher).not.toHaveBeenCalled();
    expect(api.updateCipherCollections).not.toHaveBeenCalled();
    expect(api.uploadAttachment).not.toHaveBeenCalled();
    expect(api.deleteAttachment).not.toHaveBeenCalled();
  });

  it('protects card and identity secret getters and direct edits with viewPassword', async () => {
    const sync: SyncResponse = {
      profile: {
        id: 'u',
        email: 'u@example.com',
        organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }],
      },
      ciphers: [
        {
          id: 'org-card',
          type: 3,
          name: await encUnder('Org card', orgKey),
          organizationId: 'org-1',
          edit: true,
          viewPassword: false,
          card: {
            number: await encUnder('4111111111111111', orgKey),
            code: await encUnder('123', orgKey),
          },
        },
        {
          id: 'org-identity',
          type: 4,
          name: await encUnder('Org identity', orgKey),
          organizationId: 'org-1',
          edit: true,
          viewPassword: false,
          identity: {
            ssn: await encUnder('111-22-3333', orgKey),
            passportNumber: await encUnder('P123', orgKey),
            licenseNumber: await encUnder('L456', orgKey),
          },
        },
      ],
    };
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    const listing = await service.sync();

    expect(listing.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'org-card', access: expect.objectContaining({ edit: false }) }),
      expect.objectContaining({ id: 'org-identity', access: expect.objectContaining({ edit: false }) }),
    ]));
    for (const [id, field] of [
      ['org-card', 'card.number'],
      ['org-card', 'card.code'],
      ['org-identity', 'identity.ssn'],
      ['org-identity', 'identity.passportNumber'],
      ['org-identity', 'identity.licenseNumber'],
    ] as const) {
      await expect(service.getField(id, field)).rejects.toMatchObject({ code: 'denied' });
    }
    await expect(service.updateCipher('org-card', {
      type: 3,
      name: 'Denied card',
      card: { number: '5555555555554444' },
    })).rejects.toMatchObject({ code: 'denied' });
    await expect(service.updateCipher('org-identity', {
      type: 4,
      name: 'Denied identity',
      identity: { firstName: 'Ada' },
    })).rejects.toMatchObject({ code: 'denied' });
    expect(api.updateCipher).not.toHaveBeenCalled();
  });

  it('enforces edit, delete, and restore as independent organization mutation grants', async () => {
    const sync = await makeOrgSync();
    const cipher = sync.ciphers[0]!;
    cipher.edit = false;
    cipher.permissions = { delete: false, restore: false };
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.updateCipher('org-login', {
      type: 1,
      name: 'Denied',
      login: { username: 'alice@org.example', password: 'new-secret' },
    })).rejects.toMatchObject({ code: 'denied' });
    await expect(service.setCipherCollections('org-login', [])).rejects.toMatchObject({ code: 'denied' });
    await expect(service.addAttachment('org-login', 'denied.txt', '')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.deleteAttachment('org-login', 'attachment-1')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.softDeleteCipher('org-login')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.deleteCipher('org-login')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.restoreCipher('org-login')).rejects.toMatchObject({ code: 'denied' });

    expect(api.updateCipher).not.toHaveBeenCalled();
    expect(api.updateCipherCollections).not.toHaveBeenCalled();
    expect(api.uploadAttachment).not.toHaveBeenCalled();
    expect(api.deleteAttachment).not.toHaveBeenCalled();
    expect(api.softDeleteCipher).not.toHaveBeenCalled();
    expect(api.deleteCipher).not.toHaveBeenCalled();
    expect(api.restoreCipher).not.toHaveBeenCalled();
  });

  it('withholds organization TOTP unless organizationUseTotp is explicitly true', async () => {
    const sync = await makeOrgSync();
    const cipher = sync.ciphers[0]!;
    cipher.organizationUseTotp = false;
    cipher.login = {
      ...cipher.login,
      totp: await encUnder(TOTP_SECRET_B32, orgKey),
    };
    const { service } = await makeService(sync, {
      privateKey: privateKeyBytes,
      now: () => 1111111109_000,
    });
    const listing = await service.sync();

    expect(listing.items[0]).toMatchObject({
      hasTotp: true,
      access: { autofillTotp: false, viewTotp: false },
    });
    await expect(service.getTotpCode('org-login')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getAutofillTotpData(
      'org-login',
      'https://org.example/login',
      UriMatchStrategy.Domain,
    )).rejects.toMatchObject({ code: 'denied' });
    await expect(service.listTotpCodes()).resolves.toEqual([]);
    await expect(service.findAutofillCandidates(
      'https://org.example/login',
      UriMatchStrategy.Domain,
      'totp',
    )).resolves.toEqual([]);
  });

  it('allows controlled organization TOTP autofill without exposing codes or seeds', async () => {
    const sync = await makeOrgSync();
    const cipher = sync.ciphers[0]!;
    cipher.viewPassword = false;
    cipher.organizationUseTotp = true;
    cipher.login = {
      ...cipher.login,
      totp: await encUnder(TOTP_SECRET_B32, orgKey),
    };
    const { service } = await makeService(sync, {
      privateKey: privateKeyBytes,
      now: () => 1111111109_000,
    });
    const listing = await service.sync();

    expect(listing.items[0]).toMatchObject({
      hasTotp: true,
      access: { autofillTotp: true, viewTotp: false },
    });
    await expect(service.getField('org-login', 'totp')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getTotpCode('org-login')).rejects.toMatchObject({ code: 'denied' });
    await expect(service.listTotpCodes()).resolves.toEqual([]);
    await expect(service.findAutofillCandidates(
      'https://org.example/login',
      UriMatchStrategy.Domain,
      'totp',
    )).resolves.toMatchObject([{ id: 'org-login', hasTotp: true }]);
    await expect(service.getAutofillTotpData(
      'org-login',
      'https://org.example/login',
      UriMatchStrategy.Domain,
    )).resolves.toMatchObject({ code: '081804' });
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
    await addWritableShareTarget(sync);
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

  it('shareCipher preserves passkeys when moving a personal item', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }] },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('My Login', testUserKey),
        login: {
          password: await encUnder('p', testUserKey),
          fido2Credentials: [await completeFido2Credential({
            credentialId: FIELD_VECTOR.encString,
            keyValue: FIELD_VECTOR.encString,
            rpId: FIELD_VECTOR.encString,
            counter: FIELD_VECTOR.encString,
          }, testUserKey)],
        },
      }],
    };
    await addWritableShareTarget(sync);
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();
    await service.shareCipher('mine', 'org-1', ['col-9']);
    expect(api.shareCipher).toHaveBeenCalledOnce();
  });

  it('shareCipher only rewraps a keyed item and preserves advanced ciphertext', async () => {
    const fixture = await makeKeyedAdvancedShareSync();
    const { service, api } = await makeService(fixture.sync, { privateKey: privateKeyBytes });
    await service.sync();
    await service.shareCipher('mine', 'org-1', ['col-9']);

    const body = vi.mocked(api.shareCipher).mock.calls.at(0)?.[2];
    expect(body).toBeDefined();
    expect(body!.cipher.key).not.toBe(fixture.wrappedCipherKey);
    const movedKey = await unwrapSymmetricKey(body!.cipher.key!, orgKey);
    expect(serializeSymmetricKey(movedKey)).toEqual(serializeSymmetricKey(fixture.perCipherKey));
    expect(body!.cipher.login?.fido2Credentials).toEqual([fixture.passkey]);
    expect(body!.cipher.passwordHistory).toEqual(fixture.history);
    expect(body!.cipher.attachments2).toEqual({
      'attachment-1': {
        fileName: fixture.attachmentFileName,
        key: fixture.wrappedAttachmentKey,
      },
    });
    expect(api.downloadAttachment).not.toHaveBeenCalled();
  });

  it('shareCipher safely migrates keyless advanced data and attachment metadata', async () => {
    const attachmentKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x36));
    const oldAttachmentKey = await wrapAttachmentKey(attachmentKey, testUserKey);
    const oldFileName = await encUnder('legacy-file.txt', testUserKey);
    const oldHistory = await encUnder('legacy-password', testUserKey);
    const oldPasskeyValue = await encUnder('legacy-passkey', testUserKey);
    const passkey = await completeFido2Credential({
      credentialId: await encUnder('legacy-credential', testUserKey),
      keyValue: oldPasskeyValue,
      rpId: await encUnder('example.com', testUserKey),
      counter: await encUnder('0', testUserKey),
    }, testUserKey);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('Legacy Login', testUserKey),
        login: {
          uris: [{
            uri: await encUnder('example.com', testUserKey),
            uriChecksum: await encUnder('checksum', testUserKey),
          }],
          fido2Credentials: [passkey],
        },
        fields: [{
          type: 0,
          name: await encUnder('field-name', testUserKey),
          value: await encUnder('field-value', testUserKey),
        }],
        passwordHistory: [{ password: oldHistory, lastUsedDate: '2025-01-01T00:00:00Z' }],
        attachments: [{ id: 'attachment-1', fileName: oldFileName, key: oldAttachmentKey }],
      }],
    };
    await addWritableShareTarget(sync);
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();
    await service.shareCipher('mine', 'org-1', ['col-9']);

    const request = vi.mocked(api.shareCipher).mock.calls.at(0)?.[2].cipher;
    expect(request).toBeDefined();
    expect(request!.key).toBeUndefined();
    expect(request!.login!.fido2Credentials![0]!.keyValue).not.toBe(oldPasskeyValue);
    await expect(decryptToText(request!.login!.fido2Credentials![0]!.keyValue!, orgKey))
      .resolves.toBe('legacy-passkey');
    await expect(decryptToText(request!.passwordHistory![0]!.password!, orgKey))
      .resolves.toBe('legacy-password');
    await expect(decryptToText(request!.attachments2!['attachment-1']!.fileName, orgKey))
      .resolves.toBe('legacy-file.txt');
    expect(serializeSymmetricKey(await unwrapSymmetricKey(
      request!.attachments2!['attachment-1']!.key,
      orgKey,
    ))).toEqual(serializeSymmetricKey(attachmentKey));
    expect(api.downloadAttachment).not.toHaveBeenCalled();
  });

  it('upgrades a keyless legacy attachment before sharing the item', async () => {
    const plain = new TextEncoder().encode('legacy-share-contents');
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'mine',
        type: 1,
        favorite: false,
        organizationId: null,
        name: await encUnder('Legacy attachment login', testUserKey),
        login: { password: await encUnder('p', testUserKey) },
        attachments: [{
          id: 'legacy-old',
          key: null,
          fileName: await encUnder('legacy.txt', testUserKey),
        }],
      }],
    };
    await addWritableShareTarget(sync);
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    vi.mocked(api.downloadAttachment).mockResolvedValue(
      await encryptAttachmentFile(plain, testUserKey),
    );
    await service.sync();

    await expect(service.shareCipher('mine', 'org-1', ['col-9'])).resolves.toBeDefined();

    expect(api.downloadAttachment).toHaveBeenCalledOnce();
    expect(api.createAttachmentUploadSlot).toHaveBeenCalledOnce();
    expect(api.uploadAttachmentSlotData).toHaveBeenCalledOnce();
    expect(api.deleteAttachment).toHaveBeenCalledWith('access', 'mine', 'legacy-old');
    expect(vi.mocked(api.deleteAttachment).mock.invocationCallOrder[0])
      .toBeLessThan(vi.mocked(api.shareCipher).mock.invocationCallOrder[0]!);
    const shared = vi.mocked(api.shareCipher).mock.calls[0]![2].cipher;
    expect(shared.attachments2).toEqual({
      'new-attachment-1': expect.objectContaining({ key: expect.any(String), fileName: expect.any(String) }),
    });
    expect(shared.attachments2).not.toHaveProperty('legacy-old');
  });

  it('shareCipher rejects attachments without an independent attachment key', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }] },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('My Login', testUserKey),
        login: { password: await encUnder('p', testUserKey) },
        attachments: [{ id: 'attachment-1', fileName: '2.encrypted', key: '2.wrapped', url: 'https://vault.example/file' }],
      }],
    };
    await addWritableShareTarget(sync);
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();
    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'denied' });
    expect(api.shareCipher).not.toHaveBeenCalled();
  });

  it.each([
    'name', 'history', 'passkey', 'passkeyMetadata', 'uriChecksum', 'customField',
  ] as const)(
    'shareCipher rejects a non-EncString %s field before remote I/O',
    async (field) => {
      const passkey = await completeFido2Credential({
        credentialId: await encUnder('credential', testUserKey),
        keyValue: await encUnder('passkey-value', testUserKey),
        rpId: await encUnder('example.com', testUserKey),
        counter: await encUnder('0', testUserKey),
      }, testUserKey);
      const cipher: CipherResponse = {
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('Login', testUserKey),
        login: {
          uris: [{
            uri: await encUnder('example.com', testUserKey),
            uriChecksum: await encUnder('checksum', testUserKey),
          }],
          fido2Credentials: [passkey],
        },
        fields: [{
          type: 0,
          name: await encUnder('field-name', testUserKey),
          value: await encUnder('field-value', testUserKey),
        }],
        passwordHistory: [{
          password: await encUnder('old-password', testUserKey),
          lastUsedDate: '2025-01-01T00:00:00Z',
        }],
      };
      if (field === 'name') cipher.name = 'not-an-encstring';
      if (field === 'history') cipher.passwordHistory![0]!.password = 'not-an-encstring';
      if (field === 'passkey') cipher.login!.fido2Credentials![0]!.keyValue = 'not-an-encstring';
      if (field === 'passkeyMetadata') cipher.login!.fido2Credentials![0]!.keyType = 'not-an-encstring';
      if (field === 'uriChecksum') cipher.login!.uris![0]!.uriChecksum = 'not-an-encstring';
      if (field === 'customField') cipher.fields![0]!.value = 'not-an-encstring';
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [cipher],
      };
      await addWritableShareTarget(sync);
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.shareCipher('mine', 'org-1', ['col-9']))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.shareCipher).not.toHaveBeenCalled();
    },
  );

  it('shareCipher rejects a keyed cipher with malformed passkey metadata', async () => {
    const fixture = await makeKeyedAdvancedShareSync();
    fixture.sync.ciphers[0]!.login!.fido2Credentials![0]!.keyAlgorithm = 'not-an-encstring';
    const { service, api } = await makeService(fixture.sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'denied' });
    expect(api.shareCipher).not.toHaveBeenCalled();
  });

  it('shareCipher treats a 2xx receipt that strips history as outcome_unknown', async () => {
    const fixture = await makeKeyedAdvancedShareSync();
    const { service, api } = await makeService(fixture.sync, { privateKey: privateKeyBytes });
    await service.sync();
    vi.mocked(api.sync).mockClear();
    vi.mocked(api.shareCipher).mockImplementation(async (_token, id, body) => {
      const { attachments2: _attachments2, lastKnownRevisionDate: _revision, ...cipher } = body.cipher;
      return {
        ...fixture.sync.ciphers[0]!,
        ...cipher,
        id,
        organizationId: body.cipher.organizationId ?? null,
        passwordHistory: [],
      };
    });

    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(api.shareCipher).toHaveBeenCalledOnce();
    expect(api.sync).not.toHaveBeenCalled();
  });

  it('shareCipher keeps a network failure behind the mutation replay barrier', async () => {
    const fixture = await makeKeyedAdvancedShareSync();
    const { service, api } = await makeService(fixture.sync, { privateKey: privateKeyBytes });
    await service.sync();
    vi.mocked(api.sync).mockClear();
    vi.mocked(api.shareCipher).mockRejectedValueOnce(new Error('network disconnected'));

    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'outcome_unknown' });
    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'committed_unsynced' });
    expect(api.shareCipher).toHaveBeenCalledOnce();
    expect(api.sync).not.toHaveBeenCalled();
  });

  it('shareCipher treats an authoritative sync that strips an attachment as outcome_unknown', async () => {
    const fixture = await makeKeyedAdvancedShareSync();
    const { service, api } = await makeService(fixture.sync, { privateKey: privateKeyBytes });
    await service.sync();
    stubApi(api).sync = vi.fn(async () => {
      const response = structuredClone(fixture.sync);
      response.ciphers[0]!.attachments = [];
      return response;
    });

    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(api.shareCipher).toHaveBeenCalledOnce();
    expect(api.sync).toHaveBeenCalledOnce();
  });

  it.each([
    ['disabled organization', (sync: SyncResponse) => { sync.profile.organizations![0]!.enabled = false; }],
    ['read-only collection', (sync: SyncResponse) => { sync.collections![0]!.readOnly = true; }],
    ['unassigned collection', (sync: SyncResponse) => { sync.collections![0]!.assigned = false; }],
  ])('shareCipher rejects a %s target before remote I/O', async (_name, invalidate) => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('Login', testUserKey), login: {},
      }],
    };
    await addWritableShareTarget(sync);
    invalidate(sync);
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'denied' });
    expect(api.shareCipher).not.toHaveBeenCalled();
  });

  it('shareCipher stops before fetch when the session lease changes at the request guard', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('Login', testUserKey), login: {},
      }],
    };
    await addWritableShareTarget(sync);
    let current = true;
    const { service, api } = await makeService(sync, {
      privateKey: privateKeyBytes,
      sessionGate: {
        capture: () => ({ generation: 1 }),
        assert: () => {
          if (!current) throw new AppError('denied', 'Session changed.');
        },
      },
      beforeRequestGuard: async (method) => {
        if (method === 'shareCipher') current = false;
      },
    });
    await service.sync();

    await expect(service.shareCipher('mine', 'org-1', ['col-9']))
      .rejects.toMatchObject({ code: 'denied' });
    expect(api.shareCipher).not.toHaveBeenCalled();
  });

  it('serializes a concurrent sync behind shareCipher preparation', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com', organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }] },
      ciphers: [{
        id: 'mine', type: 1, favorite: false, organizationId: null,
        name: await encUnder('My Login', testUserKey),
        login: { password: await encUnder('p', testUserKey) },
      }],
    };
    await addWritableShareTarget(sync);
    const { service, api, session } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();
    const pause = pauseNextPrivateKeyLoad(session);

    const pending = service.shareCipher('mine', 'org-1', ['col-9']);
    await pause.started;
    const trailingSync = service.sync();
    pause.release();

    await expect(pending).resolves.toBeDefined();
    await trailingSync;
    expect(api.shareCipher).toHaveBeenCalledOnce();
  });

  describe('collection CRUD + membership', () => {
    // Seeds a synced cache with: an org cipher ('orgCipherId', org 'o1'), a personal cipher
    // ('personalCipherId'), a profile org 'o1' the fake private key can unwrap, and cached
    // collections for org 'o1' (sameOrgCollection) and a different org 'o2' (collectionFromOtherOrg).
    async function makeCollectionSync(): Promise<SyncResponse> {
      return {
        profile: {
          id: 'u',
          email: 'u@example.com',
          organizations: [{
            id: 'o1',
            key: ORG_KEY_VECTOR.encOrgKey,
            status: 2,
            type: 0,
            enabled: true,
            organizationUserId: 'membership-o1',
            allowAdminAccessToAllCollectionItems: true,
          }],
        },
        ciphers: [
          {
            id: 'orgCipherId', type: 1, favorite: false, organizationId: 'o1',
            edit: true, viewPassword: true,
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
          {
            id: 'sameOrgCollection',
            organizationId: 'o1',
            name: await encUnder('C', orgKey),
            externalId: 'directory-collection-1',
            type: 0,
            manage: true,
            assigned: true,
            readOnly: false,
          },
          {
            id: 'collectionFromOtherOrg',
            organizationId: 'o2',
            name: await encUnder('D', orgKey),
            externalId: null,
          },
        ],
      };
    }

    it('createCollection encrypts the name under the org key and re-syncs', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await service.createCollection('o1', 'Shared');
      expect(api.createCollection).toHaveBeenCalledTimes(1);
      const [, orgId, encName, access] = (api.createCollection as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(orgId).toBe('o1');
      expect(access).toEqual({
        groups: [],
        users: [{
          id: 'membership-o1',
          readOnly: false,
          hidePasswords: false,
          manage: true,
        }],
      });
      expect(encName).toMatch(/^2\./); // encType=2 EncString
      await expect(decryptToText(encName, orgKey)).resolves.toBe('Shared');
      expect(api.sync).toHaveBeenCalled(); // re-sync after write
    });

    it('serializes a concurrent sync behind collection preparation', async () => {
      const initial = await makeCollectionSync();
      const { service, api, session } = await makeService(initial, { privateKey: privateKeyBytes });
      await service.sync();
      const pause = pauseNextPrivateKeyLoad(session);
      const updated = { ...initial, profile: { ...initial.profile, organizations: [] } };
      stubApi(api).sync = vi.fn(async () => updated);

      const pending = service.createCollection('o1', 'Stale collection');
      await pause.started;
      const trailingSync = service.sync();
      pause.release();

      await expect(pending).resolves.toBeDefined();
      await trailingSync;
      expect(api.createCollection).toHaveBeenCalledOnce();
    });

    it('renameCollection uses a name-only update and never replays collection access', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await service.renameCollection('o1', 'sameOrgCollection', 'New');
      expect(api.getCollectionDetails).not.toHaveBeenCalled();
      expect(api.updateCollection).not.toHaveBeenCalled();
      const call = (api.updateCollectionName as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(call[4]).toBe('directory-collection-1');
      await expect(decryptToText(call[3], orgKey)).resolves.toBe('New');
    });

    it('renameCollection fails closed when the synced externalId is malformed', async () => {
      const response = await makeCollectionSync();
      response.collections![0]!.externalId = 42 as never;
      const { service, api } = await makeService(response, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.renameCollection('o1', 'sameOrgCollection', 'New'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.updateCollectionName).not.toHaveBeenCalled();
    });

    it('renameCollection treats a 2xx receipt that strips externalId as outcome unknown', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      (api.updateCollectionName as ReturnType<typeof vi.fn>).mockImplementation(async (
        _token: string,
        organizationId: string,
        id: string,
        encryptedName: string,
      ) => ({ id, organizationId, name: encryptedName }));

      await expect(service.renameCollection('o1', 'sameOrgCollection', 'New'))
        .rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(api.updateCollectionName).toHaveBeenCalledOnce();
      expect(api.sync).toHaveBeenCalledOnce();
    });

    it('hides and rejects collection rename when name-only updates are unavailable', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), {
        privateKey: privateKeyBytes,
        authorizeCollectionNameOnlyUpdate: async () => {
          throw new AppError('denied', 'unsupported backend');
        },
      });
      const listing = await service.sync();

      expect(listing.collections.find((entry) => entry.id === 'sameOrgCollection')?.canRename)
        .toBe(false);
      await expect(service.renameCollection('o1', 'sameOrgCollection', 'New'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.updateCollectionName).not.toHaveBeenCalled();
    });

    it('createCollection throws when the org key is unavailable', async () => {
      const { service } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await expect(service.createCollection('unknown-org', 'X'))
        .rejects.toMatchObject({ code: 'denied' });
    });

    it('deleteCollection calls the API and re-syncs', async () => {
      const { service, api } = await makeService(await makeCollectionSync(), { privateKey: privateKeyBytes });
      await service.sync();
      await service.deleteCollection('o1', 'sameOrgCollection');
      expect(api.deleteCollection).toHaveBeenCalledWith(expect.any(String), 'o1', 'sameOrgCollection');
      expect(api.sync).toHaveBeenCalled();
    });

    it('protects default collection lifecycle and former-default names', async () => {
      const defaultSync = await makeCollectionSync();
      defaultSync.collections![0]!.type = 1;
      const defaultSetup = await makeService(defaultSync, { privateKey: privateKeyBytes });
      await defaultSetup.service.sync();
      await expect(defaultSetup.service.renameCollection('o1', 'sameOrgCollection', 'Blocked'))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(defaultSetup.service.deleteCollection('o1', 'sameOrgCollection'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(defaultSetup.api.getCollectionDetails).not.toHaveBeenCalled();
      expect(defaultSetup.api.deleteCollection).not.toHaveBeenCalled();

      const formerDefaultSync = await makeCollectionSync();
      formerDefaultSync.collections![0]!.defaultUserCollectionEmail = 'former-member@example.com';
      const formerDefault = await makeService(formerDefaultSync, { privateKey: privateKeyBytes });
      await formerDefault.service.sync();
      await expect(formerDefault.service.renameCollection('o1', 'sameOrgCollection', 'Blocked'))
        .rejects.toMatchObject({ code: 'denied' });
      await expect(formerDefault.service.deleteCollection('o1', 'sameOrgCollection'))
        .resolves.toBeDefined();
      expect(formerDefault.api.getCollectionDetails).not.toHaveBeenCalled();
      expect(formerDefault.api.deleteCollection).toHaveBeenCalledOnce();
    });

    it('enforces collection creation limits at the current worker snapshot', async () => {
      const sync = await makeCollectionSync();
      Object.assign(sync.profile.organizations![0]!, {
        type: 2,
        limitCollectionCreation: true,
        permissions: { createNewCollections: false },
      });
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.createCollection('o1', 'Blocked'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.createCollection).not.toHaveBeenCalled();
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

    it('preserves an immutable read-only membership and rejects removing it', async () => {
      const sync = await makeCollectionSync();
      Object.assign(sync.profile.organizations![0]!, {
        type: 2,
        allowAdminAccessToAllCollectionItems: false,
      });
      const collection = sync.collections![0]!;
      Object.assign(collection, { manage: false, assigned: true, readOnly: true });
      sync.ciphers.find((cipher) => cipher.id === 'orgCipherId')!.collectionIds = [collection.id];
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.setCipherCollections('orgCipherId', []))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.updateCipherCollections).not.toHaveBeenCalled();
      await expect(service.setCipherCollections('orgCipherId', [collection.id]))
        .resolves.toBeDefined();
      expect(api.updateCipherCollections).toHaveBeenCalledWith(
        expect.any(String),
        'orgCipherId',
        [collection.id],
      );
    });

    it('allows an unassigned collection when collection-level manage authority is present', async () => {
      const sync = await makeCollectionSync();
      Object.assign(sync.collections![0]!, { manage: true, assigned: false, readOnly: true });
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.setCipherCollections('orgCipherId', ['sameOrgCollection']))
        .resolves.toBeDefined();
      expect(api.updateCipherCollections).toHaveBeenCalledOnce();
    });

    it('does not add a shared-only item to a default user collection', async () => {
      const sync = await makeCollectionSync();
      const shared = sync.collections![0]!;
      shared.type = 0;
      sync.collections!.push({
        id: 'defaultCollection',
        organizationId: 'o1',
        name: await encUnder('My Items', orgKey),
        type: 1,
        manage: true,
        assigned: true,
        readOnly: false,
      });
      sync.ciphers.find((cipher) => cipher.id === 'orgCipherId')!.collectionIds = [shared.id];
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.setCipherCollections('orgCipherId', [shared.id, 'defaultCollection']))
        .rejects.toMatchObject({ code: 'denied' });
      expect(api.updateCipherCollections).not.toHaveBeenCalled();
    });

    it('allows collection assignment while archived but rejects it from the trash', async () => {
      const archivedSync = await makeCollectionSync();
      archivedSync.ciphers.find((cipher) => cipher.id === 'orgCipherId')!.archivedDate =
        '2026-08-29T00:00:00.000Z';
      const archived = await makeService(archivedSync, { privateKey: privateKeyBytes });
      await archived.service.sync();
      await expect(archived.service.setCipherCollections('orgCipherId', ['sameOrgCollection']))
        .resolves.toBeDefined();
      expect(archived.api.updateCipherCollections)
        .toHaveBeenCalledWith(expect.any(String), 'orgCipherId', ['sameOrgCollection']);

      const deletedSync = await makeCollectionSync();
      deletedSync.ciphers.find((cipher) => cipher.id === 'orgCipherId')!.deletedDate =
        '2026-08-30T00:00:00.000Z';
      const deleted = await makeService(deletedSync, { privateKey: privateKeyBytes });
      await deleted.service.sync();
      await expect(deleted.service.setCipherCollections('orgCipherId', ['sameOrgCollection']))
        .rejects.toMatchObject({ code: 'denied' });
      expect(deleted.api.updateCipherCollections).not.toHaveBeenCalled();
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
    await expect(service.getField('cipher-1', 'totp')).rejects.toMatchObject({ code: 'denied' });
  });

  it('getTotpCode returns undefined for a login without a TOTP secret or a missing cipher', async () => {
    const { service } = await makeService();
    await service.sync();
    await expect(service.getTotpCode('cipher-1')).resolves.toBeUndefined();
    await expect(service.getTotpCode('nope')).resolves.toBeUndefined();
  });

  it('createFolder encrypts the name under the user key, calls the API, and re-syncs', async () => {
    const { service, api } = await makeServiceWithRaw();
    await service.createFolder('Work');
    expect(api.createFolder).toHaveBeenCalledTimes(1);
    const [token, enc] = (api.createFolder as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(token).toBe('access');
    expect((enc as string).startsWith('2.')).toBe(true);
    await expect(decryptToText(enc as string, testUserKey)).resolves.toBe('Work');
    expect(api.sync).toHaveBeenCalled();
  });

  it('keeps an initial 401 plus refresh failure definitely not committed and leaves the lane reusable', async () => {
    const executeAuthenticatedRequest: AuthService['executeAuthenticatedRequest'] = async (
      _lease,
      rebuildRequest,
    ) => {
      try {
        return await rebuildRequest('rejected-access');
      } catch (error) {
        if (error instanceof ApiHttpError && error.status === 401) {
          throw new AppError(
            'error',
            'Authentication could not be refreshed. Try the request again.',
          );
        }
        throw error;
      }
    };
    const { service, api } = await makeServiceWithRaw(makeSync(), { executeAuthenticatedRequest });
    vi.mocked(api.createFolder).mockImplementation(async (accessToken) => {
      if (accessToken === 'rejected-access') throw new ApiHttpError(401, 'expired');
      return { id: 'unexpected', name: '2.enc' };
    });

    await expect(service.createFolder('First')).rejects.toMatchObject({
      code: 'error',
      message: 'Authentication could not be refreshed. Try the request again.',
    });
    expect(api.sync).not.toHaveBeenCalled();

    vi.mocked(api.createFolder).mockResolvedValue({ id: 'new-folder', name: '2.enc' });
    await expect(service.createFolder('Second')).resolves.toBeDefined();
    expect(api.createFolder).toHaveBeenCalledTimes(2);
    expect(api.sync).toHaveBeenCalledOnce();
  });

  it('marks a network failure from the rebuilt mutation as outcome unknown', async () => {
    const executeAuthenticatedRequest: AuthService['executeAuthenticatedRequest'] = async (
      _lease,
      rebuildRequest,
    ) => {
      try {
        return await rebuildRequest('rejected-access');
      } catch (error) {
        if (error instanceof ApiHttpError && error.status === 401) {
          return rebuildRequest('refreshed-access');
        }
        throw error;
      }
    };
    const { service, api } = await makeServiceWithRaw(makeSync(), { executeAuthenticatedRequest });
    vi.mocked(api.createFolder).mockImplementation(async (accessToken) => {
      if (accessToken === 'rejected-access') throw new ApiHttpError(401, 'expired');
      throw new Error('retry transport failed');
    });

    await expect(service.createFolder('Uncertain')).rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(vi.mocked(api.createFolder).mock.calls.map(([accessToken]) => accessToken)).toEqual([
      'rejected-access',
      'refreshed-access',
    ]);
    expect(api.sync).not.toHaveBeenCalled();
  });

  it('renameFolder encrypts the new name and updates the folder by id', async () => {
    const { service, api } = await makeServiceWithRaw();
    await service.renameFolder('f1', 'Personal');
    const [token, id, enc] = (api.updateFolder as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect([token, id]).toEqual(['access', 'f1']);
    await expect(decryptToText(enc as string, testUserKey)).resolves.toBe('Personal');
  });

  it('deleteFolder calls the API by id and re-syncs', async () => {
    const { service, api } = await makeServiceWithRaw();
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
    const { service, api } = await makeServiceWithRaw();
    await service.createCipher({ type: 1, name: 'New Login', login: { password: 'p@ssw0rd' } });
    expect(api.createCipher).toHaveBeenCalledTimes(1);
    const [token, req] = (api.createCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(token).toBe('access');
    expect((req as { name: string }).name.startsWith('2.')).toBe(true);
    expect(JSON.stringify(req)).not.toContain('p@ssw0rd');
    expect(api.sync).toHaveBeenCalled();
  });

  it('creates an organization cipher atomically under the organization key', async () => {
    const sync = await makeOrganizationCreateSync();
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await service.createCipher(
      { type: 1, name: 'Organization Login', login: { password: 'org-secret' } },
      { kind: 'organization', organizationId: 'org-1', collectionIds: ['collection-1'] },
    );

    expect(api.createCipher).not.toHaveBeenCalled();
    expect(api.createOrganizationCipher).toHaveBeenCalledOnce();
    const [token, request, collectionIds] = (
      api.createOrganizationCipher as ReturnType<typeof vi.fn>
    ).mock.calls[0]!;
    expect(token).toBe('access');
    expect(collectionIds).toEqual(['collection-1']);
    expect(request).toMatchObject({ type: 1, organizationId: 'org-1' });
    await expect(decryptToText((request as CipherRequest).name, orgKey))
      .resolves.toBe('Organization Login');
    await expect(decryptToText((request as CipherRequest).login!.password!, orgKey))
      .resolves.toBe('org-secret');
    expect(JSON.stringify(request)).not.toContain('org-secret');
    expect(api.sync).toHaveBeenCalled();
  });

  it('accepts Vaultwarden collectionDetails as assigned when no explicit assigned flag exists', async () => {
    const sync = await makeOrganizationCreateSync();
    sync.collections![0] = {
      ...sync.collections![0]!,
      assigned: undefined,
      object: 'collectionDetails',
    } as never;
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.createCipher(
      { type: 2, name: 'Shared note' },
      { kind: 'organization', organizationId: 'org-1', collectionIds: ['collection-1'] },
    )).resolves.toBeDefined();
    expect(api.createOrganizationCipher).toHaveBeenCalledOnce();
  });

  it('rejects unavailable organizations and invalid collection authority before remote I/O', async () => {
    const cases: Array<{
      readonly name: string;
      readonly mutate: (sync: SyncResponse) => void;
      readonly target?: { readonly organizationId: string; readonly collectionIds: readonly string[] };
      readonly privateKey?: Uint8Array;
    }> = [{
      name: 'organizationsNew authoritative empty',
      mutate: (sync) => { sync.profile.organizationsNew = []; },
    }, {
      name: 'accepted membership',
      mutate: (sync) => { sync.profile.organizationsNew![0]!.status = 1; },
    }, {
      name: 'disabled membership',
      mutate: (sync) => { sync.profile.organizationsNew![0]!.enabled = false; },
    }, {
      name: 'provider-only metadata',
      mutate: (sync) => {
        sync.profile.organizationsNew = [];
        sync.profile.providerOrganizations = [{
          id: 'org-1', providerId: 'provider-1', status: 2, enabled: true,
        }];
      },
    }, {
      name: 'missing organization key',
      mutate: () => {},
    }, {
      name: 'read-only collection',
      mutate: () => {},
      target: { organizationId: 'org-1', collectionIds: ['collection-read-only'] },
      privateKey: privateKeyBytes,
    }, {
      name: 'unassigned collection',
      mutate: () => {},
      target: { organizationId: 'org-1', collectionIds: ['collection-unassigned'] },
      privateKey: privateKeyBytes,
    }, {
      name: 'cross-organization collection',
      mutate: () => {},
      target: { organizationId: 'org-1', collectionIds: ['collection-2'] },
      privateKey: privateKeyBytes,
    }, {
      name: 'unknown collection',
      mutate: () => {},
      target: { organizationId: 'org-1', collectionIds: ['missing'] },
      privateKey: privateKeyBytes,
    }, {
      name: 'unknown organization',
      mutate: () => {},
      target: { organizationId: 'missing-org', collectionIds: ['collection-1'] },
      privateKey: privateKeyBytes,
    }];

    for (const testCase of cases) {
      const sync = await makeOrganizationCreateSync();
      testCase.mutate(sync);
      const { service, api } = await makeService(sync, {
        ...(testCase.privateKey ? { privateKey: testCase.privateKey } : {}),
      });
      await service.sync();
      const target = testCase.target ?? {
        organizationId: 'org-1', collectionIds: ['collection-1'],
      };

      await expect(service.createCipher(
        { type: 1, name: testCase.name },
        { kind: 'organization', ...target },
      ), testCase.name).rejects.toMatchObject({ code: 'denied' });
      expect(api.createOrganizationCipher, testCase.name).not.toHaveBeenCalled();
      expect(api.createCipher, testCase.name).not.toHaveBeenCalled();
    }
  });

  it('rejects empty, duplicate, sparse, and malformed organization targets before enqueueing', async () => {
    const { service, api } = await makeServiceWithRaw(await makeOrganizationCreateSync(), {
      privateKey: privateKeyBytes,
    });
    const sparseCollectionIds = new Array<string>(1);
    const targets = [
      { kind: 'organization', organizationId: 'org-1', collectionIds: [] },
      { kind: 'organization', organizationId: 'org-1', collectionIds: ['collection-1', 'collection-1'] },
      { kind: 'organization', organizationId: 'org-1', collectionIds: sparseCollectionIds },
      { kind: 'organization', organizationId: ' org-1', collectionIds: ['collection-1'] },
      { kind: 'organization', organizationId: 'org-1', collectionIds: Object.assign(['collection-1'], { extra: true }) },
      { kind: 'personal', organizationId: 'org-1' },
    ];

    for (const target of targets) {
      await expect(service.createCipher(
        { type: 1, name: 'Invalid target' },
        target as never,
      )).rejects.toMatchObject({ code: 'denied' });
    }
    expect(api.createOrganizationCipher).not.toHaveBeenCalled();
    expect(api.createCipher).not.toHaveBeenCalled();
  });

  it('enforces restricted item policy against the selected organization target', async () => {
    const sync = await makeOrganizationCreateSync();
    sync.profile.organizationsNew![0]!.usePolicies = true;
    sync.policiesNew = [{
      id: 'restricted-login',
      organizationId: 'org-1',
      type: EnterprisePolicyType.RestrictedItemTypes,
      enabled: true,
      data: [1],
    }];
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.createCipher(
      { type: 1, name: 'Restricted' },
      { kind: 'organization', organizationId: 'org-1', collectionIds: ['collection-1'] },
    )).rejects.toMatchObject({ code: 'denied' });
    expect(api.createOrganizationCipher).not.toHaveBeenCalled();
  });

  it('keeps type-5 creation on its dedicated SSH command even with an organization target', async () => {
    const { service, api } = await makeServiceWithRaw(await makeOrganizationCreateSync(), {
      privateKey: privateKeyBytes,
    });

    await expect(service.createCipher(
      { type: 5, name: 'Crafted SSH' } as never,
      { kind: 'organization', organizationId: 'org-1', collectionIds: ['collection-1'] },
    )).rejects.toMatchObject({ code: 'denied' });
    expect(api.createOrganizationCipher).not.toHaveBeenCalled();
    expect(api.createCipher).not.toHaveBeenCalled();
  });

  it('updateCipher encrypts and PUTs by id', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.revisionDate = '2026-08-30T00:00:00.000Z';
    const { service, api } = await makeService(sync);
    await service.sync();
    await service.updateCipher('cipher-1', { type: 1, name: 'Renamed' });
    const [token, id, req] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect([token, id]).toEqual(['access', 'cipher-1']);
    expect((req as { name: string }).name.startsWith('2.')).toBe(true);
    expect((req as CipherRequest).lastKnownRevisionDate).toBe(sync.ciphers[0]!.revisionDate);
  });

  it('updates only active personal cipher folder/favorite metadata and preserves encrypted content', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login!.password = await encUnder('partial-update-secret', testUserKey);
    sync.folders = [{ id: 'folder-1', name: await encUnder('Work', testUserKey) }];
    const original = structuredClone(sync.ciphers[0]!);
    const { service, api } = await makeService(sync);
    await service.sync();
    const encryptedPassword = sync.ciphers[0]!.login!.password;
    const decryptText = vi.spyOn(encstringNs, 'decryptToText');
    decryptText.mockClear();

    try {
      const listing = await service.updateCipherLocalMetadata('cipher-1', {
        folderId: 'folder-1',
        favorite: true,
      });

      expect(api.updateCipherPartial).toHaveBeenCalledWith('access', 'cipher-1', {
        folderId: 'folder-1',
        favorite: true,
      });
      expect(api.updateCipher).not.toHaveBeenCalled();
      const request = vi.mocked(api.updateCipherPartial).mock.calls[0]![2];
      expect(Reflect.ownKeys(request)).toEqual(['folderId', 'favorite']);
      expect(listing.items[0]).toMatchObject({ id: 'cipher-1', folderId: 'folder-1', favorite: true });
      expect(sync.ciphers[0]).toMatchObject({
        name: original.name,
        login: original.login,
        folderId: 'folder-1',
        favorite: true,
      });
      expect(decryptText.mock.calls.map(([value]) => value)).not.toContain(encryptedPassword);
    } finally {
      decryptText.mockRestore();
    }
  });

  it('sets favorite while preserving the folder captured by the same vault mutation', async () => {
    const sync = makeSync();
    sync.folders = [{ id: 'folder-1', name: await encUnder('Work', testUserKey) }];
    sync.ciphers[0]!.folderId = 'folder-1';
    sync.ciphers[0]!.favorite = false;
    const { service, api } = await makeService(sync);
    await service.sync();

    const listing = await service.setCipherFavorite('cipher-1', true);

    expect(api.updateCipherPartial).toHaveBeenCalledWith('access', 'cipher-1', {
      folderId: 'folder-1',
      favorite: true,
    });
    expect(Reflect.ownKeys(vi.mocked(api.updateCipherPartial).mock.calls[0]![2]))
      .toEqual(['folderId', 'favorite']);
    expect(listing.items[0]).toMatchObject({
      id: 'cipher-1',
      folderId: 'folder-1',
      favorite: true,
    });
  });

  it('allows organization local metadata without content-edit or password-view grants', async () => {
    const sync = await makeOrgSync();
    sync.ciphers[0]!.edit = false;
    sync.ciphers[0]!.viewPassword = false;
    sync.folders = [{ id: 'folder-1', name: await encUnder('Personal folder', testUserKey) }];
    sync.ciphers[0]!.folderId = 'folder-1';
    const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    const listing = await service.setCipherFavorite('org-login', true);

    expect(api.updateCipherPartial).toHaveBeenCalledWith('access', 'org-login', {
      folderId: 'folder-1',
      favorite: true,
    });
    expect(listing.items[0]).toMatchObject({
      id: 'org-login',
      folderId: 'folder-1',
      favorite: true,
      access: expect.objectContaining({ edit: false, viewPassword: false }),
    });
  });

  it('rejects invalid, inactive, unsupported, and unknown favorite targets before remote I/O', async () => {
    const setup = await makeService(makeSync());
    await setup.service.sync();
    await expect(setup.service.setCipherFavorite('cipher-1', 'true' as never))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(setup.service.setCipherFavorite(' missing', true))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(setup.service.setCipherFavorite('missing', true))
      .rejects.toMatchObject({ code: 'denied' });
    expect(setup.api.updateCipherPartial).not.toHaveBeenCalled();

    for (const lifecycle of ['deletedDate', 'archivedDate'] as const) {
      const sync = makeSync();
      sync.ciphers[0]![lifecycle] = '2026-08-30T00:00:00.000Z';
      const inactive = await makeService(sync);
      await inactive.service.sync();
      await expect(inactive.service.setCipherFavorite('cipher-1', true))
        .rejects.toMatchObject({ code: 'denied' });
      expect(inactive.api.updateCipherPartial).not.toHaveBeenCalled();
    }

    const future = makeSync();
    future.ciphers[0]!.type = 6;
    const unsupported = await makeService(future);
    await unsupported.service.sync();
    await expect(unsupported.service.setCipherFavorite('cipher-1', true))
      .rejects.toMatchObject({ code: 'denied' });
    expect(unsupported.api.updateCipherPartial).not.toHaveBeenCalled();
  });

  it('clears an existing folder through an explicit null without touching cipher content', async () => {
    const sync = makeSync();
    sync.folders = [{ id: 'folder-1', name: await encUnder('Work', testUserKey) }];
    sync.ciphers[0]!.folderId = 'folder-1';
    const password = sync.ciphers[0]!.login!.password;
    const { service, api } = await makeService(sync);
    await service.sync();

    const listing = await service.updateCipherLocalMetadata('cipher-1', {
      folderId: null,
      favorite: false,
    });

    expect(api.updateCipherPartial).toHaveBeenCalledWith('access', 'cipher-1', {
      folderId: null,
      favorite: false,
    });
    expect(listing.items[0]).not.toHaveProperty('folderId');
    expect(sync.ciphers[0]!.login!.password).toBe(password);
  });

  it('rejects malformed local metadata and unavailable cache identities before remote I/O', async () => {
    const sync = makeSync();
    sync.folders = [{ id: 'folder-1', name: await encUnder('Work', testUserKey) }];
    const setup = await makeService(sync);
    await setup.service.sync();
    const accessor = { folderId: null } as Record<string, unknown>;
    Object.defineProperty(accessor, 'favorite', { enumerable: true, get: () => true });
    const nonEnumerable = { folderId: null } as Record<string, unknown>;
    Object.defineProperty(nonEnumerable, 'favorite', { enumerable: false, value: true });
    const symbolField = { folderId: null, favorite: true } as Record<PropertyKey, unknown>;
    symbolField[Symbol('unexpected')] = true;
    for (const input of [
      { folderId: null },
      { folderId: null, favorite: true, name: 'must-not-send' },
      { folderId: ' folder-1', favorite: true },
      { folderId: null, favorite: 1 },
      accessor,
      nonEnumerable,
      symbolField,
    ]) {
      await expect(setup.service.updateCipherLocalMetadata('cipher-1', input as never))
        .rejects.toMatchObject({ code: 'denied' });
    }
    await expect(setup.service.updateCipherLocalMetadata(' missing', {
      folderId: null,
      favorite: true,
    })).rejects.toMatchObject({ code: 'denied' });
    await expect(setup.service.updateCipherLocalMetadata('missing', {
      folderId: null,
      favorite: true,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(setup.api.updateCipherPartial).not.toHaveBeenCalled();

    const duplicateSync = makeSync();
    duplicateSync.ciphers.push({ ...duplicateSync.ciphers[0]! });
    const duplicate = await makeService(duplicateSync);
    await duplicate.service.sync();
    await expect(duplicate.service.updateCipherLocalMetadata('cipher-1', {
      folderId: null,
      favorite: true,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(duplicate.api.updateCipherPartial).not.toHaveBeenCalled();
  });

  it('requires an active cipher and one current account-owned folder', async () => {
    for (const field of ['deletedDate', 'archivedDate'] as const) {
      const sync = makeSync();
      sync.ciphers[0]![field] = '2026-08-30T00:00:00.000Z';
      const setup = await makeService(sync);
      await setup.service.sync();
      await expect(setup.service.updateCipherLocalMetadata('cipher-1', {
        folderId: null,
        favorite: true,
      })).rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.updateCipherPartial).not.toHaveBeenCalled();
    }

    for (const folders of [
      [],
      [
        { id: 'folder-1', name: '2.one' },
        { id: 'folder-1', name: '2.duplicate' },
      ],
    ]) {
      const sync = makeSync();
      sync.folders = folders;
      const setup = await makeService(sync);
      await setup.service.sync();
      await expect(setup.service.updateCipherLocalMetadata('cipher-1', {
        folderId: 'folder-1',
        favorite: true,
      })).rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.updateCipherPartial).not.toHaveBeenCalled();
    }
  });

  it('fails committed-unsynced when the authoritative sync does not prove local metadata', async () => {
    const sync = makeSync();
    sync.folders = [{ id: 'folder-1', name: await encUnder('Work', testUserKey) }];
    const { service, api } = await makeService(sync);
    await service.sync();
    vi.mocked(api.sync).mockClear();
    vi.mocked(api.updateCipherPartial).mockImplementationOnce(async () => ({
      ...sync.ciphers[0]!,
      folderId: 'folder-1',
      favorite: true,
    }));

    await expect(service.updateCipherLocalMetadata('cipher-1', {
      folderId: 'folder-1',
      favorite: true,
    })).rejects.toMatchObject({ code: 'committed_unsynced' });
    expect(api.updateCipherPartial).toHaveBeenCalledOnce();
    expect(api.sync).toHaveBeenCalledOnce();
  });

  it('rebuilds the exact partial request once after a bearer 401', async () => {
    const sync = makeSync();
    sync.folders = [{ id: 'folder-1', name: await encUnder('Work', testUserKey) }];
    const executeAuthenticatedRequest: AuthService['executeAuthenticatedRequest'] = async (
      _lease,
      rebuildRequest,
    ) => {
      try {
        return await rebuildRequest('rejected-access');
      } catch (error) {
        if (error instanceof ApiHttpError && error.status === 401) {
          return rebuildRequest('refreshed-access');
        }
        throw error;
      }
    };
    const { service, api } = await makeService(sync, { executeAuthenticatedRequest });
    await service.sync();
    const commit = vi.mocked(api.updateCipherPartial).getMockImplementation()!;
    vi.mocked(api.updateCipherPartial).mockImplementation(async (token, id, partial) => {
      if (token === 'rejected-access') throw new ApiHttpError(401, 'expired');
      return commit(token, id, partial);
    });

    await expect(service.updateCipherLocalMetadata('cipher-1', {
      folderId: 'folder-1',
      favorite: true,
    })).resolves.toMatchObject({
      items: [expect.objectContaining({ id: 'cipher-1', folderId: 'folder-1', favorite: true })],
    });
    expect(vi.mocked(api.updateCipherPartial).mock.calls.map(([token]) => token)).toEqual([
      'rejected-access',
      'refreshed-access',
    ]);
    expect(vi.mocked(api.updateCipherPartial).mock.calls.map(([, , partial]) => partial)).toEqual([
      { folderId: 'folder-1', favorite: true },
      { folderId: 'folder-1', favorite: true },
    ]);
  });

  it('updates archived items without changing their authoritative archive state', async () => {
    const archivedDate = '2026-08-30T00:00:00.000Z';
    const sync = makeSync();
    sync.ciphers[0]!.archivedDate = archivedDate;
    sync.ciphers[0]!.login!.fido2Credentials = [await completeFido2Credential({
      credentialId: await encUnder('archived-credential', testUserKey),
      keyValue: await encUnder('archived-private-key', testUserKey),
      rpId: await encUnder('example.com', testUserKey),
      counter: await encUnder('0', testUserKey),
    }, testUserKey)];
    sync.ciphers[0]!.passwordHistory = [{
      password: await encUnder('old password', testUserKey),
      lastUsedDate: '2026-01-01T00:00:00.000Z',
    }];
    const { service, api } = await makeService(sync);
    await service.sync();

    const listing = await service.updateCipher('cipher-1', {
      type: 1,
      name: 'Archived rename',
      login: { username: FIELD_VECTOR.plaintext, password: FIELD_VECTOR.plaintext },
    });

    const request = vi.mocked(api.updateCipher).mock.calls[0]![2];
    expect(request.archivedDate).toBe(archivedDate);
    expect(request.passwordHistory).toEqual(sync.ciphers[0]!.passwordHistory);
    expect(request.login?.fido2Credentials).toEqual(sync.ciphers[0]!.login!.fido2Credentials);
    expect(listing.items[0]?.archivedDate).toBe(archivedDate);
  });

  it('keeps active updates active and rejects trashed updates before remote I/O', async () => {
    const active = await makeService(makeSync());
    await active.service.sync();
    const activeListing = await active.service.updateCipher('cipher-1', {
      type: 1,
      name: 'Active rename',
      login: { password: FIELD_VECTOR.plaintext },
    });
    const activeRequest = vi.mocked(active.api.updateCipher).mock.calls[0]![2];
    expect(activeRequest.archivedDate).toBeUndefined();
    expect(activeListing.items[0]?.archivedDate).toBeUndefined();

    const deletedSync = makeSync();
    deletedSync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
    const deleted = await makeService(deletedSync);
    await deleted.service.sync();
    await expect(deleted.service.updateCipher('cipher-1', {
      type: 1,
      name: 'Forbidden rename',
    })).rejects.toMatchObject({ code: 'denied' });
    expect(deleted.api.updateCipher).not.toHaveBeenCalled();
  });

  it('maps revision conflicts without replaying the non-idempotent update', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.revisionDate = '2026-08-30T00:00:00.000Z';
    const { service, api } = await makeService(sync);
    await service.sync();
    (api.updateCipher as ReturnType<typeof vi.fn>).mockRejectedValue(
      new ApiHttpError(409, { message: 'Cipher revision conflict' }),
    );

    await expect(service.updateCipher('cipher-1', { type: 1, name: 'Stale' }))
      .rejects.toMatchObject({ code: 'conflict' });
    expect(api.updateCipher).toHaveBeenCalledOnce();
  });

  it('distinguishes an unknown write outcome from a known committed write whose sync failed', async () => {
    const unknown = await makeServiceWithRaw();
    (unknown.api.createCipher as ReturnType<typeof vi.fn>).mockRejectedValue(new TypeError('network closed'));
    await expect(unknown.service.createCipher({ type: 1, name: 'Maybe' }))
      .rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(unknown.api.createCipher).toHaveBeenCalledOnce();

    const committed = await makeServiceWithRaw();
    (committed.api.sync as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('offline'));
    await expect(committed.service.createCipher({ type: 1, name: 'Saved remotely' }))
      .rejects.toMatchObject({ code: 'committed_unsynced' });
    expect(committed.api.createCipher).toHaveBeenCalledOnce();
  });

  it('serializes a concurrent sync behind update preparation', async () => {
    const { service, api, session } = await makeService();
    await service.sync();
    const pause = pauseNextPrivateKeyLoad(session);
    stubApi(api).sync = vi.fn(async () => ({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));

    const pending = service.updateCipher('cipher-1', { type: 1, name: 'Stale update' });
    await pause.started;
    const trailingSync = service.sync();
    pause.release();

    await expect(pending).resolves.toBeDefined();
    await trailingSync;
    expect(api.updateCipher).toHaveBeenCalledOnce();
  });

  it('keeps a force sync queued while updateCipher is at its request guard', async () => {
    let markGuardWaiting!: () => void;
    const guardWaiting = new Promise<void>((resolve) => { markGuardWaiting = resolve; });
    let releaseGuard!: () => void;
    const guardGate = new Promise<void>((resolve) => { releaseGuard = resolve; });
    const { service, api } = await makeService(makeSync(), {
      beforeRequestGuard: async (method) => {
        if (method !== 'updateCipher') return;
        markGuardWaiting();
        await guardGate;
      },
    });
    await service.sync();
    stubApi(api).sync = vi.fn(async () => ({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));

    const pending = service.updateCipher('cipher-1', { type: 1, name: 'Must not reach fetch' });
    await guardWaiting;
    const trailingSync = service.sync();
    releaseGuard();

    await expect(pending).resolves.toBeDefined();
    await trailingSync;
    expect(api.updateCipher).toHaveBeenCalledOnce();
  });

  it('updateCipher preserves the passkey the editor does not model, and writes editor-controlled reprompt/fields', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.login = {
      username: FIELD_VECTOR.encString,
      password: FIELD_VECTOR.encString,
      fido2Credentials: [await completeFido2Credential({
        credentialId: FIELD_VECTOR.encString,
        keyValue: FIELD_VECTOR.encString,
        rpId: FIELD_VECTOR.encString,
        counter: FIELD_VECTOR.encString,
      }, testUserKey)],
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

    it('archives the prior Hidden-field value as name: value when it changes', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.fields = [{
        type: 1,
        name: await encUnder('Recovery answer', testUserKey),
        value: await encUnder('old secret', testUserKey),
      }];
      const { service, api } = await makeService(sync, { now: () => 1_700_000_000_000 });
      await service.sync();

      await service.updateCipher('cipher-1', {
        type: 1,
        name: 'X',
        login: { password: FIELD_VECTOR.plaintext },
        fields: [{ type: 1, name: 'Recovery answer', value: 'new secret' }],
      });

      const [, , request] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
      const history = (request as CipherRequest).passwordHistory!;
      expect(history).toHaveLength(1);
      expect(JSON.stringify(request)).not.toContain('Recovery answer: old secret');
      await expect(decryptToText(history[0]!.password!, testUserKey))
        .resolves.toBe('Recovery answer: old secret');
      expect(history[0]!.lastUsedDate).toBe(new Date(1_700_000_000_000).toISOString());
    });

    it('archives a deleted Hidden field on a non-login cipher', async () => {
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [{
          id: 'note-1',
          type: 2,
          name: await encUnder('Note', testUserKey),
          secureNote: { type: 0 },
          fields: [{
            type: 1,
            name: await encUnder('Door code', testUserKey),
            value: await encUnder('1234', testUserKey),
          }],
        }],
      };
      const { service, api } = await makeService(sync);
      await service.sync();

      await service.updateCipher('note-1', { type: 2, name: 'Note', fields: [] });

      const [, , request] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
      const history = (request as CipherRequest).passwordHistory!;
      expect(history).toHaveLength(1);
      await expect(decryptToText(history[0]!.password!, testUserKey))
        .resolves.toBe('Door code: 1234');
    });

    it('combines deleted Hidden fields with a changed login password before one five-entry truncation', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.fields = [
        { type: 1, name: await encUnder('First', testUserKey), value: await encUnder('one', testUserKey) },
        { type: 1, name: await encUnder('Second', testUserKey), value: await encUnder('two', testUserKey) },
      ];
      sync.ciphers[0]!.passwordHistory = await Promise.all(
        ['existing-1', 'existing-2', 'existing-3', 'existing-4'].map(async (password) => ({
          password: await encUnder(password, testUserKey),
          lastUsedDate: '2025-01-01T00:00:00.000Z',
        })),
      );
      const { service, api } = await makeService(sync, { now: () => 1_700_000_000_000 });
      await service.sync();

      await service.updateCipher('cipher-1', {
        type: 1,
        name: 'X',
        login: { password: 'new login password' },
        fields: [],
      });

      const [, , request] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
      const written = request as CipherRequest;
      expect(written.passwordHistory).toHaveLength(5);
      await expect(Promise.all(written.passwordHistory!.map((entry) => (
        decryptToText(entry.password!, testUserKey)
      )))).resolves.toEqual([
        'Second: two',
        'First: one',
        FIELD_VECTOR.plaintext,
        'existing-1',
        'existing-2',
      ]);
      expect(written.login?.passwordRevisionDate)
        .toBe(new Date(1_700_000_000_000).toISOString());
    });

    it('does not duplicate or archive empty and unchanged Hidden-field values', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.fields = [
        { type: 1, name: await encUnder('Duplicate', testUserKey), value: await encUnder('old', testUserKey) },
        { type: 1, name: await encUnder('Duplicate', testUserKey), value: await encUnder('old', testUserKey) },
        { type: 1, name: await encUnder('', testUserKey), value: await encUnder('ignored', testUserKey) },
        { type: 1, name: await encUnder('Empty', testUserKey), value: null },
        { type: 1, name: await encUnder('Unchanged', testUserKey), value: await encUnder('same', testUserKey) },
      ];
      const { service, api } = await makeService(sync);
      await service.sync();

      await service.updateCipher('cipher-1', {
        type: 1,
        name: 'X',
        login: { password: FIELD_VECTOR.plaintext },
        fields: [
          { type: 1, name: 'Duplicate', value: 'new' },
          { type: 1, name: 'Unchanged', value: 'same' },
        ],
      });

      const [, , request] = (api.updateCipher as ReturnType<typeof vi.fn>).mock.calls[0]!;
      const history = (request as CipherRequest).passwordHistory!;
      expect(history).toHaveLength(1);
      await expect(decryptToText(history[0]!.password!, testUserKey))
        .resolves.toBe('Duplicate: old');
    });

    it('sync surfaces the password-history count on the summary', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.passwordHistory = [
        { password: await encUnder('old1', testUserKey), lastUsedDate: '2020-01-01T00:00:00.000Z' },
        { password: await encUnder('old2', testUserKey), lastUsedDate: '2021-01-01T00:00:00.000Z' },
      ];
      const { service } = await makeService(sync);
      const { items } = await service.sync();
      expect(items[0]!.passwordHistoryCount).toBe(2);
    });

    it('getPasswordHistory decrypts entries most-recent first, reprompt-gated', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.passwordHistory = [
        { password: await encUnder('old1', testUserKey), lastUsedDate: '2020-01-01T00:00:00.000Z' },
        { password: await encUnder('old2', testUserKey), lastUsedDate: '2021-01-01T00:00:00.000Z' },
      ];
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getPasswordHistory('cipher-1')).resolves.toEqual([
        { password: 'old1', lastUsedDate: '2020-01-01T00:00:00.000Z' },
        { password: 'old2', lastUsedDate: '2021-01-01T00:00:00.000Z' },
      ]);
    });

    it('getPasswordHistory requires the master password for a reprompt item', async () => {
      const sync = makeSync();
      sync.ciphers[0]!.reprompt = 1;
      sync.ciphers[0]!.passwordHistory = [{
        password: await encUnder('old1', testUserKey),
        lastUsedDate: '2020-01-01T00:00:00.000Z',
      }];
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getPasswordHistory('cipher-1')).rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(service.getPasswordHistory('cipher-1', 'correct-master')).resolves.toEqual([{
        password: 'old1',
        lastUsedDate: '2020-01-01T00:00:00.000Z',
      }]);
    });
  });

  it('deleteCipher calls the API by id and re-syncs', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.deletedDate = '2026-08-31T00:00:00.000Z';
    const { service, api } = await makeService(sync);
    await service.sync();
    await service.deleteCipher('cipher-1');
    expect(api.deleteCipher).toHaveBeenCalledWith('access', 'cipher-1');
    expect(api.sync).toHaveBeenCalled();
  });

  it('softDeleteCipher moves the cipher to trash via the API and re-syncs', async () => {
    const { service, api } = await makeService();
    await service.sync();
    await service.softDeleteCipher('cipher-1');
    expect(api.softDeleteCipher).toHaveBeenCalledWith('access', 'cipher-1');
    expect(api.deleteCipher).not.toHaveBeenCalled();
    expect(api.sync).toHaveBeenCalled();
  });

  it('restoreCipher restores from trash via the API and re-syncs', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.deletedDate = '2026-08-31T00:00:00.000Z';
    const { service, api } = await makeService(sync);
    await service.sync();
    await service.restoreCipher('cipher-1');
    expect(api.restoreCipher).toHaveBeenCalledWith('access', 'cipher-1');
    expect(api.sync).toHaveBeenCalled();
  });

  it('soft-deletes archived items but rejects items already in the trash', async () => {
    const archivedSync = makeSync();
    archivedSync.ciphers[0]!.archivedDate = '2026-08-29T00:00:00.000Z';
    const archived = await makeService(archivedSync);
    await archived.service.sync();
    await expect(archived.service.softDeleteCipher('cipher-1')).resolves.toBeDefined();
    expect(archived.api.softDeleteCipher).toHaveBeenCalledWith('access', 'cipher-1');

    const deletedSync = makeSync();
    deletedSync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
    const deleted = await makeService(deletedSync);
    await deleted.service.sync();
    await expect(deleted.service.softDeleteCipher('cipher-1'))
      .rejects.toMatchObject({ code: 'denied' });
    expect(deleted.api.softDeleteCipher).not.toHaveBeenCalled();
  });

  it('rejects permanent deletion and restore outside the trash before remote I/O', async () => {
    const active = await makeService(makeSync());
    await active.service.sync();

    await expect(active.service.deleteCipher('cipher-1')).rejects.toMatchObject({ code: 'denied' });
    await expect(active.service.restoreCipher('cipher-1')).rejects.toMatchObject({ code: 'denied' });
    expect(active.api.deleteCipher).not.toHaveBeenCalled();
    expect(active.api.restoreCipher).not.toHaveBeenCalled();

    const archivedSync = makeSync();
    archivedSync.ciphers[0]!.archivedDate = '2026-08-31T00:00:00.000Z';
    const archived = await makeService(archivedSync);
    await archived.service.sync();
    await expect(archived.service.restoreCipher('cipher-1')).rejects.toMatchObject({ code: 'denied' });
    expect(archived.api.restoreCipher).not.toHaveBeenCalled();
  });

  describe('cipher archive lifecycle', () => {
    const currentArchiveAuthorization = () => ({ assertCurrent: vi.fn() });

    it('archives an entitled active cipher through a current capability and authoritative sync', async () => {
      const sync = makeSync();
      sync.profile.premium = true;
      const authorization = currentArchiveAuthorization();
      const { service, api } = await makeService(sync, {
        authorizeCipherArchive: () => authorization,
      });
      await service.sync();

      await service.archiveCipher('cipher-1');

      expect(authorization.assertCurrent).toHaveBeenCalled();
      expect(api.archiveCiphers).toHaveBeenCalledWith('access', ['cipher-1']);
      expect(api.sync).toHaveBeenCalled();
    });

    it('allows a read-only organization cipher to be archived as per-user metadata', async () => {
      const sync = await makeOrgSync();
      sync.profile.premiumFromOrganization = true;
      sync.ciphers[0]!.edit = false;
      sync.ciphers[0]!.viewPassword = false;
      sync.ciphers[0]!.permissions = { delete: false, restore: false };
      const { service, api } = await makeService(sync, {
        privateKey: privateKeyBytes,
        authorizeCipherArchive: currentArchiveAuthorization,
      });
      await service.sync();

      await expect(service.archiveCipher('org-login')).resolves.toBeDefined();
      expect(api.archiveCiphers).toHaveBeenCalledWith('access', ['org-login']);
    });

    it('unarchives an existing item without premium or archive capability authorization', async () => {
      const sync = makeSync();
      sync.profile.premium = false;
      sync.profile.premiumFromOrganization = false;
      sync.ciphers[0]!.archivedDate = '2026-08-31T00:00:00.000Z';
      const { service, api } = await makeService(sync);
      await service.sync();

      await service.unarchiveCipher('cipher-1');

      expect(api.unarchiveCiphers).toHaveBeenCalledWith('access', ['cipher-1']);
      expect(api.sync).toHaveBeenCalled();
    });

    it('enforces master-password reprompt for archive and unarchive', async () => {
      const archiveSync = makeSync();
      archiveSync.profile.premium = true;
      archiveSync.ciphers[0]!.reprompt = 1;
      const archive = await makeService(archiveSync, {
        authorizeCipherArchive: currentArchiveAuthorization,
      });
      await archive.service.sync();

      await expect(archive.service.archiveCipher('cipher-1'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(archive.service.archiveCipher('cipher-1', 'correct-master'))
        .resolves.toBeDefined();
      expect(archive.api.archiveCiphers).toHaveBeenCalledOnce();

      const unarchiveSync = makeSync();
      unarchiveSync.ciphers[0]!.reprompt = 1;
      unarchiveSync.ciphers[0]!.archivedDate = '2026-08-31T00:00:00.000Z';
      const unarchive = await makeService(unarchiveSync);
      await unarchive.service.sync();

      await expect(unarchive.service.unarchiveCipher('cipher-1'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(unarchive.service.unarchiveCipher('cipher-1', 'correct-master'))
        .resolves.toBeDefined();
      expect(unarchive.api.unarchiveCiphers).toHaveBeenCalledOnce();
    });

    it('rejects archive without premium or capability before remote I/O', async () => {
      const noPremiumSync = makeSync();
      noPremiumSync.profile.premium = false;
      noPremiumSync.profile.premiumFromOrganization = false;
      const authorize = vi.fn(currentArchiveAuthorization);
      const noPremium = await makeService(noPremiumSync, { authorizeCipherArchive: authorize });
      await noPremium.service.sync();
      await expect(noPremium.service.archiveCipher('cipher-1'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(authorize).not.toHaveBeenCalled();
      expect(noPremium.api.archiveCiphers).not.toHaveBeenCalled();

      const entitledSync = makeSync();
      entitledSync.profile.premium = true;
      const noCapability = await makeService(entitledSync);
      await noCapability.service.sync();
      await expect(noCapability.service.archiveCipher('cipher-1'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(noCapability.api.archiveCiphers).not.toHaveBeenCalled();
    });

    it('rejects invalid lifecycle transitions before remote I/O', async () => {
      const cases: Array<{
        readonly operation: 'archive' | 'unarchive';
        readonly deletedDate?: string;
        readonly archivedDate?: string;
        readonly reprompt?: number;
      }> = [
        { operation: 'archive', archivedDate: '2026-08-31T00:00:00.000Z' },
        { operation: 'archive', deletedDate: '2026-08-31T00:00:00.000Z' },
        { operation: 'unarchive' },
        {
          operation: 'unarchive',
          deletedDate: '2026-08-31T00:00:00.000Z',
          archivedDate: '2026-08-30T00:00:00.000Z',
        },
      ];

      for (const testCase of cases) {
        const sync = makeSync();
        sync.profile.premium = true;
        Object.assign(sync.ciphers[0]!, testCase);
        delete (sync.ciphers[0]! as unknown as Record<string, unknown>).operation;
        const setup = await makeService(sync, {
          authorizeCipherArchive: currentArchiveAuthorization,
        });
        await setup.service.sync();

        const operation = testCase.operation === 'archive'
          ? setup.service.archiveCipher('cipher-1')
          : setup.service.unarchiveCipher('cipher-1');
        await expect(operation).rejects.toMatchObject({ code: 'denied' });
        expect(setup.api.archiveCiphers).not.toHaveBeenCalled();
        expect(setup.api.unarchiveCiphers).not.toHaveBeenCalled();
      }
    });

    it('revalidates archive capability at the final request guard', async () => {
      const sync = makeSync();
      sync.profile.premium = true;
      let current = true;
      const { service, api } = await makeServiceWithRaw(sync, {
        authorizeCipherArchive: () => ({
          assertCurrent() {
            if (!current) throw new Error('capability changed');
          },
        }),
        beforeRequestGuard: async (method) => {
          if (method === 'archiveCiphers') current = false;
        },
      });

      await expect(service.archiveCipher('cipher-1')).rejects.toMatchObject({ code: 'denied' });
      expect(api.archiveCiphers).not.toHaveBeenCalled();
    });

    it('preserves outcome_unknown and committed_unsynced mutation semantics', async () => {
      const sync = makeSync();
      sync.profile.premium = true;
      const unknown = await makeServiceWithRaw(sync, {
        authorizeCipherArchive: currentArchiveAuthorization,
      });
      (unknown.api.archiveCiphers as ReturnType<typeof vi.fn>)
        .mockRejectedValue(new TypeError('network closed'));

      await expect(unknown.service.archiveCipher('cipher-1'))
        .rejects.toMatchObject({ code: 'outcome_unknown' });

      const committed = await makeServiceWithRaw(sync, {
        authorizeCipherArchive: currentArchiveAuthorization,
      });
      (committed.api.sync as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('offline'));

      await expect(committed.service.archiveCipher('cipher-1'))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(committed.api.archiveCiphers).toHaveBeenCalledOnce();
    });
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

  it('excludes trashed credentials from both local and breach health reports', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
    sync.ciphers[0]!.login!.password = await encUnder('reused-weak', testUserKey);
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getPasswordHealth()).resolves.toEqual([]);
    await expect(service.getPwnedReport()).resolves.toEqual([]);
  });

  it('projects archived items but excludes them from every active credential candidate surface', async () => {
    const archivedDate = '2026-08-30T00:00:00.000Z';
    const credential = await completeFido2Credential({
      credentialId: await encUnder('archived-credential', testUserKey),
      keyValue: await encUnder('archived-private-key', testUserKey),
      rpId: await encUnder('archived.example', testUserKey),
      counter: await encUnder('0', testUserKey),
      userName: await encUnder('archived-user', testUserKey),
    }, testUserKey);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        {
          id: 'archived-login',
          type: 1,
          name: await encUnder('Archived login', testUserKey),
          favorite: false,
          archivedDate,
          login: {
            username: await encUnder('archived-user', testUserKey),
            password: await encUnder('archived-password', testUserKey),
            totp: await encUnder(TOTP_SECRET_B32, testUserKey),
            uris: [{ uri: await encUnder('https://archived.example/', testUserKey), match: UriMatchStrategy.Domain }],
            fido2Credentials: [credential],
          },
        },
        {
          id: 'archived-card',
          type: 3,
          name: await encUnder('Archived card', testUserKey),
          favorite: false,
          archivedDate,
          card: { number: await encUnder('4111111111111111', testUserKey) },
        },
        {
          id: 'archived-identity',
          type: 4,
          name: await encUnder('Archived identity', testUserKey),
          favorite: false,
          archivedDate,
          identity: { email: await encUnder('archived@example.com', testUserKey) },
        },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();

    const listing = await service.listItems();
    expect(listing.items).toHaveLength(3);
    expect(listing.items.every((item) => item.archivedDate === archivedDate)).toBe(true);
    await expect(service.findAutofillCandidates(
      'https://archived.example/',
      UriMatchStrategy.Domain,
    )).resolves.toEqual([]);
    await expect(service.getHttpAuthLoginData(
      'https://archived.example/',
      UriMatchStrategy.Domain,
    )).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getTotpCode('archived-login')).resolves.toBeUndefined();
    await expect(service.listTotpCodes()).resolves.toEqual([]);
    await expect(service.hasMatchingPasskey({
      rpId: 'archived.example',
      origin: 'https://archived.example',
    })).resolves.toBe(false);
    await expect(service.listPasskeyCandidates({
      rpId: 'archived.example',
      origin: 'https://archived.example',
    })).resolves.toEqual([]);
    await expect(service.getPasskeyTargets({
      rpId: 'archived.example',
      origin: 'https://archived.example',
    })).resolves.toEqual([]);
    await expect(service.findFillItems('card')).resolves.toEqual([]);
    await expect(service.findFillItems('identity')).resolves.toEqual([]);
    await expect(service.getFillData('archived-card', 'card', ['number']))
      .rejects.toMatchObject({ code: 'denied' });
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

  it('allows reprompt-cleared archived editor input but rejects trashed editor input', async () => {
    const archivedSync = makeSync();
    archivedSync.ciphers[0]!.archivedDate = '2026-08-30T00:00:00.000Z';
    archivedSync.ciphers[0]!.reprompt = 1;
    const archived = await makeService(archivedSync);
    await archived.service.sync();
    await expect(archived.service.getCipherInput('cipher-1'))
      .rejects.toMatchObject({ code: 'reprompt_required' });
    await expect(archived.service.getCipherInput('cipher-1', 'correct-master'))
      .resolves.toMatchObject({ login: { password: FIELD_VECTOR.plaintext } });

    const deletedSync = makeSync();
    deletedSync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
    const deleted = await makeService(deletedSync);
    await deleted.service.sync();
    await expect(deleted.service.getCipherInput('cipher-1'))
      .rejects.toMatchObject({ code: 'denied' });
  });

  it('allows reprompt-gated detail and secret reveal for trashed items', async () => {
    const sync = makeSync();
    sync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
    sync.ciphers[0]!.reprompt = 1;
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getCipherDetail('cipher-1'))
      .rejects.toMatchObject({ code: 'reprompt_required' });
    await expect(service.getCipherDetail('cipher-1', 'correct-master'))
      .resolves.toMatchObject({ id: 'cipher-1', deletedDate: sync.ciphers[0]!.deletedDate });
    await expect(service.getField('cipher-1', 'password', 'correct-master'))
      .resolves.toBe(FIELD_VECTOR.plaintext);
  });

  it('keeps organization password-view policy on trashed detail reveals', async () => {
    const sync = await makeOrgSync();
    sync.ciphers[0]!.deletedDate = '2026-08-30T00:00:00.000Z';
    sync.ciphers[0]!.viewPassword = false;
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.getCipherDetail('org-login'))
      .resolves.toMatchObject({ id: 'org-login', deletedDate: sync.ciphers[0]!.deletedDate });
    await expect(service.getField('org-login', 'password'))
      .rejects.toMatchObject({ code: 'denied' });
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

  it('exportVault excludes organization-owned items from a personal export', async () => {
    const sync = makeSync();
    const organization = await makeOrgSync();
    sync.profile.organizations = organization.profile.organizations ?? [];
    sync.ciphers.push(...organization.ciphers);
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    const parsed = JSON.parse(await service.exportVault());

    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0]).toMatchObject({ id: 'cipher-1', organizationId: null });
    expect(JSON.stringify(parsed)).not.toContain('Org Login');
  });

  describe('unknown cipher worker boundary', () => {
    it('keeps the opaque raw payload while publishing only a metadata placeholder', async () => {
      const response = makeUnknownCipherSync();
      const { service, localStore } = await makeService(response);

      const listing = await service.sync();

      expect(listing.items).toEqual([expect.objectContaining({
        id: 'future-6',
        type: 6,
        name: '(unsupported item)',
        unsupported: true,
        undecryptable: true,
        uris: [],
        loginUris: [],
      })]);
      const raw = await localStore.get<{ response: SyncResponse }>(RAW_VAULT_CACHE_KEY);
      expect(raw?.response.ciphers[0]).toEqual(response.ciphers[0]);
      expect(raw?.response.ciphers[0]?.bankAccount).toEqual({ accountNumber: '2.opaque-account-number' });
    });

    it('rejects direct secret and detail requests before any encrypted field is materialized', async () => {
      const { service, api } = await makeService(makeUnknownCipherSync());
      await service.sync();
      const decryptText = vi.spyOn(encstringNs, 'decryptToText');
      decryptText.mockClear();

      const reads = [
        () => service.getField('future-6', 'password'),
        () => service.getCipherDetail('future-6'),
        () => service.getCipherInput('future-6'),
        () => service.getCustomField('future-6', 0),
        () => service.getPasswordHistory('future-6'),
        () => service.getTotpCode('future-6'),
        () => service.getAttachment('future-6', 'future-attachment'),
        () => service.getAutofillLoginData('future-6', 'https://example.com', UriMatchStrategy.Domain),
        () => service.getAutofillTotpData('future-6', 'https://example.com', UriMatchStrategy.Domain),
        () => service.getFillData('future-6', 'card', ['number']),
      ];
      for (const read of reads) await expect(read()).rejects.toMatchObject({ code: 'denied' });

      expect(decryptText).not.toHaveBeenCalled();
      expect(api.downloadAttachment).not.toHaveBeenCalled();
    });

    it('rejects direct mutation requests before any remote write', async () => {
      const { service, api } = await makeService(makeUnknownCipherSync());
      await service.sync();

      const mutations = [
        () => service.updateCipher('future-6', { type: 1, name: 'Replacement' }),
        () => service.shareCipher('future-6', 'org-1', ['collection-1']),
        () => service.setCipherCollections('future-6', ['collection-1']),
        () => service.deleteCipher('future-6'),
        () => service.softDeleteCipher('future-6'),
        () => service.restoreCipher('future-6'),
        () => service.addAttachment('future-6', 'new.txt', bytesToBase64(new TextEncoder().encode('secret'))),
        () => service.deleteAttachment('future-6', 'future-attachment'),
        () => service.updateLoginPassword(
          'future-6',
          'replacement-password',
          'https://example.com',
          UriMatchStrategy.Domain,
        ),
        () => service.createPasskey({
          rpId: 'example.com',
          origin: 'https://example.com',
          challenge: 'challenge',
          targetCipherId: 'future-6',
        }),
      ];
      for (const mutation of mutations) await expect(mutation()).rejects.toMatchObject({ code: 'denied' });

      for (const method of [
        api.updateCipher,
        api.shareCipher,
        api.updateCipherCollections,
        api.deleteCipher,
        api.softDeleteCipher,
        api.restoreCipher,
        api.uploadAttachment,
        api.deleteAttachment,
        api.createCipher,
      ]) expect(method).not.toHaveBeenCalled();
    });

    it('fails the entire personal export for an active unknown or undecryptable item', async () => {
      const unknown = await makeService(makeUnknownCipherSync());
      await unknown.service.sync();
      await expect(unknown.service.exportVault()).rejects.toMatchObject({ code: 'denied' });

      const corrupted = makeSync();
      corrupted.ciphers[0]!.name = '2.invalid';
      const undecryptable = await makeService(corrupted);
      await undecryptable.service.sync();
      await expect(undecryptable.service.exportVault()).rejects.toMatchObject({ code: 'denied' });
    });

    it('continues to exclude organization and trashed unknown items from a personal export', async () => {
      const sync = makeSync();
      const unknown = makeUnknownCipherSync().ciphers[0]!;
      sync.ciphers.push(
        { ...unknown, id: 'future-org', organizationId: 'org-1' },
        { ...unknown, id: 'future-trash', deletedDate: '2026-08-30T00:00:00.000Z' },
      );
      const { service } = await makeService(sync);
      await service.sync();

      const parsed = JSON.parse(await service.exportVault());
      expect(parsed.items).toHaveLength(1);
      expect(parsed.items[0]).toMatchObject({ id: 'cipher-1', type: 1 });
    });
  });

  it('importVault creates a cipher per parsed item and re-syncs once', async () => {
    const { service, api } = await makeServiceWithRaw();
    const json = JSON.stringify({ items: [{ type: 1, name: 'Imported', login: { password: 'p' } }, { type: 2, name: 'Note', notes: 'n' }] });
    await expect(service.importVault(json)).resolves.toMatchObject({ imported: 2, failed: 0 });
    expect(api.createCipher).toHaveBeenCalledTimes(2);
    expect(api.sync).toHaveBeenCalled();
  });

  it('importVault rejects malformed JSON', async () => {
    const { service } = await makeServiceWithRaw();
    await expect(service.importVault('{ not valid json')).rejects.toThrow();
  });

  it('importVault parses a CSV export (logins) and creates a cipher per row', async () => {
    const { service, api } = await makeServiceWithRaw();
    const csv = 'name,login_username,login_password,login_uri\nGitHub,octocat,s3cret,https://github.com\nGmail,me@example.com,hunter2,https://mail.google.com\n';
    await expect(service.importVault(csv)).resolves.toMatchObject({ imported: 2, failed: 0 });
    expect(api.createCipher).toHaveBeenCalledTimes(2);
  });

  it('importVault requires a password for an encrypted export', async () => {
    const { service } = await makeServiceWithRaw();
    const encrypted = JSON.stringify({ encrypted: true, passwordProtected: true, salt: 'x', kdfIterations: 600000, data: '2.a|b|c' });
    await expect(service.importVault(encrypted)).rejects.toThrow(/password-protected/);
  });

  it('importVault continues past a failing item, still syncs, and reports imported/failed counts', async () => {
    const { service, api } = await makeServiceWithRaw();
    const json = JSON.stringify({ items: [
      { type: 1, name: 'First', login: { password: 'a' } },
      { type: 1, name: 'Second', login: { password: 'b' } },
      { type: 1, name: 'Third', login: { password: 'c' } },
    ] });
    // Reject the middle item's createCipher; the first and third must still be created.
    const createCipher = api.createCipher as unknown as Mock;
    createCipher.mockReset();
    let call = 0;
    createCipher.mockImplementation(async () => {
      call += 1;
      if (call === 2) throw new ApiHttpError(400, 'server rejected item');
      return { id: 'new-cipher', type: 1, name: '2.enc' };
    });

    const result = await service.importVault(json);

    // (a) the other items were still created despite the middle failure (no early abort).
    expect(createCipher).toHaveBeenCalledTimes(3);
    // (b) the final sync still ran because at least one item imported.
    expect(api.sync).toHaveBeenCalled();
    // (c) the return value reports the correct imported/failed counts.
    expect(result.imported).toBe(2);
    expect(result.failed).toBe(1);
    expect(result.failures).toEqual([{ index: 1, message: 'server rejected item' }]);
    // (d) reaching here proves importVault did not throw a total-failure error.
  });

  it('importVault aborts the batch when a failed request also invalidates the session', async () => {
    let generation = 0;
    const sessionGate: SessionLeaseGate = {
      capture: () => ({ generation }),
      assert: (lease) => {
        if (lease.generation !== generation) throw new Error('Vault session changed');
      },
    };
    const { service, api } = await makeServiceWithRaw(makeSync(), { sessionGate });
    const createCipher = api.createCipher as unknown as Mock;
    createCipher.mockReset();
    createCipher.mockImplementation(async () => {
      generation++;
      throw new Error('request failed after account switch');
    });
    const json = JSON.stringify({ items: [
      { type: 1, name: 'First', login: { password: 'a' } },
      { type: 1, name: 'Second', login: { password: 'b' } },
    ] });

    await expect(service.importVault(json)).rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(createCipher).toHaveBeenCalledTimes(1);
  });

  it('binds an encrypted import to the session that started archive parsing', async () => {
    let generation = 0;
    let identityEpoch = 0;
    let releaseParse!: (inputs: CipherInput[]) => void;
    const parsePending = new Promise<CipherInput[]>((resolve) => { releaseParse = resolve; });
    const sessionGate: SessionLeaseGate = {
      capture: () => ({ generation }),
      assert: (lease) => {
        if (lease.generation !== generation) throw new Error('Vault session changed');
      },
    };
    const { service, api } = await makeServiceWithRaw(makeSync(), {
      sessionGate,
      getIdentityEpoch: () => identityEpoch,
      parseImport: () => parsePending,
    });

    const importing = service.importVault('{"encrypted":true}', 'archive-password');
    await vi.waitFor(() => expect(generation).toBe(0));
    generation++;
    identityEpoch++;
    releaseParse([{ type: 1, name: 'From account A', login: { password: 'secret' } }]);

    await expect(importing).rejects.toThrow(/session changed/i);
    expect(api.createCipher).not.toHaveBeenCalled();
  });

  it('importVault does not re-sync when every item fails', async () => {
    const { service, api } = await makeServiceWithRaw();
    const json = JSON.stringify({ items: [
      { type: 1, name: 'First', login: { password: 'a' } },
      { type: 1, name: 'Second', login: { password: 'b' } },
    ] });
    const createCipher = api.createCipher as unknown as Mock;
    createCipher.mockReset();
    createCipher.mockRejectedValue(new ApiHttpError(400, 'server rejected item'));

    const result = await service.importVault(json);

    expect(createCipher).toHaveBeenCalledTimes(2);
    expect(api.sync).not.toHaveBeenCalled();
    expect(result).toMatchObject({ imported: 0, failed: 2 });
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
        login: { fido2Credentials: [await completeFido2Credential({
          credentialId: await encUnder('cred-1', testUserKey),
          keyValue: await encUnder(keyValueB64url, testUserKey),
          rpId: await encUnder('acme.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }, testUserKey)] },
      }],
    };
    const { service, api } = await makeService(sync);
    await service.sync();
    (api.sync as ReturnType<typeof vi.fn>).mockClear();
    expect((await service.listItems()).items[0]).toMatchObject({ id: 'pk', hasPasskey: true });

    const challenge = bytesToBase64Url(new TextEncoder().encode('chal'));
    const assertion = await service.getPasskeyAssertion({ rpId: 'acme.com', origin: 'https://acme.com', challenge });
    expect(assertion?.credentialId).toBe('cred-1');
    expect(JSON.stringify(assertion)).not.toContain(keyValueB64url);

    // The returned signature verifies against the credential's public key.
    const authData = base64UrlToBytes(assertion!.authenticatorData);
    expect([...authData.slice(33, 37)]).toEqual([0, 0, 0, 0]);
    expect(api.updateCipher).not.toHaveBeenCalled();
    expect(api.sync).not.toHaveBeenCalled();
    const clientHash = new Uint8Array(await subtle.digest('SHA-256', base64UrlToBytes(assertion!.clientDataJSON) as BufferSource));
    const signedData = new Uint8Array([...authData, ...clientHash]);
    const rawSig = derToRawSignature(base64UrlToBytes(assertion!.signature));
    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, rawSig as BufferSource, signedData as BufferSource);
    expect(ok).toBe(true);
    const crossOriginAssertion = await service.getPasskeyAssertion({
      rpId: 'acme.com', origin: 'https://acme.com', challenge, crossOrigin: true,
    });
    expect(JSON.parse(new TextDecoder().decode(base64UrlToBytes(crossOriginAssertion!.clientDataJSON))))
      .toMatchObject({ crossOrigin: true });
  });

  describe('stateful passkey signature counters', () => {
    const revisionDate = '2026-08-30T12:34:56.000Z';
    const nextRevisionDate = '2026-08-30T12:35:00.000Z';
    const challenge = bytesToBase64Url(new TextEncoder().encode('counter-challenge'));
    const request = {
      rpId: 'acme.com',
      origin: 'https://acme.com',
      challenge,
      allowedCredentialIds: ['cred-1'],
    } as const;
    type CounterSetup = Awaited<ReturnType<typeof makeServiceWithPasskey>>;

    const assertionCounter = (assertion: NonNullable<Awaited<ReturnType<VaultService['getPasskeyAssertion']>>>): number => {
      const data = base64UrlToBytes(assertion.authenticatorData);
      return new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0);
    };

    const ecdsaSignCount = (spy: unknown): number => (
      (spy as Mock).mock.calls.filter(([algorithm]) => (
        typeof algorithm === 'object'
        && algorithm !== null
        && (algorithm as { name?: unknown }).name === 'ECDSA'
      )).length
    );

    const resetCounterMocks = (setup: CounterSetup): void => {
      (setup.api.sync as ReturnType<typeof vi.fn>).mockClear();
      (setup.api.updateCipher as ReturnType<typeof vi.fn>).mockReset();
    };

    const installAuthoritativeCounterUpdate = (
      setup: CounterSetup,
      server = setup.sync,
      beforeUpdate?: () => void,
    ): void => {
      (setup.api.updateCipher as unknown as Mock).mockImplementation(async (
        _token: string,
        id: string,
        cipherRequest: CipherRequest,
      ) => {
        beforeUpdate?.();
        const index = server.ciphers.findIndex((cipher) => cipher.id === id);
        if (index < 0) throw new Error('counter fixture cipher is missing');
        const current = server.ciphers[index]!;
        const {
          lastKnownRevisionDate: _lastKnownRevisionDate,
          attachments2: _attachments2,
          ...wire
        } = cipherRequest;
        const committed = {
          ...current,
          ...wire,
          id,
          revisionDate: nextRevisionDate,
        } as CipherResponse;
        server.ciphers[index] = committed;
        return committed;
      });
    };

    it('increments, persists, verifies, and only then signs a non-zero counter', async () => {
      const setup = await makeServiceWithPasskey({
        rpId: 'acme.com',
        counter: '7',
        revisionDate,
      });
      resetCounterMocks(setup);
      const originalCredential = structuredClone(
        setup.sync.ciphers[0]!.login!.fido2Credentials![0]!,
      );
      const sign = vi.spyOn(globalThis.crypto.subtle, 'sign');
      const events: string[] = [];
      let updateCommitted = false;
      (setup.api.sync as unknown as Mock).mockImplementation(async () => {
        events.push(updateCommitted ? 'post-sync' : 'pre-sync');
        expect(ecdsaSignCount(sign)).toBe(0);
        return setup.sync;
      });
      installAuthoritativeCounterUpdate(setup, setup.sync, () => {
        events.push('put');
        expect(ecdsaSignCount(sign)).toBe(0);
        updateCommitted = true;
      });

      try {
        const assertion = await setup.service.getPasskeyAssertion(request);
        expect(assertion).toBeDefined();
        expect(events).toEqual(['pre-sync', 'put', 'post-sync']);
        expect(ecdsaSignCount(sign)).toBe(1);
        expect(assertionCounter(assertion!)).toBe(8);

        const [, id, update] = (setup.api.updateCipher as unknown as Mock).mock.calls[0]!;
        expect(id).toBe('pk');
        expect((update as CipherRequest).lastKnownRevisionDate).toBe(revisionDate);
        const updatedCredential = (update as CipherRequest).login!.fido2Credentials![0]!;
        await expect(decryptToText(updatedCredential.counter!, testUserKey)).resolves.toBe('8');
        expect({ ...updatedCredential, counter: originalCredential.counter }).toEqual(originalCredential);
      } finally {
        sign.mockRestore();
      }
    });

    it('uses the fresh server counter and revision instead of the advisory cached value', async () => {
      const setup = await makeServiceWithPasskey({
        rpId: 'acme.com',
        counter: '3',
        revisionDate,
      });
      resetCounterMocks(setup);
      const server = structuredClone(setup.sync);
      const freshRevisionDate = '2026-08-30T12:34:58.000Z';
      server.ciphers[0]!.revisionDate = freshRevisionDate;
      server.ciphers[0]!.login!.fido2Credentials![0]!.counter = await encUnder('9', testUserKey);
      (setup.api.sync as unknown as Mock).mockImplementation(async () => server);
      installAuthoritativeCounterUpdate(setup, server);

      const assertion = await setup.service.getPasskeyAssertion(request);
      expect(assertionCounter(assertion!)).toBe(10);
      const update = (setup.api.updateCipher as unknown as Mock).mock.calls[0]![2] as CipherRequest;
      expect(update.lastKnownRevisionDate).toBe(freshRevisionDate);
      await expect(decryptToText(
        update.login!.fido2Credentials![0]!.counter!,
        testUserKey,
      )).resolves.toBe('10');
    });

    it.each([
      ['conflict', 'conflict'],
      ['outcome unknown', 'outcome_unknown'],
      ['stale authoritative sync', 'committed_unsynced'],
    ] as const)('does not sign when the counter update ends in %s', async (scenario, code) => {
      const setup = await makeServiceWithPasskey({
        rpId: 'acme.com',
        counter: '1',
        revisionDate,
      });
      resetCounterMocks(setup);
      const sign = vi.spyOn(globalThis.crypto.subtle, 'sign');
      if (scenario === 'conflict') {
        (setup.api.updateCipher as ReturnType<typeof vi.fn>).mockRejectedValue(
          new ApiHttpError(409, { message: 'Cipher revision conflict' }),
        );
      } else if (scenario === 'outcome unknown') {
        (setup.api.updateCipher as ReturnType<typeof vi.fn>).mockRejectedValue(
          new TypeError('network closed'),
        );
      } else {
        (setup.api.updateCipher as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: 'pk',
          type: 1,
          name: setup.sync.ciphers[0]!.name,
        });
      }

      try {
        await expect(setup.service.getPasskeyAssertion(request)).rejects.toMatchObject({ code });
        expect(ecdsaSignCount(sign)).toBe(0);
        expect(setup.api.updateCipher).toHaveBeenCalledOnce();
        expect(setup.api.sync).toHaveBeenCalledTimes(scenario === 'stale authoritative sync' ? 2 : 1);
      } finally {
        sign.mockRestore();
      }
    });

    it.each([
      ['empty', { counter: '' }],
      ['negative', { counter: '-1' }],
      ['fraction', { counter: '1.5' }],
      ['leading zero', { counter: '01' }],
      ['scientific notation', { counter: '1e3' }],
      ['uint32 overflow', { counter: '4294967296' }],
      ['exhausted uint32', { counter: '4294967295' }],
    ] as const)('fails closed for a %s passkey counter', async (_scenario, counter) => {
      const setup = await makeServiceWithPasskey({
        rpId: 'acme.com',
        ...counter,
        revisionDate,
      });
      resetCounterMocks(setup);
      const sign = vi.spyOn(globalThis.crypto.subtle, 'sign');
      try {
        await expect(setup.service.getPasskeyAssertion(request))
          .rejects.toMatchObject({ code: 'denied' });
        expect(ecdsaSignCount(sign)).toBe(0);
        expect(setup.api.updateCipher).not.toHaveBeenCalled();
      } finally {
        sign.mockRestore();
      }
    });

    it.each([
      ['missing', { omitCounter: true }],
      ['null', { counter: null }],
    ] as const)('rejects a wire-invalid %s counter during sync', async (_scenario, counter) => {
      await expect(makeServiceWithPasskey({
        rpId: 'acme.com',
        ...counter,
        revisionDate,
      })).rejects.toThrow('invalid_structured_projection');
    });

    it('does not sign a credential whose counter ciphertext is undecryptable', async () => {
      const setup = await makeServiceWithPasskey({
        rpId: 'acme.com',
        rawCounter: '2.invalid',
        revisionDate,
      });
      resetCounterMocks(setup);
      const sign = vi.spyOn(globalThis.crypto.subtle, 'sign');
      try {
        await expect(setup.service.getPasskeyAssertion(request)).resolves.toBeUndefined();
        expect(ecdsaSignCount(sign)).toBe(0);
        expect(setup.api.updateCipher).not.toHaveBeenCalled();
      } finally {
        sign.mockRestore();
      }
    });

    it('requires a fresh revision before incrementing a non-zero counter', async () => {
      const setup = await makeServiceWithPasskey({ rpId: 'acme.com', counter: '1' });
      resetCounterMocks(setup);
      const sign = vi.spyOn(globalThis.crypto.subtle, 'sign');
      try {
        await expect(setup.service.getPasskeyAssertion(request))
          .rejects.toMatchObject({ code: 'denied' });
        expect(ecdsaSignCount(sign)).toBe(0);
        expect(setup.api.updateCipher).not.toHaveBeenCalled();
        expect(setup.api.sync).toHaveBeenCalledOnce();
      } finally {
        sign.mockRestore();
      }
    });

    it('serializes concurrent assertions into distinct increasing counters', async () => {
      const setup = await makeServiceWithPasskey({
        rpId: 'acme.com',
        counter: '1',
        revisionDate,
      });
      resetCounterMocks(setup);
      installAuthoritativeCounterUpdate(setup);

      const assertions = await Promise.all([
        setup.service.getPasskeyAssertion(request),
        setup.service.getPasskeyAssertion(request),
      ]);

      expect(assertions.map((assertion) => assertionCounter(assertion!))).toEqual([2, 3]);
      expect(setup.api.updateCipher).toHaveBeenCalledTimes(2);
      expect(setup.api.sync).toHaveBeenCalledTimes(4);
      const counters = await Promise.all(
        (setup.api.updateCipher as unknown as Mock).mock.calls.map((call) => decryptToText(
          (call[2] as CipherRequest).login!.fido2Credentials![0]!.counter!,
          testUserKey,
        )),
      );
      expect(counters).toEqual(['2', '3']);
    });
  });

  it('does not sign with a passkey removed by a concurrent sync', async () => {
    const { service, api, session } = await makeServiceWithPasskey({ rpId: 'acme.com' });
    const pause = pauseNextPrivateKeyLoad(session);
    stubApi(api).sync = vi.fn(async () => ({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));
    const challenge = bytesToBase64Url(new TextEncoder().encode('concurrent-sync'));

    const pending = service.getPasskeyAssertion({ rpId: 'acme.com', origin: 'https://acme.com', challenge });
    await pause.started;
    await service.sync();
    pause.release();

    await expect(pending).rejects.toMatchObject({ code: 'denied' });
  });

  it('listPasskeyCandidates returns every matching passkey (name/username, no key material)', async () => {
    const cred = async (id: string, rp: string) => completeFido2Credential({
      credentialId: await encUnder(id, testUserKey),
      keyValue: await encUnder(`KEY-${id}`, testUserKey),
      rpId: await encUnder(rp, testUserKey),
      counter: await encUnder('0', testUserKey),
    }, testUserKey);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await encUnder('Acme Work', testUserKey), favorite: false, organizationId: null,
          login: { username: await encUnder('work@acme.com', testUserKey), fido2Credentials: [await cred('cred-a', 'acme.com')] } },
        { id: 'b', type: 1, name: await encUnder('Acme Personal', testUserKey), favorite: false, organizationId: null,
          login: { username: await encUnder('me@acme.com', testUserKey), fido2Credentials: [await cred('cred-b', 'acme.com')] } },
        { id: 'c', type: 1, name: await encUnder('Other Site', testUserKey), favorite: false, organizationId: null,
          login: { fido2Credentials: [await cred('cred-c', 'other.com')] } },
        { id: 'd', type: 1, name: await encUnder('Trashed', testUserKey), favorite: false, organizationId: null, deletedDate: '2020-01-01T00:00:00Z',
          login: { fido2Credentials: [await cred('cred-d', 'acme.com')] } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();

    // Every non-trashed acme.com passkey, in vault order, with display name/username and no key material.
    const candidates = await service.listPasskeyCandidates({ rpId: 'acme.com', origin: 'https://acme.com' });
    expect(candidates).toEqual([
      { credentialId: 'cred-a', name: 'Acme Work', username: 'work@acme.com' },
      { credentialId: 'cred-b', name: 'Acme Personal', username: 'me@acme.com' },
    ]);
    expect(JSON.stringify(candidates)).not.toContain('KEY-');

    // allowCredentials filters to the RP-allowed subset.
    const filtered = await service.listPasskeyCandidates({ rpId: 'acme.com', origin: 'https://acme.com', allowedCredentialIds: ['cred-b'] });
    expect(filtered.map((c) => c.credentialId)).toEqual(['cred-b']);
  });

  it('uses the official single credential at [0] for resident and explicit lookup', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8Bytes = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    const keyValue = bytesToBase64Url(pkcs8Bytes);
    pkcs8Bytes.fill(0);
    const credential = async (
      credentialId: string,
      rpId: string,
      discoverable: Fido2CredentialData['discoverable'],
    ) => completeFido2Credential({
      credentialId: await encUnder(credentialId, testUserKey),
      keyValue: await encUnder(keyValue, testUserKey),
      rpId: await encUnder(rpId, testUserKey),
      counter: await encUnder('0', testUserKey),
      ...(discoverable === undefined ? {} : { discoverable }),
    }, testUserKey);
    const fixture = async (
      id: string,
      credentialId: string,
      rpId: string,
      discoverable: Fido2CredentialData['discoverable'],
    ): Promise<CipherResponse> => ({
      id,
      type: 1,
      name: await encUnder(`Passkey ${id}`, testUserKey),
      login: { fido2Credentials: [await credential(credentialId, rpId, discoverable)] },
    });
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        await fixture('resident-item', 'resident', 'example.com', await encUnder('true', testUserKey)),
        await fixture('nonresident-item', 'nonresident', 'example.com', await encUnder('false', testUserKey)),
        await fixture('malformed-item', 'malformed-discoverable', 'example.com', '2.bad|bad|bad'),
        await fixture('other-rp-item', 'other-rp', 'login.example.com', null),
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();

    const resident = await service.listPasskeyCandidates({
      rpId: 'example.com',
      origin: 'https://example.com',
    });
    expect(resident.map((candidate) => candidate.credentialId)).toEqual(['resident']);
    await expect(service.listPasskeyCandidates({
      rpId: 'example.com',
      origin: 'https://example.com',
      allowedCredentialIds: [],
    })).resolves.toEqual(resident);

    const explicit = await service.listPasskeyCandidates({
      rpId: 'example.com',
      origin: 'https://example.com',
      allowedCredentialIds: ['nonresident', 'malformed-discoverable', 'nonresident'],
    });
    expect(explicit.map((candidate) => candidate.credentialId)).toEqual([
      'nonresident',
      'malformed-discoverable',
    ]);
    await expect(service.hasMatchingPasskey({
      rpId: 'login.example.com',
      origin: 'https://login.example.com',
    })).resolves.toBe(false);
    await expect(service.hasMatchingPasskey({
      rpId: 'login.example.com',
      origin: 'https://login.example.com',
      allowedCredentialIds: ['other-rp'],
    })).resolves.toBe(true);
    const assertion = await service.getPasskeyAssertion({
      rpId: 'login.example.com',
      origin: 'https://login.example.com',
      challenge: 'AAAA',
      allowedCredentialIds: ['other-rp'],
    });
    expect(assertion?.credentialId).toBe('other-rp');
  });

  it('fails closed for corrupt and non-official multi-entry credential arrays', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    const keyValue = bytesToBase64Url(pkcs8);
    pkcs8.fill(0);
    const credential = async (id: string) => completeFido2Credential({
      credentialId: await encUnder(id, testUserKey),
      keyValue: await encUnder(keyValue, testUserKey),
      rpId: await encUnder('example.com', testUserKey),
      counter: await encUnder('0', testUserKey),
    }, testUserKey);
    const corruptCredential = await credential('corrupt');
    corruptCredential.credentialId = '2.invalid';
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        {
          id: 'multi-passkey',
          type: 1,
          name: await encUnder('Multi passkey', testUserKey),
          login: {
            uris: [{ uri: await encUnder('https://example.com', testUserKey) }],
            fido2Credentials: [await credential('first'), await credential('second')],
          },
        },
        {
          id: 'corrupt-passkey',
          type: 1,
          name: await encUnder('Corrupt passkey', testUserKey),
          login: {
            uris: [{ uri: await encUnder('https://example.com', testUserKey) }],
            fido2Credentials: [corruptCredential],
          },
        },
      ],
    };
    const generate = vi.fn(generateFido2Keypair);
    const { service, api } = await makeService(sync, { generateFido2Keypair: generate });
    await service.sync();

    await expect(service.listPasskeyCandidates({
      rpId: 'example.com',
      origin: 'https://example.com',
      allowedCredentialIds: ['second'],
    })).resolves.toEqual([]);
    await expect(service.hasMatchingPasskey({
      rpId: 'example.com',
      origin: 'https://example.com',
      allowedCredentialIds: ['second'],
    })).resolves.toBe(false);
    await expect(service.getPasskeyAssertion({
      rpId: 'example.com',
      origin: 'https://example.com',
      challenge: 'AAAA',
      allowedCredentialIds: ['second'],
    })).resolves.toBeUndefined();
    await expect(service.getPasskeyTargets({
      rpId: 'example.com',
      origin: 'https://example.com',
    })).resolves.toEqual([]);
    for (const targetCipherId of ['multi-passkey', 'corrupt-passkey']) {
      await expect(service.createPasskey({
        rpId: 'example.com',
        origin: 'https://example.com',
        challenge: 'AAAA',
        targetCipherId,
      })).rejects.toMatchObject({ code: 'error' });
    }
    expect(generate).not.toHaveBeenCalled();
    expect(api.updateCipher).not.toHaveBeenCalled();
  });

  it('marks reprompt candidates, excludes occupied create targets, and never silently signs them', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8Bytes = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
    const keyValue = bytesToBase64Url(pkcs8Bytes);
    pkcs8Bytes.fill(0);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'protected-passkey',
        type: 1,
        name: await encUnder('Protected', testUserKey),
        reprompt: 1,
        login: {
          username: await encUnder('protected@example.com', testUserKey),
          uris: [{ uri: await encUnder('https://example.com', testUserKey) }],
          fido2Credentials: [await completeFido2Credential({
            credentialId: await encUnder('protected-id', testUserKey),
            keyValue: await encUnder(keyValue, testUserKey),
            rpId: await encUnder('example.com', testUserKey),
            counter: await encUnder('0', testUserKey),
          }, testUserKey)],
        },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.hasMatchingPasskey({
      rpId: 'example.com',
      origin: 'https://example.com',
    })).resolves.toBe(true);
    await expect(service.listPasskeyCandidates({
      rpId: 'example.com',
      origin: 'https://example.com',
    })).resolves.toEqual([{
      credentialId: 'protected-id',
      name: 'Protected',
      username: 'protected@example.com',
      requiresReprompt: true,
    }]);
    await expect(service.getPasskeyTargets({
      rpId: 'example.com',
      origin: 'https://example.com',
    })).resolves.toEqual([]);
    await expect(service.getPasskeyAssertion({
      rpId: 'example.com',
      origin: 'https://example.com',
      challenge: 'AAAA',
    })).resolves.toBeUndefined();
  });

  it('listTotpCodes returns a live code for each non-reprompt TOTP login (no secret leak)', async () => {
    const SECRET = 'JBSWY3DPEHPK3PXP';
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await encUnder('GitHub', testUserKey), favorite: false, organizationId: null,
          login: { username: await encUnder('octo', testUserKey), totp: await encUnder(SECRET, testUserKey) } },
        { id: 'b', type: 1, name: await encUnder('No TOTP', testUserKey), favorite: false, organizationId: null,
          login: { username: await encUnder('nope', testUserKey) } },
        { id: 'c', type: 1, name: await encUnder('Protected', testUserKey), favorite: false, organizationId: null, reprompt: 1,
          login: { totp: await encUnder(SECRET, testUserKey) } },
        { id: 'd', type: 1, name: await encUnder('Trashed', testUserKey), favorite: false, organizationId: null, deletedDate: '2020-01-01T00:00:00Z',
          login: { totp: await encUnder(SECRET, testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();

    // Only the plain TOTP login — no-TOTP, reprompt-protected, and trashed logins are excluded.
    const entries = await service.listTotpCodes();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ id: 'a', name: 'GitHub', username: 'octo', period: 30 });
    expect(entries[0]!.code).toMatch(/^\d{6}$/);
    expect(entries[0]!.remaining).toBeGreaterThan(0);
    expect(JSON.stringify(entries)).not.toContain(SECRET);
  });

  it('passkey assertion never trusts caller-supplied user-verification state', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pkcs8 = bytesToBase64Url(new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey)));
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'pk', type: 1, name: await encUnder('Acme', testUserKey), favorite: false, organizationId: null,
        login: { fido2Credentials: [await completeFido2Credential({
          credentialId: await encUnder('cred-1', testUserKey),
          keyValue: await encUnder(pkcs8, testUserKey),
          rpId: await encUnder('acme.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }, testUserKey)] },
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
    expect(await flags(false)).toBe(0x19);  // legacy false is ignored
    expect(await flags(true)).toBe(0x19);   // legacy true is untrusted and ignored
  });

  it('hasMatchingPasskey reports whether a stored passkey matches the rpId / allowed credential', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'pk', type: 1, name: await encUnder('Acme', testUserKey), favorite: false, organizationId: null,
        login: { fido2Credentials: [await completeFido2Credential({
          credentialId: await encUnder('cred-1', testUserKey),
          keyValue: await encUnder('2.kv==', testUserKey),
          rpId: await encUnder('acme.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }, testUserKey)] },
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

  it('reports non-secret metadata for every password so breach results can be joined by id', async () => {
    const weak = await encUnder('weakpass', testUserKey);
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await encUnder('A', testUserKey), favorite: false, organizationId: null, login: { password: weak } },
        { id: 'b', type: 1, name: await encUnder('B', testUserKey), favorite: false, organizationId: null, login: { password: weak } },
        { id: 'c', type: 1, name: await encUnder('C', testUserKey), favorite: false, organizationId: null, login: { password: await encUnder('strong-pwned', testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const entries = await service.getPasswordHealth();
    // Every password-bearing login is represented so an explicit HIBP result can be joined by id.
    expect(entries.map((e) => e.id).sort()).toEqual(['a', 'b', 'c']);
    expect(entries.filter((e) => e.id !== 'c').every((e) => e.weak && e.reuseCount === 2)).toBe(true);
    expect(entries.find((e) => e.id === 'c')).toEqual({ id: 'c', name: 'C', weak: false, reuseCount: 1 });
    expect(JSON.stringify(entries)).not.toContain('weakpass');
    expect(JSON.stringify(entries)).not.toContain('strong-pwned');
  });

  it('limits password health to active decryptable personal logins', async () => {
    const sharedPassword = await encUnder('weakpass', testUserKey);
    const sync: SyncResponse = {
      profile: {
        id: 'u',
        email: 'u@example.com',
        organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }],
      },
      ciphers: [
        {
          id: 'personal-active',
          type: 1,
          name: await encUnder('Personal active', testUserKey),
          favorite: false,
          organizationId: null,
          login: { password: sharedPassword },
        },
        {
          id: 'organization-viewable',
          type: 1,
          name: await encUnder('Organization viewable', orgKey),
          favorite: false,
          organizationId: 'org-1',
          edit: true,
          viewPassword: true,
          organizationUseTotp: true,
          permissions: { delete: true, restore: true },
          login: { password: await encUnder('weakpass', orgKey) },
        },
        {
          id: 'personal-archived',
          type: 1,
          name: await encUnder('Personal archived', testUserKey),
          favorite: false,
          organizationId: null,
          archivedDate: '2026-08-01T00:00:00Z',
          login: { password: sharedPassword },
        },
        {
          id: 'personal-trashed',
          type: 1,
          name: await encUnder('Personal trashed', testUserKey),
          favorite: false,
          organizationId: null,
          deletedDate: '2026-08-02T00:00:00Z',
          login: { password: sharedPassword },
        },
        {
          id: 'personal-undecryptable',
          type: 1,
          name: await encUnder('Personal undecryptable', testUserKey),
          favorite: false,
          organizationId: null,
          login: { password: '2.bad|bad|bad' },
        },
      ],
    };
    const { service } = await makeService(sync, { privateKey: privateKeyBytes });
    await service.sync();

    await expect(service.getPasswordHealth()).resolves.toEqual([{
      id: 'personal-active',
      name: 'Personal active',
      weak: true,
      reuseCount: 1,
    }]);
  });

  it('getPwnedReport dedupes by password, maps counts back per id, and returns no passwords', async () => {
    const enc = async (s: string) => encUnder(s, testUserKey); // existing helper
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await enc('A'), favorite: false, organizationId: null, login: { password: await enc('reused-weak') } },
        { id: 'b', type: 1, name: await enc('B'), favorite: false, organizationId: null, login: { password: await enc('reused-weak') } },
        { id: 'c', type: 1, name: await enc('C'), favorite: false, organizationId: null, login: { password: await enc('strong-pwned') } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const entries = await service.getPwnedReport();
    expect(entries).toEqual([{ id: 'a', pwnedCount: 42 }, { id: 'b', pwnedCount: 42 }, { id: 'c', pwnedCount: 17 }]);
    const { pwnedCount } = await import('./pwned.js');
    expect(vi.mocked(pwnedCount).mock.calls.length).toBe(2); // deduped: 'reused-weak' + 'strong-pwned'
    expect(JSON.stringify(entries)).not.toContain('reused-weak'); // no password crosses the boundary
    expect(JSON.stringify(entries)).not.toContain('strong-pwned');
  });

  it('getPwnedReport tolerates a single failed HIBP lookup (allSettled), omitting only that id', async () => {
    const { pwnedCount } = await import('./pwned.js');
    const mock = vi.mocked(pwnedCount);
    const original = mock.getMockImplementation();
    mock.mockImplementation(async (pw: string) => {
      if (pw === 'boom') throw new Error('network down');
      return pw === 'pwned' ? 7 : 0;
    });
    try {
      const enc = async (s: string) => encUnder(s, testUserKey);
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [
          { id: 'a', type: 1, name: await enc('A'), favorite: false, organizationId: null, login: { password: await enc('pwned') } },
          { id: 'b', type: 1, name: await enc('B'), favorite: false, organizationId: null, login: { password: await enc('boom') } },
          { id: 'c', type: 1, name: await enc('C'), favorite: false, organizationId: null, login: { password: await enc('safe') } },
        ],
      };
      const { service } = await makeService(sync);
      await service.sync();
      const entries = await service.getPwnedReport();
      // 'b' failed → omitted (never 0, so the UI shows it as unknown); 'a' and 'c' succeeded.
      expect(entries).toEqual([{ id: 'a', pwnedCount: 7 }, { id: 'c', pwnedCount: 0 }]);
    } finally {
      mock.mockImplementation(original!);
    }
  });

  it('getPwnedReport throws only when every HIBP lookup fails', async () => {
    const { pwnedCount } = await import('./pwned.js');
    const mock = vi.mocked(pwnedCount);
    const original = mock.getMockImplementation();
    mock.mockImplementation(async () => { throw new Error('all down'); });
    try {
      const enc = async (s: string) => encUnder(s, testUserKey);
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [
          { id: 'a', type: 1, name: await enc('A'), favorite: false, organizationId: null, login: { password: await enc('p1') } },
          { id: 'b', type: 1, name: await enc('B'), favorite: false, organizationId: null, login: { password: await enc('p2') } },
        ],
      };
      const { service } = await makeService(sync);
      await service.sync();
      await expect(service.getPwnedReport()).rejects.toMatchObject({ code: 'error' });
    } finally {
      mock.mockImplementation(original!);
    }
  });

  it('queries HIBP only for personal logins when personal lookups have mixed outcomes', async () => {
    const { pwnedCount } = await import('./pwned.js');
    const mock = vi.mocked(pwnedCount);
    const original = mock.getMockImplementation();
    mock.mockClear();
    mock.mockImplementation(async (password: string) => {
      if (password === 'personal-failed') throw new Error('network down');
      if (password === 'personal-pwned') return 7;
      if (password === 'personal-safe') return 0;
      return 99;
    });
    try {
      const sync: SyncResponse = {
        profile: {
          id: 'u',
          email: 'u@example.com',
          organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }],
        },
        ciphers: [
          {
            id: 'personal-pwned',
            type: 1,
            name: await encUnder('Personal pwned', testUserKey),
            favorite: false,
            organizationId: null,
            login: { password: await encUnder('personal-pwned', testUserKey) },
          },
          {
            id: 'personal-failed',
            type: 1,
            name: await encUnder('Personal failed', testUserKey),
            favorite: false,
            organizationId: null,
            login: { password: await encUnder('personal-failed', testUserKey) },
          },
          {
            id: 'personal-safe',
            type: 1,
            name: await encUnder('Personal safe', testUserKey),
            favorite: false,
            organizationId: null,
            login: { password: await encUnder('personal-safe', testUserKey) },
          },
          {
            id: 'organization-shared',
            type: 1,
            name: await encUnder('Organization shared', orgKey),
            favorite: false,
            organizationId: 'org-1',
            edit: true,
            viewPassword: true,
            organizationUseTotp: true,
            permissions: { delete: true, restore: true },
            login: { password: await encUnder('personal-pwned', orgKey) },
          },
          {
            id: 'organization-only',
            type: 1,
            name: await encUnder('Organization only', orgKey),
            favorite: false,
            organizationId: 'org-1',
            edit: true,
            viewPassword: true,
            organizationUseTotp: true,
            permissions: { delete: true, restore: true },
            login: { password: await encUnder('organization-only', orgKey) },
          },
          {
            id: 'personal-archived',
            type: 1,
            name: await encUnder('Personal archived', testUserKey),
            favorite: false,
            organizationId: null,
            archivedDate: '2026-08-01T00:00:00Z',
            login: { password: await encUnder('archived-only', testUserKey) },
          },
          {
            id: 'personal-trashed',
            type: 1,
            name: await encUnder('Personal trashed', testUserKey),
            favorite: false,
            organizationId: null,
            deletedDate: '2026-08-02T00:00:00Z',
            login: { password: await encUnder('trashed-only', testUserKey) },
          },
          {
            id: 'personal-undecryptable',
            type: 1,
            name: await encUnder('Personal undecryptable', testUserKey),
            favorite: false,
            organizationId: null,
            login: { password: '2.bad|bad|bad' },
          },
        ],
      };
      const { service } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.getPwnedReport()).resolves.toEqual([
        { id: 'personal-pwned', pwnedCount: 7 },
        { id: 'personal-safe', pwnedCount: 0 },
      ]);
      expect(mock.mock.calls.map(([password]) => password).sort()).toEqual([
        'personal-failed',
        'personal-pwned',
        'personal-safe',
      ]);
    } finally {
      mock.mockImplementation(original!);
      mock.mockClear();
    }
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

  it('getFillData releases only requested card roles and never couples the number to the CVC', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null,
        card: { cardholderName: await encUnder('Ada Lovelace', testUserKey), brand: await encUnder('Visa', testUserKey), number: await encUnder('4111111111111111', testUserKey), code: await encUnder('123', testUserKey), expMonth: await encUnder('9', testUserKey), expYear: await encUnder('2030', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();

    const decryptText = vi.spyOn(encstringNs, 'decryptToText');
    decryptText.mockClear();
    await expect(service.getFillData('card-1', 'card', ['number']))
      .resolves.toEqual({ number: '4111111111111111' });
    expect(decryptText).toHaveBeenCalledOnce();
    expect(decryptText).toHaveBeenCalledWith(sync.ciphers[0]!.card!.number, expect.anything());
    await expect(service.getFillData('card-1', 'card', ['code']))
      .resolves.toEqual({ code: '123' });
    await expect(service.getFillData('card-1', 'card', ['brand']))
      .resolves.toEqual({ brand: 'Visa' });
    await expect(service.getFillData('card-1', 'card', ['exp']))
      .resolves.toEqual({ expMonth: '9', expYear: '2030' });
    await expect(service.getFillData('card-1', 'card', ['expMonth']))
      .resolves.toEqual({ expMonth: '9' });
    await expect(service.getFillData('card-1', 'card', ['expYear']))
      .resolves.toEqual({ expYear: '2030' });
    await expect(service.getFillData('card-1', 'card', ['number', 'number']))
      .resolves.toEqual({ number: '4111111111111111' });
  });

  it('getFillData releases only requested identity roles and omits national-ID secrets', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'id-1', type: 4, name: await encUnder('Me', testUserKey), favorite: false, organizationId: null,
        identity: { title: await encUnder('Countess', testUserKey), firstName: await encUnder('Ada', testUserKey), middleName: await encUnder('Byron', testUserKey), lastName: await encUnder('Lovelace', testUserKey), address1: await encUnder('1 Analytical Way', testUserKey), address2: await encUnder('Suite 2', testUserKey), address3: await encUnder('London', testUserKey), email: await encUnder('ada@example.com', testUserKey),
          ssn: await encUnder('999-99-9999', testUserKey), passportNumber: await encUnder('P123', testUserKey), licenseNumber: await encUnder('L123', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();

    const data = await service.getFillData('id-1', 'identity', ['fullName']);
    expect(data).toEqual({ firstName: 'Ada', middleName: 'Byron', lastName: 'Lovelace' });
    expect(JSON.stringify(data)).not.toContain('999-99-9999');
    expect(JSON.stringify(data)).not.toContain('P123');
    expect(JSON.stringify(data)).not.toContain('L123');
    expect(JSON.stringify(data)).not.toContain('ada@example.com');
    await expect(service.getFillData('id-1', 'identity', ['email']))
      .resolves.toEqual({ email: 'ada@example.com' });
    await expect(service.getFillData('id-1', 'identity', ['address']))
      .resolves.toEqual({ address1: '1 Analytical Way', address2: 'Suite 2', address3: 'London' });
  });

  it('getFillData unwraps a per-cipher key before decrypting the requested role', async () => {
    const perCipherKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x42));
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'keyed-card',
        type: 3,
        name: await encUnder('Keyed card', perCipherKey),
        favorite: false,
        organizationId: null,
        key: await wrapAttachmentKey(perCipherKey, testUserKey),
        card: {
          number: await encUnder('4111111111111111', perCipherKey),
          code: await encUnder('123', perCipherKey),
        },
      }],
    };
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getFillData('keyed-card', 'card', ['number']))
      .resolves.toEqual({ number: '4111111111111111' });
  });

  it('getFillData does not materialize malformed fields outside the requested projection', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null,
          card: { number: await encUnder('4111', testUserKey), code: 'not-an-enc-string' } },
        { id: 'id-1', type: 4, name: await encUnder('Me', testUserKey), favorite: false, organizationId: null,
          identity: { email: await encUnder('ada@example.com', testUserKey), ssn: 'not-an-enc-string' } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();

    await expect(service.getFillData('card-1', 'card', ['number'])).resolves.toEqual({ number: '4111' });
    await expect(service.getFillData('card-1', 'card', ['code'])).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('id-1', 'identity', ['email']))
      .resolves.toEqual({ email: 'ada@example.com' });
  });

  it('getFillData rejects empty, invalid, cross-kind, and over-limit role requests', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null,
        card: { number: await encUnder('4111', testUserKey), code: await encUnder('123', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();

    const decryptText = vi.spyOn(encstringNs, 'decryptToText');
    decryptText.mockClear();
    await expect(service.getFillData('card-1', 'card', [])).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('card-1', 'card', null as never)).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('card-1', 'card', [42] as never)).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('card-1', 'card', ['email'] as never)).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('card-1', 'card', ['number', 'ssn'] as never)).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('card-1', 'payment' as never, ['number']))
      .rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData(
      'card-1',
      'card',
      Array.from({ length: 17 }, () => 'number') as Array<'number'>,
    )).rejects.toMatchObject({ code: 'denied' });
    expect(decryptText).not.toHaveBeenCalled();
  });

  it('releases reprompt card and identity projections only with a live background grant assertion', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        {
          id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false,
          organizationId: null, reprompt: 1,
          card: { number: await encUnder('4111', testUserKey), code: await encUnder('123', testUserKey) },
        },
        {
          id: 'identity-1', type: 4, name: await encUnder('Ada', testUserKey), favorite: false,
          organizationId: null, reprompt: 1,
          identity: {
            firstName: await encUnder('Ada', testUserKey),
            lastName: await encUnder('Lovelace', testUserKey),
            email: await encUnder('ada@example.com', testUserKey),
          },
        },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const cardGrant = vi.fn();
    const identityGrant = vi.fn();

    await expect(service.getFillData('card-1', 'card', ['number'], cardGrant))
      .resolves.toEqual({ number: '4111' });
    await expect(service.getFillData('identity-1', 'identity', ['fullName', 'email'], identityGrant))
      .resolves.toEqual({ firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.com' });
    expect(cardGrant.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(identityGrant.mock.calls.length).toBeGreaterThanOrEqual(3);
    await expect(service.getFillData('card-1', 'card', ['number']))
      .rejects.toMatchObject({ code: 'reprompt_required' });
    await expect(service.getFillData('identity-1', 'identity', ['email']))
      .rejects.toMatchObject({ code: 'reprompt_required' });
  });

  it('getFillData preserves locked, deleted, kind/type mismatch, and reprompt enforcement', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null, reprompt: 1,
          card: { number: await encUnder('4111', testUserKey) } },
        { id: 'login-1', type: 1, name: await encUnder('L', testUserKey), favorite: false, organizationId: null,
          login: { password: await encUnder('p', testUserKey) } },
        { id: 'deleted-card', type: 3, name: await encUnder('Old card', testUserKey), favorite: false, organizationId: null,
          deletedDate: '2026-08-30T00:00:00.000Z', card: { number: await encUnder('5555', testUserKey) } },
      ],
    };
    const { service, session } = await makeService(sync);
    await service.sync();
    const decryptText = vi.spyOn(encstringNs, 'decryptToText');
    decryptText.mockClear();
    const repromptErr = await service.getFillData('card-1', 'card', ['number']).then(() => null, (e) => e);
    expect(repromptErr).toMatchObject({ code: 'reprompt_required' });
    expect(JSON.stringify(repromptErr)).not.toContain('4111'); // no card number leaks via the thrown value
    await expect(service.getFillData('login-1', 'card', ['number'])).rejects.toMatchObject({ code: 'denied' });
    await expect(service.getFillData('deleted-card', 'card', ['number'])).rejects.toMatchObject({ code: 'denied' });
    await session.lock();
    await expect(service.getFillData('card-1', 'card', ['number'])).rejects.toMatchObject({ code: 'locked' });
    expect(decryptText).not.toHaveBeenCalled();
  });

  describe('passkey deletion', () => {
    const revisionDate = '2026-08-30T12:34:56.000Z';

    async function makeDeletePasskeySync(
      credentialIds: readonly string[],
      options: {
        organization?: boolean;
        edit?: boolean;
        viewPassword?: boolean;
        reprompt?: number;
        deletedDate?: string;
        archivedDate?: string;
      } = {},
    ): Promise<{
      response: SyncResponse;
      cipher: CipherResponse;
      credentials: Fido2CredentialData[];
      privateValues: string[];
    }> {
      const fieldKey = options.organization ? orgKey : testUserKey;
      const privateValues = credentialIds.map((id, index) => `private-${id}-${index}`);
      const credentials = await Promise.all(credentialIds.map(async (id, index) => (
        completeFido2Credential({
          credentialId: await encUnder(id, fieldKey),
          keyValue: await encUnder(privateValues[index]!, fieldKey),
          rpId: await encUnder('example.com', fieldKey),
          userHandle: await encUnder(`handle-${index}`, fieldKey),
          userName: await encUnder(`user-${index}`, fieldKey),
          counter: await encUnder(String(index), fieldKey),
          rpName: await encUnder('Example', fieldKey),
          userDisplayName: await encUnder(`User ${index}`, fieldKey),
        }, fieldKey)
      )));
      const cipher: CipherResponse = {
        id: 'passkey-item',
        type: 1,
        name: await encUnder('Passkey item', fieldKey),
        notes: await encUnder('Unchanged notes', fieldKey),
        favorite: true,
        folderId: 'folder-1',
        organizationId: options.organization ? 'org-1' : null,
        ...(options.organization ? {
          edit: options.edit ?? true,
          viewPassword: options.viewPassword ?? true,
          permissions: { delete: true, restore: true },
        } : {}),
        login: {
          username: await encUnder('ada', fieldKey),
          password: await encUnder('unchanged-password', fieldKey),
          totp: await encUnder(TOTP_SECRET_B32, fieldKey),
          uris: [{
            uri: await encUnder('https://example.com/login', fieldKey),
            match: UriMatchStrategy.Exact,
          }],
          autofillOnPageLoad: false,
          passwordRevisionDate: '2026-08-29T00:00:00.000Z',
          fido2Credentials: credentials,
        },
        fields: [{
          type: 1,
          name: await encUnder('recovery', fieldKey),
          value: await encUnder('unchanged-field', fieldKey),
        }],
        passwordHistory: [{
          password: await encUnder('old-password', fieldKey),
          lastUsedDate: '2026-08-28T00:00:00.000Z',
        }],
        reprompt: options.reprompt ?? 0,
        revisionDate,
        ...(options.deletedDate ? { deletedDate: options.deletedDate } : {}),
        ...(options.archivedDate ? { archivedDate: options.archivedDate } : {}),
      };
      return {
        response: {
          profile: options.organization
            ? {
              id: 'u',
              email: 'u@example.com',
              organizations: [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }],
            }
            : { id: 'u', email: 'u@example.com' },
          ciphers: [cipher],
        },
        cipher,
        credentials,
        privateValues,
      };
    }

    it.each([
      ['first', 0],
      ['middle', 1],
      ['last', 2],
    ] as const)('removes the %s credential by decrypted ID and preserves every other encrypted field', async (_position, index) => {
      const fixture = await makeDeletePasskeySync(['cred-a', 'cred-b', 'cred-c']);
      const setup = await makeServiceWithRaw(fixture.response);
      const privateKeyValues = new Set(fixture.credentials.map((credential) => credential.keyValue));
      const decryptText = vi.spyOn(encstringNs, 'decryptToText');
      decryptText.mockClear();

      try {
        const listing = await setup.service.deletePasskey('passkey-item', ['cred-a', 'cred-b', 'cred-c'][index]!);
        const [token, id, request] = vi.mocked(setup.api.updateCipher).mock.calls[0]!;
        const remaining = fixture.credentials.filter((_, credentialIndex) => credentialIndex !== index);

        expect([token, id]).toEqual(['access', 'passkey-item']);
        expect(request).toEqual({
          type: 1,
          name: fixture.cipher.name,
          notes: fixture.cipher.notes,
          favorite: fixture.cipher.favorite,
          folderId: fixture.cipher.folderId,
          login: { ...fixture.cipher.login, fido2Credentials: remaining },
          fields: fixture.cipher.fields,
          passwordHistory: fixture.cipher.passwordHistory,
          reprompt: fixture.cipher.reprompt,
          lastKnownRevisionDate: revisionDate,
        });
        expect(decryptText.mock.calls.every(([encrypted]) => !privateKeyValues.has(encrypted))).toBe(true);
        expect(JSON.stringify(listing)).not.toContain(fixture.privateValues[index]);
        expect(setup.api.sync).toHaveBeenCalledOnce();
      } finally {
        decryptText.mockRestore();
      }
    });

    it('deletes an organization credential under the organization key without exposing private material', async () => {
      const fixture = await makeDeletePasskeySync(['org-cred-a', 'org-cred-b'], { organization: true });
      const setup = await makeServiceWithRaw(fixture.response, { privateKey: privateKeyBytes });

      const listing = await setup.service.deletePasskey('passkey-item', 'org-cred-b');
      const request = vi.mocked(setup.api.updateCipher).mock.calls[0]![2];

      expect(request.organizationId).toBe('org-1');
      expect(request.login?.fido2Credentials).toEqual([fixture.credentials[0]]);
      expect(request.login?.fido2Credentials?.[0]?.keyValue).toBe(fixture.credentials[0]!.keyValue);
      expect(JSON.stringify(request)).not.toContain(fixture.privateValues[0]);
      expect(JSON.stringify(listing)).not.toContain(fixture.privateValues[0]);
    });

    it('keeps an empty raw credential array when the only credential is removed', async () => {
      const fixture = await makeDeletePasskeySync(['only-cred']);
      const setup = await makeServiceWithRaw(fixture.response);

      await setup.service.deletePasskey('passkey-item', 'only-cred');

      expect(vi.mocked(setup.api.updateCipher).mock.calls[0]![2].login?.fido2Credentials)
        .toEqual([]);
    });

    it('allows deleting a passkey from an archived item while preserving archive metadata', async () => {
      const fixture = await makeDeletePasskeySync(['archived-cred']);
      fixture.cipher.archivedDate = '2026-08-30T00:00:00.000Z';
      const setup = await makeServiceWithRaw(fixture.response);

      await expect(setup.service.deletePasskey('passkey-item', 'archived-cred'))
        .resolves.toBeDefined();

      const request = vi.mocked(setup.api.updateCipher).mock.calls[0]![2];
      expect(request.archivedDate).toBe(fixture.cipher.archivedDate);
      expect(request.login?.fido2Credentials).toEqual([]);
    });

    it('requires a valid master-password reprompt before decrypting or dispatching', async () => {
      const fixture = await makeDeletePasskeySync(['protected-cred'], { reprompt: 1 });
      const setup = await makeServiceWithRaw(fixture.response);

      await expect(setup.service.deletePasskey('passkey-item', 'protected-cred'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      await expect(setup.service.deletePasskey('passkey-item', 'protected-cred', 'wrong-master'))
        .rejects.toMatchObject({ code: 'reprompt_required' });
      expect(setup.api.updateCipher).not.toHaveBeenCalled();

      await expect(setup.service.deletePasskey('passkey-item', 'protected-cred', 'correct-master'))
        .resolves.toBeDefined();
      expect(setup.auth.verifyMasterPassword).toHaveBeenCalledTimes(2);
      expect(setup.api.updateCipher).toHaveBeenCalledOnce();
    });

    it.each([
      'deleted',
      'wrong-type',
      'organization-no-edit',
      'organization-no-password-view',
      'restricted-by-policy',
    ] as const)('fails closed for %s items before remote I/O', async (scenario) => {
      const organization = scenario.startsWith('organization-');
      const fixture = await makeDeletePasskeySync(['blocked-cred'], {
        organization,
        ...(scenario === 'organization-no-edit' ? { edit: false } : {}),
        ...(scenario === 'organization-no-password-view' ? { viewPassword: false } : {}),
        ...(scenario === 'deleted' ? { deletedDate: '2026-08-30T00:00:00.000Z' } : {}),
      });
      if (scenario === 'wrong-type') {
        fixture.cipher.type = 2;
        delete fixture.cipher.login;
      }
      const response = scenario === 'restricted-by-policy'
        ? withEnterprisePolicies(fixture.response, [{
          type: EnterprisePolicyType.RestrictedItemTypes,
          data: [1],
        }])
        : fixture.response;
      const setup = await makeServiceWithRaw(response, {
        ...(organization ? { privateKey: privateKeyBytes } : {}),
      });

      await expect(setup.service.deletePasskey('passkey-item', 'blocked-cred'))
        .rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.updateCipher).not.toHaveBeenCalled();
    });

    it.each([
      ['a later credential ID cannot be decrypted', ['cred-a', 'cred-b'], 'cred-a', 'corrupt'],
      ['the requested ID is duplicated', ['cred-a', 'cred-a'], 'cred-a', 'unchanged'],
      ['an unrelated ID is duplicated', ['cred-a', 'cred-b', 'cred-b'], 'cred-a', 'unchanged'],
      ['the requested ID is absent', ['cred-a', 'cred-b'], 'cred-missing', 'unchanged'],
    ] as const)('fails closed when %s', async (_reason, ids, requestedId, mutation) => {
      const fixture = await makeDeletePasskeySync(ids);
      if (mutation === 'corrupt') fixture.credentials[1]!.credentialId = '2.invalid';
      const setup = await makeServiceWithRaw(fixture.response);

      await expect(setup.service.deletePasskey('passkey-item', requestedId))
        .rejects.toMatchObject({ code: 'denied' });
      expect(setup.api.updateCipher).not.toHaveBeenCalled();
    });

    it('preserves conflict, outcome-unknown, and committed-unsynced mutation semantics', async () => {
      const conflictFixture = await makeDeletePasskeySync(['conflict-cred']);
      const conflict = await makeServiceWithRaw(conflictFixture.response);
      vi.mocked(conflict.api.updateCipher).mockRejectedValue(
        new ApiHttpError(409, { message: 'Cipher revision conflict' }),
      );
      await expect(conflict.service.deletePasskey('passkey-item', 'conflict-cred'))
        .rejects.toMatchObject({ code: 'conflict' });
      expect(conflict.api.updateCipher).toHaveBeenCalledOnce();

      const unknownFixture = await makeDeletePasskeySync(['unknown-cred']);
      const unknown = await makeServiceWithRaw(unknownFixture.response);
      vi.mocked(unknown.api.updateCipher).mockRejectedValue(new TypeError('network closed'));
      await expect(unknown.service.deletePasskey('passkey-item', 'unknown-cred'))
        .rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(unknown.api.updateCipher).toHaveBeenCalledOnce();

      const unsyncedFixture = await makeDeletePasskeySync(['unsynced-cred']);
      const unsynced = await makeServiceWithRaw(unsyncedFixture.response);
      vi.mocked(unsynced.api.sync).mockRejectedValue(new Error('offline'));
      await expect(unsynced.service.deletePasskey('passkey-item', 'unsynced-cred'))
        .rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(unsynced.api.updateCipher).toHaveBeenCalledOnce();
      expect(unsynced.api.sync).toHaveBeenCalledOnce();
    });

    it('rejects a concurrent raw-cache generation change before dispatch', async () => {
      const fixture = await makeDeletePasskeySync(['raced-cred'], { organization: true });
      const setup = await makeServiceWithRaw(fixture.response, { privateKey: privateKeyBytes });
      const pause = pauseNextPrivateKeyLoad(setup.session);

      const pending = setup.service.deletePasskey('passkey-item', 'raced-cred');
      await pause.started;
      const raw = await setup.localStore.get<{
        schemaVersion: 2;
        identity: string;
        rawGeneration: string;
        response: SyncResponse;
      }>(RAW_VAULT_CACHE_KEY);
      if (!raw) throw new Error('test cache was not initialized');
      await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
        ...raw,
        rawGeneration: 'concurrent-passkey-delete-generation',
      });
      pause.release();

      await expect(pending).rejects.toMatchObject({ code: 'error' });
      expect(setup.api.updateCipher).not.toHaveBeenCalled();
    });
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

    it('offers and updates a same-domain writable organization login target', async () => {
      const sync = await makeOrgSync();
      const { service, api } = await makeService(sync, { privateKey: privateKeyBytes });
      await service.sync();

      await expect(service.getPasskeyTargets({
        rpId: 'org.example',
        origin: 'https://org.example',
      })).resolves.toEqual([{ id: 'org-login', name: 'Org Login', username: 'alice@org.example' }]);

      await service.createPasskey({
        rpId: 'org.example',
        rpName: 'Org Example',
        userHandle: 'dXNlcg',
        userName: 'alice@org.example',
        challenge: 'AAAA',
        origin: 'https://org.example',
        targetCipherId: 'org-login',
      });

      expect(api.createCipher).not.toHaveBeenCalled();
      expect(api.updateCipher).toHaveBeenCalledOnce();
      const [, id, request] = vi.mocked(api.updateCipher).mock.calls[0]!;
      expect(id).toBe('org-login');
      expect(request.organizationId).toBe('org-1');
      expect(request.login?.fido2Credentials).toHaveLength(1);
      await expect(decryptToText(
        request.login!.fido2Credentials![0]!.keyValue!,
        orgKey,
      )).resolves.toMatch(/^[A-Za-z0-9_-]+$/u);
      await expect(decryptToText(
        request.login!.fido2Credentials![0]!.keyValue!,
        testUserKey,
      )).rejects.toThrow(EncStringMacError);
    });

    it('does not offer an organization login without both edit and password-view authority', async () => {
      for (const denied of ['edit', 'viewPassword'] as const) {
        const sync = await makeOrgSync();
        sync.ciphers[0]![denied] = false;
        const { service } = await makeService(sync, { privateKey: privateKeyBytes });
        await service.sync();
        await expect(service.getPasskeyTargets({
          rpId: 'org.example',
          origin: 'https://org.example',
        })).resolves.toEqual([]);
      }
    });

    it('getPasskeyTargets rejects a cross-origin rpId', async () => {
      const { service } = await makeServiceWithLogins([]);
      await expect(service.getPasskeyTargets({ rpId: 'example.com', origin: 'https://evil.com' })).rejects.toThrow(/rpId is not valid/i);
    });

    it('createPasskey (new item) POSTs a login with an encrypted fido2Credential and returns an attestation', async () => {
      const createCipher = vi.fn(async (_t: string, req: CipherRequest): Promise<CipherResponse> => ({ id: 'new1', ...req }));
      const { service } = await makeUnlockedService({ api: { createCipher } });
      const reg = await service.createPasskey({ rpId: 'example.com', rpName: 'Example', userHandle: 'dXNlcg', userName: 'me', challenge: 'AAAA', origin: 'https://example.com', userVerified: true, crossOrigin: true });
      expect(reg.publicKeyAlgorithm).toBe(-7);
      expect(reg.credentialId && reg.attestationObject && reg.clientDataJSON && reg.authData && reg.publicKeySpki).toBeTruthy();
      const [, req] = createCipher.mock.calls[0]!;
      expect(req.type).toBe(1);
      expect(req.login?.fido2Credentials).toHaveLength(1);
      expect(req.login?.fido2Credentials?.[0]?.keyValue).toMatch(/^2\./); // an EncString
      await expect(decryptToText(
        req.login!.fido2Credentials![0]!.discoverable!,
        testUserKey,
      )).resolves.toBe('false');
      expect(base64UrlToBytes(reg.authData)[32]).toBe(0x59); // caller `userVerified: true` is ignored
      expect(JSON.parse(new TextDecoder().decode(base64UrlToBytes(reg.clientDataJSON))))
        .toMatchObject({ crossOrigin: true });
    });

    it('writes one credential into an empty selected login and preserves every non-passkey encrypted field', async () => {
      const cipher: CipherResponse = {
        id: 'c1',
        type: 1,
        name: await encUnder('Existing Login', testUserKey),
        notes: await encUnder('Keep notes', testUserKey),
        favorite: true,
        folderId: 'folder-1',
        organizationId: null,
        revisionDate: '2026-08-30T12:00:00.000Z',
        login: {
          username: await encUnder('me', testUserKey),
          password: await encUnder('old-pass', testUserKey),
          totp: await encUnder(TOTP_SECRET_B32, testUserKey),
          uris: [{ uri: await encUnder('https://example.com/login', testUserKey), match: UriMatchStrategy.Domain }],
          autofillOnPageLoad: false,
          passwordRevisionDate: '2026-08-29T12:00:00.000Z',
          fido2Credentials: [],
        },
        fields: [{
          type: 1,
          name: await encUnder('recovery', testUserKey),
          value: await encUnder('keep-secret', testUserKey),
        }],
        passwordHistory: [{
          password: await encUnder('older-pass', testUserKey),
          lastUsedDate: '2026-08-28T12:00:00.000Z',
        }],
        reprompt: 0,
      };
      const sync: SyncResponse = {
        profile: { id: 'u', email: 'u@example.com' },
        ciphers: [cipher],
      };
      const updateCipher = vi.fn(async (
        _token: string,
        id: string,
        request: CipherRequest,
      ): Promise<CipherResponse> => {
        const {
          lastKnownRevisionDate: _lastKnownRevisionDate,
          attachments2: _attachments2,
          ...wire
        } = request;
        const committed: CipherResponse = {
          ...cipher,
          ...wire,
          id,
          revisionDate: '2026-08-30T12:01:00.000Z',
        };
        sync.ciphers[0] = committed;
        return committed;
      });
      const setup = await makeService(sync);
      Object.assign(setup.api, { updateCipher });
      await setup.service.sync();

      await expect(setup.service.getPasskeyTargets({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toEqual([{ id: 'c1', name: 'Existing Login', username: 'me' }]);

      const reg = await setup.service.createPasskey({
        rpId: 'example.com',
        userHandle: 'dXNlcg',
        userName: 'me',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'c1',
      });
      expect(reg.credentialId).toBeTruthy();
      const [, id, request] = updateCipher.mock.calls[0]!;
      expect(id).toBe('c1');
      expect(request.login?.fido2Credentials).toHaveLength(1);
      expect(request).toMatchObject({
        name: cipher.name,
        notes: cipher.notes,
        favorite: cipher.favorite,
        folderId: cipher.folderId,
        fields: cipher.fields,
        passwordHistory: cipher.passwordHistory,
        reprompt: cipher.reprompt,
      });
      expect(request.login).toMatchObject({
        username: cipher.login!.username,
        password: cipher.login!.password,
        totp: cipher.login!.totp,
        uris: cipher.login!.uris,
        autofillOnPageLoad: cipher.login!.autofillOnPageLoad,
        passwordRevisionDate: cipher.login!.passwordRevisionDate,
      });

      await expect(setup.service.getPasskeyTargets({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toEqual([]);
      await expect(setup.service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'c1',
      })).rejects.toMatchObject({ code: 'error', message: 'Target already contains a passkey' });
      expect(updateCipher).toHaveBeenCalledOnce();
    });

    it('encrypts the sole new credential under the selected cipher\'s own field key', async () => {
      // c2's own per-cipher key: a random 64-byte symmetric key, wrapped under the account UserKey the
      // same way a cipher's `key` field is wrapped by its owning key (decrypt.ts:
      // `cipher.key ? unwrapSymmetricKey(cipher.key, baseKey) : baseKey`). wrapAttachmentKey is just
      // `encryptToBytes(raw64Bytes, wrappingKey)` — the same generic wrap operation, reused verbatim.
      const perCipherKey = generateAttachmentKey(() => new Uint8Array(64).fill(0x42));
      const wrappedCipherKey = await wrapAttachmentKey(perCipherKey, testUserKey);
      const cipher = {
        id: 'c2', type: 1 as const, favorite: false, organizationId: null,
        key: wrappedCipherKey,
        name: await encUnder('Keyed Login', perCipherKey),
        login: {
          uris: [{ uri: await encUnder('https://example.com', perCipherKey) }],
          fido2Credentials: [],
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
      expect(req.login?.fido2Credentials).toHaveLength(1);
      const newCred = req.login!.fido2Credentials![0]!;
      // Pins cipherFieldKey: the NEW credential decrypts under the unwrapped per-cipher key...
      await expect(decryptToText(newCred.keyValue!, perCipherKey)).resolves.toMatch(/^[A-Za-z0-9_-]+$/); // base64url PKCS#8
      // ...and FAILS to decrypt under the raw account UserKey — proving the selected-target path did NOT fall
      // back to (or accidentally use) the account key, which would silently corrupt this item.
      await expect(decryptToText(newCred.keyValue!, testUserKey)).rejects.toThrow(EncStringMacError);
    });

    it('excludes a login that already has its official [0] credential and rejects a stale explicit target', async () => {
      const { service, api } = await makeServiceWithExistingPasskeyLogin({
        id: 'occupied',
        rpId: 'example.com',
      });

      await expect(service.getPasskeyTargets({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toEqual([]);
      await expect(service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'occupied',
      })).rejects.toMatchObject({ code: 'error', message: 'Target already contains a passkey' });
      expect(api.updateCipher).not.toHaveBeenCalled();
    });

    it('rolls back the mutation barrier after a definitely rejected selected-target update', async () => {
      const { service, api } = await makeServiceWithLogins([{
        id: 'empty-target',
        name: 'Empty target',
        username: 'me',
        uris: ['https://example.com/login'],
      }]);
      vi.mocked(api.sync).mockClear();
      vi.mocked(api.updateCipher).mockRejectedValueOnce(
        new ApiHttpError(400, { message: 'request rejected' }),
      );

      await expect(service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'empty-target',
      })).rejects.toMatchObject({ status: 'not_committed' });
      expect(api.updateCipher).toHaveBeenCalledOnce();
      expect(api.sync).not.toHaveBeenCalled();
      await expect(service.getPasskeyTargets({
        rpId: 'example.com',
        origin: 'https://example.com',
      })).resolves.toEqual([{ id: 'empty-target', name: 'Empty target', username: 'me' }]);
    });

    it('keeps a selected-target transport failure classified as outcome_unknown', async () => {
      const { service, api } = await makeServiceWithLogins([{
        id: 'uncertain-target',
        name: 'Uncertain target',
        uris: ['https://example.com/login'],
      }]);
      vi.mocked(api.sync).mockClear();
      vi.mocked(api.updateCipher).mockRejectedValueOnce(new TypeError('network closed'));

      await expect(service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'uncertain-target',
      })).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(api.updateCipher).toHaveBeenCalledOnce();
      const request = vi.mocked(api.updateCipher).mock.calls[0]![2];
      expect(request.login?.fido2Credentials).toHaveLength(1);
      expect(api.sync).not.toHaveBeenCalled();
    });

    it('does not publish or clear dirty when authoritative sync returns more than the one new credential', async () => {
      const setup = await makeServiceWithLogins([{
        id: 'bad-sync-target',
        name: 'Bad sync target',
        uris: ['https://example.com/login'],
      }]);
      vi.mocked(setup.api.sync).mockClear();
      const updateCipher = vi.fn(async (
        _token: string,
        id: string,
        request: CipherRequest,
      ): Promise<CipherResponse> => {
        const {
          lastKnownRevisionDate: _lastKnownRevisionDate,
          attachments2: _attachments2,
          ...wire
        } = request;
        const credential = request.login!.fido2Credentials![0]!;
        const committed: CipherResponse = {
          ...setup.sync.ciphers[0]!,
          ...wire,
          id,
          login: {
            ...request.login,
            fido2Credentials: [credential, structuredClone(credential)],
          },
        };
        setup.sync.ciphers[0] = committed;
        return committed;
      });
      Object.assign(setup.api, { updateCipher });

      const registration = await setup.service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'bad-sync-target',
      });
      expect(registration.credentialId).toBeTruthy();
      expect(updateCipher).toHaveBeenCalledOnce();
      expect(setup.api.sync).toHaveBeenCalledOnce();

      const raw = await setup.localStore.get<RawVaultEnvelope>(RAW_VAULT_CACHE_KEY);
      expect(raw?.response.ciphers[0]?.login?.fido2Credentials ?? []).toEqual([]);
      await expect(setup.service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        targetCipherId: 'bad-sync-target',
      })).rejects.toMatchObject({ code: 'committed_unsynced' });
      expect(updateCipher).toHaveBeenCalledOnce();
    });

    it('createPasskey rejects a targetCipherId that is not a same-domain personal login', async () => {
      const { service } = await makeServiceWithLogins([{ id: 'c2', name: 'Other', username: 'x', uris: ['https://other.com'] }]);
      await expect(service.createPasskey({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com', targetCipherId: 'c2' })).rejects.toThrow(/not a valid target/i);
    });

    it('createPasskey throws when locked', async () => {
      const { service } = await makeLockedService();
      await expect(service.createPasskey({ rpId: 'example.com', challenge: 'AAAA', origin: 'https://example.com' })).rejects.toThrow();
    });

    it('authoritatively re-syncs after createPasskey before clearing the mutation marker', async () => {
      const createCipher = vi.fn(async (_t: string, req: CipherRequest): Promise<CipherResponse> => ({ id: 'new1', ...req }));
      const { service, api } = await makeUnlockedService({ api: { createCipher } });
      await service.sync(); // seed VAULT_CACHE_KEY, as a real caller would have done before offering to register
      const syncCallsBefore = (api.sync as ReturnType<typeof vi.fn>).mock.calls.length;
      await service.createPasskey({ rpId: 'example.com', userHandle: 'dXNlcg', challenge: 'AAAA', origin: 'https://example.com', userVerified: true });
      expect((api.sync as ReturnType<typeof vi.fn>).mock.calls.length).toBe(syncCallsBefore + 1);
    });
  });
});

describe('VaultService WebAuthn core semantics', () => {
  it.each([
    [{}, false],
    [{ residentKey: 'discouraged' as const }, false],
    [{ residentKey: 'preferred' as const }, true],
    [{ residentKey: 'required' as const }, true],
    [{ requireResidentKey: true }, true],
    [{ residentKey: 'discouraged' as const, requireResidentKey: true }, true],
  ])('stores an accurate discoverable value for resident selection', async (selection, discoverable) => {
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const { service } = await makeUnlockedService({ api: { createCipher } });

    await service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
      ...selection,
    });

    const request = createCipher.mock.calls[0]![1];
    await expect(decryptToText(
      request.login!.fido2Credentials![0]!.discoverable!,
      testUserKey,
    )).resolves.toBe(String(discoverable));
  });

  it('stores the canonical browser origin URI including localhost ports', async () => {
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const { service } = await makeUnlockedService({ api: { createCipher } });

    await service.createPasskey({
      rpId: 'localhost',
      challenge: 'AAAA',
      origin: 'http://localhost:8443',
    });

    const request = createCipher.mock.calls[0]![1];
    await expect(decryptToText(request.login!.uris![0]!.uri!, testUserKey))
      .resolves.toBe('http://localhost:8443');
    await expect(service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'http://example.com',
    })).rejects.toMatchObject({ code: 'denied' });
    await expect(service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com/path',
    })).rejects.toMatchObject({ code: 'denied' });
    expect(createCipher).toHaveBeenCalledOnce();
  });

  it('accepts only the exact IPv4 loopback development RP over HTTP', async () => {
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const { service } = await makeUnlockedService({ api: { createCipher } });

    await service.createPasskey({
      rpId: '127.0.0.1',
      challenge: 'AAAA',
      origin: 'http://127.0.0.1:43123',
    });
    await expect(service.createPasskey({
      rpId: '127.0.0.2',
      challenge: 'AAAA',
      origin: 'http://127.0.0.2:43123',
    })).rejects.toMatchObject({ code: 'denied' });
    expect(createCipher).toHaveBeenCalledOnce();
  });

  it('sends the canonical UTC creation date required by current Bitwarden servers', async () => {
    const now = Date.parse('2026-08-30T08:09:10.123Z');
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const { service } = await makeUnlockedService({ api: { createCipher }, now: () => now });

    await service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    });

    expect(createCipher.mock.calls[0]![1].login?.fido2Credentials?.[0]?.creationDate)
      .toBe('2026-08-30T08:09:10.123Z');
  });

  it('accepts only canonical 1..64-byte user handles and never POSTs invalid values', async () => {
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const { service } = await makeUnlockedService({ api: { createCipher } });
    const handle = bytesToBase64Url(new Uint8Array(64).fill(7));

    await service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
      userHandle: handle,
    });
    const request = createCipher.mock.calls[0]![1];
    await expect(decryptToText(
      request.login!.fido2Credentials![0]!.userHandle!,
      testUserKey,
    )).resolves.toBe(handle);

    for (const invalid of [
      '',
      `${bytesToBase64Url(new Uint8Array([1]))}=`,
      bytesToBase64Url(new Uint8Array(65)),
    ]) {
      await expect(service.createPasskey({
        rpId: 'example.com',
        challenge: 'AAAA',
        origin: 'https://example.com',
        userHandle: invalid,
      })).rejects.toMatchObject({ code: 'denied' });
    }
    expect(createCipher).toHaveBeenCalledOnce();
  });

  it('returns native fallback for cross-platform requests without generating or storing a key', async () => {
    const createCipher = vi.fn();
    const generate = vi.fn(generateFido2Keypair);
    const setup = await makeServiceWithRaw(makeSync(), { generateFido2Keypair: generate });
    Object.assign(setup.api, { createCipher });

    await expect(setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
      authenticatorAttachment: 'cross-platform',
    })).rejects.toMatchObject({ code: 'no_match' });
    expect(generate).not.toHaveBeenCalled();
    expect(createCipher).not.toHaveBeenCalled();
  });

  it('zeroes the generated PKCS8 buffer after a successful committed creation', async () => {
    const generated = await generateFido2Keypair();
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const setup = await makeServiceWithRaw(makeSync(), {
      generateFido2Keypair: async () => generated,
    });
    Object.assign(setup.api, { createCipher });

    await setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    });

    expect(createCipher).toHaveBeenCalledOnce();
    expect([...generated.pkcs8].every((byte) => byte === 0)).toBe(true);
  });

  it('returns the attestation after a known commit even when authoritative reconciliation fails', async () => {
    const generated = await generateFido2Keypair();
    const createCipher = vi.fn(async (_token: string, request: CipherRequest): Promise<CipherResponse> => ({
      id: 'new1',
      ...request,
    }));
    const setup = await makeServiceWithRaw(makeSync(), {
      generateFido2Keypair: async () => generated,
    });
    Object.assign(setup.api, {
      createCipher,
      sync: vi.fn(async () => { throw new Error('reconcile unavailable'); }),
    });

    const registration = await setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    });

    expect(registration.credentialId).toBe(bytesToBase64Url(generated.credentialId));
    expect(createCipher).toHaveBeenCalledOnce();
    expect(setup.api.sync).toHaveBeenCalledOnce();
    expect([...generated.pkcs8].every((byte) => byte === 0)).toBe(true);
  });

  it('rejects an existing excludeCredential before key generation or POST', async () => {
    const excludedId = bytesToBase64Url(new TextEncoder().encode('existing-credential'));
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'existing',
        type: 1,
        name: await encUnder('Existing', testUserKey),
        login: { fido2Credentials: [await completeFido2Credential({
          credentialId: await encUnder(excludedId, testUserKey),
          keyValue: await encUnder('AAAA', testUserKey),
          rpId: await encUnder('example.com', testUserKey),
          counter: await encUnder('0', testUserKey),
        }, testUserKey)] },
      }],
    };
    const generate = vi.fn(generateFido2Keypair);
    const { service, api } = await makeService(sync, { generateFido2Keypair: generate });
    await service.sync();

    await expect(service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
      excludeCredentialIds: [excludedId, excludedId],
    })).rejects.toMatchObject({
      code: 'conflict',
      message: 'An excluded passkey already exists for this relying party',
    });
    expect(generate).not.toHaveBeenCalled();
    expect(api.createCipher).not.toHaveBeenCalled();
    expect(api.updateCipher).not.toHaveBeenCalled();
  });

  it('re-checks excludeCredentials after key generation and zeroes PKCS8 on the TOCTOU path', async () => {
    const excludedId = bytesToBase64Url(new TextEncoder().encode('raced-credential'));
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const generated = await generateFido2Keypair();
    const setup = await makeService(makeSync(), {
      generateFido2Keypair: async () => {
        markStarted();
        await gate;
        return generated;
      },
    });
    await setup.service.sync();
    const pending = setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
      excludeCredentialIds: [excludedId],
    });
    await started;

    const raw = await setup.localStore.get<{
      schemaVersion: 2;
      identity: string;
      rawGeneration: string;
      response: SyncResponse;
    }>(RAW_VAULT_CACHE_KEY);
    if (!raw) throw new Error('test cache was not initialized');
    const racedResponse = structuredClone(raw.response);
    racedResponse.ciphers.push({
      id: 'raced',
      type: 1,
      name: await encUnder('Raced', testUserKey),
      login: { fido2Credentials: [await completeFido2Credential({
        credentialId: await encUnder(excludedId, testUserKey),
        keyValue: await encUnder('AAAA', testUserKey),
        rpId: await encUnder('example.com', testUserKey),
        counter: await encUnder('0', testUserKey),
      }, testUserKey)] },
    });
    await setup.localStore.set(RAW_VAULT_CACHE_KEY, {
      ...raw,
      rawGeneration: 'exclude-race-generation',
      response: racedResponse,
    });
    release();

    await expect(pending).rejects.toMatchObject({ code: 'conflict' });
    expect(setup.api.createCipher).not.toHaveBeenCalled();
    expect([...generated.pkcs8].every((byte) => byte === 0)).toBe(true);
  });

  it('revalidates the session and policy at the final passkey request guard', async () => {
    let sessionGeneration = 0;
    const sessionGate: SessionLeaseGate = {
      capture: () => ({ generation: sessionGeneration }),
      assert: (lease) => {
        if (lease.generation !== sessionGeneration) throw new AppError('locked', 'session changed');
      },
    };
    const policyGateRef: { current?: EnterprisePolicyGate } = {};
    let race: 'session' | 'policy' = 'session';
    const setup = await makeServiceWithRaw(makeSync(), {
      sessionGate,
      beforeRequestGuard: async (method) => {
        if (method !== 'createCipher') return;
        if (race === 'session') sessionGeneration += 1;
        else policyGateRef.current?.invalidate();
      },
    });
    policyGateRef.current = setup.policyGate;

    await expect(setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    })).rejects.toMatchObject({ code: 'locked' });
    expect(setup.api.createCipher).not.toHaveBeenCalled();

    sessionGeneration += 1;
    race = 'policy';
    await expect(setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    })).rejects.toMatchObject({ code: 'denied' });
    expect(setup.api.createCipher).not.toHaveBeenCalled();
  });

  it('checks external passkey authorization at entry before key generation or remote I/O', async () => {
    const denial = new AppError('denied', 'exact external denial');
    const generate = vi.fn(generateFido2Keypair);
    const setup = await makeServiceWithRaw(makeSync(), { generateFido2Keypair: generate });

    const pending = setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    }, {
      assertAuthorized: () => { throw denial; },
    });

    await expect(pending).rejects.toBe(denial);
    expect(generate).not.toHaveBeenCalled();
    expect(setup.api.createCipher).not.toHaveBeenCalled();
  });

  it('stops deterministically when external authorization is revoked by key generation', async () => {
    const denial = new AppError('denied', 'exact post-keygen denial');
    const generated = await generateFido2Keypair();
    let authorized = true;
    const setup = await makeServiceWithRaw(makeSync(), {
      generateFido2Keypair: async () => {
        authorized = false;
        return generated;
      },
    });

    const pending = setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    }, {
      assertAuthorized: () => {
        if (!authorized) throw denial;
      },
    });

    await expect(pending).rejects.toBe(denial);
    expect(setup.api.createCipher).not.toHaveBeenCalled();
    expect([...generated.pkcs8].every((byte) => byte === 0)).toBe(true);
  });

  it('classifies an authorization failure in the final request guard as definitely not committed', async () => {
    const denial = new AppError('denied', 'exact pre-dispatch denial');
    let authorized = true;
    const setup = await makeServiceWithRaw(makeSync(), {
      beforeRequestGuard: async (method) => {
        if (method === 'createCipher') authorized = false;
      },
    });

    const pending = setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    }, {
      assertAuthorized: () => {
        if (!authorized) throw denial;
      },
    });

    await expect(pending).rejects.toBe(denial);
    expect(setup.api.createCipher).not.toHaveBeenCalled();
  });

  it('keeps a transport failure after passkey dispatch classified as outcome_unknown', async () => {
    const setup = await makeServiceWithRaw();
    const createCipher = vi.fn(async () => { throw new Error('transport failed after dispatch'); });
    Object.assign(setup.api, { createCipher });

    await expect(setup.service.createPasskey({
      rpId: 'example.com',
      challenge: 'AAAA',
      origin: 'https://example.com',
    }, {
      assertAuthorized: () => {},
    })).rejects.toMatchObject({ code: 'outcome_unknown' });
    expect(createCipher).toHaveBeenCalledOnce();
  });
});
