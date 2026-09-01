import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { createMemoryStore } from '../../platform/store.js';
import { ApiHttpError, type ApiClient } from '../api/client.js';
import type { CipherRequest, CipherResponse, SyncResponse } from '../api/types.js';
import { decryptToBytes, encryptToText, decryptToText } from '../crypto/encstring.js';
import { bytesToBase64Url, bytesToUtf8 } from '../crypto/encoding.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { AccountLeaseGate, type AccountLease } from '../session/account-gate.js';
import type { AuthService } from '../session/auth-service.js';
import { SessionManager, type SessionLeaseGate } from '../session/session-manager.js';
import { EnterprisePolicyGate, EnterprisePolicyType } from '../policy/effective-enterprise-policy.js';
import { encryptAttachmentFile, generateAttachmentKey, wrapAttachmentKey } from './attachments.js';
import { readVaultArchive } from './vault-archive.js';
import { VaultMutationCoordinator } from './vault-mutation-coordinator.js';
import { inspectVaultTransferCsv, inspectVaultTransferJson } from './vault-transfer.js';
import type { VaultTransferSourceOk } from './vault-transfer-source.js';
import { decryptEncryptedExport } from './vault-io.js';
import {
  VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES,
  VAULT_SERVICE_IMPORT_CAPABILITIES,
  VAULT_SERVICE_SSH_ARCHIVE_IMPORT_CAPABILITIES,
  VAULT_SERVICE_SSH_IMPORT_CAPABILITIES,
  VaultService,
  type PortableVaultImportJournal,
  type PortableVaultImportSettlement,
  type VaultListing,
} from './vault-service.js';

const userKey = symmetricKeyFromBytes(new Uint8Array(64).map((_, index) => index + 1));
const ORGANIZATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const MANAGED_COLLECTION_ID = 'managed-collection';
const UNMANAGED_COLLECTION_ID = 'unmanaged-collection';

interface AccountExportDocument extends Record<string, unknown> {
  encKeyValidation_DO_NOT_EDIT: string;
  items: Array<Record<string, unknown> & {
    name: string;
    login: Record<string, unknown>;
  }>;
}

function parseAccountExport(value: string): AccountExportDocument {
  return JSON.parse(value) as AccountExportDocument;
}

interface Fixture {
  service: VaultService;
  api: ApiClient;
  session: SessionManager;
  accountGate: AccountLeaseGate;
  policyGate: EnterprisePolicyGate;
  captureAuthority(): { accountLease: AccountLease; sessionLease: ReturnType<SessionLeaseGate['capture']> };
  invalidateSession(): void;
}

interface JournalFixture extends PortableVaultImportJournal {
  readonly events: string[];
  readonly settlements: PortableVaultImportSettlement[];
  readonly skipped: Array<{ kind: 'folder' | 'item'; sourceIndex: number; code: string }>;
  readonly inFlight: { operationId: string; kind: 'folder' | 'item'; sourceIndex: number } | undefined;
}

async function createFixture(
  response: SyncResponse,
  options: {
    authorizeSshCipherType5Write?: () => PromiseLike<{ assertCurrent(): void }>;
    authorizeCipherArchive?: () => PromiseLike<{ assertCurrent(): void }>;
  } = {},
): Promise<Fixture> {
  const localStore = createMemoryStore();
  const sessionStore = createMemoryStore();
  const session = new SessionManager({ localStore, sessionStore });
  await session.saveUnlocked({
    email: 'u@example.com',
    accessToken: 'access',
    refreshToken: 'refresh',
    expiresAt: Date.now() + 60_000,
    protectedKey: '2.protected',
    kdf: 0,
    kdfIterations: 5_000,
    userKey,
  });
  const api = {
    sync: vi.fn(async () => response),
    createFolder: vi.fn(async () => ({ id: 'created-folder', name: '2.created' })),
    createCipher: vi.fn(async (_token: string, request: CipherRequest) => ({
      id: 'created-item',
      ...request,
    })),
    getAttachmentDownloadUrl: vi.fn(async (_token: string, _cipherId: string, attachmentId: string) => (
      `https://files.example/${attachmentId}`
    )),
    downloadAttachment: vi.fn(async () => new Uint8Array()),
  } as unknown as ApiClient;
  Object.assign(api, {
    forServer: vi.fn(() => api),
    withRequestGuard: vi.fn((assertCurrent: () => void) => new Proxy(api, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown;
        if (typeof value !== 'function' || property === 'withRequestGuard') return value;
        return async (...args: unknown[]) => {
          assertCurrent();
          return Reflect.apply(value, target, args);
        };
      },
    })),
  });
  const accountGate = new AccountLeaseGate();
  accountGate.initialize({ serverUrl: 'https://vault.example', accountIdentity: 'u@example.com' });
  let sessionGeneration = 0;
  const sessionGate: SessionLeaseGate = {
    capture: () => ({ generation: sessionGeneration }),
    assert: (lease) => {
      if (lease.generation !== sessionGeneration) throw new Error('session changed');
    },
  };
  const policyGate = new EnterprisePolicyGate();
  const coordinator = new VaultMutationCoordinator<string, AccountLease, VaultListing, string, string>({
    captureLease: () => accountGate.capture(),
    assertLease: (_account, lease) => accountGate.assert(lease),
  });
  const service = new VaultService({
    api,
    auth: {
      refreshIfNeeded: vi.fn(async () => {}),
      executeAuthenticatedRequest: async <Result>(
        _lease: AccountLease,
        rebuildRequest: (accessToken: string) => Promise<Result>,
      ) => (
        rebuildRequest((await session.getActiveAuth())!.accessToken)
      ),
      verifyMasterPassword: vi.fn(async () => true),
    } as unknown as AuthService,
    session,
    localStore,
    sessionStore,
    getVaultIdentity: () => 'https://vault.example\nu@example.com',
    sessionGate,
    accountGate,
    policyGate,
    coordinator,
    getIdentityEpoch: () => 0,
    onSecurityStampMismatch: async () => {},
    ...(options.authorizeSshCipherType5Write
      ? { authorizeSshCipherType5Write: options.authorizeSshCipherType5Write }
      : {}),
    ...(options.authorizeCipherArchive
      ? { authorizeCipherArchive: options.authorizeCipherArchive }
      : {}),
  });
  await service.sync();
  vi.mocked(api.sync).mockClear();
  return {
    service,
    api,
    session,
    accountGate,
    policyGate,
    captureAuthority: () => ({ accountLease: accountGate.capture(), sessionLease: sessionGate.capture() }),
    invalidateSession: () => { sessionGeneration += 1; },
  };
}

function importSource(document: unknown): VaultTransferSourceOk {
  const inspection = inspectVaultTransferJson(JSON.stringify(document));
  expect(inspection.canCommit).toBe(true);
  return {
    status: 'ok',
    format: 'json',
    inspection,
    attachmentCount: 0,
    attachments: [],
    skippedAttachmentCount: 0,
  };
}

async function p256Pkcs8(): Promise<string> {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  return bytesToBase64Url(
    new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)),
  );
}

function createJournal(overrides: Partial<PortableVaultImportJournal> = {}): JournalFixture {
  const abort = new AbortController();
  const events: string[] = [];
  const settlements: PortableVaultImportSettlement[] = [];
  const skipped: Array<{ kind: 'folder' | 'item'; sourceIndex: number; code: string }> = [];
  let sequence = 0;
  let inFlight: { operationId: string; kind: 'folder' | 'item'; sourceIndex: number } | undefined;
  const journal: JournalFixture = {
    signal: abort.signal,
    events,
    settlements,
    skipped,
    get inFlight() { return inFlight; },
    assertCurrent: vi.fn(async () => {}),
    markInFlight: vi.fn(async (kind, sourceIndex) => {
      events.push(`mark:${kind}:${sourceIndex}`);
      inFlight = { operationId: `operation-${sequence++}`, kind, sourceIndex };
      return inFlight;
    }),
    settleInFlight: vi.fn(async (settlement) => {
      events.push(`settle:${settlement.status}`);
      settlements.push(settlement);
      inFlight = undefined;
    }),
    recordSkipped: vi.fn(async (kind, sourceIndex, code) => {
      events.push(`skip:${kind}:${sourceIndex}:${code}`);
      skipped.push({ kind, sourceIndex, code });
    }),
    getAlias: vi.fn(async () => undefined),
    ...overrides,
  };
  return journal;
}

async function encryptedExportSync(withAttachment = false): Promise<{
  response: SyncResponse;
  attachmentPlaintext?: Uint8Array;
  attachmentBlob?: Uint8Array;
  encryptedSecrets: string[];
}> {
  const encryptedSecrets: string[] = [];
  const enc = async (value: string): Promise<string> => {
    const encrypted = await encryptToText(value, userKey);
    encryptedSecrets.push(encrypted);
    return encrypted;
  };
  const login: CipherResponse = {
    id: 'login-1',
    type: 1,
    name: await enc('Complete login'),
    favorite: true,
    organizationId: null,
    folderId: 'folder-1',
    fields: [
      { type: 0, name: await enc('environment'), value: await enc('production') },
      { type: 1, name: await enc('recovery'), value: await enc('hidden-value') },
      { type: 2, name: await enc('enabled'), value: await enc('true') },
      { type: 3, name: await enc('linked-user'), value: null, linkedId: 100 },
    ],
    login: {
      username: await enc('alice'),
      password: await enc('secret'),
      totp: await enc('JBSWY3DPEHPK3PXP'),
      autofillOnPageLoad: false,
      passwordRevisionDate: '2026-01-02T03:04:05.1234567Z',
      uris: [{ uri: await enc('https://example.com/login'), match: 2 }],
    },
  };
  let attachmentPlaintext: Uint8Array | undefined;
  let attachmentBlob: Uint8Array | undefined;
  if (withAttachment) {
    attachmentPlaintext = new TextEncoder().encode('complete attachment bytes');
    const attachmentKey = generateAttachmentKey((length) => new Uint8Array(length).fill(9));
    attachmentBlob = await encryptAttachmentFile(
      attachmentPlaintext,
      attachmentKey,
      new Uint8Array(16).fill(3),
    );
    login.attachments = [{
      id: 'attachment-1',
      url: 'https://files.example/attachment-1',
      key: await wrapAttachmentKey(attachmentKey, userKey),
      fileName: await enc('report.txt'),
      size: String(attachmentBlob.byteLength),
      sizeName: `${attachmentBlob.byteLength} bytes`,
    }];
  }
  const response: SyncResponse = {
    profile: { id: 'u', email: 'u@example.com' },
    folders: [{ id: 'folder-1', name: await enc('Work') }],
    ciphers: [login, {
      id: 'ssh-1',
      type: 5,
      name: await enc('Deploy key'),
      favorite: false,
      organizationId: null,
      sshKey: {
        privateKey: await enc('PRIVATE KEY'),
        publicKey: await enc('ssh-ed25519 PUBLIC'),
        keyFingerprint: await enc('SHA256:fingerprint'),
      },
    }],
  };
  return {
    response,
    ...(attachmentPlaintext ? { attachmentPlaintext } : {}),
    ...(attachmentBlob ? { attachmentBlob } : {}),
    encryptedSecrets,
  };
}

async function managedOrganizationExportSync(): Promise<{
  response: SyncResponse;
  organizationKeyBytes: Uint8Array;
}> {
  const organizationKeyBytes = new Uint8Array(64).map((_, index) => 255 - index);
  const organizationKey = symmetricKeyFromBytes(organizationKeyBytes);
  const enc = (value: string) => encryptToText(value, organizationKey);
  return {
    organizationKeyBytes,
    response: {
      profile: {
        id: 'u',
        email: 'u@example.com',
        organizationsNew: [{
          id: ORGANIZATION_ID,
          key: null,
          name: 'Managed organization',
          status: 2,
          type: 2,
          enabled: true,
          usePasswordManager: true,
        }],
      },
      collections: [{
        id: MANAGED_COLLECTION_ID,
        organizationId: ORGANIZATION_ID,
        name: await enc('Managed'),
        externalId: null,
        manage: true,
      }, {
        id: UNMANAGED_COLLECTION_ID,
        organizationId: ORGANIZATION_ID,
        name: await enc('Private'),
        externalId: null,
        manage: false,
      }],
      ciphers: [{
        id: 'managed-login',
        type: 1,
        organizationId: ORGANIZATION_ID,
        collectionIds: [UNMANAGED_COLLECTION_ID, MANAGED_COLLECTION_ID],
        name: await enc('Managed login'),
        favorite: true,
        login: {
          username: await enc('managed-user'),
          password: await enc('managed-password'),
          uris: [{ uri: await enc('https://managed.example') }],
        },
      }, {
        id: 'private-login',
        type: 1,
        organizationId: ORGANIZATION_ID,
        collectionIds: [UNMANAGED_COLLECTION_ID],
        name: await enc('Private login'),
        favorite: false,
        login: { username: await enc('private-user'), uris: [] },
      }],
    },
  };
}

function mockOrganizationKeys(
  service: VaultService,
  organizationKeyBytes: Uint8Array,
): void {
  vi.spyOn(service as unknown as {
    buildOrgKeys(profile: unknown): Promise<Map<string, ReturnType<typeof symmetricKeyFromBytes>>>;
  }, 'buildOrgKeys').mockImplementation(async () => new Map([
    [ORGANIZATION_ID, symmetricKeyFromBytes(organizationKeyBytes)],
  ]));
}

function withPolicy(response: SyncResponse, type: number, data?: unknown): SyncResponse {
  return {
    ...response,
    profile: {
      ...response.profile,
      organizationsNew: [{
        id: 'policy-org', key: null, status: 2, type: 2, enabled: true, usePolicies: true,
      }],
    },
    policiesNew: [{
      id: 'policy', organizationId: 'policy-org', type, enabled: true,
      ...(data === undefined ? {} : { data }),
    }],
  };
}

describe('VaultService portable export', () => {
  it('exports complete type 1-5 plaintext fields without emitting any source EncString', async () => {
    const source = await encryptedExportSync();
    const fixture = await createFixture(source.response);

    const built = await fixture.service.buildPortableVaultExport('json');
    const text = bytesToUtf8(built.bytes);
    const document = JSON.parse(text) as { folders: unknown[]; items: Array<Record<string, unknown>> };

    expect(built.filename).toBe('miyu-vault.json');
    expect(document.folders).toEqual([{ id: 'folder-1', name: 'Work' }]);
    expect(document.items).toEqual(expect.arrayContaining([
      expect.objectContaining({
        type: 1,
        name: 'Complete login',
        fields: expect.arrayContaining([
          expect.objectContaining({ type: 1, name: 'recovery', value: 'hidden-value' }),
          expect.objectContaining({ type: 3, name: 'linked-user', linkedId: 100 }),
        ]),
        login: expect.objectContaining({
          username: 'alice',
          password: 'secret',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2026-01-02T03:04:05.1234567Z',
          uris: [{ uri: 'https://example.com/login', match: 2 }],
        }),
      }),
      expect.objectContaining({
        type: 5,
        sshKey: {
          privateKey: 'PRIVATE KEY',
          publicKey: 'ssh-ed25519 PUBLIC',
          keyFingerprint: 'SHA256:fingerprint',
        },
      }),
    ]));
    for (const encrypted of source.encryptedSecrets) expect(text).not.toContain(encrypted);
  });

  it.each([
    ['json', undefined],
    ['encrypted-json', 'export password'],
  ] as const)('exports data-only %s when attachments exist without reading attachment content', async (format, password) => {
    const source = await encryptedExportSync(true);
    const fixture = await createFixture(source.response);

    const built = await fixture.service.buildPortableVaultExport(format, password);
    const plaintext = format === 'encrypted-json'
      ? await decryptEncryptedExport(bytesToUtf8(built.bytes), password!)
      : bytesToUtf8(built.bytes);

    expect(plaintext).toContain('Complete login');
    expect(plaintext).not.toContain('attachment.txt');
    expect(plaintext).not.toContain('attachments');
    expect(fixture.api.downloadAttachment).not.toHaveBeenCalled();
  });

  it('exports passwordless CSV with a bounded review for every omitted personal data category', async () => {
    const source = await encryptedExportSync(true);
    const enc = (value: string) => encryptToText(value, userKey);
    source.response.ciphers![0]!.login!.fido2Credentials = [{
      credentialId: await enc('credential-id'),
      keyType: await enc('public-key'),
      keyAlgorithm: await enc('ECDSA'),
      keyCurve: await enc('P-256'),
      keyValue: await enc('private-passkey'),
      rpId: await enc('example.com'),
      counter: await enc('0'),
      discoverable: await enc('true'),
      creationDate: '2026-01-02T03:04:05.000Z',
    }];
    source.response.ciphers!.push(
      {
        id: 'card-1', type: 3, name: await enc('Corporate card'),
        organizationId: null, card: { number: await enc('4111111111111111') },
      },
      {
        id: 'identity-1', type: 4, name: await enc('Personal identity'),
        organizationId: null, identity: { firstName: await enc('Ada') },
      },
    );
    const fixture = await createFixture(source.response);

    await expect(fixture.service.buildPortableVaultExport('csv', 'not-allowed'))
      .rejects.toMatchObject({ code: 'error' });
    const built = await fixture.service.buildPortableVaultExport('csv');
    const text = bytesToUtf8(built.bytes);

    expect(built.filename).toBe('miyu-vault.csv');
    expect(text.startsWith('folder,favorite,type,name,notes,fields,reprompt,archivedDate,'))
      .toBe(true);
    expect(text).toContain('Complete login');
    expect(text).not.toContain('PRIVATE KEY');
    expect(text).not.toContain('4111111111111111');
    expect(text).not.toContain('private-passkey');
    expect(text).not.toContain('report.txt');
    expect(built.review).toMatchObject({ exportedItemCount: 1, omittedItemCount: 3 });
    expect(built.review?.warnings).toEqual(expect.arrayContaining([
      { code: 'card_items_omitted', count: 1 },
      { code: 'identity_items_omitted', count: 1 },
      { code: 'ssh_key_items_omitted', count: 1 },
      { code: 'attachments_omitted', count: 1 },
      { code: 'passkeys_omitted', count: 1 },
    ]));
    expect(fixture.api.downloadAttachment).not.toHaveBeenCalled();
    expect(inspectVaultTransferCsv(text).canCommit).toBe(true);
  });

  it('keeps formula escaping reversible through the production CSV builder', async () => {
    const source = await encryptedExportSync();
    const enc = (value: string) => encryptToText(value, userKey);
    source.response.folders![0]!.name = await enc('=Work');
    source.response.ciphers![0]!.name = await enc('=HYPERLINK("https://example.com")');
    source.response.ciphers![0]!.login!.username = await enc('@SUM(A1)');
    const fixture = await createFixture(source.response);

    const built = await fixture.service.buildPortableVaultExport('csv');
    const text = bytesToUtf8(built.bytes);
    expect(text).toContain('"\t=Work"');
    expect(text).toContain('"\t=HYPERLINK(""https://example.com"")"');
    const inspected = inspectVaultTransferCsv(text);
    expect(inspected.ir?.folders[0]?.name).toBe('=Work');
    expect(inspected.ir?.items[0]).toMatchObject({
      name: '=HYPERLINK("https://example.com")',
      payload: { username: '@SUM(A1)' },
    });
  });

  it('emits a valid header-only CSV and an empty review for a zero-item vault', async () => {
    const fixture = await createFixture({
      profile: { id: 'u', email: 'u@example.com' }, folders: [], ciphers: [],
    });

    const built = await fixture.service.buildPortableVaultExport('csv');

    expect(bytesToUtf8(built.bytes)).toBe(
      'folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp',
    );
    expect(built.review).toEqual({ exportedItemCount: 0, omittedItemCount: 0, warnings: [] });
  });

  it('wraps the same lossless JSON in the password-protected export format', async () => {
    const source = await encryptedExportSync();
    const fixture = await createFixture(source.response);

    const built = await fixture.service.buildPortableVaultExport('encrypted-json', 'export password');
    const plaintext = await decryptEncryptedExport(bytesToUtf8(built.bytes), 'export password');

    expect(built.filename).toBe('miyu-vault-encrypted.json');
    expect(plaintext).toContain('Complete login');
    expect(plaintext).toContain('PRIVATE KEY');
    for (const encrypted of source.encryptedSecrets) expect(plaintext).not.toContain(encrypted);
  });

  it('exports and reimports the official account-encrypted shape under one final authority', async () => {
    const source = await encryptedExportSync();
    const fixture = await createFixture(source.response);
    const authority = fixture.captureAuthority();

    const built = await fixture.service.buildPortableVaultExport(
      'encrypted-json',
      undefined,
      authority,
    );
    const text = bytesToUtf8(built.bytes);
    const document = parseAccountExport(text);
    expect(built.filename).toBe('miyu-vault-account-encrypted.json');
    expect(Object.keys(document)).toEqual([
      'encrypted', 'encKeyValidation_DO_NOT_EDIT', 'folders', 'items',
    ]);
    expect(document).not.toHaveProperty('passwordProtected');
    expect(document).not.toHaveProperty('data');
    expect(document.items[0]!.name).toBe(source.response.ciphers[0]!.name);
    expect(document.items[0]!.login.username).toBe(source.response.ciphers[0]!.login!.username);
    expect(document.items[0]!.login).not.toHaveProperty('autofillOnPageLoad');
    expect(document.items[0]!.login).not.toHaveProperty('passwordRevisionDate');
    const validation = await decryptToBytes(document.encKeyValidation_DO_NOT_EDIT, userKey);
    validation.fill(0);

    const inspected = await fixture.service.inspectPortableVaultTransferSource(
      built.bytes,
      {},
      authority,
    );
    expect(inspected.status).toBe('ok');
    if (inspected.status !== 'ok') throw new Error('Expected account-encrypted import inspection');
    expect(inspected.format).toBe('encrypted-json');
    expect(inspected.inspection.ir?.items[0]).toMatchObject({
      name: 'Complete login',
      payload: { username: 'alice', password: 'secret' },
    });
  });

  it('rejects stale export authority and hides wrong-account versus tamper during import', async () => {
    const source = await encryptedExportSync();
    const fixture = await createFixture(source.response);
    const authority = fixture.captureAuthority();
    const built = await fixture.service.buildPortableVaultExport('encrypted-json', undefined, authority);

    fixture.invalidateSession();
    await expect(fixture.service.buildPortableVaultExport('encrypted-json', undefined, authority))
      .rejects.toThrow();

    const freshAuthority = fixture.captureAuthority();
    const tampered = parseAccountExport(bytesToUtf8(built.bytes));
    tampered.items[0]!.name += 'A';
    const tamperedBytes = new TextEncoder().encode(JSON.stringify(tampered));
    const tamperedResult = await fixture.service.inspectPortableVaultTransferSource(
      tamperedBytes,
      {},
      freshAuthority,
    );
    expect(tamperedResult).toEqual({ status: 'failed', code: 'decryption_failed' });
  });

  it('zeroes the owned account private-key copy after an OrgKey lookup failure', async () => {
    const fixture = await createFixture({
      profile: { id: 'u', email: 'u@example.com', organizations: [] },
      ciphers: [],
      collections: [],
    });
    const privateKey = new Uint8Array([1, 2, 3, 4]);
    vi.spyOn(fixture.session, 'loadPrivateKey').mockResolvedValue(privateKey);
    const unrelatedOrgKey = symmetricKeyFromBytes(new Uint8Array(64).fill(7));
    const source = new TextEncoder().encode(JSON.stringify({
      encrypted: true,
      encKeyValidation_DO_NOT_EDIT: await encryptToText('validation', unrelatedOrgKey),
      collections: [],
      items: [],
    }));

    await expect(fixture.service.inspectPortableVaultTransferSource(
      source,
      {},
      fixture.captureAuthority(),
    )).resolves.toEqual({ status: 'failed', code: 'decryption_failed' });
    expect([...privateKey]).toEqual([0, 0, 0, 0]);
  });

  it('exports only the selected organization managed collections and intersecting ciphers', async () => {
    const source = await managedOrganizationExportSync();
    const fixture = await createFixture(source.response);
    mockOrganizationKeys(fixture.service, source.organizationKeyBytes);

    const built = await fixture.service.buildPortableVaultExport(
      'json',
      undefined,
      fixture.captureAuthority(),
      { kind: 'organization', organizationId: ORGANIZATION_ID.toUpperCase() },
    );
    const document = JSON.parse(bytesToUtf8(built.bytes)) as {
      collections: Array<{ id: string; organizationId: string; name: string }>;
      items: Array<{ id: string; organizationId: string; collectionIds: string[] }>;
    };

    expect(built.filename).toBe('miyu-organization-vault.json');
    expect(Object.keys(document)).toEqual(['encrypted', 'collections', 'items']);
    expect(document.collections).toEqual([{
      id: MANAGED_COLLECTION_ID,
      organizationId: ORGANIZATION_ID,
      name: 'Managed',
      externalId: null,
    }]);
    expect(document.items).toHaveLength(1);
    expect(document.items[0]).toMatchObject({
      id: 'managed-login',
      organizationId: ORGANIZATION_ID,
      collectionIds: [MANAGED_COLLECTION_ID],
      name: 'Managed login',
    });
    expect(bytesToUtf8(built.bytes)).not.toContain('Private login');

    const fileEncrypted = await fixture.service.buildPortableVaultExport(
      'encrypted-json',
      'organization-file-password',
      fixture.captureAuthority(),
      { kind: 'organization', organizationId: ORGANIZATION_ID },
    );
    const decrypted = await decryptEncryptedExport(
      bytesToUtf8(fileEncrypted.bytes),
      'organization-file-password',
    );
    expect(decrypted).toContain('Managed login');
    expect(decrypted).not.toContain('Private login');
  });

  it('uses the selected OrgKey for exact-shape organization account-encrypted export and reinspection', async () => {
    const source = await managedOrganizationExportSync();
    const fixture = await createFixture(source.response);
    mockOrganizationKeys(fixture.service, source.organizationKeyBytes);
    const authority = fixture.captureAuthority();

    const built = await fixture.service.buildPortableVaultExport(
      'encrypted-json',
      undefined,
      authority,
      { kind: 'organization', organizationId: ORGANIZATION_ID },
    );
    const document = JSON.parse(bytesToUtf8(built.bytes)) as {
      encKeyValidation_DO_NOT_EDIT: string;
      collections: Array<Record<string, unknown>>;
      items: Array<Record<string, unknown>>;
    };
    expect(Object.keys(document)).toEqual([
      'encrypted', 'encKeyValidation_DO_NOT_EDIT', 'collections', 'items',
    ]);
    expect(document.collections).toHaveLength(1);
    expect(document.items).toHaveLength(1);
    expect(document.items[0]).toMatchObject({
      id: 'managed-login',
      organizationId: ORGANIZATION_ID,
      collectionIds: [MANAGED_COLLECTION_ID],
    });
    expect(document.items[0]!.name).toBe(source.response.ciphers[0]!.name);
    const verificationKey = symmetricKeyFromBytes(source.organizationKeyBytes);
    const validation = await decryptToBytes(document.encKeyValidation_DO_NOT_EDIT, verificationKey);
    expect(validation.byteLength).toBeGreaterThan(0);
    validation.fill(0);

    const inspected = await fixture.service.inspectPortableVaultTransferSource(
      built.bytes,
      {},
      authority,
    );
    expect(inspected.status).toBe('ok');
    if (inspected.status !== 'ok') throw new Error('Expected organization account export inspection');
    expect(inspected.inspection.ir).toMatchObject({
      scope: 'organization',
      collections: [{ id: MANAGED_COLLECTION_ID, organizationId: ORGANIZATION_ID }],
      items: [{ id: 'managed-login', organizationId: ORGANIZATION_ID }],
    });
  });

  it('emits official organization CSV and refuses ZIP or organizations without managed collections', async () => {
    const source = await managedOrganizationExportSync();
    const fixture = await createFixture(source.response);
    mockOrganizationKeys(fixture.service, source.organizationKeyBytes);
    const target = { kind: 'organization', organizationId: ORGANIZATION_ID } as const;

    const csv = await fixture.service.buildPortableVaultExport(
      'csv',
      undefined,
      fixture.captureAuthority(),
      target,
    );
    expect(bytesToUtf8(csv.bytes).startsWith(
      'collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp',
    )).toBe(true);
    expect(bytesToUtf8(csv.bytes)).toContain('Managed login');
    expect(bytesToUtf8(csv.bytes)).not.toContain('Private login');
    expect(csv.review?.warnings).toContainEqual({ code: 'unknown_data_omitted', count: 1 });

    await expect(fixture.service.buildPortableVaultExport(
      'zip',
      undefined,
      fixture.captureAuthority(),
      target,
    )).rejects.toMatchObject({ code: 'denied' });

    source.response.collections![0]!.manage = false;
    const unavailable = await createFixture(source.response);
    mockOrganizationKeys(unavailable.service, source.organizationKeyBytes);
    await expect(unavailable.service.buildPortableVaultExport(
      'json',
      undefined,
      unavailable.captureAuthority(),
      target,
    )).rejects.toMatchObject({ code: 'denied' });
  });

  it('rejects an organization export when its account-session authority changes during key loading', async () => {
    const source = await managedOrganizationExportSync();
    const fixture = await createFixture(source.response);
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const buildOrgKeys = vi.spyOn(fixture.service as unknown as {
      buildOrgKeys(profile: unknown): Promise<Map<string, ReturnType<typeof symmetricKeyFromBytes>>>;
    }, 'buildOrgKeys').mockImplementation(async () => {
      await blocked;
      return new Map([
        [ORGANIZATION_ID, symmetricKeyFromBytes(source.organizationKeyBytes)],
      ]);
    });

    const exporting = fixture.service.buildPortableVaultExport(
      'json',
      undefined,
      fixture.captureAuthority(),
      { kind: 'organization', organizationId: ORGANIZATION_ID },
    );
    await vi.waitFor(() => expect(buildOrgKeys).toHaveBeenCalledOnce());
    fixture.invalidateSession();
    release();

    await expect(exporting).rejects.toThrow();
  });

  it('downloads, decrypts, validates, and archives every attachment with a stable manifest mapping', async () => {
    const source = await encryptedExportSync(true);
    delete source.response.ciphers[0]!.attachments![0]!.url;
    const fixture = await createFixture(source.response);
    vi.mocked(fixture.api.getAttachmentDownloadUrl)
      .mockResolvedValue('https://fresh-files.example/attachment-1?signature=current');
    vi.mocked(fixture.api.downloadAttachment).mockResolvedValue(source.attachmentBlob!.slice());

    const built = await fixture.service.buildPortableVaultExport('zip');
    const archive = readVaultArchive(built.bytes);

    expect(built.filename).toBe('miyu-vault.zip');
    expect(fixture.api.getAttachmentDownloadUrl).toHaveBeenCalledWith(
      'access',
      'login-1',
      'attachment-1',
    );
    expect(fixture.api.downloadAttachment).toHaveBeenCalledWith(
      'https://fresh-files.example/attachment-1?signature=current',
      'access',
      source.attachmentBlob!.byteLength,
    );
    expect(archive.ok).toBe(true);
    expect(archive.attachments).toHaveLength(1);
    expect(archive.attachments[0]).toMatchObject({
      itemToken: 'login-1',
      attachmentId: 'attachment-1',
    });
    expect([...archive.attachments[0]!.data]).toEqual([...source.attachmentPlaintext!]);
    expect(archive.manifest?.attachments).toEqual([expect.objectContaining({
      itemToken: 'login-1',
      attachmentId: 'attachment-1',
    })]);
    const dataJson = bytesToUtf8(archive.dataJson!);
    expect(dataJson).toContain('Complete login');
    for (const encrypted of source.encryptedSecrets) expect(dataJson).not.toContain(encrypted);
  });

  it('falls back to the cached attachment URL for ZIP export only on a fresh-URL 404', async () => {
    const source = await encryptedExportSync(true);
    const fixture = await createFixture(source.response);
    vi.mocked(fixture.api.getAttachmentDownloadUrl)
      .mockRejectedValue(new ApiHttpError(404, { message: 'unsupported' }));
    vi.mocked(fixture.api.downloadAttachment).mockResolvedValue(source.attachmentBlob!.slice());

    const built = await fixture.service.buildPortableVaultExport('zip');
    const archive = readVaultArchive(built.bytes);

    expect(archive.ok).toBe(true);
    expect(fixture.api.downloadAttachment).toHaveBeenCalledWith(
      'https://files.example/attachment-1',
      'access',
      source.attachmentBlob!.byteLength,
    );
  });

  it('rejects an unknown personal item type as an all-or-nothing export failure', async () => {
    const fixture = await createFixture({
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{
        id: 'future', type: 99, name: '2.opaque', organizationId: null,
        futurePayload: { secret: '2.future-secret' },
      }],
    });

    for (const format of ['json', 'csv'] as const) {
      await expect(fixture.service.buildPortableVaultExport(format))
        .rejects.toMatchObject({ code: 'denied' });
    }
  });
});

describe('VaultService portable import', () => {
  it('reports advanced import capabilities only for current dynamic authorizations', async () => {
    const base = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    expect(await base.service.getPortableVaultImportCapabilities())
      .toBe(VAULT_SERVICE_IMPORT_CAPABILITIES);

    const archiveOnly = await createFixture(
      { profile: { id: 'u', email: 'u@example.com', premium: true }, ciphers: [] },
      { authorizeCipherArchive: async () => ({ assertCurrent() {} }) },
    );
    expect(await archiveOnly.service.getPortableVaultImportCapabilities())
      .toBe(VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES);

    const both = await createFixture(
      { profile: { id: 'u', email: 'u@example.com', premium: true }, ciphers: [] },
      {
        authorizeCipherArchive: async () => ({ assertCurrent() {} }),
        authorizeSshCipherType5Write: async () => ({ assertCurrent() {} }),
      },
    );
    expect(await both.service.getPortableVaultImportCapabilities())
      .toBe(VAULT_SERVICE_SSH_ARCHIVE_IMPORT_CAPABILITIES);
  });

  it('preserves folder mapping, custom fields, linked fields, and per-URI match values', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [{ id: 'source-folder', name: 'Imported folder' }],
      items: [{
        type: 1,
        name: 'Imported login',
        folderId: 'source-folder',
        reprompt: 1,
        creationDate: '2025-01-01T00:00:00.000Z',
        revisionDate: '2025-02-01T00:00:00.000Z',
        deletedDate: null,
        archivedDate: null,
        fields: [
          { type: 0, name: 'environment', value: 'production' },
          { type: 1, name: 'hidden', value: 'secret-field' },
          { type: 2, name: 'enabled', value: 'true' },
          { type: 3, name: 'linked-user', value: null, linkedId: 100 },
        ],
        login: {
          username: 'alice',
          password: 'password',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2025-01-15T00:00:00.1234567Z',
          uris: [{ uri: 'https://example.com/login', match: 3 }],
        },
      }],
    });

    expect(VAULT_SERVICE_IMPORT_CAPABILITIES.autofillOnPageLoad).toBe(true);
    expect(VAULT_SERVICE_IMPORT_CAPABILITIES.passwordHistory).toBe(true);
    expect(VAULT_SERVICE_IMPORT_CAPABILITIES.passkeys).toBe(true);
    expect(VAULT_SERVICE_IMPORT_CAPABILITIES.itemDates).toBe(false);
    expect(source.inspection.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'warning', code: 'server_managed_dates_dropped', sourceIndex: 0,
    }));

    await fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    });

    expect(fixture.api.createFolder).toHaveBeenCalledOnce();
    const request = vi.mocked(fixture.api.createCipher).mock.calls[0]![1];
    expect(request.folderId).toBe('created-folder');
    expect(request.reprompt).toBe(1);
    expect(request.login).toHaveProperty('autofillOnPageLoad', false);
    expect(request.login).toHaveProperty('passwordRevisionDate', '2025-01-15T00:00:00.1234567Z');
    expect(request.login?.uris?.[0]?.match).toBe(3);
    expect(request).not.toHaveProperty('creationDate');
    expect(request).not.toHaveProperty('revisionDate');
    expect(request).not.toHaveProperty('deletedDate');
    expect(request).not.toHaveProperty('archivedDate');
    expect(await decryptToText(request.login!.uris![0]!.uri!, userKey)).toBe('https://example.com/login');
    expect(await Promise.all(request.fields!.map(async (field) => ({
      type: field.type,
      name: field.name ? await decryptToText(field.name, userKey) : null,
      value: field.value ? await decryptToText(field.value, userKey) : null,
      linkedId: field.linkedId,
    })))).toEqual([
      { type: 0, name: 'environment', value: 'production', linkedId: undefined },
      { type: 1, name: 'hidden', value: 'secret-field', linkedId: undefined },
      { type: 2, name: 'enabled', value: 'true', linkedId: undefined },
      { type: 3, name: 'linked-user', value: null, linkedId: 100 },
    ]);
    expect(journal.settlements.map((entry) => entry.status)).toEqual(['committed', 'committed']);
    expect(fixture.api.sync).toHaveBeenCalledOnce();
  });

  it('atomically preserves password history, passkeys, login metadata, and archived state', async () => {
    const assertArchiveCurrent = vi.fn();
    const fixture = await createFixture(
      { profile: { id: 'u', email: 'u@example.com', premium: true }, ciphers: [] },
      { authorizeCipherArchive: async () => ({ assertCurrent: assertArchiveCurrent }) },
    );
    const journal = createJournal();
    const privateKey = await p256Pkcs8();
    const source = importSource({
      encrypted: false,
      folders: [{ id: 'source-folder', name: 'Archived' }],
      items: [{
        type: 1,
        name: 'Passkey login',
        folderId: 'source-folder',
        creationDate: '2024-01-01T00:00:00Z',
        revisionDate: '2024-02-01T00:00:00Z',
        archivedDate: '2025-03-04T05:06:07.1234567Z',
        passwordHistory: [
          { password: 'old-password-one', lastUsedDate: '2023-01-01T00:00:00Z' },
          { password: 'old-password-two', lastUsedDate: null },
        ],
        login: {
          username: 'alice',
          password: 'current-password',
          passwordRevisionDate: '2025-02-03T04:05:06.7654321Z',
          uris: [{ uri: 'https://example.com', match: 0 }],
          fido2Credentials: [{
            credentialId: 'AQIDBA',
            keyType: 'public-key',
            keyAlgorithm: 'ECDSA',
            keyCurve: 'P-256',
            keyValue: privateKey,
            rpId: 'example.com',
            counter: '4294967295',
            discoverable: 'true',
            userHandle: 'BQYH',
            userName: 'alice@example.com',
            rpName: 'Example',
            userDisplayName: 'Alice',
            creationDate: '2025-01-02T03:04:05.1234567Z',
          }],
        },
      }],
    });

    await expect(fixture.service.validatePortableVaultImportSource(
      source,
      VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES,
    )).resolves.toBe(true);

    await fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES,
      journal,
    });

    const request = vi.mocked(fixture.api.createCipher).mock.calls[0]![1];
    expect(request.folderId).toBe('created-folder');
    expect(request.archivedDate).toBe('2025-03-04T05:06:07.1234567Z');
    expect(request.login?.passwordRevisionDate).toBe('2025-02-03T04:05:06.7654321Z');
    expect(request).not.toHaveProperty('creationDate');
    expect(request).not.toHaveProperty('revisionDate');
    expect(request).not.toHaveProperty('deletedDate');
    expect(await Promise.all(request.passwordHistory!.map((entry) => (
      decryptToText(entry.password!, userKey)
    )))).toEqual(['old-password-one', 'old-password-two']);
    expect(request.passwordHistory!.map((entry) => entry.lastUsedDate))
      .toEqual(['2023-01-01T00:00:00Z', null]);
    const passkey = request.login!.fido2Credentials![0]!;
    expect(await decryptToText(passkey.credentialId!, userKey)).toBe('AQIDBA');
    expect(await decryptToText(passkey.keyValue!, userKey)).toBe(privateKey);
    expect(await decryptToText(passkey.rpId!, userKey)).toBe('example.com');
    expect(await decryptToText(passkey.counter!, userKey)).toBe('4294967295');
    expect(await decryptToText(passkey.discoverable!, userKey)).toBe('true');
    expect(passkey.creationDate).toBe('2025-01-02T03:04:05.1234567Z');
    const serialized = JSON.stringify(request);
    expect(serialized).not.toContain('old-password-one');
    expect(serialized).not.toContain(privateKey);
    expect(assertArchiveCurrent.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(journal.settlements.map((entry) => entry.status)).toEqual(['committed', 'committed']);
  });

  it('validates every advanced item before creating folders, WAL entries, or ciphers', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [{ id: 'source-folder', name: 'Must not exist' }],
      items: [
        { type: 2, name: 'Valid first item', secureNote: { type: 0 } },
        {
          type: 1,
          name: 'Invalid later passkey',
          login: {
            uris: [],
            fido2Credentials: [{
              credentialId: 'AQIDBA',
              keyType: 'public-key',
              keyAlgorithm: 'ECDSA',
              keyCurve: 'P-256',
              keyValue: 'AQ',
              rpId: 'example.com',
              counter: '0',
              discoverable: 'false',
              creationDate: '2025-01-02T03:04:05Z',
            }],
          },
        },
      ],
    });

    await expect(fixture.service.validatePortableVaultImportSource(
      source,
      VAULT_SERVICE_IMPORT_CAPABILITIES,
    )).resolves.toBe(false);

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'denied' });

    expect(fixture.api.createFolder).not.toHaveBeenCalled();
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
    expect(journal.markInFlight).not.toHaveBeenCalled();
    expect(JSON.stringify(journal)).not.toContain('AQIDBA');
  });

  it.each(['passwordHistory', 'passkeys', 'passwordRevisionDate', 'archivedDate'] as const)(
    'treats a 2xx receipt that drops %s as outcome_unknown',
    async (droppedField) => {
      const fixture = await createFixture(
        { profile: { id: 'u', email: 'u@example.com', premium: true }, ciphers: [] },
        { authorizeCipherArchive: async () => ({ assertCurrent() {} }) },
      );
      vi.mocked(fixture.api.createCipher).mockImplementation(async (_token, request) => {
        const response: CipherResponse = { id: 'created-item', ...request };
        if (droppedField === 'passwordHistory') return { ...response, passwordHistory: [] };
        if (droppedField === 'passkeys') {
          return { ...response, login: { ...response.login, fido2Credentials: [] } };
        }
        if (droppedField === 'passwordRevisionDate') {
          return { ...response, login: { ...response.login, passwordRevisionDate: null } };
        }
        return { ...response, archivedDate: null };
      });
      const journal = createJournal();
      const source = importSource({
        encrypted: false,
        folders: [],
        items: [{
          type: 1,
          name: 'Advanced login',
          archivedDate: '2025-03-04T05:06:07Z',
          passwordHistory: [{ password: 'old-password', lastUsedDate: '2024-01-01T00:00:00Z' }],
          login: {
            passwordRevisionDate: '2025-02-03T04:05:06Z',
            uris: [],
            fido2Credentials: [{
              credentialId: 'AQIDBA',
              keyType: 'public-key',
              keyAlgorithm: 'ECDSA',
              keyCurve: 'P-256',
              keyValue: await p256Pkcs8(),
              rpId: 'example.com',
              counter: '0',
              discoverable: 'false',
              creationDate: '2025-01-02T03:04:05Z',
            }],
          },
        }],
      });

      await expect(fixture.service.commitPortableVaultImport({
        source,
        capabilities: VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES,
        journal,
      })).rejects.toMatchObject({ code: 'outcome_unknown' });
      expect(journal.settlements).toEqual([{
        operationId: 'operation-0', status: 'outcome_unknown', code: 'invalid_commit_receipt',
      }]);
      expect(fixture.api.sync).not.toHaveBeenCalled();
    },
  );

  it('imports a complete type-5 item only under the dynamic SSH capability policy', async () => {
    const assertCurrent = vi.fn();
    const fixture = await createFixture(
      { profile: { id: 'u', email: 'u@example.com' }, ciphers: [] },
      { authorizeSshCipherType5Write: async () => ({ assertCurrent }) },
    );
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{
        type: 5,
        name: 'Imported SSH key',
        notes: 'Deploy access',
        fields: [{ type: 0, name: 'environment', value: 'production' }],
        sshKey: {
          privateKey: 'PRIVATE KEY',
          publicKey: 'ssh-ed25519 PUBLIC',
          keyFingerprint: 'SHA256:fingerprint',
        },
      }],
    });

    await fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_SSH_IMPORT_CAPABILITIES,
      journal,
    });

    const request = vi.mocked(fixture.api.createCipher).mock.calls[0]![1];
    expect(request.type).toBe(5);
    expect(await decryptToText(request.name, userKey)).toBe('Imported SSH key');
    expect(await decryptToText(request.sshKey!.privateKey, userKey)).toBe('PRIVATE KEY');
    expect(await decryptToText(request.sshKey!.publicKey, userKey)).toBe('ssh-ed25519 PUBLIC');
    expect(await decryptToText(request.sshKey!.keyFingerprint, userKey)).toBe('SHA256:fingerprint');
    expect(await decryptToText(request.fields![0]!.value!, userKey)).toBe('production');
    expect(assertCurrent.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(journal.settlements).toEqual([{
      operationId: 'operation-0', status: 'committed',
    }]);
  });

  it('rejects type-5 import before WAL when current SSH capability authorization is unavailable', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{
        type: 5,
        name: 'Blocked SSH key',
        sshKey: {
          privateKey: 'PRIVATE KEY',
          publicKey: 'ssh-ed25519 PUBLIC',
          keyFingerprint: 'SHA256:fingerprint',
        },
      }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_SSH_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(journal.markInFlight).not.toHaveBeenCalled();
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
  });

  it('settles and aborts a type-5 import when capability is revoked after WAL but before fetch', async () => {
    let current = true;
    const fixture = await createFixture(
      { profile: { id: 'u', email: 'u@example.com' }, ciphers: [] },
      {
        authorizeSshCipherType5Write: async () => ({
          assertCurrent() {
            if (!current) throw new Error('capability changed');
          },
        }),
      },
    );
    const baseJournal = createJournal();
    const journal = createJournal({
      markInFlight: vi.fn(async (kind, sourceIndex) => {
        current = false;
        return baseJournal.markInFlight(kind, sourceIndex);
      }),
      settleInFlight: baseJournal.settleInFlight,
    });
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{
        type: 5,
        name: 'Revoked SSH key',
        sshKey: {
          privateKey: 'PRIVATE KEY',
          publicKey: 'ssh-ed25519 PUBLIC',
          keyFingerprint: 'SHA256:fingerprint',
        },
      }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_SSH_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
    expect(baseJournal.settlements).toEqual([{
      operationId: 'operation-0', status: 'rejected', code: 'capability_blocked',
    }]);
  });

  it('settles an archived import as rejected when archive authorization changes after WAL', async () => {
    let current = true;
    const fixture = await createFixture(
      { profile: { id: 'u', email: 'u@example.com', premium: true }, ciphers: [] },
      {
        authorizeCipherArchive: async () => ({
          assertCurrent() {
            if (!current) throw new Error('capability changed');
          },
        }),
      },
    );
    const baseJournal = createJournal();
    const journal = createJournal({
      markInFlight: vi.fn(async (kind, sourceIndex) => {
        current = false;
        return baseJournal.markInFlight(kind, sourceIndex);
      }),
      settleInFlight: baseJournal.settleInFlight,
    });
    const source = importSource({
      encrypted: false,
      folders: [{ id: 'source-folder', name: 'Must not exist' }],
      items: [{
        type: 2,
        name: 'Archived note',
        folderId: 'source-folder',
        archivedDate: '2025-01-02T03:04:05Z',
        secureNote: { type: 0 },
      }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(fixture.api.createFolder).not.toHaveBeenCalled();
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
    expect(baseJournal.settlements).toEqual([{
      operationId: 'operation-0', status: 'rejected', code: 'capability_blocked',
    }]);
  });

  it('durably rejects a definite 4xx and continues later items with one final sync', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    vi.mocked(fixture.api.createCipher)
      .mockRejectedValueOnce(new ApiHttpError(400, { message: 'SERVER SECRET BODY' }))
      .mockResolvedValue({ id: 'created', type: 2, name: '2.created' });
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [
        { type: 2, name: 'Rejected', secureNote: { type: 0 } },
        { type: 2, name: 'Committed', secureNote: { type: 0 } },
      ],
    });

    await fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    });

    expect(fixture.api.createCipher).toHaveBeenCalledTimes(2);
    expect(journal.settlements).toEqual([
      { operationId: 'operation-0', status: 'rejected', code: 'remote_rejected' },
      { operationId: 'operation-1', status: 'committed' },
    ]);
    expect(JSON.stringify(journal.settlements)).not.toContain('SERVER SECRET BODY');
    expect(fixture.api.sync).toHaveBeenCalledOnce();
  });

  it('settles a network failure as outcome_unknown and never sends a later POST', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    vi.mocked(fixture.api.createCipher).mockRejectedValueOnce(new Error('network disconnected'));
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [
        { type: 2, name: 'Unknown', secureNote: { type: 0 } },
        { type: 2, name: 'Must not post', secureNote: { type: 0 } },
      ],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'outcome_unknown' });

    expect(fixture.api.createCipher).toHaveBeenCalledOnce();
    expect(journal.settlements).toEqual([{
      operationId: 'operation-0', status: 'outcome_unknown', code: 'remote_outcome_unknown',
    }]);
    expect(fixture.api.sync).not.toHaveBeenCalled();
  });

  it('does not POST when the write-ahead marker cannot be persisted', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal({
      markInFlight: vi.fn(async () => { throw new Error('journal storage failed'); }),
    });
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'No POST', secureNote: { type: 0 } }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toThrow(/journal storage failed/i);
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
  });

  it('leaves an in-flight marker when committed settlement fails', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal({
      settleInFlight: vi.fn(async () => { throw new Error('journal settlement failed'); }),
    });
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'Committed remotely', secureNote: { type: 0 } }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'committed_unsynced' });
    expect(fixture.api.createCipher).toHaveBeenCalledOnce();
    expect(journal.inFlight).toMatchObject({ kind: 'item', sourceIndex: 0 });
    expect(fixture.api.sync).not.toHaveBeenCalled();
  });

  it.each([
    ['account', (fixture: Fixture) => { fixture.accountGate.beginAccountTransition(); }],
    ['session', (fixture: Fixture) => { fixture.invalidateSession(); }],
    ['policy', (fixture: Fixture) => { fixture.policyGate.invalidate(); }],
    ['cache', async (fixture: Fixture) => { await fixture.service.clearCache(); }],
  ])('stops before POST when the %s lease changes after WAL', async (_name, invalidate) => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal({
      markInFlight: vi.fn(async (kind, sourceIndex) => {
        await invalidate(fixture);
        return { operationId: `changed-${kind}-${sourceIndex}` };
      }),
    });
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'Must not post', secureNote: { type: 0 } }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toBeDefined();
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
  });

  it('rejects capabilities that differ from the production writer before remote I/O', async () => {
    const fixture = await createFixture({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'Unsupported claim', secureNote: { type: 0 } }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: { ...VAULT_SERVICE_IMPORT_CAPABILITIES, passkeys: false },
      journal,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
    expect(journal.markInFlight).not.toHaveBeenCalled();
  });

  it.each([
    [EnterprisePolicyType.OrganizationDataOwnership, undefined],
    [EnterprisePolicyType.RestrictedItemTypes, [1]],
  ])('enforces enterprise create policy %s before any import WAL or POST', async (policyType, data) => {
    const response = withPolicy(
      { profile: { id: 'u', email: 'u@example.com' }, ciphers: [] },
      policyType,
      data,
    );
    const fixture = await createFixture(response);
    const journal = createJournal();
    const source = importSource({
      encrypted: false,
      folders: [],
      items: [{ type: 1, name: 'Blocked login', login: { uris: [] } }],
    });

    await expect(fixture.service.commitPortableVaultImport({
      source,
      capabilities: VAULT_SERVICE_IMPORT_CAPABILITIES,
      journal,
    })).rejects.toMatchObject({ code: 'denied' });
    expect(journal.markInFlight).not.toHaveBeenCalled();
    expect(fixture.api.createCipher).not.toHaveBeenCalled();
  });
});
