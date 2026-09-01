// @vitest-environment node
// Live production transfer test. It is hard-bound to the authorized test-env SSH tunnel.
// Run: $env:LIVE='1'; $env:MIYU_SERVER='http://127.0.0.1:18082'; npm run test:live -- test/live/transfer.live.test.ts
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { ApiClient, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import { normalizeServerUrl } from '../../src/background/settings.js';
import { SessionGate } from '../../src/background/session-gate.js';
import {
  createVaultTransferLeaseBindings,
  type VaultTransferAccountSessionLeases,
} from '../../src/background/vault-transfer-lifecycle.js';
import { VaultTransferController } from '../../src/background/vault-transfer-controller.js';
import { AccountLeaseGate, type AccountLease } from '../../src/core/session/account-gate.js';
import { SessionManager, type SessionLease } from '../../src/core/session/session-manager.js';
import { EnterprisePolicyGate, type PolicyLease } from '../../src/core/policy/effective-enterprise-policy.js';
import {
  deriveMasterKey,
  deriveMasterPasswordHash,
  parseKdfConfig,
  stretchMasterKey,
} from '../../src/core/crypto/kdf.js';
import { decryptPrivateKey, unwrapSymmetricKey, type SymmetricKey } from '../../src/core/crypto/keys.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { encryptToText } from '../../src/core/crypto/encstring.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import { decryptCipher, decryptFolders } from '../../src/core/vault/decrypt.js';
import type { DecryptedCipher } from '../../src/core/vault/models.js';
import { readVaultArchive } from '../../src/core/vault/vault-archive.js';
import { VaultMutationCoordinator } from '../../src/core/vault/vault-mutation-coordinator.js';
import { VaultTransferSessionManager } from '../../src/core/vault/vault-transfer-session.js';
import { VaultTransferJournalStore } from '../../src/core/vault/vault-transfer-journal.js';
import {
  VAULT_SERVICE_IMPORT_CAPABILITIES,
  VaultService,
  type VaultListing,
} from '../../src/core/vault/vault-service.js';
import { createMemoryStore } from '../../src/platform/store.js';

const LIVE = process.env.LIVE === '1';
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const SERVER = normalizeServerUrl(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER);

if (LIVE && SERVER !== AUTHORIZED_SERVER) {
  throw new Error(`transfer live test is restricted to ${AUTHORIZED_SERVER}`);
}

interface TransferFixture {
  readonly service: VaultService;
  readonly authorizeExport: (format: 'json' | 'encrypted-json' | 'zip') => string;
  readonly controller: VaultTransferController<
    AccountLease,
    SessionLease,
    PolicyLease,
    AccountLease,
    VaultTransferAccountSessionLeases<AccountLease, SessionLease>,
    VaultTransferAccountSessionLeases<AccountLease, SessionLease>
  >;
}

interface SeedMarkers {
  readonly folder: string;
  readonly login: string;
  readonly note: string;
  readonly card: string;
  readonly identity: string;
}

async function requestRegistrationToken(email: string): Promise<string | undefined> {
  const response = await fetch(`${SERVER}identity/accounts/register/send-verification-email`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ email, name: 'Transfer Live Test' }),
  });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`registration start failed with status ${response.status}`);
  const text = await response.text();
  if (!text.trim()) return undefined;
  let token: unknown;
  try {
    token = JSON.parse(text) as unknown;
  } catch {
    token = text.trim();
  }
  if (typeof token !== 'string'
    || token.length === 0
    || token.length > 16_384
    || [...token].some((character) => {
      const code = character.charCodeAt(0);
      return code <= 0x1f || code === 0x7f;
    })) {
    throw new Error('registration start returned an invalid token');
  }
  return token;
}

async function deleteAccount(accessToken: string, masterPasswordHash: string): Promise<void> {
  const response = await fetch(`${SERVER}api/accounts`, {
    method: 'DELETE',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!response.ok) throw new Error(`account cleanup failed with status ${response.status}`);
}

function clearKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}

async function seedVault(
  api: ApiClient,
  accessToken: string,
  userKey: SymmetricKey,
  markers: SeedMarkers,
): Promise<void> {
  const folder = await api.createFolder(accessToken, await encryptToText(markers.folder, userKey));
  const inputs = [
    {
      type: 1 as const,
      name: markers.login,
      notes: 'login notes',
      favorite: true,
      reprompt: true,
      folderId: folder.id,
      login: {
        username: 'transfer-user@example.com',
        password: 'Transfer-Login-Pass-1!',
        totp: 'JBSWY3DPEHPK3PXP',
        autofillOnPageLoad: false,
        passwordRevisionDate: '2026-08-01T00:00:00.000Z',
        uris: [{ uri: 'https://transfer.example.com/login', match: 2 }],
      },
      fields: [
        { type: 0 as const, name: 'environment', value: 'test' },
        { type: 1 as const, name: 'recovery', value: 'hidden-value' },
        { type: 2 as const, name: 'enabled', value: 'true' },
        { type: 3 as const, name: 'linked-username', linkedId: 100 },
      ],
    },
    {
      type: 2 as const,
      name: markers.note,
      notes: 'secure note body',
      folderId: folder.id,
    },
    {
      type: 3 as const,
      name: markers.card,
      notes: 'card notes',
      folderId: folder.id,
      card: {
        cardholderName: 'Transfer Holder',
        brand: 'Visa',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2031',
        code: '123',
      },
    },
    {
      type: 4 as const,
      name: markers.identity,
      notes: 'identity notes',
      folderId: folder.id,
      identity: {
        title: 'Mx',
        firstName: 'Transfer',
        middleName: 'Live',
        lastName: 'Tester',
        address1: '1 Integration Way',
        city: 'Test City',
        state: 'CA',
        postalCode: '94105',
        country: 'US',
        company: 'MiYu Test',
        email: 'identity@example.com',
        phone: '+1-555-0100',
        ssn: '000-00-0000',
        username: 'identity-user',
        passportNumber: 'TEST-PASSPORT',
        licenseNumber: 'TEST-LICENSE',
      },
    },
  ];

  for (const input of inputs) {
    await api.createCipher(accessToken, await encryptCipher(input, userKey));
  }
}

function buildTransferFixture(input: {
  api: ApiClient;
  session: SessionManager;
  accountGate: AccountLeaseGate;
  sessionGate: SessionGate;
  policyGate: EnterprisePolicyGate;
  localStore: ReturnType<typeof createMemoryStore>;
  sessionStore: ReturnType<typeof createMemoryStore>;
  accountKey: string;
}): TransferFixture {
  const coordinator = new VaultMutationCoordinator<
    string,
    AccountLease,
    VaultListing,
    string,
    string
  >({
    captureLease: (account) => {
      const lease = input.accountGate.capture();
      if (`${lease.serverUrl}\n${lease.accountIdentity}` !== account) {
        throw new Error('coordinator account mismatch');
      }
      return lease;
    },
    assertLease: (account, lease) => {
      input.accountGate.assert(lease);
      if (`${lease.serverUrl}\n${lease.accountIdentity}` !== account) {
        throw new Error('coordinator account changed');
      }
    },
  });
  const service = new VaultService({
    api: input.api,
    auth: {
      refreshIfNeeded: async () => {},
      executeAuthenticatedRequest: async (_lease, rebuildRequest) => (
        rebuildRequest((await input.session.getActiveAuth())!.accessToken)
      ),
      verifyMasterPassword: async () => false,
    },
    session: input.session,
    localStore: input.localStore,
    sessionStore: input.sessionStore,
    getVaultIdentity: () => input.accountKey,
    sessionGate: input.sessionGate,
    accountGate: input.accountGate,
    policyGate: input.policyGate,
    coordinator,
    getIdentityEpoch: () => 0,
    onSecurityStampMismatch: async () => {},
  });
  const leases = createVaultTransferLeaseBindings(
    input.accountGate,
    input.sessionGate,
    input.policyGate,
  );
  const sessions = new VaultTransferSessionManager<AccountLease, SessionLease, PolicyLease>({
    captureLeases: leases.captureSecurity,
    assertLeasesCurrent: leases.assertSecurity,
  });
  const journal = new VaultTransferJournalStore(input.localStore);
  const exportAuthorizations = new Map<string, 'json' | 'encrypted-json' | 'zip'>();
  const controller = new VaultTransferController({
    sessions,
    journal,
    getImportCapabilities: () => VAULT_SERVICE_IMPORT_CAPABILITIES,
    captureAccountIdentity: () => {
      const lease = input.accountGate.capture();
      return Object.freeze({
        canonicalIdentity: `${lease.serverUrl}\n${lease.accountIdentity}`,
        lease,
      });
    },
    assertAccountIdentityCurrent: (snapshot) => {
      input.accountGate.assert(snapshot.lease);
      return snapshot.canonicalIdentity
        === `${snapshot.lease.serverUrl}\n${snapshot.lease.accountIdentity}`;
    },
    captureTransferLeases: leases.captureAccountSession,
    assertTransferLeasesCurrent: leases.assertAccountSession,
    captureReconcileLeases: leases.captureAccountSession,
    assertReconcileLeasesCurrent: leases.assertAccountSession,
    commitImport: (commitInput) => service.commitPortableVaultImport(commitInput),
    buildExport: (format, password) => service.buildPortableVaultExport(format, password),
    redeemExportAuthorization: ({ authorizationId, format }) => {
      const expected = exportAuthorizations.get(authorizationId);
      exportAuthorizations.delete(authorizationId);
      return expected === format;
    },
    reconcileCurrentAccount: async () => {
      await service.sync('vault-transfer-live-reconcile', 'force');
    },
  });
  return {
    service,
    controller,
    authorizeExport: (format) => {
      const authorizationId = crypto.randomUUID();
      exportAuthorizations.set(authorizationId, format);
      return authorizationId;
    },
  };
}

async function collectExport(
  transfer: TransferFixture,
  format: 'json' | 'encrypted-json' | 'zip',
  password?: string,
): Promise<Uint8Array> {
  const begun = await transfer.controller.beginExport({
    format,
    authorizationId: transfer.authorizeExport(format),
    ...(password === undefined ? {} : { filePassword: password }),
  });
  const collected = new Uint8Array(begun.totalBytes);
  let offset = 0;
  await transfer.controller.streamExport(begun.transferId, async ({ producer, totalBytes }) => {
    expect(totalBytes).toBe(collected.byteLength);
    for (;;) {
      const chunk = await producer.next();
      if (chunk.done) {
        expect(chunk.totalBytes).toBe(collected.byteLength);
        break;
      }
      collected.set(chunk.bytes, offset);
      offset += chunk.bytes.byteLength;
      producer.acknowledge(chunk.sequence);
      expect(chunk.bytes.every((byte) => byte === 0)).toBe(true);
    }
  });
  expect(offset).toBe(collected.byteLength);
  return collected;
}

async function uploadForPreview(
  controller: TransferFixture['controller'],
  bytes: Uint8Array,
  password?: string,
) {
  const begun = controller.beginImport({ expectedTotalBytes: bytes.byteLength });
  let sequence = 0;
  for (let offset = 0; offset < bytes.byteLength; sequence += 1) {
    const width = Math.min(113 + (sequence % 5) * 37, begun.maxChunkBytes, bytes.byteLength - offset);
    const ack = controller.appendImportChunk(
      begun.transferId,
      sequence,
      bytes.subarray(offset, offset + width),
    );
    expect(ack.totalBytes).toBe(offset + width);
    controller.acknowledgeImportChunk(begun.transferId, ack.sequence);
    offset += width;
  }
  const preview = await controller.sealAndInspectImport(begun.transferId, password);
  return { begun, preview };
}

async function importExport(
  controller: TransferFixture['controller'],
  bytes: Uint8Array,
  password?: string,
) {
  const uploaded = await uploadForPreview(controller, bytes, password);
  expect(uploaded.preview.preview.canCommit).toBe(true);
  expect(uploaded.preview.preview.counts).toMatchObject({ folders: 1, items: 4 });
  expect(controller.confirmImport(
    uploaded.begun.transferId,
    uploaded.preview.previewCapability,
  )).toEqual({ transferId: uploaded.begun.transferId, status: 'confirmed' });
  const result = await controller.commitConfirmedImport(uploaded.begun.transferId);
  expect(result).toEqual({
    transferId: uploaded.begun.transferId,
    status: 'completed',
    counts: { committed: 5, rejected: 0, skipped: 0, outcomeUnknown: 0 },
    requiresReconcile: false,
  });
  return result;
}

async function verifyRoundTrip(
  api: ApiClient,
  accessToken: string,
  userKey: SymmetricKey,
  markers: SeedMarkers,
  expectedCopies: number,
): Promise<void> {
  const sync = await api.sync(accessToken);
  const folders = await decryptFolders(sync.folders, userKey);
  const matchingFolders = folders.filter((folder) => folder.name === markers.folder);
  expect(matchingFolders).toHaveLength(expectedCopies);
  const folderIds = new Set(matchingFolders.map((folder) => folder.id));

  const decrypted = (await Promise.all(sync.ciphers.map((cipher) => decryptCipher(cipher, userKey))))
    .filter((cipher): cipher is DecryptedCipher => (
      cipher !== undefined && Object.values(markers).includes(cipher.name)
    ));
  const expectedItems = [markers.login, markers.note, markers.card, markers.identity];
  for (const name of expectedItems) {
    expect(decrypted.filter((cipher) => cipher.name === name)).toHaveLength(expectedCopies);
  }
  for (const folderId of folderIds) {
    expect(decrypted.filter((cipher) => cipher.folderId === folderId)).toHaveLength(4);
  }
  expect(decrypted.every((cipher) => cipher.folderId !== undefined && folderIds.has(cipher.folderId))).toBe(true);

  for (const login of decrypted.filter((cipher) => cipher.name === markers.login)) {
    expect(login).toMatchObject({
      type: 1,
      favorite: true,
      reprompt: true,
      notes: 'login notes',
      username: 'transfer-user@example.com',
      password: 'Transfer-Login-Pass-1!',
      totp: 'JBSWY3DPEHPK3PXP',
      loginUris: [{ uri: 'https://transfer.example.com/login', match: 2 }],
      fields: [
        { type: 0, name: 'environment', value: 'test' },
        { type: 1, name: 'recovery', value: 'hidden-value' },
        { type: 2, name: 'enabled', value: 'true' },
        { type: 3, name: 'linked-username', linkedId: 100 },
      ],
    });
  }
  for (const raw of sync.ciphers) {
    const clear = await decryptCipher(raw, userKey);
    if (clear?.name !== markers.login) continue;
    expect(raw.login).toMatchObject({
      autofillOnPageLoad: false,
      uris: [expect.objectContaining({ uriChecksum: expect.any(String) })],
    });
    expect(Date.parse(raw.login?.passwordRevisionDate ?? '')).toBe(
      Date.parse('2026-08-01T00:00:00.000Z'),
    );
  }
  for (const note of decrypted.filter((cipher) => cipher.name === markers.note)) {
    expect(note).toMatchObject({ type: 2, notes: 'secure note body' });
  }
  for (const card of decrypted.filter((cipher) => cipher.name === markers.card)) {
    expect(card).toMatchObject({
      type: 3,
      notes: 'card notes',
      card: {
        cardholderName: 'Transfer Holder',
        brand: 'Visa',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2031',
        code: '123',
      },
    });
  }
  for (const identity of decrypted.filter((cipher) => cipher.name === markers.identity)) {
    expect(identity).toMatchObject({
      type: 4,
      notes: 'identity notes',
      identity: {
        title: 'Mx',
        firstName: 'Transfer',
        middleName: 'Live',
        lastName: 'Tester',
        address1: '1 Integration Way',
        city: 'Test City',
        state: 'CA',
        postalCode: '94105',
        country: 'US',
        company: 'MiYu Test',
        email: 'identity@example.com',
        phone: '+1-555-0100',
        ssn: '000-00-0000',
        username: 'identity-user',
        passportNumber: 'TEST-PASSPORT',
        licenseNumber: 'TEST-LICENSE',
      },
    });
  }
}

(LIVE ? describe : describe.skip)('live production vault transfer against test-env', () => {
  it('round-trips rich personal data through JSON and encrypted JSON with WAL and replay barriers', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const api = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: fetch,
      localStore,
    });
    const unique = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
    const email = `transfer-${unique}@example.com`;
    const password = `Transfer-Live-${unique}-Pass!`;
    const exportPassword = `Transfer-Export-${unique}-Pass!`;
    const markers: SeedMarkers = {
      folder: `Transfer Folder ${unique}`,
      login: `Transfer Login ${unique}`,
      note: `Transfer Note ${unique}`,
      card: `Transfer Card ${unique}`,
      identity: `Transfer Identity ${unique}`,
    };
    let accessToken: string | undefined;
    let masterPasswordHash: string | undefined;
    let masterKey: Uint8Array | undefined;
    let stretched: SymmetricKey | undefined;
    let userKey: SymmetricKey | undefined;
    let privateKey: Uint8Array | undefined;
    let session: SessionManager | undefined;
    let jsonExport: Uint8Array | undefined;
    let encryptedExport: Uint8Array | undefined;
    let zipExport: Uint8Array | undefined;
    let accountRegistered = false;
    let cleanupError: Error | undefined;

    try {
      const registration = await buildRegistration(email, password);
      masterPasswordHash = registration.masterPasswordHash;
      const emailVerificationToken = await requestRegistrationToken(email);
      await api.register({
        ...registration,
        masterPasswordHint: '',
        email,
        name: 'Transfer Live Test',
        ...(emailVerificationToken ? { emailVerificationToken } : {}),
      });
      accountRegistered = true;

      const kdf = parseKdfConfig(await api.prelogin(email));
      masterKey = await deriveMasterKey(password, email, kdf);
      expect(await deriveMasterPasswordHash(masterKey, password)).toBe(masterPasswordHash);
      const login = await api.passwordLogin({ email, masterPasswordHash });
      expect(login.kind).toBe('success');
      if (login.kind !== 'success') throw new Error('registered transfer account did not log in');
      const refreshed = await api.refresh(login.data.refresh_token);
      accessToken = refreshed.access_token;
      stretched = await stretchMasterKey(masterKey);
      userKey = await unwrapSymmetricKey(login.data.Key, stretched);
      if (!login.data.PrivateKey) throw new Error('login response omitted the encrypted private key');
      privateKey = await decryptPrivateKey(login.data.PrivateKey, userKey);

      session = new SessionManager({ localStore, sessionStore });
      await session.saveUnlocked({
        email,
        accessToken,
        refreshToken: refreshed.refresh_token,
        expiresAt: Date.now() + refreshed.expires_in * 1_000,
        protectedKey: login.data.Key,
        encPrivateKey: login.data.PrivateKey,
        ...kdf,
        userKey,
        privateKey,
      });
      privateKey.fill(0);
      privateKey = undefined;
      masterKey.fill(0);
      masterKey = undefined;
      clearKey(stretched);
      stretched = undefined;

      await seedVault(api, accessToken, userKey, markers);
      await verifyRoundTrip(api, accessToken, userKey, markers, 1);

      const accountGate = new AccountLeaseGate();
      accountGate.initialize({ serverUrl: SERVER, accountIdentity: email });
      const sessionGate = new SessionGate('unlocked');
      const policyGate = new EnterprisePolicyGate();
      const transfer = buildTransferFixture({
        api,
        session,
        accountGate,
        sessionGate,
        policyGate,
        localStore,
        sessionStore,
        accountKey: `${SERVER}\n${email}`,
      });
      await transfer.service.sync('vault-transfer-live-seed', 'force');
      expect(await transfer.controller.inspectJournalForStartup()).toMatchObject({ kind: 'none' });

      jsonExport = await collectExport(transfer, 'json');
      encryptedExport = await collectExport(transfer, 'encrypted-json', exportPassword);
      zipExport = await collectExport(transfer, 'zip');

      const exportedDocument = JSON.parse(new TextDecoder().decode(jsonExport)) as {
        folders?: unknown[];
        items?: Array<Record<string, unknown>>;
      };
      expect(exportedDocument.folders).toHaveLength(1);
      expect(exportedDocument.items).toHaveLength(4);
      const exportedLogin = exportedDocument.items?.find((item) => item.name === markers.login);
      expect(exportedLogin).toMatchObject({
        type: 1,
        reprompt: 1,
        favorite: true,
        fields: expect.arrayContaining([
          expect.objectContaining({ type: 3, name: 'linked-username', linkedId: 100 }),
        ]),
        login: expect.objectContaining({
          username: 'transfer-user@example.com',
          autofillOnPageLoad: false,
          uris: [{ uri: 'https://transfer.example.com/login', match: 2 }],
        }),
      });
      expect(Date.parse(
        ((exportedLogin?.login as Record<string, unknown> | undefined)
          ?.passwordRevisionDate as string | undefined) ?? '',
      )).toBe(Date.parse('2026-08-01T00:00:00.000Z'));

      const archive = readVaultArchive(zipExport);
      try {
        expect(archive.ok).toBe(true);
        expect(archive.dataJson).not.toBeNull();
        expect(archive.attachments).toHaveLength(0);
        expect(archive.manifest).toMatchObject({ version: 1, attachments: [] });
      } finally {
        archive.dataJson?.fill(0);
        for (const attachment of archive.attachments) attachment.data.fill(0);
      }

      const jsonResult = await importExport(transfer.controller, jsonExport);
      expect(await transfer.controller.inspectReplayBarriers()).toMatchObject({ count: 1 });

      const replay = transfer.controller.beginImport({ expectedTotalBytes: jsonExport.byteLength });
      for (let offset = 0, sequence = 0; offset < jsonExport.byteLength; sequence += 1) {
        const end = Math.min(offset + 257, jsonExport.byteLength);
        const ack = transfer.controller.appendImportChunk(
          replay.transferId,
          sequence,
          jsonExport.subarray(offset, end),
        );
        transfer.controller.acknowledgeImportChunk(replay.transferId, ack.sequence);
        offset = end;
      }
      await expect(transfer.controller.sealAndInspectImport(replay.transferId))
        .rejects.toMatchObject({ code: 'outcome_unknown' });

      await transfer.controller.acknowledgeImportResult(jsonResult.transferId);
      expect(await transfer.controller.inspectReplayBarriers()).toMatchObject({ count: 0 });
      const allowedReplay = await uploadForPreview(transfer.controller, jsonExport);
      expect(allowedReplay.preview.preview.canCommit).toBe(true);
      expect(await transfer.controller.cancel(allowedReplay.begun.transferId)).toMatchObject({
        cancelled: true,
        requiresReconcile: false,
      });

      const encryptedResult = await importExport(transfer.controller, encryptedExport, exportPassword);
      await transfer.controller.acknowledgeImportResult(encryptedResult.transferId);
      expect(await transfer.controller.inspectReplayBarriers()).toMatchObject({ count: 0 });

      await verifyRoundTrip(api, accessToken, userKey, markers, 3);
      expect(transfer.controller.retainedPasswordBytes).toBe(0);
    } finally {
      jsonExport?.fill(0);
      encryptedExport?.fill(0);
      zipExport?.fill(0);
      privateKey?.fill(0);
      masterKey?.fill(0);
      clearKey(stretched);
      clearKey(userKey);
      try {
        let currentToken = (await session?.getActiveAuth())?.accessToken ?? accessToken;
        if (!currentToken && accountRegistered && masterPasswordHash) {
          const cleanupLogin = await api.passwordLogin({ email, masterPasswordHash });
          if (cleanupLogin.kind === 'success') currentToken = cleanupLogin.data.access_token;
        }
        if (accountRegistered && currentToken && masterPasswordHash) {
          await deleteAccount(currentToken, masterPasswordHash);
        } else if (accountRegistered) {
          cleanupError = new Error('registered account could not be authenticated for cleanup');
        }
      } catch (error) {
        cleanupError = error instanceof Error ? error : new Error('account cleanup failed');
      }
      await sessionStore.clear();
      await localStore.clear();
    }
    if (cleanupError) throw cleanupError;
  }, 300_000);
});
