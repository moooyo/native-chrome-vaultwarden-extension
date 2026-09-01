// @vitest-environment node
// Live production SSH-key integration test. It is hard-bound to the authorized test-env SSH tunnel.
// Run: $env:LIVE='1'; $env:MIYU_SERVER='http://127.0.0.1:18082'; npm run test:live -- test/live/ssh.live.test.ts
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { ApiClient, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import { normalizeServerUrl } from '../../src/background/settings.js';
import { SessionGate } from '../../src/background/session-gate.js';
import {
  ServerCapabilityManager,
  authorizeSshCipherType5Write,
} from '../../src/background/server-capability-manager.js';
import {
  PRODUCTION_SERVER_CAPABILITY_DECLARATION,
  fetchFixedServerConfig,
} from '../../src/background/server-capability-production.js';
import {
  createVaultTransferLeaseBindings,
  type VaultTransferAccountSessionLeases,
} from '../../src/background/vault-transfer-lifecycle.js';
import { VaultTransferController } from '../../src/background/vault-transfer-controller.js';
import { AccountLeaseGate, type AccountLease } from '../../src/core/session/account-gate.js';
import { SessionManager, type SessionLease } from '../../src/core/session/session-manager.js';
import {
  EnterprisePolicyGate,
  type PolicyLease,
} from '../../src/core/policy/effective-enterprise-policy.js';
import {
  deriveMasterKey,
  deriveMasterPasswordHash,
  parseKdfConfig,
  stretchMasterKey,
} from '../../src/core/crypto/kdf.js';
import {
  decryptPrivateKey,
  unwrapSymmetricKey,
  type SymmetricKey,
} from '../../src/core/crypto/keys.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import type { CipherResponse } from '../../src/core/api/types.js';
import type { CompleteDecryptedSshKey, SshKeyMetadataInput } from '../../src/core/vault/models.js';
import { generateSshKey, importSshPrivateKey } from '../../src/core/vault/ssh-key-codec.js';
import { VaultMutationCoordinator } from '../../src/core/vault/vault-mutation-coordinator.js';
import { VaultTransferSessionManager } from '../../src/core/vault/vault-transfer-session.js';
import { VaultTransferJournalStore } from '../../src/core/vault/vault-transfer-journal.js';
import {
  VAULT_SERVICE_IMPORT_CAPABILITIES,
  VAULT_SERVICE_SSH_IMPORT_CAPABILITIES,
  VaultService,
  type VaultListing,
} from '../../src/core/vault/vault-service.js';
import { createMemoryStore } from '../../src/platform/store.js';

const execFileAsync = promisify(execFile);
const LIVE = process.env.LIVE === '1';
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const SERVER = normalizeServerUrl(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER);

if (LIVE && SERVER !== AUTHORIZED_SERVER) {
  throw new Error(`SSH live test is restricted to ${AUTHORIZED_SERVER}`);
}

type LiveTransferController = VaultTransferController<
  AccountLease,
  SessionLease,
  PolicyLease,
  AccountLease,
  VaultTransferAccountSessionLeases<AccountLease, SessionLease>,
  VaultTransferAccountSessionLeases<AccountLease, SessionLease>
>;

interface LiveFixture {
  readonly service: VaultService;
  readonly transfer: LiveTransferController;
}

async function requestRegistrationToken(email: string): Promise<string | undefined> {
  const response = await fetch(new URL('identity/accounts/register/send-verification-email', SERVER), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ email, name: 'SSH Live Test' }),
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
  if (
    typeof token !== 'string'
    || token.length === 0
    || token.length > 16_384
    || [...token].some((character) => {
      const code = character.charCodeAt(0);
      return code <= 0x1f || code === 0x7f;
    })
  ) {
    throw new Error('registration start returned an invalid token');
  }
  return token;
}

async function deleteAccount(accessToken: string, masterPasswordHash: string): Promise<void> {
  const response = await fetch(new URL('api/accounts', SERVER), {
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

async function cleanupAccount(
  api: ApiClient,
  email: string,
  masterPasswordHash: string,
  accessToken?: string,
): Promise<void> {
  let tokenError: unknown;
  if (accessToken) {
    try {
      await deleteAccount(accessToken, masterPasswordHash);
      return;
    } catch (error) {
      tokenError = error;
    }
  }
  try {
    const login = await api.passwordLogin({ email, masterPasswordHash });
    if (login.kind !== 'success') throw new Error('cleanup login unexpectedly required two-factor authentication');
    await deleteAccount(login.data.access_token, masterPasswordHash);
  } catch (error) {
    if (tokenError) {
      throw new AggregateError(
        [tokenError, error],
        'account cleanup failed with both active and fresh tokens',
        { cause: error },
      );
    }
    throw error;
  }
}

function clearKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}

function accountKeyFor(lease: AccountLease): string {
  return `${lease.serverUrl}\n${lease.accountIdentity}`;
}

function buildLiveFixture(input: {
  readonly api: ApiClient;
  readonly session: SessionManager;
  readonly accountGate: AccountLeaseGate;
  readonly sessionGate: SessionGate;
  readonly policyGate: EnterprisePolicyGate;
  readonly capabilities: ServerCapabilityManager<AccountLease>;
  readonly localStore: ReturnType<typeof createMemoryStore>;
  readonly sessionStore: ReturnType<typeof createMemoryStore>;
  readonly accountKey: string;
}): LiveFixture {
  const coordinator = new VaultMutationCoordinator<
    string,
    AccountLease,
    VaultListing,
    string,
    string
  >({
    captureLease: (account) => {
      const lease = input.accountGate.capture();
      if (accountKeyFor(lease) !== account) throw new Error('coordinator account mismatch');
      return lease;
    },
    assertLease: (account, lease) => {
      input.accountGate.assert(lease);
      if (accountKeyFor(lease) !== account) throw new Error('coordinator account changed');
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
    authorizeSshCipherType5Write: () => authorizeSshCipherType5Write(input.capabilities),
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
  const transfer = new VaultTransferController({
    sessions,
    journal,
    getImportCapabilities: () => {
      const snapshot = input.capabilities.current();
      return snapshot?.availability === 'available'
        && snapshot.capabilities.features.sshCipherType5 === 'available'
        ? VAULT_SERVICE_SSH_IMPORT_CAPABILITIES
        : VAULT_SERVICE_IMPORT_CAPABILITIES;
    },
    captureAccountIdentity: () => {
      const lease = input.accountGate.capture();
      return Object.freeze({ canonicalIdentity: accountKeyFor(lease), lease });
    },
    assertAccountIdentityCurrent: (snapshot) => {
      input.accountGate.assert(snapshot.lease);
      return snapshot.canonicalIdentity === accountKeyFor(snapshot.lease);
    },
    captureTransferLeases: leases.captureAccountSession,
    assertTransferLeasesCurrent: leases.assertAccountSession,
    captureReconcileLeases: leases.captureAccountSession,
    assertReconcileLeasesCurrent: leases.assertAccountSession,
    commitImport: (commitInput) => service.commitPortableVaultImport(commitInput),
    buildExport: (format, password) => service.buildPortableVaultExport(format, password),
    reconcileCurrentAccount: async () => {
      await service.sync('ssh-live-transfer-reconcile', 'force');
    },
  });
  return { service, transfer };
}

async function importPortableJson(
  controller: LiveTransferController,
  bytes: Uint8Array,
): Promise<void> {
  const begun = controller.beginImport({ expectedTotalBytes: bytes.byteLength });
  let sequence = 0;
  for (let offset = 0; offset < bytes.byteLength; sequence += 1) {
    const end = Math.min(offset + 257, bytes.byteLength);
    const ack = controller.appendImportChunk(
      begun.transferId,
      sequence,
      bytes.subarray(offset, end),
    );
    controller.acknowledgeImportChunk(begun.transferId, ack.sequence);
    offset = end;
  }
  const inspected = await controller.sealAndInspectImport(begun.transferId);
  expect(inspected.preview.canCommit).toBe(true);
  expect(inspected.preview.counts).toMatchObject({ folders: 0, items: 1 });
  expect(controller.confirmImport(
    begun.transferId,
    inspected.previewCapability,
  )).toEqual({ transferId: begun.transferId, status: 'confirmed' });
  const result = await controller.commitConfirmedImport(begun.transferId);
  expect(result).toEqual({
    transferId: begun.transferId,
    status: 'completed',
    counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 0 },
    requiresReconcile: false,
  });
  await controller.acknowledgeImportResult(begun.transferId);
}

function normalizeOpenSshPublicKey(value: string): string {
  return value.trim().split(/\s+/).slice(0, 2).join(' ');
}

function parseOpenSshFingerprint(value: string): string {
  const match = /(?:^|\s)(SHA256:[A-Za-z0-9+/]{43})(?:\s|$)/.exec(value);
  if (!match) throw new Error('ssh-keygen returned no SHA-256 fingerprint');
  return match[1]!;
}

async function verifySshIdentity(
  privateKey: string,
  expectedPublicKey: string,
  expectedFingerprint: string,
): Promise<void> {
  const codec = await importSshPrivateKey(privateKey);
  expect(codec.publicKey).toBe(expectedPublicKey);
  expect(codec.keyFingerprint).toBe(expectedFingerprint);

  const directory = await mkdtemp(join(tmpdir(), 'miyu-ssh-live-'));
  const privateKeyPath = join(directory, 'id_ed25519');
  try {
    await writeFile(privateKeyPath, privateKey, { encoding: 'utf8', mode: 0o600 });
    if (process.platform === 'win32') {
      const user = process.env.USERNAME;
      if (!user) throw new Error('USERNAME is required to secure the temporary SSH private key');
      const domain = process.env.USERDOMAIN;
      const identity = domain ? `${domain}\\${user}` : user;
      await execFileAsync(
        'icacls.exe',
        [privateKeyPath, '/inheritance:r', '/grant:r', `${identity}:(R)`],
        { encoding: 'utf8', windowsHide: true },
      );
    }
    const publicResult = await execFileAsync(
      'ssh-keygen',
      ['-y', '-f', privateKeyPath],
      { encoding: 'utf8', windowsHide: true },
    );
    const fingerprintResult = await execFileAsync(
      'ssh-keygen',
      ['-lf', privateKeyPath, '-E', 'sha256'],
      { encoding: 'utf8', windowsHide: true },
    );
    expect(normalizeOpenSshPublicKey(publicResult.stdout)).toBe(
      normalizeOpenSshPublicKey(expectedPublicKey),
    );
    expect(parseOpenSshFingerprint(fingerprintResult.stdout)).toBe(expectedFingerprint);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function findSshCipher(ciphers: readonly CipherResponse[], id: string): CipherResponse {
  const cipher = ciphers.find((candidate) => candidate.id === id);
  if (!cipher) throw new Error(`SSH cipher ${id} is missing from sync`);
  expect(cipher.type).toBe(5);
  return cipher;
}

(LIVE ? describe : describe.skip)('live production SSH key lifecycle against test-env', () => {
  it('round-trips a real type-5 Ed25519 key through service, OpenSSH, export, and transfer import', async () => {
    const localStore = createMemoryStore();
    const sessionStore = createMemoryStore();
    const api = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: fetch,
      localStore,
    });
    const unique = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
    const email = `ssh-live-${unique}@example.com`;
    const password = `SSH-Live-${unique}-Pass!`;
    const initialName = `SSH Live ${unique}`;
    const updatedName = `SSH Live Updated ${unique}`;
    const initialMetadata: SshKeyMetadataInput = {
      name: initialName,
      notes: 'Generated by the SSH live integration test',
      favorite: false,
      reprompt: false,
      folderId: null,
      fields: [{ type: 0, name: 'environment', value: 'test-env' }],
    };
    const updatedMetadata: SshKeyMetadataInput = {
      name: updatedName,
      notes: 'Metadata changed without replacing key material',
      favorite: true,
      reprompt: false,
      folderId: null,
      fields: [
        { type: 0, name: 'environment', value: 'test-env' },
        { type: 1, name: 'rotation', value: 'verified' },
      ],
    };

    let registrationAttempted = false;
    let masterPasswordHash: string | undefined;
    let accessToken: string | undefined;
    let masterKey: Uint8Array | undefined;
    let stretched: SymmetricKey | undefined;
    let userKey: SymmetricKey | undefined;
    let privateKey: Uint8Array | undefined;
    let session: SessionManager | undefined;
    let portableExport: Uint8Array | undefined;
    let replacement: CompleteDecryptedSshKey | undefined;
    let revealedPrivateKey: string | undefined;
    let failure: unknown;
    let cleanupFailure: unknown;

    try {
      expect(BITWARDEN_CLIENT_VERSION).toBe('2024.12.0');
      expect(PRODUCTION_SERVER_CAPABILITY_DECLARATION).toMatchObject({
        advertisedProtocolVersion: '2024.12.0',
        supportedCipherTypes: expect.arrayContaining([5]),
      });

      const registration = await buildRegistration(email, password);
      masterPasswordHash = registration.masterPasswordHash;
      const emailVerificationToken = await requestRegistrationToken(email);
      registrationAttempted = true;
      await api.register({
        ...registration,
        masterPasswordHint: '',
        email,
        name: 'SSH Live Test',
        ...(emailVerificationToken ? { emailVerificationToken } : {}),
      });

      const kdf = parseKdfConfig(await api.prelogin(email));
      masterKey = await deriveMasterKey(password, email, kdf);
      expect(await deriveMasterPasswordHash(masterKey, password)).toBe(masterPasswordHash);
      const login = await api.passwordLogin({ email, masterPasswordHash });
      expect(login.kind).toBe('success');
      if (login.kind !== 'success') throw new Error('registered SSH account did not log in');
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

      const accountGate = new AccountLeaseGate();
      accountGate.initialize({ serverUrl: SERVER, accountIdentity: email });
      const sessionGate = new SessionGate('unlocked');
      const policyGate = new EnterprisePolicyGate();
      const capabilityApi = { forServer: (serverUrl: string) => api.forServer(serverUrl) };
      const capabilities = new ServerCapabilityManager<AccountLease>({
        captureIdentity: () => {
          const lease = accountGate.capture();
          return {
            identity: { serverUrl: lease.serverUrl, accountIdentity: lease.accountIdentity },
            lease,
          };
        },
        assertIdentityCurrent: (lease) => accountGate.assert(lease),
        fetchConfig: (request) => fetchFixedServerConfig(capabilityApi, request),
        clientDeclaration: PRODUCTION_SERVER_CAPABILITY_DECLARATION,
      });
      const capability = await capabilities.resolve({ forceRefresh: true });
      expect(capability.availability).toBe('available');
      expect(capability.capabilities.features.sshCipherType5).toBe('available');
      const authorization = await authorizeSshCipherType5Write(capabilities);
      expect(() => authorization.assertCurrent()).not.toThrow();

      const fixture = buildLiveFixture({
        api,
        session,
        accountGate,
        sessionGate,
        policyGate,
        capabilities,
        localStore,
        sessionStore,
        accountKey: `${SERVER}\n${email}`,
      });
      await fixture.service.initializeCache();
      await fixture.service.sync('ssh-live-initial', 'force');
      expect(await fixture.transfer.inspectJournalForStartup()).toMatchObject({ kind: 'none' });
      await expect(fixture.service.getSshKeyWriteAvailability()).resolves.toEqual({ available: true });

      const created = await fixture.service.createGeneratedSshKey(initialMetadata);
      const createdSummary = created.items.find((item) => item.type === 5 && item.name === initialName);
      expect(createdSummary).toBeDefined();
      const sshId = createdSummary!.id;
      expect(createdSummary!.subtitle).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);

      const directSync = await api.sync(accessToken);
      const rawCreated = findSshCipher(directSync.ciphers, sshId);
      expect(rawCreated.sshKey).toMatchObject({
        privateKey: expect.stringMatching(/^2\./),
        publicKey: expect.stringMatching(/^2\./),
        keyFingerprint: expect.stringMatching(/^2\./),
      });

      const listed = await fixture.service.listItems();
      expect(listed.items.find((item) => item.id === sshId)).toMatchObject({
        type: 5,
        name: initialName,
        subtitle: createdSummary!.subtitle,
      });
      const publicDetails = await fixture.service.getSshKeyDetails(sshId);
      expect(publicDetails).toBeDefined();
      expect(Object.prototype.hasOwnProperty.call(publicDetails, 'privateKey')).toBe(false);
      expect(publicDetails).toMatchObject({
        hasPrivateKey: true,
        keyFingerprint: createdSummary!.subtitle,
        publicKey: expect.stringMatching(/^ssh-ed25519 /),
      });
      const safeDetails = await fixture.service.getCipherDetail(sshId);
      expect(safeDetails).toBeDefined();
      expect(Object.prototype.hasOwnProperty.call(safeDetails, 'sshKey')).toBe(false);

      revealedPrivateKey = await fixture.service.revealSshPrivateKey(sshId);
      expect(revealedPrivateKey).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----/);
      expect(revealedPrivateKey).toMatch(/-----END OPENSSH PRIVATE KEY-----\n?$/);
      await verifySshIdentity(
        revealedPrivateKey!,
        publicDetails!.publicKey!,
        publicDetails!.keyFingerprint!,
      );

      await fixture.service.updateSshKeyMetadata(sshId, updatedMetadata);
      const metadataDetails = await fixture.service.getSshKeyDetails(sshId);
      expect(metadataDetails).toEqual(publicDetails);
      await expect(fixture.service.revealSshPrivateKey(sshId)).resolves.toBe(revealedPrivateKey);
      const updatedSafeDetails = await fixture.service.getCipherDetail(sshId);
      expect(updatedSafeDetails).toMatchObject({
        id: sshId,
        type: 5,
        name: updatedName,
        notes: updatedMetadata.notes,
        favorite: true,
        fields: [
          { type: 0, name: 'environment', value: 'test-env' },
          { type: 1, name: 'rotation' },
        ],
      });
      expect(Object.prototype.hasOwnProperty.call(updatedSafeDetails, 'sshKey')).toBe(false);
      const hiddenMetadata = updatedSafeDetails?.fields?.find((field) => field.type === 1);
      expect(Object.prototype.hasOwnProperty.call(hiddenMetadata, 'value')).toBe(false);

      replacement = generateSshKey();
      expect(replacement.keyFingerprint).not.toBe(publicDetails!.keyFingerprint);
      await fixture.service.replaceSshKey(sshId, replacement.privateKey);
      const replacedDetails = await fixture.service.getSshKeyDetails(sshId);
      expect(replacedDetails).toEqual({
        publicKey: replacement.publicKey,
        keyFingerprint: replacement.keyFingerprint,
        hasPrivateKey: true,
      });
      const replacedPrivateKey = await fixture.service.revealSshPrivateKey(sshId);
      expect(replacedPrivateKey).toBe(replacement.privateKey);
      await verifySshIdentity(
        replacedPrivateKey!,
        replacement.publicKey,
        replacement.keyFingerprint,
      );

      const builtExport = await fixture.service.buildPortableVaultExport('json');
      portableExport = builtExport.bytes;
      expect(builtExport.filename).toBe('miyu-vault.json');
      const exported = JSON.parse(new TextDecoder().decode(portableExport)) as {
        readonly items?: ReadonlyArray<Record<string, unknown>>;
      };
      const exportedSsh = exported.items?.find((item) => item.type === 5 && item.name === updatedName);
      expect(exportedSsh).toMatchObject({
        type: 5,
        name: updatedName,
        sshKey: {
          privateKey: replacement.privateKey,
          publicKey: replacement.publicKey,
          keyFingerprint: replacement.keyFingerprint,
        },
      });

      await importPortableJson(fixture.transfer, portableExport);
      const afterImport = await api.sync(accessToken);
      const sshCopies = afterImport.ciphers.filter((cipher) => cipher.type === 5);
      expect(sshCopies).toHaveLength(2);
      const importedCopy = sshCopies.find((cipher) => cipher.id !== sshId);
      expect(importedCopy).toBeDefined();
      const importedDetails = await fixture.service.getSshKeyDetails(importedCopy!.id);
      expect(importedDetails).toEqual(replacedDetails);
      await expect(fixture.service.revealSshPrivateKey(importedCopy!.id)).resolves.toBe(replacement.privateKey);
      await fixture.service.softDeleteCipher(importedCopy!.id);
      await fixture.service.deleteCipher(importedCopy!.id);

      await fixture.service.softDeleteCipher(sshId);
      const trashed = findSshCipher((await api.sync(accessToken)).ciphers, sshId);
      expect(trashed.deletedDate).toEqual(expect.any(String));
      await fixture.service.restoreCipher(sshId);
      const restored = findSshCipher((await api.sync(accessToken)).ciphers, sshId);
      expect(restored.deletedDate ?? null).toBeNull();
      await fixture.service.softDeleteCipher(sshId);
      await fixture.service.deleteCipher(sshId);
      expect((await api.sync(accessToken)).ciphers.some((cipher) => cipher.id === sshId)).toBe(false);
      expect(fixture.transfer.retainedPasswordBytes).toBe(0);
    } catch (error) {
      failure = error;
    } finally {
      portableExport?.fill(0);
      privateKey?.fill(0);
      masterKey?.fill(0);
      clearKey(stretched);
      clearKey(userKey);
      try {
        if (registrationAttempted && masterPasswordHash) {
          const activeToken = (await session?.getActiveAuth())?.accessToken ?? accessToken;
          await cleanupAccount(api, email, masterPasswordHash, activeToken);
        }
      } catch (error) {
        cleanupFailure = error;
      }
      await sessionStore.clear();
      await localStore.clear();
    }

    if (failure && cleanupFailure) {
      throw new AggregateError([failure, cleanupFailure], 'SSH live test and account cleanup failed');
    }
    if (failure) throw failure;
    if (cleanupFailure) throw cleanupFailure;
  }, 300_000);
});
