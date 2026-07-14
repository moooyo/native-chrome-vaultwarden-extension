import type { ApiClient } from '../api/client.js';
import type { CipherRequest, CipherResponse, SyncProfile, SyncResponse } from '../api/types.js';
import type { SessionManager } from '../session/session-manager.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { CipherSummary, CipherInput, CollectionSummary, DecryptedCipher, FieldName, FolderSummary, PasskeyTarget, PasskeyCandidate, TotpListEntry } from './models.js';
import { decryptCipher, decryptCipherSummary, undecryptableSummary, decryptFolders, decryptCollections, buildOrgKeyMap } from './decrypt.js';
import { encryptCipher, mergeServerManagedFields } from './encrypt.js';
import { getTotp, type TotpResult } from './totp.js';
import { signFido2Assertion, type PasskeyAssertion } from './fido2.js';
import { generateFido2Keypair, buildAttestationObject, buildCreateClientDataJSON, encryptFido2Credential } from './fido2-create.js';
import { encryptToText, decryptToText } from '../crypto/encstring.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import { base64UrlToBytes, base64ToBytes, bytesToBase64, bytesToBase64Url } from '../crypto/encoding.js';
import { decryptAttachmentKey, decryptAttachmentFile, encryptAttachmentFile, generateAttachmentKey, wrapAttachmentKey } from './attachments.js';
import { buildPasswordHealthReport, type PasswordHealthEntry, type PasswordHealthInput } from './password-health.js';
import { pwnedCount } from './pwned.js';
import { buildExportJson, buildEncryptedExportJson, parseImport } from './vault-io.js';
import { buildTextSendRequest, buildFileSendRequest, buildUpdateSendRequest, decryptSend, type SendInput, type SendSummary, type UpdateSendInput } from './sends.js';
import { AppError } from '../errors.js';
import type { AutofillCandidate, AutofillCredentials, FillKind, FillItemCandidate, CardFillData, IdentityFillData } from '../../messaging/protocol.js';
import { compareMatchResults, matchLoginUri, UriMatchStrategy, type UriMatchResult, type UriMatchStrategySetting } from './uri-match.js';
import { buildEquivalentDomainIndex } from './equivalent-domains.js';
import { toOrgPermission } from './org-permissions.js';
import type { OrgPermission } from './org-permissions.js';
import { getHostAndPort, isRegistrableRpId } from './domain.js';

export interface VaultServiceDeps {
  api: ApiClient;
  auth: Pick<AuthService, 'refreshIfNeeded' | 'verifyMasterPassword'>;
  session: SessionManager;
  localStore: KeyValueStore;
  getIdentityEpoch?: () => number;
  now?: () => number;
}

const VAULT_CACHE_KEY = 'vaultCache';
const SUMMARY_CACHE_KEY = 'vaultSummaries';
const FOLDER_CACHE_KEY = 'vaultFolders';
const COLLECTION_CACHE_KEY = 'vaultCollections';
const EQUIV_DOMAINS_KEY = 'vaultEquivalentDomains';
const EQUIV_EXCLUDED_KEY = 'vaultExcludedDomains';
const SKIPPED_ORG_KEY = 'vaultSkippedOrgCount';
const ORG_PERMISSIONS_KEY = 'vaultOrgPermissions';
/** Cap on retained prior passwords (the server may trim further). Keeps the audit trail bounded. */
const MAX_PASSWORD_HISTORY = 20;

export interface VaultListing {
  items: CipherSummary[];
  folders: FolderSummary[];
  collections: CollectionSummary[];
  orgPermissions: OrgPermission[];
}

/** Outcome of an {@link VaultService.importVault} run. Reports how many items were created versus how
 *  many failed so the caller can surface a partial import instead of treating one failure as total. */
export interface ImportResult {
  /** Number of items successfully created on the server. */
  imported: number;
  /** Number of items that failed to import. */
  failed: number;
  /** Per-item failure detail, in input order: the index into the parsed import and the error message. */
  failures: Array<{ index: number; message: string }>;
}

/** The save/update decision for a captured form submission. */
export type SaveLoginPrompt =
  | { action: 'none' }
  | { action: 'save'; suggestedName: string }
  | { action: 'update'; cipherId: string; name: string };

/** The public attestation returned to the page after registering a new passkey. The private key
 *  (keyValue) never leaves the worker — only these public/opaque values cross the boundary. */
export interface Fido2Registration {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
  authData: string;
  publicKeySpki: string;
  publicKeyAlgorithm: -7;
}

export class VaultService {
  private cacheMutationTail: Promise<void> = Promise.resolve();

  constructor(private readonly deps: VaultServiceDeps) {}

  async sync(): Promise<VaultListing> {
    const identityEpoch = this.identityEpoch();
    await this.deps.auth.refreshIfNeeded();
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const response = await this.deps.api.sync(auth.accessToken);
    this.assertIdentityEpoch(identityEpoch);
    return this.decryptAndPersist(response, identityEpoch);
  }

  /**
   * Decrypt a sync response and persist every derived cache (summaries, folders, collections, org
   * permissions, equivalence data). Requires an unlocked vault. Shared by sync() and the lock/unlock
   * cache rebuild so the two paths cannot drift.
   */
  private async decryptAndPersist(response: SyncResponse, identityEpoch: number): Promise<VaultListing> {
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const orgKeys = await this.buildOrgKeys(response.profile);
    const items = await this.decryptSummaries(response.ciphers, userKey, orgKeys);
    const folders = await decryptFolders(response.folders, userKey);
    const collections = await decryptCollections(response.collections, orgKeys);
    // Org ciphers whose key could not be unwrapped (e.g. locked private key) are surfaced to the UI.
    const skippedOrgCount = response.ciphers.filter((c) => c.organizationId && !orgKeys.has(c.organizationId)).length;
    // Domains of global equivalence groups the user has switched off (Domain Rules), so the client
    // stops treating them as equivalent for autofill.
    const excludedDomains = (response.domains?.globalEquivalentDomains ?? [])
      .filter((g) => g.excluded)
      .flatMap((g) => g.domains ?? []);
    const orgPermissions = (response.profile?.organizations ?? [])
      .filter((o) => orgKeys.has(o.id))
      .map(toOrgPermission);
    await this.withCacheMutation(async () => {
      this.assertIdentityEpoch(identityEpoch);
      await this.deps.localStore.set(VAULT_CACHE_KEY, response);
      await this.deps.localStore.set(SUMMARY_CACHE_KEY, items);
      await this.deps.localStore.set(FOLDER_CACHE_KEY, folders);
      await this.deps.localStore.set(COLLECTION_CACHE_KEY, collections);
      await this.deps.localStore.set(EQUIV_DOMAINS_KEY, response.domains?.equivalentDomains ?? []);
      await this.deps.localStore.set(EQUIV_EXCLUDED_KEY, excludedDomains);
      await this.deps.localStore.set(SKIPPED_ORG_KEY, skippedOrgCount);
      await this.deps.localStore.set(ORG_PERMISSIONS_KEY, orgPermissions);
    });
    this.assertIdentityEpoch(identityEpoch);
    return { items, folders, collections, orgPermissions };
  }

  /**
   * Purge the DECRYPTED metadata caches (item names, login URIs, folder/collection names, org
   * permissions) from storage.local — called on lock so they don't linger as plaintext on disk. The
   * encrypted VAULT_CACHE is kept, so listItems() rebuilds the listing locally (no re-sync) on the
   * next unlocked read.
   */
  async purgeDecryptedCaches(): Promise<void> {
    await this.withCacheMutation(async () => {
      await this.deps.localStore.remove(SUMMARY_CACHE_KEY);
      await this.deps.localStore.remove(FOLDER_CACHE_KEY);
      await this.deps.localStore.remove(COLLECTION_CACHE_KEY);
      await this.deps.localStore.remove(EQUIV_DOMAINS_KEY);
      await this.deps.localStore.remove(EQUIV_EXCLUDED_KEY);
      await this.deps.localStore.remove(ORG_PERMISSIONS_KEY);
    });
  }

  /** Rebuild the decrypted caches from the still-cached encrypted vault, only when unlocked. */
  private async rebuildDecryptedCachesIfUnlocked(): Promise<VaultListing | undefined> {
    const response = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!response) return undefined;
    if (!(await this.deps.session.loadUserKey())) return undefined; // locked — keep the caches purged
    return this.decryptAndPersist(response, this.identityEpoch());
  }

  private identityEpoch(): number {
    return this.deps.getIdentityEpoch?.() ?? 0;
  }

  private assertIdentityEpoch(expected: number): void {
    if (this.identityEpoch() !== expected) throw new AppError('error', 'Account changed during vault operation');
  }

  private async withCacheMutation<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.cacheMutationTail.then(operation, operation);
    this.cacheMutationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Build the equivalent-domain index from the built-in list plus any cached user-defined groups,
   *  dropping built-in groups the server's Domain Rules have excluded. */
  private async loadEquivalentIndex(): Promise<Map<string, number>> {
    const userGroups = (await this.deps.localStore.get<string[][]>(EQUIV_DOMAINS_KEY)) ?? [];
    const excludedDomains = (await this.deps.localStore.get<string[]>(EQUIV_EXCLUDED_KEY)) ?? [];
    return buildEquivalentDomainIndex(userGroups, excludedDomains);
  }

  /** Unwrap each organization key from the synced profile using the decrypted account private key. */
  private async buildOrgKeys(profile: SyncProfile | undefined): Promise<Map<string, SymmetricKey>> {
    const privateKey = await this.deps.session.loadPrivateKey();
    return buildOrgKeyMap(profile?.organizations, privateKey);
  }

  async listItems(): Promise<VaultListing> {
    let items = await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY);
    if (!items) {
      // Caches were purged on lock but the encrypted vault is still cached — rebuild locally on the
      // first unlocked read (no re-sync). Stays empty while locked (no user key).
      const rebuilt = await this.rebuildDecryptedCachesIfUnlocked();
      if (rebuilt) return rebuilt;
      items = [];
    }
    return {
      items,
      folders: (await this.deps.localStore.get<FolderSummary[]>(FOLDER_CACHE_KEY)) ?? [],
      collections: (await this.deps.localStore.get<CollectionSummary[]>(COLLECTION_CACHE_KEY)) ?? [],
      orgPermissions: (await this.deps.localStore.get<OrgPermission[]>(ORG_PERMISSIONS_KEY)) ?? [],
    };
  }

  async getSkippedOrgCount(): Promise<number> {
    return (await this.deps.localStore.get<number>(SKIPPED_ORG_KEY)) ?? 0;
  }

  /** Create a folder: encrypt the name under the user key, POST it, then re-sync the listing. */
  async createFolder(name: string): Promise<VaultListing> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    await this.deps.api.createFolder(token, await encryptToText(name, userKey));
    return this.sync();
  }

  /** Rename a folder: encrypt the new name under the user key, PUT it, then re-sync the listing. */
  async renameFolder(id: string, name: string): Promise<VaultListing> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    await this.deps.api.updateFolder(token, id, await encryptToText(name, userKey));
    return this.sync();
  }

  /** Delete a folder, then re-sync the listing (its ciphers fall back to No Folder server-side). */
  async deleteFolder(id: string): Promise<VaultListing> {
    const token = await this.requireToken();
    await this.deps.api.deleteFolder(token, id);
    return this.sync();
  }

  /** Resolve the org symmetric key from the cached profile, or fail closed. */
  private async requireOrgKey(orgId: string): Promise<SymmetricKey> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    const orgKeys = await this.buildOrgKeys(cache?.profile);
    const key = orgKeys.get(orgId);
    if (!key) throw new AppError('error', 'Organization key unavailable');
    return key;
  }

  /** Create a collection: encrypt the name under the org key, POST it, then re-sync. */
  async createCollection(orgId: string, name: string): Promise<VaultListing> {
    await this.requireUserKey();
    const token = await this.requireToken();
    const orgKey = await this.requireOrgKey(orgId);
    await this.deps.api.createCollection(token, orgId, await encryptToText(name, orgKey));
    return this.sync();
  }

  /** Rename a collection: fetch its current access, resend it with the new (org-key-encrypted) name. */
  async renameCollection(orgId: string, id: string, name: string): Promise<VaultListing> {
    await this.requireUserKey();
    const token = await this.requireToken();
    const orgKey = await this.requireOrgKey(orgId);
    const access = await this.deps.api.getCollectionDetails(token, orgId, id);
    await this.deps.api.updateCollection(token, orgId, id, await encryptToText(name, orgKey), { groups: access.groups, users: access.users });
    return this.sync();
  }

  /** Delete a collection, then re-sync (member ciphers keep existing, with the collection removed). */
  async deleteCollection(orgId: string, id: string): Promise<VaultListing> {
    await this.requireUserKey();
    const token = await this.requireToken();
    await this.deps.api.deleteCollection(token, orgId, id);
    return this.sync();
  }

  /** Assign an organization cipher to collections (all in the cipher's org), then re-sync. */
  async setCipherCollections(id: string, collectionIds: string[]): Promise<VaultListing> {
    await this.requireUserKey();
    const token = await this.requireToken();
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    const orgId = cache?.ciphers.find((c) => c.id === id)?.organizationId ?? undefined;
    if (!orgId) throw new AppError('error', 'Only organization items can be assigned to collections');
    const collections = (await this.deps.localStore.get<CollectionSummary[]>(COLLECTION_CACHE_KEY)) ?? [];
    const validIds = new Set(collections.filter((c) => c.organizationId === orgId).map((c) => c.id));
    if (!collectionIds.every((cid) => validIds.has(cid))) throw new AppError('error', 'Invalid collection for this item');
    await this.deps.api.updateCipherCollections(token, id, collectionIds);
    return this.sync();
  }

  /** Create a personal cipher: encrypt every field under the user key, POST it, then re-sync. */
  async createCipher(input: CipherInput): Promise<VaultListing> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    await this.deps.api.createCipher(token, await encryptCipher(input, userKey));
    return this.sync();
  }

  async updateCipher(id: string, input: CipherInput): Promise<VaultListing> {
    const token = await this.requireToken();
    const original = await this.findCachedCipher(id);
    // Old plaintext for the password-history diff; only meaningful when the cipher is cached.
    const previous = original ? await this.decryptCipherById(id) : undefined;
    // Encrypt under the SAME key the cipher already uses — the org key (or its per-cipher key) for an
    // org-owned item, the account key otherwise. Previously this always used the account UserKey, which
    // corrupted org ciphers (re-encrypting their fields under the wrong key while the server kept them
    // org-owned).
    const fieldKey = await this.cipherFieldKey(original);
    const request = await encryptCipher(input, fieldKey);
    // Carry forward server-managed fields the editor cannot represent (passkeys, the per-cipher key,
    // password history) so the wholesale PUT does not wipe them.
    mergeServerManagedFields(request, original);
    // Keep org ownership so the server keeps treating the item as org-owned under the org key.
    if (original?.organizationId) request.organizationId = original.organizationId;
    // When the password actually changed, archive the prior one and bump the revision date so the
    // security audit trail stays current (previously the history went stale on every edit here).
    this.appendPasswordHistory(request, original, input, previous);
    await this.deps.api.updateCipher(token, id, request);
    return this.sync();
  }

  /** The key a cipher's fields are encrypted under: its per-cipher key when present (unwrapped with the
   *  owning key), otherwise the owning key itself — the org key for org-owned items, else the account key. */
  private async cipherFieldKey(original: CipherResponse | undefined): Promise<SymmetricKey> {
    const owningKey = await this.cipherOwningKey(original);
    return original?.key ? unwrapSymmetricKey(original.key, owningKey) : owningKey;
  }

  /** The owning key for a cipher: the organization key for org-owned items, else the account UserKey. */
  private async cipherOwningKey(original: CipherResponse | undefined): Promise<SymmetricKey> {
    const userKey = await this.requireUserKey();
    if (!original?.organizationId) return userKey;
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    const orgKeys = await this.buildOrgKeys(cache?.profile);
    const orgKey = orgKeys.get(original.organizationId);
    if (!orgKey) throw new AppError('error', 'Organization key is unavailable; cannot edit this item');
    return orgKey;
  }

  /** Enforce the passkey trust boundary in the worker: the rpId must be a registrable-domain suffix of
   *  the frame origin's host (PSL-checked). The content-script bridge supplies `origin` from its own
   *  location, so the page cannot forge a cross-origin rpId. */
  private assertRpIdForOrigin(rpId: string, origin: string): void {
    let host: string;
    try { host = new URL(origin).hostname; } catch { throw new AppError('error', 'Invalid origin'); }
    if (!isRegistrableRpId(rpId, host)) throw new AppError('error', 'rpId is not valid for this origin');
  }

  /** Prepend the previous (still-encrypted) password to history and stamp passwordRevisionDate when the
   *  login password changed. Reuses the original EncString verbatim — no re-encryption of old secrets. */
  private appendPasswordHistory(
    request: CipherRequest,
    original: CipherResponse | undefined,
    input: CipherInput,
    previous: DecryptedCipher | undefined,
  ): void {
    if (request.type !== 1 || !original?.login?.password) return;
    const oldPassword = previous?.password;
    const newPassword = input.login?.password ?? '';
    if (!oldPassword || oldPassword === newPassword) return;
    const now = new Date((this.deps.now ?? Date.now)()).toISOString();
    request.passwordHistory = [
      { password: original.login.password, lastUsedDate: now },
      ...(request.passwordHistory ?? []),
    ].slice(0, MAX_PASSWORD_HISTORY);
    request.login = { ...(request.login ?? {}), passwordRevisionDate: now };
  }

  /** Look up the raw (still-encrypted) cipher from the last sync cache, for field-preserving updates. */
  private async findCachedCipher(id: string): Promise<CipherResponse | undefined> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    return cache?.ciphers.find((c) => c.id === id);
  }

  /**
   * Move a personal cipher into an organization (Bitwarden "share"): re-encrypt its fields under the
   * organization key and assign it to collections. Refuses items carrying a passkey or password history
   * (those secrets aren't in the editable input and would be dropped) so a move never loses data.
   */
  async shareCipher(id: string, organizationId: string, collectionIds: string[], masterPassword?: string): Promise<VaultListing> {
    if (!collectionIds.length) throw new AppError('error', 'Select at least one collection');
    const token = await this.requireToken();
    const original = await this.findCachedCipher(id);
    if (!original) throw new AppError('error', 'Item is not available');
    if (original.organizationId) throw new AppError('error', 'This item already belongs to an organization');
    if (original.login?.fido2Credentials?.length || original.passwordHistory?.length) {
      throw new AppError('error', 'Move items with passkeys or password history from the web vault to avoid data loss');
    }
    const orgKeys = await this.buildOrgKeys((await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY))?.profile);
    const orgKey = orgKeys.get(organizationId);
    if (!orgKey) throw new AppError('error', 'Organization key is unavailable');
    const input = await this.getCipherInput(id, masterPassword); // reprompt-gated; full editable plaintext
    if (!input) throw new AppError('error', 'This item type cannot be moved');
    const request = await encryptCipher(input, orgKey); // fresh encryption directly under the org key
    request.organizationId = organizationId;
    await this.deps.api.shareCipher(token, id, { cipher: request, collectionIds });
    return this.sync();
  }

  /** List the account's Sends, decrypted for display (name/text + the shareable access URL). */
  async listSends(serverUrl: string): Promise<SendSummary[]> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    const sends = await this.deps.api.listSends(token);
    const out: SendSummary[] = [];
    for (const send of sends) {
      try {
        out.push(await decryptSend(send, userKey, serverUrl));
      } catch {
        // Skip a send we cannot decrypt rather than failing the whole list.
      }
    }
    return out;
  }

  /** Create a text Send and return it decrypted (with its access URL) for immediate sharing. */
  async createTextSend(input: SendInput, serverUrl: string): Promise<SendSummary> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    const { request } = await buildTextSendRequest(input, userKey, this.deps.now ? { now: this.deps.now } : {});
    const created = await this.deps.api.createSend(token, request);
    return decryptSend(created, userKey, serverUrl);
  }

  /** Create a file Send: encrypt the file in the worker (EncArrayBuffer), upload via v2, return it
   *  decrypted with its access URL. The plaintext file never leaves the worker. */
  async createFileSend(input: SendInput, dataB64: string, fileName: string, serverUrl: string): Promise<SendSummary> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    const fileBytes = base64ToBytes(dataB64);
    const { request, encryptedFile, encryptedFileName } = await buildFileSendRequest(
      input, fileName, fileBytes, userKey, this.deps.now ? { now: this.deps.now } : {},
    );
    const { url, sendResponse } = await this.deps.api.createSendFile(token, request);
    try {
      await this.deps.api.uploadSendFileData(token, url, encryptedFile, encryptedFileName);
    } catch (err) {
      // The Send record exists but holds no blob — delete the orphan, then surface the original error.
      await this.deps.api.deleteSend(token, sendResponse.id).catch(() => {});
      throw err;
    }
    return decryptSend(sendResponse, userKey, serverUrl);
  }

  /** Edit an existing Send's metadata: re-encrypt under its existing send key and PUT. Password removal
   *  uses the dedicated endpoint. Returns the updated, decrypted summary. */
  async updateSend(id: string, input: UpdateSendInput, serverUrl: string): Promise<SendSummary> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    // The pre-PUT read is required — there is no single-send GET, and buildUpdateSendRequest needs the
    // existing send key / dates / file. The PUT response is the authoritative post-update record, so we
    // reuse it directly instead of re-listing every send.
    const existing = (await this.deps.api.listSends(token)).find((s) => s.id === id);
    if (!existing) throw new AppError('error', 'Send not found');
    const request = await buildUpdateSendRequest(existing, input, userKey, this.deps.now ? { now: this.deps.now } : {});
    const updated = await this.deps.api.updateSend(token, id, request);
    if (input.passwordMode === 'remove') {
      await this.deps.api.removeSendPassword(token, id);
      // The PUT response still carries the pre-removal password hash; clear it so the summary reports
      // passwordProtected: false to match the just-removed state.
      return decryptSend({ ...updated, password: null }, userKey, serverUrl);
    }
    return decryptSend(updated, userKey, serverUrl);
  }

  /** Delete a Send. */
  async deleteSend(id: string): Promise<void> {
    await this.deps.api.deleteSend(await this.requireToken(), id);
  }

  /** Permanently delete a cipher (no recovery), then re-sync. Used for "delete forever" from the trash. */
  async deleteCipher(id: string): Promise<VaultListing> {
    const token = await this.requireToken();
    await this.deps.api.deleteCipher(token, id);
    return this.sync();
  }

  /** Soft-delete a cipher: move it to the trash (recoverable), then re-sync. */
  async softDeleteCipher(id: string): Promise<VaultListing> {
    const token = await this.requireToken();
    await this.deps.api.softDeleteCipher(token, id);
    return this.sync();
  }

  /** Restore a cipher from the trash, then re-sync. */
  async restoreCipher(id: string): Promise<VaultListing> {
    const token = await this.requireToken();
    await this.deps.api.restoreCipher(token, id);
    return this.sync();
  }

  /**
   * Decrypt a cipher into editable plaintext for the editor. Unlike getCipherDetail this DOES include
   * secrets (password/totp/card number/etc.) because the editor must round-trip them.
   */
  async getCipherInput(id: string, masterPassword?: string): Promise<CipherInput | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted || decrypted.undecryptable || decrypted.type === 5) return undefined;
    await this.assertRepromptCleared(decrypted, masterPassword);
    const input: CipherInput = { type: decrypted.type, name: decrypted.name, favorite: decrypted.favorite };
    if (decrypted.reprompt) input.reprompt = true;
    if (decrypted.notes) input.notes = decrypted.notes;
    if (decrypted.folderId) input.folderId = decrypted.folderId;
    if (decrypted.type === 1) {
      const login: NonNullable<CipherInput['login']> = {};
      if (decrypted.username) login.username = decrypted.username;
      if (decrypted.password) login.password = decrypted.password;
      if (decrypted.totp) login.totp = decrypted.totp;
      if (decrypted.loginUris.length) login.uris = decrypted.loginUris;
      input.login = login;
    } else if (decrypted.type === 3 && decrypted.card) {
      input.card = decrypted.card;
    } else if (decrypted.type === 4 && decrypted.identity) {
      input.identity = decrypted.identity;
    }
    if (decrypted.fields?.length) input.fields = decrypted.fields;
    return input;
  }

  private async requireUserKey(): Promise<SymmetricKey> {
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    return userKey;
  }

  private async requireToken(): Promise<string> {
    await this.deps.auth.refreshIfNeeded();
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new AppError('locked', 'Not logged in');
    return auth.accessToken;
  }

  /**
   * Enforce master-password reprompt at the worker boundary: a reprompt-flagged cipher releases its
   * secrets only after the master password is re-verified. Throws 'reprompt_required' when the proof
   * is missing or wrong. This is the real security gate — UI prompts are convenience on top of it.
   */
  private async assertRepromptCleared(cipher: Pick<DecryptedCipher, 'reprompt'> | undefined, masterPassword?: string): Promise<void> {
    if (!cipher?.reprompt) return;
    if (!masterPassword || !(await this.deps.auth.verifyMasterPassword(masterPassword))) {
      throw new AppError('reprompt_required', 'Master password required to access this item');
    }
  }

  async getField(id: string, field: FieldName, masterPassword?: string): Promise<string | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted) return undefined;
    await this.assertRepromptCleared(decrypted, masterPassword);
    if (field === 'card.number') return decrypted.card?.number;
    if (field === 'card.code') return decrypted.card?.code;
    if (field === 'identity.ssn') return decrypted.identity?.ssn;
    if (field === 'identity.passportNumber') return decrypted.identity?.passportNumber;
    if (field === 'identity.licenseNumber') return decrypted.identity?.licenseNumber;
    return decrypted[field];
  }

  /** Decrypt one cipher for the detail view, with the sensitive secrets stripped out. */
  async getCipherDetail(id: string): Promise<DecryptedCipher | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted) return undefined;
    const safe: DecryptedCipher = { ...decrypted };
    delete safe.password;
    delete safe.totp;
    if (safe.card) {
      safe.card = { ...safe.card };
      delete safe.card.number;
      delete safe.card.code;
    }
    if (safe.identity) {
      safe.identity = { ...safe.identity };
      delete safe.identity.ssn;
      delete safe.identity.passportNumber;
      delete safe.identity.licenseNumber;
    }
    // Passkeys may ride along for display, but the private key (keyValue) must never cross the boundary.
    if (safe.fido2Credentials) {
      safe.fido2Credentials = safe.fido2Credentials.map((c) => ({ ...c, keyValue: '' }));
    }
    // Hidden custom-field values are secrets: mask them in the detail view (revealed on demand via
    // getCustomField). Text/Boolean/Linked fields are non-secret and ride along for display.
    if (safe.fields) {
      safe.fields = safe.fields.map((f) => {
        if (f.type !== 1) return f;
        const { value: _hidden, ...masked } = f; // drop the Hidden value entirely (not even undefined)
        void _hidden;
        return masked;
      });
    }
    return safe;
  }

  /** Reveal one Hidden custom field's value on demand (reprompt-gated like other secret fields). */
  async getCustomField(id: string, index: number, masterPassword?: string): Promise<string | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted) return undefined;
    await this.assertRepromptCleared(decrypted, masterPassword);
    return decrypted.fields?.[index]?.value;
  }

  /**
   * Download and decrypt one attachment inside the worker, returning the plaintext bytes (base64) and
   * file name for the popup to save. Reprompt-gated; the attachment key never crosses the boundary.
   */
  async getAttachment(cipherId: string, attachmentId: string, masterPassword?: string): Promise<{ fileName: string; dataB64: string }> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const cipher = cache.ciphers.find((c) => c.id === cipherId);
    const att = cipher?.attachments?.find((a) => a.id === attachmentId);
    if (!cipher || !att?.url || !att.key) throw new AppError('error', 'Attachment is unavailable');
    const decrypted = await this.decryptCipherById(cipherId);
    await this.assertRepromptCleared(decrypted, masterPassword);
    const cipherKey = await this.cipherFieldKey(cipher);
    const attachmentKey = await decryptAttachmentKey(att.key, cipherKey);
    const blob = await this.deps.api.downloadAttachment(att.url, await this.requireToken());
    const data = await decryptAttachmentFile(blob, attachmentKey);
    const fileName = decrypted?.attachments?.find((a) => a.id === attachmentId)?.fileName ?? 'attachment';
    return { fileName, dataB64: bytesToBase64(data) };
  }

  /** Encrypt a file under a fresh attachment key (wrapped by the cipher key) and upload it, then re-sync. */
  async addAttachment(cipherId: string, fileName: string, dataB64: string, masterPassword?: string): Promise<VaultListing> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    const cipher = cache?.ciphers.find((c) => c.id === cipherId);
    if (!cipher) throw new AppError('error', 'Item is not available');
    const decrypted = await this.decryptCipherById(cipherId);
    await this.assertRepromptCleared(decrypted, masterPassword);
    const token = await this.requireToken();
    const cipherKey = await this.cipherFieldKey(cipher);
    const attachmentKey = generateAttachmentKey();
    const wrappedKey = await wrapAttachmentKey(attachmentKey, cipherKey);
    const encrypted = await encryptAttachmentFile(base64ToBytes(dataB64), attachmentKey);
    const encryptedFileName = await encryptToText(fileName, cipherKey);
    await this.deps.api.uploadAttachment(token, cipherId, { key: wrappedKey, encryptedFileName, data: encrypted });
    return this.sync();
  }

  /** Delete one attachment from a cipher, then re-sync. */
  async deleteAttachment(cipherId: string, attachmentId: string): Promise<VaultListing> {
    const token = await this.requireToken();
    await this.deps.api.deleteAttachment(token, cipherId, attachmentId);
    return this.sync();
  }

  /** Decrypt a login's retained previous passwords (most-recent first), reprompt-gated. The decrypted
   *  values cross the boundary only on this explicit, user-initiated request. */
  async getPasswordHistory(id: string, masterPassword?: string): Promise<Array<{ password: string; lastUsedDate?: string }>> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const cipher = cache.ciphers.find((c) => c.id === id);
    if (!cipher?.passwordHistory?.length) return [];
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    await this.assertRepromptCleared(await decryptCipher(cipher, userKey, orgKeys), masterPassword);
    const baseKey = cipher.organizationId ? orgKeys.get(cipher.organizationId) : userKey;
    if (!baseKey) return [];
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, baseKey) : baseKey;
    const out: Array<{ password: string; lastUsedDate?: string }> = [];
    for (const entry of cipher.passwordHistory) {
      if (!entry.password) continue;
      try {
        const password = await decryptToText(entry.password, key);
        out.push(entry.lastUsedDate ? { password, lastUsedDate: entry.lastUsedDate } : { password });
      } catch {
        // Skip an entry we cannot decrypt rather than failing the whole history.
      }
    }
    return out;
  }

  /** Generate the current TOTP code for a login, decrypting the secret only inside the worker. */
  async getTotpCode(id: string, masterPassword?: string): Promise<TotpResult | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted?.totp) return undefined;
    await this.assertRepromptCleared(decrypted, masterPassword);
    return getTotp(decrypted.totp, (this.deps.now ?? Date.now)());
  }

  /** Live one-time codes for every non-trashed login carrying a TOTP secret, for the 2FA view. The
   *  secret is decrypted only in the worker; only the short code + timing + display name/username
   *  cross the boundary. Master-password-reprompt items are omitted — their code must be revealed
   *  explicitly through the item detail, not shown at a glance. */
  async listTotpCodes(): Promise<TotpListEntry[]> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const now = (this.deps.now ?? Date.now)();
    const out: TotpListEntry[] = [];
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || cipher.deletedDate || cipher.reprompt) continue;
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not drop every other code
      }
      if (!decrypted?.totp) continue;
      const totp = await getTotp(decrypted.totp, now);
      if (!totp) continue; // unparseable secret → skip rather than surface a broken row
      out.push(decrypted.username
        ? { id: decrypted.id, name: decrypted.name, username: decrypted.username, code: totp.code, period: totp.period, remaining: totp.remaining }
        : { id: decrypted.id, name: decrypted.name, code: totp.code, period: totp.period, remaining: totp.remaining });
    }
    return out;
  }

  /**
   * Sign a WebAuthn assertion for a stored passkey matching the request. Searches all logins for a
   * fido2Credential with the requested rpId (and allowed credentialId, if any), signs in the worker
   * with the credential's private key, and returns the assertion. The private key never leaves the worker.
   */
  async getPasskeyAssertion(params: {
    rpId: string;
    origin: string;
    challenge: string;
    allowedCredentialIds?: string[];
    userVerified?: boolean;
  }): Promise<PasskeyAssertion | undefined> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    const cred = await this.findPasskeyCredential(params.rpId, params.allowedCredentialIds);
    if (!cred) return undefined;
    const assertion = await signFido2Assertion(base64UrlToBytes(cred.keyValue), {
      rpId: params.rpId,
      origin: params.origin,
      challenge: params.challenge,
      counter: cred.counter,
      // Honest user-verification: the caller (content-script bridge) sets this from the RP's
      // userVerification requirement AND whether the user actually consented. Default false —
      // we must never assert UV that did not happen (previously this defaulted to true).
      userVerified: params.userVerified ?? false,
    });
    const result: PasskeyAssertion = { credentialId: cred.credentialId, ...assertion };
    if (cred.userHandle) result.userHandle = cred.userHandle;
    return result;
  }

  /** True when an unexpired stored passkey matches the rpId (and allowedCredentialIds, if given).
   *  Lets the page decide whether to prompt for consent without signing or revealing key material. */
  async hasMatchingPasskey(params: { rpId: string; origin: string; allowedCredentialIds?: string[] }): Promise<boolean> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    return (await this.findPasskeyCredential(params.rpId, params.allowedCredentialIds)) !== undefined;
  }

  /** Every stored passkey matching the rpId (and allowedCredentialIds, if given), for the get() account
   *  picker when a site has more than one. Display-only: the public credentialId plus the login's
   *  name/username (or the passkey's stored userName) — never the private keyValue. */
  async listPasskeyCandidates(params: { rpId: string; origin: string; allowedCredentialIds?: string[] }): Promise<PasskeyCandidate[]> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const out: PasskeyCandidate[] = [];
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || !cipher.login?.fido2Credentials?.length || cipher.deletedDate) continue;
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not poison the picker for all rpIds
      }
      for (const cred of decrypted?.fido2Credentials ?? []) {
        if (cred.rpId !== params.rpId) continue;
        if (params.allowedCredentialIds?.length && !params.allowedCredentialIds.includes(cred.credentialId)) continue;
        const username = decrypted!.username || cred.userName;
        out.push(username
          ? { credentialId: cred.credentialId, name: decrypted!.name, username }
          : { credentialId: cred.credentialId, name: decrypted!.name });
      }
    }
    return out;
  }

  /** Same-domain personal login items a new passkey could be saved into (for the create picker).
   *  Reads the decrypted summary cache — carries only id/name/username, never secrets. */
  async getPasskeyTargets(params: { rpId: string; origin: string }): Promise<PasskeyTarget[]> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    const summaries = (await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY)) ?? [];
    const out: PasskeyTarget[] = [];
    for (const s of summaries) {
      if (s.type !== 1 || s.organizationId || s.deletedDate || s.undecryptable) continue;
      const matches = s.loginUris.some((u) => {
        const host = getHostAndPort(u.uri)?.host;
        return host ? isRegistrableRpId(params.rpId, host) : false;
      });
      if (!matches) continue;
      out.push(s.username ? { id: s.id, name: s.name, username: s.username } : { id: s.id, name: s.name });
    }
    return out;
  }

  /** Generate an ES256 passkey, build its attestation, store it (new personal login OR appended to a
   *  same-domain personal login the picker offered), merge the returned cipher into the cache, and
   *  return the attestation. The private key never leaves the worker. */
  async createPasskey(params: {
    rpId: string; rpName?: string; userHandle?: string; userName?: string; userDisplayName?: string;
    challenge: string; origin: string; userVerified?: boolean; targetCipherId?: string;
  }): Promise<Fido2Registration> {
    this.assertRpIdForOrigin(params.rpId, params.origin);
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();

    const keypair = await generateFido2Keypair();
    const credentialIdB64 = bytesToBase64Url(keypair.credentialId);
    const { attestationObject, authData } = await buildAttestationObject({
      rpId: params.rpId, coseKey: keypair.coseKey, credentialId: keypair.credentialId,
      userVerified: params.userVerified ?? false,
    });
    const clientDataJSON = buildCreateClientDataJSON(params.challenge, params.origin);
    const newCredPlain = {
      credentialId: credentialIdB64,
      keyValue: bytesToBase64Url(keypair.pkcs8),
      rpId: params.rpId,
      counter: 0,
      ...(params.userHandle ? { userHandle: params.userHandle } : {}),
      ...(params.userName ? { userName: params.userName } : {}),
      ...(params.rpName ? { rpName: params.rpName } : {}),
      ...(params.userDisplayName ? { userDisplayName: params.userDisplayName } : {}),
    };

    let saved: CipherResponse;
    if (params.targetCipherId) {
      // Re-resolve the target through the same domain match — never trust the caller-supplied id.
      const allowed = await this.getPasskeyTargets({ rpId: params.rpId, origin: params.origin });
      if (!allowed.some((t) => t.id === params.targetCipherId)) throw new AppError('error', 'Target is not a valid target for this passkey');
      const original = await this.findCachedCipher(params.targetCipherId);
      if (!original || original.type !== 1 || original.organizationId || original.deletedDate) throw new AppError('error', 'Target is not a valid target for this passkey');
      // Append under the TARGET cipher's own field key (its per-cipher key, or the org/account key that
      // owns it) — NEVER the account UserKey. Encrypting under the wrong key would make an org or
      // per-cipher-keyed item's passkey (and everything else read with that field key) undecryptable.
      const fieldKey = await this.cipherFieldKey(original);
      const newCred = await encryptFido2Credential(newCredPlain, fieldKey);
      // Build the PUT body verbatim from the original CipherResponse (bypassing encryptCipher/
      // mergeServerManagedFields entirely) so every other field — and the OLD passkey EncStrings —
      // survive byte-for-byte. mergeServerManagedFields only carries a fixed allowlist of fields onto a
      // freshly-encrypted editor request; it was never meant to preserve an unedited item wholesale, and
      // using it here would still leave the new passkey dropped since it copies from `original`, not `request`.
      const request = this.cipherResponseToRequest(original);
      request.login = { ...(request.login ?? {}), fido2Credentials: [...(original.login?.fido2Credentials ?? []), newCred] };
      saved = await this.deps.api.updateCipher(token, params.targetCipherId, request);
    } else {
      const newCred = await encryptFido2Credential(newCredPlain, userKey);
      const request = await encryptCipher({
        type: 1, name: params.rpName || params.rpId,
        login: { ...(params.userName ? { username: params.userName } : {}), uris: [{ uri: `https://${params.rpId}` }] },
      }, userKey);
      request.login = { ...(request.login ?? {}), fido2Credentials: [newCred] };
      saved = await this.deps.api.createCipher(token, request);
    }

    // Best-effort cache merge so the new passkey is immediately assertable; a merge failure must NOT
    // fail the (already-succeeded) server write — the attestation is returned regardless, and the next
    // sync() will reconcile the cache. Deliberately NOT sync(): a failed post-write sync must not orphan
    // an already-saved cipher from the caller's point of view.
    try { await this.mergeCipherIntoCache(saved); } catch { /* next sync will reconcile */ }

    return {
      credentialId: credentialIdB64,
      attestationObject: bytesToBase64Url(attestationObject),
      clientDataJSON: bytesToBase64Url(new TextEncoder().encode(clientDataJSON)),
      authData: bytesToBase64Url(authData),
      publicKeySpki: bytesToBase64Url(keypair.publicKeySpki),
      publicKeyAlgorithm: -7,
    };
  }

  /** Build a wholesale CipherRequest from an existing CipherResponse, carrying every field verbatim
   *  (all already EncStrings). Used by the passkey-append path to avoid re-encrypting/dropping fields. */
  private cipherResponseToRequest(c: CipherResponse): CipherRequest {
    const req: CipherRequest = { type: c.type, name: c.name ?? '' };
    if (c.notes != null) req.notes = c.notes;
    if (c.favorite != null) req.favorite = c.favorite;
    if (c.folderId != null) req.folderId = c.folderId;
    if (c.organizationId != null) req.organizationId = c.organizationId;
    if (c.login != null) req.login = { ...c.login };
    if (c.card != null) req.card = c.card;
    if (c.identity != null) req.identity = c.identity;
    if (c.key != null) req.key = c.key;
    if (c.fields != null) req.fields = c.fields;
    if (c.passwordHistory != null) req.passwordHistory = c.passwordHistory;
    if (c.reprompt != null) req.reprompt = c.reprompt;
    return req;
  }

  /** Replace-or-insert a server cipher representation into the raw sync cache (so findPasskeyCredential
   *  sees it immediately). Does not rebuild the decrypted summary caches — the popup re-syncs. */
  private async mergeCipherIntoCache(cipher: CipherResponse): Promise<void> {
    const identityEpoch = this.identityEpoch();
    await this.withCacheMutation(async () => {
      const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
      if (!cache) return;
      const idx = cache.ciphers.findIndex((c) => c.id === cipher.id);
      if (idx >= 0) cache.ciphers[idx] = cipher; else cache.ciphers.push(cipher);
      this.assertIdentityEpoch(identityEpoch);
      await this.deps.localStore.set(VAULT_CACHE_KEY, cache);
    });
  }

  /** Find a stored passkey for the rpId. Returns the decrypted credential (incl. private key, which
   *  stays inside the worker) or undefined. Trashed ciphers never authenticate. */
  private async findPasskeyCredential(rpId: string, allowedCredentialIds?: string[]) {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || !cipher.login?.fido2Credentials?.length) continue;
      if (cipher.deletedDate) continue; // trashed passkeys must not authenticate
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not poison passkey lookup for all rpIds
      }
      for (const cred of decrypted?.fido2Credentials ?? []) {
        if (cred.rpId !== rpId) continue;
        if (allowedCredentialIds?.length && !allowedCredentialIds.includes(cred.credentialId)) continue;
        return cred;
      }
    }
    return undefined;
  }

  /**
   * Decrypt every login password in the worker and report only the problematic ones (weak or reused).
   * Passwords never cross the messaging boundary — only the id/name plus weak/reuse flags do.
   */
  async getPasswordHealth(): Promise<PasswordHealthEntry[]> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const inputs: PasswordHealthInput[] = [];
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1) continue;
      if (cipher.deletedDate) continue; // exclude trashed logins from the health report
      const decrypted = await decryptCipher(cipher, userKey, orgKeys);
      if (decrypted && !decrypted.undecryptable && decrypted.password) {
        inputs.push({ id: decrypted.id, name: decrypted.name, password: decrypted.password });
      }
    }
    return buildPasswordHealthReport(inputs).filter((entry) => entry.weak || entry.reuseCount > 1);
  }

  /** Check each login password against HIBP (k-anonymity). Decrypts in the worker, dedupes by password,
   *  looks up unique passwords (concurrency-limited), and returns only per-id breach counts. */
  async getPwnedReport(): Promise<Array<{ id: string; pwnedCount: number }>> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const logins: Array<{ id: string; password: string }> = [];
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || cipher.deletedDate) continue;
      const decrypted = await decryptCipher(cipher, userKey, orgKeys);
      if (decrypted && !decrypted.undecryptable && decrypted.password) logins.push({ id: decrypted.id, password: decrypted.password });
    }
    const unique = [...new Set(logins.map((l) => l.password))];
    const byPassword = new Map<string, number>();
    const LIMIT = 6;
    // Look up each unique password independently: one failed HIBP request must not abort the whole
    // report. Failed passwords are simply left out of byPassword (their ids get pwnedCount undefined,
    // never a misleading 0). Only a total failure — no lookup succeeded — surfaces as an error.
    for (let i = 0; i < unique.length; i += LIMIT) {
      const batch = unique.slice(i, i + LIMIT);
      const results = await Promise.allSettled(batch.map((pw) => pwnedCount(pw)));
      results.forEach((r, j) => {
        if (r.status === 'fulfilled') byPassword.set(batch[j]!, r.value);
      });
    }
    if (unique.length > 0 && byPassword.size === 0) {
      throw new AppError('error', 'Could not reach the breach service');
    }
    // Omit ids whose lookup failed so the UI shows them as unknown (undefined) rather than "0 breaches".
    return logins.flatMap((l) => {
      const count = byPassword.get(l.password);
      return count === undefined ? [] : [{ id: l.id, pwnedCount: count }];
    });
  }

  /**
   * Serialize the decrypted vault to a Bitwarden-compatible unencrypted JSON export. This deliberately
   * emits plaintext secrets — an explicit, user-initiated action — so callers must warn the user.
   */
  async exportVault(password?: string): Promise<string> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const folders = (await this.deps.localStore.get<FolderSummary[]>(FOLDER_CACHE_KEY)) ?? [];
    const decrypted: DecryptedCipher[] = [];
    for (const cipher of cache.ciphers) {
      if (cipher.deletedDate) continue; // trashed ciphers are excluded from exports
      const d = await decryptCipher(cipher, userKey, orgKeys);
      if (d && !d.undecryptable) decrypted.push(d);
    }
    const plaintext = buildExportJson(decrypted, folders);
    if (!password) return plaintext;
    // Password-protected export: wrap the plaintext payload under a password-derived key.
    const auth = await this.deps.session.getPersistedAuth();
    return buildEncryptedExportJson(plaintext, password, auth?.kdfIterations ?? 600_000);
  }

  /**
   * Import a Bitwarden export (plaintext JSON, password-protected JSON, or CSV): parse, then create one
   * cipher per item and re-sync once. `password` is required for an encrypted export.
   *
   * Each item is imported independently: a single item's failure (e.g. a server 4xx) is recorded and
   * the batch continues, rather than aborting on the first rejection. Aborting would leave the items
   * created before the failure silently committed while the caller sees a total failure and retries —
   * duplicating those successes. The final `sync()` runs whenever at least one item landed so the local
   * cache reflects what was imported. Returns the imported/failed counts and per-item failure detail.
   */
  async importVault(content: string, password?: string): Promise<ImportResult> {
    const inputs = await parseImport(content, password);
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    let imported = 0;
    const failures: ImportResult['failures'] = [];
    for (const [index, input] of inputs.entries()) {
      try {
        await this.deps.api.createCipher(token, await encryptCipher(input, userKey));
        imported++;
      } catch (err) {
        failures.push({ index, message: err instanceof Error ? err.message : String(err) });
      }
    }
    if (imported > 0) await this.sync();
    return { imported, failed: failures.length, failures };
  }

  private async decryptCipherById(id: string): Promise<DecryptedCipher | undefined> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    // AppError codes so the router maps these to 'sync_required' / 'locked' (a sync/unlock prompt),
    // not the generic 'error'. Messages kept verbatim for callers that match on them.
    if (!cache) throw new AppError('sync_required', 'vault is not synced');
    const cipher = cache.ciphers.find((c) => c.id === id);
    if (!cipher) return undefined;
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    return decryptCipher(cipher, userKey, orgKeys);
  }

  async clearCache(): Promise<void> {
    await this.withCacheMutation(async () => {
      await this.deps.localStore.remove(VAULT_CACHE_KEY);
      await this.deps.localStore.remove(SUMMARY_CACHE_KEY);
      await this.deps.localStore.remove(FOLDER_CACHE_KEY);
      await this.deps.localStore.remove(COLLECTION_CACHE_KEY);
      await this.deps.localStore.remove(EQUIV_DOMAINS_KEY);
      await this.deps.localStore.remove(EQUIV_EXCLUDED_KEY);
      await this.deps.localStore.remove(SKIPPED_ORG_KEY);
      await this.deps.localStore.remove(ORG_PERMISSIONS_KEY);
    });
  }

  async findAutofillCandidates(
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
  ): Promise<AutofillCandidate[]> {
    const summaries = await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY);
    if (!summaries) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const equivalentIndex = await this.loadEquivalentIndex();

    const candidates = summaries
      .filter((item) => item.type === 1 && !item.undecryptable && !item.deletedDate)
      .flatMap((item) => {
        const best = bestMatch(item.loginUris, frameUrl, defaultStrategy, equivalentIndex);
        if (!best) return [];
        const candidate: AutofillCandidate = {
          id: item.id,
          name: item.name,
          matchedUri: best.matchedUri,
          matchType: best.matchType,
          favorite: item.favorite,
        };
        if (item.username) candidate.username = item.username;
        if (item.reprompt) candidate.reprompt = true;
        return [candidate];
      });

    candidates.sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      const score = matchScore(a.matchType) - matchScore(b.matchType);
      if (score !== 0) return score;
      const name = a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
      if (name !== 0) return name;
      return (a.username ?? '').localeCompare(b.username ?? '', undefined, { sensitivity: 'base' });
    });
    return candidates;
  }

  /** List every card (type 3) or identity (type 4) as a fill candidate. No URL match — card/identity
   *  have no URI; authorization is the user's explicit popover selection. Never returns secrets. */
  async findFillItems(kind: FillKind): Promise<FillItemCandidate[]> {
    const summaries = await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY);
    if (!summaries) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const wantType = kind === 'card' ? 3 : 4;
    const items = summaries
      .filter((item) => item.type === wantType && !item.undecryptable && !item.deletedDate)
      .map((item) => {
        const candidate: FillItemCandidate = { id: item.id, name: item.name, favorite: item.favorite };
        if (item.subtitle) candidate.subtitle = item.subtitle;
        if (item.reprompt) candidate.reprompt = true;
        return candidate;
      });
    items.sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });
    return items;
  }

  /** Decrypt a card/identity for filling. Refuses kind/type mismatch and reprompt items; strips
   *  identity national-ID secrets. Card number + code ARE returned (released on explicit selection). */
  async getFillData(cipherId: string, kind: FillKind): Promise<CardFillData | IdentityFillData> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const cipher = cache.ciphers.find((c) => c.id === cipherId);
    if (!cipher) throw new AppError('denied', 'Autofill item is not allowed');
    const wantType = kind === 'card' ? 3 : 4;
    if (cipher.type !== wantType) throw new AppError('denied', 'Autofill item type mismatch');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const decrypted = await decryptCipher(cipher, userKey, orgKeys);
    if (!decrypted || decrypted.undecryptable) throw new AppError('denied', 'Autofill item is not allowed');
    if (decrypted.reprompt) throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    if (kind === 'card') {
      const c = decrypted.card ?? {};
      const out: CardFillData = {};
      if (c.cardholderName) out.cardholderName = c.cardholderName;
      if (c.number) out.number = c.number;
      if (c.expMonth) out.expMonth = c.expMonth;
      if (c.expYear) out.expYear = c.expYear;
      if (c.code) out.code = c.code;
      return out;
    }
    const i = decrypted.identity ?? {};
    const out: IdentityFillData = {};
    const fields: Array<keyof IdentityFillData> = [
      'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
      'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'username',
    ];
    for (const key of fields) {
      const value = (i as Record<string, string | undefined>)[key];
      if (value) out[key] = value;
    }
    return out;
  }

  async getAutofillCredentials(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
  ): Promise<AutofillCredentials> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const cipher = cache.ciphers.find((c) => c.id === cipherId);
    if (!cipher) throw new AppError('denied', 'Autofill item is not allowed for this page');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const decrypted = await decryptCipher(cipher, userKey, orgKeys);
    const equivalentIndex = await this.loadEquivalentIndex();
    if (!decrypted || decrypted.undecryptable || !bestMatch(decrypted.loginUris, frameUrl, defaultStrategy, equivalentIndex)) {
      throw new AppError('denied', 'Autofill item is not allowed for this page');
    }
    // Reprompt-protected items must not release secrets into the page. We deliberately do NOT collect
    // the master password inside a page-injected element; the user must verify in the extension popup.
    if (decrypted.reprompt) {
      throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    }
    const out: AutofillCredentials = {};
    if (decrypted.username) out.username = decrypted.username;
    if (decrypted.password) out.password = decrypted.password;
    // Generate the current TOTP code in the worker; the secret itself never crosses the boundary.
    if (decrypted.totp) {
      const totp = await getTotp(decrypted.totp, (this.deps.now ?? Date.now)());
      if (totp) out.totp = totp.code;
    }
    return out;
  }

  /**
   * Decide whether a just-submitted credential should be offered for save or update. Compares the
   * submitted username/password against logins that match the page (by URI). Reprompt-protected items
   * are skipped (never revealed or auto-updated from a page). Returns 'none' when already stored.
   */
  async checkSaveLogin(
    frameUrl: string,
    submitted: { username?: string; password: string },
    defaultStrategy: UriMatchStrategySetting,
  ): Promise<SaveLoginPrompt> {
    if (!submitted.password) return { action: 'none' };
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) return { action: 'none' };
    const summaries = (await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY)) ?? [];
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) return { action: 'none' };
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const equivalentIndex = await this.loadEquivalentIndex();
    const username = submitted.username?.trim().toLowerCase();
    // Pre-filter against the already-decrypted summary cache (name / loginUris / username) so the
    // expensive full decrypt — which materializes the password — runs only for URI + username matches,
    // not for every stored cipher on each form submit.
    for (const summary of summaries) {
      if (summary.type !== 1 || summary.deletedDate || summary.undecryptable || summary.reprompt) continue;
      if (!bestMatch(summary.loginUris, frameUrl, defaultStrategy, equivalentIndex)) continue;
      const sameUser = username ? summary.username?.trim().toLowerCase() === username : !summary.username;
      if (!sameUser) continue;
      const cipher = cache.ciphers.find((c) => c.id === summary.id);
      if (!cipher) continue;
      const decrypted = await decryptCipher(cipher, userKey, orgKeys);
      if (!decrypted || decrypted.undecryptable) continue;
      if (decrypted.password === submitted.password) return { action: 'none' }; // already stored
      return { action: 'update', cipherId: decrypted.id, name: decrypted.name };
    }
    // A new credential: offer to save it whether or not other accounts exist for this site.
    return { action: 'save', suggestedName: hostnameOf(frameUrl) };
  }

  /** Create a new login cipher from a captured submission, scoped to the submitting page's origin. */
  async saveLogin(frameUrl: string, username: string | undefined, password: string): Promise<VaultListing> {
    if (!password) throw new AppError('error', 'A password is required to save a login');
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    const origin = originOf(frameUrl);
    const input: CipherInput = {
      type: 1,
      name: hostnameOf(frameUrl),
      login: { password, ...(username ? { username } : {}), ...(origin ? { uris: [{ uri: origin }] } : {}) },
    };
    await this.deps.api.createCipher(token, await encryptCipher(input, userKey));
    return this.sync();
  }

  /**
   * Update an existing login's password from a captured submission. Verifies the target still matches
   * the submitting page (a page cannot rewrite arbitrary ciphers) and refuses reprompt-protected items.
   */
  async updateLoginPassword(
    cipherId: string,
    password: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
  ): Promise<VaultListing> {
    if (!password) throw new AppError('error', 'A password is required');
    const decrypted = await this.decryptCipherById(cipherId);
    if (!decrypted || decrypted.undecryptable || decrypted.type !== 1) {
      throw new AppError('denied', 'Login update is not allowed for this item');
    }
    if (decrypted.reprompt) throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    const equivalentIndex = await this.loadEquivalentIndex();
    if (!bestMatch(decrypted.loginUris, frameUrl, defaultStrategy, equivalentIndex)) {
      throw new AppError('denied', 'Login update is not allowed for this page');
    }
    const input = await this.getCipherInput(cipherId);
    if (!input) throw new AppError('denied', 'Login update is not allowed for this item');
    input.login = { ...(input.login ?? {}), password };
    return this.updateCipher(cipherId, input);
  }

  private async decryptSummaries(ciphers: CipherResponse[], userKey: SymmetricKey, orgKeys: Map<string, SymmetricKey>): Promise<CipherSummary[]> {
    const out: CipherSummary[] = [];
    for (const cipher of ciphers) {
      try {
        // Lightweight path: decrypt only the list-visible fields (name, URIs, username, subtitle) and
        // derive the presence flags from the encrypted shape. The password/TOTP/passkey key and other
        // secrets are decrypted on demand for detail/reveal/edit flows, never for the list.
        const summary = await decryptCipherSummary(cipher, userKey, orgKeys);
        if (summary) out.push(summary);
      } catch {
        out.push(undecryptableSummary(cipher));
      }
    }
    return out;
  }
}

// Score map mirrors uri-match.ts MATCH_SCORE (lower = better match)
const AUTOFILL_MATCH_SCORES: Record<UriMatchStrategySetting, number> = {
  [UriMatchStrategy.Exact]: 0,
  [UriMatchStrategy.StartsWith]: 1,
  [UriMatchStrategy.Host]: 2,
  [UriMatchStrategy.Domain]: 3,
  [UriMatchStrategy.RegularExpression]: 4,
  [UriMatchStrategy.Never]: 99,
};

function bestMatch(
  loginUris: CipherSummary['loginUris'],
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
  equivalentIndex?: Map<string, number>,
): UriMatchResult | undefined {
  return loginUris
    .map((uri) => matchLoginUri(uri, frameUrl, defaultStrategy, equivalentIndex))
    .filter((match): match is UriMatchResult => Boolean(match))
    .sort(compareMatchResults)[0];
}

function matchScore(matchType: UriMatchStrategySetting): number {
  return AUTOFILL_MATCH_SCORES[matchType] ?? 99;
}

/** The hostname of a URL (for a default cipher name), falling back to the raw string. */
function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname || url;
  } catch {
    return url;
  }
}

/** The origin of a URL (the saved login's URI), or undefined when it cannot be parsed. */
function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}
