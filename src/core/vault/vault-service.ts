import type { ApiClient } from '../api/client.js';
import type { CipherRequest, CipherResponse, SyncProfile, SyncResponse } from '../api/types.js';
import type { SessionManager } from '../session/session-manager.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { CipherSummary, CipherInput, CollectionSummary, DecryptedCipher, FieldName, FolderSummary } from './models.js';
import { decryptCipher, decryptFolders, decryptCollections, buildOrgKeyMap } from './decrypt.js';
import { encryptCipher, mergeServerManagedFields } from './encrypt.js';
import { getTotp, type TotpResult } from './totp.js';
import { signFido2Assertion, type PasskeyAssertion } from './fido2.js';
import { encryptToText, decryptToText } from '../crypto/encstring.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import { base64UrlToBytes } from '../crypto/encoding.js';
import { buildPasswordHealthReport, type PasswordHealthEntry, type PasswordHealthInput } from './password-health.js';
import { buildExportJson, parseImportJson } from './vault-io.js';
import { AppError } from '../errors.js';
import type { AutofillCandidate, AutofillCredentials } from '../../messaging/protocol.js';
import { compareMatchResults, matchLoginUri, UriMatchStrategy, type UriMatchResult, type UriMatchStrategySetting } from './uri-match.js';
import { buildEquivalentDomainIndex } from './equivalent-domains.js';

export interface VaultServiceDeps {
  api: ApiClient;
  auth: Pick<AuthService, 'refreshIfNeeded' | 'verifyMasterPassword'>;
  session: SessionManager;
  localStore: KeyValueStore;
  now?: () => number;
}

const VAULT_CACHE_KEY = 'vaultCache';
const SUMMARY_CACHE_KEY = 'vaultSummaries';
const FOLDER_CACHE_KEY = 'vaultFolders';
const COLLECTION_CACHE_KEY = 'vaultCollections';
const EQUIV_DOMAINS_KEY = 'vaultEquivalentDomains';
const EQUIV_EXCLUDED_KEY = 'vaultExcludedDomains';
const SKIPPED_ORG_KEY = 'vaultSkippedOrgCount';
/** Cap on retained prior passwords (the server may trim further). Keeps the audit trail bounded. */
const MAX_PASSWORD_HISTORY = 20;

export interface VaultListing {
  items: CipherSummary[];
  folders: FolderSummary[];
  collections: CollectionSummary[];
}

/** The save/update decision for a captured form submission. */
export type SaveLoginPrompt =
  | { action: 'none' }
  | { action: 'save'; suggestedName: string }
  | { action: 'update'; cipherId: string; name: string };

export class VaultService {
  constructor(private readonly deps: VaultServiceDeps) {}

  async sync(): Promise<VaultListing> {
    await this.deps.auth.refreshIfNeeded();
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const response = await this.deps.api.sync(auth.accessToken);
    await this.deps.localStore.set(VAULT_CACHE_KEY, response);
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const orgKeys = await this.buildOrgKeys(response.profile);
    const items = await this.decryptSummaries(response.ciphers, userKey, orgKeys);
    const folders = await decryptFolders(response.folders, userKey);
    const collections = await decryptCollections(response.collections, orgKeys);
    // Org ciphers whose key could not be unwrapped (e.g. locked private key) are surfaced to the UI.
    const skippedOrgCount = response.ciphers.filter((c) => c.organizationId && !orgKeys.has(c.organizationId)).length;
    await this.deps.localStore.set(SUMMARY_CACHE_KEY, items);
    await this.deps.localStore.set(FOLDER_CACHE_KEY, folders);
    await this.deps.localStore.set(COLLECTION_CACHE_KEY, collections);
    await this.deps.localStore.set(EQUIV_DOMAINS_KEY, response.domains?.equivalentDomains ?? []);
    // Domains of global equivalence groups the user has switched off (Domain Rules), so the client
    // stops treating them as equivalent for autofill.
    const excludedDomains = (response.domains?.globalEquivalentDomains ?? [])
      .filter((g) => g.excluded)
      .flatMap((g) => g.domains ?? []);
    await this.deps.localStore.set(EQUIV_EXCLUDED_KEY, excludedDomains);
    await this.deps.localStore.set(SKIPPED_ORG_KEY, skippedOrgCount);
    return { items, folders, collections };
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
    return {
      items: (await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY)) ?? [],
      folders: (await this.deps.localStore.get<FolderSummary[]>(FOLDER_CACHE_KEY)) ?? [],
      collections: (await this.deps.localStore.get<CollectionSummary[]>(COLLECTION_CACHE_KEY)) ?? [],
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

  /** Create a personal cipher: encrypt every field under the user key, POST it, then re-sync. */
  async createCipher(input: CipherInput): Promise<VaultListing> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    await this.deps.api.createCipher(token, await encryptCipher(input, userKey));
    return this.sync();
  }

  async updateCipher(id: string, input: CipherInput): Promise<VaultListing> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    const original = await this.findCachedCipher(id);
    // Old plaintext for the password-history diff; only meaningful when the cipher is cached.
    const previous = original ? await this.decryptCipherById(id) : undefined;
    const request = await encryptCipher(input, userKey);
    // Carry forward server-managed fields the editor cannot represent (passkeys, the per-cipher key,
    // password history) so the wholesale PUT does not wipe them.
    mergeServerManagedFields(request, original);
    // When the password actually changed, archive the prior one and bump the revision date so the
    // security audit trail stays current (previously the history went stale on every edit here).
    this.appendPasswordHistory(request, original, input, previous);
    await this.deps.api.updateCipher(token, id, request);
    return this.sync();
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
  async hasMatchingPasskey(params: { rpId: string; allowedCredentialIds?: string[] }): Promise<boolean> {
    return (await this.findPasskeyCredential(params.rpId, params.allowedCredentialIds)) !== undefined;
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
      const decrypted = await decryptCipher(cipher, userKey, orgKeys);
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

  /**
   * Serialize the decrypted vault to a Bitwarden-compatible unencrypted JSON export. This deliberately
   * emits plaintext secrets — an explicit, user-initiated action — so callers must warn the user.
   */
  async exportVault(): Promise<string> {
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
    return buildExportJson(decrypted, folders);
  }

  /** Import a Bitwarden unencrypted JSON export: create one cipher per parsed item, then re-sync once. */
  async importVault(json: string): Promise<number> {
    const inputs = parseImportJson(json);
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    let imported = 0;
    for (const input of inputs) {
      await this.deps.api.createCipher(token, await encryptCipher(input, userKey));
      imported++;
    }
    if (imported > 0) await this.sync();
    return imported;
  }

  private async decryptCipherById(id: string): Promise<DecryptedCipher | undefined> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new Error('vault is not synced');
    const cipher = cache.ciphers.find((c) => c.id === id);
    if (!cipher) return undefined;
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    return decryptCipher(cipher, userKey, orgKeys);
  }

  async clearCache(): Promise<void> {
    await this.deps.localStore.remove(VAULT_CACHE_KEY);
    await this.deps.localStore.remove(SUMMARY_CACHE_KEY);
    await this.deps.localStore.remove(FOLDER_CACHE_KEY);
    await this.deps.localStore.remove(COLLECTION_CACHE_KEY);
    await this.deps.localStore.remove(EQUIV_DOMAINS_KEY);
    await this.deps.localStore.remove(EQUIV_EXCLUDED_KEY);
    await this.deps.localStore.remove(SKIPPED_ORG_KEY);
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
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) return { action: 'none' };
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const equivalentIndex = await this.loadEquivalentIndex();
    const username = submitted.username?.trim().toLowerCase();
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || cipher.deletedDate) continue;
      const decrypted = await decryptCipher(cipher, userKey, orgKeys);
      if (!decrypted || decrypted.undecryptable || decrypted.reprompt) continue;
      if (!bestMatch(decrypted.loginUris, frameUrl, defaultStrategy, equivalentIndex)) continue;
      const sameUser = username ? decrypted.username?.trim().toLowerCase() === username : !decrypted.username;
      if (!sameUser) continue;
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
        const decrypted = await decryptCipher(cipher, userKey, orgKeys);
        if (decrypted) {
          if (decrypted.undecryptable) {
            const summary: CipherSummary = {
              id: decrypted.id,
              type: decrypted.type,
              favorite: decrypted.favorite,
              name: '(undecryptable)',
              uris: [],
              loginUris: [],
              undecryptable: true,
            };
            if (decrypted.organizationId) summary.organizationId = decrypted.organizationId;
            if (decrypted.folderId) summary.folderId = decrypted.folderId;
            if (decrypted.collectionIds) summary.collectionIds = decrypted.collectionIds;
            if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
            out.push(summary);
          } else {
            const summary: CipherSummary = {
              id: decrypted.id,
              type: decrypted.type,
              favorite: decrypted.favorite,
              name: decrypted.name,
              uris: decrypted.uris,
              loginUris: decrypted.loginUris,
            };
            if (decrypted.username) summary.username = decrypted.username;
            if (decrypted.totp) summary.hasTotp = true;
            if (decrypted.fido2Credentials?.length) summary.hasPasskey = true;
            if (decrypted.reprompt) summary.reprompt = true;
            if (decrypted.passwordHistoryCount) summary.passwordHistoryCount = decrypted.passwordHistoryCount;
            if (decrypted.organizationId) summary.organizationId = decrypted.organizationId;
            if (decrypted.folderId) summary.folderId = decrypted.folderId;
            if (decrypted.collectionIds) summary.collectionIds = decrypted.collectionIds;
            if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
            const subtitle = summarySubtitle(decrypted);
            if (subtitle) summary.subtitle = subtitle;
            out.push(summary);
          }
        }
      } catch {
        const summary: CipherSummary = {
          id: cipher.id,
          type: cipher.type,
          favorite: cipher.favorite ?? false,
          name: '(undecryptable)',
          uris: [],
          loginUris: [],
          undecryptable: true,
        };
        if (cipher.organizationId) summary.organizationId = cipher.organizationId;
        if (cipher.folderId) summary.folderId = cipher.folderId;
        if (cipher.collectionIds?.length) summary.collectionIds = cipher.collectionIds;
        if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
        out.push(summary);
      }
    }
    return out;
  }
}

/** Non-sensitive list subtitle for card (brand) and identity (full name). Never returns secrets. */
function summarySubtitle(decrypted: DecryptedCipher): string | undefined {
  if (decrypted.type === 3) return decrypted.card?.brand;
  if (decrypted.type === 4) {
    const name = [decrypted.identity?.firstName, decrypted.identity?.lastName].filter(Boolean).join(' ');
    return name || undefined;
  }
  return undefined;
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
