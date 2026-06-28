import type { ApiClient } from '../api/client.js';
import type { CipherResponse, SyncProfile, SyncResponse } from '../api/types.js';
import type { SessionManager } from '../session/session-manager.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { CipherSummary, CipherInput, CollectionSummary, DecryptedCipher, FieldName, FolderSummary } from './models.js';
import { decryptCipher, decryptFolders, decryptCollections, buildOrgKeyMap } from './decrypt.js';
import { encryptCipher } from './encrypt.js';
import { getTotp, type TotpResult } from './totp.js';
import { encryptToText } from '../crypto/encstring.js';
import { AppError } from '../errors.js';
import type { AutofillCandidate, AutofillCredentials } from '../../messaging/protocol.js';
import { compareMatchResults, matchLoginUri, UriMatchStrategy, type UriMatchResult, type UriMatchStrategySetting } from './uri-match.js';

export interface VaultServiceDeps {
  api: ApiClient;
  auth: Pick<AuthService, 'refreshIfNeeded'>;
  session: SessionManager;
  localStore: KeyValueStore;
  now?: () => number;
}

const VAULT_CACHE_KEY = 'vaultCache';
const SUMMARY_CACHE_KEY = 'vaultSummaries';
const FOLDER_CACHE_KEY = 'vaultFolders';
const COLLECTION_CACHE_KEY = 'vaultCollections';
const SKIPPED_ORG_KEY = 'vaultSkippedOrgCount';

export interface VaultListing {
  items: CipherSummary[];
  folders: FolderSummary[];
  collections: CollectionSummary[];
}

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
    await this.deps.localStore.set(SKIPPED_ORG_KEY, skippedOrgCount);
    return { items, folders, collections };
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
    await this.deps.api.updateCipher(token, id, await encryptCipher(input, userKey));
    return this.sync();
  }

  async deleteCipher(id: string): Promise<VaultListing> {
    const token = await this.requireToken();
    await this.deps.api.deleteCipher(token, id);
    return this.sync();
  }

  /**
   * Decrypt a cipher into editable plaintext for the editor. Unlike getCipherDetail this DOES include
   * secrets (password/totp/card number/etc.) because the editor must round-trip them.
   */
  async getCipherInput(id: string): Promise<CipherInput | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted || decrypted.undecryptable || decrypted.type === 5) return undefined;
    const input: CipherInput = { type: decrypted.type, name: decrypted.name, favorite: decrypted.favorite };
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

  async getField(id: string, field: FieldName): Promise<string | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted) return undefined;
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
    return safe;
  }

  /** Generate the current TOTP code for a login, decrypting the secret only inside the worker. */
  async getTotpCode(id: string): Promise<TotpResult | undefined> {
    const decrypted = await this.decryptCipherById(id);
    if (!decrypted?.totp) return undefined;
    return getTotp(decrypted.totp, (this.deps.now ?? Date.now)());
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

    const candidates = summaries
      .filter((item) => item.type === 1 && !item.undecryptable)
      .flatMap((item) => {
        const best = bestMatch(item.loginUris, frameUrl, defaultStrategy);
        if (!best) return [];
        const candidate: AutofillCandidate = {
          id: item.id,
          name: item.name,
          matchedUri: best.matchedUri,
          matchType: best.matchType,
          favorite: item.favorite,
        };
        if (item.username) candidate.username = item.username;
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
    if (!decrypted || decrypted.undecryptable || !bestMatch(decrypted.loginUris, frameUrl, defaultStrategy)) {
      throw new AppError('denied', 'Autofill item is not allowed for this page');
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
            if (decrypted.organizationId) summary.organizationId = decrypted.organizationId;
            if (decrypted.folderId) summary.folderId = decrypted.folderId;
            if (decrypted.collectionIds) summary.collectionIds = decrypted.collectionIds;
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
): UriMatchResult | undefined {
  return loginUris
    .map((uri) => matchLoginUri(uri, frameUrl, defaultStrategy))
    .filter((match): match is UriMatchResult => Boolean(match))
    .sort(compareMatchResults)[0];
}

function matchScore(matchType: UriMatchStrategySetting): number {
  return AUTOFILL_MATCH_SCORES[matchType] ?? 99;
}
