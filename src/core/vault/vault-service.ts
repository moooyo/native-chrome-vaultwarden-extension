import type { ApiClient } from '../api/client.js';
import type { CipherResponse, SyncResponse } from '../api/types.js';
import type { SessionManager } from '../session/session-manager.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { CipherSummary, FieldName } from './models.js';
import { decryptCipher } from './decrypt.js';
import { AppError } from '../errors.js';
import type { AutofillCandidate, AutofillCredentials } from '../../messaging/protocol.js';
import { compareMatchResults, matchLoginUri, UriMatchStrategy, type UriMatchResult, type UriMatchStrategySetting } from './uri-match.js';

export interface VaultServiceDeps {
  api: ApiClient;
  auth: Pick<AuthService, 'refreshIfNeeded'>;
  session: SessionManager;
  localStore: KeyValueStore;
}

const VAULT_CACHE_KEY = 'vaultCache';
const SUMMARY_CACHE_KEY = 'vaultSummaries';

export class VaultService {
  constructor(private readonly deps: VaultServiceDeps) {}

  async sync(): Promise<CipherSummary[]> {
    await this.deps.auth.refreshIfNeeded();
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const response = await this.deps.api.sync(auth.accessToken);
    await this.deps.localStore.set(VAULT_CACHE_KEY, response);
    const summaries = await this.decryptSummaries(response.ciphers);
    await this.deps.localStore.set(SUMMARY_CACHE_KEY, summaries);
    return summaries;
  }

  async listItems(): Promise<CipherSummary[]> {
    return (await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY)) ?? [];
  }

  async getField(id: string, field: FieldName): Promise<string | undefined> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new Error('vault is not synced');
    const cipher = cache.ciphers.find((c) => c.id === id);
    if (!cipher) return undefined;
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const decrypted = await decryptCipher(cipher, userKey);
    return decrypted?.[field];
  }

  async clearCache(): Promise<void> {
    await this.deps.localStore.remove(VAULT_CACHE_KEY);
    await this.deps.localStore.remove(SUMMARY_CACHE_KEY);
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
    const decrypted = await decryptCipher(cipher, userKey);
    if (!decrypted || decrypted.undecryptable || !bestMatch(decrypted.loginUris, frameUrl, defaultStrategy)) {
      throw new AppError('denied', 'Autofill item is not allowed for this page');
    }
    const out: AutofillCredentials = {};
    if (decrypted.username) out.username = decrypted.username;
    if (decrypted.password) out.password = decrypted.password;
    return out;
  }

  private async decryptSummaries(ciphers: CipherResponse[]): Promise<CipherSummary[]> {
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const out: CipherSummary[] = [];
    for (const cipher of ciphers) {
      try {
        const decrypted = await decryptCipher(cipher, userKey);
        if (decrypted) {
          if (decrypted.undecryptable) {
            out.push({
              id: decrypted.id,
              type: decrypted.type,
              favorite: decrypted.favorite,
              name: '(undecryptable)',
              uris: [],
              loginUris: [],
              undecryptable: true,
            });
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
            out.push(summary);
          }
        }
      } catch {
        out.push({
          id: cipher.id,
          type: cipher.type,
          favorite: cipher.favorite ?? false,
          name: '(undecryptable)',
          uris: [],
          loginUris: [],
          undecryptable: true,
        });
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
): UriMatchResult | undefined {
  return loginUris
    .map((uri) => matchLoginUri(uri, frameUrl, defaultStrategy))
    .filter((match): match is UriMatchResult => Boolean(match))
    .sort(compareMatchResults)[0];
}

function matchScore(matchType: UriMatchStrategySetting): number {
  return AUTOFILL_MATCH_SCORES[matchType] ?? 99;
}
