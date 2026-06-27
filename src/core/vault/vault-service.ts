import type { ApiClient } from '../api/client.js';
import type { CipherResponse, SyncResponse } from '../api/types.js';
import type { SessionManager } from '../session/session-manager.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { CipherSummary, FieldName } from './models.js';
import { decryptCipher } from './decrypt.js';

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
              undecryptable: true,
            });
          } else {
            const summary: CipherSummary = {
              id: decrypted.id,
              type: decrypted.type,
              favorite: decrypted.favorite,
              name: decrypted.name,
              uris: decrypted.uris,
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
          undecryptable: true,
        });
      }
    }
    return out;
  }
}
