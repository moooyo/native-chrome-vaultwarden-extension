import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { symmetricKeyFromBytes, serializeSymmetricKey } from '../crypto/keys.js';
import { bytesToBase64, base64ToBytes } from '../crypto/encoding.js';

export type SessionState = 'loggedOut' | 'locked' | 'unlocked';

export interface PersistedAuth {
  email: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  protectedKey: string;
  kdf: 0;
  kdfIterations: number;
  /** UserKey-wrapped RSA PrivateKey (encType=2). Safe to persist; plaintext PKCS8 lives in session. */
  encPrivateKey?: string;
}

export interface SaveUnlockedInput extends PersistedAuth {
  userKey: SymmetricKey;
  /** Decrypted PKCS8 private key bytes; stored only in session storage. */
  privateKey?: Uint8Array;
}

export interface SessionManagerDeps {
  localStore: KeyValueStore;
  sessionStore: KeyValueStore;
}

const AUTH_KEY = 'auth';
const USER_KEY_KEY = 'userKey';
const PRIVATE_KEY_KEY = 'privateKey';
const PIN_KEY = 'pinProtectedUserKey';
const ACCOUNTS_KEY = 'accounts';
const REMEMBER_TOKENS_KEY = 'rememberDeviceTokens';

export interface AccountSummary {
  email: string;
  active: boolean;
}

export class SessionManager {
  constructor(private readonly deps: SessionManagerDeps) {}

  async getState(): Promise<SessionState> {
    const auth = await this.getPersistedAuth();
    if (!auth) return 'loggedOut';
    const userKey = await this.loadUserKey();
    return userKey ? 'unlocked' : 'locked';
  }

  async saveUnlocked(input: SaveUnlockedInput): Promise<void> {
    const { userKey, privateKey, ...auth } = input;
    await this.deps.localStore.set(AUTH_KEY, auth);
    await this.upsertAccount(auth);
    await this.saveUserKey(userKey);
    if (privateKey) {
      await this.savePrivateKey(privateKey);
    } else {
      await this.deps.sessionStore.remove(PRIVATE_KEY_KEY);
    }
  }

  async saveTokens(tokens: { accessToken: string; refreshToken: string; expiresAt: number }): Promise<void> {
    const auth = await this.getPersistedAuth();
    if (!auth) throw new Error('cannot save tokens without persisted auth');
    const updated = { ...auth, ...tokens };
    await this.deps.localStore.set(AUTH_KEY, updated);
    await this.upsertAccount(updated);
  }

  async getPersistedAuth(): Promise<PersistedAuth | undefined> {
    return this.deps.localStore.get<PersistedAuth>(AUTH_KEY);
  }

  /**
   * Update the master-password-derived material after a password or KDF change: the UserKey-wrapping
   * protectedKey, and the KDF iterations when changed. The UserKey itself is unchanged, so the cached
   * vault, the session UserKey, and any PIN-protected blob all stay valid.
   */
  async updateMasterKeyMaterial(update: { protectedKey: string; kdfIterations?: number }): Promise<void> {
    const auth = await this.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const updated: PersistedAuth = {
      ...auth,
      protectedKey: update.protectedKey,
      ...(update.kdfIterations !== undefined ? { kdfIterations: update.kdfIterations } : {}),
    };
    await this.deps.localStore.set(AUTH_KEY, updated);
    await this.upsertAccount(updated);
  }

  async loadUserKey(): Promise<SymmetricKey | undefined> {
    const stored = await this.deps.sessionStore.get<string>(USER_KEY_KEY);
    if (!stored) return undefined;
    return symmetricKeyFromBytes(base64ToBytes(stored));
  }

  async loadPrivateKey(): Promise<Uint8Array | undefined> {
    const stored = await this.deps.sessionStore.get<string>(PRIVATE_KEY_KEY);
    return stored ? base64ToBytes(stored) : undefined;
  }

  async lock(): Promise<void> {
    await this.deps.sessionStore.remove(USER_KEY_KEY);
    await this.deps.sessionStore.remove(PRIVATE_KEY_KEY);
  }

  /** Log out the active account: drop it from the registry, falling back to a remaining account
   *  (left locked) or fully logged out. Always clears the in-memory keys and PIN. */
  async logout(): Promise<void> {
    await this.lock();
    await this.deps.localStore.remove(PIN_KEY);
    const active = (await this.getPersistedAuth())?.email;
    const accounts = await this.loadAccounts();
    if (active) delete accounts[active];
    await this.persistAccountsAndActivate(accounts);
  }

  /** All logged-in accounts (the active one flagged), for the account switcher. */
  async listAccounts(): Promise<AccountSummary[]> {
    const accounts = await this.loadAccounts();
    const active = (await this.getPersistedAuth())?.email;
    return Object.keys(accounts).map((email) => ({ email, active: email === active }));
  }

  /** Make another logged-in account active. The vault is locked (PIN cleared) so the user re-unlocks it. */
  async switchAccount(email: string): Promise<void> {
    const accounts = await this.loadAccounts();
    const target = accounts[email];
    if (!target) throw new Error('unknown account');
    await this.lock();
    await this.deps.localStore.remove(PIN_KEY);
    await this.deps.localStore.set(AUTH_KEY, target);
  }

  /** Remove an account. If it was active, fall back to a remaining account (locked) or logged out. */
  async removeAccount(email: string): Promise<void> {
    const accounts = await this.loadAccounts();
    const wasActive = (await this.getPersistedAuth())?.email === email;
    delete accounts[email];
    if (wasActive) {
      await this.lock();
      await this.deps.localStore.remove(PIN_KEY);
      await this.persistAccountsAndActivate(accounts);
    } else {
      await this.deps.localStore.set(ACCOUNTS_KEY, accounts);
    }
  }

  /** Remove every authenticated account and unlock method while preserving device-level settings
   *  and remembered-2FA tokens. Used before changing the configured Vaultwarden server so tokens
   *  issued by the old server can never be sent to the new one. */
  async resetAllAccounts(): Promise<void> {
    await this.lock();
    await this.deps.localStore.remove(PIN_KEY);
    await this.deps.localStore.remove(AUTH_KEY);
    await this.deps.localStore.remove(ACCOUNTS_KEY);
  }

  private async loadAccounts(): Promise<Record<string, PersistedAuth>> {
    return (await this.deps.localStore.get<Record<string, PersistedAuth>>(ACCOUNTS_KEY)) ?? {};
  }

  private async upsertAccount(auth: PersistedAuth): Promise<void> {
    const accounts = await this.loadAccounts();
    accounts[auth.email] = auth;
    await this.deps.localStore.set(ACCOUNTS_KEY, accounts);
  }

  /** Persist the registry and point AUTH at a remaining account, or clear it when none remain. */
  private async persistAccountsAndActivate(accounts: Record<string, PersistedAuth>): Promise<void> {
    await this.deps.localStore.set(ACCOUNTS_KEY, accounts);
    const remaining = Object.values(accounts)[0];
    if (remaining) {
      await this.deps.localStore.set(AUTH_KEY, remaining);
    } else {
      await this.deps.localStore.remove(AUTH_KEY);
    }
  }

  /** PIN-protected UserKey (encType=2 wrapped by a PIN-derived key). Persisted to enable PIN unlock. */
  async savePinProtectedUserKey(blob: string): Promise<void> {
    await this.deps.localStore.set(PIN_KEY, blob);
  }

  async getPinProtectedUserKey(): Promise<string | undefined> {
    return this.deps.localStore.get<string>(PIN_KEY);
  }

  async removePinProtectedUserKey(): Promise<void> {
    await this.deps.localStore.remove(PIN_KEY);
  }

  /**
   * Device-remember 2FA tokens, keyed by (serverUrl, email). This is a 2FA-bypass credential of the
   * same sensitivity as refreshToken; it is intentionally NOT cleared on lock/logout (that is what
   * makes "remember this device" outlive a logout). Cleared only via removeRememberDeviceToken.
   */
  async getRememberDeviceToken(serverUrl: string, email: string): Promise<string | undefined> {
    const map = await this.loadRememberTokens();
    return map[rememberKey(serverUrl, email)];
  }

  async saveRememberDeviceToken(serverUrl: string, email: string, token: string): Promise<void> {
    const map = await this.loadRememberTokens();
    map[rememberKey(serverUrl, email)] = token;
    await this.deps.localStore.set(REMEMBER_TOKENS_KEY, map);
  }

  async removeRememberDeviceToken(serverUrl: string, email: string): Promise<void> {
    const map = await this.loadRememberTokens();
    if (!(rememberKey(serverUrl, email) in map)) return;
    delete map[rememberKey(serverUrl, email)];
    await this.deps.localStore.set(REMEMBER_TOKENS_KEY, map);
  }

  private async loadRememberTokens(): Promise<Record<string, string>> {
    return (await this.deps.localStore.get<Record<string, string>>(REMEMBER_TOKENS_KEY)) ?? {};
  }

  private async saveUserKey(userKey: SymmetricKey): Promise<void> {
    await this.deps.sessionStore.set(USER_KEY_KEY, bytesToBase64(serializeSymmetricKey(userKey)));
  }

  private async savePrivateKey(privateKey: Uint8Array): Promise<void> {
    await this.deps.sessionStore.set(PRIVATE_KEY_KEY, bytesToBase64(privateKey));
  }
}

/** Compose the per-(server,email) storage key. Newline separates the two (absent from URLs/emails). */
function rememberKey(serverUrl: string, email: string): string {
  return `${serverUrl}\n${email}`;
}
