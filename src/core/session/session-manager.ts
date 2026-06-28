import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
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
    await this.deps.localStore.set(AUTH_KEY, { ...auth, ...tokens });
  }

  async getPersistedAuth(): Promise<PersistedAuth | undefined> {
    return this.deps.localStore.get<PersistedAuth>(AUTH_KEY);
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

  async logout(): Promise<void> {
    await this.deps.sessionStore.remove(USER_KEY_KEY);
    await this.deps.sessionStore.remove(PRIVATE_KEY_KEY);
    await this.deps.localStore.remove(AUTH_KEY);
    await this.deps.localStore.remove(PIN_KEY);
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

  private async saveUserKey(userKey: SymmetricKey): Promise<void> {
    const raw = new Uint8Array(64);
    raw.set(userKey.encKey, 0);
    raw.set(userKey.macKey, 32);
    await this.deps.sessionStore.set(USER_KEY_KEY, bytesToBase64(raw));
  }

  private async savePrivateKey(privateKey: Uint8Array): Promise<void> {
    await this.deps.sessionStore.set(PRIVATE_KEY_KEY, bytesToBase64(privateKey));
  }
}
