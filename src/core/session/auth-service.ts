import type { ApiClient, PasswordLoginInput, PasswordLoginResult } from '../api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey, assertKdfIterationsFloor } from '../crypto/kdf.js';
import { unwrapSymmetricKey, decryptPrivateKey, type SymmetricKey } from '../crypto/keys.js';
import { encryptToBytes } from '../crypto/encstring.js';
import { buildRegistration } from '../crypto/registration.js';
import type { SessionManager, SessionState } from './session-manager.js';

export type AuthResult =
  | { kind: 'unlocked' }
  | { kind: 'twoFactor'; providers: Array<0 | 1>; token?: string };

export interface AuthServiceDeps {
  api: ApiClient;
  session: SessionManager;
  now?: () => number;
}

interface PendingLogin {
  email: string;
  masterPasswordHash: string;
  stretchedMasterKey: Awaited<ReturnType<typeof stretchMasterKey>>;
  kdfIterations: number;
  twoFactorToken?: string;
}

export class AuthService {
  private pendingLogin: PendingLogin | undefined;
  private readonly now: () => number;

  constructor(private readonly deps: AuthServiceDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  /** Register a new PBKDF2 account (client-side key generation), then auto-log-in. */
  async register(input: { email: string; masterPassword: string; name?: string }): Promise<AuthResult> {
    const email = input.email.trim().toLowerCase();
    const reg = await buildRegistration(email, input.masterPassword);
    await this.deps.api.register({
      email,
      masterPasswordHash: reg.masterPasswordHash,
      key: reg.key,
      keys: reg.keys,
      kdf: reg.kdf,
      kdfIterations: reg.kdfIterations,
      ...(input.name ? { name: input.name } : {}),
    });
    return this.login({ email, masterPassword: input.masterPassword });
  }

  async login(input: { email: string; masterPassword: string }): Promise<AuthResult> {
    const email = input.email.trim().toLowerCase();
    const prelogin = await this.deps.api.prelogin(email);
    if (prelogin.kdf !== 0) throw new Error('Argon2id accounts are not supported in this MVP');
    assertKdfIterationsFloor(prelogin.kdfIterations);
    const masterKey = await deriveMasterKey(input.masterPassword, email, prelogin.kdfIterations);
    const masterPasswordHash = await deriveMasterPasswordHash(masterKey, input.masterPassword);
    const stretchedMasterKey = await stretchMasterKey(masterKey);
    const result = await this.deps.api.passwordLogin({ email, masterPasswordHash });
    return this.finishPasswordLogin({
      result,
      pending: { email, masterPasswordHash, stretchedMasterKey, kdfIterations: prelogin.kdfIterations },
    });
  }

  async submitTwoFactor(input: { provider: 0 | 1; code: string; remember?: boolean }): Promise<AuthResult> {
    if (!this.pendingLogin) throw new Error('no pending 2FA login');
    const loginInput: PasswordLoginInput = {
      email: this.pendingLogin.email,
      masterPasswordHash: this.pendingLogin.masterPasswordHash,
      twoFactorProvider: input.provider,
      twoFactorToken: input.code,
    };
    if (input.remember !== undefined) loginInput.remember = input.remember;
    const result = await this.deps.api.passwordLogin(loginInput);
    return this.finishPasswordLogin({ result, pending: this.pendingLogin });
  }

  async sendEmailCode(): Promise<void> {
    if (!this.pendingLogin?.twoFactorToken) throw new Error('no pending 2FA token');
    await this.deps.api.sendEmailLogin({
      email: this.pendingLogin.email,
      twoFactorToken: this.pendingLogin.twoFactorToken,
    });
  }

  async unlock(masterPassword: string): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const masterKey = await deriveMasterKey(masterPassword, auth.email, auth.kdfIterations);
    const userKey = await unwrapSymmetricKey(auth.protectedKey, await stretchMasterKey(masterKey));
    const privateKey = auth.encPrivateKey ? await decryptPrivateKey(auth.encPrivateKey, userKey) : undefined;
    await this.deps.session.saveUnlocked(privateKey ? { ...auth, userKey, privateKey } : { ...auth, userKey });
  }

  /**
   * Enable PIN unlock: wrap the current UserKey under a PIN-derived key and persist it. The PIN is
   * low-entropy, so the persisted blob is brute-forceable offline (PBKDF2 raises the cost) — an
   * explicit convenience/security trade-off, matching Bitwarden's PIN unlock. Requires an unlocked vault.
   */
  async setPin(pin: string): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const pinKey = await this.derivePinKey(pin, auth.email, auth.kdfIterations);
    const raw = new Uint8Array(64);
    raw.set(userKey.encKey, 0);
    raw.set(userKey.macKey, 32);
    await this.deps.session.savePinProtectedUserKey(await encryptToBytes(raw, pinKey));
  }

  /** Unlock with a PIN (no network). A wrong PIN fails the MAC check and throws. */
  async unlockWithPin(pin: string): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const blob = await this.deps.session.getPinProtectedUserKey();
    if (!blob) throw new Error('PIN unlock is not enabled');
    const pinKey = await this.derivePinKey(pin, auth.email, auth.kdfIterations);
    const userKey = await unwrapSymmetricKey(blob, pinKey);
    const privateKey = auth.encPrivateKey ? await decryptPrivateKey(auth.encPrivateKey, userKey) : undefined;
    await this.deps.session.saveUnlocked(privateKey ? { ...auth, userKey, privateKey } : { ...auth, userKey });
  }

  async disablePin(): Promise<void> {
    await this.deps.session.removePinProtectedUserKey();
  }

  async isPinEnabled(): Promise<boolean> {
    return Boolean(await this.deps.session.getPinProtectedUserKey());
  }

  private async derivePinKey(pin: string, email: string, iterations: number): Promise<SymmetricKey> {
    return stretchMasterKey(await deriveMasterKey(pin, email, iterations));
  }

  getState(): Promise<SessionState> {
    return this.deps.session.getState();
  }

  lock(): Promise<void> {
    return this.deps.session.lock();
  }

  logout(): Promise<void> {
    this.pendingLogin = undefined;
    return this.deps.session.logout();
  }

  async refreshIfNeeded(skewMs = 60_000): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) return;
    if (auth.expiresAt - this.now() > skewMs) return;
    const refreshed = await this.deps.api.refresh(auth.refreshToken);
    await this.deps.session.saveTokens({
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token,
      expiresAt: this.now() + refreshed.expires_in * 1000,
    });
  }

  private async finishPasswordLogin(input: {
    result: PasswordLoginResult;
    pending: PendingLogin;
  }): Promise<AuthResult> {
    if (input.result.kind === 'twoFactor') {
      const supported = input.result.providers.filter((p): p is 0 | 1 => p === 0 || p === 1);
      this.pendingLogin = input.result.token
        ? { ...input.pending, twoFactorToken: input.result.token }
        : input.pending;
      return input.result.token
        ? { kind: 'twoFactor', providers: supported, token: input.result.token }
        : { kind: 'twoFactor', providers: supported };
    }
    const data = input.result.data;
    if (data.Kdf !== undefined && data.Kdf !== 0) {
      throw new Error('Argon2id accounts are not supported in this MVP');
    }
    if (data.KdfIterations !== undefined) {
      // Defense-in-depth: the token response must not weaken or disagree with the prelogin value.
      assertKdfIterationsFloor(data.KdfIterations);
      if (data.KdfIterations !== input.pending.kdfIterations) {
        throw new Error('Server changed KDF settings during login; refusing to continue.');
      }
    }
    const userKey = await unwrapSymmetricKey(data.Key, input.pending.stretchedMasterKey);
    const privateKey = data.PrivateKey ? await decryptPrivateKey(data.PrivateKey, userKey) : undefined;
    const saveInput = {
      email: input.pending.email,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: this.now() + data.expires_in * 1000,
      protectedKey: data.Key,
      kdf: 0 as const,
      kdfIterations: input.pending.kdfIterations,
      userKey,
      // Persist only the userKey-wrapped (encrypted) blob; plaintext PKCS8 is set via privateKey below.
      ...(data.PrivateKey ? { encPrivateKey: data.PrivateKey } : {}),
    };
    await this.deps.session.saveUnlocked(
      privateKey ? { ...saveInput, privateKey } : saveInput,
    );
    this.pendingLogin = undefined;
    return { kind: 'unlocked' };
  }
}
