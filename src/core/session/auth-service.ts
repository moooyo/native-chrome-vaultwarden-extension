import type { ApiClient, PasswordLoginInput, PasswordLoginResult } from '../api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../crypto/kdf.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
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

  async login(input: { email: string; masterPassword: string }): Promise<AuthResult> {
    const email = input.email.trim().toLowerCase();
    const prelogin = await this.deps.api.prelogin(email);
    if (prelogin.kdf !== 0) throw new Error('Argon2id accounts are not supported in this MVP');
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
    await this.deps.session.saveUnlocked({ ...auth, userKey });
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
    const userKey = await unwrapSymmetricKey(data.Key, input.pending.stretchedMasterKey);
    const saveInput = {
      email: input.pending.email,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: this.now() + data.expires_in * 1000,
      protectedKey: data.Key,
      kdf: 0 as const,
      kdfIterations: input.pending.kdfIterations,
      userKey,
    };
    await this.deps.session.saveUnlocked(
      data.PrivateKey ? { ...saveInput, privateKey: data.PrivateKey } : saveInput,
    );
    this.pendingLogin = undefined;
    return { kind: 'unlocked' };
  }
}
