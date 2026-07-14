import type { ApiClient, PasswordLoginInput, PasswordLoginResult } from '../api/client.js';
import { ApiHttpError } from '../api/client.js';
import { AppError } from '../errors.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey, assertKdfIterationsFloor } from '../crypto/kdf.js';
import { unwrapSymmetricKey, decryptPrivateKey, serializeSymmetricKey, type SymmetricKey } from '../crypto/keys.js';
import { encryptToBytes } from '../crypto/encstring.js';
import { buildRegistration } from '../crypto/registration.js';
import type { SessionManager, SessionState } from './session-manager.js';
import { rotateAccountKey as runRotation } from './key-rotation.js';

export type AuthResult =
  | { kind: 'unlocked' }
  | { kind: 'twoFactor'; providers: number[]; token?: string };

export interface AuthServiceDeps {
  api: ApiClient;
  session: SessionManager;
  /** Current configured server URL (for per-(server,email) remember-token keying). */
  serverUrlProvider?: () => Promise<string | undefined>;
  /** Clears data derived from the active account whenever that identity changes. */
  onIdentityChanged?: () => Promise<void>;
  /** Runs after a lock (not a logout) so callers can purge decrypted metadata left on disk. */
  onLock?: () => Promise<void>;
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
  private activeRefresh: { key: string; promise: Promise<void> } | undefined;
  private serverResetPending = false;
  private refreshAttempts = 0;
  private refreshIdleResolvers: Array<() => void> = [];
  private readonly now: () => number;

  constructor(private readonly deps: AuthServiceDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  /** The configured server URL, or undefined when none is set (remember-token keying is then skipped). */
  private currentServerUrl(): Promise<string | undefined> {
    return this.deps.serverUrlProvider ? this.deps.serverUrlProvider() : Promise.resolve(undefined);
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
    const pending: PendingLogin = { email, masterPasswordHash, stretchedMasterKey, kdfIterations: prelogin.kdfIterations };

    // If this (server, email) has a remembered device token, try to reuse it to skip 2FA.
    const serverUrl = await this.currentServerUrl();
    const remembered = serverUrl ? await this.deps.session.getRememberDeviceToken(serverUrl, email) : undefined;
    if (serverUrl && remembered) {
      return this.loginWithRememberToken({ email, masterPasswordHash, serverUrl, token: remembered, pending });
    }

    const result = await this.deps.api.passwordLogin({ email, masterPasswordHash });
    return this.finishPasswordLogin({ result, pending });
  }

  /**
   * Reuse a stored device-remember token (two_factor_provider=5) to skip the 2FA challenge. Best-effort:
   *  - success  → finishPasswordLogin (which captures the server's freshly ROTATED token)
   *  - twoFactor → the token is stale; the server already returned the REAL providers, so clear the
   *               token and drive the normal 2FA screen from THIS SAME result (no second round-trip,
   *               and no duplicate email for email-2FA accounts)
   *  - throws    → any other rejection (non-2FA 400, 5xx): clear the token and retry ONCE without it,
   *               guaranteeing the fallback to the normal login/2FA flow regardless of error shape
   */
  private async loginWithRememberToken(args: {
    email: string;
    masterPasswordHash: string;
    serverUrl: string;
    token: string;
    pending: PendingLogin;
  }): Promise<AuthResult> {
    let result: PasswordLoginResult;
    try {
      result = await this.deps.api.passwordLogin({
        email: args.email,
        masterPasswordHash: args.masterPasswordHash,
        twoFactorProvider: 5,
        twoFactorToken: args.token,
        remember: true,
      });
    } catch {
      await this.deps.session.removeRememberDeviceToken(args.serverUrl, args.email);
      const retry = await this.deps.api.passwordLogin({ email: args.email, masterPasswordHash: args.masterPasswordHash });
      return this.finishPasswordLogin({ result: retry, pending: args.pending });
    }
    if (result.kind === 'twoFactor') {
      await this.deps.session.removeRememberDeviceToken(args.serverUrl, args.email);
    }
    return this.finishPasswordLogin({ result, pending: args.pending });
  }

  async submitTwoFactor(input: { provider: number; code: string; remember?: boolean }): Promise<AuthResult> {
    // pendingLogin lives only in the (ephemeral) service-worker memory. If the SW was torn down while the
    // user fetched an emailed code, it is gone — surface a specific signal so the UI resets to the login
    // screen rather than throwing an opaque error. Do NOT persist the master-key material.
    if (!this.pendingLogin) throw new AppError('session_expired', 'Your sign-in session expired. Re-enter your password.');
    const loginInput: PasswordLoginInput = {
      email: this.pendingLogin.email,
      masterPasswordHash: this.pendingLogin.masterPasswordHash,
      twoFactorProvider: input.provider,
      twoFactorToken: input.code.trim(),
    };
    if (input.remember !== undefined) loginInput.remember = input.remember;
    const result = await this.deps.api.passwordLogin(loginInput);
    return this.finishPasswordLogin({ result, pending: this.pendingLogin });
  }

  async sendEmailCode(): Promise<void> {
    if (!this.pendingLogin) throw new AppError('session_expired', 'Your sign-in session expired. Re-enter your password.');
    if (!this.pendingLogin.twoFactorToken) throw new Error('no pending 2FA token');
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
    await this.deps.session.savePinProtectedUserKey(await encryptToBytes(serializeSymmetricKey(userKey), pinKey));
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

  /**
   * Change the master password without re-encrypting the vault: the UserKey is unchanged, only its
   * wrapping (protectedKey) and the password hash change. Verifies the current password first, sends
   * the re-wrapped key + new hash to the server, then updates the local persisted material so the next
   * unlock uses the new password. Requires an unlocked vault and the current password.
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<void> {
    const { auth, userKey, oldMasterKey } = await this.requireForRewrap(currentPassword);
    const newMasterKey = await deriveMasterKey(newPassword, auth.email, auth.kdfIterations);
    const newProtectedKey = await this.wrapUserKey(userKey, await stretchMasterKey(newMasterKey));
    await this.deps.api.changePassword(auth.accessToken, {
      masterPasswordHash: await deriveMasterPasswordHash(oldMasterKey, currentPassword),
      newMasterPasswordHash: await deriveMasterPasswordHash(newMasterKey, newPassword),
      key: newProtectedKey,
    });
    await this.deps.session.updateMasterKeyMaterial({ protectedKey: newProtectedKey });
  }

  /**
   * Rotate the account UserKey (re-encrypts the whole vault server-side and logs out on success).
   * Delegates to the `rotateAccountKey` orchestrator; see `./key-rotation.js` for the full flow.
   */
  async rotateAccountKey(masterPassword: string): Promise<void> {
    await runRotation(masterPassword, {
      api: this.deps.api,
      session: {
        getPersistedAuth: () => this.deps.session.getPersistedAuth(),
        loadUserKey: () => this.deps.session.loadUserKey(),
        loadPrivateKey: () => this.deps.session.loadPrivateKey(),
        logout: () => this.logout(),
      },
      verifyMasterPassword: (pw) => this.verifyMasterPassword(pw),
    });
  }

  /**
   * Change the KDF iteration count (PBKDF2): re-derive from the same password with the new iterations,
   * re-wrap the UserKey, and update the server + local material. Argon2 is out of scope.
   */
  async changeKdfIterations(currentPassword: string, newIterations: number): Promise<void> {
    assertKdfIterationsFloor(newIterations);
    const { auth, userKey, oldMasterKey } = await this.requireForRewrap(currentPassword);
    if (newIterations === auth.kdfIterations) throw new Error('KDF iterations are already set to that value');
    const newMasterKey = await deriveMasterKey(currentPassword, auth.email, newIterations);
    const newProtectedKey = await this.wrapUserKey(userKey, await stretchMasterKey(newMasterKey));
    await this.deps.api.changeKdf(auth.accessToken, {
      kdf: 0,
      kdfIterations: newIterations,
      masterPasswordHash: await deriveMasterPasswordHash(oldMasterKey, currentPassword),
      newMasterPasswordHash: await deriveMasterPasswordHash(newMasterKey, currentPassword),
      key: newProtectedKey,
    });
    await this.deps.session.updateMasterKeyMaterial({ protectedKey: newProtectedKey, kdfIterations: newIterations });
  }

  /** Shared preamble for password/KDF re-wrap: require unlock + verify the current password. */
  private async requireForRewrap(currentPassword: string) {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const oldMasterKey = await deriveMasterKey(currentPassword, auth.email, auth.kdfIterations);
    try {
      await unwrapSymmetricKey(auth.protectedKey, await stretchMasterKey(oldMasterKey));
    } catch {
      throw new Error('Current master password is incorrect');
    }
    return { auth, userKey, oldMasterKey };
  }

  /** Wrap the 64-byte UserKey (enc‖mac) under a stretched master key as an encType=2 EncString. */
  private async wrapUserKey(userKey: SymmetricKey, stretched: SymmetricKey): Promise<string> {
    return encryptToBytes(serializeSymmetricKey(userKey), stretched);
  }

  /**
   * Verify the master password against the persisted account WITHOUT changing lock state. Re-derives
   * the master key and confirms it still unwraps the stored UserKey (the unwrap MAC-checks, so a wrong
   * password fails). Used to satisfy master-password reprompt. Returns false on mismatch or no account;
   * never throws for a wrong password.
   */
  async verifyMasterPassword(masterPassword: string): Promise<boolean> {
    if (!masterPassword) return false;
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) return false;
    try {
      const masterKey = await deriveMasterKey(masterPassword, auth.email, auth.kdfIterations);
      await unwrapSymmetricKey(auth.protectedKey, await stretchMasterKey(masterKey));
      return true;
    } catch {
      return false;
    }
  }

  async isPinEnabled(): Promise<boolean> {
    return Boolean(await this.deps.session.getPinProtectedUserKey());
  }

  /** All logged-in accounts (active flagged), for the account switcher. */
  listAccounts() {
    return this.deps.session.listAccounts();
  }

  /** Activate another logged-in account; the vault locks so the user re-unlocks it. */
  async switchAccount(email: string): Promise<void> {
    const normalized = email.trim().toLowerCase();
    this.pendingLogin = undefined;
    const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
    if (normalized !== activeBefore) await this.notifyIdentityChanged();
    await this.deps.session.switchAccount(normalized);
  }

  async removeAccount(email: string): Promise<void> {
    const normalized = email.trim().toLowerCase();
    this.pendingLogin = undefined;
    const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
    const serverUrl = await this.currentServerUrl();
    if (serverUrl) await this.deps.session.removeRememberDeviceToken(serverUrl, normalized);
    if (normalized === activeBefore) await this.notifyIdentityChanged();
    await this.deps.session.removeAccount(normalized);
  }

  /** Drop all account-scoped authentication before switching the configured server. */
  async resetForServerChange(): Promise<void> {
    this.pendingLogin = undefined;
    this.serverResetPending = true;
    try {
      await this.waitForRefreshIdle();
      await this.notifyIdentityChanged();
      await this.deps.session.resetAllAccounts();
    } finally {
      this.serverResetPending = false;
    }
  }

  /** Forget this device's remembered-2FA token for `email` (defaults to the current account). No-op
   *  when no server is configured or no account/email is resolvable. */
  async forgetDevice(email?: string): Promise<void> {
    const serverUrl = await this.currentServerUrl();
    if (!serverUrl) return;
    const target = await this.resolveRememberEmail(email);
    if (!target) return;
    await this.deps.session.removeRememberDeviceToken(serverUrl, target);
  }

  /** Whether a remembered-2FA token is stored for `email` (defaults to the current account). */
  async isDeviceRemembered(email?: string): Promise<boolean> {
    const serverUrl = await this.currentServerUrl();
    if (!serverUrl) return false;
    const target = await this.resolveRememberEmail(email);
    if (!target) return false;
    return Boolean(await this.deps.session.getRememberDeviceToken(serverUrl, target));
  }

  /** Normalize an explicit email, or fall back to the current persisted account's email. */
  private async resolveRememberEmail(email?: string): Promise<string | undefined> {
    if (email) return email.trim().toLowerCase();
    return (await this.deps.session.getPersistedAuth())?.email;
  }

  private async derivePinKey(pin: string, email: string, iterations: number): Promise<SymmetricKey> {
    return stretchMasterKey(await deriveMasterKey(pin, email, iterations));
  }

  getState(): Promise<SessionState> {
    return this.deps.session.getState();
  }

  async lock(): Promise<void> {
    await this.deps.session.lock();
    // Best-effort: purge decrypted metadata left on disk. Must never turn a lock into a failure.
    try {
      await this.deps.onLock?.();
    } catch {
      /* ignore */
    }
  }

  async logout(): Promise<void> {
    this.pendingLogin = undefined;
    await this.notifyIdentityChanged();
    await this.deps.session.logout();
  }

  async refreshIfNeeded(skewMs = 60_000): Promise<void> {
    if (this.serverResetPending) return;
    this.refreshAttempts++;
    try {
      if (this.serverResetPending) return;
      await this.runRefreshIfNeeded(skewMs);
    } finally {
      this.refreshAttempts--;
      if (this.refreshAttempts === 0) {
        for (const resolve of this.refreshIdleResolvers.splice(0)) resolve();
      }
    }
  }

  private async runRefreshIfNeeded(skewMs: number): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) return;
    if (auth.expiresAt - this.now() > skewMs) return;
    const serverUrl = await this.currentServerUrl();
    const key = `${serverUrl ?? ''}\n${auth.email}\n${auth.refreshToken}`;
    if (this.activeRefresh?.key === key) return this.activeRefresh.promise;

    const promise = (async () => {
      let refreshed;
      try {
        refreshed = await this.deps.api.refresh(auth.refreshToken);
      } catch (err) {
        // A permanently-invalid refresh token (revoked/expired) returns 400 invalid_grant (or 401). The
        // session is dead and every later request would fail opaquely, so clear it and drive re-login.
        // Transient errors (network, 5xx) are rethrown so the caller can retry with the token intact.
        if (err instanceof ApiHttpError && (err.status === 400 || err.status === 401)) {
          await this.logout();
          return;
        }
        throw err;
      }
      const [current, currentServerUrl] = await Promise.all([
        this.deps.session.getPersistedAuth(),
        this.currentServerUrl(),
      ]);
      if (currentServerUrl !== serverUrl || current?.email !== auth.email || current.refreshToken !== auth.refreshToken) return;
      await this.deps.session.saveTokens({
        accessToken: refreshed.access_token,
        refreshToken: refreshed.refresh_token,
        expiresAt: this.now() + refreshed.expires_in * 1000,
      });
    })();
    this.activeRefresh = { key, promise };
    try {
      await promise;
    } finally {
      if (this.activeRefresh?.promise === promise) this.activeRefresh = undefined;
    }
  }

  private waitForRefreshIdle(): Promise<void> {
    if (this.refreshAttempts === 0) return Promise.resolve();
    return new Promise((resolve) => this.refreshIdleResolvers.push(resolve));
  }

  private async notifyIdentityChanged(): Promise<void> {
    await this.deps.onIdentityChanged?.();
  }

  private async finishPasswordLogin(input: {
    result: PasswordLoginResult;
    pending: PendingLogin;
  }): Promise<AuthResult> {
    if (input.result.kind === 'twoFactor') {
      // Surface every provider the server advertises (Authenticator, Email, Duo, YubiKey, FIDO2, …);
      // the UI picks how to collect each one's token.
      const providers = input.result.providers;
      this.pendingLogin = input.result.token
        ? { ...input.pending, twoFactorToken: input.result.token }
        : input.pending;
      return input.result.token
        ? { kind: 'twoFactor', providers, token: input.result.token }
        : { kind: 'twoFactor', providers };
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
    const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
    if (input.pending.email !== activeBefore) await this.notifyIdentityChanged();
    await this.deps.session.saveUnlocked(
      privateKey ? { ...saveInput, privateKey } : saveInput,
    );
    this.pendingLogin = undefined;
    // Capture the device-remember token whenever the server returns one. The server only includes it
    // when remember was in play — a first-time opt-in, or a reuse that auto-rotated it — so
    // capture-on-presence covers both first capture and every subsequent rotation. Keyed by (server,
    // email); undefined server (none configured) skips silently. This is a best-effort convenience:
    // the login already succeeded and is persisted unlocked above, so a storage-write failure here
    // (e.g. chrome.storage.local rejecting) must never surface as a login failure. Swallow errors.
    try {
      const rememberServerUrl = await this.currentServerUrl();
      if (rememberServerUrl && data.TwoFactorToken) {
        await this.deps.session.saveRememberDeviceToken(rememberServerUrl, input.pending.email, data.TwoFactorToken);
      }
    } catch {
      /* best-effort token capture; never fail the login over it */
    }
    return { kind: 'unlocked' };
  }
}
