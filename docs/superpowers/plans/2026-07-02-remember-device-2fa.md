# Remember-Device 2FA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user opt into "remember this device" on a 2FA login so the extension captures the server's device-remember token, persists it per-(server,email) across logout, and reuses it (`two_factor_provider=5`) on the next login to skip the 2FA challenge — staying in sync as the server rotates the token, with always-reachable revocation.

**Architecture:** `SessionManager` gains a per-(server,email) token store (survives logout/lock). `AuthService` captures the token on every successful login that returns one (`finishPasswordLogin`, handles first-capture AND rotation), reuses a stored token at the front of `login()` with a best-effort fallback to normal 2FA, and exposes `forgetDevice`/`isDeviceRemembered`. The protocol/router gain two messages; the popup gains a remember checkbox and two Forget affordances (account panel + login screen).

**Tech Stack:** TypeScript, MV3 extension (service worker + popup), Vitest, esbuild. Vaultwarden 1.35.0 server.

## Global Constraints

- **Argon2 is out of scope** — do not touch the existing `kdf !== 0` fail-close guards; this feature only runs on PBKDF2 accounts.
- **Vault secrets (UserKey/master password/plaintext) never leave the service worker.** The remember token is NOT a vault secret; it is a 2FA-bypass device credential of the same sensitivity as `refreshToken`, stored in `localStore`.
- **Capture rule:** save the token whenever a **success** response carries a non-empty `TwoFactorToken`, **regardless of the remember input flag**. The server only returns one when remember was in play (first opt-in) or when a reuse auto-rotates it; capture-on-presence therefore covers first-capture AND every rotation. Never gate capture on `remember===true`.
- **Reuse rule:** a stored token is replayed with `two_factor_provider=5`, `remember: true`. The reuse attempt is **best-effort**: on a `twoFactor` result, clear the token and drive the 2FA screen from **that same result** (its `providers` are already the real challenge — do NOT re-send a second `passwordLogin`); on ANY thrown error, clear the token and retry once WITHOUT it.
- **Remember provider id = 5.**
- **Per-(server,email) keying:** the token map key is `` `${serverUrl}\n${emailLower}` ``. A token is only ever replayed to the server that issued it.
- **Never clear the token on logout/lock** (that would kill the feature); clear only on explicit `forgetDevice` and on `removeAccount`.
- **Emails are normalized by the caller** (`trim().toLowerCase()`), matching the existing convention in `login()`/`removeAccount`.
- All new UI copy is English. TDD, DRY, YAGNI, frequent commits.

---

### Task 1: SessionManager per-(server,email) token store

**Files:**
- Modify: `src/core/session/session-manager.ts`
- Test: `src/core/session/session-manager.test.ts`

**Interfaces:**
- Consumes: nothing new (uses the existing `localStore: KeyValueStore`).
- Produces:
  - `getRememberDeviceToken(serverUrl: string, email: string): Promise<string | undefined>`
  - `saveRememberDeviceToken(serverUrl: string, email: string, token: string): Promise<void>`
  - `removeRememberDeviceToken(serverUrl: string, email: string): Promise<void>`
  - New local-storage key `rememberDeviceTokens` holding `Record<string, string>` keyed by `` `${serverUrl}\n${email}` ``.

- [ ] **Step 1: Write the failing tests**

Add this `describe` block at the end of `describe('SessionManager', …)` in `src/core/session/session-manager.test.ts` (before its closing `});`):

```ts
  describe('remember-device tokens', () => {
    const SERVER_A = 'https://a.example';
    const SERVER_B = 'https://b.example';
    function newSm() {
      return new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    }

    it('saves, reads, and removes a token keyed by (server, email)', async () => {
      const sm = newSm();
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBeUndefined();
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-1');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-1');
      await sm.removeRememberDeviceToken(SERVER_A, 'u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBeUndefined();
    });

    it('isolates tokens by server and by email', async () => {
      const sm = newSm();
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-A');
      await sm.saveRememberDeviceToken(SERVER_B, 'u@x.com', 'tok-B');
      await sm.saveRememberDeviceToken(SERVER_A, 'other@x.com', 'tok-O');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-A');
      expect(await sm.getRememberDeviceToken(SERVER_B, 'u@x.com')).toBe('tok-B');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'other@x.com')).toBe('tok-O');
      // Removing one leaves the others intact.
      await sm.removeRememberDeviceToken(SERVER_A, 'u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBeUndefined();
      expect(await sm.getRememberDeviceToken(SERVER_B, 'u@x.com')).toBe('tok-B');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'other@x.com')).toBe('tok-O');
    });

    it('overwrites the token on re-save (rotation)', async () => {
      const sm = newSm();
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-old');
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-new');
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-new');
    });

    it('survives logout and lock (the token is not a session secret)', async () => {
      const sm = newSm();
      await sm.saveUnlocked({
        email: 'u@x.com', accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000, userKey,
      });
      await sm.saveRememberDeviceToken(SERVER_A, 'u@x.com', 'tok-1');
      await sm.lock();
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-1');
      await sm.logout();
      expect(await sm.getRememberDeviceToken(SERVER_A, 'u@x.com')).toBe('tok-1');
    });

    it('removing a token that was never saved is a no-op', async () => {
      const sm = newSm();
      await expect(sm.removeRememberDeviceToken(SERVER_A, 'nobody@x.com')).resolves.toBeUndefined();
    });
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/core/session/session-manager.test.ts`
Expected: FAIL — `sm.getRememberDeviceToken is not a function`.

- [ ] **Step 3: Implement the store**

In `src/core/session/session-manager.ts`, add the storage key next to the other key constants (after `const ACCOUNTS_KEY = 'accounts';` at line 35):

```ts
const REMEMBER_TOKENS_KEY = 'rememberDeviceTokens';
```

Then add these methods inside the `SessionManager` class (place them right after `removePinProtectedUserKey()` near line 183):

```ts
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
```

And add this module-level helper at the bottom of the file (after the class, near line 195):

```ts
/** Compose the per-(server,email) storage key. Newline separates the two (absent from URLs/emails). */
function rememberKey(serverUrl: string, email: string): string {
  return `${serverUrl}\n${email}`;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/core/session/session-manager.test.ts`
Expected: PASS (all existing SessionManager tests + the 5 new ones).

- [ ] **Step 5: Commit**

```bash
git add src/core/session/session-manager.ts src/core/session/session-manager.test.ts
git commit -m "feat: SessionManager per-(server,email) remember-device token store"
```

---

### Task 2: AuthService — serverUrl dependency + capture-on-success

**Files:**
- Modify: `src/core/session/auth-service.ts`
- Test: `src/core/session/auth-service.test.ts`

**Interfaces:**
- Consumes: `SessionManager.saveRememberDeviceToken` (Task 1); `settings.getServerUrl` shape `() => Promise<string | undefined>` (wired in Task 6-adjacent index change below).
- Produces:
  - `AuthServiceDeps` gains `serverUrlProvider?: () => Promise<string | undefined>`.
  - Private `currentServerUrl(): Promise<string | undefined>`.
  - `finishPasswordLogin` now captures the token on any success carrying `TwoFactorToken`.

- [ ] **Step 1: Write the failing tests**

First, UPDATE the `makeService` helper at the top of `src/core/session/auth-service.test.ts` (lines 21-24) so every service has a server URL and the new tests can override it:

```ts
function makeService(
  api: Partial<ApiClient>,
  serverUrlProvider: () => Promise<string | undefined> = async () => 'https://vault.example',
) {
  const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
  return { sm, auth: new AuthService({ api: api as ApiClient, session: sm, now: () => 1000, serverUrlProvider }) };
}
```

Then add this `describe` block just before the final closing `});` of `describe('AuthService', …)`:

```ts
  describe('remember-device: capture on success', () => {
    const SERVER_URL = 'https://vault.example';
    const email = KDF_VECTOR_600K.email.trim().toLowerCase();

    function successData(twoFactorToken?: string) {
      return {
        kind: 'success' as const,
        data: {
          access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
          ...(twoFactorToken ? { TwoFactorToken: twoFactorToken } : {}),
        },
      };
    }

    it('saves the token when a 2FA success returns TwoFactorToken (remember opt-in)', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData('remember-tok-1'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await auth.submitTwoFactor({ provider: 0, code: '123456', remember: true });
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBe('remember-tok-1');
    });

    it('does NOT save when the success response carries no TwoFactorToken', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await auth.submitTwoFactor({ provider: 0, code: '123456', remember: false });
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBeUndefined();
    });

    it('does not save when no serverUrl is configured', async () => {
      const passwordLogin = vi.fn()
        .mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0], token: 'tf' })
        .mockResolvedValueOnce(successData('remember-tok-1'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api, async () => undefined);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      await auth.submitTwoFactor({ provider: 0, code: '123456', remember: true });
      expect(await sm.getRememberDeviceToken('https://vault.example', email)).toBeUndefined();
    });
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/core/session/auth-service.test.ts`
Expected: FAIL — the first two remember tests fail (token not saved); TS also flags `serverUrlProvider` is not a known dep property.

- [ ] **Step 3: Add the dependency + capture**

In `src/core/session/auth-service.ts`, extend `AuthServiceDeps` (lines 13-17):

```ts
export interface AuthServiceDeps {
  api: ApiClient;
  session: SessionManager;
  /** Current configured server URL (for per-(server,email) remember-token keying). */
  serverUrlProvider?: () => Promise<string | undefined>;
  now?: () => number;
}
```

Add this private helper inside the class (place it right after the constructor, near line 33):

```ts
  /** The configured server URL, or undefined when none is set (remember-token keying is then skipped). */
  private currentServerUrl(): Promise<string | undefined> {
    return this.deps.serverUrlProvider ? this.deps.serverUrlProvider() : Promise.resolve(undefined);
  }
```

Then replace the tail of `finishPasswordLogin` — the current lines 315-319:

```ts
    await this.deps.session.saveUnlocked(
      privateKey ? { ...saveInput, privateKey } : saveInput,
    );
    this.pendingLogin = undefined;
    return { kind: 'unlocked' };
```

with:

```ts
    await this.deps.session.saveUnlocked(
      privateKey ? { ...saveInput, privateKey } : saveInput,
    );
    // Capture the device-remember token whenever the server returns one. The server only includes it
    // when remember was in play — a first-time opt-in, or a reuse that auto-rotated it — so
    // capture-on-presence covers both first capture and every subsequent rotation. Keyed by (server,
    // email); undefined server (none configured) skips silently.
    const rememberServerUrl = await this.currentServerUrl();
    if (rememberServerUrl && data.TwoFactorToken) {
      await this.deps.session.saveRememberDeviceToken(rememberServerUrl, input.pending.email, data.TwoFactorToken);
    }
    this.pendingLogin = undefined;
    return { kind: 'unlocked' };
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/core/session/auth-service.test.ts`
Expected: PASS (all existing AuthService tests + the 3 new capture tests).

- [ ] **Step 5: Commit**

```bash
git add src/core/session/auth-service.ts src/core/session/auth-service.test.ts
git commit -m "feat: AuthService captures device-remember token on success (handles rotation)"
```

---

### Task 3: AuthService — reuse a stored token on login (best-effort)

**Files:**
- Modify: `src/core/session/auth-service.ts`
- Test: `src/core/session/auth-service.test.ts`

**Interfaces:**
- Consumes: `SessionManager.getRememberDeviceToken`/`removeRememberDeviceToken` (Task 1); `currentServerUrl` (Task 2); `ApiClient.passwordLogin` (existing).
- Produces: `login()` now transparently reuses a stored token; private `loginWithRememberToken(...)`.

- [ ] **Step 1: Write the failing tests**

Add this `describe` block just before the final closing `});` of `describe('AuthService', …)`:

```ts
  describe('remember-device: reuse on login', () => {
    const SERVER_URL = 'https://vault.example';
    const email = KDF_VECTOR_600K.email.trim().toLowerCase();

    function successData(twoFactorToken?: string) {
      return {
        kind: 'success' as const,
        data: {
          access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
          Key: USER_KEY_VECTOR_600K.akey, Kdf: 0 as const, KdfIterations: KDF_VECTOR_600K.iterations,
          ...(twoFactorToken ? { TwoFactorToken: twoFactorToken } : {}),
        },
      };
    }

    it('valid stored token → sends provider=5 and skips the 2FA screen; captures the rotated token', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce(successData('rotated-T2'));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stored-T1');
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'unlocked' });
      // Exactly one passwordLogin call, and it carried the Remember provider + stored token.
      expect(passwordLogin).toHaveBeenCalledTimes(1);
      expect(passwordLogin.mock.calls[0]![0]).toMatchObject({
        twoFactorProvider: 5, twoFactorToken: 'stored-T1', remember: true,
      });
      // Rotation synced: the stored token is now the server's new one.
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBe('rotated-T2');
    });

    it('stale stored token → clears it and drives 2FA from the SAME result (no re-send)', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce({ kind: 'twoFactor' as const, providers: [0, 1], token: 'tf' });
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stale-T1');
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1], token: 'tf' });
      // Only ONE passwordLogin call — the stale-token attempt already returned the real providers.
      expect(passwordLogin).toHaveBeenCalledTimes(1);
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBeUndefined();
    });

    it('reuse attempt throws → clears the token and retries once WITHOUT it', async () => {
      const passwordLogin = vi.fn()
        .mockRejectedValueOnce(new Error('boom 500'))
        .mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth, sm } = makeService(api);
      await sm.saveRememberDeviceToken(SERVER_URL, email, 'stale-T1');
      await expect(auth.login({ email, masterPassword: KDF_VECTOR_600K.password }))
        .resolves.toEqual({ kind: 'unlocked' });
      expect(passwordLogin).toHaveBeenCalledTimes(2);
      // First call carried provider=5; the retry carried no 2FA fields.
      expect(passwordLogin.mock.calls[0]![0]).toMatchObject({ twoFactorProvider: 5 });
      expect(passwordLogin.mock.calls[1]![0].twoFactorProvider).toBeUndefined();
      expect(await sm.getRememberDeviceToken(SERVER_URL, email)).toBeUndefined();
    });

    it('no stored token → ordinary login (no provider=5 attempt)', async () => {
      const passwordLogin = vi.fn().mockResolvedValueOnce(successData(undefined));
      const api: Partial<ApiClient> = {
        prelogin: vi.fn().mockResolvedValue({ kdf: 0 as const, kdfIterations: KDF_VECTOR_600K.iterations }),
        passwordLogin,
      };
      const { auth } = makeService(api);
      await auth.login({ email, masterPassword: KDF_VECTOR_600K.password });
      expect(passwordLogin).toHaveBeenCalledTimes(1);
      expect(passwordLogin.mock.calls[0]![0].twoFactorProvider).toBeUndefined();
    });
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/core/session/auth-service.test.ts -t "reuse on login"`
Expected: FAIL — the first three fail (no reuse logic yet; provider=5 is never sent).

- [ ] **Step 3: Implement reuse in `login()`**

In `src/core/session/auth-service.ts`, replace the body of `login()` (current lines 51-64) with:

```ts
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
```

Note: `PasswordLoginResult` is already imported at the top of the file (line 1). `PendingLogin` is the existing interface (lines 19-25).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/core/session/auth-service.test.ts`
Expected: PASS (all existing + the 4 new reuse tests). The `submitTwoFactor forwards … trims the code` and `keeps pending login …` tests still pass because no token is seeded there, so the reuse branch is skipped.

- [ ] **Step 5: Commit**

```bash
git add src/core/session/auth-service.ts src/core/session/auth-service.test.ts
git commit -m "feat: AuthService reuses stored device-remember token on login (best-effort fallback)"
```

---

### Task 4: AuthService — forgetDevice / isDeviceRemembered + removeAccount cleanup

**Files:**
- Modify: `src/core/session/auth-service.ts`
- Test: `src/core/session/auth-service.test.ts`

**Interfaces:**
- Consumes: `SessionManager.getRememberDeviceToken`/`removeRememberDeviceToken` (Task 1); `currentServerUrl` (Task 2); `SessionManager.getPersistedAuth`/`removeAccount` (existing).
- Produces:
  - `forgetDevice(email?: string): Promise<void>`
  - `isDeviceRemembered(email?: string): Promise<boolean>`
  - `removeAccount(email)` now also clears that account's remember token.

- [ ] **Step 1: Write the failing tests**

Add this `describe` block just before the final closing `});` of `describe('AuthService', …)`:

```ts
  describe('remember-device: forget / query / removeAccount cleanup', () => {
    const SERVER_URL = 'https://vault.example';

    async function persist(sm: SessionManager, email: string) {
      await sm.saveUnlocked({
        email, accessToken: 'a', refreshToken: 'r', expiresAt: 999999,
        protectedKey: USER_KEY_VECTOR.akey, kdf: 0, kdfIterations: 600000,
        userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
      });
    }

    it('isDeviceRemembered(email) reflects whether a token is stored', async () => {
      const { auth, sm } = makeService({});
      expect(await auth.isDeviceRemembered('u@x.com')).toBe(false);
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      expect(await auth.isDeviceRemembered('u@x.com')).toBe(true);
    });

    it('isDeviceRemembered() defaults to the current account', async () => {
      const { auth, sm } = makeService({});
      await persist(sm, 'active@x.com');
      expect(await auth.isDeviceRemembered()).toBe(false);
      await sm.saveRememberDeviceToken(SERVER_URL, 'active@x.com', 'tok');
      expect(await auth.isDeviceRemembered()).toBe(true);
    });

    it('forgetDevice(email) removes the stored token', async () => {
      const { auth, sm } = makeService({});
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      await auth.forgetDevice('u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBeUndefined();
    });

    it('forgetDevice() defaults to the current account', async () => {
      const { auth, sm } = makeService({});
      await persist(sm, 'active@x.com');
      await sm.saveRememberDeviceToken(SERVER_URL, 'active@x.com', 'tok');
      await auth.forgetDevice();
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'active@x.com')).toBeUndefined();
    });

    it('forgetDevice normalizes the email', async () => {
      const { auth, sm } = makeService({});
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      await auth.forgetDevice('  U@X.COM  ');
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBeUndefined();
    });

    it('removeAccount clears that account’s remember token', async () => {
      const { auth, sm } = makeService({});
      await persist(sm, 'u@x.com');
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      await auth.removeAccount('u@x.com');
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBeUndefined();
      expect((await sm.listAccounts()).map((a) => a.email)).toEqual([]);
    });

    it('query methods return false / no-op when no server is configured', async () => {
      const { auth, sm } = makeService({}, async () => undefined);
      await sm.saveRememberDeviceToken(SERVER_URL, 'u@x.com', 'tok');
      expect(await auth.isDeviceRemembered('u@x.com')).toBe(false);
      await auth.forgetDevice('u@x.com'); // no throw
      expect(await sm.getRememberDeviceToken(SERVER_URL, 'u@x.com')).toBe('tok'); // untouched
    });
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/core/session/auth-service.test.ts -t "forget / query"`
Expected: FAIL — `auth.isDeviceRemembered`/`auth.forgetDevice` are not functions.

- [ ] **Step 3: Implement forget / query + removeAccount cleanup**

In `src/core/session/auth-service.ts`, replace the existing `removeAccount` method (lines 241-244):

```ts
  async removeAccount(email: string): Promise<void> {
    this.pendingLogin = undefined;
    await this.deps.session.removeAccount(email);
  }
```

with:

```ts
  async removeAccount(email: string): Promise<void> {
    this.pendingLogin = undefined;
    const serverUrl = await this.currentServerUrl();
    if (serverUrl) await this.deps.session.removeRememberDeviceToken(serverUrl, email.trim().toLowerCase());
    await this.deps.session.removeAccount(email);
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/core/session/auth-service.test.ts`
Expected: PASS (all existing + the 7 new forget/query/cleanup tests).

- [ ] **Step 5: Commit**

```bash
git add src/core/session/auth-service.ts src/core/session/auth-service.test.ts
git commit -m "feat: AuthService forgetDevice/isDeviceRemembered + removeAccount token cleanup"
```

---

### Task 5: Protocol + router wiring

**Files:**
- Modify: `src/messaging/protocol.ts`
- Modify: `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `AuthService.forgetDevice`/`isDeviceRemembered` (Task 4).
- Produces:
  - `RequestMessage` variants `{ type: 'auth.forgetDevice'; email?: string }` and `{ type: 'auth.isDeviceRemembered'; email?: string }`.
  - `ResponseMessage` variant `{ ok: true; data: { remembered: boolean } }`.
  - Router cases `auth.forgetDevice` (returns `{ ok:true, data:null }`) and `auth.isDeviceRemembered` (returns `{ ok:true, data:{ remembered } }`).

- [ ] **Step 1: Write the failing tests**

Add these two tests to `src/background/router.test.ts` (place them right after the `auth.submitTwoFactor includes remember property when provided` test, near line 455). They reuse the same full `settings` stub shape used throughout the file:

```ts
  it('auth.isDeviceRemembered returns the remembered flag and forwards the email', async () => {
    const isDeviceRemembered = vi.fn(async () => true);
    const router = createRouter({
      auth: { isDeviceRemembered },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.isDeviceRemembered', email: 'u@x.com' }))
      .resolves.toEqual({ ok: true, data: { remembered: true } });
    expect(isDeviceRemembered).toHaveBeenCalledWith('u@x.com');
  });

  it('auth.forgetDevice forwards the email and returns null data', async () => {
    const forgetDevice = vi.fn(async () => {});
    const router = createRouter({
      auth: { forgetDevice },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.forgetDevice', email: 'u@x.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(forgetDevice).toHaveBeenCalledWith('u@x.com');
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/background/router.test.ts -t "Device"`
Expected: FAIL — the router has no `auth.isDeviceRemembered`/`auth.forgetDevice` cases; TS also flags the request types are unknown.

- [ ] **Step 3: Extend the protocol**

In `src/messaging/protocol.ts`, add these two variants to the `RequestMessage` union (right after the `auth.removeAccount` line, line 114):

```ts
  | { type: 'auth.forgetDevice'; email?: string }
  | { type: 'auth.isDeviceRemembered'; email?: string }
```

And add this variant to the `ResponseMessage` union (right after the `{ enabled: boolean }` line, line 178):

```ts
  | { ok: true; data: { remembered: boolean } }
```

- [ ] **Step 4: Add the router cases**

In `src/background/router.ts`, add these two cases right after the `auth.removeAccount` case (lines 110-113):

```ts
          case 'auth.forgetDevice':
            if (!deps.auth.forgetDevice) throw new Error('auth.forgetDevice is not wired');
            await deps.auth.forgetDevice(request.email);
            return { ok: true, data: null };
          case 'auth.isDeviceRemembered':
            if (!deps.auth.isDeviceRemembered) throw new Error('auth.isDeviceRemembered is not wired');
            return { ok: true, data: { remembered: await deps.auth.isDeviceRemembered(request.email) } };
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npx vitest run src/background/router.test.ts`
Expected: PASS (all existing router tests + the 2 new ones).

- [ ] **Step 6: Commit**

```bash
git add src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat: protocol + router for auth.forgetDevice / auth.isDeviceRemembered"
```

---

### Task 6: Popup UI + background wiring

**Files:**
- Modify: `src/background/index.ts` (wire `serverUrlProvider` into `AuthService`)
- Modify: `src/ui/popup/popup.ts` (remember checkbox + two Forget affordances)
- Verify: `npm run typecheck`, `npm run test`, `npm run build`, manual smoke

**Interfaces:**
- Consumes: `auth.submitTwoFactor` `remember` (existing), `auth.isDeviceRemembered`/`auth.forgetDevice` (Task 5).
- Produces: no new exported interfaces (UI-only).

- [ ] **Step 1: Wire `serverUrlProvider` into AuthService**

In `src/background/index.ts`, replace line 27:

```ts
const auth = new AuthService({ api, session });
```

with:

```ts
const auth = new AuthService({ api, session, serverUrlProvider: () => settings.getServerUrl() });
```

- [ ] **Step 2: Add the "Remember this device" checkbox to the 2FA form**

In `src/ui/popup/popup.ts`, in `renderTwoFactor`, add the checkbox inside `#twoFactorForm` — insert it right after the `</label>` that closes the Code field (after line 257, before the submit button on line 258):

```ts
        <label class="tf-remember"><input id="tfRemember" type="checkbox" /><span>Remember this device</span></label>
```

Then update the submit handler (line 279) to read and send the flag. Replace:

```ts
      await handleAuthResult(await sendRequest({ type: 'auth.submitTwoFactor', provider, code }));
```

with:

```ts
      const remember = (document.getElementById('tfRemember') as HTMLInputElement | null)?.checked ?? false;
      await handleAuthResult(await sendRequest({ type: 'auth.submitTwoFactor', provider, code, remember }));
```

- [ ] **Step 3: Add the login-screen Forget affordance**

In `src/ui/popup/popup.ts`, in `renderLogin`, add a slot after the `</form>` — replace lines 137-138:

```ts
      </form>
    </div>`;
```

with:

```ts
      </form>
      <div id="rememberForgetSlot" class="remember-forget"></div>
    </div>`;
```

Then, inside `renderLogin`, add this wiring right after the existing `document.getElementById('goRegister')!.addEventListener(...)` line (line 139). It reveals a Forget link only once the user types an email that this device actually remembers (nothing is shown for an unknown email, so no email is leaked on a shared machine):

```ts
  const emailInput = document.getElementById('email') as HTMLInputElement;
  const forgetSlot = document.getElementById('rememberForgetSlot')!;
  emailInput.addEventListener('change', async () => {
    const email = emailInput.value.trim();
    forgetSlot.innerHTML = '';
    if (!email) return;
    const status = await sendRequest({ type: 'auth.isDeviceRemembered', email });
    if (!status.ok || !(status.data as { remembered: boolean }).remembered) return;
    forgetSlot.innerHTML = `<button id="forgetRemembered" class="link-btn" type="button">This device is remembered for 2-step login — Forget</button>`;
    document.getElementById('forgetRemembered')!.addEventListener('click', async () => {
      const forgotten = await sendRequest({ type: 'auth.forgetDevice', email });
      if (forgotten.ok) forgetSlot.innerHTML = '<span class="muted">This device is no longer remembered.</span>';
    });
  });
```

- [ ] **Step 4: Add the account-panel Forget affordance**

In `src/ui/popup/popup.ts`, in `openAccountSwitcher`, add a slot into the rendered markup — replace the `host.innerHTML = ...` block (lines 1068-1069):

```ts
  host.innerHTML = `<div class="account-list">${rows}
    <button id="accountAdd" class="btn btn-secondary btn-sm btn-block" type="button">${icon('plus')}<span>Add account</span></button></div>`;
```

with:

```ts
  host.innerHTML = `<div class="account-list">${rows}
    <div id="forgetDeviceSlot" class="forget-device"></div>
    <button id="accountAdd" class="btn btn-secondary btn-sm btn-block" type="button">${icon('plus')}<span>Add account</span></button></div>`;
```

Then, at the END of `openAccountSwitcher` (after the `for (const btn of host.querySelectorAll<HTMLButtonElement>('button[data-remove]'))` loop closes, near line 1087), add:

```ts
  const remembered = await sendRequest({ type: 'auth.isDeviceRemembered' });
  const forgetSlot = document.getElementById('forgetDeviceSlot');
  if (forgetSlot && remembered.ok && (remembered.data as { remembered: boolean }).remembered) {
    forgetSlot.innerHTML = `<button id="forgetDevice" class="link-btn" type="button">Forget this device (2-step login)</button>`;
    document.getElementById('forgetDevice')!.addEventListener('click', async () => {
      const forgotten = await sendRequest({ type: 'auth.forgetDevice' });
      if (forgotten.ok) forgetSlot.innerHTML = '<span class="muted">This device is no longer remembered.</span>';
    });
  }
```

- [ ] **Step 5: Typecheck, test, and build**

Run: `npm run typecheck`
Expected: no errors.

Run: `npm run test`
Expected: PASS (full unit suite, including Tasks 1-5).

Run: `npm run build`
Expected: build succeeds, no errors.

- [ ] **Step 6: Manual smoke (record results in the task report)**

Load the unpacked build in Chrome against the test server (`http://10.0.1.20:8080`, account `test@winvaultwarden.local`, master `Test-Master-Password-1!`). Because this account is PBKDF2 and 2FA must be enabled server-side first, the LIVE task (Task 7) is the authoritative end-to-end proof; this smoke is a UI sanity check:
1. The 2FA form (if reachable) shows a "Remember this device" checkbox.
2. On the account switcher, when a token is stored, a "Forget this device (2-step login)" link appears and, when clicked, reports the device is no longer remembered.
3. On the login screen, typing a remembered email surfaces the Forget link; an unknown email surfaces nothing.

If 2FA cannot be enabled for a manual run, note that the UI paths were verified structurally and defer behavioral proof to Task 7.

- [ ] **Step 7: Commit**

```bash
git add src/background/index.ts src/ui/popup/popup.ts
git commit -m "feat: popup remember-device checkbox + Forget affordances; wire serverUrlProvider"
```

---

### Task 7: LIVE end-to-end test (server contract)

**Files:**
- Create: `test/live/remember-2fa.live.test.ts`

**Interfaces:**
- Consumes: `ApiClient.passwordLogin` (provider/token/remember, existing); `generateTotpCode`/`parseTotp` from `src/core/vault/totp.ts` (existing); raw `fetch` for the 2FA-enable endpoint.
- Produces: a LIVE-gated test proving the real Vaultwarden 1.35.0 contract (token returned on success, provider=5 skips 2FA, token rotates on each reuse).

**Context:** This test is LIVE-gated (`describe.skip` unless `LIVE=1`), mirroring `test/live/rotate.live.test.ts`. The direct path `10.0.1.20:8080` is blocked from this environment; reach the server through an SSH tunnel. Before running, start the tunnel in the background:

```bash
/c/Windows/System32/OpenSSH/ssh.exe -N -L 18080:localhost:8080 test-env
```

then run with `LIVE=1 npx vitest run test/live/remember-2fa.live.test.ts` (default `SERVER=http://localhost:18080`).

- [ ] **Step 1: Write the LIVE test**

Create `test/live/remember-2fa.live.test.ts`:

```ts
// Live end-to-end test for remember-device 2FA against the disposable test Vaultwarden (CLAUDE.md),
// reached via the SSH tunnel (direct 10.0.1.20:8080 is blocked). Skipped by default; run with:
//   LIVE=1 npx vitest run test/live/remember-2fa.live.test.ts
//
// Registers a throwaway account, enables authenticator (TOTP) 2FA, then proves the server contract
// this feature relies on: (1) a 2FA success with remember returns a TwoFactorToken; (2) replaying it
// with two_factor_provider=5 skips the 2FA challenge; (3) each successful reuse ROTATES the token
// (returns a new one). The throwaway account is deleted in a `finally`.
import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash } from '../../src/core/crypto/kdf.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { generateTotpCode, parseTotp } from '../../src/core/vault/totp.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = process.env.REMEMBER_SERVER ?? 'http://localhost:18080';
const LIVE = Boolean(process.env.LIVE);

// A valid 32-char (20-byte) base32 TOTP secret used to enrol authenticator 2FA for the test account.
const TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return {
    get: async <T>(k: string) => m.get(k) as T | undefined,
    set: async (k: string, v: unknown) => { m.set(k, v); },
    remove: async (k: string) => { m.delete(k); },
  } as KeyValueStore;
}

/** Current 6-digit TOTP code for TOTP_SECRET. */
async function totpNow(): Promise<string> {
  return generateTotpCode(parseTotp(TOTP_SECRET)!, Math.floor(Date.now() / 1000));
}

/** Enable authenticator 2FA on the account via raw fetch. Vaultwarden 1.35.0 expects the secret key,
 *  a CURRENT code from that key, and the master-password hash. If the server rejects with 400, inspect
 *  the response and switch the field casing to PascalCase (Key/Token/MasterPasswordHash). */
async function enableAuthenticator(token: string, masterPasswordHash: string): Promise<void> {
  const res = await fetch(`${SERVER}/api/two-factor/authenticator`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ key: TOTP_SECRET, token: await totpNow(), masterPasswordHash }),
  });
  const text = await res.text();
  expect(res.ok, `enable authenticator failed: ${res.status} ${text}`).toBe(true);
}

async function deleteAccount(token: string, masterPasswordHash: string): Promise<void> {
  try {
    await fetch(`${SERVER}/api/accounts`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ masterPasswordHash }),
    });
  } catch { /* best-effort */ }
}

(LIVE ? describe : describe.skip)('live remember-device 2FA against the test server', () => {
  it('returns a TwoFactorToken on remember success, skips 2FA on reuse, and rotates the token', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const email = `remember-${Date.now()}@winvaultwarden.local`;
    const password = 'Remember-Test-Pass-1!';

    const reg = await buildRegistration(email, password);
    await api.register({
      email, name: 'Remember Test', masterPasswordHash: reg.masterPasswordHash,
      key: reg.key, keys: reg.keys, kdf: reg.kdf, kdfIterations: reg.kdfIterations,
    });
    const pre = await api.prelogin(email);
    const masterKey = await deriveMasterKey(password, email, pre.kdfIterations);
    const hash = await deriveMasterPasswordHash(masterKey, password);

    // First login (no 2FA yet) to get a token for enabling authenticator + final cleanup.
    const first = await api.passwordLogin({ email, masterPasswordHash: hash });
    expect(first.kind, 'initial login').toBe('success');
    if (first.kind !== 'success') throw new Error('unreachable');
    const adminToken = first.data.access_token;

    try {
      await enableAuthenticator(adminToken, hash);

      // Now login requires 2FA.
      const challenged = await api.passwordLogin({ email, masterPasswordHash: hash });
      expect(challenged.kind, 'login now requires 2FA').toBe('twoFactor');

      // Submit the TOTP code WITH remember → success carries a TwoFactorToken (device-remember token).
      const submitted = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 0, twoFactorToken: await totpNow(), remember: true,
      });
      expect(submitted.kind, '2FA submit with remember').toBe('success');
      if (submitted.kind !== 'success') throw new Error('unreachable');
      const t1 = submitted.data.TwoFactorToken;
      expect(t1, 'success returns a device-remember token').toBeTruthy();

      // Reuse with provider=5 skips the 2FA challenge and ROTATES the token (returns a new one).
      const reuse1 = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: t1!, remember: true,
      });
      expect(reuse1.kind, 'provider=5 reuse skips 2FA').toBe('success');
      if (reuse1.kind !== 'success') throw new Error('unreachable');
      const t2 = reuse1.data.TwoFactorToken;
      expect(t2, 'reuse returns a rotated token').toBeTruthy();
      expect(t2, 'rotated token differs from the first').not.toBe(t1);

      // The rotated token also works (proves the client MUST sync each rotation).
      const reuse2 = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: t2!, remember: true,
      });
      expect(reuse2.kind, 'rotated token still skips 2FA').toBe('success');

      // The stale first token no longer skips 2FA (server rotated away from it).
      const stale = await api.passwordLogin({
        email, masterPasswordHash: hash, twoFactorProvider: 5, twoFactorToken: t1!, remember: true,
      });
      expect(stale.kind, 'stale token falls back to 2FA').toBe('twoFactor');
    } finally {
      await deleteAccount(adminToken, hash);
    }
  }, 60_000);
});
```

- [ ] **Step 2: Start the tunnel and run the LIVE test**

Start the tunnel (background), then:

Run: `LIVE=1 npx vitest run test/live/remember-2fa.live.test.ts`
Expected: PASS. If `enableAuthenticator` returns 400, inspect the response body and switch the JSON field casing to PascalCase (`Key`/`Token`/`MasterPasswordHash`) — Vaultwarden's serde config varies by version — then re-run. Record the working request shape in the task report.

- [ ] **Step 3: Confirm the test is skipped without LIVE**

Run: `npx vitest run test/live/remember-2fa.live.test.ts`
Expected: the suite is skipped (0 tests run, no failures).

- [ ] **Step 4: Commit**

```bash
git add test/live/remember-2fa.live.test.ts
git commit -m "test: LIVE e2e proving remember-device 2FA server contract (capture, reuse-skip, rotation)"
```

---

## Self-Review

**1. Spec coverage:**
- §4.1 SessionManager per-(server,email) store, survives logout, cleared on removeAccount + forget → Task 1 (+ removeAccount cleanup in Task 4). ✓
- §4.2 capture on finishPasswordLogin success by token-presence (rotation) → Task 2. ✓ Reuse with provider=5; stale→clear+use-same-result (no re-send); throw→clear+retry-without → Task 3. ✓ no-token fail-safe (silent no-op) → Task 2 ("no TwoFactorToken" test). ✓
- §4.3 protocol/router: remember passthrough already exists (not re-added); forgetDevice + isDeviceRemembered added → Task 5. ✓
- §4.4 popup: remember checkbox; login-screen Forget (typed-email, no email leak); account-panel Forget → Task 6. ✓
- §5 security: token survives logout (Task 1 test), best-effort fallback (Task 3), revocable logged-in AND logged-out (Task 6), per-(server,email) (Task 1), not logged/displayed (no console/DOM of token). ✓
- §6 LIVE: TOTP enrol via totp.ts, capture, reuse-skip, rotation-sync, cleanup → Task 7. ✓
- §7 tests enumerated → Tasks 1-5 unit + Task 7 LIVE. ✓

**Design refinement vs spec (within an approved option):** §4.4 offered "list `listRememberedDevices` OR typed-email" for the login screen. This plan chose the typed-email path (privacy on shared machines) and therefore does NOT add `listRememberedDevices` — the spec's "OR" makes this in-scope, and it avoids an unused API the reviewer would flag.

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code. The LIVE 2FA-enable request has a documented casing-fallback (inherent to a live probe), not a placeholder.

**3. Type consistency:** `serverUrlProvider: () => Promise<string | undefined>` matches `settings.getServerUrl` (Task 2 dep, Task 6 wiring). `getRememberDeviceToken(serverUrl, email)` / `saveRememberDeviceToken(serverUrl, email, token)` / `removeRememberDeviceToken(serverUrl, email)` signatures identical across Tasks 1-4. Protocol `{ remembered: boolean }` matches router return + popup reads (Tasks 5-6). `forgetDevice(email?)` / `isDeviceRemembered(email?)` identical across Tasks 4-6. Provider id `5` used in Task 3 (send) and Task 7 (live). ✓

## Execution Handoff

Plan complete. Recommended: Subagent-Driven Development (fresh subagent per task, review between tasks).
