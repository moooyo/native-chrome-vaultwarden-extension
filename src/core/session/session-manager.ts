import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { symmetricKeyFromBytes, serializeSymmetricKey } from '../crypto/keys.js';
import { bytesToBase64, base64ToBytes } from '../crypto/encoding.js';
import { parseKdfConfig, sameKdfConfig, type KdfConfig } from '../crypto/kdf.js';
import {
  parsePasswordChangeRequirement,
  type PasswordChangeRequirement,
} from '../policy/master-password-policy.js';

export type SessionState = 'loggedOut' | 'locked' | 'restricted' | 'unlocked';

/** Proof that secret work belongs to one unlocked in-memory session generation. */
export interface SessionLease {
  readonly generation: number;
}

/** Narrow authorization fence consumed by vault and fill operations. */
export interface SessionLeaseGate {
  capture(): SessionLease;
  assert(lease: SessionLease): void;
}

interface PersistedAuthBase {
  email: string;
  /** Explicit server-provided salt for master-password unlock; legacy/password grants use email. */
  masterKeySalt?: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  protectedKey: string;
  /** UserKey-wrapped RSA PrivateKey (encType=2). Safe to persist; plaintext PKCS8 lives in session. */
  encPrivateKey?: string;
  /** Durable account restriction. Restricted accounts never own a live session secret bundle. */
  restriction?: PasswordChangeRequirement;
}

export type PersistedAuth = PersistedAuthBase & KdfConfig;
type PersistedAuthCore = Omit<PersistedAuthBase, 'accessToken' | 'refreshToken' | 'expiresAt'>
  & KdfConfig;

export type AuthTokenExpectation = Pick<PersistedAuth, 'email' | 'refreshToken'>
  & Partial<Pick<PersistedAuth, 'accessToken'>>;

export type AuthTokenStorage = 'local' | 'session';
export type AuthTokenStorageReason = 'conservative' | 'localLogout' | 'effectivePolicy';

export interface AuthTokenLease {
  readonly email: string;
  readonly credentialId: string;
  readonly tokenRevision: string;
}

export interface ActiveAuthSnapshot {
  readonly auth: ActiveAuth;
  readonly tokenStorage: AuthTokenStorage;
  readonly tokenLease: AuthTokenLease;
}

export interface RefreshTokenPermit extends AuthTokenLease {
  readonly serverUrl: string;
  readonly operationId: string;
  readonly nextTokenRevision: string;
}

export interface TokenStorageMoveReceipt {
  readonly moved: readonly AuthTokenLease[];
  readonly reclassified: readonly {
    readonly tokenLease: AuthTokenLease;
    readonly previousReason: AuthTokenStorageReason;
  }[];
}

/** Active-auth metadata used to bind local credentials to one ephemeral secret bundle. */
export type ActiveAuth = PersistedAuth & {
  readonly sessionBindingId?: string;
};

export type SaveUnlockedInput = PersistedAuth & {
  userKey: SymmetricKey;
  /** Decrypted PKCS8 private key bytes; stored only in session storage. */
  privateKey?: Uint8Array;
};

export type SaveLockedAuthenticatedInput = PersistedAuth;
type WithPasswordRestriction<Auth> = Auth extends unknown
  ? Omit<Auth, 'restriction'> & { readonly restriction: PasswordChangeRequirement }
  : never;
export type SaveRestrictedAuthenticatedInput = WithPasswordRestriction<PersistedAuth>;

export interface SessionManagerDeps {
  localStore: KeyValueStore;
  sessionStore: KeyValueStore;
  createSessionBindingId?: () => string;
  /** New and replacement authentication commits use this conservative initial tier. */
  defaultTokenStorage?: AuthTokenStorage;
}

const AUTH_KEY = 'auth';
const SESSION_AUTH_TOKENS_KEY = 'authTokens';
const REFRESH_INTENTS_KEY = 'authRefreshIntents';
const SESSION_SECRETS_KEY = 'sessionSecrets';
const USER_KEY_KEY = 'userKey';
const PRIVATE_KEY_KEY = 'privateKey';
const LEGACY_PIN_KEY = 'pinProtectedUserKey';
const PIN_CONFIGURATIONS_KEY = 'pinConfigurations';
const PIN_EPHEMERAL_ENVELOPES_KEY = 'pinEphemeralEnvelopes';
const PIN_FAILURES_KEY = 'pinFailures';
const ACCOUNTS_KEY = 'accounts';
const REMEMBER_TOKENS_KEY = 'rememberDeviceTokens';

export const MAX_ACCOUNT_COUNT = 5;

export type PinLockType = 'afterFirstUnlock' | 'beforeFirstUnlock';

export interface PinUnlockState {
  readonly protectedUserKey: string;
  readonly credentialId: string;
  readonly requireMasterPasswordOnRestart: boolean;
  readonly legacy: boolean;
}

export interface PinStateSummary {
  readonly configured: boolean;
  readonly available: boolean;
  readonly requireMasterPasswordOnRestart: boolean;
}

export interface PinRearmData {
  readonly configurationId: string;
  readonly encryptedPin: string;
}

interface PinConfigurationBaseV1 {
  readonly schemaVersion: 1;
  readonly configurationId: string;
}

type PinConfigurationV1 =
  | PinConfigurationBaseV1 & {
      readonly lockType: 'afterFirstUnlock';
      readonly encryptedPin: string;
    }
  | PinConfigurationBaseV1 & {
      readonly lockType: 'beforeFirstUnlock';
      readonly protectedUserKey: string;
    };

interface PinEphemeralEnvelopeV1 {
  readonly schemaVersion: 1;
  readonly configurationId: string;
  readonly protectedUserKey: string;
  readonly legacy?: true;
}

interface PinFailureStateV1 {
  readonly schemaVersion: 1;
  readonly credentialId: string;
  readonly attempts: number;
}

export interface AccountSummary {
  email: string;
  active: boolean;
}

interface SessionSecretsV1 {
  readonly schemaVersion: 1;
  readonly owner: string;
  readonly sessionBindingId: string;
  readonly userKey: string;
  readonly privateKey?: string;
}

interface LoadedSessionSecrets {
  readonly owner: string;
  readonly sessionBindingId: string;
  readonly userKey: SymmetricKey;
  readonly privateKey?: Uint8Array;
}

interface VersionedAuthMarker {
  readonly credentialId: string;
  readonly tokenRevision: string;
}

interface LocalBackedAuthMarker extends VersionedAuthMarker {
  readonly tokenStorage: 'local';
}

interface SessionBackedAuthMarker extends VersionedAuthMarker {
  readonly tokenStorage: 'session';
  readonly tokenBindingId: string;
  readonly tokenStorageReason: AuthTokenStorageReason;
}

type LocalBackedAuth = PersistedAuth & LocalBackedAuthMarker;
type SessionBackedAuth = PersistedAuthCore & SessionBackedAuthMarker;
type StoredPersistedAuth = PersistedAuth | LocalBackedAuth | SessionBackedAuth;
type StoredActiveAuth = StoredPersistedAuth & { readonly sessionBindingId?: string };

interface SessionAuthTokensV1 {
  readonly schemaVersion: 2;
  readonly owner: string;
  readonly credentialId: string;
  readonly tokenRevision: string;
  readonly tokenBindingId: string;
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: number;
}

interface RefreshIntentV1 extends RefreshTokenPermit {
  readonly schemaVersion: 1;
}

interface AccountRegistrySnapshot {
  readonly accounts: Record<string, PersistedAuth>;
  readonly storedAccounts: Record<string, StoredPersistedAuth>;
  readonly sessionTokens: Record<string, SessionAuthTokensV1>;
  readonly refreshIntents: Record<string, RefreshIntentV1>;
}

interface SessionInspection {
  readonly auth?: PersistedAuth;
  readonly secrets?: LoadedSessionSecrets;
}

export class SessionManager {
  private accountRegistryMutationTail: Promise<void> = Promise.resolve();
  private rememberTokenMutationTail: Promise<void> = Promise.resolve();
  private pinMutationTail: Promise<void> = Promise.resolve();

  constructor(private readonly deps: SessionManagerDeps) {}

  /** Run one-way session-storage migration before the background worker accepts requests. */
  async initialize(): Promise<void> {
    await this.runAccountRegistryMutation(() => this.initializeWithinRegistryMutation());
  }

  private async initializeWithinRegistryMutation(): Promise<void> {
    await this.clearLegacySessionSecrets();
    const auth = await this.getActiveAuth();
    const stored = await this.deps.sessionStore.get<unknown>(SESSION_SECRETS_KEY);
    const secrets = parseSessionSecrets(stored);
    try {
      if (
        auth?.restriction !== undefined
        || !auth?.sessionBindingId
        || !secrets
        || secrets.owner !== auth.email
        || secrets.sessionBindingId !== auth.sessionBindingId
      ) {
        if (auth?.restriction || auth?.sessionBindingId) {
          await this.clearActiveSessionBindingWithinRegistryMutation();
        }
        await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
      }
    } finally {
      clearLoadedSessionSecrets(secrets);
    }
    await this.migrateLegacyPin(auth?.email);
  }

  async getState(): Promise<SessionState> {
    const inspected = await this.inspectSession();
    try {
      if (!inspected.auth) return 'loggedOut';
      if (inspected.auth.restriction) return 'restricted';
      return inspected.secrets ? 'unlocked' : 'locked';
    } finally {
      clearLoadedSessionSecrets(inspected.secrets);
    }
  }

  async saveUnlocked(
    input: SaveUnlockedInput,
    options: { readonly replaceCredential?: boolean } = {},
  ): Promise<void> {
    const { userKey, privateKey, ...auth } = input;
    const validated = parsePersistedAuth(auth);
    if (validated.restriction) throw new Error('Restricted authentication cannot be unlocked');
    const sessionBindingId = this.createSessionBindingId();
    const active: ActiveAuth = { ...validated, sessionBindingId };
    const rawUserKey = serializeSymmetricKey(userKey);
    let encodedUserKey: string;
    try {
      encodedUserKey = bytesToBase64(rawUserKey);
    } finally {
      rawUserKey.fill(0);
    }
    const secrets: SessionSecretsV1 = {
      schemaVersion: 1,
      owner: validated.email,
      sessionBindingId,
      userKey: encodedUserKey,
      ...(privateKey ? { privateKey: bytesToBase64(privateKey) } : {}),
    };

    await this.mutateAccountRegistry(async (registry) => {
      this.assertAccountAdmission(registry.accounts, validated.email);
      const previous = await this.getPersistedAuth();
      // Legacy session slots are never trusted or migrated. The account registry remains unbound so
      // selecting an account can only restore a locked session.
      await this.clearLegacySessionSecrets();
      if (previous && pinStateMustBeCleared(previous, validated)) {
        await this.removePinProtectedUserKey(previous.email);
      }
      await this.commitAuthenticatedAccount(
        registry,
        validated,
        active,
        options.replaceCredential !== false,
      );
      await this.deps.sessionStore.set(SESSION_SECRETS_KEY, secrets);
    });
  }

  /**
   * Publish authenticated token and password-unlock material without publishing a UserKey. This is
   * used after an account-passkey grant when PRF unlock is unavailable or intentionally deferred.
   */
  async saveLockedAuthenticated(input: SaveLockedAuthenticatedInput): Promise<void> {
    const validated = parsePersistedAuth(input);
    if (validated.restriction) throw new Error('Use saveRestrictedAuthenticated for restrictions');
    await this.mutateAccountRegistry(async (registry) => {
      this.assertAccountAdmission(registry.accounts, validated.email);
      await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
      await this.clearLegacySessionSecrets();
      const previous = await this.getPersistedAuth();
      if (previous && pinStateMustBeCleared(previous, validated)) {
        await this.removePinProtectedUserKey(previous.email);
      }
      await this.commitAuthenticatedAccount(registry, validated, validated);
    });
  }

  /** Publish tokens and password-unlock material without publishing any decrypted session secrets. */
  async saveRestrictedAuthenticated(input: SaveRestrictedAuthenticatedInput): Promise<void> {
    const validated = parsePersistedAuth(input);
    if (!validated.restriction) throw new Error('Restricted authentication requires a reason');
    await this.mutateAccountRegistry(async (registry) => {
      this.assertAccountAdmission(registry.accounts, validated.email);
      // Publish the no-binding restriction first. If cleanup is interrupted, every reader rejects the
      // old secret bundle and startup physically removes it before any gate is initialized.
      await this.commitAuthenticatedAccount(registry, validated, validated);
      await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
      await this.clearLegacySessionSecrets();
      await this.removePinProtectedUserKey(validated.email);
    });
  }

  async getPasswordChangeRequirement(): Promise<PasswordChangeRequirement | undefined> {
    return (await this.getPersistedAuth())?.restriction;
  }

  /** Conditionally update tokens for the account/refresh token that initiated a refresh request. */
  async saveTokensFor(
    expected: AuthTokenExpectation,
    tokens: { accessToken: string; refreshToken: string; expiresAt: number },
  ): Promise<boolean> {
    return this.mutateAccountRegistry(async (registry) => {
      const snapshot = await this.getActiveAuthSnapshot();
      const auth = snapshot?.auth;
      if (!auth || !matchesAuthExpectation(auth, expected)) return false;
      if (!snapshot) return false;
      return Boolean(await this.commitTokensForLease(
        registry,
        snapshot.tokenLease,
        this.createTokenRevision(),
        tokens,
      ));
    });
  }

  /** Persist a non-secret write-ahead marker before a refresh token can be dispatched. */
  async prepareTokenRefresh(
    expected: AuthTokenLease & { readonly serverUrl: string },
  ): Promise<RefreshTokenPermit | undefined> {
    return this.mutateAccountRegistry(async (registry) => {
      if (!this.getAuthForTokenLease(registry, expected)) return undefined;
      if (Object.values(registry.refreshIntents).some((intent) => (
        intent.credentialId === expected.credentialId
      ))) {
        throw new Error('A refresh outcome is already pending for this credential');
      }
      const operationId = crypto.randomUUID();
      const permit: RefreshTokenPermit = {
        ...expected,
        operationId,
        nextTokenRevision: this.createTokenRevision(),
      };
      registry.refreshIntents[operationId] = { schemaVersion: 1, ...permit };
      try {
        await this.writeRefreshIntents(registry.refreshIntents);
      } catch (error) {
        let committed = false;
        try {
          committed = sameRefreshIntent(
            (await this.loadRefreshIntents())[operationId],
            permit,
          );
        } catch {
          // An unreadable local area cannot prove that the dispatch marker was committed.
        }
        if (!committed) throw error;
      }
      return permit;
    });
  }

  /** Commit one rotated token generation to its original account, active or inactive. */
  async commitTokenRefresh(
    permit: RefreshTokenPermit,
    tokens: { accessToken: string; refreshToken: string; expiresAt: number },
  ): Promise<AuthTokenLease | undefined> {
    return this.mutateAccountRegistry(async (registry) => {
      if (!sameRefreshIntent(registry.refreshIntents[permit.operationId], permit)) return undefined;
      const committed = await this.commitTokensForLease(
        registry,
        permit,
        permit.nextTokenRevision,
        tokens,
        permit.operationId,
      );
      if (!committed) {
        delete registry.refreshIntents[permit.operationId];
        await this.writeRefreshIntents(registry.refreshIntents);
      }
      return committed;
    });
  }

  /** Clear an intent only when the request guard proves no refresh request was dispatched. */
  async cancelUndispatchedTokenRefresh(permit: RefreshTokenPermit): Promise<boolean> {
    return this.runAccountRegistryMutation(async () => {
      const intents = await this.loadRefreshIntents();
      if (!sameRefreshIntent(intents[permit.operationId], permit)) return false;
      delete intents[permit.operationId];
      try {
        await this.writeRefreshIntents(intents);
      } catch (error) {
        let removed = false;
        try {
          removed = !sameRefreshIntent(
            (await this.loadRefreshIntents())[permit.operationId],
            permit,
          );
        } catch {
          // Preserve the write failure when removal cannot be proven.
        }
        if (!removed) throw error;
      }
      return true;
    });
  }

  /** Remove exactly one credential generation after an invalid or ambiguous refresh outcome. */
  async removeAccountIfTokenCurrent(
    expected: AuthTokenLease,
  ): Promise<'active' | 'inactive' | false> {
    return this.mutateAccountRegistry(async (registry) => {
      const stored = registry.storedAccounts[expected.email];
      if (!stored || !storedAuthMatchesTokenLease(stored, expected)) return false;
      const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
      const active = activeRaw === undefined || activeRaw === null
        ? undefined
        : parseStoredActiveAuth(activeRaw);
      const wasActive = Boolean(active && storedAuthMatchesTokenLease(active, expected));
      delete registry.accounts[expected.email];
      delete registry.storedAccounts[expected.email];
      for (const [operationId, intent] of Object.entries(registry.refreshIntents)) {
        if (intent.credentialId === expected.credentialId) delete registry.refreshIntents[operationId];
      }
      if (isSessionBackedAuth(stored)) delete registry.sessionTokens[stored.tokenBindingId];
      const nextActive = wasActive
        ? Object.values(registry.storedAccounts)[0] ?? null
        : active ?? null;
      await this.setLocalAccountState(registry.storedAccounts, nextActive, {
        [REFRESH_INTENTS_KEY]: registry.refreshIntents,
      });
      await this.writeSessionAuthTokens(registry.sessionTokens);
      await this.removePinProtectedUserKey(expected.email);
      if (wasActive) await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
      return wasActive ? 'active' : 'inactive';
    });
  }

  async isTokenLeaseCurrent(expected: AuthTokenLease): Promise<boolean> {
    return this.mutateAccountRegistry(async (registry) => Boolean(
      this.getAuthForTokenLease(registry, expected),
    ));
  }

  async getPersistedAuth(): Promise<PersistedAuth | undefined> {
    const active = await this.getActiveAuth();
    return active ? stripSessionBinding(active) : undefined;
  }

  /** One-read active auth snapshot for account/server lease comparisons. */
  async getActiveAuth(): Promise<ActiveAuth | undefined> {
    const stored = await this.deps.localStore.get<unknown>(AUTH_KEY);
    if (stored === undefined || stored === null) return undefined;
    const before = parseStoredActiveAuth(stored);
    if (!isSessionBackedAuth(before)) return parseActiveAuth(before);
    const token = (await this.loadSessionAuthTokens())[before.tokenBindingId];
    const composed = composeStoredAuth(before, token);
    if (!composed) return undefined;
    // The local metadata read remains the final storage await, binding the token slot against
    // remove, re-login, lock, and A -> B -> A account changes while session storage was read.
    const current = await this.deps.localStore.get<unknown>(AUTH_KEY);
    if (current === undefined || current === null) return undefined;
    const after = parseStoredActiveAuth(current);
    return sameStoredActiveAuth(before, after) ? composed : undefined;
  }

  /** Versioned active credential snapshot used by refresh CAS and per-owner cleanup. */
  async getActiveAuthSnapshot(): Promise<ActiveAuthSnapshot | undefined> {
    const rawBefore = await this.deps.localStore.get<unknown>(AUTH_KEY);
    if (rawBefore === undefined || rawBefore === null) return undefined;
    const before = parseStoredActiveAuth(rawBefore);
    const tokenLease = storedAuthTokenLease(before);
    if (!tokenLease) return undefined;
    const tokenStorage: AuthTokenStorage = isSessionBackedAuth(before) ? 'session' : 'local';
    const token = isSessionBackedAuth(before)
      ? (await this.loadSessionAuthTokens())[before.tokenBindingId]
      : undefined;
    const auth = composeStoredAuth(before, token);
    if (!auth) return undefined;
    const rawAfter = await this.deps.localStore.get<unknown>(AUTH_KEY);
    if (rawAfter === undefined || rawAfter === null) return undefined;
    const after = parseStoredActiveAuth(rawAfter);
    if (!sameStoredActiveAuth(before, after)) return undefined;
    return { auth, tokenStorage, tokenLease };
  }

  /**
   * Update the master-password-derived material after a password or KDF change: the UserKey-wrapping
   * protectedKey, and the complete KDF configuration when changed. The UserKey itself is unchanged,
   * but a KDF change invalidates the PIN-derived wrapping key, so its persisted blob is removed.
   */
  async updateMasterKeyMaterialFor(
    expected: Pick<PersistedAuth, 'email' | 'protectedKey'> & KdfConfig,
    update: { protectedKey: string; kdf?: KdfConfig },
  ): Promise<void> {
    await this.mutateAccountRegistry(async (registry) => {
      const auth = await this.getActiveAuth();
      if (!auth) throw new Error('not logged in');
      if (
        auth.email !== expected.email
        || auth.protectedKey !== expected.protectedKey
        || !sameKdfConfig(auth, expected)
      ) {
        throw new Error('active account key material changed');
      }
      this.assertAccountAdmission(registry.accounts, auth.email);
      const updated = parsePersistedAuth({
        email: auth.email,
        ...(auth.masterKeySalt ? { masterKeySalt: auth.masterKeySalt } : {}),
        accessToken: auth.accessToken,
        refreshToken: auth.refreshToken,
        expiresAt: auth.expiresAt,
        protectedKey: update.protectedKey,
        ...pickKdfConfig(update.kdf ?? auth),
        ...(auth.encPrivateKey ? { encPrivateKey: auth.encPrivateKey } : {}),
        ...(auth.restriction ? { restriction: auth.restriction } : {}),
      });
      if (update.kdf) await this.removePinProtectedUserKey(auth.email);
      await this.persistUpdatedActiveAuth(registry, {
        ...updated,
        ...(auth.sessionBindingId ? { sessionBindingId: auth.sessionBindingId } : {}),
      });
    });
  }

  /** Move the active account's tokens to the tier required by one effective timeout snapshot. */
  async reconcileActiveTokenStorage(
    expected: {
      readonly email: string;
      readonly credentialId?: string;
      readonly tokenRevision?: string;
      readonly sessionBindingId?: string;
    },
    target: AuthTokenStorage,
    sessionReason: AuthTokenStorageReason = 'conservative',
  ): Promise<boolean> {
    return this.mutateAccountRegistry(async (registry) => {
      const snapshot = await this.getActiveAuthSnapshot();
      const active = snapshot?.auth;
      if (
        !active
        || active.email !== expected.email
        || (expected.credentialId !== undefined
          && snapshot?.tokenLease.credentialId !== expected.credentialId)
        || (expected.tokenRevision !== undefined
          && snapshot?.tokenLease.tokenRevision !== expected.tokenRevision)
        || active.sessionBindingId !== expected.sessionBindingId
      ) return false;
      const stored = registry.storedAccounts[active.email];
      if (!stored) return false;
      const identity = storedAuthTokenLease(stored) ?? {
        email: active.email,
        credentialId: this.createCredentialId(),
        tokenRevision: this.createTokenRevision(),
      };
      const current = isSessionBackedAuth(stored) ? 'session' : 'local';
      if (current === target) {
        if (!isSessionBackedAuth(stored) || stored.tokenStorageReason === sessionReason) return true;
        const updated = { ...stored, tokenStorageReason: sessionReason };
        registry.storedAccounts[active.email] = updated;
        await this.setLocalAccountState(
          registry.storedAccounts,
          withStoredSessionBinding(updated, active.sessionBindingId),
        );
        return true;
      }

      if (target === 'local') {
        const localStored = localBackedAuth(
          active,
          identity.credentialId,
          identity.tokenRevision,
        );
        registry.accounts[active.email] = stripSessionBinding(active);
        registry.storedAccounts[active.email] = localStored;
        await this.setLocalAccountState(
          registry.storedAccounts,
          withStoredSessionBinding(localStored, active.sessionBindingId),
        );
        if (isSessionBackedAuth(stored)) delete registry.sessionTokens[stored.tokenBindingId];
        await this.writeSessionAuthTokens(registry.sessionTokens);
        return true;
      }

      const tokenBindingId = this.createTokenBindingId();
      const sessionStored = sessionBackedAuth(
        active,
        tokenBindingId,
        identity.credentialId,
        identity.tokenRevision,
        sessionReason,
      );
      const sessionActive = active.sessionBindingId
        ? { ...sessionStored, sessionBindingId: active.sessionBindingId }
        : sessionStored;
      const token = sessionAuthTokens(active, sessionStored);
      registry.storedAccounts[active.email] = sessionStored;
      // Erase both local token copies before publishing the session slot. A crash in between leaves
      // an intentionally unavailable account that startup retires; it never restores tokens to disk.
      try {
        await this.setLocalAccountState(registry.storedAccounts, sessionActive);
      } catch (error) {
        if (!await this.confirmSessionBackedLocalState([sessionStored], sessionActive)) throw error;
      }
      registry.sessionTokens[tokenBindingId] = token;
      try {
        await this.writeSessionAuthTokens(registry.sessionTokens);
      } catch (error) {
        let committed = false;
        try {
          committed = sameSessionAuthTokens(
            (await this.loadSessionAuthTokens())[tokenBindingId],
            token,
          );
        } catch {
          // An unreadable session area cannot prove that the exact slot was committed.
        }
        if (!committed) {
          delete registry.storedAccounts[active.email];
          delete registry.accounts[active.email];
          delete registry.sessionTokens[tokenBindingId];
          await this.persistAccountsAndActivate(registry);
          await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
          await this.removePinProtectedUserKey(active.email);
          throw error;
        }
      }
      return true;
    });
  }

  /** Conservatively tighten every account before a global logout timeout setting is published. */
  async moveAllTokensToSession(): Promise<TokenStorageMoveReceipt> {
    return this.mutateAccountRegistry(async (registry) => {
      const moved: AuthTokenLease[] = [];
      const reclassified: TokenStorageMoveReceipt['reclassified'][number][] = [];
      const localAccounts = Object.values(registry.storedAccounts)
        .filter((account): account is PersistedAuth => !isSessionBackedAuth(account));
      const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
      const active = activeRaw === undefined || activeRaw === null
        ? undefined
        : parseStoredActiveAuth(activeRaw);
      for (const [owner, account] of Object.entries(registry.storedAccounts)) {
        if (!isSessionBackedAuth(account) || account.tokenStorageReason !== 'conservative') continue;
        const tokenLease = storedAuthTokenLease(account)!;
        reclassified.push({ tokenLease, previousReason: account.tokenStorageReason });
        registry.storedAccounts[owner] = { ...account, tokenStorageReason: 'localLogout' };
      }
      for (const account of localAccounts) {
        const tokenBindingId = this.createTokenBindingId();
        const identity = storedAuthTokenLease(account) ?? {
          email: account.email,
          credentialId: this.createCredentialId(),
          tokenRevision: this.createTokenRevision(),
        };
        const storedAccount = sessionBackedAuth(
          account,
          tokenBindingId,
          identity.credentialId,
          identity.tokenRevision,
          'localLogout',
        );
        moved.push(identity);
        registry.storedAccounts[account.email] = storedAccount;
        registry.sessionTokens[tokenBindingId] = sessionAuthTokens(account, storedAccount);
      }
      const activeAccount = active ? registry.storedAccounts[active.email] : undefined;
      // An older worker may have restored the pre-migration local copy while locking. Repair only
      // that exact credential generation; unrelated inconsistencies still fail closed at startup.
      const repairActiveCopy = active && activeAccount
        && isLocalBackedAuth(active)
        && isSessionBackedAuth(activeAccount)
        && storedAuthMatchesTokenLease(active, activeAccount)
        && samePersistedAuth(active, registry.accounts[active.email]!);
      if (moved.length === 0 && reclassified.length === 0 && !repairActiveCopy) {
        return Object.freeze({ moved: Object.freeze([]), reclassified: Object.freeze([]) });
      }
      const nextActive = activeAccount
        ? withStoredSessionBinding(activeAccount, active?.sessionBindingId)
        : undefined;
      try {
        await this.setLocalAccountState(registry.storedAccounts, nextActive ?? null);
      } catch (error) {
        const expected = Object.values(registry.storedAccounts).filter(isSessionBackedAuth);
        if (!await this.confirmSessionBackedLocalState(expected, nextActive)) throw error;
      }
      try {
        await this.writeSessionAuthTokens(registry.sessionTokens);
      } catch (error) {
        let committed = false;
        try {
          const confirmed = await this.loadSessionAuthTokens();
          committed = Object.values(registry.storedAccounts).every((account) => (
            !isSessionBackedAuth(account)
            || sameSessionAuthTokens(
              confirmed[account.tokenBindingId],
              registry.sessionTokens[account.tokenBindingId],
            )
          ));
        } catch {
          // Fall through to the terminal reset below.
        }
        if (!committed) {
          await this.resetAllAccountsWithinRegistryMutation();
          throw error;
        }
      }
      return Object.freeze({
        moved: Object.freeze(moved),
        reclassified: Object.freeze(reclassified),
      });
    });
  }

  /** Undo a pre-setting tightening when the setting write was rejected or did not commit. */
  async rollbackTokenStorageMove(receipt: TokenStorageMoveReceipt): Promise<void> {
    const movedCredentials = new Set(receipt.moved.map((entry) => entry.credentialId));
    const priorReasons = new Map(receipt.reclassified.map((entry) => [
      entry.tokenLease.credentialId,
      entry.previousReason,
    ]));
    await this.mutateAccountRegistry(async (registry) => {
      const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
      const active = activeRaw === undefined || activeRaw === null
        ? undefined
        : parseStoredActiveAuth(activeRaw);
      let nextActive = active;
      for (const [owner, account] of Object.entries(registry.storedAccounts)) {
        if (!isSessionBackedAuth(account)) continue;
        const priorReason = priorReasons.get(account.credentialId);
        if (priorReason) {
          const restoredReason = { ...account, tokenStorageReason: priorReason };
          registry.storedAccounts[owner] = restoredReason;
          if (active && storedAuthMatchesCredential(active, account)) {
            nextActive = withStoredSessionBinding(restoredReason, active.sessionBindingId);
          }
        }
        if (!movedCredentials.has(account.credentialId)) continue;
        const auth = composeStoredAuth(account, registry.sessionTokens[account.tokenBindingId]);
        if (!auth) continue;
        const local = localBackedAuth(auth, account.credentialId, account.tokenRevision);
        registry.accounts[owner] = stripSessionBinding(auth);
        registry.storedAccounts[owner] = local;
        delete registry.sessionTokens[account.tokenBindingId];
        if (active && storedAuthMatchesCredential(active, account)) {
          nextActive = withStoredSessionBinding(local, active.sessionBindingId);
        }
      }
      await this.setLocalAccountState(registry.storedAccounts, nextActive ?? null);
      await this.writeSessionAuthTokens(registry.sessionTokens);
    });
  }

  /** Restore every account whose session placement was owned by the local logout preference. */
  async restoreLocalLogoutTokensToLocal(): Promise<void> {
    await this.mutateAccountRegistry(async (registry) => {
      const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
      const active = activeRaw === undefined || activeRaw === null
        ? undefined
        : parseStoredActiveAuth(activeRaw);
      let nextActive = active;
      let changed = false;
      for (const [owner, account] of Object.entries(registry.storedAccounts)) {
        if (!isSessionBackedAuth(account) || account.tokenStorageReason !== 'localLogout') continue;
        const auth = composeStoredAuth(account, registry.sessionTokens[account.tokenBindingId]);
        if (!auth) continue;
        const local = localBackedAuth(auth, account.credentialId, account.tokenRevision);
        registry.accounts[owner] = stripSessionBinding(auth);
        registry.storedAccounts[owner] = local;
        delete registry.sessionTokens[account.tokenBindingId];
        if (active && storedAuthMatchesCredential(active, account)) {
          nextActive = withStoredSessionBinding(local, active.sessionBindingId);
        }
        changed = true;
      }
      if (!changed) return;
      await this.setLocalAccountState(registry.storedAccounts, nextActive ?? null);
      await this.writeSessionAuthTokens(registry.sessionTokens);
    });
  }

  async loadUserKey(): Promise<SymmetricKey | undefined> {
    const secrets = (await this.inspectSession()).secrets;
    secrets?.privateKey?.fill(0);
    return secrets?.userKey;
  }

  async loadPrivateKey(): Promise<Uint8Array | undefined> {
    const secrets = (await this.inspectSession()).secrets;
    if (secrets) clearSymmetricKey(secrets.userKey);
    return secrets?.privateKey;
  }

  async lock(): Promise<void> {
    await this.runAccountRegistryMutation(() => this.lockWithinRegistryMutation());
  }

  /** Lock without re-entering the registry queue when an account mutation already owns it. */
  private async lockWithinRegistryMutation(): Promise<void> {
    const auth = await this.getActiveAuth();
    if (auth?.sessionBindingId) {
      // Revoke the local half first. A reader that already loaded the bundle will fail its final
      // active-auth check even if this operation is interrupted before session storage is cleared.
      await this.clearActiveSessionBindingWithinRegistryMutation();
    }
    await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
    await this.clearLegacySessionSecrets();
  }

  /** Log out the active account: drop it from the registry, falling back to a remaining account
   *  (left locked) or fully logged out. Always clears the in-memory keys and PIN. */
  async logout(): Promise<void> {
    await this.mutateAccountRegistry((registry) => this.logoutWithinRegistryMutation(registry));
  }

  /** Log out only if the active credentials still belong to the refresh that requested it. */
  async logoutIfCurrent(
    expected: AuthTokenExpectation,
  ): Promise<boolean> {
    return this.mutateAccountRegistry(async (registry) => {
      const active = await this.getActiveAuth();
      if (!active || !matchesAuthExpectation(active, expected)) return false;
      await this.logoutWithinRegistryMutation(registry);
      return true;
    });
  }

  /** Log out only when the active account still owns one exact versioned token lease. */
  async logoutIfTokenCurrent(expected: AuthTokenLease): Promise<boolean> {
    return this.mutateAccountRegistry(async (registry) => {
      const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
      if (activeRaw === undefined || activeRaw === null) return false;
      const active = parseStoredActiveAuth(activeRaw);
      if (!storedAuthMatchesTokenLease(active, expected)) return false;
      await this.logoutWithinRegistryMutation(registry);
      return true;
    });
  }

  /** Reset every account only when the active account still owns one exact token lease. */
  async resetAllAccountsIfTokenCurrent(expected: AuthTokenLease): Promise<boolean> {
    return this.mutateAccountRegistry(async () => {
      const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
      if (activeRaw === undefined || activeRaw === null) return false;
      const active = parseStoredActiveAuth(activeRaw);
      if (!storedAuthMatchesTokenLease(active, expected)) return false;
      await this.resetAllAccountsWithinRegistryMutation();
      return true;
    });
  }

  /** All logged-in accounts (the active one flagged), for the account switcher. */
  async listAccounts(): Promise<AccountSummary[]> {
    const accounts = await this.loadAccounts();
    const active = (await this.getPersistedAuth())?.email;
    return Object.keys(accounts).map((email) => ({ email, active: email === active }));
  }

  /** Return the bounded credential generations currently retained by the account registry. */
  async listAuthTokenLeases(): Promise<readonly AuthTokenLease[]> {
    return this.mutateAccountRegistry(async (registry) => Object.freeze(
      Object.values(registry.storedAccounts).map((account) => {
        const lease = storedAuthTokenLease(account);
        if (!lease) throw new Error('Account registry contains an unversioned credential');
        return Object.freeze({ ...lease });
      }),
    ));
  }

  /** Make another logged-in account active. The vault is locked; PIN state remains owner-keyed. */
  async switchAccount(email: string): Promise<void> {
    await this.mutateAccountRegistry(async (registry) => {
      const target = registry.storedAccounts[email];
      if (!target) throw new Error('unknown account');
      await this.lockWithinRegistryMutation();
      await this.deps.localStore.set(AUTH_KEY, stripStoredSessionBinding(target));
    });
  }

  /** Remove an account. If it was active, fall back to a remaining account (locked) or logged out. */
  async removeAccount(email: string): Promise<void> {
    await this.mutateAccountRegistry(async (registry) => {
      const wasActive = (await this.getPersistedAuth())?.email === email;
      const removed = registry.storedAccounts[email];
      if (removed) removeRefreshIntentsForStoredAuth(registry.refreshIntents, removed);
      delete registry.accounts[email];
      delete registry.storedAccounts[email];
      if (wasActive) {
        await this.lockWithinRegistryMutation();
        await this.removePinProtectedUserKey(email);
        await this.persistAccountsAndActivate(registry);
      } else {
        await this.removePinProtectedUserKey(email);
        await this.persistAccountsKeepingActive(registry);
      }
      if (removed && isSessionBackedAuth(removed)) {
        delete registry.sessionTokens[removed.tokenBindingId];
        await this.writeSessionAuthTokens(registry.sessionTokens);
      }
      await this.writeRefreshIntents(registry.refreshIntents);
    });
  }

  /** Remove every authenticated account and unlock method while preserving device-level settings
   *  and remembered-2FA tokens. Used before changing the configured Vaultwarden server so tokens
   *  issued by the old server can never be sent to the new one. */
  async resetAllAccounts(): Promise<void> {
    await this.runAccountRegistryMutation(() => this.resetAllAccountsWithinRegistryMutation());
  }

  /** Fail closed on a corrupt or unsupported account registry before startup reads account owners. */
  async recoverInvalidAccountRegistry(): Promise<boolean> {
    return this.runAccountRegistryMutation(async () => {
      const [stored, activeRaw, rawSessionTokens, rawRefreshIntents] = await Promise.all([
        this.deps.localStore.get<unknown>(ACCOUNTS_KEY),
        this.deps.localStore.get<unknown>(AUTH_KEY),
        this.deps.sessionStore.get<unknown>(SESSION_AUTH_TOKENS_KEY),
        this.deps.localStore.get<unknown>(REFRESH_INTENTS_KEY),
      ]);
      if (stored === undefined) {
        const clean = (activeRaw === undefined || activeRaw === null)
          && Object.keys(parseSessionAuthTokenMap(rawSessionTokens)).length === 0
          && Object.keys(parseRefreshIntentMap(rawRefreshIntents)).length === 0;
        if (clean) return false;
        await this.resetAllAccountsWithinRegistryMutation();
        return true;
      }
      let storedAccounts: Record<string, StoredPersistedAuth>;
      let active: StoredActiveAuth | undefined;
      try {
        storedAccounts = parseStoredAccountRegistry(stored);
        if (Object.keys(storedAccounts).length > MAX_ACCOUNT_COUNT) {
          throw new Error('Persisted account registry exceeds the supported account limit');
        }
        active = activeRaw === undefined || activeRaw === null
          ? undefined
          : parseStoredActiveAuth(activeRaw);
      } catch {
        // Invalid persisted authentication is not safe to partially retain or silently trim.
        await this.resetAllAccountsWithinRegistryMutation();
        return true;
      }

      const sessionTokens = parseSessionAuthTokenMap(rawSessionTokens);
      const refreshIntents = parseRefreshIntentMap(rawRefreshIntents);
      let changed = storedAuthRegistryNeedsUpgrade(stored, rawSessionTokens, rawRefreshIntents);
      let activeRetired = false;

      for (const [operationId, intent] of Object.entries(refreshIntents)) {
        const account = storedAccounts[intent.email];
        const accountLease = account ? storedAuthTokenLease(account) : undefined;
        if (!account || accountLease?.credentialId !== intent.credentialId) {
          delete refreshIntents[operationId];
          changed = true;
          continue;
        }
        if (accountLease.tokenRevision !== intent.tokenRevision) {
          delete refreshIntents[operationId];
          changed = true;
          continue;
        }
        const committed = isSessionBackedAuth(account)
          && sessionTokens[account.tokenBindingId]?.credentialId === intent.credentialId
          && sessionTokens[account.tokenBindingId]?.tokenRevision === intent.nextTokenRevision;
        if (committed && isSessionBackedAuth(account)) {
          const adopted = { ...account, tokenRevision: intent.nextTokenRevision };
          storedAccounts[intent.email] = adopted;
          if (active && storedAuthMatchesTokenLease(active, intent)) {
            active = withStoredSessionBinding(adopted, active.sessionBindingId);
          }
          delete refreshIntents[operationId];
          changed = true;
          continue;
        }
        if (active && storedAuthMatchesTokenLease(active, intent)) activeRetired = true;
        if (isSessionBackedAuth(account)) delete sessionTokens[account.tokenBindingId];
        delete storedAccounts[intent.email];
        delete refreshIntents[operationId];
        await this.removePinProtectedUserKey(intent.email);
        changed = true;
      }

      const unavailableOwners = Object.values(storedAccounts)
        .filter((account) => isSessionBackedAuth(account)
          && !composeStoredAuth(account, sessionTokens[account.tokenBindingId]))
        .map((account) => account.email);
      for (const owner of unavailableOwners) {
        if (active?.email === owner) activeRetired = true;
        delete storedAccounts[owner];
        await this.removePinProtectedUserKey(owner);
        changed = true;
      }

      if (active && !activeRetired) {
        const activeAccount = storedAccounts[active.email];
        const compatibleLegacyPair = activeAccount
          && !isSessionBackedAuth(active)
          && !isSessionBackedAuth(activeAccount)
          && (!isVersionedAuth(active) || !isVersionedAuth(activeAccount))
          && samePersistedAuth(parseActiveAuth(active), parseActiveAuth(activeAccount));
        if (!activeAccount || (!sameStoredAccount(active, activeAccount) && !compatibleLegacyPair)) {
          await this.resetAllAccountsWithinRegistryMutation();
          return true;
        }
      } else if (!active && Object.keys(storedAccounts).length > 0 && !activeRetired) {
        await this.resetAllAccountsWithinRegistryMutation();
        return true;
      }

      for (const [owner, account] of Object.entries(storedAccounts)) {
        if (isVersionedAuth(account)) continue;
        const activeLease = active?.email === owner && isLocalBackedAuth(active)
          ? storedAuthTokenLease(active)
          : undefined;
        const upgraded = localBackedAuth(
          account,
          activeLease?.credentialId ?? this.createCredentialId(),
          activeLease?.tokenRevision ?? this.createTokenRevision(),
        );
        storedAccounts[owner] = upgraded;
        if (active?.email === owner) {
          active = withStoredSessionBinding(upgraded, active.sessionBindingId);
        }
        changed = true;
      }

      const canonicalTokens = Object.fromEntries(Object.values(storedAccounts).flatMap((account) => {
        if (!isSessionBackedAuth(account)) return [];
        const token = sessionTokens[account.tokenBindingId];
        return composeStoredAuth(account, token) ? [[account.tokenBindingId, token!]] : [];
      }));
      if (!sameSessionTokenMap(sessionTokens, canonicalTokens)) changed = true;
      if (!changed) return false;
      const matching = active && !activeRetired ? active : undefined;
      await this.setLocalAccountState(
        storedAccounts,
        matching ?? Object.values(storedAccounts)[0] ?? null,
        { [REFRESH_INTENTS_KEY]: refreshIntents },
      );
      await this.writeSessionAuthTokens(canonicalTokens);
      if (!matching) await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
      return true;
    });
  }

  private async resetAllAccountsWithinRegistryMutation(): Promise<void> {
    // Invalidate the active binding first so an interrupted reset cannot retain usable secrets.
    await this.deps.localStore.remove(AUTH_KEY);
    await this.deps.sessionStore.remove(SESSION_AUTH_TOKENS_KEY);
    await this.deps.localStore.remove(REFRESH_INTENTS_KEY);
    await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
    await this.clearLegacySessionSecrets();
    await this.runPinMutation(async () => {
      await this.deps.localStore.remove(LEGACY_PIN_KEY);
      await this.deps.localStore.remove(PIN_CONFIGURATIONS_KEY);
      await this.deps.sessionStore.remove(PIN_EPHEMERAL_ENVELOPES_KEY);
      await this.deps.sessionStore.remove(PIN_FAILURES_KEY);
    });
    await this.deps.localStore.remove(ACCOUNTS_KEY);
  }

  private async loadAccounts(): Promise<Record<string, PersistedAuth>> {
    return (await this.loadAccountRegistry()).accounts;
  }

  private async loadAccountRegistry(): Promise<AccountRegistrySnapshot> {
    const [stored, refreshIntents] = await Promise.all([
      this.deps.localStore.get<unknown>(ACCOUNTS_KEY),
      this.loadRefreshIntents(),
    ]);
    const storedAccounts = stored === undefined
      ? {}
      : parseStoredAccountRegistry(stored);
    if (Object.keys(storedAccounts).length > MAX_ACCOUNT_COUNT) {
      throw new Error('Persisted account registry exceeds the supported account limit');
    }
    const hasSessionBackedAccount = Object.values(storedAccounts).some(isSessionBackedAuth);
    const sessionTokens = hasSessionBackedAccount ? await this.loadSessionAuthTokens() : {};
    const accounts = Object.fromEntries(Object.entries(storedAccounts).map(([owner, account]) => {
      const composed = composeStoredAuth(
        account,
        isSessionBackedAuth(account) ? sessionTokens[account.tokenBindingId] : undefined,
      );
      if (!composed) throw new Error(`Session authentication token is unavailable for ${owner}`);
      return [owner, stripSessionBinding(composed)];
    }));
    return { accounts, storedAccounts, sessionTokens, refreshIntents };
  }

  private async commitAuthenticatedAccount(
    registry: AccountRegistrySnapshot,
    account: PersistedAuth,
    active: ActiveAuth,
    replaceCredential = true,
  ): Promise<void> {
    const previous = registry.storedAccounts[account.email];
    const previousLease = previous ? storedAuthTokenLease(previous) : undefined;
    if (!replaceCredential && !previousLease) {
      throw new Error('Unlock requires an existing versioned credential');
    }
    if (previous && replaceCredential) {
      removeRefreshIntentsForStoredAuth(registry.refreshIntents, previous);
    }
    const credentialId = replaceCredential
      ? this.createCredentialId()
      : previousLease!.credentialId;
    const tokenRevision = replaceCredential
      ? this.createTokenRevision()
      : previousLease!.tokenRevision;
    const tokenStorage = !replaceCredential && previous
      ? isSessionBackedAuth(previous) ? 'session' : 'local'
      : this.deps.defaultTokenStorage ?? 'local';
    if (tokenStorage === 'local') {
      const storedAccount = localBackedAuth(account, credentialId, tokenRevision);
      const storedActive = withStoredSessionBinding(storedAccount, active.sessionBindingId);
      registry.accounts[account.email] = account;
      registry.storedAccounts[account.email] = storedAccount;
      await this.setLocalAccountState(registry.storedAccounts, storedActive);
      await this.writeRefreshIntents(registry.refreshIntents);
      if (previous && isSessionBackedAuth(previous)) {
        delete registry.sessionTokens[previous.tokenBindingId];
        await this.writeSessionAuthTokens(registry.sessionTokens);
      }
      return;
    }

    const tokenBindingId = this.createTokenBindingId();
    const storedAccount = sessionBackedAuth(
      account,
      tokenBindingId,
      credentialId,
      tokenRevision,
      !replaceCredential && previous && isSessionBackedAuth(previous)
        ? previous.tokenStorageReason
        : 'conservative',
    );
    const storedActive = withStoredSessionBinding(storedAccount, active.sessionBindingId);
    const token = sessionAuthTokens(account, storedAccount);
    const nextTokens = { ...registry.sessionTokens, [tokenBindingId]: token };
    const nextAccounts = { ...registry.storedAccounts, [account.email]: storedAccount };
    try {
      await this.setLocalAccountState(nextAccounts, storedActive);
    } catch (error) {
      let committed = false;
      try {
        const current = await this.deps.localStore.get<unknown>(AUTH_KEY);
        committed = current !== undefined
          && current !== null
          && sameStoredActiveAuth(parseStoredActiveAuth(current), storedActive);
      } catch {
        // If the local commit cannot be proven, the unreferenced session slot is cleaned below.
      }
      if (!committed) {
        throw error;
      }
    }
    try {
      await this.writeSessionAuthTokens(nextTokens);
    } catch (error) {
      let committed = false;
      try {
        committed = sameSessionAuthTokens(
          (await this.loadSessionAuthTokens())[tokenBindingId],
          token,
        );
      } catch {
        // An unreadable session area cannot prove that the exact slot was committed.
      }
      if (!committed) {
        delete nextAccounts[account.email];
        const fallback = Object.values(nextAccounts)[0] ?? null;
        await this.setLocalAccountState(nextAccounts, fallback);
        await this.deps.sessionStore.remove(SESSION_SECRETS_KEY);
        await this.removePinProtectedUserKey(account.email);
        throw error;
      }
    }
    registry.accounts[account.email] = account;
    registry.storedAccounts[account.email] = storedAccount;
    Object.assign(registry.sessionTokens, nextTokens);
    if (previous && isSessionBackedAuth(previous)) {
      delete registry.sessionTokens[previous.tokenBindingId];
      await this.writeSessionAuthTokens(registry.sessionTokens);
    }
    await this.writeRefreshIntents(registry.refreshIntents);
  }

  private getAuthForTokenLease(
    registry: AccountRegistrySnapshot,
    expected: AuthTokenLease,
  ): PersistedAuth | undefined {
    const stored = registry.storedAccounts[expected.email];
    if (!stored || !storedAuthMatchesTokenLease(stored, expected)) return undefined;
    const token = isSessionBackedAuth(stored)
      ? registry.sessionTokens[stored.tokenBindingId]
      : undefined;
    const composed = composeStoredAuth(stored, token);
    return composed ? stripSessionBinding(composed) : undefined;
  }

  private async commitTokensForLease(
    registry: AccountRegistrySnapshot,
    expected: AuthTokenLease,
    nextTokenRevision: string,
    tokens: { accessToken: string; refreshToken: string; expiresAt: number },
    refreshOperationId?: string,
  ): Promise<AuthTokenLease | undefined> {
    const auth = this.getAuthForTokenLease(registry, expected);
    const stored = registry.storedAccounts[expected.email];
    if (!auth || !stored || !storedAuthMatchesTokenLease(stored, expected)) return undefined;
    const updated = parsePersistedAuth({ ...auth, ...tokens });
    const nextLease: AuthTokenLease = {
      email: expected.email,
      credentialId: expected.credentialId,
      tokenRevision: nextTokenRevision,
    };
    const activeRaw = await this.deps.localStore.get<unknown>(AUTH_KEY);
    const active = activeRaw === undefined || activeRaw === null
      ? undefined
      : parseStoredActiveAuth(activeRaw);
    const activeIsOwner = Boolean(active && storedAuthMatchesTokenLease(active, expected));
    const nextIntents = { ...registry.refreshIntents };
    if (refreshOperationId) delete nextIntents[refreshOperationId];
    registry.accounts[expected.email] = updated;

    if (!isSessionBackedAuth(stored)) {
      const nextStored = localBackedAuth(updated, expected.credentialId, nextTokenRevision);
      registry.storedAccounts[expected.email] = nextStored;
      const nextActive = activeIsOwner
        ? withStoredSessionBinding(nextStored, active?.sessionBindingId)
        : active ?? null;
      await this.setLocalAccountState(registry.storedAccounts, nextActive, refreshOperationId
        ? { [REFRESH_INTENTS_KEY]: nextIntents }
        : {});
      Object.assign(registry.refreshIntents, nextIntents);
      if (refreshOperationId) delete registry.refreshIntents[refreshOperationId];
      return nextLease;
    }

    const nextStored = sessionBackedAuth(
      updated,
      stored.tokenBindingId,
      expected.credentialId,
      nextTokenRevision,
      stored.tokenStorageReason,
    );
    const nextToken = sessionAuthTokens(updated, nextStored);
    registry.sessionTokens[stored.tokenBindingId] = nextToken;
    await this.writeSessionAuthTokens(registry.sessionTokens);
    registry.storedAccounts[expected.email] = nextStored;
    const nextActive = activeIsOwner
      ? withStoredSessionBinding(nextStored, active?.sessionBindingId)
      : active ?? null;
    await this.setLocalAccountState(registry.storedAccounts, nextActive, refreshOperationId
      ? { [REFRESH_INTENTS_KEY]: nextIntents }
      : {});
    Object.assign(registry.refreshIntents, nextIntents);
    if (refreshOperationId) delete registry.refreshIntents[refreshOperationId];
    return nextLease;
  }

  private async persistUpdatedActiveAuth(
    registry: AccountRegistrySnapshot,
    active: ActiveAuth,
  ): Promise<void> {
    const current = registry.storedAccounts[active.email];
    if (!current) throw new Error('Active account is absent from the registry');
    const identity = storedAuthTokenLease(current) ?? {
      email: active.email,
      credentialId: this.createCredentialId(),
      tokenRevision: this.createTokenRevision(),
    };
    const persisted = stripSessionBinding(active);
    registry.accounts[active.email] = persisted;
    if (!isSessionBackedAuth(current)) {
      const stored = localBackedAuth(
        persisted,
        identity.credentialId,
        identity.tokenRevision,
      );
      registry.storedAccounts[active.email] = stored;
      await this.setLocalAccountState(
        registry.storedAccounts,
        withStoredSessionBinding(stored, active.sessionBindingId),
      );
      return;
    }
    const token = sessionAuthTokens(active, current);
    registry.sessionTokens[current.tokenBindingId] = token;
    try {
      await this.writeSessionAuthTokens(registry.sessionTokens);
    } catch (error) {
      let committed = false;
      try {
        committed = sameSessionAuthTokens(
          (await this.loadSessionAuthTokens())[current.tokenBindingId],
          token,
        );
      } catch {
        // Preserve the original write failure when the exact commit cannot be confirmed.
      }
      if (!committed) throw error;
    }
    const stored = sessionBackedAuth(
      active,
      current.tokenBindingId,
      current.credentialId,
      current.tokenRevision,
      current.tokenStorageReason,
    );
    registry.storedAccounts[active.email] = stored;
    await this.setLocalAccountState(
      registry.storedAccounts,
      withStoredSessionBinding(stored, active.sessionBindingId),
    );
  }

  private async clearActiveSessionBindingWithinRegistryMutation(): Promise<void> {
    const raw = await this.deps.localStore.get<unknown>(AUTH_KEY);
    if (raw === undefined || raw === null) return;
    const active = parseStoredPersistedAuth(raw);
    await this.deps.localStore.set(AUTH_KEY, active);
  }

  private async persistAccountsKeepingActive(registry: AccountRegistrySnapshot): Promise<void> {
    const raw = await this.deps.localStore.get<unknown>(AUTH_KEY);
    const active = raw === undefined || raw === null ? undefined : parseStoredActiveAuth(raw);
    const activeAccount = active ? registry.storedAccounts[active.email] : undefined;
    const retained = active && activeAccount
      && sameStoredAccount(active, activeAccount)
      ? active
      : Object.values(registry.storedAccounts)[0];
    await this.setLocalAccountState(registry.storedAccounts, retained ?? null);
  }

  private async setLocalAccountState(
    accounts: Readonly<Record<string, StoredPersistedAuth>>,
    active: StoredActiveAuth | null,
    extra: Readonly<Record<string, unknown>> = {},
  ): Promise<void> {
    const setMany = this.deps.localStore.setMany;
    if (!setMany) throw new Error('Atomic multi-key storage writes are not supported');
    await setMany.call(this.deps.localStore, {
      [ACCOUNTS_KEY]: accounts,
      [AUTH_KEY]: active,
      ...extra,
    });
    if (active === null) await this.deps.localStore.remove(AUTH_KEY);
  }

  private async confirmSessionBackedLocalState(
    accounts: readonly SessionBackedAuth[],
    active: StoredActiveAuth | undefined,
  ): Promise<boolean> {
    try {
      const [rawAccounts, rawActive] = await Promise.all([
        this.deps.localStore.get<unknown>(ACCOUNTS_KEY),
        this.deps.localStore.get<unknown>(AUTH_KEY),
      ]);
      if (!isRecord(rawAccounts)) return false;
      if (!accounts.every((account) => rawSessionBackedAuthMatches(rawAccounts[account.email], account))) {
        return false;
      }
      if (!active) return rawActive === undefined || rawActive === null;
      return isSessionBackedAuth(active)
        && rawSessionBackedAuthMatches(rawActive, active, true);
    } catch {
      return false;
    }
  }

  private async loadSessionAuthTokens(): Promise<Record<string, SessionAuthTokensV1>> {
    const stored = await this.deps.sessionStore.get<unknown>(SESSION_AUTH_TOKENS_KEY);
    return parseSessionAuthTokenMap(stored);
  }

  private async loadRefreshIntents(): Promise<Record<string, RefreshIntentV1>> {
    const stored = await this.deps.localStore.get<unknown>(REFRESH_INTENTS_KEY);
    return parseRefreshIntentMap(stored);
  }

  private async writeRefreshIntents(
    intents: Readonly<Record<string, RefreshIntentV1>>,
  ): Promise<void> {
    if (Object.keys(intents).length === 0) {
      await this.deps.localStore.remove(REFRESH_INTENTS_KEY);
    } else {
      await this.deps.localStore.set(REFRESH_INTENTS_KEY, intents);
    }
  }

  private async writeSessionAuthTokens(
    tokens: Readonly<Record<string, SessionAuthTokensV1>>,
  ): Promise<void> {
    if (Object.keys(tokens).length === 0) {
      await this.deps.sessionStore.remove(SESSION_AUTH_TOKENS_KEY);
    } else {
      await this.deps.sessionStore.set(SESSION_AUTH_TOKENS_KEY, tokens);
    }
  }

  private createTokenBindingId(): string {
    const id = crypto.randomUUID();
    if (!id.trim()) throw new Error('Token binding ID cannot be blank');
    return id;
  }

  private createCredentialId(): string {
    const id = crypto.randomUUID();
    if (!id.trim()) throw new Error('Credential ID cannot be blank');
    return id;
  }

  private createTokenRevision(): string {
    const id = crypto.randomUUID();
    if (!id.trim()) throw new Error('Token revision cannot be blank');
    return id;
  }

  private assertAccountAdmission(
    accounts: Readonly<Record<string, PersistedAuth>>,
    email: string,
  ): void {
    if (
      !Object.prototype.hasOwnProperty.call(accounts, email)
      && Object.keys(accounts).length >= MAX_ACCOUNT_COUNT
    ) {
      throw new Error(`Account limit of ${MAX_ACCOUNT_COUNT} reached`);
    }
  }

  private async logoutWithinRegistryMutation(
    registry: AccountRegistrySnapshot,
  ): Promise<void> {
    await this.lockWithinRegistryMutation();
    const active = (await this.getPersistedAuth())?.email;
    if (active) {
      await this.removePinProtectedUserKey(active);
      const removed = registry.storedAccounts[active];
      if (removed) removeRefreshIntentsForStoredAuth(registry.refreshIntents, removed);
      delete registry.accounts[active];
      delete registry.storedAccounts[active];
      if (removed && isSessionBackedAuth(removed)) {
        delete registry.sessionTokens[removed.tokenBindingId];
      }
    }
    await this.persistAccountsAndActivate(registry);
    await this.writeSessionAuthTokens(registry.sessionTokens);
    await this.writeRefreshIntents(registry.refreshIntents);
  }

  private async mutateAccountRegistry<Result>(
    mutation: (registry: AccountRegistrySnapshot) => Promise<Result>,
  ): Promise<Result> {
    return this.runAccountRegistryMutation(async () => mutation(await this.loadAccountRegistry()));
  }

  private async runAccountRegistryMutation<Result>(
    mutation: () => Promise<Result>,
  ): Promise<Result> {
    const run = this.accountRegistryMutationTail.then(mutation, mutation);
    this.accountRegistryMutationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Persist the registry and point AUTH at a remaining account, or clear it when none remain. */
  private async persistAccountsAndActivate(registry: AccountRegistrySnapshot): Promise<void> {
    const remaining = Object.values(registry.storedAccounts)[0];
    await this.setLocalAccountState(registry.storedAccounts, remaining ?? null);
  }

  /**
   * Save a PIN-protected UserKey for the active account. The default after-first-unlock mode keeps
   * the brute-forceable envelope in browser session storage; only an explicit opt-out persists it.
   */
  async savePinProtectedUserKey(
    protectedUserKey: string,
    options: {
      readonly owner?: string;
      readonly requireMasterPasswordOnRestart?: boolean;
      readonly encryptedPin?: string;
    } = {},
  ): Promise<void> {
    if (!protectedUserKey) throw new Error('PIN-protected UserKey cannot be blank');
    const owner = await this.requireActivePinOwner(options.owner);
    const requireMasterPasswordOnRestart = options.requireMasterPasswordOnRestart !== false;
    if (requireMasterPasswordOnRestart && !options.encryptedPin) {
      throw new Error('After-first-unlock PIN state requires a UserKey-encrypted PIN');
    }
    const configurationId = crypto.randomUUID();
    if (!configurationId.trim()) throw new Error('PIN configuration ID cannot be blank');

    await this.runPinMutation(async () => {
      const configurations = await this.loadPinConfigurations();
      const envelopes = await this.loadPinEphemeralEnvelopes();
      if (requireMasterPasswordOnRestart) {
        envelopes[owner] = {
          schemaVersion: 1,
          configurationId,
          protectedUserKey,
        };
        await this.writePinMap(this.deps.sessionStore, PIN_EPHEMERAL_ENVELOPES_KEY, envelopes);
        configurations[owner] = {
          schemaVersion: 1,
          configurationId,
          lockType: 'afterFirstUnlock',
          encryptedPin: options.encryptedPin!,
        };
      } else {
        configurations[owner] = {
          schemaVersion: 1,
          configurationId,
          lockType: 'beforeFirstUnlock',
          protectedUserKey,
        };
      }
      await this.writePinMap(this.deps.localStore, PIN_CONFIGURATIONS_KEY, configurations);
      if (!requireMasterPasswordOnRestart && envelopes[owner]) {
        delete envelopes[owner];
        await this.writePinMap(this.deps.sessionStore, PIN_EPHEMERAL_ENVELOPES_KEY, envelopes);
      }
      await this.clearPinFailuresForOwner(owner);
      await this.deps.localStore.remove(LEGACY_PIN_KEY);
    });
  }

  async getPinUnlockState(owner?: string): Promise<PinUnlockState | undefined> {
    const resolvedOwner = await this.resolvePinOwner(owner);
    if (!resolvedOwner) return undefined;
    return this.getPinUnlockStateForOwner(resolvedOwner);
  }

  async getPinProtectedUserKey(owner?: string): Promise<string | undefined> {
    return (await this.getPinUnlockState(owner))?.protectedUserKey;
  }

  async getPinStateSummary(owner?: string): Promise<PinStateSummary> {
    const resolvedOwner = await this.resolvePinOwner(owner);
    if (!resolvedOwner) {
      return { configured: false, available: false, requireMasterPasswordOnRestart: true };
    }
    const [configurations, envelopes] = await Promise.all([
      this.loadPinConfigurations(),
      this.loadPinEphemeralEnvelopes(),
    ]);
    const configuration = configurations[resolvedOwner];
    const envelope = envelopes[resolvedOwner];
    const legacyAvailable = configuration === undefined && envelope?.legacy === true;
    const available = Boolean(this.pinUnlockStateFrom(configuration, envelope));
    return {
      configured: configuration !== undefined || legacyAvailable,
      available,
      requireMasterPasswordOnRestart: configuration?.lockType !== 'beforeFirstUnlock',
    };
  }

  async getPinRearmData(owner?: string): Promise<PinRearmData | undefined> {
    const resolvedOwner = await this.resolvePinOwner(owner);
    if (!resolvedOwner) return undefined;
    const configuration = (await this.loadPinConfigurations())[resolvedOwner];
    return configuration?.lockType === 'afterFirstUnlock'
      ? {
          configurationId: configuration.configurationId,
          encryptedPin: configuration.encryptedPin,
        }
      : undefined;
  }

  async saveRearmedPinProtectedUserKey(
    owner: string,
    expectedConfigurationId: string,
    protectedUserKey: string,
  ): Promise<boolean> {
    const resolvedOwner = await this.requireActivePinOwner(owner);
    return this.runPinMutation(async () => {
      const configuration = (await this.loadPinConfigurations())[resolvedOwner];
      if (
        configuration?.lockType !== 'afterFirstUnlock'
        || configuration.configurationId !== expectedConfigurationId
      ) return false;
      const envelopes = await this.loadPinEphemeralEnvelopes();
      envelopes[resolvedOwner] = {
        schemaVersion: 1,
        configurationId: expectedConfigurationId,
        protectedUserKey,
      };
      await this.writePinMap(this.deps.sessionStore, PIN_EPHEMERAL_ENVELOPES_KEY, envelopes);
      await this.clearPinFailuresForOwner(resolvedOwner);
      return true;
    });
  }

  async upgradeLegacyPinAfterUnlock(
    owner: string,
    expectedProtectedUserKey: string,
    encryptedPin: string,
  ): Promise<boolean> {
    const resolvedOwner = await this.requireActivePinOwner(owner);
    return this.runPinMutation(async () => {
      const configurations = await this.loadPinConfigurations();
      const envelopes = await this.loadPinEphemeralEnvelopes();
      const envelope = envelopes[resolvedOwner];
      if (
        configurations[resolvedOwner]
        || envelope?.legacy !== true
        || envelope.protectedUserKey !== expectedProtectedUserKey
      ) return false;
      const configurationId = crypto.randomUUID();
      configurations[resolvedOwner] = {
        schemaVersion: 1,
        configurationId,
        lockType: 'afterFirstUnlock',
        encryptedPin,
      };
      await this.writePinMap(this.deps.localStore, PIN_CONFIGURATIONS_KEY, configurations);
      envelopes[resolvedOwner] = {
        schemaVersion: 1,
        configurationId,
        protectedUserKey: expectedProtectedUserKey,
      };
      await this.writePinMap(this.deps.sessionStore, PIN_EPHEMERAL_ENVELOPES_KEY, envelopes);
      return true;
    });
  }

  async removePinProtectedUserKey(owner?: string): Promise<void> {
    const resolvedOwner = await this.resolvePinOwner(owner);
    if (!resolvedOwner) {
      await this.deps.localStore.remove(LEGACY_PIN_KEY);
      return;
    }
    await this.runPinMutation(() => this.removePinStateForOwner(resolvedOwner));
  }

  /** Remove a failed PIN commit only when its envelope is still the current credential. */
  async removePinProtectedUserKeyIfCurrent(
    expectedProtectedUserKey: string,
    owner?: string,
  ): Promise<boolean> {
    const resolvedOwner = await this.resolvePinOwner(owner);
    if (!resolvedOwner) return false;
    return this.runPinMutation(async () => {
      const envelopes = await this.loadPinEphemeralEnvelopes();
      const configurations = await this.loadPinConfigurations();
      const configuration = configurations[resolvedOwner];
      const envelope = envelopes[resolvedOwner];
      const current = this.pinUnlockStateFrom(configuration, envelope);
      const pendingEnvelopeMatches = envelope?.protectedUserKey === expectedProtectedUserKey;
      if (current?.protectedUserKey !== expectedProtectedUserKey && !pendingEnvelopeMatches) {
        return false;
      }
      await this.removePinStateForOwner(resolvedOwner, configurations, envelopes);
      return true;
    });
  }

  async recordFailedPinAttempt(
    owner: string,
    expectedCredentialId: string,
  ): Promise<number | undefined> {
    const resolvedOwner = await this.requireActivePinOwner(owner);
    return this.runPinMutation(async () => {
      const current = await this.getPinUnlockStateForOwner(resolvedOwner);
      if (current?.credentialId !== expectedCredentialId) return undefined;
      const failures = await this.loadPinFailures();
      const previous = failures[resolvedOwner];
      const attempts = previous?.credentialId === expectedCredentialId
        ? Math.min(5, previous.attempts + 1)
        : 1;
      failures[resolvedOwner] = {
        schemaVersion: 1,
        credentialId: expectedCredentialId,
        attempts,
      };
      await this.writePinMap(this.deps.sessionStore, PIN_FAILURES_KEY, failures);
      return attempts;
    });
  }

  async clearFailedPinAttempts(owner: string, expectedCredentialId?: string): Promise<void> {
    const resolvedOwner = await this.requireActivePinOwner(owner);
    await this.runPinMutation(async () => {
      const failures = await this.loadPinFailures();
      if (
        expectedCredentialId !== undefined
        && failures[resolvedOwner]?.credentialId !== expectedCredentialId
      ) return;
      if (!failures[resolvedOwner]) return;
      delete failures[resolvedOwner];
      await this.writePinMap(this.deps.sessionStore, PIN_FAILURES_KEY, failures);
    });
  }

  private async migrateLegacyPin(owner: string | undefined): Promise<void> {
    const legacy = await this.deps.localStore.get<unknown>(LEGACY_PIN_KEY);
    if (legacy === undefined) return;
    if (typeof legacy !== 'string' || !legacy || !owner) {
      await this.deps.localStore.remove(LEGACY_PIN_KEY);
      return;
    }
    const normalizedOwner = normalizePinOwner(owner);
    await this.runPinMutation(async () => {
      const configurations = await this.loadPinConfigurations();
      const envelopes = await this.loadPinEphemeralEnvelopes();
      if (!configurations[normalizedOwner] && !envelopes[normalizedOwner]) {
        envelopes[normalizedOwner] = {
          schemaVersion: 1,
          configurationId: `legacy-${crypto.randomUUID()}`,
          protectedUserKey: legacy,
          legacy: true,
        };
        // Commit the session-only copy before deleting the legacy persistent credential.
        await this.writePinMap(this.deps.sessionStore, PIN_EPHEMERAL_ENVELOPES_KEY, envelopes);
      }
      await this.deps.localStore.remove(LEGACY_PIN_KEY);
    });
  }

  private async getPinUnlockStateForOwner(owner: string): Promise<PinUnlockState | undefined> {
    const [configurations, envelopes] = await Promise.all([
      this.loadPinConfigurations(),
      this.loadPinEphemeralEnvelopes(),
    ]);
    return this.pinUnlockStateFrom(configurations[owner], envelopes[owner]);
  }

  private pinUnlockStateFrom(
    configuration: PinConfigurationV1 | undefined,
    envelope: PinEphemeralEnvelopeV1 | undefined,
  ): PinUnlockState | undefined {
    if (configuration?.lockType === 'beforeFirstUnlock') {
      return {
        protectedUserKey: configuration.protectedUserKey,
        credentialId: configuration.configurationId,
        requireMasterPasswordOnRestart: false,
        legacy: false,
      };
    }
    if (
      configuration?.lockType === 'afterFirstUnlock'
      && envelope?.configurationId === configuration.configurationId
    ) {
      return {
        protectedUserKey: envelope.protectedUserKey,
        credentialId: configuration.configurationId,
        requireMasterPasswordOnRestart: true,
        legacy: false,
      };
    }
    if (!configuration && envelope?.legacy === true) {
      return {
        protectedUserKey: envelope.protectedUserKey,
        credentialId: envelope.configurationId,
        requireMasterPasswordOnRestart: true,
        legacy: true,
      };
    }
    return undefined;
  }

  private async removePinStateForOwner(
    owner: string,
    loadedConfigurations?: Record<string, PinConfigurationV1>,
    loadedEnvelopes?: Record<string, PinEphemeralEnvelopeV1>,
  ): Promise<void> {
    const configurations = loadedConfigurations ?? await this.loadPinConfigurations();
    if (configurations[owner]) {
      delete configurations[owner];
      // Removing disk configuration first makes both persistent and paired session envelopes unusable.
      await this.writePinMap(this.deps.localStore, PIN_CONFIGURATIONS_KEY, configurations);
    }
    const envelopes = loadedEnvelopes ?? await this.loadPinEphemeralEnvelopes();
    if (envelopes[owner]) {
      delete envelopes[owner];
      await this.writePinMap(this.deps.sessionStore, PIN_EPHEMERAL_ENVELOPES_KEY, envelopes);
    }
    await this.clearPinFailuresForOwner(owner);
    await this.deps.localStore.remove(LEGACY_PIN_KEY);
  }

  private async clearPinFailuresForOwner(owner: string): Promise<void> {
    const failures = await this.loadPinFailures();
    if (!failures[owner]) return;
    delete failures[owner];
    await this.writePinMap(this.deps.sessionStore, PIN_FAILURES_KEY, failures);
  }

  private async resolvePinOwner(owner?: string): Promise<string | undefined> {
    if (owner !== undefined) return normalizePinOwner(owner);
    return (await this.getPersistedAuth())?.email;
  }

  private async requireActivePinOwner(owner?: string): Promise<string> {
    const active = (await this.getPersistedAuth())?.email;
    if (!active) throw new Error('not logged in');
    const resolvedOwner = owner === undefined ? active : normalizePinOwner(owner);
    if (resolvedOwner !== active) throw new Error('active account changed');
    return resolvedOwner;
  }

  private loadPinConfigurations(): Promise<Record<string, PinConfigurationV1>> {
    return this.loadPinMap(PIN_CONFIGURATIONS_KEY, this.deps.localStore, parsePinConfiguration);
  }

  private loadPinEphemeralEnvelopes(): Promise<Record<string, PinEphemeralEnvelopeV1>> {
    return this.loadPinMap(
      PIN_EPHEMERAL_ENVELOPES_KEY,
      this.deps.sessionStore,
      parsePinEphemeralEnvelope,
    );
  }

  private loadPinFailures(): Promise<Record<string, PinFailureStateV1>> {
    return this.loadPinMap(PIN_FAILURES_KEY, this.deps.sessionStore, parsePinFailureState);
  }

  private async loadPinMap<T>(
    key: string,
    store: KeyValueStore,
    parseEntry: (value: unknown) => T | undefined,
  ): Promise<Record<string, T>> {
    const stored = await store.get<unknown>(key);
    if (!isRecord(stored)) return {};
    return Object.fromEntries(Object.entries(stored).flatMap(([owner, value]) => {
      const parsed = parseEntry(value);
      if (!parsed) return [];
      try {
        return [[normalizePinOwner(owner), parsed]] as const;
      } catch {
        return [];
      }
    }));
  }

  private async writePinMap<T>(
    store: KeyValueStore,
    key: string,
    value: Readonly<Record<string, T>>,
  ): Promise<void> {
    if (Object.keys(value).length === 0) {
      await store.remove(key);
    } else {
      await store.set(key, value);
    }
  }

  private async runPinMutation<T>(mutation: () => Promise<T>): Promise<T> {
    const run = this.pinMutationTail.then(mutation, mutation);
    this.pinMutationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Roll back a failed unlock only while its exact owner/binding is still active. */
  async lockIfCurrentSessionBinding(
    expected: { readonly email: string; readonly sessionBindingId: string },
  ): Promise<boolean> {
    return this.runAccountRegistryMutation(async () => {
      const active = await this.getActiveAuth();
      if (active?.email !== expected.email || active.sessionBindingId !== expected.sessionBindingId) {
        return false;
      }
      await this.lockWithinRegistryMutation();
      return true;
    });
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
    await this.runRememberTokenMutation(async () => {
      const map = await this.loadRememberTokens();
      map[rememberKey(serverUrl, email)] = token;
      await this.deps.localStore.set(REMEMBER_TOKENS_KEY, map);
    });
  }

  async removeRememberDeviceToken(serverUrl: string, email: string): Promise<void> {
    await this.runRememberTokenMutation(async () => {
      const map = await this.loadRememberTokens();
      if (!(rememberKey(serverUrl, email) in map)) return;
      delete map[rememberKey(serverUrl, email)];
      await this.deps.localStore.set(REMEMBER_TOKENS_KEY, map);
    });
  }

  private async loadRememberTokens(): Promise<Record<string, string>> {
    return (await this.deps.localStore.get<Record<string, string>>(REMEMBER_TOKENS_KEY)) ?? {};
  }

  private async runRememberTokenMutation(mutation: () => Promise<void>): Promise<void> {
    const run = this.rememberTokenMutationTail.then(mutation, mutation);
    this.rememberTokenMutationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  private createSessionBindingId(): string {
    const id = this.deps.createSessionBindingId?.() ?? crypto.randomUUID();
    if (!id.trim()) throw new Error('Session binding ID cannot be blank');
    return id;
  }

  private async inspectSession(): Promise<SessionInspection> {
    const before = await this.getActiveAuth();
    const stored = await this.deps.sessionStore.get<unknown>(SESSION_SECRETS_KEY);
    const secrets = parseSessionSecrets(stored);
    const valid = Boolean(
      before?.sessionBindingId
      && secrets
      && secrets.owner === before.email
      && secrets.sessionBindingId === before.sessionBindingId,
    );

    // This read must remain the final storage await. It detects account switches, re-login with the
    // same owner, and lock/logout after the bundle was read (including A -> B -> A sequences).
    let ownershipTransferred = false;
    try {
      const after = await this.getActiveAuth();
      if (!after) return {};
      if (!valid || !before || !sameBoundOwner(before, after)) {
        return { auth: stripSessionBinding(after) };
      }
      ownershipTransferred = true;
      return { auth: stripSessionBinding(after), secrets: secrets! };
    } finally {
      if (!ownershipTransferred) clearLoadedSessionSecrets(secrets);
    }
  }

  private async clearLegacySessionSecrets(): Promise<void> {
    await this.deps.sessionStore.remove(USER_KEY_KEY);
    await this.deps.sessionStore.remove(PRIVATE_KEY_KEY);
  }
}

function clearSymmetricKey(key: SymmetricKey): void {
  key.encKey.fill(0);
  key.macKey.fill(0);
}

function clearLoadedSessionSecrets(secrets: LoadedSessionSecrets | undefined): void {
  if (!secrets) return;
  clearSymmetricKey(secrets.userKey);
  secrets.privateKey?.fill(0);
}

/** Compose the per-(server,email) storage key. Newline separates the two (absent from URLs/emails). */
function rememberKey(serverUrl: string, email: string): string {
  return `${serverUrl}\n${email}`;
}

function parseStoredAccountRegistry(value: unknown): Record<string, StoredPersistedAuth> {
  if (!isRecord(value)) throw new Error('Invalid persisted account registry');
  return Object.fromEntries(Object.entries(value).map(([email, candidate]) => {
    const auth = parseStoredPersistedAuth(candidate);
    if (auth.email !== email) throw new Error('Invalid persisted account registry owner');
    return [email, auth];
  }));
}

function storedAuthRegistryNeedsUpgrade(
  rawAccounts: unknown,
  rawSessionTokens: unknown,
  rawRefreshIntents: unknown,
): boolean {
  if (!isRecord(rawAccounts)) return true;
  const accountUpgrade = Object.values(rawAccounts).some((value) => (
    !isRecord(value)
    || (value.tokenStorage !== 'local' && value.tokenStorage !== 'session')
    || !optionalVersionId(value, 'credentialId')
    || !optionalVersionId(value, 'tokenRevision')
    || (value.tokenStorage === 'session' && !isTokenStorageReason(value.tokenStorageReason))
  ));
  const tokenUpgrade = rawSessionTokens !== undefined && (
    !isRecord(rawSessionTokens)
    || Object.values(rawSessionTokens).some((value) => !isRecord(value) || value.schemaVersion !== 2)
  );
  const intentUpgrade = rawRefreshIntents !== undefined && (
    !isRecord(rawRefreshIntents)
    || Object.keys(parseRefreshIntentMap(rawRefreshIntents)).length !== Object.keys(rawRefreshIntents).length
  );
  return accountUpgrade || tokenUpgrade || intentUpgrade;
}

function parsePersistedAuth(value: unknown): PersistedAuth {
  const core = parsePersistedAuthCore(value);
  if (!isRecord(value)) throw new Error('Invalid persisted authentication data');
  const accessToken = requireString(value, 'accessToken');
  const refreshToken = requireString(value, 'refreshToken');
  if (typeof value.expiresAt !== 'number' || !Number.isFinite(value.expiresAt)) {
    throw new Error('Invalid persisted authentication field: expiresAt');
  }
  return { ...core, accessToken, refreshToken, expiresAt: value.expiresAt };
}

function parsePersistedAuthCore(value: unknown): PersistedAuthCore {
  if (!isRecord(value)) throw new Error('Invalid persisted authentication data');
  const email = requireString(value, 'email');
  const masterKeySalt = value.masterKeySalt === undefined
    ? undefined
    : requireCanonicalMasterKeySalt(value.masterKeySalt);
  const protectedKey = requireString(value, 'protectedKey');
  if (value.encPrivateKey !== undefined && typeof value.encPrivateKey !== 'string') {
    throw new Error('Invalid persisted authentication field: encPrivateKey');
  }
  const restriction = value.restriction === undefined
    ? undefined
    : parsePasswordChangeRequirement(value.restriction);
  const kdf = parseKdfConfig(value);
  return {
    email,
    ...(masterKeySalt ? { masterKeySalt } : {}),
    protectedKey,
    ...kdf,
    ...(typeof value.encPrivateKey === 'string' ? { encPrivateKey: value.encPrivateKey } : {}),
    ...(restriction ? { restriction } : {}),
  };
}

function parseStoredPersistedAuth(value: unknown): StoredPersistedAuth {
  if (!isRecord(value)) return parsePersistedAuth(value);
  if (value.tokenStorage === 'session') {
    if (
      Object.hasOwn(value, 'accessToken')
      || Object.hasOwn(value, 'refreshToken')
      || Object.hasOwn(value, 'expiresAt')
    ) throw new Error('Session-backed authentication leaked token material');
    const tokenBindingId = requireString(value, 'tokenBindingId');
    const credentialId = optionalVersionId(value, 'credentialId') ?? tokenBindingId;
    const tokenRevision = optionalVersionId(value, 'tokenRevision') ?? tokenBindingId;
    const tokenStorageReason = isTokenStorageReason(value.tokenStorageReason)
      ? value.tokenStorageReason
      : 'conservative';
    return {
      ...parsePersistedAuthCore(value),
      tokenStorage: 'session',
      tokenBindingId,
      credentialId,
      tokenRevision,
      tokenStorageReason,
    };
  }
  if (value.tokenStorage === 'local') {
    return {
      ...parsePersistedAuth(value),
      tokenStorage: 'local',
      credentialId: requireString(value, 'credentialId'),
      tokenRevision: requireString(value, 'tokenRevision'),
    };
  }
  return parsePersistedAuth(value);
}

function parseStoredActiveAuth(value: unknown): StoredActiveAuth {
  const auth = parseStoredPersistedAuth(value);
  if (auth.restriction || !isRecord(value) || value.sessionBindingId === undefined) return auth;
  if (typeof value.sessionBindingId !== 'string' || !value.sessionBindingId.trim()) return auth;
  return { ...auth, sessionBindingId: value.sessionBindingId };
}

function parseActiveAuth(value: unknown): ActiveAuth {
  const auth = parsePersistedAuth(value);
  if (auth.restriction) return auth;
  if (!isRecord(value) || value.sessionBindingId === undefined) return auth;
  if (typeof value.sessionBindingId !== 'string' || !value.sessionBindingId.trim()) {
    // Invalid or legacy binding metadata is never enough to authorize session secrets.
    return auth;
  }
  return { ...auth, sessionBindingId: value.sessionBindingId };
}

function parseSessionAuthTokenMap(value: unknown): Record<string, SessionAuthTokensV1> {
  if (value === undefined || !isRecord(value)) return {};
  return Object.fromEntries(Object.entries(value).flatMap(([bindingId, candidate]) => {
    const parsed = parseSessionAuthTokens(candidate);
    return parsed?.tokenBindingId === bindingId ? [[bindingId, parsed]] : [];
  }));
}

function parseSessionAuthTokens(value: unknown): SessionAuthTokensV1 | undefined {
  if (!isRecord(value) || (value.schemaVersion !== 1 && value.schemaVersion !== 2)) return undefined;
  if (
    typeof value.owner !== 'string'
    || !value.owner
    || typeof value.tokenBindingId !== 'string'
    || !value.tokenBindingId.trim()
    || typeof value.accessToken !== 'string'
    || !value.accessToken
    || typeof value.refreshToken !== 'string'
    || !value.refreshToken
    || typeof value.expiresAt !== 'number'
    || !Number.isFinite(value.expiresAt)
  ) return undefined;
  const credentialId = value.schemaVersion === 1
    ? value.tokenBindingId
    : optionalVersionId(value, 'credentialId');
  const tokenRevision = value.schemaVersion === 1
    ? value.tokenBindingId
    : optionalVersionId(value, 'tokenRevision');
  if (!credentialId || !tokenRevision) return undefined;
  return {
    schemaVersion: 2,
    owner: value.owner,
    credentialId,
    tokenRevision,
    tokenBindingId: value.tokenBindingId,
    accessToken: value.accessToken,
    refreshToken: value.refreshToken,
    expiresAt: value.expiresAt,
  };
}

function parseRefreshIntentMap(value: unknown): Record<string, RefreshIntentV1> {
  if (value === undefined || !isRecord(value)) return {};
  return Object.fromEntries(Object.entries(value).flatMap(([operationId, candidate]) => {
    const parsed = parseRefreshIntent(candidate);
    return parsed?.operationId === operationId ? [[operationId, parsed]] : [];
  }));
}

function parseRefreshIntent(value: unknown): RefreshIntentV1 | undefined {
  if (!isRecord(value) || value.schemaVersion !== 1) return undefined;
  const fields = [
    'email',
    'credentialId',
    'tokenRevision',
    'serverUrl',
    'operationId',
    'nextTokenRevision',
  ] as const;
  if (fields.some((field) => typeof value[field] !== 'string' || !value[field])) return undefined;
  return {
    schemaVersion: 1,
    email: value.email as string,
    credentialId: value.credentialId as string,
    tokenRevision: value.tokenRevision as string,
    serverUrl: value.serverUrl as string,
    operationId: value.operationId as string,
    nextTokenRevision: value.nextTokenRevision as string,
  };
}

function isSessionBackedAuth(auth: StoredPersistedAuth | StoredActiveAuth): auth is SessionBackedAuth & {
  readonly sessionBindingId?: string;
} {
  return 'tokenStorage' in auth && auth.tokenStorage === 'session';
}

function composeStoredAuth(
  stored: StoredPersistedAuth | StoredActiveAuth,
  token: SessionAuthTokensV1 | undefined,
): ActiveAuth | undefined {
  if (!isSessionBackedAuth(stored)) return parseActiveAuth(stored);
  if (
    !token
    || token.owner !== stored.email
    || token.tokenBindingId !== stored.tokenBindingId
    || token.credentialId !== stored.credentialId
    || token.tokenRevision !== stored.tokenRevision
  ) return undefined;
  const { tokenStorage: _tokenStorage, tokenBindingId: _tokenBindingId, ...core } = stored;
  return parseActiveAuth({
    ...core,
    accessToken: token.accessToken,
    refreshToken: token.refreshToken,
    expiresAt: token.expiresAt,
  });
}

function sessionBackedAuth(
  auth: PersistedAuth | ActiveAuth,
  tokenBindingId: string,
  credentialId: string,
  tokenRevision: string,
  tokenStorageReason: AuthTokenStorageReason = 'conservative',
): SessionBackedAuth {
  const persisted = stripSessionBinding(auth);
  const {
    accessToken: _accessToken,
    refreshToken: _refreshToken,
    expiresAt: _expiresAt,
    ...core
  } = persisted;
  return {
    ...core,
    tokenStorage: 'session',
    tokenBindingId,
    credentialId,
    tokenRevision,
    tokenStorageReason,
  };
}

function localBackedAuth(
  auth: PersistedAuth | ActiveAuth,
  credentialId: string,
  tokenRevision: string,
): LocalBackedAuth {
  return {
    ...stripSessionBinding(auth),
    tokenStorage: 'local',
    credentialId,
    tokenRevision,
  };
}

function sessionAuthTokens(
  auth: PersistedAuth | ActiveAuth,
  marker: SessionBackedAuth,
): SessionAuthTokensV1 {
  return {
    schemaVersion: 2,
    owner: auth.email,
    credentialId: marker.credentialId,
    tokenRevision: marker.tokenRevision,
    tokenBindingId: marker.tokenBindingId,
    accessToken: auth.accessToken,
    refreshToken: auth.refreshToken,
    expiresAt: auth.expiresAt,
  };
}

function stripStoredSessionBinding(auth: StoredActiveAuth): StoredPersistedAuth {
  if (isSessionBackedAuth(auth)) return sessionBackedCore(auth);
  if (isLocalBackedAuth(auth)) {
    return localBackedAuth(auth, auth.credentialId, auth.tokenRevision);
  }
  return parsePersistedAuth(auth);
}

function sessionBackedCore(auth: SessionBackedAuth & { readonly sessionBindingId?: string }): SessionBackedAuth {
  const { sessionBindingId: _sessionBindingId, ...stored } = auth;
  return stored;
}

function withStoredSessionBinding(
  auth: StoredPersistedAuth,
  sessionBindingId: string | undefined,
): StoredActiveAuth {
  return sessionBindingId ? { ...auth, sessionBindingId } : auth;
}

function sameStoredAccount(left: StoredActiveAuth, right: StoredPersistedAuth): boolean {
  if (left.email !== right.email || storedAuthKind(left) !== storedAuthKind(right)) return false;
  if (!samePersistedAuthCore(left, right)) return false;
  if (isSessionBackedAuth(left) && isSessionBackedAuth(right)) {
    return left.tokenBindingId === right.tokenBindingId
      && left.credentialId === right.credentialId
      && left.tokenRevision === right.tokenRevision
      && left.tokenStorageReason === right.tokenStorageReason;
  }
  if (isLocalBackedAuth(left) && isLocalBackedAuth(right)) {
    return left.credentialId === right.credentialId
      && left.tokenRevision === right.tokenRevision
      && samePersistedTokens(left, right);
  }
  return !isVersionedAuth(left) && !isVersionedAuth(right)
    && samePersistedTokens(left, right);
}

function sameStoredActiveAuth(left: StoredActiveAuth, right: StoredActiveAuth): boolean {
  return sameStoredAccount(left, right)
    && left.sessionBindingId === right.sessionBindingId;
}

function rawSessionBackedAuthMatches(
  value: unknown,
  expected: SessionBackedAuth & { readonly sessionBindingId?: string },
  active = false,
): boolean {
  if (
    !isRecord(value)
    || Object.hasOwn(value, 'accessToken')
    || Object.hasOwn(value, 'refreshToken')
    || Object.hasOwn(value, 'expiresAt')
  ) return false;
  try {
    const parsed = active ? parseStoredActiveAuth(value) : parseStoredPersistedAuth(value);
    return isSessionBackedAuth(parsed)
      && parsed.email === expected.email
      && parsed.tokenBindingId === expected.tokenBindingId
      && parsed.credentialId === expected.credentialId
      && parsed.tokenRevision === expected.tokenRevision
      && parsed.tokenStorageReason === expected.tokenStorageReason
      && (!active || parsed.sessionBindingId === expected.sessionBindingId);
  } catch {
    return false;
  }
}

function sameSessionAuthTokens(
  left: SessionAuthTokensV1 | undefined,
  right: SessionAuthTokensV1 | undefined,
): boolean {
  return Boolean(left && right
    && left.owner === right.owner
    && left.credentialId === right.credentialId
    && left.tokenRevision === right.tokenRevision
    && left.tokenBindingId === right.tokenBindingId
    && left.accessToken === right.accessToken
    && left.refreshToken === right.refreshToken
    && left.expiresAt === right.expiresAt);
}

function sameSessionTokenMap(
  left: Readonly<Record<string, SessionAuthTokensV1>>,
  right: Readonly<Record<string, SessionAuthTokensV1>>,
): boolean {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return leftKeys.length === rightKeys.length
    && leftKeys.every((key) => sameSessionAuthTokens(left[key], right[key]));
}

function storedAuthTokenLease(auth: StoredPersistedAuth | StoredActiveAuth): AuthTokenLease | undefined {
  return isVersionedAuth(auth) ? {
    email: auth.email,
    credentialId: auth.credentialId,
    tokenRevision: auth.tokenRevision,
  } : undefined;
}

function storedAuthMatchesTokenLease(
  auth: StoredPersistedAuth | StoredActiveAuth,
  expected: AuthTokenLease,
): boolean {
  const current = storedAuthTokenLease(auth);
  return Boolean(current
    && current.email === expected.email
    && current.credentialId === expected.credentialId
    && current.tokenRevision === expected.tokenRevision);
}

function storedAuthMatchesCredential(
  left: StoredPersistedAuth | StoredActiveAuth,
  right: StoredPersistedAuth | StoredActiveAuth | AuthTokenLease,
): boolean {
  const leftLease = storedAuthTokenLease(left);
  const rightLease = 'tokenRevision' in right && 'credentialId' in right
    ? { email: right.email, credentialId: right.credentialId }
    : undefined;
  return Boolean(leftLease && rightLease
    && leftLease.email === rightLease.email
    && leftLease.credentialId === rightLease.credentialId);
}

function sameRefreshIntent(
  intent: RefreshIntentV1 | undefined,
  permit: RefreshTokenPermit,
): boolean {
  return Boolean(intent
    && intent.email === permit.email
    && intent.credentialId === permit.credentialId
    && intent.tokenRevision === permit.tokenRevision
    && intent.serverUrl === permit.serverUrl
    && intent.operationId === permit.operationId
    && intent.nextTokenRevision === permit.nextTokenRevision);
}

function removeRefreshIntentsForStoredAuth(
  intents: Record<string, RefreshIntentV1>,
  auth: StoredPersistedAuth | StoredActiveAuth,
): void {
  const lease = storedAuthTokenLease(auth);
  if (!lease) return;
  for (const [operationId, intent] of Object.entries(intents)) {
    if (intent.credentialId === lease.credentialId) delete intents[operationId];
  }
}

function isLocalBackedAuth(auth: StoredPersistedAuth | StoredActiveAuth): auth is LocalBackedAuth & {
  readonly sessionBindingId?: string;
} {
  return 'tokenStorage' in auth && auth.tokenStorage === 'local';
}

function isVersionedAuth(auth: StoredPersistedAuth | StoredActiveAuth): auth is LocalBackedAuth | SessionBackedAuth {
  return isLocalBackedAuth(auth) || isSessionBackedAuth(auth);
}

function storedAuthKind(auth: StoredPersistedAuth | StoredActiveAuth): 'legacy' | AuthTokenStorage {
  return isSessionBackedAuth(auth) ? 'session' : isLocalBackedAuth(auth) ? 'local' : 'legacy';
}

function samePersistedTokens(left: PersistedAuth, right: PersistedAuth): boolean {
  return left.accessToken === right.accessToken
    && left.refreshToken === right.refreshToken
    && left.expiresAt === right.expiresAt;
}

function samePersistedAuth(left: PersistedAuth, right: PersistedAuth): boolean {
  return samePersistedAuthCore(left, right) && samePersistedTokens(left, right);
}

function samePersistedAuthCore(left: PersistedAuthCore, right: PersistedAuthCore): boolean {
  return left.email === right.email
    && left.masterKeySalt === right.masterKeySalt
    && left.protectedKey === right.protectedKey
    && left.encPrivateKey === right.encPrivateKey
    && JSON.stringify(left.restriction) === JSON.stringify(right.restriction)
    && sameKdfConfig(left, right);
}

function optionalVersionId(value: Record<string, unknown>, field: string): string | undefined {
  const candidate = value[field];
  return typeof candidate === 'string' && candidate.trim() ? candidate : undefined;
}

function isTokenStorageReason(value: unknown): value is AuthTokenStorageReason {
  return value === 'conservative' || value === 'localLogout' || value === 'effectivePolicy';
}

function parseSessionSecrets(value: unknown): LoadedSessionSecrets | undefined {
  if (!isRecord(value) || value.schemaVersion !== 1) return undefined;
  if (
    typeof value.owner !== 'string'
    || !value.owner
    || typeof value.sessionBindingId !== 'string'
    || !value.sessionBindingId.trim()
    || typeof value.userKey !== 'string'
    || !value.userKey
    || (value.privateKey !== undefined
      && (typeof value.privateKey !== 'string' || !value.privateKey))
  ) {
    return undefined;
  }
  let rawUserKey: Uint8Array | undefined;
  let userKey: SymmetricKey | undefined;
  let privateKey: Uint8Array | undefined;
  let ownershipTransferred = false;
  try {
    rawUserKey = base64ToBytes(value.userKey);
    userKey = symmetricKeyFromBytes(rawUserKey);
    privateKey = typeof value.privateKey === 'string'
      ? base64ToBytes(value.privateKey)
      : undefined;
    ownershipTransferred = true;
    return {
      owner: value.owner,
      sessionBindingId: value.sessionBindingId,
      userKey,
      ...(privateKey ? { privateKey } : {}),
    };
  } catch {
    return undefined;
  } finally {
    rawUserKey?.fill(0);
    if (!ownershipTransferred) {
      if (userKey) clearSymmetricKey(userKey);
      privateKey?.fill(0);
    }
  }
}

function stripSessionBinding(auth: PersistedAuth | ActiveAuth): PersistedAuth {
  return parsePersistedAuth(auth);
}

function sameBoundOwner(left: ActiveAuth, right: ActiveAuth): boolean {
  return Boolean(
    left.sessionBindingId
    && right.sessionBindingId
    && left.email === right.email
    && left.sessionBindingId === right.sessionBindingId,
  );
}

function matchesAuthExpectation(
  auth: ActiveAuth,
  expected: AuthTokenExpectation,
): boolean {
  return auth.email === expected.email
    && auth.refreshToken === expected.refreshToken
    && (expected.accessToken === undefined || auth.accessToken === expected.accessToken);
}

function pinStateMustBeCleared(previous: PersistedAuth, next: PersistedAuth): boolean {
  return previous.email !== next.email
    || previous.masterKeySalt !== next.masterKeySalt
    || previous.protectedKey !== next.protectedKey
    || !sameKdfConfig(previous, next);
}

function requireCanonicalMasterKeySalt(value: unknown): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 254
    || value !== value.trim().toLowerCase()
    || containsAsciiControl(value)
  ) throw new Error('Invalid persisted authentication field: masterKeySalt');
  return value;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function parsePinConfiguration(value: unknown): PinConfigurationV1 | undefined {
  if (
    !isRecord(value)
    || value.schemaVersion !== 1
    || typeof value.configurationId !== 'string'
    || !value.configurationId.trim()
  ) return undefined;
  if (
    value.lockType === 'afterFirstUnlock'
    && typeof value.encryptedPin === 'string'
    && value.encryptedPin.length > 0
  ) {
    return {
      schemaVersion: 1,
      configurationId: value.configurationId,
      lockType: 'afterFirstUnlock',
      encryptedPin: value.encryptedPin,
    };
  }
  if (
    value.lockType === 'beforeFirstUnlock'
    && typeof value.protectedUserKey === 'string'
    && value.protectedUserKey.length > 0
  ) {
    return {
      schemaVersion: 1,
      configurationId: value.configurationId,
      lockType: 'beforeFirstUnlock',
      protectedUserKey: value.protectedUserKey,
    };
  }
  return undefined;
}

function parsePinEphemeralEnvelope(value: unknown): PinEphemeralEnvelopeV1 | undefined {
  if (
    !isRecord(value)
    || value.schemaVersion !== 1
    || typeof value.configurationId !== 'string'
    || !value.configurationId.trim()
    || typeof value.protectedUserKey !== 'string'
    || !value.protectedUserKey
    || (value.legacy !== undefined && value.legacy !== true)
  ) return undefined;
  return {
    schemaVersion: 1,
    configurationId: value.configurationId,
    protectedUserKey: value.protectedUserKey,
    ...(value.legacy === true ? { legacy: true as const } : {}),
  };
}

function parsePinFailureState(value: unknown): PinFailureStateV1 | undefined {
  if (
    !isRecord(value)
    || value.schemaVersion !== 1
    || typeof value.credentialId !== 'string'
    || !value.credentialId.trim()
    || typeof value.attempts !== 'number'
    || !Number.isSafeInteger(value.attempts)
    || value.attempts < 1
    || value.attempts > 5
  ) return undefined;
  return {
    schemaVersion: 1,
    credentialId: value.credentialId,
    attempts: value.attempts,
  };
}

function normalizePinOwner(owner: string): string {
  const normalized = owner.trim().toLowerCase();
  if (!normalized || normalized.length > 1_024) throw new Error('Invalid PIN owner');
  return normalized;
}

function requireString(value: Record<string, unknown>, field: string): string {
  const result = value[field];
  if (typeof result !== 'string' || result.length === 0) {
    throw new Error(`Invalid persisted authentication field: ${field}`);
  }
  return result;
}

function pickKdfConfig(value: KdfConfig): KdfConfig {
  return value.kdf === 0
    ? { kdf: 0, kdfIterations: value.kdfIterations }
    : {
        kdf: 1,
        kdfIterations: value.kdfIterations,
        kdfMemory: value.kdfMemory,
        kdfParallelism: value.kdfParallelism,
      };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
