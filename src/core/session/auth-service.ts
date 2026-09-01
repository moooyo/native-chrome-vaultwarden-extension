import type {
  ApiClient,
  DeviceLoginInput,
  DeviceLoginResult,
  PasswordHintResult,
  PasswordLoginResult,
} from '../api/client.js';
import {
  ApiHttpError,
  parseLoginTokenSuccess,
  parseRefreshTokenSuccess,
  tokenExpiresAt,
} from '../api/client.js';
import {
  parseAccountPasskeyWebAuthnPrfOption,
  type AccountPasskeyWebAuthnPrfOption,
  type AccountPasskeyAssertion,
  type AccountPasskeyLoginSuccess,
} from '../api/account-passkey.js';
import type { LoginSuccessResponse } from '../api/types.js';
import {
  captureMasterPasswordEvidence,
  combineMasterPasswordPolicies,
  evaluateMasterPasswordEvidence,
  evaluateMasterPasswordPolicy,
  isNewMasterPasswordLengthAllowed,
  mergePasswordChangeRequirement,
  passwordChangeRequirement,
  requireMasterPasswordHint,
  samePasswordChangeRequirement,
  type MasterPasswordEvidence,
  type MasterPasswordPolicy,
  type PasswordChangeRequirement,
} from '../policy/master-password-policy.js';
import { canonicalizeServerCapabilityUrl } from '../api/server-capabilities.js';
import { AppError } from '../errors.js';
import {
  assertKdfConfigForSetting,
  deriveMasterKey,
  deriveMasterPasswordHash,
  parseKdfConfig,
  sameKdfConfig,
  stretchMasterKey,
  type KdfConfig,
} from '../crypto/kdf.js';
import {
  unwrapSymmetricKey,
  decryptPrivateKey,
  serializeSymmetricKey,
  symmetricKeyFromBytes,
  type SymmetricKey,
} from '../crypto/keys.js';
import {
  EncStringMacError,
  decryptToBytes,
  encryptToBytes,
  parseEncString,
} from '../crypto/encstring.js';
import {
  base64UrlToBytes,
  bytesToUtf8,
  constantTimeEqual,
  utf8ToBytes,
} from '../crypto/encoding.js';
import { buildRegistration } from '../crypto/registration.js';
import type {
  ActiveAuth,
  ActiveAuthSnapshot,
  AuthTokenLease,
  RefreshTokenPermit,
  SaveLockedAuthenticatedInput,
  SaveRestrictedAuthenticatedInput,
  SaveUnlockedInput,
  SessionLease,
  SessionLeaseGate,
  SessionManager,
  SessionState,
} from './session-manager.js';
import {
  PENDING_LOGIN_CONTINUATION_TTL_MS,
  type ActivePendingLoginContinuation,
  type PendingLoginContinuationData,
  type PendingLoginContinuationOwner,
  type PendingLoginContinuationStore,
  type PendingLoginPublicStatus,
  type PendingSsoHandoff,
  type PendingSsoLoginGrant,
} from './pending-login-continuation.js';
import type { AccountLease, AccountLeaseGate } from './account-gate.js';
import { isDeviceLoginStateExpired, type DeviceLoginBoundState } from './device-login.js';
import {
  copyAccountPasskeyPrfOutput,
  recoverAccountPasskeyPrfUnlockMaterial,
  type AccountPasskeyPrfUnlockMaterial,
} from './account-passkey-unlock.js';
import { rotateAccountKey as runRotation } from './key-rotation.js';
import type {
  RotationPendingIdentity,
  RotationPendingMarker,
  RotationPendingStore,
} from './rotation-pending-store.js';
import type { PasswordChangePendingStore } from './forced-password-change-pending-store.js';
import { pinConstraintMessage, pinConstraintViolation } from './pin-constraints.js';
import type { VaultTerminalTaskContext } from '../vault/vault-mutation-coordinator.js';
import {
  consumeValidatedFido2TwoFactorSubmission,
  parseFido2TwoFactorRequest,
  validateFido2TwoFactorAssertionToken,
  type Fido2TwoFactorRequest,
  type ValidatedFido2TwoFactorSubmission,
} from './fido2-two-factor.js';
import {
  createDuoChallengeOwner,
  extractDuoProviderSeed,
  sameDuoChallengeOwner,
  type DuoChallengeOwner,
  type DuoProviderSeed,
  type DuoTwoFactorProvider,
} from './duo-two-factor.js';
import {
  createInteractiveTwoFactorChallenge,
  createInteractiveTwoFactorLaunch,
  createInteractiveTwoFactorOwner,
  interactiveTwoFactorConnectorUrl,
  parseInteractiveTwoFactorDocumentId,
  sameInteractiveTwoFactorOwner,
  type InteractiveTwoFactorBeginInput,
  type InteractiveTwoFactorBroker,
  type InteractiveTwoFactorConnectorCaller,
  type InteractiveTwoFactorLaunch,
  type InteractiveTwoFactorLaunchBinding,
  type InteractiveTwoFactorOwner,
  type InteractiveTwoFactorSubmission,
  type InteractiveTwoFactorTabBinding,
} from './interactive-two-factor.js';
import {
  enterprisePolicyAllows,
  type EffectiveEnterprisePolicySnapshot,
  type EnterprisePolicyGate,
  type PolicyLease,
} from '../policy/effective-enterprise-policy.js';

export interface Fido2TwoFactorChallenge {
  readonly owner: InteractiveTwoFactorOwner;
}

export interface Fido2ConnectorLaunch {
  attemptId: number;
  url: string;
  replace?: InteractiveTwoFactorConnectorCaller;
}

export interface NewDeviceVerificationAuthResult {
  readonly kind: 'newDeviceVerification';
  readonly attemptId: number;
  readonly continuationId?: string;
  readonly expiresAt: number;
}

export type RegistrationStartAuthResult =
  | {
      readonly kind: 'registrationFinish';
      readonly attemptId: number;
      readonly email: string;
      readonly expiresAt: number;
    }
  | {
      readonly kind: 'registrationEmailSent';
      readonly email: string;
    };

export interface RegistrationCompleteAuthResult {
  readonly kind: 'registrationComplete';
  readonly email: string;
}

export type AuthResult =
  | { kind: 'unlocked' }
  | { kind: 'locked' }
  | { kind: 'restricted'; requirement: PasswordChangeRequirement }
  | NewDeviceVerificationAuthResult
  | {
      readonly kind: 'ssoRequired';
      readonly email: string;
      readonly organizationIdentifier: string;
    }
  | {
      kind: 'twoFactor';
      providers: number[];
      fido2?: Fido2TwoFactorChallenge;
      token?: string;
      continuationId?: string;
      forcePasswordReset?: true;
      masterPasswordPolicy?: MasterPasswordPolicy;
    };
export type DeviceLoginAuthResult =
  | Exclude<
      AuthResult,
      NewDeviceVerificationAuthResult | { kind: 'twoFactor' } | { kind: 'ssoRequired' }
    >
  | {
      readonly kind: 'twoFactor';
      readonly providers: number[];
      /** Internal-only provider options retained for strict coordinator parsing. */
      readonly providerMetadata?: Readonly<Record<string, unknown>>;
      readonly token?: string;
      readonly forcePasswordReset?: true;
      readonly masterPasswordPolicy?: MasterPasswordPolicy;
    };

export const GENERATOR_HISTORY_CLEANUP_WAIT_MS = 500;

export type SessionTransitionReason =
  | 'login'
  | 'unlock'
  | 'pinUnlock'
  | 'lock'
  | 'logout'
  | 'switchAccount'
  | 'removeAccount'
  | 'serverChange'
  | 'keyRotation';

export type SessionTransitionEvent =
  | {
      phase: 'start';
      transitionId: number;
      reason: SessionTransitionReason;
      identityChanged: boolean;
      owner?: InteractiveTwoFactorOwner;
    }
  | {
      phase: 'settled';
      transitionId: number;
      reason: SessionTransitionReason;
      identityChanged: boolean;
      state: SessionState;
      succeeded: boolean;
      owner?: InteractiveTwoFactorOwner;
    };

export interface AuthServiceDeps {
  api: ApiClient;
  session: SessionManager;
  sessionGate: SessionLeaseGate;
  accountGate?: Pick<
    AccountLeaseGate,
    'captureServer' | 'assertServer' | 'capture' | 'assert'
  >;
  /** Current configured server URL (for per-(server,email) remember-token keying). */
  serverUrlProvider?: () => Promise<string | undefined>;
  /** Clears data derived from the active account whenever that identity changes. */
  onIdentityChanged?: () => Promise<void>;
  /** Invalidates in-flight secret work before a session mutation, then publishes its final state. */
  onSessionTransition?: (event: SessionTransitionEvent) => void | Promise<void>;
  /** Serialized lifecycle hook for AccountLeaseGate; unlike session invalidation, starts in queue. */
  onSerializedSessionTransition?: (event: SessionTransitionEvent) => void | Promise<void>;
  /** Runs after a lock (not a logout) so callers can purge decrypted metadata left on disk. */
  onLock?: () => Promise<void>;
  /** Shared per-account vault lane used to exclude ordinary writes during key rotation. */
  rotationBarrier?: {
    readonly run: <Result>(
      account: string,
      task: (
        context: VaultTerminalTaskContext<string, AccountLease>,
      ) => Result | PromiseLike<Result>,
    ) => Promise<Awaited<Result>>;
  };
  /** Durable write-ahead marker for the irreversible key-rotation request. */
  rotationPending?: Pick<RotationPendingStore, 'markBeforeRotation' | 'clear'>;
  /** Deletes every local history scope on the reset server before a rotation marker is cleared. */
  clearGeneratorHistoryForServerAfterRotation?: (serverUrl: string) => Promise<void>;
  /** Deletes every client-event scope on the reset server before the rotation marker is cleared. */
  clearClientEventsAfterRotation?: (identity: RotationPendingIdentity) => Promise<void>;
  /** Best-effort cleanup after one exact account has been durably removed. */
  clearGeneratorHistoryForAccount?: (identity: RotationPendingIdentity) => Promise<void>;
  /** Best-effort cleanup after every account on an old server has been durably reset. */
  clearGeneratorHistoryForServer?: (serverUrl: string) => Promise<void>;
  /** Durable claim preventing an ambiguous password-change request from being replayed after restart. */
  passwordChangePending?: Pick<
    PasswordChangePendingStore,
    'markBeforeChange' | 'clear'
  >;
  /** Optional in tests; production supplies the single worker-owned enterprise-policy fence. */
  enterprisePolicyGate?: Pick<EnterprisePolicyGate, 'capture' | 'assert'>;
  /** Persistent Require SSO gate resolved against one exact trusted Web Vault environment. */
  assertPasswordLoginAllowed?: (email: string, serverUrl: string) => Promise<void>;
  /** Re-authorizes a durable SSO continuation and returns its fresh synchronous lease fence. */
  authorizeSsoContinuation?: (input: {
    readonly serverUrl: string;
    readonly identityUrl: string;
    readonly redirectUri: string;
    readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  }) => Promise<{ readonly assertCurrent: () => void }>;
  /** Five-minute MV3 continuation store. It never receives vault-decryption key material. */
  pendingLoginStore?: PendingLoginContinuationStore;
  /** Best-effort, document-bound cleanup for a cancelled password FIDO connector. */
  closeInteractiveTwoFactorConnector?: (
    document: InteractiveTwoFactorConnectorCaller,
  ) => void | PromiseLike<void>;
  now?: () => number;
}

export interface PinStatus {
  readonly enabled: boolean;
  readonly available: boolean;
  readonly allowed: boolean;
  readonly requireMasterPasswordOnRestart: boolean;
}

const MAX_INVALID_PIN_ATTEMPTS = 5;
const NEW_DEVICE_VERIFICATION_TTL_MS = 5 * 60 * 1_000;
const REGISTRATION_FINISH_TTL_MS = 10 * 60 * 1_000;
const MAX_NEW_DEVICE_OTP_LENGTH = 256;
const DIRECT_CODE_TWO_FACTOR_PROVIDERS = new Set([0, 1, 3]);

export type DeviceLoginActivationStage = 'pre_grant' | 'grant_started' | 'grant_rejected';

export type DeviceLoginDirectTwoFactorProvider = 0 | 1 | 2 | 3 | 6;
export type DeviceLoginTwoFactorSubmission =
  | {
      readonly provider: DeviceLoginDirectTwoFactorProvider;
      readonly code: string;
      readonly remember?: boolean;
    }
  | {
      readonly provider: 7;
      readonly assertion: ValidatedFido2TwoFactorSubmission;
    };

export interface CompleteDeviceLoginInput {
  /** Strictly restored and response-bound by the controller; never persisted by AuthService. */
  readonly state: DeviceLoginBoundState;
  /** UserKey recovered from the approved response with the request's ephemeral private key. */
  readonly userKey: SymmetricKey;
  /** Canonical server captured when the auth request was created. */
  readonly serverUrl: string;
  readonly twoFactor?: DeviceLoginTwoFactorSubmission;
  /** Monotonic security facts retained by the device-login controller across a 2FA round trip. */
  readonly forcePasswordReset?: true;
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
  /** Exact requester owner emitted on the resulting session transition in production. */
  readonly transitionOwner?: InteractiveTwoFactorOwner;
  /** Synchronous requester fence composed into every pre-request and post-request check. */
  readonly assertTransitionOwnerCurrent?: () => void;
  /** Internal progress signal used to classify whether a token grant could have committed. */
  readonly reportActivationStage?: (stage: DeviceLoginActivationStage) => void;
  readonly onGrantStarted?: () => Promise<void>;
  readonly onGrantDispatched?: () => void;
}

type DeviceLoginGrant = (input: DeviceLoginInput) => Promise<DeviceLoginResult>;

interface PasswordLoginSecurityFacts {
  readonly forcePasswordReset: boolean;
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
}

interface DeviceLoginGrantOutcome {
  readonly result: DeviceLoginResult;
  readonly security: PasswordLoginSecurityFacts;
}

interface ResolvedDeviceLoginTwoFactor {
  readonly provider: DeviceLoginDirectTwoFactorProvider | 7;
  readonly code: string;
  readonly remember: boolean;
}

export interface CompleteAccountPasskeyLoginInput {
  /** Canonical server captured by the attempt coordinator before options were requested. */
  readonly serverUrl: string;
  /** Opaque server-signed continuation token paired with the assertion options. */
  readonly token: string;
  readonly assertion: AccountPasskeyAssertion;
  /** Borrowed from the coordinator; AuthService immediately copies and later zeroes its copy. */
  readonly prfOutput?: Uint8Array;
}

export interface CompleteSsoLoginInput {
  readonly ssoAttemptId: string;
  readonly ssoAttemptGeneration: number;
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly email: string;
  readonly code: string;
  readonly codeVerifier: string;
  readonly redirectUri: string;
  readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  /** Ephemeral callback-time authority. It is never copied into persistent continuation data. */
  readonly assertCurrent: () => void;
  readonly onGrantStarted: () => Promise<void>;
  readonly onGrantDispatched: () => void;
}

export type AccountPasskeyAuthResult =
  | { readonly kind: 'unlocked' | 'locked' }
  | { readonly kind: 'restricted'; readonly requirement: PasswordChangeRequirement }
  | { readonly kind: 'twoFactorUnsupported'; readonly providers: readonly number[] };

interface ValidatedDeviceLoginSuccess {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: number;
  readonly protectedKey: string;
  readonly kdf: KdfConfig;
  readonly encPrivateKey?: string;
  readonly rememberToken?: string;
  readonly forcePasswordReset?: true;
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
}

interface ValidatedAccountPasskeyLoginSuccess {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: number;
  readonly protectedKey: string;
  readonly encPrivateKey: string;
  readonly kdf: KdfConfig;
  readonly accountIdentity: string;
  readonly rememberToken?: string;
  readonly webAuthnPrfOption?: AccountPasskeyWebAuthnPrfOption;
  readonly forcePasswordReset?: true;
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
}

interface PendingFido2Challenge {
  request: Fido2TwoFactorRequest;
  connectorUrl: string;
  expectedUrl?: string;
  tabId?: number;
  documentId?: string;
}

interface PendingLogin {
  attempt: number;
  api: ApiClient;
  serverUrl: string;
  email: string;
  masterPasswordHash?: string;
  sso?: PendingSsoLoginGrant;
  /** Ephemeral callback capability; deliberately excluded from continuationData(). */
  assertSsoAuthorizationCurrent?: () => void;
  onSsoGrantStarted?: () => Promise<void>;
  onSsoGrantDispatched?: () => void;
  /** Present only in this worker. Restored continuations intentionally authenticate to locked. */
  stretchedMasterKey?: Awaited<ReturnType<typeof stretchMasterKey>>;
  kdf: KdfConfig;
  fido2?: PendingFido2Challenge;
  duo?: readonly DuoProviderSeed[];
  twoFactorProviders?: readonly number[];
  twoFactorToken?: string;
  newDeviceVerification?: { readonly expiresAt: number };
  newDeviceOtp?: string;
  rememberDeviceToken?: string;
  passwordEvidence?: MasterPasswordEvidence;
  masterPasswordPolicy?: MasterPasswordPolicy;
  forcePasswordReset?: true;
  passwordChangeRequirement?: PasswordChangeRequirement;
  /** Stable random public binding for this continuation; storage CAS additionally binds generation. */
  continuationId?: string;
  /** Five-minute deadline retained even when an OTP/assertion keeps this stage memory-only. */
  continuationExpiresAt?: number;
  /** User-entered material retained in memory only for a following NDV step. */
  submittedTwoFactor?: {
    readonly provider: number;
    readonly token: string;
    readonly remember: boolean;
  };
  continuation?: {
    readonly owner: PendingLoginContinuationOwner;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly claimed: boolean;
    readonly memoryOnly?: boolean;
  };
}

interface PendingRegistration {
  readonly attempt: number;
  readonly api: ApiClient;
  readonly serverUrl: string;
  readonly email: string;
  readonly name?: string;
  readonly emailVerificationToken?: string;
  readonly expiresAt: number;
}

interface AccountOperationSeed {
  sessionLease: SessionLease;
  accountLease?: AccountLease;
  api: ApiClient;
  fixedApi: ApiClient;
}

interface AccountOperation extends AccountOperationSeed {
  auth: ActiveAuth;
  userKey: SymmetricKey;
}

interface MasterPasswordPolicyAuthorization {
  readonly lease?: PolicyLease;
  readonly policy?: MasterPasswordPolicy;
}

interface RefreshSeed {
  readonly identityGeneration: number;
  /** Present only for callers that may return an access token to an unlocked-session operation. */
  readonly callerSessionLease?: SessionLease;
  readonly accountLease?: AccountLease;
  readonly api: ApiClient;
}

export type ReplayableAuthenticatedRequest<Result> = (
  accessToken: string,
) => Promise<Result>;

export class AuthService {
  readonly interactiveTwoFactor: InteractiveTwoFactorBroker<AuthResult>;
  private pendingLogin: PendingLogin | undefined;
  private pendingRegistration: PendingRegistration | undefined;
  private activeTwoFactorSubmission: { attempt: number; marker: symbol } | undefined;
  private activeNewDeviceVerificationSubmission: { attempt: number; marker: symbol } | undefined;
  private activeDeviceLoginSubmission: {
    requestId: string;
    marker: symbol;
  } | undefined;
  private activationAttempt = 0;
  private transitionSequence = 0;
  private transitionTail: Promise<void> = Promise.resolve();
  private queuedTransitions = 0;
  private sessionMutationTail: Promise<void> = Promise.resolve();
  private accountOperationTail: Promise<void> = Promise.resolve();
  private pinUnlockTail: Promise<void> = Promise.resolve();
  private readonly activeRefresh = new Map<string, Promise<void>>();
  private serverResetPending = false;
  private serverResetSequence = 0;
  private refreshAttempts = 0;
  private refreshIdentityGeneration = 0;
  private refreshIdleResolvers: Array<() => void> = [];
  private readonly now: () => number;
  private activationApi: ApiClient | undefined;
  private activationServerUrl: string | undefined;
  private terminalSessionBlocked = false;
  private passwordChangeSessionBlocked = false;

  constructor(private readonly deps: AuthServiceDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.interactiveTwoFactor = Object.freeze({
      begin: (input: InteractiveTwoFactorBeginInput) => this.#beginPasswordInteractive(input),
      cancelLaunch: (input: InteractiveTwoFactorLaunchBinding) => (
        this.#cancelPasswordInteractiveLaunch(input)
      ),
      bindTab: (input: InteractiveTwoFactorTabBinding) => this.#bindPasswordInteractiveTab(input),
      matchCaller: (input: InteractiveTwoFactorConnectorCaller) => (
        this.#matchPasswordInteractiveCaller(input)
      ),
      complete: (input: InteractiveTwoFactorSubmission) => this.#completePasswordInteractive(input),
    });
  }

  /** The configured server URL, or undefined when none is set (remember-token keying is then skipped). */
  private currentServerUrl(): Promise<string | undefined> {
    return this.deps.serverUrlProvider ? this.deps.serverUrlProvider() : Promise.resolve(undefined);
  }

  /** Send one anonymous password-hint request against the exact configured server generation. */
  async requestPasswordHint(email: string): Promise<PasswordHintResult> {
    const serverAuthority = this.deps.accountGate;
    if (!serverAuthority) {
      throw new AppError('error', 'Password hint server authority is unavailable.');
    }
    const serverLease = serverAuthority.captureServer();
    const assertCurrent = (): void => serverAuthority.assertServer(serverLease);
    assertCurrent();
    const api = this.deps.api
      .forServer(serverLease.serverUrl)
      .withRequestGuard(assertCurrent);
    const result = await api.requestPasswordHint(email);
    assertCurrent();
    return result;
  }

  /** Start registration with identity-only data; account key material is not generated yet. */
  async startRegistration(input: { email: string; name?: string }): Promise<RegistrationStartAuthResult> {
    this.assertNoPendingGrantInFlight();
    const email = normalizeRegistrationEmail(input.email);
    const name = normalizeRegistrationName(input.name);
    await this.clearStoredPendingLogin();
    const attempt = this.beginActivationAttempt();
    const { api, serverUrl } = await this.prepareActivationAttempt(attempt);
    let started: Awaited<ReturnType<ApiClient['startRegistration']>>;
    try {
      started = await api.startRegistration({ email, ...(name ? { name } : {}) });
      this.assertActivationAttempt(attempt);
    } catch (error) {
      if (attempt === this.activationAttempt) this.cancelActivationAttempts();
      throw error;
    }
    if (started.kind === 'email_required') {
      this.cancelActivationAttempts();
      return Object.freeze({ kind: 'registrationEmailSent', email });
    }
    const expiresAt = this.now() + REGISTRATION_FINISH_TTL_MS;
    this.pendingRegistration = Object.freeze({
      attempt,
      api,
      serverUrl,
      email,
      ...(name ? { name } : {}),
      ...(started.kind === 'inline'
        ? { emailVerificationToken: started.emailVerificationToken }
        : {}),
      expiresAt,
    });
    return Object.freeze({ kind: 'registrationFinish', attemptId: attempt, email, expiresAt });
  }

  /** Finish one bound registration, generate account keys locally, then auto-log-in. */
  async register(
    input: { attemptId: number; masterPassword: string; masterPasswordHint: string },
  ): Promise<AuthResult | RegistrationCompleteAuthResult> {
    this.assertNoPendingGrantInFlight();
    const pending = this.requirePendingRegistration(input.attemptId);
    const email = pending.email;
    this.assertNewMasterPasswordAllowed(input.masterPassword, email, {});
    const masterPasswordHint = requireMasterPasswordHint(
      input.masterPasswordHint,
      input.masterPassword,
    );
    const reg = await buildRegistration(email, input.masterPassword);
    this.assertActivationAttempt(pending.attempt);
    try {
      await pending.api.register({
        ...reg,
        email,
        masterPasswordHint,
        ...(pending.name ? { name: pending.name } : {}),
        ...(pending.emailVerificationToken
          ? { emailVerificationToken: pending.emailVerificationToken }
          : {}),
      });
    } catch (error) {
      if (isRegistrationDefinitelyRejected(error)) throw error;
      this.pendingRegistration = undefined;
      if (pending.attempt === this.activationAttempt) this.cancelActivationAttempts();
      throw new AppError(
        'outcome_unknown',
        'The account may have been created. Try signing in before starting registration again.',
      );
    }
    this.pendingRegistration = undefined;
    try {
      this.assertActivationAttempt(pending.attempt);
      return await this.loginForAttempt(
        { email, masterPassword: input.masterPassword },
        pending.attempt,
        pending.api,
      );
    } catch {
      if (pending.attempt === this.activationAttempt) this.cancelActivationAttempts();
      return Object.freeze({ kind: 'registrationComplete', email });
    }
  }

  async cancelRegistration(attemptId: number): Promise<boolean> {
    const pending = this.pendingRegistration;
    if (!pending || pending.attempt !== attemptId) return false;
    this.cancelActivationAttempts();
    return true;
  }

  async login(input: { email: string; masterPassword: string }): Promise<AuthResult> {
    this.assertNoPendingGrantInFlight();
    await this.clearStoredPendingLogin();
    const attempt = this.beginActivationAttempt();
    const { api, serverUrl } = await this.prepareActivationAttempt(attempt);
    const email = input.email.trim().toLowerCase();
    if (/^[^@\s]+@[^@\s]+$/u.test(email)) {
      await this.deps.assertPasswordLoginAllowed?.(email, serverUrl);
    }
    this.assertActivationAttempt(attempt);
    return this.loginForAttempt(input, attempt, api);
  }

  /** Complete one browser-bound SSO callback through the shared token-login state machine. */
  async completeSsoLogin(input: CompleteSsoLoginInput): Promise<AuthResult> {
    if (typeof input.assertCurrent !== 'function'
        || typeof input.onGrantStarted !== 'function'
        || typeof input.onGrantDispatched !== 'function') {
      throw new AppError('denied', 'The SSO callback authority is unavailable.');
    }
    input.assertCurrent();
    this.assertNoPendingGrantInFlight();
    await this.clearStoredPendingLogin();
    input.assertCurrent();
    const attempt = this.beginActivationAttempt();
    const { api, serverUrl } = await this.prepareActivationAttempt(attempt);
    const assertSsoAuthorizationCurrent = (): void => {
      this.assertActivationAttempt(attempt);
      input.assertCurrent();
    };
    assertSsoAuthorizationCurrent();
    if (canonicalizeServerCapabilityUrl(input.serverUrl) !== serverUrl) {
      throw new AppError('session_expired', 'The configured server changed during SSO login.');
    }
    const email = normalizeRegistrationEmail(input.email);
    const authorizedApi = api.withRequestGuard(assertSsoAuthorizationCurrent);
    const prelogin = await authorizedApi.prelogin(email);
    assertSsoAuthorizationCurrent();
    const pending: PendingLogin = {
      attempt,
      api: authorizedApi,
      serverUrl,
      email,
      kdf: parseKdfConfig(prelogin),
      assertSsoAuthorizationCurrent,
      onSsoGrantStarted: input.onGrantStarted,
      onSsoGrantDispatched: input.onGrantDispatched,
      sso: Object.freeze({
        ssoAttemptId: requireSsoAttemptId(input.ssoAttemptId),
        ssoAttemptGeneration: requireSsoAttemptGeneration(input.ssoAttemptGeneration),
        code: input.code,
        codeVerifier: input.codeVerifier,
        redirectUri: input.redirectUri,
        identityUrl: input.identityUrl,
        emailTwoFactorMode: input.emailTwoFactorMode,
      }),
    };
    const remembered = await this.deps.session.getRememberDeviceToken(serverUrl, email);
    assertSsoAuthorizationCurrent();
    let result: PasswordLoginResult;
    try {
      result = await this.executePendingLoginGrant(pending, remembered
        ? { twoFactorProvider: 5, twoFactorToken: remembered, remember: true }
        : {});
    } catch (error) {
      if (remembered && error instanceof ApiHttpError && error.status === 400) {
        this.assertActivationAttempt(attempt);
        await this.deps.session.removeRememberDeviceToken(serverUrl, email);
        this.assertActivationAttempt(attempt);
      }
      throw error;
    }
    assertSsoAuthorizationCurrent();
    this.assertSsoResultIdentity(pending, result);
    if (remembered && result.kind === 'twoFactor') {
      await this.deps.session.removeRememberDeviceToken(serverUrl, email);
      assertSsoAuthorizationCurrent();
    }
    return this.finishPasswordLogin({
      result,
      pending: this.applySsoChallengeFacts(pending, result),
    });
  }

  /** Return only the public binding needed to retire a completed outer SSO claim after restart. */
  async getPendingSsoHandoff(): Promise<PendingSsoHandoff | undefined> {
    const pending = this.pendingLogin;
    if (
      pending?.sso
      && pending.continuation
      && !pending.continuation.claimed
      && !pending.continuation.memoryOnly
      && pending.twoFactorProviders
    ) {
      return pendingSsoHandoff(pending.serverUrl, pending.email, pending.sso);
    }
    const stored = await this.deps.pendingLoginStore?.read();
    if (
      stored?.status !== 'active'
      || stored.memoryOnly
      || stored.data?.stage !== 'twoFactor'
      || !stored.data.sso
    ) return undefined;
    return pendingSsoHandoff(stored.owner.serverUrl, stored.owner.email, stored.data.sso);
  }

  /** Restore a five-minute 2FA/NDV continuation after an MV3 worker restart. */
  async getPendingLoginStatus(): Promise<PendingLoginPublicStatus> {
    if (this.pendingLogin) {
      const status = this.projectPendingLogin(this.pendingLogin);
      if (status.status !== 'none') return status;
      await this.clearPendingLoginOwner(this.pendingLogin);
      this.cancelActivationAttempts();
      return status;
    }
    const store = this.deps.pendingLoginStore;
    if (!store) return Object.freeze({ status: 'none' });
    const stored = await store.read();
    if (!stored) return Object.freeze({ status: 'none' });
    if (stored.status === 'outcome_unknown') {
      return Object.freeze({
        status: 'outcome_unknown',
        serverOrigin: new URL(stored.owner.serverUrl).origin,
        email: stored.owner.email,
        createdAt: stored.createdAt,
        expiresAt: stored.expiresAt,
        terminalAt: stored.terminalAt,
      });
    }
    if (stored.status === 'claimed') {
      const outcome = await store.markOutcomeUnknown(stored.owner);
      return outcome
        ? Object.freeze({
            status: 'outcome_unknown',
            serverOrigin: new URL(outcome.owner.serverUrl).origin,
            email: outcome.owner.email,
            createdAt: outcome.createdAt,
            expiresAt: outcome.expiresAt,
            terminalAt: outcome.terminalAt,
          })
        : Object.freeze({ status: 'none' });
    }
    if (!stored.data || stored.memoryOnly) {
      await store.clearAttempt(stored.owner);
      return Object.freeze({ status: 'none' });
    }
    const restored = await this.restorePendingLogin(stored);
    return restored
      ? this.projectPendingLogin(restored)
      : Object.freeze({ status: 'none' });
  }

  expirePendingLoginContinuation(attemptId: string): boolean {
    const pending = this.pendingLogin;
    const continuation = pending?.continuation;
    if (!pending
        || !continuation
        || continuation.owner.attemptId !== attemptId
        || this.now() < continuation.expiresAt) return false;
    this.cancelActivationAttempts();
    return true;
  }

  /** Cancel only the exact current continuation generation. */
  async cancelPendingLogin(input?: { readonly continuationId?: string }): Promise<boolean> {
    const store = this.deps.pendingLoginStore;
    const local = this.pendingLogin?.continuation;
    let cleared = false;
    if (store && local) {
      if (local.claimed) {
        if (input) return false;
        throw new AppError(
          'outcome_unknown',
          'The previous sign-in is still being verified. Check its result before starting again.',
        );
      }
      if (input && input.continuationId !== local.owner.attemptId) return false;
      cleared = await store.clear(local.owner);
    } else if (store) {
      const stored = await store.read();
      if (stored) {
        if (stored.status === 'claimed') {
          if (input) return false;
          throw new AppError(
            'outcome_unknown',
            'The previous sign-in is still being verified. Check its result before starting again.',
          );
        }
        if (input && input.continuationId !== stored.owner.attemptId) return false;
        cleared = input
          ? await store.clear(stored.owner)
          : await store.clearAttempt(stored.owner);
      }
    } else if (input && input.continuationId !== this.pendingLogin?.continuationId) {
      return false;
    }
    const hadLocal = this.pendingLogin !== undefined;
    this.cancelActivationAttempts();
    return cleared || hadLocal;
  }

  async sendNewDeviceVerificationOtp(input: {
    attemptId: number;
    continuationId?: string;
  }): Promise<void> {
    const pending = this.requireNewDeviceVerificationPending(input.attemptId);
    this.assertPendingLoginContinuationId(pending, input.continuationId);
    if (this.activeNewDeviceVerificationSubmission) {
      throw new AppError('session_expired', 'A device verification action is already in progress.');
    }
    const marker = Symbol('new-device-verification-send');
    this.activeNewDeviceVerificationSubmission = { attempt: pending.attempt, marker };
    try {
      if (pending.sso || !pending.masterPasswordHash) {
        throw new AppError(
          'denied',
          'Resending new-device verification is unavailable for this SSO sign-in.',
        );
      }
      await pending.api.sendNewDeviceVerificationOtp({
        email: pending.email,
        masterPasswordHash: pending.masterPasswordHash,
      });
      this.requireNewDeviceVerificationPending(pending.attempt);
    } finally {
      if (this.activeNewDeviceVerificationSubmission?.marker === marker) {
        this.activeNewDeviceVerificationSubmission = undefined;
      }
    }
  }

  async submitNewDeviceVerification(input: {
    attemptId: number;
    code: string;
    continuationId?: string;
  }): Promise<AuthResult> {
    const pending = this.requireNewDeviceVerificationPending(input.attemptId);
    this.assertPendingLoginContinuationId(pending, input.continuationId);
    if (this.activeNewDeviceVerificationSubmission) {
      throw new AppError('session_expired', 'A device verification action is already in progress.');
    }
    const code = normalizeNewDeviceOtp(input.code);
    const marker = Symbol('new-device-verification-submit');
    this.activeNewDeviceVerificationSubmission = { attempt: pending.attempt, marker };
    let claimed = pending;
    try {
      claimed = await this.claimPendingLogin(pending);
      this.pendingLogin = claimed;
      const priorTwoFactor = claimed.submittedTwoFactor;
      const result = await this.executePendingLoginGrant(claimed, {
        newDeviceOtp: code,
        ...(priorTwoFactor
          ? {
              twoFactorProvider: priorTwoFactor.provider,
              twoFactorToken: priorTwoFactor.token,
              remember: priorTwoFactor.remember,
            }
          : claimed.rememberDeviceToken
            ? {
                twoFactorProvider: 5,
                twoFactorToken: claimed.rememberDeviceToken,
                remember: true,
              }
            : {}),
      });
      this.assertActivationAttempt(claimed.attempt);
      this.assertSsoResultIdentity(claimed, result);
      let nextPending: PendingLogin = this.applySsoChallengeFacts(
        { ...claimed, newDeviceOtp: code },
        result,
      );
      if (result.kind === 'twoFactor' && claimed.rememberDeviceToken) {
        await this.deps.session.removeRememberDeviceToken(claimed.serverUrl, claimed.email);
        this.assertActivationAttempt(claimed.attempt);
        const { rememberDeviceToken: _rememberDeviceToken, ...withoutRememberToken } = nextPending;
        nextPending = withoutRememberToken;
      }
      return this.finishPasswordLogin({ result, pending: nextPending });
    } catch (error) {
      if (error instanceof ApiHttpError && error.status === 400) {
        const released = await this.releasePendingLogin(claimed);
        this.pendingLogin = released;
        throw new AppError(
          'error',
          isInvalidNewDeviceOtpError(error)
            ? 'The verification code is invalid or expired.'
          : 'Device verification was rejected by the server.',
        );
      }
      if (claimed.continuation?.claimed) {
        await this.markPendingLoginOutcomeUnknown(claimed);
        throw new AppError(
          'outcome_unknown',
          'Device verification may have completed. Sign in again to check account state.',
        );
      }
      throw error;
    } finally {
      if (this.activeNewDeviceVerificationSubmission?.marker === marker) {
        this.activeNewDeviceVerificationSubmission = undefined;
      }
    }
  }

  async cancelNewDeviceVerification(input: {
    attemptId: number;
    continuationId?: string;
  }): Promise<boolean> {
    if (!Number.isSafeInteger(input.attemptId) || input.attemptId <= 0) {
      throw new AppError('denied', 'Invalid device verification attempt.');
    }
    const pending = this.pendingLogin;
    if (!pending?.newDeviceVerification || pending.attempt !== input.attemptId) return false;
    try {
      this.assertPendingLoginContinuationId(pending, input.continuationId);
    } catch {
      return false;
    }
    if (pending.continuation?.claimed) return false;
    await this.clearPendingLoginOwner(pending);
    this.cancelActivationAttempts();
    return true;
  }

  /**
   * Redeem an approved Login-with-device request and publish its already-recovered UserKey only
   * after the password grant succeeds. The controller owns the short-lived request state; this
   * service never places its access code or ephemeral RSA private key in persistent auth storage.
   */
  async completeDeviceLogin(input: CompleteDeviceLoginInput): Promise<DeviceLoginAuthResult> {
    this.assertNoPendingGrantInFlight();
    input.reportActivationStage?.('pre_grant');
    const boundServerUrl = canonicalAccountPasskeyServer(input.serverUrl);
    const transitionOwner = parseDeviceLoginTransitionOwner(
      input.transitionOwner,
      input.state,
      boundServerUrl,
    );
    if (Boolean(transitionOwner) !== Boolean(input.assertTransitionOwnerCurrent)) {
      throw new AppError('denied', 'The device login transition owner is incomplete.');
    }
    input.assertTransitionOwnerCurrent?.();
    if (this.activeDeviceLoginSubmission?.requestId === input.state.requestId) {
      throw new AppError('session_expired', 'This device login request is already being verified.');
    }
    if (input.state.phase !== 'bound' || isDeviceLoginStateExpired(input.state, this.now())) {
      throw new AppError('session_expired', 'The device login request expired. Start a new request.');
    }

    const userKey = copyDeviceLoginUserKey(input.userKey);
    let marker: symbol | undefined;
    try {
      const attempt = this.beginActivationAttempt();
      marker = Symbol('device-login-submission');
      this.activeDeviceLoginSubmission = { requestId: input.state.requestId, marker };
      return await this.completeDeviceLoginForAttempt(
        input,
        boundServerUrl,
        userKey,
        attempt,
        transitionOwner,
      );
    } finally {
      if (marker && this.activeDeviceLoginSubmission?.marker === marker) {
        this.activeDeviceLoginSubmission = undefined;
      }
      userKey.encKey.fill(0);
      userKey.macKey.fill(0);
    }
  }

  /** Redeem one account-passkey assertion and use an exact matching PRF key chain when available. */
  async completeAccountPasskeyLogin(
    input: CompleteAccountPasskeyLoginInput,
  ): Promise<AccountPasskeyAuthResult> {
    this.assertNoPendingGrantInFlight();
    const prfOutput = copyAccountPasskeyPrfOutput(input.prfOutput);
    try {
      const boundServerUrl = canonicalAccountPasskeyServer(input.serverUrl);
      const attempt = this.beginActivationAttempt();
      return await this.completeAccountPasskeyLoginForAttempt(
        input,
        boundServerUrl,
        prfOutput,
        attempt,
      );
    } finally {
      prfOutput?.fill(0);
    }
  }

  private async completeAccountPasskeyLoginForAttempt(
    input: CompleteAccountPasskeyLoginInput,
    boundServerUrl: string,
    prfOutput: Uint8Array | undefined,
    attempt: number,
  ): Promise<AccountPasskeyAuthResult> {
    const { api, serverUrl } = await this.prepareActivationAttempt(attempt);
    if (canonicalAccountPasskeyServer(serverUrl) !== boundServerUrl) {
      throw new AppError('session_expired', 'The server changed during account passkey login.');
    }
    const result = await api.accountPasskeyLogin({
      token: input.token,
      assertion: input.assertion,
    });
    this.assertActivationAttempt(attempt);
    if (result.kind === 'twoFactorUnsupported') {
      return Object.freeze({
        kind: 'twoFactorUnsupported',
        providers: Object.freeze([...result.providers]),
      });
    }

    const data = validateAccountPasskeyLoginSuccess(result.data, this.now());
    const requirement = mergePasswordChangeRequirement(
      undefined,
      data.forcePasswordReset === true,
      data.masterPasswordPolicy,
    );
    if (requirement) {
      const persisted: SaveRestrictedAuthenticatedInput = {
        email: data.accountIdentity,
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expiresAt: data.expiresAt,
        protectedKey: data.protectedKey,
        ...data.kdf,
        encPrivateKey: data.encPrivateKey,
        restriction: requirement,
      };
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      this.assertActivationAttempt(attempt);
      await this.runSessionTransition('login', data.accountIdentity !== activeBefore, async () => {
        this.assertActivationAttempt(attempt);
        if (data.accountIdentity !== activeBefore) await this.deps.onIdentityChanged?.();
        await this.commitRestrictedLogin(attempt, persisted);
      });
      this.pendingLogin = undefined;
      if (data.rememberToken) {
        await this.deps.session.saveRememberDeviceToken(
          boundServerUrl,
          data.accountIdentity,
          data.rememberToken,
        ).catch(() => undefined);
      }
      return Object.freeze({ kind: 'restricted' as const, requirement });
    }
    const matchingOption = data.webAuthnPrfOption?.credentialId === input.assertion.id
      ? data.webAuthnPrfOption
      : undefined;
    let unlockMaterial: AccountPasskeyPrfUnlockMaterial | undefined;
    let expectedState: 'unlocked' | 'locked' = 'locked';
    try {
      if (prfOutput && matchingOption) {
        unlockMaterial = await recoverAccountPasskeyPrfUnlockMaterial({
          prfOutput,
          option: matchingOption,
          encPrivateKey: data.encPrivateKey,
        });
        this.assertActivationAttempt(attempt);
      }
      expectedState = unlockMaterial ? 'unlocked' : 'locked';
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      this.assertActivationAttempt(attempt);
      await this.runSessionTransition('login', data.accountIdentity !== activeBefore, async () => {
        this.assertActivationAttempt(attempt);
        if (data.accountIdentity !== activeBefore) await this.deps.onIdentityChanged?.();
        await this.runSessionMutation(async () => {
          let commitStarted = false;
          try {
            commitStarted = true;
            const persisted = {
              email: data.accountIdentity,
              accessToken: data.accessToken,
              refreshToken: data.refreshToken,
              expiresAt: data.expiresAt,
              protectedKey: data.protectedKey,
              ...data.kdf,
              encPrivateKey: data.encPrivateKey,
            };
            if (unlockMaterial) {
              await this.deps.session.saveUnlocked({
                ...persisted,
                userKey: unlockMaterial.userKey,
                privateKey: unlockMaterial.privateKey,
              });
            } else {
              await this.deps.session.saveLockedAuthenticated(persisted);
            }
            await this.assertAccountPasskeyCommit(data, expectedState, unlockMaterial);
            this.assertActivationAttempt(attempt);
          } catch (error) {
            if (commitStarted) {
              await this.deps.session.logoutIfCurrent({
                email: data.accountIdentity,
                refreshToken: data.refreshToken,
              }).catch(() => undefined);
            }
            throw error;
          }
        });
      });
      this.assertActivationAttempt(attempt);

    } finally {
      clearSymmetricKey(unlockMaterial?.userKey);
      unlockMaterial?.privateKey.fill(0);
    }

    this.pendingLogin = undefined;
    if (data.rememberToken) {
      await this.deps.session.saveRememberDeviceToken(
        boundServerUrl,
        data.accountIdentity,
        data.rememberToken,
      ).catch(() => undefined);
    }
    return Object.freeze({ kind: expectedState });
  }

  private async assertAccountPasskeyCommit(
    data: ValidatedAccountPasskeyLoginSuccess,
    expectedState: 'unlocked' | 'locked',
    unlockMaterial: AccountPasskeyPrfUnlockMaterial | undefined,
  ): Promise<void> {
    let committedUserKey: SymmetricKey | undefined;
    let committedPrivateKey: Uint8Array | undefined;
    try {
      const state = await this.deps.session.getState();
      committedUserKey = await this.deps.session.loadUserKey();
      committedPrivateKey = await this.deps.session.loadPrivateKey();
      const active = await this.deps.session.getActiveAuth();
      const secretsMatch = expectedState === 'unlocked'
        ? Boolean(
            unlockMaterial
            && committedUserKey
            && committedPrivateKey
            && sameSymmetricKey(committedUserKey, unlockMaterial.userKey)
            && constantTimeEqual(committedPrivateKey, unlockMaterial.privateKey),
          )
        : committedUserKey === undefined && committedPrivateKey === undefined;
      if (
        state !== expectedState
        || !active
        || (expectedState === 'unlocked'
          ? !active.sessionBindingId
          : active.sessionBindingId !== undefined)
        || active.email !== data.accountIdentity
        || active.accessToken !== data.accessToken
        || active.refreshToken !== data.refreshToken
        || active.expiresAt !== data.expiresAt
        || active.protectedKey !== data.protectedKey
        || active.encPrivateKey !== data.encPrivateKey
        || !sameKdfConfig(active, data.kdf)
        || !secretsMatch
      ) {
        throw new AppError('session_expired', 'Account passkey session commit was not authoritative.');
      }
    } finally {
      clearSymmetricKey(committedUserKey);
      committedPrivateKey?.fill(0);
    }
  }

  private async completeDeviceLoginForAttempt(
    input: CompleteDeviceLoginInput,
    boundServerUrl: string,
    userKey: SymmetricKey,
    attempt: number,
    transitionOwner: InteractiveTwoFactorOwner | undefined,
  ): Promise<DeviceLoginAuthResult> {
    const assertCurrent = (): void => {
      this.assertDeviceLoginRequestCurrent(input.state, attempt);
      input.assertTransitionOwnerCurrent?.();
    };
    const { api, serverUrl } = await this.prepareActivationAttempt(attempt);
    const currentServerUrl = canonicalDeviceLoginServer(serverUrl);
    if (currentServerUrl !== boundServerUrl) {
      throw new AppError('session_expired', 'The server changed after the device login request was created.');
    }
    assertCurrent();

    const deviceIdentifier = await api.getDeviceIdentifier();
    assertCurrent();
    if (
      input.state.device.identifier !== deviceIdentifier
      || input.state.device.type !== 2
      || input.state.device.name !== 'chrome'
    ) {
      throw new AppError('session_expired', 'The device identity changed during device login.');
    }
    const twoFactor = resolveDeviceLoginTwoFactorSubmission(input.twoFactor, boundServerUrl);
    const preflightApi = api.withRequestGuard(() => {
      assertCurrent();
    });
    const prelogin = await preflightApi.prelogin(input.state.email);
    assertCurrent();
    const kdf = parseKdfConfig(prelogin);
    const grantApi = api.withRequestGuard(() => {
      assertCurrent();
      if (!input.onGrantStarted) input.reportActivationStage?.('grant_started');
    });
    const grant: DeviceLoginGrant = async (grantInput) => {
      try {
        const result = await grantApi.deviceLogin(input.onGrantStarted
          ? {
              ...grantInput,
              onGrantStarted: input.onGrantStarted,
              onGrantDispatched: () => {
                input.reportActivationStage?.('grant_started');
                input.onGrantDispatched?.();
              },
            }
          : grantInput);
        if (result.kind === 'twoFactor') {
          input.reportActivationStage?.('grant_rejected');
        }
        return result;
      } catch (error) {
        if (isDefiniteDeviceLoginGrantRejection(error)) {
          input.reportActivationStage?.('grant_rejected');
        }
        throw error;
      }
    };
    const baseLoginInput = {
      email: input.state.email,
      accessCode: input.state.accessCode,
      authRequestId: input.state.requestId,
    };
    const initialSecurity: PasswordLoginSecurityFacts = {
      forcePasswordReset: input.forcePasswordReset === true,
      ...(input.masterPasswordPolicy
        ? { masterPasswordPolicy: input.masterPasswordPolicy }
        : {}),
    };
    const outcome = twoFactor
      ? mergeDeviceLoginGrantSecurity(initialSecurity, await grant({
          ...baseLoginInput,
          twoFactorProvider: twoFactor.provider,
          twoFactorToken: twoFactor.code,
          remember: twoFactor.remember,
        }))
      : await this.deviceLoginWithRememberToken(
          grant,
          input.state,
          boundServerUrl,
          attempt,
          initialSecurity,
        );
    assertCurrent();

    const { result, security } = outcome;
    if (result.kind === 'twoFactor') {
      return {
        kind: 'twoFactor',
        providers: result.providers,
        ...(result.providerMetadata ? { providerMetadata: result.providerMetadata } : {}),
        ...(result.token ? { token: result.token } : {}),
        ...(security.forcePasswordReset ? { forcePasswordReset: true as const } : {}),
        ...(security.masterPasswordPolicy
          ? { masterPasswordPolicy: security.masterPasswordPolicy }
          : {}),
      };
    }

    return this.finishDeviceLogin({
      data: result.data,
      state: input.state,
      userKey,
      serverUrl: boundServerUrl,
      kdf,
      attempt,
      security,
      assertCurrent,
      ...(input.assertTransitionOwnerCurrent
        ? { assertTransitionOwnerCurrent: input.assertTransitionOwnerCurrent }
        : {}),
      ...(transitionOwner ? { transitionOwner } : {}),
    });
  }

  private async deviceLoginWithRememberToken(
    grant: DeviceLoginGrant,
    state: DeviceLoginBoundState,
    serverUrl: string,
    attempt: number,
    initialSecurity: PasswordLoginSecurityFacts,
  ): Promise<DeviceLoginGrantOutcome> {
    const baseLoginInput = {
      email: state.email,
      accessCode: state.accessCode,
      authRequestId: state.requestId,
    };
    const remembered = await this.deps.session.getRememberDeviceToken(serverUrl, state.email);
    this.assertDeviceLoginRequestCurrent(state, attempt);
    if (!remembered) {
      return mergeDeviceLoginGrantSecurity(initialSecurity, await grant(baseLoginInput));
    }

    let result: DeviceLoginResult;
    try {
      result = await grant({
        ...baseLoginInput,
        twoFactorProvider: 5,
        twoFactorToken: remembered,
        remember: true,
      });
    } catch (error) {
      // A 400 response is a definite non-success and therefore safe to retry without the stale
      // remember credential. Never replay after network, timeout, 5xx, or another unknown outcome.
      if (!(error instanceof ApiHttpError) || error.status !== 400) throw error;
      this.assertDeviceLoginRequestCurrent(state, attempt);
      await this.deps.session.removeRememberDeviceToken(serverUrl, state.email);
      this.assertDeviceLoginRequestCurrent(state, attempt);
      return mergeDeviceLoginGrantSecurity(initialSecurity, await grant(baseLoginInput));
    }
    this.assertDeviceLoginRequestCurrent(state, attempt);
    const first = mergeDeviceLoginGrantSecurity(initialSecurity, result);
    if (result.kind === 'success') return first;

    await this.deps.session.removeRememberDeviceToken(serverUrl, state.email);
    this.assertDeviceLoginRequestCurrent(state, attempt);
    return mergeDeviceLoginGrantSecurity(first.security, await grant(baseLoginInput));
  }

  private async loginForAttempt(
    input: { email: string; masterPassword: string },
    attempt: number,
    api: ApiClient,
  ): Promise<AuthResult> {
    const { serverUrl } = await this.prepareActivationAttempt(attempt);
    const email = input.email.trim().toLowerCase();
    const prelogin = await api.prelogin(email);
    this.assertActivationAttempt(attempt);
    const kdf = parseKdfConfig(prelogin);
    const masterKey = await deriveMasterKey(input.masterPassword, email, kdf);
    const masterPasswordHash = await deriveMasterPasswordHash(masterKey, input.masterPassword);
    const stretchedMasterKey = await stretchMasterKey(masterKey);
    this.assertActivationAttempt(attempt);
    const pending: PendingLogin = {
      attempt,
      api,
      serverUrl,
      email,
      masterPasswordHash,
      stretchedMasterKey,
      kdf,
      passwordEvidence: captureMasterPasswordEvidence(input.masterPassword, email),
    };

    // If this (server, email) has a remembered device token, try to reuse it to skip 2FA.
    const remembered = await this.deps.session.getRememberDeviceToken(serverUrl, email);
    this.assertActivationAttempt(attempt);
    if (remembered) {
      return this.loginWithRememberToken({
        email,
        masterPassword: input.masterPassword,
        masterPasswordHash,
        serverUrl,
        token: remembered,
        pending,
      });
    }

    const result = await api.passwordLogin({ email, masterPasswordHash });
    return this.finishPasswordLogin({
      result,
      pending: this.assessPasswordLoginPolicy(pending, result),
    });
  }

  /**
   * Reuse a stored device-remember token (two_factor_provider=5) to skip the 2FA challenge. Best-effort:
   *  - success  → finishPasswordLogin (which keeps the stored token unless the server replaces it)
   *  - twoFactor → the token is stale; the server already returned the REAL providers, so clear the
   *               token and drive the normal 2FA screen from THIS SAME result (no second round-trip,
   *               and no duplicate email for email-2FA accounts)
   *  - HTTP 400  → the token was definitely rejected; clear it and retry once without it
   *  - other failure → preserve the token and never replay an outcome-unknown password grant
   */
  private async loginWithRememberToken(args: {
    email: string;
    masterPassword: string;
    masterPasswordHash: string;
    serverUrl: string;
    token: string;
    pending: PendingLogin;
  }): Promise<AuthResult> {
    let result: PasswordLoginResult;
    try {
      result = await args.pending.api.passwordLogin({
        email: args.email,
        masterPasswordHash: args.masterPasswordHash,
        twoFactorProvider: 5,
        twoFactorToken: args.token,
        remember: true,
      });
    } catch (error) {
      if (!(error instanceof ApiHttpError) || error.status !== 400) throw error;
      this.assertActivationAttempt(args.pending.attempt);
      await this.deps.session.removeRememberDeviceToken(args.serverUrl, args.email);
      this.assertActivationAttempt(args.pending.attempt);
      const retry = await args.pending.api.passwordLogin({
        email: args.email,
        masterPasswordHash: args.masterPasswordHash,
      });
      return this.finishPasswordLogin({
        result: retry,
        pending: this.assessPasswordLoginPolicy(args.pending, retry),
      });
    }
    this.assertActivationAttempt(args.pending.attempt);
    if (result.kind === 'twoFactor') {
      await this.deps.session.removeRememberDeviceToken(args.serverUrl, args.email);
      this.assertActivationAttempt(args.pending.attempt);
    }
    return this.finishPasswordLogin({
      result,
      pending: this.assessPasswordLoginPolicy(
        result.kind === 'newDeviceVerification'
        ? { ...args.pending, rememberDeviceToken: args.token }
        : args.pending,
        result,
      ),
    });
  }

  private assessPasswordLoginPolicy(
    pending: PendingLogin,
    result: PasswordLoginResult,
  ): PendingLogin {
    if (result.kind === 'newDeviceVerification' || result.kind === 'ssoRequired') return pending;
    const source = result.kind === 'success' ? result.data : result;
    return applyPasswordLoginSecurityFacts(
      pending,
      source.forcePasswordReset === true,
      source.masterPasswordPolicy,
    );
  }

  private executePendingLoginGrant(
    pending: PendingLogin,
    input: {
      readonly twoFactorProvider?: number;
      readonly twoFactorToken?: string;
      readonly remember?: boolean;
      readonly newDeviceOtp?: string;
    },
    lifecycle?: {
      readonly onGrantStarted: () => Promise<void>;
      readonly onGrantDispatched: () => void;
    },
  ): Promise<PasswordLoginResult> {
    this.assertPendingLoginCurrent(pending);
    if (pending.sso) {
      if (pending.masterPasswordHash !== undefined) {
        throw new AppError('denied', 'The pending login grant is ambiguous.');
      }
      return pending.api.ssoLogin(pending.sso.identityUrl, {
        code: pending.sso.code,
        codeVerifier: pending.sso.codeVerifier,
        redirectUri: pending.sso.redirectUri,
        ...(pending.onSsoGrantStarted || lifecycle
          ? {
              onGrantStarted: async () => {
                await pending.onSsoGrantStarted?.();
                await lifecycle?.onGrantStarted();
              },
            }
          : {}),
        ...(pending.onSsoGrantDispatched || lifecycle
          ? {
              onGrantDispatched: () => {
                pending.onSsoGrantDispatched?.();
                lifecycle?.onGrantDispatched();
              },
            }
          : {}),
        ...input,
      });
    }
    if (!pending.masterPasswordHash) {
      throw new AppError('session_expired', 'The pending password login is unavailable.');
    }
    return pending.api.passwordLogin({
      email: pending.email,
      masterPasswordHash: pending.masterPasswordHash,
      ...input,
      ...(lifecycle ? {
        onGrantStarted: lifecycle.onGrantStarted,
        onGrantDispatched: lifecycle.onGrantDispatched,
      } : {}),
    });
  }

  private assertPendingLoginCurrent(pending: PendingLogin): void {
    this.assertActivationAttempt(pending.attempt);
    pending.assertSsoAuthorizationCurrent?.();
  }

  private assertSsoResultIdentity(pending: PendingLogin, result: PasswordLoginResult): void {
    if (!pending.sso) return;
    const resultEmail = result.kind === 'success'
      ? accessTokenEmail(result.data.access_token)
      : result.kind === 'twoFactor'
        ? result.email
        : undefined;
    if (resultEmail !== undefined && resultEmail !== pending.email) {
      throw new AppError('denied', 'The SSO response belongs to a different account.');
    }
  }

  private applySsoChallengeFacts(
    pending: PendingLogin,
    result: PasswordLoginResult,
  ): PendingLogin {
    if (!pending.sso || result.kind !== 'twoFactor' || !result.ssoEmail2FaSessionToken) {
      return pending;
    }
    return {
      ...pending,
      sso: Object.freeze({
        ...pending.sso,
        emailTwoFactorSessionToken: result.ssoEmail2FaSessionToken,
      }),
    };
  }

  async #beginPasswordInteractive(
    input: InteractiveTwoFactorBeginInput,
  ): Promise<InteractiveTwoFactorLaunch> {
    const pending = this.#requirePasswordInteractiveOwner(input.owner);
    const launch = this.beginFido2({
      attemptId: pending.attempt,
      ...(pending.continuationId ? { continuationId: pending.continuationId } : {}),
      parentUrl: input.parentUrl,
      locale: input.locale,
    });
    return Object.freeze({
      owner: passwordInteractiveOwner(pending),
      url: launch.url,
      ...(launch.replace ? { replace: launch.replace } : {}),
    });
  }

  async #cancelPasswordInteractiveLaunch(
    input: InteractiveTwoFactorLaunchBinding,
  ): Promise<boolean> {
    const pending = this.#passwordPendingForOwner(input.owner);
    if (!pending?.fido2
        || pending.fido2.expectedUrl !== input.url
        || pending.fido2.tabId !== undefined) return false;
    this.cancelFido2Launch({ attemptId: pending.attempt, url: input.url });
    return true;
  }

  async #bindPasswordInteractiveTab(input: InteractiveTwoFactorTabBinding): Promise<void> {
    const pending = this.#requirePasswordInteractiveOwner(input.owner);
    this.bindFido2Tab({
      attemptId: pending.attempt,
      url: input.url,
      tabId: input.tabId,
      documentId: input.documentId,
    });
  }

  #matchPasswordInteractiveCaller(
    input: InteractiveTwoFactorConnectorCaller,
  ): InteractiveTwoFactorOwner | undefined {
    try {
      this.assertFido2ConnectorCaller(input);
      return passwordInteractiveOwner(this.pendingLogin!);
    } catch {
      return undefined;
    }
  }

  async #completePasswordInteractive(input: InteractiveTwoFactorSubmission): Promise<AuthResult> {
    this.#requirePasswordInteractiveOwner(input.owner);
    return this.completeFido2({
      url: input.url,
      tabId: input.tabId,
      documentId: input.documentId,
      token: input.token,
      remember: input.remember,
    });
  }

  #requirePasswordInteractiveOwner(owner: InteractiveTwoFactorOwner): PendingLogin {
    const pending = this.#passwordPendingForOwner(owner);
    if (!pending?.fido2) {
      throw new AppError('session_expired', 'The security-key challenge is no longer available. Sign in again.');
    }
    return pending;
  }

  #passwordPendingForOwner(owner: InteractiveTwoFactorOwner): PendingLogin | undefined {
    let parsed: InteractiveTwoFactorOwner;
    try {
      parsed = createInteractiveTwoFactorOwner(owner);
    } catch {
      return undefined;
    }
    if (parsed.flow !== 'password' || !this.pendingLogin?.fido2) return undefined;
    return sameInteractiveTwoFactorOwner(parsed, passwordInteractiveOwner(this.pendingLogin))
      ? this.pendingLogin
      : undefined;
  }

  beginFido2(input: {
    attemptId: number;
    continuationId?: string;
    parentUrl: string;
    locale: string;
  }): Fido2ConnectorLaunch {
    const pending = this.pendingLogin;
    if (!pending || pending.attempt !== input.attemptId || !pending.fido2) {
      throw new AppError('session_expired', 'The security-key challenge is no longer available. Sign in again.');
    }
    this.assertPendingLoginContinuationId(pending, input.continuationId);
    this.assertPendingLoginNotExpired(pending);
    if (this.activeTwoFactorSubmission) {
      throw new AppError('session_expired', 'A two-factor response is already being verified.');
    }
    if (pending.fido2.expectedUrl !== undefined && pending.fido2.tabId === undefined) {
      throw new AppError('session_expired', 'The security-key connector is already opening.');
    }
    if (input.locale !== 'en' && input.locale !== 'zh-CN') {
      throw new AppError('denied', 'Unsupported connector locale.');
    }
    if (typeof input.parentUrl !== 'string' || input.parentUrl.length === 0 || input.parentUrl.length > 2_048) {
      throw new AppError('denied', 'Invalid connector parent URL.');
    }
    let parent: URL;
    try {
      parent = new URL(input.parentUrl);
    } catch {
      throw new AppError('denied', 'Invalid connector parent URL.');
    }
    if ((parent.protocol !== 'chrome-extension:' && parent.protocol !== 'moz-extension:')
        || parent.username
        || parent.password) {
      throw new AppError('denied', 'Invalid connector parent URL.');
    }

    const owner = createInteractiveTwoFactorOwner({
      flow: 'password',
      generation: pending.continuation?.owner.generation ?? pending.attempt,
      serverUrl: pending.serverUrl,
      bindingId: pending.continuationId ?? `password-${pending.attempt}`,
    });
    let replace: InteractiveTwoFactorConnectorCaller | undefined;
    if (pending.fido2.tabId !== undefined) {
      if (!pending.fido2.documentId || !pending.fido2.expectedUrl) {
        throw new AppError('session_expired', 'The security-key connector binding is invalid. Sign in again.');
      }
      replace = Object.freeze({
        tabId: pending.fido2.tabId,
        documentId: pending.fido2.documentId,
        url: pending.fido2.expectedUrl,
      });
    }
    const launch = createInteractiveTwoFactorLaunch(
      createInteractiveTwoFactorChallenge({
        owner,
        connectorData: pending.fido2.request.connectorData,
        connectorUrl: pending.fido2.connectorUrl,
      }),
      { parentUrl: parent.toString(), locale: input.locale },
      replace,
    );
    pending.fido2.expectedUrl = launch.url;
    delete pending.fido2.tabId;
    delete pending.fido2.documentId;
    return {
      attemptId: pending.attempt,
      url: launch.url,
      ...(launch.replace ? { replace: launch.replace } : {}),
    };
  }

  cancelFido2Launch(input: { attemptId: number; url: string }): void {
    const pending = this.pendingLogin;
    if (pending?.attempt === input.attemptId
        && pending.fido2?.expectedUrl === input.url
        && pending.fido2.tabId === undefined) {
      delete pending.fido2.expectedUrl;
    }
  }

  bindFido2Tab(input: {
    attemptId: number;
    url: string;
    tabId: number;
    documentId: string;
  }): void {
    const pending = this.pendingLogin;
    if (!pending
        || pending.attempt !== input.attemptId
        || !pending.fido2
        || pending.fido2.expectedUrl !== input.url
        || !Number.isSafeInteger(input.tabId)
        || input.tabId < 0
        || !validConnectorDocumentId(input.documentId)) {
      throw new AppError('session_expired', 'The security-key challenge is no longer available. Sign in again.');
    }
    pending.fido2.tabId = input.tabId;
    pending.fido2.documentId = input.documentId;
  }

  assertFido2ConnectorCaller(input: { url: string; tabId: number; documentId: string }): void {
    const pending = this.pendingLogin;
    if (!pending) {
      throw new AppError('session_expired', 'Your sign-in session expired. Re-enter your password.');
    }
    if (!pending.fido2
        || pending.fido2.expectedUrl !== input.url
        || pending.fido2.tabId !== input.tabId
        || pending.fido2.documentId !== input.documentId) {
      throw new AppError('denied', 'sender not permitted');
    }
  }

  async completeFido2(input: {
    url: string;
    tabId: number;
    documentId: string;
    token: string;
    remember: boolean;
  }): Promise<AuthResult> {
    if (this.activeTwoFactorSubmission) {
      throw new AppError('session_expired', 'A two-factor response is already being verified.');
    }
    this.assertFido2ConnectorCaller(input);
    const pending = this.pendingLogin!;
    delete pending.fido2!.expectedUrl;
    delete pending.fido2!.tabId;
    delete pending.fido2!.documentId;
    return this.submitTwoFactor({
      provider: 7,
      code: input.token,
      remember: input.remember,
      ...(pending.continuationId ? { continuationId: pending.continuationId } : {}),
    });
  }

  async submitTwoFactor(input: {
    provider: number;
    code: string;
    remember?: boolean;
    continuationId?: string;
  }, interactiveDuo = false, lifecycle?: {
    readonly onGrantStarted: () => Promise<void>;
    readonly onGrantDispatched: () => void;
  }): Promise<AuthResult> {
    const pending = this.pendingLogin;
    if (!pending) throw new AppError('session_expired', 'Your sign-in session expired. Re-enter your password.');
    this.assertPendingLoginContinuationId(pending, input.continuationId);
    this.assertPendingLoginNotExpired(pending);
    if (!Number.isSafeInteger(input.provider) || !pending.twoFactorProviders?.includes(input.provider)) {
      throw new AppError('denied', 'The two-factor provider is not available for this sign-in.');
    }
    if (input.provider !== 7 && !DIRECT_CODE_TWO_FACTOR_PROVIDERS.has(input.provider)
        && !(interactiveDuo && (input.provider === 2 || input.provider === 6))) {
      throw new AppError(
        'denied',
        'This two-factor provider requires an interactive flow that is not supported yet.',
      );
    }
    if (this.activeTwoFactorSubmission) {
      throw new AppError('session_expired', 'A two-factor response is already being verified.');
    }
    if (input.provider !== 7 && pending.fido2) {
      this.closePendingFidoConnectorSoon();
      delete pending.fido2.expectedUrl;
      delete pending.fido2.tabId;
      delete pending.fido2.documentId;
    }
    const marker = Symbol('two-factor-submission');
    this.activeTwoFactorSubmission = { attempt: pending.attempt, marker };
    let claimed = pending;
    let grantDispatched = false;
    try {
      let token = input.code.trim();
      if (input.provider === 7) {
        if (!pending.fido2) {
          this.cancelActivationAttempts();
          throw new AppError('session_expired', 'The security-key challenge is no longer available. Sign in again.');
        }
        try {
          token = await validateFido2TwoFactorAssertionToken(input.code, pending.fido2.request);
        } catch {
          await this.clearPendingLoginOwner(pending);
          if (pending.attempt === this.activationAttempt) this.cancelActivationAttempts();
          throw new AppError('session_expired', 'The security-key response was invalid or expired. Sign in again.');
        }
        this.assertActivationAttempt(pending.attempt);
      }
      claimed = await this.claimPendingLogin(pending);
      this.pendingLogin = claimed;
      const loginInput: {
        twoFactorProvider: number;
        twoFactorToken: string;
        remember?: boolean;
        newDeviceOtp?: string;
      } = {
        twoFactorProvider: input.provider,
        twoFactorToken: token,
        ...(claimed.newDeviceOtp ? { newDeviceOtp: claimed.newDeviceOtp } : {}),
      };
      if (input.remember !== undefined) loginInput.remember = input.remember;
      const result = await this.executePendingLoginGrant(
        claimed,
        loginInput,
        lifecycle
          ? {
              onGrantStarted: lifecycle.onGrantStarted,
              onGrantDispatched: () => {
                grantDispatched = true;
                lifecycle.onGrantDispatched();
              },
            }
          : undefined,
      );
      this.assertSsoResultIdentity(claimed, result);
      const nextPendingBase = result.kind === 'newDeviceVerification'
        ? {
            ...claimed,
            submittedTwoFactor: {
              provider: input.provider,
              token,
              remember: input.remember ?? false,
            },
          }
        : claimed;
      const nextPending = this.applySsoChallengeFacts(nextPendingBase, result);
      return this.finishPasswordLogin({ result, pending: nextPending });
    } catch (error) {
      if (claimed.continuation?.claimed && (
        (error instanceof ApiHttpError && error.status === 400)
        || (lifecycle !== undefined && !grantDispatched)
      )) {
        const released = await this.releasePendingLogin(claimed);
        this.pendingLogin = input.provider === 7
          ? this.rebuildPendingFido2(released)
          : released;
      } else if (claimed.continuation?.claimed) {
        await this.markPendingLoginOutcomeUnknown(claimed);
        throw new AppError(
          'outcome_unknown',
          'Two-factor verification may have completed. Sign in again to check account state.',
        );
      }
      throw error;
    } finally {
      if (this.activeTwoFactorSubmission?.marker === marker) {
        this.activeTwoFactorSubmission = undefined;
      }
    }
  }

  async prepareDuoTwoFactor(input: {
    readonly provider: DuoTwoFactorProvider;
    readonly continuationId: string;
  }): Promise<{ readonly owner: DuoChallengeOwner; readonly seed: DuoProviderSeed }> {
    const pending = this.pendingLogin;
    if (!pending) throw new AppError('session_expired', 'The sign-in continuation is unavailable.');
    this.assertPendingLoginContinuationId(pending, input.continuationId);
    this.assertPendingLoginNotExpired(pending);
    if (!pending.twoFactorProviders?.includes(input.provider)) {
      throw new AppError('denied', 'The Duo provider is unavailable.');
    }
    const seed = pending.duo?.find((candidate) => candidate.provider === input.provider);
    if (!seed || !pending.continuationId) {
      throw new AppError('denied', 'The Duo authorization metadata is unavailable.');
    }
    return Object.freeze({
      owner: createDuoChallengeOwner({
        flow: 'password',
        generation: pending.continuation?.owner.generation ?? pending.attempt,
        serverUrl: pending.serverUrl,
        email: pending.email,
        provider: input.provider,
        bindingId: pending.continuationId,
      }),
      seed,
    });
  }

  async completeDuoTwoFactor(input: {
    readonly owner: DuoChallengeOwner;
    readonly token: string;
    readonly remember: boolean;
    readonly onGrantStarted: () => Promise<void>;
    readonly onGrantDispatched: () => void;
  }): Promise<AuthResult> {
    const expected = await this.prepareDuoTwoFactor({
      provider: input.owner.provider,
      continuationId: input.owner.bindingId,
    });
    if (!sameDuoChallengeOwner(input.owner, expected.owner)) {
      throw new AppError('session_expired', 'The Duo challenge changed.');
    }
    return this.submitTwoFactor({
      provider: input.owner.provider,
      code: input.token,
      remember: input.remember,
      continuationId: input.owner.bindingId,
    }, true, {
      onGrantStarted: input.onGrantStarted,
      onGrantDispatched: input.onGrantDispatched,
    });
  }

  async sendEmailCode(input?: { readonly continuationId?: string }): Promise<void> {
    const pending = this.pendingLogin;
    if (!pending) throw new AppError('session_expired', 'Your sign-in session expired. Re-enter your password.');
    this.assertPendingLoginContinuationId(pending, input?.continuationId);
    this.assertPendingLoginNotExpired(pending);
    if (pending.sso) {
      if (pending.sso.emailTwoFactorMode === 'vaultwarden-device') {
        await pending.api.sendSsoEmailLogin({ mode: 'vaultwarden-device' });
      } else {
        if (!pending.sso.emailTwoFactorSessionToken) {
          throw new AppError('session_expired', 'The SSO email verification session expired.');
        }
        await pending.api.sendSsoEmailLogin({
          mode: 'bitwarden-session',
          email: pending.email,
          ssoEmail2FaSessionToken: pending.sso.emailTwoFactorSessionToken,
        });
      }
    } else {
      if (!pending.twoFactorToken) throw new Error('no pending 2FA token');
      await pending.api.sendEmailLogin({
        email: pending.email,
        twoFactorToken: pending.twoFactorToken,
      });
    }
    this.assertActivationAttempt(pending.attempt);
  }

  async unlock(masterPassword: string): Promise<void> {
    const attempt = this.beginActivationAttempt();
    const auth = await this.deps.session.getPersistedAuth();
    this.assertActivationAttempt(attempt);
    if (!auth) throw new Error('not logged in');
    const masterKey = await deriveMasterKey(
      masterPassword,
      auth.masterKeySalt ?? auth.email,
      auth,
    );
    const userKey = await unwrapSymmetricKey(auth.protectedKey, await stretchMasterKey(masterKey));
    let privateKey: Uint8Array | undefined;
    try {
      privateKey = auth.encPrivateKey ? await decryptPrivateKey(auth.encPrivateKey, userKey) : undefined;
      this.assertActivationAttempt(attempt);
      await this.runSessionTransition('unlock', false, async () => {
        this.assertActivationAttempt(attempt);
        await this.commitUnlockedLogin({
          attempt,
          saveInput: privateKey ? { ...auth, userKey, privateKey } : { ...auth, userKey },
          failureMessage: 'Master password unlock session commit was not authoritative.',
          replaceCredential: false,
        });
      });
      await this.rearmPinAfterMasterPasswordUnlock(auth, userKey);
    } finally {
      clearSymmetricKey(userKey);
      privateKey?.fill(0);
    }
  }

  /**
   * Enable PIN unlock: wrap the current UserKey under a PIN-derived key and persist it. The PIN is
   * low-entropy, so the persisted blob is brute-forceable offline (PBKDF2 raises the cost) — an
   * explicit convenience/security trade-off, matching Bitwarden's PIN unlock. Requires an unlocked vault.
   */
  async setPin(pin: string, requireMasterPasswordOnRestart = true): Promise<void> {
    assertValidPin(pin);
    const policyLease = this.capturePinPolicyLease();
    const seed = this.captureAccountOperationSeed();
    await this.runAccountOperation(async () => {
      const operation = await this.beginAccountMutation(seed);
      let pinKey: SymmetricKey | undefined;
      let rawUserKey: Uint8Array | undefined;
      let pinBytes: Uint8Array | undefined;
      let protectedUserKey: string | undefined;
      try {
        this.assertPinPolicyAllowed(policyLease);
        pinKey = await this.derivePinKey(pin, operation.auth.email, operation.auth);
        this.assertPinPolicyAllowed(policyLease);
        rawUserKey = serializeSymmetricKey(operation.userKey);
        protectedUserKey = await encryptToBytes(rawUserKey, pinKey);
        let encryptedPin: string | undefined;
        if (requireMasterPasswordOnRestart) {
          pinBytes = utf8ToBytes(pin);
          encryptedPin = await encryptToBytes(pinBytes, operation.userKey);
        }
        this.assertPinPolicyAllowed(policyLease);
        await this.assertAccountOperation(operation);
        this.assertPinPolicyAllowed(policyLease);
        await this.runSessionMutation(async () => {
          await this.assertAccountOperation(operation);
          this.assertPinPolicyAllowed(policyLease);
          this.cancelActivationAttempts();
          try {
            await this.deps.session.savePinProtectedUserKey(protectedUserKey!, {
              owner: operation.auth.email,
              requireMasterPasswordOnRestart,
              ...(encryptedPin ? { encryptedPin } : {}),
            });
            this.assertPinPolicyAllowed(policyLease);
            await this.assertAccountOperation(operation);
            this.assertPinPolicyAllowed(policyLease);
          } catch (error) {
            // A policy/account transition may race the storage await. Removing only the matching
            // envelope keeps the operation fail closed without deleting a newer replacement PIN.
            await this.deps.session.removePinProtectedUserKeyIfCurrent(
              protectedUserKey!,
              operation.auth.email,
            ).catch(() => undefined);
            throw error;
          }
        });
      } finally {
        if (pinKey) clearSymmetricKey(pinKey);
        rawUserKey?.fill(0);
        pinBytes?.fill(0);
      }
    });
  }

  /** Unlock with a PIN (no network), serializing attempts so parallel requests cannot bypass limits. */
  async unlockWithPin(pin: string): Promise<void> {
    assertValidPin(pin);
    return this.runPinUnlockOperation(() => this.unlockWithPinOnce(pin));
  }

  private async unlockWithPinOnce(pin: string): Promise<void> {
    const policyLease = this.capturePinPolicyLease();
    const attempt = this.beginActivationAttempt();
    const auth = await this.deps.session.getPersistedAuth();
    this.assertPinPolicyAllowed(policyLease);
    this.assertActivationAttempt(attempt);
    if (!auth) throw new Error('not logged in');
    const pinState = await this.deps.session.getPinUnlockState(auth.email);
    this.assertPinPolicyAllowed(policyLease);
    this.assertActivationAttempt(attempt);
    if (!pinState) throw new Error('PIN unlock is not available');

    let pinKey: SymmetricKey | undefined;
    let userKey: SymmetricKey | undefined;
    try {
      pinKey = await this.derivePinKey(pin, auth.email, auth);
      this.assertPinPolicyAllowed(policyLease);
      try {
        userKey = await unwrapSymmetricKey(pinState.protectedUserKey, pinKey);
      } catch (error) {
        if (!(error instanceof EncStringMacError)) throw error;
        await this.rejectInvalidPin(auth.email, pinState.credentialId, attempt, policyLease);
      }
    } finally {
      if (pinKey) clearSymmetricKey(pinKey);
    }
    if (!userKey) throw new Error('PIN authentication did not return a UserKey');

    await this.deps.session.clearFailedPinAttempts(auth.email, pinState.credentialId)
      .catch(() => undefined);
    let privateKey: Uint8Array | undefined;
    try {
      this.assertActivationAttempt(attempt);
      this.assertPinPolicyAllowed(policyLease);
      privateKey = auth.encPrivateKey ? await decryptPrivateKey(auth.encPrivateKey, userKey) : undefined;
      this.assertPinPolicyAllowed(policyLease);
      this.assertActivationAttempt(attempt);
      await this.runSessionTransition('pinUnlock', false, async () => {
        this.assertActivationAttempt(attempt);
        this.assertPinPolicyAllowed(policyLease);
        await this.commitUnlockedLogin({
          attempt,
          saveInput: privateKey ? { ...auth, userKey, privateKey } : { ...auth, userKey },
          failureMessage: 'PIN unlock session commit was not authoritative.',
          replaceCredential: false,
          finalValidate: () => { this.assertPinPolicyAllowed(policyLease); },
        });
      });
      if (pinState.legacy) {
        await this.upgradeLegacyPinAfterUnlock(auth, pin, userKey, pinState.protectedUserKey);
      }
    } finally {
      clearSymmetricKey(userKey);
      privateKey?.fill(0);
    }
  }

  async disablePin(): Promise<void> {
    const seed = this.captureAccountOperationSeed();
    await this.runAccountOperation(async () => {
      const operation = await this.beginAccountMutation(seed);
      await this.runSessionMutation(async () => {
        await this.assertAccountOperation(operation);
        this.cancelActivationAttempts();
        await this.deps.session.removePinProtectedUserKey(operation.auth.email);
        await this.assertAccountOperation(operation);
      });
      await this.assertAccountOperation(operation);
    });
  }

  /**
   * Change the master password without re-encrypting the vault: the UserKey is unchanged, only its
   * wrapping (protectedKey) and the password hash change. After the server accepts the re-wrapped key,
   * the changed account is removed locally so no old credential or plaintext key remains reusable.
   * Requires an unlocked vault and the current password.
   */
  async changeMasterPassword(
    currentPassword: string,
    newPassword: string,
    masterPasswordHint: string,
  ): Promise<void> {
    if (!this.deps.passwordChangePending) {
      throw new AppError('denied', 'Password change safety state is unavailable.');
    }
    const policy = this.captureMasterPasswordPolicyForChange();
    const seed = this.captureAccountOperationSeed();
    await this.runAccountOperation(async () => {
      const { operation, oldMasterKey } = await this.requireForRewrap(seed, currentPassword);
      let newMasterKey: Uint8Array | undefined;
      let newStretched: SymmetricKey | undefined;
      try {
        this.assertNewMasterPasswordAllowed(newPassword, operation.auth.email, policy);
        const hint = requireMasterPasswordHint(masterPasswordHint, newPassword);
        newMasterKey = await deriveMasterKey(newPassword, operation.auth.email, operation.auth);
        newStretched = await stretchMasterKey(newMasterKey);
        const newProtectedKey = await this.wrapUserKey(operation.userKey, newStretched);
        const request = {
          masterPasswordHash: await deriveMasterPasswordHash(oldMasterKey, currentPassword),
          newMasterPasswordHash: await deriveMasterPasswordHash(newMasterKey, newPassword),
          key: newProtectedKey,
          masterPasswordHint: hint,
        };
        await this.runPasswordWriteAndRetireAccount(
          operation,
          () => {
            this.assertMasterPasswordPolicyCurrent(policy);
            return operation.api.changePassword(operation.auth.accessToken, request);
          },
        );
      } finally {
        oldMasterKey.fill(0);
        newMasterKey?.fill(0);
        clearSymmetricKey(newStretched);
      }
    });
  }

  /** Complete the only privileged action admitted for a restricted authenticated account. */
  async changeForcedMasterPassword(currentPassword: string, newPassword: string): Promise<void> {
    const pending = this.deps.passwordChangePending;
    const accountGate = this.deps.accountGate;
    if (!pending || !accountGate) {
      throw new AppError('denied', 'Forced password change safety state is unavailable.');
    }
    const accountLease = accountGate.capture();
    await this.runAccountOperation(async () => {
      const accessToken = await this.getAccountAccessToken(accountLease);
      const auth = await this.deps.session.getActiveAuth();
      accountGate.assert(accountLease);
      if (
        !auth?.restriction
        || auth.sessionBindingId !== undefined
        || auth.email !== accountLease.accountIdentity
        || await this.deps.session.getState() !== 'restricted'
      ) {
        throw new AppError('session_expired', 'The password change requirement is no longer current.');
      }
      this.assertNewMasterPasswordAllowed(newPassword, auth.email, {
        ...(auth.restriction.policy ? { policy: auth.restriction.policy } : {}),
      });

      const oldMasterKey = await deriveMasterKey(currentPassword, auth.email, auth);
      let oldStretched: SymmetricKey | undefined;
      let userKey: SymmetricKey | undefined;
      let newMasterKey: Uint8Array | undefined;
      let newStretched: SymmetricKey | undefined;
      try {
        oldStretched = await stretchMasterKey(oldMasterKey);
        try {
          userKey = await unwrapSymmetricKey(auth.protectedKey, oldStretched);
        } catch (error) {
          if (error instanceof EncStringMacError) {
            throw new AppError('denied', 'Current master password is incorrect.');
          }
          throw error;
        }
        accountGate.assert(accountLease);
        newMasterKey = await deriveMasterKey(newPassword, auth.email, auth);
        newStretched = await stretchMasterKey(newMasterKey);
        const newProtectedKey = await this.wrapUserKey(userKey, newStretched);
        const newMasterPasswordHash = await deriveMasterPasswordHash(newMasterKey, newPassword);
        const currentMasterPasswordHash = await deriveMasterPasswordHash(oldMasterKey, currentPassword);
        accountGate.assert(accountLease);
        await pending.markBeforeChange({
          serverUrl: accountLease.serverUrl,
          accountId: accountLease.accountIdentity,
        });

        const fixedApi = this.deps.api.forServer(accountLease.serverUrl).withRequestGuard(() => {
          accountGate.assert(accountLease);
        });
        try {
          if (auth.restriction.reason === 'adminForcePasswordReset') {
            await fixedApi.updateTemporaryPassword(accessToken, {
              newMasterPasswordHash,
              key: newProtectedKey,
              masterPasswordHint: '',
            });
          } else {
            await fixedApi.changePassword(accessToken, {
              masterPasswordHash: currentMasterPasswordHash,
              newMasterPasswordHash,
              key: newProtectedKey,
              masterPasswordHint: '',
            });
          }
        } catch (error) {
          if (isDefinitePasswordChangeRejection(error)) {
            await pending.clear();
            throw error;
          }
          await this.retireAmbiguousPasswordChange(auth.email, pending);
          throw passwordChangeOutcomeUnknown();
        }

        try {
          await this.logoutAccountOwner(auth.email);
          await pending.clear();
        } catch {
          await this.retireAmbiguousPasswordChange(auth.email, pending);
          throw passwordChangeOutcomeUnknown();
        }
      } finally {
        oldMasterKey.fill(0);
        clearSymmetricKey(oldStretched);
        clearSymmetricKey(userKey);
        newMasterKey?.fill(0);
        clearSymmetricKey(newStretched);
      }
    });
  }

  /**
   * Rotate the account UserKey under a terminal vault barrier. Once the final POST is invoked, local
   * account state is reset regardless of the response because the remote outcome may be ambiguous.
   */
  async rotateAccountKey(masterPassword: string): Promise<void> {
    const barrier = this.deps.rotationBarrier;
    const pending = this.deps.rotationPending;
    const clearIdentity = this.deps.onIdentityChanged;
    if (!barrier || !pending || !clearIdentity) {
      throw new Error('Key rotation safety dependencies are not configured');
    }
    const seed = this.captureAccountOperationSeed();
    await this.runAccountOperation(async () => {
      const operation = await this.beginAccountMutation(seed);
      const accountLease = operation.accountLease;
      if (!accountLease) throw new Error('Key rotation requires an account lease');
      const account = accountKeyFor(accountLease);
      await barrier.run(account, async (terminal) => {
        terminal.assertCurrent();
        await this.assertAccountOperation(operation);
        await runRotation(masterPassword, {
          api: {
            sync: (token) => this.runRotationRemote(operation, terminal, (api) => api.sync(token)),
            getTrustedEmergencyAccess: (token) => this.runRotationRemote(
              operation,
              terminal,
              (api) => api.getTrustedEmergencyAccess(token),
            ),
            getOrganizationPublicKey: (token, orgId) => this.runRotationRemote(
              operation,
              terminal,
              (api) => api.getOrganizationPublicKey(token, orgId),
            ),
            getAccountPublicKey: (token) => this.runRotationRemote(
              operation,
              terminal,
              (api) => api.getAccountPublicKey(token),
            ),
            getKeyRotationUnlockRecordsStatus: (token) => this.runRotationRemote(
              operation,
              terminal,
              (api) => api.getKeyRotationUnlockRecordsStatus(token),
            ),
            rotateAccountKey: (token, body) => this.commitAccountKeyRotation(
              operation,
              accountLease,
              terminal,
              pending,
              clearIdentity,
              token,
              body,
            ),
          },
          session: {
            getPersistedAuth: async () => {
              await this.assertAccountOperation(operation);
              return operation.auth;
            },
            loadUserKey: async () => {
              await this.assertAccountOperation(operation);
              return operation.userKey;
            },
            loadPrivateKey: async () => {
              await this.assertAccountOperation(operation);
              const privateKey = await this.deps.session.loadPrivateKey();
              await this.assertAccountOperation(operation);
              return privateKey;
            },
          },
          verifyMasterPassword: (pw) => this.verifyMasterPasswordForOperation(operation, pw),
        });
      });
    });
  }

  /**
   * Change the complete KDF configuration: re-derive from the same password, re-wrap the UserKey,
   * and update the server + local material. A successful change also disables PIN unlock because its
   * persisted wrapping key was derived with the previous KDF.
   */
  async changeKdf(currentPassword: string, newKdf: KdfConfig): Promise<void> {
    assertKdfConfigForSetting(newKdf);
    const seed = this.captureAccountOperationSeed();
    await this.runAccountOperation(async () => {
      const { operation, oldMasterKey } = await this.requireForRewrap(seed, currentPassword);
      if (sameKdfConfig(newKdf, operation.auth)) throw new Error('KDF settings are already set to those values');
      const newMasterKey = await deriveMasterKey(currentPassword, operation.auth.email, newKdf);
      const newProtectedKey = await this.wrapUserKey(operation.userKey, await stretchMasterKey(newMasterKey));
      const apiKdf = toApiKdfSettings(newKdf);
      const newMasterPasswordHash = await deriveMasterPasswordHash(newMasterKey, currentPassword);
      const request = {
        kdf: newKdf.kdf,
        kdfIterations: newKdf.kdfIterations,
        kdfMemory: newKdf.kdf === 1 ? newKdf.kdfMemory : null,
        kdfParallelism: newKdf.kdf === 1 ? newKdf.kdfParallelism : null,
        masterPasswordHash: await deriveMasterPasswordHash(oldMasterKey, currentPassword),
        newMasterPasswordHash,
        key: newProtectedKey,
        authenticationData: {
          salt: operation.auth.email,
          kdf: apiKdf,
          masterPasswordAuthenticationHash: newMasterPasswordHash,
        },
        unlockData: {
          salt: operation.auth.email,
          kdf: apiKdf,
          masterKeyWrappedUserKey: newProtectedKey,
        },
      };
      await this.runAccountWriteAndCommit(
        operation,
        () => operation.api.changeKdf(operation.auth.accessToken, request),
        { protectedKey: newProtectedKey, kdf: newKdf },
      );
    });
  }

  /** Shared preamble for password/KDF re-wrap: require unlock + verify the current password. */
  private async requireForRewrap(seed: AccountOperationSeed, currentPassword: string) {
    const operation = await this.beginAccountMutation(seed);
    const oldMasterKey = await deriveMasterKey(
      currentPassword,
      operation.auth.email,
      operation.auth,
    );
    let oldStretched: SymmetricKey | undefined;
    let verifiedUserKey: SymmetricKey | undefined;
    try {
      oldStretched = await stretchMasterKey(oldMasterKey);
      verifiedUserKey = await unwrapSymmetricKey(operation.auth.protectedKey, oldStretched);
    } catch (error) {
      oldMasterKey.fill(0);
      if (error instanceof EncStringMacError) {
        throw new Error('Current master password is incorrect', { cause: error });
      }
      throw error;
    } finally {
      clearSymmetricKey(verifiedUserKey);
      clearSymmetricKey(oldStretched);
    }
    try {
      await this.assertAccountOperation(operation);
    } catch (error) {
      oldMasterKey.fill(0);
      throw error;
    }
    return { operation, oldMasterKey };
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
    try {
      const operation = await this.loadAccountOperation(this.captureAccountOperationSeed());
      return this.verifyMasterPasswordForOperation(operation, masterPassword);
    } catch (error) {
      if (error instanceof AppError && (error.code === 'locked' || error.code === 'session_expired')) return false;
      throw error;
    }
  }

  private captureMasterPasswordPolicyForChange(): MasterPasswordPolicyAuthorization {
    const gate = this.deps.enterprisePolicyGate;
    if (!gate) return Object.freeze({});
    const lease = gate.capture();
    const snapshot = gate.assert(lease);
    if (snapshot.masterPasswordPolicyMalformed === true) {
      throw new AppError('denied', 'The master password policy is invalid.');
    }
    return Object.freeze({
      lease,
      ...(snapshot.masterPasswordPolicy
        ? { policy: snapshot.masterPasswordPolicy }
        : {}),
    });
  }

  private assertMasterPasswordPolicyCurrent(
    authorization: MasterPasswordPolicyAuthorization,
  ): void {
    if (authorization.lease) this.deps.enterprisePolicyGate?.assert(authorization.lease);
  }

  private assertNewMasterPasswordAllowed(
    newPassword: string,
    email: string,
    authorization: MasterPasswordPolicyAuthorization,
  ): void {
    this.assertMasterPasswordPolicyCurrent(authorization);
    if (
      !isNewMasterPasswordLengthAllowed(newPassword, authorization.policy)
      || !evaluateMasterPasswordPolicy(newPassword, email, authorization.policy)
    ) {
      throw new AppError('denied', 'The new master password does not meet the required policy.');
    }
  }

  async isPinEnabled(): Promise<boolean> {
    return (await this.getPinStatus()).enabled;
  }

  /** One policy-consistent status read. A missing policy snapshot never reveals a stored PIN. */
  async getPinStatus(): Promise<PinStatus> {
    let policyLease: PolicyLease | undefined;
    try {
      policyLease = this.capturePinPolicyLease();
    } catch {
      return {
        enabled: false,
        available: false,
        allowed: false,
        requireMasterPasswordOnRestart: true,
      };
    }
    const state = await this.deps.session.getPinStateSummary();
    try {
      this.assertPinPolicyAllowed(policyLease);
      return {
        enabled: state.configured,
        available: state.available,
        allowed: true,
        requireMasterPasswordOnRestart: state.requireMasterPasswordOnRestart,
      };
    } catch {
      return {
        enabled: false,
        available: false,
        allowed: false,
        requireMasterPasswordOnRestart: true,
      };
    }
  }

  /** Apply RemoveUnlockWithPin to already-persisted state after a fresh policy snapshot is published. */
  async enforceCurrentEnterprisePolicy(): Promise<void> {
    const gate = this.deps.enterprisePolicyGate;
    if (!gate) return;
    const lease = gate.capture();
    const snapshot = gate.assert(lease);
    if (enterprisePolicyAllows(snapshot, 'unlockWithPin')) return;
    await this.runSessionMutation(async () => {
      const current = gate.assert(lease);
      if (enterprisePolicyAllows(current, 'unlockWithPin')) return;
      await this.deps.session.removePinProtectedUserKey();
    });
  }

  /** All logged-in accounts (active flagged), for the account switcher. */
  listAccounts() {
    return this.deps.session.listAccounts();
  }

  /** Activate another logged-in account; the vault locks so the user re-unlocks it. */
  async switchAccount(email: string): Promise<void> {
    const normalized = email.trim().toLowerCase();
    const pendingClear = this.clearStoredPendingLogin();
    this.cancelActivationAttempts();
    await this.runSessionTransition(
      'switchAccount',
      true,
      async () => {
        await pendingClear;
        const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
        if (normalized === activeBefore) return;
        await this.deps.onIdentityChanged?.();
        await this.runSessionMutation(() => this.deps.session.switchAccount(normalized));
      },
    );
  }

  async removeAccount(email: string): Promise<void> {
    const normalized = email.trim().toLowerCase();
    const pendingClear = this.clearStoredPendingLogin();
    this.cancelActivationAttempts();
    await this.runSessionTransition('removeAccount', true, async () => {
      await pendingClear;
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      if (normalized === activeBefore) await this.deps.onIdentityChanged?.();
      const serverUrl = await this.currentServerUrl();
      if (serverUrl) await this.deps.session.removeRememberDeviceToken(serverUrl, normalized);
      await this.runSessionMutation(() => this.deps.session.removeAccount(normalized));
      if (serverUrl) {
        await boundedGeneratorHistoryCleanup(() => this.deps.clearGeneratorHistoryForAccount?.({
          serverUrl, accountId: normalized,
        }));
      }
    });
  }

  /** Drop all account-scoped authentication before switching the configured server. */
  async resetForServerChange(commitServerUrl?: () => Promise<void>): Promise<void> {
    const pendingClear = this.clearStoredPendingLogin();
    this.cancelActivationAttempts();
    const reset = ++this.serverResetSequence;
    this.serverResetPending = true;
    try {
      await this.runSessionTransition('serverChange', true, async () => {
        await pendingClear;
        const previousServerUrl = this.deps.clearGeneratorHistoryForServer
          ? await this.currentServerUrl()
          : undefined;
        await this.deps.onIdentityChanged?.();
        await this.waitForRefreshIdle();
        await this.runSessionMutation(async () => {
          await this.deps.session.resetAllAccounts();
          await commitServerUrl?.();
        });
        if (previousServerUrl) {
          await boundedGeneratorHistoryCleanup(
            () => this.deps.clearGeneratorHistoryForServer?.(previousServerUrl),
          );
        }
      });
    } finally {
      if (reset === this.serverResetSequence) this.serverResetPending = false;
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

  private captureAccountOperationSeed(): AccountOperationSeed {
    const sessionLease = this.deps.sessionGate.capture();
    const accountLease = this.deps.accountGate?.capture();
    const fixedApi = accountLease
      ? this.deps.api.forServer(accountLease.serverUrl)
      : this.deps.api;
    const assertCurrent = (): void => {
      this.assertSessionLease(sessionLease);
      if (accountLease) this.assertAccountLease(accountLease);
    };
    return {
      sessionLease,
      ...(accountLease ? { accountLease } : {}),
      fixedApi,
      api: fixedApi.withRequestGuard(assertCurrent),
    };
  }

  private async beginAccountMutation(seed: AccountOperationSeed): Promise<AccountOperation> {
    this.assertAccountOperationSeed(seed);
    this.cancelActivationAttempts();
    return this.loadAccountOperation(seed);
  }

  private async loadAccountOperation(seed: AccountOperationSeed): Promise<AccountOperation> {
    this.assertAccountOperationSeed(seed);
    const [auth, userKey] = await Promise.all([
      this.deps.session.getActiveAuth(),
      this.deps.session.loadUserKey(),
    ]);
    this.assertAccountOperationSeed(seed);
    if (!auth) throw new AppError('session_expired', 'The active account changed during the operation.');
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    return { ...seed, auth, userKey };
  }

  private async assertAccountOperation(operation: AccountOperation): Promise<void> {
    this.assertAccountOperationSeed(operation);
    const [current, userKey] = await Promise.all([
      this.deps.session.getActiveAuth(),
      this.deps.session.loadUserKey(),
    ]);
    this.assertAccountOperationSeed(operation);
    if (
      !current
      || current.email !== operation.auth.email
      || current.sessionBindingId !== operation.auth.sessionBindingId
      || current.protectedKey !== operation.auth.protectedKey
      || !sameKdfConfig(current, operation.auth)
    ) {
      throw new AppError('session_expired', 'The active account changed during the operation.');
    }
    if (!userKey) throw new AppError('locked', 'Vault is locked');
  }

  private assertAccountOperationSeed(seed: AccountOperationSeed): void {
    this.assertSessionLease(seed.sessionLease);
    if (seed.accountLease) this.assertAccountLease(seed.accountLease);
  }

  private assertSessionLease(sessionLease: SessionLease): void {
    try {
      this.deps.sessionGate.assert(sessionLease);
    } catch {
      throw new AppError('session_expired', 'The active account changed during the operation.');
    }
  }

  private assertAccountLease(accountLease: AccountLease): void {
    try {
      this.deps.accountGate?.assert(accountLease);
    } catch {
      throw new AppError('session_expired', 'The active account changed during the operation.');
    }
  }

  private async runAccountRemote<T>(
    operation: AccountOperation,
    request: (api: ApiClient) => Promise<T>,
  ): Promise<T> {
    await this.assertAccountOperation(operation);
    const result = await request(operation.api);
    await this.assertAccountOperation(operation);
    return result;
  }

  private async runRotationRemote<T>(
    operation: AccountOperation,
    terminal: VaultTerminalTaskContext<string, AccountLease>,
    request: (api: ApiClient) => Promise<T>,
  ): Promise<T> {
    terminal.assertCurrent();
    const result = await this.runAccountRemote(operation, request);
    terminal.assertCurrent();
    return result;
  }

  private async commitAccountKeyRotation(
    operation: AccountOperation,
    accountLease: AccountLease,
    terminal: VaultTerminalTaskContext<string, AccountLease>,
    pending: Pick<RotationPendingStore, 'markBeforeRotation' | 'clear'>,
    clearIdentity: () => Promise<void>,
    token: string,
    body: Parameters<ApiClient['rotateAccountKey']>[1],
  ): Promise<void> {
    if (token !== operation.auth.accessToken) throw new Error('Key rotation access token changed');
    await this.waitForTransitionIdle();
    await this.assertAccountOperation(operation);
    terminal.assertCurrent();
    const pendingMarker = await pending.markBeforeRotation({
      serverUrl: accountLease.serverUrl,
      accountId: accountLease.accountIdentity,
    });
    try {
      // No await may separate these final synchronous checks from terminal admission.
      this.assertAccountOperationSeed(operation);
      terminal.assertCurrent();
      terminal.commitTerminal();
    } catch (error) {
      // No request left the process, so a successfully written marker can be removed safely.
      await pending.clear();
      throw error;
    }
    this.terminalSessionBlocked = true;
    this.cancelActivationAttempts();

    let remoteFailed = false;
    try {
      await this.runSessionTransition('keyRotation', true, async () => {
        await this.runSessionMutation(async () => {
          try {
            await operation.fixedApi.rotateAccountKey(token, body);
          } catch {
            remoteFailed = true;
          } finally {
            await this.cleanupAfterAccountKeyRotation(pending, clearIdentity, pendingMarker);
          }
        });
      }, { terminal: true, settleOnFailure: false });
    } catch {
      throw rotationOutcomeUnknown();
    }

    this.terminalSessionBlocked = false;
    if (remoteFailed) throw rotationOutcomeUnknown();
  }

  private async cleanupAfterAccountKeyRotation(
    pending: Pick<RotationPendingStore, 'clear'>,
    clearIdentity: () => Promise<void>,
    marker: RotationPendingMarker,
  ): Promise<void> {
    const failures: unknown[] = [];
    try {
      await this.deps.session.resetAllAccounts();
    } catch (error) {
      failures.push(error);
    }
    try {
      await clearIdentity();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.deps.clearGeneratorHistoryForServerAfterRotation?.(marker.serverUrl);
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.deps.clearClientEventsAfterRotation?.(marker);
    } catch (error) {
      failures.push(error);
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) {
      throw new AggregateError(failures, 'Account key rotation cleanup failed');
    }
    await pending.clear();
  }

  private async verifyMasterPasswordForOperation(
    operation: AccountOperation,
    masterPassword: string,
  ): Promise<boolean> {
    const masterKey = await deriveMasterKey(
      masterPassword,
      operation.auth.email,
      operation.auth,
    );
    let verified = false;
    try {
      await unwrapSymmetricKey(operation.auth.protectedKey, await stretchMasterKey(masterKey));
      verified = true;
    } catch (error) {
      // Only a verified wrong-key MAC failure is an ordinary password mismatch. Corrupt persisted
      // material and runtime crypto failures must stay visible to the caller.
      if (!(error instanceof EncStringMacError)) throw error;
    }
    await this.assertAccountOperation(operation);
    return verified;
  }

  private async runAccountWriteAndCommit(
    operation: AccountOperation,
    remoteWrite: () => Promise<void>,
    update: { protectedKey: string; kdf?: KdfConfig },
  ): Promise<void> {
    await this.assertAccountOperation(operation);
    await this.runSessionMutation(async () => {
      await this.assertAccountOperation(operation);
      this.cancelActivationAttempts();
      if (update.kdf) {
        // Disable both PIN tiers before the irreversible remote KDF request. If the request fails,
        // requiring the user to configure PIN again is safer than retaining stale unlock material.
        await this.deps.session.removePinProtectedUserKey(operation.auth.email);
      }
      await remoteWrite();
      await this.deps.session.updateMasterKeyMaterialFor({
        email: operation.auth.email,
        protectedKey: operation.auth.protectedKey,
        ...pickKdfConfig(operation.auth),
      }, update);
      const nextKdf = pickKdfConfig(update.kdf ?? operation.auth);
      operation.auth = {
        email: operation.auth.email,
        accessToken: operation.auth.accessToken,
        refreshToken: operation.auth.refreshToken,
        expiresAt: operation.auth.expiresAt,
        protectedKey: update.protectedKey,
        ...nextKdf,
        ...(operation.auth.encPrivateKey ? { encPrivateKey: operation.auth.encPrivateKey } : {}),
        ...(operation.auth.sessionBindingId
          ? { sessionBindingId: operation.auth.sessionBindingId }
          : {}),
      };
      this.cancelActivationAttempts();
    });
    await this.assertAccountOperation(operation);
  }

  private async runPasswordWriteAndRetireAccount(
    operation: AccountOperation,
    remoteWrite: () => Promise<void>,
  ): Promise<void> {
    const pending = this.deps.passwordChangePending;
    if (!pending) throw new AppError('denied', 'Password change safety state is unavailable.');
    const configuredServer = operation.accountLease?.serverUrl ?? await this.currentServerUrl();
    if (!configuredServer) {
      throw new AppError('denied', 'Password change server identity is unavailable.');
    }
    const serverUrl = canonicalAccountPasskeyServer(configuredServer);
    await this.assertAccountOperation(operation);
    let remoteDispatched = false;
    let outcomeUnknown = false;
    try {
      await this.runSessionMutation(async () => {
        await this.assertAccountOperation(operation);
        this.cancelActivationAttempts();
        await pending.markBeforeChange({
          serverUrl,
          accountId: operation.auth.email,
        });
        try {
          remoteDispatched = true;
          await remoteWrite();
        } catch (error) {
          if (isDefinitePasswordChangeRejection(error)) {
            remoteDispatched = false;
            // A clear failure intentionally preserves the WAL. Startup retires the local account;
            // the password request is never replayed even though the server definitely rejected it.
            await pending.clear();
            throw error;
          }
          outcomeUnknown = true;
          this.passwordChangeSessionBlocked = true;
          throw error;
        }
        this.passwordChangeSessionBlocked = true;
      });
      await this.logoutAccountOwner(operation.auth.email);
      await pending.clear();
      this.passwordChangeSessionBlocked = false;
    } catch (error) {
      if (!remoteDispatched && !outcomeUnknown) throw error;
      await this.retireAmbiguousPasswordChange(operation.auth.email, pending);
      throw passwordChangeOutcomeUnknown();
    }
  }

  private async retireAmbiguousPasswordChange(
    owner: string,
    pending: Pick<PasswordChangePendingStore, 'clear'>,
  ): Promise<void> {
    this.passwordChangeSessionBlocked = true;
    let loggedOut = false;
    try {
      await this.logoutAccountOwner(owner);
      loggedOut = true;
    } catch {
      // Preserve the durable marker so startup can finish cleanup if immediate logout fails.
      await this.deps.session.lock().catch(() => undefined);
    }
    if (loggedOut) {
      this.passwordChangeSessionBlocked = false;
      await pending.clear().catch(() => undefined);
    }
  }

  private async derivePinKey(pin: string, email: string, kdf: KdfConfig): Promise<SymmetricKey> {
    return stretchMasterKey(await deriveMasterKey(pin, email, kdf));
  }

  private async rejectInvalidPin(
    owner: string,
    credentialId: string,
    attempt: number,
    policyLease: PolicyLease | undefined,
  ): Promise<never> {
    this.assertPinPolicyAllowed(policyLease);
    this.assertActivationAttempt(attempt);
    let attempts: number | undefined;
    try {
      attempts = await this.deps.session.recordFailedPinAttempt(owner, credentialId);
    } catch {
      await this.logoutAfterPinLimit(owner);
      throw new AppError(
        'pin_attempts_exceeded',
        'PIN attempt protection could not be persisted. The account was logged out.',
      );
    }
    if (attempts !== undefined && attempts >= MAX_INVALID_PIN_ATTEMPTS) {
      await this.logoutAfterPinLimit(owner);
      throw new AppError(
        'pin_attempts_exceeded',
        'Too many invalid PIN attempts. The account was logged out.',
      );
    }
    this.assertPinPolicyAllowed(policyLease);
    this.assertActivationAttempt(attempt);
    if (attempts === undefined) {
      throw new AppError('session_expired', 'The PIN credential changed during the unlock attempt.');
    }
    throw new AppError('invalid_pin', 'Incorrect PIN');
  }

  private async logoutAfterPinLimit(owner: string): Promise<void> {
    const pendingClear = this.clearStoredPendingLogin();
    this.cancelActivationAttempts();
    await this.runSessionTransition('logout', true, async () => {
      await pendingClear;
      const serverUrl = await this.currentServerUrl();
      const active = await this.deps.session.getPersistedAuth();
      if (active?.email === owner) {
        try {
          await this.deps.onIdentityChanged?.();
        } catch {
          // Transition-start fences already revoke secret work. Local account removal must still
          // complete if a derived-cache purge reports an independent failure.
        }
      }
      await this.runSessionMutation(async () => {
        const current = await this.deps.session.getPersistedAuth();
        if (current?.email === owner) {
          await this.deps.session.logout();
        } else {
          await this.deps.session.removeAccount(owner);
        }
      });
      if (serverUrl) {
        await boundedGeneratorHistoryCleanup(() => this.deps.clearGeneratorHistoryForAccount?.({
          serverUrl, accountId: owner,
        }));
      }
    });
  }

  private async logoutAccountOwner(owner: string): Promise<void> {
    this.cancelActivationAttempts();
    await this.runSessionTransition('logout', true, async () => {
      const serverUrl = await this.currentServerUrl();
      const active = await this.deps.session.getPersistedAuth();
      if (active?.email === owner) {
        try {
          await this.deps.onIdentityChanged?.();
        } catch {
          // The transition fence remains closed while owner-bound credential removal continues.
        }
      }
      await this.runSessionMutation(async () => {
        const current = await this.deps.session.getPersistedAuth();
        if (current?.email === owner) await this.deps.session.logout();
        else await this.deps.session.removeAccount(owner);
      });
      if (serverUrl) {
        await boundedGeneratorHistoryCleanup(() => this.deps.clearGeneratorHistoryForAccount?.({
          serverUrl, accountId: owner,
        }));
      }
    }, { passwordChangeRecovery: true, settleOnFailure: false });
  }

  private async rearmPinAfterMasterPasswordUnlock(
    auth: ActiveAuth,
    userKey: SymmetricKey,
  ): Promise<void> {
    let policyLease: PolicyLease | undefined;
    let pinBytes: Uint8Array | undefined;
    let pinKey: SymmetricKey | undefined;
    let rawUserKey: Uint8Array | undefined;
    try {
      policyLease = this.capturePinPolicyLease();
      const activePin = await this.deps.session.getPinUnlockState(auth.email);
      if (activePin) {
        await this.deps.session.clearFailedPinAttempts(auth.email, activePin.credentialId);
      }
      const rearm = await this.deps.session.getPinRearmData(auth.email);
      this.assertPinPolicyAllowed(policyLease);
      if (!rearm) return;
      pinBytes = await decryptToBytes(rearm.encryptedPin, userKey);
      const pin = bytesToUtf8(pinBytes);
      assertValidPin(pin);
      pinKey = await this.derivePinKey(pin, auth.email, auth);
      rawUserKey = serializeSymmetricKey(userKey);
      const protectedUserKey = await encryptToBytes(rawUserKey, pinKey);
      this.assertPinPolicyAllowed(policyLease);
      await this.deps.session.saveRearmedPinProtectedUserKey(
        auth.email,
        rearm.configurationId,
        protectedUserKey,
      );
      this.assertPinPolicyAllowed(policyLease);
    } catch {
      // PIN rearming is optional after a successful master-password unlock. Corrupt, stale, or
      // policy-blocked state remains unavailable and never turns a valid master unlock into failure.
    } finally {
      pinBytes?.fill(0);
      if (pinKey) clearSymmetricKey(pinKey);
      rawUserKey?.fill(0);
    }
  }

  private async upgradeLegacyPinAfterUnlock(
    auth: ActiveAuth,
    pin: string,
    userKey: SymmetricKey,
    expectedProtectedUserKey: string,
  ): Promise<void> {
    let pinBytes: Uint8Array | undefined;
    try {
      const policyLease = this.capturePinPolicyLease();
      pinBytes = utf8ToBytes(pin);
      const encryptedPin = await encryptToBytes(pinBytes, userKey);
      this.assertPinPolicyAllowed(policyLease);
      await this.deps.session.upgradeLegacyPinAfterUnlock(
        auth.email,
        expectedProtectedUserKey,
        encryptedPin,
      );
      this.assertPinPolicyAllowed(policyLease);
    } catch {
      // The migrated session-only PIN remains usable until browser exit even if the optional
      // after-first-unlock metadata upgrade cannot be committed.
    } finally {
      pinBytes?.fill(0);
    }
  }

  getState(): Promise<SessionState> {
    if (this.passwordChangeSessionBlocked) return Promise.resolve('loggedOut');
    return this.deps.session.getState();
  }

  async getPasswordChangeRequirement(): Promise<PasswordChangeRequirement | undefined> {
    if (await this.deps.session.getState() !== 'restricted') return undefined;
    return this.deps.session.getPasswordChangeRequirement();
  }

  /** Return a usable token only while both caller-owned session and account leases remain current. */
  async getAccessToken(
    sessionLease: SessionLease,
    accountLease: AccountLease,
    skewMs = 60_000,
  ): Promise<string> {
    if (!Number.isSafeInteger(skewMs) || skewMs < 0) {
      throw new RangeError('access token skewMs must be a non-negative safe integer');
    }
    const seed = this.createLeasedRefreshSeed(sessionLease, accountLease);
    await this.readLeasedAuth(sessionLease, accountLease);
    this.assertAccessTokenLeases(sessionLease, accountLease);
    await this.trackRefreshIfNeeded(skewMs, seed);
    this.assertAccessTokenLeases(sessionLease, accountLease);
    const auth = await this.readLeasedAuth(sessionLease, accountLease);
    this.assertAccessTokenLeases(sessionLease, accountLease);
    if (auth.expiresAt <= this.now() || !auth.accessToken.trim()) throw accessTokenUnavailable();
    return auth.accessToken;
  }

  /** Return a usable token for one exact account while the vault is either locked or unlocked. */
  async getAccountAccessToken(
    accountLease: AccountLease,
    skewMs = 60_000,
  ): Promise<string> {
    if (!Number.isSafeInteger(skewMs) || skewMs < 0) {
      throw new RangeError('access token skewMs must be a non-negative safe integer');
    }
    const seed = this.createAccountLeasedRefreshSeed(accountLease);
    await this.readAccountLeasedAuth(accountLease);
    this.assertAccountAccessTokenLease(accountLease);
    await this.trackRefreshIfNeeded(skewMs, seed);
    this.assertAccountAccessTokenLease(accountLease);
    const auth = await this.readAccountLeasedAuth(accountLease);
    this.assertAccountAccessTokenLease(accountLease);
    if (auth.expiresAt <= this.now() || !auth.accessToken.trim()) throw accessTokenUnavailable();
    return auth.accessToken;
  }

  /**
   * Execute one explicitly rebuildable account request. A server 401 forces one token refresh and
   * exactly one rebuilt retry; every other failure is returned without replaying the request. The
   * caller owns post-response authority checks so a committed mutation can be marked before a stale
   * lease is reported.
   */
  async executeAuthenticatedRequest<Result>(
    accountLease: AccountLease,
    rebuildRequest: ReplayableAuthenticatedRequest<Result>,
  ): Promise<Result> {
    if (typeof rebuildRequest !== 'function') throw new TypeError('Authenticated request factory is required');
    const initialAccessToken = await this.getAccountAccessToken(accountLease);
    try {
      return await rebuildRequest(initialAccessToken);
    } catch (error) {
      if (!isUnauthorizedResponse(error)) throw error;
    }

    let retryAccessToken: string;
    try {
      retryAccessToken = await this.forceRefreshAfterUnauthorized(
        accountLease,
        initialAccessToken,
      );
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError(
        'error',
        'Authentication could not be refreshed. Try the request again.',
      );
    }
    try {
      return await rebuildRequest(retryAccessToken);
    } catch (error) {
      if (isUnauthorizedResponse(error)) {
        await this.logoutAfterRepeatedUnauthorized(accountLease, retryAccessToken);
      }
      throw error;
    }
  }

  async lock(): Promise<void> {
    this.cancelActivationAttempts();
    await this.runSessionTransition('lock', false, async () => {
      await this.runSessionMutation(() => this.deps.session.lock());
      // Best-effort: purge decrypted metadata left on disk. Must never turn a lock into a failure.
      try {
        await this.deps.onLock?.();
      } catch {
        /* ignore */
      }
    });
  }

  async logout(): Promise<void> {
    const pendingClear = this.clearStoredPendingLogin();
    this.cancelActivationAttempts();
    await this.runSessionTransition(
      'logout',
      true,
      async () => {
        await pendingClear;
        const active = await this.deps.session.getPersistedAuth();
        const serverUrl = active ? await this.currentServerUrl() : undefined;
        if (active) await this.deps.onIdentityChanged?.();
        await this.runSessionMutation(() => this.deps.session.logout());
        if (active && serverUrl) {
          await boundedGeneratorHistoryCleanup(() => this.deps.clearGeneratorHistoryForAccount?.({
            serverUrl, accountId: active.email.trim().toLowerCase(),
          }));
        }
      },
    );
  }

  /**
   * Revoke credentials after a validated sync security-stamp failure. The caller must bind this
   * call to the still-current account credential immediately before invocation.
   */
  async revokeForSecurityStampFailure(
    expected: AuthTokenLease,
    scope: 'currentCredential' | 'allAccounts',
  ): Promise<boolean> {
    const pendingClear = this.clearStoredPendingLogin();
    this.cancelActivationAttempts();
    return this.runSessionTransition('logout', true, async () => {
      await pendingClear.catch(() => undefined);
      const serverUrl = await this.currentServerUrl();
      const removed = await this.runSessionMutation(() => scope === 'allAccounts'
        ? this.deps.session.resetAllAccountsIfTokenCurrent(expected)
        : this.deps.session.logoutIfTokenCurrent(expected));
      if (removed) {
        try {
          await this.deps.onIdentityChanged?.();
        } catch {
          // Credential revocation is authoritative even if physical cache cleanup must be retried.
        }
      }
      if (removed && serverUrl) {
        if (scope === 'allAccounts') {
          await boundedGeneratorHistoryCleanup(
            () => this.deps.clearGeneratorHistoryForServer?.(serverUrl),
          );
        } else {
          await boundedGeneratorHistoryCleanup(() => this.deps.clearGeneratorHistoryForAccount?.({
            serverUrl, accountId: expected.email.trim().toLowerCase(),
          }));
        }
      }
      return removed;
    });
  }

  async refreshIfNeeded(skewMs = 60_000): Promise<void> {
    if (this.serverResetPending) return;
    const seed = this.captureRefreshSeed();
    if (!seed) return;
    await this.trackRefreshIfNeeded(skewMs, seed);
  }

  private async trackRefreshIfNeeded(skewMs: number, seed: RefreshSeed): Promise<void> {
    this.refreshAttempts++;
    try {
      if (this.serverResetPending) return;
      await this.runRefreshIfNeeded(skewMs, seed);
    } finally {
      this.refreshAttempts--;
      if (this.refreshAttempts === 0) {
        for (const resolve of this.refreshIdleResolvers.splice(0)) resolve();
      }
    }
  }

  private createLeasedRefreshSeed(
    sessionLease: SessionLease,
    accountLease: AccountLease,
  ): RefreshSeed {
    return this.createAccountLeasedRefreshSeed(accountLease, sessionLease);
  }

  private createAccountLeasedRefreshSeed(
    accountLease: AccountLease,
    callerSessionLease?: SessionLease,
  ): RefreshSeed {
    if (callerSessionLease) this.assertAccessTokenLeases(callerSessionLease, accountLease);
    else this.assertAccountAccessTokenLease(accountLease);
    const identityGeneration = this.refreshIdentityGeneration;
    try {
      if (canonicalizeServerCapabilityUrl(accountLease.serverUrl) !== accountLease.serverUrl) {
        throw accessTokenUnavailable();
      }
    } catch {
      throw accessTokenUnavailable();
    }
    const api = this.deps.api
      .forServer(accountLease.serverUrl)
      .withRequestGuard(() => {
        if (identityGeneration !== this.refreshIdentityGeneration) throw accessTokenUnavailable();
        if (callerSessionLease) this.assertAccessTokenLeases(callerSessionLease, accountLease);
        else this.assertAccountAccessTokenLease(accountLease);
      });
    const seed = {
      identityGeneration,
      accountLease,
      api,
    };
    return callerSessionLease ? { ...seed, callerSessionLease } : seed;
  }

  private async readLeasedAuth(
    sessionLease: SessionLease,
    accountLease: AccountLease,
  ): Promise<ActiveAuth> {
    this.assertAccessTokenLeases(sessionLease, accountLease);
    const auth = await this.readAccountLeasedAuth(accountLease);
    this.assertAccessTokenLeases(sessionLease, accountLease);
    if (!auth.sessionBindingId) throw accessTokenUnavailable();
    return auth;
  }

  private async readAccountLeasedAuth(accountLease: AccountLease): Promise<ActiveAuth> {
    this.assertAccountAccessTokenLease(accountLease);
    let auth: ActiveAuth | undefined;
    try {
      auth = await this.deps.session.getActiveAuth();
    } catch {
      this.assertAccountAccessTokenLease(accountLease);
      throw accessTokenUnavailable();
    }
    this.assertAccountAccessTokenLease(accountLease);
    const normalizedAccount = auth?.email.trim().toLowerCase();
    if (
      !auth
      || auth.email !== normalizedAccount
      || accountLease.accountIdentity !== normalizedAccount
    ) {
      throw accessTokenUnavailable();
    }

    this.assertAccountAccessTokenLease(accountLease);
    let currentServerUrl: string | undefined;
    try {
      currentServerUrl = await this.currentServerUrl();
    } catch {
      this.assertAccountAccessTokenLease(accountLease);
      throw accessTokenUnavailable();
    }
    this.assertAccountAccessTokenLease(accountLease);
    if (!currentServerUrl) throw accessTokenUnavailable();
    try {
      const normalizedLeaseServer = canonicalizeServerCapabilityUrl(accountLease.serverUrl);
      const normalizedCurrentServer = canonicalizeServerCapabilityUrl(currentServerUrl);
      if (
        accountLease.serverUrl !== normalizedLeaseServer
        || normalizedCurrentServer !== normalizedLeaseServer
      ) {
        throw accessTokenUnavailable();
      }
    } catch {
      throw accessTokenUnavailable();
    }
    return auth;
  }

  private assertAccessTokenLeases(
    sessionLease: SessionLease,
    accountLease: AccountLease,
  ): void {
    this.assertAccountAccessTokenLease(accountLease);
    try {
      this.deps.sessionGate.assert(sessionLease);
    } catch {
      throw accessTokenUnavailable();
    }
  }

  private assertAccountAccessTokenLease(accountLease: AccountLease): void {
    if (this.serverResetPending || !this.deps.accountGate) throw accessTokenUnavailable();
    try {
      this.deps.accountGate.assert(accountLease);
    } catch {
      throw accessTokenUnavailable();
    }
  }

  private async runRefreshIfNeeded(skewMs: number, seed: RefreshSeed): Promise<void> {
    if (!this.isRefreshCallerCurrent(seed)) return;
    const snapshot = await this.deps.session.getActiveAuthSnapshot();
    if (!this.isRefreshCallerCurrent(seed)) return;
    if (!snapshot) return;
    const auth = snapshot.auth;
    if (seed.accountLease && seed.accountLease.accountIdentity !== auth.email) return;
    if (auth.expiresAt - this.now() > skewMs) return;
    const serverUrl = seed.accountLease?.serverUrl ?? await this.currentServerUrl();
    if (!this.isRefreshCallerCurrent(seed)) return;
    if (!serverUrl) return;
    const api = seed.accountLease ? seed.api : seed.api.forServer(serverUrl);
    const key = this.refreshFlightKey(serverUrl, snapshot.tokenLease);
    const active = this.activeRefresh.get(key);
    if (active) {
      try {
        await active;
      } catch (error) {
        if (!this.isRefreshCallerCurrent(seed)) return;
        throw error;
      }
      if (!this.isRefreshCallerCurrent(seed)) return;
      return this.runRefreshIfNeeded(skewMs, seed);
    }

    const promise = this.performRefresh(snapshot, serverUrl, api);
    this.activeRefresh.set(key, promise);
    try {
      await promise;
    } catch (error) {
      if (!this.isRefreshCallerCurrent(seed)) return;
      throw error;
    } finally {
      if (this.activeRefresh.get(key) === promise) this.activeRefresh.delete(key);
    }
  }

  private async forceRefreshAfterUnauthorized(
    accountLease: AccountLease,
    rejectedAccessToken: string,
  ): Promise<string> {
    const seed = this.createAccountLeasedRefreshSeed(accountLease);
    this.refreshAttempts++;
    try {
      const snapshot = await this.deps.session.getActiveAuthSnapshot();
      const auth = await this.readAccountLeasedAuth(accountLease);
      this.assertAccountAccessTokenLease(accountLease);
      if (!snapshot
          || snapshot.auth.email !== auth.email
          || snapshot.auth.accessToken !== auth.accessToken
          || snapshot.auth.refreshToken !== auth.refreshToken) throw accessTokenUnavailable();
      if (auth.accessToken !== rejectedAccessToken) return this.requireUsableAccessToken(auth);
      const key = this.refreshFlightKey(accountLease.serverUrl, snapshot.tokenLease);
      const active = this.activeRefresh.get(key);
      if (active) {
        try {
          await active;
        } catch (error) {
          if (!this.isRefreshPersistenceCurrent(seed)) throw accessTokenUnavailable();
          throw error;
        }
      } else {
        const promise = this.performRefresh(snapshot, accountLease.serverUrl, seed.api);
        this.activeRefresh.set(key, promise);
        try {
          await promise;
        } catch (error) {
          if (!this.isRefreshPersistenceCurrent(seed)) throw accessTokenUnavailable();
          throw error;
        } finally {
          if (this.activeRefresh.get(key) === promise) this.activeRefresh.delete(key);
        }
      }
      const current = await this.readAccountLeasedAuth(accountLease);
      this.assertAccountAccessTokenLease(accountLease);
      return this.requireUsableAccessToken(current);
    } finally {
      this.refreshAttempts--;
      if (this.refreshAttempts === 0) {
        for (const resolve of this.refreshIdleResolvers.splice(0)) resolve();
      }
    }
  }

  private refreshFlightKey(serverUrl: string, lease: AuthTokenLease): string {
    return `${serverUrl}\n${lease.credentialId}\n${lease.tokenRevision}`;
  }

  private async performRefresh(
    snapshot: ActiveAuthSnapshot,
    serverUrl: string,
    api: ApiClient,
  ): Promise<void> {
    const permit = await this.deps.session.prepareTokenRefresh({
      ...snapshot.tokenLease,
      serverUrl,
    });
    if (!permit) return;
    let refreshed;
    let grantStarted = false;
    try {
      refreshed = parseRefreshTokenSuccess(await api.refresh(snapshot.auth.refreshToken, {
        onGrantStarted: () => { grantStarted = true; },
      }));
    } catch (error) {
      // Once the grant is dispatched, any missing or rejected response is outcome-unknown for a
      // rotating refresh token. Retire only this exact credential instead of ever replaying RT1.
      if (!grantStarted) {
        await this.deps.session.cancelUndispatchedTokenRefresh(permit);
        if (error instanceof AppError && error.code === 'session_expired') return;
        throw error;
      }
      await this.logoutAfterRejectedRefresh(permit);
      if (isInvalidGrant(error)) return;
      throw error;
    }
    try {
      await this.runSessionMutation(async () => {
        await this.deps.session.commitTokenRefresh(permit, {
          accessToken: refreshed.access_token,
          refreshToken: refreshed.refresh_token,
          expiresAt: tokenExpiresAt(refreshed.expires_in, this.now()),
        });
      });
    } catch (error) {
      await this.logoutAfterRejectedRefresh(permit);
      throw error;
    }
  }

  private requireUsableAccessToken(auth: ActiveAuth): string {
    if (auth.expiresAt <= this.now() || !auth.accessToken.trim()) throw accessTokenUnavailable();
    return auth.accessToken;
  }

  private captureRefreshSeed(): RefreshSeed | undefined {
    const identityGeneration = this.refreshIdentityGeneration;
    if (!this.deps.accountGate) {
      const api = this.deps.api.withRequestGuard(() => {
        if (this.serverResetPending || identityGeneration !== this.refreshIdentityGeneration) {
          throw accessTokenUnavailable();
        }
      });
      return { identityGeneration, api };
    }
    try {
      const accountLease = this.deps.accountGate.capture();
      const api = this.deps.api
        .forServer(accountLease.serverUrl)
        .withRequestGuard(() => {
          if (this.serverResetPending || identityGeneration !== this.refreshIdentityGeneration) {
            throw accessTokenUnavailable();
          }
          this.assertAccountLease(accountLease);
        });
      return { identityGeneration, accountLease, api };
    } catch (error) {
      if (error instanceof AppError && error.code === 'session_expired') return undefined;
      throw error;
    }
  }

  private isRefreshPersistenceCurrent(seed: RefreshSeed): boolean {
    try {
      if (this.serverResetPending) return false;
      if (seed.identityGeneration !== this.refreshIdentityGeneration) return false;
      if (!seed.accountLease) return true;
      this.deps.accountGate?.assert(seed.accountLease);
      return true;
    } catch {
      return false;
    }
  }

  private isRefreshCallerCurrent(seed: RefreshSeed): boolean {
    if (!this.isRefreshPersistenceCurrent(seed)) return false;
    try {
      if (seed.callerSessionLease) this.deps.sessionGate.assert(seed.callerSessionLease);
      return true;
    } catch {
      return false;
    }
  }

  private async logoutAfterRejectedRefresh(expected: RefreshTokenPermit): Promise<void> {
    if (this.serverResetPending) return;
    if (!await this.deps.session.isTokenLeaseCurrent(expected)) return;
    await this.runSessionTransition('removeAccount', true, async () => {
      const removed = await this.runSessionMutation(() => (
        this.deps.session.removeAccountIfTokenCurrent(expected)
      ));
      if (removed === 'active') await this.deps.onIdentityChanged?.();
    });
  }

  private async logoutAfterRepeatedUnauthorized(
    accountLease: AccountLease,
    rejectedAccessToken: string,
  ): Promise<void> {
    let auth: ActiveAuth;
    try {
      auth = await this.readAccountLeasedAuth(accountLease);
      this.assertAccountAccessTokenLease(accountLease);
    } catch {
      return;
    }
    if (auth.accessToken !== rejectedAccessToken) return;
    const expected = {
      email: auth.email,
      accessToken: auth.accessToken,
      refreshToken: auth.refreshToken,
    } as const;
    this.cancelActivationAttempts();
    await this.runSessionTransition('logout', true, async () => {
      await this.clearStoredPendingLogin();
      const removed = await this.runSessionMutation(() => (
        this.deps.session.logoutIfCurrent(expected)
      ));
      if (!removed) throw accessTokenUnavailable();
      try {
        await this.deps.onIdentityChanged?.();
      } catch {
        // The account and session credentials are already gone; cache cleanup remains best effort.
      }
    });
  }

  private waitForRefreshIdle(): Promise<void> {
    if (this.refreshAttempts === 0) return Promise.resolve();
    return new Promise((resolve) => this.refreshIdleResolvers.push(resolve));
  }

  private async waitForTransitionIdle(): Promise<void> {
    while (true) {
      const observed = this.transitionTail;
      await observed;
      if (observed === this.transitionTail) return;
    }
  }

  private async clearStoredPendingLogin(): Promise<void> {
    const store = this.deps.pendingLoginStore;
    if (!store) return;
    const localOwner = this.pendingLogin?.continuation?.owner;
    if (localOwner) {
      await store.clearAttempt(localOwner);
      return;
    }
    const stored = await store.read();
    if (stored) await store.clearAttempt(stored.owner);
  }

  private async restorePendingLogin(
    stored: ActivePendingLoginContinuation,
  ): Promise<PendingLogin | undefined> {
    if (!stored.data || stored.memoryOnly) return undefined;
    const configured = await this.currentServerUrl();
    if (!configured || canonicalAccountPasskeyServer(configured) !== stored.owner.serverUrl) {
      await this.deps.pendingLoginStore?.clear(stored.owner);
      return undefined;
    }
    const serverLease = this.deps.accountGate?.captureServer();
    if (serverLease) {
      this.deps.accountGate?.assertServer(serverLease);
      if (serverLease.serverUrl !== stored.owner.serverUrl) {
        await this.deps.pendingLoginStore?.clear(stored.owner);
        return undefined;
      }
    }
    let ssoAuthority: { readonly assertCurrent: () => void } | undefined;
    if (stored.data.sso) {
      const authorize = this.deps.authorizeSsoContinuation;
      if (!authorize) {
        await this.deps.pendingLoginStore?.clear(stored.owner);
        throw new AppError('session_expired', 'The SSO continuation authority is unavailable.');
      }
      try {
        ssoAuthority = await authorize({
          serverUrl: stored.owner.serverUrl,
          identityUrl: stored.data.sso.identityUrl,
          redirectUri: stored.data.sso.redirectUri,
          emailTwoFactorMode: stored.data.sso.emailTwoFactorMode,
        });
        if (typeof ssoAuthority.assertCurrent !== 'function') throw new TypeError('invalid authority');
        ssoAuthority.assertCurrent();
      } catch {
        await this.deps.pendingLoginStore?.clear(stored.owner);
        throw new AppError(
          'session_expired',
          'The SSO server environment changed. Start sign-in again.',
        );
      }
    }
    const attempt = ++this.activationAttempt;
    const assertCurrent = (): void => {
      this.assertActivationAttempt(attempt);
      if (serverLease) this.deps.accountGate?.assertServer(serverLease);
      ssoAuthority?.assertCurrent();
    };
    const api = this.deps.api
      .forServer(stored.owner.serverUrl)
      .withRequestGuard(assertCurrent);
    let fido2: PendingFido2Challenge | undefined;
    if (stored.data.fido2) {
      try {
        const connector = new URL(stored.data.fido2.connectorUrl);
        const request = parseFido2TwoFactorRequest(
          JSON.parse(stored.data.fido2.connectorData) as unknown,
          { origin: connector.origin, rpId: connector.hostname },
        );
        fido2 = { request, connectorUrl: stored.data.fido2.connectorUrl };
      } catch {
        await this.deps.pendingLoginStore?.clear(stored.owner);
        return undefined;
      }
    }
    const rememberDeviceToken = stored.data.stage === 'newDeviceVerification'
      ? await this.deps.session.getRememberDeviceToken(stored.owner.serverUrl, stored.owner.email)
      : undefined;
    assertCurrent();
    const pendingBase: PendingLogin = {
      attempt,
      api,
      serverUrl: stored.owner.serverUrl,
      email: stored.data.email,
      kdf: stored.data.kdf,
      ...(stored.data.masterPasswordHash
        ? { masterPasswordHash: stored.data.masterPasswordHash }
        : {}),
      ...(stored.data.sso ? { sso: stored.data.sso } : {}),
      ...(ssoAuthority ? { assertSsoAuthorizationCurrent: ssoAuthority.assertCurrent } : {}),
      ...(stored.data.duo ? { duo: stored.data.duo } : {}),
      ...(stored.data.stage === 'newDeviceVerification'
        ? { newDeviceVerification: { expiresAt: stored.expiresAt } }
        : { twoFactorProviders: stored.data.providers }),
      ...(stored.data.twoFactorToken ? { twoFactorToken: stored.data.twoFactorToken } : {}),
      ...(fido2 ? { fido2 } : {}),
      ...(stored.data.passwordEvidence ? { passwordEvidence: stored.data.passwordEvidence } : {}),
      ...(rememberDeviceToken ? { rememberDeviceToken } : {}),
      continuationId: stored.owner.attemptId,
      continuationExpiresAt: stored.expiresAt,
      continuation: {
        owner: stored.owner,
        createdAt: stored.createdAt,
        expiresAt: stored.expiresAt,
        claimed: false,
        memoryOnly: false,
      },
    };
    const pending = applyPasswordLoginSecurityFacts(
      pendingBase,
      stored.data.forcePasswordReset === true,
      stored.data.masterPasswordPolicy,
    );
    this.pendingLogin = pending;
    this.activeTwoFactorSubmission = undefined;
    this.activeNewDeviceVerificationSubmission = undefined;
    this.activeDeviceLoginSubmission = undefined;
    this.activationServerUrl = stored.owner.serverUrl;
    this.activationApi = api;
    return pending;
  }

  private projectPendingLogin(pending: PendingLogin): PendingLoginPublicStatus {
    const expiresAt = pending.continuation?.expiresAt
      ?? pending.continuationExpiresAt
      ?? pending.newDeviceVerification?.expiresAt;
    if (!expiresAt || !pending.continuationId || this.now() >= expiresAt) {
      return Object.freeze({ status: 'none' });
    }
    if (pending.newDeviceVerification) {
      return Object.freeze({
        status: 'newDeviceVerification',
        attemptId: pending.attempt,
        continuationId: pending.continuationId,
        expiresAt,
      });
    }
    const providers = pending.twoFactorProviders;
    if (!providers?.length) return Object.freeze({ status: 'none' });
    return Object.freeze({
      status: 'twoFactor',
      attemptId: pending.attempt,
      continuationId: pending.continuationId,
      providers: Object.freeze([...providers]),
      ...(pending.fido2
        ? { fido2: Object.freeze({ owner: passwordInteractiveOwner(pending) }) }
        : {}),
      expiresAt,
    });
  }

  private continuationData(
    pending: PendingLogin,
    stage: PendingLoginContinuationData['stage'],
    providers: readonly number[],
  ): PendingLoginContinuationData {
    if (Boolean(pending.masterPasswordHash) === Boolean(pending.sso)) {
      throw new AppError('session_expired', 'The pending login grant is invalid.');
    }
    return Object.freeze({
      stage,
      email: pending.email,
      kdf: pending.kdf,
      providers: Object.freeze([...providers]),
      ...(pending.masterPasswordHash ? { masterPasswordHash: pending.masterPasswordHash } : {}),
      ...(pending.sso ? { sso: pending.sso } : {}),
      ...(stage === 'twoFactor' && pending.twoFactorToken
        ? { twoFactorToken: pending.twoFactorToken }
        : {}),
      ...(stage === 'twoFactor' && pending.fido2
        ? {
            fido2: Object.freeze({
              connectorData: pending.fido2.request.connectorData,
              connectorUrl: pending.fido2.connectorUrl,
            }),
          }
        : {}),
      ...(stage === 'twoFactor' && pending.duo ? { duo: pending.duo } : {}),
      ...(pending.passwordEvidence ? { passwordEvidence: pending.passwordEvidence } : {}),
      ...(pending.masterPasswordPolicy
        ? { masterPasswordPolicy: pending.masterPasswordPolicy }
        : {}),
      ...(pending.forcePasswordReset ? { forcePasswordReset: true as const } : {}),
    });
  }

  private async persistPendingLogin(
    pending: PendingLogin,
    stage: PendingLoginContinuationData['stage'],
    providers: readonly number[],
  ): Promise<PendingLogin> {
    const store = this.deps.pendingLoginStore;
    const { continuation: previous, ...withoutContinuation } = pending;
    const fallbackExpiresAt = safePendingLoginDeadline(this.now());
    const publicPending: PendingLogin = {
      ...withoutContinuation,
      ...(stage === 'twoFactor' ? { twoFactorProviders: Object.freeze([...providers]) } : {}),
      continuationExpiresAt: previous?.expiresAt
        ?? pending.continuationExpiresAt
        ?? pending.newDeviceVerification?.expiresAt
        ?? fallbackExpiresAt,
    };
    // A following stage may need an OTP/assertion that is intentionally memory-only. Redact the
    // resumable data but keep an attempt-bound marker so a crash during its next grant is terminal.
    if (pending.newDeviceOtp || pending.submittedTwoFactor) {
      if (!store || !previous) return publicPending;
      const active = await store.redact(previous.owner);
      if (!active) {
        throw new AppError('session_expired', 'The pending login continuation changed. Sign in again.');
      }
      try {
        this.assertPendingLoginCurrent(pending);
      } catch (error) {
        await store.clearAttempt(active.owner).catch(() => false);
        throw error;
      }
      return {
        ...publicPending,
        continuationId: active.owner.attemptId,
        continuationExpiresAt: active.expiresAt,
        continuation: {
          owner: active.owner,
          createdAt: active.createdAt,
          expiresAt: active.expiresAt,
          claimed: false,
          memoryOnly: true,
        },
      };
    }
    if (!store) return publicPending;
    const data = this.continuationData(publicPending, stage, providers);
    const active = previous?.claimed
      ? await store.release(previous.owner, data)
      : previous
        ? undefined
        : await store.write(pending.serverUrl, data);
    if (!active) {
      if (previous) await store.clear(previous.owner).catch(() => false);
      throw new AppError('session_expired', 'The pending login continuation changed. Sign in again.');
    }
    try {
      this.assertPendingLoginCurrent(pending);
    } catch (error) {
      await store.clearAttempt(active.owner).catch(() => false);
      throw error;
    }
    return {
      ...publicPending,
      continuationId: active.owner.attemptId,
      continuationExpiresAt: active.expiresAt,
      continuation: {
        owner: active.owner,
        createdAt: active.createdAt,
        expiresAt: active.expiresAt,
        claimed: false,
        memoryOnly: false,
      },
      ...(stage === 'newDeviceVerification'
        ? { newDeviceVerification: { expiresAt: active.expiresAt } }
        : {}),
    };
  }

  private async claimPendingLogin(pending: PendingLogin): Promise<PendingLogin> {
    const store = this.deps.pendingLoginStore;
    const continuation = pending.continuation;
    if (!store || !continuation) return pending;
    if (continuation.claimed) {
      throw new AppError('session_expired', 'The pending login continuation is already claimed.');
    }
    const claimed = await store.claim(continuation.owner);
    if (!claimed) {
      throw new AppError('session_expired', 'The pending login continuation changed. Sign in again.');
    }
    try {
      this.assertActivationAttempt(pending.attempt);
    } catch (error) {
      await store.clearAttempt(claimed.owner).catch(() => false);
      throw error;
    }
    return {
      ...pending,
      continuation: {
        owner: claimed.owner,
        createdAt: claimed.createdAt,
        expiresAt: claimed.expiresAt,
        claimed: true,
        ...(continuation.memoryOnly ? { memoryOnly: true } : {}),
      },
    };
  }

  private async releasePendingLogin(pending: PendingLogin): Promise<PendingLogin> {
    const store = this.deps.pendingLoginStore;
    const continuation = pending.continuation;
    if (!store || !continuation?.claimed) return pending;
    const stage = pending.newDeviceVerification ? 'newDeviceVerification' : 'twoFactor';
    const providers = stage === 'twoFactor' ? pending.twoFactorProviders ?? [] : [];
    const active = continuation.memoryOnly
      ? await store.releaseMarker(continuation.owner)
      : await store.release(
          continuation.owner,
          this.continuationData(pending, stage, providers),
        );
    if (!active) {
      throw new AppError('session_expired', 'The pending login continuation changed. Sign in again.');
    }
    try {
      this.assertActivationAttempt(pending.attempt);
    } catch (error) {
      await store.clearAttempt(active.owner).catch(() => false);
      throw error;
    }
    return {
      ...pending,
      continuationId: active.owner.attemptId,
      continuationExpiresAt: active.expiresAt,
      continuation: {
        owner: active.owner,
        createdAt: active.createdAt,
        expiresAt: active.expiresAt,
        claimed: false,
        ...(continuation.memoryOnly ? { memoryOnly: true } : {}),
      },
    };
  }

  private async markPendingLoginOutcomeUnknown(pending: PendingLogin): Promise<void> {
    const continuation = pending.continuation;
    if (continuation && this.deps.pendingLoginStore) {
      await this.deps.pendingLoginStore.markOutcomeUnknown(continuation.owner).catch(() => undefined);
    }
    if (this.pendingLogin?.attempt === pending.attempt) this.pendingLogin = undefined;
  }

  private async clearPendingLoginOwner(pending: PendingLogin): Promise<void> {
    const continuation = pending.continuation;
    if (continuation && this.deps.pendingLoginStore) {
      try {
        await this.deps.pendingLoginStore.clearAttempt(continuation.owner);
      } catch {
        // Authentication already committed: replace any surviving credential-bearing envelope
        // with a secret-free terminal marker and let its armed expiry alarm retry final deletion.
        await this.deps.pendingLoginStore.markOutcomeUnknown(continuation.owner).catch(() => undefined);
      }
    }
  }

  private assertPendingLoginContinuationId(
    pending: PendingLogin,
    continuationId: string | undefined,
  ): void {
    if (pending.continuationId === undefined) {
      if (continuationId === undefined) return;
    } else if (continuationId === pending.continuationId) {
      return;
    }
    throw new AppError('session_expired', 'The pending login continuation changed. Sign in again.');
  }

  private assertNoPendingGrantInFlight(): void {
    if (this.activeTwoFactorSubmission || this.activeNewDeviceVerificationSubmission) {
      throw new AppError(
        'outcome_unknown',
        'The previous sign-in is still being verified. Check its result before starting again.',
      );
    }
  }

  private assertPendingLoginNotExpired(pending: PendingLogin): void {
    const expiresAt = pending.continuation?.expiresAt ?? pending.continuationExpiresAt;
    if (expiresAt !== undefined && this.now() >= expiresAt) {
      this.clearLocalPendingLoginOwnerSoon();
      this.cancelActivationAttempts();
      throw new AppError('session_expired', 'Your sign-in session expired. Re-enter your password.');
    }
  }

  private beginActivationAttempt(): number {
    const serverLease = this.deps.accountGate?.captureServer();
    this.closePendingFidoConnectorSoon();
    this.clearLocalPendingLoginOwnerSoon();
    this.pendingLogin = undefined;
    this.pendingRegistration = undefined;
    this.activeTwoFactorSubmission = undefined;
    this.activeNewDeviceVerificationSubmission = undefined;
    this.activeDeviceLoginSubmission = undefined;
    const attempt = ++this.activationAttempt;
    if (serverLease) {
      const fixedApi = this.deps.api.forServer(serverLease.serverUrl);
      this.activationServerUrl = serverLease.serverUrl;
      this.activationApi = fixedApi.withRequestGuard(() => {
        this.assertActivationAttempt(attempt);
        this.deps.accountGate?.assertServer(serverLease);
      });
    } else {
      this.activationServerUrl = undefined;
      this.activationApi = undefined;
    }
    return attempt;
  }

  private cancelActivationAttempts(): void {
    this.closePendingFidoConnectorSoon();
    this.clearLocalPendingLoginOwnerSoon();
    this.pendingLogin = undefined;
    this.pendingRegistration = undefined;
    this.activeTwoFactorSubmission = undefined;
    this.activeNewDeviceVerificationSubmission = undefined;
    this.activeDeviceLoginSubmission = undefined;
    this.activationAttempt++;
    this.activationServerUrl = undefined;
    this.activationApi = undefined;
  }

  private clearLocalPendingLoginOwnerSoon(): void {
    const owner = this.pendingLogin?.continuation?.owner;
    if (!owner || !this.deps.pendingLoginStore) return;
    void this.deps.pendingLoginStore.clearAttempt(owner).catch(() => false);
  }

  private closePendingFidoConnectorSoon(): void {
    const connector = this.pendingLogin?.fido2;
    const close = this.deps.closeInteractiveTwoFactorConnector;
    if (!close
        || connector?.tabId === undefined
        || !connector.documentId
        || !connector.expectedUrl) return;
    const document = Object.freeze({
      tabId: connector.tabId,
      documentId: connector.documentId,
      url: connector.expectedUrl,
    });
    try {
      void Promise.resolve(close(document)).catch(() => undefined);
    } catch {
      // Authentication cancellation is authoritative even if a stale tab cannot be closed.
    }
  }

  private assertActivationAttempt(attempt: number): void {
    if (attempt !== this.activationAttempt) {
      throw new AppError('session_expired', 'A newer authentication action replaced this one.');
    }
  }

  private assertDeviceLoginRequestCurrent(
    state: DeviceLoginBoundState,
    attempt: number,
  ): void {
    this.assertActivationAttempt(attempt);
    if (state.phase !== 'bound' || isDeviceLoginStateExpired(state, this.now())) {
      throw new AppError('session_expired', 'The device login request expired. Start a new request.');
    }
  }

  private requireNewDeviceVerificationPending(attemptId: number): PendingLogin {
    if (!Number.isSafeInteger(attemptId) || attemptId <= 0) {
      throw new AppError('denied', 'Invalid device verification attempt.');
    }
    const pending = this.pendingLogin;
    if (
      !pending?.newDeviceVerification
      || pending.attempt !== attemptId
      || pending.serverUrl !== this.activationServerUrl
    ) {
      throw new AppError('session_expired', 'The device verification request is no longer available.');
    }
    this.assertActivationAttempt(attemptId);
    if (this.now() >= pending.newDeviceVerification.expiresAt) {
      this.cancelActivationAttempts();
      throw new AppError('session_expired', 'The device verification request expired. Sign in again.');
    }
    return pending;
  }

  private requirePendingRegistration(attemptId: number): PendingRegistration {
    if (!Number.isSafeInteger(attemptId) || attemptId <= 0) {
      throw new AppError('denied', 'Invalid registration attempt.');
    }
    const pending = this.pendingRegistration;
    if (!pending
        || pending.attempt !== attemptId
        || pending.serverUrl !== this.activationServerUrl) {
      throw new AppError('session_expired', 'The registration request is no longer available.');
    }
    this.assertActivationAttempt(attemptId);
    if (this.now() >= pending.expiresAt) {
      this.cancelActivationAttempts();
      throw new AppError('session_expired', 'The registration request expired. Start again.');
    }
    return pending;
  }

  private async prepareActivationAttempt(
    attempt: number,
  ): Promise<{ api: ApiClient; serverUrl: string }> {
    this.assertActivationAttempt(attempt);
    if (this.activationApi && this.activationServerUrl) {
      return { api: this.activationApi, serverUrl: this.activationServerUrl };
    }

    const serverUrl = await this.currentServerUrl();
    this.assertActivationAttempt(attempt);
    if (!serverUrl) throw new Error('serverUrl is not configured');
    const api = this.deps.api
      .forServer(serverUrl)
      .withRequestGuard(() => this.assertActivationAttempt(attempt));
    this.activationServerUrl = serverUrl;
    this.activationApi = api;
    return { api, serverUrl };
  }

  private async runAccountOperation<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.accountOperationTail.then(operation, operation);
    this.accountOperationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  private async runPinUnlockOperation(operation: () => Promise<void>): Promise<void> {
    const run = this.pinUnlockTail.then(operation, operation);
    this.pinUnlockTail = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Serialize every local auth/session commit; transition invalidation remains immediate. */
  private async runSessionMutation<T>(mutation: () => Promise<T>): Promise<T> {
    const run = this.sessionMutationTail.then(mutation, mutation);
    this.sessionMutationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  private capturePinPolicyLease(): PolicyLease | undefined {
    const gate = this.deps.enterprisePolicyGate;
    if (!gate) return undefined;
    const lease = gate.capture();
    this.assertPinPolicyAllowed(lease);
    return lease;
  }

  private assertPinPolicyAllowed(
    lease: PolicyLease | undefined,
  ): EffectiveEnterprisePolicySnapshot | undefined {
    const gate = this.deps.enterprisePolicyGate;
    if (!gate || !lease) return undefined;
    const snapshot = gate.assert(lease);
    if (!enterprisePolicyAllows(snapshot, 'unlockWithPin')) {
      throw new AppError('denied', 'PIN unlock is disabled by your organization.');
    }
    return snapshot;
  }

  private async runSessionTransition<T>(
    reason: SessionTransitionReason,
    identityChanged: boolean,
    action: () => Promise<T>,
    options: {
      terminal?: boolean;
      passwordChangeRecovery?: boolean;
      settleOnFailure?: boolean;
      owner?: InteractiveTwoFactorOwner;
    } = {},
  ): Promise<T> {
    if (this.terminalSessionBlocked && !options.terminal) throw rotationOutcomeUnknown();
    if (this.passwordChangeSessionBlocked && !options.passwordChangeRecovery) {
      throw passwordChangeOutcomeUnknown();
    }
    if (invalidatesRefreshIdentity(reason)) this.refreshIdentityGeneration++;
    const transitionId = ++this.transitionSequence;
    const startEvent = {
      phase: 'start', transitionId, reason, identityChanged,
      ...(options.owner ? { owner: options.owner } : {}),
    } as const;
    let immediateStart: Promise<void>;
    try {
      immediateStart = Promise.resolve(this.deps.onSessionTransition?.(startEvent));
    } catch (error) {
      immediateStart = Promise.reject(error);
    }
    const previous = this.transitionTail;
    const execute = async (): Promise<T> => {
      let result: T;
      try {
        // Account/server lifecycle starts are invoked only after the previous lifecycle settled.
        // When the queue is idle this function is called synchronously, so capture closes at once.
        const serializedStart = Promise.resolve(
          this.deps.onSerializedSessionTransition?.(startEvent),
        );
        await Promise.all([immediateStart, serializedStart]);
        result = await action();
      } catch (error) {
        if (options.settleOnFailure !== false) {
          try {
            await this.notifyTransitionSettled({
              transitionId, reason, identityChanged, succeeded: false,
              ...(options.owner ? { owner: options.owner } : {}),
            });
          } catch {
            // Preserve the transition's primary error. A failed settled hook remains fail-closed.
          }
        }
        throw error;
      }
      await this.notifyTransitionSettled({
        transitionId, reason, identityChanged, succeeded: true,
        ...(options.owner ? { owner: options.owner } : {}),
      });
      return result;
    };
    this.queuedTransitions++;
    const execution = this.queuedTransitions === 1
      ? execute()
      : previous.then(execute, execute);
    const tracked = execution.finally(() => {
      this.queuedTransitions--;
    });
    this.transitionTail = tracked.then(() => undefined, () => undefined);
    return execution;
  }

  private async notifyTransitionSettled(input: {
    transitionId: number;
    reason: SessionTransitionReason;
    identityChanged: boolean;
    succeeded: boolean;
    owner?: InteractiveTwoFactorOwner;
  }): Promise<void> {
    if (!this.deps.onSessionTransition && !this.deps.onSerializedSessionTransition) return;
    const state = await this.deps.session.getState();
    const event = { phase: 'settled', state, ...input } as const;
    await this.deps.onSerializedSessionTransition?.(event);
    await this.deps.onSessionTransition?.(event);
  }

  private async finishDeviceLogin(input: {
    data: LoginSuccessResponse;
    state: DeviceLoginBoundState;
    userKey: SymmetricKey;
    serverUrl: string;
    kdf: KdfConfig;
    attempt: number;
    security: PasswordLoginSecurityFacts;
    assertCurrent: () => void;
    assertTransitionOwnerCurrent?: () => void;
    transitionOwner?: InteractiveTwoFactorOwner;
  }): Promise<DeviceLoginAuthResult> {
    input.assertCurrent();
    const validated = validateDeviceLoginSuccess(
      parseLoginTokenSuccess(input.data),
      input.kdf,
      this.now(),
    );
    const security = mergePasswordLoginSecurityFacts(
      input.security,
      validated.forcePasswordReset === true,
      validated.masterPasswordPolicy,
    );
    const requirement = security.forcePasswordReset
      ? passwordChangeRequirement('adminForcePasswordReset', security.masterPasswordPolicy)
      : undefined;
    if (requirement) {
      const persisted: SaveRestrictedAuthenticatedInput = {
        email: input.state.email,
        accessToken: validated.accessToken,
        refreshToken: validated.refreshToken,
        expiresAt: validated.expiresAt,
        protectedKey: validated.protectedKey,
        ...validated.kdf,
        ...(validated.encPrivateKey ? { encPrivateKey: validated.encPrivateKey } : {}),
        restriction: requirement,
      };
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      input.assertCurrent();
      await this.runSessionTransition('login', input.state.email !== activeBefore, async () => {
        input.assertCurrent();
        if (input.state.email !== activeBefore) await this.deps.onIdentityChanged?.();
        input.assertCurrent();
        await this.commitRestrictedLogin(input.attempt, persisted, input.assertCurrent);
      }, input.transitionOwner ? { owner: input.transitionOwner } : {});
      this.pendingLogin = undefined;
      input.assertTransitionOwnerCurrent?.();
      if (validated.rememberToken) {
        try {
          await this.deps.session.saveRememberDeviceToken(
            input.serverUrl,
            input.state.email,
            validated.rememberToken,
          );
        } catch {
          // Remember-token capture cannot alter an already fenced restricted session.
        }
      }
      return { kind: 'restricted', requirement };
    }
    input.assertCurrent();
    const privateKey = validated.encPrivateKey
      ? await decryptPrivateKey(validated.encPrivateKey, input.userKey)
      : undefined;
    input.assertCurrent();

    const saveInput = {
      email: input.state.email,
      accessToken: validated.accessToken,
      refreshToken: validated.refreshToken,
      expiresAt: validated.expiresAt,
      protectedKey: validated.protectedKey,
      ...validated.kdf,
      userKey: input.userKey,
      ...(validated.encPrivateKey ? { encPrivateKey: validated.encPrivateKey } : {}),
    };
    const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
    input.assertCurrent();
    await this.runSessionTransition('login', input.state.email !== activeBefore, async () => {
      input.assertCurrent();
      if (input.state.email !== activeBefore) await this.deps.onIdentityChanged?.();
      input.assertCurrent();
      await this.commitUnlockedLogin({
        attempt: input.attempt,
        saveInput: privateKey ? { ...saveInput, privateKey } : saveInput,
        failureMessage: 'Device login session commit was not authoritative.',
        finalValidate: input.assertCurrent,
      });
    }, input.transitionOwner ? { owner: input.transitionOwner } : {});

    this.pendingLogin = undefined;
    input.assertTransitionOwnerCurrent?.();
    if (validated.rememberToken) {
      try {
        await this.deps.session.saveRememberDeviceToken(
          input.serverUrl,
          input.state.email,
          validated.rememberToken,
        );
      } catch {
        /* best-effort token capture; never fail an established device login over it */
      }
    }
    return { kind: 'unlocked' };
  }

  private async finishPasswordLogin(input: {
    result: PasswordLoginResult;
    pending: PendingLogin;
  }): Promise<AuthResult> {
    this.assertPendingLoginCurrent(input.pending);
    input = {
      result: input.result,
      pending: this.assessPasswordLoginPolicy(input.pending, input.result),
    };
    if (input.result.kind === 'ssoRequired') {
      await this.clearPendingLoginOwner(input.pending);
      this.pendingLogin = undefined;
      return Object.freeze({
        kind: 'ssoRequired',
        email: input.pending.email,
        organizationIdentifier: input.result.organizationIdentifier,
      });
    }
    if (input.result.kind === 'newDeviceVerification') {
      const now = this.now();
      const newDeadline = now + NEW_DEVICE_VERIFICATION_TTL_MS;
      if (!Number.isSafeInteger(newDeadline)) {
        throw new AppError('session_expired', 'The device verification deadline is invalid.');
      }
      const existingDeadline = input.pending.continuation?.expiresAt
        ?? input.pending.continuationExpiresAt;
      const expiresAt = Math.min(
        input.pending.newDeviceVerification?.expiresAt ?? newDeadline,
        existingDeadline ?? newDeadline,
      );
      const {
        fido2: _previousFido2,
        twoFactorToken: _previousToken,
        newDeviceOtp: _previousOtp,
        newDeviceVerification: _previousVerification,
        ...pendingBase
      } = input.pending;
      const nextPending = await this.persistPendingLogin({
        ...pendingBase,
        newDeviceVerification: { expiresAt },
      }, 'newDeviceVerification', []);
      this.pendingLogin = nextPending;
      return {
        kind: 'newDeviceVerification',
        attemptId: input.pending.attempt,
        ...(nextPending.continuationId ? { continuationId: nextPending.continuationId } : {}),
        expiresAt: nextPending.continuation?.expiresAt
          ?? nextPending.continuationExpiresAt
          ?? expiresAt,
      };
    }
    if (input.result.kind === 'twoFactor') {
      const fido2 = input.result.providers.includes(7)
        ? this.parseFido2Challenge(input.pending, input.result.providerMetadata)
        : undefined;
      const duo = parseDuoSeeds(input.result.providerMetadata, input.result.providers);
      // Interactive providers remain visible only when their modern metadata was retained safely.
      const providers = input.result.providers.filter((provider) => (
        (provider !== 7 || fido2 !== undefined)
        && (provider !== 2 && provider !== 6
          || duo.some((entry) => entry.provider === provider))
      ));
      const {
        fido2: _previousFido2,
        duo: _previousDuo,
        twoFactorToken: _previousToken,
        newDeviceVerification: _previousVerification,
        ...pendingBase
      } = input.pending;
      const nextPending = await this.persistPendingLogin({
        ...pendingBase,
        ...(fido2 ? { fido2 } : {}),
        ...(duo.length ? { duo } : {}),
        ...(input.result.token ? { twoFactorToken: input.result.token } : {}),
      }, 'twoFactor', providers);
      this.pendingLogin = nextPending;
      return {
        kind: 'twoFactor',
        providers,
        ...(fido2 ? { fido2: Object.freeze({ owner: passwordInteractiveOwner(nextPending) }) } : {}),
        ...(input.result.token ? { token: input.result.token } : {}),
        ...(nextPending.continuationId ? { continuationId: nextPending.continuationId } : {}),
      };
    }
    const data = parseLoginTokenSuccess(input.result.data);
    if (data.MasterKeySalt !== undefined && data.MasterKeySalt !== input.pending.email) {
      throw new AppError('denied', 'The SSO master-key salt does not match the authenticated account.');
    }
    if (
      data.Kdf !== undefined
      || data.KdfIterations !== undefined
      || data.KdfMemory !== undefined
      || data.KdfParallelism !== undefined
    ) {
      const pending = input.pending.kdf;
      const responseKdf = parseKdfConfig({
        kdf: data.Kdf ?? pending.kdf,
        kdfIterations: data.KdfIterations ?? pending.kdfIterations,
        kdfMemory: data.KdfMemory ?? (pending.kdf === 1 ? pending.kdfMemory : undefined),
        kdfParallelism: data.KdfParallelism ?? (pending.kdf === 1 ? pending.kdfParallelism : undefined),
      });
      if (!sameKdfConfig(responseKdf, pending)) {
        throw new Error('Server changed KDF settings during login; refusing to continue.');
      }
    }
    const securedPending = applyPasswordLoginSecurityFacts(
      input.pending,
      data.forcePasswordReset === true,
      data.masterPasswordPolicy,
    );
    const requirement = securedPending.passwordChangeRequirement;
    if (requirement) {
      const persisted: SaveRestrictedAuthenticatedInput = {
        email: input.pending.email,
        ...(data.MasterKeySalt ? { masterKeySalt: data.MasterKeySalt } : {}),
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: tokenExpiresAt(data.expires_in, this.now()),
        protectedKey: data.Key,
        ...input.pending.kdf,
        ...(data.PrivateKey ? { encPrivateKey: data.PrivateKey } : {}),
        restriction: requirement,
      };
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      this.assertPendingLoginCurrent(input.pending);
      await this.runSessionTransition('login', input.pending.email !== activeBefore, async () => {
        this.assertPendingLoginCurrent(input.pending);
        if (input.pending.email !== activeBefore) await this.deps.onIdentityChanged?.();
        this.assertPendingLoginCurrent(input.pending);
        await this.commitRestrictedLogin(
          input.pending.attempt,
          persisted,
          () => this.assertPendingLoginCurrent(input.pending),
        );
        this.assertPendingLoginCurrent(input.pending);
      });
      await this.clearPendingLoginOwner(input.pending);
      this.pendingLogin = undefined;
      await this.capturePasswordLoginRememberToken(data, input.pending);
      return { kind: 'restricted', requirement };
    }
    if (!input.pending.stretchedMasterKey) {
      const persisted: SaveLockedAuthenticatedInput = {
        email: input.pending.email,
        ...(data.MasterKeySalt ? { masterKeySalt: data.MasterKeySalt } : {}),
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: tokenExpiresAt(data.expires_in, this.now()),
        protectedKey: data.Key,
        ...input.pending.kdf,
        ...(data.PrivateKey ? { encPrivateKey: data.PrivateKey } : {}),
      };
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      this.assertPendingLoginCurrent(input.pending);
      await this.runSessionTransition('login', input.pending.email !== activeBefore, async () => {
        this.assertPendingLoginCurrent(input.pending);
        if (input.pending.email !== activeBefore) await this.deps.onIdentityChanged?.();
        this.assertPendingLoginCurrent(input.pending);
        await this.commitLockedLogin(
          input.pending.attempt,
          persisted,
          () => this.assertPendingLoginCurrent(input.pending),
        );
      });
      await this.clearPendingLoginOwner(input.pending);
      this.pendingLogin = undefined;
      await this.capturePasswordLoginRememberToken(data, input.pending);
      return { kind: 'locked' };
    }
    const userKey = await unwrapSymmetricKey(data.Key, input.pending.stretchedMasterKey);
    let privateKey: Uint8Array | undefined;
    try {
      privateKey = data.PrivateKey ? await decryptPrivateKey(data.PrivateKey, userKey) : undefined;
      this.assertPendingLoginCurrent(input.pending);
      const saveInput = {
        email: input.pending.email,
        ...(data.MasterKeySalt ? { masterKeySalt: data.MasterKeySalt } : {}),
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: tokenExpiresAt(data.expires_in, this.now()),
        protectedKey: data.Key,
        ...input.pending.kdf,
        userKey,
        // Persist only the userKey-wrapped (encrypted) blob; plaintext PKCS8 is set via privateKey below.
        ...(data.PrivateKey ? { encPrivateKey: data.PrivateKey } : {}),
      };
      const activeBefore = (await this.deps.session.getPersistedAuth())?.email;
      this.assertPendingLoginCurrent(input.pending);
      await this.runSessionTransition('login', input.pending.email !== activeBefore, async () => {
        this.assertPendingLoginCurrent(input.pending);
        if (input.pending.email !== activeBefore) await this.deps.onIdentityChanged?.();
        this.assertPendingLoginCurrent(input.pending);
        await this.commitUnlockedLogin({
          attempt: input.pending.attempt,
          saveInput: privateKey ? { ...saveInput, privateKey } : saveInput,
          failureMessage: 'Password login session commit was not authoritative.',
          finalValidate: () => this.assertPendingLoginCurrent(input.pending),
        });
        this.assertPendingLoginCurrent(input.pending);
      });
      this.assertPendingLoginCurrent(input.pending);
      await this.clearPendingLoginOwner(input.pending);
      this.pendingLogin = undefined;
      // Capture the device-remember token whenever the server returns one. Modern servers may omit it
      // after a successful provider=5 reuse, which intentionally preserves the previously stored token.
      // Capture-on-presence therefore supports both stable and rotating server contracts. Keyed by
      // (server, email); undefined server (none configured) skips silently. This is a best-effort convenience:
      // the login already succeeded and is persisted unlocked above, so a storage-write failure here
      // (e.g. chrome.storage.local rejecting) must never surface as a login failure. Swallow errors.
      await this.capturePasswordLoginRememberToken(data, input.pending);
      this.assertActivationAttempt(input.pending.attempt);
      return { kind: 'unlocked' };
    } finally {
      clearSymmetricKey(userKey);
      privateKey?.fill(0);
    }
  }

  private async capturePasswordLoginRememberToken(
    data: LoginSuccessResponse,
    pending: PendingLogin,
  ): Promise<void> {
    try {
      this.assertActivationAttempt(pending.attempt);
      if (data.TwoFactorToken) {
        await this.deps.session.saveRememberDeviceToken(
          pending.serverUrl,
          pending.email,
          data.TwoFactorToken,
        );
      }
    } catch {
      /* best-effort token capture; never fail an established login over it */
    }
  }

  /** Publish and validate one unlocked login while the session mutation lane is held. Any failure
   *  before transition settlement locks only the exact binding created by this commit. */
  private async commitUnlockedLogin(input: {
    readonly attempt: number;
    readonly saveInput: SaveUnlockedInput;
    readonly failureMessage: string;
    readonly finalValidate?: () => void;
    readonly replaceCredential?: boolean;
  }): Promise<void> {
    await this.runSessionMutation(async () => {
      const bindingBefore = (await this.deps.session.getActiveAuth())?.sessionBindingId;
      this.assertActivationAttempt(input.attempt);
      let commitStarted = false;
      let publishedBinding: { email: string; sessionBindingId: string } | undefined;
      try {
        commitStarted = true;
        await this.deps.session.saveUnlocked(input.saveInput, {
          ...(input.replaceCredential === undefined
            ? {}
            : { replaceCredential: input.replaceCredential }),
        });
        const [active, state] = await Promise.all([
          this.deps.session.getActiveAuth(),
          this.deps.session.getState(),
        ]);
        publishedBinding = newUnlockedLoginBinding(active, bindingBefore);
        if (
          state !== 'unlocked'
          || !publishedBinding
          || !activeAuthMatchesUnlockedLogin(active, input.saveInput)
        ) {
          throw new AppError('session_expired', input.failureMessage);
        }
        input.finalValidate?.();
        this.assertActivationAttempt(input.attempt);
      } catch (error) {
        if (commitStarted) {
          try {
            await this.rollbackUnlockedLoginCommit(
              bindingBefore,
              publishedBinding,
            );
          } catch (cleanupError) {
            throw new AggregateError(
              [error, cleanupError],
              'Login failed and its local session could not be cleaned up.',
              { cause: cleanupError },
            );
          }
        }
        throw error;
      }
    });
  }

  private async commitRestrictedLogin(
    attempt: number,
    input: SaveRestrictedAuthenticatedInput,
    finalValidate?: () => void,
  ): Promise<void> {
    let commitStarted = false;
    try {
      await this.runSessionMutation(async () => {
        this.assertActivationAttempt(attempt);
        commitStarted = true;
        await this.deps.session.saveRestrictedAuthenticated(input);
        const [active, state, userKey, privateKey] = await Promise.all([
          this.deps.session.getActiveAuth(),
          this.deps.session.getState(),
          this.deps.session.loadUserKey(),
          this.deps.session.loadPrivateKey(),
        ]);
        try {
          if (
            state !== 'restricted'
            || userKey !== undefined
            || privateKey !== undefined
            || !activeAuthMatchesRestrictedLogin(active, input)
          ) {
            throw new AppError(
              'session_expired',
              'Restricted login session commit was not authoritative.',
            );
          }
          finalValidate?.();
          this.assertActivationAttempt(attempt);
        } finally {
          clearSymmetricKey(userKey);
          privateKey?.fill(0);
        }
      });
    } catch (error) {
      if (commitStarted) {
        try {
          await this.deps.session.logoutIfCurrent({
            email: input.email,
            refreshToken: input.refreshToken,
          });
        } catch (cleanupError) {
          try {
            await this.deps.session.resetAllAccounts();
          } catch (resetError) {
            throw new AggregateError(
              [error, cleanupError, resetError],
              'Restricted login failed and its local session could not be removed.',
              { cause: resetError },
            );
          }
        }
      }
      throw error;
    }
    try {
      await this.deps.onLock?.();
    } catch {
      // Authorization is already restricted; cache cleanup remains best effort.
    }
  }

  private async commitLockedLogin(
    attempt: number,
    input: SaveLockedAuthenticatedInput,
    finalValidate?: () => void,
  ): Promise<void> {
    let commitStarted = false;
    try {
      await this.runSessionMutation(async () => {
        this.assertActivationAttempt(attempt);
        commitStarted = true;
        await this.deps.session.saveLockedAuthenticated(input);
        const [active, state] = await Promise.all([
          this.deps.session.getActiveAuth(),
          this.deps.session.getState(),
        ]);
        if (state !== 'locked' || !activeAuthMatchesLockedLogin(active, input)) {
          throw new AppError(
            'session_expired',
            'Restored password login session commit was not authoritative.',
          );
        }
        finalValidate?.();
        this.assertActivationAttempt(attempt);
      });
    } catch (error) {
      if (commitStarted) {
        try {
          await this.deps.session.logoutIfCurrent({
            email: input.email,
            refreshToken: input.refreshToken,
          });
        } catch (cleanupError) {
          try {
            await this.deps.session.resetAllAccounts();
          } catch (resetError) {
            throw new AggregateError(
              [error, cleanupError, resetError],
              'Locked login failed and its local session could not be removed.',
              { cause: resetError },
            );
          }
        }
      }
      throw error;
    }
  }

  private async rollbackUnlockedLoginCommit(
    bindingBefore: string | undefined,
    publishedBinding: { email: string; sessionBindingId: string } | undefined,
  ): Promise<void> {
    let binding = publishedBinding;
    if (!binding) {
      try {
        binding = newUnlockedLoginBinding(
          await this.deps.session.getActiveAuth(),
          bindingBefore,
        );
      } catch (readError) {
        await this.resetAccountsAfterRollbackFailure(readError);
        return;
      }
    }
    if (!binding) return;
    try {
      await this.deps.session.lockIfCurrentSessionBinding(binding);
    } catch (lockError) {
      await this.resetAccountsAfterRollbackFailure(lockError);
    }
  }

  private async resetAccountsAfterRollbackFailure(primaryError: unknown): Promise<void> {
    try {
      await this.deps.session.resetAllAccounts();
    } catch (resetError) {
      throw new AggregateError(
        [primaryError, resetError],
        'Login session rollback failed.',
        { cause: resetError },
      );
    }
  }

  private parseFido2Challenge(
    pending: PendingLogin,
    providerMetadata: Readonly<Record<string, unknown>> | undefined,
  ): PendingFido2Challenge | undefined {
    if (!providerMetadata) return undefined;
    try {
      const connectorUrl = interactiveTwoFactorConnectorUrl(pending.serverUrl);
      const connector = new URL(connectorUrl);
      const binding = parseFido2TwoFactorRequest(providerMetadata, {
        origin: connector.origin,
        rpId: connector.hostname,
      });
      return { request: binding, connectorUrl };
    } catch {
      return undefined;
    }
  }

  private rebuildPendingFido2(pending: PendingLogin): PendingLogin {
    if (!pending.fido2) return pending;
    try {
      const connector = new URL(pending.fido2.connectorUrl);
      const request = parseFido2TwoFactorRequest(
        JSON.parse(pending.fido2.request.connectorData) as unknown,
        { origin: connector.origin, rpId: connector.hostname },
      );
      return {
        ...pending,
        fido2: { request, connectorUrl: pending.fido2.connectorUrl },
      };
    } catch {
      return pending;
    }
  }
}

function normalizeRegistrationEmail(value: string): string {
  if (typeof value !== 'string') throw new AppError('denied', 'Invalid registration email.');
  const email = value.trim().toLowerCase();
  if (email.length < 3 || email.length > 254 || !/^[^@\s]+@[^@\s]+$/u.test(email)) {
    throw new AppError('denied', 'Invalid registration email.');
  }
  return email;
}

function accessTokenEmail(token: string): string {
  if (typeof token !== 'string' || token.length > 64 * 1024) {
    throw new AppError('denied', 'The SSO access token is invalid.');
  }
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/u.test(part))) {
    throw new AppError('denied', 'The SSO access token is invalid.');
  }
  let claims: unknown;
  try {
    claims = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[1]!))) as unknown;
  } catch {
    throw new AppError('denied', 'The SSO access token claims are invalid.');
  }
  if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) {
    throw new AppError('denied', 'The SSO access token claims are invalid.');
  }
  const prototype = Object.getPrototypeOf(claims) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AppError('denied', 'The SSO access token claims are invalid.');
  }
  const descriptor = Object.getOwnPropertyDescriptor(claims, 'email');
  if (!descriptor?.enumerable || !('value' in descriptor)) {
    throw new AppError('denied', 'The SSO access token has no account identity.');
  }
  return normalizeRegistrationEmail(descriptor.value as string);
}

function normalizeRegistrationName(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new AppError('denied', 'Invalid registration name.');
  const name = value.trim();
  if (name.length === 0) return undefined;
  if (name.length > 255 || Array.from(name).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint < 32 || codePoint === 127;
  })) {
    throw new AppError('denied', 'Invalid registration name.');
  }
  return name;
}

function isRegistrationDefinitelyRejected(error: unknown): boolean {
  if (error instanceof AppError) return true;
  return error instanceof ApiHttpError
    && error.status >= 400
    && error.status < 500
    && error.status !== 408;
}

function newUnlockedLoginBinding(
  active: ActiveAuth | undefined,
  bindingBefore: string | undefined,
): { email: string; sessionBindingId: string } | undefined {
  if (
    !active?.sessionBindingId
    || active.sessionBindingId === bindingBefore
  ) return undefined;
  return { email: active.email, sessionBindingId: active.sessionBindingId };
}

function activeAuthMatchesUnlockedLogin(
  active: ActiveAuth | undefined,
  expected: SaveUnlockedInput,
): boolean {
  return Boolean(
    active?.sessionBindingId
    && active.email === expected.email
    && active.masterKeySalt === expected.masterKeySalt
    && active.accessToken === expected.accessToken
    && active.refreshToken === expected.refreshToken
    && active.expiresAt === expected.expiresAt
    && active.protectedKey === expected.protectedKey
    && active.encPrivateKey === expected.encPrivateKey
    && sameKdfConfig(active, expected)
  );
}

function activeAuthMatchesLockedLogin(
  active: ActiveAuth | undefined,
  expected: SaveLockedAuthenticatedInput,
): boolean {
  return Boolean(
    active
    && !active.sessionBindingId
    && active.email === expected.email
    && active.masterKeySalt === expected.masterKeySalt
    && active.accessToken === expected.accessToken
    && active.refreshToken === expected.refreshToken
    && active.expiresAt === expected.expiresAt
    && active.protectedKey === expected.protectedKey
    && active.encPrivateKey === expected.encPrivateKey
    && sameKdfConfig(active, expected)
  );
}

function activeAuthMatchesRestrictedLogin(
  active: ActiveAuth | undefined,
  expected: SaveRestrictedAuthenticatedInput,
): boolean {
  return activeAuthMatchesLockedLogin(active, expected)
    && samePasswordChangeRequirement(active?.restriction, expected.restriction);
}

function canonicalDeviceLoginServer(serverUrl: string): string {
  try {
    return canonicalizeServerCapabilityUrl(serverUrl);
  } catch {
    throw new AppError('session_expired', 'The device login request has an invalid server binding.');
  }
}

function parseDeviceLoginTransitionOwner(
  owner: InteractiveTwoFactorOwner | undefined,
  state: DeviceLoginBoundState,
  serverUrl: string,
): InteractiveTwoFactorOwner | undefined {
  if (!owner) return undefined;
  let parsed: InteractiveTwoFactorOwner;
  try {
    parsed = createInteractiveTwoFactorOwner(owner);
  } catch {
    throw new AppError('denied', 'The device login transition owner is invalid.');
  }
  if (
    parsed.flow !== 'deviceLogin'
    || parsed.serverUrl !== serverUrl
    || parsed.bindingId !== state.requestId
  ) throw new AppError('denied', 'The device login transition owner is invalid.');
  return parsed;
}

function passwordInteractiveOwner(pending: PendingLogin): InteractiveTwoFactorOwner {
  return createInteractiveTwoFactorOwner({
    flow: 'password',
    generation: pending.continuation?.owner.generation ?? pending.attempt,
    serverUrl: pending.serverUrl,
    bindingId: pending.continuationId ?? `password-${pending.attempt}`,
  });
}

function validConnectorDocumentId(value: unknown): value is string {
  try {
    parseInteractiveTwoFactorDocumentId(value);
    return true;
  } catch {
    return false;
  }
}

function resolveDeviceLoginTwoFactorSubmission(
  submission: DeviceLoginTwoFactorSubmission | undefined,
  serverUrl: string,
): ResolvedDeviceLoginTwoFactor | undefined {
  if (!submission) return undefined;
  if (submission.provider === 7) {
    const assertion = consumeValidatedFido2TwoFactorSubmission(submission.assertion);
    if (assertion.origin !== new URL(serverUrl).origin) {
      throw new AppError('denied', 'The security-key assertion belongs to another server.');
    }
    return Object.freeze({
      provider: 7,
      code: assertion.token,
      remember: assertion.remember,
    });
  }
  if (submission.provider !== 0 && submission.provider !== 1 && submission.provider !== 2
      && submission.provider !== 3 && submission.provider !== 6) {
    throw new AppError('denied', 'This two-factor provider requires an unsupported interactive flow.');
  }
  const code = submission.code.trim();
  if (!code) throw new AppError('denied', 'The two-factor code is required.');
  return Object.freeze({
    provider: submission.provider,
    code,
    remember: submission.remember ?? false,
  });
}

function parseDuoSeeds(
  providerMetadata: Readonly<Record<string, unknown>> | undefined,
  providers: readonly number[],
): readonly DuoProviderSeed[] {
  if (!providerMetadata) return Object.freeze([]);
  const seeds: DuoProviderSeed[] = [];
  for (const provider of [2, 6] as const) {
    if (!providers.includes(provider)) continue;
    try {
      seeds.push(extractDuoProviderSeed(providerMetadata, provider));
    } catch {
      // Legacy Host/Signature or malformed AuthUrl stays unavailable rather than widening parsing.
    }
  }
  return Object.freeze(seeds);
}

function mergePasswordLoginSecurityFacts(
  current: PasswordLoginSecurityFacts,
  forcePasswordReset: boolean,
  masterPasswordPolicy: MasterPasswordPolicy | undefined,
): PasswordLoginSecurityFacts {
  const policy = combineMasterPasswordPolicies(
    current.masterPasswordPolicy,
    masterPasswordPolicy,
  );
  return Object.freeze({
    forcePasswordReset: current.forcePasswordReset || forcePasswordReset,
    ...(policy ? { masterPasswordPolicy: policy } : {}),
  });
}

function mergeDeviceLoginGrantSecurity(
  current: PasswordLoginSecurityFacts,
  result: DeviceLoginResult,
): DeviceLoginGrantOutcome {
  const source = result.kind === 'success' ? result.data : result;
  return Object.freeze({
    result,
    security: mergePasswordLoginSecurityFacts(
      current,
      source.forcePasswordReset === true,
      source.masterPasswordPolicy,
    ),
  });
}

function applyPasswordLoginSecurityFacts(
  pending: PendingLogin,
  forcePasswordReset: boolean,
  masterPasswordPolicy: MasterPasswordPolicy | undefined,
): PendingLogin {
  const security = mergePasswordLoginSecurityFacts(
    {
      forcePasswordReset: pending.forcePasswordReset === true
        || pending.passwordChangeRequirement?.reason === 'adminForcePasswordReset',
      ...(pending.masterPasswordPolicy || pending.passwordChangeRequirement?.policy
        ? {
            masterPasswordPolicy: combineMasterPasswordPolicies(
              pending.masterPasswordPolicy,
              pending.passwordChangeRequirement?.policy,
            )!,
          }
        : {}),
    },
    forcePasswordReset,
    masterPasswordPolicy,
  );
  const weakRequired = pending.passwordChangeRequirement?.reason === 'weakMasterPassword'
    || Boolean(
      security.masterPasswordPolicy?.enforceOnLogin
      && (
        !pending.passwordEvidence
        || !evaluateMasterPasswordEvidence(
          pending.passwordEvidence,
          security.masterPasswordPolicy,
        )
      ),
    );
  const requirement = security.forcePasswordReset
    ? passwordChangeRequirement('adminForcePasswordReset', security.masterPasswordPolicy)
    : weakRequired
      ? passwordChangeRequirement('weakMasterPassword', security.masterPasswordPolicy)
      : undefined;
  const {
    masterPasswordPolicy: _previousPolicy,
    forcePasswordReset: _previousForce,
    passwordChangeRequirement: _previousRequirement,
    ...base
  } = pending;
  return {
    ...base,
    ...(security.masterPasswordPolicy
      ? { masterPasswordPolicy: security.masterPasswordPolicy }
      : {}),
    ...(security.forcePasswordReset ? { forcePasswordReset: true as const } : {}),
    ...(requirement ? { passwordChangeRequirement: requirement } : {}),
  };
}

function canonicalAccountPasskeyServer(serverUrl: string): string {
  try {
    return canonicalizeServerCapabilityUrl(serverUrl);
  } catch {
    throw new AppError('session_expired', 'The account passkey request has an invalid server binding.');
  }
}

function copyDeviceLoginUserKey(userKey: SymmetricKey): SymmetricKey {
  if (
    typeof userKey !== 'object'
    || userKey === null
    || !(userKey.encKey instanceof Uint8Array)
    || !(userKey.macKey instanceof Uint8Array)
    || userKey.encKey.byteLength !== 32
    || userKey.macKey.byteLength !== 32
  ) {
    throw new AppError('session_expired', 'The recovered device login key is invalid.');
  }
  const raw = serializeSymmetricKey(userKey);
  try {
    return symmetricKeyFromBytes(raw);
  } finally {
    raw.fill(0);
  }
}

function sameSymmetricKey(left: SymmetricKey, right: SymmetricKey): boolean {
  return constantTimeEqual(left.encKey, right.encKey)
    && constantTimeEqual(left.macKey, right.macKey);
}

async function boundedGeneratorHistoryCleanup(
  operation: () => Promise<void> | undefined,
): Promise<void> {
  // Start the production FIFO operation immediately. If the bounded wait expires, the observed
  // promise keeps running, so a same-worker re-login queues new tracking after this deletion.
  const observed = Promise.resolve().then(operation).then(
    () => undefined,
    () => undefined,
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, GENERATOR_HISTORY_CLEANUP_WAIT_MS);
  });
  await Promise.race([observed, timeout]);
  if (timer !== undefined) clearTimeout(timer);
}

function clearSymmetricKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}

function safePendingLoginDeadline(now: number): number {
  const expiresAt = now + PENDING_LOGIN_CONTINUATION_TTL_MS;
  if (!Number.isSafeInteger(expiresAt)) {
    throw new AppError('session_expired', 'The pending login deadline is invalid.');
  }
  return expiresAt;
}

function validateDeviceLoginSuccess(
  data: LoginSuccessResponse,
  expectedKdf: KdfConfig,
  issuedAt: number,
): ValidatedDeviceLoginSuccess {
  const accessToken = requireDeviceLoginString(data?.access_token, 'access token', 64 * 1024);
  const refreshToken = requireDeviceLoginString(data?.refresh_token, 'refresh token', 64 * 1024);
  const protectedKey = requireDeviceLoginString(data?.Key, 'protected key', 8 * 1024);
  const tokenType = requireDeviceLoginString(data?.token_type, 'token type', 64);
  if (tokenType.toLowerCase() !== 'bearer') {
    throw new Error('Device login response has an unsupported token type.');
  }
  assertType2EncString(protectedKey, 'protected key');
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) {
    throw new Error('Device login clock is invalid.');
  }
  if (!Number.isSafeInteger(data?.expires_in) || data.expires_in <= 0) {
    throw new Error('Device login response has an invalid token lifetime.');
  }
  const lifetimeMs = data.expires_in * 1_000;
  const expiresAt = issuedAt + lifetimeMs;
  if (!Number.isSafeInteger(lifetimeMs) || !Number.isSafeInteger(expiresAt)) {
    throw new Error('Device login response token lifetime is out of range.');
  }

  let kdf = pickKdfConfig(expectedKdf);
  if (
    data.Kdf !== undefined
    || data.KdfIterations !== undefined
    || data.KdfMemory !== undefined
    || data.KdfParallelism !== undefined
  ) {
    const responseKdf = parseKdfConfig({
      kdf: data.Kdf ?? expectedKdf.kdf,
      kdfIterations: data.KdfIterations ?? expectedKdf.kdfIterations,
      kdfMemory: data.KdfMemory ?? (expectedKdf.kdf === 1 ? expectedKdf.kdfMemory : undefined),
      kdfParallelism: data.KdfParallelism
        ?? (expectedKdf.kdf === 1 ? expectedKdf.kdfParallelism : undefined),
    });
    if (!sameKdfConfig(responseKdf, expectedKdf)) {
      throw new Error('Server changed KDF settings during device login; refusing to continue.');
    }
    kdf = pickKdfConfig(responseKdf);
  }

  const encPrivateKey = data.PrivateKey === undefined
    ? undefined
    : requireDeviceLoginString(data.PrivateKey, 'encrypted private key', 64 * 1024);
  if (encPrivateKey !== undefined) assertType2EncString(encPrivateKey, 'encrypted private key');
  const rememberToken = data.TwoFactorToken === undefined
    ? undefined
    : requireDeviceLoginString(data.TwoFactorToken, 'remember token', 64 * 1024);

  return Object.freeze({
    accessToken,
    refreshToken,
    expiresAt,
    protectedKey,
    kdf,
    ...(encPrivateKey !== undefined ? { encPrivateKey } : {}),
    ...(rememberToken !== undefined ? { rememberToken } : {}),
    ...(data.forcePasswordReset === true ? { forcePasswordReset: true as const } : {}),
    ...(data.masterPasswordPolicy ? { masterPasswordPolicy: data.masterPasswordPolicy } : {}),
  });
}

function validateAccountPasskeyLoginSuccess(
  data: AccountPasskeyLoginSuccess,
  issuedAt: number,
): ValidatedAccountPasskeyLoginSuccess {
  if (data?.tokenType !== 'Bearer') {
    throw new Error('Account passkey response has an unsupported token type.');
  }
  const accessToken = requireAccountPasskeyString(data?.accessToken, 'access token', 64 * 1024);
  const refreshToken = requireAccountPasskeyString(data?.refreshToken, 'refresh token', 64 * 1024);
  const protectedKey = requireAccountPasskeyString(data?.protectedKey, 'protected key', 64 * 1024);
  assertAccountPasskeyType2EncString(protectedKey, 'protected key');
  const accountIdentity = requireAccountPasskeyString(
    data?.accountIdentity,
    'account identity',
    254,
  ).toLowerCase();
  if (data.accountIdentity !== accountIdentity || !/^[^@\s]+@[^@\s]+$/u.test(accountIdentity)) {
    throw new Error('Account passkey response has an invalid account identity.');
  }
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0
      || !Number.isSafeInteger(data?.expiresIn) || data.expiresIn <= 0) {
    throw new Error('Account passkey response has an invalid token lifetime.');
  }
  const lifetimeMs = data.expiresIn * 1_000;
  const expiresAt = issuedAt + lifetimeMs;
  if (!Number.isSafeInteger(lifetimeMs) || !Number.isSafeInteger(expiresAt)) {
    throw new Error('Account passkey response token lifetime is out of range.');
  }
  const kdf = pickKdfConfig(parseKdfConfig(data.kdf));
  const encPrivateKey = requireAccountPasskeyString(
    data.encPrivateKey,
    'encrypted private key',
    64 * 1024,
  );
  assertAccountPasskeyType2EncString(encPrivateKey, 'encrypted private key');
  const rememberToken = data.rememberToken === undefined
    ? undefined
    : requireAccountPasskeyString(data.rememberToken, 'remember token', 64 * 1024);
  const webAuthnPrfOption = parseAccountPasskeyWebAuthnPrfOption(data.webAuthnPrfOption);
  return Object.freeze({
    accessToken,
    refreshToken,
    expiresAt,
    protectedKey,
    kdf,
    accountIdentity,
    encPrivateKey,
    ...(rememberToken ? { rememberToken } : {}),
    ...(webAuthnPrfOption ? { webAuthnPrfOption } : {}),
    ...(data.forcePasswordReset === true ? { forcePasswordReset: true as const } : {}),
    ...(data.masterPasswordPolicy ? { masterPasswordPolicy: data.masterPasswordPolicy } : {}),
  });
}

function requireAccountPasskeyString(value: unknown, label: string, maximumLength: number): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maximumLength
    || value.trim() !== value
    || containsAsciiControl(value)
  ) {
    throw new Error(`Account passkey response has an invalid ${label}.`);
  }
  return value;
}

function assertAccountPasskeyType2EncString(value: string, label: string): void {
  let parsed: ReturnType<typeof parseEncString>;
  try {
    parsed = parseEncString(value);
  } catch {
    throw new Error(`Account passkey response has an invalid ${label}.`);
  }
  if (
    parsed.encType !== 2
    || parsed.iv.byteLength !== 16
    || parsed.mac.byteLength !== 32
    || parsed.ct.byteLength === 0
    || parsed.ct.byteLength % 16 !== 0
  ) {
    throw new Error(`Account passkey response has an invalid ${label}.`);
  }
}

function requireDeviceLoginString(value: unknown, label: string, maximumLength: number): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > maximumLength
    || value.trim() !== value
    || containsAsciiControl(value)
  ) {
    throw new Error(`Device login response has an invalid ${label}.`);
  }
  return value;
}

function assertType2EncString(value: string, label: string): void {
  let parsed: ReturnType<typeof parseEncString>;
  try {
    parsed = parseEncString(value);
  } catch {
    throw new Error(`Device login response has an invalid ${label}.`);
  }
  if (
    parsed.encType !== 2
    || parsed.iv.byteLength !== 16
    || parsed.mac.byteLength !== 32
    || parsed.ct.byteLength === 0
    || parsed.ct.byteLength % 16 !== 0
  ) {
    throw new Error(`Device login response has an invalid ${label}.`);
  }
}

function assertValidPin(pin: string): void {
  const violation = pinConstraintViolation(pin);
  if (violation) throw new AppError('error', pinConstraintMessage(violation));
}

function normalizeNewDeviceOtp(value: unknown): string {
  if (typeof value !== 'string') throw new AppError('denied', 'Invalid device verification code.');
  const code = value.trim();
  if (code.length === 0 || code.length > MAX_NEW_DEVICE_OTP_LENGTH) {
    throw new AppError('denied', 'Invalid device verification code.');
  }
  for (let index = 0; index < code.length; index += 1) {
    const unit = code.charCodeAt(index);
    if (unit <= 0x1f || unit === 0x7f) {
      throw new AppError('denied', 'Invalid device verification code.');
    }
  }
  return code;
}

function isInvalidNewDeviceOtpError(error: ApiHttpError): boolean {
  if (typeof error.body !== 'object' || error.body === null || Array.isArray(error.body)) return false;
  const prototype = Object.getPrototypeOf(error.body) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  const descriptor = Object.getOwnPropertyDescriptor(error.body, 'error_description');
  return descriptor?.enumerable === true
    && 'value' in descriptor
    && descriptor.value === 'Invalid New Device OTP';
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
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

function toApiKdfSettings(value: KdfConfig) {
  return {
    kdfType: value.kdf,
    iterations: value.kdfIterations,
    memory: value.kdf === 1 ? value.kdfMemory : null,
    parallelism: value.kdf === 1 ? value.kdfParallelism : null,
  };
}

function isInvalidGrant(error: unknown): error is ApiHttpError {
  if (!(error instanceof ApiHttpError) || (error.status !== 400 && error.status !== 401)) return false;
  const body = error.body;
  return typeof body === 'object'
    && body !== null
    && !Array.isArray(body)
    && (body as { error?: unknown }).error === 'invalid_grant';
}

function isUnauthorizedResponse(error: unknown): error is ApiHttpError {
  return error instanceof ApiHttpError && error.status === 401;
}

function isDefinitePasswordChangeRejection(error: unknown): error is ApiHttpError {
  return error instanceof ApiHttpError
    && error.status >= 400
    && error.status < 500
    && error.status !== 408
    && error.status !== 429;
}

function isDefiniteDeviceLoginGrantRejection(error: unknown): error is ApiHttpError {
  return isDefinitePasswordChangeRejection(error);
}

function accountKeyFor(lease: AccountLease): string {
  return `${lease.serverUrl}\n${lease.accountIdentity}`;
}

function rotationOutcomeUnknown(): AppError {
  return new AppError(
    'outcome_unknown',
    'Account key rotation outcome is unknown. Restart the extension and sign in again; do not retry.',
  );
}

function passwordChangeOutcomeUnknown(): AppError {
  return new AppError(
    'outcome_unknown',
    'The password change may have completed. Sign in again with the new password first.',
  );
}

function requireSsoAttemptId(input: unknown): string {
  if (
    typeof input !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(input)
  ) throw new AppError('denied', 'The SSO attempt binding is invalid.');
  return input;
}

function pendingSsoHandoff(
  serverUrl: string,
  email: string,
  sso: PendingSsoLoginGrant,
): PendingSsoHandoff {
  return Object.freeze({
    attemptId: requireSsoAttemptId(sso.ssoAttemptId),
    attemptGeneration: requireSsoAttemptGeneration(sso.ssoAttemptGeneration),
    serverUrl,
    identityUrl: sso.identityUrl,
    email,
  });
}

function requireSsoAttemptGeneration(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) <= 0) {
    throw new AppError('denied', 'The SSO attempt generation is invalid.');
  }
  return input as number;
}

function accessTokenUnavailable(): AppError {
  return new AppError(
    'session_expired',
    'A current access token is not available for this session.',
  );
}

function invalidatesRefreshIdentity(reason: SessionTransitionReason): boolean {
  return reason === 'login'
    || reason === 'logout'
    || reason === 'switchAccount'
    || reason === 'removeAccount'
    || reason === 'serverChange'
    || reason === 'keyRotation';
}
