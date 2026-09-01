import type { KeyValueStore } from '../../platform/store.js';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  utf8ToBytes,
} from '../crypto/encoding.js';
import { parseEncString } from '../crypto/encstring.js';
import { parseKdfConfig, sameKdfConfig, type KdfConfig } from '../crypto/kdf.js';
import {
  parseMasterPasswordPolicy,
  requireMasterPasswordHint,
} from '../policy/master-password-policy.js';
import {
  serializeClientEventBatch,
  type ClientEventWire,
} from '../events/client-event.js';
import {
  canonicalizeServerCapabilityUrl,
  normalizeServerEnvironmentUrl,
} from './server-capabilities.js';
import {
  ACCOUNT_PASSKEY_OPTIONS_MAX_BYTES,
  ACCOUNT_PASSKEY_TOKEN_MAX_BYTES,
  parseAccountPasskeyAssertionOptions,
  parseAccountPasskeyLoginSuccess,
  parseAccountPasskeyTwoFactorProviders,
  serializeAccountPasskeyAssertion,
  type AccountPasskeyAssertion,
  type AccountPasskeyAssertionOptions,
  type AccountPasskeyLoginResult,
} from './account-passkey.js';
import type {
  AttachmentUploadRequest,
  AttachmentUploadSlotReceipt,
  CipherBulkIdsRequest,
  CipherBulkShareRequest,
  CipherPartialRequest,
  CipherRequest,
  CipherResponse,
  CipherWithIdRequest,
  CollectionAccess,
  CollectionAccessDetails,
  CollectionResponse,
  CollectionUpdateAccess,
  EmergencyAccessGrant,
  FolderResponse,
  KeyRotationUnlockRecordsStatus,
  LoginSuccessResponse,
  OrganizationCipherCreateRequest,
  OrgPublicKeyResponse,
  PreloginResponse,
  RefreshTokenResponse,
  RegisterRequest,
  RotateKeyData,
  SendFileUploadResponse,
  SendRequest,
  SendResponse,
  SyncResponse,
  TwoFactorRequiredResponse,
  UserPublicKeyResponse,
  ChangeKdfRequest,
} from './types.js';
import { parseSyncResponse } from './sync-profile.js';

export interface PasswordLoginInput {
  email: string;
  masterPasswordHash: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  remember?: boolean;
  newDeviceOtp?: string;
  readonly onGrantStarted?: () => void | Promise<void>;
  readonly onGrantDispatched?: () => void;
}

export interface SsoTokenLoginInput {
  readonly code: string;
  readonly codeVerifier: string;
  readonly redirectUri: string;
  readonly twoFactorProvider?: number;
  readonly twoFactorToken?: string;
  readonly remember?: boolean;
  readonly newDeviceOtp?: string;
  /** Internal phase signal invoked synchronously after the request guard and immediately before fetch. */
  readonly onGrantStarted?: () => void | Promise<void>;
  readonly onGrantDispatched?: () => void;
}

export type PasswordLoginResult =
  | { kind: 'success'; data: LoginSuccessResponse }
  | {
      kind: 'twoFactor';
      providers: number[];
      providerMetadata?: Readonly<Record<string, unknown>>;
      token?: string;
      email?: string;
      ssoEmail2FaSessionToken?: string;
      forcePasswordReset?: true;
      masterPasswordPolicy?: ReturnType<typeof parseMasterPasswordPolicy>;
    }
  | { kind: 'newDeviceVerification' }
  | { kind: 'ssoRequired'; organizationIdentifier: string };

export type DeviceLoginResult = Exclude<
  PasswordLoginResult,
  { kind: 'newDeviceVerification' } | { kind: 'ssoRequired' }
>;

export type PasswordHintResult =
  | { readonly status: 'sent' }
  | { readonly status: 'hint'; readonly message: string }
  | { readonly status: 'no_hint' }
  | { readonly status: 'unavailable' };

export interface NewDeviceVerificationOtpRequestInput {
  email: string;
  masterPasswordHash: string;
}

export interface RegistrationStartInput {
  email: string;
  name?: string;
}

export type RegistrationStartResult =
  | { readonly kind: 'inline'; readonly emailVerificationToken: string }
  | { readonly kind: 'email_required' }
  | { readonly kind: 'legacy' };

export type FetchFn = typeof fetch;

export interface ApiClientDeps {
  serverUrlProvider(): Promise<string>;
  fetchFn?: FetchFn;
  localStore: KeyValueStore;
}

export interface DeviceLoginInput {
  email: string;
  accessCode: string;
  authRequestId: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  remember?: boolean;
  readonly onGrantStarted?: () => void | Promise<void>;
  readonly onGrantDispatched?: () => void;
}

export interface AccountPasskeyLoginInput {
  readonly token: string;
  readonly assertion: AccountPasskeyAssertion;
}

export interface KnownDeviceInput {
  email: string;
  deviceIdentifier?: string;
}

export interface AuthRequestCreateInput {
  email: string;
  publicKey: string;
  deviceIdentifier: string;
  accessCode: string;
  type: 0;
}

export type AuthRequestUpdateInput =
  | {
      key: string;
      masterPasswordHash?: string;
      deviceIdentifier: string;
      requestApproved: true;
    }
  | {
      key?: never;
      masterPasswordHash?: never;
      deviceIdentifier: string;
      requestApproved: false;
    };

export interface ServerConfigResponse {
  readonly body: unknown;
  readonly responseBytes: number;
}

export type ClientEventCollectResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly status: number; readonly retryAfter?: string };

export const BITWARDEN_CLIENT_VERSION = '2024.12.0';

interface ApiClientSharedState {
  fetchFn: FetchFn;
  deviceIdentifierPromise: Promise<string> | undefined;
}

interface ApiClientScope {
  shared: ApiClientSharedState;
  requestGuard?: () => void;
  fixedServerUrl?: string;
}

const DEVICE_ID_KEY = 'deviceIdentifier';
const REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;
const SYNC_RESPONSE_MAX_BYTES = 64 * 1024 * 1024;
const SERVER_CONFIG_RESPONSE_MAX_BYTES = 1024 * 1024;
const PASSWORD_HINT_RESPONSE_MAX_BYTES = 64 * 1024;
export const PASSWORD_HINT_MESSAGE_MAX_LENGTH = 4 * 1024;
const PASSWORD_HINT_PREFIX = 'Your password hint is: ';
const PASSWORD_HINT_NONE = 'Sorry, you have no password hint...';
const PASSWORD_HINT_UNAVAILABLE = 'This server is not configured to provide password hints.';
const ATTACHMENT_METADATA_RESPONSE_MAX_BYTES = 64 * 1024;
export const CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES = 64 * 1024;
export const ATTACHMENT_RESPONSE_MAX_BYTES = 128 * 1024 * 1024;
const ATTACHMENT_URL_MAX_LENGTH = 8 * 1024;
const ATTACHMENT_METADATA_MAX_LENGTH = 64 * 1024;
const ATTACHMENT_UPLOAD_RESPONSE_KEYS = new Set([
  'attachmentId', 'AttachmentId', 'fileUploadType', 'FileUploadType',
  'cipherResponse', 'CipherResponse', 'cipherMiniResponse', 'CipherMiniResponse',
  'url', 'Url', 'object', 'Object',
]);
const BITWARDEN_CLIENT_VERSION_HEADER = 'Bitwarden-Client-Version';
const BITWARDEN_CLIENT_NAME_HEADER = 'Bitwarden-Client-Name';
const DEVICE_TYPE = '2';
const DEVICE_NAME = 'chrome';
const DEVICE_LOGIN_ACCESS_CODE_LENGTH = 25;
const MAX_EMAIL_LENGTH = 254;
const MAX_ACCOUNT_NAME_LENGTH = 255;
const MAX_REGISTRATION_TOKEN_LENGTH = 16 * 1024;
const MAX_DEVICE_IDENTIFIER_LENGTH = 255;
const MAX_PUBLIC_KEY_LENGTH = 2_048;
const MIN_PUBLIC_KEY_BYTES = 256;
const MAX_PUBLIC_KEY_BYTES = 1_024;
const MAX_AUTH_REQUEST_KEY_LENGTH = 2_000;
const MAX_MASTER_PASSWORD_HASH_LENGTH = 1_024;
const MAX_TWO_FACTOR_TOKEN_LENGTH = 32 * 1_024;
const MAX_NEW_DEVICE_OTP_LENGTH = 256;
const MAX_PENDING_AUTH_REQUESTS = 1_024;
const MAX_KEY_ROTATION_UNLOCK_RECORDS = 1_024;
const MAX_ROTATION_ENCRYPTED_KEY_LENGTH = 16 * 1_024;
const MAX_CIPHER_MUTATION_IDS = 1_000;
const MAX_CIPHER_BULK_SHARE_COUNT = 50_000;
const MAX_CIPHER_BULK_SHARE_REQUEST_BYTES = 64 * 1024 * 1024;
const MAX_CIPHER_BULK_SHARE_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_CIPHER_ID_LENGTH = 4_096;
const MAX_CIPHER_ENCRYPTED_NAME_LENGTH = 16 * 1024;
const MAX_CIPHER_DATE_LENGTH = 128;
const CIPHER_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const KNOWN_DEVICE_INPUT_KEYS = new Set(['email', 'deviceIdentifier']);
const AUTH_REQUEST_CREATE_INPUT_KEYS = new Set([
  'email', 'publicKey', 'deviceIdentifier', 'accessCode', 'type',
]);
const AUTH_REQUEST_UPDATE_INPUT_KEYS = new Set([
  'key', 'masterPasswordHash', 'deviceIdentifier', 'requestApproved',
]);
const DEVICE_LOGIN_INPUT_KEYS = new Set([
  'email', 'accessCode', 'authRequestId', 'twoFactorProvider', 'twoFactorToken', 'remember',
  'onGrantStarted', 'onGrantDispatched',
]);
const PASSWORD_LOGIN_INPUT_KEYS = new Set([
  'email', 'masterPasswordHash', 'twoFactorProvider', 'twoFactorToken', 'remember', 'newDeviceOtp',
  'onGrantStarted', 'onGrantDispatched',
]);
const SSO_TOKEN_LOGIN_INPUT_KEYS = new Set([
  'code', 'codeVerifier', 'redirectUri', 'twoFactorProvider', 'twoFactorToken', 'remember',
  'newDeviceOtp', 'onGrantStarted', 'onGrantDispatched',
]);
const NEW_DEVICE_OTP_REQUEST_INPUT_KEYS = new Set(['email', 'masterPasswordHash']);
const ACCOUNT_PASSKEY_LOGIN_INPUT_KEYS = new Set(['token', 'assertion']);
const CIPHER_BULK_SHARE_REQUEST_KEYS = new Set([
  'ciphers', 'collectionIds', 'encryptedFor',
]);
const CIPHER_BULK_SHARE_CIPHER_KEYS = new Set([
  'id', 'encryptedFor', 'type', 'name', 'notes', 'favorite', 'folderId', 'organizationId',
  'login', 'card', 'identity', 'sshKey', 'secureNote', 'key', 'fields', 'passwordHistory',
  'attachments2', 'reprompt', 'archivedDate', 'lastKnownRevisionDate',
]);
const CIPHER_PARTIAL_REQUEST_KEYS = new Set(['folderId', 'favorite']);
const ATTACHMENT_DOWNLOAD_RESPONSE_KEYS = new Set([
  'id', 'Id', 'url', 'Url', 'fileName', 'FileName', 'key', 'Key',
  'size', 'Size', 'sizeName', 'SizeName', 'object', 'Object',
]);
const NEW_DEVICE_VERIFICATION_REQUIRED_MESSAGE = 'new device verification required';

type ApiRequestScope = 'configured-server' | 'external';

export class ApiClient {
  private readonly fetchFn: FetchFn;
  private readonly shared: ApiClientSharedState;
  private readonly requestGuard: (() => void) | undefined;
  private readonly fixedServerUrl: string | undefined;

  constructor(private readonly deps: ApiClientDeps, scope?: ApiClientScope) {
    this.shared = scope?.shared ?? {
      fetchFn: deps.fetchFn ?? globalThis.fetch.bind(globalThis),
      deviceIdentifierPromise: undefined,
    };
    this.fetchFn = this.shared.fetchFn;
    this.requestGuard = scope?.requestGuard;
    this.fixedServerUrl = scope?.fixedServerUrl;
  }

  /** Pin every request made by the clone to one server URL captured by its caller. */
  forServer(serverUrl: string): ApiClient {
    const fixedServerUrl = parseServerBaseUrl(serverUrl).toString();
    return new ApiClient(this.deps, {
      shared: this.shared,
      ...(this.requestGuard ? { requestGuard: this.requestGuard } : {}),
      fixedServerUrl,
    });
  }

  /**
   * Return a client that shares transport and device identity with this one, but revalidates its
   * caller-owned operation immediately before every network request. Guards compose when an already
   * scoped client is scoped again.
   */
  withRequestGuard(assertCurrent: () => void): ApiClient {
    const inheritedGuard = this.requestGuard;
    const requestGuard = inheritedGuard
      ? () => {
          inheritedGuard();
          assertCurrent();
        }
      : assertCurrent;
    return new ApiClient(this.deps, {
      shared: this.shared,
      requestGuard,
      ...(this.fixedServerUrl ? { fixedServerUrl: this.fixedServerUrl } : {}),
    });
  }

  async passwordLogin(input: PasswordLoginInput): Promise<PasswordLoginResult> {
    const parsed = parsePasswordLoginInput(input);
    const form = await this.baseTokenForm();
    form.set('grant_type', 'password');
    form.set('username', parsed.email);
    form.set('password', parsed.masterPasswordHash);
    form.set('scope', 'api offline_access');
    if (parsed.twoFactor !== undefined) {
      form.set('twoFactorProvider', String(parsed.twoFactor.provider));
      form.set('twoFactorToken', parsed.twoFactor.token);
      form.set('twoFactorRemember', parsed.twoFactor.remember ? '1' : '0');
    }
    if (parsed.newDeviceOtp !== undefined) form.set('newDeviceOtp', parsed.newDeviceOtp);

    const { response, body } = await this.tokenRequest(form, {
      ...(parsed.onGrantStarted ? { onGrantStarted: parsed.onGrantStarted } : {}),
      ...(parsed.onGrantDispatched ? { onGrantDispatched: parsed.onGrantDispatched } : {}),
    });
    return parsePasswordLoginResult(response, body, true);
  }

  /** Exchange one SSO authorization code against the identity service bound to this server. */
  async ssoLogin(
    identityUrl: string,
    input: SsoTokenLoginInput,
  ): Promise<PasswordLoginResult> {
    const parsed = parseSsoTokenLoginInput(input);
    const form = await this.baseTokenForm();
    form.set('grant_type', 'authorization_code');
    form.set('scope', 'api offline_access');
    form.set('code', parsed.code);
    form.set('code_verifier', parsed.codeVerifier);
    form.set('redirect_uri', parsed.redirectUri);
    if (parsed.twoFactor !== undefined) {
      form.set('twoFactorProvider', String(parsed.twoFactor.provider));
      form.set('twoFactorToken', parsed.twoFactor.token);
      form.set('twoFactorRemember', parsed.twoFactor.remember ? '1' : '0');
    }
    if (parsed.newDeviceOtp !== undefined) form.set('newDeviceOtp', parsed.newDeviceOtp);

    const { response, body } = await this.identityTokenRequest(
      identityUrl,
      form,
      parsed.onGrantStarted,
      parsed.onGrantDispatched,
    );
    return parseSsoLoginResult(response, body);
  }

  /** Positive, credential-free Vaultwarden SSO probe. Callers treat every failure as unavailable. */
  async probeVaultwardenSso(identityUrl: string): Promise<void> {
    const identity = await this.sameServerIdentityBase(identityUrl);
    const { response, body } = await this.requestBytes(
      new URL('sso/prevalidate', identity).toString(),
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
      },
      64 * 1024,
      64 * 1024,
    );
    if (!response.ok) throw new ApiHttpError(response.status, parseBodyBytes(body));
    const record = requirePlainRecord(parseBodyBytes(body), 'SSO prevalidation response');
    requireBoundedString(record.token, 'SSO prevalidation token', 1, 64 * 1024);
  }

  /** Read the implementation release independently of the protocol version in /api/config. */
  async getServerVersion(): Promise<string> {
    const value = await this.jsonRequest<unknown>('/api/version', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
    }, 4 * 1024);
    return requireBoundedString(value, 'server version', 1, 128);
  }

  /** Redeem one approved AuthenticateAndUnlock request through the regular password grant. */
  async deviceLogin(input: DeviceLoginInput): Promise<DeviceLoginResult> {
    requireExactInputKeys(input, DEVICE_LOGIN_INPUT_KEYS, 'device login input');
    const email = normalizeDeviceLoginEmail(input.email);
    const accessCode = requireBoundedString(
      input.accessCode,
      'accessCode',
      DEVICE_LOGIN_ACCESS_CODE_LENGTH,
      DEVICE_LOGIN_ACCESS_CODE_LENGTH,
    );
    const authRequestId = requireUuid(input.authRequestId, 'authRequestId');
    const twoFactor = parseLoginTwoFactor(input);
    assertGrantCallbacks(input.onGrantStarted, input.onGrantDispatched);
    requireDeviceIdentifier(await this.getDeviceIdentifier());
    const form = await this.baseTokenForm();
    form.set('grant_type', 'password');
    form.set('username', email);
    form.set('password', accessCode);
    form.set('AuthRequest', authRequestId);
    form.set('scope', 'api offline_access');
    if (twoFactor !== undefined) {
      form.set('twoFactorProvider', String(twoFactor.provider));
      form.set('twoFactorToken', twoFactor.token);
      form.set('twoFactorRemember', twoFactor.remember ? '1' : '0');
    }

    const { response, body } = await this.tokenRequest(form, {
      ...(input.onGrantStarted ? { onGrantStarted: input.onGrantStarted } : {}),
      ...(input.onGrantDispatched ? { onGrantDispatched: input.onGrantDispatched } : {}),
    });
    return parsePasswordLoginResult(response, body, false);
  }

  async sendNewDeviceVerificationOtp(input: NewDeviceVerificationOtpRequestInput): Promise<void> {
    requireExactInputKeys(input, NEW_DEVICE_OTP_REQUEST_INPUT_KEYS, 'new device verification request');
    const email = normalizeDeviceLoginEmail(input.email);
    const masterPasswordHash = requireBoundedString(
      input.masterPasswordHash,
      'masterPasswordHash',
      1,
      MAX_MASTER_PASSWORD_HASH_LENGTH,
    );
    await this.noBodyRequest('/api/accounts/resend-new-device-otp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, masterPasswordHash }),
    });
  }

  async sendEmailLogin(input: { email: string; twoFactorToken: string }): Promise<void> {
    // Vaultwarden returns 200 with an EMPTY body here, so this must not try to JSON-parse the response.
    await this.noBodyRequest('/api/two-factor/send-email-login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: input.email.trim().toLowerCase(), token: input.twoFactorToken }),
    });
  }

  async prelogin(email: string): Promise<PreloginResponse> {
    const response = await this.jsonRequest<unknown>('/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });
    return parseKdfConfig(response);
  }

  /** Request delivery of the account's password hint without disclosing whether the account exists. */
  async requestPasswordHint(email: string): Promise<PasswordHintResult> {
    const normalizedEmail = normalizePasswordHintEmail(email);
    const { response, body } = await this.requestBytes(
      await this.url('/api/accounts/password-hint'),
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'content-type': 'application/json',
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
        },
        body: JSON.stringify({ email: normalizedEmail }),
      },
      PASSWORD_HINT_RESPONSE_MAX_BYTES,
      PASSWORD_HINT_RESPONSE_MAX_BYTES,
    );
    try {
      if (!response.ok) {
        const responseBody = parseBodyBytes(body);
        const result = response.status === 400
          ? parsePasswordHintResponseBody(responseBody)
          : undefined;
        if (result) return result;
        throw new ApiHttpError(response.status, responseBody);
      }
      return Object.freeze({ status: 'sent' });
    } finally {
      body.fill(0);
    }
  }

  async sendSsoEmailLogin(input:
    | { readonly mode: 'vaultwarden-device' }
    | {
        readonly mode: 'bitwarden-session';
        readonly email: string;
        readonly ssoEmail2FaSessionToken: string;
      }): Promise<void> {
    const body = input.mode === 'vaultwarden-device'
      ? { deviceIdentifier: await this.getDeviceIdentifier() }
      : {
          email: normalizeDeviceLoginEmail(input.email),
          ssoEmail2FaSessionToken: requireBoundedString(
            input.ssoEmail2FaSessionToken,
            'SSO email two-factor session token',
            1,
            MAX_TWO_FACTOR_TOKEN_LENGTH,
          ),
          deviceIdentifier: await this.getDeviceIdentifier(),
        };
    await this.noBodyRequest('/api/two-factor/send-email-login', {
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  /** Begin modern registration without generating or transmitting any account key material. */
  async startRegistration(input: RegistrationStartInput): Promise<RegistrationStartResult> {
    requireExactInputKeys(input, new Set(['email', 'name']), 'registration start input');
    const email = normalizeDeviceLoginEmail(input.email);
    const name = input.name === undefined
      ? null
      : requireBoundedString(input.name, 'registration name', 1, MAX_ACCOUNT_NAME_LENGTH, true);
    const { response, body } = await this.requestBytes(
      await this.url('/identity/accounts/register/send-verification-email'),
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'content-type': 'application/json',
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
        },
        body: JSON.stringify({ email, name, receiveMarketingEmails: false }),
      },
      MAX_REGISTRATION_TOKEN_LENGTH,
      DEFAULT_RESPONSE_MAX_BYTES,
    );
    try {
      if (response.status === 404) return Object.freeze({ kind: 'legacy' });
      if (!response.ok) throw new ApiHttpError(response.status, parseBodyBytes(body));
      if (response.status === 204) {
        if (body.byteLength !== 0) throw new Error('registration start 204 response must be empty');
        return Object.freeze({ kind: 'email_required' });
      }
      if (response.status !== 200) throw new Error('registration start returned an unexpected status');
      const raw = decodeBodyBytes(body).trim();
      let token: unknown = raw;
      try {
        token = JSON.parse(raw) as unknown;
      } catch {
        // Self-hosted servers may return the opaque token as plain text.
      }
      if (typeof token !== 'string'
          || token.length === 0
          || token.length > MAX_REGISTRATION_TOKEN_LENGTH
          || token !== token.trim()
          || /\s/u.test(token)
          || containsAsciiControl(token)) {
        throw new Error('registration start returned an invalid token');
      }
      return Object.freeze({ kind: 'inline', emailVerificationToken: token });
    } finally {
      body.fill(0);
    }
  }

  /** Register a new account. All key material in `data` is derived client-side (zero-knowledge). */
  async register(data: RegisterRequest): Promise<void> {
    const normalizedEmail = normalizeDeviceLoginEmail(data.email);
    const masterPasswordHint = requireMasterPasswordHint(data.masterPasswordHint);
    const name = data.name === undefined
      ? undefined
      : requireBoundedString(data.name, 'registration name', 1, MAX_ACCOUNT_NAME_LENGTH, true);
    const emailVerificationToken = data.emailVerificationToken === undefined
      ? undefined
      : requireBoundedString(
          data.emailVerificationToken,
          'emailVerificationToken',
          1,
          MAX_REGISTRATION_TOKEN_LENGTH,
        );
    if (emailVerificationToken !== undefined && /\s/u.test(emailVerificationToken)) {
      throw new TypeError('emailVerificationToken contains invalid whitespace');
    }
    const kdf = {
      kdfType: data.kdf,
      iterations: data.kdfIterations,
      memory: data.kdf === 1 ? data.kdfMemory : null,
      parallelism: data.kdf === 1 ? data.kdfParallelism : null,
    };
    const modernBody = JSON.stringify({
      email: normalizedEmail,
      ...(emailVerificationToken === undefined ? {} : { emailVerificationToken }),
      masterPasswordHint,
      userAsymmetricKeys: data.keys,
      masterPasswordAuthentication: {
        salt: normalizedEmail,
        kdf,
        masterPasswordAuthenticationHash: data.masterPasswordHash,
      },
      masterPasswordUnlock: {
        salt: normalizedEmail,
        kdf,
        masterKeyWrappedUserKey: data.key,
      },
    });
    const legacyBody = JSON.stringify({
      email: normalizedEmail,
      ...(name === undefined ? {} : { name }),
      ...(emailVerificationToken === undefined ? {} : { emailVerificationToken }),
      masterPasswordHash: data.masterPasswordHash,
      key: data.key,
      keys: data.keys,
      kdf: data.kdf,
      kdfIterations: data.kdfIterations,
      ...(data.kdfMemory === undefined ? {} : { kdfMemory: data.kdfMemory }),
      ...(data.kdfParallelism === undefined ? {} : { kdfParallelism: data.kdfParallelism }),
      masterPasswordHint,
    });
    try {
      await this.noBodyRequest('/identity/accounts/register/finish', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: modernBody,
      });
    } catch (error) {
      // A missing route proves the first request could not have committed. Never retry any other
      // registration failure because its remote outcome may be ambiguous.
      if (!(error instanceof ApiHttpError) || error.status !== 404) throw error;
      await this.noBodyRequest('/identity/accounts/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: legacyBody,
      });
    }
  }

  /** Fetch a fresh anonymous account-passkey challenge from the fixed Identity endpoint. */
  async getAccountPasskeyAssertionOptions(): Promise<AccountPasskeyAssertionOptions> {
    const body = await this.jsonRequest<unknown>(
      '/identity/accounts/webauthn/assertion-options',
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
      },
      ACCOUNT_PASSKEY_OPTIONS_MAX_BYTES,
    );
    return parseAccountPasskeyAssertionOptions(body);
  }

  /** Redeem one assertion. The serializer deliberately excludes all client extension results. */
  async accountPasskeyLogin(input: AccountPasskeyLoginInput): Promise<AccountPasskeyLoginResult> {
    requireExactInputKeys(input, ACCOUNT_PASSKEY_LOGIN_INPUT_KEYS, 'account passkey login input');
    const token = requireBoundedString(input.token, 'account passkey token', 1, 64 * 1024);
    const deviceResponse = serializeAccountPasskeyAssertion(input.assertion);
    const form = await this.baseTokenForm();
    form.set('grant_type', 'webauthn');
    form.set('scope', 'api offline_access');
    form.set('token', token);
    form.set('deviceResponse', deviceResponse);
    const { response, body } = await this.tokenRequest(form, {
      maxResponseBytes: ACCOUNT_PASSKEY_TOKEN_MAX_BYTES,
      noStore: true,
    });
    if (response.ok) {
      return Object.freeze({ kind: 'success', data: parseAccountPasskeyLoginSuccess(body) });
    }
    if (response.status === 400) {
      const providers = parseAccountPasskeyTwoFactorProviders(body);
      if (providers) return Object.freeze({ kind: 'twoFactorUnsupported', providers });
    }
    throw new ApiHttpError(response.status, body);
  }

  /** Check whether this extension installation is already known for one account. */
  async isKnownDevice(input: KnownDeviceInput): Promise<boolean> {
    requireExactInputKeys(input, KNOWN_DEVICE_INPUT_KEYS, 'known-device input');
    const email = normalizeDeviceLoginEmail(input.email);
    const rawDeviceIdentifier = input.deviceIdentifier === undefined
      ? await this.getDeviceIdentifier()
      : input.deviceIdentifier;
    const deviceIdentifier = requireDeviceIdentifier(rawDeviceIdentifier);
    const response = await this.jsonRequest<unknown>('/api/devices/knowndevice', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      headers: {
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
        'Device-Type': DEVICE_TYPE,
        'Device-Identifier': deviceIdentifier,
        'X-Device-Identifier': deviceIdentifier,
        'X-Request-Email': bytesToBase64Url(utf8ToBytes(email)),
      },
    });
    if (typeof response !== 'boolean') {
      throw new Error('known-device response must be boolean');
    }
    return response;
  }

  /** Create an anonymous AuthenticateAndUnlock request for this known device. */
  async createAuthRequest(input: AuthRequestCreateInput): Promise<unknown> {
    const body = parseAuthRequestCreateInput(input);
    return requireAuthRequestResponse(await this.jsonRequest<unknown>('/api/auth-requests/', {
      method: 'POST',
      credentials: 'omit',
      headers: {
        'content-type': 'application/json',
        'Device-Type': DEVICE_TYPE,
        'Device-Identifier': body.deviceIdentifier,
      },
      body: JSON.stringify(body),
    }));
  }

  /** Read an anonymous auth-request response using its one-time access code. */
  async getAuthRequestResponse(requestId: string, accessCode: string): Promise<unknown> {
    const id = requireUuid(requestId, 'requestId');
    const code = requireBoundedString(
      accessCode,
      'accessCode',
      DEVICE_LOGIN_ACCESS_CODE_LENGTH,
      DEVICE_LOGIN_ACCESS_CODE_LENGTH,
    );
    const deviceIdentifier = requireDeviceIdentifier(await this.getDeviceIdentifier());
    const query = new URLSearchParams({ code });
    return requireAuthRequestResponse(await this.jsonRequest<unknown>(
      `/api/auth-requests/${encodeURIComponent(id)}/response?${query.toString()}`,
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
          'Device-Type': DEVICE_TYPE,
          'Device-Identifier': deviceIdentifier,
        },
      },
    ));
  }

  /** List pending requests visible to an authenticated approving device. */
  async listPendingAuthRequests(accessToken: string): Promise<unknown[]> {
    const token = requireAccessToken(accessToken);
    const response = await this.jsonRequest<unknown>('/api/auth-requests/pending', {
      method: 'GET',
      cache: 'no-store',
      credentials: 'omit',
      headers: {
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
        authorization: `Bearer ${token}`,
      },
    });
    return parseAuthRequestList(response);
  }

  /** Fetch one request visible to an authenticated approving device. */
  async getAuthRequest(accessToken: string, requestId: string): Promise<unknown> {
    const token = requireAccessToken(accessToken);
    const id = requireUuid(requestId, 'requestId');
    return requireAuthRequestResponse(await this.jsonRequest<unknown>(
      `/api/auth-requests/${encodeURIComponent(id)}`,
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
          authorization: `Bearer ${token}`,
        },
      },
    ));
  }

  /** Approve or deny one request. Denials send only Vaultwarden's required empty key field. */
  async updateAuthRequest(
    accessToken: string,
    requestId: string,
    input: AuthRequestUpdateInput,
  ): Promise<unknown> {
    const token = requireAccessToken(accessToken);
    const id = requireUuid(requestId, 'requestId');
    const body = parseAuthRequestUpdateInput(input);
    return requireAuthRequestResponse(await this.jsonRequest<unknown>(
      `/api/auth-requests/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        credentials: 'omit',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      },
    ));
  }

  async refresh(
    refreshToken: string,
    options: { readonly onGrantStarted?: () => void } = {},
  ): Promise<RefreshTokenResponse> {
    const form = await this.baseTokenForm();
    form.set('grant_type', 'refresh_token');
    form.set('refresh_token', refreshToken);
    const { response, body } = await this.tokenRequest(form, {
      ...(options.onGrantStarted ? { onGrantStarted: options.onGrantStarted } : {}),
    });
    if (!response.ok) throw new ApiHttpError(response.status, body);
    return parseRefreshTokenSuccess(body);
  }

  async sync(accessToken: string): Promise<SyncResponse> {
    return parseSyncResponse(await this.jsonRequest<unknown>('/api/sync', {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    }, SYNC_RESPONSE_MAX_BYTES));
  }

  /** Upload one canonical, bounded client-audit batch without retrying inside the transport. */
  async collectClientEvents(
    accessToken: string,
    events: readonly ClientEventWire[],
  ): Promise<ClientEventCollectResult> {
    const token = requireAccessToken(accessToken);
    const serialized = serializeClientEventBatch(events);
    const { response, body } = await this.requestBytes(
      await this.url('/api/events/collect'),
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${token}`,
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
        },
        body: serialized,
      },
      CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES,
      CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES,
    );
    if (response.ok) {
      try {
        if (body.byteLength !== 0) {
          throw new TypeError('Client event collection response must be empty');
        }
        return Object.freeze({ ok: true });
      } finally {
        body.fill(0);
      }
    }
    if (response.status === 401) {
      throw new ApiHttpError(response.status, parseBodyBytes(body));
    }
    body.fill(0);
    const retryAfter = parseClientEventRetryAfter(response.headers.get('retry-after'));
    return Object.freeze({
      ok: false,
      status: response.status,
      ...(retryAfter === undefined ? {} : { retryAfter }),
    });
  }

  /** Fetch this client's fixed server capability document without ambient credentials. */
  async getServerConfig(
    maxResponseBytes = SERVER_CONFIG_RESPONSE_MAX_BYTES,
  ): Promise<ServerConfigResponse> {
    assertServerConfigResponseLimit(maxResponseBytes);
    const serverUrl = canonicalizeServerCapabilityUrl(await this.resolveServerUrl());
    const { response, body } = await this.requestBytes(
      new URL('api/config', serverUrl).toString(),
      { method: 'GET', credentials: 'omit' },
      maxResponseBytes,
      maxResponseBytes,
    );
    const responseBytes = body.byteLength;
    if (!response.ok) {
      body.fill(0);
      throw new ApiHttpError(response.status, undefined);
    }
    return Object.freeze({ body: parseBodyBytes(body), responseBytes });
  }

  /** Create a folder. `encryptedName` is an encType=2 EncString of the folder name. */
  async createFolder(accessToken: string, encryptedName: string): Promise<FolderResponse> {
    return this.jsonRequest<FolderResponse>('/api/folders', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: encryptedName }),
    });
  }

  /** Rename a folder. `encryptedName` is an encType=2 EncString of the new name. */
  async updateFolder(accessToken: string, id: string, encryptedName: string): Promise<FolderResponse> {
    return this.jsonRequest<FolderResponse>(`/api/folders/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: encryptedName }),
    });
  }

  async deleteFolder(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/folders/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Create a collection in an org. `encryptedName` is an encType=2 EncString under the ORG key.
   *  groups/users are mandatory on Vaultwarden (empty is fine — an access-all manager still sees it). */
  async createCollection(
    accessToken: string,
    orgId: string,
    encryptedName: string,
    access: CollectionAccess = { groups: [], users: [] },
  ): Promise<CollectionResponse> {
    return this.jsonRequest<CollectionResponse>(`/api/organizations/${encodeURIComponent(orgId)}/collections`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        name: encryptedName,
        groups: access.groups,
        users: access.users,
        externalId: null,
      }),
    });
  }

  /** Fetch the complete collection state that must survive a whole-object update. */
  async getCollectionDetails(accessToken: string, orgId: string, id: string): Promise<CollectionAccessDetails> {
    return this.jsonRequest<CollectionAccessDetails>(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}/details`, {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Rename a collection while round-tripping its access assignments and external identity. */
  async updateCollection(accessToken: string, orgId: string, id: string, encryptedName: string, access: CollectionUpdateAccess): Promise<CollectionResponse> {
    return this.jsonRequest<CollectionResponse>(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        name: encryptedName,
        groups: access.groups,
        users: access.users,
        externalId: access.externalId,
      }),
    });
  }

  async deleteCollection(accessToken: string, orgId: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Set a cipher's collection membership. Return ignored; re-sync is the source of truth. */
  async updateCipherCollections(accessToken: string, id: string, collectionIds: string[]): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}/collections`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ collectionIds }),
    });
  }

  /** Create a personal cipher. `cipher` carries EncString field values. */
  async createCipher(accessToken: string, cipher: CipherRequest): Promise<CipherResponse> {
    return this.jsonRequest<CipherResponse>('/api/ciphers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(cipher),
    });
  }

  /** Rename without modifying group/user associations. Unsupported Vaultwarden versions reject the
   *  null association fields before mutating, which is safer than replaying a stale access snapshot. */
  async updateCollectionName(
    accessToken: string,
    orgId: string,
    id: string,
    encryptedName: string,
    externalId: string | null,
  ): Promise<CollectionResponse> {
    return this.jsonRequest<CollectionResponse>(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        name: encryptedName,
        groups: null,
        users: null,
        externalId,
      }),
    });
  }

  /** Atomically create a cipher whose fields are already encrypted with its organization key. */
  async createOrganizationCipher(
    accessToken: string,
    cipher: CipherRequest,
    collectionIds: readonly string[],
  ): Promise<CipherResponse> {
    const organizationId = requireBoundedString(
      cipher.organizationId,
      'organizationId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    const ids = requireCipherMutationIds(collectionIds, 'collectionIds');
    const body: OrganizationCipherCreateRequest = { cipher, collectionIds: ids };
    const response = await this.jsonRequest<unknown>('/api/ciphers/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
    const parsed = parseCipherMutationResponse(response, 'organization cipher create response');
    if (parsed.organizationId !== organizationId || parsed.type !== cipher.type) {
      throw new Error('organization cipher create response does not match the request target');
    }
    return parsed;
  }

  async updateCipher(accessToken: string, id: string, cipher: CipherRequest): Promise<CipherResponse> {
    return this.jsonRequest<CipherResponse>(`/api/ciphers/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(cipher),
    });
  }

  /** Update only the acting user's folder/favorite metadata for one accessible cipher. */
  async updateCipherPartial(
    accessToken: string,
    id: string,
    request: CipherPartialRequest,
  ): Promise<CipherResponse> {
    const cipherId = requireBoundedString(id, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const partial = parseCipherPartialRequest(request);
    const response = await this.jsonRequest<unknown>(
      `/api/ciphers/${encodeURIComponent(cipherId)}/partial`,
      {
        method: 'PUT',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
        body: JSON.stringify(partial),
      },
    );
    const parsed = parseCipherMutationResponse(response, 'cipher partial update response');
    if (
      parsed.id !== cipherId
      || parsed.favorite !== partial.favorite
      || (parsed.folderId ?? null) !== partial.folderId
    ) {
      throw new Error('cipher partial update response does not match the requested metadata');
    }
    return parsed;
  }

  /** Move a personal cipher into an organization and validate the authoritative 2xx target identity. */
  async shareCipher(
    accessToken: string,
    id: string,
    body: { cipher: CipherRequest; collectionIds: readonly string[] },
  ): Promise<CipherResponse> {
    const cipherId = requireBoundedString(id, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const organizationId = requireBoundedString(
      body.cipher.organizationId,
      'organizationId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    const collectionIds = requireCipherMutationIds(body.collectionIds, 'collectionIds');
    const response = await this.jsonRequest<unknown>(`/api/ciphers/${encodeURIComponent(cipherId)}/share`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ cipher: body.cipher, collectionIds }),
    });
    const parsed = parseCipherMutationResponse(response, 'cipher share response');
    if (parsed.id !== cipherId
      || parsed.organizationId !== organizationId
      || parsed.type !== body.cipher.type) {
      throw new Error('cipher share response does not match the request target');
    }
    return parsed;
  }

  /** Move a complete personal-vault batch into one organization in a single official request. */
  async shareCiphers(
    accessToken: string,
    request: CipherBulkShareRequest,
  ): Promise<readonly CipherResponse[] | undefined> {
    const normalized = parseCipherBulkShareRequest(request);
    const body = stringifyBoundedJson(
      normalized,
      'cipher bulk share request',
      MAX_CIPHER_BULK_SHARE_REQUEST_BYTES,
    );
    const { response, body: responseBytes } = await this.requestBytes(
      await this.url('/api/ciphers/share'),
      {
        method: 'PUT',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
        body,
      },
      MAX_CIPHER_BULK_SHARE_RESPONSE_BYTES,
      DEFAULT_RESPONSE_MAX_BYTES,
    );
    const responseBody = parseBodyBytes(responseBytes);
    if (!response.ok) throw new ApiHttpError(response.status, responseBody);
    // Vaultwarden currently returns an empty success body; the official server returns a list receipt.
    if (responseBody === '') return undefined;
    return parseCipherBulkShareResponse(responseBody, normalized.ciphers);
  }

  /** Revoke the current ODO member, falling back to Vaultwarden's equivalent leave endpoint. */
  async revokeCurrentOrganizationMembership(
    accessToken: string,
    organizationId: string,
  ): Promise<void> {
    const id = requireBoundedString(
      organizationId,
      'organizationId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    // Pin both attempts to the same resolved server; each fetch still runs the inherited request guard.
    const scoped = this.fixedServerUrl === undefined
      ? this.forServer(await this.resolveServerUrl())
      : this;
    try {
      await scoped.noBodyRequest(
        `/api/organizations/${encodeURIComponent(id)}/users/revoke-self`,
        { method: 'PUT', headers: { authorization: `Bearer ${accessToken}` } },
      );
    } catch (error) {
      if (!(error instanceof ApiHttpError) || error.status !== 404) throw error;
      await scoped.noBodyRequest(
        `/api/organizations/${encodeURIComponent(id)}/leave`,
        { method: 'POST', headers: { authorization: `Bearer ${accessToken}` } },
      );
    }
  }

  /** Hard-delete a cipher. */
  async deleteCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Soft-delete a cipher: move it to the trash (sets deletedDate server-side; recoverable). */
  async softDeleteCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}/delete`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Restore a cipher from the trash (clears deletedDate server-side). */
  async restoreCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}/restore`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Archive per-user cipher metadata in one official Bitwarden bulk request. */
  async archiveCiphers(
    accessToken: string,
    ids: readonly string[],
  ): Promise<readonly CipherResponse[]> {
    return this.mutateCipherArchiveState(accessToken, ids, 'archive');
  }

  /** Clear per-user archive metadata in one official Bitwarden bulk request. */
  async unarchiveCiphers(
    accessToken: string,
    ids: readonly string[],
  ): Promise<readonly CipherResponse[]> {
    return this.mutateCipherArchiveState(accessToken, ids, 'unarchive');
  }

  private async mutateCipherArchiveState(
    accessToken: string,
    ids: readonly string[],
    operation: 'archive' | 'unarchive',
  ): Promise<readonly CipherResponse[]> {
    const requestedIds = requireCipherMutationIds(ids, 'cipher ids');
    const body: CipherBulkIdsRequest = { ids: requestedIds };
    const response = await this.jsonRequest<unknown>(`/api/ciphers/${operation}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
    return parseCipherBulkMutationResponse(response, requestedIds, operation);
  }

  /** List the account's Sends. */
  async listSends(accessToken: string): Promise<SendResponse[]> {
    const res = await this.jsonRequest<{ data?: SendResponse[] }>('/api/sends', {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    return res.data ?? [];
  }

  /** Create a (text) Send. */
  async createSend(accessToken: string, send: SendRequest): Promise<SendResponse> {
    return this.jsonRequest<SendResponse>('/api/sends', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Create a file Send (v2): POST the metadata, get back where to upload the encrypted blob. */
  async createSendFile(accessToken: string, send: SendRequest): Promise<SendFileUploadResponse> {
    return this.jsonRequest<SendFileUploadResponse>('/api/sends/file/v2', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Upload the encrypted Send file blob to the URL returned by createSendFile (multipart, 204). The
   *  multipart filename is the encrypted file name, mirroring the attachment upload. */
  async uploadSendFileData(accessToken: string, url: string, data: Uint8Array, encryptedFileName: string): Promise<void> {
    const form = new FormData();
    form.append('data', new Blob([data as BlobPart], { type: 'application/octet-stream' }), encryptedFileName);
    if (/^https?:\/\//i.test(url)) {
      // Absolute upload URL (direct-blob storage): gate the bearer token to the configured base path.
      const sameServerPath = await this.isConfiguredServerPath(url);
      const { response, body } = await this.requestBytes(
        url,
        {
          method: 'POST',
          headers: sameServerPath ? { authorization: `Bearer ${accessToken}` } : {},
          body: form,
        },
        DEFAULT_RESPONSE_MAX_BYTES,
        DEFAULT_RESPONSE_MAX_BYTES,
        sameServerPath ? 'configured-server' : 'external',
      );
      if (!response.ok) throw new ApiHttpError(response.status, parseBodyBytes(body));
      body.fill(0);
      return;
    }
    const path = url.startsWith('/api') ? url : `/api${url}`;
    await this.noBodyRequest(path, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}` }, // no content-type: browser sets the multipart boundary
      body: form,
    });
  }

  /** Delete a Send. */
  async deleteSend(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/sends/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Update a Send's metadata (PUT). The send key is unchanged; the body carries the existing key. */
  async updateSend(accessToken: string, id: string, send: SendRequest): Promise<SendResponse> {
    return this.jsonRequest<SendResponse>(`/api/sends/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Remove a Send's password via the dedicated endpoint (PUT /api/sends/{id}/remove-password). */
  async removeSendPassword(accessToken: string, id: string): Promise<void> {
    await this.jsonRequest<SendResponse>(`/api/sends/${encodeURIComponent(id)}/remove-password`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: '{}',
    });
  }

  /** Resolve a fresh attachment URL through the authenticated account API. */
  async getAttachmentDownloadUrl(
    accessToken: string,
    cipherId: string,
    attachmentId: string,
  ): Promise<string> {
    const token = requireAccessToken(accessToken);
    const cipher = requireBoundedString(cipherId, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const attachment = requireBoundedString(
      attachmentId,
      'attachmentId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    const response = await this.jsonRequest<unknown>(
      `/api/ciphers/${encodeURIComponent(cipher)}/attachment/${encodeURIComponent(attachment)}`,
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
          authorization: `Bearer ${token}`,
        },
      },
      ATTACHMENT_METADATA_RESPONSE_MAX_BYTES,
    );
    return parseAttachmentDownloadResponse(response, attachment);
  }

  /** Download an attachment's encrypted blob from its (absolute) URL. */
  async downloadAttachment(
    url: string,
    accessToken: string,
    maxBytes = ATTACHMENT_RESPONSE_MAX_BYTES,
  ): Promise<Uint8Array> {
    assertAttachmentResponseLimit(maxBytes);
    // The URL comes from the sync response and may point off-origin (CDN/blob storage). Only attach the
    // bearer token inside the configured server base path so another backend cannot capture it.
    const target = parseAttachmentDownloadUrl(url);
    const base = parseServerBaseUrl(await this.resolveServerUrl());
    const sameServerPath = isWithinServerBasePath(target, base);
    if (target.protocol === 'http:' && (!sameServerPath || !isLoopbackHostname(base.hostname))) {
      throw new ApiInvalidDownloadUrlError();
    }
    const headers = sameServerPath ? { authorization: `Bearer ${accessToken}` } : {};
    const { response, body } = await this.requestBytes(
      target.toString(),
      { headers, credentials: 'omit' },
      maxBytes,
      DEFAULT_RESPONSE_MAX_BYTES,
      sameServerPath ? 'configured-server' : 'external',
    );
    if (!response.ok) throw new ApiHttpError(response.status, parseBodyBytes(body));
    return body;
  }

  /** Allocate a two-phase attachment upload slot and bind the receipt to its requested cipher. */
  async createAttachmentUploadSlot(
    accessToken: string,
    cipherId: string,
    request: AttachmentUploadRequest,
  ): Promise<AttachmentUploadSlotReceipt> {
    const token = requireAccessToken(accessToken);
    const cipher = requireBoundedString(cipherId, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const parsed = parseAttachmentUploadRequest(request);
    const response = await this.jsonRequest<unknown>(
      `/api/ciphers/${encodeURIComponent(cipher)}/attachment/v2`,
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'content-type': 'application/json',
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(parsed),
      },
      ATTACHMENT_METADATA_RESPONSE_MAX_BYTES,
    );
    return parseAttachmentUploadSlotResponse(response, cipher, parsed);
  }

  /** Upload encrypted bytes into a previously allocated attachment slot. */
  async uploadAttachmentSlotData(
    accessToken: string,
    cipherId: string,
    receipt: AttachmentUploadSlotReceipt,
    encryptedFileName: string,
    data: Uint8Array,
  ): Promise<void> {
    const token = requireAccessToken(accessToken);
    const cipher = requireBoundedString(cipherId, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const attachment = requireBoundedString(
      receipt.attachmentId,
      'attachmentId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    requireType2EncString(encryptedFileName, 'encryptedFileName', ATTACHMENT_METADATA_MAX_LENGTH);
    assertAttachmentUploadData(data);

    if (receipt.fileUploadType === 0) {
      const form = new FormData();
      form.append(
        'data',
        new Blob([data as BlobPart], { type: 'application/octet-stream' }),
        encryptedFileName,
      );
      await this.noBodyRequest(
        `/api/ciphers/${encodeURIComponent(cipher)}/attachment/${encodeURIComponent(attachment)}`,
        {
          method: 'POST',
          cache: 'no-store',
          credentials: 'omit',
          headers: {
            'Cache-Control': 'no-store',
            Pragma: 'no-cache',
            authorization: `Bearer ${token}`,
          },
          body: form,
        },
      );
      return;
    }

    if (receipt.fileUploadType !== 1) throw new TypeError('Unknown attachment file upload type');
    let uploadUrl = parseAttachmentUploadUrl(receipt.url).toString();
    if (attachmentUploadUrlNeedsRenewal(uploadUrl)) {
      uploadUrl = await this.renewAttachmentUploadUrl(token, cipher, attachment);
    }
    await this.putAzureAttachment(uploadUrl, data);
  }

  /** Resolve a fresh signed URL for an Azure attachment upload. */
  async renewAttachmentUploadUrl(
    accessToken: string,
    cipherId: string,
    attachmentId: string,
  ): Promise<string> {
    const token = requireAccessToken(accessToken);
    const cipher = requireBoundedString(cipherId, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const attachment = requireBoundedString(
      attachmentId,
      'attachmentId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    const response = await this.jsonRequest<unknown>(
      `/api/ciphers/${encodeURIComponent(cipher)}/attachment/${encodeURIComponent(attachment)}/renew`,
      {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
          authorization: `Bearer ${token}`,
        },
      },
      ATTACHMENT_METADATA_RESPONSE_MAX_BYTES,
    );
    return parseAttachmentUploadRenewResponse(response, cipher, attachment);
  }

  private async putAzureAttachment(url: string, data: Uint8Array): Promise<void> {
    const target = parseAttachmentUploadUrl(url);
    const version = target.searchParams.get('sv');
    if (!version || !/^\d{4}-\d{2}-\d{2}$/u.test(version)) {
      throw new ApiInvalidUploadUrlError();
    }
    const { response, body } = await this.requestBytes(
      target.toString(),
      {
        method: 'PUT',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'content-length': String(data.byteLength),
          'x-ms-blob-type': 'BlockBlob',
          'x-ms-date': new Date().toUTCString(),
          'x-ms-version': version,
        },
        body: data as unknown as BodyInit,
      },
      DEFAULT_RESPONSE_MAX_BYTES,
      DEFAULT_RESPONSE_MAX_BYTES,
      'external',
    );
    try {
      if (response.status !== 201) {
        throw new ApiHttpError(response.status, parseBodyBytes(body));
      }
    } finally {
      body.fill(0);
    }
  }

  /** Upload an encrypted attachment (legacy single-POST multipart, supported by Vaultwarden). The
   *  multipart file's filename is the encrypted file name (an EncString); `key` wraps the file key. */
  async uploadAttachment(accessToken: string, cipherId: string, params: { key: string; encryptedFileName: string; data: Uint8Array }): Promise<CipherResponse> {
    const token = requireAccessToken(accessToken);
    const cipher = requireBoundedString(cipherId, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const key = requireType2EncString(params.key, 'attachment key', ATTACHMENT_METADATA_MAX_LENGTH);
    const encryptedFileName = requireType2EncString(
      params.encryptedFileName,
      'encryptedFileName',
      ATTACHMENT_METADATA_MAX_LENGTH,
    );
    assertAttachmentUploadData(params.data);
    const form = new FormData();
    form.append('key', key);
    form.append('data', new Blob([params.data as BlobPart], { type: 'application/octet-stream' }), encryptedFileName);
    return this.jsonRequest<CipherResponse>(`/api/ciphers/${encodeURIComponent(cipher)}/attachment`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` }, // no content-type: the browser sets the multipart boundary
      body: form,
    });
  }

  /** Delete one attachment from a cipher. */
  async deleteAttachment(accessToken: string, cipherId: string, attachmentId: string): Promise<void> {
    const token = requireAccessToken(accessToken);
    const cipher = requireBoundedString(cipherId, 'cipherId', 1, MAX_CIPHER_ID_LENGTH);
    const attachment = requireBoundedString(
      attachmentId,
      'attachmentId',
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(cipher)}/attachment/${encodeURIComponent(attachment)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${token}` },
    });
  }

  /** Change the master password: the UserKey is re-wrapped under the new password (`key`); ciphers stay valid. */
  async changePassword(accessToken: string, body: {
    masterPasswordHash: string;
    newMasterPasswordHash: string;
    key: string;
    masterPasswordHint: string;
  }): Promise<void> {
    const masterPasswordHint = requireMasterPasswordHint(body.masterPasswordHint);
    await this.noBodyRequest('/api/accounts/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        masterPasswordHash: body.masterPasswordHash,
        newMasterPasswordHash: body.newMasterPasswordHash,
        key: body.key,
        masterPasswordHint,
      }),
    });
  }

  /** Change KDF settings: the UserKey is re-wrapped under the password re-derived with the new KDF. */
  async changeKdf(accessToken: string, body: ChangeKdfRequest): Promise<void> {
    await this.noBodyRequest('/api/accounts/kdf', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }

  async rotateAccountKey(accessToken: string, body: RotateKeyData): Promise<void> {
    await this.noBodyRequest('/api/accounts/key-management/rotate-user-account-keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }

  /** Replace an administrator-issued temporary password after local proof of decryption. */
  async updateTemporaryPassword(
    accessToken: string,
    body: { newMasterPasswordHash: string; key: string; masterPasswordHint: string },
  ): Promise<void> {
    const masterPasswordHint = requireMasterPasswordHint(body.masterPasswordHint);
    await this.noBodyRequest('/api/accounts/update-temp-password', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        newMasterPasswordHash: body.newMasterPasswordHash,
        key: body.key,
        masterPasswordHint,
      }),
    });
  }

  /**
   * Read every server-side unlock record that this client cannot yet re-wrap. The two list schemas
   * are parsed strictly: missing or future fields reject instead of being treated as an empty list.
   */
  async getKeyRotationUnlockRecordsStatus(
    accessToken: string,
  ): Promise<KeyRotationUnlockRecordsStatus> {
    const headers = { authorization: `Bearer ${accessToken}` };
    const [passkeys, devices] = await Promise.all([
      this.jsonRequest<unknown>('/api/webauthn', {
        method: 'GET',
        headers,
        cache: 'no-store',
      }),
      this.jsonRequest<unknown>('/api/devices', {
        method: 'GET',
        headers,
        cache: 'no-store',
      }),
    ]);
    const passkeyRecords = parseKeyRotationPasskeyRecords(passkeys);
    const deviceRecords = parseKeyRotationDeviceRecords(devices);
    return Object.freeze({
      passkeyUnlockData: passkeyRecords.some((record) => record.prfStatus === 0)
        ? 'present'
        : 'empty',
      deviceKeyUnlockData: deviceRecords.some((record) => record.isTrusted)
        ? 'present'
        : 'empty',
    });
  }

  /** Grants where THIS user is the grantor (people who can access my vault). Non-empty => rotation fails closed. */
  async getTrustedEmergencyAccess(accessToken: string): Promise<EmergencyAccessGrant[]> {
    const res = await this.jsonRequest<{ data?: EmergencyAccessGrant[] }>('/api/emergency-access/trusted', { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    return res.data ?? [];
  }

  async getOrganizationPublicKey(accessToken: string, orgId: string): Promise<OrgPublicKeyResponse> {
    return this.jsonRequest<OrgPublicKeyResponse>(`/api/organizations/${encodeURIComponent(orgId)}/keys`, { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
  }

  async getAccountPublicKey(accessToken: string): Promise<UserPublicKeyResponse> {
    return this.jsonRequest<UserPublicKeyResponse>('/api/accounts/keys', { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
  }

  /** Send a request that may return an empty body (DELETE endpoints); throws on a non-OK status. */
  private async noBodyRequest(path: string, init: RequestInit): Promise<void> {
    const { response, body } = await this.requestBytes(await this.url(path), init);
    if (!response.ok) {
      throw new ApiHttpError(response.status, parseBodyBytes(body));
    }
    body.fill(0);
  }

  async getDeviceIdentifier(): Promise<string> {
    if (!this.shared.deviceIdentifierPromise) {
      this.shared.deviceIdentifierPromise = this.loadOrCreateDeviceIdentifier().catch(error => {
        this.shared.deviceIdentifierPromise = undefined;
        throw error;
      });
    }
    return this.shared.deviceIdentifierPromise;
  }

  private async loadOrCreateDeviceIdentifier(): Promise<string> {
    const existing = await this.deps.localStore.get<string>(DEVICE_ID_KEY);
    if (existing) return existing;
    const id = crypto.randomUUID();
    await this.deps.localStore.set(DEVICE_ID_KEY, id);
    return id;
  }

  private async jsonRequest<T>(
    path: string,
    init: RequestInit,
    maxResponseBytes = DEFAULT_RESPONSE_MAX_BYTES,
  ): Promise<T> {
    const { response, body } = await this.requestBytes(
      await this.url(path),
      init,
      maxResponseBytes,
    );
    const text = decodeBodyBytes(body);

    if (!response.ok) {
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      throw new ApiHttpError(response.status, body);
    }

    return JSON.parse(text) as T;
  }

  /** Shared form for the two /identity/connect/token grants (password + refresh): device fields. */
  private async baseTokenForm(): Promise<URLSearchParams> {
    const form = new URLSearchParams();
    form.set('client_id', 'browser');
    form.set('deviceType', DEVICE_TYPE);
    form.set('deviceIdentifier', await this.getDeviceIdentifier());
    form.set('deviceName', DEVICE_NAME);
    return form;
  }

  /** POST a token grant and return the raw response + best-effort parsed body (each caller maps status). */
  private async tokenRequest(
    form: URLSearchParams,
    options: {
      readonly maxResponseBytes?: number;
      readonly noStore?: boolean;
      readonly onGrantStarted?: () => void | Promise<void>;
      readonly onGrantDispatched?: () => void;
    } = {},
  ): Promise<{ response: Response; body: unknown }> {
    const noStoreHeaders = options.noStore
      ? { 'Cache-Control': 'no-store', Pragma: 'no-cache' }
      : {};
    const { response, body } = await this.requestBytes(await this.url('/identity/connect/token'), {
      method: 'POST',
      ...(options.noStore ? { cache: 'no-store' as const, credentials: 'omit' as const } : {}),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...noStoreHeaders,
      },
      body: form.toString(),
    }, options.maxResponseBytes, options.maxResponseBytes, 'configured-server',
    options.onGrantStarted, options.onGrantDispatched);
    return { response, body: parseBodyBytes(body) };
  }

  private async identityTokenRequest(
    identityUrl: string,
    form: URLSearchParams,
    onGrantStarted?: () => void | Promise<void>,
    onGrantDispatched?: () => void,
  ): Promise<{ response: Response; body: unknown }> {
    const identity = await this.sameServerIdentityBase(identityUrl);
    const { response, body } = await this.requestBytes(
      new URL('connect/token', identity).toString(),
      {
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
        },
        body: form.toString(),
      },
      DEFAULT_RESPONSE_MAX_BYTES,
      DEFAULT_RESPONSE_MAX_BYTES,
      'configured-server',
      onGrantStarted,
      onGrantDispatched,
    );
    return { response, body: parseBodyBytes(body) };
  }

  private async sameServerIdentityBase(identityUrl: string): Promise<string> {
    const normalized = normalizeServerEnvironmentUrl(identityUrl);
    if (!normalized || normalized !== identityUrl) {
      throw new TypeError('identityUrl must be a canonical trusted environment URL');
    }
    const identity = parseServerBaseUrl(normalized);
    const server = parseServerBaseUrl(await this.resolveServerUrl());
    if (!isWithinServerBasePath(identity, server)) {
      throw new TypeError('Split-origin identity services are unavailable');
    }
    return identity.toString();
  }

  private async isConfiguredServerPath(url: string): Promise<boolean> {
    try {
      const target = new URL(url);
      const base = parseServerBaseUrl(await this.resolveServerUrl());
      return isWithinServerBasePath(target, base);
    } catch {
      return false;
    }
  }

  /** Fetch and consume a bounded response body under one request-wide deadline. */
  private async requestBytes(
    url: string,
    init: RequestInit,
    maxSuccessBytes = DEFAULT_RESPONSE_MAX_BYTES,
    maxErrorBytes = DEFAULT_RESPONSE_MAX_BYTES,
    scope: ApiRequestScope = 'configured-server',
    onRequestStarted?: () => void | Promise<void>,
    onRequestDispatched?: () => void,
  ): Promise<{ response: Response; body: Uint8Array }> {
    assertResponseLimit(maxSuccessBytes);
    assertResponseLimit(maxErrorBytes);
    const controller = new AbortController();
    const timeoutError = new ApiTimeoutError(REQUEST_TIMEOUT_MS);
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const headers = buildRequestHeaders(init.headers, scope);
      // This must stay synchronous and immediately adjacent to fetch. URL resolution, device-id
      // loading, and origin checks may all await; a session/server transition during any of them must
      // still prevent the request from leaving the process.
      this.requestGuard?.();
      const start = onRequestStarted?.();
      if (isPromiseLike(start)) {
        await start;
        this.requestGuard?.();
      }
      const deadline = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          controller.abort();
          reject(timeoutError);
        }, REQUEST_TIMEOUT_MS);
      });
      const request = this.fetchFn(url, { ...init, headers, redirect: 'error', signal: controller.signal });
      onRequestDispatched?.();
      const response = await Promise.race([
        request,
        deadline,
      ]);
      const body = await readResponseBytes(
        response,
        response.ok ? maxSuccessBytes : maxErrorBytes,
        controller.signal,
      );
      return { response, body };
    } catch (error) {
      if (timedOut || controller.signal.aborted) throw timeoutError;
      throw error;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async url(path: string): Promise<string> {
    const base = parseServerBaseUrl(await this.resolveServerUrl());
    return new URL(path.replace(/^\//, ''), base).toString();
  }

  private resolveServerUrl(): Promise<string> {
    return this.fixedServerUrl === undefined
      ? this.deps.serverUrlProvider()
      : Promise.resolve(this.fixedServerUrl);
  }
}

function buildRequestHeaders(headers: HeadersInit | undefined, scope: ApiRequestScope): HeadersInit {
  const normalized = new Headers(headers);
  normalized.delete(BITWARDEN_CLIENT_VERSION_HEADER);
  normalized.delete(BITWARDEN_CLIENT_NAME_HEADER);
  const result: Record<string, string> = {};
  normalized.forEach((value, name) => {
    result[name] = value;
  });
  if (scope === 'configured-server') {
    result[BITWARDEN_CLIENT_VERSION_HEADER] = BITWARDEN_CLIENT_VERSION;
    result[BITWARDEN_CLIENT_NAME_HEADER] = 'browser';
  }
  return result;
}

function isPromiseLike(value: void | Promise<void>): value is Promise<void> {
  return value !== undefined && typeof (value as PromiseLike<void>).then === 'function';
}

function parseServerBaseUrl(serverUrl: string): URL {
  if (!serverUrl.trim()) throw new Error('serverUrl cannot be blank');
  const url = new URL(serverUrl);
  if (url.search || url.hash || /[?#]/.test(url.href)) {
    throw new Error('serverUrl must not include query or fragment');
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url;
}

export class ApiHttpError extends Error {
  constructor(public readonly status: number, public readonly body: unknown) {
    super(`Vaultwarden API error ${status}`);
    this.name = 'ApiHttpError';
  }
}

export class ApiTimeoutError extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`Vaultwarden API request timed out after ${timeoutMs}ms`);
    this.name = 'ApiTimeoutError';
  }
}

export class ApiUnsupportedSsoAccountError extends Error {
  constructor() {
    super('This SSO account requires an unsupported vault decryption method.');
    this.name = 'ApiUnsupportedSsoAccountError';
  }
}

export class ApiResponseTooLargeError extends Error {
  constructor(
    public readonly maxBytes: number,
    public readonly receivedBytes: number,
  ) {
    super(`Vaultwarden API response exceeded the ${maxBytes}-byte limit`);
    this.name = 'ApiResponseTooLargeError';
  }
}

export class ApiInvalidDownloadUrlError extends Error {
  constructor() {
    super('Attachment download URL is not allowed');
    this.name = 'ApiInvalidDownloadUrlError';
  }
}

export class ApiInvalidUploadUrlError extends Error {
  constructor() {
    super('Attachment upload URL is not allowed');
    this.name = 'ApiInvalidUploadUrlError';
  }
}

function parseAttachmentUploadRequest(input: AttachmentUploadRequest): AttachmentUploadRequest {
  requireExactInputKeys(
    input,
    new Set(['key', 'fileName', 'fileSize', 'adminRequest', 'lastKnownRevisionDate']),
    'attachment upload request',
  );
  const key = requireType2EncString(input.key, 'attachment upload key', ATTACHMENT_METADATA_MAX_LENGTH);
  const fileName = requireType2EncString(
    input.fileName,
    'attachment upload fileName',
    ATTACHMENT_METADATA_MAX_LENGTH,
  );
  if (!Number.isSafeInteger(input.fileSize) || input.fileSize <= 0
      || input.fileSize > ATTACHMENT_RESPONSE_MAX_BYTES) {
    throw new TypeError('attachment upload fileSize is invalid');
  }
  if (input.adminRequest !== false) {
    throw new TypeError('attachment upload adminRequest must be false');
  }
  const lastKnownRevisionDate = input.lastKnownRevisionDate == null
    ? input.lastKnownRevisionDate
    : requireCipherDate(input.lastKnownRevisionDate, 'attachment upload lastKnownRevisionDate');
  return Object.freeze({ key, fileName, fileSize: input.fileSize, adminRequest: false,
    ...(lastKnownRevisionDate === undefined ? {} : { lastKnownRevisionDate }) });
}

function parseAttachmentUploadSlotResponse(
  input: unknown,
  expectedCipherId: string,
  request: AttachmentUploadRequest,
): AttachmentUploadSlotReceipt {
  const response = requireAttachmentUploadResponse(input, 'attachment upload slot response');
  const object = readOptionalAliasedField(
    response,
    'object',
    'Object',
    'attachment upload slot response',
  );
  if (object !== undefined && object !== 'attachment-fileUpload') {
    throw new Error('attachment upload slot response object is invalid');
  }
  const attachmentId = requireBoundedString(
    readRequiredAliasedField(
      response,
      'attachmentId',
      'AttachmentId',
      'attachment upload slot response',
    ),
    'attachment upload slot response attachmentId',
    1,
    MAX_CIPHER_ID_LENGTH,
  );
  const fileUploadType = readRequiredAliasedField(
    response,
    'fileUploadType',
    'FileUploadType',
    'attachment upload slot response',
  );
  if (fileUploadType !== 0 && fileUploadType !== 1) {
    throw new Error('attachment upload slot response fileUploadType is invalid');
  }
  const cipherInput = readRequiredAliasedField(
    response,
    'cipherResponse',
    'CipherResponse',
    'attachment upload slot response',
  );
  const miniInput = readOptionalAliasedField(
    response,
    'cipherMiniResponse',
    'CipherMiniResponse',
    'attachment upload slot response',
  );
  if (miniInput !== undefined && miniInput !== null) {
    throw new Error('attachment upload slot response unexpectedly contains cipherMiniResponse');
  }
  const cipherResponse = parseCipherMutationResponse(
    cipherInput,
    'attachment upload slot cipher response',
  );
  if (cipherResponse.id !== expectedCipherId) {
    throw new Error('attachment upload slot response cipher does not match the request');
  }
  assertAttachmentSlotMetadata(cipherResponse, attachmentId, request);

  const rawUrl = readOptionalAliasedField(
    response,
    'url',
    'Url',
    'attachment upload slot response',
  );
  if (fileUploadType === 0) {
    if (rawUrl !== undefined && rawUrl !== null
        && (typeof rawUrl !== 'string' || rawUrl.length > ATTACHMENT_URL_MAX_LENGTH)) {
      throw new Error('attachment upload slot response URL is invalid');
    }
    return Object.freeze({ attachmentId, fileUploadType, cipherResponse });
  }
  const url = parseAttachmentUploadUrl(requireBoundedString(
    rawUrl,
    'attachment upload slot response URL',
    1,
    ATTACHMENT_URL_MAX_LENGTH,
  )).toString();
  return Object.freeze({ attachmentId, fileUploadType, url, cipherResponse });
}

function parseAttachmentUploadRenewResponse(
  input: unknown,
  expectedCipherId: string,
  expectedAttachmentId: string,
): string {
  const response = requireAttachmentUploadResponse(input, 'attachment upload renew response');
  const object = readOptionalAliasedField(
    response,
    'object',
    'Object',
    'attachment upload renew response',
  );
  if (object !== undefined && object !== 'attachment-fileUpload') {
    throw new Error('attachment upload renew response object is invalid');
  }
  const attachmentId = readOptionalAliasedField(
    response,
    'attachmentId',
    'AttachmentId',
    'attachment upload renew response',
  );
  if (attachmentId !== undefined && requireBoundedString(
    attachmentId,
    'attachment upload renew response attachmentId',
    1,
    MAX_CIPHER_ID_LENGTH,
  ) !== expectedAttachmentId) {
    throw new Error('attachment upload renew response attachmentId does not match the request');
  }
  const uploadType = readOptionalAliasedField(
    response,
    'fileUploadType',
    'FileUploadType',
    'attachment upload renew response',
  );
  if (uploadType !== undefined && uploadType !== 1) {
    throw new Error('attachment upload renew response fileUploadType is invalid');
  }
  const cipherInput = readOptionalAliasedField(
    response,
    'cipherResponse',
    'CipherResponse',
    'attachment upload renew response',
  );
  if (cipherInput !== undefined && cipherInput !== null) {
    const cipher = parseCipherMutationResponse(
      cipherInput,
      'attachment upload renew cipher response',
    );
    if (cipher.id !== expectedCipherId) {
      throw new Error('attachment upload renew response cipher does not match the request');
    }
  }
  const miniInput = readOptionalAliasedField(
    response,
    'cipherMiniResponse',
    'CipherMiniResponse',
    'attachment upload renew response',
  );
  if (miniInput !== undefined && miniInput !== null) {
    throw new Error('attachment upload renew response unexpectedly contains cipherMiniResponse');
  }
  return parseAttachmentUploadUrl(requireBoundedString(
    readRequiredAliasedField(response, 'url', 'Url', 'attachment upload renew response'),
    'attachment upload renew response URL',
    1,
    ATTACHMENT_URL_MAX_LENGTH,
  )).toString();
}

function requireAttachmentUploadResponse(
  input: unknown,
  name: string,
): Record<string, unknown> {
  const response = requirePlainRecord(input, name);
  if (Object.getOwnPropertySymbols(response).length > 0
      || Object.keys(response).some((key) => !ATTACHMENT_UPLOAD_RESPONSE_KEYS.has(key))) {
    throw new Error(`${name} contains unsupported fields`);
  }
  return response;
}

function assertAttachmentSlotMetadata(
  cipher: CipherResponse,
  expectedAttachmentId: string,
  request: AttachmentUploadRequest,
): void {
  if (!Array.isArray(cipher.attachments)) {
    throw new Error('attachment upload slot cipher response is missing attachments');
  }
  const matches = cipher.attachments.filter((attachment) => attachment?.id === expectedAttachmentId);
  if (matches.length !== 1) {
    throw new Error('attachment upload slot cipher response does not contain the allocated attachment');
  }
  const attachment = matches[0]!;
  if (attachment.key !== request.key
      || attachment.fileName !== request.fileName
      || attachment.size !== String(request.fileSize)) {
    throw new Error('attachment upload slot metadata does not match the request');
  }
}

function assertAttachmentUploadData(data: Uint8Array): void {
  if (!(data instanceof Uint8Array)
      || data.byteLength < 50
      || data.byteLength > ATTACHMENT_RESPONSE_MAX_BYTES
      || data[0] !== 2) {
    throw new TypeError('attachment upload data is invalid');
  }
}

function parseAttachmentUploadUrl(value: string): URL {
  if (value.length === 0
      || value.length > ATTACHMENT_URL_MAX_LENGTH
      || value !== value.trim()
      || !/^https:\/\//iu.test(value)) {
    throw new ApiInvalidUploadUrlError();
  }
  let target: URL;
  try {
    target = new URL(value);
  } catch {
    throw new ApiInvalidUploadUrlError();
  }
  if (target.protocol !== 'https:'
      || target.username !== ''
      || target.password !== ''
      || hasAuthorityUserInfo(value)
      || value.includes('#')
      || target.toString().length > ATTACHMENT_URL_MAX_LENGTH) {
    throw new ApiInvalidUploadUrlError();
  }
  return target;
}

function attachmentUploadUrlNeedsRenewal(value: string): boolean {
  const expiry = new Date(new URL(value).searchParams.get('se') ?? '').getTime();
  return Number.isFinite(expiry) && expiry < Date.now() + 1_000;
}

function parseAttachmentDownloadResponse(input: unknown, expectedId: string): string {
  const response = requirePlainRecord(input, 'attachment download response');
  if (Object.getOwnPropertySymbols(response).length > 0) {
    throw new Error('attachment download response contains unsupported fields');
  }
  for (const key of Object.keys(response)) {
    if (!ATTACHMENT_DOWNLOAD_RESPONSE_KEYS.has(key)) {
      throw new Error('attachment download response contains unsupported fields');
    }
  }

  const id = requireBoundedString(
    readRequiredAliasedField(response, 'id', 'Id', 'attachment download response'),
    'attachment download response id',
    1,
    MAX_CIPHER_ID_LENGTH,
  );
  if (id !== expectedId) throw new Error('attachment download response id does not match the request');

  for (const [camelName, pascalName] of [
    ['fileName', 'FileName'],
    ['key', 'Key'],
    ['size', 'Size'],
    ['sizeName', 'SizeName'],
  ] as const) {
    const value = readOptionalAliasedField(
      response,
      camelName,
      pascalName,
      'attachment download response',
    );
    if (value !== undefined && value !== null && typeof value !== 'string') {
      throw new Error(`attachment download response ${camelName} must be a string or null`);
    }
  }
  const object = readOptionalAliasedField(
    response,
    'object',
    'Object',
    'attachment download response',
  );
  if (object !== undefined && object !== 'attachment') {
    throw new Error('attachment download response object must be attachment');
  }

  const url = requireBoundedString(
    readRequiredAliasedField(response, 'url', 'Url', 'attachment download response'),
    'attachment download response url',
    1,
    ATTACHMENT_URL_MAX_LENGTH,
  );
  return parseAttachmentDownloadUrl(url).toString();
}

function parseAttachmentDownloadUrl(value: string): URL {
  if (
    value.length === 0
    || value.length > ATTACHMENT_URL_MAX_LENGTH
    || value !== value.trim()
    || !/^https?:\/\//iu.test(value)
  ) {
    throw new ApiInvalidDownloadUrlError();
  }

  let target: URL;
  try {
    target = new URL(value);
  } catch {
    throw new ApiInvalidDownloadUrlError();
  }
  if (
    (target.protocol !== 'https:' && target.protocol !== 'http:')
    || target.username !== ''
    || target.password !== ''
    || hasAuthorityUserInfo(value)
    || value.includes('#')
    || target.toString().length > ATTACHMENT_URL_MAX_LENGTH
  ) {
    throw new ApiInvalidDownloadUrlError();
  }
  return target;
}

function hasAuthorityUserInfo(value: string): boolean {
  const authorityStart = value.indexOf('://') + 3;
  if (authorityStart < 3) return false;
  const remainder = value.slice(authorityStart);
  const authorityEnd = remainder.search(/[/?#]/u);
  return remainder.slice(0, authorityEnd < 0 ? remainder.length : authorityEnd).includes('@');
}

function isWithinServerBasePath(target: URL, base: URL): boolean {
  if (target.origin !== base.origin) return false;
  const basePath = base.pathname;
  return basePath === '/'
    || target.pathname === basePath.slice(0, -1)
    || target.pathname.startsWith(basePath);
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;
  if (normalized === '[::1]' || normalized === '::1') return true;
  const octets = normalized.split('.');
  return octets.length === 4
    && octets.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255)
    && octets[0] === '127';
}

async function readResponseBytes(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  const body = response.body;
  if (!body) return new Uint8Array();

  const declaredLength = parseContentLength(response.headers.get('content-length'));
  if (declaredLength !== undefined && declaredLength > maxBytes) {
    void body.cancel().catch(() => {});
    throw new ApiResponseTooLargeError(maxBytes, declaredLength);
  }

  const reader = body.getReader();
  let output: Uint8Array = new Uint8Array();
  let totalBytes = 0;
  let chunkCount = 0;
  let currentChunk: Uint8Array | undefined;
  let completed = false;
  let rejectAborted!: (reason: unknown) => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAborted = reject;
  });
  const onAbort = (): void => {
    rejectAborted(signal.reason ?? new DOMException('The operation was aborted.', 'AbortError'));
  };
  signal.addEventListener('abort', onAbort, { once: true });
  if (signal.aborted) onAbort();

  try {
    while (true) {
      const result = await Promise.race([reader.read(), aborted]);
      if (result.done) break;
      currentChunk = result.value;
      const nextTotal = totalBytes + currentChunk.byteLength;
      if (nextTotal > maxBytes) {
        throw new ApiResponseTooLargeError(maxBytes, nextTotal);
      }

      if (currentChunk.byteLength > 0) {
        output = growResponseBuffer(output, nextTotal, maxBytes);
        output.set(currentChunk, totalBytes);
        totalBytes = nextTotal;
        currentChunk.fill(0);
        currentChunk = undefined;
      }

      chunkCount += 1;
      if (chunkCount % 256 === 0) {
        // A hostile stream can resolve reads forever from queued zero-byte chunks, starving timers
        // through an endless microtask chain. Yield periodically so the hard deadline can fire.
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
        if (signal.aborted) onAbort();
      }
    }

    completed = true;
    return output.subarray(0, totalBytes);
  } catch (error) {
    currentChunk?.fill(0);
    output.fill(0);
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    signal.removeEventListener('abort', onAbort);
    if (completed) reader.releaseLock();
  }
}

function growResponseBuffer(buffer: Uint8Array, requiredBytes: number, maxBytes: number): Uint8Array {
  if (requiredBytes <= buffer.byteLength) return buffer;
  const initialCapacity = Math.min(64 * 1024, maxBytes);
  const nextCapacity = Math.min(
    maxBytes,
    Math.max(requiredBytes, buffer.byteLength === 0 ? initialCapacity : buffer.byteLength * 2),
  );
  const grown = new Uint8Array(nextCapacity);
  grown.set(buffer);
  buffer.fill(0);
  return grown;
}

function parseContentLength(value: string | null): number | undefined {
  if (value === null || !/^\d+$/.test(value.trim())) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
}

function decodeBodyBytes(body: Uint8Array): string {
  try {
    return new TextDecoder().decode(body);
  } finally {
    body.fill(0);
  }
}

function parseBodyBytes(body: Uint8Array): unknown {
  const text = decodeBodyBytes(body);
  if (!text) return text;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Project only Vaultwarden's exact default API-error envelope for password-hint outcomes. */
export function parsePasswordHintResponseBody(body: unknown): PasswordHintResult | undefined {
  try {
    const record = exactPasswordHintRecord(body, [
      'message',
      'validationErrors',
      'errorModel',
      'error',
      'error_description',
      'exceptionMessage',
      'exceptionStackTrace',
      'innerExceptionMessage',
      'object',
    ]);
    if (!record) return undefined;
    const errorModel = exactPasswordHintRecord(record.errorModel, ['message', 'object']);
    const validationErrors = exactPasswordHintRecord(record.validationErrors, ['']);
    const validationMessage = validationErrors?.[''];
    if (!errorModel
        || typeof record.message !== 'string'
        || record.message.length === 0
        || record.message.length > PASSWORD_HINT_MESSAGE_MAX_LENGTH
        || containsUnsafePasswordHintText(record.message)
        || errorModel.message !== record.message
        || errorModel.object !== 'error'
        || record.error !== ''
        || record.error_description !== ''
        || record.exceptionMessage !== null
        || record.exceptionStackTrace !== null
        || record.innerExceptionMessage !== null
        || record.object !== 'error'
        || !Array.isArray(validationMessage)
        || validationMessage.length !== 1
        || Reflect.ownKeys(validationMessage).length !== 2
        || Object.getOwnPropertyDescriptor(validationMessage, '0')?.value !== record.message
        || Object.getOwnPropertyDescriptor(validationMessage, 'length')?.value !== 1) {
      return undefined;
    }
    const message = record.message;
    if (message === PASSWORD_HINT_NONE) return Object.freeze({ status: 'no_hint' });
    if (message === PASSWORD_HINT_UNAVAILABLE) return Object.freeze({ status: 'unavailable' });
    if (message.startsWith(PASSWORD_HINT_PREFIX)
        && message.length > PASSWORD_HINT_PREFIX.length
        && message.trim() === message) {
      return Object.freeze({ status: 'hint', message });
    }
    return undefined;
  } catch {
    return undefined;
  }
}

function exactPasswordHintRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expectedKeys.length
      || keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))) {
    return undefined;
  }
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) return undefined;
  }
  return value as Record<string, unknown>;
}

function assertResponseLimit(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new RangeError('response maxBytes must be a positive safe integer');
  }
}

function assertAttachmentResponseLimit(maxBytes: number): void {
  assertResponseLimit(maxBytes);
  if (maxBytes > ATTACHMENT_RESPONSE_MAX_BYTES) {
    throw new RangeError(`attachment maxBytes cannot exceed ${ATTACHMENT_RESPONSE_MAX_BYTES}`);
  }
}

function assertServerConfigResponseLimit(maxBytes: number): void {
  assertResponseLimit(maxBytes);
  if (maxBytes > SERVER_CONFIG_RESPONSE_MAX_BYTES) {
    throw new RangeError(`server config maxBytes cannot exceed ${SERVER_CONFIG_RESPONSE_MAX_BYTES}`);
  }
}

function parsePasswordLoginResult(
  response: Response,
  body: unknown,
  allowNewDeviceVerification: true,
): PasswordLoginResult;
function parsePasswordLoginResult(
  response: Response,
  body: unknown,
  allowNewDeviceVerification: false,
): DeviceLoginResult;
function parsePasswordLoginResult(
  response: Response,
  body: unknown,
  allowNewDeviceVerification: boolean,
): PasswordLoginResult {
  if (response.ok) {
    return { kind: 'success', data: parseLoginTokenSuccess(body) };
  }

  if (response.status === 400 && isTwoFactorRequired(body)) {
    const responseRecord = requireTokenDataRecord(body, 'two-factor response');
    const providerMetadata = isRecord(body.TwoFactorProviders2)
      && !Array.isArray(body.TwoFactorProviders2)
      ? Object.freeze({ ...body.TwoFactorProviders2 })
      : undefined;
    const providers = [...new Set([
      ...readProviderIds(body.TwoFactorProviders),
      ...readProviderIds(providerMetadata),
    ])].sort((a, b) => a - b);
    const security = parseLoginSecurityFields(responseRecord, 'two-factor response');
    const emailValue = readOptionalAliasedField(
      responseRecord,
      'email',
      'Email',
      'two-factor response',
    );
    const ssoEmailSessionValue = readOptionalAliasedField(
      responseRecord,
      'ssoEmail2faSessionToken',
      'SsoEmail2faSessionToken',
      'two-factor response',
    );
    const email = emailValue === undefined
      ? undefined
      : normalizeDeviceLoginEmail(emailValue);
    const ssoEmail2FaSessionToken = ssoEmailSessionValue === undefined
      ? undefined
      : requireBoundedString(
          ssoEmailSessionValue,
          'SSO email two-factor session token',
          1,
          MAX_TWO_FACTOR_TOKEN_LENGTH,
        );
    return {
      kind: 'twoFactor',
      providers,
      ...(providerMetadata ? { providerMetadata } : {}),
      ...(body.TwoFactorToken !== undefined
        ? { token: requireBoundedString(
            body.TwoFactorToken,
            'two-factor continuation token',
            1,
            MAX_TWO_FACTOR_TOKEN_LENGTH,
          ) }
        : {}),
      ...(email ? { email } : {}),
      ...(ssoEmail2FaSessionToken ? { ssoEmail2FaSessionToken } : {}),
      ...security,
    };
  }
  if (allowNewDeviceVerification && isNewDeviceVerificationRequired(response, body)) {
    return { kind: 'newDeviceVerification' };
  }
  if (allowNewDeviceVerification && response.status === 400) {
    const organizationIdentifier = parseSsoRequiredIdentifier(body);
    if (organizationIdentifier) return { kind: 'ssoRequired', organizationIdentifier };
  }
  throw new ApiHttpError(response.status, body);
}

function parseSsoRequiredIdentifier(input: unknown): string | undefined {
  let record: Record<string, unknown>;
  try {
    record = requireTokenDataRecord(input, 'SSO-required response');
  } catch {
    return undefined;
  }
  const value = readOptionalAliasedField(
    record,
    'ssoOrganizationIdentifier',
    'SsoOrganizationIdentifier',
    'SSO-required response',
  );
  if (value === undefined || value === null) return undefined;
  const identifier = requireBoundedString(value, 'SSO organization identifier', 1, 256);
  if (!/^[A-Za-z0-9._~-]+$/u.test(identifier)) {
    throw new TypeError('SSO organization identifier is invalid');
  }
  return identifier;
}

function parseSsoLoginResult(response: Response, body: unknown): PasswordLoginResult {
  if (!response.ok) return parsePasswordLoginResult(response, body, false);
  return { kind: 'success', data: parseSsoLoginTokenSuccess(body) };
}

function parseSsoLoginTokenSuccess(input: unknown): Readonly<LoginSuccessResponse> {
  const record = requireTokenDataRecord(input, 'SSO token success response');
  const optionsValue = readOptionalAliasedField(
    record,
    'userDecryptionOptions',
    'UserDecryptionOptions',
    'SSO token success response',
  );
  let modernProtectedKey: unknown;
  let nestedKdf: KdfConfig | undefined;
  let masterKeySalt: string | undefined;
  if (optionsValue !== undefined && optionsValue !== null) {
    const options = requireTokenDataRecord(optionsValue, 'SSO user decryption options');
    const hasMasterPassword = readOptionalAliasedField(
      options,
      'hasMasterPassword',
      'HasMasterPassword',
      'SSO user decryption options',
    );
    if (hasMasterPassword !== undefined && typeof hasMasterPassword !== 'boolean') {
      throw new TypeError('SSO user decryption options hasMasterPassword must be boolean');
    }
    if (hasMasterPassword === false) throw new ApiUnsupportedSsoAccountError();
    const unlockValue = readOptionalAliasedField(
      options,
      'masterPasswordUnlock',
      'MasterPasswordUnlock',
      'SSO user decryption options',
    );
    if (unlockValue !== undefined && unlockValue !== null) {
      const unlock = requireTokenDataRecord(unlockValue, 'SSO master password unlock');
      const saltValue = readOptionalAliasedField(
        unlock,
        'salt',
        'Salt',
        'SSO master password unlock',
      );
      if (saltValue !== undefined) {
        masterKeySalt = normalizeDeviceLoginEmail(saltValue);
        if (saltValue !== masterKeySalt) {
          throw new TypeError('SSO master password salt is not canonical');
        }
      }
      const kdfValue = readOptionalAliasedField(
        unlock,
        'kdf',
        'Kdf',
        'SSO master password unlock',
      );
      if (kdfValue !== undefined && kdfValue !== null) nestedKdf = parseKdfConfig(kdfValue);
      const wrapped = readOptionalAliasedField(
        unlock,
        'masterKeyWrappedUserKey',
        'MasterKeyWrappedUserKey',
        'SSO master password unlock',
      );
      const encrypted = readOptionalAliasedField(
        unlock,
        'masterKeyEncryptedUserKey',
        'MasterKeyEncryptedUserKey',
        'SSO master password unlock',
      );
      if (wrapped !== undefined && encrypted !== undefined && wrapped !== encrypted) {
        throw new TypeError('SSO response contains conflicting wrapped user keys');
      }
      modernProtectedKey = wrapped ?? encrypted;
    }
  }

  const legacyProtectedKey = readOptionalAliasedField(
    record,
    'key',
    'Key',
    'SSO token success response',
  );
  if (
    legacyProtectedKey !== undefined
    && modernProtectedKey !== undefined
    && legacyProtectedKey !== modernProtectedKey
  ) {
    throw new TypeError('SSO response contains conflicting protected keys');
  }
  const protectedKey = legacyProtectedKey ?? modernProtectedKey;
  if (protectedKey === undefined) throw new ApiUnsupportedSsoAccountError();

  const topLevelHasKdf = [
    'Kdf', 'KdfIterations', 'KdfMemory', 'KdfParallelism',
    'kdf', 'kdfIterations', 'kdfMemory', 'kdfParallelism',
  ].some((key) => Object.hasOwn(record, key));
  const topLevelKdf = topLevelHasKdf ? parseKdfConfig(record) : undefined;
  if (nestedKdf && topLevelKdf && !sameKdfConfig(nestedKdf, topLevelKdf)) {
    throw new TypeError('SSO response contains conflicting KDF settings');
  }
  const kdf = nestedKdf ?? topLevelKdf;

  let modernPrivateKey: unknown;
  const accountKeysValue = readOptionalAliasedField(
    record,
    'accountKeys',
    'AccountKeys',
    'SSO token success response',
  );
  if (accountKeysValue !== undefined && accountKeysValue !== null) {
    const accountKeys = requireTokenDataRecord(accountKeysValue, 'SSO account keys');
    const pairValue = readOptionalAliasedField(
      accountKeys,
      'publicKeyEncryptionKeyPair',
      'PublicKeyEncryptionKeyPair',
      'SSO account keys',
    );
    if (pairValue !== undefined && pairValue !== null) {
      const pair = requireTokenDataRecord(pairValue, 'SSO public-key encryption key pair');
      modernPrivateKey = readOptionalAliasedField(
        pair,
        'wrappedPrivateKey',
        'WrappedPrivateKey',
        'SSO public-key encryption key pair',
      );
    }
  }
  const legacyPrivateKey = readOptionalAliasedField(
    record,
    'privateKey',
    'PrivateKey',
    'SSO token success response',
  );
  if (legacyPrivateKey !== undefined && modernPrivateKey !== undefined
      && legacyPrivateKey !== modernPrivateKey) {
    throw new TypeError('SSO response contains conflicting encrypted private keys');
  }
  return parseLoginTokenSuccess({
    ...record,
    Key: protectedKey,
    ...(kdf?.kdf === 0
      ? { Kdf: 0, KdfIterations: kdf.kdfIterations }
      : kdf?.kdf === 1
        ? {
            Kdf: 1,
            KdfIterations: kdf.kdfIterations,
            KdfMemory: kdf.kdfMemory,
            KdfParallelism: kdf.kdfParallelism,
          }
        : {}),
    ...(masterKeySalt ? { MasterKeySalt: masterKeySalt } : {}),
    ...((legacyPrivateKey ?? modernPrivateKey) === undefined
      ? {}
      : { PrivateKey: legacyPrivateKey ?? modernPrivateKey }),
  });
}

function isNewDeviceVerificationRequired(response: Response, body: unknown): boolean {
  if (response.status !== 400) return false;
  let record: Record<string, unknown>;
  let errorModel: Record<string, unknown>;
  try {
    record = requireTokenDataRecord(body, 'new device verification response');
    errorModel = requireTokenDataRecord(record.ErrorModel, 'new device verification error model');
  } catch {
    return false;
  }
  if (errorModel.Message !== NEW_DEVICE_VERIFICATION_REQUIRED_MESSAGE) return false;
  if (record.DeviceVerified !== undefined && record.DeviceVerified !== false) {
    throw new TypeError('new device verification response has an invalid verification state');
  }
  return true;
}

/** Validate and rebuild the OAuth refresh payload before any caller can persist it. */
export function parseRefreshTokenSuccess(input: unknown): Readonly<RefreshTokenResponse> {
  const record = requireTokenDataRecord(input, 'token success response');
  const accessToken = requireBoundedString(record.access_token, 'access token', 1, 64 * 1024);
  const refreshToken = requireBoundedString(record.refresh_token, 'refresh token', 1, 64 * 1024);
  const tokenType = requireBoundedString(record.token_type, 'token type', 1, 64);
  if (tokenType.toLowerCase() !== 'bearer') {
    throw new TypeError('token type must be Bearer');
  }
  if (!Number.isSafeInteger(record.expires_in) || (record.expires_in as number) <= 0) {
    throw new TypeError('token lifetime must be a positive safe integer');
  }
  const expiresIn = record.expires_in as number;
  if (!Number.isSafeInteger(expiresIn * 1_000)) {
    throw new TypeError('token lifetime is out of range');
  }
  return Object.freeze({
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: expiresIn,
    token_type: 'Bearer',
  });
}

/** Validate login-only key material and normalize optional KDF fields over the base token payload. */
export function parseLoginTokenSuccess(input: unknown): Readonly<LoginSuccessResponse> {
  const record = requireTokenDataRecord(input, 'login success response');
  const token = parseRefreshTokenSuccess(record);
  const protectedKey = requireType2EncString(record.Key, 'protected key', 64 * 1024);
  const encryptedPrivateKey = record.PrivateKey === undefined
    ? undefined
    : requireType2EncString(record.PrivateKey, 'encrypted private key', 64 * 1024);
  const rememberToken = record.TwoFactorToken === undefined
    ? undefined
    : requireBoundedString(record.TwoFactorToken, 'remember token', 1, MAX_TWO_FACTOR_TOKEN_LENGTH);
  const hasKdf = [
    'Kdf', 'KdfIterations', 'KdfMemory', 'KdfParallelism',
    'kdf', 'kdfIterations', 'kdfMemory', 'kdfParallelism',
    'kdfType', 'iterations', 'memory', 'parallelism',
  ].some((field) => Object.prototype.hasOwnProperty.call(record, field));
  const kdf = hasKdf ? parseKdfConfig(record) : undefined;
  const security = parseLoginSecurityFields(record, 'login success response');
  const masterKeySaltValue = readOptionalAliasedField(
    record,
    'masterKeySalt',
    'MasterKeySalt',
    'login success response',
  );
  const masterKeySalt = masterKeySaltValue === undefined
    ? undefined
    : normalizeDeviceLoginEmail(masterKeySaltValue);
  return Object.freeze({
    ...token,
    Key: protectedKey,
    ...(encryptedPrivateKey !== undefined ? { PrivateKey: encryptedPrivateKey } : {}),
    ...(kdf !== undefined ? toLoginResponseKdf(kdf) : {}),
    ...(rememberToken !== undefined ? { TwoFactorToken: rememberToken } : {}),
    ...(masterKeySalt !== undefined ? { MasterKeySalt: masterKeySalt } : {}),
    ...security,
  });
}

function parseLoginSecurityFields(
  record: Record<string, unknown>,
  owner: string,
): Pick<LoginSuccessResponse, 'forcePasswordReset' | 'masterPasswordPolicy'> {
  const rawForce = readOptionalAliasedField(
    record,
    'forcePasswordReset',
    'ForcePasswordReset',
    owner,
  );
  if (rawForce !== undefined && typeof rawForce !== 'boolean') {
    throw new TypeError(`${owner} forcePasswordReset must be boolean`);
  }
  const rawPolicy = readOptionalAliasedField(
    record,
    'masterPasswordPolicy',
    'MasterPasswordPolicy',
    owner,
  );
  const masterPasswordPolicy = parseMasterPasswordPolicy(rawPolicy);
  return Object.freeze({
    ...(rawForce === true ? { forcePasswordReset: true as const } : {}),
    ...(masterPasswordPolicy ? { masterPasswordPolicy } : {}),
  });
}

/** Convert a validated relative token lifetime into an absolute timestamp without numeric overflow. */
export function tokenExpiresAt(expiresIn: number, issuedAt: number): number {
  if (!Number.isSafeInteger(expiresIn) || expiresIn <= 0
      || !Number.isSafeInteger(issuedAt) || issuedAt < 0) {
    throw new TypeError('token lifetime or clock is invalid');
  }
  const lifetimeMs = expiresIn * 1_000;
  const expiresAt = issuedAt + lifetimeMs;
  if (!Number.isSafeInteger(lifetimeMs) || !Number.isSafeInteger(expiresAt)) {
    throw new TypeError('token expiration is out of range');
  }
  return expiresAt;
}

function toLoginResponseKdf(kdf: KdfConfig): Pick<
  LoginSuccessResponse,
  'Kdf' | 'KdfIterations' | 'KdfMemory' | 'KdfParallelism'
> {
  return kdf.kdf === 0
    ? { Kdf: 0, KdfIterations: kdf.kdfIterations }
    : {
        Kdf: 1,
        KdfIterations: kdf.kdfIterations,
        KdfMemory: kdf.kdfMemory,
        KdfParallelism: kdf.kdfParallelism,
      };
}

function requireType2EncString(input: unknown, name: string, maximumLength: number): string {
  const value = requireBoundedString(input, name, 1, maximumLength);
  let parsed: ReturnType<typeof parseEncString> | undefined;
  try {
    parsed = parseEncString(value);
    if (
      parsed.iv.byteLength !== 16
      || parsed.ct.byteLength === 0
      || parsed.ct.byteLength % 16 !== 0
      || parsed.mac.byteLength !== 32
      || `2.${bytesToBase64(parsed.iv)}|${bytesToBase64(parsed.ct)}|${bytesToBase64(parsed.mac)}` !== value
    ) {
      throw new TypeError(`${name} is not a canonical type-2 EncString`);
    }
  } catch {
    throw new TypeError(`${name} is not a canonical type-2 EncString`);
  } finally {
    parsed?.iv.fill(0);
    parsed?.ct.fill(0);
    parsed?.mac.fill(0);
  }
  return value;
}

function requireTokenDataRecord(input: unknown, name: string): Record<string, unknown> {
  const record = requirePlainRecord(input, name);
  for (const key of Reflect.ownKeys(record)) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError(`${name} must contain only enumerable data properties`);
    }
  }
  return record;
}

function parseAuthRequestCreateInput(input: AuthRequestCreateInput): AuthRequestCreateInput {
  requireExactInputKeys(input, AUTH_REQUEST_CREATE_INPUT_KEYS, 'auth request create input');
  if (input.type !== 0) throw new TypeError('auth request type must be AuthenticateAndUnlock');
  const publicKey = requireBoundedString(input.publicKey, 'publicKey', 1, MAX_PUBLIC_KEY_LENGTH);
  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = base64ToBytes(publicKey);
  } catch {
    throw new TypeError('publicKey must be canonical base64');
  }
  if (
    publicKeyBytes.byteLength < MIN_PUBLIC_KEY_BYTES
    || publicKeyBytes.byteLength > MAX_PUBLIC_KEY_BYTES
    || bytesToBase64(publicKeyBytes) !== publicKey
  ) {
    throw new TypeError('publicKey must be canonical base64');
  }
  return Object.freeze({
    email: normalizeDeviceLoginEmail(input.email),
    publicKey,
    deviceIdentifier: requireDeviceIdentifier(input.deviceIdentifier),
    accessCode: requireBoundedString(
      input.accessCode,
      'accessCode',
      DEVICE_LOGIN_ACCESS_CODE_LENGTH,
      DEVICE_LOGIN_ACCESS_CODE_LENGTH,
    ),
    type: 0,
  });
}

function parseAuthRequestUpdateInput(input: AuthRequestUpdateInput) {
  requireExactInputKeys(input, AUTH_REQUEST_UPDATE_INPUT_KEYS, 'auth request update input');
  if (typeof input.requestApproved !== 'boolean') {
    throw new TypeError('requestApproved must be boolean');
  }
  const deviceIdentifier = requireDeviceIdentifier(input.deviceIdentifier);
  if (!input.requestApproved) {
    const record = input as unknown as Record<string, unknown>;
    if ((record.key !== undefined && record.key !== '') || record.masterPasswordHash !== undefined) {
      throw new TypeError('denied auth request must not include key material');
    }
    return Object.freeze({ key: '', deviceIdentifier, requestApproved: false });
  }

  const key = requireAuthRequestKey(input.key);
  const masterPasswordHash = input.masterPasswordHash === undefined
    ? undefined
    : requireBoundedString(
        input.masterPasswordHash,
        'masterPasswordHash',
        1,
        MAX_MASTER_PASSWORD_HASH_LENGTH,
      );
  return Object.freeze({
    key,
    ...(masterPasswordHash !== undefined ? { masterPasswordHash } : {}),
    deviceIdentifier,
    requestApproved: true,
  });
}

function parsePasswordLoginInput(input: PasswordLoginInput): {
  readonly email: string;
  readonly masterPasswordHash: string;
  readonly twoFactor?: { readonly provider: number; readonly token: string; readonly remember: boolean };
  readonly newDeviceOtp?: string;
  readonly onGrantStarted?: () => void | Promise<void>;
  readonly onGrantDispatched?: () => void;
} {
  requireExactInputKeys(input, PASSWORD_LOGIN_INPUT_KEYS, 'password login input');
  const twoFactor = parseLoginTwoFactor(input);
  const newDeviceOtp = input.newDeviceOtp === undefined
    ? undefined
    : requireBoundedString(input.newDeviceOtp, 'newDeviceOtp', 1, MAX_NEW_DEVICE_OTP_LENGTH, true);
  assertGrantCallbacks(input.onGrantStarted, input.onGrantDispatched);
  return Object.freeze({
    email: normalizeDeviceLoginEmail(input.email),
    masterPasswordHash: requireBoundedString(
      input.masterPasswordHash,
      'masterPasswordHash',
      1,
      MAX_MASTER_PASSWORD_HASH_LENGTH,
    ),
    ...(twoFactor === undefined ? {} : { twoFactor }),
    ...(newDeviceOtp === undefined ? {} : { newDeviceOtp }),
    ...(input.onGrantStarted === undefined ? {} : { onGrantStarted: input.onGrantStarted }),
    ...(input.onGrantDispatched === undefined ? {} : { onGrantDispatched: input.onGrantDispatched }),
  });
}

function parseSsoTokenLoginInput(input: SsoTokenLoginInput): {
  readonly code: string;
  readonly codeVerifier: string;
  readonly redirectUri: string;
  readonly twoFactor?: { readonly provider: number; readonly token: string; readonly remember: boolean };
  readonly newDeviceOtp?: string;
  readonly onGrantStarted?: () => void | Promise<void>;
  readonly onGrantDispatched?: () => void;
} {
  requireExactInputKeys(input, SSO_TOKEN_LOGIN_INPUT_KEYS, 'SSO token login input');
  const code = requireBoundedString(input.code, 'SSO authorization code', 1, 64 * 1024);
  if (/\s/u.test(code)) throw new TypeError('SSO authorization code contains whitespace');
  const codeVerifier = requireBoundedString(input.codeVerifier, 'SSO code verifier', 43, 128);
  if (!/^[A-Za-z0-9._~-]+$/u.test(codeVerifier)) {
    throw new TypeError('SSO code verifier is not valid PKCE material');
  }
  const redirectUri = requireBoundedString(input.redirectUri, 'SSO redirect URI', 1, 4_096);
  const redirect = new URL(redirectUri);
  if (
    redirect.toString() !== redirectUri
    || redirect.username
    || redirect.password
    || redirect.search
    || redirect.hash
    || !redirect.pathname.endsWith('/sso-connector.html')
    || (redirect.protocol !== 'https:' && !(redirect.protocol === 'http:' && isLoopbackHostname(redirect.hostname)))
  ) {
    throw new TypeError('SSO redirect URI is invalid');
  }
  const twoFactor = parseLoginTwoFactor(input);
  const newDeviceOtp = input.newDeviceOtp === undefined
    ? undefined
    : requireBoundedString(input.newDeviceOtp, 'newDeviceOtp', 1, MAX_NEW_DEVICE_OTP_LENGTH, true);
  assertGrantCallbacks(input.onGrantStarted, input.onGrantDispatched);
  return Object.freeze({
    code,
    codeVerifier,
    redirectUri,
    ...(twoFactor === undefined ? {} : { twoFactor }),
    ...(newDeviceOtp === undefined ? {} : { newDeviceOtp }),
    ...(input.onGrantStarted === undefined ? {} : { onGrantStarted: input.onGrantStarted }),
    ...(input.onGrantDispatched === undefined ? {} : { onGrantDispatched: input.onGrantDispatched }),
  });
}

function assertGrantCallbacks(
  onGrantStarted: unknown,
  onGrantDispatched: unknown,
): void {
  if (onGrantStarted !== undefined && typeof onGrantStarted !== 'function') {
    throw new TypeError('onGrantStarted must be a function');
  }
  if (onGrantDispatched !== undefined && typeof onGrantDispatched !== 'function') {
    throw new TypeError('onGrantDispatched must be a function');
  }
}

function parseLoginTwoFactor(input: {
  readonly twoFactorProvider?: number;
  readonly twoFactorToken?: string;
  readonly remember?: boolean;
}): {
  provider: number;
  token: string;
  remember: boolean;
} | undefined {
  const hasProvider = input.twoFactorProvider !== undefined;
  const hasToken = input.twoFactorToken !== undefined;
  if (hasProvider !== hasToken) {
    throw new TypeError('two-factor provider and token must be provided together');
  }
  if (!hasProvider) {
    if (input.remember !== undefined) {
      throw new TypeError('remember requires two-factor credentials');
    }
    return undefined;
  }
  if (
    !Number.isInteger(input.twoFactorProvider)
    || input.twoFactorProvider! < 0
    || input.twoFactorProvider! > 255
  ) {
    throw new TypeError('twoFactorProvider must be an integer from 0 through 255');
  }
  if (input.remember !== undefined && typeof input.remember !== 'boolean') {
    throw new TypeError('remember must be boolean');
  }
  return Object.freeze({
    provider: input.twoFactorProvider!,
    token: requireBoundedString(
      input.twoFactorToken,
      'twoFactorToken',
      1,
      MAX_TWO_FACTOR_TOKEN_LENGTH,
    ),
    remember: input.remember ?? false,
  });
}

interface KeyRotationPasskeyRecord {
  readonly id: string;
  readonly prfStatus: 0 | 1 | 2;
}

interface KeyRotationDeviceRecord {
  readonly id: string;
  readonly isTrusted: boolean;
}

function parseKeyRotationPasskeyRecords(input: unknown): KeyRotationPasskeyRecord[] {
  return parseKeyRotationList(input, 'WebAuthn credentials').map((entry) => {
    const record = requirePlainRecord(entry, 'WebAuthn credential');
    const id = requireUuid(
      readRequiredAliasedField(record, 'id', 'Id', 'WebAuthn credential'),
      'WebAuthn credential id',
    );
    const prfStatus = readRequiredAliasedField(
      record,
      'prfStatus',
      'PrfStatus',
      'WebAuthn credential',
    );
    if (prfStatus !== 0 && prfStatus !== 1 && prfStatus !== 2) {
      throw new Error('WebAuthn credential has an unsupported PRF status');
    }

    const encryptedPublicKey = readOptionalAliasedField(
      record,
      'encryptedPublicKey',
      'EncryptedPublicKey',
      'WebAuthn credential',
    );
    const encryptedUserKey = readOptionalAliasedField(
      record,
      'encryptedUserKey',
      'EncryptedUserKey',
      'WebAuthn credential',
    );
    if (prfStatus === 0) {
      requireBoundedString(
        encryptedPublicKey,
        'WebAuthn encryptedPublicKey',
        1,
        MAX_ROTATION_ENCRYPTED_KEY_LENGTH,
      );
      requireBoundedString(
        encryptedUserKey,
        'WebAuthn encryptedUserKey',
        1,
        MAX_ROTATION_ENCRYPTED_KEY_LENGTH,
      );
    } else if (
      (encryptedPublicKey !== undefined && encryptedPublicKey !== null)
      || (encryptedUserKey !== undefined && encryptedUserKey !== null)
    ) {
      // A future server may add another key-bearing PRF state. Treat that as an unknown schema.
      throw new Error('WebAuthn credential has key data in a non-enabled PRF state');
    }
    return Object.freeze({ id, prfStatus });
  });
}

function parseKeyRotationDeviceRecords(input: unknown): KeyRotationDeviceRecord[] {
  return parseKeyRotationList(input, 'devices').map((entry) => {
    const record = requirePlainRecord(entry, 'device');
    const id = requireUuid(
      readRequiredAliasedField(record, 'id', 'Id', 'device'),
      'device id',
    );
    const isTrusted = readRequiredAliasedField(record, 'isTrusted', 'IsTrusted', 'device');
    if (typeof isTrusted !== 'boolean') throw new Error('device isTrusted must be boolean');
    return Object.freeze({ id, isTrusted });
  });
}

function parseKeyRotationList(input: unknown, name: string): unknown[] {
  const response = requirePlainRecord(input, `${name} response`);
  const data = readRequiredAliasedField(response, 'data', 'Data', `${name} response`);
  if (!Array.isArray(data)) throw new Error(`${name} response data must be an array`);
  const continuationToken = readOptionalAliasedField(
    response,
    'continuationToken',
    'ContinuationToken',
    `${name} response`,
  );
  if (continuationToken !== undefined && continuationToken !== null) {
    throw new Error(`${name} response is paginated and cannot prove a complete inventory`);
  }
  if (data.length > MAX_KEY_ROTATION_UNLOCK_RECORDS) {
    throw new Error(`${name} response contains too many records`);
  }
  return data;
}

function readRequiredAliasedField(
  record: Record<string, unknown>,
  camelName: string,
  pascalName: string,
  owner: string,
): unknown {
  const value = readOptionalAliasedField(record, camelName, pascalName, owner);
  if (value === undefined) throw new Error(`${owner} is missing ${camelName}`);
  return value;
}

function readOptionalAliasedField(
  record: Record<string, unknown>,
  camelName: string,
  pascalName: string,
  owner: string,
): unknown {
  const hasCamel = Object.prototype.hasOwnProperty.call(record, camelName);
  const hasPascal = Object.prototype.hasOwnProperty.call(record, pascalName);
  if (hasCamel && hasPascal) throw new Error(`${owner} contains duplicate ${camelName} fields`);
  if (hasCamel) return record[camelName];
  if (hasPascal) return record[pascalName];
  return undefined;
}

function parseAuthRequestList(input: unknown): unknown[] {
  const response = requirePlainRecord(input, 'pending auth requests response');
  const hasData = Object.prototype.hasOwnProperty.call(response, 'data');
  const hasPascalData = Object.prototype.hasOwnProperty.call(response, 'Data');
  if (hasData === hasPascalData) {
    throw new Error('pending auth requests response must contain exactly one data field');
  }
  const data = hasData ? response.data : response.Data;
  if (!Array.isArray(data)) {
    throw new Error('pending auth requests data must be an array');
  }
  if (data.length > MAX_PENDING_AUTH_REQUESTS) {
    throw new Error('pending auth requests response contains too many entries');
  }
  return data.map((entry) => requireAuthRequestResponse(entry));
}

function requireAuthRequestResponse(input: unknown): Readonly<Record<string, unknown>> {
  return Object.freeze({ ...requirePlainRecord(input, 'auth request response') });
}

function requirePlainRecord(input: unknown, name: string): Record<string, unknown> {
  if (!isRecord(input) || Array.isArray(input)) {
    throw new Error(`${name} must be a JSON object`);
  }
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${name} must be a plain object`);
  }
  return input;
}

function requireExactInputKeys(
  input: unknown,
  allowedKeys: ReadonlySet<string>,
  name: string,
): asserts input is Record<string, unknown> {
  const record = requirePlainRecord(input, name);
  if (Object.getOwnPropertySymbols(record).length > 0) {
    throw new TypeError(`${name} contains unsupported fields`);
  }
  for (const key of Object.keys(record)) {
    if (!allowedKeys.has(key)) throw new TypeError(`${name} contains unsupported fields`);
  }
}

function requireCipherMutationIds(input: readonly string[], name: string): string[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_CIPHER_MUTATION_IDS) {
    throw new TypeError(`${name} must contain between 1 and ${MAX_CIPHER_MUTATION_IDS} entries`);
  }
  if (Object.getOwnPropertySymbols(input).length > 0 || Object.keys(input).length !== input.length) {
    throw new TypeError(`${name} must be a dense array without extra fields`);
  }
  const ids = input.map((id, index) => requireBoundedString(
    id,
    `${name}[${index}]`,
    1,
    MAX_CIPHER_ID_LENGTH,
  ));
  if (new Set(ids).size !== ids.length) throw new TypeError(`${name} must not contain duplicates`);
  return ids;
}

function parseCipherPartialRequest(input: unknown): CipherPartialRequest {
  const record = requirePlainRecord(input, 'cipher partial update request');
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== CIPHER_PARTIAL_REQUEST_KEYS.size
    || keys.some((key) => typeof key !== 'string' || !CIPHER_PARTIAL_REQUEST_KEYS.has(key))
  ) {
    throw new TypeError('cipher partial update request must contain exactly folderId and favorite');
  }
  for (const key of CIPHER_PARTIAL_REQUEST_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError('cipher partial update request fields must be enumerable data properties');
    }
  }
  const folderId = record.folderId === null
    ? null
    : requireBoundedString(record.folderId, 'cipher partial update folderId', 1, MAX_CIPHER_ID_LENGTH);
  if (typeof record.favorite !== 'boolean') {
    throw new TypeError('cipher partial update favorite must be a boolean');
  }
  return Object.freeze({ folderId, favorite: record.favorite });
}

function parseCipherBulkShareRequest(input: CipherBulkShareRequest): CipherBulkShareRequest {
  requireExactInputKeys(input, CIPHER_BULK_SHARE_REQUEST_KEYS, 'cipher bulk share request');
  const encryptedFor = requireBoundedString(
    input.encryptedFor,
    'cipher bulk share encryptedFor',
    1,
    MAX_CIPHER_ID_LENGTH,
  );
  const collectionIds = requireCipherMutationIds(
    input.collectionIds,
    'cipher bulk share collectionIds',
  );
  if (!Array.isArray(input.ciphers)
      || input.ciphers.length === 0
      || input.ciphers.length > MAX_CIPHER_BULK_SHARE_COUNT) {
    throw new TypeError(
      `cipher bulk share ciphers must contain between 1 and ${MAX_CIPHER_BULK_SHARE_COUNT} entries`,
    );
  }
  if (Object.getOwnPropertySymbols(input.ciphers).length > 0
      || Object.keys(input.ciphers).length !== input.ciphers.length) {
    throw new TypeError('cipher bulk share ciphers must be a dense array without extra fields');
  }

  const seenIds = new Set<string>();
  let organizationId: string | undefined;
  const ciphers = input.ciphers.map((cipher, index): CipherWithIdRequest => {
    const name = `cipher bulk share ciphers[${index}]`;
    const rawCipher: unknown = cipher;
    requireExactInputKeys(rawCipher, CIPHER_BULK_SHARE_CIPHER_KEYS, name);
    const id = requireBoundedString(cipher.id, `${name} id`, 1, MAX_CIPHER_ID_LENGTH);
    if (seenIds.has(id)) throw new TypeError('cipher bulk share cipher ids must not contain duplicates');
    seenIds.add(id);
    const cipherOrganizationId = requireBoundedString(
      cipher.organizationId,
      `${name} organizationId`,
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    if (organizationId === undefined) organizationId = cipherOrganizationId;
    else if (organizationId !== cipherOrganizationId) {
      throw new TypeError('cipher bulk share ciphers must target one organization');
    }
    const cipherEncryptedFor = requireBoundedString(
      cipher.encryptedFor,
      `${name} encryptedFor`,
      1,
      MAX_CIPHER_ID_LENGTH,
    );
    if (cipherEncryptedFor !== encryptedFor) {
      throw new TypeError('cipher bulk share encryptedFor must match every cipher');
    }
    if (!Number.isSafeInteger(cipher.type) || cipher.type < 1 || cipher.type > 5) {
      throw new TypeError(`${name} type must be a supported cipher type`);
    }
    requireBoundedString(cipher.name, `${name} name`, 1, MAX_CIPHER_ENCRYPTED_NAME_LENGTH);
    return Object.freeze({ ...cipher, id, organizationId: cipherOrganizationId, encryptedFor });
  });
  return Object.freeze({
    ciphers: Object.freeze(ciphers),
    collectionIds: Object.freeze(collectionIds),
    encryptedFor,
  });
}

/** Validate and size-bound a bulk-share envelope without resolving a server or issuing I/O. */
export function assertCipherBulkShareRequest(input: CipherBulkShareRequest): void {
  stringifyBoundedJson(
    parseCipherBulkShareRequest(input),
    'cipher bulk share request',
    MAX_CIPHER_BULK_SHARE_REQUEST_BYTES,
  );
}

function parseCipherBulkShareResponse(
  input: unknown,
  requested: readonly CipherWithIdRequest[],
): readonly CipherResponse[] {
  const response = requirePlainRecord(input, 'cipher bulk share response');
  if (response.object !== undefined && response.object !== 'list') {
    throw new Error('cipher bulk share response object must be list');
  }
  if (response.continuationToken !== undefined && response.continuationToken !== null) {
    throw new Error('cipher bulk share response must not be paginated');
  }
  if (!Array.isArray(response.data) || response.data.length > requested.length) {
    throw new Error('cipher bulk share response data is not a request subset');
  }
  if (Object.getOwnPropertySymbols(response.data).length > 0
      || Object.keys(response.data).length !== response.data.length) {
    throw new Error('cipher bulk share response data must be a dense array without extra fields');
  }

  const expected = new Map(requested.map((cipher) => [cipher.id, cipher]));
  const seen = new Set<string>();
  const parsed = response.data.map((entry) => {
    const cipher = parseCipherMutationResponse(entry, 'cipher bulk share cipher response');
    const request = expected.get(cipher.id);
    if (!request || seen.has(cipher.id)) {
      throw new Error('cipher bulk share response contains an unexpected cipher id');
    }
    seen.add(cipher.id);
    if (cipher.organizationId !== request.organizationId || cipher.type !== request.type) {
      throw new Error('cipher bulk share response does not match the request target');
    }
    return cipher;
  });
  return Object.freeze(parsed);
}

function stringifyBoundedJson(input: unknown, name: string, maxBytes: number): string {
  const serialized = JSON.stringify(input);
  if (typeof serialized !== 'string') throw new TypeError(`${name} is not JSON serializable`);
  const bytes = new TextEncoder().encode(serialized);
  try {
    if (bytes.byteLength > maxBytes) {
      throw new RangeError(`${name} exceeds the ${maxBytes}-byte limit`);
    }
  } finally {
    bytes.fill(0);
  }
  return serialized;
}

function parseCipherBulkMutationResponse(
  input: unknown,
  requestedIds: readonly string[],
  operation: 'archive' | 'unarchive',
): readonly CipherResponse[] {
  const response = requirePlainRecord(input, `${operation} response`);
  if (response.object !== undefined && response.object !== 'list') {
    throw new Error(`${operation} response object must be list`);
  }
  if (response.continuationToken !== undefined && response.continuationToken !== null) {
    throw new Error(`${operation} response must not be paginated`);
  }
  if (!Array.isArray(response.data) || response.data.length !== requestedIds.length) {
    throw new Error(`${operation} response data does not match the request count`);
  }

  const expectedIds = new Set(requestedIds);
  const seenIds = new Set<string>();
  const parsed = response.data.map((entry) => {
    const cipher = parseCipherMutationResponse(entry, `${operation} cipher response`);
    if (!expectedIds.has(cipher.id) || seenIds.has(cipher.id)) {
      throw new Error(`${operation} response contains an unexpected cipher id`);
    }
    seenIds.add(cipher.id);
    if (operation === 'archive') {
      requireCipherDate(cipher.archivedDate, 'archive response archivedDate');
    } else if (cipher.archivedDate !== undefined && cipher.archivedDate !== null) {
      throw new Error('unarchive response retained archivedDate');
    }
    return cipher;
  });
  return Object.freeze(parsed);
}

function parseCipherMutationResponse(input: unknown, name: string): CipherResponse {
  const response = requirePlainRecord(input, name);
  const id = requireBoundedString(response.id, `${name} id`, 1, MAX_CIPHER_ID_LENGTH);
  if (!Number.isSafeInteger(response.type) || (response.type as number) <= 0) {
    throw new Error(`${name} type must be a positive safe integer`);
  }
  const organizationId = response.organizationId;
  if (organizationId !== undefined && organizationId !== null) {
    requireBoundedString(organizationId, `${name} organizationId`, 1, MAX_CIPHER_ID_LENGTH);
  }
  for (const field of ['archivedDate', 'deletedDate', 'creationDate', 'revisionDate'] as const) {
    const value = response[field];
    if (value !== undefined && value !== null) requireCipherDate(value, `${name} ${field}`);
  }
  return Object.freeze({ ...response, id, type: response.type as number }) as CipherResponse;
}

function requireCipherDate(input: unknown, name: string): string {
  const value = requireBoundedString(input, name, 1, MAX_CIPHER_DATE_LENGTH);
  if (!CIPHER_DATE_PATTERN.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new TypeError(`${name} must be an ISO date`);
  }
  return value;
}

function normalizeDeviceLoginEmail(input: unknown): string {
  const email = requireBoundedString(input, 'email', 3, MAX_EMAIL_LENGTH, true).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/u.test(email)) throw new TypeError('email is invalid');
  return email;
}

function normalizePasswordHintEmail(input: unknown): string {
  if (typeof input !== 'string' || containsAsciiControl(input)) {
    throw new TypeError('email contains invalid characters');
  }
  return normalizeDeviceLoginEmail(input);
}

function requireDeviceIdentifier(input: unknown): string {
  return requireBoundedString(input, 'deviceIdentifier', 1, MAX_DEVICE_IDENTIFIER_LENGTH);
}

function requireAuthRequestKey(input: unknown): string {
  const key = requireBoundedString(input, 'key', 1, MAX_AUTH_REQUEST_KEY_LENGTH);
  if (!key.startsWith('4.') || key.includes('|')) {
    throw new TypeError('key must be a canonical RSA EncString');
  }
  let ciphertext: Uint8Array;
  try {
    ciphertext = base64ToBytes(key.slice(2));
  } catch {
    throw new TypeError('key must be a canonical RSA EncString');
  }
  if (ciphertext.byteLength !== 256 || `4.${bytesToBase64(ciphertext)}` !== key) {
    throw new TypeError('key must be a canonical RSA EncString');
  }
  return key;
}

function requireAccessToken(input: unknown): string {
  return requireBoundedString(input, 'accessToken', 1, 64 * 1024);
}

function requireUuid(input: unknown, name: string): string {
  const value = requireBoundedString(input, name, 36, 36);
  if (!UUID_PATTERN.test(value)) throw new TypeError(`${name} must be a UUID`);
  return value.toLowerCase();
}

function requireBoundedString(
  input: unknown,
  name: string,
  minLength: number,
  maxLength: number,
  trim = false,
): string {
  if (typeof input !== 'string') throw new TypeError(`${name} must be a string`);
  const value = trim ? input.trim() : input;
  if (
    value.length < minLength
    || value.length > maxLength
    || (!trim && value !== value.trim())
    || containsAsciiControl(value)
  ) {
    throw new TypeError(`${name} has an invalid length or characters`);
  }
  return value;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function containsUnsafePasswordHintText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f
        || (code >= 0x7f && code <= 0x9f)
        || code === 0x061c
        || code === 0x200e
        || code === 0x200f
        || (code >= 0x2028 && code <= 0x202e)
        || (code >= 0x2066 && code <= 0x2069)
        || code === 0xfeff) return true;
  }
  return false;
}

function parseClientEventRetryAfter(value: string | null): string | undefined {
  if (value === null || value.length === 0 || value.length > 128
      || value.trim() !== value || containsAsciiControl(value)) return undefined;
  return value;
}

/** Detect optimistic-concurrency failures across Bitwarden and Vaultwarden response variants. */
export function isVaultConflictError(error: unknown): boolean {
  if (!(error instanceof ApiHttpError)) return false;
  if (error.status === 409 || error.status === 412) return true;
  if (error.status < 400 || error.status >= 500) return false;
  const text = collectErrorText(error.body).toLowerCase();
  return /revision|out[ -]of[ -]date|modified|updated since|newer (copy|version)|conflict/.test(text);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function collectErrorText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(collectErrorText).join(' ');
  if (!isRecord(value)) return '';
  return Object.values(value).map(collectErrorText).join(' ');
}

function isTwoFactorRequired(body: unknown): body is TwoFactorRequiredResponse {
  if (typeof body !== 'object' || body === null) return false;
  const candidate = body as Partial<TwoFactorRequiredResponse>;
  return candidate.error === 'invalid_grant'
    && typeof candidate.error_description === 'string'
    && candidate.error_description.toLowerCase().replace('-', ' ').includes('two factor')
    && (isProviderCollection(candidate.TwoFactorProviders)
      || isProviderCollection(candidate.TwoFactorProviders2));
}

function isProviderCollection(value: unknown): boolean {
  return Array.isArray(value) || (isRecord(value) && !Array.isArray(value));
}

function readProviderIds(value: unknown): number[] {
  const raw = Array.isArray(value)
    ? value
    : isRecord(value) && !Array.isArray(value)
      ? Object.keys(value)
      : [];
  return raw.flatMap((entry) => {
    if ((typeof entry !== 'string' && typeof entry !== 'number') || String(entry).trim() === '') return [];
    const provider = Number(entry);
    return Number.isInteger(provider) && provider >= 0 && provider <= 255 ? [provider] : [];
  });
}
