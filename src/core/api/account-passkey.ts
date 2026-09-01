import {
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  bytesToUtf8,
  constantTimeEqual,
} from '../crypto/encoding.js';
import { parseEncString, parseRsaEncString } from '../crypto/encstring.js';
import { parseKdfConfig, sameKdfConfig, type KdfConfig } from '../crypto/kdf.js';
import {
  parseMasterPasswordPolicy,
  type MasterPasswordPolicy,
} from '../policy/master-password-policy.js';

export const ACCOUNT_PASSKEY_OPTIONS_MAX_BYTES = 512 * 1024;
export const ACCOUNT_PASSKEY_TOKEN_MAX_BYTES = 1024 * 1024;

const MAX_TOKEN_LENGTH = 64 * 1024;
const MAX_RP_ID_LENGTH = 253;
const MAX_CREDENTIALS = 128;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_CHALLENGE_BYTES = 1024;
const MAX_CLIENT_DATA_BYTES = 16 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 4 * 1024;
const MAX_SIGNATURE_BYTES = 8 * 1024;
const MAX_USER_HANDLE_BYTES = 1024;
const MAX_ENC_STRING_LENGTH = 64 * 1024;
const MAX_ASSERTION_TIMEOUT_MS = 10 * 60 * 1000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const ALLOWED_TRANSPORTS = new Set<AuthenticatorTransport>([
  'ble', 'hybrid', 'internal', 'nfc', 'usb',
]);

export interface AccountPasskeyCredentialDescriptor {
  readonly id: string;
  readonly type: 'public-key';
  readonly transports?: readonly AuthenticatorTransport[];
}

export interface AccountPasskeyRequestOptions {
  readonly challenge: string;
  readonly timeout: number;
  readonly rpId: string;
  readonly allowCredentials: readonly AccountPasskeyCredentialDescriptor[];
  readonly userVerification: UserVerificationRequirement;
}

export interface AccountPasskeyAssertionOptions {
  readonly options: AccountPasskeyRequestOptions;
  /** Opaque, server-signed continuation token. It must never enter the connector page. */
  readonly token: string;
}

export interface AccountPasskeyAssertion {
  readonly id: string;
  readonly rawId: string;
  readonly type: 'public-key';
  readonly extensions: Readonly<Record<string, never>>;
  readonly response: {
    readonly authenticatorData: string;
    readonly signature: string;
    readonly clientDataJSON: string;
    readonly userHandle: string;
  };
}

/** JSON-safe result returned by the isolated connector. PRF output stays client-side. */
export interface AccountPasskeyConnectorResult {
  readonly assertion: AccountPasskeyAssertion;
  /** Mutable so the background parser can consume and overwrite the structured-cloned source. */
  readonly prfOutput?: number[];
}

export interface ParsedAccountPasskeyConnectorResult {
  readonly assertion: AccountPasskeyAssertion;
  readonly prfOutput?: Uint8Array;
}

export interface AccountPasskeyWebAuthnPrfOption {
  readonly encryptedPrivateKey: string;
  readonly encryptedUserKey: string;
  readonly credentialId: string;
  readonly transports: readonly AuthenticatorTransport[];
}

export interface AccountPasskeyLoginSuccess {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresIn: number;
  readonly tokenType: 'Bearer';
  readonly protectedKey: string;
  readonly encPrivateKey: string;
  readonly kdf: KdfConfig;
  readonly accountIdentity: string;
  readonly accountId: string;
  readonly rememberToken?: string;
  readonly webAuthnPrfOption?: AccountPasskeyWebAuthnPrfOption;
  readonly forcePasswordReset?: true;
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
}

export type AccountPasskeyLoginResult =
  | { readonly kind: 'success'; readonly data: AccountPasskeyLoginSuccess }
  | { readonly kind: 'twoFactorUnsupported'; readonly providers: readonly number[] };

/** Parse the anonymous assertion-options response into a frozen, bounded WebAuthn projection. */
export function parseAccountPasskeyAssertionOptions(input: unknown): AccountPasskeyAssertionOptions {
  const response = requirePlainRecord(input, 'account passkey assertion-options response');
  const options = requirePlainRecord(readRequired(response, 'options'), 'account passkey options');
  const status = readOptional(options, 'status');
  const errorMessage = readOptional(options, 'errorMessage');
  if (status !== undefined && status !== 'ok') {
    throw new Error('Account passkey options did not report a successful status');
  }
  if (errorMessage !== undefined && errorMessage !== '') {
    throw new Error('Account passkey options contain an error');
  }
  const extensions = readOptional(options, 'extensions');
  if (extensions !== undefined
      && Object.keys(requirePlainRecord(extensions, 'account passkey extensions')).length !== 0) {
    throw new Error('Server-provided account passkey extensions are not supported');
  }

  const allowCredentialsValue = readOptional(options, 'allowCredentials') ?? [];
  if (!Array.isArray(allowCredentialsValue) || allowCredentialsValue.length > MAX_CREDENTIALS) {
    throw new Error('Account passkey allowCredentials is invalid');
  }
  const allowCredentials = allowCredentialsValue.map(parseCredentialDescriptor);
  if (new Set(allowCredentials.map((credential) => credential.id)).size !== allowCredentials.length) {
    throw new Error('Account passkey options contain duplicate credential ids');
  }
  const objectName = readOptional(response, 'object');
  if (objectName !== undefined && objectName !== 'webAuthnLoginAssertionOptions') {
    throw new Error('Account passkey assertion-options object type is invalid');
  }

  return Object.freeze({
    options: Object.freeze({
      challenge: requireCanonicalBase64Url(
        readRequired(options, 'challenge'), 'account passkey challenge', 16, MAX_CHALLENGE_BYTES,
      ).encoded,
      timeout: requireInteger(
        readRequired(options, 'timeout'), 'account passkey timeout', 1, MAX_ASSERTION_TIMEOUT_MS,
      ),
      rpId: requireRpId(readRequired(options, 'rpId')),
      allowCredentials: Object.freeze(allowCredentials),
      userVerification: requireUserVerification(readRequired(options, 'userVerification')),
    }),
    token: requireBoundedString(
      readRequired(response, 'token'), 'account passkey continuation token', 1, MAX_TOKEN_LENGTH,
    ),
  });
}

/**
 * Parse and bind a connector result to the exact options and server origin. Signature validation is
 * performed by the server, while clientData and authenticatorData are checked here before sending.
 */
export async function parseAndBindAccountPasskeyConnectorResult(
  input: unknown,
  expected: AccountPasskeyRequestOptions,
  connectorOrigin: string,
): Promise<ParsedAccountPasskeyConnectorResult> {
  const record = requireExactRecord(input, ['assertion', 'prfOutput'], 'account passkey connector result');
  const prfOutput = record.prfOutput === undefined
    ? undefined
    : consumeAccountPasskeyPrfOutput(record.prfOutput);

  try {
    const assertion = parseAccountPasskeyAssertion(record.assertion);
    if (expected.allowCredentials.length > 0
        && !expected.allowCredentials.some((credential) => credential.id === assertion.id)) {
      throw new Error('Account passkey credential is not allowed by this attempt');
    }
    await assertClientData(assertion.response.clientDataJSON, expected.challenge, connectorOrigin);
    await assertAuthenticatorData(
      assertion.response.authenticatorData,
      expected.rpId,
      expected.userVerification,
    );
    return Object.freeze({ assertion, ...(prfOutput ? { prfOutput } : {}) });
  } catch (error) {
    prfOutput?.fill(0);
    throw error;
  }
}

/** Serialize exactly the official request projection. PRF output and unknown extensions cannot leak. */
export function serializeAccountPasskeyAssertion(input: AccountPasskeyAssertion): string {
  const assertion = parseAccountPasskeyAssertion(input);
  return JSON.stringify({
    id: assertion.id,
    rawId: assertion.rawId,
    type: assertion.type,
    extensions: {},
    response: {
      authenticatorData: assertion.response.authenticatorData,
      signature: assertion.response.signature,
      clientDataJSON: assertion.response.clientDataJSON,
      userHandle: assertion.response.userHandle,
    },
  });
}

/** Parse a successful grant using only identity claims returned by the fixed server. */
export function parseAccountPasskeyLoginSuccess(input: unknown): AccountPasskeyLoginSuccess {
  const response = requirePlainRecord(input, 'account passkey token response');
  const accessToken = requireBoundedString(
    readRequired(response, 'access_token'), 'account passkey access token', 1, MAX_TOKEN_LENGTH,
  );
  const identity = parseIdentityFromAccessToken(accessToken);
  const kdfType = readRequired(response, 'Kdf');
  if (kdfType !== 0 && kdfType !== 1) throw new Error('Account passkey KDF type is invalid');
  const kdf = parseKdfConfig(response);
  const userDecryptionValue = readOptional(response, 'UserDecryptionOptions');
  const userDecryption = userDecryptionValue === undefined
    ? undefined
    : requirePlainRecord(userDecryptionValue, 'account passkey user decryption options');
  if (userDecryption !== undefined && readRequired(userDecryption, 'HasMasterPassword') !== true) {
    throw new Error('Account passkey response cannot be unlocked with a master password');
  }
  const protectedKey = resolveProtectedKey(response, userDecryption, identity.email, kdf);
  const privateKey = resolvePrivateKey(response);
  const prfOption = userDecryption === undefined
    ? undefined
    : parseAccountPasskeyWebAuthnPrfOption(readOptional(userDecryption, 'WebAuthnPrfOption'));
  const tokenType = requireBoundedString(
    readRequired(response, 'token_type'), 'account passkey token type', 1, 64,
  );
  if (tokenType.toLowerCase() !== 'bearer') {
    throw new Error('Account passkey token type is not Bearer');
  }
  const rememberToken = readOptional(response, 'TwoFactorToken');
  const forcePasswordReset = readOptional(response, 'ForcePasswordReset');
  if (forcePasswordReset !== undefined && typeof forcePasswordReset !== 'boolean') {
    throw new Error('Account passkey forcePasswordReset must be boolean');
  }
  const masterPasswordPolicy = parseMasterPasswordPolicy(
    readOptional(response, 'MasterPasswordPolicy'),
  );

  return Object.freeze({
    accessToken,
    refreshToken: requireBoundedString(
      readRequired(response, 'refresh_token'), 'account passkey refresh token', 1, MAX_TOKEN_LENGTH,
    ),
    expiresIn: requireInteger(
      readRequired(response, 'expires_in'),
      'account passkey token lifetime',
      1,
      366 * 24 * 60 * 60,
    ),
    tokenType: 'Bearer',
    protectedKey,
    encPrivateKey: privateKey,
    kdf,
    accountIdentity: identity.email,
    accountId: identity.accountId,
    ...(rememberToken === undefined
      ? {}
      : {
          rememberToken: requireBoundedString(
            rememberToken, 'account passkey remember token', 1, MAX_TOKEN_LENGTH,
          ),
        }),
    ...(prfOption ? { webAuthnPrfOption: prfOption } : {}),
    ...(forcePasswordReset === true ? { forcePasswordReset: true as const } : {}),
    ...(masterPasswordPolicy ? { masterPasswordPolicy } : {}),
  });
}

/** Recognize the only non-success response that the first account-passkey version exposes. */
export function parseAccountPasskeyTwoFactorProviders(input: unknown): readonly number[] | undefined {
  if (!isRecord(input)) return undefined;
  const error = readOptional(input, 'error');
  const description = readOptional(input, 'error_description');
  if (error !== 'invalid_grant'
      || typeof description !== 'string'
      || !description.toLowerCase().replace(/-/gu, ' ').includes('two factor')) {
    return undefined;
  }
  const values = [
    ...providerIds(readOptional(input, 'TwoFactorProviders')),
    ...providerIds(readOptional(input, 'TwoFactorProviders2')),
  ];
  if (values.length === 0) return undefined;
  return Object.freeze([...new Set(values)].sort((left, right) => left - right));
}

function parseCredentialDescriptor(input: unknown): AccountPasskeyCredentialDescriptor {
  const record = requireExactRecord(
    input, ['id', 'type', 'transports'], 'account passkey credential descriptor',
  );
  if (record.type !== 'public-key') {
    throw new Error('Account passkey credential type is invalid');
  }
  const id = requireCanonicalBase64Url(
    record.id, 'account passkey credential id', 8, MAX_CREDENTIAL_ID_BYTES,
  ).encoded;
  const transports = record.transports === undefined
    ? undefined
    : parseTransports(record.transports, 'account passkey credential transports');
  return Object.freeze({ id, type: 'public-key', ...(transports ? { transports } : {}) });
}

function parseAccountPasskeyAssertion(input: unknown): AccountPasskeyAssertion {
  const record = requireExactRecord(
    input,
    ['id', 'rawId', 'type', 'extensions', 'response'],
    'account passkey assertion',
  );
  if (record.type !== 'public-key') throw new Error('Account passkey assertion type is invalid');
  const extensions = requirePlainRecord(record.extensions, 'account passkey assertion extensions');
  if (Object.keys(extensions).length !== 0) {
    throw new Error('Account passkey assertion extensions must be empty');
  }
  const id = requireCanonicalBase64Url(
    record.id, 'account passkey assertion id', 8, MAX_CREDENTIAL_ID_BYTES,
  ).encoded;
  const rawId = requireCanonicalBase64Url(
    record.rawId, 'account passkey assertion rawId', 8, MAX_CREDENTIAL_ID_BYTES,
  ).encoded;
  if (id !== rawId) throw new Error('Account passkey assertion id and rawId differ');
  const response = requireExactRecord(
    record.response,
    ['authenticatorData', 'signature', 'clientDataJSON', 'userHandle'],
    'account passkey assertion response',
  );
  return Object.freeze({
    id,
    rawId,
    type: 'public-key',
    extensions: Object.freeze({}),
    response: Object.freeze({
      authenticatorData: requireCanonicalBase64Url(
        response.authenticatorData,
        'account passkey authenticatorData',
        37,
        MAX_AUTHENTICATOR_DATA_BYTES,
      ).encoded,
      signature: requireCanonicalBase64Url(
        response.signature, 'account passkey signature', 1, MAX_SIGNATURE_BYTES,
      ).encoded,
      clientDataJSON: requireCanonicalBase64Url(
        response.clientDataJSON, 'account passkey clientDataJSON', 1, MAX_CLIENT_DATA_BYTES,
      ).encoded,
      userHandle: requireCanonicalBase64Url(
        response.userHandle, 'account passkey userHandle', 1, MAX_USER_HANDLE_BYTES,
      ).encoded,
    }),
  });
}

async function assertClientData(
  encoded: string,
  expectedChallenge: string,
  connectorOrigin: string,
): Promise<void> {
  let value: unknown;
  try {
    value = JSON.parse(bytesToUtf8(base64UrlToBytes(encoded))) as unknown;
  } catch {
    throw new Error('Account passkey clientDataJSON is invalid');
  }
  const data = requirePlainRecord(value, 'account passkey clientDataJSON');
  if (data.type !== 'webauthn.get' || data.challenge !== expectedChallenge) {
    throw new Error('Account passkey clientDataJSON is not bound to this challenge');
  }
  if (data.crossOrigin !== undefined && data.crossOrigin !== false) {
    throw new Error('Cross-origin account passkey assertions are not accepted');
  }
  if (data.origin !== canonicalOrigin(connectorOrigin)) {
    throw new Error('Account passkey assertion origin does not match the connector');
  }
}

async function assertAuthenticatorData(
  encoded: string,
  rpId: string,
  userVerification: UserVerificationRequirement,
): Promise<void> {
  const data = base64UrlToBytes(encoded);
  const expectedHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId) as BufferSource),
  );
  if (!constantTimeEqual(data.subarray(0, 32), expectedHash)) {
    throw new Error('Account passkey authenticatorData has the wrong RP ID hash');
  }
  const flags = data[32]!;
  if ((flags & 0x01) === 0) throw new Error('Account passkey assertion lacks user presence');
  if (userVerification === 'required' && (flags & 0x04) === 0) {
    throw new Error('Account passkey assertion lacks required user verification');
  }
}

function resolveProtectedKey(
  response: Record<string, unknown>,
  userDecryption: Record<string, unknown> | undefined,
  email: string,
  responseKdf: KdfConfig,
): string {
  const legacy = readOptional(response, 'Key');
  const unlockValue = userDecryption === undefined
    ? undefined
    : readOptional(userDecryption, 'MasterPasswordUnlock');
  let modern: string | undefined;
  if (unlockValue !== undefined && unlockValue !== null) {
    const unlock = requirePlainRecord(unlockValue, 'master password unlock option');
    const salt = normalizeEmail(readRequired(unlock, 'Salt'));
    if (salt !== email) throw new Error('Master password unlock salt does not match the account');
    const partialUnlockKdf = requirePlainRecord(
      readRequired(unlock, 'Kdf'),
      'master password unlock KDF',
    );
    const inheritedKdf = responseKdf.kdf === 0
      ? { kdf: 0, kdfIterations: responseKdf.kdfIterations }
      : {
          kdf: 1,
          kdfIterations: responseKdf.kdfIterations,
          kdfMemory: responseKdf.kdfMemory,
          kdfParallelism: responseKdf.kdfParallelism,
        };
    const unlockKdf = parseKdfConfig({ ...inheritedKdf, ...partialUnlockKdf });
    if (!sameKdfConfig(unlockKdf, responseKdf)) {
      throw new Error('Master password unlock KDF differs from the token response');
    }
    modern = requireBoundedString(
      readRequired(unlock, 'MasterKeyEncryptedUserKey'),
      'master-key-wrapped user key',
      1,
      MAX_ENC_STRING_LENGTH,
    );
  }
  if (legacy !== undefined && modern !== undefined && legacy !== modern) {
    throw new Error('Conflicting master-key-wrapped user keys');
  }
  const protectedKey = requireBoundedString(
    modern ?? legacy, 'account passkey protected key', 1, MAX_ENC_STRING_LENGTH,
  );
  validateSymmetricEncString(protectedKey, 'account passkey protected key');
  return protectedKey;
}

function resolvePrivateKey(response: Record<string, unknown>): string {
  const legacy = readOptional(response, 'PrivateKey');
  const accountKeysValue = readOptional(response, 'AccountKeys');
  let modern: unknown;
  if (accountKeysValue !== undefined && accountKeysValue !== null) {
    const accountKeys = requirePlainRecord(accountKeysValue, 'account keys');
    const pair = requirePlainRecord(
      readRequired(accountKeys, 'publicKeyEncryptionKeyPair'),
      'account public-key encryption key pair',
    );
    modern = readRequired(pair, 'wrappedPrivateKey');
  }
  if (legacy !== undefined && modern !== undefined && legacy !== modern) {
    throw new Error('Conflicting encrypted account private keys');
  }
  if (legacy === undefined && modern === undefined) {
    throw new Error('Account passkey response is missing the encrypted account private key');
  }
  const privateKey = requireBoundedString(
    modern ?? legacy, 'encrypted account private key', 1, MAX_ENC_STRING_LENGTH,
  );
  validateSymmetricEncString(privateKey, 'encrypted account private key');
  return privateKey;
}

export function parseAccountPasskeyWebAuthnPrfOption(
  input: unknown,
): AccountPasskeyWebAuthnPrfOption | undefined {
  if (input === undefined || input === null) return undefined;
  const option = requirePlainRecord(input, 'account passkey PRF option');
  const encryptedPrivateKey = requireBoundedString(
    readRequired(option, 'EncryptedPrivateKey'),
    'account passkey PRF encrypted private key',
    1,
    MAX_ENC_STRING_LENGTH,
  );
  validateSymmetricEncString(encryptedPrivateKey, 'account passkey PRF encrypted private key');
  const encryptedUserKey = requireBoundedString(
    readRequired(option, 'EncryptedUserKey'),
    'account passkey PRF encrypted user key',
    1,
    MAX_ENC_STRING_LENGTH,
  );
  validateRsaEncString(encryptedUserKey, 'account passkey PRF encrypted user key');
  return Object.freeze({
    encryptedPrivateKey,
    encryptedUserKey,
    credentialId: requireCanonicalBase64Url(
      readRequired(option, 'CredentialId'),
      'account passkey PRF credential id',
      8,
      MAX_CREDENTIAL_ID_BYTES,
    ).encoded,
    transports: parseTransports(
      readOptional(option, 'Transports') ?? [], 'account passkey PRF transports',
    ),
  });
}

function consumeAccountPasskeyPrfOutput(input: unknown): Uint8Array {
  if (!Array.isArray(input) || input.length !== 32) {
    throw new Error('Account passkey PRF output must contain exactly 32 bytes');
  }
  const bytes = new Uint8Array(32);
  let valid = true;
  let sourceCleared: boolean;
  for (let index = 0; index < input.length; index += 1) {
    const value = input[index];
    if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 255) {
      valid = false;
    } else {
      bytes[index] = value as number;
    }
  }
  try {
    for (let index = 0; index < input.length; index += 1) input[index] = 0;
    sourceCleared = input.every((value) => value === 0);
  } catch {
    sourceCleared = false;
  }
  if (!valid || !sourceCleared || bytes.every((value) => value === 0)) {
    bytes.fill(0);
    throw new Error('Account passkey PRF output is invalid');
  }
  return bytes;
}

function parseIdentityFromAccessToken(token: string): { email: string; accountId: string } {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => !isCanonicalBase64Url(part, 1, MAX_TOKEN_LENGTH))) {
    throw new Error('Account passkey access token is not a canonical JWT');
  }
  let claims: unknown;
  try {
    claims = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[1]!))) as unknown;
  } catch {
    throw new Error('Account passkey access token claims are invalid');
  }
  const record = requirePlainRecord(claims, 'account passkey access token claims');
  const accountId = requireBoundedString(record.sub, 'account id', 36, 36).toLowerCase();
  if (!UUID_PATTERN.test(accountId)) throw new Error('Account passkey access token account id is invalid');
  return Object.freeze({ email: normalizeEmail(record.email), accountId });
}

function normalizeEmail(input: unknown): string {
  const email = requireBoundedString(input, 'account email', 3, 254, true).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/u.test(email)) throw new Error('Account email is invalid');
  return email;
}

function validateSymmetricEncString(value: string, name: string): void {
  let parsed;
  try {
    parsed = parseEncString(value);
  } catch {
    throw new Error(`${name} is not a canonical encType=2 EncString`);
  }
  if (
    parsed.iv.byteLength !== 16
    || parsed.ct.byteLength === 0
    || parsed.ct.byteLength % 16 !== 0
    || parsed.mac.byteLength !== 32
    || `2.${bytesToBase64(parsed.iv)}|${bytesToBase64(parsed.ct)}|${bytesToBase64(parsed.mac)}` !== value
  ) {
    throw new Error(`${name} is not a canonical encType=2 EncString`);
  }
}

function validateRsaEncString(value: string, name: string): void {
  let parsed;
  try {
    parsed = parseRsaEncString(value);
  } catch {
    throw new Error(`${name} is not a canonical RSA EncString`);
  }
  if (
    (parsed.encType !== 3 && parsed.encType !== 4)
    || parsed.data.byteLength !== 256
    || `${parsed.encType}.${bytesToBase64(parsed.data)}` !== value
  ) {
    throw new Error(`${name} is not a canonical RSA EncString`);
  }
}

function parseTransports(input: unknown, name: string): readonly AuthenticatorTransport[] {
  if (!Array.isArray(input) || input.length > ALLOWED_TRANSPORTS.size) {
    throw new Error(`${name} is invalid`);
  }
  const transports = input.map((value) => {
    if (typeof value !== 'string' || !ALLOWED_TRANSPORTS.has(value as AuthenticatorTransport)) {
      throw new Error(`${name} contains an unsupported transport`);
    }
    return value as AuthenticatorTransport;
  });
  if (new Set(transports).size !== transports.length) {
    throw new Error(`${name} contains duplicate transports`);
  }
  return Object.freeze(transports);
}

function providerIds(input: unknown): number[] {
  const values = Array.isArray(input)
    ? input
    : isRecord(input) && !Array.isArray(input)
      ? Object.keys(input)
      : [];
  if (values.length > 256) return [];
  return values.flatMap((value) => {
    if ((typeof value !== 'string' && typeof value !== 'number') || String(value).trim() === '') return [];
    const provider = Number(value);
    return Number.isInteger(provider) && provider >= 0 && provider <= 255 ? [provider] : [];
  });
}

function requireUserVerification(input: unknown): UserVerificationRequirement {
  if (input !== 'required' && input !== 'preferred' && input !== 'discouraged') {
    throw new Error('Account passkey userVerification is invalid');
  }
  return input;
}

function requireRpId(input: unknown): string {
  const value = requireBoundedString(input, 'account passkey rpId', 1, MAX_RP_ID_LENGTH).toLowerCase();
  if (value.endsWith('.') || value.includes(':') || value.includes('/') || value.includes('@')) {
    throw new Error('Account passkey rpId is invalid');
  }
  let parsed: URL;
  try {
    parsed = new URL(`https://${value}/`);
  } catch {
    throw new Error('Account passkey rpId is invalid');
  }
  if (parsed.hostname !== value || parsed.host !== value || parsed.pathname !== '/') {
    throw new Error('Account passkey rpId is invalid');
  }
  return value;
}

function requireCanonicalBase64Url(
  input: unknown,
  name: string,
  minimumBytes: number,
  maximumBytes: number,
): { readonly encoded: string; readonly bytes: Uint8Array } {
  const encoded = requireBoundedString(input, name, 1, maximumBytes * 2);
  if (!BASE64URL_PATTERN.test(encoded)) throw new Error(`${name} must be canonical base64url`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(encoded);
  } catch {
    throw new Error(`${name} must be canonical base64url`);
  }
  if (
    bytes.byteLength < minimumBytes
    || bytes.byteLength > maximumBytes
    || bytesToBase64Url(bytes) !== encoded
  ) {
    throw new Error(`${name} must be canonical base64url`);
  }
  return Object.freeze({ encoded, bytes });
}

function isCanonicalBase64Url(value: string, minimumBytes: number, maximumBytes: number): boolean {
  try {
    requireCanonicalBase64Url(value, 'base64url value', minimumBytes, maximumBytes);
    return true;
  } catch {
    return false;
  }
}

function canonicalOrigin(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error('Account passkey connector origin is invalid');
  }
  if (
    url.username
    || url.password
    || url.pathname !== '/'
    || url.search
    || url.hash
    || (url.protocol !== 'https:' && !isLoopbackHttp(url))
  ) {
    throw new Error('Account passkey connector origin is invalid');
  }
  return url.origin;
}

function isLoopbackHttp(url: URL): boolean {
  if (url.protocol !== 'http:') return false;
  const hostname = url.hostname.toLowerCase();
  return hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname === '[::1]'
    || hostname === '::1'
    || /^127(?:\.\d{1,3}){3}$/u.test(hostname);
}

function requireInteger(input: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(input) || (input as number) < minimum || (input as number) > maximum) {
    throw new Error(`${name} is outside the supported range`);
  }
  return input as number;
}

function requireBoundedString(
  input: unknown,
  name: string,
  minimumLength: number,
  maximumLength: number,
  trim = false,
): string {
  if (typeof input !== 'string') throw new Error(`${name} must be a string`);
  const value = trim ? input.trim() : input;
  if (
    value.length < minimumLength
    || value.length > maximumLength
    || (!trim && value !== value.trim())
    || containsAsciiControl(value)
  ) {
    throw new Error(`${name} has invalid characters or length`);
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

function readRequired(record: Record<string, unknown>, name: string): unknown {
  const value = readOptional(record, name);
  if (value === undefined) throw new Error(`Missing account passkey field: ${name}`);
  return value;
}

function readOptional(record: Record<string, unknown>, name: string): unknown {
  const alternate = name[0] === name[0]?.toUpperCase()
    ? `${name[0]!.toLowerCase()}${name.slice(1)}`
    : `${name[0]!.toUpperCase()}${name.slice(1)}`;
  const hasName = Object.hasOwn(record, name);
  const hasAlternate = Object.hasOwn(record, alternate);
  if (hasName && hasAlternate) throw new Error(`Conflicting account passkey field: ${name}`);
  if (hasName) return record[name];
  if (hasAlternate) return record[alternate];
  return undefined;
}

function requireExactRecord(
  input: unknown,
  keys: readonly string[],
  name: string,
): Record<string, unknown> {
  const record = requirePlainRecord(input, name);
  if (Object.keys(record).some((key) => !keys.includes(key))
      || Object.getOwnPropertySymbols(record).length > 0) {
    throw new Error(`${name} contains unsupported fields`);
  }
  return record;
}

function requirePlainRecord(input: unknown, name: string): Record<string, unknown> {
  if (!isRecord(input) || Array.isArray(input)) throw new Error(`${name} must be a JSON object`);
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${name} must be a plain JSON object`);
  }
  return input;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}
