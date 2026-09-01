import { parseRsaEncString } from '../crypto/encstring.js';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  constantTimeEqual,
  utf8ToBytes,
} from '../crypto/encoding.js';
import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import { hkdfExpandSha256, rsaOaepDecrypt } from '../crypto/primitives.js';

export const DEVICE_LOGIN_REQUEST_TTL_MS = 15 * 60_000;
export const DEVICE_LOGIN_ACCESS_CODE_LENGTH = 25;
export const DEVICE_LOGIN_AUTH_REQUEST_TYPE = 0 as const;

const DEVICE_LOGIN_STATE_VERSION = 1 as const;
const FINGERPRINT_WORD_COUNT = 5;
const FINGERPRINT_WORDLIST_LENGTH = 7_776;
const OFFICIAL_WORDLIST_SHA256 =
  'abae49761b88f3f1ba31ef944bea1f61b795a3cd7e1cfb7d276ed45bf77967ba';
const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const MAX_EMAIL_LENGTH = 254;
const MAX_DEVICE_IDENTIFIER_LENGTH = 255;
const MAX_DEVICE_NAME_LENGTH = 128;
const MAX_AUTH_REQUEST_ID_LENGTH = 36;
const MAX_PUBLIC_KEY_B64_LENGTH = 2_048;
const MAX_PRIVATE_KEY_B64_LENGTH = 8_192;
const MAX_ENCRYPTED_KEY_LENGTH = 2_000;
const MAX_DISPLAY_FIELD_LENGTH = 512;
const ACCESS_CODE_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ACCESS_CODE_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const ACCESS_CODE_NUMBERS = '0123456789';
const ACCESS_CODE_ALPHABET =
  ACCESS_CODE_UPPERCASE + ACCESS_CODE_LOWERCASE + ACCESS_CODE_NUMBERS;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/;

const RESPONSE_FIELDS = [
  ['Object', 'object'],
  ['Id', 'id'],
  ['PublicKey', 'publicKey'],
  ['RequestDeviceType', 'requestDeviceType'],
  ['RequestDeviceTypeValue', 'requestDeviceTypeValue'],
  ['RequestDeviceIdentifier', 'requestDeviceIdentifier'],
  ['RequestIpAddress', 'requestIpAddress'],
  ['RequestCountryName', 'requestCountryName'],
  ['Key', 'key'],
  ['MasterPasswordHash', 'masterPasswordHash'],
  ['CreationDate', 'creationDate'],
  ['RequestApproved', 'requestApproved'],
  ['ResponseDate', 'responseDate'],
  ['RequestDeviceId', 'requestDeviceId'],
  ['Origin', 'origin'],
] as const;
const RESPONSE_FIELD_NAMES = new Set(RESPONSE_FIELDS.flat());
const BASE_STATE_FIELDS = new Set([
  'version', 'phase', 'email', 'device', 'publicKey', 'privateKeyPkcs8', 'accessCode',
  'createdAt', 'expiresAt',
]);
const BOUND_STATE_FIELDS = new Set([...BASE_STATE_FIELDS, 'requestId', 'serverCreationDate']);
const DEVICE_FIELDS = new Set(['type', 'name', 'identifier']);

export class DeviceLoginProtocolError extends Error {
  constructor(message: string) {
    super(`Invalid device login data: ${message}`);
    this.name = 'DeviceLoginProtocolError';
  }
}

export interface DeviceLoginDeviceIdentity {
  readonly type: number;
  readonly name: string;
  readonly identifier: string;
}

export interface DeviceLoginCreateRequest {
  readonly email: string;
  readonly deviceIdentifier: string;
  readonly publicKey: string;
  readonly type: typeof DEVICE_LOGIN_AUTH_REQUEST_TYPE;
  readonly accessCode: string;
}

interface DeviceLoginStateBase {
  readonly version: typeof DEVICE_LOGIN_STATE_VERSION;
  readonly email: string;
  readonly device: DeviceLoginDeviceIdentity;
  /** Base64-encoded RSA SubjectPublicKeyInfo DER. */
  readonly publicKey: string;
  /**
   * Base64-encoded RSA PKCS#8 DER. This is sensitive session material. The core never persists it;
   * an integrating browser layer may place the whole state only in storage.session.
   */
  readonly privateKeyPkcs8: string;
  readonly accessCode: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface DeviceLoginPendingState extends DeviceLoginStateBase {
  readonly phase: 'pending';
}

export interface DeviceLoginBoundState extends DeviceLoginStateBase {
  readonly phase: 'bound';
  readonly requestId: string;
  readonly serverCreationDate: string;
}

export type DeviceLoginState = DeviceLoginPendingState | DeviceLoginBoundState;

export interface NewDeviceLoginRequest {
  readonly request: DeviceLoginCreateRequest;
  readonly state: DeviceLoginPendingState;
}

export interface ParsedAuthRequestResponse {
  readonly id: string;
  readonly publicKey: string;
  readonly requestDeviceType?: string;
  readonly requestDeviceTypeValue: number;
  readonly requestDeviceIdentifier: string;
  readonly requestIpAddress?: string;
  readonly requestCountryName?: string;
  readonly key?: string;
  readonly masterPasswordHash?: string;
  readonly creationDate: string;
  readonly creationTime: number;
  readonly requestApproved: boolean;
  readonly responseDate?: string;
  readonly responseTime?: number;
  readonly requestDeviceId?: string;
  readonly origin?: string;
  readonly answered: boolean;
  readonly expired: boolean;
}

export interface RecoveredDeviceLogin {
  readonly response: ParsedAuthRequestResponse;
  readonly userKey: SymmetricKey;
}

/** Generate the requester's one-time RSA-2048 OAEP-SHA1 key pair and access code. */
export async function createDeviceLoginRequest(
  input: { readonly email: string; readonly device: DeviceLoginDeviceIdentity },
  now: number = Date.now(),
): Promise<NewDeviceLoginRequest> {
  const email = normalizeEmail(input.email);
  const device = parseDeviceIdentity(input.device);
  const createdAt = parseTimestamp(now, 'createdAt');
  const generated = await globalThis.crypto.subtle.generateKey(
    rsaOaepParameters(),
    true,
    ['encrypt', 'decrypt'],
  );
  if (!isCryptoKeyPair(generated)) fail('RSA key generation did not return a key pair');
  assertRsa2048OaepSha1(generated.publicKey, 'generated public key');
  assertRsa2048OaepSha1(generated.privateKey, 'generated private key');

  const publicKey = bytesToBase64(
    new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', generated.publicKey)),
  );
  const privateKeyPkcs8 = bytesToBase64(
    new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', generated.privateKey)),
  );
  const accessCode = generateDeviceLoginAccessCode();
  const expiresAt = safeAdd(createdAt, DEVICE_LOGIN_REQUEST_TTL_MS, 'expiresAt');
  const state: DeviceLoginPendingState = freezeState({
    version: DEVICE_LOGIN_STATE_VERSION,
    phase: 'pending',
    email,
    device,
    publicKey,
    privateKeyPkcs8,
    accessCode,
    createdAt,
    expiresAt,
  });
  const request: DeviceLoginCreateRequest = Object.freeze({
    email,
    deviceIdentifier: device.identifier,
    publicKey,
    type: DEVICE_LOGIN_AUTH_REQUEST_TYPE,
    accessCode,
  });
  return Object.freeze({ request, state });
}

/** Match Bitwarden's defaults: upper, lower, and numbers, with no special characters. */
export function generateDeviceLoginAccessCode(): string {
  const characters = [
    randomCharacter(ACCESS_CODE_UPPERCASE),
    randomCharacter(ACCESS_CODE_LOWERCASE),
    randomCharacter(ACCESS_CODE_NUMBERS),
  ];
  while (characters.length < DEVICE_LOGIN_ACCESS_CODE_LENGTH) {
    characters.push(randomCharacter(ACCESS_CODE_ALPHABET));
  }
  for (let index = characters.length - 1; index > 0; index--) {
    const swapWith = secureRandomIndex(index + 1);
    [characters[index], characters[swapWith]] = [characters[swapWith]!, characters[index]!];
  }
  return characters.join('');
}

/** Derive Bitwarden's five-word device-login fingerprint. */
export async function deriveDeviceLoginFingerprint(
  email: string,
  publicKeySpki: Uint8Array,
  officialWordlist: readonly string[],
): Promise<string> {
  const normalizedEmail = normalizeEmail(email);
  await importRsaPublicKey(publicKeySpki);
  const publicKeyHash = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', publicKeySpki as BufferSource),
  );
  const entropy = await hkdfExpandSha256(publicKeyHash, normalizedEmail, 32);
  return fingerprintPhraseFromEntropy(entropy, officialWordlist);
}

/** Convert an upstream-compatible 32-byte fingerprint value to five EFF words. */
export async function fingerprintPhraseFromEntropy(
  entropy: Uint8Array,
  officialWordlist: readonly string[],
): Promise<string> {
  if (entropy.byteLength !== 32) fail('fingerprint entropy must be exactly 32 bytes');
  const words = await validatedOfficialWordlist(officialWordlist);
  let value = 0n;
  for (const byte of entropy) value = (value << 8n) | BigInt(byte);
  const phrase: string[] = [];
  const radix = BigInt(words.length);
  for (let index = 0; index < FINGERPRINT_WORD_COUNT; index++) {
    phrase.push(words[Number(value % radix)]!);
    value /= radix;
  }
  return phrase.join('-');
}

/** Parse an auth-request response without trusting server-provided derived status flags. */
export function parseAuthRequestResponse(
  input: unknown,
  now: number = Date.now(),
): ParsedAuthRequestResponse {
  const record = requirePlainRecord(input, 'auth request response');
  assertKnownKeys(record, RESPONSE_FIELD_NAMES, 'auth request response');
  const objectName = optionalString(readAlias(record, 'Object', 'object'), 'object', 32, true);
  if (objectName !== undefined && objectName !== 'auth-request') {
    fail('response object is not auth-request');
  }

  const id = parseUuid(
    requiredString(readAlias(record, 'Id', 'id'), 'id', MAX_AUTH_REQUEST_ID_LENGTH),
    'id',
  );
  const publicKey = parseCanonicalBase64String(
    requiredString(
      readAlias(record, 'PublicKey', 'publicKey'),
      'publicKey',
      MAX_PUBLIC_KEY_B64_LENGTH,
    ),
    'publicKey',
    256,
    1_024,
  ).encoded;
  const requestDeviceType = optionalString(
    readAlias(record, 'RequestDeviceType', 'requestDeviceType'),
    'requestDeviceType',
    MAX_DISPLAY_FIELD_LENGTH,
    true,
  );
  const requestDeviceTypeValue = requiredInteger(
    readAlias(record, 'RequestDeviceTypeValue', 'requestDeviceTypeValue'),
    'requestDeviceTypeValue',
    0,
    255,
  );
  const requestDeviceIdentifier = requiredString(
    readAlias(record, 'RequestDeviceIdentifier', 'requestDeviceIdentifier'),
    'requestDeviceIdentifier',
    MAX_DEVICE_IDENTIFIER_LENGTH,
  );
  assertSafeText(requestDeviceIdentifier, 'requestDeviceIdentifier');
  const requestIpAddress = optionalString(
    readAlias(record, 'RequestIpAddress', 'requestIpAddress'),
    'requestIpAddress',
    128,
    true,
  );
  const requestCountryName = optionalString(
    readAlias(record, 'RequestCountryName', 'requestCountryName'),
    'requestCountryName',
    MAX_DISPLAY_FIELD_LENGTH,
    true,
  );
  const key = optionalString(
    readAlias(record, 'Key', 'key'),
    'key',
    MAX_ENCRYPTED_KEY_LENGTH,
  );
  const masterPasswordHash = optionalString(
    readAlias(record, 'MasterPasswordHash', 'masterPasswordHash'),
    'masterPasswordHash',
    1_024,
  );
  const creationDate = parseIsoDate(
    requiredString(readAlias(record, 'CreationDate', 'creationDate'), 'creationDate', 64),
    'creationDate',
  );
  const requestApproved = requiredBoolean(
    readAlias(record, 'RequestApproved', 'requestApproved'),
    'requestApproved',
  );
  const responseDateValue = readAlias(record, 'ResponseDate', 'responseDate');
  const responseDate = responseDateValue === undefined || responseDateValue === null
    ? undefined
    : parseIsoDate(requiredString(responseDateValue, 'responseDate', 64), 'responseDate');
  const requestDeviceId = optionalString(
    readAlias(record, 'RequestDeviceId', 'requestDeviceId'),
    'requestDeviceId',
    MAX_AUTH_REQUEST_ID_LENGTH,
    true,
  );
  const origin = optionalString(
    readAlias(record, 'Origin', 'origin'),
    'origin',
    MAX_DISPLAY_FIELD_LENGTH,
    true,
  );
  const currentTime = parseTimestamp(now, 'now');
  const answered = responseDate !== undefined;
  const expired = currentTime - creationDate.time >= DEVICE_LOGIN_REQUEST_TTL_MS;

  return Object.freeze({
    id,
    publicKey,
    ...(requestDeviceType !== undefined ? { requestDeviceType } : {}),
    requestDeviceTypeValue,
    requestDeviceIdentifier,
    ...(requestIpAddress !== undefined ? { requestIpAddress } : {}),
    ...(requestCountryName !== undefined ? { requestCountryName } : {}),
    ...(key !== undefined ? { key } : {}),
    ...(masterPasswordHash !== undefined ? { masterPasswordHash } : {}),
    creationDate: creationDate.text,
    creationTime: creationDate.time,
    requestApproved,
    ...(responseDate !== undefined
      ? { responseDate: responseDate.text, responseTime: responseDate.time }
      : {}),
    ...(requestDeviceId !== undefined ? { requestDeviceId } : {}),
    ...(origin !== undefined ? { origin } : {}),
    answered,
    expired,
  });
}

/** Bind the server-issued request id and creation time to the one-time local key pair. */
export async function bindDeviceLoginRequest(
  pending: DeviceLoginPendingState,
  rawCreationResponse: unknown,
  now: number = Date.now(),
): Promise<DeviceLoginBoundState> {
  const currentTime = parseTimestamp(now, 'now');
  await validateStateCryptography(pending, currentTime, 'pending');
  const response = parseAuthRequestResponse(rawCreationResponse, currentTime);
  await validateResponseBinding(pending, response);
  if (response.answered || response.requestApproved || response.key !== undefined) {
    fail('new auth request is already answered');
  }
  if (response.expired) fail('new auth request is expired');
  if (
    response.creationTime < pending.createdAt - MAX_CLOCK_SKEW_MS
    || response.creationTime > currentTime + MAX_CLOCK_SKEW_MS
  ) {
    fail('server creation date is outside the allowed clock skew');
  }

  const serverExpiresAt = safeAdd(
    response.creationTime,
    DEVICE_LOGIN_REQUEST_TTL_MS,
    'server expiresAt',
  );
  return freezeState({
    ...pending,
    phase: 'bound',
    requestId: response.id,
    serverCreationDate: response.creationDate,
    expiresAt: Math.min(pending.expiresAt, serverExpiresAt),
  });
}

/** Validate an approved response and recover its 64-byte UserKey from encType=4. */
export async function recoverApprovedDeviceLogin(
  state: DeviceLoginBoundState,
  rawResponse: unknown,
  now: number = Date.now(),
): Promise<RecoveredDeviceLogin> {
  const currentTime = parseTimestamp(now, 'now');
  await validateStateCryptography(state, currentTime, 'bound');
  const response = parseAuthRequestResponse(rawResponse, currentTime);
  await validateResponseBinding(state, response);
  if (response.id !== state.requestId) {
    fail('response request id does not match the bound request');
  }
  if (response.creationTime !== Date.parse(state.serverCreationDate)) {
    fail('response creation date does not match the bound request');
  }
  if (!response.answered || response.responseTime === undefined) {
    fail('auth request has not been answered');
  }
  if (!response.requestApproved) fail('auth request was not approved');
  if (response.expired || currentTime >= state.expiresAt) fail('auth request is expired');
  if (
    response.responseTime < response.creationTime
    || response.responseTime >= response.creationTime + DEVICE_LOGIN_REQUEST_TTL_MS
    || response.responseTime > currentTime + MAX_CLOCK_SKEW_MS
  ) {
    fail('auth request response date is invalid');
  }
  if (response.key === undefined) fail('approved auth request is missing the encrypted user key');

  const wrapped = parseStrictType4EncString(response.key);
  const privateKeyPkcs8 = parseCanonicalBase64String(
    state.privateKeyPkcs8,
    'privateKeyPkcs8',
    512,
    4_096,
  ).bytes;
  let rawUserKey: Uint8Array | undefined;
  try {
    try {
      rawUserKey = await rsaOaepDecrypt(privateKeyPkcs8, wrapped, 'SHA-1');
    } catch {
      fail('encrypted user key could not be decrypted by the request key');
    }
    if (rawUserKey.byteLength !== 64) fail('decrypted user key must be exactly 64 bytes');
    const userKey = symmetricKeyFromBytes(rawUserKey);
    return Object.freeze({ response, userKey: Object.freeze(userKey) });
  } finally {
    privateKeyPkcs8.fill(0);
    wrapped.fill(0);
    rawUserKey?.fill(0);
  }
}

/** Restore a JSON/structured-cloned session snapshot after strict validation. */
export async function restoreDeviceLoginState(
  input: unknown,
  now: number = Date.now(),
): Promise<DeviceLoginState> {
  const currentTime = parseTimestamp(now, 'now');
  const record = requirePlainRecord(input, 'device login state');
  const phase = record.phase;
  if (phase !== 'pending' && phase !== 'bound') fail('state phase is invalid');
  assertKnownKeys(
    record,
    phase === 'bound' ? BOUND_STATE_FIELDS : BASE_STATE_FIELDS,
    'device login state',
  );
  if (record.version !== DEVICE_LOGIN_STATE_VERSION) fail('state version is unsupported');
  const email = normalizeEmail(requiredString(record.email, 'email', MAX_EMAIL_LENGTH));
  if (record.email !== email) fail('state email is not canonical');
  const device = parseDeviceIdentity(record.device);
  const publicKey = parseCanonicalBase64String(
    requiredString(record.publicKey, 'publicKey', MAX_PUBLIC_KEY_B64_LENGTH),
    'publicKey',
    256,
    1_024,
  ).encoded;
  const privateKeyPkcs8 = parseCanonicalBase64String(
    requiredString(record.privateKeyPkcs8, 'privateKeyPkcs8', MAX_PRIVATE_KEY_B64_LENGTH),
    'privateKeyPkcs8',
    512,
    4_096,
  ).encoded;
  const accessCode = validateAccessCode(record.accessCode);
  const createdAt = parseTimestamp(record.createdAt, 'createdAt');
  const expiresAt = parseTimestamp(record.expiresAt, 'expiresAt');

  let state: DeviceLoginState;
  if (phase === 'pending') {
    if (expiresAt !== safeAdd(createdAt, DEVICE_LOGIN_REQUEST_TTL_MS, 'expiresAt')) {
      fail('pending state TTL is invalid');
    }
    state = freezeState({
      version: DEVICE_LOGIN_STATE_VERSION,
      phase,
      email,
      device,
      publicKey,
      privateKeyPkcs8,
      accessCode,
      createdAt,
      expiresAt,
    });
  } else {
    const requestId = parseUuid(
      requiredString(record.requestId, 'requestId', MAX_AUTH_REQUEST_ID_LENGTH),
      'requestId',
    );
    const serverCreationDate = parseIsoDate(
      requiredString(record.serverCreationDate, 'serverCreationDate', 64),
      'serverCreationDate',
    );
    const expectedExpiry = Math.min(
      safeAdd(createdAt, DEVICE_LOGIN_REQUEST_TTL_MS, 'local expiresAt'),
      safeAdd(serverCreationDate.time, DEVICE_LOGIN_REQUEST_TTL_MS, 'server expiresAt'),
    );
    if (expiresAt !== expectedExpiry) fail('bound state TTL is invalid');
    state = freezeState({
      version: DEVICE_LOGIN_STATE_VERSION,
      phase,
      email,
      device,
      publicKey,
      privateKeyPkcs8,
      accessCode,
      createdAt,
      expiresAt,
      requestId,
      serverCreationDate: serverCreationDate.text,
    });
  }
  await validateStateCryptography(state, currentTime, phase);
  return state;
}

export function isDeviceLoginStateExpired(
  state: Pick<DeviceLoginState, 'expiresAt'>,
  now: number = Date.now(),
): boolean {
  return parseTimestamp(now, 'now') >= parseTimestamp(state.expiresAt, 'expiresAt');
}

async function validateResponseBinding(
  state: DeviceLoginState,
  response: ParsedAuthRequestResponse,
): Promise<void> {
  if (response.requestDeviceIdentifier !== state.device.identifier) {
    fail('response device identifier does not match the request');
  }
  if (response.requestDeviceTypeValue !== state.device.type) {
    fail('response device type does not match the request');
  }
  const responsePublicKey = parseCanonicalBase64String(
    response.publicKey,
    'response publicKey',
    256,
    1_024,
  ).bytes;
  const derivedPublicKey = await derivePublicKeyFromPrivateKey(state.privateKeyPkcs8);
  if (!constantTimeEqual(responsePublicKey, derivedPublicKey)) {
    fail('response public key does not match the request private key');
  }
}

async function validateStateCryptography(
  state: DeviceLoginState,
  now: number,
  expectedPhase: DeviceLoginState['phase'],
): Promise<void> {
  validateStateShape(state, expectedPhase);
  if (now >= state.expiresAt) fail('auth request is expired');
  const publicKey = parseCanonicalBase64String(
    state.publicKey,
    'publicKey',
    256,
    1_024,
  ).bytes;
  const derivedPublicKey = await derivePublicKeyFromPrivateKey(state.privateKeyPkcs8);
  if (!constantTimeEqual(publicKey, derivedPublicKey)) {
    fail('state public key does not match its private key');
  }
}

function validateStateShape(
  state: DeviceLoginState,
  expectedPhase: DeviceLoginState['phase'],
): void {
  if (state.version !== DEVICE_LOGIN_STATE_VERSION || state.phase !== expectedPhase) {
    fail(`state is not ${expectedPhase}`);
  }
  if (normalizeEmail(state.email) !== state.email) fail('state email is not canonical');
  parseDeviceIdentity(state.device);
  validateAccessCode(state.accessCode);
  const createdAt = parseTimestamp(state.createdAt, 'createdAt');
  const expiresAt = parseTimestamp(state.expiresAt, 'expiresAt');
  if (expiresAt <= createdAt || expiresAt - createdAt > DEVICE_LOGIN_REQUEST_TTL_MS) {
    fail('state TTL is invalid');
  }
  if (state.phase === 'bound') {
    parseUuid(state.requestId, 'requestId');
    parseIsoDate(state.serverCreationDate, 'serverCreationDate');
  }
}

async function derivePublicKeyFromPrivateKey(privateKeyBase64: string): Promise<Uint8Array> {
  const privateKeyBytes = parseCanonicalBase64String(
    privateKeyBase64,
    'privateKeyPkcs8',
    512,
    4_096,
  ).bytes;
  let privateKey: CryptoKey;
  try {
    privateKey = await globalThis.crypto.subtle.importKey(
      'pkcs8',
      privateKeyBytes as BufferSource,
      rsaOaepImportParameters(),
      true,
      ['decrypt'],
    );
  } catch {
    fail('privateKeyPkcs8 is not a valid RSA-OAEP key');
  }
  assertRsa2048OaepSha1(privateKey, 'privateKeyPkcs8');
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', privateKey);
  if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
    fail('privateKeyPkcs8 is missing RSA public parameters');
  }
  const publicJwk: JsonWebKey = {
    kty: 'RSA',
    n: jwk.n,
    e: jwk.e,
    alg: 'RSA-OAEP',
    ext: true,
    key_ops: ['encrypt'],
  };
  let publicKey: CryptoKey;
  try {
    publicKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      publicJwk,
      rsaOaepImportParameters(),
      true,
      ['encrypt'],
    );
  } catch {
    fail('privateKeyPkcs8 public parameters are invalid');
  }
  assertRsa2048OaepSha1(publicKey, 'derived public key');
  return new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', publicKey));
}

async function importRsaPublicKey(publicKeySpki: Uint8Array): Promise<CryptoKey> {
  if (
    !(publicKeySpki instanceof Uint8Array)
    || publicKeySpki.byteLength < 256
    || publicKeySpki.byteLength > 1_024
  ) {
    fail('public key SPKI length is invalid');
  }
  let key: CryptoKey;
  try {
    key = await globalThis.crypto.subtle.importKey(
      'spki',
      publicKeySpki as BufferSource,
      rsaOaepImportParameters(),
      false,
      ['encrypt'],
    );
  } catch {
    fail('public key is not valid SPKI RSA-OAEP data');
  }
  assertRsa2048OaepSha1(key, 'public key');
  return key;
}

function assertRsa2048OaepSha1(key: CryptoKey, label: string): void {
  const algorithm = key.algorithm as Partial<RsaHashedKeyAlgorithm>;
  if (
    algorithm.name !== 'RSA-OAEP'
    || algorithm.modulusLength !== 2_048
    || algorithm.hash?.name !== 'SHA-1'
    || !(algorithm.publicExponent instanceof Uint8Array)
    || !constantTimeEqual(algorithm.publicExponent, Uint8Array.from([1, 0, 1]))
  ) {
    fail(`${label} must be RSA-2048 OAEP-SHA1 with exponent 65537`);
  }
}

async function validatedOfficialWordlist(wordlist: readonly string[]): Promise<readonly string[]> {
  if (!Array.isArray(wordlist) || wordlist.length !== FINGERPRINT_WORDLIST_LENGTH) {
    fail(`fingerprint wordlist must contain exactly ${FINGERPRINT_WORDLIST_LENGTH} words`);
  }
  const words = Array.from(wordlist);
  const unique = new Set<string>();
  for (const word of words) {
    if (
      typeof word !== 'string'
      || word.length === 0
      || word.length > 64
      || !/^[a-z]+(?:-[a-z]+)*$/.test(word)
    ) {
      fail('fingerprint wordlist contains an invalid word');
    }
    if (unique.has(word)) fail('fingerprint wordlist contains duplicate words');
    unique.add(word);
  }
  const digest = bytesToHex(new Uint8Array(
    await globalThis.crypto.subtle.digest(
      'SHA-256',
      utf8ToBytes(words.join('\n')) as BufferSource,
    ),
  ));
  if (digest !== OFFICIAL_WORDLIST_SHA256) {
    fail('fingerprint wordlist is not the official ordered EFF long wordlist');
  }
  return words;
}

function parseStrictType4EncString(value: string): Uint8Array {
  if (!/^4\.[A-Za-z0-9+/]+={0,2}$/.test(value) || value.includes('|')) {
    fail('encrypted user key must be an encType=4 RSA EncString');
  }
  let parsed: ReturnType<typeof parseRsaEncString>;
  try {
    parsed = parseRsaEncString(value);
  } catch {
    fail('encrypted user key is not a valid RSA EncString');
  }
  if (parsed.encType !== 4 || parsed.mac !== undefined || parsed.data.byteLength !== 256) {
    fail('encrypted user key must contain one 256-byte RSA-OAEP-SHA1 ciphertext');
  }
  if (`4.${bytesToBase64(parsed.data)}` !== value) {
    fail('encrypted user key is not canonical base64');
  }
  return parsed.data;
}

function parseDeviceIdentity(input: unknown): DeviceLoginDeviceIdentity {
  const record = requirePlainRecord(input, 'device identity');
  assertKnownKeys(record, DEVICE_FIELDS, 'device identity');
  const type = requiredInteger(record.type, 'device.type', 0, 255);
  const name = requiredString(record.name, 'device.name', MAX_DEVICE_NAME_LENGTH);
  const identifier = requiredString(
    record.identifier,
    'device.identifier',
    MAX_DEVICE_IDENTIFIER_LENGTH,
  );
  assertSafeText(name, 'device.name');
  assertSafeText(identifier, 'device.identifier');
  return Object.freeze({ type, name, identifier });
}

function validateAccessCode(input: unknown): string {
  if (
    typeof input !== 'string'
    || input.length !== DEVICE_LOGIN_ACCESS_CODE_LENGTH
    || !/^[A-Za-z0-9]{25}$/.test(input)
    || !/[A-Z]/.test(input)
    || !/[a-z]/.test(input)
    || !/[0-9]/.test(input)
  ) {
    fail('accessCode must be 25 alphanumeric characters with upper, lower, and number');
  }
  return input;
}

function normalizeEmail(input: unknown): string {
  const email = requiredString(input, 'email', MAX_EMAIL_LENGTH).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+$/u.test(email) || containsAsciiControl(email, true)) {
    fail('email is invalid');
  }
  return email;
}

function parseCanonicalBase64String(
  value: string,
  label: string,
  minimumBytes: number,
  maximumBytes: number,
): { readonly bytes: Uint8Array; readonly encoded: string } {
  if (
    value.length === 0
    || value.length > Math.ceil(maximumBytes / 3) * 4
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    fail(`${label} is not canonical base64`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(value);
  } catch {
    fail(`${label} is not canonical base64`);
  }
  if (bytes.byteLength < minimumBytes || bytes.byteLength > maximumBytes) {
    fail(`${label} byte length is invalid`);
  }
  if (bytesToBase64(bytes) !== value) fail(`${label} is not canonical base64`);
  return { bytes, encoded: value };
}

function parseIsoDate(value: string, label: string): { readonly text: string; readonly time: number } {
  if (!ISO_DATE_PATTERN.test(value)) fail(`${label} is not a bounded ISO-8601 timestamp`);
  const time = Date.parse(value);
  if (!Number.isFinite(time)) fail(`${label} is invalid`);
  return { text: value, time };
}

function readAlias(
  record: Record<string, unknown>,
  pascalName: string,
  camelName: string,
): unknown {
  const hasPascal = Object.prototype.hasOwnProperty.call(record, pascalName);
  const hasCamel = Object.prototype.hasOwnProperty.call(record, camelName);
  if (hasPascal && hasCamel) fail(`response contains ambiguous aliases for ${camelName}`);
  return hasPascal ? record[pascalName] : record[camelName];
}

function requiredString(value: unknown, label: string, maximumLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximumLength) {
    fail(`${label} must be a non-empty string no longer than ${maximumLength}`);
  }
  return value;
}

function optionalString(
  value: unknown,
  label: string,
  maximumLength: number,
  allowEmpty = false,
): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (
    typeof value !== 'string'
    || value.length > maximumLength
    || (!allowEmpty && value.length === 0)
  ) {
    fail(`${label} is invalid`);
  }
  return value;
}

function requiredInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function requiredBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') fail(`${label} must be boolean`);
  return value;
}

function parseTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail(`${label} must be a non-negative safe integer timestamp`);
  }
  return value as number;
}

function parseUuid(value: string, label: string): string {
  if (value.length !== MAX_AUTH_REQUEST_ID_LENGTH || !UUID_PATTERN.test(value)) {
    fail(`${label} must be a canonical UUID`);
  }
  return value.toLowerCase();
}

function assertSafeText(value: string, label: string): void {
  if (containsAsciiControl(value, false)) fail(`${label} contains control characters`);
}

function containsAsciiControl(value: string, includeSpace: boolean): boolean {
  const upperBound = includeSpace ? 0x20 : 0x1f;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= upperBound || code === 0x7f) return true;
  }
  return false;
}

function requirePlainRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) fail(`${label} must be a plain object`);
  return value as Record<string, unknown>;
}

function assertKnownKeys(
  record: Record<string, unknown>,
  known: ReadonlySet<string>,
  label: string,
): void {
  for (const key of Object.keys(record)) {
    if (!known.has(key)) fail(`${label} contains unsupported field: ${key}`);
  }
}

function randomCharacter(alphabet: string): string {
  return alphabet[secureRandomIndex(alphabet.length)]!;
}

function secureRandomIndex(exclusiveMaximum: number): number {
  if (!Number.isInteger(exclusiveMaximum) || exclusiveMaximum < 1 || exclusiveMaximum > 256) {
    fail('random selection range is invalid');
  }
  const limit = Math.floor(256 / exclusiveMaximum) * exclusiveMaximum;
  const random = new Uint8Array(1);
  do {
    globalThis.crypto.getRandomValues(random);
  } while (random[0]! >= limit);
  return random[0]! % exclusiveMaximum;
}

function rsaOaepParameters(): RsaHashedKeyGenParams {
  return {
    name: 'RSA-OAEP',
    modulusLength: 2_048,
    publicExponent: Uint8Array.from([1, 0, 1]),
    hash: 'SHA-1',
  };
}

function rsaOaepImportParameters(): RsaHashedImportParams {
  return { name: 'RSA-OAEP', hash: 'SHA-1' };
}

function isCryptoKeyPair(value: CryptoKeyPair | CryptoKey): value is CryptoKeyPair {
  return 'publicKey' in value && 'privateKey' in value;
}

function safeAdd(value: number, increment: number, label: string): number {
  const result = value + increment;
  if (!Number.isSafeInteger(result)) fail(`${label} exceeds the safe timestamp range`);
  return result;
}

function freezeState<T extends DeviceLoginState>(state: T): T {
  Object.freeze(state.device);
  return Object.freeze(state);
}

function fail(message: string): never {
  throw new DeviceLoginProtocolError(message);
}
