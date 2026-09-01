import type {
  CipherPasswordHistoryData,
  CipherRequest,
  Fido2CredentialRequestData,
} from '../api/types.js';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  constantTimeEqual,
  utf8ToBytes,
} from '../crypto/encoding.js';
import { encryptToBytes } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { encryptCipher } from './encrypt.js';
import { isRegistrableRpId } from './domain.js';
import { MAX_PASSKEY_CREDENTIAL_ID_BYTES, MAX_PASSKEY_USER_HANDLE_BYTES } from './fido2-limits.js';
import { isIsoTimestamp } from './iso-date.js';
import {
  MAX_PERSONAL_IMPORT_PASSWORD_HISTORY,
  type PersonalImportItemWrite,
  type PersonalImportPasskeyWrite,
  type PersonalImportPasswordHistoryWrite,
} from './vault-transfer-commit.js';

const MAX_IMPORT_PASSKEYS = 100;
const MAX_P256_PKCS8_BYTES = 4_096;
const MAX_IMPORT_SECRET_CHARS = 1024 * 1024;
const MAX_PASSKEY_TEXT_CHARS = 1_024;
const UINT32_MAX = 0xffff_ffffn;

const PASSKEY_REQUIRED_KEYS = [
  'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
  'counter', 'discoverable',
] as const;
const PASSKEY_OPTIONAL_KEYS = [
  'userHandle', 'userName', 'rpName', 'userDisplayName', 'creationDate',
] as const;
const PASSKEY_KEYS = new Set<string>([...PASSKEY_REQUIRED_KEYS, ...PASSKEY_OPTIONAL_KEYS]);
const HISTORY_KEYS = new Set(['password', 'lastUsedDate']);
const DATE_KEYS = new Set(['archivedDate']);

export type PersonalImportCryptoErrorCode =
  | 'invalid_write'
  | 'password_history_limit_exceeded'
  | 'invalid_password_history'
  | 'invalid_passkey'
  | 'invalid_archived_date'
  | 'cipher_encryption_failed';

const ERROR_MESSAGES: Readonly<Record<PersonalImportCryptoErrorCode, string>> = Object.freeze({
  invalid_write: 'The imported item write is invalid.',
  password_history_limit_exceeded: 'The imported password history exceeds the supported limit.',
  invalid_password_history: 'The imported password history is invalid.',
  invalid_passkey: 'The imported passkey is invalid or unsupported.',
  invalid_archived_date: 'The imported archive timestamp is invalid.',
  cipher_encryption_failed: 'The imported item could not be encrypted.',
});

export class PersonalImportCryptoError extends Error {
  constructor(readonly code: PersonalImportCryptoErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = 'PersonalImportCryptoError';
  }
}

export interface PersonalImportCryptoOptions {
  /** Injectable WebCrypto boundary; canonical import/export checks always remain in this module. */
  readonly pkcs8Crypto?: PersonalImportPkcs8Crypto;
}

export interface PersonalImportPkcs8Crypto {
  importPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey>;
  exportPrivateKey(key: CryptoKey): Promise<ArrayBuffer>;
}

/** Validate advanced import metadata without producing ciphertext or crossing the worker boundary. */
export async function validatePersonalImportItemWrite(
  write: PersonalImportItemWrite,
  options: PersonalImportCryptoOptions = {},
): Promise<void> {
  try {
    await validateWrite(write, options.pkcs8Crypto ?? DEFAULT_PKCS8_CRYPTO);
  } catch (error) {
    if (error instanceof PersonalImportCryptoError) throw error;
    throw new PersonalImportCryptoError('invalid_write');
  }
}

/**
 * Encrypt a preflighted personal-import write into the complete request sent by the worker.
 * Advanced secret fields stay outside CipherInput so they can never cross the popup protocol.
 */
export async function encryptPersonalImportItemWrite(
  write: PersonalImportItemWrite,
  targetKey: SymmetricKey,
  options: PersonalImportCryptoOptions = {},
): Promise<CipherRequest> {
  await validatePersonalImportItemWrite(write, options);

  let request: CipherRequest;
  try {
    request = await encryptCipher(write.cipher, targetKey);
  } catch {
    throw new PersonalImportCryptoError('cipher_encryption_failed');
  }

  try {
    if (write.secureNoteType !== undefined) {
      request.secureNote = { type: write.secureNoteType };
    }
    if (write.passwordHistory !== undefined) {
      request.passwordHistory = await encryptPasswordHistory(write.passwordHistory, targetKey);
    }
    if (write.fido2Credentials !== undefined) {
      request.login = {
        ...(request.login ?? {}),
        fido2Credentials: await encryptPasskeys(write.fido2Credentials, targetKey),
      };
    }
    if (write.dates !== undefined && hasOwn(write.dates, 'archivedDate')) {
      request.archivedDate = write.dates.archivedDate ?? null;
    }
    return request;
  } catch (error) {
    if (error instanceof PersonalImportCryptoError) throw error;
    throw new PersonalImportCryptoError('cipher_encryption_failed');
  }
}

async function validateWrite(
  value: PersonalImportItemWrite,
  pkcs8Crypto: PersonalImportPkcs8Crypto,
): Promise<void> {
  if (!isPlainRecord(value)
    || !Number.isSafeInteger(value.sourceIndex)
    || value.sourceIndex < 0
    || !isPlainRecord(value.cipher)) {
    throw new PersonalImportCryptoError('invalid_write');
  }

  if (value.secureNoteType !== undefined
    && (value.cipher.type !== 2
      || !Number.isSafeInteger(value.secureNoteType)
      || value.secureNoteType < 0)) {
    throw new PersonalImportCryptoError('invalid_write');
  }

  validatePasswordHistory(value.passwordHistory);
  await validatePasskeys(value.fido2Credentials, value.cipher.type, pkcs8Crypto);
  validateDates(value.dates);

  const passwordRevisionDate = value.cipher.type === 1
    ? value.cipher.login?.passwordRevisionDate
    : undefined;
  if (passwordRevisionDate !== undefined
    && passwordRevisionDate !== null
    && !isUtcIsoTimestamp(passwordRevisionDate)) {
    throw new PersonalImportCryptoError('invalid_write');
  }
}

function validatePasswordHistory(value: PersonalImportPasswordHistoryWrite[] | undefined): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) throw new PersonalImportCryptoError('invalid_password_history');
  if (value.length > MAX_PERSONAL_IMPORT_PASSWORD_HISTORY) {
    throw new PersonalImportCryptoError('password_history_limit_exceeded');
  }
  for (const entry of value) {
    if (!isPlainRecord(entry)
      || !hasOnlyDataProperties(entry, HISTORY_KEYS)
      || typeof entry.password !== 'string'
      || entry.password.length === 0
      || entry.password.length > MAX_IMPORT_SECRET_CHARS) {
      throw new PersonalImportCryptoError('invalid_password_history');
    }
    if (hasOwn(entry, 'lastUsedDate')) {
      if (entry.lastUsedDate === undefined
        || (entry.lastUsedDate !== null && !isUtcIsoTimestamp(entry.lastUsedDate))) {
        throw new PersonalImportCryptoError('invalid_password_history');
      }
    }
  }
}

async function validatePasskeys(
  value: PersonalImportPasskeyWrite[] | undefined,
  cipherType: number,
  pkcs8Crypto: PersonalImportPkcs8Crypto,
): Promise<void> {
  if (value === undefined) return;
  if (cipherType !== 1 || !Array.isArray(value) || value.length > MAX_IMPORT_PASSKEYS) {
    throw new PersonalImportCryptoError('invalid_passkey');
  }

  const credentialIds = new Set<string>();
  for (const credential of value) {
    await validatePasskey(credential, pkcs8Crypto);
    if (credentialIds.has(credential.credentialId)) {
      throw new PersonalImportCryptoError('invalid_passkey');
    }
    credentialIds.add(credential.credentialId);
  }
}

async function validatePasskey(
  value: PersonalImportPasskeyWrite,
  pkcs8Crypto: PersonalImportPkcs8Crypto,
): Promise<void> {
  if (!isPlainRecord(value) || !hasOnlyDataProperties(value, PASSKEY_KEYS)) {
    throw new PersonalImportCryptoError('invalid_passkey');
  }
  for (const key of PASSKEY_REQUIRED_KEYS) {
    if (typeof value[key] !== 'string' || value[key].length === 0) {
      throw new PersonalImportCryptoError('invalid_passkey');
    }
  }
  for (const key of ['userHandle', 'userName', 'rpName', 'userDisplayName'] as const) {
    const field = value[key];
    if (hasOwn(value, key) && field === undefined) {
      throw new PersonalImportCryptoError('invalid_passkey');
    }
    if (field !== undefined && field !== null && field.length > MAX_PASSKEY_TEXT_CHARS) {
      throw new PersonalImportCryptoError('invalid_passkey');
    }
  }
  if (value.keyType !== 'public-key'
    || value.keyAlgorithm !== 'ECDSA'
    || value.keyCurve !== 'P-256'
    || !isCanonicalRpId(value.rpId)
    || !isUint32String(value.counter)
    || (value.discoverable !== 'true' && value.discoverable !== 'false')
    || !isUtcIsoTimestamp(value.creationDate)) {
    throw new PersonalImportCryptoError('invalid_passkey');
  }

  validateCanonicalBase64Url(
    value.credentialId,
    1,
    MAX_PASSKEY_CREDENTIAL_ID_BYTES,
    'invalid_passkey',
  );
  if (value.userHandle !== undefined && value.userHandle !== null) {
    validateCanonicalBase64Url(
      value.userHandle,
      1,
      MAX_PASSKEY_USER_HANDLE_BYTES,
      'invalid_passkey',
    );
  }

  let pkcs8: Uint8Array | undefined;
  try {
    pkcs8 = decodeCanonicalBase64Url(value.keyValue, 1, MAX_P256_PKCS8_BYTES);
    await validateCanonicalP256PrivateKey(pkcs8, pkcs8Crypto);
  } catch {
    throw new PersonalImportCryptoError('invalid_passkey');
  } finally {
    pkcs8?.fill(0);
  }
}

function validateDates(value: PersonalImportItemWrite['dates']): void {
  if (value === undefined) return;
  if (!isPlainRecord(value) || !hasOnlyDataProperties(value, DATE_KEYS)) {
    throw new PersonalImportCryptoError('invalid_archived_date');
  }
  if (hasOwn(value, 'archivedDate')) {
    if (value.archivedDate === undefined
      || (value.archivedDate !== null && !isUtcIsoTimestamp(value.archivedDate))) {
      throw new PersonalImportCryptoError('invalid_archived_date');
    }
  }
}

async function encryptPasswordHistory(
  history: PersonalImportPasswordHistoryWrite[],
  key: SymmetricKey,
): Promise<CipherPasswordHistoryData[]> {
  const output: CipherPasswordHistoryData[] = [];
  for (const entry of history) {
    const encrypted: CipherPasswordHistoryData = {
      password: await encryptTextAndClear(entry.password, key),
    };
    if (hasOwn(entry, 'lastUsedDate')) encrypted.lastUsedDate = entry.lastUsedDate ?? null;
    output.push(encrypted);
  }
  return output;
}

async function encryptPasskeys(
  credentials: PersonalImportPasskeyWrite[],
  key: SymmetricKey,
): Promise<Fido2CredentialRequestData[]> {
  const output: Fido2CredentialRequestData[] = [];
  for (const credential of credentials) {
    const encrypted: Fido2CredentialRequestData = {
      credentialId: await encryptTextAndClear(credential.credentialId, key),
      keyType: await encryptTextAndClear(credential.keyType, key),
      keyAlgorithm: await encryptTextAndClear(credential.keyAlgorithm, key),
      keyCurve: await encryptTextAndClear(credential.keyCurve, key),
      keyValue: await encryptTextAndClear(credential.keyValue, key),
      rpId: await encryptTextAndClear(credential.rpId, key),
      counter: await encryptTextAndClear(credential.counter, key),
      discoverable: await encryptTextAndClear(credential.discoverable, key),
      creationDate: credential.creationDate!,
    };
    for (const field of ['userHandle', 'userName', 'rpName', 'userDisplayName'] as const) {
      if (!hasOwn(credential, field)) continue;
      const plaintext = credential[field];
      encrypted[field] = plaintext === null || plaintext === undefined
        ? null
        : await encryptTextAndClear(plaintext, key);
    }
    output.push(encrypted);
  }
  return output;
}

async function encryptTextAndClear(value: string, key: SymmetricKey): Promise<string> {
  const plaintext = utf8ToBytes(value);
  try {
    return await encryptToBytes(plaintext, key);
  } finally {
    plaintext.fill(0);
  }
}

const DEFAULT_PKCS8_CRYPTO: PersonalImportPkcs8Crypto = Object.freeze({
  importPrivateKey: (pkcs8: Uint8Array) => globalThis.crypto.subtle.importKey(
    'pkcs8',
    pkcs8 as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  ),
  exportPrivateKey: (key: CryptoKey) => globalThis.crypto.subtle.exportKey('pkcs8', key),
});

async function validateCanonicalP256PrivateKey(
  pkcs8: Uint8Array,
  crypto: PersonalImportPkcs8Crypto,
): Promise<void> {
  const key = await crypto.importPrivateKey(pkcs8);
  const algorithm = key.algorithm as Partial<EcKeyAlgorithm>;
  if (key.type !== 'private'
    || key.extractable !== true
    || key.usages.length !== 1
    || key.usages[0] !== 'sign'
    || algorithm.name !== 'ECDSA'
    || algorithm.namedCurve !== 'P-256') {
    throw new TypeError('invalid private key');
  }

  let canonical: Uint8Array | undefined;
  try {
    canonical = new Uint8Array(await crypto.exportPrivateKey(key));
    if (!constantTimeEqual(canonical, pkcs8)) throw new TypeError('noncanonical private key');
  } finally {
    canonical?.fill(0);
  }
}

function validateCanonicalBase64Url(
  value: string,
  minimumBytes: number,
  maximumBytes: number,
  code: PersonalImportCryptoErrorCode,
): void {
  let bytes: Uint8Array | undefined;
  try {
    bytes = decodeCanonicalBase64Url(value, minimumBytes, maximumBytes);
  } catch {
    throw new PersonalImportCryptoError(code);
  } finally {
    bytes?.fill(0);
  }
}

function decodeCanonicalBase64Url(
  value: string,
  minimumBytes: number,
  maximumBytes: number,
): Uint8Array {
  const maximumChars = Math.ceil((maximumBytes * 4) / 3);
  if (!value
    || value.length > maximumChars
    || value.length % 4 === 1
    || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError('invalid base64url');
  }
  const bytes = base64UrlToBytes(value);
  if (bytes.byteLength < minimumBytes
    || bytes.byteLength > maximumBytes
    || bytesToBase64Url(bytes) !== value) {
    bytes.fill(0);
    throw new TypeError('invalid base64url');
  }
  return bytes;
}

function isUtcIsoTimestamp(value: unknown): value is string {
  return isIsoTimestamp(value) && value.endsWith('Z');
}

function isUint32String(value: string): boolean {
  return value.length <= 10
    && /^(?:0|[1-9]\d*)$/.test(value)
    && BigInt(value) <= UINT32_MAX;
}

function isCanonicalRpId(value: string): boolean {
  return value.length <= 253
    && !/[/:@]/.test(value)
    && value === value.trim().toLowerCase()
    && isRegistrableRpId(value, value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyDataProperties(value: object, allowed: ReadonlySet<string>): boolean {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  return Object.entries(descriptors).every(([key, descriptor]) =>
    allowed.has(key)
    && descriptor.enumerable === true
    && Object.prototype.hasOwnProperty.call(descriptor, 'value'));
}

function hasOwn<T extends object, K extends PropertyKey>(value: T, key: K): key is K & keyof T {
  return Object.prototype.hasOwnProperty.call(value, key);
}
