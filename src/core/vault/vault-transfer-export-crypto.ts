import type { CipherResponse } from '../api/types.js';
import { decryptToBytes, UnsupportedEncTypeError } from '../crypto/encstring.js';
import { utf8ToBytes } from '../crypto/encoding.js';
import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import {
  encodeVaultTransferJson,
  type EncodeVaultTransferJsonOptions,
  type VaultTransferJsonDiagnostic,
} from './vault-transfer-json.js';
import type { VaultTransferIR } from './vault-transfer.js';
import { validateLoginUriChecksum } from './login-uri-checksum.js';
import { validateLoginUriAlias } from './vault-transfer-login-wire.js';
import { isOptionalNullableIsoTimestamp } from './iso-date.js';
import {
  RAW_SYNC_CIPHER_FIELDS,
  validateRawSyncCipherCompatibility,
} from './vault-sync-cipher-compat.js';
import type {
  VaultTransferDecryptFailureCode,
  VaultTransferDecryptResult,
  VaultTransferExportCipher,
  VaultTransferExportDecryptors,
  VaultTransferExportField,
  VaultTransferExportLogin,
  VaultTransferExportLoginUri,
  VaultTransferExportPasskey,
  VaultTransferExportPasswordHistory,
  VaultTransferExportScope,
} from './vault-transfer-export.js';

export interface VaultTransferExportCryptoOptions {
  readonly scope: VaultTransferExportScope;
  readonly userKey: SymmetricKey;
  readonly organizationKeys?: ReadonlyMap<string, SymmetricKey>;
}

export type EncodeVaultTransferJsonBytesResult =
  | { ok: true; bytes: Uint8Array; diagnostics: VaultTransferJsonDiagnostic[] }
  | { ok: false; bytes: null; diagnostics: VaultTransferJsonDiagnostic[] };

const FOLDER_FIELDS = new Set(['id', 'name', 'revisionDate', 'object']);
const COLLECTION_FIELDS = new Set([
  'id', 'organizationId', 'name', 'externalId', 'readOnly', 'manage', 'hidePasswords', 'object',
]);
// The official plaintext LoginExport omits this sync timestamp; validate its shape but do not turn it
// into portable vault data.
const LOGIN_FIELDS = new Set([
  'username', 'password', 'totp', 'autofillOnPageLoad', 'uris', 'fido2Credentials',
  'passwordRevisionDate', 'uri',
]);
const URI_FIELDS = new Set(['uri', 'uriChecksum', 'match']);
const PASSKEY_REQUIRED_FIELDS = [
  'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter',
  'discoverable',
] as const;
const PASSKEY_OPTIONAL_ENCRYPTED_FIELDS = [
  'userHandle', 'userName', 'rpName', 'userDisplayName',
] as const;
const PASSKEY_FIELDS = new Set([
  ...PASSKEY_REQUIRED_FIELDS, ...PASSKEY_OPTIONAL_ENCRYPTED_FIELDS, 'creationDate',
]);
const CUSTOM_FIELD_FIELDS = new Set(['type', 'name', 'value', 'linkedId']);
const PASSWORD_HISTORY_FIELDS = new Set(['password', 'lastUsedDate']);
const ATTACHMENT_FIELDS = new Set(['id', 'url', 'fileName', 'key', 'size', 'sizeName']);
const SECURE_NOTE_FIELDS = new Set(['type']);
const CARD_FIELDS = ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'] as const;
const IDENTITY_FIELDS = [
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3', 'city',
  'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn', 'username',
  'passportNumber', 'licenseNumber',
] as const;
const SSH_FIELDS = ['privateKey', 'publicKey', 'keyFingerprint'] as const;
const CARD_FIELD_SET = new Set<string>(CARD_FIELDS);
const IDENTITY_FIELD_SET = new Set<string>(IDENTITY_FIELDS);
const SSH_FIELD_SET = new Set<string>(SSH_FIELDS);
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const ITEM_PAYLOAD_FIELDS = [
  'login', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount', 'driversLicense', 'passport',
] as const;

/**
 * Create fail-closed decryptors for a single export scope. These decryptors intentionally do not
 * share the vault detail decryptor's partial-data recovery behavior: one malformed or unauthenticated
 * value rejects the whole export object.
 */
export function createStrictVaultTransferExportDecryptors(
  options: VaultTransferExportCryptoOptions,
): VaultTransferExportDecryptors {
  return {
    decryptFolder: (folder) => captureDecrypt(async () => {
      if (options.scope.kind !== 'personal') throw new ExportDecryptError('undecryptable');
      const raw = requireRecord(folder);
      requireKnownFields(raw, FOLDER_FIELDS);
      return { name: await decryptRequiredText(raw.name, options.userKey) };
    }),
    decryptCollection: (collection) => captureDecrypt(async () => {
      const raw = requireRecord(collection);
      requireKnownFields(raw, COLLECTION_FIELDS);
      const key = requireOrganizationKey(options, raw.organizationId);
      return { name: await decryptRequiredText(raw.name, key) };
    }),
    decryptCipher: (cipher) => captureDecrypt(() => decryptCipherStrict(cipher, options)),
  };
}

/** Encode an already validated transfer IR directly to ephemeral UTF-8 bytes. */
export function encodeVaultTransferJsonBytes(
  ir: VaultTransferIR,
  options: EncodeVaultTransferJsonOptions = {},
): EncodeVaultTransferJsonBytesResult {
  const encoded = encodeVaultTransferJson(ir, options);
  if (!encoded.ok || encoded.json === null) {
    return { ok: false, bytes: null, diagnostics: [...encoded.diagnostics] };
  }
  try {
    return { ok: true, bytes: utf8ToBytes(encoded.json), diagnostics: [...encoded.diagnostics] };
  } catch {
    return {
      ok: false,
      bytes: null,
      diagnostics: [...encoded.diagnostics, {
        severity: 'error',
        code: 'utf8_encoding_failed',
        message: 'The transfer JSON could not be encoded as UTF-8.',
        path: '$',
      }],
    };
  }
}

async function decryptCipherStrict(
  cipher: CipherResponse,
  options: VaultTransferExportCryptoOptions,
): Promise<VaultTransferExportCipher> {
  const compatibility = validateRawSyncCipherCompatibility(cipher);
  if (!compatibility.ok) {
    throw new ExportDecryptError(
      compatibility.code === 'unsupported_cipher_type' ? 'unsupported_encryption' : 'undecryptable',
    );
  }
  const raw = requireRecord(cipher);
  requireKnownFields(raw, RAW_SYNC_CIPHER_FIELDS);
  const type = raw.type;
  if (!isSupportedCipherType(type)) {
    throw new ExportDecryptError('unsupported_encryption');
  }
  requireExpectedPayload(raw, type);
  const baseKey = cipherBaseKey(options, raw.organizationId, raw.collectionIds);
  let fieldKey = baseKey;
  let destroyFieldKey = false;
  try {
    if (raw.key !== undefined && raw.key !== null) {
      fieldKey = await unwrapEphemeralSymmetricKey(raw.key, baseKey);
      destroyFieldKey = true;
    }
    const decrypted: VaultTransferExportCipher = {
      type,
      name: await decryptRequiredText(raw.name, fieldKey),
    };
    await copyOptionalEncrypted(raw, decrypted, 'notes', fieldKey);
    await copyOptionalArray(raw, decrypted, 'fields', (value) => decryptCustomField(value, fieldKey));
    await copyOptionalArray(
      raw,
      decrypted,
      'passwordHistory',
      (value) => decryptPasswordHistory(value, fieldKey),
    );
    await copyOptionalArray(
      raw,
      decrypted,
      'attachments',
      (value) => decryptAttachmentMetadata(value, fieldKey),
    );

    switch (type) {
      case 1:
        decrypted.login = await decryptLogin(requireRecord(raw.login), fieldKey);
        break;
      case 2:
        decrypted.secureNote = decryptSecureNote(requireRecord(raw.secureNote));
        break;
      case 3:
        decrypted.card = await decryptStringPayload(
          requireRecord(raw.card), CARD_FIELDS, CARD_FIELD_SET, fieldKey,
        );
        break;
      case 4:
        decrypted.identity = await decryptStringPayload(
          requireRecord(raw.identity), IDENTITY_FIELDS, IDENTITY_FIELD_SET, fieldKey,
        );
        break;
      case 5:
        decrypted.sshKey = await decryptSshKey(requireRecord(raw.sshKey), fieldKey);
        break;
    }
    return decrypted;
  } finally {
    if (destroyFieldKey) destroySymmetricKey(fieldKey);
  }
}

function cipherBaseKey(
  options: VaultTransferExportCryptoOptions,
  organizationId: unknown,
  collectionIds: unknown,
): SymmetricKey {
  if (options.scope.kind === 'personal') {
    if (organizationId !== undefined && organizationId !== null) {
      throw new ExportDecryptError('undecryptable');
    }
    if (Array.isArray(collectionIds) && collectionIds.length > 0) {
      throw new ExportDecryptError('undecryptable');
    }
    return options.userKey;
  }
  if (organizationId !== options.scope.organizationId) {
    throw new ExportDecryptError('undecryptable');
  }
  return requireOrganizationKey(options, organizationId);
}

function requireOrganizationKey(
  options: VaultTransferExportCryptoOptions,
  organizationId: unknown,
): SymmetricKey {
  if (options.scope.kind !== 'organization' || organizationId !== options.scope.organizationId) {
    throw new ExportDecryptError('undecryptable');
  }
  const key = options.organizationKeys?.get(options.scope.organizationId);
  if (!key) throw new ExportDecryptError('missing_organization_key');
  return key;
}

async function decryptLogin(raw: Record<string, unknown>, key: SymmetricKey): Promise<VaultTransferExportLogin> {
  requireKnownFields(raw, LOGIN_FIELDS);
  if (!validateLoginUriAlias(raw).ok) throw new ExportDecryptError('undecryptable');
  const login: VaultTransferExportLogin = {};
  await copyOptionalEncrypted(raw, login, 'username', key);
  await copyOptionalEncrypted(raw, login, 'password', key);
  await copyOptionalEncrypted(raw, login, 'totp', key);
  copyOptionalNullableBoolean(raw, login, 'autofillOnPageLoad');
  copyOptionalIsoDate(raw, login, 'passwordRevisionDate');
  await copyOptionalArray(raw, login, 'uris', (value) => decryptLoginUri(value, key));
  await copyOptionalArray(
    raw,
    login,
    'fido2Credentials',
    (value) => decryptPasskey(value, key),
  );
  return login;
}

async function decryptLoginUri(value: unknown, key: SymmetricKey): Promise<VaultTransferExportLoginUri> {
  const raw = requireRecord(value);
  requireKnownFields(raw, URI_FIELDS);
  const clearUri = await decryptRequiredText(raw.uri, key);
  if (raw.uriChecksum !== undefined && raw.uriChecksum !== null) {
    const checksum = await decryptText(raw.uriChecksum, key);
    if (!await validateLoginUriChecksum(clearUri, checksum)) {
      throw new ExportDecryptError('undecryptable');
    }
  }
  const uri: VaultTransferExportLoginUri = { uri: clearUri };
  copyOptionalInteger(raw, uri, 'match');
  return uri;
}

async function decryptPasskey(value: unknown, key: SymmetricKey): Promise<VaultTransferExportPasskey> {
  const raw = requireRecord(value);
  requireKnownFields(raw, PASSKEY_FIELDS);
  const passkey = {} as VaultTransferExportPasskey;
  for (const field of PASSKEY_REQUIRED_FIELDS) {
    passkey[field] = await decryptRequiredText(raw[field], key);
  }
  for (const field of PASSKEY_OPTIONAL_ENCRYPTED_FIELDS) {
    await copyOptionalEncrypted(raw, passkey, field, key);
  }
  passkey.creationDate = requireDate(raw.creationDate);
  return passkey;
}

async function decryptCustomField(value: unknown, key: SymmetricKey): Promise<VaultTransferExportField> {
  const raw = requireRecord(value);
  requireKnownFields(raw, CUSTOM_FIELD_FIELDS);
  if (raw.type !== 0 && raw.type !== 1 && raw.type !== 2 && raw.type !== 3) {
    throw new ExportDecryptError('undecryptable');
  }
  const field: VaultTransferExportField = { type: raw.type };
  await copyOptionalEncrypted(raw, field, 'name', key);
  await copyOptionalEncrypted(raw, field, 'value', key);
  copyOptionalInteger(raw, field, 'linkedId');
  if (field.type === 3 && !Number.isInteger(field.linkedId)) {
    throw new ExportDecryptError('undecryptable');
  }
  return field;
}

async function decryptPasswordHistory(
  value: unknown,
  key: SymmetricKey,
): Promise<VaultTransferExportPasswordHistory> {
  const raw = requireRecord(value);
  requireKnownFields(raw, PASSWORD_HISTORY_FIELDS);
  const history: VaultTransferExportPasswordHistory = {
    password: await decryptRequiredText(raw.password, key),
    lastUsedDate: requireDate(raw.lastUsedDate),
  };
  return history;
}

async function decryptAttachmentMetadata(
  value: unknown,
  key: SymmetricKey,
): Promise<{ id: string; fileName: string; size?: string | null; sizeName?: string | null }> {
  const raw = requireRecord(value);
  requireKnownFields(raw, ATTACHMENT_FIELDS);
  const id = requireNonEmptyString(raw.id);
  if (raw.url !== undefined && raw.url !== null) requireNonEmptyString(raw.url);
  const attachmentKey = await unwrapEphemeralSymmetricKey(raw.key, key);
  destroySymmetricKey(attachmentKey);
  const metadata: { id: string; fileName: string; size?: string | null; sizeName?: string | null } = {
    id,
    fileName: await decryptRequiredText(raw.fileName, key),
  };
  copyOptionalString(raw, metadata, 'size');
  copyOptionalString(raw, metadata, 'sizeName');
  return metadata;
}

function decryptSecureNote(raw: Record<string, unknown>): { type: number } {
  requireKnownFields(raw, SECURE_NOTE_FIELDS);
  if (typeof raw.type !== 'number' || !Number.isInteger(raw.type)) {
    throw new ExportDecryptError('undecryptable');
  }
  return { type: raw.type };
}

async function decryptStringPayload(
  raw: Record<string, unknown>,
  fields: readonly string[],
  fieldSet: ReadonlySet<string>,
  key: SymmetricKey,
): Promise<Record<string, string | null>> {
  requireKnownFields(raw, fieldSet);
  const output: Record<string, string | null> = {};
  for (const field of fields) await copyOptionalEncrypted(raw, output, field, key);
  return output;
}

async function decryptSshKey(
  raw: Record<string, unknown>,
  key: SymmetricKey,
): Promise<Record<string, string | null>> {
  requireKnownFields(raw, SSH_FIELD_SET);
  const output: Record<string, string | null> = {};
  for (const field of SSH_FIELDS) output[field] = await decryptRequiredText(raw[field], key);
  return output;
}

async function copyOptionalEncrypted(
  source: Record<string, unknown>,
  target: object,
  field: string,
  key: SymmetricKey,
): Promise<void> {
  const value = source[field];
  if (value === undefined) return;
  if (value === null) {
    assign(target, field, null);
    return;
  }
  assign(target, field, await decryptText(value, key));
}

async function copyOptionalArray<T>(
  source: Record<string, unknown>,
  target: object,
  field: string,
  mapper: (value: unknown) => Promise<T>,
): Promise<void> {
  const value = source[field];
  if (value === undefined) return;
  if (value === null) {
    assign(target, field, null);
    return;
  }
  if (!Array.isArray(value)) throw new ExportDecryptError('undecryptable');
  const output: T[] = [];
  for (const entry of value) output.push(await mapper(entry));
  assign(target, field, output);
}

function copyOptionalInteger(source: Record<string, unknown>, target: object, field: string): void {
  const value = source[field];
  if (value === undefined) return;
  if (value !== null && (typeof value !== 'number' || !Number.isInteger(value))) {
    throw new ExportDecryptError('undecryptable');
  }
  assign(target, field, value);
}

function requireDate(value: unknown): string {
  if (typeof value !== 'string' || !isOptionalNullableIsoTimestamp(value)) {
    throw new ExportDecryptError('undecryptable');
  }
  return value;
}

function copyOptionalIsoDate(source: Record<string, unknown>, target: object, field: string): void {
  const value = source[field];
  if (value === undefined) return;
  if (!isOptionalNullableIsoTimestamp(value)) throw new ExportDecryptError('undecryptable');
  assign(target, field, value);
}

function copyOptionalNullableBoolean(source: Record<string, unknown>, target: object, field: string): void {
  const value = source[field];
  if (value === undefined) return;
  if (value !== null && typeof value !== 'boolean') throw new ExportDecryptError('undecryptable');
  assign(target, field, value);
}

function copyOptionalString(source: Record<string, unknown>, target: object, field: string): void {
  const value = source[field];
  if (value === undefined) return;
  if (value !== null && typeof value !== 'string') throw new ExportDecryptError('undecryptable');
  assign(target, field, value);
}

async function decryptRequiredText(value: unknown, key: SymmetricKey): Promise<string> {
  const plaintext = await decryptText(value, key);
  if (plaintext.length === 0) throw new ExportDecryptError('undecryptable');
  return plaintext;
}

async function decryptText(value: unknown, key: SymmetricKey): Promise<string> {
  const plaintext = await decryptToBytes(requireEncryptedString(value), key);
  try {
    return STRICT_UTF8_DECODER.decode(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

async function unwrapEphemeralSymmetricKey(value: unknown, wrappingKey: SymmetricKey): Promise<SymmetricKey> {
  const plaintext = await decryptToBytes(requireEncryptedString(value), wrappingKey);
  try {
    return symmetricKeyFromBytes(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

function requireEncryptedString(value: unknown): string {
  return requireNonEmptyString(value);
}

function requireNonEmptyString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) throw new ExportDecryptError('undecryptable');
  return value;
}

function requireExpectedPayload(raw: Record<string, unknown>, type: number): void {
  const expected = ITEM_PAYLOAD_FIELDS[type - 1];
  if (!expected || !isRecord(raw[expected])) throw new ExportDecryptError('undecryptable');
  for (const field of ITEM_PAYLOAD_FIELDS) {
    if (field !== expected && raw[field] !== undefined && raw[field] !== null) {
      throw new ExportDecryptError('undecryptable');
    }
  }
}

function isSupportedCipherType(value: unknown): value is 1 | 2 | 3 | 4 | 5 {
  return value === 1 || value === 2 || value === 3 || value === 4 || value === 5;
}

function requireKnownFields(raw: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  if (Object.keys(raw).some((field) => !allowed.has(field))) {
    throw new ExportDecryptError('undecryptable');
  }
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new ExportDecryptError('undecryptable');
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function assign(target: object, field: string, value: unknown): void {
  (target as Record<string, unknown>)[field] = value;
}

function destroySymmetricKey(key: SymmetricKey): void {
  key.encKey.fill(0);
  key.macKey.fill(0);
}

async function captureDecrypt<T>(
  operation: () => Promise<T>,
): Promise<VaultTransferDecryptResult<T>> {
  try {
    return { status: 'decrypted', value: await operation() };
  } catch (error) {
    if (error instanceof ExportDecryptError) return { status: 'failed', code: error.code };
    if (error instanceof UnsupportedEncTypeError) {
      return { status: 'failed', code: 'unsupported_encryption' };
    }
    return { status: 'failed', code: 'undecryptable' };
  }
}

class ExportDecryptError extends Error {
  constructor(readonly code: VaultTransferDecryptFailureCode) {
    super(code);
  }
}
