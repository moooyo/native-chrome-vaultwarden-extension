/**
 * Strict compatibility gate for the redundant cipher representations returned by Bitwarden 2026.8.
 * The server's `data` string uses the PascalCase CipherData DTO while the deprecated structured
 * projection remains camelCase. This module compares those representations before any decryption.
 */

import { validateLoginUriAlias } from './vault-transfer-login-wire.js';

export interface RawSyncCipherCompatibilityLimits {
  maxDataBytes: number;
  maxDataChars: number;
  maxDepth: number;
  maxNodes: number;
  maxProperties: number;
  maxArrayLength: number;
}

export const DEFAULT_RAW_SYNC_CIPHER_COMPATIBILITY_LIMITS: Readonly<RawSyncCipherCompatibilityLimits> = Object.freeze({
  // CipherRequestModel.Data is capped at 500,000 UTF-16 characters by the 2026.8 server.
  maxDataBytes: 2_000_000,
  maxDataChars: 500_000,
  maxDepth: 8,
  maxNodes: 20_000,
  maxProperties: 20_000,
  maxArrayLength: 5_000,
});

export interface ValidateRawSyncCipherCompatibilityOptions {
  readonly limits?: Partial<RawSyncCipherCompatibilityLimits>;
}

export type RawSyncCipherCompatibilityErrorCode =
  | 'invalid_cipher'
  | 'unsupported_cipher_type'
  | 'invalid_permissions'
  | 'invalid_data_type'
  | 'data_too_large'
  | 'data_limit_exceeded'
  | 'malformed_data'
  | 'invalid_data_root'
  | 'duplicate_data_key'
  | 'encrypted_data_blob'
  | 'unknown_data_field'
  | 'invalid_data_shape'
  | 'invalid_structured_projection'
  | 'login_uri_alias_mismatch'
  | 'data_projection_mismatch';

export type RawSyncCipherCompatibilityResult =
  | { readonly ok: true; readonly dataMode: 'structured-only' | 'redundant-plain-data' }
  | { readonly ok: false; readonly code: RawSyncCipherCompatibilityErrorCode };

type PlainRecord = Record<string, unknown>;
type CompatibilitySide = 'data' | 'projection';
type ScalarKind = 'string' | 'boolean' | 'integer' | 'date';

const PERMISSION_FIELDS = new Set(['delete', 'restore']);
const MAX_ENVELOPE_STRING_CHARS = 1024 * 1024;
export const RAW_SYNC_CIPHER_FIELDS: ReadonlySet<string> = new Set([
  'id', 'type', 'attachments', 'name', 'notes', 'favorite', 'organizationId', 'folderId',
  'collectionIds', 'key', 'login', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount',
  'driversLicense', 'passport', 'fields', 'passwordHistory', 'reprompt', 'deletedDate',
  'revisionDate', 'creationDate', 'archivedDate', 'organizationUseTotp', 'edit', 'viewPassword',
  'localData', 'object', 'data', 'permissions',
]);
const ATTACHMENT_FIELDS = new Set(['id', 'url', 'fileName', 'key', 'size', 'sizeName', 'object']);
const DATA_BASE_FIELDS = ['Name', 'Notes', 'Fields', 'PasswordHistory'] as const;
const DATA_LOGIN_FIELDS = [
  'Uris', 'Username', 'Password', 'PasswordRevisionDate', 'Totp', 'AutofillOnPageLoad',
  'Fido2Credentials',
] as const;
const DATA_CARD_FIELDS = ['CardholderName', 'Brand', 'Number', 'ExpMonth', 'ExpYear', 'Code'] as const;
const DATA_IDENTITY_FIELDS = [
  'Title', 'FirstName', 'MiddleName', 'LastName', 'Address1', 'Address2', 'Address3', 'City',
  'State', 'PostalCode', 'Country', 'Company', 'Email', 'Phone', 'SSN', 'Username',
  'PassportNumber', 'LicenseNumber',
] as const;
const DATA_SSH_FIELDS = ['PrivateKey', 'PublicKey', 'KeyFingerprint'] as const;

const STRUCTURED_LOGIN_FIELDS = new Set([
  'uri', 'uris', 'username', 'password', 'passwordRevisionDate', 'totp', 'autofillOnPageLoad',
  'fido2Credentials',
]);
const DATA_URI_FIELDS = new Set(['Uri', 'UriChecksum', 'Match']);
const STRUCTURED_URI_FIELDS = new Set(['uri', 'uriChecksum', 'match']);
const DATA_PASSKEY_FIELDS = new Set([
  'CredentialId', 'KeyType', 'KeyAlgorithm', 'KeyCurve', 'KeyValue', 'RpId', 'RpName',
  'UserHandle', 'UserName', 'UserDisplayName', 'Counter', 'Discoverable', 'CreationDate',
]);
const STRUCTURED_PASSKEY_FIELDS = new Set([
  'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'rpName',
  'userHandle', 'userName', 'userDisplayName', 'counter', 'discoverable', 'creationDate',
]);
const DATA_CUSTOM_FIELD_FIELDS = new Set(['Type', 'Name', 'Value', 'LinkedId']);
const STRUCTURED_CUSTOM_FIELD_FIELDS = new Set(['type', 'name', 'value', 'linkedId']);
const DATA_HISTORY_FIELDS = new Set(['Password', 'LastUsedDate']);
const STRUCTURED_HISTORY_FIELDS = new Set(['password', 'lastUsedDate']);
const STRUCTURED_SECURE_NOTE_FIELDS = new Set(['type']);
const STRUCTURED_CARD_FIELDS = new Set(DATA_CARD_FIELDS.map(lowerFirst));
const STRUCTURED_IDENTITY_FIELDS = new Set(DATA_IDENTITY_FIELDS.map(lowerFirst));
const STRUCTURED_SSH_FIELDS = new Set(['privateKey', 'publicKey', 'keyFingerprint']);

const PASSKEY_REQUIRED_STRINGS = [
  ['CredentialId', 'credentialId'],
  ['KeyType', 'keyType'],
  ['KeyAlgorithm', 'keyAlgorithm'],
  ['KeyCurve', 'keyCurve'],
  ['KeyValue', 'keyValue'],
  ['RpId', 'rpId'],
  ['Counter', 'counter'],
] as const;
const PASSKEY_OPTIONAL_STRINGS = [
  ['RpName', 'rpName'],
  ['UserHandle', 'userHandle'],
  ['UserName', 'userName'],
  ['UserDisplayName', 'userDisplayName'],
  // Legacy credentials may omit this encrypted flag. The crypto layer treats a missing, malformed,
  // or non-"true" value as non-discoverable while preserving exact-ID authentication.
  ['Discoverable', 'discoverable'],
] as const;

/** Validate one raw sync cipher without decrypting or returning any secret-bearing data. */
export function validateRawSyncCipherCompatibility(
  cipher: unknown,
  options: ValidateRawSyncCipherCompatibilityOptions = {},
): RawSyncCipherCompatibilityResult {
  const limits = resolveLimits(options.limits);
  try {
    const raw = requirePlainDataRecord(cipher, 'invalid_cipher', RAW_SYNC_CIPHER_FIELDS);
    if (!isSupportedCipherType(raw.type)) fail('unsupported_cipher_type');
    validateEnvelopeMetadata(raw, limits);
    validateUnexpectedPayloads(raw, raw.type);
    validatePermissions(raw);

    const dataEntry = ownEntry(raw, 'data');
    if (!dataEntry.present || dataEntry.value === null) {
      validateStructuredProjectionOnly(raw, raw.type, limits);
      return { ok: true, dataMode: 'structured-only' };
    }
    if (typeof dataEntry.value !== 'string') fail('invalid_data_type');
    const rawData = dataEntry.value;
    if (rawData.length > limits.maxDataChars || utf8ByteLength(rawData) > limits.maxDataBytes) {
      fail('data_too_large');
    }

    const data = new BoundedJsonParser(rawData, limits).parse();
    if (!isPlainDataRecord(data)) fail('invalid_data_root');
    rejectBlobMarker(data);
    compareCipherData(raw, data, raw.type, limits);
    return { ok: true, dataMode: 'redundant-plain-data' };
  } catch (error) {
    if (error instanceof CompatibilityFailure) return { ok: false, code: error.code };
    return { ok: false, code: 'invalid_cipher' };
  }
}

function validatePermissions(cipher: PlainRecord): void {
  const entry = ownEntry(cipher, 'permissions');
  if (!entry.present) return;
  const permissions = requirePlainDataRecord(entry.value, 'invalid_permissions', PERMISSION_FIELDS);
  for (const field of PERMISSION_FIELDS) {
    const entry = ownEntry(permissions, field);
    if (!entry.present) continue;
    if (entry.value !== null && typeof entry.value !== 'boolean') fail('invalid_permissions');
  }
}

function validateEnvelopeMetadata(
  cipher: PlainRecord,
  limits: RawSyncCipherCompatibilityLimits,
): void {
  validateWireString(cipher, 'id', false, true, MAX_ENVELOPE_STRING_CHARS);
  for (const field of ['organizationId', 'folderId', 'key']) {
    validateWireString(cipher, field, true, false, MAX_ENVELOPE_STRING_CHARS);
  }
  validateWireString(cipher, 'object', false, false, MAX_ENVELOPE_STRING_CHARS);
  for (const field of ['favorite', 'organizationUseTotp', 'edit', 'viewPassword']) {
    validateWireBoolean(cipher, field);
  }
  for (const field of ['deletedDate', 'revisionDate', 'creationDate', 'archivedDate']) {
    validateWireDate(cipher, field);
  }
  validateWireReprompt(cipher);
  validateOptionalArray(cipher, 'collectionIds', limits, (value) => {
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ENVELOPE_STRING_CHARS) {
      fail('invalid_cipher');
    }
  }, 'invalid_cipher');
  validateOptionalArray(
    cipher,
    'attachments',
    limits,
    validateAttachment,
    'invalid_cipher',
  );

  const localData = ownEntry(cipher, 'localData');
  if (localData.present && localData.value !== null) fail('invalid_cipher');
}

function validateAttachment(value: unknown): void {
  const attachment = requirePlainDataRecord(value, 'invalid_cipher', ATTACHMENT_FIELDS);
  validateWireString(attachment, 'id', false, true, MAX_ENVELOPE_STRING_CHARS);
  for (const field of ['url', 'fileName', 'key', 'size', 'sizeName']) {
    validateWireString(attachment, field, true, false, MAX_ENVELOPE_STRING_CHARS);
  }
  validateWireString(attachment, 'object', false, false, MAX_ENVELOPE_STRING_CHARS);
}

function validateWireString(
  record: PlainRecord,
  field: string,
  nullable: boolean,
  required: boolean,
  maxChars: number,
): void {
  const entry = ownEntry(record, field);
  if (!entry.present) {
    if (required) fail('invalid_cipher');
    return;
  }
  if (entry.value === null) {
    if (!nullable) fail('invalid_cipher');
    return;
  }
  if (typeof entry.value !== 'string' || entry.value.length === 0 || entry.value.length > maxChars) {
    fail('invalid_cipher');
  }
}

function validateWireBoolean(record: PlainRecord, field: string): void {
  const entry = ownEntry(record, field);
  if (entry.present && typeof entry.value !== 'boolean') fail('invalid_cipher');
}

function validateWireDate(record: PlainRecord, field: string): void {
  const entry = ownEntry(record, field);
  if (!entry.present || entry.value === null) return;
  if (typeof entry.value !== 'string' || parseIsoInstant(entry.value) === null) fail('invalid_cipher');
}

function validateWireReprompt(record: PlainRecord): void {
  const entry = ownEntry(record, 'reprompt');
  if (!entry.present || entry.value === null) return;
  if (entry.value !== 0 && entry.value !== 1) fail('invalid_cipher');
}

function compareCipherData(
  cipher: PlainRecord,
  data: PlainRecord,
  type: 1 | 2 | 3 | 4 | 5,
  limits: RawSyncCipherCompatibilityLimits,
): void {
  const typeFields = type === 1
    ? DATA_LOGIN_FIELDS
    : type === 2
      ? (['Type'] as const)
      : type === 3
        ? DATA_CARD_FIELDS
        : type === 4
          ? DATA_IDENTITY_FIELDS
          : DATA_SSH_FIELDS;
  requireKnownDataFields(data, new Set<string>([...DATA_BASE_FIELDS, ...typeFields]));

  compareRequiredString(data, 'Name', cipher, 'name');
  compareOptionalScalar(data, 'Notes', cipher, 'notes', 'string');
  compareOptionalArray(data, 'Fields', cipher, 'fields', limits, compareCustomField);
  compareOptionalArray(data, 'PasswordHistory', cipher, 'passwordHistory', limits, comparePasswordHistory);

  switch (type) {
    case 1:
      compareLogin(data, requireProjectionRecord(cipher.login, STRUCTURED_LOGIN_FIELDS), limits);
      break;
    case 2:
      compareSecureNote(data, requireProjectionRecord(cipher.secureNote, STRUCTURED_SECURE_NOTE_FIELDS));
      break;
    case 3:
      compareStringPayload(
        data,
        requireProjectionRecord(cipher.card, STRUCTURED_CARD_FIELDS),
        DATA_CARD_FIELDS,
      );
      break;
    case 4:
      compareStringPayload(
        data,
        requireProjectionRecord(cipher.identity, STRUCTURED_IDENTITY_FIELDS),
        DATA_IDENTITY_FIELDS,
      );
      break;
    case 5:
      compareSshKey(data, requireProjectionRecord(cipher.sshKey, STRUCTURED_SSH_FIELDS));
      break;
  }
}

function compareLogin(
  data: PlainRecord,
  login: PlainRecord,
  limits: RawSyncCipherCompatibilityLimits,
): void {
  if (!validateLoginUriAlias(login).ok) fail('login_uri_alias_mismatch');
  compareOptionalScalar(data, 'Username', login, 'username', 'string');
  compareOptionalScalar(data, 'Password', login, 'password', 'string');
  compareOptionalScalar(data, 'PasswordRevisionDate', login, 'passwordRevisionDate', 'date');
  compareOptionalScalar(data, 'Totp', login, 'totp', 'string');
  compareOptionalScalar(data, 'AutofillOnPageLoad', login, 'autofillOnPageLoad', 'boolean');
  compareOptionalArray(data, 'Uris', login, 'uris', limits, compareLoginUri);
  compareOptionalArray(
    data,
    'Fido2Credentials',
    login,
    'fido2Credentials',
    limits,
    comparePasskey,
  );
}

function validateStructuredProjectionOnly(
  cipher: PlainRecord,
  type: 1 | 2 | 3 | 4 | 5,
  limits: RawSyncCipherCompatibilityLimits,
): void {
  validateRequiredString(cipher, 'name', 'projection');
  validateOptionalScalar(cipher, 'notes', 'string', 'projection');
  validateOptionalArray(cipher, 'fields', limits, validateCustomFieldProjection);
  validateOptionalArray(cipher, 'passwordHistory', limits, validatePasswordHistoryProjection);

  const expected = ['login', 'secureNote', 'card', 'identity', 'sshKey'][type - 1]!;
  const payloadEntry = ownEntry(cipher, expected);
  if (!payloadEntry.present || payloadEntry.value === null) fail('invalid_structured_projection');
  switch (type) {
    case 1:
      validateLoginProjection(requireProjectionRecord(payloadEntry.value, STRUCTURED_LOGIN_FIELDS), limits);
      break;
    case 2:
      validateSecureNoteProjection(
        requireProjectionRecord(payloadEntry.value, STRUCTURED_SECURE_NOTE_FIELDS),
      );
      break;
    case 3:
      validateStringProjection(
        requireProjectionRecord(payloadEntry.value, STRUCTURED_CARD_FIELDS),
        [...STRUCTURED_CARD_FIELDS],
      );
      break;
    case 4:
      validateStringProjection(
        requireProjectionRecord(payloadEntry.value, STRUCTURED_IDENTITY_FIELDS),
        [...STRUCTURED_IDENTITY_FIELDS],
      );
      break;
    case 5:
      validateSshProjection(requireProjectionRecord(payloadEntry.value, STRUCTURED_SSH_FIELDS));
      break;
  }
}

function validateUnexpectedPayloads(cipher: PlainRecord, type: 1 | 2 | 3 | 4 | 5): void {
  const expected = ['login', 'secureNote', 'card', 'identity', 'sshKey'][type - 1]!;
  for (const field of [
    'login', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount', 'driversLicense', 'passport',
  ]) {
    if (field === expected) continue;
    const entry = ownEntry(cipher, field);
    if (entry.present && entry.value !== null) {
      fail('invalid_structured_projection');
    }
  }
}

function validateLoginProjection(login: PlainRecord, limits: RawSyncCipherCompatibilityLimits): void {
  if (!validateLoginUriAlias(login).ok) fail('login_uri_alias_mismatch');
  validateOptionalScalar(login, 'username', 'string', 'projection');
  validateOptionalScalar(login, 'password', 'string', 'projection');
  validateOptionalScalar(login, 'passwordRevisionDate', 'date', 'projection');
  validateOptionalScalar(login, 'totp', 'string', 'projection');
  validateOptionalScalar(login, 'autofillOnPageLoad', 'boolean', 'projection');
  validateOptionalArray(login, 'uris', limits, validateLoginUriProjection);
  validateOptionalArray(login, 'fido2Credentials', limits, validatePasskeyProjection);
}

function validateSecureNoteProjection(secureNote: PlainRecord): void {
  requiredInteger(secureNote, 'type', 'projection', 0, 0);
}

function validateStringProjection(projection: PlainRecord, fields: readonly string[]): void {
  for (const field of fields) validateOptionalScalar(projection, field, 'string', 'projection');
}

function validateSshProjection(sshKey: PlainRecord): void {
  validateRequiredString(sshKey, 'privateKey', 'projection');
  validateOptionalScalar(sshKey, 'publicKey', 'string', 'projection');
  validateOptionalScalar(sshKey, 'keyFingerprint', 'string', 'projection');
}

function validateCustomFieldProjection(value: unknown): void {
  const field = requireProjectionRecord(value, STRUCTURED_CUSTOM_FIELD_FIELDS);
  requiredInteger(field, 'type', 'projection', 0, 3);
  validateOptionalScalar(field, 'name', 'string', 'projection');
  validateOptionalScalar(field, 'value', 'string', 'projection');
  validateOptionalScalar(field, 'linkedId', 'integer', 'projection');
}

function validatePasswordHistoryProjection(value: unknown): void {
  const history = requireProjectionRecord(value, STRUCTURED_HISTORY_FIELDS);
  validateRequiredString(history, 'password', 'projection');
  validateRequiredDate(history, 'lastUsedDate', 'projection');
}

function validateLoginUriProjection(value: unknown): void {
  const uri = requireProjectionRecord(value, STRUCTURED_URI_FIELDS);
  validateRequiredString(uri, 'uri', 'projection');
  validateOptionalScalar(uri, 'uriChecksum', 'string', 'projection');
  const match = optionalScalar(uri, 'match', 'integer', 'projection');
  if (typeof match === 'number' && (match < 0 || match > 5)) fail('invalid_structured_projection');
}

function validatePasskeyProjection(value: unknown): void {
  const passkey = requireProjectionRecord(value, STRUCTURED_PASSKEY_FIELDS);
  for (const [, field] of PASSKEY_REQUIRED_STRINGS) validateRequiredString(passkey, field, 'projection');
  for (const [, field] of PASSKEY_OPTIONAL_STRINGS) {
    validateOptionalScalar(passkey, field, 'string', 'projection');
  }
  validateRequiredDate(passkey, 'creationDate', 'projection');
}

function compareSecureNote(data: PlainRecord, secureNote: PlainRecord): void {
  compareRequiredInteger(data, 'Type', secureNote, 'type', 0, 0);
}

function compareStringPayload(
  data: PlainRecord,
  projection: PlainRecord,
  fields: readonly string[],
): void {
  for (const field of fields) {
    compareOptionalScalar(data, field, projection, lowerFirst(field), 'string');
  }
}

function compareSshKey(data: PlainRecord, sshKey: PlainRecord): void {
  compareRequiredString(data, 'PrivateKey', sshKey, 'privateKey');
  compareOptionalScalar(data, 'PublicKey', sshKey, 'publicKey', 'string');
  compareOptionalScalar(data, 'KeyFingerprint', sshKey, 'keyFingerprint', 'string');
}

function compareCustomField(dataValue: unknown, projectionValue: unknown): void {
  const data = requireDataRecord(dataValue, DATA_CUSTOM_FIELD_FIELDS);
  const projection = requireProjectionRecord(projectionValue, STRUCTURED_CUSTOM_FIELD_FIELDS);
  compareRequiredInteger(data, 'Type', projection, 'type', 0, 3);
  compareOptionalScalar(data, 'Name', projection, 'name', 'string');
  compareOptionalScalar(data, 'Value', projection, 'value', 'string');
  compareOptionalScalar(data, 'LinkedId', projection, 'linkedId', 'integer');
}

function comparePasswordHistory(dataValue: unknown, projectionValue: unknown): void {
  const data = requireDataRecord(dataValue, DATA_HISTORY_FIELDS);
  const projection = requireProjectionRecord(projectionValue, STRUCTURED_HISTORY_FIELDS);
  compareRequiredString(data, 'Password', projection, 'password');
  compareRequiredDate(data, 'LastUsedDate', projection, 'lastUsedDate');
}

function compareLoginUri(dataValue: unknown, projectionValue: unknown): void {
  const data = requireDataRecord(dataValue, DATA_URI_FIELDS);
  const projection = requireProjectionRecord(projectionValue, STRUCTURED_URI_FIELDS);
  compareRequiredString(data, 'Uri', projection, 'uri');
  // UriChecksum is itself an EncString. Its decrypted SHA-256 Base64 shape belongs to the crypto
  // layer; this pre-decrypt gate can only require byte-for-byte equality of the opaque ciphertext.
  compareOptionalScalar(data, 'UriChecksum', projection, 'uriChecksum', 'string');
  compareOptionalInteger(data, 'Match', projection, 'match', 0, 5);
}

function comparePasskey(dataValue: unknown, projectionValue: unknown): void {
  const data = requireDataRecord(dataValue, DATA_PASSKEY_FIELDS);
  const projection = requireProjectionRecord(projectionValue, STRUCTURED_PASSKEY_FIELDS);
  for (const [dataField, projectionField] of PASSKEY_REQUIRED_STRINGS) {
    compareRequiredString(data, dataField, projection, projectionField);
  }
  for (const [dataField, projectionField] of PASSKEY_OPTIONAL_STRINGS) {
    compareOptionalScalar(data, dataField, projection, projectionField, 'string');
  }
  compareRequiredDate(data, 'CreationDate', projection, 'creationDate');
}

function compareOptionalArray(
  data: PlainRecord,
  dataField: string,
  projection: PlainRecord,
  projectionField: string,
  limits: RawSyncCipherCompatibilityLimits,
  compareEntry: (dataValue: unknown, projectionValue: unknown) => void,
): void {
  const left = readOptionalArray(data, dataField, 'data', limits);
  const right = readOptionalArray(projection, projectionField, 'projection', limits);
  if (left === null || right === null) {
    if (left !== right) fail('data_projection_mismatch');
    return;
  }
  if (left.length !== right.length) fail('data_projection_mismatch');
  for (let index = 0; index < left.length; index++) compareEntry(left[index], right[index]);
}

function readOptionalArray(
  record: PlainRecord,
  field: string,
  side: CompatibilitySide,
  limits: RawSyncCipherCompatibilityLimits,
): unknown[] | null {
  const entry = ownEntry(record, field);
  if (!entry.present || entry.value === null) return null;
  if (!Array.isArray(entry.value)) fail(sideError(side));
  requireDenseDataArray(entry.value, sideError(side));
  if (entry.value.length > limits.maxArrayLength) fail('data_limit_exceeded');
  return entry.value;
}

function validateOptionalArray(
  record: PlainRecord,
  field: string,
  limits: RawSyncCipherCompatibilityLimits,
  validateEntry: (value: unknown) => void,
  code: RawSyncCipherCompatibilityErrorCode = 'invalid_structured_projection',
): void {
  const entry = ownEntry(record, field);
  if (!entry.present || entry.value === null) return;
  if (!Array.isArray(entry.value)) fail(code);
  requireDenseDataArray(entry.value, code);
  if (entry.value.length > limits.maxArrayLength) fail('data_limit_exceeded');
  for (const value of entry.value) validateEntry(value);
}

function validateRequiredString(
  record: PlainRecord,
  field: string,
  side: CompatibilitySide,
): void {
  const entry = ownEntry(record, field);
  if (!entry.present || typeof entry.value !== 'string' || entry.value.length === 0
    || entry.value.length > MAX_ENVELOPE_STRING_CHARS) {
    fail(sideError(side));
  }
}

function validateOptionalScalar(
  record: PlainRecord,
  field: string,
  kind: ScalarKind,
  side: CompatibilitySide,
): void {
  optionalScalar(record, field, kind, side);
}

function validateRequiredDate(record: PlainRecord, field: string, side: CompatibilitySide): void {
  const entry = ownEntry(record, field);
  if (!entry.present || typeof entry.value !== 'string' || parseIsoInstant(entry.value) === null) {
    fail(sideError(side));
  }
}

function compareRequiredDate(
  data: PlainRecord,
  dataField: string,
  projection: PlainRecord,
  projectionField: string,
): void {
  const leftEntry = ownEntry(data, dataField);
  if (!leftEntry.present || typeof leftEntry.value !== 'string') fail('invalid_data_shape');
  const left = parseIsoInstant(leftEntry.value);
  if (left === null) fail('invalid_data_shape');
  const rightEntry = ownEntry(projection, projectionField);
  if (!rightEntry.present || typeof rightEntry.value !== 'string') fail('invalid_structured_projection');
  const right = parseIsoInstant(rightEntry.value);
  if (right === null) fail('invalid_structured_projection');
  if (left !== right) fail('data_projection_mismatch');
}

function compareRequiredString(
  data: PlainRecord,
  dataField: string,
  projection: PlainRecord,
  projectionField: string,
): void {
  const left = ownEntry(data, dataField);
  const right = ownEntry(projection, projectionField);
  if (!left.present || typeof left.value !== 'string' || left.value.length === 0
    || left.value.length > MAX_ENVELOPE_STRING_CHARS) fail('invalid_data_shape');
  if (!right.present || typeof right.value !== 'string' || right.value.length === 0
    || right.value.length > MAX_ENVELOPE_STRING_CHARS) {
    fail('invalid_structured_projection');
  }
  if (left.value !== right.value) fail('data_projection_mismatch');
}

function compareRequiredInteger(
  data: PlainRecord,
  dataField: string,
  projection: PlainRecord,
  projectionField: string,
  minimum: number,
  maximum: number,
): void {
  const left = requiredInteger(data, dataField, 'data', minimum, maximum);
  const right = requiredInteger(projection, projectionField, 'projection', minimum, maximum);
  if (left !== right) fail('data_projection_mismatch');
}

function compareOptionalInteger(
  data: PlainRecord,
  dataField: string,
  projection: PlainRecord,
  projectionField: string,
  minimum: number,
  maximum: number,
): void {
  const left = optionalScalar(data, dataField, 'integer', 'data');
  const right = optionalScalar(projection, projectionField, 'integer', 'projection');
  if (typeof left === 'number' && (left < minimum || left > maximum)) fail('invalid_data_shape');
  if (typeof right === 'number' && (right < minimum || right > maximum)) {
    fail('invalid_structured_projection');
  }
  if (left !== right) fail('data_projection_mismatch');
}

function requiredInteger(
  record: PlainRecord,
  field: string,
  side: CompatibilitySide,
  minimum: number,
  maximum: number,
): number {
  const entry = ownEntry(record, field);
  if (!entry.present || !Number.isSafeInteger(entry.value)) fail(sideError(side));
  const value = entry.value as number;
  if (value < minimum || value > maximum) fail(sideError(side));
  return value;
}

function compareOptionalScalar(
  data: PlainRecord,
  dataField: string,
  projection: PlainRecord,
  projectionField: string,
  kind: ScalarKind,
): void {
  const left = optionalScalar(data, dataField, kind, 'data');
  const right = optionalScalar(projection, projectionField, kind, 'projection');
  if (left !== right) fail('data_projection_mismatch');
}

function optionalScalar(
  record: PlainRecord,
  field: string,
  kind: ScalarKind,
  side: CompatibilitySide,
): string | number | boolean | bigint | null {
  const entry = ownEntry(record, field);
  if (!entry.present || entry.value === null) return null;
  const error = sideError(side);
  switch (kind) {
    case 'string':
      if (typeof entry.value !== 'string' || entry.value.length > MAX_ENVELOPE_STRING_CHARS) fail(error);
      return entry.value;
    case 'boolean':
      if (typeof entry.value !== 'boolean') fail(error);
      return entry.value;
    case 'integer':
      if (!Number.isSafeInteger(entry.value)) fail(error);
      return entry.value as number;
    case 'date': {
      if (typeof entry.value !== 'string') fail(error);
      const instant = parseIsoInstant(entry.value);
      if (instant === null) fail(error);
      return instant;
    }
  }
}

function requireDataRecord(value: unknown, allowed: ReadonlySet<string>): PlainRecord {
  const record = requirePlainDataRecord(value, 'invalid_data_shape');
  requireKnownDataFields(record, allowed);
  return record;
}

function requireProjectionRecord(value: unknown, allowed: ReadonlySet<string>): PlainRecord {
  return requirePlainDataRecord(value, 'invalid_structured_projection', allowed);
}

function requireKnownDataFields(record: PlainRecord, allowed: ReadonlySet<string>): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) fail('unknown_data_field');
  }
}

function requirePlainDataRecord(
  value: unknown,
  code: RawSyncCipherCompatibilityErrorCode,
  allowed?: ReadonlySet<string>,
): PlainRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(code);
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) fail(code);
    const folded = new Set<string>();
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') fail(code);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) fail(code);
      const canonical = key.toLocaleLowerCase('en-US');
      if (folded.has(canonical)) fail(code);
      folded.add(canonical);
      if (allowed && !allowed.has(key)) fail(code);
    }
  } catch (error) {
    if (error instanceof CompatibilityFailure) throw error;
    fail(code);
  }
  return value as PlainRecord;
}

function requireDenseDataArray(value: unknown[], code: RawSyncCipherCompatibilityErrorCode): void {
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype) fail(code);
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length')) fail(code);
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) fail(code);
    }
  } catch (error) {
    if (error instanceof CompatibilityFailure) throw error;
    fail(code);
  }
}

function rejectBlobMarker(data: PlainRecord): void {
  // The pinned server and SDK probe this exact, case-sensitive key. Lookalike casing remains an
  // unknown legacy field and is rejected by the schema rather than being mislabeled as a blob.
  if (Object.prototype.hasOwnProperty.call(data, 'format_version')) fail('encrypted_data_blob');
}

function ownEntry(record: PlainRecord, field: string): { present: boolean; value?: unknown } {
  if (!Object.prototype.hasOwnProperty.call(record, field)) return { present: false };
  return { present: true, value: record[field] };
}

function sideError(side: CompatibilitySide): RawSyncCipherCompatibilityErrorCode {
  return side === 'data' ? 'invalid_data_shape' : 'invalid_structured_projection';
}

function isSupportedCipherType(value: unknown): value is 1 | 2 | 3 | 4 | 5 {
  return value === 1 || value === 2 || value === 3 || value === 4 || value === 5;
}

function isPlainDataRecord(value: unknown): value is PlainRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function lowerFirst(value: string): string {
  if (value === 'SSN') return 'ssn';
  return `${value[0]!.toLocaleLowerCase('en-US')}${value.slice(1)}`;
}

function parseIsoInstant(value: string): bigint | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (year < 1 || year > 9_999 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)
    || hour > 23 || minute > 59 || second > 59) return null;
  const offsetHour = match[10] === undefined ? 0 : Number(match[10]);
  const offsetMinute = match[11] === undefined ? 0 : Number(match[11]);
  if (offsetHour > 14 || offsetMinute > 59 || (offsetHour === 14 && offsetMinute !== 0)) return null;
  const offsetSign = match[9] === '-' ? -1 : 1;
  const offsetMinutes = match[8] === 'Z' ? 0 : offsetSign * (offsetHour * 60 + offsetMinute);
  const fraction = BigInt((match[7] ?? '').padEnd(7, '0'));
  const ticksPerSecond = 10_000_000n;
  const instant = BigInt(daysFromCivil(year, month, day)) * 86_400n * ticksPerSecond
    + BigInt(hour * 3_600 + minute * 60 + second) * ticksPerSecond
    + fraction
    - BigInt(offsetMinutes * 60) * ticksPerSecond;
  const minimum = BigInt(daysFromCivil(1, 1, 1)) * 86_400n * ticksPerSecond;
  const maximum = BigInt(daysFromCivil(9_999, 12, 31)) * 86_400n * ticksPerSecond
    + 86_399n * ticksPerSecond
    + 9_999_999n;
  return instant < minimum || instant > maximum ? null : instant;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysFromCivil(year: number, month: number, day: number): number {
  const adjustedYear = year - (month <= 2 ? 1 : 0);
  const era = Math.floor(adjustedYear / 400);
  const yearOfEra = adjustedYear - era * 400;
  const shiftedMonth = month + (month > 2 ? -3 : 9);
  const dayOfYear = Math.floor((153 * shiftedMonth + 2) / 5) + day - 1;
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}

function resolveLimits(
  overrides: Partial<RawSyncCipherCompatibilityLimits> | undefined,
): RawSyncCipherCompatibilityLimits {
  const limits = { ...DEFAULT_RAW_SYNC_CIPHER_COMPATIBILITY_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive safe integer`);
  }
  return limits;
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const low = value.charCodeAt(index + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        bytes += 4;
        index++;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

class CompatibilityFailure extends Error {
  constructor(readonly code: RawSyncCipherCompatibilityErrorCode) {
    super(code);
  }
}

function fail(code: RawSyncCipherCompatibilityErrorCode): never {
  throw new CompatibilityFailure(code);
}

class BoundedJsonParser {
  private index = 0;
  private nodes = 0;
  private properties = 0;

  constructor(
    private readonly source: string,
    private readonly limits: RawSyncCipherCompatibilityLimits,
  ) {}

  parse(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(1);
    this.skipWhitespace();
    if (this.index !== this.source.length) fail('malformed_data');
    return value;
  }

  private parseValue(depth: number): unknown {
    if (depth > this.limits.maxDepth || ++this.nodes > this.limits.maxNodes) {
      fail('data_limit_exceeded');
    }
    this.skipWhitespace();
    const character = this.source[this.index];
    if (character === '{') return this.parseObject(depth);
    if (character === '[') return this.parseArray(depth);
    if (character === '"') return this.parseString();
    if (character === 't') return this.parseLiteral('true', true);
    if (character === 'f') return this.parseLiteral('false', false);
    if (character === 'n') return this.parseLiteral('null', null);
    return this.parseNumber();
  }

  private parseObject(depth: number): PlainRecord {
    this.index++;
    const output = Object.create(null) as PlainRecord;
    const foldedKeys = new Set<string>();
    this.skipWhitespace();
    if (this.consume('}')) return output;
    while (true) {
      if (this.source[this.index] !== '"') fail('malformed_data');
      const key = this.parseString();
      if (++this.properties > this.limits.maxProperties) fail('data_limit_exceeded');
      const folded = key.toLocaleLowerCase('en-US');
      if (foldedKeys.has(folded)) fail('duplicate_data_key');
      foldedKeys.add(folded);
      this.skipWhitespace();
      if (!this.consume(':')) fail('malformed_data');
      const value = this.parseValue(depth + 1);
      Object.defineProperty(output, key, {
        value, enumerable: true, writable: true, configurable: true,
      });
      this.skipWhitespace();
      if (this.consume('}')) return output;
      if (!this.consume(',')) fail('malformed_data');
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): unknown[] {
    this.index++;
    const output: unknown[] = [];
    this.skipWhitespace();
    if (this.consume(']')) return output;
    while (true) {
      if (output.length >= this.limits.maxArrayLength) fail('data_limit_exceeded');
      output.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume(']')) return output;
      if (!this.consume(',')) fail('malformed_data');
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    const start = this.index;
    this.index++;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code === 0x22) {
        this.index++;
        try {
          return JSON.parse(this.source.slice(start, this.index)) as string;
        } catch {
          fail('malformed_data');
        }
      }
      if (code < 0x20) fail('malformed_data');
      if (code === 0x5c) {
        this.index++;
        const escape = this.source[this.index];
        if (escape === 'u') {
          const hex = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('malformed_data');
          this.index += 5;
          continue;
        }
        if (!escape || !'"\\/bfnrt'.includes(escape)) fail('malformed_data');
      }
      this.index++;
    }
    fail('malformed_data');
  }

  private parseLiteral(token: string, value: boolean | null): boolean | null {
    if (this.source.slice(this.index, this.index + token.length) !== token) fail('malformed_data');
    this.index += token.length;
    return value;
  }

  private parseNumber(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.source.slice(this.index));
    if (!match) fail('malformed_data');
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail('malformed_data');
    return value;
  }

  private consume(expected: string): boolean {
    if (this.source[this.index] !== expected) return false;
    this.index++;
    return true;
  }

  private skipWhitespace(): void {
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return;
      this.index++;
    }
  }
}
