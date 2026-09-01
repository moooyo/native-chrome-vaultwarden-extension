import type {
  CipherResponse,
  CollectionResponse,
  FolderResponse,
  SyncResponse,
} from '../api/types.js';
import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import { utf8ToBytes } from '../crypto/encoding.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { buildVaultTransferExport } from './vault-transfer-export.js';
import { createStrictVaultTransferExportDecryptors } from './vault-transfer-export-crypto.js';
import {
  DEFAULT_VAULT_TRANSFER_LIMITS,
  type VaultTransferInspection,
  type VaultTransferIR,
  type VaultTransferLimits,
} from './vault-transfer.js';

const ROOT_PERSONAL_KEYS = new Set([
  'encrypted', 'encKeyValidation_DO_NOT_EDIT', 'folders', 'items',
]);
const ROOT_ORGANIZATION_KEYS = new Set([
  'encrypted', 'encKeyValidation_DO_NOT_EDIT', 'collections', 'items',
]);
const FOLDER_KEYS = new Set(['id', 'name']);
const RAW_FOLDER_KEYS = new Set(['id', 'name', 'revisionDate', 'object']);
const COLLECTION_KEYS = new Set(['id', 'organizationId', 'name', 'externalId']);
const RAW_COLLECTION_KEYS = new Set([
  'id', 'organizationId', 'name', 'externalId', 'readOnly', 'manage', 'hidePasswords', 'object',
]);
const ITEM_KEYS = new Set([
  'id', 'organizationId', 'folderId', 'type', 'reprompt', 'name', 'notes', 'key',
  'favorite', 'fields', 'login', 'secureNote', 'card', 'identity', 'sshKey',
  'passwordHistory', 'creationDate', 'revisionDate', 'deletedDate', 'archivedDate',
  'collectionIds',
]);
const FIELD_KEYS = new Set(['name', 'value', 'type', 'linkedId']);
const HISTORY_KEYS = new Set(['password', 'lastUsedDate']);
const LOGIN_KEYS = new Set(['uris', 'username', 'password', 'totp', 'fido2Credentials']);
const URI_KEYS = new Set(['uri', 'uriChecksum', 'match']);
const PASSKEY_KEYS = new Set([
  'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
  'userHandle', 'userName', 'counter', 'rpName', 'userDisplayName', 'discoverable',
  'creationDate',
]);
const SECURE_NOTE_KEYS = new Set(['type']);
const CARD_KEYS = new Set(['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code']);
const IDENTITY_KEYS = new Set([
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
  'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn',
  'username', 'passportNumber', 'licenseNumber',
]);
const SSH_KEY_KEYS = new Set(['privateKey', 'publicKey', 'keyFingerprint']);
const TYPE_PAYLOADS = ['login', 'secureNote', 'card', 'identity', 'sshKey'] as const;

export interface AccountEncryptedVaultCrypto {
  encryptBytes(plaintext: Uint8Array, key: SymmetricKey): Promise<string>;
  decryptBytes(ciphertext: string, key: SymmetricKey): Promise<Uint8Array>;
}

export interface EncodeAccountEncryptedVaultOptions {
  readonly maxOutputBytes: number;
  readonly validationText?: () => string;
  readonly crypto?: Partial<AccountEncryptedVaultCrypto>;
  readonly organization?: {
    readonly organizationId: string;
    readonly key: SymmetricKey;
  };
}

export interface InspectAccountEncryptedVaultOptions {
  readonly userKey: SymmetricKey;
  readonly organizationKeys?: ReadonlyMap<string, SymmetricKey>;
  readonly loadOrganizationKeys?: () => Promise<ReadonlyMap<string, SymmetricKey>>;
  readonly limits?: Partial<VaultTransferLimits>;
  readonly assertCurrent?: () => void | Promise<void>;
  readonly crypto?: Partial<AccountEncryptedVaultCrypto>;
}

export class AccountEncryptedVaultTransferError extends Error {
  readonly code = 'authentication_failed' as const;

  constructor() {
    super('The account-encrypted vault transfer could not be authenticated.');
    this.name = 'AccountEncryptedVaultTransferError';
  }
}

interface ParsedAccountEncryptedDocument {
  readonly scope: 'personal' | 'organization';
  readonly validation: string;
  readonly folders: FolderResponse[];
  readonly collections: CollectionResponse[];
  readonly items: CipherResponse[];
}

/** Encode selected records using the Bitwarden v2026.8 account-encrypted wire shape. */
export async function encodeAccountEncryptedVaultExport(
  sync: SyncResponse,
  ir: VaultTransferIR,
  userKey: SymmetricKey,
  options: EncodeAccountEncryptedVaultOptions,
): Promise<Uint8Array> {
  const crypto = resolveCrypto(options.crypto);
  const maxOutputBytes = positiveLimit(options.maxOutputBytes, 'maxOutputBytes');
  let validationBytes: Uint8Array | undefined;
  try {
    const organization = options.organization;
    const key = ir.scope === 'personal'
      ? requirePersonalExport(ir, organization, userKey)
      : requireOrganizationExport(ir, organization);
    const validationText = (options.validationText ?? (() => globalThis.crypto.randomUUID()))();
    if (typeof validationText !== 'string' || validationText.length === 0 || validationText.length > 1_024) {
      throw new AccountEncryptedVaultTransferError();
    }
    validationBytes = utf8ToBytes(validationText);
    const validation = await crypto.encryptBytes(validationBytes, key);
    const document = ir.scope === 'personal'
      ? exportPersonalDocument(sync, ir, validation)
      : exportOrganizationDocument(sync, ir, validation, organization!);
    const encoded = utf8ToBytes(JSON.stringify(document, null, 2));
    if (encoded.byteLength === 0 || encoded.byteLength > maxOutputBytes) {
      encoded.fill(0);
      throw new AccountEncryptedVaultTransferError();
    }
    return encoded;
  } catch (error) {
    if (error instanceof AccountEncryptedVaultTransferError) throw error;
    throw new AccountEncryptedVaultTransferError();
  } finally {
    validationBytes?.fill(0);
  }
}

function requirePersonalExport(
  ir: VaultTransferIR,
  organization: EncodeAccountEncryptedVaultOptions['organization'],
  userKey: SymmetricKey,
): SymmetricKey {
  if (organization !== undefined || ir.collections.length > 0 || ir.collectionRelationships.length > 0) {
    throw new AccountEncryptedVaultTransferError();
  }
  return userKey;
}

function requireOrganizationExport(
  ir: VaultTransferIR,
  organization: EncodeAccountEncryptedVaultOptions['organization'],
): SymmetricKey {
  if (ir.scope !== 'organization' || organization === undefined
    || !validIdentifier(organization.organizationId)
    || ir.folders.length > 0 || ir.folderRelationships.length > 0) {
    throw new AccountEncryptedVaultTransferError();
  }
  return organization.key;
}

function exportPersonalDocument(
  sync: SyncResponse,
  ir: VaultTransferIR,
  validation: string,
): Record<string, unknown> {
  const folders = stableBySourceIndex(ir.folders).map((folder) => {
    const raw = sync.folders?.[folder.sourceIndex];
    if (!raw || raw.id !== folder.id) throw new AccountEncryptedVaultTransferError();
    assertExactKeys(raw as unknown as Record<string, unknown>, RAW_FOLDER_KEYS);
    return { id: requireString(raw.id), name: requireEncryptedString(raw.name) };
  });
  const items = stableBySourceIndex(ir.items).map((item) => {
    const raw = sync.ciphers[item.sourceIndex];
    if (!raw || raw.id !== item.id || raw.organizationId != null || raw.deletedDate != null) {
      throw new AccountEncryptedVaultTransferError();
    }
    return exportCipher(raw, null);
  });
  return {
    encrypted: true,
    encKeyValidation_DO_NOT_EDIT: validation,
    folders,
    items,
  };
}

function exportOrganizationDocument(
  sync: SyncResponse,
  ir: VaultTransferIR,
  validation: string,
  organization: NonNullable<EncodeAccountEncryptedVaultOptions['organization']>,
): Record<string, unknown> {
  const { organizationId } = organization;
  const collections = stableBySourceIndex(ir.collections).map((collection) => {
    const raw = sync.collections?.[collection.sourceIndex];
    if (!raw || raw.id !== collection.id || raw.organizationId !== organizationId
      || collection.organizationId !== organizationId) {
      throw new AccountEncryptedVaultTransferError();
    }
    assertExactKeys(raw as unknown as Record<string, unknown>, RAW_COLLECTION_KEYS);
    return exportCollection(raw);
  });
  const collectionIds = new Set(collections.map((collection) => collection.id as string));
  if (collectionIds.size !== collections.length) throw new AccountEncryptedVaultTransferError();
  const items = stableBySourceIndex(ir.items).map((item) => {
    const raw = sync.ciphers[item.sourceIndex];
    if (!raw || raw.id !== item.id || raw.organizationId !== organizationId
      || item.organizationId !== organizationId || raw.folderId != null || raw.deletedDate != null) {
      throw new AccountEncryptedVaultTransferError();
    }
    const selectedIds = requireSelectedCollectionIds(raw.collectionIds, item.collectionIds, collectionIds);
    return exportCipher(raw, selectedIds);
  });
  return {
    encrypted: true,
    encKeyValidation_DO_NOT_EDIT: validation,
    collections,
    items,
  };
}

/** Authenticate and inspect an account-encrypted export without exposing key-selection errors. */
export async function inspectAccountEncryptedVaultExport(
  content: string,
  options: InspectAccountEncryptedVaultOptions,
): Promise<VaultTransferInspection> {
  await options.assertCurrent?.();
  let inspection: VaultTransferInspection;
  try {
    inspection = await inspectAccountEncryptedVaultExportCore(content, options);
  } catch (error) {
    if (error instanceof AccountEncryptedVaultTransferError) throw error;
    throw new AccountEncryptedVaultTransferError();
  }
  await options.assertCurrent?.();
  return inspection;
}

async function inspectAccountEncryptedVaultExportCore(
  content: string,
  options: InspectAccountEncryptedVaultOptions,
): Promise<VaultTransferInspection> {
  const limits = resolveLimits(options.limits);
  if (typeof content !== 'string' || utf8ByteLength(content) > limits.maxInputBytes) {
    throw new AccountEncryptedVaultTransferError();
  }
  const document = parseDocument(content, limits);
  const crypto = resolveCrypto(options.crypto);
  let scope: { kind: 'personal' } | { kind: 'organization'; organizationId: string };
  let organizationKeys: ReadonlyMap<string, SymmetricKey> | undefined;

  if (document.scope === 'personal') {
    if (!await validates(document.validation, options.userKey, crypto)) {
      throw new AccountEncryptedVaultTransferError();
    }
    scope = { kind: 'personal' };
  } else {
    organizationKeys = options.organizationKeys
      ?? await options.loadOrganizationKeys?.()
      ?? new Map();
    if (organizationKeys.size === 0 || organizationKeys.size > limits.maxCollections) {
      throw new AccountEncryptedVaultTransferError();
    }
    const matches: string[] = [];
    for (const [organizationId, key] of organizationKeys) {
      if (typeof organizationId !== 'string' || organizationId.length === 0) continue;
      if (await validates(document.validation, key, crypto)) matches.push(organizationId);
    }
    if (matches.length !== 1) throw new AccountEncryptedVaultTransferError();
    const organizationId = matches[0]!;
    assertOrganizationIdentity(document, organizationId);
    scope = { kind: 'organization', organizationId };
  }

  const sync: SyncResponse = {
    profile: {
      id: 'account-encrypted-export',
      email: 'account-encrypted-export',
      ...(scope.kind === 'organization' ? { organizations: [{ id: scope.organizationId }] } : {}),
    },
    ciphers: document.items,
    ...(document.scope === 'personal' ? { folders: document.folders } : { collections: document.collections }),
  };
  const strict = createStrictVaultTransferExportDecryptors({
    scope,
    userKey: options.userKey,
    ...(organizationKeys ? { organizationKeys } : {}),
  });
  const built = await buildVaultTransferExport(
    sync,
    { scope, limits },
    strict,
  );
  if (!built.ok || !built.ir || built.diagnostics.some((entry) => entry.severity === 'error')) {
    throw new AccountEncryptedVaultTransferError();
  }
  return { canCommit: true, ir: built.ir, diagnostics: built.diagnostics };
}

function parseDocument(content: string, limits: VaultTransferLimits): ParsedAccountEncryptedDocument {
  const raw = requireRecord(JSON.parse(content) as unknown);
  const hasFolders = hasOwn(raw, 'folders');
  const hasCollections = hasOwn(raw, 'collections');
  if (raw.encrypted !== true || hasFolders === hasCollections) {
    throw new AccountEncryptedVaultTransferError();
  }
  assertExactKeys(raw, hasFolders ? ROOT_PERSONAL_KEYS : ROOT_ORGANIZATION_KEYS);
  const validation = requireEncryptedString(raw.encKeyValidation_DO_NOT_EDIT);
  if (validation.length > limits.maxStringChars) throw new AccountEncryptedVaultTransferError();
  const items = requireBoundedArray(raw.items, limits.maxItems).map((value) => {
    assertAccountItemShape(value, limits);
    return value as CipherResponse;
  });
  const folders = hasFolders
    ? requireBoundedArray(raw.folders, limits.maxFolders).map((value) => {
        const folder = requireRecord(value);
        assertExactKeys(folder, FOLDER_KEYS);
        return folder as unknown as FolderResponse;
      })
    : [];
  const collections = hasCollections
    ? requireBoundedArray(raw.collections, limits.maxCollections).map((value) => {
        const collection = requireRecord(value);
        assertExactKeys(collection, COLLECTION_KEYS);
        return collection as unknown as CollectionResponse;
      })
    : [];
  return {
    scope: hasFolders ? 'personal' : 'organization',
    validation,
    folders,
    collections,
    items,
  };
}

function assertAccountItemShape(value: unknown, limits: VaultTransferLimits): void {
  const item = requireRecord(value);
  assertExactKeys(item, ITEM_KEYS);
  if (item.fields != null) {
    for (const field of requireBoundedArray(item.fields, limits.maxFieldsPerItem)) {
      assertExactKeys(requireRecord(field), FIELD_KEYS);
    }
  }
  if (item.passwordHistory != null) {
    for (const history of requireBoundedArray(item.passwordHistory, limits.maxPasswordHistoryPerItem)) {
      assertExactKeys(requireRecord(history), HISTORY_KEYS);
    }
  }
  const type = item.type;
  const payloadName = typeof type === 'number' && Number.isInteger(type) ? TYPE_PAYLOADS[type - 1] : undefined;
  if (!payloadName) throw new AccountEncryptedVaultTransferError();
  const payload = requireRecord(item[payloadName]);
  for (const candidate of TYPE_PAYLOADS) {
    if (candidate !== payloadName && item[candidate] != null) throw new AccountEncryptedVaultTransferError();
  }
  if (payloadName === 'login') {
    assertExactKeys(payload, LOGIN_KEYS);
    if (payload.uris != null) {
      for (const uri of requireBoundedArray(payload.uris, limits.maxUrisPerItem)) {
        assertExactKeys(requireRecord(uri), URI_KEYS);
      }
    }
    if (payload.fido2Credentials != null) {
      for (const credential of requireBoundedArray(payload.fido2Credentials, limits.maxPasskeysPerItem)) {
        assertExactKeys(requireRecord(credential), PASSKEY_KEYS);
      }
    }
  } else if (payloadName === 'secureNote') {
    assertExactKeys(payload, SECURE_NOTE_KEYS);
  } else if (payloadName === 'card') {
    assertExactKeys(payload, CARD_KEYS);
  } else if (payloadName === 'identity') {
    assertExactKeys(payload, IDENTITY_KEYS);
  } else {
    assertExactKeys(payload, SSH_KEY_KEYS);
  }
}

function assertOrganizationIdentity(document: ParsedAccountEncryptedDocument, organizationId: string): void {
  for (const collection of document.collections) {
    if (collection.organizationId !== organizationId) throw new AccountEncryptedVaultTransferError();
  }
  for (const item of document.items) {
    if (item.organizationId !== organizationId) throw new AccountEncryptedVaultTransferError();
  }
}

async function validates(
  ciphertext: string,
  key: SymmetricKey,
  crypto: AccountEncryptedVaultCrypto,
): Promise<boolean> {
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = await crypto.decryptBytes(ciphertext, key);
    return plaintext.byteLength > 0;
  } catch {
    return false;
  } finally {
    plaintext?.fill(0);
  }
}

function exportCollection(raw: CollectionResponse): Record<string, unknown> {
  const output: Record<string, unknown> = {
    id: requireString(raw.id),
    organizationId: requireString(raw.organizationId),
    name: requireEncryptedString(raw.name),
  };
  if (hasOwn(raw, 'externalId')) {
    if (raw.externalId != null && typeof raw.externalId !== 'string') {
      throw new AccountEncryptedVaultTransferError();
    }
    output.externalId = raw.externalId;
  }
  return output;
}

function requireSelectedCollectionIds(
  rawIds: CipherResponse['collectionIds'],
  irIds: readonly string[],
  selectedIds: ReadonlySet<string>,
): string[] {
  const ids = rawIds == null ? [] : requireArray(rawIds).map(requireIdentifier);
  if (ids.length !== irIds.length || new Set(ids).size !== ids.length
    || ids.some((id, index) => id !== irIds[index] || !selectedIds.has(id))) {
    throw new AccountEncryptedVaultTransferError();
  }
  return ids;
}

function exportCipher(raw: CipherResponse, collectionIds: readonly string[] | null): Record<string, unknown> {
  const output: Record<string, unknown> = { id: requireString(raw.id) };
  copyPresent(output, raw, 'organizationId');
  copyPresent(output, raw, 'folderId');
  output.type = raw.type;
  output.reprompt = raw.reprompt ?? 0;
  output.name = requireEncryptedString(raw.name);
  copyEncrypted(output, raw, 'notes');
  copyEncrypted(output, raw, 'key');
  output.favorite = raw.favorite ?? false;
  if (raw.fields != null) output.fields = raw.fields.map(exportField);
  const payloadName = TYPE_PAYLOADS[raw.type - 1];
  if (!payloadName) throw new AccountEncryptedVaultTransferError();
  output[payloadName] = exportPayload(payloadName, raw[payloadName]);
  if (raw.passwordHistory != null) output.passwordHistory = raw.passwordHistory.map(exportHistory);
  for (const field of ['creationDate', 'revisionDate', 'deletedDate', 'archivedDate'] as const) {
    copyPresent(output, raw, field);
  }
  output.collectionIds = collectionIds === null ? null : [...collectionIds];
  return output;
}

function exportField(value: unknown): Record<string, unknown> {
  const field = requireRecord(value);
  const output: Record<string, unknown> = {};
  copyEncrypted(output, field, 'name');
  copyEncrypted(output, field, 'value');
  output.type = field.type ?? 0;
  copyPresent(output, field, 'linkedId');
  return output;
}

function exportHistory(value: unknown): Record<string, unknown> {
  const history = requireRecord(value);
  const output: Record<string, unknown> = { password: requireEncryptedString(history.password) };
  copyPresent(output, history, 'lastUsedDate');
  return output;
}

function exportPayload(name: typeof TYPE_PAYLOADS[number], value: unknown): Record<string, unknown> {
  const payload = requireRecord(value);
  if (name === 'login') {
    const output: Record<string, unknown> = {};
    if (payload.uris != null) output.uris = requireArray(payload.uris).map(exportUri);
    if (payload.fido2Credentials != null) {
      output.fido2Credentials = requireArray(payload.fido2Credentials).map(exportPasskey);
    }
    for (const field of ['username', 'password', 'totp']) copyEncrypted(output, payload, field);
    return output;
  }
  if (name === 'secureNote') return { type: payload.type };
  const fields = name === 'card' ? CARD_KEYS : (name === 'identity' ? IDENTITY_KEYS : SSH_KEY_KEYS);
  const output: Record<string, unknown> = {};
  for (const field of fields) copyEncrypted(output, payload, field);
  return output;
}

function exportUri(value: unknown): Record<string, unknown> {
  const uri = requireRecord(value);
  const output: Record<string, unknown> = {};
  copyEncrypted(output, uri, 'uri');
  copyEncrypted(output, uri, 'uriChecksum');
  copyPresent(output, uri, 'match');
  return output;
}

function exportPasskey(value: unknown): Record<string, unknown> {
  const passkey = requireRecord(value);
  const output: Record<string, unknown> = {};
  for (const field of PASSKEY_KEYS) {
    if (field === 'creationDate') copyPresent(output, passkey, field);
    else copyEncrypted(output, passkey, field);
  }
  return output;
}

function resolveCrypto(overrides: Partial<AccountEncryptedVaultCrypto> | undefined): AccountEncryptedVaultCrypto {
  return {
    encryptBytes: overrides?.encryptBytes ?? encryptToBytes,
    decryptBytes: overrides?.decryptBytes ?? decryptToBytes,
  };
}

function resolveLimits(overrides: Partial<VaultTransferLimits> | undefined): VaultTransferLimits {
  const limits = { ...DEFAULT_VAULT_TRANSFER_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) positiveLimit(value, name);
  return limits;
}

function positiveLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function assertExactKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new AccountEncryptedVaultTransferError();
  }
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AccountEncryptedVaultTransferError();
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AccountEncryptedVaultTransferError();
  }
  return value as Record<string, unknown>;
}

function requireArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new AccountEncryptedVaultTransferError();
  return value;
}

function requireBoundedArray(value: unknown, limit: number): unknown[] {
  const array = requireArray(value);
  if (array.length > limit) throw new AccountEncryptedVaultTransferError();
  return array;
}

function requireString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new AccountEncryptedVaultTransferError();
  }
  return value;
}

function requireIdentifier(value: unknown): string {
  if (!validIdentifier(value)) throw new AccountEncryptedVaultTransferError();
  return value;
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4_096 && !value.includes('\0');
}

function requireEncryptedString(value: unknown): string {
  const text = requireString(value);
  if (!text.startsWith('2.')) throw new AccountEncryptedVaultTransferError();
  return text;
}

function copyEncrypted(target: Record<string, unknown>, source: Record<string, unknown>, key: string): void {
  const value = source[key];
  if (value == null) return;
  target[key] = requireEncryptedString(value);
}

function copyPresent(target: Record<string, unknown>, source: object, key: string): void {
  if (hasOwn(source, key)) target[key] = (source as Record<string, unknown>)[key];
}

function stableBySourceIndex<T extends { sourceIndex: number }>(values: readonly T[]): T[] {
  return [...values].sort((left, right) => left.sourceIndex - right.sourceIndex);
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
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
