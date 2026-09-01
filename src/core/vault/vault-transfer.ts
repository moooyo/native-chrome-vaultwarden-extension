/**
 * Pure, write-free inspection of Bitwarden JSON and CSV transfers.
 *
 * This module deliberately stops at a versioned intermediate representation. A future commit layer
 * must consume only inspections whose `canCommit` flag is true and must apply its own capability
 * checks. Keeping parsing separate prevents malformed or forward-incompatible data from being
 * silently narrowed into the editor's smaller CipherInput model.
 */

import { isIsoTimestamp } from './iso-date.js';

export const VAULT_TRANSFER_IR_VERSION = 1 as const;

export type VaultTransferFormat = 'bitwarden-json' | 'bitwarden-csv';
export type VaultTransferScope = 'personal' | 'organization';
export type VaultTransferDiagnosticSeverity = 'info' | 'warning' | 'error';

export interface VaultTransferDiagnostic {
  severity: VaultTransferDiagnosticSeverity;
  code: string;
  message: string;
  path?: string;
  sourceKind?: 'root' | 'folder' | 'collection' | 'item' | 'field' | 'row' | 'cell';
  sourceIndex?: number;
}

export interface VaultTransferLimits {
  maxInputBytes: number;
  maxItems: number;
  maxFolders: number;
  maxCollections: number;
  maxFieldsPerItem: number;
  maxUrisPerItem: number;
  maxPasskeysPerItem: number;
  maxPasswordHistoryPerItem: number;
  maxCollectionIdsPerItem: number;
  maxStringChars: number;
  maxCsvRows: number;
  maxCsvColumns: number;
  maxCellChars: number;
  maxDiagnostics: number;
}

export const DEFAULT_VAULT_TRANSFER_LIMITS: Readonly<VaultTransferLimits> = Object.freeze({
  maxInputBytes: 16 * 1024 * 1024,
  maxItems: 10_000,
  maxFolders: 5_000,
  maxCollections: 5_000,
  maxFieldsPerItem: 100,
  maxUrisPerItem: 100,
  maxPasskeysPerItem: 100,
  maxPasswordHistoryPerItem: 100,
  maxCollectionIdsPerItem: 1_000,
  maxStringChars: 1024 * 1024,
  maxCsvRows: 10_000,
  maxCsvColumns: 128,
  maxCellChars: 256 * 1024,
  maxDiagnostics: 1_000,
});

export interface VaultTransferInspectOptions {
  format?: 'auto' | 'json' | 'csv';
  limits?: Partial<VaultTransferLimits>;
}

export interface VaultTransferFolder {
  sourceIndex: number;
  id: string;
  name: string;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferCollection {
  sourceIndex: number;
  id: string;
  name: string;
  organizationId?: string | null;
  externalId?: string | null;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferFolderRelationship {
  itemSourceIndex: number;
  sourceFolderId: string;
  folderSourceIndex?: number;
}

export interface VaultTransferCollectionRelationship {
  itemSourceIndex: number;
  sourceCollectionId: string;
  collectionSourceIndex?: number;
}

export interface VaultTransferCustomField {
  sourceIndex: number;
  type: 0 | 1 | 2 | 3;
  name?: string | null;
  value?: string | null;
  linkedId?: number | null;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferPasswordHistory {
  sourceIndex: number;
  password: string;
  lastUsedDate?: string | null;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferLoginUri {
  sourceIndex: number;
  uri: string;
  match?: number | null;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferPasskey {
  sourceIndex: number;
  credentialId: string;
  keyType: string;
  keyAlgorithm: string;
  keyCurve: string;
  keyValue: string;
  rpId: string;
  counter: string;
  discoverable: string;
  userHandle?: string | null;
  userName?: string | null;
  rpName?: string | null;
  userDisplayName?: string | null;
  creationDate?: string | null;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferLoginPayload {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  autofillOnPageLoad?: boolean | null;
  passwordRevisionDate?: string | null;
  uris: VaultTransferLoginUri[];
  fido2Credentials: VaultTransferPasskey[];
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferSecureNotePayload {
  type: number;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferStringPayload {
  values: Readonly<Record<string, string | null>>;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferItemBase {
  sourceIndex: number;
  rawType: number;
  id?: string | null;
  organizationId?: string | null;
  folderId?: string | null;
  collectionIds: string[];
  name: string;
  notes?: string | null;
  favorite: boolean;
  reprompt: 0 | 1;
  fields: VaultTransferCustomField[];
  passwordHistory: VaultTransferPasswordHistory[];
  creationDate?: string | null;
  revisionDate?: string | null;
  deletedDate?: string | null;
  archivedDate?: string | null;
  raw: Readonly<Record<string, unknown>>;
  unknownFieldPaths: string[];
}

export interface VaultTransferLoginItem extends VaultTransferItemBase {
  rawType: 1;
  kind: 'login';
  payload: VaultTransferLoginPayload;
}

export interface VaultTransferSecureNoteItem extends VaultTransferItemBase {
  rawType: 2;
  kind: 'secureNote';
  payload: VaultTransferSecureNotePayload;
}

export interface VaultTransferCardItem extends VaultTransferItemBase {
  rawType: 3;
  kind: 'card';
  payload: VaultTransferStringPayload;
}

export interface VaultTransferIdentityItem extends VaultTransferItemBase {
  rawType: 4;
  kind: 'identity';
  payload: VaultTransferStringPayload;
}

export interface VaultTransferSshKeyItem extends VaultTransferItemBase {
  rawType: 5;
  kind: 'sshKey';
  payload: VaultTransferStringPayload;
}

export interface VaultTransferBankAccountItem extends VaultTransferItemBase {
  rawType: 6;
  kind: 'bankAccount';
  payload: VaultTransferStringPayload;
}

export interface VaultTransferDriversLicenseItem extends VaultTransferItemBase {
  rawType: 7;
  kind: 'driversLicense';
  payload: VaultTransferStringPayload;
}

export interface VaultTransferPassportItem extends VaultTransferItemBase {
  rawType: 8;
  kind: 'passport';
  payload: VaultTransferStringPayload;
}

export interface VaultTransferUnsupportedItem extends VaultTransferItemBase {
  kind: 'unsupported';
  payload: Readonly<Record<string, unknown>>;
}

export type VaultTransferItem =
  | VaultTransferLoginItem
  | VaultTransferSecureNoteItem
  | VaultTransferCardItem
  | VaultTransferIdentityItem
  | VaultTransferSshKeyItem
  | VaultTransferBankAccountItem
  | VaultTransferDriversLicenseItem
  | VaultTransferPassportItem
  | VaultTransferUnsupportedItem;

export interface VaultTransferIR {
  version: typeof VAULT_TRANSFER_IR_VERSION;
  format: VaultTransferFormat;
  scope: VaultTransferScope;
  inputBytes: number;
  folders: VaultTransferFolder[];
  collections: VaultTransferCollection[];
  items: VaultTransferItem[];
  folderRelationships: VaultTransferFolderRelationship[];
  collectionRelationships: VaultTransferCollectionRelationship[];
  unknownFieldPaths: string[];
}

export interface VaultTransferInspection {
  canCommit: boolean;
  ir: VaultTransferIR | null;
  diagnostics: VaultTransferDiagnostic[];
}

interface InspectContext {
  limits: VaultTransferLimits;
  diagnostics: VaultTransferDiagnostic[];
  unknownFieldPaths: string[];
  diagnosticsTruncated: boolean;
}

const ROOT_FIELDS = new Set([
  'encrypted', 'folders', 'collections', 'items', 'passwordProtected', 'salt', 'kdfType',
  'kdfIterations', 'kdfMemory', 'kdfParallelism', 'encKeyValidation_DO_NOT_EDIT', 'data',
]);
const ENCRYPTION_ENVELOPE_FIELDS = [
  'passwordProtected', 'salt', 'kdfType', 'kdfIterations', 'kdfMemory', 'kdfParallelism',
  'encKeyValidation_DO_NOT_EDIT', 'data',
] as const;

const ITEM_FIELDS = new Set([
  'id', 'organizationId', 'folderId', 'collectionIds', 'type', 'name', 'notes', 'favorite',
  'fields', 'login', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount',
  'driversLicense', 'passport', 'reprompt', 'passwordHistory', 'creationDate', 'revisionDate',
  'deletedDate', 'archivedDate', 'key', 'attachments',
]);

const CARD_FIELDS = ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'] as const;
const IDENTITY_FIELDS = [
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3', 'city',
  'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn', 'username',
  'passportNumber', 'licenseNumber',
] as const;
const SSH_KEY_FIELDS = ['privateKey', 'publicKey', 'keyFingerprint'] as const;
const BANK_ACCOUNT_FIELDS = [
  'bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber',
  'pin', 'swiftCode', 'iban', 'bankContactPhone',
] as const;
const DRIVERS_LICENSE_FIELDS = [
  'firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry',
  'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass',
] as const;
const PASSPORT_FIELDS = [
  'surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry',
  'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority',
  'issueDate', 'expirationDate',
] as const;

const ITEM_PAYLOAD_FIELDS = [
  'login', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount', 'driversLicense', 'passport',
] as const;

const CSV_FIELDS = new Set([
  'folder', 'collections', 'favorite', 'type', 'name', 'title', 'account', 'notes', 'note',
  'comments', 'fields', 'reprompt', 'archiveddate', 'archived_date', 'login_uri', 'url', 'uri',
  'website', 'login_username', 'username', 'user', 'email', 'login', 'login_password',
  'password', 'pass', 'login_totp', 'totp', 'otpauth',
]);

/** Inspect plaintext Bitwarden JSON or CSV without performing any storage or network writes. */
export function inspectVaultTransfer(
  content: string,
  options: VaultTransferInspectOptions = {},
): VaultTransferInspection {
  const limits = resolveLimits(options.limits);
  const diagnostics: VaultTransferDiagnostic[] = [];
  const context: InspectContext = {
    limits,
    diagnostics,
    unknownFieldPaths: [],
    diagnosticsTruncated: false,
  };
  const inputBytes = utf8ByteLength(content);
  if (inputBytes > limits.maxInputBytes) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'input_too_large',
      message: `Input is ${inputBytes} bytes; the limit is ${limits.maxInputBytes} bytes.`,
      path: '$',
      sourceKind: 'root',
    });
    return finishInspection(null, context);
  }
  if (content.trim().length === 0) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'empty_input',
      message: 'The transfer input is empty.',
      path: '$',
      sourceKind: 'root',
    });
    return finishInspection(null, context);
  }

  const requested = options.format ?? 'auto';
  const format = requested === 'auto'
    ? (content.trimStart().startsWith('{') ? 'json' : 'csv')
    : requested;
  const ir = format === 'json'
    ? inspectJson(content, inputBytes, context)
    : inspectCsv(content, inputBytes, context);
  return finishInspection(ir, context);
}

/** Inspect a plaintext Bitwarden JSON export. */
export function inspectVaultTransferJson(
  content: string,
  options: Omit<VaultTransferInspectOptions, 'format'> = {},
): VaultTransferInspection {
  return inspectVaultTransfer(content, { ...options, format: 'json' });
}

/** Inspect a Bitwarden or browser-compatible CSV export. */
export function inspectVaultTransferCsv(
  content: string,
  options: Omit<VaultTransferInspectOptions, 'format'> = {},
): VaultTransferInspection {
  return inspectVaultTransfer(content, { ...options, format: 'csv' });
}

function finishInspection(ir: VaultTransferIR | null, context: InspectContext): VaultTransferInspection {
  return {
    canCommit: ir !== null && !context.diagnostics.some((diagnostic) => diagnostic.severity === 'error'),
    ir,
    diagnostics: context.diagnostics,
  };
}

function resolveLimits(overrides: Partial<VaultTransferLimits> | undefined): VaultTransferLimits {
  const limits: VaultTransferLimits = { ...DEFAULT_VAULT_TRANSFER_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`${name} must be a positive safe integer`);
    }
  }
  return limits;
}

function addDiagnostic(context: InspectContext, diagnostic: VaultTransferDiagnostic): void {
  if (context.diagnostics.length < context.limits.maxDiagnostics) {
    context.diagnostics.push(diagnostic);
    return;
  }
  if (context.diagnosticsTruncated) return;
  context.diagnosticsTruncated = true;
  context.diagnostics[context.diagnostics.length - 1] = {
    severity: 'error',
    code: 'diagnostics_truncated',
    message: `Diagnostics exceeded the limit of ${context.limits.maxDiagnostics}.`,
    path: '$',
    sourceKind: 'root',
  };
}

function addUnknownField(
  context: InspectContext,
  path: string,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): void {
  if (context.unknownFieldPaths.length < context.limits.maxDiagnostics) {
    context.unknownFieldPaths.push(path);
  }
  addDiagnostic(context, {
    severity: 'error',
    code: 'unknown_field',
    message: 'This field is not represented by the current transfer schema and would be lost.',
    path,
    sourceKind,
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function collectUnknownFields(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  context: InspectContext,
  sourceIndex?: number,
): string[] {
  const paths: string[] = [];
  for (const key of Object.keys(value)) {
    if (allowed.has(key)) continue;
    const unknownPath = propertyPath(path, key);
    paths.push(unknownPath);
    addUnknownField(context, unknownPath, sourceKind, sourceIndex);
  }
  return paths;
}

function inspectJson(content: string, inputBytes: number, context: InspectContext): VaultTransferIR | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    addDiagnostic(context, {
      severity: 'error',
      code: 'malformed_json',
      message: 'The input is not valid JSON.',
      path: '$',
      sourceKind: 'root',
    });
    return null;
  }
  if (!isRecord(parsed)) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'invalid_json_root',
      message: 'A Bitwarden JSON export must have an object at its root.',
      path: '$',
      sourceKind: 'root',
    });
    return null;
  }

  collectUnknownFields(parsed, ROOT_FIELDS, '$', 'root', context);
  if (parsed.encrypted === true) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'encrypted_input_requires_decryption',
      message: 'Encrypted JSON must be decrypted before transfer inspection.',
      path: '$.encrypted',
      sourceKind: 'root',
    });
    return emptyIr('bitwarden-json', 'personal', inputBytes, context);
  }
  if (parsed.encrypted !== false) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'invalid_encryption_marker',
      message: 'A plaintext Bitwarden JSON export must set encrypted to false.',
      path: '$.encrypted',
      sourceKind: 'root',
    });
  }
  for (const field of ENCRYPTION_ENVELOPE_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(parsed, field)) continue;
    addDiagnostic(context, {
      severity: 'error',
      code: 'unsupported_known_data',
      message: 'Encryption-envelope data is not valid in a plaintext transfer.',
      path: `$.${field}`,
      sourceKind: 'root',
    });
  }
  if (!Array.isArray(parsed.items)) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'missing_items',
      message: 'A Bitwarden JSON export must contain an items array.',
      path: '$.items',
      sourceKind: 'root',
    });
    return emptyIr('bitwarden-json', 'personal', inputBytes, context);
  }
  if (parsed.items.length > context.limits.maxItems) {
    addLimitDiagnostic(context, 'items_limit_exceeded', '$.items', parsed.items.length, context.limits.maxItems);
    return emptyIr('bitwarden-json', 'personal', inputBytes, context);
  }

  const hasCollections = Object.prototype.hasOwnProperty.call(parsed, 'collections');
  const hasFolders = Object.prototype.hasOwnProperty.call(parsed, 'folders');
  if (hasCollections && hasFolders) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'ambiguous_transfer_scope',
      message: 'A transfer cannot contain both folders and collections.',
      path: '$',
      sourceKind: 'root',
    });
  }
  let scope: VaultTransferScope = hasCollections ? 'organization' : 'personal';
  if (scope === 'organization') addOrganizationDiagnostic(context, '$.collections');
  if (scope === 'personal' && !hasFolders) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'missing_folders',
      message: 'A personal Bitwarden JSON export must contain a folders array.',
      path: '$.folders',
      sourceKind: 'root',
    });
  }

  const folders = inspectFolders(parsed.folders, context);
  const collections = inspectCollections(parsed.collections, context);
  const items = parsed.items.map((item, sourceIndex) => inspectJsonItem(item, sourceIndex, context));
  const folderRelationships: VaultTransferFolderRelationship[] = [];
  const collectionRelationships: VaultTransferCollectionRelationship[] = [];
  resolveRelationships(items, folders, collections, folderRelationships, collectionRelationships, context);

  if (scope === 'personal' && items.some((item) => item.organizationId != null || item.collectionIds.length > 0)) {
    scope = 'organization';
    addOrganizationDiagnostic(context, '$.items');
  }

  return {
    version: VAULT_TRANSFER_IR_VERSION,
    format: 'bitwarden-json',
    scope,
    inputBytes,
    folders,
    collections,
    items,
    folderRelationships,
    collectionRelationships,
    unknownFieldPaths: [...context.unknownFieldPaths],
  };
}

function emptyIr(
  format: VaultTransferFormat,
  scope: VaultTransferScope,
  inputBytes: number,
  context: InspectContext,
): VaultTransferIR {
  return {
    version: VAULT_TRANSFER_IR_VERSION,
    format,
    scope,
    inputBytes,
    folders: [],
    collections: [],
    items: [],
    folderRelationships: [],
    collectionRelationships: [],
    unknownFieldPaths: [...context.unknownFieldPaths],
  };
}

function addLimitDiagnostic(
  context: InspectContext,
  code: string,
  path: string,
  actual: number,
  limit: number,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']> = 'root',
  sourceIndex?: number,
): void {
  addDiagnostic(context, {
    severity: 'error',
    code,
    message: `Count ${actual} exceeds the limit of ${limit}.`,
    path,
    sourceKind,
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function addOrganizationDiagnostic(context: InspectContext, path: string): void {
  if (context.diagnostics.some((diagnostic) => diagnostic.code === 'organization_target_required')) return;
  addDiagnostic(context, {
    severity: 'error',
    code: 'organization_target_required',
    message: 'Organization transfers require an explicit target organization and permission check.',
    path,
    sourceKind: 'root',
  });
}

function inspectFolders(value: unknown, context: InspectContext): VaultTransferFolder[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, '$.folders', 'folders must be an array', 'folder');
    return [];
  }
  if (value.length > context.limits.maxFolders) {
    addLimitDiagnostic(context, 'folders_limit_exceeded', '$.folders', value.length, context.limits.maxFolders);
    return [];
  }
  const seen = new Set<string>();
  return value.map((raw, sourceIndex) => {
    const path = `$.folders[${sourceIndex}]`;
    if (!isRecord(raw)) {
      addInvalidShape(context, path, 'folder must be an object', 'folder', sourceIndex);
      return { sourceIndex, id: '', name: '', raw: {}, unknownFieldPaths: [] };
    }
    const unknownFieldPaths = collectUnknownFields(raw, new Set(['id', 'name']), path, 'folder', context, sourceIndex);
    const id = readRequiredString(raw.id, `${path}.id`, context, 'folder', sourceIndex);
    const name = readRequiredString(raw.name, `${path}.name`, context, 'folder', sourceIndex);
    if (id && seen.has(id)) {
      addDiagnostic(context, {
        severity: 'error', code: 'duplicate_folder_id', message: 'Folder ids must be unique.',
        path: `${path}.id`, sourceKind: 'folder', sourceIndex,
      });
    }
    if (id) seen.add(id);
    return { sourceIndex, id, name, raw, unknownFieldPaths };
  });
}

function inspectCollections(value: unknown, context: InspectContext): VaultTransferCollection[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, '$.collections', 'collections must be an array', 'collection');
    return [];
  }
  if (value.length > context.limits.maxCollections) {
    addLimitDiagnostic(context, 'collections_limit_exceeded', '$.collections', value.length, context.limits.maxCollections);
    return [];
  }
  const allowed = new Set(['id', 'name', 'organizationId', 'externalId']);
  const seen = new Set<string>();
  return value.map((raw, sourceIndex) => {
    const path = `$.collections[${sourceIndex}]`;
    if (!isRecord(raw)) {
      addInvalidShape(context, path, 'collection must be an object', 'collection', sourceIndex);
      return { sourceIndex, id: '', name: '', raw: {}, unknownFieldPaths: [] };
    }
    const unknownFieldPaths = collectUnknownFields(raw, allowed, path, 'collection', context, sourceIndex);
    const id = readRequiredString(raw.id, `${path}.id`, context, 'collection', sourceIndex);
    const name = readRequiredString(raw.name, `${path}.name`, context, 'collection', sourceIndex);
    const collection: VaultTransferCollection = { sourceIndex, id, name, raw, unknownFieldPaths };
    assignOptionalString(collection, 'organizationId', raw.organizationId, `${path}.organizationId`, context, 'collection', sourceIndex);
    assignOptionalString(collection, 'externalId', raw.externalId, `${path}.externalId`, context, 'collection', sourceIndex);
    if (id && seen.has(id)) {
      addDiagnostic(context, {
        severity: 'error', code: 'duplicate_collection_id', message: 'Collection ids must be unique.',
        path: `${path}.id`, sourceKind: 'collection', sourceIndex,
      });
    }
    if (id) seen.add(id);
    return collection;
  });
}

function inspectJsonItem(rawValue: unknown, sourceIndex: number, context: InspectContext): VaultTransferItem {
  const path = `$.items[${sourceIndex}]`;
  const unknownStart = context.unknownFieldPaths.length;
  if (!isRecord(rawValue)) {
    addInvalidShape(context, path, 'item must be an object', 'item', sourceIndex);
    return unsupportedItem(sourceIndex, -1, {}, context.unknownFieldPaths.slice(unknownStart));
  }
  const raw = rawValue;
  collectUnknownFields(raw, ITEM_FIELDS, path, 'item', context, sourceIndex);

  const rawType = readItemType(raw.type, `${path}.type`, context, sourceIndex);
  const name = readRequiredString(raw.name, `${path}.name`, context, 'item', sourceIndex);
  const collectionIds = readStringArray(
    raw.collectionIds,
    `${path}.collectionIds`,
    context,
    'item',
    sourceIndex,
    context.limits.maxCollectionIdsPerItem,
    'collection_ids_limit_exceeded',
  );
  const reprompt = readReprompt(raw.reprompt, `${path}.reprompt`, context, sourceIndex);
  const fields = inspectCustomFields(raw.fields, path, sourceIndex, context);
  const passwordHistory = inspectPasswordHistory(raw.passwordHistory, path, sourceIndex, context);
  const base: VaultTransferItemBase = {
    sourceIndex,
    rawType,
    collectionIds,
    name,
    favorite: readBoolean(raw.favorite, false, `${path}.favorite`, context, sourceIndex),
    reprompt,
    fields,
    passwordHistory,
    raw,
    unknownFieldPaths: [],
  };
  assignOptionalString(base, 'id', raw.id, `${path}.id`, context, 'item', sourceIndex);
  assignOptionalString(base, 'organizationId', raw.organizationId, `${path}.organizationId`, context, 'item', sourceIndex);
  assignOptionalString(base, 'folderId', raw.folderId, `${path}.folderId`, context, 'item', sourceIndex);
  assignOptionalString(base, 'notes', raw.notes, `${path}.notes`, context, 'item', sourceIndex);
  assignOptionalDateString(base, 'creationDate', raw.creationDate, `${path}.creationDate`, context, 'item', sourceIndex);
  assignOptionalDateString(base, 'revisionDate', raw.revisionDate, `${path}.revisionDate`, context, 'item', sourceIndex);
  assignOptionalDateString(base, 'deletedDate', raw.deletedDate, `${path}.deletedDate`, context, 'item', sourceIndex);
  assignOptionalUtcDateString(base, 'archivedDate', raw.archivedDate, `${path}.archivedDate`, context, 'item', sourceIndex);
  if (base.creationDate != null || base.revisionDate != null) {
    addDiagnostic(context, {
      severity: 'warning',
      code: 'server_managed_dates_dropped',
      message: 'Creation and revision dates are server-managed and will not be preserved during import.',
      path,
      sourceKind: 'item',
      sourceIndex,
    });
  }

  if (raw.key != null) addUnsupportedKnownData(context, `${path}.key`, 'Per-item encrypted keys cannot be committed from a plaintext transfer.', sourceIndex);
  if (raw.attachments != null) addUnsupportedKnownData(context, `${path}.attachments`, 'Attachments require a bounded ZIP transfer.', sourceIndex);
  flagUnexpectedPayloads(raw, rawType, path, sourceIndex, context);

  let item: VaultTransferItem;
  switch (rawType) {
    case 1:
      item = { ...base, rawType: 1, kind: 'login', payload: inspectLogin(raw.login, path, sourceIndex, context) };
      break;
    case 2:
      item = { ...base, rawType: 2, kind: 'secureNote', payload: inspectSecureNote(raw.secureNote, path, sourceIndex, context) };
      break;
    case 3:
      item = { ...base, rawType: 3, kind: 'card', payload: inspectStringPayload(raw.card, `${path}.card`, CARD_FIELDS, sourceIndex, context) };
      break;
    case 4:
      item = { ...base, rawType: 4, kind: 'identity', payload: inspectStringPayload(raw.identity, `${path}.identity`, IDENTITY_FIELDS, sourceIndex, context) };
      break;
    case 5:
      item = { ...base, rawType: 5, kind: 'sshKey', payload: inspectStringPayload(raw.sshKey, `${path}.sshKey`, SSH_KEY_FIELDS, sourceIndex, context, true) };
      break;
    case 6:
      item = { ...base, rawType: 6, kind: 'bankAccount', payload: inspectStringPayload(raw.bankAccount, `${path}.bankAccount`, BANK_ACCOUNT_FIELDS, sourceIndex, context) };
      break;
    case 7:
      item = { ...base, rawType: 7, kind: 'driversLicense', payload: inspectStringPayload(raw.driversLicense, `${path}.driversLicense`, DRIVERS_LICENSE_FIELDS, sourceIndex, context) };
      break;
    case 8:
      item = { ...base, rawType: 8, kind: 'passport', payload: inspectStringPayload(raw.passport, `${path}.passport`, PASSPORT_FIELDS, sourceIndex, context) };
      break;
    default:
      addDiagnostic(context, {
        severity: 'error', code: 'unknown_item_type', message: `Item type ${rawType} is not supported by this transfer schema.`,
        path: `${path}.type`, sourceKind: 'item', sourceIndex,
      });
      item = { ...base, kind: 'unsupported', payload: raw };
  }
  item.unknownFieldPaths = context.unknownFieldPaths.slice(unknownStart);
  return item;
}

function unsupportedItem(
  sourceIndex: number,
  rawType: number,
  raw: Readonly<Record<string, unknown>>,
  unknownFieldPaths: string[],
): VaultTransferUnsupportedItem {
  return {
    sourceIndex, rawType, kind: 'unsupported', id: null, organizationId: null, folderId: null,
    collectionIds: [], name: '', favorite: false, reprompt: 0, fields: [], passwordHistory: [],
    raw, unknownFieldPaths, payload: raw,
  };
}

function flagUnexpectedPayloads(
  raw: Record<string, unknown>,
  rawType: number,
  path: string,
  sourceIndex: number,
  context: InspectContext,
): void {
  const expected = ITEM_PAYLOAD_FIELDS[rawType - 1];
  for (const field of ITEM_PAYLOAD_FIELDS) {
    if (field === expected || raw[field] == null) continue;
    addUnsupportedKnownData(
      context,
      `${path}.${field}`,
      `Payload ${field} does not belong to item type ${rawType} and would be lost.`,
      sourceIndex,
    );
  }
}

function inspectLogin(
  value: unknown,
  itemPath: string,
  sourceIndex: number,
  context: InspectContext,
): VaultTransferLoginPayload {
  const path = `${itemPath}.login`;
  if (!isRecord(value)) {
    addInvalidShape(context, path, 'login must be an object', 'item', sourceIndex);
    return { uris: [], fido2Credentials: [], raw: {}, unknownFieldPaths: [] };
  }
  const allowed = new Set([
    'username', 'password', 'totp', 'autofillOnPageLoad', 'passwordRevisionDate',
    'uris', 'fido2Credentials',
  ]);
  const unknownFieldPaths = collectUnknownFields(value, allowed, path, 'item', context, sourceIndex);
  const payload: VaultTransferLoginPayload = {
    uris: inspectLoginUris(value.uris, itemPath, sourceIndex, context),
    fido2Credentials: inspectPasskeys(value.fido2Credentials, itemPath, sourceIndex, context),
    raw: value,
    unknownFieldPaths,
  };
  assignOptionalString(payload, 'username', value.username, `${path}.username`, context, 'item', sourceIndex);
  assignOptionalString(payload, 'password', value.password, `${path}.password`, context, 'item', sourceIndex);
  assignOptionalString(payload, 'totp', value.totp, `${path}.totp`, context, 'item', sourceIndex);
  assignOptionalNullableBoolean(
    payload,
    'autofillOnPageLoad',
    value.autofillOnPageLoad,
    `${path}.autofillOnPageLoad`,
    context,
    sourceIndex,
  );
  assignOptionalIsoDateString(
    payload,
    'passwordRevisionDate',
    value.passwordRevisionDate,
    `${path}.passwordRevisionDate`,
    context,
    sourceIndex,
  );
  return payload;
}

function inspectLoginUris(
  value: unknown,
  itemPath: string,
  sourceIndex: number,
  context: InspectContext,
): VaultTransferLoginUri[] {
  const path = `${itemPath}.login.uris`;
  if (value == null) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, path, 'login uris must be an array', 'item', sourceIndex);
    return [];
  }
  if (value.length > context.limits.maxUrisPerItem) {
    addLimitDiagnostic(context, 'uris_limit_exceeded', path, value.length, context.limits.maxUrisPerItem, 'item', sourceIndex);
    return [];
  }
  const allowed = new Set(['uri', 'match']);
  return value.map((raw, uriIndex) => {
    const uriPath = `${path}[${uriIndex}]`;
    if (!isRecord(raw)) {
      addInvalidShape(context, uriPath, 'login uri must be an object', 'item', sourceIndex);
      return { sourceIndex: uriIndex, uri: '', raw: {}, unknownFieldPaths: [] };
    }
    const unknownFieldPaths = collectUnknownFields(raw, allowed, uriPath, 'item', context, sourceIndex);
    const uri: VaultTransferLoginUri = {
      sourceIndex: uriIndex,
      uri: readRequiredString(raw.uri, `${uriPath}.uri`, context, 'item', sourceIndex),
      raw,
      unknownFieldPaths,
    };
    if (raw.match === null) uri.match = null;
    else if (raw.match !== undefined) {
      if (typeof raw.match === 'number' && Number.isInteger(raw.match)) uri.match = raw.match;
      else addInvalidShape(context, `${uriPath}.match`, 'uri match must be an integer or null', 'item', sourceIndex);
    }
    return uri;
  });
}

function inspectPasskeys(
  value: unknown,
  itemPath: string,
  sourceIndex: number,
  context: InspectContext,
): VaultTransferPasskey[] {
  const path = `${itemPath}.login.fido2Credentials`;
  if (value == null) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, path, 'fido2Credentials must be an array', 'item', sourceIndex);
    return [];
  }
  if (value.length > context.limits.maxPasskeysPerItem) {
    addLimitDiagnostic(context, 'passkeys_limit_exceeded', path, value.length, context.limits.maxPasskeysPerItem, 'item', sourceIndex);
    return [];
  }
  const required = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable'] as const;
  const optional = ['userHandle', 'userName', 'rpName', 'userDisplayName', 'creationDate'] as const;
  const allowed = new Set<string>([...required, ...optional]);
  return value.map((raw, passkeyIndex) => {
    const passkeyPath = `${path}[${passkeyIndex}]`;
    if (!isRecord(raw)) {
      addInvalidShape(context, passkeyPath, 'passkey must be an object', 'item', sourceIndex);
      return emptyPasskey(passkeyIndex);
    }
    const unknownFieldPaths = collectUnknownFields(raw, allowed, passkeyPath, 'item', context, sourceIndex);
    const passkey: VaultTransferPasskey = {
      sourceIndex: passkeyIndex,
      credentialId: readRequiredString(raw.credentialId, `${passkeyPath}.credentialId`, context, 'item', sourceIndex),
      keyType: readRequiredString(raw.keyType, `${passkeyPath}.keyType`, context, 'item', sourceIndex),
      keyAlgorithm: readRequiredString(raw.keyAlgorithm, `${passkeyPath}.keyAlgorithm`, context, 'item', sourceIndex),
      keyCurve: readRequiredString(raw.keyCurve, `${passkeyPath}.keyCurve`, context, 'item', sourceIndex),
      keyValue: readRequiredString(raw.keyValue, `${passkeyPath}.keyValue`, context, 'item', sourceIndex),
      rpId: readRequiredString(raw.rpId, `${passkeyPath}.rpId`, context, 'item', sourceIndex),
      counter: readRequiredString(raw.counter, `${passkeyPath}.counter`, context, 'item', sourceIndex),
      discoverable: readRequiredString(raw.discoverable, `${passkeyPath}.discoverable`, context, 'item', sourceIndex),
      raw,
      unknownFieldPaths,
    };
    for (const key of optional) {
      if (key === 'creationDate') {
        assignOptionalUtcDateString(passkey, key, raw[key], `${passkeyPath}.${key}`, context, 'item', sourceIndex);
      } else {
        assignOptionalString(passkey, key, raw[key], `${passkeyPath}.${key}`, context, 'item', sourceIndex);
      }
    }
    return passkey;
  });
}

function emptyPasskey(sourceIndex: number): VaultTransferPasskey {
  return {
    sourceIndex,
    credentialId: '', keyType: '', keyAlgorithm: '', keyCurve: '', keyValue: '', rpId: '',
    counter: '', discoverable: '', raw: {}, unknownFieldPaths: [],
  };
}

function inspectSecureNote(
  value: unknown,
  itemPath: string,
  sourceIndex: number,
  context: InspectContext,
): VaultTransferSecureNotePayload {
  const path = `${itemPath}.secureNote`;
  if (!isRecord(value)) {
    addInvalidShape(context, path, 'secureNote must be an object', 'item', sourceIndex);
    return { type: 0, raw: {}, unknownFieldPaths: [] };
  }
  const unknownFieldPaths = collectUnknownFields(value, new Set(['type']), path, 'item', context, sourceIndex);
  let type = 0;
  if (typeof value.type === 'number' && Number.isInteger(value.type)) type = value.type;
  else addInvalidShape(context, `${path}.type`, 'secureNote type must be an integer', 'item', sourceIndex);
  return { type, raw: value, unknownFieldPaths };
}

function inspectStringPayload(
  value: unknown,
  path: string,
  fields: readonly string[],
  sourceIndex: number,
  context: InspectContext,
  requireAll = false,
): VaultTransferStringPayload {
  if (!isRecord(value)) {
    addInvalidShape(context, path, 'item payload must be an object', 'item', sourceIndex);
    return { values: {}, raw: {}, unknownFieldPaths: [] };
  }
  const allowed = new Set(fields);
  const unknownFieldPaths = collectUnknownFields(value, allowed, path, 'item', context, sourceIndex);
  const values: Record<string, string | null> = {};
  for (const field of fields) {
    const fieldPath = `${path}.${field}`;
    if (requireAll) {
      values[field] = readRequiredString(value[field], fieldPath, context, 'item', sourceIndex);
      continue;
    }
    const parsed = readOptionalString(value[field], fieldPath, context, 'item', sourceIndex);
    if (parsed !== undefined) values[field] = parsed;
  }
  return { values, raw: value, unknownFieldPaths };
}

function inspectCustomFields(
  value: unknown,
  itemPath: string,
  itemSourceIndex: number,
  context: InspectContext,
): VaultTransferCustomField[] {
  const path = `${itemPath}.fields`;
  if (value == null) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, path, 'fields must be an array', 'item', itemSourceIndex);
    return [];
  }
  if (value.length > context.limits.maxFieldsPerItem) {
    addLimitDiagnostic(context, 'fields_limit_exceeded', path, value.length, context.limits.maxFieldsPerItem, 'item', itemSourceIndex);
    return [];
  }
  const allowed = new Set(['name', 'value', 'type', 'linkedId']);
  return value.map((raw, sourceIndex) => {
    const fieldPath = `${path}[${sourceIndex}]`;
    if (!isRecord(raw)) {
      addInvalidShape(context, fieldPath, 'custom field must be an object', 'field', sourceIndex);
      return { sourceIndex, type: 0, raw: {}, unknownFieldPaths: [] };
    }
    const unknownFieldPaths = collectUnknownFields(raw, allowed, fieldPath, 'field', context, sourceIndex);
    const field: VaultTransferCustomField = {
      sourceIndex,
      type: readCustomFieldType(raw.type, `${fieldPath}.type`, context, sourceIndex),
      raw,
      unknownFieldPaths,
    };
    assignOptionalString(field, 'name', raw.name, `${fieldPath}.name`, context, 'field', sourceIndex);
    assignOptionalString(field, 'value', raw.value, `${fieldPath}.value`, context, 'field', sourceIndex);
    if (raw.linkedId === null) field.linkedId = null;
    else if (raw.linkedId !== undefined) {
      if (typeof raw.linkedId === 'number' && Number.isInteger(raw.linkedId)) field.linkedId = raw.linkedId;
      else addInvalidShape(context, `${fieldPath}.linkedId`, 'linkedId must be an integer or null', 'field', sourceIndex);
    }
    if (field.type === 3 && field.linkedId == null) {
      addInvalidShape(context, `${fieldPath}.linkedId`, 'a linked field must have a linkedId', 'field', sourceIndex);
    }
    return field;
  });
}

function inspectPasswordHistory(
  value: unknown,
  itemPath: string,
  itemSourceIndex: number,
  context: InspectContext,
): VaultTransferPasswordHistory[] {
  const path = `${itemPath}.passwordHistory`;
  if (value == null) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, path, 'passwordHistory must be an array', 'item', itemSourceIndex);
    return [];
  }
  if (value.length > context.limits.maxPasswordHistoryPerItem) {
    addLimitDiagnostic(context, 'password_history_limit_exceeded', path, value.length, context.limits.maxPasswordHistoryPerItem, 'item', itemSourceIndex);
    return [];
  }
  const allowed = new Set(['password', 'lastUsedDate']);
  return value.map((raw, sourceIndex) => {
    const historyPath = `${path}[${sourceIndex}]`;
    if (!isRecord(raw)) {
      addInvalidShape(context, historyPath, 'password history entry must be an object', 'item', itemSourceIndex);
      return { sourceIndex, password: '', raw: {}, unknownFieldPaths: [] };
    }
    const unknownFieldPaths = collectUnknownFields(raw, allowed, historyPath, 'item', context, itemSourceIndex);
    const entry: VaultTransferPasswordHistory = {
      sourceIndex,
      password: readRequiredString(raw.password, `${historyPath}.password`, context, 'item', itemSourceIndex),
      raw,
      unknownFieldPaths,
    };
    assignOptionalUtcDateString(entry, 'lastUsedDate', raw.lastUsedDate, `${historyPath}.lastUsedDate`, context, 'item', itemSourceIndex);
    return entry;
  });
}

function inspectCsv(content: string, inputBytes: number, context: InspectContext): VaultTransferIR | null {
  const rows = parseCsvRowsBounded(content, context);
  if (!rows) return null;
  if (rows.length < 2) {
    addDiagnostic(context, {
      severity: 'error', code: 'missing_items', message: 'A CSV transfer must contain a header and at least one item row.',
      path: '$.rows', sourceKind: 'root',
    });
    return emptyIr('bitwarden-csv', 'personal', inputBytes, context);
  }
  const itemCount = rows.length - 1;
  if (itemCount > context.limits.maxItems) {
    addLimitDiagnostic(context, 'items_limit_exceeded', '$.rows', itemCount, context.limits.maxItems);
    return emptyIr('bitwarden-csv', 'personal', inputBytes, context);
  }
  addDiagnostic(context, {
    severity: 'warning',
    code: 'csv_format_is_lossy',
    message: 'CSV can represent only login and secure-note transfer data.',
    path: '$',
    sourceKind: 'root',
  });

  const header = rows[0]!.map((value, index) => (index === 0 ? value.replace(/^\uFEFF/, '') : value).trim().toLowerCase());
  const seenHeaders = new Set<string>();
  for (const [index, name] of header.entries()) {
    const path = `$.headers[${index}]`;
    if (!name) {
      addInvalidShape(context, path, 'CSV header names must not be empty', 'cell', index);
      continue;
    }
    if (seenHeaders.has(name)) {
      addDiagnostic(context, {
        severity: 'error', code: 'duplicate_csv_header', message: `CSV header ${name} appears more than once.`,
        path, sourceKind: 'cell', sourceIndex: index,
      });
    }
    seenHeaders.add(name);
    if (!CSV_FIELDS.has(name)) addUnknownField(context, path, 'cell', index);
  }

  const folders: VaultTransferFolder[] = [];
  const collections: VaultTransferCollection[] = [];
  const items: VaultTransferItem[] = [];
  const folderRelationships: VaultTransferFolderRelationship[] = [];
  const collectionRelationships: VaultTransferCollectionRelationship[] = [];
  const foldersByName = new Map<string, VaultTransferFolder>();
  const collectionsByName = new Map<string, VaultTransferCollection>();
  let scope: VaultTransferScope = 'personal';

  for (const [rowOffset, row] of rows.slice(1).entries()) {
    const sourceIndex = rowOffset;
    const rowPath = `$.rows[${sourceIndex}]`;
    const raw: Record<string, unknown> = {};
    for (let column = 0; column < header.length; column++) {
      const key = header[column];
      if (key) raw[key] = row[column] ?? '';
    }
    const col = (...names: string[]): string => csvColumn(row, header, names);
    const typeName = col('type').toLowerCase();
    const rawType = typeName === 'note' || typeName === '2' ? 2 : 1;
    if (typeName && !['login', 'note', '1', '2'].includes(typeName)) {
      addDiagnostic(context, {
        severity: 'error', code: 'unknown_item_type', message: `CSV item type ${typeName} is not supported.`,
        path: `${rowPath}.type`, sourceKind: 'row', sourceIndex,
      });
    }
    const name = col('name', 'title', 'account');
    if (!name) addInvalidShape(context, `${rowPath}.name`, 'CSV items must have a name', 'row', sourceIndex);
    const fields = inspectCsvFields(col('fields'), rowPath, sourceIndex, context);
    const common: VaultTransferItemBase = {
      sourceIndex,
      rawType,
      collectionIds: [],
      name,
      favorite: parseCsvBoolean(col('favorite'), `${rowPath}.favorite`, sourceIndex, context),
      reprompt: parseCsvReprompt(col('reprompt'), `${rowPath}.reprompt`, sourceIndex, context),
      fields,
      passwordHistory: [],
      raw,
      unknownFieldPaths: [],
    };
    const notes = col('notes', 'note', 'comments');
    if (notes) common.notes = notes;
    const archivedDate = col('archiveddate', 'archived_date');
    if (archivedDate) assignOptionalUtcDateString(common, 'archivedDate', archivedDate, `${rowPath}.archivedDate`, context, 'row', sourceIndex);

    const folderName = col('folder');
    if (folderName) {
      let folder = foldersByName.get(folderName);
      if (!folder) {
        if (folders.length >= context.limits.maxFolders) {
          addLimitDiagnostic(context, 'folders_limit_exceeded', `${rowPath}.folder`, folders.length + 1, context.limits.maxFolders, 'row', sourceIndex);
        } else {
          folder = {
            sourceIndex,
            id: `csv-folder-${folders.length}`,
            name: folderName,
            raw: { name: folderName },
            unknownFieldPaths: [],
          };
          folders.push(folder);
          foldersByName.set(folderName, folder);
        }
      }
      if (folder) {
        common.folderId = folder.id;
        folderRelationships.push({ itemSourceIndex: sourceIndex, sourceFolderId: folder.id, folderSourceIndex: folder.sourceIndex });
      }
    }

    const collectionNames = parseCsvList(col('collections'));
    if (collectionNames.length > 0) {
      scope = 'organization';
      addOrganizationDiagnostic(context, `${rowPath}.collections`);
      if (collectionNames.length > context.limits.maxCollectionIdsPerItem) {
        addLimitDiagnostic(context, 'collection_ids_limit_exceeded', `${rowPath}.collections`, collectionNames.length, context.limits.maxCollectionIdsPerItem, 'row', sourceIndex);
      } else {
        for (const collectionName of collectionNames) {
          let collection = collectionsByName.get(collectionName);
          if (!collection) {
            if (collections.length >= context.limits.maxCollections) {
              addLimitDiagnostic(context, 'collections_limit_exceeded', `${rowPath}.collections`, collections.length + 1, context.limits.maxCollections, 'row', sourceIndex);
              break;
            }
            collection = {
              sourceIndex,
              id: `csv-collection-${collections.length}`,
              name: collectionName,
              raw: { name: collectionName },
              unknownFieldPaths: [],
            };
            collections.push(collection);
            collectionsByName.set(collectionName, collection);
          }
          common.collectionIds.push(collection.id);
          collectionRelationships.push({
            itemSourceIndex: sourceIndex,
            sourceCollectionId: collection.id,
            collectionSourceIndex: collection.sourceIndex,
          });
        }
      }
    }

    if (rawType === 2) {
      items.push({
        ...common,
        rawType: 2,
        kind: 'secureNote',
        payload: { type: 0, raw: { type: 0 }, unknownFieldPaths: [] },
      });
      continue;
    }
    const loginRaw: Record<string, unknown> = {};
    const username = col('login_username', 'username', 'user', 'email', 'login');
    const password = col('login_password', 'password', 'pass');
    const totp = col('login_totp', 'totp', 'otpauth');
    if (username) loginRaw.username = username;
    if (password) loginRaw.password = password;
    if (totp) loginRaw.totp = totp;
    const officialUriValue = col('login_uri');
    const genericUriValue = col('url', 'uri', 'website');
    const uriValues = officialUriValue
      ? parseCsvList(officialUriValue)
      : (genericUriValue ? [genericUriValue] : []);
    if (uriValues.length > context.limits.maxUrisPerItem) {
      addLimitDiagnostic(context, 'uris_limit_exceeded', `${rowPath}.login_uri`, uriValues.length, context.limits.maxUrisPerItem, 'row', sourceIndex);
    }
    const uris = uriValues.slice(0, context.limits.maxUrisPerItem).map((uri, uriIndex) => ({
      sourceIndex: uriIndex,
      uri,
      raw: { uri },
      unknownFieldPaths: [],
    } satisfies VaultTransferLoginUri));
    items.push({
      ...common,
      rawType: 1,
      kind: 'login',
      payload: {
        ...(username ? { username } : {}),
        ...(password ? { password } : {}),
        ...(totp ? { totp } : {}),
        uris,
        fido2Credentials: [],
        raw: loginRaw,
        unknownFieldPaths: [],
      },
    });
  }

  return {
    version: VAULT_TRANSFER_IR_VERSION,
    format: 'bitwarden-csv',
    scope,
    inputBytes,
    folders,
    collections,
    items,
    folderRelationships,
    collectionRelationships,
    unknownFieldPaths: [...context.unknownFieldPaths],
  };
}

function parseCsvRowsBounded(text: string, context: InspectContext): string[][] | null {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let hasContent = false;

  const pushField = (): boolean => {
    if (row.length >= context.limits.maxCsvColumns) {
      addLimitDiagnostic(context, 'csv_columns_limit_exceeded', `$.rows[${rows.length}]`, row.length + 1, context.limits.maxCsvColumns, 'row', rows.length);
      return false;
    }
    row.push(field);
    field = '';
    return true;
  };
  const pushRow = (): boolean => {
    if (rows.length >= context.limits.maxCsvRows + 1) {
      addLimitDiagnostic(context, 'csv_rows_limit_exceeded', '$.rows', rows.length, context.limits.maxCsvRows, 'root');
      return false;
    }
    rows.push(row);
    row = [];
    hasContent = false;
    return true;
  };
  const append = (value: string): boolean => {
    field += value;
    if (field.length <= context.limits.maxCellChars) return true;
    addLimitDiagnostic(context, 'csv_cell_limit_exceeded', `$.rows[${rows.length}][${row.length}]`, field.length, context.limits.maxCellChars, 'cell', row.length);
    return false;
  };

  for (let index = 0; index < text.length; index++) {
    const char = text[index]!;
    if (inQuotes) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          if (!append('"')) return null;
          index++;
        } else {
          inQuotes = false;
        }
      } else if (!append(char)) return null;
      continue;
    }
    if (char === '"' && field.length === 0) {
      inQuotes = true;
      hasContent = true;
    } else if (char === ',') {
      if (!pushField()) return null;
      hasContent = true;
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[index + 1] === '\n') index++;
      if (hasContent || field.length > 0 || row.length > 0) {
        if (!pushField() || !pushRow()) return null;
      }
    } else {
      if (!append(char)) return null;
      hasContent = true;
    }
  }
  if (inQuotes) {
    addDiagnostic(context, {
      severity: 'error', code: 'malformed_csv', message: 'CSV contains an unterminated quoted cell.',
      path: `$.rows[${rows.length}][${row.length}]`, sourceKind: 'cell', sourceIndex: row.length,
    });
    return null;
  }
  if (hasContent || field.length > 0 || row.length > 0) {
    if (!pushField() || !pushRow()) return null;
  }
  return rows;
}

function inspectCsvFields(
  value: string,
  rowPath: string,
  rowIndex: number,
  context: InspectContext,
): VaultTransferCustomField[] {
  if (!value) return [];
  const lines = value.split(/\r?\n/).filter((line) => line.length > 0);
  if (lines.length > context.limits.maxFieldsPerItem) {
    addLimitDiagnostic(context, 'fields_limit_exceeded', `${rowPath}.fields`, lines.length, context.limits.maxFieldsPerItem, 'row', rowIndex);
    return [];
  }
  return lines.map((line, sourceIndex) => {
    const delimiter = line.lastIndexOf(': ');
    if (delimiter < 0) {
      addUnsupportedKnownData(context, `${rowPath}.fields[${sourceIndex}]`, 'CSV custom fields must use the "name: value" form.', rowIndex);
      return { sourceIndex, type: 0, name: line, raw: { name: line }, unknownFieldPaths: [] };
    }
    const name = line.slice(0, delimiter);
    const fieldValue = line.slice(delimiter + 2);
    return {
      sourceIndex,
      type: 0,
      name,
      value: fieldValue,
      raw: { name, value: fieldValue, type: 0 },
      unknownFieldPaths: [],
    };
  });
}

function resolveRelationships(
  items: VaultTransferItem[],
  folders: VaultTransferFolder[],
  collections: VaultTransferCollection[],
  folderRelationships: VaultTransferFolderRelationship[],
  collectionRelationships: VaultTransferCollectionRelationship[],
  context: InspectContext,
): void {
  const folderById = new Map(folders.filter((folder) => folder.id).map((folder) => [folder.id, folder]));
  const collectionById = new Map(collections.filter((collection) => collection.id).map((collection) => [collection.id, collection]));
  for (const item of items) {
    if (item.folderId) {
      const folder = folderById.get(item.folderId);
      folderRelationships.push({
        itemSourceIndex: item.sourceIndex,
        sourceFolderId: item.folderId,
        ...(folder ? { folderSourceIndex: folder.sourceIndex } : {}),
      });
      if (!folder) {
        addDiagnostic(context, {
          severity: 'error', code: 'missing_folder_reference', message: `Folder ${item.folderId} is not present in this transfer.`,
          path: `$.items[${item.sourceIndex}].folderId`, sourceKind: 'item', sourceIndex: item.sourceIndex,
        });
      }
    }
    for (const collectionId of item.collectionIds) {
      const collection = collectionById.get(collectionId);
      collectionRelationships.push({
        itemSourceIndex: item.sourceIndex,
        sourceCollectionId: collectionId,
        ...(collection ? { collectionSourceIndex: collection.sourceIndex } : {}),
      });
      if (!collection) {
        addDiagnostic(context, {
          severity: 'error', code: 'missing_collection_reference', message: `Collection ${collectionId} is not present in this transfer.`,
          path: `$.items[${item.sourceIndex}].collectionIds`, sourceKind: 'item', sourceIndex: item.sourceIndex,
        });
      }
    }
  }
}

function readRequiredString(
  value: unknown,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): string {
  if (typeof value !== 'string' || value.length === 0) {
    addInvalidShape(context, path, 'a non-empty string is required', sourceKind, sourceIndex);
    return '';
  }
  enforceStringLimit(value, path, context, sourceKind, sourceIndex);
  return value;
}

function readOptionalString(
  value: unknown,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== 'string') {
    addInvalidShape(context, path, 'value must be a string or null', sourceKind, sourceIndex);
    return undefined;
  }
  enforceStringLimit(value, path, context, sourceKind, sourceIndex);
  return value;
}

function assignOptionalString(
  target: object,
  key: string,
  value: unknown,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): void {
  const parsed = readOptionalString(value, path, context, sourceKind, sourceIndex);
  if (parsed !== undefined) Object.assign(target, { [key]: parsed });
}

function assignOptionalDateString(
  target: object,
  key: string,
  value: unknown,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): void {
  const parsed = readOptionalString(value, path, context, sourceKind, sourceIndex);
  if (parsed === undefined) return;
  if (typeof parsed === 'string' && !isIsoTimestamp(parsed)) {
    addInvalidShape(context, path, 'date values must be valid ISO-8601 timestamps or null', sourceKind, sourceIndex);
  }
  Object.assign(target, { [key]: parsed });
}

function assignOptionalUtcDateString(
  target: object,
  key: string,
  value: unknown,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): void {
  const parsed = readOptionalString(value, path, context, sourceKind, sourceIndex);
  if (parsed === undefined) return;
  if (typeof parsed === 'string' && (!isIsoTimestamp(parsed) || !parsed.endsWith('Z'))) {
    addInvalidShape(context, path, 'portable date values must be UTC ISO-8601 timestamps or null', sourceKind, sourceIndex);
  }
  Object.assign(target, { [key]: parsed });
}

function assignOptionalIsoDateString(
  target: object,
  key: string,
  value: unknown,
  path: string,
  context: InspectContext,
  sourceIndex: number,
): void {
  const parsed = readOptionalString(value, path, context, 'item', sourceIndex);
  if (parsed === undefined) return;
  if (parsed !== null && (!isIsoTimestamp(parsed) || !parsed.endsWith('Z'))) {
    addInvalidShape(context, path, 'value must be a UTC ISO-8601 timestamp or null', 'item', sourceIndex);
  }
  Object.assign(target, { [key]: parsed });
}

function assignOptionalNullableBoolean(
  target: object,
  key: string,
  value: unknown,
  path: string,
  context: InspectContext,
  sourceIndex: number,
): void {
  if (value === undefined) return;
  if (value !== null && typeof value !== 'boolean') {
    addInvalidShape(context, path, 'value must be a boolean or null', 'item', sourceIndex);
    return;
  }
  Object.assign(target, { [key]: value });
}

function enforceStringLimit(
  value: string,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): void {
  if (value.length <= context.limits.maxStringChars) return;
  addLimitDiagnostic(context, 'string_limit_exceeded', path, value.length, context.limits.maxStringChars, sourceKind, sourceIndex);
}

function readStringArray(
  value: unknown,
  path: string,
  context: InspectContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex: number,
  limit: number,
  limitCode: string,
): string[] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    addInvalidShape(context, path, 'value must be an array of strings', sourceKind, sourceIndex);
    return [];
  }
  if (value.length > limit) {
    addLimitDiagnostic(context, limitCode, path, value.length, limit, sourceKind, sourceIndex);
    return [];
  }
  const output: string[] = [];
  for (const [index, entry] of value.entries()) {
    if (typeof entry !== 'string' || entry.length === 0) {
      addInvalidShape(context, `${path}[${index}]`, 'a non-empty string is required', sourceKind, sourceIndex);
      continue;
    }
    enforceStringLimit(entry, `${path}[${index}]`, context, sourceKind, sourceIndex);
    output.push(entry);
  }
  return output;
}

function readItemType(value: unknown, path: string, context: InspectContext, sourceIndex: number): number {
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  addInvalidShape(context, path, 'item type must be an integer', 'item', sourceIndex);
  return -1;
}

function readCustomFieldType(value: unknown, path: string, context: InspectContext, sourceIndex: number): 0 | 1 | 2 | 3 {
  if (value === 0 || value === 1 || value === 2 || value === 3) return value;
  addInvalidShape(context, path, 'custom field type must be 0, 1, 2, or 3', 'field', sourceIndex);
  return 0;
}

function readReprompt(value: unknown, path: string, context: InspectContext, sourceIndex: number): 0 | 1 {
  if (value == null || value === 0) return 0;
  if (value === 1) return 1;
  addInvalidShape(context, path, 'reprompt must be 0 or 1', 'item', sourceIndex);
  return 0;
}

function readBoolean(
  value: unknown,
  fallback: boolean,
  path: string,
  context: InspectContext,
  sourceIndex: number,
): boolean {
  if (value == null) return fallback;
  if (typeof value === 'boolean') return value;
  addInvalidShape(context, path, 'value must be a boolean', 'item', sourceIndex);
  return fallback;
}

function parseCsvBoolean(value: string, path: string, sourceIndex: number, context: InspectContext): boolean {
  if (!value || value === '0' || value.toLowerCase() === 'false') return false;
  if (value === '1' || value.toLowerCase() === 'true') return true;
  addInvalidShape(context, path, 'CSV favorite must be 0, 1, true, or false', 'row', sourceIndex);
  return false;
}

function parseCsvReprompt(value: string, path: string, sourceIndex: number, context: InspectContext): 0 | 1 {
  if (!value || value === '0') return 0;
  if (value === '1') return 1;
  addInvalidShape(context, path, 'CSV reprompt must be 0 or 1', 'row', sourceIndex);
  return 0;
}

function csvColumn(row: string[], header: string[], names: string[]): string {
  for (const name of names) {
    const index = header.indexOf(name);
    if (index >= 0) return (row[index] ?? '').trim();
  }
  return '';
}

function parseCsvList(value: string): string[] {
  if (!value) return [];
  if (value.startsWith('[')) {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (Array.isArray(parsed) && parsed.every((entry) => typeof entry === 'string')) {
        return parsed.map((entry) => entry.trim()).filter(Boolean);
      }
    } catch {
      // Fall through to the official CSV's comma-separated array representation.
    }
  }
  return value.split(',').map((entry) => entry.trim()).filter(Boolean);
}

function addInvalidShape(
  context: InspectContext,
  path: string,
  detail: string,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
  sourceIndex?: number,
): void {
  addDiagnostic(context, {
    severity: 'error',
    code: 'invalid_shape',
    message: `Invalid transfer data: ${detail}.`,
    path,
    sourceKind,
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function addUnsupportedKnownData(
  context: InspectContext,
  path: string,
  message: string,
  sourceIndex: number,
): void {
  addDiagnostic(context, {
    severity: 'error',
    code: 'unsupported_known_data',
    message,
    path,
    sourceKind: 'item',
    sourceIndex,
  });
}

function propertyPath(base: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? `${base}.${key}` : `${base}[${JSON.stringify(key)}]`;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
