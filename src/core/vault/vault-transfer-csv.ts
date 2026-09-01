import { isOptionalNullableIsoTimestamp } from './iso-date.js';
import {
  DEFAULT_VAULT_TRANSFER_LIMITS,
  type VaultTransferCollection,
  type VaultTransferCustomField,
  type VaultTransferFolder,
  type VaultTransferIR,
  type VaultTransferItem,
  type VaultTransferLoginItem,
} from './vault-transfer.js';

export const BITWARDEN_PERSONAL_CSV_COLUMNS = Object.freeze([
  'folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'archivedDate',
  'login_uri', 'login_username', 'login_password', 'login_totp',
] as const);

export const BITWARDEN_ORGANIZATION_CSV_COLUMNS = Object.freeze([
  'collections', 'type', 'name', 'notes', 'fields', 'reprompt', 'archivedDate',
  'login_uri', 'login_username', 'login_password', 'login_totp',
] as const);

export interface VaultTransferCsvLimits {
  /** Maximum number of data rows. The header does not count toward this limit. */
  readonly maxRows: number;
  /** Maximum unescaped UTF-16 length of any cell. */
  readonly maxCellChars: number;
  /** Maximum UTF-8 byte length of the complete CSV. */
  readonly maxOutputBytes: number;
  /** Maximum diagnostics retained in the result. */
  readonly maxDiagnostics: number;
}

export const DEFAULT_VAULT_TRANSFER_CSV_LIMITS: Readonly<VaultTransferCsvLimits> = Object.freeze({
  maxRows: DEFAULT_VAULT_TRANSFER_LIMITS.maxCsvRows,
  maxCellChars: DEFAULT_VAULT_TRANSFER_LIMITS.maxCellChars,
  maxOutputBytes: DEFAULT_VAULT_TRANSFER_LIMITS.maxInputBytes,
  maxDiagnostics: DEFAULT_VAULT_TRANSFER_LIMITS.maxDiagnostics,
});

export interface EncodeVaultTransferCsvOptions {
  readonly limits?: Partial<VaultTransferCsvLimits>;
}

export interface VaultTransferCsvDiagnostic {
  readonly severity: 'warning' | 'error';
  readonly code: string;
  readonly message: string;
  readonly path?: string;
  readonly sourceIndex?: number;
}

export interface EncodeVaultTransferCsvResult {
  readonly ok: boolean;
  readonly csv: string | null;
  readonly exportedItemCount: number;
  readonly omittedItemCount: number;
  readonly diagnostics: readonly VaultTransferCsvDiagnostic[];
}

type CsvCell = string | number | null;
interface CsvRow {
  readonly cells: readonly CsvCell[];
  readonly sourceIndex: number;
}

interface CsvContext {
  readonly limits: VaultTransferCsvLimits;
  readonly diagnostics: VaultTransferCsvDiagnostic[];
  diagnosticOverflow: number;
  hasError: boolean;
  omittedItemCount: number;
}

const HARD_MAX_ROWS = 100_000;
const HARD_MAX_CELL_CHARS = 1024 * 1024;
const HARD_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const HARD_MAX_DIAGNOSTICS = 10_000;
const FORMULA_PREFIX = /^[=+\-@\t\r]/u;
const CSV_SPECIAL = /[",\r\n\uFEFF]/u;

/** Encode a personal or organization IR using the Bitwarden v2026.8 CSV projection. */
export function encodeVaultTransferCsv(
  ir: VaultTransferIR,
  options: EncodeVaultTransferCsvOptions = {},
): EncodeVaultTransferCsvResult {
  const context: CsvContext = {
    limits: resolveLimits(options.limits),
    diagnostics: [],
    diagnosticOverflow: 0,
    hasError: false,
    omittedItemCount: 0,
  };
  if (!validateRoot(ir, context)) return failed(context, 0);
  const folders = ir.scope === 'personal' ? buildFolderMap(ir.folders, context) : new Map();
  const collections = ir.scope === 'organization'
    ? buildCollectionMap(ir.collections, context)
    : new Map();
  validateUniqueSources(ir.items, '$.items', context);
  if (ir.scope === 'organization') {
    validateOrganizationCollectionReferences(ir.items, collections, context);
    diagnoseUnrepresentedCollections(ir.collections, ir.items, context);
  }
  if (context.hasError) return failed(context, 0);

  const rows: CsvRow[] = [];
  for (const item of stableBySourceIndex(ir.items)) {
    const row = buildRow(item, ir.scope, folders, collections, context);
    if (row) rows.push(row);
    if (rows.length > context.limits.maxRows) {
      addError(
        context,
        'csv_rows_limit_exceeded',
        `CSV data rows exceed the configured limit of ${context.limits.maxRows}.`,
        '$.items',
      );
      break;
    }
  }
  if (context.hasError) return failed(context, rows.length);
  const columns = ir.scope === 'personal'
    ? BITWARDEN_PERSONAL_CSV_COLUMNS
    : BITWARDEN_ORGANIZATION_CSV_COLUMNS;
  const csv = serializeRows(rows, columns, context);
  if (context.hasError || csv === null) return failed(context, rows.length);
  finalizeDiagnostics(context);
  return {
    ok: true,
    csv,
    exportedItemCount: rows.length,
    omittedItemCount: context.omittedItemCount,
    diagnostics: context.diagnostics,
  };
}

function validateRoot(ir: VaultTransferIR, context: CsvContext): boolean {
  if (!ir || typeof ir !== 'object') {
    addError(context, 'invalid_ir', 'Transfer IR must be an object.', '$');
    return false;
  }
  if (ir.version !== 1) {
    addError(context, 'unsupported_ir_version', 'Transfer IR version is not supported.', '$.version');
  }
  if (ir.scope !== 'personal' && ir.scope !== 'organization') {
    addError(context, 'unsupported_vault_scope', 'Transfer scope is not supported.', '$.scope');
  }
  if (!Array.isArray(ir.folders) || !Array.isArray(ir.collections)
    || !Array.isArray(ir.items) || !Array.isArray(ir.folderRelationships)
    || !Array.isArray(ir.collectionRelationships) || !Array.isArray(ir.unknownFieldPaths)) {
    addError(context, 'invalid_ir',
      'Transfer collections, folders, relationships, and items must be arrays.', '$');
    return false;
  }
  if (ir.folders.length > HARD_MAX_ROWS || ir.collections.length > HARD_MAX_ROWS
    || ir.items.length > HARD_MAX_ROWS) {
    addError(context, 'input_capacity_exceeded', 'Transfer IR exceeds the hard collection limit.', '$');
    return false;
  }
  if (ir.scope === 'personal'
    && (ir.collections.length > 0 || ir.collectionRelationships.length > 0)) {
    addError(context, 'personal_contains_collections', 'Personal CSV cannot contain organization collections.', '$.collections');
  }
  if (ir.scope === 'organization'
    && (ir.folders.length > 0 || ir.folderRelationships.length > 0)) {
    addError(context, 'organization_contains_folders',
      'Organization CSV cannot contain personal folders.', '$.folders');
  }
  if (ir.unknownFieldPaths.length > 0) {
    addWarning(context, 'unknown_transfer_data_omitted',
      'Unknown transfer data is not represented by Bitwarden CSV.', '$');
  }
  return !context.hasError;
}

function buildFolderMap(
  folders: readonly VaultTransferFolder[],
  context: CsvContext,
): ReadonlyMap<string, VaultTransferFolder> {
  validateUniqueSources(folders, '$.folders', context);
  const byId = new Map<string, VaultTransferFolder>();
  for (const folder of folders) {
    if (!folder.id || byId.has(folder.id)) {
      addError(context, 'duplicate_or_empty_folder_id', 'Folder ids must be non-empty and unique.',
        '$.folders', folder.sourceIndex);
      continue;
    }
    if (typeof folder.name !== 'string') {
      addError(context, 'invalid_folder_name', 'Folder names must be strings.',
        `$.folders[${folder.sourceIndex}].name`, folder.sourceIndex);
      continue;
    }
    if (folder.unknownFieldPaths.length > 0) {
      addWarning(context, 'unknown_folder_data_omitted',
        'Unknown folder data is not represented by Bitwarden CSV.',
        `$.folders[${folder.sourceIndex}]`, folder.sourceIndex);
    }
    byId.set(folder.id, folder);
  }
  return byId;
}

function buildCollectionMap(
  collections: readonly VaultTransferCollection[],
  context: CsvContext,
): ReadonlyMap<string, VaultTransferCollection> {
  validateUniqueSources(collections, '$.collections', context);
  const byId = new Map<string, VaultTransferCollection>();
  const firstByName = new Map<string, VaultTransferCollection>();
  for (const collection of collections) {
    const path = `$.collections[${collection.sourceIndex}]`;
    if (!collection.id || byId.has(collection.id)) {
      addError(context, 'duplicate_or_empty_collection_id',
        'Collection ids must be non-empty and unique.', '$.collections', collection.sourceIndex);
      continue;
    }
    if (typeof collection.name !== 'string' || collection.name.length === 0) {
      addError(context, 'invalid_collection_name', 'Collection names must be non-empty strings.',
        `${path}.name`, collection.sourceIndex);
      continue;
    }
    if (collection.unknownFieldPaths.length > 0) {
      addWarning(context, 'unknown_collection_data_omitted',
        'Unknown collection data is not represented by Bitwarden CSV.', path,
        collection.sourceIndex);
    }
    if (collection.externalId != null) {
      addWarning(context, 'collection_external_id_omitted',
        'Collection external ids are not represented by Bitwarden CSV.',
        `${path}.externalId`, collection.sourceIndex);
    }
    if (collection.name.includes(',')) {
      addWarning(context, 'collection_list_round_trip_ambiguous',
        'A collection name contains the comma used by the official CSV array representation.',
        `${path}.name`, collection.sourceIndex);
    }
    if (firstByName.has(collection.name)) {
      addWarning(context, 'duplicate_collection_name_ambiguous',
        'Distinct collections with the same name cannot be distinguished by Bitwarden CSV.',
        `${path}.name`, collection.sourceIndex);
    } else {
      firstByName.set(collection.name, collection);
    }
    byId.set(collection.id, collection);
  }
  return byId;
}

function validateOrganizationCollectionReferences(
  items: readonly VaultTransferItem[],
  collections: ReadonlyMap<string, VaultTransferCollection>,
  context: CsvContext,
): void {
  for (const item of items) {
    const path = `$.items[${item.sourceIndex}].collectionIds`;
    if (!Array.isArray(item.collectionIds)) {
      addError(context, 'invalid_collection_ids', 'CSV item collection ids must be an array.',
        path, item.sourceIndex);
      continue;
    }
    if (item.collectionIds.length > DEFAULT_VAULT_TRANSFER_LIMITS.maxCollectionIdsPerItem) {
      addError(context, 'collection_ids_limit_exceeded',
        `CSV collection ids exceed the limit of ${DEFAULT_VAULT_TRANSFER_LIMITS.maxCollectionIdsPerItem}.`,
        path, item.sourceIndex);
      continue;
    }
    for (const collectionId of item.collectionIds) {
      if (typeof collectionId !== 'string' || collectionId.length === 0) {
        addError(context, 'invalid_collection_reference',
          'CSV collection references must be non-empty strings.', path, item.sourceIndex);
      } else if (!collections.has(collectionId)) {
        addError(context, 'missing_collection_reference',
          `Collection ${collectionId} is not present in this transfer.`, path, item.sourceIndex);
      }
    }
  }
}

function diagnoseUnrepresentedCollections(
  collections: readonly VaultTransferCollection[],
  items: readonly VaultTransferItem[],
  context: CsvContext,
): void {
  const representedIds = new Set<string>();
  for (const item of items) {
    if (item.deletedDate != null || !isCsvItem(item) || !Array.isArray(item.collectionIds)) continue;
    for (const collectionId of item.collectionIds) {
      if (typeof collectionId === 'string') representedIds.add(collectionId);
    }
  }
  for (const collection of collections) {
    if (!representedIds.has(collection.id)) {
      addWarning(context, 'unrepresented_collection_omitted',
        'A collection without exported login or secure-note items is not represented by Bitwarden CSV.',
        `$.collections[${collection.sourceIndex}]`, collection.sourceIndex);
    }
  }
}

function buildRow(
  item: VaultTransferItem,
  scope: VaultTransferIR['scope'],
  folders: ReadonlyMap<string, VaultTransferFolder>,
  collections: ReadonlyMap<string, VaultTransferCollection>,
  context: CsvContext,
): CsvRow | null {
  const path = `$.items[${item.sourceIndex}]`;
  if (!Array.isArray(item.collectionIds)) {
    addError(context, 'invalid_collection_ids', 'CSV item collection ids must be an array.',
      `${path}.collectionIds`, item.sourceIndex);
    return null;
  }
  if (scope === 'personal' && (item.organizationId != null || item.collectionIds.length > 0)) {
    omitItem(context, item, 'organization_item_omitted',
      'Organization-owned items are not part of a personal CSV export.');
    return null;
  }
  if (item.deletedDate != null) {
    omitItem(context, item, 'trashed_item_omitted',
      'Items in the trash are not part of a Bitwarden CSV export.');
    return null;
  }
  if (!isCsvItem(item)) {
    omitItem(context, item, omittedItemCode(item),
      `Item type ${item.rawType} cannot be represented by the official Bitwarden CSV schema.`);
    return null;
  }

  validateCommonItem(item, context);
  if (context.hasError) return null;
  const location = scope === 'personal'
    ? resolveFolder(item, folders, context)
    : resolveCollections(item, collections, context);
  const fields = encodeFields(item.fields, item.sourceIndex, context);
  diagnoseCommonLoss(item, context);
  if (scope === 'organization') diagnoseOrganizationLoss(item, context);
  if (context.hasError) return null;

  if (item.kind === 'login') {
    diagnoseLoginLoss(item, context);
    const uris = encodeUris(item, context);
    if (context.hasError) return null;
    return scope === 'personal'
      ? { sourceIndex: item.sourceIndex, cells: [
        location,
        item.favorite ? 1 : null,
        'login',
        item.name,
        item.notes ?? null,
        fields,
        item.reprompt,
        item.archivedDate ?? null,
        uris,
        item.payload.username ?? null,
        item.payload.password ?? null,
        item.payload.totp ?? null,
      ] }
      : { sourceIndex: item.sourceIndex, cells: [
        location,
        'login',
        item.name,
        item.notes ?? null,
        fields,
        item.reprompt,
        item.archivedDate ?? null,
        uris,
        item.payload.username ?? null,
        item.payload.password ?? null,
        item.payload.totp ?? null,
      ] };
  }

  if (item.payload.type !== 0) {
    addWarning(context, 'secure_note_subtype_omitted',
      'The CSV note row cannot preserve a non-generic secure-note subtype.',
      `${path}.secureNote.type`, item.sourceIndex);
  }
  if (item.payload.unknownFieldPaths.length > 0) {
    addWarning(context, 'unknown_secure_note_data_omitted',
      'Unknown secure-note data is not represented by Bitwarden CSV.',
      `${path}.secureNote`, item.sourceIndex);
  }
  return scope === 'personal'
    ? { sourceIndex: item.sourceIndex, cells: [
      location,
      item.favorite ? 1 : null,
      'note',
      item.name,
      item.notes ?? null,
      fields,
      item.reprompt,
      item.archivedDate ?? null,
      null,
      null,
      null,
      null,
    ] }
    : { sourceIndex: item.sourceIndex, cells: [
      location,
      'note',
      item.name,
      item.notes ?? null,
      fields,
      item.reprompt,
      item.archivedDate ?? null,
      null,
      null,
      null,
      null,
    ] };
}

function validateCommonItem(
  item: Extract<VaultTransferItem, { kind: 'login' | 'secureNote' }>,
  context: CsvContext,
): void {
  const path = `$.items[${item.sourceIndex}]`;
  if (typeof item.name !== 'string' || item.name.length === 0) {
    addError(context, 'invalid_item_name', 'CSV item names must be non-empty strings.',
      `${path}.name`, item.sourceIndex);
  }
  if (item.notes !== undefined && item.notes !== null && typeof item.notes !== 'string') {
    addError(context, 'invalid_item_notes', 'CSV item notes must be a string or null.',
      `${path}.notes`, item.sourceIndex);
  }
  if (typeof item.favorite !== 'boolean') {
    addError(context, 'invalid_favorite', 'CSV favorite must be a boolean.',
      `${path}.favorite`, item.sourceIndex);
  }
  if (item.reprompt !== 0 && item.reprompt !== 1) {
    addError(context, 'invalid_reprompt', 'CSV reprompt must be 0 or 1.',
      `${path}.reprompt`, item.sourceIndex);
  }
  if (!isOptionalNullableIsoTimestamp(item.archivedDate)) {
    addError(context, 'invalid_archived_date',
      'CSV archivedDate must be a valid ISO-8601 timestamp or null.',
      `${path}.archivedDate`, item.sourceIndex);
  }
  if (!Array.isArray(item.fields)) {
    addError(context, 'invalid_custom_fields', 'CSV custom fields must be an array.',
      `${path}.fields`, item.sourceIndex);
  } else if (item.fields.length > DEFAULT_VAULT_TRANSFER_LIMITS.maxFieldsPerItem) {
    addError(context, 'fields_limit_exceeded',
      `CSV custom fields exceed the limit of ${DEFAULT_VAULT_TRANSFER_LIMITS.maxFieldsPerItem}.`,
      `${path}.fields`, item.sourceIndex);
  }

  if (item.kind !== 'login') return;
  if (!Array.isArray(item.payload.uris)) {
    addError(context, 'invalid_login_uris', 'CSV login URIs must be an array.',
      `${path}.login.uris`, item.sourceIndex);
  } else if (item.payload.uris.length > DEFAULT_VAULT_TRANSFER_LIMITS.maxUrisPerItem) {
    addError(context, 'uris_limit_exceeded',
      `CSV login URIs exceed the limit of ${DEFAULT_VAULT_TRANSFER_LIMITS.maxUrisPerItem}.`,
      `${path}.login.uris`, item.sourceIndex);
  }
  for (const key of ['username', 'password', 'totp'] as const) {
    const value = item.payload[key];
    if (value !== undefined && value !== null && typeof value !== 'string') {
      addError(context, 'invalid_login_value', `CSV login ${key} must be a string or null.`,
        `${path}.login.${key}`, item.sourceIndex);
    }
  }
}

function resolveFolder(
  item: Extract<VaultTransferItem, { kind: 'login' | 'secureNote' }>,
  folders: ReadonlyMap<string, VaultTransferFolder>,
  context: CsvContext,
): string | null {
  if (!item.folderId) return null;
  const folder = folders.get(item.folderId);
  if (folder) return folder.name;
  addWarning(context, 'folder_reference_omitted',
    'The item folder is unavailable and is emitted as an empty CSV cell.',
    `$.items[${item.sourceIndex}].folderId`, item.sourceIndex);
  return null;
}

function resolveCollections(
  item: Extract<VaultTransferItem, { kind: 'login' | 'secureNote' }>,
  collections: ReadonlyMap<string, VaultTransferCollection>,
  context: CsvContext,
): string | null {
  const path = `$.items[${item.sourceIndex}].collectionIds`;
  if (item.collectionIds.length > DEFAULT_VAULT_TRANSFER_LIMITS.maxCollectionIdsPerItem) {
    addError(context, 'collection_ids_limit_exceeded',
      `CSV collection ids exceed the limit of ${DEFAULT_VAULT_TRANSFER_LIMITS.maxCollectionIdsPerItem}.`,
      path, item.sourceIndex);
    return null;
  }
  const names: string[] = [];
  let length = 0;
  for (const collectionId of item.collectionIds) {
    if (typeof collectionId !== 'string' || collectionId.length === 0) {
      addError(context, 'invalid_collection_reference',
        'CSV collection references must be non-empty strings.', path, item.sourceIndex);
      continue;
    }
    const collection = collections.get(collectionId);
    if (!collection) {
      addError(context, 'missing_collection_reference',
        `Collection ${collectionId} is not present in this transfer.`, path, item.sourceIndex);
      continue;
    }
    const nextLength = length + (names.length > 0 ? 1 : 0) + collection.name.length;
    if (nextLength > context.limits.maxCellChars) {
      addError(context, 'csv_cell_limit_exceeded',
        `CSV cell exceeds the configured limit of ${context.limits.maxCellChars} characters.`,
        path, item.sourceIndex);
      return null;
    }
    names.push(collection.name);
    length = nextLength;
  }
  return names.length > 0 ? names.join(',') : null;
}

function encodeFields(
  fields: readonly VaultTransferCustomField[],
  itemSourceIndex: number,
  context: CsvContext,
): string | null {
  if (fields.length === 0) return null;
  const parts: string[] = [];
  let length = 0;
  for (const field of stableBySourceIndex(fields)) {
    const path = `$.items[${itemSourceIndex}].fields[${field.sourceIndex}]`;
    if ((field.name !== undefined && field.name !== null && typeof field.name !== 'string')
      || (field.value !== undefined && field.value !== null && typeof field.value !== 'string')) {
      addError(context, 'invalid_custom_field',
        'CSV custom-field names and values must be strings or null.', path, itemSourceIndex);
      return null;
    }
    if (field.type !== 0 || field.linkedId != null) {
      addWarning(context, 'custom_field_type_flattened',
        'Bitwarden CSV preserves custom fields only as name/value text.', path, itemSourceIndex);
    }
    if (field.unknownFieldPaths.length > 0) {
      addWarning(context, 'unknown_custom_field_data_omitted',
        'Unknown custom-field data is not represented by Bitwarden CSV.', path, itemSourceIndex);
    }
    const name = field.name || '';
    // The official exporter relies on JavaScript string coercion for a missing field value.
    const value = String(field.value);
    if (/\r|\n/u.test(name) || /\r|\n|: /u.test(value)) {
      addWarning(context, 'custom_field_round_trip_ambiguous',
        'This custom field uses delimiters that the official CSV format cannot round-trip unambiguously.',
        path, itemSourceIndex);
    }
    const part = `${name}: ${value}`;
    const nextLength = length + (parts.length > 0 ? 1 : 0) + part.length;
    if (nextLength > context.limits.maxCellChars) {
      addError(context, 'csv_cell_limit_exceeded',
        `CSV cell exceeds the configured limit of ${context.limits.maxCellChars} characters.`,
        `$.items[${itemSourceIndex}].fields`, itemSourceIndex);
      return null;
    }
    parts.push(part);
    length = nextLength;
  }
  return parts.join('\n');
}

function encodeUris(item: VaultTransferLoginItem, context: CsvContext): string {
  const parts: string[] = [];
  let length = 0;
  for (const uri of stableBySourceIndex(item.payload.uris)) {
    if (typeof uri.uri !== 'string' || uri.uri.length === 0) {
      addError(context, 'invalid_login_uri', 'CSV login URIs must be non-empty strings.',
        `$.items[${item.sourceIndex}].login.uris[${uri.sourceIndex}]`, item.sourceIndex);
      return '';
    }
    const nextLength = length + (parts.length > 0 ? 1 : 0) + uri.uri.length;
    if (nextLength > context.limits.maxCellChars) {
      addError(context, 'csv_cell_limit_exceeded',
        `CSV cell exceeds the configured limit of ${context.limits.maxCellChars} characters.`,
        `$.items[${item.sourceIndex}].login.uris`, item.sourceIndex);
      return '';
    }
    parts.push(uri.uri);
    length = nextLength;
  }
  return parts.join(',');
}

function diagnoseCommonLoss(
  item: Extract<VaultTransferItem, { kind: 'login' | 'secureNote' }>,
  context: CsvContext,
): void {
  const path = `$.items[${item.sourceIndex}]`;
  if (item.passwordHistory.length > 0) {
    addWarning(context, 'password_history_omitted',
      'Password history is not represented by Bitwarden CSV.',
      `${path}.passwordHistory`, item.sourceIndex);
  }
  if (hasNonEmptyRawValue(item.raw, 'attachments')) {
    addWarning(context, 'attachments_omitted',
      'Attachments require a ZIP export and are not represented by Bitwarden CSV.',
      `${path}.attachments`, item.sourceIndex);
  }
  if (item.raw.key != null) {
    addWarning(context, 'encrypted_item_key_omitted',
      'Per-item encryption metadata is not represented by plaintext CSV.',
      `${path}.key`, item.sourceIndex);
  }
  if (item.unknownFieldPaths.length > 0) {
    addWarning(context, 'unknown_item_data_omitted',
      'Unknown item data is not represented by Bitwarden CSV.', path, item.sourceIndex);
  }
}

function diagnoseLoginLoss(item: VaultTransferLoginItem, context: CsvContext): void {
  const path = `$.items[${item.sourceIndex}].login`;
  if (item.payload.fido2Credentials.length > 0) {
    addWarning(context, 'passkeys_omitted', 'Stored passkeys are not represented by Bitwarden CSV.',
      `${path}.fido2Credentials`, item.sourceIndex);
  }
  if (item.payload.autofillOnPageLoad != null) {
    addWarning(context, 'autofill_override_omitted',
      'Per-item autofill-on-page-load settings are not represented by Bitwarden CSV.',
      `${path}.autofillOnPageLoad`, item.sourceIndex);
  }
  if (item.payload.passwordRevisionDate != null) {
    addWarning(context, 'password_revision_date_omitted',
      'Password revision dates are not represented by Bitwarden CSV.',
      `${path}.passwordRevisionDate`, item.sourceIndex);
  }
  if (item.payload.uris.some((uri) => uri.match != null)) {
    addWarning(context, 'uri_match_rules_omitted',
      'Per-URI match rules are not represented by Bitwarden CSV.',
      `${path}.uris`, item.sourceIndex);
  }
  if (item.payload.uris.some((uri) => uri.uri.includes(','))) {
    addWarning(context, 'uri_list_round_trip_ambiguous',
      'A URI contains the comma used by the official CSV array representation.',
      `${path}.uris`, item.sourceIndex);
  }
  if (item.payload.unknownFieldPaths.length > 0) {
    addWarning(context, 'unknown_login_data_omitted',
      'Unknown login data is not represented by Bitwarden CSV.', path, item.sourceIndex);
  }
  if (item.payload.uris.some((uri) => uri.unknownFieldPaths.length > 0)) {
    addWarning(context, 'unknown_uri_data_omitted',
      'Unknown URI data is not represented by Bitwarden CSV.', `${path}.uris`, item.sourceIndex);
  }
}

function diagnoseOrganizationLoss(
  item: Extract<VaultTransferItem, { kind: 'login' | 'secureNote' }>,
  context: CsvContext,
): void {
  const path = `$.items[${item.sourceIndex}]`;
  if (item.folderId) {
    addWarning(context, 'organization_folder_omitted',
      'Personal folder membership is not represented by organization CSV.',
      `${path}.folderId`, item.sourceIndex);
  }
  if (item.favorite) {
    addWarning(context, 'organization_favorite_omitted',
      'Favorite status is not represented by the official organization CSV schema.',
      `${path}.favorite`, item.sourceIndex);
  }
}

function serializeRows(
  rows: readonly CsvRow[],
  columns: readonly string[],
  context: CsvContext,
): string | null {
  const chunks = [columns.join(',')];
  let totalBytes = utf8ByteLength(chunks[0]!);
  for (const [rowIndex, row] of rows.entries()) {
    const encoded = row.cells.map((cell, columnIndex) => encodeCell(
      cell, `$.rows[${rowIndex}][${columnIndex}]`, row.sourceIndex, context,
    )).join(',');
    const rowBytes = 2 + utf8ByteLength(encoded);
    if (totalBytes + rowBytes > context.limits.maxOutputBytes) {
      addError(context, 'csv_output_limit_exceeded',
        `CSV output exceeds the configured limit of ${context.limits.maxOutputBytes} bytes.`, '$');
      return null;
    }
    chunks.push(`\r\n${encoded}`);
    totalBytes += rowBytes;
  }
  return chunks.join('');
}

function encodeCell(
  input: CsvCell,
  path: string,
  sourceIndex: number,
  context: CsvContext,
): string {
  if (input === null) return '';
  let value = String(input);
  if (value.length > context.limits.maxCellChars) {
    addError(context, 'csv_cell_limit_exceeded',
      `CSV cell exceeds the configured limit of ${context.limits.maxCellChars} characters.`,
      path, sourceIndex);
    return '';
  }
  let forceQuote = false;
  if (FORMULA_PREFIX.test(value)) {
    // The importer trims this tab, so spreadsheet safety does not alter a vault round trip.
    value = `\t${value}`;
    forceQuote = true;
    addWarning(context, 'formula_prefix_escaped',
      'A spreadsheet formula prefix was neutralized with a reversible leading tab.',
      path, sourceIndex);
  }
  const escaped = value.replaceAll('"', '""');
  const quote = forceQuote || CSV_SPECIAL.test(value) || value.startsWith(' ') || value.endsWith(' ');
  return quote ? `"${escaped}"` : escaped;
}

function omitItem(
  context: CsvContext,
  item: VaultTransferItem,
  code: string,
  message: string,
): void {
  context.omittedItemCount += 1;
  addWarning(context, code, message, `$.items[${item.sourceIndex}].type`, item.sourceIndex);
}

function isCsvItem(
  item: VaultTransferItem,
): item is Extract<VaultTransferItem, { kind: 'login' | 'secureNote' }> {
  return (item.rawType === 1 && item.kind === 'login')
    || (item.rawType === 2 && item.kind === 'secureNote');
}

function omittedItemCode(item: VaultTransferItem): string {
  if (item.kind === 'card' && item.rawType === 3) return 'card_item_omitted';
  if (item.kind === 'identity' && item.rawType === 4) return 'identity_item_omitted';
  if (item.kind === 'sshKey' && item.rawType === 5) return 'ssh_key_item_omitted';
  return 'new_item_type_omitted';
}

function hasNonEmptyRawValue(record: Readonly<Record<string, unknown>>, key: string): boolean {
  const value = record[key];
  return Array.isArray(value) ? value.length > 0 : value !== undefined && value !== null;
}

function validateUniqueSources<T extends { sourceIndex: number }>(
  values: readonly T[],
  path: string,
  context: CsvContext,
): void {
  const seen = new Set<number>();
  for (const value of values) {
    if (!Number.isSafeInteger(value.sourceIndex) || value.sourceIndex < 0 || seen.has(value.sourceIndex)) {
      addError(context, 'invalid_source_index',
        'Source indices must be unique non-negative integers.', path, value.sourceIndex);
    }
    seen.add(value.sourceIndex);
  }
}

function stableBySourceIndex<T extends { sourceIndex: number }>(values: readonly T[]): T[] {
  return [...values].sort((left, right) => left.sourceIndex - right.sourceIndex);
}

function resolveLimits(overrides: Partial<VaultTransferCsvLimits> | undefined): VaultTransferCsvLimits {
  const limits = { ...DEFAULT_VAULT_TRANSFER_CSV_LIMITS, ...overrides };
  validateLimit(limits.maxRows, 'maxRows', HARD_MAX_ROWS);
  validateLimit(limits.maxCellChars, 'maxCellChars', HARD_MAX_CELL_CHARS);
  validateLimit(limits.maxOutputBytes, 'maxOutputBytes', HARD_MAX_OUTPUT_BYTES);
  validateLimit(limits.maxDiagnostics, 'maxDiagnostics', HARD_MAX_DIAGNOSTICS);
  return limits;
}

function validateLimit(value: number, name: string, hardMaximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > hardMaximum) {
    throw new RangeError(`${name} must be an integer between 1 and ${hardMaximum}`);
  }
}

function addWarning(
  context: CsvContext,
  code: string,
  message: string,
  path?: string,
  sourceIndex?: number,
): void {
  addDiagnostic(context, {
    severity: 'warning', code, message,
    ...(path === undefined ? {} : { path }),
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function addError(
  context: CsvContext,
  code: string,
  message: string,
  path?: string,
  sourceIndex?: number,
): void {
  context.hasError = true;
  addDiagnostic(context, {
    severity: 'error', code, message,
    ...(path === undefined ? {} : { path }),
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function addDiagnostic(context: CsvContext, diagnostic: VaultTransferCsvDiagnostic): void {
  if (context.diagnostics.length < context.limits.maxDiagnostics) {
    context.diagnostics.push(Object.freeze(diagnostic));
    return;
  }
  context.diagnosticOverflow += 1;
}

function finalizeDiagnostics(context: CsvContext): void {
  if (context.diagnosticOverflow === 0) return;
  const omitted = context.diagnosticOverflow + 1;
  context.diagnostics[context.diagnostics.length - 1] = Object.freeze({
    severity: context.hasError ? 'error' : 'warning',
    code: 'diagnostics_truncated',
    message: `${omitted} additional CSV diagnostics were omitted.`,
    path: '$',
  });
}

function failed(context: CsvContext, exportedItemCount: number): EncodeVaultTransferCsvResult {
  finalizeDiagnostics(context);
  return {
    ok: false,
    csv: null,
    exportedItemCount,
    omittedItemCount: context.omittedItemCount,
    diagnostics: context.diagnostics,
  };
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const low = value.charCodeAt(index + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}
