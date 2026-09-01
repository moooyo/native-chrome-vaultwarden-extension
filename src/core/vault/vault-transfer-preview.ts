import {
  MAX_PERSONAL_IMPORT_PASSWORD_HISTORY,
  type PersonalImportCapabilityPolicy,
} from './vault-transfer-commit.js';
import { isIsoTimestamp } from './iso-date.js';
import type {
  VaultTransferDiagnostic,
  VaultTransferFormat,
  VaultTransferInspection,
  VaultTransferScope,
} from './vault-transfer.js';

export type VaultTransferPreviewFormat = VaultTransferFormat | 'bitwarden-zip';
export type VaultTransferPreviewDiagnosticCategory = 'error' | 'warning' | 'unsupported';

/**
 * Vaultwarden exposes the official route but implements it as ordered collection, cipher, and
 * relationship writes. A late relationship failure can therefore leave earlier writes committed,
 * and cipher write failures are discarded. Never route a transactional import through it.
 */
export const VAULTWARDEN_ORGANIZATION_IMPORT_BLOCKER = Object.freeze({
  endpoint: '/api/ciphers/import-organization',
  code: 'non_atomic_partial_commit',
  atomic: false,
} as const);

const SAFE_DIAGNOSTIC_CODES = [
  'ambiguous_transfer_scope', 'archive_metadata_invalid', 'attachments_unsupported',
  'autofill_on_page_load_unsupported',
  'capability_policy_invalid', 'collection_ids_limit_exceeded', 'collections_limit_exceeded',
  'csv_cell_limit_exceeded', 'csv_columns_limit_exceeded', 'csv_format_is_lossy',
  'csv_rows_limit_exceeded', 'custom_fields_unsupported', 'diagnostics_truncated',
  'duplicate_collection_id', 'duplicate_csv_header', 'duplicate_folder_id', 'empty_input',
  'encrypted_input_requires_decryption', 'fields_limit_exceeded', 'folders_limit_exceeded',
  'folders_unsupported', 'format_mismatch', 'input_too_large', 'inspection_invalid',
  'inspection_resource_limit', 'invalid_encryption_marker', 'invalid_json_root', 'invalid_shape',
  'item_dates_unsupported', 'item_type_unsupported', 'items_limit_exceeded', 'malformed_csv',
  'malformed_json', 'missing_collection_reference', 'missing_folder_reference', 'missing_folders',
  'missing_items', 'organization_import_atomicity_unavailable', 'organization_target_required',
  'outcome_unknown', 'passkeys_limit_exceeded',
  'passkeys_unsupported', 'password_history_limit_exceeded', 'password_history_unsupported',
  'preview_options_invalid', 'reprompt_unsupported', 'secure_note_type_unsupported',
  'server_managed_dates_dropped',
  'ssh_linked_fields_unsupported',
  'string_limit_exceeded', 'transfer_diagnostic', 'transfer_notice', 'unknown_field',
  'unknown_fields', 'unknown_item_type', 'unsupported_ir_version', 'unsupported_known_data',
  'uri_match_unsupported', 'uris_limit_exceeded',
] as const;

export type VaultTransferPreviewDiagnosticCode = typeof SAFE_DIAGNOSTIC_CODES[number];

export interface VaultTransferPreviewDiagnostic {
  readonly category: VaultTransferPreviewDiagnosticCategory;
  readonly code: VaultTransferPreviewDiagnosticCode;
  readonly sourceIndex?: number;
}

export interface VaultTransferPreviewCounts {
  readonly folders: number;
  readonly collections: number;
  readonly items: number;
  readonly attachments: number;
}

export interface VaultTransferPreviewDiagnostics {
  readonly errors: readonly VaultTransferPreviewDiagnostic[];
  readonly warnings: readonly VaultTransferPreviewDiagnostic[];
  readonly unsupported: readonly VaultTransferPreviewDiagnostic[];
  readonly omittedCount: number;
}

export interface VaultTransferPreview {
  readonly format: VaultTransferPreviewFormat;
  readonly scope: VaultTransferScope;
  readonly counts: VaultTransferPreviewCounts;
  readonly diagnostics: VaultTransferPreviewDiagnostics;
  readonly organizationTargetRequired: boolean;
  readonly hasUnknownOutcome: boolean;
  readonly canCommit: boolean;
}

export interface VaultTransferPreviewOptions {
  readonly format?: VaultTransferPreviewFormat;
  readonly attachmentCount?: number;
  readonly unknownOutcome?: boolean;
  readonly advancedDataUnsupported?: boolean;
}

const SAFE_CODE_SET = new Set<string>(SAFE_DIAGNOSTIC_CODES);
const UNSUPPORTED_CODE_SET = new Set<VaultTransferPreviewDiagnosticCode>([
  'attachments_unsupported', 'custom_fields_unsupported', 'encrypted_input_requires_decryption',
  'autofill_on_page_load_unsupported', 'folders_unsupported', 'item_dates_unsupported',
  'item_type_unsupported', 'passkeys_unsupported',
  'organization_import_atomicity_unavailable',
  'password_history_unsupported', 'reprompt_unsupported', 'secure_note_type_unsupported',
  'ssh_linked_fields_unsupported',
  'unknown_field', 'unknown_fields', 'unknown_item_type', 'unsupported_ir_version',
  'unsupported_known_data', 'uri_match_unsupported',
]);

const MAX_DIAGNOSTICS_PER_CATEGORY = 32;
const MAX_SOURCE_DIAGNOSTICS = 1_000;
const MAX_ITEMS = 10_000;
const MAX_FOLDERS = 5_000;
const MAX_COLLECTIONS = 5_000;
const MAX_RELATIONSHIPS = 100_000;
const MAX_ATTACHMENTS = 5_000;
const MAX_FIELDS_PER_ITEM = 100;
const MAX_URIS_PER_ITEM = 100;
const MAX_PASSKEYS_PER_ITEM = 100;
const MAX_PASSWORD_HISTORY_PER_ITEM = 100;
const MAX_COLLECTION_IDS_PER_ITEM = 1_000;
const MAX_STRING_CHARS = 1024 * 1024;
const MAX_RECORD_KEYS = 128;
const MAX_SOURCE_INDEX = 1_000_000;

const INSPECTION_KEYS = new Set(['canCommit', 'ir', 'diagnostics']);
const IR_KEYS = new Set([
  'version', 'format', 'scope', 'inputBytes', 'folders', 'collections', 'items',
  'folderRelationships', 'collectionRelationships', 'unknownFieldPaths',
]);
const COMMON_ITEM_KEYS = new Set([
  'sourceIndex', 'rawType', 'id', 'organizationId', 'folderId', 'collectionIds', 'name',
  'notes', 'favorite', 'reprompt', 'fields', 'passwordHistory', 'creationDate',
  'revisionDate', 'deletedDate', 'archivedDate', 'raw', 'unknownFieldPaths', 'kind', 'payload',
]);
const FOLDER_KEYS = new Set(['sourceIndex', 'id', 'name', 'raw', 'unknownFieldPaths']);
const COLLECTION_KEYS = new Set([
  'sourceIndex', 'id', 'name', 'organizationId', 'externalId', 'raw', 'unknownFieldPaths',
]);
const FIELD_KEYS = new Set(['sourceIndex', 'type', 'name', 'value', 'linkedId', 'raw', 'unknownFieldPaths']);
const HISTORY_KEYS = new Set(['sourceIndex', 'password', 'lastUsedDate', 'raw', 'unknownFieldPaths']);
const LOGIN_KEYS = new Set([
  'username', 'password', 'totp', 'autofillOnPageLoad', 'passwordRevisionDate',
  'uris', 'fido2Credentials', 'raw', 'unknownFieldPaths',
]);
const URI_KEYS = new Set(['sourceIndex', 'uri', 'match', 'raw', 'unknownFieldPaths']);
const PASSKEY_KEYS = new Set([
  'sourceIndex', 'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
  'counter', 'discoverable', 'userHandle', 'userName', 'rpName', 'userDisplayName',
  'creationDate', 'raw', 'unknownFieldPaths',
]);
const SECURE_NOTE_KEYS = new Set(['type', 'raw', 'unknownFieldPaths']);
const STRING_PAYLOAD_KEYS = new Set(['values', 'raw', 'unknownFieldPaths']);
const SSH_KEY_VALUE_KEYS = new Set(['privateKey', 'publicKey', 'keyFingerprint']);
const DIAGNOSTIC_KEYS = new Set(['severity', 'code', 'message', 'path', 'sourceKind', 'sourceIndex']);
const FOLDER_RELATIONSHIP_KEYS = new Set(['itemSourceIndex', 'sourceFolderId', 'folderSourceIndex']);
const COLLECTION_RELATIONSHIP_KEYS = new Set([
  'itemSourceIndex', 'sourceCollectionId', 'collectionSourceIndex',
]);
const POLICY_KEYS = new Set([
  'supportedItemTypes', 'folders', 'customFields', 'reprompt', 'loginUriMatch',
  'autofillOnPageLoad', 'passwordHistory', 'passkeys', 'itemDates', 'nonGenericSecureNotes',
]);
const OPTION_KEYS = new Set([
  'format', 'attachmentCount', 'unknownOutcome', 'advancedDataUnsupported',
]);

const ITEM_KINDS = new Map<number, string>([
  [1, 'login'], [2, 'secureNote'], [3, 'card'], [4, 'identity'], [5, 'sshKey'],
  [6, 'bankAccount'], [7, 'driversLicense'], [8, 'passport'],
]);

interface ParsedDiagnostic {
  readonly severity: VaultTransferDiagnostic['severity'];
  readonly code: string;
  readonly sourceIndex?: number;
}

interface ParsedItemCapabilities {
  readonly sourceIndex: number;
  readonly rawType: number;
  readonly kind: string;
  readonly organizationOwned: boolean;
  readonly customFieldCount: number;
  readonly hasLinkedCustomField: boolean;
  readonly reprompt: 0 | 1;
  readonly passwordHistoryCount: number;
  readonly hasDeletedDate: boolean;
  readonly hasArchivedDate: boolean;
  readonly passkeyCount: number;
  readonly hasMissingPasskeyCreationDate: boolean;
  readonly hasUriMatch: boolean;
  readonly hasAutofillOnPageLoad: boolean;
  readonly secureNoteType: number | undefined;
}

interface ParsedInspection {
  readonly canCommit: boolean;
  readonly format: VaultTransferFormat;
  readonly scope: VaultTransferScope;
  readonly folders: number;
  readonly collections: number;
  readonly items: readonly ParsedItemCapabilities[];
  readonly unknownFieldCount: number;
  readonly diagnostics: readonly ParsedDiagnostic[];
  readonly hasIr: boolean;
}

interface ParsedPolicy {
  readonly supportedItemTypes: ReadonlySet<number>;
  readonly folders: boolean;
  readonly customFields: boolean;
  readonly reprompt: boolean;
  readonly loginUriMatch: boolean;
  readonly autofillOnPageLoad: boolean;
  readonly passwordHistory: boolean;
  readonly passkeys: boolean;
  readonly itemDates: boolean;
  readonly nonGenericSecureNotes: boolean;
}

interface ParsedOptions {
  readonly format: VaultTransferPreviewFormat | undefined;
  readonly attachmentCount: number;
  readonly unknownOutcome: boolean;
  readonly advancedDataUnsupported: boolean;
}

class PreviewParseError extends Error {
  constructor(readonly kind: 'invalid' | 'resource', readonly omittedHint = 0) {
    super(kind);
  }
}

class DiagnosticCollector {
  private readonly errors: VaultTransferPreviewDiagnostic[] = [];
  private readonly warnings: VaultTransferPreviewDiagnostic[] = [];
  private readonly unsupported: VaultTransferPreviewDiagnostic[] = [];
  private omittedCount = 0;

  omit(count: number): void {
    if (Number.isSafeInteger(count) && count > 0) this.omittedCount += count;
  }

  add(category: VaultTransferPreviewDiagnosticCategory, code: VaultTransferPreviewDiagnosticCode, sourceIndex?: number): void {
    const target = category === 'error' ? this.errors : (category === 'warning' ? this.warnings : this.unsupported);
    if (target.length >= MAX_DIAGNOSTICS_PER_CATEGORY) {
      this.omittedCount++;
      return;
    }
    target.push(Object.freeze({ category, code, ...(sourceIndex === undefined ? {} : { sourceIndex }) }));
  }

  addUnique(category: VaultTransferPreviewDiagnosticCategory, code: VaultTransferPreviewDiagnosticCode, sourceIndex?: number): void {
    const target = category === 'error' ? this.errors : (category === 'warning' ? this.warnings : this.unsupported);
    if (target.some((entry) => entry.code === code && entry.sourceIndex === sourceIndex)) return;
    this.add(category, code, sourceIndex);
  }

  hasBlocking(): boolean {
    return this.errors.length > 0 || this.unsupported.length > 0;
  }

  finish(): VaultTransferPreviewDiagnostics {
    return Object.freeze({
      errors: Object.freeze(this.errors),
      warnings: Object.freeze(this.warnings),
      unsupported: Object.freeze(this.unsupported),
      omittedCount: this.omittedCount,
    });
  }
}

/** Build a bounded preview without carrying transfer values across the worker/UI boundary. */
export function buildVaultTransferPreview(
  inspection: VaultTransferInspection,
  capabilities: PersonalImportCapabilityPolicy,
  options: VaultTransferPreviewOptions = {},
): VaultTransferPreview {
  const diagnostics = new DiagnosticCollector();
  let parsedOptions: ParsedOptions = {
    format: undefined,
    attachmentCount: 0,
    unknownOutcome: false,
    advancedDataUnsupported: false,
  };
  let optionsValid = true;
  try {
    parsedOptions = parseOptions(options);
  } catch {
    optionsValid = false;
    diagnostics.add('error', 'preview_options_invalid');
  }

  let parsedInspection: ParsedInspection | undefined;
  try {
    parsedInspection = parseInspection(inspection);
  } catch (error) {
    const parsedError = error instanceof PreviewParseError ? error : new PreviewParseError('invalid');
    diagnostics.omit(parsedError.omittedHint);
    diagnostics.add('error', parsedError.kind === 'resource' ? 'inspection_resource_limit' : 'inspection_invalid');
  }

  let policy: ParsedPolicy | undefined;
  try {
    policy = parsePolicy(capabilities);
  } catch {
    diagnostics.add('error', 'capability_policy_invalid');
  }

  const selectedFormat = parsedOptions.format ?? parsedInspection?.format ?? 'bitwarden-json';
  if (parsedInspection && parsedOptions.format !== undefined) {
    const expected = parsedOptions.format === 'bitwarden-zip' ? 'bitwarden-json' : parsedOptions.format;
    if (expected !== parsedInspection.format) diagnostics.add('error', 'format_mismatch');
  }
  if (parsedOptions.attachmentCount > 0 && selectedFormat !== 'bitwarden-zip') {
    diagnostics.add('error', 'archive_metadata_invalid');
  }

  const scope = parsedInspection?.scope ?? 'personal';
  const organizationTargetRequired = scope === 'organization';
  if (organizationTargetRequired) {
    diagnostics.addUnique('error', 'organization_target_required');
    diagnostics.addUnique('unsupported', 'organization_import_atomicity_unavailable');
  }
  if (parsedOptions.attachmentCount > 0) diagnostics.add('unsupported', 'attachments_unsupported');
  if (parsedOptions.unknownOutcome) diagnostics.add('error', 'outcome_unknown');
  if (parsedOptions.advancedDataUnsupported) {
    diagnostics.addUnique('unsupported', 'unsupported_known_data');
  }
  if (parsedInspection && policy && parsedInspection.hasIr) {
    addCapabilityDiagnostics(diagnostics, parsedInspection, policy);
  }
  if (parsedInspection) {
    for (const diagnostic of parsedInspection.diagnostics) addInspectionDiagnostic(diagnostics, diagnostic);
  }

  const counts = Object.freeze({
    folders: parsedInspection?.folders ?? 0,
    collections: parsedInspection?.collections ?? 0,
    items: parsedInspection?.items.length ?? 0,
    attachments: parsedOptions.attachmentCount,
  });
  const canCommit = optionsValid
    && parsedInspection !== undefined
    && policy !== undefined
    && parsedInspection.hasIr
    && parsedInspection.canCommit
    && !diagnostics.hasBlocking();
  return Object.freeze({
    format: selectedFormat,
    scope,
    counts,
    diagnostics: diagnostics.finish(),
    organizationTargetRequired,
    hasUnknownOutcome: parsedOptions.unknownOutcome,
    canCommit,
  });
}

function parseOptions(value: unknown): ParsedOptions {
  const record = exactRecord(value, OPTION_KEYS, 4);
  const formatValue = optionalData(record, 'format');
  const format = formatValue.present ? parsePreviewFormat(formatValue.value) : undefined;
  const attachmentCountValue = optionalData(record, 'attachmentCount');
  const attachmentCount = attachmentCountValue.present
    ? boundedInteger(attachmentCountValue.value, 0, MAX_ATTACHMENTS)
    : 0;
  const unknownOutcomeValue = optionalData(record, 'unknownOutcome');
  const unknownOutcome = unknownOutcomeValue.present ? strictBoolean(unknownOutcomeValue.value) : false;
  const advancedDataValue = optionalData(record, 'advancedDataUnsupported');
  const advancedDataUnsupported = advancedDataValue.present
    ? strictBoolean(advancedDataValue.value)
    : false;
  return { format, attachmentCount, unknownOutcome, advancedDataUnsupported };
}

function parsePolicy(value: unknown): ParsedPolicy {
  const record = exactRecord(value, POLICY_KEYS, POLICY_KEYS.size);
  const supported = denseArray(requiredData(record, 'supportedItemTypes'), 5);
  const supportedItemTypes = new Set<number>();
  for (const itemType of supported) {
    const parsed = boundedInteger(itemType, 1, 5);
    if (supportedItemTypes.has(parsed)) throw new PreviewParseError('invalid');
    supportedItemTypes.add(parsed);
  }
  return {
    supportedItemTypes,
    folders: strictBoolean(requiredData(record, 'folders')),
    customFields: strictBoolean(requiredData(record, 'customFields')),
    reprompt: strictBoolean(requiredData(record, 'reprompt')),
    loginUriMatch: strictBoolean(requiredData(record, 'loginUriMatch')),
    autofillOnPageLoad: strictBoolean(requiredData(record, 'autofillOnPageLoad')),
    passwordHistory: strictBoolean(requiredData(record, 'passwordHistory')),
    passkeys: strictBoolean(requiredData(record, 'passkeys')),
    itemDates: strictBoolean(requiredData(record, 'itemDates')),
    nonGenericSecureNotes: strictBoolean(requiredData(record, 'nonGenericSecureNotes')),
  };
}

function parseInspection(value: unknown): ParsedInspection {
  const record = exactRecord(value, INSPECTION_KEYS, 3);
  const canCommit = strictBoolean(requiredData(record, 'canCommit'));
  const diagnosticValues = denseArray(requiredData(record, 'diagnostics'), MAX_SOURCE_DIAGNOSTICS, true);
  const diagnostics = diagnosticValues.map(parseDiagnostic);
  const irValue = requiredData(record, 'ir');
  const hasErrors = diagnostics.some((diagnostic) => diagnostic.severity === 'error');
  if (irValue === null) {
    if (canCommit || !hasErrors) throw new PreviewParseError('invalid');
    return {
      canCommit,
      format: 'bitwarden-json',
      scope: 'personal',
      folders: 0,
      collections: 0,
      items: Object.freeze([]),
      unknownFieldCount: 0,
      diagnostics: Object.freeze(diagnostics),
      hasIr: false,
    };
  }
  const ir = exactRecord(irValue, IR_KEYS, IR_KEYS.size);
  boundedInteger(requiredData(ir, 'version'), 1, 1);
  const format = parseTransferFormat(requiredData(ir, 'format'));
  const scope = parseScope(requiredData(ir, 'scope'));
  boundedInteger(requiredData(ir, 'inputBytes'), 0, 32 * 1024 * 1024);
  const folders = parseFolders(requiredData(ir, 'folders'));
  const collections = parseCollections(requiredData(ir, 'collections'));
  const itemValues = denseArray(requiredData(ir, 'items'), MAX_ITEMS);
  const items = itemValues.map(parseItem);
  parseFolderRelationships(requiredData(ir, 'folderRelationships'));
  parseCollectionRelationships(requiredData(ir, 'collectionRelationships'));
  const unknownFieldPaths = parseStringArray(requiredData(ir, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  if (canCommit !== !hasErrors) throw new PreviewParseError('invalid');
  if (canCommit && unknownFieldPaths.length > 0) throw new PreviewParseError('invalid');
  return {
    canCommit,
    format,
    scope,
    folders,
    collections,
    items: Object.freeze(items),
    unknownFieldCount: unknownFieldPaths.length,
    diagnostics: Object.freeze(diagnostics),
    hasIr: true,
  };
}

function parseDiagnostic(value: unknown): ParsedDiagnostic {
  const record = exactRecord(value, DIAGNOSTIC_KEYS, DIAGNOSTIC_KEYS.size);
  const severityValue = requiredData(record, 'severity');
  if (severityValue !== 'info' && severityValue !== 'warning' && severityValue !== 'error') {
    throw new PreviewParseError('invalid');
  }
  const code = boundedString(requiredData(record, 'code'), 128);
  boundedString(requiredData(record, 'message'));
  const path = optionalData(record, 'path');
  if (path.present) boundedString(path.value);
  const sourceKind = optionalData(record, 'sourceKind');
  if (sourceKind.present && ![
    'root', 'folder', 'collection', 'item', 'field', 'row', 'cell',
  ].includes(boundedString(sourceKind.value, 16))) throw new PreviewParseError('invalid');
  const sourceIndexValue = optionalData(record, 'sourceIndex');
  const sourceIndex = sourceIndexValue.present
    ? boundedInteger(sourceIndexValue.value, 0, MAX_SOURCE_INDEX)
    : undefined;
  return { severity: severityValue, code, ...(sourceIndex === undefined ? {} : { sourceIndex }) };
}

function parseFolders(value: unknown): number {
  const folders = denseArray(value, MAX_FOLDERS);
  for (const folder of folders) {
    const record = exactRecord(folder, FOLDER_KEYS, FOLDER_KEYS.size);
    boundedInteger(requiredData(record, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
    boundedString(requiredData(record, 'id'));
    boundedString(requiredData(record, 'name'));
    opaqueRecord(requiredData(record, 'raw'));
    parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  }
  return folders.length;
}

function parseCollections(value: unknown): number {
  const collections = denseArray(value, MAX_COLLECTIONS);
  for (const collection of collections) {
    const record = exactRecord(collection, COLLECTION_KEYS, COLLECTION_KEYS.size);
    boundedInteger(requiredData(record, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
    boundedString(requiredData(record, 'id'));
    boundedString(requiredData(record, 'name'));
    parseOptionalNullableString(record, 'organizationId');
    parseOptionalNullableString(record, 'externalId');
    opaqueRecord(requiredData(record, 'raw'));
    parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  }
  return collections.length;
}

function parseItem(value: unknown): ParsedItemCapabilities {
  const record = exactRecord(value, COMMON_ITEM_KEYS, COMMON_ITEM_KEYS.size);
  const sourceIndex = boundedInteger(requiredData(record, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
  const rawType = boundedInteger(requiredData(record, 'rawType'), -1, Number.MAX_SAFE_INTEGER);
  const kind = boundedString(requiredData(record, 'kind'), 32);
  const expectedKind = ITEM_KINDS.get(rawType) ?? 'unsupported';
  if (kind !== expectedKind) throw new PreviewParseError('invalid');
  parseOptionalNullableString(record, 'id');
  const organizationId = parseOptionalNullableString(record, 'organizationId');
  parseOptionalNullableString(record, 'folderId');
  const collectionIds = parseStringArray(requiredData(record, 'collectionIds'), MAX_COLLECTION_IDS_PER_ITEM);
  boundedString(requiredData(record, 'name'));
  parseOptionalNullableString(record, 'notes');
  strictBoolean(requiredData(record, 'favorite'));
  const repromptValue = requiredData(record, 'reprompt');
  if (repromptValue !== 0 && repromptValue !== 1) throw new PreviewParseError('invalid');
  const customFields = parseFields(requiredData(record, 'fields'));
  const passwordHistoryCount = parsePasswordHistory(requiredData(record, 'passwordHistory'));
  parseOptionalNullableIsoTimestamp(record, 'creationDate');
  parseOptionalNullableIsoTimestamp(record, 'revisionDate');
  const deletedDate = parseOptionalNullableIsoTimestamp(record, 'deletedDate');
  const archivedDate = parseOptionalNullableUtcTimestamp(record, 'archivedDate');
  opaqueRecord(requiredData(record, 'raw'));
  parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  const payload = requiredData(record, 'payload');
  let passkeyCount = 0;
  let hasMissingPasskeyCreationDate = false;
  let hasUriMatch = false;
  let hasAutofillOnPageLoad = false;
  let secureNoteType: number | undefined;
  if (kind === 'login') {
    const login = parseLoginPayload(payload);
    passkeyCount = login.passkeyCount;
    hasMissingPasskeyCreationDate = login.hasMissingPasskeyCreationDate;
    hasUriMatch = login.hasUriMatch;
    hasAutofillOnPageLoad = login.hasAutofillOnPageLoad;
  } else if (kind === 'secureNote') {
    secureNoteType = parseSecureNotePayload(payload);
  } else if (kind === 'sshKey') {
    parseSshKeyPayload(payload);
  } else if (kind === 'unsupported') {
    opaqueRecord(payload);
  } else {
    parseStringPayload(payload);
  }
  return {
    sourceIndex,
    rawType,
    kind,
    organizationOwned: organizationId.value != null || collectionIds.length > 0,
    customFieldCount: customFields.count,
    hasLinkedCustomField: customFields.hasLinked,
    reprompt: repromptValue,
    passwordHistoryCount,
    hasDeletedDate: deletedDate.value != null,
    hasArchivedDate: archivedDate.value != null,
    passkeyCount,
    hasMissingPasskeyCreationDate,
    hasUriMatch,
    hasAutofillOnPageLoad,
    secureNoteType,
  };
}

function parseFields(value: unknown): { readonly count: number; readonly hasLinked: boolean } {
  const fields = denseArray(value, MAX_FIELDS_PER_ITEM);
  let hasLinked = false;
  for (const field of fields) {
    const record = exactRecord(field, FIELD_KEYS, FIELD_KEYS.size);
    boundedInteger(requiredData(record, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
    const type = boundedInteger(requiredData(record, 'type'), 0, 3);
    if (type === 3) hasLinked = true;
    parseOptionalNullableString(record, 'name');
    parseOptionalNullableString(record, 'value');
    const linkedId = optionalData(record, 'linkedId');
    if (linkedId.present && linkedId.value !== null) {
      boundedInteger(linkedId.value, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
    }
    opaqueRecord(requiredData(record, 'raw'));
    parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  }
  return { count: fields.length, hasLinked };
}

function parsePasswordHistory(value: unknown): number {
  const entries = denseArray(value, MAX_PASSWORD_HISTORY_PER_ITEM);
  for (const entry of entries) {
    const record = exactRecord(entry, HISTORY_KEYS, HISTORY_KEYS.size);
    boundedInteger(requiredData(record, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
    boundedString(requiredData(record, 'password'));
    parseOptionalNullableUtcTimestamp(record, 'lastUsedDate');
    opaqueRecord(requiredData(record, 'raw'));
    parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  }
  return entries.length;
}

function parseLoginPayload(value: unknown): {
  passkeyCount: number;
  hasMissingPasskeyCreationDate: boolean;
  hasUriMatch: boolean;
  hasAutofillOnPageLoad: boolean;
} {
  const record = exactRecord(value, LOGIN_KEYS, LOGIN_KEYS.size);
  parseOptionalNullableString(record, 'username');
  parseOptionalNullableString(record, 'password');
  parseOptionalNullableString(record, 'totp');
  const autofillOnPageLoad = parseOptionalNullableBoolean(record, 'autofillOnPageLoad');
  parseOptionalNullableUtcTimestamp(record, 'passwordRevisionDate');
  const uris = denseArray(requiredData(record, 'uris'), MAX_URIS_PER_ITEM);
  let hasUriMatch = false;
  for (const uri of uris) {
    const uriRecord = exactRecord(uri, URI_KEYS, URI_KEYS.size);
    boundedInteger(requiredData(uriRecord, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
    boundedString(requiredData(uriRecord, 'uri'));
    const match = optionalData(uriRecord, 'match');
    if (match.present && match.value !== null) {
      boundedInteger(match.value, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
      hasUriMatch = true;
    }
    opaqueRecord(requiredData(uriRecord, 'raw'));
    parseStringArray(requiredData(uriRecord, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  }
  const passkeys = denseArray(requiredData(record, 'fido2Credentials'), MAX_PASSKEYS_PER_ITEM);
  let hasMissingPasskeyCreationDate = false;
  for (const passkey of passkeys) {
    if (parsePasskey(passkey)) hasMissingPasskeyCreationDate = true;
  }
  opaqueRecord(requiredData(record, 'raw'));
  parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  return {
    passkeyCount: passkeys.length,
    hasMissingPasskeyCreationDate,
    hasUriMatch,
    hasAutofillOnPageLoad: autofillOnPageLoad.present,
  };
}

function parsePasskey(value: unknown): boolean {
  const record = exactRecord(value, PASSKEY_KEYS, PASSKEY_KEYS.size);
  boundedInteger(requiredData(record, 'sourceIndex'), 0, MAX_SOURCE_INDEX);
  for (const key of [
    'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable',
  ]) boundedString(requiredData(record, key));
  for (const key of ['userHandle', 'userName', 'rpName', 'userDisplayName']) {
    parseOptionalNullableString(record, key);
  }
  const creationDate = parseOptionalNullableUtcTimestamp(record, 'creationDate');
  opaqueRecord(requiredData(record, 'raw'));
  parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  return creationDate.value == null;
}

function parseSecureNotePayload(value: unknown): number {
  const record = exactRecord(value, SECURE_NOTE_KEYS, SECURE_NOTE_KEYS.size);
  const type = boundedInteger(requiredData(record, 'type'), Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
  opaqueRecord(requiredData(record, 'raw'));
  parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
  return type;
}

function parseStringPayload(value: unknown): void {
  const record = exactRecord(value, STRING_PAYLOAD_KEYS, STRING_PAYLOAD_KEYS.size);
  const values = opaqueRecord(requiredData(record, 'values'));
  for (const key of Reflect.ownKeys(values)) {
    if (typeof key !== 'string') throw new PreviewParseError('invalid');
    const entry = requiredData(values, key);
    if (entry !== null) boundedString(entry);
  }
  opaqueRecord(requiredData(record, 'raw'));
  parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
}

function parseSshKeyPayload(value: unknown): void {
  const record = exactRecord(value, STRING_PAYLOAD_KEYS, STRING_PAYLOAD_KEYS.size);
  const values = exactRecord(requiredData(record, 'values'), SSH_KEY_VALUE_KEYS, SSH_KEY_VALUE_KEYS.size);
  for (const key of SSH_KEY_VALUE_KEYS) boundedString(requiredData(values, key));
  opaqueRecord(requiredData(record, 'raw'));
  parseStringArray(requiredData(record, 'unknownFieldPaths'), MAX_SOURCE_DIAGNOSTICS);
}

function parseFolderRelationships(value: unknown): void {
  const relationships = denseArray(value, MAX_RELATIONSHIPS);
  for (const relationship of relationships) {
    const record = exactRecord(relationship, FOLDER_RELATIONSHIP_KEYS, FOLDER_RELATIONSHIP_KEYS.size);
    boundedInteger(requiredData(record, 'itemSourceIndex'), 0, MAX_SOURCE_INDEX);
    boundedString(requiredData(record, 'sourceFolderId'));
    const folderIndex = optionalData(record, 'folderSourceIndex');
    if (folderIndex.present) boundedInteger(folderIndex.value, 0, MAX_SOURCE_INDEX);
  }
}

function parseCollectionRelationships(value: unknown): void {
  const relationships = denseArray(value, MAX_RELATIONSHIPS);
  for (const relationship of relationships) {
    const record = exactRecord(relationship, COLLECTION_RELATIONSHIP_KEYS, COLLECTION_RELATIONSHIP_KEYS.size);
    boundedInteger(requiredData(record, 'itemSourceIndex'), 0, MAX_SOURCE_INDEX);
    boundedString(requiredData(record, 'sourceCollectionId'));
    const collectionIndex = optionalData(record, 'collectionSourceIndex');
    if (collectionIndex.present) boundedInteger(collectionIndex.value, 0, MAX_SOURCE_INDEX);
  }
}

function addInspectionDiagnostic(collector: DiagnosticCollector, diagnostic: ParsedDiagnostic): void {
  const code = SAFE_CODE_SET.has(diagnostic.code)
    ? diagnostic.code as VaultTransferPreviewDiagnosticCode
    : (diagnostic.severity === 'info' ? 'transfer_notice' : 'transfer_diagnostic');
  const category: VaultTransferPreviewDiagnosticCategory = UNSUPPORTED_CODE_SET.has(code)
    ? 'unsupported'
    : (diagnostic.severity === 'error' ? 'error' : 'warning');
  collector.add(category, code, diagnostic.sourceIndex);
}

function addCapabilityDiagnostics(
  collector: DiagnosticCollector,
  inspection: ParsedInspection,
  policy: ParsedPolicy,
): void {
  if (inspection.unknownFieldCount > 0) collector.addUnique('unsupported', 'unknown_fields');
  if (inspection.folders > 0 && !policy.folders) collector.add('unsupported', 'folders_unsupported');
  for (const item of inspection.items) {
    if (!isPersonalImportPreviewItem(item) || !policy.supportedItemTypes.has(item.rawType)) {
      collector.add('unsupported', 'item_type_unsupported', item.sourceIndex);
      continue;
    }
    if (item.organizationOwned) collector.addUnique('error', 'organization_target_required', item.sourceIndex);
    if (item.customFieldCount > 0 && !policy.customFields) {
      collector.add('unsupported', 'custom_fields_unsupported', item.sourceIndex);
    }
    if (item.kind === 'sshKey' && item.hasLinkedCustomField) {
      collector.add('unsupported', 'ssh_linked_fields_unsupported', item.sourceIndex);
    }
    if (item.reprompt !== 0 && !policy.reprompt) {
      collector.add('unsupported', 'reprompt_unsupported', item.sourceIndex);
    }
    if (item.passwordHistoryCount > MAX_PERSONAL_IMPORT_PASSWORD_HISTORY) {
      collector.add('unsupported', 'password_history_limit_exceeded', item.sourceIndex);
    } else if (item.passwordHistoryCount > 0 && !policy.passwordHistory) {
      collector.add('unsupported', 'password_history_unsupported', item.sourceIndex);
    }
    if (item.hasDeletedDate || (item.hasArchivedDate && !policy.itemDates)) {
      collector.add('unsupported', 'item_dates_unsupported', item.sourceIndex);
    }
    if (item.kind === 'login') {
      if (item.passkeyCount > 0
        && (!policy.passkeys || item.hasMissingPasskeyCreationDate)) {
        collector.add('unsupported', 'passkeys_unsupported', item.sourceIndex);
      }
      if (item.hasUriMatch && !policy.loginUriMatch) {
        collector.add('unsupported', 'uri_match_unsupported', item.sourceIndex);
      }
      if (item.hasAutofillOnPageLoad && !policy.autofillOnPageLoad) {
        collector.add('unsupported', 'autofill_on_page_load_unsupported', item.sourceIndex);
      }
    }
    if (item.kind === 'secureNote' && item.secureNoteType !== 0 && !policy.nonGenericSecureNotes) {
      collector.add('unsupported', 'secure_note_type_unsupported', item.sourceIndex);
    }
  }
}

function isPersonalImportPreviewItem(item: ParsedItemCapabilities): boolean {
  switch (item.rawType) {
    case 1: return item.kind === 'login';
    case 2: return item.kind === 'secureNote';
    case 3: return item.kind === 'card';
    case 4: return item.kind === 'identity';
    case 5: return item.kind === 'sshKey';
    default: return false;
  }
}

function parsePreviewFormat(value: unknown): VaultTransferPreviewFormat {
  if (value === 'bitwarden-json' || value === 'bitwarden-csv' || value === 'bitwarden-zip') return value;
  throw new PreviewParseError('invalid');
}

function parseTransferFormat(value: unknown): VaultTransferFormat {
  if (value === 'bitwarden-json' || value === 'bitwarden-csv') return value;
  throw new PreviewParseError('invalid');
}

function parseScope(value: unknown): VaultTransferScope {
  if (value === 'personal' || value === 'organization') return value;
  throw new PreviewParseError('invalid');
}

function exactRecord(value: unknown, allowedKeys: ReadonlySet<string>, maxKeys: number): Record<string, unknown> {
  const record = dataRecord(value, maxKeys);
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== 'string' || !allowedKeys.has(key)) throw new PreviewParseError('invalid');
  }
  return record;
}

function opaqueRecord(value: unknown): Record<string, unknown> {
  return dataRecord(value, MAX_RECORD_KEYS);
}

function dataRecord(value: unknown, maxKeys: number): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new PreviewParseError('invalid');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new PreviewParseError('invalid');
  const keys = Reflect.ownKeys(value);
  if (keys.length > maxKeys) throw new PreviewParseError('resource');
  for (const key of keys) {
    if (typeof key !== 'string') throw new PreviewParseError('invalid');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      throw new PreviewParseError('invalid');
    }
  }
  return value as Record<string, unknown>;
}

function denseArray(value: unknown, maximum: number, countAsOmittedDiagnostics = false): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new PreviewParseError('invalid');
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  if (!lengthDescriptor || !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value')) {
    throw new PreviewParseError('invalid');
  }
  const length = lengthDescriptor.value;
  if (!Number.isSafeInteger(length) || length < 0) throw new PreviewParseError('invalid');
  if (length > maximum) {
    throw new PreviewParseError('resource', countAsOmittedDiagnostics ? length : 0);
  }
  const output: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      throw new PreviewParseError('invalid');
    }
    output.push(descriptor.value);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1) throw new PreviewParseError('invalid');
  return output;
}

function parseStringArray(value: unknown, maximum: number): string[] {
  return denseArray(value, maximum).map((entry) => boundedString(entry));
}

function requiredData(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
    throw new PreviewParseError('invalid');
  }
  return descriptor.value;
}

function optionalData(
  record: Record<string, unknown>,
  key: string,
): { present: false; value?: never } | { present: true; value: unknown } {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor) return { present: false };
  if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) throw new PreviewParseError('invalid');
  return { present: true, value: descriptor.value };
}

function parseOptionalNullableString(
  record: Record<string, unknown>,
  key: string,
): { present: boolean; value: string | null | undefined } {
  const property = optionalData(record, key);
  if (!property.present) return { present: false, value: undefined };
  if (property.value === null) return { present: true, value: null };
  return { present: true, value: boundedString(property.value) };
}

function parseOptionalNullableIsoTimestamp(
  record: Record<string, unknown>,
  key: string,
): { present: boolean; value: string | null | undefined } {
  const parsed = parseOptionalNullableString(record, key);
  if (parsed.value !== undefined && parsed.value !== null && !isIsoTimestamp(parsed.value)) {
    throw new PreviewParseError('invalid');
  }
  return parsed;
}

function parseOptionalNullableUtcTimestamp(
  record: Record<string, unknown>,
  key: string,
): { present: boolean; value: string | null | undefined } {
  const parsed = parseOptionalNullableIsoTimestamp(record, key);
  if (typeof parsed.value === 'string' && !parsed.value.endsWith('Z')) {
    throw new PreviewParseError('invalid');
  }
  return parsed;
}

function parseOptionalNullableBoolean(
  record: Record<string, unknown>,
  key: string,
): { present: boolean; value: boolean | null | undefined } {
  const property = optionalData(record, key);
  if (!property.present) return { present: false, value: undefined };
  if (property.value === null) return { present: true, value: null };
  return { present: true, value: strictBoolean(property.value) };
}

function boundedString(value: unknown, maximum = MAX_STRING_CHARS): string {
  if (typeof value !== 'string' || value.length > maximum) throw new PreviewParseError('invalid');
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new PreviewParseError('invalid');
  }
  return value as number;
}

function strictBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new PreviewParseError('invalid');
  return value;
}
