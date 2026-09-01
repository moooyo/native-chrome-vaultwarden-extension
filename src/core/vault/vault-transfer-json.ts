import type {
  VaultTransferCollection,
  VaultTransferFolder,
  VaultTransferIR,
  VaultTransferItem,
  VaultTransferLoginPayload,
  VaultTransferPasskey,
  VaultTransferStringPayload,
} from './vault-transfer.js';
import { isOptionalNullableIsoTimestamp } from './iso-date.js';

export type VaultTransferJsonDiagnosticSeverity = 'warning' | 'error';

export interface VaultTransferJsonDiagnostic {
  severity: VaultTransferJsonDiagnosticSeverity;
  code: string;
  message: string;
  path?: string;
  sourceIndex?: number;
}

export type VaultTransferOrganizationMode =
  | { mode: 'export' }
  | { mode: 'target'; organizationId: string };

export interface EncodeVaultTransferJsonOptions {
  /** Required for organization IR. Omit for the default personal-only mode. */
  organization?: VaultTransferOrganizationMode;
  /** Pretty-print with two spaces by default. */
  pretty?: boolean;
}

export interface EncodeVaultTransferJsonResult {
  ok: boolean;
  json: string | null;
  diagnostics: VaultTransferJsonDiagnostic[];
}

type JsonObject = Record<string, unknown>;

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
const ITEM_DATE_FIELDS = ['creationDate', 'revisionDate', 'deletedDate', 'archivedDate'] as const;

/** Encode a validated transfer IR as canonical Bitwarden plaintext JSON without side effects. */
export function encodeVaultTransferJson(
  ir: VaultTransferIR,
  options: EncodeVaultTransferJsonOptions = {},
): EncodeVaultTransferJsonResult {
  const diagnostics: VaultTransferJsonDiagnostic[] = [];
  validateIr(ir, options, diagnostics);
  if (hasErrors(diagnostics)) return { ok: false, json: null, diagnostics };

  const document: JsonObject = { encrypted: false };
  if (ir.scope === 'personal') {
    document.folders = stableBySourceIndex(ir.folders).map(encodeFolder);
  } else {
    document.collections = stableBySourceIndex(ir.collections).map((collection) =>
      encodeCollection(collection, options.organization));
  }
  document.items = stableBySourceIndex(ir.items).map((item) => encodeItem(item, options.organization));

  try {
    return {
      ok: true,
      json: JSON.stringify(document, null, options.pretty === false ? undefined : 2),
      diagnostics,
    };
  } catch {
    diagnostics.push({
      severity: 'error',
      code: 'serialization_failed',
      message: 'The transfer could not be serialized as JSON.',
      path: '$',
    });
    return { ok: false, json: null, diagnostics };
  }
}

function validateIr(
  ir: VaultTransferIR,
  options: EncodeVaultTransferJsonOptions,
  diagnostics: VaultTransferJsonDiagnostic[],
): void {
  if (ir.version !== 1) addError(diagnostics, 'unsupported_ir_version', 'Transfer IR version is not supported.', '$.version');

  if (ir.scope === 'personal') {
    if (options.organization) {
      addError(diagnostics, 'organization_mode_on_personal', 'Organization mode cannot encode a personal transfer.', '$.scope');
    }
    if (ir.collections.length > 0 || ir.collectionRelationships.length > 0) {
      addError(diagnostics, 'personal_contains_collections', 'Personal transfers cannot contain collections.', '$.collections');
    }
  } else {
    if (!options.organization) {
      addError(
        diagnostics,
        'organization_mode_required',
        'Organization JSON requires an explicit export or target mode.',
        '$.scope',
      );
    } else if (options.organization.mode === 'target' && !validOrganizationId(options.organization.organizationId)) {
      addError(diagnostics, 'invalid_organization_target', 'Organization target id must be a bounded non-empty string.', '$.scope');
    }
    if (ir.folders.length > 0 || ir.folderRelationships.length > 0) {
      addError(diagnostics, 'organization_contains_folders', 'Organization transfers cannot contain personal folders.', '$.folders');
    }
  }

  const unknownPaths = collectUnknownPaths(ir);
  for (const path of unknownPaths) {
    addError(diagnostics, 'unknown_field', 'Unknown transfer fields cannot be represented without loss.', path);
  }

  validateUniqueSources(ir.folders, '$.folders', diagnostics);
  validateUniqueSources(ir.collections, '$.collections', diagnostics);
  validateUniqueSources(ir.items, '$.items', diagnostics);
  validateUniqueIds(ir.folders, '$.folders', diagnostics);
  validateUniqueIds(ir.collections, '$.collections', diagnostics);

  for (const folder of ir.folders) {
    if (!folder.name) addError(diagnostics, 'unrepresentable_known_data', 'Folder names must be non-empty strings.', `$.folders[${folder.sourceIndex}].name`, folder.sourceIndex);
  }
  for (const collection of ir.collections) {
    if (!collection.name) addError(diagnostics, 'unrepresentable_known_data', 'Collection names must be non-empty strings.', `$.collections[${collection.sourceIndex}].name`, collection.sourceIndex);
  }
  for (const item of ir.items) validateItem(item, ir.scope, ir.format, diagnostics);
  validateFolderRelationships(ir, diagnostics);
  validateCollectionRelationships(ir, diagnostics);
}

function validateItem(
  item: VaultTransferItem,
  scope: VaultTransferIR['scope'],
  format: VaultTransferIR['format'],
  diagnostics: VaultTransferJsonDiagnostic[],
): void {
  const path = `$.items[${item.sourceIndex}]`;
  if (item.kind === 'unsupported' || !kindMatchesType(item)) {
    addError(diagnostics, 'unsupported_item', 'Unsupported or mismatched item data cannot be encoded.', `${path}.type`, item.sourceIndex);
  }
  if (item.raw.attachments != null) {
    addError(diagnostics, 'attachments_require_archive', 'Attachments require a ZIP archive and cannot be embedded in Bitwarden JSON.', `${path}.attachments`, item.sourceIndex);
  }
  if (item.raw.key != null) {
    addError(diagnostics, 'encrypted_item_key_unsupported', 'Encrypted per-item keys cannot be emitted in plaintext JSON.', `${path}.key`, item.sourceIndex);
  }
  if (scope === 'personal' && (item.organizationId != null || item.collectionIds.length > 0)) {
    addError(diagnostics, 'organization_data_in_personal', 'Organization ownership cannot be encoded in personal mode.', path, item.sourceIndex);
  }
  if (scope === 'organization' && item.folderId != null) {
    addError(diagnostics, 'folder_data_in_organization', 'Personal folder ownership cannot be encoded in organization mode.', `${path}.folderId`, item.sourceIndex);
  }
  if (!item.name) {
    addError(diagnostics, 'unrepresentable_known_data', 'Item names must be non-empty strings.', `${path}.name`, item.sourceIndex);
  }
  if (format === 'bitwarden-json') validateJsonRawItemShape(item, diagnostics);
}

function validateJsonRawItemShape(item: VaultTransferItem, diagnostics: VaultTransferJsonDiagnostic[]): void {
  const path = `$.items[${item.sourceIndex}]`;
  const invalid = (condition: boolean, fieldPath: string): void => {
    if (condition) addError(diagnostics, 'unrepresentable_known_data', 'Known transfer data has a shape that cannot be represented safely.', fieldPath, item.sourceIndex);
  };
  for (const field of ['id', 'organizationId', 'folderId', 'notes'] as const) {
    invalid(!isOptionalString(item.raw[field]), `${path}.${field}`);
  }
  for (const field of ITEM_DATE_FIELDS) {
    const value = item.raw[field];
    invalid(!isOptionalDateString(value), `${path}.${field}`);
  }
  invalid(typeof item.raw.type !== 'number' || !Number.isInteger(item.raw.type), `${path}.type`);
  invalid(typeof item.raw.name !== 'string' || item.raw.name.length === 0, `${path}.name`);
  invalid(item.raw.favorite != null && typeof item.raw.favorite !== 'boolean', `${path}.favorite`);
  invalid(item.raw.reprompt != null && item.raw.reprompt !== 0 && item.raw.reprompt !== 1, `${path}.reprompt`);
  invalid(!isOptionalStringArray(item.raw.collectionIds), `${path}.collectionIds`);
  invalid(item.raw.fields != null && !Array.isArray(item.raw.fields), `${path}.fields`);
  invalid(item.raw.passwordHistory != null && !Array.isArray(item.raw.passwordHistory), `${path}.passwordHistory`);

  for (const field of item.fields) {
    invalid(!isRecord(field.raw), `${path}.fields[${field.sourceIndex}]`);
    invalid(field.raw.type !== 0 && field.raw.type !== 1 && field.raw.type !== 2 && field.raw.type !== 3, `${path}.fields[${field.sourceIndex}].type`);
    invalid(!isOptionalString(field.raw.name), `${path}.fields[${field.sourceIndex}].name`);
    invalid(!isOptionalString(field.raw.value), `${path}.fields[${field.sourceIndex}].value`);
    invalid(field.raw.linkedId != null && (typeof field.raw.linkedId !== 'number' || !Number.isInteger(field.raw.linkedId)), `${path}.fields[${field.sourceIndex}].linkedId`);
  }
  for (const entry of item.passwordHistory) {
    invalid(typeof entry.raw.password !== 'string' || entry.raw.password.length === 0, `${path}.passwordHistory[${entry.sourceIndex}].password`);
    invalid(!isOptionalDateString(entry.raw.lastUsedDate), `${path}.passwordHistory[${entry.sourceIndex}].lastUsedDate`);
  }

  switch (item.kind) {
    case 'login':
      invalid(!isRecord(item.raw.login), `${path}.login`);
      validateRawLogin(item.payload, path, item.sourceIndex, diagnostics);
      break;
    case 'secureNote':
      invalid(!isRecord(item.raw.secureNote), `${path}.secureNote`);
      invalid(typeof item.payload.raw.type !== 'number' || !Number.isInteger(item.payload.raw.type), `${path}.secureNote.type`);
      break;
    case 'card':
      invalid(!isRecord(item.raw.card), `${path}.card`);
      validateRawStringPayload(item.payload, CARD_FIELDS, `${path}.card`, item.sourceIndex, diagnostics);
      break;
    case 'identity':
      invalid(!isRecord(item.raw.identity), `${path}.identity`);
      validateRawStringPayload(item.payload, IDENTITY_FIELDS, `${path}.identity`, item.sourceIndex, diagnostics);
      break;
    case 'sshKey':
      invalid(!isRecord(item.raw.sshKey), `${path}.sshKey`);
      validateRawStringPayload(item.payload, SSH_KEY_FIELDS, `${path}.sshKey`, item.sourceIndex, diagnostics);
      break;
    case 'bankAccount':
      invalid(!isRecord(item.raw.bankAccount), `${path}.bankAccount`);
      validateRawStringPayload(item.payload, BANK_ACCOUNT_FIELDS, `${path}.bankAccount`, item.sourceIndex, diagnostics);
      break;
    case 'driversLicense':
      invalid(!isRecord(item.raw.driversLicense), `${path}.driversLicense`);
      validateRawStringPayload(item.payload, DRIVERS_LICENSE_FIELDS, `${path}.driversLicense`, item.sourceIndex, diagnostics);
      break;
    case 'passport':
      invalid(!isRecord(item.raw.passport), `${path}.passport`);
      validateRawStringPayload(item.payload, PASSPORT_FIELDS, `${path}.passport`, item.sourceIndex, diagnostics);
      break;
    case 'unsupported':
      break;
  }
}

function validateRawLogin(
  login: VaultTransferLoginPayload,
  itemPath: string,
  sourceIndex: number,
  diagnostics: VaultTransferJsonDiagnostic[],
): void {
  const path = `${itemPath}.login`;
  for (const field of ['username', 'password', 'totp'] as const) {
    if (!isOptionalString(login.raw[field])) addError(diagnostics, 'unrepresentable_known_data', 'Login data cannot be represented safely.', `${path}.${field}`, sourceIndex);
  }
  if (!isOptionalNullableBoolean(login.raw.autofillOnPageLoad)) {
    addError(diagnostics, 'unrepresentable_known_data', 'Login autofill data cannot be represented safely.', `${path}.autofillOnPageLoad`, sourceIndex);
  }
  if (!isOptionalNullableIsoTimestamp(login.raw.passwordRevisionDate)) {
    addError(diagnostics, 'unrepresentable_known_data', 'Login password revision data cannot be represented safely.', `${path}.passwordRevisionDate`, sourceIndex);
  }
  if (login.raw.uris != null && !Array.isArray(login.raw.uris)) {
    addError(diagnostics, 'unrepresentable_known_data', 'Login URI data cannot be represented safely.', `${path}.uris`, sourceIndex);
  }
  if (login.raw.fido2Credentials != null && !Array.isArray(login.raw.fido2Credentials)) {
    addError(diagnostics, 'unrepresentable_known_data', 'Passkey data cannot be represented safely.', `${path}.fido2Credentials`, sourceIndex);
  }
  for (const uri of login.uris) {
    if (typeof uri.raw.uri !== 'string' || uri.raw.uri.length === 0
      || (uri.raw.match != null && (typeof uri.raw.match !== 'number' || !Number.isInteger(uri.raw.match)))) {
      addError(diagnostics, 'unrepresentable_known_data', 'Login URI data cannot be represented safely.', `${path}.uris[${uri.sourceIndex}]`, sourceIndex);
    }
  }
  for (const passkey of login.fido2Credentials) {
    for (const field of ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable'] as const) {
      if (typeof passkey.raw[field] !== 'string' || passkey.raw[field].length === 0) {
        addError(diagnostics, 'unrepresentable_known_data', 'Passkey data cannot be represented safely.', `${path}.fido2Credentials[${passkey.sourceIndex}].${field}`, sourceIndex);
      }
    }
    for (const field of ['userHandle', 'userName', 'rpName', 'userDisplayName'] as const) {
      if (!isOptionalString(passkey.raw[field])) {
        addError(diagnostics, 'unrepresentable_known_data', 'Passkey data cannot be represented safely.', `${path}.fido2Credentials[${passkey.sourceIndex}].${field}`, sourceIndex);
      }
    }
    if (!isOptionalDateString(passkey.raw.creationDate)) {
      addError(diagnostics, 'unrepresentable_known_data', 'Passkey date data cannot be represented safely.', `${path}.fido2Credentials[${passkey.sourceIndex}].creationDate`, sourceIndex);
    }
  }
}

function validateRawStringPayload(
  payload: VaultTransferStringPayload,
  fields: readonly string[],
  path: string,
  sourceIndex: number,
  diagnostics: VaultTransferJsonDiagnostic[],
): void {
  for (const field of fields) {
    if (!isOptionalString(payload.raw[field])) {
      addError(diagnostics, 'unrepresentable_known_data', 'Item payload cannot be represented safely.', `${path}.${field}`, sourceIndex);
    }
  }
}

function validateFolderRelationships(ir: VaultTransferIR, diagnostics: VaultTransferJsonDiagnostic[]): void {
  const itemBySource = new Map(ir.items.map((item) => [item.sourceIndex, item]));
  const folderById = new Map(ir.folders.map((folder) => [folder.id, folder]));
  const relationKeys = new Set<string>();
  for (const [relationIndex, relation] of ir.folderRelationships.entries()) {
    const path = `$.folderRelationships[${relationIndex}]`;
    const item = itemBySource.get(relation.itemSourceIndex);
    const folder = folderById.get(relation.sourceFolderId);
    const key = `${relation.itemSourceIndex}\u0000${relation.sourceFolderId}`;
    if (relationKeys.has(key)) addError(diagnostics, 'duplicate_folder_relationship', 'Folder relationships must be unique.', path);
    relationKeys.add(key);
    if (!item || item.folderId !== relation.sourceFolderId || !folder
      || relation.folderSourceIndex === undefined || relation.folderSourceIndex !== folder.sourceIndex) {
      addError(diagnostics, 'unresolved_folder_relationship', 'A folder relationship cannot be resolved exactly.', path, relation.itemSourceIndex);
    }
  }
  for (const item of ir.items) {
    if (!item.folderId) continue;
    const key = `${item.sourceIndex}\u0000${item.folderId}`;
    if (!relationKeys.has(key)) {
      addError(
        diagnostics,
        'unresolved_folder_relationship',
        'An item folder reference has no resolved relationship.',
        `$.items[${item.sourceIndex}].folderId`,
        item.sourceIndex,
      );
    }
  }
}

function validateCollectionRelationships(ir: VaultTransferIR, diagnostics: VaultTransferJsonDiagnostic[]): void {
  const itemBySource = new Map(ir.items.map((item) => [item.sourceIndex, item]));
  const collectionById = new Map(ir.collections.map((collection) => [collection.id, collection]));
  const relationKeys = new Set<string>();
  for (const [relationIndex, relation] of ir.collectionRelationships.entries()) {
    const path = `$.collectionRelationships[${relationIndex}]`;
    const item = itemBySource.get(relation.itemSourceIndex);
    const collection = collectionById.get(relation.sourceCollectionId);
    const key = `${relation.itemSourceIndex}\u0000${relation.sourceCollectionId}`;
    if (relationKeys.has(key)) addError(diagnostics, 'duplicate_collection_relationship', 'Collection relationships must be unique.', path);
    relationKeys.add(key);
    if (!item || !item.collectionIds.includes(relation.sourceCollectionId) || !collection
      || relation.collectionSourceIndex === undefined || relation.collectionSourceIndex !== collection.sourceIndex) {
      addError(diagnostics, 'unresolved_collection_relationship', 'A collection relationship cannot be resolved exactly.', path, relation.itemSourceIndex);
    }
  }
  for (const item of ir.items) {
    for (const collectionId of item.collectionIds) {
      const key = `${item.sourceIndex}\u0000${collectionId}`;
      if (!relationKeys.has(key)) {
        addError(
          diagnostics,
          'unresolved_collection_relationship',
          'An item collection reference has no resolved relationship.',
          `$.items[${item.sourceIndex}].collectionIds`,
          item.sourceIndex,
        );
      }
    }
  }
}

function encodeFolder(folder: VaultTransferFolder): JsonObject {
  return { id: folder.id, name: folder.name };
}

function encodeCollection(
  collection: VaultTransferCollection,
  organization: VaultTransferOrganizationMode | undefined,
): JsonObject {
  const output: JsonObject = { id: collection.id, name: collection.name };
  if (organization?.mode === 'target') output.organizationId = organization.organizationId;
  else putOptional(output, 'organizationId', collection, collection.organizationId);
  putOptional(output, 'externalId', collection, collection.externalId);
  return output;
}

function encodeItem(
  item: VaultTransferItem,
  organization: VaultTransferOrganizationMode | undefined,
): JsonObject {
  const output: JsonObject = {};
  putOptional(output, 'id', item, item.id);
  if (organization?.mode === 'target') output.organizationId = organization.organizationId;
  else putOptional(output, 'organizationId', item, item.organizationId);
  putOptional(output, 'folderId', item, item.folderId);
  output.type = item.rawType;
  output.reprompt = item.reprompt;
  output.name = item.name;
  putOptional(output, 'notes', item, item.notes);
  output.favorite = item.favorite;

  encodeCollectionIds(item, output);
  encodeCustomFields(item, output);
  encodePayload(item, output);
  encodePasswordHistory(item, output);
  for (const field of ITEM_DATE_FIELDS) putOptional(output, field, item, item[field]);
  return output;
}

function encodeCollectionIds(item: VaultTransferItem, output: JsonObject): void {
  if (item.raw.collectionIds === null) {
    output.collectionIds = null;
  } else if (item.collectionIds.length > 0 || hasOwn(item.raw, 'collectionIds')) {
    output.collectionIds = [...item.collectionIds];
  }
}

function encodeCustomFields(item: VaultTransferItem, output: JsonObject): void {
  if (item.raw.fields === null) {
    output.fields = null;
    return;
  }
  if (item.fields.length === 0 && !hasOwn(item.raw, 'fields')) return;
  output.fields = stableBySourceIndex(item.fields).map((field) => {
    const encoded: JsonObject = { type: field.type };
    putOptional(encoded, 'name', field, field.name);
    putOptional(encoded, 'value', field, field.value);
    putOptional(encoded, 'linkedId', field, field.linkedId);
    return encoded;
  });
}

function encodePasswordHistory(item: VaultTransferItem, output: JsonObject): void {
  if (item.raw.passwordHistory === null) {
    output.passwordHistory = null;
    return;
  }
  if (item.passwordHistory.length === 0 && !hasOwn(item.raw, 'passwordHistory')) return;
  output.passwordHistory = stableBySourceIndex(item.passwordHistory).map((entry) => {
    const encoded: JsonObject = { password: entry.password };
    putOptional(encoded, 'lastUsedDate', entry, entry.lastUsedDate);
    return encoded;
  });
}

function encodePayload(item: VaultTransferItem, output: JsonObject): void {
  switch (item.kind) {
    case 'login':
      output.login = encodeLogin(item.payload);
      break;
    case 'secureNote':
      output.secureNote = { type: item.payload.type };
      break;
    case 'card':
      output.card = encodeStringPayload(item.payload, CARD_FIELDS);
      break;
    case 'identity':
      output.identity = encodeStringPayload(item.payload, IDENTITY_FIELDS);
      break;
    case 'sshKey':
      output.sshKey = encodeStringPayload(item.payload, SSH_KEY_FIELDS);
      break;
    case 'bankAccount':
      output.bankAccount = encodeStringPayload(item.payload, BANK_ACCOUNT_FIELDS);
      break;
    case 'driversLicense':
      output.driversLicense = encodeStringPayload(item.payload, DRIVERS_LICENSE_FIELDS);
      break;
    case 'passport':
      output.passport = encodeStringPayload(item.payload, PASSPORT_FIELDS);
      break;
    case 'unsupported':
      break;
  }
}

function encodeLogin(login: VaultTransferLoginPayload): JsonObject {
  const output: JsonObject = {};
  putOptional(output, 'username', login, login.username);
  putOptional(output, 'password', login, login.password);
  putOptional(output, 'totp', login, login.totp);
  putOptional(output, 'autofillOnPageLoad', login, login.autofillOnPageLoad);
  putOptional(output, 'passwordRevisionDate', login, login.passwordRevisionDate);

  if (login.raw.uris === null) output.uris = null;
  else if (login.uris.length > 0 || hasOwn(login.raw, 'uris')) {
    output.uris = stableBySourceIndex(login.uris).map((uri) => {
      const encoded: JsonObject = {};
      putOptional(encoded, 'match', uri, uri.match);
      encoded.uri = uri.uri;
      return encoded;
    });
  }

  if (login.raw.fido2Credentials === null) output.fido2Credentials = null;
  else if (login.fido2Credentials.length > 0 || hasOwn(login.raw, 'fido2Credentials')) {
    output.fido2Credentials = stableBySourceIndex(login.fido2Credentials).map(encodePasskey);
  }
  return output;
}

function encodePasskey(passkey: VaultTransferPasskey): JsonObject {
  const output: JsonObject = {
    credentialId: passkey.credentialId,
    keyType: passkey.keyType,
    keyAlgorithm: passkey.keyAlgorithm,
    keyCurve: passkey.keyCurve,
    keyValue: passkey.keyValue,
    rpId: passkey.rpId,
    counter: passkey.counter,
    discoverable: passkey.discoverable,
  };
  putOptional(output, 'userHandle', passkey, passkey.userHandle);
  putOptional(output, 'userName', passkey, passkey.userName);
  putOptional(output, 'rpName', passkey, passkey.rpName);
  putOptional(output, 'userDisplayName', passkey, passkey.userDisplayName);
  putOptional(output, 'creationDate', passkey, passkey.creationDate);
  return output;
}

function encodeStringPayload(
  payload: VaultTransferStringPayload,
  fields: readonly string[],
): JsonObject {
  const output: JsonObject = {};
  for (const field of fields) {
    if (hasOwn(payload.values, field)) output[field] = payload.values[field];
  }
  return output;
}

function collectUnknownPaths(ir: VaultTransferIR): string[] {
  const paths = new Set(ir.unknownFieldPaths);
  for (const folder of ir.folders) for (const path of folder.unknownFieldPaths) paths.add(path);
  for (const collection of ir.collections) for (const path of collection.unknownFieldPaths) paths.add(path);
  for (const item of ir.items) {
    for (const path of item.unknownFieldPaths) paths.add(path);
    for (const field of item.fields) for (const path of field.unknownFieldPaths) paths.add(path);
    for (const entry of item.passwordHistory) for (const path of entry.unknownFieldPaths) paths.add(path);
    if (item.kind === 'unsupported') continue;
    for (const path of item.payload.unknownFieldPaths) paths.add(path);
    if (item.kind === 'login') {
      for (const uri of item.payload.uris) for (const path of uri.unknownFieldPaths) paths.add(path);
      for (const passkey of item.payload.fido2Credentials) {
        for (const path of passkey.unknownFieldPaths) paths.add(path);
      }
    }
  }
  return [...paths].sort();
}

function kindMatchesType(item: VaultTransferItem): boolean {
  switch (item.rawType) {
    case 1: return item.kind === 'login';
    case 2: return item.kind === 'secureNote';
    case 3: return item.kind === 'card';
    case 4: return item.kind === 'identity';
    case 5: return item.kind === 'sshKey';
    case 6: return item.kind === 'bankAccount';
    case 7: return item.kind === 'driversLicense';
    case 8: return item.kind === 'passport';
    default: return false;
  }
}

function validateUniqueSources<T extends { sourceIndex: number }>(
  values: readonly T[],
  path: string,
  diagnostics: VaultTransferJsonDiagnostic[],
): void {
  const seen = new Set<number>();
  for (const value of values) {
    if (!Number.isSafeInteger(value.sourceIndex) || value.sourceIndex < 0 || seen.has(value.sourceIndex)) {
      addError(diagnostics, 'invalid_source_index', 'Source indices must be unique non-negative integers.', path, value.sourceIndex);
    }
    seen.add(value.sourceIndex);
  }
}

function validateUniqueIds<T extends { id: string; sourceIndex: number }>(
  values: readonly T[],
  path: string,
  diagnostics: VaultTransferJsonDiagnostic[],
): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (!value.id || seen.has(value.id)) {
      addError(diagnostics, 'duplicate_or_empty_id', 'Grouping ids must be non-empty and unique.', path, value.sourceIndex);
    }
    seen.add(value.id);
  }
}

function stableBySourceIndex<T extends { sourceIndex: number }>(values: readonly T[]): T[] {
  return [...values].sort((left, right) => left.sourceIndex - right.sourceIndex);
}

function putOptional(target: JsonObject, key: string, source: object, value: unknown): void {
  if (hasOwn(source, key)) target[key] = value;
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function validOrganizationId(value: string): boolean {
  return value.length > 0 && value.length <= 4_096 && !value.includes('\0');
}

function isOptionalString(value: unknown): boolean {
  return value === undefined || value === null || typeof value === 'string';
}

function isOptionalNullableBoolean(value: unknown): boolean {
  return value === undefined || value === null || typeof value === 'boolean';
}

function isOptionalDateString(value: unknown): boolean {
  return isOptionalNullableIsoTimestamp(value);
}

function isOptionalStringArray(value: unknown): boolean {
  return value === undefined || value === null
    || (Array.isArray(value) && value.every((entry) => typeof entry === 'string' && entry.length > 0));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function addError(
  diagnostics: VaultTransferJsonDiagnostic[],
  code: string,
  message: string,
  path: string,
  sourceIndex?: number,
): void {
  diagnostics.push({
    severity: 'error',
    code,
    message,
    path,
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function hasErrors(diagnostics: readonly VaultTransferJsonDiagnostic[]): boolean {
  return diagnostics.some((diagnostic) => diagnostic.severity === 'error');
}
