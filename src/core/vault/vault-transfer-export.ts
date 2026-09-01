import type {
  CipherResponse,
  CollectionResponse,
  FolderResponse,
  SyncResponse,
} from '../api/types.js';
import {
  DEFAULT_VAULT_TRANSFER_LIMITS,
  inspectVaultTransferJson,
  type VaultTransferDiagnostic,
  type VaultTransferIR,
  type VaultTransferLimits,
} from './vault-transfer.js';
import { validateIgnoredUserDecryptionProperty } from './vault-transfer-control-plane.js';
import {
  RAW_SYNC_CIPHER_FIELDS,
  validateRawSyncCipherCompatibility,
  type RawSyncCipherCompatibilityErrorCode,
} from './vault-sync-cipher-compat.js';
import { isOptionalNullableIsoTimestamp } from './iso-date.js';

export type VaultTransferExportScope =
  | { kind: 'personal' }
  | { kind: 'organization'; organizationId: string };

export interface VaultTransferExportLimits extends Pick<
  VaultTransferLimits,
  | 'maxInputBytes'
  | 'maxItems'
  | 'maxFolders'
  | 'maxCollections'
  | 'maxFieldsPerItem'
  | 'maxUrisPerItem'
  | 'maxPasskeysPerItem'
  | 'maxPasswordHistoryPerItem'
  | 'maxCollectionIdsPerItem'
  | 'maxStringChars'
  | 'maxDiagnostics'
> {
  maxAttachmentsPerItem: number;
  maxTotalAttachments: number;
  maxTotalDeclaredAttachmentBytes: number;
}

export const DEFAULT_VAULT_TRANSFER_EXPORT_LIMITS: Readonly<VaultTransferExportLimits> = Object.freeze({
  maxInputBytes: DEFAULT_VAULT_TRANSFER_LIMITS.maxInputBytes,
  maxItems: DEFAULT_VAULT_TRANSFER_LIMITS.maxItems,
  maxFolders: DEFAULT_VAULT_TRANSFER_LIMITS.maxFolders,
  maxCollections: DEFAULT_VAULT_TRANSFER_LIMITS.maxCollections,
  maxFieldsPerItem: DEFAULT_VAULT_TRANSFER_LIMITS.maxFieldsPerItem,
  maxUrisPerItem: DEFAULT_VAULT_TRANSFER_LIMITS.maxUrisPerItem,
  maxPasskeysPerItem: DEFAULT_VAULT_TRANSFER_LIMITS.maxPasskeysPerItem,
  maxPasswordHistoryPerItem: DEFAULT_VAULT_TRANSFER_LIMITS.maxPasswordHistoryPerItem,
  maxCollectionIdsPerItem: DEFAULT_VAULT_TRANSFER_LIMITS.maxCollectionIdsPerItem,
  maxStringChars: DEFAULT_VAULT_TRANSFER_LIMITS.maxStringChars,
  maxDiagnostics: DEFAULT_VAULT_TRANSFER_LIMITS.maxDiagnostics,
  maxAttachmentsPerItem: 100,
  maxTotalAttachments: 5_000,
  maxTotalDeclaredAttachmentBytes: 256 * 1024 * 1024,
});

export interface VaultTransferExportOptions {
  scope: VaultTransferExportScope;
  limits?: Partial<VaultTransferExportLimits>;
}

export type VaultTransferDecryptFailureCode =
  | 'undecryptable'
  | 'missing_organization_key'
  | 'unsupported_encryption';

export type VaultTransferDecryptResult<T> =
  | { status: 'decrypted'; value: T }
  | { status: 'failed'; code: VaultTransferDecryptFailureCode };

export interface VaultTransferExportField {
  type: 0 | 1 | 2 | 3;
  name?: string | null;
  value?: string | null;
  linkedId?: number | null;
}

export interface VaultTransferExportPasswordHistory {
  password: string;
  lastUsedDate?: string | null;
}

export interface VaultTransferExportLoginUri {
  uri: string;
  match?: number | null;
}

export interface VaultTransferExportPasskey {
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
}

export interface VaultTransferExportLogin {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  autofillOnPageLoad?: boolean | null;
  passwordRevisionDate?: string | null;
  uris?: VaultTransferExportLoginUri[] | null;
  fido2Credentials?: VaultTransferExportPasskey[] | null;
}

export interface VaultTransferExportAttachmentMetadata {
  id: string;
  fileName: string;
  size?: string | null;
  sizeName?: string | null;
}

export interface VaultTransferExportCipher {
  type: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
  name: string;
  notes?: string | null;
  fields?: VaultTransferExportField[] | null;
  passwordHistory?: VaultTransferExportPasswordHistory[] | null;
  login?: VaultTransferExportLogin | null;
  secureNote?: { type: number } | null;
  card?: Record<string, string | null> | null;
  identity?: Record<string, string | null> | null;
  sshKey?: Record<string, string | null> | null;
  bankAccount?: Record<string, string | null> | null;
  driversLicense?: Record<string, string | null> | null;
  passport?: Record<string, string | null> | null;
  attachments?: VaultTransferExportAttachmentMetadata[] | null;
}

export interface VaultTransferExportDecryptors {
  decryptFolder(folder: FolderResponse, sourceIndex: number): Promise<VaultTransferDecryptResult<{ name: string }>>;
  decryptCollection(collection: CollectionResponse, sourceIndex: number): Promise<VaultTransferDecryptResult<{ name: string }>>;
  /** Must return every plaintext field needed by export; the builder performs no cryptography. */
  decryptCipher(cipher: CipherResponse, sourceIndex: number): Promise<VaultTransferDecryptResult<VaultTransferExportCipher>>;
}

export interface VaultTransferExportAttachment {
  itemSourceIndex: number;
  sourceIndex: number;
  itemToken: string;
  attachmentId: string;
  fileName: string;
  size?: string | null;
  sizeName?: string | null;
}

export interface VaultTransferExportBuildResult {
  ok: boolean;
  ir: VaultTransferIR | null;
  attachments: VaultTransferExportAttachment[];
  diagnostics: VaultTransferDiagnostic[];
}

interface SelectedFolder {
  raw: FolderResponse;
  sourceIndex: number;
}

interface SelectedCollection {
  raw: CollectionResponse;
  sourceIndex: number;
}

interface SelectedCipher {
  raw: CipherResponse;
  sourceIndex: number;
}

interface BuildContext {
  limits: VaultTransferExportLimits;
  diagnostics: VaultTransferDiagnostic[];
  attachmentCount: number;
  declaredAttachmentBytes: number;
}

const SUPPORTED_TYPES = new Set([1, 2, 3, 4, 5]);

/** Build a complete export IR and attachment plan without downloading files or performing crypto. */
export async function buildVaultTransferExport(
  sync: SyncResponse,
  options: VaultTransferExportOptions,
  decryptors: VaultTransferExportDecryptors,
): Promise<VaultTransferExportBuildResult> {
  const context: BuildContext = {
    limits: resolveLimits(options.limits),
    diagnostics: [],
    attachmentCount: 0,
    declaredAttachmentBytes: 0,
  };
  const selection = selectScope(sync, options.scope, context);
  auditSelectedRaw(sync, options.scope, selection.folders, selection.collections, selection.ciphers, context);
  if (hasBlockingDiagnostics(context)) return failed(context);

  const folders = await decryptFolders(selection.folders, decryptors, context);
  const collections = await decryptCollections(selection.collections, decryptors, context);
  const builtCiphers = await decryptCiphers(selection.ciphers, decryptors, context);
  if (hasBlockingDiagnostics(context)) return failed(context);

  const document = options.scope.kind === 'personal'
    ? { encrypted: false, folders: folders.map((entry) => entry.value), items: builtCiphers.map((entry) => entry.value) }
    : { encrypted: false, collections: collections.map((entry) => entry.value), items: builtCiphers.map((entry) => entry.value) };
  let inspection;
  try {
    inspection = inspectVaultTransferJson(JSON.stringify(document), {
      limits: transferLimits(context.limits),
    });
  } catch {
    addError(context, 'export_inspection_failed', 'The normalized export could not be inspected.', '$');
    return failed(context);
  }

  if (inspection.ir) {
    remapSourceIndices(
      inspection.ir,
      folders.map((entry) => entry.sourceIndex),
      collections.map((entry) => entry.sourceIndex),
      builtCiphers.map((entry) => entry.sourceIndex),
    );
  }

  for (const diagnostic of inspection.diagnostics) {
    if (options.scope.kind === 'organization' && diagnostic.code === 'organization_target_required') continue;
    addDiagnostic(context, remapInspectionDiagnostic(
      diagnostic,
      folders.map((entry) => entry.sourceIndex),
      collections.map((entry) => entry.sourceIndex),
      builtCiphers.map((entry) => entry.sourceIndex),
    ));
  }
  if (!inspection.ir || hasBlockingDiagnostics(context)) return failed(context);
  rebuildRelationships(inspection.ir, context);
  if (hasBlockingDiagnostics(context)) return failed(context);
  return {
    ok: true,
    ir: inspection.ir,
    attachments: builtCiphers.flatMap((entry) => entry.attachments),
    diagnostics: context.diagnostics,
  };
}

function selectScope(
  sync: SyncResponse,
  scope: VaultTransferExportScope,
  context: BuildContext,
): { folders: SelectedFolder[]; collections: SelectedCollection[]; ciphers: SelectedCipher[] } {
  const allCiphers = sync.ciphers ?? [];
  if (scope.kind === 'personal') {
    const ciphers = allCiphers.flatMap((raw, sourceIndex) => (
      raw.organizationId == null && raw.deletedDate == null ? [{ raw, sourceIndex }] : []
    ));
    const organizationExcluded = allCiphers.filter((raw) => raw.organizationId != null).length;
    const trashedExcluded = allCiphers.filter((raw) => raw.organizationId == null && raw.deletedDate != null).length;
    if (organizationExcluded > 0) {
      addDiagnostic(context, {
        severity: 'info', code: 'organization_items_excluded',
        message: `${organizationExcluded} organization-owned item(s) are outside the personal export scope.`,
        path: '$.ciphers', sourceKind: 'root',
      });
    }
    if (trashedExcluded > 0) {
      addDiagnostic(context, {
        severity: 'info', code: 'trashed_items_excluded',
        message: `${trashedExcluded} trashed item(s) are outside the portable export scope.`,
        path: '$.ciphers', sourceKind: 'root',
      });
    }
    return {
      folders: (sync.folders ?? []).map((raw, sourceIndex) => ({ raw, sourceIndex })),
      collections: [],
      ciphers,
    };
  }

  if (!validIdentifier(scope.organizationId)) {
    addError(context, 'invalid_organization_target', 'Organization id must be a bounded non-empty string.', '$.scope');
  }
  const organizationPresent = (sync.profile.organizations ?? []).some((organization) => organization.id === scope.organizationId);
  if (!organizationPresent) {
    addError(context, 'organization_unavailable', 'The selected organization is not present in the sync profile.', '$.scope');
  }
  const ciphers = allCiphers.flatMap((raw, sourceIndex) =>
    raw.organizationId === scope.organizationId && raw.deletedDate == null ? [{ raw, sourceIndex }] : []);
  const collections = (sync.collections ?? []).flatMap((raw, sourceIndex) =>
    raw.organizationId === scope.organizationId ? [{ raw, sourceIndex }] : []);
  const excluded = allCiphers.length - ciphers.length;
  if (excluded > 0) {
    addDiagnostic(context, {
      severity: 'info', code: 'out_of_scope_items_excluded',
      message: `${excluded} item(s) are outside the selected organization export scope.`,
      path: '$.ciphers', sourceKind: 'root',
    });
  }
  const trashedExcluded = allCiphers.filter(
    (raw) => raw.organizationId === scope.organizationId && raw.deletedDate != null,
  ).length;
  if (trashedExcluded > 0) {
    addDiagnostic(context, {
      severity: 'info', code: 'trashed_items_excluded',
      message: `${trashedExcluded} trashed item(s) are outside the portable export scope.`,
      path: '$.ciphers', sourceKind: 'root',
    });
  }
  return { folders: [], collections, ciphers };
}

const SYNC_FIELDS = new Set([
  'profile', 'ciphers', 'folders', 'collections', 'policies', 'policiesNew', 'domains', 'sends',
  'settings', 'object', 'userDecryption',
]);
const FOLDER_FIELDS = new Set(['id', 'name', 'revisionDate', 'object']);
const COLLECTION_FIELDS = new Set([
  'id', 'organizationId', 'name', 'externalId', 'readOnly', 'manage', 'hidePasswords', 'object',
]);
const LOGIN_FIELDS = new Set([
  'username', 'password', 'totp', 'autofillOnPageLoad', 'uris', 'fido2Credentials',
  'passwordRevisionDate', 'uri',
]);
const URI_FIELDS = new Set(['uri', 'uriChecksum', 'match']);
const PASSKEY_FIELDS = new Set([
  'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'userHandle',
  'userName', 'counter', 'rpName', 'userDisplayName', 'discoverable', 'creationDate',
]);
const FIELD_FIELDS = new Set(['type', 'name', 'value', 'linkedId']);
const HISTORY_FIELDS = new Set(['password', 'lastUsedDate']);
const ATTACHMENT_FIELDS = new Set(['id', 'url', 'fileName', 'key', 'size', 'sizeName']);
const DECRYPTED_GROUPING_FIELDS = new Set(['name']);
const DECRYPTED_CIPHER_FIELDS = new Set([
  'type', 'name', 'notes', 'fields', 'passwordHistory', 'login', 'secureNote', 'card', 'identity',
  'sshKey', 'bankAccount', 'driversLicense', 'passport', 'attachments',
]);
const DECRYPTED_ATTACHMENT_FIELDS = new Set(['id', 'fileName', 'size', 'sizeName']);
const SECURE_NOTE_FIELDS = new Set(['type']);
const CARD_FIELDS = new Set(['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code']);
const IDENTITY_FIELDS = new Set([
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3', 'city',
  'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn', 'username',
  'passportNumber', 'licenseNumber',
]);
const SSH_FIELDS = new Set(['privateKey', 'publicKey', 'keyFingerprint']);
const BANK_FIELDS = new Set([
  'bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber',
  'pin', 'swiftCode', 'iban', 'bankContactPhone',
]);
const LICENSE_FIELDS = new Set([
  'firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry',
  'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass',
]);
const PASSPORT_FIELDS = new Set([
  'surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry',
  'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority',
  'issueDate', 'expirationDate',
]);

function auditSelectedRaw(
  sync: SyncResponse,
  scope: VaultTransferExportScope,
  folders: SelectedFolder[],
  collections: SelectedCollection[],
  ciphers: SelectedCipher[],
  context: BuildContext,
): void {
  auditUnknownFields(sync, SYNC_FIELDS, '$', context);
  const userDecryption = validateIgnoredUserDecryptionProperty(sync);
  if (!userDecryption.ok) {
    addError(
      context,
      userDecryption.code,
      'Account decryption metadata has an invalid or unsupported shape.',
      '$.userDecryption',
    );
  }
  if (folders.length > context.limits.maxFolders) {
    addLimitError(context, 'folders_limit_exceeded', '$.folders', folders.length, context.limits.maxFolders);
  }
  if (collections.length > context.limits.maxCollections) {
    addLimitError(context, 'collections_limit_exceeded', '$.collections', collections.length, context.limits.maxCollections);
  }
  if (ciphers.length > context.limits.maxItems) {
    addLimitError(context, 'items_limit_exceeded', '$.ciphers', ciphers.length, context.limits.maxItems);
  }
  const rawAttachmentCount = ciphers.reduce((count, cipher) => count + (cipher.raw.attachments?.length ?? 0), 0);
  if (rawAttachmentCount > context.limits.maxTotalAttachments) {
    addLimitError(context, 'total_attachments_limit_exceeded', '$.ciphers', rawAttachmentCount, context.limits.maxTotalAttachments);
  }
  for (const folder of folders) auditUnknownFields(folder.raw as unknown as Record<string, unknown>, FOLDER_FIELDS, `$.folders[${folder.sourceIndex}]`, context, 'folder', folder.sourceIndex);
  for (const collection of collections) auditUnknownFields(collection.raw as unknown as Record<string, unknown>, COLLECTION_FIELDS, `$.collections[${collection.sourceIndex}]`, context, 'collection', collection.sourceIndex);
  for (const cipher of ciphers) auditRawCipher(cipher, scope, context);
}

function auditRawCipher(selected: SelectedCipher, scope: VaultTransferExportScope, context: BuildContext): void {
  const { raw, sourceIndex } = selected;
  const path = `$.ciphers[${sourceIndex}]`;
  auditUnknownFields(raw, RAW_SYNC_CIPHER_FIELDS, path, context, 'item', sourceIndex);
  const compatibility = validateRawSyncCipherCompatibility(raw);
  if (!compatibility.ok) {
    const typeDescriptor = safeOwnDataDescriptor(raw, 'type');
    if (typeDescriptor && !SUPPORTED_TYPES.has(typeDescriptor.value as number)) {
      addError(
        context,
        'unknown_item_type',
        'The cipher type is not supported for export.',
        `${path}.type`,
        sourceIndex,
        'item',
      );
    }
    addError(
      context,
      compatibility.code,
      'The raw cipher is not a supported lossless server projection.',
      compatibilityPath(path, compatibility.code),
      sourceIndex,
      'item',
    );
    return;
  }
  if (!SUPPORTED_TYPES.has(raw.type)) {
    addError(context, 'unknown_item_type', 'The cipher type is not supported for export.', `${path}.type`, sourceIndex, 'item');
  }
  if (scope.kind === 'personal' && (raw.organizationId != null || (raw.collectionIds?.length ?? 0) > 0)) {
    addError(context, 'organization_data_in_personal', 'Organization data cannot enter a personal export.', path, sourceIndex, 'item');
  }
  if (scope.kind === 'organization' && raw.folderId != null) {
    addError(context, 'folder_data_in_organization', 'Organization exports cannot contain personal folder references.', `${path}.folderId`, sourceIndex, 'item');
  }
  if ((raw.fields?.length ?? 0) > context.limits.maxFieldsPerItem) {
    addLimitError(context, 'fields_limit_exceeded', `${path}.fields`, raw.fields!.length, context.limits.maxFieldsPerItem, sourceIndex);
  }
  if ((raw.passwordHistory?.length ?? 0) > context.limits.maxPasswordHistoryPerItem) {
    addLimitError(context, 'password_history_limit_exceeded', `${path}.passwordHistory`, raw.passwordHistory!.length, context.limits.maxPasswordHistoryPerItem, sourceIndex);
  }
  if ((raw.login?.uris?.length ?? 0) > context.limits.maxUrisPerItem) {
    addLimitError(context, 'uris_limit_exceeded', `${path}.login.uris`, raw.login!.uris!.length, context.limits.maxUrisPerItem, sourceIndex);
  }
  if ((raw.login?.fido2Credentials?.length ?? 0) > context.limits.maxPasskeysPerItem) {
    addLimitError(context, 'passkeys_limit_exceeded', `${path}.login.fido2Credentials`, raw.login!.fido2Credentials!.length, context.limits.maxPasskeysPerItem, sourceIndex);
  }
  if ((raw.attachments?.length ?? 0) > context.limits.maxAttachmentsPerItem) {
    addLimitError(context, 'attachments_limit_exceeded', `${path}.attachments`, raw.attachments!.length, context.limits.maxAttachmentsPerItem, sourceIndex);
  }
  auditNested(raw.login, LOGIN_FIELDS, `${path}.login`, context, sourceIndex);
  for (const [index, uri] of (raw.login?.uris ?? []).entries()) auditNested(uri, URI_FIELDS, `${path}.login.uris[${index}]`, context, sourceIndex);
  for (const [index, passkey] of (raw.login?.fido2Credentials ?? []).entries()) auditNested(passkey, PASSKEY_FIELDS, `${path}.login.fido2Credentials[${index}]`, context, sourceIndex);
  for (const [index, field] of (raw.fields ?? []).entries()) auditNested(field, FIELD_FIELDS, `${path}.fields[${index}]`, context, sourceIndex);
  for (const [index, history] of (raw.passwordHistory ?? []).entries()) auditNested(history, HISTORY_FIELDS, `${path}.passwordHistory[${index}]`, context, sourceIndex);
  for (const [index, attachment] of (raw.attachments ?? []).entries()) auditNested(attachment, ATTACHMENT_FIELDS, `${path}.attachments[${index}]`, context, sourceIndex);
  auditNested(raw.secureNote, SECURE_NOTE_FIELDS, `${path}.secureNote`, context, sourceIndex);
  auditNested(raw.card, CARD_FIELDS, `${path}.card`, context, sourceIndex);
  auditNested(raw.identity, IDENTITY_FIELDS, `${path}.identity`, context, sourceIndex);
  auditNested(raw.sshKey, SSH_FIELDS, `${path}.sshKey`, context, sourceIndex);
  auditNested(raw.bankAccount, BANK_FIELDS, `${path}.bankAccount`, context, sourceIndex);
  auditNested(raw.driversLicense, LICENSE_FIELDS, `${path}.driversLicense`, context, sourceIndex);
  auditNested(raw.passport, PASSPORT_FIELDS, `${path}.passport`, context, sourceIndex);
}

function safeOwnDataDescriptor(
  value: object,
  key: string,
): PropertyDescriptor & { value: unknown } | undefined {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && 'value' in descriptor ? descriptor as PropertyDescriptor & { value: unknown } : undefined;
  } catch {
    return undefined;
  }
}

function compatibilityPath(path: string, code: RawSyncCipherCompatibilityErrorCode): string {
  if (code === 'invalid_permissions') return `${path}.permissions`;
  if (code === 'unsupported_cipher_type') return `${path}.type`;
  if (code === 'login_uri_alias_mismatch') return `${path}.login.uri`;
  if ([
    'invalid_data_type', 'data_too_large', 'data_limit_exceeded', 'malformed_data',
    'invalid_data_root', 'duplicate_data_key', 'encrypted_data_blob', 'unknown_data_field',
    'invalid_data_shape', 'data_projection_mismatch',
  ].includes(code)) return `${path}.data`;
  return path;
}

function auditNested(
  value: unknown,
  allowed: ReadonlySet<string>,
  path: string,
  context: BuildContext,
  sourceIndex: number,
): void {
  if (value == null) return;
  if (!isRecord(value)) {
    addError(context, 'invalid_raw_shape', 'Encrypted vault data has an invalid shape.', path, sourceIndex, 'item');
    return;
  }
  auditUnknownFields(value, allowed, path, context, 'item', sourceIndex);
}

function auditUnknownFields(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
  context: BuildContext,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']> = 'root',
  sourceIndex?: number,
): void {
  for (const key of Object.keys(value)) {
    if (allowed.has(key)) continue;
    addError(
      context,
      'unknown_raw_field',
      'Raw vault data contains a field the export schema cannot preserve.',
      propertyPath(path, key),
      sourceIndex,
      sourceKind,
    );
  }
}

interface BuiltGrouping {
  sourceIndex: number;
  value: Record<string, unknown>;
}

interface BuiltCipher {
  sourceIndex: number;
  value: Record<string, unknown>;
  attachments: VaultTransferExportAttachment[];
}

async function decryptFolders(
  folders: SelectedFolder[],
  decryptors: VaultTransferExportDecryptors,
  context: BuildContext,
): Promise<BuiltGrouping[]> {
  const output: BuiltGrouping[] = [];
  for (const folder of folders) {
    const result = await safeDecrypt(() => decryptors.decryptFolder(folder.raw, folder.sourceIndex));
    if (result.status === 'failed') {
      addDecryptError(context, result.code, `$.folders[${folder.sourceIndex}]`, folder.sourceIndex, 'folder');
      continue;
    }
    auditUnknownFields(result.value, DECRYPTED_GROUPING_FIELDS, `$.folders[${folder.sourceIndex}].decrypted`, context, 'folder', folder.sourceIndex);
    if (!validIdentifier(folder.raw.id) || !validPlaintext(result.value.name, context)) {
      addError(context, 'invalid_decrypted_folder', 'Folder metadata could not be represented safely.', `$.folders[${folder.sourceIndex}]`, folder.sourceIndex, 'folder');
      continue;
    }
    output.push({ sourceIndex: folder.sourceIndex, value: { id: folder.raw.id, name: result.value.name } });
  }
  return output;
}

async function decryptCollections(
  collections: SelectedCollection[],
  decryptors: VaultTransferExportDecryptors,
  context: BuildContext,
): Promise<BuiltGrouping[]> {
  const output: BuiltGrouping[] = [];
  for (const collection of collections) {
    const result = await safeDecrypt(() => decryptors.decryptCollection(collection.raw, collection.sourceIndex));
    if (result.status === 'failed') {
      addDecryptError(context, result.code, `$.collections[${collection.sourceIndex}]`, collection.sourceIndex, 'collection');
      continue;
    }
    auditUnknownFields(result.value, DECRYPTED_GROUPING_FIELDS, `$.collections[${collection.sourceIndex}].decrypted`, context, 'collection', collection.sourceIndex);
    if (!validIdentifier(collection.raw.id) || !validPlaintext(result.value.name, context)) {
      addError(context, 'invalid_decrypted_collection', 'Collection metadata could not be represented safely.', `$.collections[${collection.sourceIndex}]`, collection.sourceIndex, 'collection');
      continue;
    }
    const value: Record<string, unknown> = {
      id: collection.raw.id,
      name: result.value.name,
      organizationId: collection.raw.organizationId,
    };
    if (hasOwn(collection.raw, 'externalId')) value.externalId = collection.raw.externalId;
    output.push({ sourceIndex: collection.sourceIndex, value });
  }
  return output;
}

async function decryptCiphers(
  ciphers: SelectedCipher[],
  decryptors: VaultTransferExportDecryptors,
  context: BuildContext,
): Promise<BuiltCipher[]> {
  const output: BuiltCipher[] = [];
  for (const selected of ciphers) {
    const { raw, sourceIndex } = selected;
    const path = `$.ciphers[${sourceIndex}]`;
    if (!validRawCipherEnvelope(raw, path, sourceIndex, context)) continue;
    const result = await safeDecrypt(() => decryptors.decryptCipher(raw, sourceIndex));
    if (result.status === 'failed') {
      addDecryptError(context, result.code, path, sourceIndex, 'item');
      continue;
    }
    auditUnknownFields(
      result.value as unknown as Record<string, unknown>,
      DECRYPTED_CIPHER_FIELDS,
      `${path}.decrypted`,
      context,
      'item',
      sourceIndex,
    );
    if (result.value.type !== raw.type || !validPlaintext(result.value.name, context)) {
      addError(context, 'decrypted_cipher_mismatch', 'Decrypted cipher metadata does not match the raw cipher.', path, sourceIndex, 'item');
      continue;
    }
    const attachments = buildAttachmentPlan(raw, result.value, sourceIndex, context);
    if (!validateDecryptedPayload(result.value, path, sourceIndex, context)) continue;
    output.push({
      sourceIndex,
      value: buildPlainCipher(raw, result.value),
      attachments,
    });
  }
  return output;
}

async function safeDecrypt<T>(operation: () => Promise<VaultTransferDecryptResult<T>>): Promise<VaultTransferDecryptResult<T>> {
  try {
    const result = await operation();
    if (result?.status === 'decrypted') return result;
    if (result?.status === 'failed'
      && (result.code === 'undecryptable' || result.code === 'missing_organization_key' || result.code === 'unsupported_encryption')) {
      return result;
    }
    return { status: 'failed', code: 'undecryptable' };
  } catch {
    return { status: 'failed', code: 'undecryptable' };
  }
}

function addDecryptError(
  context: BuildContext,
  code: VaultTransferDecryptFailureCode,
  path: string,
  sourceIndex: number,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']>,
): void {
  const message = code === 'missing_organization_key'
    ? 'The organization key required to decrypt this export object is unavailable.'
    : (code === 'unsupported_encryption'
        ? 'This export object uses an unsupported encryption format.'
        : 'This export object could not be decrypted completely.');
  addError(context, code, message, path, sourceIndex, sourceKind);
}

function validRawCipherEnvelope(
  raw: CipherResponse,
  path: string,
  sourceIndex: number,
  context: BuildContext,
): boolean {
  let valid = true;
  const reject = (condition: boolean, code: string, fieldPath: string): void => {
    if (!condition) return;
    valid = false;
    addError(context, code, 'Raw cipher metadata has an invalid shape.', fieldPath, sourceIndex, 'item');
  };
  reject(!validIdentifier(raw.id), 'invalid_cipher_id', `${path}.id`);
  reject(!Number.isInteger(raw.type) || !SUPPORTED_TYPES.has(raw.type), 'unknown_item_type', `${path}.type`);
  reject(raw.favorite !== undefined && typeof raw.favorite !== 'boolean', 'invalid_cipher_metadata', `${path}.favorite`);
  reject(raw.reprompt != null && raw.reprompt !== 0 && raw.reprompt !== 1, 'invalid_cipher_metadata', `${path}.reprompt`);
  reject(!isOptionalIdentifier(raw.organizationId), 'invalid_cipher_metadata', `${path}.organizationId`);
  reject(!isOptionalIdentifier(raw.folderId), 'invalid_cipher_metadata', `${path}.folderId`);
  reject(raw.collectionIds != null && (!Array.isArray(raw.collectionIds)
    || raw.collectionIds.length > context.limits.maxCollectionIdsPerItem
    || !raw.collectionIds.every(validIdentifier)), 'invalid_cipher_metadata', `${path}.collectionIds`);
  for (const field of ['revisionDate', 'creationDate', 'deletedDate', 'archivedDate'] as const) {
    reject(!isOptionalDate(raw[field]), 'invalid_cipher_date', `${path}.${field}`);
  }
  return valid;
}

const PAYLOAD_BY_TYPE = new Map<number, keyof VaultTransferExportCipher>([
  [1, 'login'], [2, 'secureNote'], [3, 'card'], [4, 'identity'], [5, 'sshKey'],
  [6, 'bankAccount'], [7, 'driversLicense'], [8, 'passport'],
]);
const PAYLOAD_FIELDS: ReadonlyArray<keyof VaultTransferExportCipher> = [
  'login', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount', 'driversLicense', 'passport',
];

function validateDecryptedPayload(
  cipher: VaultTransferExportCipher,
  path: string,
  sourceIndex: number,
  context: BuildContext,
): boolean {
  let valid = true;
  const expected = PAYLOAD_BY_TYPE.get(cipher.type);
  if (!expected || cipher[expected] == null) {
    addError(context, 'missing_decrypted_payload', 'The decrypted type-specific payload is missing.', path, sourceIndex, 'item');
    valid = false;
  }
  for (const field of PAYLOAD_FIELDS) {
    if (field !== expected && cipher[field] != null) {
      addError(context, 'conflicting_decrypted_payload', 'The decrypted cipher contains a payload for another item type.', `${path}.${field}`, sourceIndex, 'item');
      valid = false;
    }
  }
  if (cipher.fields && cipher.fields.length > context.limits.maxFieldsPerItem) {
    addLimitError(context, 'fields_limit_exceeded', `${path}.fields`, cipher.fields.length, context.limits.maxFieldsPerItem, sourceIndex);
    valid = false;
  }
  if (cipher.passwordHistory && cipher.passwordHistory.length > context.limits.maxPasswordHistoryPerItem) {
    addLimitError(context, 'password_history_limit_exceeded', `${path}.passwordHistory`, cipher.passwordHistory.length, context.limits.maxPasswordHistoryPerItem, sourceIndex);
    valid = false;
  }
  if (cipher.login?.uris && cipher.login.uris.length > context.limits.maxUrisPerItem) {
    addLimitError(context, 'uris_limit_exceeded', `${path}.login.uris`, cipher.login.uris.length, context.limits.maxUrisPerItem, sourceIndex);
    valid = false;
  }
  if (cipher.login?.fido2Credentials && cipher.login.fido2Credentials.length > context.limits.maxPasskeysPerItem) {
    addLimitError(context, 'passkeys_limit_exceeded', `${path}.login.fido2Credentials`, cipher.login.fido2Credentials.length, context.limits.maxPasskeysPerItem, sourceIndex);
    valid = false;
  }
  if (cipher.attachments && cipher.attachments.length > context.limits.maxAttachmentsPerItem) {
    addLimitError(context, 'attachments_limit_exceeded', `${path}.attachments`, cipher.attachments.length, context.limits.maxAttachmentsPerItem, sourceIndex);
    valid = false;
  }
  return valid;
}

function buildPlainCipher(raw: CipherResponse, decrypted: VaultTransferExportCipher): Record<string, unknown> {
  const output: Record<string, unknown> = { id: raw.id };
  copyPresent(output, raw, 'organizationId');
  copyPresent(output, raw, 'folderId');
  output.type = raw.type;
  output.reprompt = raw.reprompt ?? 0;
  output.name = decrypted.name;
  copyPresent(output, decrypted, 'notes');
  output.favorite = raw.favorite ?? false;
  copyPresent(output, raw, 'collectionIds');
  copyPresent(output, decrypted, 'fields');
  copyTypePayload(output, decrypted);
  copyPresent(output, decrypted, 'passwordHistory');
  for (const field of ['revisionDate', 'creationDate', 'deletedDate', 'archivedDate'] as const) {
    copyPresent(output, raw, field);
  }
  return output;
}

function copyTypePayload(output: Record<string, unknown>, decrypted: VaultTransferExportCipher): void {
  const field = PAYLOAD_BY_TYPE.get(decrypted.type);
  if (field) output[field] = decrypted[field];
}

function copyPresent(
  target: Record<string, unknown>,
  source: object,
  key: string,
): void {
  if (hasOwn(source, key)) target[key] = (source as Record<string, unknown>)[key];
}

function buildAttachmentPlan(
  raw: CipherResponse,
  decrypted: VaultTransferExportCipher,
  itemSourceIndex: number,
  context: BuildContext,
): VaultTransferExportAttachment[] {
  const rawAttachments = raw.attachments ?? [];
  const decryptedAttachments = decrypted.attachments ?? [];
  if (rawAttachments.length !== decryptedAttachments.length) {
    addError(
      context,
      'attachment_metadata_incomplete',
      'Every raw attachment must have complete decrypted metadata.',
      `$.ciphers[${itemSourceIndex}].attachments`,
      itemSourceIndex,
      'item',
    );
  }
  const decryptedById = new Map<string, VaultTransferExportAttachmentMetadata>();
  for (const metadata of decryptedAttachments) {
    auditUnknownFields(
      metadata as unknown as Record<string, unknown>,
      DECRYPTED_ATTACHMENT_FIELDS,
      `$.ciphers[${itemSourceIndex}].decryptedAttachments`,
      context,
      'item',
      itemSourceIndex,
    );
    if (!validIdentifier(metadata.id) || decryptedById.has(metadata.id)) {
      addError(context, 'invalid_attachment_id', 'Decrypted attachment ids must be non-empty and unique.', `$.ciphers[${itemSourceIndex}].attachments`, itemSourceIndex, 'item');
      continue;
    }
    decryptedById.set(metadata.id, metadata);
  }

  const seenRaw = new Set<string>();
  const output: VaultTransferExportAttachment[] = [];
  for (const [sourceIndex, attachment] of rawAttachments.entries()) {
    context.attachmentCount++;
    const path = `$.ciphers[${itemSourceIndex}].attachments[${sourceIndex}]`;
    if (context.attachmentCount > context.limits.maxTotalAttachments) {
      addLimitError(context, 'total_attachments_limit_exceeded', path, context.attachmentCount, context.limits.maxTotalAttachments, itemSourceIndex);
      continue;
    }
    if (!validIdentifier(attachment.id) || seenRaw.has(attachment.id)) {
      addError(context, 'invalid_attachment_id', 'Raw attachment ids must be non-empty and unique.', `${path}.id`, itemSourceIndex, 'item');
      continue;
    }
    seenRaw.add(attachment.id);
    if (typeof attachment.key !== 'string' || !attachment.key) {
      addError(context, 'attachment_unavailable', 'Attachment download metadata is incomplete.', path, itemSourceIndex, 'item');
    }
    const metadata = decryptedById.get(attachment.id);
    if (!metadata || !validPlaintext(metadata.fileName, context)) {
      addError(context, 'attachment_metadata_incomplete', 'Attachment file name could not be decrypted safely.', path, itemSourceIndex, 'item');
      continue;
    }
    const declaredSize = parseDeclaredSize(attachment.size ?? metadata.size);
    if (declaredSize === undefined && (attachment.size != null || metadata.size != null)) {
      addError(context, 'invalid_attachment_size', 'Attachment size metadata is invalid.', `${path}.size`, itemSourceIndex, 'item');
    } else if (declaredSize !== undefined) {
      context.declaredAttachmentBytes += declaredSize;
      if (context.declaredAttachmentBytes > context.limits.maxTotalDeclaredAttachmentBytes) {
        addLimitError(
          context,
          'declared_attachment_bytes_limit_exceeded',
          path,
          context.declaredAttachmentBytes,
          context.limits.maxTotalDeclaredAttachmentBytes,
          itemSourceIndex,
        );
      }
    }
    const planned: VaultTransferExportAttachment = {
      itemSourceIndex,
      sourceIndex,
      itemToken: raw.id,
      attachmentId: attachment.id,
      fileName: metadata.fileName,
    };
    if (metadata.size !== undefined) planned.size = metadata.size;
    else if (attachment.size !== undefined) planned.size = attachment.size;
    if (metadata.sizeName !== undefined) planned.sizeName = metadata.sizeName;
    else if (attachment.sizeName !== undefined) planned.sizeName = attachment.sizeName;
    output.push(planned);
  }
  for (const metadata of decryptedAttachments) {
    if (!seenRaw.has(metadata.id)) {
      addError(context, 'attachment_metadata_orphan', 'Decrypted attachment metadata has no raw attachment.', `$.ciphers[${itemSourceIndex}].attachments`, itemSourceIndex, 'item');
    }
  }
  return output;
}

function parseDeclaredSize(value: string | null | undefined): number | undefined {
  if (value == null) return undefined;
  if (!/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

function remapSourceIndices(
  ir: VaultTransferIR,
  folderSourceIndices: number[],
  collectionSourceIndices: number[],
  itemSourceIndices: number[],
): void {
  ir.folders.forEach((folder, index) => { folder.sourceIndex = folderSourceIndices[index] ?? folder.sourceIndex; });
  ir.collections.forEach((collection, index) => { collection.sourceIndex = collectionSourceIndices[index] ?? collection.sourceIndex; });
  ir.items.forEach((item, index) => { item.sourceIndex = itemSourceIndices[index] ?? item.sourceIndex; });
}

function remapInspectionDiagnostic(
  diagnostic: VaultTransferDiagnostic,
  folderSourceIndices: number[],
  collectionSourceIndices: number[],
  itemSourceIndices: number[],
): VaultTransferDiagnostic {
  let sourceIndex = diagnostic.sourceIndex;
  if (sourceIndex !== undefined) {
    if (diagnostic.sourceKind === 'folder') sourceIndex = folderSourceIndices[sourceIndex] ?? sourceIndex;
    else if (diagnostic.sourceKind === 'collection') sourceIndex = collectionSourceIndices[sourceIndex] ?? sourceIndex;
    else if (diagnostic.sourceKind === 'item') sourceIndex = itemSourceIndices[sourceIndex] ?? sourceIndex;
  }
  const path = diagnostic.path
    ?.replace(/^\$\.folders\[(\d+)\]/, (_match, index: string) => `$.folders[${folderSourceIndices[Number(index)] ?? index}]`)
    .replace(/^\$\.collections\[(\d+)\]/, (_match, index: string) => `$.collections[${collectionSourceIndices[Number(index)] ?? index}]`)
    .replace(/^\$\.items\[(\d+)\]/, (_match, index: string) => `$.items[${itemSourceIndices[Number(index)] ?? index}]`);
  return {
    ...diagnostic,
    ...(path === undefined ? {} : { path }),
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  };
}

function rebuildRelationships(ir: VaultTransferIR, context: BuildContext): void {
  const folders = new Map(ir.folders.map((folder) => [folder.id, folder.sourceIndex]));
  const collections = new Map(ir.collections.map((collection) => [collection.id, collection.sourceIndex]));
  ir.folderRelationships = [];
  ir.collectionRelationships = [];
  for (const item of ir.items) {
    if (item.folderId) {
      const folderSourceIndex = folders.get(item.folderId);
      if (folderSourceIndex === undefined) {
        addError(context, 'broken_folder_relationship', 'An exported item references a folder outside the export.', `$.ciphers[${item.sourceIndex}].folderId`, item.sourceIndex, 'item');
      } else {
        ir.folderRelationships.push({ itemSourceIndex: item.sourceIndex, sourceFolderId: item.folderId, folderSourceIndex });
      }
    }
    for (const collectionId of item.collectionIds) {
      const collectionSourceIndex = collections.get(collectionId);
      if (collectionSourceIndex === undefined) {
        addError(context, 'broken_collection_relationship', 'An exported item references a collection outside the export.', `$.ciphers[${item.sourceIndex}].collectionIds`, item.sourceIndex, 'item');
      } else {
        ir.collectionRelationships.push({
          itemSourceIndex: item.sourceIndex,
          sourceCollectionId: collectionId,
          collectionSourceIndex,
        });
      }
    }
  }
}

function transferLimits(limits: VaultTransferExportLimits): Partial<VaultTransferLimits> {
  return {
    maxInputBytes: limits.maxInputBytes,
    maxItems: limits.maxItems,
    maxFolders: limits.maxFolders,
    maxCollections: limits.maxCollections,
    maxFieldsPerItem: limits.maxFieldsPerItem,
    maxUrisPerItem: limits.maxUrisPerItem,
    maxPasskeysPerItem: limits.maxPasskeysPerItem,
    maxPasswordHistoryPerItem: limits.maxPasswordHistoryPerItem,
    maxCollectionIdsPerItem: limits.maxCollectionIdsPerItem,
    maxStringChars: limits.maxStringChars,
    maxDiagnostics: limits.maxDiagnostics,
  };
}

function resolveLimits(overrides: Partial<VaultTransferExportLimits> | undefined): VaultTransferExportLimits {
  const limits: VaultTransferExportLimits = { ...DEFAULT_VAULT_TRANSFER_EXPORT_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive safe integer`);
  }
  return limits;
}

function failed(context: BuildContext): VaultTransferExportBuildResult {
  return { ok: false, ir: null, attachments: [], diagnostics: context.diagnostics };
}

function addLimitError(
  context: BuildContext,
  code: string,
  path: string,
  actual: number,
  limit: number,
  sourceIndex?: number,
): void {
  addError(
    context,
    code,
    `Value ${actual} exceeds the configured limit of ${limit}.`,
    path,
    sourceIndex,
    sourceIndex === undefined ? 'root' : 'item',
  );
}

function addError(
  context: BuildContext,
  code: string,
  message: string,
  path: string,
  sourceIndex?: number,
  sourceKind: NonNullable<VaultTransferDiagnostic['sourceKind']> = 'root',
): void {
  addDiagnostic(context, {
    severity: 'error', code, message, path, sourceKind,
    ...(sourceIndex === undefined ? {} : { sourceIndex }),
  });
}

function addDiagnostic(context: BuildContext, diagnostic: VaultTransferDiagnostic): void {
  if (context.diagnostics.length < context.limits.maxDiagnostics) {
    context.diagnostics.push(diagnostic);
    return;
  }
  const last = context.diagnostics[context.diagnostics.length - 1];
  if (last?.code === 'diagnostics_truncated') return;
  context.diagnostics[context.diagnostics.length - 1] = {
    severity: 'error', code: 'diagnostics_truncated',
    message: 'Export diagnostics exceeded the configured limit.', path: '$', sourceKind: 'root',
  };
}

function hasBlockingDiagnostics(context: BuildContext): boolean {
  return context.diagnostics.some((diagnostic) => diagnostic.severity === 'error');
}

function validPlaintext(value: unknown, context: BuildContext): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= context.limits.maxStringChars;
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4_096 && !value.includes('\0');
}

function isOptionalIdentifier(value: unknown): boolean {
  return value == null || validIdentifier(value);
}

function isOptionalDate(value: unknown): boolean {
  return isOptionalNullableIsoTimestamp(value);
}

function propertyPath(base: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? `${base}.${key}` : `${base}[${JSON.stringify(key)}]`;
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
