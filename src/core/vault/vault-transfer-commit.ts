import type {
  VaultTransferInspection,
  VaultTransferItem,
  VaultTransferLoginItem,
  VaultTransferSshKeyItem,
} from './vault-transfer.js';
import type {
  CipherInput,
  CompleteDecryptedSshKey,
  DecryptedCard,
  DecryptedField,
  DecryptedIdentity,
  WritableCipherInput,
} from './models.js';
import { parseCompleteDecryptedSshKey } from './ssh-key.js';

export type PersonalImportItemType = 1 | 2 | 3 | 4 | 5;

export interface PersonalImportCapabilityPolicy {
  supportedItemTypes: readonly PersonalImportItemType[];
  folders: boolean;
  customFields: boolean;
  reprompt: boolean;
  loginUriMatch: boolean;
  autofillOnPageLoad: boolean;
  passwordHistory: boolean;
  passkeys: boolean;
  /** The current lossless writer uses this only for the portable per-user archivedDate field. */
  itemDates: boolean;
  nonGenericSecureNotes: boolean;
}

export const MAX_PERSONAL_IMPORT_PASSWORD_HISTORY = 5;

/** Capabilities of the repository's current CipherInput-based writer. */
export const CIPHER_INPUT_IMPORT_CAPABILITIES: Readonly<PersonalImportCapabilityPolicy> = Object.freeze({
  supportedItemTypes: Object.freeze([1, 2, 3, 4] as const),
  folders: true,
  customFields: true,
  reprompt: true,
  loginUriMatch: true,
  autofillOnPageLoad: true,
  passwordHistory: false,
  passkeys: false,
  itemDates: false,
  nonGenericSecureNotes: false,
});

export interface PersonalImportCapabilityError {
  code: string;
  message: string;
  path?: string;
  sourceIndex?: number;
}

export interface PersonalImportDateMetadata {
  /** Portable per-user state accepted by current Bitwarden and Vaultwarden create requests. */
  archivedDate?: string | null;
}

export interface PersonalImportPasswordHistoryWrite {
  password: string;
  lastUsedDate?: string | null;
}

export interface PersonalImportPasskeyWrite {
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
  creationDate: string;
}

/**
 * A lossless handoff to a remote-write adapter. `cipher` is the current editor write model; optional
 * metadata is carried separately and may be present only when the capability policy promises that
 * the adapter can encode it without loss.
 */
export interface PersonalImportItemWrite {
  sourceIndex: number;
  cipher: WritableCipherInput;
  secureNoteType?: number;
  passwordHistory?: PersonalImportPasswordHistoryWrite[];
  fido2Credentials?: PersonalImportPasskeyWrite[];
  dates?: PersonalImportDateMetadata;
}

export interface PersonalImportFolderWrite {
  sourceIndex: number;
  sourceId: string;
  name: string;
}

export interface RemoteCreateFailure {
  /** Stable, sanitized error code. */
  code: string;
  /** Sanitized display message; must not contain imported secret values. */
  message: string;
}

export type RemoteCreateResult<T> =
  | { status: 'committed'; value: T }
  | { status: 'rejected'; failure: RemoteCreateFailure }
  | { status: 'outcome_unknown'; failure: RemoteCreateFailure };

export interface PersonalImportCommitDeps {
  createFolder(folder: PersonalImportFolderWrite): Promise<RemoteCreateResult<{ id: string }>>;
  createItem(item: PersonalImportItemWrite): Promise<RemoteCreateResult<{ id?: string }>>;
  markDirty(reason: 'import_outcome_unknown'): void | Promise<void>;
  forceReconcile(): void | Promise<void>;
}

export type PersonalImportSkipReason =
  | 'folder_rejected'
  | 'folder_unavailable'
  | 'stopped_after_unknown_outcome';

export type PersonalImportFolderOutcome =
  | { kind: 'folder'; sourceIndex: number; sourceId: string; status: 'committed'; createdId: string }
  | { kind: 'folder'; sourceIndex: number; sourceId: string; status: 'rejected'; failure: RemoteCreateFailure }
  | { kind: 'folder'; sourceIndex: number; sourceId: string; status: 'outcome_unknown'; failure: RemoteCreateFailure }
  | { kind: 'folder'; sourceIndex: number; sourceId: string; status: 'skipped'; reason: 'stopped_after_unknown_outcome' };

export type PersonalImportItemOutcome =
  | { kind: 'item'; sourceIndex: number; rawType: number; status: 'committed'; createdId?: string }
  | { kind: 'item'; sourceIndex: number; rawType: number; status: 'rejected'; failure: RemoteCreateFailure }
  | { kind: 'item'; sourceIndex: number; rawType: number; status: 'outcome_unknown'; failure: RemoteCreateFailure }
  | { kind: 'item'; sourceIndex: number; rawType: number; status: 'skipped'; reason: PersonalImportSkipReason; folderSourceId?: string };

export interface PersonalImportCommitResult {
  status: 'blocked' | 'completed' | 'partial' | 'outcome_unknown';
  capabilityErrors: PersonalImportCapabilityError[];
  folderOutcomes: PersonalImportFolderOutcome[];
  itemOutcomes: PersonalImportItemOutcome[];
  mustSyncBeforeRetry: boolean;
  dirtyMarked: boolean;
  forceReconcileAttempted: boolean;
  forceReconcileSucceeded: boolean;
}

export interface PersonalImportCommitRequest {
  inspection: VaultTransferInspection;
  capabilities: PersonalImportCapabilityPolicy;
  deps: PersonalImportCommitDeps;
}

const CARD_FIELDS: ReadonlyArray<keyof DecryptedCard> = [
  'cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code',
];

const IDENTITY_FIELDS: ReadonlyArray<keyof DecryptedIdentity> = [
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
  'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn',
  'username', 'passportNumber', 'licenseNumber',
];

/** Pure preflight shared by preview construction and the commit engine. */
export function inspectPersonalImportCapabilities(
  inspection: VaultTransferInspection,
  capabilities: PersonalImportCapabilityPolicy,
): PersonalImportCapabilityError[] {
  const errors: PersonalImportCapabilityError[] = [];
  const ir = inspection.ir;
  if (!ir) {
    errors.push({
      code: 'inspection_not_committable',
      message: 'Transfer inspection contains blocking errors.',
      path: '$',
    });
    return errors;
  }
  if (!inspection.canCommit) {
    errors.push({
      code: 'inspection_not_committable',
      message: 'Transfer inspection contains blocking errors.',
      path: '$',
    });
  }
  if (inspection.diagnostics.some((diagnostic) => diagnostic.severity === 'error')) {
    errors.push({
      code: 'inspection_has_errors',
      message: 'Transfer diagnostics contain an error.',
      path: '$',
    });
  }
  if (ir.version !== 1) {
    errors.push({ code: 'unsupported_ir_version', message: 'Transfer IR version is not supported.', path: '$.version' });
  }
  if (ir.scope !== 'personal' || ir.collections.length > 0 || ir.collectionRelationships.length > 0) {
    errors.push({
      code: 'organization_target_required',
      message: 'Organization data requires an explicit organization target and permission check.',
      path: '$.scope',
    });
  }
  if (ir.unknownFieldPaths.length > 0) {
    errors.push({ code: 'unknown_fields', message: 'Unknown fields cannot be committed without loss.', path: '$' });
  }
  if (ir.folders.length > 0 && !capabilities.folders) {
    errors.push({ code: 'folders_unsupported', message: 'The active writer cannot create folders.', path: '$.folders' });
  }

  const supportedTypes = new Set<number>(capabilities.supportedItemTypes);
  for (const item of ir.items) inspectItemCapabilities(item, capabilities, supportedTypes, errors);
  return dedupeCapabilityErrors(errors);
}

function inspectItemCapabilities(
  item: VaultTransferItem,
  capabilities: PersonalImportCapabilityPolicy,
  supportedTypes: ReadonlySet<number>,
  errors: PersonalImportCapabilityError[],
): void {
  const basePath = `$.items[${item.sourceIndex}]`;
  const add = (code: string, message: string, path: string): void => {
    errors.push({ code, message, path, sourceIndex: item.sourceIndex });
  };
  if (!isPersonalImportItem(item) || !supportedTypes.has(item.rawType)) {
    add('item_type_unsupported', `Item type ${item.rawType} is not supported by the active writer.`, `${basePath}.type`);
    return;
  }
  if (item.organizationId != null || item.collectionIds.length > 0) {
    add('organization_target_required', 'Organization-owned items require an explicit organization target.', basePath);
  }
  if (item.fields.length > 0 && !capabilities.customFields) {
    add('custom_fields_unsupported', 'The active writer cannot preserve custom fields.', `${basePath}.fields`);
  }
  if (item.kind === 'sshKey' && hasLinkedCustomField(item)) {
    add(
      'ssh_linked_fields_unsupported',
      'SSH key items cannot preserve linked custom fields.',
      `${basePath}.fields`,
    );
  }
  if (item.reprompt !== 0 && !capabilities.reprompt) {
    add('reprompt_unsupported', 'The active writer cannot preserve master-password reprompt.', `${basePath}.reprompt`);
  }
  if (item.passwordHistory.length > MAX_PERSONAL_IMPORT_PASSWORD_HISTORY) {
    add(
      'password_history_limit_exceeded',
      `Password history cannot exceed ${MAX_PERSONAL_IMPORT_PASSWORD_HISTORY} entries.`,
      `${basePath}.passwordHistory`,
    );
  } else if (item.passwordHistory.length > 0 && !capabilities.passwordHistory) {
    add('password_history_unsupported', 'The active writer cannot preserve password history.', `${basePath}.passwordHistory`);
  }
  if (item.deletedDate != null) {
    add('item_dates_unsupported', 'Deleted item timestamps cannot be preserved during import.', `${basePath}.deletedDate`);
  }
  if (item.archivedDate != null && !capabilities.itemDates) {
    add('item_dates_unsupported', 'The active writer cannot preserve archived item state.', `${basePath}.archivedDate`);
  }
  if (item.rawType === 1 && item.kind === 'login') {
    if (item.payload.fido2Credentials.length > 0 && !capabilities.passkeys) {
      add('passkeys_unsupported', 'The active writer cannot preserve stored passkeys.', `${basePath}.login.fido2Credentials`);
    } else if (item.payload.fido2Credentials.some((credential) => credential.creationDate == null)) {
      add(
        'passkeys_unsupported',
        'Imported passkeys require a creation timestamp.',
        `${basePath}.login.fido2Credentials`,
      );
    }
    if (item.payload.uris.some((uri) => uri.match != null) && !capabilities.loginUriMatch) {
      add('uri_match_unsupported', 'The active writer cannot preserve per-URI match rules.', `${basePath}.login.uris`);
    }
    if (Object.prototype.hasOwnProperty.call(item.payload, 'autofillOnPageLoad')
      && !capabilities.autofillOnPageLoad) {
      add(
        'autofill_on_page_load_unsupported',
        'The active writer cannot preserve the page-load autofill override.',
        `${basePath}.login.autofillOnPageLoad`,
      );
    }
  }
  if (item.rawType === 2 && item.kind === 'secureNote'
    && item.payload.type !== 0 && !capabilities.nonGenericSecureNotes) {
    add('secure_note_type_unsupported', 'The active writer cannot preserve this secure-note subtype.', `${basePath}.secureNote.type`);
  }
}

function dedupeCapabilityErrors(errors: PersonalImportCapabilityError[]): PersonalImportCapabilityError[] {
  const seen = new Set<string>();
  return errors.filter((error) => {
    const key = `${error.code}\u0000${error.path ?? ''}\u0000${error.sourceIndex ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Commit a preflighted personal transfer exactly once per remote object, in source order. */
export async function commitPersonalVaultTransfer(
  request: PersonalImportCommitRequest,
): Promise<PersonalImportCommitResult> {
  const capabilityErrors = inspectPersonalImportCapabilities(request.inspection, request.capabilities);
  const blocked = (): PersonalImportCommitResult => ({
    status: 'blocked',
    capabilityErrors,
    folderOutcomes: [],
    itemOutcomes: [],
    mustSyncBeforeRetry: false,
    dirtyMarked: false,
    forceReconcileAttempted: false,
    forceReconcileSucceeded: false,
  });
  if (capabilityErrors.length > 0 || !request.inspection.ir) return blocked();

  const ir = request.inspection.ir;
  const folderOutcomes: PersonalImportFolderOutcome[] = [];
  const itemOutcomes: PersonalImportItemOutcome[] = [];
  const mappedFolders = new Map<string, string>();
  const rejectedFolders = new Set<string>();
  let unknownOutcome = false;
  let dirtyMarked = false;
  let forceReconcileAttempted = false;
  let forceReconcileSucceeded = false;

  for (const folder of ir.folders) {
    if (unknownOutcome) {
      folderOutcomes.push({
        kind: 'folder', sourceIndex: folder.sourceIndex, sourceId: folder.id,
        status: 'skipped', reason: 'stopped_after_unknown_outcome',
      });
      continue;
    }
    const result = await classifyRemoteCreate(() => request.deps.createFolder({
      sourceIndex: folder.sourceIndex,
      sourceId: folder.id,
      name: folder.name,
    }));
    if (result.status === 'committed') {
      if (typeof result.value.id === 'string' && result.value.id.length > 0) {
        mappedFolders.set(folder.id, result.value.id);
        folderOutcomes.push({
          kind: 'folder', sourceIndex: folder.sourceIndex, sourceId: folder.id,
          status: 'committed', createdId: result.value.id,
        });
      } else {
        unknownOutcome = true;
        folderOutcomes.push({
          kind: 'folder', sourceIndex: folder.sourceIndex, sourceId: folder.id,
          status: 'outcome_unknown',
          failure: {
            code: 'invalid_commit_receipt',
            message: 'The folder may have been committed, but its returned id is unavailable.',
          },
        });
      }
    } else if (result.status === 'rejected') {
      rejectedFolders.add(folder.id);
      folderOutcomes.push({
        kind: 'folder', sourceIndex: folder.sourceIndex, sourceId: folder.id,
        status: 'rejected', failure: result.failure,
      });
    } else {
      unknownOutcome = true;
      folderOutcomes.push({
        kind: 'folder', sourceIndex: folder.sourceIndex, sourceId: folder.id,
        status: 'outcome_unknown', failure: result.failure,
      });
    }
  }

  if (!unknownOutcome) {
    for (const item of ir.items) {
      const dependency = resolveItemFolder(item, mappedFolders, rejectedFolders);
      if (dependency.status === 'rejected') {
        itemOutcomes.push({
          kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType,
          status: 'skipped', reason: 'folder_rejected', folderSourceId: dependency.sourceId,
        });
        continue;
      }
      if (dependency.status === 'unavailable') {
        itemOutcomes.push({
          kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType,
          status: 'skipped', reason: 'folder_unavailable', folderSourceId: dependency.sourceId,
        });
        continue;
      }
      const write = toPersonalImportItemWrite(item, dependency.status === 'mapped' ? dependency.createdId : undefined);
      if (!write) {
        itemOutcomes.push({
          kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType,
          status: 'rejected', failure: { code: 'invalid_ir_item', message: 'The inspected item cannot be converted safely.' },
        });
        continue;
      }
      const result = await classifyRemoteCreate(() => request.deps.createItem(write));
      if (result.status === 'committed') {
        const createdId = result.value.id;
        itemOutcomes.push({
          kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType, status: 'committed',
          ...(createdId ? { createdId } : {}),
        });
      } else if (result.status === 'rejected') {
        itemOutcomes.push({
          kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType,
          status: 'rejected', failure: result.failure,
        });
      } else {
        unknownOutcome = true;
        itemOutcomes.push({
          kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType,
          status: 'outcome_unknown', failure: result.failure,
        });
        break;
      }
    }
  }

  if (unknownOutcome) {
    const alreadyReported = new Set(itemOutcomes.map((outcome) => outcome.sourceIndex));
    for (const item of ir.items) {
      if (alreadyReported.has(item.sourceIndex)) continue;
      itemOutcomes.push({
        kind: 'item', sourceIndex: item.sourceIndex, rawType: item.rawType,
        status: 'skipped', reason: 'stopped_after_unknown_outcome',
      });
    }
    try {
      await request.deps.markDirty('import_outcome_unknown');
      dirtyMarked = true;
    } catch {
      // Reconciliation is still mandatory even if the durable dirty marker could not be written.
    }
    forceReconcileAttempted = true;
    try {
      await request.deps.forceReconcile();
      forceReconcileSucceeded = true;
    } catch {
      // The result remains outcome_unknown and must be surfaced to the caller.
    }
  }

  const allOutcomes = [...folderOutcomes, ...itemOutcomes];
  const hasCommitted = allOutcomes.some((outcome) => outcome.status === 'committed');
  const hasNonCommitted = allOutcomes.some((outcome) => outcome.status !== 'committed');
  const partial = !unknownOutcome && hasNonCommitted;
  return {
    status: unknownOutcome ? 'outcome_unknown' : (partial ? 'partial' : 'completed'),
    capabilityErrors,
    folderOutcomes,
    itemOutcomes,
    mustSyncBeforeRetry: unknownOutcome || (hasCommitted && hasNonCommitted),
    dirtyMarked,
    forceReconcileAttempted,
    forceReconcileSucceeded,
  };
}

async function classifyRemoteCreate<T extends object>(
  create: () => Promise<RemoteCreateResult<T>>,
): Promise<RemoteCreateResult<T>> {
  try {
    const result: unknown = await create();
    if (!isRecord(result)) return unknownRemoteResult();
    if (result.status === 'committed' && isRecord(result.value)) {
      return { status: 'committed', value: result.value as T };
    }
    if ((result.status === 'rejected' || result.status === 'outcome_unknown') && isRemoteFailure(result.failure)) {
      return { status: result.status, failure: result.failure };
    }
    return unknownRemoteResult();
  } catch {
    return unknownRemoteResult();
  }
}

function unknownRemoteResult<T extends object>(): RemoteCreateResult<T> {
  return {
    status: 'outcome_unknown',
    failure: {
      code: 'unclassified_remote_exception',
      message: 'The remote create did not return a classified outcome.',
    },
  };
}

function isRemoteFailure(value: unknown): value is RemoteCreateFailure {
  return isRecord(value) && typeof value.code === 'string' && typeof value.message === 'string';
}

type FolderResolution =
  | { status: 'none' }
  | { status: 'mapped'; sourceId: string; createdId: string }
  | { status: 'rejected'; sourceId: string }
  | { status: 'unavailable'; sourceId: string };

function resolveItemFolder(
  item: VaultTransferItem,
  mappedFolders: ReadonlyMap<string, string>,
  rejectedFolders: ReadonlySet<string>,
): FolderResolution {
  if (!item.folderId) return { status: 'none' };
  if (rejectedFolders.has(item.folderId)) return { status: 'rejected', sourceId: item.folderId };
  const createdId = mappedFolders.get(item.folderId);
  return createdId
    ? { status: 'mapped', sourceId: item.folderId, createdId }
    : { status: 'unavailable', sourceId: item.folderId };
}

export function toPersonalImportItemWrite(
  item: VaultTransferItem,
  mappedFolderId: string | undefined,
): PersonalImportItemWrite | undefined {
  if (!isPersonalImportItem(item)) return undefined;
  if (item.kind === 'sshKey' && hasLinkedCustomField(item)) return undefined;
  const base = baseCipherInput(item, mappedFolderId);
  let cipher: WritableCipherInput;
  switch (item.kind) {
    case 'login':
      cipher = { ...base, type: 1, login: loginInput(item) };
      break;
    case 'secureNote':
      cipher = { ...base, type: 2 };
      break;
    case 'card':
      cipher = { ...base, type: 3, card: copyStringPayload(item.payload.values, CARD_FIELDS) };
      break;
    case 'identity':
      cipher = { ...base, type: 4, identity: copyStringPayload(item.payload.values, IDENTITY_FIELDS) };
      break;
    case 'sshKey': {
      const sshKey = sshKeyInput(item);
      if (!sshKey) return undefined;
      cipher = { ...base, type: 5, sshKey };
      break;
    }
    default:
      return undefined;
  }

  const write: PersonalImportItemWrite = { sourceIndex: item.sourceIndex, cipher };
  if (item.kind === 'secureNote') write.secureNoteType = item.payload.type;
  if (item.passwordHistory.length > 0) {
    write.passwordHistory = item.passwordHistory.map((entry) => ({
      password: entry.password,
      ...(entry.lastUsedDate !== undefined ? { lastUsedDate: entry.lastUsedDate } : {}),
    }));
  }
  if (item.kind === 'login' && item.payload.fido2Credentials.length > 0) {
    if (item.payload.fido2Credentials.some((credential) => credential.creationDate == null)) {
      return undefined;
    }
    write.fido2Credentials = item.payload.fido2Credentials.map((credential) => ({
      credentialId: credential.credentialId,
      keyType: credential.keyType,
      keyAlgorithm: credential.keyAlgorithm,
      keyCurve: credential.keyCurve,
      keyValue: credential.keyValue,
      rpId: credential.rpId,
      counter: credential.counter,
      discoverable: credential.discoverable,
      ...(credential.userHandle !== undefined ? { userHandle: credential.userHandle } : {}),
      ...(credential.userName !== undefined ? { userName: credential.userName } : {}),
      ...(credential.rpName !== undefined ? { rpName: credential.rpName } : {}),
      ...(credential.userDisplayName !== undefined ? { userDisplayName: credential.userDisplayName } : {}),
      creationDate: credential.creationDate!,
    }));
  }
  if (item.archivedDate != null) {
    write.dates = { archivedDate: item.archivedDate };
  }
  return write;
}

type PersonalImportCipherBase = Omit<
  CipherInput<PersonalImportItemType>,
  'type' | 'login' | 'card' | 'identity' | 'sshKey'
>;

function baseCipherInput(
  item: VaultTransferItem,
  mappedFolderId: string | undefined,
): PersonalImportCipherBase {
  const cipher: PersonalImportCipherBase = {
    name: item.name,
    favorite: item.favorite,
    reprompt: item.reprompt === 1,
  };
  if (item.notes !== undefined && item.notes !== null) cipher.notes = item.notes;
  if (mappedFolderId) cipher.folderId = mappedFolderId;
  if (item.fields.length > 0) cipher.fields = item.fields.map(copyCustomField);
  return cipher;
}

type PersonalImportItem = Extract<
  VaultTransferItem,
  { kind: 'login' | 'secureNote' | 'card' | 'identity' | 'sshKey' }
>;

function isPersonalImportItem(item: VaultTransferItem): item is PersonalImportItem {
  switch (item.rawType) {
    case 1: return item.kind === 'login';
    case 2: return item.kind === 'secureNote';
    case 3: return item.kind === 'card';
    case 4: return item.kind === 'identity';
    case 5: return item.kind === 'sshKey';
    default: return false;
  }
}

function sshKeyInput(item: VaultTransferSshKeyItem): CompleteDecryptedSshKey | undefined {
  try {
    return parseCompleteDecryptedSshKey({
      privateKey: item.payload.values.privateKey,
      publicKey: item.payload.values.publicKey,
      keyFingerprint: item.payload.values.keyFingerprint,
    });
  } catch {
    return undefined;
  }
}

function hasLinkedCustomField(item: VaultTransferItem): boolean {
  return item.fields.some((field) => field.type === 3);
}

function copyCustomField(field: VaultTransferItem['fields'][number]): DecryptedField {
  const output: DecryptedField = { type: field.type, name: field.name ?? '' };
  if (field.value !== undefined && field.value !== null) output.value = field.value;
  if (field.linkedId !== undefined && field.linkedId !== null) output.linkedId = field.linkedId;
  return output;
}

function loginInput(item: VaultTransferLoginItem): NonNullable<CipherInput['login']> {
  const payload = item.payload;
  const login: NonNullable<CipherInput['login']> = {};
  if (payload.username !== undefined && payload.username !== null) login.username = payload.username;
  if (payload.password !== undefined && payload.password !== null) login.password = payload.password;
  if (payload.totp !== undefined && payload.totp !== null) login.totp = payload.totp;
  if (Object.prototype.hasOwnProperty.call(payload, 'autofillOnPageLoad')) {
    const value = payload.autofillOnPageLoad;
    if (value !== undefined) login.autofillOnPageLoad = value;
  }
  if (Object.prototype.hasOwnProperty.call(payload, 'passwordRevisionDate')) {
    const value = payload.passwordRevisionDate;
    if (value !== undefined) login.passwordRevisionDate = value;
  }
  if (payload.uris.length > 0) {
    login.uris = payload.uris.map((uri) => ({
      uri: uri.uri,
      ...(uri.match !== undefined ? { match: uri.match } : {}),
    }));
  }
  return login;
}

function copyStringPayload<T extends object, K extends keyof T>(
  values: Readonly<Record<string, string | null>>,
  fields: ReadonlyArray<K>,
): T {
  const output = {} as T;
  for (const field of fields) {
    const value = values[String(field)];
    if (value !== undefined && value !== null) Object.assign(output, { [field]: value });
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
