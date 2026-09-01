export const CollectionTypes = Object.freeze({
  SharedCollection: 0,
  DefaultUserCollection: 1,
} as const);

export interface CollectionOrganizationAuthority {
  readonly id: string;
  readonly status?: number | null;
  readonly enabled?: boolean | null;
  readonly type?: number | null;
  readonly isProviderUser?: boolean | null;
  readonly limitCollectionCreation?: boolean | null;
  readonly limitCollectionDeletion?: boolean | null;
  readonly allowAdminAccessToAllCollectionItems?: boolean | null;
  readonly permissions?: {
    readonly createNewCollections?: boolean | null;
    readonly editAnyCollection?: boolean | null;
    readonly deleteAnyCollection?: boolean | null;
  } | null;
}

export interface CollectionAuthority {
  readonly organizationId: string;
  readonly object?: unknown;
  readonly type?: number | null;
  readonly defaultUserCollectionEmail?: string | null;
  readonly assigned?: boolean | null;
  readonly manage?: boolean | null;
  readonly readOnly?: boolean | null;
}

export interface OrganizationCipherCloneSource {
  readonly organizationId?: string | null;
  readonly collectionIds?: readonly string[] | null;
}

export interface CloneCollectionAuthority extends CollectionAuthority {
  readonly id: string;
}

export interface CollectionCapabilities {
  readonly canCreate: boolean;
  readonly canRename: boolean;
  readonly canDelete: boolean;
  readonly canAssign: boolean;
}

interface ParsedOrganizationAuthority {
  readonly id: string;
  readonly role: 0 | 1 | 2 | 3 | 4;
  readonly isProviderUser: boolean;
  readonly limitCollectionCreation: boolean | undefined;
  readonly limitCollectionDeletion: boolean | undefined;
  readonly allowAdminAccessToAllCollectionItems: boolean;
  readonly createNewCollections: boolean;
  readonly editAnyCollection: boolean;
  readonly deleteAnyCollection: boolean;
}

interface ParsedCollectionAuthority {
  readonly type: 0 | 1;
  readonly hasProtectedDefaultName: boolean;
  readonly assigned: boolean;
  readonly manage: boolean;
  readonly readOnly: boolean | undefined;
}

const DENIED_CAPABILITIES: CollectionCapabilities = Object.freeze({
  canCreate: false,
  canRename: false,
  canDelete: false,
  canAssign: false,
});

const MAX_CLONE_SOURCE_COLLECTIONS = 1_024;
const MAX_AUTHORITY_ID_LENGTH = 4_096;

/**
 * Authorize cloning an organization cipher from one raw profile/collection snapshot. Every source
 * collection must resolve uniquely in that organization, while at least one must carry an exact
 * manage grant. Malformed, sparse, duplicate, or conflicting authority fails closed.
 */
export function canCloneOrganizationCipher(
  organization: CollectionOrganizationAuthority | null | undefined,
  source: OrganizationCipherCloneSource | null | undefined,
  collections: readonly CloneCollectionAuthority[] | null | undefined,
): boolean {
  const org = parseOrganizationAuthority(organization);
  const sourceRecord = plainDataRecord(source);
  if (!org || !sourceRecord || !isDenseDataArray(collections)) return false;

  const sourceOrganizationId = dataValue(sourceRecord, 'organizationId');
  const sourceCollectionIds = dataValue(sourceRecord, 'collectionIds');
  if (
    sourceOrganizationId !== org.id
    || !isDenseDataArray(sourceCollectionIds)
    || sourceCollectionIds.length === 0
    || sourceCollectionIds.length > MAX_CLONE_SOURCE_COLLECTIONS
  ) return false;

  const uniqueIds = new Set<string>();
  for (let index = 0; index < sourceCollectionIds.length; index++) {
    const id = ownArrayValue(sourceCollectionIds, index);
    if (
      typeof id !== 'string'
      || id.length === 0
      || id.length > MAX_AUTHORITY_ID_LENGTH
      || id !== id.trim()
      || containsAsciiControl(id)
      || uniqueIds.has(id)
    ) return false;
    uniqueIds.add(id);
  }

  let hasManageGrant = false;
  for (const id of uniqueIds) {
    let match: CloneCollectionAuthority | undefined;
    let matchCount = 0;
    for (let index = 0; index < collections.length; index++) {
      const candidate = ownArrayValue(collections, index);
      if (candidate === INVALID_DATA) return false;
      const candidateRecord = plainDataRecord(candidate);
      if (!candidateRecord) return false;
      const candidateId = dataValue(candidateRecord, 'id');
      if (candidateId === INVALID_DATA) return false;
      if (candidateId !== id) continue;
      match = candidate;
      matchCount += 1;
    }
    if (matchCount !== 1 || !match) return false;
    const parsed = parseCollectionAuthority(match, org.id);
    if (!parsed) return false;
    if (parsed.manage) hasManageGrant = true;
  }
  return hasManageGrant;
}

function isDenseDataArray(value: unknown): value is readonly unknown[] {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
    return keys.every((key) => {
      if (key === 'length') return true;
      if (typeof key !== 'string' || !/^(0|[1-9]\d*)$/.test(key)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && 'value' in descriptor;
    });
  } catch {
    return false;
  }
}

function ownArrayValue<T>(value: readonly T[], index: number): T | typeof INVALID_DATA {
  const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
  return descriptor && 'value' in descriptor ? descriptor.value as T : INVALID_DATA;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * Resolve organization and collection capabilities from one current, server-derived snapshot.
 * Missing or malformed authority is never interpreted as a grant. Callers must still revalidate
 * the same snapshot immediately before a write and let the server make the final decision.
 */
export function resolveCollectionCapabilities(
  organization: CollectionOrganizationAuthority | null | undefined,
  collection?: CollectionAuthority | null,
): CollectionCapabilities {
  const org = parseOrganizationAuthority(organization);
  if (!org) return DENIED_CAPABILITIES;

  const isOwner = org.role === 0 || org.isProviderUser;
  const isAdmin = org.role === 1 || isOwner;
  const canCreate = org.limitCollectionCreation !== true || isAdmin || org.createNewCollections;
  if (collection == null) {
    return Object.freeze({ canCreate, canRename: false, canDelete: false, canAssign: false });
  }

  const target = parseCollectionAuthority(collection, org.id);
  if (!target) {
    return Object.freeze({ canCreate, canRename: false, canDelete: false, canAssign: false });
  }

  const isDefaultCollection = target.type === CollectionTypes.DefaultUserCollection;
  const canEditAnyCollection = org.isProviderUser
    || (org.role === 4 && org.editAnyCollection)
    || (org.allowAdminAccessToAllCollectionItems && isAdmin);
  const canEditAllCiphers = (org.role === 4 && org.editAnyCollection)
    || (org.allowAdminAccessToAllCollectionItems && (org.role === 0 || org.role === 1));
  const canDeleteAnyCollection = org.isProviderUser
    || org.deleteAnyCollection
    || (org.allowAdminAccessToAllCollectionItems && (org.role === 0 || org.role === 1));
  const canDeleteManagedCollection = target.manage
    && (org.limitCollectionDeletion !== true || isAdmin);

  return Object.freeze({
    canCreate,
    canRename: !isDefaultCollection
      && !target.hasProtectedDefaultName
      && (target.manage || canEditAnyCollection),
    canDelete: !isDefaultCollection
      && (canDeleteAnyCollection || canDeleteManagedCollection),
    canAssign: canEditAllCiphers
      || target.manage
      || (target.assigned && target.readOnly === false),
  });
}

function parseOrganizationAuthority(
  input: CollectionOrganizationAuthority | null | undefined,
): ParsedOrganizationAuthority | undefined {
  const record = plainDataRecord(input);
  if (!record) return undefined;

  const id = dataValue(record, 'id');
  const status = dataValue(record, 'status');
  const enabled = dataValue(record, 'enabled');
  const rawRole = dataValue(record, 'type');
  const isProviderUser = optionalBoolean(record, 'isProviderUser');
  const enabledValue = optionalBoolean(record, 'enabled');
  if (!isProviderUser.valid || !enabledValue.valid) return undefined;
  const provider = isProviderUser.value === true;
  const role = provider && (rawRole === undefined || rawRole === null) ? 0 : rawRole;
  if (
    typeof id !== 'string'
    || id.length === 0
    || (!provider && (status !== 2 || enabled !== true))
    || (provider && status !== undefined && status !== null && status !== 2)
    || (role !== 0 && role !== 1 && role !== 2 && role !== 3 && role !== 4)
  ) return undefined;

  const limitCollectionCreation = optionalBoolean(record, 'limitCollectionCreation');
  const limitCollectionDeletion = optionalBoolean(record, 'limitCollectionDeletion');
  const allowAdminAccess = optionalBoolean(record, 'allowAdminAccessToAllCollectionItems');
  if (
    !limitCollectionCreation.valid
    || !limitCollectionDeletion.valid
    || !allowAdminAccess.valid
  ) return undefined;

  const permissionsValue = dataValue(record, 'permissions');
  const permissions = permissionsValue == null ? EMPTY_RECORD : plainDataRecord(permissionsValue);
  if (!permissions) return undefined;
  const createNewCollections = optionalBoolean(permissions, 'createNewCollections');
  const editAnyCollection = optionalBoolean(permissions, 'editAnyCollection');
  const deleteAnyCollection = optionalBoolean(permissions, 'deleteAnyCollection');
  if (!createNewCollections.valid || !editAnyCollection.valid || !deleteAnyCollection.valid) {
    return undefined;
  }

  return Object.freeze({
    id,
    role,
    isProviderUser: provider,
    limitCollectionCreation: limitCollectionCreation.value,
    limitCollectionDeletion: limitCollectionDeletion.value,
    allowAdminAccessToAllCollectionItems: allowAdminAccess.value === true,
    createNewCollections: createNewCollections.value === true,
    editAnyCollection: editAnyCollection.value === true,
    deleteAnyCollection: deleteAnyCollection.value === true,
  });
}

function parseCollectionAuthority(
  input: CollectionAuthority,
  expectedOrganizationId: string,
): ParsedCollectionAuthority | undefined {
  const record = plainDataRecord(input);
  if (!record || dataValue(record, 'organizationId') !== expectedOrganizationId) return undefined;

  const typeValue = dataValue(record, 'type');
  const type = typeValue == null ? CollectionTypes.SharedCollection : typeValue;
  if (type !== CollectionTypes.SharedCollection && type !== CollectionTypes.DefaultUserCollection) {
    return undefined;
  }

  const assigned = optionalBoolean(record, 'assigned');
  const manage = optionalBoolean(record, 'manage');
  const readOnly = optionalBoolean(record, 'readOnly');
  const defaultEmail = dataValue(record, 'defaultUserCollectionEmail');
  const object = dataValue(record, 'object');
  if (
    !assigned.valid
    || !manage.valid
    || !readOnly.valid
    || (defaultEmail != null && typeof defaultEmail !== 'string')
    || object === INVALID_DATA
    || (object !== undefined && object !== null && typeof object !== 'string')
  ) return undefined;

  return Object.freeze({
    type,
    hasProtectedDefaultName: typeof defaultEmail === 'string' && defaultEmail.length > 0,
    assigned: assigned.value === true
      || (assigned.value === undefined && object === 'collectionDetails'),
    manage: manage.value === true,
    readOnly: readOnly.value ?? false,
  });
}

const INVALID_DATA = Symbol('invalid-data');
const EMPTY_RECORD: Readonly<Record<string, unknown>> = Object.freeze({});

function plainDataRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    return value as Readonly<Record<string, unknown>>;
  } catch {
    return undefined;
  }
}

function dataValue(record: Readonly<Record<string, unknown>>, key: string): unknown | typeof INVALID_DATA {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor) return undefined;
    return Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ? descriptor.value
      : INVALID_DATA;
  } catch {
    return INVALID_DATA;
  }
}

function optionalBoolean(
  record: Readonly<Record<string, unknown>>,
  key: string,
): { readonly valid: boolean; readonly value: boolean | undefined } {
  const value = dataValue(record, key);
  if (value === undefined || value === null) return { valid: true, value: undefined };
  return typeof value === 'boolean'
    ? { valid: true, value }
    : { valid: false, value: undefined };
}
