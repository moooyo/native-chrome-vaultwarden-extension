import type { OrganizationResponse } from '../api/types.js';

/** Minimal role summary carried to the popup so it can gate collection-management controls. */
export interface OrgPermission {
  id: string;
  name: string;
  canCreateCollections: boolean;
  canEditCollections: boolean;
  canDeleteCollections: boolean;
  /** Compatibility aggregate. Consumers must use the operation-specific gates for actions. */
  canManageCollections: boolean;
  /** Migration fields populated once the sync metadata helper is wired into VaultService. */
  isMember?: boolean;
  isProviderUser?: boolean;
  canCreateItems?: boolean;
}

export interface OrgPermissionContext {
  readonly isMember: boolean;
  readonly isProviderUser: boolean;
  readonly keyAvailable: boolean;
}

type CollectionPermissions = Pick<OrgPermission,
  'canCreateCollections' | 'canEditCollections' | 'canDeleteCollections'>;

const NO_COLLECTION_PERMISSIONS: CollectionPermissions = {
  canCreateCollections: false,
  canEditCollections: false,
  canDeleteCollections: false,
};

const ALL_COLLECTION_PERMISSIONS: CollectionPermissions = {
  canCreateCollections: true,
  canEditCollections: true,
  canDeleteCollections: true,
};

function collectionPermissions(org: OrganizationResponse): CollectionPermissions {
  if (org.status !== 2) return NO_COLLECTION_PERMISSIONS;

  if (org.type === 0 || org.type === 1) {
    return ALL_COLLECTION_PERMISSIONS;
  }

  if (org.type === 4) {
    return {
      canCreateCollections: Boolean(org.permissions?.createNewCollections),
      canEditCollections: Boolean(org.permissions?.editAnyCollection),
      canDeleteCollections: Boolean(org.permissions?.deleteAnyCollection),
    };
  }

  // A User's create/delete rights depend on organization settings and per-collection access that
  // are not present here. Legacy Manager(3) was removed by Bitwarden and is remapped by Vaultwarden.
  return NO_COLLECTION_PERMISSIONS;
}

/** Coarse compatibility gate. Action controls must use the operation-specific permission fields. */
export function canManageCollections(org: OrganizationResponse): boolean {
  const permissions = collectionPermissions(org);
  return permissions.canCreateCollections
    || permissions.canEditCollections
    || permissions.canDeleteCollections;
}

export function toOrgPermission(org: OrganizationResponse): OrgPermission {
  return projectOrgPermission(org);
}

export function toContextualOrgPermission(
  org: OrganizationResponse,
  context: OrgPermissionContext,
): OrgPermission {
  return projectOrgPermission(org, context);
}

function projectOrgPermission(
  org: OrganizationResponse,
  context?: OrgPermissionContext,
): OrgPermission {
  const permissions = context
    ? contextualCollectionPermissions(org, context)
    : collectionPermissions(org);
  return {
    id: org.id,
    name: org.name ?? '(unnamed organization)',
    ...permissions,
    canManageCollections: permissions.canCreateCollections
      || permissions.canEditCollections
      || permissions.canDeleteCollections,
    ...(context ? {
      isMember: context.isMember,
      isProviderUser: context.isProviderUser,
      canCreateItems: context.isMember
        && context.keyAvailable
        && org.status === 2
        && org.enabled === true,
    } : {}),
  };
}

function contextualCollectionPermissions(
  org: OrganizationResponse,
  context: OrgPermissionContext,
): CollectionPermissions {
  if (!context.keyAvailable) {
    return NO_COLLECTION_PERMISSIONS;
  }
  // Official clients treat Provider users as owners for collection administration. A direct member
  // can simultaneously be a Provider user; that does not remove either authority.
  if (context.isProviderUser) {
    if ((org.status !== undefined && org.status !== null && org.status !== 2)
        || (org.enabled !== undefined && org.enabled !== null && org.enabled !== true)) {
      return NO_COLLECTION_PERMISSIONS;
    }
    return ALL_COLLECTION_PERMISSIONS;
  }
  if (org.status !== 2 || org.enabled !== true) return NO_COLLECTION_PERMISSIONS;
  return collectionPermissions(org);
}
