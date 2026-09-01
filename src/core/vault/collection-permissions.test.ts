import { describe, expect, it, vi } from 'vitest';
import {
  canCloneOrganizationCipher,
  CollectionTypes,
  resolveCollectionCapabilities,
  type CloneCollectionAuthority,
  type CollectionAuthority,
  type CollectionOrganizationAuthority,
} from './collection-permissions.js';

function organization(
  overrides: Partial<CollectionOrganizationAuthority> = {},
): CollectionOrganizationAuthority {
  return {
    id: 'org-1',
    status: 2,
    enabled: true,
    type: 2,
    limitCollectionCreation: true,
    limitCollectionDeletion: true,
    allowAdminAccessToAllCollectionItems: false,
    permissions: {},
    ...overrides,
  };
}

function collection(overrides: Partial<CollectionAuthority> = {}): CollectionAuthority {
  return {
    organizationId: 'org-1',
    type: CollectionTypes.SharedCollection,
    assigned: false,
    manage: false,
    readOnly: true,
    ...overrides,
  };
}

function cloneCollection(
  id: string,
  overrides: Partial<CloneCollectionAuthority> = {},
): CloneCollectionAuthority {
  return { id, ...collection(), ...overrides };
}

describe('canCloneOrganizationCipher', () => {
  it('requires an exact manage grant on at least one current source collection', () => {
    const source = { organizationId: 'org-1', collectionIds: ['col-1', 'col-2'] };
    expect(canCloneOrganizationCipher(organization(), source, [
      cloneCollection('col-1', { assigned: true, readOnly: false }),
      cloneCollection('col-2', { manage: true }),
    ])).toBe(true);
    expect(canCloneOrganizationCipher(organization(), source, [
      cloneCollection('col-1', { assigned: true, readOnly: false }),
      cloneCollection('col-2', { assigned: true, readOnly: false }),
    ])).toBe(false);
  });

  it('fails closed for empty, duplicate, unknown, and conflicting source collection authority', () => {
    const managed = cloneCollection('col-1', { manage: true });
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-1', collectionIds: [],
    }, [managed])).toBe(false);
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-1', collectionIds: ['col-1', 'col-1'],
    }, [managed])).toBe(false);
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-1', collectionIds: ['missing'],
    }, [managed])).toBe(false);
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-1', collectionIds: ['col-1'],
    }, [managed, cloneCollection('col-1', { manage: false })])).toBe(false);
  });

  it('fails closed for stale membership, organization mismatch, sparse ids, and accessors', () => {
    const managed = cloneCollection('col-1', { manage: true });
    const source = { organizationId: 'org-1', collectionIds: ['col-1'] };
    expect(canCloneOrganizationCipher(organization({ enabled: false }), source, [managed])).toBe(false);
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-2', collectionIds: ['col-1'],
    }, [managed])).toBe(false);
    const sparse = new Array<string>(1);
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-1', collectionIds: sparse,
    }, [managed])).toBe(false);
    const getter = vi.fn(() => ['col-1']);
    const accessor = Object.defineProperty({ organizationId: 'org-1' }, 'collectionIds', {
      enumerable: true, get: getter,
    });
    expect(canCloneOrganizationCipher(organization(), accessor, [managed])).toBe(false);
    expect(getter).not.toHaveBeenCalled();

    const arrayGetter = vi.fn(() => 'col-1');
    const accessorIds = ['placeholder'];
    Object.defineProperty(accessorIds, '0', { enumerable: true, get: arrayGetter });
    expect(canCloneOrganizationCipher(organization(), {
      organizationId: 'org-1', collectionIds: accessorIds,
    }, [managed])).toBe(false);
    expect(arrayGetter).not.toHaveBeenCalled();
  });
});

describe('resolveCollectionCapabilities', () => {
  it('resolves collection creation from limits, admin authority, providers, and custom grants', () => {
    expect(resolveCollectionCapabilities(organization({ limitCollectionCreation: false })).canCreate).toBe(true);
    expect(resolveCollectionCapabilities(organization()).canCreate).toBe(false);
    expect(resolveCollectionCapabilities(organization({ type: 0 })).canCreate).toBe(true);
    expect(resolveCollectionCapabilities(organization({ type: 1 })).canCreate).toBe(true);
    expect(resolveCollectionCapabilities(organization({ isProviderUser: true })).canCreate).toBe(true);
    expect(resolveCollectionCapabilities(organization({
      type: 4,
      permissions: { createNewCollections: true },
    })).canCreate).toBe(true);
  });

  it('allows rename through collection management or organization-wide edit authority', () => {
    expect(resolveCollectionCapabilities(organization(), collection({ manage: true })).canRename).toBe(true);
    expect(resolveCollectionCapabilities(
      organization({ type: 4, permissions: { editAnyCollection: true } }),
      collection(),
    ).canRename).toBe(true);
    expect(resolveCollectionCapabilities(
      organization({ type: 1, allowAdminAccessToAllCollectionItems: true }),
      collection(),
    ).canRename).toBe(true);
    expect(resolveCollectionCapabilities(
      organization({ type: 1, allowAdminAccessToAllCollectionItems: false }),
      collection(),
    ).canRename).toBe(false);
  });

  it('never renames default or protected former-default collection names', () => {
    const fullAuthority = organization({
      type: 4,
      permissions: { editAnyCollection: true, deleteAnyCollection: true },
    });
    expect(resolveCollectionCapabilities(fullAuthority, collection({
      type: CollectionTypes.DefaultUserCollection,
      manage: true,
    })).canRename).toBe(false);
    expect(resolveCollectionCapabilities(fullAuthority, collection({
      manage: true,
      defaultUserCollectionEmail: 'offboarded@example.com',
    })).canRename).toBe(false);
  });

  it('combines organization-wide deletion with the managed-collection deletion rule', () => {
    expect(resolveCollectionCapabilities(
      organization({ limitCollectionDeletion: false }),
      collection({ manage: true }),
    ).canDelete).toBe(true);
    expect(resolveCollectionCapabilities(
      organization({ limitCollectionDeletion: true }),
      collection({ manage: true }),
    ).canDelete).toBe(false);
    expect(resolveCollectionCapabilities(
      organization({ type: 1, limitCollectionDeletion: true }),
      collection({ manage: true }),
    ).canDelete).toBe(true);
    expect(resolveCollectionCapabilities(
      organization({ type: 4, permissions: { deleteAnyCollection: true } }),
      collection(),
    ).canDelete).toBe(true);
    expect(resolveCollectionCapabilities(
      organization({ type: 1, allowAdminAccessToAllCollectionItems: true }),
      collection(),
    ).canDelete).toBe(true);
  });

  it('never deletes a DefaultUserCollection even with organization-wide authority', () => {
    expect(resolveCollectionCapabilities(
      organization({ type: 0, allowAdminAccessToAllCollectionItems: true }),
      collection({ type: CollectionTypes.DefaultUserCollection, manage: true }),
    ).canDelete).toBe(false);
    expect(resolveCollectionCapabilities(
      organization({ isProviderUser: true }),
      collection({ type: CollectionTypes.DefaultUserCollection, manage: true }),
    ).canDelete).toBe(false);
  });

  it('allows assignment through all-cipher, manage, or writable assigned authority', () => {
    expect(resolveCollectionCapabilities(
      organization({ type: 4, permissions: { editAnyCollection: true } }),
      collection(),
    ).canAssign).toBe(true);
    expect(resolveCollectionCapabilities(organization(), collection({ manage: true })).canAssign).toBe(true);
    expect(resolveCollectionCapabilities(
      organization(), collection({ assigned: true, readOnly: false }),
    ).canAssign).toBe(true);
    expect(resolveCollectionCapabilities(
      organization(), collection({ assigned: true, readOnly: true }),
    ).canAssign).toBe(false);
    expect(resolveCollectionCapabilities(
      organization(), {
        organizationId: 'org-1',
        type: CollectionTypes.SharedCollection,
        assigned: true,
        manage: false,
      },
    ).canAssign).toBe(true);
  });

  it('accepts Vaultwarden collectionDetails as an assigned collection', () => {
    const vaultwardenCollection = {
      ...collection(),
      assigned: undefined,
      readOnly: false,
      object: 'collectionDetails',
    } as unknown as CollectionAuthority;
    expect(resolveCollectionCapabilities(organization(), vaultwardenCollection).canAssign).toBe(true);
  });

  it('treats Manager as a valid non-admin role whose collection manage grant drives actions', () => {
    expect(resolveCollectionCapabilities(
      organization({ type: 3, limitCollectionDeletion: false }),
      collection({ manage: true, readOnly: true }),
    )).toEqual({ canCreate: false, canRename: true, canDelete: true, canAssign: true });
    expect(resolveCollectionCapabilities(
      organization({ type: 3, limitCollectionDeletion: true }),
      collection({ manage: true }),
    ).canDelete).toBe(false);
  });

  it('uses official nullish defaults and accepts provider rows without direct-member status', () => {
    expect(resolveCollectionCapabilities(
      { id: 'org-1', status: 2, enabled: true, type: 2 },
    ).canCreate).toBe(true);
    expect(resolveCollectionCapabilities(
      { id: 'org-1', status: 2, enabled: true, type: 2 },
      collection({ manage: true }),
    ).canDelete).toBe(true);
    expect(resolveCollectionCapabilities({
      id: 'org-1',
      isProviderUser: true,
    }, collection())).toMatchObject({
      canCreate: true,
      canRename: true,
      canDelete: true,
      canAssign: false,
    });
  });

  it('applies allowAdminAccessToAllCollectionItems only to Owner and Admin roles', () => {
    for (const type of [0, 1] as const) {
      expect(resolveCollectionCapabilities(
        organization({ type, allowAdminAccessToAllCollectionItems: true }),
        collection(),
      )).toMatchObject({ canRename: true, canDelete: true, canAssign: true });
    }
    expect(resolveCollectionCapabilities(
      organization({ type: 2, allowAdminAccessToAllCollectionItems: true }),
      collection(),
    )).toMatchObject({ canRename: false, canDelete: false, canAssign: false });
  });

  it('keeps custom collection grants independent', () => {
    expect(resolveCollectionCapabilities(
      organization({ type: 4, permissions: { createNewCollections: true } }),
      collection(),
    )).toEqual({ canCreate: true, canRename: false, canDelete: false, canAssign: false });
    expect(resolveCollectionCapabilities(
      organization({ type: 4, permissions: { editAnyCollection: true } }),
      collection(),
    )).toEqual({ canCreate: false, canRename: true, canDelete: false, canAssign: true });
    expect(resolveCollectionCapabilities(
      organization({ type: 4, permissions: { deleteAnyCollection: true } }),
      collection(),
    )).toEqual({ canCreate: false, canRename: false, canDelete: true, canAssign: false });
  });

  it('fails closed for inactive memberships, unknown roles, mismatched organizations, and future types', () => {
    const denied = { canCreate: false, canRename: false, canDelete: false, canAssign: false };
    expect(resolveCollectionCapabilities(organization({ status: 1 }), collection({ manage: true }))).toEqual(denied);
    expect(resolveCollectionCapabilities(organization({ enabled: false }), collection({ manage: true }))).toEqual(denied);
    expect(resolveCollectionCapabilities(organization({ type: 99 }), collection({ manage: true }))).toEqual(denied);
    expect(resolveCollectionCapabilities(
      organization(), collection({ organizationId: 'org-2', manage: true }),
    )).toEqual(denied);
    expect(resolveCollectionCapabilities(
      organization(), collection({ type: 99, manage: true }),
    )).toEqual(denied);
  });

  it.each([
    ['limitCollectionCreation', 'yes'],
    ['limitCollectionDeletion', 1],
    ['allowAdminAccessToAllCollectionItems', {}],
    ['isProviderUser', 'true'],
  ])('fails closed for malformed organization field %s', (field, value) => {
    const malformed = { ...organization(), [field]: value } as unknown as CollectionOrganizationAuthority;
    expect(resolveCollectionCapabilities(malformed, collection({ manage: true }))).toEqual({
      canCreate: false,
      canRename: false,
      canDelete: false,
      canAssign: false,
    });
  });

  it('does not invoke inherited or accessor authority', () => {
    const getter = vi.fn(() => 0);
    const withAccessor = Object.defineProperty({
      id: 'org-1',
      status: 2,
      enabled: true,
    }, 'type', { enumerable: true, get: getter });
    const inherited = Object.create(organization()) as CollectionOrganizationAuthority;

    expect(resolveCollectionCapabilities(
      withAccessor as CollectionOrganizationAuthority,
      collection({ manage: true }),
    )).toEqual({ canCreate: false, canRename: false, canDelete: false, canAssign: false });
    expect(resolveCollectionCapabilities(inherited, collection({ manage: true }))).toEqual({
      canCreate: false,
      canRename: false,
      canDelete: false,
      canAssign: false,
    });
    expect(getter).not.toHaveBeenCalled();
  });

  it('returns immutable capability snapshots', () => {
    expect(Object.isFrozen(resolveCollectionCapabilities(
      organization({ type: 1 }),
      collection({ manage: true }),
    ))).toBe(true);
  });
});
