import { describe, expect, it } from 'vitest';
import {
  canManageCollections,
  toContextualOrgPermission,
  toOrgPermission,
} from './org-permissions.js';
import type { OrganizationResponse } from '../api/types.js';

const org = (over: Partial<OrganizationResponse> & Record<string, unknown>): OrganizationResponse => ({ id: 'o1', key: 'k', name: 'Acme', status: 2, ...over });

const noCollectionPermissions = {
  canCreateCollections: false,
  canEditCollections: false,
  canDeleteCollections: false,
  canManageCollections: false,
};

const allCollectionPermissions = {
  canCreateCollections: true,
  canEditCollections: true,
  canDeleteCollections: true,
  canManageCollections: true,
};

describe('toOrgPermission', () => {
  it('grants every operation to confirmed Owners and Admins regardless of API flags', () => {
    expect(toOrgPermission(org({ type: 0 }))).toEqual({
      id: 'o1',
      name: 'Acme',
      ...allCollectionPermissions,
    });
    expect(toOrgPermission(org({
      type: 1,
      permissions: {
        createNewCollections: false,
        editAnyCollection: false,
        deleteAnyCollection: false,
      },
    }))).toEqual({
      id: 'o1',
      name: 'Acme',
      ...allCollectionPermissions,
    });
  });

  it.each([
    ['create-only', { createNewCollections: true }, {
      canCreateCollections: true,
      canEditCollections: false,
      canDeleteCollections: false,
      canManageCollections: true,
    }],
    ['edit-only', { editAnyCollection: true }, {
      canCreateCollections: false,
      canEditCollections: true,
      canDeleteCollections: false,
      canManageCollections: true,
    }],
    ['delete-only', { deleteAnyCollection: true }, {
      canCreateCollections: false,
      canEditCollections: false,
      canDeleteCollections: true,
      canManageCollections: true,
    }],
    ['no', {}, noCollectionPermissions],
  ])('maps Custom %s collection permissions independently', (_label, permissions, expected) => {
    expect(toOrgPermission(org({ type: 4, permissions }))).toEqual({
      id: 'o1',
      name: 'Acme',
      ...expected,
    });
  });

  it('fails closed for User, legacy Manager, and unknown roles even if stale flags are present', () => {
    const permissions = {
      createNewCollections: true,
      editAnyCollection: true,
      deleteAnyCollection: true,
    };
    for (const type of [2, 3, 99]) {
      expect(toOrgPermission(org({ type, permissions }))).toEqual({
        id: 'o1',
        name: 'Acme',
        ...noCollectionPermissions,
      });
    }
  });

  it('fails closed for non-confirmed membership and falls back for a null name', () => {
    expect(toOrgPermission(org({ type: 0, status: 1, name: null }))).toEqual({
      id: 'o1',
      name: '(unnamed organization)',
      ...noCollectionPermissions,
    });
    expect(toOrgPermission(org({ type: 0, status: undefined as never }))).toMatchObject(noCollectionPermissions);
    expect(toOrgPermission(org({ type: undefined as never }))).toMatchObject(noCollectionPermissions);
  });
});

describe('canManageCollections', () => {
  it('retains an aggregate compatibility gate without widening individual grants', () => {
    expect(canManageCollections(org({ type: 4, permissions: { createNewCollections: true } }))).toBe(true);
    expect(canManageCollections(org({ type: 4, permissions: { editAnyCollection: true } }))).toBe(true);
    expect(canManageCollections(org({ type: 4, permissions: { deleteAnyCollection: true } }))).toBe(true);
    expect(canManageCollections(org({ type: 4 }))).toBe(false);
    expect(canManageCollections(org({ type: 2 }))).toBe(false);
  });
});

describe('organization create projection', () => {
  it('permits only enabled, confirmed, direct members with a decoded organization key', () => {
    expect(toContextualOrgPermission(org({ type: 2, enabled: true }), {
      isMember: true,
      isProviderUser: true,
      keyAvailable: true,
    })).toMatchObject({
      isMember: true,
      isProviderUser: true,
      canCreateItems: true,
    });

    for (const permission of [
      toContextualOrgPermission(org({ type: 2, enabled: false }), {
        isMember: true, isProviderUser: false, keyAvailable: true,
      }),
      toContextualOrgPermission(org({ type: 2, enabled: true, status: 1 }), {
        isMember: true, isProviderUser: false, keyAvailable: true,
      }),
      toContextualOrgPermission(org({ type: 0, enabled: true }), {
        isMember: false, isProviderUser: true, keyAvailable: true,
      }),
      toContextualOrgPermission(org({ type: 2, enabled: true }), {
        isMember: true, isProviderUser: false, keyAvailable: false,
      }),
    ]) {
      expect(permission.canCreateItems).toBe(false);
    }
  });

  it('does not widen the legacy projection before service integration supplies context', () => {
    expect(toOrgPermission(org({ type: 0, enabled: true }))).not.toHaveProperty('canCreateItems');
  });
});
