import { describe, expect, it } from 'vitest';
import { canManageCollections, toOrgPermission } from './org-permissions.js';
import type { OrganizationResponse } from '../api/types.js';

const org = (over: Partial<OrganizationResponse> & Record<string, any>): OrganizationResponse => ({ id: 'o1', key: 'k', name: 'Acme', status: 2, ...over });

describe('canManageCollections', () => {
  it('is true for a confirmed Owner or Admin regardless of permissions', () => {
    expect(canManageCollections(org({ type: 0 }))).toBe(true);
    expect(canManageCollections(org({ type: 1, permissions: { createNewCollections: false } }))).toBe(true);
  });
  it('is true for Custom only when a collection permission is set', () => {
    expect(canManageCollections(org({ type: 4, permissions: { createNewCollections: true } }))).toBe(true);
    expect(canManageCollections(org({ type: 4, permissions: { editAnyCollection: true } }))).toBe(true);
    expect(canManageCollections(org({ type: 4, permissions: { manageUsers: true } as never }))).toBe(false);
    expect(canManageCollections(org({ type: 4 }))).toBe(false);
  });
  it('is false for a plain User', () => {
    expect(canManageCollections(org({ type: 2 }))).toBe(false);
  });
  it('fails closed on non-confirmed status or unknown/missing type', () => {
    expect(canManageCollections(org({ type: 0, status: 1 }))).toBe(false);
    expect(canManageCollections(org({ type: 0, status: undefined as any }))).toBe(false);
    expect(canManageCollections(org({ type: undefined as any }))).toBe(false);
    expect(canManageCollections(org({ type: 99 }))).toBe(false);
  });
});

describe('toOrgPermission', () => {
  it('maps id/name/gate and falls back for a null name', () => {
    expect(toOrgPermission(org({ type: 0 }))).toEqual({ id: 'o1', name: 'Acme', canManageCollections: true });
    expect(toOrgPermission(org({ type: 2, name: null })))
      .toEqual({ id: 'o1', name: '(unnamed organization)', canManageCollections: false });
  });
});
