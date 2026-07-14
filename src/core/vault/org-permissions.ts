import type { OrganizationResponse } from '../api/types.js';

/** Minimal role summary carried to the popup so it can gate collection-management controls. */
export interface OrgPermission {
  id: string;
  name: string;
  canManageCollections: boolean;
}

/** UI gate: may this user manage collections in this org at all? This is intentionally a single
 *  COARSE boolean: for a Custom member it is true when ANY of create / edit-any / delete-any is
 *  granted, so a create-only member reads as "can manage". It is not split into create vs
 *  edit/delete because the sole consumer only needs the coarse entry-point gate; the server enforces
 *  the specific operation and rejects anything the member lacks. FAILS CLOSED; the server remains the
 *  final authority on every operation. */
export function canManageCollections(org: OrganizationResponse): boolean {
  if (org.status !== 2) return false; // Confirmed members only
  const type = org.type;
  if (type === 0 || type === 1) return true; // Owner / Admin — gated by type, not permissions
  if (type === 3) return true; // Manager — harmless fallback; Vaultwarden actually remaps this to Custom(4)
  if (type === 4) {
    const p = org.permissions;
    // Coarse OR: any collection-management grant surfaces the control; the server gates the exact op.
    return Boolean(p?.createNewCollections || p?.editAnyCollection || p?.deleteAnyCollection);
  }
  return false; // User(2), undefined, or any unknown value
}

export function toOrgPermission(org: OrganizationResponse): OrgPermission {
  return {
    id: org.id,
    name: org.name ?? '(unnamed organization)',
    canManageCollections: canManageCollections(org),
  };
}
