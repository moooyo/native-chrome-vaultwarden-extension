export const CARD_FILL_ROLES = Object.freeze([
  'cardholderName',
  'brand',
  'number',
  'exp',
  'expMonth',
  'expYear',
  'code',
] as const);

export const IDENTITY_FILL_ROLES = Object.freeze([
  'title',
  'firstName',
  'middleName',
  'lastName',
  'fullName',
  'address',
  'address1',
  'address2',
  'address3',
  'city',
  'state',
  'postalCode',
  'country',
  'company',
  'email',
  'phone',
  'username',
] as const);

export type FillKind = 'card' | 'identity';
export type CardFillRole = (typeof CARD_FILL_ROLES)[number];
export type IdentityFillRole = (typeof IDENTITY_FILL_ROLES)[number];
export type FillRole = CardFillRole | IdentityFillRole;
export type StructuredFillRole = FillRole;
export type CardFillDataKey = 'cardholderName' | 'brand' | 'number' | 'expMonth' | 'expYear' | 'code';
export type IdentityFillDataKey = Exclude<IdentityFillRole, 'fullName' | 'address'>;
export type FillDataKey = CardFillDataKey | IdentityFillDataKey;

export const MAX_FILL_ROLES = 16;

/**
 * Validate untrusted wire roles and return a deduplicated, stable canonical ordering. The raw input
 * is bounded before allocation so a renderer cannot use duplicate roles to create unbounded work.
 */
export function normalizeFillRoles(kind: 'card', value: unknown): readonly CardFillRole[] | undefined;
export function normalizeFillRoles(kind: 'identity', value: unknown): readonly IdentityFillRole[] | undefined;
export function normalizeFillRoles(kind: FillKind, value: unknown): readonly FillRole[] | undefined;
export function normalizeFillRoles(kind: FillKind, value: unknown): readonly FillRole[] | undefined {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FILL_ROLES) return undefined;
  const allowed: readonly FillRole[] = kind === 'card' ? CARD_FILL_ROLES : IDENTITY_FILL_ROLES;
  const allowedSet = new Set<FillRole>(allowed);
  const requested = new Set<FillRole>();
  for (const role of value) {
    if (typeof role !== 'string' || !allowedSet.has(role as FillRole)) return undefined;
    requested.add(role as FillRole);
  }
  return Object.freeze(allowed.filter((role) => requested.has(role)));
}

export function equalFillRoles(
  kind: FillKind,
  first: unknown,
  second: unknown,
): boolean {
  const left = normalizeFillRoles(kind, first);
  const right = normalizeFillRoles(kind, second);
  return left !== undefined
    && right !== undefined
    && left.length === right.length
    && left.every((role, index) => role === right[index]);
}

/** Return the only data properties that may be released for a validated canonical role set. */
export function fillDataKeysForRoles(
  kind: FillKind,
  roles: unknown,
): readonly FillDataKey[] | undefined {
  const normalized = normalizeFillRoles(kind, roles);
  if (!normalized) return undefined;
  const requested = new Set<FillDataKey>();
  for (const role of normalized) {
    if (kind === 'card') {
      if (role === 'exp') {
        requested.add('expMonth');
        requested.add('expYear');
      } else {
        requested.add(role as CardFillDataKey);
      }
    } else if (role === 'fullName') {
      requested.add('firstName');
      requested.add('middleName');
      requested.add('lastName');
    } else if (role === 'address') {
      requested.add('address1');
      requested.add('address2');
      requested.add('address3');
    } else {
      requested.add(role as IdentityFillDataKey);
    }
  }
  const order: readonly FillDataKey[] = kind === 'card'
    ? ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code']
    : IDENTITY_FILL_ROLES.filter((role): role is IdentityFillDataKey => role !== 'fullName' && role !== 'address');
  return Object.freeze(order.filter((key) => requested.has(key)));
}
