const ORGANIZATION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export type VaultTransferExportTarget =
  | { readonly kind: 'personal' }
  | { readonly kind: 'organization'; readonly organizationId: string };

export const PERSONAL_VAULT_TRANSFER_EXPORT_TARGET: VaultTransferExportTarget =
  Object.freeze({ kind: 'personal' });

/** Canonicalize one untrusted export target without retaining its caller-owned object. */
export function canonicalizeVaultTransferExportTarget(
  value: unknown,
): VaultTransferExportTarget {
  if (!isPlainRecord(value)) throw new TypeError('Vault transfer export target must be an object');
  const keys = Object.keys(value);
  const kind = ownDataValue(value, 'kind');
  if (kind === 'personal') {
    if (keys.length !== 1 || keys[0] !== 'kind') {
      throw new TypeError('Personal vault transfer export target is invalid');
    }
    return PERSONAL_VAULT_TRANSFER_EXPORT_TARGET;
  }
  if (kind !== 'organization'
    || keys.length !== 2
    || !keys.includes('kind')
    || !keys.includes('organizationId')) {
    throw new TypeError('Organization vault transfer export target is invalid');
  }
  return Object.freeze({
    kind: 'organization',
    organizationId: canonicalizeVaultTransferOrganizationId(ownDataValue(value, 'organizationId')),
  });
}

function ownDataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
    throw new TypeError('Vault transfer export target contains an invalid property');
  }
  return descriptor.value;
}

export function canonicalizeVaultTransferOrganizationId(value: unknown): string {
  if (typeof value !== 'string' || !ORGANIZATION_ID_PATTERN.test(value)) {
    throw new TypeError('Organization id must be a UUID');
  }
  return value.toLowerCase();
}

export function sameVaultTransferExportTarget(
  left: VaultTransferExportTarget,
  right: VaultTransferExportTarget,
): boolean {
  return left.kind === right.kind
    && (left.kind === 'personal'
      || (right.kind === 'organization' && left.organizationId === right.organizationId));
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}
