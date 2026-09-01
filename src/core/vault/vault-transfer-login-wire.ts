export type LoginUriAliasValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'login_uri_alias_mismatch' };

/**
 * Validate the obsolete response-level Login.Uri alias. Current Bitwarden servers either omit it,
 * emit null with no URI, or repeat the first Uris entry byte-for-byte.
 */
export function validateLoginUriAlias(value: unknown): LoginUriAliasValidation {
  if (!isPlainRecord(value)) return { ok: false, code: 'login_uri_alias_mismatch' };
  const alias = ownData(value, 'uri');
  if (alias.kind === 'absent') return { ok: true };
  if (alias.kind === 'invalid') return { ok: false, code: 'login_uri_alias_mismatch' };

  const uris = ownData(value, 'uris');
  const uriValues = uris.kind === 'value' ? uris.value : undefined;
  if (uris.kind === 'invalid' || (uriValues != null && !Array.isArray(uriValues))) {
    return { ok: false, code: 'login_uri_alias_mismatch' };
  }
  const first = Array.isArray(uriValues) && uriValues.length > 0 ? uriValues[0] : undefined;
  let firstUri: OwnData = { kind: 'absent' };
  if (first !== undefined) {
    if (!isPlainRecord(first)) return { ok: false, code: 'login_uri_alias_mismatch' };
    firstUri = ownData(first, 'uri');
    if (firstUri.kind === 'invalid') return { ok: false, code: 'login_uri_alias_mismatch' };
  }

  if (alias.value === null || alias.value === '') {
    const firstValue = firstUri.kind === 'value' ? firstUri.value : undefined;
    return firstValue === undefined || firstValue === null || firstValue === ''
      ? { ok: true }
      : { ok: false, code: 'login_uri_alias_mismatch' };
  }
  if (typeof alias.value !== 'string') {
    return { ok: false, code: 'login_uri_alias_mismatch' };
  }
  return firstUri.kind === 'value' && firstUri.value === alias.value
    ? { ok: true }
    : { ok: false, code: 'login_uri_alias_mismatch' };
}

type OwnData =
  | { kind: 'absent' }
  | { kind: 'invalid' }
  | { kind: 'value'; value: unknown };

function ownData(value: object, key: string): OwnData {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) return { kind: 'absent' };
    if (!descriptor.enumerable || !('value' in descriptor)) return { kind: 'invalid' };
    return { kind: 'value', value: descriptor.value };
  } catch {
    return { kind: 'invalid' };
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}
