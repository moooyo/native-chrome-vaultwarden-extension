import type { CipherResponse } from '../api/types.js';
import type { CipherAccess, CipherSummary, FieldName } from './models.js';

export type CipherAccessAction = keyof CipherAccess;

const PERSONAL_ACCESS: Readonly<CipherAccess> = Object.freeze({
  edit: true,
  viewPassword: true,
  clone: true,
  delete: true,
  restore: true,
  autofillTotp: true,
  viewTotp: true,
});

const PASSWORD_PROTECTED_FIELDS: ReadonlySet<FieldName> = new Set([
  'password',
  'totp',
  'card.number',
  'card.code',
  'identity.ssn',
  'identity.passportNumber',
  'identity.licenseNumber',
]);

/**
 * Project authorization metadata only after the raw cipher compatibility gate has validated the
 * response. Missing, null, or false organization grants all fail closed; personal ownership remains
 * authoritative even on servers that omit every organization-only authorization field.
 */
export function projectValidatedCipherAccess(
  cipher: CipherResponse,
  organizationCloneAllowed = false,
): Readonly<CipherAccess> {
  if (cipher.organizationId == null) return PERSONAL_ACCESS;
  const viewPassword = cipher.viewPassword === true;
  const autofillTotp = cipher.organizationUseTotp === true;
  const edit = cipher.edit === true && viewPassword;
  return Object.freeze({
    edit,
    viewPassword,
    clone: edit && organizationCloneAllowed === true,
    delete: cipher.permissions?.delete === true,
    restore: cipher.permissions?.restore === true,
    autofillTotp,
    viewTotp: autofillTotp && viewPassword,
  });
}

/** Direct getters for these fields expose password-like plaintext and require viewPassword. */
export function isPasswordProtectedField(field: FieldName): boolean {
  return PASSWORD_PROTECTED_FIELDS.has(field);
}

/** UI-only convenience. Organization summaries with a missing or stale projection fail closed. */
export function summaryAllowsCipherAccess(
  summary: Pick<CipherSummary, 'organizationId' | 'access'>,
  action: CipherAccessAction,
): boolean {
  if (summary.organizationId == null) return true;
  if (action === 'edit') {
    return summary.access?.edit === true && summary.access.viewPassword === true;
  }
  if (action === 'viewTotp') {
    return summary.access?.viewTotp === true && summary.access.viewPassword === true;
  }
  return summary.access?.[action] === true;
}
