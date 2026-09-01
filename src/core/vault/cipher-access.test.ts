import { describe, expect, it } from 'vitest';
import type { CipherResponse } from '../api/types.js';
import {
  isPasswordProtectedField,
  projectValidatedCipherAccess,
  summaryAllowsCipherAccess,
} from './cipher-access.js';

function cipher(overrides: Partial<CipherResponse> = {}): CipherResponse {
  return { id: 'cipher-1', type: 1, name: '2.encrypted', login: {}, ...overrides };
}

describe('cipher access projection', () => {
  it('keeps personal item behavior independent of omitted server authorization metadata', () => {
    expect(projectValidatedCipherAccess(cipher({ organizationId: null }))).toEqual({
      edit: true,
      viewPassword: true,
      clone: true,
      delete: true,
      restore: true,
      autofillTotp: true,
      viewTotp: true,
    });
  });

  it('fails closed for every missing organization grant', () => {
    expect(projectValidatedCipherAccess(cipher({ organizationId: 'org-1' }))).toEqual({
      edit: false,
      viewPassword: false,
      clone: false,
      delete: false,
      restore: false,
      autofillTotp: false,
      viewTotp: false,
    });
  });

  it('projects only exact true organization grants', () => {
    expect(projectValidatedCipherAccess(cipher({
      organizationId: 'org-1',
      edit: true,
      viewPassword: true,
      organizationUseTotp: true,
      permissions: { delete: true, restore: true },
    }))).toEqual({
      edit: true,
      viewPassword: true,
      clone: false,
      delete: true,
      restore: true,
      autofillTotp: true,
      viewTotp: true,
    });
    expect(projectValidatedCipherAccess(cipher({
      organizationId: 'org-1',
      edit: false,
      viewPassword: false,
      organizationUseTotp: false,
      permissions: { delete: null, restore: null },
    }))).toEqual({
      edit: false,
      viewPassword: false,
      clone: false,
      delete: false,
      restore: false,
      autofillTotp: false,
      viewTotp: false,
    });
  });

  it('requires viewPassword for edit and visible TOTP while preserving controlled TOTP autofill', () => {
    expect(projectValidatedCipherAccess(cipher({
      organizationId: 'org-1',
      edit: true,
      viewPassword: false,
      organizationUseTotp: true,
    }))).toEqual({
      edit: false,
      viewPassword: false,
      clone: false,
      delete: false,
      restore: false,
      autofillTotp: true,
      viewTotp: false,
    });
  });

  it('projects organization clone only from an explicit current authorization result', () => {
    const source = cipher({ organizationId: 'org-1', edit: true, viewPassword: true });
    expect(projectValidatedCipherAccess(source, true).clone).toBe(true);
    expect(projectValidatedCipherAccess(source, false).clone).toBe(false);
    expect(projectValidatedCipherAccess({ ...source, viewPassword: false }, true).clone).toBe(false);
  });

  it('classifies every direct password-like field consistently', () => {
    for (const field of [
      'password', 'totp', 'card.number', 'card.code',
      'identity.ssn', 'identity.passportNumber', 'identity.licenseNumber',
    ] as const) expect(isPasswordProtectedField(field)).toBe(true);
    expect(isPasswordProtectedField('username')).toBe(false);
    expect(isPasswordProtectedField('notes')).toBe(false);
  });

  it('treats a missing organization summary projection as denied while preserving personal access', () => {
    expect(summaryAllowsCipherAccess({ organizationId: 'org-1' }, 'edit')).toBe(false);
    expect(summaryAllowsCipherAccess({ organizationId: 'org-1' }, 'clone')).toBe(false);
    expect(summaryAllowsCipherAccess({}, 'edit')).toBe(true);
    expect(summaryAllowsCipherAccess({}, 'clone')).toBe(true);
    expect(summaryAllowsCipherAccess({ organizationId: 'org-1', access: {
      edit: true,
      viewPassword: false,
      delete: false,
      restore: false,
      autofillTotp: false,
      viewTotp: false,
    } }, 'edit')).toBe(false);
  });
});
