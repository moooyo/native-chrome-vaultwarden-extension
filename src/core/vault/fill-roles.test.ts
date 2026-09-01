import { describe, expect, it } from 'vitest';
import { fillDataKeysForRoles, MAX_FILL_ROLES, normalizeFillRoles } from './fill-roles.js';

describe('normalizeFillRoles', () => {
  it('deduplicates valid roles into a stable canonical order', () => {
    expect(normalizeFillRoles('card', ['code', 'brand', 'number', 'code'])).toEqual(['brand', 'number', 'code']);
    expect(normalizeFillRoles('identity', ['postalCode', 'firstName', 'postalCode']))
      .toEqual(['firstName', 'postalCode']);
  });

  it('rejects empty, cross-kind, unknown, and oversized role arrays', () => {
    expect(normalizeFillRoles('card', [])).toBeUndefined();
    expect(normalizeFillRoles('card', ['firstName'])).toBeUndefined();
    expect(normalizeFillRoles('identity', ['passportNumber'])).toBeUndefined();
    expect(normalizeFillRoles('identity', Array.from({ length: MAX_FILL_ROLES + 1 }, () => 'email')))
      .toBeUndefined();
  });

  it('expands only the composite data required by expiry and full-name controls', () => {
    expect(fillDataKeysForRoles('card', ['brand', 'number', 'exp'])).toEqual(['brand', 'number', 'expMonth', 'expYear']);
    expect(fillDataKeysForRoles('card', ['expMonth'])).toEqual(['expMonth']);
    expect(fillDataKeysForRoles('card', ['expYear'])).toEqual(['expYear']);
    expect(fillDataKeysForRoles('identity', ['fullName', 'email']))
      .toEqual(['firstName', 'middleName', 'lastName', 'email']);
    expect(fillDataKeysForRoles('identity', ['address', 'postalCode']))
      .toEqual(['address1', 'address2', 'address3', 'postalCode']);
  });
});
