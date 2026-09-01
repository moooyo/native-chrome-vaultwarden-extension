import { describe, expect, it } from 'vitest';

import {
  DEFAULT_MASTER_PASSWORD_MIN_LENGTH,
  captureMasterPasswordEvidence,
  combineMasterPasswordPolicies,
  evaluateMasterPasswordEvidence,
  evaluateMasterPasswordPolicy,
  isNewMasterPasswordLengthAllowed,
  masterPasswordHintValidationError,
  mergePasswordChangeRequirement,
  newMasterPasswordMinimumLength,
  parseMasterPasswordEvidence,
  parseMasterPasswordPolicy,
  weakPasswordRequirement,
} from './master-password-policy.js';

describe('master password policy', () => {
  it('validates hints with the official raw case-sensitive comparison', () => {
    expect(masterPasswordHintValidationError('', 'new-password')).toBeUndefined();
    expect(masterPasswordHintValidationError('new-password', 'new-password')).toBe('matchesPassword');
    expect(masterPasswordHintValidationError('NEW-PASSWORD', 'new-password')).toBeUndefined();
    expect(masterPasswordHintValidationError(' new-password ', 'new-password')).toBeUndefined();
    expect(masterPasswordHintValidationError('x'.repeat(50), 'new-password')).toBeUndefined();
    expect(masterPasswordHintValidationError('x'.repeat(51), 'new-password')).toBe('tooLong');
    expect(masterPasswordHintValidationError(undefined, 'new-password')).toBe('invalid');
  });

  it('uses the official 12-character default and lets stronger policy raise it', () => {
    expect(DEFAULT_MASTER_PASSWORD_MIN_LENGTH).toBe(12);
    expect(newMasterPasswordMinimumLength()).toBe(12);
    expect(isNewMasterPasswordLengthAllowed('a'.repeat(11))).toBe(false);
    expect(isNewMasterPasswordLengthAllowed('a'.repeat(12))).toBe(true);
    expect(newMasterPasswordMinimumLength({ minLength: 20 })).toBe(20);
    expect(isNewMasterPasswordLengthAllowed('a'.repeat(19), { minLength: 20 })).toBe(false);
    expect(isNewMasterPasswordLengthAllowed('a'.repeat(20), { minLength: 20 })).toBe(true);
  });

  it('parses PascalCase Identity fields, the official object discriminator, and omitted controls', () => {
    expect(parseMasterPasswordPolicy({
      Object: 'masterPasswordPolicy',
      MinLength: 14,
      EnforceOnLogin: true,
    })).toEqual({
      minComplexity: 0,
      minLength: 14,
      requireUpper: false,
      requireLower: false,
      requireNumbers: false,
      requireSpecial: false,
      enforceOnLogin: true,
    });
  });

  it.each([
    { MinLength: '14' },
    { MinComplexity: 5 },
    { RequireUpper: 1 },
    { EnforceOnLogin: 'true' },
    { Object: 'unexpectedPolicy' },
    { Object: 'masterPasswordPolicy', object: 'masterPasswordPolicy' },
    { MinLength: 12, minLength: 12 },
    { MinLength: 12, unexpected: false },
  ])('rejects malformed policy data', (input) => {
    expect(() => parseMasterPasswordPolicy(input)).toThrow();
  });

  it('enforces the official character set and zxcvbn score', () => {
    const policy = parseMasterPasswordPolicy({
      MinComplexity: 3,
      MinLength: 12,
      RequireUpper: true,
      RequireLower: true,
      RequireNumbers: true,
      RequireSpecial: true,
      EnforceOnLogin: true,
    });
    expect(evaluateMasterPasswordPolicy('password123!', 'user@example.com', policy)).toBe(false);
    expect(evaluateMasterPasswordPolicy('V7!gQ2@zL9#pR4$x', 'user@example.com', policy)).toBe(true);
    expect(weakPasswordRequirement('password123!', 'user@example.com', policy)?.reason)
      .toBe('weakMasterPassword');
  });

  it('gives the server administrator reset priority over a weak-password result', () => {
    const policy = parseMasterPasswordPolicy({ MinLength: 20, EnforceOnLogin: true });
    const weak = weakPasswordRequirement('short', 'user@example.com', policy);
    expect(mergePasswordChangeRequirement(weak, true, policy)?.reason)
      .toBe('adminForcePasswordReset');
  });

  it('combines staged policies with numeric maxima and boolean OR semantics', () => {
    const first = parseMasterPasswordPolicy({
      MinComplexity: 2,
      MinLength: 14,
      RequireUpper: true,
    });
    const second = parseMasterPasswordPolicy({
      MinComplexity: 4,
      MinLength: 10,
      RequireNumbers: true,
      EnforceOnLogin: true,
    });

    expect(combineMasterPasswordPolicies(first, second)).toEqual({
      minComplexity: 4,
      minLength: 14,
      requireUpper: true,
      requireLower: false,
      requireNumbers: true,
      requireSpecial: false,
      enforceOnLogin: true,
    });
  });

  it('round-trips only bounded secret-free evidence and re-evaluates later policy', () => {
    const password = 'Known-Password-7!';
    const evidence = captureMasterPasswordEvidence(password, 'user@example.com');
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain(password);
    expect(parseMasterPasswordEvidence(JSON.parse(serialized))).toEqual(evidence);
    expect(evaluateMasterPasswordEvidence(evidence, parseMasterPasswordPolicy({
      MinLength: 20,
      EnforceOnLogin: true,
    }))).toBe(false);
    expect(() => parseMasterPasswordEvidence({ ...evidence, plaintext: password })).toThrow();
  });
});
