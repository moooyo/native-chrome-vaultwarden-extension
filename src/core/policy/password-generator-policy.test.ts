import { describe, expect, it } from 'vitest';
import {
  EMPTY_PASSWORD_GENERATOR_POLICY,
  combinePasswordGeneratorPolicyData,
  parsePasswordGeneratorPolicyData,
  passwordGeneratorPolicyInEffect,
} from './password-generator-policy.js';

describe('password generator policy parsing', () => {
  it('parses every official field without treating neutral values as absent', () => {
    expect(parsePasswordGeneratorPolicyData({
      overridePasswordType: '',
      minLength: 0,
      useUpper: false,
      useLower: true,
      useNumbers: false,
      minNumbers: 0,
      useSpecial: true,
      minSpecial: 2,
      minNumberWords: 6,
      capitalize: false,
      includeNumber: true,
    })).toEqual({
      overridePasswordType: '',
      minLength: 0,
      useUpper: false,
      useLower: true,
      useNumbers: false,
      minNumbers: 0,
      useSpecial: true,
      minSpecial: 2,
      minNumberWords: 6,
      capitalize: false,
      includeNumber: true,
    });
  });

  it('treats omitted and nullish fields as official neutral defaults', () => {
    expect(parsePasswordGeneratorPolicyData({ minLength: null, capitalize: undefined }))
      .toEqual(EMPTY_PASSWORD_GENERATOR_POLICY);
  });

  it.each([
    ['missing data', undefined],
    ['array data', []],
    ['unknown override', { overridePasswordType: 'pin' }],
    ['numeric override', { overridePasswordType: 1 }],
    ['string integer', { minLength: '20' }],
    ['negative integer', { minNumbers: -1 }],
    ['fractional integer', { minSpecial: 1.5 }],
    ['unsafe integer', { minNumberWords: Number.MAX_SAFE_INTEGER + 1 }],
    ['numeric boolean', { useNumbers: 1 }],
  ])('rejects %s', (_label, data) => {
    expect(parsePasswordGeneratorPolicyData(data)).toBeNull();
  });
});

describe('password generator policy combination', () => {
  it('takes numeric maxima, boolean ORs, and password over a passphrase conflict', () => {
    const passphrase = parsePasswordGeneratorPolicyData({
      overridePasswordType: 'passphrase',
      minLength: 18,
      useUpper: true,
      minNumbers: 2,
      minNumberWords: 7,
      capitalize: true,
    })!;
    const password = parsePasswordGeneratorPolicyData({
      overridePasswordType: 'password',
      minLength: 24,
      useLower: true,
      useNumbers: true,
      minNumbers: 4,
      useSpecial: true,
      minSpecial: 3,
      includeNumber: true,
    })!;

    expect(combinePasswordGeneratorPolicyData([passphrase, password])).toEqual({
      overridePasswordType: 'password',
      minLength: 24,
      useUpper: true,
      useLower: true,
      useNumbers: true,
      minNumbers: 4,
      useSpecial: true,
      minSpecial: 3,
      minNumberWords: 7,
      capitalize: true,
      includeNumber: true,
    });
  });

  it('is order independent when password and passphrase overrides conflict', () => {
    const password = parsePasswordGeneratorPolicyData({ overridePasswordType: 'password' })!;
    const passphrase = parsePasswordGeneratorPolicyData({ overridePasswordType: 'passphrase' })!;

    expect(combinePasswordGeneratorPolicyData([password, passphrase]).overridePasswordType)
      .toBe('password');
    expect(combinePasswordGeneratorPolicyData([passphrase, password]).overridePasswordType)
      .toBe('password');
  });

  it('reports whether any generator requirement is in effect', () => {
    expect(passwordGeneratorPolicyInEffect(EMPTY_PASSWORD_GENERATOR_POLICY)).toBe(false);
    expect(passwordGeneratorPolicyInEffect({
      ...EMPTY_PASSWORD_GENERATOR_POLICY,
      minNumberWords: 4,
    })).toBe(true);
  });
});
