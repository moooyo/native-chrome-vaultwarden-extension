import { describe, expect, it } from 'vitest';
import { classifyCardField, classifyIdentityField, type FieldHints } from './field-map.js';

function hints(partial: Partial<FieldHints>): FieldHints {
  return { autocomplete: '', name: '', id: '', ariaLabel: '', placeholder: '', type: 'text', ...partial };
}

describe('card field classification', () => {
  it('maps cc-* autocomplete tokens, including a billing section prefix', () => {
    expect(classifyCardField(hints({ autocomplete: 'cc-number' }))).toBe('number');
    expect(classifyCardField(hints({ autocomplete: 'billing cc-csc' }))).toBe('code');
    expect(classifyCardField(hints({ autocomplete: 'cc-exp' }))).toBe('exp');
    expect(classifyCardField(hints({ autocomplete: 'cc-exp-month' }))).toBe('expMonth');
    expect(classifyCardField(hints({ autocomplete: 'cc-name' }))).toBe('cardholderName');
  });

  it('falls back to name/id hints', () => {
    expect(classifyCardField(hints({ name: 'cardNumber' }))).toBe('number');
    expect(classifyCardField(hints({ id: 'cvv' }))).toBe('code');
    expect(classifyCardField(hints({ name: 'cardholder-name' }))).toBe('cardholderName');
  });

  it('returns undefined for unrelated fields', () => {
    expect(classifyCardField(hints({ name: 'search' }))).toBeUndefined();
  });
});

describe('identity field classification', () => {
  it('maps standard address/contact autocomplete tokens', () => {
    expect(classifyIdentityField(hints({ autocomplete: 'given-name' }))).toBe('firstName');
    expect(classifyIdentityField(hints({ autocomplete: 'family-name' }))).toBe('lastName');
    expect(classifyIdentityField(hints({ autocomplete: 'shipping street-address' }))).toBe('address1');
    expect(classifyIdentityField(hints({ autocomplete: 'address-line2' }))).toBe('address2');
    expect(classifyIdentityField(hints({ autocomplete: 'address-level2' }))).toBe('city');
    expect(classifyIdentityField(hints({ autocomplete: 'postal-code' }))).toBe('postalCode');
    expect(classifyIdentityField(hints({ autocomplete: 'country-name' }))).toBe('country');
    expect(classifyIdentityField(hints({ autocomplete: 'name' }))).toBe('fullName');
  });

  it('does not misclassify "company name" as a full name', () => {
    expect(classifyIdentityField(hints({ name: 'company name' }))).toBe('company');
  });

  it('does not treat a username field as an identity name field', () => {
    // \bname\b must not match inside "username"
    expect(classifyIdentityField(hints({ name: 'username' }))).toBe('username');
  });
});
