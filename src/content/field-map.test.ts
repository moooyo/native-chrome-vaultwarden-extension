import { describe, expect, it } from 'vitest';
import {
  classifyCardField,
  classifyIdentityField,
  hasCardFieldEvidence,
  type FieldHints,
} from './field-map.js';

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
    expect(classifyCardField(hints({ autocomplete: 'cc-type' }))).toBe('brand');
  });

  it('accepts one normalized card autocomplete role and rejects distinct role conflicts', () => {
    expect(classifyCardField(hints({ autocomplete: 'cc-name cc-given-name' }))).toBe('cardholderName');
    expect(classifyCardField(hints({ autocomplete: 'cc-number cc-csc' }))).toBeUndefined();
    expect(classifyCardField(hints({ autocomplete: 'cc-csc cc-number' }))).toBeUndefined();
  });

  it('falls back to name/id hints', () => {
    expect(classifyCardField(hints({ name: 'cardNumber' }))).toBe('number');
    expect(classifyCardField(hints({ id: 'cvv' }))).toBe('code');
    expect(classifyCardField(hints({ name: 'cardholder-name' }))).toBe('cardholderName');
    expect(classifyCardField(hints({ name: 'payment-card-brand' }))).toBe('brand');
  });

  it('requires non-semantic card hints to resolve to one normalized role', () => {
    expect(classifyCardField(hints({ name: 'cardNumber', id: 'ccnumber' }))).toBe('number');
    expect(classifyCardField(hints({ name: 'cardNumber', placeholder: 'Security code' }))).toBeUndefined();
  });

  it('returns undefined for unrelated fields', () => {
    expect(classifyCardField(hints({ name: 'search' }))).toBeUndefined();
  });

  it('classifies semantic labels only when their card role is unambiguous', () => {
    expect(classifyCardField(hints({ semanticLabels: ['Card number'] }))).toBe('number');
    expect(classifyCardField(hints({ semanticLabels: ['Card number', 'CC number'] }))).toBe('number');
    expect(classifyCardField(hints({ name: 'cardNumber', semanticLabels: ['Card number'] }))).toBe('number');
    expect(classifyCardField(hints({ semanticLabels: ['Card number', 'Card CVC'] }))).toBeUndefined();
    expect(classifyCardField(hints({ semanticLabels: ['Card number / security code'] }))).toBeUndefined();
    expect(classifyCardField(hints({ ariaLabel: 'Card number / CVC' }))).toBeUndefined();
    expect(classifyCardField(hints({ name: 'cardNumber', semanticLabels: ['Card CVC'] }))).toBeUndefined();
    expect(classifyCardField(hints({ name: 'cvv', semanticLabels: ['One-time code'] }))).toBeUndefined();
    expect(hasCardFieldEvidence(hints({ semanticLabels: ['Card number', 'Card CVC'] }))).toBe(true);
  });

  it('keeps specific expiration semantics distinct from a combined expiration field', () => {
    expect(classifyCardField(hints({ semanticLabels: ['Expiration month'] }))).toBe('expMonth');
    expect(classifyCardField(hints({ semanticLabels: ['Expiration year'] }))).toBe('expYear');
    expect(classifyCardField(hints({ semanticLabels: ['Expiration date (MM/YY)'] }))).toBe('exp');
    expect(classifyCardField(hints({ ariaLabel: 'Expiration month' }))).toBe('expMonth');
  });

  it('keeps autocomplete authoritative over bounded semantic fallback', () => {
    expect(classifyCardField(hints({
      autocomplete: 'cc-number',
      semanticLabels: ['Card CVC'],
      semanticLabelsUnsafe: true,
    }))).toBe('number');
  });

  it('fails closed for conflicting TOTP and card-code autocomplete tokens', () => {
    expect(classifyCardField(hints({
      autocomplete: 'section-checkout one-time-code cc-csc',
      name: 'security-code',
    }))).toBeUndefined();
    expect(classifyCardField(hints({
      autocomplete: 'one-time-code',
      name: 'security-code',
    }))).toBeUndefined();
  });
});

describe('identity field classification', () => {
  it('maps standard address/contact autocomplete tokens', () => {
    expect(classifyIdentityField(hints({ autocomplete: 'given-name' }))).toBe('firstName');
    expect(classifyIdentityField(hints({ autocomplete: 'family-name' }))).toBe('lastName');
    expect(classifyIdentityField(hints({ autocomplete: 'shipping street-address' }))).toBe('address');
    expect(classifyIdentityField(hints({ autocomplete: 'address-line2' }))).toBe('address2');
    expect(classifyIdentityField(hints({ autocomplete: 'address-level2' }))).toBe('city');
    expect(classifyIdentityField(hints({ autocomplete: 'postal-code' }))).toBe('postalCode');
    expect(classifyIdentityField(hints({ autocomplete: 'country-name' }))).toBe('country');
    expect(classifyIdentityField(hints({ autocomplete: 'name' }))).toBe('fullName');
    expect(classifyIdentityField(hints({ name: 'mailing-address', type: 'textarea' }))).toBe('address');
  });

  it('accepts one normalized identity autocomplete role and rejects distinct role conflicts', () => {
    expect(classifyIdentityField(hints({ autocomplete: 'country country-name' }))).toBe('country');
    expect(classifyIdentityField(hints({ autocomplete: 'given-name family-name' }))).toBeUndefined();
    expect(classifyIdentityField(hints({ autocomplete: 'family-name given-name' }))).toBeUndefined();
  });

  it('requires non-semantic identity hints to resolve to one normalized role', () => {
    expect(classifyIdentityField(hints({ name: 'first-name', placeholder: 'Given name' }))).toBe('firstName');
    expect(classifyIdentityField(hints({ name: 'first-name', placeholder: 'Last name' }))).toBeUndefined();
  });

  it('does not misclassify "company name" as a full name', () => {
    expect(classifyIdentityField(hints({ name: 'company name' }))).toBe('company');
  });

  it('does not treat a username field as an identity name field', () => {
    // The specific username role must remain distinct from the exact full-name fallback.
    expect(classifyIdentityField(hints({ name: 'username' }))).toBe('username');
  });

  it('classifies semantic identity labels and rejects conflicting roles', () => {
    expect(classifyIdentityField(hints({ semanticLabels: ['First name'] }))).toBe('firstName');
    expect(classifyIdentityField(hints({ semanticLabels: ['First name', 'Given name'] }))).toBe('firstName');
    expect(classifyIdentityField(hints({ name: 'first-name', semanticLabels: ['Given name'] }))).toBe('firstName');
    expect(classifyIdentityField(hints({ semanticLabels: ['First name', 'Last name'] }))).toBeUndefined();
    expect(classifyIdentityField(hints({ semanticLabels: ['First name / Last name'] }))).toBeUndefined();
    expect(classifyIdentityField(hints({ ariaLabel: 'First name / Last name' }))).toBeUndefined();
    expect(classifyIdentityField(hints({ semanticLabels: ['Shipping address line 1'] }))).toBe('address1');
    expect(classifyIdentityField(hints({ semanticLabels: ['Company name'] }))).toBe('company');
    expect(classifyIdentityField(hints({ semanticLabels: ['Email address'] }))).toBe('email');
    expect(classifyIdentityField(hints({
      semanticLabels: ['Street address'],
      semanticLabelsUnsafe: true,
    }))).toBeUndefined();
  });

  it('does not treat email or reserved security fields as identity addresses', () => {
    expect(classifyIdentityField(hints({ name: 'email-address' }))).toBe('email');
    expect(classifyIdentityField(hints({ ariaLabel: 'Email address' }))).toBe('email');
    expect(classifyIdentityField(hints({ autocomplete: 'one-time-code', name: 'first-name' }))).toBeUndefined();
    expect(classifyIdentityField(hints({ autocomplete: 'cc-number', name: 'street-address' }))).toBeUndefined();
  });
});
