// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectCardForms, detectIdentityForms } from './field-detection.js';

describe('card form detection', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('detects a card form when a card-number field is present', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-name">
        <input autocomplete="cc-number">
        <input autocomplete="cc-exp">
        <input autocomplete="cc-csc">
      </form>`;
    const forms = detectCardForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.kind).toBe('card');
    expect(forms[0]?.fields.has('number')).toBe(true);
    expect(forms[0]?.fields.has('code')).toBe(true);
  });

  it('does not detect a card form without a number field', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-csc"></form>`;
    expect(detectCardForms()).toEqual([]);
  });
});

describe('identity form detection (conservative)', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('detects an identity form when an address signal is present', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="given-name">
        <input autocomplete="family-name">
        <input autocomplete="street-address">
        <input autocomplete="postal-code">
      </form>`;
    const forms = detectIdentityForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.fields.has('address1')).toBe(true);
  });

  it('detects an identity form on a first+last name pair without an address', () => {
    document.body.innerHTML = `
      <form><input autocomplete="given-name"><input autocomplete="family-name"></form>`;
    expect(detectIdentityForms()).toHaveLength(1);
  });

  it('does not fire on a lone email/subscribe field', () => {
    document.body.innerHTML = `<form><input type="email" autocomplete="email"></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('skips fields in the exclude set (already claimed by login detection)', () => {
    document.body.innerHTML = `
      <form>
        <input id="u" type="email" autocomplete="email">
        <input autocomplete="given-name">
        <input autocomplete="family-name">
      </form>`;
    const email = document.getElementById('u') as HTMLInputElement;
    const forms = detectIdentityForms(document, new Set([email]));
    expect(forms[0]?.fields.has('email')).toBe(false);
    expect(forms[0]?.fields.has('firstName')).toBe(true);
  });
});
