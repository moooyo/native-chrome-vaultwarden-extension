// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { isAutofillIgnored } from './autofill-ignore.js';

describe('Bitwarden DOM autofill opt-out', () => {
  it('uses data-bwignore presence regardless of its value', () => {
    const input = document.createElement('input');
    expect(isAutofillIgnored(input)).toBe(false);
    input.setAttribute('data-bwignore', 'false');
    expect(isAutofillIgnored(input)).toBe(true);
    input.removeAttribute('data-bwignore');
    expect(isAutofillIgnored(input)).toBe(false);
  });
});
