// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { computeFillExclusion, resolveFocusedFill } from './focused-fill.js';

describe('resolveFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('classifies a focused login password field as login', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    pw.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'login' });
  });

  it('classifies a focused card-number field as card', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"></form>';
    const num = document.querySelector<HTMLInputElement>('input[autocomplete="cc-number"]')!;
    num.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
  });

  it('classifies a focused address field as identity', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"><input autocomplete="postal-code"></form>';
    const addr = document.querySelector<HTMLInputElement>('input[autocomplete="street-address"]')!;
    addr.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'identity' });
  });

  it('returns none for a fillable-but-unrecognized field and for the body', () => {
    document.body.innerHTML = '<input type="search">';
    document.querySelector<HTMLInputElement>('input')!.focus();
    expect(resolveFocusedFill(document.activeElement)).toEqual({ kind: 'none' });
    document.body.innerHTML = '';
    expect(resolveFocusedFill(document.body)).toEqual({ kind: 'none' });
  });

  it('resolves a CVC-rendered-as-password field to card, not login (carve-out)', () => {
    document.body.innerHTML = '<form><input autocomplete="username" name="u"><input autocomplete="cc-number" name="c"><input type="password" autocomplete="cc-csc" name="cvc"><button type="submit">Pay</button></form>';
    const cvc = document.querySelector<HTMLInputElement>('input[name="cvc"]')!;
    cvc.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
  });
});

describe('computeFillExclusion', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('excludes real login fields but drops a CVC-as-password login form', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const { loginForms, exclude } = computeFillExclusion();
    expect(loginForms).toHaveLength(1);
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    expect(exclude.has(pw)).toBe(true);
  });
});
