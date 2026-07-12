// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { detectRegistrationFields, matchRegistrationField } from './registration-detection.js';

function form(html: string): HTMLFormElement {
  const wrap = document.createElement('div');
  wrap.innerHTML = `<form>${html}</form>`;
  document.body.append(wrap);
  return wrap.querySelector('form')!;
}

afterEach(() => document.body.replaceChildren());

describe('registration-detection', () => {
  it('detects a signup new-password field and resolves the username field', () => {
    const f = form(`
      <input type="email" name="email" autocomplete="email" />
      <input type="password" name="password" autocomplete="new-password" />
      <input type="password" name="confirm" autocomplete="new-password" />
      <button type="submit">Create</button>
    `);
    const targets = detectRegistrationFields(document);
    expect(targets).toHaveLength(1);
    expect(targets[0]!.input).toBe(f.querySelector('[name="password"]'));
    expect(targets[0]!.usernameInput).toBe(f.querySelector('[name="email"]'));
  });

  it('excludes confirm/retype fields', () => {
    const f = form(`<input type="password" name="confirm-password" autocomplete="new-password" />`);
    expect(matchRegistrationField(f.querySelector('input')!)).toBeUndefined();
  });

  it('ignores current-password (login) fields', () => {
    const f = form(`<input type="password" name="password" autocomplete="current-password" />`);
    expect(matchRegistrationField(f.querySelector('input')!)).toBeUndefined();
  });

  it('matches a bare new-password field by hint', () => {
    const f = form(`<input type="password" name="newPassword" />`);
    const match = matchRegistrationField(f.querySelector('input')!);
    expect(match).not.toBeUndefined();
    expect(match!.input).toBe(f.querySelector('input'));
  });
});
