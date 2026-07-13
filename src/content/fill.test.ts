// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { detectLoginForms } from './form-detection.js';
import { fillLoginForm } from './fill.js';

describe('fillLoginForm', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('fills username and password and dispatches input/change events', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email">
        <input id="pass" type="password">
      </form>
    `;
    const user = document.getElementById('user') as HTMLInputElement;
    const pass = document.getElementById('pass') as HTMLInputElement;
    const userInput = vi.fn();
    const passChange = vi.fn();
    user.addEventListener('input', userInput);
    pass.addEventListener('change', passChange);

    const form = detectLoginForms()[0]!;
    expect(fillLoginForm(form, { username: 'me@example.com', password: 'secret' })).toBe(true);

    expect(user.value).toBe('me@example.com');
    expect(pass.value).toBe('secret');
    expect(userInput).toHaveBeenCalledTimes(1);
    expect(passChange).toHaveBeenCalledTimes(1);
  });

  it('does not fill disabled or readonly fields', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email" readonly>
        <input id="pass" type="password" disabled>
      </form>
    `;
    expect(detectLoginForms()).toEqual([]);
  });

  it('fills only the username for a username-first form (no password field)', () => {
    document.body.innerHTML = `
      <form><input id="u" type="email" autocomplete="username"><button>Next</button></form>
    `;
    const form = detectLoginForms()[0]!;
    expect(form.passwordInput).toBeUndefined();
    expect(fillLoginForm(form, { username: 'me@example.com', password: 'secret' })).toBe(true);
    expect((document.getElementById('u') as HTMLInputElement).value).toBe('me@example.com');
  });

  it('fills only the current password on a change-password form, never new/confirm', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email" autocomplete="username">
        <input id="cur" type="password" autocomplete="current-password">
        <input id="new" type="password" autocomplete="new-password">
        <input id="confirm" type="password" autocomplete="new-password">
      </form>
    `;
    const form = detectLoginForms()[0]!;
    fillLoginForm(form, { username: 'me@example.com', password: 'secret' });
    expect((document.getElementById('cur') as HTMLInputElement).value).toBe('secret');
    expect((document.getElementById('new') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('confirm') as HTMLInputElement).value).toBe('');
  });

  it('handles a missing passwordInput without throwing', () => {
    document.body.innerHTML = `<form><input id="u" type="email"></form>`;
    const u = document.getElementById('u') as HTMLInputElement;
    const form = { id: 'x', form: null, usernameInput: u, anchor: u };
    expect(() => fillLoginForm(form, { username: 'me@example.com', password: 'secret' })).not.toThrow();
    expect(u.value).toBe('me@example.com');
  });

  it('never writes the stored password into a new-password field (defense-in-depth)', () => {
    document.body.innerHTML = `<form><input id="np" type="password" autocomplete="new-password"></form>`;
    const np = document.getElementById('np') as HTMLInputElement;
    const form = { id: 'x', form: np.form, passwordInput: np, anchor: np };
    fillLoginForm(form, { username: 'me@example.com', password: 'secret' });
    expect(np.value).toBe('');
  });

  it('fills the TOTP code into a one-time-code field alongside the credentials', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email">
        <input id="pass" type="password">
        <input id="otp" type="text" autocomplete="one-time-code">
      </form>
    `;
    const form = detectLoginForms()[0]!;
    expect(fillLoginForm(form, { username: 'me@example.com', password: 'secret', totp: '123456' })).toBe(true);
    expect((document.getElementById('otp') as HTMLInputElement).value).toBe('123456');
  });

  it('fills only the TOTP code on a standalone verification step', () => {
    document.body.innerHTML = `
      <form><input id="otp" type="text" autocomplete="one-time-code" name="otp"><button>Verify</button></form>
    `;
    const form = detectLoginForms()[0]!;
    expect(form.passwordInput).toBeUndefined();
    expect(fillLoginForm(form, { totp: '654321' })).toBe(true);
    expect((document.getElementById('otp') as HTMLInputElement).value).toBe('654321');
  });

  it('leaves a one-time-code field empty when the credentials carry no TOTP code', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email"><input id="pass" type="password">
        <input id="otp" type="text" autocomplete="one-time-code">
      </form>
    `;
    const form = detectLoginForms()[0]!;
    fillLoginForm(form, { username: 'me@example.com', password: 'secret' });
    expect((document.getElementById('otp') as HTMLInputElement).value).toBe('');
  });
});
