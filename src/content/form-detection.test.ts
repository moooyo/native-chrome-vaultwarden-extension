// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectLoginForms, isFillableInput } from './form-detection.js';

describe('form detection', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('detects a visible login form with username and password fields', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username" value="">
        <input type="password" autocomplete="current-password" value="">
      </form>
    `;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.type).toBe('email');
    expect(forms[0]?.passwordInput?.type).toBe('password');
  });

  it('ignores hidden, disabled, and readonly password fields', () => {
    document.body.innerHTML = `
      <input type="password" hidden>
      <input type="password" disabled>
      <input type="password" readonly>
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('uses a nearby username field when inputs are not inside a form element', () => {
    document.body.innerHTML = `
      <section>
        <input type="text" name="user">
        <div><input type="password" name="pass"></div>
      </section>
    `;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.name).toBe('user');
  });

  it('checks fillable input state directly', () => {
    const input = document.createElement('input');
    input.type = 'password';
    expect(isFillableInput(input)).toBe(false);
    document.body.appendChild(input);
    expect(isFillableInput(input)).toBe(true);
    input.readOnly = true;
    expect(isFillableInput(input)).toBe(false);
  });

  it('ignores inputs hidden by CSS display:none', () => {
    document.body.innerHTML = `
      <input type="password" style="display:none">
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('ignores inputs hidden by a CSS-hidden ancestor', () => {
    document.body.innerHTML = `
      <form style="display:none">
        <input type="email">
        <input type="password">
      </form>
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('ignores inputs hidden by visibility:hidden even when they have layout', () => {
    document.body.innerHTML = `
      <form style="visibility:hidden">
        <input type="email">
        <input type="password">
      </form>
    `;
    for (const input of document.querySelectorAll('input')) {
      Object.defineProperty(input, 'offsetParent', { configurable: true, value: document.body });
    }

    expect(detectLoginForms()).toEqual([]);
  });

  it('detects a username-first login step that has no password field yet', () => {
    document.body.innerHTML = `
      <form><input type="email" autocomplete="username"><button>Next</button></form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.type).toBe('email');
    expect(forms[0]?.passwordInput).toBeUndefined();
  });

  it('does not treat a lone non-login text field as a login step', () => {
    document.body.innerHTML = `<div><input type="search" name="q"></div>`;
    expect(detectLoginForms()).toEqual([]);
  });

  it('requires a submit affordance for a non-form username-only step', () => {
    document.body.innerHTML = `<section><input type="text" name="username"></section>`;
    expect(detectLoginForms()).toEqual([]);

    document.body.innerHTML = `<section><input type="text" name="username"><button>Continue</button></section>`;
    expect(detectLoginForms()).toHaveLength(1);
  });

  it('collapses a change-password form to one form whose passwordInput is the current password', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" autocomplete="current-password" id="cur">
        <input type="password" autocomplete="new-password" id="new">
        <input type="password" autocomplete="new-password" id="confirm">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.id).toBe('cur');
  });

  it('identifies the current password by name hints when autocomplete is absent', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="oldPassword">
        <input type="password" name="newPassword">
        <input type="password" name="confirmPassword">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.getAttribute('name')).toBe('oldPassword');
  });

  it('still detects an ordinary single-password login with a defined passwordInput', () => {
    document.body.innerHTML = `
      <form><input type="email" autocomplete="username"><input type="password" autocomplete="current-password"></form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.type).toBe('password');
    expect(forms[0]?.usernameInput?.type).toBe('email');
  });

  it('emits no fillable password form when every password field is a new-password field (sign-up)', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username">
        <input type="password" autocomplete="new-password" id="pw">
        <input type="password" autocomplete="new-password" id="confirm">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms.some((f) => f.passwordInput)).toBe(false);
  });

  it('emits no password form for a single new-password reset field', () => {
    document.body.innerHTML = `<form><input type="password" autocomplete="new-password" name="newPassword"></form>`;
    expect(detectLoginForms()).toEqual([]);
  });

  it('does not select a new-password field as current when current-password is also present', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="newPassword">
        <input type="password" autocomplete="current-password" id="cur">
        <input type="password" name="confirmPassword">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.id).toBe('cur');
  });

  it('emits one form per password for formless multi-login blocks sharing an ancestor', () => {
    document.body.innerHTML = `<main>
      <div><input type="text" name="user1"><input type="password" name="pass1"></div>
      <div><input type="text" name="user2"><input type="password" name="pass2"></div>
    </main>`;
    const forms = detectLoginForms();
    expect(forms.map((f) => f.passwordInput?.getAttribute('name')).sort()).toEqual(['pass1', 'pass2']);
  });
});
