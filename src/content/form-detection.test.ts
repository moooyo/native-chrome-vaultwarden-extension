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
    expect(forms[0]?.passwordInput.type).toBe('password');
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
});
