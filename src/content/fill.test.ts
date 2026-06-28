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
});
