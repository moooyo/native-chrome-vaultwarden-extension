// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { detectLoginForms } from './form-detection.js';
import { clearTotpCode, fillLoginForm, fillTotpCode, setInputValue } from './fill.js';

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

  it('never writes a legacy bundled TOTP value into a one-time-code field', () => {
    document.body.innerHTML = `
      <form>
        <input id="user" type="email">
        <input id="pass" type="password">
        <input id="otp" type="text" autocomplete="one-time-code">
      </form>
    `;
    const form = detectLoginForms()[0]!;
    const legacyPayload = { username: 'me@example.com', password: 'secret', totp: '123456' } as {
      username: string;
      password: string;
    };
    expect(fillLoginForm(form, legacyPayload)).toBe(true);
    expect((document.getElementById('otp') as HTMLInputElement).value).toBe('');
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

describe('setInputValue', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('writes through the native prototype setter, bypassing a React-style value tracker', () => {
    document.body.innerHTML = '<input id="u" type="text">';
    const input = document.getElementById('u') as HTMLInputElement;
    const nativeDesc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!;
    // Simulate React's instance-level value tracker: an own accessor shadowing the prototype. React uses
    // it to cache the last value it set and decides whether onChange fires; a direct `input.value = x`
    // goes through it and updates the cache, so no change is detected. Our fill must bypass it.
    let trackerWrites = 0;
    Object.defineProperty(input, 'value', {
      configurable: true,
      get() { return nativeDesc.get!.call(input); },
      set(v: string) { trackerWrites++; nativeDesc.set!.call(input, v); },
    });
    let inputEvents = 0;
    input.addEventListener('input', () => inputEvents++);

    setInputValue(input, 'me@example.com');

    expect(trackerWrites).toBe(0); // bypassed the instance value tracker
    expect(nativeDesc.get!.call(input)).toBe('me@example.com'); // real DOM value updated
    expect(inputEvents).toBe(1); // input event dispatched so onChange can fire
  });
});

describe('fillTotpCode', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('preserves full-code filling for a single TOTP input', () => {
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code" maxlength="6"></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    const events: string[] = [];
    input.addEventListener('input', () => events.push('input'));
    input.addEventListener('change', () => events.push('change'));

    expect(fillTotpCode(input, '123456')).toBe(true);
    expect(input.value).toBe('123456');
    expect(events).toEqual(['input', 'change']);
  });

  it('fills a safe split-code group in DOM order from any member', () => {
    document.body.innerHTML = `
      <form><div id="otp-group">
        <input id="digit-1" autocomplete="one-time-code" maxlength="1">
        <input id="digit-2" maxlength="1">
        <input id="digit-3" maxlength="1">
        <input id="digit-4" maxlength="1">
        <input id="digit-5" maxlength="1">
        <input id="digit-6" maxlength="1">
      </div></form>`;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('#otp-group input'));
    const events: string[] = [];
    for (const input of inputs) {
      input.addEventListener('input', () => events.push(`${input.id}:input`));
      input.addEventListener('change', () => events.push(`${input.id}:change`));
    }

    expect(fillTotpCode(inputs[3]!, '654321')).toBe(true);
    expect(inputs.map((input) => input.value)).toEqual(['6', '5', '4', '3', '2', '1']);
    expect(events).toEqual(inputs.flatMap((input) => [`${input.id}:input`, `${input.id}:change`]));

    expect(clearTotpCode(inputs[3]!, '654321')).toBe(true);
    expect(inputs.map((input) => input.value)).toEqual(['', '', '', '', '', '']);
  });

  it('preserves a later manual edit to a single code when undo is requested', () => {
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code" maxlength="6"></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    expect(fillTotpCode(input, '123456')).toBe(true);
    input.value = '654321';
    expect(clearTotpCode(input, '123456')).toBe(false);
    expect(input.value).toBe('654321');
  });

  it('undoes unchanged split digits while retaining a later edit', () => {
    document.body.innerHTML = `<form><div>
      <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
      <input maxlength="1"><input maxlength="1"><input maxlength="1">
    </div></form>`;
    const inputs = [...document.querySelectorAll<HTMLInputElement>('input')];
    expect(fillTotpCode(inputs[0]!, '123456')).toBe(true);
    inputs[2]!.value = '9';
    expect(clearTotpCode(inputs[0]!, '123456')).toBe(true);
    expect(inputs.map((input) => input.value)).toEqual(['', '', '9', '', '', '']);
  });

  it('preserves edits made to a later split field by an undo event', () => {
    document.body.innerHTML = `<form><div>
      <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
      <input maxlength="1"><input maxlength="1"><input maxlength="1">
    </div></form>`;
    const inputs = [...document.querySelectorAll<HTMLInputElement>('input')];
    expect(fillTotpCode(inputs[0]!, '123456')).toBe(true);
    inputs[0]!.addEventListener('input', () => { inputs[4]!.value = '8'; }, { once: true });
    expect(clearTotpCode(inputs[0]!, '123456')).toBe(true);
    expect(inputs.map((input) => input.value)).toEqual(['', '', '', '', '8', '']);
  });

  it('supports component-enforced boxes when every input has one-time-code autocomplete', () => {
    document.body.innerHTML = `
      <form><div id="otp-group">
        <input type="number" name="otp-code-0" autocomplete="one-time-code">
        <input type="number" name="otp-code-1" autocomplete="one-time-code">
        <input type="number" name="otp-code-2" autocomplete="one-time-code">
        <input type="number" name="otp-code-3" autocomplete="one-time-code">
        <input type="number" name="otp-code-4" autocomplete="one-time-code">
        <input type="number" name="otp-code-5" autocomplete="one-time-code">
      </div></form>`;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input'));

    expect(fillTotpCode(inputs[0]!, '102938')).toBe(true);
    expect(inputs.map((input) => input.value)).toEqual(['1', '0', '2', '9', '3', '8']);
  });

  it('fails closed when the code length does not exactly match the split group', () => {
    document.body.innerHTML = `
      <form><div>
        <input autocomplete="one-time-code" maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>`;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input'));

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['', '', '', '']);
  });

  it('does not mix a full-code field with unrelated single-character inputs', () => {
    document.body.innerHTML = `
      <form><div>
        <input id="otp" autocomplete="one-time-code" maxlength="6">
        <input id="a" maxlength="1"><input id="b" maxlength="1">
        <input id="c" maxlength="1"><input id="d" maxlength="1"><input id="e" maxlength="1">
      </div></form>`;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input'));

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.every((input) => input.value === '')).toBe(true);
  });

  it('does not distribute a code across form-associated inputs owned by different forms', () => {
    document.body.innerHTML = `
      <form id="first"></form><form id="second"></form>
      <div>
        <input id="first-digit" form="first" autocomplete="one-time-code" maxlength="1">
        <input id="second-digit" form="second" autocomplete="one-time-code" maxlength="1">
      </div>`;
    const first = document.getElementById('first-digit') as HTMLInputElement;
    const second = document.getElementById('second-digit') as HTMLInputElement;

    expect(fillTotpCode(first, '12')).toBe(false);
    expect([first.value, second.value]).toEqual(['', '']);
  });

  it('fills only the nearest split group when a form contains two code groups', () => {
    document.body.innerHTML = `
      <form>
        <div id="first">
          <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
          <input maxlength="1"><input maxlength="1"><input maxlength="1">
        </div>
        <div id="second">
          <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
          <input maxlength="1"><input maxlength="1"><input maxlength="1">
        </div>
      </form>`;
    const first = Array.from(document.querySelectorAll<HTMLInputElement>('#first input'));
    const second = Array.from(document.querySelectorAll<HTMLInputElement>('#second input'));

    expect(fillTotpCode(first[0]!, '123456')).toBe(true);
    expect(first.map((input) => input.value)).toEqual(['1', '2', '3', '4', '5', '6']);
    expect(second.every((input) => input.value === '')).toBe(true);
  });

  it('stops before the next character if page events reorder the group', () => {
    document.body.innerHTML = `
      <form><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    inputs[0]!.addEventListener('input', () => group.append(inputs[1]!));

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '', '', '', '', '']);
  });

  it('checks the caller authority before and after every split-code write', () => {
    document.body.innerHTML = `
      <form><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>`;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('#otp-group input'));
    let current = true;
    inputs[0]!.addEventListener('input', () => { current = false; }, { once: true });

    expect(fillTotpCode(inputs[0]!, '123456', () => current)).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '', '', '', '', '']);
  });

  it('stops before the next character if page events opt a group member out', () => {
    document.body.innerHTML = `
      <form><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>`;
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('#otp-group input'));
    inputs[0]!.addEventListener('input', () => inputs[1]!.setAttribute('data-bwignore', ''), { once: true });

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '', '', '', '', '']);
  });

  it('stops if the first input event moves the original group to another form', () => {
    document.body.innerHTML = `
      <form id="first"><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>
      <form id="second"></form>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    inputs[0]!.addEventListener('input', () => document.getElementById('second')!.append(group), { once: true });

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '', '', '', '', '']);
  });

  it('invalidates the fill receipt when the final input event changes the owner', () => {
    document.body.innerHTML = `
      <form id="first"><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>
      <form id="second"></form>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    inputs[5]!.addEventListener('input', () => document.getElementById('second')!.append(group), { once: true });

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(clearTotpCode(inputs[0]!, '123456')).toBe(false);
  });

  it.each([
    ['input', 'detaches', (group: HTMLElement, inputs: HTMLInputElement[]) => inputs[5]!.remove()],
    ['change', 'reorders', (group: HTMLElement, inputs: HTMLInputElement[]) => group.prepend(inputs[5]!)],
  ] as const)('revalidates after the final %s event %s the group', (eventType, _action, mutate) => {
    document.body.innerHTML = `
      <form><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    inputs[5]!.addEventListener(eventType, () => mutate(group, inputs), { once: true });

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '2', '3', '4', '5', '6']);
    expect(clearTotpCode(inputs[0]!, '123456')).toBe(false);
  });

  it('stops if the first input event moves the original group into another root', () => {
    document.body.innerHTML = `
      <div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    inputs[0]!.addEventListener('input', () => {
      const host = document.createElement('div');
      const shadow = host.attachShadow({ mode: 'open' });
      document.body.append(host);
      shadow.append(group);
    }, { once: true });

    expect(fillTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '', '', '', '', '']);
  });

  it('uses the successful fill binding for undo instead of clearing a moved group', () => {
    document.body.innerHTML = `
      <form id="first"><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>
      <form id="second"></form>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    expect(fillTotpCode(inputs[0]!, '123456')).toBe(true);
    document.getElementById('second')!.append(group);

    expect(clearTotpCode(inputs[0]!, '123456')).toBe(false);
    expect(inputs.map((input) => input.value)).toEqual(['1', '2', '3', '4', '5', '6']);
  });
});
