// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { detectLoginForms } from './form-detection.js';
import {
  commitLoginCustomAssignments,
  planLoginCustomTargets,
} from './login-custom-fields.js';

beforeEach(() => {
  document.body.innerHTML = '';
});

function loginForm() {
  const form = detectLoginForms(document)[0];
  if (!form) throw new Error('Expected a login form');
  return form;
}

describe('login custom DOM targets', () => {
  it('emits only exact metadata for bounded eligible controls', () => {
    document.body.innerHTML = `<form>
      <input name="username" autocomplete="username">
      <input type="password" autocomplete="current-password">
      <input name="department" id="ignored-id">
      <input id="employee-code">
      <textarea aria-label="Biography"></textarea>
      <select name="region"><option>east</option></select>
      <input type="checkbox" name="remember-department">
    </form>`;
    const result = planLoginCustomTargets(loginForm());
    expect(result.targets.map(({ controlType, hints }) => ({ controlType, hints }))).toEqual([
      { controlType: 'text', hints: [{ kind: 'name', value: 'department' }, { kind: 'id', value: 'ignored-id' }] },
      { controlType: 'text', hints: [{ kind: 'id', value: 'employee-code' }] },
      { controlType: 'textarea', hints: [{ kind: 'label', value: 'Biography' }] },
      { controlType: 'select', hints: [{ kind: 'name', value: 'region' }] },
      { controlType: 'checkbox', hints: [{ kind: 'name', value: 'remember-department' }] },
    ]);
  });

  it('excludes hidden, disabled, invisible, new-password, TOTP, and payment controls', () => {
    document.body.innerHTML = `<form>
      <input name="username"><input type="password">
      <input name="hidden-a" type="hidden">
      <input name="hidden-b" hidden>
      <input name="disabled" disabled>
      <input name="invisible" style="display:none">
      <input name="ignored-input" data-bwignore>
      <textarea name="ignored-textarea" data-bwignore></textarea>
      <select name="ignored-select" data-bwignore><option>ignored</option></select>
      <span data-bwautofill name="unsupported-span">ignored</span>
      <input name="replacement" autocomplete="new-password">
      <input name="auth-code" autocomplete="one-time-code">
      <input name="cvc">
      <input name="cardholder" autocomplete="cc-name">
      <input name="safe-custom">
    </form>`;
    expect(planLoginCustomTargets(loginForm()).targets.map((target) => target.hints[0]!.value)).toEqual(['safe-custom']);
  });

  it('accepts 32 custom targets and fails the entire plan closed at 33', () => {
    document.body.innerHTML = `<form><input name="username"><input type="password">${Array.from(
      { length: 32 },
      (_, index) => `<input name="custom-${index}">`,
    ).join('')}</form>`;
    expect(planLoginCustomTargets(loginForm()).targets).toHaveLength(32);

    document.querySelector('form')!.insertAdjacentHTML('beforeend', '<input name="custom-32">');
    expect(planLoginCustomTargets(loginForm()).targets).toHaveLength(0);
  });

  it('fails the entire custom plan closed when one field exceeds its hint budget', () => {
    document.body.innerHTML = `<form>
      <input name="username"><input type="password">
      <input name="${'x'.repeat(257)}">
      <input name="team"><input name="team">
    </form>`;
    const form = loginForm();
    const plan = planLoginCustomTargets(form);
    expect(plan.targets).toHaveLength(0);
  });

  it('includes external form=id controls but never crosses a native form boundary', () => {
    document.body.innerHTML = `
      <form id="login"><input name="username"><input type="password"></form>
      <input form="login" name="tenant">
      <form id="other"><input name="other-secret"></form>`;
    expect(planLoginCustomTargets(loginForm()).targets.map((target) => target.hints[0]!.value)).toEqual(['tenant']);
  });

  it('keeps a shadow-root login plan local to that root', () => {
    document.body.innerHTML = '<input name="outside">';
    const host = document.createElement('div');
    document.body.append(host);
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input name="username"><input type="password"><input name="realm"></form>';
    const form = detectLoginForms(shadow)[0]!;
    expect(planLoginCustomTargets(form).targets.map((target) => target.hints[0]!.value)).toEqual(['realm']);
  });

  it('captures bounded associated-label and placeholder hints without selector material', () => {
    document.body.innerHTML = `<form>
      <input name="username"><input type="password">
      <label for="tenant">Tenant\n code</label>
      <input id="tenant" placeholder="Workspace">
    </form>`;
    expect(planLoginCustomTargets(loginForm()).targets[0]!.hints).toEqual([
      { kind: 'id', value: 'tenant' },
      { kind: 'label', value: 'Tenant code' },
      { kind: 'placeholder', value: 'Workspace' },
    ]);
  });

  it('fills text and Boolean assignments through private ids', () => {
    document.body.innerHTML = '<form><input name="username"><input type="password"><input name="team"><input type="checkbox" name="enabled"></form>';
    const form = loginForm();
    const plan = planLoginCustomTargets(form);
    const text = document.querySelector<HTMLInputElement>('[name=team]')!;
    const checkbox = document.querySelector<HTMLInputElement>('[name=enabled]')!;
    const changed = vi.fn();
    checkbox.addEventListener('change', changed);
    expect(commitLoginCustomAssignments(form, plan, [
      { fieldId: plan.targets[0]!.fieldId, value: 'platform' },
      { fieldId: plan.targets[1]!.fieldId, checked: true },
    ])).toBe(true);
    expect(text.value).toBe('platform');
    expect(checkbox.checked).toBe(true);
    expect(changed).toHaveBeenCalledOnce();
  });

  it('rejects the whole custom portion when an element or exact hint changes', () => {
    document.body.innerHTML = '<form><input name="username"><input type="password"><input name="team"><input name="realm"></form>';
    const form = loginForm();
    const plan = planLoginCustomTargets(form);
    const team = document.querySelector<HTMLInputElement>('[name=team]')!;
    const realm = document.querySelector<HTMLInputElement>('[name=realm]')!;
    realm.name = 'changed-realm';
    expect(commitLoginCustomAssignments(form, plan, [
      { fieldId: plan.targets[0]!.fieldId, value: 'must-not-fill' },
      { fieldId: plan.targets[1]!.fieldId, value: 'must-not-fill' },
    ])).toBe(false);
    expect(team.value).toBe('');
    expect(realm.value).toBe('');
  });

  it.each([
    ['moves it to another form', (target: HTMLInputElement) => {
      const other = document.createElement('form');
      document.body.append(other);
      other.append(target);
    }],
    ['retypes it as a password', (target: HTMLInputElement) => { target.type = 'password'; }],
    ['replaces it with a lookalike', (target: HTMLInputElement) => { target.replaceWith(target.cloneNode()); }],
    ['marks it with data-bwignore', (target: HTMLInputElement) => { target.setAttribute('data-bwignore', ''); }],
  ])('stops before a later assignment when the first input event %s', (_name, mutate) => {
    document.body.innerHTML = '<form><input name="username"><input type="password"><input name="team"><input name="realm"></form>';
    const form = loginForm();
    const plan = planLoginCustomTargets(form);
    const team = document.querySelector<HTMLInputElement>('[name=team]')!;
    const realm = document.querySelector<HTMLInputElement>('[name=realm]')!;
    team.addEventListener('input', () => mutate(realm), { once: true });

    expect(commitLoginCustomAssignments(form, plan, [
      { fieldId: plan.targets[0]!.fieldId, value: 'platform' },
      { fieldId: plan.targets[1]!.fieldId, value: 'must-not-fill' },
    ])).toBe(false);
    expect(team.value).toBe('platform');
    expect(realm.value).toBe('');
    expect(document.querySelector<HTMLInputElement>('[name=realm]')?.value ?? '').toBe('');
  });

  it('binds a formless plan to its root for the entire staged commit', () => {
    document.body.innerHTML = `
      <section id="login">
        <input name="username"><input type="password"><input name="team"><input name="realm">
      </section>`;
    const form = loginForm();
    const plan = planLoginCustomTargets(form);
    const section = document.getElementById('login')!;
    const team = document.querySelector<HTMLInputElement>('[name=team]')!;
    const realm = document.querySelector<HTMLInputElement>('[name=realm]')!;
    team.addEventListener('input', () => {
      const host = document.createElement('div');
      const shadow = host.attachShadow({ mode: 'open' });
      document.body.append(host);
      shadow.append(section);
    }, { once: true });

    expect(commitLoginCustomAssignments(form, plan, [
      { fieldId: plan.targets[0]!.fieldId, value: 'platform' },
      { fieldId: plan.targets[1]!.fieldId, value: 'must-not-fill' },
    ])).toBe(false);
    expect(team.value).toBe('platform');
    expect(realm.value).toBe('');
  });

  it('keeps formless targets unowned and inside one composed slot path', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<section><slot name="login"></slot><slot name="other"></slot></section>';
    const loginSlot = shadow.querySelector<HTMLSlotElement>('slot[name=login]')!;
    const otherSlot = shadow.querySelector<HTMLSlotElement>('slot[name=other]')!;
    const username = document.createElement('input');
    username.name = 'username';
    const password = document.createElement('input');
    password.type = 'password';
    const tenant = document.createElement('input');
    tenant.name = 'tenant';
    const outside = document.createElement('input');
    outside.name = 'outside';
    for (const input of [username, password, tenant]) {
      Object.defineProperty(input, 'assignedSlot', { configurable: true, value: loginSlot });
      host.append(input);
    }
    Object.defineProperty(outside, 'assignedSlot', { configurable: true, value: otherSlot });
    host.append(outside);
    document.body.append(host);

    expect(planLoginCustomTargets(loginForm()).targets.map((target) => target.hints[0]!.value))
      .toEqual(['tenant']);
  });

  it('excludes native-form-owned controls from a formless custom scope', () => {
    document.body.innerHTML = `
      <form id="other"></form>
      <section>
        <input name="username"><input type="password"><input name="tenant">
        <input name="foreign" form="other">
      </section>`;

    expect(planLoginCustomTargets(loginForm()).targets.map((target) => target.hints[0]!.value))
      .toEqual(['tenant']);
  });

  it('reserves unsafe and secondary OTP companions from custom-field filling', () => {
    document.body.innerHTML = `
      <form>
        <input name="username"><input type="password">
        <div>
          <input autocomplete="one-time-code" maxlength="1" hidden>
          <input name="digit-two" maxlength="1"><input name="digit-three" maxlength="1">
        </div>
        <div>
          <input name="backup-otp" maxlength="1">
          <input name="backup-two" maxlength="1"><input name="backup-three" maxlength="1">
        </div>
        <input name="middle-initial" maxlength="1">
        <input name="safe-custom">
      </form>`;

    expect(planLoginCustomTargets(loginForm()).targets.map((target) => target.hints[0]!.value))
      .toEqual(['middle-initial', 'safe-custom']);
  });
});
