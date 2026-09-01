// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import type { FrameCardForm, FrameIdentityForm, FrameLoginForm } from '../messaging/protocol.js';
import { createFrameAutofillController } from './frame-autofill.js';

const FRAME_URL = 'https://login.example.com/';

describe('frame autofill controller', () => {
  beforeEach(() => {
    document.body.innerHTML = '<form><input name="email" type="email"><input type="password"></form>';
  });

  it('returns private login metadata without field values', () => {
    const email = document.querySelector<HTMLInputElement>('input[type=email]')!;
    email.value = 'must-not-cross';
    const controller = createController(() => 1000);
    controller.noteFocus(email);

    const inspection = controller.inspect();
    const login = findLogin(inspection.forms);
    expect(inspection.frameUrl).toBe(FRAME_URL);
    expect(inspection.generation).toBeGreaterThan(0);
    expect(login.kind).toBe('login');
    expect(login.focusedAt).toBe(1000);
    expect(login.formId).toMatch(/^vw-frame-form-/);
    expect(email.dataset).toEqual({});
    expect(JSON.stringify(inspection)).not.toContain('must-not-cross');
  });

  it('keeps generation stable across identical inspections and focus changes', () => {
    const controller = createController(() => 2000);
    const first = controller.inspect();
    const second = controller.inspect();
    controller.noteFocus(document.querySelector<HTMLInputElement>('input[type=email]')!);
    const focused = controller.inspect();

    expect(second.generation).toBe(first.generation);
    expect(focused.generation).toBe(first.generation);
    expect(findLogin(focused.forms).focusedAt).toBe(2000);
  });

  it('keeps generation stable when login and explicit card hints coexist', () => {
    document.body.innerHTML = `
      <form>
        <input name="username" autocomplete="cc-name">
        <input type="password" autocomplete="current-password">
        <input autocomplete="cc-number">
      </form>`;
    const controller = createController();
    const first = controller.inspect();
    const second = controller.inspect();

    expect(findCard(first.forms).roles).toEqual(['cardholderName', 'number']);
    expect(findCard(second.forms).formId).toBe(findCard(first.forms).formId);
    expect(second.generation).toBe(first.generation);
  });

  it('reports canonical card and identity roles without field values', () => {
    document.body.innerHTML = `
      <form id="payment">
        <input autocomplete="cc-name" value="Private Cardholder">
        <select autocomplete="cc-type"><option>Visa</option></select>
        <input autocomplete="cc-number" value="4111111111111111">
        <select autocomplete="cc-exp-month"><option value="03">March</option></select>
        <input autocomplete="cc-csc" value="123">
      </form>
      <form id="address">
        <input autocomplete="given-name" value="Private">
        <input autocomplete="family-name" value="Person">
        <input autocomplete="street-address" value="Private Street">
        <input autocomplete="postal-code" value="00000">
        <input autocomplete="email" value="private@example.com">
      </form>`;
    const inspection = createController().inspect();
    const card = findCard(inspection.forms);
    const identity = findIdentity(inspection.forms);

    expect(card.roles).toEqual(['cardholderName', 'brand', 'number', 'expMonth', 'code']);
    expect(identity.roles).toEqual(['firstName', 'lastName', 'address', 'postalCode', 'email']);
    const serialized = JSON.stringify(inspection);
    expect(serialized).not.toContain('4111111111111111');
    expect(serialized).not.toContain('Private Street');
    expect(serialized).not.toContain('private@example.com');
  });

  it('records focus for a card select', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-month"><option value="03">March</option></select>
      </form>`;
    const controller = createController(() => 3000);
    controller.noteFocus(document.querySelector('select')!);
    expect(findCard(controller.inspect().forms).focusedAt).toBe(3000);
  });

  it('fails a login commit closed when the URL changes', () => {
    let url = 'https://example.com/login';
    const controller = createFrameAutofillController({
      root: document,
      frameUrl: () => url,
      now: () => 0,
    });
    const inspection = controller.inspect();
    const target = findLogin(inspection.forms);
    url = 'https://evil.example/';

    expect(controller.commitLogin({
      formId: target.formId,
      expectedFrameUrl: 'https://example.com/login',
      expectedGeneration: inspection.generation,
      login: { username: 'u', password: 'p' },
      customPlan: target.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'target_changed' });
  });

  it('fills a login only at the inspected generation', () => {
    const controller = createController();
    const inspection = controller.inspect();
    const target = findLogin(inspection.forms);

    expect(controller.commitLogin({
      formId: target.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { username: 'user', password: 'secret' },
      customPlan: target.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'filled' });
    expect(document.querySelector<HTMLInputElement>('input[type=email]')!.value).toBe('user');
    expect(document.querySelector<HTMLInputElement>('input[type=password]')!.value).toBe('secret');
  });

  it('fills an unhinted native-form identifier through the inspected login target', () => {
    document.body.innerHTML = '<form><input id="identifier" type="text"><input id="password" type="password"></form>';
    const identifier = document.getElementById('identifier') as HTMLInputElement;
    const password = document.getElementById('password') as HTMLInputElement;
    const controller = createController();
    const inspection = controller.inspect();
    const target = findLogin(inspection.forms);

    expect(controller.commitLogin({
      formId: target.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { username: 'fallback-user', password: 'secret' },
      customPlan: target.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'filled' });
    expect(identifier.value).toBe('fallback-user');
    expect(password.value).toBe('secret');
  });

  it.each([
    ['moves', (password: HTMLInputElement) => {
      const other = document.createElement('form');
      document.body.append(other);
      other.append(password);
    }],
    ['retypes', (password: HTMLInputElement) => { password.type = 'text'; }],
    ['replaces', (password: HTMLInputElement) => { password.replaceWith(password.cloneNode()); }],
    ['ignores', (password: HTMLInputElement) => { password.setAttribute('data-bwignore', ''); }],
  ])('stops before password when the username input event %s the password target', (_name, mutate) => {
    const controller = createController();
    const inspection = controller.inspect();
    const target = findLogin(inspection.forms);
    const username = document.querySelector<HTMLInputElement>('input[type=email]')!;
    const password = document.querySelector<HTMLInputElement>('input[type=password]')!;
    username.addEventListener('input', () => mutate(password), { once: true });

    expect(controller.commitLogin({
      formId: target.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { username: 'user', password: 'must-not-fill' },
      customPlan: target.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'target_changed' });
    expect(username.value).toBe('user');
    expect(password.value).toBe('');
  });

  it('keeps username/password but rejects the whole custom portion after a target hint changes', () => {
    document.body.innerHTML = '<form><input name="username"><input type="password"><input name="department"><input name="realm"></form>';
    const controller = createController();
    const inspection = controller.inspect();
    const target = findLogin(inspection.forms);
    const department = document.querySelector<HTMLInputElement>('[name=department]')!;
    const realm = document.querySelector<HTMLInputElement>('[name=realm]')!;
    const assignments = target.customPlan.targets.map((customTarget) => ({
      fieldId: customTarget.fieldId,
      value: 'must-not-fill',
    }));
    realm.name = 'changed-realm';

    expect(controller.commitLogin({
      formId: target.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { username: 'user', password: 'secret' },
      customPlan: target.customPlan,
      customAssignments: assignments,
    })).toEqual({ status: 'filled' });
    expect(document.querySelector<HTMLInputElement>('[name=username]')!.value).toBe('user');
    expect(document.querySelector<HTMLInputElement>('input[type=password]')!.value).toBe('secret');
    expect(department.value).toBe('');
    expect(realm.value).toBe('');
  });

  it('changes generation and rejects when the login form scope changes', () => {
    const controller = createController();
    const inspection = controller.inspect();
    const original = findLogin(inspection.forms);
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    const replacementForm = document.createElement('form');
    document.body.append(replacementForm);
    replacementForm.append(password);

    expect(controller.commitLogin({
      formId: original.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { password: 'must-not-fill' },
      customPlan: original.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'target_changed' });
    expect(controller.inspect().generation).toBeGreaterThan(inspection.generation);
    expect(password.value).toBe('');
  });

  it('changes generation and rejects when a login member is replaced', () => {
    const controller = createController();
    const inspection = controller.inspect();
    const original = findLogin(inspection.forms);
    const email = document.querySelector<HTMLInputElement>('input[type="email"]')!;
    email.replaceWith(email.cloneNode());

    expect(controller.commitLogin({
      formId: original.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { username: 'must-not-fill', password: 'must-not-fill' },
      customPlan: original.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'target_changed' });
  });

  it('discovers and commits a login in nested open shadow roots by default', () => {
    document.body.replaceChildren();
    const outerHost = document.createElement('div');
    const outer = outerHost.attachShadow({ mode: 'open' });
    const innerHost = document.createElement('div');
    const inner = innerHost.attachShadow({ mode: 'open' });
    inner.innerHTML = '<form><input type="email"><input type="password"></form>';
    outer.append(innerHost);
    document.body.append(outerHost);
    const controller = createController();
    const inspection = controller.inspect();
    const login = findLogin(inspection.forms);

    expect(controller.commitLogin({
      formId: login.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { username: 'shadow-user', password: 'shadow-secret' },
      customPlan: login.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'filled' });
    expect(inner.querySelector<HTMLInputElement>('input[type="email"]')!.value).toBe('shadow-user');
    expect(inner.querySelector<HTMLInputElement>('input[type="password"]')!.value).toBe('shadow-secret');
  });

  it('commits card and identity data through their exact inspected roles', () => {
    document.body.innerHTML = `
      <form id="payment"><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>
      <form id="identity"><input autocomplete="given-name"><input autocomplete="family-name"></form>`;
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);
    const identity = findIdentity(inspection.forms);

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: '4111', code: '123' },
    })).toEqual({ status: 'filled' });
    expect(controller.commitStructured({
      kind: 'identity',
      formId: identity.formId,
      roles: identity.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { firstName: 'Ada', lastName: 'Lovelace' },
    })).toEqual({ status: 'filled' });
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.value).toBe('4111');
    expect(document.querySelector<HTMLInputElement>('[autocomplete="given-name"]')!.value).toBe('Ada');
  });

  it('stops a card commit when the number event moves the CVC to another form', () => {
    document.body.innerHTML = `
      <form id="payment"><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>
      <form id="other"></form>`;
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);
    const number = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    const code = document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!;
    number.addEventListener('input', () => document.getElementById('other')!.append(code), { once: true });

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: '4111', code: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(number.value).toBe('4111');
    expect(code.value).toBe('');
  });

  it('stops before card number when the cc-type select event moves the number target', () => {
    document.body.innerHTML = `
      <form id="payment">
        <select autocomplete="cc-type" id="brand"><option value="">Type</option><option value="visa">Visa</option></select>
        <input autocomplete="cc-number" id="number">
      </form><form id="other"></form>`;
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);
    const brand = document.getElementById('brand') as HTMLSelectElement;
    const number = document.getElementById('number') as HTMLInputElement;
    brand.addEventListener('input', () => document.getElementById('other')!.append(number), { once: true });

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { brand: 'Visa', number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(brand.value).toBe('visa');
    expect(number.value).toBe('');
  });

  it('stops a card commit when the number event opts the CVC out', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);
    const number = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    const code = document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!;
    number.addEventListener('input', () => code.setAttribute('data-bwignore', ''), { once: true });

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: '4111', code: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(number.value).toBe('4111');
    expect(code.value).toBe('');
  });

  it('stops an identity commit when the first-name event replaces the last-name target', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"></form>';
    const controller = createController();
    const inspection = controller.inspect();
    const identity = findIdentity(inspection.forms);
    const firstName = document.querySelector<HTMLInputElement>('[autocomplete="given-name"]')!;
    const lastName = document.querySelector<HTMLInputElement>('[autocomplete="family-name"]')!;
    firstName.addEventListener('input', () => lastName.replaceWith(lastName.cloneNode()), { once: true });

    expect(controller.commitStructured({
      kind: 'identity',
      formId: identity.formId,
      roles: identity.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { firstName: 'Ada', lastName: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(firstName.value).toBe('Ada');
    expect(lastName.value).toBe('');
    expect(document.querySelector<HTMLInputElement>('[autocomplete="family-name"]')!.value).toBe('');
  });

  it('stops after a street-address textarea event replaces the full-name target', () => {
    document.body.innerHTML = `
      <form><textarea autocomplete="street-address" id="address"></textarea><input autocomplete="name" id="full"></form>`;
    const controller = createController();
    const inspection = controller.inspect();
    const identity = findIdentity(inspection.forms);
    const address = document.getElementById('address') as HTMLTextAreaElement;
    const full = document.getElementById('full') as HTMLInputElement;
    address.addEventListener('input', () => full.replaceWith(full.cloneNode()), { once: true });

    expect(controller.commitStructured({
      kind: 'identity',
      formId: identity.formId,
      roles: identity.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { firstName: 'Ada', lastName: 'must-not-fill', address1: '1 Analytical Way' },
    })).toEqual({ status: 'target_changed' });
    expect(address.value).toBe('1 Analytical Way');
    expect(full.value).toBe('');
    expect((document.getElementById('full') as HTMLInputElement).value).toBe('');
  });

  it('does not publish an OTP-only detector result as a login fill target', () => {
    document.body.innerHTML = '<form><input autocomplete="one-time-code"><button>Verify</button></form>';
    const inspection = createController().inspect();
    expect(inspection.forms.some((form) => form.kind === 'login')).toBe(false);
  });

  it('changes target identity when the same form moves to another open root', () => {
    const controller = createController();
    const inspection = controller.inspect();
    const original = findLogin(inspection.forms);
    const form = document.querySelector('form')!;
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    document.body.append(host);
    shadow.append(form);

    const moved = controller.inspect();
    expect(moved.generation).toBeGreaterThan(inspection.generation);
    expect(findLogin(moved.forms).formId).not.toBe(original.formId);
    expect(controller.commitLogin({
      formId: original.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { password: 'must-not-fill' },
      customPlan: original.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'target_changed' });
  });

  it('changes split-login generation when its surface moves between existing open roots', () => {
    document.body.replaceChildren();
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    const firstRoot = firstHost.attachShadow({ mode: 'open' });
    const secondRoot = secondHost.attachShadow({ mode: 'open' });
    firstRoot.innerHTML = `
      <div id="login-surface">
        <input type="email"><input type="password">
        <div><input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
          <input maxlength="1"><input maxlength="1"><input maxlength="1"></div>
      </div>`;
    document.body.append(firstHost, secondHost);
    const surface = firstRoot.getElementById('login-surface')!;
    const password = surface.querySelector<HTMLInputElement>('input[type="password"]')!;
    const controller = createController();
    const inspection = controller.inspect();
    const original = findLogin(inspection.forms);

    secondRoot.append(surface);
    const moved = controller.inspect();

    expect(moved.generation).toBeGreaterThan(inspection.generation);
    expect(findLogin(moved.forms).formId).not.toBe(original.formId);
    expect(controller.commitLogin({
      formId: original.formId,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      login: { password: 'must-not-fill' },
      customPlan: original.customPlan,
      customAssignments: [],
    })).toEqual({ status: 'target_changed' });
    expect(password.value).toBe('');
  });

  it('changes generation when a non-anchor formless field moves to another slot owner', () => {
    document.body.replaceChildren();
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<section><slot name="first"></slot><slot name="second"></slot></section>';
    const firstSlot = shadow.querySelector<HTMLSlotElement>('slot[name=first]')!;
    const secondSlot = shadow.querySelector<HTMLSlotElement>('slot[name=second]')!;
    const number = document.createElement('input');
    number.autocomplete = 'cc-number';
    const code = document.createElement('input');
    code.autocomplete = 'cc-csc';
    Object.defineProperty(number, 'assignedSlot', { configurable: true, value: firstSlot });
    Object.defineProperty(code, 'assignedSlot', { configurable: true, value: firstSlot });
    host.append(number, code);
    document.body.append(host);
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);

    Object.defineProperty(code, 'assignedSlot', { configurable: true, value: secondSlot });
    const moved = controller.inspect();

    expect(moved.generation).toBeGreaterThan(inspection.generation);
    expect(findCard(moved.forms).formId).not.toBe(card.formId);
    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: '4111', code: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(number.value).toBe('');
    expect(code.value).toBe('');
  });

  it('rejects a structured commit with a non-matching role set', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: ['number'],
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: ['code', 'number'],
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.value).toBe('');
  });

  it.each([
    ['detached', (field: HTMLInputElement) => field.remove()],
    ['reclassified', (field: HTMLInputElement) => field.setAttribute('autocomplete', 'cc-exp')],
    ['hidden', (field: HTMLInputElement) => { field.hidden = true; }],
    ['disabled', (field: HTMLInputElement) => { field.disabled = true; }],
    ['ignored', (field: HTMLInputElement) => { field.setAttribute('data-bwignore', ''); }],
  ])('rejects when a structured member is %s', (_name, mutate) => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);
    const code = document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!;
    mutate(code);

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: 'must-not-fill', code: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.value).toBe('');
  });

  it('rejects an old commit when the open-root inventory changes', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"></form>';
    const controller = createController();
    const inspection = controller.inspect();
    const card = findCard(inspection.forms);
    const host = document.createElement('div');
    host.attachShadow({ mode: 'open' });
    document.body.append(host);

    expect(controller.commitStructured({
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(controller.inspect().generation).toBeGreaterThan(inspection.generation);
  });
});

function createController(now: () => number = () => 0) {
  return createFrameAutofillController({
    root: document,
    frameUrl: () => FRAME_URL,
    now,
  });
}

function findLogin(forms: readonly (FrameLoginForm | FrameCardForm | FrameIdentityForm)[]): FrameLoginForm {
  return forms.find((form): form is FrameLoginForm => form.kind === 'login')!;
}

function findCard(forms: readonly (FrameLoginForm | FrameCardForm | FrameIdentityForm)[]): FrameCardForm {
  return forms.find((form): form is FrameCardForm => form.kind === 'card')!;
}

function findIdentity(forms: readonly (FrameLoginForm | FrameCardForm | FrameIdentityForm)[]): FrameIdentityForm {
  return forms.find((form): form is FrameIdentityForm => form.kind === 'identity')!;
}
