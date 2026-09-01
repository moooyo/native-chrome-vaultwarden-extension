// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  isPageLoadLoginTargetCurrent,
  selectPageLoadLoginTarget,
  selectPageLoadLoginTargetFromSnapshot,
} from './page-load-fill.js';

function makeVisible(element: Element): void {
  vi.spyOn(element, 'getClientRects').mockReturnValue([
    { x: 10, y: 10, left: 10, top: 10, right: 210, bottom: 42, width: 200, height: 32, toJSON: () => ({}) },
  ] as unknown as DOMRectList);
}

describe('page-load login target', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  });

  it('selects the sole visible empty current-password form', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password" autocomplete="current-password"></form>';
    const [username, password] = [...document.querySelectorAll<HTMLInputElement>('input')];
    makeVisible(username!);
    makeVisible(password!);
    expect(selectPageLoadLoginTarget()).toMatchObject({ usernameInput: username, passwordInput: password });
  });

  it('fails closed for multiple forms, hidden fields, and prefilled fields', () => {
    document.body.innerHTML = `
      <form><input type="password" autocomplete="current-password"></form>
      <form><input type="password" autocomplete="current-password"></form>`;
    const passwords = [...document.querySelectorAll<HTMLInputElement>('input')];
    passwords.forEach(makeVisible);
    expect(selectPageLoadLoginTarget()).toBeUndefined();

    passwords[1]!.form!.remove();
    passwords[0]!.value = 'typed';
    expect(selectPageLoadLoginTarget()).toBeUndefined();
    passwords[0]!.value = '';
    passwords[0]!.style.opacity = '0';
    expect(selectPageLoadLoginTarget()).toBeUndefined();
  });

  it('rejects a detached or replaced field after the worker round trip', () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="current-password"></form>';
    const original = document.querySelector<HTMLInputElement>('input')!;
    makeVisible(original);
    const target = selectPageLoadLoginTarget()!;
    expect(isPageLoadLoginTargetCurrent(target)).toBe(true);

    const replacement = original.cloneNode() as HTMLInputElement;
    makeVisible(replacement);
    original.replaceWith(replacement);
    expect(isPageLoadLoginTargetCurrent(target)).toBe(false);
  });

  it('rejects the same form and fields after they move to another open root', () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="current-password"></form>';
    const password = document.querySelector<HTMLInputElement>('input')!;
    makeVisible(password);
    const target = selectPageLoadLoginTarget()!;
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    document.body.append(host);
    shadow.append(password.form!);

    expect(isPageLoadLoginTargetCurrent(target, [document, shadow])).toBe(false);
  });

  it('requires a visible document and a non-zero viewport rectangle', () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="current-password"></form>';
    const password = document.querySelector<HTMLInputElement>('input')!;
    expect(selectPageLoadLoginTarget()).toBeUndefined();
    makeVisible(password);
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    expect(selectPageLoadLoginTarget()).toBeUndefined();
  });

  it('accepts one globally unique, visible, empty formless current-password target', () => {
    document.body.innerHTML = '<input type="password" autocomplete="current-password">';
    const password = document.querySelector<HTMLInputElement>('input')!;
    makeVisible(password);
    const target = selectPageLoadLoginTarget();
    expect(target).toMatchObject({ passwordInput: password });
    expect(target?.form.form).toBeNull();
    expect(isPageLoadLoginTargetCurrent(target!)).toBe(true);

    password.value = 'typed';
    expect(isPageLoadLoginTargetCurrent(target!)).toBe(false);
  });

  it('parses canonical current-password token lists with section and mode prefixes', () => {
    for (const autocomplete of [
      'section-login current-password',
      'SECTION-ACCOUNT billing current-password webauthn',
      'shipping current-password',
    ]) {
      document.body.innerHTML = `<form><input type="password" autocomplete="${autocomplete}"></form>`;
      makeVisible(document.querySelector('input')!);
      expect(selectPageLoadLoginTarget(), autocomplete).toBeDefined();
    }

    for (const autocomplete of [
      'section- current-password',
      'account current-password',
      'current-password new-password',
      'section-login\u00a0current-password',
    ]) {
      document.body.innerHTML = `<form><input type="password" autocomplete="${autocomplete}"></form>`;
      makeVisible(document.querySelector('input')!);
      expect(selectPageLoadLoginTarget(), autocomplete).toBeUndefined();
    }
  });

  it('rejects a formless target when another fillable password exists in a shadow root', () => {
    document.body.innerHTML = '<input id="light" type="password" autocomplete="current-password">';
    const light = document.getElementById('light') as HTMLInputElement;
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<input id="shadow" type="password" autocomplete="current-password">';
    document.body.append(host);
    const shadowPassword = shadow.getElementById('shadow') as HTMLInputElement;
    makeVisible(light);
    makeVisible(shadowPassword);

    expect(selectPageLoadLoginTarget([document, shadow])).toBeUndefined();

    light.remove();
    expect(selectPageLoadLoginTarget([document, shadow])).toMatchObject({
      passwordInput: shadowPassword,
      root: shadow,
    });
  });

  it('invalidates a formless target when its composed slot owner changes', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<section><slot name="first"></slot><slot name="second"></slot></section>';
    const password = document.createElement('input');
    password.type = 'password';
    password.autocomplete = 'current-password';
    password.slot = 'first';
    host.append(password);
    document.body.append(host);
    const first = shadow.querySelector<HTMLSlotElement>('slot[name=first]')!;
    const second = shadow.querySelector<HTMLSlotElement>('slot[name=second]')!;
    Object.defineProperty(password, 'assignedSlot', { configurable: true, value: first });
    makeVisible(password);
    const target = selectPageLoadLoginTarget([document, shadow])!;

    expect(target.passwordInput).toBe(password);
    Object.defineProperty(password, 'assignedSlot', { configurable: true, value: second });
    expect(isPageLoadLoginTargetCurrent(target, [document, shadow])).toBe(false);
  });

  it('still rejects implicit-password and change-password targets', () => {

    document.body.innerHTML = '<form><input type="password"></form>';
    makeVisible(document.querySelector('input')!);
    expect(selectPageLoadLoginTarget()).toBeUndefined();

    document.body.innerHTML = '<form><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"></form>';
    document.querySelectorAll('input').forEach(makeVisible);
    expect(selectPageLoadLoginTarget()).toBeUndefined();
  });

  it('rejects an otherwise unique target when composed discovery was truncated', () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="current-password"></form>';
    makeVisible(document.querySelector('input')!);
    expect(selectPageLoadLoginTargetFromSnapshot({ roots: [document], truncated: true })).toBeUndefined();
    expect(selectPageLoadLoginTargetFromSnapshot({ roots: [document], truncated: false })).toBeDefined();
  });
});
