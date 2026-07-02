// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { renderConsentInto, renderPasskeyPickerInto } from './passkey-consent.js';

afterEach(() => { document.body.innerHTML = ''; });

function mount(rpId: string): { root: HTMLElement; result: () => boolean | undefined } {
  const root = document.createElement('div');
  document.body.append(root);
  let result: boolean | undefined;
  renderConsentInto(root, rpId, (c) => { result = c; });
  return { root, result: () => result };
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el!.dispatchEvent(event);
}

describe('passkey consent dialog', () => {
  it('reports true only after a trusted confirm click', () => {
    const { root, result } = mount('example.com');
    trustedClick(root.querySelector('#vw-pk-confirm'));
    expect(result()).toBe(true);
  });

  it('reports false on cancel', () => {
    const { root, result } = mount('example.com');
    trustedClick(root.querySelector('#vw-pk-cancel'));
    expect(result()).toBe(false);
  });

  it('ignores untrusted (page-synthesized) clicks so consent cannot be forged', () => {
    const { root, result } = mount('example.com');
    // A synthetic event has isTrusted=false, exactly what a malicious page can dispatch.
    root.querySelector('#vw-pk-confirm')!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(result()).toBeUndefined();
  });

  it('shows the rpId so the user knows where they are signing in', () => {
    const { root } = mount('login.acme.com');
    expect(root.querySelector('.rp')?.textContent).toBe('login.acme.com');
  });

  it('fires the result at most once', () => {
    const root = document.createElement('div');
    document.body.append(root);
    let count = 0;
    renderConsentInto(root, 'x.com', () => { count++; });
    trustedClick(root.querySelector('#vw-pk-confirm'));
    trustedClick(root.querySelector('#vw-pk-cancel'));
    expect(count).toBe(1);
  });
});

describe('renderPasskeyPickerInto', () => {
  function setup(targets: Array<{ id: string; name: string; username?: string }>) {
    const root = document.createElement('div');
    document.body.append(root);
    let result: { cancelled: true } | { targetCipherId?: string } | undefined;
    renderPasskeyPickerInto(root, 'example.com', targets, (r) => { result = r; });
    return { root, get: () => result };
  }
  it('picking "New login item" resolves with no targetCipherId', () => {
    const { root, get } = setup([{ id: 'c1', name: 'Example', username: 'me' }]);
    trustedClick(root.querySelector('#vw-pk-new'));
    expect(get()).toEqual({});
  });
  it('picking an existing target resolves with its id', () => {
    const { root, get } = setup([{ id: 'c1', name: 'Example', username: 'me' }]);
    trustedClick(root.querySelector('[data-target="c1"]'));
    expect(get()).toEqual({ targetCipherId: 'c1' });
  });
  it('cancel resolves cancelled', () => {
    const { root, get } = setup([]);
    trustedClick(root.querySelector('#vw-pk-cancel'));
    expect(get()).toEqual({ cancelled: true });
  });
  it('ignores untrusted (synthetic) clicks only when isTrusted is enforced', () => {
    // renderPasskeyPickerInto gates on e.isTrusted; happy-dom MouseEvent has isTrusted=false, so the
    // production dialog would ignore it. This test documents the guard by asserting the handler checks it.
    const { root, get } = setup([{ id: 'c1', name: 'Example' }]);
    (root.querySelector('#vw-pk-new') as HTMLButtonElement).click(); // .click() → isTrusted false in happy-dom
    expect(get()).toBeUndefined();
  });
});
