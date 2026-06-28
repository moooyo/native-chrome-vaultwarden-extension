// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { renderConsentInto } from './passkey-consent.js';

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
