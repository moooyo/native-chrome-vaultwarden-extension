// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  VwPasskeyConsent,
  VwPasskeyRegister,
  type PasskeyRegisterResult,
} from './passkey-dialog-element.js';
import './passkey-dialog-element.js';

afterEach(() => {
  document.body.replaceChildren();
});

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

function shadowOf(element: HTMLElement): ShadowRoot {
  if (!element.shadowRoot) {
    throw new Error('element has no render root');
  }
  return element.shadowRoot;
}

async function mountConsent(
  rpId: string,
  onResult: (confirmed: boolean) => void,
): Promise<VwPasskeyConsent> {
  const element = document.createElement('vw-passkey-consent') as VwPasskeyConsent;
  element.rpId = rpId;
  element.onResult = onResult;
  document.body.append(element);
  await element.updateComplete;
  return element;
}

describe('vw-passkey-consent', () => {
  it('confirms only on a trusted confirm click', async () => {
    let result: boolean | undefined;
    const element = await mountConsent('example.com', (confirmed) => {
      result = confirmed;
    });
    const confirm = shadowOf(element).querySelector('#vw-pk-confirm');
    // An untrusted (page-forged) click must be ignored.
    confirm?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(result).toBeUndefined();
    trustedClick(confirm);
    expect(result).toBe(true);
  });

  it('cancels on a trusted cancel click', async () => {
    let result: boolean | undefined;
    const element = await mountConsent('example.com', (confirmed) => {
      result = confirmed;
    });
    trustedClick(shadowOf(element).querySelector('#vw-pk-cancel'));
    expect(result).toBe(false);
  });

  it('cancels on a trusted click outside the card', async () => {
    let result: boolean | undefined;
    const element = await mountConsent('example.com', (confirmed) => {
      result = confirmed;
    });
    trustedClick(shadowOf(element).querySelector('.overlay'));
    expect(result).toBe(false);
  });

  it('cancels on the Escape key', async () => {
    let result: boolean | undefined;
    await mountConsent('example.com', (confirmed) => {
      result = confirmed;
    });
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(result).toBe(false);
  });

  it('fires the result at most once', async () => {
    const onResult = vi.fn();
    const element = await mountConsent('example.com', onResult);
    trustedClick(shadowOf(element).querySelector('#vw-pk-confirm'));
    trustedClick(shadowOf(element).querySelector('#vw-pk-cancel'));
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(onResult).toHaveBeenCalledTimes(1);
  });

  it('shows the rpId so the user knows where they are signing in', async () => {
    const element = await mountConsent('login.acme.com', () => {});
    expect(shadowOf(element).querySelector('.domain')?.textContent).toContain('login.acme.com');
  });
});

async function mountRegister(
  targets: Array<{ id: string; name: string; username?: string }>,
  onResult: (result: PasskeyRegisterResult) => void,
): Promise<VwPasskeyRegister> {
  const element = document.createElement('vw-passkey-register') as VwPasskeyRegister;
  element.rpId = 'example.com';
  element.targets = targets;
  element.onResult = onResult;
  document.body.append(element);
  await element.updateComplete;
  return element;
}

describe('vw-passkey-register', () => {
  it('resolves with no targetCipherId when choosing a new item', async () => {
    let result: PasskeyRegisterResult | undefined;
    const element = await mountRegister([{ id: 'c1', name: 'Example', username: 'me' }], (r) => {
      result = r;
    });
    trustedClick(shadowOf(element).querySelector('#vw-pk-new'));
    expect(result).toEqual({});
  });

  it('resolves an existing target by in-memory index without exposing its id', async () => {
    let result: PasskeyRegisterResult | undefined;
    const element = await mountRegister(
      [
        { id: 'c1', name: 'Example', username: 'me' },
        { id: 'c2', name: 'Second', username: 'you' },
      ],
      (r) => {
        result = r;
      },
    );
    const root = shadowOf(element);
    const targets = root.querySelectorAll('button.target');
    trustedClick(targets[1] ?? null);
    expect(result).toEqual({ targetCipherId: 'c2' });
    // The cipher id is selected by rendered index and must never reach the DOM.
    expect(root.innerHTML).not.toContain('c2');
  });

  it('ignores an untrusted (page-forged) target click', async () => {
    let result: PasskeyRegisterResult | undefined;
    const element = await mountRegister([{ id: 'c1', name: 'Example', username: 'me' }], (r) => {
      result = r;
    });
    const target = shadowOf(element).querySelector('button.target');
    target?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(result).toBeUndefined();
  });

  it('cancels on a trusted cancel click', async () => {
    let result: PasskeyRegisterResult | undefined;
    const element = await mountRegister([], (r) => {
      result = r;
    });
    trustedClick(shadowOf(element).querySelector('#vw-pk-cancel'));
    expect(result).toEqual({ cancelled: true });
  });

  it('cancels on a trusted click outside the card', async () => {
    let result: PasskeyRegisterResult | undefined;
    const element = await mountRegister([{ id: 'c1', name: 'Example' }], (r) => {
      result = r;
    });
    trustedClick(shadowOf(element).querySelector('.overlay'));
    expect(result).toEqual({ cancelled: true });
  });

  it('cancels on the Escape key', async () => {
    let result: PasskeyRegisterResult | undefined;
    await mountRegister([{ id: 'c1', name: 'Example' }], (r) => {
      result = r;
    });
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(result).toEqual({ cancelled: true });
  });

  it('renders a long target list as locally scrollable', async () => {
    const element = await mountRegister(
      Array.from({ length: 14 }, (_, index) => ({ id: `c${index}`, name: `Item ${index}` })),
      () => {},
    );
    expect(shadowOf(element).querySelector('.list.scrollable')).not.toBeNull();
  });

  it('fires the result at most once', async () => {
    const onResult = vi.fn();
    const element = await mountRegister([{ id: 'c1', name: 'Example' }], onResult);
    trustedClick(shadowOf(element).querySelector('#vw-pk-new'));
    trustedClick(shadowOf(element).querySelector('#vw-pk-cancel'));
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(onResult).toHaveBeenCalledTimes(1);
  });
});
