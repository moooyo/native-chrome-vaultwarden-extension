// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';
import {
  DIALOG_STYLES,
  renderPasskeyConsent,
  renderPasskeyLoginPicker,
  renderPasskeyRegister,
  type PasskeyConsentHandlers,
  type PasskeyConsentState,
  type PasskeyLoginPickerHandlers,
  type PasskeyLoginPickerState,
  type PasskeyRegisterHandlers,
  type PasskeyRegisterState,
} from './passkey-dialog-element.js';

// These dialogs are render-based surfaces (no custom element — content scripts run in an isolated world
// with no custom-element registry, Chromium 41118431). Tests render the exported template functions into
// a container and assert on the produced DOM, exactly as the factory renders them into a closed shadow
// root. Escape / one-shot settling live in the factory now (see passkey-consent.test.ts); here we cover
// the template's trusted-click gating, outside-click detection, index-only target selection, and styles.

let container: HTMLElement | undefined;

afterEach(() => {
  container?.remove();
  container = undefined;
});

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

function mountConsent(
  state: Partial<PasskeyConsentState>,
  handlers: PasskeyConsentHandlers = {},
): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  render(renderPasskeyConsent({ rpId: 'example.com', ...state }, handlers), container);
  return container;
}

function mountRegister(
  state: Partial<PasskeyRegisterState>,
  handlers: PasskeyRegisterHandlers = {},
): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  render(renderPasskeyRegister({ rpId: 'example.com', targets: [], ...state }, handlers), container);
  return container;
}

function mountLoginPicker(
  state: Partial<PasskeyLoginPickerState>,
  handlers: PasskeyLoginPickerHandlers = {},
): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  render(renderPasskeyLoginPicker({ rpId: 'example.com', accounts: [], ...state }, handlers), container);
  return container;
}

describe('passkey consent surface', () => {
  it('confirms only on a trusted confirm click', () => {
    const onConfirm = vi.fn();
    const root = mountConsent({}, { onConfirm });
    const confirm = root.querySelector('#vw-pk-confirm');
    // An untrusted (page-forged) click must be ignored.
    confirm?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onConfirm).not.toHaveBeenCalled();
    trustedClick(confirm);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('cancels on a trusted cancel click', () => {
    const onCancel = vi.fn();
    const root = mountConsent({}, { onCancel });
    root.querySelector('#vw-pk-cancel')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onCancel).not.toHaveBeenCalled();
    trustedClick(root.querySelector('#vw-pk-cancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('cancels on a trusted click outside the card but not on the card itself', () => {
    const onOverlay = vi.fn();
    const root = mountConsent({}, { onOverlay });
    // A trusted click that bubbles up from inside the card is not an outside click.
    trustedClick(root.querySelector('.card'));
    expect(onOverlay).not.toHaveBeenCalled();
    trustedClick(root.querySelector('.overlay'));
    expect(onOverlay).toHaveBeenCalledTimes(1);
  });

  it('shows the rpId so the user knows where they are signing in', () => {
    const root = mountConsent({ rpId: 'login.acme.com' });
    expect(root.querySelector('.domain')?.textContent).toContain('login.acme.com');
  });
});

describe('passkey register surface', () => {
  it('resolves a new item on a trusted new click', () => {
    const onNew = vi.fn();
    const root = mountRegister({ targets: [{ id: 'c1', name: 'Example', username: 'me' }] }, { onNew });
    root.querySelector('#vw-pk-new')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onNew).not.toHaveBeenCalled();
    trustedClick(root.querySelector('#vw-pk-new'));
    expect(onNew).toHaveBeenCalledTimes(1);
  });

  it('selects an existing target by in-memory index without exposing its id', () => {
    const onSelectTarget = vi.fn();
    const root = mountRegister(
      {
        targets: [
          { id: 'c1', name: 'Example', username: 'me' },
          { id: 'c2', name: 'Second', username: 'you' },
        ],
      },
      { onSelectTarget },
    );
    const targets = root.querySelectorAll('button.target');
    trustedClick(targets[1] ?? null);
    expect(onSelectTarget).toHaveBeenCalledWith(1);
    // The cipher id is selected by rendered index and must never reach the DOM.
    expect(root.innerHTML).not.toContain('c2');
  });

  it('ignores an untrusted (page-forged) target click', () => {
    const onSelectTarget = vi.fn();
    const root = mountRegister({ targets: [{ id: 'c1', name: 'Example', username: 'me' }] }, { onSelectTarget });
    root.querySelector('button.target')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onSelectTarget).not.toHaveBeenCalled();
  });

  it('cancels on a trusted cancel click', () => {
    const onCancel = vi.fn();
    const root = mountRegister({ targets: [] }, { onCancel });
    trustedClick(root.querySelector('#vw-pk-cancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('cancels on a trusted click outside the card', () => {
    const onOverlay = vi.fn();
    const root = mountRegister({ targets: [{ id: 'c1', name: 'Example' }] }, { onOverlay });
    trustedClick(root.querySelector('.overlay'));
    expect(onOverlay).toHaveBeenCalledTimes(1);
  });

  it('renders a long target list as locally scrollable', () => {
    const root = mountRegister({
      targets: Array.from({ length: 14 }, (_, index) => ({ id: `c${index}`, name: `Item ${index}` })),
    });
    expect(root.querySelector('.list.scrollable')).not.toBeNull();
  });

  it('renders no list when there are no targets', () => {
    const root = mountRegister({ targets: [] });
    expect(root.querySelector('.list')).toBeNull();
  });
});

describe('passkey login picker surface', () => {
  it('selects an account by in-memory index on a trusted click', () => {
    const onSelect = vi.fn();
    const root = mountLoginPicker(
      { accounts: [{ name: 'Work', username: 'work@acme.com' }, { name: 'Personal', username: 'me@acme.com' }] },
      { onSelect },
    );
    const rows = root.querySelectorAll('button.target');
    expect(rows).toHaveLength(2);
    // An untrusted (page-forged) click must be ignored.
    rows[1]?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onSelect).not.toHaveBeenCalled();
    trustedClick(rows[1] ?? null);
    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it('shows each account name/username and the rpId', () => {
    const root = mountLoginPicker({ rpId: 'login.acme.com', accounts: [{ name: 'Work', username: 'work@acme.com' }] });
    expect(root.textContent).toContain('Work');
    expect(root.textContent).toContain('work@acme.com');
    expect(root.querySelector('.domain')?.textContent).toContain('login.acme.com');
  });

  it('cancels on a trusted cancel click and on an outside click', () => {
    const onCancel = vi.fn();
    const onOverlay = vi.fn();
    const root = mountLoginPicker({ accounts: [{ name: 'Work' }] }, { onCancel, onOverlay });
    trustedClick(root.querySelector('#vw-pk-cancel'));
    expect(onCancel).toHaveBeenCalledTimes(1);
    trustedClick(root.querySelector('.overlay'));
    expect(onOverlay).toHaveBeenCalledTimes(1);
  });

  it('renders a long account list as locally scrollable', () => {
    const root = mountLoginPicker({ accounts: Array.from({ length: 12 }, (_, i) => ({ name: `Acct ${i}` })) });
    expect(root.querySelector('.list.scrollable')).not.toBeNull();
  });
});

describe('passkey dialog styles', () => {
  it('declares dark and reduced-motion blocks', () => {
    expect(DIALOG_STYLES).toContain('prefers-color-scheme: dark');
    expect(DIALOG_STYLES).toContain('prefers-reduced-motion: reduce');
  });

  it('caps the target list height and scrolls it locally', () => {
    expect(DIALOG_STYLES).toContain('max-height');
    expect(DIALOG_STYLES).toContain('overflow-y');
  });
});
