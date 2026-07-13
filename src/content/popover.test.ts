// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAutofillPopover } from './popover.js';
import type { AutofillPopover } from './popover.js';

// The factory mounts a render-based surface inside a CLOSED shadow root (no custom element — content
// scripts run in an isolated world with no custom-element registry, Chromium 41118431). The closed root
// is exposed only through the returned handle's `.root`; the host's own `.shadowRoot` stays null so the
// page cannot reach it. Rendering is synchronous, so no update flush is needed between drive and assert.

describe('autofill popover factory', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="pass" type="password">';
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it('mounts inside a closed shadow root the host does not expose', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });

    expect(popover.element.shadowRoot).toBeNull();
    expect(popover.root.querySelector('.box')).not.toBeNull();
    expect(popover.root.querySelector('#vw-open')?.textContent).toContain('密屿');
  });

  it('renders status text in the closed root', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showStatus('Locked');
    expect(content(popover).textContent).toContain('Locked');
  });

  it('ignores untrusted open clicks', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onOpen = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect: vi.fn() });

    content(popover).querySelector<HTMLButtonElement>('#vw-open')?.click();

    expect(onOpen).not.toHaveBeenCalled();
  });

  it('renders candidates (common shape) and calls onSelect when clicked', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{ id: '1', name: 'Example', sub: 'me@example.com', favorite: false }]);
    const root = content(popover);
    trustedClick(root.querySelector<HTMLButtonElement>('button.candidate')!);
    expect(onSelect).toHaveBeenCalledWith('1');
    expect(root.textContent).toContain('me@example.com');
    expect(root.textContent).not.toContain('secret');
  });

  it('uses a card header when kind is card', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, kind: 'card', onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{ id: '1', name: 'Visa', sub: '•••• 4242', favorite: false }]);
    expect(content(popover).textContent).toContain('填充银行卡');
  });

  it('uses an identity header when kind is identity', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, kind: 'identity', onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{ id: '1', name: 'Ada Lovelace', sub: '1 Analytical Way', favorite: false }]);
    expect(content(popover).textContent).toContain('填充身份');
  });

  it('ignores untrusted candidate clicks', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{ id: '1', name: 'Example', sub: 'me@example.com', favorite: false }]);

    content(popover).querySelector<HTMLButtonElement>('button.candidate')?.click();

    expect(onSelect).not.toHaveBeenCalled();
  });

  it('does not render cipher ids into DOM attributes or serialized HTML', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{
      id: 'cipher-secret-id',
      name: 'Example',
      sub: 'me@example.com',
      favorite: false,
    }]);
    const root = content(popover);

    expect(root.querySelector('[data-cipher-id]')).toBeNull();
    expect(root.innerHTML).not.toContain('cipher-secret-id');
  });

  it('open() invokes onOpen without a DOM event', () => {
    const anchor = document.createElement('input');
    document.body.append(anchor);
    const onOpen = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect: () => {} });
    popover.open();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('remove() detaches the host from the page', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    expect(popover.element.isConnected).toBe(true);
    popover.remove();
    expect(popover.element.isConnected).toBe(false);
  });
});

/** The popover's closed shadow root, exposed through the handle. Rendering is synchronous, so the latest
 *  view is present immediately after any drive call. */
function content(popover: AutofillPopover): ShadowRoot {
  return popover.root;
}

function trustedClick(button: HTMLButtonElement): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  button.dispatchEvent(event);
}
