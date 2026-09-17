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
    vi.useRealTimers();
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

  it('invalidates a retirement receipt when the same panel is reopened', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    const receiptCurrent = popover.showFilled();
    expect(typeof receiptCurrent === 'function' && receiptCurrent()).toBe(true);
    popover.open();
    expect(typeof receiptCurrent === 'function' && receiptCurrent()).toBe(false);
  });

  it('dismisses a status surface only on a trusted Escape key', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onDismiss = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn(), onDismiss });
    popover.showStatus('Locked');
    const box = popover.root.querySelector<HTMLElement>('.box')!;
    box.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(onDismiss).not.toHaveBeenCalled();
    const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
    Object.defineProperty(event, 'isTrusted', { value: true });
    box.dispatchEvent(event);
    expect(onDismiss).toHaveBeenCalledWith('escape');
    expect(popover.root.querySelector('.box')).toBeNull();
  });

  it('keeps the page field focused when candidates arrive from an automatic field open', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({
      anchor,
      onOpen: () => popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]),
      onSelect: vi.fn(),
    });
    anchor.focus();

    popover.open();

    expect(document.activeElement).toBe(anchor);
    expect(popover.root.activeElement).toBeNull();
  });

  it('moves focus into the list when the focused trigger opens it', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({
      anchor,
      onOpen: () => popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]),
      onSelect: vi.fn(),
    });
    const trigger = content(popover).querySelector<HTMLButtonElement>('#vw-open')!;
    trigger.focus();

    trustedClick(trigger);

    expect(popover.root.activeElement).toBe(content(popover).querySelector('[role="listbox"]'));
  });

  it('supports an explicit keyboard-owned open without changing automatic-open behavior', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({
      anchor,
      onOpen: () => popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]),
      onSelect: vi.fn(),
    });
    anchor.focus();

    popover.open(undefined, { focusList: true });

    expect(popover.root.activeElement).toBe(content(popover).querySelector('[role="listbox"]'));
  });

  it('updates the active descendant and selects its closure-owned id from the keyboard', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onOpen = vi.fn();
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect });
    popover.showCandidates([
      { id: 'cipher-secret-a', name: 'Alpha', favorite: false },
      { id: 'cipher-secret-b', name: 'Beta', favorite: false },
    ]);
    anchor.focus();
    popover.open(undefined, { focusList: true });
    popover.showCandidates([
      { id: 'cipher-secret-a', name: 'Alpha', favorite: false },
      { id: 'cipher-secret-b', name: 'Beta', favorite: false },
    ]);
    let listbox = content(popover).querySelector<HTMLElement>('[role="listbox"]')!;

    trustedKey(listbox, 'ArrowDown');
    listbox = content(popover).querySelector<HTMLElement>('[role="listbox"]')!;
    expect(listbox.getAttribute('aria-activedescendant')).toBe('vw-autofill-option-1');
    trustedKey(listbox, 'Enter');

    expect(onSelect).toHaveBeenCalledWith('cipher-secret-b');
    expect(document.activeElement).toBe(anchor);
    expect(content(popover).innerHTML).not.toContain('cipher-secret-a');
    expect(content(popover).innerHTML).not.toContain('cipher-secret-b');
  });

  it('closes on Escape, restores the anchor, and suppresses asynchronous focus reopening', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onOpen = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect: vi.fn() });
    anchor.focus();
    popover.open(undefined, { focusList: true });
    popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]);
    const listbox = content(popover).querySelector<HTMLElement>('[role="listbox"]')!;
    anchor.addEventListener('focus', () => queueMicrotask(() => popover.open()));
    onOpen.mockClear();

    const event = trustedKey(listbox, 'Escape');
    await Promise.resolve();

    expect(event.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(anchor);
    expect(content(popover).querySelector('.box')).toBeNull();
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('registers controller suppression around restored page focus', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const clearSuppression = vi.fn();
    const beforeFocusRestore = vi.fn(() => clearSuppression);
    const popover = createAutofillPopover({
      anchor,
      beforeFocusRestore,
      onOpen: vi.fn(),
      onSelect: vi.fn(),
    });
    anchor.focus();
    anchor.addEventListener('focus', () => expect(beforeFocusRestore).toHaveBeenCalledWith(anchor));
    popover.open(undefined, { focusList: true });
    popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]);

    trustedKey(content(popover).querySelector<HTMLElement>('[role="listbox"]')!, 'Escape');

    expect(clearSuppression).toHaveBeenCalledOnce();
    expect(document.activeElement).toBe(anchor);
  });

  it('does not let a suppressed delayed open rebind a newer anchor', () => {
    const first = document.getElementById('pass') as HTMLElement;
    const second = document.createElement('input');
    document.body.append(second);
    const popover = createAutofillPopover({ anchor: first, onOpen: vi.fn(), onSelect: vi.fn() });
    first.focus();
    popover.open(undefined, { focusList: true });
    popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]);
    trustedKey(content(popover).querySelector<HTMLElement>('[role="listbox"]')!, 'Escape');

    popover.open(second, { focusList: true });
    popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]);
    popover.open(first);
    trustedKey(content(popover).querySelector<HTMLElement>('[role="listbox"]')!, 'Escape');

    expect(document.activeElement).toBe(second);
  });

  it('closes after Tab without preventing or reversing native focus movement', () => {
    vi.useFakeTimers();
    const anchor = document.getElementById('pass') as HTMLElement;
    const next = document.createElement('button');
    document.body.append(next);
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    anchor.focus();
    popover.open(undefined, { focusList: true });
    popover.showCandidates([{ id: '1', name: 'Example', favorite: false }]);
    const listbox = content(popover).querySelector<HTMLElement>('[role="listbox"]')!;

    const event = trustedKey(listbox, 'Tab');
    next.focus();
    vi.runOnlyPendingTimers();

    expect(event.defaultPrevented).toBe(false);
    expect(content(popover).querySelector('.box')).toBeNull();
    expect(document.activeElement).toBe(next);
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

function trustedKey(element: Element, key: string): KeyboardEvent {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  element.dispatchEvent(event);
  return event;
}
