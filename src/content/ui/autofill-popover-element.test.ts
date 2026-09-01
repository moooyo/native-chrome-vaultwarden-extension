// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';
import {
  POPOVER_STYLES,
  renderPopover,
  type PopoverHandlers,
  type PopoverState,
} from './autofill-popover-element.js';

// The popover is a render-based surface (no custom element — content scripts run in an isolated world
// with no custom-element registry, Chromium 41118431). Tests render its template into a container and
// assert on the produced DOM, exactly as the factory renders it into a closed shadow root.

let container: HTMLElement | undefined;

afterEach(() => {
  container?.remove();
  container = undefined;
});

function mount(state: Partial<PopoverState>, handlers: PopoverHandlers = {}): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  const full: PopoverState = {
    kind: 'login',
    view: 'trigger',
    statusMessage: '',
    candidates: [],
    activeIndex: -1,
    sidePanel: false,
    ...state,
  };
  render(renderPopover(full, handlers), container);
  return container;
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

function trustedKey(el: Element, key: string, options: KeyboardEventInit = {}): KeyboardEvent {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...options });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el.dispatchEvent(event);
  return event;
}

describe('popover surface', () => {
  it('invokes onOpen only on a trusted trigger click', () => {
    const onOpen = vi.fn();
    const root = mount({ view: 'trigger' }, { onOpen });
    const trigger = root.querySelector('#vw-open');
    expect(trigger?.textContent).toContain('密屿');
    trigger?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onOpen).not.toHaveBeenCalled();
    trustedClick(trigger);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('renders the status message inertly', () => {
    const root = mount({ view: 'status', statusMessage: '<img src=x onerror=alert(1)> Locked' });
    const status = root.querySelector('.status');
    expect(status?.querySelector('img')).toBeNull();
    expect(status?.textContent).toContain('Locked');
    expect(status?.getAttribute('role')).toBe('status');
    expect(status?.getAttribute('aria-live')).toBe('polite');
    expect(status?.getAttribute('aria-atomic')).toBe('true');
  });

  it('announces a completed fill without moving focus', () => {
    const root = mount({ view: 'filled' });
    const filled = root.querySelector('.filled');
    expect(filled?.getAttribute('role')).toBe('status');
    expect(filled?.getAttribute('aria-live')).toBe('polite');
    expect(filled?.getAttribute('aria-atomic')).toBe('true');
  });

  it.each([
    ['login', '1 个匹配项', '没有匹配的登录项'] as const,
    ['card', '填充银行卡', '没有保存的银行卡'] as const,
    ['identity', '填充身份', '没有保存的身份'] as const,
  ])('renders the %s header and empty state', (kind, header, empty) => {
    const withRows = mount({ kind, view: 'list', candidates: [{ id: '1', name: 'Item', sub: 'sub', favorite: false }] });
    expect(withRows.textContent).toContain('密屿');
    expect(withRows.textContent).toContain(header);

    const emptyEl = mount({ kind, view: 'list', candidates: [] });
    expect(emptyEl.textContent).toContain(empty);
  });

  it('renders each candidate as a MiYu row with a monogram tile and a 填充 action', () => {
    const root = mount({ view: 'list', candidates: [{ id: '1', name: 'Alpha', sub: 'a@example.com', favorite: false }] });
    expect(root.querySelector('.tile')?.textContent).toBe('A');
    expect(root.querySelector('.fill')?.textContent).toContain('填充');
    expect(root.textContent).toContain('Alpha');
    expect(root.textContent).toContain('a@example.com');
  });

  it('calls onSelect with the candidate id resolved from the in-memory index', () => {
    const onSelect = vi.fn();
    const root = mount({
      view: 'list',
      candidates: [
        { id: 'first', name: 'Alpha', sub: 'a@example.com', favorite: false },
        { id: 'second', name: 'Beta', sub: 'b@example.com', favorite: true },
      ],
    }, { onSelect });
    const buttons = root.querySelectorAll('button.candidate');
    trustedClick(buttons[1] ?? null);
    expect(onSelect).toHaveBeenCalledWith('second');
  });

  it('ignores untrusted candidate clicks', () => {
    const onSelect = vi.fn();
    const root = mount({ view: 'list', candidates: [{ id: '1', name: 'Alpha', sub: 'a@example.com', favorite: false }] }, { onSelect });
    root.querySelector('button.candidate')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('never emits cipher ids into DOM attributes or serialized HTML', () => {
    const root = mount({ view: 'list', candidates: [{ id: 'cipher-secret-id', name: 'Alpha', sub: 'a@example.com', favorite: false }] });
    expect(root.querySelector('[data-cipher-id]')).toBeNull();
    expect(root.querySelector('[data-target]')).toBeNull();
    expect(root.innerHTML).not.toContain('cipher-secret-id');
  });

  it('uses selected-row semantics without exposing candidate ids', () => {
    const root = mount({ view: 'list', candidates: [{ id: 'cipher-secret-id', name: 'Alpha', sub: 'a@example.com', favorite: false }] });
    const row = root.querySelector('[role="option"]')!;
    expect(row.getAttribute('aria-selected')).toBe('true');
    expect(root.innerHTML).not.toContain('cipher-secret-id');
  });

  it('uses a single listbox tab stop and an index-only active descendant', () => {
    const root = mount({
      view: 'list',
      activeIndex: 1,
      candidates: [
        { id: 'cipher-secret-a', name: 'Alpha', favorite: false },
        { id: 'cipher-secret-b', name: 'Beta', favorite: false },
      ],
    });
    const listbox = root.querySelector<HTMLElement>('[role="listbox"]')!;
    const options = root.querySelectorAll<HTMLElement>('[role="option"]');

    expect(listbox.tabIndex).toBe(0);
    expect(listbox.getAttribute('aria-activedescendant')).toBe('vw-autofill-option-1');
    expect([...options].map((option) => option.tabIndex)).toEqual([-1, -1]);
    expect([...options].map((option) => option.getAttribute('aria-selected'))).toEqual(['false', 'true']);
    expect(root.innerHTML).not.toContain('cipher-secret-a');
    expect(root.innerHTML).not.toContain('cipher-secret-b');
  });

  it('maps trusted movement keys to the next roving option index', () => {
    const onActiveIndexChange = vi.fn();
    const root = mount({
      view: 'list',
      activeIndex: 1,
      candidates: [
        { id: 'a', name: 'Alpha', favorite: false },
        { id: 'b', name: 'Beta', favorite: false },
        { id: 'c', name: 'Gamma', favorite: false },
      ],
    }, { onActiveIndexChange });
    const listbox = root.querySelector<HTMLElement>('[role="listbox"]')!;

    for (const key of ['ArrowDown', 'ArrowUp', 'Home', 'End']) trustedKey(listbox, key);

    expect(onActiveIndexChange.mock.calls.map(([index]) => index)).toEqual([2, 0, 0, 2]);
  });

  it('selects the active option only from a trusted, non-repeating Enter or Space key', () => {
    const onKeyboardSelect = vi.fn();
    const root = mount({
      view: 'list',
      activeIndex: 1,
      candidates: [
        { id: 'a', name: 'Alpha', favorite: false },
        { id: 'b', name: 'Beta', favorite: false },
      ],
    }, { onKeyboardSelect });
    const listbox = root.querySelector<HTMLElement>('[role="listbox"]')!;

    listbox.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    trustedKey(listbox, 'Enter', { repeat: true });
    trustedKey(listbox, 'Enter');
    trustedKey(listbox, ' ');

    expect(onKeyboardSelect.mock.calls.map(([index]) => index)).toEqual([1, 1]);
  });

  it('cancels on Escape but lets Tab continue its native focus movement', () => {
    const onDismiss = vi.fn();
    const root = mount({
      view: 'list',
      candidates: [{ id: 'a', name: 'Alpha', favorite: false }],
    }, { onDismiss });
    const listbox = root.querySelector<HTMLElement>('[role="listbox"]')!;

    const escape = trustedKey(listbox, 'Escape');
    const tab = trustedKey(listbox, 'Tab');

    expect(escape.defaultPrevented).toBe(true);
    expect(tab.defaultPrevented).toBe(false);
    expect(onDismiss.mock.calls.map(([reason]) => reason)).toEqual(['escape', 'tab']);
  });

  it('caps the list height and marks long lists as locally scrollable', () => {
    const root = mount({
      view: 'list',
      candidates: Array.from({ length: 12 }, (_, index) => ({ id: String(index), name: `Item ${index}`, sub: `sub ${index}`, favorite: false })),
    });
    expect(root.querySelector('.list.scrollable')).not.toBeNull();
    expect(POPOVER_STYLES).toContain('max-height');
    expect(POPOVER_STYLES).toContain('overflow-y');
  });

  it('declares dark and reduced-motion tokens', () => {
    expect(POPOVER_STYLES).toContain('prefers-color-scheme: dark');
    expect(POPOVER_STYLES).toContain('prefers-reduced-motion: reduce');
  });
});
