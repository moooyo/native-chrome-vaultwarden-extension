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
  const full: PopoverState = { kind: 'login', view: 'trigger', statusMessage: '', candidates: [], sidePanel: false, ...state };
  render(renderPopover(full, handlers), container);
  return container;
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
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
