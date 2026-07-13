// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';
import {
  SAVE_BAR_STYLES,
  renderSaveBar,
  type SaveBarHandlers,
  type SaveBarState,
} from './save-bar-element.js';

// The save bar is a render-based surface (no custom element — content scripts run in an isolated world
// with no custom-element registry, Chromium 41118431). Tests render its template into a container and
// assert on the produced DOM, exactly as the factory renders it into a closed shadow root.

let container: HTMLElement | undefined;

afterEach(() => {
  container?.remove();
  container = undefined;
});

function mount(state: Partial<SaveBarState>, handlers: SaveBarHandlers = {}): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  const full: SaveBarState = { message: '', actionLabel: '', ...state };
  render(renderSaveBar(full, handlers), container);
  return container;
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

describe('save bar surface', () => {
  it('invokes onAction and onDismiss only on trusted clicks', () => {
    const onAction = vi.fn();
    const onDismiss = vi.fn();
    const root = mount({ message: 'Save this login?', actionLabel: 'Save' }, { onAction, onDismiss });

    expect(root.querySelector('#vw-save-act')?.textContent).toContain('Save');
    expect(root.querySelector('#vw-save-dismiss')?.textContent).toContain('暂不');

    root.querySelector('#vw-save-act')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onAction).not.toHaveBeenCalled();

    trustedClick(root.querySelector('#vw-save-act'));
    expect(onAction).toHaveBeenCalledTimes(1);
    trustedClick(root.querySelector('#vw-save-dismiss'));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('renders site-controlled text inertly', () => {
    const root = mount({ message: '<img src=x onerror=alert(1)> evil.test', actionLabel: 'Save' });
    const message = root.querySelector('.msg');
    expect(message?.querySelector('img')).toBeNull();
    expect(message?.textContent).toContain('evil.test');
  });

  it('allows the message to wrap on narrow viewports', () => {
    expect(SAVE_BAR_STYLES).toContain('overflow-wrap');
    expect(SAVE_BAR_STYLES).toContain('prefers-color-scheme: dark');
    expect(SAVE_BAR_STYLES).toContain('prefers-reduced-motion: reduce');
  });
});
