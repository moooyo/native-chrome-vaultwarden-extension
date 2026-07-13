// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';
import { NOTICE_STYLES, NOTICE_TIMEOUT_MS, presentNotice, renderNotice } from './notice-element.js';

// The notice is a render-based surface (no custom element — content scripts run in an isolated world
// with no custom-element registry, Chromium 41118431). The view test renders its template into a
// container and asserts on the produced DOM; presentNotice mounts the same template into a closed
// shadow root and auto-dismisses.

let container: HTMLElement | undefined;

afterEach(() => {
  container?.remove();
  container = undefined;
  document.body.replaceChildren();
  document.documentElement.querySelectorAll('[data-vw-notice]').forEach((node) => node.remove());
});

function mount(message: string): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  render(renderNotice({ message }), container);
  return container;
}

describe('notice surface', () => {
  it('renders the message inertly and allows long words to wrap', () => {
    const root = mount('<b>keep</b> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const bar = root.querySelector('.bar');
    expect(bar?.querySelector('b')).toBeNull();
    expect(bar?.textContent).toContain('keep');
    expect(NOTICE_STYLES).toContain('overflow-wrap');
    expect(NOTICE_STYLES).toContain('prefers-color-scheme: dark');
    expect(NOTICE_STYLES).toContain('prefers-reduced-motion: reduce');
  });

  it('presentNotice mounts a closed surface and auto-dismisses after four seconds', () => {
    vi.useFakeTimers();
    try {
      const handle = presentNotice('Protected item');
      const host = document.querySelector('[data-vw-notice]') as HTMLElement | null;
      expect(host).not.toBeNull();
      expect(host?.shadowRoot).toBeNull();
      expect(NOTICE_TIMEOUT_MS).toBe(4000);
      vi.advanceTimersByTime(NOTICE_TIMEOUT_MS);
      expect(document.querySelector('[data-vw-notice]')).toBeNull();
      handle.remove();
    } finally {
      vi.useRealTimers();
    }
  });
});
