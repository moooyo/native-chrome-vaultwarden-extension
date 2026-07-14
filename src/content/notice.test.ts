// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { showNotice } from './notice.js';

// showNotice is the stable content factory; it delegates to the render-based closed-shadow notice
// surface (no custom element — content scripts run in an isolated world with no custom-element
// registry, Chromium 41118431; rendering/auto-dismiss are covered by notice-element.test.ts). These
// tests assert the factory still mounts an isolated, page-inert, self-dismissing notice.

afterEach(() => {
  document.documentElement.querySelectorAll('[data-vw-notice]').forEach((node) => node.remove());
});

describe('showNotice', () => {
  it('mounts the notice inside a closed shadow root the page cannot reach', () => {
    showNotice('Protected item — open the extension to verify');
    const host = document.querySelector('[data-vw-notice]') as HTMLElement | null;
    expect(host).not.toBeNull();
    expect(host?.shadowRoot).toBeNull(); // closed shadow: not reachable from the page
  });

  it('auto-dismisses after four seconds', () => {
    vi.useFakeTimers();
    try {
      showNotice('x');
      expect(document.querySelector('[data-vw-notice]')).not.toBeNull();
      vi.advanceTimersByTime(4000);
      expect(document.querySelector('[data-vw-notice]')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('replaces the previous notice so errors never overlap', () => {
    showNotice('first error');
    showNotice('second error');
    // Only the most recent notice remains — no illegible stack of bottom-center bars.
    expect(document.querySelectorAll('[data-vw-notice]')).toHaveLength(1);
  });

  it('returns a handle that removes the notice early', () => {
    const handle = showNotice('dismiss me');
    expect(document.querySelector('[data-vw-notice]')).not.toBeNull();
    handle.remove();
    expect(document.querySelector('[data-vw-notice]')).toBeNull();
  });
});
