// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { showNotice } from './notice.js';

// showNotice is the stable content factory; it now delegates to the closed-shadow Lit `vw-notice`
// (rendering/auto-dismiss are covered by notice-element.test.ts). These tests assert the factory
// still mounts an isolated, page-inert, self-dismissing notice.

afterEach(() => {
  document.documentElement.querySelectorAll('[data-vw-notice]').forEach((node) => node.remove());
});

describe('showNotice', () => {
  it('mounts the Lit notice inside a closed shadow root the page cannot reach', () => {
    showNotice('Protected item — open the extension to verify');
    const host = document.querySelector('[data-vw-notice]') as HTMLElement | null;
    expect(host).not.toBeNull();
    expect(customElements.get('vw-notice')).toBeDefined();
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
});
