// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NOTICE_TIMEOUT_MS, VwNotice, presentNotice } from './notice-element.js';
import './notice-element.js';

afterEach(() => {
  document.body.replaceChildren();
  document.documentElement.querySelectorAll('[data-vw-notice]').forEach((node) => node.remove());
});

async function mount(configure: (element: VwNotice) => void): Promise<VwNotice> {
  const element = document.createElement('vw-notice') as VwNotice;
  configure(element);
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function shadow(element: VwNotice): ShadowRoot {
  if (!element.shadowRoot) {
    throw new Error('element has no render root');
  }
  return element.shadowRoot;
}

describe('vw-notice', () => {
  it('renders the message inertly and allows long words to wrap', async () => {
    const element = await mount((el) => {
      el.message = '<b>keep</b> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    });
    const bar = shadow(element).querySelector('.bar');
    expect(bar?.querySelector('b')).toBeNull();
    expect(bar?.textContent).toContain('keep');
    const styleText = styleTextOf(VwNotice);
    expect(styleText).toContain('overflow-wrap');
    expect(styleText).toContain('prefers-color-scheme: dark');
    expect(styleText).toContain('prefers-reduced-motion: reduce');
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

function styleTextOf(ctor: typeof VwNotice): string {
  const styles = ctor.styles;
  const list = Array.isArray(styles) ? styles : [styles];
  return list.map((style) => String((style as { cssText: string }).cssText)).join('\n');
}
