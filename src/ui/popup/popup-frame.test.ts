// @vitest-environment happy-dom
import { afterEach, expect, it } from 'vitest';
import './popup-frame.js';
import { VwPopupFrame } from './popup-frame.js';

async function mount(mode: 'double' | 'single' | 'auth'): Promise<VwPopupFrame> {
  const frame = document.createElement('vw-popup-frame') as VwPopupFrame;
  frame.mode = mode;
  frame.innerHTML = '<div slot="toolbar">t</div><div slot="list">l</div><div slot="detail">d</div><div>s</div>';
  document.body.append(frame);
  await frame.updateComplete;
  return frame;
}

afterEach(() => document.body.replaceChildren());

it('renders two panes in double mode', async () => {
  const frame = await mount('double');
  expect(frame.shadowRoot?.querySelector('[data-list-pane]')).not.toBeNull();
  expect(frame.shadowRoot?.querySelector('[data-detail-pane]')).not.toBeNull();
});

it.each(['single', 'auth'] as const)('renders one region in %s mode', async (mode) => {
  const frame = await mount(mode);
  expect(frame.shadowRoot?.querySelector('[data-single-pane]')).not.toBeNull();
  expect(frame.shadowRoot?.querySelector('[data-list-pane]')).toBeNull();
});

it('uses intrinsic geometry instead of the provisional extension viewport', () => {
  const cssText = VwPopupFrame.styles.map((style) => style.cssText).join(' ');

  expect(cssText).toContain('width: var(--vw-popup-double-width)');
  expect(cssText).toContain('height: var(--vw-popup-height)');
  expect(cssText).toContain('width: var(--vw-popup-single-width)');
  expect(cssText).not.toContain('100vw');
  expect(cssText).not.toContain('100vh');
});
