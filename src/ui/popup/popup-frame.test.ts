// @vitest-environment happy-dom
import { afterEach, expect, it } from 'vitest';
import './popup-frame.js';
import { VwPopupFrame } from './popup-frame.js';

async function mount(): Promise<VwPopupFrame> {
  const frame = document.createElement('vw-popup-frame') as VwPopupFrame;
  frame.innerHTML = '<div id="child">content</div>';
  document.body.append(frame);
  await frame.updateComplete;
  return frame;
}

afterEach(() => document.body.replaceChildren());

it('renders a single-column panel that slots its content', async () => {
  const frame = await mount();
  const panel = frame.shadowRoot?.querySelector('.panel');
  expect(panel).not.toBeNull();
  expect(panel?.querySelector('slot')).not.toBeNull();
});

it('the panel is a flex column filling the popup window', () => {
  const cssText = VwPopupFrame.styles.map((style) => style.cssText).join(' ');
  expect(cssText).toContain('flex-direction: column');
  expect(cssText).toContain('background: var(--vw-panel)');
});
