// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './appearance-section.js';
import type { VwAppearanceSection } from './appearance-section.js';
import { getTheme, getDensity } from '../../theme.js';
import { getLocale, setLocale } from '../../i18n/index.js';

afterEach(() => { document.body.replaceChildren(); setLocale('zh-CN', false); });

async function mount(): Promise<VwAppearanceSection> {
  const el = document.createElement('vw-appearance-section') as VwAppearanceSection;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-appearance-section', () => {
  it('renders theme, language, and density controls', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('vw-segmented')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('vw-select')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('vw-toggle')).not.toBeNull();
  });

  it('applies theme via the appearance module', async () => {
    const el = await mount();
    el.shadowRoot!.querySelector('vw-segmented')!.dispatchEvent(new CustomEvent('vw-segmented-change', { detail: { id: 'dark' }, bubbles: true, composed: true }));
    expect(getTheme()).toBe('dark');
    el.shadowRoot!.querySelector('vw-segmented')!.dispatchEvent(new CustomEvent('vw-segmented-change', { detail: { id: 'light' }, bubbles: true, composed: true }));
  });

  it('switches language via the i18n module', async () => {
    const el = await mount();
    el.shadowRoot!.querySelector('vw-select')!.dispatchEvent(new CustomEvent('vw-select-change', { detail: { value: 'en' }, bubbles: true, composed: true }));
    expect(getLocale()).toBe('en');
  });

  it('toggles compact density', async () => {
    const el = await mount();
    el.shadowRoot!.querySelector('vw-toggle')!.dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: true }, bubbles: true, composed: true }));
    expect(getDensity()).toBe('compact');
    el.shadowRoot!.querySelector('vw-toggle')!.dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: false }, bubbles: true, composed: true }));
  });
});
