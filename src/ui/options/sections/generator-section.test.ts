// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './generator-section.js';
import type { VwGeneratorSection } from './generator-section.js';
import { getPrefs, setPref } from '../../prefs.js';

afterEach(() => document.body.replaceChildren());

async function mount(): Promise<VwGeneratorSection> {
  const el = document.createElement('vw-generator-section') as VwGeneratorSection;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-generator-section', () => {
  it('renders the length slider and two toggles', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('input[type="range"]')).not.toBeNull();
    expect(el.shadowRoot!.querySelectorAll('vw-toggle')).toHaveLength(2);
  });

  it('updates the length pref from the slider', async () => {
    const el = await mount();
    const range = el.shadowRoot!.querySelector('input[type="range"]') as HTMLInputElement;
    range.value = '30';
    range.dispatchEvent(new Event('input'));
    expect(getPrefs().genLength).toBe(30);
    setPref('genLength', 20, false);
  });

  it('updates the numbers pref from the toggle', async () => {
    const el = await mount();
    setPref('genNumbers', true, false);
    el.shadowRoot!.querySelectorAll('vw-toggle')[0]!.dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: false }, bubbles: true, composed: true }));
    expect(getPrefs().genNumbers).toBe(false);
    setPref('genNumbers', true, false);
  });
});
