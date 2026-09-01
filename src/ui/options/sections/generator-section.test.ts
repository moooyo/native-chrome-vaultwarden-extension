// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './generator-section.js';
import type { VwGeneratorSection } from './generator-section.js';
import { getPrefs, initPrefs, setPref } from '../../prefs.js';

afterEach(() => document.body.replaceChildren());
beforeEach(async () => { await initPrefs(); });

async function mount(): Promise<VwGeneratorSection> {
  const el = document.createElement('vw-generator-section') as VwGeneratorSection;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-generator-section', () => {
  it('renders the length slider and all random-password class defaults', async () => {
    const el = await mount();
    const range = el.shadowRoot!.querySelector<HTMLInputElement>('input[type="range"]')!;
    expect(range.min).toBe('5');
    expect(range.max).toBe('128');
    expect(el.shadowRoot!.querySelectorAll('vw-toggle')).toHaveLength(5);
    expect(el.shadowRoot!.querySelectorAll('input[type="number"]')).toHaveLength(2);
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
    el.shadowRoot!.querySelector('[data-numbers]')!.dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: false }, bubbles: true, composed: true }));
    expect(getPrefs().genNumbers).toBe(false);
    setPref('genNumbers', true, false);
  });

  it('updates the uppercase pref from the toggle', async () => {
    const el = await mount();
    setPref('genUppercase', true, false);
    el.shadowRoot!.querySelector('[data-uppercase]')!.dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: false }, bubbles: true, composed: true }));
    expect(getPrefs().genUppercase).toBe(false);
    setPref('genUppercase', true, false);
  });

  it('updates lowercase, minimum counts, and ambiguous-character defaults', async () => {
    const el = await mount();
    el.shadowRoot!.querySelector('[data-lowercase]')!.dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    expect(getPrefs().genLowercase).toBe(false);

    const minimum = el.shadowRoot!.querySelector<HTMLInputElement>('[data-min-numbers]')!;
    minimum.value = '4';
    minimum.dispatchEvent(new Event('change'));
    expect(getPrefs().genMinNumbers).toBe(4);

    el.shadowRoot!.querySelector('[data-avoid-ambiguous]')!.dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    expect(getPrefs().genAvoidAmbiguous).toBe(false);
  });
});
