// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } } } }));
import './autofill-section.js';
import type { VwAutofillSection } from './autofill-section.js';
import type { AutofillSaveDetail } from '../types.js';

async function mount(strategy = 0): Promise<VwAutofillSection> {
  const el = document.createElement('vw-autofill-section') as VwAutofillSection;
  el.defaultUriMatchStrategy = strategy as VwAutofillSection['defaultUriMatchStrategy'];
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwAutofillSection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-autofill-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the MiYu setting-cards: strategy select, both toggles, and the shortcut chip', async () => {
    const el = await mount(0);
    expect(q(el, '[data-strategy]')).toBeTruthy();
    expect(q(el, '[data-inline]')).toBeTruthy();
    expect(q(el, '[data-auto-submit]')).toBeTruthy();
    expect(q<HTMLElement>(el, '[data-shortcut]').textContent).toContain('Space');
  });

  it('emits the chosen strategy when the dropdown changes', async () => {
    const el = await mount(0);
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (e) => saved((e as CustomEvent<AutofillSaveDetail>).detail));
    const select = q<HTMLElement>(el, '[data-strategy]');
    select.dispatchEvent(new CustomEvent('vw-select-change', { detail: { value: '1' }, bubbles: true, composed: true }));
    expect(saved).toHaveBeenCalledWith({ defaultUriMatchStrategy: 1 });
  });

  it('reflects the loaded strategy as the select value', async () => {
    const el = await mount(5);
    expect(q<HTMLElement & { value: string }>(el, '[data-strategy]').value).toBe('5');
  });
});
