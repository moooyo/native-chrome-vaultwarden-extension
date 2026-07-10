// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
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

  it('shows plain-language help for the selected strategy', async () => {
    const el = await mount(0);
    expect(q<HTMLElement>(el, '[data-strategy-help]').textContent?.toLowerCase()).toContain('registrable domain');
  });

  it('updates the help text when the strategy changes', async () => {
    const el = await mount(0);
    const select = q<HTMLSelectElement>(el, '[data-strategy]');
    select.value = '5';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;
    expect(q<HTMLElement>(el, '[data-strategy-help]').textContent?.toLowerCase()).toContain('never');
  });

  it('emits the chosen strategy on save', async () => {
    const el = await mount(0);
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (e) => saved((e as CustomEvent<AutofillSaveDetail>).detail));
    const select = q<HTMLSelectElement>(el, '[data-strategy]');
    select.value = '1';
    q<HTMLButtonElement>(el, '[data-strategy-save]').click();
    expect(saved).toHaveBeenCalledWith({ defaultUriMatchStrategy: 1 });
  });
});
