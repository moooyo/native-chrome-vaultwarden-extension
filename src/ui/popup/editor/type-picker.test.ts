// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './type-picker.js';
import type { VwTypePicker } from './type-picker.js';
import type { EditorTypeDetail } from './editor-types.js';

async function mount(): Promise<VwTypePicker> {
  const el = document.createElement('vw-type-picker') as VwTypePicker;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-type-picker', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders the four cipher types', async () => {
    const el = await mount();
    const types = [...el.shadowRoot!.querySelectorAll('[data-type]')].map((b) => (b as HTMLElement).dataset.type);
    expect(types).toEqual(['1', '2', '3', '4']);
  });

  it('emits vw-editor-type with the chosen type', async () => {
    const el = await mount();
    const detail = await new Promise<EditorTypeDetail>((resolve) => {
      el.addEventListener('vw-editor-type', (e) => resolve((e as CustomEvent<EditorTypeDetail>).detail), { once: true });
      el.shadowRoot!.querySelector<HTMLButtonElement>('[data-type="3"]')!.click();
    });
    expect(detail).toEqual({ type: 3 });
  });

  it('emits vw-item-back from the back button', async () => {
    const el = await mount();
    const fired = await new Promise<boolean>((resolve) => {
      el.addEventListener('vw-item-back', () => resolve(true), { once: true });
      el.shadowRoot!.querySelector<HTMLButtonElement>('[data-back]')!.click();
    });
    expect(fired).toBe(true);
  });
});
