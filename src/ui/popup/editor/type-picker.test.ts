// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The reskinned picker composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so we stub it before importing the component.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

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

  it('renders the four cipher types as icon-tile rows in the design order', async () => {
    const el = await mount();
    const rows = [...el.shadowRoot!.querySelectorAll<HTMLElement>('[data-type]')];
    rows.forEach((row) => {
      expect(row.tagName).toBe('BUTTON');
      expect(row.querySelector('.tile')).not.toBeNull();
      expect(row.querySelector('.chev')).not.toBeNull();
    });
    // Order follows the design: 登录 / 银行卡 / 身份 / 笔记.
    expect(rows.map((b) => b.dataset.type)).toEqual(['1', '3', '4', '2']);
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
