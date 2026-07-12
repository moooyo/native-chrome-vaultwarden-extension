// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './select-menu.js';
import type { VwSelect } from './select-menu.js';

afterEach(() => document.body.replaceChildren());

describe('vw-select', () => {
  it('renders options and emits vw-select-change', async () => {
    const el = document.createElement('vw-select') as VwSelect;
    el.options = [{ value: '1', label: 'One' }, { value: '2', label: 'Two' }];
    el.value = '1';
    document.body.append(el);
    await el.updateComplete;
    expect(el.shadowRoot!.querySelectorAll('option')).toHaveLength(2);
    const fired = vi.fn();
    el.addEventListener('vw-select-change', fired);
    const select = el.shadowRoot!.querySelector('select')!;
    select.value = '2';
    select.dispatchEvent(new Event('change'));
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { value: '2' } }));
  });
});
