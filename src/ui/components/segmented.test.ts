// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './segmented.js';
import type { VwSegmented } from './segmented.js';

async function mount(): Promise<VwSegmented> {
  const el = document.createElement('vw-segmented') as VwSegmented;
  el.options = [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }];
  el.value = 'a';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => document.body.replaceChildren());

describe('vw-segmented', () => {
  it('marks the active tab', async () => {
    const el = await mount();
    const tabs = el.shadowRoot!.querySelectorAll('button');
    expect(tabs[0]!.getAttribute('aria-selected')).toBe('true');
    expect(tabs[1]!.getAttribute('aria-selected')).toBe('false');
  });

  it('emits vw-segmented-change on selecting another tab', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-segmented-change', fired);
    el.shadowRoot!.querySelectorAll('button')[1]!.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 'b' } }));
  });
});
