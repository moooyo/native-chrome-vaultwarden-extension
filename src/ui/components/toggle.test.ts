// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './toggle.js';
import type { VwToggle } from './toggle.js';

async function mount(checked = false): Promise<VwToggle> {
  const el = document.createElement('vw-toggle') as VwToggle;
  el.checked = checked;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => document.body.replaceChildren());

describe('vw-toggle', () => {
  it('renders a switch with the right aria-checked', async () => {
    const el = await mount(true);
    const btn = el.shadowRoot!.querySelector('button')!;
    expect(btn.getAttribute('role')).toBe('switch');
    expect(btn.getAttribute('aria-checked')).toBe('true');
  });

  it('toggles and emits vw-toggle-change on click', async () => {
    const el = await mount(false);
    const fired = vi.fn();
    el.addEventListener('vw-toggle-change', fired);
    el.shadowRoot!.querySelector('button')!.click();
    expect(el.checked).toBe(true);
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { checked: true } }));
  });

  it('does nothing when disabled', async () => {
    const el = await mount(false);
    el.disabled = true;
    await el.updateComplete;
    const fired = vi.fn();
    el.addEventListener('vw-toggle-change', fired);
    el.shadowRoot!.querySelector('button')!.click();
    expect(fired).not.toHaveBeenCalled();
  });
});
