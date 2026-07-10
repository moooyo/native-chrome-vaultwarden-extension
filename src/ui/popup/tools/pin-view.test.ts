// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './pin-view.js';
import type { VwPinView } from './pin-view.js';
import type { PinSetDetail } from '../types.js';

async function mount(enabled = false): Promise<VwPinView> {
  const el = document.createElement('vw-pin-view') as VwPinView;
  el.enabled = enabled;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwPinView, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-pin-view', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows the set-PIN form when disabled', async () => {
    const el = await mount(false);
    expect(q(el, '[data-pin]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-remove]')).toBeNull();
  });

  it('shows the remove control when enabled', async () => {
    const el = await mount(true);
    expect(q(el, '[data-remove]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-pin]')).toBeNull();
    expect(el.shadowRoot!.textContent!.toLowerCase()).toContain('pin unlock is on');
  });

  it('rejects a PIN shorter than 4 characters', async () => {
    const el = await mount(false);
    const set = vi.fn();
    el.addEventListener('vw-pin-set', set);
    q<HTMLInputElement>(el, '[data-pin]').value = '12';
    q<HTMLButtonElement>(el, '[data-set]').click();
    await el.updateComplete;
    expect(set).not.toHaveBeenCalled();
    expect(el.validationError ?? '').toContain('at least 4 digits');
  });

  it('emits a validated PIN', async () => {
    const el = await mount(false);
    const set = vi.fn();
    el.addEventListener('vw-pin-set', (e) => set((e as CustomEvent<PinSetDetail>).detail));
    q<HTMLInputElement>(el, '[data-pin]').value = '1234';
    q<HTMLButtonElement>(el, '[data-set]').click();
    expect(set).toHaveBeenCalledWith({ pin: '1234' });
  });

  it('emits a remove request', async () => {
    const el = await mount(true);
    const removed = vi.fn();
    el.addEventListener('vw-pin-remove', removed);
    q<HTMLButtonElement>(el, '[data-remove]').click();
    expect(removed).toHaveBeenCalledTimes(1);
  });
});
