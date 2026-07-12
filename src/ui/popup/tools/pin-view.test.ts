// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The component composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so we stub it. LocalizeController only subscribes on connect; no storage call happens
// at mount, but the stub covers the surface it could touch.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

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
    expect(q(el, '[data-set]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-remove]')).toBeNull();
  });

  it('shows the remove control when enabled', async () => {
    const el = await mount(true);
    expect(q(el, '[data-remove]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-pin]')).toBeNull();
    expect(el.shadowRoot!.textContent).toContain('PIN 解锁已开启');
  });

  it('always renders a back control', async () => {
    const el = await mount(false);
    expect(q(el, '[data-back]')).toBeTruthy();
  });

  it('rejects a PIN shorter than 4 characters', async () => {
    const el = await mount(false);
    const set = vi.fn();
    el.addEventListener('vw-pin-set', set);
    q<HTMLInputElement>(el, '[data-pin]').value = '12';
    q<HTMLButtonElement>(el, '[data-set]').click();
    await el.updateComplete;
    expect(set).not.toHaveBeenCalled();
    expect(el.validationError ?? '').toContain('4');
    expect(q(el, 'vw-status-message')).toBeTruthy();
  });

  it('emits a validated PIN', async () => {
    const el = await mount(false);
    const set = vi.fn();
    el.addEventListener('vw-pin-set', (e) => set((e as CustomEvent<PinSetDetail>).detail));
    q<HTMLInputElement>(el, '[data-pin]').value = '1234';
    q<HTMLButtonElement>(el, '[data-set]').click();
    expect(set).toHaveBeenCalledWith({ pin: '1234' });
  });

  it('emits a validated PIN on Enter', async () => {
    const el = await mount(false);
    const set = vi.fn();
    el.addEventListener('vw-pin-set', (e) => set((e as CustomEvent<PinSetDetail>).detail));
    const input = q<HTMLInputElement>(el, '[data-pin]');
    input.value = '1234';
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(set).toHaveBeenCalledWith({ pin: '1234' });
  });

  it('emits a remove request', async () => {
    const el = await mount(true);
    const removed = vi.fn();
    el.addEventListener('vw-pin-remove', removed);
    q<HTMLButtonElement>(el, '[data-remove]').click();
    expect(removed).toHaveBeenCalledTimes(1);
  });

  it('emits vw-item-back from the back control', async () => {
    const el = await mount(false);
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    q<HTMLButtonElement>(el, '[data-back]').click();
    expect(back).toHaveBeenCalledTimes(1);
  });
});
