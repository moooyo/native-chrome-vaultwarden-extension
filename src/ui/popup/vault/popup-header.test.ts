// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The component composes the MiYu i18n module, which imports webextension-polyfill; that throws
// outside an extension, so stub it (matching the project's test convention).
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './popup-header.js';
import type { VwPopupHeader } from './popup-header.js';

async function mount(): Promise<VwPopupHeader> {
  const el = document.createElement('vw-popup-header') as VwPopupHeader;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function buttons(el: VwPopupHeader): HTMLButtonElement[] {
  return [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];
}

describe('vw-popup-header', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders the brand, score, lock, and account controls', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('vw-logo')).not.toBeNull();
    expect(el.shadowRoot?.textContent).toContain('密屿');
    expect(buttons(el)).toHaveLength(3);
  });

  it.each([
    ['vw-sync-now', 0],
    ['vw-lock', 1],
    ['vw-open-settings', 2],
  ] as const)('emits %s from its button', async (event, index) => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener(event, fired);
    buttons(el)[index]!.click();
    expect(fired).toHaveBeenCalledTimes(1);
  });

  it('animates the score ring while syncing', async () => {
    const el = await mount();
    el.syncing = true;
    await el.updateComplete;
    expect(buttons(el)[0]!.classList.contains('syncing')).toBe(true);
    expect(buttons(el)[0]!.disabled).toBe(true);
  });
});
