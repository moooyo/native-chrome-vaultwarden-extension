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

  it('renders the brand, menu slots, and lock control without a fabricated score', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('vw-logo')).not.toBeNull();
    expect(el.shadowRoot?.textContent).toContain('密屿');
    expect(buttons(el)).toHaveLength(1);
    expect(el.shadowRoot?.querySelector('slot[name="tools"]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('slot[name="account"]')).not.toBeNull();
    expect(el.shadowRoot?.textContent).not.toContain('86');
  });

  it('emits vw-lock from its button', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-lock', fired);
    buttons(el)[0]!.click();
    expect(fired).toHaveBeenCalledTimes(1);
  });
});
