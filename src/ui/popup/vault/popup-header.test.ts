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

async function mount(generatorActive = false): Promise<VwPopupHeader> {
  const el = document.createElement('vw-popup-header') as VwPopupHeader;
  el.generatorActive = generatorActive;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function buttons(el: VwPopupHeader): HTMLButtonElement[] {
  return [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];
}

describe('vw-popup-header', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders the brand and five action buttons', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('vw-logo')).not.toBeNull();
    expect(el.shadowRoot?.textContent).toContain('密屿');
    expect(buttons(el)).toHaveLength(5);
  });

  it.each([
    ['vw-add', 0],
    ['vw-open-totp', 1],
    ['vw-generator-toggle', 2],
    ['vw-open-settings', 3],
    ['vw-lock', 4],
  ] as const)('emits %s from its button', async (event, index) => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener(event, fired);
    buttons(el)[index]!.click();
    expect(fired).toHaveBeenCalledTimes(1);
  });

  it('highlights the generator button while the generator view is open', async () => {
    const el = await mount(true);
    const generator = buttons(el)[2]!;
    expect(generator.classList.contains('active')).toBe(true);
    expect(generator.getAttribute('aria-pressed')).toBe('true');
  });

  it('highlights the authenticator button while the 2FA view is open', async () => {
    const el = await mount();
    el.totpActive = true;
    await el.updateComplete;
    const totp = buttons(el)[1]!;
    expect(totp.classList.contains('active')).toBe(true);
    expect(totp.getAttribute('aria-pressed')).toBe('true');
  });
});
