// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './options-shell.js';
import type { VwOptionsShell, OptionsNavItem } from './options-shell.js';

const ITEMS: OptionsNavItem[] = [
  { id: 'account', labelKey: 'options.nav.account' },
  { id: 'about', labelKey: 'options.nav.about' },
];

async function mount(): Promise<VwOptionsShell> {
  const el = document.createElement('vw-options-shell') as VwOptionsShell;
  el.items = ITEMS;
  el.selected = 'account';
  el.version = '1.3.0';
  el.accountEmail = 'me@x.dev';
  el.accountName = '张之航';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => document.body.replaceChildren());

describe('vw-options-shell', () => {
  it('renders the sidebar (logo, version badge, nav, user card) and the section title', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('vw-logo')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('.badge')!.textContent).toContain('v1.3.0');
    expect(el.shadowRoot!.querySelectorAll('.nav-item')).toHaveLength(2);
    expect(el.shadowRoot!.querySelector('.user .email')!.textContent).toContain('me@x.dev');
    // title reflects the selected nav item's localized label
    expect(el.shadowRoot!.querySelector('.title')!.textContent).toContain('账户与同步');
  });

  it('marks the selected nav item and emits vw-nav-change on click', async () => {
    const el = await mount();
    const items = el.shadowRoot!.querySelectorAll<HTMLButtonElement>('.nav-item');
    expect(items[0]!.classList.contains('on')).toBe(true);
    const fired = vi.fn();
    el.addEventListener('vw-nav-change', fired);
    items[1]!.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 'about' } }));
  });
});
