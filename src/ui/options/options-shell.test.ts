// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './options-shell.js';
import type { VwOptionsShell, OptionsNavItem } from './options-shell.js';
import { getLocale, setLocale } from '../i18n/index.js';
import { getTheme, setTheme } from '../theme.js';

const ITEMS: OptionsNavItem[] = [
  { id: 'account', labelKey: 'options.nav.account' },
  { id: 'about', labelKey: 'options.nav.about' },
];

async function mount(): Promise<VwOptionsShell> {
  const el = document.createElement('vw-options-shell') as VwOptionsShell;
  el.items = ITEMS;
  el.selected = 'account';
  el.version = '1.3.0';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

// Theme + locale are module-global singletons; reset them so tests don't leak into each other.
beforeEach(() => {
  setTheme('light', false);
  setLocale('zh-CN', false);
});
afterEach(() => document.body.replaceChildren());

describe('vw-options-shell', () => {
  it('renders the sidebar (logo, version badge, nav) and the section title', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('vw-logo')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('.badge')!.textContent).toContain('v1.3.0');
    expect(el.shadowRoot!.querySelectorAll('.nav-item')).toHaveLength(2);
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

  // --- footer quick controls -----------------------------------------------------------------

  it('footer shows theme, language, and logout controls — and no account email', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('[data-theme-toggle]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-lang="zh-CN"]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-lang="en"]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-logout]')).not.toBeNull();
    // The old user card (avatar + name + email) must be gone.
    expect(el.shadowRoot!.querySelector('.user')).toBeNull();
  });

  it('theme toggle flips the active theme between light and dark', async () => {
    const el = await mount();
    expect(getTheme()).toBe('light');
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-theme-toggle]')!.click();
    expect(getTheme()).toBe('dark');
    await el.updateComplete;
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-theme-toggle]')!.click();
    expect(getTheme()).toBe('light');
  });

  it('theme toggle exposes aria-pressed reflecting the active (dark) theme', async () => {
    const el = await mount();
    const btn = () => el.shadowRoot!.querySelector<HTMLButtonElement>('[data-theme-toggle]')!;
    expect(btn().getAttribute('aria-pressed')).toBe('false');
    btn().click();
    await el.updateComplete;
    expect(btn().getAttribute('aria-pressed')).toBe('true');
  });

  it('language segments switch the active locale', async () => {
    const el = await mount();
    expect(getLocale()).toBe('zh-CN');
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-lang="en"]')!.click();
    expect(getLocale()).toBe('en');
    await el.updateComplete;
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-lang="zh-CN"]')!.click();
    expect(getLocale()).toBe('zh-CN');
  });

  it('emits vw-logout when the logout control is clicked', async () => {
    const el = await mount();
    const out = vi.fn();
    el.addEventListener('vw-logout', out);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-logout]')!.click();
    expect(out).toHaveBeenCalledTimes(1);
  });
});
