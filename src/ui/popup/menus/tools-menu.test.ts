// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './tools-menu.js';
import type { VwToolsMenu } from './tools-menu.js';
import type { VwMenu } from '../../components/menu.js';
import { setLocale } from '../../i18n/index.js';

async function mount(): Promise<VwToolsMenu> {
  const el = document.createElement('vw-tools-menu') as VwToolsMenu;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function trigger(el: VwToolsMenu): HTMLButtonElement {
  return el.shadowRoot!.querySelector<HTMLButtonElement>('[data-trigger]')!;
}

async function open(el: VwToolsMenu): Promise<VwMenu> {
  trigger(el).click();
  await el.updateComplete;
  const menu = el.shadowRoot!.querySelector('vw-menu') as VwMenu;
  await menu.updateComplete;
  return menu;
}

function itemByText(menu: VwMenu, text: string): HTMLButtonElement {
  const buttons = Array.from(menu.shadowRoot?.querySelectorAll('button[role="menuitem"]') ?? []);
  const found = buttons.find((b) => b.textContent?.toLowerCase().includes(text.toLowerCase()));
  if (!found) throw new Error(`no menu item with text "${text}"`);
  return found as HTMLButtonElement;
}

describe('vw-tools-menu', () => {
  beforeEach(() => setLocale('en', false));

  afterEach(() => {
    document.body.replaceChildren();
  });

  it('lists the safe, fully wired tool actions', async () => {
    const menu = await open(await mount());
    const text = (menu.shadowRoot?.textContent ?? '').toLowerCase();
    for (const label of ['generator', 'health', 'send', 'sync']) {
      expect(text).toContain(label);
    }
    expect(text).not.toContain('trash');
  });

  it.each([
    ['Generator', 'generator'],
    ['health', 'health'],
    ['Send', 'sends'],
    ['Sync', 'sync'],
  ] as const)('emits %s as the %s tool action', async (label, action) => {
    const el = await mount();
    const emitted = vi.fn();
    el.addEventListener('vw-tool-action', emitted);
    const menu = await open(el);
    itemByText(menu, label).click();
    expect(emitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { action } }));
  });

  it('restores focus to the trigger when the menu closes', async () => {
    const el = await mount();
    const menu = await open(el);
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await el.updateComplete;
    expect(el.shadowRoot?.activeElement).toBe(trigger(el));
  });

  it('closes when the open trigger is clicked again', async () => {
    const el = await mount();
    await open(el);
    trigger(el).dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    trigger(el).click();
    await el.updateComplete;
    expect(el.open).toBe(false);
  });

  it('uses roving tabindex and selects the focused item', async () => {
    const el = await mount();
    const emitted = vi.fn();
    el.addEventListener('vw-tool-action', emitted);
    const menu = await open(el);
    const buttons = [...menu.shadowRoot!.querySelectorAll<HTMLButtonElement>('[role="menuitem"]')];
    expect(buttons.map((button) => button.tabIndex)).toEqual([0, -1, -1, -1]);
    buttons[1]!.focus();
    await menu.updateComplete;
    buttons[1]!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, composed: true }));
    expect(emitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { action: 'health' } }));
  });

  it('disables sync while a sync is already running', async () => {
    const el = await mount();
    el.syncing = true;
    await el.updateComplete;
    const menu = await open(el);
    expect(itemByText(menu, 'Syncing').disabled).toBe(true);
  });

  it('closes and disables the trigger when its owner is busy', async () => {
    const el = await mount();
    await open(el);
    el.disabled = true;
    await el.updateComplete;
    expect(el.open).toBe(false);
    expect(trigger(el).disabled).toBe(true);
  });
});
