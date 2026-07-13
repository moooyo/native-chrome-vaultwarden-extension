// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './tools-menu.js';
import type { VwToolsMenu } from './tools-menu.js';
import type { VwMenu } from '../../components/menu.js';

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
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('lists generator, health, Sends, trash, and sync', async () => {
    const menu = await open(await mount());
    const text = (menu.shadowRoot?.textContent ?? '').toLowerCase();
    for (const label of ['generator', 'health', 'sends', 'trash', 'sync']) {
      expect(text).toContain(label);
    }
  });

  it.each([
    ['Generator', 'generator'],
    ['health', 'health'],
    ['Sends', 'sends'],
    ['Trash', 'trash'],
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
});
