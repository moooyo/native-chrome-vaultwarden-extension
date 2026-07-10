// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './menu.js';
import type { VwMenu } from './menu.js';

async function mountMenu(): Promise<VwMenu> {
  const menu = document.createElement('vw-menu') as VwMenu;
  menu.items = [
    { id: 'health', label: 'Password Health' },
    { id: 'sync', label: 'Sync' },
    { id: 'danger', label: 'Delete vault', tone: 'danger', disabled: true },
  ];
  menu.open = true;
  document.body.append(menu);
  await menu.updateComplete;
  return menu;
}

describe('vw-menu', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });


  it('moves menu focus and selects the active item', async () => {
    const menu = document.createElement('vw-menu') as VwMenu;
    menu.items = [
      { id: 'health', label: 'Password Health' },
      { id: 'sync', label: 'Sync' },
    ];
    menu.open = true;
    const selected = vi.fn();
    menu.addEventListener('vw-menu-select', selected);
    document.body.append(menu);
    await menu.updateComplete;
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(selected).toHaveBeenCalledWith(expect.objectContaining({
      detail: { id: 'sync' },
    }));
  });

  it('uses native button controls with menu/menuitem roles', async () => {
    const menu = await mountMenu();
    expect(menu.shadowRoot?.querySelector('[role="menu"]')).not.toBeNull();
    const items = menu.shadowRoot?.querySelectorAll('button[role="menuitem"]');
    expect(items?.length).toBe(3);
  });

  it('moves to the last enabled item with End, skipping disabled entries', async () => {
    const menu = await mountMenu();
    const selected = vi.fn();
    menu.addEventListener('vw-menu-select', selected);
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    // last enabled item is 'sync' because 'danger' is disabled
    expect(selected).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 'sync' } }));
  });

  it('returns to the first item with Home after moving with End', async () => {
    const menu = await mountMenu();
    const selected = vi.fn();
    menu.addEventListener('vw-menu-select', selected);
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(selected).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 'health' } }));
  });

  it('clicking a disabled item does not select it or close the menu', async () => {
    const menu = await mountMenu();
    const selected = vi.fn();
    const closed = vi.fn();
    menu.addEventListener('vw-menu-select', selected);
    menu.addEventListener('vw-menu-close', closed);
    const disabledButton = menu.shadowRoot?.querySelectorAll('button[role="menuitem"]')[2] as HTMLButtonElement;
    disabledButton.click();
    expect(selected).not.toHaveBeenCalled();
    expect(closed).not.toHaveBeenCalled();
    expect(menu.open).toBe(true);
  });

  it('closes and emits vw-menu-close on Escape', async () => {
    const menu = await mountMenu();
    const closed = vi.fn();
    menu.addEventListener('vw-menu-close', closed);
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(menu.open).toBe(false);
    expect(closed).toHaveBeenCalledTimes(1);
  });

  it('closes when a pointerdown happens outside the menu', async () => {
    const menu = await mountMenu();
    const closed = vi.fn();
    menu.addEventListener('vw-menu-close', closed);
    const outside = document.createElement('div');
    document.body.append(outside);
    outside.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    expect(menu.open).toBe(false);
    expect(closed).toHaveBeenCalledTimes(1);
  });

  it('removes the document pointerdown listener on disconnect', async () => {
    const menu = await mountMenu();
    const removeSpy = vi.spyOn(document, 'removeEventListener');
    menu.remove();
    expect(removeSpy).toHaveBeenCalledWith('pointerdown', expect.any(Function));
    removeSpy.mockRestore();
  });

  it('dispatches select/close events that are composed and bubbling', async () => {
    const menu = await mountMenu();
    let captured: CustomEvent | undefined;
    menu.addEventListener('vw-menu-select', (event) => {
      captured = event as CustomEvent;
    });
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(captured?.bubbles).toBe(true);
    expect(captured?.composed).toBe(true);
  });
});
