// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './tabs.js';
import type { VwTabs } from './tabs.js';

async function mountTabs(): Promise<VwTabs> {
  const tabs = document.createElement('vw-tabs') as VwTabs;
  tabs.tabs = [
    { id: 'suggestions', label: 'Suggestions', count: 2 },
    { id: 'all', label: 'All items' },
  ];
  tabs.selected = 'suggestions';
  document.body.append(tabs);
  await tabs.updateComplete;
  return tabs;
}

describe('vw-tabs', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });


  it('changes tabs with ArrowRight and Home', async () => {
    const tabs = await mountTabs();
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    expect(tabs.selected).toBe('all');
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
    expect(tabs.selected).toBe('suggestions');
  });

  it('moves to the previous tab with ArrowLeft and wraps at the edges', async () => {
    const tabs = await mountTabs();
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }));
    expect(tabs.selected).toBe('all');
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    expect(tabs.selected).toBe('all');
  });

  it('moves real DOM focus to the newly selected tab on ArrowRight', async () => {
    const tabs = await mountTabs();
    const buttons = Array.from(tabs.shadowRoot?.querySelectorAll('button[role="tab"]') ?? []) as HTMLButtonElement[];
    buttons[0]?.focus();
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    await tabs.updateComplete;
    expect(tabs.shadowRoot?.activeElement).toBe(buttons[1]);
  });

  it('moves real DOM focus to the newly selected tab on ArrowLeft', async () => {
    const tabs = await mountTabs();
    const buttons = Array.from(tabs.shadowRoot?.querySelectorAll('button[role="tab"]') ?? []) as HTMLButtonElement[];
    buttons[0]?.focus();
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }));
    await tabs.updateComplete;
    expect(tabs.shadowRoot?.activeElement).toBe(buttons[1]);
  });

  it('moves real DOM focus to the last tab on End and back to the first on Home', async () => {
    const tabs = await mountTabs();
    const buttons = Array.from(tabs.shadowRoot?.querySelectorAll('button[role="tab"]') ?? []) as HTMLButtonElement[];
    buttons[0]?.focus();
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    await tabs.updateComplete;
    expect(tabs.shadowRoot?.activeElement).toBe(buttons[1]);
    tabs.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
    await tabs.updateComplete;
    expect(tabs.shadowRoot?.activeElement).toBe(buttons[0]);
  });

  it('uses native buttons with tablist/tab roles and roving tabindex', async () => {
    const tabs = await mountTabs();
    const list = tabs.shadowRoot?.querySelector('[role="tablist"]');
    expect(list).not.toBeNull();
    const buttons = Array.from(tabs.shadowRoot?.querySelectorAll('button[role="tab"]') ?? []);
    expect(buttons).toHaveLength(2);
    const selectedButton = buttons[0] as HTMLButtonElement;
    const otherButton = buttons[1] as HTMLButtonElement;
    expect(selectedButton.getAttribute('aria-selected')).toBe('true');
    expect(selectedButton.tabIndex).toBe(0);
    expect(otherButton.getAttribute('aria-selected')).toBe('false');
    expect(otherButton.tabIndex).toBe(-1);
  });

  it('selects a tab on click and dispatches a composed, bubbling vw-tab-change event', async () => {
    const tabs = await mountTabs();
    const changed = vi.fn();
    tabs.addEventListener('vw-tab-change', changed);
    const buttons = tabs.shadowRoot?.querySelectorAll('button[role="tab"]');
    (buttons?.[1] as HTMLButtonElement).click();
    expect(tabs.selected).toBe('all');
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({
      detail: { id: 'all' },
      bubbles: true,
      composed: true,
    }));
  });

  it('does not re-dispatch vw-tab-change when the selection does not change', async () => {
    const tabs = await mountTabs();
    const changed = vi.fn();
    tabs.addEventListener('vw-tab-change', changed);
    const buttons = tabs.shadowRoot?.querySelectorAll('button[role="tab"]');
    (buttons?.[0] as HTMLButtonElement).click();
    expect(changed).not.toHaveBeenCalled();
  });

  it('removes the keydown listener on disconnect', async () => {
    const tabs = await mountTabs();
    const removeSpy = vi.spyOn(HTMLElement.prototype, 'removeEventListener');
    tabs.remove();
    expect(removeSpy).toHaveBeenCalledWith('keydown', expect.any(Function));
    removeSpy.mockRestore();
  });
});
