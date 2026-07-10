// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './page-shell.js';
import type { VwPageShell } from './page-shell.js';

async function mountShell(narrow: boolean): Promise<VwPageShell> {
  const shell = document.createElement('vw-page-shell') as VwPageShell;
  shell.items = [
    { id: 'general', label: 'General', icon: 'shield' },
    { id: 'sync', label: 'Sync', icon: 'refresh' },
  ];
  shell.selected = 'general';
  shell.narrow = narrow;
  document.body.append(shell);
  await shell.updateComplete;
  return shell;
}

describe('vw-page-shell', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });


  it('renders a navigation rail of native buttons when not narrow', async () => {
    const shell = await mountShell(false);
    expect(shell.hasAttribute('narrow')).toBe(false);
    expect(shell.shadowRoot?.querySelector('select')).toBeNull();
    const nav = shell.shadowRoot?.querySelector('nav');
    expect(nav).not.toBeNull();
    const buttons = shell.shadowRoot?.querySelectorAll('nav button');
    expect(buttons).toHaveLength(2);
  });

  it('renders bounded rail and content workbench regions', async () => {
    const shell = await mountShell(false);
    expect(shell.shadowRoot!.querySelector('[data-page-shell]')).not.toBeNull();
    expect(shell.shadowRoot!.querySelector('[data-settings-rail]')).not.toBeNull();
    expect(shell.shadowRoot!.querySelector('[data-settings-content]')).not.toBeNull();
    expect((shell.constructor as typeof VwPageShell).styles.toString()).toContain('width: 18px');
  });

  it('selects a rail item on click and emits a composed, bubbling vw-tab-change', async () => {
    const shell = await mountShell(false);
    const changed = vi.fn();
    shell.addEventListener('vw-tab-change', changed);
    const buttons = shell.shadowRoot?.querySelectorAll('nav button');
    (buttons?.[1] as HTMLButtonElement).click();
    expect(shell.selected).toBe('sync');
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({
      detail: { id: 'sync' },
      bubbles: true,
      composed: true,
    }));
  });

  it('marks the active rail item with aria-current', async () => {
    const shell = await mountShell(false);
    const buttons = Array.from(shell.shadowRoot?.querySelectorAll('nav button') ?? []) as HTMLButtonElement[];
    expect(buttons[0]?.getAttribute('aria-current')).toBe('page');
    expect(buttons[1]?.hasAttribute('aria-current')).toBe(false);
  });

  it('renders a narrow top-selector class and a native select instead of the rail', async () => {
    const shell = await mountShell(true);
    expect(shell.hasAttribute('narrow')).toBe(true);
    expect(shell.shadowRoot?.querySelector('nav')).toBeNull();
    const select = shell.shadowRoot?.querySelector('select');
    expect(select).not.toBeNull();
    expect(select?.value).toBe('general');
  });

  it('changes selection from the narrow selector and emits vw-tab-change', async () => {
    const shell = await mountShell(true);
    const changed = vi.fn();
    shell.addEventListener('vw-tab-change', changed);
    const select = shell.shadowRoot!.querySelector('select')!;
    select.value = 'sync';
    select.dispatchEvent(new Event('change', { bubbles: true }));
    expect(shell.selected).toBe('sync');
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 'sync' } }));
  });

  it('renders slotted content in the main region', async () => {
    const shell = await mountShell(false);
    const content = document.createElement('p');
    content.textContent = 'panel body';
    shell.append(content);
    await shell.updateComplete;
    const slot = shell.shadowRoot?.querySelector('slot:not([name])') as HTMLSlotElement;
    expect(slot.assignedElements()).toContain(content);
  });
});
