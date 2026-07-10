// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './account-menu.js';
import type { VwAccountMenu } from './account-menu.js';
import type { AccountInfo, AccountActionDetail } from '../types.js';
import type { VwMenu } from '../../components/menu.js';

interface Props {
  accounts?: AccountInfo[];
  pinEnabled?: boolean;
  deviceRemembered?: boolean;
}

async function mount(props: Props = {}): Promise<VwAccountMenu> {
  const el = document.createElement('vw-account-menu') as VwAccountMenu;
  el.accounts = props.accounts ?? [{ email: 'me@example.com', active: true }];
  el.pinEnabled = props.pinEnabled ?? false;
  el.deviceRemembered = props.deviceRemembered ?? false;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function trigger(el: VwAccountMenu): HTMLButtonElement {
  return el.shadowRoot!.querySelector<HTMLButtonElement>('[data-trigger]')!;
}

async function open(el: VwAccountMenu): Promise<VwMenu> {
  trigger(el).click();
  await el.updateComplete;
  const menu = el.shadowRoot!.querySelector('vw-menu') as VwMenu;
  await menu.updateComplete;
  return menu;
}

function itemByText(menu: VwMenu, text: string): HTMLButtonElement {
  const buttons = Array.from(menu.shadowRoot?.querySelectorAll('button[role="menuitem"]') ?? []);
  const found = buttons.find((b) => b.textContent?.includes(text));
  if (!found) throw new Error(`no menu item with text "${text}"`);
  return found as HTMLButtonElement;
}

describe('vw-account-menu', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('lists every approved account action', async () => {
    const menu = await open(await mount({ deviceRemembered: true }));
    const text = menu.shadowRoot?.textContent ?? '';
    for (const label of ['Add account', 'PIN', 'Account security', 'Options', 'Forget this device', 'Lock', 'Log out']) {
      expect(text).toContain(label);
    }
  });

  it.each([
    ['Account security', 'account-security'],
    ['Options', 'options'],
    ['Add account', 'add-account'],
    ['Lock', 'lock'],
    ['Log out', 'logout'],
  ] as const)('emits %s as the %s action', async (label, action) => {
    const el = await mount({ deviceRemembered: true });
    const emitted = vi.fn();
    el.addEventListener('vw-account-action', emitted);
    const menu = await open(el);
    itemByText(menu, label).click();
    expect(emitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { action } as AccountActionDetail }));
  });

  it('emits pin regardless of whether a PIN is configured, and labels it accordingly', async () => {
    const off = await mount({ pinEnabled: false });
    let menu = await open(off);
    expect(menu.shadowRoot?.textContent).toContain('Set up PIN');
    off.remove();

    const on = await mount({ pinEnabled: true });
    const emitted = vi.fn();
    on.addEventListener('vw-account-action', emitted);
    menu = await open(on);
    expect(menu.shadowRoot?.textContent).toContain('Manage PIN');
    itemByText(menu, 'Manage PIN').click();
    expect(emitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { action: 'pin' } }));
  });

  it('emits switch-account and remove-account with the target email', async () => {
    const el = await mount({ accounts: [{ email: 'me@x', active: true }, { email: 'other@x', active: false }] });
    const emitted = vi.fn();
    el.addEventListener('vw-account-action', emitted);
    const menu = await open(el);
    itemByText(menu, 'Switch to other@x').click();
    expect(emitted).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { action: 'switch-account', email: 'other@x' } }),
    );
    const menu2 = await open(el);
    itemByText(menu2, 'Remove other@x').click();
    expect(emitted).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { action: 'remove-account', email: 'other@x' } }),
    );
  });

  it('omits Forget this device unless the device is remembered', async () => {
    const menu = await open(await mount({ deviceRemembered: false }));
    expect(menu.shadowRoot?.textContent).not.toContain('Forget this device');
  });

  it('emits forget-device when remembered', async () => {
    const el = await mount({ deviceRemembered: true });
    const emitted = vi.fn();
    el.addEventListener('vw-account-action', emitted);
    const menu = await open(el);
    itemByText(menu, 'Forget this device').click();
    expect(emitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { action: 'forget-device' } }));
  });

  it('restores focus to the trigger when the menu closes', async () => {
    const el = await mount();
    const menu = await open(el);
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await el.updateComplete;
    expect(el.shadowRoot?.activeElement).toBe(trigger(el));
  });
});
