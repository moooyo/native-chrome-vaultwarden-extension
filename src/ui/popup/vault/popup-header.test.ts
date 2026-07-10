// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './popup-header.js';
import type { VwPopupHeader } from './popup-header.js';
import type { AccountInfo } from '../types.js';

async function mount(accounts: AccountInfo[] = [{ email: 'me@example.com', active: true }]): Promise<VwPopupHeader> {
  const el = document.createElement('vw-popup-header') as VwPopupHeader;
  el.accounts = accounts;
  el.pinEnabled = false;
  el.deviceRemembered = false;
  el.query = '';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-popup-header', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the account and tools menus', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('vw-account-menu')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('vw-tools-menu')).not.toBeNull();
  });

  it('emits vw-add when the add control is used', async () => {
    const el = await mount();
    const added = vi.fn();
    el.addEventListener('vw-add', added);
    el.shadowRoot?.querySelector<HTMLButtonElement>('[data-add]')!.click();
    expect(added).toHaveBeenCalledTimes(1);
  });

  it('renders New item as the primary toolbar command', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('[data-add]')?.textContent).toContain('New item');
  });

  it('emits the current search query', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-search-change', changed);
    const input = el.shadowRoot!.querySelector<HTMLInputElement>('[data-search]')!;
    input.value = 'github';
    input.dispatchEvent(new Event('input'));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { query: 'github' } }));
  });

  it('emits vw-generator when the generator control is used', async () => {
    const el = await mount();
    const gen = vi.fn();
    el.addEventListener('vw-generator', gen);
    el.shadowRoot?.querySelector<HTMLButtonElement>('[data-generator]')!.click();
    expect(gen).toHaveBeenCalledTimes(1);
  });

  it('forwards the account list to the account menu', async () => {
    const accounts: AccountInfo[] = [{ email: 'a@x', active: true }, { email: 'b@x', active: false }];
    const el = await mount(accounts);
    const menu = el.shadowRoot?.querySelector('vw-account-menu') as (Element & { accounts: AccountInfo[] }) | null;
    expect(menu?.accounts).toEqual(accounts);
  });
});
