// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './sync-bar.js';
import type { VwSyncBar } from './sync-bar.js';

async function mount(over: Partial<VwSyncBar> = {}): Promise<VwSyncBar> {
  const el = document.createElement('vw-sync-bar') as VwSyncBar;
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-sync-bar', () => {
  afterEach(() => document.body.replaceChildren());

  it('shows a relative "synced" label and a teal dot when idle', async () => {
    const el = await mount({ syncing: false, lastSync: Date.now() });
    expect(el.shadowRoot?.textContent).toContain('已同步');
    expect(el.shadowRoot?.querySelector('.dot.syncing')).toBeNull();
  });

  it('spins the icon and shows the syncing label while syncing', async () => {
    const el = await mount({ syncing: true, lastSync: Date.now() });
    expect(el.shadowRoot?.textContent).toContain('正在同步');
    expect(el.shadowRoot?.querySelector('.dot.syncing')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('button.spin')).not.toBeNull();
  });

  it('emits vw-sync-now on click when not already syncing', async () => {
    const el = await mount({ syncing: false });
    const fired = vi.fn();
    el.addEventListener('vw-sync-now', fired);
    el.shadowRoot!.querySelector<HTMLButtonElement>('button')!.click();
    expect(fired).toHaveBeenCalledTimes(1);
  });

  it('does not emit while a sync is already in flight', async () => {
    const el = await mount({ syncing: true });
    const fired = vi.fn();
    el.addEventListener('vw-sync-now', fired);
    el.shadowRoot!.querySelector<HTMLButtonElement>('button')!.click();
    expect(fired).not.toHaveBeenCalled();
  });
});
