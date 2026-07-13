// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } },
  },
}));

import './connection-section.js';
import type { VwConnectionSection } from './connection-section.js';
import type { ConnectionSaveDetail } from '../types.js';

async function mount(props: Partial<VwConnectionSection> = {}): Promise<VwConnectionSection> {
  const el = document.createElement('vw-connection-section') as VwConnectionSection;
  Object.assign(el, props);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwConnectionSection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-connection-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the account identity with an avatar initial and the self-hosted label', async () => {
    const el = await mount({ accountName: 'Alice', accountEmail: 'alice@example.com' });
    const account = q<HTMLElement>(el, '[data-account]');
    expect(account.textContent).toContain('Alice');
    expect(account.textContent).toContain('alice@example.com');
    expect(account.textContent).toContain('自托管 Vaultwarden');
    expect(q<HTMLElement>(el, '.avatar').textContent).toBe('A');
  });

  it('shows the loaded server URL', async () => {
    const el = await mount({ serverUrl: 'https://vault.example.com/' });
    expect(q<HTMLInputElement>(el, '[data-server-url]').value).toBe('https://vault.example.com/');
  });

  it('emits a normalized server URL on save', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-connection-save', (e) => saved((e as CustomEvent<ConnectionSaveDetail>).detail));
    q<HTMLInputElement>(el, '[data-server-url]').value = 'http://example.com';
    q<HTMLButtonElement>(el, '[data-save]').click();
    expect(saved).toHaveBeenCalledWith({ serverUrl: 'http://example.com/' });
  });

  it('rejects a malformed URL without emitting and shows a validation banner', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-connection-save', saved);
    q<HTMLInputElement>(el, '[data-server-url]').value = 'not a url';
    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;
    expect(saved).not.toHaveBeenCalled();
    const status = el.shadowRoot!.querySelector('vw-status-message');
    expect((status as { tone?: string } | null)?.tone).toBe('danger');
  });

  it('emits vw-sync-now when the sync button is clicked', async () => {
    const el = await mount({ lastSync: Date.now() });
    const synced = vi.fn();
    el.addEventListener('vw-sync-now', synced);
    q<HTMLButtonElement>(el, '[data-sync-now]').click();
    expect(synced).toHaveBeenCalledTimes(1);
  });

  // The sync description is passed to <vw-setting-card description="…">, which renders it in its own
  // shadow root, so it is read here from the card's reflected attribute rather than section text.
  function syncDescription(el: VwConnectionSection): string {
    const cards = [...el.shadowRoot!.querySelectorAll('vw-setting-card')];
    const syncCard = cards.find((c) => c.getAttribute('heading') === '密钥库同步');
    return syncCard?.getAttribute('description') ?? '';
  }

  it('describes the sync state: never / relative last-sync / syncing', async () => {
    const never = await mount();
    expect(syncDescription(never)).toContain('尚未同步');

    const recent = await mount({ lastSync: Date.now() });
    expect(syncDescription(recent)).toContain('刚刚');

    const busy = await mount({ syncing: true });
    expect(syncDescription(busy)).toContain('同步中');
    // The sync button is disabled while a sync is in flight.
    expect(q<HTMLButtonElement>(busy, '[data-sync-now]').disabled).toBe(true);
  });

  it('reflects the auto-sync preference as a toggle', async () => {
    const el = await mount();
    // Default pref (autoSync: true) renders a checked toggle.
    expect(el.shadowRoot!.querySelector('vw-toggle')).not.toBeNull();
  });
});
