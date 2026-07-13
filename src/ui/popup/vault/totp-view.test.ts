// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The component composes the MiYu i18n module, which imports webextension-polyfill; that throws
// outside an extension, so stub it (matching the project's test convention).
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './totp-view.js';
import type { VwTotpView } from './totp-view.js';
import type { TotpListEntry } from '../../../core/vault/models.js';

function entry(over: Partial<TotpListEntry> = {}): TotpListEntry {
  return { id: 'a', name: 'GitHub', username: 'octo', code: '123456', period: 30, remaining: 21, ...over };
}

async function mount(over: Partial<VwTotpView> = {}): Promise<VwTotpView> {
  const el = document.createElement('vw-totp-view') as VwTotpView;
  el.entries = [entry()];
  el.currentIds = [];
  el.currentDomain = '';
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function rows(el: VwTotpView): Element[] {
  return [...el.shadowRoot!.querySelectorAll('.row')];
}

describe('vw-totp-view', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders one row per entry with name, username, code, and a countdown ring', async () => {
    const el = await mount({ entries: [entry(), entry({ id: 'b', name: 'Nebula', username: 'me@x.dev' })] });
    // Two entries in the "all" group (no current-site group without matching ids).
    expect(rows(el)).toHaveLength(2);
    expect(el.shadowRoot?.textContent).toContain('GitHub');
    expect(el.shadowRoot?.textContent).toContain('octo');
    // Code is grouped "XXX XXX" and the draining ring is present.
    expect(el.shadowRoot?.querySelector('.code')?.textContent?.trim()).toBe('123 456');
    expect(el.shadowRoot?.querySelector('svg.ring .ring-arc')).not.toBeNull();
  });

  it('shows a current-site group for entries matching the active tab, plus the all group', async () => {
    const el = await mount({
      entries: [entry({ id: 'a', name: 'GitHub' }), entry({ id: 'b', name: 'Nebula' })],
      currentIds: ['a'],
    });
    const labels = [...el.shadowRoot!.querySelectorAll('.group-label')];
    expect(labels).toHaveLength(2); // current-site + all
    // The matching entry appears in both groups (3 rows total): current(1) + all(2).
    expect(rows(el)).toHaveLength(3);
  });

  it('warms the ring to urgent in the final seconds', async () => {
    const calm = await mount({ entries: [entry({ remaining: 20 })] });
    expect(calm.shadowRoot?.querySelector('.row.urgent')).toBeNull();
    const urgent = await mount({ entries: [entry({ remaining: 3 })] });
    expect(urgent.shadowRoot?.querySelector('.row.urgent')).not.toBeNull();
  });

  it('emits vw-copy with the code when a row is clicked', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-copy', (e) => fired((e as CustomEvent).detail));
    el.shadowRoot!.querySelector<HTMLButtonElement>('.row')!.click();
    expect(fired).toHaveBeenCalledTimes(1);
    expect(fired.mock.calls[0]![0]).toMatchObject({ value: '123456' });
  });

  it('shows an empty state when there are no TOTP entries', async () => {
    const el = await mount({ entries: [] });
    expect(rows(el)).toHaveLength(0);
    expect(el.shadowRoot?.querySelector('.empty')).not.toBeNull();
  });
});
