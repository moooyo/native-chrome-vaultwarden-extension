// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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
import { setLocale } from '../../i18n/index.js';

async function mount(over: Partial<VwSyncBar> = {}): Promise<VwSyncBar> {
  const el = document.createElement('vw-sync-bar') as VwSyncBar;
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-sync-bar action rail', () => {
  beforeEach(() => {
    setLocale('en', false);
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:05:00Z'));
  });

  afterEach(() => {
    document.body.replaceChildren();
    vi.useRealTimers();
  });

  it('renders unknown scheduler state and five fixed actions', async () => {
    const el = await mount();
    expect(el.shadowRoot?.textContent).toContain('Sync status unknown');
    expect(el.shadowRoot?.querySelectorAll('button')).toHaveLength(5);
  });

  it('renders scheduler-owned syncing, dirty, and successful-time states', async () => {
    const el = await mount({ syncing: true });
    expect(el.shadowRoot?.textContent).toContain('Syncing');

    el.syncing = false;
    el.dirty = true;
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).toContain('Changes waiting to sync');

    el.dirty = false;
    el.lastSuccessfulSyncAt = Date.now() - 120_000;
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).toContain('Synced · 2 min ago');
  });

  it.each([
    ['vw-generator-toggle', 0],
    ['vw-open-totp', 1],
    ['vw-open-health', 2],
    ['vw-open-settings', 3],
    ['vw-add', 4],
  ] as const)('emits %s from its action', async (event, index) => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener(event, fired);
    el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')[index]!.click();
    expect(fired).toHaveBeenCalledTimes(1);
  });

  it('marks the active generator, authenticator, and health routes', async () => {
    const el = await mount({ generatorActive: true, totpActive: true, healthActive: true });
    const buttons = el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button');
    expect(buttons[0]!.classList.contains('active')).toBe(true);
    expect(buttons[1]!.classList.contains('active')).toBe(true);
    expect(buttons[2]!.classList.contains('active')).toBe(true);
  });
});
