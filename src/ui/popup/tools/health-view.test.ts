// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './health-view.js';
import type { VwHealthView } from './health-view.js';
import type { VwStatusMessage } from '../../components/status-message.js';
import type { HealthEntry } from '../types.js';

async function mount(): Promise<VwHealthView> {
  const el = document.createElement('vw-health-view') as VwHealthView;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

const entries: HealthEntry[] = [
  { id: 'a', name: 'Weak site', weak: true, reuseCount: 1 },
  { id: 'b', name: 'Reused site', weak: false, reuseCount: 3 },
];

async function ready(el: VwHealthView): Promise<void> {
  el.report = { status: 'ready', data: entries };
  await el.updateComplete;
}

function statusText(el: VwHealthView): string {
  const own = el.shadowRoot!.textContent ?? '';
  const messages = [...el.shadowRoot!.querySelectorAll('vw-status-message')]
    .map((node) => (node as VwStatusMessage).message ?? '')
    .join(' ');
  return `${own} ${messages}`.toLowerCase();
}

describe('vw-health-view', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows loading while the report is pending', async () => {
    const el = await mount();
    el.report = { status: 'loading' };
    await el.updateComplete;
    expect(statusText(el)).toContain('checking');
  });

  it('shows a clean-vault message when empty', async () => {
    const el = await mount();
    el.report = { status: 'empty' };
    await el.updateComplete;
    expect(statusText(el)).toContain('no weak or reused');
  });

  it('lists weak and reused entries with tags', async () => {
    const el = await mount();
    await ready(el);
    const rows = el.shadowRoot!.querySelectorAll('[data-entry]');
    expect(rows).toHaveLength(2);
    const text = el.shadowRoot!.textContent ?? '';
    expect(text).toContain('Weak');
    expect(text).toContain('Reused ×3');
  });

  it('opens an item when a row is clicked', async () => {
    const el = await mount();
    await ready(el);
    const opened = vi.fn();
    el.addEventListener('vw-item-open', (e) => opened((e as CustomEvent).detail));
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-entry="b"]')!.click();
    expect(opened).toHaveBeenCalledWith({ cipherId: 'b' });
  });

  it('requests an explicit HIBP check', async () => {
    const el = await mount();
    await ready(el);
    const checked = vi.fn();
    el.addEventListener('vw-health-check', checked);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-check]')!.click();
    expect(checked).toHaveBeenCalledTimes(1);
  });

  it('does not re-request while a check is loading', async () => {
    const el = await mount();
    await ready(el);
    el.pwned = { status: 'loading' };
    await el.updateComplete;
    const checked = vi.fn();
    el.addEventListener('vw-health-check', checked);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-check]')!.click();
    expect(checked).not.toHaveBeenCalled();
  });

  it('renders breach counts once the pwned result is ready', async () => {
    const el = await mount();
    await ready(el);
    el.pwned = { status: 'ready', data: new Map([['a', 5], ['b', 0]]) };
    await el.updateComplete;
    const text = el.shadowRoot!.textContent ?? '';
    expect(text).toContain('Found in 5 breaches');
    expect(text).toContain('Not found');
  });
});
