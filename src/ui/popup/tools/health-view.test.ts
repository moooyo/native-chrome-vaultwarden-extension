// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The reskinned view composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so we stub it. LocalizeController only subscribes on connect; no storage call happens
// at mount, but the stub covers the surface it could touch.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

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

/** Own shadow text plus every child status-message's `.message` property (which lives in that
 *  element's own shadow root and so is invisible to `textContent`). */
function statusText(el: VwHealthView): string {
  const own = el.shadowRoot!.textContent ?? '';
  const messages = [...el.shadowRoot!.querySelectorAll('vw-status-message')]
    .map((node) => (node as VwStatusMessage).message ?? '')
    .join(' ');
  return `${own} ${messages}`;
}

describe('vw-health-view', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the header with a back button and localized title', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('[data-back]')).toBeTruthy();
    expect(el.shadowRoot!.textContent).toContain('密码健康'); // health.title
  });

  it('emits vw-item-back from the back button', async () => {
    const el = await mount();
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-back]')!.click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('shows loading while the report is pending', async () => {
    const el = await mount();
    el.report = { status: 'loading' };
    await el.updateComplete;
    expect(statusText(el)).toContain('加载中'); // common.loading
  });

  it('surfaces the report error message', async () => {
    const el = await mount();
    el.report = { status: 'error', message: '无法读取密码健康' };
    await el.updateComplete;
    expect(statusText(el)).toContain('无法读取密码健康');
  });

  it('shows a clean-vault empty state with a check-circle', async () => {
    const el = await mount();
    el.report = { status: 'empty' };
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-empty]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-empty] svg')).toBeTruthy();
    expect(statusText(el)).toContain('未发现问题'); // health.healthy
  });

  it('lists weak and reused entries with severity chips', async () => {
    const el = await mount();
    await ready(el);
    const rows = el.shadowRoot!.querySelectorAll('[data-entry]');
    expect(rows).toHaveLength(2);
    const text = el.shadowRoot!.textContent ?? '';
    expect(text).toContain('弱密码'); // health.weak
    expect(text).toContain('重复使用'); // health.reused
    expect(text).toContain('×3'); // reuse count
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
    // The guard blocks the emit even if the (disabled) button were somehow clicked.
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-check]')!.click();
    expect(checked).not.toHaveBeenCalled();
  });

  it('renders breach chips once the pwned result is ready', async () => {
    const el = await mount();
    await ready(el);
    el.pwned = { status: 'ready', data: new Map([['a', 5], ['b', 0]]) };
    await el.updateComplete;
    const text = el.shadowRoot!.textContent ?? '';
    expect(text).toContain('已泄露'); // health.pwned, with count
    expect(text).toContain('5');
    expect(text).toContain('未泄露'); // safe marker
  });

  it('surfaces a pwned-check error', async () => {
    const el = await mount();
    await ready(el);
    el.pwned = { status: 'error', message: '泄露检查失败' };
    await el.updateComplete;
    expect(statusText(el)).toContain('泄露检查失败');
  });
});
