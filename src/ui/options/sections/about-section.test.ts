// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } } } }));
import './about-section.js';
import type { VwAboutSection } from './about-section.js';

async function mount(version = '0.1.0'): Promise<VwAboutSection> {
  const el = document.createElement('vw-about-section') as VwAboutSection;
  el.version = version;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwAboutSection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-about-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows the extension version', async () => {
    const el = await mount('1.2.3');
    expect(q(el, '[data-version]').textContent).toContain('1.2.3');
  });

  it('renders the hero logo and brand name', async () => {
    const el = await mount();
    expect(q(el, 'vw-logo')).toBeTruthy();
    expect(el.shadowRoot!.textContent).toContain('MiYu');
  });

  it('emits check-update when the button is clicked', async () => {
    const el = await mount();
    const checked = vi.fn();
    el.addEventListener('vw-check-update', checked);
    q<HTMLButtonElement>(el, '[data-check-update]').click();
    expect(checked).toHaveBeenCalledTimes(1);
  });

  it('shows the status message when the root supplies one', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('[data-status]')).toBeNull();
    el.status = { message: 'up to date', tone: 'info' };
    await el.updateComplete;
    expect(q(el, '[data-status]')).toBeTruthy();
  });
});
