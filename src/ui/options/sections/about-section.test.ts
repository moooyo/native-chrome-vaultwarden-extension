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

  it('shows an accurate relationship note without fake document links', async () => {
    const el = await mount();
    expect(q(el, '[data-description]').textContent).toContain('Vaultwarden');
    expect(el.shadowRoot!.querySelector('a')).toBeNull();
    expect(el.shadowRoot!.textContent).not.toMatch(/白皮书|隐私政策|开源许可|whitepaper|privacy policy|licenses/i);
  });

});
