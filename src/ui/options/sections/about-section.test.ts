// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './about-section.js';
import type { VwAboutSection } from './about-section.js';

async function mount(version = '0.1.0'): Promise<VwAboutSection> {
  const el = document.createElement('vw-about-section') as VwAboutSection;
  el.version = version;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-about-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows the extension version', async () => {
    const el = await mount('1.2.3');
    expect(el.shadowRoot!.querySelector('[data-version]')?.textContent).toContain('1.2.3');
  });

  it('states that secrets stay on the local device', async () => {
    const el = await mount();
    const text = el.shadowRoot!.textContent?.toLowerCase() ?? '';
    expect(text).toContain('local');
    expect(text).toContain('device');
  });
});
