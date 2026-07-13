// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './logo.js';
import type { VwLogo } from './logo.js';

afterEach(() => document.body.replaceChildren());

describe('vw-logo', () => {
  it('renders a moss block with a concentric-circle glyph', async () => {
    const el = document.createElement('vw-logo') as VwLogo;
    el.variant = 'hero';
    document.body.append(el);
    await el.updateComplete;
    const block = el.shadowRoot!.querySelector('.block') as HTMLElement;
    expect(block).not.toBeNull();
    expect(el.shadowRoot!.querySelector('.ring')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('.dot')).not.toBeNull();
    // hero variant → 46px block
    expect(block.getAttribute('style')).toContain('46px');
  });
});
