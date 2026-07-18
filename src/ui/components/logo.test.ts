// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './logo.js';
import type { VwLogo } from './logo.js';

afterEach(() => document.body.replaceChildren());

describe('vw-logo', () => {
  it('renders the Material-blue key mark at the requested size', async () => {
    const el = document.createElement('vw-logo') as VwLogo;
    el.variant = 'hero';
    document.body.append(el);
    await el.updateComplete;
    const block = el.shadowRoot!.querySelector('.block') as HTMLElement;
    expect(block).not.toBeNull();
    expect(el.shadowRoot!.querySelector('svg path')).not.toBeNull();
    expect(block.getAttribute('style')).toContain('60px');
  });
});
