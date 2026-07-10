// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { render } from 'lit';
import { uiIcon } from './icon.js';

describe('UI foundation', () => {
  it('renders static SVG without unsafe HTML', () => {
    const host = document.createElement('div');
    render(uiIcon('shield'), host);
    expect(host.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(host.querySelector('path')).not.toBeNull();
  });
});
