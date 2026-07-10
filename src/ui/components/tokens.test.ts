// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { themeTokens } from './tokens.js';

describe('UI foundation', () => {
  it('pins the approved blue and geometry tokens', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('--vw-blue-600:#3267e3');
    expect(css).toContain('--vw-canvas:#f6f8fb');
    expect(css).toContain('--vw-radius-shell:14px');
    expect(css).toContain('prefers-color-scheme:dark');
    expect(css).toContain('prefers-reduced-motion:reduce');
  });
});
