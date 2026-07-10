// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { themeTokens } from './tokens.js';

describe('UI foundation', () => {
  it('pins the approved popup geometry and compact visual contract', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('--vw-popup-double-width:600px');
    expect(css).toContain('--vw-popup-single-width:350px');
    expect(css).toContain('--vw-popup-height:450px');
    expect(css).toContain('--vw-blue:hsl(212 96% 47%)');
    expect(css).toContain('--vw-font-size-body:14px');
    expect(css).toContain('--vw-font-size-meta:12px');
    expect(css).toContain('--vw-radius-row:8px');
    expect(css).toContain('--vw-duration-normal:175ms');
  });

  it('defines semantic dark-mode equivalents and reduced motion', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('prefers-color-scheme:dark');
    expect(css).toContain('--vw-row-selected:hsl(214 100% 16%)');
    expect(css).toContain('prefers-reduced-motion:reduce');
    expect(css).toContain('--vw-duration-normal:0ms');
  });
});
