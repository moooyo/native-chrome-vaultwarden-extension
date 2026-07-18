// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { paletteTokens, themeTokens } from './tokens.js';

describe('MiYu design tokens', () => {
  it('defines the handoff Material 3 palette, radii, and fonts', () => {
    const css = paletteTokens.cssText;
    expect(css).toContain('--p:#0b57d0');
    expect(css).toContain('--pc:#d3e3fd');
    expect(css).toContain('--sf:#ffffff');
    expect(css).toContain('--txt:#1f1f1f');
    expect(css).toContain("--vw-font-ui:'Roboto'");
    expect(css).toContain("--vw-font-mono:'Roboto Mono'");
    expect(css).toContain('--vw-radius-panel:16px');
    expect(css).not.toContain('--vw-blue');
  });

  it('themes dark at runtime via data-theme and follows system + reduced motion', () => {
    const css = paletteTokens.cssText;
    // Explicit dark override (Appearance switch) and system-following dark.
    expect(css).toContain("[data-theme='dark']");
    expect(css).toContain("[data-theme='system']");
    expect(css).toContain('prefers-color-scheme: dark');
    expect(css).toContain('--sf:#1f1f1f');
    expect(css).toContain('--p:#a8c7fa');
    expect(css).toContain('prefers-reduced-motion: reduce');
  });

  it('base themeTokens set the inherited font + color without redefining palette values', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('font-family:var(--vw-font-ui)');
    expect(css).toContain('color:var(--vw-ink)');
    // Palette values live in paletteTokens, not here (so the runtime theme switch is not shadowed).
    expect(css).not.toContain('#0b57d0');
  });
});
