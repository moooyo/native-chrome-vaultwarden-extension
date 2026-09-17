// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { paletteTokens, themeTokens } from './tokens.js';

describe('MiYu design tokens', () => {
  it('defines the final blue-and-white palette, radii, and bundled fonts', () => {
    const css = paletteTokens.cssText;
    expect(css).toContain('--p:#155ed7');
    expect(css).toContain('--pc:#edf4ff');
    expect(css).toContain('--sf:#ffffff');
    expect(css).toContain('--txt:#192d48');
    expect(css).toContain("--vw-font-ui:'Instrument Sans'");
    expect(css).toContain("--vw-font-mono:'JetBrains Mono'");
    expect(css).toContain('--vw-radius-panel:12px');
    expect(css).not.toContain('--vw-blue');
  });

  it('themes dark at runtime via data-theme and follows system + reduced motion', () => {
    const css = paletteTokens.cssText;
    // Explicit dark override (Appearance switch) and system-following dark.
    expect(css).toContain("[data-theme='dark']");
    expect(css).toContain("[data-theme='system']");
    expect(css).toContain('prefers-color-scheme: dark');
    expect(css).toContain('--sf:#162230');
    expect(css).toContain('--p:#91b9ff');
    expect(css).toContain('prefers-reduced-motion: reduce');
  });

  it('base themeTokens set the inherited font + color without redefining palette values', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('font-family:var(--vw-font-ui)');
    expect(css).toContain('color:var(--vw-ink)');
    // Palette values live in paletteTokens, not here (so the runtime theme switch is not shadowed).
    expect(css).not.toContain('#155ed7');
  });
});
