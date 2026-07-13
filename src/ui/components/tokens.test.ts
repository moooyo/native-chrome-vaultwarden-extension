// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { paletteTokens, themeTokens } from './tokens.js';

describe('MiYu design tokens', () => {
  it('defines the moss-green MiYu palette and MiYu radii/fonts', () => {
    const css = paletteTokens.cssText;
    expect(css).toContain('--vw-teal-solid:#0E8A72');
    expect(css).toContain('--vw-accent:#0E8A72');
    expect(css).toContain('--vw-panel:#FCFCFB');
    expect(css).toContain('--vw-ink:#16181D');
    expect(css).toContain("--vw-font-ui:'Instrument Sans'");
    expect(css).toContain("--vw-font-mono:'JetBrains Mono'");
    expect(css).toContain('--vw-radius-panel:14px');
    // No trace of the deprecated Fluent-blue direction.
    expect(css).not.toContain('--vw-blue');
    expect(css).not.toContain('600px');
  });

  it('themes dark at runtime via data-theme and follows system + reduced motion', () => {
    const css = paletteTokens.cssText;
    // Explicit dark override (Appearance switch) and system-following dark.
    expect(css).toContain("[data-theme='dark']");
    expect(css).toContain("[data-theme='system']");
    expect(css).toContain('prefers-color-scheme: dark');
    expect(css).toContain('--vw-panel:#1F2229');
    // Confirmed spec correction: dark toggle-on is #2FBF9C, not the accent.
    expect(css).toContain('--vw-toggle-on:#2FBF9C');
    expect(css).toContain('prefers-reduced-motion: reduce');
  });

  it('base themeTokens set the inherited font + color without redefining palette values', () => {
    const css = themeTokens.cssText;
    expect(css).toContain('font-family: var(--vw-font-ui)');
    expect(css).toContain('color: var(--vw-ink)');
    // Palette values live in paletteTokens, not here (so the runtime theme switch is not shadowed).
    expect(css).not.toContain('#0E8A72');
  });
});
