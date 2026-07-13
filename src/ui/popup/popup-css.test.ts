import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// The action popup is an AUTO-SIZED extension window: Chrome measures the document and sizes the
// popup to the body's height. Viewport units (vh/vw) reference the popup's own not-yet-established
// viewport during that measure, so `max-height: 100vh` on the body resolves to a near-zero value
// and collapses the popup to a sliver (the v0.0.15 regression). The frame must use a DEFINITE pixel
// height and no viewport units. This guard exists because the render harness renders the popup in a
// normal fixed-viewport page — where `vh` is well-defined — and therefore cannot catch the collapse.
const css = readFileSync(fileURLToPath(new URL('./popup.css', import.meta.url)), 'utf8');

describe('popup.css frame sizing', () => {
  it('uses no viewport units — they collapse an auto-sized popup', () => {
    expect(css).not.toMatch(/\b\d+(?:\.\d+)?v(?:h|w|min|max)\b/);
  });

  it('gives the body a definite pixel height so Chrome sizes the popup', () => {
    expect(css).toMatch(/body\s*\{[^}]*\bheight:\s*\d+px/);
  });
});
