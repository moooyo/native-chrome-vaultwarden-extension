import { test, expect, type Page } from '@playwright/test';
import { gotoFixture, type FixtureParams } from './helpers.js';

/** A normal-text sample: a CSS selector (open shadow roots are pierced) and a human label. */
interface TextSample {
  selector: string;
  label: string;
}

interface Contrast {
  ratio: number;
  color: string;
  background: string;
}

/** Parses a computed `rgb(...)`/`rgba(...)` color into 0-255 channels. */
function parseRgb(value: string): [number, number, number] | null {
  const match = value.match(/rgba?\(([^)]+)\)/);
  if (!match || match[1] === undefined) return null;
  const parts = match[1].split(',').map((part) => Number.parseFloat(part.trim()));
  const [r, g, b] = parts;
  if (r === undefined || g === undefined || b === undefined) return null;
  if (Number.isNaN(r) || Number.isNaN(g) || Number.isNaN(b)) return null;
  return [r, g, b];
}

/** WCAG 2.1 relative luminance of an sRGB color. */
function relativeLuminance([r, g, b]: [number, number, number]): number {
  const channel = (raw: number): number => {
    const c = raw / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/** WCAG contrast ratio between two computed colors. */
function contrastRatio(foreground: string, background: string): number {
  const fg = parseRgb(foreground);
  const bg = parseRgb(background);
  if (!fg || !bg) return 0;
  const lighter = Math.max(relativeLuminance(fg), relativeLuminance(bg));
  const darker = Math.min(relativeLuminance(fg), relativeLuminance(bg));
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * Measures the actual computed text color and effective background (the nearest ancestor — across
 * open shadow boundaries — with a non-transparent background) for a rendered element.
 */
async function measure(page: Page, selector: string): Promise<{ color: string; background: string }> {
  return page.locator(selector).first().evaluate((element: Element) => {
    const isOpaque = (value: string): boolean =>
      value !== 'transparent' && !/rgba\(\s*0,\s*0,\s*0,\s*0\s*\)/.test(value);
    const color = getComputedStyle(element).color;
    let node: Element | null = element;
    while (node !== null) {
      const background = getComputedStyle(node).backgroundColor;
      if (isOpaque(background)) {
        return { color, background };
      }
      const parentElement: Element | null = node.parentElement;
      if (parentElement !== null) {
        node = parentElement;
      } else {
        const rootNode: Node = node.getRootNode();
        node = rootNode instanceof ShadowRoot ? rootNode.host : null;
      }
    }
    return { color, background: getComputedStyle(document.body).backgroundColor };
  });
}

async function contrastFor(page: Page, selector: string): Promise<Contrast> {
  const { color, background } = await measure(page, selector);
  return { ratio: contrastRatio(color, background), color, background };
}

const SURFACES: Array<{ params: FixtureParams; samples: TextSample[] }> = [
  {
    params: { surface: 'popup', state: 'suggestions', count: 6 },
    samples: [
      { selector: 'vw-suggestions-view .name', label: 'suggestion name' },
      { selector: 'vw-suggestions-view .sub', label: 'suggestion sub-text' },
    ],
  },
  {
    params: { surface: 'options' },
    samples: [{ selector: 'vw-connection-section h1', label: 'options heading' }],
  },
];

for (const theme of ['light', 'dark'] as const) {
  for (const { params, samples } of SURFACES) {
    for (const sample of samples) {
      test(`${sample.label} meets 4.5:1 contrast in ${theme} theme`, async ({ page }) => {
        await gotoFixture(page, { ...params, theme });
        const contrast = await contrastFor(page, sample.selector);
        expect(
          contrast.ratio,
          `${sample.label} (${theme}): ${contrast.color} on ${contrast.background} = ${contrast.ratio.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(4.5);
      });
    }
  }
}
