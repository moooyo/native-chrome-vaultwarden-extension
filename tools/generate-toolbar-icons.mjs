/* global document, Image, ImageData */
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';

const root = path.resolve(import.meta.dirname, '..');
const iconDir = path.join(root, 'src', 'icons');
const source = await readFile(path.join(iconDir, 'icon128.png'));
const sourceUrl = `data:image/png;base64,${source.toString('base64')}`;
const sizes = [16, 32, 48, 128];

await mkdir(iconDir, { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const rendered = await page.evaluate(async ({ sourceUrl, sizes }) => {
    const image = await loadImage(sourceUrl);
    const base = document.createElement('canvas');
    base.width = 128;
    base.height = 128;
    const context = base.getContext('2d', { willReadFrequently: true });
    if (!context) throw new Error('Canvas 2D is unavailable');
    context.drawImage(image, 0, 0, 128, 128);
    const original = context.getImageData(0, 0, 128, 128);

    const neutral = document.createElement('canvas');
    neutral.width = 128;
    neutral.height = 128;
    const neutralContext = neutral.getContext('2d', { willReadFrequently: true });
    if (!neutralContext) throw new Error('Canvas 2D is unavailable');
    const neutralPixels = new ImageData(new Uint8ClampedArray(original.data), 128, 128);
    for (let index = 0; index < neutralPixels.data.length; index += 4) {
      const red = neutralPixels.data[index];
      const green = neutralPixels.data[index + 1];
      const blue = neutralPixels.data[index + 2];
      const luminance = Math.round(red * 0.299 + green * 0.587 + blue * 0.114);
      neutralPixels.data[index] = luminance;
      neutralPixels.data[index + 1] = luminance;
      neutralPixels.data[index + 2] = luminance;
      neutralPixels.data[index + 3] = Math.round(neutralPixels.data[index + 3] * 0.62);
    }
    neutralContext.putImageData(neutralPixels, 0, 0);

    const locked = document.createElement('canvas');
    locked.width = 128;
    locked.height = 128;
    const lockedContext = locked.getContext('2d', { willReadFrequently: true });
    if (!lockedContext) throw new Error('Canvas 2D is unavailable');
    const lockedPixels = new ImageData(new Uint8ClampedArray(original.data), 128, 128);
    for (let index = 0; index < lockedPixels.data.length; index += 4) {
      const red = lockedPixels.data[index];
      const green = lockedPixels.data[index + 1];
      const blue = lockedPixels.data[index + 2];
      const alpha = lockedPixels.data[index + 3];
      if (alpha === 0 || (red > 225 && green > 225 && blue > 225)) continue;
      const luminance = red * 0.299 + green * 0.587 + blue * 0.114;
      const factor = 0.72 + (luminance / 255) * 0.28;
      lockedPixels.data[index] = Math.round(176 * factor);
      lockedPixels.data[index + 1] = Math.round(122 * factor);
      lockedPixels.data[index + 2] = Math.round(45 * factor);
    }
    lockedContext.putImageData(lockedPixels, 0, 0);

    // Reconstruct every white shield scanline. This removes the original check without guessing or
    // redrawing the shield outline and preserves its existing antialiasing silhouette.
    const repaired = lockedContext.getImageData(0, 0, 128, 128);
    for (let y = 0; y < 128; y += 1) {
      let first = 128;
      let last = -1;
      for (let x = 0; x < 128; x += 1) {
        const index = (y * 128 + x) * 4;
        if (repaired.data[index + 3] > 180
            && repaired.data[index] > 225
            && repaired.data[index + 1] > 225
            && repaired.data[index + 2] > 225) {
          first = Math.min(first, x);
          last = Math.max(last, x);
        }
      }
      if (last - first < 14) continue;
      for (let x = first; x <= last; x += 1) {
        const index = (y * 128 + x) * 4;
        repaired.data[index] = 255;
        repaired.data[index + 1] = 255;
        repaired.data[index + 2] = 255;
        repaired.data[index + 3] = 255;
      }
    }
    lockedContext.putImageData(repaired, 0, 0);

    // Exact geometry from uiIcon('lock'); only the stroke width/color are adapted for 16px raster use.
    const lockSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#8A5A0A" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`;
    const lock = await loadImage(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(lockSvg)}`);
    lockedContext.drawImage(lock, 28, 25, 72, 72);

    const outputs = {};
    for (const [kind, stateCanvas] of [['neutral', neutral], ['locked', locked]]) {
      outputs[kind] = {};
      for (const size of sizes) {
        const target = document.createElement('canvas');
        target.width = size;
        target.height = size;
        const targetContext = target.getContext('2d', { willReadFrequently: true });
        if (!targetContext) throw new Error('Canvas 2D is unavailable');
        targetContext.imageSmoothingEnabled = true;
        targetContext.imageSmoothingQuality = 'high';
        targetContext.drawImage(stateCanvas, 0, 0, size, size);
        const pixels = targetContext.getImageData(0, 0, size, size).data;
        let nonTransparent = 0;
        for (let index = 3; index < pixels.length; index += 4) {
          if (pixels[index] > 0) nonTransparent += 1;
        }
        if (nonTransparent < size * size * 0.35) throw new Error(`${kind}-${size} rendered blank`);
        outputs[kind][size] = target.toDataURL('image/png').slice('data:image/png;base64,'.length);
      }
    }
    return outputs;

    function loadImage(url) {
      return new Promise((resolve, reject) => {
        const next = new Image();
        next.onload = () => resolve(next);
        next.onerror = () => reject(new Error('Toolbar icon image could not be decoded'));
        next.src = url;
      });
    }
  }, { sourceUrl, sizes });

  for (const kind of ['neutral', 'locked']) {
    for (const size of sizes) {
      const bytes = Buffer.from(rendered[kind][size], 'base64');
      await writeFile(path.join(iconDir, `icon${size}_${kind}.png`), bytes);
    }
  }

  const hashes = await Promise.all(['neutral', 'locked'].flatMap((kind) => sizes.map(async (size) => ({
    kind,
    size,
    digest: createHash('sha256')
      .update(await readFile(path.join(iconDir, `icon${size}_${kind}.png`)))
      .digest('hex'),
  }))));
  if (new Set(hashes.map(({ digest }) => digest)).size !== hashes.length) {
    throw new Error('Toolbar icon variants are not unique');
  }
  console.log(`Generated and validated ${hashes.length} toolbar icon variants.`);
} finally {
  await browser.close();
}
