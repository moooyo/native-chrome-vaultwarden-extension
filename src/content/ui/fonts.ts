import browser from 'webextension-polyfill';

/**
 * Registers the bundled Latin webfonts into the host page's `document.fonts` so the
 * content-script Shadow-DOM surfaces render with Roboto / Roboto Mono. `@font-face`
 * declared *inside* a closed shadow root is not reliably honoured, so we register via the FontFace
 * API at the document level instead. The woff2 files are exposed through `web_accessible_resources`.
 *
 * Idempotent and best-effort: a page with a locked-down font policy, or a duplicate registration,
 * never throws out of here. Latin only — CJK falls back to the system stack, as designed.
 */
const FACES: ReadonlyArray<{ family: string; weight: string; file: string }> = [
  { family: 'Roboto', weight: '400', file: 'roboto-latin-400-normal.woff2' },
  { family: 'Roboto', weight: '500', file: 'roboto-latin-500-normal.woff2' },
  { family: 'Roboto', weight: '700', file: 'roboto-latin-700-normal.woff2' },
  { family: 'Roboto Mono', weight: '400', file: 'roboto-mono-latin-400-normal.woff2' },
  { family: 'Roboto Mono', weight: '500', file: 'roboto-mono-latin-500-normal.woff2' },
];

let registered = false;

export function ensureMiyuFonts(): void {
  if (registered) return;
  registered = true;
  const fontSet = (document as Document & { fonts?: FontFaceSet }).fonts;
  if (!fontSet || typeof FontFace === 'undefined') return;
  for (const face of FACES) {
    try {
      const url = browser.runtime.getURL(`ui/fonts/${face.file}`);
      const ff = new FontFace(face.family, `url(${JSON.stringify(url)}) format('woff2')`, {
        weight: face.weight,
        style: 'normal',
        display: 'swap',
      });
      // Load lazily; add immediately so layout can use it as soon as bytes arrive.
      void ff.load().then((loaded) => fontSet.add(loaded)).catch(() => undefined);
    } catch {
      /* best-effort */
    }
  }
}
