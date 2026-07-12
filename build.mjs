import * as esbuild from 'esbuild';
import { cp, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const watch = process.argv.includes('--watch');
const prod = process.argv.includes('--prod');
const outdir = 'dist';

async function copyStatic() {
  await cp('src/manifest.json', join(outdir, 'manifest.json'));
  await mkdir(join(outdir, 'ui'), { recursive: true });
  await cp('src/icons', join(outdir, 'icons'), { recursive: true });
  await cp('src/ui/fonts', join(outdir, 'ui', 'fonts'), { recursive: true });
  await cp('src/offscreen.html', join(outdir, 'offscreen.html'));
  for (const page of ['popup', 'options', 'receive']) {
    await mkdir(join(outdir, 'ui', page), { recursive: true });
    await cp(`src/ui/${page}/${page}.html`, join(outdir, 'ui', page, `${page}.html`));
    await cp(`src/ui/${page}/${page}.css`, join(outdir, 'ui', page, `${page}.css`));
  }
}

// Extension pages + the background service worker load as ES modules (<script type="module"> /
// "type":"module"), so they build as ESM. Content scripts are injected as CLASSIC scripts, which
// cannot carry a top-level `export`/`import` — they build as IIFE, wrapping their (test-only) exports
// away so only the entry's side-effect init runs.
const shared = { bundle: true, target: 'es2022', outdir, sourcemap: !prod, logLevel: 'info' };

const esmOptions = {
  ...shared,
  format: 'esm',
  entryPoints: {
    background: 'src/background/index.ts',
    'ui/popup/popup': 'src/ui/popup/popup.ts',
    'ui/options/options': 'src/ui/options/options.ts',
    'ui/receive/receive': 'src/ui/receive/receive.ts',
    offscreen: 'src/offscreen.ts',
  },
};

const iifeOptions = {
  ...shared,
  format: 'iife',
  entryPoints: {
    'content/autofill': 'src/content/autofill.ts',
    'content/page-webauthn': 'src/content/page-webauthn.ts',
    'content/webauthn-bridge': 'src/content/webauthn-bridge.ts',
  },
};

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

if (watch) {
  const esmCtx = await esbuild.context(esmOptions);
  const iifeCtx = await esbuild.context(iifeOptions);
  await Promise.all([esmCtx.watch(), iifeCtx.watch()]);
  await copyStatic();
  console.log('watching...');
} else {
  await Promise.all([esbuild.build(esmOptions), esbuild.build(iifeOptions)]);
  await copyStatic();
  console.log('build done');
}
