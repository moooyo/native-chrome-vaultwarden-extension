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
  await cp('src/offscreen.html', join(outdir, 'offscreen.html'));
  for (const page of ['popup', 'options', 'receive']) {
    await mkdir(join(outdir, 'ui', page), { recursive: true });
    await cp(`src/ui/${page}/${page}.html`, join(outdir, 'ui', page, `${page}.html`));
    await cp(`src/ui/${page}/${page}.css`, join(outdir, 'ui', page, `${page}.css`));
  }
}

const options = {
  entryPoints: {
    background: 'src/background/index.ts',
    'ui/popup/popup': 'src/ui/popup/popup.ts',
    'ui/options/options': 'src/ui/options/options.ts',
    'ui/receive/receive': 'src/ui/receive/receive.ts',
    'content/autofill': 'src/content/autofill.ts',
    'content/page-webauthn': 'src/content/page-webauthn.ts',
    'content/webauthn-bridge': 'src/content/webauthn-bridge.ts',
    offscreen: 'src/offscreen.ts',
  },
  bundle: true,
  format: 'esm',
  target: 'es2022',
  outdir,
  sourcemap: !prod,
  logLevel: 'info',
};

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  await copyStatic();
  console.log('watching...');
} else {
  await esbuild.build(options);
  await copyStatic();
  console.log('build done');
}
