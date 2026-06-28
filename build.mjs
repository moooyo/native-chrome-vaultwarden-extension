import * as esbuild from 'esbuild';
import { cp, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const watch = process.argv.includes('--watch');
const outdir = 'dist';

async function copyStatic() {
  await cp('src/manifest.json', join(outdir, 'manifest.json'));
  await mkdir(join(outdir, 'ui'), { recursive: true });
  await cp('src/ui/theme.css', join(outdir, 'ui', 'theme.css'));
  await cp('src/icons', join(outdir, 'icons'), { recursive: true });
  for (const page of ['popup', 'options']) {
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
    'content/autofill': 'src/content/autofill.ts',
  },
  bundle: true,
  format: 'esm',
  target: 'es2022',
  outdir,
  sourcemap: true,
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
