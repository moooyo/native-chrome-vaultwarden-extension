import * as esbuild from 'esbuild';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

await mkdir('dist/ui-test', { recursive: true });

await esbuild.build({
  entryPoints: ['test/ui-render/fixture-entry.ts'],
  bundle: true,
  splitting: false,
  format: 'esm',
  target: 'es2022',
  outfile: 'dist/ui-test/fixture.js',
  sourcemap: true,
  logLevel: 'info',
  // The dormant UI modules import webextension-polyfill, which throws when loaded outside an
  // extension. The fixture must never touch a real browser/worker API, so redirect that import to
  // a deterministic stub.
  alias: {
    'webextension-polyfill': resolve('test/ui-render/webext-polyfill-stub.mjs'),
  },
});

console.log('ui fixtures built');
