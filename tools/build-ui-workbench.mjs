/** Build only in the designated verification environment unless local builds are authorized. */
import { build } from 'esbuild';
import { cp, mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, '.ui-workbench');
await mkdir(output, { recursive: true });
await build({
  entryPoints: { entry: join(root, 'tools/ui-workbench/entry.ts'), inline: join(root, 'tools/ui-workbench/inline.ts') },
  outdir: output, bundle: true, format: 'esm', target: 'es2022', sourcemap: true,
  alias: { 'webextension-polyfill': join(root, 'tools/ui-workbench/browser.ts') },
  logLevel: 'info', metafile: true,
}).then(async (result) => {
  await writeFile(join(output, 'build-metadata.json'), JSON.stringify({
    fixture: true,
    productionSources: Object.keys(result.metafile.inputs).filter((path) => path.startsWith('src/')).sort(),
    entryPoints: ['src/ui/popup/app.ts', 'src/ui/options/options-app.ts', 'src/ui/receive/receive-app.ts', 'src/content/popover.ts', 'src/content/save-bar.ts', 'src/content/generate-fill.ts', 'src/content/totp-fill.ts', 'src/content/frame-autofill.ts', 'src/content/ui/structured-preview-element.ts'],
    isolatedAdapters: ['tools/ui-workbench/browser.ts', 'tools/ui-workbench/fixtures.ts'],
    limitations: ['No real worker or vault account', 'No real extension permissions', 'Login, generator, and TOTP form mutations use fixture callbacks; card and identity use real detection, staged filling, preview, and undo with synthetic returned values', 'MV3 verification is a separate extension-loaded check'],
  }, null, 2));
});
await cp(join(root, 'src/ui/fonts'), join(output, 'ui/fonts'), { recursive: true });
await cp(join(root, 'src/icons'), join(output, 'icons'), { recursive: true });
await Promise.all(['index.html', 'inline.html'].map((name) => cp(join(root, 'tools/ui-workbench', name), join(output, name))));
await writeFile(join(output, 'sample-import.json'), JSON.stringify({ encrypted: false, folders: [{ id: 'folder-workbench', name: 'Workbench' }], items: [{ id: 'cipher-workbench', organizationId: null, folderId: 'folder-workbench', type: 1, name: 'Workbench example', favorite: false, login: { username: 'lin@example.test', password: 'Synthetic-only-2026!', uris: [{ uri: 'https://example.test', match: null }] } }] }, null, 2));
console.log('UI workbench: ' + output);
