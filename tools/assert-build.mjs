// Atomic UI-cutover build gate. Fails the production build unless every active surface has been
// switched to the Lit roots and every legacy artifact is gone. Run automatically by `build:prod`
// after `node build.mjs --prod`, and standalone via `node tools/assert-build.mjs`.
//
// It asserts the *shipped* shape, not the source: each page HTML loads only its own script and its
// own minimal page CSS (never the deleted shared theme.css); the popup/options/receive/content
// bundles all exist; the manifest keeps the current-tab autofill permissions; the production entry
// sources are thin mounts with no imperative `innerHTML =` renderer; and no legacy theme.css
// survives anywhere under dist.

import { access, readFile } from 'node:fs/promises';

const PAGES = ['popup', 'options', 'receive'];

const required = [
  'dist/manifest.json',
  'dist/ui/popup/popup.html',
  'dist/ui/popup/popup.js',
  'dist/ui/popup/popup.css',
  'dist/ui/options/options.html',
  'dist/ui/options/options.js',
  'dist/ui/options/options.css',
  'dist/ui/receive/receive.html',
  'dist/ui/receive/receive.js',
  'dist/ui/receive/receive.css',
  'dist/content/autofill.js',
  'dist/content/page-webauthn.js',
  'dist/content/webauthn-bridge.js',
  'dist/background.js',
];

async function fileExists(path) {
  return access(path)
    .then(() => true)
    .catch((error) => {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return false;
      throw error;
    });
}

const missing = [];
for (const file of required) {
  if (!(await fileExists(file))) missing.push(file);
}
if (missing.length > 0) {
  throw new Error(`Missing built artifact(s): ${missing.join(', ')}`);
}

for (const page of PAGES) {
  const html = await readFile(`dist/ui/${page}/${page}.html`, 'utf8');
  if (html.includes('theme.css')) {
    throw new Error(`${page}.html still references the deleted shared theme.css`);
  }
  // Each page must load only its own bundle and its own minimal page CSS.
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((match) => match[1]);
  if (scripts.length !== 1 || scripts[0] !== `${page}.js`) {
    throw new Error(`${page}.html must load exactly its own ${page}.js (found: ${scripts.join(', ') || 'none'})`);
  }
  const stylesheets = [...html.matchAll(/<link\b[^>]*\brel="stylesheet"[^>]*\bhref="([^"]+)"/g)].map((match) => match[1]);
  // Each page loads the shared bundled MiYu fonts, then its own minimal page CSS.
  const expectedCss = ['../fonts/fonts.css', `${page}.css`];
  if (stylesheets.length !== 2 || stylesheets[0] !== expectedCss[0] || stylesheets[1] !== expectedCss[1]) {
    throw new Error(`${page}.html must load ../fonts/fonts.css then its own ${page}.css (found: ${stylesheets.join(', ') || 'none'})`);
  }

  const source = await readFile(`src/ui/${page}/${page}.ts`, 'utf8');
  if (/\binnerHTML\s*=/.test(source)) {
    throw new Error(`${page}.ts still contains an imperative innerHTML renderer`);
  }
}

const manifest = JSON.parse(await readFile('dist/manifest.json', 'utf8'));
for (const permission of ['activeTab', 'webNavigation']) {
  if (!manifest.permissions?.includes(permission)) {
    throw new Error(`Manifest is missing the ${permission} permission`);
  }
}

if (await fileExists('dist/ui/theme.css')) {
  throw new Error('Legacy dist/ui/theme.css still exists');
}

console.log('assert-build: atomic UI cutover verified');
