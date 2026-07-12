// Verifies the inline generate panel (design 2e) mounts on a real page: serves a registration form
// over http (content scripts only run on http/https), loads the built extension, focuses the
// new-password field, and confirms a closed-shadow panel host appears — then screenshots it. The 2FA
// panel (3a) needs a matching vault item with a TOTP, so it's covered by unit/factory tests instead.
//
// NOTE: run this against REAL Chrome. Playwright's bundled Chromium exposes `customElements` as null
// in the content-script isolated world, so no content-script custom element (this project's popover,
// save-bar, passkey dialog, or these panels) can upgrade there — the panels render only where
// content-script custom elements are supported. The extension pages (popup/options/receive) are
// verified separately by tools/verify-render.mjs, which passes.
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createServer } from 'node:http';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ext = join(root, 'dist');

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signup</title>
<style>body{font-family:sans-serif;max-width:360px;margin:60px auto}input{display:block;width:100%;height:34px;margin:8px 0;box-sizing:border-box}</style></head>
<body><form><h2>Create account</h2>
<input type="email" name="email" autocomplete="email" placeholder="Email" />
<input type="password" name="password" autocomplete="new-password" placeholder="New password" />
<input type="password" name="confirm" autocomplete="new-password" placeholder="Confirm password" />
<button type="submit">Sign up</button></form></body></html>`;

const server = createServer((_req, res) => { res.setHeader('content-type', 'text/html'); res.end(PAGE); });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

const ctx = await chromium.launchPersistentContext('', {
  headless: false,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-sandbox'],
});
let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });

const page = await ctx.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(`${e.message}\n${e.stack ?? ''}`.slice(0, 400)));
page.on('console', (m) => {
  if (m.type() === 'error') {
    const loc = m.location();
    errors.push(`${m.text()} @ ${loc.url}:${loc.lineNumber}`);
  }
});
await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'load' });
await page.waitForTimeout(1200); // content script attaches at document_idle

const before = await page.evaluate(() => document.querySelectorAll('div[data-vw-popover-for]').length);
await page.focus('input[autocomplete="new-password"]');
await page.waitForTimeout(900);
const after = await page.evaluate(() => document.querySelectorAll('div[data-vw-popover-for]').length);
await page.screenshot({ path: '/tmp/miyu-generate-panel.png' });

console.log('\n=== 2e generate panel ===');
console.log('panel hosts before focus:', before);
console.log('panel hosts after focus :', after);
console.log('page errors:', errors.length);
for (const e of errors.slice(0, 5)) console.log('  -', e);
console.log('screenshot: /tmp/miyu-generate-panel.png');

await ctx.close();
server.close();
const ok = after > before && errors.length === 0;
console.log(`\n=== ${ok ? 'PASS' : 'FAIL'} ===`);
process.exit(ok ? 0 : 1);
