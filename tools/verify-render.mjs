// Render smoke-test: loads the built MiYu extension in a real Chromium, opens the popup, options,
// and receive pages, captures console/page errors, asserts the MiYu brand renders, and screenshots
// each to /tmp. Run under xvfb (headed Chromium is required to load an MV3 extension).
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ext = join(root, 'dist');

const ctx = await chromium.launchPersistentContext('', {
  headless: false,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-sandbox'],
});

// Resolve the extension id from its MV3 service worker.
let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
const extId = new URL(sw.url()).host;
console.log('extension id:', extId);

const pages = [
  { name: 'popup', url: `chrome-extension://${extId}/ui/popup/popup.html`, expect: '密屿' },
  { name: 'options', url: `chrome-extension://${extId}/ui/options/options.html`, expect: '设置' },
  { name: 'receive', url: `chrome-extension://${extId}/ui/receive/receive.html`, expect: '接收' },
];

let failed = false;
for (const p of pages) {
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(p.url, { waitUntil: 'load' });
  await page.waitForTimeout(800);
  // Deep text extraction that pierces open shadow roots (the whole UI lives in shadow DOM).
  const body = await page.evaluate(() => {
    const out = [];
    const walk = (node) => {
      if (node.nodeType === Node.TEXT_NODE) { out.push(node.textContent); return; }
      if (node.shadowRoot) node.shadowRoot.childNodes.forEach(walk);
      node.childNodes && node.childNodes.forEach(walk);
    };
    walk(document.body);
    return out.join(' ');
  });
  const has = body.includes(p.expect);
  await page.screenshot({ path: `/tmp/miyu-${p.name}.png`, fullPage: true });
  const realErrors = errors.filter((e) => !/favicon|net::ERR|Failed to load resource/i.test(e));
  console.log(`\n[${p.name}] ${p.url}`);
  console.log(`  contains "${p.expect}": ${has ? 'YES' : 'NO'}`);
  console.log(`  console/page errors: ${realErrors.length}`);
  for (const e of realErrors.slice(0, 8)) console.log(`    - ${e}`);
  console.log(`  screenshot: /tmp/miyu-${p.name}.png`);
  if (!has || realErrors.length > 0) failed = true;
  await page.close();
}

await ctx.close();
console.log(`\n=== ${failed ? 'FAIL' : 'PASS'} ===`);
process.exit(failed ? 1 : 0);
