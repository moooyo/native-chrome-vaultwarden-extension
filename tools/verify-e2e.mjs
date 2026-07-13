// End-to-end against a test Vaultwarden (MIYU_SERVER / MIYU_EMAIL / MIYU_PASSWORD): configures the server in the options
// page, logs in through the popup with the one-time test account, and verifies the popup reaches the
// vault. Requires the built dist; temporarily grants the server host so no interactive permission
// prompt is needed. Run under xvfb.
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ext = join(root, 'dist');
const SERVER = process.env.MIYU_SERVER || 'http://localhost:8080';
const EMAIL = process.env.MIYU_EMAIL || 'test@example.com';
const PASSWORD = process.env.MIYU_PASSWORD || '';

// Grant the server host in the built manifest so `permissions.request` resolves without a prompt.
const manifestPath = join(ext, 'manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.host_permissions = [...new Set([...(manifest.host_permissions ?? []), `${SERVER}/*`])];
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

const ctx = await chromium.launchPersistentContext('', {
  headless: false,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-sandbox'],
});

let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
const extId = new URL(sw.url()).host;
const errors = [];

// 1) Configure the server URL in the options page.
const opt = await ctx.newPage();
opt.on('pageerror', (e) => errors.push('options: ' + e));
await opt.goto(`chrome-extension://${extId}/ui/options/options.html`, { waitUntil: 'load' });
await opt.waitForTimeout(600);
const serverInput = opt.locator('input').first();
await serverInput.fill(SERVER);
await opt.getByText('保存', { exact: true }).first().click();
await opt.waitForTimeout(1500);
console.log('server configured');

// 2) Log in via the popup.
const pop = await ctx.newPage();
pop.on('pageerror', (e) => errors.push('popup: ' + e));
await pop.goto(`chrome-extension://${extId}/ui/popup/popup.html`, { waitUntil: 'load' });
await pop.waitForTimeout(600);
const inputs = pop.locator('input');
await inputs.nth(0).fill(EMAIL);          // email
await inputs.nth(1).fill(PASSWORD);        // master password
await pop.getByText('登录', { exact: true }).first().click();

// 3) Wait for the vault (search box placeholder) or an error banner.
let outcome = 'unknown';
try {
  await pop.getByPlaceholder('搜索密钥库').waitFor({ timeout: 20000 });
  outcome = 'vault';
} catch {
  outcome = 'no-vault';
}
// Pull the vault from the server, then let the list populate.
try {
  await pop.locator('vw-sync-bar button').click({ timeout: 5000 });
  await pop.waitForTimeout(4000);
} catch { /* sync button not present */ }
await pop.waitForTimeout(500);
const deepText = await pop.evaluate(() => {
  const out = [];
  const walk = (n) => { if (n.nodeType === 3) out.push(n.textContent); if (n.shadowRoot) n.shadowRoot.childNodes.forEach(walk); n.childNodes && n.childNodes.forEach(walk); };
  walk(document.body);
  return out.join(' ');
});
await pop.screenshot({ path: '/tmp/miyu-e2e-popup.png', fullPage: true });

console.log('\n=== E2E result ===');
console.log('login outcome:', outcome);
console.log('vault search present:', deepText.includes('搜索密钥库'));
console.log('has category chips:', deepText.includes('全部') && deepText.includes('登录'));
console.log('items after sync:', ['GitHub', 'Nebula', 'Forge', '北岸银行', '家庭 Wi-Fi', '张之航'].filter((n) => deepText.includes(n)).join(', ') || '(none visible)');
console.log('page errors:', errors.length);
for (const e of errors.slice(0, 6)) console.log('  -', e);
console.log('screenshot: /tmp/miyu-e2e-popup.png');

// Restore the manifest.
manifest.host_permissions = (manifest.host_permissions ?? []).filter((h) => h !== `${SERVER}/*`);
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

await ctx.close();
process.exit(outcome === 'vault' ? 0 : 1);
