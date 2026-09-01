// End-to-end against a disposable Vaultwarden (MIYU_SERVER / MIYU_EMAIL / MIYU_PASSWORD): configure
// the server through Options, log in through the popup, sync through the visible Tools menu, and
// verify the seeded vault appears. The built extension is copied before host permissions are added,
// so an interrupted run can never mutate the release candidate in dist/.
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sourceExt = join(root, 'dist');
const runRoot = mkdtempSync(join(tmpdir(), 'miyu-e2e-'));
const ext = join(runRoot, 'dist');
const screenshotPath = join(tmpdir(), 'miyu-e2e-popup.png');
const SERVER = process.env.MIYU_SERVER || 'http://localhost:8080';
const EMAIL = process.env.MIYU_EMAIL || 'test@example.com';
const PASSWORD = process.env.MIYU_PASSWORD || '';
const BROWSER_EXECUTABLE = process.env.MIYU_BROWSER_EXECUTABLE;
const SERVER_ORIGIN = new URL(SERVER).origin;
const EXPECTED_ITEMS = [
  'MiYu-Test: Localhost Login',
  'MiYu-Test: Localhost Card',
  'MiYu-Test: Localhost Identity',
  'MiYu-Test: Passkey Work',
  'MiYu-Test: Passkey Personal',
];

cpSync(sourceExt, ext, { recursive: true });
const manifestPath = join(ext, 'manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.host_permissions = [...new Set([...(manifest.host_permissions ?? []), `${SERVER}/*`])];
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

const errors = [];
const failedRequests = [];
let context;
let popup;
let outcome = 'not-started';
let state = 'unknown';
let visibleItems = [];

try {
  context = await chromium.launchPersistentContext('', {
    headless: false,
    ...(BROWSER_EXECUTABLE ? { executablePath: BROWSER_EXECUTABLE } : {}),
    args: [
      `--disable-extensions-except=${ext}`,
      `--load-extension=${ext}`,
      '--no-sandbox',
    ],
  });
  context.on('weberror', (webError) => errors.push(`browser: ${webError.error()}`));
  context.on('requestfailed', (request) => {
    const url = request.url();
    if (url.startsWith('chrome-extension://') || url.startsWith(SERVER_ORIGIN)) {
      failedRequests.push(`${request.method()} ${url}: ${request.failure()?.errorText ?? 'failed'}`);
    }
  });

  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent('serviceworker', { timeout: 15_000 });
  worker.on('console', (message) => {
    if (message.type() === 'error') errors.push(`worker: ${message.text()}`);
  });
  const extensionId = new URL(worker.url()).host;

  const options = await context.newPage();
  watchPage(options, 'options', errors);
  await options.goto(`chrome-extension://${extensionId}/ui/options/options.html`, { waitUntil: 'load' });
  await waitForRpc(options, { type: 'auth.getState' }, (response) => response?.ok === true, 'background RPC');

  const serverInput = options.locator('input').first();
  await serverInput.fill(SERVER);
  await options.getByText('保存', { exact: true }).first().click();
  await waitForRpc(
    options,
    { type: 'settings.get' },
    (response) => response?.ok === true && sameServer(response.data?.serverUrl, SERVER),
    'server configuration',
  );
  console.log('server configured');

  popup = await context.newPage();
  watchPage(popup, 'popup', errors);
  await popup.goto(`chrome-extension://${extensionId}/ui/popup/popup.html`, { waitUntil: 'load' });
  const inputs = popup.locator('vw-auth-views input');
  await inputs.nth(0).fill(EMAIL);
  await inputs.nth(1).fill(PASSWORD);
  await popup.getByText('登录', { exact: true }).first().click();

  const unlocked = await waitForRpc(
    popup,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'unlocked',
    'unlocked session',
    20_000,
  );
  state = unlocked.data.state;
  await popup.locator('vw-vault-view input[type="search"]').waitFor({ timeout: 10_000 });
  outcome = 'vault';

  await popup.locator('vw-tools-menu [data-trigger]').click();
  await popup.locator('vw-tools-menu').getByText('同步', { exact: true }).click();
  await popup.getByText(EXPECTED_ITEMS[0], { exact: true }).waitFor({ timeout: 20_000 });

  const deepText = await shadowText(popup);
  visibleItems = EXPECTED_ITEMS.filter((name) => deepText.includes(name));
  await popup.screenshot({ path: screenshotPath, fullPage: true });
} catch (error) {
  errors.push(`runner: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
  if (popup) await popup.screenshot({ path: screenshotPath, fullPage: true }).catch(() => undefined);
} finally {
  await context?.close().catch(() => undefined);
  rmSync(runRoot, { recursive: true, force: true });
}

console.log('\n=== E2E result ===');
console.log('login outcome:', outcome);
console.log('session state:', state);
console.log('seeded items visible:', `${visibleItems.length}/${EXPECTED_ITEMS.length}`);
console.log('items:', visibleItems.join(', ') || '(none visible)');
console.log('page/worker errors:', errors.length);
for (const error of errors.slice(0, 8)) console.log('  -', error);
console.log('relevant failed requests:', failedRequests.length);
for (const failure of failedRequests.slice(0, 8)) console.log('  -', failure);
console.log('screenshot:', screenshotPath);

if (
  outcome !== 'vault'
  || state !== 'unlocked'
  || visibleItems.length !== EXPECTED_ITEMS.length
  || errors.length > 0
  || failedRequests.length > 0
) {
  process.exitCode = 1;
}

function watchPage(page, label, target) {
  page.on('pageerror', (error) => target.push(`${label}: ${error}`));
  page.on('console', (message) => {
    if (message.type() === 'error') target.push(`${label} console: ${message.text()}`);
  });
}

async function waitForRpc(page, message, accept, label, timeoutMs = 10_000) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    try {
      last = await page.evaluate((request) => chrome.runtime.sendMessage(request), message);
      if (accept(last)) return last;
    } catch (error) {
      last = error;
    }
    await page.waitForTimeout(100);
  }
  throw new Error(`Timed out waiting for ${label}; last result: ${formatValue(last)}`);
}

async function shadowText(page) {
  return page.evaluate(() => {
    const output = [];
    const walk = (node) => {
      if (node.nodeType === Node.TEXT_NODE) output.push(node.textContent ?? '');
      if (node.shadowRoot) node.shadowRoot.childNodes.forEach(walk);
      node.childNodes?.forEach(walk);
    };
    walk(document.body);
    return output.join(' ');
  });
}

function sameServer(actual, expected) {
  if (typeof actual !== 'string') return false;
  try {
    const left = new URL(actual);
    const right = new URL(expected);
    return left.origin === right.origin
      && left.pathname.replace(/\/+$/, '') === right.pathname.replace(/\/+$/, '');
  } catch {
    return false;
  }
}

function formatValue(value) {
  if (value instanceof Error) return value.message;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
