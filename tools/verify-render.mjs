// Render smoke-test: loads the built MiYu extension in a real Chromium, opens the popup, options,
// and receive pages, captures console/page errors, asserts the MiYu brand renders, and screenshots
// each to /tmp. Run under xvfb (headed Chromium is required to load an MV3 extension).
import { chromium } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ext = join(root, 'dist');
const browserExecutable = process.env.MIYU_BROWSER_EXECUTABLE;
const runRoot = mkdtempSync(join(tmpdir(), 'miyu-render-'));
let ctx;

try {
  ctx = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
    headless: false,
    ...(browserExecutable ? { executablePath: browserExecutable } : {}),
    ignoreDefaultArgs: ['--disable-extensions'],
    args: [
      '--enable-unsafe-extension-debugging',
      '--no-first-run',
      '--no-default-browser-check',
      ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
    ],
  });

  // Chrome 137+ ignores the old --load-extension flag. Load the unpacked build through CDP.
  const extId = await loadUnpackedExtension(ctx, ext);
  let sw = ctx.serviceWorkers().find((worker) => new URL(worker.url()).host === extId);
  if (!sw) {
    sw = await ctx.waitForEvent('serviceworker', {
      predicate: (worker) => new URL(worker.url()).host === extId,
      timeout: 15_000,
    });
  }
  console.log('extension id:', extId);
  const workerMessages = [];
  sw.on('console', (message) => {
    if (message.type() === 'warning' || message.type() === 'error') {
      workerMessages.push(`${message.type()}:${message.text()}`.slice(0, 512));
    }
  });

  const pages = [
    { name: 'popup', url: `chrome-extension://${extId}/ui/popup/popup.html`, expect: '密屿' },
    { name: 'workspace', url: `chrome-extension://${extId}/ui/popup/popup.html?workspace=1`, expect: '密屿' },
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
    const body = await waitForDeepText(page, p.expect, 10_000);
    const has = body.includes(p.expect);
    const screenshotPath = join(tmpdir(), `miyu-${p.name}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });
    const realErrors = errors.filter((e) => !/favicon|net::ERR|Failed to load resource/i.test(e));
    console.log(`\n[${p.name}] ${p.url}`);
    console.log(`  contains "${p.expect}": ${has ? 'YES' : 'NO'}`);
    console.log(`  console/page errors: ${realErrors.length}`);
    for (const e of realErrors.slice(0, 8)) console.log(`    - ${e}`);
    console.log(`  screenshot: ${screenshotPath}`);
    if (!has && p.name === 'popup') {
      const diagnostic = await popupStartupDiagnostic(page);
      diagnostic.workerHasMessageListener = await sw.evaluate(() => (
        chrome.runtime.onMessage.hasListeners()
      ));
      console.log(`  startup diagnostic: ${JSON.stringify(diagnostic)}`);
      console.log(`  final text: ${body.replace(/\s+/gu, ' ').trim().slice(0, 256)}`);
    }
    if (!has || realErrors.length > 0) failed = true;
    await page.close();
  }

  if (workerMessages.length > 0) {
    console.log('\nworker warnings/errors:');
    for (const message of workerMessages.slice(0, 8)) console.log(`  - ${message}`);
  }
  console.log(`\n=== ${failed ? 'FAIL' : 'PASS'} ===`);
  process.exitCode = failed ? 1 : 0;
} finally {
  await ctx?.close().catch(() => undefined);
  removeTemporaryWorkspace(runRoot);
}

async function loadUnpackedExtension(browserContext, extensionPath) {
  const browser = browserContext.browser();
  if (!browser) throw new Error('Persistent Chrome did not expose its browser CDP connection');
  const session = await browser.newBrowserCDPSession();
  try {
    const loaded = await session.send('Extensions.loadUnpacked', {
      path: extensionPath,
      enableInIncognito: false,
    });
    if (typeof loaded?.id !== 'string' || loaded.id.length === 0) {
      throw new Error('Chrome did not return an extension id');
    }
    return loaded.id;
  } finally {
    await session.detach().catch(() => undefined);
  }
}

function removeTemporaryWorkspace(path) {
  const resolvedPath = resolve(path);
  const temporaryRoot = `${resolve(tmpdir())}${sep}`;
  if (!resolvedPath.startsWith(temporaryRoot) || !resolvedPath.includes('miyu-render-')) {
    throw new Error(`Refusing to remove unexpected render workspace: ${resolvedPath}`);
  }
  rmSync(resolvedPath, { recursive: true, force: true });
}

async function waitForDeepText(page, expected, timeoutMs) {
  const started = Date.now();
  let text = '';
  while (Date.now() - started < timeoutMs) {
    // Deep text extraction pierces open shadow roots, where the whole extension UI lives.
    text = await page.evaluate(() => {
      const out = [];
      const walk = (node) => {
        if (node.nodeType === Node.TEXT_NODE) { out.push(node.textContent); return; }
        if (node.shadowRoot) node.shadowRoot.childNodes.forEach(walk);
        node.childNodes && node.childNodes.forEach(walk);
      };
      walk(document.body);
      return out.join(' ');
    });
    if (text.includes(expected)) return text;
    await page.waitForTimeout(100);
  }
  return text;
}

async function popupStartupDiagnostic(page) {
  return page.evaluate(async () => {
    const bounded = async (operation) => {
      let timer;
      try {
        await Promise.race([
          operation,
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('timeout')), 2_000);
          }),
        ]);
        return 'ok';
      } catch (error) {
        return error instanceof Error ? error.message.slice(0, 128) : 'failed';
      } finally {
        clearTimeout(timer);
      }
    };
    return {
      localRead: await bounded(chrome.storage.local.get('__miyu_render_probe__')),
      sessionRead: await bounded(chrome.storage.session.get('__miyu_render_probe__')),
      localAccess: typeof chrome.storage.local.setAccessLevel === 'function'
        ? await bounded(chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }))
        : 'unavailable',
      sessionAccess: typeof chrome.storage.session.setAccessLevel === 'function'
        ? await bounded(chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }))
        : 'unavailable',
      authState: await bounded(chrome.runtime.sendMessage({ type: 'auth.getState' })),
      authStateCallback: await bounded(new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'auth.getState' }, (response) => {
          resolve(chrome.runtime.lastError ? `lastError:${chrome.runtime.lastError.message}` : response);
        });
      })),
    };
  });
}
