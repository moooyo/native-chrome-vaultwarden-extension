// Browser-level autofill hardening gate with no backend or account dependency. It loads a copied
// production build into a fresh Chrome profile, exercises a loopback test origin, and
// verifies runtime activation, bounded form detection, screen-reader labels, late closed roots,
// trusted closed-root context fills, and BFCache incarnation fencing.
import { chromium } from '@playwright/test';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sourceExtensionPath = join(root, 'dist');
const browserExecutable = process.env.MIYU_BROWSER_EXECUTABLE;

const pageA = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>MiYu local browser smoke</title>
  <style>
    body { font: 16px sans-serif; margin: 24px; }
    form, section { display: block; margin: 18px 0; padding: 12px; border: 1px solid #ccc; }
    input, button { display: block; width: 280px; min-height: 32px; margin: 8px 0; }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
      overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
  </style>
</head>
<body>
  <form id="accessible-login">
    <label class="sr-only" for="accessible-user">Email address</label>
    <input id="accessible-user" type="text">
    <label class="sr-only" for="accessible-pass">Current password</label>
    <input id="accessible-pass" type="password">
    <button type="submit">Sign in</button>
  </form>
  <form id="totp-step">
    <input name="verification-code" autocomplete="one-time-code" inputmode="numeric"
      maxlength="6" pattern="[0-9]*">
    <button type="submit">Verify</button>
  </form>
  <form id="registration">
    <input name="new-password" type="password" autocomplete="new-password">
    <input name="confirm-password" type="password" autocomplete="new-password">
  </form>
  <form id="card">
    <input name="cardnumber" autocomplete="cc-number">
    <input name="cvc" autocomplete="cc-csc">
  </form>
  <form id="identity">
    <input name="first" autocomplete="given-name">
    <input name="last" autocomplete="family-name">
  </form>
  <section><div id="late-closed-host"></div></section>
  <script>
    window.__pageShowPersisted = false;
    addEventListener('pageshow', (event) => { window.__pageShowPersisted = event.persisted; });
    window.__attachLateClosedCard = () => {
      const host = document.getElementById('late-closed-host');
      if (window.__closedCardInput) return false;
      const shadow = host.attachShadow({ mode: 'closed' });
      shadow.innerHTML = '<style>input{display:block;width:280px;height:36px;margin:8px}</style>'
        + '<input autocomplete="cc-number" aria-label="Closed card number">';
      window.__closedCardInput = shadow.querySelector('input');
      window.__closedContextSeen = false;
      window.__closedCardInput.addEventListener('contextmenu', () => {
        window.__closedContextSeen = true;
      });
      return true;
    };
  </script>
</body>
</html>`;

const pageB = '<!doctype html><html><body><h1>BFCache destination</h1></body></html>';
const server = createServer((request, response) => {
  const body = request.url?.startsWith('/b') ? pageB : pageA;
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end(body);
});
await new Promise((resolvePromise, rejectPromise) => {
  server.once('error', rejectPromise);
  server.listen(0, '127.0.0.1', resolvePromise);
});
const address = server.address();
if (!address || typeof address === 'string') throw new Error('Could not bind local test server');
const pageUrl = `http://127.0.0.1:${address.port}/a`;
const destinationUrl = `http://127.0.0.1:${address.port}/b`;
const screenshotPath = join(tmpdir(), 'miyu-autofill-browser.png');

const runRoot = mkdtempSync(join(tmpdir(), 'miyu-local-browser-smoke-'));
const extensionPath = join(runRoot, 'dist');
cpSync(sourceExtensionPath, extensionPath, { recursive: true });
const manifestPath = join(extensionPath, 'manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.host_permissions = ['http://127.0.0.1/*'];
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
let context;
const errors = [];

try {
  context = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
    ...(browserExecutable ? { executablePath: browserExecutable } : {}),
    headless: false,
    viewport: { width: 1100, height: 850 },
    ignoreDefaultArgs: ['--disable-extensions', '--disable-back-forward-cache'],
    args: [
      '--enable-unsafe-extension-debugging',
      '--no-first-run',
      '--no-default-browser-check',
      ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
    ],
  });
  context.on('weberror', (error) => errors.push(`browser:${error.error()}`));
  const extensionId = await loadUnpackedExtension(context, extensionPath);
  console.log('browser:', context.browser()?.version() ?? 'unknown');
  let worker = context.serviceWorkers().find((candidate) => new URL(candidate.url()).host === extensionId);
  if (!worker) {
    worker = await context.waitForEvent('serviceworker', {
      predicate: (candidate) => new URL(candidate.url()).host === extensionId,
      timeout: 15_000,
    });
  }
  worker.on('console', (message) => {
    if (message.type() === 'error') errors.push(`worker:${message.text()}`);
  });

  const page = await context.newPage();
  page.on('pageerror', (error) => errors.push(`page:${error}`));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(`page-console:${message.text()}`);
  });
  await page.goto(pageUrl, { waitUntil: 'load' });
  const initial = await waitForInspection(worker, page, (inspection) => (
    inspection.forms.some((form) => form.kind === 'login')
      && inspection.forms.some((form) => form.kind === 'card')
      && inspection.forms.some((form) => form.kind === 'identity')
  ));
  assert(initial.forms.some((form) => form.kind === 'login'), 'Login form was not detected');
  assert(initial.forms.some((form) => form.kind === 'card' && form.roles.includes('number')),
    'Card form was not detected');
  assert(initial.forms.some((form) => form.kind === 'identity'
    && form.roles.includes('firstName') && form.roles.includes('lastName')),
  'Identity form was not detected');

  await page.locator('#accessible-user').click();
  const focused = await waitForInspection(worker, page, (inspection) => (
    inspection.forms.some((form) => form.kind === 'login' && Number.isFinite(form.focusedAt))
  ));
  const focusedLogin = focused.forms.find((form) => (
    form.kind === 'login' && Number.isFinite(form.focusedAt)
  ));
  assert(focusedLogin?.kind === 'login', 'Accessible login target was not focused');
  const customPlanDigest = createHash('sha256')
    .update(JSON.stringify(focusedLogin.customPlan))
    .digest('hex');
  const fillOutcome = await sendContentMessage(worker, page, {
    type: 'autofill.commitLoginFill',
    formId: focusedLogin.formId,
    expectedFrameUrl: focused.frameUrl,
    expectedRuntimeIncarnation: focused.runtimeIncarnation,
    expectedGeneration: focused.generation,
    login: { username: 'screen-reader-user', password: 'screen-reader-password' },
    customPlan: focusedLogin.customPlan,
    customPlanDigest,
    customAssignments: [],
  });
  assert(fillOutcome?.status === 'filled', 'Accessible login fill was rejected');
  const accessibleValues = await page.evaluate(() => ({
    username: globalThis.document.querySelector('#accessible-user').value,
    password: globalThis.document.querySelector('#accessible-pass').value,
  }));
  assert(accessibleValues.username === 'screen-reader-user', 'Screen-reader username label was not filled');
  assert(accessibleValues.password === 'screen-reader-password', 'Password field was not filled');
  await page.evaluate(() => {
    globalThis.document.querySelector('#accessible-user').value = '';
    globalThis.document.querySelector('#accessible-pass').value = '';
  });

  const cardCountBefore = initial.forms.filter((form) => form.kind === 'card').length;
  assert(await page.evaluate(() => globalThis.__attachLateClosedCard()) === true,
    'Late closed root was not attached');
  const withClosedRoot = await waitForInspection(worker, page, (inspection) => (
    inspection.forms.filter((form) => form.kind === 'card').length > cardCountBefore
  ), 12_000);
  assert(withClosedRoot.forms.filter((form) => form.kind === 'card').length > cardCountBefore,
    'Late closed shadow card was not discovered');

  const closedRect = await page.evaluate(() => {
    const rect = globalThis.__closedCardInput.getBoundingClientRect();
    return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
  });
  await page.mouse.click(
    closedRect.x + (closedRect.width / 2),
    closedRect.y + (closedRect.height / 2),
    { button: 'right' },
  );
  await page.keyboard.press('Escape').catch(() => undefined);
  const reservationId = crypto.randomUUID();
  const reservation = await sendContentMessage(worker, page, {
    type: 'autofill.reserveFillTarget',
    reservationId,
    scope: 'field',
    kind: 'card',
    expectedFrameUrl: page.url(),
    contextMenuClickTime: Date.now() + 1,
  });
  const pageSawClosedContext = await page.evaluate(() => globalThis.__closedContextSeen);
  assert(reservation?.status === 'reserved' && reservation.roles.length === 1
    && reservation.roles[0] === 'number',
  `Closed-shadow context target was not reserved exactly once: ${JSON.stringify({
    reservation,
    pageSawClosedContext,
  })}`);
  const duplicateReservation = await sendContentMessage(worker, page, {
    type: 'autofill.reserveFillTarget',
    reservationId: crypto.randomUUID(),
    scope: 'field',
    kind: 'card',
    expectedFrameUrl: page.url(),
    contextMenuClickTime: Date.now() + 1,
  });
  assert(duplicateReservation?.status === 'no_target', 'Closed-shadow event was queued more than once');
  const closedFill = await sendContentMessage(worker, page, {
    type: 'autofill.fill',
    reservationId,
    scope: 'field',
    kind: 'card',
    roles: reservation.roles,
    expectedFrameUrl: page.url(),
    expectedRuntimeIncarnation: reservation.runtimeIncarnation,
    data: { number: '4111111111111111' },
  });
  assert(closedFill?.status === 'filled', 'Closed-shadow card fill failed');
  assert(await page.evaluate(() => globalThis.__closedCardInput.value) === '4111111111111111',
    'Closed-shadow card value was not written');

  const beforeRestore = await waitForInspection(worker, page, () => true);
  const beforeDocument = await frameInfo(worker, page);
  const oldLogin = beforeRestore.forms.find((form) => form.kind === 'login');
  assert(oldLogin?.kind === 'login', 'BFCache source login form was unavailable');
  await page.goto(destinationUrl, { waitUntil: 'load' });
  await page.goBack({ waitUntil: 'commit' });
  await page.waitForURL(pageUrl, { waitUntil: 'commit' });
  assert(await page.evaluate(() => globalThis.__pageShowPersisted) === true,
    'Chrome did not restore the source page from BFCache');
  const afterRestore = await waitForInspection(worker, page, (inspection) => (
    inspection.runtimeIncarnation !== beforeRestore.runtimeIncarnation
  ));
  const afterDocument = await frameInfo(worker, page);
  assert(afterRestore.runtimeIncarnation !== beforeRestore.runtimeIncarnation,
    'BFCache restore reused the old content runtime incarnation');
  assert(beforeDocument.documentId === afterDocument.documentId,
    'BFCache restore did not preserve the browser document id in this run');
  const staleCommit = await sendContentMessage(worker, page, {
    type: 'autofill.commitLoginFill',
    formId: oldLogin.formId,
    expectedFrameUrl: beforeRestore.frameUrl,
    expectedRuntimeIncarnation: beforeRestore.runtimeIncarnation,
    expectedGeneration: beforeRestore.generation,
    login: { username: 'must-not-fill', password: 'must-not-fill' },
    customPlan: oldLogin.customPlan,
    customPlanDigest: createHash('sha256').update(JSON.stringify(oldLogin.customPlan)).digest('hex'),
    customAssignments: [],
  });
  assert(staleCommit?.status === 'target_changed', 'Pre-BFCache commit was not rejected');
  const staleValues = await page.evaluate(() => ({
    username: globalThis.document.querySelector('#accessible-user').value,
    password: globalThis.document.querySelector('#accessible-pass').value,
  }));
  assert(staleValues.username === '' && staleValues.password === '',
    'A stale BFCache commit wrote credentials');

  await page.screenshot({ path: screenshotPath, fullPage: true });
  assert(errors.length === 0, `Browser errors: ${errors.join(' | ')}`);
  console.log('initial forms:', initial.forms.map((form) => form.kind).join(', '));
  console.log('accessible login fill: PASS');
  console.log('late closed-root discovery: PASS');
  console.log('closed-root context reservation/fill: PASS');
  console.log('BFCache runtime/document fencing: PASS');
  console.log('screenshot:', screenshotPath);
  console.log('RESULT: PASS');
} finally {
  await context?.close().catch(() => undefined);
  await new Promise((resolvePromise) => server.close(resolvePromise));
  removeTemporaryWorkspace(runRoot);
}

async function loadUnpackedExtension(browserContext, path) {
  const browser = browserContext.browser();
  if (!browser) throw new Error('Persistent Chrome did not expose a browser CDP connection');
  const session = await browser.newBrowserCDPSession();
  try {
    const loaded = await session.send('Extensions.loadUnpacked', {
      path,
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

async function waitForInspection(worker, page, accept, timeoutMs = 10_000) {
  const started = Date.now();
  let lastError;
  let lastInspection;
  while (Date.now() - started < timeoutMs) {
    try {
      const inspection = await sendContentMessage(worker, page, { type: 'autofill.inspectFrame' });
      lastInspection = inspection;
      if (inspection?.forms && accept(inspection)) return inspection;
    } catch (error) {
      lastError = error;
    }
    await page.waitForTimeout(100);
  }
  throw new Error(`Timed out waiting for frame inspection: ${lastError ?? JSON.stringify(lastInspection)}`);
}

async function sendContentMessage(worker, page, message) {
  await page.bringToFront();
  return worker.evaluate(async (request) => {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (typeof tab?.id !== 'number') throw new Error('Could not find the active test tab');
    return chrome.tabs.sendMessage(tab.id, request, { frameId: 0 });
  }, message);
}

async function frameInfo(worker, page) {
  await page.bringToFront();
  return worker.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (typeof tab?.id !== 'number') throw new Error('Could not find the active test tab');
    const frame = await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 });
    if (!frame?.documentId) throw new Error('Browser frame document id is unavailable');
    return { documentId: frame.documentId, url: frame.url };
  });
}

function removeTemporaryWorkspace(path) {
  const resolvedPath = resolve(path);
  const temporaryRoot = `${resolve(tmpdir())}${sep}`;
  if (!resolvedPath.startsWith(temporaryRoot) || !resolvedPath.includes('miyu-local-browser-smoke-')) {
    throw new Error(`Refusing to remove unexpected browser workspace: ${resolvedPath}`);
  }
  rmSync(resolvedPath, { recursive: true, force: true });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
