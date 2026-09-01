// Production-like account-passkey browser verification against the authorized test-env tunnel.
// It attaches an empty virtual authenticator from the page event without pausing navigation, so
// the production worker can first bind the connector's browser-owned documentId.
import { spawn } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from '@playwright/test';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const SERVER = new URL(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER).toString();
const CONNECTOR_URL = new URL('webauthn-fallback-connector.html', SERVER).toString();
const OPTIONS_URL = new URL('/identity/accounts/webauthn/assertion-options', SERVER).toString();
const CHROME_EXECUTABLE = process.env.MIYU_BROWSER_EXECUTABLE
  ?? (process.platform === 'win32'
    ? String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`
    : chromium.executablePath());

let phase = 'startup';
let context;
let connectorSession;
let control;
let popup;
let extensionId;
let runRoot;
const diagnostics = {
  connectorFrameKeys: [],
  connectorFrameType: undefined,
  connectorOrigin: undefined,
  rpId: undefined,
  allowCredentials: undefined,
  outcome: undefined,
  finalState: undefined,
  optionGets: 0,
  tokenPosts: 0,
  storageCleared: false,
  hostPermission: undefined,
  directOptions: undefined,
  lastStatus: undefined,
  attemptStatus: undefined,
  popupText: undefined,
  workerWarnings: [],
  errors: [],
};

async function main() {
  try {
    assert(SERVER === AUTHORIZED_SERVER, `Account passkey E2E is restricted to ${AUTHORIZED_SERVER}`);
    assert(existsSync(CHROME_EXECUTABLE), `Google Chrome was not found at ${CHROME_EXECUTABLE}`);

    phase = 'production-build';
    await runNode(join(root, 'build.mjs'), ['--prod']);
    await runNode(join(root, 'tools', 'assert-build.mjs'));

    phase = 'test-workspace';
    runRoot = mkdtempSync(join(tmpdir(), 'miyu-account-passkey-e2e-'));
    const extensionPath = join(runRoot, 'dist');
    cpSync(join(root, 'dist'), extensionPath, { recursive: true });
    grantCopiedExtensionServerAccess(extensionPath);

    phase = 'chrome-launch';
    context = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
      executablePath: CHROME_EXECUTABLE,
      headless: false,
      viewport: { width: 900, height: 700 },
      ignoreDefaultArgs: ['--disable-extensions'],
      args: [
        '--enable-unsafe-extension-debugging',
        '--no-first-run',
        '--no-default-browser-check',
        ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
      ],
    });
    context.setDefaultTimeout(15_000);
    watchContext(context);
    extensionId = await loadUnpackedExtension(context, extensionPath);

    phase = 'server-configuration';
    control = await context.newPage();
    await control.goto(extensionUrl(extensionId, 'ui/options/options.html'), { waitUntil: 'load' });
    await waitForRpc(control, { type: 'auth.getState' }, (value) => value?.ok === true, 'background');
    const saved = await sendRpc(control, { type: 'settings.save', serverUrl: SERVER });
    assert(saved?.ok === true, 'Server transition did not settle successfully');

    phase = 'connector-launch';
    popup = await context.newPage();
    await popup.goto(extensionUrl(extensionId, 'ui/popup/popup.html'), { waitUntil: 'load' });
    const start = popup.locator('vw-auth-views [data-account-passkey]');
    await start.waitFor({ state: 'visible' });

    const connectorReady = deferred();
    let acceptingConnector = true;
    const onPage = (page) => {
      if (!acceptingConnector) return;
      acceptingConnector = false;
      void attachEmptyAuthenticator(context, page).then(connectorReady.resolve, connectorReady.reject);
    };
    context.on('page', onPage);
    const frameReady = waitForConnectorFrame(popup, 15_000);
    await start.click();
    const connector = await withTimeout(connectorReady.promise, 15_000, 'connector target');
    context.off('page', onPage);
    connectorSession = connector.session;

    phase = 'connector-binding';
    const frame = await frameReady;
    diagnostics.connectorFrameKeys = Object.keys(frame).sort();
    diagnostics.connectorFrameType = frame.frameType;
    diagnostics.connectorOrigin = new URL(frame.url).origin;
    assert(frame.url === CONNECTOR_URL, 'Connector frame URL changed');
    assert(frame.frameType === 'outermost_frame', 'Connector is not the outermost frame');
    assert(typeof frame.documentId === 'string' && frame.documentId.length > 0, 'Connector documentId is missing');
    assert(diagnostics.connectorOrigin === new URL(SERVER).origin, 'Connector origin changed');

    phase = 'empty-authenticator';
    const statusResponse = await withTimeout(
      sendRpc(popup, { type: 'auth.accountPasskey.status' }),
      2_000,
      'initial account passkey status',
    );
    assert(statusResponse?.ok === true, 'Account passkey status could not be read');
    diagnostics.attemptStatus = statusResponse.data?.status;
    if (statusResponse.data?.status === 'waiting') {
      await connector.session.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: connector.authenticatorId,
        enabled: true,
      });
    } else {
      assert(statusResponse.data?.status === 'none', 'Account passkey attempt entered an unexpected state');
    }
    const outcomePage = await waitForOutcomePage(context, extensionId, 30_000);
    diagnostics.outcome = new URL(outcomePage.url()).searchParams.get('accountPasskey');
    diagnostics.finalState = (await sendRpc(outcomePage, { type: 'auth.getState' }))?.data?.state;
    diagnostics.storageCleared = await outcomePage.evaluate(async () => {
      const stored = await chrome.storage.session.get('accountPasskeyAttempt');
      return stored.accountPasskeyAttempt === undefined;
    });

    assert(
      diagnostics.outcome === 'cancelled' || diagnostics.outcome === 'failed',
      'Empty authenticator did not produce a safe terminal outcome',
    );
    assert(diagnostics.rpId === '127.0.0.1', 'Server returned an unexpected account-passkey RP ID');
    assert(diagnostics.allowCredentials === 0, 'Test endpoint unexpectedly returned a credential');
    assert(diagnostics.tokenPosts === 0, 'A token grant was sent without an assertion');
    assert(diagnostics.finalState === 'loggedOut', 'Empty authenticator changed the auth state');
    assert(diagnostics.storageCleared, 'Cancelled account-passkey state was not erased');
    phase = 'complete';
  } catch (error) {
    diagnostics.errors.push(sanitizeError(error));
    await collectFailureDiagnostics();
  } finally {
    await connectorSession?.detach().catch(() => undefined);
    await context?.close().catch((error) => diagnostics.errors.push(sanitizeError(error)));
    if (runRoot) removeTemporaryWorkspace(runRoot);
  }

  report();
  if (phase !== 'complete' || diagnostics.errors.length > 0) process.exitCode = 1;
}

async function collectFailureDiagnostics() {
  if (!control || !popup) return;
  try {
    diagnostics.hostPermission = await control.evaluate(async (origin) => (
      chrome.permissions.contains({ origins: [`${origin}/*`] })
    ), new URL(SERVER).origin);
  } catch (error) {
    diagnostics.errors.push(`permission-diagnostic:${sanitizeError(error)}`);
  }
  try {
    diagnostics.directOptions = await control.evaluate(async (url) => {
      try {
        const response = await fetch(url, {
          cache: 'no-store',
          credentials: 'omit',
          signal: AbortSignal.timeout(2_000),
        });
        const body = await response.json();
        return {
          status: response.status,
          hasOptions: typeof body?.options === 'object' && body.options !== null,
          hasToken: typeof body?.token === 'string' && body.token.length > 0,
        };
      } catch (error) {
        return { error: error instanceof Error ? error.message.slice(0, 128) : 'failed' };
      }
    }, OPTIONS_URL);
  } catch (error) {
    diagnostics.errors.push(`options-diagnostic:${sanitizeError(error)}`);
  }
  try {
    diagnostics.lastStatus = await withTimeout(
      sendRpc(popup, { type: 'auth.accountPasskey.status' }),
      2_000,
      'status diagnostic',
    );
    diagnostics.attemptStatus = await popup.evaluate(async () => {
      const stored = await chrome.storage.session.get('accountPasskeyAttempt');
      return typeof stored.accountPasskeyAttempt?.status === 'string'
        ? stored.accountPasskeyAttempt.status
        : 'none';
    });
    diagnostics.popupText = await popup.evaluate(() => globalThis.document.body.innerText.slice(0, 256));
  } catch (error) {
    diagnostics.errors.push(`status-diagnostic:${sanitizeError(error)}`);
  }
}

function grantCopiedExtensionServerAccess(extensionPath) {
  const manifestPath = join(extensionPath, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.host_permissions = [...new Set([
    ...(manifest.host_permissions ?? []),
    `${new URL(SERVER).origin}/*`,
  ])];
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function loadUnpackedExtension(browserContext, extensionPath) {
  const browser = browserContext.browser();
  assert(browser, 'Persistent Chrome did not expose its browser CDP connection');
  const session = await browser.newBrowserCDPSession();
  try {
    const loaded = await session.send('Extensions.loadUnpacked', {
      path: extensionPath,
      enableInIncognito: false,
    });
    assert(typeof loaded?.id === 'string' && loaded.id.length > 0, 'Chrome did not return an extension id');
    return loaded.id;
  } finally {
    await session.detach().catch(() => undefined);
  }
}

async function attachEmptyAuthenticator(browserContext, page) {
  const session = await browserContext.newCDPSession(page);
  try {
    await session.send('WebAuthn.enable');
    const added = await session.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: false,
      },
    });
    assert(typeof added?.authenticatorId === 'string', 'Chrome did not create a virtual authenticator');
    return { page, session, authenticatorId: added.authenticatorId };
  } catch (error) {
    await session.detach().catch(() => undefined);
    throw error;
  }
}

async function readConnectorFrame(page) {
  return page.evaluate(async (url) => {
    const tabs = await chrome.tabs.query({ url });
    if (tabs.length !== 1 || typeof tabs[0]?.id !== 'number') return undefined;
    return chrome.webNavigation.getFrame({ tabId: tabs[0].id, frameId: 0 });
  }, CONNECTOR_URL);
}

async function waitForConnectorFrame(page, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const frame = await readConnectorFrame(page).catch(() => undefined);
    if (frame) return frame;
    await delay(20);
  }
  throw new Error('Timed out waiting for the browser-owned connector frame');
}

async function waitForOutcomePage(browserContext, extensionId, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    for (const page of browserContext.pages()) {
      const url = safeUrl(page.url());
      if (
        url?.protocol === 'chrome-extension:'
        && url.host === extensionId
        && url.pathname === '/ui/popup/popup.html'
        && url.searchParams.has('accountPasskey')
      ) return page;
    }
    await delay(100);
  }
  throw new Error('Timed out waiting for the account-passkey outcome popup');
}

function watchContext(browserContext) {
  browserContext.on('weberror', (event) => {
    diagnostics.errors.push(`browser:${sanitizeError(event.error())}`);
  });
  browserContext.on('request', (request) => {
    if (request.method() === 'GET' && request.url() === OPTIONS_URL) diagnostics.optionGets += 1;
    if (request.method() === 'POST' && request.url().endsWith('/identity/connect/token')) {
      diagnostics.tokenPosts += 1;
    }
  });
  browserContext.on('response', (response) => {
    if (response.url() !== OPTIONS_URL || response.status() !== 200) return;
    void response.json().then((body) => {
      if (diagnostics.rpId === undefined) diagnostics.rpId = body?.options?.rpId;
      if (diagnostics.allowCredentials === undefined) {
        diagnostics.allowCredentials = Array.isArray(body?.options?.allowCredentials)
          ? body.options.allowCredentials.length
          : undefined;
      }
    }).catch(() => {
      diagnostics.errors.push('options-response:invalid-json');
    });
  });
  browserContext.on('serviceworker', watchWorker);
  for (const worker of browserContext.serviceWorkers()) watchWorker(worker);
}

const watchedWorkers = new WeakSet();
function watchWorker(worker) {
  if (watchedWorkers.has(worker)) return;
  watchedWorkers.add(worker);
  worker.on('console', (message) => {
    if (message.type() !== 'warning' && message.type() !== 'error') return;
    const text = message.text().slice(0, 256);
    if (text.includes('account_passkey_')) diagnostics.workerWarnings.push(text);
    if (message.type() === 'error') diagnostics.errors.push(`worker:${text}`);
  });
}

async function sendRpc(page, message) {
  return page.evaluate((request) => chrome.runtime.sendMessage(request), message);
}

async function waitForRpc(page, message, accept, label, timeoutMs = 15_000) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    try {
      last = await withTimeout(sendRpc(page, message), 2_000, `${label} RPC`);
      if (accept(last)) return last;
    } catch (error) {
      last = error;
    }
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${label}: ${sanitizeError(last)}`);
}

function runNode(script, args = []) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: root,
      stdio: 'inherit',
      windowsHide: true,
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`Node subprocess failed (${signal ?? code ?? 'unknown'})`));
    });
  });
}

function removeTemporaryWorkspace(workspace) {
  const expectedParent = `${resolve(tmpdir())}${sep}`;
  const target = resolve(workspace);
  assert(target.startsWith(expectedParent), 'Account passkey workspace escaped the temporary directory');
  assert(target.includes('miyu-account-passkey-e2e-'), 'Account passkey workspace has an unexpected name');
  rmSync(target, { recursive: true, force: true });
  assert(!existsSync(target), 'Account passkey workspace remains after cleanup');
}

function deferred() {
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolveDeferred, rejectDeferred) => {
    resolvePromise = resolveDeferred;
    rejectPromise = rejectDeferred;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

async function withTimeout(operation, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      operation,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function extensionUrl(extensionId, pagePath) {
  return `chrome-extension://${extensionId}/${pagePath}`;
}

function safeUrl(value) {
  try { return new URL(value); } catch { return undefined; }
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function sanitizeError(error) {
  if (error instanceof Error) return `${error.name}:${error.message}`.slice(0, 512);
  return String(error ?? 'unknown').slice(0, 512);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function report() {
  console.log('\n=== Account Passkey Chrome E2E ===');
  console.log('phase:', phase);
  console.log('connector frame keys:', diagnostics.connectorFrameKeys.join(','));
  console.log('connector frame type:', diagnostics.connectorFrameType ?? 'not-observed');
  console.log('connector origin:', diagnostics.connectorOrigin ?? 'not-observed');
  console.log('rp id:', diagnostics.rpId ?? 'not-observed');
  console.log('allow credentials:', diagnostics.allowCredentials ?? 'not-observed');
  console.log('outcome:', diagnostics.outcome ?? 'not-observed');
  console.log('final state:', diagnostics.finalState ?? 'not-observed');
  console.log('options GETs:', diagnostics.optionGets);
  console.log('token POSTs:', diagnostics.tokenPosts);
  console.log('storage cleared:', diagnostics.storageCleared);
  console.log('host permission:', diagnostics.hostPermission ?? 'not-observed');
  console.log('direct options:', diagnostics.directOptions ? JSON.stringify(diagnostics.directOptions) : 'not-observed');
  console.log('last status:', diagnostics.lastStatus ? JSON.stringify(diagnostics.lastStatus) : 'not-observed');
  console.log('attempt status:', diagnostics.attemptStatus ?? 'not-observed');
  console.log('popup text:', diagnostics.popupText ?? 'not-observed');
  console.log('worker warnings:', diagnostics.workerWarnings.join(',') || 'none');
  console.log('errors:', diagnostics.errors.length);
  for (const error of diagnostics.errors) console.log('  -', error);
}

await main();
