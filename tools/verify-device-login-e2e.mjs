// Production-like dual-Chrome Login with device gate against the authorized test-env tunnel.
// It drives only visible extension UI, observes sanitized wire semantics, and always removes the
// disposable account and both persistent Chrome profiles.
import { spawn } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { chromium } from '@playwright/test';
import { build as esbuildBuild } from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const CHROME_EXECUTABLE = String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`;
const STANDARD_VIEWPORT = Object.freeze({ width: 372, height: 600 });
const NARROW_VIEWPORT = Object.freeze({ width: 320, height: 600 });
const OUTPUT_DIR = join(root, 'test-results', 'device-login-e2e');
const SERVER = new URL(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER).toString();

const issues = [];
const failedRequests = [];
const secrets = new Set();
const wire = createWireObservations();
let collectingDiagnostics = true;
let cleanupResult = 'not-needed';
let phase = 'startup';
let serviceWorkerDiagnostic = 'not-attempted';
let requesterDiagnostic = 'not-captured';
let denialDiagnostic = 'not-captured';

async function main() {
  let requesterContext;
  let approverContext;
  let requesterPopup;
  let approverPopup;
  let runRoot;
  let helper;
  let preparedAccount;
  let accountArmed = false;
  let cleanupToken;
  let stopIdlePulse;

  try {
    assert(SERVER === AUTHORIZED_SERVER, `Device login E2E is restricted to ${AUTHORIZED_SERVER}`);
    assert(existsSync(CHROME_EXECUTABLE), `Google Chrome was not found at ${CHROME_EXECUTABLE}`);

    phase = 'production-build';
    await runNode(join(root, 'build.mjs'), ['--prod']);
    await runNode(join(root, 'tools', 'assert-build.mjs'));

    phase = 'test-workspace';
    resetOutputDirectory();
    runRoot = mkdtempSync(join(tmpdir(), 'miyu-device-login-e2e-'));
    const requesterExtensionPath = join(runRoot, 'requester-dist');
    const approverExtensionPath = join(runRoot, 'approver-dist');
    cpSync(join(root, 'dist'), requesterExtensionPath, { recursive: true });
    cpSync(join(root, 'dist'), approverExtensionPath, { recursive: true });
    grantCopiedExtensionServerAccess(requesterExtensionPath);
    grantCopiedExtensionServerAccess(approverExtensionPath);
    helper = await loadAccountHelper(runRoot);

    phase = 'chrome-launch';
    requesterContext = await launchChrome(join(runRoot, 'requester-profile'));
    approverContext = await launchChrome(join(runRoot, 'approver-profile'));
    watchContext(requesterContext, 'requester');
    watchContext(approverContext, 'approver');
    const requesterExtensionId = await loadUnpackedExtension(
      requesterContext,
      requesterExtensionPath,
    );
    const approverExtensionId = await loadUnpackedExtension(
      approverContext,
      approverExtensionPath,
    );
    assert(requesterExtensionId === approverExtensionId, 'Copied extensions have different ids');

    phase = 'server-configuration';
    await configureServerThroughUi(requesterContext, requesterExtensionId, 'requester');
    await configureServerThroughUi(approverContext, approverExtensionId, 'approver');
    stopIdlePulse = await startWindowsIdlePulse();

    phase = 'account-registration';
    const identity = helper.createSshE2eIdentity();
    secrets.add(identity.email);
    secrets.add(identity.password);
    preparedAccount = await helper.prepareSshE2eAccount(
      identity.email,
      identity.password,
      'MiYu Device Login E2E',
    );
    secrets.add(preparedAccount.masterPasswordHash);
    accountArmed = true;
    const registered = await helper.registerSshE2eAccount(SERVER, preparedAccount);
    cleanupToken = registered.accessToken;
    secrets.add(cleanupToken);

    phase = 'visible-known-device-logins';
    requesterPopup = await loginThroughVisiblePopup(
      requesterContext,
      requesterExtensionId,
      identity,
      'requester popup',
      'requester',
    );
    approverPopup = await loginThroughVisiblePopup(
      approverContext,
      approverExtensionId,
      identity,
      'approver popup',
      'approver',
    );

    phase = 'requester-first-request';
    await logoutThroughVisibleUi(requesterPopup);
    await startDeviceLoginThroughVisibleUi(requesterPopup, identity.email);
    const requesterView = requesterPopup.locator('vw-device-login-view .requester');
    const requesterFingerprint = await readFingerprint(requesterView);
    await assertCountdownAdvances(requesterPopup);
    await assertRequesterDomHasNoRequestSecrets(requesterPopup);
    await requesterPopup.setViewportSize(STANDARD_VIEWPORT);
    assert(await hasNoDeviceLoginOverflow(requesterPopup), 'Requester waiting view overflows at 372px');
    await captureRedactedScreenshot(requesterPopup, 'requester-waiting-372x600.png');
    await requesterPopup.setViewportSize(NARROW_VIEWPORT);
    assert(await hasNoDeviceLoginOverflow(requesterPopup), 'Requester waiting view overflows at 320px');
    await captureRedactedScreenshot(requesterPopup, 'requester-waiting-320x600.png');
    await requesterPopup.setViewportSize(STANDARD_VIEWPORT);

    phase = 'requester-worker-recovery';
    serviceWorkerDiagnostic = await stopServiceWorkerAndWaitForRecovery(
      requesterContext,
      requesterExtensionId,
      requesterPopup,
    );
    const recoveredFingerprint = await readFingerprint(requesterView);
    assert(
      JSON.stringify(recoveredFingerprint) === JSON.stringify(requesterFingerprint),
      'Requester fingerprint changed after service-worker recovery',
    );
    await assertRequesterDomHasNoRequestSecrets(requesterPopup);

    phase = 'approver-first-decision';
    await reopenUnlockedPopup(approverPopup);
    const approvalDetail = await openDeviceLoginApprovals(approverPopup);
    const approverFingerprint = await readFingerprint(approvalDetail);
    assert(
      JSON.stringify(approverFingerprint) === JSON.stringify(requesterFingerprint),
      'Requester and approver fingerprints differ',
    );
    await approverPopup.setViewportSize(STANDARD_VIEWPORT);
    assert(await hasNoDeviceLoginOverflow(approverPopup), 'Approver review overflows at 372px');
    await captureRedactedScreenshot(approverPopup, 'approver-review-372x600.png');
    await approvalDetail.locator('[data-action="approve"]').click();

    phase = 'requester-automatic-activation';
    await waitForAutomaticRequesterUnlock(requesterPopup);
    requesterDiagnostic = {
      fingerprintMatched: true,
      sensitiveDomValues: false,
      automaticUnlock: true,
      workerRecovery: serviceWorkerDiagnostic,
    };

    phase = 'requester-second-request';
    await logoutThroughVisibleUi(requesterPopup);
    await startDeviceLoginThroughVisibleUi(requesterPopup, identity.email);
    const deniedRequesterView = requesterPopup.locator('vw-device-login-view .requester');
    const deniedRequesterFingerprint = await readFingerprint(deniedRequesterView);
    await assertRequesterDomHasNoRequestSecrets(requesterPopup);
    const deviceGrantsBeforeDenial = wire.requester.deviceTokenGrants;

    phase = 'approver-second-decision';
    await reopenUnlockedPopup(approverPopup);
    const denialDetail = await openDeviceLoginApprovals(approverPopup);
    const deniedApproverFingerprint = await readFingerprint(denialDetail);
    assert(
      JSON.stringify(deniedApproverFingerprint) === JSON.stringify(deniedRequesterFingerprint),
      'Denial fingerprints differ between requester and approver',
    );
    await approverPopup.setViewportSize(STANDARD_VIEWPORT);
    assert(await hasNoDeviceLoginOverflow(approverPopup), 'Denial review overflows at 372px');
    await captureRedactedScreenshot(approverPopup, 'approver-denial-372x600.png');
    await denialDetail.locator('[data-action="deny"]').click();

    phase = 'requester-automatic-denial';
    await waitForAutomaticRequesterDenial(requesterPopup);
    assert(
      wire.requester.deviceTokenGrants === deviceGrantsBeforeDenial,
      'Denied request triggered a device token grant',
    );
    await requesterPopup.setViewportSize(NARROW_VIEWPORT);
    assert(await hasNoDeviceLoginOverflow(requesterPopup), 'Requester denied view overflows at 320px');
    await captureRedactedScreenshot(requesterPopup, 'requester-denied-320x600.png');
    denialDiagnostic = {
      fingerprintMatched: true,
      automaticDenial: true,
      remainedLoggedOut: true,
      addedDeviceTokenGrants: 0,
    };

    phase = 'wire-assertions';
    assertWireSemantics();
    phase = 'complete';
  } catch (error) {
    recordIssue('runner', error);
  } finally {
    stopIdlePulse?.();
    collectingDiagnostics = false;
    if (accountArmed && helper && preparedAccount) {
      try {
        cleanupResult = await withTimeout(
          helper.cleanupSshE2eAccount(SERVER, preparedAccount, cleanupToken),
          20_000,
          'account cleanup',
        );
      } catch {
        cleanupResult = 'failed';
        recordIssue('account cleanup');
      }
    }
    await closeChromeContext(requesterContext, 'requester Chrome cleanup');
    await closeChromeContext(approverContext, 'approver Chrome cleanup');
    if (runRoot) {
      try {
        removeTemporaryWorkspace(runRoot);
      } catch {
        recordIssue('temporary workspace cleanup');
      }
    }
  }

  report();
  if (
    phase !== 'complete'
    || !['deleted', 'absent'].includes(cleanupResult)
    || issues.length > 0
    || failedRequests.length > 0
  ) process.exitCode = 1;
}

function resetOutputDirectory() {
  const expectedParent = `${resolve(root, 'test-results')}${sep}`;
  const output = resolve(OUTPUT_DIR);
  assert(output.startsWith(expectedParent), 'Device login output path escaped test-results');
  rmSync(output, { recursive: true, force: true });
  mkdirSync(output, { recursive: true });
}

function removeTemporaryWorkspace(runRoot) {
  const expectedParent = `${resolve(tmpdir())}${sep}`;
  const workspace = resolve(runRoot);
  assert(workspace.startsWith(expectedParent), 'Device login temp path escaped the OS temp directory');
  assert(workspace.includes('miyu-device-login-e2e-'), 'Device login temp path is unexpected');
  rmSync(workspace, { recursive: true, force: true });
  assert(!existsSync(workspace), 'Device login temporary workspace remains after cleanup');
}

async function runNode(script, args = []) {
  await new Promise((resolvePromise, reject) => {
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

async function launchChrome(profilePath) {
  return chromium.launchPersistentContext(profilePath, {
    executablePath: CHROME_EXECUTABLE,
    headless: false,
    viewport: STANDARD_VIEWPORT,
    ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--enable-unsafe-extension-debugging', '--no-first-run', '--no-default-browser-check'],
  });
}

function grantCopiedExtensionServerAccess(extensionPath) {
  const manifestPath = join(extensionPath, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const originPattern = `${new URL(SERVER).origin}/*`;
  manifest.host_permissions = [...new Set([...(manifest.host_permissions ?? []), originPattern])];
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function loadAccountHelper(runRoot) {
  const outputPath = join(runRoot, 'device-login-e2e-account-helper.mjs');
  await esbuildBuild({
    entryPoints: [join(root, 'test', 'support', 'ssh-e2e-account.ts')],
    outfile: outputPath,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    sourcemap: false,
    logLevel: 'silent',
  });
  return import(`${pathToFileURL(outputPath).href}?run=${Date.now()}`);
}

async function loadUnpackedExtension(context, extensionPath) {
  const browser = context.browser();
  assert(browser, 'Persistent Chrome did not expose its browser CDP connection');
  const session = await browser.newBrowserCDPSession();
  try {
    const result = await session.send('Extensions.loadUnpacked', {
      path: extensionPath,
      enableInIncognito: false,
    });
    assert(typeof result?.id === 'string' && result.id.length > 0, 'Chrome did not return an extension id');
    const installed = await session.send('Extensions.getExtensions');
    const loaded = installed.extensions.find((extension) => extension.id === result.id);
    assert(loaded?.enabled === true, 'Chrome loaded the unpacked extension in a disabled state');
    return result.id;
  } finally {
    await session.detach().catch(() => undefined);
  }
}

async function configureServerThroughUi(context, extensionId, actor) {
  const options = await context.newPage();
  watchPage(options, `${actor} options`, actor);
  try {
    await options.goto(extensionUrl(extensionId, 'ui/options/options.html'), { waitUntil: 'load' });
    await waitForRpc(options, { type: 'auth.getState' }, (response) => response?.ok === true, 'background RPC');
    await options.locator('vw-connection-section [data-server-url]').fill(SERVER);
    await options.locator('vw-connection-section [data-save]').click();
    await waitForRpc(
      options,
      { type: 'settings.get' },
      (response) => response?.ok === true && sameServer(response.data?.serverUrl, SERVER),
      'server configuration',
    );
  } finally {
    await options.close();
  }
}

async function loginThroughVisiblePopup(context, extensionId, identity, label, actor) {
  const popup = await context.newPage();
  watchPage(popup, label, actor);
  await popup.goto(extensionUrl(extensionId, 'ui/popup/popup.html'), { waitUntil: 'load' });
  await popup.locator('vw-auth-views #email').fill(identity.email);
  await popup.locator('vw-auth-views #password').fill(identity.password);
  await popup.locator('vw-auth-views form').first().locator('button[type="submit"]').click();
  await waitForRpc(
    popup,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'unlocked',
    `${label} unlocked state`,
    30_000,
  );
  await popup.locator('vw-vault-view input[type="search"]').waitFor({ timeout: 20_000 });
  return popup;
}

function createWireObservations() {
  const actor = () => ({
    knownDeviceGets: 0,
    authRequestCreates: 0,
    responseGets: 0,
    pendingGets: 0,
    detailGets: 0,
    approvalPuts: 0,
    denialPuts: 0,
    ordinaryTokenGrants: 0,
    deviceTokenGrants: 0,
    exactDeviceTokenCasing: true,
    exactApprovalShape: true,
    exactDenialShape: true,
    anonymousHubConnections: 0,
    exactAnonymousTokenCasing: null,
  });
  return { requester: actor(), approver: actor() };
}

const watchedPages = new WeakSet();
const watchedWorkers = new WeakSet();

function watchContext(context, actor) {
  context.on('page', (page) => watchPage(page, `${actor} page`, actor));
  context.on('serviceworker', (worker) => watchWorker(worker, actor));
  context.on('weberror', () => recordIssue(`${actor} browser error`));
  context.on('request', (request) => observeWireRequest(actor, request));
  context.on('requestfailed', (request) => {
    if (!collectingDiagnostics) return;
    const url = safeUrl(request.url());
    if (!isRelevantUrl(url)) return;
    failedRequests.push(`${actor}:${request.method()}:${sanitizeRelevantPath(url?.pathname)}`);
  });
  for (const page of context.pages()) watchPage(page, `${actor} page`, actor);
  for (const worker of context.serviceWorkers()) watchWorker(worker, actor);
}

function watchPage(page, label, actor) {
  if (watchedPages.has(page)) return;
  watchedPages.add(page);
  page.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'assert') {
      recordIssue(`${label} console`);
    }
  });
  page.on('crash', () => recordIssue(`${label} crash`));
  page.on('websocket', (socket) => observeAnonymousHub(actor, socket.url()));
}

function watchWorker(worker, actor) {
  if (watchedWorkers.has(worker)) return;
  watchedWorkers.add(worker);
  worker.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'assert') {
      recordIssue(`${actor} worker console`);
    }
  });
}

function observeWireRequest(actor, request) {
  const url = safeUrl(request.url());
  if (url?.origin !== new URL(AUTHORIZED_SERVER).origin) return;
  const observation = wire[actor];
  const method = request.method();
  const path = url.pathname;
  if (method === 'GET' && path.endsWith('/api/devices/knowndevice')) {
    observation.knownDeviceGets += 1;
  } else if (method === 'POST' && /\/api\/auth-requests\/$/u.test(path)) {
    observation.authRequestCreates += 1;
  } else if (method === 'GET' && /\/api\/auth-requests\/[0-9a-f-]{36}\/response$/u.test(path)) {
    observation.responseGets += 1;
  } else if (method === 'GET' && path.endsWith('/api/auth-requests/pending')) {
    observation.pendingGets += 1;
  } else if (method === 'GET' && /\/api\/auth-requests\/[0-9a-f-]{36}$/u.test(path)) {
    observation.detailGets += 1;
  } else if (method === 'PUT' && /\/api\/auth-requests\/[0-9a-f-]{36}$/u.test(path)) {
    observeDecisionBody(observation, request.postData());
  } else if (method === 'POST' && path.endsWith('/identity/connect/token')) {
    observeTokenForm(observation, request.postData());
  }
  if (path.endsWith('/notifications/anonymous-hub')) observeAnonymousHub(actor, request.url());
}

function observeDecisionBody(observation, body) {
  const parsed = parseJsonRecord(body);
  if (!parsed) {
    observation.exactApprovalShape = false;
    observation.exactDenialShape = false;
    return;
  }
  const keys = Object.keys(parsed).sort().join(',');
  if (parsed.requestApproved === true) {
    observation.approvalPuts += 1;
    observation.exactApprovalShape &&= keys === 'deviceIdentifier,key,requestApproved'
      && typeof parsed.key === 'string'
      && parsed.key.startsWith('4.');
  } else if (parsed.requestApproved === false) {
    observation.denialPuts += 1;
    observation.exactDenialShape &&= keys === 'deviceIdentifier,key,requestApproved'
      && parsed.key === '';
  }
}

function observeTokenForm(observation, body) {
  if (typeof body !== 'string') return;
  const form = new URLSearchParams(body);
  if (!form.has('AuthRequest')) {
    if (form.get('grant_type') === 'password') observation.ordinaryTokenGrants += 1;
    return;
  }
  observation.deviceTokenGrants += 1;
  observation.exactDeviceTokenCasing &&= form.has('AuthRequest')
    && !form.has('authRequest')
    && !form.has('auth_request')
    && form.has('deviceType')
    && form.has('deviceIdentifier')
    && form.has('deviceName');
}

function observeAnonymousHub(actor, rawUrl) {
  const url = safeUrl(rawUrl);
  const server = new URL(AUTHORIZED_SERVER);
  if (!url
    || !['http:', 'ws:'].includes(url.protocol)
    || url.host !== server.host
    || !url.pathname.endsWith('/notifications/anonymous-hub')) return;
  const observation = wire[actor];
  observation.anonymousHubConnections += 1;
  const canonicalCasing = url.searchParams.has('Token')
    && !url.searchParams.has('token');
  observation.exactAnonymousTokenCasing = observation.exactAnonymousTokenCasing !== false
    && canonicalCasing;
}

function assertWireSemantics() {
  const requester = wire.requester;
  const approver = wire.approver;

  assert(requester.knownDeviceGets >= 2, 'Requester did not perform both known-device checks');
  assert(requester.authRequestCreates === 2, 'Requester did not create exactly two auth requests');
  assert(requester.responseGets >= 2, 'Requester did not poll both authoritative responses');
  assert(requester.deviceTokenGrants === 1, 'Requester device-token grant count was not exactly one');
  assert(requester.exactDeviceTokenCasing, 'Requester device-token wire casing was not canonical');

  assert(approver.pendingGets >= 2, 'Approver did not fetch both pending request lists');
  assert(approver.detailGets >= 2, 'Approver did not fetch both authoritative request details');
  assert(approver.approvalPuts === 1, 'Approver did not send exactly one approval');
  assert(approver.denialPuts === 1, 'Approver did not send exactly one denial');
  assert(approver.exactApprovalShape, 'Approval wire shape was not canonical');
  assert(approver.exactDenialShape, 'Denial wire shape was not canonical');
  assert(approver.deviceTokenGrants === 0, 'Approver unexpectedly sent a device-token grant');

  assert(requester.ordinaryTokenGrants >= 1, 'Requester visible password login was not observed');
  assert(approver.ordinaryTokenGrants >= 1, 'Approver visible password login was not observed');
  assert(requester.exactAnonymousTokenCasing !== false, 'Requester anonymous-hub token casing was not canonical');
  assert(approver.exactAnonymousTokenCasing !== false, 'Approver anonymous-hub token casing was not canonical');
}

function parseJsonRecord(value) {
  if (typeof value !== 'string') return undefined;
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? parsed
      : undefined;
  } catch {
    return undefined;
  }
}

async function logoutThroughVisibleUi(popup) {
  const menu = popup.locator('vw-account-menu');
  await menu.locator('[data-trigger]').click();
  const logout = menu.locator('vw-menu button[role="menuitem"]')
    .filter({ hasText: /Log out|退出登录/u });
  await logout.waitFor({ state: 'visible', timeout: 10_000 });
  await logout.click();
  await waitForRpc(
    popup,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'loggedOut',
    'visible logout',
    20_000,
  );
  await popup.locator('vw-auth-views [data-device-login]').waitFor({ state: 'visible' });
}

async function startDeviceLoginThroughVisibleUi(popup, email) {
  await popup.locator('vw-auth-views #email').fill(email);
  await popup.locator('vw-auth-views [data-device-login]').click();
  const requester = popup.locator('vw-device-login-view .requester');
  await requester.waitFor({ state: 'visible', timeout: 30_000 });
  await popup.locator('vw-device-login-view .fingerprint-word').first()
    .waitFor({ state: 'visible', timeout: 20_000 });
  return requester;
}

async function readFingerprint(page) {
  const words = await page.locator('.fingerprint-word .word-value')
    .allTextContents();
  assert(words.length === 5, `Expected five fingerprint words, found ${words.length}`);
  assert(words.every((word) => word.trim().length > 0), 'Fingerprint contains an empty word');
  return words.map((word) => word.trim());
}

async function assertCountdownAdvances(page) {
  const timer = page.locator('vw-device-login-view [role="timer"]');
  const first = parseCountdown(await timer.innerText());
  await delay(1_100);
  const second = parseCountdown(await timer.innerText());
  assert(second < first && second > 0, 'Device login countdown did not advance');
}

function parseCountdown(value) {
  const match = /^(\d+):(\d{2})$/u.exec(value.trim());
  assert(match, 'Device login countdown has an invalid format');
  return Number(match[1]) * 60 + Number(match[2]);
}

async function assertRequesterDomHasNoRequestSecrets(page) {
  const result = await page.evaluate(async () => {
    const stored = await chrome.storage.session.get('deviceLoginState');
    const envelope = stored.deviceLoginState;
    const state = envelope && typeof envelope === 'object' ? envelope.state : undefined;
    const values = state && typeof state === 'object'
      ? [state.requestId, state.publicKey, state.privateKeyPkcs8, state.accessCode]
          .filter((value) => typeof value === 'string' && value.length > 0)
      : [];
    const parts = [];
    const visit = (root) => {
      for (const node of root.childNodes) {
        if (node.nodeType === globalThis.Node.TEXT_NODE) parts.push(node.textContent ?? '');
        if (!(node instanceof globalThis.Element)) continue;
        parts.push(node.tagName);
        for (const attribute of node.attributes) parts.push(attribute.name, attribute.value);
        if (node instanceof globalThis.HTMLInputElement
          || node instanceof globalThis.HTMLTextAreaElement
          || node instanceof globalThis.HTMLSelectElement) parts.push(node.value);
        if (node.shadowRoot) visit(node.shadowRoot);
        visit(node);
      }
    };
    visit(globalThis.document);
    const rendered = parts.join('\n');
    return {
      activeStatePresent: values.length === 4,
      leakedValue: values.some((value) => rendered.includes(value)),
    };
  });
  assert(result.activeStatePresent === true, 'Requester state was unavailable for the DOM audit');
  assert(result.leakedValue === false, 'Requester DOM exposed request cryptographic material');
}

async function hasNoDeviceLoginOverflow(page) {
  return page.evaluate(() => {
    const document = globalThis.document;
    const within = (element) => !element || element.scrollWidth <= element.clientWidth + 1;
    const app = document.querySelector('vw-popup-app');
    const view = app?.shadowRoot?.querySelector('vw-device-login-view');
    const surface = view?.shadowRoot?.querySelector('.surface');
    return Boolean(app && view && surface)
      && document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1
      && within(document.body)
      && within(document.querySelector('#app'))
      && within(app)
      && within(view)
      && within(surface);
  });
}

async function openDeviceLoginApprovals(popup) {
  const menu = popup.locator('vw-account-menu');
  await menu.locator('[data-trigger]').click();
  const approvals = menu.locator('vw-menu button[role="menuitem"]')
    .filter({ hasText: /Device login requests|设备登录请求/u });
  await approvals.waitFor({ state: 'visible', timeout: 10_000 });
  await approvals.click();
  const list = popup.locator('vw-device-login-view .approver-list');
  await list.waitFor({ state: 'visible', timeout: 20_000 });
  const row = popup.locator('vw-device-login-view [data-action="select"]');
  await row.first().waitFor({ state: 'visible', timeout: 20_000 });
  assert(await row.count() === 1, 'Approver did not show exactly one pending request');
  await row.first().click();
  const detail = popup.locator('vw-device-login-view .approver-detail');
  await detail.waitFor({ state: 'visible', timeout: 20_000 });
  return detail;
}

async function reopenUnlockedPopup(popup) {
  await popup.reload({ waitUntil: 'load' });
  await waitForRpc(
    popup,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'unlocked',
    'reopened approver state',
  );
  await popup.locator('vw-vault-view input[type="search"]').waitFor({ timeout: 20_000 });
}

async function waitForAutomaticRequesterUnlock(popup) {
  await popup.locator('vw-vault-view input[type="search"]')
    .waitFor({ state: 'visible', timeout: 35_000 });
  await waitForRpc(
    popup,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'unlocked',
    'automatic requester unlock',
    15_000,
  );
}

async function waitForAutomaticRequesterDenial(popup) {
  const denied = popup.locator('vw-device-login-view .requester .state-line.expired');
  await denied.waitFor({ state: 'visible', timeout: 35_000 });
  const text = (await denied.innerText()).replaceAll(/\s+/gu, ' ').trim();
  assert(/Request denied|请求已被拒绝/u.test(text), 'Requester did not display the denied state');
  await waitForRpc(
    popup,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'loggedOut',
    'requester remains logged out after denial',
  );
}

async function stopServiceWorkerAndWaitForRecovery(context, extensionId, requesterPopup) {
  const browser = context.browser();
  if (!browser) return 'unsupported:no-browser';
  const session = await browser.newBrowserCDPSession();
  try {
    let targets;
    try {
      targets = await session.send('Target.getTargets');
    } catch {
      return 'unsupported:target-list';
    }
    const worker = targets.targetInfos.find((target) => (
      target.type === 'service_worker' && isExtensionUrl(target.url, extensionId)
    ));
    if (!worker) return 'unsupported:no-worker-target';

    let closed;
    try {
      closed = await session.send('Target.closeTarget', { targetId: worker.targetId });
    } catch {
      return 'unsupported:close-target';
    }
    if (closed?.success !== true) return 'unsupported:close-rejected';

    const disappearanceDeadline = Date.now() + 3_000;
    let closureObserved = false;
    while (Date.now() < disappearanceDeadline) {
      const current = await session.send('Target.getTargets');
      if (!current.targetInfos.some((target) => target.targetId === worker.targetId)) {
        closureObserved = true;
        break;
      }
      await delay(50);
    }
    if (!closureObserved) return 'unsupported:close-not-observable';

    const responseGetsBeforeRecovery = wire.requester.responseGets;
    const started = Date.now();
    while (Date.now() - started < 15_000) {
      const current = await session.send('Target.getTargets');
      const replacement = current.targetInfos.find((target) => (
        target.type === 'service_worker'
        && isExtensionUrl(target.url, extensionId)
      ));
      if (replacement && wire.requester.responseGets > responseGetsBeforeRecovery) {
        await waitForRpc(
          requesterPopup,
          { type: 'auth.deviceLogin.status' },
          (response) => response?.ok === true,
          'requester status after automatic worker recovery',
          5_000,
        );
        return 'restarted-after-cdp-stop-and-status-poll';
      }
      await delay(100);
    }
    throw new Error('Requester service worker did not recover after CDP stop');
  } finally {
    await session.detach().catch(() => undefined);
  }
}

function isExtensionUrl(value, extensionId) {
  const url = safeUrl(value);
  return url?.protocol === 'chrome-extension:' && url.host === extensionId;
}

async function startWindowsIdlePulse() {
  let stopped = false;
  let running = false;
  await pulseWindowsUserActivity();
  const timer = setInterval(() => {
    if (stopped || running) return;
    running = true;
    void pulseWindowsUserActivity()
      .catch(() => recordIssue('idle pulse'))
      .finally(() => { running = false; });
  }, 5_000);
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

async function pulseWindowsUserActivity() {
  const script = [
    "$signature = '[DllImport(\"user32.dll\")] public static extern void mouse_event(uint flags, int dx, int dy, uint data, UIntPtr extraInfo);'",
    '$native = Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace MiYuDeviceLoginE2E -PassThru',
    '$native::mouse_event(1, 1, 0, 0, [UIntPtr]::Zero)',
    '$native::mouse_event(1, -1, 0, 0, [UIntPtr]::Zero)',
  ].join('; ');
  await new Promise((resolvePromise, reject) => {
    const child = spawn(
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', script],
      { stdio: 'ignore', windowsHide: true },
    );
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`Windows idle pulse failed (${signal ?? code ?? 'unknown'})`));
    });
  });
}

async function sendRpc(page, message) {
  return page.evaluate((request) => chrome.runtime.sendMessage(request), message);
}

async function waitForRpc(page, message, accept, label, timeoutMs = 15_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await sendRpc(page, message);
      if (accept(response)) return response;
    } catch {
      // A service-worker restart can transiently make the runtime endpoint unavailable.
    }
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function captureRedactedScreenshot(page, fileName) {
  const masks = [page.locator('input, textarea')];
  for (const secret of secrets) masks.push(page.getByText(secret, { exact: true }));
  await page.screenshot({
    path: join(OUTPUT_DIR, fileName),
    mask: masks,
    maskColor: '#d1d5db',
  });
}

async function closeChromeContext(context, label) {
  if (!context) return;
  try {
    await withTimeout(context.close(), 10_000, label);
  } catch {
    recordIssue(label);
  }
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

function extensionUrl(extensionId, path) {
  return `chrome-extension://${extensionId}/${path}`;
}

function sameServer(actual, expected) {
  if (typeof actual !== 'string') return false;
  try {
    const left = new URL(actual);
    const right = new URL(expected);
    return left.origin === right.origin
      && left.pathname.replace(/\/+$/u, '') === right.pathname.replace(/\/+$/u, '');
  } catch {
    return false;
  }
}

function safeUrl(value) {
  try { return new URL(value); } catch { return undefined; }
}

function sanitizeRelevantPath(pathname) {
  if (typeof pathname !== 'string') return 'invalid';
  return pathname.replace(
    /\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?=\/|$)/giu,
    '/:requestId',
  );
}

function isRelevantUrl(url) {
  return url?.protocol === 'chrome-extension:'
    || url?.origin === new URL(AUTHORIZED_SERVER).origin;
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function recordIssue(label, _error) {
  if (!collectingDiagnostics
    && label !== 'requester Chrome cleanup'
    && label !== 'approver Chrome cleanup'
    && label !== 'account cleanup'
    && label !== 'temporary workspace cleanup') return;
  issues.push(`${phase}:${label}`);
}

function report() {
  console.log('\n=== Login with device dual-Chrome E2E ===');
  console.log('phase:', phase);
  console.log('account cleanup:', cleanupResult);
  console.log('service-worker recovery:', serviceWorkerDiagnostic);
  console.log('requester:', typeof requesterDiagnostic === 'string'
    ? requesterDiagnostic
    : JSON.stringify(requesterDiagnostic));
  console.log('denial:', typeof denialDiagnostic === 'string'
    ? denialDiagnostic
    : JSON.stringify(denialDiagnostic));
  console.log('wire:', JSON.stringify(wire));
  console.log('page/worker errors:', issues.length);
  for (const issue of issues.slice(0, 10)) console.log('  -', issue);
  console.log('relevant failed requests:', failedRequests.length);
  for (const request of failedRequests.slice(0, 10)) console.log('  -', request);
  console.log('artifacts:', OUTPUT_DIR);
}

await main();
