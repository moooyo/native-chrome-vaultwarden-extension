// Production-like Type 5 gate against the authorized test-env tunnel. It builds the extension,
// loads a copied dist into a fresh branded-Chrome profile, exercises only visible UI, and always
// reconciles the unique disposable account before reporting success or failure.
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
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
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { chromium } from '@playwright/test';
import { build as esbuildBuild } from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const CHROME_EXECUTABLE = String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`;
const STANDARD_VIEWPORT = Object.freeze({ width: 372, height: 600 });
const NARROW_VIEWPORT = Object.freeze({ width: 320, height: 600 });
const OUTPUT_DIR = join(root, 'test-results', 'ssh-e2e');
const SERVER = new URL(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER).toString();

const issues = [];
const failedRequests = [];
const secrets = new Set();
let cleanupResult = 'not-needed';
let phase = 'startup';
let collectingDiagnostics = true;
let sshDiagnostic = 'not-captured';
let clipboardDiagnostic = 'not-captured';

async function main() {
  let context;
  let popup;
  let runRoot;
  let helper;
  let preparedAccount;
  let accountArmed = false;
  let accessToken;
  let privateKey;
  let stopIdlePulse;

  try {
    assert(SERVER === AUTHORIZED_SERVER, `SSH E2E is restricted to ${AUTHORIZED_SERVER}`);
    assert(existsSync(CHROME_EXECUTABLE), `Google Chrome was not found at ${CHROME_EXECUTABLE}`);

    phase = 'production-build';
    await runNode(join(root, 'build.mjs'), ['--prod']);
    await runNode(join(root, 'tools', 'assert-build.mjs'));

    phase = 'test-workspace';
    rmSync(OUTPUT_DIR, { recursive: true, force: true });
    mkdirSync(OUTPUT_DIR, { recursive: true });
    runRoot = mkdtempSync(join(tmpdir(), 'miyu-ssh-e2e-'));
    const extensionPath = join(runRoot, 'dist');
    cpSync(join(root, 'dist'), extensionPath, { recursive: true });
    grantCopiedExtensionServerAccess(extensionPath);
    helper = await loadAccountHelper(runRoot);

    phase = 'chrome-launch';
    context = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
      executablePath: CHROME_EXECUTABLE,
      headless: false,
      viewport: STANDARD_VIEWPORT,
      ignoreDefaultArgs: ['--disable-extensions'],
      args: ['--enable-unsafe-extension-debugging', '--no-first-run', '--no-default-browser-check'],
    });
    watchContext(context);
    const extensionId = await loadUnpackedExtension(context, extensionPath);

    phase = 'server-configuration';
    const options = await context.newPage();
    watchPage(options, 'options');
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
    await options.close();

    // Playwright input does not update Windows' system-idle clock. Keep it active exactly as a user
    // interacting with the popup would, without changing the extension's timeout or policy state.
    stopIdlePulse = await startWindowsIdlePulse();

    phase = 'account-registration';
    const identity = helper.createSshE2eIdentity();
    secrets.add(identity.password);
    preparedAccount = await helper.prepareSshE2eAccount(identity.email, identity.password, identity.name);
    secrets.add(preparedAccount.masterPasswordHash);
    accountArmed = true;
    const registered = await helper.registerSshE2eAccount(SERVER, preparedAccount);
    accessToken = registered.accessToken;
    secrets.add(accessToken);

    phase = 'ui-login';
    popup = await context.newPage();
    watchPage(popup, 'popup');
    await popup.goto(extensionUrl(extensionId, 'ui/popup/popup.html'), { waitUntil: 'load' });
    await popup.locator('vw-auth-views #email').fill(identity.email);
    await popup.locator('vw-auth-views #password').fill(identity.password);
    await popup.locator('vw-auth-views form').first().locator('button[type="submit"]').click();
    await waitForRpc(
      popup,
      { type: 'auth.getState' },
      (response) => response?.ok === true && response.data?.state === 'unlocked',
      'unlocked disposable account',
      30_000,
    );
    await popup.locator('vw-vault-view input[type="search"]').waitFor({ timeout: 15_000 });
    phase = 'ssh-create';
    const marker = randomUUID().slice(0, 8);
    const initialName = `Type5 E2E ${marker}`;
    const updatedName = `Type5 E2E ${marker} updated`;
    const initialNotes = 'Created through the visible Type 5 E2E flow.';
    const updatedNotes = 'Metadata updated through the visible Type 5 E2E flow.';
    await popup.locator('vw-sync-bar button.add').click();
    const picker = popup.locator('vw-type-picker');
    const sshType = picker.locator('[data-type="5"]');
    await sshType.waitFor({ state: 'visible', timeout: 20_000 });
    assert(await sshType.isEnabled(), 'SSH type is not available for the authorized server');
    await sshType.click();

    const createEditor = popup.locator('vw-ssh-key-editor');
    await createEditor.locator('[data-create-ssh]').waitFor({ state: 'visible' });
    await createEditor.locator('[data-name]').fill(initialName);
    await createEditor.locator('[data-notes]').fill(initialNotes);
    await createEditor.locator('[data-add-field]').click();
    const customField = createEditor.locator('[data-ssh-field]').last();
    await customField.locator('[data-field-name]').fill('Environment');
    await customField.locator('[data-field-value]').fill('test-env');
    await popup.setViewportSize(STANDARD_VIEWPORT);
    await popup.screenshot({ path: join(OUTPUT_DIR, 'ssh-create-372x600.png') });
    const preflight = await captureSshPreflight(popup);
    sshDiagnostic = preflight;
    assert(preflight.firstAuthState === 'unlocked', 'Vault locked before the SSH create preflight');
    assert(preflight.secondAuthState === 'unlocked', 'Vault locked during the SSH create preflight');
    assert(preflight.sshAvailable === true, 'SSH write capability became unavailable before create');
    await createEditor.locator('[data-create-ssh]').click();
    try {
      await waitForSshCreateCompletion(createEditor);
      sshDiagnostic = { ...preflight, createResult: 'success' };
    } catch (error) {
      sshDiagnostic = {
        ...preflight,
        createResult: 'error',
        committedAfterReconcile: await reconcileNamedSshCreate(popup, initialName),
      };
      throw error;
    }

    phase = 'ssh-round-trip';
    await reopenUnlockedPopup(popup);
    await syncThroughUi(popup);
    await openNamedVaultItem(popup, initialName);
    const detail = popup.locator('vw-item-detail');
    await detail.locator('[data-ssh-private]').waitFor({ state: 'visible', timeout: 20_000 });
    const publicDetails = await detail.evaluate((element) => element.sshKey);
    assertSshPublicDetails(publicDetails);
    await detail.getByText(publicDetails.publicKey, { exact: true }).waitFor();
    await detail.getByText(publicDetails.keyFingerprint, { exact: true }).waitFor();

    const reveal = detail.locator('[data-reveal-ssh-private]');
    await reveal.click();
    await waitForAttribute(reveal, 'aria-pressed', 'true');
    privateKey = await detail.locator('[data-ssh-private] pre').textContent();
    assert(typeof privateKey === 'string' && privateKey.includes('BEGIN OPENSSH PRIVATE KEY'), 'Generated private key is invalid');
    secrets.add(privateKey);
    await reveal.click();
    await waitForAttribute(reveal, 'aria-pressed', 'false');
    assert(!(await detail.locator('[data-ssh-private] pre').textContent())?.includes('BEGIN OPENSSH PRIVATE KEY'), 'Private key remained visible after masking');

    await detail.locator('[data-copy-ssh-private]').click();
    const clipboardResult = await clipboardEventuallyEquals(detail, privateKey);
    clipboardDiagnostic = clipboardResult.diagnostic;
    assert(clipboardResult.ok, 'Private key copy did not reach the clipboard');
    await clearWindowsClipboard();

    await popup.setViewportSize(STANDARD_VIEWPORT);
    await popup.screenshot({ path: join(OUTPUT_DIR, 'ssh-detail-372x600.png') });
    await popup.setViewportSize(NARROW_VIEWPORT);
    await popup.screenshot({ path: join(OUTPUT_DIR, 'ssh-detail-320x600.png') });
    assert(await hasNoDocumentOverflow(popup), 'SSH detail overflows the narrow viewport');

    phase = 'ssh-metadata-edit';
    await popup.setViewportSize(STANDARD_VIEWPORT);
    await detail.locator('[data-edit]').click();
    const editEditor = popup.locator('vw-ssh-key-editor');
    await editEditor.locator('[data-save-ssh-metadata]').waitFor({ state: 'visible', timeout: 20_000 });
    await editEditor.locator('[data-name]').fill(updatedName);
    await editEditor.locator('[data-notes]').fill(updatedNotes);
    await editEditor.locator('[data-save-ssh-metadata]').click();
    const updatedDetail = popup.locator('vw-item-detail');
    await updatedDetail.locator('h1').getByText(updatedName, { exact: true }).waitFor({ timeout: 20_000 });
    await updatedDetail.getByText(updatedNotes, { exact: true }).waitFor();
    const updatedPublicDetails = await updatedDetail.evaluate((element) => element.sshKey);
    assert(updatedPublicDetails?.publicKey === publicDetails.publicKey, 'Public key changed during metadata edit');
    assert(updatedPublicDetails?.keyFingerprint === publicDetails.keyFingerprint, 'Fingerprint changed during metadata edit');
    await syncThroughUi(popup);
    await updatedDetail.locator('[data-back]').click();
    await waitForNamedVaultRow(popup, updatedName);
    phase = 'complete';
  } catch (error) {
    recordIssue('runner', error);
    if (popup && await ensurePrivateKeyMasked(popup)) {
      await popup.screenshot({ path: join(OUTPUT_DIR, 'ssh-e2e-failure.png') }).catch(() => undefined);
    }
  } finally {
    stopIdlePulse?.();
    if (popup) await popup.evaluate(() => navigator.clipboard.writeText('')).catch(() => undefined);
    await clearWindowsClipboard().catch(() => undefined);
    collectingDiagnostics = false;
    await context?.close().catch((error) => recordIssue('chrome cleanup', error));
    if (accountArmed && helper && preparedAccount) {
      try {
        cleanupResult = await helper.cleanupSshE2eAccount(SERVER, preparedAccount, accessToken);
      } catch (error) {
        cleanupResult = 'failed';
        recordIssue('account cleanup', error);
      }
    }
    if (runRoot) {
      try {
        rmSync(runRoot, { recursive: true, force: true });
      } catch (error) {
        recordIssue('temporary workspace cleanup', error);
      }
    }
  }

  report();
  if (
    phase !== 'complete'
    || !['deleted', 'absent'].includes(cleanupResult)
    || issues.length > 0
    || failedRequests.length > 0
  ) {
    process.exitCode = 1;
  }
}

async function runNode(script, args = []) {
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: root,
      stdio: 'inherit',
      windowsHide: true,
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`Node subprocess failed (${signal ?? code ?? 'unknown'})`));
    });
  });
}

async function startWindowsIdlePulse() {
  let stopped = false;
  let running = false;
  await pulseWindowsUserActivity();
  const timer = setInterval(() => {
    if (stopped || running) return;
    running = true;
    void pulseWindowsUserActivity()
      .catch((error) => recordIssue('idle pulse', error))
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
    '$native = Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace MiYuE2E -PassThru',
    '$native::mouse_event(1, 1, 0, 0, [UIntPtr]::Zero)',
    '$native::mouse_event(1, -1, 0, 0, [UIntPtr]::Zero)',
  ].join('; ');
  await new Promise((resolve, reject) => {
    const child = spawn(
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', script],
      { stdio: 'ignore', windowsHide: true },
    );
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`Windows idle pulse failed (${signal ?? code ?? 'unknown'})`));
    });
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
  const outputPath = join(runRoot, 'ssh-e2e-account-helper.mjs');
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

const watchedPages = new WeakSet();
const watchedWorkers = new WeakSet();

function watchContext(context) {
  context.on('page', (page) => watchPage(page, 'page'));
  context.on('serviceworker', (worker) => watchWorker(worker));
  context.on('weberror', (error) => recordIssue('browser', error.error()));
  context.on('requestfailed', (request) => {
    if (!collectingDiagnostics) return;
    const url = safeUrl(request.url());
    if (!isRelevantUrl(url)) return;
    failedRequests.push(`${request.method()} ${safeDisplayUrl(url)}: ${request.failure()?.errorText ?? 'failed'}`);
  });
  for (const page of context.pages()) watchPage(page, 'page');
  for (const worker of context.serviceWorkers()) watchWorker(worker);
}

function watchPage(page, label) {
  if (watchedPages.has(page)) return;
  watchedPages.add(page);
  page.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'assert') {
      recordIssue(`${label} console`, message.text());
    }
  });
  page.on('crash', () => recordIssue(label, 'page crashed'));
}

function watchWorker(worker) {
  if (watchedWorkers.has(worker)) return;
  watchedWorkers.add(worker);
  worker.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'assert') {
      recordIssue('worker console', message.text());
    }
  });
}

async function syncThroughUi(page) {
  const before = await waitForRpc(
    page,
    { type: 'vault.getSyncStatus' },
    (response) => response?.ok === true && response.data?.syncing === false,
    'idle sync status',
    30_000,
  );
  const previous = Number(before.data?.lastSuccessfulSyncAt ?? 0);
  const tools = page.locator('vw-tools-menu');
  await tools.locator('[data-trigger]').click();
  const syncItem = tools.locator('vw-menu button[role="menuitem"]').last();
  await syncItem.waitFor({ state: 'visible' });
  await waitForEnabled(syncItem, 10_000);
  await syncItem.click();
  await waitForRpc(
    page,
    { type: 'vault.getSyncStatus' },
    (response) => response?.ok === true
      && response.data?.syncing === false
      && Number(response.data?.lastSuccessfulSyncAt ?? 0) > previous,
    'visible sync completion',
    30_000,
  );
}

async function reopenUnlockedPopup(page) {
  await page.reload({ waitUntil: 'load' });
  await waitForRpc(
    page,
    { type: 'auth.getState' },
    (response) => response?.ok === true && response.data?.state === 'unlocked',
    'reopened unlocked popup',
  );
  await page.locator('vw-vault-view input[type="search"]').waitFor({ state: 'visible', timeout: 15_000 });
}

async function waitForNamedVaultRow(page, name) {
  const search = page.locator('vw-vault-view input[type="search"]');
  await search.waitFor({ state: 'visible', timeout: 15_000 });
  await search.fill(name);
  const row = page.locator('vw-vault-view button.row-main').filter({ hasText: name });
  await row.first().waitFor({ state: 'visible', timeout: 20_000 });
  assert(await row.count() === 1, 'Disposable SSH key row is not unique');
  const title = await row.locator('.title').textContent();
  assert(title?.trim() === name, 'Disposable SSH key row title does not match');
  return row;
}

async function openNamedVaultItem(page, name) {
  const row = await waitForNamedVaultRow(page, name);
  await row.click();
  await page.locator('vw-item-detail').waitFor({ state: 'visible', timeout: 20_000 });
}

async function waitForSshCreateCompletion(editor, timeoutMs = 45_000) {
  const started = Date.now();
  let state;
  while (Date.now() - started < timeoutMs) {
    if (await editor.count() === 0) return;
    state = await editor.evaluate((element) => ({
      available: element.available,
      pending: element.pending,
      status: element.status,
    }));
    if (state.status?.tone === 'danger') {
      throw new Error(`SSH create failed: ${state.status.message}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`SSH create did not complete: ${JSON.stringify(state)}`);
}

function assertSshPublicDetails(value) {
  assert(value && typeof value === 'object', 'SSH public details are unavailable');
  assert(/^ssh-ed25519 [A-Za-z0-9+/]+=*(?: .*)?$/u.test(value.publicKey ?? ''), 'Generated SSH public key is invalid');
  assert(/^SHA256:[A-Za-z0-9+/]{43}$/u.test(value.keyFingerprint ?? ''), 'Generated SSH fingerprint is invalid');
  assert(value.hasPrivateKey === true, 'Generated SSH item does not report private key material');
}

async function waitForAttribute(locator, name, expected, timeoutMs = 10_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await locator.getAttribute(name) === expected) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${name}=${expected}`);
}

async function waitForEnabled(locator, timeoutMs = 10_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await locator.isEnabled()) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('Timed out waiting for an enabled UI control');
}

async function clipboardEventuallyEquals(detail, expected, timeoutMs = 5_000) {
  const started = Date.now();
  let actual = '';
  let status;
  while (Date.now() - started < timeoutMs) {
    try {
      actual = await readWindowsClipboard();
      status = await detail.evaluate((element) => element.status);
      if (normalizedClipboardText(actual) === normalizedClipboardText(expected)) {
        return {
          ok: true,
          diagnostic: {
            uiTone: status?.tone ?? 'none',
            normalizedMatch: true,
            windowsLineEndingsNormalized: actual !== expected,
          },
        };
      }
      if (status?.tone === 'danger') break;
    } catch {
      // The clipboard can be momentarily busy while Chrome commits the user-initiated write.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return {
    ok: false,
    diagnostic: {
      uiTone: status?.tone ?? 'none',
      actualLength: actual.length,
      expectedLength: expected.length,
      looksLikeOpenSsh: normalizedClipboardText(actual).includes('BEGIN OPENSSH PRIVATE KEY'),
    },
  };
}

async function readWindowsClipboard() {
  return runPowerShellWithOutput('$text = Get-Clipboard -Raw -ErrorAction Stop; [Console]::Out.Write($text)');
}

async function clearWindowsClipboard() {
  await runPowerShellWithOutput("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::Clear()");
}

function normalizedClipboardText(value) {
  return value.replace(/\r\n?/gu, '\n').trim();
}

async function runPowerShellWithOutput(script) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-STA', '-WindowStyle', 'Hidden', '-Command', script],
      { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true },
    );
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.length > 32_768) child.kill();
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0 && output.length <= 32_768) resolve(output);
      else reject(new Error(`Windows clipboard command failed (${signal ?? code ?? 'unknown'})`));
    });
  });
}

async function ensurePrivateKeyMasked(page) {
  try {
    const value = page.locator('vw-item-detail [data-ssh-private] pre');
    if (await value.count() === 0) return true;
    const reveal = page.locator('vw-item-detail [data-reveal-ssh-private]');
    if (await reveal.getAttribute('aria-pressed') === 'true') {
      await reveal.click();
      await waitForAttribute(reveal, 'aria-pressed', 'false', 2_000);
    }
    return !(await value.textContent())?.includes('BEGIN OPENSSH PRIVATE KEY');
  } catch {
    return false;
  }
}

async function hasNoDocumentOverflow(page) {
  return page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.document.documentElement.clientWidth + 1);
}

async function captureSshPreflight(page) {
  const firstAuth = await sendRpc(page, { type: 'auth.getState' });
  await new Promise((resolve) => setTimeout(resolve, 150));
  const secondAuth = await sendRpc(page, { type: 'auth.getState' });
  const availability = await sendRpc(page, { type: 'vault.getSshKeyWriteAvailability' });
  const sync = await sendRpc(page, { type: 'vault.getSyncStatus' });
  return {
    firstAuthState: firstAuth?.ok === true ? firstAuth.data?.state : 'error',
    secondAuthState: secondAuth?.ok === true ? secondAuth.data?.state : 'error',
    sshAvailable: availability?.ok === true && availability.data?.available === true,
    syncOk: sync?.ok === true,
    syncing: sync?.ok === true ? sync.data?.syncing : undefined,
    dirty: sync?.ok === true ? sync.data?.dirty : undefined,
  };
}

async function reconcileNamedSshCreate(page, name) {
  const response = await sendRpc(page, { type: 'vault.sync' }).catch(() => undefined);
  if (response?.ok !== true || !Array.isArray(response.data?.items)) return false;
  return response.data.items.some((item) => item?.type === 5 && item?.name === name);
}

async function sendRpc(page, message) {
  return page.evaluate((request) => chrome.runtime.sendMessage(request), message);
}

async function waitForRpc(page, message, accept, label, timeoutMs = 15_000) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    try {
      last = await page.evaluate((request) => chrome.runtime.sendMessage(request), message);
      if (accept(last)) return last;
    } catch (error) {
      last = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}; last result: ${redact(formatValue(last))}`);
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
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function isRelevantUrl(url) {
  return url?.protocol === 'chrome-extension:' || url?.origin === new URL(AUTHORIZED_SERVER).origin;
}

function safeDisplayUrl(url) {
  if (!url) return '(invalid URL)';
  return `${url.origin}${url.pathname}`;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function formatValue(value) {
  if (value instanceof Error) return value.stack ?? value.message;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function recordIssue(label, error) {
  if (!collectingDiagnostics && label !== 'chrome cleanup' && label !== 'account cleanup' && label !== 'temporary workspace cleanup') return;
  issues.push(`${label}: ${formatValue(error)}`);
}

function redact(value) {
  let output = String(value);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length > 0) output = output.replaceAll(secret, '[REDACTED]');
  }
  return output;
}

function report() {
  console.log('\n=== SSH Type 5 E2E ===');
  console.log('phase:', phase);
  console.log('account cleanup:', cleanupResult);
  console.log('SSH diagnostic:', typeof sshDiagnostic === 'string' ? sshDiagnostic : JSON.stringify(sshDiagnostic));
  console.log('clipboard diagnostic:', typeof clipboardDiagnostic === 'string' ? clipboardDiagnostic : JSON.stringify(clipboardDiagnostic));
  console.log('page/worker errors:', issues.length);
  for (const issue of issues.slice(0, 10)) console.log('  -', redact(issue));
  console.log('relevant failed requests:', failedRequests.length);
  for (const failure of failedRequests.slice(0, 10)) console.log('  -', redact(failure));
  console.log('artifacts:', OUTPUT_DIR);
}

await main();
