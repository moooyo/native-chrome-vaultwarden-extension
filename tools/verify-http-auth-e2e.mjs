// Production-like HTTP Basic authentication verification against a disposable account on test-env.
// The Basic endpoint also runs on test-env and is exposed only through a temporary loopback tunnel.
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
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { chromium } from '@playwright/test';
import { build as esbuildBuild } from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const VAULT_SERVER = 'http://127.0.0.1:18082/';
const BASIC_ORIGIN = 'http://127.0.0.1:18083';
const BASIC_URL = `${BASIC_ORIGIN}/protected`;
const RUNNING_ON_TEST_ENV = process.env.MIYU_E2E_ON_TEST_ENV === '1';
const CHROME_EXECUTABLE = process.env.MIYU_BROWSER_EXECUTABLE
  ?? (process.platform === 'win32'
    ? String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`
    : chromium.executablePath());
const OUTPUT_DIR = join(root, 'test-results', 'http-auth-e2e');

const issues = [];
const secrets = new Set();
let phase = 'startup';
let cleanupResult = 'not-needed';
let context;
let tunnel;
let localBasicServer;
let remoteDirectory;
let runRoot;
let helper;
let preparedAccount;
let cleanupToken;
let accountArmed = false;
let extensionId;
let diagnosticPage;
const diagnostics = {
  metrics: undefined,
  tombstonePresent: undefined,
  browserPermissions: undefined,
};

async function main() {
  try {
    assert(existsSync(CHROME_EXECUTABLE), `Google Chrome was not found at ${CHROME_EXECUTABLE}`);
    assert(new URL(process.env.MIYU_SERVER ?? VAULT_SERVER).toString() === VAULT_SERVER,
      `HTTP auth E2E is restricted to ${VAULT_SERVER}`);

    phase = 'production-build';
    await runNode(join(root, 'build.mjs'), ['--prod']);
    await runNode(join(root, 'tools', 'assert-build.mjs'));

    phase = 'test-workspace';
    rmSync(OUTPUT_DIR, { recursive: true, force: true });
    mkdirSync(OUTPUT_DIR, { recursive: true });
    runRoot = mkdtempSync(join(tmpdir(), 'miyu-http-auth-e2e-'));
    const extensionPath = join(runRoot, 'dist');
    cpSync(join(root, 'dist'), extensionPath, { recursive: true });
    grantCopiedExtensionAccess(extensionPath);
    helper = await loadAccountHelper(runRoot);

    const marker = randomUUID().replaceAll('-', '').slice(0, 12);
    const basicUsername = `miyu-${marker}`;
    const basicPassword = `Basic-${randomUUID()}-Aa1!`;
    secrets.add(basicUsername);
    secrets.add(basicPassword);

    phase = 'test-env-basic-endpoint';
    remoteDirectory = RUNNING_ON_TEST_ENV
      ? join(tmpdir(), `miyu-http-auth-e2e-${marker}`)
      : `/tmp/miyu-http-auth-e2e-${marker}`;
    if (RUNNING_ON_TEST_ENV) {
      assert(process.platform === 'linux', 'Direct test-env mode requires Linux');
      localBasicServer = startLocalBasicEndpoint(remoteDirectory, basicUsername, basicPassword);
    } else {
      await deployBasicEndpoint(runRoot, remoteDirectory, basicUsername, basicPassword);
      tunnel = startTunnel();
    }
    await waitForHttp(`${BASIC_ORIGIN}/health`, 15_000);

    phase = 'test-env-account';
    const identity = helper.createSshE2eIdentity();
    secrets.add(identity.email);
    secrets.add(identity.password);
    preparedAccount = await helper.prepareSshE2eAccount(
      identity.email,
      identity.password,
      'MiYu HTTP Auth E2E',
    );
    secrets.add(preparedAccount.masterPasswordHash);
    accountArmed = true;
    const registered = await helper.registerSshE2eAccount(VAULT_SERVER, preparedAccount);
    cleanupToken = registered.accessToken;
    secrets.add(cleanupToken);
    await helper.seedHttpAuthLogin(
      VAULT_SERVER,
      preparedAccount,
      registered,
      identity.password,
      {
        name: `HTTP Auth E2E ${marker}`,
        origin: BASIC_ORIGIN,
        username: basicUsername,
        password: basicPassword,
      },
    );

    phase = 'chrome-launch';
    context = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
      executablePath: CHROME_EXECUTABLE,
      headless: false,
      viewport: { width: 1100, height: 760 },
      ignoreDefaultArgs: ['--disable-extensions'],
      args: [
        '--enable-unsafe-extension-debugging',
        '--no-first-run',
        '--no-default-browser-check',
        ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
      ],
    });
    context.setDefaultTimeout(15_000);
    context.setDefaultNavigationTimeout(20_000);
    watchContext(context);
    extensionId = await loadUnpackedExtension(context, extensionPath);

    phase = 'visible-server-configuration';
    const options = await context.newPage();
    diagnosticPage = options;
    watchPage(options, 'options');
    await options.goto(extensionUrl(extensionId, 'ui/options/options.html'), { waitUntil: 'load' });
    await waitForRpc(options, { type: 'auth.getState' }, (response) => response?.ok === true, 'background RPC');
    await options.locator('vw-connection-section [data-server-url]').fill(VAULT_SERVER);
    await options.locator('vw-connection-section [data-save]').click();
    await waitForRpc(
      options,
      { type: 'settings.get' },
      (response) => response?.ok === true && sameServer(response.data?.serverUrl, VAULT_SERVER),
      'server configuration',
    );

    phase = 'visible-login';
    const popup = await context.newPage();
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
    await waitForRpc(
      popup,
      { type: 'vault.sync' },
      (response) => response?.ok === true,
      'vault sync',
      30_000,
    );
    await waitForRpc(
      options,
      { type: 'settings.save', defaultUriMatchStrategy: 1 },
      (response) => response?.ok === true,
      'host URI matching configuration',
    );

    phase = 'visible-http-auth-configuration';
    await options.locator('vw-options-shell nav button').nth(2).click();
    const httpAuthOrigins = options.locator('vw-autofill-section [data-http-auth-origins]');
    await httpAuthOrigins.waitFor({ state: 'visible' });
    await httpAuthOrigins.fill(BASIC_ORIGIN);
    await options.locator('vw-autofill-section [data-save-http-auth-origins]').click();
    await waitForRpc(
      options,
      { type: 'settings.get' },
      (response) => response?.ok === true
        && response.data?.httpAuth?.enabled === false
        && response.data?.httpAuth?.valid === true
        && JSON.stringify(response.data?.httpAuth?.allowedOrigins) === JSON.stringify([BASIC_ORIGIN]),
      'saved HTTP auth origin',
    );
    await options.locator('vw-autofill-section [data-http-auth] button').click();
    await waitForRpc(
      options,
      { type: 'settings.get' },
      (response) => response?.ok === true && response.data?.httpAuth?.enabled === true,
      'enabled HTTP auth policy',
    );
    await options.screenshot({ path: join(OUTPUT_DIR, 'http-auth-settings.png'), fullPage: true });

    phase = 'browser-authentication';
    const protectedPage = await context.newPage();
    watchPage(protectedPage, 'protected page');
    const response = await protectedPage.goto(BASIC_URL, {
      waitUntil: 'domcontentloaded',
      timeout: 20_000,
    });
    assert(response?.status() === 200, `Protected endpoint returned HTTP ${response?.status()}`);
    await protectedPage.locator('[data-authenticated="true"]').waitFor({ timeout: 5_000 });
    await protectedPage.screenshot({ path: join(OUTPUT_DIR, 'http-auth-success.png') });

    phase = 'replay-and-storage-assertions';
    const metrics = await fetchJson(`${BASIC_ORIGIN}/metrics`);
    assert(metrics.requests === 2, `Expected challenge plus authenticated retry, got ${metrics.requests}`);
    assert(metrics.challenges === 1, `Expected one Basic challenge, got ${metrics.challenges}`);
    assert(metrics.authorizationAttempts === 1,
      `Expected one credential-bearing request, got ${metrics.authorizationAttempts}`);
    assert(metrics.successes === 1, `Expected one authenticated response, got ${metrics.successes}`);
    const tombstone = await readSessionTombstone(context, extensionId);
    assertSafeTombstone(tombstone);

    phase = 'visible-disable';
    await options.locator('vw-autofill-section [data-http-auth] button').click();
    await waitForRpc(
      options,
      { type: 'settings.get' },
      (settings) => settings?.ok === true && settings.data?.httpAuth?.enabled === false,
      'disabled HTTP auth policy',
    );
    phase = 'complete';
  } catch (error) {
    recordIssue(error);
    await collectFailureDiagnostics();
  } finally {
    if (context) {
      await withTimeout(context.close(), 10_000, 'Chrome cleanup')
        .catch((error) => recordIssue(error, 'chrome-cleanup'));
    }
    if (accountArmed && helper && preparedAccount) {
      try {
        cleanupResult = await helper.cleanupSshE2eAccount(
          VAULT_SERVER,
          preparedAccount,
          cleanupToken,
        );
      } catch (error) {
        cleanupResult = 'failed';
        recordIssue(error, 'account-cleanup');
      }
    }
    await stopChild(localBasicServer);
    await stopTunnel(tunnel);
    if (remoteDirectory && RUNNING_ON_TEST_ENV) {
      removeLocalBasicEndpointDirectory(remoteDirectory);
    } else if (remoteDirectory) {
      await runProcess('ssh', ['test-env', remoteCleanupCommand(remoteDirectory)])
        .catch((error) => recordIssue(error, 'endpoint-cleanup'));
    }
    if (runRoot) rmSync(runRoot, { recursive: true, force: true });
  }

  console.log('\n=== HTTP auth E2E result ===');
  console.log('phase:', phase);
  console.log('test-env account cleanup:', cleanupResult);
  console.log('metrics:', diagnostics.metrics ? JSON.stringify(diagnostics.metrics) : 'not-observed');
  console.log('tombstone present:', diagnostics.tombstonePresent ?? 'not-observed');
  console.log('browser permissions:', diagnostics.browserPermissions
    ? JSON.stringify(diagnostics.browserPermissions)
    : 'not-observed');
  console.log('issues:', issues.length);
  for (const issue of issues) console.log('  -', issue);
  console.log('artifacts:', OUTPUT_DIR);
  if (phase !== 'complete' || cleanupResult !== 'deleted' || issues.length > 0) {
    process.exitCode = 1;
  }
}

async function collectFailureDiagnostics() {
  try {
    diagnostics.metrics = await fetchJson(`${BASIC_ORIGIN}/metrics`);
  } catch (error) {
    recordIssue(error, 'metrics-diagnostic');
  }
  if (!context || !extensionId || !diagnosticPage) return;
  try {
    const tombstone = await readSessionTombstone(context, extensionId);
    diagnostics.tombstonePresent = Boolean(tombstone);
  } catch (error) {
    recordIssue(error, 'tombstone-diagnostic');
  }
  try {
    diagnostics.browserPermissions = await diagnosticPage.evaluate(async () => ({
      webRequest: await chrome.permissions.contains({ permissions: ['webRequest'] }),
      authProvider: await chrome.permissions.contains({ permissions: ['webRequestAuthProvider'] }),
    }));
  } catch (error) {
    recordIssue(error, 'permission-diagnostic');
  }
}

function grantCopiedExtensionAccess(extensionPath) {
  const manifestPath = join(extensionPath, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.host_permissions = [...new Set([
    ...(manifest.host_permissions ?? []),
    `${new URL(VAULT_SERVER).origin}/*`,
    `${new URL(BASIC_ORIGIN).origin}/*`,
  ])];
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function loadAccountHelper(workspace) {
  const outputPath = join(workspace, 'http-auth-e2e-account-helper.mjs');
  await esbuildBuild({
    entryPoints: [join(root, 'test', 'support', 'http-auth-e2e-account.ts')],
    outfile: outputPath,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node20',
    sourcemap: false,
    logLevel: 'silent',
  });
  return import(`${pathToFileURL(outputPath).href}?run=${Date.now()}`);
}

function startLocalBasicEndpoint(directory, username, password) {
  assert(!existsSync(directory), 'The direct test-env endpoint directory already exists');
  mkdirSync(directory, { mode: 0o700 });
  const configPath = join(directory, 'http-auth-config.json');
  const serverPath = join(directory, 'http-auth-test-server.mjs');
  writeFileSync(configPath, JSON.stringify({ username, password }), { mode: 0o600 });
  cpSync(join(root, 'test', 'support', 'http-auth-test-server.mjs'), serverPath);
  const child = spawn(process.execPath, [serverPath, configPath], {
    cwd: directory,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (chunk) => {
    const text = String(chunk).trim();
    if (text) issues.push(`basic-endpoint:${redact(text)}`);
  });
  return child;
}

function removeLocalBasicEndpointDirectory(directory) {
  const target = resolve(directory);
  const expectedParent = `${resolve(tmpdir())}${sep}`;
  assert(target.startsWith(expectedParent), 'HTTP auth endpoint escaped the temporary directory');
  assert(target.includes('miyu-http-auth-e2e-'), 'HTTP auth endpoint has an unexpected name');
  rmSync(target, { recursive: true, force: true });
  assert(!existsSync(target), 'HTTP auth endpoint directory remains after cleanup');
}

async function deployBasicEndpoint(workspace, directory, username, password) {
  await runProcess('ssh', ['test-env', [
    `test ! -e ${directory}`,
    "test -z \"$(ss -H -ltn 'sport = :18083')\"",
    `mkdir -m 700 ${directory}`,
  ].join(' && ')]);
  const configPath = join(workspace, 'http-auth-config.json');
  writeFileSync(configPath, JSON.stringify({ username, password }), { mode: 0o600 });
  await runProcess('scp', [
    join(root, 'test', 'support', 'http-auth-test-server.mjs'),
    configPath,
    `test-env:${directory}/`,
  ]);
  await runProcess('ssh', ['test-env', [
    `cd ${directory}`,
    'chmod 600 http-auth-config.json',
    '(nohup node http-auth-test-server.mjs http-auth-config.json >server.log 2>&1 < /dev/null & echo $! >server.pid)',
    'sleep 0.2',
    'kill -0 "$(cat server.pid)"',
  ].join(' && ')]);
}

function remoteCleanupCommand(directory) {
  return `if test -f ${directory}/server.pid; then kill "$(cat ${directory}/server.pid)" 2>/dev/null || true; fi; rm -rf ${directory}`;
}

function startTunnel() {
  const child = spawn('ssh', [
    '-N',
    '-o', 'ExitOnForwardFailure=yes',
    '-L', '18083:127.0.0.1:18083',
    'test-env',
  ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  child.stderr.on('data', (chunk) => {
    const text = String(chunk).trim();
    if (text) issues.push(`tunnel:${redact(text)}`);
  });
  return child;
}

async function stopTunnel(child) {
  if (!child || child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolvePromise) => child.once('exit', resolvePromise)),
    new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000)),
  ]);
  if (child.exitCode === null) child.kill('SIGKILL');
}

async function waitForHttp(url, timeoutMs) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000), cache: 'no-store' });
      if (response.ok) return;
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for test-env Basic endpoint: ${redact(String(last))}`);
}

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(5_000), cache: 'no-store' });
  if (!response.ok) throw new Error(`Metrics returned HTTP ${response.status}`);
  return response.json();
}

async function loadUnpackedExtension(browserContext, extensionPath) {
  const browser = browserContext.browser();
  assert(browser, 'Persistent Chrome did not expose its browser CDP connection');
  const session = await browser.newBrowserCDPSession();
  try {
    const result = await session.send('Extensions.loadUnpacked', {
      path: extensionPath,
      enableInIncognito: false,
    });
    assert(typeof result?.id === 'string' && result.id.length > 0,
      'Chrome did not return an extension id');
    return result.id;
  } finally {
    await session.detach().catch(() => undefined);
  }
}

function watchContext(browserContext) {
  browserContext.on('weberror', (event) => issues.push(`browser:${redact(String(event.error()))}`));
  browserContext.on('serviceworker', (worker) => watchWorker(worker));
  for (const worker of browserContext.serviceWorkers()) watchWorker(worker);
}

const watchedWorkers = new WeakSet();
function watchWorker(worker) {
  if (watchedWorkers.has(worker)) return;
  watchedWorkers.add(worker);
  worker.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'assert') {
      issues.push(`worker-console:${redact(message.text())}`);
    }
  });
}

function watchPage(page, label) {
  page.on('pageerror', (error) => issues.push(`${label}:${redact(String(error))}`));
  page.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'assert') {
      issues.push(`${label}-console:${redact(message.text())}`);
    }
  });
}

async function readSessionTombstone(browserContext, extensionId) {
  let worker = browserContext.serviceWorkers().find((candidate) => (
    new URL(candidate.url()).host === extensionId
  ));
  if (!worker) worker = await browserContext.waitForEvent('serviceworker', { timeout: 10_000 });
  return worker.evaluate(async () => {
    const value = await chrome.storage.session.get('httpAuth.tombstones');
    return value['httpAuth.tombstones'];
  });
}

function assertSafeTombstone(value) {
  assert(value?.schemaVersion === 1, 'HTTP auth tombstone schema is missing');
  assert(Array.isArray(value.entries) && value.entries.length === 1,
    'HTTP auth tombstone does not contain exactly one request claim');
  const entry = value.entries[0];
  assert(JSON.stringify(Object.keys(entry).sort()) === JSON.stringify(['claimedAt', 'expiresAt', 'fingerprint']),
    'HTTP auth tombstone contains unexpected fields');
  assert(/^[0-9a-f]{64}$/.test(entry.fingerprint), 'HTTP auth tombstone fingerprint is invalid');
  const serialized = JSON.stringify(value);
  assert(!serialized.includes(BASIC_ORIGIN), 'HTTP auth tombstone persisted the protected origin');
  for (const secret of secrets) {
    assert(!serialized.includes(secret), 'HTTP auth tombstone persisted sensitive data');
  }
}

async function waitForRpc(page, message, accept, label, timeoutMs = 10_000) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    try {
      last = await withTimeout(
        page.evaluate((request) => chrome.runtime.sendMessage(request), message),
        2_000,
        `${label} RPC attempt`,
      );
      if (accept(last)) return last;
    } catch (error) {
      last = error;
    }
    await page.waitForTimeout(100);
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

async function runNode(script, args = []) {
  return runProcess(process.execPath, [script, ...args]);
}

function runProcess(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`${command} exited ${code}: ${redact(stderr || stdout)}`));
    });
  });
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

function recordIssue(error, label = 'runner') {
  issues.push(`${phase}:${label}:${redact(error instanceof Error ? error.message : String(error))}`);
}

function redact(value) {
  let output = String(value);
  for (const secret of secrets) output = output.replaceAll(secret, '[redacted]');
  return output;
}

function formatValue(value) {
  if (value instanceof Error) return value.message;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

await main();
