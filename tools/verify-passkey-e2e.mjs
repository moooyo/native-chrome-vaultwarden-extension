// Production-like website Passkey gate against the authorized test-env tunnel. It builds the
// extension, loads a copied dist into a fresh branded-Chrome profile, drives a real loopback RP via
// navigator.credentials, and always reconciles the unique disposable Bitwarden account.
import { spawn } from 'node:child_process';
import {
  createHash,
  createPublicKey,
  randomUUID,
  verify as verifySignature,
} from 'node:crypto';
import { createServer } from 'node:http';
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
const RP_HOST = '127.0.0.1';
const RP_ID = '127.0.0.1';
const RP_NAME = 'MiYu Passkey E2E';
const STANDARD_VIEWPORT = Object.freeze({ width: 372, height: 600 });
const NARROW_VIEWPORT = Object.freeze({ width: 320, height: 600 });
const OUTPUT_DIR = join(root, 'test-results', 'passkey-e2e');
const WEBSITE_PASSKEY_SCRIPT_IDS = Object.freeze([
  'miyu-website-passkey-main',
  'miyu-website-passkey-bridge',
]);
const WEBSITE_PASSKEY_SCRIPT_MATCHES = Object.freeze([
  'https://*/*',
  'http://localhost/*',
  'http://127.0.0.1/*',
]);
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SERVER = new URL(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER).toString();

const issues = [];
const failedRequests = [];
const secrets = new Set();
const wireShapeTasks = [];
const wireShapeDiagnostics = [];
let cleanupResult = 'not-needed';
let phase = 'startup';
let collectingDiagnostics = true;
let createDiagnostic = 'not-captured';
let getDiagnostic = 'not-captured';
let duplicateDiagnostic = 'not-captured';
let vaultDiagnostic = 'not-captured';

async function main() {
  let context;
  let loginPopup;
  let localRp;
  let runRoot;
  let helper;
  let preparedAccount;
  let accountArmed = false;
  let accessToken;
  let stopIdlePulse;
  let rp;

  try {
    assert(SERVER === AUTHORIZED_SERVER, `Passkey E2E is restricted to ${AUTHORIZED_SERVER}`);
    assert(existsSync(CHROME_EXECUTABLE), `Google Chrome was not found at ${CHROME_EXECUTABLE}`);

    phase = 'production-build';
    await runNode(join(root, 'build.mjs'), ['--prod']);
    await runNode(join(root, 'tools', 'assert-build.mjs'));

    phase = 'test-workspace';
    resetOutputDirectory();
    runRoot = mkdtempSync(join(tmpdir(), 'miyu-passkey-e2e-'));
    const marker = randomUUID().slice(0, 8);
    const rpUserName = `passkey-user-${marker}`;
    const rpUserDisplayName = `Passkey User ${marker}`;
    const extensionPath = join(runRoot, 'dist');
    cpSync(join(root, 'dist'), extensionPath, { recursive: true });
    grantCopiedExtensionAccess(extensionPath);
    helper = await loadAccountHelper(runRoot);
    localRp = await startRelyingPartyServer({ marker, rpUserName, rpUserDisplayName });
    const rpOrigin = localRp.origin;

    phase = 'chrome-launch';
    context = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
      executablePath: CHROME_EXECUTABLE,
      headless: false,
      viewport: STANDARD_VIEWPORT,
      ignoreDefaultArgs: ['--disable-extensions'],
      args: ['--enable-unsafe-extension-debugging', '--no-first-run', '--no-default-browser-check'],
    });
    watchContext(context, rpOrigin);
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

    // Playwright input does not update Windows' system-idle clock. Keep it active exactly as a user
    // interacting with the popup would, without changing the extension's timeout or policy state.
    stopIdlePulse = await startWindowsIdlePulse();

    phase = 'account-registration';
    const identity = helper.createSshE2eIdentity();
    secrets.add(identity.email);
    secrets.add(identity.password);
    preparedAccount = await helper.prepareSshE2eAccount(identity.email, identity.password, 'MiYu Passkey E2E');
    secrets.add(preparedAccount.masterPasswordHash);
    accountArmed = true;
    const registered = await helper.registerSshE2eAccount(SERVER, preparedAccount);
    accessToken = registered.accessToken;
    secrets.add(accessToken);

    phase = 'ui-login';
    loginPopup = await context.newPage();
    watchPage(loginPopup, 'popup');
    await loginPopup.goto(extensionUrl(extensionId, 'ui/popup/popup.html'), { waitUntil: 'load' });
    await loginPopup.locator('vw-auth-views #email').fill(identity.email);
    await loginPopup.locator('vw-auth-views #password').fill(identity.password);
    await loginPopup.locator('vw-auth-views form').first().locator('button[type="submit"]').click();
    await waitForRpc(
      loginPopup,
      { type: 'auth.getState' },
      (response) => response?.ok === true && response.data?.state === 'unlocked',
      'unlocked disposable account',
      30_000,
    );
    await loginPopup.locator('vw-vault-view input[type="search"]').waitFor({ timeout: 20_000 });

    phase = 'passkey-enable';
    await options.reload({ waitUntil: 'load' });
    const hostPermission = await options.evaluate(
      (origins) => chrome.permissions.contains({ origins }),
      [...WEBSITE_PASSKEY_SCRIPT_MATCHES],
    );
    assert(hostPermission === true, 'Copied extension is missing pre-granted website Passkey host access');
    await options.locator('vw-options-shell .nav-item').nth(2).click();
    const passkeyToggle = options.locator('vw-autofill-section [data-website-passkeys] button');
    await passkeyToggle.waitFor({ state: 'visible', timeout: 15_000 });
    assert(await passkeyToggle.getAttribute('aria-checked') === 'false', 'Website Passkey setting was not safely disabled by default');
    await passkeyToggle.click();
    await waitForRpc(
      options,
      { type: 'settings.get' },
      (response) => response?.ok === true
        && response.data?.websitePasskeys?.enabled === true
        && response.data?.websitePasskeys?.valid === true,
      'enabled website Passkey setting',
      30_000,
    );
    await waitForAttribute(passkeyToggle, 'aria-checked', 'true', 15_000);
    await waitForRegisteredPasskeyScripts(options);

    phase = 'rp-ready';
    rp = await context.newPage();
    watchPage(rp, 'relying party');
    await rp.goto(rpOrigin, { waitUntil: 'load' });
    await rp.locator('[data-rp-ready]').waitFor({ state: 'visible' });
    await waitForPageInterception(rp);

    phase = 'passkey-create';
    const createApproval = await startCeremonyAndWaitForApproval(
      context,
      rp,
      '[data-create]',
      extensionId,
      'create approval',
    );
    await createApproval.locator('vw-website-passkey-view [role="dialog"]').waitFor({ state: 'visible', timeout: 20_000 });
    const createBefore = await readRpOperation(rp, 'create');
    assert(createBefore.status === 'pending', 'RP create ceremony did not remain pending for approval');
    assertApprovalUrl(createApproval, extensionId);
    await assertApprovalDom(createApproval, [createBefore.challenge, createBefore.userId]);
    await assertApprovalSource(createApproval, rpOrigin, RP_ID);
    await createApproval.setViewportSize(STANDARD_VIEWPORT);
    assert(await hasNoApprovalOverflow(createApproval), 'Create approval overflows the standard viewport');
    await createApproval.screenshot({ path: join(OUTPUT_DIR, 'passkey-create-approval-372x600.png') });
    await createApproval.setViewportSize(NARROW_VIEWPORT);
    assert(await hasNoApprovalOverflow(createApproval), 'Create approval overflows the narrow viewport');
    await createApproval.screenshot({ path: join(OUTPUT_DIR, 'passkey-create-approval-320x600.png') });
    await createApproval.setViewportSize(STANDARD_VIEWPORT);
    const createClosed = createApproval.waitForEvent('close', { timeout: 45_000 });
    await createApproval.locator('vw-website-passkey-view [data-primary-action]').click();
    const created = await waitForRpOperation(rp, 'create', 45_000);
    await createClosed;
    assertCreateResult(created, rpOrigin);
    createDiagnostic = {
      publicKeyCredential: created.publicKeyCredential,
      attestationResponse: created.attestationResponse,
      authenticatorAttachment: created.authenticatorAttachment,
      transport: created.transports?.join(',') ?? '',
      resident: created.clientExtensionResults?.credProps?.rk === true,
      publicKeyAlgorithm: created.publicKeyAlgorithm,
      clientDataVerified: true,
    };

    phase = 'passkey-get';
    const getApproval = await startCeremonyAndWaitForApproval(
      context,
      rp,
      '[data-get]',
      extensionId,
      'get approval',
    );
    await getApproval.locator('vw-website-passkey-view [role="dialog"]').waitFor({ state: 'visible', timeout: 20_000 });
    const getBefore = await readRpOperation(rp, 'get');
    assert(getBefore.status === 'pending', 'RP get ceremony did not remain pending for approval');
    await assertApprovalDom(getApproval, [getBefore.challenge, created.credentialId]);
    await assertApprovalSource(getApproval, rpOrigin, RP_ID);
    const candidateButtons = getApproval.locator('vw-website-passkey-view .choices .choice');
    assert(await candidateButtons.count() === 1, 'Get approval did not expose exactly one matching credential');
    const getClosed = getApproval.waitForEvent('close', { timeout: 45_000 });
    await candidateButtons.first().click();
    const assertion = await waitForRpOperation(rp, 'get', 45_000);
    await getClosed;
    assertGetResult(assertion, created, getBefore.challenge, rpOrigin);
    getDiagnostic = {
      publicKeyCredential: assertion.publicKeyCredential,
      assertionResponse: assertion.assertionResponse,
      credentialMatched: assertion.credentialId === created.credentialId,
      userHandleMatched: assertion.userHandle === created.userId,
      signatureVerified: true,
      clientDataVerified: true,
    };

    phase = 'passkey-duplicate';
    const duplicateApproval = await startCeremonyAndWaitForApproval(
      context,
      rp,
      '[data-duplicate]',
      extensionId,
      'duplicate create approval',
    );
    await duplicateApproval.locator('vw-website-passkey-view [role="dialog"]').waitFor({ state: 'visible', timeout: 20_000 });
    const duplicateBefore = await readRpOperation(rp, 'duplicate');
    assert(duplicateBefore.status === 'pending', 'Duplicate create did not remain pending for approval');
    await assertApprovalDom(duplicateApproval, [duplicateBefore.challenge, created.credentialId]);
    await duplicateApproval.locator('vw-website-passkey-view [data-primary-action]').click();
    const duplicate = await waitForRpOperation(rp, 'duplicate', 45_000);
    assert(duplicate.status === 'error', 'Duplicate create unexpectedly succeeded');
    assert(duplicate.errorName === 'InvalidStateError', `Duplicate create failed with ${duplicate.errorName ?? 'no DOMException name'}`);
    duplicateDiagnostic = { status: duplicate.status, errorName: duplicate.errorName };
    if (!duplicateApproval.isClosed()) {
      const duplicateClose = duplicateApproval.locator('vw-website-passkey-view [data-cancel]');
      if (await duplicateClose.count().catch(() => 0) > 0) {
        await duplicateClose.click().catch(() => undefined);
      }
      if (!duplicateApproval.isClosed()) {
        await duplicateApproval.waitForEvent('close', { timeout: 10_000 })
          .catch(() => duplicateApproval.close());
      }
    }

    phase = 'vault-reconciliation';
    await reopenUnlockedPopup(loginPopup);
    await syncThroughUi(loginPopup);
    const listing = await sendRpc(loginPopup, { type: 'vault.listItems' });
    assert(listing?.ok === true && Array.isArray(listing.data?.items), 'Vault listing was unavailable after visible sync');
    const matching = listing.data.items.filter((item) => item?.type === 1
      && item?.name === RP_NAME
      && item?.username === rpUserName
      && item?.hasPasskey === true
      && Array.isArray(item?.uris)
      && item.uris.includes(rpOrigin));
    assert(matching.length === 1, `Expected one corresponding Passkey login item, found ${matching.length}`);
    const detail = await sendRpc(loginPopup, { type: 'vault.getCipherDetail', id: matching[0].id });
    const credentials = detail?.ok === true ? detail.data?.cipher?.fido2Credentials : undefined;
    assert(Array.isArray(credentials) && credentials.length === 1, 'Corresponding login does not contain exactly one Passkey credential');
    assert(credentials[0]?.credentialId === created.credentialId, 'Stored Passkey credential id differs from the RP registration');
    assert(credentials[0]?.keyValue === '', 'Vault detail exposed Passkey private key material');
    vaultDiagnostic = {
      matchingItems: matching.length,
      passkeysInItem: credentials.length,
      visibleSync: true,
      privateMaterialRedacted: credentials[0].keyValue === '',
    };
    phase = 'complete';
  } catch (error) {
    recordIssue('runner', error);
    if (rp) {
      const snapshot = await readRpOperation(rp, phase === 'passkey-create'
        ? 'create'
        : phase === 'passkey-get' ? 'get' : 'duplicate').catch(() => undefined);
      if (snapshot) recordIssue('RP state', sanitizeRpFailure(snapshot));
    }
    const failurePage = context?.pages().find((page) => page.url().includes('websitePasskey='));
    await failurePage?.screenshot({ path: join(OUTPUT_DIR, 'passkey-e2e-failure.png') }).catch(() => undefined);
  } finally {
    stopIdlePulse?.();
    collectingDiagnostics = false;
    await context?.close().catch((error) => recordIssue('chrome cleanup', error));
    await localRp?.close().catch((error) => recordIssue('RP cleanup', error));
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
        removeTemporaryWorkspace(runRoot);
      } catch (error) {
        recordIssue('temporary workspace cleanup', error);
      }
    }
    await settleWireShapeDiagnostics();
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

function resetOutputDirectory() {
  const expectedParent = `${resolve(root, 'test-results')}${sep}`;
  const resolvedOutput = resolve(OUTPUT_DIR);
  assert(resolvedOutput.startsWith(expectedParent), 'Passkey E2E output path escaped test-results');
  rmSync(resolvedOutput, { recursive: true, force: true });
  mkdirSync(resolvedOutput, { recursive: true });
}

function removeTemporaryWorkspace(runRoot) {
  const expectedParent = `${resolve(tmpdir())}${sep}`;
  const resolvedRunRoot = resolve(runRoot);
  assert(resolvedRunRoot.startsWith(expectedParent), 'Passkey E2E temporary path escaped the OS temp directory');
  assert(resolvedRunRoot.includes('miyu-passkey-e2e-'), 'Passkey E2E temporary path has an unexpected name');
  rmSync(resolvedRunRoot, { recursive: true, force: true });
  assert(!existsSync(resolvedRunRoot), 'Passkey E2E temporary workspace still exists after cleanup');
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
    '$native = Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace MiYuPasskeyE2E -PassThru',
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

function grantCopiedExtensionAccess(extensionPath) {
  const manifestPath = join(extensionPath, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const backendPattern = `${new URL(SERVER).origin}/*`;
  // Pre-grant the dynamic-script match set in the disposable copy so the visible toggle can
  // exercise its normal permission path without an unautomatable Chrome permission bubble.
  manifest.host_permissions = [...new Set([
    ...(manifest.host_permissions ?? []),
    backendPattern,
    ...WEBSITE_PASSKEY_SCRIPT_MATCHES,
  ])];
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function loadAccountHelper(runRoot) {
  const outputPath = join(runRoot, 'passkey-e2e-account-helper.mjs');
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

async function startRelyingPartyServer({ marker, rpUserName, rpUserDisplayName }) {
  const html = relyingPartyHtml({ marker, rpUserName, rpUserDisplayName });
  const server = createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== '/') {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('Not found');
      return;
    }
    response.writeHead(200, {
      'cache-control': 'no-store',
      'content-type': 'text/html; charset=utf-8',
      'x-content-type-options': 'nosniff',
    });
    response.end(html);
  });
  await new Promise((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(0, RP_HOST, resolvePromise);
  });
  const address = server.address();
  assert(address && typeof address === 'object', 'Loopback RP did not expose a TCP address');
  const origin = `http://${RP_HOST}:${address.port}`;
  return Object.freeze({
    origin,
    async close() {
      if (!server.listening) return;
      await new Promise((resolvePromise, reject) => {
        server.close((error) => error ? reject(error) : resolvePromise());
      });
    },
  });
}

function relyingPartyHtml({ marker, rpUserName, rpUserDisplayName }) {
  const config = JSON.stringify({ marker, rpId: RP_ID, rpName: RP_NAME, rpUserName, rpUserDisplayName });
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MiYu Passkey E2E RP</title>
  <link rel="icon" href="data:,">
</head>
<body>
  <main>
    <h1>MiYu Passkey E2E RP</h1>
    <p data-rp-ready>Relying party ready</p>
    <button type="button" data-create>Create passkey</button>
    <button type="button" data-get disabled>Get passkey</button>
    <button type="button" data-duplicate disabled>Create duplicate</button>
    <pre data-status>{"create":"idle","get":"idle","duplicate":"idle"}</pre>
  </main>
  <script>
    (() => {
      'use strict';
      const config = ${config};
      const state = {
        create: { status: 'idle' },
        get: { status: 'idle' },
        duplicate: { status: 'idle' },
      };
      let createdCredential;

      const bytes = (value) => value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      const base64url = (value) => {
        let binary = '';
        for (const byte of bytes(value)) binary += String.fromCharCode(byte);
        return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
      };
      const challenge = () => crypto.getRandomValues(new Uint8Array(32));
      const userId = new TextEncoder().encode('miyu-passkey-' + config.marker);
      const render = () => {
        document.querySelector('[data-status]').textContent = JSON.stringify({
          create: state.create.status,
          get: state.get.status,
          duplicate: state.duplicate.status,
        });
        const ready = state.create.status === 'success';
        document.querySelector('[data-get]').disabled = !ready || state.get.status === 'pending';
        document.querySelector('[data-duplicate]').disabled = !ready || state.duplicate.status === 'pending';
      };
      const clientData = (buffer) => JSON.parse(new TextDecoder().decode(buffer));
      const errorResult = (error) => ({
        status: 'error',
        errorName: typeof error?.name === 'string' ? error.name : 'Error',
        errorMessage: typeof error?.message === 'string' ? error.message : 'Unknown failure',
      });

      const beginCreate = async () => {
        if (state.create.status === 'pending') return;
        const requestChallenge = challenge();
        state.create = {
          status: 'pending',
          challenge: base64url(requestChallenge),
          userId: base64url(userId),
        };
        render();
        try {
          const credential = await navigator.credentials.create({ publicKey: {
            challenge: requestChallenge,
            rp: { id: config.rpId, name: config.rpName },
            user: {
              id: userId,
              name: config.rpUserName,
              displayName: config.rpUserDisplayName,
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 90000,
            excludeCredentials: [],
            authenticatorSelection: {
              authenticatorAttachment: 'platform',
              residentKey: 'required',
              requireResidentKey: true,
              userVerification: 'preferred',
            },
            attestation: 'none',
            extensions: { credProps: true },
          } });
          if (!credential) throw new Error('Credential creation returned null');
          createdCredential = credential;
          const response = credential.response;
          const publicKey = response.getPublicKey();
          state.create = {
            status: 'success',
            challenge: state.create.challenge,
            userId: state.create.userId,
            credentialId: credential.id,
            rawId: base64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            publicKeyCredential: credential instanceof PublicKeyCredential
              && Object.getPrototypeOf(credential) === PublicKeyCredential.prototype,
            attestationResponse: response instanceof AuthenticatorAttestationResponse
              && Object.getPrototypeOf(response) === AuthenticatorAttestationResponse.prototype,
            hasToJSON: typeof credential.toJSON === 'function',
            hasClientExtensionResults: typeof credential.getClientExtensionResults === 'function',
            clientExtensionResults: credential.getClientExtensionResults(),
            clientDataJSON: base64url(response.clientDataJSON),
            clientData: clientData(response.clientDataJSON),
            attestationObject: base64url(response.attestationObject),
            authenticatorData: base64url(response.getAuthenticatorData()),
            publicKeySpki: publicKey ? base64url(publicKey) : null,
            publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
            transports: response.getTransports(),
            json: credential.toJSON(),
          };
        } catch (error) {
          state.create = { ...state.create, ...errorResult(error) };
        }
        render();
      };

      const beginGet = async () => {
        if (!createdCredential || state.get.status === 'pending') return;
        const requestChallenge = challenge();
        state.get = { status: 'pending', challenge: base64url(requestChallenge) };
        render();
        try {
          const credential = await navigator.credentials.get({ publicKey: {
            challenge: requestChallenge,
            rpId: config.rpId,
            allowCredentials: [{
              id: createdCredential.rawId,
              type: 'public-key',
              transports: ['internal'],
            }],
            userVerification: 'preferred',
            timeout: 90000,
          }, mediation: 'optional' });
          if (!credential) throw new Error('Credential lookup returned null');
          const response = credential.response;
          state.get = {
            status: 'success',
            challenge: state.get.challenge,
            credentialId: credential.id,
            rawId: base64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            publicKeyCredential: credential instanceof PublicKeyCredential
              && Object.getPrototypeOf(credential) === PublicKeyCredential.prototype,
            assertionResponse: response instanceof AuthenticatorAssertionResponse
              && Object.getPrototypeOf(response) === AuthenticatorAssertionResponse.prototype,
            hasToJSON: typeof credential.toJSON === 'function',
            hasClientExtensionResults: typeof credential.getClientExtensionResults === 'function',
            clientExtensionResults: credential.getClientExtensionResults(),
            clientDataJSON: base64url(response.clientDataJSON),
            clientData: clientData(response.clientDataJSON),
            authenticatorData: base64url(response.authenticatorData),
            signature: base64url(response.signature),
            userHandle: response.userHandle === null ? null : base64url(response.userHandle),
            json: credential.toJSON(),
          };
        } catch (error) {
          state.get = { ...state.get, ...errorResult(error) };
        }
        render();
      };

      const beginDuplicate = async () => {
        if (!createdCredential || state.duplicate.status === 'pending') return;
        const requestChallenge = challenge();
        state.duplicate = { status: 'pending', challenge: base64url(requestChallenge) };
        render();
        try {
          const credential = await navigator.credentials.create({ publicKey: {
            challenge: requestChallenge,
            rp: { id: config.rpId, name: config.rpName },
            user: {
              id: userId,
              name: config.rpUserName,
              displayName: config.rpUserDisplayName,
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 90000,
            excludeCredentials: [{
              id: createdCredential.rawId,
              type: 'public-key',
              transports: ['internal'],
            }],
            authenticatorSelection: {
              authenticatorAttachment: 'platform',
              residentKey: 'required',
              requireResidentKey: true,
              userVerification: 'preferred',
            },
            attestation: 'none',
            extensions: { credProps: true },
          } });
          state.duplicate = {
            status: 'unexpected-success',
            credentialId: credential?.id ?? null,
          };
        } catch (error) {
          state.duplicate = { ...state.duplicate, ...errorResult(error) };
        }
        render();
      };

      globalThis.__miyuPasskeyE2E = Object.freeze({ state, beginCreate, beginGet, beginDuplicate });
      document.querySelector('[data-create]').addEventListener('click', () => void beginCreate());
      document.querySelector('[data-get]').addEventListener('click', () => void beginGet());
      document.querySelector('[data-duplicate]').addEventListener('click', () => void beginDuplicate());
      render();
    })();
  </script>
</body>
</html>`;
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

function watchContext(context, rpOrigin) {
  context.on('page', (page) => watchPage(page, 'page'));
  context.on('serviceworker', (worker) => watchWorker(worker));
  context.on('weberror', (error) => recordIssue('browser', error.error()));
  context.on('requestfailed', (request) => {
    if (!collectingDiagnostics) return;
    const url = safeUrl(request.url());
    if (!isRelevantUrl(url, rpOrigin)) return;
    failedRequests.push(`${request.method()} ${safeDisplayUrl(url)}: ${request.failure()?.errorText ?? 'failed'}`);
  });
  context.on('response', (response) => {
    const task = captureWireShape(response);
    if (task) wireShapeTasks.push(task);
  });
  for (const page of context.pages()) watchPage(page, 'page');
  for (const worker of context.serviceWorkers()) watchWorker(worker);
}

function captureWireShape(response) {
  const url = safeUrl(response.url());
  if (url?.origin !== new URL(AUTHORIZED_SERVER).origin) return undefined;
  const method = response.request().method();
  const create = method === 'POST' && /\/api\/ciphers\/?$/u.test(url.pathname);
  const sync = method === 'GET' && /\/api\/sync\/?$/u.test(url.pathname);
  if (!create && !sync) return undefined;
  return response.json().then((body) => {
    const ciphers = sync ? readArrayProperty(body, 'ciphers', 'Ciphers') : undefined;
    const candidate = create ? body : ciphers?.find(hasPasskeyWireShape);
    let requestBody;
    if (create) {
      try { requestBody = response.request().postDataJSON(); } catch { requestBody = undefined; }
    }
    wireShapeDiagnostics.push({
      route: create ? 'createCipher' : 'sync',
      status: response.status(),
      ...(sync ? { cipherCount: ciphers?.length ?? null } : {}),
      ...(create ? { requestCipher: requestBody ? cipherWireShape(requestBody) : null } : {}),
      cipher: candidate ? cipherWireShape(candidate) : null,
    });
  }).catch(() => {
    wireShapeDiagnostics.push({
      route: create ? 'createCipher' : 'sync',
      status: response.status(),
      inspection: 'unavailable',
    });
  });
}

function hasPasskeyWireShape(value) {
  if (!isRecord(value)) return false;
  const login = readRecordProperty(value, 'login', 'Login');
  if ((readArrayProperty(login, 'fido2Credentials', 'Fido2Credentials')?.length ?? 0) > 0) return true;
  const rawData = readProperty(value, 'data', 'Data');
  if (typeof rawData !== 'string') return false;
  try {
    const data = JSON.parse(rawData);
    return (readArrayProperty(data, 'Fido2Credentials', 'fido2Credentials')?.length ?? 0) > 0;
  } catch {
    return false;
  }
}

function cipherWireShape(value) {
  if (!isRecord(value)) return { kind: valueKind(value) };
  const login = readRecordProperty(value, 'login', 'Login');
  const rawData = readProperty(value, 'data', 'Data');
  let parsedData;
  if (typeof rawData === 'string') {
    try { parsedData = JSON.parse(rawData); } catch { parsedData = 'invalid-json'; }
  }
  return {
    keys: Object.keys(value).sort(),
    data: rawData === undefined
      ? { present: false }
      : rawData === null
        ? { present: true, kind: 'null' }
        : {
            present: true,
            kind: valueKind(rawData),
            rootKeys: isRecord(parsedData) ? Object.keys(parsedData).sort() : undefined,
            fido2Credentials: arrayWireShape(readArrayProperty(
              parsedData,
              'Fido2Credentials',
              'fido2Credentials',
            )),
          },
    login: login === undefined
      ? { present: false }
      : {
          present: true,
          keys: Object.keys(login).sort(),
          fido2Credentials: arrayWireShape(readArrayProperty(
            login,
            'fido2Credentials',
            'Fido2Credentials',
          )),
        },
  };
}

function arrayWireShape(value) {
  if (!Array.isArray(value)) return { present: false };
  const first = value[0];
  const creationDate = readProperty(first, 'creationDate', 'CreationDate');
  return {
    present: true,
    length: value.length,
    itemKeys: isRecord(first) ? Object.keys(first).sort() : undefined,
    itemTypes: isRecord(first)
      ? Object.fromEntries(Object.keys(first).sort().map((key) => [key, valueKind(first[key])]))
      : undefined,
    creationDate: dateShape(creationDate),
  };
}

function dateShape(value) {
  if (value === undefined) return { present: false };
  if (value === null) return { present: true, kind: 'null' };
  if (typeof value !== 'string') return { present: true, kind: typeof value };
  const match = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$/u.exec(value);
  return {
    present: true,
    kind: 'string',
    length: value.length,
    empty: value.length === 0,
    dateTimeShape: match ? 'date-time' : 'other',
    fractionalDigits: match?.[1]?.length ?? 0,
    timezone: match?.[2] === 'Z' ? 'Z' : match?.[2] ? 'offset' : 'none',
    dotNetDefaultWithoutZone: /^0001-01-01T00:00:00(?:\.0+)?$/u.test(value),
  };
}

function readProperty(value, camel, pascal) {
  if (!isRecord(value)) return undefined;
  if (Object.prototype.hasOwnProperty.call(value, camel)) return value[camel];
  return Object.prototype.hasOwnProperty.call(value, pascal) ? value[pascal] : undefined;
}

function readRecordProperty(value, camel, pascal) {
  const property = readProperty(value, camel, pascal);
  return isRecord(property) ? property : undefined;
}

function readArrayProperty(value, camel, pascal) {
  const property = readProperty(value, camel, pascal);
  return Array.isArray(property) ? property : undefined;
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function valueKind(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `array(${value.length})`;
  return typeof value;
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

async function waitForRegisteredPasskeyScripts(page, timeoutMs = 30_000) {
  const started = Date.now();
  let last = [];
  while (Date.now() - started < timeoutMs) {
    last = await page.evaluate(
      (ids) => chrome.scripting.getRegisteredContentScripts({ ids }),
      [...WEBSITE_PASSKEY_SCRIPT_IDS],
    );
    if (Array.isArray(last) && last.length === 2) {
      const byId = new Map(last.map((script) => [script.id, script]));
      const main = byId.get(WEBSITE_PASSKEY_SCRIPT_IDS[0]);
      const bridge = byId.get(WEBSITE_PASSKEY_SCRIPT_IDS[1]);
      if (validRegisteredScript(main, 'MAIN') && validRegisteredScript(bridge, 'ISOLATED')) return;
    }
    await delay(100);
  }
  const diagnostic = last.map((script) => ({
    id: script.id,
    runAt: script.runAt,
    allFrames: script.allFrames,
    persistAcrossSessions: script.persistAcrossSessions,
    world: script.world,
    matches: script.matches,
  }));
  throw new Error(`Timed out waiting for registered website Passkey scripts; ${JSON.stringify(diagnostic)}`);
}

function validRegisteredScript(script, world) {
  return script?.runAt === 'document_start'
    && (script.allFrames ?? false) === false
    && (script.persistAcrossSessions ?? true) === true
    && (script.world ?? 'ISOLATED') === world
    && sameStringSet(script.matches, WEBSITE_PASSKEY_SCRIPT_MATCHES);
}

function sameStringSet(left, right) {
  return Array.isArray(left)
    && left.length === right.length
    && right.every((value) => left.includes(value));
}

async function waitForPageInterception(page, timeoutMs = 20_000) {
  await page.waitForFunction(() => {
    const credentials = navigator.credentials;
    return Boolean(credentials
      && Object.prototype.hasOwnProperty.call(credentials, 'create')
      && Object.prototype.hasOwnProperty.call(credentials, 'get'));
  }, undefined, { timeout: timeoutMs });
}

async function startCeremonyAndWaitForApproval(context, rp, selector, extensionId, label) {
  const known = new Set(context.pages());
  await rp.locator(selector).click();
  const started = Date.now();
  while (Date.now() - started < 20_000) {
    for (const page of context.pages()) {
      if (known.has(page)) continue;
      const url = safeUrl(page.url());
      if (url?.protocol === 'chrome-extension:'
        && url.host === extensionId
        && url.pathname === '/ui/popup/popup.html'
        && url.searchParams.has('websitePasskey')) {
        watchPage(page, label);
        return page;
      }
    }
    await delay(50);
  }
  const pageKinds = context.pages().map((page) => safePageKind(page.url(), extensionId));
  throw new Error(`Timed out waiting for ${label}; pages=${JSON.stringify(pageKinds)}`);
}

function safePageKind(value, extensionId) {
  const url = safeUrl(value);
  if (!url) return 'invalid';
  if (url.protocol === 'chrome-extension:' && url.host === extensionId) return `extension:${url.pathname}`;
  if (url.hostname === RP_HOST) return 'loopback-rp';
  return url.protocol;
}

function assertApprovalUrl(page, extensionId) {
  const url = new URL(page.url());
  assert(url.protocol === 'chrome-extension:' && url.host === extensionId, 'Approval popup has an unexpected origin');
  assert(url.pathname === '/ui/popup/popup.html', 'Approval popup has an unexpected path');
  assert(UUID_V4_PATTERN.test(url.searchParams.get('websitePasskey') ?? ''), 'Approval popup lacks a ceremony id');
}

async function assertApprovalDom(page, forbiddenValues) {
  const text = await page.evaluate(() => {
    const parts = [];
    const visit = (root) => {
      for (const node of root.childNodes) {
        if (node.nodeType === globalThis.Node.TEXT_NODE) parts.push(node.textContent ?? '');
        if (!(node instanceof globalThis.Element)) continue;
        parts.push(node.tagName);
        for (const attribute of node.attributes) parts.push(attribute.name, attribute.value);
        if (node.shadowRoot) visit(node.shadowRoot);
        visit(node);
      }
    };
    visit(globalThis.document);
    return parts.join('\n');
  });
  for (const value of forbiddenValues) {
    if (typeof value === 'string' && value.length > 0) {
      assert(!text.includes(value), 'Approval DOM exposed ceremony request material');
    }
  }
}

async function assertApprovalSource(page, origin, rpId) {
  const source = page.locator('vw-website-passkey-view .source');
  await source.waitFor({ state: 'visible' });
  const originText = (await source.locator('.origin').innerText()).trim();
  const rpText = (await source.locator('.rp').innerText()).replaceAll(/\s+/gu, ' ').trim();
  assert(originText === origin, 'Approval popup does not show the authoritative RP origin');
  assert(rpText !== origin && rpText.endsWith(rpId), 'Approval popup does not show the RP id in its dedicated field');
}

async function hasNoApprovalOverflow(page) {
  return page.evaluate(() => {
    const document = globalThis.document;
    const within = (element) => !element || element.scrollWidth <= element.clientWidth + 1;
    const app = document.querySelector('vw-popup-app');
    const view = app?.shadowRoot?.querySelector('vw-website-passkey-view');
    const ceremony = view?.shadowRoot?.querySelector('.ceremony');
    return document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1
      && within(document.body)
      && within(document.querySelector('#app'))
      && within(app)
      && within(view)
      && within(ceremony);
  });
}

async function readRpOperation(page, operation) {
  return page.evaluate((key) => {
    const controller = globalThis.__miyuPasskeyE2E;
    return structuredClone(controller.state[key]);
  }, operation);
}

async function waitForRpOperation(page, operation, timeoutMs) {
  const started = Date.now();
  let value;
  while (Date.now() - started < timeoutMs) {
    value = await readRpOperation(page, operation);
    if (value?.status !== 'idle' && value?.status !== 'pending') return value;
    await delay(50);
  }
  throw new Error(`${operation} ceremony did not settle; status=${value?.status ?? 'unknown'}`);
}

function sanitizeRpFailure(value) {
  return JSON.stringify({
    status: value?.status,
    errorName: value?.errorName,
    errorMessage: value?.errorMessage,
  });
}

function assertCreateResult(result, origin) {
  assert(result.status === 'success', `Passkey create failed with ${result.errorName ?? 'unknown error'}`);
  assert(result.publicKeyCredential === true, 'Create result is not a real PublicKeyCredential prototype');
  assert(result.attestationResponse === true, 'Create response is not an AuthenticatorAttestationResponse prototype');
  assert(result.hasToJSON === true && result.hasClientExtensionResults === true, 'Create result is missing PublicKeyCredential methods');
  assert(result.type === 'public-key', 'Create result has the wrong credential type');
  assert(result.rawId === result.credentialId, 'Create rawId and credential id differ');
  assert(result.authenticatorAttachment === 'platform', 'Create result is not platform-attached');
  assert(Array.isArray(result.transports) && result.transports.length === 1 && result.transports[0] === 'internal', 'Create result does not expose the internal transport');
  assert(result.clientExtensionResults?.credProps?.rk === true, 'Create result does not report a resident credential');
  assert(result.publicKeyAlgorithm === -7, 'Create result does not report ES256');
  assert(typeof result.publicKeySpki === 'string' && result.publicKeySpki.length > 0, 'Create result lacks the public SPKI');
  assertClientData(result.clientDataJSON, 'webauthn.create', result.challenge, origin);
  assert(result.clientData?.type === 'webauthn.create'
    && result.clientData?.challenge === result.challenge
    && result.clientData?.origin === origin, 'Create clientData view differs from its bytes');
  assert(result.json?.id === result.credentialId
    && result.json?.rawId === result.rawId
    && result.json?.response?.clientDataJSON === result.clientDataJSON
    && result.json?.response?.publicKey === result.publicKeySpki
    && result.json?.response?.publicKeyAlgorithm === -7
    && result.json?.authenticatorAttachment === 'platform'
    && result.json?.clientExtensionResults?.credProps?.rk === true,
  'Create toJSON is inconsistent with the credential');
  assertAuthenticatorData(result.authenticatorData, true);
}

function assertGetResult(result, created, expectedChallenge, origin) {
  assert(result.status === 'success', `Passkey get failed with ${result.errorName ?? 'unknown error'}`);
  assert(result.publicKeyCredential === true, 'Get result is not a real PublicKeyCredential prototype');
  assert(result.assertionResponse === true, 'Get response is not an AuthenticatorAssertionResponse prototype');
  assert(result.hasToJSON === true && result.hasClientExtensionResults === true, 'Get result is missing PublicKeyCredential methods');
  assert(result.type === 'public-key', 'Get result has the wrong credential type');
  assert(result.rawId === created.rawId && result.credentialId === created.credentialId, 'Get result selected the wrong credential');
  assert(result.authenticatorAttachment === 'platform', 'Get result is not platform-attached');
  assert(result.userHandle === created.userId, 'Get result has the wrong user handle');
  assert(result.clientExtensionResults && Object.keys(result.clientExtensionResults).length === 0, 'Get result exposed unexpected extension output');
  assertClientData(result.clientDataJSON, 'webauthn.get', expectedChallenge, origin);
  assert(result.clientData?.type === 'webauthn.get'
    && result.clientData?.challenge === expectedChallenge
    && result.clientData?.origin === origin, 'Get clientData view differs from its bytes');
  assert(result.json?.id === created.credentialId
    && result.json?.rawId === created.rawId
    && result.json?.response?.clientDataJSON === result.clientDataJSON
    && result.json?.response?.authenticatorData === result.authenticatorData
    && result.json?.response?.signature === result.signature
    && result.json?.response?.userHandle === created.userId
    && result.json?.authenticatorAttachment === 'platform',
  'Get toJSON is inconsistent with the assertion');
  assertAuthenticatorData(result.authenticatorData, false);
  verifyAssertionSignature(result, created.publicKeySpki);
}

function assertClientData(encoded, type, challenge, origin) {
  const parsed = JSON.parse(base64UrlBytes(encoded).toString('utf8'));
  assert(parsed.type === type, `clientDataJSON type differs from ${type}`);
  assert(parsed.challenge === challenge, 'clientDataJSON challenge differs from the request');
  assert(parsed.origin === origin, 'clientDataJSON origin differs from the RP');
}

function assertAuthenticatorData(encoded, includesAttestedCredential) {
  const data = base64UrlBytes(encoded);
  assert(data.length >= (includesAttestedCredential ? 55 : 37), 'Authenticator data is too short');
  const expectedRpHash = createHash('sha256').update(RP_ID, 'utf8').digest();
  assert(data.subarray(0, 32).equals(expectedRpHash), 'Authenticator data has the wrong RP id hash');
  const flags = data[32];
  assert((flags & 0x01) !== 0, 'Authenticator data lacks user presence');
  assert((flags & 0x08) !== 0 && (flags & 0x10) !== 0, 'Authenticator data lacks backup eligibility/state flags');
  assert((flags & 0x04) === 0, 'Vault-backed ceremony incorrectly claimed user verification');
  assert(((flags & 0x40) !== 0) === includesAttestedCredential, 'Authenticator data AT flag is inconsistent');
}

function verifyAssertionSignature(assertion, publicKeySpki) {
  const authenticatorData = base64UrlBytes(assertion.authenticatorData);
  const clientDataJSON = base64UrlBytes(assertion.clientDataJSON);
  const signed = Buffer.concat([
    authenticatorData,
    createHash('sha256').update(clientDataJSON).digest(),
  ]);
  const key = createPublicKey({ key: base64UrlBytes(publicKeySpki), format: 'der', type: 'spki' });
  const valid = verifySignature('sha256', signed, key, base64UrlBytes(assertion.signature));
  assert(valid, 'ES256 assertion signature verification failed');
}

function base64UrlBytes(value) {
  assert(typeof value === 'string' && /^[A-Za-z0-9_-]+$/u.test(value), 'Invalid base64url test result');
  return Buffer.from(value, 'base64url');
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

async function waitForAttribute(locator, name, expected, timeoutMs = 10_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await locator.getAttribute(name) === expected) return;
    await delay(50);
  }
  throw new Error(`Timed out waiting for ${name}=${expected}`);
}

async function waitForEnabled(locator, timeoutMs = 10_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await locator.isEnabled()) return;
    await delay(50);
  }
  throw new Error('Timed out waiting for an enabled UI control');
}

async function sendRpc(page, message) {
  return page.evaluate((request) => chrome.runtime.sendMessage(request), message);
}

async function waitForRpc(page, message, accept, label, timeoutMs = 15_000) {
  const started = Date.now();
  let last;
  while (Date.now() - started < timeoutMs) {
    try {
      last = await sendRpc(page, message);
      if (accept(last)) return last;
    } catch (error) {
      last = error;
    }
    await delay(100);
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

function isRelevantUrl(url, rpOrigin) {
  return url?.protocol === 'chrome-extension:'
    || url?.origin === new URL(AUTHORIZED_SERVER).origin
    || url?.origin === rpOrigin;
}

function safeDisplayUrl(url) {
  if (!url) return '(invalid URL)';
  return `${url.origin}${url.pathname}`;
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

async function settleWireShapeDiagnostics(timeoutMs = 1_000) {
  const settled = Promise.allSettled([...wireShapeTasks]);
  await Promise.race([settled, delay(timeoutMs)]);
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
  if (!collectingDiagnostics
    && label !== 'chrome cleanup'
    && label !== 'RP cleanup'
    && label !== 'account cleanup'
    && label !== 'temporary workspace cleanup') return;
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
  console.log('\n=== Website Passkey E2E ===');
  console.log('phase:', phase);
  console.log('account cleanup:', cleanupResult);
  console.log('create:', typeof createDiagnostic === 'string' ? createDiagnostic : JSON.stringify(createDiagnostic));
  console.log('get:', typeof getDiagnostic === 'string' ? getDiagnostic : JSON.stringify(getDiagnostic));
  console.log('duplicate:', typeof duplicateDiagnostic === 'string' ? duplicateDiagnostic : JSON.stringify(duplicateDiagnostic));
  console.log('vault:', typeof vaultDiagnostic === 'string' ? vaultDiagnostic : JSON.stringify(vaultDiagnostic));
  console.log('wire shapes:', JSON.stringify(
    phase === 'complete' ? compactWireShapeReport() : wireShapeDiagnostics.slice(-8),
  ));
  console.log('page/worker errors:', issues.length);
  for (const issue of issues.slice(0, 10)) console.log('  -', redact(issue));
  console.log('relevant failed requests:', failedRequests.length);
  for (const failure of failedRequests.slice(0, 10)) console.log('  -', redact(failure));
  console.log('artifacts:', OUTPUT_DIR);
}

function compactWireShapeReport() {
  const create = wireShapeDiagnostics.find((entry) => entry.route === 'createCipher');
  const synced = wireShapeDiagnostics.findLast((entry) => entry.route === 'sync' && entry.cipher);
  return {
    createResponses: wireShapeDiagnostics.filter((entry) => entry.route === 'createCipher').length,
    syncResponses: wireShapeDiagnostics.filter((entry) => entry.route === 'sync').length,
    requestCreationDate: create?.requestCipher?.login?.fido2Credentials?.creationDate,
    responseCreationDate: create?.cipher?.login?.fido2Credentials?.creationDate,
    syncCreationDate: synced?.cipher?.login?.fido2Credentials?.creationDate,
    redundantDataObserved: create?.cipher?.data?.fido2Credentials?.present === true
      && synced?.cipher?.data?.fido2Credentials?.present === true,
  };
}

await main();
