// Run only in an authorized verification environment. On Linux, use xvfb-run for headed Chromium.
// This builds an isolated extension from production transport modules and loads it into a fresh
// profile. Synthetic bytes never contact a backend, a user's vault, or an existing browser profile.
import { chromium } from '@playwright/test';
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fillPayload } from './binary-transport-browser/payload.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runRoot = mkdtempSync(join(tmpdir(), 'miyu-binary-transport-browser-'));
const extensionPath = join(runRoot, 'extension');
const browserExecutable = process.env.MIYU_BROWSER_EXECUTABLE;
const MIB = 1024 * 1024;
const LARGE_BYTES = 100 * MIB;
const ATTACHMENT_BYTES = 65 * MIB + 7;
const CHUNK_BYTES = 256 * 1024;
const SMALL_BYTES = CHUNK_BYTES * 3 + 7;
const errors = [];
let context;

try {
  mkdirSync(join(extensionPath, 'ui', 'popup'), { recursive: true });
  // Omit message_serialization so Chrome exercises its default JSON message transport.
  writeFileSync(join(extensionPath, 'manifest.json'), JSON.stringify({
    manifest_version: 3,
    name: 'MiYu isolated binary transport verification',
    version: '1.0.0',
    permissions: ['storage', 'alarms'],
    background: { service_worker: 'worker.js', type: 'module' },
    action: { default_popup: 'ui/popup/popup.html' },
  }, null, 2));
  writeFileSync(join(extensionPath, 'ui', 'popup', 'popup.html'),
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Binary transport verification</title></head>'
    + '<body><p>Isolated synthetic binary transport verification.</p><script type="module" src="../../page.js"></script></body></html>');
  await build({
    entryPoints: {
      worker: join(root, 'tools', 'binary-transport-browser', 'worker.mjs'),
      page: join(root, 'tools', 'binary-transport-browser', 'page.mjs'),
    },
    outdir: extensionPath,
    bundle: true,
    platform: 'browser',
    format: 'esm',
    target: 'chrome124',
    logLevel: 'warning',
  });
  context = await chromium.launchPersistentContext(join(runRoot, 'chrome-profile'), {
    ...(browserExecutable ? { executablePath: browserExecutable } : {}),
    headless: false,
    ignoreDefaultArgs: ['--disable-extensions'],
    args: [
      '--enable-unsafe-extension-debugging',
      '--no-first-run',
      '--no-default-browser-check',
      ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
    ],
  });
  context.on('weberror', (event) => errors.push(`browser: ${event.error()}`));
  const extensionId = await loadUnpackedExtension(context, extensionPath);
  const worker = context.serviceWorkers().find((candidate) => new URL(candidate.url()).host === extensionId)
    ?? await context.waitForEvent('serviceworker', {
      predicate: (candidate) => new URL(candidate.url()).host === extensionId,
      timeout: 15_000,
    });
  worker.on('console', (message) => {
    if (message.type() === 'error') errors.push(`worker: ${message.text()}`);
  });
  await deadline(worker.evaluate(async () => {
    const stopAt = Date.now() + 15_000;
    while (!globalThis.binaryTransportWorker) {
      if (Date.now() >= stopAt) throw new Error('The isolated worker did not initialize');
      await new Promise((done) => setTimeout(done, 25));
    }
    await globalThis.binaryTransportWorker.ready();
  }), 30_000);
  const page = await context.newPage();
  page.on('pageerror', (error) => errors.push(`page: ${error}`));
  await page.goto(`chrome-extension://${extensionId}/ui/popup/popup.html`);
  await page.waitForFunction(() => Boolean(globalThis.binaryTransportPage));
  console.log('browser:', context.browser()?.version() ?? 'unknown');
  console.log('transport: native Chrome runtime Port with JSON serialization');

  for (const [kind, size, expectedType] of [
    ['send', LARGE_BYTES, 'sends.createFile'],
    ['attachment', ATTACHMENT_BYTES, 'vault.addAttachment'],
  ]) {
    await worker.evaluate(() => globalThis.binaryTransportWorker.reset());
    const uploaded = await deadline(page.evaluate((input) => globalThis.binaryTransportPage.upload(input), { kind, size }));
    const snapshot = await closedSnapshot(worker);
    assert(uploaded.result.ok, `${kind} upload failed: ${JSON.stringify(uploaded.result)}`);
    assert(snapshot.uploadDigest === expectedDigest(size), `${kind} upload bytes were corrupted`);
    assert(snapshot.uploadBytes === size && snapshot.receivedUploadBytes === size, `${kind} upload size did not match`);
    assert(snapshot.executions.length === 1 && snapshot.executions[0] === expectedType, `${kind} upload did not use production dispatch`);
    assert(snapshot.uploadChunks === Math.ceil(size / CHUNK_BYTES), `${kind} upload chunk count did not match`);
    assert(snapshot.uploadChunks === snapshot.uploadAcks && uploaded.uploadChunks === uploaded.uploadAcks,
      `${kind} upload did not acknowledge every chunk`);
    assert(uploaded.maxPendingUploadChunks === 1, `${kind} client sent a chunk before receiving the prior ACK`);
    assert(snapshot.results === 1 && snapshot.retainedBufferCount === 1 && snapshot.retainedBuffersWiped,
      `${kind} upload did not complete and erase its worker buffer`);
    assertTransport(snapshot);
    console.log(`${kind} upload: PASS (${size} bytes, ${snapshot.uploadChunks} chunks, SHA-256 ${snapshot.uploadDigest})`);
  }

  await worker.evaluate((size) => globalThis.binaryTransportWorker.reset(size), LARGE_BYTES);
  const downloaded = await deadline(page.evaluate(() => globalThis.binaryTransportPage.download()));
  const downloadSnapshot = await closedSnapshot(worker);
  assert(downloaded.result.ok, `Download failed: ${JSON.stringify(downloaded.result)}`);
  assert(downloaded.result.byteLength === LARGE_BYTES && downloaded.result.sha256 === expectedDigest(LARGE_BYTES),
    'Downloaded Blob bytes did not match the original payload');
  assert(downloaded.result.fileName === 'synthetic-download.bin', 'Download filename was lost');
  assert(downloadSnapshot.downloadChunks === Math.ceil(LARGE_BYTES / CHUNK_BYTES)
    && downloadSnapshot.downloadAcks === downloadSnapshot.downloadChunks
    && downloadSnapshot.sentDownloadBytes === LARGE_BYTES, 'Download chunk/ACK accounting did not match');
  assert(downloadSnapshot.maxPendingDownloadChunks === 1, 'Worker emitted more than one unacknowledged download chunk');
  assert(downloadSnapshot.done === 1 && downloadSnapshot.retainedBuffersWiped, 'Download completion did not erase the worker buffer');
  assertTransport(downloadSnapshot);
  console.log(`attachment download: PASS (${LARGE_BYTES} bytes, ${downloadSnapshot.downloadChunks} chunks, SHA-256 ${downloaded.result.sha256})`);

  await worker.evaluate((size) => globalThis.binaryTransportWorker.reset(size), SMALL_BYTES);
  await page.evaluate(() => globalThis.binaryTransportPage.startRawDownload());
  await page.waitForFunction(() => globalThis.binaryTransportPage.rawSnapshot().chunks.length === 1);
  await page.waitForTimeout(300);
  const stalled = await worker.evaluate(() => globalThis.binaryTransportWorker.snapshot());
  assert(stalled.downloadChunks === 1 && stalled.downloadAcks === 0 && stalled.done === 0,
    'Worker advanced while the first native Port ACK was withheld');
  await page.evaluate(() => globalThis.binaryTransportPage.acknowledge(0));
  await page.waitForFunction(() => globalThis.binaryTransportPage.rawSnapshot().chunks.length === 2);
  await page.waitForTimeout(300);
  const resumed = await worker.evaluate(() => globalThis.binaryTransportWorker.snapshot());
  assert(resumed.downloadChunks === 2 && resumed.downloadAcks === 1 && resumed.maxPendingDownloadChunks === 1,
    'One native ACK did not release exactly one further chunk');
  await page.evaluate(() => globalThis.binaryTransportPage.cancelRaw());
  await page.waitForFunction(() => globalThis.binaryTransportPage.rawSnapshot().disconnected);
  const cancelled = await closedSnapshot(worker);
  assert(cancelled.cancellations === 1 && cancelled.downloadChunks === 2 && cancelled.done === 0
    && cancelled.retainedBuffersWiped, 'Protocol cancellation released more data or retained the download buffer');
  console.log('native ACK backpressure and download cancellation: PASS');

  await worker.evaluate(() => globalThis.binaryTransportWorker.reset());
  const cancelledUpload = await page.evaluate((size) => globalThis.binaryTransportPage.upload({
    kind: 'send', size, cancelAfterAck: true,
  }), SMALL_BYTES);
  const cancelledUploadSnapshot = await closedSnapshot(worker);
  assert(!cancelledUpload.result.ok && cancelledUpload.result.error.code === 'cancelled', 'Upload abort did not reach the production client');
  assert(cancelledUploadSnapshot.uploadChunks === 1 && cancelledUploadSnapshot.executions.length === 0
    && cancelledUploadSnapshot.results === 0, 'Cancelled upload reached the backend or emitted more chunks');
  console.log('native upload cancellation before backend dispatch: PASS');

  await worker.evaluate((size) => globalThis.binaryTransportWorker.reset(size), SMALL_BYTES);
  await page.evaluate(() => globalThis.binaryTransportPage.startStalledDownload());
  await page.waitForFunction(() => globalThis.binaryTransportPage.clientSnapshot().heldAck === 0);
  await worker.evaluate(() => globalThis.binaryTransportWorker.lock());
  const lockedClient = await deadline(page.evaluate(() => globalThis.binaryTransportPage.finishStalledDownload()), 30_000);
  const lockedSnapshot = await closedSnapshot(worker);
  assert(!lockedClient.ok && lockedClient.error.code === 'locked', 'Session lock was not delivered to the production client');
  assert(lockedSnapshot.currentState === 'locked' && lockedSnapshot.downloadChunks === 1
    && lockedSnapshot.done === 0 && lockedSnapshot.retainedBuffersWiped, 'Session lock released further data or retained the download buffer');
  console.log('native session lock revocation and buffer cleanup: PASS');

  assert(errors.length === 0, `Browser errors: ${errors.join(' | ')}`);
  console.log('RESULT: PASS');
} finally {
  await context?.close().catch(() => undefined);
  removeTemporaryWorkspace(runRoot);
}

function expectedDigest(size) {
  const hash = createHash('sha256');
  for (let offset = 0; offset < size; offset += CHUNK_BYTES) {
    hash.update(fillPayload(new Uint8Array(Math.min(CHUNK_BYTES, size - offset)), offset));
  }
  return hash.digest('hex');
}

function assertTransport(snapshot) {
  assert(snapshot.acceptedConnections === 1 && snapshot.senderDocumentIds.every((id) => typeof id === 'string' && id.length > 0),
    'Transfer did not originate from a trusted Chrome extension document');
  assert(snapshot.maxInboundJsonBytes < 400_000 && snapshot.maxOutboundJsonBytes < 400_000,
    'A transfer message exceeded the bounded JSON chunk envelope');
}

async function closedSnapshot(worker) {
  const stopAt = Date.now() + 15_000;
  let snapshot;
  do {
    snapshot = await worker.evaluate(() => globalThis.binaryTransportWorker.snapshot());
    if (snapshot.openConnections === 0 && snapshot.retainedBuffersWiped) return snapshot;
    await new Promise((done) => setTimeout(done, 50));
  } while (Date.now() < stopAt);
  throw new Error(`Transfer did not close and clean up: ${JSON.stringify(snapshot)}`);
}

async function loadUnpackedExtension(browserContext, path) {
  const browser = browserContext.browser();
  if (!browser) throw new Error('Persistent Chrome did not expose a browser CDP connection');
  const session = await browser.newBrowserCDPSession();
  try {
    const loaded = await session.send('Extensions.loadUnpacked', { path, enableInIncognito: false });
    assert(typeof loaded?.id === 'string' && loaded.id.length > 0, 'Chrome did not return an extension id');
    return loaded.id;
  } finally {
    await session.detach().catch(() => undefined);
  }
}

async function deadline(promise, timeoutMs = 180_000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Browser transfer timed out')), timeoutMs); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function removeTemporaryWorkspace(path) {
  const resolvedPath = resolve(path);
  const temporaryRoot = `${resolve(tmpdir())}${sep}`;
  if (!resolvedPath.startsWith(temporaryRoot) || !resolvedPath.includes('miyu-binary-transport-browser-')) {
    throw new Error(`Refusing to remove unexpected browser workspace: ${resolvedPath}`);
  }
  rmSync(resolvedPath, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
