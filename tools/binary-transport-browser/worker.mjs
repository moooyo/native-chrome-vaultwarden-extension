// This isolated worker substitutes only synthetic vault operations and account data. All transport,
// lease gates, production dispatch, timeout persistence, and Chrome Port objects are real.
import browser from 'webextension-polyfill';
import { BinaryTransferPortHandler } from '../../src/background/binary-transfer-port-handler.ts';
import { createBinaryTransferProduction } from '../../src/background/binary-transfer-production.ts';
import { SessionGate } from '../../src/background/session-gate.ts';
import { VaultReleaseGate } from '../../src/background/vault-release-gate.ts';
import { VaultTimeoutController } from '../../src/background/vault-timeout-controller.ts';
import { VaultTimeoutStateStore } from '../../src/background/vault-timeout-state.ts';
import { resolveEffectiveVaultTimeout } from '../../src/background/vault-timeout-policy.ts';
import { EnterprisePolicyGate } from '../../src/core/policy/effective-enterprise-policy.ts';
import { AccountLeaseGate } from '../../src/core/session/account-gate.ts';
import { createBrowserStore } from '../../src/platform/store.ts';
import { BINARY_TRANSFER_PORT_NAME } from '../../src/messaging/binary-transfer-port.ts';
import { digestBytes, fillPayload } from './payload.mjs';

const SERVER_URL = 'https://binary-transport.invalid/';
const EMAIL = 'synthetic@binary-transport.invalid';
const session = new SessionGate('unlocked');
const account = new AccountLeaseGate();
const policy = new EnterprisePolicyGate();
const retainedBuffers = [];
const connections = new Set();
let currentState = 'unlocked';
let transitionId = 0;
let downloadSize = 0;
let stats = freshStats();

account.initialize({ serverUrl: SERVER_URL, accountIdentity: EMAIL });
policy.replace({
  accountLease: account.capture(),
  rawGeneration: 'synthetic-sync',
  response: { profile: { id: 'synthetic-account', email: EMAIL }, ciphers: [] },
});
const timeoutState = new VaultTimeoutStateStore({
  localStore: createBrowserStore('local'),
  sessionStore: createBrowserStore('session'),
});
const timeout = new VaultTimeoutController({
  state: timeoutState,
  alarms: browser.alarms,
  getContext: async () => ({
    state: currentState,
    accountKey: `${SERVER_URL}\n${EMAIL}`,
    email: EMAIL,
    sessionBindingId: 'synthetic-session',
  }),
  getConfig: async () => resolveEffectiveVaultTimeout('never', 'lock', { kind: 'available', policy: null }),
  applyAction: async () => { await transition('locked'); },
});
session.setPreflight(() => timeout.preflight());
const ready = (async () => {
  await timeoutState.initializeBrowserSession();
  await timeout.initialize();
})();

function bindFinalAuthority(bind, assertCurrent) {
  const sessionLease = session.capture();
  const accountLease = account.capture();
  const policyLease = policy.capture();
  assertCurrent();
  bind(() => {
    session.assert(sessionLease);
    account.assert(accountLease);
    policy.assert(policyLease);
  });
}

async function receiveUpload(kind, bytes, bind, assertCurrent) {
  stats.executions.push(kind);
  retainedBuffers.push(bytes);
  const sha256 = await digestBytes(bytes);
  bindFinalAuthority(bind, assertCurrent);
  stats.uploadDigest = sha256;
  stats.uploadBytes = bytes.byteLength;
  return { id: 'synthetic-result', sha256, byteLength: bytes.byteLength };
}

const production = createBinaryTransferProduction({
  sessionGate: session,
  accountGate: account,
  policyGate: policy,
  settings: { getServerUrl: async () => SERVER_URL },
  timeout,
  vault: {
    async createFileSendBytes(_input, bytes, _fileName, _serverUrl, bind, assertCurrent) {
      return receiveUpload('sends.createFile', bytes, bind, assertCurrent);
    },
    async addAttachmentBytes(_cipherId, _fileName, bytes, _password, bind, assertCurrent) {
      return receiveUpload('vault.addAttachment', bytes, bind, assertCurrent);
    },
    async getAttachmentBytes(_cipherId, _attachmentId, _password, bind, assertCurrent) {
      stats.executions.push('vault.getAttachment');
      const bytes = fillPayload(new Uint8Array(downloadSize));
      retainedBuffers.push(bytes);
      bindFinalAuthority(bind, assertCurrent);
      return { fileName: 'synthetic-download.bin', bytes };
    },
  },
});
const handler = new BinaryTransferPortHandler({
  ...production,
  ready,
  releaseGate: new VaultReleaseGate(timeout, session),
});

browser.runtime.onConnect.addListener((nativePort) => {
  if (nativePort.name !== BINARY_TRANSFER_PORT_NAME) return;
  const connection = {};
  connections.add(connection);
  const close = () => connections.delete(connection);
  nativePort.onDisconnect.addListener(close);
  nativePort.onMessage.addListener((message) => {
    stats.maxInboundJsonBytes = Math.max(stats.maxInboundJsonBytes, JSON.stringify(message).length);
    if (message.type === 'chunk') {
      stats.uploadChunks += 1;
      stats.receivedUploadBytes += message.byteLength;
    }
    if (message.type === 'ack') {
      stats.downloadAcks += 1;
      stats.pendingDownloadChunks -= 1;
    }
    if (message.type === 'cancel') stats.cancellations += 1;
  });
  // This observer forwards the original events and every message to an actual Chrome runtime Port.
  // It neither synthesizes messages nor changes delivery timing.
  const observedPort = {
    name: nativePort.name,
    sender: nativePort.sender,
    onMessage: nativePort.onMessage,
    onDisconnect: nativePort.onDisconnect,
    postMessage(message) {
      stats.maxOutboundJsonBytes = Math.max(stats.maxOutboundJsonBytes, JSON.stringify(message).length);
      if (message.type === 'chunk') {
        stats.downloadChunks += 1;
        stats.sentDownloadBytes += message.byteLength;
        stats.pendingDownloadChunks += 1;
        stats.maxPendingDownloadChunks = Math.max(stats.maxPendingDownloadChunks, stats.pendingDownloadChunks);
      }
      if (message.type === 'ack') stats.uploadAcks += 1;
      if (message.type === 'result') stats.results += 1;
      if (message.type === 'done') stats.done += 1;
      if (message.type === 'error') stats.errors.push(message.error.code);
      nativePort.postMessage(message);
    },
    disconnect() {
      close();
      nativePort.disconnect();
    },
  };
  const accepted = handler.handle(observedPort, browser.runtime.getURL(''), browser.runtime.id);
  stats.acceptedConnections += Number(accepted);
  stats.senderDocumentIds.push(nativePort.sender?.documentId ?? null);
});

async function transition(state) {
  const reason = state === 'unlocked' ? 'unlock' : 'lock';
  const id = ++transitionId;
  timeout.transitionStarted();
  session.handleTransition({ phase: 'start', transitionId: id, reason, identityChanged: false });
  handler.invalidateAll();
  currentState = state;
  session.handleTransition({
    phase: 'settled', transitionId: id, reason, identityChanged: false, state, succeeded: true,
  });
  await timeout.transitionSettled(true, state);
}

globalThis.binaryTransportWorker = {
  ready: () => ready,
  snapshot: () => ({
    ...stats,
    currentState,
    openConnections: connections.size,
    retainedBufferCount: retainedBuffers.length,
    retainedBuffersWiped: retainedBuffers.every((bytes) => bytes.every((value) => value === 0)),
  }),
  async reset(size = 0) {
    await ready;
    if (connections.size !== 0) throw new Error('Cannot reset while a transfer Port is still open.');
    if (retainedBuffers.some((bytes) => bytes.some((value) => value !== 0))) {
      throw new Error('A previous transfer retained plaintext bytes.');
    }
    retainedBuffers.length = 0;
    if (currentState !== 'unlocked') await transition('unlocked');
    downloadSize = size;
    stats = freshStats();
  },
  lock: () => transition('locked'),
};

function freshStats() {
  return {
    acceptedConnections: 0, senderDocumentIds: [], executions: [],
    uploadChunks: 0, uploadAcks: 0, receivedUploadBytes: 0, uploadBytes: 0, uploadDigest: null,
    downloadChunks: 0, downloadAcks: 0, sentDownloadBytes: 0,
    pendingDownloadChunks: 0, maxPendingDownloadChunks: 0,
    maxInboundJsonBytes: 0, maxOutboundJsonBytes: 0,
    results: 0, done: 0, cancellations: 0, errors: [],
  };
}
