import { describe, expect, it, vi } from 'vitest';
import {
  WEBSITE_PASSKEY_PORT_NAME,
  WEBSITE_PASSKEY_PORT_VERSION,
  canonicalizeWebsitePasskeyRequest,
  createWebsitePasskeyPreflightOutcomeMessage,
  parseWebsitePasskeyServerMessage,
  type CanonicalWebsitePasskeyGetRequest,
  type WebsitePasskeyOutcomeMessage,
  type WebsitePasskeyServerMessage,
} from '../messaging/website-passkey-port.js';
import {
  WebsitePasskeyPortHandler,
  type WebsitePasskeyPortEvent,
  type WebsitePasskeyPortLike,
} from './website-passkey-port-handler.js';
import type {
  WebsitePasskeyDocumentConnection,
  WebsitePasskeyDocumentContext,
} from './website-passkey-coordinator.js';
import type { MessageSenderInfo } from './sender-guard.js';

const BRIDGE_A = '10000000-0000-4000-8000-000000000001';
const BRIDGE_B = '10000000-0000-4000-8000-000000000002';

class TestEvent<Listener extends (...args: never[]) => void> implements WebsitePasskeyPortEvent<Listener> {
  readonly listeners = new Set<Listener>();
  addListener(listener: Listener): void { this.listeners.add(listener); }
  removeListener(listener: Listener): void { this.listeners.delete(listener); }
  emit(...args: Parameters<Listener>): void {
    for (const listener of [...this.listeners]) listener(...args);
  }
}

class TestPort implements WebsitePasskeyPortLike {
  readonly onMessage = new TestEvent<(message: unknown) => void>();
  readonly onDisconnect = new TestEvent<() => void>();
  readonly posted: WebsitePasskeyServerMessage[] = [];
  readonly disconnect = vi.fn();

  constructor(
    readonly name = WEBSITE_PASSKEY_PORT_NAME,
    readonly sender: MessageSenderInfo = trustedSender(),
  ) {}

  postMessage(message: WebsitePasskeyServerMessage): void {
    this.posted.push(parseWebsitePasskeyServerMessage(message));
  }
}

function trustedSender() {
  return {
    id: 'extension-id',
    url: 'https://login.example.com/path',
    origin: 'https://login.example.com',
    frameId: 0,
    documentId: 'doc-A',
    tab: { id: 7 },
  };
}

function request(overrides: Partial<CanonicalWebsitePasskeyGetRequest> = {}): CanonicalWebsitePasskeyGetRequest {
  return canonicalizeWebsitePasskeyRequest({
    bridgeRequestId: BRIDGE_A,
    kind: 'get',
    rpId: 'example.com',
    challenge: 'Y2hhbGxlbmdl',
    allowCredentials: [],
    timeout: 30_000,
    ...overrides,
  }) as CanonicalWebsitePasskeyGetRequest;
}

const CEREMONY_ID = '00000000-0000-4000-8000-000000000001';
const OUTCOME_ID = '00000000-0000-4000-8000-000000000002';

function accepted(
  bridgeRequestId = BRIDGE_A,
): Extract<WebsitePasskeyServerMessage, { type: 'accepted' }> {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'accepted',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    deadlineAt: 31_000,
  };
}

function unlockPending(
  bridgeRequestId = BRIDGE_A,
): Extract<WebsitePasskeyServerMessage, { type: 'unlockPending' }> {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'unlockPending',
    continuationId: CEREMONY_ID,
    bridgeRequestId,
    deadlineAt: 31_000,
  };
}

function conditionalActive(bridgeRequestId = BRIDGE_A): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'conditionalActive',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    deadlineAt: 31_000,
    candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work', username: 'alice' }],
  };
}

function fallback(bridgeRequestId = BRIDGE_A): WebsitePasskeyOutcomeMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    outcomeId: OUTCOME_ID,
    outcome: { status: 'fallback', reason: 'no_match' },
  };
}

function success(bridgeRequestId = BRIDGE_A): WebsitePasskeyOutcomeMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    outcomeId: OUTCOME_ID,
    outcome: {
      status: 'success',
      result: {
        kind: 'get',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credentialId: 'Y3JlZGVudGlhbA',
        authenticatorData: 'YXV0aA',
        clientDataJSON: 'Y2xpZW50',
        signature: 'c2ln',
      },
    },
  };
}

function makeHarness(options: {
  enabled?: boolean;
  begin?: WebsitePasskeyDocumentConnection['begin'];
  now?: () => number;
  onDocumentDisconnected?: (document: WebsitePasskeyDocumentContext) => void | Promise<void>;
  vaultReleaseGate?: {
    capture: ReturnType<typeof vi.fn>;
    checkpoint: ReturnType<typeof vi.fn>;
    assertAuthorities: ReturnType<typeof vi.fn>;
    assert: ReturnType<typeof vi.fn>;
  };
} = {}) {
  let deliver!: (
    message: Exclude<WebsitePasskeyServerMessage, { type: 'config' }>,
    assertCurrent?: () => void,
  ) => void | Promise<void>;
  let document!: WebsitePasskeyDocumentContext;
  const connection: WebsitePasskeyDocumentConnection = {
    getConfig: vi.fn(async () => options.enabled ?? true),
    begin: vi.fn(options.begin ?? (async (value) => accepted(value.bridgeRequestId))) as WebsitePasskeyDocumentConnection['begin'],
    resume: vi.fn(async () => undefined),
    selectConditional: vi.fn(async () => true),
    cancel: vi.fn(async () => {}),
    acknowledge: vi.fn(async () => true),
    close: vi.fn(),
  };
  const coordinator = {
    connect: vi.fn((
      value: WebsitePasskeyDocumentContext,
      sink: (
        message: WebsitePasskeyOutcomeMessage,
        assertCurrent?: () => void,
      ) => void | Promise<void>,
      controlSink?: (
        message: Exclude<WebsitePasskeyServerMessage,
          { type: 'config' } | WebsitePasskeyOutcomeMessage>,
      ) => void | Promise<void>,
    ) => {
      document = value;
      deliver = (message, assertCurrent) => message.type === 'outcome'
        ? sink(message, assertCurrent)
        : controlSink?.(message);
      return connection;
    }),
  };
  const handler = new WebsitePasskeyPortHandler(
    coordinator as never,
    Promise.resolve(),
    options.now ?? Date.now,
    options.onDocumentDisconnected,
    options.vaultReleaseGate as never,
  );
  return { connection, coordinator, handler, get deliver() { return deliver; }, get document() { return document; } };
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  const promise = new Promise<Value>((done) => { resolve = done; });
  return { promise, resolve };
}

async function configure(port: TestPort): Promise<void> {
  port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' });
  await flush();
  port.posted.length = 0;
}

describe('WebsitePasskeyPortHandler sender boundary', () => {
  it('accepts only the exact port name and complete browser-owned HTTPS document metadata', () => {
    const harness = makeHarness();
    const trusted = new TestPort();
    expect(harness.handler.handle(trusted, 'chrome-extension://extension-id/', 'extension-id')).toBe(true);
    expect(harness.document).toEqual({
      tabId: 7,
      frameId: 0,
      documentId: 'doc-A',
      url: 'https://login.example.com/path',
      origin: 'https://login.example.com',
    });

    for (const port of [
      new TestPort('wrong-name'),
      new TestPort(WEBSITE_PASSKEY_PORT_NAME, { ...trustedSender(), id: 'other-extension' }),
      new TestPort(WEBSITE_PASSKEY_PORT_NAME, { ...trustedSender(), documentId: '' }),
      new TestPort(WEBSITE_PASSKEY_PORT_NAME, { ...trustedSender(), origin: 'https://other.example' }),
      new TestPort(WEBSITE_PASSKEY_PORT_NAME, {
        ...trustedSender(), url: 'http://remote.example/path', origin: 'http://remote.example',
      }),
    ]) {
      expect(makeHarness().handler.handle(port, 'chrome-extension://extension-id/', 'extension-id')).toBe(false);
      expect(port.disconnect).toHaveBeenCalledOnce();
    }
  });

  it('preserves a browser-owned same-origin subframe id in the coordinator context', () => {
    const harness = makeHarness();
    const port = new TestPort(WEBSITE_PASSKEY_PORT_NAME, {
      ...trustedSender(),
      frameId: 7,
      documentId: 'subframe-document',
    });

    expect(harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id')).toBe(true);
    expect(harness.document).toMatchObject({ frameId: 7, documentId: 'subframe-document' });
  });

  it('reports the exact browser document after Port disconnect for removal revalidation', async () => {
    const disconnected = vi.fn(async () => {});
    const harness = makeHarness({ onDocumentDisconnected: disconnected });
    const port = new TestPort(WEBSITE_PASSKEY_PORT_NAME, {
      ...trustedSender(),
      frameId: 3,
      documentId: 'removed-frame-document',
    });
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');

    port.onDisconnect.emit();
    await flush();

    expect(disconnected).toHaveBeenCalledWith(expect.objectContaining({
      tabId: 7,
      frameId: 3,
      documentId: 'removed-frame-document',
    }));
    expect(harness.connection.close).toHaveBeenCalledOnce();
  });

  it('allows explicit loopback HTTP origins', () => {
    for (const origin of ['http://localhost:8080', 'http://127.5.6.7', 'http://[::1]:8080']) {
      const port = new TestPort(WEBSITE_PASSKEY_PORT_NAME, {
        ...trustedSender(), url: `${origin}/login`, origin,
      });
      expect(makeHarness().handler.handle(port, 'chrome-extension://extension-id/', 'extension-id')).toBe(true);
    }
  });
});

describe('WebsitePasskeyPortHandler locked continuation release boundary', () => {
  it('binds unlock pending without an unlocked release lease, then captures one on promotion', async () => {
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ generation: 1 })),
      checkpoint: vi.fn(async () => ({ generation: 1 })),
      assertAuthorities: vi.fn(),
      assert: vi.fn(),
    };
    const harness = makeHarness({
      begin: async () => unlockPending(),
      vaultReleaseGate,
      now: () => 1_000,
    });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request(),
    });
    await flush();
    expect(port.posted.at(-1)).toEqual(unlockPending());
    expect(vaultReleaseGate.capture).not.toHaveBeenCalled();

    await harness.deliver(accepted());
    expect(vaultReleaseGate.capture).toHaveBeenCalledOnce();
    expect(port.posted.at(-1)).toEqual(accepted());
    expect(port.disconnect).not.toHaveBeenCalled();
  });

  it('routes an exact cancel to the locked continuation id', async () => {
    const harness = makeHarness({ begin: async () => unlockPending(), now: () => 1_000 });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: 1, type: 'begin', request: request() });
    await flush();

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
    });
    await flush();
    expect(harness.connection.cancel).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_A);
  });
});

describe('WebsitePasskeyPortHandler protocol binding', () => {
  it('runs the retained security assertion immediately before posting a successful outcome', async () => {
    const harness = makeHarness();
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    const assertCurrent = vi.fn(() => { throw new Error('session timed out'); });

    await expect(harness.deliver(success(), assertCurrent)).rejects.toThrow('session timed out');

    expect(assertCurrent).toHaveBeenCalledOnce();
    expect(port.posted).toEqual([accepted()]);
    expect(port.disconnect).toHaveBeenCalledOnce();
  });

  it('withholds a successful outcome when its durable release checkpoint fails', async () => {
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(async () => { throw new Error('checkpoint unavailable'); }),
      assertAuthorities: vi.fn((_proof: unknown, assertCurrent: () => void) => assertCurrent()),
      assert: vi.fn(),
      settlePendingAction: vi.fn(async () => undefined),
    };
    const harness = makeHarness({ vaultReleaseGate });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();

    await expect(harness.deliver(success(), vi.fn())).rejects.toThrow('checkpoint unavailable');

    expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    expect(port.posted).toEqual([accepted()]);
    expect(port.disconnect).toHaveBeenCalledOnce();
  });

  it('rechecks the original passkey security proof after the checkpoint await', async () => {
    const pending = deferred<object>();
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(() => pending.promise),
      assertAuthorities: vi.fn((_proof: object, assertCurrent: () => void) => assertCurrent()),
      assert: vi.fn(),
    };
    const harness = makeHarness({ vaultReleaseGate });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    let revoked = false;
    const assertCurrent = vi.fn(() => {
      if (revoked) throw new Error('security proof revoked');
    });
    const delivery = harness.deliver(success(), assertCurrent);
    await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
    revoked = true;
    pending.resolve({});

    await expect(delivery).rejects.toThrow('security proof revoked');
    expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    expect(port.posted).toEqual([accepted()]);
  });

  it('returns config false without disconnecting the document port', async () => {
    const harness = makeHarness({ enabled: false });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' });
    await flush();
    expect(port.posted).toEqual([{ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false }]);
    expect(port.disconnect).not.toHaveBeenCalled();
    expect(port.onMessage.listeners.size).toBe(1);
  });

  it('keeps existing cancel, terminal delivery, and ACK usable after config turns false', async () => {
    const harness = makeHarness();
    vi.mocked(harness.connection.getConfig)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' });
    await flush();
    expect(port.posted.at(-1)).toEqual({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false });

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
    });
    await flush();
    expect(harness.connection.cancel).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_A);
    harness.deliver(fallback());
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      outcomeId: OUTCOME_ID,
    });
    await flush();
    expect(harness.connection.acknowledge).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_A, OUTCOME_ID);
    expect(port.disconnect).not.toHaveBeenCalled();
  });

  it('resumes an accepted request after reconnect while disabled without admitting a new begin', async () => {
    const harness = makeHarness();
    vi.mocked(harness.connection.getConfig)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    vi.mocked(harness.connection.resume).mockResolvedValue(fallback());

    const first = new TestPort();
    harness.handler.handle(first, 'chrome-extension://extension-id/', 'extension-id');
    await configure(first);
    first.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    first.onDisconnect.emit();

    const second = new TestPort();
    harness.handler.handle(second, 'chrome-extension://extension-id/', 'extension-id');
    second.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' });
    await flush();
    expect(second.posted.at(-1)).toEqual({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false });
    second.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'resume', request: request() });
    await flush();
    expect(harness.connection.resume).toHaveBeenCalledWith(request());
    expect(second.posted.at(-1)).toEqual(fallback());

    second.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      outcomeId: OUTCOME_ID,
    });
    await flush();
    second.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request({ bridgeRequestId: BRIDGE_B, challenge: 'b3RoZXI' }),
    });
    await flush();
    expect(harness.connection.begin).toHaveBeenCalledOnce();
    expect(second.posted.at(-1)).toEqual(createWebsitePasskeyPreflightOutcomeMessage(BRIDGE_B, 'busy'));
    expect(second.disconnect).not.toHaveBeenCalled();
  });

  it('strictly parses begin, binds one canonical request, and permits an idempotent duplicate', async () => {
    const harness = makeHarness();
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    const begin = { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() };
    port.onMessage.emit(begin);
    await flush();
    port.onMessage.emit(begin);
    await flush();
    expect(harness.connection.begin).toHaveBeenCalledTimes(2);
    expect(port.posted).toEqual([accepted(), accepted()]);
  });

  it('dispatches conditional mediation as an accepted begin without an unsupported reason', async () => {
    const harness = makeHarness({ begin: async () => conditionalActive() });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    const conditional = request({ mediation: 'conditional' });

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: conditional,
    });
    await flush();

    expect(harness.connection.begin).toHaveBeenCalledWith(
      conditional,
      undefined,
      expect.any(Number),
    );
    expect(port.posted).toEqual([conditionalActive()]);
    expect(port.disconnect).not.toHaveBeenCalled();
  });

  it('accepts a conditional selection only after the exact active binding is established', async () => {
    const harness = makeHarness({ begin: async () => conditionalActive() });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request({ mediation: 'conditional' }),
    });
    await flush();

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'conditionalSelect',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      credentialId: 'Y3JlZGVudGlhbA',
    });
    await flush();

    expect(harness.connection.selectConditional).toHaveBeenCalledWith(
      CEREMONY_ID,
      BRIDGE_A,
      'Y3JlZGVudGlhbA',
    );
    expect(port.disconnect).not.toHaveBeenCalled();
  });

  it('binds and ACKs a durable terminal outcome even when it is the first begin response', async () => {
    const harness = makeHarness({ begin: async () => fallback() });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    expect(port.posted).toEqual([fallback()]);
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      outcomeId: OUTCOME_ID,
    });
    await flush();
    expect(harness.connection.acknowledge).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_A, OUTCOME_ID);
    expect(port.disconnect).not.toHaveBeenCalled();
  });

  it('keeps one document port alive when a second request receives busy preflight', async () => {
    const begin = vi.fn<WebsitePasskeyDocumentConnection['begin']>(async (value) => (
      value.bridgeRequestId === BRIDGE_A
        ? accepted(BRIDGE_A)
        : createWebsitePasskeyPreflightOutcomeMessage(value.bridgeRequestId, 'busy')
    ));
    const harness = makeHarness({ begin });
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request({ bridgeRequestId: BRIDGE_B, challenge: 'b3RoZXI' }),
    });
    await flush();
    await flush();

    expect(port.posted).toEqual([
      accepted(BRIDGE_A),
      createWebsitePasskeyPreflightOutcomeMessage(BRIDGE_B, 'busy'),
    ]);
    expect(port.disconnect).not.toHaveBeenCalled();
    expect(port.onMessage.listeners.size).toBe(1);
  });

  it('does not let a slow begin block cancellation of an already accepted request', async () => {
    const slow = new Promise<WebsitePasskeyServerMessage>(() => {});
    const harness = makeHarness();
    vi.mocked(harness.connection.begin)
      .mockResolvedValueOnce(accepted(BRIDGE_A))
      .mockReturnValueOnce(slow);
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request({ bridgeRequestId: BRIDGE_B, challenge: 'b3RoZXI' }),
    });
    await vi.waitFor(() => expect(harness.connection.begin).toHaveBeenCalledTimes(2));
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
    });
    await flush();
    expect(harness.connection.cancel).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_A);
  });

  it('freezes each request deadline when the message enters the port queue', async () => {
    const now = { value: 1_000 };
    const first = deferred<WebsitePasskeyServerMessage>();
    const harness = makeHarness({ now: () => now.value });
    vi.mocked(harness.connection.begin)
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce(accepted(BRIDGE_B));
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);

    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await vi.waitFor(() => expect(harness.connection.begin).toHaveBeenCalledOnce());
    now.value = 2_000;
    const secondRequest = request({ bridgeRequestId: BRIDGE_B, challenge: 'b3RoZXI' });
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: secondRequest });
    now.value = 100_000;
    first.resolve(accepted(BRIDGE_A));

    await vi.waitFor(() => expect(harness.connection.begin).toHaveBeenCalledTimes(2));
    expect(harness.connection.begin).toHaveBeenNthCalledWith(1, request(), undefined, 31_000);
    expect(harness.connection.begin).toHaveBeenNthCalledWith(2, secondRequest, undefined, 32_000);
  });

  it('disconnects instead of disguising resume storage failures as a business outcome', async () => {
    const harness = makeHarness();
    vi.mocked(harness.connection.resume).mockRejectedValue(new Error('storage unavailable'));
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);

    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'resume', request: request() });
    await flush();

    expect(port.posted).toEqual([]);
    expect(port.disconnect).toHaveBeenCalledOnce();
  });

  it('disconnects on cancel or ACK persistence failures so the exact request can reconnect', async () => {
    for (const operation of ['cancel', 'ack'] as const) {
      const harness = makeHarness();
      const port = new TestPort();
      harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
      await configure(port);
      port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
      await flush();
      if (operation === 'cancel') {
        vi.mocked(harness.connection.cancel).mockRejectedValue(new Error('storage unavailable'));
        port.onMessage.emit({
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: 'cancel',
          ceremonyId: CEREMONY_ID,
          bridgeRequestId: BRIDGE_A,
        });
      } else {
        harness.deliver(fallback());
        vi.mocked(harness.connection.acknowledge).mockRejectedValue(new Error('storage unavailable'));
        port.onMessage.emit({
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: 'ack',
          ceremonyId: CEREMONY_ID,
          bridgeRequestId: BRIDGE_A,
          outcomeId: OUTCOME_ID,
        });
      }
      await flush();
      expect(port.disconnect, operation).toHaveBeenCalledOnce();
    }
  });

  it('drops a late resume result after an exact ACK removes its binding', async () => {
    const pending = deferred<WebsitePasskeyServerMessage | undefined>();
    const harness = makeHarness();
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    harness.deliver(fallback());
    vi.mocked(harness.connection.resume).mockReturnValue(pending.promise);
    const postedBeforeResume = port.posted.length;

    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'resume', request: request() });
    await vi.waitFor(() => expect(harness.connection.resume).toHaveBeenCalledOnce());
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      outcomeId: OUTCOME_ID,
    });
    await flush();
    pending.resolve(fallback());
    await flush();

    expect(port.posted).toHaveLength(postedBeforeResume);
    expect(port.disconnect).not.toHaveBeenCalled();
  });

  it('disconnects on malformed messages or an attempted bridge/request swap', async () => {
    const malformed = new TestPort();
    makeHarness().handler.handle(malformed, 'chrome-extension://extension-id/', 'extension-id');
    malformed.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello', extra: true });
    expect(malformed.disconnect).toHaveBeenCalledOnce();

    const harness = makeHarness();
    const swapped = new TestPort();
    harness.handler.handle(swapped, 'chrome-extension://extension-id/', 'extension-id');
    await configure(swapped);
    swapped.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    swapped.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: request({ bridgeRequestId: BRIDGE_A, challenge: 'b3RoZXI' }),
    });
    await flush();
    expect(swapped.disconnect).toHaveBeenCalledOnce();
    expect(harness.connection.begin).toHaveBeenCalledOnce();
  });

  it('accepts only the exact delivered outcome ACK and never treats disconnect as ACK', async () => {
    const harness = makeHarness();
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    harness.deliver(fallback());
    expect(port.posted.at(-1)).toEqual(fallback());

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      outcomeId: OUTCOME_ID,
    });
    await flush();
    expect(harness.connection.acknowledge).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_A, OUTCOME_ID);
    expect(port.disconnect).not.toHaveBeenCalled();

    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_A,
      outcomeId: OUTCOME_ID,
    });
    await flush();
    expect(harness.connection.acknowledge).toHaveBeenCalledOnce();
    expect(port.disconnect).not.toHaveBeenCalled();

    const next = request({ bridgeRequestId: BRIDGE_B, challenge: 'b3RoZXI' });
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: next });
    await flush();
    expect(harness.connection.begin).toHaveBeenCalledTimes(2);
    expect(port.posted.at(-1)).toEqual(accepted(BRIDGE_B));

    const reconnect = makeHarness();
    const disconnected = new TestPort();
    reconnect.handler.handle(disconnected, 'chrome-extension://extension-id/', 'extension-id');
    disconnected.onDisconnect.emit();
    expect(reconnect.connection.close).toHaveBeenCalledOnce();
    expect(reconnect.connection.acknowledge).not.toHaveBeenCalled();
    expect(reconnect.connection.cancel).not.toHaveBeenCalled();
  });

  it('disconnects on a forged cancel or outcome ACK without invoking coordinator state changes', async () => {
    const harness = makeHarness();
    const port = new TestPort();
    harness.handler.handle(port, 'chrome-extension://extension-id/', 'extension-id');
    await configure(port);
    port.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    port.onMessage.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: '00000000-0000-4000-8000-000000000099',
      bridgeRequestId: BRIDGE_A,
    });
    await flush();
    expect(port.disconnect).toHaveBeenCalledOnce();
    expect(harness.connection.cancel).not.toHaveBeenCalled();
  });

  it('drops a late outcome from a superseded connection and delivers it only to the reconnect', async () => {
    const harness = makeHarness();
    const first = new TestPort();
    const second = new TestPort();
    harness.handler.handle(first, 'chrome-extension://extension-id/', 'extension-id');
    await configure(first);
    first.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    harness.handler.handle(second, 'chrome-extension://extension-id/', 'extension-id');
    await configure(second);
    second.onMessage.emit({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: request() });
    await flush();
    harness.deliver(fallback());
    expect(first.posted).toEqual([accepted()]);
    expect(second.posted.at(-1)).toEqual(fallback());
  });
});
