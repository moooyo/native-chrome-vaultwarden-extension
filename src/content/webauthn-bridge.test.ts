// @vitest-environment happy-dom
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const browserMocks = vi.hoisted(() => ({
  connect: vi.fn(),
  sendMessage: vi.fn(),
}));

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: {
      connect: browserMocks.connect,
      sendMessage: browserMocks.sendMessage,
    },
  },
}));

import {
  WebsitePasskeyBridge,
  installWebsitePasskeyBridge,
  websitePasskeyBridge,
  type WebsitePasskeyPort,
  type WebsitePasskeyPortEvent,
  type WebsitePasskeyRuntimeResponse,
} from './webauthn-bridge.js';
import {
  installPageWebAuthnInterception,
  pageWebAuthnController,
} from './page-webauthn.js';
import {
  WEBSITE_PASSKEY_BRIDGE_SOURCE,
  WEBSITE_PASSKEY_PAGE_SOURCE,
  WEBSITE_PASSKEY_WINDOW_VERSION,
} from './website-passkey-feature.js';
import type {
  WebsitePasskeyConditionalUi,
  WebsitePasskeyConditionalUiBinding,
} from './conditional-passkey-ui.js';
import {
  WEBSITE_PASSKEY_PORT_NAME,
  WEBSITE_PASSKEY_PORT_VERSION,
  WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE,
  parseWebsitePasskeyConfigChangedAck,
  type CanonicalWebsitePasskeyGetRequest,
  type CanonicalWebsitePasskeyCreateRequest,
  type WebsitePasskeyClientMessage,
  type WebsitePasskeyServerMessage,
} from '../messaging/website-passkey-port.js';
import {
  parseWebsitePasskeyFeaturePolicyProbeResponse,
  WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
  WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
} from '../messaging/website-passkey-feature-policy.js';

const ORIGIN = 'https://login.example.com';
const BRIDGE_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CEREMONY_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OUTCOME_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

class FakeEvent<Listener extends (...args: never[]) => void> implements WebsitePasskeyPortEvent<Listener> {
  readonly listeners = new Set<Listener>();

  addListener(listener: Listener): void {
    this.listeners.add(listener);
  }

  removeListener(listener: Listener): void {
    this.listeners.delete(listener);
  }

  emit(...args: Parameters<Listener>): void {
    for (const listener of [...this.listeners]) listener(...args);
  }
}

class FakePort implements WebsitePasskeyPort {
  readonly onMessage = new FakeEvent<(message: unknown) => void>();
  readonly onDisconnect = new FakeEvent<() => void>();
  readonly sent: WebsitePasskeyClientMessage[] = [];
  disconnected = false;

  postMessage(message: WebsitePasskeyClientMessage): void {
    if (this.disconnected) throw new Error('Port disconnected');
    this.sent.push(message);
  }

  disconnect(): void {
    if (this.disconnected) return;
    this.disconnected = true;
    this.onDisconnect.emit();
  }

  emit(message: WebsitePasskeyServerMessage): void {
    this.onMessage.emit(message);
  }

  drop(): void {
    this.disconnect();
  }
}

class FakeConditionalUi implements WebsitePasskeyConditionalUi {
  readonly activate = vi.fn((
    _binding: WebsitePasskeyConditionalUiBinding,
    onSelect: (credentialId: string) => void,
  ) => { this.onSelect = onSelect; });
  readonly clear = vi.fn();
  readonly dispose = vi.fn();
  onSelect: ((credentialId: string) => void) | undefined;

  select(credentialId: string): void {
    this.onSelect?.(credentialId);
  }
}

let bridge: WebsitePasskeyBridge | undefined;
let postMessage: ReturnType<typeof vi.spyOn>;
let previousSecureContext: PropertyDescriptor | undefined;
let previousPermissionsPolicy: PropertyDescriptor | undefined;
let previousFeaturePolicy: PropertyDescriptor | undefined;

beforeAll(() => {
  websitePasskeyBridge.stop();
  pageWebAuthnController.dispose();
});

afterAll(() => {
  websitePasskeyBridge.stop();
});

beforeEach(() => {
  (window as unknown as { happyDOM: { setURL(url: string): void } }).happyDOM.setURL(`${ORIGIN}/signin`);
  previousSecureContext = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
  previousPermissionsPolicy = Object.getOwnPropertyDescriptor(document, 'permissionsPolicy');
  previousFeaturePolicy = Object.getOwnPropertyDescriptor(document, 'featurePolicy');
  Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true });
  postMessage = vi.spyOn(window, 'postMessage').mockImplementation(() => {});
  browserMocks.connect.mockReset();
  browserMocks.sendMessage.mockReset();
});

afterEach(() => {
  bridge?.stop();
  bridge = undefined;
  postMessage.mockRestore();
  vi.useRealTimers();
  if (previousSecureContext) Object.defineProperty(window, 'isSecureContext', previousSecureContext);
  else delete (window as unknown as { isSecureContext?: unknown }).isSecureContext;
  if (previousPermissionsPolicy) Object.defineProperty(document, 'permissionsPolicy', previousPermissionsPolicy);
  else delete (document as unknown as { permissionsPolicy?: unknown }).permissionsPolicy;
  if (previousFeaturePolicy) Object.defineProperty(document, 'featurePolicy', previousFeaturePolicy);
  else delete (document as unknown as { featurePolicy?: unknown }).featurePolicy;
});

describe('Port configuration lifecycle', () => {
  it('refreshes config on the same Port, returns a fixed ack, and removes the listener on stop', () => {
    const port = new FakePort();
    let runtimeListener: ((message: unknown) => WebsitePasskeyRuntimeResponse | undefined) | undefined;
    const unsubscribe = vi.fn();
    bridge = new WebsitePasskeyBridge({
      connectPort: () => port,
      subscribeRuntimeMessages(listener) {
        runtimeListener = listener;
        return unsubscribe;
      },
    });
    bridge.start();
    port.emit(config(false));
    const helloCount = port.sent.filter((message) => message.type === 'hello').length;

    const ack = runtimeListener?.({ type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE });
    expect(parseWebsitePasskeyConfigChangedAck(ack)).toEqual({
      websitePasskey: true,
    });
    expect(() => parseWebsitePasskeyConfigChangedAck({ websitePasskey: true, extra: true })).toThrow();
    expect(port.sent.filter((message) => message.type === 'hello')).toHaveLength(helloCount + 1);
    expect(runtimeListener?.({ type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE, payload: true })).toBeUndefined();
    port.emit(config(true));
    expect(port.disconnected).toBe(false);
    expect(lastWindowMessage('config')).toMatchObject({ enabled: true });

    bridge.stop();
    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it('answers feature-policy probes only through the isolated runtime listener', () => {
    const port = new FakePort();
    let runtimeListener: ((message: unknown) => WebsitePasskeyRuntimeResponse | undefined) | undefined;
    const answerFeaturePolicyProbe = vi.fn((request: unknown) => {
      const challenge = (request as { challenge: string }).challenge;
      return { challenge, get: true, create: false };
    });
    bridge = new WebsitePasskeyBridge({
      connectPort: () => port,
      answerFeaturePolicyProbe,
      subscribeRuntimeMessages(listener) {
        runtimeListener = listener;
        return () => {};
      },
    });
    bridge.start();
    const request = {
      type: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
      version: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
      challenge: BRIDGE_ID,
    };

    const response = runtimeListener?.(request);

    expect(parseWebsitePasskeyFeaturePolicyProbeResponse(response, BRIDGE_ID)).toEqual({
      challenge: BRIDGE_ID,
      get: true,
      create: false,
    });
    expect(answerFeaturePolicyProbe).toHaveBeenCalledWith(request);
    expect(postMessage).not.toHaveBeenCalledWith(expect.objectContaining({ challenge: BRIDGE_ID }), expect.anything());
  });

  it('uses the isolated-realm sentinel and refreshes hello on duplicate injection', () => {
    const port = new FakePort();
    const first = installWebsitePasskeyBridge({ connectPort: () => port });
    bridge = first;
    const second = installWebsitePasskeyBridge({
      connectPort: () => { throw new Error('duplicate bridge opened'); },
    });

    expect(second).toBe(first);
    expect(port.sent.filter((message) => message.type === 'hello')).toHaveLength(2);
  });

  it('opens one long-lived Port, sends hello first, and mirrors authoritative config', () => {
    const port = new FakePort();
    bridge = startBridge([port]);

    expect(port.sent).toEqual([{ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' }]);
    port.emit(config(true));
    expect(lastWindowMessage('config')).toEqual({
      source: WEBSITE_PASSKEY_BRIDGE_SOURCE,
      version: WEBSITE_PASSKEY_WINDOW_VERSION,
      type: 'config',
      enabled: true,
    });

    port.emit(config(false));
    expect(lastWindowMessage('config')).toMatchObject({ enabled: false });
  });

  it('does not forward a page request until config enables this exact document', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    dispatchPage(beginMessage());
    port.emit(config(false));
    dispatchPage(beginMessage());

    expect(port.sent).toEqual([{ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' }]);
    expect(browserMocks.sendMessage).not.toHaveBeenCalled();
  });
});

describe('request delivery and acknowledgement', () => {
  it.each([
    ['get', 'publickey-credentials-get', getRequest()],
    ['create', 'publickey-credentials-create', createRequest()],
  ] as const)('rejects %s before Port delivery when Permissions Policy denies it', async (_kind, feature, request) => {
    const allowsFeature = vi.fn(() => false);
    Object.defineProperty(document, 'featurePolicy', {
      configurable: true,
      value: { allowsFeature },
    });
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));

    dispatchPage(beginMessage(request));

    expect(allowsFeature).toHaveBeenCalledWith(feature);
    expect(port.sent.filter((message) => message.type === 'begin')).toHaveLength(0);
    expect(lastWindowMessage('preflightOutcome')).toMatchObject({
      bridgeRequestId: request.bridgeRequestId,
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
  });

  it('forwards conditional mediation unchanged over the authenticated document Port', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    const request = getRequest({ mediation: 'conditional' });

    dispatchPage(beginMessage(request));

    expect(port.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request,
    });
  });

  it('keeps conditional candidates private and sends selection only after inline UI chooses', () => {
    const port = new FakePort();
    const conditionalUi = new FakeConditionalUi();
    bridge = startBridge([port], conditionalUi);
    port.emit(config(true));
    const request = getRequest({ mediation: 'conditional' });
    dispatchPage(beginMessage(request));

    port.emit(conditionalActive());

    expect(conditionalUi.activate).toHaveBeenCalledWith(
      expect.objectContaining({
        ceremonyId: CEREMONY_ID,
        candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work', username: 'alice' }],
      }),
      expect.any(Function),
    );
    expect(lastWindowMessage('accepted')).toMatchObject({
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
    });
    expect(lastWindowMessage('accepted')).not.toHaveProperty('candidates');
    expect(port.sent.some((message) => message.type === 'conditionalSelect')).toBe(false);

    conditionalUi.select('Y3JlZGVudGlhbA');
    expect(port.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'conditionalSelect',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
      credentialId: 'Y3JlZGVudGlhbA',
    });
  });

  it('clears conditional UI when the native provider wins and cancels the extension branch', () => {
    const port = new FakePort();
    const conditionalUi = new FakeConditionalUi();
    bridge = startBridge([port], conditionalUi);
    port.emit(config(true));
    dispatchPage(beginMessage(getRequest({ mediation: 'conditional' })));
    port.emit(conditionalActive());

    dispatchPage(cancelMessage());

    expect(conditionalUi.clear).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_ID);
    expect(port.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
    });
  });

  it('withdraws conditional UI at its worker deadline while retaining terminal recovery', () => {
    vi.useFakeTimers();
    const port = new FakePort();
    const conditionalUi = new FakeConditionalUi();
    bridge = startBridge([port], conditionalUi);
    port.emit(config(true));
    dispatchPage(beginMessage(getRequest({ mediation: 'conditional' })));
    const active = conditionalActive(Date.now() + 30_000);
    port.emit(active);
    conditionalUi.clear.mockClear();

    vi.advanceTimersByTime(30_000);

    expect(conditionalUi.clear).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_ID);
    expect(port.sent.some((message) => message.type === 'ack')).toBe(false);
  });

  it('forwards an unbound preflight outcome without ACK or a second begin', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());
    port.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_ID,
      outcome: { status: 'fallback', reason: 'capacity' },
    });

    expect(lastWindowMessage('preflightOutcome')).toMatchObject({
      source: WEBSITE_PASSKEY_BRIDGE_SOURCE,
      bridgeRequestId: BRIDGE_ID,
      outcome: { status: 'fallback', reason: 'capacity' },
    });
    expect(port.sent.filter((message) => message.type === 'ack')).toHaveLength(0);
    expect(port.sent.filter((message) => message.type === 'begin')).toHaveLength(1);
  });

  it('forwards begin, accepted, and outcome but ACKs only after MAIN confirms delivery', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());
    expect(port.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: getRequest(),
    });

    port.emit(accepted());
    expect(lastWindowMessage('accepted')).toMatchObject({
      source: WEBSITE_PASSKEY_BRIDGE_SOURCE,
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
    });
    port.emit(successOutcome());
    expect(lastWindowMessage('outcome')).toMatchObject({ outcomeId: OUTCOME_ID });
    expect(port.sent.some((message) => message.type === 'ack')).toBe(false);

    dispatchPage(deliveredMessage());
    expect(port.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
      outcomeId: OUTCOME_ID,
    });
    expect(browserMocks.sendMessage).not.toHaveBeenCalled();
  });

  it.each(['excluded_domain', 'no_match', 'unsupported', 'user_selected_browser'] as const)(
    'binds and ACKs an atomic %s outcome without a preceding accepted message',
    (reason) => {
      const port = new FakePort();
      bridge = startBridge([port]);
      port.emit(config(true));
      dispatchPage(beginMessage());
      port.emit(fallbackOutcome(reason));

      expect(lastWindowMessage('outcome')).toMatchObject({
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: BRIDGE_ID,
        outcome: { status: 'fallback', reason },
      });
      dispatchPage(deliveredMessage());
      expect(port.sent.at(-1)).toMatchObject({
        type: 'ack',
        ceremonyId: CEREMONY_ID,
        outcomeId: OUTCOME_ID,
      });
    },
  );

  it('drains and ACKs a terminal outcome after RP abort without redelivering it to MAIN', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());
    dispatchPage(cancelMessage());
    expect(port.sent.some((message) => message.type === 'cancel')).toBe(false);

    port.emit(accepted());
    expect(port.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
    });
    const beforeOutcomeMessages = windowMessages('outcome').length;
    port.emit(errorOutcome(BRIDGE_ID, 'AbortError'));

    expect(windowMessages('outcome')).toHaveLength(beforeOutcomeMessages);
    expect(port.sent.at(-1)).toMatchObject({ type: 'ack', outcomeId: OUTCOME_ID });
  });

  it('ACKs an exact duplicate outcome without resolving the page a second time', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());
    port.emit(accepted());
    port.emit(successOutcome());
    dispatchPage(deliveredMessage());
    const deliveredCount = windowMessages('outcome').length;
    const ackCount = port.sent.filter((message) => message.type === 'ack').length;

    port.emit(successOutcome());

    expect(windowMessages('outcome')).toHaveLength(deliveredCount);
    expect(port.sent.filter((message) => message.type === 'ack')).toHaveLength(ackCount + 1);
  });

  it('drains an outcome when abort wins before MAIN delivery and keeps the ACK across reconnect', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    dispatchPage(beginMessage());
    first.emit(accepted());
    first.emit(successOutcome());

    dispatchPage(cancelMessage());
    expect(first.sent.at(-1)).toMatchObject({ type: 'ack', outcomeId: OUTCOME_ID });

    first.drop();
    vi.advanceTimersByTime(250);
    second.emit(config(true));
    expect(second.sent.filter((message) => message.type === 'begin')).toHaveLength(0);
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'resume',
      request: getRequest(),
    });
    second.emit(successOutcome());
    expect(second.sent.at(-1)).toMatchObject({ type: 'ack', outcomeId: OUTCOME_ID });
  });
});

describe('reconnection and exact redelivery', () => {
  it('holds unlock pending across reconnect and cancels the exact continuation', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    dispatchPage(beginMessage());
    const deadlineAt = Date.now() + 30_000;
    first.emit(unlockPending(deadlineAt));
    expect(lastWindowMessage('unlockPending')).toMatchObject({
      continuationId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
      deadlineAt,
    });

    first.drop();
    vi.advanceTimersByTime(250);
    second.emit(config(true));
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'resume',
      request: getRequest(),
    });
    second.emit(unlockPending(deadlineAt));
    dispatchPage(cancelMessage());
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'cancel',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
    });
  });

  it('queues a new canonical begin while transport is disconnected and sends it after config', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    first.drop();
    dispatchPage(beginMessage());

    expect(first.sent.filter((message) => message.type === 'begin')).toHaveLength(0);
    vi.advanceTimersByTime(250);
    second.emit(config(true));
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'begin',
      request: getRequest(),
    });
  });

  it('reconnects, withdraws, and restores the same conditional request before a terminal outcome', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    const conditionalUi = new FakeConditionalUi();
    const request = getRequest({ mediation: 'conditional' });
    bridge = startBridge([first, second], conditionalUi);
    first.emit(config(true));
    dispatchPage(beginMessage(request));
    const active = conditionalActive(Date.now() + 60_000);
    first.emit(active);
    const firstBegin = first.sent.find((message) => message.type === 'begin');

    first.drop();
    expect(conditionalUi.clear).toHaveBeenCalledWith(CEREMONY_ID, BRIDGE_ID);
    expect(windowMessages('config').at(-1)).toMatchObject({ enabled: true });
    vi.advanceTimersByTime(250);
    expect(second.sent[0]).toEqual({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' });
    second.emit(config(true));

    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'resume',
      request: firstBegin?.type === 'begin' ? firstBegin.request : undefined,
    });
    second.emit(active);
    expect(conditionalUi.activate).toHaveBeenCalledTimes(2);
  });

  it('rebinds and resends the exact ACK after reconnect beyond the ceremony deadline', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    dispatchPage(beginMessage());
    first.emit(accepted());
    first.emit(successOutcome());
    dispatchPage(deliveredMessage());

    first.drop();
    vi.advanceTimersByTime(60_001);
    second.emit(config(true));

    expect(second.sent.filter((message) => message.type === 'begin')).toHaveLength(0);
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'resume',
      request: getRequest(),
    });
    second.emit(successOutcome());
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'ack',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: BRIDGE_ID,
      outcomeId: OUTCOME_ID,
    });
  });

  it('recovers an accepted create across disconnect without native fallback or an orphan result', async () => {
    vi.useFakeTimers();
    const previousCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
    const nativeCreate = vi.fn(async () => ({ id: 'native-create' }));
    const credentials = {
      get: vi.fn(async () => null),
      create: nativeCreate,
    } as unknown as CredentialsContainer;
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
    postMessage.mockImplementation(((message: unknown) => {
      window.dispatchEvent(new MessageEvent('message', {
        source: window,
        origin: location.origin,
        data: message,
      }));
    }) as typeof window.postMessage);
    const page = installPageWebAuthnInterception();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);

    try {
      first.emit(config(true));
      const promise = credentials.create({
        publicKey: {
          rp: { id: 'example.com', name: 'Example' },
          user: { id: new Uint8Array([9]), name: 'person@example.com', displayName: 'Person' },
          challenge: new Uint8Array([1, 2, 3]),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      });
      const firstBegin = first.sent.find((message) => message.type === 'begin');
      expect(firstBegin?.type).toBe('begin');
      const bridgeRequestId = firstBegin?.type === 'begin'
        ? firstBegin.request.bridgeRequestId
        : '';
      const acceptedMessage: WebsitePasskeyServerMessage = {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'accepted',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId,
        deadlineAt: Date.now() + 60_000,
      };
      first.emit(acceptedMessage);
      first.drop();
      vi.advanceTimersByTime(250);
      second.emit(config(true));
      expect(second.sent.find((message) => message.type === 'resume')).toEqual({
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'resume',
        request: firstBegin?.type === 'begin' ? firstBegin.request : undefined,
      });
      second.emit(createSuccessOutcome(bridgeRequestId));

      const credential = await promise;
      expect(credential?.id).toBe('AQ');
      expect(nativeCreate).not.toHaveBeenCalled();
      expect(second.sent.at(-1)).toMatchObject({ type: 'ack', bridgeRequestId });
    } finally {
      page.dispose();
      if (previousCredentials) Object.defineProperty(navigator, 'credentials', previousCredentials);
      else delete (navigator as unknown as { credentials?: unknown }).credentials;
    }
  });

  it('resumes an accepted create after page timeout and ACKs the uncertain terminal', async () => {
    vi.useFakeTimers();
    const previousCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
    const nativeCreate = vi.fn(async () => ({ id: 'native-create' }));
    const credentials = {
      get: vi.fn(async () => null),
      create: nativeCreate,
    } as unknown as CredentialsContainer;
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
    postMessage.mockImplementation(((message: unknown) => {
      window.dispatchEvent(new MessageEvent('message', {
        source: window,
        origin: location.origin,
        data: message,
      }));
    }) as typeof window.postMessage);
    const page = installPageWebAuthnInterception();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);

    try {
      first.emit(config(true));
      const promise = credentials.create({
        publicKey: {
          rp: { id: 'example.com', name: 'Example' },
          user: { id: new Uint8Array([9]), name: 'person@example.com', displayName: 'Person' },
          challenge: new Uint8Array([1, 2, 3]),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          timeout: 30_000,
        },
      });
      const rejection = promise.then(
        () => undefined,
        (error: unknown) => error,
      );
      const begin = first.sent.find((message) => message.type === 'begin');
      const bridgeRequestId = begin?.type === 'begin' ? begin.request.bridgeRequestId : '';
      first.emit({
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'accepted',
        ceremonyId: CEREMONY_ID,
        bridgeRequestId,
        deadlineAt: Date.now() + 30_000,
      });
      first.drop();
      vi.advanceTimersByTime(30_001);

      second.emit(config(false));
      expect(second.sent.at(-1)).toMatchObject({ type: 'resume' });
      second.emit(errorOutcome(bridgeRequestId, 'UnknownError'));

      expect(await rejection).toMatchObject({ name: 'UnknownError' });
      expect(nativeCreate).not.toHaveBeenCalled();
      expect(second.sent.at(-1)).toMatchObject({
        type: 'ack',
        bridgeRequestId,
        outcomeId: OUTCOME_ID,
      });
    } finally {
      page.dispose();
      if (previousCredentials) Object.defineProperty(navigator, 'credentials', previousCredentials);
      else delete (navigator as unknown as { credentials?: unknown }).credentials;
    }
  });

  it('rejects a direct worker-restart terminal when accepted was lost without native create', async () => {
    vi.useFakeTimers();
    const previousCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
    const nativeCreate = vi.fn(async () => ({ id: 'native-create' }));
    const credentials = {
      get: vi.fn(async () => null),
      create: nativeCreate,
    } as unknown as CredentialsContainer;
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
    postMessage.mockImplementation(((message: unknown) => {
      window.dispatchEvent(new MessageEvent('message', {
        source: window,
        origin: location.origin,
        data: message,
      }));
    }) as typeof window.postMessage);
    const page = installPageWebAuthnInterception();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);

    try {
      first.emit(config(true));
      const promise = credentials.create({
        publicKey: {
          rp: { id: 'example.com', name: 'Example' },
          user: { id: new Uint8Array([9]), name: 'person@example.com', displayName: 'Person' },
          challenge: new Uint8Array([1, 2, 3]),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      });
      const begin = first.sent.find((message) => message.type === 'begin');
      const bridgeRequestId = begin?.type === 'begin' ? begin.request.bridgeRequestId : '';
      first.drop();
      vi.advanceTimersByTime(250);
      second.emit(config(true));
      expect(second.sent.at(-1)).toMatchObject({ type: 'resume' });
      second.emit(errorOutcome(bridgeRequestId, 'UnknownError'));

      await expect(promise).rejects.toMatchObject({ name: 'UnknownError' });
      expect(nativeCreate).not.toHaveBeenCalled();
      expect(second.sent.at(-1)).toMatchObject({ type: 'ack', bridgeRequestId });
    } finally {
      page.dispose();
      if (previousCredentials) Object.defineProperty(navigator, 'credentials', previousCredentials);
      else delete (navigator as unknown as { credentials?: unknown }).credentials;
    }
  });

  it('resumes an accepted request and delivers its terminal outcome when refreshed disabled', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    dispatchPage(beginMessage());
    first.emit(accepted());
    first.drop();
    vi.advanceTimersByTime(250);

    second.emit(config(false));
    expect(second.sent.at(-1)).toEqual({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'resume',
      request: getRequest(),
    });
    second.emit(successOutcome());
    expect(lastWindowMessage('outcome')).toMatchObject({ outcomeId: OUTCOME_ID });
    dispatchPage(deliveredMessage());
    expect(second.sent.at(-1)).toMatchObject({ type: 'ack', outcomeId: OUTCOME_ID });
  });

  it('rebinds a delivered-but-unacknowledged outcome while disabled before ACKing it', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    dispatchPage(beginMessage());
    first.emit(successOutcome());
    first.drop();
    vi.advanceTimersByTime(250);

    second.emit(config(false));
    expect(second.sent.at(-1)).toMatchObject({ type: 'resume', request: getRequest() });
    second.emit(successOutcome());
    dispatchPage(deliveredMessage());
    expect(second.sent.at(-1)).toMatchObject({ type: 'ack', outcomeId: OUTCOME_ID });
  });

  it('resumes a worker-restart terminal when disconnect happened before accepted was delivered', () => {
    vi.useFakeTimers();
    const first = new FakePort();
    const second = new FakePort();
    bridge = startBridge([first, second]);
    first.emit(config(true));
    dispatchPage(beginMessage());
    first.drop();
    vi.advanceTimersByTime(250);

    second.emit(config(false));
    expect(second.sent.at(-1)).toMatchObject({ type: 'resume', request: getRequest() });
    second.emit(errorOutcome(BRIDGE_ID, 'UnknownError'));
    expect(lastWindowMessage('outcome')).toMatchObject({
      outcome: { status: 'error', error: { name: 'UnknownError' } },
    });
    dispatchPage(deliveredMessage());
    expect(second.sent.at(-1)).toMatchObject({ type: 'ack', outcomeId: OUTCOME_ID });
  });
});

describe('window-message boundary', () => {
  it('ignores wrong origins, unknown fields, invalid ids, and never uses direct runtime messages', () => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage(), 'https://evil.example');
    dispatchPage({ ...beginMessage(), extra: true });
    dispatchPage({ ...beginMessage(), request: { ...getRequest(), bridgeRequestId: 'not-a-uuid' } });

    expect(port.sent.filter((message) => message.type === 'begin')).toHaveLength(0);
    expect(browserMocks.sendMessage).not.toHaveBeenCalled();
    expect(document.body.childElementCount).toBe(0);
  });

  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
    ['NUL', '\0'],
  ])('rejects local window-message UUIDs with trailing %s', (_label, suffix) => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));

    dispatchPage({
      ...beginMessage(),
      request: { ...getRequest(), bridgeRequestId: `${BRIDGE_ID}${suffix}` },
    });
    dispatchPage({ ...cancelMessage(), bridgeRequestId: `${BRIDGE_ID}${suffix}` });
    dispatchPage({ ...deliveredMessage(), ceremonyId: `${CEREMONY_ID}${suffix}` });
    dispatchPage({ ...deliveredMessage(), outcomeId: `${OUTCOME_ID}${suffix}` });

    expect(port.sent.filter((message) => message.type === 'begin')).toHaveLength(0);
    expect(port.sent.filter((message) => message.type === 'cancel')).toHaveLength(0);
    expect(port.sent.filter((message) => message.type === 'ack')).toHaveLength(0);
  });

  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
    ['NUL', '\0'],
  ])('disconnects a Port server message whose ceremony UUID has trailing %s', (_label, suffix) => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());

    port.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'accepted',
      ceremonyId: `${CEREMONY_ID}${suffix}`,
      bridgeRequestId: BRIDGE_ID,
      deadlineAt: Date.now() + 60_000,
    } as unknown as WebsitePasskeyServerMessage);

    expect(port.disconnected).toBe(true);
  });

  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
    ['NUL', '\0'],
  ])('disconnects a Port server message whose bridge UUID has trailing %s', (_label, suffix) => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());

    port.emit({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'accepted',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: `${BRIDGE_ID}${suffix}`,
      deadlineAt: Date.now() + 60_000,
    } as unknown as WebsitePasskeyServerMessage);

    expect(port.disconnected).toBe(true);
  });

  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
    ['NUL', '\0'],
  ])('disconnects a Port server outcome whose outcome UUID has trailing %s', (_label, suffix) => {
    const port = new FakePort();
    bridge = startBridge([port]);
    port.emit(config(true));
    dispatchPage(beginMessage());
    const message = successOutcome();

    port.emit({ ...message, outcomeId: `${OUTCOME_ID}${suffix}` } as WebsitePasskeyServerMessage);

    expect(port.disconnected).toBe(true);
  });
});

function startBridge(
  ports: FakePort[],
  conditionalUi?: WebsitePasskeyConditionalUi,
): WebsitePasskeyBridge {
  let index = 0;
  const instance = new WebsitePasskeyBridge({
    connectPort(name) {
      expect(name).toBe(WEBSITE_PASSKEY_PORT_NAME);
      const port = ports[index++];
      if (!port) throw new Error('No fake Port available');
      return port;
    },
    ...(conditionalUi ? { conditionalUi } : {}),
  });
  instance.start();
  return instance;
}

function config(enabled: boolean): WebsitePasskeyServerMessage {
  return { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled };
}

function accepted(): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'accepted',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId: BRIDGE_ID,
    deadlineAt: Date.now() + 60_000,
  };
}

function unlockPending(deadlineAt = Date.now() + 60_000): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'unlockPending',
    continuationId: CEREMONY_ID,
    bridgeRequestId: BRIDGE_ID,
    deadlineAt,
  };
}

function conditionalActive(deadlineAt = Date.now() + 60_000): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'conditionalActive',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId: BRIDGE_ID,
    deadlineAt,
    candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work', username: 'alice' }],
  };
}

function successOutcome(): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId: BRIDGE_ID,
    outcomeId: OUTCOME_ID,
    outcome: {
      status: 'success',
      result: {
        kind: 'get',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credentialId: 'AQ',
        authenticatorData: 'Ag',
        clientDataJSON: 'Aw',
        signature: 'BA',
      },
    },
  };
}

function createSuccessOutcome(bridgeRequestId: string): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    outcomeId: OUTCOME_ID,
    outcome: {
      status: 'success',
      result: {
        kind: 'create',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credProps: { rk: true },
        credentialId: 'AQ',
        attestationObject: 'Ag',
        clientDataJSON: 'Aw',
        authData: 'BA',
        publicKeySpki: 'BQ',
        publicKeyAlgorithm: -7,
      },
    },
  };
}

function errorOutcome(
  bridgeRequestId: string,
  name: 'AbortError' | 'NotAllowedError' | 'UnknownError',
): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    outcomeId: OUTCOME_ID,
    outcome: {
      status: 'error',
      error: {
        name,
        message: name === 'AbortError'
          ? 'The operation was aborted.'
          : 'The operation could not be completed.',
      },
    },
  };
}

function fallbackOutcome(
  reason: 'excluded_domain' | 'no_match' | 'unsupported' | 'user_selected_browser',
): WebsitePasskeyServerMessage {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId: BRIDGE_ID,
    outcomeId: OUTCOME_ID,
    outcome: { status: 'fallback', reason },
  };
}

function getRequest(
  overrides: Partial<CanonicalWebsitePasskeyGetRequest> = {},
): CanonicalWebsitePasskeyGetRequest {
  return {
    bridgeRequestId: BRIDGE_ID,
    kind: 'get',
    rpId: 'example.com',
    challenge: 'AQID',
    allowCredentials: [],
    userVerification: 'preferred',
    mediation: 'optional',
    timeout: 60_000,
    ...overrides,
  };
}

function createRequest(): CanonicalWebsitePasskeyCreateRequest {
  return {
    bridgeRequestId: BRIDGE_ID,
    kind: 'create',
    rp: { id: 'example.com', name: 'Example' },
    user: { id: 'CQ', name: 'person@example.com', displayName: 'Person' },
    challenge: 'AQID',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'preferred',
    },
    attestation: 'none',
    extensions: { credProps: false },
    timeout: 60_000,
  };
}

function beginMessage(
  request: CanonicalWebsitePasskeyGetRequest | CanonicalWebsitePasskeyCreateRequest = getRequest(),
): Record<string, unknown> {
  return {
    source: WEBSITE_PASSKEY_PAGE_SOURCE,
    version: WEBSITE_PASSKEY_WINDOW_VERSION,
    type: 'begin',
    request,
  };
}

function cancelMessage(): Record<string, unknown> {
  return {
    source: WEBSITE_PASSKEY_PAGE_SOURCE,
    version: WEBSITE_PASSKEY_WINDOW_VERSION,
    type: 'cancel',
    bridgeRequestId: BRIDGE_ID,
    settled: true,
  };
}

function deliveredMessage(): Record<string, unknown> {
  return {
    source: WEBSITE_PASSKEY_PAGE_SOURCE,
    version: WEBSITE_PASSKEY_WINDOW_VERSION,
    type: 'delivered',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId: BRIDGE_ID,
    outcomeId: OUTCOME_ID,
  };
}

function dispatchPage(message: Record<string, unknown>, origin = location.origin): void {
  window.dispatchEvent(new MessageEvent('message', {
    source: window,
    origin,
    data: message,
  }));
}

function windowMessages(type: string): Array<Record<string, unknown>> {
  const calls = postMessage.mock.calls as unknown[][];
  return calls
    .map((call) => call[0])
    .filter((message): message is Record<string, unknown> => (
      typeof message === 'object' && message !== null && (message as { type?: unknown }).type === type
    ));
}

function lastWindowMessage(type: string): Record<string, unknown> {
  const message = windowMessages(type).at(-1);
  if (!message) throw new Error(`No ${type} message was posted`);
  return message;
}
