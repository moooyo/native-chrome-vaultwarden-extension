// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

const browserMocks = vi.hoisted(() => ({ connect: vi.fn(), sendMessage: vi.fn() }));
vi.mock('webextension-polyfill', () => ({
  default: { runtime: { connect: browserMocks.connect, sendMessage: browserMocks.sendMessage } },
}));

import {
  WebsitePasskeyBridge,
  websitePasskeyBridge,
  type WebsitePasskeyPort,
} from './webauthn-bridge.js';
import {
  WEBSITE_PASSKEY_PAGE_SOURCE,
  WEBSITE_PASSKEY_WINDOW_VERSION,
} from './website-passkey-feature.js';
import {
  WEBSITE_PASSKEY_PORT_VERSION,
  type WebsitePasskeyClientMessage,
} from '../messaging/website-passkey-port.js';

let bridge: WebsitePasskeyBridge | undefined;

afterEach(() => {
  bridge?.stop();
  bridge = undefined;
  websitePasskeyBridge.stop();
  vi.restoreAllMocks();
});

describe('disabled website passkey boundary', () => {
  it('ignores a page-forged begin while the authoritative Port config is disabled', () => {
    websitePasskeyBridge.stop();
    (window as unknown as { happyDOM: { setURL(url: string): void } }).happyDOM.setURL(
      'https://login.example.com/signin',
    );
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true });
    const sent: WebsitePasskeyClientMessage[] = [];
    let onMessage: ((message: unknown) => void) | undefined;
    const port: WebsitePasskeyPort = {
      onMessage: {
        addListener(listener) { onMessage = listener; },
      },
      onDisconnect: {
        addListener() {},
      },
      postMessage(message) { sent.push(message); },
      disconnect() {},
    };
    bridge = new WebsitePasskeyBridge({ connectPort: () => port });
    bridge.start();
    onMessage?.({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false });

    window.dispatchEvent(new MessageEvent('message', {
      source: window,
      origin: location.origin,
      data: {
        source: WEBSITE_PASSKEY_PAGE_SOURCE,
        version: WEBSITE_PASSKEY_WINDOW_VERSION,
        type: 'begin',
        request: {
          bridgeRequestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          kind: 'get',
          rpId: 'example.com',
          challenge: 'AQID',
          allowCredentials: [],
          userVerification: 'preferred',
          mediation: 'optional',
          timeout: 60_000,
        },
      },
    }));

    expect(sent).toEqual([{ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' }]);
    expect(browserMocks.sendMessage).toHaveBeenCalledWith({
      type: 'websitePasskey.reportIframeInventory',
      iframes: [],
    });
    expect(document.body.childElementCount).toBe(0);
  });
});
