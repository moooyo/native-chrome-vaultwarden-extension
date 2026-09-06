import { describe, expect, it, vi } from 'vitest';
import { BINARY_TRANSFER_PORT_NAME } from '../messaging/binary-transfer-port.js';
import { VAULT_TRANSFER_PORT_NAME } from '../messaging/vault-transfer-port.js';
import {
  WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE,
  WEBSITE_PASSKEY_PORT_NAME,
} from '../messaging/website-passkey-port.js';
import {
  WebsitePasskeyBrowserRuntimeError,
  createBackgroundPortDispatcher,
  createWebsitePasskeyTopFrameNotifier,
  websitePasskeyOriginMatchPattern,
  type WebsitePasskeyBrowserFrame,
  type WebsitePasskeyBrowserLike,
} from './website-passkey-browser.js';
import type { WebsitePasskeyScriptState } from './website-passkey-script-manager.js';

const ACTIVE_STATE = Object.freeze({
  enabled: true,
  sessionState: 'unlocked',
  policyGeneration: 1,
} satisfies WebsitePasskeyScriptState);

interface BrowserScenario {
  readonly tabs?: readonly { readonly id?: number }[];
  readonly getFrame?: (
    tabId: number,
    call: number,
    frameId: number,
  ) => WebsitePasskeyBrowserFrame | null | undefined | Promise<WebsitePasskeyBrowserFrame | null | undefined>;
  readonly getAllFrames?: (
    tabId: number,
  ) => readonly WebsitePasskeyBrowserFrame[] | null | undefined | Promise<readonly WebsitePasskeyBrowserFrame[] | null | undefined>;
  readonly sendMessage?: (
    tabId: number,
    call: number,
    options: { readonly frameId: number; readonly documentId: string },
  ) => unknown | Promise<unknown>;
  readonly contains?: (pattern: string, tabCall: number) => boolean | Promise<boolean>;
  readonly executeScript?: (
    tabId: number,
    file: string,
    world: 'ISOLATED' | 'MAIN',
    documentId: string,
  ) => unknown | Promise<unknown>;
}

function createBrowser(scenario: BrowserScenario = {}) {
  const frameCalls = new Map<number, number>();
  const sendCalls = new Map<number, number>();
  let permissionCall = 0;
  const getFrame = vi.fn(async ({ tabId, frameId }: { tabId: number; frameId: number }) => {
    const call = (frameCalls.get(tabId) ?? 0) + 1;
    frameCalls.set(tabId, call);
    return scenario.getFrame ? scenario.getFrame(tabId, call, frameId) : {
      frameId: 0,
      documentId: `document-${tabId}`,
      url: `https://tab-${tabId}.example/sign-in`,
    };
  });
  const sendMessage = vi.fn(async (
    tabId: number,
    message: Readonly<{ type: typeof WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE }>,
    options: { frameId: number; documentId: string },
  ) => {
    expect(message).toEqual({ type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE });
    const call = (sendCalls.get(tabId) ?? 0) + 1;
    sendCalls.set(tabId, call);
    return scenario.sendMessage
      ? scenario.sendMessage(tabId, call, options)
      : { websitePasskey: true };
  });
  const contains = vi.fn(async ({ origins }: { readonly origins: readonly [string] }) => {
    permissionCall += 1;
    return scenario.contains?.(origins[0], permissionCall) ?? true;
  });
  const executeScript = vi.fn(async (injection: {
    target: { tabId: number; documentIds: readonly [string] };
    files: readonly [string];
    world: 'ISOLATED' | 'MAIN';
  }) => {
    const custom = await scenario.executeScript?.(
      injection.target.tabId,
      injection.files[0],
      injection.world,
      injection.target.documentIds[0],
    );
    if (Array.isArray(custom)) return custom;
    return [{
      frameId: 0,
      documentId: injection.target.documentIds[0],
    }];
  });
  const browser: WebsitePasskeyBrowserLike = {
    tabs: {
      query: vi.fn(async () => scenario.tabs ?? [{ id: 7 }]),
      sendMessage,
    },
    webNavigation: {
      getFrame,
      ...(scenario.getAllFrames
        ? { getAllFrames: vi.fn(async ({ tabId }: { tabId: number }) => scenario.getAllFrames?.(tabId)) }
        : {}),
    },
    permissions: { contains },
    scripting: { executeScript },
  };
  return { browser, getFrame, sendMessage, contains, executeScript };
}

describe('websitePasskeyOriginMatchPattern', () => {
  it.each([
    ['https://example.com/path?q=1#fragment', 'https://example.com/*'],
    ['https://sub.example.com:8443/path', 'https://sub.example.com/*'],
    ['http://localhost:8080/path', 'http://localhost/*'],
    ['http://127.0.0.1/path', 'http://127.0.0.1/*'],
    ['http://127.0.0.1:18082/random-port', 'http://127.0.0.1/*'],
  ])('normalizes the supported URL %j', (url, expected) => {
    expect(websitePasskeyOriginMatchPattern(url)).toBe(expected);
  });

  it.each([
    'http://example.com/',
    'http://sub.localhost/',
    'http://127.0.0.2/',
    'http://[::1]/',
    'https://[::1]/',
    'https://user:password@example.com/',
    'file:///tmp/index.html',
    'chrome://settings/',
    'data:text/html,hello',
    'not a url',
  ])('rejects URLs outside the dynamic script match set: %j', (url) => {
    expect(websitePasskeyOriginMatchPattern(url)).toBeUndefined();
  });
});

describe('createWebsitePasskeyTopFrameNotifier', () => {
  it('notifies eligible cross-origin frames and leaves final ancestry policy to the worker gate', async () => {
    const frames: WebsitePasskeyBrowserFrame[] = [
      {
        frameId: 0,
        parentFrameId: -1,
        documentId: 'top-document',
        url: 'https://login.example.com/top',
      },
      {
        frameId: 1,
        parentFrameId: 0,
        documentId: 'same-origin-document',
        url: 'https://login.example.com/frame',
      },
      {
        frameId: 2,
        parentFrameId: 0,
        documentId: 'cross-origin-document',
        url: 'https://other.example/frame',
      },
      {
        frameId: 3,
        parentFrameId: 2,
        documentId: 'nested-document',
        url: 'https://login.example.com/nested',
      },
    ];
    const fixture = createBrowser({
      getAllFrames: () => frames,
      getFrame: (_tabId, _call, frameId) => frames.find((frame) => frame.frameId === frameId),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.sendMessage).toHaveBeenCalledTimes(4);
    expect(fixture.sendMessage.mock.calls.map((call) => call[2])).toEqual([
      { frameId: 0, documentId: 'top-document' },
      { frameId: 1, documentId: 'same-origin-document' },
      { frameId: 2, documentId: 'cross-origin-document' },
      { frameId: 3, documentId: 'nested-document' },
    ]);
  });

  it('repairs an already-open same-origin iframe in its exact browser document', async () => {
    const frames: WebsitePasskeyBrowserFrame[] = [
      {
        frameId: 0,
        parentFrameId: -1,
        documentId: 'top-document',
        url: 'https://login.example.com/top',
      },
      {
        frameId: 1,
        parentFrameId: 0,
        documentId: 'same-origin-document',
        url: 'https://login.example.com/frame',
      },
    ];
    let subframeMessages = 0;
    const fixture = createBrowser({
      getAllFrames: () => frames,
      getFrame: (_tabId, _call, frameId) => frames.find((frame) => frame.frameId === frameId),
      sendMessage: (_tabId, _call, target) => {
        if (target.frameId === 0) return { websitePasskey: true };
        subframeMessages += 1;
        return subframeMessages === 1 ? undefined : { websitePasskey: true };
      },
      executeScript: (_tabId, _file, _world, documentId) => ([{
        frameId: 1,
        documentId,
      }]),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.executeScript).toHaveBeenNthCalledWith(1, {
      target: { tabId: 7, documentIds: ['same-origin-document'] },
      files: ['content/page-webauthn.js'],
      world: 'MAIN',
    });
    expect(fixture.executeScript).toHaveBeenNthCalledWith(2, {
      target: { tabId: 7, documentIds: ['same-origin-document'] },
      files: ['content/webauthn-bridge.js'],
      world: 'ISOLATED',
    });
    expect(fixture.sendMessage).toHaveBeenLastCalledWith(
      7,
      { type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE },
      { frameId: 1, documentId: 'same-origin-document' },
    );
  });

  it('uses the requested top-frame id when getFrame omits it and stops after a strict acknowledgement', async () => {
    const fixture = createBrowser({
      tabs: [{ id: 7 }, {}, { id: 7 }],
      getFrame: () => ({
        documentId: 'exact-document',
        url: 'https://accounts.example/path?secret=redacted',
      }),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.browser.tabs.query).toHaveBeenCalledWith({});
    expect(fixture.sendMessage).toHaveBeenCalledOnce();
    expect(fixture.sendMessage).toHaveBeenCalledWith(
      7,
      { type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE },
      { frameId: 0, documentId: 'exact-document' },
    );
    expect(fixture.contains).not.toHaveBeenCalled();
    expect(fixture.executeScript).not.toHaveBeenCalled();
  });

  it('uses the requested frame id for same-document checks when getFrame omits it', async () => {
    const fixture = createBrowser({
      sendMessage: (_tabId, call) => call === 1 ? undefined : { websitePasskey: true },
      getFrame: () => ({
        documentId: 'exact-document',
        url: 'https://accounts.example/sign-in',
      }),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.contains).toHaveBeenCalledOnce();
    expect(fixture.executeScript).toHaveBeenCalledTimes(2);
    expect(fixture.sendMessage).toHaveBeenCalledTimes(2);
  });

  it('rejects a getFrame result that carries an invalid or conflicting frame id', async () => {
    const fixture = createBrowser({
      tabs: [{ id: 1 }, { id: 2 }],
      getFrame: (tabId) => Object.defineProperty({
        documentId: `document-${tabId}`,
        url: `https://tab-${tabId}.example/sign-in`,
      }, 'frameId', { enumerable: true, value: tabId === 1 ? undefined : 1 }),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.sendMessage).not.toHaveBeenCalled();
  });

  it('checks exact host access, injects MAIN before ISOLATED, and requires a second strict ack', async () => {
    const calls: string[] = [];
    const fixture = createBrowser({
      sendMessage: (_tabId, call) => {
        calls.push(`message:${call}`);
        return call === 1 ? { websitePasskey: true, extra: true } : { websitePasskey: true };
      },
      contains: (pattern) => {
        calls.push(`permission:${pattern}`);
        return true;
      },
      executeScript: (_tabId, file, world) => {
        calls.push(`inject:${world}:${file}`);
      },
      getFrame: () => ({
        frameId: 0,
        documentId: 'document-7',
        url: 'https://tab-7.example:8443/sign-in',
      }),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.contains).toHaveBeenCalledWith({ origins: ['https://tab-7.example/*'] });
    expect(fixture.executeScript).toHaveBeenNthCalledWith(1, {
      target: { tabId: 7, documentIds: ['document-7'] },
      files: ['content/page-webauthn.js'],
      world: 'MAIN',
    });
    expect(fixture.executeScript).toHaveBeenNthCalledWith(2, {
      target: { tabId: 7, documentIds: ['document-7'] },
      files: ['content/webauthn-bridge.js'],
      world: 'ISOLATED',
    });
    expect(calls).toEqual([
      'message:1',
      'permission:https://tab-7.example/*',
      'inject:MAIN:content/page-webauthn.js',
      'inject:ISOLATED:content/webauthn-bridge.js',
      'message:2',
    ]);
  });

  it('safely skips injection when exact-origin host permission is absent', async () => {
    const fixture = createBrowser({
      sendMessage: () => undefined,
      contains: () => false,
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.contains).toHaveBeenCalledOnce();
    expect(fixture.executeScript).not.toHaveBeenCalled();
    expect(fixture.sendMessage).toHaveBeenCalledOnce();
  });

  it.each([
    { enabled: false, sessionState: 'unlocked' as const },
    { enabled: true, sessionState: 'loggedOut' as const },
  ])('only notifies and never repairs inactive state: $enabled/$sessionState', async (partial) => {
    const fixture = createBrowser({ sendMessage: () => undefined });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)({
      ...partial,
      policyGeneration: 3,
    });

    expect(fixture.sendMessage).toHaveBeenCalledOnce();
    expect(fixture.contains).not.toHaveBeenCalled();
    expect(fixture.executeScript).not.toHaveBeenCalled();
  });

  it('treats a vanished exact document as a navigation race instead of an injection failure', async () => {
    const fixture = createBrowser({
      sendMessage: () => undefined,
      getFrame: (_tabId, call) => call <= 3
        ? { frameId: 0, documentId: 'old-document', url: 'https://old.example/path' }
        : null,
      executeScript: () => {
        throw new Error('No document with the given id at https://old.example/path');
      },
    });

    await expect(createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE))
      .resolves.toBeUndefined();
    expect(fixture.executeScript).toHaveBeenCalledOnce();
  });

  it('does not confuse a reused document id at another URL after permission ports are removed', async () => {
    const fixture = createBrowser({
      sendMessage: () => undefined,
      getFrame: (_tabId, call) => ({
        frameId: 0,
        documentId: 'reused-document-id',
        url: call === 1
          ? 'https://same.example:8443/original'
          : 'https://same.example:9443/replacement',
      }),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.sendMessage).toHaveBeenCalledOnce();
    expect(fixture.contains).not.toHaveBeenCalled();
    expect(fixture.executeScript).not.toHaveBeenCalled();
  });

  it('continues repairing the same document after a same-origin SPA URL change', async () => {
    const fixture = createBrowser({
      sendMessage: (_tabId, call) => call === 1 ? undefined : { websitePasskey: true },
      getFrame: (_tabId, call) => ({
        frameId: 0,
        documentId: 'stable-document-id',
        url: call === 1
          ? 'https://spa.example:8443/original?view=one'
          : 'https://spa.example:8443/replacement?view=two',
      }),
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.contains).toHaveBeenCalledWith({ origins: ['https://spa.example/*'] });
    expect(fixture.executeScript).toHaveBeenCalledTimes(2);
    expect(fixture.sendMessage).toHaveBeenCalledTimes(2);
  });

  it('reports a same-document partial injection failure without exposing browser details', async () => {
    const fixture = createBrowser({
      tabs: [{ id: 1 }, { id: 2 }],
      sendMessage: (tabId) => tabId === 2 ? { websitePasskey: true } : undefined,
      executeScript: (_tabId, file) => {
        if (file === 'content/webauthn-bridge.js') {
          throw new Error('Failed at https://private.example/path?token=sensitive');
        }
      },
    });
    const notify = createWebsitePasskeyTopFrameNotifier(fixture.browser);

    let failure: unknown;
    try {
      await notify(ACTIVE_STATE);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    const aggregate = failure as AggregateError;
    expect(aggregate.message).toBe('Website passkey top-frame refresh failed');
    expect(aggregate.errors).toHaveLength(1);
    expect(aggregate.errors[0]).toMatchObject({
      name: 'WebsitePasskeyBrowserRuntimeError',
      code: 'bridge_injection_failed',
    });
    expect(String(aggregate.errors[0])).not.toContain('private.example');
    expect(fixture.sendMessage).toHaveBeenCalledWith(
      2,
      { type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE },
      { frameId: 0, documentId: 'document-2' },
    );
  });

  it('rejects a resolved injection that did not execute in the exact target document', async () => {
    const fixture = createBrowser({ sendMessage: () => undefined });
    vi.mocked(fixture.browser.scripting.executeScript).mockResolvedValueOnce([]);

    let failure: unknown;
    try {
      await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors[0]).toMatchObject({
      code: 'main_injection_failed',
    });
    expect(fixture.executeScript).toHaveBeenCalledOnce();
  });

  it('reports a missing second acknowledgement while the exact document remains current', async () => {
    const fixture = createBrowser({ sendMessage: () => undefined });
    const notify = createWebsitePasskeyTopFrameNotifier(fixture.browser);

    await expect(notify(ACTIVE_STATE)).rejects.toSatisfy((error: unknown) => {
      if (!(error instanceof AggregateError)) return false;
      const failure = error.errors[0];
      return failure instanceof WebsitePasskeyBrowserRuntimeError
        && failure.code === 'bridge_ack_missing';
    });
  });

  it('skips malformed, non-top, ineligible, and unavailable browser frame records', async () => {
    const fixture = createBrowser({
      tabs: [{ id: -1 }, { id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }],
      getFrame: (tabId) => {
        if (tabId === 1) return { frameId: 1, documentId: 'subframe', url: 'https://one.example/' };
        if (tabId === 2) return { frameId: 0, documentId: '', url: 'https://two.example/' };
        if (tabId === 3) return { frameId: 0, documentId: 'document-3', url: 'http://three.example/' };
        throw new Error('tab disappeared');
      },
    });

    await createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE);

    expect(fixture.getFrame).toHaveBeenCalledTimes(4);
    expect(fixture.sendMessage).not.toHaveBeenCalled();
    expect(fixture.contains).not.toHaveBeenCalled();
  });

  it('fails closed before browser access for malformed script state', async () => {
    const fixture = createBrowser();
    const notify = createWebsitePasskeyTopFrameNotifier(fixture.browser);

    await expect(notify({
      enabled: true,
      sessionState: 'unlocked',
      policyGeneration: -1,
    })).rejects.toMatchObject({ code: 'invalid_state' });
    expect(fixture.browser.tabs.query).not.toHaveBeenCalled();
  });

  it('sanitizes a tab enumeration failure', async () => {
    const fixture = createBrowser();
    vi.mocked(fixture.browser.tabs.query).mockRejectedValueOnce(
      new Error('Failed to enumerate https://private.example/?token=sensitive'),
    );

    await expect(createWebsitePasskeyTopFrameNotifier(fixture.browser)(ACTIVE_STATE))
      .rejects.toMatchObject({ code: 'tabs_query_failed' });
  });
});

describe('createBackgroundPortDispatcher', () => {
  function createPort(name: string) {
    return { name, disconnect: vi.fn() };
  }

  function createDispatcher() {
    const binaryTransferHandler = {
      handle: vi.fn((_port: ReturnType<typeof createPort>) => true),
    };
    const vaultTransferHandler = {
      handle: vi.fn((_port: ReturnType<typeof createPort>) => true),
    };
    const websitePasskeyHandler = {
      handle: vi.fn((_port: ReturnType<typeof createPort>) => true),
    };
    const dispatch = createBackgroundPortDispatcher({
      extensionBaseUrl: 'chrome-extension://extension-id/',
      extensionId: 'extension-id',
      vaultTransferHandler,
      websitePasskeyHandler,
      binaryTransferHandler,
    });
    return { dispatch, vaultTransferHandler, websitePasskeyHandler, binaryTransferHandler };
  }

  it('routes each exact Port name only to its owning handler', () => {
    const fixture = createDispatcher();
    const transfer = createPort(VAULT_TRANSFER_PORT_NAME);
    const passkey = createPort(WEBSITE_PASSKEY_PORT_NAME);
    const binary = createPort(BINARY_TRANSFER_PORT_NAME);

    fixture.dispatch(transfer);
    fixture.dispatch(passkey);
    fixture.dispatch(binary);

    expect(fixture.vaultTransferHandler.handle).toHaveBeenCalledOnce();
    expect(fixture.vaultTransferHandler.handle).toHaveBeenCalledWith(
      transfer,
      'chrome-extension://extension-id/',
      'extension-id',
    );
    expect(fixture.websitePasskeyHandler.handle).toHaveBeenCalledOnce();
    expect(fixture.websitePasskeyHandler.handle).toHaveBeenCalledWith(
      passkey,
      'chrome-extension://extension-id/',
      'extension-id',
    );
    expect(transfer.disconnect).not.toHaveBeenCalled();
    expect(passkey.disconnect).not.toHaveBeenCalled();
    expect(fixture.binaryTransferHandler.handle).toHaveBeenCalledOnce();
    expect(fixture.binaryTransferHandler.handle).toHaveBeenCalledWith(
      binary, 'chrome-extension://extension-id/', 'extension-id',
    );
    expect(binary.disconnect).not.toHaveBeenCalled();
  });

  it('disconnects an unknown Port exactly once without showing it to either handler', () => {
    const fixture = createDispatcher();
    const unknown = createPort('unknown-port');

    fixture.dispatch(unknown);

    expect(unknown.disconnect).toHaveBeenCalledOnce();
    expect(fixture.vaultTransferHandler.handle).not.toHaveBeenCalled();
    expect(fixture.websitePasskeyHandler.handle).not.toHaveBeenCalled();
    expect(fixture.binaryTransferHandler.handle).not.toHaveBeenCalled();
  });

  it('contains a matching handler throw and disconnects the affected Port', () => {
    const fixture = createDispatcher();
    const transfer = createPort(VAULT_TRANSFER_PORT_NAME);
    fixture.vaultTransferHandler.handle.mockImplementationOnce(() => {
      throw new Error('handler failed');
    });

    expect(() => fixture.dispatch(transfer)).not.toThrow();
    expect(transfer.disconnect).toHaveBeenCalledOnce();
    expect(fixture.websitePasskeyHandler.handle).not.toHaveBeenCalled();
  });

  it('lets a matching handler own a false return without double-disconnecting', () => {
    const fixture = createDispatcher();
    const passkey = createPort(WEBSITE_PASSKEY_PORT_NAME);
    fixture.websitePasskeyHandler.handle.mockImplementationOnce((port) => {
      port.disconnect();
      return false;
    });

    fixture.dispatch(passkey);

    expect(passkey.disconnect).toHaveBeenCalledOnce();
    expect(fixture.vaultTransferHandler.handle).not.toHaveBeenCalled();
  });
});
