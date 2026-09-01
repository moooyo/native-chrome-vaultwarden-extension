import { describe, expect, it, vi } from 'vitest';
import {
  registerAutofillSaveCaptureBrowserListeners,
  type AutofillSaveCaptureChromeApi,
} from './autofill-save-capture-browser.js';

function event() {
  let listener: ((details: Record<string, unknown>) => void) | undefined;
  const addListener = vi.fn((next: (details: Record<string, unknown>) => void) => {
    listener = next;
  });
  return {
    addListener,
    emit(details: Record<string, unknown>) { listener?.(details); },
  };
}

function fixture() {
  const onBeforeRequest = event();
  const onBeforeRedirect = event();
  const onCompleted = event();
  const onErrorOccurred = event();
  const coordinator = {
    observeBeforeRequest: vi.fn(async () => {}),
    observeRedirect: vi.fn(async () => {}),
    observeCompleted: vi.fn(async () => {}),
    observeError: vi.fn(async () => {}),
    invalidateNetworkWindow: vi.fn(async () => {}),
  };
  const warn = vi.fn();
  const getFrame = vi.fn(async (): Promise<{ documentId: string; url: string } | null> => ({
    documentId: 'source-document',
    url: COMMON.originUrl,
  }));
  const chromeApi = {
    webRequest: { onBeforeRequest, onBeforeRedirect, onCompleted, onErrorOccurred },
    webNavigation: { getFrame },
  } as unknown as AutofillSaveCaptureChromeApi;
  return {
    onBeforeRequest,
    onBeforeRedirect,
    onCompleted,
    onErrorOccurred,
    coordinator,
    warn,
    getFrame,
    register: () => registerAutofillSaveCaptureBrowserListeners(chromeApi, coordinator, { warn }),
  };
}

const COMMON = Object.freeze({
  requestId: 'request-1',
  tabId: 7,
  frameId: 0,
  documentId: 'document-A',
  documentUrl: 'https://accounts.example.com/login?private=source',
  originUrl: 'https://accounts.example.com/login?private=source',
  initiator: 'https://accounts.example.com',
  url: 'https://api.example.com/session?private=request',
  method: 'POST',
  type: 'xmlhttprequest',
  timeStamp: 1_000.75,
});

describe('registerAutofillSaveCaptureBrowserListeners', () => {
  it('registers non-blocking HTTP listeners without requestBody access', () => {
    const f = fixture();
    expect(f.register()).toBe(true);

    for (const entry of [f.onBeforeRequest, f.onBeforeRedirect, f.onCompleted, f.onErrorOccurred]) {
      expect(entry.addListener).toHaveBeenCalledWith(expect.any(Function), {
        urls: ['http://*/*', 'https://*/*'],
        types: ['main_frame', 'sub_frame', 'xmlhttprequest'],
      });
      expect(entry.addListener.mock.calls[0]).toHaveLength(2);
    }
  });

  it('resolves Chromium XHR and navigation sources without Firefox-only URL fields', async () => {
    const f = fixture();
    f.getFrame.mockResolvedValueOnce({
      documentId: COMMON.documentId,
      url: COMMON.documentUrl,
    });
    f.register();
    f.onBeforeRequest.emit({
      ...COMMON,
      documentUrl: undefined,
      originUrl: undefined,
      requestBody: { raw: [{ bytes: new Uint8Array([1]) }] },
    });
    await vi.waitFor(() => expect(f.coordinator.observeBeforeRequest).toHaveBeenCalledOnce());
    expect(f.coordinator.observeBeforeRequest).toHaveBeenCalledWith({
      requestId: COMMON.requestId,
      tabId: COMMON.tabId,
      frameId: COMMON.frameId,
      documentId: COMMON.documentId,
      sourceDocumentUrl: COMMON.originUrl,
      initiator: COMMON.initiator,
      url: COMMON.url,
      method: COMMON.method,
      type: COMMON.type,
      timeStamp: COMMON.timeStamp,
    });
    expect(JSON.stringify(f.coordinator.observeBeforeRequest.mock.calls)).not.toContain('requestBody');

    f.coordinator.observeBeforeRequest.mockClear();
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'navigation-without-origin-url',
      type: 'main_frame',
      documentUrl: undefined,
      originUrl: undefined,
    });
    await vi.waitFor(() => expect(f.coordinator.observeBeforeRequest).toHaveBeenCalledWith(expect.objectContaining({
      documentId: 'source-document',
      sourceDocumentUrl: COMMON.originUrl,
      url: COMMON.url,
      type: 'main_frame',
    })));

    f.coordinator.observeBeforeRequest.mockClear();
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'navigation-mismatched-origin-url',
      type: 'main_frame',
      originUrl: 'https://other.example.com/',
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(f.coordinator.observeBeforeRequest).not.toHaveBeenCalled();
  });

  it('forwards terminal and redirect evidence with method and resource type', async () => {
    const f = fixture();
    f.register();
    f.onBeforeRedirect.emit({
      ...COMMON,
      redirectUrl: 'https://app.example.com/complete',
      statusCode: 302,
    });
    f.onCompleted.emit({ ...COMMON, method: 'GET', statusCode: 200 });
    f.onErrorOccurred.emit({ ...COMMON, method: 'GET' });

    await vi.waitFor(() => expect(f.coordinator.observeError).toHaveBeenCalledOnce());

    expect(f.coordinator.observeRedirect).toHaveBeenCalledWith(expect.objectContaining({
      method: 'POST', type: 'xmlhttprequest', statusCode: 302,
    }));
    expect(f.coordinator.observeCompleted).toHaveBeenCalledWith(expect.objectContaining({
      method: 'GET', type: 'xmlhttprequest', statusCode: 200,
    }));
    expect(f.coordinator.observeError).toHaveBeenCalledWith(expect.objectContaining({
      method: 'GET', type: 'xmlhttprequest',
    }));
  });

  it('serializes navigation source resolution ahead of fast redirect and completion events', async () => {
    const f = fixture();
    let resolveFrame!: (frame: { documentId: string; url: string }) => void;
    f.getFrame.mockImplementationOnce(() => new Promise<{ documentId: string; url: string }>((resolve) => {
      resolveFrame = resolve;
    }));
    f.register();
    f.onBeforeRequest.emit({
      ...COMMON,
      type: 'main_frame',
      documentId: 'target-document',
      documentUrl: 'https://app.example.com/complete',
    });
    f.onBeforeRedirect.emit({
      ...COMMON,
      type: 'main_frame',
      documentId: 'target-document',
      redirectUrl: 'https://app.example.com/complete',
      statusCode: 302,
    });
    f.onCompleted.emit({
      ...COMMON,
      type: 'main_frame',
      documentId: 'destination-document',
      url: 'https://app.example.com/complete',
      method: 'GET',
      statusCode: 200,
    });

    await Promise.resolve();
    expect(f.coordinator.observeBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.observeRedirect).not.toHaveBeenCalled();
    expect(f.coordinator.observeCompleted).not.toHaveBeenCalled();
    resolveFrame({ documentId: 'source-document', url: COMMON.originUrl });
    await vi.waitFor(() => expect(f.coordinator.observeCompleted).toHaveBeenCalledOnce());

    expect(f.coordinator.observeBeforeRequest.mock.invocationCallOrder[0])
      .toBeLessThan(f.coordinator.observeRedirect.mock.invocationCallOrder[0]!);
    expect(f.coordinator.observeRedirect.mock.invocationCallOrder[0])
      .toBeLessThan(f.coordinator.observeCompleted.mock.invocationCallOrder[0]!);
  });

  it('ignores malformed, bodyless GET starts and unavailable APIs', () => {
    const f = fixture();
    f.register();
    f.onBeforeRequest.emit({ ...COMMON, method: 'GET' });
    f.onBeforeRequest.emit({ ...COMMON, documentId: undefined });
    f.onCompleted.emit({ ...COMMON, statusCode: '200' });
    expect(f.coordinator.observeBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.observeCompleted).not.toHaveBeenCalled();
    expect(registerAutofillSaveCaptureBrowserListeners(undefined, f.coordinator)).toBe(false);
  });

  it('contains async failures behind fixed non-sensitive log events', async () => {
    const f = fixture();
    f.getFrame.mockResolvedValueOnce({
      documentId: COMMON.documentId,
      url: COMMON.documentUrl,
    });
    f.coordinator.observeBeforeRequest.mockRejectedValueOnce(new Error('private URL must not be logged'));
    f.register();
    f.onBeforeRequest.emit(COMMON);
    await vi.waitFor(() => expect(f.warn).toHaveBeenCalledWith('before_request'));

    expect(f.warn).not.toHaveBeenCalledWith(expect.stringContaining('private'));
  });

  it('invalidates the correlation window instead of dropping evidence when request lanes overflow', async () => {
    const f = fixture();
    f.getFrame.mockImplementation(() => new Promise(() => {}));
    f.register();
    for (let index = 0; index <= 128; index += 1) {
      f.onBeforeRequest.emit({
        ...COMMON,
        requestId: `request-${index}`,
        type: 'main_frame',
      });
    }

    expect(f.coordinator.invalidateNetworkWindow).toHaveBeenCalledOnce();
  });
});
