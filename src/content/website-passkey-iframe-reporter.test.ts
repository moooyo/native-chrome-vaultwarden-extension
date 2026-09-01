// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY } from '../messaging/website-passkey-iframe-inventory.js';
import { WebsitePasskeyIframeReporter } from './website-passkey-iframe-reporter.js';

afterEach(() => {
  document.head.innerHTML = '';
  document.body.innerHTML = '';
  vi.restoreAllMocks();
});

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('WebsitePasskeyIframeReporter', () => {
  it('observes iframe and base attributes before scanning the root', async () => {
    const observe = vi.fn();
    const disconnect = vi.fn();
    let observedBeforeScan = false;
    vi.spyOn(document, 'querySelectorAll').mockImplementation(() => {
      observedBeforeScan = observe.mock.calls.length > 0;
      return [] as unknown as NodeListOf<Element>;
    });
    const reporter = new WebsitePasskeyIframeReporter({
      report: async () => ({ ok: true, data: null }),
      createObserver: () => ({ observe, disconnect } as unknown as MutationObserver),
    });
    reporter.start();
    await settle();

    expect(observedBeforeScan).toBe(true);
    expect(observe).toHaveBeenCalledWith(document, expect.objectContaining({
      attributes: true,
      attributeFilter: ['allow', 'href', 'src', 'srcdoc'],
      childList: true,
      subtree: true,
    }));
    reporter.stop();
    expect(disconnect).toHaveBeenCalledOnce();
  });

  it('reports empty snapshots and resolves document/open-shadow iframe attributes', async () => {
    (window as unknown as { happyDOM: { setURL(url: string): void } }).happyDOM.setURL(
      'https://parent.example/path/page',
    );
    const reports: unknown[] = [];
    const reporter = new WebsitePasskeyIframeReporter({
      report: async (request) => { reports.push(request); },
    });
    reporter.start();
    await settle();
    expect(reports).toEqual([{
      type: 'websitePasskey.reportIframeInventory',
      iframes: [],
    }]);

    const direct = document.createElement('iframe');
    direct.setAttribute('src', 'data:text/html,child');
    direct.setAttribute('allow', 'publickey-credentials-get');
    document.body.append(direct);
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    const nested = document.createElement('iframe');
    nested.setAttribute('srcdoc', '<p>inline</p>');
    nested.setAttribute('allow', 'publickey-credentials-create');
    shadow.append(nested);
    document.body.append(host);
    await settle();

    expect(reports.at(-1)).toEqual({
      type: 'websitePasskey.reportIframeInventory',
      iframes: [
        {
          src: 'data:text/html,child',
          allow: 'publickey-credentials-get',
          srcdoc: false,
        },
        { src: '', allow: 'publickey-credentials-create', srcdoc: true },
      ],
    });
    reporter.stop();
  });

  it('discovers an open shadow root attached after its host without a light-DOM mutation', async () => {
    let rescan: (() => void) | undefined;
    const report = vi.fn(async (_request: unknown) => ({ ok: true, data: null }));
    const reporter = new WebsitePasskeyIframeReporter({
      report,
      scheduleShadowRootRescan(callback) {
        rescan = callback;
        return () => { rescan = undefined; };
      },
    });
    const host = document.createElement('div');
    document.body.append(host);
    reporter.start();
    await settle();

    const shadow = host.attachShadow({ mode: 'open' });
    const iframe = document.createElement('iframe');
    iframe.setAttribute('src', 'data:text/html,shadow-child');
    shadow.append(iframe);
    await settle();
    expect(report).toHaveBeenCalledOnce();

    rescan?.();
    await settle();
    expect(report).toHaveBeenCalledTimes(2);
    expect(report.mock.calls[1]?.[0]).toMatchObject({
      iframes: [{ src: 'data:text/html,shadow-child' }],
    });
    reporter.stop();
  });

  it('coalesces mutations behind one in-flight report and reruns when dirty', async () => {
    let release!: () => void;
    const first = new Promise<void>((resolve) => { release = resolve; });
    const report = vi.fn()
      .mockImplementationOnce(() => first)
      .mockResolvedValue(undefined);
    const reporter = new WebsitePasskeyIframeReporter({ report });
    reporter.start();
    await settle();
    expect(report).toHaveBeenCalledOnce();

    document.body.append(document.createElement('iframe'));
    document.head.append(document.createElement('base'));
    await settle();
    expect(report).toHaveBeenCalledOnce();

    release();
    await settle();
    expect(report).toHaveBeenCalledTimes(2);
    reporter.stop();
  });

  it('deduplicates acknowledged fingerprints and force-reports source changes and pageshow', async () => {
    (window as unknown as { happyDOM: { setURL(url: string): void } }).happyDOM.setURL(
      'https://parent.example/root/page',
    );
    const base = document.createElement('base');
    base.href = 'https://parent.example/first/';
    document.head.append(base);
    const iframe = document.createElement('iframe');
    iframe.setAttribute('src', 'child');
    vi.spyOn(document, 'querySelectorAll').mockReturnValue(
      [iframe] as unknown as NodeListOf<Element>,
    );
    const report = vi.fn(async (_request: unknown) => ({ ok: true, data: null }));
    const reporter = new WebsitePasskeyIframeReporter({ report });
    reporter.start();
    await settle();
    expect(report).toHaveBeenCalledOnce();

    document.body.append(document.createElement('div'));
    await settle();
    expect(report).toHaveBeenCalledOnce();

    base.setAttribute('href', 'https://parent.example/second/');
    // happy-dom does not recompute a detached iframe's reflected relative URL after a base change.
    iframe.setAttribute('src', 'https://parent.example/second/child');
    reporter.markDirty();
    await settle();
    expect(report).toHaveBeenCalledTimes(2);
    expect(report.mock.calls[1]?.[0]).toMatchObject({
      iframes: [{ src: 'https://parent.example/second/child' }],
    });

    window.dispatchEvent(new Event('pageshow'));
    await settle();
    expect(report).toHaveBeenCalledTimes(3);
    reporter.stop();
  });

  it('distinguishes a missing src attribute from an explicit empty canonical src', async () => {
    (window as unknown as { happyDOM: { setURL(url: string): void } }).happyDOM.setURL(
      'https://parent.example/current/page',
    );
    const iframe = document.createElement('iframe');
    iframe.setAttribute('src', '');
    vi.spyOn(document, 'querySelectorAll').mockReturnValue(
      [iframe] as unknown as NodeListOf<Element>,
    );
    const report = vi.fn(async (_request: unknown) => ({ ok: true, data: null }));
    const reporter = new WebsitePasskeyIframeReporter({ report });
    reporter.start();
    await settle();

    expect(report).toHaveBeenCalledWith({
      type: 'websitePasskey.reportIframeInventory',
      iframes: [{ src: 'https://parent.example/current/page', allow: '', srcdoc: false }],
    });
    reporter.stop();
  });

  it('does not deduplicate a fingerprint whose worker acknowledgement was unavailable', async () => {
    const report = vi.fn(async (_request: unknown) => undefined);
    const reporter = new WebsitePasskeyIframeReporter({ report });
    reporter.start();
    await settle();
    document.body.append(document.createElement('div'));
    await settle();
    expect(report).toHaveBeenCalledTimes(2);
    reporter.stop();
  });

  it('sends a bounded malformed sentinel so an over-limit document revokes old authority', async () => {
    for (let index = 0; index <= MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY; index += 1) {
      document.body.append(document.createElement('iframe'));
    }
    const report = vi.fn(async (_request: unknown) => undefined);
    const reporter = new WebsitePasskeyIframeReporter({ report });
    reporter.start();
    await settle();

    const snapshot = report.mock.calls[0]?.[0] as { iframes?: unknown[] } | undefined;
    expect(snapshot?.iframes).toHaveLength(MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY + 1);
    reporter.stop();
  });
});
