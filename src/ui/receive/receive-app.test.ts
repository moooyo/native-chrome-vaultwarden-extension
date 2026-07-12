// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    permissions: { request: vi.fn(async () => true) },
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

import './receive-app.js';
import type { VwReceiveApp } from './receive-app.js';
import type { ReceiveDeps } from './types.js';
import { deriveSendKey } from '../../core/vault/sends.js';
import { encryptToText } from '../../core/crypto/encstring.js';
import { bytesToBase64Url } from '../../core/crypto/encoding.js';
import { encryptAttachmentFile } from '../../core/vault/attachments.js';

const sendKey = new Uint8Array(16).fill(7);

function linkFor(accessId: string): string {
  return `https://vault.example/#/send/${accessId}/${bytesToBase64Url(sendKey)}`;
}

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

type FetchImpl = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

interface DepStubs {
  deps: ReceiveDeps;
  requestOrigin: ReturnType<typeof vi.fn>;
  download: ReturnType<typeof vi.fn>;
  fetchCalls: string[];
}

function makeDeps(overrides: Partial<{
  requestOriginResult: boolean;
  fetchImpl: FetchImpl;
}> = {}): DepStubs {
  const fetchCalls: string[] = [];
  const fetchImpl = overrides.fetchImpl ?? (async () => jsonRes({}));
  const wrappedFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    fetchCalls.push(String(input));
    return fetchImpl(input, init);
  }) as typeof fetch;
  const requestOrigin = vi.fn(async () => overrides.requestOriginResult ?? true);
  const download = vi.fn();
  const deps: ReceiveDeps = { fetch: wrappedFetch, requestOrigin, download };
  return { deps, requestOrigin, download, fetchCalls };
}

function flushAsync(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Waits until the app leaves a busy state (`accessing`/`downloading`). Real PBKDF2/HKDF work runs
 *  through actual WebCrypto, which resolves via the platform's async work queue rather than a
 *  single microtask/macrotask turn, so a plain `flushAsync()` is not always enough. */
async function settle(app: VwReceiveApp): Promise<void> {
  for (let i = 0; i < 100; i++) {
    await flushAsync();
    await app.updateComplete;
    if (app.state.status !== 'accessing' && app.state.status !== 'downloading') return;
  }
}

async function mount(deps: ReceiveDeps): Promise<VwReceiveApp> {
  const app = document.createElement('vw-receive-app') as VwReceiveApp;
  app.deps = deps;
  document.body.append(app);
  await app.updateComplete;
  return app;
}

function linkInput(app: VwReceiveApp): HTMLInputElement {
  return app.shadowRoot!.querySelector<HTMLInputElement>('[data-link]')!;
}
function passwordInput(app: VwReceiveApp): HTMLInputElement | null {
  return app.shadowRoot!.querySelector<HTMLInputElement>('[data-password]');
}
function accessButton(app: VwReceiveApp): HTMLButtonElement {
  return app.shadowRoot!.querySelector<HTMLButtonElement>('[data-access]')!;
}
function downloadButton(app: VwReceiveApp): HTMLButtonElement | null {
  return app.shadowRoot!.querySelector<HTMLButtonElement>('[data-download]');
}

it('renders a focused page task with a heading and constrained body', async () => {
  const app = await mount(makeDeps().deps);
  expect(app.shadowRoot!.querySelector('[data-page-heading]')?.textContent).toContain('接收 Send');
  expect(app.shadowRoot!.querySelector('[data-task-column]')).not.toBeNull();
});

async function accessFor(app: VwReceiveApp, link: string, password?: string): Promise<void> {
  linkInput(app).value = link;
  accessButton(app).click();
  await settle(app);
  if (password !== undefined) {
    passwordInput(app)!.value = password;
    accessButton(app).click();
    await settle(app);
  }
}

describe('vw-receive-app invalid link', () => {
  afterEach(() => document.body.replaceChildren());

  it('shows an error and never requests permission or fetches for a malformed link', async () => {
    const stubs = makeDeps();
    const app = await mount(stubs.deps);
    linkInput(app).value = 'not a send link';
    accessButton(app).click();
    await flushAsync();
    await app.updateComplete;
    expect(app.state).toEqual({ status: 'error', message: '无效的 Send 链接' });
    expect(stubs.requestOrigin).not.toHaveBeenCalled();
    expect(stubs.fetchCalls).toHaveLength(0);
  });
});

describe('vw-receive-app permission gesture', () => {
  afterEach(() => document.body.replaceChildren());

  it('requests host permission as the first await, before any fetch', async () => {
    let resolveOrigin: (v: boolean) => void = () => {};
    const stubs = makeDeps();
    stubs.requestOrigin.mockImplementation(() => new Promise<boolean>((resolve) => { resolveOrigin = resolve; }));
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();

    // Permission is requested synchronously in the click; nothing has been fetched yet.
    expect(stubs.requestOrigin).toHaveBeenCalledWith('https://vault.example/*');
    expect(stubs.fetchCalls).toHaveLength(0);
    expect(app.state.status).toBe('accessing');

    resolveOrigin(true);
    await flushAsync();
    await app.updateComplete;
    expect(stubs.fetchCalls.length).toBeGreaterThan(0);
  });

  it('shows an error and does not fetch when permission is denied', async () => {
    const stubs = makeDeps({ requestOriginResult: false });
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    await settle(app);
    expect(app.state).toMatchObject({ status: 'error' });
    expect((app.state as { message: string }).message).toContain('vault.example');
    expect(stubs.fetchCalls).toHaveLength(0);
  });
});

describe('vw-receive-app password required', () => {
  afterEach(() => document.body.replaceChildren());

  it('shows the password field, focuses it, and does not clear it as an error', async () => {
    const stubs = makeDeps({
      fetchImpl: async (input) => (String(input).includes('/access/') ? new Response('', { status: 401 }) : jsonRes({})),
    });
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    await settle(app);
    expect(app.state).toEqual({ status: 'passwordRequired', message: '此 Send 需要访问密码' });
    const pwInput = passwordInput(app);
    expect(pwInput).not.toBeNull();
    expect(app.shadowRoot!.activeElement).toBe(pwInput);
  });
});

describe('vw-receive-app text send', () => {
  afterEach(() => document.body.replaceChildren());

  it('decrypts and shows the send name and text', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-1', type: 0, name: await encryptToText('Greeting', derived), text: { text: await encryptToText('hello there', derived) } };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    expect(app.state).toEqual({ status: 'textReady', name: 'Greeting', text: 'hello there' });
    expect(app.shadowRoot!.textContent).toContain('Greeting');
    expect(app.shadowRoot!.textContent).toContain('hello there');
  });

  it('sends the password hash once the user supplies one after password_required', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-1', type: 0, name: await encryptToText('Greeting', derived), text: { text: await encryptToText('secret', derived) } };
    let seenBody: string | undefined;
    const stubs = makeDeps({
      fetchImpl: async (input, init) => {
        if (String(input).includes('/access/')) {
          seenBody = init?.body as string | undefined;
          const parsed = seenBody ? (JSON.parse(seenBody) as { password?: string }) : {};
          return parsed.password ? jsonRes(raw) : new Response('', { status: 401 });
        }
        return jsonRes({});
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'), 'the-password');
    expect(app.state).toMatchObject({ status: 'textReady', name: 'Greeting' });
    expect(seenBody).toBeDefined();
    expect(JSON.parse(seenBody!)).toHaveProperty('password');
  });
});

describe('vw-receive-app file send', () => {
  afterEach(() => document.body.replaceChildren());

  it('decrypts and shows file metadata with a Download button', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' },
    };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    expect(app.state).toMatchObject({ status: 'fileReady' });
    expect(app.shadowRoot!.textContent).toContain('Doc');
    expect(app.shadowRoot!.textContent).toContain('secret.pdf');
    expect(app.shadowRoot!.textContent).toContain('3 KB');
    expect(downloadButton(app)).not.toBeNull();
  });

  it('downloads and decrypts the file, invoking deps.download with the decrypted bytes', async () => {
    const derived = await deriveSendKey(sendKey);
    const fileBytes = new Uint8Array([9, 8, 7, 6]);
    const blob = await encryptAttachmentFile(fileBytes, derived);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' },
    };
    const stubs = makeDeps({
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.includes('/access/file/')) return jsonRes({ url: 'https://vault.example/dl?t=jwt' });
        if (url.includes('/dl?t=jwt')) return new Response(Buffer.from(blob));
        return jsonRes(raw);
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    downloadButton(app)!.click();
    await settle(app);
    expect(stubs.download).toHaveBeenCalledTimes(1);
    const [bytes, fileName] = stubs.download.mock.calls[0]!;
    expect(Array.from(bytes as Uint8Array)).toEqual([9, 8, 7, 6]);
    expect(fileName).toBe('secret.pdf');
    expect(app.state).toMatchObject({ status: 'fileReady' });
  });

  it('does not download twice on a rapid double click', async () => {
    const derived = await deriveSendKey(sendKey);
    const fileBytes = new Uint8Array([1, 2, 3]);
    const blob = await encryptAttachmentFile(fileBytes, derived);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' },
    };
    let fileUrlCalls = 0;
    const stubs = makeDeps({
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.includes('/access/file/')) {
          fileUrlCalls += 1;
          return jsonRes({ url: 'https://vault.example/dl?t=jwt' });
        }
        if (url.includes('/dl?t=jwt')) return new Response(Buffer.from(blob));
        return jsonRes(raw);
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    downloadButton(app)!.click();
    downloadButton(app)?.click();
    await settle(app);
    expect(fileUrlCalls).toBe(1);
    expect(stubs.download).toHaveBeenCalledTimes(1);
  });

  it('shows unavailable when the send is missing file id/send id', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: '', type: 1, name: await encryptToText('Doc', derived), file: { fileName: await encryptToText('secret.pdf', derived), sizeName: '3 KB' } };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    expect(app.state).toMatchObject({ status: 'fileReady' });
    downloadButton(app)!.click();
    await settle(app);
    expect(app.state).toEqual({ status: 'error', message: '此 Send 已过期或已达到访问次数上限' });
    expect(stubs.download).not.toHaveBeenCalled();
  });

  it('shows a decrypt error when the downloaded blob is corrupt', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' },
    };
    const stubs = makeDeps({
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.includes('/access/file/')) return jsonRes({ url: 'https://vault.example/dl?t=jwt' });
        if (url.includes('/dl?t=jwt')) return new Response(Buffer.from(new Uint8Array([2, 0, 0])));
        return jsonRes(raw);
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    downloadButton(app)!.click();
    await settle(app);
    expect(app.state).toEqual({ status: 'error', message: '无法解密，链接或文件可能已损坏' });
    expect(stubs.download).not.toHaveBeenCalled();
  });
});

describe('vw-receive-app unavailable send', () => {
  afterEach(() => document.body.replaceChildren());

  it('shows unavailable when the server rejects the access request', async () => {
    const stubs = makeDeps({ fetchImpl: async () => new Response('', { status: 404 }) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    expect(app.state).toEqual({ status: 'error', message: '此 Send 已过期或已达到访问次数上限' });
  });
});

describe('vw-receive-app double-submit prevention on Access', () => {
  afterEach(() => document.body.replaceChildren());

  it('ignores a second Access click while the first is still in flight', async () => {
    let resolveOrigin: (v: boolean) => void = () => {};
    const stubs = makeDeps();
    stubs.requestOrigin.mockImplementation(() => new Promise<boolean>((resolve) => { resolveOrigin = resolve; }));
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    accessButton(app).click();
    accessButton(app).click();
    expect(stubs.requestOrigin).toHaveBeenCalledTimes(1);
    resolveOrigin(true);
    await settle(app);
  });
});

describe('vw-receive-app default deps object URL cleanup', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.replaceChildren();
  });

  it('creates and revokes an object URL and clicks an anchor when downloading with the real deps', async () => {
    const created = 'blob:mock-url';
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue(created);
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const clickSpy = vi.fn();
    const realCreate = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = realCreate(tag) as HTMLElement;
      if (tag === 'a') el.click = clickSpy;
      return el;
    });

    const app = document.createElement('vw-receive-app') as VwReceiveApp;
    document.body.append(app);
    await app.updateComplete;
    app.deps.download(new Uint8Array([1, 2, 3]), 'file.bin');

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith(created);
  });
});
