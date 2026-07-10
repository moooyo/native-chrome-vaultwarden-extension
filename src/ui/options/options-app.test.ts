// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: { sendMessage: vi.fn(), getURL: vi.fn((path: string) => path), getManifest: vi.fn(() => ({ version: '0.0.0' })) },
    permissions: { request: vi.fn(async () => true) },
  },
}));

import './options-app.js';
import type { VwOptionsApp } from './options-app.js';
import type { OptionsDeps, OptionsRequest, LoadedSettings } from './types.js';
import type { VwConnectionSection } from './sections/connection-section.js';
import type { VwDataSection } from './sections/data-section.js';
import type { VwPageShell } from '../components/page-shell.js';

type Req = Parameters<OptionsRequest>[0];
type Res = Awaited<ReturnType<OptionsRequest>>;
type ReqHandler<K extends Req['type']> = (req: Extract<Req, { type: K }>) => Res | Promise<Res>;

function fakeRequest(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>): OptionsRequest {
  const dispatch = async (req: Req): Promise<Res> => {
    const handler = handlers[req.type] as ReqHandler<Req['type']> | undefined;
    if (handler) return handler(req);
    return { ok: true, data: null };
  };
  return dispatch as OptionsRequest;
}

const loadedSettings: LoadedSettings = {
  serverUrl: 'http://10.0.1.20:8080/',
  defaultUriMatchStrategy: 0,
  lockTimeout: '15',
  onIdleAction: 'lock',
  clipboardClearSeconds: '60',
};

interface DepStubs {
  deps: OptionsDeps;
  calls: string[];
  requestOrigins: ReturnType<typeof vi.fn>;
  downloadText: ReturnType<typeof vi.fn>;
  readFile: ReturnType<typeof vi.fn>;
}

function makeDeps(overrides: Partial<{
  handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>;
  state: 'locked' | 'unlocked' | 'loggedOut';
  requestOriginsResult: boolean;
  readFileResult: string;
}> = {}): DepStubs {
  const calls: string[] = [];
  const state = overrides.state ?? 'unlocked';
  const baseHandlers: Partial<{ [K in Req['type']]: ReqHandler<K> }> = {
    'auth.getState': async () => ({ ok: true, data: { state } }),
    'settings.get': async () => ({ ok: true, data: loadedSettings }),
    ...overrides.handlers,
  };
  const wrapped = fakeRequest(baseHandlers);
  const request: OptionsRequest = (req) => {
    calls.push(req.type);
    return wrapped(req);
  };
  const requestOrigins = vi.fn(async () => overrides.requestOriginsResult ?? true);
  const downloadText = vi.fn();
  const readFile = vi.fn(async () => overrides.readFileResult ?? '[]');
  const deps: OptionsDeps = {
    request,
    requestOrigins,
    downloadText,
    readFile,
    extensionVersion: () => '9.9.9',
  };
  return { deps, calls, requestOrigins, downloadText, readFile };
}

function flushAsync(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function mount(stubs: DepStubs): Promise<VwOptionsApp> {
  const app = document.createElement('vw-options-app') as VwOptionsApp;
  app.deps = stubs.deps;
  document.body.append(app);
  await flushAsync();
  await app.updateComplete;
  return app;
}

function section<T extends Element>(app: VwOptionsApp, tag: string): T {
  return app.shadowRoot!.querySelector<T>(tag)!;
}

async function show(app: VwOptionsApp, id: string): Promise<void> {
  app.selected = id as VwOptionsApp['selected'];
  await app.updateComplete;
}

describe('vw-options-app rail', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders a five-section rail: Connection, Security, Autofill, Data, About', async () => {
    const app = await mount(makeDeps());
    const shell = section<VwPageShell>(app, 'vw-page-shell');
    expect(shell.items.map((i) => i.id)).toEqual(['connection', 'security', 'autofill', 'data', 'about']);
  });

  it('passes narrow mode through to the page shell', async () => {
    const app = await mount(makeDeps());
    app.narrow = true;
    await app.updateComplete;
    const shell = section<VwPageShell>(app, 'vw-page-shell');
    expect(shell.narrow).toBe(true);
  });

  it('switches the active section on vw-tab-change', async () => {
    const app = await mount(makeDeps());
    const shell = section<VwPageShell>(app, 'vw-page-shell');
    shell.dispatchEvent(new CustomEvent('vw-tab-change', { detail: { id: 'about' }, bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.selected).toBe('about');
    expect(section(app, 'vw-about-section')).toBeTruthy();
  });
});

describe('vw-options-app connection save', () => {
  afterEach(() => document.body.replaceChildren());

  it('requests host permission synchronously before any save await, then saves the normalized URL', async () => {
    let resolveOrigins: (v: boolean) => void = () => {};
    const stubs = makeDeps();
    stubs.requestOrigins.mockImplementation(() => new Promise<boolean>((r) => { resolveOrigins = r; }));
    const app = await mount(stubs);
    await show(app, 'connection');
    const conn = section<VwConnectionSection>(app, 'vw-connection-section');
    conn.shadowRoot!.querySelector<HTMLInputElement>('[data-server-url]')!.value = 'http://example.com';
    conn.shadowRoot!.querySelector<HTMLButtonElement>('[data-save]')!.click();

    // Permission is requested in the gesture, before settings.save is awaited.
    expect(stubs.requestOrigins).toHaveBeenCalledWith(['http://example.com/*']);
    expect(stubs.calls).not.toContain('settings.save');

    resolveOrigins(true);
    await flushAsync();
    await app.updateComplete;
    expect(stubs.calls).toContain('settings.save');
  });

  it('does not save when host permission is denied', async () => {
    const stubs = makeDeps({ requestOriginsResult: false });
    const app = await mount(stubs);
    await show(app, 'connection');
    const conn = section<VwConnectionSection>(app, 'vw-connection-section');
    conn.shadowRoot!.querySelector<HTMLInputElement>('[data-server-url]')!.value = 'http://example.com';
    conn.shadowRoot!.querySelector<HTMLButtonElement>('[data-save]')!.click();
    await flushAsync();
    await app.updateComplete;
    expect(stubs.calls).not.toContain('settings.save');
    expect(conn.status?.tone).toBe('danger');
  });
});

describe('vw-options-app autofill and lock timeout reuse the loaded URL', () => {
  afterEach(() => document.body.replaceChildren());

  it('saves the strategy with the loaded server URL and without re-prompting for permission', async () => {
    let saved: Req | undefined;
    const stubs = makeDeps({ handlers: { 'settings.save': async (req) => { saved = req; return { ok: true, data: null }; } } });
    const app = await mount(stubs);
    await show(app, 'autofill');
    const autofill = section(app, 'vw-autofill-section');
    (autofill as HTMLElement).dispatchEvent(new CustomEvent('vw-autofill-save', { detail: { defaultUriMatchStrategy: 1 }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(stubs.requestOrigins).not.toHaveBeenCalled();
    expect(saved).toEqual({ type: 'settings.save', serverUrl: 'http://10.0.1.20:8080/', defaultUriMatchStrategy: 1 });
  });

  it('saves the lock timeout with the loaded server URL and without re-prompting', async () => {
    let saved: Req | undefined;
    const stubs = makeDeps({ handlers: { 'settings.save': async (req) => { saved = req; return { ok: true, data: null }; } } });
    const app = await mount(stubs);
    await show(app, 'security');
    const security = section(app, 'vw-security-section');
    (security as HTMLElement).dispatchEvent(new CustomEvent('vw-lock-timeout-save', { detail: { lockTimeout: '30' }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(stubs.requestOrigins).not.toHaveBeenCalled();
    expect(saved).toEqual({ type: 'settings.save', serverUrl: 'http://10.0.1.20:8080/', lockTimeout: '30' });
  });

  it('saves idle/clipboard security settings on change', async () => {
    let saved: Req | undefined;
    const stubs = makeDeps({ handlers: { 'settings.saveSecurity': async (req) => { saved = req; return { ok: true, data: null }; } } });
    const app = await mount(stubs);
    await show(app, 'security');
    const security = section(app, 'vw-security-section');
    (security as HTMLElement).dispatchEvent(new CustomEvent('vw-security-save', { detail: { onIdleAction: 'logout', clipboardClearSeconds: '120' }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(saved).toEqual({ type: 'settings.saveSecurity', onIdleAction: 'logout', clipboardClearSeconds: '120' });
  });
});

describe('vw-options-app data section', () => {
  afterEach(() => document.body.replaceChildren());

  it('marks the Data section locked when the vault is locked', async () => {
    const app = await mount(makeDeps({ state: 'locked' }));
    await show(app, 'data');
    expect(section<VwDataSection>(app, 'vw-data-section').locked).toBe(true);
  });

  it('marks the Data section unlocked when the vault is unlocked', async () => {
    const app = await mount(makeDeps({ state: 'unlocked' }));
    await show(app, 'data');
    expect(section<VwDataSection>(app, 'vw-data-section').locked).toBe(false);
  });

  it('downloads an encrypted export with an encrypted filename', async () => {
    const stubs = makeDeps({ handlers: { 'vault.export': async () => ({ ok: true, data: { json: '{"encrypted":true}' } }) } });
    const app = await mount(stubs);
    await show(app, 'data');
    section(app, 'vw-data-section').dispatchEvent(new CustomEvent('vw-export', { detail: { password: 'pw' }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(stubs.downloadText).toHaveBeenCalledTimes(1);
    const [content, fileName] = stubs.downloadText.mock.calls[0]!;
    expect(content).toBe('{"encrypted":true}');
    expect(fileName).toMatch(/^vaultwarden-export-encrypted-\d{4}-\d{2}-\d{2}\.json$/);
  });

  it('downloads a plaintext export with a plain filename', async () => {
    const stubs = makeDeps({ handlers: { 'vault.export': async () => ({ ok: true, data: { json: '{}' } }) } });
    const app = await mount(stubs);
    await show(app, 'data');
    section(app, 'vw-data-section').dispatchEvent(new CustomEvent('vw-export', { detail: {}, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    const fileName = stubs.downloadText.mock.calls[0]![1];
    expect(fileName).toMatch(/^vaultwarden-export-\d{4}-\d{2}-\d{2}\.json$/);
  });

  it('imports a plain JSON file directly and reports the imported count', async () => {
    const stubs = makeDeps({
      readFileResult: '{"items":[]}',
      handlers: { 'vault.import': async () => ({ ok: true, data: { imported: 3 } }) },
    });
    const app = await mount(stubs);
    await show(app, 'data');
    const data = section<VwDataSection>(app, 'vw-data-section');
    const file = new File(['{"items":[]}'], 'vault.json');
    data.dispatchEvent(new CustomEvent('vw-import-file', { detail: { file }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(stubs.calls).toContain('vault.import');
    expect(data.status?.message).toContain('3');
  });

  it('imports a CSV file directly', async () => {
    let importReq: Req | undefined;
    const stubs = makeDeps({
      readFileResult: 'name,login_username\nExample,alice',
      handlers: { 'vault.import': async (req) => { importReq = req; return { ok: true, data: { imported: 1 } }; } },
    });
    const app = await mount(stubs);
    await show(app, 'data');
    const data = section<VwDataSection>(app, 'vw-data-section');
    const file = new File(['name,login_username\nExample,alice'], 'vault.csv');
    data.dispatchEvent(new CustomEvent('vw-import-file', { detail: { file }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(importReq).toMatchObject({ type: 'vault.import', content: 'name,login_username\nExample,alice' });
  });

  it('prompts for a password on an encrypted export file, then imports with it', async () => {
    let importReq: Req | undefined;
    const stubs = makeDeps({
      readFileResult: '{"encrypted":true,"passwordProtected":true}',
      handlers: { 'vault.import': async (req) => { importReq = req; return { ok: true, data: { imported: 2 } }; } },
    });
    const app = await mount(stubs);
    await show(app, 'data');
    const data = section<VwDataSection>(app, 'vw-data-section');
    const file = new File(['{"encrypted":true,"passwordProtected":true}'], 'vault.json');
    data.dispatchEvent(new CustomEvent('vw-import-file', { detail: { file }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    // No import yet: it must wait for the password.
    expect(stubs.calls).not.toContain('vault.import');
    expect(data.awaitingImportPassword).toBe(true);

    data.dispatchEvent(new CustomEvent('vw-import-password', { detail: { password: 'exportpw' }, bubbles: true, composed: true }));
    await flushAsync();
    await app.updateComplete;
    expect(importReq).toMatchObject({ type: 'vault.import', content: '{"encrypted":true,"passwordProtected":true}', password: 'exportpw' });
  });
});

describe('vw-options-app about section', () => {
  afterEach(() => document.body.replaceChildren());

  it('shows the injected extension version', async () => {
    const app = await mount(makeDeps());
    await show(app, 'about');
    expect(section(app, 'vw-about-section').shadowRoot!.textContent).toContain('9.9.9');
  });
});
