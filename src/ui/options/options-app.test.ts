// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: { sendMessage: vi.fn(), getURL: vi.fn((path: string) => path), getManifest: vi.fn(() => ({ version: '1.3.0' })), openOptionsPage: vi.fn() },
    permissions: { request: vi.fn(async () => true) },
    tabs: { query: vi.fn(async () => []), create: vi.fn() },
    storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } },
  },
}));

import './options-app.js';
import type { VwOptionsApp } from './options-app.js';
import type { OptionsDeps, OptionsRequest, LoadedSettings } from './types.js';

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

function makeDeps(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }> = {}, calls: string[] = []): OptionsDeps {
  const wrapped = fakeRequest({
    'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
    'settings.get': async () => ({ ok: true, data: loadedSettings }),
    'auth.listAccounts': async () => ({ ok: true, data: { accounts: [{ email: 'me@x.dev', active: true }] } }),
    'sends.list': async () => ({ ok: true, data: { sends: [] } }),
    ...handlers,
  });
  return {
    request: (req) => { calls.push(req.type); return wrapped(req); },
    requestOrigins: vi.fn(async () => true),
    downloadText: vi.fn(),
    readFile: vi.fn(async () => '[]'),
    extensionVersion: () => '1.3.0',
  };
}

async function mount(deps: OptionsDeps): Promise<VwOptionsApp> {
  const app = document.createElement('vw-options-app') as VwOptionsApp;
  app.deps = deps;
  document.body.append(app);
  await new Promise((r) => setTimeout(r, 0));
  await app.updateComplete;
  return app;
}

function shell(app: VwOptionsApp): Element {
  return app.shadowRoot!.querySelector('vw-options-shell')!;
}

beforeEach(() => {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn(async () => {}) }, configurable: true });
});
afterEach(() => document.body.replaceChildren());

describe('vw-options-app', () => {
  it('loads settings + account and defaults to the account section', async () => {
    const app = await mount(makeDeps());
    expect(app.selected).toBe('account');
    expect(app.accountEmail).toBe('me@x.dev');
    expect(app.shadowRoot!.querySelector('vw-connection-section')).not.toBeNull();
  });

  it('switches sections on nav-change', async () => {
    const app = await mount(makeDeps());
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id: 'appearance' }, bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.selected).toBe('appearance');
    expect(app.shadowRoot!.querySelector('vw-appearance-section')).not.toBeNull();
  });

  it('renders all eight sections in turn', async () => {
    const app = await mount(makeDeps());
    const map: Record<string, string> = {
      account: 'vw-connection-section', security: 'vw-security-section', autofill: 'vw-autofill-section',
      generator: 'vw-generator-section', send: 'vw-send-section', appearance: 'vw-appearance-section',
      data: 'vw-data-section', about: 'vw-about-section',
    };
    for (const [id, tag] of Object.entries(map)) {
      shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id }, bubbles: true, composed: true }));
      await app.updateComplete;
      expect(app.shadowRoot!.querySelector(tag), tag).not.toBeNull();
    }
  });

  it('requests host permission then saves the server URL on connection-save', async () => {
    const calls: string[] = [];
    const deps = makeDeps({}, calls);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-connection-save', { detail: { serverUrl: 'http://10.0.1.20:8080/' }, bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(deps.requestOrigins).toHaveBeenCalledWith(['http://10.0.1.20:8080/*']);
    expect(calls).toContain('settings.save');
  });

  it('syncs on vw-sync-now and records the time', async () => {
    const calls: string[] = [];
    const app = await mount(makeDeps({ 'vault.sync': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('vault.sync');
    expect(app.lastSync).toBeTypeOf('number');
  });

  it('changes the master password on vw-change-password', async () => {
    const calls: string[] = [];
    const app = await mount(makeDeps({ 'auth.changePassword': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-change-password', { detail: { currentPassword: 'a', newPassword: 'bbbbbbbb' }, bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('auth.changePassword');
  });

  it('creates a Send and copies its link', async () => {
    const calls: string[] = [];
    const app = await mount(makeDeps({
      'sends.createText': async () => ({ ok: true, data: { send: { id: 's1', accessId: 'a', type: 0, name: 'x', hidden: false, url: 'https://s', deletionDate: '', accessCount: 0, disabled: false, passwordProtected: false } } }),
    }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-send-create', { detail: { kind: 'text', input: { name: 'x', deletionDays: 7 } }, bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('sends.createText');
    expect((navigator.clipboard.writeText as ReturnType<typeof vi.fn>)).toHaveBeenCalledWith('https://s');
  });

  it('exports the vault on vw-export', async () => {
    const calls: string[] = [];
    const deps = makeDeps({ 'vault.export': async () => ({ ok: true, data: { json: '{}' } }) }, calls);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-export', { detail: {}, bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('vault.export');
    expect(deps.downloadText).toHaveBeenCalled();
  });

  it('signs out on vw-delete-local (confirmed)', async () => {
    const calls: string[] = [];
    window.confirm = vi.fn(() => true);
    const app = await mount(makeDeps({ 'auth.logout': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-delete-local', { bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('auth.logout');
    expect(app.locked).toBe(true);
  });

  it('reports up-to-date on vw-check-update', async () => {
    const app = await mount(makeDeps());
    shell(app).dispatchEvent(new CustomEvent('vw-check-update', { bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.aboutStatus?.tone).toBe('info');
  });
});
