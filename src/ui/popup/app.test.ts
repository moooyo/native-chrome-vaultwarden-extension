// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: { sendMessage: vi.fn(), getURL: vi.fn((path: string) => path), openOptionsPage: vi.fn() },
    tabs: { query: vi.fn(async () => []), create: vi.fn() },
    storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } },
  },
}));

import './app.js';
import type { VwPopupApp } from './app.js';
import type { PopupRequest, PopupBrowser } from './types.js';
import type { CipherSummary } from '../../core/vault/models.js';

type Req = Parameters<PopupRequest>[0];
type Res = Awaited<ReturnType<PopupRequest>>;
type ReqHandler<K extends Req['type']> = (req: Extract<Req, { type: K }>) => Res | Promise<Res>;

/** A `PopupRequest` stub from a partial per-`type` handler map; unhandled types resolve to a neutral
 *  `{ ok: true, data: null }` so tests only stub what they exercise. */
function fakeRequest(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>): PopupRequest {
  const dispatch = async (req: Req): Promise<Res> => {
    const handler = handlers[req.type] as ReqHandler<Req['type']> | undefined;
    if (handler) return handler(req);
    return { ok: true, data: null };
  };
  return dispatch as PopupRequest;
}

function flushAsync(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function settle(app: VwPopupApp): Promise<void> {
  await flushAsync();
  await app.updateComplete;
}

function fakeBrowser(over: Partial<PopupBrowser> = {}): PopupBrowser {
  return {
    getActiveTabId: over.getActiveTabId ?? (async () => 7),
    openOptions: over.openOptions ?? (async () => {}),
    openReceive: over.openReceive ?? (async () => {}),
    openUrl: over.openUrl ?? (async () => {}),
  };
}

async function mountApp(request: PopupRequest, browser?: PopupBrowser): Promise<VwPopupApp> {
  const app = document.createElement('vw-popup-app') as VwPopupApp;
  app.request = request;
  if (browser) app.browser = browser;
  document.body.append(app);
  await settle(app);
  return app;
}

function login(over: Partial<CipherSummary> = {}): CipherSummary {
  return { id: 'c1', name: 'Nebula', username: 'me@x.dev', uris: ['https://nebula.dev'], loginUris: [], type: 1, favorite: false, ...over };
}

const UNLOCKED: Partial<{ [K in Req['type']]: ReqHandler<K> }> = {
  'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
  'vault.listItems': async () => ({ ok: true, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }),
  'auth.listAccounts': async () => ({ ok: true, data: { accounts: [{ email: 'me@x.dev', active: true }] } }),
  'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
  'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [] } } }),
  'vault.getCipherInput': async () => ({ ok: true, data: { input: null } }),
};

beforeEach(() => {
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn(async () => {}) },
    configurable: true,
  });
});
afterEach(() => document.body.replaceChildren());

function view<T extends Element = Element>(app: VwPopupApp, sel: string): T {
  return app.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-popup-app routing', () => {
  it('routes to unlock when locked', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
    }));
    expect(app.route.name).toBe('unlock');
  });

  it('routes to login when logged out', async () => {
    const app = await mountApp(fakeRequest({ 'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }) }));
    expect(app.route.name).toBe('login');
  });

  it('routes to login with the error when getState fails', async () => {
    const app = await mountApp(fakeRequest({ 'auth.getState': async () => ({ ok: false, error: { code: 'error', message: 'boom' } }) }));
    expect(app.route).toEqual({ name: 'login', error: 'boom' });
  });

  it('routes to vault when unlocked', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    expect(app.route.name).toBe('vault');
    expect(view(app, 'vw-vault-view')).not.toBeNull();
    expect(view(app, 'vw-popup-header')).not.toBeNull();
    expect(view(app, 'vw-sync-bar')).not.toBeNull();
  });
});

describe('vw-popup-app auth flows', () => {
  it('logs in and routes to vault', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'unlocked' } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', { detail: { email: 'a@b.c', masterPassword: 'pw' } }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });

  it('returns to login with the error on failure', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: false, error: { code: 'error', message: 'bad' } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', { detail: { email: 'a@b.c', masterPassword: 'x' } }));
    await settle(app);
    expect(app.route).toEqual({ name: 'login', error: 'bad' });
  });

  it('routes to twoFactor when required', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [0, 1] } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', { detail: { email: 'a@b.c', masterPassword: 'x' } }));
    await settle(app);
    expect(app.route).toEqual({ name: 'twoFactor', providers: [0, 1] });
  });

  it('unlocks and routes to vault', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
      'auth.unlock': async () => ({ ok: true, data: { state: 'unlocked' } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-unlock-submit', { detail: { masterPassword: 'pw' } }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });
});

describe('vw-popup-app top bar', () => {
  it('opens the editor on add', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-popup-header').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('editor');
  });

  it('toggles the generator view', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    const header = view(app, 'vw-popup-header');
    header.dispatchEvent(new CustomEvent('vw-generator-toggle', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('generator');
    header.dispatchEvent(new CustomEvent('vw-generator-toggle', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });

  it('opens options on settings', async () => {
    const openOptions = vi.fn(async () => {});
    const app = await mountApp(fakeRequest(UNLOCKED), fakeBrowser({ openOptions }));
    view(app, 'vw-popup-header').dispatchEvent(new CustomEvent('vw-open-settings', { bubbles: true, composed: true }));
    await settle(app);
    expect(openOptions).toHaveBeenCalled();
  });

  it('locks the vault', async () => {
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.lock': async () => ({ ok: true, data: null }) }));
    view(app, 'vw-popup-header').dispatchEvent(new CustomEvent('vw-lock', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('unlock');
  });
});

describe('vw-popup-app vault interactions', () => {
  it('expands an item and loads its detail extras', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-toggle', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.selectedCipherId).toBe('c1');
  });

  it('copies a secret via secret-request without exposing plaintext in a prop', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, data: { value: 's3cret' } }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.getField': getField }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-toggle', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-secret-request', { detail: { kind: 'field', field: 'password', label: '密码' }, bubbles: true, composed: true }));
    await settle(app);
    expect(getField).toHaveBeenCalled();
    expect((navigator.clipboard.writeText as ReturnType<typeof vi.fn>)).toHaveBeenCalledWith('s3cret');
  });

  it('fills the current tab from a suggestion', async () => {
    const fill = vi.fn(async () => ({ ok: true as const, data: { outcome: { status: 'filled' as const } } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [{ id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false, target: { frameId: 0, formId: 'f1' } }] } } }),
      'autofill.fillTabSuggestion': fill,
    }), fakeBrowser());
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', { detail: { cipherId: 'c1', target: { frameId: 0, formId: 'f1' } }, bubbles: true, composed: true }));
    await settle(app);
    expect(fill).toHaveBeenCalled();
  });

  it('edits an item', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-edit-item', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('editor');
  });
});

describe('vw-popup-app sync bar', () => {
  it('syncs on demand and records the time', async () => {
    const sync = vi.fn(async () => ({ ok: true as const, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.sync': sync }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
    await settle(app);
    expect(sync).toHaveBeenCalled();
    expect(app.lastSync).toBeTypeOf('number');
  });
});
