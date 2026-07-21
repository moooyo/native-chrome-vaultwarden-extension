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
import browserPolyfill from 'webextension-polyfill';
import type { VwPopupApp } from './app.js';
import type { PopupRequest, PopupBrowser, ToolActionDetail } from './types.js';
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
    expect(view(app, 'vw-tools-menu')).not.toBeNull();
    expect(view(app, 'vw-account-menu')).not.toBeNull();
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

describe('vw-popup-app unlocked navigation', () => {
  it('opens the editor on add', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('editor');
  });

  it('toggles the generator view', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'generator' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('generator');
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-generator-toggle', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });

  it('opens options on settings', async () => {
    const openOptions = vi.fn(async () => {});
    const app = await mountApp(fakeRequest(UNLOCKED), fakeBrowser({ openOptions }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', { detail: { action: 'options' }, bubbles: true, composed: true }));
    await settle(app);
    expect(openOptions).toHaveBeenCalled();
  });

  it('locks the vault', async () => {
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.lock': async () => ({ ok: true, data: null }) }));
    view(app, 'vw-popup-header').dispatchEvent(new CustomEvent('vw-lock', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('unlock');
  });

  it('logs out from the account menu only after the worker confirms success', async () => {
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.logout': async () => ({ ok: true, data: null }) }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', { detail: { action: 'logout' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('login');
  });

  it('keeps the vault open and reports a failed logout', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.logout': async () => ({ ok: false, error: { code: 'error', message: 'Logout failed' } }),
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', { detail: { action: 'logout' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('vault');
    expect(app.toastMessage).toBe('Logout failed');
  });

  it('disables navigation controls and ignores menu routing while a request is pending', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    app.pending = true;
    await app.updateComplete;
    const tools = view<HTMLElement & { disabled: boolean }>(app, 'vw-tools-menu');
    const account = view<HTMLElement & { disabled: boolean }>(app, 'vw-account-menu');
    const rail = view<HTMLElement & { disabled: boolean }>(app, 'vw-sync-bar');
    expect(tools.disabled).toBe(true);
    expect(account.disabled).toBe(true);
    expect(rail.disabled).toBe(true);
    tools.dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'health' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });

  it('keeps the Send route stable while a local file is encoding', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'sends' }, bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-sends-view').dispatchEvent(new CustomEvent('vw-send-encoding', { detail: { encoding: true }, bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.sendEncoding).toBe(true);
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'health' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('sends');
    expect((view<HTMLElement & { disabled: boolean }>(app, 'vw-sync-bar')).disabled).toBe(true);
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
    expect(app.toastMessage).not.toBe('');
  });

  it('surfaces a stale fill target instead of failing silently', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [{ id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false, target: { frameId: 0, formId: 'f1' } }] } } }),
      'autofill.fillTabSuggestion': async () => ({ ok: true, data: { outcome: { status: 'target_changed' } } }),
    }), fakeBrowser());
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', { detail: { cipherId: 'c1', target: { frameId: 0, formId: 'f1' } }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.toastMessage).toContain('页面已变化');
  });

  it('edits an item', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-edit-item', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('editor');
  });

  it('renders an editor load failure with a way back', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getCipherInput': async () => ({ ok: false, error: { code: 'error', message: 'Unable to load item' } }),
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-edit-item', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await settle(app);
    const status = view<HTMLElement & { message: string }>(app, '.load-state vw-status-message');
    expect(status.message).toBe('Unable to load item');
    expect(view(app, '.load-back')).not.toBeNull();
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

  it('surfaces a sync failure and does not stamp a successful time', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.sync': async () => ({ ok: false, error: { code: 'error', message: 'Server unavailable' } }),
    }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.lastSync).toBeUndefined();
    expect(app.toastMessage).toBe('Server unavailable');
  });
});

// --- Hardening: open-url scheme gate (uses the real default browser + mocked polyfill) ---
describe('vw-popup-app open-url safety', () => {
  const createMock = vi.mocked(browserPolyfill.tabs.create);

  async function fillItem(uri: string): Promise<VwPopupApp> {
    // No browser override → the real createDefaultBrowser().openUrl runs, backed by the polyfill mock.
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: { items: [login({ uris: [uri] })], folders: [], collections: [], orgPermissions: [] } }),
    }));
    createMock.mockClear();
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-fill', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await settle(app);
    return app;
  }

  it('opens a legitimate bare-domain item uri in a new tab', async () => {
    await fillItem('nebula.dev');
    expect(createMock).toHaveBeenCalled();
  });

  it('does not navigate to a non-web-scheme item uri', async () => {
    await fillItem('file:///etc/passwd');
    expect(createMock).not.toHaveBeenCalled();
  });
});

// --- Hardening: tools-menu sync stamps the last-synced label ---
describe('vw-popup-app tools menu', () => {
  it('records the sync time when syncing from the tools menu', async () => {
    const sync = vi.fn(async () => ({ ok: true as const, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.sync': sync }));
    await (app as unknown as { handleToolAction(d: ToolActionDetail): Promise<void> }).handleToolAction({ action: 'sync' });
    await settle(app);
    expect(sync).toHaveBeenCalled();
    expect(app.lastSync).toBeTypeOf('number');
  });
});

// --- Hardening: the TOTP-list countdown must not leak on a programmatic detach ---
describe('vw-popup-app totp countdown lifecycle', () => {
  it('stops the totp list countdown when detached mid-route', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getTotpCodes': async () => ({ ok: true, data: { totpEntries: [{ id: 'c1', name: 'Nebula', code: '123456', period: 30, remaining: 20 }] } }),
    }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-open-totp', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('totp');
    const timers = app as unknown as { totpListTimer: number | undefined };
    expect(timers.totpListTimer).toBeDefined();
    app.remove(); // programmatic detach while the totp route is still active
    expect(timers.totpListTimer).toBeUndefined();
  });
});

// --- Hardening: clipboard copy helpers preserve their per-caller toast behavior ---
describe('vw-popup-app clipboard copy', () => {
  it('copies a tool value without raising the copy toast', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'generator' }, bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-generator-view').dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'gen-pass', label: 'Password' }, bubbles: true, composed: true }));
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('gen-pass');
    expect(app.toastMessage).toBe('');
  });

  it('raises the copy toast when copying a displayed detail value', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'shown', label: 'Username' }, bubbles: true, composed: true }));
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('shown');
    expect(app.toastMessage).not.toBe('');
  });

  it('does not let an older clipboard promise overwrite a newer Send result', async () => {
    let releaseFirst: (() => void) | undefined;
    const writeText = vi.fn()
      .mockImplementationOnce(() => new Promise<void>((resolve) => { releaseFirst = resolve; }))
      .mockResolvedValueOnce(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const created = { id: 's1', accessId: 'a', type: 0 as const, name: 'x', hidden: false, url: 'https://new', deletionDate: '2026-08-01T00:00:00Z', accessCount: 0, disabled: false, passwordProtected: false };
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'sends.list': async () => ({ ok: true, data: { sends: [created] } }),
      'sends.createText': async () => ({ ok: true, data: { send: created } }),
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'sends' }, bubbles: true, composed: true }));
    await settle(app);
    const sends = view(app, 'vw-sends-view');
    sends.dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'https://old', label: 'Old link' }, bubbles: true, composed: true }));
    sends.dispatchEvent(new CustomEvent('vw-send-create', { detail: { kind: 'text', input: { name: 'x', text: 'secret', deletionDays: 7 } }, bubbles: true, composed: true }));
    await settle(app);
    const mutationMessage = app.toolStatus?.message;
    expect(mutationMessage).toContain('已创建');
    releaseFirst?.();
    await settle(app);
    expect(app.toolStatus?.message).toBe(mutationMessage);
  });
});

// --- Hardening: a stale suggestions response must not clobber a newer one ---
describe('vw-popup-app suggestions race', () => {
  it('ignores a stale suggestions response that resolves after a newer request', async () => {
    let call = 0;
    let releaseFirst: (() => void) | undefined;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => {
        call += 1;
        if (call === 1) {
          await new Promise<void>((resolve) => { releaseFirst = resolve; });
          return { ok: true, data: { outcome: { status: 'ready', suggestions: [{ id: 'STALE', name: 'Old', matchedUri: 'https://old.dev', matchType: 0, favorite: false }] } } };
        }
        return { ok: true, data: { outcome: { status: 'ready', suggestions: [{ id: 'FRESH', name: 'New', matchedUri: 'https://new.dev', matchType: 0, favorite: false }] } } };
      },
    }), fakeBrowser());
    // The mount-time suggestions request (#1) is parked; fire a newer one (#2) via a sync.
    await (app as unknown as { handleToolAction(d: ToolActionDetail): Promise<void> }).handleToolAction({ action: 'sync' });
    await settle(app);
    const fresh = app.suggestionsState;
    expect(fresh.status === 'ready' && fresh.suggestions[0]?.id).toBe('FRESH');
    // Release the stale request; it must not overwrite the newer result.
    releaseFirst?.();
    await settle(app);
    const still = app.suggestionsState;
    expect(still.status === 'ready' && still.suggestions[0]?.id).toBe('FRESH');
  });
});
