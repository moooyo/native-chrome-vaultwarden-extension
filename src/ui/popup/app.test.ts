// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: { sendMessage: vi.fn(), getURL: vi.fn((path: string) => path), openOptionsPage: vi.fn() },
    tabs: { query: vi.fn(async () => []), create: vi.fn() },
  },
}));

import './app.js';
import type { VwPopupApp } from './app.js';
import type { PopupRequest } from './types.js';
import type { CipherSummary } from '../../core/vault/models.js';

type Req = Parameters<PopupRequest>[0];
type Res = Awaited<ReturnType<PopupRequest>>;
type ReqHandler<K extends Req['type']> = (req: Extract<Req, { type: K }>) => Res | Promise<Res>;

/** Builds a `PopupRequest` stub from a partial map of per-`type` handlers; unhandled request
 *  types resolve to a neutral `{ ok: true, data: null }` so tests only need to stub what they
 *  exercise. */
function fakeRequest(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>): PopupRequest {
  const dispatch = async (req: Req): Promise<Res> => {
    const handler = handlers[req.type] as ReqHandler<Req['type']> | undefined;
    if (handler) return handler(req);
    return { ok: true, data: null };
  };
  return dispatch as PopupRequest;
}

/** Lets in-flight microtask chains from the mocked `request` fully settle before asserting on
 *  `route`: a plain `await app.updateComplete` only awaits an update already scheduled at the
 *  time it's read, not one a still-pending promise chain will schedule a few ticks later. */
function flushAsync(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function settle(app: VwPopupApp): Promise<void> {
  await flushAsync();
  await app.updateComplete;
}

async function mountApp(request: PopupRequest): Promise<VwPopupApp> {
  const app = document.createElement('vw-popup-app') as VwPopupApp;
  app.request = request;
  document.body.append(app);
  await settle(app);
  return app;
}

describe('vw-popup-app routing', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('routes to unlock when auth.getState reports locked', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
    });
    const app = await mountApp(request);
    expect(app.route.name).toBe('unlock');
  });

  it('routes to login when auth.getState reports loggedOut', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
    });
    const app = await mountApp(request);
    expect(app.route.name).toBe('login');
  });

  it('routes to login with the error message when auth.getState fails', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: false, error: { code: 'error', message: 'boom' } }),
    });
    const app = await mountApp(request);
    expect(app.route).toEqual({ name: 'login', error: 'boom' });
  });

  it('routes to vault(suggestions) when auth.getState reports unlocked', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
    });
    const app = await mountApp(request);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });
});

describe('vw-popup-app login flow', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('submits auth.login and routes to vault on success', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async (req) => {
        expect(req.email).toBe('user@example.com');
        expect(req.masterPassword).toBe('hunter2');
        return { ok: true, data: { kind: 'unlocked' } };
      },
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });

  it('routes back to login with the server error on a failed login', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: false, error: { code: 'error', message: 'Invalid credentials' } }),
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'wrong' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'login', error: 'Invalid credentials' });
  });

  it('routes to twoFactor with the reported providers when login requires 2FA', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [0, 1] } }),
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'twoFactor', providers: [0, 1] });
  });

  it('checks device-remembered status on email change and clears it on forget', async () => {
    const isDeviceRemembered = vi.fn(async () => ({ ok: true as const, data: { remembered: true } }));
    const forgetDevice = vi.fn(async () => ({ ok: true as const, data: null }));
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.isDeviceRemembered': isDeviceRemembered,
      'auth.forgetDevice': forgetDevice,
    });
    const app = await mountApp(request);
    const view = app.shadowRoot!.querySelector('vw-auth-views')!;
    view.dispatchEvent(new CustomEvent('vw-auth-email-change', { detail: { email: 'user@example.com' } }));
    await settle(app);
    expect(isDeviceRemembered).toHaveBeenCalledWith(expect.objectContaining({ email: 'user@example.com' }));
    expect(app.deviceRemembered).toBe(true);

    view.dispatchEvent(new CustomEvent('vw-auth-forget-device'));
    await settle(app);
    expect(forgetDevice).toHaveBeenCalledWith(expect.objectContaining({ email: 'user@example.com' }));
    expect(app.deviceRemembered).toBe(false);
    expect(app.deviceForgotten).toBe(true);
  });
});

describe('vw-popup-app registration flow', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('rejects a too-short master password without calling auth.register', async () => {
    const register = vi.fn();
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.register': register,
    });
    const app = await mountApp(request);
    app.navigate({ name: 'register' });
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-register-submit', {
      detail: { email: 'new@example.com', masterPassword: 'short', confirm: 'short' },
    }));
    await settle(app);
    expect(register).not.toHaveBeenCalled();
    expect(app.route).toEqual({ name: 'register', error: 'Master password must be at least 8 characters' });
  });

  it('rejects a mismatched confirmation without calling auth.register', async () => {
    const register = vi.fn();
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.register': register,
    });
    const app = await mountApp(request);
    app.navigate({ name: 'register' });
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-register-submit', {
      detail: { email: 'new@example.com', masterPassword: 'a long enough password', confirm: 'not the same password' },
    }));
    await settle(app);
    expect(register).not.toHaveBeenCalled();
    expect(app.route).toEqual({ name: 'register', error: 'Passwords do not match' });
  });

  it('submits auth.register (threading name) and routes to vault on success', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.register': async (req) => {
        expect(req.email).toBe('new@example.com');
        expect(req.name).toBe('Ada');
        expect(req.masterPassword).toBe('a long enough password');
        return { ok: true, data: { kind: 'unlocked' } };
      },
    });
    const app = await mountApp(request);
    app.navigate({ name: 'register' });
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-register-submit', {
      detail: { email: 'new@example.com', name: 'Ada', masterPassword: 'a long enough password', confirm: 'a long enough password' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });
});

describe('vw-popup-app two-factor flow', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it.each([0, 1, 2, 3, 6])('submits auth.submitTwoFactor for code-based provider %i and routes to vault on success', async (provider) => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [provider] } }),
      'auth.submitTwoFactor': async (req) => {
        expect(req.provider).toBe(provider);
        expect(req.code).toBe('123456');
        expect(req.remember).toBe(true);
        return { ok: true, data: { kind: 'unlocked' } };
      },
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
    await settle(app);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-two-factor-submit', {
      detail: { provider, code: '123456', remember: true },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });

  it('routes back to twoFactor with the server error on a failed code', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [0] } }),
      'auth.submitTwoFactor': async () => ({ ok: false, error: { code: 'error', message: 'Invalid code' } }),
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
    await settle(app);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-two-factor-submit', {
      detail: { provider: 0, code: 'wrong', remember: false },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'twoFactor', providers: [0], error: 'Invalid code' });
  });

  it('sends the email code via auth.sendEmailCode', async () => {
    const sendEmailCode = vi.fn(async () => ({ ok: true as const, data: null }));
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [1] } }),
      'auth.sendEmailCode': sendEmailCode,
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
    await settle(app);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-send-email-code'));
    await settle(app);
    expect(sendEmailCode).toHaveBeenCalledTimes(1);
  });
});

describe('vw-popup-app unlock flow', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('submits auth.unlock and routes to vault on success', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
      'auth.unlock': async (req) => {
        expect(req.masterPassword).toBe('hunter2');
        return { ok: true, data: null };
      },
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-unlock-submit', {
      detail: { masterPassword: 'hunter2' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });

  it('routes back to unlock with the server error on a failed unlock', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
      'auth.unlock': async () => ({ ok: false, error: { code: 'error', message: 'Wrong password' } }),
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-unlock-submit', {
      detail: { masterPassword: 'wrong' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'unlock', error: 'Wrong password' });
  });

  it('fetches PIN status on entering unlock and passes pinEnabled to the view', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: true } }),
    });
    const app = await mountApp(request);
    expect(app.pinEnabled).toBe(true);
  });

  it('submits auth.unlockWithPin and routes to vault on success', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: true } }),
      'auth.unlockWithPin': async (req) => {
        expect(req.pin).toBe('4321');
        return { ok: true, data: null };
      },
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-pin-unlock-submit', {
      detail: { pin: '4321' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });

  it('logs out and returns to the login route', async () => {
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
      'auth.logout': logout,
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-logout'));
    await settle(app);
    expect(logout).toHaveBeenCalledTimes(1);
    expect(app.route).toEqual({ name: 'login' });
  });
});

describe('vw-popup-app navigation clears ephemeral auth state', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('resets pinEnabled when navigating away from unlock', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: { enabled: true } }),
    });
    const app = await mountApp(request);
    expect(app.pinEnabled).toBe(true);
    app.navigate({ name: 'login' });
    expect(app.pinEnabled).toBe(false);
  });

  it('resets deviceRemembered/deviceForgotten when navigating away from login', async () => {
    const request = fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.isDeviceRemembered': async () => ({ ok: true, data: { remembered: true } }),
    });
    const app = await mountApp(request);
    app.shadowRoot!.querySelector('vw-auth-views')!.dispatchEvent(new CustomEvent('vw-auth-email-change', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);
    expect(app.deviceRemembered).toBe(true);
    app.navigate({ name: 'register' });
    expect(app.deviceRemembered).toBe(false);
    expect(app.deviceForgotten).toBe(false);
  });
});

// --- Task 6: vault, suggestions, filters, and menus integration ---

const TARGET = { frameId: 0, formId: 'f1' };

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return { id: 'c1', name: 'GitHub', uris: ['https://github.com'], loginUris: [], type: 1, favorite: false, ...overrides };
}

/** Base handler map for a freshly-unlocked vault; individual tests override what they exercise. */
function unlockedHandlers(over: Partial<{ [K in Req['type']]: ReqHandler<K> }> = {}): PopupRequest {
  return fakeRequest({
    'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
    'vault.listItems': async () => ({ ok: true, data: { items: [summary()], folders: [], collections: [], orgPermissions: [] } }),
    'vault.getSkippedOrgCount': async () => ({ ok: true, data: { count: 0 } }),
    'auth.listAccounts': async () => ({ ok: true, data: { accounts: [{ email: 'me@example.com', active: true }] } }),
    'auth.pinStatus': async () => ({ ok: true, data: { enabled: false } }),
    'auth.isDeviceRemembered': async () => ({ ok: true, data: { remembered: false } }),
    'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [] } } }),
    ...over,
  });
}

function browserSeam(over: Partial<{ getActiveTabId: () => Promise<number | undefined>; openOptions: () => Promise<void>; openReceive: () => Promise<void> }> = {}) {
  return {
    getActiveTabId: over.getActiveTabId ?? (async () => 7),
    openOptions: over.openOptions ?? (async () => {}),
    openReceive: over.openReceive ?? (async () => {}),
  };
}

async function fully(app: VwPopupApp): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await new Promise((r) => setTimeout(r, 0));
    await app.updateComplete;
  }
}

async function mountVault(request: PopupRequest, browser?: ReturnType<typeof browserSeam>): Promise<VwPopupApp> {
  const app = document.createElement('vw-popup-app') as VwPopupApp;
  app.request = request;
  if (browser) app.browser = browser;
  document.body.append(app);
  await fully(app);
  return app;
}

function vaultView(app: VwPopupApp): Element {
  return app.shadowRoot!.querySelector('vw-vault-view')!;
}

function header(app: VwPopupApp): Element {
  return app.shadowRoot!.querySelector('vw-popup-header')!;
}

function suggestionMessages(app: VwPopupApp): string[] {
  const sv = vaultView(app).shadowRoot!.querySelector('vw-suggestions-view');
  return Array.from(sv?.shadowRoot?.querySelectorAll('vw-status-message') ?? []).map((s) => s.getAttribute('message') ?? '');
}

describe('vw-popup-app vault suggestions', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('defaults to Suggestions and loads tab suggestions for an eligible active tab', async () => {
    const getTabSuggestions = vi.fn(async (): Promise<Res> => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [{ id: 's1', name: 'Example', username: 'alice', matchedUri: 'https://example.com', matchType: 0, favorite: false, target: TARGET }] } } }));
    const app = await mountVault(unlockedHandlers({ 'autofill.getTabSuggestions': getTabSuggestions }), browserSeam());
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
    expect(getTabSuggestions).toHaveBeenCalledWith(expect.objectContaining({ tabId: 7 }));
    expect(vaultView(app).shadowRoot!.querySelector('vw-suggestions-view')).not.toBeNull();
    expect(vaultView(app).shadowRoot!.querySelector('vw-suggestions-view')!.shadowRoot!.textContent).toContain('Example');
  });

  it('shows neutral guidance and keeps All items selectable for a restricted tab', async () => {
    const app = await mountVault(unlockedHandlers({ 'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'restricted_page', suggestions: [] } } }) }), browserSeam());
    expect(suggestionMessages(app).some((m) => m.length > 0)).toBe(true);
    vaultView(app).dispatchEvent(new CustomEvent('vw-tab-change', { detail: { id: 'all' }, bubbles: true, composed: true }));
    await fully(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    expect(vaultView(app).shadowRoot!.querySelector('vw-all-items-view')).not.toBeNull();
  });

  it('treats a missing active tab as no_eligible_tab without requesting suggestions', async () => {
    const getTabSuggestions = vi.fn(async (): Promise<Res> => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [] } } }));
    const app = await mountVault(unlockedHandlers({ 'autofill.getTabSuggestions': getTabSuggestions }), browserSeam({ getActiveTabId: async () => undefined }));
    expect(getTabSuggestions).not.toHaveBeenCalled();
    expect(suggestionMessages(app).some((m) => m.length > 0)).toBe(true);
  });

  it('fills only tab/cipher/target and records the filled outcome', async () => {
    const fillTabSuggestion = vi.fn(async (req: Extract<Req, { type: 'autofill.fillTabSuggestion' }>): Promise<Res> => {
      expect(req).toEqual({ type: 'autofill.fillTabSuggestion', tabId: 7, cipherId: 'cip', target: TARGET });
      return { ok: true, data: { outcome: { status: 'filled' } } };
    });
    const app = await mountVault(unlockedHandlers({ 'autofill.fillTabSuggestion': fillTabSuggestion }), browserSeam());
    vaultView(app).dispatchEvent(new CustomEvent('vw-suggestion-fill', { detail: { cipherId: 'cip', target: TARGET }, bubbles: true, composed: true }));
    await fully(app);
    expect(fillTabSuggestion).toHaveBeenCalledTimes(1);
    expect(suggestionMessages(app).join(' ').toLowerCase()).toContain('filled');
  });

  it('surfaces a failed fill request as an error', async () => {
    const app = await mountVault(unlockedHandlers({ 'autofill.fillTabSuggestion': async () => ({ ok: false, error: { code: 'error', message: 'blocked' } }) }), browserSeam());
    vaultView(app).dispatchEvent(new CustomEvent('vw-suggestion-fill', { detail: { cipherId: 'cip', target: TARGET }, bubbles: true, composed: true }));
    await fully(app);
    expect(suggestionMessages(app).join(' ')).toContain('blocked');
  });
});

describe('vw-popup-app all items', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  async function inAllItems(request: PopupRequest): Promise<VwPopupApp> {
    const app = await mountVault(request, browserSeam());
    vaultView(app).dispatchEvent(new CustomEvent('vw-tab-change', { detail: { id: 'all' }, bubbles: true, composed: true }));
    await fully(app);
    return app;
  }

  it('narrows the list through the shared core filter on filter-change', async () => {
    const items = [summary({ id: 'a', name: 'GitHub', uris: [] }), summary({ id: 'b', name: 'GitLab', uris: [] })];
    const app = await inAllItems(unlockedHandlers({ 'vault.listItems': async () => ({ ok: true, data: { items, folders: [], collections: [], orgPermissions: [] } }) }));
    vaultView(app).dispatchEvent(new CustomEvent('vw-filter-change', { detail: { query: 'hub' }, bubbles: true, composed: true }));
    await fully(app);
    const list = vaultView(app).shadowRoot!.querySelector('vw-all-items-view')!;
    expect(list.shadowRoot!.querySelectorAll('vw-vault-item-row')).toHaveLength(1);
  });

  it('performs folder CRUD through vault.createFolder', async () => {
    const createFolder = vi.fn(async (): Promise<Res> => ({ ok: true, data: { items: [], folders: [{ id: 'nf', name: 'New' }], collections: [], orgPermissions: [] } }));
    const app = await inAllItems(unlockedHandlers({ 'vault.createFolder': createFolder }));
    vaultView(app).dispatchEvent(new CustomEvent('vw-folder-mutate', { detail: { op: 'create', name: 'New' }, bubbles: true, composed: true }));
    await fully(app);
    expect(createFolder).toHaveBeenCalledWith(expect.objectContaining({ name: 'New' }));
    expect(app.folders).toEqual([{ id: 'nf', name: 'New' }]);
  });

  it('performs collection CRUD through vault.createCollection', async () => {
    const createCollection = vi.fn(async (): Promise<Res> => ({ ok: true, data: { items: [], folders: [], collections: [{ id: 'nc', name: 'Ops', organizationId: 'o1' }], orgPermissions: [] } }));
    const app = await inAllItems(unlockedHandlers({ 'vault.createCollection': createCollection }));
    vaultView(app).dispatchEvent(new CustomEvent('vw-collection-mutate', { detail: { op: 'create', organizationId: 'o1', name: 'Ops' }, bubbles: true, composed: true }));
    await fully(app);
    expect(createCollection).toHaveBeenCalledWith(expect.objectContaining({ organizationId: 'o1', name: 'Ops' }));
  });
});

describe('vw-popup-app account and tool actions', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  function account(app: VwPopupApp, detail: Record<string, unknown>): void {
    header(app).dispatchEvent(new CustomEvent('vw-account-action', { detail, bubbles: true, composed: true }));
  }
  function tool(app: VwPopupApp, detail: Record<string, unknown>): void {
    header(app).dispatchEvent(new CustomEvent('vw-tool-action', { detail, bubbles: true, composed: true }));
  }

  it('locks via auth.lock and routes to unlock', async () => {
    const lock = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountVault(unlockedHandlers({ 'auth.lock': lock }), browserSeam());
    account(app, { action: 'lock' });
    await fully(app);
    expect(lock).toHaveBeenCalledTimes(1);
    expect(app.route.name).toBe('unlock');
  });

  it('logs out via auth.logout and routes to login', async () => {
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountVault(unlockedHandlers({ 'auth.logout': logout }), browserSeam());
    account(app, { action: 'logout' });
    await fully(app);
    expect(logout).toHaveBeenCalledTimes(1);
    expect(app.route.name).toBe('login');
  });

  it('opens options through the browser seam', async () => {
    const openOptions = vi.fn(async () => {});
    const app = await mountVault(unlockedHandlers(), browserSeam({ openOptions }));
    account(app, { action: 'options' });
    await fully(app);
    expect(openOptions).toHaveBeenCalledTimes(1);
  });

  it('routes to account security', async () => {
    const app = await mountVault(unlockedHandlers(), browserSeam());
    account(app, { action: 'account-security' });
    await fully(app);
    expect(app.route.name).toBe('accountSecurity');
  });

  it('routes to the PIN editor', async () => {
    const app = await mountVault(unlockedHandlers(), browserSeam());
    account(app, { action: 'pin' });
    await fully(app);
    expect(app.route.name).toBe('pin');
  });

  it('syncs via vault.sync and applies the listing', async () => {
    const sync = vi.fn(async (): Promise<Res> => ({ ok: true, data: { items: [summary({ id: 'synced' })], folders: [], collections: [], orgPermissions: [] } }));
    const app = await mountVault(unlockedHandlers({ 'vault.sync': sync }), browserSeam());
    tool(app, { action: 'sync' });
    await fully(app);
    expect(sync).toHaveBeenCalledTimes(1);
    expect(app.items.map((i) => i.id)).toEqual(['synced']);
  });

  it('shows trash within All items', async () => {
    const items = [summary({ id: 'a' }), summary({ id: 'b', deletedDate: '2026-01-01' })];
    const app = await mountVault(unlockedHandlers({ 'vault.listItems': async () => ({ ok: true, data: { items, folders: [], collections: [], orgPermissions: [] } }) }), browserSeam());
    tool(app, { action: 'trash' });
    await fully(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    const list = vaultView(app).shadowRoot!.querySelector('vw-all-items-view')!;
    expect(list.shadowRoot!.querySelectorAll('vw-vault-item-row')).toHaveLength(1);
  });

  it('routes to health and sends', async () => {
    const app = await mountVault(unlockedHandlers(), browserSeam());
    tool(app, { action: 'health' });
    await fully(app);
    expect(app.route.name).toBe('health');
    app.navigate({ name: 'vault', scope: 'suggestions' });
    await fully(app);
    tool(app, { action: 'sends' });
    await fully(app);
    expect(app.route.name).toBe('sends');
  });

  it('routes to the editor on add and to the generator', async () => {
    const app = await mountVault(unlockedHandlers(), browserSeam());
    header(app).dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await fully(app);
    expect(app.route.name).toBe('editor');
    // return to the vault, then open the generator
    app.navigate({ name: 'vault', scope: 'suggestions' });
    await fully(app);
    header(app).dispatchEvent(new CustomEvent('vw-generator', { bubbles: true, composed: true }));
    await fully(app);
    expect(app.route.name).toBe('generator');
  });

  it('opens item detail from a vault row', async () => {
    const app = await mountVault(unlockedHandlers(), browserSeam());
    vaultView(app).dispatchEvent(new CustomEvent('vw-item-open', { detail: { cipherId: 'c1' }, bubbles: true, composed: true }));
    await fully(app);
    expect(app.route).toEqual({ name: 'detail', cipherId: 'c1' });
  });
});

