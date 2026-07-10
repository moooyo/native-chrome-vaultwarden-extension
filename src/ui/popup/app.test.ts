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
