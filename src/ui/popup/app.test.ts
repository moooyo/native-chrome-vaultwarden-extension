// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: {
      id: 'extension-id',
      sendMessage: vi.fn(),
      getURL: vi.fn((path: string) => path),
      openOptionsPage: vi.fn(),
      onMessage: { addListener: vi.fn(), removeListener: vi.fn() },
    },
    tabs: { query: vi.fn(async () => []), create: vi.fn() },
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn(), removeListener: vi.fn() },
    },
  },
}));

vi.mock('./editor/totp-capture.js', () => ({
  decodeTotpQr: vi.fn(async (value: string) => (
    value.startsWith('otpauth://totp/') ? value : undefined
  )),
}));

import './app.js';
import browserPolyfill from 'webextension-polyfill';
import { setLocale, t } from '../i18n/index.js';
import type { VwPopupApp } from './app.js';
import type { VwSendsView } from './tools/sends-view.js';
import { PERSONAL_VAULT_FILTER_ID } from './types.js';
import type {
  DetailPresentationMetadata,
  PopupRequest,
  PopupBrowser,
  SuggestionFillDetail,
  SuggestionsViewState,
  ToolActionDetail,
} from './types.js';
import type { SessionState } from '../../core/session/session-manager.js';
import type { CipherInput, CipherSummary, KnownCipherSummary } from '../../core/vault/models.js';
import type { EditorContext } from './editor/editor-types.js';
import { EMPTY_LOGIN_CUSTOM_PLAN_DIGEST } from '../../core/vault/login-custom-fields.js';
import {
  createGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
} from '../../core/generator/enterprise-password-policy.js';

type Req = Parameters<PopupRequest>[0];
type Res = Awaited<ReturnType<PopupRequest>>;
type ReqHandler<K extends Req['type']> = (req: Extract<Req, { type: K }>) => Res | Promise<Res>;
const SSO_ATTEMPT_ID = '11111111-1111-4111-8111-111111111111';
const SSO_ATTEMPT_GENERATION = 1;
const TARGET_RUNTIME_INCARNATION = 'a0b1c2d3-e4f5-4a6b-8c9d-0123456789ab';
const NEXT_TARGET_RUNTIME_INCARNATION = 'b1c2d3e4-f5a6-4b7c-8d9e-1234567890ab';

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

type StorageChangeListener = (changes: Record<string, unknown>, areaName: string) => void;

function vaultSyncMetadata(identity: string, lastSuccess: number, lastAttempt = lastSuccess) {
  return {
    schemaVersion: 1,
    identities: { [identity]: { lastAttempt, lastSuccess } },
  };
}

function vaultSyncStorageListener(): StorageChangeListener {
  const addListener = vi.mocked(browserPolyfill.storage.onChanged.addListener);
  const listener = addListener.mock.calls
    .map(([candidate]) => candidate as StorageChangeListener & { name?: string })
    .filter((candidate) => candidate.name === 'handleVaultSyncStorageChanged')
    .at(-1);
  if (!listener) throw new Error('vault sync metadata listener was not installed');
  return listener;
}

function enterprisePolicyMessageListener(): (message: unknown) => void {
  const addListener = vi.mocked(browserPolyfill.runtime.onMessage.addListener);
  const listener = addListener.mock.calls
    .map(([candidate]) => candidate as unknown as { name?: string })
    .filter((candidate) => candidate.name === 'handleEnterprisePolicyClientChanged')
    .at(-1);
  if (!listener) throw new Error('enterprise policy listener was not installed');
  return listener as (message: unknown) => void;
}

function contextMenuCreateMessageListener(): (
  message: unknown,
  sender: { id?: string; url?: string; tab?: unknown },
) => unknown {
  const addListener = vi.mocked(browserPolyfill.runtime.onMessage.addListener);
  const listener = addListener.mock.calls
    .map(([candidate]) => candidate as unknown as { name?: string })
    .filter((candidate) => candidate.name === 'handleContextMenuCreateIntent')
    .at(-1);
  if (!listener) throw new Error('context menu create listener was not installed');
  return listener as unknown as (
    message: unknown,
    sender: { id?: string; url?: string; tab?: unknown },
  ) => unknown;
}

function emitVaultSyncSuccess(
  listener: StorageChangeListener,
  identity: string,
  previous: number,
  next: number,
): void {
  listener({
    vaultSyncSchedulerMetadata: {
      oldValue: vaultSyncMetadata(identity, previous),
      newValue: vaultSyncMetadata(identity, next),
    },
  }, 'local');
}

/** A `PopupRequest` stub from a partial per-`type` handler map; unhandled types resolve to a neutral
 *  `{ ok: true, data: null }` so tests only stub what they exercise. */
function fakeRequest(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>): PopupRequest {
  const dispatch = async (req: Req): Promise<Res> => {
    const handler = handlers[req.type] as ReqHandler<Req['type']> | undefined;
    if (handler) return handler(req);
    if (req.type === 'auth.deviceLogin.status') {
      return { ok: true, data: { status: 'none' } } as Res;
    }
    if (req.type === 'auth.sso.status') {
      return { ok: true, data: { status: 'none' } } as Res;
    }
    if (req.type === 'auth.accountPasskey.status') {
      return { ok: true, data: { status: 'none' } } as Res;
    }
    if (req.type === 'auth.pendingLogin.status') {
      return { ok: true, data: { status: 'none' } } as Res;
    }
    if (req.type === 'auth.deviceLogin.approvals.list') {
      return { ok: true, data: { approvals: [] } } as Res;
    }
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
    getActiveTabUrl: over.getActiveTabUrl ?? (async () => 'https://active.example/path'),
    captureVisibleTab: over.captureVisibleTab ?? (async () => 'data:image/png;base64,AA=='),
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

function login(over: Partial<KnownCipherSummary> = {}): KnownCipherSummary {
  return { id: 'c1', name: 'Nebula', username: 'me@x.dev', uris: ['https://nebula.dev'], loginUris: [], type: 1, favorite: false, ...over };
}

const UNLOCKED: Partial<{ [K in Req['type']]: ReqHandler<K> }> = {
  'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
  'vault.popupOpened': async () => ({ ok: true, data: null }),
  'vault.getSyncStatus': async () => ({ ok: true, data: { dirty: false, syncing: false } }),
  'vault.listItems': async () => ({ ok: true, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }),
  'vault.getOrganizationDataOwnershipStatus': async () => ({ ok: true, data: { status: 'not_required' } }),
  'auth.listAccounts': async () => ({ ok: true, data: { accounts: [{ email: 'me@x.dev', active: true }] } }),
  'auth.pinStatus': async () => ({
    ok: true,
    data: {
      enabled: false,
      available: false,
      allowed: true,
      requireMasterPasswordOnRestart: true,
    },
  }),
  'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [] } } }),
  'vault.getCipherInput': async () => ({ ok: true, data: { input: null } }),
};

const PENDING_LOGIN_CONTINUATION_ID = 'c8882c32-17e1-4052-ac72-9b09f0bbb11d';
const FIDO_ROUTE_DATA = Object.freeze({
  owner: Object.freeze({
    flow: 'password' as const,
    generation: 9,
    serverUrl: 'https://vault.example/',
    bindingId: PENDING_LOGIN_CONTINUATION_ID,
  }),
});

const DEVICE_LOGIN_REQUEST_ID = '123e4567-e89b-42d3-a456-426614174000';
const DEVICE_LOGIN_FINGERPRINT = 'amber-cedar-harbor-lunar-velvet';
const DEVICE_FIDO_ROUTE_DATA = Object.freeze({
  owner: Object.freeze({
    flow: 'deviceLogin' as const,
    generation: 4,
    serverUrl: 'https://vault.example/',
    bindingId: DEVICE_LOGIN_REQUEST_ID,
  }),
});

function deviceLoginPending(overrides: Record<string, unknown> = {}) {
  return {
    status: 'pending' as const,
    generation: 4,
    fingerprint: DEVICE_LOGIN_FINGERPRINT,
    serverOrigin: 'https://vault.example',
    email: 'user@example.com',
    deviceName: 'chrome',
    expiresAt: Date.now() + 60_000,
    ...overrides,
  };
}

function deviceLoginBinding(proof = 'P'.repeat(43)) {
  const creationDate = new Date(Date.now() - 1_000).toISOString();
  return {
    version: 1 as const,
    requestId: DEVICE_LOGIN_REQUEST_ID,
    publicKeyDigest: 'D'.repeat(43),
    requestDeviceIdentifier: 'requesting-device',
    creationDate,
    requestDeviceTypeValue: 8,
    nonce: 'N'.repeat(22),
    proof,
  };
}

function deviceLoginApproval(proof = 'P'.repeat(43)) {
  const decisionBinding = deviceLoginBinding(proof);
  const creationTime = Date.parse(decisionBinding.creationDate);
  return {
    view: {
      id: DEVICE_LOGIN_REQUEST_ID,
      fingerprint: DEVICE_LOGIN_FINGERPRINT,
      requestDeviceType: 'Chrome extension',
      requestDeviceTypeValue: 8,
      requestDeviceIdentifier: 'requesting-device',
      requestIpAddress: '203.0.113.7',
      requestCountryName: 'Canada',
      creationDate: decisionBinding.creationDate,
      creationTime,
      expiresAt: creationTime + 15 * 60_000,
    },
    decisionBinding,
  };
}

beforeEach(() => {
  Object.defineProperty(window, 'confirm', { value: vi.fn(() => true), configurable: true, writable: true });
  vi.mocked(browserPolyfill.storage.onChanged.addListener).mockClear();
  vi.mocked(browserPolyfill.storage.onChanged.removeListener).mockClear();
  vi.mocked(browserPolyfill.runtime.onMessage.addListener).mockClear();
  vi.mocked(browserPolyfill.runtime.onMessage.removeListener).mockClear();
  setLocale('zh-CN', false);
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn(async () => {}) },
    configurable: true,
  });
});
afterEach(() => {
  document.body.replaceChildren();
  window.history.replaceState(null, '', '/');
  vi.useRealTimers();
});

function view<T extends Element = Element>(app: VwPopupApp, sel: string): T {
  return app.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-popup-app routing', () => {
  it('routes to unlock when locked', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
    }));
    expect(app.route.name).toBe('unlock');
  });

  it('does not expose PIN unlock when organization policy denies it', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: true, available: true, allowed: false, requireMasterPasswordOnRestart: false,
      } }),
    }));
    const auth = view<HTMLElement & { pinEnabled: boolean }>(app, 'vw-auth-views');
    expect(app.pinAllowed).toBe(false);
    expect(auth.pinEnabled).toBe(false);
  });

  it('does not expose an after-first-unlock PIN before the first master-password unlock', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: true,
        available: false,
        allowed: true,
        requireMasterPasswordOnRestart: true,
      } }),
    }));
    const auth = view<HTMLElement & { pinEnabled: boolean }>(app, 'vw-auth-views');
    expect(auth.pinEnabled).toBe(false);
  });

  it('routes to login when logged out', async () => {
    const app = await mountApp(fakeRequest({ 'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }) }));
    expect(app.route.name).toBe('login');
  });

  it('routes a restricted account only to the forced password-change surface', async () => {
    const requirement = {
      schemaVersion: 1 as const,
      reason: 'adminForcePasswordReset' as const,
    };
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({
        ok: true,
        data: { state: 'restricted', restriction: requirement },
      }),
    }));
    expect(app.route).toEqual({ name: 'restricted', requirement });
    const auth = view<HTMLElement & { mode: string }>(app, 'vw-auth-views');
    expect(auth.mode).toBe('restricted');
    expect(app.shadowRoot!.querySelector('vw-popup-header')).toBeNull();
  });

  it('restores password two-factor before consulting device-login state', async () => {
    const startupOrder: string[] = [];
    const deviceStatus = vi.fn(async () => ({ ok: true as const, data: { status: 'none' as const } }));
    const expiresAt = Date.now() + 60_000;
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.sso.status': async () => {
        startupOrder.push('sso');
        return { ok: true, data: { status: 'none' } };
      },
      'auth.pendingLogin.status': async () => {
        startupOrder.push('pending');
        return {
          ok: true,
          data: {
            status: 'twoFactor',
            attemptId: 19,
            continuationId: PENDING_LOGIN_CONTINUATION_ID,
            providers: [0, 7],
            fido2: {
              owner: {
                flow: 'password',
                generation: 19,
                serverUrl: 'https://vault.example/',
                bindingId: PENDING_LOGIN_CONTINUATION_ID,
              },
            },
            expiresAt,
          },
        };
      },
      'auth.deviceLogin.status': deviceStatus,
    }));

    expect(app.route).toEqual({
      name: 'twoFactor',
      flow: 'password',
      providers: [0, 7],
      fido2: {
        owner: {
          flow: 'password',
          generation: 19,
          serverUrl: 'https://vault.example/',
          bindingId: PENDING_LOGIN_CONTINUATION_ID,
        },
      },
      continuationId: PENDING_LOGIN_CONTINUATION_ID,
    });
    expect(deviceStatus).not.toHaveBeenCalled();
    expect(startupOrder).toEqual(['sso', 'pending']);
  });

  it('ignores a stale pending-login startup status after the user navigates elsewhere', async () => {
    const pending = deferred<Res>();
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => pending.promise,
    }));
    app.navigate({ name: 'register' });
    pending.resolve({
      ok: true,
      data: {
        status: 'twoFactor',
        attemptId: 20,
        providers: [0],
        expiresAt: Date.now() + 60_000,
      },
    } as Res);
    await settle(app);

    expect(app.route).toEqual({ name: 'register' });
  });

  it('restores new-device verification and exposes no persisted credential data', async () => {
    const expiresAt = Date.now() + 60_000;
    const status = vi.fn(async () => ({
      ok: true as const,
      data: {
        status: 'newDeviceVerification' as const,
        attemptId: 21,
        continuationId: PENDING_LOGIN_CONTINUATION_ID,
        expiresAt,
      },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': status,
    }));

    expect(app.route).toEqual({
      name: 'newDeviceVerification',
      attemptId: 21,
      continuationId: PENDING_LOGIN_CONTINUATION_ID,
      expiresAt,
    });
    expect(JSON.stringify(status.mock.results)).not.toMatch(/password|token|kdf/i);
  });

  it('shows an outcome-unknown warning instead of automatically replaying a restored grant', async () => {
    const now = Date.now();
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => ({
        ok: true,
        data: {
          status: 'outcome_unknown',
          serverOrigin: 'https://vault.example',
          email: 'user@example.com',
          createdAt: now - 1_000,
          expiresAt: now + 60_000,
          terminalAt: now,
        },
      }),
    }));

    expect(app.route).toEqual({ name: 'login', error: t('auth.pendingLogin.outcomeUnknown') });
  });

  it('rejects a widened pending-login status containing credential material', async () => {
    const deviceStatus = vi.fn(async () => ({ ok: true as const, data: { status: 'none' as const } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => ({
        ok: true,
        data: {
          status: 'twoFactor',
          attemptId: 26,
          continuationId: PENDING_LOGIN_CONTINUATION_ID,
          providers: [0],
          expiresAt: Date.now() + 60_000,
          masterPasswordHash: 'must-not-cross-the-wire',
        },
      } as Res),
      'auth.deviceLogin.status': deviceStatus,
    }));

    expect(app.route).toEqual({ name: 'login', error: t('common.error') });
    expect(deviceStatus).not.toHaveBeenCalled();
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
  it('routes password hints from logged-out login through generic success and back', async () => {
    const requestPasswordHint = vi.fn(async () => ({
      ok: true as const, data: { status: 'sent' as const },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.requestPasswordHint': requestPasswordHint,
    }));
    let auth = view(app, 'vw-auth-views');
    auth.dispatchEvent(new CustomEvent('vw-auth-password-hint-start', {
      detail: { email: 'User@Example.COM' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'passwordHint', email: 'User@Example.COM' });

    auth = view(app, 'vw-auth-views');
    auth.dispatchEvent(new CustomEvent('vw-password-hint-submit', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);
    expect(requestPasswordHint).toHaveBeenCalledWith({
      type: 'auth.requestPasswordHint', email: 'user@example.com',
    });
    expect(app.route).toEqual({
      name: 'passwordHint', email: 'user@example.com', status: 'sent',
    });
    await settle(app);
    const renderedAuth = view<HTMLElement & {
      updateComplete: Promise<unknown>;
      passwordHintStatus?: string;
    }>(app, 'vw-auth-views');
    await renderedAuth.updateComplete;
    expect(renderedAuth.passwordHintStatus).toBe('sent');
    const hint = renderedAuth.shadowRoot?.querySelector('vw-password-hint-view');
    await hint?.updateComplete;
    const banner = hint?.shadowRoot?.querySelector('vw-status-message');
    await banner?.updateComplete;
    expect(banner?.message).toBe(t('auth.passwordHint.success'));
    expect(banner?.message).not.toContain('user@example.com');

    hint?.dispatchEvent(new CustomEvent('vw-password-hint-back', {
      detail: { email: 'user@example.com' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'login' });
  });

  it('displays typed password-hint errors and rejects widened success data', async () => {
    const handler = vi.fn()
      .mockResolvedValueOnce({
        ok: false, error: { code: 'error', message: 'Hint delivery failed.' },
      })
      .mockResolvedValueOnce({ ok: true, data: { accountExists: true } });
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.requestPasswordHint': handler as ReqHandler<'auth.requestPasswordHint'>,
    }));

    for (const [email, error] of [
      ['first@example.com', 'Hint delivery failed.'],
      ['second@example.com', t('common.error')],
    ] as const) {
      app.navigate({ name: 'passwordHint', email });
      view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-password-hint-submit', {
        detail: { email },
      }));
      await settle(app);
      expect(app.route).toEqual({ name: 'passwordHint', email, error });
    }
    expect(document.body.textContent).not.toContain('accountExists');
  });

  it('surfaces only an exact bounded Vaultwarden hint result', async () => {
    const message = 'Your password hint is: favorite constellation';
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.requestPasswordHint': async () => ({
        ok: true, data: { status: 'hint', message },
      }),
    }));
    app.navigate({ name: 'passwordHint', email: 'user@example.com' });

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-password-hint-submit', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);

    expect(app.route).toEqual({
      name: 'passwordHint', email: 'user@example.com', status: 'hint', message,
    });
  });

  it.each([
    [
      'waiting',
      { status: 'waiting', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com', expiresAt: 120_000 },
      { name: 'sso', status: 'waiting', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com' },
    ],
    [
      'processing',
      { status: 'processing', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com', expiresAt: 120_000 },
      { name: 'sso', status: 'processing', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com' },
    ],
    [
      'outcome_unknown',
      {
        status: 'outcome_unknown',
        attemptId: SSO_ATTEMPT_ID,
        generation: SSO_ATTEMPT_GENERATION,
        email: 'user@example.com',
        createdAt: 10_000,
        expiresAt: 120_000,
        terminalAt: 20_000,
      },
      { name: 'sso', status: 'outcome_unknown', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com' },
    ],
    [
      'error',
      { status: 'error', message: 'Identity provider rejected the request' },
      { name: 'sso', status: 'error', error: 'Identity provider rejected the request' },
    ],
  ] as const)('restores the SSO %s state before other logged-out flows', async (
    _label,
    status,
    expectedRoute,
  ) => {
    const accountPasskeyStatus = vi.fn(async () => ({
      ok: true as const,
      data: { status: 'none' as const },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.sso.status': async () => ({ ok: true, data: status } as Res),
      'auth.accountPasskey.status': accountPasskeyStatus,
    }));

    expect(app.route).toEqual(expectedRoute);
    expect(accountPasskeyStatus).not.toHaveBeenCalled();
  });

  it('starts SSO from the login view and can cancel a waiting attempt', async () => {
    const begin = vi.fn(async () => ({
      ok: true as const,
      data: { status: 'waiting' as const, attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com', expiresAt: 120_000 },
    }));
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: true } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.sso.begin': begin,
      'auth.sso.cancel': cancel,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-sso-start', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);

    expect(begin).toHaveBeenCalledWith({ type: 'auth.sso.begin', email: 'user@example.com' });
    expect(app.route).toEqual({ name: 'sso', status: 'waiting', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com' });

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-sso-cancel'));
    await settle(app);
    expect(cancel).toHaveBeenCalledWith({
      type: 'auth.sso.cancel', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION,
    });
    expect(app.route).toEqual({ name: 'login' });
  });

  it('keeps authoritative SSO state when cancellation loses to callback claim', async () => {
    const status = vi.fn()
      .mockResolvedValueOnce({
        ok: true as const,
        data: { status: 'waiting' as const, attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com', expiresAt: 120_000 },
      })
      .mockResolvedValueOnce({
        ok: true as const,
        data: { status: 'processing' as const, attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com', expiresAt: 120_000 },
      });
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.sso.status': status,
      'auth.sso.cancel': async () => ({ ok: true, data: { cancelled: false } }),
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-sso-cancel'));
    await settle(app);

    expect(app.route).toEqual({
      name: 'sso',
      status: 'processing',
      attemptId: SSO_ATTEMPT_ID,
      generation: SSO_ATTEMPT_GENERATION,
      email: 'user@example.com',
    });
  });

  it('applies RequireSso for the exact email and exposes only the SSO login action', async () => {
    const requirement = vi.fn(async () => ({ ok: true as const, data: { required: true } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.isDeviceRemembered': async () => ({ ok: true, data: { remembered: false } }),
      'auth.sso.requirement': requirement,
    }));
    const auth = view<HTMLElement & { ssoRequired: boolean }>(app, 'vw-auth-views');
    const email = auth.shadowRoot!.getElementById('email') as HTMLInputElement;
    email.value = 'required@example.com';
    email.dispatchEvent(new Event('change'));
    await settle(app);

    expect(requirement).toHaveBeenCalledWith({
      type: 'auth.sso.requirement',
      email: 'required@example.com',
    });
    expect(app.ssoRequired).toBe(true);
    expect(auth.ssoRequired).toBe(true);
    expect(auth.shadowRoot!.getElementById('password')).toBeNull();
    expect(auth.shadowRoot!.querySelector('[data-account-passkey]')).toBeNull();
    expect(auth.shadowRoot!.querySelector('[data-device-login]')).toBeNull();
    expect(auth.shadowRoot!.querySelector('[data-sso-login].primary')).not.toBeNull();
  });

  it('automatically starts SSO with the organization identifier returned by password login', async () => {
    const begin = vi.fn(async () => ({
      ok: true as const,
      data: { status: 'waiting' as const, attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com', expiresAt: 120_000 },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: {
          kind: 'ssoRequired',
          email: 'user@example.com',
          organizationIdentifier: 'example-org',
        },
      }),
      'auth.sso.begin': begin,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'must-not-reappear' },
    }));
    await settle(app);

    expect(begin).toHaveBeenCalledWith({
      type: 'auth.sso.begin',
      email: 'user@example.com',
      organizationIdentifier: 'example-org',
    });
    expect(JSON.stringify(begin.mock.calls)).not.toContain('must-not-reappear');
    expect(app.route).toEqual({ name: 'sso', status: 'waiting', attemptId: SSO_ATTEMPT_ID, generation: SSO_ATTEMPT_GENERATION, email: 'user@example.com' });
  });

  it('starts account passkey login without email and renders the waiting state', async () => {
    const begin = vi.fn(async () => ({
      ok: true as const,
      data: {
        status: 'waiting' as const,
        attemptId: '11111111-1111-4111-8111-111111111111',
        expiresAt: Date.now() + 60_000,
      },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.accountPasskey.begin': begin,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-account-passkey-start'));
    await settle(app);

    expect(begin).toHaveBeenCalledWith({ type: 'auth.accountPasskey.begin' });
    expect(app.route).toEqual({ name: 'accountPasskey', status: 'waiting' });
  });

  it('restores an active account passkey attempt before device login state', async () => {
    const deviceStatus = vi.fn(async () => ({ ok: true as const, data: { status: 'none' as const } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.accountPasskey.status': async () => ({
        ok: true,
        data: {
          status: 'waiting',
          attemptId: '11111111-1111-4111-8111-111111111111',
          expiresAt: Date.now() + 60_000,
        },
      }),
      'auth.deviceLogin.status': deviceStatus,
    }));

    expect(app.route).toEqual({ name: 'accountPasskey', status: 'waiting' });
    expect(deviceStatus).not.toHaveBeenCalled();
  });

  it.each([
    [true, { name: 'login' }],
    [false, { name: 'accountPasskey', status: 'outcome_unknown' }],
  ] as const)('routes account passkey cancellation result %s without hiding uncertainty', async (
    cancelled,
    expectedRoute,
  ) => {
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.accountPasskey.status': async () => ({
        ok: true,
        data: {
          status: 'waiting',
          attemptId: '11111111-1111-4111-8111-111111111111',
          expiresAt: Date.now() + 60_000,
        },
      }),
      'auth.accountPasskey.cancel': cancel,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-account-passkey-cancel'));
    await settle(app);

    expect(cancel).toHaveBeenCalledWith({ type: 'auth.accountPasskey.cancel' });
    expect(app.route).toEqual(expectedRoute);
    if (!cancelled) {
      expect(view(app, 'vw-auth-views').shadowRoot?.querySelector('[data-account-passkey-check]'))
        .not.toBeNull();
    }
  });

  it('shows successful account passkey completion only as a locked master-password step', async () => {
    window.history.replaceState(null, '', '/ui/popup/popup.html?accountPasskey=locked');
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
    }));

    expect(app.route).toEqual({
      name: 'unlock',
      notice: t('auth.accountPasskey.success'),
    });
    const auth = view<HTMLElement & { notice?: string }>(app, 'vw-auth-views');
    expect(auth.notice).toBe(t('auth.accountPasskey.success'));
  });

  it('enters the vault and reports immediate unlock for an authoritative PRF outcome', async () => {
    window.history.replaceState(null, '', '/ui/popup/popup.html?accountPasskey=unlocked');
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
    }));

    expect(app.route.name).toBe('vault');
    expect(app.toastMessage).toBe(t('auth.accountPasskey.unlocked'));
  });

  it('does not claim unlock when an unlocked outcome popup finds no session', async () => {
    window.history.replaceState(null, '', '/ui/popup/popup.html?accountPasskey=unlocked');
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
    }));

    expect(app.route).toEqual({ name: 'accountPasskey', status: 'outcome_unknown' });
  });

  it('keeps two-factor and unknown account passkey outcomes distinct', async () => {
    window.history.replaceState(null, '', '/ui/popup/popup.html?accountPasskey=two_factor_unsupported');
    const twoFactor = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
    }));
    expect(twoFactor.route).toEqual({ name: 'accountPasskey', status: 'two_factor_unsupported' });
    twoFactor.remove();

    window.history.replaceState(null, '', '/ui/popup/popup.html?accountPasskey=outcome_unknown');
    const unknown = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
    }));
    expect(unknown.route).toEqual({ name: 'accountPasskey', status: 'outcome_unknown' });
  });

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

  it('starts registration before collecting a password and enforces the 11/12 finish boundary', async () => {
    const startRegistration = vi.fn(async () => ({
      ok: true as const,
      data: {
        kind: 'registrationFinish' as const,
        attemptId: 7,
        email: 'new@example.com',
        expiresAt: Date.now() + 60_000,
      },
    }));
    const register = vi.fn(async () => ({
      ok: true as const,
      data: { kind: 'twoFactor' as const, providers: [0] },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.startRegistration': startRegistration,
      'auth.register': register,
    }));
    app.navigate({ name: 'register' });
    await app.updateComplete;
    const authView = view(app, 'vw-auth-views');

    authView.dispatchEvent(new CustomEvent('vw-auth-register-submit', {
      detail: { email: 'new@example.com', name: 'Ada' },
    }));
    await settle(app);
    expect(startRegistration).toHaveBeenCalledWith({
      type: 'auth.startRegistration',
      email: 'new@example.com',
      name: 'Ada',
    });
    expect(app.route).toMatchObject({
      name: 'registrationFinish',
      attemptId: 7,
      email: 'new@example.com',
    });

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-register-finish-submit', {
      detail: { masterPassword: 'a'.repeat(11), confirm: 'a'.repeat(11), masterPasswordHint: '' },
    }));
    await settle(app);
    expect(register).not.toHaveBeenCalled();
    expect(app.route).toMatchObject({
      name: 'registrationFinish',
      error: t('auth.passwordMin', { min: 12 }),
    });

    const password = 'TwelveChars!';
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-register-finish-submit', {
      detail: { masterPassword: password, confirm: password, masterPasswordHint: password },
    }));
    await settle(app);
    expect(register).not.toHaveBeenCalled();
    expect(app.route).toMatchObject({
      name: 'registrationFinish',
      error: t('security.masterPasswordHintMatches'),
    });

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-register-finish-submit', {
      detail: { masterPassword: password, confirm: password, masterPasswordHint: 'case matters' },
    }));
    await settle(app);
    expect(register).toHaveBeenCalledWith({
      type: 'auth.register',
      attemptId: 7,
      masterPassword: password,
      masterPasswordHint: 'case matters',
    });
    expect(app.route).toEqual({ name: 'twoFactor', flow: 'password', providers: [0] });
  });

  it('shows check-email without retaining a registration password', async () => {
    const startRegistration = vi.fn(async () => ({
      ok: true as const,
      data: { kind: 'registrationEmailSent' as const, email: 'new@example.com' },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.startRegistration': startRegistration,
    }));
    app.navigate({ name: 'register' });
    await app.updateComplete;

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-register-submit', {
      detail: { email: 'new@example.com' },
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'registrationCheckEmail', email: 'new@example.com' });
    const authView = view(app, 'vw-auth-views');
    expect(authView.shadowRoot?.querySelector('input')).toBeNull();
  });

  it('leaves finish after a committed registration or an ambiguous outcome', async () => {
    const complete = vi.fn(async () => ({
      ok: true as const,
      data: { kind: 'registrationComplete' as const, email: 'new@example.com' },
    }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.register': complete,
    }));
    app.navigate({
      name: 'registrationFinish',
      attemptId: 3,
      email: 'new@example.com',
      expiresAt: Date.now() + 60_000,
    });
    await app.updateComplete;
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-register-finish-submit', {
      detail: { masterPassword: 'TwelveChars!', confirm: 'TwelveChars!', masterPasswordHint: '' },
    }));
    await settle(app);
    expect(app.route).toEqual({
      name: 'login',
      notice: t('auth.registrationCompleteLogin'),
    });

    const uncertain = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.register': async () => ({
        ok: false,
        error: { code: 'outcome_unknown' as const, message: 'Account may exist' },
      }),
    }));
    uncertain.navigate({
      name: 'registrationFinish',
      attemptId: 4,
      email: 'other@example.com',
      expiresAt: Date.now() + 60_000,
    });
    await uncertain.updateComplete;
    view(uncertain, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-register-finish-submit', {
      detail: { masterPassword: 'TwelveChars!', confirm: 'TwelveChars!', masterPasswordHint: '' },
    }));
    await settle(uncertain);
    expect(uncertain.route).toEqual({ name: 'login', error: 'Account may exist' });
  });

  it('cancels the exact in-memory registration attempt when starting over', async () => {
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: true } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.cancelRegistration': cancel,
    }));
    app.navigate({
      name: 'registrationFinish',
      attemptId: 8,
      email: 'new@example.com',
      expiresAt: Date.now() + 60_000,
    });
    await app.updateComplete;
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-registration-cancel'));
    await settle(app);

    expect(cancel).toHaveBeenCalledWith({ type: 'auth.cancelRegistration', attemptId: 8 });
    expect(app.route).toEqual({ name: 'register' });
  });

  it('routes to twoFactor when required', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [0, 1] } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', { detail: { email: 'a@b.c', masterPassword: 'x' } }));
    await settle(app);
    expect(app.route).toEqual({ name: 'twoFactor', flow: 'password', providers: [0, 1] });
  });

  it('uses official 2FA priority, retains a choice for one attempt, and resets it for the next', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [0, 1, 6] } }),
      'auth.sendEmailCode': async () => ({ ok: true, data: null }),
    }));
    const auth = view<HTMLElement & {
      selectedProvider?: number;
      twoFactorAttemptKey: string;
    }>(app, 'vw-auth-views');
    auth.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);
    expect(auth.selectedProvider).toBe(6);
    const firstAttemptKey = auth.twoFactorAttemptKey;

    const provider = auth.shadowRoot!.getElementById('provider') as HTMLSelectElement;
    provider.value = '1';
    provider.dispatchEvent(new Event('change'));
    await settle(app);
    expect(auth.selectedProvider).toBe(1);
    app.navigate({ ...app.route as Extract<typeof app.route, { name: 'twoFactor' }>, error: 'Retry' });
    await app.updateComplete;
    expect(auth.selectedProvider).toBe(1);
    expect(auth.twoFactorAttemptKey).toBe(firstAttemptKey);

    app.navigate({ name: 'login' });
    app.navigate({ name: 'twoFactor', flow: 'password', providers: [0, 1, 6] });
    await app.updateComplete;
    expect(auth.twoFactorAttemptKey).not.toBe(firstAttemptKey);
    expect(auth.selectedProvider).toBe(6);
  });

  it('auto-sends the first email code once and reports explicit resend success accessibly', async () => {
    const sendEmail = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'twoFactor', providers: [1], continuationId: PENDING_LOGIN_CONTINUATION_ID },
      }),
      'auth.sendEmailCode': sendEmail,
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(sendEmail).toHaveBeenLastCalledWith({
      type: 'auth.sendEmailCode',
      continuationId: PENDING_LOGIN_CONTINUATION_ID,
    });

    const auth = view<HTMLElement>(app, 'vw-auth-views');
    const resend = [...auth.shadowRoot!.querySelectorAll('button')]
      .find((candidate) => candidate.textContent?.includes(t('auth.twoFactor.resendEmailCode')));
    resend?.click();
    await settle(app);

    expect(sendEmail).toHaveBeenCalledTimes(2);
    expect(app.route).toMatchObject({
      name: 'twoFactor',
      notice: t('auth.twoFactor.emailCodeSent'),
    });
    const status = auth.shadowRoot!.querySelectorAll<HTMLElement & { message?: string }>('vw-status-message');
    expect([...status].some((message) => message.message === t('auth.twoFactor.emailCodeSent'))).toBe(true);
  });

  it('reports resend failure and rejects email events from a non-email or stale attempt', async () => {
    let sends = 0;
    const sendEmail = vi.fn(async () => {
      sends += 1;
      return sends === 1
        ? { ok: true as const, data: null }
        : { ok: false as const, error: { code: 'error' as const, message: 'Email unavailable' } };
    });
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({ ok: true, data: { kind: 'twoFactor', providers: [0, 1] } }),
      'auth.sendEmailCode': sendEmail,
    }));
    const auth = view<HTMLElement & { twoFactorAttemptKey: string }>(app, 'vw-auth-views');
    auth.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);
    const attemptKey = auth.twoFactorAttemptKey;
    auth.dispatchEvent(new CustomEvent('vw-auth-send-email-code', {
      detail: { provider: 1, attemptKey, automatic: false },
    }));
    await settle(app);
    expect(sendEmail).not.toHaveBeenCalled();

    const provider = auth.shadowRoot!.getElementById('provider') as HTMLSelectElement;
    provider.value = '1';
    provider.dispatchEvent(new Event('change'));
    await settle(app);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    const resend = [...auth.shadowRoot!.querySelectorAll('button')]
      .find((candidate) => candidate.textContent?.includes(t('auth.twoFactor.resendEmailCode')));
    resend?.click();
    await settle(app);
    expect(sendEmail).toHaveBeenCalledTimes(2);
    expect(app.route).toMatchObject({ name: 'twoFactor', error: 'Email unavailable' });

    app.navigate({ name: 'login' });
    await app.updateComplete;
    auth.dispatchEvent(new CustomEvent('vw-auth-send-email-code', {
      detail: { provider: 1, attemptKey, automatic: false },
    }));
    await settle(app);
    expect(sendEmail).toHaveBeenCalledTimes(2);
  });

  it('auto-sends Email 2FA through the generation-bound device-login verb', async () => {
    const sendEmail = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.status': async () => ({
        ok: true,
        data: deviceLoginPending({ status: 'two_factor', providers: [1] }),
      }),
      'auth.deviceLogin.sendEmailCode': sendEmail,
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'twoFactor', flow: 'device', providers: [1] });
    expect(sendEmail).toHaveBeenCalledWith({
      type: 'auth.deviceLogin.sendEmailCode',
      generation: 4,
    });
  });

  it('starts Duo with only the current password continuation binding', async () => {
    const submitted: Req[] = [];
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: {
          kind: 'twoFactor',
          providers: [2],
          continuationId: PENDING_LOGIN_CONTINUATION_ID,
        },
      }),
      'auth.duo.begin': async (request) => {
        submitted.push(request);
        return { ok: true, data: { status: 'waiting' } };
      },
    }));
    const authView = view(app, 'vw-auth-views');
    authView.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);

    authView.dispatchEvent(new CustomEvent('vw-auth-duo-start', {
      detail: { provider: 2, remember: true },
    }));
    await settle(app);

    expect(submitted).toEqual([{
      type: 'auth.duo.begin',
      flow: 'password',
      provider: 2,
      continuationId: PENDING_LOGIN_CONTINUATION_ID,
      remember: true,
    }]);
    expect(JSON.stringify(submitted)).not.toMatch(/authUrl|redirect|state|code/iu);
  });

  it('routes a restored successful grant to master-password unlock', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => ({
        ok: true,
        data: {
          status: 'twoFactor',
          attemptId: 23,
          continuationId: PENDING_LOGIN_CONTINUATION_ID,
          providers: [0],
          expiresAt: Date.now() + 60_000,
        },
      }),
      'auth.submitTwoFactor': async () => ({ ok: true, data: { kind: 'locked' } }),
      'auth.pinStatus': async () => ({
        ok: true,
        data: {
          enabled: false,
          available: false,
          allowed: true,
          requireMasterPasswordOnRestart: true,
        },
      }),
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-two-factor-submit', {
      detail: { provider: 0, code: '123456', remember: false },
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'unlock' });
  });

  it('cancels a restored password continuation when leaving two-factor login', async () => {
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: true } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => ({
        ok: true,
        data: {
          status: 'twoFactor',
          attemptId: 24,
          continuationId: PENDING_LOGIN_CONTINUATION_ID,
          providers: [1],
          expiresAt: Date.now() + 60_000,
        },
      }),
      'auth.pendingLogin.cancel': cancel,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-back-to-login'));
    await settle(app);

    expect(cancel).toHaveBeenCalledWith({
      type: 'auth.pendingLogin.cancel',
      continuationId: PENDING_LOGIN_CONTINUATION_ID,
    });
    expect(app.route).toEqual({ name: 'login' });
  });

  it('opens two-factor recovery without exposing a URL or cancelling the pending continuation', async () => {
    const openRecovery = vi.fn(async () => ({ ok: true as const, data: null }));
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: true } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => ({
        ok: true,
        data: {
          status: 'twoFactor',
          attemptId: 26,
          continuationId: PENDING_LOGIN_CONTINUATION_ID,
          providers: [0],
          expiresAt: Date.now() + 60_000,
        },
      }),
      'auth.openTwoFactorRecovery': openRecovery,
      'auth.pendingLogin.cancel': cancel,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-two-factor-recovery'));
    await settle(app);

    expect(openRecovery).toHaveBeenCalledWith({ type: 'auth.openTwoFactorRecovery' });
    expect(cancel).not.toHaveBeenCalled();
    expect(app.route).toEqual({
      name: 'twoFactor',
      flow: 'password',
      providers: [0],
      continuationId: PENDING_LOGIN_CONTINUATION_ID,
    });
  });

  it('does not report a claimed password continuation as cancelled', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.pendingLogin.status': async () => ({
        ok: true,
        data: {
          status: 'twoFactor',
          attemptId: 25,
          continuationId: PENDING_LOGIN_CONTINUATION_ID,
          providers: [1],
          expiresAt: Date.now() + 60_000,
        },
      }),
      'auth.pendingLogin.cancel': async () => ({ ok: true, data: { cancelled: false } }),
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-back-to-login'));
    await settle(app);

    expect(app.route).toEqual({ name: 'login', error: t('auth.pendingLogin.outcomeUnknown') });
  });

  it('routes new-device verification and sends only attempt-bound OTP actions', async () => {
    const expiresAt = Date.now() + 5 * 60_000;
    const submitted: Req[] = [];
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'newDeviceVerification', attemptId: 7, expiresAt },
      }),
      'auth.newDeviceVerification.sendOtp': async (request) => {
        submitted.push(request);
        return { ok: true, data: null };
      },
      'auth.newDeviceVerification.submit': async (request) => {
        submitted.push(request);
        return { ok: true, data: { kind: 'unlocked' } };
      },
    }));
    const authView = view(app, 'vw-auth-views');
    authView.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'must-not-reappear' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'newDeviceVerification', attemptId: 7, expiresAt });

    authView.dispatchEvent(new CustomEvent('vw-auth-new-device-verification-send-otp'));
    await settle(app);
    expect(app.route).toEqual({
      name: 'newDeviceVerification',
      attemptId: 7,
      expiresAt,
      notice: t('auth.newDeviceVerification.codeSent'),
    });
    authView.dispatchEvent(new CustomEvent('vw-auth-new-device-verification-submit', {
      detail: { code: '123456' },
    }));
    await settle(app);

    expect(submitted).toEqual([
      { type: 'auth.newDeviceVerification.sendOtp', attemptId: 7 },
      { type: 'auth.newDeviceVerification.submit', attemptId: 7, code: '123456' },
    ]);
    expect(JSON.stringify(submitted)).not.toContain('must-not-reappear');
    expect(app.route.name).toBe('vault');
  });

  it('cancels the exact new-device verification attempt before returning to login', async () => {
    const expiresAt = Date.now() + 5 * 60_000;
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: true } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'newDeviceVerification', attemptId: 11, expiresAt },
      }),
      'auth.newDeviceVerification.cancel': cancel,
    }));
    const authView = view(app, 'vw-auth-views');
    authView.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'password' },
    }));
    await settle(app);

    authView.dispatchEvent(new CustomEvent('vw-auth-new-device-verification-cancel'));
    await settle(app);
    expect(cancel).toHaveBeenCalledWith({
      type: 'auth.newDeviceVerification.cancel',
      attemptId: 11,
    });
    expect(app.route).toEqual({ name: 'login' });
  });

  it('rejects malformed new-device verification route data instead of showing a false challenge', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'newDeviceVerification', attemptId: -1, expiresAt: Number.NaN },
      } as Res),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'user@example.com', masterPassword: 'password' },
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'login', error: t('common.error') });
  });

  it('keeps the provider 7 owner in the active auth route', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'twoFactor', providers: [0, 7], fido2: FIDO_ROUTE_DATA },
      }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'twoFactor', flow: 'password', providers: [0, 7], fido2: FIDO_ROUTE_DATA });
  });

  it('opens the fallback connector only for the current provider 7 attempt', async () => {
    const submitted: Req[] = [];
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'twoFactor', providers: [7], fido2: FIDO_ROUTE_DATA },
      }),
      'auth.beginFido2': async (request) => {
        submitted.push(request);
        return { ok: true, data: null };
      },
    }));
    const authView = view(app, 'vw-auth-views');
    authView.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);

    authView.dispatchEvent(new CustomEvent('vw-auth-fido2-start', {
      detail: { owner: { ...FIDO_ROUTE_DATA.owner, generation: 8 } },
    }));
    await settle(app);
    expect(submitted).toHaveLength(0);

    authView.dispatchEvent(new CustomEvent('vw-auth-fido2-start', {
      detail: { owner: FIDO_ROUTE_DATA.owner },
    }));
    await settle(app);
    expect(submitted).toEqual([{
      type: 'auth.beginFido2', owner: FIDO_ROUTE_DATA.owner, locale: 'zh-CN',
    }]);
    expect(app.route.name).toBe('twoFactor');
  });

  it('keeps the provider 7 launch retryable when opening the fallback tab fails', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'twoFactor', providers: [7], fido2: FIDO_ROUTE_DATA },
      }),
      'auth.beginFido2': async () => ({
        ok: false, error: { code: 'error', message: 'security key rejected' },
      }),
    }));
    const authView = view(app, 'vw-auth-views');
    authView.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);
    authView.dispatchEvent(new CustomEvent('vw-auth-fido2-start', {
      detail: { owner: FIDO_ROUTE_DATA.owner },
    }));
    await settle(app);
    expect(app.route).toEqual({
      name: 'twoFactor',
      flow: 'password',
      providers: [7],
      fido2: FIDO_ROUTE_DATA,
      error: 'security key rejected',
    });
  });

  it('ignores a delayed fallback launch after returning to login', async () => {
    const begin = vi.fn(async () => ({ ok: true, data: null } as Res));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.login': async () => ({
        ok: true,
        data: { kind: 'twoFactor', providers: [7], fido2: FIDO_ROUTE_DATA },
      }),
      'auth.beginFido2': begin,
    }));
    const authView = view(app, 'vw-auth-views');
    authView.dispatchEvent(new CustomEvent('vw-auth-login-submit', {
      detail: { email: 'a@b.c', masterPassword: 'x' },
    }));
    await settle(app);
    authView.dispatchEvent(new CustomEvent('vw-auth-back-to-login'));
    await settle(app);
    authView.dispatchEvent(new CustomEvent('vw-auth-fido2-start', {
      detail: { owner: FIDO_ROUTE_DATA.owner },
    }));
    await settle(app);
    expect(begin).not.toHaveBeenCalled();
  });

  it('unlocks and routes to vault', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
      'auth.unlock': async () => ({ ok: true, data: { state: 'unlocked' } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-unlock-submit', { detail: { masterPassword: 'pw' } }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });

  it('resumes a locked keyboard action once and closes before background dispatch', async () => {
    const continuationId = '11111111-1111-4111-8111-111111111111';
    const resume = vi.fn(async () => ({ ok: true as const, data: { status: 'started' as const } }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
      'auth.unlock': async () => ({ ok: true, data: { state: 'unlocked' } }),
      'autofill.continuation.status': async () => ({
        ok: true,
        data: { status: 'unlock_required', continuationId, channel: 'keyboard', expiresAt: Date.now() + 30_000 },
      }),
      'autofill.continuation.resumeUnlock': resume,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-unlock-submit', {
      detail: { masterPassword: 'pw' },
    }));
    await settle(app);

    expect(resume).toHaveBeenCalledWith(expect.objectContaining({ continuationId }));
    expect(close).toHaveBeenCalledOnce();
  });

  it('pins locked context suggestions to the original tab instead of the current Popup tab', async () => {
    const continuationId = '22222222-2222-4222-8222-222222222222';
    const suggestions = vi.fn(async () => ({
      ok: true as const,
      data: { outcome: { status: 'ready' as const, suggestions: [] } },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
      'auth.unlock': async () => ({ ok: true, data: { state: 'unlocked' } }),
      'autofill.continuation.status': async () => ({
        ok: true,
        data: { status: 'unlock_required', continuationId, channel: 'context', expiresAt: Date.now() + 30_000 },
      }),
      'autofill.continuation.resumeUnlock': async () => ({
        ok: true,
        data: {
          status: 'show_suggestions',
          tabId: 42,
          outcome: { status: 'ready', suggestions: [] },
        },
      }),
      'autofill.getTabSuggestions': suggestions,
    }), fakeBrowser({ getActiveTabId: async () => 999 }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-unlock-submit', {
      detail: { masterPassword: 'pw' },
    }));
    await settle(app);

    expect(suggestions).not.toHaveBeenCalled();
    expect((app as unknown as { activeTabId: number }).activeTabId).toBe(42);
  });

  it('shows a localized invalid-PIN error without logging out', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: true, available: true, allowed: true, requireMasterPasswordOnRestart: false,
      } }),
      'auth.unlockWithPin': async () => ({
        ok: false,
        error: { code: 'invalid_pin', message: 'Incorrect PIN' },
      }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-pin-unlock-submit', {
      detail: { pin: 'wrong' },
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'unlock', error: t('auth.invalidPin') });
  });

  it('routes to login after the worker logs out an account at the PIN attempt limit', async () => {
    let stateReads = 0;
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({
        ok: true,
        data: { state: stateReads++ === 0 ? 'locked' : 'loggedOut' },
      }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: true, available: true, allowed: true, requireMasterPasswordOnRestart: false,
      } }),
      'auth.unlockWithPin': async () => ({
        ok: false,
        error: { code: 'pin_attempts_exceeded', message: 'The account was logged out.' },
      }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-pin-unlock-submit', {
      detail: { pin: 'wrong' },
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'login', error: t('auth.tooManyInvalidPin') });
  });

  it('logs out from the unlock screen only after the worker confirms success', async () => {
    let stateReads = 0;
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({
        ok: true,
        data: { state: stateReads++ === 0 ? 'locked' : 'loggedOut' },
      }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
      'auth.logout': logout,
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-logout'));
    await settle(app);
    expect(window.confirm).toHaveBeenCalledWith(t('auth.logoutConfirm'));
    expect(logout).toHaveBeenCalledOnce();
    expect(app.route.name).toBe('login');
  });

  it('does not request logout from the unlock screen when confirmation is cancelled', async () => {
    vi.mocked(window.confirm).mockReturnValue(false);
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
      'auth.logout': logout,
    }));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-logout'));
    await settle(app);

    expect(logout).not.toHaveBeenCalled();
    expect(app.route.name).toBe('unlock');
  });

  it('shows a generic retry error when reopened after a failed fallback completion', async () => {
    window.history.replaceState(null, '', '/ui/popup/popup.html?fido2=error');
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
    }));
    expect(app.route).toEqual({ name: 'login', error: t('auth.fido2.unknownResult') });
  });

  it('stays on the unlock screen and reports a failed logout', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' } }),
      'auth.pinStatus': async () => ({ ok: true, data: {
        enabled: false, available: false, allowed: true, requireMasterPasswordOnRestart: true,
      } }),
      'auth.logout': async () => ({ ok: false, error: { code: 'error', message: 'Logout failed' } }),
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-logout'));
    await settle(app);
    expect(app.route.name).toBe('unlock');
    expect(app.toastMessage).toBe('Logout failed');
  });
});

describe('vw-popup-app device login requester', () => {
  it('restores a pending requester before showing the logged-out login screen', async () => {
    const status = vi.fn(async () => ({ ok: true as const, data: deviceLoginPending() }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.status': status,
    }));

    expect(status).toHaveBeenCalledOnce();
    expect(app.route).toEqual({ name: 'deviceLogin' });
    const requester = view<HTMLElement & { model?: Record<string, unknown> }>(app, 'vw-device-login-view');
    expect(requester.model?.status).toBe('pending');
    expect(Object.isFrozen(requester.model)).toBe(true);
    expect(requester.model).not.toHaveProperty('requestId');
    expect(requester.shadowRoot?.textContent).toContain('amber');
  });

  it('keeps and refreshes the requester when exact cancellation returns false', async () => {
    const status = vi.fn(async () => ({ ok: true as const, data: deviceLoginPending() }));
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: false } }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.status': status,
      'auth.deviceLogin.cancel': cancel,
    }));

    view(app, 'vw-device-login-view').dispatchEvent(new CustomEvent('vw-device-login-cancel'));
    await settle(app);

    expect(cancel).toHaveBeenCalledWith({ type: 'auth.deviceLogin.cancel', generation: 4 });
    expect(status).toHaveBeenNthCalledWith(1, { type: 'auth.deviceLogin.status' });
    expect(status).toHaveBeenNthCalledWith(2, { type: 'auth.deviceLogin.status', generation: 4 });
    expect(app.route).toEqual({ name: 'deviceLogin' });
    const requester = view<HTMLElement & { model?: Record<string, unknown> }>(
      app,
      'vw-device-login-view',
    );
    expect(requester.model).toMatchObject({ status: 'pending', ownerGeneration: 4 });
  });

  it('begins from the email-only event and never sends a master password', async () => {
    const begin = vi.fn(async (request: Extract<Req, { type: 'auth.deviceLogin.begin' }>) => {
      expect(request.email).toBe('user@example.com');
      return { ok: true as const, data: deviceLoginPending() };
    });
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.begin': begin,
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-device-login-start', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);

    expect(begin).toHaveBeenCalledWith({ type: 'auth.deviceLogin.begin', email: 'user@example.com' });
    expect(Object.keys(begin.mock.calls[0]![0])).toEqual(['type', 'email']);
    expect(app.route).toEqual({ name: 'deviceLogin' });
  });

  it('keeps device direct-code two-factor on its generation-bound verb', async () => {
    const deviceSubmit = vi.fn(async () => ({ ok: true as const, data: { status: 'unlocked' as const } }));
    const passwordSubmit = vi.fn(async () => ({ ok: true as const, data: { kind: 'unlocked' as const } }));
    const beginFido = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.begin': async () => ({
        ok: true,
        data: deviceLoginPending({ status: 'two_factor', providers: [1] }),
      }),
      'auth.deviceLogin.submitTwoFactor': deviceSubmit,
      'auth.submitTwoFactor': passwordSubmit,
      'auth.beginFido2': beginFido,
    }));
    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-device-login-start', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'twoFactor', flow: 'device', providers: [1] });
    const auth = view(app, 'vw-auth-views');
    auth.dispatchEvent(new CustomEvent('vw-auth-fido2-start', {
      detail: { owner: FIDO_ROUTE_DATA.owner },
    }));
    auth.dispatchEvent(new CustomEvent('vw-auth-two-factor-submit', {
      detail: { provider: 1, code: '123456', remember: true },
    }));
    await settle(app);

    expect(deviceSubmit).toHaveBeenCalledWith({
      type: 'auth.deviceLogin.submitTwoFactor', generation: 4,
      provider: 1, code: '123456', remember: true,
    });
    expect(passwordSubmit).not.toHaveBeenCalled();
    expect(beginFido).not.toHaveBeenCalled();
    expect(app.route.name).toBe('vault');
  });

  it('launches a device-login FIDO2 challenge with its exact flow owner', async () => {
    const beginFido = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.begin': async () => ({
        ok: true,
        data: deviceLoginPending({
          status: 'two_factor',
          providers: [7],
          fido2: DEVICE_FIDO_ROUTE_DATA,
        }),
      }),
      'auth.beginFido2': beginFido,
    }));
    const auth = view(app, 'vw-auth-views');
    auth.dispatchEvent(new CustomEvent('vw-auth-device-login-start', {
      detail: { email: 'user@example.com' },
    }));
    await settle(app);
    expect(app.route).toEqual({
      name: 'twoFactor',
      flow: 'device',
      providers: [7],
      fido2: DEVICE_FIDO_ROUTE_DATA,
    });

    auth.dispatchEvent(new CustomEvent('vw-auth-fido2-start', {
      detail: { owner: DEVICE_FIDO_ROUTE_DATA.owner },
    }));
    await settle(app);
    expect(beginFido).toHaveBeenCalledWith({
      type: 'auth.beginFido2',
      owner: DEVICE_FIDO_ROUTE_DATA.owner,
      locale: 'zh-CN',
    });
  });

  it('rechecks auth state when a pending poll observes no coordinator state after background completion', async () => {
    const getState = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: { state: 'loggedOut' } })
      .mockResolvedValueOnce({ ok: true, data: { state: 'unlocked' } });
    const status = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: deviceLoginPending() })
      .mockResolvedValueOnce({ ok: true, data: { status: 'none' } });
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.getState': getState, 'auth.deviceLogin.status': status }));
    const internals = app as unknown as {
      deviceLoginGeneration: number;
      clearDeviceLoginCountdown(): void;
      clearDeviceLoginStatusPoll(): void;
      scheduleDeviceLoginStatusPoll(generation: number): void;
    };
    internals.clearDeviceLoginCountdown();
    internals.clearDeviceLoginStatusPoll();
    vi.useFakeTimers();
    internals.scheduleDeviceLoginStatusPoll(internals.deviceLoginGeneration);

    await vi.advanceTimersByTimeAsync(5_000);
    await app.updateComplete;

    expect(status).toHaveBeenCalledTimes(2);
    expect(getState).toHaveBeenCalledTimes(2);
    expect(app.route.name).toBe('vault');
  });

  it('clears both requester timers on disconnect and ignores a stale startup status', async () => {
    const pendingStatus = deferred<Res>();
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.status': async () => pendingStatus.promise,
    }));
    app.navigate({ name: 'register' });
    pendingStatus.resolve({ ok: true, data: deviceLoginPending() } as Res);
    await settle(app);
    expect(app.route).toEqual({ name: 'register' });

    const active = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.status': async () => ({ ok: true, data: deviceLoginPending() }),
    }));
    const internals = active as unknown as {
      deviceLoginCountdownTimer?: number;
      deviceLoginStatusPollTimer?: number;
    };
    expect(internals.deviceLoginCountdownTimer).not.toBeUndefined();
    expect(internals.deviceLoginStatusPollTimer).not.toBeUndefined();
    active.remove();
    expect(internals.deviceLoginCountdownTimer).toBeUndefined();
    expect(internals.deviceLoginStatusPollTimer).toBeUndefined();
  });

  it('renders outcome unknown as a dedicated non-retry state', async () => {
    const app = await mountApp(fakeRequest({
      'auth.getState': async () => ({ ok: true, data: { state: 'loggedOut' } }),
      'auth.deviceLogin.status': async () => ({
        ok: true,
        data: {
          status: 'outcome_unknown',
          generation: 4,
          serverOrigin: 'https://vault.example',
          createdAt: Date.now() - 1_000,
          expiresAt: Date.now() + 60_000,
          terminalAt: Date.now(),
        },
      }),
    }));
    const requester = view(app, 'vw-device-login-view');
    expect(requester.shadowRoot?.textContent).toContain(t('auth.deviceLogin.outcomeUnknownTitle'));
    expect(requester.shadowRoot?.textContent).not.toContain(t('auth.deviceLogin.expiredDescription'));
    expect(requester.shadowRoot?.querySelector('[data-action="retry"]')).toBeNull();
  });
});

describe('vw-popup-app unlocked navigation', () => {
  it('re-reads auth state and routes to a remaining locked account after password change', async () => {
    const getState = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: { state: 'unlocked' } })
      .mockResolvedValueOnce({ ok: true, data: { state: 'locked' } });
    const changePassword = vi.fn<ReqHandler<'auth.changePassword'>>(async () => ({
      ok: true,
      data: null,
    }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.getState': getState, 'auth.changePassword': changePassword }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'account-security' }, bubbles: true, composed: true,
    }));
    await settle(app);

    view(app, 'vw-account-security-view').dispatchEvent(new CustomEvent('vw-change-password', {
      detail: {
        currentPassword: 'old-password',
        newPassword: 'new-password',
        masterPasswordHint: '',
      },
    }));
    await settle(app);

    expect(changePassword).toHaveBeenCalledWith({
      type: 'auth.changePassword',
      currentPassword: 'old-password',
      newPassword: 'new-password',
      masterPasswordHint: '',
    });
    expect(getState).toHaveBeenCalledTimes(2);
    expect(app.route).toEqual({ name: 'unlock' });
  });

  it('re-reads fail-closed state after an uncertain password-change outcome', async () => {
    const getState = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: { state: 'unlocked' } })
      .mockResolvedValueOnce({ ok: true, data: { state: 'loggedOut' } });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': getState,
      'auth.changePassword': async () => ({
        ok: false,
        error: { code: 'outcome_unknown', message: 'Sign in with the new password.' },
      }),
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'account-security' }, bubbles: true, composed: true,
    }));
    await settle(app);

    view(app, 'vw-account-security-view').dispatchEvent(new CustomEvent('vw-change-password', {
      detail: {
        currentPassword: 'old-password',
        newPassword: 'new-password',
        masterPasswordHint: 'phrase',
      },
    }));
    await settle(app);

    expect(getState).toHaveBeenCalledTimes(2);
    expect(app.route.name).toBe('login');
  });

  it('forwards the explicit browser-restart PIN policy to the worker', async () => {
    const setPin = vi.fn<ReqHandler<'auth.setPin'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.setPin': setPin }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'pin' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-pin-view').dispatchEvent(new CustomEvent('vw-pin-set', {
      detail: { pin: 'word pin', requireMasterPasswordOnRestart: false },
    }));
    await settle(app);

    expect(setPin).toHaveBeenCalledWith({
      type: 'auth.setPin',
      pin: 'word pin',
      requireMasterPasswordOnRestart: false,
    });
  });

  it('refreshes PIN status after a failed KDF request may have revoked PIN first', async () => {
    let pinReads = 0;
    const changeKdf = vi.fn<ReqHandler<'auth.changeKdf'>>(async () => ({
      ok: false,
      error: { code: 'error', message: 'network unavailable' },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.changeKdf': changeKdf,
      'auth.pinStatus': async () => {
        const enabled = pinReads++ === 0;
        return { ok: true, data: {
          enabled,
          available: enabled,
          allowed: true,
          requireMasterPasswordOnRestart: true,
        } };
      },
    }));
    expect(app.pinConfigured).toBe(true);
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'account-security' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-account-security-view').dispatchEvent(new CustomEvent('vw-change-kdf', {
      detail: {
        currentPassword: 'master-password',
        kdf: { kdf: 0, kdfIterations: 800_000 },
      },
    }));
    await settle(app);

    expect(changeKdf).toHaveBeenCalledOnce();
    expect(app.pinConfigured).toBe(false);
  });

  it('keeps PIN shown as configured when KDF preflight rejects before revocation', async () => {
    let pinReads = 0;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.changeKdf': async () => ({
        ok: false,
        error: { code: 'error', message: 'Incorrect master password' },
      }),
      'auth.pinStatus': async () => {
        pinReads += 1;
        return { ok: true, data: {
          enabled: true,
          available: true,
          allowed: true,
          requireMasterPasswordOnRestart: true,
        } };
      },
    }));
    expect(app.pinConfigured).toBe(true);
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'account-security' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-account-security-view').dispatchEvent(new CustomEvent('vw-change-kdf', {
      detail: {
        currentPassword: 'wrong-password',
        kdf: { kdf: 0, kdfIterations: 800_000 },
      },
    }));
    await settle(app);

    expect(pinReads).toBeGreaterThanOrEqual(2);
    expect(app.pinConfigured).toBe(true);
  });

  it('refreshes PIN status after a successful KDF change', async () => {
    let pinReads = 0;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.changeKdf': async () => ({ ok: true, data: null }),
      'auth.pinStatus': async () => {
        const enabled = pinReads++ === 0;
        return { ok: true, data: {
          enabled,
          available: enabled,
          allowed: true,
          requireMasterPasswordOnRestart: true,
        } };
      },
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'account-security' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-account-security-view').dispatchEvent(new CustomEvent('vw-change-kdf', {
      detail: {
        currentPassword: 'master-password',
        kdf: { kdf: 0, kdfIterations: 800_000 },
      },
    }));
    await settle(app);

    expect(pinReads).toBeGreaterThanOrEqual(2);
    expect(app.pinConfigured).toBe(false);
  });

  it('opens the editor on add', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('editor');
  });

  it('inherits validated vault filters and a canonical browser-owned URL into a new login draft', async () => {
    const browser = fakeBrowser({
      getActiveTabUrl: vi.fn(async () => 'HTTPS://Example.COM/account/../login'),
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [login()],
          folders: [{ id: 'folder-1', name: 'Folder' }],
          collections: [{
            id: 'collection-1', name: 'Team', organizationId: 'org-1', canAssignItems: true,
          }],
          orgPermissions: [{
            id: 'org-1', name: 'Acme', isMember: true, canCreateItems: true,
            canCreateCollections: false, canEditCollections: false,
            canDeleteCollections: false, canManageCollections: false,
          }],
        },
      }),
    }), browser);
    const filters = view(app, 'vw-vault-filters');
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { folderId: 'folder-1' }, bubbles: true, composed: true,
    }));
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: 'org-1', collectionId: 'collection-1' },
      bubbles: true,
      composed: true,
    }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-type-picker').dispatchEvent(new CustomEvent('vw-editor-type', {
      detail: { type: 1 }, bubbles: true, composed: true,
    }));
    await settle(app);

    const editor = view<HTMLElement & { context: EditorContext }>(app, 'vw-cipher-editor');
    expect(editor.context.createDefaults).toEqual({
      folderId: 'folder-1',
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
      loginUri: 'https://example.com/login',
    });
    expect(editor.context.draftKey).toMatch(/^\d+:\d+$/);
    expect(editor.shadowRoot?.querySelector<HTMLInputElement>('[data-uri]')?.value)
      .toBe('https://example.com/login');
  });

  it('does not prefill a new login from a non-http active-tab URL', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED), fakeBrowser({
      getActiveTabUrl: vi.fn(async () => 'javascript:alert(1)'),
    }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-type-picker').dispatchEvent(new CustomEvent('vw-editor-type', {
      detail: { type: 1 }, bubbles: true, composed: true,
    }));
    await settle(app);

    const editor = view<HTMLElement & { context: EditorContext }>(app, 'vw-cipher-editor');
    expect(editor.context.createDefaults?.loginUri).toBeUndefined();
    expect(editor.shadowRoot?.querySelector<HTMLInputElement>('[data-uri]')?.value).toBe('');
  });

  it('tracks an inline generated password, writes it into the draft, and protects unsaved changes', async () => {
    const entries: Array<{ generatedAt: number; type: 'password'; value: string }> = [];
    const track = vi.fn(async (request: Extract<Req, { type: 'generator.history.track' }>) => {
      entries.unshift({ generatedAt: 10, type: 'password', value: request.entry.value });
      return { ok: true as const, data: { added: true } };
    });
    const listing = {
      items: [login()], folders: [], collections: [], orgPermissions: [], personalCreationAllowed: true,
    };
    const create = vi.fn(async () => ({ ok: true as const, data: listing }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: listing }),
      'settings.get': async () => ({
        ok: true, data: { generator: createGeneratorPolicySnapshot(null, 9) },
      } as Res),
      'generator.history.list': async () => ({ ok: true, data: { entries: [...entries] } }),
      'generator.history.track': track,
      'vault.createCipher': create,
    }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-type-picker').dispatchEvent(new CustomEvent('vw-editor-type', {
      detail: { type: 1 }, bubbles: true, composed: true,
    }));
    await settle(app);
    const editor = view<HTMLElement & {
      updateComplete: Promise<unknown>;
      hasUnsavedChanges: boolean;
    }>(app, 'vw-cipher-editor');
    editor.shadowRoot!.querySelector<HTMLButtonElement>('[data-generate-password]')!.click();
    await editor.updateComplete;
    const generator = editor.shadowRoot!.querySelector<HTMLElement & {
      updateComplete: Promise<unknown>;
    }>('vw-generator-view')!;
    await generator.updateComplete;
    await settle(app);
    const generated = generator.shadowRoot!.querySelector('[data-output]')?.textContent ?? '';
    expect(generated).not.toBe('');
    generator.shadowRoot!.querySelector<HTMLButtonElement>('[data-select-generated]')!.click();
    await editor.updateComplete;

    expect(editor.shadowRoot!.querySelector<HTMLInputElement>('[data-password]')!.value).toBe(generated);
    expect(editor.hasUnsavedChanges).toBe(true);
    expect(track).toHaveBeenCalledWith(expect.objectContaining({
      type: 'generator.history.track',
      entry: { value: generated, type: 'password', policyRevision: 9 },
    }));

    const confirm = vi.fn(() => false);
    Object.defineProperty(window, 'confirm', { value: confirm, configurable: true });
    app.shadowRoot!.querySelector<HTMLDivElement>('.scrim')!.click();
    expect(app.route.name).toBe('editor');
    expect(confirm).toHaveBeenCalledOnce();

    const name = editor.shadowRoot!.querySelector<HTMLInputElement>('[data-field="name"]')!;
    name.value = 'Generated login';
    name.dispatchEvent(new Event('input'));
    editor.shadowRoot!.querySelector<HTMLButtonElement>('[data-save]')!.click();
    await settle(app);
    expect(create).toHaveBeenCalledWith(expect.objectContaining({
      type: 'vault.createCipher',
      input: expect.objectContaining({
        name: 'Generated login',
        login: expect.objectContaining({ password: generated }),
      }),
    }));
  });

  it('tracks Send password-selector generations through the shared encrypted history channel', async () => {
    const entries: Array<{ generatedAt: number; type: 'password'; value: string }> = [];
    const track = vi.fn(async (request: Extract<Req, { type: 'generator.history.track' }>) => {
      entries.unshift({ generatedAt: 12, type: 'password', value: request.entry.value });
      return { ok: true as const, data: { added: true } };
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': async () => ({
        ok: true, data: { generator: createGeneratorPolicySnapshot(null, 11) },
      } as Res),
      'generator.history.list': async () => ({ ok: true, data: { entries: [...entries] } }),
      'generator.history.track': track,
      'sends.list': async () => ({ ok: true, data: { sends: [] } }),
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'sends' }, bubbles: true, composed: true,
    }));
    await settle(app);
    await settle(app);
    const sends = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-sends-view');
    sends.shadowRoot!.querySelector<HTMLButtonElement>('[data-new-send]')!.click();
    await sends.updateComplete;
    sends.shadowRoot!.querySelector<HTMLButtonElement>('[data-generate-password="create"]')!.click();
    await sends.updateComplete;
    const generator = sends.shadowRoot!.querySelector<HTMLElement & {
      updateComplete: Promise<unknown>;
    }>('vw-generator-view')!;
    await generator.updateComplete;
    await settle(app);
    const generated = generator.shadowRoot!.querySelector('[data-output]')?.textContent ?? '';

    expect(generated).not.toBe('');
    expect(track).toHaveBeenCalledWith({
      type: 'generator.history.track',
      entry: { value: generated, type: 'password', policyRevision: 11 },
    });
    expect(app.generatorHistory).toEqual(entries);
  });

  it('toggles the generator view', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'generator' }, bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('generator');
    const generator = view<HTMLElement & {
      defaultLength: number;
      defaultUppercase: boolean;
      defaultNumbers: boolean;
      defaultSymbols: boolean;
    }>(app, 'vw-generator-view');
    expect(generator.defaultLength).toBe(20);
    expect(generator.defaultUppercase).toBe(true);
    expect(generator.defaultNumbers).toBe(true);
    expect(generator.defaultSymbols).toBe(true);
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-generator-toggle', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('vault');
  });

  it('loads typed generator history on entry and renders it in the generator', async () => {
    const entries = [{ generatedAt: 1, type: 'pin' as const, value: '123456' }];
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': async () => ({ ok: false, error: { code: 'error', message: 'unavailable' } }),
      'generator.history.list': async () => ({ ok: true, data: { entries } }),
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'generator' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(app.generatorHistory).toEqual(entries);
    expect(view(app, 'vw-generator-view').shadowRoot?.querySelector('.history-value')?.textContent)
      .toBe('123456');
  });

  it('tracks the initial successful generation and refreshes only after worker acknowledgement', async () => {
    const entries: Array<{ generatedAt: number; type: 'password'; value: string }> = [];
    const track = vi.fn(async (request: Extract<Req, { type: 'generator.history.track' }>) => {
      entries.unshift({ generatedAt: 2, type: 'password', value: request.entry.value });
      return { ok: true, data: { added: true } } as Res;
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': async () => ({
        ok: true, data: { generator: createGeneratorPolicySnapshot(null, 7) },
      } as Res),
      'generator.history.list': async () => ({ ok: true, data: { entries: [...entries] } }),
      'generator.history.track': track,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'generator' }, bubbles: true, composed: true,
    }));
    await settle(app);
    await settle(app);

    expect(track).toHaveBeenCalledWith(expect.objectContaining({
      type: 'generator.history.track',
      entry: expect.objectContaining({ type: 'password', policyRevision: 7 }),
    }));
    expect(app.generatorHistory).toEqual(entries);
  });

  it('ignores a late successful history track after enterprise-policy revoke', async () => {
    const delayed = deferred<Res>();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': async () => ({
        ok: true, data: { generator: createGeneratorPolicySnapshot(null, 7) },
      } as Res),
      'generator.history.list': async () => ({ ok: true, data: { entries: [] } }),
      'generator.history.track': () => delayed.promise,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'generator' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const generator = view(app, 'vw-generator-view');
    expect(generator.shadowRoot?.querySelector('[data-output]')?.textContent).not.toBe('');

    enterprisePolicyMessageListener()({ type: 'enterprisePolicy.clientChanged', phase: 'revoke' });
    delayed.resolve({ ok: true, data: { added: true } } as Res);
    await settle(app);

    expect(app.generatorHistory).toEqual([]);
    expect(app.route.name).not.toBe('generator');
  });

  it('does not clear a successful generated value when history persistence fails', async () => {
    const track = vi.fn(async () => ({
      ok: false as const, error: { code: 'error' as const, message: 'history unavailable' },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': async () => ({
        ok: true, data: { generator: createGeneratorPolicySnapshot(null, 7) },
      } as Res),
      'generator.history.list': async () => ({ ok: true, data: { entries: [] } }),
      'generator.history.track': track,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'generator' }, bubbles: true, composed: true,
    }));
    await settle(app);
    await settle(app);

    expect(track).toHaveBeenCalled();
    expect(view(app, 'vw-generator-view').shadowRoot?.querySelector('[data-output]')?.textContent)
      .not.toBe('');
    expect(app.generatorHistory).toEqual([]);
  });

  it('retains history on clear failure and clears it only after a successful response', async () => {
    const entries = [{ generatedAt: 1, type: 'password' as const, value: 'old-secret' }];
    const clear = vi.fn()
      .mockResolvedValueOnce({ ok: false, error: { code: 'error', message: 'failed' } })
      .mockResolvedValueOnce({ ok: true, data: { cleared: false } });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': async () => ({ ok: false, error: { code: 'error', message: 'unavailable' } }),
      'generator.history.list': async () => ({ ok: true, data: { entries } }),
      'generator.history.clear': clear,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'generator' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const generator = view(app, 'vw-generator-view');

    generator.dispatchEvent(new CustomEvent('vw-history-clear', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.generatorHistory).toEqual(entries);
    generator.dispatchEvent(new CustomEvent('vw-history-clear', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.generatorHistory).toEqual([]);
  });

  it('revokes a cached generator policy before an extension-wide refresh settles', async () => {
    const refreshed = deferred<Res>();
    let reads = 0;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'settings.get': () => {
        reads += 1;
        return reads === 1
          ? Promise.resolve({ ok: true, data: { generator: createGeneratorPolicySnapshot(null, 7) } } as Res)
          : refreshed.promise;
      },
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'generator' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.generatorPolicy.revision).toBe(7);

    enterprisePolicyMessageListener()({ type: 'enterprisePolicy.clientChanged', phase: 'refresh' });
    await app.updateComplete;
    expect(app.generatorPolicy).toBe(UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT);

    refreshed.resolve({
      ok: true,
      data: { generator: createGeneratorPolicySnapshot(null, 8) },
    } as Res);
    await settle(app);
    expect(app.generatorPolicy.revision).toBe(8);
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
    app.selectedOrganizationId = PERSONAL_VAULT_FILTER_ID;
    view(app, 'vw-popup-header').dispatchEvent(new CustomEvent('vw-lock', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('unlock');
    expect(app.selectedOrganizationId).toBeNull();
  });

  it('logs out from the account menu only after the worker confirms success', async () => {
    let stateReads = 0;
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({
        ok: true,
        data: { state: stateReads++ === 0 ? 'unlocked' : 'locked' },
      }),
      'auth.logout': logout,
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', { detail: { action: 'logout' }, bubbles: true, composed: true }));
    await settle(app);
    expect(window.confirm).toHaveBeenCalledWith(t('auth.logoutConfirm'));
    expect(logout).toHaveBeenCalledOnce();
    expect(app.route.name).toBe('unlock');
  });

  it('routes an unlocked fallback account back into its workspace after logout', async () => {
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.logout': logout }));

    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'logout' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(logout).toHaveBeenCalledOnce();
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });

  it('does not request logout from the account menu when confirmation is cancelled', async () => {
    vi.mocked(window.confirm).mockReturnValue(false);
    const logout = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'auth.logout': logout }));

    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'logout' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(logout).not.toHaveBeenCalled();
    expect(app.route.name).toBe('vault');
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

  it('guards tool and bottom-bar navigation while a Send draft has unsaved changes', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const switchAccount = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'sends.list': async () => ({ ok: true, data: { sends: [] } }),
      'auth.switchAccount': switchAccount,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'sends' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const sends = view<VwSendsView>(app, 'vw-sends-view');
    (sends.shadowRoot!.querySelector('[data-new-send]') as HTMLButtonElement).click();
    await sends.updateComplete;
    (sends.shadowRoot!.querySelector('[data-text]') as HTMLTextAreaElement).value = 'keep me';

    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'health' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.route.name).toBe('sends');
    expect((sends.shadowRoot!.querySelector('[data-text]') as HTMLTextAreaElement).value).toBe('keep me');

    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('sends');

    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'switch-account', email: 'other@example.com' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(switchAccount).not.toHaveBeenCalled();
    expect(app.route.name).toBe('sends');

    confirm.mockReturnValue(true);
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'health' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.route.name).toBe('health');
    confirm.mockRestore();
  });
});

describe('vw-popup-app device login approvals', () => {
  it('opens only the fixed notification deep link directly on the approval list', async () => {
    const approval = deviceLoginApproval('A'.repeat(43));
    const list = vi.fn(async () => ({ ok: true as const, data: { approvals: [approval] } }));
    window.history.replaceState(null, '', '/ui/popup/popup.html?deviceLoginApprovals=1');

    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.deviceLogin.approvals.list': list,
    }));

    expect(app.route).toEqual({ name: 'deviceLoginApprovals', view: 'list' });
    expect(list).toHaveBeenCalled();
    expect(window.location.search).toBe('?deviceLoginApprovals=1');
    expect(window.location.href).not.toContain(DEVICE_LOGIN_REQUEST_ID);
  });

  it.each([
    '/ui/popup/popup.html?deviceLoginApprovals=0',
    `/ui/popup/popup.html?deviceLoginApprovals=1&requestId=${DEVICE_LOGIN_REQUEST_ID}`,
    '/ui/popup/popup.html?deviceLoginApprovals=1#fragment',
  ])('does not route an injected notification deep link: %s', async (url) => {
    window.history.replaceState(null, '', url);

    const app = await mountApp(fakeRequest(UNLOCKED));

    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
  });

  it('loads the safe approval count for the account menu and keeps bindings out of DOM', async () => {
    const approval = deviceLoginApproval('A'.repeat(43));
    const list = vi.fn(async () => ({ ok: true as const, data: { approvals: [approval] } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.deviceLogin.approvals.list': list,
    }));
    await settle(app);
    const accountMenu = view<HTMLElement & { deviceLoginApprovalCount: number }>(app, 'vw-account-menu');
    expect(accountMenu.deviceLoginApprovalCount).toBe(1);

    accountMenu.dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'device-login-approvals' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'deviceLoginApprovals', view: 'list' });
    const approvals = view(app, 'vw-device-login-view');
    const markup = `${approvals.outerHTML}\n${approvals.shadowRoot?.innerHTML ?? ''}`;
    expect(markup).not.toContain(DEVICE_LOGIN_REQUEST_ID);
    expect(markup).not.toContain('A'.repeat(43));
    expect(markup).toContain('requesting-device');
  });

  it('gets a fresh binding and sends only that binding for one approval decision', async () => {
    const listed = deviceLoginApproval('A'.repeat(43));
    const fresh = deviceLoginApproval('B'.repeat(43));
    const list = vi.fn(async () => ({ ok: true as const, data: { approvals: [listed] } }));
    const get = vi.fn(async () => ({ ok: true as const, data: { approval: fresh } }));
    const approve = vi.fn(async (request: Extract<Req, { type: 'auth.deviceLogin.approvals.approve' }>) => {
      expect(request.decisionBinding).toEqual(fresh.decisionBinding);
      return {
        ok: true as const,
        data: {
          decision: {
            requestId: DEVICE_LOGIN_REQUEST_ID,
            requestApproved: true,
            responseDate: new Date().toISOString(),
          },
        },
      };
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.deviceLogin.approvals.list': list,
      'auth.deviceLogin.approvals.get': get,
      'auth.deviceLogin.approvals.approve': approve,
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'device-login-approvals' }, bubbles: true, composed: true,
    }));
    await settle(app);
    let approvals = view(app, 'vw-device-login-view');
    approvals.dispatchEvent(new CustomEvent('vw-device-login-select', {
      detail: { requestId: DEVICE_LOGIN_REQUEST_ID }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(get).toHaveBeenCalledWith({
      type: 'auth.deviceLogin.approvals.get', requestId: DEVICE_LOGIN_REQUEST_ID,
    });
    expect(app.route).toEqual({ name: 'deviceLoginApprovals', view: 'detail' });
    approvals = view(app, 'vw-device-login-view');
    expect(approvals.shadowRoot?.innerHTML).not.toContain('B'.repeat(43));
    approvals.dispatchEvent(new CustomEvent('vw-device-login-approve', {
      detail: { requestId: DEVICE_LOGIN_REQUEST_ID }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(approve).toHaveBeenCalledTimes(1);
    const sent = approve.mock.calls[0]![0];
    expect(Object.keys(sent).sort()).toEqual(['decisionBinding', 'type']);
    expect(sent).not.toHaveProperty('requestId');
    expect(sent.decisionBinding).toEqual(fresh.decisionBinding);
    expect(sent.decisionBinding).not.toEqual(listed.decisionBinding);
    expect(app.route).toEqual({ name: 'deviceLoginApprovals', view: 'list' });
  });

  it('refreshes first and shows an explicit warning when a decision outcome is unknown', async () => {
    const approval = deviceLoginApproval();
    const list = vi.fn()
      .mockResolvedValueOnce({ ok: true as const, data: { approvals: [approval] } })
      .mockResolvedValueOnce({ ok: true as const, data: { approvals: [approval] } })
      .mockResolvedValueOnce({
        ok: false as const,
        error: { code: 'error' as const, message: 'refresh unavailable' },
      });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.deviceLogin.approvals.list': list,
      'auth.deviceLogin.approvals.get': async () => ({ ok: true, data: { approval } }),
      'auth.deviceLogin.approvals.approve': async () => ({
        ok: false, error: { code: 'outcome_unknown', message: 'ambiguous write' },
      }),
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'device-login-approvals' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-device-login-view').dispatchEvent(new CustomEvent('vw-device-login-select', {
      detail: { requestId: DEVICE_LOGIN_REQUEST_ID }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-device-login-view').dispatchEvent(new CustomEvent('vw-device-login-approve', {
      detail: { requestId: DEVICE_LOGIN_REQUEST_ID }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(list.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(app.route).toEqual({ name: 'deviceLoginApprovals', view: 'list' });
    const model = (view(app, 'vw-device-login-view') as HTMLElement & {
      model?: { notice?: { tone: string; message: string } };
    }).model;
    expect(model?.notice?.tone).toBe('warning');
    expect(model?.notice?.message).toBe(t('auth.deviceLogin.approvalOutcomeUnknown'));
    expect(model?.notice?.message).not.toContain('ambiguous write');
  });

  it('drops a delayed fresh-binding response after workspace reset', async () => {
    const approval = deviceLoginApproval();
    const fresh = deferred<Res>();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.deviceLogin.approvals.list': async () => ({ ok: true, data: { approvals: [approval] } }),
      'auth.deviceLogin.approvals.get': async () => fresh.promise,
    }));
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'device-login-approvals' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-device-login-view').dispatchEvent(new CustomEvent('vw-device-login-select', {
      detail: { requestId: DEVICE_LOGIN_REQUEST_ID }, bubbles: true, composed: true,
    }));
    (app as unknown as { resetVaultState(): void }).resetVaultState();
    app.navigate({ name: 'login' });
    fresh.resolve({ ok: true, data: { approval } } as Res);
    await settle(app);

    expect(app.route).toEqual({ name: 'login' });
    expect(app.deviceLoginApprovalModel).toBeUndefined();
    expect(app.deviceLoginApprovalCount).toBe(0);
  });
});

describe('vw-popup-app vault interactions', () => {
  it('combines folder, organization, and collection facets with AND semantics', async () => {
    const personal = login({ id: 'personal', folderId: 'folder-a' });
    const intersection = login({
      id: 'intersection',
      folderId: 'folder-a',
      organizationId: 'org-1',
      collectionIds: ['collection-b'],
    });
    const otherOrganization = login({
      id: 'other-organization',
      folderId: 'folder-a',
      organizationId: 'org-2',
      collectionIds: ['collection-c'],
    });
    const otherFolder = login({
      id: 'other-folder',
      folderId: 'folder-other',
      organizationId: 'org-1',
      collectionIds: ['collection-b'],
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [personal, intersection, otherOrganization, otherFolder],
          folders: [{ id: 'folder-a', name: 'A' }, { id: 'folder-other', name: 'Other' }],
          collections: [
            { id: 'collection-b', name: 'B', organizationId: 'org-1' },
            { id: 'collection-c', name: 'C', organizationId: 'org-2' },
          ],
          orgPermissions: [
            { id: 'org-1', name: 'Org 1', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false },
            { id: 'org-2', name: 'Org 2', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false },
          ],
        },
      }),
      'autofill.getTabSuggestions': async () => ({
        ok: true,
        data: { outcome: { status: 'ready', suggestions: [{
          kind: 'login', id: 'intersection', name: 'Intersection', matchedUri: 'https://nebula.dev',
          matchType: 0, favorite: false,
        }] } },
      }),
    }), fakeBrowser());
    const filters = view<HTMLElement & {
      items: CipherSummary[];
      folders: unknown[];
      collections: unknown[];
      orgPermissions: unknown[];
      selectedOrganizationId: string | null;
    }>(app, 'vw-vault-filters');
    expect(filters.items).toHaveLength(4);
    expect(filters.folders).toHaveLength(2);
    expect(filters.collections).toHaveLength(2);
    expect(filters.orgPermissions).toHaveLength(2);
    expect(filters.selectedOrganizationId).toBeNull();

    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { folderId: 'folder-a' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedFolderId).toBe('folder-a');
    expect(app.selectedCollectionId).toBeNull();
    expect(app.selectedOrganizationId).toBeNull();
    expect(view<HTMLElement & { items: CipherSummary[]; suggestionsState: SuggestionsViewState }>(app, 'vw-vault-view').items
      .map((item) => item.id)).toEqual(['personal', 'intersection', 'other-organization']);
    expect(view<HTMLElement & { suggestionsState: SuggestionsViewState }>(app, 'vw-vault-view').suggestionsState)
      .toEqual({ status: 'ready', suggestions: [] });

    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-b', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedFolderId).toBe('folder-a');
    expect(app.selectedCollectionId).toBe('collection-b');
    expect(app.selectedOrganizationId).toBe('org-1');
    expect(view<HTMLElement & { items: CipherSummary[] }>(app, 'vw-vault-view').items.map((item) => item.id))
      .toEqual(['intersection']);

    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: 'org-2', collectionId: null }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedFolderId).toBe('folder-a');
    expect(app.selectedCollectionId).toBeNull();
    expect(app.selectedOrganizationId).toBe('org-2');
    expect(view<HTMLElement & { items: CipherSummary[] }>(app, 'vw-vault-view').items.map((item) => item.id))
      .toEqual(['other-organization']);

    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: PERSONAL_VAULT_FILTER_ID, collectionId: null }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedOrganizationId).toBe(PERSONAL_VAULT_FILTER_ID);
    expect(view<HTMLElement & { items: CipherSummary[] }>(app, 'vw-vault-view').items.map((item) => item.id))
      .toEqual(['personal']);

    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { folderId: null, organizationId: null, collectionId: null }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(view<HTMLElement & { suggestionsState: SuggestionsViewState }>(app, 'vw-vault-view').suggestionsState)
      .toEqual(expect.objectContaining({ status: 'ready', suggestions: [expect.objectContaining({ id: 'intersection' })] }));

    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-b', organizationId: 'org-2' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedCollectionId).toBeNull();
    expect(app.selectedOrganizationId).toBeNull();
  });

  it('reconciles stale and incompatible listing facets without coercing them to Personal', async () => {
    const item = login({
      id: 'intersection',
      folderId: 'folder-a',
      organizationId: 'org-1',
      collectionIds: ['collection-b'],
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [item],
          folders: [{ id: 'folder-a', name: 'Folder' }],
          collections: [{ id: 'collection-b', name: 'Collection', organizationId: 'org-1' }],
          orgPermissions: [{ id: 'org-1', name: 'Org', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false }],
        },
      }),
    }));
    const filters = view(app, 'vw-vault-filters');
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { folderId: 'folder-a' }, bubbles: true, composed: true,
    }));
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-b', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    (app as unknown as { applyListingData(data: {
      items: CipherSummary[];
      folders: Array<{ id: string; name: string }>;
      collections: Array<{ id: string; name: string; organizationId: string }>;
      orgPermissions: Array<{ id: string; name: string; canManageCollections: boolean; canCreateCollections: boolean; canEditCollections: boolean; canDeleteCollections: boolean }>;
    }): void }).applyListingData({
      items: [item],
      folders: [{ id: 'folder-a', name: 'Folder' }],
      collections: [{ id: 'collection-b', name: 'Moved collection', organizationId: 'org-2' }],
      orgPermissions: [{ id: 'org-1', name: 'Org', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false }],
    });
    await app.updateComplete;
    expect(app.selectedFolderId).toBe('folder-a');
    expect(app.selectedOrganizationId).toBe('org-1');
    expect(app.selectedCollectionId).toBeNull();

    (app as unknown as { applyListingData(data: {
      items: CipherSummary[];
      folders: never[];
      collections: never[];
      orgPermissions: never[];
    }): void }).applyListingData({ items: [], folders: [], collections: [], orgPermissions: [] });
    await app.updateComplete;
    expect(app.selectedFolderId).toBeNull();
    expect(app.selectedOrganizationId).toBeNull();
    expect(app.selectedCollectionId).toBeNull();
    expect(app.selectedOrganizationId).not.toBe(PERSONAL_VAULT_FILTER_ID);
  });

  it('ignores ambiguous collection pairs and unknown organization patches', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [],
          folders: [],
          collections: [
            { id: 'duplicate', name: 'One', organizationId: 'org-1' },
            { id: 'duplicate', name: 'Two', organizationId: 'org-2' },
          ],
          orgPermissions: [{ id: 'org-1', name: 'Org', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false }],
        },
      }),
    }));
    const filters = view(app, 'vw-vault-filters');

    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'duplicate', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: 'unknown-org' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    expect(app.selectedCollectionId).toBeNull();
    expect(app.selectedOrganizationId).toBeNull();
  });

  it('defends sparse organization patches without relying on child cleanup', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [],
          folders: [{ id: 'folder-a', name: 'Folder' }],
          collections: [{ id: 'collection-1', name: 'Collection', organizationId: 'org-1' }],
          orgPermissions: [
            { id: 'org-1', name: 'Org 1', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false },
            { id: 'org-2', name: 'Org 2', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false },
            { id: 'duplicate-org', name: 'Duplicate A', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false },
            { id: 'duplicate-org', name: 'Duplicate B', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false },
          ],
        },
      }),
    }));
    const filters = view(app, 'vw-vault-filters');
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { folderId: 'folder-a' }, bubbles: true, composed: true,
    }));
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-1', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: 'org-2' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedFolderId).toBe('folder-a');
    expect(app.selectedOrganizationId).toBe('org-2');
    expect(app.selectedCollectionId).toBeNull();

    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-1', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: PERSONAL_VAULT_FILTER_ID }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect(app.selectedOrganizationId).toBe(PERSONAL_VAULT_FILTER_ID);
    expect(app.selectedCollectionId).toBeNull();

    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-1', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    const beforeUnknown = {
      folderId: app.selectedFolderId,
      organizationId: app.selectedOrganizationId,
      collectionId: app.selectedCollectionId,
    };
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: 'unknown-org' }, bubbles: true, composed: true,
    }));
    filters.dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { organizationId: 'duplicate-org' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    expect({
      folderId: app.selectedFolderId,
      organizationId: app.selectedOrganizationId,
      collectionId: app.selectedCollectionId,
    }).toEqual(beforeUnknown);
  });

  it('clears a collection whose organization disappears while the collection record remains', async () => {
    const item = login({ organizationId: 'org-1', collectionIds: ['collection-1'] });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [item],
          folders: [],
          collections: [{ id: 'collection-1', name: 'Collection', organizationId: 'org-1' }],
          orgPermissions: [{ id: 'org-1', name: 'Org', canManageCollections: false, canCreateCollections: false, canEditCollections: false, canDeleteCollections: false }],
        },
      }),
    }));
    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-filter-change', {
      detail: { collectionId: 'collection-1', organizationId: 'org-1' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    (app as unknown as { applyListingData(data: {
      items: CipherSummary[];
      folders: never[];
      collections: Array<{ id: string; name: string; organizationId: string }>;
      orgPermissions: never[];
    }): void }).applyListingData({
      items: [item],
      folders: [],
      collections: [{ id: 'collection-1', name: 'Collection', organizationId: 'org-1' }],
      orgPermissions: [],
    });
    await app.updateComplete;

    expect(app.selectedOrganizationId).toBeNull();
    expect(app.selectedCollectionId).toBeNull();
  });

  it('clears every vault facet during an explicit workspace reset', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    app.selectedFolderId = 'stale-folder';
    app.selectedOrganizationId = 'stale-organization';
    app.selectedCollectionId = 'stale-collection';

    (app as unknown as { resetVaultState(): void }).resetVaultState();

    expect(app.selectedFolderId).toBeNull();
    expect(app.selectedOrganizationId).toBeNull();
    expect(app.selectedCollectionId).toBeNull();
  });

  it('uses the existing category state to render Favorites without extra root wiring', async () => {
    const favorite = login({ id: 'favorite', name: 'Favorite login', favorite: true });
    const ordinary = login({ id: 'ordinary', name: 'Ordinary login', favorite: false });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [favorite, ordinary], folders: [], collections: [], orgPermissions: [] },
      }),
    }));
    const vault = view<HTMLElement & { category: string; updateComplete: Promise<unknown> }>(app, 'vw-vault-view');
    vault.dispatchEvent(new CustomEvent('vw-category-change', {
      detail: { category: 'favorite' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    const updatedVault = view<HTMLElement & { category: string; updateComplete: Promise<unknown> }>(app, 'vw-vault-view');
    await updatedVault.updateComplete;

    expect(app.category).toBe('favorite');
    expect(updatedVault.category).toBe('favorite');
    expect([...updatedVault.shadowRoot!.querySelectorAll<HTMLElement>('.title')]
      .map((title) => title.textContent)).toEqual(['Favorite login']);
  });

  it('toggles favorite for a read-only organization item using an exact metadata-free command', async () => {
    const item = login({
      id: 'org-read-only',
      organizationId: 'org-1',
      folderId: 'folder-1',
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const listing = {
      items: [{ ...item, favorite: true }],
      folders: [{ id: 'folder-1', name: 'Personal folder' }],
      collections: [],
      orgPermissions: [{
        id: 'org-1', name: 'Read only org', canManageCollections: false,
        canCreateCollections: false, canEditCollections: false, canDeleteCollections: false,
      }],
    };
    const setFavorite = vi.fn(async (_request: Extract<Req, { type: 'vault.setCipherFavorite' }>) => ({
      ok: true as const,
      data: listing,
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: { ...listing, items: [item] } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: item } }),
      'vault.setCipherFavorite': setFavorite,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: item.id }, bubbles: true, composed: true,
    }));
    await settle(app);

    const detail = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-item-detail');
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-favorite-toggle]')!.click();
    await settle(app);

    expect(setFavorite).toHaveBeenCalledWith({
      type: 'vault.setCipherFavorite', id: item.id, favorite: true,
    });
    expect(Reflect.ownKeys(setFavorite.mock.calls[0]![0])).toEqual(['type', 'id', 'favorite']);
    expect(JSON.stringify(setFavorite.mock.calls[0]![0])).not.toContain('folderId');
    expect(app.items.find((candidate) => candidate.id === item.id)?.favorite).toBe(true);
    const updated = view<HTMLElement & { summary: CipherSummary; updateComplete: Promise<unknown> }>(
      app,
      'vw-item-detail',
    );
    await updated.updateComplete;
    expect(updated.summary.favorite).toBe(true);
    expect(updated.shadowRoot!.querySelector('[data-edit]')).toBeNull();
  });

  it('prevents rapid duplicate favorite submits and waits for the authoritative listing', async () => {
    const item = login();
    const response = deferred<Res>();
    const setFavorite = vi.fn(() => response.promise);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: item } }),
      'vault.setCipherFavorite': setFavorite,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: item.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    const detail = view(app, 'vw-item-detail');
    const button = detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-favorite-toggle]')!;

    button.click();
    button.click();

    expect(setFavorite).toHaveBeenCalledOnce();
    expect(app.pending).toBe(true);
    expect(app.items[0]?.favorite).toBe(false);
    response.resolve({
      ok: true,
      data: { items: [{ ...item, favorite: true }], folders: [], collections: [], orgPermissions: [] },
    } as Res);
    await settle(app);
    expect(app.pending).toBe(false);
    expect(app.items[0]?.favorite).toBe(true);
  });

  it('rejects stale, inactive, unsupported, duplicate, and unknown favorite intents in the Popup', async () => {
    const active = login({ id: 'active' });
    const archived = login({ id: 'archived', archivedDate: '2026-08-30T00:00:00.000Z' });
    const deleted = login({ id: 'deleted', deletedDate: '2026-08-30T00:00:00.000Z' });
    const unsupported: CipherSummary = {
      id: 'future', type: 6, name: 'Future', uris: [], loginUris: [], favorite: false,
      unsupported: true, undecryptable: true,
    };
    const setFavorite = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [active, archived, deleted, unsupported],
          folders: [], collections: [], orgPermissions: [],
        },
      }),
      'vault.getCipherDetail': async (request) => ({
        ok: true, data: { cipher: [active, archived, deleted].find((item) => item.id === request.id) ?? null },
      }),
      'vault.setCipherFavorite': setFavorite,
    }));

    for (const intent of [
      { routeId: active.id, cipherId: active.id, favorite: false },
      { routeId: archived.id, cipherId: archived.id, favorite: true },
      { routeId: deleted.id, cipherId: deleted.id, favorite: true },
      { routeId: unsupported.id, cipherId: unsupported.id, favorite: true },
      { routeId: active.id, cipherId: 'missing', favorite: true },
    ]) {
      app.navigate({ name: 'detail', cipherId: intent.routeId });
      await settle(app);
      view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-favorite-toggle', {
        detail: { cipherId: intent.cipherId, favorite: intent.favorite },
        bubbles: true,
        composed: true,
      }));
    }
    (app as unknown as { applyListingData(data: {
      items: CipherSummary[]; folders: never[]; collections: never[]; orgPermissions: never[];
    }): void }).applyListingData({
      items: [active, { ...active }], folders: [], collections: [], orgPermissions: [],
    });
    app.navigate({ name: 'detail', cipherId: active.id });
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-favorite-toggle', {
      detail: { cipherId: active.id, favorite: true }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(setFavorite).not.toHaveBeenCalled();
  });

  it('does not let a favorite response overwrite a different detail', async () => {
    const first = login({ id: 'first', name: 'First' });
    const second = login({ id: 'second', name: 'Second' });
    const response = deferred<Res>();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [first, second], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': async (request) => ({
        ok: true, data: { cipher: request.id === first.id ? first : second },
      }),
      'vault.setCipherFavorite': () => response.promise,
    }));
    app.navigate({ name: 'detail', cipherId: first.id });
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-favorite-toggle', {
      detail: { cipherId: first.id, favorite: true }, bubbles: true, composed: true,
    }));
    app.navigate({ name: 'detail', cipherId: second.id });
    response.resolve({
      ok: true,
      data: {
        items: [{ ...first, favorite: true }, { ...second, name: 'Stale overwrite' }],
        folders: [], collections: [], orgPermissions: [],
      },
    } as Res);
    await settle(app);

    expect(app.route).toEqual({ name: 'detail', cipherId: second.id });
    expect(app.items).toEqual([first, second]);
  });

  it('does not let a favorite response cross a workspace reset or release a newer pending action', async () => {
    const item = login();
    const response = deferred<Res>();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: item } }),
      'vault.setCipherFavorite': () => response.promise,
    }));
    app.navigate({ name: 'detail', cipherId: item.id });
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-favorite-toggle', {
      detail: { cipherId: item.id, favorite: true }, bubbles: true, composed: true,
    }));
    (app as unknown as { resetVaultState(): void }).resetVaultState();
    app.navigate({ name: 'login' });
    app.pending = true;
    response.resolve({
      ok: true,
      data: { items: [{ ...item, favorite: true }], folders: [], collections: [], orgPermissions: [] },
    } as Res);
    await settle(app);

    expect(app.route).toEqual({ name: 'login' });
    expect(app.items).toEqual([]);
    expect(app.pending).toBe(true);
  });

  it('renders the full detail route with summary, detail, extras, status and pending', async () => {
    const cipher = { ...login(), notes: 'A note' };
    const getDetail = vi.fn(async () => ({ ok: true as const, data: { cipher } }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.getCipherDetail': getDetail }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const detail = view<HTMLElement & {
      summary: CipherSummary;
      cipher: typeof cipher;
      extras: unknown;
      status: unknown;
      pending: boolean;
    }>(app, 'vw-item-detail');
    expect(getDetail).toHaveBeenCalledWith(expect.objectContaining({ id: 'c1' }));
    expect(detail.summary.id).toBe('c1');
    expect(detail.cipher.notes).toBe('A note');
    expect(detail.extras).toBeDefined();
    expect(detail.status).toBeUndefined();
    expect(detail.pending).toBe(false);
  });

  it('marks only the initial detail request as an intentional view and acknowledges after render', async () => {
    const cipher = { ...login(), notes: 'Intentional view' };
    const getDetail = vi.fn(async (_request: Extract<Req, { type: 'vault.getCipherDetail' }>): Promise<Res> => ({
      ok: true,
      data: {
        cipher,
        clientEventAckId: 'detail-view-ack',
      },
    } as Res));
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getCipherDetail': getDetail,
      'clientEvent.ack': acknowledge,
    }));

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(getDetail).toHaveBeenNthCalledWith(1, {
      type: 'vault.getCipherDetail', id: 'c1', clientEventPurpose: 'view',
    });
    expect(view(app, 'vw-item-detail')).not.toBeNull();
    expect(acknowledge).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: 'detail-view-ack' });

    acknowledge.mockClear();
    await (app as unknown as { loadDetail(id: string): Promise<void> }).loadDetail('c1');
    expect(getDetail).toHaveBeenNthCalledWith(2, { type: 'vault.getCipherDetail', id: 'c1' });
    expect(acknowledge).not.toHaveBeenCalled();
  });

  it('marks an initial editor load as intentional and acknowledges only after the editor mounts', async () => {
    const getInput = vi.fn(async (): Promise<Res> => ({
      ok: true,
      data: {
        input: { type: 1, name: 'Nebula', login: { password: 'editor-secret' } },
        clientEventAckId: 'editor-open-ack',
      },
    } as Res));
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getCipherInput': getInput,
      'clientEvent.ack': acknowledge,
    }));

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-edit-item', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(getInput).toHaveBeenCalledWith({
      type: 'vault.getCipherInput', id: 'c1', cipherInputPurpose: 'edit', clientEventPurpose: 'editor',
    });
    expect(view(app, 'vw-cipher-editor')).not.toBeNull();
    expect(acknowledge).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: 'editor-open-ack' });
  });

  it('reprompt-loads an acknowledged clone into a sanitized create draft without writing it', async () => {
    const source = login({
      id: 'clone-source',
      name: 'Archived source',
      folderId: 'folder-1',
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
      archivedDate: '2026-08-30T00:00:00Z',
      reprompt: true,
      hasPasskey: true,
      passwordHistoryCount: 2,
      access: {
        edit: true,
        viewPassword: true,
        clone: true,
        delete: true,
        restore: true,
        autofillTotp: true,
        viewTotp: true,
      },
    });
    const sourceInput = {
      type: 1,
      name: 'Archived source',
      notes: 'Copied notes',
      favorite: true,
      reprompt: true,
      folderId: 'folder-1',
      login: {
        username: 'alice',
        password: 'secret',
        uris: [{ uri: 'https://example.com' }],
        passwordRevisionDate: '2026-08-01T00:00:00Z',
      },
      fields: [{ type: 1, name: 'Recovery', value: 'hidden' }],
      id: 'must-not-copy',
      revisionDate: 'must-not-copy',
      archivedDate: 'must-not-copy',
      attachments: [{ id: 'attachment', fileName: 'secret.txt' }],
      passwordHistory: [{ password: 'old-secret' }],
      fido2Credentials: [{ credentialId: 'passkey' }],
    } as unknown as CipherInput;
    const getInput = vi.fn(async (): Promise<Res> => ({
      ok: true, data: { input: sourceInput },
    } as Res));
    const create = vi.fn(async () => ({ ok: true as const, data: null }));
    const update = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [source],
          folders: [{ id: 'folder-1', name: 'Folder' }],
          collections: [{
            id: 'collection-1', name: 'Team', organizationId: 'org-1', canAssignItems: true,
          }],
          orgPermissions: [{
            id: 'org-1', name: 'Acme', isMember: true, canCreateItems: true,
            canCreateCollections: false, canEditCollections: false,
            canDeleteCollections: false, canManageCollections: false,
          }],
        },
      }),
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: source } }),
      'vault.getCipherInput': getInput,
      'vault.createCipher': create,
      'vault.updateCipher': update,
    }));
    app.vaultMode = 'archive';
    app.navigate({ name: 'detail', cipherId: source.id });
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);

    const item = view(app, 'vw-item-detail');
    item.dispatchEvent(new CustomEvent('vw-clone-item', {
      detail: { cipherId: source.id, passkeyWarningAcknowledged: false },
      bubbles: true,
      composed: true,
    }));
    expect(app.route).toEqual({ name: 'detail', cipherId: source.id });
    item.dispatchEvent(new CustomEvent('vw-clone-item', {
      detail: { cipherId: source.id, passkeyWarningAcknowledged: true },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(getInput).toHaveBeenCalledWith({
      type: 'vault.getCipherInput', id: source.id, cipherInputPurpose: 'clone', masterPassword: 'correct-master',
    });
    expect(app.route).toEqual({ name: 'editor', mode: 'clone', cipherId: source.id });
    const editor = view<HTMLElement & { context: EditorContext; summary?: CipherSummary }>(app, 'vw-cipher-editor');
    expect(editor.summary).toBeUndefined();
    expect(editor.context.cipherId).toBeUndefined();
    expect(editor.context.createDefaults).toEqual({
      folderId: 'folder-1',
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
    });
    expect(editor.context.input).toEqual({
      type: 1,
      name: 'Archived source',
      notes: 'Copied notes',
      favorite: true,
      reprompt: true,
      folderId: 'folder-1',
      login: {
        username: 'alice',
        password: 'secret',
        uris: [{ uri: 'https://example.com' }],
      },
      fields: [{ type: 1, name: 'Recovery', value: 'hidden' }],
    });
    expect(create).not.toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
  });

  it('acknowledges only password, Hidden, card-code, and card-number reveals after display', async () => {
    const loginItem = login();
    const cardItem = login({ id: 'card-1', name: 'Card', type: 3, uris: [] });
    const identityItem = login({ id: 'identity-1', name: 'Identity', type: 4, uris: [] });
    const getDetail = vi.fn(async (request: Extract<Req, { type: 'vault.getCipherDetail' }>) => ({
      ok: true as const,
      data: {
        cipher: request.id === 'card-1'
          ? { ...cardItem, card: { brand: 'Visa' } }
          : request.id === 'identity-1'
            ? { ...identityItem, identity: {} }
            : { ...loginItem, fields: [{ type: 1 as const, name: 'Recovery' }] },
      },
    }));
    const getField = vi.fn(async (request: Extract<Req, { type: 'vault.getField' }>): Promise<Res> => ({
      ok: true,
      data: { value: `shown-${request.field}`, clientEventAckId: `reveal-${request.field}` },
    } as Res));
    const getCustomField = vi.fn(async (): Promise<Res> => ({
      ok: true,
      data: { value: 'shown-hidden', clientEventAckId: 'reveal-hidden' },
    } as Res));
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [loginItem, cardItem, identityItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': getDetail,
      'vault.getField': getField,
      'vault.getCustomField': getCustomField,
      'clientEvent.ack': acknowledge,
    }));

    app.navigate({ name: 'detail', cipherId: loginItem.id });
    await settle(app);
    let detail = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-item-detail');
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-reveal="password"]')!.click();
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-cf-reveal]')!.click();
    await settle(app);

    app.navigate({ name: 'detail', cipherId: cardItem.id });
    await settle(app);
    detail = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-item-detail');
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-reveal="card.number"]')!.click();
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-reveal="card.code"]')!.click();
    await settle(app);

    app.navigate({ name: 'detail', cipherId: identityItem.id });
    await settle(app);
    detail = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-item-detail');
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-reveal="identity.ssn"]')!.click();
    await settle(app);

    expect(acknowledge.mock.calls.map(([request]) => request)).toEqual([
      { type: 'clientEvent.ack', ackId: 'reveal-password' },
      { type: 'clientEvent.ack', ackId: 'reveal-hidden' },
      { type: 'clientEvent.ack', ackId: 'reveal-card.number' },
      { type: 'clientEvent.ack', ackId: 'reveal-card.code' },
    ]);
    expect(getField.mock.calls.map(([request]) => request)).toEqual([
      { type: 'vault.getField', id: 'c1', field: 'password', clientEventPurpose: 'reveal' },
      { type: 'vault.getField', id: 'card-1', field: 'card.number', clientEventPurpose: 'reveal' },
      { type: 'vault.getField', id: 'card-1', field: 'card.code', clientEventPurpose: 'reveal' },
      { type: 'vault.getField', id: 'identity-1', field: 'identity.ssn' },
    ]);
    expect(getCustomField).toHaveBeenCalledWith({
      type: 'vault.getCustomField', id: 'c1', index: 0, clientEventPurpose: 'reveal',
    });
    expect(detail.shadowRoot?.textContent).toContain('shown-identity.ssn');
  });

  it('projects display-only detail metadata and updates names without reloading secrets', async () => {
    const item = login({
      id: 'shared',
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
      access: {
        edit: true,
        viewPassword: true,
        delete: true,
        restore: true,
        autofillTotp: true,
        viewTotp: true,
      },
    });
    const getDetail = vi.fn(async () => ({ ok: true as const, data: { cipher: item } }));
    const getField = vi.fn(async () => ({ ok: true as const, data: { value: 'loaded-secret' } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [item],
          folders: [{ id: 'folder-1', name: 'Initial folder' }],
          collections: [{ id: 'collection-1', name: 'Initial collection', organizationId: 'org-1' }],
          orgPermissions: [{
            id: 'org-1', name: 'Initial organization', canManageCollections: true,
            canCreateCollections: true, canEditCollections: true, canDeleteCollections: true,
          }],
        },
      }),
      'vault.getCipherDetail': getDetail,
      'vault.getField': getField,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: 'shared' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const detail = view<HTMLElement & {
      presentationMetadata: DetailPresentationMetadata;
      updateComplete: Promise<unknown>;
    }>(app, 'vw-item-detail');

    expect(detail.presentationMetadata.organizations).toEqual([{ id: 'org-1', name: 'Initial organization' }]);
    expect(Object.keys(detail.presentationMetadata.organizations![0]!)).toEqual(['id', 'name']);
    expect(detail.presentationMetadata.collections).toEqual([{
      id: 'collection-1', name: 'Initial collection', organizationId: 'org-1',
    }]);
    expect(detail.shadowRoot?.textContent).toContain('Initial organization');
    expect(detail.shadowRoot?.textContent).toContain('Initial collection');

    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-toggle-password]')!.click();
    await settle(app);
    expect(getField).toHaveBeenCalledTimes(1);
    expect(detail.shadowRoot?.textContent).toContain('loaded-secret');

    (app as unknown as { applyListingData(data: {
      items: CipherSummary[];
      folders: Array<{ id: string; name: string }>;
      collections: Array<{ id: string; name: string; organizationId: string }>;
      orgPermissions: Array<{ id: string; name: string; canManageCollections: boolean; canCreateCollections: boolean; canEditCollections: boolean; canDeleteCollections: boolean }>;
    }): void }).applyListingData({
      items: [item],
      folders: [{ id: 'folder-1', name: 'Renamed folder' }],
      collections: [{ id: 'collection-1', name: 'Renamed collection', organizationId: 'org-1' }],
      orgPermissions: [{
        id: 'org-1', name: 'Renamed organization', canManageCollections: false,
        canCreateCollections: false, canEditCollections: false, canDeleteCollections: false,
      }],
    });
    await app.updateComplete;
    const updatedDetail = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-item-detail');
    await updatedDetail.updateComplete;

    expect(updatedDetail.shadowRoot?.textContent).toContain('Renamed organization');
    expect(updatedDetail.shadowRoot?.textContent).toContain('Renamed collection');
    expect(updatedDetail.shadowRoot?.textContent).toContain('loaded-secret');
    expect(updatedDetail.shadowRoot?.textContent).not.toContain('Initial organization');
    expect(getDetail).toHaveBeenCalledTimes(1);
    expect(getField).toHaveBeenCalledTimes(1);
  });

  it('keeps an unknown cipher in a read-only placeholder without issuing detail or mutation requests', async () => {
    const future: CipherSummary = {
      id: 'future-6',
      type: 6,
      name: '(unsupported item)',
      uris: [],
      loginUris: [],
      favorite: false,
      unsupported: true,
      undecryptable: true,
    };
    const getDetail = vi.fn(async () => ({ ok: true as const, data: { cipher: null } }));
    const getInput = vi.fn(async () => ({ ok: true as const, data: { input: null } }));
    const getField = vi.fn(async () => ({ ok: true as const, data: { value: 'must-not-load' } }));
    const update = vi.fn(async () => ({ ok: true as const, data: null }));
    const remove = vi.fn(async () => ({ ok: true as const, data: null }));
    const restore = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [future], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': getDetail,
      'vault.getCipherInput': getInput,
      'vault.getField': getField,
      'vault.updateCipher': update,
      'vault.softDeleteCipher': remove,
      'vault.restoreCipher': restore,
    }));

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: 'future-6' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'detail', cipherId: 'future-6' });
    expect(getDetail).not.toHaveBeenCalled();
    expect(view<HTMLElement & { extras: unknown }>(app, 'vw-item-detail').extras).toBeUndefined();
    expect(view(app, 'vw-item-detail').shadowRoot?.textContent).toContain('不支持的类型 6');

    for (const [type, detail] of [
      ['vw-secret-request', { kind: 'field', field: 'password', label: 'Password' }],
      ['vw-delete-item', { cipherId: 'future-6', permanent: false }],
      ['vw-restore-item', { cipherId: 'future-6' }],
      ['vw-edit-item', { cipherId: 'future-6' }],
    ] as const) {
      view(app, 'vw-item-detail').dispatchEvent(new CustomEvent(type, {
        detail, bubbles: true, composed: true,
      }));
    }
    await settle(app);
    expect(app.route).toEqual({ name: 'detail', cipherId: 'future-6' });
    expect(getField).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();

    app.navigate({ name: 'editor', mode: 'edit', cipherId: 'future-6' });
    await settle(app);
    expect(getInput).not.toHaveBeenCalled();
    await (app as unknown as { handleEditorSave(input: unknown): Promise<void> }).handleEditorSave({
      input: { type: 1, name: 'Replacement' },
      target: undefined,
    });
    expect(update).not.toHaveBeenCalled();
  });

  it('does not create detail loaders or request protected detail until reprompt succeeds', async () => {
    const protectedItem = login({ reprompt: true });
    const getDetail = vi.fn(async (req: Extract<Req, { type: 'vault.getCipherDetail' }>) => (
      req.masterPassword === 'correct'
        ? { ok: true as const, data: { cipher: protectedItem, clientEventAckId: 'reprompt-view-ack' } }
        : { ok: false as const, error: { code: 'reprompt_required' as const, message: 'Master password required' } }
    ));
    const verify = vi.fn(async () => ({ ok: true as const, data: { verified: true } }));
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] } }),
      'vault.getCipherDetail': getDetail,
      'auth.verifyMasterPassword': verify,
      'clientEvent.ack': acknowledge,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(view(app, 'vw-reprompt-gate')).not.toBeNull();
    expect(app.shadowRoot?.querySelector('vw-item-detail')).toBeNull();
    expect(getDetail).not.toHaveBeenCalled();
    expect((app as unknown as { detailExtrasCache?: unknown }).detailExtrasCache).toBeUndefined();
    await (app as unknown as { loadDetail(id: string): Promise<void> }).loadDetail('c1');
    expect(getDetail).not.toHaveBeenCalled();

    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(verify).toHaveBeenCalled();
    expect(getDetail).toHaveBeenCalledTimes(1);
    expect(getDetail).toHaveBeenCalledWith({
      type: 'vault.getCipherDetail', id: 'c1', masterPassword: 'correct', clientEventPurpose: 'view',
    });
    expect(view<HTMLElement & { extras: unknown }>(app, 'vw-item-detail').extras).toBeDefined();
    expect(acknowledge).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: 'reprompt-view-ack' });
  });

  it('uses one short-lived authorization to fill the exact protected item without sending its password', async () => {
    const protectedItem = login({ reprompt: true });
    const target = {
      kind: 'login' as const,
      frameId: 0,
      formId: 'login-form',
      documentId: 'target-doc-1',
      runtimeIncarnation: TARGET_RUNTIME_INCARNATION,
      generation: 3,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    };
    const authorize = vi.fn(async () => ({
      ok: true as const,
      data: {
        verified: true,
        authorization: {
          authorizationId: '11111111-1111-4111-8111-111111111111',
          expiresAt: Date.now() + 30_000,
        },
      },
    }));
    const fill = vi.fn(async () => ({
      ok: true as const,
      data: { outcome: { status: 'filled' as const } },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: protectedItem } }),
      'autofill.getTabSuggestions': async () => ({
        ok: true,
        data: { outcome: { status: 'ready', suggestions: [{
          kind: 'login', id: protectedItem.id, name: protectedItem.name,
          matchedUri: protectedItem.uris[0]!, matchType: 0, favorite: false,
          reprompt: true, target,
        }] } },
      }),
      'autofill.authorizeRepromptFill': authorize,
      'autofill.fillTabSuggestion': fill,
    }), fakeBrowser());

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', {
      detail: { cipherId: protectedItem.id, target }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'master-secret' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(authorize).toHaveBeenCalledWith({
      type: 'autofill.authorizeRepromptFill',
      tabId: 7,
      cipherId: protectedItem.id,
      target,
      masterPassword: 'master-secret',
    });
    expect(fill).toHaveBeenCalledWith({
      type: 'autofill.fillTabSuggestion',
      tabId: 7,
      cipherId: protectedItem.id,
      target,
      repromptAuthorizationId: '11111111-1111-4111-8111-111111111111',
    });
    expect(JSON.stringify(fill.mock.calls)).not.toContain('master-secret');
    expect(JSON.stringify(fill.mock.calls)).not.toContain('masterPassword');
    expect((app as unknown as { repromptCredential: unknown }).repromptCredential).toBeNull();
    expect((app as unknown as { repromptAutofillAuthorization: unknown }).repromptAutofillAuthorization).toBeNull();
    expect(view(app, 'vw-reprompt-gate')).not.toBeNull();
    expect(authorize).toHaveBeenCalledTimes(1);
  });

  it('does not reuse a reprompt authorization across runtime incarnations with the same structural target', async () => {
    const protectedItem = login({ reprompt: true });
    const previousTarget = {
      kind: 'login' as const,
      frameId: 0,
      formId: 'login-form',
      documentId: 'target-doc-1',
      runtimeIncarnation: TARGET_RUNTIME_INCARNATION,
      generation: 3,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    };
    const currentTarget = {
      ...previousTarget,
      runtimeIncarnation: NEXT_TARGET_RUNTIME_INCARNATION,
    };
    const authorize = vi.fn(async () => ({
      ok: true as const,
      data: {
        verified: true,
        authorization: {
          authorizationId: '11111111-1111-4111-8111-111111111111',
          expiresAt: Date.now() + 30_000,
        },
      },
    }));
    const fill = vi.fn(async () => ({
      ok: true as const,
      data: { outcome: { status: 'filled' as const } },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: protectedItem } }),
      'autofill.getTabSuggestions': async () => ({
        ok: true,
        data: { outcome: { status: 'ready', suggestions: [{
          kind: 'login', id: protectedItem.id, name: protectedItem.name,
          matchedUri: protectedItem.uris[0]!, matchType: 0, favorite: false,
          reprompt: true, target: previousTarget,
        }] } },
      }),
      'autofill.authorizeRepromptFill': authorize,
      'autofill.fillTabSuggestion': fill,
    }), fakeBrowser());

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', {
      detail: { cipherId: protectedItem.id, target: previousTarget },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    const internal = app as unknown as {
      handleSuggestionFill(detail: SuggestionFillDetail): Promise<void>;
      repromptAutofillAuthorization: { targetKey: string } | null;
      repromptFillContinuation: unknown;
    };
    const handleSuggestionFill = internal.handleSuggestionFill.bind(app);
    internal.handleSuggestionFill = vi.fn(async () => {});
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'master-secret' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(authorize).toHaveBeenCalledWith(expect.objectContaining({ target: previousTarget }));
    expect(internal.repromptAutofillAuthorization?.targetKey)
      .toContain(TARGET_RUNTIME_INCARNATION);

    internal.handleSuggestionFill = handleSuggestionFill;
    await handleSuggestionFill({ cipherId: protectedItem.id, target: currentTarget });
    await app.updateComplete;

    expect(fill).not.toHaveBeenCalled();
    expect(internal.repromptFillContinuation).toEqual({
      kind: 'matched',
      cipherId: protectedItem.id,
      tabId: 7,
      target: currentTarget,
    });
    expect(internal.repromptAutofillAuthorization).toBeNull();
  });

  it('does not treat verification without an authorization as permission to fill', async () => {
    const protectedItem = login({ reprompt: true });
    const target = {
      kind: 'login' as const,
      frameId: 0,
      formId: 'login-form',
      documentId: 'target-doc-1',
      runtimeIncarnation: TARGET_RUNTIME_INCARNATION,
      generation: 3,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    };
    const authorize = vi.fn(async () => ({ ok: true as const, data: { verified: true } }));
    const fill = vi.fn();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: protectedItem } }),
      'autofill.getTabSuggestions': async () => ({
        ok: true,
        data: { outcome: { status: 'ready', suggestions: [{
          kind: 'login', id: protectedItem.id, name: protectedItem.name,
          matchedUri: protectedItem.uris[0]!, matchType: 0, favorite: false,
          reprompt: true, target,
        }] } },
      }),
      'autofill.authorizeRepromptFill': authorize,
      'autofill.fillTabSuggestion': fill,
    }), fakeBrowser());

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', {
      detail: { cipherId: protectedItem.id, target }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'master-secret' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(fill).not.toHaveBeenCalled();
    expect(view<HTMLElement & { error?: string }>(app, 'vw-reprompt-gate').error)
      .toBe(t('fill.repromptRequired'));
  });

  it('confirms a mismatched fill-and-save without exposing its target metadata', async () => {
    const item = login({ id: 'manual', name: 'Manual login' });
    const prepare = vi.fn(async () => ({
      ok: true as const,
      data: {
        warning: {
          risk: 'no_match' as const,
          site: 'current.example',
          canSave: true,
          requiresReprompt: false,
        },
        authorization: {
          authorizationId: '11111111-1111-4111-8111-111111111111',
          expiresAt: Date.now() + 30_000,
        },
      },
    }));
    const commit = vi.fn(async () => ({
      ok: true as const,
      data: { outcome: { status: 'filled_and_saved' as const } },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [item], folders: [], collections: [], orgPermissions: [] },
      }),
      'autofill.getTabSuggestions': async () => ({
        ok: true, data: { outcome: { status: 'ready', suggestions: [] } },
      }),
      'autofill.manual.prepare': prepare,
      'autofill.manual.commit': commit,
    }), fakeBrowser());

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-fill', {
      detail: { cipherId: item.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    const confirmation = view(app, 'vw-manual-autofill-confirmation');
    expect(confirmation.textContent).not.toContain('target-document');
    confirmation.dispatchEvent(new CustomEvent('vw-manual-autofill-action', {
      detail: { action: 'fill_and_save' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(prepare).toHaveBeenCalledWith({
      type: 'autofill.manual.prepare', tabId: 7, cipherId: item.id,
    });
    expect(commit).toHaveBeenCalledWith({
      type: 'autofill.manual.commit',
      authorizationId: '11111111-1111-4111-8111-111111111111',
      action: 'fill_and_save',
    });
    expect((app as unknown as { manualAutofillConfirmation: unknown }).manualAutofillConfirmation)
      .toBeNull();
  });

  it('automatically continues a mismatched reprompt fill with no retained password', async () => {
    const item = login({ id: 'manual-protected', name: 'Protected manual', reprompt: true });
    const commit = vi.fn(async () => ({
      ok: true as const,
      data: { outcome: { status: 'filled' as const } },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [item], folders: [], collections: [], orgPermissions: [] },
      }),
      'autofill.getTabSuggestions': async () => ({
        ok: true, data: { outcome: { status: 'ready', suggestions: [] } },
      }),
      'autofill.manual.prepare': async () => ({
        ok: true,
        data: {
          warning: {
            risk: 'no_match', site: 'current.example', canSave: false, requiresReprompt: true,
          },
          authorization: {
            authorizationId: '22222222-2222-4222-8222-222222222222',
            expiresAt: Date.now() + 30_000,
          },
        },
      }),
      'autofill.manual.commit': commit,
    }), fakeBrowser());

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-fill', {
      detail: { cipherId: item.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-manual-autofill-confirmation').dispatchEvent(new CustomEvent(
      'vw-manual-autofill-action',
      { detail: { action: 'fill_only' }, bubbles: true, composed: true },
    ));
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'one-use-password' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(commit).toHaveBeenCalledWith({
      type: 'autofill.manual.commit',
      authorizationId: '22222222-2222-4222-8222-222222222222',
      action: 'fill_only',
      masterPassword: 'one-use-password',
    });
    expect((app as unknown as { repromptCredential: unknown }).repromptCredential).toBeNull();
    expect((app as unknown as { manualAutofillConfirmation: unknown }).manualAutofillConfirmation)
      .toBeNull();
  });

  it('returns a failed manual reprompt continuation to the vault instead of changing it into detail access', async () => {
    const item = login({ id: 'manual-failed', reprompt: true });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [item], folders: [], collections: [], orgPermissions: [] },
      }),
      'autofill.manual.commit': async () => ({
        ok: false, error: { code: 'reprompt_required', message: 'Wrong password' },
      }),
    }));
    app.navigate({ name: 'detail', cipherId: item.id });
    Object.assign(app as unknown as Record<string, unknown>, {
      manualAutofillConfirmation: {
        cipherId: item.id,
        tabId: 7,
        name: item.name,
        warning: { risk: 'no_match', site: 'current.example', canSave: false, requiresReprompt: true },
        authorization: {
          authorizationId: '33333333-3333-4333-8333-333333333333',
          expiresAt: Date.now() + 30_000,
        },
        action: 'fill_only',
      },
      repromptFillContinuation: { kind: 'manual', cipherId: item.id },
    });
    await app.updateComplete;
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'wrong-password' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'vault', scope: 'suggestions' });
    expect((app as unknown as { repromptCredential: unknown }).repromptCredential).toBeNull();
    expect((app as unknown as { repromptFillContinuation: unknown }).repromptFillContinuation)
      .toBeNull();
    expect(app.toastMessage).toBe(t('fill.manual.retry'));
  });

  it('keeps an external reprompt on wrong password, then auto-resumes and closes on success', async () => {
    const item = login({ id: 'external-protected', reprompt: true });
    const continuationId = '44444444-4444-4444-8444-444444444444';
    let verified = false;
    const authorize = vi.fn(async () => ({
      ok: true as const,
      data: verified
        ? { verified: true, result: { status: 'started' as const } }
        : { verified: false },
    }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [item], folders: [], collections: [], orgPermissions: [] },
      }),
      'autofill.continuation.status': async () => ({
        ok: true,
        data: {
          status: 'reprompt_required',
          continuationId,
          channel: 'keyboard',
          cipherId: item.id,
          expiresAt: Date.now() + 30_000,
        },
      }),
      'autofill.continuation.authorizeReprompt': authorize,
    }));
    close.mockClear();
    await settle(app);
    expect(app.route).toEqual({ name: 'detail', cipherId: item.id });

    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'wrong' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'detail', cipherId: item.id });
    expect(close).not.toHaveBeenCalled();

    verified = true;
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'right' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(authorize).toHaveBeenCalledTimes(2);
    expect(close).toHaveBeenCalledOnce();
  });

  it('never reuses a verified detail credential for another protected item', async () => {
    const itemA = login({ id: 'a', name: 'A', reprompt: true });
    const itemB = login({ id: 'b', name: 'B', reprompt: true });
    const getDetail = vi.fn(async (req: Extract<Req, { type: 'vault.getCipherDetail' }>) => ({
      ok: true as const,
      data: { cipher: req.id === 'a' ? itemA : itemB },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: { items: [itemA, itemB], folders: [], collections: [], orgPermissions: [] } }),
      'vault.getCipherDetail': getDetail,
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
    }));

    app.navigate({ name: 'detail', cipherId: 'a' });
    await app.updateComplete;
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'alpha-password' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(getDetail).toHaveBeenLastCalledWith({
      type: 'vault.getCipherDetail', id: 'a', masterPassword: 'alpha-password', clientEventPurpose: 'view',
    });

    app.navigate({ name: 'detail', cipherId: 'b' });
    await app.updateComplete;
    expect(view(app, 'vw-reprompt-gate')).not.toBeNull();
    expect(getDetail).toHaveBeenCalledTimes(1);
    await (app as unknown as { loadDetail(id: string): Promise<void> }).loadDetail('b');
    expect(getDetail).toHaveBeenCalledTimes(1);

    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'bravo-password' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(getDetail).toHaveBeenCalledTimes(2);
    expect(getDetail).toHaveBeenLastCalledWith({
      type: 'vault.getCipherDetail', id: 'b', masterPassword: 'bravo-password', clientEventPurpose: 'view',
    });
  });

  it('rejects a late detail response after navigating A to B', async () => {
    const lateA = deferred<Res>();
    const itemA = login({ id: 'a', name: 'A' });
    const itemB = login({ id: 'b', name: 'B' });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: { items: [itemA, itemB], folders: [], collections: [], orgPermissions: [] } }),
      'vault.getCipherDetail': (req) => req.id === 'a'
        ? lateA.promise
        : Promise.resolve({ ok: true, data: { cipher: { ...itemB, notes: 'current-b' } } }),
    }));
    app.navigate({ name: 'detail', cipherId: 'a' });
    await app.updateComplete;
    app.navigate({ name: 'detail', cipherId: 'b' });
    await settle(app);
    expect((view<HTMLElement & { cipher: { id: string } }>(app, 'vw-item-detail')).cipher.id).toBe('b');
    lateA.resolve({ ok: true, data: { cipher: { ...itemA, notes: 'stale-a' } } });
    await settle(app);
    expect((view<HTMLElement & { cipher: { id: string } }>(app, 'vw-item-detail')).cipher.id).toBe('b');
  });

  it('shows only deleted items in Trash, loads read-only detail, and returns to the vault', async () => {
    const deleted = login({ id: 'deleted', name: 'Deleted', deletedDate: '2026-01-01T00:00:00Z' });
    const getDetail = vi.fn(async () => ({ ok: true as const, data: { cipher: deleted } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: { items: [login({ id: 'live' }), deleted], folders: [], collections: [], orgPermissions: [] } }),
      'vault.getCipherDetail': getDetail,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'trash' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const vault = view<HTMLElement & {
      items: CipherSummary[];
      mode: string;
      updateComplete: Promise<unknown>;
    }>(app, 'vw-vault-view');
    await vault.updateComplete;
    expect(vault.mode).toBe('trash');
    expect(vault.items.map((item) => item.id)).toEqual(['deleted']);
    expect(app.shadowRoot?.querySelector('vw-vault-filters')).toBeNull();
    expect(vault.shadowRoot?.querySelector('.chips')).toBeNull();
    expect(vault.shadowRoot?.querySelector('.row-copy')).toBeNull();
    vault.shadowRoot!.querySelector<HTMLButtonElement>('.row-main')!.click();
    await settle(app);
    expect(getDetail).toHaveBeenCalledWith({
      type: 'vault.getCipherDetail', id: 'deleted', clientEventPurpose: 'view',
    });
    expect(view<HTMLElement & { mode: string }>(app, 'vw-item-detail').mode).toBe('trash');
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('vault');
    expect(app.vaultMode).toBe('trash');
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-vault-mode-change', {
      detail: { mode: 'active' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.vaultMode).toBe('active');
    expect(view(app, 'vw-vault-filters')).not.toBeNull();
  });

  it('reprompt-gates archived detail and editor loads while hiding organization move', async () => {
    const archived = login({
      id: 'archived',
      name: 'Archived',
      archivedDate: '2026-08-30T00:00:00Z',
      reprompt: true,
    });
    const getDetail = vi.fn(async () => ({ ok: true as const, data: { cipher: archived } }));
    const getInput = vi.fn(async () => ({
      ok: true as const,
      data: { input: { type: 1 as const, name: 'Archived', login: { password: 'secret' } } },
    }));
    const share = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [archived],
          folders: [],
          collections: [{ id: 'collection-1', name: 'Team', organizationId: 'org-1' }],
          orgPermissions: [],
        },
      }),
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
      'vault.getCipherDetail': getDetail,
      'vault.getCipherInput': getInput,
      'vault.shareCipher': share,
    }));

    app.navigate({ name: 'detail', cipherId: archived.id });
    await settle(app);
    expect(view(app, 'vw-reprompt-gate')).not.toBeNull();
    expect(getDetail).not.toHaveBeenCalled();
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(getDetail).toHaveBeenCalledWith({
      type: 'vault.getCipherDetail', id: archived.id, masterPassword: 'correct-master', clientEventPurpose: 'view',
    });

    const item = view<HTMLElement>(app, 'vw-item-detail');
    item.shadowRoot!.querySelector<HTMLButtonElement>('[data-edit]')!.click();
    await settle(app);
    expect(view(app, 'vw-reprompt-gate')).not.toBeNull();
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);

    expect(getInput).toHaveBeenCalledWith({
      type: 'vault.getCipherInput', id: archived.id, cipherInputPurpose: 'edit', masterPassword: 'correct-master', clientEventPurpose: 'editor',
    });
    expect(app.route).toEqual({ name: 'editor', mode: 'edit', cipherId: archived.id });
    const editor = view<HTMLElement>(app, 'vw-cipher-editor');
    expect(editor.shadowRoot?.querySelector('[data-move]')).toBeNull();
    editor.dispatchEvent(new CustomEvent('vw-editor-share', {
      detail: { cipherId: archived.id, organizationId: 'org-1', collectionIds: ['collection-1'] },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(share).not.toHaveBeenCalled();
  });

  it('loads reprompt-cleared trash detail but rejects forged edit and mutation events', async () => {
    const deleted = login({
      id: 'deleted',
      name: 'Deleted',
      deletedDate: '2026-08-30T00:00:00Z',
      reprompt: true,
      hasPasskey: true,
    });
    const getDetail = vi.fn(async () => ({ ok: true as const, data: { cipher: deleted } }));
    const update = vi.fn(async () => ({ ok: true as const, data: null }));
    const addAttachment = vi.fn(async () => ({ ok: true as const, data: null }));
    const upgradeAttachment = vi.fn(async () => ({ ok: true as const, data: null }));
    const deleteAttachment = vi.fn(async () => ({ ok: true as const, data: null }));
    const deletePasskey = vi.fn(async () => ({ ok: true as const, data: null }));
    const softDelete = vi.fn(async () => ({ ok: true as const, data: null }));
    const browser = fakeBrowser({ openUrl: vi.fn(async () => {}) });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [deleted], folders: [], collections: [], orgPermissions: [] },
      }),
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
      'vault.getCipherDetail': getDetail,
      'vault.updateCipher': update,
      'vault.addAttachment': addAttachment,
      'vault.upgradeLegacyAttachment': upgradeAttachment,
      'vault.deleteAttachment': deleteAttachment,
      'vault.deletePasskey': deletePasskey,
      'vault.softDeleteCipher': softDelete,
    }), browser);

    app.navigate({ name: 'detail', cipherId: deleted.id });
    await settle(app);
    expect(getDetail).not.toHaveBeenCalled();
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(getDetail).toHaveBeenCalledWith({
      type: 'vault.getCipherDetail', id: deleted.id, masterPassword: 'correct-master', clientEventPurpose: 'view',
    });

    const item = view(app, 'vw-item-detail');
    const events: Array<[string, unknown]> = [
      ['vw-edit-item', { cipherId: deleted.id }],
      ['vw-item-fill', { cipherId: deleted.id }],
      ['vw-attachment-add', { cipherId: deleted.id, fileName: 'x', dataB64: '' }],
      ['vw-attachment-upgrade', { cipherId: deleted.id, attachmentId: 'a', fileName: 'x' }],
      ['vw-attachment-delete', { cipherId: deleted.id, attachmentId: 'a', fileName: 'x' }],
      ['vw-passkey-delete', { cipherId: deleted.id, credentialId: 'credential' }],
      ['vw-delete-item', { cipherId: deleted.id, permanent: false }],
    ];
    for (const [type, detail] of events) {
      item.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
    }
    await settle(app);

    expect(app.route).toEqual({ name: 'detail', cipherId: deleted.id });
    expect(update).not.toHaveBeenCalled();
    expect(addAttachment).not.toHaveBeenCalled();
    expect(upgradeAttachment).not.toHaveBeenCalled();
    expect(deleteAttachment).not.toHaveBeenCalled();
    expect(deletePasskey).not.toHaveBeenCalled();
    expect(softDelete).not.toHaveBeenCalled();
    expect(browser.openUrl).not.toHaveBeenCalled();
  });

  it('shows only archived items and applies a typed unarchive result without reloading the list', async () => {
    const archived = login({
      id: 'archived',
      name: 'Archived',
      archivedDate: '2026-08-30T00:00:00Z',
    });
    const deletedArchived = login({
      id: 'deleted-archived',
      name: 'Deleted archived',
      archivedDate: '2026-08-29T00:00:00Z',
      deletedDate: '2026-08-31T00:00:00Z',
    });
    const active = login({ id: 'archived', name: 'Archived' });
    const unarchive = vi.fn(async () => ({
      ok: true as const,
      data: { items: [active], folders: [], collections: [], orgPermissions: [] },
    }));
    const listItems = vi.fn(async () => ({
      ok: true as const,
      data: {
        items: [login({ id: 'live', name: 'Live' }), archived, deletedArchived],
        folders: [], collections: [], orgPermissions: [],
      },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': listItems,
      'vault.unarchiveCipher': unarchive,
    }));

    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'archive' }, bubbles: true, composed: true,
    }));
    await settle(app);
    const vault = view<HTMLElement & { items: CipherSummary[]; mode: string }>(app, 'vw-vault-view');
    expect(vault.mode).toBe('archive');
    expect(vault.items.map((item) => item.id)).toEqual(['archived']);
    expect(app.shadowRoot?.querySelector('vw-vault-filters')).toBeNull();

    vault.dispatchEvent(new CustomEvent('vw-unarchive-item', {
      detail: {
        action: 'unarchive',
        cipherId: 'archived',
        sourceMode: 'archive',
        targetMode: 'active',
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(unarchive).toHaveBeenCalledWith({ type: 'vault.unarchiveCipher', id: 'archived' });
    expect(listItems).toHaveBeenCalledTimes(1);
    expect(app.vaultMode).toBe('active');
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    expect(app.items[0]?.archivedDate).toBeUndefined();
    expect(app.toastMessage).toBe(t('detail.unarchived'));
  });

  it('passes the reprompt proof through an archive transition and opens Archive on success', async () => {
    const protectedItem = login({ reprompt: true });
    const archived = login({ reprompt: true, archivedDate: '2026-08-31T00:00:00Z' });
    const archive = vi.fn(async () => ({
      ok: true as const,
      data: { items: [archived], folders: [], collections: [], orgPermissions: [] },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: protectedItem } }),
      'vault.archiveCipher': archive,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: protectedItem.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-archive-item', {
      detail: {
        action: 'archive',
        cipherId: protectedItem.id,
        sourceMode: 'active',
        targetMode: 'archive',
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(archive).toHaveBeenCalledWith({
      type: 'vault.archiveCipher',
      id: protectedItem.id,
      masterPassword: 'correct-master',
    });
    expect(app.vaultMode).toBe('archive');
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    expect(app.toastMessage).toBe(t('detail.archived'));
  });

  it('deletes one passkey with the current item reprompt proof and refreshes detail', async () => {
    const protectedItem = login({ hasPasskey: true, reprompt: true });
    const updatedItem = login({ reprompt: true });
    const passkeyDetail = {
      ...protectedItem,
      fido2Credentials: [{
        credentialId: 'public-credential-id',
        keyValue: '',
        rpId: 'nebula.dev',
        counter: 0,
        discoverable: true,
      }],
    };
    const getDetail = vi.fn()
      .mockResolvedValueOnce({ ok: true as const, data: { cipher: passkeyDetail } })
      .mockResolvedValueOnce({ ok: true as const, data: { cipher: updatedItem } });
    const remove = vi.fn(async () => ({
      ok: true as const,
      data: { items: [updatedItem], folders: [], collections: [], orgPermissions: [] },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
      'vault.getCipherDetail': getDetail,
      'vault.deletePasskey': remove,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: protectedItem.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-passkey-delete', {
      detail: { cipherId: protectedItem.id, credentialId: 'public-credential-id' },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(remove).toHaveBeenCalledWith({
      type: 'vault.deletePasskey',
      id: protectedItem.id,
      credentialId: 'public-credential-id',
      masterPassword: 'correct-master',
    });
    expect(getDetail).toHaveBeenCalledTimes(2);
    expect(app.items[0]?.hasPasskey).toBeUndefined();
    expect(app.toastMessage).toBe(t('detail.passkeyDeleted'));
  });

  it('upgrades a legacy attachment with the current reprompt proof and refreshes detail', async () => {
    const protectedItem = login({ reprompt: true });
    const legacyDetail = {
      ...protectedItem,
      attachments: [{ id: 'legacy-id', fileName: 'legacy.txt', legacy: true as const }],
    };
    const modernDetail = {
      ...protectedItem,
      attachments: [{ id: 'modern-id', fileName: 'legacy.txt' }],
    };
    const getDetail = vi.fn()
      .mockResolvedValueOnce({ ok: true as const, data: { cipher: legacyDetail } })
      .mockResolvedValueOnce({ ok: true as const, data: { cipher: modernDetail } });
    const upgrade = vi.fn(async () => ({
      ok: true as const,
      data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [protectedItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
      'vault.getCipherDetail': getDetail,
      'vault.upgradeLegacyAttachment': upgrade,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: protectedItem.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'correct-master' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-attachment-upgrade', {
      detail: { cipherId: protectedItem.id, attachmentId: 'legacy-id', fileName: 'legacy.txt' },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(upgrade).toHaveBeenCalledWith({
      type: 'vault.upgradeLegacyAttachment',
      cipherId: protectedItem.id,
      attachmentId: 'legacy-id',
      masterPassword: 'correct-master',
    });
    expect(getDetail).toHaveBeenCalledTimes(2);
    expect(app.detailStatus).toEqual({
      message: t('detail.attachmentUpgraded', { name: 'legacy.txt' }),
      tone: 'success',
    });
  });

  it('restores an archived trashed item back to Archive', async () => {
    const trashed = login({
      archivedDate: '2026-08-29T00:00:00Z',
      deletedDate: '2026-08-30T00:00:00Z',
    });
    const restored = login({ archivedDate: '2026-08-29T00:00:00Z' });
    const restore = vi.fn(async () => ({
      ok: true as const,
      data: { items: [restored], folders: [], collections: [], orgPermissions: [] },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true, data: { items: [trashed], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.restoreCipher': restore,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'trash' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-open', {
      detail: { cipherId: trashed.id }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-restore-item', {
      detail: {
        action: 'restore',
        cipherId: trashed.id,
        sourceMode: 'trash',
        targetMode: 'archive',
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(restore).toHaveBeenCalledWith({ type: 'vault.restoreCipher', id: trashed.id });
    expect(app.vaultMode).toBe('archive');
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    expect(app.items[0]?.deletedDate).toBeUndefined();
  });

  it('applies mutation listings directly and surfaces mutation failures as a toast', async () => {
    const listItems = vi.fn(async () => ({ ok: true as const, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }));
    const moved = login({ deletedDate: '2026-01-01T00:00:00Z' });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': listItems,
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: login() } }),
      'vault.softDeleteCipher': async () => ({ ok: true, data: { items: [moved], folders: [], collections: [], orgPermissions: [] } }),
      'vault.createFolder': async () => ({ ok: false, error: { code: 'error', message: 'Folder failed' } }),
    }));
    app.navigate({ name: 'detail', cipherId: 'c1' });
    await settle(app);
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-delete-item', {
      detail: { cipherId: 'c1', permanent: false }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(listItems).toHaveBeenCalledTimes(1);
    expect(app.items[0]?.deletedDate).toBeDefined();

    view(app, 'vw-vault-filters').dispatchEvent(new CustomEvent('vw-folder-mutate', {
      detail: { op: 'create', name: 'Work' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(app.toastMessage).toBe('Folder failed');
  });

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
      'autofill.getTabSuggestions': async () => ({
        ok: true,
        data: {
          outcome: {
            status: 'ready',
            suggestions: [{
              kind: 'login', id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false,
              target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 2, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
            }],
          },
        },
      }),
      'autofill.fillTabSuggestion': fill,
    }), fakeBrowser());
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', {
      detail: {
        cipherId: 'c1',
        target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 2, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(fill).toHaveBeenCalledWith({
      type: 'autofill.fillTabSuggestion',
      tabId: 7,
      cipherId: 'c1',
      target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 2, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
    });
    expect(app.toastMessage).not.toBe('');
  });

  it('keeps structured suggestion metadata but strips accidental secrets and preserves its fill target', async () => {
    const fill = vi.fn(async () => ({ ok: true as const, data: { outcome: { status: 'filled' as const } } }));
    const unsafeCard = {
      kind: 'card',
      id: 'card-1',
      name: 'Travel Card',
      subtitle: 'Visa',
      favorite: true,
      password: 'must-not-enter-popup-state',
      data: { number: '4111111111111111', code: '123' },
      target: {
        kind: 'card', frameId: 0, formId: 'payment', documentId: 'doc-0',
        runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 8,
        roles: ['number', 'expMonth'],
        code: 'must-not-enter-popup-state',
      },
    };
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => ({
        ok: true,
        data: { outcome: { status: 'ready', suggestions: [unsafeCard] } },
      }) as Res,
      'autofill.fillTabSuggestion': fill,
    }), fakeBrowser());

    expect(app.suggestionsState).toEqual({
      status: 'ready',
      suggestions: [{
        kind: 'card',
        id: 'card-1',
        name: 'Travel Card',
        subtitle: 'Visa',
        favorite: true,
        target: {
          kind: 'card', frameId: 0, formId: 'payment', documentId: 'doc-0',
          runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 8,
          roles: ['number', 'expMonth'],
        },
      }],
    });
    expect((app as unknown as { currentSiteIds(): string[] }).currentSiteIds()).toEqual([]);

    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', {
      detail: {
        cipherId: 'card-1',
        target: {
          kind: 'card', frameId: 0, formId: 'payment', documentId: 'doc-0',
          runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 8,
          roles: ['number', 'expMonth'],
        },
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(fill).toHaveBeenCalledWith({
      type: 'autofill.fillTabSuggestion',
      tabId: 7,
      cipherId: 'card-1',
      target: {
        kind: 'card', frameId: 0, formId: 'payment', documentId: 'doc-0',
        runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 8,
        roles: ['number', 'expMonth'],
      },
    });
  });

  it('surfaces a stale fill target instead of failing silently', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [{
        kind: 'login', id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false,
        target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 1, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
      }] } } }),
      'autofill.fillTabSuggestion': async () => ({ ok: true, data: { outcome: { status: 'target_changed' } } }),
    }), fakeBrowser());
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-suggestion-fill', {
      detail: {
        cipherId: 'c1',
        target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 1, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
      },
      bubbles: true,
      composed: true,
    }));
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

  it('passes the authoritative vault target from the create editor to the worker', async () => {
    const listing = {
      items: [login()],
      folders: [],
      collections: [{
        id: 'collection-1',
        name: 'Engineering',
        organizationId: 'org-1',
        readOnly: false,
        assigned: true,
      }],
      orgPermissions: [{
        id: 'org-1',
        name: 'Acme',
        canCreateCollections: false,
        canEditCollections: false,
        canDeleteCollections: false,
        canManageCollections: false,
        isMember: true,
        isProviderUser: false,
        canCreateItems: true,
      }],
      personalCreationAllowed: false,
    };
    const create = vi.fn(async () => ({ ok: true as const, data: listing }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: listing }),
      'vault.createCipher': create,
    }));
    expect(app.personalCreationAllowed).toBe(false);

    app.navigate({ name: 'editor', mode: 'create', cipherType: 1 });
    await settle(app);
    const target = {
      kind: 'organization' as const,
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
    };
    view(app, 'vw-cipher-editor').dispatchEvent(new CustomEvent('vw-editor-save', {
      detail: { input: { type: 1, name: 'Organization login' }, target },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(create).toHaveBeenCalledWith({
      type: 'vault.createCipher',
      input: { type: 1, name: 'Organization login' },
      target,
    });
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
  });

  it('opens the exact data-ownership migration target and submits one master-password proof', async () => {
    const personal = login({ id: 'personal-1', name: 'Personal login' });
    const migrated = login({
      id: 'personal-1',
      name: 'Personal login',
      organizationId: 'org-1',
      collectionIds: ['default-collection'],
    });
    const listing = {
      items: [personal],
      folders: [],
      collections: [{
        id: 'default-collection',
        name: 'My Items',
        organizationId: 'org-1',
        readOnly: false,
        assigned: true,
        type: 1,
      }],
      orgPermissions: [{
        id: 'org-1',
        name: 'Acme',
        canCreateCollections: false,
        canEditCollections: false,
        canDeleteCollections: false,
        canManageCollections: false,
        isMember: true,
        canCreateItems: true,
      }],
      personalCreationAllowed: false,
    };
    let migrationComplete = false;
    const migrate = vi.fn(async () => {
      migrationComplete = true;
      return {
        ok: true as const,
        data: { ...listing, items: [migrated] },
      };
    });
    const openOptions = vi.fn(async () => {});
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { ...listing, items: migrationComplete ? [migrated] : [personal] },
      }),
      'vault.getOrganizationDataOwnershipStatus': async () => migrationComplete
        ? ({ ok: true, data: { status: 'compliant' } })
        : ({
            ok: true,
            data: {
              status: 'migration_available',
              organizationId: 'org-1',
              collectionId: 'default-collection',
              personalItemCount: 1,
              migrateAuthorization: {
                authorizationId: '11111111-1111-4111-8111-111111111111',
                expiresAt: Date.now() + 30_000,
              },
              leaveAuthorization: {
                authorizationId: '22222222-2222-4222-8222-222222222222',
                expiresAt: Date.now() + 30_000,
              },
            },
          }),
      'vault.migrateOrganizationDataOwnership': migrate,
    }), fakeBrowser({ openOptions }));
    await settle(app);

    expect(app.route).toEqual({ name: 'dataOwnership' });
    const constrainedMenu = view<HTMLElement & { constrained: boolean }>(app, 'vw-account-menu');
    expect(constrainedMenu.constrained).toBe(true);
    constrainedMenu.dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'device-login-approvals' },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(app.route).toEqual({ name: 'dataOwnership' });
    app.navigate({ name: 'generator' });
    expect(app.route).toEqual({ name: 'dataOwnership' });
    constrainedMenu.dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'options' },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(openOptions).not.toHaveBeenCalled();
    const viewElement = view(app, 'vw-data-ownership-view');
    expect(viewElement.shadowRoot?.textContent).toContain('Acme');
    expect(viewElement.shadowRoot?.textContent).toContain('My Items');
    const password = viewElement.shadowRoot!.querySelector<HTMLInputElement>('[data-master-password]')!;
    password.value = 'correct-master';
    viewElement.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', {
      cancelable: true,
    }));
    await settle(app);

    expect(migrate).toHaveBeenCalledWith({
      type: 'vault.migrateOrganizationDataOwnership',
      organizationId: 'org-1',
      collectionId: 'default-collection',
      authorizationId: '11111111-1111-4111-8111-111111111111',
      masterPassword: 'correct-master',
    });
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    expect(app.items[0]).toMatchObject({ organizationId: 'org-1' });
    expect(app.toastMessage).toBe(t('dataOwnership.completed'));
  });

  it('keeps a blocked ownership policy in front and leaves only after explicit confirmation', async () => {
    const listing = {
      items: [login({ id: 'personal-1' })],
      folders: [],
      collections: [],
      orgPermissions: [{
        id: 'org-1',
        name: 'Acme',
        canCreateCollections: false,
        canEditCollections: false,
        canDeleteCollections: false,
        canManageCollections: false,
        isMember: true,
        canCreateItems: true,
      }],
      personalCreationAllowed: false,
    };
    let left = false;
    const leave = vi.fn(async () => {
      left = true;
      return {
        ok: true as const,
        data: { ...listing, items: [], orgPermissions: [] },
      };
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: listing }),
      'vault.getOrganizationDataOwnershipStatus': async () => left
        ? ({ ok: true, data: { status: 'not_required' } })
        : ({
            ok: true,
            data: {
              status: 'blocked',
              organizationId: 'org-1',
              personalItemCount: 1,
              reason: 'target_unavailable',
              leaveAuthorization: {
                authorizationId: '33333333-3333-4333-8333-333333333333',
                expiresAt: Date.now() + 30_000,
              },
            },
          }),
      'vault.leaveOrganizationDataOwnership': leave,
    }));
    await settle(app);

    expect(app.route).toEqual({ name: 'dataOwnership' });
    const ownership = view<HTMLElement & { updateComplete: Promise<unknown> }>(
      app,
      'vw-data-ownership-view',
    );
    ownership.shadowRoot!.querySelector<HTMLButtonElement>('button')!.click();
    await ownership.updateComplete;
    expect(leave).not.toHaveBeenCalled();
    ownership.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')[1]!.click();
    await settle(app);

    expect(leave).toHaveBeenCalledWith({
      type: 'vault.leaveOrganizationDataOwnership',
      organizationId: 'org-1',
      authorizationId: '33333333-3333-4333-8333-333333333333',
    });
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
    expect(app.toastMessage).toBe(t('dataOwnership.left'));
  });

  it('requires authoritative reconciliation after an unknown migration outcome', async () => {
    const listing = {
      items: [login({ id: 'personal-1' })],
      folders: [],
      collections: [{
        id: 'default-collection', name: 'My Items', organizationId: 'org-1',
        readOnly: false, assigned: true, type: 1,
      }],
      orgPermissions: [{
        id: 'org-1', name: 'Acme', canCreateCollections: false,
        canEditCollections: false, canDeleteCollections: false, canManageCollections: false,
        isMember: true, canCreateItems: true,
      }],
      personalCreationAllowed: false,
    };
    const migrate = vi.fn(async () => ({
      ok: false as const,
      error: { code: 'outcome_unknown' as const, message: 'The server outcome is unknown.' },
    }));
    let reconciled = false;
    const fullSync = vi.fn(async () => {
      reconciled = true;
      return { ok: true as const, data: listing };
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: listing }),
      'vault.getOrganizationDataOwnershipStatus': async () => reconciled
        ? ({ ok: true, data: { status: 'compliant' as const } })
        : ({
        ok: true,
        data: {
          status: 'migration_available', organizationId: 'org-1',
          collectionId: 'default-collection', personalItemCount: 1,
          migrateAuthorization: {
            authorizationId: '44444444-4444-4444-8444-444444444444',
            expiresAt: Date.now() + 30_000,
          },
          leaveAuthorization: {
            authorizationId: '55555555-5555-4555-8555-555555555555',
            expiresAt: Date.now() + 30_000,
          },
        },
      }),
      'vault.migrateOrganizationDataOwnership': migrate,
      'vault.sync': fullSync,
    }));
    await settle(app);

    const ownership = view(app, 'vw-data-ownership-view');
    ownership.shadowRoot!.querySelector<HTMLInputElement>('[data-master-password]')!.value = 'secret';
    ownership.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    await settle(app);

    expect(app.organizationDataOwnershipStatus).toEqual({
      status: 'reconciliation_required',
      operation: 'migrate',
      reason: 'outcome_unknown',
    });
    const reconcile = view(app, 'vw-data-ownership-view');
    expect(reconcile.shadowRoot!.querySelector('form')).toBeNull();
    const messages = [...reconcile.shadowRoot!.querySelectorAll<HTMLElement & { message: string }>(
      'vw-status-message',
    )];
    expect(messages.at(-1)?.message).toBe('The server outcome is unknown.');
    expect(reconcile.shadowRoot?.textContent).toContain(t('dataOwnership.fullSync'));
    reconcile.shadowRoot!.querySelector<HTMLButtonElement>('[data-full-sync]')!.click();
    await settle(app);
    expect(fullSync).toHaveBeenCalledOnce();
    expect(app.route).toEqual({ name: 'vault', scope: 'all' });
  });

  it('fails closed across enterprise-policy revoke and reloads ownership on refresh', async () => {
    let status: unknown = { status: 'not_required' };
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getOrganizationDataOwnershipStatus': async () => ({ ok: true, data: status } as Res),
    }));
    await settle(app);
    expect(app.route.name).toBe('vault');

    enterprisePolicyMessageListener()({ type: 'enterprisePolicy.clientChanged', phase: 'revoke' });
    await app.updateComplete;
    expect(app.route).toEqual({ name: 'dataOwnership' });

    status = {
      status: 'migration_available', organizationId: 'org-1', collectionId: 'collection-1',
      personalItemCount: 1,
      migrateAuthorization: {
        authorizationId: '66666666-6666-4666-8666-666666666666',
        expiresAt: Date.now() + 30_000,
      },
      leaveAuthorization: {
        authorizationId: '77777777-7777-4777-8777-777777777777',
        expiresAt: Date.now() + 30_000,
      },
    };
    enterprisePolicyMessageListener()({ type: 'enterprisePolicy.clientChanged', phase: 'refresh' });
    await settle(app);
    await settle(app);

    expect(app.route).toEqual({ name: 'dataOwnership' });
    expect(app.organizationDataOwnershipStatus).toMatchObject({
      status: 'migration_available',
      migrateAuthorization: {
        authorizationId: '66666666-6666-4666-8666-666666666666',
      },
    });
  });

  it('captures a visible-tab TOTP QR code only after the editor command', async () => {
    const uri = 'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    const captureVisibleTab = vi.fn(async () => uri);
    const app = await mountApp(fakeRequest(UNLOCKED), fakeBrowser({ captureVisibleTab }));
    app.navigate({ name: 'editor', mode: 'create', cipherType: 1 });
    await settle(app);
    expect(captureVisibleTab).not.toHaveBeenCalled();

    view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-cipher-editor')
      .shadowRoot!.querySelector<HTMLButtonElement>('[data-capture-totp]')!.click();
    await settle(app);
    const editor = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-cipher-editor');
    await editor.updateComplete;

    expect(captureVisibleTab).toHaveBeenCalledOnce();
    expect(editor.shadowRoot!.querySelector<HTMLInputElement>('[data-field="totp"]')!.value).toBe(uri);
    expect(app.editorStatus).toEqual({ message: t('editor.totpCaptured'), tone: 'success' });
  });
});

describe('vw-popup-app sync bar', () => {
  it('syncs on demand and refreshes the scheduler-owned successful time', async () => {
    const sync = vi.fn(async () => ({ ok: true as const, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }));
    let statusCalls = 0;
    const getSyncStatus = vi.fn(async () => ({
      ok: true as const,
      data: { dirty: false, syncing: false, lastSuccessfulSyncAt: ++statusCalls === 1 ? 100 : 200 },
    }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.sync': sync, 'vault.getSyncStatus': getSyncStatus }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
    await settle(app);
    expect(sync).toHaveBeenCalled();
    expect(getSyncStatus).toHaveBeenCalledTimes(2);
    expect(app.lastSuccessfulSyncAt).toBe(200);
  });

  it('surfaces a sync failure and keeps scheduler status unknown when its refresh fails', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getSyncStatus': async () => ({ ok: false, error: { code: 'error', message: 'Status unavailable' } }),
      'vault.sync': async () => ({ ok: false, error: { code: 'error', message: 'Server unavailable' } }),
    }));
    view(app, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.syncStatus).toBeNull();
    expect(app.lastSuccessfulSyncAt).toBeUndefined();
    expect(app.toastMessage).toBe('Server unavailable');
  });
});

describe('vw-popup-app scheduler status', () => {
  it('notifies popupOpened once without blocking first-screen routing', async () => {
    const opened = deferred<Res>();
    const popupOpened = vi.fn(() => opened.promise);
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.popupOpened': popupOpened }));
    expect(app.route.name).toBe('vault');
    expect(popupOpened).toHaveBeenCalledTimes(1);
    app.requestUpdate();
    await app.updateComplete;
    expect(popupOpened).toHaveBeenCalledTimes(1);
    opened.resolve({ ok: true, data: null });
    await settle(app);
  });

  it('uses getSyncStatus as the only source for time, dirty state, and syncing', async () => {
    const status = { identity: 'account-a', lastSuccessfulSyncAt: 123, dirty: true, syncing: true };
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getSyncStatus': async () => ({ ok: true, data: status }),
    }));
    expect(app.syncStatus).toEqual(status);
    expect(app.lastSuccessfulSyncAt).toBe(123);
    expect(app.syncDirty).toBe(true);
    expect(app.syncing).toBe(true);
    const bar = view<HTMLElement & {
      lastSuccessfulSyncAt: number | undefined;
      dirty: boolean | undefined;
      syncing: boolean;
    }>(app, 'vw-sync-bar');
    expect(bar.lastSuccessfulSyncAt).toBe(123);
    expect(bar.dirty).toBe(true);
    expect(bar.syncing).toBe(true);
  });

  it('refreshes a transient login sync until the scheduler reports completion', async () => {
    const opened = deferred<Res>();
    let statusCalls = 0;
    const getSyncStatus = vi.fn(async () => ({
      ok: true as const,
      data: statusCalls++ === 0
        ? { identity: 'account-a', dirty: false, syncing: true }
        : { identity: 'account-a', lastSuccessfulSyncAt: 456, dirty: false, syncing: false },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.popupOpened': () => opened.promise,
      'vault.getSyncStatus': getSyncStatus,
    }));

    expect(app.syncing).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 350));
    await app.updateComplete;

    expect(getSyncStatus).toHaveBeenCalledTimes(2);
    expect(app.syncing).toBe(false);
    expect(app.lastSuccessfulSyncAt).toBe(456);
    opened.resolve({ ok: true, data: null });
  });

  it('discards a sync-status response from the workspace that was locked', async () => {
    const pendingStatus = deferred<Res>();
    const opened = deferred<Res>();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.popupOpened': () => opened.promise,
      'vault.getSyncStatus': () => pendingStatus.promise,
      'auth.lock': async () => ({ ok: true, data: null }),
    }));
    view(app, 'vw-popup-header').dispatchEvent(new CustomEvent('vw-lock', { bubbles: true, composed: true }));
    await settle(app);
    expect(app.route.name).toBe('unlock');
    pendingStatus.resolve({ ok: true, data: { identity: 'old-account', lastSuccessfulSyncAt: 999, dirty: true, syncing: true } });
    opened.resolve({ ok: true, data: null });
    await settle(app);
    expect(app.syncStatus).toBeNull();
    expect(app.lastSuccessfulSyncAt).toBeUndefined();
    expect(app.syncing).toBe(false);
  });

  it('reloads listing, suggestions, and status after a same-identity successful sync metadata advance', async () => {
    let successfulAt = 100;
    let listingVersion = 0;
    const listItems = vi.fn(async () => ({
      ok: true as const,
      data: {
        items: [login({ name: listingVersion++ === 0 ? 'Before sync' : 'After sync' })],
        folders: [], collections: [], orgPermissions: [],
      },
    }));
    const suggestions = vi.fn(async () => ({ ok: true as const, data: { outcome: { status: 'ready' as const, suggestions: [] } } }));
    const getSyncStatus = vi.fn(async () => ({
      ok: true as const,
      data: { identity: 'account-a', lastSuccessfulSyncAt: successfulAt, dirty: false, syncing: false },
    }));
    const sync = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': listItems,
      'autofill.getTabSuggestions': suggestions,
      'vault.getSyncStatus': getSyncStatus,
      'vault.sync': sync,
    }), fakeBrowser());
    const listener = vaultSyncStorageListener();
    const listCalls = listItems.mock.calls.length;
    const suggestionCalls = suggestions.mock.calls.length;
    const statusCalls = getSyncStatus.mock.calls.length;

    successfulAt = 200;
    emitVaultSyncSuccess(listener, 'account-a', 100, 200);
    await settle(app);
    await settle(app);

    expect(listItems).toHaveBeenCalledTimes(listCalls + 1);
    expect(suggestions).toHaveBeenCalledTimes(suggestionCalls + 1);
    expect(getSyncStatus).toHaveBeenCalledTimes(statusCalls + 1);
    expect(app.items[0]?.name).toBe('After sync');
    expect(app.lastSuccessfulSyncAt).toBe(200);
    expect(sync).not.toHaveBeenCalled();
  });

  it('ignores another identity, stale or dirty-only metadata and removes the listener on disconnect', async () => {
    const listItems = vi.fn(UNLOCKED['vault.listItems']!);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': listItems,
      'vault.getSyncStatus': async () => ({
        ok: true,
        data: { identity: 'account-a', lastSuccessfulSyncAt: 100, dirty: false, syncing: false },
      }),
    }));
    const listener = vaultSyncStorageListener();
    const baseline = listItems.mock.calls.length;

    emitVaultSyncSuccess(listener, 'account-b', 100, 200);
    emitVaultSyncSuccess(listener, 'account-a', 200, 150);
    listener({
      vaultSyncSchedulerMetadata: {
        oldValue: vaultSyncMetadata('account-a', 100, 100),
        newValue: vaultSyncMetadata('account-a', 100, 200),
      },
    }, 'local');
    await settle(app);
    expect(listItems).toHaveBeenCalledTimes(baseline);

    app.remove();
    expect(browserPolyfill.storage.onChanged.removeListener).toHaveBeenCalledWith(listener);
    emitVaultSyncSuccess(listener, 'account-a', 100, 300);
    await flushAsync();
    expect(listItems).toHaveBeenCalledTimes(baseline);
  });

  it('revokes an old-account metadata refresh when the workspace switches accounts', async () => {
    let state: SessionState = 'unlocked';
    const listItems = vi.fn(UNLOCKED['vault.listItems']!);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state } }),
      'auth.switchAccount': async () => {
        state = 'locked';
        return { ok: true, data: null };
      },
      'vault.listItems': listItems,
      'vault.getSyncStatus': async () => ({
        ok: true,
        data: { identity: 'account-a', lastSuccessfulSyncAt: 100, dirty: false, syncing: false },
      }),
    }));
    const listener = vaultSyncStorageListener();
    const baseline = listItems.mock.calls.length;
    app.selectedOrganizationId = PERSONAL_VAULT_FILTER_ID;
    view(app, 'vw-account-menu').dispatchEvent(new CustomEvent('vw-account-action', {
      detail: { action: 'switch-account', email: 'other@example.com' },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(app.route.name).toBe('unlock');
    expect(app.selectedOrganizationId).toBeNull();

    emitVaultSyncSuccess(listener, 'account-a', 100, 200);
    await settle(app);
    expect(listItems).toHaveBeenCalledTimes(baseline);
  });

  it('coalesces concurrent metadata advances into one latest trailing refresh', async () => {
    const delayedListing = deferred<Res>();
    let listCall = 0;
    let successfulAt = 100;
    const listItems = vi.fn((): Promise<Res> => {
      listCall += 1;
      if (listCall === 1) return Promise.resolve({
        ok: true, data: { items: [login({ name: 'Initial' })], folders: [], collections: [], orgPermissions: [] },
      });
      if (listCall === 2) return delayedListing.promise;
      return Promise.resolve({
        ok: true, data: { items: [login({ name: 'Latest' })], folders: [], collections: [], orgPermissions: [] },
      });
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': listItems,
      'vault.getSyncStatus': async () => ({
        ok: true,
        data: { identity: 'account-a', lastSuccessfulSyncAt: successfulAt, dirty: false, syncing: false },
      }),
    }));
    const listener = vaultSyncStorageListener();
    successfulAt = 200;
    emitVaultSyncSuccess(listener, 'account-a', 100, 200);
    await flushAsync();
    successfulAt = 300;
    emitVaultSyncSuccess(listener, 'account-a', 200, 300);
    emitVaultSyncSuccess(listener, 'account-a', 200, 300);
    delayedListing.resolve({
      ok: true,
      data: { items: [login({ name: 'Intermediate' })], folders: [], collections: [], orgPermissions: [] },
    });
    await settle(app);
    await settle(app);
    await settle(app);

    expect(listItems).toHaveBeenCalledTimes(3);
    expect(app.items[0]?.name).toBe('Latest');
    expect(app.lastSuccessfulSyncAt).toBe(300);
  });

  it('keeps an unsaved ordinary editor mounted when the refreshed listing removes its item', async () => {
    let refreshed = false;
    let successfulAt = 100;
    const share = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: refreshed ? [] : [login()], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherInput': async () => ({
        ok: true,
        data: { input: { type: 1, name: 'Nebula', login: { password: 'old-secret' } } },
      }),
      'vault.shareCipher': share,
      'vault.getSyncStatus': async () => ({
        ok: true,
        data: { identity: 'account-a', lastSuccessfulSyncAt: successfulAt, dirty: false, syncing: false },
      }),
    }));
    app.navigate({ name: 'editor', mode: 'edit', cipherId: 'c1' });
    await settle(app);
    const editor = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-cipher-editor');
    const password = editor.shadowRoot!.querySelector<HTMLInputElement>('[data-password]')!;
    password.value = 'unsaved-secret';
    password.dispatchEvent(new Event('input'));
    await editor.updateComplete;
    editor.dispatchEvent(new CustomEvent('vw-editor-share', {
      detail: { cipherId: 'c1', organizationId: 'org-1', collectionIds: ['collection-1'] },
      bubbles: true,
      composed: true,
    }));
    await app.updateComplete;
    expect(share).not.toHaveBeenCalled();
    expect(app.editorStatus?.message).toBe('请先保存条目修改，再将其移动到组织。');

    refreshed = true;
    successfulAt = 200;
    emitVaultSyncSuccess(vaultSyncStorageListener(), 'account-a', 100, 200);
    await settle(app);
    await settle(app);

    expect(app.items).toEqual([]);
    expect(view(app, 'vw-cipher-editor')).toBe(editor);
    expect(editor.shadowRoot!.querySelector<HTMLInputElement>('[data-password]')!.value).toBe('unsaved-secret');
  });

  it('preserves unsaved SSH metadata, import mode, and private key across an external sync refresh', async () => {
    const ssh: KnownCipherSummary = {
      id: 'ssh-1', type: 5, name: 'Deploy key', uris: [], loginUris: [], favorite: false,
    };
    let refreshed = false;
    let successfulAt = 100;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: refreshed ? [] : [ssh], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: { ...ssh, notes: 'Original' } } }),
      'vault.getSshKeyDetails': async () => ({
        ok: true,
        data: { sshKey: { publicKey: 'ssh-ed25519 PUBLIC', keyFingerprint: 'SHA256:ssh', hasPrivateKey: true } },
      }),
      'vault.getSyncStatus': async () => ({
        ok: true,
        data: { identity: 'account-a', lastSuccessfulSyncAt: successfulAt, dirty: false, syncing: false },
      }),
    }));
    app.navigate({ name: 'editor', mode: 'edit', cipherId: ssh.id });
    await settle(app);
    const editor = view<HTMLElement & { updateComplete: Promise<unknown> }>(app, 'vw-ssh-key-editor');
    const name = editor.shadowRoot!.querySelector<HTMLInputElement>('[data-name]')!;
    name.value = 'Unsaved deploy key';
    name.dispatchEvent(new Event('input'));
    const privateKey = editor.shadowRoot!.querySelector<HTMLTextAreaElement>('[data-private-key]')!;
    privateKey.value = 'PRIVATE-UNSAVED';
    privateKey.dispatchEvent(new Event('input'));
    await editor.updateComplete;

    refreshed = true;
    successfulAt = 200;
    emitVaultSyncSuccess(vaultSyncStorageListener(), 'account-a', 100, 200);
    await settle(app);
    await settle(app);

    expect(app.items).toEqual([]);
    expect(view(app, 'vw-ssh-key-editor')).toBe(editor);
    expect(editor.shadowRoot!.querySelector<HTMLInputElement>('[data-name]')!.value).toBe('Unsaved deploy key');
    expect(editor.shadowRoot!.querySelector<HTMLTextAreaElement>('[data-private-key]')!.value).toBe('PRIVATE-UNSAVED');
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
    app.navigate({ name: 'detail', cipherId: 'c1' });
    await app.updateComplete;
    view(app, 'vw-item-detail').dispatchEvent(new CustomEvent('vw-item-fill', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
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
  it('refreshes scheduler status when syncing from the tools menu', async () => {
    const sync = vi.fn(async () => ({ ok: true as const, data: { items: [login()], folders: [], collections: [], orgPermissions: [] } }));
    const getSyncStatus = vi.fn(async () => ({ ok: true as const, data: { lastSuccessfulSyncAt: 321, dirty: false, syncing: false } }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'vault.sync': sync, 'vault.getSyncStatus': getSyncStatus }));
    await (app as unknown as { handleToolAction(d: ToolActionDetail): Promise<void> }).handleToolAction({ action: 'sync' });
    await settle(app);
    expect(sync).toHaveBeenCalled();
    expect(getSyncStatus).toHaveBeenCalledTimes(2);
    expect(app.lastSuccessfulSyncAt).toBe(321);
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
    const scheduleClear = vi.fn<ReqHandler<'clipboard.scheduleClear'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({ ...UNLOCKED, 'clipboard.scheduleClear': scheduleClear }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', { detail: { action: 'generator' }, bubbles: true, composed: true }));
    await settle(app);
    view(app, 'vw-generator-view').dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'gen-pass', label: 'Password' }, bubbles: true, composed: true }));
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('gen-pass');
    expect(scheduleClear).toHaveBeenCalledWith({ type: 'clipboard.scheduleClear', value: 'gen-pass' });
    expect(app.toastMessage).toBe('');
  });

  it('does not claim ownership when the clipboard write fails', async () => {
    const scheduleClear = vi.fn<ReqHandler<'clipboard.scheduleClear'>>(async () => ({ ok: true, data: null }));
    const getField = vi.fn(async (): Promise<Res> => ({
      ok: true,
      data: { value: 'not-copied', clientEventAckId: 'failed-copy-ack' },
    } as Res));
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn(async () => { throw new Error('denied'); }) },
      configurable: true,
    });
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getField': getField,
      'clipboard.scheduleClear': scheduleClear,
      'clientEvent.ack': acknowledge,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-toggle', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-secret-request', {
      detail: { kind: 'field', field: 'password', label: 'Password' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(scheduleClear).not.toHaveBeenCalled();
    expect(acknowledge).not.toHaveBeenCalled();
    expect(app.detailStatus).toEqual(expect.objectContaining({ tone: 'danger' }));
  });

  it('acknowledges only password, Hidden, and card-code copies and suppresses duplicate ids', async () => {
    const loginItem = login({ hasTotp: true });
    const cardItem = login({ id: 'card-copy', name: 'Card', type: 3, uris: [] });
    const getDetail = vi.fn(async (request: Extract<Req, { type: 'vault.getCipherDetail' }>) => ({
      ok: true as const,
      data: {
        cipher: request.id === cardItem.id
          ? { ...cardItem, card: { brand: 'Visa' } }
          : { ...loginItem, fields: [{ type: 1 as const, name: 'Recovery' }] },
      },
    }));
    const getField = vi.fn(async (request: Extract<Req, { type: 'vault.getField' }>): Promise<Res> => ({
      ok: true,
      data: {
        value: `copied-${request.field}`,
        clientEventAckId: request.field === 'password' ? 'copy-password-once' : `copy-${request.field}`,
      },
    } as Res));
    const getCustomField = vi.fn(async (): Promise<Res> => ({
      ok: true,
      data: { value: 'copied-hidden', clientEventAckId: 'copy-hidden' },
    } as Res));
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({
        ok: true,
        data: { items: [loginItem, cardItem], folders: [], collections: [], orgPermissions: [] },
      }),
      'vault.getCipherDetail': getDetail,
      'vault.getField': getField,
      'vault.getCustomField': getCustomField,
      'vault.getTotp': async () => ({ ok: true, data: { totp: { code: '123456', period: 30, remaining: 20 } } }),
      'clientEvent.ack': acknowledge,
    }));

    app.navigate({ name: 'detail', cipherId: loginItem.id });
    await settle(app);
    let detail = view<HTMLElement>(app, 'vw-item-detail');
    detail.dispatchEvent(new CustomEvent('vw-copy', {
      detail: { value: 'me@x.dev', label: 'Username' }, bubbles: true, composed: true,
    }));
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-copy-password]')!.click();
    await settle(app);
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-copy-password]')!.click();
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-cf-copy]')!.click();
    await settle(app);
    detail.dispatchEvent(new CustomEvent('vw-copy', {
      detail: { value: '123456', label: 'Authenticator key' }, bubbles: true, composed: true,
    }));
    await settle(app);

    app.navigate({ name: 'detail', cipherId: cardItem.id });
    await settle(app);
    detail = view<HTMLElement>(app, 'vw-item-detail');
    for (const field of ['card.number', 'card.code'] as const) {
      const reveal = detail.shadowRoot!.querySelector<HTMLButtonElement>(`[data-reveal="${field}"]`)!;
      reveal.closest('[data-secret-row]')!.querySelectorAll<HTMLButtonElement>('button')[1]!.click();
      await settle(app);
    }

    expect(acknowledge.mock.calls.map(([request]) => request)).toEqual([
      { type: 'clientEvent.ack', ackId: 'copy-password-once' },
      { type: 'clientEvent.ack', ackId: 'copy-hidden' },
      { type: 'clientEvent.ack', ackId: 'copy-card.code' },
    ]);
    expect(getField.mock.calls.map(([request]) => request)).toEqual([
      { type: 'vault.getField', id: 'c1', field: 'password', clientEventPurpose: 'copy' },
      { type: 'vault.getField', id: 'c1', field: 'password', clientEventPurpose: 'copy' },
      { type: 'vault.getField', id: 'card-copy', field: 'card.number' },
      { type: 'vault.getField', id: 'card-copy', field: 'card.code', clientEventPurpose: 'copy' },
    ]);
    expect(getCustomField).toHaveBeenCalledWith({
      type: 'vault.getCustomField', id: 'c1', index: 0, clientEventPurpose: 'copy',
    });
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('copied-card.number');
  });

  it('raises the copy toast when copying a displayed detail value', async () => {
    const app = await mountApp(fakeRequest(UNLOCKED));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'shown', label: 'Username' }, bubbles: true, composed: true }));
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('shown');
    expect(app.toastMessage).not.toBe('');
  });

  it('reports an auto-clear scheduling failure without claiming the clipboard write failed', async () => {
    const acknowledge = vi.fn<ReqHandler<'clientEvent.ack'>>(async () => ({ ok: true, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getField': async () => ({
        ok: true,
        data: { value: 'shown', clientEventAckId: 'copy-without-clear' },
      } as Res),
      'clipboard.scheduleClear': async () => ({ ok: false, error: { code: 'error', message: 'alarm unavailable' } }),
      'clientEvent.ack': acknowledge,
    }));
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-item-toggle', {
      detail: { cipherId: 'c1' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-vault-view').dispatchEvent(new CustomEvent('vw-secret-request', {
      detail: { kind: 'field', field: 'password', label: 'Password' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('shown');
    expect(acknowledge).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: 'copy-without-clear' });
    expect(app.detailStatus).toEqual(expect.objectContaining({ tone: 'warning' }));
    expect(app.toastMessage).toContain('无法安排自动清除');
  });

  it('does not let an older clipboard promise overwrite a newer Send result', async () => {
    let releaseFirst: (() => void) | undefined;
    const writeText = vi.fn()
      .mockImplementationOnce(() => new Promise<void>((resolve) => { releaseFirst = resolve; }))
      .mockResolvedValueOnce(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const created = { id: 's1', accessId: 'a', type: 0 as const, name: 'x', hidden: false, hideEmail: false, url: 'https://new', deletionDate: '2026-08-01T00:00:00Z', accessCount: 0, disabled: false, passwordProtected: false };
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

  it('shows a saved-withheld warning without retrying a committed Send mutation', async () => {
    const createText = vi.fn(async () => ({
      ok: false as const,
      error: {
        code: 'committed_unsynced' as const,
        message: 'The Send was saved, but its secret result was withheld.',
      },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'sends.list': async () => ({ ok: true, data: { sends: [] } }),
      'sends.createText': createText,
    }));
    view(app, 'vw-tools-menu').dispatchEvent(new CustomEvent('vw-tool-action', {
      detail: { action: 'sends' }, bubbles: true, composed: true,
    }));
    await settle(app);
    view(app, 'vw-sends-view').dispatchEvent(new CustomEvent('vw-send-create', {
      detail: { kind: 'text', input: { name: 'x', text: 'secret', deletionDays: 7 } },
      bubbles: true,
      composed: true,
    }));
    await settle(app);

    expect(createText).toHaveBeenCalledOnce();
    expect(app.toolStatus).toEqual(expect.objectContaining({ tone: 'warning' }));
    expect(app.toolStatus?.message).toContain('已保存');
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
          return { ok: true, data: { outcome: { status: 'ready', suggestions: [{ kind: 'login', id: 'STALE', name: 'Old', matchedUri: 'https://old.dev', matchType: 0, favorite: false }] } } };
        }
        return { ok: true, data: { outcome: { status: 'ready', suggestions: [{ kind: 'login', id: 'FRESH', name: 'New', matchedUri: 'https://new.dev', matchType: 0, favorite: false }] } } };
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

  it('ignores a suggestions response from a previous workspace generation', async () => {
    let release!: () => void;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => {
        await new Promise<void>((resolve) => { release = resolve; });
        return { ok: true, data: { outcome: { status: 'ready', suggestions: [{ kind: 'login', id: 'STALE', name: 'Old', matchedUri: 'https://old.dev', matchType: 0, favorite: false }] } } };
      },
    }), fakeBrowser());
    (app as unknown as { resetVaultState(): void }).resetVaultState();
    release();
    await settle(app);
    expect(app.suggestionsState.status).not.toBe('ready');
  });

  it('ignores a fill result from a previous workspace generation', async () => {
    let release!: () => void;
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'autofill.getTabSuggestions': async () => ({ ok: true, data: { outcome: { status: 'ready', suggestions: [] } } }),
      'autofill.fillTabSuggestion': async () => {
        await new Promise<void>((resolve) => { release = resolve; });
        return { ok: true, data: { outcome: { status: 'filled' } } };
      },
    }), fakeBrowser());
    const pending = (app as unknown as {
      handleSuggestionFill(detail: {
        cipherId: string;
        target: { kind: 'login'; frameId: number; formId: string; documentId: string; runtimeIncarnation: string; generation: number; customPlanDigest: string };
      }): Promise<void>;
    }).handleSuggestionFill({
      cipherId: 'c1',
      target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-1', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 1, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
    });
    await flushAsync();
    (app as unknown as { resetVaultState(): void }).resetVaultState();
    release();
    await pending;
    await app.updateComplete;
    expect(app.fillResult).toEqual({});
    expect(app.toastMessage).toBe('');
  });
});

describe('vw-popup-app SSH key orchestration', () => {
  function sshItem(id = 'ssh-1', overrides: Partial<KnownCipherSummary> = {}): KnownCipherSummary {
    return { id, type: 5, name: `SSH ${id}`, uris: [], loginUris: [], favorite: false, ...overrides };
  }

  function sshListing(items: KnownCipherSummary[]) {
    return { items, folders: [], collections: [], orgPermissions: [], personalCreationAllowed: true };
  }

  it('shows an actionable type 5 choice only after the capability probe succeeds', async () => {
    const available = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
    }));
    view(available, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(available);
    expect(view(available, 'vw-type-picker').shadowRoot?.querySelector('[data-type="5"]')).not.toBeNull();

    const unavailable = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: false } }),
    }));
    view(unavailable, 'vw-sync-bar').dispatchEvent(new CustomEvent('vw-add', { bubbles: true, composed: true }));
    await settle(unavailable);
    expect(view(unavailable, 'vw-type-picker').shadowRoot?.querySelector('[data-type="5"]')).toBeNull();
  });

  it('uses dedicated generate and import commands and never a generic cipher create', async () => {
    const generated = vi.fn(async () => ({ ok: true as const, data: sshListing([sshItem('generated')]) }));
    const generic = vi.fn(async () => ({ ok: true as const, data: null }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.createGeneratedSshKey': generated,
      'vault.createCipher': generic,
    }));
    app.navigate({ name: 'editor', mode: 'create', cipherType: 5 });
    await settle(app);
    view(app, 'vw-ssh-key-editor').dispatchEvent(new CustomEvent('vw-ssh-create-generate', {
      detail: {
        metadata: { name: 'Generated', notes: '', favorite: false, reprompt: false, folderId: null, fields: [] },
        target: { kind: 'personal' },
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(generated).toHaveBeenCalledWith(expect.objectContaining({ type: 'vault.createGeneratedSshKey' }));
    expect(generic).not.toHaveBeenCalled();

    const imported = vi.fn(async () => ({ ok: false as const, error: { code: 'error' as const, message: 'invalid key' } }));
    app.navigate({ name: 'editor', mode: 'create', cipherType: 5 });
    app.request = fakeRequest({
      ...UNLOCKED,
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.importSshKey': imported,
    });
    await app.updateComplete;
    view(app, 'vw-ssh-key-editor').dispatchEvent(new CustomEvent('vw-ssh-create-import', {
      detail: {
        metadata: { name: 'Imported', notes: '', favorite: false, reprompt: false, folderId: null, fields: [] },
        privateKey: 'PRIVATE',
        target: { kind: 'personal' },
      },
      bubbles: true,
      composed: true,
    }));
    await settle(app);
    expect(imported).toHaveBeenCalledWith(expect.objectContaining({ type: 'vault.importSshKey', privateKey: 'PRIVATE' }));
    expect(app.editorStatus).toEqual({ message: 'invalid key', tone: 'danger' });
  });

  it('loads public SSH details without private material and reveals/copies private only explicitly', async () => {
    const item = sshItem();
    const reveal = vi.fn(async () => ({ ok: true as const, data: { privateKey: 'PRIVATE-SSH' } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: sshListing([item]) }),
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: { ...item, notes: 'Deploy only' } } }),
      'vault.getSshKeyDetails': async () => ({ ok: true, data: { sshKey: { publicKey: 'ssh-ed25519 PUBLIC', keyFingerprint: 'SHA256:ssh', hasPrivateKey: true } } }),
      'vault.revealSshPrivateKey': reveal,
    }));
    app.navigate({ name: 'detail', cipherId: item.id });
    await settle(app);
    const detail = view(app, 'vw-item-detail');
    expect(detail.shadowRoot?.textContent).toContain('ssh-ed25519 PUBLIC');
    expect(detail.shadowRoot?.textContent).toContain('SHA256:ssh');
    expect(detail.shadowRoot?.textContent).not.toContain('PRIVATE-SSH');
    expect(reveal).not.toHaveBeenCalled();

    detail.shadowRoot!.querySelector<HTMLButtonElement>('[aria-label="复制 公钥"]')!.click();
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('ssh-ed25519 PUBLIC');
    detail.shadowRoot!.querySelector<HTMLButtonElement>('[aria-label="复制 指纹"]')!.click();
    await settle(app);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('SHA256:ssh');

    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-copy-ssh-private]')!.click();
    await settle(app);
    expect(reveal).toHaveBeenCalledTimes(1);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('PRIVATE-SSH');
    expect(detail.shadowRoot?.textContent).not.toContain('PRIVATE-SSH');

    detail.shadowRoot!.querySelector<HTMLButtonElement>('[data-reveal-ssh-private]')!.click();
    await settle(app);
    expect(detail.shadowRoot?.textContent).toContain('PRIVATE-SSH');
    app.navigate({ name: 'vault', scope: 'all' });
    await app.updateComplete;
    expect(app.shadowRoot?.textContent).not.toContain('PRIVATE-SSH');
  });

  it('gates both generic and public SSH details behind reprompt and suppresses stale A to B to A', async () => {
    const a = sshItem('a', { reprompt: true });
    const b = sshItem('b');
    const staleA = deferred<Res>();
    let aCalls = 0;
    const getSsh = vi.fn((request: Extract<Req, { type: 'vault.getSshKeyDetails' }>): Promise<Res> => {
      if (request.id === 'a' && ++aCalls === 1) return staleA.promise;
      return Promise.resolve({
        ok: true,
        data: { sshKey: { publicKey: `PUBLIC-${request.id}-${aCalls}`, keyFingerprint: `FP-${request.id}`, hasPrivateKey: true } },
      });
    });
    const getDetail = vi.fn(async (request: Extract<Req, { type: 'vault.getCipherDetail' }>) => ({
      ok: true as const,
      data: { cipher: request.id === 'a' ? a : b },
    }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: sshListing([a, b]) }),
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.getCipherDetail': getDetail,
      'vault.getSshKeyDetails': getSsh,
      'auth.verifyMasterPassword': async () => ({ ok: true, data: { verified: true } }),
    }));
    app.navigate({ name: 'detail', cipherId: 'a' });
    await app.updateComplete;
    expect(getDetail).not.toHaveBeenCalled();
    expect(getSsh).not.toHaveBeenCalled();
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'proof' }, bubbles: true, composed: true,
    }));
    await flushAsync();
    expect(getSsh).toHaveBeenCalledWith({ type: 'vault.getSshKeyDetails', id: 'a', masterPassword: 'proof' });

    app.navigate({ name: 'detail', cipherId: 'b' });
    await settle(app);
    app.navigate({ name: 'detail', cipherId: 'a' });
    await app.updateComplete;
    view(app, 'vw-reprompt-gate').dispatchEvent(new CustomEvent('vw-reprompt-submit', {
      detail: { password: 'new-proof' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(view(app, 'vw-item-detail').shadowRoot?.textContent).toContain('PUBLIC-a-2');
    staleA.resolve({ ok: true, data: { sshKey: { publicKey: 'STALE-A', keyFingerprint: 'STALE', hasPrivateKey: true } } });
    await settle(app);
    expect(view(app, 'vw-item-detail').shadowRoot?.textContent).not.toContain('STALE-A');
  });

  it('edits metadata and replaces key material through separate dedicated commands', async () => {
    const item = sshItem();
    const update = vi.fn(async () => ({ ok: false as const, error: { code: 'error' as const, message: 'metadata rejected' } }));
    const replace = vi.fn(async () => ({ ok: false as const, error: { code: 'error' as const, message: 'replacement rejected' } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: sshListing([item]) }),
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: { ...item, notes: 'Metadata only', fields: [] } } }),
      'vault.getSshKeyDetails': async () => ({ ok: true, data: { sshKey: { publicKey: 'PUBLIC', keyFingerprint: 'FP', hasPrivateKey: true } } }),
      'vault.updateSshKeyMetadata': update,
      'vault.replaceSshKey': replace,
    }));
    app.navigate({ name: 'editor', mode: 'edit', cipherId: item.id });
    await settle(app);
    const editor = view(app, 'vw-ssh-key-editor');
    const metadata = { name: 'Renamed', notes: '', favorite: true, reprompt: false, folderId: null, fields: [] };
    editor.dispatchEvent(new CustomEvent('vw-ssh-update-metadata', {
      detail: { cipherId: item.id, metadata }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(update).toHaveBeenCalledWith({ type: 'vault.updateSshKeyMetadata', id: item.id, metadata });
    expect(JSON.stringify(update.mock.calls[0])).not.toContain('privateKey');
    expect(app.editorStatus).toEqual({ message: 'metadata rejected', tone: 'danger' });

    editor.dispatchEvent(new CustomEvent('vw-ssh-replace-key', {
      detail: { cipherId: item.id, privateKey: 'PRIVATE-REPLACEMENT' }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(replace).toHaveBeenCalledWith({ type: 'vault.replaceSshKey', id: item.id, privateKey: 'PRIVATE-REPLACEMENT' });
    expect(app.editorStatus).toEqual({ message: 'replacement rejected', tone: 'danger' });
  });

  it('fails closed instead of editing a type 5 item with a linked custom field', async () => {
    const item = sshItem();
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: sshListing([item]) }),
      'vault.getSshKeyWriteAvailability': async () => ({ ok: true, data: { available: true } }),
      'vault.getCipherDetail': async () => ({ ok: true, data: { cipher: { ...item, fields: [{ type: 3, name: 'Linked', linkedId: 100 }] } } }),
      'vault.getSshKeyDetails': async () => ({ ok: true, data: { sshKey: { publicKey: 'PUBLIC', keyFingerprint: 'FP', hasPrivateKey: true } } }),
    }));
    app.navigate({ name: 'editor', mode: 'edit', cipherId: item.id });
    await settle(app);
    expect(app.editorStatus?.message).toContain('关联字段');
    expect(app.shadowRoot?.querySelector('vw-ssh-key-editor')).toBeNull();
  });
});

describe('vw-popup-app website passkey ceremony route', () => {
  const CEREMONY_ID = '11111111-1111-4111-8111-111111111111';

  function approval(overrides: Record<string, unknown> = {}) {
    return {
      ceremonyId: CEREMONY_ID,
      kind: 'get',
      origin: 'https://login.example.test',
      rpId: 'example.test',
      state: 'awaiting',
      candidates: [{ id: 'credential-secret-id', name: 'Work', username: 'alice@example.test' }],
      challenge: 'challenge-must-not-survive',
      ...overrides,
    };
  }

  function approvalResponse(overrides: Record<string, unknown> = {}): Res {
    return { ok: true, data: { approval: approval(overrides) as never } };
  }

  async function mountCeremony(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>) {
    window.history.replaceState(null, '', `/ui/popup/popup.html?websitePasskey=${CEREMONY_ID}`);
    const app = await mountApp(fakeRequest(handlers));
    for (let attempt = 0; attempt < 8 && !app.websitePasskeyModel; attempt += 1) await settle(app);
    return app;
  }

  it('intercepts the exact ceremony query before every ordinary popup bootstrap request', async () => {
    const getState = vi.fn(async () => ({ ok: true as const, data: { state: 'unlocked' as const } }));
    const popupOpened = vi.fn(async () => ({ ok: true as const, data: null }));
    const listItems = vi.fn(async () => ({ ok: true as const, data: { items: [], folders: [], collections: [], orgPermissions: [] } }));
    const getApproval = vi.fn(async () => approvalResponse());
    const app = await mountCeremony({
      'auth.getState': getState,
      'vault.popupOpened': popupOpened,
      'vault.listItems': listItems,
      'websitePasskey.getApproval': getApproval,
    });

    expect(app.route).toEqual({ name: 'websitePasskey' });
    expect(getApproval).toHaveBeenCalledWith({ type: 'websitePasskey.getApproval', ceremonyId: CEREMONY_ID });
    expect(getState).not.toHaveBeenCalled();
    expect(popupOpened).not.toHaveBeenCalled();
    expect(listItems).not.toHaveBeenCalled();
    expect(app.shadowRoot?.querySelector('vw-popup-header')).toBeNull();
    expect(app.shadowRoot?.querySelector('vw-vault-view')).toBeNull();
    const passkey = view(app, 'vw-website-passkey-view');
    const markup = `${app.shadowRoot!.innerHTML}\n${passkey.shadowRoot!.innerHTML}`;
    expect(markup).not.toContain(CEREMONY_ID);
    expect(markup).not.toContain('credential-secret-id');
    expect(markup).not.toContain('challenge-must-not-survive');
    expect(JSON.stringify(app.websitePasskeyModel)).not.toContain('challenge-must-not-survive');
  });

  it('fails closed for a non-exact ceremony query without falling through to auth', async () => {
    window.history.replaceState(null, '', `/ui/popup/popup.html?websitePasskey=${CEREMONY_ID}&extra=1`);
    const getState = vi.fn(async () => ({ ok: true as const, data: { state: 'unlocked' as const } }));
    const getApproval = vi.fn(async () => approvalResponse());
    const app = await mountApp(fakeRequest({ 'auth.getState': getState, 'websitePasskey.getApproval': getApproval }));
    await settle(app);
    expect(app.route).toEqual({ name: 'websitePasskey' });
    expect(getState).not.toHaveBeenCalled();
    expect(getApproval).not.toHaveBeenCalled();
    const status = view(app, 'vw-website-passkey-view').shadowRoot!.querySelector<HTMLElement & { message: string }>('vw-status-message')!;
    expect(status.message).toContain('无效');
  });

  it('claims approval once, exposes execution cancel, and never falls back for an executing create', async () => {
    const approve = deferred<Res>();
    const approveRequest = vi.fn(() => approve.promise);
    const cancel = vi.fn(async () => ({ ok: true as const, data: { outcome: 'failed' as const } }));
    const fallbackOnce = vi.fn(async () => ({ ok: true as const, data: { outcome: 'fallback' as const } }));
    const fallbackAlways = vi.fn(async () => ({ ok: true as const, data: { outcome: 'fallback' as const } }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const app = await mountCeremony({
      'websitePasskey.getApproval': async () => approvalResponse({ kind: 'create', candidates: undefined, targets: [{ id: 'cipher-id', name: 'Login' }] }),
      'websitePasskey.approve': approveRequest,
      'websitePasskey.cancel': cancel,
      'websitePasskey.fallbackOnce': fallbackOnce,
      'websitePasskey.fallbackAlways': fallbackAlways,
    });
    const passkey = view(app, 'vw-website-passkey-view');
    const first = passkey.shadowRoot!.querySelector<HTMLButtonElement>('[data-primary-action]')!;
    first.click();
    first.click();
    await app.updateComplete;
    expect(approveRequest).toHaveBeenCalledTimes(1);
    expect(app.websitePasskeyModel?.state).toBe('executing');
    passkey.shadowRoot!.querySelector<HTMLButtonElement>('[data-cancel]')!.click();
    await settle(app);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(fallbackOnce).not.toHaveBeenCalled();
    expect(fallbackAlways).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalled();
    approve.resolve({ ok: true, data: { outcome: 'uncertain' } });
    await settle(app);
    close.mockRestore();
  });

  it.each([
    ['once', 'vw-website-passkey-fallback-once', 'websitePasskey.fallbackOnce'],
    ['always', 'vw-website-passkey-fallback-always', 'websitePasskey.fallbackAlways'],
  ] as const)('routes browser fallback %s through its dedicated command', async (_label, eventName, requestType) => {
    const fallback = vi.fn(async () => ({ ok: true as const, data: { outcome: 'fallback' as const } }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const app = await mountCeremony({
      'websitePasskey.getApproval': async () => approvalResponse(),
      [requestType]: fallback,
    });
    view(app, 'vw-website-passkey-view').dispatchEvent(new CustomEvent(eventName, {
      detail: { ceremonyId: CEREMONY_ID }, bubbles: true, composed: true,
    }));
    await settle(app);
    expect(fallback).toHaveBeenCalledWith({ type: requestType, ceremonyId: CEREMONY_ID });
    expect(close).toHaveBeenCalled();
    close.mockRestore();
  });

  it('sends one safe cancellation across pagehide and disconnect, but not for an expired model', async () => {
    const cancel = vi.fn(async () => ({ ok: true as const, data: { outcome: 'failed' as const } }));
    const app = await mountCeremony({
      'websitePasskey.getApproval': async () => approvalResponse(),
      'websitePasskey.cancel': cancel,
    });
    window.dispatchEvent(new Event('pagehide'));
    app.remove();
    await flushAsync();
    expect(cancel).toHaveBeenCalledTimes(1);

    const expired = await mountCeremony({
      'websitePasskey.getApproval': async () => ({ ok: true, data: { approval: null } }),
      'websitePasskey.cancel': cancel,
    });
    expired.remove();
    await flushAsync();
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(expired.shadowRoot?.querySelector('[data-primary-action]')).toBeNull();
  });

  it('keeps the newest approval across an A to B to A load sequence', async () => {
    const CEREMONY_B = '22222222-2222-4222-8222-222222222222';
    const stale = deferred<Res>();
    let call = 0;
    const app = await mountCeremony({
      'websitePasskey.getApproval': (request) => {
        call += 1;
        if (call === 1) return stale.promise;
        return Promise.resolve(approvalResponse({
          ceremonyId: request.ceremonyId,
          candidates: [{ id: `${request.ceremonyId}-fresh`, name: request.ceremonyId === CEREMONY_ID ? 'Fresh A' : 'Current B' }],
        }));
      },
    });
    const internals = app as unknown as {
      websitePasskeyQuery: { kind: 'ceremony'; ceremonyId: string };
      loadWebsitePasskeyApproval(id: string): Promise<void>;
    };
    internals.websitePasskeyQuery = { kind: 'ceremony', ceremonyId: CEREMONY_B };
    void internals.loadWebsitePasskeyApproval(CEREMONY_B);
    await settle(app);
    expect(view(app, 'vw-website-passkey-view').shadowRoot?.textContent).toContain('Current B');
    internals.websitePasskeyQuery = { kind: 'ceremony', ceremonyId: CEREMONY_ID };
    void internals.loadWebsitePasskeyApproval(CEREMONY_ID);
    await settle(app);
    expect(view(app, 'vw-website-passkey-view').shadowRoot?.textContent).toContain('Fresh A');
    stale.resolve(approvalResponse({ candidates: [{ id: 'stale-id', name: 'Stale' }] }));
    await settle(app);
    expect(view(app, 'vw-website-passkey-view').shadowRoot?.textContent).toContain('Fresh A');
    expect(view(app, 'vw-website-passkey-view').shadowRoot?.textContent).not.toContain('Stale');
  });
});

describe('vw-popup-app locked website passkey continuation', () => {
  const CONTINUATION_ID = '33333333-3333-4333-8333-333333333333';

  function openLockedContinuation(): void {
    window.history.replaceState(
      null,
      '',
      `/ui/popup/popup.html?websitePasskeyUnlock=${CONTINUATION_ID}`,
    );
  }

  function lockedStatus() {
    return {
      ok: true as const,
      data: {
        status: 'unlock_required' as const,
        continuationId: CONTINUATION_ID,
        expiresAt: Date.now() + 30_000,
      },
    };
  }

  it('claims the exact query and resumes only after master-password unlock succeeds', async () => {
    openLockedContinuation();
    const status = vi.fn(async () => lockedStatus());
    const resume = vi.fn(async () => ({ ok: true as const, data: { status: 'started' as const } }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' as const } }),
      'websitePasskey.lockedStatus': status,
      'auth.unlock': async () => ({ ok: true, data: { state: 'unlocked' as const } }),
      'websitePasskey.resumeLocked': resume,
    }));
    await vi.waitFor(() => expect(app.route.name).toBe('unlock'));
    expect(status).toHaveBeenCalledWith({
      type: 'websitePasskey.lockedStatus',
      continuationId: CONTINUATION_ID,
    });
    expect(app.route).toMatchObject({
      name: 'unlock',
      notice: expect.stringMatching(/通行密钥/u),
    });

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-unlock-submit', {
      detail: { masterPassword: 'password' },
    }));
    await vi.waitFor(() => expect(resume).toHaveBeenCalledWith({
      type: 'websitePasskey.resumeLocked',
      continuationId: CONTINUATION_ID,
    }));
    expect(close).toHaveBeenCalled();
    close.mockRestore();
  });

  it('resumes the same continuation after PIN unlock without entering the vault UI', async () => {
    openLockedContinuation();
    const resume = vi.fn(async () => ({ ok: true as const, data: { status: 'started' as const } }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' as const } }),
      'websitePasskey.lockedStatus': async () => lockedStatus(),
      'auth.unlockWithPin': async () => ({ ok: true, data: { state: 'unlocked' as const } }),
      'websitePasskey.resumeLocked': resume,
    }));
    await vi.waitFor(() => expect(app.route.name).toBe('unlock'));

    view(app, 'vw-auth-views').dispatchEvent(new CustomEvent('vw-auth-pin-unlock-submit', {
      detail: { pin: '1234' },
    }));
    await vi.waitFor(() => expect(resume).toHaveBeenCalledOnce());
    expect(app.shadowRoot?.querySelector('vw-vault-view')).toBeNull();
    expect(close).toHaveBeenCalled();
    close.mockRestore();
  });

  it('cancels exactly once when the unlock popout closes before unlock', async () => {
    openLockedContinuation();
    const cancel = vi.fn(async () => ({ ok: true as const, data: { cancelled: true } }));
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'locked' as const } }),
      'websitePasskey.lockedStatus': async () => lockedStatus(),
      'websitePasskey.cancelLocked': cancel,
    }));
    await vi.waitFor(() => expect(app.route.name).toBe('unlock'));

    window.dispatchEvent(new Event('pagehide'));
    app.remove();
    await flushAsync();
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledWith({
      type: 'websitePasskey.cancelLocked',
      continuationId: CONTINUATION_ID,
    });
  });

  it('resumes a surviving continuation when the popup reloads after unlock', async () => {
    openLockedContinuation();
    const resume = vi.fn(async () => ({ ok: true as const, data: { status: 'started' as const } }));
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    await mountApp(fakeRequest({
      ...UNLOCKED,
      'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' as const } }),
      'websitePasskey.lockedStatus': async () => lockedStatus(),
      'websitePasskey.resumeLocked': resume,
    }));

    await vi.waitFor(() => expect(resume).toHaveBeenCalledOnce());
    expect(close).toHaveBeenCalled();
    close.mockRestore();
  });
});

describe('vw-popup-app context-menu create intent', () => {
  it('accepts only a background-owned intent and opens the concrete editor after vault data loads', async () => {
    const app = await mountApp(fakeRequest({
      ...UNLOCKED,
      'vault.listItems': async () => ({ ok: true, data: {
        items: [login()], folders: [], collections: [], orgPermissions: [],
        personalCreationAllowed: true,
      } }),
    }), fakeBrowser());
    await vi.waitFor(() => expect(app.route.name).toBe('vault'));
    const listener = contextMenuCreateMessageListener();
    const intent = {
      type: 'contextMenu.openCreateCipher',
      intentId: '11111111-1111-4111-8111-111111111111',
      cipherType: 1,
      loginUri: 'https://example.com/login?step=2',
    };

    expect(listener(intent, {
      id: 'extension-id',
      url: 'ui/popup/popup.html',
    })).toBeUndefined();
    expect(app.route.name).toBe('vault');
    await expect(listener(intent, {
      id: 'extension-id',
      url: 'background.js',
    })).resolves.toEqual({ accepted: true });
    await vi.waitFor(() => expect(app.route).toEqual({
      name: 'editor',
      mode: 'create',
      cipherType: 1,
    }));
    await app.updateComplete;
    const editor = view<HTMLElement & { context?: EditorContext }>(app, 'vw-cipher-editor');
    expect(editor.context?.createDefaults?.loginUri).toBe('https://example.com/login?step=2');
  });
});
