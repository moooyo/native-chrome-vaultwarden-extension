// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface FakePopover {
  element: HTMLElement;
  open: ReturnType<typeof vi.fn>;
  showStatus: ReturnType<typeof vi.fn>;
  showCandidates: ReturnType<typeof vi.fn>;
  showFilled: ReturnType<typeof vi.fn>;
  hide: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
  options: {
    kind?: 'login' | 'card' | 'identity';
    sidePanel?: boolean;
    onOpen(): void;
    onSelect(cipherId: string): void;
    onDismiss?(reason: 'escape' | 'tab'): void;
    beforeFocusRestore?(anchor: HTMLElement): () => void;
  };
}

interface FakeGeneratePanel {
  element: HTMLElement;
  update: ReturnType<typeof vi.fn>;
  showFilled: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
  options: { onUse(): void };
}

interface FakeSaveBar {
  remove: ReturnType<typeof vi.fn>;
  options: {
    message: string;
    actionLabel: string;
    onAction(): Promise<boolean>;
    onDismiss?(): void;
    successMessage?: string;
  };
}

interface FakeTotpPanel {
  element: HTMLElement;
  showCandidates: ReturnType<typeof vi.fn>;
  showFilled: ReturnType<typeof vi.fn>;
  showStatus: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
  update: ReturnType<typeof vi.fn>;
  options: {
    onSelect(candidateKey: string): void;
    onChooseOther(): void;
    onFill(): void;
    onCopy(): void;
    onUndo(): void;
  };
}

const popoverState = vi.hoisted(() => ({
  instances: [] as FakePopover[],
}));

const generatePanelState = vi.hoisted(() => ({
  instances: [] as FakeGeneratePanel[],
}));

const saveBarState = vi.hoisted(() => ({
  instances: [] as FakeSaveBar[],
}));

const totpPanelState = vi.hoisted(() => ({
  instances: [] as FakeTotpPanel[],
}));

const extensionContextState = vi.hoisted(() => ({ alive: true }));

vi.mock('webextension-polyfill', () => ({
  default: { runtime: { onMessage: { addListener: vi.fn() } } },
}));

vi.mock('../messaging/protocol.js', () => ({
  sendRequest: vi.fn(),
  isExtensionContextAlive: () => extensionContextState.alive,
}));

vi.mock('./fill.js', () => ({
  fillLoginForm: vi.fn(),
  setInputValue: vi.fn((input: HTMLInputElement | HTMLSelectElement, value: string) => { input.value = value; }),
  fillTotpCode: vi.fn((
    input: HTMLInputElement,
    value: string,
    revalidate: () => boolean = () => true,
  ) => {
    if (!revalidate()) return false;
    input.value = value;
    return revalidate();
  }),
  clearTotpCode: vi.fn((input: HTMLInputElement) => {
    input.value = '';
    return true;
  }),
}));

vi.mock('./generate-fill.js', () => ({
  createGeneratePanel: vi.fn((options: FakeGeneratePanel['options']) => {
    const element = document.createElement('div');
    document.documentElement.append(element);
    const panel: FakeGeneratePanel = {
      element,
      update: vi.fn(),
      showFilled: vi.fn(),
      remove: vi.fn(() => element.remove()),
      options,
    };
    generatePanelState.instances.push(panel);
    return panel;
  }),
}));

vi.mock('./save-bar.js', () => ({
  createSaveBar: vi.fn((options: FakeSaveBar['options']) => {
    const bar: FakeSaveBar = { remove: vi.fn(), options };
    saveBarState.instances.push(bar);
    return bar;
  }),
}));

vi.mock('./totp-fill.js', () => ({
  createTotpPanel: vi.fn((options: FakeTotpPanel['options']) => {
    const element = document.createElement('div');
    document.documentElement.append(element);
    const panel: FakeTotpPanel = {
      element,
      showCandidates: vi.fn(),
      showFilled: vi.fn(),
      showStatus: vi.fn(),
      remove: vi.fn(() => element.remove()),
      update: vi.fn(),
      options,
    };
    totpPanelState.instances.push(panel);
    return panel;
  }),
}));

vi.mock('./popover.js', () => ({
  createAutofillPopover: vi.fn((options: FakePopover['options']) => {
    const element = document.createElement('div');
    document.documentElement.append(element);
    const popover: FakePopover = {
      element,
      open: vi.fn(),
      showStatus: vi.fn(),
      showCandidates: vi.fn(),
      showFilled: vi.fn(),
      hide: vi.fn(),
      remove: vi.fn(),
      options,
    };
    popoverState.instances.push(popover);
    return popover;
  }),
}));

import { sendRequest, type AutofillClientConfig, type ResponseMessage } from '../messaging/protocol.js';
import { createGeneratorPolicySnapshot } from '../core/generator/enterprise-password-policy.js';
import { EMPTY_PASSWORD_GENERATOR_POLICY } from '../core/policy/password-generator-policy.js';
import { fillLoginForm, fillTotpCode, setInputValue } from './fill.js';
import {
  EMPTY_LOGIN_CUSTOM_PLAN,
  EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
} from '../core/vault/login-custom-fields.js';
import * as noticeModule from './notice.js';
import { createWebsitePasskeyConditionalUi } from './conditional-passkey-ui.js';
import {
  CONTEXT_TARGET_RESERVATION_TTL_MS,
  startAutofill,
  stopAutofill,
  handleContentCommand,
  handleFocusedFill,
  handleFrameAutofillMessage,
  openPickerFor,
  popoverRegistry,
  relayFido2FallbackMessage,
} from './autofill.js';

describe('FIDO2 fallback relay', () => {
  it('forwards only an exact trusted same-window result from the top-level vault page', async () => {
    const request = vi.fn(async () => ({ ok: true, data: null } as ResponseMessage));
    const event = {
      isTrusted: true,
      source: window,
      origin: window.location.origin,
      data: { command: 'webAuthnResult', data: '{"credential":true}', remember: true },
    } satisfies Pick<MessageEvent, 'data' | 'isTrusted' | 'origin' | 'source'>;

    expect(relayFido2FallbackMessage(event, window, request)).toBe(true);
    await Promise.resolve();
    expect(request).toHaveBeenCalledWith({
      type: 'auth.completeFido2',
      token: '{"credential":true}',
      remember: true,
    });
  });

  it.each([
    ['synthetic event', { isTrusted: false }],
    ['wrong source', { source: null }],
    ['wrong origin', { origin: 'https://evil.example' }],
    ['unknown field', { data: { command: 'webAuthnResult', data: '{}', remember: false, extra: true } }],
    ['wrong command', { data: { command: 'other', data: '{}', remember: false } }],
    ['invalid remember', { data: { command: 'webAuthnResult', data: '{}', remember: 'yes' } }],
    ['oversized token', { data: { command: 'webAuthnResult', data: 'x'.repeat(32 * 1_024 + 1), remember: false } }],
  ])('rejects %s', (_label, override) => {
    const request = vi.fn(async () => ({ ok: true, data: null } as ResponseMessage));
    const event = {
      isTrusted: true,
      source: window,
      origin: window.location.origin,
      data: { command: 'webAuthnResult', data: '{}', remember: false },
      ...override,
    } as Pick<MessageEvent, 'data' | 'isTrusted' | 'origin' | 'source'>;

    expect(relayFido2FallbackMessage(event, window, request)).toBe(false);
    expect(request).not.toHaveBeenCalled();
  });

  it('rejects a result observed in a child frame', () => {
    const child = {
      top: {},
      location: { origin: 'https://vault.example' },
    } as unknown as Window;
    const request = vi.fn(async () => ({ ok: true, data: null } as ResponseMessage));

    expect(relayFido2FallbackMessage({
      isTrusted: true,
      source: child,
      origin: 'https://vault.example',
      data: { command: 'webAuthnResult', data: '{}', remember: false },
    }, child, request)).toBe(false);
    expect(request).not.toHaveBeenCalled();
  });
});

describe('autofill controller', () => {
  beforeEach(() => {
    stopAutofill();
    runtimeStartedForTest = false;
    extensionContextState.alive = true;
    document.querySelectorAll('[data-vw-popover-for]').forEach((node) => node.remove());
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    popoverState.instances.length = 0;
    generatePanelState.instances.length = 0;
    saveBarState.instances.length = 0;
    totpPanelState.instances.length = 0;
    vi.mocked(sendRequest).mockReset();
    mockRequests();
    vi.mocked(fillLoginForm).mockReset();
  });

  afterEach(() => {
    document.querySelectorAll('[data-vw-popover-for]').forEach((node) => node.remove());
  });

  it('requests candidates for the current frame URL when popover opens', async () => {
    mockRequests({ ok: true, data: [] });

    await startReady('https://example.com/login');
    vi.mocked(sendRequest).mockClear();
    popover().options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(nonConfigRequests()).toContainEqual({ type: 'autofill.findCandidates', purpose: 'login' });
  });

  it('opens the login side panel when a login field is focused (design 2c)', async () => {
    mockRequests({ ok: true, data: [] });

    await startReady('https://example.com/login');
    const current = popover();
    const emailInput = document.querySelector('input[type="email"]') as HTMLInputElement;
    trustedPageEvent(emailInput, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise(r => setTimeout(r, 0));

    expect(current.open).toHaveBeenCalled();
  });

  it('yields a login form surface to an active conditional Passkey picker without overlap', async () => {
    document.body.innerHTML = '<form><input type="email" autocomplete="username webauthn"><input type="password"></form>';
    await startReady('https://example.com/login');
    const ordinary = popover();
    const emailInput = document.querySelector('input[type="email"]') as HTMLInputElement;
    trustedPageEvent(emailInput, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(ordinary.open).toHaveBeenCalledOnce();

    const conditional = createWebsitePasskeyConditionalUi(document);
    conditional.activate({
      ceremonyId: '11111111-1111-4111-8111-111111111111',
      bridgeRequestId: '22222222-2222-4222-8222-222222222222',
      candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work' }],
    }, vi.fn());
    trustedPageEvent(emailInput, new PointerEvent('pointerdown', { bubbles: true, composed: true }));

    expect(popoverState.instances).toHaveLength(2);
    expect(ordinary.hide).toHaveBeenCalledOnce();
    ordinary.open.mockClear();
    trustedPageEvent(emailInput, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(ordinary.open).not.toHaveBeenCalled();
    conditional.dispose();
  });

  it('does not attach a generic login popover to an OTP-only form', async () => {
    document.body.innerHTML = '<form><input autocomplete="one-time-code"><button>Verify</button></form>';

    await startReady('https://example.com/login');

    expect(popoverState.instances).toHaveLength(0);
  });

  it('does not attach inline surfaces to data-bwignore login fields', async () => {
    document.body.innerHTML = `
      <form>
        <input type="email" data-bwignore>
        <input type="password" data-bwignore>
      </form>`;

    await startReady('https://example.com/login');

    expect(popoverState.instances).toHaveLength(0);
  });

  it('dismisses the login side panel on a pointer-down outside the field and panel', async () => {
    mockRequests({ ok: true, data: [] });

    await startReady('https://example.com/login');
    const current = popover();
    const emailInput = document.querySelector('input[type="email"]') as HTMLInputElement;
    trustedPageEvent(emailInput, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise(r => setTimeout(r, 0));

    const outside = document.createElement('button');
    document.body.append(outside);
    trustedPageEvent(outside, new MouseEvent('pointerdown', { bubbles: true, composed: true }));

    expect(current.hide).toHaveBeenCalled();
  });

  it('uses the current frame URL after same-document navigation', async () => {
    window.history.replaceState({}, '', '/login');
    mockRequests(
      { ok: true, data: [{
        id: '1',
        name: 'Test',
        username: 'user',
        matchedUri: `${window.location.origin}/other`,
        matchType: 3,
        favorite: false,
      }] },
      { ok: true, data: { intentId: 'login-intent' } },
      { ok: true, data: { login: { username: 'user', password: 'secret' } } },
    );

    await startReady();
    vi.mocked(sendRequest).mockClear();
    const current = popover();
    window.history.pushState({}, '', '/other');

    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));
    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(nonConfigRequests()).toEqual([
      { type: 'autofill.findCandidates', purpose: 'login' },
      { type: 'autofill.issueIntent', cipherId: '1', purpose: 'login' },
      { type: 'autofill.redeemLoginIntent', intentId: 'login-intent' },
    ]);
  });

  it('does not fill if the frame URL changes before credentials return', async () => {
    window.history.replaceState({}, '', '/login');
    let resolveCredentials: (value: ResponseMessage) => void = () => {};
    const credentialsResponse = new Promise<ResponseMessage>((resolve) => {
      resolveCredentials = resolve;
    });
    mockRequests(
      { ok: true, data: [{
        id: '1',
        name: 'Test',
        username: 'user',
        matchedUri: `${window.location.origin}/login`,
        matchType: 3,
        favorite: false,
      }] },
      { ok: true, data: { intentId: 'login-intent' } },
      credentialsResponse,
    );

    await startReady();
    vi.mocked(sendRequest).mockClear();
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));
    window.history.pushState({}, '', '/other');
    resolveCredentials({ ok: true, data: { login: { username: 'user', password: 'secret' } } });
    await new Promise(r => setTimeout(r, 0));

    expect(nonConfigRequests()).toEqual([
      { type: 'autofill.findCandidates', purpose: 'login' },
      { type: 'autofill.issueIntent', cipherId: '1', purpose: 'login' },
      { type: 'autofill.redeemLoginIntent', intentId: 'login-intent' },
    ]);
    expect(fillLoginForm).not.toHaveBeenCalled();
    expect(current.showStatus).toHaveBeenCalledWith('Page changed before autofill');
  });

  it('shows no matches when findCandidates returns an empty array', async () => {
    mockRequests({ ok: true, data: [] });

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showCandidates).toHaveBeenCalledWith([]);
    expect(current.showStatus).not.toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('ignores page-controlled detector ids containing selector special characters', async () => {
    mockRequests({ ok: true, data: [] });

    const formHtml = '<form><input id="pass" type="email"><input type="password" data-vw-autofill-id=\'test"[attr]"></form>';
    document.body.innerHTML = formHtml;

    await expect(startReady('https://example.com/login')).resolves.toBeUndefined();
  });

  it('ignores page-forged duplicate detector ids and keeps forms distinct', async () => {
    document.body.innerHTML = `
      <form><input type="email"><input type="password" data-vw-autofill-id="forged"></form>
      <form><input type="email"><input type="password" data-vw-autofill-id="forged"></form>`;
    await startReady('https://example.com/login');

    expect(popoverState.instances).toHaveLength(2);
    const secondEmail = document.querySelectorAll<HTMLInputElement>('input[type="email"]')[1]!;
    trustedPageEvent(secondEmail, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(popoverState.instances[0]!.open).not.toHaveBeenCalled();
    expect(popoverState.instances[1]!.open).toHaveBeenCalled();
  });

  it('shows status when findCandidates returns unexpected data shape', async () => {
    mockRequests({ ok: true, data: null });

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when findCandidates returns malformed candidate items', async () => {
    mockRequests(malformedOk([{ matchedUri: 'https://example.com' }]));

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when issueIntent returns unexpected data shape', async () => {
    mockRequests(
      {
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: 'https://example.com',
          matchType: 0,
          favorite: false,
        }],
      },
      { ok: true, data: null },
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when issueIntent returns array instead of object', async () => {
    mockRequests(
      {
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: 'https://example.com',
          matchType: 0,
          favorite: false,
        }],
      },
      { ok: true, data: [] },
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when redeemLoginIntent returns malformed login fields', async () => {
    mockRequests(
      {
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: 'https://example.com',
          matchType: 0,
          favorite: false,
        }],
      },
      { ok: true, data: { intentId: 'login-intent' } },
      malformedOk({ login: { username: 42, password: 'secret' } }),
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
    expect(fillLoginForm).not.toHaveBeenCalled();
  });

  it('rejects a login intent response that carries TOTP data', async () => {
    mockRequests(
      {
        ok: true,
        data: [{ id: '1', name: 'Test', matchedUri: 'https://example.com', matchType: 0, favorite: false }],
      },
      { ok: true, data: { intentId: 'login-intent' } },
      malformedOk({ login: { username: 'user', password: 'secret', totp: '123456' } }),
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));
    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
    expect(fillLoginForm).not.toHaveBeenCalled();
  });

  it('shows status when findCandidates returns non-array data', async () => {
    mockRequests(malformedOk({ username: 'foo' }));

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('fills only the username for a username-only step without reporting it unavailable', async () => {
    document.body.innerHTML = '<form><input type="email" autocomplete="username"><button>Next</button></form>';
    vi.mocked(fillLoginForm).mockReturnValue(true);
    mockRequests(
      {
        ok: true,
        data: [{ id: '1', name: 'Test', username: 'user', matchedUri: 'https://example.com', matchType: 0, favorite: false }],
      },
      { ok: true, data: { intentId: 'login-intent' } },
      { ok: true, data: { login: { username: 'user', password: 'secret' } } },
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));
    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    const filledForm = vi.mocked(fillLoginForm).mock.calls[0]?.[0];
    expect(filledForm?.passwordInput).toBeUndefined();
    expect(filledForm?.usernameInput?.type).toBe('email');
    expect(current.showStatus).not.toHaveBeenCalledWith('Form is no longer available');
    expect(current.showFilled).toHaveBeenCalled();
  });

  it('auto-dismisses the login panel roughly one second after a successful fill', async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(fillLoginForm).mockReturnValue(true);
      mockRequests(
        { ok: true, data: [{ id: '1', name: 'T', username: 'u', matchedUri: 'https://example.com', matchType: 0, favorite: false }] },
        { ok: true, data: { intentId: 'login-intent' } },
        { ok: true, data: { login: { username: 'u', password: 'p' } } },
      );

      await startReady('https://example.com/login');
      const current = popover();
      current.options.onOpen();
      await vi.advanceTimersByTimeAsync(0);
      current.options.onSelect('1');
      await vi.advanceTimersByTimeAsync(0);

      expect(current.showFilled).toHaveBeenCalled();
      expect(current.hide).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1000);
      expect(current.hide).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not release or fill TOTP data through a login intent', async () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"><input type="text" autocomplete="one-time-code" name="otp"></form>';
    vi.mocked(fillLoginForm).mockReturnValue(true);
    mockRequests(
      {
        ok: true,
        data: [{ id: '1', name: 'Test', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true }],
      },
      { ok: true, data: { intentId: 'login-intent' } },
      { ok: true, data: { login: { username: 'user', password: 'secret' } } },
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));
    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(nonConfigRequests()).toHaveLength(3);
    expect(sendRequest).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'autofill.issueIntent', purpose: 'totp' }));
    expect(vi.mocked(fillLoginForm).mock.calls[0]?.[1]).toEqual({ username: 'user', password: 'secret' });
    expect(current.showFilled).toHaveBeenCalled();
  });

  it('stages a username-only trusted submission for the next same-origin password step', async () => {
    document.body.innerHTML = '<form id="step"><input type="email" autocomplete="username" value="alice@example.com"><button>Next</button></form>';
    mockRequests({ ok: true, data: null });
    await startReady('https://example.com/login');
    vi.mocked(sendRequest).mockClear();

    trustedPageEvent(
      document.getElementById('step')!,
      new Event('submit', { bubbles: true, cancelable: true, composed: true }),
    );
    await Promise.resolve();

    expect(nonConfigRequests()).toEqual([{
      type: 'autofill.captureSubmission',
      username: 'alice@example.com',
    }]);
  });

  it('does not capture credentials until authoritative client config allows it', async () => {
    document.body.innerHTML = `<form id="login">
      <input type="email" value="alice@example.com">
      <input type="password" value="secret-password">
    </form>`;
    let resolveConfig!: (response: ResponseMessage) => void;
    const config = new Promise<ResponseMessage>((resolve) => { resolveConfig = resolve; });
    vi.mocked(sendRequest).mockImplementation((request) => {
      if (request.type === 'autofill.getClientConfig') return config;
      if (request.type === 'autofill.claimSavePrompt') {
        return Promise.resolve({ ok: true, data: { action: 'none' } });
      }
      if (request.type === 'autofill.captureSubmission') {
        return Promise.resolve({ ok: true, data: null });
      }
      return Promise.resolve({ ok: false, error: { code: 'error', message: 'unexpected request' } });
    });
    startAutofill('https://example.com/login');
    runtimeStartedForTest = true;

    trustedPageEvent(
      document.getElementById('login')!,
      new Event('submit', { bubbles: true, cancelable: true, composed: true }),
    );

    expect(vi.mocked(sendRequest).mock.calls.map(([request]) => request)).not.toContainEqual({
      type: 'autofill.captureSubmission',
      username: 'alice@example.com',
      password: 'secret-password',
      submission: { kind: 'formless' },
    });
    resolveConfig(ENABLED_CLIENT_CONFIG);
    await Promise.resolve();
    await Promise.resolve();

    trustedPageEvent(
      document.getElementById('login')!,
      new Event('submit', { bubbles: true, cancelable: true, composed: true }),
    );
    expect(vi.mocked(sendRequest).mock.calls.map(([request]) => request)).toContainEqual({
      type: 'autofill.captureSubmission',
      username: 'alice@example.com',
      password: 'secret-password',
      submission: { kind: 'formless' },
    });
  });

  it('fills an exact custom login target after an inline user selection', async () => {
    const ackId = '10000000-0000-4000-8000-000000000001';
    const totpCopyAckId = '20000000-0000-4000-8000-000000000001';
    document.body.innerHTML = '<form><input name="username"><input type="password"><input name="department"></form>';
    let issuedPlan: Extract<Parameters<typeof sendRequest>[0], { type: 'autofill.issueIntent'; purpose: 'login' }>['customPlan'] | undefined;
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return ENABLED_CLIENT_CONFIG;
      if (request.type === 'autofill.findCandidates') return { ok: true, data: [{
        id: 'c1', name: 'Example', matchedUri: 'https://example.com', matchType: 0, favorite: false,
      }] } as ResponseMessage;
      if (request.type === 'autofill.issueIntent' && request.purpose === 'login') {
        issuedPlan = request.customPlan;
        return { ok: true, data: { intentId: 'custom-intent' } };
      }
      if (request.type === 'autofill.redeemLoginIntent') {
        return { ok: true, data: {
          login: { username: 'ada', password: 'secret' },
          customAssignments: [{ fieldId: issuedPlan!.targets[0]!.fieldId, value: 'engineering' }],
          clientEventAckId: ackId,
          totpCopyAckId,
        } } as ResponseMessage;
      }
      if (request.type === 'clientEvent.ack') return { ok: true, data: null } as ResponseMessage;
      if (request.type === 'autofill.ackTotpCopy') return { ok: true, data: { copied: true } } as ResponseMessage;
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });
    vi.mocked(fillLoginForm).mockReturnValue(true);

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise((resolve) => setTimeout(resolve, 0));
    current.options.onSelect('c1');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(issuedPlan?.targets).toEqual([expect.objectContaining({
      controlType: 'text', hints: [{ kind: 'name', value: 'department' }],
    })]);
    expect(document.querySelector<HTMLInputElement>('[name=department]')!.value).toBe('engineering');
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledWith(
      expect.any(Object),
      { username: 'ada', password: 'secret' },
      expect.any(Object),
    );
    expect(sendRequest).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.ackTotpCopy', ackId: totpCopyAckId });
  });

  it('stops an interactive login before password when username events move the target', async () => {
    const ackId = '10000000-0000-4000-8000-000000000002';
    const totpCopyAckId = '20000000-0000-4000-8000-000000000002';
    document.body.innerHTML = `
      <form id="login"><input name="username"><input type="password"></form>
      <form id="other"></form>`;
    const username = document.querySelector<HTMLInputElement>('[name=username]')!;
    const password = document.querySelector<HTMLInputElement>('input[type=password]')!;
    username.addEventListener('input', () => document.getElementById('other')!.append(password), { once: true });
    vi.mocked(fillLoginForm).mockImplementation((form, login, staged) => {
      if (!staged) throw new Error('Expected a staged login fill');
      let filled = false;
      if (login.username && form.usernameInput) {
        const input = form.usernameInput;
        filled = staged.write(() => {
          input.value = login.username!;
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
          return true;
        });
      }
      if (!staged.stale && login.password && form.passwordInput) {
        const input = form.passwordInput;
        filled = staged.write(() => { input.value = login.password!; return true; }) || filled;
      }
      return filled;
    });
    mockRequests(
      { ok: true, data: [{ id: 'c1', name: 'Example', matchedUri: 'https://example.com', matchType: 0, favorite: false }] } as ResponseMessage,
      { ok: true, data: { intentId: 'login-intent' } } as ResponseMessage,
      { ok: true, data: {
        login: { username: 'ada', password: 'must-not-fill' },
        clientEventAckId: ackId,
        totpCopyAckId,
      } } as ResponseMessage,
    );

    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise((resolve) => setTimeout(resolve, 0));
    current.options.onSelect('c1');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(username.value).toBe('ada');
    expect(password.value).toBe('');
    expect(current.showFilled).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'autofill.ackTotpCopy', ackId: totpCopyAckId });
  });

  it('mounts and opens card and identity pickers when their fields receive focus', async () => {
    document.body.innerHTML = `
      <form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" id="csc"></form>
      <form><input autocomplete="given-name" id="fn"><input autocomplete="family-name"><input autocomplete="street-address"><input autocomplete="postal-code"></form>`;

    await startReady('https://shop.example/checkout');
    vi.mocked(sendRequest).mockClear();
    trustedPageEvent(document.getElementById('num')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    trustedPageEvent(document.getElementById('fn')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(popoverState.instances).toHaveLength(2);
    const card = popoverState.instances.find((entry) => entry.options.kind === 'card')!;
    const identity = popoverState.instances.find((entry) => entry.options.kind === 'identity')!;
    expect(card.open).toHaveBeenCalledWith(document.getElementById('num'));
    expect(identity.open).toHaveBeenCalledWith(document.getElementById('fn'));
    expect(nonConfigRequests()).toHaveLength(0);
  });

  it('attaches only the card picker when a CVC is rendered as type=password', async () => {
    mockRequests({ ok: true, data: [] });
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" type="password" id="cvc"></form>';
    await startReady('https://shop.example/checkout');
    expect(popoverState.instances).toHaveLength(1);
    expect(popoverState.instances[0]!.options.kind).toBe('card');
  });

  it('redeems a structured selection through a document-bound worker commit', async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc"></form>';
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return ENABLED_CLIENT_CONFIG;
      if (request.type === 'autofill.findStructuredCandidates') {
        return { ok: true, data: [{ id: 'card-1', name: 'Primary card', subtitle: 'Visa', favorite: true }] } as ResponseMessage;
      }
      if (request.type === 'autofill.issueStructuredIntent') {
        return { ok: true, data: { intentId: 'structured-intent' } } as ResponseMessage;
      }
      if (request.type === 'autofill.redeemStructuredIntent') {
        return { ok: true, data: { outcome: { status: 'filled' } } } as ResponseMessage;
      }
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });

    await startReady('https://shop.example/checkout');
    const card = popoverState.instances.find((entry) => entry.options.kind === 'card')!;
    card.options.onOpen();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(card.showCandidates).toHaveBeenCalledWith([{
      id: 'card-1', name: 'Primary card', sub: 'Visa', favorite: true,
    }]);

    card.options.onSelect('card-1');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const issue = vi.mocked(sendRequest).mock.calls.find(([request]) => request.type === 'autofill.issueStructuredIntent')?.[0];
    const redeem = vi.mocked(sendRequest).mock.calls.find(([request]) => request.type === 'autofill.redeemStructuredIntent')?.[0];
    expect(issue).toMatchObject({
      type: 'autofill.issueStructuredIntent',
      cipherId: 'card-1',
      target: { kind: 'card', roles: ['number', 'code'] },
    });
    expect(redeem).toMatchObject({
      type: 'autofill.redeemStructuredIntent',
      intentId: 'structured-intent',
      target: issue && 'target' in issue ? issue.target : undefined,
    });
    expect(card.showFilled).toHaveBeenCalledOnce();
    expect(vi.mocked(sendRequest).mock.calls.some(([request]) => request.type === 'clientEvent.ack')).toBe(false);
  });

  it('fills generated credentials without saving before the site submits', async () => {
    document.body.innerHTML = `
      <form>
        <input type="email" name="email" value="new@example.com">
        <input type="password" autocomplete="new-password" id="new-password">
        <input type="password" name="confirm-password" id="confirm-password">
      </form>`;
    mockRequests();
    await startReady('https://signup.example/register');
    trustedPageEvent(document.getElementById('new-password')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    vi.mocked(sendRequest).mockClear();
    const generated = generatePanelState.instances.at(-1)!;
    const password = generated.update.mock.calls.at(-1)![0].password as string;

    generated.options.onUse();
    generated.options.onUse();
    await new Promise((resolve) => setTimeout(resolve, 0));

    const generatorRequests = nonConfigRequests();
    expect(generatorRequests).toHaveLength(2);
    expect(generatorRequests[0]).toMatchObject({
      type: 'autofill.authorizeGeneratorUse',
      revision: 1,
      options: {
        mode: 'password',
        password: { length: 18 },
      },
    });
    expect(generatorRequests[1]).toEqual({
      type: 'autofill.trackGeneratedValue',
      token: '40000000-0000-4000-8000-000000000001',
      value: password,
    });
    expect(generatorRequests[1]).not.toHaveProperty('typeHint');
    expect((document.getElementById('new-password') as HTMLInputElement).value).toBe(password);
    expect((document.getElementById('confirm-password') as HTMLInputElement).value).toBe(password);
    expect(generated.showFilled).toHaveBeenCalledOnce();
    expect(generated.showFilled).toHaveBeenCalledWith({ user: 'new@example.com' });
    generated.options.onUse();
    expect(generated.showFilled).toHaveBeenCalledOnce();
  });

  it('routes generated credentials through the normal save prompt after a trusted submit', async () => {
    document.body.innerHTML = `
      <form>
        <input type="email" name="email" value="new@example.com">
        <input type="password" autocomplete="new-password" id="new-password">
      </form>`;
    let captured = false;
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return ENABLED_CLIENT_CONFIG;
      if (request.type === 'autofill.authorizeGeneratorUse') {
        return { ok: true, data: { trackToken: '40000000-0000-4000-8000-000000000001' } };
      }
      if (request.type === 'autofill.trackGeneratedValue') {
        return { ok: true, data: { added: true } };
      }
      if (request.type === 'autofill.captureSubmission') {
        captured = true;
        return { ok: true, data: null };
      }
      if (request.type === 'autofill.claimSavePrompt') {
        return captured
          ? { ok: true, data: { action: 'save', promptId: '00000000-0000-4000-8000-000000000001', suggestedName: 'signup.example' } }
          : { ok: true, data: { action: 'none' } };
      }
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });
    await startReady('https://signup.example/register');
    trustedPageEvent(document.getElementById('new-password')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    vi.mocked(sendRequest).mockClear();
    const generated = generatePanelState.instances.at(-1)!;

    generated.options.onUse();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(nonConfigRequests()).toEqual([
      expect.objectContaining({
        type: 'autofill.authorizeGeneratorUse',
        revision: 1,
        options: expect.objectContaining({ mode: 'password' }),
      }),
      expect.objectContaining({
        type: 'autofill.trackGeneratedValue',
        token: '40000000-0000-4000-8000-000000000001',
      }),
    ]);
    trustedPageEvent(
      document.querySelector('form')!,
      new Event('submit', { bubbles: true, cancelable: true, composed: true }),
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(nonConfigRequests()).toEqual([
      expect.objectContaining({ type: 'autofill.authorizeGeneratorUse', revision: 1 }),
      expect.objectContaining({ type: 'autofill.trackGeneratedValue' }),
      {
        type: 'autofill.captureSubmission',
        username: 'new@example.com',
        password: expect.any(String),
        submission: { kind: 'formless' },
      },
    ]);
    expect(saveBarState.instances.at(-1)?.options.actionLabel).toBe('保存');
  });

  it('offers addUri by name and commits only through the opaque prompt intent', async () => {
    document.body.innerHTML = `
      <form id="login">
        <input type="email" name="email" value="user@example.com">
        <input type="password" name="password" value="secret-password">
        <button type="submit">Sign in</button>
      </form>`;
    const promptId = '00000000-0000-4000-8000-000000000002';
    let captured = false;
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return ENABLED_CLIENT_CONFIG;
      if (request.type === 'autofill.captureSubmission') {
        captured = true;
        return { ok: true, data: null };
      }
      if (request.type === 'autofill.claimSavePrompt') {
        return captured
          ? { ok: true, data: { action: 'addUri', promptId, name: 'Existing login' } }
          : { ok: true, data: { action: 'none' } };
      }
      if (request.type === 'autofill.commitSavePrompt') return { ok: true, data: null };
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });
    await startReady('https://new.example/login');
    vi.mocked(sendRequest).mockClear();

    trustedPageEvent(
      document.getElementById('login')!,
      new Event('submit', { bubbles: true, cancelable: true, composed: true }),
    );
    await new Promise((resolve) => setTimeout(resolve, 0));

    const bar = saveBarState.instances.at(-1)!;
    expect(bar.options.message).toBe('将此网站添加到“Existing login”？');
    expect(bar.options.actionLabel).toBe('添加网站');
    expect(bar.options.successMessage).toBe('已将此网站添加到密屿');
    await expect(bar.options.onAction()).resolves.toBe(true);
    expect(nonConfigRequests()).toEqual([
      {
        type: 'autofill.captureSubmission',
        username: 'user@example.com',
        password: 'secret-password',
        submission: { kind: 'formless' },
      },
      {
        type: 'autofill.commitSavePrompt',
        promptId,
      },
    ]);
    expect(JSON.stringify(nonConfigRequests().at(-1))).not.toContain('password');
    expect(JSON.stringify(nonConfigRequests())).not.toContain('cipherId');
  });

  it('does not recreate a generator after its password was used and the panel was dismissed', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
    mockRequests();
    await startReady('https://signup.example/register');
    const input = document.getElementById('new-password') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    vi.mocked(sendRequest).mockClear();
    const generated = generatePanelState.instances.at(-1)!;

    generated.options.onUse();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const outside = document.createElement('button');
    document.body.append(outside);
    trustedPageEvent(outside, new MouseEvent('pointerdown', { bubbles: true, composed: true }));
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));

    expect(generatePanelState.instances).toHaveLength(1);
    expect(nonConfigRequests()).toEqual([
      expect.objectContaining({
        type: 'autofill.authorizeGeneratorUse',
        revision: 1,
        options: expect.objectContaining({ mode: 'password' }),
      }),
      expect.objectContaining({ type: 'autofill.trackGeneratedValue' }),
    ]);
  });

  it('keeps inline suggestions disabled without disabling the generated-password flow', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: true,
      updateAllowed: true,
    });

    await startReady('https://signup.example/register');
    expect(popoverState.instances).toHaveLength(0);
    trustedPageEvent(document.getElementById('new-password')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(popoverState.instances).toHaveLength(0);
    expect(generatePanelState.instances).toHaveLength(1);
  });

  it('keeps the generator available when save and update prompts are disabled', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: false,
      updateAllowed: false,
      generatorAllowed: true,
    });

    await startReady('https://signup.example/register');
    const input = document.getElementById('new-password') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const generated = generatePanelState.instances.at(-1)!;
    const value = generated.update.mock.calls.at(-1)![0].password as string;

    generated.options.onUse();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(input.value).toBe(value);
    expect(nonConfigRequests()).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'autofill.authorizeGeneratorUse' }),
      expect.objectContaining({ type: 'autofill.trackGeneratedValue', value }),
    ]));
    expect(saveBarState.instances).toHaveLength(0);
  });

  it('does not roll back an actual generator fill when encrypted history tracking fails', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
    mockRequests();
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return ENABLED_CLIENT_CONFIG;
      if (request.type === 'autofill.authorizeGeneratorUse') {
        return { ok: true, data: { trackToken: '40000000-0000-4000-8000-000000000001' } };
      }
      if (request.type === 'autofill.trackGeneratedValue') throw new Error('history unavailable');
      if (request.type === 'autofill.claimSavePrompt') {
        return { ok: true, data: { action: 'none' } };
      }
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });
    await startReady('https://signup.example/register');
    const input = document.getElementById('new-password') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const generated = generatePanelState.instances.at(-1)!;
    const value = generated.update.mock.calls.at(-1)![0].password as string;

    generated.options.onUse();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(input.value).toBe(value);
    expect(generated.showFilled).toHaveBeenCalledOnce();
    expect(nonConfigRequests()).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'autofill.trackGeneratedValue', value }),
    ]));
  });

  it('uses the worker snapshot for a forced managed passphrase', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
    const generator = createGeneratorPolicySnapshot({
      malformed: false,
      data: {
        ...EMPTY_PASSWORD_GENERATOR_POLICY,
        overridePasswordType: 'passphrase',
        minNumberWords: 8,
        capitalize: true,
        includeNumber: true,
      },
    }, 4);
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: true,
      updateAllowed: true,
      generator,
    });

    await startReady('https://signup.example/register');
    trustedPageEvent(document.getElementById('new-password')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const state = generatePanelState.instances.at(-1)!.update.mock.calls.at(-1)![0];
    expect(state).toMatchObject({
      mode: 'passphrase',
      words: 8,
      capitalize: true,
      includeNumber: true,
      managed: true,
      disabledReason: '',
    });
    expect(String(state.password).split('-')).toHaveLength(8);
  });

  it('does not let a late worker authorization use a panel from an old policy generation', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
    let resolveAuthorization!: (response: ResponseMessage) => void;
    const authorization = new Promise<ResponseMessage>((resolve) => { resolveAuthorization = resolve; });
    let configRevision = 1;
    vi.mocked(sendRequest).mockImplementation((request) => {
      if (request.type === 'autofill.getClientConfig') {
        return Promise.resolve({
          ok: true,
          data: { ...ENABLED_CLIENT_CONFIG.data, generator: createGeneratorPolicySnapshot(null, configRevision) },
        });
      }
      if (request.type === 'autofill.authorizeGeneratorUse') return authorization;
      if (request.type === 'autofill.claimSavePrompt') {
        return Promise.resolve({ ok: true, data: { action: 'none' } });
      }
      return Promise.resolve({ ok: false, error: { code: 'error', message: 'unexpected request' } });
    });

    await startReady('https://signup.example/register');
    const input = document.getElementById('new-password') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const oldPanel = generatePanelState.instances.at(-1)!;
    oldPanel.options.onUse();

    configRevision = 2;
    handleContentCommand({ type: 'autofill.clientConfigChanged' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    resolveAuthorization({
      ok: true,
      data: { trackToken: '40000000-0000-4000-8000-000000000001' },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(oldPanel.remove).toHaveBeenCalled();
    expect(oldPanel.showFilled).not.toHaveBeenCalled();
    expect(input.value).toBe('');
  });

  it('does not fill or track after same-document navigation wins an authorization race', async () => {
    const originalUrl = window.location.href;
    window.history.replaceState({}, '', '/generator-start');
    try {
      document.body.innerHTML = '<form><input type="password" autocomplete="new-password" id="new-password"></form>';
      let resolveAuthorization!: (response: ResponseMessage) => void;
      const authorization = new Promise<ResponseMessage>((resolve) => { resolveAuthorization = resolve; });
      vi.mocked(sendRequest).mockImplementation((request) => {
        if (request.type === 'autofill.getClientConfig') return Promise.resolve(ENABLED_CLIENT_CONFIG);
        if (request.type === 'autofill.authorizeGeneratorUse') return authorization;
        return Promise.resolve({ ok: false, error: { code: 'error', message: 'unexpected request' } });
      });

      await startReady(() => window.location.href);
      const input = document.getElementById('new-password') as HTMLInputElement;
      trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
      await new Promise((resolve) => setTimeout(resolve, 0));
      const panel = generatePanelState.instances.at(-1)!;
      panel.options.onUse();
      window.history.pushState({}, '', '/generator-next');
      resolveAuthorization({
        ok: true,
        data: { trackToken: '40000000-0000-4000-8000-000000000001' },
      });
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(input.value).toBe('');
      expect(panel.showFilled).not.toHaveBeenCalled();
      expect(vi.mocked(sendRequest).mock.calls.some(([request]) => (
        request.type === 'autofill.trackGeneratedValue'
      ))).toBe(false);
    } finally {
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('does not run periodic composed-tree scans when every client feature is disabled', async () => {
    vi.useFakeTimers();
    const createTreeWalker = vi.spyOn(document, 'createTreeWalker');
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: false,
      updateAllowed: false,
    });
    try {
      await startReady('https://example.com/login');
      expect(createTreeWalker).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(5_000);
      expect(createTreeWalker).not.toHaveBeenCalled();
    } finally {
      stopAutofill();
      runtimeStartedForTest = false;
      vi.useRealTimers();
    }
  });

  it('discovers open roots on demand for frame inspection while live observation is disabled', async () => {
    document.body.replaceChildren();
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: false,
      updateAllowed: false,
    });
    await startReady('https://example.com/login');

    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input type="email"><input type="password"></form>';
    document.body.append(host);
    const inspection = handleFrameAutofillMessage({ type: 'autofill.inspectFrame' });

    expect('forms' in inspection && inspection.forms).toHaveLength(1);
  });

  it('discovers a dynamically connected nested open-shadow login and opens its panel', async () => {
    document.body.replaceChildren();
    await startReady('https://example.com/login');
    expect(popoverState.instances).toHaveLength(0);

    const outerHost = document.createElement('div');
    const outer = outerHost.attachShadow({ mode: 'open' });
    const innerHost = document.createElement('div');
    const inner = innerHost.attachShadow({ mode: 'open' });
    inner.innerHTML = '<form><input type="email"><input type="password"></form>';
    outer.append(innerHost);
    document.body.append(outerHost);
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(popoverState.instances).toHaveLength(1);
    const email = inner.querySelector<HTMLInputElement>('input[type="email"]')!;
    trustedPageEvent(email, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(popoverState.instances[0]!.open).toHaveBeenCalled();
  });

  it('rescans an open root when autofill-relevant attributes change', async () => {
    document.body.replaceChildren();
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input id="candidate" type="text" name="query"></form>';
    document.body.append(host);
    await startReady('https://example.com/login');
    expect(popoverState.instances).toHaveLength(0);

    const input = shadow.querySelector<HTMLInputElement>('#candidate')!;
    input.type = 'password';
    input.autocomplete = 'current-password';
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(popoverState.instances).toHaveLength(1);
  });

  it('removes and refuses a login surface after its password field is reclassified', async () => {
    await startReady('https://example.com/login');
    const current = popover();
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;

    password.type = 'text';
    password.name = 'search';
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(current.remove).toHaveBeenCalled();

    vi.mocked(sendRequest).mockClear();
    current.options.onSelect('cipher-1');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(nonConfigRequests()).toHaveLength(0);
    expect(fillLoginForm).not.toHaveBeenCalled();
  });

  it('removes an existing login surface when its password opts out at runtime', async () => {
    await startReady('https://example.com/login');
    const current = popover();
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;

    password.setAttribute('data-bwignore', '');
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(current.remove).toHaveBeenCalled();
  });

  it('attaches password generation and TOTP flows inside open roots', async () => {
    document.body.replaceChildren();
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form><input type="email"><input id="new-password" type="password" autocomplete="new-password"></form>
      <form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>`;
    document.body.append(host);
    mockRequests(
      { ok: true, data: [{ id: 'c1', name: 'Account', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true }] } as ResponseMessage,
      { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
      { ok: true, data: { totp: { code: '123456', period: 30, remaining: 15 } } } as ResponseMessage,
    );
    await startReady('https://example.com/login');

    trustedPageEvent(shadow.getElementById('new-password')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(generatePanelState.instances).toHaveLength(1);

    trustedPageEvent(shadow.getElementById('otp')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(nonConfigRequests()).toEqual(expect.arrayContaining([
      { type: 'autofill.findCandidates', purpose: 'totp' },
      { type: 'autofill.issueIntent', cipherId: 'c1', purpose: 'totp' },
      { type: 'autofill.redeemTotpIntent', intentId: 'totp-intent' },
    ]));
  });

  it('shows bounded same-name TOTP candidates without requesting a code before selection', async () => {
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    const candidates = Array.from({ length: 10 }, (_, index) => ({
      id: `c${index}`,
      name: 'Shared account',
      username: `user-${index}@example.com`,
      matchedUri: 'https://example.com',
      matchType: 0 as const,
      favorite: false,
      hasTotp: true,
    }));
    mockRequests(
      { ok: true, data: candidates } as ResponseMessage,
      { ok: true, data: { intentId: 'selected-intent' } } as ResponseMessage,
      { ok: true, data: { totp: { code: '876543', period: 30, remaining: 15 } } } as ResponseMessage,
    );
    await startReady('https://example.com/login');
    trustedPageEvent(document.getElementById('otp')!, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');

    expect(panel.showCandidates).toHaveBeenCalledWith({
      candidates: candidates.slice(0, 8).map((candidate, index) => ({
        key: `candidate-${index}`,
        name: candidate.name,
        username: candidate.username,
        reprompt: false,
      })),
      overflowCount: 2,
    });
    expect(nonConfigRequests()).toEqual([{ type: 'autofill.findCandidates', purpose: 'totp' }]);
    expect(JSON.stringify(panel.showCandidates.mock.calls)).not.toContain('876543');

    panel.options.onSelect('candidate-1');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.issueIntent', cipherId: 'c1', purpose: 'totp' });
    expect(panel.update).toHaveBeenCalledWith({
      itemName: 'Shared account',
      itemUser: 'user-1@example.com',
      code: '876543',
      remaining: 15,
    });
  });

  it('drops a stale first TOTP response after switching candidates and only ACKs the selected code', async () => {
    const firstAck = '10000000-0000-4000-8000-000000000021';
    const secondAck = '10000000-0000-4000-8000-000000000022';
    let resolveFirst!: (response: ResponseMessage) => void;
    const firstResponse = new Promise<ResponseMessage>((resolve) => { resolveFirst = resolve; });
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [
        { id: 'first', name: 'Same', username: 'first@example.com', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true },
        { id: 'second', name: 'Same', username: 'second@example.com', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true },
      ] } as ResponseMessage,
      { ok: true, data: { intentId: 'first-intent' } } as ResponseMessage,
      firstResponse,
      { ok: true, data: { intentId: 'second-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '222222', period: 30, remaining: 15 },
        clientEventAckId: secondAck,
      } } as ResponseMessage,
      { ok: true, data: null } as ResponseMessage,
    );
    await startReady('https://example.com/login');
    const input = document.getElementById('otp') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');

    panel.options.onSelect('candidate-0');
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({
      type: 'autofill.redeemTotpIntent', intentId: 'first-intent',
    }));
    panel.options.onSelect('candidate-1');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(panel.update).toHaveBeenLastCalledWith(expect.objectContaining({ code: '222222' }));

    resolveFirst({ ok: true, data: {
      totp: { code: '111111', period: 30, remaining: 15 },
      clientEventAckId: firstAck,
    } } as ResponseMessage);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(panel.update).not.toHaveBeenCalledWith(expect.objectContaining({ code: '111111' }));

    vi.mocked(fillTotpCode).mockClear();
    panel.options.onFill();
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: secondAck }));
    expect(input.value).toBe('222222');
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: firstAck });
  });

  it('drops a selected TOTP response that arrives after same-document navigation', async () => {
    const ackId = '10000000-0000-4000-8000-000000000025';
    let frameUrl = 'https://example.com/login';
    let resolveTotp!: (response: ResponseMessage) => void;
    const pendingTotp = new Promise<ResponseMessage>((resolve) => { resolveTotp = resolve; });
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [
        { id: 'first', name: 'First', matchedUri: frameUrl, matchType: 0, favorite: false, hasTotp: true },
        { id: 'second', name: 'Second', matchedUri: frameUrl, matchType: 0, favorite: false, hasTotp: true },
      ] } as ResponseMessage,
      { ok: true, data: { intentId: 'pending-intent' } } as ResponseMessage,
      pendingTotp,
    );
    await startReady(() => frameUrl);
    const input = document.getElementById('otp') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');

    panel.options.onSelect('candidate-0');
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({
      type: 'autofill.redeemTotpIntent', intentId: 'pending-intent',
    }));
    frameUrl = 'https://example.com/next';
    resolveTotp({ ok: true, data: {
      totp: { code: '333333', period: 30, remaining: 15 }, clientEventAckId: ackId,
    } } as ResponseMessage);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(panel.update).not.toHaveBeenCalledWith(expect.objectContaining({ code: '333333' }));
    vi.mocked(fillTotpCode).mockClear();
    panel.options.onFill();
    expect(fillTotpCode).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('revokes a loaded TOTP code, ACK, and timer before choosing another account', async () => {
    const firstAck = '10000000-0000-4000-8000-000000000023';
    const secondAck = '10000000-0000-4000-8000-000000000024';
    const clearInterval = vi.spyOn(window, 'clearInterval');
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [
        { id: 'first', name: 'First', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true },
        { id: 'second', name: 'Second', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true },
      ] } as ResponseMessage,
      { ok: true, data: { intentId: 'first-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '111111', period: 30, remaining: 15 }, clientEventAckId: firstAck,
      } } as ResponseMessage,
      { ok: true, data: { intentId: 'second-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '222222', period: 30, remaining: 15 }, clientEventAckId: secondAck,
      } } as ResponseMessage,
      { ok: true, data: null } as ResponseMessage,
    );
    await startReady('https://example.com/login');
    const input = document.getElementById('otp') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');

    panel.options.onSelect('candidate-0');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(panel.update).toHaveBeenLastCalledWith(expect.objectContaining({ code: '111111' }));

    panel.options.onChooseOther();
    expect(clearInterval).toHaveBeenCalled();
    vi.mocked(fillTotpCode).mockClear();
    panel.options.onFill();
    expect(fillTotpCode).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: firstAck });

    panel.options.onSelect('candidate-1');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    panel.options.onFill();
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId: secondAck }));
    expect(input.value).toBe('222222');
    clearInterval.mockRestore();
  });

  it.each([
    [
      'reprompt',
      { ok: true, data: { repromptContinuationId: '30000000-0000-4000-8000-000000000001' } } as ResponseMessage,
      'Protected item',
    ],
    [
      'permission loss',
      { ok: false, error: { code: 'denied', message: 'TOTP permission changed' } } as ResponseMessage,
      'Autofill denied',
    ],
  ])('does not release or fill a TOTP after selected-candidate %s', async (_label, issueResponse, status) => {
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [
        { id: 'blocked', name: 'Blocked', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true, reprompt: true },
        { id: 'other', name: 'Other', matchedUri: 'https://example.com', matchType: 0, favorite: false, hasTotp: true },
      ] } as ResponseMessage,
      issueResponse,
    );
    await startReady('https://example.com/login');
    const input = document.getElementById('otp') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');

    panel.options.onSelect('candidate-0');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(panel.update).not.toHaveBeenCalled();
    expect(panel.showCandidates).toHaveBeenLastCalledWith(expect.objectContaining({
      statusMessage: expect.stringContaining(status),
    }));
    panel.options.onFill();
    expect(input.value).toBe('');
    expect(sendRequest).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'autofill.redeemTotpIntent' }));
  });

  it('acknowledges one inline TOTP DOM fill exactly once', async () => {
    const ackId = '10000000-0000-4000-8000-000000000003';
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [{
        id: 'c1', name: 'Account', matchedUri: 'https://example.com', matchType: 0,
        favorite: false, hasTotp: true,
      }] } as ResponseMessage,
      { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '123456', period: 30, remaining: 15 },
        clientEventAckId: ackId,
      } } as ResponseMessage,
      { ok: true, data: null } as ResponseMessage,
    );
    await startReady('https://example.com/login');
    trustedPageEvent(document.getElementById('otp')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');
    panel.options.onFill();
    panel.options.onFill();
    await Promise.resolve();

    expect(vi.mocked(sendRequest).mock.calls.filter(([request]) => (
      request.type === 'clientEvent.ack' && request.ackId === ackId
    ))).toHaveLength(1);
  });

  it('does not acknowledge an inline TOTP when the DOM fill fails', async () => {
    const ackId = '10000000-0000-4000-8000-000000000004';
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    vi.mocked(fillTotpCode).mockReturnValueOnce(false);
    mockRequests(
      { ok: true, data: [{
        id: 'c1', name: 'Account', matchedUri: 'https://example.com', matchType: 0,
        favorite: false, hasTotp: true,
      }] } as ResponseMessage,
      { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '123456', period: 30, remaining: 15 },
        clientEventAckId: ackId,
      } } as ResponseMessage,
    );
    await startReady('https://example.com/login');
    trustedPageEvent(document.getElementById('otp')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');
    panel.options.onFill();
    await Promise.resolve();

    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('does not fill or acknowledge inline TOTP after same-document navigation', async () => {
    const ackId = '10000000-0000-4000-8000-000000000014';
    let frameUrl = 'https://example.com/login';
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [{
        id: 'c1', name: 'Account', matchedUri: frameUrl, matchType: 0,
        favorite: false, hasTotp: true,
      }] } as ResponseMessage,
      { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '123456', period: 30, remaining: 15 },
        clientEventAckId: ackId,
      } } as ResponseMessage,
    );
    await startReady(() => frameUrl);
    trustedPageEvent(document.getElementById('otp')!, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');
    vi.mocked(fillTotpCode).mockClear();

    frameUrl = 'https://example.com/next';
    panel.options.onFill();
    await Promise.resolve();

    expect(fillTotpCode).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('withholds inline TOTP acknowledgement when synchronous DOM events navigate during the write', async () => {
    const ackId = '10000000-0000-4000-8000-000000000015';
    let frameUrl = 'https://example.com/login';
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [{
        id: 'c1', name: 'Account', matchedUri: frameUrl, matchType: 0,
        favorite: false, hasTotp: true,
      }] } as ResponseMessage,
      { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '123456', period: 30, remaining: 15 },
        clientEventAckId: ackId,
      } } as ResponseMessage,
    );
    await startReady(() => frameUrl);
    trustedPageEvent(document.getElementById('otp')!, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');
    vi.mocked(fillTotpCode).mockImplementationOnce((input, value) => {
      input.value = value;
      frameUrl = 'https://example.com/navigated-during-input';
      return true;
    });

    panel.options.onFill();
    await Promise.resolve();

    expect(fillTotpCode).toHaveBeenCalledOnce();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('stops a split TOTP after the first cell pushes a new SPA URL and never acknowledges it', async () => {
    const originalUrl = window.location.href;
    const ackId = '10000000-0000-4000-8000-000000000017';
    window.history.replaceState({}, '', '/otp-start');
    try {
      document.body.innerHTML = `<form><div id="otp-group">
        <input id="digit-1" autocomplete="one-time-code" maxlength="1">
        <input id="digit-2" maxlength="1"><input id="digit-3" maxlength="1">
        <input id="digit-4" maxlength="1"><input id="digit-5" maxlength="1">
        <input id="digit-6" maxlength="1">
      </div><button>Verify</button></form>`;
      mockRequests(
        { ok: true, data: [{
          id: 'c1', name: 'Account', matchedUri: window.location.href, matchType: 0,
          favorite: false, hasTotp: true,
        }] } as ResponseMessage,
        { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
        { ok: true, data: {
          totp: { code: '123456', period: 30, remaining: 15 },
          clientEventAckId: ackId,
        } } as ResponseMessage,
      );
      await startReady(() => window.location.href);
      const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('#otp-group input'));
      trustedPageEvent(inputs[0]!, new FocusEvent('focusin', { bubbles: true }));
      await new Promise((resolve) => setTimeout(resolve, 0));
      await new Promise((resolve) => setTimeout(resolve, 0));
      const panel = totpPanelState.instances.at(-1);
      if (!panel) throw new Error('Expected TOTP panel');
      inputs[0]!.addEventListener('input', () => {
        window.history.pushState({}, '', '/otp-next');
      }, { once: true });
      vi.mocked(fillTotpCode).mockImplementationOnce((_input, value, revalidate = () => true) => {
        const characters = Array.from(value);
        for (let index = 0; index < inputs.length; index += 1) {
          if (!revalidate()) return false;
          inputs[index]!.value = characters[index]!;
          inputs[index]!.dispatchEvent(new Event('input', { bubbles: true }));
          if (!revalidate()) return false;
        }
        return true;
      });

      panel.options.onFill();
      await Promise.resolve();

      expect(inputs.map((input) => input.value)).toEqual(['1', '', '', '', '', '']);
      expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
      expect(panel.showFilled).not.toHaveBeenCalled();
    } finally {
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('does not fill or acknowledge inline TOTP after its control owner changes', async () => {
    const ackId = '10000000-0000-4000-8000-000000000016';
    document.body.innerHTML = '<form><input id="otp" autocomplete="one-time-code"><button>Verify</button></form>';
    mockRequests(
      { ok: true, data: [{
        id: 'c1', name: 'Account', matchedUri: 'https://example.com', matchType: 0,
        favorite: false, hasTotp: true,
      }] } as ResponseMessage,
      { ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage,
      { ok: true, data: {
        totp: { code: '123456', period: 30, remaining: 15 },
        clientEventAckId: ackId,
      } } as ResponseMessage,
    );
    await startReady('https://example.com/login');
    const input = document.getElementById('otp') as HTMLInputElement;
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const panel = totpPanelState.instances.at(-1);
    if (!panel) throw new Error('Expected TOTP panel');
    const replacementOwner = document.createElement('form');
    document.body.append(replacementOwner);
    replacementOwner.append(input);
    vi.mocked(fillTotpCode).mockClear();

    panel.options.onFill();
    await Promise.resolve();

    expect(fillTotpCode).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('disconnects page listeners, observers, surfaces, and timers after extension invalidation', async () => {
    vi.useFakeTimers();
    try {
      await startReady('https://example.com/login');
      const current = popover();
      extensionContextState.alive = false;
      await vi.advanceTimersByTimeAsync(1_000);
      expect(current.remove).toHaveBeenCalled();

      popoverState.instances.length = 0;
      const host = document.createElement('div');
      const shadow = host.attachShadow({ mode: 'open' });
      shadow.innerHTML = '<form><input type="email"><input type="password"></form>';
      document.body.append(host);
      trustedPageEvent(shadow.querySelector('input')!, new FocusEvent('focusin', { bubbles: true, composed: true }));
      await vi.advanceTimersByTimeAsync(2_000);
      expect(popoverState.instances).toHaveLength(0);
    } finally {
      extensionContextState.alive = true;
      vi.useRealTimers();
    }
  });

  it('rebuilds the complete runtime from authoritative state after a BFCache restore', async () => {
    const originalUrl = window.location.href;
    let issued = 0;
    let captured = 0;
    try {
      window.history.replaceState({}, '', '/bfcache-before');
      document.body.innerHTML = '<form id="bfcache-login"><input autocomplete="username" id="bfcache-username"><input type="password" autocomplete="current-password" id="bfcache-password"></form>';
      const username = document.getElementById('bfcache-username') as HTMLInputElement;
      const password = document.getElementById('bfcache-password') as HTMLInputElement;
      makePageLoadVisible(username);
      makePageLoadVisible(password);
      vi.mocked(sendRequest).mockImplementation(async (request) => {
        if (request.type === 'autofill.getClientConfig') {
          return { ok: true, data: { ...ENABLED_CLIENT_CONFIG.data, pageLoadFill: true } } as ResponseMessage;
        }
        if (request.type === 'autofill.claimSavePrompt') {
          return { ok: true, data: { action: 'none' } } as ResponseMessage;
        }
        if (request.type === 'autofill.issuePageLoadIntent') {
          issued += 1;
          return { ok: true, data: { intentId: `page-load-${issued}` } } as ResponseMessage;
        }
        if (request.type === 'autofill.redeemPageLoadIntent') {
          return { ok: true, data: {
            login: { username: `user-${issued}`, password: `secret-${issued}` },
          } } as ResponseMessage;
        }
        if (request.type === 'autofill.captureSubmission') {
          captured += 1;
          return { ok: true, data: null } as ResponseMessage;
        }
        return { ok: false, error: { code: 'error', message: 'unexpected request' } } as ResponseMessage;
      });

      await startReady(() => window.location.href);
      await vi.waitFor(() => expect(password.value).toBe('secret-1'));
      const oldPopover = popover();
      const claimsBeforeHide = requestsOfType('autofill.claimSavePrompt').length;

      dispatchPageTransition('pagehide', true);
      expect(oldPopover.remove).toHaveBeenCalledOnce();
      username.value = '';
      password.value = '';
      window.history.replaceState({}, '', '/bfcache-after');
      dispatchPageTransition('pageshow', true);

      await vi.waitFor(() => expect(password.value).toBe('secret-2'));
      expect(requestsOfType('autofill.getClientConfig')).toHaveLength(2);
      expect(requestsOfType('autofill.issuePageLoadIntent')).toHaveLength(2);
      expect(requestsOfType('autofill.claimSavePrompt').length).toBeGreaterThan(claimsBeforeHide);
      const inspection = handleFrameAutofillMessage({ type: 'autofill.inspectFrame' });
      expect('frameUrl' in inspection ? inspection.frameUrl : '').toBe(`${window.location.origin}/bfcache-after`);

      const restoredPopover = popover();
      expect(restoredPopover).not.toBe(oldPopover);
      trustedPageEvent(username, new FocusEvent('focusin', { bubbles: true, composed: true }));
      await vi.waitFor(() => expect(restoredPopover.open).toHaveBeenCalled());

      const popoversBeforeMutation = popoverState.instances.length;
      const addedForm = document.createElement('form');
      addedForm.innerHTML = '<input type="email"><input type="password">';
      document.body.append(addedForm);
      await vi.waitFor(() => expect(popoverState.instances.length).toBeGreaterThan(popoversBeforeMutation));

      trustedPageEvent(
        document.getElementById('bfcache-login')!,
        new Event('submit', { bubbles: true, cancelable: true, composed: true }),
      );
      await vi.waitFor(() => expect(captured).toBe(1));
    } finally {
      stopAutofill();
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('supports repeated BFCache cycles, clears old targets, and does not resume a normal pagehide', async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="bfcache-card"></form>';
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: false,
      updateAllowed: false,
    });
    await startReady('https://example.com/checkout');
    const card = document.getElementById('bfcache-card') as HTMLInputElement;
    const oldReservationId = reserveTarget(card, 'field', 'card');

    dispatchPageTransition('pagehide', true);
    dispatchPageTransition('pageshow', true);
    await flushRuntimeStart();
    expect(handleContentCommand({
      type: 'autofill.fill',
      reservationId: oldReservationId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'no_target' });
    expect(card.value).toBe('');

    for (let cycle = 0; cycle < 2; cycle += 1) {
      dispatchPageTransition('pagehide', true);
      dispatchPageTransition('pageshow', true);
      await flushRuntimeStart();
    }
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(4);

    dispatchPageTransition('pagehide', false);
    dispatchPageTransition('pageshow', true);
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(4);
  });

  it('clears the restored document unconfirmed capture before BFCache resume and then accepts confirmation', async () => {
    let resolveDiscard!: (response: ResponseMessage) => void;
    const discard = new Promise<ResponseMessage>((resolve) => { resolveDiscard = resolve; });
    let claims = 0;
    vi.mocked(sendRequest).mockImplementation((request) => {
      if (request.type === 'autofill.getClientConfig') return Promise.resolve(ENABLED_CLIENT_CONFIG);
      if (request.type === 'autofill.claimSavePrompt') {
        claims += 1;
        return Promise.resolve({ ok: true, data: { action: 'none' } } as ResponseMessage);
      }
      if (request.type === 'autofill.discardBfcacheCapture') return discard;
      return Promise.resolve({ ok: false, error: { code: 'error', message: 'unexpected request' } });
    });
    await startReady('https://example.com/login');
    const initialClaims = claims;

    dispatchPageTransition('pagehide', true);
    dispatchPageTransition('pageshow', true);
    await Promise.resolve();

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.discardBfcacheCapture' });
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(1);
    resolveDiscard({ ok: true, data: null });
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(2);
    expect(claims).toBeGreaterThan(initialClaims);

    const claimsBeforeConfirmation = claims;
    await expect(handleContentCommand({ type: 'autofill.saveCaptureConfirmed' }))
      .resolves.toEqual({ status: 'accepted' });
    expect(claims).toBe(claimsBeforeConfirmation + 1);
  });

  it('does not acknowledge a save-capture wake until the worker claim succeeds', async () => {
    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: true,
      updateAllowed: true,
    });
    await startReady('https://example.com/login');
    vi.mocked(sendRequest).mockImplementation((request) => {
      if (request.type === 'autofill.claimSavePrompt') {
        return Promise.reject(new Error('worker unavailable'));
      }
      return Promise.resolve(ENABLED_CLIENT_CONFIG);
    });

    await expect(handleContentCommand({ type: 'autofill.saveCaptureConfirmed' }))
      .resolves.toEqual({ status: 'not_ready' });
    stopAutofill();
    await expect(handleContentCommand({ type: 'autofill.saveCaptureConfirmed' }))
      .resolves.toEqual({ status: 'not_ready' });
  });

  it('lets explicit stop and start cancel a pending BFCache resume hook', async () => {
    mockRequestsWithConfig({ inlineSuggestions: false, pageLoadFill: false, saveAllowed: false, updateAllowed: false });
    await startReady('https://example.com/login');
    dispatchPageTransition('pagehide', true);
    stopAutofill();
    dispatchPageTransition('pageshow', true);
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(1);
    startAutofill('https://example.com/login');
    await flushRuntimeStart();
    dispatchPageTransition('pagehide', true);
    startAutofill('https://example.com/login');
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(3);
    dispatchPageTransition('pageshow', true);
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(3);
  });

  it('does not resume from BFCache when the extension context is gone', async () => {
    mockRequestsWithConfig({ inlineSuggestions: false, pageLoadFill: false, saveAllowed: false, updateAllowed: false });
    await startReady('https://example.com/login');
    dispatchPageTransition('pagehide', true);
    extensionContextState.alive = false;
    dispatchPageTransition('pageshow', true);
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(1);
    extensionContextState.alive = true;
    dispatchPageTransition('pageshow', true);
    await flushRuntimeStart();
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(1);
  });

  it('ignores a client config response from the runtime destroyed for BFCache', async () => {
    let resolveOldConfig!: (response: ResponseMessage) => void;
    const oldConfig = new Promise<ResponseMessage>((resolve) => { resolveOldConfig = resolve; });
    let configRequests = 0;
    vi.mocked(sendRequest).mockImplementation((request) => {
      if (request.type === 'autofill.getClientConfig') {
        configRequests += 1;
        return configRequests === 1 ? oldConfig : Promise.resolve(ENABLED_CLIENT_CONFIG);
      }
      if (request.type === 'autofill.claimSavePrompt') {
        return Promise.resolve({ ok: true, data: { action: 'none' } } as ResponseMessage);
      }
      return Promise.resolve({
        ok: false,
        error: { code: 'error', message: 'unexpected request' },
      } as ResponseMessage);
    });
    startAutofill('https://example.com/login');
    runtimeStartedForTest = true;
    await Promise.resolve();

    dispatchPageTransition('pagehide', true);
    dispatchPageTransition('pageshow', true);
    await vi.waitFor(() => expect(popoverState.instances).toHaveLength(1));

    resolveOldConfig(ENABLED_CLIENT_CONFIG);
    await flushRuntimeStart();
    expect(popoverState.instances).toHaveLength(1);
    expect(requestsOfType('autofill.getClientConfig')).toHaveLength(2);
  });

  it('drops old save and page-load responses after a BFCache runtime replacement', async () => {
    document.body.innerHTML = '<input id="bfcache-secret" type="password" autocomplete="current-password">';
    const password = document.getElementById('bfcache-secret') as HTMLInputElement;
    makePageLoadVisible(password);
    let resolveOldClaim!: (response: ResponseMessage) => void;
    const oldClaim = new Promise<ResponseMessage>((resolve) => { resolveOldClaim = resolve; });
    let resolveOldLogin!: (response: ResponseMessage) => void;
    const oldLogin = new Promise<ResponseMessage>((resolve) => { resolveOldLogin = resolve; });
    let claims = 0;
    let issues = 0;
    vi.mocked(sendRequest).mockImplementation((request) => {
      if (request.type === 'autofill.getClientConfig') {
        return Promise.resolve({ ok: true, data: {
          ...ENABLED_CLIENT_CONFIG.data,
          inlineSuggestions: false,
          pageLoadFill: true,
          saveAllowed: false,
          updateAllowed: false,
          generatorAllowed: false,
        } } as ResponseMessage);
      }
      if (request.type === 'autofill.claimSavePrompt') {
        claims += 1;
        return claims === 1
          ? oldClaim
          : Promise.resolve({ ok: true, data: { action: 'none' } } as ResponseMessage);
      }
      if (request.type === 'autofill.issuePageLoadIntent') {
        issues += 1;
        return Promise.resolve({ ok: true, data: { intentId: 'bfcache-intent-' + issues } } as ResponseMessage);
      }
      if (request.type === 'autofill.redeemPageLoadIntent') {
        return request.intentId === 'bfcache-intent-1'
          ? oldLogin
          : Promise.resolve({ ok: true, data: { login: { password: 'fresh-secret' } } } as ResponseMessage);
      }
      return Promise.resolve({
        ok: false,
        error: { code: 'error', message: 'unexpected request' },
      } as ResponseMessage);
    });
    await startReady('https://example.com/login');
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({
      type: 'autofill.redeemPageLoadIntent',
      intentId: 'bfcache-intent-1',
    }));

    dispatchPageTransition('pagehide', true);
    dispatchPageTransition('pageshow', true);
    await vi.waitFor(() => expect(password.value).toBe('fresh-secret'));

    resolveOldClaim({ ok: true, data: {
      action: 'save',
      promptId: '00000000-0000-4000-8000-000000000777',
      suggestedName: 'stale.example',
    } } as ResponseMessage);
    resolveOldLogin({ ok: true, data: { login: { password: 'stale-secret' } } } as ResponseMessage);
    await flushRuntimeStart();

    expect(password.value).toBe('fresh-secret');
    expect(saveBarState.instances).toHaveLength(0);
  });

  it('clears every old runtime timer before waiting for a BFCache pageshow', async () => {
    vi.useFakeTimers();
    try {
      document.body.innerHTML = '<form><input autocomplete="cc-number" id="timer-target"></form>';
      vi.mocked(sendRequest).mockImplementation(async (request) => {
        if (request.type === 'autofill.getClientConfig') {
          return { ok: true, data: {
            ...ENABLED_CLIENT_CONFIG.data,
            inlineSuggestions: false,
            pageLoadFill: true,
            saveAllowed: false,
            updateAllowed: false,
            generatorAllowed: false,
          } } as ResponseMessage;
        }
        if (request.type === 'autofill.claimSavePrompt') {
          return { ok: true, data: { action: 'none', retryAfterMs: 2_000 } } as ResponseMessage;
        }
        return { ok: false, error: { code: 'error', message: 'unexpected request' } } as ResponseMessage;
      });
      await startReady('https://example.com/checkout');
      reserveTarget(document.getElementById('timer-target')!, 'field', 'card');
      expect(vi.getTimerCount()).toBeGreaterThan(0);

      dispatchPageTransition('pagehide', true);
      expect(vi.getTimerCount()).toBe(0);
      const requestCount = vi.mocked(sendRequest).mock.calls.length;
      await vi.advanceTimersByTimeAsync(60_000);
      expect(vi.mocked(sendRequest)).toHaveBeenCalledTimes(requestCount);
    } finally {
      stopAutofill();
      vi.useRealTimers();
    }
  });

  it('tears down an existing inline surface and ignores its late candidate response', async () => {
    let resolveCandidates!: (response: ResponseMessage) => void;
    mockRequests(new Promise<ResponseMessage>((resolve) => { resolveCandidates = resolve; }));
    await startReady('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise((resolve) => setTimeout(resolve, 0));

    mockRequestsWithConfig({
      inlineSuggestions: false,
      pageLoadFill: false,
      saveAllowed: false,
      updateAllowed: false,
    });
    handleContentCommand({ type: 'autofill.clientConfigChanged' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    resolveCandidates({ ok: true, data: [] });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(current.remove).toHaveBeenCalled();
    expect(current.showCandidates).not.toHaveBeenCalled();
  });

  it('fills the sole visible page-load login once without TOTP or form submission', async () => {
    const ackId = '10000000-0000-4000-8000-000000000005';
    const totpCopyAckId = '20000000-0000-4000-8000-000000000005';
    document.body.innerHTML = `
      <form id="login">
        <input autocomplete="username" id="username">
        <input type="password" autocomplete="current-password" id="password">
        <input autocomplete="one-time-code" id="totp">
      </form>`;
    makePageLoadVisible(document.getElementById('username')!);
    makePageLoadVisible(document.getElementById('password')!);
    const submit = vi.fn();
    document.getElementById('login')!.addEventListener('submit', submit);
    mockRequestsWithConfig(
      { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
      { ok: true, data: { intentId: 'page-load-intent' } },
      { ok: true, data: {
        login: { username: 'user', password: 'secret' },
        clientEventAckId: ackId,
        totpCopyAckId,
      } } as ResponseMessage,
      { ok: true, data: null },
      { ok: true, data: { copied: true } },
    );

    await startReady('https://example.com/login');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect((document.getElementById('username') as HTMLInputElement).value).toBe('user');
    expect((document.getElementById('password') as HTMLInputElement).value).toBe('secret');
    expect((document.getElementById('totp') as HTMLInputElement).value).toBe('');
    expect(submit).not.toHaveBeenCalled();
    expect(nonConfigRequests()).toEqual([
      { type: 'autofill.issuePageLoadIntent' },
      { type: 'autofill.redeemPageLoadIntent', intentId: 'page-load-intent' },
      { type: 'clientEvent.ack', ackId },
      { type: 'autofill.ackTotpCopy', ackId: totpCopyAckId },
    ]);

    document.body.append(document.createElement('div'));
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(nonConfigRequests()).toHaveLength(4);
  });

  it('creates one page-load opportunity per exact SPA URL and rejects URL ABA replay', async () => {
    const originalUrl = window.location.href;
    try {
      window.history.replaceState({}, '', '/page-load-a');
      document.body.innerHTML = '<input id="password-a" type="password" autocomplete="current-password">';
      const passwordA = document.getElementById('password-a') as HTMLInputElement;
      makePageLoadVisible(passwordA);
      mockRequestsWithConfig(
        { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
        { ok: true, data: { intentId: 'intent-a' } },
        { ok: true, data: { login: { password: 'secret-a' } } },
        { ok: true, data: { intentId: 'intent-b' } },
        { ok: true, data: { login: { password: 'secret-b' } } },
      );
      await startReady(() => window.location.href);
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(passwordA.value).toBe('secret-a');

      window.history.pushState({}, '', '/page-load-b');
      document.body.innerHTML = '<input id="password-b" type="password" autocomplete="current-password">';
      const passwordB = document.getElementById('password-b') as HTMLInputElement;
      makePageLoadVisible(passwordB);
      await vi.waitFor(() => expect(passwordB.value).toBe('secret-b'));

      window.history.pushState({}, '', '/page-load-a');
      document.body.innerHTML = '<input id="password-a-return" type="password" autocomplete="current-password">';
      const returningPassword = document.getElementById('password-a-return') as HTMLInputElement;
      makePageLoadVisible(returningPassword);
      await new Promise((resolve) => setTimeout(resolve, 150));

      expect(returningPassword.value).toBe('');
      expect(nonConfigRequests().filter((request) => (
        (request as { type?: unknown }).type === 'autofill.issuePageLoadIntent'
      ))).toHaveLength(2);
    } finally {
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('detects a pure pushState URL change through the bounded health poll', async () => {
    vi.useFakeTimers();
    const originalUrl = window.location.href;
    try {
      window.history.replaceState({}, '', '/poll-a');
      document.body.innerHTML = '<input id="poll-password" type="password" autocomplete="current-password">';
      const password = document.getElementById('poll-password') as HTMLInputElement;
      makePageLoadVisible(password);
      mockRequestsWithConfig(
        { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
        { ok: true, data: { intentId: 'poll-a-intent' } },
        { ok: true, data: { login: { password: 'first-secret' } } },
        { ok: true, data: { intentId: 'poll-b-intent' } },
        { ok: true, data: { login: { password: 'second-secret' } } },
      );
      await startReady(() => window.location.href);
      await vi.advanceTimersByTimeAsync(0);
      expect(password.value).toBe('first-secret');

      password.value = '';
      window.history.pushState({}, '', '/poll-b');
      await vi.advanceTimersByTimeAsync(999);
      expect(password.value).toBe('');
      await vi.advanceTimersByTimeAsync(1);

      expect(password.value).toBe('second-secret');
    } finally {
      stopAutofill();
      vi.useRealTimers();
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('drops an old page-load response after pushState establishes a new URL generation', async () => {
    const originalUrl = window.location.href;
    let resolveOldLogin!: (response: ResponseMessage) => void;
    const oldLogin = new Promise<ResponseMessage>((resolve) => { resolveOldLogin = resolve; });
    try {
      window.history.replaceState({}, '', '/page-load-old');
      document.body.innerHTML = '<input id="old-password" type="password" autocomplete="current-password">';
      const oldPassword = document.getElementById('old-password') as HTMLInputElement;
      makePageLoadVisible(oldPassword);
      mockRequestsWithConfig(
        { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
        { ok: true, data: { intentId: 'old-intent' } },
        oldLogin,
        { ok: true, data: { intentId: 'new-intent' } },
        { ok: true, data: { login: { password: 'fresh-secret' } } },
      );
      await startReady(() => window.location.href);
      await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({
        type: 'autofill.redeemPageLoadIntent', intentId: 'old-intent',
      }));

      window.history.pushState({}, '', '/page-load-new');
      document.body.innerHTML = '<input id="new-password" type="password" autocomplete="current-password">';
      const newPassword = document.getElementById('new-password') as HTMLInputElement;
      makePageLoadVisible(newPassword);
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(newPassword.value).toBe('fresh-secret');

      resolveOldLogin({ ok: true, data: { login: { password: 'stale-secret' } } } as ResponseMessage);
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(oldPassword.value).toBe('');
      expect(newPassword.value).toBe('fresh-secret');
    } finally {
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('bounds rapid same-document URL opportunities for the document runtime', async () => {
    const originalUrl = window.location.href;
    let issued = 0;
    try {
      window.history.replaceState({}, '', '/bounded-0');
      document.body.innerHTML = '<input id="bounded-password" type="password" autocomplete="current-password">';
      const password = document.getElementById('bounded-password') as HTMLInputElement;
      makePageLoadVisible(password);
      vi.mocked(sendRequest).mockImplementation(async (request) => {
        if (request.type === 'autofill.getClientConfig') {
          return {
            ok: true,
            data: {
              inlineSuggestions: false,
              pageLoadFill: true,
              saveAllowed: false,
              updateAllowed: false,
              generatorAllowed: false,
              generator: createGeneratorPolicySnapshot(null, 1),
            },
          } as ResponseMessage;
        }
        if (request.type === 'autofill.issuePageLoadIntent') {
          issued += 1;
          return { ok: true, data: { intentId: `bounded-${issued}` } } as ResponseMessage;
        }
        if (request.type === 'autofill.redeemPageLoadIntent') {
          return { ok: true, data: { login: { password: `secret-${issued}` } } } as ResponseMessage;
        }
        return { ok: false, error: { code: 'denied', message: 'unexpected' } } as ResponseMessage;
      });
      await startReady(() => window.location.href);
      await new Promise((resolve) => setTimeout(resolve, 0));

      for (let index = 1; index <= 40; index += 1) {
        password.value = '';
        window.history.pushState({}, '', `/bounded-${index}`);
        window.dispatchEvent(new PopStateEvent('popstate'));
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      expect(issued).toBe(32);
      expect(password.value).toBe('');
    } finally {
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('removes same-document navigation listeners when the runtime stops', async () => {
    const originalUrl = window.location.href;
    try {
      window.history.replaceState({}, '', '/listener-start');
      document.body.replaceChildren();
      mockRequestsWithConfig({
        inlineSuggestions: false,
        pageLoadFill: true,
        saveAllowed: false,
        updateAllowed: false,
      });
      await startReady(() => window.location.href);
      vi.mocked(sendRequest).mockClear();
      stopAutofill();

      window.history.pushState({}, '', '/listener-after-stop');
      window.dispatchEvent(new PopStateEvent('popstate'));
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(sendRequest).not.toHaveBeenCalled();
    } finally {
      window.history.replaceState({}, '', originalUrl);
    }
  });

  it('stops page-load fill before password when username events move the form to another root', async () => {
    const ackId = '10000000-0000-4000-8000-000000000006';
    document.body.innerHTML = `
      <form id="login">
        <input autocomplete="username" id="username">
        <input type="password" autocomplete="current-password" id="password">
      </form>`;
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    document.body.append(host);
    const username = document.getElementById('username') as HTMLInputElement;
    const password = document.getElementById('password') as HTMLInputElement;
    makePageLoadVisible(username);
    makePageLoadVisible(password);
    username.addEventListener('input', () => shadow.append(document.getElementById('login')!), { once: true });
    vi.mocked(setInputValue).mockImplementationOnce((input, value) => {
      input.value = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    mockRequestsWithConfig(
      { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
      { ok: true, data: { intentId: 'page-load-intent' } },
      { ok: true, data: {
        login: { username: 'user', password: 'must-not-fill' },
        clientEventAckId: ackId,
      } } as ResponseMessage,
    );

    await startReady('https://example.com/login');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(username.value).toBe('user');
    expect(password.value).toBe('');
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('stops page-load fill before a password opted out by the username event', async () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="username" id="username">
        <input type="password" autocomplete="current-password" id="password">
      </form>`;
    const username = document.getElementById('username') as HTMLInputElement;
    const password = document.getElementById('password') as HTMLInputElement;
    makePageLoadVisible(username);
    makePageLoadVisible(password);
    username.addEventListener('input', () => password.setAttribute('data-bwignore', ''), { once: true });
    vi.mocked(setInputValue).mockImplementationOnce((input, value) => {
      input.value = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    mockRequestsWithConfig(
      { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
      { ok: true, data: { intentId: 'page-load-intent' } },
      { ok: true, data: { login: { username: 'user', password: 'must-not-fill' } } },
    );

    await startReady('https://example.com/login');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(username.value).toBe('user');
    expect(password.value).toBe('');
  });

  it('does not page-load fill a field replaced while the intent is being redeemed', async () => {
    const ackId = '10000000-0000-4000-8000-000000000007';
    const totpCopyAckId = '20000000-0000-4000-8000-000000000007';
    document.body.innerHTML = '<form><input type="password" autocomplete="current-password" id="password"></form>';
    const original = document.getElementById('password') as HTMLInputElement;
    makePageLoadVisible(original);
    let resolveLogin!: (response: ResponseMessage) => void;
    mockRequestsWithConfig(
      { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
      { ok: true, data: { intentId: 'page-load-intent' } },
      new Promise<ResponseMessage>((resolve) => { resolveLogin = resolve; }),
    );

    await startReady('https://example.com/login');
    await new Promise((resolve) => setTimeout(resolve, 0));
    const replacement = original.cloneNode() as HTMLInputElement;
    makePageLoadVisible(replacement);
    original.replaceWith(replacement);
    resolveLogin({ ok: true, data: {
      login: { password: 'secret' },
      clientEventAckId: ackId,
      totpCopyAckId,
    } } as ResponseMessage);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(original.value).toBe('');
    expect(replacement.value).toBe('');
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'autofill.ackTotpCopy', ackId: totpCopyAckId });
  });

  it('rejects a page-load response that tries to carry custom assignments', async () => {
    document.body.innerHTML = '<form><input type="password" autocomplete="current-password" id="password"><input name="department"></form>';
    makePageLoadVisible(document.getElementById('password')!);
    mockRequestsWithConfig(
      { inlineSuggestions: false, pageLoadFill: true, saveAllowed: false, updateAllowed: false },
      { ok: true, data: { intentId: 'page-load-intent' } },
      { ok: true, data: {
        login: { password: 'must-not-fill' },
        customAssignments: [{ fieldId: 'forged', value: 'must-not-fill' }],
      } } as ResponseMessage,
    );

    await startReady('https://example.com/login');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect((document.getElementById('password') as HTMLInputElement).value).toBe('');
    expect(document.querySelector<HTMLInputElement>('[name=department]')!.value).toBe('');
  });

  it('fills only the right-clicked field on a field-scope command', async () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    const csc = document.getElementById('csc') as HTMLInputElement;
    const reservationId = reserveTarget(csc, 'field', 'card');
    handleContentCommand({ type: 'autofill.fill', reservationId, scope: 'field', kind: 'card', roles: ['code'], expectedFrameUrl: window.location.href, data: { number: '4111', code: '123' } });
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123'); // only the CVC
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');   // number untouched

    csc.value = '';
    handleContentCommand({ type: 'autofill.fill', reservationId, scope: 'field', kind: 'card', roles: ['code'], expectedFrameUrl: window.location.href, data: { code: '999' } });
    expect(csc.value).toBe(''); // the context target was consumed by the first command
  });

  it('reports the exact field and form roles captured by a reservation', () => {
    document.body.innerHTML = `
      <form id="card-form">
        <input autocomplete="cc-name" id="card-name">
        <input autocomplete="cc-number" id="card-number">
        <input autocomplete="cc-exp" id="card-exp">
        <input autocomplete="cc-csc" id="card-code">
      </form>
      <form id="identity-form">
        <input autocomplete="name" id="full-name">
        <input autocomplete="street-address" id="address">
      </form>`;

    trustedContextMenu(document.getElementById('card-code')!);
    expect(reservePendingTarget('field', 'card').result).toEqual({
      status: 'reserved',
      roles: ['code'],
    });

    trustedContextMenu(document.getElementById('card-number')!);
    expect(reservePendingTarget('form', 'card').result).toEqual({
      status: 'reserved',
      roles: ['cardholderName', 'number', 'exp', 'code'],
    });

    trustedContextMenu(document.getElementById('full-name')!);
    expect(reservePendingTarget('field', 'identity').result).toEqual({
      status: 'reserved',
      roles: ['fullName'],
    });

    trustedContextMenu(document.getElementById('address')!);
    expect(reservePendingTarget('form', 'identity').result).toEqual({
      status: 'reserved',
      roles: ['fullName', 'address'],
    });
  });

  it('claims only the exact trusted right-clicked login form for background-coordinated fill', async () => {
    document.body.innerHTML = `
      <form id="login-a">
        <input autocomplete="username" id="username-a">
        <input autocomplete="current-password" id="password-a" type="password">
      </form>
      <form id="login-b">
        <input autocomplete="username" id="username-b">
        <input autocomplete="current-password" id="password-b" type="password">
      </form>`;
    trustedContextMenu(document.getElementById('password-b')!);

    const result = await handleContentCommand({
      type: 'autofill.claimContextLoginTarget',
      expectedFrameUrl: window.location.href,
      contextMenuClickTime: contextClockForTest() + 1,
    });

    expect(result).toMatchObject({
      status: 'claimed',
      generation: expect.any(Number),
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
    });
    const inspection = handleFrameAutofillMessage({ type: 'autofill.inspectFrame' });
    if (!('forms' in inspection)) throw new Error('expected frame inspection');
    const focused = inspection.forms.filter((form) => form.kind === 'login' && form.focusedAt !== undefined);
    expect(focused).toHaveLength(1);
    expect(focused[0]?.kind).toBe('login');
    expect(result.status === 'claimed' ? result.formId : undefined).toBe(focused[0]?.formId);
    await expect(handleContentCommand({
      type: 'autofill.claimContextLoginTarget',
      expectedFrameUrl: window.location.href,
      contextMenuClickTime: contextClockForTest() + 1,
    })).resolves.toEqual({ status: 'no_target' });
  });

  it('rejects a field moved to another form between trusted capture and reserve', () => {
    document.body.innerHTML = `
      <form id="first"><input autocomplete="cc-number" id="target"></form>
      <form id="second"></form>`;
    const target = document.getElementById('target') as HTMLInputElement;
    trustedContextMenu(target);
    document.getElementById('second')!.append(target);

    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });
  });

  it('rejects a field moved to another form between reserve and fill', () => {
    document.body.innerHTML = `
      <form id="first"><input autocomplete="cc-number" id="target"></form>
      <form id="second"></form>`;
    const target = document.getElementById('target') as HTMLInputElement;
    const reservationId = reserveTarget(target, 'field', 'card');
    document.getElementById('second')!.append(target);

    expect(handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(target.value).toBe('');
  });

  it('does not fill a field whose classified role changed after reservation', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="target"></form>';
    const target = document.getElementById('target') as HTMLInputElement;
    const reservationId = reserveTarget(target, 'field', 'card');
    target.autocomplete = 'cc-csc';

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111' },
    });

    expect(target.value).toBe('');
  });

  it('fails closed for a TOTP and card-code autocomplete conflict at capture and recheck', () => {
    document.body.innerHTML = '<form><input id="target" autocomplete="one-time-code cc-csc"></form>';
    const target = document.getElementById('target') as HTMLInputElement;
    trustedContextMenu(target);
    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });

    target.autocomplete = 'cc-csc';
    trustedContextMenu(target);
    target.setAttribute('autocomplete', 'one-time-code cc-csc');
    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });

    target.autocomplete = 'cc-csc';
    const reservationId = reserveTarget(target, 'field', 'card');
    target.setAttribute('autocomplete', 'one-time-code cc-csc');
    expect(handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'field',
      kind: 'card',
      roles: ['code'],
      expectedFrameUrl: window.location.href,
      data: { code: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(target.value).toBe('');
  });

  it('does not reserve or fill a context target carrying data-bwignore', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="target" data-bwignore></form>';
    const target = document.getElementById('target') as HTMLInputElement;
    trustedContextMenu(target);
    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });

    target.removeAttribute('data-bwignore');
    const reservationId = reserveTarget(target, 'field', 'card');
    target.setAttribute('data-bwignore', '');
    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: 'must-not-fill' },
    });
    expect(target.value).toBe('');
  });

  it('rejects a fill command whose roles differ from the reserved form roles', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="number">
        <input autocomplete="cc-csc" id="code">
      </form>`;
    const reservationId = reserveTarget(document.getElementById('number')!, 'form', 'card');

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111' },
    });

    expect((document.getElementById('number') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('code') as HTMLInputElement).value).toBe('');
  });

  it('does not let an untrusted contextmenu event authorize or replace a fill target', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    const number = document.getElementById('num') as HTMLInputElement;
    const csc = document.getElementById('csc') as HTMLInputElement;

    csc.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });
    expect(csc.value).toBe('');

    trustedContextMenu(number);
    csc.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    const reservation = reservePendingTarget('field', 'card');
    expect(reservation.result).toEqual({ status: 'reserved', roles: ['number'] });
    handleContentCommand({ type: 'autofill.fill', reservationId: reservation.reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '4111', code: '123' } });
    expect(number.value).toBe('4111');
    expect(csc.value).toBe('');
  });

  it('single-field fill skips a readonly target', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" id="csc" readonly></form>`;
    const csc = document.getElementById('csc') as HTMLInputElement;
    trustedContextMenu(csc);
    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe(''); // readonly not filled
  });

  it('does not fill a form-scope command without a live right-click target', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    handleContentCommand({
      type: 'autofill.fill',
      reservationId: nextReservationId(),
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111', code: '123' },
    } as Parameters<typeof handleContentCommand>[0]);
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('');
  });

  it('rejects fill data bound to a different frame URL', async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" id="csc"></form>';
    await startReady('https://shop.example/checkout');
    const reservationId = reserveTarget(document.getElementById('num')!, 'form', 'card');

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: 'https://attacker.example/checkout',
      data: { number: '4111', code: '123' },
    } as Parameters<typeof handleContentCommand>[0]);

    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('');

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: window.location.href,
      data: { number: '5555', code: '456' },
    } as Parameters<typeof handleContentCommand>[0]);
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');
  });

  it('shows a notice (no fill) on a fillError command', async () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number" id="num"></form>`;
    const reservationId = reserveTarget(document.getElementById('num')!, 'field', 'card');
    handleContentCommand({ type: 'autofill.fillError', reservationId, expectedFrameUrl: window.location.href, code: 'reprompt_required' });
    handleContentCommand({ type: 'autofill.fill', reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '4111' } });
    expect(document.querySelector('[data-vw-notice]')).toBeTruthy();
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');
  });

  it('form-scope fills the form containing the right-clicked element', async () => {
    document.body.innerHTML = `
      <form id="f1"><input autocomplete="cc-number" id="num1"><input autocomplete="cc-csc" id="csc1"></form>
      <form id="f2"><input autocomplete="cc-number" id="num2"><input autocomplete="cc-csc" id="csc2"></form>`;
    const reservationId = reserveTarget(document.getElementById('num2')!, 'form', 'card');
    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111', code: '123' },
    } as Parameters<typeof handleContentCommand>[0]);
    expect((document.getElementById('num2') as HTMLInputElement).value).toBe('4111'); // clicked form filled
    expect((document.getElementById('num1') as HTMLInputElement).value).toBe('');     // other form untouched
  });

  it('stops a context-menu card fill when the number event moves the reserved CVC', () => {
    document.body.innerHTML = `
      <form id="payment"><input autocomplete="cc-number" id="number"><input autocomplete="cc-csc" id="code"></form>
      <form id="other"></form>`;
    const number = document.getElementById('number') as HTMLInputElement;
    const code = document.getElementById('code') as HTMLInputElement;
    const reservationId = reserveTarget(number, 'form', 'card');
    number.addEventListener('input', () => document.getElementById('other')!.append(code), { once: true });

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111', code: 'must-not-fill' },
    });

    expect(number.value).toBe('4111');
    expect(code.value).toBe('');
  });

  it('stops a context-menu card fill when the number event opts the CVC out', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="number"><input autocomplete="cc-csc" id="code"></form>';
    const number = document.getElementById('number') as HTMLInputElement;
    const code = document.getElementById('code') as HTMLInputElement;
    const reservationId = reserveTarget(number, 'form', 'card');
    number.addEventListener('input', () => code.setAttribute('data-bwignore', ''), { once: true });

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111', code: 'must-not-fill' },
    });

    expect(number.value).toBe('4111');
    expect(code.value).toBe('');
  });

  it('stops a context-menu identity fill when the first field replaces the next target', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name" id="first"><input autocomplete="family-name" id="last"></form>';
    const first = document.getElementById('first') as HTMLInputElement;
    const last = document.getElementById('last') as HTMLInputElement;
    const reservationId = reserveTarget(first, 'form', 'identity');
    first.addEventListener('input', () => last.replaceWith(last.cloneNode()), { once: true });

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'identity',
      roles: ['firstName', 'lastName'],
      expectedFrameUrl: window.location.href,
      data: { firstName: 'Ada', lastName: 'must-not-fill' },
    });

    expect(first.value).toBe('Ada');
    expect(last.value).toBe('');
    expect((document.getElementById('last') as HTMLInputElement).value).toBe('');
  });

  it('accepts a document-bound identity fill command from the background', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="given-name" id="first">
        <input autocomplete="family-name" id="last">
        <input autocomplete="street-address" id="street">
        <input autocomplete="postal-code" id="postal">
      </form>`;
    const reservationId = reserveTarget(document.getElementById('first')!, 'form', 'identity');

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'identity',
      roles: ['firstName', 'lastName', 'address', 'postalCode'],
      expectedFrameUrl: window.location.href,
      data: { firstName: 'Ada', lastName: 'Lovelace', address1: '1 Analytical Way', postalCode: 'EC1' },
    } as Parameters<typeof handleContentCommand>[0]);

    expect((document.getElementById('first') as HTMLInputElement).value).toBe('Ada');
    expect((document.getElementById('last') as HTMLInputElement).value).toBe('Lovelace');
    expect((document.getElementById('street') as HTMLInputElement).value).toBe('1 Analytical Way');
    expect((document.getElementById('postal') as HTMLInputElement).value).toBe('EC1');
  });

  it('reserves and fills a street-address textarea through the composite address role', () => {
    document.body.innerHTML = '<form><textarea autocomplete="street-address" id="address"></textarea></form>';
    const address = document.getElementById('address') as HTMLTextAreaElement;
    const reservationId = reserveTarget(address, 'field', 'identity');

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'field',
      kind: 'identity',
      roles: ['address'],
      expectedFrameUrl: window.location.href,
      data: { address1: '1 Analytical Way', address2: 'Suite 2', address3: 'London' },
    });

    expect(address.value).toBe('1 Analytical Way\nSuite 2\nLondon');
  });

  it('does not fall back to another form after the right-click target disconnects', () => {
    document.body.innerHTML = `
      <form id="original"><input autocomplete="cc-number" id="old-num"><input autocomplete="cc-csc"></form>
      <form><input autocomplete="cc-number" id="new-num"><input autocomplete="cc-csc" id="new-csc"></form>`;
    const original = document.getElementById('original')!;
    const reservationId = reserveTarget(document.getElementById('old-num')!, 'form', 'card');
    original.remove();

    handleContentCommand({ type: 'autofill.fill', reservationId, scope: 'form', kind: 'card', roles: ['number', 'code'], expectedFrameUrl: window.location.href, data: { number: '4111', code: '123' } });

    expect((document.getElementById('new-num') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('new-csc') as HTMLInputElement).value).toBe('');
  });

  it('does not retarget a reserved form after its field moves to another form', () => {
    document.body.innerHTML = `
      <form id="first"><input autocomplete="cc-number" id="moving"><input autocomplete="cc-csc" id="first-code"></form>
      <form id="second"><input autocomplete="cc-number" id="second-number"><input autocomplete="cc-csc" id="second-code"></form>`;
    const moving = document.getElementById('moving') as HTMLInputElement;
    const reservationId = reserveTarget(moving, 'form', 'card');
    document.getElementById('second')!.append(moving);

    handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'form',
      kind: 'card',
      roles: ['number', 'code'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111', code: '123' },
    });

    expect(moving.value).toBe('');
    expect((document.getElementById('first-code') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('second-number') as HTMLInputElement).value).toBe('');
    expect((document.getElementById('second-code') as HTMLInputElement).value).toBe('');
  });

  it('keeps A bound to its click when B is right-clicked before A reserve arrives', () => {
    document.body.innerHTML = `
      <form><input autocomplete="cc-number" id="a"></form>
      <form><input autocomplete="cc-number" id="b"></form>`;
    const a = document.getElementById('a') as HTMLInputElement;
    const b = document.getElementById('b') as HTMLInputElement;
    const clock = vi.spyOn(performance, 'now');
    const origin = performance.timeOrigin;
    clock.mockReturnValue(100);
    trustedContextMenu(a);
    clock.mockReturnValue(200);
    trustedContextMenu(b);
    clock.mockReturnValue(300);

    const aReservation = reservePendingTarget('field', 'card', nextReservationId(), origin + 150);
    const bReservation = reservePendingTarget('field', 'card', nextReservationId(), origin + 250);
    expect(aReservation.result).toEqual({ status: 'reserved', roles: ['number'] });
    expect(bReservation.result).toEqual({ status: 'reserved', roles: ['number'] });

    handleContentCommand({ type: 'autofill.fill', reservationId: bReservation.reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '2222' } });
    handleContentCommand({ type: 'autofill.fill', reservationId: aReservation.reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '1111' } });
    expect(a.value).toBe('1111');
    expect(b.value).toBe('2222');
    clock.mockRestore();
  });

  it('fails closed when a dismissed menu makes the selected target ambiguous', () => {
    document.body.innerHTML = `
      <form><input autocomplete="cc-number" id="a"></form>
      <form><input autocomplete="cc-number" id="b"></form>`;
    const a = document.getElementById('a') as HTMLInputElement;
    const b = document.getElementById('b') as HTMLInputElement;
    const clock = vi.spyOn(performance, 'now');
    const origin = performance.timeOrigin;
    clock.mockReturnValue(100);
    trustedContextMenu(a); // dismissed without an onClicked action
    clock.mockReturnValue(200);
    trustedContextMenu(b);
    clock.mockReturnValue(300);

    const reservation = reservePendingTarget('field', 'card', nextReservationId(), origin + 250);
    expect(reservation.result).toEqual({ status: 'no_target' });
    expect(a.value).toBe('');
    expect(b.value).toBe('');

    trustedContextMenu(b);
    const retry = reservePendingTarget('field', 'card', nextReservationId(), origin + 350);
    expect(retry.result).toEqual({ status: 'reserved', roles: ['number'] });
    handleContentCommand({ type: 'autofill.fill', reservationId: retry.reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '2222' } });
    expect(b.value).toBe('2222');
    clock.mockRestore();
  });

  it('expires both unreserved and reserved context targets', () => {
    vi.useFakeTimers();
    try {
      document.body.innerHTML = '<form><input autocomplete="cc-number" id="number"></form>';
      const number = document.getElementById('number') as HTMLInputElement;
      trustedContextMenu(number);
      vi.advanceTimersByTime(CONTEXT_TARGET_RESERVATION_TTL_MS + 1);
      expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });

      const reservationId = reserveTarget(number, 'field', 'card');
      vi.advanceTimersByTime(CONTEXT_TARGET_RESERVATION_TTL_MS + 1);
      handleContentCommand({ type: 'autofill.fill', reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '4111' } });
      expect(number.value).toBe('');
    } finally {
      vi.useRealTimers();
    }
  });

  it('moves one exact context target into a one-use reprompt hold', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="number"></form>';
    const number = document.getElementById('number') as HTMLInputElement;
    const reservationId = reserveTarget(number, 'field', 'card');
    const holdId = nextReservationId();

    expect(handleContentCommand({
      type: 'autofill.holdFillTarget',
      reservationId,
      holdId,
      expectedFrameUrl: window.location.href,
    })).toEqual({ status: 'held' });
    expect(handleContentCommand({
      type: 'autofill.resumeHeldFillTarget',
      holdId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: '4111' },
    })).toEqual({ status: 'filled' });
    expect(number.value).toBe('4111');

    number.value = '';
    expect(handleContentCommand({
      type: 'autofill.resumeHeldFillTarget',
      holdId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: '9999' },
    })).toEqual({ status: 'no_target' });
    expect(number.value).toBe('');
  });

  it('rejects a held field after its composed slot path changes', () => {
    document.body.replaceChildren();
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<slot name="first"></slot><slot name="second"></slot>';
    const first = shadow.querySelector<HTMLSlotElement>('slot[name="first"]')!;
    const second = shadow.querySelector<HTMLSlotElement>('slot[name="second"]')!;
    const target = document.createElement('input');
    target.autocomplete = 'cc-number';
    host.append(target);
    document.body.append(host);
    Object.defineProperty(target, 'assignedSlot', { configurable: true, value: first });
    const reservationId = reserveTarget(target, 'field', 'card');
    const holdId = nextReservationId();
    expect(handleContentCommand({
      type: 'autofill.holdFillTarget',
      reservationId,
      holdId,
      expectedFrameUrl: window.location.href,
    })).toEqual({ status: 'held' });
    Object.defineProperty(target, 'assignedSlot', { configurable: true, value: second });

    expect(handleContentCommand({
      type: 'autofill.resumeHeldFillTarget',
      holdId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(target.value).toBe('');
  });

  it('rejects a slotted field whose owner changes between trusted capture and reserve', () => {
    document.body.replaceChildren();
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<slot name="first"></slot><slot name="second"></slot>';
    const first = shadow.querySelector<HTMLSlotElement>('slot[name="first"]')!;
    const second = shadow.querySelector<HTMLSlotElement>('slot[name="second"]')!;
    const target = document.createElement('input');
    target.autocomplete = 'cc-number';
    host.append(target);
    document.body.append(host);
    Object.defineProperty(target, 'assignedSlot', { configurable: true, value: first });

    trustedContextMenu(target);
    Object.defineProperty(target, 'assignedSlot', { configurable: true, value: second });

    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });
  });

  it('rejects a slotted field whose owner changes between reserve and fill', () => {
    document.body.replaceChildren();
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<slot name="first"></slot><slot name="second"></slot>';
    const first = shadow.querySelector<HTMLSlotElement>('slot[name="first"]')!;
    const second = shadow.querySelector<HTMLSlotElement>('slot[name="second"]')!;
    const target = document.createElement('input');
    target.autocomplete = 'cc-number';
    host.append(target);
    document.body.append(host);
    Object.defineProperty(target, 'assignedSlot', { configurable: true, value: first });
    const reservationId = reserveTarget(target, 'field', 'card');
    Object.defineProperty(target, 'assignedSlot', { configurable: true, value: second });

    expect(handleContentCommand({
      type: 'autofill.fill',
      reservationId,
      scope: 'field',
      kind: 'card',
      roles: ['number'],
      expectedFrameUrl: window.location.href,
      data: { number: 'must-not-fill' },
    })).toEqual({ status: 'target_changed' });
    expect(target.value).toBe('');
  });

  it('consumes a raw target on page mismatch and preserves B when a reservation id is duplicated', () => {
    document.body.innerHTML = `
      <form><input autocomplete="cc-number" id="a"></form>
      <form><input autocomplete="cc-number" id="b"></form>`;
    const a = document.getElementById('a')!;
    const b = document.getElementById('b')!;
    trustedContextMenu(a);
    const mismatchedId = nextReservationId();
    expect(handleContentCommand({
      type: 'autofill.reserveFillTarget',
      reservationId: mismatchedId,
      scope: 'field',
      kind: 'card',
      expectedFrameUrl: 'https://other.example/',
      contextMenuClickTime: contextClockForTest() + 1,
    })).toEqual({ status: 'page_changed' });
    expect(reservePendingTarget('field', 'card').result).toEqual({ status: 'no_target' });

    const aReservation = reserveTarget(a, 'field', 'card');
    trustedContextMenu(b);
    expect(reservePendingTarget('field', 'card', aReservation).result).toEqual({ status: 'no_target' });
    const bReservation = reservePendingTarget('field', 'card');
    expect(bReservation.result).toEqual({ status: 'reserved', roles: ['number'] });
    handleContentCommand({ type: 'autofill.fill', reservationId: bReservation.reservationId, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '2222' } });
    expect((b as HTMLInputElement).value).toBe('2222');
  });

  it('cancels only the named reservation and rejects a scope upgrade', () => {
    document.body.innerHTML = `
      <form><input autocomplete="cc-number" id="a"><input autocomplete="cc-csc" id="a-code"></form>
      <form><input autocomplete="cc-number" id="b"></form>
      <form><input autocomplete="cc-number" id="c"><input autocomplete="cc-csc" id="c-code"></form>`;
    const a = document.getElementById('a') as HTMLInputElement;
    const b = document.getElementById('b') as HTMLInputElement;
    const c = document.getElementById('c') as HTMLInputElement;
    const aReservation = reserveTarget(a, 'field', 'card');
    const bReservation = reserveTarget(b, 'field', 'card');
    const cReservation = reserveTarget(c, 'field', 'card');

    handleContentCommand({ type: 'autofill.cancelFillTarget', reservationId: aReservation, expectedFrameUrl: window.location.href });
    handleContentCommand({ type: 'autofill.cancelFillTarget', reservationId: aReservation, expectedFrameUrl: window.location.href });
    handleContentCommand({ type: 'autofill.fill', reservationId: aReservation, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '1111' } });
    handleContentCommand({ type: 'autofill.fill', reservationId: bReservation, scope: 'field', kind: 'card', roles: ['number'], expectedFrameUrl: window.location.href, data: { number: '2222' } });
    handleContentCommand({ type: 'autofill.fill', reservationId: cReservation, scope: 'form', kind: 'card', roles: ['number', 'code'], expectedFrameUrl: window.location.href, data: { number: '3333', code: '123' } });

    expect(a.value).toBe('');
    expect(b.value).toBe('2222');
    expect(c.value).toBe('');
    expect((document.getElementById('c-code') as HTMLInputElement).value).toBe('');
  });

  it('allows a form-scope reservation from an unclassified field in the same native form', () => {
    document.body.innerHTML = `
      <form>
        <input name="promo" id="promo">
        <input autocomplete="cc-number" id="number">
        <input autocomplete="cc-csc" id="code">
      </form>`;
    const reservationId = reserveTarget(document.getElementById('promo')!, 'form', 'card');

    handleContentCommand({ type: 'autofill.fill', reservationId, scope: 'form', kind: 'card', roles: ['number', 'code'], expectedFrameUrl: window.location.href, data: { number: '4111', code: '123' } });

    expect((document.getElementById('number') as HTMLInputElement).value).toBe('4111');
    expect((document.getElementById('code') as HTMLInputElement).value).toBe('123');
  });
});

function popover(): FakePopover {
  const current = popoverState.instances.at(-1);
  if (!current) throw new Error('Expected popover to exist');
  return current;
}

function malformedOk(data: unknown): ResponseMessage {
  return { ok: true, data } as ResponseMessage;
}

const ENABLED_CLIENT_CONFIG = {
  ok: true,
  data: {
    inlineSuggestions: true,
    pageLoadFill: false,
    saveAllowed: true,
    updateAllowed: true,
    generatorAllowed: true,
    generator: createGeneratorPolicySnapshot(null, 1),
  },
} as const satisfies ResponseMessage;

function mockRequests(...responses: Array<ResponseMessage | Promise<ResponseMessage>>): void {
  mockRequestsWithConfig(ENABLED_CLIENT_CONFIG.data, ...responses);
}

function mockRequestsWithConfig(
  config: Omit<AutofillClientConfig, 'generator' | 'generatorAllowed'>
    & Partial<Pick<AutofillClientConfig, 'generator' | 'generatorAllowed'>>,
  ...responses: Array<ResponseMessage | Promise<ResponseMessage>>
): void {
  let index = 0;
  const completeConfig: AutofillClientConfig = {
    generator: createGeneratorPolicySnapshot(null, 1),
    generatorAllowed: config.generatorAllowed ?? config.saveAllowed,
    ...config,
  };
  vi.mocked(sendRequest).mockImplementation((request) => {
    if (request.type === 'autofill.getClientConfig') return Promise.resolve({ ok: true, data: completeConfig });
    if (request.type === 'autofill.authorizeGeneratorUse') {
      return Promise.resolve({
        ok: true,
        data: { trackToken: '40000000-0000-4000-8000-000000000001' },
      });
    }
    if (request.type === 'autofill.trackGeneratedValue') {
      return Promise.resolve({ ok: true, data: { added: true } });
    }
    if (request.type === 'autofill.claimSavePrompt') {
      return Promise.resolve({ ok: true, data: { action: 'none' } });
    }
    const response = responses[index++];
    const fallback: ResponseMessage = { ok: false, error: { code: 'error', message: 'No mocked response' } };
    return Promise.resolve(response ?? fallback)
      .then((resolved) => withInteractiveAssignments(request.type, resolved));
  });
}

function withInteractiveAssignments(type: string, response: ResponseMessage): ResponseMessage {
  if (type !== 'autofill.redeemLoginIntent' || !response.ok || !isTestRecord(response.data) || !('login' in response.data)) {
    return response;
  }
  return { ok: true, data: { ...response.data, customAssignments: [] } } as ResponseMessage;
}

function isTestRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonConfigRequests(): unknown[] {
  return vi.mocked(sendRequest).mock.calls
    .map(([request]) => request)
    .filter((request) => request.type !== 'autofill.getClientConfig' && request.type !== 'autofill.claimSavePrompt')
    .map((request) => request.type === 'autofill.issueIntent' && request.purpose === 'login'
      ? { type: request.type, cipherId: request.cipherId, purpose: request.purpose }
      : request);
}

function requestsOfType(type: string): unknown[] {
  return vi.mocked(sendRequest).mock.calls
    .map(([request]) => request)
    .filter((request) => request.type === type);
}

function dispatchPageTransition(type: 'pagehide' | 'pageshow', persisted: boolean): void {
  const event = new PageTransitionEvent(type);
  Object.defineProperty(event, 'persisted', { value: persisted });
  window.dispatchEvent(event);
}

async function flushRuntimeStart(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

function makePageLoadVisible(element: Element): void {
  vi.spyOn(element, 'getClientRects').mockReturnValue([
    { x: 10, y: 10, left: 10, top: 10, right: 210, bottom: 42, width: 200, height: 32, toJSON: () => ({}) },
  ] as unknown as DOMRectList);
}

async function startReady(frameUrl: string | (() => string) = () => window.location.href): Promise<void> {
  startAutofill(frameUrl);
  runtimeStartedForTest = true;
  await Promise.resolve();
  await Promise.resolve();
}

let runtimeStartedForTest = false;

function trustedContextMenu(target: Element): void {
  if (!runtimeStartedForTest) {
    startAutofill(() => window.location.href);
    runtimeStartedForTest = true;
  }
  trustedPageEvent(target, new MouseEvent('contextmenu', {
    bubbles: true,
    cancelable: true,
    composed: true,
  }));
}

function trustedPageEvent(target: EventTarget, event: Event): void {
  Object.defineProperty(event, 'isTrusted', { value: true });
  target.dispatchEvent(event);
}

let reservationSequence = 0;

function nextReservationId(): string {
  reservationSequence += 1;
  return `00000000-0000-4000-8000-${String(reservationSequence).padStart(12, '0')}`;
}

function contextClockForTest(): number {
  return performance.timeOrigin + performance.now();
}

function reservePendingTarget(
  scope: 'form' | 'field',
  kind: 'card' | 'identity',
  reservationId = nextReservationId(),
  contextMenuClickTime = contextClockForTest() + 1,
) {
  return {
    reservationId,
    result: handleContentCommand({
      type: 'autofill.reserveFillTarget',
      reservationId,
      scope,
      kind,
      expectedFrameUrl: window.location.href,
      contextMenuClickTime,
    }),
  };
}

function reserveTarget(target: Element, scope: 'form' | 'field', kind: 'card' | 'identity'): string {
  trustedContextMenu(target);
  const reservation = reservePendingTarget(scope, kind);
  expect(reservation.result?.status).toBe('reserved');
  return reservation.reservationId;
}

describe('focused-fill command', () => {
  const commandToken = '00000000-0000-4000-8000-000000000101';
  const keyboardGrantId = '00000000-0000-4000-8000-000000000102';
  beforeEach(() => {
    stopAutofill();
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    popoverRegistry.clear();
    popoverState.instances.length = 0;
    vi.mocked(sendRequest).mockReset();
    vi.mocked(fillLoginForm).mockReset();
    vi.mocked(fillLoginForm).mockReturnValue(true);
  });

  it('acknowledges focus only from the exact current document URL', async () => {
    await expect(handleContentCommand({
      type: 'autofill.awaitFocus',
      requestId: nextReservationId(),
      expectedFrameUrl: window.location.href,
      expiresAt: Date.now() + 1_000,
    })).resolves.toEqual({ status: 'focused' });
    await expect(handleContentCommand({
      type: 'autofill.awaitFocus',
      requestId: nextReservationId(),
      expectedFrameUrl: 'https://other.example/',
      expiresAt: Date.now() + 1_000,
    })).resolves.toEqual({ status: 'stale' });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does nothing when the frame is not focused', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(false);
    await handleFocusedFill(() => 'https://ex.com', commandToken);
    expect(sendRequest).not.toHaveBeenCalled();
  });

  it('does nothing (no notice) when the active element is a nested frame', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    const iframe = document.createElement('iframe');
    document.body.append(iframe);
    iframe.focus();
    vi.spyOn(document, 'activeElement', 'get').mockReturnValue(iframe);
    await handleFocusedFill(() => 'https://ex.com', commandToken);
    expect(sendRequest).not.toHaveBeenCalled();
  });

  it('fills a login when the focused password field has one match', async () => {
    const ackId = '10000000-0000-4000-8000-000000000008';
    const totpCopyAckId = '20000000-0000-4000-8000-000000000008';
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    vi.mocked(fillLoginForm).mockReturnValue(true);
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: { keyboardGrantId } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'c1', name: 'A', username: 'u', matchedUri: 'x', matchType: 0, favorite: false }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { intentId: 'login-intent' } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: {
        login: { username: 'u', password: 'p' },
        clientEventAckId: ackId,
        totpCopyAckId,
      } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: null } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { copied: true } } as ResponseMessage);
    await handleFocusedFill(() => 'https://ex.com', commandToken);
    expect(sendRequest).toHaveBeenNthCalledWith(1, expect.objectContaining({
      type: 'autofill.claimKeyboardGrant', commandToken, binding: expect.objectContaining({ purpose: 'login' }),
    }));
    expect(sendRequest).toHaveBeenNthCalledWith(2, { type: 'autofill.keyboard.findCandidates', keyboardGrantId });
    expect(sendRequest).toHaveBeenNthCalledWith(3, { type: 'autofill.keyboard.issueIntent', keyboardGrantId, cipherId: 'c1' });
    expect(sendRequest).toHaveBeenNthCalledWith(4, { type: 'autofill.keyboard.redeemLoginIntent', intentId: 'login-intent' });
    expect(sendRequest).toHaveBeenNthCalledWith(5, { type: 'clientEvent.ack', ackId });
    expect(sendRequest).toHaveBeenNthCalledWith(6, { type: 'autofill.ackTotpCopy', ackId: totpCopyAckId });
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(1);
  });

  it('does not acknowledge a keyboard login when the DOM fill reports failure', async () => {
    const ackId = '10000000-0000-4000-8000-000000000012';
    const totpCopyAckId = '20000000-0000-4000-8000-000000000012';
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    vi.mocked(fillLoginForm).mockReturnValue(false);
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: { keyboardGrantId } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: [{
        id: 'c1', name: 'A', username: 'u', matchedUri: 'x', matchType: 0, favorite: false,
      }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { intentId: 'login-intent' } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: {
        login: { username: 'u', password: 'p' },
        clientEventAckId: ackId,
        totpCopyAckId,
      } } as ResponseMessage);

    await handleFocusedFill(() => 'https://ex.com', commandToken);

    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'autofill.ackTotpCopy', ackId: totpCopyAckId });
  });

  it('fills custom login assignments through the focused-fill shortcut', async () => {
    document.body.innerHTML = '<form><input name="username"><input type="password"><input name="realm"></form>';
    await startReady('https://ex.com');
    document.querySelector<HTMLInputElement>('input[type=password]')!.focus();
    let fieldId = '';
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return ENABLED_CLIENT_CONFIG;
      if (request.type === 'autofill.claimKeyboardGrant' && request.binding.purpose === 'login') {
        fieldId = request.binding.customPlan.targets[0]!.fieldId;
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') return { ok: true, data: [{
        id: 'c1', name: 'Example', matchedUri: 'https://ex.com', matchType: 0, favorite: false,
      }] } as ResponseMessage;
      if (request.type === 'autofill.keyboard.issueIntent') {
        return { ok: true, data: { intentId: 'focused-custom' } };
      }
      if (request.type === 'autofill.keyboard.redeemLoginIntent') return { ok: true, data: {
        login: { username: 'u', password: 'p' },
        customAssignments: [{ fieldId, value: 'production' }],
      } } as ResponseMessage;
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });
    vi.mocked(fillLoginForm).mockReturnValue(true);

    await handleFocusedFill(() => 'https://ex.com', commandToken);

    expect(document.querySelector<HTMLInputElement>('[name=realm]')!.value).toBe('production');
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(1);
  });

  it('cycles multiple login matches while issuing a fresh one-time intent each round', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    const issuedCipherIds: string[] = [];
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.claimKeyboardGrant') {
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') {
        return { ok: true, data: [
          { id: 'a', name: 'A', username: 'ua', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
          { id: 'b', name: 'B', username: 'ub', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
          { id: 'c', name: 'C', username: 'uc', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
        ] } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.issueIntent') {
        issuedCipherIds.push(request.cipherId);
        return { ok: true, data: { intentId: `intent-${request.cipherId}-${issuedCipherIds.length}` } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.redeemLoginIntent') {
        return { ok: true, data: { login: { username: request.intentId, password: 'fresh-secret' } } } as ResponseMessage;
      }
      throw new Error(`unexpected request: ${request.type}`);
    });

    await handleFocusedFill(() => 'https://ex.com', commandToken);
    await handleFocusedFill(() => 'https://ex.com', commandToken);
    await handleFocusedFill(() => 'https://ex.com', commandToken);
    await handleFocusedFill(() => 'https://ex.com', commandToken);

    expect(issuedCipherIds).toEqual(['a', 'b', 'c', 'a']);
    expect(vi.mocked(sendRequest).mock.calls.filter(([request]) => request.type === 'autofill.keyboard.findCandidates')).toHaveLength(4);
    expect(vi.mocked(sendRequest).mock.calls.filter(([request]) => request.type === 'autofill.keyboard.redeemLoginIntent')).toHaveLength(4);
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(4);
  });

  it('serializes rapid shortcut presses so candidate advancement cannot race', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    let releaseFirstRedeem: ((response: ResponseMessage) => void) | undefined;
    const firstRedeem = new Promise<ResponseMessage>((resolve) => { releaseFirstRedeem = resolve; });
    const issuedCipherIds: string[] = [];
    let redeemCount = 0;
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.claimKeyboardGrant') {
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') {
        return { ok: true, data: [
          { id: 'a', name: 'A', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
          { id: 'b', name: 'B', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
        ] } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.issueIntent') {
        issuedCipherIds.push(request.cipherId);
        return { ok: true, data: { intentId: `intent-${request.cipherId}` } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.redeemLoginIntent') {
        redeemCount += 1;
        if (redeemCount === 1) return firstRedeem;
        return { ok: true, data: { login: { username: request.intentId, password: 'second-secret' } } } as ResponseMessage;
      }
      throw new Error(`unexpected request: ${request.type}`);
    });

    const first = handleFocusedFill(() => 'https://ex.com', commandToken);
    const second = handleFocusedFill(() => 'https://ex.com', commandToken);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(issuedCipherIds).toEqual(['a']);
    expect(vi.mocked(sendRequest).mock.calls.filter(([request]) => request.type === 'autofill.keyboard.findCandidates')).toHaveLength(1);
    releaseFirstRedeem?.({ ok: true, data: { login: { username: 'first', password: 'first-secret' } } } as ResponseMessage);
    await Promise.all([first, second]);

    expect(issuedCipherIds).toEqual(['a', 'b']);
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(2);
  });

  it('drops in-flight and queued shortcut work when teardown changes the runtime generation', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    let resolveCandidates: ((response: ResponseMessage) => void) | undefined;
    const candidates = new Promise<ResponseMessage>((resolve) => { resolveCandidates = resolve; });
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.claimKeyboardGrant') {
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') return candidates;
      if (request.type === 'autofill.keyboard.issueIntent') {
        return { ok: true, data: { intentId: 'must-not-be-issued' } } as ResponseMessage;
      }
      throw new Error(`unexpected request: ${request.type}`);
    });

    const first = handleFocusedFill(() => 'https://ex.com', commandToken);
    const second = handleFocusedFill(() => 'https://ex.com', commandToken);
    await new Promise((resolve) => setTimeout(resolve, 0));
    stopAutofill();
    resolveCandidates?.({ ok: true, data: [
      { id: 'a', name: 'A', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
      { id: 'b', name: 'B', matchedUri: 'https://ex.com', matchType: 0, favorite: false },
    ] } as ResponseMessage);
    await Promise.all([first, second]);

    expect(vi.mocked(sendRequest).mock.calls.filter(([request]) => request.type === 'autofill.keyboard.findCandidates')).toHaveLength(1);
    expect(vi.mocked(sendRequest).mock.calls.some(([request]) => request.type === 'autofill.keyboard.issueIntent')).toBe(false);
    expect(vi.mocked(fillLoginForm)).not.toHaveBeenCalled();
  });

  it('uses only the TOTP intent path when the focused field is a verification code', async () => {
    const ackId = '10000000-0000-4000-8000-000000000009';
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"><input autocomplete="one-time-code" id="otp"></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    input.focus();
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: { keyboardGrantId } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'c1', name: 'A', matchedUri: 'x', matchType: 0, favorite: false, hasTotp: true }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { intentId: 'totp-intent' } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: {
        totp: { code: '123456', period: 30, remaining: 12 },
        clientEventAckId: ackId,
      } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: null } as ResponseMessage);

    await handleFocusedFill(() => 'https://ex.com', commandToken);

    expect(sendRequest).toHaveBeenNthCalledWith(1, {
      type: 'autofill.claimKeyboardGrant', commandToken, binding: { purpose: 'totp' },
    });
    expect(sendRequest).toHaveBeenNthCalledWith(2, { type: 'autofill.keyboard.findCandidates', keyboardGrantId });
    expect(sendRequest).toHaveBeenNthCalledWith(3, { type: 'autofill.keyboard.issueIntent', keyboardGrantId, cipherId: 'c1' });
    expect(sendRequest).toHaveBeenNthCalledWith(4, { type: 'autofill.keyboard.redeemTotpIntent', intentId: 'totp-intent' });
    expect(sendRequest).toHaveBeenNthCalledWith(5, { type: 'clientEvent.ack', ackId });
    expect(sendRequest).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'autofill.keyboard.redeemLoginIntent' }));
    expect(input.value).toBe('123456');
    expect(vi.mocked(fillLoginForm)).not.toHaveBeenCalled();
  });

  it('drops a held TOTP when an SPA navigation wins during secret redemption', async () => {
    const ackId = '10000000-0000-4000-8000-000000000010';
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    vi.mocked(fillTotpCode).mockClear();
    document.body.innerHTML = '<form><input autocomplete="one-time-code" id="otp"><button>Verify</button></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    input.focus();
    const sourceUrl = window.location.href;
    const continuationId = '00000000-0000-4000-8000-000000000103';
    const heldIntentId = '00000000-0000-4000-8000-000000000104';
    let resolveTotp!: (response: ResponseMessage) => void;
    const pendingTotp = new Promise<ResponseMessage>((resolve) => { resolveTotp = resolve; });
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.claimKeyboardGrant') {
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') {
        return { ok: true, data: [{
          id: 'protected-totp', name: 'Protected', matchedUri: sourceUrl,
          matchType: 0, favorite: false, hasTotp: true, reprompt: true,
        }] } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.issueIntent') {
        return { ok: true, data: { repromptContinuationId: continuationId } } as ResponseMessage;
      }
      if (request.type === 'autofill.continuation.redeemKeyboardReprompt') {
        return { ok: true, data: { intentId: heldIntentId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.redeemTotpIntent') return pendingTotp;
      throw new Error(`unexpected request: ${request.type}`);
    });

    await handleFocusedFill(() => sourceUrl, commandToken);
    handleContentCommand({
      type: 'autofill.resumeKeyboardReprompt',
      continuationId,
      expectedFrameUrl: sourceUrl,
    });
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({
      type: 'autofill.keyboard.redeemTotpIntent',
      intentId: heldIntentId,
    }));
    window.history.pushState(null, '', `${window.location.pathname}?route=next`);
    resolveTotp({
      ok: true,
      data: {
        totp: { code: 'must-not-fill', period: 30, remaining: 12 },
        clientEventAckId: ackId,
      },
    } as ResponseMessage);
    await Promise.resolve();
    await Promise.resolve();

    expect(input.value).toBe('');
    expect(fillTotpCode).not.toHaveBeenCalled();
    expect(sendRequest).not.toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId });
  });

  it('acknowledges a reprompted keyboard TOTP only after its held target is filled', async () => {
    const ackId = '10000000-0000-4000-8000-000000000011';
    const continuationId = '00000000-0000-4000-8000-000000000105';
    const heldIntentId = '00000000-0000-4000-8000-000000000106';
    const sourceUrl = window.location.href;
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.body.innerHTML = '<form><input autocomplete="one-time-code" id="otp"><button>Verify</button></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    input.focus();
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.claimKeyboardGrant') {
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') {
        return { ok: true, data: [{
          id: 'protected-totp', name: 'Protected', matchedUri: sourceUrl,
          matchType: 0, favorite: false, hasTotp: true, reprompt: true,
        }] } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.issueIntent') {
        return { ok: true, data: { repromptContinuationId: continuationId } } as ResponseMessage;
      }
      if (request.type === 'autofill.continuation.redeemKeyboardReprompt') {
        return { ok: true, data: { intentId: heldIntentId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.redeemTotpIntent') {
        return { ok: true, data: {
          totp: { code: '654321', period: 30, remaining: 12 },
          clientEventAckId: ackId,
        } } as ResponseMessage;
      }
      if (request.type === 'clientEvent.ack') return { ok: true, data: null } as ResponseMessage;
      throw new Error(`unexpected request: ${request.type}`);
    });

    await handleFocusedFill(() => sourceUrl, commandToken);
    handleContentCommand({
      type: 'autofill.resumeKeyboardReprompt',
      continuationId,
      expectedFrameUrl: sourceUrl,
    });
    await vi.waitFor(() => expect(sendRequest).toHaveBeenCalledWith({ type: 'clientEvent.ack', ackId }));

    expect(input.value).toBe('654321');
  });

  it('cycles TOTP matches with a fresh TOTP-only ticket for every candidate', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.body.innerHTML = '<form><input autocomplete="one-time-code" id="otp"><button>Verify</button></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    input.focus();
    const issuedCipherIds: string[] = [];
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.claimKeyboardGrant') {
        expect(request.binding.purpose).toBe('totp');
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') {
        return { ok: true, data: [
          { id: 'a', name: 'A', matchedUri: 'https://ex.com', matchType: 0, favorite: false, hasTotp: true },
          { id: 'b', name: 'B', matchedUri: 'https://ex.com', matchType: 0, favorite: false, hasTotp: true },
        ] } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.issueIntent') {
        issuedCipherIds.push(request.cipherId);
        return { ok: true, data: { intentId: `totp-${request.cipherId}` } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.redeemTotpIntent') {
        return { ok: true, data: { totp: { code: request.intentId, period: 30, remaining: 12 } } } as ResponseMessage;
      }
      throw new Error(`unexpected request: ${request.type}`);
    });

    await handleFocusedFill(() => 'https://ex.com', commandToken);
    await handleFocusedFill(() => 'https://ex.com', commandToken);

    expect(issuedCipherIds).toEqual(['a', 'b']);
    expect(input.value).toBe('totp-b');
    expect(vi.mocked(sendRequest).mock.calls.some(([request]) => request.type === 'autofill.keyboard.redeemLoginIntent')).toBe(false);
    expect(vi.mocked(fillLoginForm)).not.toHaveBeenCalled();
  });

  it('fills a focused card through an opaque structured intent without returning secrets', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"></form>';
    document.querySelector<HTMLInputElement>('input[autocomplete="cc-number"]')!.focus();
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: { keyboardGrantId } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'card-1', name: 'Card', favorite: false }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { intentId: 'structured-intent' } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { outcome: { status: 'filled' } } } as ResponseMessage);

    await handleFocusedFill(() => 'https://shop.example/checkout', commandToken);

    const claim = vi.mocked(sendRequest).mock.calls[0]![0];
    expect(claim).toMatchObject({
      type: 'autofill.claimKeyboardGrant',
      commandToken,
      binding: { purpose: 'card', structuredTarget: { kind: 'card', roles: ['number', 'exp', 'code'] } },
    });
    expect(sendRequest).toHaveBeenNthCalledWith(2, { type: 'autofill.keyboard.findCandidates', keyboardGrantId });
    expect(sendRequest).toHaveBeenNthCalledWith(3, {
      type: 'autofill.keyboard.issueIntent', keyboardGrantId, cipherId: 'card-1',
    });
    expect(sendRequest).toHaveBeenNthCalledWith(4, {
      type: 'autofill.keyboard.redeemStructuredIntent',
      intentId: 'structured-intent',
      target: claim.type === 'autofill.claimKeyboardGrant' && 'structuredTarget' in claim.binding
        ? claim.binding.structuredTarget
        : undefined,
    });
  });

  it('binds a focused identity fill to only the roles present in that form', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"><input autocomplete="email"></form>';
    document.querySelector<HTMLInputElement>('input[autocomplete="street-address"]')!.focus();
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: { keyboardGrantId } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'identity-1', name: 'Personal', favorite: false }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { intentId: 'identity-intent' } } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { outcome: { status: 'filled' } } } as ResponseMessage);

    await handleFocusedFill(() => 'https://shop.example/checkout', commandToken);

    expect(sendRequest).toHaveBeenNthCalledWith(1, expect.objectContaining({
      type: 'autofill.claimKeyboardGrant',
      binding: expect.objectContaining({
        purpose: 'identity',
        structuredTarget: expect.objectContaining({
          kind: 'identity',
          roles: ['firstName', 'lastName', 'address', 'email'],
        }),
      }),
    }));
    expect(sendRequest).toHaveBeenNthCalledWith(3, expect.objectContaining({
      type: 'autofill.keyboard.issueIntent',
      cipherId: 'identity-1',
    }));
  });

  it('keeps a one-shot structured picker usable when inline suggestions are disabled', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    vi.mocked(sendRequest).mockImplementation(async (request) => {
      if (request.type === 'autofill.getClientConfig') return { ok: true, data: {
        inlineSuggestions: false, pageLoadFill: false, saveAllowed: true, updateAllowed: true,
      } } as ResponseMessage;
      if (request.type === 'autofill.claimKeyboardGrant') {
        return { ok: true, data: { keyboardGrantId } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.findCandidates') {
        return { ok: true, data: [
          { id: 'one', name: 'One', favorite: false },
          { id: 'two', name: 'Two', favorite: false },
        ] } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.issueIntent') {
        return { ok: true, data: { intentId: 'picker-intent' } } as ResponseMessage;
      }
      if (request.type === 'autofill.keyboard.redeemStructuredIntent') {
        return { ok: true, data: { outcome: { status: 'filled' } } } as ResponseMessage;
      }
      return { ok: false, error: { code: 'error', message: 'unexpected request' } };
    });
    await startReady('https://shop.example/checkout');
    const input = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    input.focus();

    await handleFocusedFill(() => 'https://shop.example/checkout', commandToken);

    const cardPickers = popoverState.instances.filter((entry) => (
      entry.options.kind === 'card' && entry.element.isConnected
    ));
    expect(cardPickers).toHaveLength(1);
    expect(cardPickers[0]!.open).toHaveBeenCalledOnce();
    expect(cardPickers[0]!.open).toHaveBeenCalledWith(input, { focusList: true });
    expect(vi.mocked(sendRequest).mock.calls.some(([request]) => request.type === 'autofill.keyboard.issueIntent')).toBe(false);

    const configRequestsBeforeRestore = vi.mocked(sendRequest).mock.calls
      .filter(([request]) => request.type === 'autofill.getClientConfig').length;
    expect(cardPickers[0]!.options.beforeFocusRestore).toBeTypeOf('function');
    const clearFocusRestore = cardPickers[0]!.options.beforeFocusRestore!(input);
    trustedPageEvent(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
    clearFocusRestore();
    await Promise.resolve();
    expect(vi.mocked(sendRequest).mock.calls
      .filter(([request]) => request.type === 'autofill.getClientConfig')).toHaveLength(configRequestsBeforeRestore);

    cardPickers[0]!.options.onSelect('two');
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(sendRequest).toHaveBeenCalledWith({
      type: 'autofill.keyboard.issueIntent', keyboardGrantId, cipherId: 'two',
    });
    expect(cardPickers[0]!.showFilled).toHaveBeenCalledOnce();
  });

  it('openPickerFor opens a registered, connected popover', () => {
    const el = document.createElement('div');
    document.documentElement.append(el);
    const open = vi.fn();
    popoverRegistry.set('f1', { element: el, open, remove: vi.fn() } as never);
    openPickerFor(() => 'https://ex.com', 'f1');
    expect(open).toHaveBeenCalledWith(undefined, { focusList: true });
  });

  it('openPickerFor notices when no popover can be found after re-attach', () => {
    const notice = vi.spyOn(noticeModule, 'showNotice');
    openPickerFor(() => 'https://ex.com', 'missing');
    expect(notice).toHaveBeenCalledWith('多个匹配项——点击输入框的密屿图标选择');
  });
});

describe('frame inspect/commit messages', () => {
  beforeEach(() => {
    document.body.innerHTML = '<form id="login"><input type="email"><input type="password"></form>';
    vi.mocked(sendRequest).mockReset();
    vi.mocked(fillLoginForm).mockReset();
  });

  it('inspectFrame reports the frame URL and detected login-form metadata only', () => {
    startAutofill('https://example.com/login');
    const result = handleFrameAutofillMessage({ type: 'autofill.inspectFrame' });
    if (!('forms' in result)) throw new Error('expected a frame inspection');
    expect(result.frameUrl).toBe('https://example.com/login');
    expect(result.forms.length).toBeGreaterThan(0);
    // Metadata only: the inspection never carries field values or credentials.
    expect(JSON.stringify(result)).not.toContain('password');
  });

  it('commitLoginFill fills the matching form and reports filled', () => {
    startAutofill('https://example.com/login');
    vi.mocked(fillLoginForm).mockReturnValue(true);
    const inspection = handleFrameAutofillMessage({ type: 'autofill.inspectFrame' });
    if (!('forms' in inspection)) throw new Error('expected a frame inspection');
    const formId = inspection.forms[0]!.formId;
    const loginForm = inspection.forms.find((form) => form.kind === 'login');
    if (!loginForm || loginForm.kind !== 'login') throw new Error('expected a login form');
    const outcome = handleFrameAutofillMessage({
      type: 'autofill.commitLoginFill',
      formId,
      expectedFrameUrl: 'https://example.com/login',
      expectedGeneration: inspection.generation,
      login: { username: 'u', password: 'p' },
      customPlan: loginForm.customPlan,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
      customAssignments: [],
    });
    expect(outcome).toEqual({ status: 'filled' });
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(1);
  });

  it('commitStructuredFill fills only the freshly inspected card target', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="number"><input autocomplete="cc-csc" id="code"></form>';
    startAutofill('https://example.com/checkout');
    const inspection = handleFrameAutofillMessage({ type: 'autofill.inspectFrame' });
    if (!('forms' in inspection)) throw new Error('expected a frame inspection');
    const card = inspection.forms.find((form) => form.kind === 'card');
    if (!card || card.kind !== 'card') throw new Error('expected a card form');

    const outcome = handleFrameAutofillMessage({
      type: 'autofill.commitStructuredFill',
      kind: 'card',
      formId: card.formId,
      roles: card.roles,
      expectedFrameUrl: inspection.frameUrl,
      expectedGeneration: inspection.generation,
      data: { number: '4111', code: '123' },
    });

    expect(outcome).toEqual({ status: 'filled' });
    expect((document.getElementById('number') as HTMLInputElement).value).toBe('4111');
    expect((document.getElementById('code') as HTMLInputElement).value).toBe('123');
  });

  it('commitLoginFill reports target_changed and fills nothing when the frame URL no longer matches', () => {
    startAutofill('https://example.com/login');
    const outcome = handleFrameAutofillMessage({
      type: 'autofill.commitLoginFill',
      formId: 'login',
      expectedFrameUrl: 'https://different.example/login',
      expectedGeneration: 1,
      login: { username: 'u', password: 'p' },
      customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
      customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
      customAssignments: [],
    });
    expect(outcome).toEqual({ status: 'target_changed' });
    expect(vi.mocked(fillLoginForm)).not.toHaveBeenCalled();
  });
});
