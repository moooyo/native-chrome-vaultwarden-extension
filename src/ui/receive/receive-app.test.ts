// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import browser from 'webextension-polyfill';

vi.mock('webextension-polyfill', () => ({
  default: {
    permissions: {
      contains: vi.fn(async () => false),
      request: vi.fn(async () => true),
      remove: vi.fn(async () => true),
      onAdded: { addListener: vi.fn(), removeListener: vi.fn() },
    },
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

import './receive-app.js';
import type { VwReceiveApp } from './receive-app.js';
import type { OriginPermissionGrant, ReceiveDeps } from './types.js';
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

function emailChallengeRes(kind: 'email_required' | 'email_and_otp_required'): Response {
  return jsonRes({
    error: 'invalid_request',
    error_description: kind === 'email_required'
      ? 'email is required.'
      : 'email and otp are required.',
    send_access_error_type: kind,
  }, 400);
}

type FetchImpl = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

interface DepStubs {
  deps: ReceiveDeps;
  requestOrigin: ReturnType<typeof vi.fn>;
  removeOrigin: ReturnType<typeof vi.fn>;
  download: ReturnType<typeof vi.fn>;
  fetchCalls: string[];
  fetchRequests: Array<{ url: string; init?: RequestInit }>;
}

function makeDeps(overrides: Partial<{
  requestOriginResult: boolean;
  newlyGrantedResult: boolean;
  removeOriginResult: boolean;
  fetchImpl: FetchImpl;
  sendTokenImpl: FetchImpl;
}> = {}): DepStubs {
  const fetchCalls: string[] = [];
  const fetchRequests: Array<{ url: string; init?: RequestInit }> = [];
  const fetchImpl = overrides.fetchImpl ?? (async () => jsonRes({}));
  const wrappedFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    fetchCalls.push(url);
    fetchRequests.push(init === undefined ? { url } : { url, init });
    if (/\/(?:identity\/)?connect\/token$/u.test(url)) {
      if (overrides.sendTokenImpl) return overrides.sendTokenImpl(input, init);
      return jsonRes({
        access_token: 'SEND_TOKEN',
        token_type: 'Bearer',
        expires_in: 300,
        scope: 'api.send.access',
      });
    }
    return fetchImpl(input, init);
  }) as typeof fetch;
  const requestOrigin = vi.fn(async (originPatterns: readonly string[]): Promise<OriginPermissionGrant> => ({
    granted: overrides.requestOriginResult ?? true,
    newlyGranted: overrides.newlyGrantedResult ? [...originPatterns] : [],
  }));
  const removeOrigin = vi.fn(async () => overrides.removeOriginResult ?? true);
  const download = vi.fn();
  const deps: ReceiveDeps = { fetch: wrappedFetch, requestOrigins: requestOrigin, removeOrigin, download };
  return { deps, requestOrigin, removeOrigin, download, fetchCalls, fetchRequests };
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
function emailInput(app: VwReceiveApp): HTMLInputElement | null {
  return app.shadowRoot!.querySelector<HTMLInputElement>('[data-email]');
}
function otpInput(app: VwReceiveApp): HTMLInputElement | null {
  return app.shadowRoot!.querySelector<HTMLInputElement>('[data-otp]');
}
function accessButton(app: VwReceiveApp): HTMLButtonElement {
  return app.shadowRoot!.querySelector<HTMLButtonElement>('[data-access]')!;
}
function downloadButton(app: VwReceiveApp): HTMLButtonElement | null {
  return app.shadowRoot!.querySelector<HTMLButtonElement>('[data-download]');
}
function revealTextButton(app: VwReceiveApp): HTMLButtonElement | null {
  return app.shadowRoot!.querySelector<HTMLButtonElement>('[data-reveal-text]');
}
function resendButton(app: VwReceiveApp): HTMLButtonElement | null {
  return app.shadowRoot!.querySelector<HTMLButtonElement>('[data-resend]');
}

it('renders a focused page task with a heading and constrained body', async () => {
  const app = await mount(makeDeps().deps);
  expect(app.shadowRoot!.querySelector('[data-page-heading]')?.textContent).toContain('接收 Send');
  expect(app.shadowRoot!.querySelector('[data-task-column]')).not.toBeNull();
});

describe('vw-receive-app appearance', () => {
  afterEach(() => document.body.replaceChildren());

  it('mirrors the saved theme + density onto the host so the page is themed', async () => {
    const app = await mount(makeDeps().deps);
    expect(app.getAttribute('data-theme')).toBe('light');
    expect(app.getAttribute('data-density')).toBe('comfortable');
  });
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
    let resolveOrigin: (v: OriginPermissionGrant) => void = () => {};
    const stubs = makeDeps();
    stubs.requestOrigin.mockImplementation(() => new Promise<OriginPermissionGrant>((resolve) => { resolveOrigin = resolve; }));
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();

    // Permission is requested synchronously in the click; nothing has been fetched yet.
    expect(stubs.requestOrigin).toHaveBeenCalledWith(['https://vault.example/*']);
    expect(stubs.fetchCalls).toHaveLength(0);
    expect(app.state.status).toBe('accessing');
    await app.updateComplete;
    expect(accessButton(app).disabled).toBe(true);
    expect(accessButton(app).textContent).toContain('正在解密');
    expect((app.shadowRoot!.querySelector('vw-status-message') as HTMLElement & { message: string }).message).toBe('正在解密…');

    resolveOrigin({ granted: true, newlyGranted: [] });
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

  it('fails closed when the existing-permission preflight is indeterminate', async () => {
    const contains = vi.mocked(browser.permissions.contains);
    contains.mockRejectedValueOnce(new Error('permission preflight unavailable'));
    vi.mocked(browser.permissions.request).mockImplementationOnce(async () => {
      const listener = vi.mocked(browser.permissions.onAdded.addListener).mock.calls.at(-1)?.[0];
      listener?.({ origins: ['https://vault.example/*'] });
      return true;
    });
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const app = document.createElement('vw-receive-app') as VwReceiveApp;
    document.body.append(app);
    await app.updateComplete;

    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    await settle(app);

    expect(app.state).toMatchObject({ status: 'error' });
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(browser.permissions.remove).toHaveBeenCalledWith({ origins: ['https://vault.example/*'] });
    fetchSpy.mockRestore();
    contains.mockResolvedValue(false);
  });

  it('leaves accessing and shows a permission error when the permission API rejects', async () => {
    const stubs = makeDeps();
    stubs.requestOrigin.mockRejectedValue(new Error('permission API unavailable'));
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
      sendTokenImpl: async () => jsonRes({
        error: 'invalid_request',
        send_access_error_type: 'password_hash_b64_required',
      }, 400),
    });
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    await settle(app);
    expect(app.state).toMatchObject({
      status: 'passwordRequired',
      linkGeneration: 1,
      message: '此 Send 需要访问密码',
    });
    const pwInput = passwordInput(app);
    expect(pwInput).not.toBeNull();
    expect(app.shadowRoot!.activeElement).toBe(pwInput);
  });

  it('renders the password prompt as a polite info message, not an assertive alert', async () => {
    const stubs = makeDeps({
      sendTokenImpl: async () => jsonRes({
        error: 'invalid_request',
        send_access_error_type: 'password_hash_b64_required',
      }, 400),
    });
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    await settle(app);
    const msg = app.shadowRoot!.querySelector('vw-status-message') as (HTMLElement & { tone: string; icon: unknown }) | null;
    expect(msg).not.toBeNull();
    // The first access of a password-protected Send is a normal prompt, not a failure.
    expect(msg!.tone).toBe('info');
    expect(msg!.icon).toBeUndefined();
  });
});

describe('vw-receive-app email OTP access', () => {
  afterEach(() => document.body.replaceChildren());

  it('reveals the email form only after an exact anonymous challenge and discloses the Identity origin', async () => {
    const stubs = makeDeps({ sendTokenImpl: async () => emailChallengeRes('email_required') });
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('email-send'));

    expect(app.state).toMatchObject({ status: 'emailRequired', linkGeneration: 1 });
    expect(emailInput(app)).not.toBeNull();
    expect(app.shadowRoot!.activeElement).toBe(emailInput(app));
    expect((app.state as { message: string }).message).toContain('https://vault.example');
    const form = new URLSearchParams(stubs.fetchRequests[0]?.init?.body as string);
    expect(form.has('email')).toBe(false);
    expect(form.has('otp')).toBe(false);
  });

  it('requests exact split US Cloud origins together and never fetches the vanity share host', async () => {
    const stubs = makeDeps({ sendTokenImpl: async () => emailChallengeRes('email_required') });
    const app = await mount(stubs.deps);
    const cloudLink = `https://send.bitwarden.com/#cloudSend/${bytesToBase64Url(sendKey)}`;

    await accessFor(app, cloudLink);

    expect(stubs.requestOrigin).toHaveBeenCalledWith([
      'https://api.bitwarden.com/*',
      'https://identity.bitwarden.com/*',
    ]);
    expect(stubs.fetchCalls).toEqual(['https://identity.bitwarden.com/connect/token']);
    expect((app.state as { message: string }).message).toContain('https://identity.bitwarden.com');
  });

  it('sends normalized email then opaque OTP and decrypts only after a scoped token', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-email',
      type: 0,
      name: await encryptToText('Email Send', derived),
      text: { text: await encryptToText('verified', derived) },
    };
    const stubs = makeDeps({
      fetchImpl: async () => jsonRes(raw),
      sendTokenImpl: async (_input, init) => {
        const form = new URLSearchParams(init?.body as string);
        if (!form.has('email')) return emailChallengeRes('email_required');
        if (!form.has('otp')) return emailChallengeRes('email_and_otp_required');
        return jsonRes({
          access_token: 'EMAIL_SEND_TOKEN',
          token_type: 'Bearer',
          expires_in: 300,
          scope: 'api.send.access',
        });
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('email-send'));

    emailInput(app)!.value = ' Recipient@Example.COM ';
    accessButton(app).click();
    await settle(app);
    expect(app.state).toMatchObject({
      status: 'otpRequired',
      email: 'recipient@example.com',
      message: '如果该邮箱有权访问，验证码已发送。',
    });
    const emailForm = new URLSearchParams(stubs.fetchRequests[1]?.init?.body as string);
    expect(emailForm.get('email')).toBe('recipient@example.com');
    expect(emailForm.has('otp')).toBe(false);

    otpInput(app)!.value = '001234';
    accessButton(app).click();
    await settle(app);
    const otpForm = new URLSearchParams(stubs.fetchRequests[2]?.init?.body as string);
    expect(otpForm.get('email')).toBe('recipient@example.com');
    expect(otpForm.get('otp')).toBe('001234');
    expect(app.state).toMatchObject({ status: 'textReady', send: { name: 'Email Send', text: 'verified' } });
    expect(emailInput(app)).toBeNull();
    expect(otpInput(app)).toBeNull();
  });

  it('fails closed on a pseudo challenge and never exposes an email input', async () => {
    const stubs = makeDeps({
      sendTokenImpl: async () => jsonRes({
        error: 'invalid_grant',
        error_description: 'Email required',
        send_access_error_type: 'email_required',
      }, 400),
    });
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('pseudo'));

    expect(app.state).toEqual({ status: 'error', message: '无法安全确认此服务器的邮件验证能力' });
    expect(emailInput(app)).toBeNull();
    expect(stubs.fetchRequests.every(({ init }) => !new URLSearchParams(init?.body as string).has('email'))).toBe(true);
  });

  it('clears the old OTP and requests a new code when the recipient changes email', async () => {
    const tokenForms: URLSearchParams[] = [];
    const stubs = makeDeps({
      sendTokenImpl: async (_input, init) => {
        const form = new URLSearchParams(init?.body as string);
        tokenForms.push(form);
        return form.has('email')
          ? emailChallengeRes('email_and_otp_required')
          : emailChallengeRes('email_required');
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('email-change'));
    emailInput(app)!.value = 'first@example.com';
    accessButton(app).click();
    await settle(app);

    otpInput(app)!.value = 'old-code';
    emailInput(app)!.value = 'second@example.com';
    emailInput(app)!.dispatchEvent(new Event('input'));
    expect(otpInput(app)!.value).toBe('');
    accessButton(app).click();
    await settle(app);

    expect(tokenForms.at(-1)?.get('email')).toBe('second@example.com');
    expect(tokenForms.at(-1)?.has('otp')).toBe(false);
    expect(app.state).toMatchObject({ status: 'otpRequired', email: 'second@example.com' });
  });

  it('keeps resend single-flight and blocks it throughout the cooldown', async () => {
    let resolveResend: (response: Response) => void = () => {};
    let holdResend = false;
    const tokenForms: URLSearchParams[] = [];
    const stubs = makeDeps({
      sendTokenImpl: async (_input, init) => {
        const form = new URLSearchParams(init?.body as string);
        tokenForms.push(form);
        if (!form.has('email')) return emailChallengeRes('email_required');
        if (holdResend) return new Promise<Response>((resolve) => { resolveResend = resolve; });
        return emailChallengeRes('email_and_otp_required');
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('resend'));
    emailInput(app)!.value = 'recipient@example.com';
    accessButton(app).click();
    await settle(app);

    const beforeCooldownClick = tokenForms.length;
    expect(resendButton(app)?.disabled).toBe(true);
    expect(resendButton(app)?.textContent).toMatch(/\d+\s*秒/);
    resendButton(app)!.click();
    await flushAsync();
    expect(tokenForms).toHaveLength(beforeCooldownClick);

    if (app.state.status !== 'otpRequired') throw new Error('expected otpRequired');
    app.state = { ...app.state, resendAvailableAt: Date.now() - 1 };
    await app.updateComplete;
    holdResend = true;
    const button = resendButton(app)!;
    button.click();
    button.click();
    await flushAsync();
    expect(tokenForms).toHaveLength(beforeCooldownClick + 1);
    expect(tokenForms.at(-1)?.has('otp')).toBe(false);
    resolveResend(emailChallengeRes('email_and_otp_required'));
    await settle(app);
    expect(app.state).toMatchObject({ status: 'otpRequired', resending: false });
    expect(resendButton(app)?.disabled).toBe(true);
    expect(resendButton(app)?.textContent).toMatch(/(?:29|30)\s*秒/);
  });

  it('does not send email or OTP when the server only advertises legacy access', async () => {
    const stubs = makeDeps({
      sendTokenImpl: async () => jsonRes({ error: 'unsupported_grant_type' }, 400),
      fetchImpl: async () => jsonRes({ message: 'Could not locate send' }, 400),
    });
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('legacy'));

    expect(emailInput(app)).toBeNull();
    const tokenForms = stubs.fetchRequests
      .filter(({ url }) => url.endsWith('/identity/connect/token'))
      .map(({ init }) => new URLSearchParams(init?.body as string));
    expect(tokenForms.every((form) => !form.has('email') && !form.has('otp'))).toBe(true);
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
    expect(app.state).toEqual({
      status: 'textReady',
      send: { id: 'send-1', type: 0, name: 'Greeting', text: 'hello there', hidden: false },
      revealed: false,
      linkGeneration: 1,
    });
    expect(app.shadowRoot!.textContent).toContain('Greeting');
    expect(app.shadowRoot!.textContent).toContain('hello there');
    expect(revealTextButton(app)).toBeNull();
  });

  it('keeps hidden text out of the DOM until an explicit reveal and preserves the flag in state', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-hidden',
      type: 0,
      name: await encryptToText('Private note', derived),
      text: { text: await encryptToText('not-before-click', derived), hidden: true },
    };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('hidden'));

    expect(app.state).toMatchObject({
      status: 'textReady',
      send: { id: 'send-hidden', hidden: true, text: 'not-before-click' },
      revealed: false,
    });
    expect(app.shadowRoot!.textContent).not.toContain('not-before-click');
    expect(app.shadowRoot!.querySelector('[data-send-text]')).toBeNull();
    expect(revealTextButton(app)?.textContent).toContain('显示文本');

    const accessRequestCount = stubs.fetchCalls.length;
    revealTextButton(app)!.click();
    await app.updateComplete;
    expect(app.state).toMatchObject({ status: 'textReady', send: { hidden: true }, revealed: true });
    expect(app.shadowRoot!.querySelector('[data-send-text]')?.textContent).toBe('not-before-click');
    expect(revealTextButton(app)).toBeNull();
    expect(stubs.fetchCalls).toHaveLength(accessRequestCount);

    accessButton(app).click();
    await settle(app);
    expect(app.state).toMatchObject({ status: 'textReady', send: { hidden: true }, revealed: false });
    expect(app.shadowRoot!.textContent).not.toContain('not-before-click');
  });

  it('copies revealed text and hides it again without another access request', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-hidden', type: 0, name: await encryptToText('Private note', derived),
      text: { text: await encryptToText('deliberately revealed', derived), hidden: true },
    };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const writeClipboard = vi.fn(async () => {});
    const app = await mount({ ...stubs.deps, writeClipboard });
    await accessFor(app, linkFor('hidden-copy'));
    const requestCount = stubs.fetchCalls.length;
    expect(app.shadowRoot!.querySelector('[data-copy-text]')).toBeNull();
    revealTextButton(app)!.click();
    await app.updateComplete;
    app.shadowRoot!.querySelector<HTMLButtonElement>('[data-copy-text]')!.click();
    await flushAsync();
    await app.updateComplete;
    expect(writeClipboard).toHaveBeenCalledWith('deliberately revealed');
    expect(app.shadowRoot!.querySelector('[data-server-context]')?.textContent).toContain('vault.example');
    app.shadowRoot!.querySelector<HTMLButtonElement>('[data-hide-text]')!.click();
    await app.updateComplete;
    expect(app.shadowRoot!.querySelector('[data-send-text]')).toBeNull();
    expect(app.shadowRoot!.querySelector('[data-copy-text]')).toBeNull();
    expect(stubs.fetchCalls).toHaveLength(requestCount);
  });

  it('sends the password hash once the user supplies one after password_required', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-1', type: 0, name: await encryptToText('Greeting', derived), text: { text: await encryptToText('secret', derived) } };
    const stubs = makeDeps({
      fetchImpl: async () => jsonRes(raw),
      sendTokenImpl: async (_input, init) => {
        const form = new URLSearchParams(init?.body as string | undefined);
        return form.has('password_hash_b64')
          ? jsonRes({
              access_token: 'SEND_TOKEN',
              token_type: 'Bearer',
              expires_in: 300,
              scope: 'api.send.access',
            })
          : jsonRes({ error: 'invalid_request', send_access_error_type: 'password_hash_b64_required' }, 400);
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'), 'the-password');
    expect(app.state).toMatchObject({ status: 'textReady', send: { name: 'Greeting' } });
    const grantRequest = stubs.fetchRequests
      .filter(({ url }) => url.endsWith('/identity/connect/token'))
      .at(-1);
    expect(grantRequest?.init?.body).toBeTypeOf('string');
    expect(new URLSearchParams(grantRequest!.init!.body as string).has('password_hash_b64')).toBe(true);
  });
});

describe('vw-receive-app temporary host permissions', () => {
  afterEach(() => document.body.replaceChildren());

  async function textSendResponse(): Promise<unknown> {
    const derived = await deriveSendKey(sendKey);
    return {
      id: 'send-1',
      type: 0,
      name: await encryptToText('Greeting', derived),
      text: { text: await encryptToText('hello', derived) },
    };
  }

  it('releases a source permission added by this page after a text Send reaches its terminal state', async () => {
    const raw = await textSendResponse();
    const stubs = makeDeps({ newlyGrantedResult: true, fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('acc1'));

    expect(app.state.status).toBe('textReady');
    expect(stubs.removeOrigin).toHaveBeenCalledOnce();
    expect(stubs.removeOrigin).toHaveBeenCalledWith('https://vault.example/*');
  });

  it('never removes a source permission that existed before this page requested it', async () => {
    const raw = await textSendResponse();
    const stubs = makeDeps({ newlyGrantedResult: false, fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('acc1'));

    expect(app.state.status).toBe('textReady');
    expect(stubs.removeOrigin).not.toHaveBeenCalled();
  });

  it('retries false and rejected permission removals before clearing its tracking', async () => {
    const raw = await textSendResponse();
    const stubs = makeDeps({ newlyGrantedResult: true, fetchImpl: async () => jsonRes(raw) });
    stubs.removeOrigin
      .mockResolvedValueOnce(false)
      .mockRejectedValueOnce(new Error('temporary cleanup failure'))
      .mockResolvedValueOnce(true);
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('acc1'));

    expect(app.state.status).toBe('textReady');
    expect(stubs.removeOrigin).toHaveBeenCalledTimes(3);
  });

  it('keeps an unremoved permission tracked for a later lifecycle retry', async () => {
    const raw = await textSendResponse();
    const stubs = makeDeps({ newlyGrantedResult: true, fetchImpl: async () => jsonRes(raw) });
    stubs.removeOrigin.mockResolvedValue(false);
    const app = await mount(stubs.deps);

    await accessFor(app, linkFor('acc1'));
    expect(stubs.removeOrigin).toHaveBeenCalledTimes(3);

    stubs.removeOrigin.mockResolvedValue(true);
    linkInput(app).value = linkFor('next');
    linkInput(app).dispatchEvent(new Event('input'));
    await flushAsync();

    expect(stubs.removeOrigin).toHaveBeenCalledTimes(4);
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
    expect(app.state).toMatchObject({ status: 'fileReady', messageTone: 'success' });
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

  it('rejects a malformed file Send that is missing its file id or send id', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: '', type: 1, name: await encryptToText('Doc', derived), file: { fileName: await encryptToText('secret.pdf', derived), sizeName: '3 KB' } };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    expect(app.state).toMatchObject({ status: 'error' });
    expect(downloadButton(app)).toBeNull();
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
    expect(app.state).toMatchObject({ status: 'fileReady', message: '无法解密，链接或文件可能已损坏' });
    expect(downloadButton(app)).not.toBeNull();
    expect(stubs.download).not.toHaveBeenCalled();
  });

  it('drops a rejected bearer and requires a fresh explicit access request', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1' },
    };
    const stubs = makeDeps({
      fetchImpl: async (input) => String(input).includes('/access/file/')
        ? new Response('', { status: 401 })
        : jsonRes(raw),
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    downloadButton(app)!.click();
    await settle(app);
    expect(app.state).toEqual({ status: 'error', message: '访问授权已失效，请重新验证此 Send' });
    expect(passwordInput(app)).toBeNull();
    const tokenRequestsBeforeRetry = stubs.fetchCalls
      .filter((url) => url.endsWith('/identity/connect/token')).length;
    accessButton(app).click();
    await settle(app);
    expect(stubs.fetchCalls.filter((url) => url.endsWith('/identity/connect/token')))
      .toHaveLength(tokenRequestsBeforeRetry + 1);
  });

  it('keeps the file context and obtains a fresh URL when a failed download is retried', async () => {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([4, 5, 6]), derived);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' },
    };
    let urlRequests = 0;
    let fileRequests = 0;
    const stubs = makeDeps({
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.includes('/access/file/')) {
          urlRequests += 1;
          return jsonRes({ url: `https://vault.example/dl?attempt=${urlRequests}` });
        }
        if (url.includes('/dl?')) {
          fileRequests += 1;
          return fileRequests === 1 ? new Response('', { status: 503 }) : new Response(Buffer.from(blob));
        }
        return jsonRes(raw);
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));

    downloadButton(app)!.click();
    await settle(app);
    expect(app.state).toMatchObject({ status: 'fileReady', message: '下载失败' });
    expect(downloadButton(app)).not.toBeNull();

    downloadButton(app)!.click();
    await settle(app);
    expect(stubs.download).toHaveBeenCalledTimes(1);
    expect(urlRequests).toBe(2);
    expect(app.state).toMatchObject({
      status: 'fileReady',
      messageTone: 'success',
      message: '已开始下载，请在关闭此页前检查浏览器下载记录。',
    });
    expect((app.state as { message?: string }).message).not.toContain('下载失败');
  });

  it('returns an unsafe server-supplied URL to fileReady instead of getting stuck downloading', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1' },
    };
    const stubs = makeDeps({
      fetchImpl: async (input) => String(input).includes('/access/file/')
        ? jsonRes({ url: 'data:application/octet-stream,nope' })
        : jsonRes(raw),
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    downloadButton(app)!.click();
    await settle(app);
    expect(app.state).toMatchObject({ status: 'fileReady', message: '下载失败' });
    expect(stubs.fetchCalls).not.toContain('data:application/octet-stream,nope');
  });
});

describe('vw-receive-app cross-origin file download', () => {
  afterEach(() => document.body.replaceChildren());

  async function crossOriginFixture() {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([7, 8, 9]), derived);
    const raw = {
      id: 'send-2', type: 1, name: await encryptToText('Doc', derived),
      file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1' },
    };
    const stubs = makeDeps({
      fetchImpl: async (input) => {
        const url = String(input);
        if (url.includes('/access/file/')) return jsonRes({ url: 'https://cdn.example/file?t=jwt' });
        if (url === 'https://cdn.example/file?t=jwt') return new Response(Buffer.from(blob));
        return jsonRes(raw);
      },
    });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('acc1'));
    return { app, stubs };
  }

  it('defers a new cross-origin permission to a second, user-initiated click', async () => {
    const { app, stubs } = await crossOriginFixture();
    downloadButton(app)!.click();
    await settle(app);

    expect(app.state).toMatchObject({
      status: 'fileReady',
      pendingDownloadUrl: 'https://cdn.example/file?t=jwt',
    });
    expect((app.state as { message: string }).message).toContain('cdn.example');
    expect(stubs.requestOrigin).toHaveBeenCalledTimes(1);
    expect(stubs.fetchCalls).not.toContain('https://cdn.example/file?t=jwt');

    downloadButton(app)!.click();
    expect(stubs.requestOrigin).toHaveBeenLastCalledWith(['https://cdn.example/*']);
    await settle(app);
    expect(stubs.download).toHaveBeenCalledTimes(1);
    expect(app.state).toMatchObject({ status: 'fileReady' });
    expect((app.state as { pendingDownloadUrl?: string }).pendingDownloadUrl).toBeUndefined();
  });

  it('keeps the pending file context when a cross-origin permission request rejects', async () => {
    const { app, stubs } = await crossOriginFixture();
    downloadButton(app)!.click();
    await settle(app);
    stubs.requestOrigin.mockRejectedValueOnce(new Error('permission API unavailable'));

    downloadButton(app)!.click();
    await settle(app);
    expect(app.state).toMatchObject({
      status: 'fileReady',
      pendingDownloadUrl: 'https://cdn.example/file?t=jwt',
      messageTone: 'danger',
    });
    expect((app.state as { message: string }).message).toContain('cdn.example');
    expect(stubs.download).not.toHaveBeenCalled();

    downloadButton(app)!.click();
    await settle(app);
    expect(stubs.requestOrigin).toHaveBeenLastCalledWith(['https://cdn.example/*']);
    expect(stubs.download).toHaveBeenCalledTimes(1);
    expect(app.state).toMatchObject({ status: 'fileReady' });
    expect((app.state as { pendingDownloadUrl?: string }).pendingDownloadUrl).toBeUndefined();
  });

  it('never contacts a newly discovered cross-origin target on the discovery click', async () => {
    const { app, stubs } = await crossOriginFixture();
    downloadButton(app)!.click();
    await settle(app);
    expect(stubs.requestOrigin).toHaveBeenCalledTimes(1);
    expect(stubs.fetchCalls).not.toContain('https://cdn.example/file?t=jwt');
    expect(stubs.download).not.toHaveBeenCalled();

    downloadButton(app)!.click();
    await settle(app);
    expect(stubs.requestOrigin).toHaveBeenLastCalledWith(['https://cdn.example/*']);
    expect(stubs.download).toHaveBeenCalledTimes(1);
  });

  it('releases only grants added by this page after a cross-origin download succeeds', async () => {
    const { app, stubs } = await crossOriginFixture();
    stubs.requestOrigin
      .mockResolvedValueOnce({ granted: true, newlyGranted: ['https://vault.example/*'] })
      .mockResolvedValueOnce({ granted: true, newlyGranted: ['https://cdn.example/*'] });

    // Re-run Access so the source grant uses the per-call result configured above.
    await accessFor(app, linkFor('acc1'));
    downloadButton(app)!.click();
    await settle(app);
    downloadButton(app)!.click();
    await settle(app);

    expect(stubs.download).toHaveBeenCalledTimes(1);
    expect(stubs.removeOrigin.mock.calls.map((call) => call[0])).toEqual(expect.arrayContaining([
      'https://vault.example/*',
      'https://cdn.example/*',
    ]));
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
    let resolveOrigin: (v: OriginPermissionGrant) => void = () => {};
    const stubs = makeDeps();
    stubs.requestOrigin.mockImplementation(() => new Promise<OriginPermissionGrant>((resolve) => { resolveOrigin = resolve; }));
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('acc1');
    accessButton(app).click();
    accessButton(app).click();
    accessButton(app).click();
    expect(stubs.requestOrigin).toHaveBeenCalledTimes(1);
    resolveOrigin({ granted: true, newlyGranted: [] });
    await settle(app);
  });
});

describe('vw-receive-app link authority lifecycle', () => {
  afterEach(() => document.body.replaceChildren());

  it('immediately hides decrypted content and invalidates the flow when the link changes', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-1',
      type: 0,
      name: await encryptToText('Greeting', derived),
      text: { text: await encryptToText('sensitive text', derived) },
    };
    const stubs = makeDeps({ fetchImpl: async () => jsonRes(raw) });
    const app = await mount(stubs.deps);
    await accessFor(app, linkFor('first'));
    expect(app.shadowRoot!.textContent).toContain('sensitive text');

    linkInput(app).value = linkFor('second');
    linkInput(app).dispatchEvent(new Event('input'));
    await app.updateComplete;

    expect(app.state).toEqual({ status: 'idle' });
    expect(app.shadowRoot!.textContent).not.toContain('sensitive text');
  });

  it('aborts an in-flight request and ignores its late completion after a link transition', async () => {
    let requestSignal: AbortSignal | undefined;
    let resolveApi: (response: Response) => void = () => {};
    const stubs = makeDeps({
      fetchImpl: async (_input, init) => {
        requestSignal = init?.signal ?? undefined;
        return new Promise<Response>((resolve) => { resolveApi = resolve; });
      },
    });
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('first');
    accessButton(app).click();
    for (let i = 0; i < 10 && requestSignal === undefined; i++) await flushAsync();
    expect(requestSignal?.aborted).toBe(false);

    linkInput(app).value = linkFor('second');
    linkInput(app).dispatchEvent(new Event('input'));
    expect(requestSignal?.aborted).toBe(true);
    resolveApi(jsonRes({ id: 'late', type: 0 }));
    await flushAsync();
    await app.updateComplete;
    expect(app.state).toEqual({ status: 'idle' });
  });

  it('reclaims a newly granted permission that arrives after the component is disconnected', async () => {
    let resolveOrigin: (grant: OriginPermissionGrant) => void = () => {};
    const stubs = makeDeps();
    stubs.requestOrigin.mockImplementation(() => new Promise<OriginPermissionGrant>((resolve) => {
      resolveOrigin = resolve;
    }));
    const app = await mount(stubs.deps);
    linkInput(app).value = linkFor('late-permission');
    accessButton(app).click();
    app.remove();

    resolveOrigin({ granted: true, newlyGranted: ['https://vault.example/*'] });
    await flushAsync();

    expect(stubs.removeOrigin).toHaveBeenCalledWith('https://vault.example/*');
    expect(stubs.fetchCalls).toHaveLength(0);
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
