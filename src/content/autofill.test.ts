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
  };
}

const popoverState = vi.hoisted(() => ({
  instances: [] as FakePopover[],
}));

vi.mock('webextension-polyfill', () => ({
  default: { runtime: { onMessage: { addListener: vi.fn() } } },
}));

vi.mock('../messaging/protocol.js', () => ({
  sendRequest: vi.fn(),
  isExtensionContextAlive: () => true,
}));

vi.mock('./fill.js', () => ({
  fillLoginForm: vi.fn(),
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

import { sendRequest, type ResponseMessage } from '../messaging/protocol.js';
import { fillLoginForm } from './fill.js';
import * as noticeModule from './notice.js';
import { startAutofill, handleContentCommand, handleFocusedFill, handleFrameAutofillMessage, openPickerFor, popoverRegistry } from './autofill.js';

describe('autofill controller', () => {
  beforeEach(() => {
    document.querySelectorAll('[data-vw-popover-for]').forEach((node) => node.remove());
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    popoverState.instances.length = 0;
    vi.mocked(sendRequest).mockReset();
    vi.mocked(fillLoginForm).mockReset();
  });

  afterEach(() => {
    document.querySelectorAll('[data-vw-popover-for]').forEach((node) => node.remove());
  });

  it('requests candidates for the current frame URL when popover opens', async () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    popover().options.onOpen();
    await Promise.resolve();

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findCandidates', frameUrl: 'https://example.com/login' });
  });

  it('opens the login side panel when a login field is focused (design 2c)', () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    const current = popover();
    const emailInput = document.querySelector('input[type="email"]') as HTMLInputElement;
    emailInput.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));

    expect(current.open).toHaveBeenCalled();
  });

  it('dismisses the login side panel on a pointer-down outside the field and panel', () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    const current = popover();
    const emailInput = document.querySelector('input[type="email"]') as HTMLInputElement;
    emailInput.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));

    const outside = document.createElement('button');
    document.body.append(outside);
    outside.dispatchEvent(new MouseEvent('pointerdown', { bubbles: true }));

    expect(current.hide).toHaveBeenCalled();
  });

  it('uses the current frame URL after same-document navigation', async () => {
    window.history.replaceState({}, '', '/login');
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: `${window.location.origin}/other`,
          matchType: 3,
          favorite: false,
        }],
      })
      .mockResolvedValueOnce({ ok: true, data: { username: 'user', password: 'secret' } });

    startAutofill();
    const current = popover();
    window.history.pushState({}, '', '/other');

    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));
    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(sendRequest).toHaveBeenNthCalledWith(1, { type: 'autofill.findCandidates', frameUrl: `${window.location.origin}/other` });
    expect(sendRequest).toHaveBeenNthCalledWith(2, { type: 'autofill.getCredentials', cipherId: '1', frameUrl: `${window.location.origin}/other` });
  });

  it('does not fill if the frame URL changes before credentials return', async () => {
    window.history.replaceState({}, '', '/login');
    let resolveCredentials: (value: ResponseMessage) => void = () => {};
    const credentialsResponse = new Promise<ResponseMessage>((resolve) => {
      resolveCredentials = resolve;
    });
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: `${window.location.origin}/login`,
          matchType: 3,
          favorite: false,
        }],
      })
      .mockReturnValueOnce(credentialsResponse);

    startAutofill();
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await Promise.resolve();
    window.history.pushState({}, '', '/other');
    resolveCredentials({ ok: true, data: { username: 'user', password: 'secret' } });
    await new Promise(r => setTimeout(r, 0));

    expect(sendRequest).toHaveBeenNthCalledWith(2, { type: 'autofill.getCredentials', cipherId: '1', frameUrl: `${window.location.origin}/login` });
    expect(fillLoginForm).not.toHaveBeenCalled();
    expect(current.showStatus).toHaveBeenCalledWith('Page changed before autofill');
  });

  it('shows no matches when findCandidates returns an empty array', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showCandidates).toHaveBeenCalledWith([]);
    expect(current.showStatus).not.toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('does not throw when form.id contains CSS selector special characters', () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    const formHtml = '<form><input id="pass" type="email"><input type="password" data-vw-autofill-id=\'test"[attr]"></form>';
    document.body.innerHTML = formHtml;

    expect(() => {
      startAutofill('https://example.com/login');
    }).not.toThrow();
  });

  it('shows status when findCandidates returns unexpected data shape', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce({ ok: true, data: null });

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when findCandidates returns malformed candidate items', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce(malformedOk([{ matchedUri: 'https://example.com' }]));

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when getCredentials returns unexpected data shape', async () => {
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: 'https://example.com',
          matchType: 0,
          favorite: false,
        }],
      })
      .mockResolvedValueOnce({ ok: true, data: null });

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when getCredentials returns array instead of object', async () => {
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: 'https://example.com',
          matchType: 0,
          favorite: false,
        }],
      })
      .mockResolvedValueOnce({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('shows status when getCredentials returns malformed credential fields', async () => {
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{
          id: '1',
          name: 'Test',
          username: 'user',
          matchedUri: 'https://example.com',
          matchType: 0,
          favorite: false,
        }],
      })
      .mockResolvedValueOnce(malformedOk({ username: 42, password: 'secret' }));

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
    expect(fillLoginForm).not.toHaveBeenCalled();
  });

  it('shows status when findCandidates returns non-array data', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce({ ok: true, data: { username: 'foo' } });

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));

    expect(current.showStatus).toHaveBeenCalledWith('Unexpected autofill response');
  });

  it('fills only the username for a username-only step without reporting it unavailable', async () => {
    document.body.innerHTML = '<form><input type="email" autocomplete="username"><button>Next</button></form>';
    vi.mocked(fillLoginForm).mockReturnValue(true);
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{ id: '1', name: 'Test', username: 'user', matchedUri: 'https://example.com', matchType: 0, favorite: false }],
      })
      .mockResolvedValueOnce({ ok: true, data: { username: 'user', password: 'secret' } });

    startAutofill('https://example.com/login');
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
      vi.mocked(sendRequest)
        .mockResolvedValueOnce({ ok: true, data: [{ id: '1', name: 'T', username: 'u', matchedUri: 'https://example.com', matchType: 0, favorite: false }] })
        .mockResolvedValueOnce({ ok: true, data: { username: 'u', password: 'p' } });

      startAutofill('https://example.com/login');
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

  it('fills a standalone verification-code step without reporting it unavailable', async () => {
    document.body.innerHTML = '<form><input type="text" autocomplete="one-time-code" name="otp"><button>Verify</button></form>';
    vi.mocked(fillLoginForm).mockReturnValue(true);
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({
        ok: true,
        data: [{ id: '1', name: 'Test', matchedUri: 'https://example.com', matchType: 0, favorite: false }],
      })
      .mockResolvedValueOnce({ ok: true, data: { totp: '123456' } });

    startAutofill('https://example.com/login');
    const current = popover();
    current.options.onOpen();
    await new Promise(r => setTimeout(r, 0));
    current.options.onSelect('1');
    await new Promise(r => setTimeout(r, 0));

    const filledForm = vi.mocked(fillLoginForm).mock.calls[0]?.[0];
    expect(filledForm?.totpInput?.getAttribute('name')).toBe('otp');
    expect(filledForm?.passwordInput).toBeUndefined();
    expect(current.showStatus).not.toHaveBeenCalledWith('Form is no longer available');
    expect(current.showFilled).toHaveBeenCalled();
  });

  it('attaches a card popover and fills the form on selection', async () => {
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'card-1', name: 'Visa', subtitle: 'Visa', favorite: false }] }) // findFillItems
      .mockResolvedValueOnce({ ok: true, data: { number: '4111111111111111', code: '123' } }); // getFillData
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" id="csc"></form>';

    startAutofill('https://shop.example/checkout');
    const cardPopover = popoverState.instances.at(-1)!; // only the card popover is attached for this DOM
    cardPopover.options.onOpen();
    await new Promise((r) => setTimeout(r, 0));
    cardPopover.options.onSelect('card-1');
    await new Promise((r) => setTimeout(r, 0));

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findFillItems', kind: 'card' });
    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.getFillData', cipherId: 'card-1', kind: 'card' });
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('4111111111111111');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123');
  });

  it('attaches an identity popover and fills the form on selection', async () => {
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'id-1', name: 'Ada Lovelace', subtitle: 'Ada Lovelace', favorite: false }] }) // findFillItems
      .mockResolvedValueOnce({ ok: true, data: { firstName: 'Ada', lastName: 'Lovelace', address1: '1 Analytical Way', postalCode: 'EC1' } }); // getFillData
    document.body.innerHTML = '<form><input autocomplete="given-name" id="fn"><input autocomplete="family-name" id="ln"><input autocomplete="street-address" id="st"><input autocomplete="postal-code" id="zip"></form>';

    startAutofill('https://shop.example/account');
    const idPopover = popoverState.instances.at(-1)!;
    idPopover.options.onOpen();
    await new Promise((r) => setTimeout(r, 0));
    idPopover.options.onSelect('id-1');
    await new Promise((r) => setTimeout(r, 0));

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findFillItems', kind: 'identity' });
    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.getFillData', cipherId: 'id-1', kind: 'identity' });
    expect((document.getElementById('fn') as HTMLInputElement).value).toBe('Ada');
    expect((document.getElementById('st') as HTMLInputElement).value).toBe('1 Analytical Way');
  });

  it('does not attach a login popover on a CVC rendered as type=password', async () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" type="password" id="cvc"></form>';
    startAutofill('https://shop.example/checkout');
    // Only the card popover attaches; the type=password CVC must NOT spawn a login popover.
    expect(popoverState.instances).toHaveLength(1);
    expect(popoverState.instances[0]!.options.kind).toBe('card');
  });

  it('fills only the right-clicked field on a field-scope command', async () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    const csc = document.getElementById('csc') as HTMLInputElement;
    csc.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    handleContentCommand({ type: 'autofill.fill', scope: 'field', kind: 'card', data: { number: '4111', code: '123' } });
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123'); // only the CVC
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');   // number untouched
  });

  it('single-field fill skips a readonly target', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" id="csc" readonly></form>`;
    const csc = document.getElementById('csc') as HTMLInputElement;
    csc.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    handleContentCommand({ type: 'autofill.fill', scope: 'field', kind: 'card', data: { code: '123' } });
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe(''); // readonly not filled
  });

  it('fills the whole detected form on a form-scope command', async () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    handleContentCommand({ type: 'autofill.fill', scope: 'form', kind: 'card', data: { number: '4111', code: '123' } });
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('4111');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123');
  });

  it('shows a notice (no fill) on a fillError command', async () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number" id="num"></form>`;
    handleContentCommand({ type: 'autofill.fillError', code: 'reprompt_required' });
    expect(document.querySelector('[data-vw-notice]')).toBeTruthy();
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');
  });

  it('form-scope fills the form containing the right-clicked element', async () => {
    document.body.innerHTML = `
      <form id="f1"><input autocomplete="cc-number" id="num1"><input autocomplete="cc-csc" id="csc1"></form>
      <form id="f2"><input autocomplete="cc-number" id="num2"><input autocomplete="cc-csc" id="csc2"></form>`;
    (document.getElementById('num2') as HTMLInputElement).dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    handleContentCommand({ type: 'autofill.fill', scope: 'form', kind: 'card', data: { number: '4111', code: '123' } });
    expect((document.getElementById('num2') as HTMLInputElement).value).toBe('4111'); // clicked form filled
    expect((document.getElementById('num1') as HTMLInputElement).value).toBe('');     // other form untouched
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

describe('focused-fill command', () => {
  beforeEach(() => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    popoverRegistry.clear();
    vi.mocked(sendRequest).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does nothing when the frame is not focused', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(false);
    await handleFocusedFill(() => 'https://ex.com');
    expect(sendRequest).not.toHaveBeenCalled();
  });

  it('does nothing (no notice) when the active element is a nested frame', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    const iframe = document.createElement('iframe');
    document.body.append(iframe);
    iframe.focus();
    vi.spyOn(document, 'activeElement', 'get').mockReturnValue(iframe);
    await handleFocusedFill(() => 'https://ex.com');
    expect(sendRequest).not.toHaveBeenCalled();
  });

  it('fills a login when the focused password field has one match', async () => {
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    document.querySelector<HTMLInputElement>('input[type="password"]')!.focus();
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'c1', name: 'A', username: 'u', matchedUri: 'x', matchType: 0, favorite: false }] } as ResponseMessage)
      .mockResolvedValueOnce({ ok: true, data: { username: 'u', password: 'p' } } as ResponseMessage);
    await handleFocusedFill(() => 'https://ex.com');
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(1);
  });

  it('openPickerFor opens a registered, connected popover', () => {
    const el = document.createElement('div');
    document.documentElement.append(el);
    const open = vi.fn();
    popoverRegistry.set('f1', { element: el, open } as never);
    openPickerFor(() => 'https://ex.com', 'f1');
    expect(open).toHaveBeenCalledTimes(1);
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
    const outcome = handleFrameAutofillMessage({
      type: 'autofill.commitLoginFill',
      formId,
      expectedFrameUrl: 'https://example.com/login',
      credentials: { username: 'u', password: 'p' },
    });
    expect(outcome).toEqual({ status: 'filled' });
    expect(vi.mocked(fillLoginForm)).toHaveBeenCalledTimes(1);
  });

  it('commitLoginFill reports target_changed and fills nothing when the frame URL no longer matches', () => {
    startAutofill('https://example.com/login');
    const outcome = handleFrameAutofillMessage({
      type: 'autofill.commitLoginFill',
      formId: 'login',
      expectedFrameUrl: 'https://different.example/login',
      credentials: { username: 'u', password: 'p' },
    });
    expect(outcome).toEqual({ status: 'target_changed' });
    expect(vi.mocked(fillLoginForm)).not.toHaveBeenCalled();
  });
});
