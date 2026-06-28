// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface FakePopover {
  element: HTMLElement;
  showStatus: ReturnType<typeof vi.fn>;
  showCandidates: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
  options: {
    onOpen(): void;
    onSelect(cipherId: string): void;
  };
}

const popoverState = vi.hoisted(() => ({
  instances: [] as FakePopover[],
}));

vi.mock('../messaging/protocol.js', () => ({
  sendRequest: vi.fn(),
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
      showStatus: vi.fn(),
      showCandidates: vi.fn(),
      remove: vi.fn(),
      options,
    };
    popoverState.instances.push(popover);
    return popover;
  }),
}));

import { sendRequest, type ResponseMessage } from '../messaging/protocol.js';
import { fillLoginForm } from './fill.js';
import { startAutofill } from './autofill.js';

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
});

function popover(): FakePopover {
  const current = popoverState.instances.at(-1);
  if (!current) throw new Error('Expected popover to exist');
  return current;
}

function malformedOk(data: unknown): ResponseMessage {
  return { ok: true, data } as ResponseMessage;
}
