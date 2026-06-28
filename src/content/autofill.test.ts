// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../messaging/protocol.js', () => ({
  sendRequest: vi.fn(),
}));

vi.mock('./fill.js', () => ({
  fillLoginForm: vi.fn(),
}));

import { sendRequest } from '../messaging/protocol.js';
import { fillLoginForm } from './fill.js';
import { startAutofill } from './autofill.js';

describe('autofill controller', () => {
  beforeEach(() => {
    document.querySelectorAll('[data-vw-popover-for]').forEach((node) => node.remove());
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    vi.mocked(sendRequest).mockReset();
    vi.mocked(fillLoginForm).mockReset();
  });

  afterEach(() => {
    document.querySelectorAll('[data-vw-popover-for]').forEach((node) => node.remove());
  });

  it('requests candidates for the current frame URL when popover opens', async () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    document.querySelector<HTMLElement>('[data-vw-popover-for]')?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await Promise.resolve();

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findCandidates', frameUrl: 'https://example.com/login' });
  });

  it('shows no matches when findCandidates returns an empty array', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    const popover = document.querySelector<HTMLElement>('[data-vw-popover-for]');
    popover?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await new Promise(r => setTimeout(r, 0));

    expect(popover?.shadowRoot?.textContent).toContain('No matching logins');
  });

  it('does not throw when form.id contains CSS selector special characters', () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    // Simulate page content setting data-vw-autofill-id to a value with quotes and CSS syntax
    const formHtml = '<form><input id="pass" type="email"><input type="password" data-vw-autofill-id=\'test"[attr]"></form>';
    document.body.innerHTML = formHtml;

    expect(() => {
      startAutofill('https://example.com/login');
    }).not.toThrow();
  });

  it('shows status when findCandidates returns unexpected data shape', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce({ ok: true, data: null });

    startAutofill('https://example.com/login');
    const popover = document.querySelector<HTMLElement>('[data-vw-popover-for]');
    popover?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await new Promise(r => setTimeout(r, 0));

    const statusText = popover?.shadowRoot?.textContent;
    expect(statusText).toContain('Unexpected autofill response');
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
    const popover = document.querySelector<HTMLElement>('[data-vw-popover-for]');
    popover?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await new Promise(r => setTimeout(r, 0));

    popover?.shadowRoot?.querySelector<HTMLButtonElement>('[data-cipher-id="1"]')?.click();
    await new Promise(r => setTimeout(r, 0));

    const statusText = popover?.shadowRoot?.textContent;
    expect(statusText).toContain('Unexpected autofill response');
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
    const popover = document.querySelector<HTMLElement>('[data-vw-popover-for]');
    popover?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await new Promise(r => setTimeout(r, 0));

    popover?.shadowRoot?.querySelector<HTMLButtonElement>('[data-cipher-id="1"]')?.click();
    await new Promise(r => setTimeout(r, 0));

    const statusText = popover?.shadowRoot?.textContent;
    expect(statusText).toContain('Unexpected autofill response');
  });

  it('shows status when findCandidates returns non-array data', async () => {
    vi.mocked(sendRequest).mockResolvedValueOnce({ ok: true, data: { username: 'foo' } });

    startAutofill('https://example.com/login');
    const popover = document.querySelector<HTMLElement>('[data-vw-popover-for]');
    popover?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await new Promise(r => setTimeout(r, 0));

    const statusText = popover?.shadowRoot?.textContent;
    expect(statusText).toContain('Unexpected autofill response');
  });
});
