// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../messaging/protocol.js', () => ({
  sendRequest: vi.fn(),
}));

import { sendRequest } from '../messaging/protocol.js';
import { startAutofill } from './autofill.js';

describe('autofill controller', () => {
  beforeEach(() => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    vi.mocked(sendRequest).mockReset();
  });

  it('requests candidates for the current frame URL when popover opens', async () => {
    vi.mocked(sendRequest).mockResolvedValue({ ok: true, data: [] });

    startAutofill('https://example.com/login');
    document.querySelector<HTMLElement>('[data-vw-popover-for]')?.shadowRoot?.querySelector<HTMLButtonElement>('#open')?.click();
    await Promise.resolve();

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findCandidates', frameUrl: 'https://example.com/login' });
  });
});
