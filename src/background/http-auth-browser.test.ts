import { describe, expect, it, vi } from 'vitest';
import {
  registerHttpAuthBrowserListeners,
  type HttpAuthChromeApi,
} from './http-auth-browser.js';

function chromeFixture() {
  const auth = vi.fn();
  const completed = vi.fn();
  const errored = vi.fn();
  const chromeApi: HttpAuthChromeApi = {
    webRequest: {
      onAuthRequired: { addListener: auth },
      onCompleted: { addListener: completed },
      onErrorOccurred: { addListener: errored },
    },
  };
  return { chromeApi, auth, completed, errored };
}

describe('registerHttpAuthBrowserListeners', () => {
  it('registers callback-style asyncBlocking synchronously without a Promise listener', () => {
    const fixture = chromeFixture();
    const broker = { handle: vi.fn(), finishRequest: vi.fn() };
    expect(registerHttpAuthBrowserListeners(fixture.chromeApi, broker as never)).toBe(true);
    expect(fixture.auth).toHaveBeenCalledWith(
      expect.any(Function),
      { urls: ['<all_urls>'], types: ['main_frame'] },
      ['asyncBlocking'],
    );
    const listener = fixture.auth.mock.calls[0]![0] as (...args: unknown[]) => unknown;
    const callback = vi.fn();
    const details = { requestId: 'r' };
    expect(listener(details, callback)).toBeUndefined();
    expect(broker.handle).toHaveBeenCalledWith(details, callback);
  });

  it('clears process-local claims on completion and error only', () => {
    const fixture = chromeFixture();
    const broker = { handle: vi.fn(), finishRequest: vi.fn() };
    registerHttpAuthBrowserListeners(fixture.chromeApi, broker as never);
    const onCompleted = fixture.completed.mock.calls[0]![0] as (value: unknown) => void;
    const onError = fixture.errored.mock.calls[0]![0] as (value: unknown) => void;
    onCompleted({ requestId: 'one' });
    onError({ requestId: 'two' });
    expect(broker.finishRequest).toHaveBeenNthCalledWith(1, 'one');
    expect(broker.finishRequest).toHaveBeenNthCalledWith(2, 'two');
  });

  it('fails closed when the raw Chrome API is unavailable', () => {
    expect(registerHttpAuthBrowserListeners(undefined, {
      handle: vi.fn(),
      finishRequest: vi.fn(),
    } as never)).toBe(false);
  });
});
