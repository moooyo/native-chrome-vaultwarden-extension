// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { shouldInterceptCreate } from './page-webauthn.js';

const ES256 = [{ type: 'public-key', alg: -7 }];

describe('shouldInterceptCreate', () => {
  it('intercepts a same-origin ES256 platform request', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: ES256 } as unknown as PublicKeyCredentialCreationOptions, 'app.example.com')).toBe(true);
  });
  it('falls back when rpId is not a suffix of host', () => {
    expect(shouldInterceptCreate({ rp: { id: 'evil.com' }, pubKeyCredParams: ES256 } as unknown as PublicKeyCredentialCreationOptions, 'example.com')).toBe(false);
  });
  it('falls back when no ES256 param', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: [{ type: 'public-key', alg: -257 }] } as unknown as PublicKeyCredentialCreationOptions, 'example.com')).toBe(false);
  });
  it('falls back for cross-platform attachment', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: ES256, authenticatorSelection: { authenticatorAttachment: 'cross-platform' } } as unknown as PublicKeyCredentialCreationOptions, 'example.com')).toBe(false);
  });
  it('defaults rpId to host when rp.id is absent', () => {
    expect(shouldInterceptCreate({ rp: {}, pubKeyCredParams: ES256 } as unknown as PublicKeyCredentialCreationOptions, 'example.com')).toBe(true);
  });
  it('matches a mixed-case rp.id case-insensitively against the lowercase host', () => {
    // A site can supply an uppercased rp.id; it must not defeat the registrable-suffix gate.
    expect(shouldInterceptCreate({ rp: { id: 'Example.COM' }, pubKeyCredParams: ES256 } as unknown as PublicKeyCredentialCreationOptions, 'app.example.com')).toBe(true);
  });
});

// The get() override must honour AbortSignal like create() does: an already-aborted request goes
// straight to the native authenticator (no consent round-trip), and an abort that fires while the
// consent round-trip is in flight unblocks the ceremony and falls back to native.
describe('navigator.credentials.get override', () => {
  let restores: Array<() => void> = [];

  afterEach(() => {
    restores.forEach((f) => f());
    restores = [];
    vi.resetModules();
  });

  async function loadWithCredentials(
    get: (o?: CredentialRequestOptions) => Promise<unknown>,
  ): Promise<(o?: CredentialRequestOptions) => Promise<unknown>> {
    const prevCreds = Object.getOwnPropertyDescriptor(navigator, 'credentials');
    const prevSecure = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { get, create: vi.fn(async () => null) },
    });
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true });
    restores.push(() => {
      if (prevCreds) Object.defineProperty(navigator, 'credentials', prevCreds);
      else delete (navigator as unknown as { credentials?: unknown }).credentials;
    });
    restores.push(() => {
      if (prevSecure) Object.defineProperty(window, 'isSecureContext', prevSecure);
      else delete (window as unknown as { isSecureContext?: unknown }).isSecureContext;
    });
    vi.resetModules();
    await import('./page-webauthn.js');
    return (navigator as unknown as { credentials: { get: (o?: CredentialRequestOptions) => Promise<unknown> } }).credentials.get;
  }

  it('defers to native without starting a consent round-trip when the signal is already aborted', async () => {
    const native = { id: 'native' } as unknown as Credential;
    const originalGet = vi.fn(async () => native);
    const wrappedGet = await loadWithCredentials(originalGet);
    const controller = new AbortController();
    controller.abort();
    const promise = wrappedGet({
      publicKey: { challenge: new Uint8Array([1, 2, 3]), rpId: location.hostname } as unknown as PublicKeyCredentialRequestOptions,
      signal: controller.signal,
    });
    // The synchronous body already ran: it went straight to the native authenticator, no round-trip.
    expect(originalGet).toHaveBeenCalledTimes(1);
    await expect(promise).resolves.toBe(native);
  });

  it('unblocks and falls back to native when the signal aborts mid-await', async () => {
    const native = { id: 'native' } as unknown as Credential;
    const originalGet = vi.fn(async () => native);
    const wrappedGet = await loadWithCredentials(originalGet);
    const controller = new AbortController();
    const promise = wrappedGet({
      publicKey: { challenge: new Uint8Array([1, 2, 3]), rpId: location.hostname } as unknown as PublicKeyCredentialRequestOptions,
      signal: controller.signal,
    });
    controller.abort(); // the bridge never responds; abort must unblock the await
    await expect(promise).resolves.toBe(native);
  }, 2000);
});
