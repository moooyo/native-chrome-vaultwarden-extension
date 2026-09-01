// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  installPageWebAuthnInterception,
  isWebsitePasskeyDocumentSupported,
  pageWebAuthnController,
} from './page-webauthn.js';
import {
  WEBSITE_PASSKEY_BRIDGE_SOURCE,
  WEBSITE_PASSKEY_PAGE_SOURCE,
  WEBSITE_PASSKEY_WINDOW_VERSION,
} from './website-passkey-feature.js';
import {
  WEBSITE_PASSKEY_PORT_VERSION,
  parseWebsitePasskeyServerMessage,
} from '../messaging/website-passkey-port.js';

const CEREMONY_ID = '11111111-1111-4111-8111-111111111111';
const OUTCOME_ID = '22222222-2222-4222-8222-222222222222';
const ORIGIN = 'https://login.example.com';

let nativeGet: ReturnType<typeof vi.fn>;
let nativeCreate: ReturnType<typeof vi.fn>;
let credentials: CredentialsContainer;
let postMessage: ReturnType<typeof vi.spyOn>;
let previousCredentials: PropertyDescriptor | undefined;
let previousSecureContext: PropertyDescriptor | undefined;

beforeEach(() => {
  (window as unknown as { happyDOM: { setURL(url: string): void } }).happyDOM.setURL(`${ORIGIN}/signin`);
  previousCredentials = Object.getOwnPropertyDescriptor(navigator, 'credentials');
  previousSecureContext = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
  nativeGet = vi.fn(async () => ({ id: 'native-get' }));
  nativeCreate = vi.fn(async () => ({ id: 'native-create' }));
  credentials = { get: nativeGet, create: nativeCreate } as unknown as CredentialsContainer;
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
  Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true });
  postMessage = vi.spyOn(window, 'postMessage').mockImplementation(() => {});
});

afterEach(() => {
  dispatchBridge({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false });
  postMessage.mockRestore();
  vi.restoreAllMocks();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  if (previousCredentials) Object.defineProperty(navigator, 'credentials', previousCredentials);
  else delete (navigator as unknown as { credentials?: unknown }).credentials;
  if (previousSecureContext) Object.defineProperty(window, 'isSecureContext', previousSecureContext);
  else delete (window as unknown as { isSecureContext?: unknown }).isSecureContext;
});

describe('MAIN-world activation lifecycle', () => {
  it('does not intercept automatically and restores the exact native methods on deactivation', () => {
    expect(pageWebAuthnController.active).toBe(false);
    expect(credentials.get).toBe(nativeGet);
    expect(credentials.create).toBe(nativeCreate);

    enable();
    expect(pageWebAuthnController.active).toBe(true);
    expect(credentials.get).not.toBe(nativeGet);
    expect(credentials.create).not.toBe(nativeCreate);

    dispatchBridge({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false });
    expect(pageWebAuthnController.active).toBe(false);
    expect(credentials.get).toBe(nativeGet);
    expect(credentials.create).toBe(nativeCreate);
  });

  it('reuses the realm sentinel instead of installing duplicate listeners or wrappers', () => {
    expect(installPageWebAuthnInterception()).toBe(pageWebAuthnController);
    expect(installPageWebAuthnInterception()).toBe(pageWebAuthnController);
    enable();
    const installedGet = credentials.get;
    enable();
    expect(credentials.get).toBe(installedGet);
  });

  it('allows cross-origin frames when the current document has a secure supported URL', () => {
    expect(isWebsitePasskeyDocumentSupported({
      isSecureContext: false,
      href: 'https://example.com',
    })).toBe(false);
    expect(isWebsitePasskeyDocumentSupported({
      isSecureContext: true,
      href: 'http://example.com',
    })).toBe(false);
    expect(isWebsitePasskeyDocumentSupported({
      isSecureContext: true,
      href: 'http://127.0.0.1:8080',
    })).toBe(true);
    expect(isWebsitePasskeyDocumentSupported({
      isSecureContext: true,
      href: 'https://example.com',
    })).toBe(true);
  });
});

describe('native passthrough prechecks', () => {
  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
    ['NUL', '\0'],
  ])('rejects a generated bridge UUID with trailing %s before interception', async (_label, suffix) => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue(
      `${CEREMONY_ID}${suffix}` as ReturnType<Crypto['randomUUID']>,
    );
    enable();

    await expect(credentials.get(getOptions())).resolves.toEqual({ id: 'native-get' });
    expect(posted('begin')).toHaveLength(0);
  });

  it('passes non-WebAuthn, silent, required-UV, hardware-only, and unsupported get requests through', async () => {
    enable();
    const get = credentials.get.bind(credentials);
    const requests = [
      { password: true },
      getOptions({ mediation: 'silent' }),
      getOptions({ publicKey: { ...baseGetPublicKey(), userVerification: 'required' } }),
      getOptions({
        mediation: 'conditional',
        publicKey: { ...baseGetPublicKey(), userVerification: 'required' },
      }),
      getOptions({ publicKey: {
        ...baseGetPublicKey(),
        allowCredentials: [{ type: 'public-key', id: new Uint8Array([9]), transports: ['usb'] }],
      } }),
      getOptions({ publicKey: {
        ...baseGetPublicKey(),
        extensions: { appid: 'https://example.com' },
      } }),
      getOptions({ publicKey: {
        ...baseGetPublicKey(),
        allowCredentials: Array.from({ length: 65 }, (_, index) => ({
          type: 'public-key' as const,
          id: new Uint8Array([index]),
        })),
      } }),
      getOptions({ publicKey: {
        ...baseGetPublicKey(),
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(1_024) }],
      } }),
    ] as unknown as CredentialRequestOptions[];

    for (const request of requests) await get(request);

    expect(nativeGet).toHaveBeenCalledTimes(requests.length);
    expect(posted('begin')).toHaveLength(0);
  });

  it('passes unsupported algorithms, cross-platform, required-UV, and hardware-only create requests through', async () => {
    enable();
    const create = credentials.create.bind(credentials);
    const requests = [
      createOptions({ pubKeyCredParams: [{ type: 'public-key', alg: -257 }] }),
      createOptions({ authenticatorSelection: { authenticatorAttachment: 'cross-platform' } }),
      createOptions({ authenticatorSelection: { userVerification: 'required' } }),
      createOptions({ excludeCredentials: [
        { type: 'public-key', id: new Uint8Array([9]), transports: ['nfc'] },
      ] }),
      createOptions({ extensions: { largeBlob: { support: 'required' } } }),
      createOptions({ excludeCredentials: Array.from({ length: 65 }, (_, index) => ({
        type: 'public-key' as const,
        id: new Uint8Array([index]),
      })) }),
      createOptions({ excludeCredentials: [{
        type: 'public-key',
        id: new Uint8Array(1_024),
      }] }),
    ] as unknown as CredentialCreationOptions[];

    for (const request of requests) await create(request);

    expect(nativeCreate).toHaveBeenCalledTimes(requests.length);
    expect(posted('begin')).toHaveLength(0);
  });
});

describe('canonical option delivery', () => {
  it('serializes the complete supported get subset without a page-supplied origin', async () => {
    enable();
    const controller = new AbortController();
    const promise = credentials.get({
      mediation: 'required',
      signal: controller.signal,
      publicKey: {
        challenge: new Uint8Array([1, 2, 3]),
        rpId: 'example.com',
        allowCredentials: [
          { type: 'public-key', id: new Uint8Array([4, 5]), transports: ['internal', 'hybrid'] },
        ],
        userVerification: 'preferred',
        timeout: 45_000,
        extensions: {},
      },
    });
    const begin = lastBegin();
    expect(begin.request).toEqual({
      bridgeRequestId: expect.stringMatching(/^[0-9a-f-]{36}$/),
      kind: 'get',
      rpId: 'example.com',
      challenge: 'AQID',
      allowCredentials: [{ id: 'BAU', type: 'public-key', transports: ['hybrid', 'internal'] }],
      userVerification: 'preferred',
      mediation: 'required',
      timeout: 45_000,
    });
    expect(begin.request).not.toHaveProperty('origin');

    controller.abort();
    expect(lastPosted('cancel')).toMatchObject({ bridgeRequestId: begin.request.bridgeRequestId });
    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('races conditional mediation against native and sends only internal-capable IDs to the extension', async () => {
    const native = deferred<Credential | null>();
    nativeGet.mockReturnValue(native.promise);
    enable();

    const promise = credentials.get({
      mediation: 'conditional',
      publicKey: {
        ...baseGetPublicKey(),
        allowCredentials: [
          { type: 'public-key', id: new Uint8Array([4]), transports: ['usb'] },
          { type: 'public-key', id: new Uint8Array([5]), transports: ['internal'] },
        ],
      },
    });
    const begin = lastBegin();
    expect(begin.request).toMatchObject({
      kind: 'get',
      mediation: 'conditional',
      allowCredentials: [{ id: 'BQ', type: 'public-key', transports: ['internal'] }],
    });
    expect(nativeGet).toHaveBeenCalledOnce();
    expect(nativeGet).toHaveBeenCalledWith(expect.objectContaining({
      mediation: 'conditional',
      publicKey: expect.objectContaining({ allowCredentials: expect.any(Array) }),
      signal: expect.any(AbortSignal),
    }));

    const nativeSignal = (nativeGet.mock.calls[0]![0] as CredentialRequestOptions).signal!;
    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'success',
      result: {
        kind: 'get',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credentialId: 'AQ',
        authenticatorData: 'Ag',
        clientDataJSON: 'Aw',
        signature: 'BA',
      },
    });

    await expect(promise).resolves.toMatchObject({ id: 'AQ', type: 'public-key' });
    expect(nativeSignal.aborted).toBe(true);
    expect(nativeGet).toHaveBeenCalledOnce();
  });

  it('lets native conditional UI win and cancels the extension branch without a second native call', async () => {
    enable();

    const promise = credentials.get(getOptions({ mediation: 'conditional' }));
    const begin = lastBegin();

    await expect(promise).resolves.toEqual({ id: 'native-get' });
    expect(nativeGet).toHaveBeenCalledOnce();
    expect(lastPosted('cancel')).toMatchObject({
      bridgeRequestId: begin.request.bridgeRequestId,
      settled: true,
    });
  });

  it('keeps native conditional UI pending after extension fallback or worker restart', async () => {
    for (const terminal of [
      { status: 'fallback', reason: 'no_match' },
      { status: 'error', error: { name: 'UnknownError', message: 'The operation could not be completed.' } },
    ] as const) {
      const native = deferred<Credential | null>();
      nativeGet.mockReturnValueOnce(native.promise);
      enable();
      const promise = credentials.get(getOptions({ mediation: 'conditional' }));
      const begin = lastBegin();
      accept(begin.request.bridgeRequestId);
      outcome(begin.request.bridgeRequestId, terminal);
      let settled = false;
      void promise.then(() => { settled = true; }, () => { settled = true; });
      await Promise.resolve();

      expect(settled).toBe(false);
      native.resolve({ id: 'native-get' } as unknown as Credential);
      await expect(promise).resolves.toEqual({ id: 'native-get' });
    }
    expect(nativeGet).toHaveBeenCalledTimes(2);
  });

  it('aborts both conditional providers from the caller signal', async () => {
    nativeGet.mockImplementation((options: CredentialRequestOptions | undefined) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener('abort', () => reject(options.signal?.reason), { once: true });
    }));
    const controller = new AbortController();
    enable();

    const promise = credentials.get(getOptions({ mediation: 'conditional', signal: controller.signal }));
    const begin = lastBegin();
    const nativeSignal = (nativeGet.mock.calls[0]![0] as CredentialRequestOptions).signal!;
    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError', message: 'The operation was aborted.' });
    expect(nativeSignal.aborted).toBe(true);
    expect(lastPosted('cancel')).toMatchObject({
      bridgeRequestId: begin.request.bridgeRequestId,
      settled: true,
    });
  });

  it('does not let the extension deadline terminate a still-pending native conditional request', async () => {
    vi.useFakeTimers();
    const native = deferred<Credential | null>();
    nativeGet.mockReturnValue(native.promise);
    enable();

    const promise = credentials.get(getOptions({
      mediation: 'conditional',
      publicKey: { ...baseGetPublicKey(), timeout: 1 },
    }));
    expect(lastBegin().request).toMatchObject({ mediation: 'conditional', timeout: 30_000 });
    await vi.advanceTimersByTimeAsync(30_000);
    let settled = false;
    void promise.then(() => { settled = true; }, () => { settled = true; });
    await Promise.resolve();
    expect(settled).toBe(false);

    native.resolve({ id: 'native-get' } as unknown as Credential);
    await expect(promise).resolves.toEqual({ id: 'native-get' });
    expect(nativeGet).toHaveBeenCalledOnce();
  });

  it('serializes the complete supported create subset', async () => {
    enable();
    const controller = new AbortController();
    const promise = credentials.create(createOptions({
      timeout: 90_000,
      excludeCredentials: [
        { type: 'public-key', id: new Uint8Array([7]), transports: ['internal'] },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'preferred',
      },
      attestation: 'direct',
      extensions: { credProps: true },
    }, controller.signal));
    const begin = lastBegin();
    expect(begin.request).toEqual({
      bridgeRequestId: expect.stringMatching(/^[0-9a-f-]{36}$/),
      kind: 'create',
      rp: { id: 'example.com', name: 'Example' },
      user: { id: 'CQ', name: 'person@example.com', displayName: 'Person' },
      challenge: 'AQID',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ id: 'Bw', type: 'public-key', transports: ['internal'] }],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'preferred',
      },
      attestation: 'direct',
      extensions: { credProps: true },
      timeout: 90_000,
    });

    controller.abort();
    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('uses the canonical timeout clamp for the page deadline', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    enable();
    const promise = credentials.create(createOptions({ timeout: 1 }, controller.signal));
    const begin = lastBegin();
    expect(begin.request).toMatchObject({ timeout: 30_000 });

    vi.advanceTimersByTime(1);
    expect(posted('cancel')).toHaveLength(0);
    controller.abort();
    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('caps the canonical timeout at the protocol maximum', async () => {
    const controller = new AbortController();
    enable();
    const promise = credentials.get(getOptions({
      signal: controller.signal,
      publicKey: { ...baseGetPublicKey(), timeout: 999_999 },
    }));
    expect(lastBegin().request).toMatchObject({ timeout: 180_000 });
    controller.abort();
    await expect(promise).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('terminal semantics', () => {
  it('lets native conditional discovery win while the locked extension branch stays pending', async () => {
    enable();
    const promise = credentials.get(getOptions({ mediation: 'conditional' }));
    const begin = lastBegin();
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'unlockPending',
      continuationId: CEREMONY_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
      deadlineAt: Date.now() + 30_000,
    });

    await expect(promise).resolves.toEqual({ id: 'native-get' });
    expect(nativeGet).toHaveBeenCalledTimes(1);
    expect(posted('cancel').at(-1)).toMatchObject({
      bridgeRequestId: begin.request.bridgeRequestId,
      settled: true,
    });
  });

  it('holds an unlock-pending request to its original deadline without native fallback', async () => {
    vi.useFakeTimers();
    enable();
    const promise = credentials.get(getOptions({
      publicKey: { ...baseGetPublicKey(), timeout: 60_000 },
    }));
    const begin = lastBegin();
    const deadlineAt = Date.now() + 5_000;
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'unlockPending',
      continuationId: CEREMONY_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
      deadlineAt,
    });

    vi.advanceTimersByTime(4_999);
    expect(nativeGet).not.toHaveBeenCalled();
    expect(posted('cancel')).toHaveLength(0);
    const rejected = expect(promise).rejects.toMatchObject({
      name: 'NotAllowedError',
      message: 'The operation timed out.',
    });
    vi.advanceTimersByTime(1);
    await rejected;
    expect(nativeGet).not.toHaveBeenCalled();
    expect(posted('cancel')).toHaveLength(1);
  });

  it('rejects a ceremony id change after unlock pending without invoking native', async () => {
    enable();
    const promise = credentials.get(getOptions());
    const begin = lastBegin();
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'unlockPending',
      continuationId: CEREMONY_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
      deadlineAt: Date.now() + 30_000,
    });
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'accepted',
      ceremonyId: OUTCOME_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
      deadlineAt: Date.now() + 30_000,
    });

    await expect(promise).rejects.toMatchObject({ name: 'UnknownError' });
    expect(nativeGet).not.toHaveBeenCalled();
  });

  it.each([
    ['LF', '\n'],
    ['CRLF', '\r\n'],
    ['NUL', '\0'],
  ])('ignores a bridge outcome UUID with trailing %s', async (_label, suffix) => {
    const controller = new AbortController();
    enable();
    const pending = credentials.get(getOptions({ signal: controller.signal }));
    const begin = lastBegin();
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'outcome',
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
      outcomeId: `${OUTCOME_ID}${suffix}`,
      outcome: { status: 'fallback', reason: 'no_match' },
    });

    expect(nativeGet).not.toHaveBeenCalled();
    expect(posted('delivered')).toHaveLength(0);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('handles unbound preflight capacity as explicit fallback and busy as a fixed error', async () => {
    enable();
    const capacityPromise = credentials.create(createOptions());
    const capacityBegin = lastBegin();
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'preflightOutcome',
      bridgeRequestId: capacityBegin.request.bridgeRequestId,
      outcome: { status: 'fallback', reason: 'capacity' },
    });
    await expect(capacityPromise).resolves.toEqual({ id: 'native-create' });

    const busyPromise = credentials.get(getOptions());
    const busyBegin = lastBegin();
    dispatchBridge({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'preflightOutcome',
      bridgeRequestId: busyBegin.request.bridgeRequestId,
      outcome: {
        status: 'error',
        error: {
          name: 'NotAllowedError',
          message: 'Another passkey request is already in progress for this document.',
        },
      },
    });
    await expect(busyPromise).rejects.toMatchObject({
      name: 'NotAllowedError',
      message: 'Another passkey request is already in progress for this document.',
    });
    expect(posted('delivered')).toHaveLength(0);
  });

  it('uses native only for explicit fallback and preserves the remaining canonical timeout', async () => {
    vi.spyOn(performance, 'now')
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(100)
      .mockReturnValue(350);
    enable();
    const promise = credentials.get(getOptions({ publicKey: { ...baseGetPublicKey(), timeout: 1_000 } }));
    const begin = lastBegin();
    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'fallback',
      reason: 'no_match',
    });

    await expect(promise).resolves.toEqual({ id: 'native-get' });
    expect(nativeGet).toHaveBeenCalledWith(expect.objectContaining({
      publicKey: expect.objectContaining({ timeout: 29_750 }),
    }));
    expect(lastPosted('delivered')).toMatchObject({
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
      outcomeId: OUTCOME_ID,
    });
  });

  it('rejects an exact safe DOMException and never turns catch-all errors into fallback', async () => {
    enable();
    const promise = credentials.get(getOptions());
    const begin = lastBegin();
    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'error',
      error: { name: 'NotAllowedError', message: 'Approval was denied.' },
    });

    await expect(promise).rejects.toMatchObject({
      name: 'NotAllowedError',
      message: 'Approval was denied.',
    });
    expect(nativeGet).not.toHaveBeenCalled();
  });

  it('rejects abort, sends cancel, and never invokes native', async () => {
    enable();
    const controller = new AbortController();
    const promise = credentials.create(createOptions({}, controller.signal));
    const begin = lastBegin();
    controller.abort();

    await expect(promise).rejects.toMatchObject({ name: 'AbortError', message: 'The operation was aborted.' });
    expect(nativeCreate).not.toHaveBeenCalled();
    expect(lastPosted('cancel')).toMatchObject({
      bridgeRequestId: begin.request.bridgeRequestId,
      settled: true,
    });
  });

  it('disables future interception but retains an existing request until an explicit outcome', async () => {
    enable();
    const pending = credentials.get(getOptions());
    const begin = lastBegin();
    let settled = false;
    void pending.then(() => { settled = true; }, () => { settled = true; });
    dispatchBridge({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: false });
    await Promise.resolve();

    expect(pageWebAuthnController.active).toBe(false);
    expect(credentials.get).toBe(nativeGet);
    expect(settled).toBe(false);
    expect(nativeGet).not.toHaveBeenCalled();
    expect(lastPosted('cancel')).toMatchObject({
      bridgeRequestId: begin.request.bridgeRequestId,
      settled: false,
    });

    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'error',
      error: { name: 'NotAllowedError', message: 'The request was cancelled.' },
    });
    await expect(pending).rejects.toMatchObject({ name: 'NotAllowedError' });
  });

  it('rejects a worker restart error after accepted and never invokes native', async () => {
    enable();
    const promise = credentials.create(createOptions());
    const begin = lastBegin();
    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'error',
      error: { name: 'UnknownError', message: 'The operation could not be completed.' },
    });

    await expect(promise).rejects.toMatchObject({ name: 'UnknownError' });
    expect(nativeCreate).not.toHaveBeenCalled();
  });

  it.each(['excluded_domain', 'no_match', 'unsupported', 'user_selected_browser'] as const)(
    'handles an atomic %s terminal outcome before accepted',
    async (reason) => {
      enable();
      const promise = credentials.get(getOptions());
      const begin = lastBegin();
      outcome(begin.request.bridgeRequestId, { status: 'fallback', reason });

      await expect(promise).resolves.toEqual({ id: 'native-get' });
      expect(lastPosted('delivered')).toMatchObject({
        ceremonyId: CEREMONY_ID,
        bridgeRequestId: begin.request.bridgeRequestId,
      });
    },
  );

  it('rejects a direct worker restart error when accepted was lost', async () => {
    enable();
    const promise = credentials.create(createOptions());
    const begin = lastBegin();
    outcome(begin.request.bridgeRequestId, {
      status: 'error',
      error: { name: 'UnknownError', message: 'The operation could not be completed.' },
    });

    await expect(promise).rejects.toMatchObject({ name: 'UnknownError' });
    expect(nativeCreate).not.toHaveBeenCalled();
    expect(lastPosted('delivered')).toMatchObject({
      ceremonyId: CEREMONY_ID,
      bridgeRequestId: begin.request.bridgeRequestId,
    });
  });

  it.each([
    'cancelled',
    'expired',
    'context_changed',
    'session_changed',
    'account_changed',
    'cache_changed',
    'feature_disabled',
    'vault_locked',
    'worker_restart',
  ])('rejects the legacy broad fallback reason %s at the wire parser', async (reason) => {
    const controller = new AbortController();
    enable();
    const pending = credentials.get(getOptions({ signal: controller.signal }));
    const bridgeRequestId = lastBegin().request.bridgeRequestId;

    expect(() => parseWebsitePasskeyServerMessage(
      terminalFallbackFixture(bridgeRequestId, reason),
    )).toThrow();

    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('rejects capacity as a terminal fallback because it is preflight-only', async () => {
    const controller = new AbortController();
    enable();
    const pending = credentials.get(getOptions({ signal: controller.signal }));
    const bridgeRequestId = lastBegin().request.bridgeRequestId;

    expect(() => parseWebsitePasskeyServerMessage(
      terminalFallbackFixture(bridgeRequestId, 'capacity'),
    )).toThrow();

    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('credential object shape', () => {
  it('builds an assertion with available browser prototypes, getters, and toJSON', async () => {
    class PublicKeyCredentialStub {}
    class AuthenticatorAssertionResponseStub {}
    vi.stubGlobal('PublicKeyCredential', PublicKeyCredentialStub);
    vi.stubGlobal('AuthenticatorAssertionResponse', AuthenticatorAssertionResponseStub);
    enable();
    const promise = credentials.get(getOptions());
    const begin = lastBegin();
    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'success',
      result: {
        kind: 'get',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credentialId: 'AQ',
        authenticatorData: 'Ag',
        clientDataJSON: 'Aw',
        signature: 'BA',
        userHandle: 'BQ',
      },
    });

    const credential = await promise as PublicKeyCredential & { toJSON(): unknown };
    expect(credential).toBeInstanceOf(PublicKeyCredentialStub);
    expect(credential.response).toBeInstanceOf(AuthenticatorAssertionResponseStub);
    expect([...new Uint8Array(credential.rawId)]).toEqual([1]);
    expect([...new Uint8Array((credential.response as AuthenticatorAssertionResponse).userHandle!)]).toEqual([5]);
    expect(credential.getClientExtensionResults()).toEqual({});
    expect(credential.toJSON()).toEqual({
      id: 'AQ',
      rawId: 'AQ',
      response: {
        clientDataJSON: 'Aw',
        authenticatorData: 'Ag',
        signature: 'BA',
        userHandle: 'BQ',
      },
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    });
  });

  it('builds an attestation with the available prototypes, credProps, transports, and toJSON', async () => {
    class PublicKeyCredentialStub {}
    class AuthenticatorAttestationResponseStub {}
    vi.stubGlobal('PublicKeyCredential', PublicKeyCredentialStub);
    vi.stubGlobal('AuthenticatorAttestationResponse', AuthenticatorAttestationResponseStub);
    enable();
    const promise = credentials.create(createOptions({ extensions: { credProps: true } }));
    const begin = lastBegin();
    accept(begin.request.bridgeRequestId);
    outcome(begin.request.bridgeRequestId, {
      status: 'success',
      result: {
        kind: 'create',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credProps: { rk: true },
        credentialId: 'AQ',
        attestationObject: 'Ag',
        clientDataJSON: 'Aw',
        authData: 'BA',
        publicKeySpki: 'BQ',
        publicKeyAlgorithm: -7,
      },
    });

    const credential = await promise as PublicKeyCredential & { toJSON(): Record<string, unknown> };
    const response = credential.response as AuthenticatorAttestationResponse;
    expect(credential).toBeInstanceOf(PublicKeyCredentialStub);
    expect(response).toBeInstanceOf(AuthenticatorAttestationResponseStub);
    expect(response.getTransports()).toEqual(['internal']);
    expect([...new Uint8Array(response.getAuthenticatorData())]).toEqual([4]);
    expect([...new Uint8Array(response.getPublicKey()!)]).toEqual([5]);
    expect(response.getPublicKeyAlgorithm()).toBe(-7);
    expect(credential.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
    expect(credential.toJSON()).toMatchObject({
      id: 'AQ',
      rawId: 'AQ',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: { credProps: { rk: true } },
      response: { transports: ['internal'], publicKeyAlgorithm: -7 },
    });
  });
});

function enable(): void {
  dispatchBridge({ version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled: true });
}

function dispatchBridge(message: Record<string, unknown>): void {
  window.dispatchEvent(new MessageEvent('message', {
    source: window,
    origin: location.origin,
    data: {
      source: WEBSITE_PASSKEY_BRIDGE_SOURCE,
      ...message,
    },
  }));
}

function accept(bridgeRequestId: string): void {
  dispatchBridge({
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'accepted',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    deadlineAt: Date.now() + 60_000,
  });
}

function outcome(bridgeRequestId: string, value: Record<string, unknown>): void {
  dispatchBridge({
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    outcomeId: OUTCOME_ID,
    outcome: value,
  });
}

function terminalFallbackFixture(bridgeRequestId: string, reason: unknown): unknown {
  return {
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'outcome',
    ceremonyId: CEREMONY_ID,
    bridgeRequestId,
    outcomeId: OUTCOME_ID,
    outcome: { status: 'fallback', reason },
  };
}

function posted(type: string): Array<Record<string, unknown>> {
  const calls = postMessage.mock.calls as unknown[][];
  return calls
    .map((call) => call[0])
    .filter((message): message is Record<string, unknown> => (
      typeof message === 'object' && message !== null && (message as { type?: unknown }).type === type
    ));
}

function lastPosted(type: string): Record<string, unknown> {
  const message = posted(type).at(-1);
  if (!message) throw new Error(`No ${type} message was posted`);
  expect(message).toMatchObject({
    source: WEBSITE_PASSKEY_PAGE_SOURCE,
    version: WEBSITE_PASSKEY_WINDOW_VERSION,
  });
  return message;
}

function lastBegin(): { request: Record<string, unknown> & { bridgeRequestId: string } } {
  return lastPosted('begin') as unknown as {
    request: Record<string, unknown> & { bridgeRequestId: string };
  };
}

function baseGetPublicKey(): PublicKeyCredentialRequestOptions {
  return {
    challenge: new Uint8Array([1, 2, 3]),
    rpId: 'example.com',
  };
}

function getOptions(
  overrides: Partial<CredentialRequestOptions> = {},
): CredentialRequestOptions {
  return { publicKey: baseGetPublicKey(), ...overrides };
}

function deferred<Value>(): {
  readonly promise: Promise<Value>;
  readonly resolve: (value: Value) => void;
  readonly reject: (error: unknown) => void;
} {
  let resolve!: (value: Value) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<Value>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function createOptions(
  overrides: Partial<PublicKeyCredentialCreationOptions> = {},
  signal?: AbortSignal,
): CredentialCreationOptions {
  return {
    publicKey: {
      rp: { id: 'example.com', name: 'Example' },
      user: {
        id: new Uint8Array([9]),
        name: 'person@example.com',
        displayName: 'Person',
      },
      challenge: new Uint8Array([1, 2, 3]),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      ...overrides,
    },
    ...(signal ? { signal } : {}),
  };
}
