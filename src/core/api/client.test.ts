import { describe, it, expect, vi } from 'vitest';
import {
  ApiClient,
  ApiHttpError,
  ApiResponseTooLargeError,
  ApiTimeoutError,
  ApiUnsupportedSsoAccountError,
  BITWARDEN_CLIENT_VERSION,
  CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES,
  PASSWORD_HINT_MESSAGE_MAX_LENGTH,
  parsePasswordHintResponseBody,
  isVaultConflictError,
} from './client.js';
import { createMemoryStore } from '../../platform/store.js';
import { USER_KEY_VECTOR_600K } from '../../../test/vectors.js';
import { AppError } from '../errors.js';
import { ClientEventType } from '../events/client-event.js';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: {
        get: vi.fn(),
        set: vi.fn(),
        remove: vi.fn(),
        clear: vi.fn(),
      },
      session: {
        get: vi.fn(),
        set: vi.fn(),
        remove: vi.fn(),
        clear: vi.fn(),
      },
    },
  },
}));

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function textResponse(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'text/html' } });
}

function vaultwardenPasswordHintError(message: string): Record<string, unknown> {
  return {
    message,
    validationErrors: { '': [message] },
    errorModel: { message, object: 'error' },
    error: '',
    error_description: '',
    exceptionMessage: null,
    exceptionStackTrace: null,
    innerExceptionMessage: null,
    object: 'error',
  };
}

function serverHeaders(headers: Readonly<Record<string, string>> = {}): Record<string, string> {
  return {
    ...headers,
    'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    'Bitwarden-Client-Name': 'browser',
  };
}

async function captureApiHttpError(operation: Promise<unknown>): Promise<ApiHttpError> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof ApiHttpError) {
      return error;
    }
    throw error;
  }
  throw new Error('Expected ApiHttpError');
}

describe('ApiClient prelogin', () => {
  it('POSTs /identity/accounts/prelogin with trimmed lowercase email in JSON body', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ kdf: 0, kdfIterations: 600000 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const res = await api.prelogin('  USER@EXAMPLE.COM  ');
    expect(res).toEqual({ kdf: 0, kdfIterations: 600000 });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/identity/accounts/prelogin', expect.objectContaining({
      method: 'POST',
      headers: serverHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ email: 'user@example.com' }),
    }));
  });
});

describe('ApiClient password hint', () => {
  it.each([200, 204])('accepts an empty %i response from the anonymous endpoint', async (status) => {
    const provider = vi.fn(async () => 'https://vw.example.com/base/');
    const fetchFn = vi.fn(async () => new Response(null, { status }));
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.requestPasswordHint('  USER@Example.COM  ')).resolves.toEqual({
      status: 'sent',
    });

    expect(provider).toHaveBeenCalledOnce();
    expect(fetchFn).toHaveBeenCalledOnce();
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/base/api/accounts/password-hint');
    expect(init).toMatchObject({
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      body: JSON.stringify({ email: 'user@example.com' }),
    });
    const headers = new Headers(init.headers);
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('cache-control')).toBe('no-store');
    expect(headers.get('pragma')).toBe('no-cache');
    expect(headers.get('Bitwarden-Client-Version')).toBe(BITWARDEN_CLIENT_VERSION);
    expect(headers.get('Bitwarden-Client-Name')).toBe('browser');
    expect(headers.has('authorization')).toBe(false);
    expect(headers.has('device-identifier')).toBe(false);
    expect(headers.has('x-device-identifier')).toBe(false);
    expect(headers.has('x-request-email')).toBe(false);
  });

  it('preserves the server JSON error body without retrying', async () => {
    const body = { ErrorModel: { Message: 'Password hints are disabled.' } };
    const fetchFn = vi.fn(async () => jsonResponse(body, 400));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    const error = await captureApiHttpError(api.requestPasswordHint('user@example.com'));

    expect(error).toMatchObject({ status: 400, body });
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it.each([
    [
      'Your password hint is: favorite constellation',
      { status: 'hint', message: 'Your password hint is: favorite constellation' },
    ],
    ['Sorry, you have no password hint...', { status: 'no_hint' }],
    [
      'This server is not configured to provide password hints.',
      { status: 'unavailable' },
    ],
  ] as const)('projects the exact Vaultwarden 400 outcome: %s', async (message, expected) => {
    const fetchFn = vi.fn(async () => jsonResponse(vaultwardenPasswordHintError(message), 400));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.requestPasswordHint('user@example.com')).resolves.toEqual(expected);
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('rejects malformed, widened, oversized, and accessor-backed hint envelopes', () => {
    const valid = vaultwardenPasswordHintError('Your password hint is: safe');
    expect(parsePasswordHintResponseBody({
      ...valid,
      errorModel: { message: 'Your password hint is: safe', object: 'error', extra: true },
    })).toBeUndefined();
    expect(parsePasswordHintResponseBody(vaultwardenPasswordHintError(
      'Your password hint is: ' + 'x'.repeat(PASSWORD_HINT_MESSAGE_MAX_LENGTH),
    ))).toBeUndefined();

    const errorModel = { object: 'error' } as Record<string, unknown>;
    Object.defineProperty(errorModel, 'message', {
      enumerable: true,
      get: () => { throw new Error('getter must not run'); },
    });
    expect(() => parsePasswordHintResponseBody({ ...valid, errorModel })).not.toThrow();
    expect(parsePasswordHintResponseBody({ ...valid, errorModel })).toBeUndefined();
  });

  it('preserves a rate-limit response and does not retry it', async () => {
    const responseBody = 'Too many requests. Try again later.';
    const fetchFn = vi.fn(async () => textResponse(responseBody, 429));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    const error = await captureApiHttpError(api.requestPasswordHint('user@example.com'));

    expect(error).toMatchObject({ status: 429, body: responseBody });
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('bounds response bodies before exposing an error body', async () => {
    const fetchFn = vi.fn(async () => new Response('x'.repeat(64 * 1024 + 1), { status: 400 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.requestPasswordHint('user@example.com')).rejects.toEqual(
      new ApiResponseTooLargeError(64 * 1024, 64 * 1024 + 1),
    );
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('checks a scoped server guard immediately before dispatch', async () => {
    const provider = vi.fn(async () => 'https://unused.example.com');
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));
    const guard = vi.fn(() => { throw new AppError('session_expired', 'server scope changed'); });
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    }).forServer('https://fixed.example/base').withRequestGuard(guard);

    await expect(api.requestPasswordHint('user@example.com')).rejects.toThrow('server scope changed');

    expect(guard).toHaveBeenCalledOnce();
    expect(provider).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    '',
    '   ',
    'not-an-email',
    '@example.com',
    'user@',
    'user@@example.com',
    'user @example.com',
    'user@example.com\u0000',
    '\tuser@example.com',
    'a'.repeat(250) + '@b.co',
  ])('rejects an invalid email before resolving the server: %j', async (email) => {
    const provider = vi.fn(async () => 'https://vw.example.com');
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.requestPasswordHint(email)).rejects.toBeInstanceOf(TypeError);
    expect(provider).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe('ApiClient device identifier', () => {
  it('stores and reuses a stable device identifier', async () => {
    const store = createMemoryStore();
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', localStore: store });
    const first = await api.getDeviceIdentifier();
    const second = await api.getDeviceIdentifier();
    expect(first).toMatch(/[0-9a-f-]{36}/);
    expect(second).toBe(first);
  });

  it('returns the same device identifier to concurrent first-time callers', async () => {
    const store = createMemoryStore();
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', localStore: store });
    const [first, second] = await Promise.all([api.getDeviceIdentifier(), api.getDeviceIdentifier()]);
    expect(second).toBe(first);
  });

});

describe('ApiClient protocol version header', () => {
  it.each([
    ['prelogin', (api: ApiClient) => api.prelogin('u@example.com')],
    ['registration', (api: ApiClient) => api.register({
      email: 'u@example.com',
      masterPasswordHash: 'hash',
      masterPasswordHint: '',
      key: '2.key',
      keys: { publicKey: 'public', encryptedPrivateKey: '2.private' },
      kdf: 0,
      kdfIterations: 600_000,
    })],
    ['password token', (api: ApiClient) => api.passwordLogin({
      email: 'u@example.com',
      masterPasswordHash: 'hash',
    })],
    ['refresh token', (api: ApiClient) => api.refresh('refresh')],
    ['sync', (api: ApiClient) => api.sync('access')],
    ['server config', (api: ApiClient) => api.getServerConfig()],
    ['JSON mutation', (api: ApiClient) => api.createFolder('access', '2.name')],
    ['no-body mutation', (api: ApiClient) => api.deleteFolder('access', 'folder')],
  ])('sends the exact version through the %s request path', async (_label, operation) => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access',
      refresh_token: 'refresh',
      token_type: 'Bearer',
      expires_in: 3600,
      Key: USER_KEY_VECTOR_600K.akey,
      kdf: 0,
      kdfIterations: 600_000,
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [],
    }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/base',
      fetchFn,
      localStore: store,
    });

    await operation(api);

    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get('Bitwarden-Client-Version')).toBe('2024.12.0');
    expect(headers.get('Bitwarden-Client-Name')).toBe('browser');
  });

  it('overrides caller spoofing while preserving unrelated server headers', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const requestBytes = (api as unknown as {
      requestBytes(url: string, init: RequestInit): Promise<{ response: Response; body: Uint8Array }>;
    }).requestBytes.bind(api);

    await requestBytes('https://vw.example.com/api/test', {
      headers: {
        'Bitwarden-Client-Version': '9999.0.0',
        'Bitwarden-Client-Name': 'desktop',
        'x-preserved': 'value',
      },
    });

    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).toEqual(serverHeaders({
      'x-preserved': 'value',
    }));
  });

  it('normalizes the current prelogin response and removes null Argon2 fields for PBKDF2', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      kdf: 0,
      kdfIterations: 600_000,
      kdfMemory: null,
      kdfParallelism: null,
      kdfSettings: {
        kdfType: 0,
        iterations: 600_000,
        memory: null,
        parallelism: null,
      },
      salt: 'user@example.com',
    }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.prelogin('user@example.com')).resolves.toEqual({
      kdf: 0,
      kdfIterations: 600_000,
    });
  });
});

describe('ApiClient server config', () => {
  it('fetches only the configured base-path api/config without credentials', async () => {
    const payload = { version: '2026.8.0', environment: { notifications: 'https://notify.example' } };
    const encoded = JSON.stringify(payload);
    const fetchFn = vi.fn(async (_input: string | URL | Request, _init?: RequestInit) => new Response(encoded, {
      status: 200,
      headers: serverHeaders({ 'content-type': 'application/json' }),
    }));
    const provider = vi.fn(async () => 'https://vault.example/tenant');
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.getServerConfig(64 * 1024)).resolves.toEqual({
      body: payload,
      responseBytes: new TextEncoder().encode(encoded).byteLength,
    });
    expect(provider).toHaveBeenCalledOnce();
    expect(fetchFn).toHaveBeenCalledWith(
      'https://vault.example/tenant/api/config',
      expect.objectContaining({
        method: 'GET',
        credentials: 'omit',
        redirect: 'error',
      }),
    );
    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.has('authorization')).toBe(false);
    expect(headers.get('Bitwarden-Client-Version')).toBe(BITWARDEN_CLIENT_VERSION);
  });

  it('uses the bounded reader for a caller-lowered server config limit', async () => {
    const first = new Uint8Array([1, 2]);
    const second = new Uint8Array([3, 4]);
    const cancel = vi.fn();
    const fetchFn = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first);
        controller.enqueue(second);
      },
      cancel,
    }), { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vault.example/base/',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.getServerConfig(3)).rejects.toEqual(new ApiResponseTooLargeError(3, 4));
    expect(cancel).toHaveBeenCalledOnce();
    expect([...first, ...second]).toEqual([0, 0, 0, 0]);
  });

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER, 1024 * 1024 + 1])(
    'rejects an invalid server config response limit before resolving the server: %s',
    async (maxResponseBytes) => {
      const provider = vi.fn(async () => 'https://vault.example');
      const fetchFn = vi.fn(async () => jsonResponse({ version: '2026.8.0' }));
      const api = new ApiClient({
        serverUrlProvider: provider,
        fetchFn,
        localStore: createMemoryStore(),
      });

      await expect(api.getServerConfig(maxResponseBytes)).rejects.toBeInstanceOf(RangeError);
      expect(provider).not.toHaveBeenCalled();
      expect(fetchFn).not.toHaveBeenCalled();
    },
  );

  it('does not expose a rejected config response body through ApiHttpError', async () => {
    const secret = new Uint8Array(new TextEncoder().encode('{"secret":"server-private"}'));
    const fetchFn = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(secret);
        controller.close();
      },
    }), { status: 503 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vault.example',
      fetchFn,
      localStore: createMemoryStore(),
    });

    const error = await captureApiHttpError(api.getServerConfig(1024));
    expect(error).toMatchObject({ status: 503, body: undefined });
    expect(error.message).not.toContain('server-private');
    expect([...secret].every((byte) => byte === 0)).toBe(true);
  });

  it('bounds rejected server config bodies before constructing ApiHttpError', async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const cancel = vi.fn();
    const fetchFn = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
      },
      cancel,
    }), { status: 503 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vault.example',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.getServerConfig(3)).rejects.toEqual(new ApiResponseTooLargeError(3, 4));
    expect(cancel).toHaveBeenCalledOnce();
    expect([...bytes]).toEqual([0, 0, 0, 0]);
  });

  it.each([
    'http://remote.example/vault/',
    'https://user:password@vault.example/',
    'ftp://vault.example/',
    'https://vault.example/base/%2f/escape/',
    `https://vault.example/${'a'.repeat(2_100)}/`,
  ])('rejects an unsafe server config base before fetch: %s', async (serverUrl) => {
    const fetchFn = vi.fn(async () => jsonResponse({ version: '2026.8.0' }));
    const api = new ApiClient({
      serverUrlProvider: async () => serverUrl,
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.getServerConfig()).rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('keeps the fixed-server request guard adjacent to the server config fetch', async () => {
    const provider = vi.fn(async () => 'https://dynamic.example/');
    const fetchFn = vi.fn(async () => jsonResponse({ version: '2026.8.0' }));
    const guard = vi.fn(() => { throw new Error('capability lease expired'); });
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    }).forServer('http://127.0.0.1:18082/vault/').withRequestGuard(guard);

    await expect(api.getServerConfig(64 * 1024)).rejects.toThrow('capability lease expired');
    expect(provider).not.toHaveBeenCalled();
    expect(guard).toHaveBeenCalledOnce();
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe('ApiClient request guards', () => {
  it('pins a clone to one server without consulting the provider', async () => {
    const serverUrlProvider = vi.fn(async () => {
      throw new Error('dynamic provider must not be read');
    });
    const fetchFn = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => jsonResponse({
      profile: { id: 'u', email: 'u@example.com' }, ciphers: [],
    }));
    const api = new ApiClient({
      serverUrlProvider,
      fetchFn,
      localStore: createMemoryStore(),
    }).forServer('https://fixed.example/base');

    await api.sync('token');

    expect(serverUrlProvider).not.toHaveBeenCalled();
    expect(fetchFn).toHaveBeenCalledWith(
      'https://fixed.example/base/api/sync',
      expect.objectContaining({ headers: serverHeaders({ authorization: 'Bearer token' }) }),
    );
  });

  it.each([
    'https://fixed.example/base?tenant=one',
    'https://fixed.example/base#settings',
    'https://fixed.example/base?',
    'https://fixed.example/base#',
  ])('rejects a fixed server URL containing a query or fragment: %s', (serverUrl) => {
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://dynamic.example',
      localStore: createMemoryStore(),
    });

    expect(() => api.forServer(serverUrl)).toThrow('serverUrl must not include query or fragment');
  });

  it('preserves fixed-server and composed-guard behavior in either clone order', async () => {
    const provider = vi.fn(async () => 'https://dynamic.example');
    const fetchFn = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => jsonResponse({
      profile: { id: 'u', email: 'u@example.com' }, ciphers: [],
    }));
    const firstGuard = vi.fn();
    const secondGuard = vi.fn();
    const base = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    });

    await base.withRequestGuard(firstGuard).forServer('https://a.example').sync('a');
    await base.forServer('https://b.example').withRequestGuard(secondGuard).sync('b');

    expect(provider).not.toHaveBeenCalled();
    expect(firstGuard).toHaveBeenCalledOnce();
    expect(secondGuard).toHaveBeenCalledOnce();
    expect(fetchFn.mock.calls.map(([url]) => url)).toEqual([
      'https://a.example/api/sync',
      'https://b.example/api/sync',
    ]);
  });

  it('limits absolute-URL bearer tokens to the fixed server base path', async () => {
    const provider = vi.fn(async () => 'https://dynamic.example');
    const fetchFn = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => (
      new Response(new Uint8Array([1]), { status: 200 })
    ));
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn: fetchFn as never,
      localStore: createMemoryStore(),
    }).forServer('https://fixed.example/base');

    await api.downloadAttachment('https://fixed.example/base/blob', 'secret');
    await api.downloadAttachment('https://fixed.example/base', 'secret');
    await api.downloadAttachment('https://fixed.example/base-sibling/blob', 'secret');
    await api.downloadAttachment('https://fixed.example/other/blob', 'secret');
    await api.downloadAttachment('https://dynamic.example/blob', 'secret');
    await api.uploadSendFileData(
      'secret',
      'https://fixed.example/base/upload',
      new Uint8Array([1]),
      '2.encrypted',
    );
    await api.uploadSendFileData(
      'secret',
      'https://fixed.example/base-sibling/upload',
      new Uint8Array([1]),
      '2.encrypted',
    );

    expect(provider).not.toHaveBeenCalled();
    expect((fetchFn.mock.calls[0]![1] as RequestInit).headers).toEqual(serverHeaders({ authorization: 'Bearer secret' }));
    expect((fetchFn.mock.calls[1]![1] as RequestInit).headers).toEqual(serverHeaders({ authorization: 'Bearer secret' }));
    for (const call of fetchFn.mock.calls.slice(2, 5)) {
      expect((call[1] as RequestInit).headers).toEqual({});
    }
    expect((fetchFn.mock.calls[5]![1] as RequestInit).headers).toEqual(serverHeaders({ authorization: 'Bearer secret' }));
    expect((fetchFn.mock.calls[6]![1] as RequestInit).headers).toEqual({});
  });

  it.each([301, 302, 307, 308])(
    'forces redirect:error for %i responses so secrets are not replayed to same- or cross-origin targets',
    async (status) => {
      for (const target of [
        'https://vw.example.com/redirect-target',
        'https://other.example/redirect-target',
      ]) {
        const requests: Array<{ url: string; init: RequestInit }> = [];
        const fetchFn: typeof fetch = async (input, init = {}) => {
          const url = typeof input === 'string'
            ? input
            : input instanceof URL
              ? input.toString()
              : input.url;
          requests.push({ url, init });
          if (url === target) {
            return jsonResponse({ access_token: 'redirected', profile: {}, ciphers: [] });
          }
          if (init.redirect !== 'error') return fetchFn(target, init);
          return new Response('', { status, headers: { location: target } });
        };
        const store = createMemoryStore();
        await store.set('deviceIdentifier', 'device-123');
        const api = new ApiClient({
          serverUrlProvider: async () => 'https://vw.example.com',
          fetchFn,
          localStore: store,
        });

        await expect(api.sync('access-secret')).rejects.toBeInstanceOf(ApiHttpError);
        await expect(api.refresh('refresh-secret')).rejects.toBeInstanceOf(ApiHttpError);

        expect(requests).toHaveLength(2);
        expect(requests.every((request) => request.url !== target)).toBe(true);
        expect(requests.every((request) => request.init.redirect === 'error')).toBe(true);
        expect(requests[0]?.init.headers).toEqual(serverHeaders({ authorization: 'Bearer access-secret' }));
        expect(requests[1]?.init.body).toContain('refresh_token=refresh-secret');
      }
    },
  );

  it('overrides a caller-provided redirect mode at the final fetch boundary', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const requestBytes = (api as unknown as {
      requestBytes(url: string, init: RequestInit): Promise<{ response: Response; body: Uint8Array }>;
    }).requestBytes.bind(api);

    await requestBytes('https://vw.example.com/api/sync', { redirect: 'follow' });

    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/api/sync',
      expect.objectContaining({ redirect: 'error' }),
    );
  });

  it('revalidates after deferred server URL resolution and never fetches when stale', async () => {
    let resolveServerUrl!: (url: string) => void;
    const serverUrl = new Promise<string>((resolve) => { resolveServerUrl = resolve; });
    const serverUrlProvider = vi.fn(() => serverUrl);
    const fetchFn = vi.fn(async () => jsonResponse({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));
    let current = true;
    const guard = vi.fn(() => {
      if (!current) throw new Error('session changed');
    });
    const api = new ApiClient({ serverUrlProvider, fetchFn, localStore: createMemoryStore() })
      .withRequestGuard(guard);

    const request = api.sync('token');
    await vi.waitFor(() => expect(serverUrlProvider).toHaveBeenCalledOnce());
    current = false;
    resolveServerUrl('https://new-server.example');

    await expect(request).rejects.toThrow('session changed');
    expect(guard).toHaveBeenCalledOnce();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    ['JSON', (api: ApiClient) => api.sync('token')],
    ['no-body', (api: ApiClient) => api.deleteFolder('token', 'folder-1')],
    ['token', (api: ApiClient) => api.passwordLogin({ email: 'u@example.com', masterPasswordHash: 'hash' })],
  ])('guards the %s request path before fetch', async (_label, request) => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({}));
    const guard = vi.fn(() => { throw new Error('operation expired'); });
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: store,
    }).withRequestGuard(guard);

    await expect(request(api)).rejects.toThrow('operation expired');
    expect(guard).toHaveBeenCalledOnce();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    ['download', (api: ApiClient) => api.downloadAttachment('https://vw.example.com/attachments/a1', 'token')],
    ['upload', (api: ApiClient) => api.uploadSendFileData(
      'token',
      'https://vw.example.com/sends/s1/file/f1',
      new Uint8Array([1, 2, 3]),
      '2.encrypted-name',
    )],
  ])('guards an absolute URL %s immediately before fetch', async (_label, request) => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const guard = vi.fn(() => { throw new Error('operation expired'); });
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    }).withRequestGuard(guard);

    await expect(request(api)).rejects.toThrow('operation expired');
    expect(guard).toHaveBeenCalledOnce();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('runs composed guards once per real fetch and shares the device identifier single-flight', async () => {
    const store = createMemoryStore();
    let releaseDeviceRead!: () => void;
    const deviceReadGate = new Promise<void>((resolve) => { releaseDeviceRead = resolve; });
    const get = vi.spyOn(store, 'get').mockImplementation(async () => {
      await deviceReadGate;
      return 'device-shared';
    });
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access', expires_in: 3600, refresh_token: 'refresh', token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey, Kdf: 0, KdfIterations: 600000,
    }));
    const firstGuard = vi.fn();
    const secondGuard = vi.fn();
    const base = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: store,
    });
    const guarded = base.withRequestGuard(firstGuard).withRequestGuard(secondGuard);

    const baseId = base.getDeviceIdentifier();
    const login = guarded.passwordLogin({ email: 'u@example.com', masterPasswordHash: 'hash' });
    await vi.waitFor(() => expect(get).toHaveBeenCalledOnce());
    releaseDeviceRead();

    await expect(baseId).resolves.toBe('device-shared');
    await expect(login).resolves.toMatchObject({ kind: 'success' });
    expect(firstGuard).toHaveBeenCalledOnce();
    expect(secondGuard).toHaveBeenCalledOnce();
    expect(fetchFn).toHaveBeenCalledOnce();
  });
});

describe('ApiClient error handling', () => {
  it('throws ApiHttpError with status and JSON body on non-OK JSON response', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: 'Invalid email' }, 400));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const error = await captureApiHttpError(api.prelogin('invalid'));
    expect(error.name).toBe('ApiHttpError');
    expect(error.status).toBe(400);
    expect(error.body).toEqual({ error: 'Invalid email' });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('throws ApiHttpError with status on non-OK non-JSON response (HTML error page)', async () => {
    const html = '<html><body>502 Bad Gateway</body></html>';
    const fetchFn = vi.fn(async () => textResponse(html, 502));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const error = await captureApiHttpError(api.prelogin('user@example.com'));
    expect(error.status).toBe(502);
    expect(error.body).toBe(html);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('throws ApiHttpError with status on non-OK response with no body', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 503 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const error = await captureApiHttpError(api.prelogin('user@example.com'));
    expect(error.status).toBe(503);
    expect(error.body).toBe('');
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('rejects OK response with non-JSON body (parsing error)', async () => {
    const fetchFn = vi.fn(async () => textResponse('not valid json', 200));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    await expect(api.prelogin('user@example.com')).rejects.toThrow(SyntaxError);
  });
});

describe('ApiClient device login protocol', () => {
  const requestId = '12345678-1234-4123-8123-123456789abc';
  const accessCode = 'Abcdefghijklmnopqrstuv123';
  const publicKey = Buffer.alloc(256).toString('base64');
  const wrappedUserKey = `4.${Buffer.alloc(256, 7).toString('base64')}`;
  const createInput = {
    email: ' User@Example.COM ',
    publicKey,
    deviceIdentifier: 'device-123',
    accessCode,
    type: 0 as const,
  };
  const authResponse = {
    id: requestId,
    publicKey,
    requestDeviceIdentifier: 'device-123',
  };

  function makeApi(fetchFn: typeof fetch, deviceIdentifier = 'device-123'): ApiClient {
    const store = createMemoryStore();
    void store.set('deviceIdentifier', deviceIdentifier);
    return new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/base',
      fetchFn,
      localStore: store,
    });
  }

  it('checks a known device with official base64url headers and no email in the URL', async () => {
    const fetchFn = vi.fn(async () => jsonResponse(true));
    const api = makeApi(fetchFn);

    await expect(api.isKnownDevice({ email: ' User@Example.COM ' })).resolves.toBe(true);

    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/base/api/devices/knowndevice');
    expect(url).not.toContain('user');
    expect(url).not.toContain('?');
    const headers = new Headers(init.headers);
    expect(headers.get('X-Request-Email')).toBe('dXNlckBleGFtcGxlLmNvbQ');
    expect(headers.get('X-Device-Identifier')).toBe('device-123');
    expect(headers.get('Device-Identifier')).toBe('device-123');
    expect(headers.get('Device-Type')).toBe('2');
    expect(headers.has('authorization')).toBe(false);
    expect(headers.get('Cache-Control')).toBe('no-store');
    expect(headers.get('Pragma')).toBe('no-cache');
    expect(init.cache).toBe('no-store');
    expect(init.credentials).toBe('omit');
  });

  it('uses and validates an explicitly supplied identifier for known-device checks', async () => {
    const fetchFn = vi.fn(async () => jsonResponse(false));
    const api = makeApi(fetchFn, 'stored-device');

    await expect(api.isKnownDevice({
      email: 'user@example.com',
      deviceIdentifier: 'explicit-device',
    })).resolves.toBe(false);

    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get('X-Device-Identifier')).toBe('explicit-device');
    expect(headers.get('Device-Identifier')).toBe('explicit-device');
  });

  it.each([null, 'true', 1, { known: true }, [true]])(
    'rejects a non-boolean known-device response: %j',
    async (response) => {
      const fetchFn = vi.fn(async () => jsonResponse(response));
      await expect(makeApi(fetchFn).isKnownDevice({ email: 'user@example.com' }))
        .rejects.toThrow('known-device response must be boolean');
    },
  );

  it('creates an anonymous request with normalized JSON and matching device headers', async () => {
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    const response = await makeApi(fetchFn).createAuthRequest(createInput);

    expect(response).toEqual(authResponse);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/base/api/auth-requests/');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('omit');
    expect(JSON.parse(init.body as string)).toEqual({
      ...createInput,
      email: 'user@example.com',
    });
    const headers = new Headers(init.headers);
    expect(headers.get('Device-Type')).toBe('2');
    expect(headers.get('Device-Identifier')).toBe(createInput.deviceIdentifier);
    expect(headers.has('authorization')).toBe(false);
  });

  it.each([
    ['invalid email', { ...createInput, email: 'not-an-email' }],
    ['invalid public key', { ...createInput, publicKey: 'not base64' }],
    ['short public key', { ...createInput, publicKey: 'AQIDBA==' }],
    ['non-canonical public key', { ...createInput, publicKey: `${'A'.repeat(342)}B=` }],
    ['blank device', { ...createInput, deviceIdentifier: '' }],
    ['header injection', { ...createInput, deviceIdentifier: 'device\r\ninjected' }],
    ['short access code', { ...createInput, accessCode: 'short' }],
    ['wrong request type', { ...createInput, type: 1 }],
    ['unknown field', { ...createInput, secret: 'unexpected' }],
  ])('rejects %s before creating an auth request', async (_label, input) => {
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    await expect(makeApi(fetchFn).createAuthRequest(input as never)).rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('URL-encodes the access code while preserving one strict UUID path segment', async () => {
    const code = `${'a'.repeat(18)}+/?&=%#`;
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));

    await makeApi(fetchFn).getAuthRequestResponse(requestId.toUpperCase(), code);

    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const parsed = new URL(url);
    expect(parsed.pathname).toBe(`/base/api/auth-requests/${requestId}/response`);
    expect(parsed.searchParams.get('code')).toBe(code);
    expect(parsed.searchParams.size).toBe(1);
    expect(url).not.toContain('#');
    expect(init.cache).toBe('no-store');
    expect(init.credentials).toBe('omit');
    const headers = new Headers(init.headers);
    expect(headers.get('Device-Type')).toBe('2');
    expect(headers.get('Device-Identifier')).toBe('device-123');
    expect(headers.has('authorization')).toBe(false);
    expect(headers.get('Cache-Control')).toBe('no-store');
    expect(headers.get('Pragma')).toBe('no-cache');
  });

  it.each([
    `${requestId}\n`,
    requestId.slice(0, -1),
    `../${requestId}`,
    '00000000-0000-0000-0000-000000000000',
    '12345678-1234-0123-8123-123456789abc',
  ])('rejects a non-strict auth request UUID before fetch: %j', async (id) => {
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    await expect(makeApi(fetchFn).getAuthRequestResponse(id, accessCode))
      .rejects.toThrow(/UUID|characters/u);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([null, true, [], 'response'])('rejects a non-object auth response: %j', async (body) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).getAuthRequestResponse(requestId, accessCode))
      .rejects.toThrow('auth request response must be a JSON object');
  });

  it('unwraps camelCase and PascalCase pending list envelopes', async () => {
    const fetchFn = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: [authResponse], object: 'list' }))
      .mockResolvedValueOnce(jsonResponse({ Data: [authResponse], Object: 'list' }));
    const api = makeApi(fetchFn);

    await expect(api.listPendingAuthRequests('access-token')).resolves.toEqual([authResponse]);
    await expect(api.listPendingAuthRequests('access-token')).resolves.toEqual([authResponse]);

    for (const [url, init] of fetchFn.mock.calls as unknown as Array<[string, RequestInit]>) {
      expect(url).toBe('https://vw.example.com/base/api/auth-requests/pending');
      expect(init.method).toBe('GET');
      expect(init.cache).toBe('no-store');
      expect(init.credentials).toBe('omit');
      const headers = new Headers(init.headers);
      expect(headers.get('authorization')).toBe('Bearer access-token');
      expect(headers.get('Cache-Control')).toBe('no-store');
      expect(headers.get('Pragma')).toBe('no-cache');
    }
  });

  it.each([
    {},
    { data: [], Data: [] },
    { data: authResponse },
    { data: [null] },
    { data: Array.from({ length: 1_025 }, () => authResponse) },
  ])('rejects a malformed pending list envelope', async (body) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).listPendingAuthRequests('access-token')).rejects.toThrow();
  });

  it('fetches a single authenticated request', async () => {
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    await expect(makeApi(fetchFn).getAuthRequest('access-token', requestId))
      .resolves.toEqual(authResponse);

    expect(fetchFn).toHaveBeenCalledWith(
      `https://vw.example.com/base/api/auth-requests/${requestId}`,
      expect.objectContaining({
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: serverHeaders({
          'cache-control': 'no-store',
          pragma: 'no-cache',
          authorization: 'Bearer access-token',
        }),
      }),
    );
  });

  it('approves with the wrapped key and denies without sending key material', async () => {
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    const api = makeApi(fetchFn);

    await api.updateAuthRequest('access-token', requestId, {
      key: wrappedUserKey,
      masterPasswordHash: 'master-hash',
      deviceIdentifier: 'approver-device',
      requestApproved: true,
    });
    await api.updateAuthRequest('access-token', requestId, {
      deviceIdentifier: 'approver-device',
      requestApproved: false,
    });

    const calls = fetchFn.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({
      key: wrappedUserKey,
      masterPasswordHash: 'master-hash',
      deviceIdentifier: 'approver-device',
      requestApproved: true,
    });
    expect(JSON.parse(calls[1]![1].body as string)).toEqual({
      key: '',
      deviceIdentifier: 'approver-device',
      requestApproved: false,
    });
    for (const [, init] of calls) {
      expect(init.method).toBe('PUT');
      expect(init.credentials).toBe('omit');
      expect(new Headers(init.headers).get('authorization')).toBe('Bearer access-token');
    }
  });

  it.each([
    ['approved without key', { deviceIdentifier: 'approver', requestApproved: true }],
    ['approved with malformed key', { key: '4.not-base64', deviceIdentifier: 'approver', requestApproved: true }],
    ['denied with key', { key: '4.secret', deviceIdentifier: 'approver', requestApproved: false }],
    ['denied with hash', { masterPasswordHash: 'secret', deviceIdentifier: 'approver', requestApproved: false }],
    ['invalid boolean', { key: '4.secret', deviceIdentifier: 'approver', requestApproved: 'true' }],
    ['unknown field', { key: '4.secret', deviceIdentifier: 'approver', requestApproved: true, extra: true }],
  ])('rejects an invalid update body: %s', async (_label, body) => {
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    await expect(makeApi(fetchFn).updateAuthRequest('access-token', requestId, body as never))
      .rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects denial key material without copying it into the error', async () => {
    const secret = '4.private-wrapped-key-marker';
    const fetchFn = vi.fn(async () => jsonResponse(authResponse));
    let thrown: unknown;
    try {
      await makeApi(fetchFn).updateAuthRequest('access-token', requestId, {
        key: secret,
        deviceIdentifier: 'approver',
        requestApproved: false,
      } as never);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(TypeError);
    expect((thrown as Error).message).not.toContain(secret);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('redeems an approved request with exact official token field casing', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access',
      refresh_token: 'refresh',
      token_type: 'Bearer',
      expires_in: 3600,
      Key: USER_KEY_VECTOR_600K.akey,
    }));

    await expect(makeApi(fetchFn).deviceLogin({
      email: ' User@Example.COM ',
      accessCode,
      authRequestId: requestId.toUpperCase(),
      twoFactorProvider: 7,
      twoFactorToken: 'assertion',
      remember: true,
    })).resolves.toMatchObject({ kind: 'success' });

    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/base/identity/connect/token');
    const form = new URLSearchParams(init.body as string);
    expect(Object.fromEntries(form)).toEqual({
      client_id: 'browser',
      deviceType: '2',
      deviceIdentifier: 'device-123',
      deviceName: 'chrome',
      grant_type: 'password',
      username: 'user@example.com',
      password: accessCode,
      AuthRequest: requestId,
      scope: 'api offline_access',
      twoFactorProvider: '7',
      twoFactorToken: 'assertion',
      twoFactorRemember: '1',
    });
    expect(form.has('authRequest')).toBe(false);
    expect(form.has('auth_request')).toBe(false);
    expect(form.has('device_type')).toBe(false);
    expect(form.has('two_factor_token')).toBe(false);
  });

  it('reuses password-grant two-factor and HTTP error mappings', async () => {
    const twoFactor = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two factor required',
      TwoFactorProviders2: { '0': {}, '7': { challenge: 'challenge' } },
      TwoFactorToken: 'two-factor-token',
    }, 400));
    await expect(makeApi(twoFactor).deviceLogin({
      email: 'user@example.com',
      accessCode,
      authRequestId: requestId,
    })).resolves.toEqual({
      kind: 'twoFactor',
      providers: [0, 7],
      providerMetadata: { '0': {}, '7': { challenge: 'challenge' } },
      token: 'two-factor-token',
    });

    const rejected = vi.fn(async () => jsonResponse({ error: 'invalid_grant' }, 400));
    const error = await captureApiHttpError(makeApi(rejected).deviceLogin({
      email: 'user@example.com',
      accessCode,
      authRequestId: requestId,
    }));
    expect(error.status).toBe(400);
    expect(error.message).not.toContain(accessCode);
  });

  it.each([
    ['short code', { email: 'user@example.com', accessCode: 'short', authRequestId: requestId }],
    ['invalid UUID', { email: 'user@example.com', accessCode, authRequestId: `${requestId}/tail` }],
    ['provider without token', { email: 'user@example.com', accessCode, authRequestId: requestId, twoFactorProvider: 0 }],
    ['token without provider', { email: 'user@example.com', accessCode, authRequestId: requestId, twoFactorToken: 'token' }],
    ['remember without 2FA', { email: 'user@example.com', accessCode, authRequestId: requestId, remember: true }],
    ['invalid provider', { email: 'user@example.com', accessCode, authRequestId: requestId, twoFactorProvider: 256, twoFactorToken: 'token' }],
    ['unknown field', { email: 'user@example.com', accessCode, authRequestId: requestId, password: 'secret' }],
  ])('rejects invalid device-login input before reading device identity: %s', async (_label, input) => {
    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'access' }));
    await expect(makeApi(fetchFn).deviceLogin(input as never)).rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('rejects a malformed persisted device identity before redeeming the request', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ access_token: 'access' }));
    await expect(makeApi(fetchFn, 'device\r\ninjected').deviceLogin({
      email: 'user@example.com',
      accessCode,
      authRequestId: requestId,
    })).rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('does not admit a password-login new-device challenge into device-login results', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      ErrorModel: { Message: 'new device verification required' },
      DeviceVerified: false,
    }, 400));

    await expect(makeApi(fetchFn).deviceLogin({
      email: 'user@example.com',
      accessCode,
      authRequestId: requestId,
    })).rejects.toMatchObject({ status: 400 });
  });

  it('keeps auth requests on the shared bounded response path', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ padding: 'x'.repeat(4 * 1024 * 1024) }));
    await expect(makeApi(fetchFn).getAuthRequest('access-token', requestId))
      .rejects.toBeInstanceOf(ApiResponseTooLargeError);
  });
});

describe('ApiClient password grant', () => {
  it('POSTs connect/token as form-urlencoded with required browser parameters', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access',
      expires_in: 3600,
      refresh_token: 'refresh',
      token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      Kdf: 0,
      KdfIterations: 600000,
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    const result = await api.passwordLogin({ email: '  USER@Example.COM  ', masterPasswordHash: 'mph' });
    expect(result.kind).toBe('success');
    const call = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const init = call[1];
    expect(init.headers).toEqual(serverHeaders({ 'content-type': 'application/x-www-form-urlencoded' }));
    const form = new URLSearchParams(init.body as string);
    expect(form.get('grant_type')).toBe('password');
    expect(form.get('username')).toBe('user@example.com');
    expect(form.get('password')).toBe('mph');
    expect(form.get('scope')).toBe('api offline_access');
    expect(form.get('client_id')).toBe('browser');
    expect(form.get('deviceType')).toBe('2');
    expect(form.get('deviceIdentifier')).toBe('device-123');
    expect(form.get('deviceName')).toBe('chrome');
    expect(form.has('device_type')).toBe(false);
    expect(form.has('device_identifier')).toBe(false);
    expect(form.has('device_name')).toBe(false);
  });

  it('normalises mixed-case/whitespace email: username field is trimmed and lowercased', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-abc');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'at', expires_in: 3600, refresh_token: 'rt', token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey, Kdf: 0, KdfIterations: 600000,
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    await api.passwordLogin({ email: '  USER@EXAMPLE.COM  ', masterPasswordHash: 'mph' });
    const form = new URLSearchParams((fetchFn.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
    expect(form.get('username')).toBe('user@example.com');
  });

  it('uses only the official camelCase two-factor token fields', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'at', expires_in: 3600, refresh_token: 'rt', token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey, Kdf: 0, KdfIterations: 600000,
    }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await api.passwordLogin({
      email: 'user@example.com',
      masterPasswordHash: 'mph',
      twoFactorProvider: 7,
      twoFactorToken: 'assertion',
      remember: true,
    });

    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const form = new URLSearchParams(init.body as string);
    expect(form.get('twoFactorProvider')).toBe('7');
    expect(form.get('twoFactorToken')).toBe('assertion');
    expect(form.get('twoFactorRemember')).toBe('1');
    expect(form.has('two_factor_provider')).toBe(false);
    expect(form.has('two_factor_token')).toBe(false);
    expect(form.has('two_factor_remember')).toBe(false);
  });

  it('recognizes only the official new-device verification challenge marker', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Device verification required.',
      ErrorModel: { Message: 'new device verification required' },
      DeviceVerified: false,
    }, 400));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' }))
      .resolves.toEqual({ kind: 'newDeviceVerification' });
  });

  it.each([
    [{ ErrorModel: { Message: 'New device verification required' }, DeviceVerified: false }, 400],
    [{ ErrorModel: { Message: 'new device verification required' }, DeviceVerified: true }, 400],
    [{ ErrorModel: { Message: 'new device verification required' }, DeviceVerified: 'false' }, 400],
    [{ errorModel: { message: 'new device verification required' }, deviceVerified: false }, 400],
    [{ ErrorModel: { Message: 'new device verification required' }, DeviceVerified: false }, 401],
  ] as const)('fails closed for malformed or misplaced new-device challenge %#', async (body, status) => {
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: async () => jsonResponse(body, status),
      localStore: createMemoryStore(),
    });

    await expect(api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' }))
      .rejects.toBeInstanceOf(Error);
  });

  it('submits only the official newDeviceOtp form field', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'at', expires_in: 3600, refresh_token: 'rt', token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey, Kdf: 0, KdfIterations: 600000,
    }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await api.passwordLogin({
      email: 'user@example.com',
      masterPasswordHash: 'mph',
      newDeviceOtp: ' 123456 ',
    });

    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const form = new URLSearchParams(init.body as string);
    expect(form.get('newDeviceOtp')).toBe('123456');
    expect(form.has('new_device_otp')).toBe(false);
  });

  it('rejects malformed password grant inputs before resolving device identity', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({}));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.passwordLogin({
      email: 'user@example.com',
      masterPasswordHash: 'mph',
      newDeviceOtp: '\r\n',
    })).rejects.toBeInstanceOf(TypeError);
    await expect(api.passwordLogin({
      email: 'user@example.com',
      masterPasswordHash: 'mph',
      injected: 'secret',
    } as never)).rejects.toBeInstanceOf(TypeError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('parses 2FA-required invalid_grant into supported provider ids (object shape)', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two factor required',
      TwoFactorProviders: { '0': {}, '1': {}, '7': {} },
      TwoFactorToken: 'tf-token',
    }, 400));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result).toEqual({ kind: 'twoFactor', providers: [0, 1, 7], token: 'tf-token' });
  });

  it('parses 2FA-required response when TwoFactorProviders is an array of provider-id strings (real Vaultwarden shape)', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two factor required',
      TwoFactorProviders: ['1'],
      TwoFactorToken: 'tf-token',
    }, 400));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    // Array shape: ["1"] means provider id 1 (Email). Must NOT return [0] (Authenticator).
    expect(result).toEqual({ kind: 'twoFactor', providers: [1], token: 'tf-token' });
  });

  it('parses 2FA-required response with multiple provider ids in array shape', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two-factor authentication required.',
      TwoFactorProviders: ['0', '1'],
    }, 400));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result).toEqual({ kind: 'twoFactor', providers: [0, 1] });
  });

  it('unions legacy and provider-map ids while preserving provider 7 metadata', async () => {
    const fido2 = {
      challenge: 'AQIDBAUGBwgJCgsMDQ4PEA',
      rpId: 'vault.example.com',
      allowCredentials: [{ type: 'public-key', id: 'AQID' }],
    };
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two factor required.',
      TwoFactorProviders: ['0', '7', '999', 'not-a-provider'],
      TwoFactorProviders2: { '1': { Email: 'u***@example.com' }, '7': fido2 },
    }, 400));

    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result).toEqual({
      kind: 'twoFactor',
      providers: [0, 1, 7],
      providerMetadata: { '1': { Email: 'u***@example.com' }, '7': fido2 },
    });
  });

  it('recognizes a current response that only carries TwoFactorProviders2', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two-factor authentication required.',
      TwoFactorProviders2: { '7': { challenge: 'metadata' } },
    }, 400));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result).toMatchObject({ kind: 'twoFactor', providers: [7] });
  });
});

describe('ApiClient new-device verification OTP delivery', () => {
  it('posts only canonical account and password hash to the official anonymous endpoint', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/base/',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await api.sendNewDeviceVerificationOtp({
      email: '  USER@Example.COM ',
      masterPasswordHash: 'master-password-hash',
    });

    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/base/api/accounts/resend-new-device-otp',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'user@example.com',
          masterPasswordHash: 'master-password-hash',
        }),
      }),
    );
    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).has('authorization')).toBe(false);
  });
});

describe('ApiClient SSO token grant', () => {
  const identityUrl = 'https://vw.example.com/base/identity/';
  const redirectUri = 'https://vw.example.com/base/sso-connector.html';
  const input = {
    code: 'opaque-code',
    codeVerifier: 'A'.repeat(43),
    redirectUri,
  } as const;

  async function makeSsoApi(body: unknown, status = 200) {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse(body, status));
    return {
      api: new ApiClient({
        serverUrlProvider: async () => 'https://vw.example.com/base/',
        fetchFn,
        localStore: store,
      }),
      fetchFn,
    };
  }

  it('exchanges an authorization code only at the same-server identity endpoint', async () => {
    const onGrantStarted = vi.fn();
    const requestGuard = vi.fn();
    const { api, fetchFn } = await makeSsoApi({
      access_token: 'access',
      refresh_token: 'refresh',
      expires_in: 3_600,
      token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      Kdf: 0,
      KdfIterations: 600_000,
    });

    await expect(api.withRequestGuard(requestGuard).ssoLogin(
      identityUrl,
      { ...input, onGrantStarted },
    ))
      .resolves.toMatchObject({ kind: 'success' });
    expect(requestGuard).toHaveBeenCalledBefore(onGrantStarted);
    expect(onGrantStarted).toHaveBeenCalledBefore(fetchFn);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/base/identity/connect/token');
    expect(init).toMatchObject({ method: 'POST', cache: 'no-store', credentials: 'omit' });
    const form = new URLSearchParams(init.body as string);
    expect(Object.fromEntries(form)).toMatchObject({
      client_id: 'browser',
      grant_type: 'authorization_code',
      scope: 'api offline_access',
      code: input.code,
      code_verifier: input.codeVerifier,
      redirect_uri: redirectUri,
      deviceIdentifier: 'device-123',
    });

    await expect(api.ssoLogin('https://identity.example.com/', input))
      .rejects.toThrow(/split-origin/iu);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it('projects and cross-checks modern master-password unlock material', async () => {
    const { api } = await makeSsoApi({
      access_token: 'access',
      refresh_token: 'refresh',
      expires_in: 3_600,
      token_type: 'Bearer',
      UserDecryptionOptions: {
        HasMasterPassword: true,
        MasterPasswordUnlock: {
          Salt: 'user@example.com',
          Kdf: { KdfType: 0, Iterations: 600_000 },
          MasterKeyWrappedUserKey: USER_KEY_VECTOR_600K.akey,
        },
      },
    });

    await expect(api.ssoLogin(identityUrl, input)).resolves.toEqual({
      kind: 'success',
      data: expect.objectContaining({
        Key: USER_KEY_VECTOR_600K.akey,
        Kdf: 0,
        KdfIterations: 600_000,
        MasterKeySalt: 'user@example.com',
      }),
    });
  });

  it('awaits asynchronous grant preparation, rechecks its guard, then signals dispatch', async () => {
    const { api, fetchFn } = await makeSsoApi({
      access_token: 'access',
      refresh_token: 'refresh',
      expires_in: 3_600,
      token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      Kdf: 0,
      KdfIterations: 600_000,
    });
    let release!: () => void;
    const onGrantStarted = vi.fn(() => new Promise<void>((resolve) => { release = resolve; }));
    const onGrantDispatched = vi.fn();
    const guard = vi.fn();

    const pending = api.withRequestGuard(guard).ssoLogin(identityUrl, {
      ...input,
      onGrantStarted,
      onGrantDispatched,
    });
    await vi.waitFor(() => { expect(onGrantStarted).toHaveBeenCalledOnce(); });
    expect(fetchFn).not.toHaveBeenCalled();
    expect(onGrantDispatched).not.toHaveBeenCalled();
    release();
    await pending;

    expect(guard).toHaveBeenCalledTimes(2);
    expect(fetchFn).toHaveBeenCalledBefore(onGrantDispatched);
    expect(onGrantDispatched).toHaveBeenCalledOnce();
  });

  it('does not dispatch when the post-preparation request guard is stale', async () => {
    const { api, fetchFn } = await makeSsoApi({ error: 'unused' }, 500);
    let checks = 0;
    const onGrantDispatched = vi.fn();
    const guarded = api.withRequestGuard(() => {
      checks += 1;
      if (checks === 2) throw new AppError('session_expired', 'stale grant');
    });

    await expect(guarded.ssoLogin(identityUrl, {
      ...input,
      onGrantStarted: async () => {},
      onGrantDispatched,
    })).rejects.toThrow(/stale grant/);
    expect(fetchFn).not.toHaveBeenCalled();
    expect(onGrantDispatched).not.toHaveBeenCalled();
  });

  it('rejects JIT/passwordless and conflicting master-password unlock responses before commit', async () => {
    const passwordless = await makeSsoApi({
      access_token: 'access', refresh_token: 'refresh', expires_in: 3_600, token_type: 'Bearer',
      UserDecryptionOptions: { HasMasterPassword: false },
    });
    await expect(passwordless.api.ssoLogin(identityUrl, input))
      .rejects.toBeInstanceOf(ApiUnsupportedSsoAccountError);

    const conflicting = await makeSsoApi({
      access_token: 'access', refresh_token: 'refresh', expires_in: 3_600, token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      Kdf: 0,
      KdfIterations: 5_000,
      UserDecryptionOptions: {
        HasMasterPassword: true,
        MasterPasswordUnlock: {
          Salt: 'user@example.com',
          Kdf: { KdfType: 0, Iterations: 600_000 },
          MasterKeyWrappedUserKey: USER_KEY_VECTOR_600K.akey,
        },
      },
    });
    await expect(conflicting.api.ssoLogin(identityUrl, input)).rejects.toThrow(/conflicting KDF/u);
  });

  it('retains SSO email 2FA facts and never maps SSO NDV into a password continuation', async () => {
    const twoFactor = await makeSsoApi({
      error: 'invalid_grant',
      error_description: 'Two factor required.',
      TwoFactorProviders: ['1'],
      Email: 'user@example.com',
      SsoEmail2faSessionToken: 'sso-email-session',
    }, 400);
    await expect(twoFactor.api.ssoLogin(identityUrl, input)).resolves.toEqual({
      kind: 'twoFactor',
      providers: [1],
      email: 'user@example.com',
      ssoEmail2FaSessionToken: 'sso-email-session',
    });

    const ndv = await makeSsoApi({
      ErrorModel: { Message: 'new device verification required' },
      DeviceVerified: false,
    }, 400);
    await expect(ndv.api.ssoLogin(identityUrl, input)).rejects.toMatchObject({ status: 400 });
  });

  it('requires a positive bounded token from the fixed Vaultwarden SSO probe', async () => {
    const success = await makeSsoApi({ token: 'probe-token' });
    await expect(success.api.probeVaultwardenSso(identityUrl)).resolves.toBeUndefined();
    expect((success.fetchFn.mock.calls as unknown as Array<[string, RequestInit]>)[0]?.[0]).toBe(
      'https://vw.example.com/base/identity/sso/prevalidate',
    );

    const invalid = await makeSsoApi({ token: '' });
    await expect(invalid.api.probeVaultwardenSso(identityUrl)).rejects.toThrow();
  });
});

describe('ApiClient refresh and sync', () => {
  it('refreshes using refresh_token grant', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'new-access',
      expires_in: 3600,
      refresh_token: 'new-refresh',
      token_type: 'Bearer',
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    await expect(api.refresh('old-refresh')).resolves.toMatchObject({ access_token: 'new-access' });
    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const form = new URLSearchParams(init.body as string);
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('old-refresh');
    expect(form.get('client_id')).toBe('browser');
    expect(form.get('deviceType')).toBe('2');
    expect(form.get('deviceName')).toBe('chrome');
    expect(form.get('deviceIdentifier')).toBe('device-123');
    expect(form.has('device_type')).toBe(false);
    expect(form.has('device_name')).toBe(false);
    expect(form.has('device_identifier')).toBe(false);
  });

  it('marks a refresh grant only after its request guard and immediately before fetch', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600, token_type: 'Bearer',
    }));
    const guard = vi.fn();
    const onGrantStarted = vi.fn();
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store,
    }).withRequestGuard(guard);

    await api.refresh('old-refresh', { onGrantStarted });

    expect(guard).toHaveBeenCalledBefore(onGrantStarted);
    expect(onGrantStarted).toHaveBeenCalledBefore(fetchFn);

    const blockedFetch = vi.fn();
    const blockedStart = vi.fn();
    const blocked = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: blockedFetch as never,
      localStore: store,
    }).withRequestGuard(() => { throw new Error('stale refresh lease'); });
    await expect(blocked.refresh('old-refresh', { onGrantStarted: blockedStart }))
      .rejects.toThrow('stale refresh lease');
    expect(blockedStart).not.toHaveBeenCalled();
    expect(blockedFetch).not.toHaveBeenCalled();
  });

  it('syncs with Authorization Bearer token', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await expect(api.sync('access')).resolves.toEqual({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/sync', expect.objectContaining({
      method: 'GET',
      headers: serverHeaders({ authorization: 'Bearer access' }),
    }));
  });
});

describe('ApiClient client event collection', () => {
  const event = Object.freeze({
    type: ClientEventType.Cipher_ClientViewed,
    date: '2026-09-01T08:09:10.123Z',
    cipherId: '11111111-1111-4111-8111-111111111111',
    organizationId: '22222222-2222-4222-8222-222222222222',
  });

  it('POSTs one canonical batch with bearer and no-store controls after the request guard', async () => {
    const order: string[] = [];
    const fetchFn = vi.fn(async () => {
      order.push('fetch');
      return new Response(null, { status: 200 });
    });
    const guard = vi.fn(() => { order.push('guard'); });
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/base',
      fetchFn,
      localStore: createMemoryStore(),
    }).withRequestGuard(guard);

    await expect(api.collectClientEvents('access-secret', [event])).resolves.toEqual({ ok: true });

    expect(order).toEqual(['guard', 'fetch']);
    expect(fetchFn).toHaveBeenCalledOnce();
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/base/api/events/collect');
    expect(init).toMatchObject({
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      body: JSON.stringify([event]),
    });
    const headers = new Headers(init.headers);
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('authorization')).toBe('Bearer access-secret');
    expect(headers.get('cache-control')).toBe('no-store');
    expect(headers.get('pragma')).toBe('no-cache');
    expect(headers.get('Bitwarden-Client-Version')).toBe(BITWARDEN_CLIENT_VERSION);
    expect(headers.get('Bitwarden-Client-Name')).toBe('browser');
  });

  it('does not dispatch when its request guard is stale', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    }).withRequestGuard(() => { throw new Error('event scope changed'); });

    await expect(api.collectClientEvents('access', [event])).rejects.toThrow('event scope changed');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('returns a bounded Retry-After value for a retryable HTTP response', async () => {
    const fetchFn = vi.fn(async () => new Response('temporarily unavailable', {
      status: 429,
      headers: { 'Retry-After': '120' },
    }));

    await expect(new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    }).collectClientEvents('access', [event])).resolves.toEqual({
      ok: false,
      status: 429,
      retryAfter: '120',
    });
  });

  it('omits an overlong Retry-After header', async () => {
    const fetchFn = vi.fn(async () => new Response(null, {
      status: 503,
      headers: { 'Retry-After': '1'.repeat(129) },
    }));

    await expect(new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    }).collectClientEvents('access', [event])).resolves.toEqual({
      ok: false,
      status: 503,
    });
  });

  it('preserves the ApiHttpError contract for 401 without retrying', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ error: 'expired' }, 401));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.collectClientEvents('expired-access', [event])).rejects.toMatchObject({
      name: 'ApiHttpError',
      status: 401,
      body: { error: 'expired' },
    });
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('rejects a non-empty success body', async () => {
    const fetchFn = vi.fn(async () => new Response('{}', { status: 200 }));

    await expect(new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    }).collectClientEvents('access', [event])).rejects.toThrow(/must be empty/i);
  });

  it('bounds an oversized error body', async () => {
    const fetchFn = vi.fn(async () => new Response(
      'x'.repeat(CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES + 1),
      { status: 503 },
    ));

    await expect(new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    }).collectClientEvents('access', [event])).rejects.toEqual(
      new ApiResponseTooLargeError(
        CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES,
        CLIENT_EVENT_COLLECT_RESPONSE_MAX_BYTES + 1,
      ),
    );
  });

  it('rejects an oversized event batch before resolving or fetching', async () => {
    const provider = vi.fn(async () => 'https://vw.example.com');
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const events = Array.from({ length: 51 }, () => ({
      type: ClientEventType.User_ClientExportedVault,
      date: '2026-09-01T08:09:10.123Z',
    } as const));
    const api = new ApiClient({
      serverUrlProvider: provider,
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.collectClientEvents('access', events)).rejects.toThrow(/1-50 events/i);
    expect(provider).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe('ApiClient sendEmailLogin', () => {
  it('POSTs /api/two-factor/send-email-login with trimmed/lowercased email and token body key', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({}));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });
    await api.sendEmailLogin({ email: '  USER@EXAMPLE.COM  ', twoFactorToken: 'mytoken' });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/two-factor/send-email-login');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ email: 'user@example.com', token: 'mytoken' });
  });
});

describe('ApiClient folders', () => {
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com/',
    fetchFn,
    localStore: createMemoryStore(),
  });

  it('POSTs /api/folders with the encrypted name and Bearer token', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'f1', name: '2.enc', revisionDate: 'd', object: 'folder' }));
    const res = await makeApi(fetchFn).createFolder('token', '2.enc');
    expect(res).toMatchObject({ id: 'f1', name: '2.enc' });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/folders', expect.objectContaining({
      method: 'POST',
      headers: serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer token' }),
      body: JSON.stringify({ name: '2.enc' }),
    }));
  });

  it('PUTs /api/folders/<id> to rename', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'f1', name: '2.new' }));
    await makeApi(fetchFn).updateFolder('token', 'f1', '2.new');
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/folders/f1', expect.objectContaining({
      method: 'PUT',
      headers: serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer token' }),
      body: JSON.stringify({ name: '2.new' }),
    }));
  });

  it('DELETEs /api/folders/<id> and tolerates an empty response body', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    await expect(makeApi(fetchFn).deleteFolder('token', 'f1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/folders/f1', expect.objectContaining({
      method: 'DELETE',
      headers: serverHeaders({ authorization: 'Bearer token' }),
    }));
  });

  it('throws ApiHttpError on a failed folder request', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ message: 'bad' }, 400));
    const err = await captureApiHttpError(makeApi(fetchFn).createFolder('token', '2.enc'));
    expect(err.status).toBe(400);
  });
});

describe('ApiClient ciphers', () => {
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com/',
    fetchFn,
    localStore: createMemoryStore(),
  });
  const request = { type: 1 as const, name: '2.enc', favorite: false, folderId: null, login: { username: '2.u' } };

  it('POSTs /api/ciphers with the encrypted request and Bearer token', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', type: 1, name: '2.enc' }));
    const res = await makeApi(fetchFn).createCipher('token', request);
    expect(res).toMatchObject({ id: 'c1' });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers', expect.objectContaining({
      method: 'POST',
      headers: serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer token' }),
      body: JSON.stringify(request),
    }));
  });

  it('PUTs /api/ciphers/<id> to update', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', type: 1, name: '2.enc' }));
    await makeApi(fetchFn).updateCipher('token', 'c1', request);
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1', expect.objectContaining({
      method: 'PUT',
      headers: serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer token' }),
      body: JSON.stringify(request),
    }));
  });

  it('PUTs exactly folderId and favorite to /api/ciphers/<id>/partial', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      id: 'c1', type: 1, name: '2.enc', folderId: 'folder-1', favorite: true,
    }));
    const result = await makeApi(fetchFn).updateCipherPartial('token', 'c1', {
      folderId: 'folder-1',
      favorite: true,
    });

    expect(result).toMatchObject({ id: 'c1', folderId: 'folder-1', favorite: true });
    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/api/ciphers/c1/partial',
      expect.objectContaining({
        method: 'PUT',
        headers: serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer token' }),
        body: JSON.stringify({ folderId: 'folder-1', favorite: true }),
      }),
    );
  });

  it('rejects malformed partial requests before network I/O', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', type: 1, folderId: null, favorite: false }));
    const api = makeApi(fetchFn);
    const accessor = { folderId: null } as Record<string, unknown>;
    Object.defineProperty(accessor, 'favorite', { enumerable: true, get: () => false });
    const symbolField = { folderId: null, favorite: false } as Record<PropertyKey, unknown>;
    symbolField[Symbol('secret')] = 'unexpected';
    const nonEnumerable = { folderId: null } as Record<string, unknown>;
    Object.defineProperty(nonEnumerable, 'favorite', { enumerable: false, value: false });
    const requests = [
      { folderId: null },
      { folderId: null, favorite: false, name: 'must-not-send' },
      { folderId: undefined, favorite: false },
      { folderId: ' folder-1', favorite: false },
      { folderId: null, favorite: 0 },
      accessor,
      symbolField,
      nonEnumerable,
      Object.assign(Object.create({}), { folderId: null, favorite: false }),
    ];

    for (const partial of requests) {
      await expect(api.updateCipherPartial('token', 'c1', partial as never)).rejects.toThrow();
    }
    await expect(api.updateCipherPartial('token', ' c1', {
      folderId: null,
      favorite: false,
    })).rejects.toThrow();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    ['id', { id: 'other', type: 1, folderId: 'folder-1', favorite: true }],
    ['folder', { id: 'c1', type: 1, folderId: 'other-folder', favorite: true }],
    ['favorite', { id: 'c1', type: 1, folderId: 'folder-1', favorite: false }],
    ['missing favorite', { id: 'c1', type: 1, folderId: 'folder-1' }],
    ['type', { id: 'c1', type: 0, folderId: 'folder-1', favorite: true }],
  ])('rejects a partial-update receipt with mismatched %s metadata', async (_label, body) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).updateCipherPartial('token', 'c1', {
      folderId: 'folder-1',
      favorite: true,
    })).rejects.toThrow();
  });

  it('DELETEs /api/ciphers/<id> and tolerates an empty body', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    await expect(makeApi(fetchFn).deleteCipher('token', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1', expect.objectContaining({
      method: 'DELETE',
      headers: serverHeaders({ authorization: 'Bearer token' }),
    }));
  });

  it('PUTs /api/ciphers/<id>/delete to soft-delete (move to trash) with an empty body', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    await expect(makeApi(fetchFn).softDeleteCipher('token', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1/delete', expect.objectContaining({
      method: 'PUT',
      headers: serverHeaders({ authorization: 'Bearer token' }),
    }));
  });

  it('PUTs /api/ciphers/<id>/restore to restore from trash', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', type: 1, name: '2.enc', deletedDate: null }));
    await expect(makeApi(fetchFn).restoreCipher('token', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1/restore', expect.objectContaining({
      method: 'PUT',
      headers: serverHeaders({ authorization: 'Bearer token' }),
    }));
  });
});

describe('ApiClient register', () => {
  it.each([
    ['plain token', new Response('registration-token', { status: 200 }), 'registration-token'],
    ['JSON token', jsonResponse('registration-token'), 'registration-token'],
  ])('starts registration and parses an inline %s', async (_label, response, token) => {
    const fetchFn = vi.fn(async () => response);
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.startRegistration({ email: ' NEW@EXAMPLE.COM ', name: ' Ada ' }))
      .resolves.toEqual({ kind: 'inline', emailVerificationToken: token });
    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/identity/accounts/register/send-verification-email',
      expect.objectContaining({
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: serverHeaders({
          'cache-control': 'no-store',
          pragma: 'no-cache',
          'content-type': 'application/json',
        }),
        body: JSON.stringify({
          email: 'new@example.com',
          name: 'Ada',
          receiveMarketingEmails: false,
        }),
      }),
    );
  });

  it('distinguishes required email verification from a legacy server', async () => {
    const emailRequired = vi.fn(async () => new Response(null, { status: 204 }));
    await expect(new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: emailRequired,
      localStore: createMemoryStore(),
    }).startRegistration({ email: 'new@example.com' }))
      .resolves.toEqual({ kind: 'email_required' });

    const legacy = vi.fn(async () => jsonResponse({ message: 'missing route' }, 404));
    await expect(new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: legacy,
      localStore: createMemoryStore(),
    }).startRegistration({ email: 'new@example.com' }))
      .resolves.toEqual({ kind: 'legacy' });
    expect(legacy).toHaveBeenCalledOnce();
  });

  it.each([
    ['empty token', new Response('', { status: 200 })],
    ['whitespace token', new Response('token with spaces', { status: 200 })],
    ['unexpected success', new Response(null, { status: 202 })],
  ])('rejects an invalid registration-start response: %s', async (_label, response) => {
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: vi.fn(async () => response),
      localStore: createMemoryStore(),
    });
    await expect(api.startRegistration({ email: 'new@example.com' })).rejects.toBeInstanceOf(Error);
  });

  it('POSTs only the modern registration model to the finish endpoint', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com/', fetchFn, localStore: createMemoryStore() });
    const data = {
      email: 'new@example.com', masterPasswordHash: 'hash', key: '2.k',
      masterPasswordHint: '',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' }, kdf: 0 as const, kdfIterations: 600000,
    };
    await expect(api.register({ ...data, emailVerificationToken: 'registration-token' }))
      .resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/identity/accounts/register/finish', expect.objectContaining({
      method: 'POST',
      headers: serverHeaders({ 'content-type': 'application/json' }),
    }));
    const [, request] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(request.body as string);
    expect(body).toMatchObject({
      email: data.email,
      emailVerificationToken: 'registration-token',
      masterPasswordHint: '',
      userAsymmetricKeys: data.keys,
      masterPasswordAuthentication: {
        salt: data.email,
        kdf: { kdfType: 0, iterations: 600_000, memory: null, parallelism: null },
        masterPasswordAuthenticationHash: data.masterPasswordHash,
      },
      masterPasswordUnlock: {
        salt: data.email,
        kdf: { kdfType: 0, iterations: 600_000, memory: null, parallelism: null },
        masterKeyWrappedUserKey: data.key,
      },
    });
    expect(body).not.toHaveProperty('keys');
    expect(body).not.toHaveProperty('key');
    expect(body).not.toHaveProperty('masterPasswordHash');
    expect(body).not.toHaveProperty('kdf');
  });

  it('falls back to the legacy registration route only after an explicit 404', async () => {
    const fetchFn = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ message: 'missing route' }, 404))
      .mockResolvedValueOnce(textResponse('', 200));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com/', fetchFn, localStore: createMemoryStore() });
    await api.register({
      email: 'NEW@EXAMPLE.COM',
      masterPasswordHash: 'hash',
      masterPasswordHint: '',
      key: '2.k',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      kdf: 1,
      kdfIterations: 2,
      kdfMemory: 16,
      kdfParallelism: 1,
    });
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(fetchFn.mock.calls.map(([url]) => url)).toEqual([
      'https://vw.example.com/identity/accounts/register/finish',
      'https://vw.example.com/identity/accounts/register',
    ]);
    const modern = JSON.parse((fetchFn.mock.calls[0]![1] as RequestInit).body as string);
    const legacy = JSON.parse((fetchFn.mock.calls[1]![1] as RequestInit).body as string);
    expect(modern).not.toHaveProperty('keys');
    expect(legacy).toMatchObject({
      email: 'new@example.com',
      masterPasswordHash: 'hash',
      key: '2.k',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      kdf: 1,
      kdfIterations: 2,
      kdfMemory: 16,
      kdfParallelism: 1,
      masterPasswordHint: '',
    });
    expect(legacy).not.toHaveProperty('userAsymmetricKeys');
  });

  it('throws ApiHttpError when registration is rejected', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ message: 'taken' }, 400));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com/', fetchFn, localStore: createMemoryStore() });
    const err = await captureApiHttpError(api.register({
      email: 'x@example.com', masterPasswordHash: 'h', masterPasswordHint: '', key: '2.k', keys: { publicKey: 'p', encryptedPrivateKey: '2.e' }, kdf: 0, kdfIterations: 600000,
    }));
    expect(err.status).toBe(400);
  });
});

describe('ApiClient password change', () => {
  it.each(['', 'remember the long phrase'])(
    'always serializes the explicit master-password hint %#',
    async (masterPasswordHint) => {
      const fetchFn = vi.fn(async () => textResponse('', 200));
      const api = new ApiClient({
        serverUrlProvider: async () => 'https://vw.example.com/',
        fetchFn,
        localStore: createMemoryStore(),
      });

      await api.changePassword('access', {
        masterPasswordHash: 'old-hash',
        newMasterPasswordHash: 'new-hash',
        key: '2.protected',
        masterPasswordHint,
      });

      const [, request] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
      const body = JSON.parse(request.body as string);
      expect(body).toEqual({
        masterPasswordHash: 'old-hash',
        newMasterPasswordHash: 'new-hash',
        key: '2.protected',
        masterPasswordHint,
      });
    },
  );

  it('rejects a missing or oversized hint before dispatch', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const base = {
      masterPasswordHash: 'old-hash',
      newMasterPasswordHash: 'new-hash',
      key: '2.protected',
    };

    await expect(api.changePassword('access', base as never)).rejects.toThrow(/hint/i);
    await expect(api.changePassword('access', {
      ...base,
      masterPasswordHint: 'x'.repeat(51),
    })).rejects.toThrow(/50/);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe('ApiClient Sends - file uploads', () => {
  it('createSendFile POSTs the send to /api/sends/file/v2 and returns the upload target', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ url: '/sends/s1/file/f1', sendResponse: { id: 's1' } }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    const res = await api.createSendFile('tok', { type: 1, name: '2.enc', key: '2.k', deletionDate: 'd' } as never);
    const [calledUrl, callInit] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(calledUrl)).toContain('/api/sends/file/v2');
    expect(callInit.method).toBe('POST');
    expect(callInit.headers).toMatchObject({ 'content-type': 'application/json' });
    expect(res.url).toBe('/sends/s1/file/f1');
  });

  it('uploadSendFileData POSTs multipart data to /api{url}', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await api.uploadSendFileData('tok', '/sends/s1/file/f1', new Uint8Array([1, 2, 3]), '2.encname');
    const [calledUrl, callInit] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(calledUrl)).toContain('/api/sends/s1/file/f1');
    expect(callInit.method).toBe('POST');
    expect(callInit.body).toBeInstanceOf(FormData);
  });

  it('updateSend PUTs the send to /api/sends/{id}', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 's1', type: 0 }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await api.updateSend('tok', 's1', { type: 0, name: '2.n', key: '2.k', deletionDate: 'd' } as never);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(url)).toContain('/api/sends/s1');
    expect(init.method).toBe('PUT');
    expect(init.headers).toMatchObject({ 'content-type': 'application/json' });
  });

  it('removeSendPassword PUTs to /api/sends/{id}/remove-password', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 's1' }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await api.removeSendPassword('tok', 's1');
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(url)).toContain('/api/sends/s1/remove-password');
    expect(init.method).toBe('PUT');
  });
});

describe('ApiClient attachment v2 uploads', () => {
  const key = USER_KEY_VECTOR_600K.akey;
  const fileName = USER_KEY_VECTOR_600K.akey;
  const data = (() => {
    const value = new Uint8Array(65);
    value[0] = 2;
    return value;
  })();
  const request = {
    key,
    fileName,
    fileSize: data.byteLength,
    adminRequest: false as const,
    lastKnownRevisionDate: '2026-08-31T00:00:00.000Z',
  };
  const slotBody = (overrides: Record<string, unknown> = {}) => ({
    object: 'attachment-fileUpload',
    attachmentId: 'attachment-1',
    fileUploadType: 0,
    url: '/ciphers/cipher-1/attachment/attachment-1',
    cipherResponse: {
      id: 'cipher-1',
      type: 1,
      attachments: [{
        id: 'attachment-1',
        key,
        fileName,
        size: String(data.byteLength),
      }],
    },
    ...overrides,
  });
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com',
    fetchFn,
    localStore: createMemoryStore(),
  });

  it('allocates a strict v2 slot with encrypted metadata and a revision fence', async () => {
    const fetchFn = vi.fn(async () => jsonResponse(slotBody()));

    await expect(makeApi(fetchFn).createAttachmentUploadSlot('secret-token', 'cipher-1', request))
      .resolves.toMatchObject({
        attachmentId: 'attachment-1',
        fileUploadType: 0,
        cipherResponse: { id: 'cipher-1' },
      });

    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/api/ciphers/cipher-1/attachment/v2',
      expect.objectContaining({
        method: 'POST',
        cache: 'no-store',
        credentials: 'omit',
        headers: serverHeaders({
          'cache-control': 'no-store',
          pragma: 'no-cache',
          'content-type': 'application/json',
          authorization: 'Bearer secret-token',
        }),
        body: JSON.stringify(request),
      }),
    );
  });

  it.each([
    ['unknown outer field', slotBody({ future: true })],
    ['duplicate aliases', slotBody({ AttachmentId: 'attachment-1' })],
    ['unknown upload type', slotBody({ fileUploadType: 2 })],
    ['wrong cipher', slotBody({ cipherResponse: { id: 'cipher-2', type: 1, attachments: [] } })],
    ['missing attachment metadata', slotBody({ cipherResponse: { id: 'cipher-1', type: 1, attachments: [] } })],
    ['wrong attachment key', slotBody({
      cipherResponse: {
        id: 'cipher-1', type: 1,
        attachments: [{ id: 'attachment-1', key: fileName, fileName, size: '64' }],
      },
    })],
    ['Azure without URL', slotBody({ fileUploadType: 1, url: null })],
    ['unsafe Azure URL', slotBody({ fileUploadType: 1, url: 'http://blob.example/upload?sv=2024-01-01' })],
  ] as const)('rejects a malformed committed slot receipt: %s', async (_label, body) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).createAttachmentUploadSlot('token', 'cipher-1', request))
      .rejects.toBeInstanceOf(Error);
  });

  it('uploads Direct data as authenticated multipart without repeating the key field', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const api = makeApi(fetchFn);
    const receipt = {
      attachmentId: 'attachment-1',
      fileUploadType: 0 as const,
      cipherResponse: slotBody().cipherResponse,
    };

    await api.uploadAttachmentSlotData('secret-token', 'cipher-1', receipt, fileName, data);

    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/ciphers/cipher-1/attachment/attachment-1');
    expect(init).toMatchObject({ method: 'POST', cache: 'no-store', credentials: 'omit' });
    expect(init.headers).toEqual(serverHeaders({
      'cache-control': 'no-store',
      pragma: 'no-cache',
      authorization: 'Bearer secret-token',
    }));
    const form = init.body as FormData;
    expect(form.get('data')).toBeInstanceOf(Blob);
    expect(form.has('key')).toBe(false);
  });

  it('PUTs Azure data without account credentials or Bitwarden headers', async () => {
    const uploadUrl = 'https://blob.example/container/object?sv=2024-11-04&sig=secret';
    const fetchFn = vi.fn(async () => new Response(null, { status: 201 }));
    const api = makeApi(fetchFn);
    const receipt = {
      attachmentId: 'attachment-1',
      fileUploadType: 1 as const,
      url: uploadUrl,
      cipherResponse: slotBody().cipherResponse,
    };

    await api.uploadAttachmentSlotData('never-leak', 'cipher-1', receipt, fileName, data);

    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(uploadUrl);
    expect(init).toMatchObject({ method: 'PUT', cache: 'no-store', credentials: 'omit', body: data });
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBeNull();
    expect(headers.get('Bitwarden-Client-Version')).toBeNull();
    expect(headers.get('x-ms-blob-type')).toBe('BlockBlob');
    expect(headers.get('x-ms-version')).toBe('2024-11-04');
    expect(headers.get('content-length')).toBe(String(data.byteLength));
  });

  it('renews an expired Azure URL before uploading and binds optional receipt identifiers', async () => {
    const expired = 'https://blob.example/old?sv=2024-11-04&se=2020-01-01T00%3A00%3A00Z&sig=old';
    const fresh = 'https://blob.example/new?sv=2024-11-04&se=2099-01-01T00%3A00%3A00Z&sig=new';
    const fetchFn = vi.fn(async (url: string) => url.includes('/renew')
      ? jsonResponse({
          object: 'attachment-fileUpload',
          attachmentId: 'attachment-1',
          fileUploadType: 1,
          cipherResponse: { id: 'cipher-1', type: 1 },
          url: fresh,
        })
      : new Response(null, { status: 201 }));
    const api = makeApi(fetchFn as never);

    await api.uploadAttachmentSlotData('token', 'cipher-1', {
      attachmentId: 'attachment-1',
      fileUploadType: 1,
      url: expired,
      cipherResponse: slotBody().cipherResponse,
    }, fileName, data);

    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(fetchFn.mock.calls[0]![0]).toBe(
      'https://vw.example.com/api/ciphers/cipher-1/attachment/attachment-1/renew',
    );
    expect(fetchFn.mock.calls[1]![0]).toBe(fresh);
  });

  it.each([
    'http://blob.example/upload?sv=2024-11-04',
    'https://user:password@blob.example/upload?sv=2024-11-04',
    'https://blob.example/upload?sv=invalid',
    'https://blob.example/upload?sv=2024-11-04#fragment',
  ])('rejects an unsafe Azure upload URL before PUT: %s', async (url) => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 201 }));
    await expect(makeApi(fetchFn).uploadAttachmentSlotData('token', 'cipher-1', {
      attachmentId: 'attachment-1',
      fileUploadType: 1,
      url,
      cipherResponse: slotBody().cipherResponse,
    }, fileName, data)).rejects.toBeInstanceOf(Error);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('keeps Vaultwarden device-only and Bitwarden session-token SSO email requests distinct', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: store,
    });

    await api.sendSsoEmailLogin({ mode: 'vaultwarden-device' });
    await api.sendSsoEmailLogin({
      mode: 'bitwarden-session',
      email: 'USER@example.com',
      ssoEmail2FaSessionToken: 'session-token',
    });
    const calls = fetchFn.mock.calls as unknown as Array<[string, RequestInit]>;
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({
      deviceIdentifier: 'device-123',
    });
    expect(JSON.parse(calls[1]![1].body as string)).toEqual({
      email: 'user@example.com',
      ssoEmail2FaSessionToken: 'session-token',
      deviceIdentifier: 'device-123',
    });
  });
});

describe('ApiClient collection endpoints', () => {
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com',
    fetchFn,
    localStore: createMemoryStore(),
  });

  it('POSTs a create-collection with an explicit initial manager', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', organizationId: 'o1' }));
    const api = makeApi(fetchFn);
    const users = [{ id: 'membership-1', readOnly: false, hidePasswords: false, manage: true }];
    await api.createCollection('tok', 'o1', '2.enc==', { groups: [], users });
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/organizations/o1/collections');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual(serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer tok' }));
    expect(JSON.parse(init.body as string)).toEqual({ name: '2.enc==', groups: [], users, externalId: null });
  });

  it('renames by resending preserved groups/users', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1' }));
    const api = makeApi(fetchFn);
    await api.updateCollection('tok', 'o1', 'c1', '2.new==', {
      groups: [{ id: 'g1' }],
      users: [{ id: 'u1' }],
      externalId: 'directory-collection-1',
    });
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/organizations/o1/collections/c1');
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual(serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer tok' }));
    expect(JSON.parse(init.body as string)).toEqual({
      name: '2.new==',
      groups: [{ id: 'g1' }],
      users: [{ id: 'u1' }],
      externalId: 'directory-collection-1',
    });
  });

  it('PUTs cipher collectionIds', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = makeApi(fetchFn);
    await api.updateCipherCollections('tok', 'ci1', ['x', 'y']);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/ciphers/ci1/collections');
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual(serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer tok' }));
    expect(JSON.parse(init.body as string)).toEqual({ collectionIds: ['x', 'y'] });
  });

  it('GETs a collection with details endpoint', async () => {
    const details = {
      id: 'c1',
      organizationId: 'o1',
      groups: [],
      users: [],
      externalId: 'directory-collection-1',
    };
    const fetchFn = vi.fn(async () => jsonResponse(details));
    const api = makeApi(fetchFn);
    const res = await api.getCollectionDetails('tok', 'o1', 'c1');
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/organizations/o1/collections/c1/details', expect.objectContaining({
      method: 'GET',
      headers: serverHeaders({ authorization: 'Bearer tok' }),
    }));
    expect(res).toEqual(details);
  });

  it('DELETEs a collection', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    const api = makeApi(fetchFn);
    await expect(api.deleteCollection('tok', 'o1', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/organizations/o1/collections/c1', expect.objectContaining({
      method: 'DELETE',
      headers: serverHeaders({ authorization: 'Bearer tok' }),
    }));
  });
});

describe('ApiClient organization create and archive endpoints', () => {
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com',
    fetchFn,
    localStore: createMemoryStore(),
  });

  it('sends a name-only Bitwarden update with null association fields', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      id: 'c1', organizationId: 'o1', name: '2.new==', externalId: 'directory-collection-1',
    }));
    const api = makeApi(fetchFn);
    await api.updateCollectionName('tok', 'o1', 'c1', '2.new==', 'directory-collection-1');
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/organizations/o1/collections/c1');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body as string)).toEqual({
      name: '2.new==',
      groups: null,
      users: null,
      externalId: 'directory-collection-1',
    });
  });
  const cipher = {
    type: 1 as const,
    name: '2.encrypted-name',
    organizationId: 'org-1',
    login: {},
  };
  const bulkCipher = {
    ...cipher,
    id: 'cipher-1',
    encryptedFor: 'user-1',
  };
  const bulkRequest = {
    ciphers: [bulkCipher],
    collectionIds: ['collection-1'],
    encryptedFor: 'user-1',
  };

  it('POSTs an atomic organization create wrapper and validates its target', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      id: 'cipher-1',
      type: 1,
      name: '2.encrypted-name',
      organizationId: 'org-1',
    }));
    const response = await makeApi(fetchFn).createOrganizationCipher(
      'tok',
      cipher,
      ['collection-1'],
    );
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];

    expect(url).toBe('https://vw.example.com/api/ciphers/create');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual(serverHeaders({
      'content-type': 'application/json',
      authorization: 'Bearer tok',
    }));
    expect(JSON.parse(init.body as string)).toEqual({
      cipher,
      collectionIds: ['collection-1'],
    });
    expect(response).toMatchObject({ id: 'cipher-1', organizationId: 'org-1', type: 1 });
  });

  it.each([
    [{ id: 'cipher-1', type: 1, organizationId: 'other-org' }, /request target/],
    [{ id: 'cipher-1', type: 2, organizationId: 'org-1' }, /request target/],
    [{ id: '', type: 1, organizationId: 'org-1' }, /invalid length/],
    [{ id: 'cipher-1', type: 0, organizationId: 'org-1' }, /positive safe integer/],
  ] as const)('rejects a malformed or mismatched organization create response', async (body, error) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).createOrganizationCipher('tok', cipher, ['collection-1']))
      .rejects.toThrow(error);
  });

  it('rejects an invalid organization target before issuing a request', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({}));
    const api = makeApi(fetchFn);

    await expect(api.createOrganizationCipher('tok', { ...cipher, organizationId: null }, ['c1']))
      .rejects.toThrow('organizationId');
    await expect(api.createOrganizationCipher('tok', cipher, []))
      .rejects.toThrow('collectionIds');
    await expect(api.createOrganizationCipher('tok', cipher, ['c1', 'c1']))
      .rejects.toThrow('duplicates');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('sends attachments2 when sharing and accepts a receipt without collectionIds', async () => {
    const request = {
      ...cipher,
      attachments2: { attachment1: { key: '2.attachment', fileName: '2.filename' } },
    };
    const fetchFn = vi.fn(async () => jsonResponse({
      id: 'cipher-1', type: 1, name: request.name, organizationId: 'org-1',
    }));
    const response = await makeApi(fetchFn).shareCipher(
      'tok', 'cipher-1', { cipher: request, collectionIds: ['collection-1'] },
    );
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(String(url)).toContain('/api/ciphers/cipher-1/share');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body as string)).toEqual({
      cipher: request, collectionIds: ['collection-1'],
    });
    expect(response).not.toHaveProperty('collectionIds');
  });

  it('rejects malformed share targets and a mismatched receipt', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      id: 'other-cipher', type: 1, name: cipher.name, organizationId: 'org-1',
    }));
    const api = makeApi(fetchFn);
    await expect(api.shareCipher(
      'tok', 'cipher-1', { cipher, collectionIds: ['collection-1'] },
    )).rejects.toThrow(/request target/);
    await expect(api.shareCipher(
      'tok', '', { cipher, collectionIds: ['collection-1'] },
    )).rejects.toThrow(/cipherId/);
    await expect(api.shareCipher(
      'tok', 'cipher-1', { cipher, collectionIds: [] },
    )).rejects.toThrow(/collectionIds/);
  });

  it('PUTs the official bulk-share envelope and validates its list receipt', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      data: [{ id: 'cipher-1', type: 1, organizationId: 'org-1' }],
      object: 'list',
      continuationToken: null,
    }));
    const response = await makeApi(fetchFn).shareCiphers('tok', bulkRequest);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];

    expect(url).toBe('https://vw.example.com/api/ciphers/share');
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual(serverHeaders({
      'content-type': 'application/json',
      authorization: 'Bearer tok',
    }));
    expect(JSON.parse(init.body as string)).toEqual(bulkRequest);
    expect(response).toEqual([{ id: 'cipher-1', type: 1, organizationId: 'org-1' }]);
    expect(Object.isFrozen(response)).toBe(true);
  });

  it.each([200, 204])('accepts Vaultwarden bulk-share success with an empty %i response', async (status) => {
    const fetchFn = vi.fn(async () => new Response(null, { status }));
    await expect(makeApi(fetchFn).shareCiphers('tok', bulkRequest)).resolves.toBeUndefined();
  });

  it('accepts an official partial-visibility receipt and defers completeness to sync', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ data: [], object: 'list' }));

    await expect(makeApi(fetchFn).shareCiphers('tok', bulkRequest)).resolves.toEqual([]);
  });

  it.each([
    [{ object: 'list', continuationToken: null }, /request subset/],
    [{ data: [{ id: 'other', type: 1, organizationId: 'org-1' }] }, /unexpected cipher id/],
    [{ data: [{ id: 'cipher-1', type: 2, organizationId: 'org-1' }] }, /request target/],
    [{ data: [{ id: 'cipher-1', type: 1, organizationId: 'other-org' }] }, /request target/],
    [{ data: [{ id: 'cipher-1', type: 1, organizationId: 'org-1' }], continuationToken: 'next' }, /paginated/],
    [null, /JSON object/],
  ] as const)('rejects a malformed official bulk-share receipt %#', async (body, error) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).shareCiphers('tok', bulkRequest)).rejects.toThrow(error);
  });

  it('rejects unsafe bulk-share envelopes before resolving or issuing a request', async () => {
    const serverUrlProvider = vi.fn(async () => 'https://vw.example.com');
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));
    const api = new ApiClient({ serverUrlProvider, fetchFn, localStore: createMemoryStore() });
    const rejectBeforeRequest = async (request: unknown, error: string | RegExp): Promise<void> => {
      await expect(api.shareCiphers('tok', request as never)).rejects.toThrow(error);
      expect(fetchFn).not.toHaveBeenCalled();
      expect(serverUrlProvider).not.toHaveBeenCalled();
    };

    await rejectBeforeRequest({ ...bulkRequest, ciphers: [] }, /between 1 and 50000/);
    await rejectBeforeRequest({ ...bulkRequest, ciphers: [bulkCipher, bulkCipher] }, /duplicates/);
    await rejectBeforeRequest({
      ...bulkRequest,
      ciphers: [bulkCipher, { ...bulkCipher, id: 'cipher-2', organizationId: 'other-org' }],
    }, /one organization/);
    await rejectBeforeRequest({
      ...bulkRequest,
      ciphers: [{ ...bulkCipher, encryptedFor: 'other-user' }],
    }, /match every cipher/);
    await rejectBeforeRequest({ ...bulkRequest, unexpected: true }, /unsupported fields/);
    await rejectBeforeRequest({
      ...bulkRequest,
      ciphers: [{ ...bulkCipher, unexpected: true }],
    }, /unsupported fields/);
    await rejectBeforeRequest({
      ...bulkRequest,
      ciphers: new Array(50_001).fill(bulkCipher),
    }, /between 1 and 50000/);
  });

  it('does not reuse the 1000-id mutation cap for an ODO bulk share', async () => {
    const ciphers = Array.from({ length: 1_001 }, (_, index) => ({
      ...bulkCipher,
      id: `cipher-${index}`,
    }));
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));

    await expect(makeApi(fetchFn).shareCiphers('tok', { ...bulkRequest, ciphers }))
      .resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('bounds the serialized bulk-share body before server resolution', async () => {
    const serverUrlProvider = vi.fn(async () => 'https://vw.example.com');
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));
    const api = new ApiClient({ serverUrlProvider, fetchFn, localStore: createMemoryStore() });
    const oversized = {
      ...bulkRequest,
      ciphers: [{
        ...bulkCipher,
        login: { password: 'x'.repeat(64 * 1024 * 1024) },
      }],
    };

    await expect(api.shareCiphers('tok', oversized)).rejects.toThrow(/64.*byte limit|67108864-byte limit/);
    expect(serverUrlProvider).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('uses the official current-member self-revoke endpoint without a body', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));

    await expect(makeApi(fetchFn).revokeCurrentOrganizationMembership('tok', 'org-1'))
      .resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/api/organizations/org-1/users/revoke-self',
      expect.objectContaining({
        method: 'PUT',
        headers: serverHeaders({ authorization: 'Bearer tok' }),
      }),
    );
    const [, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.body).toBeUndefined();
  });

  it('falls back to Vaultwarden leave only after an explicit 404 and rechecks the request guard', async () => {
    const fetchFn = vi.fn()
      .mockResolvedValueOnce(textResponse('missing route', 404))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const guard = vi.fn();
    const api = makeApi(fetchFn).withRequestGuard(guard);

    await expect(api.revokeCurrentOrganizationMembership('tok', 'org-1'))
      .resolves.toBeUndefined();
    expect(fetchFn.mock.calls.map(([url, init]) => [url, (init as RequestInit).method])).toEqual([
      ['https://vw.example.com/api/organizations/org-1/users/revoke-self', 'PUT'],
      ['https://vw.example.com/api/organizations/org-1/leave', 'POST'],
    ]);
    expect(guard).toHaveBeenCalledTimes(2);
  });

  it('never falls back from a non-404 self-revoke failure', async () => {
    const fetchFn = vi.fn(async () => textResponse('forbidden', 403));

    await expect(makeApi(fetchFn).revokeCurrentOrganizationMembership('tok', 'org-1'))
      .rejects.toMatchObject({ status: 403 });
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('rejects an unsafe self-revoke organization id before server resolution', async () => {
    const serverUrlProvider = vi.fn(async () => 'https://vw.example.com');
    const fetchFn = vi.fn(async () => new Response(null, { status: 204 }));
    const api = new ApiClient({ serverUrlProvider, fetchFn, localStore: createMemoryStore() });

    await expect(api.revokeCurrentOrganizationMembership('tok', ' org-1 '))
      .rejects.toThrow(/organizationId/);
    expect(serverUrlProvider).not.toHaveBeenCalled();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    ['archive', '2026-08-31T00:00:00.000Z'],
    ['unarchive', null],
  ] as const)('PUTs the official %s bulk request and parses its list response', async (operation, archivedDate) => {
    const fetchFn = vi.fn(async () => jsonResponse({
      data: [{ id: 'cipher-1', type: 1, archivedDate }],
      object: 'list',
      continuationToken: null,
    }));
    const api = makeApi(fetchFn);
    const response = operation === 'archive'
      ? await api.archiveCiphers('tok', ['cipher-1'])
      : await api.unarchiveCiphers('tok', ['cipher-1']);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];

    expect(url).toBe(`https://vw.example.com/api/ciphers/${operation}`);
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual(serverHeaders({
      'content-type': 'application/json',
      authorization: 'Bearer tok',
    }));
    expect(JSON.parse(init.body as string)).toEqual({ ids: ['cipher-1'] });
    expect(response).toHaveLength(1);
    expect(response[0]).toMatchObject({ id: 'cipher-1', type: 1 });
  });

  it.each([
    [{ object: 'list', continuationToken: null }, /data/],
    [{ data: [], object: 'list', continuationToken: null }, /request count/],
    [{ data: [{ id: 'other', type: 1, archivedDate: '2026-08-31T00:00:00Z' }] }, /unexpected cipher id/],
    [{ data: [{ id: 'cipher-1', type: 1, archivedDate: null }] }, /archivedDate/],
    [{ data: [{ id: 'cipher-1', type: 1, archivedDate: 'not-a-date' }] }, /ISO date/],
    [{ data: [{ id: 'cipher-1', type: 1, archivedDate: '2026-08-31' }] }, /ISO date/],
    [{ data: [{ id: 'cipher-1', type: 1, archivedDate: '2026-08-31T00:00:00Z' }], continuationToken: 'next' }, /paginated/],
  ] as const)('rejects an invalid archive list response', async (body, error) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    await expect(makeApi(fetchFn).archiveCiphers('tok', ['cipher-1'])).rejects.toThrow(error);
  });

  it('rejects an unarchive response that retains archive state', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      data: [{ id: 'cipher-1', type: 1, archivedDate: '2026-08-31T00:00:00Z' }],
      object: 'list',
    }));

    await expect(makeApi(fetchFn).unarchiveCiphers('tok', ['cipher-1']))
      .rejects.toThrow('retained archivedDate');
  });
});

describe('ApiClient KDF change', () => {
  it('POSTs one modern and legacy-compatible superset without retrying', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const kdf = { kdfType: 1 as const, iterations: 4, memory: 32, parallelism: 2 };
    const body = {
      masterPasswordHash: 'old-hash',
      newMasterPasswordHash: 'new-hash',
      key: '2.wrapped',
      kdf: 1 as const,
      kdfIterations: 4,
      kdfMemory: 32,
      kdfParallelism: 2,
      authenticationData: {
        salt: 'user@example.com',
        kdf,
        masterPasswordAuthenticationHash: 'new-hash',
      },
      unlockData: {
        salt: 'user@example.com',
        kdf,
        masterKeyWrappedUserKey: '2.wrapped',
      },
    };

    await api.changeKdf('token', body);

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/accounts/kdf', expect.objectContaining({
      method: 'POST',
      headers: serverHeaders({ 'content-type': 'application/json', authorization: 'Bearer token' }),
      body: JSON.stringify(body),
    }));
  });

  it.each([
    { securityStamp: '' },
    { securityStamp: 'a', SecurityStamp: 'b' },
    { securityStamp: 42 },
  ])('rejects invalid security stamp fields at the sync wire boundary', async (fields) => {
    const fetchFn = vi.fn(async () => jsonResponse({
      profile: { id: 'u', email: 'u@example.com', ...fields },
      ciphers: [],
    }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.sync('access')).rejects.toThrow(/security stamp/i);
  });
});

describe('key-rotation endpoints', () => {
  const PASSKEY_ID = '11111111-1111-4111-8111-111111111111';
  const DEVICE_ID = '22222222-2222-4222-8222-222222222222';

  it('POSTs the rotate payload', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn: fetchFn as never, localStore: createMemoryStore() });
    await api.rotateAccountKey('tok', { oldMasterKeyAuthenticationHash: 'h' } as never);
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/accounts/key-management/rotate-user-account-keys', expect.objectContaining({ method: 'POST' }));
  });

  it('GETs the trusted emergency-access list, org public key, and account public key', async () => {
    const fetchFn = vi.fn(async (u: string) => u.includes('trusted') ? jsonResponse({ data: [{ id: 'e1' }] }) : jsonResponse({ publicKey: 'PUB' }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn: fetchFn as never, localStore: createMemoryStore() });
    expect(await api.getTrustedEmergencyAccess('t')).toEqual([{ id: 'e1' }]);
    expect((await api.getOrganizationPublicKey('t', 'o1')).publicKey).toBe('PUB');
    expect((await api.getAccountPublicKey('t')).publicKey).toBe('PUB');
  });

  it('proves empty passkey and trusted-device unlock inventories from two no-store reads', async () => {
    const fetchFn = vi.fn(async (url: string) => url.endsWith('/api/webauthn')
      ? jsonResponse({ data: [] })
      : jsonResponse({ Data: [{ Id: DEVICE_ID, IsTrusted: false }] }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: fetchFn as never,
      localStore: createMemoryStore(),
    });

    await expect(api.getKeyRotationUnlockRecordsStatus('rotation-token')).resolves.toEqual({
      passkeyUnlockData: 'empty',
      deviceKeyUnlockData: 'empty',
    });

    expect(fetchFn).toHaveBeenCalledTimes(2);
    for (const [url, init] of fetchFn.mock.calls as unknown as Array<[string, RequestInit]>) {
      expect(url).toMatch(/\/api\/(webauthn|devices)$/u);
      expect(init).toMatchObject({
        method: 'GET',
        cache: 'no-store',
        headers: serverHeaders({ authorization: 'Bearer rotation-token' }),
      });
    }
  });

  it('reports only PRF-enabled credentials and trusted devices as key-bearing records', async () => {
    const fetchFn = vi.fn(async (url: string) => url.endsWith('/api/webauthn')
      ? jsonResponse({
          data: [{
            id: PASSKEY_ID,
            prfStatus: 0,
            encryptedPublicKey: '2.encrypted-public-key',
            encryptedUserKey: '2.encrypted-user-key',
          }],
        })
      : jsonResponse({ data: [{ id: DEVICE_ID, isTrusted: true }] }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: fetchFn as never,
      localStore: createMemoryStore(),
    });

    await expect(api.getKeyRotationUnlockRecordsStatus('token')).resolves.toEqual({
      passkeyUnlockData: 'present',
      deviceKeyUnlockData: 'present',
    });
  });

  it.each([
    ['missing list data', { object: 'list' }, { data: [] }],
    ['future PRF status', { data: [{ id: PASSKEY_ID, prfStatus: 3 }] }, { data: [] }],
    ['enabled PRF record without wrapped keys', { data: [{ id: PASSKEY_ID, prfStatus: 0 }] }, { data: [] }],
    ['device without trust state', { data: [] }, { data: [{ id: DEVICE_ID }] }],
    ['duplicate casing aliases', { data: [], Data: [] }, { data: [] }],
    ['paginated response', { data: [], continuationToken: 'next-page' }, { data: [] }],
  ])('rejects uncertain unlock inventory schema: %s', async (_name, passkeys, devices) => {
    const fetchFn = vi.fn(async (url: string) => url.endsWith('/api/webauthn')
      ? jsonResponse(passkeys)
      : jsonResponse(devices));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com',
      fetchFn: fetchFn as never,
      localStore: createMemoryStore(),
    });

    await expect(api.getKeyRotationUnlockRecordsStatus('token')).rejects.toBeTruthy();
  });
});

describe('ApiClient hardening', () => {
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com',
    fetchFn,
    localStore: createMemoryStore(),
  });

  it('passwordLogin maps a non-JSON error body to ApiHttpError (not a raw SyntaxError)', async () => {
    const fetchFn = vi.fn(async () => textResponse('<html>502 Bad Gateway</html>', 502));
    const err = await captureApiHttpError(makeApi(fetchFn).passwordLogin({ email: 'u@e.com', masterPasswordHash: 'h' }));
    expect(err.status).toBe(502);
    expect(err.body).toContain('Bad Gateway');
  });

  it('refresh maps a non-JSON error body to ApiHttpError (not a raw SyntaxError)', async () => {
    const fetchFn = vi.fn(async () => textResponse('proxy down', 502));
    const err = await captureApiHttpError(makeApi(fetchFn).refresh('rt'));
    expect(err.status).toBe(502);
  });

  it('passwordLogin throws a descriptive error when a 200 body lacks access_token', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ unexpected: true }, 200));
    await expect(makeApi(fetchFn).passwordLogin({ email: 'u@e.com', masterPasswordHash: 'h' }))
      .rejects.toThrow(/access[_ ]?token/i);
  });

  it.each([
    ['non-Bearer token type', { token_type: 'MAC' }],
    ['missing refresh token', { refresh_token: undefined }],
    ['fractional lifetime', { expires_in: 3_600.5 }],
    ['overflowing lifetime', { expires_in: Number.MAX_SAFE_INTEGER }],
    ['malformed protected key', { Key: '2.invalid' }],
    ['malformed private key', { PrivateKey: '2.invalid' }],
    ['control character in remember token', { TwoFactorToken: 'remember\r\ninjected' }],
    ['incomplete Argon2 KDF', { Kdf: 1, KdfIterations: 4, KdfMemory: 64 }],
  ])('rejects malformed successful login data: %s', async (_label, override) => {
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access',
      refresh_token: 'refresh',
      expires_in: 3_600,
      token_type: 'Bearer',
      Key: USER_KEY_VECTOR_600K.akey,
      Kdf: 0,
      KdfIterations: 600_000,
      ...override,
    }));
    await expect(makeApi(fetchFn).passwordLogin({ email: 'u@e.com', masterPasswordHash: 'h' }))
      .rejects.toThrow();
  });

  it.each([
    ['missing refresh token', { refresh_token: undefined }],
    ['non-Bearer token type', { token_type: 'Basic' }],
    ['zero lifetime', { expires_in: 0 }],
    ['control character in access token', { access_token: 'access\nheader' }],
  ])('rejects malformed successful refresh data: %s', async (_label, override) => {
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      expires_in: 3_600,
      token_type: 'Bearer',
      ...override,
    }));
    await expect(makeApi(fetchFn).refresh('old-refresh')).rejects.toBeInstanceOf(TypeError);
  });

  it('sendEmailLogin tolerates an empty 200 body (Vaultwarden returns no body)', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    await expect(makeApi(fetchFn).sendEmailLogin({ email: 'u@e.com', twoFactorToken: 't' })).resolves.toBeUndefined();
  });

  it.each([
    ['camelCase', { id: 'attachment-1', url: 'https://cdn.example/blob?signature=fresh', object: 'attachment' }],
    ['PascalCase', { Id: 'attachment-1', Url: 'https://cdn.example/blob?signature=fresh', Object: 'attachment' }],
  ])('fetches and strictly parses a fresh attachment download URL in %s', async (_case, body) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));
    const api = makeApi(fetchFn);

    await expect(api.getAttachmentDownloadUrl('secret-token', 'cipher/1', 'attachment-1'))
      .resolves.toBe('https://cdn.example/blob?signature=fresh');

    expect(fetchFn).toHaveBeenCalledWith(
      'https://vw.example.com/api/ciphers/cipher%2F1/attachment/attachment-1',
      expect.objectContaining({
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        headers: serverHeaders({
          'cache-control': 'no-store',
          pragma: 'no-cache',
          authorization: 'Bearer secret-token',
        }),
      }),
    );
  });

  it.each([
    ['mismatched id', { id: 'other', url: 'https://cdn.example/blob' }],
    ['missing url', { id: 'attachment-1' }],
    ['duplicate url aliases', { id: 'attachment-1', url: 'https://cdn.example/a', Url: 'https://cdn.example/b' }],
    ['unknown field', { id: 'attachment-1', url: 'https://cdn.example/blob', future: true }],
    ['invalid metadata type', { id: 'attachment-1', url: 'https://cdn.example/blob', size: 1 }],
    ['invalid URL', { id: 'attachment-1', url: 'javascript:alert(1)' }],
  ])('rejects an invalid attachment download response: %s', async (_case, body) => {
    const fetchFn = vi.fn(async () => jsonResponse(body));

    await expect(makeApi(fetchFn).getAttachmentDownloadUrl('token', 'cipher-1', 'attachment-1'))
      .rejects.toBeInstanceOf(Error);
  });

  it('preserves an explicit 404 from the fresh attachment URL endpoint', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ message: 'unsupported' }, 404));

    const error = await captureApiHttpError(
      makeApi(fetchFn).getAttachmentDownloadUrl('token', 'cipher-1', 'attachment-1'),
    );
    expect(error).toMatchObject({ status: 404 });
  });

  it('downloadAttachment attaches the Bearer token only when the URL is the configured origin', async () => {
    const sameOrigin = vi.fn(async () => jsonResponse({}));
    await makeApi(sameOrigin as never).downloadAttachment('https://vw.example.com/attachments/a1', 'secret-token');
    const sameOriginInit = (sameOrigin.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(sameOriginInit.headers).toMatchObject({ authorization: 'Bearer secret-token' });
    expect(new Headers(sameOriginInit.headers).get('Bitwarden-Client-Version'))
      .toBe(BITWARDEN_CLIENT_VERSION);
    expect(sameOriginInit.credentials).toBe('omit');
    expect(sameOriginInit.redirect).toBe('error');

    const crossOrigin = vi.fn(async () => jsonResponse({}));
    await makeApi(crossOrigin as never).downloadAttachment('https://evil.example.net/blob', 'secret-token');
    const crossOriginInit = (crossOrigin.mock.calls[0] as unknown as [string, RequestInit])[1];
    const headers = crossOriginInit.headers as Record<string, string> | undefined;
    expect(headers?.authorization).toBeUndefined();
    expect(new Headers(headers).has('Bitwarden-Client-Version')).toBe(false);
    expect(crossOriginInit.credentials).toBe('omit');
    expect(crossOriginInit.redirect).toBe('error');
  });

  it.each([
    'data:application/octet-stream;base64,AQID',
    'file:///C:/Users/example/secret.bin',
    'https://user:password@cdn.example.net/blob',
    'https://@cdn.example.net/blob',
    'https://cdn.example.net/blob#fragment',
    'http://cdn.example.net/blob',
    '/relative/attachment',
    `https://cdn.example.net/blob?signature=${'x'.repeat(8 * 1024)}`,
  ])('rejects an unsafe attachment URL before fetch: %s', async (url) => {
    const fetchFn = vi.fn(async () => new Response(new Uint8Array([1])));

    await expect(makeApi(fetchFn).downloadAttachment(url, 'secret-token', 32))
      .rejects.toMatchObject({ name: 'ApiInvalidDownloadUrlError' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('preserves a signed cross-origin HTTPS query without sending credentials or the bearer token', async () => {
    const signedUrl = 'https://cdn.example.net/blob/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc%2B123';
    const fetchFn = vi.fn(async () => new Response(new Uint8Array([1, 2, 3])));

    await expect(makeApi(fetchFn).downloadAttachment(signedUrl, 'secret-token', 32))
      .resolves.toEqual(new Uint8Array([1, 2, 3]));

    expect(fetchFn).toHaveBeenCalledWith(signedUrl, expect.objectContaining({
      headers: {},
      credentials: 'omit',
      redirect: 'error',
    }));
  });

  it('allows HTTP only inside the configured loopback base path', async () => {
    const fetchFn = vi.fn(async () => new Response(new Uint8Array([4, 5, 6])));
    const api = new ApiClient({
      serverUrlProvider: async () => 'http://127.0.0.1:18082/vault',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const attachmentUrl = 'http://127.0.0.1:18082/vault/attachments/a?token=signed';

    await expect(api.downloadAttachment(attachmentUrl, 'secret-token', 32))
      .resolves.toEqual(new Uint8Array([4, 5, 6]));
    expect(fetchFn).toHaveBeenCalledWith(attachmentUrl, expect.objectContaining({
      headers: serverHeaders({ authorization: 'Bearer secret-token' }),
      credentials: 'omit',
      redirect: 'error',
    }));
  });

  it('rejects HTTP loopback URLs outside the configured base path', async () => {
    const fetchFn = vi.fn(async () => new Response(new Uint8Array([1])));
    const api = new ApiClient({
      serverUrlProvider: async () => 'http://localhost:18082/vault',
      fetchFn,
      localStore: createMemoryStore(),
    });

    await expect(api.downloadAttachment('http://localhost:18082/vault/../admin/export', 'token', 32))
      .rejects.toMatchObject({ name: 'ApiInvalidDownloadUrlError' });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('keeps the token request deadline active until the response body finishes', async () => {
    vi.useFakeTimers();
    try {
      const firstChunk = new Uint8Array([123, 34, 97, 34, 58, 49]);
      const cancel = vi.fn();
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(firstChunk);
        },
        cancel,
      });
      const fetchFn = vi.fn(async () => new Response(body, { status: 200 }));
      const store = createMemoryStore();
      await store.set('deviceIdentifier', 'device-123');
      const api = new ApiClient({
        serverUrlProvider: async () => 'https://vw.example.com',
        fetchFn,
        localStore: store,
      });

      const request = api.passwordLogin({ email: 'u@example.com', masterPasswordHash: 'hash' });
      const assertion = expect(request).rejects.toBeInstanceOf(ApiTimeoutError);
      await vi.advanceTimersByTimeAsync(30_000);
      await assertion;

      expect(cancel).toHaveBeenCalledOnce();
      expect([...firstChunk]).toEqual([0, 0, 0, 0, 0, 0]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('allows a sync response above the ordinary limit but below the sync limit', async () => {
    const padding = 'x'.repeat(4 * 1024 * 1024);
    const fetchFn = vi.fn(async () => jsonResponse({
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [],
      padding,
    }));

    const response = await makeApi(fetchFn).sync('token');

    expect((response as unknown as { padding: string }).padding).toHaveLength(padding.length);
  });

  it('rejects an ordinary successful API response above the default limit', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      kdf: 0,
      kdfIterations: 600_000,
      padding: 'x'.repeat(4 * 1024 * 1024),
    }));

    await expect(makeApi(fetchFn).prelogin('u@example.com'))
      .rejects.toBeInstanceOf(ApiResponseTooLargeError);
  });

  it('bounds a token error body before constructing ApiHttpError', async () => {
    const fetchFn = vi.fn(async () => new Response('x'.repeat(4 * 1024 * 1024 + 1), { status: 400 }));

    await expect(makeApi(fetchFn).passwordLogin({ email: 'u@example.com', masterPasswordHash: 'hash' }))
      .rejects.toMatchObject({
        name: 'ApiResponseTooLargeError',
        maxBytes: 4 * 1024 * 1024,
      });
  });

  it('rejects an attachment from Content-Length before reading its body', async () => {
    const pull = vi.fn();
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ pull, cancel }, { highWaterMark: 0 });
    const fetchFn = vi.fn(async () => new Response(body, {
      status: 200,
      headers: { 'content-length': '10' },
    }));

    await expect(makeApi(fetchFn).downloadAttachment('https://vw.example.com/a', 'token', 3))
      .rejects.toEqual(new ApiResponseTooLargeError(3, 10));
    expect(pull).not.toHaveBeenCalled();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('does not trust an under-reported Content-Length and cancels on actual overflow', async () => {
    const first = new Uint8Array([1, 2]);
    const second = new Uint8Array([3, 4]);
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first);
        controller.enqueue(second);
      },
      cancel,
    });
    const fetchFn = vi.fn(async () => new Response(body, {
      status: 200,
      headers: { 'content-length': '1' },
    }));

    await expect(makeApi(fetchFn).downloadAttachment('https://vw.example.com/a', 'token', 3))
      .rejects.toEqual(new ApiResponseTooLargeError(3, 4));
    expect(cancel).toHaveBeenCalledOnce();
    expect([...first, ...second]).toEqual([0, 0, 0, 0]);
  });

  it('propagates a response reader failure and clears already-read chunks', async () => {
    const first = new Uint8Array([1, 2, 3]);
    const streamError = new Error('response stream failed');
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first);
      },
      pull(controller) {
        controller.error(streamError);
      },
      cancel,
    }, { highWaterMark: 0 });
    const fetchFn = vi.fn(async () => new Response(body, { status: 200 }));

    await expect(makeApi(fetchFn).downloadAttachment('https://vw.example.com/a', 'token', 16))
      .rejects.toBe(streamError);
    expect([...first]).toEqual([0, 0, 0]);
  });

  it('validates an explicit attachment limit before making a request', async () => {
    const fetchFn = vi.fn(async () => new Response('unused'));
    const api = makeApi(fetchFn);

    await expect(api.downloadAttachment('https://vw.example.com/a', 'token', 0))
      .rejects.toThrow(/positive safe integer/i);
    await expect(api.downloadAttachment('https://vw.example.com/a', 'token', 128 * 1024 * 1024 + 1))
      .rejects.toThrow(/cannot exceed/i);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('times out a stalled request with a clear error', async () => {
    vi.useFakeTimers();
    try {
      const fetchFn = vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      }));
      const promise = makeApi(fetchFn as never).sync('token');
      const assertion = expect(promise).rejects.toThrow(/timed out|timeout/i);
      await vi.advanceTimersByTimeAsync(60_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('ApiClient vault conflicts', () => {
  it.each([409, 412])('classifies HTTP %s as an optimistic concurrency conflict', (status) => {
    expect(isVaultConflictError(new ApiHttpError(status, { message: 'conflict' }))).toBe(true);
  });

  it('recognizes Vaultwarden revision errors returned as a validation response', () => {
    expect(isVaultConflictError(new ApiHttpError(400, {
      error: 'The client copy of this cipher is out of date. Please sync and try again.',
    }))).toBe(true);
    expect(isVaultConflictError(new ApiHttpError(500, 'revision backend failed'))).toBe(false);
  });
});

describe('ApiClient password-change requirements', () => {
  const success = {
    access_token: 'access',
    refresh_token: 'refresh',
    expires_in: 3_600,
    token_type: 'Bearer',
    Key: USER_KEY_VECTOR_600K.akey,
    Kdf: 0,
    KdfIterations: 600_000,
  };

  function apiFor(body: unknown, status = 200): ApiClient {
    return new ApiClient({
      serverUrlProvider: async () => 'https://vault.example',
      fetchFn: vi.fn(async () => jsonResponse(body, status)),
      localStore: createMemoryStore(),
    });
  }

  it('strictly projects force reset and master password policy on token success', async () => {
    const result = await apiFor({
      ...success,
      ForcePasswordReset: true,
      MasterPasswordPolicy: { MinLength: 18, RequireNumbers: true, EnforceOnLogin: true },
    }).passwordLogin({ email: 'user@example.com', masterPasswordHash: 'hash' });
    expect(result).toMatchObject({
      kind: 'success',
      data: {
        forcePasswordReset: true,
        masterPasswordPolicy: {
          minLength: 18,
          requireNumbers: true,
          enforceOnLogin: true,
        },
      },
    });
  });

  it('carries the policy on a two-factor continuation', async () => {
    const result = await apiFor({
      error: 'invalid_grant',
      error_description: 'Two factor required',
      TwoFactorProviders: ['0'],
      MasterPasswordPolicy: { MinLength: 20, EnforceOnLogin: true },
    }, 400).passwordLogin({ email: 'user@example.com', masterPasswordHash: 'hash' });
    expect(result).toMatchObject({
      kind: 'twoFactor',
      masterPasswordPolicy: { minLength: 20, enforceOnLogin: true },
    });
  });

  it.each([
    { ForcePasswordReset: 'true' },
    { MasterPasswordPolicy: { EnforceOnLogin: 'true' } },
    { MasterPasswordPolicy: { MinLength: -1 } },
  ])('rejects malformed login security fields before returning success', async (override) => {
    await expect(apiFor({ ...success, ...override }).passwordLogin({
      email: 'user@example.com',
      masterPasswordHash: 'hash',
    })).rejects.toThrow();
  });
});
