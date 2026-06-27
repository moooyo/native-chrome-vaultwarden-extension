import { describe, it, expect, vi } from 'vitest';
import { ApiClient, ApiHttpError } from './client.js';
import { createMemoryStore } from '../../platform/store.js';

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
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'user@example.com' }),
    });
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

describe('ApiClient password grant', () => {
  it('POSTs connect/token as form-urlencoded with required browser parameters', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access',
      expires_in: 3600,
      refresh_token: 'refresh',
      token_type: 'Bearer',
      Key: '2.iv|ct|mac',
      Kdf: 0,
      KdfIterations: 600000,
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result.kind).toBe('success');
    const call = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    const init = call[1];
    expect(init.headers).toEqual({ 'content-type': 'application/x-www-form-urlencoded' });
    const form = new URLSearchParams(init.body as string);
    expect(form.get('grant_type')).toBe('password');
    expect(form.get('username')).toBe('user@example.com');
    expect(form.get('password')).toBe('mph');
    expect(form.get('scope')).toBe('api offline_access');
    expect(form.get('client_id')).toBe('browser');
    expect(form.get('device_type')).toBe('2');
    expect(form.get('device_identifier')).toBe('device-123');
    expect(form.get('device_name')).toBe('chrome');
  });

  it('parses 2FA-required invalid_grant into supported provider ids', async () => {
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
});
