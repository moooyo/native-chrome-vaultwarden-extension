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

describe('ApiClient prelogin', () => {
  it('POSTs /identity/accounts/prelogin with lowercase email in JSON body', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ kdf: 0, kdfIterations: 600000 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const res = await api.prelogin('USER@EXAMPLE.COM');
    expect(res).toEqual({ kdf: 0, kdfIterations: 600000 });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'user@example.com' }),
    });
  });

  it('stores and reuses a stable device identifier', async () => {
    const store = createMemoryStore();
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', localStore: store });
    const first = await api.getDeviceIdentifier();
    const second = await api.getDeviceIdentifier();
    expect(first).toMatch(/[0-9a-f-]{36}/);
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
    await expect(api.prelogin('invalid')).rejects.toThrow(ApiHttpError);
    const error = (await api.prelogin('invalid').catch(e => e)) as ApiHttpError;
    expect(error.status).toBe(400);
    expect(error.body).toEqual({ error: 'Invalid email' });
  });

  it('throws ApiHttpError with status on non-OK non-JSON response (HTML error page)', async () => {
    const fetchFn = vi.fn(async () => textResponse('<html><body>502 Bad Gateway</body></html>', 502));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    await expect(api.prelogin('user@example.com')).rejects.toThrow(ApiHttpError);
    const error = (await api.prelogin('user@example.com').catch(e => e)) as ApiHttpError;
    expect(error.status).toBe(502);
    expect(typeof error.body).toBe('string');
  });

  it('throws ApiHttpError with status on non-OK response with no body', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 503 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    await expect(api.prelogin('user@example.com')).rejects.toThrow(ApiHttpError);
    const error = (await api.prelogin('user@example.com').catch(e => e)) as ApiHttpError;
    expect(error.status).toBe(503);
    expect(error.body).toBe('');
  });
});
