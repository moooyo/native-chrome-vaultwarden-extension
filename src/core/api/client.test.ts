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
    const result = await api.passwordLogin({ email: '  USER@Example.COM  ', masterPasswordHash: 'mph' });
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

  it('normalises mixed-case/whitespace email: username field is trimmed and lowercased', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-abc');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'at', expires_in: 3600, refresh_token: 'rt', token_type: 'Bearer',
      Key: '2.iv|ct|mac', Kdf: 0, KdfIterations: 600000,
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    await api.passwordLogin({ email: '  USER@EXAMPLE.COM  ', masterPasswordHash: 'mph' });
    const form = new URLSearchParams((fetchFn.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
    expect(form.get('username')).toBe('user@example.com');
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
    expect(form.get('device_type')).toBe('2');
    expect(form.get('device_name')).toBe('chrome');
    expect(form.get('device_identifier')).toBe('device-123');
  });

  it('syncs with Authorization Bearer token', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await expect(api.sync('access')).resolves.toEqual({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/sync', {
      method: 'GET',
      headers: { authorization: 'Bearer access' },
    });
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
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/folders', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
      body: JSON.stringify({ name: '2.enc' }),
    });
  });

  it('PUTs /api/folders/<id> to rename', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'f1', name: '2.new' }));
    await makeApi(fetchFn).updateFolder('token', 'f1', '2.new');
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/folders/f1', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
      body: JSON.stringify({ name: '2.new' }),
    });
  });

  it('DELETEs /api/folders/<id> and tolerates an empty response body', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    await expect(makeApi(fetchFn).deleteFolder('token', 'f1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/folders/f1', {
      method: 'DELETE',
      headers: { authorization: 'Bearer token' },
    });
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
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
      body: JSON.stringify(request),
    });
  });

  it('PUTs /api/ciphers/<id> to update', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', type: 1, name: '2.enc' }));
    await makeApi(fetchFn).updateCipher('token', 'c1', request);
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
      body: JSON.stringify(request),
    });
  });

  it('DELETEs /api/ciphers/<id> and tolerates an empty body', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    await expect(makeApi(fetchFn).deleteCipher('token', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1', {
      method: 'DELETE',
      headers: { authorization: 'Bearer token' },
    });
  });

  it('PUTs /api/ciphers/<id>/delete to soft-delete (move to trash) with an empty body', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    await expect(makeApi(fetchFn).softDeleteCipher('token', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1/delete', {
      method: 'PUT',
      headers: { authorization: 'Bearer token' },
    });
  });

  it('PUTs /api/ciphers/<id>/restore to restore from trash', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', type: 1, name: '2.enc', deletedDate: null }));
    await expect(makeApi(fetchFn).restoreCipher('token', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/ciphers/c1/restore', {
      method: 'PUT',
      headers: { authorization: 'Bearer token' },
    });
  });
});

describe('ApiClient register', () => {
  it('POSTs /identity/accounts/register with the registration payload', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com/', fetchFn, localStore: createMemoryStore() });
    const data = {
      email: 'new@example.com', masterPasswordHash: 'hash', key: '2.k',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' }, kdf: 0, kdfIterations: 600000,
    };
    await expect(api.register(data)).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/identity/accounts/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    });
  });

  it('throws ApiHttpError when registration is rejected', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ message: 'taken' }, 400));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com/', fetchFn, localStore: createMemoryStore() });
    const err = await captureApiHttpError(api.register({
      email: 'x', masterPasswordHash: 'h', key: '2.k', keys: { publicKey: 'p', encryptedPrivateKey: '2.e' }, kdf: 0, kdfIterations: 600000,
    }));
    expect(err.status).toBe(400);
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

describe('ApiClient collection endpoints', () => {
  const makeApi = (fetchFn: typeof fetch) => new ApiClient({
    serverUrlProvider: async () => 'https://vw.example.com',
    fetchFn,
    localStore: createMemoryStore(),
  });

  it('POSTs a create-collection with mandatory empty groups/users', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', organizationId: 'o1' }));
    const api = makeApi(fetchFn);
    await api.createCollection('tok', 'o1', '2.enc==');
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/organizations/o1/collections');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer tok' });
    expect(JSON.parse(init.body as string)).toEqual({ name: '2.enc==', groups: [], users: [], externalId: null });
  });

  it('renames by resending preserved groups/users', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1' }));
    const api = makeApi(fetchFn);
    await api.updateCollection('tok', 'o1', 'c1', '2.new==', { groups: [{ id: 'g1' }], users: [{ id: 'u1' }] });
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/organizations/o1/collections/c1');
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer tok' });
    expect(JSON.parse(init.body as string)).toEqual({ name: '2.new==', groups: [{ id: 'g1' }], users: [{ id: 'u1' }], externalId: null });
  });

  it('PUTs cipher collectionIds', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 200 }));
    const api = makeApi(fetchFn);
    await api.updateCipherCollections('tok', 'ci1', ['x', 'y']);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://vw.example.com/api/ciphers/ci1/collections');
    expect(init.method).toBe('PUT');
    expect(init.headers).toEqual({ 'content-type': 'application/json', authorization: 'Bearer tok' });
    expect(JSON.parse(init.body as string)).toEqual({ collectionIds: ['x', 'y'] });
  });

  it('GETs a collection with details endpoint', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ id: 'c1', organizationId: 'o1', groups: [], users: [] }));
    const api = makeApi(fetchFn);
    const res = await api.getCollectionDetails('tok', 'o1', 'c1');
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/organizations/o1/collections/c1/details', expect.objectContaining({
      method: 'GET',
      headers: { authorization: 'Bearer tok' },
    }));
    expect(res).toEqual({ id: 'c1', organizationId: 'o1', groups: [], users: [] });
  });

  it('DELETEs a collection', async () => {
    const fetchFn = vi.fn(async () => textResponse('', 200));
    const api = makeApi(fetchFn);
    await expect(api.deleteCollection('tok', 'o1', 'c1')).resolves.toBeUndefined();
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/organizations/o1/collections/c1', expect.objectContaining({
      method: 'DELETE',
      headers: { authorization: 'Bearer tok' },
    }));
  });
});
