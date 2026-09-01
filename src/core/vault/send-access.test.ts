import { describe, it, expect, vi } from 'vitest';
import {
  parseSendUrl,
  decryptAccessedSend,
  sendPasswordHash,
  accessSend,
  requestFileDownloadUrl,
  resolveSendDownloadTarget,
  downloadAndDecryptFile,
  type AccessedSendResult,
  type SendAccessAuthorization,
  type SendAccessEndpoints,
  type SendAccessResult,
  type SendEmailAuthProof,
} from './send-access.js';
import { deriveSendKey } from './sends.js';
import { encryptToText } from '../crypto/encstring.js';
import { bytesToBase64Url } from '../crypto/encoding.js';
import { encryptAttachmentFile } from './attachments.js';

const sendKey = new Uint8Array(16).fill(7);

describe('parseSendUrl', () => {
  it('parses server, accessId and send key from a share link', () => {
    const link = `https://vault.example/#/send/AbC123/${bytesToBase64Url(sendKey)}`;
    const parsed = parseSendUrl(link);
    expect(parsed.serverUrl).toBe('https://vault.example');
    expect(parsed.serverOrigin).toBe('https://vault.example');
    expect(parsed.originPattern).toBe('https://vault.example/*');
    expect(parsed.accessId).toBe('AbC123');
    expect(Array.from(parsed.sendKey)).toEqual(Array.from(sendKey));
  });
  it('rejects a non-send or malformed link', () => {
    expect(() => parseSendUrl('https://vault.example/#/login')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl('not a url')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl('https://vault.example/#/send/acc/')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://#/send/acc/${bytesToBase64Url(sendKey)}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://%/#/send/acc/${bytesToBase64Url(sendKey)}`)).toThrowError(/invalid_link/);
  });
  it('uses URL semantics and rejects unsupported schemes, credentials, queries and extra fragments', () => {
    const key = bytesToBase64Url(sendKey);
    expect(() => parseSendUrl(`ftp://vault.example/#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://user:pass@vault.example/#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://vault.example/?next=evil#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://vault.example/#/send/acc/${key}/extra`)).toThrowError(/invalid_link/);
  });
  it('rejects non-canonical route and base encodings before normalization', () => {
    const key = bytesToBase64Url(sendKey);
    expect(() => parseSendUrl(`https://vault.example/#/send/%61cc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://vault.example/#//send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://vault.example/base/../#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://vault.example/base/%2e%2e/#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://@vault.example/#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https:////vault.example/#/send/acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(String.raw`https:\vault.example#/send/acc/${key}`)).toThrowError(/invalid_link/);
  });
  it('preserves explicit HTTP self-hosting for loopback, private-network and public hosts', () => {
    const key = bytesToBase64Url(sendKey);
    expect(parseSendUrl(`http://localhost:8080/#/send/acc/${key}`).serverUrl).toBe('http://localhost:8080');
    expect(parseSendUrl(`http://127.1/#/send/acc/${key}`).serverUrl).toBe('http://127.0.0.1');
    expect(parseSendUrl(`http://[::1]:8080/#/send/acc/${key}`).serverUrl).toBe('http://[::1]:8080');
    expect(parseSendUrl(`http://192.168.1.10:8080/#/send/acc/${key}`).serverUrl).toBe('http://192.168.1.10:8080');
    expect(parseSendUrl(`http://vault.example/#/send/acc/${key}`).serverUrl).toBe('http://vault.example');
  });
  it('preserves and canonicalizes a server base path', () => {
    const parsed = parseSendUrl(`https://vault.example/base//#/send/acc/${bytesToBase64Url(sendKey)}`);
    expect(parsed.serverUrl).toBe('https://vault.example/base');
    expect(parseSendUrl(`HTTPS://Vault.Example:443/base/#/send/acc/${bytesToBase64Url(sendKey)}`)).toMatchObject({
      serverUrl: 'https://vault.example/base',
      serverOrigin: 'https://vault.example',
      originPattern: 'https://vault.example/*',
    });
  });
  it('maps the exact official US vanity and redirected vault routes to split Cloud services', () => {
    const key = bytesToBase64Url(sendKey);
    const vanity = parseSendUrl(`https://send.bitwarden.com/#AbC123/${key}`);
    expect(vanity).toMatchObject({
      serverUrl: 'https://send.bitwarden.com',
      accessId: 'AbC123',
      endpoints: {
        apiBaseUrl: 'https://api.bitwarden.com/',
        identityBaseUrl: 'https://identity.bitwarden.com/',
        downloadBaseUrl: 'https://api.bitwarden.com',
        originPatterns: ['https://api.bitwarden.com/*', 'https://identity.bitwarden.com/*'],
      },
    });
    expect(parseSendUrl(`https://vault.bitwarden.com/#/send/AbC123/${key}`).endpoints)
      .toMatchObject(vanity.endpoints);
    expect(parseSendUrl(`https://send.bitwarden.com:443/#AbC123/${key}`).endpoints)
      .toMatchObject(vanity.endpoints);
  });
  it('maps the exact official EU and Gov standard routes from the production environment table', () => {
    const key = bytesToBase64Url(sendKey);
    expect(parseSendUrl(`https://vault.bitwarden.eu/#/send/eu123/${key}`).endpoints).toMatchObject({
      apiBaseUrl: 'https://api.bitwarden.eu/',
      identityBaseUrl: 'https://identity.bitwarden.eu/',
    });
    expect(parseSendUrl(`https://send.bitwarden-gov.com/#/send/gov123/${key}`).endpoints).toMatchObject({
      apiBaseUrl: 'https://api.bitwarden-gov.com/',
      identityBaseUrl: 'https://identity.bitwarden-gov.com/',
    });
  });
  it('never grants Cloud routing to lookalike hosts, unsupported EU vanity, or non-default ports', () => {
    const key = bytesToBase64Url(sendKey);
    expect(() => parseSendUrl(`https://send.bitwarden.eu/#eu123/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://send.bitwarden.eu/#/send/eu123/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://send.bitwarden.com:444/#acc/${key}`)).toThrowError(/invalid_link/);
    expect(() => parseSendUrl(`https://send.bitwarden.com:444/#/send/acc/${key}`)).toThrowError(/invalid_link/);
    const lookalike = parseSendUrl(`https://evil.send.bitwarden.com/#/send/acc/${key}`);
    expect(lookalike.endpoints).toMatchObject({
      apiBaseUrl: 'https://evil.send.bitwarden.com/api/',
      identityBaseUrl: 'https://evil.send.bitwarden.com/identity/',
    });
  });
  it('rejects a key that is not 16 bytes', () => {
    expect(() => parseSendUrl(`https://vault.example/#/send/acc/${bytesToBase64Url(new Uint8Array(8))}`)).toThrowError(/invalid_link/);
  });
  it('throws an error carrying code invalid_link', () => {
    const err = (() => { try { parseSendUrl('nope'); return null; } catch (e) { return e as { code?: string }; } })();
    expect(err?.code).toBe('invalid_link');
  });
});

describe('decryptAccessedSend', () => {
  it('decrypts a text send name + text', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = {
      id: 'send-1',
      type: 0,
      name: await encryptToText('Greeting', derived),
      text: { text: await encryptToText('hello', derived), hidden: true },
    };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out).toMatchObject({ id: 'send-1', type: 0, name: 'Greeting', text: 'hello', hidden: true });
  });
  it('defaults an omitted text hidden flag to false', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-1', type: 0, name: await encryptToText('Greeting', derived), text: { text: await encryptToText('hello', derived) } };
    await expect(decryptAccessedSend(raw, sendKey)).resolves.toMatchObject({ hidden: false });
  });
  it('decrypts a file send name + file name, keeping fileId/sizeName', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-2', type: 1, name: await encryptToText('Doc', derived), file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out).toMatchObject({ id: 'send-2', type: 1, name: 'Doc', fileName: 'secret.pdf', fileId: 'f1', sizeName: '3 KB' });
    expect(out.text).toBeUndefined();
  });
  it('degrades an undecryptable field to a placeholder rather than throwing', async () => {
    const raw = { id: 'send-x', type: 0, name: 'not-a-valid-encstring', text: { text: 'also-bad' } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out.name).toBe('(undecryptable)');
    expect(out.text).toBe('(undecryptable)');
  });
  it('rejects a syntactically valid JSON value with an invalid Send schema', async () => {
    await expect(decryptAccessedSend({}, sendKey)).rejects.toMatchObject({ code: 'invalid_response' });
    await expect(decryptAccessedSend({ id: 's1', type: 1, name: 'name', file: { fileName: 'file' } }, sendKey))
      .rejects.toMatchObject({ code: 'invalid_response' });
    await expect(decryptAccessedSend({ id: 's1', type: 2, name: 'name' }, sendKey))
      .rejects.toMatchObject({ code: 'invalid_response' });
    await expect(decryptAccessedSend({ id: 's1', type: 0, name: 'name', text: { text: 'body', hidden: 'true' } }, sendKey))
      .rejects.toMatchObject({ code: 'invalid_response' });
  });
});

describe('sendPasswordHash', () => {
  it('derives a stable base64 hash for a password + send key', async () => {
    const a = await sendPasswordHash('pw', sendKey);
    const b = await sendPasswordHash('pw', sendKey);
    expect(a).toBe(b);
    expect(a).not.toContain('pw');
  });
});

function jsonRes(body: unknown, status = 200): Response { return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }); }
function tokenRes(body: unknown = {
  access_token: 'SEND_TOKEN',
  token_type: 'Bearer',
  expires_in: 300,
  scope: 'api.send.access',
}, status = 200): Response {
  return jsonRes(body, status);
}

function emailChallengeRes(kind: 'email_required' | 'email_and_otp_required'): Response {
  return tokenRes({
    error: 'invalid_request',
    error_description: kind === 'email_required'
      ? 'email is required.'
      : 'email and otp are required.',
    send_access_error_type: kind,
  }, 400);
}

function endpointsFor(serverUrl = 'https://vault.example'): SendAccessEndpoints {
  return parseSendUrl(`${serverUrl}/#/send/fixture/${bytesToBase64Url(sendKey)}`).endpoints;
}

function requireAccessed(result: SendAccessResult): AccessedSendResult {
  if (result.kind !== 'accessed') throw new Error(`Expected accessed, got ${result.kind}`);
  return result;
}

async function emailProofFor(endpoints = endpointsFor(), accessId = 'acc1'): Promise<SendEmailAuthProof> {
  const fetchFn = (async () => emailChallengeRes('email_required')) as typeof fetch;
  const result = await accessSend(fetchFn, endpoints, accessId, { kind: 'none' });
  if (result.kind !== 'email_required') throw new Error(`Expected email_required, got ${result.kind}`);
  return result.proof;
}

function bearerAuthorization(endpoints = endpointsFor()): SendAccessAuthorization {
  return Object.freeze({
    kind: 'bearer',
    endpointBinding: endpoints.binding,
    token: 'SEND_TOKEN',
    expiresAt: Date.now() + 60_000,
  });
}

describe('accessSend', () => {
  it('exchanges the access id for a scoped token before fetching the Send', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchFn = (async (u: string, init: RequestInit) => {
      calls.push([String(u), init]);
      return calls.length === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as unknown as typeof fetch;
    const res = requireAccessed(await accessSend(
      fetchFn,
      endpointsFor(),
      'acc1',
      { kind: 'password', passwordHashB64: 'HASH' },
    ));

    expect(calls.map(([url]) => url)).toEqual([
      'https://vault.example/identity/connect/token',
      'https://vault.example/api/sends/access',
    ]);
    expect(Object.fromEntries(new URLSearchParams(calls[0]![1].body as string))).toEqual({
      grant_type: 'send_access',
      client_id: 'send',
      scope: 'api.send.access',
      send_id: 'acc1',
      password_hash_b64: 'HASH',
    });
    expect(new Headers(calls[1]![1].headers).get('authorization')).toBe('Bearer SEND_TOKEN');
    expect(calls[1]![1].body).toBeUndefined();
    expect(res.payload).toMatchObject({ id: 'send-1' });
    expect(res.authorization).toMatchObject({
      kind: 'bearer',
      endpointBinding: endpointsFor().binding,
      token: 'SEND_TOKEN',
    });
  });
  it('keeps API routes inside a normalized self-hosted base path', async () => {
    const seen: string[] = [];
    const fetchFn = (async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return seen.length === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as typeof fetch;

    await accessSend(fetchFn, endpointsFor('http://192.168.1.10/vault'), 'acc1', { kind: 'none' });

    expect(seen).toEqual([
      'http://192.168.1.10/vault/identity/connect/token',
      'http://192.168.1.10/vault/api/sends/access',
    ]);
  });
  it('maps modern grant password errors to password_required', async () => {
    const fetchFn = (async () => tokenRes({
      error: 'invalid_request',
      send_access_error_type: 'password_hash_b64_required',
    }, 400)) as unknown as typeof fetch;
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'password_required' });
  });
  it('treats an exact anonymous email_required response as the positive Email OTP capability proof', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => emailChallengeRes('email_required'));
    const fetchFn = fetchMock as unknown as typeof fetch;

    const result = await accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' });
    expect(result).toMatchObject({
      kind: 'email_required',
      endpointBinding: endpointsFor().binding,
    });
    const form = new URLSearchParams(fetchMock.mock.calls[0]?.[1]?.body as string);
    expect(form.has('email')).toBe(false);
    expect(form.has('otp')).toBe(false);
  });
  it('accepts the official optional error_description field without trusting its prose', async () => {
    const fetchFn = (async () => tokenRes({
      error: 'invalid_request',
      send_access_error_type: 'email_required',
    }, 400)) as typeof fetch;
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }))
      .resolves.toMatchObject({ kind: 'email_required' });
  });
  it('sends a normalized email only after capability proof and parses the OTP challenge', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => emailChallengeRes('email_and_otp_required'));
    const fetchFn = fetchMock as unknown as typeof fetch;
    const proof = await emailProofFor();

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', {
      kind: 'email',
      email: ' Recipient@Example.COM ',
      proof,
    })).resolves.toMatchObject({
      kind: 'email_otp_required',
      endpointBinding: endpointsFor().binding,
    });
    expect(Object.fromEntries(new URLSearchParams(fetchMock.mock.calls[0]?.[1]?.body as string))).toMatchObject({
      send_id: 'acc1',
      email: 'recipient@example.com',
    });
    expect(new URLSearchParams(fetchMock.mock.calls[0]?.[1]?.body as string).has('otp')).toBe(false);
  });
  it('sends email and opaque OTP together and accepts a scoped token only at that stage', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const proof = await emailProofFor();
    const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(input), init ?? {}]);
      return calls.length === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as typeof fetch;

    const result = requireAccessed(await accessSend(fetchFn, endpointsFor(), 'acc1', {
      kind: 'email_otp',
      email: 'recipient@example.com',
      otp: ' 001234 ',
      proof,
    }));
    expect(Object.fromEntries(new URLSearchParams(calls[0]![1].body as string))).toMatchObject({
      email: 'recipient@example.com',
      otp: '001234',
    });
    expect(result.authorization.kind).toBe('bearer');
    const replayFetch = vi.fn() as unknown as typeof fetch;
    await expect(accessSend(replayFetch, endpointsFor(), 'acc1', {
      kind: 'email', email: 'recipient@example.com', proof,
    })).rejects.toMatchObject({ code: 'email_auth_unsupported' });
    expect(replayFetch).not.toHaveBeenCalled();
  });
  it('returns the same OTP challenge for a non-recipient email and an invalid OTP', async () => {
    const fetchFn = (async () => emailChallengeRes('email_and_otp_required')) as typeof fetch;
    const proof = await emailProofFor();
    const emailOnly = await accessSend(fetchFn, endpointsFor(), 'acc1', {
      kind: 'email', email: 'nobody@example.com', proof,
    });
    const wrongOtp = await accessSend(fetchFn, endpointsFor(), 'acc1', {
      kind: 'email_otp', email: 'recipient@example.com', otp: 'wrong', proof,
    });
    expect(emailOnly).toEqual(wrongOtp);
  });
  it.each([
    [{ error: 'invalid_request', error_description: 42, send_access_error_type: 'email_required' }, 400],
    [{ error: 'invalid_request', error_description: 'bad\nvalue', send_access_error_type: 'email_required' }, 400],
    [{ error: 'invalid_grant', error_description: 'email is required.', send_access_error_type: 'email_required' }, 400],
    [{ error: 'invalid_request', error_description: 'email is required.', send_access_error_type: 'email_required' }, 401],
  ] as const)('fails closed on a malformed or pseudo Email challenge %#', async (body, status) => {
    const fetchFn = vi.fn(async () => tokenRes(body, status)) as unknown as typeof fetch;
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'email_auth_unsupported' });
    expect(fetchFn).toHaveBeenCalledOnce();
  });
  it('rejects an out-of-order OTP challenge and never sends Email credentials to a legacy server', async () => {
    const outOfOrder = vi.fn(async () => emailChallengeRes('email_and_otp_required')) as unknown as typeof fetch;
    await expect(accessSend(outOfOrder, endpointsFor(), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'email_auth_unsupported' });

    const legacy = vi.fn(async () => tokenRes({ error: 'unsupported_grant_type' }, 400)) as unknown as typeof fetch;
    const proof = await emailProofFor();
    await expect(accessSend(legacy, endpointsFor(), 'acc1', {
      kind: 'email', email: 'recipient@example.com', proof,
    }))
      .rejects.toMatchObject({ code: 'email_auth_unsupported' });
    expect(legacy).toHaveBeenCalledOnce();
  });
  it('refuses Email capability over cleartext except for loopback development servers', async () => {
    const fetchFn = (async () => emailChallengeRes('email_required')) as typeof fetch;
    await expect(accessSend(fetchFn, endpointsFor('http://192.168.1.10'), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'email_auth_unsupported' });
    await expect(accessSend(fetchFn, endpointsFor('http://127.0.0.1:8080'), 'acc1', { kind: 'none' }))
      .resolves.toMatchObject({ kind: 'email_required' });
  });
  it('refuses password credentials over cleartext except for loopback development servers', async () => {
    const blocked = vi.fn() as unknown as typeof fetch;
    await expect(accessSend(blocked, endpointsFor('http://192.168.1.10'), 'acc1', {
      kind: 'password', passwordHashB64: 'HASH',
    })).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(blocked).not.toHaveBeenCalled();

    let calls = 0;
    const loopback = (async () => {
      calls += 1;
      return calls === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as unknown as typeof fetch;
    await expect(accessSend(loopback, endpointsFor('http://127.0.0.1:8080'), 'acc1', {
      kind: 'password', passwordHashB64: 'HASH',
    })).resolves.toMatchObject({ kind: 'accessed' });
  });
  it('rejects malformed Email and OTP inputs before a network request', async () => {
    const fetchFn = vi.fn() as unknown as typeof fetch;
    const proof = await emailProofFor();
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'email', email: 'not-an-email', proof }))
      .rejects.toMatchObject({ code: 'invalid_credentials' });
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', {
      kind: 'email_otp', email: 'recipient@example.com', otp: '   ', proof,
    })).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(fetchFn).not.toHaveBeenCalled();
  });
  it('enforces bounded credentials while keeping OTP format opaque', async () => {
    const endpoints = endpointsFor();
    const emailProof = await emailProofFor(endpoints);
    const emailFetch = vi.fn(async () => emailChallengeRes('email_and_otp_required')) as unknown as typeof fetch;
    const emailAtLimit = `${'a'.repeat(242)}@example.com`;
    await expect(accessSend(emailFetch, endpoints, 'acc1', {
      kind: 'email', email: emailAtLimit, proof: emailProof,
    })).resolves.toMatchObject({ kind: 'email_otp_required' });
    await expect(accessSend(emailFetch, endpoints, 'acc1', {
      kind: 'email', email: `${'a'.repeat(243)}@example.com`, proof: emailProof,
    })).rejects.toMatchObject({ code: 'invalid_credentials' });

    const otpProof = await emailProofFor(endpoints);
    const otpCalls: string[] = [];
    const otpFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      otpCalls.push(String(init?.body ?? ''));
      return otpCalls.length === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as typeof fetch;
    await expect(accessSend(otpFetch, endpoints, 'acc1', {
      kind: 'email_otp', email: 'recipient@example.com', otp: 'x'.repeat(256), proof: otpProof,
    })).resolves.toMatchObject({ kind: 'accessed' });

    const tooLongProof = await emailProofFor(endpoints);
    const noFetch = vi.fn() as unknown as typeof fetch;
    await expect(accessSend(noFetch, endpoints, 'acc1', {
      kind: 'email_otp', email: 'recipient@example.com', otp: 'x'.repeat(257), proof: tooLongProof,
    })).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(noFetch).not.toHaveBeenCalled();
  });
  it('binds the opaque Email proof to the exact endpoint set and access id', async () => {
    const proof = await emailProofFor(endpointsFor(), 'acc1');
    const fetchFn = vi.fn() as unknown as typeof fetch;
    await expect(accessSend(fetchFn, endpointsFor(), 'other', {
      kind: 'email', email: 'recipient@example.com', proof,
    })).rejects.toMatchObject({ code: 'email_auth_unsupported' });
    await expect(accessSend(fetchFn, endpointsFor('https://other.example'), 'acc1', {
      kind: 'email', email: 'recipient@example.com', proof,
    })).rejects.toMatchObject({ code: 'email_auth_unsupported' });
    const forged = {
      endpointBinding: endpointsFor().binding,
      accessId: 'acc1',
    } as unknown as SendEmailAuthProof;
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', {
      kind: 'email', email: 'recipient@example.com', proof: forged,
    })).rejects.toMatchObject({ code: 'email_auth_unsupported' });
    expect(fetchFn).not.toHaveBeenCalled();
  });
  it('routes an official Cloud token and content request only to the mapped Identity and API hosts', async () => {
    const parsed = parseSendUrl(`https://send.bitwarden.com/#cloudSend/${bytesToBase64Url(sendKey)}`);
    const seen: Array<{ url: string; body?: string }> = [];
    const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push({ url: String(input), ...(typeof init?.body === 'string' ? { body: init.body } : {}) });
      return seen.length === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as typeof fetch;

    await accessSend(fetchFn, parsed.endpoints, parsed.accessId, { kind: 'none' });

    expect(seen.map(({ url }) => url)).toEqual([
      'https://identity.bitwarden.com/connect/token',
      'https://api.bitwarden.com/sends/access',
    ]);
    expect(JSON.stringify(seen)).not.toContain(bytesToBase64Url(sendKey));
  });
  it('rejects a redirected official Cloud token response', async () => {
    const parsed = parseSendUrl(`https://send.bitwarden.com/#cloudSend/${bytesToBase64Url(sendKey)}`);
    const response = tokenRes();
    Object.defineProperties(response, {
      redirected: { value: true },
      url: { value: 'https://vault.bitwarden.com/redirected' },
    });
    const fetchFn = (async () => response) as typeof fetch;
    await expect(accessSend(fetchFn, parsed.endpoints, parsed.accessId, { kind: 'none' }))
      .rejects.toMatchObject({ code: 'server_error' });
  });
  it('maps an invalid modern Send password without attempting legacy fallback', async () => {
    const fetchFn = vi.fn(async () => tokenRes({
      error: 'invalid_grant',
      send_access_error_type: 'password_hash_b64_invalid',
    }, 404)) as unknown as typeof fetch;

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'password', passwordHashB64: 'WRONG' }))
      .rejects.toMatchObject({ code: 'password_invalid' });
    expect(fetchFn).toHaveBeenCalledOnce();
  });
  it('separates an unavailable Send from other server failures and malformed responses', async () => {
    const missing = (async () => tokenRes({
      error: 'invalid_grant',
      send_access_error_type: 'send_id_invalid',
    }, 400)) as unknown as typeof fetch;
    const failed = (async () => tokenRes({ error: 'server_error' }, 500)) as unknown as typeof fetch;
    let malformedCalls = 0;
    const malformed = (async () => {
      malformedCalls += 1;
      return malformedCalls === 1 ? tokenRes() : new Response('not json');
    }) as unknown as typeof fetch;
    await expect(accessSend(missing, endpointsFor(), 'acc1', { kind: 'none' })).rejects.toMatchObject({ code: 'unavailable' });
    await expect(accessSend(failed, endpointsFor(), 'acc1', { kind: 'none' })).rejects.toMatchObject({ code: 'server_error' });
    await expect(accessSend(malformed, endpointsFor(), 'acc1', { kind: 'none' })).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('does not downgrade a structured 404 grant rejection to the legacy protocol', async () => {
    const fetchFn = vi.fn(async () => tokenRes({
      error: 'invalid_grant',
      send_access_error_type: 'send_id_invalid',
    }, 404)) as unknown as typeof fetch;

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'unavailable' });
    expect(fetchFn).toHaveBeenCalledOnce();
  });
  it('falls back only when the server explicitly lacks the modern Send grant', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(input), init ?? {}]);
      return calls.length === 1
        ? tokenRes({ error: 'unsupported_grant_type' }, 400)
        : jsonRes({ id: 'legacy-send', type: 0 });
    }) as typeof fetch;

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'password', passwordHashB64: 'HASH' }))
      .resolves.toMatchObject({
        payload: { id: 'legacy-send' },
        authorization: {
          kind: 'legacy',
          endpointBinding: endpointsFor().binding,
          passwordHash: 'HASH',
        },
      });
    expect(calls[1]![0]).toBe('https://vault.example/api/sends/access/acc1');
    expect(JSON.parse(calls[1]![1].body as string)).toEqual({ password: 'HASH' });
  });
  it('does not downgrade client, scope, or authorization failures', async () => {
    for (const oauthError of ['invalid_client', 'unauthorized_client', 'invalid_scope']) {
      const fetchFn = vi.fn(async () => tokenRes({ error: oauthError }, 400)) as unknown as typeof fetch;
      await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }))
        .rejects.toMatchObject({ code: 'server_error' });
      expect(fetchFn).toHaveBeenCalledOnce();
    }
  });
  it.each([
    ['Invalid password', 'password_invalid'],
    ['Invalid password.', 'password_invalid'],
    ['Could not locate send', 'unavailable'],
    ['unexpected', 'server_error'],
  ] as const)('maps the legacy error %s to %s', async (message, code) => {
    let calls = 0;
    const fetchFn = (async () => {
      calls += 1;
      return calls === 1
        ? tokenRes({ error: 'unsupported_grant_type' }, 400)
        : jsonRes({ message }, 400);
    }) as unknown as typeof fetch;

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'password', passwordHashB64: 'HASH' }))
      .rejects.toMatchObject({ code });
  });
  it('classifies fetch rejection, timeout and caller cancellation', async () => {
    const failed = (async () => { throw new TypeError('offline'); }) as unknown as typeof fetch;
    await expect(accessSend(failed, endpointsFor(), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'network_failed' });

    const waitForAbort = (async (_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    })) as typeof fetch;
    await expect(accessSend(waitForAbort, endpointsFor(), 'acc1', { kind: 'none' }, { timeoutMs: 1 }))
      .rejects.toMatchObject({ code: 'timeout' });

    const controller = new AbortController();
    const cancelled = accessSend(waitForAbort, endpointsFor(), 'acc1', { kind: 'none' }, { signal: controller.signal });
    controller.abort();
    await expect(cancelled).rejects.toMatchObject({ code: 'aborted' });
  });
  it('keeps the deadline active while a response body is stalled', async () => {
    const cancel = vi.fn();
    const stalledBody = new ReadableStream<Uint8Array>({ cancel });
    const fetchFn = (async () => new Response(stalledBody)) as unknown as typeof fetch;

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }, { timeoutMs: 5 }))
      .rejects.toMatchObject({ code: 'timeout' });
    expect(cancel).toHaveBeenCalledOnce();
  });
  it('rejects a response that exceeds the configured byte limit', async () => {
    const fetchFn = (async () => new Response('{"id":"send-1"}', {
      headers: { 'content-length': '15' },
    })) as unknown as typeof fetch;
    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }, { maxResponseBytes: 8 }))
      .rejects.toMatchObject({ code: 'response_too_large' });
  });
  it('uses an anonymous, non-redirecting request policy and passes an AbortSignal', async () => {
    const seen: RequestInit[] = [];
    const fetchFn = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init ?? {});
      return seen.length === 1 ? tokenRes() : jsonRes({ id: 'send-1', type: 0 });
    }) as typeof fetch;
    await accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' });
    for (const request of seen) {
      expect(request).toMatchObject({ credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store' });
      expect(request.signal?.aborted).toBe(false);
    }
  });
  it('rejects a response whose final URL does not match the requested API URL', async () => {
    const response = tokenRes();
    Object.defineProperty(response, 'url', { value: 'https://other.example/identity/connect/token' });
    const fetchFn = (async () => response) as unknown as typeof fetch;

    await expect(accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }))
      .rejects.toMatchObject({ code: 'server_error' });
  });
});

describe('requestFileDownloadUrl', () => {
  it('reuses the access authorization for the modern file route without minting again', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchFn = (async (u: string, init: RequestInit) => {
      calls.push([String(u), init]);
      if (calls.length === 1) return tokenRes();
      if (calls.length === 2) return jsonRes({ id: 'send-1', type: 1 });
      return jsonRes({ url: 'http://abs/url?t=jwt' });
    }) as unknown as typeof fetch;
    const accessed = requireAccessed(await accessSend(
      fetchFn,
      endpointsFor(),
      'acc1',
      { kind: 'password', passwordHashB64: 'HASH' },
    ));
    const url = await requestFileDownloadUrl(
      fetchFn,
      endpointsFor(),
      'send-1',
      'f1',
      accessed.authorization,
    );
    expect(calls.map(([requestUrl]) => requestUrl)).toEqual([
      'https://vault.example/identity/connect/token',
      'https://vault.example/api/sends/access',
      'https://vault.example/api/sends/access/file/f1',
    ]);
    expect(new Headers(calls[2]![1].headers).get('authorization')).toBe('Bearer SEND_TOKEN');
    expect(calls.filter(([requestUrl]) => requestUrl.endsWith('/identity/connect/token'))).toHaveLength(1);
    expect(url).toBe('http://abs/url?t=jwt');
  });
  it('uses the legacy file route only for an explicitly unsupported grant', async () => {
    const calls: string[] = [];
    const fetchFn = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return calls.length === 1
        ? tokenRes({ error: 'unsupported_grant_type' }, 400)
        : calls.length === 2
          ? jsonRes({ id: 'legacy-send', type: 1 })
          : jsonRes({ url: 'https://vault.example/file?t=jwt' });
    }) as typeof fetch;

    const accessed = requireAccessed(await accessSend(fetchFn, endpointsFor(), 'acc1', { kind: 'none' }));
    await requestFileDownloadUrl(fetchFn, endpointsFor(), 'send-1', 'f1', accessed.authorization);
    expect(calls[2]).toBe('https://vault.example/api/sends/send-1/access/file/f1');
  });
  it('rejects a successful response without a usable URL', async () => {
    const fetchFn = (async () => jsonRes({ url: 42 })) as unknown as typeof fetch;
    await expect(requestFileDownloadUrl(
      fetchFn,
      endpointsFor(),
      'send-1',
      'f1',
      bearerAuthorization(),
    ))
      .rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('rejects a file response whose id does not match the requested file', async () => {
    const fetchFn = (async () => jsonRes({ id: 'other-file', url: 'https://vault.example/file' })) as unknown as typeof fetch;
    await expect(requestFileDownloadUrl(
      fetchFn,
      endpointsFor(),
      'send-1',
      'f1',
      bearerAuthorization(),
    )).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('never sends a bearer authorization to a different configured server', async () => {
    const fetchFn = vi.fn() as unknown as typeof fetch;
    await expect(requestFileDownloadUrl(
      fetchFn,
      endpointsFor('https://other.example'),
      'send-1',
      'f1',
      bearerAuthorization(),
    )).rejects.toMatchObject({ code: 'invalid_link' });
    expect(fetchFn).not.toHaveBeenCalled();
  });
  it('refuses a legacy password body over cleartext before requesting a file URL', async () => {
    const endpoints = endpointsFor('http://192.168.1.10');
    const fetchFn = vi.fn() as unknown as typeof fetch;
    await expect(requestFileDownloadUrl(
      fetchFn,
      endpoints,
      'send-1',
      'f1',
      Object.freeze({
        kind: 'legacy',
        endpointBinding: endpoints.binding,
        passwordHash: 'HASH',
      }),
    )).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(fetchFn).not.toHaveBeenCalled();
  });
  it('invalidates an expired or server-rejected bearer instead of retaining it', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 401 })) as unknown as typeof fetch;
    await expect(requestFileDownloadUrl(
      fetchFn,
      endpointsFor(),
      'send-1',
      'f1',
      bearerAuthorization(),
    )).rejects.toMatchObject({ code: 'authorization_rejected' });
    expect(fetchFn).toHaveBeenCalledOnce();

    const expired = Object.freeze({
      kind: 'bearer' as const,
      endpointBinding: endpointsFor().binding,
      token: 'EXPIRED',
      expiresAt: Date.now() + 5_000,
    });
    const noFetch = vi.fn() as unknown as typeof fetch;
    await expect(requestFileDownloadUrl(noFetch, endpointsFor(), 'send-1', 'f1', expired))
      .rejects.toMatchObject({ code: 'authorization_rejected' });
    expect(noFetch).not.toHaveBeenCalled();
  });
});

describe('resolveSendDownloadTarget', () => {
  it('resolves a same-origin relative URL and identifies an HTTPS cross-origin URL', () => {
    expect(resolveSendDownloadTarget('/sends/s/x?t=jwt', 'https://vault.example')).toEqual({
      url: 'https://vault.example/sends/s/x?t=jwt',
      origin: 'https://vault.example',
      originPattern: 'https://vault.example/*',
      isCrossOrigin: false,
    });
    expect(resolveSendDownloadTarget('https://cdn.example/file?t=jwt', 'https://vault.example')).toMatchObject({
      origin: 'https://cdn.example',
      originPattern: 'https://cdn.example/*',
      isCrossOrigin: true,
    });
    expect(resolveSendDownloadTarget('sends/s/x?t=jwt', 'https://vault.example/base')).toMatchObject({
      url: 'https://vault.example/base/sends/s/x?t=jwt',
      isCrossOrigin: false,
    });
    expect(resolveSendDownloadTarget('/sends/s/x?t=jwt', 'https://vault.example/base')).toMatchObject({
      url: 'https://vault.example/base/sends/s/x?t=jwt',
      isCrossOrigin: false,
    });
  });
  it('keeps same-origin downloads inside a normalized self-hosted base path', () => {
    expect(resolveSendDownloadTarget('files/s/x?t=jwt', 'https://vault.example/base//')).toMatchObject({
      url: 'https://vault.example/base/files/s/x?t=jwt',
      isCrossOrigin: false,
    });
    expect(resolveSendDownloadTarget('/files/s/x?t=jwt', 'https://vault.example/base')).toMatchObject({
      url: 'https://vault.example/base/files/s/x?t=jwt',
      isCrossOrigin: false,
    });
    expect(() => resolveSendDownloadTarget('https://vault.example/outside/file?t=jwt', 'https://vault.example/base'))
      .toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('../outside/file?t=jwt', 'https://vault.example/base'))
      .toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('files/%2e%2e%2fadmin?t=jwt', 'https://vault.example/base'))
      .toThrowError(/unsafe_download/);
  });
  it('rejects unsupported schemes, credentials, fragments and malformed absolute URLs', () => {
    expect(() => resolveSendDownloadTarget('data:text/plain,nope', 'https://vault.example')).toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('https://user:pass@cdn.example/file', 'https://vault.example')).toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('https://cdn.example/file#fragment', 'https://vault.example')).toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('//cdn.example/file', 'https://vault.example')).toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('https:/cdn.example/file', 'https://vault.example')).toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget(' https://cdn.example/file', 'https://vault.example')).toThrowError(/unsafe_download/);
    expect(() => resolveSendDownloadTarget('http://cdn.example/file', 'https://vault.example')).toThrowError(/unsafe_download/);
  });
  it('preserves explicitly authorized HTTP self-hosting targets', () => {
    expect(resolveSendDownloadTarget('http://localhost:8081/file?t=jwt', 'http://localhost:8080')).toMatchObject({
      origin: 'http://localhost:8081',
      originPattern: 'http://localhost:8081/*',
      isCrossOrigin: true,
    });
    expect(resolveSendDownloadTarget('http://192.168.1.10/file', 'http://localhost:8080')).toMatchObject({
      origin: 'http://192.168.1.10',
      originPattern: 'http://192.168.1.10/*',
      isCrossOrigin: true,
    });
    expect(() => resolveSendDownloadTarget('http://192.168.1.10/file', 'https://vault.example'))
      .toThrowError(/unsafe_download/);
  });
});

describe('downloadAndDecryptFile', () => {
  it('GETs the absolute url and decrypts the EncArrayBuffer with the send key', async () => {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([9, 8, 7]), derived);
    let seenInit: RequestInit | undefined;
    const fetchFn = (async (u: RequestInfo | URL, init?: RequestInit) => {
      expect(String(u)).toBe('https://vault.example/file?t=jwt');
      seenInit = init;
      return new Response(Buffer.from(blob));
    }) as typeof fetch;
    const back = await downloadAndDecryptFile(fetchFn, 'https://vault.example/file?t=jwt', 'https://vault.example', sendKey);
    expect(Array.from(back)).toEqual([9, 8, 7]);
    expect(seenInit).toMatchObject({ method: 'GET', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store' });
  });
  it('throws decrypt_failed on a corrupt blob', async () => {
    const fetchFn = (async () => new Response(Buffer.from(new Uint8Array([2, 0, 0])))) as unknown as typeof fetch;
    await expect(downloadAndDecryptFile(fetchFn, 'https://vault.example/x', 'https://vault.example', sendKey)).rejects.toMatchObject({ code: 'decrypt_failed' });
  });
  it('resolves a relative download url against the server URL', async () => {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([1]), derived);
    let seen = '';
    const fetchFn = (async (u: string) => { seen = String(u); return new Response(Buffer.from(blob)); }) as unknown as typeof fetch;
    await downloadAndDecryptFile(fetchFn, '/sends/s/x?t=jwt', 'https://vault.example', sendKey);
    expect(seen).toBe('https://vault.example/sends/s/x?t=jwt');
  });
  it('requires an exact authorization for a cross-origin URL', async () => {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([1]), derived);
    const fetchFn = (async () => new Response(Buffer.from(blob))) as unknown as typeof fetch;
    await expect(downloadAndDecryptFile(fetchFn, 'https://cdn.example/x', 'https://vault.example', sendKey))
      .rejects.toMatchObject({ code: 'unsafe_download' });
    await expect(downloadAndDecryptFile(fetchFn, 'https://cdn.example/x', 'https://vault.example', sendKey, {
      allowedCrossOrigin: 'https://other.example',
    })).rejects.toMatchObject({ code: 'unsafe_download' });
    const result = await downloadAndDecryptFile(fetchFn, 'https://cdn.example/x', 'https://vault.example', sendKey, {
      allowedCrossOrigin: 'https://cdn.example',
    });
    expect(Array.from(result)).toEqual([1]);
  });
  it('enforces the encrypted file response limit before decrypting', async () => {
    const fetchFn = (async () => new Response(Buffer.from(new Uint8Array([1, 2, 3, 4])), {
      headers: { 'content-length': '4' },
    })) as unknown as typeof fetch;
    await expect(downloadAndDecryptFile(fetchFn, '/file', 'https://vault.example', sendKey, { maxResponseBytes: 3 }))
      .rejects.toMatchObject({ code: 'response_too_large' });
  });
  it('enforces the response limit when Content-Length is absent or inaccurate', async () => {
    const fetchFn = (async () => new Response(Buffer.from(new Uint8Array([1, 2, 3, 4])))) as unknown as typeof fetch;
    await expect(downloadAndDecryptFile(fetchFn, '/file', 'https://vault.example', sendKey, { maxResponseBytes: 3 }))
      .rejects.toMatchObject({ code: 'response_too_large' });
  });
  it('rejects a redirected or mismatched final download target', async () => {
    const response = new Response(Buffer.from(new Uint8Array([1])));
    Object.defineProperties(response, {
      redirected: { value: true },
      url: { value: 'https://cdn.example/redirected' },
    });
    const fetchFn = (async () => response) as unknown as typeof fetch;

    await expect(downloadAndDecryptFile(fetchFn, 'https://vault.example/file', 'https://vault.example', sendKey))
      .rejects.toMatchObject({ code: 'unsafe_download' });
  });
});

