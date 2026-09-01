import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import {
  parseAccountPasskeyAssertionOptions,
  parseAccountPasskeyLoginSuccess,
  parseAndBindAccountPasskeyConnectorResult,
  serializeAccountPasskeyAssertion,
  type AccountPasskeyAssertionOptions,
} from './account-passkey.js';
import { ApiClient, ApiResponseTooLargeError } from './client.js';
import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import { createMemoryStore } from '../../platform/store.js';
import {
  KDF_VECTOR_600K,
  ORG_KEY_VECTOR,
  RSA_PRIVATE_KEY_VECTOR,
  USER_KEY_VECTOR_600K,
} from '../../../test/vectors.js';

const ACCOUNT_ID = '11111111-1111-4111-8111-111111111111';
const CREDENTIAL_ID = bytesToBase64Url(new Uint8Array(32).fill(7));

function assertionOptions(overrides: Record<string, unknown> = {}) {
  return {
    options: {
      challenge: '6CG3jqMCVASJVXySMi9KWw',
      timeout: 60_000,
      rpId: '127.0.0.1',
      allowCredentials: [],
      userVerification: 'required',
      status: 'ok',
      errorMessage: '',
      ...overrides,
    },
    token: 'BWWebAuthnLoginAssertionOptions_CfDJ8_fixture',
    object: 'webAuthnLoginAssertionOptions',
  };
}

function jwt(email = KDF_VECTOR_600K.email): string {
  return [
    bytesToBase64Url(utf8ToBytes(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))),
    bytesToBase64Url(utf8ToBytes(JSON.stringify({ sub: ACCOUNT_ID, email }))),
    bytesToBase64Url(new Uint8Array(32).fill(9)),
  ].join('.');
}

function loginResponse(overrides: Record<string, unknown> = {}) {
  return {
    access_token: jwt(),
    expires_in: 3_600,
    refresh_token: 'refresh-secret',
    token_type: 'Bearer',
    Key: USER_KEY_VECTOR_600K.akey,
    PrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
    Kdf: 0,
    KdfIterations: KDF_VECTOR_600K.iterations,
    ...overrides,
  };
}

async function connectorResult(options: AccountPasskeyAssertionOptions, origin: string) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(new Uint8Array(
    await crypto.subtle.digest('SHA-256', utf8ToBytes(options.options.rpId) as BufferSource),
  ));
  authenticatorData[32] = 0x05;
  return {
    assertion: {
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key',
      extensions: {},
      response: {
        authenticatorData: bytesToBase64Url(authenticatorData),
        signature: bytesToBase64Url(new Uint8Array(64).fill(3)),
        clientDataJSON: bytesToBase64Url(utf8ToBytes(JSON.stringify({
          type: 'webauthn.get',
          challenge: options.options.challenge,
          origin,
          crossOrigin: false,
        }))),
        userHandle: bytesToBase64Url(new Uint8Array(16).fill(4)),
      },
    },
    prfOutput: Array.from(new Uint8Array(32).fill(5)),
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('account passkey protocol', () => {
  it('parses the official assertion-options fixture into a bounded frozen projection', () => {
    const parsed = parseAccountPasskeyAssertionOptions(assertionOptions({
      allowCredentials: [{ id: CREDENTIAL_ID, type: 'public-key', transports: ['usb', 'hybrid'] }],
    }));

    expect(parsed).toEqual({
      options: {
        challenge: '6CG3jqMCVASJVXySMi9KWw',
        timeout: 60_000,
        rpId: '127.0.0.1',
        allowCredentials: [{
          id: CREDENTIAL_ID,
          type: 'public-key',
          transports: ['usb', 'hybrid'],
        }],
        userVerification: 'required',
      },
      token: 'BWWebAuthnLoginAssertionOptions_CfDJ8_fixture',
    });
    expect(Object.isFrozen(parsed.options.allowCredentials)).toBe(true);
  });

  it.each([
    ['padded challenge', { challenge: '6CG3jqMCVASJVXySMi9KWw==' }],
    ['URL in rpId', { rpId: 'https://127.0.0.1' }],
    ['unknown UV', { userVerification: 'sometimes' }],
    ['unbounded timeout', { timeout: 60 * 60 * 1000 }],
    ['server PRF injection', { extensions: { prf: { eval: { first: 'secret' } } } }],
  ])('rejects %s in assertion options', (_name, override) => {
    expect(() => parseAccountPasskeyAssertionOptions(assertionOptions(override))).toThrow();
  });

  it('rejects excessive and duplicate allowCredentials collections', () => {
    expect(() => parseAccountPasskeyAssertionOptions(assertionOptions({
      allowCredentials: Array.from({ length: 129 }, () => ({
        id: CREDENTIAL_ID,
        type: 'public-key',
      })),
    }))).toThrow(/allowCredentials/u);
    expect(() => parseAccountPasskeyAssertionOptions(assertionOptions({
      allowCredentials: [
        { id: CREDENTIAL_ID, type: 'public-key' },
        { id: CREDENTIAL_ID, type: 'public-key' },
      ],
    }))).toThrow(/duplicate/u);
  });

  it('binds challenge, origin, RP hash, presence and required verification before redemption', async () => {
    const options = parseAccountPasskeyAssertionOptions(assertionOptions());
    const result = await connectorResult(options, 'http://127.0.0.1:18082');
    const parsed = await parseAndBindAccountPasskeyConnectorResult(
      result,
      options.options,
      'http://127.0.0.1:18082',
    );
    expect(parsed.assertion.id).toBe(CREDENTIAL_ID);
    expect(parsed.prfOutput).toEqual(new Uint8Array(32).fill(5));
    expect(result.prfOutput).toEqual(new Array(32).fill(0));

    await expect(parseAndBindAccountPasskeyConnectorResult(
      await connectorResult(options, 'http://127.0.0.1:18082'),
      options.options,
      'http://localhost:18082',
    )).rejects.toThrow(/origin/u);
    await expect(parseAndBindAccountPasskeyConnectorResult(
      await connectorResult(options, 'http://127.0.0.1:18082'),
      { ...options.options, rpId: 'localhost' },
      'http://127.0.0.1:18082',
    )).rejects.toThrow(/RP ID hash/u);
  });

  it('rejects all-zero PRF results before redemption and overwrites the cloned source', async () => {
    const options = parseAccountPasskeyAssertionOptions(assertionOptions());
    const result = await connectorResult(options, 'http://127.0.0.1:18082');
    result.prfOutput.fill(0);

    await expect(parseAndBindAccountPasskeyConnectorResult(
      result,
      options.options,
      'http://127.0.0.1:18082',
    )).rejects.toThrow(/PRF output/u);
    expect(result.prfOutput).toEqual(new Array(32).fill(0));
  });

  it('rejects non-byte PRF arrays and still overwrites their contents', async () => {
    const options = parseAccountPasskeyAssertionOptions(assertionOptions());
    const result = await connectorResult(options, 'http://127.0.0.1:18082');
    result.prfOutput[4] = 256;

    await expect(parseAndBindAccountPasskeyConnectorResult(
      result,
      options.options,
      'http://127.0.0.1:18082',
    )).rejects.toThrow(/PRF output/u);
    expect(result.prfOutput).toEqual(new Array(32).fill(0));
  });

  it('serializes only the official assertion fields and never PRF output', async () => {
    const options = parseAccountPasskeyAssertionOptions(assertionOptions());
    const connector = await connectorResult(options, 'http://127.0.0.1:18082');
    const parsed = await parseAndBindAccountPasskeyConnectorResult(
      connector,
      options.options,
      'http://127.0.0.1:18082',
    );
    const wire = serializeAccountPasskeyAssertion(parsed.assertion);
    expect(JSON.parse(wire)).toEqual(parsed.assertion);
    expect(wire).not.toContain('prf');
    expect(wire).not.toContain('prfOutput');
  });
});

describe('account passkey token response', () => {
  it('inherits token KDF costs when the current master-password unlock DTO carries only KdfType', () => {
    const parsed = parseAccountPasskeyLoginSuccess(loginResponse({
      UserDecryptionOptions: {
        HasMasterPassword: true,
        MasterPasswordUnlock: {
          Salt: KDF_VECTOR_600K.email,
          Kdf: { KdfType: 0 },
          MasterKeyEncryptedUserKey: USER_KEY_VECTOR_600K.akey,
        },
      },
    }));

    expect(parsed.kdf).toEqual({ kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations });
    expect(parsed.protectedKey).toBe(USER_KEY_VECTOR_600K.akey);
  });

  it('rejects a partial master-password unlock KDF that conflicts with the token KDF', () => {
    expect(() => parseAccountPasskeyLoginSuccess(loginResponse({
      UserDecryptionOptions: {
        HasMasterPassword: true,
        MasterPasswordUnlock: {
          Salt: KDF_VECTOR_600K.email,
          Kdf: { KdfType: 1 },
          MasterKeyEncryptedUserKey: USER_KEY_VECTOR_600K.akey,
        },
      },
    }))).toThrow(/KDF|conflict/u);
  });

  it('takes account identity only from strict access-token claims and preserves locked-unlock data', () => {
    const parsed = parseAccountPasskeyLoginSuccess(loginResponse({
      UserDecryptionOptions: {
        HasMasterPassword: true,
        WebAuthnPrfOption: {
          EncryptedPrivateKey: USER_KEY_VECTOR_600K.akey,
          EncryptedUserKey: ORG_KEY_VECTOR.encOrgKey,
          CredentialId: CREDENTIAL_ID,
          Transports: ['internal'],
        },
      },
    }));

    expect(parsed).toMatchObject({
      accountIdentity: KDF_VECTOR_600K.email,
      accountId: ACCOUNT_ID,
      protectedKey: USER_KEY_VECTOR_600K.akey,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      kdf: { kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations },
      webAuthnPrfOption: {
        credentialId: CREDENTIAL_ID,
        transports: ['internal'],
      },
    });
  });

  it.each([
    ['opaque token', { access_token: 'opaque-token' }],
    ['missing trusted email', { access_token: jwt('') }],
    ['invalid protected key', { Key: '2.not-an-enc-string' }],
    ['missing encrypted private key', { PrivateKey: undefined }],
    ['missing KDF type', { Kdf: undefined }],
    ['unsupported KDF', { Kdf: 9 }],
    ['wrong token type', { token_type: 'MAC' }],
  ])('rejects %s', (_name, override) => {
    expect(() => parseAccountPasskeyLoginSuccess(loginResponse(override))).toThrow();
  });
});

describe('ApiClient account passkey endpoints', () => {
  it('uses fixed Identity options and token endpoints with the exact official form', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const options = parseAccountPasskeyAssertionOptions(assertionOptions());
    const connector = await connectorResult(options, 'http://127.0.0.1:18082');
    const parsed = await parseAndBindAccountPasskeyConnectorResult(
      connector,
      options.options,
      'http://127.0.0.1:18082',
    );
    const fetchFn = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => (
      String(input).endsWith('/assertion-options')
        ? jsonResponse(assertionOptions())
        : jsonResponse(loginResponse())
    ));
    const api = new ApiClient({
      serverUrlProvider: async () => 'http://127.0.0.1:18082/',
      fetchFn,
      localStore: store,
    });

    await expect(api.getAccountPasskeyAssertionOptions()).resolves.toEqual(options);
    await expect(api.accountPasskeyLogin({
      token: options.token,
      assertion: parsed.assertion,
    })).resolves.toMatchObject({ kind: 'success' });

    expect(fetchFn.mock.calls[0]?.[0]).toBe(
      'http://127.0.0.1:18082/identity/accounts/webauthn/assertion-options',
    );
    const optionsInit = fetchFn.mock.calls[0]![1]!;
    expect(optionsInit).toMatchObject({ method: 'GET', cache: 'no-store', credentials: 'omit' });
    const [tokenUrl, tokenInit] = fetchFn.mock.calls[1] as unknown as [string, RequestInit];
    expect(tokenUrl).toBe('http://127.0.0.1:18082/identity/connect/token');
    expect(tokenInit).toMatchObject({ method: 'POST', cache: 'no-store', credentials: 'omit' });
    const form = new URLSearchParams(tokenInit.body as string);
    expect(Object.fromEntries(form)).toMatchObject({
      client_id: 'browser',
      deviceType: '2',
      deviceIdentifier: 'device-123',
      deviceName: 'chrome',
      grant_type: 'webauthn',
      scope: 'api offline_access',
      token: options.token,
    });
    expect(JSON.parse(form.get('deviceResponse')!)).toEqual(parsed.assertion);
    expect(form.get('deviceResponse')).not.toContain('prf');
  });

  it('surfaces two-factor as explicitly unsupported without replaying the assertion', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const options = parseAccountPasskeyAssertionOptions(assertionOptions());
    const connector = await connectorResult(options, 'https://vault.example');
    const parsed = await parseAndBindAccountPasskeyConnectorResult(
      connector,
      options.options,
      'https://vault.example',
    );
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two factor required.',
      TwoFactorProviders: ['0', '7'],
    }, 400));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vault.example', fetchFn, localStore: store,
    });

    await expect(api.accountPasskeyLogin({
      token: options.token,
      assertion: parsed.assertion,
    })).resolves.toEqual({ kind: 'twoFactorUnsupported', providers: [0, 7] });
    expect(fetchFn).toHaveBeenCalledOnce();
  });

  it('bounds the anonymous options response before parsing', async () => {
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vault.example',
      fetchFn: async () => new Response('x', {
        status: 200,
        headers: { 'content-length': String(512 * 1024 + 1) },
      }),
      localStore: createMemoryStore(),
    });
    await expect(api.getAccountPasskeyAssertionOptions()).rejects.toBeInstanceOf(
      ApiResponseTooLargeError,
    );
  });
});
