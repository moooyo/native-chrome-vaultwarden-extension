import { describe, expect, it } from 'vitest';

import {
  duoConnectorUrl,
  parseDuoAuthorization,
  parseDuoCallback,
} from './duo-two-factor.js';
import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';

const VAULT = 'https://vault.example/base/';
const REDIRECT = 'https://vault.example/base/duo-redirect-connector.html?client=browser';
const STATE = 'server-protected-state';
const AUTH_URL = 'https://api-example.duosecurity.com/oauth/v1/authorize'
  + `?response_type=code&client_id=client-id&redirect_uri=${encodeURIComponent(REDIRECT)}`
  + `&state=${STATE}&scope=openid`;

describe('Duo Universal Prompt protocol', () => {
  it.each([2, 6] as const)('parses modern provider %s metadata against the trusted connector', (provider) => {
    expect(parseDuoAuthorization({
      [provider]: { Host: 'api-example.duosecurity.com', AuthUrl: AUTH_URL },
    }, provider, VAULT)).toEqual({
      provider,
      authUrl: AUTH_URL,
      duoHost: 'api-example.duosecurity.com',
      redirectUri: REDIRECT,
      state: STATE,
    });
  });

  it('parses the Vaultwarden request-JWT shape without legacy Host metadata', () => {
    const payload = bytesToBase64Url(utf8ToBytes(JSON.stringify({
      response_type: 'code',
      client_id: 'client-id',
      iss: 'client-id',
      aud: 'https://api-example.duosecurity.com',
      exp: 2_000_000_000,
      state: STATE,
      redirect_uri: REDIRECT,
    })));
    const request = `eyJhbGciOiJIUzUxMiJ9.${payload}.c2lnbmF0dXJl`;
    const authUrl = 'https://api-example.duosecurity.com/oauth/v1/authorize'
      + `?response_type=code&client_id=client-id&request=${request}`;

    expect(parseDuoAuthorization({ 2: { AuthUrl: authUrl } }, 2, VAULT)).toMatchObject({
      authUrl,
      duoHost: 'api-example.duosecurity.com',
      redirectUri: REDIRECT,
      state: STATE,
    });
  });

  it('parses the official DuoUniversal C# request JWT wire shape', () => {
    const payload = bytesToBase64Url(utf8ToBytes(JSON.stringify({
      iss: 'client-id',
      aud: 'https://api-example.duosecurity.com/oauth/v1/authorize',
      exp: '2000000000',
      client_id: 'client-id',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      state: STATE,
      duo_uname: 'user@example.com',
    })));
    const request = `eyJhbGciOiJIUzUxMiJ9.${payload}.c2lnbmF0dXJl`;
    const authUrl = 'https://api-example.duosecurity.com/oauth/v1/authorize'
      + `?response_type=code&client_id=client-id&request=${request}`;

    expect(parseDuoAuthorization({ 6: { AuthUrl: authUrl } }, 6, VAULT)).toMatchObject({
      authUrl,
      redirectUri: REDIRECT,
      state: STATE,
    });
  });

  it.each(['02000000000', '+2000000000', '2e9', '9007199254740992', '', 1.5])(
    'rejects a non-canonical request JWT expiration %j',
    (exp) => {
      const payload = bytesToBase64Url(utf8ToBytes(JSON.stringify({
        response_type: 'code',
        client_id: 'client-id',
        iss: 'client-id',
        aud: 'https://api-example.duosecurity.com',
        exp,
        state: STATE,
        redirect_uri: REDIRECT,
      })));
      const request = `eyJhbGciOiJIUzUxMiJ9.${payload}.c2lnbmF0dXJl`;
      const authUrl = 'https://api-example.duosecurity.com/oauth/v1/authorize'
        + `?response_type=code&client_id=client-id&request=${request}`;
      expect(() => parseDuoAuthorization({ 2: { AuthUrl: authUrl } }, 2, VAULT)).toThrow();
    },
  );

  it('rejects non-Duo hosts, connector injection, duplicates, and legacy-only metadata', () => {
    for (const data of [
      { 2: { Host: 'evil.example', AuthUrl: AUTH_URL.replace('api-example.duosecurity.com', 'evil.example') } },
      { 2: { Host: 'api-example.duosecurity.com', AuthUrl: AUTH_URL.replace('vault.example', 'evil.example') } },
      { 2: { Host: 'api-example.duosecurity.com', AuthUrl: `${AUTH_URL}&state=duplicate` } },
      { 2: { Host: 'api-example.duosecurity.com', Signature: 'legacy' } },
    ]) {
      expect(() => parseDuoAuthorization(data, 2, VAULT)).toThrow();
    }
  });

  it('accepts one exact callback, scrubs it, and composes code|state', () => {
    const authorization = parseDuoAuthorization({
      2: { Host: 'api-example.duosecurity.com', AuthUrl: AUTH_URL },
    }, 2, VAULT);
    const callback = `${REDIRECT}&code=authorization-code&state=${STATE}`;

    expect(parseDuoCallback(callback, authorization)).toEqual({
      code: 'authorization-code',
      state: STATE,
      token: `authorization-code|${STATE}`,
      scrubbedUrl: REDIRECT,
    });
  });

  it('rejects callback state, connector, duplicate, extra, and token-delimiter confusion', () => {
    const authorization = parseDuoAuthorization({
      6: { Host: 'api-example.duosecurity.com', AuthUrl: AUTH_URL },
    }, 6, VAULT);
    for (const callback of [
      `${REDIRECT}&code=code&state=wrong`,
      `https://evil.example/duo-redirect-connector.html?client=browser&code=code&state=${STATE}`,
      `${REDIRECT}&code=one&code=two&state=${STATE}`,
      `${REDIRECT}&code=code&state=${STATE}&extra=value`,
      `${REDIRECT}&code=bad%7Ccode&state=${STATE}`,
    ]) {
      expect(() => parseDuoCallback(callback, authorization)).toThrow();
    }
  });

  it('builds the browser connector only from a trusted Web Vault base', () => {
    expect(duoConnectorUrl(VAULT)).toBe(REDIRECT);
    expect(() => duoConnectorUrl('javascript:alert(1)')).toThrow();
  });
});
