import { describe, expect, it } from 'vitest';

import {
  SSO_BROWSER_STATE_SUFFIX,
  buildSsoLoginUrls,
  deriveSsoPkceS256Challenge,
  generateSsoPkceVerifier,
  generateSsoState,
  normalizeSsoEmail,
  parseSsoCallbackUrl,
  parseSsoPkceVerifier,
  parseSsoState,
  scrubSsoCallbackUrl,
} from './sso-login.js';

const STATE = `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA${SSO_BROWSER_STATE_SUFFIX}`;
const CHALLENGE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

describe('SSO login primitives', () => {
  it('normalizes a bounded ASCII email and rejects ambiguous addresses', () => {
    expect(normalizeSsoEmail('  User.Name+SSO@Example.COM  '))
      .toBe('user.name+sso@example.com');

    for (const invalid of [
      'missing-at.example.com',
      'two@@example.com',
      '.user@example.com',
      'user..name@example.com',
      'user@-example.com',
      'user@example..com',
      'usér@example.com',
      `user@${'a'.repeat(64)}.com`,
    ]) expect(() => normalizeSsoEmail(invalid)).toThrow(/email/u);
  });

  it('generates canonical 256-bit verifier and browser-marked state values', () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, index) => index);
    const random = (length: number): Uint8Array => {
      expect(length).toBe(32);
      return bytes;
    };

    const verifier = generateSsoPkceVerifier(random);
    const state = generateSsoState(random);

    expect(verifier).toBe('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
    expect(state).toBe(`${verifier}${SSO_BROWSER_STATE_SUFFIX}`);
    expect(parseSsoPkceVerifier(verifier)).toBe(verifier);
    expect(parseSsoState(state)).toBe(state);
  });

  it('derives the RFC 7636 S256 challenge vector', async () => {
    await expect(deriveSsoPkceS256Challenge(
      'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    )).resolves.toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('builds vault-hosted browser start/callback URLs and an identity token URL', () => {
    const urls = buildSsoLoginUrls({
      vaultUrl: 'https://vault.example/base',
      identityUrl: 'https://identity.example/tenant/identity',
      email: 'USER@example.com',
      state: STATE,
      codeChallenge: CHALLENGE,
    });

    expect(urls).toMatchObject({
      vaultUrl: 'https://vault.example/base/',
      identityUrl: 'https://identity.example/tenant/identity/',
      connectorCallbackUrl: 'https://vault.example/base/sso-connector.html',
      connectorOrigin: 'https://vault.example',
      connectorPath: '/base/sso-connector.html',
      identityTokenUrl: 'https://identity.example/tenant/identity/connect/token',
    });
    expect(urls).not.toHaveProperty('ssoUrl');

    const hash = new URL(urls.startUrl).hash;
    expect(hash.startsWith('#/sso?')).toBe(true);
    const params = new URLSearchParams(hash.slice(hash.indexOf('?') + 1));
    expect(Object.fromEntries(params)).toEqual({
      clientId: 'browser',
      redirectUri: urls.connectorCallbackUrl,
      state: STATE,
      codeChallenge: CHALLENGE,
      email: 'user@example.com',
    });
  });

  it('accepts but does not require a separately advertised hosted SSO service', () => {
    const urls = buildSsoLoginUrls({
      vaultUrl: 'https://vault.example/',
      identityUrl: 'https://identity.example/',
      ssoUrl: 'https://sso.example/tenant',
      email: 'user@example.com',
      state: STATE,
      codeChallenge: CHALLENGE,
    });

    expect(urls.ssoUrl).toBe('https://sso.example/tenant/');
    expect(urls.startUrl.startsWith('https://vault.example/#/sso?')).toBe(true);
  });

  it('rejects unsafe environment services and malformed ceremony material', () => {
    const valid = {
      vaultUrl: 'https://vault.example/',
      identityUrl: 'https://identity.example/',
      email: 'user@example.com',
      state: STATE,
      codeChallenge: CHALLENGE,
    };
    for (const override of [
      { vaultUrl: 'http://vault.example/' },
      { identityUrl: 'https://user:secret@identity.example/' },
      { identityUrl: 'https://identity.example/?token=secret' },
      { ssoUrl: '' },
      { state: `${STATE}x` },
      { codeChallenge: 'not-base64url' },
    ]) expect(() => buildSsoLoginUrls({ ...valid, ...override })).toThrow();
  });

  it('parses one exact callback and returns a secret-free scrub URL', () => {
    const redirectUri = 'https://vault.example/base/sso-connector.html';
    const callback = `${redirectUri}?state=${encodeURIComponent(STATE)}&code=opaque_code-123`;

    expect(parseSsoCallbackUrl(callback, { redirectUri, state: STATE })).toEqual({
      code: 'opaque_code-123',
      state: STATE,
      scrubbedUrl: redirectUri,
    });
    expect(scrubSsoCallbackUrl(`${callback}#handoff`, redirectUri)).toBe(redirectUri);
  });

  it('accepts at most one standard scope and issuer callback parameter', () => {
    const redirectUri = 'https://vault.example/base/sso-connector.html';
    const callback = `${redirectUri}?code=opaque-code&state=${encodeURIComponent(STATE)}`
      + '&scope=api+offline_access&iss=https%3A%2F%2Fidentity.example';

    expect(parseSsoCallbackUrl(callback, { redirectUri, state: STATE })).toEqual({
      code: 'opaque-code',
      state: STATE,
      scope: 'api offline_access',
      iss: 'https://identity.example/',
      scrubbedUrl: redirectUri,
    });
  });

  it('accepts one bounded Web Vault organization identifier suffix while binding the base state', () => {
    const redirectUri = 'https://vault.example/base/sso-connector.html';
    const returnedState = `${STATE}_identifier=org-sso_123`;
    const callback = `${redirectUri}?code=opaque-code&state=${encodeURIComponent(returnedState)}`;

    expect(parseSsoCallbackUrl(callback, { redirectUri, state: STATE })).toEqual({
      code: 'opaque-code',
      state: STATE,
      organizationIdentifier: 'org-sso_123',
      scrubbedUrl: redirectUri,
    });
  });

  it('rejects ambiguous, encoded, or invalid Web Vault identifier suffixes', () => {
    const redirectUri = 'https://vault.example/base/sso-connector.html';
    const callback = (state: string) => (
      `${redirectUri}?code=opaque-code&state=${encodeURIComponent(state)}`
    );
    const other = `BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB${SSO_BROWSER_STATE_SUFFIX}`;
    for (const state of [
      `${STATE}_identifier=`,
      `${STATE}_identifier=one_identifier=two`,
      `${STATE}_identifier=${'a'.repeat(257)}`,
      `${STATE}_identifier=bad\nvalue`,
      `${other}_identifier=org`,
    ]) expect(() => parseSsoCallbackUrl(callback(state), { redirectUri, state: STATE })).toThrow();

    const encodedDelimiter = `${redirectUri}?code=opaque-code&state=${encodeURIComponent(STATE)}`
      + '%5Fidentifier%3Dorg';
    expect(() => parseSsoCallbackUrl(encodedDelimiter, { redirectUri, state: STATE })).toThrow();
  });

  it('rejects callback confusion, duplicates, extras, fragments, and state mismatch', () => {
    const redirectUri = 'https://vault.example/base/sso-connector.html';
    const validQuery = `code=opaque-code&state=${encodeURIComponent(STATE)}`;
    const callbacks = [
      `https://evil.example/base/sso-connector.html?${validQuery}`,
      `https://vault.example/other/sso-connector.html?${validQuery}`,
      `${redirectUri}?${validQuery}&extra=1`,
      `${redirectUri}?${validQuery}&code=replay`,
      `${redirectUri}?${validQuery}&scope=openid`,
      `${redirectUri}?${validQuery}&scope=api+offline_access&scope=api+offline_access`,
      `${redirectUri}?${validQuery}&iss=javascript%3Aalert(1)`,
      `${redirectUri}?${validQuery}&iss=https%3A%2F%2Fidentity.example%2F&iss=https%3A%2F%2Fidentity.example%2F`,
      `${redirectUri}?${validQuery}#fragment`,
      `${redirectUri}?code=opaque-code&state=${encodeURIComponent(`BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB${SSO_BROWSER_STATE_SUFFIX}`)}`,
      `${redirectUri}?code=opaque%2Bcode&state=${encodeURIComponent(STATE)}`,
    ];
    for (const callback of callbacks) {
      expect(() => parseSsoCallbackUrl(callback, { redirectUri, state: STATE })).toThrow();
    }
    expect(() => scrubSsoCallbackUrl(callbacks[0], redirectUri)).toThrow(/redirect URI/u);
  });
});
