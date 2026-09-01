import { describe, expect, it } from 'vitest';
import {
  parseWebsitePasskeyIframeAllowAttribute,
  parseWebsitePasskeyPermissionsPolicyHeader,
} from './website-passkey-permissions-policy-parser.js';

describe('website passkey Permissions-Policy header parser', () => {
  it('parses create/get independently, normalizes origins, and applies later members', () => {
    const result = parseWebsitePasskeyPermissionsPolicyHeader([
      'publickey-credentials-get=(self "https://Login.Example/path"), publickey-credentials-create=()',
      'publickey-credentials-get=(*)',
    ]);

    expect(result).toEqual({
      ok: true,
      value: {
        'publickey-credentials-create': [],
        'publickey-credentials-get': [{ type: 'wildcard' }],
      },
    });
  });

  it('keeps an observed response with no policy as the declared-policy default', () => {
    expect(parseWebsitePasskeyPermissionsPolicyHeader([])).toEqual({ ok: true, value: {} });
    expect(parseWebsitePasskeyPermissionsPolicyHeader(['camera=(), geolocation=(self)']))
      .toEqual({ ok: true, value: {} });
  });

  it.each([
    ['unterminated list', ['publickey-credentials-get=(self']],
    ['bare boolean member', ['publickey-credentials-get']],
    ['unknown relevant token', ['publickey-credentials-get=(src)']],
    ['invalid relevant origin', ['publickey-credentials-get=("not an origin")']],
    ['unsupported wildcard origin', ['publickey-credentials-get=("https://*.example.com")']],
    ['header injection', ['publickey-credentials-get=(*)\r\nX: y']],
  ])('fails closed for %s', (_name, values) => {
    expect(parseWebsitePasskeyPermissionsPolicyHeader(values)).toEqual({ ok: false });
  });

  it('accepts syntactically valid unrelated value types without weakening a WebAuthn directive', () => {
    expect(parseWebsitePasskeyPermissionsPolicyHeader([
      'unrelated=?1, publickey-credentials-get=(self);x=?1',
    ])).toEqual({
      ok: true,
      value: { 'publickey-credentials-get': [{ type: 'self' }] },
    });
  });
});

describe('website passkey iframe allow parser', () => {
  const child = 'https://child.example';
  const parent = 'https://parent.example';

  it('implements src, self, wildcard, explicit-origin, none, and later-wins semantics', () => {
    expect(parseWebsitePasskeyIframeAllowAttribute(
      "publickey-credentials-get 'self'; publickey-credentials-create *; publickey-credentials-get 'src'",
      child,
      parent,
    )).toEqual({
      ok: true,
      value: {
        'publickey-credentials-create': [{ type: 'wildcard' }],
        'publickey-credentials-get': [{ type: 'origin', value: child }],
      },
    });
    expect(parseWebsitePasskeyIframeAllowAttribute(
      "publickey-credentials-get 'none'",
      child,
      parent,
    )).toEqual({ ok: true, value: { 'publickey-credentials-get': [] } });
  });

  it('uses src when a directive has no allowlist and keeps an absent directive absent', () => {
    expect(parseWebsitePasskeyIframeAllowAttribute('publickey-credentials-get', child, parent))
      .toEqual({
        ok: true,
        value: { 'publickey-credentials-get': [{ type: 'origin', value: child }] },
      });
    expect(parseWebsitePasskeyIframeAllowAttribute('', child, parent)).toEqual({ ok: true, value: {} });
  });

  it.each([
    "publickey-credentials-get 'none' *",
    "publickey-credentials-get 'unknown'",
    'publickey-credentials-get not-an-origin',
    'publickey-credentials-get https://*.example.com',
    'publickey-credentials-get\n*',
  ])('fails closed for malformed allow=%s', (raw) => {
    expect(parseWebsitePasskeyIframeAllowAttribute(raw, child, parent)).toEqual({ ok: false });
  });
});
