import { describe, expect, it } from 'vitest';
import {
  AUTOFILL_POLICY_ACTIONS,
  MAX_AUTOFILL_BLOCKLIST_ENTRIES,
  decideAutofillPolicy,
  normalizeAutofillBlocklist,
  pageLoadAutofillAllowed,
} from './autofill-policy.js';

describe('pageLoadAutofillAllowed', () => {
  it.each([
    [true, false, true],
    [true, true, true],
    [false, false, false],
    [false, true, false],
    [null, false, false],
    [null, true, true],
    [undefined, false, false],
    [undefined, true, true],
    ['true', true, false],
    [1, true, false],
  ])('resolves item override %j against default %j to %j', (item, fallback, expected) => {
    expect(pageLoadAutofillAllowed(item, fallback)).toBe(expected);
  });
});

describe('normalizeAutofillBlocklist', () => {
  it('normalizes, de-duplicates, and sorts hostname rules', () => {
    const policy = normalizeAutofillBlocklist([
      ' Accounts.Example.COM. ',
      'example.com',
      'accounts.example.com',
    ]);
    expect(policy).toEqual({
      valid: true,
      rules: [
        { kind: 'host', hostname: 'accounts.example.com', match: 'host-and-subdomains', pattern: 'accounts.example.com' },
        { kind: 'host', hostname: 'example.com', match: 'host-and-subdomains', pattern: 'example.com' },
      ],
      errors: [],
    });
  });

  it('normalizes IDNs and HTTP(S) origins including default ports', () => {
    const policy = normalizeAutofillBlocklist([
      { pattern: 'BÜCHER.example', match: 'exact' },
      { pattern: 'HTTPS://Example.COM:443/', match: 'exact' },
      'http://example.com:8080',
    ]);
    expect(policy.valid).toBe(true);
    expect(policy.rules).toEqual(expect.arrayContaining([
      { kind: 'host', hostname: 'xn--bcher-kva.example', match: 'exact', pattern: 'xn--bcher-kva.example' },
      { kind: 'origin', scheme: 'https:', hostname: 'example.com', port: '', match: 'exact', pattern: 'https://example.com' },
      { kind: 'origin', scheme: 'http:', hostname: 'example.com', port: '8080', match: 'host-and-subdomains', pattern: 'http://example.com:8080' },
    ]));
  });

  it('keeps exact and host-and-subdomains variants as distinct rules', () => {
    const policy = normalizeAutofillBlocklist([
      { pattern: 'example.com', match: 'exact' },
      'example.com',
    ]);
    expect(policy.valid).toBe(true);
    expect(policy.rules).toHaveLength(2);
  });

  it.each([
    undefined,
    null,
    {},
    'example.com',
  ])('fails closed when the persisted list is not an array: %j', (input) => {
    const policy = normalizeAutofillBlocklist(input);
    expect(policy.valid).toBe(false);
    expect(policy.errors).toEqual([{ code: 'invalid_list' }]);
  });

  it.each([
    [42, 'invalid_entry'],
    [{ pattern: 'example.com', match: 'suffix' }, 'invalid_match'],
    [{ pattern: 42 }, 'invalid_pattern'],
    ['', 'invalid_pattern'],
    ['https://user:secret@example.com', 'invalid_pattern'],
    ['https://example.com/path', 'invalid_pattern'],
    ['https://example.com?mode=login', 'invalid_pattern'],
    ['example.com:8443', 'invalid_pattern'],
    ['*.example.com', 'invalid_pattern'],
    ['.example.com', 'invalid_pattern'],
    ['example..com', 'invalid_pattern'],
    ['ftp://example.com', 'unsupported_scheme'],
  ])('marks a malformed entry invalid instead of silently dropping it: %j', (entry, code) => {
    const policy = normalizeAutofillBlocklist([entry]);
    expect(policy.valid).toBe(false);
    expect(policy.errors).toEqual([{ index: 0, code }]);
  });

  it('fails closed when the entry bound is exceeded', () => {
    const input = Array.from({ length: MAX_AUTOFILL_BLOCKLIST_ENTRIES + 1 }, (_, index) => `host-${index}.example`);
    expect(normalizeAutofillBlocklist(input)).toEqual({
      valid: false,
      rules: [],
      errors: [{ code: 'too_many_entries' }],
    });
  });

  it('treats a sparse array slot as invalid policy data', () => {
    const sparse = Array<string>(1);
    expect(normalizeAutofillBlocklist(sparse)).toEqual({
      valid: false,
      rules: [],
      errors: [{ index: 0, code: 'invalid_entry' }],
    });
  });
});

describe('decideAutofillPolicy', () => {
  it('uses exact hostname boundaries and does not suffix-match lookalike domains', () => {
    const policy = normalizeAutofillBlocklist([{ pattern: 'example.com', match: 'exact' }]);
    expect(decideAutofillPolicy(policy, { action: 'candidate', url: 'https://example.com/login' })).toMatchObject({ allowed: false, reason: 'blocked' });
    expect(decideAutofillPolicy(policy, { action: 'candidate', url: 'https://www.example.com/login' })).toMatchObject({ allowed: true });
    expect(decideAutofillPolicy(policy, { action: 'candidate', url: 'https://notexample.com/login' })).toMatchObject({ allowed: true });
  });

  it('matches the apex and real child hosts for a host-and-subdomains rule', () => {
    const policy = normalizeAutofillBlocklist(['example.com']);
    for (const url of ['http://example.com', 'https://a.example.com', 'https://deep.a.example.com:9443']) {
      expect(decideAutofillPolicy(policy, { action: 'intent', url })).toMatchObject({ allowed: false, reason: 'blocked' });
    }
    expect(decideAutofillPolicy(policy, { action: 'intent', url: 'https://example.com.evil.test' })).toMatchObject({ allowed: true });
  });

  it('scopes origin rules by scheme and effective port while retaining hostname boundaries', () => {
    const policy = normalizeAutofillBlocklist(['https://example.com:8443']);
    expect(decideAutofillPolicy(policy, { action: 'page-load', url: 'https://login.example.com:8443/form' })).toMatchObject({ allowed: false, reason: 'blocked' });
    expect(decideAutofillPolicy(policy, { action: 'page-load', url: 'http://login.example.com:8443/form' })).toMatchObject({ allowed: true });
    expect(decideAutofillPolicy(policy, { action: 'page-load', url: 'https://login.example.com/form' })).toMatchObject({ allowed: true });
  });

  it('applies the same block decision to every policy action', () => {
    const policy = normalizeAutofillBlocklist(['example.com']);
    for (const action of AUTOFILL_POLICY_ACTIONS) {
      expect(decideAutofillPolicy(policy, { action, url: 'https://example.com/login' })).toMatchObject({
        allowed: false,
        reason: 'blocked',
      });
    }
  });

  it('returns a canonical URL and origin for an allowed action', () => {
    const policy = normalizeAutofillBlocklist([]);
    expect(decideAutofillPolicy(policy, {
      action: 'save',
      url: 'HTTPS://BÜCHER.example:443/account/../login?step=1#field',
    })).toEqual({
      allowed: true,
      action: 'save',
      url: 'https://xn--bcher-kva.example/login?step=1',
      origin: 'https://xn--bcher-kva.example',
    });
  });

  it.each([
    'not a url',
    'file:///tmp/login.html',
    'https://user:password@example.com/login',
  ])('rejects an ineligible target URL: %s', (url) => {
    expect(decideAutofillPolicy(normalizeAutofillBlocklist([]), { action: 'update', url }))
      .toEqual({ allowed: false, reason: 'invalid_url' });
  });

  it('denies every action when even one stored rule is malformed', () => {
    const policy = normalizeAutofillBlocklist(['example.com', 'https://example.net/path']);
    expect(decideAutofillPolicy(policy, { action: 'candidate', url: 'https://allowed.test' }))
      .toEqual({ allowed: false, reason: 'invalid_policy' });
  });

  it('rejects forged policy shapes and unknown action values', () => {
    expect(decideAutofillPolicy(
      { valid: true, rules: [{ kind: 'host', hostname: '', match: 'exact', pattern: '' }], errors: [] },
      { action: 'intent', url: 'https://example.com' },
    )).toEqual({ allowed: false, reason: 'invalid_policy' });
    expect(decideAutofillPolicy(
      { valid: true, rules: [{ kind: 'host', hostname: 'Example.COM', match: 'exact', pattern: 'Example.COM' }], errors: [] },
      { action: 'intent', url: 'https://example.com' },
    )).toEqual({ allowed: false, reason: 'invalid_policy' });
    expect(decideAutofillPolicy(
      normalizeAutofillBlocklist([]),
      { action: 'unknown', url: 'https://example.com' } as never,
    )).toEqual({ allowed: false, reason: 'invalid_action' });
  });
});
