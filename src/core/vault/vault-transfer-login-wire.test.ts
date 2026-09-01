import { describe, expect, it, vi } from 'vitest';
import { validateLoginUriAlias } from './vault-transfer-login-wire.js';

describe('validateLoginUriAlias', () => {
  it('accepts an omitted alias or an exact first-URI ciphertext alias', () => {
    expect(validateLoginUriAlias({ uris: [{ uri: '2.first' }] })).toEqual({ ok: true });
    expect(validateLoginUriAlias({ uri: '2.first', uris: [{ uri: '2.first' }, { uri: '2.second' }] }))
      .toEqual({ ok: true });
  });

  it('accepts null or empty only when the first URI value is likewise absent or empty', () => {
    expect(validateLoginUriAlias({ uri: null, uris: [] })).toEqual({ ok: true });
    expect(validateLoginUriAlias({ uri: null, uris: null })).toEqual({ ok: true });
    expect(validateLoginUriAlias({ uri: null, uris: [{ uri: null }] })).toEqual({ ok: true });
    expect(validateLoginUriAlias({ uri: '', uris: [] })).toEqual({ ok: true });
    expect(validateLoginUriAlias({ uri: '', uris: [{ uri: '' }] })).toEqual({ ok: true });
    expect(validateLoginUriAlias({ uri: null, uris: [{ uri: '2.first' }] })).toEqual({
      ok: false,
      code: 'login_uri_alias_mismatch',
    });
    expect(validateLoginUriAlias({ uri: '', uris: [{ uri: '2.first' }] })).toEqual({
      ok: false,
      code: 'login_uri_alias_mismatch',
    });
  });

  it('blocks empty, alias-only, mismatched, and malformed aliases', () => {
    for (const value of [
      { uri: '2.legacy' },
      { uri: '2.one', uris: [{ uri: '2.two' }] },
      { uri: 1, uris: [] },
    ]) {
      expect(validateLoginUriAlias(value)).toEqual({
        ok: false,
        code: 'login_uri_alias_mismatch',
      });
    }
  });

  it('rejects accessors without evaluating them', () => {
    const getter = vi.fn(() => '2.secret');
    const login = Object.defineProperty({ uris: [] }, 'uri', { enumerable: true, get: getter });
    expect(validateLoginUriAlias(login)).toEqual({
      ok: false,
      code: 'login_uri_alias_mismatch',
    });
    expect(getter).not.toHaveBeenCalled();
  });
});
