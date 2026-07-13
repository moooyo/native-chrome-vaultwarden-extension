import { describe, it, expect, vi } from 'vitest';
import { createHostAccessCheck, originMatchPattern } from './host-access.js';

describe('originMatchPattern', () => {
  it('reduces an HTTP(S) URL with a path/query/fragment to an ${origin}/* host match pattern', () => {
    expect(originMatchPattern('https://other-origin.example/widget?foo=bar#frag')).toBe('https://other-origin.example/*');
    expect(originMatchPattern('http://example.com/login')).toBe('http://example.com/*');
  });

  it('preserves a non-default port and subdomain in the origin', () => {
    expect(originMatchPattern('https://sub.example.com:8443/a/b?c=d')).toBe('https://sub.example.com:8443/*');
  });

  it.each([
    'about:blank',
    'about:srcdoc',
    'data:text/html,<h1>hi</h1>',
    'blob:https://other-origin.example/1234',
    'file:///etc/passwd',
    'chrome://extensions/',
    'chrome-extension://abcdef/page.html',
    'ftp://example.com/file',
    'not a url',
    '',
  ])('fails closed (undefined) for the non-HTTP(S)/unparseable URL %j', (url) => {
    expect(originMatchPattern(url)).toBeUndefined();
  });
});

describe('createHostAccessCheck', () => {
  it('calls permissions.contains with the exact normalized ${origin}/* pattern and returns its result', async () => {
    const contains = vi.fn(async () => true);
    const check = createHostAccessCheck(contains);

    const granted = await check('https://other-origin.example/widget?foo=bar#frag');

    expect(granted).toBe(true);
    expect(contains).toHaveBeenCalledTimes(1);
    expect(contains).toHaveBeenCalledWith({ origins: ['https://other-origin.example/*'] });
  });

  it('returns the false result from contains when the permanent permission is absent', async () => {
    const contains = vi.fn(async () => false);
    const check = createHostAccessCheck(contains);
    await expect(check('https://other-origin.example/path')).resolves.toBe(false);
    expect(contains).toHaveBeenCalledWith({ origins: ['https://other-origin.example/*'] });
  });

  it.each([
    'about:blank',
    'data:text/html,<h1>hi</h1>',
    'blob:https://other-origin.example/1234',
    'file:///etc/passwd',
    'chrome://extensions/',
    'not a url',
  ])('fails closed for %j without ever calling permissions.contains', async (url) => {
    const contains = vi.fn(async () => true);
    const check = createHostAccessCheck(contains);
    await expect(check(url)).resolves.toBe(false);
    expect(contains).not.toHaveBeenCalled();
  });
});
