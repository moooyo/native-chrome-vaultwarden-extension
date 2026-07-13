import { describe, expect, it } from 'vitest';
import { getBaseDomain, getHostAndPort, isHttpUrl, isRegistrableRpId } from './domain.js';

describe('domain helpers', () => {
  it('extracts a public-suffix-aware base domain', () => {
    expect(getBaseDomain('https://login.example.com/account')).toBe('example.com');
    expect(getBaseDomain('login.example.co.uk')).toBe('example.co.uk');
  });

  it('keeps localhost and IP addresses as their own base domain', () => {
    expect(getBaseDomain('http://localhost:8080/login')).toBe('localhost');
    expect(getBaseDomain('https://127.0.0.1:8080/login')).toBe('127.0.0.1');
  });

  it('extracts host and optional port from URLs and host strings', () => {
    expect(getHostAndPort('https://vault.example.com:8443/login')).toEqual({ host: 'vault.example.com', port: '8443' });
    expect(getHostAndPort('vault.example.com')).toEqual({ host: 'vault.example.com' });
  });

  it('rejects non-http URLs for autofill matching', () => {
    expect(isHttpUrl('https://example.com')).toBe(true);
    expect(isHttpUrl('http://example.com')).toBe(true);
    expect(isHttpUrl('file:///tmp/login.html')).toBe(false);
    expect(isHttpUrl('about:blank')).toBe(false);
  });
});

describe('isRegistrableRpId', () => {
  it('accepts exact and subdomain matches on a registrable domain', () => {
    expect(isRegistrableRpId('example.com', 'example.com')).toBe(true);
    expect(isRegistrableRpId('example.com', 'app.example.com')).toBe(true);
    expect(isRegistrableRpId('example.co.uk', 'app.example.co.uk')).toBe(true);
  });
  it('rejects a bare public suffix as rpId (no PSL registrable domain)', () => {
    expect(isRegistrableRpId('github.io', 'a.github.io')).toBe(false);
    expect(isRegistrableRpId('co.uk', 'foo.co.uk')).toBe(false);
  });
  it('rejects a cross-domain rpId', () => {
    expect(isRegistrableRpId('evil.com', 'victim.com')).toBe(false);
    expect(isRegistrableRpId('example.com', 'notexample.com')).toBe(false); // not a dot-suffix
  });
  it('rejects an IP rpId and allows only exact localhost', () => {
    expect(isRegistrableRpId('1.2.3.4', '1.2.3.4')).toBe(false);
    expect(isRegistrableRpId('localhost', 'localhost')).toBe(true);
    expect(isRegistrableRpId('localhost', 'app.localhost')).toBe(false);
  });
  it('is case-insensitive and rejects empty', () => {
    expect(isRegistrableRpId('Example.com', 'APP.EXAMPLE.COM')).toBe(true);
    expect(isRegistrableRpId('', 'example.com')).toBe(false);
  });
});
