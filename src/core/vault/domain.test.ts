import { describe, expect, it } from 'vitest';
import { getBaseDomain, getHostAndPort, isHttpUrl } from './domain.js';

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
