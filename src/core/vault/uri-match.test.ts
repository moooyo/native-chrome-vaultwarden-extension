import { describe, expect, it } from 'vitest';
import {
  compareMatchResults,
  isUriMatchStrategySetting,
  matchLoginUri,
  UriMatchStrategy,
} from './uri-match.js';
import { buildEquivalentDomainIndex } from './equivalent-domains.js';

describe('equivalent-domain matching', () => {
  it('matches equivalent domains under the Domain strategy when an index is provided', () => {
    const index = buildEquivalentDomainIndex();
    expect(matchLoginUri({ uri: 'https://google.com', match: UriMatchStrategy.Domain }, 'https://youtube.com/watch', UriMatchStrategy.Domain, index))
      .toMatchObject({ matchType: UriMatchStrategy.Domain });
  });

  it('does not match equivalent domains without an index', () => {
    expect(matchLoginUri({ uri: 'https://google.com', match: UriMatchStrategy.Domain }, 'https://youtube.com/watch', UriMatchStrategy.Domain))
      .toBeUndefined();
  });
});

describe('uri matching', () => {
  it('matches by domain including subdomains and complex public suffixes', () => {
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'https://login.example.com/auth', UriMatchStrategy.Host))
      .toMatchObject({ matchedUri: 'https://example.com', matchType: UriMatchStrategy.Domain });
    expect(matchLoginUri({ uri: 'https://example.co.uk', match: UriMatchStrategy.Domain }, 'https://id.example.co.uk/auth', UriMatchStrategy.Host))
      .toMatchObject({ matchedUri: 'https://example.co.uk', matchType: UriMatchStrategy.Domain });
    expect(matchLoginUri({ uri: 'https://evil.co.uk', match: UriMatchStrategy.Domain }, 'https://id.example.co.uk/auth', UriMatchStrategy.Host))
      .toBeUndefined();
  });

  it('matches by host and respects a saved port when present', () => {
    expect(matchLoginUri({ uri: 'https://vault.example.com', match: UriMatchStrategy.Host }, 'https://vault.example.com/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Host });
    expect(matchLoginUri({ uri: 'https://vault.example.com:8443', match: UriMatchStrategy.Host }, 'https://vault.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://vault.example.com:8443', match: UriMatchStrategy.Host }, 'https://vault.example.com:8443/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Host });
  });

  it('does not match HTTPS saved URIs into HTTP frames for domain or host strategies', () => {
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'http://login.example.com/auth', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://vault.example.com', match: UriMatchStrategy.Host }, 'http://vault.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'http://example.com', match: UriMatchStrategy.Domain }, 'http://login.example.com/auth', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Domain });
  });

  it('matches starts-with and exact against full URLs', () => {
    expect(matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.StartsWith }, 'https://example.com/login?next=%2F', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.StartsWith });
    expect(matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.Exact }, 'https://example.com/login?next=%2F', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.Exact }, 'https://example.com/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Exact });
  });

  it('matches safe regular expressions and rejects invalid, overlong, or unsafe regular expressions', () => {
    expect(matchLoginUri({ uri: '^https://app\\.example\\.com/[a-z]+$', match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.RegularExpression });
    expect(matchLoginUri({ uri: '[', match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'a'.repeat(513), match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: '(a+)+$', match: UriMatchStrategy.RegularExpression }, 'https://app.example.com/login', UriMatchStrategy.Domain))
      .toBeUndefined();
  });

  it('uses the configured default strategy when match is absent or invalid', () => {
    expect(matchLoginUri({ uri: 'https://example.com' }, 'https://login.example.com', UriMatchStrategy.Domain))
      .toMatchObject({ matchType: UriMatchStrategy.Domain });
    expect(matchLoginUri({ uri: 'https://example.com', match: 99 }, 'https://login.example.com', UriMatchStrategy.Host))
      .toBeUndefined();
  });

  it('never matches Never and rejects non-http frame URLs', () => {
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Never }, 'https://example.com', UriMatchStrategy.Domain))
      .toBeUndefined();
    expect(matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'about:blank', UriMatchStrategy.Domain))
      .toBeUndefined();
  });

  it('sorts stronger matches before weaker matches', () => {
    const exact = matchLoginUri({ uri: 'https://example.com/login', match: UriMatchStrategy.Exact }, 'https://example.com/login', UriMatchStrategy.Domain)!;
    const domain = matchLoginUri({ uri: 'https://example.com', match: UriMatchStrategy.Domain }, 'https://login.example.com/login', UriMatchStrategy.Domain)!;
    expect(compareMatchResults(exact, domain)).toBeLessThan(0);
    expect(compareMatchResults(domain, exact)).toBeGreaterThan(0);
  });

  it('recognizes only supported strategy values', () => {
    expect(isUriMatchStrategySetting(UriMatchStrategy.Domain)).toBe(true);
    expect(isUriMatchStrategySetting(UriMatchStrategy.Never)).toBe(true);
    expect(isUriMatchStrategySetting(6)).toBe(false);
    expect(isUriMatchStrategySetting('0')).toBe(false);
  });
});
