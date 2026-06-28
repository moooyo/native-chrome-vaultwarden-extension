import { describe, it, expect } from 'vitest';
import { buildEquivalentDomainIndex, areDomainsEquivalent, BUILTIN_EQUIVALENT_DOMAINS } from './equivalent-domains.js';

describe('equivalent domains', () => {
  const index = buildEquivalentDomainIndex();

  it('treats domains in the same built-in group as equivalent', () => {
    expect(areDomainsEquivalent('google.com', 'youtube.com', index)).toBe(true);
    expect(areDomainsEquivalent('amazon.com', 'amazon.co.uk', index)).toBe(true);
  });

  it('treats identical domains as equivalent even when not listed', () => {
    expect(areDomainsEquivalent('example.com', 'example.com', index)).toBe(true);
  });

  it('does not treat unrelated domains as equivalent', () => {
    expect(areDomainsEquivalent('google.com', 'example.com', index)).toBe(false);
    expect(areDomainsEquivalent('', 'google.com', index)).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(areDomainsEquivalent('GOOGLE.com', 'YouTube.COM', index)).toBe(true);
  });

  it('merges user-defined groups on top of the built-in list', () => {
    const merged = buildEquivalentDomainIndex([['intranet.local', 'wiki.local']]);
    expect(areDomainsEquivalent('intranet.local', 'wiki.local', merged)).toBe(true);
    // built-ins still apply
    expect(areDomainsEquivalent('google.com', 'youtube.com', merged)).toBe(true);
  });

  it('ships a non-trivial built-in list', () => {
    expect(BUILTIN_EQUIVALENT_DOMAINS.length).toBeGreaterThan(5);
  });

  it('skips a built-in group when the server marks its domains excluded', () => {
    // google.com/youtube.com share a built-in group; excluding google.com drops the whole group…
    const idx = buildEquivalentDomainIndex([], ['google.com']);
    expect(areDomainsEquivalent('google.com', 'youtube.com', idx)).toBe(false);
    // …but other built-in groups are unaffected.
    expect(areDomainsEquivalent('amazon.com', 'amazon.co.uk', idx)).toBe(true);
  });

  it('still applies user groups when a built-in group is excluded', () => {
    const idx = buildEquivalentDomainIndex([['a.local', 'b.local']], ['youtube.com']);
    expect(areDomainsEquivalent('a.local', 'b.local', idx)).toBe(true);
    expect(areDomainsEquivalent('google.com', 'youtube.com', idx)).toBe(false);
  });
});
