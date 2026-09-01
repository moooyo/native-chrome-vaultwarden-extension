import { describe, expect, it } from 'vitest';
import {
  MAX_SECURITY_STAMP_LENGTH,
  parseSyncResponse,
  parseSyncSecurityProfile,
} from './sync-profile.js';

describe('sync security profile parsing', () => {
  it.each([
    [{ id: 'profile-1', email: 'User@Example.com', securityStamp: 'stamp-a' }, 'stamp-a'],
    [{ id: 'profile-1', email: 'user@example.com', SecurityStamp: 'stamp-a' }, 'stamp-a'],
    [{
      id: 'profile-1', email: 'user@example.com', securityStamp: 'stamp-a', SecurityStamp: 'stamp-a',
    }, 'stamp-a'],
    [{ id: 'profile-1', email: 'user@example.com', securityStamp: null }, undefined],
    [{ id: 'profile-1', email: 'user@example.com' }, undefined],
  ])('parses bounded camelCase and PascalCase stamp forms', (profile, expected) => {
    expect(parseSyncSecurityProfile(profile)).toEqual({
      profileId: 'profile-1',
      accountIdentity: 'user@example.com',
      securityStamp: expected,
    });
  });

  it.each([
    { id: 'profile-1', email: 'user@example.com', securityStamp: '' },
    { id: 'profile-1', email: 'user@example.com', securityStamp: ' padded ' },
    { id: 'profile-1', email: 'user@example.com', securityStamp: 'line\nbreak' },
    { id: 'profile-1', email: 'user@example.com', securityStamp: 'x'.repeat(MAX_SECURITY_STAMP_LENGTH + 1) },
    { id: 'profile-1', email: 'user@example.com', securityStamp: 42 },
    { id: 'profile-1', email: 'user@example.com', securityStamp: 'a', SecurityStamp: 'b' },
    { id: '', email: 'user@example.com', securityStamp: 'a' },
    { id: 'profile-1', email: 'not-an-email', securityStamp: 'a' },
  ])('rejects malformed security-sensitive profile fields', (profile) => {
    expect(() => parseSyncSecurityProfile(profile)).toThrow();
  });

  it('does not invoke a security stamp accessor', () => {
    let accessed = false;
    const profile = { id: 'profile-1', email: 'user@example.com' } as Record<string, unknown>;
    Object.defineProperty(profile, 'securityStamp', {
      enumerable: true,
      get() {
        accessed = true;
        return 'stamp-a';
      },
    });

    expect(() => parseSyncSecurityProfile(profile)).toThrow(/data property/i);
    expect(accessed).toBe(false);
  });

  it('does not invoke a sync response profile accessor', () => {
    let accessed = false;
    const response = { ciphers: [] } as Record<string, unknown>;
    Object.defineProperty(response, 'profile', {
      enumerable: true,
      get() {
        accessed = true;
        return { id: 'profile-1', email: 'user@example.com' };
      },
    });

    expect(() => parseSyncResponse(response)).toThrow(/data property/i);
    expect(accessed).toBe(false);
  });

  it('validates the minimum sync response shape while preserving future fields', () => {
    const response = {
      profile: { id: 'profile-1', email: 'user@example.com', securityStamp: 'stamp-a' },
      ciphers: [],
      future: { retained: true },
    };
    expect(parseSyncResponse(response)).toBe(response);
    expect(() => parseSyncResponse({ profile: response.profile, ciphers: {} })).toThrow(/ciphers/i);
  });
});
