import { describe, it, expect } from 'vitest';
import { randomAlphanumeric, generatePlusAddressedEmail, generateCatchAllEmail, generateRandomWordUsername, DEFAULT_USERNAME_OPTIONS } from './username.js';

const fixed = (v: number) => () => v; // deterministic randomInt: always returns v

describe('randomAlphanumeric', () => {
  it('produces the requested length from lowercase letters + digits', () => {
    expect(randomAlphanumeric(10, fixed(0))).toBe('aaaaaaaaaa'); // index 0 → 'a'
    expect(/^[a-z0-9]+$/.test(randomAlphanumeric(20, (n) => n - 1))).toBe(true); // last index → '9'
  });
});

describe('generatePlusAddressedEmail', () => {
  it('inserts +<random> before the @', () => {
    expect(generatePlusAddressedEmail('me@example.com', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('me+aaaa@example.com');
  });
  it('handles a base with no @ (no domain), trimming', () => {
    expect(generatePlusAddressedEmail('  me  ', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('me+aaaa');
  });
});

describe('generateCatchAllEmail', () => {
  it('builds <random>@domain and strips a leading @', () => {
    expect(generateCatchAllEmail('@example.com', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('aaaa@example.com');
  });
  it('empty domain → just the random part', () => {
    expect(generateCatchAllEmail('   ', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('aaaa');
  });
});

describe('generateRandomWordUsername', () => {
  const words = ['alpha', 'bravo'];
  it('default lowercase word', () => {
    expect(generateRandomWordUsername(DEFAULT_USERNAME_OPTIONS, fixed(0), words)).toBe('alpha');
  });
  it('capitalize + includeNumber', () => {
    expect(generateRandomWordUsername({ ...DEFAULT_USERNAME_OPTIONS, capitalize: true, includeNumber: true }, fixed(0), words)).toBe('Alpha0');
  });
});
