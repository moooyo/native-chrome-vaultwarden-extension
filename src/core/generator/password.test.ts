import { describe, it, expect } from 'vitest';
import { generatePassword, DEFAULT_PASSWORD_OPTIONS } from './password.js';

const LOWER = /[a-z]/;
const UPPER = /[A-Z]/;
const DIGIT = /[0-9]/;
const SPECIAL = /[!@#$%^&*]/;
const AMBIGUOUS = /[Il1O0]/;

// Deterministic counter "rng" so tests can assert exact, reproducible behavior.
function seededRandomInt(seed = 0): (maxExclusive: number) => number {
  let n = seed;
  return (max: number) => {
    n = (n * 1103515245 + 12345) & 0x7fffffff;
    return n % max;
  };
}

describe('generatePassword', () => {
  it('produces a password of the requested length', () => {
    const pw = generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 24 }, seededRandomInt(1));
    expect(pw).toHaveLength(24);
  });

  it('only draws from the enabled character sets', () => {
    const pw = generatePassword(
      { length: 40, lowercase: true, uppercase: false, numbers: false, special: false, minNumbers: 0, minSpecial: 0, avoidAmbiguous: false },
      seededRandomInt(2),
    );
    expect(pw).toMatch(/^[a-z]+$/);
  });

  it('enforces at least one of each enabled set', () => {
    const pw = generatePassword(
      { length: 8, lowercase: true, uppercase: true, numbers: true, special: true, minNumbers: 1, minSpecial: 1, avoidAmbiguous: false },
      seededRandomInt(3),
    );
    expect(pw).toMatch(LOWER);
    expect(pw).toMatch(UPPER);
    expect(pw).toMatch(DIGIT);
    expect(pw).toMatch(SPECIAL);
  });

  it('honors minNumbers and minSpecial', () => {
    const pw = generatePassword(
      { length: 20, lowercase: true, uppercase: false, numbers: true, special: true, minNumbers: 4, minSpecial: 3, avoidAmbiguous: false },
      seededRandomInt(4),
    );
    expect((pw.match(/[0-9]/g) ?? []).length).toBeGreaterThanOrEqual(4);
    expect((pw.match(/[!@#$%^&*]/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });

  it('excludes ambiguous characters when avoidAmbiguous is set', () => {
    const pw = generatePassword(
      { length: 60, lowercase: true, uppercase: true, numbers: true, special: false, minNumbers: 1, minSpecial: 0, avoidAmbiguous: true },
      seededRandomInt(5),
    );
    expect(pw).not.toMatch(AMBIGUOUS);
  });

  it('clamps the length up to the sum of the configured minimums', () => {
    // length 3 but mins demand 2 numbers + 3 specials = 5 chars.
    const pw = generatePassword(
      { length: 3, lowercase: false, uppercase: false, numbers: true, special: true, minNumbers: 2, minSpecial: 3, avoidAmbiguous: false },
      seededRandomInt(6),
    );
    expect(pw.length).toBeGreaterThanOrEqual(5);
    expect((pw.match(/[0-9]/g) ?? []).length).toBeGreaterThanOrEqual(2);
    expect((pw.match(/[!@#$%^&*]/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });

  it('returns an empty string when no character set is enabled', () => {
    const pw = generatePassword(
      { length: 12, lowercase: false, uppercase: false, numbers: false, special: false, minNumbers: 0, minSpecial: 0, avoidAmbiguous: false },
      seededRandomInt(7),
    );
    expect(pw).toBe('');
  });

  it('is reproducible for a fixed random source and varies with the seed', () => {
    const opts = { ...DEFAULT_PASSWORD_OPTIONS, length: 16 };
    expect(generatePassword(opts, seededRandomInt(9))).toBe(generatePassword(opts, seededRandomInt(9)));
    expect(generatePassword(opts, seededRandomInt(9))).not.toBe(generatePassword(opts, seededRandomInt(10)));
  });

  it('defaults to a 14-char strong password using crypto when no rng is injected', () => {
    const pw = generatePassword(DEFAULT_PASSWORD_OPTIONS);
    expect(pw).toHaveLength(14);
    // With all sets enabled, a 14-char password realistically mixes classes.
    expect(pw).toMatch(/[a-z]/);
  });
});
