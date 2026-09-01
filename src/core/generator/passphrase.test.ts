import { describe, it, expect } from 'vitest';
import { generatePassphrase, DEFAULT_PASSPHRASE_OPTIONS } from './passphrase.js';
import { FINGERPRINT_WORDLIST, PASSPHRASE_WORDLIST } from './wordlist.js';

const WORDS = ['alpha', 'bravo', 'charlie'] as const;

describe('generatePassphrase', () => {
  it('joins capitalized words with the separator (deterministic randomInt)', () => {
    const out = generatePassphrase(
      { numWords: 3, separator: '-', capitalize: true, includeNumber: false },
      () => 0, // always pick WORDS[0]
      WORDS,
    );
    expect(out).toBe('Alpha-Alpha-Alpha');
  });

  it('lowercases when capitalize is off and honors a custom separator', () => {
    const out = generatePassphrase(
      { numWords: 3, separator: '.', capitalize: false, includeNumber: false },
      () => 1, // always pick WORDS[1]
      WORDS,
    );
    expect(out).toBe('bravo.bravo.bravo');
  });

  it('appends a single digit to one word when includeNumber is set', () => {
    // Sequence: 3 word picks, then idx pick, then the digit.
    const seq = [0, 1, 2, 0, 7];
    let i = 0;
    const out = generatePassphrase(
      { numWords: 3, separator: '-', capitalize: true, includeNumber: true },
      () => seq[i++]!,
      WORDS,
    );
    expect(out).toBe('Alpha7-Bravo-Charlie');
  });

  it('clamps the word count to [3, 20]', () => {
    const tooFew = generatePassphrase({ numWords: 1, separator: '-', capitalize: false, includeNumber: false }, () => 0, WORDS);
    expect(tooFew.split('-')).toHaveLength(3);
    const tooMany = generatePassphrase({ numWords: 99, separator: '-', capitalize: false, includeNumber: false }, () => 0, WORDS);
    expect(tooMany.split('-')).toHaveLength(20);
  });

  it('uses the official six-word lowercase default without adding a number', () => {
    expect(DEFAULT_PASSPHRASE_OPTIONS).toEqual({
      numWords: 6,
      separator: '-',
      capitalize: false,
      includeNumber: false,
    });
    const out = generatePassphrase(DEFAULT_PASSPHRASE_OPTIONS);
    expect(out).toMatch(/^[a-z]+(?:-[a-z]+){5}$/);
  });
});

describe('PASSPHRASE_WORDLIST', () => {
  it('is a large (>= 4096), unique, all lowercase-ASCII wordlist for adequate entropy', () => {
    expect(PASSPHRASE_WORDLIST.length).toBeGreaterThanOrEqual(4096);
    expect(new Set(PASSPHRASE_WORDLIST).size).toBe(PASSPHRASE_WORDLIST.length); // no duplicates
    for (const w of PASSPHRASE_WORDLIST) {
      expect(w).toMatch(/^[a-z]{3,}$/);
    }
  });
});

describe('FINGERPRINT_WORDLIST', () => {
  it('restores the four official hyphenated words without changing the passphrase list', () => {
    expect(PASSPHRASE_WORDLIST).toHaveLength(7_772);
    expect(FINGERPRINT_WORDLIST).toHaveLength(7_776);
    expect(FINGERPRINT_WORDLIST[FINGERPRINT_WORDLIST.indexOf('droop') + 1]).toBe('drop-down');
    expect(FINGERPRINT_WORDLIST[FINGERPRINT_WORDLIST.indexOf('feline') + 1]).toBe('felt-tip');
    expect(FINGERPRINT_WORDLIST[FINGERPRINT_WORDLIST.indexOf('system') + 1]).toBe('t-shirt');
    expect(FINGERPRINT_WORDLIST[FINGERPRINT_WORDLIST.indexOf('yippee') + 1]).toBe('yo-yo');
    expect(PASSPHRASE_WORDLIST.some((word) => word.includes('-'))).toBe(false);
  });

  it('matches the official ordered EFF long-wordlist digest', async () => {
    const digest = new Uint8Array(await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(FINGERPRINT_WORDLIST.join('\n')),
    ));
    const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(hex).toBe('abae49761b88f3f1ba31ef944bea1f61b795a3cd7e1cfb7d276ed45bf77967ba');
  });
});
