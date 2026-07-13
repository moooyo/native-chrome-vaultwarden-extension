import { describe, it, expect } from 'vitest';
import { generatePassphrase, DEFAULT_PASSPHRASE_OPTIONS } from './passphrase.js';
import { PASSPHRASE_WORDLIST } from './wordlist.js';

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

  it('uses the built-in wordlist by default and produces the requested number of words', () => {
    const out = generatePassphrase({ ...DEFAULT_PASSPHRASE_OPTIONS, includeNumber: false });
    expect(out.split('-')).toHaveLength(DEFAULT_PASSPHRASE_OPTIONS.numWords);
  });
});

describe('PASSPHRASE_WORDLIST', () => {
  it('is non-trivial, unique, and all lowercase ASCII words', () => {
    expect(PASSPHRASE_WORDLIST.length).toBeGreaterThanOrEqual(128);
    expect(new Set(PASSPHRASE_WORDLIST).size).toBe(PASSPHRASE_WORDLIST.length); // no duplicates
    for (const w of PASSPHRASE_WORDLIST) {
      expect(w).toMatch(/^[a-z]{3,}$/);
    }
  });
});
