// Passphrase generator (Bitwarden-style): pick N random words, optionally capitalize each, join with a
// separator, and optionally append a digit to one word. Randomness defaults to crypto.getRandomValues
// (unbiased via rejection sampling); an injectable randomInt keeps it deterministic in tests.

import { cryptoRandomInt } from './password.js';
import { PASSPHRASE_WORDLIST } from './wordlist.js';
import { clamp } from '../util/num.js';

export interface PassphraseGenOptions {
  numWords: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseGenOptions = {
  numWords: 4,
  separator: '-',
  capitalize: true,
  includeNumber: true,
};

const MIN_WORDS = 3;
const MAX_WORDS = 20;

export function generatePassphrase(
  options: PassphraseGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
  words: readonly string[] = PASSPHRASE_WORDLIST,
): string {
  if (words.length === 0) return '';
  const count = clamp(Math.trunc(options.numWords) || 0, MIN_WORDS, MAX_WORDS);
  const chosen: string[] = [];
  for (let i = 0; i < count; i++) {
    const word = words[randomInt(words.length)]!;
    chosen.push(options.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word);
  }
  if (options.includeNumber) {
    // Append a single 0-9 digit to one randomly chosen word (Bitwarden's behavior).
    const idx = randomInt(chosen.length);
    chosen[idx] = `${chosen[idx]}${randomInt(10)}`;
  }
  return chosen.join(options.separator);
}
