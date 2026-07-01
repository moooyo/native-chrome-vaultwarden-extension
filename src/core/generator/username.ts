// Local username generators (Bitwarden-style): plus-addressed email, catch-all email, and random-word
// username. All pure and offline — no vault secret, no network. `randomInt` is injectable for tests.

import { cryptoRandomInt } from './password.js';
import { PASSPHRASE_WORDLIST } from './wordlist.js';

export type UsernameType = 'plusAddressed' | 'catchAll' | 'randomWord';

export interface UsernameGenOptions {
  /** Random local-part / suffix length for plus-addressed & catch-all. */
  randomLength: number;
  /** random-word: capitalize the first letter. */
  capitalize: boolean;
  /** random-word: append one 0-9 digit. */
  includeNumber: boolean;
}

export const DEFAULT_USERNAME_OPTIONS: UsernameGenOptions = { randomLength: 8, capitalize: false, includeNumber: false };

const ALPHANUM = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** Lowercase letters + digits, unbiased via the injected randomInt (rejection sampling in cryptoRandomInt). */
export function randomAlphanumeric(length: number, randomInt: (maxExclusive: number) => number = cryptoRandomInt): string {
  const n = clamp(Math.trunc(length) || 0, 1, 64);
  let out = '';
  for (let i = 0; i < n; i++) out += ALPHANUM[randomInt(ALPHANUM.length)];
  return out;
}

/** `local+<random>@domain`. A base without '@' becomes `base+<random>` (no domain). Trims the base. */
export function generatePlusAddressedEmail(
  baseEmail: string,
  options: UsernameGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
): string {
  const trimmed = baseEmail.trim();
  const rand = randomAlphanumeric(clampLen(options.randomLength), randomInt);
  const at = trimmed.indexOf('@');
  const domain = at < 0 ? '' : trimmed.slice(at + 1);
  const local = at < 0 ? trimmed : trimmed.slice(0, at);
  return domain ? `${local}+${rand}@${domain}` : `${local}+${rand}`;
}

/** `<random>@domain`. A leading '@' on the domain is stripped; an empty domain yields just the random part. */
export function generateCatchAllEmail(
  domain: string,
  options: UsernameGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
): string {
  const d = domain.trim().replace(/^@+/, '');
  const rand = randomAlphanumeric(clampLen(options.randomLength), randomInt);
  return d ? `${rand}@${d}` : rand;
}

/** A random word, optionally capitalized, optionally with a trailing 0-9 digit. */
export function generateRandomWordUsername(
  options: UsernameGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
  words: readonly string[] = PASSPHRASE_WORDLIST,
): string {
  if (words.length === 0) return '';
  let word = words[randomInt(words.length)]!;
  if (options.capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
  if (options.includeNumber) word = `${word}${randomInt(10)}`;
  return word;
}

function clampLen(len: number): number { return clamp(Math.trunc(len) || 0, 4, 32); }
function clamp(v: number, min: number, max: number): number { return Math.max(min, Math.min(max, v)); }
