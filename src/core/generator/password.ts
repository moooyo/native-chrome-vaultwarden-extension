// Password generator (Bitwarden-style): guarantees at least one of every enabled character set and
// honors per-class minimums, then fills the remaining length from the combined pool and shuffles.
// Randomness defaults to crypto.getRandomValues; an injectable randomInt keeps it deterministic in tests.

export interface PasswordGenOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  numbers: boolean;
  special: boolean;
  minNumbers: number;
  minSpecial: number;
  avoidAmbiguous: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordGenOptions = {
  length: 14,
  lowercase: true,
  uppercase: true,
  numbers: true,
  special: true,
  minNumbers: 1,
  minSpecial: 1,
  avoidAmbiguous: true,
};

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SPECIAL = '!@#$%^&*';
const AMBIGUOUS = new Set(['I', 'l', '1', 'O', '0']);

/**
 * Hard ceiling on generated length; also caps the sum of the per-class minimums. Defense-in-depth
 * against a caller passing an absurd or malformed length/minimum (e.g. 1e7, NaN) that would spin the
 * fill loop into a multi-megabyte string and hang the popup. Well above the UI's [8, 40] range.
 */
export const MAX_PASSWORD_LENGTH = 128;

/** Coerce to an integer within [min, max]; a non-finite input (NaN/Infinity) falls back to `min`. */
function clampInt(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(Math.trunc(value), min), max);
}

export function generatePassword(
  options: PasswordGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
): string {
  const drop = (set: string): string =>
    options.avoidAmbiguous ? [...set].filter((c) => !AMBIGUOUS.has(c)).join('') : set;

  const lower = options.lowercase ? drop(LOWERCASE) : '';
  const upper = options.uppercase ? drop(UPPERCASE) : '';
  const numbers = options.numbers ? drop(NUMBERS) : '';
  const special = options.special ? drop(SPECIAL) : '';
  const all = lower + upper + numbers + special;
  if (!all) return '';

  // Clamp per-class minimums so their sum can never exceed MAX_PASSWORD_LENGTH (a huge minNumbers
  // otherwise forces an equally huge, class-skewed password regardless of `length`).
  const minNum = options.numbers ? clampInt(options.minNumbers, 0, MAX_PASSWORD_LENGTH) : 0;
  const minSpec = options.special ? clampInt(options.minSpecial, 0, MAX_PASSWORD_LENGTH - minNum) : 0;

  const chars: string[] = [];
  for (let i = 0; i < minNum; i++) chars.push(pick(numbers, randomInt));
  for (let i = 0; i < minSpec; i++) chars.push(pick(special, randomInt));
  // At least one of every enabled set (per-class minimums above already cover numbers/special).
  if (lower) chars.push(pick(lower, randomInt));
  if (upper) chars.push(pick(upper, randomInt));
  if (numbers && minNum === 0) chars.push(pick(numbers, randomInt));
  if (special && minSpec === 0) chars.push(pick(special, randomInt));

  // Clamp the requested length to [chars.length, MAX_PASSWORD_LENGTH] (never below the guaranteed
  // characters already collected), coercing an absurd or non-finite length instead of looping on it.
  const cap = Math.max(MAX_PASSWORD_LENGTH, chars.length);
  const targetLength = Math.max(clampInt(options.length, 0, cap), chars.length);
  while (chars.length < targetLength) chars.push(pick(all, randomInt));

  shuffle(chars, randomInt);
  return chars.join('');
}

function pick(set: string, randomInt: (maxExclusive: number) => number): string {
  return set[randomInt(set.length)]!;
}

function shuffle(arr: string[], randomInt: (maxExclusive: number) => number): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const tmp = arr[i]!;
    arr[i] = arr[j]!;
    arr[j] = tmp;
  }
}

/** Unbiased integer in [0, maxExclusive) via rejection sampling over crypto.getRandomValues. */
export function cryptoRandomInt(maxExclusive: number): number {
  if (maxExclusive <= 1) return 0;
  const limit = Math.floor(0x1_0000_0000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    const x = buf[0]!;
    if (x < limit) return x % maxExclusive;
  }
}
