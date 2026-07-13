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

  const minNum = options.numbers ? Math.max(options.minNumbers, 0) : 0;
  const minSpec = options.special ? Math.max(options.minSpecial, 0) : 0;

  const chars: string[] = [];
  for (let i = 0; i < minNum; i++) chars.push(pick(numbers, randomInt));
  for (let i = 0; i < minSpec; i++) chars.push(pick(special, randomInt));
  // At least one of every enabled set (per-class minimums above already cover numbers/special).
  if (lower) chars.push(pick(lower, randomInt));
  if (upper) chars.push(pick(upper, randomInt));
  if (numbers && minNum === 0) chars.push(pick(numbers, randomInt));
  if (special && minSpec === 0) chars.push(pick(special, randomInt));

  const targetLength = Math.max(options.length, chars.length);
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
