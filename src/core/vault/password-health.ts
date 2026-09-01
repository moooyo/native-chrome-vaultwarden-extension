// Password health: weak-password scoring and reuse detection. Runs in the worker over decrypted
// passwords; only item identity and non-sensitive flags ever cross the messaging boundary.

import zxcvbn from 'zxcvbn';

export interface PasswordHealthInput {
  id: string;
  name: string;
  username?: string;
  password?: string;
}

export interface PasswordHealthEntry {
  id: string;
  name: string;
  weak: boolean;
  /** How many vault logins share this exact password (>1 means reused). */
  reuseCount: number;
}

const MAX_PASSWORD_SCORE_LENGTH = 256;
const MAX_USER_INPUT_LENGTH = 256;

/** zxcvbn strength score 0 (very weak) to 4 (strong), aligned with Bitwarden reports. */
export function scorePasswordStrength(password: string, userInputs: readonly string[] = []): number {
  if (!password) return 0;
  const boundedInputs = userInputs
    .filter((value) => typeof value === 'string' && value.length > 0)
    .map((value) => value.slice(0, MAX_USER_INPUT_LENGTH));
  return zxcvbn(password.slice(0, MAX_PASSWORD_SCORE_LENGTH), boundedInputs).score;
}

export function isWeakPassword(password: string, userInputs: readonly string[] = []): boolean {
  return scorePasswordStrength(password, userInputs) <= 2;
}

/** Build non-secret health metadata for every login with a password. */
export function buildPasswordHealthReport(items: PasswordHealthInput[]): PasswordHealthEntry[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    if (item.password) counts.set(item.password, (counts.get(item.password) ?? 0) + 1);
  }
  return items
    .filter((item): item is Required<PasswordHealthInput> => Boolean(item.password))
    .map((item) => ({
      id: item.id,
      name: item.name,
      weak: isWeakPassword(item.password, item.username ? [item.username] : []),
      reuseCount: counts.get(item.password) ?? 1,
    }));
}
