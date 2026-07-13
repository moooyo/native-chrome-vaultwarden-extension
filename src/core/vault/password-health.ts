// Password health: weak-password scoring and reuse detection. Runs in the worker over decrypted
// passwords; only non-sensitive flags (weak/reuse count) ever cross the messaging boundary.

export interface PasswordHealthInput {
  id: string;
  name: string;
  password?: string;
}

export interface PasswordHealthEntry {
  id: string;
  name: string;
  weak: boolean;
  /** How many vault logins share this exact password (>1 means reused). */
  reuseCount: number;
}

const COMMON = /^(password|passw0rd|123456|12345678|1234567890|qwerty|qwertyuiop|letmein|admin|welcome|iloveyou|abc123|monkey|dragon|111111|000000)$/i;

/** Heuristic strength score 0 (very weak) – 4 (strong) from length and character variety. */
export function scorePasswordStrength(password: string): number {
  if (!password) return 0;
  if (/^(.)\1*$/.test(password)) return 0; // all one repeated character
  if (COMMON.test(password)) return 0;

  let score = 0;
  const len = password.length;
  if (len >= 8) score++;
  if (len >= 12) score++;
  if (len >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(password)).length;
  score += Math.max(0, classes - 1);

  // A password under 8 chars is weak regardless of variety.
  if (len < 8) return Math.min(1, score);
  return Math.min(4, score);
}

export function isWeakPassword(password: string): boolean {
  return scorePasswordStrength(password) <= 1;
}

/** Build a per-login health report (weak + reuse count), skipping logins with no password. */
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
      weak: isWeakPassword(item.password),
      reuseCount: counts.get(item.password) ?? 1,
    }));
}
