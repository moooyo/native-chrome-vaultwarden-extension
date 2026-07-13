// Generated-password history: a bounded, de-duplicated, most-recent-first list. Held in memory only
// (the popup session) and NEVER persisted — plaintext generated passwords must not reach storage,
// per the security red line in the M1–M3 design. Pure functions so the popup stays a thin UI.

export const MAX_PASSWORD_HISTORY = 50;

/** Return a new history with `password` moved to the front, de-duplicated and capped at `max`. */
export function addPasswordToHistory(
  history: readonly string[],
  password: string,
  max = MAX_PASSWORD_HISTORY,
): string[] {
  if (!password) return [...history];
  const deduped = history.filter((entry) => entry !== password);
  return [password, ...deduped].slice(0, max);
}
