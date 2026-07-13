// Capture credentials the user enters so the extension can offer to save or update them. Listens for
// real (trusted) submit, Enter, and submit-button clicks, then snapshots the current login form's
// username/password from the live DOM. The decision to prompt happens in the worker; this only watches.

import { detectLoginForms } from './form-detection.js';

export interface CapturedLogin {
  username?: string;
  password: string;
}

/**
 * Watch the page for credential submissions. `onCapture` fires with the current username/password
 * whenever the user submits a form that has a filled password. Returns a teardown function.
 */
export function startSaveCapture(onCapture: (login: CapturedLogin) => void): () => void {
  const trigger = (): void => {
    const captured = snapshotLogin();
    if (captured) onCapture(captured);
  };

  const onSubmit = (e: Event): void => { if (e.isTrusted) trigger(); };
  const onClick = (e: Event): void => {
    if (!e.isTrusted) return;
    const el = e.target as HTMLElement | null;
    if (el?.closest('button:not([type="button"]), input[type="submit"], input[type="image"], [role="button"]')) trigger();
  };
  const onKey = (e: KeyboardEvent): void => {
    if (e.isTrusted && e.key === 'Enter' && e.target instanceof HTMLInputElement) trigger();
  };

  // Capture phase so we still observe the event even if the page calls stopPropagation.
  document.addEventListener('submit', onSubmit, true);
  document.addEventListener('click', onClick, true);
  document.addEventListener('keydown', onKey, true);

  return () => {
    document.removeEventListener('submit', onSubmit, true);
    document.removeEventListener('click', onClick, true);
    document.removeEventListener('keydown', onKey, true);
  };
}

/** Read the username/password from the first detected login form that currently holds a password. */
export function snapshotLogin(root: ParentNode = document): CapturedLogin | undefined {
  for (const form of detectLoginForms(root)) {
    const password = form.passwordInput?.value;
    if (!password) continue;
    const username = form.usernameInput?.value.trim();
    return username ? { username, password } : { password };
  }
  return undefined;
}
