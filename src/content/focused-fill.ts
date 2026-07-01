import { detectLoginForms, type DetectedLoginForm } from './form-detection.js';
import { detectCardForms, detectIdentityForms, type DetectedFillForm } from './field-detection.js';

export type FocusedTarget =
  | { kind: 'login'; form: DetectedLoginForm }
  | { kind: 'card'; form: DetectedFillForm }
  | { kind: 'identity'; form: DetectedFillForm }
  | { kind: 'none' };

export interface FillExclusion {
  /** Real login forms — a login form whose password field is actually a card CVC is dropped. */
  loginForms: DetectedLoginForm[];
  /** The username/password/totp fields of those login forms, to keep them out of card/identity detection. */
  exclude: Set<Element>;
}

/**
 * Single source of truth for the login/card/identity carve-out. Mirrors what attachPopovers did inline:
 * build the set of card CVC fields first, then treat a "login" form whose password IS a CVC as not-a-login.
 */
export function computeFillExclusion(root: ParentNode = document): FillExclusion {
  const cardCodeFields = new Set<Element>();
  for (const card of detectCardForms(root)) {
    const code = card.fields.get('code');
    if (code) cardCodeFields.add(code);
  }
  const loginForms: DetectedLoginForm[] = [];
  const exclude = new Set<Element>();
  for (const form of detectLoginForms(root)) {
    if (form.passwordInput && cardCodeFields.has(form.passwordInput)) continue; // a CVC, not a login
    loginForms.push(form);
    for (const el of [form.usernameInput, form.passwordInput, form.totpInput]) if (el) exclude.add(el);
  }
  return { loginForms, exclude };
}

/**
 * Determine which detected form the focused element belongs to. Precedence (identical to attachPopovers):
 * CVC carve-out (inside computeFillExclusion) → login → card → identity → none.
 */
export function resolveFocusedFill(activeEl: Element | null, root: ParentNode = document): FocusedTarget {
  if (!(activeEl instanceof HTMLInputElement || activeEl instanceof HTMLSelectElement)) return { kind: 'none' };
  const { loginForms, exclude } = computeFillExclusion(root);
  for (const form of loginForms) {
    if (activeEl === form.usernameInput || activeEl === form.passwordInput || activeEl === form.totpInput) {
      return { kind: 'login', form };
    }
  }
  for (const form of detectCardForms(root, exclude)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'card', form };
  }
  for (const form of detectIdentityForms(root, exclude)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'identity', form };
  }
  return { kind: 'none' };
}
