export interface DetectedLoginForm {
  id: string;
  form: HTMLFormElement | null;
  usernameInput?: HTMLInputElement;
  passwordInput?: HTMLInputElement;
  /** A one-time-code / TOTP field, when one is present in the form's scope. */
  totpInput?: HTMLInputElement;
  anchor: HTMLElement;
}

let nextFormId = 0;

const USERNAME_TYPES = ['email', 'text', 'search', 'tel', 'url'];
const TOTP_TYPES = ['text', 'tel', 'number'];
const NEW_PASSWORD_HINT = /new|confirm|retype|repeat|again|verify/;
// One-time-code hints: the standard `autocomplete="one-time-code"` plus common name/id patterns.
const TOTP_HINT = /otp|one[-_ ]?time|mfa|2fa|two[-_ ]?factor|authenticator|verif(?:y|ication)?[-_ ]?code|security[-_ ]?code|auth[-_ ]?code/;

export function detectLoginForms(root: ParentNode = document): DetectedLoginForm[] {
  const forms: DetectedLoginForm[] = [];
  const consumedUsernames = new Set<HTMLInputElement>();
  const consumedTotps = new Set<HTMLInputElement>();

  // 1) Password-based forms. Passwords inside the same <form> collapse to ONE form (change-password
  //    blocks); formless passwords stay one-per-field so distinct logins under a shared ancestor are
  //    not coalesced. A group with only new-password fields emits no fillable password form.
  const passwords = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter(isFillableInput);
  const seenForms = new Set<HTMLFormElement>();
  const handled = new Set<HTMLInputElement>();
  for (const pw of passwords) {
    if (handled.has(pw)) continue;
    let group: HTMLInputElement[];
    if (pw.form) {
      if (seenForms.has(pw.form)) continue;
      seenForms.add(pw.form);
      group = passwords.filter((p) => p.form === pw.form);
    } else {
      group = [pw];
    }
    group.forEach((p) => handled.add(p));
    const current = selectCurrentPassword(group);
    if (!current) continue; // every field is a new-password field → nothing safe to fill
    const scope = current.form ?? nearestContainer(current);
    const usernameInput = findUsernameInput(scope, current);
    const totpInput = findTotpInput(scope, current, usernameInput);
    const entry: DetectedLoginForm = {
      id: current.dataset.vwAutofillId ?? assignFormId(current),
      form: current.form,
      passwordInput: current,
      anchor: current,
      ...(usernameInput !== undefined ? { usernameInput } : {}),
      ...(totpInput !== undefined ? { totpInput } : {}),
    };
    if (usernameInput) consumedUsernames.add(usernameInput);
    if (totpInput) consumedTotps.add(totpInput);
    forms.push(entry);
  }

  // 2) Username-only steps: a visible username/email field whose container has no fillable
  //    password yet (two-step logins). Requires a submit affordance to avoid false positives.
  const candidates = Array.from(root.querySelectorAll<HTMLInputElement>('input')).filter(isFillableInput).filter(isUsernameCandidate);
  const seenUserContainers = new Set<ParentNode>();
  for (const u of candidates) {
    if (consumedUsernames.has(u)) continue;
    const container = u.form ?? nearestContainer(u);
    if (seenUserContainers.has(container)) continue;
    const containerHasPassword = Array.from(container.querySelectorAll<HTMLInputElement>('input[type="password"]')).some(isFillableInput);
    if (containerHasPassword) continue;
    if (!hasSubmitAffordance(container, u)) continue;
    seenUserContainers.add(container);
    forms.push({
      id: u.dataset.vwAutofillId ?? assignFormId(u),
      form: u.form,
      usernameInput: u,
      anchor: u,
    });
  }

  // 3) Standalone verification-code steps: a one-time-code field whose container has no fillable
  //    password (the second step of a 2FA flow). Requires a submit affordance, like the username step.
  const totpCandidates = Array.from(root.querySelectorAll<HTMLInputElement>('input')).filter(isFillableInput).filter(isTotpCandidate);
  const seenTotpContainers = new Set<ParentNode>();
  for (const t of totpCandidates) {
    if (consumedTotps.has(t)) continue;
    const container = t.form ?? nearestContainer(t);
    if (seenTotpContainers.has(container)) continue;
    const containerHasPassword = Array.from(container.querySelectorAll<HTMLInputElement>('input[type="password"]')).some(isFillableInput);
    if (containerHasPassword) continue;
    if (!hasSubmitAffordance(container, t)) continue;
    seenTotpContainers.add(container);
    forms.push({
      id: t.dataset.vwAutofillId ?? assignFormId(t),
      form: t.form,
      totpInput: t,
      anchor: t,
    });
  }

  return forms;
}

export function isFillableInput(input: HTMLInputElement): boolean {
  const editable = input.type !== 'hidden' && !input.hidden && !input.disabled && !input.readOnly;
  if (!editable) return false;
  if (!isVisibleInTree(input)) return false;
  if (input.offsetParent != null) return true;
  return input.isConnected;
}

/** Pick the current-password field from a group, or undefined when every field is a new-password field. */
function selectCurrentPassword(passwords: HTMLInputElement[]): HTMLInputElement | undefined {
  const byAutocomplete = passwords.find((p) => p.autocomplete === 'current-password');
  if (byAutocomplete) return byAutocomplete;
  return passwords.find((p) => !isNewPasswordField(p));
}

export function isNewPasswordField(input: HTMLInputElement): boolean {
  if (input.autocomplete === 'new-password') return true;
  return NEW_PASSWORD_HINT.test(fieldHint(input));
}

function isUsernameCandidate(input: HTMLInputElement): boolean {
  if (!USERNAME_TYPES.includes(input.type)) return false;
  const hint = fieldHint(input);
  return hint.includes('user') || hint.includes('email') || hint.includes('login') || input.type === 'email';
}

/** A one-time-code / TOTP field: an `autocomplete="one-time-code"` field or a code-named text field. */
export function isTotpCandidate(input: HTMLInputElement): boolean {
  if (!TOTP_TYPES.includes(input.type)) return false;
  if (input.autocomplete === 'one-time-code') return true;
  return TOTP_HINT.test(fieldHint(input));
}

function hasSubmitAffordance(container: ParentNode, usernameInput: HTMLInputElement): boolean {
  if (usernameInput.form) return true; // a wrapping <form> submits on Enter
  return container.querySelector('button:not([type="button"]), input[type="submit"], input[type="image"], [role="button"]') !== null;
}

function fieldHint(input: HTMLInputElement): string {
  return `${input.name} ${input.id} ${input.autocomplete} ${input.getAttribute('aria-label') ?? ''}`.toLowerCase();
}

function assignFormId(input: HTMLInputElement): string {
  const id = `vw-form-${nextFormId++}`;
  input.dataset.vwAutofillId = id;
  return id;
}

function nearestContainer(input: HTMLInputElement): ParentNode {
  return input.closest('form, section, main, article') ?? document;
}

function findUsernameInput(container: ParentNode, passwordInput: HTMLInputElement): HTMLInputElement | undefined {
  const candidates = Array.from(container.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input !== passwordInput)
    .filter(isFillableInput)
    .filter(isUsernameCandidate);
  return candidates.at(-1);
}

/** Find a one-time-code field in scope, excluding the already-claimed password and username inputs. */
function findTotpInput(
  container: ParentNode,
  passwordInput: HTMLInputElement,
  usernameInput: HTMLInputElement | undefined,
): HTMLInputElement | undefined {
  return Array.from(container.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input !== passwordInput && input !== usernameInput)
    .filter(isFillableInput)
    .filter(isTotpCandidate)
    .at(0);
}

export function isVisibleInTree(element: HTMLElement): boolean {
  if (!element.isConnected) return false;
  const view = element.ownerDocument.defaultView;
  if (!view) return false;
  for (let node: HTMLElement | null = element; node; node = node.parentElement) {
    const style = view.getComputedStyle(node);
    if (node.hidden || style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return true;
}
