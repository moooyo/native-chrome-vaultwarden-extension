export interface DetectedLoginForm {
  id: string;
  form: HTMLFormElement | null;
  usernameInput?: HTMLInputElement;
  passwordInput?: HTMLInputElement;
  anchor: HTMLElement;
}

let nextFormId = 0;

const USERNAME_TYPES = ['email', 'text', 'search', 'tel', 'url'];
const NEW_PASSWORD_HINT = /new|confirm|retype|repeat|again|verify/;

export function detectLoginForms(root: ParentNode = document): DetectedLoginForm[] {
  const forms: DetectedLoginForm[] = [];
  const consumedUsernames = new Set<HTMLInputElement>();

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
    const entry: DetectedLoginForm = {
      id: current.dataset.vwAutofillId ?? assignFormId(current),
      form: current.form,
      passwordInput: current,
      anchor: current,
      ...(usernameInput !== undefined ? { usernameInput } : {}),
    };
    if (usernameInput) consumedUsernames.add(usernameInput);
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

function isVisibleInTree(input: HTMLInputElement): boolean {
  if (!input.isConnected) return false;
  const view = input.ownerDocument.defaultView;
  if (!view) return false;
  for (let element: HTMLElement | null = input; element; element = element.parentElement) {
    const style = view.getComputedStyle(element);
    if (element.hidden || style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return true;
}
