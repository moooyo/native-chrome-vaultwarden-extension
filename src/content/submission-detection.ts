import {
  isFillableInput,
  isLoginPasswordCandidate,
  isTotpCandidate,
} from './form-detection.js';

export interface SubmittedCredentials {
  username?: string;
  password: string;
}

export interface SubmittedUsername {
  username: string;
}

const USERNAME_TYPES = new Set(['email', 'text', 'search', 'tel', 'url']);
const CONFIRM_HINT = /(?:^|[^a-z])(?:confirm|confirmation|retype|repeat|again|verify)(?:[^a-z]|$)|(?:confirm|retype|repeat|verify)(?:password|pass|pwd)|(?:password|pass|pwd)(?:confirm|confirmation|retype|repeat|again|verify)/;
const NEW_PASSWORD_HINT = /(?:^|[^a-z])(?:new|create)(?:[^a-z]|$)|(?:new|create)(?:password|pass|pwd)|(?:password|pass|pwd)(?:new|create)/;
const CURRENT_PASSWORD_HINT = /(?:^|[^a-z])(?:current|old|existing)(?:[^a-z]|$)|(?:current|old|existing)(?:password|pass|pwd)|(?:password|pass|pwd)(?:current|old|existing)/;
const USERNAME_HINT = /(?:^|[^a-z])(?:user(?:name)?|email|e-mail|login|account)(?:[^a-z]|$)|(?:user|email|login)(?:name|id|address)/;
const PAYMENT_SECRET_HINT = /(?:^|[^a-z])(?:cvc|cvv|csc|cvn|cid|card[-_ ]?(?:code|pin|password)|security[-_ ]?code|payment[-_ ]?(?:code|pin|password))(?:[^a-z]|$)|(?:card|creditcard|payment)(?:cvc|cvv|csc|cvn|cid|code|pin|password)/;
const PAYMENT_CONTEXT_HINT = /(?:^|[^a-z])(?:card|credit|payment|billing)(?:[^a-z]|$)|cc[-_ ]?(?:number|name|exp|csc)/;

/** Snapshot credentials from controls owned by one native form. `form.elements` is authoritative so
 * controls associated through `form=id` participate even when they are outside the form subtree. */
export function detectNativeFormSubmission(form: HTMLFormElement): SubmittedCredentials | undefined {
  const inputs = nativeFormInputs(form);
  return detectSubmissionFromInputs(inputs);
}

/** Capture only an explicit username-only step. A form containing any fillable password belongs to
 * the ordinary credential path, even while that password is empty. */
export function detectNativeUsernameSubmission(form: HTMLFormElement): SubmittedUsername | undefined {
  return detectUsernameSubmissionFromInputs(nativeFormInputs(form));
}

/** Snapshot a form-less submission only inside a narrow DOM scope associated with the trigger. */
export function detectFormlessSubmission(trigger: HTMLElement): SubmittedCredentials | undefined {
  const scope = findFormlessScope(trigger);
  if (!scope) return undefined;
  const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input.form === null);
  return detectSubmissionFromInputs(inputs);
}

/** Snapshot a form-less username step inside the same narrow explicit scope rules as credentials. */
export function detectFormlessUsernameSubmission(trigger: HTMLElement): SubmittedUsername | undefined {
  const scope = findFormlessUsernameScope(trigger);
  if (!scope) return undefined;
  const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input.form === null);
  return detectUsernameSubmissionFromInputs(inputs);
}

export function detectSubmissionFromInputs(inputs: readonly HTMLInputElement[]): SubmittedCredentials | undefined {
  const fillable = inputs.filter(isFillableInput);
  const passwordInput = selectSubmittedPassword(fillable);
  if (!passwordInput || !passwordInput.value) return undefined;
  const username = selectUsername(fillable)?.value.trim();
  return username ? { username, password: passwordInput.value } : { password: passwordInput.value };
}

export function detectUsernameSubmissionFromInputs(inputs: readonly HTMLInputElement[]): SubmittedUsername | undefined {
  const fillable = inputs.filter(isFillableInput);
  if (fillable.some((input) => input.type === 'password')) return undefined;
  const username = selectUsername(fillable)?.value.trim();
  return username ? { username } : undefined;
}

function nativeFormInputs(form: HTMLFormElement): HTMLInputElement[] {
  return Array.from(form.elements)
    .filter((control): control is HTMLInputElement => control instanceof HTMLInputElement)
    .filter((input) => input.form === form);
}

function selectSubmittedPassword(inputs: readonly HTMLInputElement[]): HTMLInputElement | undefined {
  const passwords = inputs
    .filter((input) => input.type === 'password')
    .filter(isLoginPasswordCandidate)
    .filter((input) => !isPaymentSecret(input, inputs));
  if (passwords.length === 0) return undefined;

  const confirmations = passwords.filter(isConfirmationPassword);
  const nonConfirmations = passwords.filter((input) => !confirmations.includes(input));
  if (confirmations.some(isCurrentPassword)) return undefined;
  if (nonConfirmations.some((input) => isNewPassword(input) && isCurrentPassword(input))) return undefined;
  const newPasswords = nonConfirmations.filter(isNewPassword);
  const currentPasswords = nonConfirmations.filter(isCurrentPassword);
  const unclassified = nonConfirmations.filter((input) => !newPasswords.includes(input) && !currentPasswords.includes(input));

  if (newPasswords.length > 0 || confirmations.length > 0) {
    const primary = newPasswords.length === 1
      ? newPasswords[0]
      : newPasswords.length === 0 && confirmations.length > 0 && unclassified.length === 1
        ? unclassified[0]
        : undefined;
    if (!primary) return undefined;

    // A new-password flow may have one old/current password. Any additional unexplained password
    // makes the target ambiguous, so no page credential is released to the extension.
    const oldCandidates = nonConfirmations.filter((input) => input !== primary);
    if (oldCandidates.length > 1) return undefined;
    if (confirmations.some((input) => input.value !== '' && input.value !== primary.value)) return undefined;
    return primary;
  }

  if (currentPasswords.length === 1 && unclassified.length === 0) return currentPasswords[0];
  if (currentPasswords.length === 0 && unclassified.length === 1) return unclassified[0];
  return undefined;
}

function selectUsername(inputs: readonly HTMLInputElement[]): HTMLInputElement | undefined {
  const candidates = inputs
    .filter((input) => USERNAME_TYPES.has(input.type))
    .filter((input) => !isTotpCandidate(input))
    .filter((input) => !isPaymentField(input));
  const priorities = [
    candidates.filter((input) => autocompleteTokens(input).includes('username')),
    candidates.filter((input) => autocompleteTokens(input).includes('email') || input.type === 'email'),
    candidates.filter((input) => USERNAME_HINT.test(fieldHint(input))),
  ];
  const firstMatch = priorities.find((matches) => matches.length > 0);
  return firstMatch ? unique(firstMatch) : undefined;
}

function unique<T>(values: readonly T[]): T | undefined {
  return values.length === 1 ? values[0] : undefined;
}

function isConfirmationPassword(input: HTMLInputElement): boolean {
  return CONFIRM_HINT.test(fieldHint(input));
}

function isNewPassword(input: HTMLInputElement): boolean {
  return autocompleteTokens(input).includes('new-password') || NEW_PASSWORD_HINT.test(fieldHint(input));
}

function isCurrentPassword(input: HTMLInputElement): boolean {
  return autocompleteTokens(input).includes('current-password') || CURRENT_PASSWORD_HINT.test(fieldHint(input));
}

function isPaymentSecret(input: HTMLInputElement, inputs: readonly HTMLInputElement[]): boolean {
  if (isPaymentField(input) || PAYMENT_SECRET_HINT.test(fieldHint(input))) return true;
  const length = input.maxLength;
  const shortNumericSecret = (length === 3 || length === 4)
    && (input.inputMode === 'numeric' || /\d/.test(input.pattern));
  return shortNumericSecret && inputs.some((candidate) => isPaymentField(candidate) || PAYMENT_CONTEXT_HINT.test(fieldHint(candidate)));
}

function isPaymentField(input: HTMLInputElement): boolean {
  return autocompleteTokens(input).some((token) => token.startsWith('cc-'));
}

function autocompleteTokens(input: HTMLInputElement): string[] {
  return (input.getAttribute('autocomplete') ?? '').trim().toLowerCase().split(/\s+/).filter(Boolean);
}

function fieldHint(input: HTMLInputElement): string {
  return [
    input.name,
    input.id,
    input.getAttribute('aria-label'),
    input.placeholder,
    ...Array.from(input.labels ?? []).map((label) => label.textContent),
  ]
    .filter((value): value is string => Boolean(value))
    .join(' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase();
}

function findFormlessScope(trigger: HTMLElement): HTMLElement | undefined {
  const ancestors = ancestorsBeforeBody(trigger);
  const explicit = ancestors.find((candidate) => candidate.matches('[role="form"], fieldset, dialog, section, article'));
  if (explicit) return hasFormlessPassword(explicit) ? explicit : undefined;

  const submitScoped = ancestors.find((candidate) => hasFormlessPassword(candidate) && hasFormlessSubmitAffordance(candidate));
  if (submitScoped) return submitScoped;

  const credentialScoped = ancestors.find((candidate) => {
    if (!hasFormlessPassword(candidate)) return false;
    return Array.from(candidate.querySelectorAll<HTMLInputElement>('input'))
      .some((input) => input.form === null && isFillableInput(input) && isLikelyUsername(input));
  });
  if (credentialScoped) return credentialScoped;

  return ancestors.find(hasFormlessPassword);
}

function findFormlessUsernameScope(trigger: HTMLElement): HTMLElement | undefined {
  const ancestors = ancestorsBeforeBody(trigger);
  const explicit = ancestors.find((candidate) => candidate.matches('[role="form"], fieldset, dialog, section, article'));
  if (explicit) return hasFormlessUsernameOnlyInput(explicit) ? explicit : undefined;
  return ancestors.find((candidate) => (
    hasFormlessUsernameOnlyInput(candidate) && hasFormlessSubmitAffordance(candidate)
  ));
}

function ancestorsBeforeBody(trigger: HTMLElement): HTMLElement[] {
  const out: HTMLElement[] = [];
  for (let node = trigger.parentElement; node && node !== document.body && node !== document.documentElement; node = node.parentElement) {
    out.push(node);
  }
  return out;
}

function hasFormlessPassword(scope: ParentNode): boolean {
  return Array.from(scope.querySelectorAll<HTMLInputElement>('input[type="password"]'))
    .some((input) => input.form === null && isFillableInput(input));
}

function hasFormlessUsernameOnlyInput(scope: ParentNode): boolean {
  const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input.form === null && isFillableInput(input));
  return !inputs.some((input) => input.type === 'password') && selectUsername(inputs) !== undefined;
}

function hasFormlessSubmitAffordance(scope: ParentNode): boolean {
  return Array.from(scope.querySelectorAll<HTMLElement>('button, input[type="submit"], input[type="image"], [role="button"]'))
    .some((control) => {
      if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement) {
        return control.form === null
          && (control instanceof HTMLButtonElement
            ? control.type === 'submit'
            : control.type === 'submit' || control.type === 'image');
      }
      return isExplicitRoleSubmit(control);
    });
}

/** ARIA button alone does not imply form submission. Require an explicit, machine-readable marker
 * so password-reveal, help, and other ordinary buttons cannot trigger credential capture. */
export function isExplicitRoleSubmit(control: HTMLElement | null | undefined): control is HTMLElement {
  if (control?.getAttribute('role')?.trim().toLowerCase() !== 'button') return false;
  if (control.getAttribute('type')?.trim().toLowerCase() === 'submit') return true;
  const dataSubmit = control.getAttribute('data-submit');
  return dataSubmit !== null && (dataSubmit === '' || dataSubmit.trim().toLowerCase() === 'true');
}

function isLikelyUsername(input: HTMLInputElement): boolean {
  if (!USERNAME_TYPES.has(input.type) || isTotpCandidate(input) || isPaymentField(input)) return false;
  const tokens = autocompleteTokens(input);
  return tokens.includes('username') || tokens.includes('email') || input.type === 'email' || USERNAME_HINT.test(fieldHint(input));
}
