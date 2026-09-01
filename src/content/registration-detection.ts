// Detects "generatable" new-password fields for the inline generation panel (design 2e): a
// new-password field (autocomplete=new-password or a new/create hint) that is NOT a confirm/retype
// field, one per form scope, with the scope's username field resolved for the save. Login forms use
// the *current* password (selectCurrentPassword excludes new-password), so this never overlaps them.

import { inputControlsInScope, isFillableInput, isNewPasswordField } from './form-detection.js';
import { classifyCardField } from './field-map.js';

export interface DetectedRegistrationField {
  id: string;
  input: HTMLInputElement;
  form: HTMLFormElement | null;
  usernameInput?: HTMLInputElement;
  anchor: HTMLElement;
}

const CONFIRM_HINT = /confirm|retype|repeat|again|verify/;
const USERNAME_TYPES = ['email', 'text', 'tel', 'url'];
let nextGenId = 0;
const generationIds = new WeakMap<HTMLInputElement, {
  readonly scope: ParentNode;
  readonly usernameInput: HTMLInputElement | undefined;
  readonly id: string;
}>();

function fieldHint(input: HTMLInputElement): string {
  return `${input.name} ${input.id} ${input.autocomplete} ${input.getAttribute('aria-label') ?? ''}`.toLowerCase();
}

function isConfirmField(input: HTMLInputElement): boolean {
  return CONFIRM_HINT.test(fieldHint(input));
}

function scopeOf(input: HTMLInputElement): ParentNode {
  const root = input.getRootNode();
  return input.form
    ?? input.closest('section, main, article')
    ?? (root.nodeType === Node.DOCUMENT_NODE ? root as Document : root as ShadowRoot);
}

function findUsernameInput(scope: ParentNode, exclude: HTMLInputElement): HTMLInputElement | undefined {
  return inputControlsInScope(scope)
    .filter((input) => input !== exclude && isFillableInput(input) && USERNAME_TYPES.includes(input.type))
    .filter((input) => classifyCardField({
      autocomplete: input.autocomplete,
      name: input.name,
      id: input.id,
      ariaLabel: input.getAttribute('aria-label') ?? '',
      placeholder: input.placeholder,
      type: input.type,
    }) === undefined)
    .find((input) => {
      const hint = fieldHint(input);
      return input.type === 'email' || hint.includes('user') || hint.includes('email') || hint.includes('login');
    });
}

function assignId(
  input: HTMLInputElement,
  scope: ParentNode,
  usernameInput: HTMLInputElement | undefined,
): string {
  const existing = generationIds.get(input);
  if (existing?.scope === scope && existing.usernameInput === usernameInput) return existing.id;
  const id = `vw-gen-${nextGenId++}`;
  generationIds.set(input, { scope, usernameInput, id });
  return id;
}

export function detectRegistrationFields(root: ParentNode = document): DetectedRegistrationField[] {
  const out: DetectedRegistrationField[] = [];
  const seenScopes = new Set<ParentNode>();
  const passwords = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter(isFillableInput);
  for (const pw of passwords) {
    const match = matchRegistrationField(pw);
    if (!match) continue;
    const scope = scopeOf(pw);
    if (seenScopes.has(scope)) continue;
    seenScopes.add(scope);
    out.push(match);
  }
  return out;
}

/** Single-field matcher (used on focus): returns the registration target for a generatable
 *  new-password field, or undefined when the field isn't one (confirm field, current-password, etc.). */
export function matchRegistrationField(input: HTMLInputElement): DetectedRegistrationField | undefined {
  if (input.type !== 'password' || !isFillableInput(input)) return undefined;
  if (!isNewPasswordField(input) || isConfirmField(input)) return undefined;
  const scope = scopeOf(input);
  const usernameInput = findUsernameInput(scope, input);
  return {
    id: assignId(input, scope, usernameInput),
    input,
    form: input.form,
    anchor: input,
    ...(usernameInput !== undefined ? { usernameInput } : {}),
  };
}

/** The confirm/retype password fields in the same scope as a generated new-password field. Used to
 *  fill them with the same value when the user accepts a generated password, so a signup form's
 *  "confirm password" field doesn't stay empty and block submission. */
export function findConfirmPasswordFields(passwordInput: HTMLInputElement): HTMLInputElement[] {
  const scope = scopeOf(passwordInput);
  return inputControlsInScope(scope)
    .filter((el) => el.type === 'password' && el !== passwordInput && isFillableInput(el) && isConfirmField(el));
}

