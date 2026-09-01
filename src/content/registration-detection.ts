// Detects "generatable" new-password fields for the inline generation panel (design 2e): a
// new-password field (autocomplete=new-password or a new/create hint) that is NOT a confirm/retype
// field, one per form scope, with the scope's username field resolved for the save. Login forms use
// the *current* password (selectCurrentPassword excludes new-password), so this never overlaps them.

import {
  inputControlsInScope,
  isFillableInput,
  isNewPasswordField,
  isSemanticSourceAvailableInTree,
} from './form-detection.js';
import { classifyCardField } from './field-map.js';
import { collectFieldHints } from './semantic-hints.js';
import {
  createScopedAutofillDetectionContext,
  type AutofillDetectionContext,
} from './autofill-detection-context.js';

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

function fieldHints(input: HTMLInputElement, context: AutofillDetectionContext) {
  return context.fieldHints(
    input,
    (budget) => collectFieldHints(input, isSemanticSourceAvailableInTree, budget),
  );
}

function fieldHint(input: HTMLInputElement, context: AutofillDetectionContext): string {
  const hints = fieldHints(input, context);
  return `${hints.name} ${hints.id} ${hints.autocomplete} ${hints.ariaLabel} ${hints.placeholder}`
    .toLowerCase();
}

function isConfirmField(input: HTMLInputElement, context: AutofillDetectionContext): boolean {
  return context.complete && CONFIRM_HINT.test(fieldHint(input, context));
}

function scopeOf(input: HTMLInputElement): ParentNode {
  const root = input.getRootNode();
  return input.form
    ?? input.closest('section, main, article')
    ?? (root.nodeType === Node.DOCUMENT_NODE ? root as Document : root as ShadowRoot);
}

function findUsernameInput(
  scope: ParentNode,
  exclude: HTMLInputElement,
  context: AutofillDetectionContext,
): HTMLInputElement | undefined {
  return inputControlsInScope(scope, context)
    .filter((input) => input !== exclude && isFillableInput(input) && USERNAME_TYPES.includes(input.type))
    .filter((input) => classifyCardField(fieldHints(input, context)) === undefined)
    .find((input) => {
      const hint = fieldHint(input, context);
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

export function detectRegistrationFields(
  root: ParentNode = document,
  context: AutofillDetectionContext = createScopedAutofillDetectionContext(root),
): DetectedRegistrationField[] {
  if (!context.complete) return [];
  const out: DetectedRegistrationField[] = [];
  const seenScopes = new Set<ParentNode>();
  const passwords = context.inputsWithin(root)
    .filter((input) => input.type === 'password')
    .filter(isFillableInput);
  for (const pw of passwords) {
    const match = matchRegistrationField(pw, context);
    if (!match) continue;
    const scope = scopeOf(pw);
    if (seenScopes.has(scope)) continue;
    seenScopes.add(scope);
    out.push(match);
  }
  return context.complete ? out : [];
}

/** Single-field matcher (used on focus): returns the registration target for a generatable
 *  new-password field, or undefined when the field isn't one (confirm field, current-password, etc.). */
export function matchRegistrationField(
  input: HTMLInputElement,
  context: AutofillDetectionContext = detectionContextFor(input),
): DetectedRegistrationField | undefined {
  if (!context.complete) return undefined;
  if (input.type !== 'password' || !isFillableInput(input)) return undefined;
  if (!isNewPasswordField(input, context) || isConfirmField(input, context) || !context.complete) return undefined;
  const scope = scopeOf(input);
  const usernameInput = findUsernameInput(scope, input, context);
  if (!context.complete) return undefined;
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
export function findConfirmPasswordFields(
  passwordInput: HTMLInputElement,
  context: AutofillDetectionContext = detectionContextFor(passwordInput),
): HTMLInputElement[] {
  if (!context.complete) return [];
  const scope = scopeOf(passwordInput);
  const result = inputControlsInScope(scope, context)
    .filter((el) => el.type === 'password'
      && el !== passwordInput
      && isFillableInput(el)
      && isConfirmField(el, context));
  return context.complete ? result : [];
}

function detectionContextFor(input: HTMLInputElement): AutofillDetectionContext {
  const root = input.getRootNode();
  return createScopedAutofillDetectionContext(
    root.nodeType === Node.DOCUMENT_NODE || root.nodeType === Node.DOCUMENT_FRAGMENT_NODE
      ? root as Document | ShadowRoot
      : input.ownerDocument,
  );
}

