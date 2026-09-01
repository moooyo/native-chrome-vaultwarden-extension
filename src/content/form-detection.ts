import { isAutofillIgnored } from './autofill-ignore.js';
import {
  classifyCardField,
  hasCardFieldEvidence,
  hasCardNumberEvidence,
  type FieldHints,
} from './field-map.js';
import { associatedLabelsFor, collectFieldHints } from './semantic-hints.js';

export interface DetectedLoginForm {
  id: string;
  form: HTMLFormElement | null;
  usernameInput?: HTMLInputElement;
  passwordInput?: HTMLInputElement;
  /** A one-time-code / TOTP field, when one is present in the form's scope. */
  totpInput?: HTMLInputElement;
  /** The stable DOM-ordered inputs for a safely recognized split-code group. */
  totpInputs?: readonly HTMLInputElement[];
  anchor: HTMLElement;
}

export type OwnerTrackedControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

export interface ControlOwnerSnapshot {
  readonly ownerDocument: Document;
  readonly root: Node;
  readonly formOwner: HTMLFormElement | null;
  readonly composedContainer: ParentNode;
  readonly slotPath: readonly HTMLSlotElement[];
}

let nextFormId = 0;
interface FormIdentity {
  readonly scope: ParentNode;
  readonly root: Node;
  readonly slotPath: readonly HTMLSlotElement[];
  readonly usernameInput: HTMLInputElement | undefined;
  readonly passwordInput: HTMLInputElement | undefined;
  readonly totpInput: HTMLInputElement | undefined;
  readonly totpInputs: readonly HTMLInputElement[];
  readonly fieldOwners: readonly (readonly [HTMLInputElement, ControlOwnerSnapshot])[];
  readonly id: string;
}
const formIds = new WeakMap<HTMLInputElement, FormIdentity>();

const USERNAME_TYPES = ['email', 'text', 'search', 'tel', 'url'];
const USERNAME_FALLBACK_TYPES = ['email', 'text', 'tel'];
const SEARCH_FIELD_TOKENS = new Set(['q', 'query', 'search']);
const TOTP_TYPES = ['text', 'tel', 'number'];
const MAX_TOTP_INPUT_GROUP_SIZE = 12;
const MIN_INTERACTABLE_SIZE = 10;
const NEW_PASSWORD_HINT = /new|confirm|retype|repeat|again|verify/;
// One-time-code hints: the standard `autocomplete="one-time-code"` plus common name/id patterns.
const TOTP_HINT = /otp|one[-_ ]?time|mfa|2fa|two[-_ ]?factor|authenticator|verif(?:y|ication)?[-_ ]?code|security[-_ ]?code|auth[-_ ]?code/;
const STRONG_CARD_CODE_HINT = /cvc|cvv|csc|card.?security.?code|card.?verification.?value/;
const HIDDEN_CLIP_PATHS = new Set([
  'inset(50%)',
  'inset(50% 50% 50% 50%)',
  'inset(100%)',
  'circle(0)',
  'circle(0px)',
  'circle(0px at 50% 50%)',
  'polygon(0 0, 0 0, 0 0, 0 0)',
  'polygon(0px 0px, 0px 0px, 0px 0px, 0px 0px)',
]);

export function detectLoginForms(root: ParentNode = document): DetectedLoginForm[] {
  const forms: DetectedLoginForm[] = [];
  const consumedUsernames = new Set<HTMLInputElement>();
  const consumedTotps = new Set<HTMLInputElement>();

  // 1) Password-based forms. Passwords inside the same <form> collapse to ONE form (change-password
  //    blocks); formless passwords stay one-per-field so distinct logins under a shared ancestor are
  //    not coalesced. A group with only new-password fields emits no fillable password form.
  const passwords = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]'))
    .filter(isFillableInput)
    .filter(isLoginPasswordCandidate);
  const seenForms = new Set<HTMLFormElement>();
  const handled = new Set<HTMLInputElement>();
  for (const pw of passwords) {
    if (handled.has(pw)) continue;
    let group: HTMLInputElement[];
    if (pw.form) {
      if (seenForms.has(pw.form)) continue;
      seenForms.add(pw.form);
      group = inputControlsInScope(pw.form)
        .filter((input) => input.type === 'password')
        .filter(isFillableInput)
        .filter(isLoginPasswordCandidate);
    } else {
      group = [pw];
    }
    group.forEach((p) => handled.add(p));
    const current = selectCurrentPassword(group);
    if (!current) continue; // every field is a new-password field → nothing safe to fill
    const scope = current.form ?? nearestContainer(current);
    const usernameInput = findUsernameInput(scope, current);
    const totpInput = findTotpInput(scope, current, usernameInput);
    const totpInputs = totpInput ? detectedTotpInputs(totpInput) : [];
    const entry: DetectedLoginForm = {
      id: assignFormId(current, scope, usernameInput, current, totpInput, totpInputs),
      form: current.form,
      passwordInput: current,
      anchor: current,
      ...(usernameInput !== undefined ? { usernameInput } : {}),
      ...(totpInput !== undefined ? { totpInput, totpInputs } : {}),
    };
    if (usernameInput) consumedUsernames.add(usernameInput);
    totpInputs.forEach((input) => consumedTotps.add(input));
    forms.push(entry);
  }

  // 2) Username-only steps: a visible username/email field whose container has no fillable
  //    password yet (two-step logins). Requires a submit affordance to avoid false positives.
  const candidates = Array.from(root.querySelectorAll<HTMLInputElement>('input')).filter(isFillableInput).filter(isUsernameCandidate);
  const seenUserOwners: HTMLInputElement[] = [];
  for (const u of candidates) {
    if (consumedUsernames.has(u)) continue;
    const container = u.form ?? nearestContainer(u);
    if (seenUserOwners.some((seen) => sameDetectionOwner(seen, u))) continue;
    const containerHasPassword = inputControlsInScope(container)
      .some((input) => (
        sameDetectionOwner(u, input)
        && input.type === 'password'
        && isFillableInput(input)
        && isLoginPasswordCandidate(input)
      ));
    if (containerHasPassword) continue;
    if (!hasSubmitAffordance(container, u)) continue;
    seenUserOwners.push(u);
    forms.push({
      id: assignFormId(u, container, u, undefined, undefined, []),
      form: u.form,
      usernameInput: u,
      anchor: u,
    });
  }

  // 3) Standalone verification-code steps: a one-time-code field whose container has no fillable
  //    password (the second step of a 2FA flow). Requires a submit affordance, like the username step.
  const totpCandidates = Array.from(root.querySelectorAll<HTMLInputElement>('input')).filter(isFillableInput).filter(isTotpCandidate);
  const seenTotpOwners: HTMLInputElement[] = [];
  for (const t of totpCandidates) {
    if (consumedTotps.has(t)) continue;
    const container = t.form ?? nearestContainer(t);
    if (seenTotpOwners.some((seen) => sameDetectionOwner(seen, t))) continue;
    const containerHasPassword = inputControlsInScope(container)
      .some((input) => (
        sameDetectionOwner(t, input)
        && input.type === 'password'
        && isFillableInput(input)
        && isLoginPasswordCandidate(input)
      ));
    if (containerHasPassword) continue;
    if (!hasSubmitAffordance(container, t)) continue;
    const totpInputs = detectedTotpInputs(t);
    seenTotpOwners.push(t);
    forms.push({
      id: assignFormId(t, container, undefined, undefined, t, totpInputs),
      form: t.form,
      totpInput: t,
      totpInputs,
      anchor: t,
    });
    totpInputs.forEach((input) => consumedTotps.add(input));
  }

  return forms;
}

export function isFillableInput(input: HTMLInputElement): boolean {
  const editable = !isAutofillIgnored(input)
    && input.type !== 'hidden'
    && !input.hidden
    && !input.disabled
    && !input.matches(':disabled')
    && !input.readOnly;
  return editable && isElementInteractable(input);
}

/** Pick the current-password field from a group, or undefined when every field is a new-password field. */
function selectCurrentPassword(passwords: HTMLInputElement[]): HTMLInputElement | undefined {
  const byAutocomplete = passwords.find(hasCurrentPasswordAutocomplete);
  if (byAutocomplete) return byAutocomplete;
  return passwords.find((p) => !isNewPasswordField(p));
}

export function isNewPasswordField(input: HTMLInputElement): boolean {
  if (hasCanonicalPasswordAutocomplete(input, 'new-password')) return true;
  if (hasCanonicalPasswordAutocomplete(input, 'current-password')) return false;
  const hints = semanticHintsFor(input);
  const text = fieldHintText(hints);
  return hints.semanticLabelsUnsafe !== true
    && !hasCardFieldEvidence(hints)
    && !TOTP_HINT.test(text)
    && NEW_PASSWORD_HINT.test(text);
}

/** Match a password autocomplete field token only when its optional prefixes and webauthn suffix
 * follow the HTML token-list grammar. */
export function hasCurrentPasswordAutocomplete(input: HTMLInputElement): boolean {
  return hasCanonicalPasswordAutocomplete(input, 'current-password');
}

function hasCanonicalPasswordAutocomplete(
  input: HTMLInputElement,
  field: 'current-password' | 'new-password',
): boolean {
  return hasCanonicalPasswordAutocompleteValue(semanticHintsFor(input).autocomplete, field);
}

function hasCanonicalPasswordAutocompleteValue(
  value: string,
  field: 'current-password' | 'new-password',
): boolean {
  if (!value) return false;
  const tokens = value.toLowerCase().split(/[\t\n\f\r ]+/u).filter(Boolean);
  if (tokens.at(-1) === 'webauthn') tokens.pop();
  if (tokens.pop() !== field) return false;
  if (tokens[0]?.startsWith('section-')) {
    if (tokens[0].length === 'section-'.length) return false;
    tokens.shift();
  }
  if (tokens[0] === 'shipping' || tokens[0] === 'billing') tokens.shift();
  return tokens.length === 0;
}

function isUsernameCandidate(input: HTMLInputElement): boolean {
  if (!USERNAME_TYPES.includes(input.type)) return false;
  const hints = semanticHintsFor(input);
  const tokens = autocompleteTokens(hints.autocomplete);
  if (hasCardFieldEvidence(hints) || tokens.has('one-time-code') || tokens.has('cc-csc')) return false;
  if (hasUsernameAutocomplete(hints)) return true;
  if (hints.semanticLabelsUnsafe) return false;
  const hint = fieldHintText(hints);
  if (TOTP_HINT.test(hint)) return false;
  return hint.includes('user') || hint.includes('email') || hint.includes('login') || input.type === 'email';
}

/** A one-time-code / TOTP field: an `autocomplete="one-time-code"` field or a code-named text field. */
export function isTotpCandidate(input: HTMLInputElement): boolean {
  if (isAutofillIgnored(input)) return false;
  const hints = semanticHintsFor(input);
  const tokens = autocompleteTokens(hints.autocomplete);
  const oneTimeCode = tokens.has('one-time-code');
  const cardCode = tokens.has('cc-csc');
  if (oneTimeCode && cardCode) return false;
  if (!TOTP_TYPES.includes(input.type) && !(input.type === 'password' && oneTimeCode)) return false;
  if (oneTimeCode) return true;
  if (cardCode) return false;
  if (hints.semanticLabelsUnsafe || hasStrongCardCodeHint(hints)) return false;
  if (isCardSecurityCodeInContext(input, hints)) return false;
  return TOTP_HINT.test(fieldHintText(hints));
}

export function isLoginPasswordCandidate(input: HTMLInputElement): boolean {
  const hints = semanticHintsFor(input);
  const tokens = autocompleteTokens(hints.autocomplete);
  if (tokens.has('one-time-code') || tokens.has('cc-csc')) return false;
  if (
    hasCanonicalPasswordAutocompleteValue(hints.autocomplete, 'current-password')
    || hasCanonicalPasswordAutocompleteValue(hints.autocomplete, 'new-password')
  ) return true;
  if (hints.semanticLabelsUnsafe || hasCardFieldEvidence(hints)) return false;
  return !TOTP_HINT.test(fieldHintText(hints));
}

export function hasConflictingSecurityCodeAutocomplete(input: HTMLInputElement): boolean {
  return hasOneTimeCodeAutocomplete(input) && hasCardCodeAutocomplete(input);
}

/** A textual "security code" is a CVC when its own form/owner also contains a card number. */
function isCardSecurityCodeInContext(input: HTMLInputElement, hints = semanticHintsFor(input)): boolean {
  if (classifyCardField(hints) !== 'code') return false;
  const scope = input.form ?? nearestContainer(input);
  return inputControlsInScope(scope).some((candidate) => (
    candidate !== input
    && sameDetectionOwner(input, candidate)
    && !isAutofillIgnored(candidate)
    && candidate.type !== 'hidden'
    && !candidate.hidden
    && isVisibleInTree(candidate)
    && (() => {
      const candidateHints = semanticHintsFor(candidate);
      return candidateHints.semanticLabelsUnsafe
        || hasCardNumberEvidence(candidateHints);
    })()
  ));
}

function semanticHintsFor(input: HTMLInputElement): FieldHints {
  return collectFieldHints(input, isVisibleInTree);
}

function hasStrongCardCodeHint(hints: FieldHints): boolean {
  return [
    hints.name,
    hints.id,
    hints.ariaLabel,
    hints.placeholder,
    ...(hints.semanticLabels ?? []),
  ].some((value) => STRONG_CARD_CODE_HINT.test(value.toLowerCase()));
}

/**
 * Resolve one live TOTP input to either itself or a conservative split-code group. A group is
 * accepted only inside the nearest local container that has multiple OTP-like/single-character
 * inputs, and every member must remain in the same form/root, be editable, and have stable DOM
 * order. Undefined means the page exposed an ambiguous or unsafe cluster.
 */
export function resolveTotpInputs(input: HTMLInputElement): readonly HTMLInputElement[] | undefined {
  if (!isTotpCompatibleInput(input) || !isFillableInput(input)) return undefined;
  const boundary = input.form ?? nearestContainer(input);
  const cluster = nearestTotpCluster(input, boundary);
  if (!cluster) return isTotpCandidate(input) ? [input] : undefined;
  if (
    cluster.length > MAX_TOTP_INPUT_GROUP_SIZE
    || !cluster.some(isTotpCandidate)
    || (!cluster.every(isSingleCharacterInput) && !cluster.every(hasOneTimeCodeAutocomplete))
    || cluster.some((candidate) => (
      candidate.form !== input.form
      || candidate.getRootNode() !== input.getRootNode()
      || !hasSameComposedSlotPath(candidate, input)
      || !isFillableInput(candidate)
    ))
    || !hasStableDomOrder(cluster)
  ) return undefined;
  return cluster;
}

export function totpInputsForForm(form: DetectedLoginForm): readonly HTMLInputElement[] {
  if (form.totpInputs !== undefined) return form.totpInputs;
  return form.totpInput ? [form.totpInput] : [];
}

export function hasSameTotpInputs(first: DetectedLoginForm, second: DetectedLoginForm): boolean {
  return sameInputs(totpInputsForForm(first), totpInputsForForm(second));
}

export function hasLoginCredentialTarget(form: DetectedLoginForm): boolean {
  return form.usernameInput !== undefined || form.passwordInput !== undefined;
}

/**
 * Reserve each OTP anchor's nearest raw companion cluster in one detector scope. This intentionally
 * includes unsafe and secondary groups so custom-field filling cannot claim them, while leaving
 * unrelated single-character controls alone. Actual TOTP writes continue to use resolveTotpInputs().
 */
export function reservedTotpInputs(scope: ParentNode): ReadonlySet<HTMLInputElement> {
  const controls = inputControlsInScope(scope);
  const scoped = new Set(controls);
  const reserved = new Set<HTMLInputElement>();
  for (const anchor of controls.filter(isTotpCandidate)) {
    for (const candidate of rawLocalTotpCluster(anchor, scope)) {
      if (scoped.has(candidate)) reserved.add(candidate);
    }
  }
  return reserved;
}

function hasSubmitAffordance(container: ParentNode, usernameInput: HTMLInputElement): boolean {
  if (usernameInput.form) return true; // a wrapping <form> submits on Enter
  return container.querySelector('button:not([type="button"]), input[type="submit"], input[type="image"], [role="button"]') !== null;
}

function fieldHintText(hints: FieldHints): string {
  return [
    hints.name,
    hints.id,
    hints.autocomplete,
    hints.ariaLabel,
    hints.placeholder,
    ...(hints.semanticLabels ?? []),
  ].join(' ').toLowerCase();
}

function assignFormId(
  input: HTMLInputElement,
  scope: ParentNode,
  usernameInput: HTMLInputElement | undefined,
  passwordInput: HTMLInputElement | undefined,
  totpInput: HTMLInputElement | undefined,
  totpInputs: readonly HTMLInputElement[],
): string {
  const existing = formIds.get(input);
  const root = input.getRootNode();
  const slotPath = composedSlotPath(input);
  const fieldOwners = [...new Set([
    usernameInput,
    passwordInput,
    totpInput,
    ...totpInputs,
  ].filter((field): field is HTMLInputElement => field !== undefined))]
    .map((field) => [field, captureControlOwner(field)] as const);
  if (
    existing?.scope === scope
    && existing.root === root
    && sameSlots(existing.slotPath, slotPath)
    && existing.usernameInput === usernameInput
    && existing.passwordInput === passwordInput
    && existing.totpInput === totpInput
    && sameInputs(existing.totpInputs, totpInputs)
    && sameFieldOwners(existing.fieldOwners, fieldOwners)
  ) return existing.id;
  const id = `vw-form-${nextFormId++}`;
  formIds.set(input, {
    scope,
    root,
    slotPath,
    usernameInput,
    passwordInput,
    totpInput,
    totpInputs: [...totpInputs],
    fieldOwners,
    id,
  });
  return id;
}

function nearestContainer(input: HTMLInputElement): ParentNode {
  return input.closest('form, section, main, article') ?? treeRoot(input);
}

function findUsernameInput(container: ParentNode, passwordInput: HTMLInputElement): HTMLInputElement | undefined {
  const candidates = inputControlsInScope(container)
    .filter((input) => input !== passwordInput && inputPrecedes(input, passwordInput))
    .filter((input) => sameDetectionOwner(passwordInput, input))
    .filter(isFillableInput)
    .filter((input) => !isTotpCandidate(input))
    .filter((input) => {
      const hints = semanticHintsFor(input);
      return (!hints.semanticLabelsUnsafe || hasUsernameAutocomplete(hints))
        && !hasCardFieldEvidence(hints);
    });
  const hinted = candidates.filter(isUsernameCandidate);
  if (hinted.length > 0) return nearestInput(hinted);
  if (!passwordInput.form || container !== passwordInput.form) return undefined;
  return nearestInput(candidates.filter(isUsernameFallbackCandidate));
}

function inputPrecedes(input: HTMLInputElement, reference: HTMLInputElement): boolean {
  return Boolean(input.compareDocumentPosition(reference) & Node.DOCUMENT_POSITION_FOLLOWING);
}

function nearestInput(inputs: readonly HTMLInputElement[]): HTMLInputElement | undefined {
  return inputs.reduce<HTMLInputElement | undefined>((nearest, input) => (
    !nearest || inputPrecedes(nearest, input) ? input : nearest
  ), undefined);
}

function isUsernameFallbackCandidate(input: HTMLInputElement): boolean {
  return input.type !== 'search'
    && USERNAME_FALLBACK_TYPES.includes(input.type)
    && !hasExplicitSearchHint(input);
}

function hasExplicitSearchHint(input: HTMLInputElement): boolean {
  const hints = semanticHintsFor(input);
  if (hints.semanticLabelsUnsafe) return true;
  const tokens = fieldHintText(hints)
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return tokens.some((token) => SEARCH_FIELD_TOKENS.has(token));
}

function hasUsernameAutocomplete(hints: FieldHints): boolean {
  const tokens = hints.autocomplete.toLowerCase().trim().split(/\s+/u).filter(Boolean);
  return tokens.includes('username') || tokens.includes('email');
}

/** Find a one-time-code field in scope, excluding the already-claimed password and username inputs. */
function findTotpInput(
  container: ParentNode,
  passwordInput: HTMLInputElement,
  usernameInput: HTMLInputElement | undefined,
): HTMLInputElement | undefined {
  return inputControlsInScope(container)
    .filter((input) => input !== passwordInput && input !== usernameInput)
    .filter((input) => sameDetectionOwner(passwordInput, input))
    .filter(isFillableInput)
    .filter(isTotpCandidate)
    .at(0);
}

function detectedTotpInputs(input: HTMLInputElement): readonly HTMLInputElement[] {
  return resolveTotpInputs(input) ?? [];
}

function nearestTotpCluster(
  input: HTMLInputElement,
  boundary: ParentNode,
): HTMLInputElement[] | undefined {
  for (const container of totpAncestorContainers(input, boundary)) {
    const allInputs = Array.from(container.querySelectorAll<HTMLInputElement>('input'));
    const rawCandidates = allInputs.filter(isPotentialTotpGroupInput);
    if (rawCandidates.includes(input) && rawCandidates.some((candidate) => (
      candidate.form === input.form
      && candidate.getRootNode() === input.getRootNode()
      && !hasSameComposedSlotPath(candidate, input)
    ))) return [];
    const candidates = allInputs.filter((candidate) => (
      isPotentialTotpGroupInput(candidate)
      && candidate.form === input.form
      && candidate.getRootNode() === input.getRootNode()
      && hasSameComposedSlotPath(candidate, input)
    ));
    if (candidates.length > 1 && candidates.includes(input)) {
      return inputsAreConsecutive(allInputs, candidates) ? candidates : [];
    }
  }
  return undefined;
}

function rawLocalTotpCluster(input: HTMLInputElement, boundary: ParentNode): readonly HTMLInputElement[] {
  const localBoundary = boundary instanceof Element && !boundary.contains(input) ? treeRoot(input) : boundary;
  for (const container of totpAncestorContainers(input, localBoundary)) {
    const candidates = Array.from(container.querySelectorAll<HTMLInputElement>('input')).filter((candidate) => (
      isPotentialTotpGroupInput(candidate)
      && candidate.form === input.form
      && candidate.getRootNode() === input.getRootNode()
      && hasSameComposedSlotPath(candidate, input)
    ));
    if (candidates.length > 1 && candidates.includes(input)) return candidates;
  }
  return [input];
}

function totpAncestorContainers(input: HTMLInputElement, boundary: ParentNode): ParentNode[] {
  const containers: ParentNode[] = [];
  const boundaryElement = boundary instanceof Element ? boundary : undefined;
  if (boundaryElement && !boundaryElement.contains(input)) return containers;
  for (let current = input.parentElement; current; current = current.parentElement) {
    if (boundaryElement && !boundaryElement.contains(current)) break;
    containers.push(current);
    if (current === boundaryElement) return containers;
  }
  if (!boundaryElement && input.getRootNode() === boundary) containers.push(boundary);
  return containers;
}

function isPotentialTotpGroupInput(input: HTMLInputElement): boolean {
  return isTotpCompatibleInput(input) && (isSingleCharacterInput(input) || isTotpCandidate(input));
}

function isTotpCompatibleInput(input: HTMLInputElement): boolean {
  return TOTP_TYPES.includes(input.type)
    || (input.type === 'password' && (hasOneTimeCodeAutocomplete(input) || isSingleCharacterInput(input)));
}

function inputsAreConsecutive(
  allInputs: readonly HTMLInputElement[],
  candidates: readonly HTMLInputElement[],
): boolean {
  const firstIndex = allInputs.indexOf(candidates[0]!);
  return firstIndex >= 0
    && candidates.every((candidate, index) => allInputs[firstIndex + index] === candidate);
}

export function isSingleCharacterInput(input: HTMLInputElement): boolean {
  return input.maxLength === 1 || input.getAttribute('maxlength')?.trim() === '1';
}

function hasStableDomOrder(inputs: readonly HTMLInputElement[]): boolean {
  return inputs.every((input, index) => index === 0 || Boolean(
    inputs[index - 1]!.compareDocumentPosition(input) & Node.DOCUMENT_POSITION_FOLLOWING,
  ));
}

function sameInputs(first: readonly HTMLInputElement[], second: readonly HTMLInputElement[]): boolean {
  return first.length === second.length && first.every((input, index) => input === second[index]);
}

export function composedSlotPath(element: Element): readonly HTMLSlotElement[] {
  const slots: HTMLSlotElement[] = [];
  for (let current: Element | null = element; current; current = composedParentElement(current)) {
    if (current instanceof HTMLSlotElement) slots.push(current);
  }
  return slots;
}

export function hasSameComposedSlotPath(first: Element, second: Element): boolean {
  const firstPath = composedSlotPath(first);
  const secondPath = composedSlotPath(second);
  return sameSlots(firstPath, secondPath);
}

export function captureControlOwner(control: OwnerTrackedControl): ControlOwnerSnapshot {
  const root = control.getRootNode();
  return {
    ownerDocument: control.ownerDocument,
    root,
    formOwner: control.form,
    composedContainer: composedContainerFor(control, root),
    slotPath: composedSlotPath(control),
  };
}

export function hasSameControlOwner(
  first: ControlOwnerSnapshot,
  second: ControlOwnerSnapshot,
): boolean {
  return first.ownerDocument === second.ownerDocument
    && first.root === second.root
    && first.formOwner === second.formOwner
    && first.composedContainer === second.composedContainer
    && sameSlots(first.slotPath, second.slotPath);
}

function sameDetectionOwner(first: OwnerTrackedControl, second: OwnerTrackedControl): boolean {
  const firstOwner = captureControlOwner(first);
  const secondOwner = captureControlOwner(second);
  if (firstOwner.formOwner || secondOwner.formOwner) {
    return firstOwner.ownerDocument === secondOwner.ownerDocument
      && firstOwner.root === secondOwner.root
      && firstOwner.formOwner !== null
      && firstOwner.formOwner === secondOwner.formOwner;
  }
  return hasSameControlOwner(firstOwner, secondOwner);
}

function composedContainerFor(element: Element, fallbackRoot: Node): ParentNode {
  let composedBoundary = isParentNode(fallbackRoot) ? fallbackRoot : element.ownerDocument;
  for (let current: Element | null = element; current; current = composedParentElement(current)) {
    const currentRoot = current.getRootNode();
    if (currentRoot.nodeType === Node.DOCUMENT_FRAGMENT_NODE && 'host' in currentRoot) {
      composedBoundary = currentRoot as ShadowRoot;
    }
    if (current !== element && current.matches('form, section, main, article')) return current;
  }
  return composedBoundary;
}

function isParentNode(node: Node): node is ParentNode {
  return 'querySelectorAll' in node;
}

function sameFieldOwners(
  first: readonly (readonly [HTMLInputElement, ControlOwnerSnapshot])[],
  second: readonly (readonly [HTMLInputElement, ControlOwnerSnapshot])[],
): boolean {
  return first.length === second.length && first.every(([field, owner], index) => {
    const current = second[index];
    return current !== undefined && field === current[0] && hasSameControlOwner(owner, current[1]);
  });
}

function sameSlots(first: readonly HTMLSlotElement[], second: readonly HTMLSlotElement[]): boolean {
  return first.length === second.length && first.every((slot, index) => slot === second[index]);
}

function autocompleteTokens(value: string): Set<string> {
  if (value.length > 1_024) return new Set();
  return new Set(value.toLowerCase().trim().split(/\s+/).filter(Boolean));
}

function hasOneTimeCodeAutocomplete(input: HTMLInputElement): boolean {
  return autocompleteTokens(semanticHintsFor(input).autocomplete).has('one-time-code');
}

function hasCardCodeAutocomplete(input: HTMLInputElement): boolean {
  return autocompleteTokens(semanticHintsFor(input).autocomplete).has('cc-csc');
}

export function isVisibleInTree(element: HTMLElement): boolean {
  if (!element.isConnected) return false;
  const view = element.ownerDocument.defaultView;
  if (!view) return false;
  for (let node: Element | null = element; node; node = composedParentElement(node)) {
    const style = view.getComputedStyle(node);
    const opacity = Number.parseFloat(style.opacity);
    if (
      (node instanceof HTMLElement && node.hidden)
      || node.hasAttribute('inert')
      || node.getAttribute('aria-hidden') === 'true'
      || style.display === 'none'
      || style.visibility === 'hidden'
      || style.visibility === 'collapse'
      || style.contentVisibility === 'hidden'
      || (Number.isFinite(opacity) && opacity < 0.1)
      || isFullyClipped(style)
      || hasCollapsingTransform(style.transform)
    ) return false;
  }
  return true;
}

/**
 * Conservative field interactability check modeled on Bitwarden's DOM visibility service. DOM
 * implementations without layout keep the style-only path so unit tests can construct fields.
 */
export function isElementInteractable(element: HTMLElement): boolean {
  if (!isVisibleInTree(element)) return false;
  const ownerDocument = element.ownerDocument;
  const view = ownerDocument.defaultView;
  if (!view) return false;

  const rect = element.getBoundingClientRect();
  const hasLayout = documentHasLayout(ownerDocument);
  if (!hasFiniteRect(rect)) return false;
  if (rect.width === 0 && rect.height === 0) return !hasLayout;
  if (rect.width < MIN_INTERACTABLE_SIZE || rect.height < MIN_INTERACTABLE_SIZE) return false;
  if (!isWithinDocumentBounds(rect, ownerDocument, view)) return false;

  const root = element.getRootNode();
  const pointRoot = hasElementFromPoint(root) ? root : ownerDocument;
  if (!hasElementFromPoint(pointRoot)) return !hasLayout;
  const hit = pointRoot.elementFromPoint(
    rect.left + rect.width / 2,
    rect.top + rect.height / 2,
  );
  if (!hit) return !hasLayout;
  return isPermittedCenterHit(element, hit);
}

function isFullyClipped(style: CSSStyleDeclaration): boolean {
  const clipPath = normalizeCssValue(style.clipPath);
  if (HIDDEN_CLIP_PATHS.has(clipPath)) return true;
  const legacyClip = normalizeCssValue(style.clip);
  if (!legacyClip.startsWith('rect(') || !legacyClip.endsWith(')')) return false;
  const values = legacyClip.slice(5, -1).split(/[\s,]+/).filter(Boolean);
  return values.length === 4 && values.every((value) => /^0(?:px|%)?$/.test(value));
}

function normalizeCssValue(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function hasCollapsingTransform(value: string): boolean {
  const normalized = value.trim().toLowerCase().replace(/\s+/g, '');
  if (!normalized || normalized === 'none') return false;
  const scaleMatch = normalized.match(/^scale(?:3d)?\(([^)]+)\)$/);
  if (scaleMatch) {
    const scales = scaleMatch[1]!.split(',').map(Number);
    const scaleX = scales[0];
    const scaleY = scales[1] ?? scaleX;
    return scaleX === 0 || scaleY === 0;
  }
  if (/^scale[xy]\(0\)$/.test(normalized)) return true;
  const matrixMatch = normalized.match(/^matrix\(([^)]+)\)$/);
  if (!matrixMatch) return false;
  const matrix = matrixMatch[1]!.split(',').map(Number);
  return matrix.length === 6
    && matrix.every(Number.isFinite)
    && Math.abs(matrix[0]! * matrix[3]! - matrix[1]! * matrix[2]!) < Number.EPSILON;
}

function documentHasLayout(ownerDocument: Document): boolean {
  const root = ownerDocument.documentElement;
  const rect = root.getBoundingClientRect();
  return root.clientWidth > 0 || root.clientHeight > 0 || rect.width > 0 || rect.height > 0;
}

function hasFiniteRect(rect: DOMRectReadOnly): boolean {
  return [rect.top, rect.right, rect.bottom, rect.left, rect.width, rect.height]
    .every(Number.isFinite);
}

function isWithinDocumentBounds(
  rect: DOMRectReadOnly,
  ownerDocument: Document,
  view: Window,
): boolean {
  const root = ownerDocument.documentElement;
  const width = Math.max(root.scrollWidth, root.clientWidth, view.innerWidth);
  const height = Math.max(root.scrollHeight, root.clientHeight, view.innerHeight);
  if (width <= 0 || height <= 0) return false;
  const left = rect.left - root.clientLeft;
  const top = rect.top - root.clientTop;
  return left >= 0
    && top >= 0
    && left + rect.width <= width
    && top + rect.height <= height;
}

interface ElementFromPointRoot {
  elementFromPoint(x: number, y: number): Element | null;
}

function hasElementFromPoint(value: unknown): value is Node & ElementFromPointRoot {
  return value instanceof Node
    && 'elementFromPoint' in value
    && typeof value.elementFromPoint === 'function';
}

function isPermittedCenterHit(target: HTMLElement, hit: Element): boolean {
  if (hit === target || target.contains(hit)) return true;
  return labelsFor(target).some((label) => label === hit || label.contains(hit));
}

function labelsFor(element: HTMLElement): readonly HTMLLabelElement[] {
  if (
    element instanceof HTMLInputElement
    || element instanceof HTMLSelectElement
    || element instanceof HTMLTextAreaElement
  ) return associatedLabelsFor(element) ?? [];
  return [];
}

/** Native forms own external `form=id` controls; non-form scopes remain confined to one tree root. */
export function inputControlsInScope(scope: ParentNode): HTMLInputElement[] {
  if (scope instanceof HTMLFormElement) {
    return Array.from(scope.elements)
      .filter((control): control is HTMLInputElement => control instanceof HTMLInputElement)
      .filter((input) => input.form === scope && input.getRootNode() === scope.getRootNode());
  }
  return Array.from(scope.querySelectorAll<HTMLInputElement>('input'));
}

export function composedParentElement(element: Element): Element | null {
  if (element.assignedSlot) return element.assignedSlot;
  if (element.parentElement) return element.parentElement;
  const root = element.getRootNode();
  return root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && 'host' in root
    ? (root as ShadowRoot).host
    : null;
}

function treeRoot(element: Element): Document | ShadowRoot {
  const root = element.getRootNode();
  return root.nodeType === Node.DOCUMENT_NODE ? root as Document : root as ShadowRoot;
}
