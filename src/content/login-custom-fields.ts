import type { DetectedLoginForm } from './form-detection.js';
import { isAutofillIgnored } from './autofill-ignore.js';
import {
  composedParentElement,
  composedSlotPath,
  hasLoginCredentialTarget,
  isFillableInput,
  isNewPasswordField,
  isSemanticSourceAvailableInTree,
  isTotpCandidate,
  isVisibleInTree,
  reservedTotpInputs,
  totpInputsForForm,
} from './form-detection.js';
import { classifyCardField } from './field-map.js';
import { collectFieldHints } from './semantic-hints.js';
import {
  createScopedAutofillDetectionContext,
  type AutofillDetectionContext,
} from './autofill-detection-context.js';
import { flashFill, flashFillCheck } from './fill-highlight.js';
import { setElementValue } from './native-set-value.js';
import { createStagedFillCommit, type StagedFillCommit } from './staged-fill.js';
import {
  LOGIN_CUSTOM_PLAN_VERSION,
  MAX_LOGIN_CUSTOM_HINT_LENGTH,
  MAX_LOGIN_CUSTOM_HINTS_PER_TARGET,
  type LoginCustomAssignment,
  type LoginCustomControlType,
  type LoginCustomTarget,
  type LoginCustomTargetHint,
  type LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';

type LoginCustomElement = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

interface PlanState {
  readonly scope: LoginCustomScope | undefined;
  readonly generation: number;
  readonly targets: readonly PrivateTarget[];
}

interface LoginCustomScope {
  readonly queryScope: ParentNode;
  readonly root: Document | ShadowRoot;
  readonly composedContainer: ParentNode;
  readonly formOwner: HTMLFormElement | null;
  readonly ownerDocument: Document;
  readonly slotPath: readonly HTMLSlotElement[];
}

interface PrivateTarget {
  readonly element: LoginCustomElement;
  readonly metadata: LoginCustomTarget;
}

const fieldIds = new WeakMap<LoginCustomElement, string>();
const planStates = new WeakMap<HTMLElement, PlanState>();

/** Build a bounded metadata-only plan for custom fields in this login's native/root-local scope. */
export function planLoginCustomTargets(
  form: DetectedLoginForm,
  context: AutofillDetectionContext = detectionContextForForm(form),
): LoginCustomTargetPlan {
  const scope = loginScope(form);
  const reservedTotps = scope && context.complete
    ? reservedTotpInputs(scope.formOwner ?? scope.queryScope, context)
    : new Set<HTMLInputElement>();
  const targets: PrivateTarget[] = [];
  for (const element of scope && context.complete ? eligibleControls(scope, context) : []) {
    if (
      element === form.usernameInput
      || element === form.passwordInput
      || (element instanceof HTMLInputElement && reservedTotps.has(element))
    ) continue;
    const metadata = metadataFor(element, context);
    if (!metadata) {
      if (!context.complete) break;
      continue;
    }
    if (!context.claimCustomTarget()) break;
    targets.push({ element, metadata });
  }
  const completeTargets = context.complete ? targets : [];
  const completeScope = context.complete ? scope : undefined;
  const previous = planStates.get(form.anchor);
  const generation = previous
    && sameLoginCustomScope(previous.scope, completeScope)
    && sameTargets(previous.targets, completeTargets)
    ? previous.generation
    : (previous?.generation ?? 0) + 1;
  planStates.set(form.anchor, { scope: completeScope, generation, targets: completeTargets });
  return Object.freeze({
    version: LOGIN_CUSTOM_PLAN_VERSION,
    generation,
    targets: Object.freeze(completeTargets.map(({ metadata }) => metadata)),
  });
}

/**
 * Re-detect the complete plan before writing. A stale field graph rejects the entire custom portion;
 * username/password are committed separately by callers and are intentionally unaffected.
 */
export function commitLoginCustomAssignments(
  form: DetectedLoginForm,
  expectedPlan: LoginCustomTargetPlan,
  assignments: readonly LoginCustomAssignment[],
  staged: StagedFillCommit = createStagedFillCommit(),
): boolean {
  if (!staged.isCurrent()) return false;
  if (assignments.length === 0) return true;
  const initial = validatedPlanState(form, expectedPlan, assignments);
  if (!initial?.state.scope) return false;
  const expectedScope = initial.state.scope;

  for (const assignment of assignments) {
    if (!staged.isCurrent()) return false;
    const before = validatedPlanState(form, expectedPlan, assignments, expectedScope);
    const target = before?.byId.get(assignment.fieldId);
    if (!target) return false;
    const wrote = staged.write(() => {
      if (!assignmentMatchesTarget(assignment, target)) return false;
      if ('checked' in assignment) setInputChecked(target.element as HTMLInputElement, assignment.checked);
      else setElementValue(target.element, assignment.value);
      return true;
    });
    if (!wrote || staged.stale) return false;
    if (!validatedPlanState(form, expectedPlan, assignments, expectedScope)) return false;
    flashFill(target.element);
    flashFillCheck(target.element);
  }
  return true;
}

export function isLoginCustomTargetPlanCurrent(
  form: DetectedLoginForm,
  expectedPlan: LoginCustomTargetPlan,
): boolean {
  return samePlans(planLoginCustomTargets(form), expectedPlan);
}

function validatedPlanState(
  form: DetectedLoginForm,
  expectedPlan: LoginCustomTargetPlan,
  assignments: readonly LoginCustomAssignment[],
  expectedScope?: LoginCustomScope,
): { readonly state: PlanState; readonly byId: ReadonlyMap<string, PrivateTarget> } | undefined {
  const fresh = planLoginCustomTargets(form);
  if (!samePlans(fresh, expectedPlan)) return undefined;
  const state = planStates.get(form.anchor);
  if (!state?.scope || state.generation !== fresh.generation) return undefined;
  if (expectedScope && !sameLoginCustomScope(state.scope, expectedScope)) return undefined;
  const byId = new Map(state.targets.map((target) => [target.metadata.fieldId, target]));
  if (assignments.some((assignment) => !assignmentMatchesTarget(assignment, byId.get(assignment.fieldId)))) {
    return undefined;
  }
  return { state, byId };
}

function samePlans(first: LoginCustomTargetPlan, second: LoginCustomTargetPlan): boolean {
  return first.version === second.version
    && first.generation === second.generation
    && first.targets.length === second.targets.length
    && first.targets.every((target, index) => {
      const other = second.targets[index];
      return other !== undefined
        && target.fieldId === other.fieldId
        && target.controlType === other.controlType
        && sameHints(target.hints, other.hints);
    });
}

function setInputChecked(input: HTMLInputElement, checked: boolean): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
  if (setter) setter.call(input, checked);
  else input.checked = checked;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

function metadataFor(
  element: LoginCustomElement,
  context: AutofillDetectionContext,
): LoginCustomTarget | undefined {
  if (!isEligibleCustomControl(element, context)) return undefined;
  const hints = exactHints(element, context);
  if (hints.length === 0) return undefined;
  let fieldId = fieldIds.get(element);
  if (!fieldId) {
    fieldId = createOpaqueFieldId();
    fieldIds.set(element, fieldId);
  }
  return Object.freeze({ fieldId, controlType: controlType(element), hints });
}

function createOpaqueFieldId(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0'));
  return `vw-custom-${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10).join('')}`;
}

function isEligibleCustomControl(
  element: LoginCustomElement,
  context: AutofillDetectionContext,
): boolean {
  if (
    isAutofillIgnored(element)
    || !element.isConnected
    || element.hidden
    || element.disabled
    || element.matches(':disabled')
    || !isVisibleInTree(element)
  ) return false;
  const hints = context.fieldHints(
    element,
    (budget) => collectFieldHints(element, isSemanticSourceAvailableInTree, budget),
  );
  if (!context.complete) return false;
  if (element instanceof HTMLTextAreaElement) return !element.readOnly && !isReservedAutocomplete(hints.autocomplete);
  if (element instanceof HTMLSelectElement) {
    return !isReservedAutocomplete(hints.autocomplete) && !isPaymentField(hints);
  }
  if (element.readOnly) return false;
  const type = element.type.toLowerCase();
  if (!['text', 'email', 'tel', 'url', 'search', 'number', 'checkbox'].includes(type)) return false;
  if (
    isNewPasswordField(element, context)
    || isTotpCandidate(element, context)
    || isReservedLoginField(hints)
    || isPaymentField(hints)
  ) return false;
  return true;
}

function isReservedLoginField(hints: ReturnType<typeof collectFieldHints>): boolean {
  const autocomplete = autocompleteTokens(hints.autocomplete);
  if (autocomplete.has('username') || autocomplete.has('current-password') || autocomplete.has('new-password') || autocomplete.has('one-time-code')) return true;
  const hint = `${hints.name} ${hints.id} ${hints.ariaLabel}`.toLowerCase();
  return /(^|[^a-z0-9])(user(name)?|login|email|e-mail|pass(word)?|otp|totp|mfa|2fa)([^a-z0-9]|$)/.test(hint);
}

function isPaymentField(hints: ReturnType<typeof collectFieldHints>): boolean {
  const autocomplete = autocompleteTokens(hints.autocomplete);
  if ([...autocomplete].some((token) => token.startsWith('cc-'))) return true;
  if (classifyCardField(hints)) return true;
  const joined = `${hints.name} ${hints.id} ${hints.ariaLabel}`.toLowerCase();
  return /(^|[^a-z0-9])(cvv|cvc|card|credit|debit|expiry|expiration)([^a-z0-9]|$)/.test(joined);
}

function isReservedAutocomplete(value: string | undefined): boolean {
  const tokens = autocompleteTokens(value);
  return tokens.has('username')
    || tokens.has('current-password')
    || tokens.has('new-password')
    || tokens.has('one-time-code')
    || [...tokens].some((token) => token.startsWith('cc-'));
}

function exactHints(
  element: LoginCustomElement,
  context: AutofillDetectionContext,
): readonly LoginCustomTargetHint[] {
  const fieldHints = context.fieldHints(
    element,
    (budget) => collectFieldHints(element, isSemanticSourceAvailableInTree, budget),
  );
  const choices: Array<readonly [LoginCustomTargetHint['kind'], string | null | undefined]> = [
    ['name', fieldHints.name],
    ['id', fieldHints.id],
    ['label', fieldHints.ariaLabel],
    ...(fieldHints.semanticLabels ?? []).map((label) => ['label', label] as const),
    ['placeholder', fieldHints.placeholder],
  ];
  const seen = new Set<string>();
  const hints: LoginCustomTargetHint[] = [];
  for (const [kind, raw] of choices) {
    const value = canonicalHint(raw, context);
    if (!value) continue;
    const key = `${kind}\0${value}`;
    if (seen.has(key)) continue;
    if (hints.length >= MAX_LOGIN_CUSTOM_HINTS_PER_TARGET) {
      context.markExceeded('hint_bytes');
      return [];
    }
    if (!context.claimHintBytes(utf8ByteLength(value))) return [];
    seen.add(key);
    hints.push(Object.freeze({ kind, value }));
  }
  return Object.freeze(hints);
}

function canonicalHint(
  value: string | null | undefined,
  context: AutofillDetectionContext,
): string {
  const canonical = value?.trim().replace(/(?:\r\n|\r|\n)/g, '').normalize('NFKC') ?? '';
  if (canonical.length <= MAX_LOGIN_CUSTOM_HINT_LENGTH) return canonical;
  context.markExceeded('hint_bytes');
  return '';
}

function controlType(element: LoginCustomElement): LoginCustomControlType {
  if (element instanceof HTMLSelectElement) return 'select';
  if (element instanceof HTMLTextAreaElement) return 'textarea';
  return element.type as LoginCustomControlType;
}

function eligibleControls(
  scope: LoginCustomScope,
  context: AutofillDetectionContext,
): LoginCustomElement[] {
  if (scope.formOwner) {
    return context.controlsForForm(scope.formOwner)
      .filter((control): control is LoginCustomElement => isLoginCustomElement(control))
      .filter((control) => (
        control.form === scope.formOwner
        && control.ownerDocument === scope.ownerDocument
        && control.getRootNode() === scope.root
      ));
  }
  return context.controlsWithin(scope.queryScope)
    .filter(isLoginCustomElement)
    .filter((control) => (
      control.form === null
      && control.ownerDocument === scope.ownerDocument
      && control.getRootNode() === scope.root
      && composedContainerFor(control, scope.root) === scope.composedContainer
      && sameSlotPath(composedSlotPath(control), scope.slotPath)
    ));
}

function loginScope(form: DetectedLoginForm): LoginCustomScope | undefined {
  const anchor = form.anchor;
  if (!hasLoginCredentialTarget(form)) return undefined;
  if (!anchor.isConnected) return undefined;
  const root = supportedRoot(anchor.getRootNode());
  if (!root) return undefined;
  const formOwner = form.form;
  const loginInputs = [form.usernameInput, form.passwordInput, ...totpInputsForForm(form)]
    .filter((input): input is HTMLInputElement => input !== undefined);
  if (loginInputs.length === 0 || loginInputs.some((input) => (
    !input.isConnected
    || !isFillableInput(input)
    || input.ownerDocument !== anchor.ownerDocument
    || input.getRootNode() !== root
    || input.form !== formOwner
  ))) return undefined;

  if (formOwner) {
    if (!formOwner.isConnected || formOwner.ownerDocument !== anchor.ownerDocument || formOwner.getRootNode() !== root) {
      return undefined;
    }
    return {
      queryScope: formOwner,
      root,
      composedContainer: formOwner,
      formOwner,
      ownerDocument: anchor.ownerDocument,
      slotPath: composedSlotPath(anchor),
    };
  }

  const composedContainer = composedContainerFor(anchor, root);
  const slotPath = composedSlotPath(anchor);
  if (loginInputs.some((input) => (
    composedContainerFor(input, root) !== composedContainer
    || !sameSlotPath(composedSlotPath(input), slotPath)
  ))) return undefined;
  return {
    queryScope: anchor.closest('section, main, article') ?? root,
    root,
    composedContainer,
    formOwner: null,
    ownerDocument: anchor.ownerDocument,
    slotPath,
  };
}

function supportedRoot(root: Node): Document | ShadowRoot | undefined {
  if (root.nodeType === Node.DOCUMENT_NODE) return root as Document;
  return root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && 'host' in root ? root as ShadowRoot : undefined;
}

function composedContainerFor(element: Element, fallbackRoot: Document | ShadowRoot): ParentNode {
  let composedBoundary: ParentNode = fallbackRoot;
  for (let current: Element | null = element; current; current = composedParentElement(current)) {
    const currentRoot = supportedRoot(current.getRootNode());
    if (currentRoot?.nodeType === Node.DOCUMENT_FRAGMENT_NODE) composedBoundary = currentRoot;
    if (current !== element && current.matches('form, section, main, article')) return current;
  }
  return composedBoundary;
}

function sameLoginCustomScope(
  first: LoginCustomScope | undefined,
  second: LoginCustomScope | undefined,
): boolean {
  if (!first || !second) return first === second;
  return first.queryScope === second.queryScope
    && first.root === second.root
    && first.composedContainer === second.composedContainer
    && first.formOwner === second.formOwner
    && first.ownerDocument === second.ownerDocument
    && sameSlotPath(first.slotPath, second.slotPath);
}

function sameSlotPath(first: readonly HTMLSlotElement[], second: readonly HTMLSlotElement[]): boolean {
  return first.length === second.length && first.every((slot, index) => slot === second[index]);
}

function sameTargets(first: readonly PrivateTarget[], second: readonly PrivateTarget[]): boolean {
  return first.length === second.length && first.every((target, index) => {
    const other = second[index];
    return other !== undefined
      && target.element === other.element
      && target.metadata.fieldId === other.metadata.fieldId
      && target.metadata.controlType === other.metadata.controlType
      && sameHints(target.metadata.hints, other.metadata.hints);
  });
}

function assignmentMatchesTarget(assignment: LoginCustomAssignment, target: PrivateTarget | undefined): boolean {
  if (!target) return false;
  const context = detectionContextForElement(target.element);
  if (!context.complete || !isEligibleCustomControl(target.element, context)) return false;
  const current = metadataFor(target.element, context);
  if (!current
      || current.fieldId !== target.metadata.fieldId
      || current.controlType !== target.metadata.controlType
      || !sameHints(current.hints, target.metadata.hints)) return false;
  return 'checked' in assignment
    ? target.element instanceof HTMLInputElement && target.element.type === 'checkbox'
    : !(target.element instanceof HTMLInputElement && target.element.type === 'checkbox');
}

function sameHints(first: readonly LoginCustomTargetHint[], second: readonly LoginCustomTargetHint[]): boolean {
  return first.length === second.length && first.every((hint, index) => {
    const other = second[index];
    return other !== undefined && hint.kind === other.kind && hint.value === other.value;
  });
}

function autocompleteTokens(value: string | undefined): Set<string> {
  return new Set((value ?? '').toLowerCase().trim().split(/\s+/).filter(Boolean));
}

function isLoginCustomElement(value: Element): value is LoginCustomElement {
  return value instanceof HTMLInputElement || value instanceof HTMLSelectElement || value instanceof HTMLTextAreaElement;
}

function detectionContextForForm(form: DetectedLoginForm): AutofillDetectionContext {
  return detectionContextForElement(form.anchor);
}

function detectionContextForElement(element: Element): AutofillDetectionContext {
  const root = supportedRoot(element.getRootNode()) ?? element.ownerDocument;
  return createScopedAutofillDetectionContext(root);
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first <= 0x7f) bytes += 1;
    else if (first <= 0x7ff) bytes += 2;
    else if (first >= 0xd800 && first <= 0xdbff && index + 1 < value.length) {
      const second = value.charCodeAt(index + 1);
      if (second >= 0xdc00 && second <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}
