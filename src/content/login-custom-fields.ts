import type { DetectedLoginForm } from './form-detection.js';
import { isAutofillIgnored } from './autofill-ignore.js';
import {
  composedParentElement,
  composedSlotPath,
  hasLoginCredentialTarget,
  isFillableInput,
  isNewPasswordField,
  isTotpCandidate,
  isVisibleInTree,
  reservedTotpInputs,
  totpInputsForForm,
} from './form-detection.js';
import { classifyCardField } from './field-map.js';
import { flashFill, flashFillCheck } from './fill-highlight.js';
import { setElementValue } from './native-set-value.js';
import { createStagedFillCommit, type StagedFillCommit } from './staged-fill.js';
import {
  LOGIN_CUSTOM_PLAN_VERSION,
  MAX_LOGIN_CUSTOM_HINT_LENGTH,
  MAX_LOGIN_CUSTOM_HINTS_PER_TARGET,
  MAX_LOGIN_CUSTOM_TARGETS,
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
export function planLoginCustomTargets(form: DetectedLoginForm): LoginCustomTargetPlan {
  const scope = loginScope(form);
  const reservedTotps = scope ? reservedTotpInputs(scope.formOwner ?? scope.queryScope) : new Set<HTMLInputElement>();
  const targets = (scope ? eligibleControls(scope) : [])
    .filter((element) => (
      element !== form.usernameInput
      && element !== form.passwordInput
      && !(element instanceof HTMLInputElement && reservedTotps.has(element))
    ))
    .flatMap((element): PrivateTarget[] => {
      const metadata = metadataFor(element);
      return metadata ? [{ element, metadata }] : [];
    })
    .slice(0, MAX_LOGIN_CUSTOM_TARGETS);
  const previous = planStates.get(form.anchor);
  const generation = previous && sameLoginCustomScope(previous.scope, scope) && sameTargets(previous.targets, targets)
    ? previous.generation
    : (previous?.generation ?? 0) + 1;
  planStates.set(form.anchor, { scope, generation, targets });
  return Object.freeze({
    version: LOGIN_CUSTOM_PLAN_VERSION,
    generation,
    targets: Object.freeze(targets.map(({ metadata }) => metadata)),
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

function metadataFor(element: LoginCustomElement): LoginCustomTarget | undefined {
  if (!isEligibleCustomControl(element)) return undefined;
  const hints = exactHints(element);
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

function isEligibleCustomControl(element: LoginCustomElement): boolean {
  if (
    isAutofillIgnored(element)
    || !element.isConnected
    || element.hidden
    || element.disabled
    || element.matches(':disabled')
    || !isVisibleInTree(element)
  ) return false;
  if (element instanceof HTMLTextAreaElement) return !element.readOnly && !isReservedAutocomplete(element.autocomplete);
  if (element instanceof HTMLSelectElement) return !isReservedAutocomplete(element.autocomplete) && !isPaymentField(element);
  if (element.readOnly) return false;
  const type = element.type.toLowerCase();
  if (!['text', 'email', 'tel', 'url', 'search', 'number', 'checkbox'].includes(type)) return false;
  if (isNewPasswordField(element) || isTotpCandidate(element) || isReservedLoginField(element) || isPaymentField(element)) return false;
  return true;
}

function isReservedLoginField(element: HTMLInputElement): boolean {
  const autocomplete = autocompleteTokens(element.autocomplete);
  if (autocomplete.has('username') || autocomplete.has('current-password') || autocomplete.has('new-password') || autocomplete.has('one-time-code')) return true;
  const hint = `${element.name} ${element.id} ${element.getAttribute('aria-label') ?? ''}`.toLowerCase();
  return /(^|[^a-z0-9])(user(name)?|login|email|e-mail|pass(word)?|otp|totp|mfa|2fa)([^a-z0-9]|$)/.test(hint);
}

function isPaymentField(element: LoginCustomElement): boolean {
  const autocomplete = autocompleteTokens(element.autocomplete);
  if ([...autocomplete].some((token) => token.startsWith('cc-'))) return true;
  const hints = {
    autocomplete: element.getAttribute('autocomplete') ?? '',
    name: element.getAttribute('name') ?? '',
    id: element.id,
    ariaLabel: element.getAttribute('aria-label') ?? '',
    placeholder: element.getAttribute('placeholder') ?? '',
    type: element instanceof HTMLInputElement ? element.type : element instanceof HTMLSelectElement ? 'select' : 'textarea',
  };
  if (!(element instanceof HTMLTextAreaElement) && classifyCardField(hints)) return true;
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

function exactHints(element: LoginCustomElement): readonly LoginCustomTargetHint[] {
  const choices: Array<readonly [LoginCustomTargetHint['kind'], string | null | undefined]> = [
    ['name', element.getAttribute('name')],
    ['id', element.getAttribute('id')],
    ['label', element.getAttribute('aria-label')],
    ...Array.from(element.labels ?? [], (label) => ['label', label.textContent] as const),
    ['placeholder', element.getAttribute('placeholder')],
  ];
  const seen = new Set<string>();
  const hints: LoginCustomTargetHint[] = [];
  for (const [kind, raw] of choices) {
    const value = canonicalHint(raw);
    if (!value) continue;
    const key = `${kind}\0${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hints.push(Object.freeze({ kind, value }));
    if (hints.length === MAX_LOGIN_CUSTOM_HINTS_PER_TARGET) break;
  }
  return Object.freeze(hints);
}

function canonicalHint(value: string | null | undefined): string {
  const canonical = value?.trim().replace(/(?:\r\n|\r|\n)/g, '').normalize('NFKC') ?? '';
  return canonical.length <= MAX_LOGIN_CUSTOM_HINT_LENGTH ? canonical : '';
}

function controlType(element: LoginCustomElement): LoginCustomControlType {
  if (element instanceof HTMLSelectElement) return 'select';
  if (element instanceof HTMLTextAreaElement) return 'textarea';
  return element.type as LoginCustomControlType;
}

function eligibleControls(scope: LoginCustomScope): LoginCustomElement[] {
  if (scope.formOwner) {
    return Array.from(scope.formOwner.elements)
      .filter((control): control is LoginCustomElement => isLoginCustomElement(control))
      .filter((control) => (
        control.form === scope.formOwner
        && control.ownerDocument === scope.ownerDocument
        && control.getRootNode() === scope.root
      ));
  }
  return Array.from(scope.queryScope.querySelectorAll('input, select, textarea'))
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
  if (!target || !isEligibleCustomControl(target.element)) return false;
  const current = metadataFor(target.element);
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
