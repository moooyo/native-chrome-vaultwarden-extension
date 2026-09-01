import { DEFAULT_COMPOSED_TREE_MAX_VISITED_ELEMENTS } from './composed-tree.js';
import { MAX_LOGIN_CUSTOM_TARGETS } from '../core/vault/login-custom-fields.js';
import type { FieldHints } from './field-map.js';
import type { SemanticHintBudget } from './semantic-hints.js';

export type AutofillDetectionControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

export const DEFAULT_AUTOFILL_DETECTION_MAX_CONTROLS = 10_000;
export const DEFAULT_AUTOFILL_DETECTION_MAX_FORMS = 128;
export const DEFAULT_AUTOFILL_DETECTION_MAX_HINT_BYTES = 4 * 1024 * 1024;
export const DEFAULT_AUTOFILL_DETECTION_MAX_SEMANTIC_SOURCES = 4_096;
export const DEFAULT_AUTOFILL_DETECTION_MAX_SEMANTIC_NODES = 100_000;
export const DEFAULT_AUTOFILL_DETECTION_MAX_CUSTOM_TARGETS = MAX_LOGIN_CUSTOM_TARGETS;

export interface AutofillDetectionLimits {
  readonly maxVisitedElements?: number;
  readonly maxControls?: number;
  readonly maxForms?: number;
  readonly maxHintBytes?: number;
  readonly maxSemanticSources?: number;
  readonly maxSemanticNodes?: number;
  readonly maxCustomTargets?: number;
}

export interface AutofillDetectionSnapshot {
  readonly roots: readonly ParentNode[];
  readonly visitedElements?: number;
  readonly truncated: boolean;
}

export type AutofillDetectionFailure =
  | 'snapshot_truncated'
  | 'element_limit'
  | 'control_limit'
  | 'form_limit'
  | 'hint_byte_limit'
  | 'semantic_source_limit'
  | 'semantic_node_limit'
  | 'custom_target_limit';

export interface AutofillDetectionContext extends SemanticHintBudget {
  readonly roots: readonly ParentNode[];
  readonly complete: boolean;
  readonly failure: AutofillDetectionFailure | undefined;
  readonly controls: readonly AutofillDetectionControl[];
  readonly inputs: readonly HTMLInputElement[];
  controlsWithin(scope: ParentNode): readonly AutofillDetectionControl[];
  inputsWithin(scope: ParentNode): readonly HTMLInputElement[];
  controlsForForm(form: HTMLFormElement): readonly AutofillDetectionControl[];
  hasSubmitAffordance(scope: ParentNode): boolean;
  fieldHints(
    control: AutofillDetectionControl,
    collect: (budget: SemanticHintBudget) => FieldHints,
  ): FieldHints;
  /** Charge one stable ownership group once across raw and final structured-form passes. */
  claimCandidateGroup(identity: object): boolean;
  claimForms(count: number): boolean;
  claimCustomTarget(): boolean;
}

interface ResolvedLimits {
  readonly maxVisitedElements: number;
  readonly maxControls: number;
  readonly maxForms: number;
  readonly maxHintBytes: number;
  readonly maxSemanticSources: number;
  readonly maxSemanticNodes: number;
  readonly maxCustomTargets: number;
}

const EMPTY_CONTROLS = Object.freeze([] as AutofillDetectionControl[]);
const EMPTY_INPUTS = Object.freeze([] as HTMLInputElement[]);
const UNSAFE_FIELD_HINTS: FieldHints = Object.freeze({
  autocomplete: '',
  name: '',
  id: '',
  ariaLabel: '',
  placeholder: '',
  type: 'text',
  semanticLabels: Object.freeze([] as string[]),
  semanticLabelsUnsafe: true,
});

/** Build one bounded control inventory across every root in a complete composed-tree snapshot. */
export function createAutofillDetectionContext(
  snapshot: AutofillDetectionSnapshot,
  limits: AutofillDetectionLimits = {},
): AutofillDetectionContext {
  return createContext(snapshot.roots, snapshot.truncated, limits);
}

/** Keep legacy subtree detector entry points bounded without discovering additional shadow roots. */
export function createScopedAutofillDetectionContext(
  roots: ParentNode | readonly ParentNode[],
  limits: AutofillDetectionLimits = {},
): AutofillDetectionContext {
  const requested = Array.isArray(roots) ? roots : [roots as ParentNode];
  return createContext(requested.map(scopeInventoryRoot), false, limits);
}

function createContext(
  unsafeRoots: readonly ParentNode[],
  snapshotTruncated: boolean,
  configured: AutofillDetectionLimits,
): AutofillDetectionContext {
  const limits = resolveLimits(configured);
  const roots = Object.freeze([...new Set(unsafeRoots)]);
  const controls: AutofillDetectionControl[] = [];
  const inputs: HTMLInputElement[] = [];
  const controlsByForm = new Map<HTMLFormElement, AutofillDetectionControl[]>();
  const submitAffordances: Element[] = [];
  const hints = new WeakMap<AutofillDetectionControl, FieldHints>();
  let failure: AutofillDetectionFailure | undefined = snapshotTruncated ? 'snapshot_truncated' : undefined;
  let visitedElements = 0;
  let hintBytes = 0;
  let semanticSources = 0;
  let semanticNodes = 0;
  const candidateGroups = new WeakSet<object>();
  let candidateGroupCount = 0;
  let forms = 0;
  let customTargets = 0;

  const fail = (reason: AutofillDetectionFailure): false => {
    failure ??= reason;
    return false;
  };

  if (!failure) {
    const seenElements = new Set<Element>();
    outer: for (const root of roots) {
      const ownerDocument = documentFor(root);
      const walker = ownerDocument.createTreeWalker(root as Node, 1);
      let node = walker.nextNode();
      while (node) {
        const element = node as Element;
        if (!seenElements.has(element)) {
          seenElements.add(element);
          visitedElements += 1;
          if (visitedElements > limits.maxVisitedElements) {
            fail('element_limit');
            break outer;
          }
          if (isAutofillControl(element)) {
            if (controls.length >= limits.maxControls) {
              fail('control_limit');
              break outer;
            }
            controls.push(element);
            if (element instanceof HTMLInputElement) inputs.push(element);
            if (element.form) {
              const owned = controlsByForm.get(element.form) ?? [];
              owned.push(element);
              controlsByForm.set(element.form, owned);
            }
          }
          if (isSubmitAffordance(element)) submitAffordances.push(element);
        }
        node = walker.nextNode();
      }
    }
  }
  const boundedControls = Object.freeze(controls);
  const boundedInputs = Object.freeze(inputs);

  const context: AutofillDetectionContext = {
    roots,
    get complete() { return failure === undefined; },
    get failure() { return failure; },
    get controls() { return failure ? EMPTY_CONTROLS : boundedControls; },
    get inputs() { return failure ? EMPTY_INPUTS : boundedInputs; },
    controlsWithin(scope) {
      return failure ? EMPTY_CONTROLS : controls.filter((control) => isDescendantOf(scope, control));
    },
    inputsWithin(scope) {
      return failure ? EMPTY_INPUTS : inputs.filter((input) => isDescendantOf(scope, input));
    },
    controlsForForm(form) {
      if (failure) return EMPTY_CONTROLS;
      let root: Node;
      try {
        root = form.getRootNode();
      } catch {
        return EMPTY_CONTROLS;
      }
      return (controlsByForm.get(form) ?? EMPTY_CONTROLS)
        .filter((control) => control.getRootNode() === root);
    },
    hasSubmitAffordance(scope) {
      return !failure && submitAffordances.some((element) => isDescendantOf(scope, element));
    },
    fieldHints(control, collect) {
      const existing = hints.get(control);
      if (existing) return existing;
      const collected = collect(context);
      const bounded = failure ? UNSAFE_FIELD_HINTS : collected;
      hints.set(control, bounded);
      return bounded;
    },
    claimCandidateGroup(identity) {
      if (failure) return false;
      if (candidateGroups.has(identity)) return true;
      candidateGroupCount += 1;
      if (candidateGroupCount > limits.maxForms) return fail('form_limit');
      candidateGroups.add(identity);
      return true;
    },
    claimForms(count) {
      if (failure) return false;
      forms += boundedCount(count);
      return forms <= limits.maxForms || fail('form_limit');
    },
    claimCustomTarget() {
      if (failure) return false;
      customTargets += 1;
      return customTargets <= limits.maxCustomTargets || fail('custom_target_limit');
    },
    claimHintBytes(bytes) {
      if (failure) return false;
      hintBytes += boundedCount(bytes);
      return hintBytes <= limits.maxHintBytes || fail('hint_byte_limit');
    },
    claimSemanticSource() {
      if (failure) return false;
      semanticSources += 1;
      return semanticSources <= limits.maxSemanticSources || fail('semantic_source_limit');
    },
    claimSemanticNode() {
      if (failure) return false;
      semanticNodes += 1;
      return semanticNodes <= limits.maxSemanticNodes || fail('semantic_node_limit');
    },
    markExceeded(kind) {
      const reason: AutofillDetectionFailure = kind === 'hint_bytes'
        ? 'hint_byte_limit'
        : kind === 'semantic_sources'
          ? 'semantic_source_limit'
          : 'semantic_node_limit';
      fail(reason);
    },
  };
  return Object.freeze(context);
}

function isAutofillControl(element: Element): element is AutofillDetectionControl {
  return element instanceof HTMLInputElement
    || element instanceof HTMLSelectElement
    || element instanceof HTMLTextAreaElement;
}

function isSubmitAffordance(element: Element): boolean {
  if (element.getAttribute('role')?.trim().toLowerCase() === 'button') return true;
  if (element instanceof HTMLButtonElement) return element.type !== 'button';
  return element instanceof HTMLInputElement && (element.type === 'submit' || element.type === 'image');
}

function isDescendantOf(scope: ParentNode, node: Node): boolean {
  if (scope === node) return false;
  try {
    return (scope as Node).contains(node);
  } catch {
    return false;
  }
}

function documentFor(root: ParentNode): Document {
  if (root.nodeType === Node.DOCUMENT_NODE) return root as Document;
  const ownerDocument = (root as Node).ownerDocument;
  if (!ownerDocument) throw new TypeError('Autofill detection root must have an owner document');
  return ownerDocument;
}

function scopeInventoryRoot(root: ParentNode): ParentNode {
  if (!(root instanceof HTMLFormElement)) return root;
  const treeRoot = root.getRootNode();
  return treeRoot.nodeType === Node.DOCUMENT_NODE || treeRoot.nodeType === Node.DOCUMENT_FRAGMENT_NODE
    ? treeRoot as ParentNode
    : root.ownerDocument;
}

function resolveLimits(configured: AutofillDetectionLimits): ResolvedLimits {
  return Object.freeze({
    maxVisitedElements: positiveLimit(
      configured.maxVisitedElements ?? DEFAULT_COMPOSED_TREE_MAX_VISITED_ELEMENTS,
      'maxVisitedElements',
    ),
    maxControls: positiveLimit(
      configured.maxControls ?? DEFAULT_AUTOFILL_DETECTION_MAX_CONTROLS,
      'maxControls',
    ),
    maxForms: positiveLimit(configured.maxForms ?? DEFAULT_AUTOFILL_DETECTION_MAX_FORMS, 'maxForms'),
    maxHintBytes: positiveLimit(
      configured.maxHintBytes ?? DEFAULT_AUTOFILL_DETECTION_MAX_HINT_BYTES,
      'maxHintBytes',
    ),
    maxSemanticSources: positiveLimit(
      configured.maxSemanticSources ?? DEFAULT_AUTOFILL_DETECTION_MAX_SEMANTIC_SOURCES,
      'maxSemanticSources',
    ),
    maxSemanticNodes: positiveLimit(
      configured.maxSemanticNodes ?? DEFAULT_AUTOFILL_DETECTION_MAX_SEMANTIC_NODES,
      'maxSemanticNodes',
    ),
    maxCustomTargets: positiveLimit(
      configured.maxCustomTargets ?? DEFAULT_AUTOFILL_DETECTION_MAX_CUSTOM_TARGETS,
      'maxCustomTargets',
    ),
  });
}

function positiveLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive safe integer`);
  return value;
}

function boundedCount(value: number): number {
  return Number.isSafeInteger(value) && value >= 0 ? value : Number.MAX_SAFE_INTEGER;
}
