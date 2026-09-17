import type {
  AutofillLoginData,
  CardFillData,
  CardFillRole,
  FrameAutofillForm,
  FrameCardForm,
  FrameIdentityForm,
  FrameInspection,
  FrameLoginForm,
  IdentityFillData,
  IdentityFillRole,
  TabFillOutcome,
  LoginCustomAssignment,
  LoginCustomTargetPlan,
} from '../messaging/protocol.js';
import {
  CARD_FILL_ROLES,
  IDENTITY_FILL_ROLES,
  normalizeFillRoles,
  type FillRole,
} from '../core/vault/fill-roles.js';
import {
  digestLoginCustomTargetPlan,
  equalLoginCustomPlanDigest,
} from '../core/vault/login-custom-fields.js';
import { scanOpenComposedRoots, type ComposedTreeSnapshot } from './composed-tree.js';
import {
  isFillableField,
  type DetectedFillForm,
  type FillFieldElement,
} from './field-detection.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';
import type { DetectedLoginForm } from './form-detection.js';
import {
  captureControlOwner,
  composedSlotPath,
  hasSameTotpInputs,
  hasSameControlOwner,
  hasLoginCredentialTarget,
  isFillableInput,
  isVisibleInTree,
  totpInputsForForm,
  type ControlOwnerSnapshot,
} from './form-detection.js';
import { fillLoginForm } from './fill.js';
import { commitLoginCustomAssignments } from './login-custom-fields.js';
import { computeFillProjection, type FillProjection } from './focused-fill.js';
import { createStagedFillCommit } from './staged-fill.js';
import { createStructuredFillUndo, type StructuredFieldWrite, type StructuredFillUndo } from './structured-fill-undo.js';
import {
  createAutofillDetectionContext,
  type AutofillDetectionContext,
  type AutofillDetectionSnapshot,
} from './autofill-detection-context.js';

export interface FrameAutofillControllerOptions {
  /** The document (or one test subtree) to scan. Defaults to `document`. */
  root?: ParentNode;
  /** Complete root snapshot; preferred because truncation must fail the entire frame projection. */
  snapshot?: () => AutofillDetectionSnapshot;
  /** Authoritative bounded refresh used for every state read, including staged revalidation. */
  refresh?: () => AutofillDetectionSnapshot;
  /** Optional owner-runtime guard for asynchronous digest verification and staged writes. */
  isCurrent?: () => boolean;
  /** Live root inventory for a document with nested open shadow roots. */
  roots?: () => readonly ParentNode[];
  /** Returns the frame's current URL. Injected so tests and iframes can control/observe it. */
  frameUrl: () => string;
  /** Returns the current time (ms). Injected for deterministic tests. */
  now: () => number;
}

export interface FrameLoginCommitRequest {
  formId: string;
  expectedFrameUrl: string;
  expectedGeneration: number;
  login: AutofillLoginData;
  customPlan: LoginCustomTargetPlan;
  customPlanDigest: string;
  customAssignments: readonly LoginCustomAssignment[];
}

export type FrameStructuredCommitRequest =
  | {
      kind: 'card';
      formId: string;
      expectedFrameUrl: string;
      expectedGeneration: number;
      roles: readonly CardFillRole[];
      selectedRoles?: readonly CardFillRole[];
      data: CardFillData;
    }
  | {
      kind: 'identity';
      formId: string;
      expectedFrameUrl: string;
      expectedGeneration: number;
      roles: readonly IdentityFillRole[];
      selectedRoles?: readonly IdentityFillRole[];
      data: IdentityFillData;
    };

export interface FrameAutofillController {
  /** Record the detected form that owns a focused input or select. */
  noteFocus(field: FillFieldElement): void;
  /** Re-detect every live root and return metadata only, never field values. */
  inspect(): Omit<FrameInspection, 'runtimeIncarnation'>;
  /** Re-detect and fill a login only when URL, generation, and form identity still match. */
  commitLogin(request: FrameLoginCommitRequest): Promise<TabFillOutcome>;
  /** Re-detect and fill a card/identity only when every structural binding still matches. */
  commitStructured(request: FrameStructuredCommitRequest): TabFillOutcome;
  /** Capture reviewed field values locally; those values never cross the worker boundary. */
  prepareStructuredSelection(formId: string, generation: number, selectedRoles: readonly FillRole[]): boolean;
  clearStructuredSelection(): void;
  takeStructuredUndo(): StructuredFillUndo | undefined;
}

interface LoginTarget {
  readonly kind: 'login';
  readonly root: ParentNode;
  readonly metadata: FrameLoginForm;
  readonly detected: DetectedLoginForm;
}

interface CardTarget {
  readonly kind: 'card';
  readonly root: ParentNode;
  readonly metadata: FrameCardForm;
  readonly detected: DetectedFillForm;
}

interface IdentityTarget {
  readonly kind: 'identity';
  readonly root: ParentNode;
  readonly metadata: FrameIdentityForm;
  readonly detected: DetectedFillForm;
}

type FrameTarget = LoginTarget | CardTarget | IdentityTarget;

interface StructuralSnapshot {
  readonly roots: readonly ParentNode[];
  readonly complete: boolean;
  readonly forms: readonly FrameAutofillForm[];
}

interface PrivateFormIdentity {
  readonly kind: FrameAutofillForm['kind'];
  readonly scope: ParentNode;
  readonly root: Node;
  readonly slotPath: readonly HTMLSlotElement[];
  readonly fields: readonly (readonly [role: string, field: FillFieldElement])[];
  readonly fieldOwners: readonly (readonly [string, FillFieldElement, ControlOwnerSnapshot])[];
  readonly formId: string;
}

/**
 * Build a per-frame metadata/commit controller. It retains only structural metadata and the last
 * focused private form id; every commit obtains fresh detector output before writing vault data.
 */
export function createFrameAutofillController(options: FrameAutofillControllerOptions): FrameAutofillController {
  let generation = 0;
  let previousStructure: StructuralSnapshot | undefined;
  let nextPrivateFormId = 0;
  const privateIds = new WeakMap<HTMLElement, Map<FrameAutofillForm['kind'], PrivateFormIdentity>>();
  let lastFocusedFormId: string | undefined;
  let focusedAt: number | undefined;
  let pendingSelection: {
    readonly target: CardTarget | IdentityTarget;
    readonly generation: number;
    readonly frameUrl: string;
    readonly roles: readonly FillRole[];
    readonly values: ReadonlyMap<FillFieldElement, string>;
    readonly expiresAt: number;
  } | undefined;
  let structuredUndo: StructuredFillUndo | undefined;

  function clearStructuredSelection(): void {
    pendingSelection = undefined;
    structuredUndo?.dispose();
    structuredUndo = undefined;
  }

  function prepareStructuredSelection(formId: string, expectedGeneration: number, selectedRoles: readonly FillRole[]): boolean {
    pendingSelection = undefined;
    structuredUndo?.dispose();
    structuredUndo = undefined;
    if (!controllerIsCurrent(options)) return false;
    const state = readState();
    const target = state.targets.find((entry) => entry.metadata.formId === formId);
    if (state.generation !== expectedGeneration || !target || target.kind === 'login' || !allFillFieldsLive(target.detected)) return false;
    const roles = normalizeFillRoles(target.kind, selectedRoles);
    if (!roles || !sameRoles(roles, selectedRoles) || roles.some((role) => !target.detected.fields.has(role))) return false;
    pendingSelection = {
      target,
      generation: state.generation,
      frameUrl: options.frameUrl(),
      roles,
      values: new Map(roles.map((role) => {
        const field = target.detected.fields.get(role)!;
        return [field, field.value];
      })),
      expiresAt: options.now() + 120_000,
    };
    return true;
  }

  function noteFocus(field: FillFieldElement): void {
    const state = readState();
    const owner = state.targets.find((target) => ownsField(target, field));
    if (!owner) return;
    lastFocusedFormId = owner.metadata.formId;
    focusedAt = options.now();
  }

  function inspect(): Omit<FrameInspection, 'runtimeIncarnation'> {
    const state = readState();
    return {
      frameUrl: options.frameUrl(),
      generation: state.generation,
      forms: state.targets.map((target) => withFocus(target.metadata)),
    };
  }

  async function commitLogin(request: FrameLoginCommitRequest): Promise<TabFillOutcome> {
    if (!controllerIsCurrent(options) || options.frameUrl() !== request.expectedFrameUrl) {
      return { status: 'target_changed' };
    }
    try {
      const actualDigest = await digestLoginCustomTargetPlan(request.customPlan);
      if (!controllerIsCurrent(options)
          || options.frameUrl() !== request.expectedFrameUrl
          || !equalLoginCustomPlanDigest(actualDigest, request.customPlanDigest)) {
        return { status: 'target_changed' };
      }
    } catch {
      return { status: 'target_changed' };
    }
    const state = readState();
    if (state.generation !== request.expectedGeneration) return { status: 'target_changed' };
    const target = state.targets.find(
      (candidate): candidate is LoginTarget => candidate.kind === 'login'
        && candidate.metadata.formId === request.formId,
    );
    if (!target || !allLoginFieldsLive(target.detected)) return { status: 'target_changed' };
    const staged = createStagedFillCommit(() => {
      if (!controllerIsCurrent(options) || options.frameUrl() !== request.expectedFrameUrl) return false;
      const currentState = readState();
      if (currentState.generation !== request.expectedGeneration) return false;
      const current = currentState.targets.find(
        (candidate): candidate is LoginTarget => candidate.kind === 'login'
          && candidate.metadata.formId === request.formId,
      );
      return Boolean(current && sameLoginTarget(target, current) && allLoginFieldsLive(current.detected));
    });
    const loginFilled = fillLoginForm(target.detected, request.login, staged);
    if (staged.stale || !staged.isCurrent()) return { status: 'target_changed' };
    const customFilled = commitLoginCustomAssignments(
      target.detected,
      request.customPlan,
      request.customAssignments,
      staged,
    );
    if (staged.stale || !staged.isCurrent()) return { status: 'target_changed' };
    return loginFilled || (customFilled && request.customAssignments.length > 0)
      ? { status: 'filled' }
      : { status: 'no_fillable_target' };
  }

  function commitStructured(request: FrameStructuredCommitRequest): TabFillOutcome {
    const selection = pendingSelection;
    pendingSelection = undefined;
    structuredUndo?.dispose();
    structuredUndo = undefined;
    if (!controllerIsCurrent(options) || options.frameUrl() !== request.expectedFrameUrl) {
      return { status: 'target_changed' };
    }
    const state = readState();
    if (state.generation !== request.expectedGeneration) return { status: 'target_changed' };
    const target = state.targets.find((candidate) => (
      candidate.kind === request.kind
      && candidate.metadata.formId === request.formId
    ));
    if (!target || target.kind === 'login' || !allFillFieldsLive(target.detected)) {
      return { status: 'target_changed' };
    }
    const selectedRoles = request.selectedRoles ?? request.roles;
    const normalized = normalizeFillRoles(request.kind, selectedRoles);
    if (!normalized || !sameRoles(normalized, selectedRoles)
        || selectedRoles.some((role) => !target.detected.fields.has(role))) return { status: 'target_changed' };
    if (request.selectedRoles !== undefined && (!selection
        || selection.generation !== state.generation
        || selection.frameUrl !== request.expectedFrameUrl
        || selection.expiresAt <= options.now()
        || !sameFillTarget(selection.target, target)
        || !sameRoles(selection.roles, selectedRoles))) return { status: 'target_changed' };
    const values = request.selectedRoles !== undefined ? new Map(selection!.values) : undefined;
    const writes: StructuredFieldWrite[] = [];
    const onWrite = (write: StructuredFieldWrite): void => {
      writes.push(write);
      // Once a field is written, page formatters may normalize it. Only untouched reviewed values
      // gate later writes; the undo receipt independently compares the exact native write value.
      values?.delete(write.element);
    };
    const staged = createStagedFillCommit(() => {
      if (!controllerIsCurrent(options) || options.frameUrl() !== request.expectedFrameUrl) return false;
      if (values && [...values].some(([field, expected]) => field.value !== expected)) return false;
      const currentState = readState();
      if (currentState.generation !== request.expectedGeneration) return false;
      const current = currentState.targets.find((candidate) => (
        candidate.kind === request.kind && candidate.metadata.formId === request.formId
      ));
      return Boolean(
        current
        && current.kind !== 'login'
        && sameFillTarget(target, current)
        && allFillFieldsLive(current.detected),
      );
    });
    // Filter actual element assignments as well as wire data: composite full-name/address/expiry
    // data keys can otherwise accidentally populate an unselected field that shares those keys.
    const selectedRoleSet = new Set<FillRole>(selectedRoles);
    const selectedForm = { ...target.detected, fields: new Map([...target.detected.fields].filter(([role]) => selectedRoleSet.has(role))) };
    const finish = (filled: boolean): TabFillOutcome => {
      if (staged.stale || !staged.isCurrent()) return { status: 'target_changed' };
      if (!filled) return { status: 'no_fillable_target' };
      if (request.selectedRoles !== undefined) {
        structuredUndo = createStructuredFillUndo(writes, () => {
          if (!controllerIsCurrent(options) || options.frameUrl() !== request.expectedFrameUrl) return false;
          const state = readState();
          if (state.generation !== request.expectedGeneration) return false;
          const current = state.targets.find((entry) => entry.kind === request.kind && entry.metadata.formId === request.formId);
          return Boolean(current && current.kind !== 'login' && sameFillTarget(target, current) && allFillFieldsLive(current.detected));
        }, options.now);
      }
      return { status: 'filled' };
    };
    if (request.kind === 'card') {
      if (target.kind !== 'card' || !sameRoles(target.metadata.roles, request.roles)) {
        return { status: 'target_changed' };
      }
      return finish(fillCardForm(selectedForm, request.data, staged, onWrite));
    }
    if (target.kind !== 'identity' || !sameRoles(target.metadata.roles, request.roles)) {
      return { status: 'target_changed' };
    }
    return finish(fillIdentityForm(selectedForm, request.data, staged, onWrite));
  }

  function readState(): { readonly generation: number; readonly targets: readonly FrameTarget[] } {
    const snapshot = readSnapshot(options);
    const context = createAutofillDetectionContext(snapshot);
    const projection = computeFillProjection(snapshot, context);
    let targets = projection.complete ? detectTargets(projection, context, privateIdFor) : [];
    const complete = projection.complete && context.complete;
    if (!complete) targets = [];
    const structure: StructuralSnapshot = {
      roots: snapshot.roots,
      complete,
      forms: targets.map((target) => target.metadata),
    };
    if (!previousStructure || !sameStructure(previousStructure, structure)) {
      generation += 1;
      previousStructure = copyStructure(structure);
    }
    return { generation, targets };
  }

  function privateIdFor(
    kind: FrameAutofillForm['kind'],
    anchor: HTMLElement,
    scope: ParentNode,
    fields: readonly (readonly [role: string, field: FillFieldElement])[],
  ): string {
    let identities = privateIds.get(anchor);
    const existing = identities?.get(kind);
    const root = anchor.getRootNode();
    const slotPath = composedSlotPath(anchor);
    const fieldOwners = fields.map(([role, field]) => [role, field, captureControlOwner(field)] as const);
    if (existing
        && existing.kind === kind
        && existing.scope === scope
        && existing.root === root
        && sameSlots(existing.slotPath, slotPath)
        && samePrivateFields(existing.fields, fields)
        && samePrivateFieldOwners(existing.fieldOwners, fieldOwners)) return existing.formId;
    const formId = `vw-frame-form-${nextPrivateFormId++}`;
    if (!identities) {
      identities = new Map();
      privateIds.set(anchor, identities);
    }
    identities.set(kind, {
      kind,
      scope,
      root,
      slotPath,
      fields: fields.map(([role, field]) => [role, field] as const),
      fieldOwners,
      formId,
    });
    return formId;
  }

  function withFocus(metadata: FrameAutofillForm): FrameAutofillForm {
    return metadata.formId === lastFocusedFormId && focusedAt !== undefined
      ? { ...metadata, focusedAt }
      : { ...metadata };
  }

  return {
    noteFocus, inspect, commitLogin, commitStructured, prepareStructuredSelection, clearStructuredSelection,
    takeStructuredUndo: () => {
      const receipt = structuredUndo;
      structuredUndo = undefined;
      return receipt;
    },
  };
}

function controllerIsCurrent(options: FrameAutofillControllerOptions): boolean {
  try {
    return options.isCurrent?.() ?? true;
  } catch {
    return false;
  }
}

function readSnapshot(options: FrameAutofillControllerOptions): AutofillDetectionSnapshot {
  const suppliedSnapshot = options.refresh?.() ?? options.snapshot?.();
  if (suppliedSnapshot) {
    return { roots: [...new Set(suppliedSnapshot.roots)], truncated: suppliedSnapshot.truncated };
  }
  const suppliedRoots = options.roots?.();
  if (suppliedRoots) return { roots: [...new Set(suppliedRoots)], truncated: false };
  return discoverSnapshot(options.root ?? document);
}

function discoverSnapshot(root: ParentNode): AutofillDetectionSnapshot {
  if (root.nodeType === Node.DOCUMENT_NODE || (root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && 'host' in root)) {
    const snapshot: ComposedTreeSnapshot = scanOpenComposedRoots(root as Document | ShadowRoot);
    return snapshot;
  }
  return { roots: [root], truncated: false };
}

function detectTargets(
  projection: FillProjection,
  context: AutofillDetectionContext,
  privateIdFor: (
    kind: FrameAutofillForm['kind'],
    anchor: HTMLElement,
    scope: ParentNode,
    fields: readonly (readonly [role: string, field: FillFieldElement])[],
  ) => string,
): FrameTarget[] {
  const targets: FrameTarget[] = [];
  for (const form of projection.loginForms) {
    const root = form.anchor.getRootNode() as ParentNode;
    if (!hasLoginCredentialTarget(form)) continue;
    const fields: Array<readonly [string, HTMLInputElement]> = [];
    if (form.usernameInput) fields.push(['username', form.usernameInput]);
    if (form.passwordInput) fields.push(['password', form.passwordInput]);
    totpInputsForForm(form).forEach((field, index) => fields.push([`totp:${index}`, field]));
    targets.push({
      kind: 'login',
      root,
      metadata: {
        kind: 'login',
        formId: privateIdFor('login', form.anchor, form.form ?? scopeFor(form.anchor), fields),
        visible: isVisibleInTree(form.anchor),
        customPlan: projection.customPlans.get(form)!,
      },
      detected: form,
    });
  }
  if (!context.complete) return [];
  for (const form of projection.cardForms) {
    const root = form.anchor.getRootNode() as ParentNode;
    const roles = CARD_FILL_ROLES.filter((role) => form.fields.has(role));
    const fields = roles.map((role) => [role, form.fields.get(role)!] as const);
    targets.push({
      kind: 'card',
      root,
      metadata: {
        kind: 'card',
        formId: privateIdFor('card', form.anchor, scopeFor(form.anchor), fields),
        roles: [...roles],
        visible: isVisibleInTree(form.anchor),
      },
      detected: form,
    });
  }
  for (const form of projection.identityForms) {
    const root = form.anchor.getRootNode() as ParentNode;
    const roles = IDENTITY_FILL_ROLES.filter((role) => form.fields.has(role));
    const fields = roles.map((role) => [role, form.fields.get(role)!] as const);
    targets.push({
      kind: 'identity',
      root,
      metadata: {
        kind: 'identity',
        formId: privateIdFor('identity', form.anchor, scopeFor(form.anchor), fields),
        roles: [...roles],
        visible: isVisibleInTree(form.anchor),
      },
      detected: form,
    });
  }
  if (!context.complete) return [];
  const rootOrder = new Map(context.roots.map((root, index) => [root, index]));
  return targets.map((target, index) => ({ target, index })).sort((left, right) => {
    const rootDifference = (rootOrder.get(left.target.root) ?? Number.MAX_SAFE_INTEGER)
      - (rootOrder.get(right.target.root) ?? Number.MAX_SAFE_INTEGER);
    if (rootDifference !== 0) return rootDifference;
    try {
      const position = left.target.detected.anchor.compareDocumentPosition(right.target.detected.anchor);
      if ((position & Node.DOCUMENT_POSITION_FOLLOWING) !== 0) return -1;
      if ((position & Node.DOCUMENT_POSITION_PRECEDING) !== 0) return 1;
    } catch {
      // Preserve detector admission order when the platform cannot compare two live anchors.
    }
    return left.index - right.index;
  }).map(({ target }) => target);
}

function ownsField(target: FrameTarget, field: FillFieldElement): boolean {
  if (target.kind === 'login') {
    return target.detected.usernameInput === field
      || target.detected.passwordInput === field
      || totpInputsForForm(target.detected).includes(field as HTMLInputElement);
  }
  return [...target.detected.fields.values()].includes(field);
}

function sameLoginTarget(first: LoginTarget, second: LoginTarget): boolean {
  return first.metadata.formId === second.metadata.formId
    && first.detected.id === second.detected.id
    && first.detected.form === second.detected.form
    && first.detected.anchor === second.detected.anchor
    && first.root === second.root
    && first.detected.usernameInput === second.detected.usernameInput
    && first.detected.passwordInput === second.detected.passwordInput
    && first.detected.totpInput === second.detected.totpInput
    && hasSameTotpInputs(first.detected, second.detected);
}

function sameFillTarget(first: CardTarget | IdentityTarget, second: CardTarget | IdentityTarget): boolean {
  return first.kind === second.kind
    && first.metadata.formId === second.metadata.formId
    && first.detected.id === second.detected.id
    && first.detected.anchor === second.detected.anchor
    && first.root === second.root
    && first.detected.fields.size === second.detected.fields.size
    && [...first.detected.fields].every(([role, field]) => second.detected.fields.get(role) === field);
}

function scopeFor(anchor: HTMLElement): ParentNode {
  if (anchor instanceof HTMLInputElement || anchor instanceof HTMLSelectElement || anchor instanceof HTMLTextAreaElement) {
    if (anchor.form) return anchor.form;
  }
  return anchor.closest('section, main, article') ?? (anchor.getRootNode() as ParentNode);
}

function samePrivateFields(
  first: readonly (readonly [role: string, field: FillFieldElement])[],
  second: readonly (readonly [role: string, field: FillFieldElement])[],
): boolean {
  return first.length === second.length
    && first.every(([role, field], index) => role === second[index]?.[0] && field === second[index]?.[1]);
}

function sameSlots(first: readonly HTMLSlotElement[], second: readonly HTMLSlotElement[]): boolean {
  return first.length === second.length && first.every((slot, index) => slot === second[index]);
}

function samePrivateFieldOwners(
  first: readonly (readonly [string, FillFieldElement, ControlOwnerSnapshot])[],
  second: readonly (readonly [string, FillFieldElement, ControlOwnerSnapshot])[],
): boolean {
  return first.length === second.length && first.every(([role, field, owner], index) => {
    const current = second[index];
    return current !== undefined
      && role === current[0]
      && field === current[1]
      && hasSameControlOwner(owner, current[2]);
  });
}

function allLoginFieldsLive(form: DetectedLoginForm): boolean {
  const fields = [form.usernameInput, form.passwordInput, ...totpInputsForForm(form)]
    .filter((field): field is HTMLInputElement => field !== undefined);
  return fields.length > 0 && fields.every((field) => field.isConnected && isFillableInput(field));
}

function allFillFieldsLive(form: DetectedFillForm): boolean {
  const fields = [...form.fields.values()];
  return fields.length > 0 && fields.every((field) => field.isConnected && isFillableField(field));
}

function sameStructure(first: StructuralSnapshot, second: StructuralSnapshot): boolean {
  return first.complete === second.complete
    && first.roots.length === second.roots.length
    && first.roots.every((root, index) => root === second.roots[index])
    && first.forms.length === second.forms.length
    && first.forms.every((form, index) => sameFormStructure(form, second.forms[index]));
}

function sameFormStructure(first: FrameAutofillForm, second: FrameAutofillForm | undefined): boolean {
  if (!second
      || first.kind !== second.kind
      || first.formId !== second.formId
      || first.visible !== second.visible) return false;
  if (first.kind === 'login' || second.kind === 'login') return first.kind === second.kind;
  return first.kind === second.kind && sameRoles(first.roles, second.roles);
}

function sameRoles(first: readonly string[], second: readonly string[]): boolean {
  return first.length === second.length && first.every((role, index) => role === second[index]);
}

function copyStructure(structure: StructuralSnapshot): StructuralSnapshot {
  return {
    roots: [...structure.roots],
    complete: structure.complete,
    forms: structure.forms.map(copyFormStructure),
  };
}

function copyFormStructure(form: FrameAutofillForm): FrameAutofillForm {
  if (form.kind === 'login') return { ...form };
  if (form.kind === 'card') return { ...form, roles: [...form.roles] };
  return { ...form, roles: [...form.roles] };
}
