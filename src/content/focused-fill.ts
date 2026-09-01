import {
  detectLoginForms,
  hasSameTotpInputs,
  totpInputsForForm,
  type DetectedLoginForm,
} from './form-detection.js';
import { detectCardForms, detectIdentityForms, type DetectedFillForm, type FillFieldElement } from './field-detection.js';
import {
  createAutofillDetectionContext,
  createScopedAutofillDetectionContext,
  type AutofillDetectionContext,
  type AutofillDetectionSnapshot,
} from './autofill-detection-context.js';
import { planLoginCustomTargets } from './login-custom-fields.js';
import type { LoginCustomTargetPlan } from '../core/vault/login-custom-fields.js';
import type {
  AutofillCandidate,
  AutofillIntentPurpose,
  AutofillLoginData,
  AutofillTotpData,
  FillItemCandidate,
  FillKind,
} from '../messaging/protocol.js';

export type FocusedTarget =
  | { kind: 'login'; form: DetectedLoginForm; input: HTMLInputElement }
  | { kind: 'totp'; form: DetectedLoginForm; input: HTMLInputElement }
  | { kind: 'card'; form: DetectedFillForm }
  | { kind: 'identity'; form: DetectedFillForm }
  | { kind: 'none' };

export interface FillExclusion {
  /** Real login forms — a login form whose password field is actually a card CVC is dropped. */
  loginForms: DetectedLoginForm[];
  /** The username/password/totp fields of those login forms, to keep them out of card/identity detection. */
  exclude: Set<Element>;
}

export interface FillProjection extends FillExclusion {
  readonly complete: boolean;
  readonly cardForms: readonly DetectedFillForm[];
  readonly identityForms: readonly DetectedFillForm[];
  readonly customPlans: ReadonlyMap<DetectedLoginForm, LoginCustomTargetPlan>;
  readonly context: AutofillDetectionContext;
}

export type AutofillDetectionRoots = ParentNode | readonly ParentNode[] | AutofillDetectionSnapshot;

/**
 * Single source of truth for the login/card/identity carve-out. Mirrors what attachPopovers did inline:
 * build the set of card CVC fields first, then treat a "login" form whose password IS a CVC as not-a-login.
 */
export function computeFillExclusion(root: AutofillDetectionRoots = document): FillExclusion {
  const projection = computeFillProjection(root);
  return { loginForms: [...projection.loginForms], exclude: projection.exclude };
}

/** Build login/card/identity forms from one shared, bounded control and hint inventory. */
export function computeFillProjection(
  root: AutofillDetectionRoots = document,
  suppliedContext?: AutofillDetectionContext,
): FillProjection {
  const roots = normalizeRoots(root);
  const context = suppliedContext ?? contextFor(root, roots);
  if ((isDetectionSnapshot(root) && root.truncated) || !context.complete) {
    return emptyProjection(context);
  }
  const loginForms: DetectedLoginForm[] = [];
  const exclude = new Set<Element>();
  const rawCardForms = new Map<ParentNode, readonly DetectedFillForm[]>();
  const rawIdentityForms = new Map<ParentNode, readonly DetectedFillForm[]>();
  for (const candidateRoot of roots) {
    rawCardForms.set(candidateRoot, detectCardForms(candidateRoot, new Set(), context, false));
    rawIdentityForms.set(candidateRoot, detectIdentityForms(candidateRoot, new Set(), context, false));
  }
  if (!context.complete) return emptyProjection(context);
  for (const candidateRoot of roots) {
    const cardCodeFields = new Set<Element>();
    for (const card of rawCardForms.get(candidateRoot) ?? []) {
      const code = card.fields.get('code');
      if (code) cardCodeFields.add(code);
    }
    const identityFields = new Set<Element>();
    for (const identity of rawIdentityForms.get(candidateRoot) ?? []) {
      for (const field of identity.fields.values()) identityFields.add(field);
    }
    for (const form of detectLoginForms(candidateRoot, context)) {
      if (form.passwordInput && cardCodeFields.has(form.passwordInput)) continue; // a CVC, not a login
      // A strong address/name form may contain an email field that superficially resembles a
      // username-only login step. Keep that field in the identity projection; real two-step login
      // forms do not meet the identity detector's address or first+last-name threshold.
      if (!form.passwordInput && !form.totpInput && form.usernameInput && identityFields.has(form.usernameInput)) continue;
      loginForms.push(form);
      for (const el of [form.usernameInput, form.passwordInput, ...totpInputsForForm(form)]) {
        if (el) exclude.add(el);
      }
    }
  }
  if (!context.complete) return emptyProjection(context);
  const cardForms = roots.flatMap((candidateRoot) => detectCardForms(candidateRoot, exclude, context));
  const identityForms = roots.flatMap((candidateRoot) => detectIdentityForms(candidateRoot, exclude, context));
  if (!context.complete) return emptyProjection(context);
  const customPlans = new Map<DetectedLoginForm, LoginCustomTargetPlan>();
  for (const form of loginForms) {
    customPlans.set(form, planLoginCustomTargets(form, context));
    if (!context.complete) return emptyProjection(context);
  }
  return { complete: true, loginForms, cardForms, identityForms, customPlans, exclude, context };
}

/**
 * Determine which detected form the focused element belongs to. Precedence (identical to attachPopovers):
 * CVC carve-out (inside computeFillExclusion) → login → card → identity → none.
 */
export function resolveFocusedFill(
  activeEl: Element | null,
  root: AutofillDetectionRoots = document,
  suppliedProjection?: FillProjection,
): FocusedTarget {
  if (!isFillFieldElement(activeEl)) return { kind: 'none' };
  const candidateRoot = normalizeRoots(root).find((entry) => entry === activeEl.getRootNode());
  if (!candidateRoot) return { kind: 'none' };
  const projection = suppliedProjection ?? computeFillProjection(root);
  if (!projection.complete) return { kind: 'none' };
  const { loginForms } = projection;
  for (const form of loginForms) {
    if (activeEl instanceof HTMLInputElement && totpInputsForForm(form).includes(activeEl)) {
      return { kind: 'totp', form, input: activeEl };
    }
    if (activeEl === form.usernameInput || activeEl === form.passwordInput) {
      return { kind: 'login', form, input: activeEl };
    }
  }
  for (const form of projection.cardForms.filter((candidate) => candidate.anchor.getRootNode() === candidateRoot)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'card', form };
  }
  for (const form of projection.identityForms.filter((candidate) => candidate.anchor.getRootNode() === candidateRoot)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'identity', form };
  }
  return { kind: 'none' };
}

function isFillFieldElement(element: Element | null): element is FillFieldElement {
  return element instanceof HTMLInputElement
    || element instanceof HTMLSelectElement
    || element instanceof HTMLTextAreaElement;
}

function normalizeRoots(roots: AutofillDetectionRoots): readonly ParentNode[] {
  const requested = isDetectionSnapshot(roots)
    ? roots.roots
    : Array.isArray(roots) ? roots : [roots as ParentNode];
  const unique = [...new Set(requested)];
  return unique.filter((candidate, index) => !unique.some((ancestor, ancestorIndex) => (
    ancestorIndex !== index && containsRoot(ancestor, candidate)
  )));
}

function containsRoot(ancestor: ParentNode, candidate: ParentNode): boolean {
  try {
    return ancestor !== candidate && (ancestor as Node).contains(candidate as Node);
  } catch {
    return false;
  }
}

function contextFor(
  input: AutofillDetectionRoots,
  roots: readonly ParentNode[],
): AutofillDetectionContext {
  return isDetectionSnapshot(input)
    ? createAutofillDetectionContext(input)
    : createScopedAutofillDetectionContext(roots);
}

function emptyProjection(context: AutofillDetectionContext): FillProjection {
  return {
    complete: false,
    loginForms: [],
    cardForms: [],
    identityForms: [],
    customPlans: new Map(),
    exclude: new Set<Element>(),
    context,
  };
}

function isDetectionSnapshot(value: AutofillDetectionRoots): value is AutofillDetectionSnapshot {
  if (Array.isArray(value) || value instanceof Node) return false;
  const candidate = value as AutofillDetectionSnapshot;
  return Array.isArray(candidate.roots)
    && typeof candidate.truncated === 'boolean';
}

export const NOTICE_FOCUS = 'Focus a login, verification code, card, or identity field, then use the shortcut';
export const NOTICE_PAGE_CHANGED = 'Page changed before autofill';
export const FOCUSED_FILL_CYCLE_TTL_MS = 10_000;

type CyclicFocusedTarget = Extract<FocusedTarget, { kind: 'login' | 'totp' }>;

interface FocusedFillCursor {
  readonly purpose: AutofillIntentPurpose;
  readonly frameUrl: string;
  readonly runtimeEpoch: number;
  readonly targetFingerprint: string;
  readonly targetGeneration: number;
  readonly candidateIds: readonly string[];
  readonly candidateFingerprint: string;
  readonly index: number;
  readonly expiresAt: number;
}

export interface FocusedFillCycleContext {
  readonly target: CyclicFocusedTarget;
  readonly purpose: AutofillIntentPurpose;
  readonly frameUrl: string;
  readonly runtimeEpoch: number;
  readonly targetGeneration: number;
  readonly candidateIds: readonly string[];
  readonly now: number;
}

export interface FocusedFillCycleSelection {
  readonly cipherId: string;
  /** Commit only after the purpose-specific secret was redeemed, revalidated, and filled. */
  commit(completedAt: number): void;
}

/**
 * Keeps only non-secret cursor metadata. The keyed element and detector-issued form id bind a
 * cursor to one concrete field role and form generation; a changed field graph cannot inherit it.
 */
export class FocusedFillCycle {
  private cursors = new WeakMap<Element, FocusedFillCursor>();
  private lastAnchor: WeakRef<Element> | undefined;
  private targetGeneration = 0;

  reset(): void {
    this.cursors = new WeakMap<Element, FocusedFillCursor>();
    this.lastAnchor = undefined;
    this.targetGeneration += 1;
  }

  noteFocusedElement(element: Element | undefined): void {
    const previous = this.lastAnchor?.deref();
    if (!element || (previous !== undefined && previous !== element)) this.reset();
    if (element) this.lastAnchor = new WeakRef(element);
  }

  captureTarget(target: CyclicFocusedTarget): number {
    this.noteFocusedElement(target.input);
    return this.targetGeneration;
  }

  isTargetGenerationCurrent(target: CyclicFocusedTarget, generation: number): boolean {
    return this.targetGeneration === generation && this.lastAnchor?.deref() === target.input;
  }

  select(context: FocusedFillCycleContext): FocusedFillCycleSelection {
    if (context.candidateIds.length === 0) throw new Error('Cannot cycle an empty candidate list');
    const anchor = context.target.input;
    this.noteFocusedElement(anchor);
    const mapAtSelection = this.cursors;
    const previous = mapAtSelection.get(anchor);
    const candidateIds = Object.freeze([...context.candidateIds]);
    const candidateFingerprint = JSON.stringify(candidateIds);
    const targetFingerprint = focusedTargetFingerprint(context.target);
    const canAdvance = previous !== undefined
      && previous.purpose === context.purpose
      && previous.frameUrl === context.frameUrl
      && previous.runtimeEpoch === context.runtimeEpoch
      && previous.targetFingerprint === targetFingerprint
      && previous.targetGeneration === context.targetGeneration
      && previous.candidateFingerprint === candidateFingerprint
      && sameCandidateIds(previous.candidateIds, candidateIds)
      && context.now < previous.expiresAt;
    const index = canAdvance ? (previous.index + 1) % candidateIds.length : 0;
    const cipherId = candidateIds[index]!;

    return Object.freeze({
      cipherId,
      commit: (completedAt: number): void => {
        // A stale async selection must never overwrite a reset or a newer committed cursor.
        if (this.cursors !== mapAtSelection || mapAtSelection.get(anchor) !== previous) return;
        mapAtSelection.set(anchor, Object.freeze({
          purpose: context.purpose,
          frameUrl: context.frameUrl,
          runtimeEpoch: context.runtimeEpoch,
          targetFingerprint,
          targetGeneration: context.targetGeneration,
          candidateIds,
          candidateFingerprint,
          index,
          expiresAt: completedAt + FOCUSED_FILL_CYCLE_TTL_MS,
        }));
      },
    });
  }
}

function focusedTargetFingerprint(target: CyclicFocusedTarget): string {
  const role = target.kind === 'totp'
    ? 'totp'
    : target.input === target.form.usernameInput ? 'username' : 'password';
  return JSON.stringify([target.kind, role, target.form.id]);
}

function sameCandidateIds(first: readonly string[], second: readonly string[]): boolean {
  return first.length === second.length && first.every((id, index) => id === second[index]);
}

export type FillOutcome<T> = { ok: true; data: T } | { ok: false; message: string };
export type IntentFillOutcome<T> = FillOutcome<T> | {
  ok: false;
  message: string;
  repromptContinuationId: string;
};

export interface FocusedFillDeps {
  frameUrl(): string;
  runtimeEpoch(): number;
  now(): number;
  isTargetCurrent(target: FocusedTarget): boolean;
  readonly cycle: FocusedFillCycle;
  loginCandidates(purpose: AutofillIntentPurpose): Promise<FillOutcome<AutofillCandidate[]>>;
  issueIntent(cipherId: string, purpose: AutofillIntentPurpose, form?: DetectedLoginForm): Promise<IntentFillOutcome<string>>;
  redeemLoginIntent(intentId: string): Promise<FillOutcome<AutofillLoginData>>;
  redeemTotpIntent(intentId: string): Promise<FillOutcome<AutofillTotpData>>;
  fillItems(kind: FillKind): Promise<FillOutcome<FillItemCandidate[]>>;
  /** Redeem a document-bound capability; the worker re-inspects and commits without returning secrets. */
  fillStructured(cipherId: string, form: DetectedFillForm): Promise<IntentFillOutcome<void>>;
  deferReprompt?(
    continuationId: string,
    target: Exclude<FocusedTarget, { kind: 'none' }>,
    selection?: FocusedFillCycleSelection,
  ): void;
  fillLogin(form: DetectedLoginForm, data: AutofillLoginData): boolean;
  fillTotp(input: HTMLInputElement, data: AutofillTotpData): boolean;
  openPicker(form: DetectedFillForm, items: readonly FillItemCandidate[]): void;
  notify(message: string): void;
}

function loginTargetLive(target: Extract<FocusedTarget, { kind: 'login' }>): boolean {
  const { form, input } = target;
  if (!input.isConnected || (input !== form.usernameInput && input !== form.passwordInput)) return false;
  const fields = [form.usernameInput, form.passwordInput].filter((f): f is HTMLInputElement => Boolean(f));
  if (fields.length === 0 || fields.some((field) => !field.isConnected)) return false;
  const root = form.anchor.getRootNode();
  if (!isParentNode(root)) return false;
  const projection = computeFillProjection(root);
  return projection.complete && projection.loginForms.some((current) => (
    current.id === form.id
    && current.form === form.form
    && current.anchor === form.anchor
    && current.usernameInput === form.usernameInput
    && current.passwordInput === form.passwordInput
    && current.totpInput === form.totpInput
    && hasSameTotpInputs(current, form)
  ));
}

function fillFormLive(form: DetectedFillForm): boolean {
  const fields = [...form.fields.values()];
  if (fields.length === 0 || fields.some((field) => !field.isConnected)) return false;
  const root = form.anchor.getRootNode();
  if (!isParentNode(root)) return false;
  const projection = computeFillProjection(root);
  if (!projection.complete) return false;
  const currentForms = form.kind === 'card' ? projection.cardForms : projection.identityForms;
  return currentForms.some((current) => (
    current.id === form.id
    && current.fields.size === form.fields.size
    && [...form.fields].every(([role, field]) => current.fields.get(role) === field)
  ));
}

function totpTargetLive(target: Extract<FocusedTarget, { kind: 'totp' }>): boolean {
  const { form, input } = target;
  if (!input.isConnected) return false;
  const root = input.getRootNode();
  if (!isParentNode(root)) return false;
  const projection = computeFillProjection(root);
  return projection.complete && projection.loginForms.some((current) => (
    current.id === form.id
    && current.form === form.form
    && current.anchor === form.anchor
    && current.usernameInput === form.usernameInput
    && current.passwordInput === form.passwordInput
    && current.totpInput === form.totpInput
    && totpInputsForForm(current).includes(input)
    && hasSameTotpInputs(current, form)
  ));
}

function isParentNode(node: Node): node is ParentNode {
  return node.nodeType === Node.ELEMENT_NODE
    || node.nodeType === Node.DOCUMENT_NODE
    || node.nodeType === Node.DOCUMENT_FRAGMENT_NODE;
}

/** Resolve a focused target to an autofill action, reusing existing worker requests via injected deps. */
export async function runFocusedFill(target: FocusedTarget, deps: FocusedFillDeps): Promise<void> {
  if (target.kind === 'none') { deps.cycle.reset(); deps.notify(NOTICE_FOCUS); return; }

  if (target.kind === 'login') {
    const frameUrl = deps.frameUrl();
    const runtimeEpoch = deps.runtimeEpoch();
    const targetGeneration = deps.cycle.captureTarget(target);
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    const cands = await deps.loginCandidates('login');
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    if (!cands.ok) { deps.notify(cands.message); return; }
    if (cands.data.length === 0) { deps.notify('No matching logins'); return; }
    const selection = deps.cycle.select({
      target,
      purpose: 'login',
      frameUrl,
      runtimeEpoch,
      targetGeneration,
      candidateIds: cands.data.map((candidate) => candidate.id),
      now: deps.now(),
    });
    const intent = await deps.issueIntent(selection.cipherId, 'login', target.form);
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    if (!intent.ok) {
      if ('repromptContinuationId' in intent) deps.deferReprompt?.(intent.repromptContinuationId, target, selection);
      deps.notify(intent.message);
      return;
    }
    const login = await deps.redeemLoginIntent(intent.data);
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    if (!login.ok) { deps.notify(login.message); return; }
    if (deps.fillLogin(target.form, login.data)) selection.commit(deps.now());
    return;
  }

  if (target.kind === 'totp') {
    const frameUrl = deps.frameUrl();
    const runtimeEpoch = deps.runtimeEpoch();
    const targetGeneration = deps.cycle.captureTarget(target);
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    const cands = await deps.loginCandidates('totp');
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    if (!cands.ok) { deps.notify(cands.message); return; }
    if (cands.data.length === 0) { deps.notify('No matching verification codes'); return; }
    const selection = deps.cycle.select({
      target,
      purpose: 'totp',
      frameUrl,
      runtimeEpoch,
      targetGeneration,
      candidateIds: cands.data.map((candidate) => candidate.id),
      now: deps.now(),
    });
    const intent = await deps.issueIntent(selection.cipherId, 'totp');
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    if (!intent.ok) {
      if ('repromptContinuationId' in intent) deps.deferReprompt?.(intent.repromptContinuationId, target, selection);
      deps.notify(intent.message);
      return;
    }
    const totp = await deps.redeemTotpIntent(intent.data);
    if (!cyclicTargetCurrent(target, deps, frameUrl, runtimeEpoch, targetGeneration)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    if (!totp.ok) { deps.notify(totp.message); return; }
    if (deps.fillTotp(target.input, totp.data)) selection.commit(deps.now());
    return;
  }

  const kind = target.kind; // 'card' | 'identity'
  deps.cycle.reset();
  const frameUrl = deps.frameUrl();
  const runtimeEpoch = deps.runtimeEpoch();
  if (!structuredTargetCurrent(target, deps, frameUrl, runtimeEpoch)) {
    deps.notify(NOTICE_PAGE_CHANGED);
    return;
  }
  const items = await deps.fillItems(kind);
  if (!structuredTargetCurrent(target, deps, frameUrl, runtimeEpoch)) {
    deps.notify(NOTICE_PAGE_CHANGED);
    return;
  }
  if (!items.ok) { deps.notify(items.message); return; }
  if (items.data.length === 0) { deps.notify(kind === 'card' ? 'No saved cards' : 'No saved identities'); return; }
  if (items.data.length > 1) { deps.openPicker(target.form, items.data); return; }
  const filled = await deps.fillStructured(items.data[0]!.id, target.form);
  if (!filled.ok) {
    if ('repromptContinuationId' in filled) deps.deferReprompt?.(filled.repromptContinuationId, target);
    deps.notify(filled.message);
  }
}

function structuredTargetCurrent(
  target: Extract<FocusedTarget, { kind: 'card' | 'identity' }>,
  deps: FocusedFillDeps,
  frameUrl: string,
  runtimeEpoch: number,
): boolean {
  return deps.frameUrl() === frameUrl
    && deps.runtimeEpoch() === runtimeEpoch
    && deps.isTargetCurrent(target)
    && fillFormLive(target.form);
}

function cyclicTargetCurrent(
  target: CyclicFocusedTarget,
  deps: FocusedFillDeps,
  frameUrl: string,
  runtimeEpoch: number,
  targetGeneration: number,
): boolean {
  if (deps.frameUrl() !== frameUrl
      || deps.runtimeEpoch() !== runtimeEpoch
      || !deps.cycle.isTargetGenerationCurrent(target, targetGeneration)
      || !deps.isTargetCurrent(target)) return false;
  return target.kind === 'login' ? loginTargetLive(target) : totpTargetLive(target);
}
