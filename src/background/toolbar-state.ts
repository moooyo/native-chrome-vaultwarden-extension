import type { SessionState } from '../core/session/session-manager.js';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';

export const TOOLBAR_BADGE_COLORS = Object.freeze({
  approvals: '#B7791F',
  matches: '#175DDC',
  empty: '#175DDC',
});

export type ToolbarIconKind = 'neutral' | 'locked' | 'unlocked';
export type ToolbarIconPaths = Readonly<Record<16 | 32 | 48 | 128, string>>;

export const TOOLBAR_ICON_PATHS: Readonly<Record<ToolbarIconKind, ToolbarIconPaths>> = Object.freeze({
  neutral: Object.freeze({
    16: 'icons/icon16_neutral.png',
    32: 'icons/icon32_neutral.png',
    48: 'icons/icon48_neutral.png',
    128: 'icons/icon128_neutral.png',
  }),
  locked: Object.freeze({
    16: 'icons/icon16_locked.png',
    32: 'icons/icon32_locked.png',
    48: 'icons/icon48_locked.png',
    128: 'icons/icon128_locked.png',
  }),
  unlocked: Object.freeze({
    16: 'icons/icon16.png',
    32: 'icons/icon32.png',
    48: 'icons/icon48.png',
    128: 'icons/icon128.png',
  }),
});

export interface ToolbarStateInput {
  readonly authState: SessionState;
  readonly copy: ToolbarStateCopy;
  readonly pendingApprovalCount?: number;
  readonly matchingLoginCount?: number;
  readonly showMatchingLoginCount?: boolean;
}

export interface ToolbarStateCopy {
  readonly unlocked: string;
  readonly locked: string;
  readonly signedOut: string;
  readonly pendingApprovals: (count: number) => string;
  readonly matchingLogins: (count: number) => string;
}

export interface ToolbarState {
  readonly iconKind: ToolbarIconKind;
  readonly icon: ToolbarIconPaths;
  readonly badgeText: string;
  readonly badgeBackgroundColor: string;
  readonly title: string;
}

export interface ToolbarAuthTransitionState {
  readonly transitionId: number;
  readonly authState: SessionState;
}

export interface ToolbarAuthTransitionResult extends ToolbarAuthTransitionState {
  readonly accepted: boolean;
  readonly clearMatches: boolean;
  readonly clearApprovals: boolean;
  readonly refreshMatches: boolean;
}

/** Transition-id fence that rejects late A settlements after a newer B start, including A -> B -> A. */
export function reduceToolbarAuthTransition(
  current: ToolbarAuthTransitionState,
  event: SessionTransitionEvent,
): ToolbarAuthTransitionResult {
  if (event.phase === 'start') {
    if (event.transitionId <= current.transitionId) return unchangedTransition(current);
    const authState = event.reason === 'lock'
      || event.reason === 'unlock'
      || event.reason === 'pinUnlock'
      || event.reason === 'keyRotation'
      ? 'locked'
      : 'loggedOut';
    return Object.freeze({
      transitionId: event.transitionId,
      authState,
      accepted: true,
      clearMatches: true,
      clearApprovals: event.identityChanged,
      refreshMatches: false,
    });
  }
  if (event.transitionId !== current.transitionId) return unchangedTransition(current);
  return Object.freeze({
    transitionId: event.transitionId,
    authState: event.state,
    accepted: true,
    clearMatches: event.state !== 'unlocked',
    clearApprovals: event.state === 'loggedOut' || event.state === 'restricted',
    refreshMatches: true,
  });
}

/** Pure toolbar arbitration. Approval delivery outranks site matches, while auth owns the icon. */
export function composeToolbarState(input: ToolbarStateInput): ToolbarState {
  const authState = toolbarAuthState(input.authState);
  const approvalCount = boundedCount(input.pendingApprovalCount);
  const matchCount = boundedCount(input.matchingLoginCount);
  const hasAccount = authState !== 'loggedOut';
  const approvalsVisible = (authState === 'locked' || authState === 'unlocked')
    && hasAccount
    && approvalCount > 0;
  const matchesVisible = authState === 'unlocked'
    && input.showMatchingLoginCount === true
    && matchCount > 0;

  const iconKind: ToolbarIconKind = authState === 'unlocked'
    ? 'unlocked'
    : authState === 'loggedOut' ? 'neutral' : 'locked';
  const badgeText = approvalsVisible
    ? countText(approvalCount, 99)
    : matchesVisible ? countText(matchCount, 9) : '';
  const badgeBackgroundColor = approvalsVisible
    ? TOOLBAR_BADGE_COLORS.approvals
    : matchesVisible ? TOOLBAR_BADGE_COLORS.matches : TOOLBAR_BADGE_COLORS.empty;
  const baseTitle = authState === 'unlocked'
    ? input.copy.unlocked
    : authState === 'loggedOut' ? input.copy.signedOut : input.copy.locked;
  const title = approvalsVisible
    ? `${baseTitle} - ${input.copy.pendingApprovals(approvalCount)}`
    : matchesVisible
      ? `${baseTitle} - ${input.copy.matchingLogins(matchCount)}`
      : baseTitle;

  return Object.freeze({
    iconKind,
    icon: TOOLBAR_ICON_PATHS[iconKind],
    badgeText,
    badgeBackgroundColor,
    title,
  });
}

export interface ToolbarActionApi {
  setIcon(details: { readonly path: ToolbarIconPaths; readonly tabId?: number }): void | PromiseLike<void>;
  setBadgeText(details: { readonly text: string; readonly tabId?: number }): void | PromiseLike<void>;
  setBadgeBackgroundColor(details: {
    readonly color: string;
    readonly tabId?: number;
  }): void | PromiseLike<void>;
  setTitle(details: { readonly title: string; readonly tabId?: number }): void | PromiseLike<void>;
}

export interface ToolbarStateControllerDeps {
  readonly action: ToolbarActionApi;
  readonly logger?: { warn(event: 'toolbar_state_write_failed'): void };
}

/** The sole Action API writer. Commits are serialized so a delayed A -> B -> A sequence ends at A. */
export class ToolbarStateController {
  readonly #latestRevision = new Map<string, number>();
  readonly #committedSignature = new Map<string, string>();
  #revision = 0;
  #tail: Promise<void> = Promise.resolve();

  constructor(private readonly deps: ToolbarStateControllerDeps) {}

  apply(input: ToolbarStateInput, tabId?: number): Promise<void> {
    const target = toolbarTarget(tabId);
    const state = composeToolbarState(input);
    const signature = JSON.stringify(state);
    const revision = ++this.#revision;
    this.#latestRevision.set(target, revision);
    const operation = this.#tail.then(async () => {
      if (this.#latestRevision.get(target) !== revision
          || this.#committedSignature.get(target) === signature) return;
      const targetDetails = tabId === undefined ? {} : { tabId };
      const results = await Promise.allSettled([
        Promise.resolve().then(() => this.deps.action.setIcon({ path: state.icon, ...targetDetails })),
        Promise.resolve().then(() => this.deps.action.setBadgeText({ text: state.badgeText, ...targetDetails })),
        Promise.resolve().then(() => this.deps.action.setBadgeBackgroundColor({
          color: state.badgeBackgroundColor,
          ...targetDetails,
        })),
        Promise.resolve().then(() => this.deps.action.setTitle({ title: state.title, ...targetDetails })),
      ]);
      if (results.some((result) => result.status === 'rejected')) {
        this.#report('toolbar_state_write_failed');
        return;
      }
      if (this.#latestRevision.get(target) === revision) {
        this.#committedSignature.set(target, signature);
      }
    });
    this.#tail = operation.catch(() => undefined);
    return operation;
  }

  /** Invalidate queued writes for a browser tab that no longer exists. */
  forgetTab(tabId: number): void {
    const target = toolbarTarget(tabId);
    this.#latestRevision.set(target, ++this.#revision);
    this.#committedSignature.delete(target);
  }

  /** Force the next global render to reapply every Action API field. */
  invalidateGlobal(): void {
    const target = toolbarTarget(undefined);
    this.#latestRevision.set(target, ++this.#revision);
    this.#committedSignature.delete(target);
  }

  #report(event: 'toolbar_state_write_failed'): void {
    try { this.deps.logger?.warn(event); } catch { /* Diagnostics are best-effort. */ }
  }
}

function toolbarAuthState(value: SessionState): SessionState {
  return value === 'loggedOut' || value === 'locked' || value === 'restricted' || value === 'unlocked'
    ? value
    : 'loggedOut';
}

function boundedCount(value: unknown): number {
  return Number.isSafeInteger(value) && (value as number) > 0
    ? value as number
    : 0;
}

function countText(value: number, cap: number): string {
  return value > cap ? `${cap}+` : String(value);
}

function toolbarTarget(tabId: number | undefined): string {
  if (tabId === undefined) return 'global';
  if (!Number.isSafeInteger(tabId) || tabId < 0) throw new TypeError('Toolbar tab id is invalid');
  return `tab:${tabId}`;
}

function unchangedTransition(current: ToolbarAuthTransitionState): ToolbarAuthTransitionResult {
  return Object.freeze({
    ...current,
    accepted: false,
    clearMatches: false,
    clearApprovals: false,
    refreshMatches: false,
  });
}
