import type {
  FillKind,
  FillItemCandidate,
  CardFillData,
  IdentityFillData,
  FillCommand,
  FillErrorCommand,
  ReserveFillTargetCommand,
  CancelFillTargetCommand,
  ClaimContextLoginTargetCommand,
  HoldFillTargetCommand,
  CancelHeldFillTargetCommand,
  ContextLoginTargetClaimResult,
  ContextFillResult,
  FillRole,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionTarget,
  TabSuggestionsOutcome,
} from '../messaging/protocol.js';
import { normalizeFillRoles } from '../core/vault/fill-roles.js';
import { isLoginCustomPlanDigest } from '../core/vault/login-custom-fields.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { AutofillContinuationBrowserSource } from './autofill-continuation-coordinator.js';

type SessionState = 'loggedOut' | 'locked' | 'restricted' | 'unlocked';

const ROOT_ID = 'vw-root';
const LOGIN_GROUP_ID = 'vw-login-form';
const EMPTY_ID = 'vw-empty';
const UNLOCK_ID = 'vw-unlock';
const GENERATE_PASSWORD_ID = 'vw-action|generate-password';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export const CONTEXT_COPY_FIELDS = Object.freeze(['username', 'password', 'totp'] as const);
export type ContextCopyField = (typeof CONTEXT_COPY_FIELDS)[number];
export type ContextCreateKind = 'login' | 'card' | 'identity';
export type ContextMenuPlatformAction =
  | { readonly kind: 'copy'; readonly field: ContextCopyField; readonly cipherId: string }
  | { readonly kind: 'generate-password' }
  | { readonly kind: 'create'; readonly cipherKind: ContextCreateKind };

export type ContextMenuActionCapability =
  | 'copyUsername'
  | 'copyPassword'
  | 'copyTotp'
  | 'generatePassword'
  | 'createLogin'
  | 'createCard'
  | 'createIdentity';

export type ContextMenuActionCapabilities = Readonly<
  Partial<Record<ContextMenuActionCapability, boolean>>
>;

const COPY_GROUPS: ReadonlyArray<{
  readonly id: string;
  readonly title: string;
  readonly field: ContextCopyField;
}> = Object.freeze([
  { id: 'vw-copy-username', title: 'Copy username', field: 'username' },
  { id: 'vw-copy-password', title: 'Copy password', field: 'password' },
  { id: 'vw-copy-totp', title: 'Copy verification code', field: 'totp' },
]);

// Four submenu groups: fill the whole detected form, or only the right-clicked field, for each kind.
const GROUPS: Array<{ id: string; title: string; scope: 'form' | 'field'; kind: FillKind }> = [
  { id: 'vw-card-form', title: 'Fill card', scope: 'form', kind: 'card' },
  { id: 'vw-identity-form', title: 'Fill identity', scope: 'form', kind: 'identity' },
  { id: 'vw-card-field', title: 'Fill this field from card', scope: 'field', kind: 'card' },
  { id: 'vw-identity-field', title: 'Fill this field from identity', scope: 'field', kind: 'identity' },
];

// Request types that change the card/identity list or lock state — refresh the menu after these.
const REFRESH_TRIGGERS = new Set<string>([
  'vault.sync', 'vault.createCipher', 'vault.updateCipher', 'vault.deleteCipher',
  'vault.softDeleteCipher', 'vault.restoreCipher',
  'auth.login', 'auth.register', 'auth.submitTwoFactor', 'auth.completeFido2',
  'auth.unlock', 'auth.unlockWithPin', 'auth.lock', 'auth.logout',
  'auth.switchAccount', 'auth.removeAccount', 'auth.rotateAccountKey',
  'settings.save',
]);

export function shouldRefreshMenu(requestType: string): boolean {
  return REFRESH_TRIGGERS.has(requestType);
}

/** Browser-authoritative identity of the document that received the context-menu click. */
export interface ContextMenuFrame {
  frameId: number;
  url: string;
  documentId?: string;
}

/**
 * Binds a fill to the clicked browser document, unlocked session, and active account.
 * Both lease types stay opaque so this module remains decoupled from session storage.
 */
export interface DocumentLease<SessionLease = unknown, AccountLease = unknown> {
  tabId: number;
  frameId: number;
  frameUrl: string;
  documentId: string;
  sessionLease: SessionLease;
  accountLease: AccountLease;
}

type MessageOptions = { frameId: number; documentId: string };
type ContextMenuMessage =
  | FillCommand
  | FillErrorCommand
  | ReserveFillTargetCommand
  | CancelFillTargetCommand
  | HoldFillTargetCommand
  | CancelHeldFillTargetCommand
  | ClaimContextLoginTargetCommand;

export interface ContextMenuPlatformActions {
  getCapabilities(): Promise<ContextMenuActionCapabilities>;
  /**
   * Returns only the selected copy value. The adapter must enforce item access and reprompt, and
   * must publish a synchronous final-authority assertion before returning any secret.
   */
  readLoginCopyValue(
    cipherId: string,
    field: ContextCopyField,
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ): Promise<string | undefined>;
  /** Generates with the shared policy engine and commits generator history before returning. */
  generatePasswordAndTrack(
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ): Promise<{ readonly value: string } | undefined>;
  clipboard: {
    /** Worker-only non-TOTP writer with bounded input and owned-clear scheduling. */
    writeSecretAndScheduleClear(value: string, assertCurrent: () => void): Promise<boolean>;
    /** Dedicated TOTP writer that preserves the existing constrained-code validation channel. */
    writeTotpAndScheduleClear(value: string, assertCurrent: () => void): Promise<boolean>;
  };
  createCipher(
    kind: ContextCreateKind,
    source: AutofillContinuationBrowserSource,
    assertCurrent: () => void,
  ): Promise<void>;
}

export interface ContextMenuDeps<SessionLease = unknown, AccountLease = unknown> {
  getState(): Promise<SessionState>;
  getActiveTabId(): Promise<number | undefined>;
  getTabSuggestions(tabId: number): Promise<TabSuggestionsOutcome>;
  fillTabSuggestion(
    tabId: number,
    cipherId: string,
    target: TabSuggestionTarget,
    assertCurrent: () => void,
  ): Promise<TabFillOutcome>;
  findFillItems(kind: FillKind): Promise<FillItemCandidate[]>;
  getFillData(
    cipherId: string,
    kind: FillKind,
    roles: readonly FillRole[],
    bindFinalAuthority?: (assertCurrent: () => void) => void,
  ): Promise<CardFillData | IdentityFillData>;
  /** Authorize the browser-owned frame URL and return a synchronous revocation check. */
  authorizeFrame(frameUrl: string, action: 'candidate' | 'intent'): Promise<{
    assertCurrent(): void;
    defaultStrategy: UriMatchStrategySetting;
  }>;
  getFrame(tabId: number, frameId: number): Promise<ContextMenuFrame | undefined>;
  /** Resolve only the currently active runtime bound to this exact browser document. */
  getRuntimeIncarnation(
    tabId: number,
    frameId: number,
    documentId: string,
  ): Promise<string | undefined>;
  actions?: ContextMenuPlatformActions;
  continuation?: {
    stageLockedContext(source: AutofillContinuationBrowserSource): Promise<void>;
    stageContextLoginReprompt(
      source: AutofillContinuationBrowserSource,
      cipherId: string,
      target: TabSuggestionTarget,
    ): Promise<void>;
    stageContextStructuredReprompt(
      source: AutofillContinuationBrowserSource,
      input: {
        cipherId: string;
        holdId: string;
        scope: 'form' | 'field';
        fillKind: FillKind;
        roles: readonly FillRole[];
        runtimeIncarnation: string;
      },
    ): Promise<void>;
    stageContextCopyReprompt?(
      source: AutofillContinuationBrowserSource,
      cipherId: string,
      field: 'password' | 'totp',
    ): Promise<void>;
  };
  captureSessionLease(): Promise<SessionLease>;
  isSessionLeaseCurrent(lease: SessionLease): Promise<boolean>;
  assertSessionLease(lease: SessionLease): void;
  captureAccountLease(): Promise<AccountLease>;
  isAccountLeaseCurrent(lease: AccountLease): Promise<boolean>;
  assertAccountLease(lease: AccountLease): void;
  vaultTimeout?: {
    captureActivity(): unknown;
    recordActivity(lease: unknown): Promise<void>;
  };
  vaultReleaseGate?: {
    capture(sessionLease: SessionLease): object;
    checkpoint(lease: object): Promise<object>;
    assertAuthorities(proof: object, assertCurrent: () => void): void;
    assert(proof: object): void;
    settlePendingAction?(): Promise<void>;
  };
  menus: {
    removeAll(): Promise<void>;
    create(props: Record<string, unknown>): void;
  };
  tabs: {
    sendMessage(
      tabId: number,
      message: ContextMenuMessage,
      options: MessageOptions,
    ): Promise<unknown>;
  };
}

function itemId(scope: 'form' | 'field', kind: FillKind, cipherId: string): string {
  return `vw-fill|${scope}|${kind}|${cipherId}`;
}

function loginItemId(cipherId: string): string {
  return `vw-login|${cipherId}`;
}

function copyItemId(field: ContextCopyField, cipherId: string): string {
  return `vw-action|copy|${field}|${cipherId}`;
}

function createItemId(kind: ContextCreateKind): string {
  return `vw-action|create|${kind}`;
}

/** Chromium treats a single ampersand as a mnemonic marker in context-menu labels. */
function contextMenuTitle(value: string): string {
  return value.replace(/&/g, '&&');
}

function parseItemId(id: string): { scope: 'form' | 'field'; kind: FillKind; cipherId: string } | undefined {
  const parts = id.split('|');
  if (parts.length !== 4 || parts[0] !== 'vw-fill') return undefined;
  const scope = parts[1];
  const kind = parts[2];
  if ((scope !== 'form' && scope !== 'field') || (kind !== 'card' && kind !== 'identity')) return undefined;
  return { scope, kind, cipherId: parts[3]! };
}

function parseLoginItemId(id: string): string | undefined {
  const prefix = 'vw-login|';
  if (!id.startsWith(prefix)) return undefined;
  const cipherId = id.slice(prefix.length);
  return cipherId && !cipherId.includes('|') ? cipherId : undefined;
}

export function parseContextMenuPlatformAction(id: string): ContextMenuPlatformAction | undefined {
  if (id === GENERATE_PASSWORD_ID) return Object.freeze({ kind: 'generate-password' });
  const parts = id.split('|');
  if (parts[0] !== 'vw-action') return undefined;
  if (parts.length === 3 && parts[1] === 'create'
      && (parts[2] === 'login' || parts[2] === 'card' || parts[2] === 'identity')) {
    return Object.freeze({ kind: 'create', cipherKind: parts[2] });
  }
  if (parts.length === 4 && parts[1] === 'copy'
      && CONTEXT_COPY_FIELDS.some((field) => field === parts[2])
      && boundedMenuIdentifier(parts[3])) {
    return Object.freeze({
      kind: 'copy',
      field: parts[2] as ContextCopyField,
      cipherId: parts[3]!,
    });
  }
  return undefined;
}

export function createContextMenu<SessionLease = unknown, AccountLease = unknown>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
) {
  /** Rebuild the menu from the current vault. Hides all vault items unless the vault is unlocked. */
  async function rebuild(preferredTabId?: number): Promise<void> {
    try {
    await deps.menus.removeAll();
    const state = await deps.getState();
    if (state === 'locked') {
      deps.menus.create({ id: UNLOCK_ID, title: 'Unlock MiYu', contexts: ['editable'] });
      return;
    }
    if (state !== 'unlocked') return;
    let leases: Pick<DocumentLease<SessionLease, AccountLease>, 'sessionLease' | 'accountLease'>;
    try {
      const [sessionLease, accountLease] = await Promise.all([
        deps.captureSessionLease(),
        deps.captureAccountLease(),
      ]);
      leases = { sessionLease, accountLease };
    } catch {
      return;
    }
    if (!(await areSecurityLeasesCurrent(deps, leases))) return;
    if (!(await areSecurityLeasesCurrent(deps, leases))) return;
    const tabId = preferredTabId ?? await deps.getActiveTabId().catch(() => undefined);
    if (!(await areSecurityLeasesCurrent(deps, leases))) return;
    const [cards, identities, tabSuggestions, actionCapabilities] = await Promise.all([
      deps.findFillItems('card'),
      deps.findFillItems('identity'),
      tabId === undefined
        ? Promise.resolve<TabSuggestionsOutcome | undefined>(undefined)
        : deps.getTabSuggestions(tabId).catch(() => undefined),
      readActionCapabilities(deps),
    ]);
    if (!(await areSecurityLeasesCurrent(deps, leases))) return;
    const logins = tabSuggestions?.status === 'ready'
      ? tabSuggestions.suggestions.filter((suggestion): suggestion is Extract<TabAutofillSuggestion, { kind: 'login' }> => (
          suggestion.kind === 'login'
        ))
      : [];
    // Menu creation is synchronous. This final check is the last await before every item name is
    // published, so no stale account metadata can reappear after a lock or account switch.
    if (!(await areSecurityLeasesCurrent(deps, leases))) return;
    assertSecurityLeasesCurrent(deps, leases);
    const menuReleaseLease = deps.vaultReleaseGate?.capture(leases.sessionLease);
    const menuReleaseProof = menuReleaseLease
      ? await deps.vaultReleaseGate!.checkpoint(menuReleaseLease)
      : undefined;
    if (menuReleaseProof) {
      deps.vaultReleaseGate!.assertAuthorities(
        menuReleaseProof,
        () => assertSecurityLeasesCurrent(deps, leases),
      );
      deps.vaultReleaseGate!.assert(menuReleaseProof);
    }
    const hasGlobalActions = hasAnyActionCapability(actionCapabilities);
    deps.menus.create({ id: ROOT_ID, title: '密屿', contexts: hasGlobalActions ? ['all'] : ['editable'] });
    if (logins.length > 0) {
      deps.menus.create({ id: LOGIN_GROUP_ID, parentId: ROOT_ID, title: 'Fill login', contexts: ['editable'] });
      for (const item of logins) {
        deps.menus.create({
          id: loginItemId(item.id),
          parentId: LOGIN_GROUP_ID,
          title: contextMenuTitle(item.reprompt ? `${item.name} 🔒` : item.name),
          contexts: ['editable'],
        });
      }
    }
    for (const group of GROUPS) {
      const items = group.kind === 'card' ? cards : identities;
      if (items.length === 0) continue;
      deps.menus.create({ id: group.id, parentId: ROOT_ID, title: group.title, contexts: ['editable'] });
      for (const item of items) {
        deps.menus.create({
          id: itemId(group.scope, group.kind, item.id),
          parentId: group.id,
          title: contextMenuTitle(item.reprompt ? `${item.name} 🔒` : item.name),
          contexts: ['editable'],
        });
      }
    }
    createCopyMenus(deps, logins, actionCapabilities);
    if (actionAllowed(actionCapabilities, 'generatePassword')) {
      deps.menus.create({
        id: GENERATE_PASSWORD_ID,
        parentId: ROOT_ID,
        title: 'Generate password and copy',
        contexts: ['all'],
      });
    }
    for (const kind of ['login', 'card', 'identity'] as const) {
      const capability = createCapability(kind);
      if (!actionAllowed(actionCapabilities, capability)) continue;
      deps.menus.create({
        id: createItemId(kind),
        parentId: ROOT_ID,
        title: `Create ${kind}`,
        contexts: ['all'],
      });
    }
    if (logins.length === 0 && cards.length === 0 && identities.length === 0 && !hasGlobalActions) {
      deps.menus.create({
        id: EMPTY_ID,
        parentId: ROOT_ID,
        title: 'No matching items',
        contexts: ['editable'],
        enabled: false,
      });
    }
    } finally {
      await deps.vaultReleaseGate?.settlePendingAction?.();
    }
  }

  // Single-flight, newest-wins serialization: removeAll()+create() must never interleave across two
  // concurrent refreshes (that races duplicate-id create() calls). A refresh requested while one is
  // in flight is coalesced into a single trailing rebuild so the final menu reflects the latest state.
  let inFlight: Promise<void> | null = null;
  let queued = false;
  let requestedTabId: number | undefined;

  return {
    /** Remove every derived menu title without consulting session state or rebuilding any entries. */
    async clearDerivedState(): Promise<void> {
      await deps.menus.removeAll();
    },

    async refresh(tabId?: number): Promise<void> {
      requestedTabId = tabId;
      if (inFlight) {
        queued = true;
        return inFlight;
      }
      inFlight = (async () => {
        try {
          do {
            queued = false;
            const nextTabId = requestedTabId;
            await rebuild(nextTabId);
          } while (queued);
        } finally {
          inFlight = null;
        }
      })();
      return inFlight;
    },

    /** A menu item was clicked: fetch fill data in the worker and forward a command to the clicked frame. */
    async handleClick(
      menuItemId: string,
      tab: { id?: number; windowId?: number } | undefined,
      frameId: number | undefined,
      clickedFrameUrl: string,
      contextMenuClickTime: number,
    ): Promise<void> {
      try {
      if (typeof tab?.id !== 'number' || typeof frameId !== 'number' || !Number.isFinite(contextMenuClickTime)) return;
      if (menuItemId === UNLOCK_ID) {
        if (typeof tab.windowId !== 'number' || !deps.continuation || await deps.getState() !== 'locked') return;
        const source = await captureBrowserSource(deps, tab.id, tab.windowId, frameId, clickedFrameUrl);
        if (source) await deps.continuation.stageLockedContext(source);
        return;
      }
      const parsed = parseItemId(menuItemId);
      const loginCipherId = parseLoginItemId(menuItemId);
      const platformAction = parseContextMenuPlatformAction(menuItemId);
      if (!parsed && !loginCipherId && !platformAction) return;
      const targetFrameId = frameId;
      let lease: DocumentLease<SessionLease, AccountLease> | undefined;
      let releaseLease: object | undefined;
      let reservationId: string | undefined;
      let reservationRuntimeIncarnation: string | undefined;
      let heldTargetId: string | undefined;
      let heldTargetRuntimeIncarnation: string | undefined;
      let reservedRoles: readonly FillRole[] | undefined;
      try {
        const activityLease = deps.vaultTimeout?.captureActivity();
        const captured = await captureDocumentLease(deps, tab.id, targetFrameId, clickedFrameUrl);
        if (captured === null) return;
        lease = captured;
        if (parsed) releaseLease = deps.vaultReleaseGate?.capture(lease.sessionLease);

        if (platformAction) {
          await executePlatformAction(
            deps,
            platformAction,
            lease,
            tab,
            activityLease,
          );
          return;
        }

        if (loginCipherId) {
          const claim: ClaimContextLoginTargetCommand = {
            type: 'autofill.claimContextLoginTarget',
            expectedFrameUrl: lease.frameUrl,
            contextMenuClickTime,
          };
          const claimResult = await deps.tabs.sendMessage(
            tab.id,
            claim,
            messageOptions(targetFrameId, lease),
          );
          if (!isClaimedLoginTarget(claimResult)) return;
          if (!(await isDocumentLeaseCurrent(deps, lease))) return;

          const authorization = await deps.authorizeFrame(lease.frameUrl, 'intent');
          if (!(await isDocumentLeaseCurrent(deps, lease))) return;
          authorization.assertCurrent();
          const suggestions = await deps.getTabSuggestions(tab.id);
          if (!(await isDocumentLeaseCurrent(deps, lease))) return;
          authorization.assertCurrent();
          if (suggestions.status !== 'ready') return;
          const selected = suggestions.suggestions.find((suggestion) => (
            suggestion.kind === 'login'
            && suggestion.id === loginCipherId
            && suggestion.target?.frameId === lease!.frameId
            && suggestion.target.documentId === lease!.documentId
            && suggestion.target.runtimeIncarnation === claimResult.runtimeIncarnation
            && suggestion.target.formId === claimResult.formId
            && suggestion.target.generation === claimResult.generation
            && suggestion.target.customPlanDigest === claimResult.customPlanDigest
          ));
          if (!selected?.target) return;
          const outcome = await deps.fillTabSuggestion(
            tab.id,
            loginCipherId,
            selected.target,
            () => assertDocumentSecurityCurrent(deps, lease!, authorization),
          );
          if (outcome.status === 'filled') await deps.vaultTimeout?.recordActivity(activityLease);
          if (outcome.status === 'reprompt_required' && deps.continuation
              && typeof tab.windowId === 'number') {
            const source = await captureBrowserSource(
              deps, tab.id, tab.windowId, targetFrameId, clickedFrameUrl,
            );
            if (source) await deps.continuation.stageContextLoginReprompt(
              source, loginCipherId, selected.target,
            );
          }
          return;
        }
        if (!parsed) return;

        reservationId = crypto.randomUUID();
        const reserveCommand: ReserveFillTargetCommand = {
          type: 'autofill.reserveFillTarget',
          reservationId,
          scope: parsed.scope,
          kind: parsed.kind,
          expectedFrameUrl: lease.frameUrl,
          contextMenuClickTime,
        };
        const reserveResult = await deps.tabs.sendMessage(
          tab.id,
          reserveCommand,
          messageOptions(targetFrameId, lease),
        );
        reservationRuntimeIncarnation = reservedTargetRuntimeIncarnation(reserveResult);
        if (!reservationRuntimeIncarnation) return;
        const roles = reservedTargetRoles(reserveResult, parsed.kind, parsed.scope);
        if (!roles) return;
        reservedRoles = roles;
        if (!(await isDocumentLeaseCurrent(deps, lease))) return;

        const authorization = await deps.authorizeFrame(lease.frameUrl, 'intent');
        if (!(await isDocumentLeaseCurrent(deps, lease))) return;
        authorization.assertCurrent();
        let assertItemAuthority: (() => void) | undefined;
        const data = await deps.getFillData(
          parsed.cipherId,
          parsed.kind,
          roles,
          (assertCurrent) => { assertItemAuthority = assertCurrent; },
        );
        if (!assertItemAuthority) throw new Error('Autofill item authority is unavailable');
        if (!(await isDocumentLeaseCurrent(deps, lease))) return;
        authorization.assertCurrent();

        const command: FillCommand = {
          type: 'autofill.fill',
          reservationId,
          scope: parsed.scope,
          kind: parsed.kind,
          roles,
          data,
          expectedFrameUrl: lease.frameUrl,
          expectedRuntimeIncarnation: reservationRuntimeIncarnation,
        };
        assertDocumentSecurityCurrent(deps, lease, authorization);
        const releaseProof = releaseLease && deps.vaultReleaseGate
          ? await deps.vaultReleaseGate.checkpoint(releaseLease)
          : undefined;
        if (releaseProof && deps.vaultReleaseGate) {
          deps.vaultReleaseGate.assertAuthorities(
            releaseProof,
            () => {
              assertDocumentSecurityCurrent(deps, lease!, authorization);
              assertItemAuthority!();
            },
          );
          deps.vaultReleaseGate.assert(releaseProof);
        }
        const fillResult = await deps.tabs.sendMessage(tab.id, command, messageOptions(targetFrameId, lease));
        reservationId = undefined;
        if (isContextFillResult(fillResult) && fillResult.status === 'filled') {
          await deps.vaultTimeout?.recordActivity(activityLease);
        }
      } catch (err) {
        const code = errorCode(err);
        // Reprompt-protected items refuse inline release; tell the page to surface that, never the data.
        if (code === 'reprompt_required') {
          if (platformAction?.kind === 'copy'
              && (platformAction.field === 'password' || platformAction.field === 'totp')) {
            if (!lease || typeof tab.windowId !== 'number'
                || !deps.continuation?.stageContextCopyReprompt) return;
            const source = await captureBrowserSource(
              deps, tab.id, tab.windowId, targetFrameId, clickedFrameUrl,
            );
            if (source) await deps.continuation.stageContextCopyReprompt(
              source,
              platformAction.cipherId,
              platformAction.field,
            );
            return;
          }
          if (!lease || !reservationId || !reservationRuntimeIncarnation || !reservedRoles
              || !parsed || !deps.continuation
              || typeof tab.windowId !== 'number') return;
          try {
            if (!(await isDocumentLeaseCurrent(deps, lease))) return;
            heldTargetId = crypto.randomUUID();
            const runtimeIncarnation = reservationRuntimeIncarnation;
            heldTargetRuntimeIncarnation = runtimeIncarnation;
            const command: HoldFillTargetCommand = {
              type: 'autofill.holdFillTarget',
              reservationId,
              holdId: heldTargetId,
              expectedFrameUrl: lease.frameUrl,
              expectedRuntimeIncarnation: runtimeIncarnation,
            };
            const held = await deps.tabs.sendMessage(tab.id, command, messageOptions(targetFrameId, lease));
            reservationId = undefined;
            reservationRuntimeIncarnation = undefined;
            if (!isHeldTarget(held)) {
              heldTargetId = undefined;
              heldTargetRuntimeIncarnation = undefined;
              return;
            }
            const source = await captureBrowserSource(
              deps, tab.id, tab.windowId, targetFrameId, clickedFrameUrl,
            );
            if (!source) return;
            await deps.continuation.stageContextStructuredReprompt(source, {
              cipherId: parsed.cipherId,
              holdId: heldTargetId,
              scope: parsed.scope,
              fillKind: parsed.kind,
              roles: reservedRoles,
              runtimeIncarnation,
            });
            heldTargetId = undefined;
            heldTargetRuntimeIncarnation = undefined;
          } catch (deliveryError) {
            if (!isStaleDocumentDeliveryError(deliveryError)) {
              console.error('context menu fill error delivery failed', deliveryError);
            }
          }
          return;
        }
        // Navigation can win the final race after the last lease check but before delivery. The
        // browser rejects the stale document/frame target; that is an expected safe refusal.
        if (isStaleDocumentDeliveryError(err)) return;
        // denied / locked / sync_required are expected refusals — safe to ignore silently.
        if (code === 'denied' || code === 'locked' || code === 'sync_required') return;
        // Anything else is unexpected; surface it for diagnosis rather than a silent no-op.
        console.error('context menu fill failed', err);
      } finally {
        if (lease && reservationId && reservationRuntimeIncarnation) {
          await cancelReservation(deps, lease, reservationId, reservationRuntimeIncarnation);
        }
        if (lease && heldTargetId && heldTargetRuntimeIncarnation) {
          await cancelHeldTarget(deps, lease, heldTargetId, heldTargetRuntimeIncarnation);
        }
      }
      } finally {
        await deps.vaultReleaseGate?.settlePendingAction?.();
      }
    },
  };
}

async function executePlatformAction<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  action: ContextMenuPlatformAction,
  lease: DocumentLease<SessionLease, AccountLease>,
  tab: { id?: number; windowId?: number },
  activityLease: unknown,
): Promise<void> {
  const actions = deps.actions;
  if (!actions) return;
  const capabilities = await readActionCapabilities(deps);
  if (!actionAllowed(capabilities, capabilityForAction(action))) return;
  if (!await isDocumentLeaseCurrent(deps, lease)) return;
  const authorization = await deps.authorizeFrame(lease.frameUrl, 'intent');
  if (!await isDocumentLeaseCurrent(deps, lease)) return;
  const assertCurrent = () => assertDocumentSecurityCurrent(deps, lease, authorization);

  if (action.kind === 'copy') {
    const currentSuggestions = await deps.getTabSuggestions(lease.tabId);
    if (!await isDocumentLeaseCurrent(deps, lease)
        || !copyCandidateCurrent(currentSuggestions, action)) return;
    assertCurrent();
  }

  if (action.kind === 'create') {
    if (typeof tab.id !== 'number' || typeof tab.windowId !== 'number') return;
    const source = await captureBrowserSource(
      deps,
      tab.id,
      tab.windowId,
      lease.frameId,
      lease.frameUrl,
    );
    if (!source || !await isDocumentLeaseCurrent(deps, lease)) return;
    assertCurrent();
    await actions.createCipher(action.cipherKind, source, assertCurrent);
    return;
  }

  const releaseLease = deps.vaultReleaseGate?.capture(lease.sessionLease);
  let itemAuthority: (() => void) | undefined;
  const bindFinalAuthority = (assertItemCurrent: () => void): void => {
    itemAuthority = assertItemCurrent;
  };
  assertCurrent();
  const value = action.kind === 'copy'
    ? await actions.readLoginCopyValue(action.cipherId, action.field, bindFinalAuthority)
    : (await actions.generatePasswordAndTrack(bindFinalAuthority))?.value;
  if (value === undefined) return;
  if (!itemAuthority) throw new Error('Context menu action authority is unavailable');
  if (!await isDocumentLeaseCurrent(deps, lease)) return;
  const assertFinal = () => {
    assertCurrent();
    itemAuthority!();
  };
  const releaseProof = releaseLease && deps.vaultReleaseGate
    ? await deps.vaultReleaseGate.checkpoint(releaseLease)
    : undefined;
  if (releaseProof && deps.vaultReleaseGate) {
    deps.vaultReleaseGate.assertAuthorities(releaseProof, assertFinal);
    deps.vaultReleaseGate.assert(releaseProof);
  }
  if (!isBoundedClipboardValue(value)) return;
  assertFinal();
  const copied = action.kind === 'copy' && action.field === 'totp'
    ? await actions.clipboard.writeTotpAndScheduleClear(value, assertFinal)
    : await actions.clipboard.writeSecretAndScheduleClear(value, assertFinal);
  if (copied) await deps.vaultTimeout?.recordActivity(activityLease);
}

function createCopyMenus<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  logins: ReadonlyArray<Extract<TabAutofillSuggestion, { kind: 'login' }>>,
  capabilities: ContextMenuActionCapabilities,
): void {
  for (const group of COPY_GROUPS) {
    if (!actionAllowed(capabilities, copyCapability(group.field))) continue;
    const items = logins.filter((item) => (
      group.field === 'password'
      || (group.field === 'username' && Boolean(item.username))
      || (group.field === 'totp' && item.hasTotp === true)
    ));
    if (items.length === 0) continue;
    deps.menus.create({
      id: group.id,
      parentId: ROOT_ID,
      title: group.title,
      contexts: ['all'],
    });
    for (const item of items) {
      deps.menus.create({
        id: copyItemId(group.field, item.id),
        parentId: group.id,
        title: contextMenuTitle(item.reprompt ? `${item.name} (locked)` : item.name),
        contexts: ['all'],
      });
    }
  }
}

function copyCandidateCurrent(
  outcome: TabSuggestionsOutcome,
  action: Extract<ContextMenuPlatformAction, { kind: 'copy' }>,
): boolean {
  if (outcome.status !== 'ready') return false;
  return outcome.suggestions.some((candidate) => candidate.kind === 'login'
    && candidate.id === action.cipherId
    && (action.field === 'password'
      || (action.field === 'username' && Boolean(candidate.username))
      || (action.field === 'totp' && candidate.hasTotp === true)));
}

const ACTION_CAPABILITIES: readonly ContextMenuActionCapability[] = Object.freeze([
  'copyUsername',
  'copyPassword',
  'copyTotp',
  'generatePassword',
  'createLogin',
  'createCard',
  'createIdentity',
]);

async function readActionCapabilities<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
): Promise<ContextMenuActionCapabilities> {
  if (!deps.actions) return Object.freeze({});
  let raw: ContextMenuActionCapabilities;
  try {
    raw = await deps.actions.getCapabilities();
  } catch {
    return Object.freeze({});
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return Object.freeze({});
  const result: Partial<Record<ContextMenuActionCapability, boolean>> = {};
  for (const capability of ACTION_CAPABILITIES) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, capability);
    if (descriptor?.enumerable && 'value' in descriptor && descriptor.value === true) {
      result[capability] = true;
    }
  }
  return Object.freeze(result);
}

function hasAnyActionCapability(capabilities: ContextMenuActionCapabilities): boolean {
  return ACTION_CAPABILITIES.some((capability) => actionAllowed(capabilities, capability));
}

function actionAllowed(
  capabilities: ContextMenuActionCapabilities,
  capability: ContextMenuActionCapability,
): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(capabilities, capability);
  return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value === true);
}

function capabilityForAction(action: ContextMenuPlatformAction): ContextMenuActionCapability {
  if (action.kind === 'copy') return copyCapability(action.field);
  if (action.kind === 'create') return createCapability(action.cipherKind);
  return 'generatePassword';
}

function copyCapability(field: ContextCopyField): ContextMenuActionCapability {
  if (field === 'username') return 'copyUsername';
  if (field === 'password') return 'copyPassword';
  return 'copyTotp';
}

function createCapability(kind: ContextCreateKind): ContextMenuActionCapability {
  if (kind === 'login') return 'createLogin';
  if (kind === 'card') return 'createCard';
  return 'createIdentity';
}

function boundedMenuIdentifier(value: string | undefined): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 4_096
    && value.trim() === value
    && !value.includes('|')
    && ![...value].some((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code <= 31 || code === 127;
    });
}

function isBoundedClipboardValue(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 65_536;
}

function isClaimedLoginTarget(value: unknown): value is Extract<
  ContextLoginTargetClaimResult,
  { readonly status: 'claimed' }
> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === 5
    && keys.every((key) => key === 'status' || key === 'formId'
      || key === 'generation' || key === 'customPlanDigest' || key === 'runtimeIncarnation')
    && record.status === 'claimed'
    && isRuntimeIncarnation(record.runtimeIncarnation)
    && typeof record.formId === 'string'
    && record.formId.length > 0
    && record.formId.length <= 4_096
    && Number.isSafeInteger(record.generation)
    && (record.generation as number) > 0
    && isLoginCustomPlanDigest(record.customPlanDigest);
}

function isHeldTarget(value: unknown): value is { readonly status: 'held' } {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 1 && record.status === 'held';
}

async function captureBrowserSource<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  tabId: number,
  windowId: number,
  frameId: number,
  clickedFrameUrl: string,
): Promise<AutofillContinuationBrowserSource | undefined> {
  const topFrame = deps.getFrame(tabId, 0);
  const [top, frame] = await Promise.all([
    topFrame,
    frameId === 0 ? topFrame : deps.getFrame(tabId, frameId),
  ]);
  if (!top?.documentId || top.frameId !== 0 || !frame?.documentId
      || frame.frameId !== frameId || frame.url !== clickedFrameUrl) return undefined;
  const topRuntime = deps.getRuntimeIncarnation(tabId, 0, top.documentId);
  const sameRuntimeBinding = frameId === 0 && frame.documentId === top.documentId;
  const frameRuntime = sameRuntimeBinding
    ? topRuntime
    : deps.getRuntimeIncarnation(tabId, frameId, frame.documentId);
  const [topRuntimeIncarnation, frameRuntimeIncarnation] = await Promise.all([
    topRuntime,
    frameRuntime,
  ]);
  if (!isRuntimeIncarnation(topRuntimeIncarnation)
      || !isRuntimeIncarnation(frameRuntimeIncarnation)) return undefined;
  return Object.freeze({
    tabId,
    windowId,
    topDocumentId: top.documentId,
    topRuntimeIncarnation,
    topUrl: top.url,
    frameId,
    frameDocumentId: frame.documentId,
    frameRuntimeIncarnation,
    frameUrl: frame.url,
  });
}

function isContextFillResult(value: unknown): value is ContextFillResult {
  if (typeof value !== 'object' || value === null || Object.keys(value).length !== 1) return false;
  const status = (value as { status?: unknown }).status;
  return status === 'filled' || status === 'no_target' || status === 'page_changed' || status === 'target_changed';
}

function reservedTargetRuntimeIncarnation(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const result = value as Record<string, unknown>;
  return result.status === 'reserved' && isRuntimeIncarnation(result.runtimeIncarnation)
    ? result.runtimeIncarnation
    : undefined;
}

function reservedTargetRoles(
  value: unknown,
  kind: FillKind,
  scope: 'form' | 'field',
): FillRole[] | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const result = value as Record<string, unknown>;
  const keys = Object.keys(result);
  if (result.status !== 'reserved' || keys.length !== 3
      || !keys.every((key) => key === 'status' || key === 'runtimeIncarnation' || key === 'roles')) {
    return undefined;
  }
  const normalized = normalizeFillRoles(kind, result.roles);
  if (!normalized || (scope === 'field' && normalized.length !== 1)) return undefined;
  return [...normalized];
}

function isRuntimeIncarnation(value: unknown): value is string {
  return typeof value === 'string' && UUID_V4.test(value);
}

async function cancelReservation<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  lease: DocumentLease<SessionLease, AccountLease>,
  reservationId: string,
  runtimeIncarnation: string,
): Promise<void> {
  const command: CancelFillTargetCommand = {
    type: 'autofill.cancelFillTarget',
    reservationId,
    expectedFrameUrl: lease.frameUrl,
    expectedRuntimeIncarnation: runtimeIncarnation,
  };
  try {
    await deps.tabs.sendMessage(lease.tabId, command, messageOptions(lease.frameId, lease));
  } catch {
    // The content reservation has its own TTL; cancellation is best-effort if the document vanished.
  }
}

async function cancelHeldTarget<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  lease: DocumentLease<SessionLease, AccountLease>,
  holdId: string,
  runtimeIncarnation: string,
): Promise<void> {
  try {
    await deps.tabs.sendMessage(lease.tabId, {
      type: 'autofill.cancelHeldFillTarget',
      holdId,
      expectedFrameUrl: lease.frameUrl,
      expectedRuntimeIncarnation: runtimeIncarnation,
    }, messageOptions(lease.frameId, lease));
  } catch {
    // Holds expire in content; cancellation is best effort after a document disappears.
  }
}

/**
 * `null` means the document, session, or account was already stale before secret retrieval.
 */
async function captureDocumentLease<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  tabId: number,
  frameId: number,
  clickedFrameUrl: string,
): Promise<DocumentLease<SessionLease, AccountLease> | null> {
  const [sessionLease, accountLease] = await Promise.all([
    deps.captureSessionLease(),
    deps.captureAccountLease(),
  ]);
  const frame = await deps.getFrame(tabId, frameId);
  if (!frame || frame.frameId !== frameId || frame.url !== clickedFrameUrl || !frame.documentId) return null;
  const documentId = frame.documentId;
  const lease: DocumentLease<SessionLease, AccountLease> = {
    tabId,
    frameId,
    frameUrl: frame.url,
    documentId,
    sessionLease,
    accountLease,
  };
  return (await areSecurityLeasesCurrent(deps, lease)) ? lease : null;
}

async function isDocumentLeaseCurrent<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  lease: DocumentLease<SessionLease, AccountLease>,
): Promise<boolean> {
  const frame = await deps.getFrame(lease.tabId, lease.frameId);
  const sameDocument = frame !== undefined
    && frame.frameId === lease.frameId
    && frame.url === lease.frameUrl
    && frame.documentId !== undefined
    && frame.documentId === lease.documentId;
  if (!sameDocument) return false;
  return areSecurityLeasesCurrent(deps, lease);
}

async function areSecurityLeasesCurrent<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  lease: Pick<DocumentLease<SessionLease, AccountLease>, 'sessionLease' | 'accountLease'>,
): Promise<boolean> {
  if (!(await deps.isAccountLeaseCurrent(lease.accountLease))) return false;
  // Keep the session check as the final await so a lock that starts while the account check is
  // pending cannot authorize an operation captured by the old unlocked session.
  return deps.isSessionLeaseCurrent(lease.sessionLease);
}

function assertSecurityLeasesCurrent<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  lease: Pick<DocumentLease<SessionLease, AccountLease>, 'sessionLease' | 'accountLease'>,
): void {
  deps.assertAccountLease(lease.accountLease);
  deps.assertSessionLease(lease.sessionLease);
}

function assertDocumentSecurityCurrent<SessionLease, AccountLease>(
  deps: ContextMenuDeps<SessionLease, AccountLease>,
  lease: DocumentLease<SessionLease, AccountLease>,
  authorization: { assertCurrent(): void },
): void {
  deps.assertAccountLease(lease.accountLease);
  authorization.assertCurrent();
  // Session timeout preflight stays immediately adjacent to the secret-bearing browser call.
  deps.assertSessionLease(lease.sessionLease);
}

function messageOptions<SessionLease, AccountLease>(
  frameId: number,
  lease: DocumentLease<SessionLease, AccountLease>,
): MessageOptions {
  return { frameId, documentId: lease.documentId };
}

function errorCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null ? (err as { code?: string }).code : undefined;
}

const STALE_DOCUMENT_DELIVERY = /could not establish connection|receiving end|message port closed|no document with id|no frame with id|frame with id .* was removed/i;

function isStaleDocumentDeliveryError(err: unknown): boolean {
  return err instanceof Error && STALE_DOCUMENT_DELIVERY.test(err.message);
}
