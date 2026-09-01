import type {
  AutofillCandidate,
  AutofillInteractiveLoginData,
  AutofillLoginData,
  AutofillTotpData,
  CardFillData,
  CardFillRole,
  FillItemCandidate,
  FillKind,
  FillRole,
  FrameAutofillForm,
  FrameAutofillMessage,
  FrameInspection,
  IdentityFillData,
  IdentityFillRole,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionsOutcome,
  TabSuggestionTarget,
} from '../messaging/protocol.js';
import { AppError } from '../core/errors.js';
import type { AppErrorCode } from '../core/errors.js';
import type { AccountLeaseGate } from '../core/session/account-gate.js';
import type { SessionLeaseGate } from '../core/session/session-manager.js';
import { fillDataKeysForRoles, normalizeFillRoles } from '../core/vault/fill-roles.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { VaultReleaseGate, VaultReleaseLease } from './vault-release-gate.js';
import type { ManualAutofillVaultBinding } from '../core/vault/vault-service.js';
import { ClientEventType } from '../core/events/client-event.js';
import type { ClientEventReceipt, ClientEventService } from './client-event-service.js';
import { bestEffortClientEvent } from './client-event-best-effort.js';
import type {
  AutofillTotpCopyAckRegistry,
  AutofillTotpCopyReceipt,
} from './autofill-totp-copy-ack-registry.js';
import {
  digestLoginCustomTargetPlan,
  isLoginCustomPlanDigest,
  parseLoginCustomAssignments,
  parseLoginCustomTargetPlan,
  type LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';

/** A frame within a tab, as reported by the browser (`webNavigation`) and never by page content. */
export interface BrowserFrame {
  frameId: number;
  url: string;
  documentId?: string;
}

/** Chrome 109+ document-scoped delivery target. */
export interface BrowserDocumentTarget {
  frameId: number;
  documentId: string;
}

/** Narrow browser and vault adapters used by the tab-level coordinator. */
export interface TabAutofillDeps {
  getTab(tabId: number): Promise<{ active: boolean; url?: string }>;
  /** Permanent host access is only consulted for cross-origin subframes. */
  hasHostAccess(url: string): Promise<boolean>;
  getFrames(tabId: number): Promise<BrowserFrame[]>;
  getFrame(tabId: number, frameId: number): Promise<BrowserFrame | undefined>;
  sendToFrame(tabId: number, target: BrowserDocumentTarget, message: FrameAutofillMessage): Promise<unknown>;
  authorizeFrame(frameUrl: string, action: 'candidate' | 'intent'): Promise<{
    assertCurrent(): void;
    defaultStrategy: UriMatchStrategySetting;
    autoCopyTotp?: boolean;
  }>;
  findCandidates(frameUrl: string, defaultStrategy: UriMatchStrategySetting): Promise<AutofillCandidate[]>;
  findFillItems(kind: FillKind): Promise<FillItemCandidate[]>;
  getLoginData(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    customPlan: LoginCustomTargetPlan,
    assertRepromptAuthorized?: () => void,
    bindFinalAuthority?: (assertCurrent: () => void) => void,
  ): Promise<AutofillInteractiveLoginData | AutofillLoginData>;
  getManualLoginData(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    customPlan: LoginCustomTargetPlan,
    expected: ManualAutofillVaultBinding,
    assertRepromptAuthorized?: () => void,
    bindFinalAuthority?: (assertCurrent: () => void) => void,
  ): Promise<AutofillInteractiveLoginData>;
  getFillData(
    cipherId: string,
    kind: FillKind,
    roles: readonly FillRole[],
    assertRepromptAuthorized?: () => void,
    bindFinalAuthority?: (assertCurrent: () => void) => void,
  ): Promise<CardFillData | IdentityFillData>;
  getTotpData?(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    bindFinalAuthority?: (assertCurrent: () => void) => void,
    assertRepromptAuthorized?: () => void,
  ): Promise<AutofillTotpData>;
  sessionGate: SessionLeaseGate;
  accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  vaultReleaseGate?: Pick<VaultReleaseGate, 'capture' | 'checkpoint' | 'assertAuthorities' | 'assert'>
    & Partial<Pick<VaultReleaseGate, 'settlePendingAction'>>;
  clientEvents?: Pick<ClientEventService, 'prepare' | 'commit'>;
  totpCopies?: Pick<
    AutofillTotpCopyAckRegistry,
    'prepareDirect' | 'commitDirect' | 'discardDirect'
  >;
  now(): number;
}

export interface TabAutofillCoordinator {
  getSuggestions(tabId: number): Promise<TabSuggestionsOutcome>;
  resolveManualLoginTarget(tabId: number): Promise<ResolvedManualAutofillTarget | undefined>;
  resolveRepromptBinding(
    tabId: number,
    target: TabSuggestionTarget,
  ): Promise<ResolvedRepromptAutofillBinding | undefined>;
  fill(
    tabId: number,
    cipherId: string,
    target: TabSuggestionTarget,
    assertExternalCurrent?: () => void,
    repromptAuthorization?: RepromptAutofillAuthorization,
  ): Promise<TabFillOutcome>;
  fillManual(
    tabId: number,
    cipherId: string,
    target: Extract<TabSuggestionTarget, { readonly kind: 'login' }>,
    binding: ManualAutofillVaultBinding,
    assertExternalCurrent: () => void,
    repromptAuthorization?: RepromptAutofillAuthorization,
  ): Promise<TabFillOutcome>;
}

export interface ResolvedRepromptAutofillBinding {
  readonly tabId: number;
  readonly frameId: number;
  readonly targetDocumentId: string;
  readonly topUrl: string;
  readonly frameUrl: string;
  readonly targetKey: string;
}

export interface ResolvedManualAutofillTarget extends ResolvedRepromptAutofillBinding {
  readonly target: Extract<TabSuggestionTarget, { readonly kind: 'login' }>;
  readonly customPlan: LoginCustomTargetPlan;
  readonly defaultStrategy: UriMatchStrategySetting;
}

export interface RepromptAutofillAuthorization {
  readonly assertCurrent: () => void;
}

const RECENT_FOCUS_WINDOW_MS = 30_000;
const MAX_FORMS_PER_FRAME = 128;
const MAX_OPAQUE_ID_LENGTH = 4_096;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

interface FormRank {
  /** 0 when focused within the last 30 seconds, 1 otherwise. */
  focusScore: number;
  /** 0 for the top frame, 1 otherwise. */
  topScore: number;
  /** Encounter order across frames and forms. */
  order: number;
}

type FrameAuthorization = Awaited<ReturnType<TabAutofillDeps['authorizeFrame']>>;
type SessionLease = ReturnType<SessionLeaseGate['capture']>;
type AccountLease = ReturnType<TabAutofillDeps['accountGate']['capture']>;

export function createTabAutofillCoordinator(deps: TabAutofillDeps): TabAutofillCoordinator {
  async function getSuggestions(tabId: number): Promise<TabSuggestionsOutcome> {
    // Candidate names and usernames are decrypted account metadata. Bind the entire scan to one
    // unlocked account before its first await so an account switch cannot merge two snapshots.
    const sessionLease = deps.sessionGate.capture();
    const accountLease = deps.accountGate.capture();
    const assertCurrent = () => assertSecurityCurrent(deps, sessionLease, accountLease);

    const tab = await deps.getTab(tabId);
    assertCurrent();
    if (!tab.active) return { status: 'no_eligible_tab', suggestions: [] };
    if (tab.url === undefined) return { status: 'site_access_unavailable', suggestions: [] };
    if (isRestrictedUrl(tab.url)) return { status: 'restricted_page', suggestions: [] };
    const topUrl = tab.url;

    const frames = await deps.getFrames(tabId);
    assertCurrent();

    const authorizations: FrameAuthorization[] = [];
    const authorizationByUrl = new Map<string, Promise<FrameAuthorization>>();
    const authorizeCandidates = (frameUrl: string): Promise<FrameAuthorization> => {
      let pending = authorizationByUrl.get(frameUrl);
      if (!pending) {
        pending = (async () => {
          const authorization = await deps.authorizeFrame(frameUrl, 'candidate');
          assertCurrent();
          authorization.assertCurrent();
          authorizations.push(authorization);
          return authorization;
        })();
        authorizationByUrl.set(frameUrl, pending);
      }
      return pending;
    };

    const candidatesByUrl = new Map<string, Promise<AutofillCandidate[]>>();
    const findCandidates = (frameUrl: string): Promise<AutofillCandidate[]> => {
      let pending = candidatesByUrl.get(frameUrl);
      if (!pending) {
        pending = (async () => {
          const authorization = await authorizeCandidates(frameUrl);
          assertCurrent();
          authorization.assertCurrent();
          const candidates = await deps.findCandidates(frameUrl, authorization.defaultStrategy);
          assertCurrent();
          authorization.assertCurrent();
          return candidates.map(narrowAutofillCandidate);
        })();
        candidatesByUrl.set(frameUrl, pending);
      }
      return pending;
    };

    const fillItemsByKind = new Map<FillKind, Promise<FillItemCandidate[]>>();
    const findFillItems = (kind: FillKind): Promise<FillItemCandidate[]> => {
      let pending = fillItemsByKind.get(kind);
      if (!pending) {
        assertCurrent();
        pending = deps.findFillItems(kind).then((items) => {
          assertCurrent();
          return items.map(narrowFillItemCandidate);
        });
        fillItemsByKind.set(kind, pending);
      }
      return pending;
    };

    const inspected: Array<{
      frame: BrowserFrame;
      documentId: string;
      inspection: FrameInspection;
      authorization: FrameAuthorization;
    }> = [];
    let attempted = 0;

    for (const frame of frames) {
      const documentId = frame.documentId;
      if (!documentId) continue;
      const accessible = await isFrameAccessible(frame, topUrl, deps);
      assertCurrent();
      if (!accessible) continue;

      let authorization: FrameAuthorization;
      try {
        authorization = await authorizeCandidates(frame.url);
      } catch (err) {
        // A blocked embed does not suppress otherwise-valid top-frame suggestions. The top URL is
        // authorized independently below, so a blocked top document still fails the request closed.
        if (err instanceof AppError && err.code === 'denied' && frame.url !== topUrl) continue;
        throw err;
      }

      attempted += 1;
      try {
        const response = await deps.sendToFrame(
          tabId,
          { frameId: frame.frameId, documentId },
          { type: 'autofill.inspectFrame' },
        );
        assertCurrent();
        authorization.assertCurrent();
        const inspection = parseFrameInspection(response);
        if (inspection) inspected.push({ frame, documentId, inspection, authorization });
      } catch (err) {
        if (!isMissingContentScriptError(err)) throw err;
      }
    }

    if (attempted > 0 && inspected.length === 0) {
      assertScanCurrent(assertCurrent, authorizations);
      return { status: 'content_script_unavailable', suggestions: [] };
    }

    const merged = new Map<string, TabAutofillSuggestion>();
    const bestRank = new Map<string, FormRank>();
    const suggestionKey = (kind: TabAutofillSuggestion['kind'], cipherId: string) => `${kind}\u0000${cipherId}`;

    const mergeLogin = (candidate: AutofillCandidate): void => {
      const key = suggestionKey('login', candidate.id);
      if (!merged.has(key)) merged.set(key, { kind: 'login', ...candidate });
    };

    const offerLoginTarget = (
      candidate: AutofillCandidate,
      target: Extract<TabSuggestionTarget, { kind: 'login' }>,
      rank: FormRank,
    ): void => {
      const key = suggestionKey('login', candidate.id);
      mergeLogin(candidate);
      const current = bestRank.get(key);
      if (!current || compareFormRank(rank, current) < 0) {
        bestRank.set(key, rank);
        merged.set(key, { kind: 'login', ...candidate, target });
      }
    };

    const offerStructuredTarget = (
      kind: FillKind,
      candidate: FillItemCandidate,
      target: Extract<TabSuggestionTarget, { kind: FillKind }>,
      rank: FormRank,
    ): void => {
      const key = suggestionKey(kind, candidate.id);
      const current = bestRank.get(key);
      if (current && compareFormRank(rank, current) >= 0) return;
      bestRank.set(key, rank);
      if (kind === 'card' && target.kind === 'card') {
        merged.set(key, { kind, ...candidate, target });
      } else if (kind === 'identity' && target.kind === 'identity') {
        merged.set(key, { kind, ...candidate, target });
      }
    };

    // URI-matched logins remain useful for opening detail even when the page has no login form.
    for (const candidate of await findCandidates(topUrl)) mergeLogin(candidate);

    let order = 0;
    for (const { frame, documentId, inspection, authorization } of inspected) {
      // Candidate matching always consumes the browser URL, never the content-reported URL.
      const frameCandidates = await findCandidates(frame.url);
      for (const candidate of frameCandidates) mergeLogin(candidate);

      // URL disagreement means navigation won the inspection race. Keep URI rows but withhold every
      // direct target and every non-URI card/identity candidate from that stale inspection.
      if (inspection.frameUrl !== frame.url) continue;

      for (const form of inspection.forms) {
        if (!form.visible) continue;
        const rank: FormRank = {
          focusScore: hasRecentFocus(form.focusedAt, deps.now()) ? 0 : 1,
          topScore: frame.frameId === 0 ? 0 : 1,
          order: order++,
        };
        const baseTarget = {
          frameId: frame.frameId,
          formId: form.formId,
          documentId,
          runtimeIncarnation: inspection.runtimeIncarnation,
          generation: inspection.generation,
        };

        if (form.kind === 'login') {
          const customPlanDigest = await digestLoginCustomTargetPlan(form.customPlan);
          assertCurrent();
          authorization.assertCurrent();
          const target = { ...baseTarget, kind: 'login', customPlanDigest } as const;
          for (const candidate of frameCandidates) offerLoginTarget(candidate, target, rank);
          continue;
        }

        assertCurrent();
        authorization.assertCurrent();
        const items = await findFillItems(form.kind);
        assertCurrent();
        authorization.assertCurrent();
        if (form.kind === 'card') {
          const target = { ...baseTarget, kind: 'card', roles: [...form.roles] } as const;
          for (const item of items) offerStructuredTarget('card', item, target, rank);
        } else {
          const target = { ...baseTarget, kind: 'identity', roles: [...form.roles] } as const;
          for (const item of items) offerStructuredTarget('identity', item, target, rank);
        }
      }
    }

    assertScanCurrent(assertCurrent, authorizations);
    return { status: 'ready', suggestions: Array.from(merged.values()) };
  }

  async function resolveRepromptBinding(
    tabId: number,
    unsafeTarget: TabSuggestionTarget,
  ): Promise<ResolvedRepromptAutofillBinding | undefined> {
    const target = parseTabSuggestionTarget(unsafeTarget);
    if (!target) return undefined;

    const tab = await deps.getTab(tabId);
    if (!tab.active || tab.url === undefined || isRestrictedUrl(tab.url)) return undefined;
    const frame = await deps.getFrame(tabId, target.frameId);
    if (!frame || !sameDocument(frame, target)) return undefined;
    if (!(await isFrameAccessible(frame, tab.url, deps))) return undefined;
    if (!(await isDocumentCurrent(tabId, tab.url, frame, deps))) return undefined;
    return Object.freeze({
      tabId,
      frameId: target.frameId,
      targetDocumentId: target.documentId,
      topUrl: tab.url,
      frameUrl: frame.url,
      targetKey: tabSuggestionTargetKey(target),
    });
  }

  async function resolveManualLoginTarget(
    tabId: number,
  ): Promise<ResolvedManualAutofillTarget | undefined> {
    const sessionLease = deps.sessionGate.capture();
    const accountLease = deps.accountGate.capture();
    const assertCurrent = () => assertSecurityCurrent(deps, sessionLease, accountLease);
    const tab = await deps.getTab(tabId);
    assertCurrent();
    if (!tab.active || tab.url === undefined || isRestrictedUrl(tab.url)) return undefined;
    const topUrl = tab.url;
    const frames = await deps.getFrames(tabId);
    assertCurrent();
    const matches: ResolvedManualAutofillTarget[] = [];
    const authorizations: FrameAuthorization[] = [];

    for (const frame of frames) {
      if (!frame.documentId || !(await isFrameAccessible(frame, topUrl, deps))) continue;
      assertCurrent();
      let authorization: FrameAuthorization;
      try {
        authorization = await deps.authorizeFrame(frame.url, 'intent');
      } catch (error) {
        if (error instanceof AppError && error.code === 'denied' && frame.frameId !== 0) continue;
        throw error;
      }
      assertCurrent();
      authorization.assertCurrent();
      authorizations.push(authorization);

      let inspection: FrameInspection | undefined;
      try {
        inspection = parseFrameInspection(await deps.sendToFrame(
          tabId,
          { frameId: frame.frameId, documentId: frame.documentId },
          { type: 'autofill.inspectFrame' },
        ));
      } catch (error) {
        if (isMissingContentScriptError(error)) continue;
        throw error;
      }
      assertCurrent();
      authorization.assertCurrent();
      if (!inspection || inspection.frameUrl !== frame.url) continue;
      for (const form of inspection.forms) {
        if (!form.visible || form.kind !== 'login') continue;
        const customPlanDigest = await digestLoginCustomTargetPlan(form.customPlan);
        assertCurrent();
        authorization.assertCurrent();
        const target = Object.freeze({
          kind: 'login' as const,
          frameId: frame.frameId,
          documentId: frame.documentId,
          runtimeIncarnation: inspection.runtimeIncarnation,
          formId: form.formId,
          generation: inspection.generation,
          customPlanDigest,
        });
        matches.push(Object.freeze({
          tabId,
          frameId: frame.frameId,
          targetDocumentId: frame.documentId,
          topUrl,
          frameUrl: frame.url,
          targetKey: tabSuggestionTargetKey(target),
          target,
          customPlan: form.customPlan,
          defaultStrategy: authorization.defaultStrategy,
        }));
        if (matches.length > 1) return undefined;
      }
    }

    assertScanCurrent(assertCurrent, authorizations);
    const match = matches[0];
    if (!match) return undefined;
    const frame = await deps.getFrame(tabId, match.frameId);
    assertScanCurrent(assertCurrent, authorizations);
    if (!frame || !sameDocument(frame, match.target)
        || !(await isDocumentCurrent(tabId, topUrl, frame, deps))) return undefined;
    assertScanCurrent(assertCurrent, authorizations);
    return match;
  }

  async function fillInternal(
    tabId: number,
    cipherId: string,
    unsafeTarget: TabSuggestionTarget,
    assertExternalCurrent?: () => void,
    repromptAuthorization?: RepromptAutofillAuthorization,
    manualBinding?: ManualAutofillVaultBinding,
  ): Promise<TabFillOutcome> {
    const target = parseTabSuggestionTarget(unsafeTarget);
    if (!target) return { status: 'target_changed' };
    let totpCopyReceipt: AutofillTotpCopyReceipt | undefined;

    try {
      // Both leases are captured synchronously before the first await. The account lease is explicit
      // rather than inferred from session transitions, so an old request cannot bind to a new vault.
      const sessionLease = deps.sessionGate.capture();
      const accountLease = deps.accountGate.capture();
      const releaseLease: VaultReleaseLease | undefined = deps.vaultReleaseGate?.capture(sessionLease);
      const assertCurrent = () => {
        assertSecurityCurrent(deps, sessionLease, accountLease);
        assertExternalCurrent?.();
        repromptAuthorization?.assertCurrent();
      };
      assertCurrent();

      const tab = await deps.getTab(tabId);
      assertCurrent();
      if (!tab.active) return { status: 'no_eligible_tab' };
      if (tab.url === undefined) return { status: 'site_access_unavailable' };
      if (isRestrictedUrl(tab.url)) return { status: 'restricted_page' };
      const topUrl = tab.url;

      const frame = await deps.getFrame(tabId, target.frameId);
      assertCurrent();
      if (!frame) return { status: 'content_script_unavailable' };
      if (!sameDocument(frame, target)) return { status: 'target_changed' };
      const accessible = await isFrameAccessible(frame, topUrl, deps);
      assertCurrent();
      if (!accessible) return { status: 'content_script_unavailable' };

      const authorization = await deps.authorizeFrame(frame.url, 'intent');
      assertCurrent();
      authorization.assertCurrent();

      // Re-inspect the exact browser document. Popup metadata never authorizes form identity, roles,
      // or the structural generation used to decide what secret fields may be released.
      const rawInspection = await deps.sendToFrame(
        tabId,
        { frameId: target.frameId, documentId: target.documentId },
        { type: 'autofill.inspectFrame' },
      );
      assertCurrent();
      authorization.assertCurrent();
      const inspection = parseFrameInspection(rawInspection);
      if (!inspection || inspection.frameUrl !== frame.url || !(await inspectionMatchesTarget(inspection, target))) {
        return { status: 'target_changed' };
      }

      // Inspection can race a same-frame navigation. Confirm browser state again before decrypting.
      if (!(await isDocumentCurrent(tabId, topUrl, frame, deps))) return { status: 'target_changed' };
      assertCurrent();
      authorization.assertCurrent();

      let message: FrameAutofillMessage;
      let assertItemAuthority: (() => void) | undefined;
      if (target.kind === 'login') {
        const inspectedForm = inspection.forms.find(
          (form): form is Extract<FrameAutofillForm, { kind: 'login' }> => form.kind === 'login' && form.formId === target.formId,
        );
        if (!inspectedForm) return { status: 'target_changed' };
        const projection = narrowInteractiveLoginData(
          await (manualBinding
            ? deps.getManualLoginData(
                cipherId,
                frame.url,
                authorization.defaultStrategy,
                inspectedForm.customPlan,
                manualBinding,
                repromptAuthorization ? assertCurrent : undefined,
                (assertCurrent) => { assertItemAuthority = assertCurrent; },
              )
            : repromptAuthorization
              ? deps.getLoginData(
                  cipherId,
                  frame.url,
                  authorization.defaultStrategy,
                  inspectedForm.customPlan,
                  assertCurrent,
                  (assertCurrent) => { assertItemAuthority = assertCurrent; },
                )
              : deps.getLoginData(
                  cipherId,
                  frame.url,
                  authorization.defaultStrategy,
                  inspectedForm.customPlan,
                  undefined,
                  (assertCurrent) => { assertItemAuthority = assertCurrent; },
                )),
          inspectedForm.customPlan,
        );
        if (!projection) return { status: 'target_changed' };
        assertCurrent();
        authorization.assertCurrent();
        message = {
          type: 'autofill.commitLoginFill',
          formId: target.formId,
          expectedFrameUrl: frame.url,
          expectedRuntimeIncarnation: target.runtimeIncarnation,
          expectedGeneration: target.generation,
          login: projection.login,
          customPlan: inspectedForm.customPlan,
          customPlanDigest: target.customPlanDigest,
          customAssignments: projection.customAssignments,
        };
      } else if (target.kind === 'card') {
        const data = narrowCardData(
          await (repromptAuthorization
            ? deps.getFillData(
                cipherId,
                target.kind,
                target.roles,
                assertCurrent,
                (assertCurrent) => { assertItemAuthority = assertCurrent; },
              )
            : deps.getFillData(
                cipherId,
                target.kind,
                target.roles,
                undefined,
                (assertCurrent) => { assertItemAuthority = assertCurrent; },
              )),
          target.roles,
        );
        assertCurrent();
        authorization.assertCurrent();
        message = {
          type: 'autofill.commitStructuredFill',
          kind: target.kind,
          formId: target.formId,
          roles: [...target.roles],
          expectedFrameUrl: frame.url,
          expectedRuntimeIncarnation: target.runtimeIncarnation,
          expectedGeneration: target.generation,
          data,
        };
      } else {
        const data = narrowIdentityData(
          await (repromptAuthorization
            ? deps.getFillData(
                cipherId,
                target.kind,
                target.roles,
                assertCurrent,
                (assertCurrent) => { assertItemAuthority = assertCurrent; },
              )
            : deps.getFillData(
                cipherId,
                target.kind,
                target.roles,
                undefined,
                (assertCurrent) => { assertItemAuthority = assertCurrent; },
              )),
          target.roles,
        );
        assertCurrent();
        authorization.assertCurrent();
        message = {
          type: 'autofill.commitStructuredFill',
          kind: target.kind,
          formId: target.formId,
          roles: [...target.roles],
          expectedFrameUrl: frame.url,
          expectedRuntimeIncarnation: target.runtimeIncarnation,
          expectedGeneration: target.generation,
          data,
        };
      }

      const clientEventReceipt = await prepareClientAutofilledEvent(deps, cipherId);

      // Secret retrieval may await cache and key work. Re-read both browser objects before commit;
      // document-scoped delivery closes the final navigation race after these synchronous fences.
      if (!(await isDocumentCurrent(tabId, topUrl, frame, deps))) return { status: 'target_changed' };
      assertCurrent();
      authorization.assertCurrent();
      const releaseProof = releaseLease && deps.vaultReleaseGate
        ? await deps.vaultReleaseGate.checkpoint(releaseLease)
        : undefined;
      if (releaseProof && deps.vaultReleaseGate) {
        deps.vaultReleaseGate.assertAuthorities(releaseProof, () => {
          assertCurrent();
          authorization.assertCurrent();
          assertItemAuthority?.();
        });
        deps.vaultReleaseGate.assert(releaseProof);
      }
      if (target.kind === 'login'
          && authorization.autoCopyTotp === true
          && deps.getTotpData
          && deps.totpCopies) {
        const totpAuthorities: Array<() => void> = [];
        try {
          const totp = await deps.getTotpData(
            cipherId,
            frame.url,
            authorization.defaultStrategy,
            (assertTotpCurrent) => { totpAuthorities.push(assertTotpCurrent); },
            repromptAuthorization?.assertCurrent,
          );
          const capturedTotpAuthorities = Object.freeze([...totpAuthorities]);
          const assertTotpCopyCurrent = (): void => {
            assertCurrent();
            authorization.assertCurrent();
            assertItemAuthority?.();
            for (const assertTotpCurrent of capturedTotpAuthorities) assertTotpCurrent();
          };
          assertTotpCopyCurrent();
          totpCopyReceipt = deps.totpCopies.prepareDirect(
            totp.code,
            assertTotpCopyCurrent,
            tabId,
          );
        } catch {
          totpCopyReceipt = undefined;
        }
      }
      if (totpCopyReceipt) {
        // TOTP retrieval is another secret-read await after the ordinary final document fence. Re-run
        // every browser and vault authority check before allowing the fill acknowledgement to own it.
        if (!(await isDocumentCurrent(tabId, topUrl, frame, deps))) {
          deps.totpCopies?.discardDirect(totpCopyReceipt);
          totpCopyReceipt = undefined;
          return { status: 'target_changed' };
        }
        assertCurrent();
        authorization.assertCurrent();
        assertItemAuthority?.();
        if (releaseProof && deps.vaultReleaseGate) {
          deps.vaultReleaseGate.assertAuthorities(releaseProof, () => {
            assertCurrent();
            authorization.assertCurrent();
            assertItemAuthority?.();
          });
          deps.vaultReleaseGate.assert(releaseProof);
        }
      }
      let response: unknown;
      try {
        response = await deps.sendToFrame(
          tabId,
          { frameId: target.frameId, documentId: target.documentId },
          message,
        );
      } catch (error) {
        if (totpCopyReceipt) deps.totpCopies?.discardDirect(totpCopyReceipt);
        if (manualBinding) return { status: 'fill_outcome_unknown' };
        throw error;
      }
      const parsed = parseTabFillOutcome(response);
      if (isExactFilledTabOutcome(response)) {
        await commitClientAutofilledEvent(deps, clientEventReceipt);
        if (totpCopyReceipt && deps.totpCopies) {
          await deps.totpCopies.commitDirect(totpCopyReceipt).catch(() => ({ kind: 'failed' as const }));
        }
      } else if (totpCopyReceipt) {
        deps.totpCopies?.discardDirect(totpCopyReceipt);
      }
      return parsed ?? { status: manualBinding ? 'fill_outcome_unknown' : 'content_script_unavailable' };
    } catch (err) {
      if (totpCopyReceipt) deps.totpCopies?.discardDirect(totpCopyReceipt);
      await deps.vaultReleaseGate?.settlePendingAction?.();
      if (err instanceof AppError) return { status: fillOutcomeForErrorCode(err.code) };
      if (isMissingContentScriptError(err)) return { status: 'content_script_unavailable' };
      throw err;
    }
  }

  function fill(
    tabId: number,
    cipherId: string,
    target: TabSuggestionTarget,
    assertExternalCurrent?: () => void,
    repromptAuthorization?: RepromptAutofillAuthorization,
  ): Promise<TabFillOutcome> {
    return fillInternal(
      tabId,
      cipherId,
      target,
      assertExternalCurrent,
      repromptAuthorization,
    );
  }

  function fillManual(
    tabId: number,
    cipherId: string,
    target: Extract<TabSuggestionTarget, { readonly kind: 'login' }>,
    binding: ManualAutofillVaultBinding,
    assertExternalCurrent: () => void,
    repromptAuthorization?: RepromptAutofillAuthorization,
  ): Promise<TabFillOutcome> {
    return fillInternal(
      tabId,
      cipherId,
      target,
      assertExternalCurrent,
      repromptAuthorization,
      binding,
    );
  }

  return { getSuggestions, resolveManualLoginTarget, resolveRepromptBinding, fill, fillManual };
}

async function prepareClientAutofilledEvent(
  deps: TabAutofillDeps,
  cipherId: string,
): Promise<ClientEventReceipt | undefined> {
  const events = deps.clientEvents;
  if (!events) return undefined;
  return bestEffortClientEvent(() => events.prepare({
      type: ClientEventType.Cipher_ClientAutofilled,
      cipherId,
  }));
}

async function commitClientAutofilledEvent(
  deps: TabAutofillDeps,
  receipt: ClientEventReceipt | undefined,
): Promise<void> {
  const events = deps.clientEvents;
  if (!receipt || !events) return;
  await bestEffortClientEvent(() => events.commit(receipt));
}

function assertSecurityCurrent(
  deps: Pick<TabAutofillDeps, 'sessionGate' | 'accountGate'>,
  sessionLease: SessionLease,
  accountLease: AccountLease,
): void {
  deps.sessionGate.assert(sessionLease);
  deps.accountGate.assert(accountLease);
}

function assertScanCurrent(assertCurrent: () => void, authorizations: readonly FrameAuthorization[]): void {
  assertCurrent();
  for (const authorization of authorizations) authorization.assertCurrent();
}

function narrowAutofillCandidate(value: AutofillCandidate): AutofillCandidate {
  const candidate: AutofillCandidate = {
    id: value.id,
    name: value.name,
    matchedUri: value.matchedUri,
    matchType: value.matchType,
    favorite: value.favorite,
  };
  if (typeof value.username === 'string') candidate.username = value.username;
  if (value.hasTotp === true) candidate.hasTotp = true;
  if (value.reprompt === true) candidate.reprompt = true;
  return candidate;
}

function narrowFillItemCandidate(value: FillItemCandidate): FillItemCandidate {
  const candidate: FillItemCandidate = {
    id: value.id,
    name: value.name,
    favorite: value.favorite,
  };
  if (typeof value.subtitle === 'string') candidate.subtitle = value.subtitle;
  if (value.reprompt === true) candidate.reprompt = true;
  return candidate;
}

/** Rebuild trusted vault results so legacy or accidentally widened properties never cross wire. */
function narrowLoginData(value: AutofillLoginData): AutofillLoginData {
  const login: AutofillLoginData = {};
  if (typeof value.username === 'string') login.username = value.username;
  if (typeof value.password === 'string') login.password = value.password;
  return login;
}

function narrowInteractiveLoginData(
  value: AutofillInteractiveLoginData | AutofillLoginData,
  plan: LoginCustomTargetPlan,
): AutofillInteractiveLoginData | undefined {
  if (!isRecord(value)) return undefined;
  if (!('login' in value)) return { login: narrowLoginData(value), customAssignments: [] };
  if (!isRecord(value.login)) return undefined;
  const customAssignments = parseLoginCustomAssignments(value.customAssignments);
  if (!customAssignments) return undefined;
  const targetTypes = new Map(plan.targets.map((target) => [target.fieldId, target.controlType]));
  if (customAssignments.some((assignment) => {
    const controlType = targetTypes.get(assignment.fieldId);
    return !controlType || ('checked' in assignment ? controlType !== 'checkbox' : controlType === 'checkbox');
  })) return undefined;
  return { login: narrowLoginData(value.login), customAssignments };
}

function narrowCardData(value: CardFillData | IdentityFillData, roles: readonly CardFillRole[]): CardFillData {
  const source = isRecord(value) ? value : {};
  const data: CardFillData = {};
  for (const key of fillDataKeysForRoles('card', roles) ?? []) {
    if (!isCardFillDataKey(key)) continue;
    const field = source[key];
    if (typeof field === 'string') data[key] = field;
  }
  return data;
}

function narrowIdentityData(
  value: CardFillData | IdentityFillData,
  roles: readonly IdentityFillRole[],
): IdentityFillData {
  const source = isRecord(value) ? value : {};
  const data: IdentityFillData = {};
  for (const key of fillDataKeysForRoles('identity', roles) ?? []) {
    if (!isIdentityFillDataKey(key)) continue;
    const field = source[key];
    if (typeof field === 'string') data[key] = field;
  }
  return data;
}

const CARD_DATA_KEYS = new Set<keyof CardFillData>([
  'cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code',
]);
const IDENTITY_DATA_KEYS = new Set<keyof IdentityFillData>([
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
  'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'username',
]);

function isCardFillDataKey(value: string): value is keyof CardFillData {
  return CARD_DATA_KEYS.has(value as keyof CardFillData);
}

function isIdentityFillDataKey(value: string): value is keyof IdentityFillData {
  return IDENTITY_DATA_KEYS.has(value as keyof IdentityFillData);
}

/** Parse browser frame data that may include Chrome's documentId extension field. */
export function parseBrowserFrame(value: unknown): BrowserFrame | undefined {
  if (!isRecord(value)) return undefined;
  const { frameId, url, documentId } = value;
  if (!isNonNegativeSafeInteger(frameId) || typeof url !== 'string') return undefined;
  if (documentId !== undefined && !isOpaqueId(documentId)) return undefined;
  return documentId !== undefined ? { frameId, url, documentId } : { frameId, url };
}

function parseTabSuggestionTarget(value: unknown): TabSuggestionTarget | undefined {
  if (!isRecord(value)) return undefined;
  const { frameId, formId, documentId, runtimeIncarnation, generation, kind } = value;
  if (
    !isNonNegativeSafeInteger(frameId)
    || !isOpaqueId(formId)
    || !isOpaqueId(documentId)
    || !isRuntimeIncarnation(runtimeIncarnation)
    || !isNonNegativeSafeInteger(generation)
  ) return undefined;

  const base = { frameId, formId, documentId, runtimeIncarnation, generation };
  if (kind === 'login') {
    if ('roles' in value || !isLoginCustomPlanDigest(value.customPlanDigest)) return undefined;
    return { ...base, kind, customPlanDigest: value.customPlanDigest };
  }
  if (kind === 'card') {
    const roles = parseCanonicalRoles(kind, value.roles);
    return roles ? { ...base, kind, roles } : undefined;
  }
  if (kind === 'identity') {
    const roles = parseCanonicalRoles(kind, value.roles);
    return roles ? { ...base, kind, roles } : undefined;
  }
  return undefined;
}

function tabSuggestionTargetKey(target: TabSuggestionTarget): string {
  const purposeBinding = target.kind === 'login'
    ? target.customPlanDigest
    : [...target.roles];
  return JSON.stringify([
    target.kind,
    target.frameId,
    target.formId,
    target.documentId,
    target.runtimeIncarnation,
    target.generation,
    purposeBinding,
  ]);
}

function parseFrameInspection(value: unknown): FrameInspection | undefined {
  if (!isRecord(value)) return undefined;
  const { runtimeIncarnation, frameUrl, generation, forms } = value;
  if (
    !isRuntimeIncarnation(runtimeIncarnation)
    || typeof frameUrl !== 'string'
    || !isNonNegativeSafeInteger(generation)
    || !Array.isArray(forms)
    || forms.length > MAX_FORMS_PER_FRAME
  ) return undefined;
  const parsedForms: FrameAutofillForm[] = [];
  for (const form of forms) {
    const parsed = parseFrameForm(form);
    if (!parsed) return undefined;
    parsedForms.push(parsed);
  }
  return { runtimeIncarnation, frameUrl, generation, forms: parsedForms };
}

function parseFrameForm(value: unknown): FrameAutofillForm | undefined {
  if (!isRecord(value)) return undefined;
  const { kind, formId, visible, focusedAt } = value;
  if (
    !isOpaqueId(formId)
    || typeof visible !== 'boolean'
    || (focusedAt !== undefined && (
      typeof focusedAt !== 'number' || !Number.isFinite(focusedAt) || focusedAt < 0
    ))
  ) return undefined;
  const base = {
    formId,
    visible,
    ...(focusedAt === undefined ? {} : { focusedAt }),
  };
  if (kind === 'login') {
    const customPlan = parseLoginCustomTargetPlan(value.customPlan);
    if ('roles' in value || !customPlan) return undefined;
    return { ...base, kind, customPlan };
  }
  if (kind === 'card') {
    const roles = parseCanonicalRoles(kind, value.roles);
    return roles ? { ...base, kind, roles } : undefined;
  }
  if (kind === 'identity') {
    const roles = parseCanonicalRoles(kind, value.roles);
    return roles ? { ...base, kind, roles } : undefined;
  }
  return undefined;
}

function parseCanonicalRoles(kind: 'card', value: unknown): CardFillRole[] | undefined;
function parseCanonicalRoles(kind: 'identity', value: unknown): IdentityFillRole[] | undefined;
function parseCanonicalRoles(kind: FillKind, value: unknown): FillRole[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const normalized = normalizeFillRoles(kind, value);
  if (
    !normalized
    || normalized.length !== value.length
    || normalized.some((role, index) => role !== value[index])
  ) return undefined;
  return [...normalized];
}

async function inspectionMatchesTarget(inspection: FrameInspection, target: TabSuggestionTarget): Promise<boolean> {
  if (inspection.runtimeIncarnation !== target.runtimeIncarnation
      || inspection.generation !== target.generation) return false;
  const matches = inspection.forms.filter((form) => form.formId === target.formId);
  if (matches.length !== 1) return false;
  const form = matches[0]!;
  if (!form.visible || form.kind !== target.kind) return false;
  if (target.kind === 'login' && form.kind === 'login') {
    return target.customPlanDigest === await digestLoginCustomTargetPlan(form.customPlan);
  }
  if (target.kind === 'card' && form.kind === 'card') return exactRoles(form.roles, target.roles);
  if (target.kind === 'identity' && form.kind === 'identity') return exactRoles(form.roles, target.roles);
  return false;
}

function exactRoles(first: readonly FillRole[], second: readonly FillRole[]): boolean {
  return first.length === second.length && first.every((role, index) => role === second[index]);
}

function hasRecentFocus(focusedAt: number | undefined, now: number): boolean {
  if (focusedAt === undefined || !Number.isFinite(now)) return false;
  const age = now - focusedAt;
  return age >= 0 && age <= RECENT_FOCUS_WINDOW_MS;
}

function compareFormRank(a: FormRank, b: FormRank): number {
  if (a.focusScore !== b.focusScore) return a.focusScore - b.focusScore;
  if (a.topScore !== b.topScore) return a.topScore - b.topScore;
  return a.order - b.order;
}

function sameDocument(frame: BrowserFrame, target: TabSuggestionTarget): boolean {
  return frame.frameId === target.frameId
    && frame.documentId !== undefined
    && frame.documentId === target.documentId;
}

async function isDocumentCurrent(
  tabId: number,
  topUrl: string,
  originalFrame: BrowserFrame & { documentId?: string },
  deps: Pick<TabAutofillDeps, 'getTab' | 'getFrame'>,
): Promise<boolean> {
  const tab = await deps.getTab(tabId);
  if (!tab.active || tab.url !== topUrl) return false;
  const frame = await deps.getFrame(tabId, originalFrame.frameId);
  return frame !== undefined
    && frame.frameId === originalFrame.frameId
    && frame.url === originalFrame.url
    && frame.documentId !== undefined
    && frame.documentId === originalFrame.documentId;
}

/** Same scheme, host, and port. Falls back to exact strings for malformed URLs. */
function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return a === b;
  }
}

const NON_HOST_URL_SCHEME = /^(?:about|data|blob):/i;

function isSkippableFrameUrl(url: string): boolean {
  return NON_HOST_URL_SCHEME.test(url);
}

async function isFrameAccessible(frame: BrowserFrame, topUrl: string, deps: TabAutofillDeps): Promise<boolean> {
  if (frame.frameId === 0) return true;
  if (isSkippableFrameUrl(frame.url)) return false;
  if (sameOrigin(frame.url, topUrl)) return true;
  return deps.hasHostAccess(frame.url);
}

const MISSING_CONTENT_SCRIPT_MESSAGE = /could not establish connection|receiving end|message port closed|no document with id|no frame with id|frame with id .* was removed/i;

function isMissingContentScriptError(err: unknown): boolean {
  return err instanceof Error && MISSING_CONTENT_SCRIPT_MESSAGE.test(err.message);
}

const RESTRICTED_HOSTS = /^https:\/\/(chrome\.google\.com\/webstore|chromewebstore\.google\.com)(\/|$)/i;

function isRestrictedUrl(url: string): boolean {
  if (!/^https?:\/\//i.test(url)) return true;
  return RESTRICTED_HOSTS.test(url);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isOpaqueId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_OPAQUE_ID_LENGTH;
}

function isRuntimeIncarnation(value: unknown): value is string {
  return typeof value === 'string' && UUID_V4_PATTERN.test(value);
}

function fillOutcomeForErrorCode(code: AppErrorCode): TabFillOutcome['status'] {
  switch (code) {
    case 'reprompt_required':
      return 'reprompt_required';
    case 'locked':
      return 'vault_locked';
    case 'sync_required':
      return 'sync_required';
    case 'denied':
    case 'session_expired':
      return 'no_longer_matched';
    default:
      return 'no_fillable_target';
  }
}

function parseTabFillOutcome(value: unknown): TabFillOutcome | undefined {
  if (!isRecord(value)) return undefined;
  const { status } = value;
  if (typeof status !== 'string') return undefined;
  switch (status) {
    case 'filled':
    case 'no_eligible_tab':
    case 'site_access_unavailable':
    case 'no_fillable_target':
    case 'target_changed':
    case 'restricted_page':
    case 'content_script_unavailable':
      return { status };
    default:
      return undefined;
  }
}

function isExactFilledTabOutcome(value: unknown): boolean {
  if (!isRecord(value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 1 || keys[0] !== 'status') return false;
  const status = Object.getOwnPropertyDescriptor(value, 'status');
  return status?.enumerable === true && 'value' in status && status.value === 'filled';
}
