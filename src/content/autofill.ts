import browser from 'webextension-polyfill';
import {
  sendRequest,
  isExtensionContextAlive,
  type AutofillCandidate,
  type AutofillIntentPurpose,
  type AutofillLoginData,
  type AutofillTotpData,
  type AutofillClientConfig,
  type AutofillSavePrompt,
  type ContextLoginTargetClaimResult,
  type ContentStructuredAutofillTarget,
  type FillItemCandidate,
  type KeyboardAutofillClaimBinding,
  type TabFillOutcome,
} from '../messaging/protocol.js';
import {
  digestLoginCustomTargetPlan,
  parseLoginCustomAssignments,
  isLoginCustomPlanDigest,
  parseLoginCustomTargetPlan,
  type LoginCustomAssignment,
  type LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';
import type { CardFillData, IdentityFillData } from '../messaging/protocol.js';
import type {
  AutofillSaveCaptureSubmission,
  AutofillSaveCaptureWakeResult,
  ContentCommand,
  ContextFillResult,
  FillCommand,
  FillRole,
  FillTargetReservationResult,
  HoldFillTargetResult,
} from '../messaging/protocol.js';
import { equalFillRoles, fillDataKeysForRoles, normalizeFillRoles } from '../core/vault/fill-roles.js';
import type { FrameAutofillMessage, FrameInspection } from '../messaging/protocol.js';
import { clearTotpCode, fillLoginForm, fillTotpCode, setInputValue } from './fill.js';
import { flashFill } from './fill-highlight.js';
import { createFrameAutofillController, type FrameAutofillController } from './frame-autofill.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';
import {
  captureControlOwner,
  composedParentElement,
  composedSlotPath,
  hasLoginCredentialTarget,
  hasSameControlOwner,
  hasSameTotpInputs,
  inputControlsInScope,
  isFillableInput,
  isLoginPasswordCandidate,
  isSemanticSourceAvailableInTree,
  resolveTotpInputs,
  type ControlOwnerSnapshot,
  type DetectedLoginForm,
} from './form-detection.js';
import { isFillableField, type DetectedFillForm } from './field-detection.js';
import type { FillFieldElement } from './field-detection.js';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole } from './field-map.js';
import {
  computeFillProjection,
  FocusedFillCycle,
  NOTICE_FOCUS,
  resolveFocusedFill,
  runFocusedFill,
  type FocusedFillDeps,
  type FocusedFillCycleSelection,
  type FocusedTarget,
  type FillProjection,
} from './focused-fill.js';
import { createAutofillPopover } from './popover.js';
import { createStructuredPreview, positionStructuredPreview } from './ui/structured-preview-element.js';
import {
  claimInlineSurface,
  inlineSurfaceScope,
  releaseInlineSurface,
} from './inline-surface-coordinator.js';
import { startSaveCapture, type CapturedLogin, type CapturedUsername } from './capture.js';
import { createSaveBar, type SaveBar } from './save-bar.js';
import { clearNotice, showNotice } from './notice.js';
import { ensureMiyuFonts } from './ui/fonts.js';
import { createTotpPanel, type TotpPanel } from './totp-fill.js';
import { copyTotpCodeWithOwnedClear } from './totp-clipboard.js';
import { createGeneratePanel, type GeneratePanel } from './generate-fill.js';
import {
  matchRegistrationField,
  findConfirmPasswordFields,
  type DetectedRegistrationField,
} from './registration-detection.js';
import { generatePassword } from '../core/generator/password.js';
import {
  applyGeneratorPolicySnapshot,
  parseGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  type PasswordGeneratorOptions,
} from '../core/generator/enterprise-password-policy.js';
import {
  DEFAULT_PASSPHRASE_OPTIONS,
  generatePassphrase,
} from '../core/generator/passphrase.js';
import { isPageLoadLoginTargetCurrent, selectPageLoadLoginTargetFromSnapshot } from './page-load-fill.js';
import {
  createAutofillDocumentController,
  rootForElement,
  type AutofillDocumentController,
} from './autofill-document-controller.js';
import {
  commitLoginCustomAssignments,
} from './login-custom-fields.js';
import { createStagedFillCommit, type FillTargetRevalidator } from './staged-fill.js';
import { bindTrustedRootCaptureEvent } from './root-event-dispatch.js';
import { collectFieldHints } from './semantic-hints.js';
import type { AutofillDetectionContext } from './autofill-detection-context.js';

type FrameUrlProvider = () => string;

/** The current frame's URL provider and its login-form inspection/commit controller. Both are set
 *  from `startAutofill` and are also used by the runtime listener that answers the background's
 *  current-tab-fill inspect/commit messages. */
let frameUrlProvider: FrameUrlProvider = () => window.location.href;
let frameController: FrameAutofillController | undefined;

const DISABLED_CLIENT_CONFIG: Readonly<AutofillClientConfig> = Object.freeze({
  inlineSuggestions: false,
  pageLoadFill: false,
  saveAllowed: false,
  updateAllowed: false,
  generatorAllowed: false,
  generator: UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
});

interface AutofillRuntime {
  readonly incarnation: string;
  readonly getFrameUrl: FrameUrlProvider;
  pageLoadUrl: string;
  pageLoadOpportunityGeneration: number;
  readonly pageLoadSeenUrls: Set<string>;
  pageLoadOpportunitiesExhausted: boolean;
  config: Readonly<AutofillClientConfig>;
  epoch: number;
  configSequence: number;
  readonly documentController: AutofillDocumentController;
  stopPageListeners: (() => void) | undefined;
  stopCapture: (() => void) | undefined;
  scanTimer: number | undefined;
  contextHealthTimer: number | undefined;
  readonly surfaceTimers: Set<number>;
  saveClaimPromise: Promise<AutofillSaveCaptureWakeResult['status']> | undefined;
  saveClaimRequested: boolean;
  saveClaimTimer: number | undefined;
  pageLoadDeadlineTimer: number | undefined;
  pageLoadDeadlineAt: number;
  pageLoadSpent: boolean;
  previousRuntimeIncarnation: string | undefined;
  activationComplete: boolean;
  activationInFlight: Promise<void> | undefined;
  initializationStarted: boolean;
  readonly focusWaiters: Set<() => void>;
}

let activeRuntime: AutofillRuntime | undefined;
let nextRuntimeEpoch = 0;
let focusedFillQueueGeneration = 0;
let focusedFillQueue: Promise<void> = Promise.resolve();
const focusedFillCycle = new FocusedFillCycle();
let restoredAutofillFocusTargets = new WeakSet<HTMLElement>();
const structuredCandidates = new WeakMap<ReturnType<typeof createAutofillPopover>, ReadonlyMap<string, FillItemCandidate>>();
let dismissStructuredPreview: (() => void) | undefined;
let structuredFillInFlight: { readonly runtime: AutofillRuntime; readonly token: symbol } | undefined;

// The suspended document keeps only navigation metadata and a one-shot hook. The runtime and all
// target, grant, continuation, capture, and surface state are destroyed before this is armed.
interface PendingBfcacheResume {
  readonly view: Window;
  readonly getFrameUrl: FrameUrlProvider;
  readonly retiredRuntimeIncarnation: string;
  readonly onPageShow: (event: PageTransitionEvent) => void;
}

let pendingBfcacheResume: PendingBfcacheResume | undefined;
let replaceableRuntimeIncarnation: string | undefined;

interface PendingInteractiveLoginPlan {
  readonly form: DetectedLoginForm;
  readonly plan: LoginCustomTargetPlan;
}

interface RedeemedInteractiveLoginPlan extends PendingInteractiveLoginPlan {
  readonly assignments: readonly LoginCustomAssignment[];
}

interface ClaimedKeyboardGrant {
  readonly id: string;
  readonly binding: KeyboardAutofillClaimBinding;
}

interface PendingKeyboardReprompt {
  readonly target: Exclude<FocusedTarget, { kind: 'none' }>;
  readonly selection?: FocusedFillCycleSelection;
  readonly runtime: AutofillRuntime | undefined;
  readonly runtimeEpoch: number | undefined;
  readonly queueGeneration: number;
  readonly frameUrl: string;
  readonly expiresAt: number;
  timer: number;
}

const MAX_PENDING_INTERACTIVE_LOGIN_PLANS = 128;
const MAX_PENDING_KEYBOARD_REPROMPTS = 16;
const KEYBOARD_REPROMPT_TTL_MS = 60_000;
const PAGE_LOAD_OPPORTUNITY_MS = 5_000;
const MAX_PAGE_LOAD_URL_OPPORTUNITIES = 32;
const MAX_PAGE_LOAD_URL_LENGTH = 8_192;
const pendingInteractiveLoginPlans = new Map<string, PendingInteractiveLoginPlan>();
let redeemedInteractiveLoginPlans = new WeakMap<AutofillLoginData, RedeemedInteractiveLoginPlan>();
let clientEventAckIds = new WeakMap<object, string>();
let totpCopyAckIds = new WeakMap<object, string>();
const pendingKeyboardReprompts = new Map<string, PendingKeyboardReprompt>();

/** Lazily build (once) the per-frame login-form controller, reading the live frame URL through the
 *  module-level provider so it always reflects the latest same-document navigation. */
function ensureFrameController(): FrameAutofillController {
  if (!frameController) {
    const ownerRuntime = activeRuntime;
    frameController = createFrameAutofillController({
      refresh: () => ownerRuntime?.documentController.refresh() ?? {
        roots: [document],
        visitedElements: 0,
        truncated: false,
      },
      isCurrent: () => ownerRuntime !== undefined
        && activeRuntime === ownerRuntime
        && ownerRuntime.activationComplete,
      frameUrl: () => frameUrlProvider(),
      now: () => Date.now(),
    });
  }
  return frameController;
}

export function startAutofill(frameUrlOrProvider: string | FrameUrlProvider = () => window.location.href): void {
  const previousRuntimeIncarnation = activeRuntime?.incarnation
    ?? pendingBfcacheResume?.retiredRuntimeIncarnation
    ?? replaceableRuntimeIncarnation;
  replaceableRuntimeIncarnation = undefined;
  startAutofillRuntime(frameUrlOrProvider, previousRuntimeIncarnation);
}

function startAutofillRuntime(
  frameUrlOrProvider: string | FrameUrlProvider,
  previousRuntimeIncarnation?: string,
): void {
  cancelPendingBfcacheResume();
  teardownRuntime();
  const getFrameUrl = typeof frameUrlOrProvider === 'function' ? frameUrlOrProvider : () => frameUrlOrProvider;
  frameUrlProvider = getFrameUrl;
  const initialUrl = getFrameUrl();
  if (!isHttpUrl(initialUrl)) return;
  ensureMiyuFonts();
  const runtimeRef: { current?: AutofillRuntime } = {};
  const documentController = createAutofillDocumentController(document, {
    observeInitially: false,
    onChange: () => {
      const current = runtimeRef.current;
      if (
        current
        && (current.config.inlineSuggestions
          || current.config.pageLoadFill
          || popoverRegistry.size > 0
          || totpPanels.size > 0
          || genPanels.size > 0)
      ) scheduleRuntimeScan(current);
    },
  });
  const runtime: AutofillRuntime = {
    incarnation: createRuntimeIncarnation(),
    getFrameUrl,
    pageLoadUrl: initialUrl,
    pageLoadOpportunityGeneration: 0,
    pageLoadSeenUrls: new Set(isBoundedPageLoadUrl(initialUrl) ? [initialUrl] : []),
    pageLoadOpportunitiesExhausted: !isBoundedPageLoadUrl(initialUrl),
    config: DISABLED_CLIENT_CONFIG,
    epoch: ++nextRuntimeEpoch,
    configSequence: 0,
    documentController,
    stopPageListeners: undefined,
    stopCapture: undefined,
    scanTimer: undefined,
    contextHealthTimer: undefined,
    surfaceTimers: new Set(),
    saveClaimPromise: undefined,
    saveClaimRequested: false,
    saveClaimTimer: undefined,
    pageLoadDeadlineTimer: undefined,
    pageLoadDeadlineAt: Date.now() + PAGE_LOAD_OPPORTUNITY_MS,
    pageLoadSpent: !isBoundedPageLoadUrl(initialUrl),
    previousRuntimeIncarnation,
    activationComplete: false,
    activationInFlight: undefined,
    initializationStarted: false,
    focusWaiters: new Set(),
  };
  runtimeRef.current = runtime;
  activeRuntime = runtime;
  frameController = createFrameAutofillController({
    refresh: () => runtime.documentController.refresh(),
    isCurrent: () => activeRuntime === runtime && runtime.activationComplete,
    frameUrl: () => runtime.getFrameUrl(),
    now: () => Date.now(),
  });
  runtime.stopPageListeners = installRuntimePageListeners(runtime);
  runtime.contextHealthTimer = window.setInterval(() => {
    if (activeRuntime !== runtime) return;
    if (!isExtensionContextAlive()) { teardownRuntime(); return; }
    if (!runtime.activationComplete) ensureRuntimeActivation(runtime);
    refreshRuntimeForUrlChange(runtime);
  }, 1_000);
  ensureRuntimeActivation(runtime);
}

export function stopAutofill(): void {
  replaceableRuntimeIncarnation = activeRuntime?.incarnation
    ?? pendingBfcacheResume?.retiredRuntimeIncarnation;
  cancelPendingBfcacheResume();
  teardownRuntime();
}

function cancelPendingBfcacheResume(): void {
  const pending = pendingBfcacheResume;
  pendingBfcacheResume = undefined;
  pending?.view.removeEventListener('pageshow', pending.onPageShow, false);
}

function armBfcacheResume(
  view: Window,
  getFrameUrl: FrameUrlProvider,
  retiredRuntimeIncarnation: string,
): void {
  cancelPendingBfcacheResume();
  const pending: PendingBfcacheResume = {
    view,
    getFrameUrl,
    retiredRuntimeIncarnation,
    onPageShow: (event) => {
      if (pendingBfcacheResume !== pending) return;
      view.removeEventListener('pageshow', pending.onPageShow, false);
      if (!event.persisted || !isExtensionContextAlive()) {
        pendingBfcacheResume = undefined;
        return;
      }
      pendingBfcacheResume = undefined;
      if (isExtensionContextAlive()) {
        startAutofillRuntime(getFrameUrl, pending.retiredRuntimeIncarnation);
      }
    },
  };
  pendingBfcacheResume = pending;
  view.addEventListener('pageshow', pending.onPageShow, { once: true });
}

function teardownRuntime(): void {
  const runtime = activeRuntime;
  if (runtime) {
    runtime.epoch = ++nextRuntimeEpoch;
    for (const settle of runtime.focusWaiters) settle();
    runtime.focusWaiters.clear();
    runtime.stopCapture?.();
    runtime.stopPageListeners?.();
    runtime.documentController.disconnect();
    if (runtime.scanTimer !== undefined) window.clearTimeout(runtime.scanTimer);
    if (runtime.saveClaimTimer !== undefined) window.clearTimeout(runtime.saveClaimTimer);
    if (runtime.pageLoadDeadlineTimer !== undefined) window.clearTimeout(runtime.pageLoadDeadlineTimer);
    if (runtime.contextHealthTimer !== undefined) window.clearInterval(runtime.contextHealthTimer);
    for (const timer of runtime.surfaceTimers) window.clearTimeout(timer);
    runtime.surfaceTimers.clear();
  }
  frameController?.clearStructuredSelection();
  activeRuntime = undefined;
  frameController = undefined;
  clearContextTargets();
  teardownInlineSurfaces();
  teardownSaveSurfaces();
  clearNotice();
  dismissables.clear();
  restoredAutofillFocusTargets = new WeakSet();
  clearCapturedCredentialState();
  resetFocusedFillState();
}

function ensureRuntimeActivation(runtime: AutofillRuntime): void {
  if (activeRuntime !== runtime || runtime.activationComplete || runtime.activationInFlight) return;
  const request = {
    type: 'autofill.activateRuntime' as const,
    runtimeIncarnation: runtime.incarnation,
    ...(runtime.previousRuntimeIncarnation
      ? { previousRuntimeIncarnation: runtime.previousRuntimeIncarnation }
      : {}),
  };
  const operation = Promise.resolve(sendRequest(request)).then((response) => {
    if (activeRuntime !== runtime || !isActiveRuntimeResponse(response)) return;
    runtime.activationComplete = true;
    runtime.previousRuntimeIncarnation = undefined;
    initializeActivatedRuntime(runtime);
  }).catch(() => undefined).finally(() => {
    if (runtime.activationInFlight === operation) runtime.activationInFlight = undefined;
  });
  runtime.activationInFlight = operation;
}

function initializeActivatedRuntime(runtime: AutofillRuntime): void {
  if (activeRuntime !== runtime || !runtime.activationComplete || runtime.initializationStarted) return;
  runtime.initializationStarted = true;
  // Security event bindings must cover every currently accessible root before policy/config awaits.
  runtime.documentController.resumeObservation();
  void claimPendingSavePrompt(runtime);
  void refreshClientConfig(runtime);
}

function isActiveRuntimeResponse(response: unknown): boolean {
  if (!isRecord(response) || response.ok !== true) return false;
  const data: unknown = response.data;
  return isRecord(data)
    && hasOnlyKeys(data, ['status'])
    && data.status === 'active';
}

function createRuntimeIncarnation(): string {
  const value = crypto.randomUUID();
  if (!isRuntimeIncarnation(value)) throw new Error('Could not create an autofill runtime incarnation');
  return value;
}

const AUTOFILL_RUNTIME_BINDING_PROPERTY = '__miyuAutofillRuntimeIncarnation';

function runtimeRequest<Request extends Parameters<typeof sendRequest>[0]>(
  runtime: AutofillRuntime,
  request: Request,
): Request {
  Object.defineProperty(request, AUTOFILL_RUNTIME_BINDING_PROPERTY, {
    value: runtime.incarnation,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return request;
}

function resetFocusedFillState(): void {
  focusedFillCycle.reset();
  pendingInteractiveLoginPlans.clear();
  redeemedInteractiveLoginPlans = new WeakMap();
  clientEventAckIds = new WeakMap();
  totpCopyAckIds = new WeakMap();
  focusedFillQueueGeneration += 1;
  focusedFillQueue = Promise.resolve();
}

async function refreshClientConfig(runtime: AutofillRuntime): Promise<Readonly<AutofillClientConfig>> {
  if (activeRuntime !== runtime) return DISABLED_CLIENT_CONFIG;
  const sequence = ++runtime.configSequence;
  const requestedUrl = runtime.getFrameUrl();
  let response: Awaited<ReturnType<typeof sendRequest>> | undefined;
  try {
    response = await sendRequest(runtimeRequest(runtime, { type: 'autofill.getClientConfig' }));
  } catch {
    // Treat transport loss exactly like an explicit disabled response.
  }
  if (activeRuntime === runtime && response && !response.ok && response.error.code === 'denied') {
    runtime.activationComplete = false;
    runtime.initializationStarted = false;
    ensureRuntimeActivation(runtime);
  }
  if (activeRuntime !== runtime || sequence !== runtime.configSequence || runtime.getFrameUrl() !== requestedUrl) {
    return DISABLED_CLIENT_CONFIG;
  }
  const next = response?.ok ? parseClientConfig(response.data) : undefined;
  runtime.config = next ?? DISABLED_CLIENT_CONFIG;
  if (!runtime.config.pageLoadFill) spendPageLoadOpportunity(runtime);
  applyClientConfig(runtime);
  return runtime.config;
}

function applyClientConfig(runtime: AutofillRuntime): void {
  if (activeRuntime !== runtime) return;
  reconcileSaveCapture(runtime);
  // Context-menu targets and focused-form ranking remain available even when inline UI and save
  // capture are disabled, so every accessible root needs the controller's incremental inventory.
  runtime.documentController.resumeObservation();
  if (!runtime.config.inlineSuggestions) teardownInlineSurfaces();
  if (!runtime.config.generatorAllowed) teardownGeneratorSurfaces();
  if (!runtime.config.saveAllowed && !runtime.config.updateAllowed) teardownSavePromptSurfaces();
  else void claimPendingSavePrompt(runtime);
  if (runtime.config.pageLoadFill) armPageLoadDeadline(runtime);
  if (runtime.config.inlineSuggestions) attachPopovers(runtime.getFrameUrl);
  if (runtime.config.pageLoadFill) void attemptPageLoadFill(runtime);
  if (runtime.config.generatorAllowed) {
    const focused = runtime.documentController.deepActiveElement();
    if (focused instanceof HTMLInputElement) maybeAttachGeneratePanel(focused);
  }
}

function reconcileSaveCapture(runtime: AutofillRuntime): void {
  const enabled = runtime.activationComplete
    && (runtime.config.saveAllowed || runtime.config.updateAllowed);
  if (!enabled) {
    runtime.stopCapture?.();
    runtime.stopCapture = undefined;
    return;
  }
  runtime.stopCapture ??= startSaveCapture(
    (login, submission) => captureSubmission(runtime, login, submission),
    runtime.documentController,
    (submitted) => captureSubmission(runtime, submitted),
  );
}

function scheduleRuntimeScan(runtime: AutofillRuntime): void {
  if (activeRuntime !== runtime || runtime.scanTimer !== undefined) return;
  runtime.scanTimer = window.setTimeout(() => {
    runtime.scanTimer = undefined;
    if (activeRuntime !== runtime) return;
    if (!isExtensionContextAlive()) { teardownRuntime(); return; }
    if (refreshRuntimeForUrlChange(runtime)) return;
    pruneDetachedSurfaces();
    if (runtime.config.inlineSuggestions) attachPopovers(runtime.getFrameUrl);
    if (runtime.config.pageLoadFill) void attemptPageLoadFill(runtime);
  }, 100);
}

function scheduleRuntimeTimeout(runtime: AutofillRuntime, callback: () => void, delayMs: number): void {
  if (activeRuntime !== runtime) return;
  const timer = window.setTimeout(() => {
    runtime.surfaceTimers.delete(timer);
    if (activeRuntime === runtime) callback();
  }, delayMs);
  runtime.surfaceTimers.add(timer);
}

function installRuntimePageListeners(runtime: AutofillRuntime): () => void {
  const ownerDocument = runtime.documentController.ownerDocument;
  const stopContextMenu = bindTrustedRootCaptureEvent(
    runtime.documentController,
    'contextmenu',
    (target) => {
      if (activeRuntime === runtime && runtime.activationComplete) handleTrustedContextMenu(target);
    },
  );
  const stopFocus = bindTrustedRootCaptureEvent(
    runtime.documentController,
    'focusin',
    (target) => {
      if (activeRuntime === runtime && runtime.activationComplete) handleTrustedFocus(target);
    },
  );
  const stopPointerDown = bindTrustedRootCaptureEvent(
    runtime.documentController,
    'pointerdown',
    (target) => {
      if (activeRuntime === runtime && runtime.activationComplete) handleTrustedPointerDown(target);
    },
  );
  const onWindowMessage = (event: MessageEvent): void => {
    if (activeRuntime === runtime) relayFido2FallbackMessage(event);
  };
  const onPageHide = (event: PageTransitionEvent): void => {
    if (activeRuntime !== runtime) return;
    const shouldResume = event.persisted;
    const resumeGetFrameUrl = runtime.getFrameUrl;
    const retiredRuntimeIncarnation = runtime.incarnation;
    teardownRuntime();
    if (shouldResume && view) {
      armBfcacheResume(view, resumeGetFrameUrl, retiredRuntimeIncarnation);
    }
  };
  const onSameDocumentNavigation = (): void => {
    if (activeRuntime === runtime) refreshRuntimeForUrlChange(runtime);
  };
  const onKeyDown = (event: KeyboardEvent): void => {
    if (activeRuntime !== runtime || !event.isTrusted || event.defaultPrevented || event.key !== 'Escape') return;
    if (dismissables.size === 0) return;
    event.preventDefault();
    dismissOtherSurfaces();
  };
  const view = ownerDocument.defaultView;
  view?.addEventListener('message', onWindowMessage, false);
  view?.addEventListener('pagehide', onPageHide, { once: true });
  view?.addEventListener('popstate', onSameDocumentNavigation, false);
  view?.addEventListener('hashchange', onSameDocumentNavigation, false);
  ownerDocument.addEventListener('keydown', onKeyDown, false);
  return () => {
    stopContextMenu();
    stopFocus();
    stopPointerDown();
    view?.removeEventListener('message', onWindowMessage, false);
    view?.removeEventListener('pagehide', onPageHide, false);
    view?.removeEventListener('popstate', onSameDocumentNavigation, false);
    view?.removeEventListener('hashchange', onSameDocumentNavigation, false);
    ownerDocument.removeEventListener('keydown', onKeyDown, false);
  };
}

function invalidateClientRuntime(): void {
  const runtime = activeRuntime;
  if (!runtime) return;
  runtime.activationComplete = false;
  runtime.initializationStarted = false;
  invalidateRuntime(runtime);
  ensureRuntimeActivation(runtime);
}

function invalidateRuntime(runtime: AutofillRuntime): void {
  if (activeRuntime !== runtime) return;
  runtime.epoch = ++nextRuntimeEpoch;
  focusedFillCycle.reset();
  runtime.configSequence += 1;
  runtime.config = DISABLED_CLIENT_CONFIG;
  runtime.documentController.pauseObservation();
  if (runtime.scanTimer !== undefined) window.clearTimeout(runtime.scanTimer);
  runtime.scanTimer = undefined;
  teardownInlineSurfaces();
  teardownSaveSurfaces();
  clearCapturedCredentialState();
  if (runtime.activationComplete) void refreshClientConfig(runtime);
}

function refreshRuntimeForUrlChange(runtime: AutofillRuntime): boolean {
  if (activeRuntime !== runtime) return false;
  const nextUrl = runtime.getFrameUrl();
  if (nextUrl === runtime.pageLoadUrl) return false;

  runtime.pageLoadUrl = nextUrl;
  runtime.pageLoadOpportunityGeneration += 1;
  clearPageLoadDeadline(runtime);
  if (
    runtime.pageLoadOpportunitiesExhausted
    || !isBoundedPageLoadUrl(nextUrl)
    || runtime.pageLoadSeenUrls.has(nextUrl)
    || runtime.pageLoadSeenUrls.size >= MAX_PAGE_LOAD_URL_OPPORTUNITIES
  ) {
    runtime.pageLoadSpent = true;
    runtime.pageLoadOpportunitiesExhausted ||= (
      runtime.pageLoadSeenUrls.size >= MAX_PAGE_LOAD_URL_OPPORTUNITIES
    );
    runtime.pageLoadDeadlineAt = Date.now();
  } else {
    runtime.pageLoadSeenUrls.add(nextUrl);
    runtime.pageLoadSpent = false;
    runtime.pageLoadDeadlineAt = Date.now() + PAGE_LOAD_OPPORTUNITY_MS;
  }
  runtime.activationComplete = false;
  runtime.initializationStarted = false;
  invalidateRuntime(runtime);
  ensureRuntimeActivation(runtime);
  return true;
}

function isBoundedPageLoadUrl(value: string): boolean {
  return value.length > 0 && value.length <= MAX_PAGE_LOAD_URL_LENGTH && isHttpUrl(value);
}

function clearPageLoadDeadline(runtime: AutofillRuntime): void {
  if (runtime.pageLoadDeadlineTimer !== undefined) window.clearTimeout(runtime.pageLoadDeadlineTimer);
  runtime.pageLoadDeadlineTimer = undefined;
}

function spendPageLoadOpportunity(runtime: AutofillRuntime): void {
  runtime.pageLoadSpent = true;
  clearPageLoadDeadline(runtime);
}

function armPageLoadDeadline(runtime: AutofillRuntime): void {
  if (runtime.pageLoadSpent || runtime.pageLoadDeadlineTimer !== undefined) return;
  const remaining = runtime.pageLoadDeadlineAt - Date.now();
  if (remaining <= 0) {
    spendPageLoadOpportunity(runtime);
    return;
  }
  const generation = runtime.pageLoadOpportunityGeneration;
  const url = runtime.pageLoadUrl;
  runtime.pageLoadDeadlineTimer = window.setTimeout(() => {
    runtime.pageLoadDeadlineTimer = undefined;
    if (
      activeRuntime === runtime
      && runtime.pageLoadOpportunityGeneration === generation
      && runtime.pageLoadUrl === url
    ) runtime.pageLoadSpent = true;
  }, remaining);
}

function parseClientConfig(value: unknown): AutofillClientConfig | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, [
    'inlineSuggestions', 'pageLoadFill', 'saveAllowed', 'updateAllowed', 'generatorAllowed', 'generator',
  ])) return undefined;
  const generator = parseGeneratorPolicySnapshot(value.generator);
  return typeof value.inlineSuggestions === 'boolean'
    && typeof value.pageLoadFill === 'boolean'
    && typeof value.saveAllowed === 'boolean'
    && typeof value.updateAllowed === 'boolean'
    && typeof value.generatorAllowed === 'boolean'
    && generator !== null
    ? {
        inlineSuggestions: value.inlineSuggestions,
        pageLoadFill: value.pageLoadFill,
        saveAllowed: value.saveAllowed,
        updateAllowed: value.updateAllowed,
        generatorAllowed: value.generatorAllowed,
        generator,
      }
    : undefined;
}

async function attemptPageLoadFill(runtime: AutofillRuntime): Promise<void> {
  if (refreshRuntimeForUrlChange(runtime)) return;
  if (
    activeRuntime !== runtime
    || runtime.pageLoadSpent
    || !runtime.config.pageLoadFill
    || Date.now() >= runtime.pageLoadDeadlineAt
  ) {
    if (Date.now() >= runtime.pageLoadDeadlineAt) spendPageLoadOpportunity(runtime);
    return;
  }
  const snapshot = runtime.documentController.refresh();
  if (snapshot.truncated) {
    spendPageLoadOpportunity(runtime);
    return;
  }
  const target = selectPageLoadLoginTargetFromSnapshot(snapshot, document);
  if (!target) return;

  const epoch = runtime.epoch;
  const opportunityGeneration = runtime.pageLoadOpportunityGeneration;
  const frameUrl = runtime.pageLoadUrl;
  spendPageLoadOpportunity(runtime);
  const issued = await sendRequest(runtimeRequest(runtime, { type: 'autofill.issuePageLoadIntent' }));
  if (refreshRuntimeForUrlChange(runtime)) return;
  if (runtime.epoch !== epoch || runtime.pageLoadOpportunityGeneration !== opportunityGeneration) return;
  const issueData: unknown = issued.ok ? issued.data : undefined;
  if (!isRecord(issueData) || !hasOnlyKeys(issueData, ['intentId']) || typeof issueData.intentId !== 'string') return;
  const redeemed = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.redeemPageLoadIntent',
    intentId: issueData.intentId,
  }));
  if (refreshRuntimeForUrlChange(runtime)) return;
  const responseData: unknown = redeemed.ok ? redeemed.data : undefined;
  if (
    !isRecord(responseData)
    || !hasOnlyKeys(responseData, ['login', 'clientEventAckId', 'totpCopyAckId'])
    || !isAutofillLoginData(responseData.login)
    || !isOptionalClientEventAckId(responseData.clientEventAckId)
    || !isOptionalClientEventAckId(responseData.totpCopyAckId)
  ) return;
  if (
    activeRuntime !== runtime
    || runtime.epoch !== epoch
    || runtime.pageLoadOpportunityGeneration !== opportunityGeneration
    || runtime.pageLoadUrl !== frameUrl
    || !runtime.config.pageLoadFill
    || runtime.getFrameUrl() !== frameUrl
    || !isPageLoadLoginTargetCurrent(target, runtime.documentController.refresh(), document)
  ) return;

  const login = responseData.login;
  rememberClientEventAck(login, responseData.clientEventAckId);
  rememberTotpCopyAck(login, responseData.totpCopyAckId);
  let usernameWritten = false;
  let passwordWritten = false;
  const staged = createStagedFillCommit(() => (
    activeRuntime === runtime
    && runtime.epoch === epoch
    && runtime.pageLoadOpportunityGeneration === opportunityGeneration
    && runtime.pageLoadUrl === frameUrl
    && runtime.config.pageLoadFill
    && runtime.getFrameUrl() === frameUrl
    && isPageLoadLoginTargetCurrent(target, runtime.documentController.refresh(), document, {
      allowUsernameValue: usernameWritten,
      allowPasswordValue: passwordWritten,
    })
  ));
  if (login.username && target.usernameInput) {
    const username = login.username;
    if (staged.write(() => {
      usernameWritten = true;
      setInputValue(target.usernameInput!, username);
      return true;
    })) flashFill(target.usernameInput);
  }
  if (staged.stale || !staged.isCurrent()) return;
  if (login.password) {
    const password = login.password;
    if (staged.write(() => {
      passwordWritten = true;
      setInputValue(target.passwordInput, password);
      return true;
    })) flashFill(target.passwordInput, 130);
  }
  settleClientEventAck(login, (usernameWritten || passwordWritten) && !staged.stale && staged.isCurrent());
}

const saveBars = new Set<SaveBar>();
const activeSavePromptIds = new Set<string>();

function clearCapturedCredentialState(): void {
  activeSavePromptIds.clear();
  generatedSaveAttempts.clear();
}

function captureSubmission(
  runtime: AutofillRuntime,
  submitted: CapturedLogin | CapturedUsername,
  submission?: AutofillSaveCaptureSubmission,
): void {
  if (activeRuntime !== runtime
      || !runtime.activationComplete
      || (!runtime.config.saveAllowed && !runtime.config.updateAllowed)
      || !isHttpUrl(runtime.getFrameUrl())) return;
  // This call intentionally starts inside the trusted event stack. The worker re-authorizes every
  // capture, so an asynchronous client-config refresh must never sit in front of persistence.
  const request = 'password' in submitted
    ? {
        type: 'autofill.captureSubmission' as const,
        ...(submitted.username ? { username: submitted.username } : {}),
        password: submitted.password,
        ...(submission ? { submission } : {}),
      }
    : { type: 'autofill.captureSubmission' as const, username: submitted.username };
  void sendRequest(runtimeRequest(runtime, request)).then(() => {
    if (activeRuntime === runtime) void claimPendingSavePrompt(runtime);
  }).catch(() => undefined);
}

function claimPendingSavePrompt(runtime: AutofillRuntime): Promise<AutofillSaveCaptureWakeResult['status']> {
  if (activeRuntime !== runtime || !runtime.activationComplete || !isHttpUrl(runtime.getFrameUrl())) {
    return Promise.resolve('not_ready');
  }
  runtime.saveClaimRequested = true;
  if (runtime.saveClaimPromise) return runtime.saveClaimPromise;
  const operation = drainPendingSaveClaims(runtime).finally(() => {
    if (runtime.saveClaimPromise === operation) runtime.saveClaimPromise = undefined;
    if (activeRuntime === runtime && runtime.saveClaimRequested) {
      void claimPendingSavePrompt(runtime);
    }
  });
  runtime.saveClaimPromise = operation;
  return operation;
}

async function drainPendingSaveClaims(
  runtime: AutofillRuntime,
): Promise<AutofillSaveCaptureWakeResult['status']> {
  let result: AutofillSaveCaptureWakeResult['status'] = 'not_ready';
  while (activeRuntime === runtime && runtime.saveClaimRequested) {
    runtime.saveClaimRequested = false;
    const current = await claimPendingSavePromptOnce(runtime);
    if (current === 'displayed') result = 'displayed';
    else if (current === 'not_displayed' && result === 'not_ready') result = 'not_displayed';
  }
  return result;
}

async function claimPendingSavePromptOnce(
  runtime: AutofillRuntime,
  captureId?: string,
): Promise<AutofillSaveCaptureWakeResult['status']> {
  if (activeRuntime !== runtime || !isHttpUrl(runtime.getFrameUrl())) return 'not_ready';
  const requestedOrigin = httpOrigin(runtime.getFrameUrl());
  const response = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.claimSavePrompt',
    ...(captureId ? { captureId } : {}),
  }));
  if (
    activeRuntime !== runtime
    || requestedOrigin === undefined
    || httpOrigin(runtime.getFrameUrl()) !== requestedOrigin
    || !response?.ok
    || !isSaveLoginPrompt(response.data)
  ) return 'not_ready';
  const prompt = response.data;
  if (prompt.action === 'none') {
    if (prompt.retryAfterMs !== undefined && runtime.saveClaimTimer === undefined) {
      runtime.saveClaimTimer = window.setTimeout(() => {
        runtime.saveClaimTimer = undefined;
        if (activeRuntime === runtime) void claimPendingSavePrompt(runtime);
      }, prompt.retryAfterMs);
    }
    return 'not_displayed';
  }
  return showSaveBar(runtime, prompt) ? 'displayed' : 'not_ready';
}

function showSaveBar(
  runtime: AutofillRuntime,
  prompt: Exclude<AutofillSavePrompt, { action: 'none' }>,
): boolean {
  if (activeRuntime !== runtime) return false;
  if (activeSavePromptIds.has(prompt.promptId)) return true;
  activeSavePromptIds.add(prompt.promptId);
  const onDismiss = (): void => {
    activeSavePromptIds.delete(prompt.promptId);
    void sendRequest(runtimeRequest(runtime, {
      type: 'autofill.dismissSavePrompt',
      promptId: prompt.promptId,
    }));
  };
  const commit = async (): Promise<boolean> => {
    const response = await sendRequest(runtimeRequest(runtime, {
      type: 'autofill.commitSavePrompt',
      promptId: prompt.promptId,
    }));
    if (response.ok) activeSavePromptIds.delete(prompt.promptId);
    return response.ok;
  };
  if (prompt.action === 'save') {
    saveBars.add(createSaveBar({
      message: `在密屿中保存“${prompt.suggestedName}”的登录？`,
      actionLabel: '保存',
      onAction: commit,
      onDismiss,
    }));
  } else if (prompt.action === 'update') {
    saveBars.add(createSaveBar({
      message: `更新“${prompt.name}”的已保存密码？`,
      actionLabel: '更新',
      onAction: commit,
      successMessage: '已更新密屿中的密码',
      onDismiss,
    }));
  } else {
    saveBars.add(createSaveBar({
      message: `将此网站添加到“${prompt.name}”？`,
      actionLabel: '添加网站',
      onAction: commit,
      successMessage: '已将此网站添加到密屿',
      onDismiss,
    }));
  }
  return true;
}

function isSaveLoginPrompt(data: unknown): data is AutofillSavePrompt {
  if (!isRecord(data)) return false;
  if (data.action === 'none') {
    return (hasOnlyKeys(data, ['action']) || hasOnlyKeys(data, ['action', 'retryAfterMs']))
      && (data.retryAfterMs === undefined
        || (Number.isSafeInteger(data.retryAfterMs) && (data.retryAfterMs as number) > 0
          && (data.retryAfterMs as number) <= 60_000));
  }
  if (data.action === 'save') {
    return hasOnlyKeys(data, ['action', 'promptId', 'suggestedName'])
      && isUuidV4(data.promptId)
      && typeof data.suggestedName === 'string';
  }
  return (data.action === 'update' || data.action === 'addUri')
    && hasOnlyKeys(data, ['action', 'promptId', 'name'])
    && isUuidV4(data.promptId)
    && typeof data.name === 'string';
}

function httpOrigin(frameUrl: string): string | undefined {
  try {
    const url = new URL(frameUrl);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

function isUuidV4(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isRuntimeIncarnation(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

function attachPopovers(getFrameUrl: FrameUrlProvider): void {
  const runtime = activeRuntime;
  if (!runtime?.config.inlineSuggestions) return;
  if (!isExtensionContextAlive()) return; // orphaned after an extension reload — stay dormant
  if (!isHttpUrl(getFrameUrl())) return;
  const projection = computeFillProjection(runtime.documentController.snapshot());
  if (!projection.complete) return;
  for (const form of projection.loginForms) {
    if (!hasLoginCredentialTarget(form)) continue;
    attachIfNew(form.id, () => attachPopover(getFrameUrl, form));
  }
  for (const form of projection.cardForms) {
    attachIfNew(form.id, () => attachStructuredPopover(getFrameUrl, form));
  }
  for (const form of projection.identityForms) {
    attachIfNew(form.id, () => attachStructuredPopover(getFrameUrl, form));
  }
}

function attachIfNew(id: string, attach: () => void): void {
  const existing = popoverRegistry.get(id);
  if (existing?.element.isConnected) return;
  if (existing) {
    unregisterDismissable(existing.element);
    releaseAutofillSurface(existing);
    existing.remove();
    popoverRegistry.delete(id);
    popoverAnchors.delete(id);
    popoverKinds.delete(id);
  }
  attach();
}

function attachPopover(getFrameUrl: FrameUrlProvider, form: DetectedLoginForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    sidePanel: true,
    beforeFocusRestore: registerAutofillFocusRestore,
    onOpen: () => {
      void loadCandidates(popover);
    },
    onSelect: (cipherId) => {
      void fillSelected(getFrameUrl, form, cipherId, popover);
    },
    onDismiss: () => {
      releaseAutofillSurface(popover);
      unregisterDismissable(popover.element);
    },
  });
  popover.element.dataset.vwPopoverFor = form.id;
  popoverRegistry.set(form.id, popover);
  popoverAnchors.set(form.id, form.anchor);
  popoverKinds.set(form.id, 'login');
}

function attachStructuredPopover(getFrameUrl: FrameUrlProvider, form: DetectedFillForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    kind: form.kind,
    beforeFocusRestore: registerAutofillFocusRestore,
    onOpen: () => {
      void loadStructuredCandidates(form.kind, popover);
    },
    onSelect: (cipherId) => {
      void fillStructuredSelected(getFrameUrl, form, cipherId, popover);
    },
    onDismiss: () => {
      releaseAutofillSurface(popover);
      unregisterDismissable(popover.element);
    },
  });
  popoverRegistry.set(form.id, popover);
  popoverAnchors.set(form.id, form.anchor);
  popoverKinds.set(form.id, form.kind);
}

async function loadCandidates(
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const runtime = activeRuntime;
  if (!runtime) return;
  const config = await refreshClientConfig(runtime);
  if (activeRuntime !== runtime || !config.inlineSuggestions || !popover.element.isConnected) {
    releaseAutofillSurface(popover);
    popover.remove();
    return;
  }
  const epoch = runtime.epoch;
  const response = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.findCandidates',
    purpose: 'login',
  }));
  if (activeRuntime !== runtime || runtime.epoch !== epoch || !runtime.config.inlineSuggestions || !popover.element.isConnected) return;
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (Array.isArray(response.data) && isAutofillCandidates(response.data)) {
    popover.showCandidates(response.data.map((c) => ({
      id: c.id, name: c.name, favorite: c.favorite,
      ...(c.username ?? c.matchedUri ? { sub: c.username ?? c.matchedUri } : {}),
      ...(c.reprompt ? { reprompt: true } : {}),
    })));
  } else {
    popover.showStatus('Unexpected autofill response');
  }
}

async function fillSelected(
  getFrameUrl: FrameUrlProvider,
  form: DetectedLoginForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const runtime = activeRuntime;
  if (!runtime) return;
  const config = await refreshClientConfig(runtime);
  if (activeRuntime !== runtime || !config.inlineSuggestions || !popover.element.isConnected) return;
  const epoch = runtime.epoch;
  if (!isCurrentLoginForm(runtime, form)) {
    popover.showStatus('Form is no longer available');
    return;
  }
  const frameUrl = getFrameUrl();
  const login = await requestLoginData(runtime, cipherId, form);
  if (
    activeRuntime !== runtime
    || runtime.epoch !== epoch
    || !runtime.config.inlineSuggestions
    || !isCurrentLoginForm(runtime, form)
  ) return;
  if (!login.ok) {
    popover.showStatus(login.message);
    return;
  }
  if (getFrameUrl() !== frameUrl) {
    popover.showStatus('Page changed before autofill');
    return;
  }
  const expectedRoot = form.anchor.getRootNode();
  const filled = fillInteractiveLogin(form, login.data, () => (
    activeRuntime === runtime
    && runtime.epoch === epoch
    && runtime.config.inlineSuggestions
    && getFrameUrl() === frameUrl
    && form.anchor.getRootNode() === expectedRoot
    && isCurrentLoginForm(runtime, form)
  ));
  settleClientEventAck(login.data, filled);
  if (filled) {
    const receiptCurrent = popover.showFilled();
    // Show the filled confirmation briefly, then dismiss the panel.
    scheduleRuntimeTimeout(runtime, () => {
      if (receiptCurrent && !receiptCurrent()) return;
      releaseAutofillSurface(popover);
      popover.hide();
      unregisterDismissable(popover.element);
    }, FILLED_DISMISS_MS);
  } else {
    popover.showStatus('No fillable fields');
  }
}

async function loadStructuredCandidates(
  kind: 'card' | 'identity',
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const runtime = activeRuntime;
  if (!runtime) return;
  const config = await refreshClientConfig(runtime);
  if (activeRuntime !== runtime || !config.inlineSuggestions || !popover.element.isConnected) {
    releaseAutofillSurface(popover);
    popover.remove();
    return;
  }
  const epoch = runtime.epoch;
  const response = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.findStructuredCandidates',
    kind,
  }));
  if (activeRuntime !== runtime || runtime.epoch !== epoch || !runtime.config.inlineSuggestions || !popover.element.isConnected) return;
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (!Array.isArray(response.data) || !isFillItemCandidates(response.data)) {
    popover.showStatus('Unexpected autofill response');
    return;
  }
  structuredCandidates.set(popover, new Map(response.data.map((candidate) => [candidate.id, candidate])));
  popover.showCandidates(response.data.map((candidate) => ({
    id: candidate.id,
    name: candidate.name,
    favorite: candidate.favorite,
    ...(candidate.subtitle ? { sub: candidate.subtitle } : {}),
    ...(candidate.reprompt ? { reprompt: true } : {}),
  })));
}

async function fillStructuredSelected(
  getFrameUrl: FrameUrlProvider,
  form: DetectedFillForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const runtime = activeRuntime;
  if (!runtime) return;
  if (structuredFillInFlight?.runtime === runtime) {
    popover.showStatus('正在处理填充，请稍后重试。');
    return;
  }
  const config = await refreshClientConfig(runtime);
  if (activeRuntime !== runtime || !config.inlineSuggestions || !popover.element.isConnected) return;
  const epoch = runtime.epoch;
  const frameUrl = getFrameUrl();
  if (!isCurrentStructuredForm(runtime, form)) {
    popover.showStatus('Form is no longer available');
    return;
  }
  const target = captureStructuredTarget(form);
  const candidate = structuredCandidates.get(popover)?.get(cipherId);
  if (!target || !candidate) return;
  const values = new Map([...form.fields].map(([role, field]) => [role, { field, value: field.value }]));
  dismissStructuredPreview?.();
  releaseAutofillSurface(popover);
  popover.hide();
  unregisterDismissable(popover.element);
  const scope = inlineSurfaceScope(form.anchor);
  const current = (): boolean => activeRuntime === runtime && runtime.epoch === epoch
    && runtime.config.inlineSuggestions && getFrameUrl() === frameUrl && isCurrentStructuredForm(runtime, form);
  const close = (): void => {
    if (dismissStructuredPreview === close) {
      dismissStructuredPreview = undefined;
      frameController?.clearStructuredSelection();
    }
    unregisterDismissable(preview.element);
    releaseInlineSurface(scope, preview.element);
    preview.remove();
  };
  const preview = createStructuredPreview({
    anchor: form.anchor,
    kind: form.kind,
    itemName: candidate.name,
    site: new URL(frameUrl).hostname,
    fields: target.roles.map((role) => ({ role, hasValue: values.get(role)!.value.trim().length > 0 })),
    onDismiss: close,
    onConfirm: (roles) => {
      if (structuredFillInFlight?.runtime === runtime) {
        preview.showError('正在处理填充，请稍后重试。');
        return;
      }
      const flight = { runtime, token: Symbol('structured-fill') };
      structuredFillInFlight = flight;
      void (async () => {
        try {
          if (!current() || dismissStructuredPreview !== close || roles.some((role) => {
            const captured = values.get(role);
            return !captured || captured.field.value !== captured.value;
          })) {
            preview.showError('表单内容已变化，请关闭并重新选择字段。');
            return;
          }
          const outcome = await requestStructuredFill(runtime, cipherId, form, undefined, { roles, target });
          if (!current() || !preview.element.isConnected) { close(); return; }
          if (!outcome.ok) { preview.showError(outcome.message); return; }
          const receipt = ensureFrameController().takeStructuredUndo();
          if (receipt) preview.showReceipt(receipt);
          else preview.showError('填充状态已变化，请检查表单内容。');
          positionStructuredPreview(preview.element, form.anchor);
        } catch {
          if (preview.element.isConnected) preview.showError('暂时无法填充，请关闭后重试。');
        } finally {
          if (dismissStructuredPreview === close) frameController?.clearStructuredSelection();
          if (structuredFillInFlight === flight) structuredFillInFlight = undefined;
        }
      })();
    },
  });
  dismissStructuredPreview = close;
  if (!claimInlineSurface(scope, preview.element, close, 1)) { close(); return; }
  dismissOtherSurfaces(preview.element);
  registerDismissable(preview.element, form.anchor.closest('form') ?? form.anchor, close);
  positionStructuredPreview(preview.element, form.anchor);
}

function isAutofillCandidates(data: unknown[]): data is AutofillCandidate[] {
  return data.every(isAutofillCandidate);
}

function isAutofillCandidate(data: unknown): data is AutofillCandidate {
  if (!isRecord(data)) return false;
  return (
    typeof data.id === 'string'
    && typeof data.name === 'string'
    && isOptionalString(data.username)
    && typeof data.matchedUri === 'string'
    && isUriMatchStrategySetting(data.matchType)
    && typeof data.favorite === 'boolean'
    && (data.hasTotp === undefined || typeof data.hasTotp === 'boolean')
  );
}

function isFillItemCandidates(data: unknown[]): data is FillItemCandidate[] {
  return data.every((candidate) => (
    isRecord(candidate)
    && hasOnlyKeys(candidate, ['id', 'name', 'subtitle', 'favorite', 'reprompt'])
    && typeof candidate.id === 'string'
    && typeof candidate.name === 'string'
    && isOptionalString(candidate.subtitle)
    && typeof candidate.favorite === 'boolean'
    && (candidate.reprompt === undefined || typeof candidate.reprompt === 'boolean')
  ));
}

type IntentOutcome<T> =
  | { ok: true; data: T }
  | { ok: false; message: string; repromptContinuationId?: string };

function keyboardClaimBinding(
  runtime: AutofillRuntime,
  target: FocusedTarget,
): KeyboardAutofillClaimBinding | undefined {
  if (target.kind === 'login') {
    const current = boundedLoginCustomPlan(runtime, target.form);
    return current ? { purpose: target.kind, customPlan: current.plan } : undefined;
  }
  if (target.kind === 'totp') return { purpose: target.kind };
  if (target.kind === 'card' || target.kind === 'identity') {
    const structuredTarget = captureStructuredTarget(target.form);
    return structuredTarget ? { purpose: target.kind, structuredTarget } : undefined;
  }
  return undefined;
}

async function claimKeyboardGrant(
  runtime: AutofillRuntime,
  commandToken: string,
  target: FocusedTarget,
): Promise<IntentOutcome<ClaimedKeyboardGrant>> {
  const binding = keyboardClaimBinding(runtime, target);
  if (!binding) return { ok: false, message: 'Autofill target changed' };
  const response = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.claimKeyboardGrant',
    commandToken,
    binding,
  }));
  if (!response.ok) return { ok: false, message: messageForError(response.error.code, response.error.message) };
  const data: unknown = response.data;
  if (
    !isRecord(data)
    || !hasOnlyKeys(data, ['keyboardGrantId'])
    || !isReservationId(data.keyboardGrantId)
  ) return { ok: false, message: 'Unexpected autofill response' };
  return { ok: true, data: { id: data.keyboardGrantId, binding } };
}

async function issueIntent(
  runtime: AutofillRuntime,
  cipherId: string,
  purpose: AutofillIntentPurpose,
  form?: DetectedLoginForm,
  keyboard?: ClaimedKeyboardGrant,
): Promise<IntentOutcome<string>> {
  let binding: PendingInteractiveLoginPlan | undefined;
  const request = keyboard
    ? (() => {
        if (keyboard.binding.purpose !== purpose) return undefined;
        if (purpose === 'login') {
          if (!form || !hasLoginCredentialTarget(form) || keyboard.binding.purpose !== 'login') {
            return undefined;
          }
          const current = boundedLoginCustomPlan(runtime, form);
          if (!current || JSON.stringify(current.plan) !== JSON.stringify(keyboard.binding.customPlan)) return undefined;
          binding = current;
        }
        return {
          type: 'autofill.keyboard.issueIntent' as const,
          keyboardGrantId: keyboard.id,
          cipherId,
        };
      })()
    : purpose === 'login'
    ? (() => {
        if (!form || !hasLoginCredentialTarget(form)) return undefined;
        const current = boundedLoginCustomPlan(runtime, form);
        if (!current) return undefined;
        binding = current;
        return {
          type: 'autofill.issueIntent' as const,
          cipherId,
          purpose,
          customPlan: current.plan,
        };
      })()
    : { type: 'autofill.issueIntent' as const, cipherId, purpose };
  if (!request) return { ok: false, message: 'Autofill target changed' };
  const response = await sendRequest(runtimeRequest(runtime, request));
  if (!response.ok) return { ok: false, message: messageForError(response.error.code, response.error.message) };
  const data: unknown = response.data;
  if (isRecord(data)
      && hasOnlyKeys(data, ['repromptContinuationId'])
      && isReservationId(data.repromptContinuationId)) {
    return {
      ok: false,
      message: 'Protected item — open the extension to verify',
      repromptContinuationId: data.repromptContinuationId,
    };
  }
  if (!isRecord(data) || !hasOnlyKeys(data, ['intentId']) || typeof data.intentId !== 'string') {
    return { ok: false, message: 'Unexpected autofill response' };
  }
  if (binding) rememberPendingInteractivePlan(data.intentId, binding);
  return { ok: true, data: data.intentId };
}

async function requestLoginData(
  runtime: AutofillRuntime,
  cipherId: string,
  form: DetectedLoginForm,
): Promise<IntentOutcome<AutofillLoginData>> {
  const intent = await issueIntent(runtime, cipherId, 'login', form);
  if (!intent.ok) return intent;
  return redeemLoginIntent(runtime, intent.data);
}

async function redeemLoginIntent(
  runtime: AutofillRuntime,
  intentId: string,
  keyboard = false,
): Promise<IntentOutcome<AutofillLoginData>> {
  const binding = pendingInteractiveLoginPlans.get(intentId);
  pendingInteractiveLoginPlans.delete(intentId);
  if (!binding) return { ok: false, message: 'Autofill target changed' };
  const response = await sendRequest(runtimeRequest(runtime, keyboard
    ? { type: 'autofill.keyboard.redeemLoginIntent', intentId }
    : { type: 'autofill.redeemLoginIntent', intentId }));
  if (!response.ok) return { ok: false, message: messageForError(response.error.code, response.error.message) };
  const data: unknown = response.data;
  const assignments = isRecord(data)
    ? data.customAssignments === undefined ? [] : parseLoginCustomAssignments(data.customAssignments)
    : undefined;
  if (!isRecord(data)
      || !hasOnlyKeys(data, ['login', 'customAssignments', 'clientEventAckId', 'totpCopyAckId'])
      || !isAutofillLoginData(data.login)
      || !isOptionalClientEventAckId(data.clientEventAckId)
      || !isOptionalClientEventAckId(data.totpCopyAckId)
      || !assignments
      || !assignmentsBelongToPlan(assignments, binding.plan)) {
    return { ok: false, message: 'Unexpected autofill response' };
  }
  redeemedInteractiveLoginPlans.set(data.login, { ...binding, assignments });
  rememberClientEventAck(data.login, data.clientEventAckId);
  rememberTotpCopyAck(data.login, data.totpCopyAckId);
  return { ok: true, data: data.login };
}

function rememberPendingInteractivePlan(intentId: string, binding: PendingInteractiveLoginPlan): void {
  if (pendingInteractiveLoginPlans.size >= MAX_PENDING_INTERACTIVE_LOGIN_PLANS) {
    const oldest = pendingInteractiveLoginPlans.keys().next().value as string | undefined;
    if (oldest) pendingInteractiveLoginPlans.delete(oldest);
  }
  pendingInteractiveLoginPlans.set(intentId, binding);
}

function assignmentsBelongToPlan(
  assignments: readonly LoginCustomAssignment[],
  plan: LoginCustomTargetPlan,
): boolean {
  const targets = new Map(plan.targets.map((target) => [target.fieldId, target]));
  return assignments.every((assignment) => {
    const target = targets.get(assignment.fieldId);
    if (!target) return false;
    return 'checked' in assignment ? target.controlType === 'checkbox' : target.controlType !== 'checkbox';
  });
}

function fillInteractiveLogin(
  form: DetectedLoginForm,
  login: AutofillLoginData,
  revalidate: FillTargetRevalidator,
): boolean {
  const binding = redeemedInteractiveLoginPlans.get(login);
  redeemedInteractiveLoginPlans.delete(login);
  const staged = createStagedFillCommit(revalidate);
  const filledLogin = fillLoginForm(form, login, staged);
  if (staged.stale || !staged.isCurrent()) return false;
  if (!binding || binding.form !== form) return filledLogin;
  const filledCustom = commitLoginCustomAssignments(form, binding.plan, binding.assignments, staged);
  if (staged.stale || !staged.isCurrent()) return false;
  return filledLogin || (filledCustom && binding.assignments.length > 0);
}

function fillTotpWithAuthority(
  input: HTMLInputElement,
  code: string,
  authorityCurrent: FillTargetRevalidator,
): boolean {
  const runtime = activeRuntime;
  if (!runtime) return false;
  const projection = computeFillProjection(runtime.documentController.refresh());
  if (!projection.complete || !resolveTotpInputs(input, projection.context)?.includes(input)) return false;
  let owner: ControlOwnerSnapshot;
  try {
    owner = captureControlOwner(input);
  } catch {
    return false;
  }
  return fillTotpCode(input, code, () => {
    if (!authorityCurrent()) return false;
    try {
      const current = computeFillProjection(runtime.documentController.snapshot());
      return current.complete
        && resolveTotpInputs(input, current.context)?.includes(input) === true
        && current.context.complete
        && hasSameControlOwner(owner, captureControlOwner(input));
    } catch {
      return false;
    }
  }, projection.context);
}

async function requestTotpData(
  cipherId: string,
  isCurrent: () => boolean = () => true,
): Promise<IntentOutcome<AutofillTotpData>> {
  const runtime = activeRuntime;
  if (!runtime) return { ok: false, message: 'Autofill target changed' };
  if (!isCurrent()) return { ok: false, message: 'Autofill target changed' };
  const intent = await issueIntent(runtime, cipherId, 'totp');
  if (!intent.ok) return intent;
  if (!isCurrent()) return { ok: false, message: 'Autofill target changed' };
  return redeemTotpIntent(runtime, intent.data);
}

async function redeemTotpIntent(
  runtime: AutofillRuntime,
  intentId: string,
  keyboard = false,
): Promise<IntentOutcome<AutofillTotpData>> {
  const response = await sendRequest(runtimeRequest(runtime, keyboard
    ? { type: 'autofill.keyboard.redeemTotpIntent', intentId }
    : { type: 'autofill.redeemTotpIntent', intentId }));
  if (!response.ok) return { ok: false, message: messageForError(response.error.code, response.error.message) };
  const data: unknown = response.data;
  if (
    !isRecord(data)
    || !hasOnlyKeys(data, ['totp', 'clientEventAckId'])
    || !isAutofillTotpData(data.totp)
    || !isOptionalClientEventAckId(data.clientEventAckId)
  ) {
    return { ok: false, message: 'Unexpected autofill response' };
  }
  rememberClientEventAck(data.totp, data.clientEventAckId);
  return { ok: true, data: data.totp };
}

function rememberClientEventAck(value: object, ackId: string | undefined): void {
  if (ackId) clientEventAckIds.set(value, ackId);
}

function rememberTotpCopyAck(value: object, ackId: string | undefined): void {
  if (ackId) totpCopyAckIds.set(value, ackId);
}

function settleClientEventAck(value: object, filled: boolean): void {
  const ackId = clientEventAckIds.get(value);
  const totpCopyAckId = totpCopyAckIds.get(value);
  clientEventAckIds.delete(value);
  totpCopyAckIds.delete(value);
  if (!filled) return;
  if (ackId) void sendRequest({ type: 'clientEvent.ack', ackId }).catch(() => undefined);
  if (totpCopyAckId) {
    void sendRequest({ type: 'autofill.ackTotpCopy', ackId: totpCopyAckId })
      .catch(() => undefined);
  }
}

function isOptionalClientEventAckId(value: unknown): value is string | undefined {
  return value === undefined || isReservationId(value);
}

async function requestStructuredFill(
  runtime: AutofillRuntime,
  cipherId: string,
  form: DetectedFillForm,
  keyboard?: ClaimedKeyboardGrant,
  selection?: { readonly roles: readonly FillRole[]; readonly target: ContentStructuredAutofillTarget },
): Promise<IntentOutcome<void>> {
  let target = captureStructuredTarget(form);
  if (!target) return { ok: false, message: 'Autofill target changed' };
  if (selection) {
    if (!equalStructuredTarget(target, selection.target)) return { ok: false, message: 'Autofill target changed' };
    const roles = normalizeFillRoles(target.kind, selection.roles);
    const capturedRoles = new Set<FillRole>(target.roles);
    if (!roles || !equalFillRoles(target.kind, roles, selection.roles)
        || roles.some((role) => !capturedRoles.has(role))) return { ok: false, message: 'Autofill target changed' };
    target = target.kind === 'card'
      ? { ...target, selectedRoles: normalizeFillRoles('card', roles)! }
      : { ...target, selectedRoles: normalizeFillRoles('identity', roles)! };
    if (!ensureFrameController().prepareStructuredSelection(target.formId, target.generation, roles)) {
      return { ok: false, message: 'Autofill target changed' };
    }
  }
  if (
    keyboard
    && (
      (keyboard.binding.purpose !== 'card' && keyboard.binding.purpose !== 'identity')
      || !equalStructuredTarget(target, keyboard.binding.structuredTarget)
    )
  ) return { ok: false, message: 'Autofill target changed' };
  const issued = await sendRequest(runtimeRequest(runtime, keyboard
    ? { type: 'autofill.keyboard.issueIntent', keyboardGrantId: keyboard.id, cipherId }
    : { type: 'autofill.issueStructuredIntent', cipherId, target }));
  if (!issued.ok) return { ok: false, message: messageForError(issued.error.code, issued.error.message) };
  const issueData: unknown = issued.data;
  if (isRecord(issueData)
      && hasOnlyKeys(issueData, ['repromptContinuationId'])
      && isReservationId(issueData.repromptContinuationId)) {
    return {
      ok: false,
      message: 'Protected item — open the extension to verify',
      repromptContinuationId: issueData.repromptContinuationId,
    };
  }
  if (!isRecord(issueData) || !hasOnlyKeys(issueData, ['intentId']) || typeof issueData.intentId !== 'string') {
    return { ok: false, message: 'Unexpected autofill response' };
  }
  const redeemed = await sendRequest(runtimeRequest(runtime, {
    type: keyboard ? 'autofill.keyboard.redeemStructuredIntent' : 'autofill.redeemStructuredIntent',
    intentId: issueData.intentId,
    target,
  }));
  if (!redeemed.ok) return { ok: false, message: messageForError(redeemed.error.code, redeemed.error.message) };
  const result: unknown = redeemed.data;
  if (!isRecord(result) || !hasOnlyKeys(result, ['outcome']) || !isTabFillOutcome(result.outcome)) {
    return { ok: false, message: 'Unexpected autofill response' };
  }
  return result.outcome.status === 'filled'
    ? { ok: true, data: undefined }
    : { ok: false, message: messageForTabFillOutcome(result.outcome) };
}

function equalStructuredTarget(
  first: ContentStructuredAutofillTarget,
  second: ContentStructuredAutofillTarget,
): boolean {
  return first.kind === second.kind
    && first.runtimeIncarnation === second.runtimeIncarnation
    && first.formId === second.formId
    && first.generation === second.generation
    && first.roles.length === second.roles.length
    && first.roles.every((role, index) => role === second.roles[index])
    && (first.selectedRoles === undefined) === (second.selectedRoles === undefined)
    && (first.selectedRoles === undefined || equalFillRoles(first.kind, first.selectedRoles, second.selectedRoles));
}

function captureStructuredTarget(form: DetectedFillForm): ContentStructuredAutofillTarget | undefined {
  const runtime = activeRuntime;
  if (!runtime || runtime.documentController.refresh().truncated) return undefined;
  if (!isCurrentStructuredForm(runtime, form)) return undefined;
  if (!(form.anchor instanceof HTMLInputElement
      || form.anchor instanceof HTMLSelectElement
      || form.anchor instanceof HTMLTextAreaElement)) return undefined;
  const controller = ensureFrameController();
  controller.noteFocus(form.anchor);
  const inspection = controller.inspect();
  const metadata = inspection.forms.filter((candidate) => (
    candidate.kind === form.kind && candidate.focusedAt !== undefined
  ));
  if (metadata.length !== 1) return undefined;
  const matched = metadata[0]!;
  if (matched.kind === 'login' || !equalFillRoles(form.kind, [...form.fields.keys()], matched.roles)) return undefined;
  if (matched.kind === 'card') {
    return Object.freeze({
      kind: matched.kind,
      runtimeIncarnation: runtime.incarnation,
      formId: matched.formId,
      generation: inspection.generation,
      roles: Object.freeze([...matched.roles]),
    });
  }
  return Object.freeze({
    kind: matched.kind,
    runtimeIncarnation: runtime.incarnation,
    formId: matched.formId,
    generation: inspection.generation,
    roles: Object.freeze([...matched.roles]),
  });
}

function isTabFillOutcome(value: unknown): value is TabFillOutcome {
  if (!isRecord(value) || !hasOnlyKeys(value, ['status'])) return false;
  return [
    'filled',
    'no_eligible_tab',
    'site_access_unavailable',
    'no_fillable_target',
    'reprompt_required',
    'vault_locked',
    'sync_required',
    'no_longer_matched',
    'target_changed',
    'fill_outcome_unknown',
    'restricted_page',
    'content_script_unavailable',
  ].includes(value.status as string);
}

function messageForTabFillOutcome(outcome: TabFillOutcome): string {
  switch (outcome.status) {
    case 'reprompt_required': return 'Protected item — open the extension to verify';
    case 'vault_locked': return 'Vault locked — open the extension to unlock';
    case 'sync_required': return 'Sync the vault before autofill';
    case 'no_fillable_target': return 'No fillable fields';
    case 'target_changed':
    case 'no_longer_matched': return 'Page changed before autofill';
    case 'fill_outcome_unknown': return 'Autofill may have completed, but the page did not confirm it';
    case 'site_access_unavailable':
    case 'restricted_page': return 'Autofill is unavailable on this page';
    case 'content_script_unavailable': return 'Autofill is unavailable in this frame';
    case 'no_eligible_tab': return 'Autofill target is no longer active';
    case 'filled': return '';
  }
}

function isAutofillLoginData(value: unknown): value is AutofillLoginData {
  return isRecord(value)
    && hasOnlyKeys(value, ['username', 'password'])
    && isOptionalString(value.username)
    && isOptionalString(value.password);
}

function isAutofillTotpData(value: unknown): value is AutofillTotpData {
  return isRecord(value)
    && hasOnlyKeys(value, ['code', 'period', 'remaining'])
    && typeof value.code === 'string'
    && typeof value.period === 'number'
    && Number.isInteger(value.period)
    && value.period > 0
    && typeof value.remaining === 'number'
    && Number.isInteger(value.remaining)
    && value.remaining >= 0
    && value.remaining <= value.period;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = new Set(allowed);
  return Object.keys(value).every((key) => keys.has(key));
}

function isUriMatchStrategySetting(value: unknown): value is AutofillCandidate['matchType'] {
  return Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 5;
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === 'string';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isHttpUrl(value: string): boolean {
  return value.startsWith('http://') || value.startsWith('https://');
}

function messageForError(code: string, fallback: string): string {
  switch (code) {
    case 'locked':
      return 'Vault is locked';
    case 'sync_required':
      return 'Sync required';
    case 'no_match':
      return 'No matching logins';
    case 'reprompt_required':
      return 'Protected item — open the extension to verify';
    case 'denied':
      return 'Autofill denied for this page';
    default:
      return fallback;
  }
}

// Trusted context-menu targets remain briefly ordered by absolute monotonic time. The worker sends
// the onClicked timestamp when reserving, so a later right-click cannot steal an earlier menu action.
export const CONTEXT_TARGET_RESERVATION_TTL_MS = 30_000;
const CONTEXT_REPROMPT_HOLD_TTL_MS = 60_000;
const MAX_PENDING_CONTEXT_TARGETS = 16;

interface PendingContextTarget {
  element: Element;
  fieldBinding?: TrustedContextFieldBinding;
  capturedAt: number;
  expiresAt: number;
}

interface TrustedContextFieldBinding {
  readonly element: FillFieldElement;
  readonly owner: ControlOwnerSnapshot;
  readonly slotPath: readonly HTMLSlotElement[];
  readonly cardRole?: CardRole;
  readonly identityRole?: IdentityRole;
}

interface ReservedContextFieldBinding {
  readonly owner: ControlOwnerSnapshot;
  readonly slotPath: readonly HTMLSlotElement[];
  readonly kind: 'card' | 'identity';
  readonly role: FillRole;
}

interface ReservedContextTarget {
  element: Element;
  root: Document | ShadowRoot;
  scope: 'form' | 'field';
  kind: 'card' | 'identity';
  roles: readonly FillRole[];
  formId?: string;
  fieldBinding?: ReservedContextFieldBinding;
  expiresAt: number;
  timer: number;
}

const pendingContextTargets: PendingContextTarget[] = [];
let pendingContextCleanupTimer: number | undefined;
const reservedContextTargets = new Map<string, ReservedContextTarget>();
const heldContextTargets = new Map<string, ReservedContextTarget>();

function handleTrustedContextMenu(target: EventTarget): void {
  if (!(target instanceof Element)) return;
  activeRuntime?.documentController.refresh();
  const now = contextClockNow();
  const fieldBinding = captureTrustedContextField(target);
  prunePendingContextTargets(now);
  pendingContextTargets.push({
    element: target,
    ...(fieldBinding ? { fieldBinding } : {}),
    capturedAt: now,
    expiresAt: now + CONTEXT_TARGET_RESERVATION_TTL_MS,
  });
  if (pendingContextTargets.length > MAX_PENDING_CONTEXT_TARGETS) pendingContextTargets.shift();
  schedulePendingContextCleanup();
}

function captureTrustedContextField(target: Element): TrustedContextFieldBinding | undefined {
  if (!(target instanceof HTMLInputElement
      || target instanceof HTMLSelectElement
      || target instanceof HTMLTextAreaElement)
      || !isFillableField(target)) return undefined;
  const runtime = activeRuntime;
  const projection = runtime
    ? computeFillProjection(runtime.documentController.snapshot())
    : computeFillProjection(rootForElement(target) ?? document);
  if (!projection.complete) return undefined;
  const hints = contextFieldHints(target, projection.context);
  if (!projection.context.complete) return undefined;
  const cardRole = classifyCardField(hints);
  const identityRole = classifyIdentityField(hints);
  if (!cardRole && !identityRole) return undefined;
  return Object.freeze({
    element: target,
    owner: captureControlOwner(target),
    slotPath: Object.freeze([...composedSlotPath(target)]),
    ...(cardRole ? { cardRole } : {}),
    ...(identityRole ? { identityRole } : {}),
  });
}

function contextFieldHints(target: FillFieldElement, context?: AutofillDetectionContext) {
  if (context) {
    return context.fieldHints(
      target,
      (budget) => collectFieldHints(target, isSemanticSourceAvailableInTree, budget),
    );
  }
  return {
    autocomplete: target.getAttribute('autocomplete') ?? '',
    name: target.getAttribute('name') ?? '',
    id: target.id,
    ariaLabel: target.getAttribute('aria-label') ?? '',
    placeholder: target.getAttribute('placeholder') ?? '',
    type: target instanceof HTMLInputElement
      ? target.type
      : target instanceof HTMLTextAreaElement ? 'textarea' : 'select',
  };
}

function sameContextSlotPath(
  first: readonly HTMLSlotElement[],
  second: readonly HTMLSlotElement[],
): boolean {
  return first.length === second.length && first.every((slot, index) => slot === second[index]);
}

function contextFieldAuthorityCurrent(
  target: Element,
  owner: ControlOwnerSnapshot,
  slotPath: readonly HTMLSlotElement[],
  kind: 'card' | 'identity',
  role: FillRole,
): target is FillFieldElement {
  if (!(target instanceof HTMLInputElement
      || target instanceof HTMLSelectElement
      || target instanceof HTMLTextAreaElement)
      || !target.isConnected
      || target.ownerDocument !== document
      || !isFillableField(target)) return false;
  try {
    if (!hasSameControlOwner(owner, captureControlOwner(target))
        || !sameContextSlotPath(slotPath, composedSlotPath(target))) return false;
  } catch {
    return false;
  }
  const runtime = activeRuntime;
  const projection = runtime
    ? computeFillProjection(runtime.documentController.refresh())
    : computeFillProjection(rootForElement(target) ?? document);
  if (!projection.complete) return false;
  const hints = contextFieldHints(target, projection.context);
  if (!projection.context.complete) return false;
  const currentRole = kind === 'card'
    ? classifyCardField(hints)
    : classifyIdentityField(hints);
  return currentRole === role;
}

function trustedContextFieldCurrent(
  binding: TrustedContextFieldBinding,
  kind: 'card' | 'identity',
  role: FillRole,
): boolean {
  return contextFieldAuthorityCurrent(binding.element, binding.owner, binding.slotPath, kind, role);
}

function contextClockNow(): number {
  const now = performance.timeOrigin + performance.now();
  return Number.isFinite(now) ? now : Date.now();
}

function prunePendingContextTargets(now = contextClockNow()): void {
  while (pendingContextTargets[0] && pendingContextTargets[0].expiresAt <= now) {
    pendingContextTargets.shift();
  }
}

function schedulePendingContextCleanup(): void {
  if (pendingContextCleanupTimer !== undefined) window.clearTimeout(pendingContextCleanupTimer);
  const first = pendingContextTargets[0];
  if (!first) {
    pendingContextCleanupTimer = undefined;
    return;
  }
  pendingContextCleanupTimer = window.setTimeout(() => {
    pendingContextCleanupTimer = undefined;
    prunePendingContextTargets();
    schedulePendingContextCleanup();
  }, Math.max(0, first.expiresAt - contextClockNow()));
}

function clearContextTargets(): void {
  pendingContextTargets.length = 0;
  if (pendingContextCleanupTimer !== undefined) window.clearTimeout(pendingContextCleanupTimer);
  pendingContextCleanupTimer = undefined;
  for (const reservation of reservedContextTargets.values()) window.clearTimeout(reservation.timer);
  reservedContextTargets.clear();
  for (const reservation of heldContextTargets.values()) window.clearTimeout(reservation.timer);
  heldContextTargets.clear();
  for (const pending of pendingKeyboardReprompts.values()) window.clearTimeout(pending.timer);
  pendingKeyboardReprompts.clear();
}

function holdReservedContextTarget(reservationId: string, holdId: string): boolean {
  if (heldContextTargets.has(holdId)) return false;
  const reservation = takeReservedContextTarget(reservationId);
  if (!reservation) return false;
  const held: ReservedContextTarget = {
    ...reservation,
    expiresAt: contextClockNow() + CONTEXT_REPROMPT_HOLD_TTL_MS,
    timer: 0,
  };
  held.timer = window.setTimeout(() => {
    if (heldContextTargets.get(holdId) === held) heldContextTargets.delete(holdId);
  }, CONTEXT_REPROMPT_HOLD_TTL_MS);
  heldContextTargets.set(holdId, held);
  return true;
}

function takeHeldContextTarget(holdId: string): ReservedContextTarget | null {
  const target = heldContextTargets.get(holdId);
  if (!target) return null;
  heldContextTargets.delete(holdId);
  window.clearTimeout(target.timer);
  return target.expiresAt > contextClockNow() ? target : null;
}

function takePendingContextTarget(contextMenuClickTime: number): PendingContextTarget | null {
  prunePendingContextTargets();
  const eligibleIndices = pendingContextTargets.flatMap((target, index) => (
    target.capturedAt < contextMenuClickTime ? [index] : []
  ));
  if (eligibleIndices.length !== 1) {
    // A delayed service-worker callback cannot distinguish a dismissed older menu from a second
    // right-click that happened after the selected action. Never guess: consume every ambiguous
    // pre-click candidate and preserve only targets known to be newer than this callback snapshot.
    for (let index = eligibleIndices.length - 1; index >= 0; index -= 1) {
      pendingContextTargets.splice(eligibleIndices[index]!, 1);
    }
    schedulePendingContextCleanup();
    return null;
  }
  const [selected] = pendingContextTargets.splice(eligibleIndices[0]!, 1);
  schedulePendingContextCleanup();
  return selected ?? null;
}

function reserveContextTarget(command: Extract<ContentCommand, { type: 'autofill.reserveFillTarget' }>): FillTargetReservationResult {
  if (reservedContextTargets.has(command.reservationId)) return { status: 'no_target' };
  const pending = takePendingContextTarget(command.contextMenuClickTime);
  if (command.expectedFrameUrl !== window.location.href) return { status: 'page_changed' };
  const target = pending?.element;
  const binding = target ? resolveFillTargetBinding(command, target, pending?.fieldBinding) : undefined;
  if (!pending || !target?.isConnected || target.ownerDocument !== document || !binding) {
    return { status: 'no_target' };
  }
  const reservation: ReservedContextTarget = {
    element: target,
    root: binding.root,
    scope: command.scope,
    kind: command.kind,
    roles: binding.roles,
    ...(binding.formId ? { formId: binding.formId } : {}),
    ...(binding.fieldBinding ? { fieldBinding: binding.fieldBinding } : {}),
    expiresAt: Math.min(pending.expiresAt, contextClockNow() + CONTEXT_TARGET_RESERVATION_TTL_MS),
    timer: 0,
  };
  reservation.timer = window.setTimeout(() => {
    if (reservedContextTargets.get(command.reservationId) === reservation) {
      reservedContextTargets.delete(command.reservationId);
    }
  }, CONTEXT_TARGET_RESERVATION_TTL_MS);
  reservedContextTargets.set(command.reservationId, reservation);
  const runtime = activeRuntime;
  if (!runtime?.activationComplete) {
    reservedContextTargets.delete(command.reservationId);
    window.clearTimeout(reservation.timer);
    return { status: 'no_target' };
  }
  return {
    status: 'reserved',
    runtimeIncarnation: runtime.incarnation,
    roles: [...binding.roles],
  };
}

async function claimContextLoginTarget(
  command: Extract<ContentCommand, { type: 'autofill.claimContextLoginTarget' }>,
): Promise<ContextLoginTargetClaimResult> {
  const pending = takePendingContextTarget(command.contextMenuClickTime);
  if (command.expectedFrameUrl !== window.location.href) return { status: 'page_changed' };
  const target = pending?.element;
  if (
    !pending
    || !(target instanceof HTMLInputElement || target instanceof HTMLSelectElement)
    || !target.isConnected
    || target.ownerDocument !== document
  ) return { status: 'no_target' };

  const runtime = activeRuntime;
  if (!runtime?.activationComplete) return { status: 'no_target' };
  const snapshot = runtime.documentController.refresh();
  if (resolveFocusedFill(target, snapshot).kind !== 'login') {
    return { status: 'no_target' };
  }
  const controller = ensureFrameController();
  controller.noteFocus(target);
  const inspection = controller.inspect();
  const focusedLoginForms = inspection.forms.filter((form): form is Extract<
    FrameInspection['forms'][number],
    { kind: 'login' }
  > => form.kind === 'login' && form.focusedAt !== undefined);
  if (focusedLoginForms.length !== 1) return { status: 'no_target' };
  const form = focusedLoginForms[0]!;
  const customPlanDigest = await digestLoginCustomTargetPlan(form.customPlan);
  if (activeRuntime !== runtime
      || !runtime.activationComplete
      || command.expectedFrameUrl !== window.location.href
      || !target.isConnected
      || target.ownerDocument !== document) return { status: 'page_changed' };
  const current = controller.inspect();
  const exact = current.generation === inspection.generation
    && current.forms.find((candidate) => candidate.kind === 'login' && candidate.formId === form.formId);
  if (!exact || exact.kind !== 'login'
      || await digestLoginCustomTargetPlan(exact.customPlan) !== customPlanDigest) {
    return { status: 'no_target' };
  }
  return {
    status: 'claimed',
    runtimeIncarnation: runtime.incarnation,
    formId: form.formId,
    generation: inspection.generation,
    customPlanDigest,
  };
}

function resolveFillTargetBinding(
  command: Extract<ContentCommand, { type: 'autofill.reserveFillTarget' }>,
  target: Element,
  trustedField: TrustedContextFieldBinding | undefined,
): {
    root: Document | ShadowRoot;
    roles: readonly FillRole[];
    formId?: string;
    fieldBinding?: ReservedContextFieldBinding;
  } | undefined {
  const targetRoot = rootForElement(target);
  if (!targetRoot) return undefined;
  if (command.scope === 'form') {
    const runtime = activeRuntime;
    const projection = runtime
      ? computeFillProjection(runtime.documentController.refresh())
      : computeFillProjection(targetRoot);
    if (!projection.complete) return undefined;
    const forms = (command.kind === 'card' ? projection.cardForms : projection.identityForms)
      .filter((candidate) => candidate.anchor.getRootNode() === targetRoot);
    const form = forms.find((candidate) => containsField(candidate, target));
    return form
      ? { root: targetRoot, formId: form.id, roles: [...form.fields.keys()] }
      : undefined;
  }
  if (!trustedField || trustedField.element !== target) return undefined;
  const role = command.kind === 'card' ? trustedField.cardRole : trustedField.identityRole;
  if (!role || !trustedContextFieldCurrent(trustedField, command.kind, role)) return undefined;
  return {
    root: targetRoot,
    roles: [role],
    fieldBinding: Object.freeze({
      owner: trustedField.owner,
      slotPath: trustedField.slotPath,
      kind: command.kind,
      role,
    }),
  };
}

function takeReservedContextTarget(
  reservationId: string,
  expected?: { scope: 'form' | 'field'; kind: 'card' | 'identity'; roles: readonly FillRole[] },
): ReservedContextTarget | null {
  const reservation = reservedContextTargets.get(reservationId);
  if (!reservation) return null;
  reservedContextTargets.delete(reservationId);
  window.clearTimeout(reservation.timer);
  if (expected && (
    reservation.scope !== expected.scope
    || reservation.kind !== expected.kind
    || !equalFillRoles(expected.kind, reservation.roles, expected.roles)
  )) return null;
  return reservation.expiresAt > contextClockNow() ? reservation : null;
}

// Record which login form was most recently focused so the background's frame inspection can rank
// the recently-used form first. Metadata only — the controller never reads or retains field values.
function handleTrustedFocus(target: EventTarget): void {
  focusedFillCycle.noteFocusedElement(target instanceof Element ? target : undefined);
  if (!(target instanceof HTMLInputElement
      || target instanceof HTMLSelectElement
      || target instanceof HTMLTextAreaElement)) return;
  activeRuntime?.documentController.refresh();
  ensureFrameController().noteFocus(target);
  if (restoredAutofillFocusTargets.delete(target)) return;
  if (!isExtensionContextAlive()) return; // orphaned after an extension reload — don't attach panels
  const runtime = activeRuntime;
  if (runtime) void handleAutofillFocus(runtime, target);
}

function registerAutofillFocusRestore(target: HTMLElement): () => void {
  restoredAutofillFocusTargets.add(target);
  return () => { restoredAutofillFocusTargets.delete(target); };
}

function restoreInlineFieldFocus(target: HTMLElement): void {
  if (!target.isConnected || document.activeElement === target) return;
  const clear = registerAutofillFocusRestore(target);
  try { target.focus({ preventScroll: true }); } finally { clear(); }
}

async function handleAutofillFocus(runtime: AutofillRuntime, field: FillFieldElement): Promise<void> {
  const snapshot = runtime.documentController.snapshot();
  const projection = computeFillProjection(snapshot);
  if (!projection.complete) return;
  const focused = resolveFocusedFill(field, snapshot, projection);
  const input = field instanceof HTMLInputElement ? field : undefined;
  const loginField = focused.kind === 'login';
  const totpField = input ? isStandaloneTotpField(input, projection.context) : false;
  const registrationField = input
    ? matchRegistrationField(input, projection.context) !== undefined
    : false;
  if (focused.kind === 'none' && !totpField && !registrationField) return;
  const config = await refreshClientConfig(runtime);
  if (activeRuntime !== runtime || !field.isConnected) return;
  if (config.inlineSuggestions) {
    if (input && loginField) maybeOpenLoginPanel(input);
    if (focused.kind === 'card' || focused.kind === 'identity') {
      maybeOpenStructuredPanel(field, focused.form);
    }
    if (input) maybeAttachTotpPanel(input);
  }
  if (config.generatorAllowed && input) maybeAttachGeneratePanel(input);
}

/** Design 2c: the login match panel hangs to the right of the focused field and opens on focus (no
 *  click-to-open trigger). Find the login form the focused input belongs to and open its side panel,
 *  attaching it first if a freshly-added form hasn't been picked up by the mutation observer yet.
 *  Returns whether a login panel was opened. */
function maybeOpenLoginPanel(input: HTMLInputElement): boolean {
  const runtime = activeRuntime;
  if (!runtime) return false;
  const projection = computeFillProjection(runtime.documentController.snapshot());
  if (!projection.complete) return false;
  const form = projection.loginForms.find((candidate) => (
    candidate.usernameInput === input || candidate.passwordInput === input
  ));
  if (!form) return false;
  let pop = popoverRegistry.get(form.id);
  if (!pop || !pop.element.isConnected) {
    attachPopovers(frameUrlProvider); // idempotent (attachIfNew de-dupes) — ensure the panel exists
    pop = popoverRegistry.get(form.id);
  }
  if (!pop || !pop.element.isConnected) return false;
  const opened = pop;
  // Dismiss when a pointer lands outside the panel and outside the login form (any of its fields).
  const keep = input.form ?? input.closest('form') ?? input;
  if (!claimAutofillSurface(opened, keep)) return false;
  opened.open();
  dismissOtherSurfaces(opened.element); // one autofill surface at a time
  registerDismissable(opened.element, keep, () => {
    releaseAutofillSurface(opened);
    opened.hide();
  });
  return true;
}

function maybeOpenStructuredPanel(field: FillFieldElement, form: DetectedFillForm): boolean {
  const runtime = activeRuntime;
  if (!runtime || !isCurrentStructuredForm(runtime, form)) return false;
  let popover = popoverRegistry.get(form.id);
  if (!popover || !popover.element.isConnected) {
    attachPopovers(frameUrlProvider);
    popover = popoverRegistry.get(form.id);
  }
  if (!popover || !popover.element.isConnected || popoverKinds.get(form.id) !== form.kind) return false;
  const keep = field.form ?? field.closest('form') ?? field;
  if (!claimAutofillSurface(popover, keep)) return false;
  popover.open(field);
  dismissOtherSurfaces(popover.element);
  registerDismissable(popover.element, keep, () => {
    releaseAutofillSurface(popover!);
    popover!.hide();
  });
  return true;
}

// --- Dismiss-on-click-away -----------------------------------------------------------------------
// An autofill surface disappears once focus/click leaves its field. Keyed by host so re-opening the
// same surface replaces its entry. Uses pointerdown (not focusout): clicking a button inside a panel
// blurs the field, so a focusout-based dismiss would tear the panel down before the click lands.

const dismissables = new Map<HTMLElement, { keep: HTMLElement; dismiss(): void }>();
const autofillSurfaceScopes = new WeakMap<HTMLElement, HTMLElement>();

function claimAutofillSurface(
  popover: ReturnType<typeof createAutofillPopover>,
  anchor: HTMLElement,
): boolean {
  releaseAutofillSurface(popover);
  const scope = inlineSurfaceScope(anchor);
  const granted = claimInlineSurface(scope, popover.element, () => {
    autofillSurfaceScopes.delete(popover.element);
    unregisterDismissable(popover.element);
    popover.hide();
  });
  if (granted) autofillSurfaceScopes.set(popover.element, scope);
  return granted;
}

function releaseAutofillSurface(popover: ReturnType<typeof createAutofillPopover>): void {
  const scope = autofillSurfaceScopes.get(popover.element);
  if (!scope) return;
  autofillSurfaceScopes.delete(popover.element);
  releaseInlineSurface(scope, popover.element);
}

function registerDismissable(host: HTMLElement, keep: HTMLElement, dismiss: () => void): void {
  dismissables.set(host, { keep, dismiss });
}

/** Close every open autofill surface except `except`, so only one is ever visible. A single form can
 *  host both a card and an identity panel (and login/2FA/generator panels live alongside them), and
 *  their `keep` is the whole form — so without this, focusing a second field in the same form would
 *  stack panels instead of replacing them. `except` is skipped so re-focusing a panel's own form (e.g.
 *  moving between a login's username and password) doesn't tear down the panel in use. */
function dismissOtherSurfaces(except?: HTMLElement): void {
  for (const [host, entry] of [...dismissables]) {
    if (host === except) continue;
    dismissables.delete(host);
    entry.dismiss();
  }
}

function unregisterDismissable(host: HTMLElement): void {
  dismissables.delete(host);
}

/** After a successful fill/save the confirmation bar shows briefly, then the whole panel auto-dismisses
 *  so it never lingers over the form. Shared 3s delay for login, verification codes, and generation. */
const FILLED_DISMISS_MS = 3000;

function handleTrustedPointerDown(target: EventTarget): void {
  if (!(target instanceof Node)) return;
  for (const [host, { keep, dismiss }] of [...dismissables]) {
    if (!host.isConnected) { dismissables.delete(host); continue; }
    // A pointerdown inside the panel's closed root retargets to the host, so `target === host` catches
    // panel clicks; `keep` (the field / login form) keeps the panel while the user works in it.
    if (target === host || host.contains(target) || target === keep || keep.contains(target)) continue;
    dismissables.delete(host);
    dismiss();
  }
}

function isCurrentLoginForm(runtime: AutofillRuntime | undefined, expected: DetectedLoginForm): boolean {
  const root = rootForElement(expected.anchor);
  if (!root) return false;
  const projection = runtime
    ? computeFillProjection(runtime.documentController.refresh())
    : computeFillProjection(root);
  if (!projection.complete || !projection.context.roots.includes(root)) return false;
  return projection.loginForms.some((current) => sameDetectedLoginForm(expected, current));
}

function boundedLoginCustomPlan(
  runtime: AutofillRuntime,
  expected: DetectedLoginForm,
): PendingInteractiveLoginPlan | undefined {
  const projection = computeFillProjection(runtime.documentController.refresh());
  if (!projection.complete) return undefined;
  const form = projection.loginForms.find((current) => sameDetectedLoginForm(expected, current));
  if (!form) return undefined;
  const plan = projection.customPlans.get(form);
  return projection.context.complete && plan ? { form: expected, plan } : undefined;
}

function sameDetectedLoginForm(first: DetectedLoginForm, second: DetectedLoginForm): boolean {
  return first.id === second.id
    && first.form === second.form
    && first.anchor === second.anchor
    && first.usernameInput === second.usernameInput
    && first.passwordInput === second.passwordInput
    && first.totpInput === second.totpInput
    && hasSameTotpInputs(first, second);
}

function isCurrentStructuredForm(runtime: AutofillRuntime | undefined, expected: DetectedFillForm): boolean {
  if (!expected.anchor.isConnected) return false;
  const root = rootForElement(expected.anchor);
  if (!root) return false;
  const projection = runtime
    ? computeFillProjection(runtime.documentController.refresh())
    : computeFillProjection(root);
  if (!projection.complete || !projection.context.roots.includes(root)) return false;
  const forms = expected.kind === 'card' ? projection.cardForms : projection.identityForms;
  return forms.some((current) => (
    current.id === expected.id
    && current.kind === expected.kind
    && current.anchor === expected.anchor
    && current.fields.size === expected.fields.size
    && [...expected.fields].every(([role, field]) => current.fields.get(role) === field)
  ));
}

/** Detector form id to its popover, so focus and shortcuts share one login/card/identity picker. */
export const popoverRegistry = new Map<string, ReturnType<typeof createAutofillPopover>>();
const popoverAnchors = new Map<string, HTMLElement>();
const popoverKinds = new Map<string, 'login' | 'card' | 'identity'>();

// --- 2FA verification-code panel (design 3a) ---------------------------------------------------
// A standalone verification-code step (a one-time-code field with no password in scope) gets a
// dedicated panel showing bounded matching accounts before any TOTP secret is requested. Mounted on
// focus of the code field so it never appears unbidden.

const MAX_INLINE_TOTP_CANDIDATES = 8;
interface ActiveTotpPanel {
  panel: TotpPanel;
  timer: number | undefined;
  input: HTMLInputElement;
  cancelSelection(): void;
}
const totpPanels = new Map<string, ActiveTotpPanel>();
const pendingTotp = new Set<string>();
let totpSeq = 0;
const totpIds = new WeakMap<HTMLInputElement, {
  readonly scope: ParentNode;
  readonly root: Node;
  readonly slotPath: readonly HTMLSlotElement[];
  readonly composedPath: readonly Element[];
  readonly inputs: readonly HTMLInputElement[];
  readonly id: string;
}>();

function isStandaloneTotpField(
  input: HTMLInputElement,
  context: AutofillDetectionContext,
): boolean {
  if (!context.complete || !resolveTotpInputs(input, context)?.includes(input)) return false;
  const root = rootForElement(input);
  if (!root) return false;
  const container = input.form ?? input.closest('section, main, article') ?? root;
  const standalone = !inputControlsInScope(container, context)
    .some((candidate) => (
      candidate.type === 'password'
      && isFillableInput(candidate)
      && isLoginPasswordCandidate(candidate, context)
    ));
  return context.complete && standalone;
}

function totpFieldId(input: HTMLInputElement, context: AutofillDetectionContext): string {
  const root = rootForElement(input);
  if (!root) return `vw-form-totp-${totpSeq++}`;
  const scope = input.form ?? input.closest('section, main, article') ?? root;
  const inputs = resolveTotpInputs(input, context);
  if (!inputs) return `vw-form-totp-${totpSeq++}`;
  const slotPath = composedSlotPath(input);
  const composedPath = composedElementPath(input);
  const existing = totpIds.get(input);
  if (
    existing?.scope === scope
    && existing.root === root
    && existing.slotPath.length === slotPath.length
    && existing.slotPath.every((slot, index) => slot === slotPath[index])
    && existing.composedPath.length === composedPath.length
    && existing.composedPath.every((element, index) => element === composedPath[index])
    && existing.inputs.length === inputs.length
    && existing.inputs.every((candidate, index) => candidate === inputs[index])
  ) return existing.id;
  const id = `vw-form-totp-${totpSeq++}`;
  totpIds.set(input, { scope, root, slotPath, composedPath, inputs: [...inputs], id });
  return id;
}

function composedElementPath(element: Element): readonly Element[] {
  const path: Element[] = [];
  for (let current: Element | null = element; current; current = composedParentElement(current)) {
    path.push(current);
  }
  return path;
}

function maybeAttachTotpPanel(input: HTMLInputElement): void {
  const runtime = activeRuntime;
  const projection = runtime ? computeFillProjection(runtime.documentController.snapshot()) : undefined;
  if (!projection?.complete || !isStandaloneTotpField(input, projection.context)) return;
  const id = totpFieldId(input, projection.context);
  if (totpPanels.has(id) || pendingTotp.has(id)) return;
  void attachTotpPanel(id, input);
}

function isCurrentTotpTarget(
  id: string,
  input: HTMLInputElement,
  suppliedProjection?: FillProjection,
): boolean {
  const runtime = activeRuntime;
  const projection = suppliedProjection
    ?? (runtime ? computeFillProjection(runtime.documentController.refresh()) : undefined);
  return Boolean(projection?.complete
    && isStandaloneTotpField(input, projection.context)
    && totpFieldId(input, projection.context) === id);
}

async function attachTotpPanel(id: string, totpInput: HTMLInputElement): Promise<void> {
  const runtime = activeRuntime;
  if (!runtime?.config.inlineSuggestions) return;
  const epoch = runtime.epoch;
  const queueGeneration = focusedFillQueueGeneration;
  const targetOwner = captureControlOwner(totpInput);
  pendingTotp.add(id);
  try {
    const frameUrl = frameUrlProvider();
    const targetAuthorityCurrent = (): boolean => {
      if (activeRuntime !== runtime
          || runtime.epoch !== epoch
          || focusedFillQueueGeneration !== queueGeneration
          || !runtime.config.inlineSuggestions
          || frameUrlProvider() !== frameUrl
          || !totpInput.isConnected
          || !isCurrentTotpTarget(id, totpInput)) return false;
      try {
        return hasSameControlOwner(targetOwner, captureControlOwner(totpInput));
      } catch {
        return false;
      }
    };
    const candResp = await sendRequest(runtimeRequest(runtime, {
      type: 'autofill.findCandidates',
      purpose: 'totp',
    }));
    if (
      !targetAuthorityCurrent()
      || !candResp.ok
      || !Array.isArray(candResp.data)
      || !isAutofillCandidates(candResp.data)
      || candResp.data.length === 0
    ) return;
    const choices = candResp.data.slice(0, MAX_INLINE_TOTP_CANDIDATES).map((candidate, index) => ({
      key: `candidate-${index}`,
      candidate,
    }));
    const choicesByKey = new Map(choices.map((choice) => [choice.key, choice]));
    const presentedCandidates = choices.map(({ key, candidate }) => ({
      key,
      name: candidate.name,
      username: candidate.username ?? '',
      reprompt: candidate.reprompt === true,
    }));
    const overflowCount = candResp.data.length - choices.length;
    let selectionGeneration = 0;
    let selectedChoice: (typeof choices)[number] | undefined;
    let currentTotp: AutofillTotpData | undefined;
    let code = '';
    let expiresAt = 0;
    let refreshingGeneration: number | undefined;

    const clearSelectionTimer = (): void => {
      const active = totpPanels.get(id);
      if (active?.panel !== panel || active.timer === undefined) return;
      window.clearInterval(active.timer);
      active.timer = undefined;
    };
    const revokeSelection = (): void => {
      selectionGeneration += 1;
      clearSelectionTimer();
      refreshingGeneration = undefined;
      if (currentTotp) settleClientEventAck(currentTotp, false);
      currentTotp = undefined;
      selectedChoice = undefined;
      code = '';
      expiresAt = 0;
    };
    const selectionCurrent = (generation: number): boolean => {
      const active = totpPanels.get(id);
      return active?.panel === panel
        && panel.element.isConnected
        && selectionGeneration === generation
        && targetAuthorityCurrent();
    };
    const showCandidates = (statusMessage = '', loadingKey = ''): void => {
      panel.showCandidates({
        candidates: presentedCandidates,
        overflowCount,
        ...(loadingKey ? { loadingKey } : {}),
        ...(statusMessage ? { statusMessage } : {}),
      });
    };
    const renderCode = (): void => {
      if (!selectedChoice) return;
      const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
      panel.update({
        itemName: selectedChoice.candidate.name,
        itemUser: selectedChoice.candidate.username ?? '',
        code,
        remaining,
        period: currentTotp?.period ?? 30,
      });
    };
    const startSelectionTimer = (choice: (typeof choices)[number], generation: number): void => {
      clearSelectionTimer();
      const active = totpPanels.get(id);
      if (!active || active.panel !== panel) return;
      active.timer = window.setInterval(() => {
        if (!selectionCurrent(generation) || selectedChoice !== choice || !isExtensionContextAlive()) {
          removeTotp(id);
          return;
        }
        const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
        if (remaining > 0 || refreshingGeneration === generation) { renderCode(); return; }
        refreshingGeneration = generation;
        if (currentTotp) settleClientEventAck(currentTotp, false);
        currentTotp = undefined;
        code = '';
        renderCode();
        // A TOTP capability is one-shot. Each period is an independent issue/redeem operation.
        void requestTotpData(
          choice.candidate.id,
          () => selectionCurrent(generation) && selectedChoice === choice,
        ).then((result) => {
          if (!selectionCurrent(generation) || selectedChoice !== choice) {
            if (result.ok) settleClientEventAck(result.data, false);
            if (selectionGeneration === generation && selectedChoice === choice
                && !targetAuthorityCurrent()) removeTotp(id);
            return;
          }
          if (!result.ok) {
            revokeSelection();
            showCandidates(result.message);
            return;
          }
          currentTotp = result.data;
          code = currentTotp.code;
          expiresAt = totpExpiry(currentTotp);
          renderCode();
        }).finally(() => {
          if (refreshingGeneration === generation) refreshingGeneration = undefined;
        });
      }, 1000);
    };
    const selectCandidate = (candidateKey: string): void => {
      const choice = choicesByKey.get(candidateKey);
      if (!choice || !targetAuthorityCurrent()) return;
      revokeSelection();
      selectedChoice = choice;
      const generation = selectionGeneration;
      showCandidates('', choice.key);
      void requestTotpData(
        choice.candidate.id,
        () => selectionCurrent(generation) && selectedChoice === choice,
      ).then((result) => {
        if (!selectionCurrent(generation) || selectedChoice !== choice) {
          if (result.ok) settleClientEventAck(result.data, false);
          if (selectionGeneration === generation && selectedChoice === choice
              && !targetAuthorityCurrent()) removeTotp(id);
          return;
        }
        if (!result.ok) {
          revokeSelection();
          showCandidates(result.message);
          return;
        }
        currentTotp = result.data;
        code = currentTotp.code;
        expiresAt = totpExpiry(currentTotp);
        renderCode();
        startSelectionTimer(choice, generation);
      });
    };
    const panel = createTotpPanel({
      anchor: totpInput,
      onDismiss: () => {
        removeTotp(id);
        restoreInlineFieldFocus(totpInput);
      },
      onSelect: selectCandidate,
      onChooseOther: () => {
        if (!targetAuthorityCurrent()) { removeTotp(id); return; }
        revokeSelection();
        showCandidates();
      },
      onFill: () => {
        const selectedTotp = currentTotp;
        const selectedCode = code;
        const generation = selectionGeneration;
        if (!selectedTotp || !selectedCode || !selectionCurrent(generation)) return;
        const filled = fillTotpWithAuthority(totpInput, selectedCode, () => (
          currentTotp === selectedTotp
          && code === selectedCode
          && selectionCurrent(generation)
        ));
        const exactSuccess = filled
          && currentTotp === selectedTotp
          && code === selectedCode
          && selectionCurrent(generation);
        settleClientEventAck(selectedTotp, exactSuccess);
        currentTotp = undefined;
        if (!exactSuccess) {
          revokeSelection();
          if (targetAuthorityCurrent()) showCandidates('目标已变化，请重新选择');
          else removeTotp(id);
          return;
        }
        panel.showFilled();
        stopTotp(id);
        // Show the verification-code confirmation briefly, then dismiss the panel.
        scheduleRuntimeTimeout(runtime, () => {
          if (totpPanels.get(id)?.panel === panel) removeTotp(id);
        }, FILLED_DISMISS_MS);
      },
      onCopy: () => {
        if (!code || !selectionCurrent(selectionGeneration)) return;
        const copiedCode = code;
        void copyTotpCodeWithOwnedClear(copiedCode, (message) => {
          const current = totpPanels.get(id);
          if (current?.panel === panel && panel.element.isConnected) panel.showStatus(message);
        });
      },
      onUndo: () => {
        if (selectionCurrent(selectionGeneration)) clearTotpCode(totpInput, code);
        removeTotp(id);
      },
    });
    panel.element.dataset.vwPopoverFor = id;
    dismissOtherSurfaces(panel.element); // one autofill surface at a time
    registerDismissable(panel.element, totpInput, () => removeTotp(id));
    totpPanels.set(id, { panel, timer: undefined, input: totpInput, cancelSelection: revokeSelection });
    showCandidates();
    const [onlyChoice] = choices;
    if (choices.length === 1 && onlyChoice) selectCandidate(onlyChoice.key);
  } finally {
    pendingTotp.delete(id);
  }
}

function stopTotp(id: string): void {
  const active = totpPanels.get(id);
  if (active?.timer !== undefined) {
    window.clearInterval(active.timer);
    active.timer = undefined;
  }
}

function removeTotp(id: string): void {
  const active = totpPanels.get(id);
  if (!active) return;
  active.cancelSelection();
  if (active.timer !== undefined) window.clearInterval(active.timer);
  unregisterDismissable(active.panel.element);
  active.panel.remove();
  totpPanels.delete(id);
}

// --- Inline registration password generation (design 2e) ---------------------------------------
// On focus of a registration new-password field, suggest a strong password with in-place rule
// tuning. The primary action only fills the page; a later trusted site submission goes through the
// normal save/update prompt. The generator runs locally, so generation never round-trips plaintext.

interface GenState {
  mode: 'password' | 'passphrase';
  username: string;
  password: string;
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  minNumbers: number;
  minSymbols: number;
  avoidAmbiguous: boolean;
  words: number;
  capitalize: boolean;
  includeNumber: boolean;
  disabledReason: string;
}
const genPanels = new Map<string, { panel: GeneratePanel; input: HTMLInputElement }>();
const generatedSaveAttempts = new Set<string>();

function teardownInlineSurfaces(): void {
  dismissStructuredPreview?.();
  for (const popover of popoverRegistry.values()) {
    unregisterDismissable(popover.element);
    releaseAutofillSurface(popover);
    popover.remove();
  }
  popoverRegistry.clear();
  popoverAnchors.clear();
  popoverKinds.clear();
  for (const id of [...totpPanels.keys()]) removeTotp(id);
  pendingTotp.clear();
}

function teardownSaveSurfaces(): void {
  teardownGeneratorSurfaces();
  teardownSavePromptSurfaces();
}

function teardownGeneratorSurfaces(): void {
  for (const { panel } of genPanels.values()) {
    unregisterDismissable(panel.element);
    panel.remove();
  }
  genPanels.clear();
}

function teardownSavePromptSurfaces(): void {
  for (const bar of saveBars) bar.remove();
  saveBars.clear();
  activeSavePromptIds.clear();
  for (const [host] of [...dismissables]) {
    if (!host.isConnected) dismissables.delete(host);
  }
}

function maybeAttachGeneratePanel(input: HTMLInputElement): void {
  const runtime = activeRuntime;
  const target = runtime ? currentRegistrationTarget(runtime, input)?.target : undefined;
  if (!target || genPanels.has(target.id) || generatedSaveAttempts.has(target.id)) return;
  attachGeneratePanel(target);
}

function currentRegistrationTarget(
  runtime: AutofillRuntime,
  input: HTMLInputElement,
): { readonly target: DetectedRegistrationField; readonly projection: FillProjection } | undefined {
  if (activeRuntime !== runtime || !input.isConnected) return undefined;
  const projection = computeFillProjection(runtime.documentController.refresh());
  if (!projection.complete) return undefined;
  const target = matchRegistrationField(input, projection.context);
  return target && projection.context.complete ? { target, projection } : undefined;
}

function attachGeneratePanel(target: DetectedRegistrationField): void {
  const runtime = activeRuntime;
  if (!runtime || !runtime.config.generatorAllowed) return;
  const owningRuntime: AutofillRuntime = runtime;
  const runtimeEpoch = runtime.epoch;
  const queueGeneration = focusedFillQueueGeneration;
  const frameUrl = runtime.getFrameUrl();
  const targetOwner = captureControlOwner(target.input);
  const generatorPolicy = runtime.config.generator;
  const state: GenState = {
    mode: generatorPolicy.forcedMode
      ?? (!generatorPolicy.password.allowed && generatorPolicy.passphrase.allowed ? 'passphrase' : 'password'),
    username: target.usernameInput?.value?.trim() ?? '',
    password: '',
    length: 18,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    minNumbers: 1,
    minSymbols: 0,
    avoidAmbiguous: true,
    words: DEFAULT_PASSPHRASE_OPTIONS.numWords,
    capitalize: DEFAULT_PASSPHRASE_OPTIONS.capitalize,
    includeNumber: DEFAULT_PASSPHRASE_OPTIONS.includeNumber,
    disabledReason: '',
  };
  let used = false;
  let authorizingUse = false;
  const isCurrentGenerator = (requirePanel = false): boolean => {
    if (activeRuntime !== runtime
        || runtime.epoch !== runtimeEpoch
        || focusedFillQueueGeneration !== queueGeneration
        || runtime.getFrameUrl() !== frameUrl
        || !runtime.config.generatorAllowed
        || runtime.config.generator.revision !== generatorPolicy.revision
        || (requirePanel && panel?.element.isConnected !== true)) return false;
    try {
      const current = currentRegistrationTarget(runtime, target.input);
      return hasSameControlOwner(targetOwner, captureControlOwner(target.input))
        && current?.target.id === target.id;
    } catch {
      return false;
    }
  };
  const canTune = (): boolean => isCurrentGenerator(true)
    && !generatorPolicy.policyInEffect
    && !generatorPolicy.malformed;
  const generatorOptions = (): PasswordGeneratorOptions => ({
    mode: state.mode,
    password: {
      length: state.length,
      lowercase: state.lowercase,
      uppercase: state.uppercase,
      numbers: state.numbers,
      special: state.symbols,
      minNumbers: state.numbers ? state.minNumbers : 0,
      minSpecial: state.symbols ? state.minSymbols : 0,
      avoidAmbiguous: state.avoidAmbiguous,
    },
    passphrase: {
      numWords: state.words,
      separator: DEFAULT_PASSPHRASE_OPTIONS.separator,
      capitalize: state.capitalize,
      includeNumber: state.includeNumber,
    },
  });
  const regen = (): void => {
    const evaluation = applyGeneratorPolicySnapshot(generatorOptions(), generatorPolicy);
    if (!evaluation.allowed) {
      state.password = '';
      state.disabledReason = evaluation.reason === 'malformed-policy'
        ? '组织的密码生成策略无效，已停止生成'
        : '组织的密码生成规则无法满足，已停止生成';
      return;
    }
    state.disabledReason = '';
    state.mode = evaluation.options.mode;
    Object.assign(state, {
      length: evaluation.options.password.length,
      lowercase: evaluation.options.password.lowercase,
      uppercase: evaluation.options.password.uppercase,
      numbers: evaluation.options.password.numbers,
      symbols: evaluation.options.password.special,
      minNumbers: evaluation.options.password.minNumbers,
      minSymbols: evaluation.options.password.minSpecial,
      avoidAmbiguous: evaluation.options.password.avoidAmbiguous,
      words: evaluation.options.passphrase.numWords,
      capitalize: evaluation.options.passphrase.capitalize,
      includeNumber: evaluation.options.passphrase.includeNumber,
    });
    state.password = state.mode === 'passphrase'
      ? generatePassphrase(evaluation.options.passphrase)
      : generatePassword(evaluation.options.password);
  };
  regen();

  const TYPES = ['uppercase', 'lowercase', 'numbers', 'symbols'] as const;
  // Toggling a character class off is refused if it is the last one on — the generator needs a non-empty pool.
  const setType = (key: (typeof TYPES)[number], on: boolean): void => {
    if (!canTune()) return;
    if (!on && !TYPES.some((k) => k !== key && state[k])) return;
    state[key] = on;
    regen();
    push();
  };
  const clampMin = (n: number): number => Math.max(0, Math.min(Math.round(n), 9));

  const panel = createGeneratePanel({
    anchor: target.anchor,
    onDismiss: () => {
      panel.remove();
      if (genPanels.get(target.id)?.panel === panel) genPanels.delete(target.id);
      unregisterDismissable(panel.element);
      restoreInlineFieldFocus(target.input);
    },
    onMode: (mode) => {
      if (!canTune()) return;
      state.mode = mode;
      regen();
      push();
    },
    // Editing the username must NOT re-render (it would reset the field and drop the caret) — just
    // record it; the next push (regen/rule change) re-renders with the recorded value.
    onUsername: (value) => { if (isCurrentGenerator(true)) state.username = value; },
    onRegenerate: () => { if (isCurrentGenerator(true) && !state.disabledReason) { regen(); push(); } },
    onLength: (n) => {
      if (!canTune()) return;
      state.length = Math.max(8, Math.min(Math.round(n), 128));
      regen();
      push();
    },
    onUppercase: (on) => setType('uppercase', on),
    onLowercase: (on) => setType('lowercase', on),
    onNumbers: (on) => setType('numbers', on),
    onSymbols: (on) => setType('symbols', on),
    onMinNumbers: (n) => {
      if (!canTune()) return;
      state.minNumbers = clampMin(n); regen(); push();
    },
    onMinSymbols: (n) => {
      if (!canTune()) return;
      state.minSymbols = clampMin(n); regen(); push();
    },
    onAvoidAmbiguous: (on) => {
      if (!canTune()) return;
      state.avoidAmbiguous = on; regen(); push();
    },
    onWords: (n) => {
      if (!canTune()) return;
      state.words = Math.max(3, Math.min(Math.round(n), 20)); regen(); push();
    },
    onCapitalize: (on) => {
      if (!canTune()) return;
      state.capitalize = on; regen(); push();
    },
    onIncludeNumber: (on) => {
      if (!canTune()) return;
      state.includeNumber = on; regen(); push();
    },
    onUse: useGenerated,
  });
  panel.element.dataset.vwPopoverFor = target.id;
  dismissOtherSurfaces(panel.element); // one autofill surface at a time
  registerDismissable(panel.element, target.input, () => {
    panel.remove();
    if (genPanels.get(target.id)?.panel === panel) genPanels.delete(target.id);
  });

  const push = (): void => panel.update({
    mode: state.mode,
    username: state.username,
    password: state.password,
    strength: strengthLabel(state.length),
    length: state.length,
    uppercase: state.uppercase,
    lowercase: state.lowercase,
    numbers: state.numbers,
    symbols: state.symbols,
    minNumbers: state.minNumbers,
    minSymbols: state.minSymbols,
    avoidAmbiguous: state.avoidAmbiguous,
    words: state.words,
    capitalize: state.capitalize,
    includeNumber: state.includeNumber,
    managed: generatorPolicy.policyInEffect,
    disabledReason: state.disabledReason,
  });
  push();

  async function useGenerated(): Promise<void> {
    if (
      !isCurrentGenerator(true)
      || used
      || authorizingUse
      || !state.password
    ) return;
    const evaluation = applyGeneratorPolicySnapshot(generatorOptions(), generatorPolicy);
    if (!evaluation.allowed || evaluation.options.mode !== state.mode) return;
    const generatedValue = state.password;
    const authorizedOptions = evaluation.options;
    const username = state.username.trim() || undefined;
    const registration = currentRegistrationTarget(owningRuntime, target.input);
    if (!registration || registration.target.id !== target.id) return;
    const confirmBindings = findConfirmPasswordFields(
      target.input,
      registration.projection.context,
    ).map((input) => ({
      input,
      owner: captureControlOwner(input),
    }));
    const usernameBinding = registration.target.usernameInput
      ? {
          input: registration.target.usernameInput,
          owner: captureControlOwner(registration.target.usernameInput),
        }
      : undefined;
    const targetsCurrent = (): boolean => {
      const currentEvaluation = applyGeneratorPolicySnapshot(generatorOptions(), generatorPolicy);
      if (!isCurrentGenerator(true)
          || state.password !== generatedValue
          || (state.username.trim() || undefined) !== username
          || !currentEvaluation.allowed
          || !sameGeneratorOptions(currentEvaluation.options, authorizedOptions)) return false;
      const currentRegistration = currentRegistrationTarget(owningRuntime, target.input);
      if (!currentRegistration || currentRegistration.target.id !== target.id) return false;
      const currentConfirms = findConfirmPasswordFields(
        target.input,
        currentRegistration.projection.context,
      );
      if (currentConfirms.length !== confirmBindings.length) return false;
      try {
        if (!confirmBindings.every((binding, index) => (
          currentConfirms[index] === binding.input
          && hasSameControlOwner(binding.owner, captureControlOwner(binding.input))
        ))) return false;
        return usernameBinding === undefined || (
          currentRegistration.target.usernameInput === usernameBinding.input
          && hasSameControlOwner(usernameBinding.owner, captureControlOwner(usernameBinding.input))
        );
      } catch {
        return false;
      }
    };
    if (!targetsCurrent()) return;
    authorizingUse = true;
    let authorization: Awaited<ReturnType<typeof sendRequest>>;
    try {
      authorization = await sendRequest(runtimeRequest(owningRuntime, {
        type: 'autofill.authorizeGeneratorUse',
        revision: generatorPolicy.revision,
        options: authorizedOptions,
      }));
    } catch {
      authorizingUse = false;
      return;
    }
    authorizingUse = false;
    if (
      !authorization.ok
      || !isCurrentGenerator(true)
      || used
      || !targetsCurrent()
    ) return;
    const authorizationData: unknown = authorization.data;
    if (!isRecord(authorizationData)
        || !hasOnlyKeys(authorizationData, ['trackToken'])
        || !isReservationId(authorizationData.trackToken)) return;
    generatedSaveAttempts.add(target.id);
    used = true;
    const staged = createStagedFillCommit(targetsCurrent);
    if (!staged.write(() => {
      setInputValue(target.input, generatedValue);
      return true;
    })) return;
    flashFill(target.input); // mvFill highlight on the just-filled new-password field
    // Co-fill any confirm/retype password field in the same form with the same value, so the signup
    // form's "confirm password" isn't left empty (which would block submission).
    for (const { input: confirm } of confirmBindings) {
      if (!staged.write(() => {
        setInputValue(confirm, generatedValue);
        return true;
      })) return;
      flashFill(confirm, 130);
    }
    // Also write the possibly edited username back into the page. A later trusted submission captures
    // the live values and lets the worker decide whether to save, update, or add the current URI.
    if (username && target.usernameInput && isFillableInput(target.usernameInput)) {
      if (!staged.write(() => {
        setInputValue(target.usernameInput!, username);
        return true;
      })) return;
      flashFill(target.usernameInput, 130);
    }
    if (staged.stale || !staged.isCurrent()) return;
    panel.showFilled({ user: username ?? '' });
    void sendRequest(runtimeRequest(owningRuntime, {
      type: 'autofill.trackGeneratedValue',
      token: authorizationData.trackToken,
      value: generatedValue,
    })).catch(() => undefined);
    // Show the filled confirmation briefly, then leave the page to perform its normal submission.
    scheduleRuntimeTimeout(owningRuntime, () => {
      panel.remove();
      if (genPanels.get(target.id)?.panel === panel) genPanels.delete(target.id);
      unregisterDismissable(panel.element);
    }, FILLED_DISMISS_MS);
  }

  genPanels.set(target.id, { panel, input: target.input });
}

function sameGeneratorOptions(
  left: PasswordGeneratorOptions,
  right: PasswordGeneratorOptions,
): boolean {
  return left.mode === right.mode
    && left.password.length === right.password.length
    && left.password.lowercase === right.password.lowercase
    && left.password.uppercase === right.password.uppercase
    && left.password.numbers === right.password.numbers
    && left.password.special === right.password.special
    && left.password.minNumbers === right.password.minNumbers
    && left.password.minSpecial === right.password.minSpecial
    && left.password.avoidAmbiguous === right.password.avoidAmbiguous
    && left.passphrase.numWords === right.passphrase.numWords
    && left.passphrase.separator === right.passphrase.separator
    && left.passphrase.capitalize === right.passphrase.capitalize
    && left.passphrase.includeNumber === right.passphrase.includeNumber;
}

function pruneDetachedSurfaces(): void {
  const runtime = activeRuntime;
  const needsProjection = popoverRegistry.size > 0 || totpPanels.size > 0 || genPanels.size > 0;
  const projection = runtime && needsProjection
    ? computeFillProjection(runtime.documentController.snapshot())
    : undefined;
  let complete = projection?.complete === true;
  const liveTotpIds = new Set<string>();
  const liveGeneratorIds = new Set<string>();
  if (complete && projection) {
    for (const [id, active] of totpPanels) {
      if (isCurrentTotpTarget(id, active.input, projection)) liveTotpIds.add(id);
      if (!projection.context.complete) break;
    }
    for (const [id, active] of genPanels) {
      if (!projection.context.complete) break;
      const target = matchRegistrationField(active.input, projection.context);
      if (projection.context.complete && target?.id === id) liveGeneratorIds.add(id);
    }
    complete = projection.context.complete;
  }
  if (!complete) {
    liveTotpIds.clear();
    liveGeneratorIds.clear();
  }
  const liveLoginForms = complete && projection ? projection.loginForms : [];
  const liveCardForms = complete && projection ? projection.cardForms : [];
  const liveIdentityForms = complete && projection ? projection.identityForms : [];
  for (const [id, popover] of [...popoverRegistry]) {
    const anchor = popoverAnchors.get(id);
    const kind = popoverKinds.get(id);
    const liveForms = kind === 'card'
      ? liveCardForms
      : kind === 'identity' ? liveIdentityForms : liveLoginForms;
    if (anchor?.isConnected && liveForms.some((form) => form.id === id && form.anchor === anchor)) continue;
    unregisterDismissable(popover.element);
    releaseAutofillSurface(popover);
    popover.remove();
    popoverRegistry.delete(id);
    popoverAnchors.delete(id);
    popoverKinds.delete(id);
  }
  for (const [id] of [...totpPanels]) {
    if (!liveTotpIds.has(id)) removeTotp(id);
  }
  for (const [id, active] of [...genPanels]) {
    if (liveGeneratorIds.has(id)) continue;
    unregisterDismissable(active.panel.element);
    active.panel.remove();
    genPanels.delete(id);
  }
}

function strengthLabel(len: number): string {
  if (len >= 16) return '极强';
  if (len >= 12) return '强';
  if (len >= 10) return '中等';
  return '较弱';
}

browser.runtime.onMessage.addListener((message: unknown): Promise<
  FrameInspection | TabFillOutcome | FillTargetReservationResult | ContextLoginTargetClaimResult
  | ContextFillResult | HoldFillTargetResult | AutofillSaveCaptureWakeResult
  | { readonly status: 'focused' | 'stale' }
> | undefined => {
  // Frame inspect/commit and target reservation return typed values that the background awaits. A
  // Promise return tells the polyfill to keep the response channel open; terminal content commands
  // return nothing so the channel closes immediately.
  if (isFrameAutofillMessage(message)) return Promise.resolve(handleFrameAutofillMessage(message));
  if (isContentCommand(message)) {
    const result = message.type === 'autofill.awaitFocus'
      ? handleContentCommand(message)
      : message.type === 'autofill.claimContextLoginTarget'
        ? handleContentCommand(message)
        : message.type === 'autofill.saveCaptureConfirmed'
          ? handleContentCommand(message)
          : handleContentCommand(message as Exclude<ContentCommand, {
              type: 'autofill.awaitFocus'
                | 'autofill.claimContextLoginTarget'
                | 'autofill.saveCaptureConfirmed';
            }>);
    if (result) return Promise.resolve(result);
  }
  return undefined;
});

/** Answer a background current-tab-fill message: report this frame's login-form metadata, or commit
 *  a fill after the controller re-validates the frame URL and form identity (TOCTOU guard). */
export function handleFrameAutofillMessage(
  message: Extract<FrameAutofillMessage, { type: 'autofill.inspectFrame' }>,
): FrameInspection | TabFillOutcome;
export function handleFrameAutofillMessage(
  message: Extract<FrameAutofillMessage, { type: 'autofill.commitLoginFill' }>,
): Promise<TabFillOutcome>;
export function handleFrameAutofillMessage(
  message: Extract<FrameAutofillMessage, { type: 'autofill.commitStructuredFill' }>,
): TabFillOutcome;
export function handleFrameAutofillMessage(
  message: FrameAutofillMessage,
): FrameInspection | TabFillOutcome | Promise<TabFillOutcome>;
export function handleFrameAutofillMessage(
  message: FrameAutofillMessage,
): FrameInspection | TabFillOutcome | Promise<TabFillOutcome> {
  const runtime = activeRuntime;
  if (!runtime?.activationComplete) {
    const outcome = { status: 'target_changed' } as const;
    return message.type === 'autofill.commitLoginFill' ? Promise.resolve(outcome) : outcome;
  }
  const controller = ensureFrameController();
  if (message.type === 'autofill.inspectFrame') {
    return { ...controller.inspect(), runtimeIncarnation: runtime.incarnation };
  }
  if (message.expectedRuntimeIncarnation !== runtime.incarnation) {
    const outcome = { status: 'target_changed' } as const;
    return message.type === 'autofill.commitLoginFill' ? Promise.resolve(outcome) : outcome;
  }
  if (message.type === 'autofill.commitLoginFill') {
    return controller.commitLogin({
      formId: message.formId,
      expectedFrameUrl: message.expectedFrameUrl,
      expectedGeneration: message.expectedGeneration,
      login: message.login,
      customPlan: message.customPlan,
      customPlanDigest: message.customPlanDigest,
      customAssignments: message.customAssignments,
    });
  }
  if (message.kind === 'card') {
    return controller.commitStructured({
      kind: message.kind,
      formId: message.formId,
      roles: [...message.roles],
      ...(message.selectedRoles ? { selectedRoles: [...message.selectedRoles] } : {}),
      expectedFrameUrl: message.expectedFrameUrl,
      expectedGeneration: message.expectedGeneration,
      data: message.data,
    });
  }
  return controller.commitStructured({
    kind: message.kind,
    formId: message.formId,
    roles: [...message.roles],
    ...(message.selectedRoles ? { selectedRoles: [...message.selectedRoles] } : {}),
    expectedFrameUrl: message.expectedFrameUrl,
    expectedGeneration: message.expectedGeneration,
    data: message.data,
  });
}

export function handleContentCommand(
  command: Extract<ContentCommand, { type: 'autofill.awaitFocus' }>,
): Promise<{ readonly status: 'focused' | 'stale' }>;
export function handleContentCommand(
  command: Extract<ContentCommand, { type: 'autofill.claimContextLoginTarget' }>,
): Promise<ContextLoginTargetClaimResult>;
export function handleContentCommand(
  command: Extract<ContentCommand, { type: 'autofill.saveCaptureConfirmed' }>,
): Promise<AutofillSaveCaptureWakeResult>;
export function handleContentCommand(
  command: Extract<ContentCommand, { type: 'autofill.holdFillTarget' }>,
): HoldFillTargetResult;
export function handleContentCommand(
  command: Exclude<ContentCommand, {
    type: 'autofill.awaitFocus' | 'autofill.claimContextLoginTarget' | 'autofill.saveCaptureConfirmed';
  }>,
): FillTargetReservationResult | ContextLoginTargetClaimResult | ContextFillResult | HoldFillTargetResult
  | void;
export function handleContentCommand(
  command: ContentCommand,
): FillTargetReservationResult | ContextLoginTargetClaimResult | ContextFillResult
  | HoldFillTargetResult | AutofillSaveCaptureWakeResult
  | Promise<
      { readonly status: 'focused' | 'stale' }
      | ContextLoginTargetClaimResult
      | AutofillSaveCaptureWakeResult
    > | void {
  if (command.type === 'autofill.clientConfigChanged') { invalidateClientRuntime(); return; }
  if ('expectedRuntimeIncarnation' in command
      && (!activeRuntime?.activationComplete
        || command.expectedRuntimeIncarnation !== activeRuntime.incarnation)) {
    if (command.type === 'autofill.awaitFocus') return Promise.resolve({ status: 'stale' });
    if (command.type === 'autofill.fill' || command.type === 'autofill.resumeHeldFillTarget') {
      return { status: 'target_changed' };
    }
    if (command.type === 'autofill.holdFillTarget') return { status: 'no_target' };
    return;
  }
  if (command.type === 'autofill.saveCaptureConfirmed') {
    const runtime = activeRuntime;
    if (!runtime?.activationComplete) return Promise.resolve({ status: 'not_ready' });
    return claimPendingSavePromptOnce(runtime, command.captureId).then(
      (status) => activeRuntime === runtime ? { status } : { status: 'not_ready' as const },
      () => ({ status: 'not_ready' as const }),
    );
  }
  if (command.type === 'autofill.focusedFill') {
    if (!activeRuntime?.activationComplete) return;
    void handleFocusedFill(frameUrlProvider, command.commandToken).catch(() => undefined);
    return;
  }
  if (command.type === 'autofill.claimContextLoginTarget') return claimContextLoginTarget(command);
  if (command.type === 'autofill.reserveFillTarget') return reserveContextTarget(command);
  if (command.type === 'autofill.cancelFillTarget') {
    takeReservedContextTarget(command.reservationId);
    return;
  }
  if (command.type === 'autofill.holdFillTarget') {
    if (command.expectedFrameUrl !== window.location.href) return { status: 'page_changed' };
    return holdReservedContextTarget(command.reservationId, command.holdId)
      ? { status: 'held' }
      : { status: 'no_target' };
  }
  if (command.type === 'autofill.cancelHeldFillTarget') {
    if (command.expectedFrameUrl === window.location.href) takeHeldContextTarget(command.holdId);
    return;
  }
  if (command.type === 'autofill.resumeHeldFillTarget') {
    const reservation = takeHeldContextTarget(command.holdId);
    if (!reservation) return { status: 'no_target' };
    const contextTarget = reservation.element;
    if (command.expectedFrameUrl !== window.location.href) return { status: 'page_changed' };
    if (reservation.scope !== command.scope || reservation.kind !== command.kind
        || !equalFillRoles(command.kind, reservation.roles, command.roles)
        || !contextReservationCurrent(command as never, contextTarget, reservation)) {
      return { status: 'target_changed' };
    }
    const filled = command.scope === 'field'
      ? fillSingleField(command as never, contextTarget, reservation)
      : fillWholeForm(command as never, contextTarget, reservation);
    return { status: filled ? 'filled' : 'target_changed' };
  }
  if (command.type === 'autofill.resumeKeyboardReprompt') {
    void resumeKeyboardReprompt(command.continuationId, command.expectedFrameUrl).catch(() => undefined);
    return;
  }
  if (command.type === 'autofill.awaitFocus') return awaitAutofillFocus(command);
  if (command.type === 'autofill.fillError') {
    const reservation = takeReservedContextTarget(command.reservationId);
    if (!reservation) return;
    const contextTarget = reservation.element;
    if (command.expectedFrameUrl !== window.location.href) return;
    if (!contextTarget.isConnected || contextTarget.ownerDocument !== document || rootForElement(contextTarget) !== reservation.root) return;
    showNotice('Protected item — open the extension to verify');
    return;
  }
  const reservation = takeReservedContextTarget(command.reservationId, {
    scope: command.scope,
    kind: command.kind,
    roles: command.roles,
  });
  if (!reservation) return { status: 'no_target' };
  const contextTarget = reservation.element;
  if (command.expectedFrameUrl !== window.location.href) return { status: 'page_changed' };
  if (!contextReservationCurrent(command, contextTarget, reservation)) {
    return { status: 'target_changed' };
  }
  const filled = command.scope === 'field'
    ? fillSingleField(command, contextTarget, reservation)
    : fillWholeForm(command, contextTarget, reservation);
  return { status: filled ? 'filled' : 'target_changed' };
}

export function openPickerFor(getFrameUrl: FrameUrlProvider, formId: string): void {
  let pop = popoverRegistry.get(formId);
  const open = (current: ReturnType<typeof createAutofillPopover>): boolean => {
    const anchor = popoverAnchors.get(formId) ?? current.element;
    if (!claimAutofillSurface(current, anchor)) return false;
    current.open(undefined, { focusList: true });
    return true;
  };
  if (pop && pop.element.isConnected) { open(pop); return; }
  popoverRegistry.delete(formId);
  popoverAnchors.delete(formId);
  popoverKinds.delete(formId);
  attachPopovers(getFrameUrl); // idempotent (attachIfNew de-dupes) — re-attach for the current form
  pop = popoverRegistry.get(formId);
  if (pop && pop.element.isConnected) open(pop);
  else showNotice('多个匹配项——点击输入框的密屿图标选择');
}

function awaitAutofillFocus(
  command: Extract<ContentCommand, { type: 'autofill.awaitFocus' }>,
): Promise<{ readonly status: 'focused' | 'stale' }> {
  const runtime = activeRuntime;
  if (!runtime?.activationComplete || runtime.incarnation !== command.expectedRuntimeIncarnation) {
    return Promise.resolve({ status: 'stale' });
  }
  const current = () => activeRuntime === runtime
    && runtime.incarnation === command.expectedRuntimeIncarnation
    && command.expectedFrameUrl === window.location.href
    && Date.now() < command.expiresAt;
  if (!current()) return Promise.resolve({ status: 'stale' });
  if (document.hasFocus() && document.visibilityState !== 'hidden') {
    return Promise.resolve({ status: 'focused' });
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (status: 'focused' | 'stale') => {
      if (settled) return;
      settled = true;
      window.removeEventListener('focus', check, true);
      document.removeEventListener('visibilitychange', check, true);
      window.clearTimeout(timer);
      runtime.focusWaiters.delete(cancel);
      resolve({ status });
    };
    const check = () => {
      if (!current()) finish('stale');
      else if (document.hasFocus() && document.visibilityState !== 'hidden') finish('focused');
    };
    const timer = window.setTimeout(() => finish('stale'), Math.max(0, command.expiresAt - Date.now()));
    const cancel = () => finish('stale');
    runtime.focusWaiters.add(cancel);
    window.addEventListener('focus', check, true);
    document.addEventListener('visibilitychange', check, true);
    check();
  });
}

function removeRegisteredPopover(formId: string, popover: ReturnType<typeof createAutofillPopover>): void {
  unregisterDismissable(popover.element);
  releaseAutofillSurface(popover);
  popover.remove();
  if (popoverRegistry.get(formId) === popover) {
    popoverRegistry.delete(formId);
    popoverAnchors.delete(formId);
    popoverKinds.delete(formId);
  }
}

function openKeyboardStructuredPicker(
  getFrameUrl: FrameUrlProvider,
  form: DetectedFillForm,
  items: readonly FillItemCandidate[],
  keyboard: ClaimedKeyboardGrant,
): void {
  const runtime = activeRuntime;
  if (!runtime || !isCurrentStructuredForm(runtime, form)) return;
  const existing = popoverRegistry.get(form.id);
  if (existing) removeRegisteredPopover(form.id, existing);
  let spent = false;
  const candidates = items.map((candidate) => ({
    id: candidate.id,
    name: candidate.name,
    favorite: candidate.favorite,
    ...(candidate.subtitle ? { sub: candidate.subtitle } : {}),
    ...(candidate.reprompt ? { reprompt: true } : {}),
  }));
  const popover = createAutofillPopover({
    anchor: form.anchor,
    kind: form.kind,
    candidates,
    beforeFocusRestore: registerAutofillFocusRestore,
    onOpen: () => { if (!spent) popover.showCandidates(candidates); },
    onSelect: (cipherId) => {
      if (spent) return;
      spent = true;
      void requestStructuredFill(runtime, cipherId, form, keyboard).then((outcome) => {
        if (!popover.element.isConnected) return;
        if (!outcome.ok) {
          popover.showStatus(outcome.message);
          return;
        }
        popover.showFilled();
        scheduleRuntimeTimeout(runtime, () => removeRegisteredPopover(form.id, popover), FILLED_DISMISS_MS);
      });
    },
    onDismiss: () => {
      if (spent) return;
      spent = true;
      removeRegisteredPopover(form.id, popover);
    },
  });
  popoverRegistry.set(form.id, popover);
  popoverAnchors.set(form.id, form.anchor);
  popoverKinds.set(form.id, form.kind);
  const focused = runtime.documentController.deepActiveElement();
  const anchor = focused instanceof HTMLInputElement || focused instanceof HTMLSelectElement || focused instanceof HTMLTextAreaElement
    ? [...form.fields.values()].includes(focused) ? focused : form.anchor
    : form.anchor;
  if (!claimAutofillSurface(popover, anchor)) {
    removeRegisteredPopover(form.id, popover);
    return;
  }
  popover.open(anchor, { focusList: true });
  dismissOtherSurfaces(popover.element);
  const keep = (anchor instanceof HTMLInputElement || anchor instanceof HTMLSelectElement || anchor instanceof HTMLTextAreaElement
    ? anchor.form
    : undefined) ?? anchor.closest('form') ?? anchor;
  registerDismissable(popover.element, keep, () => removeRegisteredPopover(form.id, popover));
}

function focusedFillDeps(
  getFrameUrl: FrameUrlProvider,
  runtime: AutofillRuntime | undefined,
  queueGeneration: number,
  keyboard: ClaimedKeyboardGrant,
): FocusedFillDeps {
  const runtimeEpoch = (): number => {
    if (focusedFillQueueGeneration !== queueGeneration || activeRuntime !== runtime) return Number.NaN;
    return runtime?.epoch ?? queueGeneration;
  };
  return {
    frameUrl: () => getFrameUrl(),
    runtimeEpoch,
    now: () => Date.now(),
    isTargetCurrent: (target) => (
      Number.isFinite(runtimeEpoch()) && isFocusedTargetCurrent(target, runtime)
    ),
    cycle: focusedFillCycle,
    loginCandidates: async (purpose) => {
      if (keyboard.binding.purpose !== purpose) return { ok: false, message: 'Autofill target changed' };
      if (!runtime) return { ok: false, message: 'Autofill target changed' };
      const r = await sendRequest(runtimeRequest(runtime, {
        type: 'autofill.keyboard.findCandidates',
        keyboardGrantId: keyboard.id,
      }));
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return Array.isArray(r.data) && isAutofillCandidates(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    issueIntent: (cipherId, purpose, form) => runtime
      ? issueIntent(runtime, cipherId, purpose, form, keyboard)
      : Promise.resolve({ ok: false, message: 'Autofill target changed' }),
    redeemLoginIntent: (intentId) => runtime
      ? redeemLoginIntent(runtime, intentId, true)
      : Promise.resolve({ ok: false, message: 'Autofill target changed' }),
    redeemTotpIntent: (intentId) => runtime
      ? redeemTotpIntent(runtime, intentId, true)
      : Promise.resolve({ ok: false, message: 'Autofill target changed' }),
    fillItems: async (kind) => {
      if (keyboard.binding.purpose !== kind) return { ok: false, message: 'Autofill target changed' };
      if (!runtime) return { ok: false, message: 'Autofill target changed' };
      const response = await sendRequest(runtimeRequest(runtime, {
        type: 'autofill.keyboard.findCandidates',
        keyboardGrantId: keyboard.id,
      }));
      if (!response.ok) return { ok: false, message: messageForError(response.error.code, response.error.message) };
      return Array.isArray(response.data) && isFillItemCandidates(response.data)
        ? { ok: true, data: response.data }
        : { ok: false, message: 'Unexpected autofill response' };
    },
    fillStructured: (cipherId, form) => runtime
      ? requestStructuredFill(runtime, cipherId, form, keyboard)
      : Promise.resolve({ ok: false, message: 'Autofill target changed' }),
    deferReprompt: (continuationId, target, selection) => {
      rememberKeyboardReprompt(continuationId, target, runtime, queueGeneration, getFrameUrl(), selection);
    },
    fillLogin: (form, data) => {
      const expectedFrameUrl = getFrameUrl();
      const expectedEpoch = runtimeEpoch();
      const expectedRoot = form.anchor.getRootNode();
      const filled = fillInteractiveLogin(form, data, () => (
        getFrameUrl() === expectedFrameUrl
        && runtimeEpoch() === expectedEpoch
        && form.anchor.getRootNode() === expectedRoot
        && isCurrentLoginForm(runtime, form)
      ));
      settleClientEventAck(data, filled);
      return filled;
    },
    fillTotp: (input, data) => {
      const expectedFrameUrl = getFrameUrl();
      const expectedEpoch = runtimeEpoch();
      runtime?.documentController.refresh();
      const expectedTarget = resolveFocusedFill(
        input,
        runtime?.documentController.snapshot() ?? document,
      );
      const filled = expectedTarget.kind === 'totp' && expectedTarget.input === input
        ? fillTotpWithAuthority(input, data.code, () => (
            getFrameUrl() === expectedFrameUrl
            && runtimeEpoch() === expectedEpoch
            && isFocusedTargetCurrent(expectedTarget, runtime)
          ))
        : false;
      settleClientEventAck(data, filled);
      return filled;
    },
    openPicker: (form, items) => openKeyboardStructuredPicker(getFrameUrl, form, items, keyboard),
    notify: (message) => showNotice(message),
  };
}

function rememberKeyboardReprompt(
  continuationId: string,
  target: Exclude<FocusedTarget, { kind: 'none' }>,
  runtime: AutofillRuntime | undefined,
  queueGeneration: number,
  frameUrl: string,
  selection?: FocusedFillCycleSelection,
): void {
  const existing = pendingKeyboardReprompts.get(continuationId);
  if (existing) window.clearTimeout(existing.timer);
  while (pendingKeyboardReprompts.size >= MAX_PENDING_KEYBOARD_REPROMPTS) {
    const oldest = pendingKeyboardReprompts.keys().next().value as string | undefined;
    if (!oldest) break;
    const entry = pendingKeyboardReprompts.get(oldest);
    if (entry) window.clearTimeout(entry.timer);
    pendingKeyboardReprompts.delete(oldest);
  }
  const expiresAt = Date.now() + KEYBOARD_REPROMPT_TTL_MS;
  const pending: PendingKeyboardReprompt = {
    target,
    ...(selection ? { selection } : {}),
    runtime,
    runtimeEpoch: runtime?.epoch,
    queueGeneration,
    frameUrl,
    expiresAt,
    timer: 0,
  };
  pending.timer = window.setTimeout(() => {
    if (pendingKeyboardReprompts.get(continuationId) === pending) {
      pendingKeyboardReprompts.delete(continuationId);
    }
  }, KEYBOARD_REPROMPT_TTL_MS);
  pendingKeyboardReprompts.set(continuationId, pending);
}

function keyboardRepromptCurrent(
  pending: PendingKeyboardReprompt,
  expectedFrameUrl: string,
): boolean {
  return pending.expiresAt > Date.now()
    && expectedFrameUrl === pending.frameUrl
    && expectedFrameUrl === window.location.href
    && focusedFillQueueGeneration === pending.queueGeneration
    && activeRuntime === pending.runtime
    && pending.runtime?.epoch === pending.runtimeEpoch
    && isFocusedTargetCurrent(pending.target, pending.runtime);
}

async function resumeKeyboardReprompt(continuationId: string, expectedFrameUrl: string): Promise<void> {
  const pending = pendingKeyboardReprompts.get(continuationId);
  if (!pending) return;
  pendingKeyboardReprompts.delete(continuationId);
  window.clearTimeout(pending.timer);
  const { target } = pending;
  if (!keyboardRepromptCurrent(pending, expectedFrameUrl)) return;
  const runtime = pending.runtime;
  if (!runtime) return;
  const response = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.continuation.redeemKeyboardReprompt',
    continuationId,
  }));
  if (!response.ok || !keyboardRepromptCurrent(pending, expectedFrameUrl)) return;
  const data: unknown = response.data;
  if (!isRecord(data) || !hasOnlyKeys(data, ['intentId']) || !isReservationId(data.intentId)) return;

  if (target.kind === 'login') {
    const current = boundedLoginCustomPlan(runtime, target.form);
    if (!current) return;
    rememberPendingInteractivePlan(data.intentId, current);
    const login = await redeemLoginIntent(runtime, data.intentId, true);
    if (!login.ok || !keyboardRepromptCurrent(pending, expectedFrameUrl)) return;
    const filled = fillInteractiveLogin(target.form, login.data, () => (
      keyboardRepromptCurrent(pending, expectedFrameUrl)
    ));
    settleClientEventAck(login.data, filled);
    if (filled) pending.selection?.commit(Date.now());
    return;
  }
  if (target.kind === 'totp') {
    const totp = await redeemTotpIntent(runtime, data.intentId, true);
    if (!totp.ok || !keyboardRepromptCurrent(pending, expectedFrameUrl)) return;
    if (!keyboardRepromptCurrent(pending, expectedFrameUrl)) return;
    const filled = fillTotpWithAuthority(target.input, totp.data.code, () => (
      keyboardRepromptCurrent(pending, expectedFrameUrl)
    ));
    settleClientEventAck(totp.data, filled);
    if (filled) pending.selection?.commit(Date.now());
    return;
  }
  const structuredTarget = captureStructuredTarget(target.form);
  if (!structuredTarget) return;
  const redeemed = await sendRequest(runtimeRequest(runtime, {
    type: 'autofill.keyboard.redeemStructuredIntent',
    intentId: data.intentId,
    target: structuredTarget,
  }));
  if (!redeemed.ok || !keyboardRepromptCurrent(pending, expectedFrameUrl)) return;
  const outcome: unknown = redeemed.data;
  if (!isRecord(outcome) || !hasOnlyKeys(outcome, ['outcome']) || !isTabFillOutcome(outcome.outcome)) return;
  if (outcome.outcome.status !== 'filled') showNotice(messageForTabFillOutcome(outcome.outcome));
}

export function handleFocusedFill(
  getFrameUrl: FrameUrlProvider = () => window.location.href,
  commandToken = '',
): Promise<void> {
  if (!isReservationId(commandToken)) return Promise.resolve();
  const queueGeneration = focusedFillQueueGeneration;
  const runtime = activeRuntime;
  const operation = focusedFillQueue.then(async () => {
    if (focusedFillQueueGeneration !== queueGeneration || activeRuntime !== runtime) return;
    await executeFocusedFill(getFrameUrl, runtime, queueGeneration, commandToken);
  });
  // Keep the queue usable after an unexpected transport or page exception while preserving the
  // original rejection for callers that explicitly await this invocation.
  focusedFillQueue = operation.catch(() => undefined);
  return operation;
}

async function executeFocusedFill(
  getFrameUrl: FrameUrlProvider,
  runtime: AutofillRuntime | undefined,
  queueGeneration: number,
  commandToken: string,
): Promise<void> {
  if (!document.hasFocus()) return;                                   // non-focused frame
  runtime?.documentController.refresh();
  const el = runtime?.documentController.deepActiveElement() ?? document.activeElement;
  // Ancestor frame — focus is in a child. HTMLFrameElement is obsolete (no <frameset> in modern
  // pages) and isn't defined in every DOM implementation (e.g. happy-dom in tests), so guard it.
  if (el instanceof HTMLIFrameElement || (typeof HTMLFrameElement !== 'undefined' && el instanceof HTMLFrameElement)) return;
  const target = resolveFocusedFill(el, runtime?.documentController.snapshot() ?? document);
  if (target.kind === 'none') {
    focusedFillCycle.reset();
    showNotice(NOTICE_FOCUS);
    return;
  }
  if (!runtime) return;
  const keyboard = await claimKeyboardGrant(runtime, commandToken, target);
  if (!keyboard.ok) {
    showNotice(keyboard.message);
    return;
  }
  if (focusedFillQueueGeneration !== queueGeneration || activeRuntime !== runtime) return;
  await runFocusedFill(target, focusedFillDeps(getFrameUrl, runtime, queueGeneration, keyboard.data));
}

function isFocusedTargetCurrent(expected: FocusedTarget, runtime: AutofillRuntime | undefined): boolean {
  if (!document.hasFocus() || activeRuntime !== runtime) return false;
  runtime?.documentController.refresh();
  const activeElement = runtime?.documentController.deepActiveElement() ?? document.activeElement;
  if (activeElement instanceof HTMLIFrameElement
      || (typeof HTMLFrameElement !== 'undefined' && activeElement instanceof HTMLFrameElement)) return false;
  const current = resolveFocusedFill(activeElement, runtime?.documentController.snapshot() ?? document);
  if (expected.kind === 'login' && current.kind === 'login') {
    return expected.input === current.input
      && expected.form.id === current.form.id
      && expected.form.form === current.form.form
      && expected.form.anchor === current.form.anchor
      && expected.form.usernameInput === current.form.usernameInput
      && expected.form.passwordInput === current.form.passwordInput
      && expected.form.totpInput === current.form.totpInput
      && hasSameTotpInputs(expected.form, current.form);
  }
  if (expected.kind === 'totp' && current.kind === 'totp') {
    return expected.input === current.input
      && expected.form.id === current.form.id
      && expected.form.form === current.form.form
      && expected.form.anchor === current.form.anchor
      && expected.form.usernameInput === current.form.usernameInput
      && expected.form.passwordInput === current.form.passwordInput
      && expected.form.totpInput === current.form.totpInput
      && hasSameTotpInputs(expected.form, current.form);
  }
  if ((expected.kind === 'card' || expected.kind === 'identity') && current.kind === expected.kind) {
    return expected.form.id === current.form.id
      && expected.form.anchor === current.form.anchor
      && expected.form.fields.size === current.form.fields.size
      && [...expected.form.fields].every(([role, field]) => current.form.fields.get(role) === field);
  }
  return false;
}

function contextReservationCurrent(
  command: Pick<FillCommand, 'expectedFrameUrl' | 'kind' | 'scope' | 'roles'>,
  contextTarget: Element,
  reservation: ReservedContextTarget,
): boolean {
  if (command.expectedFrameUrl !== window.location.href
      || !contextTarget.isConnected
      || contextTarget.ownerDocument !== document
      || rootForElement(contextTarget) !== reservation.root) return false;
  if (command.scope !== 'field') return true;
  const field = reservation.fieldBinding;
  return Boolean(
    field
    && field.kind === command.kind
    && command.roles.length === 1
    && field.role === command.roles[0]
    && contextFieldAuthorityCurrent(
      contextTarget,
      field.owner,
      field.slotPath,
      field.kind,
      field.role,
    ),
  );
}

function fillWholeForm(
  command: FillCommand,
  contextTarget: Element,
  reservation: ReservedContextTarget,
): boolean {
  const targetRoot = reservation.root;
  const expectedFormId = reservation.formId;
  if (!expectedFormId || rootForElement(contextTarget) !== targetRoot) return false;
  const runtime = activeRuntime;
  const projection = runtime
    ? computeFillProjection(runtime.documentController.refresh())
    : computeFillProjection(targetRoot);
  if (!projection.complete) return false;
  const forms = (command.kind === 'card' ? projection.cardForms : projection.identityForms)
    .filter((candidate) => candidate.anchor.getRootNode() === targetRoot);
  const form = forms.find((candidate) => candidate.id === expectedFormId && containsField(candidate, contextTarget));
  if (!form || !equalFillRoles(command.kind, [...form.fields.keys()], command.roles)) return false;
  const staged = createStagedFillCommit(() => {
    if (
      command.expectedFrameUrl !== window.location.href
      || !contextTarget.isConnected
      || contextTarget.ownerDocument !== document
      || rootForElement(contextTarget) !== targetRoot
      || form.anchor.getRootNode() !== targetRoot
    ) return false;
    const currentProjection = runtime
      ? computeFillProjection(runtime.documentController.refresh())
      : computeFillProjection(targetRoot);
    if (!currentProjection.complete) return false;
    const currentForms = (command.kind === 'card'
      ? currentProjection.cardForms
      : currentProjection.identityForms)
      .filter((candidate) => candidate.anchor.getRootNode() === targetRoot);
    const current = currentForms.find((candidate) => (
      candidate.id === expectedFormId && containsField(candidate, contextTarget)
    ));
    return Boolean(
      current
      && equalFillRoles(command.kind, [...current.fields.keys()], command.roles)
      && sameDetectedFillForm(form, current),
    );
  });
  return command.kind === 'card'
    ? fillCardForm(form, command.data as CardFillData, staged)
    : fillIdentityForm(form, command.data as IdentityFillData, staged);
}

function sameDetectedFillForm(first: DetectedFillForm, second: DetectedFillForm): boolean {
  return first.kind === second.kind
    && first.id === second.id
    && first.anchor === second.anchor
    && first.fields.size === second.fields.size
    && [...first.fields].every(([role, field]) => second.fields.get(role) === field);
}

function fillSingleField(
  command: FillCommand,
  el: Element,
  reservation: ReservedContextTarget,
): boolean {
  if (!contextReservationCurrent(command, el, reservation)) return false;
  const reservedRole = reservation.fieldBinding?.role;
  if (!(el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement)
      || !reservedRole) return false;
  const staged = createStagedFillCommit(() => contextReservationCurrent(command, el, reservation));
  const hints = contextFieldHints(el);
  if (command.kind === 'card') {
    const role = classifyCardField(hints);
    if (!role || role !== reservedRole) return false;
    const form = { kind: 'card' as const, id: 'vw-ctx', fields: new Map([[role as CardRole, el as FillFieldElement]]), anchor: el };
    return fillCardForm(form, command.data as CardFillData, staged);
  } else {
    const role = classifyIdentityField(hints);
    if (!role || role !== reservedRole) return false;
    const form = { kind: 'identity' as const, id: 'vw-ctx', fields: new Map([[role as IdentityRole, el as FillFieldElement]]), anchor: el };
    return fillIdentityForm(form, command.data as IdentityFillData, staged);
  }
}

function containsField(form: DetectedFillForm, el: Element): boolean {
  const nativeForm = el instanceof HTMLInputElement || el instanceof HTMLSelectElement
    || el instanceof HTMLTextAreaElement || el instanceof HTMLButtonElement
    ? el.form
    : el.closest('form');
  for (const field of form.fields.values()) {
    if (field === el || (nativeForm && field.form === nativeForm)) return true;
  }
  return false;
}

function totpExpiry(data: AutofillTotpData): number {
  const lifetimeSeconds = data.remaining > 0 ? data.remaining : data.period;
  return Date.now() + lifetimeSeconds * 1000;
}

function isContentCommand(value: unknown): value is ContentCommand {
  if (!isRecord(value)) return false;
  if (value.type === 'autofill.focusedFill') return isReservationId(value.commandToken);
  if (value.type === 'autofill.clientConfigChanged') return true;
  if (value.type === 'autofill.saveCaptureConfirmed') {
    return hasOnlyKeys(value, ['type', 'captureId']) && isReservationId(value.captureId);
  }
  if (value.type === 'autofill.claimContextLoginTarget') {
    return typeof value.expectedFrameUrl === 'string'
      && typeof value.contextMenuClickTime === 'number'
      && Number.isFinite(value.contextMenuClickTime);
  }
  if (value.type === 'autofill.reserveFillTarget' || value.type === 'autofill.cancelFillTarget') {
    return isReservationId(value.reservationId)
      && typeof value.expectedFrameUrl === 'string'
      && (value.type === 'autofill.reserveFillTarget'
        || isRuntimeIncarnation(value.expectedRuntimeIncarnation))
      && (value.type !== 'autofill.reserveFillTarget'
        || ((value.scope === 'form' || value.scope === 'field')
          && (value.kind === 'card' || value.kind === 'identity')
          && typeof value.contextMenuClickTime === 'number'
          && Number.isFinite(value.contextMenuClickTime)));
  }
  if (value.type === 'autofill.fillError') {
    return value.code === 'reprompt_required'
      && isReservationId(value.reservationId)
      && typeof value.expectedFrameUrl === 'string'
      && isRuntimeIncarnation(value.expectedRuntimeIncarnation);
  }
  if (value.type === 'autofill.holdFillTarget') {
    return isReservationId(value.reservationId)
      && isReservationId(value.holdId)
      && typeof value.expectedFrameUrl === 'string'
      && isRuntimeIncarnation(value.expectedRuntimeIncarnation);
  }
  if (value.type === 'autofill.cancelHeldFillTarget') {
    return isReservationId(value.holdId)
      && typeof value.expectedFrameUrl === 'string'
      && isRuntimeIncarnation(value.expectedRuntimeIncarnation);
  }
  if (value.type === 'autofill.resumeKeyboardReprompt') {
    return isReservationId(value.continuationId)
      && typeof value.expectedFrameUrl === 'string'
      && isRuntimeIncarnation(value.expectedRuntimeIncarnation);
  }
  if (value.type === 'autofill.awaitFocus') {
    return isReservationId(value.requestId)
      && typeof value.expectedFrameUrl === 'string'
      && isRuntimeIncarnation(value.expectedRuntimeIncarnation)
      && Number.isSafeInteger(value.expiresAt)
      && (value.expiresAt as number) > Date.now()
      && (value.expiresAt as number) - Date.now() <= KEYBOARD_REPROMPT_TTL_MS;
  }
  if (value.type === 'autofill.resumeHeldFillTarget') {
    return isReservationId(value.holdId)
      && (value.scope === 'form' || value.scope === 'field')
      && (value.kind === 'card' || value.kind === 'identity')
      && isCanonicalCommandRoles(value.kind, value.scope, value.roles)
      && typeof value.expectedFrameUrl === 'string'
      && isRuntimeIncarnation(value.expectedRuntimeIncarnation)
      && isMinimalFillData(value.kind, value.roles, value.data);
  }
  return value.type === 'autofill.fill'
    && isReservationId(value.reservationId)
    && (value.scope === 'form' || value.scope === 'field')
    && (value.kind === 'card' || value.kind === 'identity')
    && isCanonicalCommandRoles(value.kind, value.scope, value.roles)
    && typeof value.expectedFrameUrl === 'string'
    && isRuntimeIncarnation(value.expectedRuntimeIncarnation)
    && isMinimalFillData(value.kind, value.roles, value.data);
}

function isCanonicalCommandRoles(
  kind: 'card' | 'identity',
  scope: 'form' | 'field',
  value: unknown,
): value is FillRole[] {
  if (!Array.isArray(value)) return false;
  const normalized = normalizeFillRoles(kind, value);
  if (!normalized || (scope === 'field' && normalized.length !== 1)) return false;
  return normalized.length === value.length
    && normalized.every((role, index) => role === value[index]);
}

function isMinimalFillData(
  kind: 'card' | 'identity',
  roles: readonly FillRole[],
  value: unknown,
): value is CardFillData | IdentityFillData {
  if (!isRecord(value)) return false;
  const allowed = fillDataKeysForRoles(kind, roles);
  if (!allowed) return false;
  const allowedKeys = new Set<string>(allowed);
  return Object.entries(value).every(([key, field]) => allowedKeys.has(key) && typeof field === 'string');
}

const RESERVATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isReservationId(value: unknown): value is string {
  return typeof value === 'string' && RESERVATION_ID.test(value);
}

function isFrameAutofillMessage(value: unknown): value is FrameAutofillMessage {
  if (!isRecord(value)) return false;
  if (value.type === 'autofill.inspectFrame') return true;
  const common = typeof value.formId === 'string'
    && typeof value.expectedFrameUrl === 'string'
    && isRuntimeIncarnation(value.expectedRuntimeIncarnation)
    && typeof value.expectedGeneration === 'number'
    && Number.isSafeInteger(value.expectedGeneration)
    && value.expectedGeneration > 0;
  if (!common) return false;
  if (value.type === 'autofill.commitLoginFill') {
    const customPlan = parseLoginCustomTargetPlan(value.customPlan);
    const customAssignments = parseLoginCustomAssignments(value.customAssignments);
    return isAutofillLoginData(value.login)
      && customPlan !== undefined
      && isLoginCustomPlanDigest(value.customPlanDigest)
      && customAssignments !== undefined
      && assignmentsBelongToPlan(customAssignments, customPlan);
  }
  if (value.type !== 'autofill.commitStructuredFill'
      || (value.kind !== 'card' && value.kind !== 'identity')
      || !isCanonicalCommandRoles(value.kind, 'form', value.roles)) return false;
  if (Object.hasOwn(value, 'selectedRoles')) {
    if (!isCanonicalCommandRoles(value.kind, 'form', value.selectedRoles)
        || !(value.selectedRoles as readonly FillRole[]).every((role) => (value.roles as readonly FillRole[]).includes(role))) return false;
    return isMinimalFillData(value.kind, value.selectedRoles, value.data);
  }
  return isMinimalFillData(value.kind, value.roles, value.data);
}

export function relayFido2FallbackMessage(
  event: Pick<MessageEvent, 'data' | 'isTrusted' | 'origin' | 'source'>,
  currentWindow: Window = window,
  request: typeof sendRequest = sendRequest,
): boolean {
  if (!event.isTrusted
      || currentWindow.top !== currentWindow
      || event.source !== currentWindow
      || event.origin !== currentWindow.location.origin
      || !isRecord(event.data)) {
    return false;
  }
  const keys = Object.keys(event.data);
  if (keys.length !== 3
      || !keys.every((key) => key === 'command' || key === 'data' || key === 'remember')
      || event.data.command !== 'webAuthnResult'
      || typeof event.data.data !== 'string'
      || event.data.data.length === 0
      || event.data.data.length > 32 * 1_024
      || typeof event.data.remember !== 'boolean') {
    return false;
  }
  void request({
    type: 'auth.completeFido2',
    token: event.data.data,
    remember: event.data.remember,
  }).catch(() => undefined);
  return true;
}

startAutofill();
