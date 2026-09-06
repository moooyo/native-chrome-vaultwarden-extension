import type { AuthResult, AuthService } from '../core/session/auth-service.js';
import type { VaultService } from '../core/vault/vault-service.js';
import { UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { LockTimeoutSetting, OnIdleAction, ClipboardClearSetting } from './settings.js';
import {
  DEFAULT_AUTOFILL_POLICY_SETTINGS,
  DEFAULT_WEBSITE_PASSKEY_SETTINGS,
  WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
  normalizeServerUrl,
  sanitizeAutofillSettings,
  sanitizeWebsitePasskeySettings,
  type AutofillSettings,
  type AutofillPolicySettings,
  type WebsitePasskeySettings,
} from './settings.js';
import type {
  AutofillSecretPurpose,
  AutofillInteractiveLoginData,
  AutofillSaveCaptureSubmission,
  ContentStructuredAutofillTarget,
  KeyboardAutofillClaimBinding,
  RequestMessage,
  ResponseMessage,
  TabFillOutcome,
  TabSuggestionsOutcome,
  TabSuggestionTarget,
} from '../messaging/protocol.js';
import { isExactPasswordHintRequest } from '../messaging/password-hint.js';
import { isExactTwoFactorRecoveryRequest } from '../messaging/two-factor-recovery.js';
import { isExactCipherFavoriteRequest } from '../messaging/cipher-favorite.js';
import { isContentTotpClipboardCode } from '../messaging/totp-clipboard-code.js';
import { AppError } from '../core/errors.js';
import {
  PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  canonicalizeVaultTransferExportTarget,
  type VaultTransferExportTarget,
} from '../core/vault/vault-transfer-target.js';
import type { RequestContext } from './sender-guard.js';
import type { SsoBrowserCoordinator } from './sso-browser.js';
import type { DuoBrowserCoordinator } from './duo-browser.js';
import type { VaultTimeoutActivityLease, VaultTimeoutController } from './vault-timeout-controller.js';
import type { VaultReleaseGate, VaultReleaseLease } from './vault-release-gate.js';
import type { SessionLease, SessionLeaseGate } from '../core/session/session-manager.js';
import { pinConstraintMessage, pinConstraintViolation } from '../core/session/pin-constraints.js';
import type { AccountLease, AccountLeaseGate } from '../core/session/account-gate.js';
import type { AutofillIntentRegistry } from './autofill-intent-registry.js';
import type { AutofillPolicyGate } from './autofill-policy-gate.js';
import {
  assertAutofillAuthorizationPolicy,
  captureAutofillAuthorizationPolicy,
  resolveAutofillAuthorizationGeneratorPolicy,
  resolveAutofillAuthorizationUriMatchDefault,
  type AutofillAuthorizationPolicyLease,
} from './autofill-authorization-policy.js';
import type { VaultExportGrantRegistry } from './vault-export-grant-registry.js';
import type {
  RepromptAutofillGrantBinding,
  RepromptAutofillGrantRegistry,
} from './reprompt-autofill-grant-registry.js';
import type { ResolvedRepromptAutofillBinding } from './tab-autofill.js';
import type { ManualAutofillCoordinator } from './manual-autofill-coordinator.js';
import type { AutofillContinuationCoordinator } from './autofill-continuation-coordinator.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import type {
  AutofillPendingSaveCredentials,
  AutofillPendingSaveDecision,
  AutofillPendingSaveDocumentContext,
  AutofillPendingSaveStore,
} from './autofill-pending-save-store.js';
import type {
  AutofillSaveCaptureCoordinator,
  AutofillSaveCaptureRuntimeAuthority,
} from './autofill-save-capture-coordinator.js';
import type {
  AutofillKeyboardGrantRegistry,
  KeyboardGrant,
  KeyboardGrantBinding,
  KeyboardGrantContext,
} from './autofill-keyboard-grant-registry.js';
import type {
  AutofillUsernameStageContext,
  AutofillUsernameStageStore,
} from './autofill-username-stage-store.js';
import type { PageLoadFillDeduper } from './page-load-fill-deduper.js';
import {
  decideAutofillPolicy,
  normalizeAutofillBlocklist,
  type AutofillPolicyAction,
} from '../core/vault/autofill-policy.js';
import {
  enterprisePolicyAllows,
  type EffectiveEnterprisePolicySnapshot,
  type EnterprisePolicyGate,
  type PolicyLease,
} from '../core/policy/effective-enterprise-policy.js';
import { resolveEnterpriseUriMatchDefault } from '../core/policy/enterprise-uri-match-default.js';
import {
  createGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
} from '../core/generator/enterprise-password-policy.js';
import { parseGeneratorHistoryEntries } from '../core/generator/history.js';
import type {
  GeneratorHistoryProductionService,
} from './generator-history-production.js';
import {
  isVaultTimeoutActionAllowed,
  isVaultTimeoutValueAllowed,
  resolveEffectiveVaultTimeout,
  type MaximumVaultTimeoutPolicyState,
} from './vault-timeout-policy.js';
import {
  digestLoginCustomTargetPlan,
  parseLoginCustomAssignments,
  parseLoginCustomTargetPlan,
  type LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';
import { normalizeFillRoles } from '../core/vault/fill-roles.js';
import {
  WEBSITE_PASSKEY_POPUP_PATH,
  type WebsitePasskeyCoordinator,
  type WebsitePasskeySelection,
} from './website-passkey-coordinator.js';
import type {
  DeviceLoginCoordinator,
  DeviceLoginCoordinatorResult,
} from './device-login-coordinator.js';
import {
  sameInteractiveTwoFactorOwner,
  type InteractiveTwoFactorBroker,
} from '../core/session/interactive-two-factor.js';
import type { InteractiveTwoFactorConnectorDocument } from './interactive-two-factor-browser.js';
import type { AccountPasskeyBrowserOrchestrator } from './account-passkey-browser.js';
import type {
  DeviceLoginApprovalService,
  DeviceLoginDecisionReceipt,
} from './device-login-approval-service.js';
import {
  ClientEventType,
  type CipherClientEventType,
} from '../core/events/client-event.js';
import type {
  ClientEventPreparationRequest,
  ClientEventReceipt,
  ClientEventService,
} from './client-event-service.js';
import type {
  ClientEventAccountRemovalReceipt,
  ClientEventServerChangeReceipt,
} from './client-event-production.js';
import { bestEffortClientEvent } from './client-event-best-effort.js';
import {
  type ClientEventAckOwner,
  type ClientEventAckRegistry,
} from './client-event-ack-registry.js';
import {
  DEFAULT_HTTP_AUTH_SETTINGS,
  HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
  sanitizeHttpAuthSettings,
  type HttpAuthSettings,
  type HttpAuthSettingsReadResult,
} from './http-auth-settings.js';
import {
  parseWebsitePasskeyIframeInventoryRequest,
} from '../messaging/website-passkey-iframe-inventory.js';
import type {
  WebsitePasskeyPermissionsPolicyResolver,
} from './website-passkey-permissions-policy.js';
import type { AutofillTotpCopyAckRegistry } from './autofill-totp-copy-ack-registry.js';
import type { InlineGeneratorTrackTokenRegistry } from './inline-generator-track-token-registry.js';

export interface RouterDeps {
  auth: Partial<AuthService>;
  /** Shared logout wrapper used by Popup, timeout, and notification initiated logouts. */
  logout?: () => Promise<void>;
  vault: Partial<VaultService>;
  generatorHistory?: Pick<
    GeneratorHistoryProductionService,
    | 'list'
    | 'track'
    | 'clear'
  >;
  sessionGate: SessionLeaseGate;
  accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  vaultTimeout?: Pick<VaultTimeoutController, 'captureActivity' | 'recordActivity'>
    & Partial<Pick<VaultTimeoutController, 'settlePendingAction'>>;
  vaultReleaseGate?: Pick<VaultReleaseGate, 'capture' | 'checkpoint' | 'assertAuthorities' | 'assert'>;
  autofillPolicyGate: Pick<AutofillPolicyGate, 'capture' | 'assert' | 'invalidate'>;
  autofillIntents: Pick<AutofillIntentRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>, 'issue' | 'redeem'>;
  pendingSaves?: Pick<AutofillPendingSaveStore, 'put' | 'claim' | 'take' | 'dismiss'>;
  saveCaptureCoordinator?: Pick<
    AutofillSaveCaptureCoordinator,
    | 'activateRuntime'
    | 'isRuntimeCurrent'
    | 'captureRuntimeAuthority'
    | 'stage'
    | 'stageUsername'
    | 'consumeUsername'
    | 'claimPendingSave'
    | 'takePendingSave'
    | 'dismissPendingSave'
  >;
  /** Returns an owned key copy. Pending-save stores consume and zero both halves. */
  loadPendingSaveUserKey?: () => Promise<SymmetricKey | undefined>;
  keyboardGrants: Pick<
    AutofillKeyboardGrantRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>,
    'takeCommand' | 'issueGrant' | 'authorizeGrant' | 'consumeGrant'
  >;
  getKeyboardTopDocument(tabId: number): Promise<{ documentId: string; url: string } | undefined>;
  getContentDocument?(
    tabId: number,
    frameId: number,
  ): Promise<{ documentId: string; url: string } | undefined>;
  usernameStages?: Pick<AutofillUsernameStageStore, 'stage' | 'consume'>;
  getSessionBindingId?: () => Promise<string | undefined>;
  pageLoadFillDeduper: Pick<PageLoadFillDeduper, 'claim' | 'persist'>;
  enterprisePolicyGate: Pick<EnterprisePolicyGate, 'capture' | 'assert'>;
  exportGrants?: Pick<
    VaultExportGrantRegistry<SessionLease, AccountLease, PolicyLease>,
    'issue'
  >;
  repromptAutofillGrants?: Pick<
    RepromptAutofillGrantRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>,
    'issue' | 'redeem'
  >;
  manualAutofill?: Pick<ManualAutofillCoordinator, 'prepare' | 'cancel' | 'commit'>;
  autofillContinuation?: Pick<
    AutofillContinuationCoordinator,
    'status' | 'cancel' | 'resumeUnlock' | 'authorizeReprompt' | 'stageKeyboardReprompt' | 'redeemKeyboardReprompt'
  >;
  clientEvents?: Pick<ClientEventService, 'prepare' | 'commit'> & {
    flushActive(): Promise<unknown>;
    captureAccountRemoval(accountIdentity: string): Promise<ClientEventAccountRemovalReceipt>;
    completeAccountRemoval(receipt: ClientEventAccountRemovalReceipt): Promise<unknown>;
    captureServerChange(serverUrl: string): Promise<ClientEventServerChangeReceipt>;
    completeServerChange(receipt: ClientEventServerChangeReceipt): Promise<unknown>;
    supportsOrganizationDecline?(): boolean;
  };
  clientEventAcks?: Pick<ClientEventAckRegistry, 'issue' | 'consume'>;
  autofillTotpCopies?: Pick<
    AutofillTotpCopyAckRegistry,
    'issueContent' | 'consumeContent' | 'revokeAll'
  >;
  inlineGeneratorTracks?: Pick<
    InlineGeneratorTrackTokenRegistry,
    'issue' | 'consume' | 'revokeAll'
  >;
  settings: {
    getServerUrl(): Promise<string | undefined>;
    saveServerUrl(serverUrl: string): Promise<void>;
    getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting>;
    saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void>;
    getAutofillSettings?(): Promise<Readonly<AutofillSettings>>;
    saveAutofillSettings?(settings: AutofillSettings): Promise<void>;
    getAutofillPolicySettings?(): Promise<Readonly<AutofillPolicySettings>>;
    saveAutofillPolicySettings?(
      settings: AutofillPolicySettings,
      assertCurrent?: () => void,
    ): Promise<void>;
    getShowMatchingLoginCount?(): Promise<boolean>;
    saveShowMatchingLoginCount?(value: boolean): Promise<void>;
    getWebsitePasskeySettings?(): Promise<Readonly<WebsitePasskeySettings>>;
    saveWebsitePasskeySettings?(settings: WebsitePasskeySettings): Promise<void>;
    getLockTimeout(): Promise<LockTimeoutSetting>;
    saveLockTimeout(value: LockTimeoutSetting): Promise<void>;
    getOnIdleAction(): Promise<OnIdleAction>;
    saveOnIdleAction(value: OnIdleAction): Promise<void>;
    getClipboardClearSetting(): Promise<ClipboardClearSetting>;
    saveClipboardClearSetting(value: ClipboardClearSetting): Promise<void>;
  };
  httpAuthSettings?: {
    get(): Promise<Readonly<HttpAuthSettingsReadResult>>;
    save(settings: HttpAuthSettings): Promise<void>;
  };
  clipboard?: {
    scheduleClear(value: string): Promise<void>;
    cancelClear?(): void;
  };
  tabAutofill?: {
    getSuggestions(tabId: number): Promise<TabSuggestionsOutcome>;
    resolveRepromptBinding?(
      tabId: number,
      target: TabSuggestionTarget,
    ): Promise<ResolvedRepromptAutofillBinding | undefined>;
    fill(
      tabId: number,
      cipherId: string,
      target: TabSuggestionTarget,
      assertExternalCurrent?: () => void,
      repromptAuthorization?: { readonly assertCurrent: () => void },
    ): Promise<TabFillOutcome>;
  };
  syncScheduler?: {
    manual(): Promise<void>;
    popupOpened(): Promise<void>;
    getLastSuccess(): Promise<number | undefined>;
    getSyncStatus(): Promise<{ identity?: string; lastSuccessfulSyncAt?: number; dirty: boolean; syncing: boolean }>;
  };
  fido2Connector?: {
    open(
      url: string,
      replace?: InteractiveTwoFactorConnectorDocument,
    ): Promise<InteractiveTwoFactorConnectorDocument>;
    close(document: InteractiveTwoFactorConnectorDocument): Promise<boolean | void>;
    finish(
      document: InteractiveTwoFactorConnectorDocument,
      outcome: 'success' | 'error',
    ): Promise<void>;
  };
  interactiveTwoFactor?: {
    readonly password: InteractiveTwoFactorBroker<AuthResult>;
    readonly deviceLogin: InteractiveTwoFactorBroker<DeviceLoginCoordinatorResult>;
  };
  accountPasskey?: Pick<AccountPasskeyBrowserOrchestrator, 'begin' | 'status' | 'cancel'>;
  sso?: Pick<SsoBrowserCoordinator, 'begin' | 'status' | 'cancel' | 'cancelCurrent' | 'reconcileHandoff'>;
  ssoRequirement?: { isRequired(email: string): Promise<boolean> };
  duo?: Pick<
    DuoBrowserCoordinator,
    'begin' | 'cancel' | 'cancelDeviceLogin' | 'cancelCurrent' | 'retireInvalidWaiting'
  >;
  websitePasskeys?: Pick<
    WebsitePasskeyCoordinator<unknown>,
    | 'getApproval'
    | 'approve'
    | 'fallbackOnce'
    | 'fallbackAlways'
    | 'cancel'
    | 'getLockedContinuation'
    | 'resumeLockedContinuation'
    | 'cancelLockedContinuation'
  >;
  websitePasskeyPermissionsPolicy?: Pick<
    WebsitePasskeyPermissionsPolicyResolver,
    'recordIframeAllowReport' | 'invalidateFrame'
  >;
  deviceLogin?: Pick<
    DeviceLoginCoordinator,
    | 'begin'
    | 'status'
    | 'retryActivation'
    | 'submitTwoFactor'
    | 'sendEmailCode'
    | 'cancel'
    | 'cancelCurrent'
  >;
  deviceLoginApprovals?: Pick<DeviceLoginApprovalService, 'list' | 'get' | 'approve' | 'deny'>;
  twoFactorRecovery?: {
    open(): Promise<void>;
  };
  onDeviceLoginApprovalDecision?: () => void | PromiseLike<void>;
  onDeviceLoginApprovalPopupOpened?: () => void | PromiseLike<void>;
}

async function prepareClientEvent(
  deps: RouterDeps,
  request: ClientEventPreparationRequest,
): Promise<ClientEventReceipt | undefined> {
  const events = deps.clientEvents;
  return events ? bestEffortClientEvent(() => events.prepare(request)) : undefined;
}

async function commitClientEvent(
  deps: RouterDeps,
  receipt: ClientEventReceipt | undefined,
): Promise<void> {
  const events = deps.clientEvents;
  if (!receipt || !events) return;
  await bestEffortClientEvent(() => events.commit(receipt));
}

async function issueClientEventAck(
  deps: RouterDeps,
  owner: ClientEventAckOwner,
  request: ClientEventPreparationRequest,
  assertCurrent: () => void,
  vaultReadAuthorities: readonly (() => void)[],
): Promise<string | undefined> {
  const acks = deps.clientEventAcks;
  if (!acks) return undefined;
  const capturedReadAuthorities = Object.freeze([...vaultReadAuthorities]);
  const assertAckCurrent = (): void => {
    assertCurrent();
    for (const assertVaultReadCurrent of capturedReadAuthorities) assertVaultReadCurrent();
  };
  const receipt = await prepareClientEvent(deps, request);
  if (!receipt) return undefined;
  try {
    assertAckCurrent();
    return acks.issue(owner, receipt, assertAckCurrent);
  } catch {
    return undefined;
  }
}

function popupClientEventOwner(
  context: RequestContext,
): Extract<ClientEventAckOwner, { readonly kind: 'popup' }> {
  const caller = requirePopupDocument(context);
  return Object.freeze({ kind: 'popup', documentId: caller.documentId });
}

function contentClientEventOwner(
  tabId: number,
  frameId: number,
  documentId: string,
): Extract<ClientEventAckOwner, { readonly kind: 'content' }> {
  return Object.freeze({ kind: 'content', tabId, frameId, documentId });
}

function clientEventAckOwnerFromContext(context: RequestContext): unknown {
  if (context.kind === 'content') {
    return context.documentId
      ? contentClientEventOwner(context.tabId, context.frameId, context.documentId)
      : Object.freeze({ kind: 'invalid' });
  }
  if (!context.documentId) return Object.freeze({ kind: 'invalid' });
  try {
    const path = new URL(context.url).pathname;
    if (path === WEBSITE_PASSKEY_POPUP_PATH) {
      return Object.freeze({ kind: 'popup', documentId: context.documentId });
    }
    if (path === '/ui/options/options.html') {
      return Object.freeze({ kind: 'options', documentId: context.documentId });
    }
  } catch {
    // The registry consumes the opaque ID before rejecting this invalid owner.
  }
  return Object.freeze({ kind: 'invalid' });
}

function popupAckCurrent(
  deps: RouterDeps,
  sessionLease: SessionLease | undefined,
): () => void {
  if (!sessionLease) throw new AppError('session_expired', 'Vault session changed.');
  const accountLease = deps.accountGate.capture();
  return () => {
    deps.sessionGate.assert(sessionLease);
    deps.accountGate.assert(accountLease);
  };
}

async function issueAutofillTotpCopyAck(
  deps: RouterDeps,
  request: {
    readonly owner: { readonly tabId: number; readonly frameId: number; readonly documentId: string };
    readonly cipherId: string;
    readonly frameUrl: string;
    readonly defaultStrategy: UriMatchStrategySetting;
    readonly assertCurrent: () => void;
    readonly assertRepromptAuthorized?: () => void;
  },
): Promise<string | undefined> {
  const copies = deps.autofillTotpCopies;
  const getTotp = deps.vault.getAutofillTotpData;
  if (!copies || !getTotp) return undefined;
  const totpAuthorities: Array<() => void> = [];
  try {
    request.assertCurrent();
    const totp = await getTotp(
      request.cipherId,
      request.frameUrl,
      request.defaultStrategy,
      (assertCurrent) => { totpAuthorities.push(assertCurrent); },
      request.assertRepromptAuthorized,
    );
    const capturedTotpAuthorities = Object.freeze([...totpAuthorities]);
    const assertCurrent = (): void => {
      request.assertCurrent();
      for (const assertTotpCurrent of capturedTotpAuthorities) assertTotpCurrent();
    };
    assertCurrent();
    return copies.issueContent(request.owner, totp.code, assertCurrent);
  } catch {
    return undefined;
  }
}

function fieldClientEventType(
  field: string,
  purpose: 'reveal' | 'copy' | undefined,
): CipherClientEventType | undefined {
  if (purpose === undefined) return undefined;
  if (purpose !== 'reveal' && purpose !== 'copy') {
    throw new AppError('denied', 'Client event purpose is invalid.');
  }
  if (field === 'password') {
    return purpose === 'reveal'
      ? ClientEventType.Cipher_ClientToggledPasswordVisible
      : ClientEventType.Cipher_ClientCopiedPassword;
  }
  if (field === 'card.code') {
    return purpose === 'reveal'
      ? ClientEventType.Cipher_ClientToggledCardCodeVisible
      : ClientEventType.Cipher_ClientCopiedCardCode;
  }
  if (field === 'card.number' && purpose === 'reveal') {
    return ClientEventType.Cipher_ClientToggledCardNumberVisible;
  }
  return undefined;
}

async function flushActiveClientEvents(deps: RouterDeps): Promise<void> {
  const events = deps.clientEvents;
  if (events) await bestEffortClientEvent(() => events.flushActive());
}

interface ClientEventLifecycleCapture<Receipt> {
  readonly receipt: Promise<Receipt | undefined>;
}

async function captureAccountRemovalClientEvents(
  deps: RouterDeps,
  accountIdentity: string,
): Promise<ClientEventLifecycleCapture<ClientEventAccountRemovalReceipt> | undefined> {
  const events = deps.clientEvents;
  if (!events) return undefined;
  const receipt = Promise.resolve()
    .then(() => events.captureAccountRemoval(accountIdentity))
    .catch(() => undefined);
  await bestEffortClientEvent(() => receipt);
  return Object.freeze({ receipt });
}

async function completeAccountRemovalClientEvents(
  deps: RouterDeps,
  capture: ClientEventLifecycleCapture<ClientEventAccountRemovalReceipt> | undefined,
): Promise<void> {
  const events = deps.clientEvents;
  if (!capture || !events) return;
  await bestEffortClientEvent(async () => {
    const receipt = await capture.receipt;
    if (receipt) await events.completeAccountRemoval(receipt);
  });
}

async function captureServerChangeClientEvents(
  deps: RouterDeps,
  serverUrl: string,
): Promise<ClientEventLifecycleCapture<ClientEventServerChangeReceipt> | undefined> {
  const events = deps.clientEvents;
  if (!events) return undefined;
  const receipt = Promise.resolve()
    .then(() => events.captureServerChange(serverUrl))
    .catch(() => undefined);
  await bestEffortClientEvent(() => receipt);
  return Object.freeze({ receipt });
}

async function completeServerChangeClientEvents(
  deps: RouterDeps,
  capture: ClientEventLifecycleCapture<ClientEventServerChangeReceipt> | undefined,
): Promise<void> {
  const events = deps.clientEvents;
  if (!capture || !events) return;
  await bestEffortClientEvent(async () => {
    const receipt = await capture.receipt;
    if (receipt) await events.completeServerChange(receipt);
  });
}

async function authIsAlreadyLoggedOut(deps: RouterDeps): Promise<boolean> {
  if (!deps.auth.getState) return false;
  try {
    return await deps.auth.getState() === 'loggedOut';
  } catch {
    return false;
  }
}

type EnterprisePolicyRead =
  | { readonly kind: 'unmanaged' }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'captured'; readonly lease: PolicyLease };

function beginEnterprisePolicyRead(deps: RouterDeps): EnterprisePolicyRead {
  const gate = deps.enterprisePolicyGate;
  if (!gate) return { kind: 'unmanaged' };
  try {
    return { kind: 'captured', lease: gate.capture() };
  } catch {
    return { kind: 'unavailable' };
  }
}

function finishEnterprisePolicyRead(
  deps: RouterDeps,
  read: EnterprisePolicyRead,
): {
  readonly timeout: MaximumVaultTimeoutPolicyState;
  readonly pinUnlockAllowed: boolean;
  readonly snapshot?: EffectiveEnterprisePolicySnapshot;
} {
  if (read.kind === 'unmanaged') {
    return { timeout: { kind: 'available', policy: null }, pinUnlockAllowed: true };
  }
  if (read.kind === 'unavailable') {
    return { timeout: { kind: 'unavailable' }, pinUnlockAllowed: false };
  }
  try {
    const snapshot = deps.enterprisePolicyGate!.assert(read.lease);
    return {
      timeout: { kind: 'available', policy: snapshot.maximumVaultTimeoutPolicy },
      pinUnlockAllowed: enterprisePolicyAllows(snapshot, 'unlockWithPin'),
      snapshot,
    };
  } catch {
    return { timeout: { kind: 'unavailable' }, pinUnlockAllowed: false };
  }
}

function assertEnterprisePolicyReadCurrent(deps: RouterDeps, read: EnterprisePolicyRead): void {
  if (read.kind === 'unavailable') {
    throw new AppError('denied', 'Enterprise policy state is unavailable.');
  }
  if (read.kind === 'captured') deps.enterprisePolicyGate!.assert(read.lease);
}

function assertValidPinRequest(value: unknown): asserts value is string {
  const violation = pinConstraintViolation(value);
  if (violation) throw new AppError('error', pinConstraintMessage(violation));
}

function requireContent(context: RequestContext): Extract<RequestContext, { kind: 'content' }> {
  if (context.kind !== 'content') throw new AppError('denied', 'sender not permitted');
  return context;
}

const RUNTIME_BOUND_AUTOFILL_REQUESTS = new Set<RequestMessage['type']>([
  'autofill.findCandidates',
  'autofill.findStructuredCandidates',
  'autofill.claimKeyboardGrant',
  'autofill.keyboard.findCandidates',
  'autofill.keyboard.issueIntent',
  'autofill.continuation.redeemKeyboardReprompt',
  'autofill.keyboard.redeemLoginIntent',
  'autofill.keyboard.redeemTotpIntent',
  'autofill.keyboard.redeemStructuredIntent',
  'autofill.issueIntent',
  'autofill.issueStructuredIntent',
  'autofill.redeemLoginIntent',
  'autofill.redeemTotpIntent',
  'autofill.redeemStructuredIntent',
  'autofill.getClientConfig',
  'autofill.authorizeGeneratorUse',
  'autofill.trackGeneratedValue',
  'autofill.issuePageLoadIntent',
  'autofill.redeemPageLoadIntent',
  'autofill.captureSubmission',
  'autofill.claimSavePrompt',
  'autofill.commitSavePrompt',
  'autofill.dismissSavePrompt',
]);

function runtimeIncarnation(value: unknown): string {
  if (typeof value !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) {
    throw deniedAutofillIntent();
  }
  return value;
}

function runtimeIncarnationProperty(value: object, key = 'runtimeIncarnation'): string {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor?.enumerable || !('value' in descriptor)) throw deniedAutofillIntent();
  return runtimeIncarnation(descriptor.value);
}

function requireExtensionPage(
  context: RequestContext,
): Extract<RequestContext, { kind: 'extensionPage' }> {
  if (context.kind === 'content') {
    throw new AppError('denied', 'sender not permitted');
  }
  return context;
}

function requireDeviceLoginGeneration(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new AppError('denied', 'The device login request owner is invalid.');
  }
  return value as number;
}

function requireSsoAttemptBinding(attemptId: unknown, generation: unknown): {
  readonly attemptId: string;
  readonly generation: number;
} {
  if (typeof attemptId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(attemptId)
      || !Number.isSafeInteger(generation)
      || (generation as number) <= 0) {
    throw new AppError('denied', 'The SSO attempt owner is invalid.');
  }
  return Object.freeze({ attemptId, generation: generation as number });
}

function requireOptionsPage(
  context: RequestContext,
): Extract<RequestContext, { kind: 'extensionPage' }> {
  const extensionPage = requireExtensionPage(context);
  try {
    if (new URL(extensionPage.url).pathname === '/ui/options/options.html') return extensionPage;
  } catch {
    // The fixed denial below intentionally hides URL parsing details.
  }
  throw new AppError('denied', 'sender not permitted');
}

async function finishDeviceLoginDecision(
  operation: () => Promise<DeviceLoginDecisionReceipt>,
  onSettled: RouterDeps['onDeviceLoginApprovalDecision'],
): Promise<DeviceLoginDecisionReceipt> {
  let refresh = false;
  try {
    const receipt = await operation();
    refresh = true;
    return receipt;
  } catch (error) {
    refresh = error instanceof AppError && error.code === 'outcome_unknown';
    throw error;
  } finally {
    if (refresh) observeDeviceLoginDecisionRefresh(onSettled);
  }
}

function observeDeviceLoginDecisionRefresh(
  onSettled: RouterDeps['onDeviceLoginApprovalDecision'],
): void {
  try {
    const operation = onSettled?.();
    if (operation) void Promise.resolve(operation).catch(() => undefined);
  } catch {
    // Badge or other authority refreshes never alter an already-settled remote decision.
  }
}

function observeDeviceLoginApprovalPopupOpened(
  onOpened: RouterDeps['onDeviceLoginApprovalPopupOpened'],
): void {
  try {
    const operation = onOpened?.();
    if (operation) void Promise.resolve(operation).catch(() => undefined);
  } catch {
    // System-notification cleanup never changes popup routing or vault synchronization.
  }
}

function requirePopupPage(
  context: RequestContext,
): Extract<RequestContext, { kind: 'extensionPage' }> {
  const page = requireExtensionPage(context);
  let url: URL;
  try { url = new URL(page.url); } catch { throw new AppError('denied', 'sender not permitted'); }
  const origin = `${url.protocol}//${url.host}`;
  if (url.username || url.password || origin !== page.origin || url.pathname !== WEBSITE_PASSKEY_POPUP_PATH) {
    throw new AppError('denied', 'sender not permitted');
  }
  return page;
}

function requirePopupDocument(
  context: RequestContext,
): Extract<RequestContext, { kind: 'extensionPage' }> & { readonly documentId: string } {
  const page = requirePopupPage(context);
  if (!page.documentId) throw new AppError('denied', 'sender not permitted');
  return page as typeof page & { readonly documentId: string };
}

function assertExactGeneratorHistoryRequest(request: Extract<
  RequestMessage,
  { readonly type: `generator.history.${string}` }
>): void {
  const expected = request.type === 'generator.history.track' ? ['type', 'entry'] : ['type'];
  const keys = Reflect.ownKeys(request);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')
    || expected.some((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(request, key);
      return !descriptor?.enumerable || !('value' in descriptor);
    })
    || keys.some((key) => !expected.includes(key as string))) {
    throw new AppError('denied', 'Generator history request is invalid');
  }
}

function websitePasskeyCeremonyId(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 36 || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) {
    throw new AppError('denied', 'Website passkey request is invalid');
  }
  return value;
}

function websitePasskeyLockedContinuationId(
  request: unknown,
  type: 'websitePasskey.lockedStatus' | 'websitePasskey.resumeLocked' | 'websitePasskey.cancelLocked',
): string | undefined {
  if (typeof request !== 'object' || request === null || Array.isArray(request)) {
    throw new AppError('denied', 'Website passkey request is invalid');
  }
  const record = request as Record<string, unknown>;
  const keys = Reflect.ownKeys(record);
  const expected = type === 'websitePasskey.lockedStatus'
    ? keys.includes('continuationId') ? ['type', 'continuationId'] : ['type']
    : ['type', 'continuationId'];
  if (keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) {
    throw new AppError('denied', 'Website passkey request is invalid');
  }
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw new AppError('denied', 'Website passkey request is invalid');
    }
  }
  const requestType = Object.getOwnPropertyDescriptor(record, 'type')?.value;
  if (requestType !== type) throw new AppError('denied', 'Website passkey request is invalid');
  if (!expected.includes('continuationId')) return undefined;
  return websitePasskeyCeremonyId(
    Object.getOwnPropertyDescriptor(record, 'continuationId')?.value,
  );
}

function websitePasskeySelection(value: unknown): WebsitePasskeySelection {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AppError('denied', 'Website passkey request is invalid');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AppError('denied', 'Website passkey request is invalid');
  }
  const record = value as Record<string, unknown>;
  const ownKeys = Reflect.ownKeys(record);
  if (ownKeys.some((key) => typeof key !== 'string')) {
    throw new AppError('denied', 'Website passkey request is invalid');
  }
  for (const key of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw new AppError('denied', 'Website passkey request is invalid');
    }
  }
  const keys = (ownKeys as string[]).sort();
  if (record.kind === 'new' && keys.length === 1 && keys[0] === 'kind') return { kind: 'new' };
  if (record.kind === 'credential'
      && keys.length === 2 && keys[0] === 'credentialId' && keys[1] === 'kind'
      && typeof record.credentialId === 'string' && record.credentialId.length > 0 && record.credentialId.length <= 4_096) {
    return { kind: 'credential', credentialId: record.credentialId };
  }
  if (record.kind === 'target'
      && keys.length === 2 && keys[0] === 'cipherId' && keys[1] === 'kind'
      && typeof record.cipherId === 'string' && record.cipherId.length > 0 && record.cipherId.length <= 4_096) {
    return { kind: 'target', cipherId: record.cipherId };
  }
  throw new AppError('denied', 'Website passkey request is invalid');
}

function deviceLoginDecisionBinding(
  request: { readonly type: string; readonly decisionBinding: unknown },
): unknown {
  try {
    const keys = Reflect.ownKeys(request);
    if (
      keys.length !== 2
      || keys.some((key) => typeof key !== 'string')
      || !keys.includes('type')
      || !keys.includes('decisionBinding')
    ) throw new Error('invalid fields');
    let binding: unknown;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(request, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) throw new Error('invalid field');
      if (key === 'decisionBinding') binding = descriptor.value;
    }
    return binding;
  } catch {
    throw new AppError('denied', 'The device login confirmation is invalid or stale.');
  }
}

function requireContentTopFrame(context: RequestContext): Extract<RequestContext, { kind: 'content' }> {
  const content = requireContent(context);
  if (content.frameId !== 0) throw new AppError('denied', 'sender not permitted');
  return content;
}

function isSessionBoundRequest(type: RequestMessage['type']): boolean {
  if (type === 'vault.popupOpened' || type === 'vault.getSyncStatus'
      || type === 'autofill.activateRuntime') return false;
  if (
    type === 'autofill.redeemLoginIntent'
    || type === 'autofill.redeemTotpIntent'
    || type === 'autofill.redeemStructuredIntent'
    || type === 'autofill.keyboard.redeemLoginIntent'
    || type === 'autofill.keyboard.redeemTotpIntent'
    || type === 'autofill.keyboard.redeemStructuredIntent'
    || type === 'autofill.redeemPageLoadIntent'
    || type === 'autofill.getClientConfig'
    || type === 'autofill.claimKeyboardGrant'
    || type === 'autofill.manual.commit'
    || type.startsWith('autofill.continuation.')
  ) return false;
  return type.startsWith('vault.')
    || type.startsWith('sends.')
    || type.startsWith('autofill.')
    || type.startsWith('generator.history.');
}

const SECRET_RESPONSE_REQUESTS: ReadonlySet<RequestMessage['type']> = new Set([
  'vault.getField',
  'vault.getCustomField',
  'vault.getCipherDetail',
  'vault.getAttachment',
  'vault.getSshKeyDetails',
  'vault.revealSshPrivateKey',
  'vault.getPasswordHistory',
  'vault.getTotp',
  'vault.getTotpCodes',
  'vault.getCipherInput',
  'sends.list',
  'generator.history.list',
]);

const USER_VAULT_ACTIVITY: ReadonlySet<RequestMessage['type']> = new Set([
  'vault.authorizeExport',
  'vault.sync',
  'vault.popupOpened',
  'vault.getField',
  'vault.getCustomField',
  'vault.getCipherDetail',
  'vault.getAttachment',
  'vault.addAttachment',
  'vault.deleteAttachment',
  'vault.getSshKeyDetails',
  'vault.revealSshPrivateKey',
  'vault.createGeneratedSshKey',
  'vault.importSshKey',
  'vault.replaceSshKey',
  'vault.updateSshKeyMetadata',
  'vault.getPasswordHistory',
  'vault.getTotp',
  'vault.getPasswordHealth',
  'vault.checkPwned',
  'vault.createFolder',
  'vault.renameFolder',
  'vault.deleteFolder',
  'vault.createCollection',
  'vault.renameCollection',
  'vault.deleteCollection',
  'vault.setCipherCollections',
  'vault.createCipher',
  'vault.updateCipher',
  'vault.setCipherFavorite',
  'vault.deleteCipher',
  'vault.softDeleteCipher',
  'vault.restoreCipher',
  'vault.archiveCipher',
  'vault.unarchiveCipher',
  'vault.deletePasskey',
  'vault.shareCipher',
  'vault.migrateOrganizationDataOwnership',
  'vault.leaveOrganizationDataOwnership',
  'vault.getCipherInput',
  'sends.createText',
  'sends.createFile',
  'sends.update',
  'sends.delete',
  'websitePasskey.approve',
  'autofill.redeemLoginIntent',
  'autofill.keyboard.redeemLoginIntent',
  'autofill.redeemTotpIntent',
  'autofill.keyboard.redeemTotpIntent',
  'autofill.redeemStructuredIntent',
  'autofill.keyboard.redeemStructuredIntent',
  'autofill.commitSavePrompt',
  'autofill.fillTabSuggestion',
  'autofill.manual.commit',
  'generator.history.list',
  'generator.history.clear',
]);

function activitySucceeded(request: RequestMessage, response: ResponseMessage): boolean {
  if (!response.ok || !USER_VAULT_ACTIVITY.has(request.type)) return false;
  if (request.type === 'autofill.manual.commit') {
    const data = response.data as { outcome?: { status?: unknown } };
    return data.outcome?.status === 'filled'
      || data.outcome?.status === 'filled_and_saved'
      || data.outcome?.status === 'filled_but_save_failed'
      || data.outcome?.status === 'filled_but_save_conflict'
      || data.outcome?.status === 'filled_but_save_committed_unsynced'
      || data.outcome?.status === 'filled_but_save_outcome_unknown';
  }
  if (request.type !== 'autofill.fillTabSuggestion'
      && request.type !== 'autofill.redeemStructuredIntent'
      && request.type !== 'autofill.keyboard.redeemStructuredIntent') return true;
  const data = response.data as { outcome?: { status?: unknown } };
  return data.outcome?.status === 'filled';
}

const RESTRICTED_REQUEST_ALLOWLIST: ReadonlySet<RequestMessage['type']> = new Set([
  'auth.getState',
  'auth.changeForcedPassword',
  'auth.logout',
  'auth.listAccounts',
  'auth.switchAccount',
  'auth.removeAccount',
  'websitePasskey.reportIframeInventory',
]);

async function assertRestrictedRequestAllowed(
  deps: RouterDeps,
  type: RequestMessage['type'],
): Promise<void> {
  if (!deps.auth.getState || RESTRICTED_REQUEST_ALLOWLIST.has(type)) return;
  if (await deps.auth.getState() === 'restricted') {
    throw new AppError('denied', 'Change the master password before using this account.');
  }
}

const AUTOFILL_INTENT_DENIED = 'Autofill intent is invalid or expired';
const REPROMPT_AUTOFILL_DENIED = 'Reprompt autofill authorization is invalid or expired';

function deniedAutofillIntent(): AppError {
  return new AppError('denied', AUTOFILL_INTENT_DENIED);
}

function deniedRepromptAutofill(): AppError {
  return new AppError('reprompt_required', REPROMPT_AUTOFILL_DENIED);
}

function autofillAuthorizationPolicyGates(deps: RouterDeps) {
  return {
    autofill: deps.autofillPolicyGate,
    enterprise: deps.enterprisePolicyGate,
  } as const;
}

function assertAutofillAuthorizationPolicyLease(
  deps: RouterDeps,
  lease: AutofillAuthorizationPolicyLease,
): EffectiveEnterprisePolicySnapshot {
  return assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates(deps), lease);
}

function repromptGrantBinding(
  popupDocumentId: string,
  cipherId: string,
  binding: ResolvedRepromptAutofillBinding,
): RepromptAutofillGrantBinding {
  return {
    popupDocumentId,
    cipherId,
    tabId: binding.tabId,
    frameId: binding.frameId,
    targetDocumentId: binding.targetDocumentId,
    topUrl: binding.topUrl,
    frameUrl: binding.frameUrl,
    targetKey: binding.targetKey,
  };
}

function sameRepromptBinding(
  first: ResolvedRepromptAutofillBinding,
  second: ResolvedRepromptAutofillBinding,
): boolean {
  return first.tabId === second.tabId
    && first.frameId === second.frameId
    && first.targetDocumentId === second.targetDocumentId
    && first.topUrl === second.topUrl
    && first.frameUrl === second.frameUrl
    && first.targetKey === second.targetKey;
}

function assertRepromptGrantLeases(
  deps: RouterDeps,
  grant: {
    readonly sessionLease: SessionLease;
    readonly accountLease: AccountLease;
    readonly policyLease: AutofillAuthorizationPolicyLease;
  },
): void {
  deps.sessionGate.assert(grant.sessionLease);
  deps.accountGate.assert(grant.accountLease);
  assertAutofillAuthorizationPolicyLease(deps, grant.policyLease);
}

function assertRepromptGrantCurrent(
  deps: RouterDeps,
  grant: {
    readonly sessionLease: SessionLease;
    readonly accountLease: AccountLease;
    readonly policyLease: AutofillAuthorizationPolicyLease;
    readonly isCurrent: () => boolean;
  },
): void {
  if (!grant.isCurrent()) throw deniedRepromptAutofill();
  assertRepromptGrantLeases(deps, grant);
}

function redeemAutofillIntent(
  deps: RouterDeps,
  intentId: string,
  purpose: AutofillSecretPurpose,
  channel: 'interactive' | 'keyboard' | 'page-load',
  context: RequestContext,
  runtimeIncarnationValue: string,
  structuredTarget?: ContentStructuredAutofillTarget,
) {
  const redemption = context.kind === 'content'
    ? {
        tabId: context.tabId,
        frameId: context.frameId,
        documentId: context.documentId ?? '',
        runtimeIncarnation: runtimeIncarnationValue,
        frameUrl: context.url,
        purpose,
        channel,
        ...(structuredTarget === undefined ? {} : { structuredTarget }),
      }
    : {
        tabId: -1,
        frameId: -1,
        documentId: '',
        runtimeIncarnation: runtimeIncarnationValue,
        frameUrl: 'https://invalid.invalid/',
        purpose,
        channel,
        ...(structuredTarget === undefined ? {} : { structuredTarget }),
      };
  return deps.autofillIntents.redeem(intentId, redemption);
}

function assertAutofillIntentLeases(
  deps: RouterDeps,
  intent: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: AutofillAuthorizationPolicyLease },
): void {
  deps.accountGate.assert(intent.accountLease);
  deps.sessionGate.assert(intent.sessionLease);
  assertAutofillAuthorizationPolicyLease(deps, intent.policyLease);
}

function rethrowAutofillIntentReadError(
  deps: RouterDeps,
  intent: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: AutofillAuthorizationPolicyLease },
  error: unknown,
): never {
  try {
    assertAutofillIntentLeases(deps, intent);
  } catch {
    throw deniedAutofillIntent();
  }
  if (
    error instanceof AppError
    && ['denied', 'locked', 'session_expired', 'sync_required', 'no_match'].includes(error.code)
  ) {
    throw deniedAutofillIntent();
  }
  throw error;
}

interface AutofillAuthorization {
  readonly settings: Readonly<AutofillPolicySettings>;
  readonly policyLease: AutofillAuthorizationPolicyLease;
  readonly defaultStrategy: UriMatchStrategySetting;
}

async function authorizeAutofill(
  deps: RouterDeps,
  url: string,
  action: AutofillPolicyAction,
  feature?: 'inlineSuggestions' | 'pageLoadFill',
  existingLease?: AutofillAuthorizationPolicyLease,
): Promise<AutofillAuthorization> {
  return authorizeAutofillActions(deps, url, [action], feature, existingLease);
}

async function authorizeAutofillActions(
  deps: RouterDeps,
  url: string,
  actions: readonly AutofillPolicyAction[],
  feature?: 'inlineSuggestions' | 'pageLoadFill',
  existingLease?: AutofillAuthorizationPolicyLease,
): Promise<AutofillAuthorization> {
  const gates = autofillAuthorizationPolicyGates(deps);
  const policyLease = existingLease ?? captureAutofillAuthorizationPolicy(gates);
  let settings: Readonly<AutofillPolicySettings>;
  try {
    if (!deps.settings.getAutofillPolicySettings) throw new Error('autofill policy settings are not wired');
    settings = await deps.settings.getAutofillPolicySettings();
  } catch {
    throw deniedAutofillIntent();
  }
  const enterpriseSnapshot = assertAutofillAuthorizationPolicy(gates, policyLease);
  const allowed = actions.some((action) => autofillActionAllowed(settings, action, url));
  const featureEnabled = feature === 'pageLoadFill'
    ? settings.pageLoadFill || enterpriseSnapshot.activateAutofillRequired
    : feature === 'inlineSuggestions'
      ? settings.inlineSuggestions
      : true;
  if (
    !allowed
    || !featureEnabled
  ) throw deniedAutofillIntent();
  const effectiveDefault = resolveAutofillAuthorizationUriMatchDefault(
    gates,
    policyLease,
    settings.defaultUriMatchStrategy,
  );
  return { settings, policyLease, defaultStrategy: effectiveDefault.value };
}

function autofillActionAllowed(
  settings: Readonly<AutofillPolicySettings>,
  action: AutofillPolicyAction,
  url: string,
): boolean {
  const globalDecision = decideAutofillPolicy(
    normalizeAutofillBlocklist(settings.blockedDomains),
    { action, url },
  );
  if (!globalDecision.allowed) return false;
  if (action === 'page-load') return isAllowedPageLoadTransport(url);
  if (action !== 'save' && action !== 'update') return true;
  if (action === 'save' ? !settings.savePromptEnabled : !settings.updatePromptEnabled) return false;
  // This second list suppresses credential capture only. It must never participate in candidate,
  // page-load, structured-fill, HTTP-auth, or website-passkey authorization.
  return decideAutofillPolicy(
    normalizeAutofillBlocklist(settings.savePromptExcludedDomains),
    { action, url },
  ).allowed;
}

function sanitizeRequestedAutofillSettings(value: unknown): {
  readonly settings: Readonly<AutofillSettings>;
  readonly pageLoadFillDefault: boolean;
} {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid autofill settings');
  }
  const record = value as Record<string, unknown>;
  const expected = [
    'inlineSuggestions',
    'pageLoadFill',
    'pageLoadFillDefault',
    'autoCopyTotp',
    'savePromptEnabled',
    'updatePromptEnabled',
    'savePromptExcludedDomains',
    'blockedDomains',
  ] as const;
  if (
    Object.keys(record).length !== expected.length
    || !expected.every((key) => Object.hasOwn(record, key))
    || typeof record.pageLoadFillDefault !== 'boolean'
  ) throw new Error('Invalid autofill settings');
  return Object.freeze({
    settings: sanitizeAutofillSettings({
      inlineSuggestions: record.inlineSuggestions,
      pageLoadFill: record.pageLoadFill,
      autoCopyTotp: record.autoCopyTotp,
      savePromptEnabled: record.savePromptEnabled,
      updatePromptEnabled: record.updatePromptEnabled,
      savePromptExcludedDomains: record.savePromptExcludedDomains,
      blockedDomains: record.blockedDomains,
    }),
    pageLoadFillDefault: record.pageLoadFillDefault,
  });
}

async function usernameStageContext(
  deps: RouterDeps,
  caller: Extract<RequestContext, { kind: 'content' }>,
  sessionLease: SessionLease,
  accountLease: AccountLease,
  policyLease: AutofillAuthorizationPolicyLease,
  runtimeIncarnationValue: string,
): Promise<AutofillUsernameStageContext> {
  if (!caller.documentId) throw deniedAutofillIntent();
  const sessionBindingId = await deps.getSessionBindingId?.();
  if (!sessionBindingId) throw deniedAutofillIntent();
  deps.accountGate.assert(accountLease);
  deps.sessionGate.assert(sessionLease);
  assertAutofillAuthorizationPolicyLease(deps, policyLease);
  return {
    tabId: caller.tabId,
    frameId: caller.frameId,
    documentId: caller.documentId,
    runtimeIncarnation: runtimeIncarnationValue,
    origin: caller.origin,
    sessionGeneration: sessionLease.generation,
    sessionBindingId,
    serverGeneration: accountLease.serverGeneration,
    accountGeneration: accountLease.accountGeneration,
    serverUrl: accountLease.serverUrl,
    accountIdentity: accountLease.accountIdentity,
    policyGeneration: policyLease.autofill.generation,
    enterprisePolicyGeneration: policyLease.enterprise.generation,
    enterprisePolicyRawGeneration: policyLease.enterprise.rawGeneration,
  };
}

type ActiveKeyboardGrant = KeyboardGrant<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>;

function keyboardGrantContext(
  caller: Extract<RequestContext, { kind: 'content' }>,
  runtimeIncarnationValue: string,
): KeyboardGrantContext {
  return {
    tabId: caller.tabId,
    frameId: caller.frameId,
    documentId: caller.documentId ?? '',
    runtimeIncarnation: runtimeIncarnationValue,
    frameUrl: caller.url,
  };
}

async function currentKeyboardTopDocument(
  deps: RouterDeps,
  tabId: number,
): Promise<{ documentId: string; url: string } | undefined> {
  try {
    return await deps.getKeyboardTopDocument(tabId);
  } catch {
    return undefined;
  }
}

async function assertKeyboardTopDocumentCurrent(
  deps: RouterDeps,
  expected: { readonly tabId: number; readonly topDocumentId: string; readonly topFrameUrl: string },
): Promise<void> {
  const current = await currentKeyboardTopDocument(deps, expected.tabId);
  let canonicalUrl: string | undefined;
  try { canonicalUrl = current ? new URL(current.url).href : undefined; } catch { /* Fail closed below. */ }
  if (
    !current
    || current.documentId !== expected.topDocumentId
    || canonicalUrl !== expected.topFrameUrl
  ) throw deniedAutofillIntent();
}

async function assertKeyboardGrantTopDocumentCurrent(
  deps: RouterDeps,
  grantId: string,
  context: KeyboardGrantContext,
  grant: ActiveKeyboardGrant,
): Promise<void> {
  try {
    await assertKeyboardTopDocumentCurrent(deps, grant);
  } catch {
    deps.keyboardGrants.consumeGrant(grantId, context);
    throw deniedAutofillIntent();
  }
}

function assertKeyboardGrantLeases(deps: RouterDeps, grant: ActiveKeyboardGrant): void {
  assertAutofillIntentLeases(deps, grant);
}

async function parseKeyboardClaimBinding(
  value: KeyboardAutofillClaimBinding,
): Promise<KeyboardGrantBinding | undefined> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const keys = Object.keys(value);
  if (value.purpose === 'login') {
    if (keys.length !== 2 || !keys.includes('purpose') || !keys.includes('customPlan')) return undefined;
    const customPlan = parseLoginCustomTargetPlan(value.customPlan);
    if (!customPlan) return undefined;
    return {
      purpose: value.purpose,
      customPlan,
      customPlanDigest: await digestLoginCustomTargetPlan(customPlan),
    };
  }
  if (value.purpose === 'totp') {
    return keys.length === 1 && keys[0] === 'purpose' ? { purpose: value.purpose } : undefined;
  }
  if (value.purpose === 'card' || value.purpose === 'identity') {
    if (keys.length !== 2 || !keys.includes('purpose') || !keys.includes('structuredTarget')) return undefined;
    const structuredTarget = parseContentStructuredAutofillTarget(value.structuredTarget);
    return structuredTarget?.kind === value.purpose
      ? { purpose: value.purpose, structuredTarget }
      : undefined;
  }
  return undefined;
}

function assertPendingSaveLeases(
  deps: RouterDeps,
  leases: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: AutofillAuthorizationPolicyLease },
): void {
  deps.accountGate.assert(leases.accountLease);
  deps.sessionGate.assert(leases.sessionLease);
  assertAutofillAuthorizationPolicyLease(deps, leases.policyLease);
}

async function pendingSaveDocumentContext(
  deps: RouterDeps,
  caller: Extract<RequestContext, { kind: 'content' }>,
  leases: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: AutofillAuthorizationPolicyLease },
  runtimeIncarnationValue: string,
): Promise<AutofillPendingSaveDocumentContext> {
  if (!caller.documentId) throw deniedAutofillIntent();
  const binding = await usernameStageContext(
    deps,
    caller,
    leases.sessionLease,
    leases.accountLease,
    leases.policyLease,
    runtimeIncarnationValue,
  );
  return Object.freeze({
    ...binding,
    documentId: caller.documentId,
    frameUrl: new URL(caller.url).href,
  });
}

function parseCapturedSubmission(
  request: Extract<RequestMessage, { readonly type: 'autofill.captureSubmission' }>,
): { readonly username: string }
  | (AutofillPendingSaveCredentials & { readonly submission: AutofillSaveCaptureSubmission }) {
  const prototype = Object.getPrototypeOf(request) as unknown;
  const keys = Reflect.ownKeys(request);
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.some((key) => typeof key !== 'string')) throw deniedAutofillIntent();
  const values = new Map<string, unknown>();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(request, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw deniedAutofillIntent();
    }
    values.set(key as string, descriptor.value);
  }
  if (values.get('type') !== 'autofill.captureSubmission'
      || [...values.keys()].some((key) => ![
        'type', 'runtimeIncarnation', 'username', 'password', 'submission',
      ].includes(key))) {
    throw deniedAutofillIntent();
  }
  const username = values.get('username');
  if (values.has('username') && (
    typeof username !== 'string'
    || username.length === 0
    || username.length > 4_096
    || username.trim() !== username
  )) throw deniedAutofillIntent();
  if (!values.has('password')) {
    if (keys.length !== 3 || !values.has('username') || values.has('submission')) {
      throw deniedAutofillIntent();
    }
    return Object.freeze({ username: username as string });
  }
  const password = values.get('password');
  if (typeof password !== 'string' || password.length === 0 || password.length > 65_536) {
    throw deniedAutofillIntent();
  }
  return Object.freeze({
    ...(typeof username === 'string' ? { username } : {}),
    password,
    submission: parseSaveCaptureSubmission(values.get('submission')),
  });
}

function parseSaveCaptureSubmission(value: unknown): AutofillSaveCaptureSubmission {
  if (value === undefined) return Object.freeze({ kind: 'formless' });
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw deniedAutofillIntent();
  const prototype = Object.getPrototypeOf(value) as unknown;
  const keys = Reflect.ownKeys(value);
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.some((key) => typeof key !== 'string')) throw deniedAutofillIntent();
  const values = new Map<string, unknown>();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw deniedAutofillIntent();
    }
    values.set(key as string, descriptor.value);
  }
  if (values.get('kind') === 'formless' && keys.length === 1) {
    return Object.freeze({ kind: 'formless' });
  }
  if (values.get('kind') !== 'native'
      || keys.length !== 3
      || !values.has('actionUrl')
      || !values.has('method')) throw deniedAutofillIntent();
  const actionUrl = values.get('actionUrl');
  const method = values.get('method');
  if (typeof actionUrl !== 'string' || !actionUrl || actionUrl.length > 16 * 1_024
      || actionUrl.trim() !== actionUrl || hasAsciiControl(actionUrl)
      || (method !== 'POST' && method !== 'PUT' && method !== 'PATCH')) {
    throw deniedAutofillIntent();
  }
  let canonicalUrl: URL;
  try { canonicalUrl = new URL(actionUrl); } catch { throw deniedAutofillIntent(); }
  if ((canonicalUrl.protocol !== 'https:' && canonicalUrl.protocol !== 'http:')
      || canonicalUrl.username || canonicalUrl.password) throw deniedAutofillIntent();
  canonicalUrl.hash = '';
  return Object.freeze({ kind: 'native', actionUrl: canonicalUrl.href, method });
}

function hasAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function strictSavePromptId(
  request: Extract<RequestMessage, {
    readonly type: 'autofill.commitSavePrompt' | 'autofill.dismissSavePrompt';
  }>,
  expectedType: 'autofill.commitSavePrompt' | 'autofill.dismissSavePrompt',
): string {
  const keys = Reflect.ownKeys(request);
  if (
    request.type !== expectedType
    || keys.length !== 3
    || keys.some((key) => typeof key !== 'string')
    || !keys.includes('type')
    || !keys.includes('promptId')
    || !keys.includes('runtimeIncarnation')
    || typeof request.promptId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.promptId)
  ) throw deniedAutofillIntent();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(request, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) throw deniedAutofillIntent();
  }
  return request.promptId;
}

function strictClaimCaptureId(
  request: Extract<RequestMessage, { readonly type: 'autofill.claimSavePrompt' }>,
): string | undefined {
  const captureDescriptor = Object.getOwnPropertyDescriptor(request, 'captureId');
  const hasCaptureId = captureDescriptor !== undefined;
  const expected = hasCaptureId
    ? ['type', 'runtimeIncarnation', 'captureId']
    : ['type', 'runtimeIncarnation'];
  const keys = Reflect.ownKeys(request);
  if (keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expected.includes(key))
      || expected.some((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(request, key);
        return !descriptor?.enumerable || !('value' in descriptor);
      })) {
    throw deniedAutofillIntent();
  }
  if (!hasCaptureId) return undefined;
  const captureId = captureDescriptor && 'value' in captureDescriptor
    ? captureDescriptor.value
    : undefined;
  if (typeof captureId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(captureId)) {
    throw deniedAutofillIntent();
  }
  return captureId;
}

function strictCipherInputPurpose(
  request: Extract<RequestMessage, { readonly type: 'vault.getCipherInput' }>,
): 'edit' | 'clone' {
  const prototype = Object.getPrototypeOf(request) as unknown;
  const keys = Reflect.ownKeys(request);
  if (
    (prototype !== Object.prototype && prototype !== null)
    || keys.some((key) => typeof key !== 'string')
    || !keys.includes('type')
    || !keys.includes('id')
    || !keys.includes('cipherInputPurpose')
  ) throw new AppError('denied', 'Cipher input request is invalid.');

  const values = new Map<string, unknown>();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(request, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw new AppError('denied', 'Cipher input request is invalid.');
    }
    values.set(key as string, descriptor.value);
  }
  if ([...values.keys()].some((key) => ![
    'type', 'id', 'cipherInputPurpose', 'masterPassword', 'clientEventPurpose',
  ].includes(key))) throw new AppError('denied', 'Cipher input request is invalid.');

  const purpose = values.get('cipherInputPurpose');
  const clientEventPurpose = values.get('clientEventPurpose');
  if (
    values.get('type') !== 'vault.getCipherInput'
    || typeof values.get('id') !== 'string'
    || (purpose !== 'edit' && purpose !== 'clone')
    || (values.has('masterPassword') && typeof values.get('masterPassword') !== 'string')
    || (purpose === 'edit' && values.has('clientEventPurpose') && clientEventPurpose !== 'editor')
    || (purpose === 'clone' && values.has('clientEventPurpose'))
  ) throw new AppError('denied', 'Cipher input request is invalid.');
  return purpose;
}

function contentTotpClipboardCode(
  request: Extract<RequestMessage, { readonly type: 'clipboard.scheduleClear' }>,
): string {
  const prototype = Object.getPrototypeOf(request) as unknown;
  const keys = Reflect.ownKeys(request);
  if (
    (prototype !== Object.prototype && prototype !== null)
    || keys.length !== 2
    || keys.some((key) => typeof key !== 'string')
    || !keys.includes('type')
    || !keys.includes('value')
  ) throw invalidContentTotpClipboardRequest();

  let type: unknown;
  let value: unknown;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(request, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw invalidContentTotpClipboardRequest();
    }
    if (key === 'type') type = descriptor.value;
    if (key === 'value') value = descriptor.value;
  }
  if (type !== 'clipboard.scheduleClear' || !isContentTotpClipboardCode(value)) {
    throw invalidContentTotpClipboardRequest();
  }
  return value;
}

function invalidContentTotpClipboardRequest(): AppError {
  return new AppError('denied', 'TOTP clipboard ownership request is invalid');
}

async function loadPendingSaveUserKey(
  deps: RouterDeps,
  leases: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: AutofillAuthorizationPolicyLease },
): Promise<SymmetricKey> {
  const key = await deps.loadPendingSaveUserKey?.();
  if (!key) throw deniedAutofillIntent();
  try {
    assertPendingSaveLeases(deps, leases);
    return key;
  } catch (error) {
    key.encKey.fill(0);
    key.macKey.fill(0);
    throw error;
  }
}

async function evaluatePendingSave(
  deps: RouterDeps,
  credentials: AutofillPendingSaveCredentials,
  sourceUrl: string,
  authorization: AutofillAuthorization,
  leases: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: AutofillAuthorizationPolicyLease },
): Promise<AutofillPendingSaveDecision> {
  if (!deps.vault.checkSaveLogin) throw new Error('vault.checkSaveLogin is not wired');
  assertPendingSaveLeases(deps, leases);
  const prompt = await deps.vault.checkSaveLogin(sourceUrl, credentials, authorization.defaultStrategy);
  assertPendingSaveLeases(deps, leases);
  if (prompt.action === 'none') return prompt;
  const policyAction = prompt.action === 'save' ? 'save' : 'update';
  if (!autofillActionAllowed(authorization.settings, policyAction, sourceUrl)) {
    return { action: 'none' };
  }
  await authorizeAutofill(
    deps,
    sourceUrl,
    policyAction,
    undefined,
    authorization.policyLease,
  );
  assertPendingSaveLeases(deps, leases);
  return prompt;
}

async function clientAutofillConfig(deps: RouterDeps, url: string) {
  const disabled = {
    inlineSuggestions: false,
    pageLoadFill: false,
    saveAllowed: false,
    updateAllowed: false,
    generatorAllowed: false,
    generator: UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  } as const;
  try {
    deps.sessionGate.capture();
  } catch {
    return disabled;
  }
  const gates = autofillAuthorizationPolicyGates(deps);
  const policyLease = captureAutofillAuthorizationPolicy(gates);
  try {
    if (!deps.settings.getAutofillPolicySettings) return disabled;
    const settings = await deps.settings.getAutofillPolicySettings();
    const enterpriseSnapshot = assertAutofillAuthorizationPolicy(gates, policyLease);
    resolveAutofillAuthorizationUriMatchDefault(
      gates,
      policyLease,
      settings.defaultUriMatchStrategy,
    );
    const generator = resolveAutofillAuthorizationGeneratorPolicy(gates, policyLease);
    const allowed = (action: AutofillPolicyAction) => autofillActionAllowed(settings, action, url);
    const generatorAllowed = isAllowedGeneratorTransport(url)
      && allowed('candidate')
      && !generator.malformed
      && (generator.password.allowed || generator.passphrase.allowed);
    return {
      inlineSuggestions: settings.inlineSuggestions && allowed('candidate'),
      pageLoadFill: (settings.pageLoadFill || enterpriseSnapshot.activateAutofillRequired)
        && allowed('page-load'),
      saveAllowed: allowed('save'),
      updateAllowed: allowed('update'),
      generatorAllowed,
      generator,
    };
  } catch {
    return disabled;
  }
}

function isAllowedGeneratorTransport(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

function isAllowedPageLoadTransport(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:') return true;
    if (url.protocol !== 'http:') return false;
    if (url.hostname === 'localhost' || url.hostname === '[::1]') return true;
    const octets = url.hostname.split('.');
    return octets.length === 4
      && octets[0] === '127'
      && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
  } catch {
    return false;
  }
}

export function createRouter(deps: RouterDeps) {
  const claimedInteractiveDocuments = new Set<string>();
  return {
    async handle(request: RequestMessage, context: RequestContext): Promise<ResponseMessage> {
      let committedSecretMutation = false;
      try {
        let contentRuntimeIncarnation: string | undefined;
        let contentRuntimeAuthority: AutofillSaveCaptureRuntimeAuthority | undefined;
        if (RUNTIME_BOUND_AUTOFILL_REQUESTS.has(request.type)) {
          const caller = requireContent(context);
          if (!caller.documentId || !deps.saveCaptureCoordinator) throw deniedAutofillIntent();
          contentRuntimeIncarnation = runtimeIncarnationProperty(request);
          contentRuntimeAuthority = await deps.saveCaptureCoordinator.captureRuntimeAuthority(
            caller.tabId,
            caller.frameId,
            caller.documentId,
            contentRuntimeIncarnation,
          );
          if (!contentRuntimeAuthority) throw deniedAutofillIntent();
        }
        if (request.type === 'auth.requestPasswordHint') {
          requirePopupDocument(context);
          if (!isExactPasswordHintRequest(request)) {
            throw new AppError('denied', 'Invalid password hint request.');
          }
        }
        if (request.type === 'vault.setCipherFavorite') {
          requirePopupDocument(context);
          if (!isExactCipherFavoriteRequest(request)) {
            throw new AppError('denied', 'Invalid cipher favorite request.');
          }
        }
        if (request.type.startsWith('generator.history.')) {
          requirePopupDocument(context);
          assertExactGeneratorHistoryRequest(request as Extract<
            RequestMessage,
            { readonly type: `generator.history.${string}` }
          >);
        }
        if (request.type === 'vault.popupOpened') {
          requirePopupPage(context);
          observeDeviceLoginApprovalPopupOpened(deps.onDeviceLoginApprovalPopupOpened);
        }
        await assertRestrictedRequestAllowed(deps, request.type);
        let activityLease: VaultTimeoutActivityLease | undefined = USER_VAULT_ACTIVITY.has(request.type)
          ? deps.vaultTimeout?.captureActivity()
          : undefined;
        const sessionLease: SessionLease | undefined = isSessionBoundRequest(request.type)
          ? deps.sessionGate.capture()
          : undefined;
        let responseSessionLease = sessionLease;
        let responseFinalAssert: (() => void) | undefined = sessionLease
          ? () => deps.sessionGate.assert(sessionLease)
          : undefined;
        let responseReleaseLease: VaultReleaseLease | undefined = sessionLease
          && SECRET_RESPONSE_REQUESTS.has(request.type)
          ? deps.vaultReleaseGate?.capture(sessionLease)
          : undefined;
        const vaultFinalAuthorities: Array<() => void> = [];
        const bindVaultFinalAuthority = (assertCurrent: () => void): void => {
          vaultFinalAuthorities.push(assertCurrent);
        };
        const captureCurrentResponseRelease = (): void => {
          activityLease = deps.vaultTimeout?.captureActivity();
          const currentSessionLease = deps.sessionGate.capture();
          responseSessionLease = currentSessionLease;
          responseFinalAssert = () => deps.sessionGate.assert(currentSessionLease);
          responseReleaseLease = deps.vaultReleaseGate?.capture(currentSessionLease);
        };
        const response = await (async (): Promise<ResponseMessage> => {
          switch (request.type) {
          case 'auth.getState':
            if (!deps.auth.getState) throw new Error('auth.getState is not wired');
            {
              const state = await deps.auth.getState();
              const restriction = state === 'restricted'
                ? await deps.auth.getPasswordChangeRequirement?.()
                : undefined;
              if (state === 'restricted' && !restriction) {
                throw new AppError('session_expired', 'Password change requirement is unavailable.');
              }
              return {
                ok: true,
                data: { state, ...(restriction ? { restriction } : {}) },
              };
            }
          case 'auth.requestPasswordHint':
            if (!deps.auth.requestPasswordHint) {
              throw new Error('auth.requestPasswordHint is not wired');
            }
            return { ok: true, data: await deps.auth.requestPasswordHint(request.email) };
          case 'auth.login':
            if (!deps.auth.login) throw new Error('auth.login is not wired');
            await Promise.all([
              deps.sso?.cancelCurrent(),
              deps.deviceLogin?.cancelCurrent(),
              deps.accountPasskey?.cancel(),
            ]);
            try {
              return {
                ok: true,
                data: await deps.auth.login({ email: request.email, masterPassword: request.masterPassword }),
              };
            } finally {
              await deps.duo?.retireInvalidWaiting().catch(() => false);
            }
          case 'auth.sso.begin': {
            const caller = requirePopupPage(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.sso) throw new Error('auth.sso.begin is not wired');
            await deps.sso.reconcileHandoff();
            await Promise.all([
              deps.accountPasskey?.cancel(),
              deps.deviceLogin?.cancelCurrent(),
              deps.auth.cancelPendingLogin?.(),
            ]);
            await deps.duo?.retireInvalidWaiting().catch(() => false);
            return {
              ok: true,
              data: await deps.sso.begin(
                request.email,
                caller.documentId,
                request.organizationIdentifier,
              ),
            };
          }
          case 'auth.sso.requirement': {
            const caller = requirePopupPage(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.ssoRequirement) throw new Error('auth.sso.requirement is not wired');
            return {
              ok: true,
              data: { required: await deps.ssoRequirement.isRequired(request.email) },
            };
          }
          case 'auth.sso.status':
            requirePopupPage(context);
            if (!deps.sso) throw new Error('auth.sso.status is not wired');
            return {
              ok: true,
              data: await deps.sso.status(request.attemptId === undefined
                ? undefined
                : requireSsoAttemptBinding(request.attemptId, request.generation)),
            };
          case 'auth.sso.cancel':
            requirePopupPage(context);
            if (!deps.sso) throw new Error('auth.sso.cancel is not wired');
            return {
              ok: true,
              data: {
                cancelled: await deps.sso.cancel(
                  requireSsoAttemptBinding(request.attemptId, request.generation),
                ),
              },
            };
          case 'auth.pendingLogin.status':
            requireExtensionPage(context);
            if (!deps.auth.getPendingLoginStatus) throw new Error('auth.pendingLogin.status is not wired');
            return { ok: true, data: await deps.auth.getPendingLoginStatus() };
          case 'auth.pendingLogin.cancel':
            requireExtensionPage(context);
            if (!deps.auth.cancelPendingLogin) throw new Error('auth.pendingLogin.cancel is not wired');
            if (request.continuationId) {
              await deps.duo?.cancel({
                flow: 'password',
                continuationId: request.continuationId,
              });
            }
            return {
              ok: true,
              data: {
                cancelled: await deps.auth.cancelPendingLogin({
                  ...(request.continuationId ? { continuationId: request.continuationId } : {}),
                }),
              },
            };
          case 'auth.newDeviceVerification.sendOtp':
            requireExtensionPage(context);
            if (!deps.auth.sendNewDeviceVerificationOtp) {
              throw new Error('auth.newDeviceVerification.sendOtp is not wired');
            }
            await deps.auth.sendNewDeviceVerificationOtp({
              attemptId: request.attemptId,
              ...(request.continuationId ? { continuationId: request.continuationId } : {}),
            });
            return { ok: true, data: null };
          case 'auth.newDeviceVerification.submit':
            requireExtensionPage(context);
            if (!deps.auth.submitNewDeviceVerification) {
              throw new Error('auth.newDeviceVerification.submit is not wired');
            }
            return {
              ok: true,
              data: await deps.auth.submitNewDeviceVerification({
                attemptId: request.attemptId,
                code: request.code,
                ...(request.continuationId ? { continuationId: request.continuationId } : {}),
              }),
            };
          case 'auth.newDeviceVerification.cancel':
            requireExtensionPage(context);
            if (!deps.auth.cancelNewDeviceVerification) {
              throw new Error('auth.newDeviceVerification.cancel is not wired');
            }
            return {
              ok: true,
              data: {
                cancelled: await deps.auth.cancelNewDeviceVerification({
                  attemptId: request.attemptId,
                  ...(request.continuationId ? { continuationId: request.continuationId } : {}),
                }),
              },
            };
          case 'auth.startRegistration':
            requireExtensionPage(context);
            if (!deps.auth.startRegistration) throw new Error('auth.startRegistration is not wired');
            await Promise.all([
              deps.sso?.cancelCurrent(),
              deps.deviceLogin?.cancelCurrent(),
              deps.accountPasskey?.cancel(),
            ]);
            try {
              return {
                ok: true,
                data: await deps.auth.startRegistration(
                  request.name === undefined
                    ? { email: request.email }
                    : { email: request.email, name: request.name },
                ),
              };
            } finally {
              await deps.duo?.retireInvalidWaiting().catch(() => false);
            }
          case 'auth.register':
            requireExtensionPage(context);
            if (!deps.auth.register) throw new Error('auth.register is not wired');
            return {
              ok: true,
              data: await deps.auth.register({
                attemptId: request.attemptId,
                masterPassword: request.masterPassword,
                masterPasswordHint: request.masterPasswordHint,
              }),
            };
          case 'auth.cancelRegistration':
            requireExtensionPage(context);
            if (!deps.auth.cancelRegistration) {
              throw new Error('auth.cancelRegistration is not wired');
            }
            return {
              ok: true,
              data: { cancelled: await deps.auth.cancelRegistration(request.attemptId) },
            };
          case 'auth.accountPasskey.begin':
            requireExtensionPage(context);
            if (!deps.accountPasskey) throw new Error('auth.accountPasskey.begin is not wired');
            await Promise.all([
              deps.sso?.cancelCurrent(),
              deps.deviceLogin?.cancelCurrent(),
              deps.auth.cancelPendingLogin?.(),
            ]);
            await deps.duo?.retireInvalidWaiting().catch(() => false);
            return { ok: true, data: await deps.accountPasskey.begin() };
          case 'auth.accountPasskey.status':
            requireExtensionPage(context);
            if (!deps.accountPasskey) throw new Error('auth.accountPasskey.status is not wired');
            return { ok: true, data: await deps.accountPasskey.status() };
          case 'auth.accountPasskey.cancel':
            requireExtensionPage(context);
            if (!deps.accountPasskey) throw new Error('auth.accountPasskey.cancel is not wired');
            return { ok: true, data: { cancelled: await deps.accountPasskey.cancel() } };
          case 'auth.deviceLogin.begin':
            requireExtensionPage(context);
            if (!deps.deviceLogin) throw new Error('auth.deviceLogin.begin is not wired');
            await Promise.all([
              deps.sso?.cancelCurrent(),
              deps.accountPasskey?.cancel(),
              deps.auth.cancelPendingLogin?.(),
            ]);
            await deps.duo?.retireInvalidWaiting().catch(() => false);
            return { ok: true, data: await deps.deviceLogin.begin(request.email) };
          case 'auth.deviceLogin.status':
            requireExtensionPage(context);
            if (!deps.deviceLogin) throw new Error('auth.deviceLogin.status is not wired');
            return {
              ok: true,
              data: await deps.deviceLogin.status(
                request.generation === undefined
                  ? undefined
                  : requireDeviceLoginGeneration(request.generation),
              ),
            };
          case 'auth.deviceLogin.retry':
            requireExtensionPage(context);
            if (!deps.deviceLogin) throw new Error('auth.deviceLogin.retry is not wired');
            return {
              ok: true,
              data: await deps.deviceLogin.retryActivation(
                requireDeviceLoginGeneration(request.generation),
              ),
            };
          case 'auth.deviceLogin.submitTwoFactor':
            requireExtensionPage(context);
            if (!deps.deviceLogin) {
              throw new Error('auth.deviceLogin.submitTwoFactor is not wired');
            }
            return {
              ok: true,
              data: await deps.deviceLogin.submitTwoFactor({
                generation: requireDeviceLoginGeneration(request.generation),
                provider: request.provider,
                code: request.code,
                ...(request.remember === undefined ? {} : { remember: request.remember }),
              }),
            };
          case 'auth.deviceLogin.sendEmailCode':
            requireExtensionPage(context);
            if (!deps.deviceLogin) throw new Error('auth.deviceLogin.sendEmailCode is not wired');
            await deps.deviceLogin.sendEmailCode(requireDeviceLoginGeneration(request.generation));
            return { ok: true, data: null };
          case 'auth.deviceLogin.cancel': {
            requireExtensionPage(context);
            if (!deps.deviceLogin) throw new Error('auth.deviceLogin.cancel is not wired');
            const generation = requireDeviceLoginGeneration(request.generation);
            await deps.duo?.cancelDeviceLogin(generation);
            return {
              ok: true,
              data: {
                cancelled: await deps.deviceLogin.cancel(generation),
              },
            };
          }
          case 'auth.deviceLogin.approvals.list':
            requireExtensionPage(context);
            if (!deps.deviceLoginApprovals) {
              throw new Error('auth.deviceLogin.approvals.list is not wired');
            }
            return {
              ok: true,
              data: { approvals: await deps.deviceLoginApprovals.list() },
            };
          case 'auth.deviceLogin.approvals.get':
            requireExtensionPage(context);
            if (!deps.deviceLoginApprovals) {
              throw new Error('auth.deviceLogin.approvals.get is not wired');
            }
            return {
              ok: true,
              data: { approval: await deps.deviceLoginApprovals.get(request.requestId) },
            };
          case 'auth.deviceLogin.approvals.approve': {
            requireExtensionPage(context);
            if (!deps.deviceLoginApprovals) {
              throw new Error('auth.deviceLogin.approvals.approve is not wired');
            }
            const decision = await finishDeviceLoginDecision(
              () => deps.deviceLoginApprovals!.approve(deviceLoginDecisionBinding(request)),
              deps.onDeviceLoginApprovalDecision,
            );
            return { ok: true, data: { decision } };
          }
          case 'auth.deviceLogin.approvals.deny': {
            requireExtensionPage(context);
            if (!deps.deviceLoginApprovals) {
              throw new Error('auth.deviceLogin.approvals.deny is not wired');
            }
            const decision = await finishDeviceLoginDecision(
              () => deps.deviceLoginApprovals!.deny(deviceLoginDecisionBinding(request)),
              deps.onDeviceLoginApprovalDecision,
            );
            return { ok: true, data: { decision } };
          }
          case 'auth.submitTwoFactor': {
            if (!deps.auth.submitTwoFactor) throw new Error('auth.submitTwoFactor is not wired');
            if (request.provider === 7) throw new AppError('denied', 'Use the security-key connector.');
            if (request.continuationId) {
              await deps.duo?.cancel({
                flow: 'password',
                continuationId: request.continuationId,
              });
            }
            return {
              ok: true,
              data: await deps.auth.submitTwoFactor(
                {
                  provider: request.provider,
                  code: request.code,
                  ...(request.remember !== undefined ? { remember: request.remember } : {}),
                  ...(request.continuationId ? { continuationId: request.continuationId } : {}),
                },
              ),
            };
          }
          case 'auth.duo.begin': {
            const caller = requirePopupPage(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.duo) throw new Error('Duo two-factor is not wired');
            return { ok: true, data: await deps.duo.begin(request, caller.documentId) };
          }
          case 'auth.duo.cancel': {
            requirePopupPage(context);
            if (!deps.duo) throw new Error('Duo two-factor is not wired');
            const cancelled = request.flow === 'password'
              ? await deps.duo.cancel({
                  flow: 'password',
                  continuationId: request.continuationId,
                })
              : await deps.duo.cancel({
                  flow: 'deviceLogin',
                  generation: request.generation,
                  provider: request.provider,
                });
            return { ok: true, data: { cancelled } };
          }
          case 'auth.beginFido2': {
            const caller = requireExtensionPage(context);
            if (!deps.interactiveTwoFactor) throw new Error('Interactive two-factor is not wired');
            if (!deps.fido2Connector) throw new Error('FIDO2 connector is not wired');
            const broker = request.owner.flow === 'password'
              ? deps.interactiveTwoFactor.password
              : deps.interactiveTwoFactor.deviceLogin;
            if (request.owner.flow === 'password') {
              await deps.duo?.cancel({
                flow: 'password',
                continuationId: request.owner.bindingId,
              });
            } else {
              await deps.duo?.cancelDeviceLogin(request.owner.generation);
            }
            const launch = await broker.begin({
              owner: request.owner,
              parentUrl: caller.url,
              locale: request.locale,
            });
            let ownerMatches = false;
            try {
              ownerMatches = sameInteractiveTwoFactorOwner(launch.owner, request.owner);
            } catch {
              // The selected broker still owns any reservation it returned, even if its owner is invalid.
            }
            if (!ownerMatches) {
              const mismatchError = new AppError(
                'denied',
                'Interactive two-factor owner changed during launch.',
              );
              try {
                await broker.cancelLaunch({ owner: launch.owner, url: launch.url });
              } catch (cleanupError) {
                throw new AggregateError(
                  [mismatchError, cleanupError],
                  'The interactive two-factor launch owner changed and its reservation could not be released.',
                  { cause: cleanupError },
                );
              }
              throw mismatchError;
            }
            let connector: InteractiveTwoFactorConnectorDocument;
            try {
              connector = await deps.fido2Connector.open(launch.url, launch.replace);
            } catch (error) {
              await broker.cancelLaunch({ owner: launch.owner, url: launch.url }).catch(() => false);
              throw error;
            }
            try {
              await broker.bindTab({
                owner: launch.owner,
                url: connector.url,
                tabId: connector.tabId,
                documentId: connector.documentId,
              });
            } catch (error) {
              await broker.cancelLaunch({ owner: launch.owner, url: launch.url }).catch(() => false);
              try {
                await deps.fido2Connector.close(connector);
              } catch (closeError) {
                throw new AggregateError(
                  [error, closeError],
                  'The security-key connector binding failed and its tab could not be closed.',
                  { cause: closeError },
                );
              }
              throw error;
            }
            return { ok: true, data: null };
          }
          case 'auth.completeFido2': {
            const caller = requireContentTopFrame(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.interactiveTwoFactor) throw new Error('Interactive two-factor is not wired');
            if (!deps.fido2Connector) throw new Error('FIDO2 connector is not wired');
            const callerBinding = {
              url: caller.url,
              tabId: caller.tabId,
              documentId: caller.documentId,
            };
            const passwordOwner = deps.interactiveTwoFactor.password.matchCaller(callerBinding);
            const deviceOwner = deps.interactiveTwoFactor.deviceLogin.matchCaller(callerBinding);
            if (Boolean(passwordOwner) === Boolean(deviceOwner)) {
              throw new AppError('denied', 'sender not permitted');
            }
            const documentClaim = JSON.stringify([
              callerBinding.tabId,
              callerBinding.documentId,
              callerBinding.url,
            ]);
            if (claimedInteractiveDocuments.has(documentClaim)) {
              throw new AppError('denied', 'sender not permitted');
            }
            claimedInteractiveDocuments.add(documentClaim);
            let outcome: 'success' | 'error' = 'error';
            try {
              const result = passwordOwner
                ? await deps.interactiveTwoFactor.password.complete({
                    owner: passwordOwner,
                    ...callerBinding,
                    token: request.token,
                    remember: request.remember,
                  })
                : await deps.interactiveTwoFactor.deviceLogin.complete({
                    owner: deviceOwner!,
                    ...callerBinding,
                    token: request.token,
                    remember: request.remember,
                  });
              if ('kind' in result) {
                if (result.kind === 'unlocked'
                  || result.kind === 'locked'
                  || result.kind === 'restricted') outcome = 'success';
              } else if (result.status === 'unlocked' || result.status === 'restricted') {
                outcome = 'success';
              }
              return {
                ok: true,
                data: result,
              };
            } finally {
              await deps.fido2Connector.finish(callerBinding, outcome).catch(() => undefined);
            }
          }
          case 'auth.sendEmailCode':
            if (!deps.auth.sendEmailCode) throw new Error('auth.sendEmailCode is not wired');
            await deps.auth.sendEmailCode({
              ...(request.continuationId ? { continuationId: request.continuationId } : {}),
            });
            return { ok: true, data: null };
          case 'auth.openTwoFactorRecovery':
            requirePopupPage(context);
            if (!isExactTwoFactorRecoveryRequest(request)) {
              throw new AppError('denied', 'Invalid two-step recovery request.');
            }
            if (!deps.twoFactorRecovery) {
              throw new Error('auth.openTwoFactorRecovery is not wired');
            }
            await deps.twoFactorRecovery.open();
            return { ok: true, data: null };
          case 'auth.unlock':
            if (!deps.auth.unlock) throw new Error('auth.unlock is not wired');
            await deps.auth.unlock(request.masterPassword);
            return { ok: true, data: null };
          case 'auth.verifyMasterPassword':
            if (!deps.auth.verifyMasterPassword) throw new Error('auth.verifyMasterPassword is not wired');
            return { ok: true, data: { verified: await deps.auth.verifyMasterPassword(request.masterPassword) } };
          case 'auth.changePassword':
            if (!deps.auth.changeMasterPassword) throw new Error('auth.changeMasterPassword is not wired');
            await deps.auth.changeMasterPassword(
              request.currentPassword,
              request.newPassword,
              request.masterPasswordHint,
            );
            return { ok: true, data: null };
          case 'auth.changeKdf':
            if (!deps.auth.changeKdf) throw new Error('auth.changeKdf is not wired');
            await deps.auth.changeKdf(request.currentPassword, request.kdf);
            return { ok: true, data: null };
          case 'auth.rotateAccountKey':
            if (!deps.auth.rotateAccountKey) throw new Error('auth.rotateAccountKey is not wired');
            await deps.auth.rotateAccountKey(request.masterPassword);
            return { ok: true, data: null };
          case 'auth.unlockWithPin':
            assertValidPinRequest(request.pin);
            if (!deps.auth.unlockWithPin) throw new Error('auth.unlockWithPin is not wired');
            await deps.auth.unlockWithPin(request.pin);
            return { ok: true, data: null };
          case 'auth.setPin':
            assertValidPinRequest(request.pin);
            if (!deps.auth.setPin) throw new Error('auth.setPin is not wired');
            await deps.auth.setPin(request.pin, request.requireMasterPasswordOnRestart);
            return { ok: true, data: null };
          case 'auth.changeForcedPassword':
            requireExtensionPage(context);
            if (!deps.auth.changeForcedMasterPassword) {
              throw new Error('auth.changeForcedMasterPassword is not wired');
            }
            await deps.auth.changeForcedMasterPassword(
              request.currentPassword,
              request.newPassword,
            );
            return { ok: true, data: null };
          case 'auth.disablePin':
            if (!deps.auth.disablePin) throw new Error('auth.disablePin is not wired');
            await deps.auth.disablePin();
            return { ok: true, data: null };
          case 'auth.pinStatus': {
            if (deps.auth.getPinStatus) {
              return { ok: true, data: await deps.auth.getPinStatus() };
            }
            if (!deps.auth.isPinEnabled) throw new Error('auth.isPinEnabled is not wired');
            const enabled = await deps.auth.isPinEnabled();
            return {
              ok: true,
              data: {
                enabled,
                available: enabled,
                allowed: true,
                requireMasterPasswordOnRestart: true,
              },
            };
          }
          case 'auth.lock':
            if (!deps.auth.lock) throw new Error('auth.lock is not wired');
            await deps.auth.lock();
            return { ok: true, data: null };
          case 'auth.logout':
            if (!deps.logout && !deps.auth.logout) throw new Error('auth.logout is not wired');
            await deps.accountPasskey?.cancel();
            if (deps.logout) await deps.logout();
            else {
              await flushActiveClientEvents(deps);
              if (!(await authIsAlreadyLoggedOut(deps))) await deps.auth.logout!();
            }
            return { ok: true, data: null };
          case 'auth.listAccounts':
            if (!deps.auth.listAccounts) throw new Error('auth.listAccounts is not wired');
            return { ok: true, data: { accounts: await deps.auth.listAccounts() } };
          case 'auth.switchAccount':
            if (!deps.auth.switchAccount) throw new Error('auth.switchAccount is not wired');
            await deps.accountPasskey?.cancel();
            await flushActiveClientEvents(deps);
            await deps.auth.switchAccount(request.email);
            return { ok: true, data: null };
          case 'auth.removeAccount': {
            if (!deps.auth.removeAccount) throw new Error('auth.removeAccount is not wired');
            const accountRemovalReceipt = await captureAccountRemovalClientEvents(deps, request.email);
            await deps.accountPasskey?.cancel();
            await flushActiveClientEvents(deps);
            await deps.auth.removeAccount(request.email);
            await completeAccountRemovalClientEvents(deps, accountRemovalReceipt);
            return { ok: true, data: null };
          }
          case 'generator.history.list': {
            if (!deps.generatorHistory) throw new Error('generator.history.list is not wired');
            const result = await deps.generatorHistory.list(bindVaultFinalAuthority);
            const entries = parseGeneratorHistoryEntries(result.entries);
            if (!entries) throw new AppError('error', 'Generator history response is invalid');
            return { ok: true, data: { entries } };
          }
          case 'generator.history.track': {
            if (!deps.generatorHistory) throw new Error('generator.history.track is not wired');
            const result = await deps.generatorHistory.track(request.entry);
            if (typeof result.added !== 'boolean') {
              throw new AppError('error', 'Generator history response is invalid');
            }
            return { ok: true, data: { added: result.added } };
          }
          case 'generator.history.clear': {
            if (!deps.generatorHistory) throw new Error('generator.history.clear is not wired');
            const result = await deps.generatorHistory.clear();
            if (typeof result.cleared !== 'boolean') {
              throw new AppError('error', 'Generator history response is invalid');
            }
            return { ok: true, data: { cleared: result.cleared } };
          }
          case 'auth.forgetDevice':
            if (!deps.auth.forgetDevice) throw new Error('auth.forgetDevice is not wired');
            await deps.auth.forgetDevice(request.email);
            return { ok: true, data: null };
          case 'auth.isDeviceRemembered':
            if (!deps.auth.isDeviceRemembered) throw new Error('auth.isDeviceRemembered is not wired');
            return { ok: true, data: { remembered: await deps.auth.isDeviceRemembered(request.email) } };
          case 'vault.authorizeExport': {
            requireOptionsPage(context);
            if (!sessionLease || !deps.auth.verifyMasterPassword || !deps.exportGrants) {
              throw new AppError('denied', 'Vault export verification is unavailable.');
            }
            let target: VaultTransferExportTarget;
            try {
              target = canonicalizeVaultTransferExportTarget(
                request.target ?? PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
              );
            } catch {
              throw new AppError('denied', 'Vault export verification failed.');
            }
            if (
              (request.format !== 'json'
                && request.format !== 'encrypted-json'
                && request.format !== 'csv'
                && request.format !== 'zip')
              || (request.format === 'encrypted-json'
                && request.encryptionType !== 'account'
                && request.encryptionType !== 'file')
              || (request.format !== 'encrypted-json' && request.encryptionType !== undefined)
              || typeof request.masterPassword !== 'string'
              || request.masterPassword.length < 1
              || request.masterPassword.length > 4_096
              || (target.kind === 'organization' && request.format === 'zip')
            ) {
              throw new AppError('denied', 'Vault export verification failed.');
            }
            const accountLease = deps.accountGate.capture();
            const policyGate = deps.enterprisePolicyGate;
            if (!policyGate) {
              throw new AppError('denied', 'Enterprise policy state is unavailable.');
            }
            const policyLease = policyGate.capture();
            const policy = policyGate.assert(policyLease);
            if (target.kind === 'personal'
              && !enterprisePolicyAllows(policy, 'exportPersonalVault')) {
              throw new AppError('denied', 'Enterprise policy denies vault export.');
            }
            const verification = deps.auth.verifyMasterPassword(request.masterPassword);
            request.masterPassword = '';
            const verified = await verification;
            deps.sessionGate.assert(sessionLease);
            deps.accountGate.assert(accountLease);
            const currentPolicy = policyGate.assert(policyLease);
            if (!verified || (target.kind === 'personal'
              && !enterprisePolicyAllows(currentPolicy, 'exportPersonalVault'))) {
              throw new AppError('denied', 'Vault export verification failed.');
            }
            try {
              return {
                ok: true,
                data: deps.exportGrants.issue({
                  format: request.format,
                  ...(request.encryptionType ? { encryptionType: request.encryptionType } : {}),
                  target,
                  sessionLease,
                  accountLease,
                  policyLease,
                }),
              };
            } catch {
              throw new AppError('denied', 'Vault export verification could not be authorized.');
            }
          }
          case 'vault.sync':
            if (deps.syncScheduler) {
              await deps.syncScheduler.manual();
              if (!deps.vault.listItems) throw new Error('vault.listItems is not wired');
              return { ok: true, data: await deps.vault.listItems() };
            }
            if (!deps.vault.sync) throw new Error('vault.sync is not wired');
            return { ok: true, data: await deps.vault.sync() };
          case 'vault.popupOpened':
            requirePopupPage(context);
            await deps.syncScheduler?.popupOpened();
            return { ok: true, data: null };
          case 'vault.getSyncStatus': {
            requireExtensionPage(context);
            return {
              ok: true,
              data: await deps.syncScheduler?.getSyncStatus()
                ?? { dirty: false, syncing: false },
            };
          }
          case 'vault.listItems':
            if (!deps.vault.listItems) throw new Error('vault.listItems is not wired');
            return { ok: true, data: await deps.vault.listItems() };
          case 'vault.getField': {
            if (!deps.vault.getField) throw new Error('vault.getField is not wired');
            const eventType = fieldClientEventType(request.field, request.clientEventPurpose);
            const owner = eventType ? popupClientEventOwner(context) : undefined;
            const value = await deps.vault.getField(
              request.id, request.field, request.masterPassword, bindVaultFinalAuthority,
            );
            const clientEventAckId = value !== undefined && eventType && owner
              ? await issueClientEventAck(
                  deps,
                  owner,
                  { type: eventType, cipherId: request.id },
                  popupAckCurrent(deps, sessionLease),
                  vaultFinalAuthorities,
                )
              : undefined;
            return {
              ok: true,
              data: value === undefined
                ? {}
                : { value, ...(clientEventAckId ? { clientEventAckId } : {}) },
            };
          }
          case 'vault.getCustomField': {
            if (!deps.vault.getCustomField) throw new Error('vault.getCustomField is not wired');
            const purpose = request.clientEventPurpose;
            if (purpose !== undefined && purpose !== 'reveal' && purpose !== 'copy') {
              throw new AppError('denied', 'Client event purpose is invalid.');
            }
            const owner = purpose ? popupClientEventOwner(context) : undefined;
            let hidden = false;
            if (purpose) {
              if (!deps.vault.getCipherDetail) throw new Error('vault.getCipherDetail is not wired');
              const detail = await deps.vault.getCipherDetail(
                request.id, request.masterPassword, bindVaultFinalAuthority,
              );
              hidden = detail?.fields?.[request.index]?.type === 1;
            }
            const value = await deps.vault.getCustomField(
              request.id, request.index, request.masterPassword, bindVaultFinalAuthority,
            );
            const eventType = purpose === 'reveal'
              ? ClientEventType.Cipher_ClientToggledHiddenFieldVisible
              : purpose === 'copy'
                ? ClientEventType.Cipher_ClientCopiedHiddenField
                : undefined;
            const clientEventAckId = value !== undefined && hidden && eventType && owner
              ? await issueClientEventAck(
                  deps,
                  owner,
                  { type: eventType, cipherId: request.id },
                  popupAckCurrent(deps, sessionLease),
                  vaultFinalAuthorities,
                )
              : undefined;
            return {
              ok: true,
              data: value === undefined
                ? {}
                : { value, ...(clientEventAckId ? { clientEventAckId } : {}) },
            };
          }
          case 'vault.getCipherDetail': {
            if (!deps.vault.getCipherDetail) throw new Error('vault.getCipherDetail is not wired');
            if (request.clientEventPurpose !== undefined
                && request.clientEventPurpose !== 'view'
                && request.clientEventPurpose !== 'editor') {
              throw new AppError('denied', 'Client event purpose is invalid.');
            }
            const owner = request.clientEventPurpose ? popupClientEventOwner(context) : undefined;
            const cipher = await deps.vault.getCipherDetail(
              request.id, request.masterPassword, bindVaultFinalAuthority,
            );
            const clientEventAckId = cipher && owner
              ? await issueClientEventAck(
                  deps,
                  owner,
                  { type: ClientEventType.Cipher_ClientViewed, cipherId: request.id },
                  popupAckCurrent(deps, sessionLease),
                  vaultFinalAuthorities,
                )
              : undefined;
            return {
              ok: true,
              data: { cipher: cipher ?? null, ...(clientEventAckId ? { clientEventAckId } : {}) },
            };
          }
          case 'vault.getAttachment': {
            if (!deps.vault.getAttachment) throw new Error('vault.getAttachment is not wired');
            return { ok: true, data: await deps.vault.getAttachment(
              request.cipherId, request.attachmentId, request.masterPassword, bindVaultFinalAuthority,
            ) };
          }
          case 'vault.addAttachment': {
            if (!deps.vault.addAttachment) throw new Error('vault.addAttachment is not wired');
            return { ok: true, data: await deps.vault.addAttachment(request.cipherId, request.fileName, request.dataB64, request.masterPassword) };
          }
          case 'vault.upgradeLegacyAttachment': {
            requireExtensionPage(context);
            if (!deps.vault.upgradeLegacyAttachment) {
              throw new Error('vault.upgradeLegacyAttachment is not wired');
            }
            return { ok: true, data: await deps.vault.upgradeLegacyAttachment(
              request.cipherId,
              request.attachmentId,
              request.masterPassword,
            ) };
          }
          case 'vault.deleteAttachment': {
            if (!deps.vault.deleteAttachment) throw new Error('vault.deleteAttachment is not wired');
            return { ok: true, data: await deps.vault.deleteAttachment(request.cipherId, request.attachmentId) };
          }
          case 'vault.getSshKeyWriteAvailability': {
            requireExtensionPage(context);
            if (!deps.vault.getSshKeyWriteAvailability) {
              throw new Error('vault.getSshKeyWriteAvailability is not wired');
            }
            return { ok: true, data: await deps.vault.getSshKeyWriteAvailability() };
          }
          case 'vault.getSshKeyDetails': {
            requireExtensionPage(context);
            if (!deps.vault.getSshKeyDetails) throw new Error('vault.getSshKeyDetails is not wired');
            const sshKey = await deps.vault.getSshKeyDetails(
              request.id, request.masterPassword, bindVaultFinalAuthority,
            );
            return { ok: true, data: { sshKey: sshKey ?? null } };
          }
          case 'vault.revealSshPrivateKey': {
            requireExtensionPage(context);
            if (!deps.vault.revealSshPrivateKey) throw new Error('vault.revealSshPrivateKey is not wired');
            const privateKey = await deps.vault.revealSshPrivateKey(
              request.id, request.masterPassword, bindVaultFinalAuthority,
            );
            return { ok: true, data: { privateKey: privateKey ?? null } };
          }
          case 'vault.createGeneratedSshKey': {
            requireExtensionPage(context);
            if (!deps.vault.createGeneratedSshKey) throw new Error('vault.createGeneratedSshKey is not wired');
            return { ok: true, data: await deps.vault.createGeneratedSshKey(request.metadata, request.target) };
          }
          case 'vault.importSshKey': {
            requireExtensionPage(context);
            if (!deps.vault.importSshKey) throw new Error('vault.importSshKey is not wired');
            return { ok: true, data: await deps.vault.importSshKey(request.metadata, request.privateKey, request.target) };
          }
          case 'vault.replaceSshKey': {
            requireExtensionPage(context);
            if (!deps.vault.replaceSshKey) throw new Error('vault.replaceSshKey is not wired');
            return {
              ok: true,
              data: await deps.vault.replaceSshKey(
                request.id,
                request.privateKey,
                request.masterPassword,
              ),
            };
          }
          case 'vault.updateSshKeyMetadata': {
            requireExtensionPage(context);
            if (!deps.vault.updateSshKeyMetadata) throw new Error('vault.updateSshKeyMetadata is not wired');
            return {
              ok: true,
              data: await deps.vault.updateSshKeyMetadata(
                request.id,
                request.metadata,
                request.masterPassword,
              ),
            };
          }
          case 'vault.getPasswordHistory': {
            if (!deps.vault.getPasswordHistory) throw new Error('vault.getPasswordHistory is not wired');
            return { ok: true, data: { history: await deps.vault.getPasswordHistory(
              request.id, request.masterPassword, bindVaultFinalAuthority,
            ) } };
          }
          case 'vault.getTotp': {
            if (!deps.vault.getTotpCode) throw new Error('vault.getTotpCode is not wired');
            const totp = await deps.vault.getTotpCode(
              request.id, request.masterPassword, bindVaultFinalAuthority,
            );
            return { ok: true, data: { totp: totp ?? null } };
          }
          case 'vault.getTotpCodes': {
            if (!deps.vault.listTotpCodes) throw new Error('vault.listTotpCodes is not wired');
            return { ok: true, data: { totpEntries: await deps.vault.listTotpCodes(bindVaultFinalAuthority) } };
          }
          case 'vault.getSkippedOrgCount': {
            if (!deps.vault.getSkippedOrgCount) throw new Error('vault.getSkippedOrgCount is not wired');
            return { ok: true, data: { count: await deps.vault.getSkippedOrgCount() } };
          }
          case 'vault.getOrganizationDataOwnershipStatus': {
            const caller = requirePopupPage(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.vault.getOrganizationDataOwnershipStatus) {
              throw new Error('vault.getOrganizationDataOwnershipStatus is not wired');
            }
            return {
              ok: true,
              data: await deps.vault.getOrganizationDataOwnershipStatus(caller.documentId),
            };
          }
          case 'vault.migrateOrganizationDataOwnership': {
            const caller = requirePopupPage(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.vault.migrateOrganizationDataOwnership) {
              throw new Error('vault.migrateOrganizationDataOwnership is not wired');
            }
            const eventReceipt = await prepareClientEvent(deps, {
              type: ClientEventType.Organization_ItemOrganization_Accepted,
              organizationId: request.organizationId,
            });
            let migration: Promise<Awaited<ReturnType<NonNullable<typeof deps.vault.migrateOrganizationDataOwnership>>>>;
            try {
              migration = deps.vault.migrateOrganizationDataOwnership(
                request.organizationId,
                request.collectionId,
                request.authorizationId,
                caller.documentId,
                request.masterPassword,
              );
            } finally {
              request.masterPassword = '';
            }
            const result = await migration;
            await commitClientEvent(deps, eventReceipt);
            return { ok: true, data: result };
          }
          case 'vault.leaveOrganizationDataOwnership': {
            const caller = requirePopupPage(context);
            if (!caller.documentId) throw new AppError('denied', 'sender not permitted');
            if (!deps.vault.leaveOrganizationDataOwnership) {
              throw new Error('vault.leaveOrganizationDataOwnership is not wired');
            }
            let supportsDecline = false;
            try {
              supportsDecline = deps.clientEvents?.supportsOrganizationDecline?.() === true;
            } catch {
              // Capability uncertainty disables this optional audit event, never the leave action.
            }
            const eventReceipt = supportsDecline
              ? await prepareClientEvent(deps, {
                  type: ClientEventType.Organization_ItemOrganization_Declined,
                  organizationId: request.organizationId,
                })
              : undefined;
            const result = await deps.vault.leaveOrganizationDataOwnership(
              request.organizationId,
              request.authorizationId,
              caller.documentId,
            );
            await commitClientEvent(deps, eventReceipt);
            return { ok: true, data: result };
          }
          case 'vault.getPasswordHealth': {
            if (!deps.vault.getPasswordHealth) throw new Error('vault.getPasswordHealth is not wired');
            return { ok: true, data: { entries: await deps.vault.getPasswordHealth() } };
          }
          case 'vault.checkPwned': {
            if (!deps.vault.getPwnedReport) throw new Error('vault.getPwnedReport is not wired');
            return { ok: true, data: { entries: await deps.vault.getPwnedReport() } };
          }
          case 'vault.createFolder':
            if (!deps.vault.createFolder) throw new Error('vault.createFolder is not wired');
            return { ok: true, data: await deps.vault.createFolder(request.name) };
          case 'vault.renameFolder':
            if (!deps.vault.renameFolder) throw new Error('vault.renameFolder is not wired');
            return { ok: true, data: await deps.vault.renameFolder(request.id, request.name) };
          case 'vault.deleteFolder':
            if (!deps.vault.deleteFolder) throw new Error('vault.deleteFolder is not wired');
            return { ok: true, data: await deps.vault.deleteFolder(request.id) };
          case 'vault.createCollection':
            if (!deps.vault.createCollection) throw new Error('vault.createCollection is not wired');
            return { ok: true, data: await deps.vault.createCollection(request.organizationId, request.name) };
          case 'vault.renameCollection':
            if (!deps.vault.renameCollection) throw new Error('vault.renameCollection is not wired');
            return { ok: true, data: await deps.vault.renameCollection(request.organizationId, request.id, request.name) };
          case 'vault.deleteCollection':
            if (!deps.vault.deleteCollection) throw new Error('vault.deleteCollection is not wired');
            return { ok: true, data: await deps.vault.deleteCollection(request.organizationId, request.id) };
          case 'vault.setCipherCollections':
            if (!deps.vault.setCipherCollections) throw new Error('vault.setCipherCollections is not wired');
            return { ok: true, data: await deps.vault.setCipherCollections(request.id, request.collectionIds) };
          case 'vault.createCipher':
            if (!deps.vault.createCipher) throw new Error('vault.createCipher is not wired');
            if ((request.input as { readonly type?: unknown }).type === 5) {
              throw new AppError('denied', 'SSH key writes require a dedicated SSH command.');
            }
            return { ok: true, data: await deps.vault.createCipher(request.input, request.target) };
          case 'vault.updateCipher':
            if (!deps.vault.updateCipher) throw new Error('vault.updateCipher is not wired');
            if ((request.input as { readonly type?: unknown }).type === 5) {
              throw new AppError('denied', 'SSH key writes require a dedicated SSH command.');
            }
            return { ok: true, data: await deps.vault.updateCipher(request.id, request.input) };
          case 'vault.setCipherFavorite':
            if (!deps.vault.setCipherFavorite) throw new Error('vault.setCipherFavorite is not wired');
            return { ok: true, data: await deps.vault.setCipherFavorite(request.id, request.favorite) };
          case 'vault.deleteCipher':
            if (!deps.vault.deleteCipher) throw new Error('vault.deleteCipher is not wired');
            return { ok: true, data: await deps.vault.deleteCipher(request.id) };
          case 'vault.softDeleteCipher':
            if (!deps.vault.softDeleteCipher) throw new Error('vault.softDeleteCipher is not wired');
            return { ok: true, data: await deps.vault.softDeleteCipher(request.id) };
          case 'vault.restoreCipher':
            if (!deps.vault.restoreCipher) throw new Error('vault.restoreCipher is not wired');
            return { ok: true, data: await deps.vault.restoreCipher(request.id) };
          case 'vault.archiveCipher':
            if (!deps.vault.archiveCipher) throw new Error('vault.archiveCipher is not wired');
            return { ok: true, data: await deps.vault.archiveCipher(request.id, request.masterPassword) };
          case 'vault.unarchiveCipher':
            if (!deps.vault.unarchiveCipher) throw new Error('vault.unarchiveCipher is not wired');
            return { ok: true, data: await deps.vault.unarchiveCipher(request.id, request.masterPassword) };
          case 'vault.deletePasskey':
            if (!deps.vault.deletePasskey) throw new Error('vault.deletePasskey is not wired');
            return {
              ok: true,
              data: await deps.vault.deletePasskey(
                request.id,
                request.credentialId,
                request.masterPassword,
              ),
            };
          case 'vault.shareCipher':
            if (!deps.vault.shareCipher) throw new Error('vault.shareCipher is not wired');
            return { ok: true, data: await deps.vault.shareCipher(request.id, request.organizationId, request.collectionIds, request.masterPassword) };
          case 'vault.getCipherInput': {
            if (!deps.vault.getCipherInput) throw new Error('vault.getCipherInput is not wired');
            const cipherInputPurpose = strictCipherInputPurpose(request);
            const owner = request.clientEventPurpose ? popupClientEventOwner(context) : undefined;
            const input = await deps.vault.getCipherInput(
              request.id, request.masterPassword, cipherInputPurpose, bindVaultFinalAuthority,
            );
            const clientEventAckId = input && owner
              ? await issueClientEventAck(
                  deps,
                  owner,
                  { type: ClientEventType.Cipher_ClientViewed, cipherId: request.id },
                  popupAckCurrent(deps, sessionLease),
                  vaultFinalAuthorities,
                )
              : undefined;
            return {
              ok: true,
              data: { input: input ?? null, ...(clientEventAckId ? { clientEventAckId } : {}) },
            };
          }
          case 'clientEvent.ack': {
            const owner = clientEventAckOwnerFromContext(context);
            if (deps.clientEventAcks) {
              await bestEffortClientEvent(() => deps.clientEventAcks!.consume(request.ackId, owner));
            }
            return { ok: true, data: null };
          }
          case 'autofill.ackTotpCopy': {
            const caller = requireContent(context);
            if (!caller.documentId || !deps.autofillTotpCopies) {
              return { ok: true, data: { copied: false } };
            }
            const result = await deps.autofillTotpCopies.consumeContent(request.ackId, {
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
            });
            return { ok: true, data: { copied: result.kind === 'copied' } };
          }
          case 'settings.get': {
            const enterpriseRead = beginEnterprisePolicyRead(deps);
            const [
              serverUrl,
              lockTimeout,
              onIdleAction,
              clipboardClearSeconds,
              showMatchingLoginCount,
              autofillState,
              websitePasskeyState,
              httpAuthState,
            ] = await Promise.all([
              deps.settings.getServerUrl(),
              deps.settings.getLockTimeout(),
              deps.settings.getOnIdleAction(),
              deps.settings.getClipboardClearSetting(),
              deps.settings.getShowMatchingLoginCount?.() ?? Promise.resolve(true),
              (deps.settings.getAutofillPolicySettings?.() ?? Promise.resolve(DEFAULT_AUTOFILL_POLICY_SETTINGS))
                .then((settings) => ({ valid: true as const, settings }))
                 .catch(() => ({ valid: false as const, settings: {
                   ...DEFAULT_AUTOFILL_POLICY_SETTINGS,
                   inlineSuggestions: false,
                   pageLoadFill: false,
                   savePromptEnabled: false,
                   updatePromptEnabled: false,
                   savePromptExcludedDomains: [],
                 } })),
              (deps.settings.getWebsitePasskeySettings?.() ?? Promise.resolve(DEFAULT_WEBSITE_PASSKEY_SETTINGS))
                .then((settings) => ({ valid: true as const, settings }))
                .catch(() => ({ valid: false as const, settings: DEFAULT_WEBSITE_PASSKEY_SETTINGS })),
              (deps.httpAuthSettings?.get() ?? Promise.resolve({
                settings: DEFAULT_HTTP_AUTH_SETTINGS,
                valid: true,
              })).catch(() => ({ settings: DEFAULT_HTTP_AUTH_SETTINGS, valid: false })),
            ]);
            const enterprise = finishEnterprisePolicyRead(deps, enterpriseRead);
            const effectiveUriMatchDefault = enterprise.snapshot
              ? resolveEnterpriseUriMatchDefault(
                  autofillState.settings.defaultUriMatchStrategy,
                  enterprise.snapshot,
                )
              : {
                  value: UriMatchStrategy.Never,
                  managed: true,
                  malformed: true,
                };
            const generator = enterprise.snapshot && enterpriseRead.kind === 'captured'
              ? createGeneratorPolicySnapshot(
                  enterprise.snapshot.passwordGeneratorPolicy,
                  enterpriseRead.lease.generation,
                )
              : UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
            const effectiveTimeout = resolveEffectiveVaultTimeout(
              lockTimeout,
              onIdleAction,
              enterprise.timeout,
            );
            const base = {
              defaultUriMatchStrategy: effectiveUriMatchDefault.value,
              lockTimeout: effectiveTimeout.lockTimeout,
              onIdleAction: effectiveTimeout.onIdleAction,
              clipboardClearSeconds,
              showMatchingLoginCount,
               inlineSuggestions: autofillState.settings.inlineSuggestions,
               pageLoadFill: autofillState.settings.pageLoadFill,
               pageLoadFillDefault: autofillState.settings.pageLoadFillDefault,
               autoCopyTotp: autofillState.settings.autoCopyTotp,
               savePromptEnabled: autofillState.settings.savePromptEnabled,
               updatePromptEnabled: autofillState.settings.updatePromptEnabled,
               savePromptExcludedDomains: [...autofillState.settings.savePromptExcludedDomains],
               blockedDomains: [...autofillState.settings.blockedDomains],
              autofillPolicyValid: autofillState.valid,
              websitePasskeys: {
                enabled: websitePasskeyState.valid && websitePasskeyState.settings.enabled,
                excludedDomains: websitePasskeyState.valid
                  ? [...websitePasskeyState.settings.excludedDomains]
                  : [],
                valid: websitePasskeyState.valid,
              },
              httpAuth: {
                enabled: httpAuthState.valid && httpAuthState.settings.enabled,
                allowedOrigins: httpAuthState.valid
                  ? [...httpAuthState.settings.allowedOrigins]
                  : [],
                valid: httpAuthState.valid,
              },
              enterprisePolicy: {
                pinUnlockAllowed: enterprise.pinUnlockAllowed,
                maximumVaultTimeoutManaged: effectiveTimeout.managed,
                maximumVaultTimeoutMode: effectiveTimeout.mode,
                 uriMatchDefaultManaged: effectiveUriMatchDefault.managed,
                 uriMatchDefaultMalformed: effectiveUriMatchDefault.malformed,
                 activateAutofillManaged: enterprise.snapshot?.activateAutofillRequired === true,
               },
               generator,
            };
            return { ok: true, data: serverUrl === undefined ? base : { serverUrl, ...base } };
          }
          case 'settings.save': {
            if (request.serverUrl !== undefined) {
              const currentServerUrl = await deps.settings.getServerUrl();
              const nextServerUrl = normalizeServerUrl(request.serverUrl);
              const currentNormalized = currentServerUrl === undefined
                ? undefined
                : normalizeServerUrl(currentServerUrl);
              if (currentNormalized !== nextServerUrl) {
                if (!deps.auth.resetForServerChange) throw new Error('auth.resetForServerChange is not wired');
                const serverChangeReceipt = currentNormalized === undefined
                  ? undefined
                  : await captureServerChangeClientEvents(deps, currentNormalized);
                await Promise.all([deps.deviceLogin?.cancelCurrent(), deps.accountPasskey?.cancel()]);
                await flushActiveClientEvents(deps);
                await deps.auth.resetForServerChange(
                  () => deps.settings.saveServerUrl(request.serverUrl!),
                );
                await completeServerChangeClientEvents(deps, serverChangeReceipt);
              } else {
                await deps.settings.saveServerUrl(request.serverUrl);
              }
            }

            const policyChanged = request.defaultUriMatchStrategy !== undefined || request.autofillSettings !== undefined;
            if (policyChanged) {
              const enterpriseRead = beginEnterprisePolicyRead(deps);
              const current = await deps.settings.getAutofillPolicySettings?.();
              if (!current) throw new Error('settings.getAutofillPolicySettings is not wired');
              const enterprise = finishEnterprisePolicyRead(deps, enterpriseRead);
              if (!enterprise.snapshot) {
                throw new AppError('denied', 'Enterprise autofill policy is unavailable.');
              }
              if (request.defaultUriMatchStrategy !== undefined) {
                const effective = resolveEnterpriseUriMatchDefault(
                  current.defaultUriMatchStrategy,
                  enterprise.snapshot,
                );
                if (effective.managed) {
                  throw new AppError('denied', 'The default URI match strategy is managed by your organization.');
                }
              }
              const requestedAutofill = request.autofillSettings === undefined
                ? undefined
                : sanitizeRequestedAutofillSettings(request.autofillSettings);
              assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
              deps.autofillTotpCopies?.revokeAll();
              deps.inlineGeneratorTracks?.revokeAll();
              deps.autofillPolicyGate.invalidate();
              try {
                if (!deps.settings.saveAutofillPolicySettings) {
                  throw new Error('settings.saveAutofillPolicySettings is not wired');
                }
                assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
                await deps.settings.saveAutofillPolicySettings({
                  ...current,
                  ...(request.defaultUriMatchStrategy === undefined
                    ? {}
                    : { defaultUriMatchStrategy: request.defaultUriMatchStrategy }),
                  ...(requestedAutofill === undefined
                    ? {}
                    : {
                        ...requestedAutofill.settings,
                        pageLoadFill: enterprise.snapshot.activateAutofillRequired
                          ? current.pageLoadFill
                          : requestedAutofill.settings.pageLoadFill,
                        pageLoadFillDefault: requestedAutofill.pageLoadFillDefault,
                      }),
                }, () => assertEnterprisePolicyReadCurrent(deps, enterpriseRead));
                assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
              } finally {
                deps.autofillPolicyGate.invalidate();
              }
            }
            if (request.lockTimeout !== undefined) {
              const enterpriseRead = beginEnterprisePolicyRead(deps);
              await deps.settings.getOnIdleAction();
              const enterprise = finishEnterprisePolicyRead(deps, enterpriseRead);
              if (!isVaultTimeoutValueAllowed(request.lockTimeout, enterprise.timeout)) {
                throw new AppError('denied', 'The requested vault timeout is not allowed by your organization.');
              }
              assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
              await deps.settings.saveLockTimeout(request.lockTimeout);
              assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
            }
            if (request.showMatchingLoginCount !== undefined) {
              if (typeof request.showMatchingLoginCount !== 'boolean'
                  || !deps.settings.saveShowMatchingLoginCount) {
                throw new Error('Invalid toolbar match-count setting');
              }
              await deps.settings.saveShowMatchingLoginCount(request.showMatchingLoginCount);
            }
            return { ok: true, data: null };
          }
          case 'settings.saveWebsitePasskeys': {
            requireExtensionPage(context);
            if (!deps.settings.saveWebsitePasskeySettings) {
              throw new Error('settings.saveWebsitePasskeySettings is not wired');
            }
            const ownKeys = Reflect.ownKeys(request);
            if (
              ownKeys.length !== 3
              || ownKeys.some((key) => typeof key !== 'string')
              || !['type', 'enabled', 'excludedDomains'].every((key) => Object.hasOwn(request, key))
            ) {
              throw new Error('Invalid website passkey settings');
            }
            const settings = sanitizeWebsitePasskeySettings({
              schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
              enabled: request.enabled,
              excludedDomains: request.excludedDomains,
            });
            await deps.settings.saveWebsitePasskeySettings(settings);
            return { ok: true, data: null };
          }
          case 'settings.saveHttpAuth': {
            requireExtensionPage(context);
            if (!deps.httpAuthSettings) {
              throw new Error('settings.saveHttpAuth is not wired');
            }
            const ownKeys = Reflect.ownKeys(request);
            if (
              ownKeys.length !== 3
              || ownKeys.some((key) => typeof key !== 'string')
              || !['type', 'enabled', 'allowedOrigins'].every((key) => Object.hasOwn(request, key))
            ) {
              throw new Error('Invalid HTTP auth settings');
            }
            const next = sanitizeHttpAuthSettings({
              schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
              enabled: request.enabled,
              allowedOrigins: request.allowedOrigins,
            });
            deps.autofillPolicyGate.invalidate();
            try {
              await deps.httpAuthSettings.save(next);
            } finally {
              deps.autofillPolicyGate.invalidate();
            }
            return { ok: true, data: null };
          }
          case 'settings.saveSecurity': {
            const enterpriseRead = beginEnterprisePolicyRead(deps);
            await deps.settings.getLockTimeout();
            const enterprise = finishEnterprisePolicyRead(deps, enterpriseRead);
            if (!isVaultTimeoutActionAllowed(request.onIdleAction, enterprise.timeout)) {
              throw new AppError('denied', 'The requested vault timeout action is not allowed by your organization.');
            }
            assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
            await deps.settings.saveOnIdleAction(request.onIdleAction);
            assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
            await deps.settings.saveClipboardClearSetting(request.clipboardClearSeconds);
            if (request.clipboardClearSeconds === 'never') deps.clipboard?.cancelClear?.();
            assertEnterprisePolicyReadCurrent(deps, enterpriseRead);
            return { ok: true, data: null };
          }
          case 'clipboard.scheduleClear':
            if (!deps.clipboard) throw new Error('clipboard is not wired');
            await deps.clipboard.scheduleClear(
              context.kind === 'content' ? contentTotpClipboardCode(request) : request.value,
            );
            return { ok: true, data: null };
          case 'websitePasskey.reportIframeInventory': {
            const caller = requireContent(context);
            const policy = deps.websitePasskeyPermissionsPolicy;
            if (!policy) throw new Error('website passkey Permissions Policy is not wired');
            if (!caller.documentId) {
              policy.invalidateFrame(caller.tabId, caller.frameId);
              throw new AppError('denied', 'Website passkey iframe inventory is invalid.');
            }
            const sender = Object.freeze({
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              url: caller.url,
            });
            let parsed;
            try {
              parsed = parseWebsitePasskeyIframeInventoryRequest(request);
            } catch {
              policy.invalidateFrame(caller.tabId, caller.frameId);
              throw new AppError('denied', 'Website passkey iframe inventory is invalid.');
            }
            const accepted = await policy.recordIframeAllowReport(
              sender,
              { iframes: parsed.iframes },
            );
            if (!accepted) {
              throw new AppError('denied', 'Website passkey iframe inventory is invalid.');
            }
            return { ok: true, data: null };
          }
          case 'websitePasskey.getApproval': {
            requirePopupPage(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const approval = await deps.websitePasskeys.getApproval(websitePasskeyCeremonyId(request.ceremonyId));
            return { ok: true, data: { approval: approval ?? null } };
          }
          case 'websitePasskey.approve': {
            requirePopupPage(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const outcome = await deps.websitePasskeys.approve(
              websitePasskeyCeremonyId(request.ceremonyId),
              websitePasskeySelection(request.selection),
            );
            return { ok: true, data: { outcome } };
          }
          case 'websitePasskey.fallbackOnce': {
            requirePopupPage(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const outcome = await deps.websitePasskeys.fallbackOnce(websitePasskeyCeremonyId(request.ceremonyId));
            return { ok: true, data: { outcome } };
          }
          case 'websitePasskey.fallbackAlways': {
            requirePopupPage(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const outcome = await deps.websitePasskeys.fallbackAlways(websitePasskeyCeremonyId(request.ceremonyId));
            return { ok: true, data: { outcome } };
          }
          case 'websitePasskey.cancel': {
            requirePopupPage(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const outcome = await deps.websitePasskeys.cancel(websitePasskeyCeremonyId(request.ceremonyId));
            return { ok: true, data: { outcome } };
          }
          case 'websitePasskey.lockedStatus': {
            const popup = requirePopupDocument(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const continuationId = websitePasskeyLockedContinuationId(request, request.type);
            const status = await deps.websitePasskeys.getLockedContinuation(
              continuationId,
              popup.documentId,
            );
            return { ok: true, data: status };
          }
          case 'websitePasskey.resumeLocked': {
            const popup = requirePopupDocument(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const status = await deps.websitePasskeys.resumeLockedContinuation(
              websitePasskeyLockedContinuationId(request, request.type)!,
              popup.documentId,
            );
            return { ok: true, data: { status } };
          }
          case 'websitePasskey.cancelLocked': {
            const popup = requirePopupDocument(context);
            if (!deps.websitePasskeys) throw new Error('website passkey coordinator is not wired');
            const cancelled = await deps.websitePasskeys.cancelLockedContinuation(
              websitePasskeyLockedContinuationId(request, request.type)!,
              popup.documentId,
            );
            return { ok: true, data: { cancelled } };
          }
          case 'sends.list': {
            if (!deps.vault.listSends) throw new Error('vault.listSends is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            return { ok: true, data: { sends: await deps.vault.listSends(serverUrl, bindVaultFinalAuthority) } };
          }
          case 'sends.createText': {
            if (!deps.vault.createTextSend) throw new Error('vault.createTextSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            const send = await deps.vault.createTextSend(
              request.input, serverUrl, bindVaultFinalAuthority,
            );
            committedSecretMutation = true;
            captureCurrentResponseRelease();
            return { ok: true, data: { send } };
          }
          case 'sends.createFile': {
            if (!deps.vault.createFileSend) throw new Error('vault.createFileSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            const send = await deps.vault.createFileSend(
              request.input, request.dataB64, request.fileName, serverUrl, bindVaultFinalAuthority,
            );
            committedSecretMutation = true;
            captureCurrentResponseRelease();
            return { ok: true, data: { send } };
          }
          case 'sends.update': {
            if (!deps.vault.updateSend) throw new Error('vault.updateSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            const send = await deps.vault.updateSend(
              request.id, request.input, serverUrl, bindVaultFinalAuthority,
            );
            committedSecretMutation = true;
            captureCurrentResponseRelease();
            return { ok: true, data: { send } };
          }
          case 'sends.delete': {
            if (!deps.vault.deleteSend) throw new Error('vault.deleteSend is not wired');
            await deps.vault.deleteSend(request.id);
            return { ok: true, data: null };
          }
          case 'autofill.activateRuntime': {
            const caller = requireContent(context);
            if (!caller.documentId || !deps.saveCaptureCoordinator || !deps.getContentDocument) {
              throw deniedAutofillIntent();
            }
            const keys = Reflect.ownKeys(request);
            const hasPrevious = Object.hasOwn(request, 'previousRuntimeIncarnation');
            const expected = hasPrevious
              ? ['type', 'runtimeIncarnation', 'previousRuntimeIncarnation']
              : ['type', 'runtimeIncarnation'];
            if (keys.length !== expected.length
                || keys.some((key) => typeof key !== 'string' || !expected.includes(key))
                || expected.some((key) => {
                  const descriptor = Object.getOwnPropertyDescriptor(request, key);
                  return !descriptor?.enumerable || !('value' in descriptor);
                })) {
              throw deniedAutofillIntent();
            }
            const currentDocument = await deps.getContentDocument(caller.tabId, caller.frameId);
            let currentUrl: string | undefined;
            try { currentUrl = currentDocument ? new URL(currentDocument.url).href : undefined; }
            catch { /* Fail closed below. */ }
            if (!currentDocument
                || currentDocument.documentId !== caller.documentId
                || currentUrl !== new URL(caller.url).href) {
              throw deniedAutofillIntent();
            }
            const active = await deps.saveCaptureCoordinator.activateRuntime({
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              frameUrl: caller.url,
              runtimeIncarnation: runtimeIncarnationProperty(request),
              ...(!hasPrevious
                ? {}
                : {
                    previousRuntimeIncarnation: runtimeIncarnationProperty(
                      request,
                      'previousRuntimeIncarnation',
                    ),
                  }),
            });
            if (!active) throw deniedAutofillIntent();
            return { ok: true, data: { status: 'active' } };
          }
          case 'autofill.claimKeyboardGrant': {
            const caller = requireContent(context);
            if (!caller.documentId) throw deniedAutofillIntent();
            const topDocument = await currentKeyboardTopDocument(deps, caller.tabId);
            const command = deps.keyboardGrants.takeCommand(request.commandToken, {
              tabId: caller.tabId,
              topDocumentId: topDocument?.documentId ?? 'unavailable',
              topFrameUrl: topDocument?.url ?? 'https://invalid.invalid/',
            });
            if (!command) throw deniedAutofillIntent();
            const binding = await parseKeyboardClaimBinding(request.binding);
            if (!binding) throw deniedAutofillIntent();
            const claimedSessionLease = deps.sessionGate.capture();
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'intent');
            await assertKeyboardTopDocumentCurrent(deps, command);
            deps.accountGate.assert(accountLease);
            deps.sessionGate.assert(claimedSessionLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            const keyboardGrantId = deps.keyboardGrants.issueGrant({
              ...keyboardGrantContext(caller, contentRuntimeIncarnation!),
              topDocumentId: command.topDocumentId,
              topFrameUrl: command.topFrameUrl,
              binding,
              sessionLease: claimedSessionLease,
              accountLease,
              policyLease: authorization.policyLease,
            });
            return { ok: true, data: { keyboardGrantId } };
          }
          case 'autofill.keyboard.findCandidates': {
            const caller = requireContent(context);
            if (!caller.documentId) throw deniedAutofillIntent();
            const grantContext = keyboardGrantContext(caller, contentRuntimeIncarnation!);
            const grant = deps.keyboardGrants.authorizeGrant(request.keyboardGrantId, grantContext);
            if (!grant) throw deniedAutofillIntent();
            await assertKeyboardGrantTopDocumentCurrent(
              deps,
              request.keyboardGrantId,
              grantContext,
              grant,
            );
            assertKeyboardGrantLeases(deps, grant);
            const authorization = await authorizeAutofill(
              deps,
              grant.frameUrl,
              'candidate',
              undefined,
              grant.policyLease,
            );
            assertKeyboardGrantLeases(deps, grant);
            const candidates = grant.purpose === 'login' || grant.purpose === 'totp'
              ? await (() => {
                  if (!deps.vault.findAutofillCandidates) {
                    throw new Error('vault.findAutofillCandidates is not wired');
                  }
                  return deps.vault.findAutofillCandidates(
                    grant.frameUrl,
                    authorization.defaultStrategy,
                    grant.purpose,
                  );
                })()
              : await (() => {
                  if (!deps.vault.findFillItems) throw new Error('vault.findFillItems is not wired');
                  return deps.vault.findFillItems(grant.purpose);
                })();
            if (!deps.keyboardGrants.authorizeGrant(request.keyboardGrantId, grantContext)) {
              throw deniedAutofillIntent();
            }
            await assertKeyboardGrantTopDocumentCurrent(
              deps,
              request.keyboardGrantId,
              grantContext,
              grant,
            );
            assertKeyboardGrantLeases(deps, grant);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            return { ok: true, data: candidates };
          }
          case 'autofill.findCandidates': {
            const caller = requireContent(context);
            if (!caller.documentId || !sessionLease) throw deniedAutofillIntent();
            if (!deps.vault.findAutofillCandidates) throw new Error('vault.findAutofillCandidates is not wired');
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'candidate', 'inlineSuggestions');
            const candidates = await deps.vault.findAutofillCandidates(caller.url, authorization.defaultStrategy, request.purpose);
            deps.accountGate.assert(accountLease);
            deps.sessionGate.assert(sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            return { ok: true, data: candidates };
          }
          case 'autofill.findStructuredCandidates': {
            const caller = requireContent(context);
            if (!caller.documentId || !sessionLease) throw deniedAutofillIntent();
            if (request.kind !== 'card' && request.kind !== 'identity') throw deniedAutofillIntent();
            if (!deps.vault.findFillItems) throw new Error('vault.findFillItems is not wired');
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'candidate', 'inlineSuggestions');
            const candidates = await deps.vault.findFillItems(request.kind);
            deps.accountGate.assert(accountLease);
            deps.sessionGate.assert(sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            return { ok: true, data: candidates };
          }
          case 'autofill.keyboard.issueIntent': {
            const caller = requireContent(context);
            if (!caller.documentId) throw deniedAutofillIntent();
            const grant = deps.keyboardGrants.consumeGrant(
              request.keyboardGrantId,
              keyboardGrantContext(caller, contentRuntimeIncarnation!),
            );
            if (!grant) throw deniedAutofillIntent();
            await assertKeyboardTopDocumentCurrent(deps, grant);
            assertKeyboardGrantLeases(deps, grant);
            const authorization = await authorizeAutofill(
              deps,
              grant.frameUrl,
              'intent',
              undefined,
              grant.policyLease,
            );
            let candidate: { id: string; reprompt?: boolean } | undefined;
            if (grant.purpose === 'login' || grant.purpose === 'totp') {
              if (!deps.vault.findAutofillCandidates) {
                throw new Error('vault.findAutofillCandidates is not wired');
              }
              const candidates = await deps.vault.findAutofillCandidates(
                grant.frameUrl,
                authorization.defaultStrategy,
                grant.purpose,
              );
              candidate = candidates.find((entry) => entry.id === request.cipherId);
            } else {
              if (!deps.vault.findFillItems) throw new Error('vault.findFillItems is not wired');
              const candidates = await deps.vault.findFillItems(grant.purpose);
              candidate = candidates.find((entry) => entry.id === request.cipherId);
            }
            await assertKeyboardTopDocumentCurrent(deps, grant);
            assertKeyboardGrantLeases(deps, grant);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            if (!candidate) throw deniedAutofillIntent();
            if (candidate.reprompt) {
              if (!deps.autofillContinuation) {
                throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
              }
              const repromptContinuationId = await deps.autofillContinuation.stageKeyboardReprompt(
                grant,
                candidate.id,
              );
              return { ok: true, data: { repromptContinuationId } };
            }
            const binding = grant.binding;
            const intentId = deps.autofillIntents.issue({
              tabId: grant.tabId,
              frameId: grant.frameId,
              documentId: grant.documentId,
              runtimeIncarnation: grant.runtimeIncarnation,
              frameUrl: grant.frameUrl,
              cipherId: candidate.id,
              purpose: grant.purpose,
              channel: 'keyboard',
              sessionLease: grant.sessionLease,
              accountLease: grant.accountLease,
              policyLease: grant.policyLease,
              ...(binding.purpose === 'login'
                ? { customPlan: binding.customPlan, customPlanDigest: binding.customPlanDigest }
                : binding.purpose === 'card' || binding.purpose === 'identity'
                  ? { structuredTarget: binding.structuredTarget }
                  : {}),
            });
            return { ok: true, data: { intentId } };
          }
          case 'autofill.continuation.redeemKeyboardReprompt': {
            const caller = requireContent(context);
            if (!caller.documentId || !deps.autofillContinuation) throw deniedAutofillIntent();
            const proof = await deps.autofillContinuation.redeemKeyboardReprompt(
              request.continuationId,
              {
                tabId: caller.tabId,
                frameId: caller.frameId,
                documentId: caller.documentId,
                runtimeIncarnation: contentRuntimeIncarnation!,
                url: caller.url,
              },
            );
            if (!proof) throw deniedAutofillIntent();
            deps.accountGate.assert(proof.accountLease);
            deps.sessionGate.assert(proof.sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, proof.policyLease);
            const authorization = await authorizeAutofill(
              deps,
              caller.url,
              'intent',
              undefined,
              proof.policyLease,
            );
            const candidates = proof.binding.purpose === 'login' || proof.binding.purpose === 'totp'
              ? await deps.vault.findAutofillCandidates!(
                  caller.url,
                  authorization.defaultStrategy,
                  proof.binding.purpose,
                )
              : await deps.vault.findFillItems!(proof.binding.purpose);
            const candidate = candidates.find((entry) => entry.id === proof.cipherId);
            deps.accountGate.assert(proof.accountLease);
            deps.sessionGate.assert(proof.sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, proof.policyLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            if (!candidate?.reprompt) throw deniedAutofillIntent();
            const intentId = deps.autofillIntents.issue({
              tabId: proof.source.tabId,
              frameId: proof.source.frameId,
              documentId: proof.source.frameDocumentId,
              runtimeIncarnation: proof.runtimeIncarnation,
              frameUrl: caller.url,
              cipherId: proof.cipherId,
              purpose: proof.binding.purpose,
              channel: 'keyboard',
              sessionLease: proof.sessionLease,
              accountLease: proof.accountLease,
              policyLease: proof.policyLease,
              repromptAuthorization: proof.repromptAuthorization,
              ...(proof.binding.purpose === 'login'
                ? {
                    customPlan: proof.binding.customPlan,
                    customPlanDigest: proof.binding.customPlanDigest,
                  }
                : proof.binding.purpose === 'card' || proof.binding.purpose === 'identity'
                  ? { structuredTarget: proof.binding.structuredTarget }
                  : {}),
            });
            return { ok: true, data: { intentId } };
          }
          case 'autofill.issueIntent': {
            const caller = requireContent(context);
            if (!caller.documentId || !sessionLease) throw deniedAutofillIntent();
            let customBinding: {
              customPlan: NonNullable<ReturnType<typeof parseLoginCustomTargetPlan>>;
              customPlanDigest: string;
            } | undefined;
            if (request.purpose === 'login') {
              const customPlan = parseLoginCustomTargetPlan(request.customPlan);
              if (!customPlan) throw deniedAutofillIntent();
              const expectedDigest = await digestLoginCustomTargetPlan(customPlan);
              customBinding = { customPlan, customPlanDigest: expectedDigest };
            } else if ('customPlan' in request || 'customPlanDigest' in request) {
              throw deniedAutofillIntent();
            }
            if (!deps.vault.findAutofillCandidates) throw new Error('vault.findAutofillCandidates is not wired');
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'intent', 'inlineSuggestions');
            const candidates = await deps.vault.findAutofillCandidates(caller.url, authorization.defaultStrategy, request.purpose);
            const candidate = candidates.find((entry) => entry.id === request.cipherId);
            deps.accountGate.assert(accountLease);
            deps.sessionGate.assert(sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            if (!candidate) throw deniedAutofillIntent();
            if (candidate.reprompt) {
              throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
            }
            const intentId = deps.autofillIntents.issue({
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              runtimeIncarnation: contentRuntimeIncarnation!,
              frameUrl: caller.url,
              cipherId: candidate.id,
              purpose: request.purpose,
              channel: 'interactive',
              sessionLease,
              accountLease,
              policyLease: authorization.policyLease,
              ...(customBinding ?? {}),
            });
            return { ok: true, data: { intentId } };
          }
          case 'autofill.issueStructuredIntent': {
            const caller = requireContent(context);
            if (!caller.documentId || !sessionLease) throw deniedAutofillIntent();
            const target = parseContentStructuredAutofillTarget(request.target);
            if (!target) throw deniedAutofillIntent();
            if (!deps.vault.findFillItems) throw new Error('vault.findFillItems is not wired');
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'intent', 'inlineSuggestions');
            const candidates = await deps.vault.findFillItems(target.kind);
            const candidate = candidates.find((entry) => entry.id === request.cipherId);
            deps.accountGate.assert(accountLease);
            deps.sessionGate.assert(sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            if (!candidate) throw deniedAutofillIntent();
            if (candidate.reprompt) {
              throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
            }
            const intentId = deps.autofillIntents.issue({
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              runtimeIncarnation: contentRuntimeIncarnation!,
              frameUrl: caller.url,
              cipherId: candidate.id,
              purpose: target.kind,
              channel: 'interactive',
              sessionLease,
              accountLease,
              policyLease: authorization.policyLease,
              structuredTarget: target,
            });
            return { ok: true, data: { intentId } };
          }
          case 'autofill.redeemLoginIntent':
          case 'autofill.keyboard.redeemLoginIntent': {
            const keyboard = request.type === 'autofill.keyboard.redeemLoginIntent';
            const intent = redeemAutofillIntent(
              deps,
              request.intentId,
              'login',
              keyboard ? 'keyboard' : 'interactive',
              context,
              contentRuntimeIncarnation!,
            );
            if (!intent) throw deniedAutofillIntent();
            responseSessionLease = intent.sessionLease;
            responseFinalAssert = () => assertAutofillIntentLeases(deps, intent);
            responseReleaseLease = deps.vaultReleaseGate?.capture(intent.sessionLease);
            if (!intent.customPlan || !intent.customPlanDigest) throw deniedAutofillIntent();
            if (!deps.vault.getInteractiveAutofillLoginData) throw new Error('vault.getInteractiveAutofillLoginData is not wired');
            try {
              assertAutofillIntentLeases(deps, intent);
              const authorization = await authorizeAutofill(
                deps,
                intent.canonicalFrameUrl,
                'intent',
                keyboard ? undefined : 'inlineSuggestions',
                intent.policyLease,
              );
              assertAutofillIntentLeases(deps, intent);
              const projection = narrowInteractiveLoginProjection(
                await deps.vault.getInteractiveAutofillLoginData(
                intent.cipherId,
                intent.canonicalFrameUrl,
                authorization.defaultStrategy,
                intent.customPlan,
                intent.repromptAuthorization?.assertCurrent,
                bindVaultFinalAuthority,
                ),
                intent.customPlan,
              );
              if (!projection) throw deniedAutofillIntent();
              assertAutofillIntentLeases(deps, intent);
              const loginReadAuthorities = Object.freeze([...vaultFinalAuthorities]);
              const totpCopyAckId = authorization.settings.autoCopyTotp
                ? await issueAutofillTotpCopyAck(deps, {
                    owner: {
                      tabId: intent.tabId,
                      frameId: intent.frameId,
                      documentId: intent.documentId,
                    },
                    cipherId: intent.cipherId,
                    frameUrl: intent.canonicalFrameUrl,
                    defaultStrategy: authorization.defaultStrategy,
                    assertCurrent: () => assertAutofillIntentLeases(deps, intent),
                    ...(intent.repromptAuthorization
                      ? { assertRepromptAuthorized: intent.repromptAuthorization.assertCurrent }
                      : {}),
                  })
                : undefined;
              const clientEventAckId = await issueClientEventAck(
                deps,
                contentClientEventOwner(intent.tabId, intent.frameId, intent.documentId),
                { type: ClientEventType.Cipher_ClientAutofilled, cipherId: intent.cipherId },
                () => assertAutofillIntentLeases(deps, intent),
                loginReadAuthorities,
              );
              assertAutofillIntentLeases(deps, intent);
              return {
                ok: true,
                data: {
                  ...projection,
                  ...(clientEventAckId ? { clientEventAckId } : {}),
                  ...(totpCopyAckId ? { totpCopyAckId } : {}),
                },
              };
            } catch (error) {
              return rethrowAutofillIntentReadError(deps, intent, error);
            }
          }
          case 'autofill.redeemTotpIntent':
          case 'autofill.keyboard.redeemTotpIntent': {
            const keyboard = request.type === 'autofill.keyboard.redeemTotpIntent';
            const intent = redeemAutofillIntent(
              deps,
              request.intentId,
              'totp',
              keyboard ? 'keyboard' : 'interactive',
              context,
              contentRuntimeIncarnation!,
            );
            if (!intent) throw deniedAutofillIntent();
            responseSessionLease = intent.sessionLease;
            responseFinalAssert = () => assertAutofillIntentLeases(deps, intent);
            responseReleaseLease = deps.vaultReleaseGate?.capture(intent.sessionLease);
            if (!deps.vault.getAutofillTotpData) throw new Error('vault.getAutofillTotpData is not wired');
            try {
              assertAutofillIntentLeases(deps, intent);
              const authorization = await authorizeAutofill(
                deps,
                intent.canonicalFrameUrl,
                'intent',
                keyboard ? undefined : 'inlineSuggestions',
                intent.policyLease,
              );
              assertAutofillIntentLeases(deps, intent);
              const totp = await (intent.repromptAuthorization
                ? deps.vault.getAutofillTotpData(
                    intent.cipherId,
                    intent.canonicalFrameUrl,
                    authorization.defaultStrategy,
                    bindVaultFinalAuthority,
                    intent.repromptAuthorization.assertCurrent,
                  )
                : deps.vault.getAutofillTotpData(
                    intent.cipherId,
                    intent.canonicalFrameUrl,
                    authorization.defaultStrategy,
                    bindVaultFinalAuthority,
                  ));
              assertAutofillIntentLeases(deps, intent);
              const clientEventAckId = await issueClientEventAck(
                deps,
                contentClientEventOwner(intent.tabId, intent.frameId, intent.documentId),
                { type: ClientEventType.Cipher_ClientAutofilled, cipherId: intent.cipherId },
                () => assertAutofillIntentLeases(deps, intent),
                vaultFinalAuthorities,
              );
              assertAutofillIntentLeases(deps, intent);
              return {
                ok: true,
                data: { totp, ...(clientEventAckId ? { clientEventAckId } : {}) },
              };
            } catch (error) {
              return rethrowAutofillIntentReadError(deps, intent, error);
            }
          }
          case 'autofill.redeemStructuredIntent':
          case 'autofill.keyboard.redeemStructuredIntent': {
            const keyboard = request.type === 'autofill.keyboard.redeemStructuredIntent';
            const unsafeTarget: unknown = request.target;
            const purpose = structuredPurposeForRedemption(unsafeTarget);
            const intent = redeemAutofillIntent(
              deps,
              request.intentId,
              purpose,
              keyboard ? 'keyboard' : 'interactive',
              context,
              contentRuntimeIncarnation!,
              request.target,
            );
            if (!intent?.structuredTarget) throw deniedAutofillIntent();
            responseSessionLease = intent.sessionLease;
            responseFinalAssert = () => assertAutofillIntentLeases(deps, intent);
            if (!deps.tabAutofill) throw new Error('tabAutofill is not wired');
            assertAutofillIntentLeases(deps, intent);
            const target: TabSuggestionTarget = {
              ...intent.structuredTarget,
              frameId: intent.frameId,
              documentId: intent.documentId,
            };
            const outcome = await (intent.repromptAuthorization
              ? deps.tabAutofill.fill(
                  intent.tabId,
                  intent.cipherId,
                  target,
                  () => assertAutofillIntentLeases(deps, intent),
                  intent.repromptAuthorization,
                )
              : deps.tabAutofill.fill(
                  intent.tabId,
                  intent.cipherId,
                  target,
                  () => assertAutofillIntentLeases(deps, intent),
                ));
            return { ok: true, data: { outcome } };
          }
          case 'autofill.getClientConfig': {
            const caller = requireContent(context);
            const config = await clientAutofillConfig(deps, caller.url);
            return { ok: true, data: caller.frameId === 0 ? config : { ...config, pageLoadFill: false } };
          }
          case 'autofill.authorizeGeneratorUse': {
            const caller = requireContent(context);
            if (!caller.documentId || !sessionLease || !deps.inlineGeneratorTracks
                || !Number.isSafeInteger(request.revision) || request.revision < 0
                || !isAllowedGeneratorTransport(caller.url)) {
              throw deniedAutofillIntent();
            }
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'candidate');
            const gates = autofillAuthorizationPolicyGates(deps);
            const generator = resolveAutofillAuthorizationGeneratorPolicy(
              gates,
              authorization.policyLease,
            );
            if (
              generator.malformed
              || generator.revision !== request.revision
              || (!generator.password.allowed && !generator.passphrase.allowed)
            ) throw deniedAutofillIntent();
            const assertCurrent = (): void => {
              deps.sessionGate.assert(sessionLease);
              deps.accountGate.assert(accountLease);
              assertAutofillAuthorizationPolicy(gates, authorization.policyLease);
            };
            assertCurrent();
            const trackToken = deps.inlineGeneratorTracks.issue({
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              url: caller.url,
            }, generator, request.options, assertCurrent);
            assertCurrent();
            return { ok: true, data: { trackToken } };
          }
          case 'autofill.trackGeneratedValue': {
            const caller = requireContent(context);
            if (!caller.documentId || !deps.inlineGeneratorTracks) {
              return { ok: true, data: { added: false } };
            }
            const result = await deps.inlineGeneratorTracks.consume(request.token, {
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              url: caller.url,
            }, request.value);
            return {
              ok: true,
              data: { added: result.kind === 'tracked' && result.added },
            };
          }
          case 'autofill.issuePageLoadIntent': {
            const caller = requireContentTopFrame(context);
            if (!caller.documentId || !sessionLease) throw deniedAutofillIntent();
            const pageLoadClaim = {
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              frameUrl: caller.url,
            };
            if (!deps.pageLoadFillDeduper.claim(pageLoadClaim)) throw deniedAutofillIntent();
            if (!(await deps.pageLoadFillDeduper.persist(pageLoadClaim))) throw deniedAutofillIntent();
            if (!deps.vault.findAutofillCandidates) throw new Error('vault.findAutofillCandidates is not wired');
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofill(deps, caller.url, 'page-load', 'pageLoadFill');
            const candidates = await deps.vault.findAutofillCandidates(
              caller.url,
              authorization.defaultStrategy,
              'login',
              'page-load',
              authorization.settings.pageLoadFillDefault,
            );
            deps.accountGate.assert(accountLease);
            deps.sessionGate.assert(sessionLease);
            assertAutofillAuthorizationPolicyLease(deps, authorization.policyLease);
            if (candidates.length !== 1 || candidates[0]!.reprompt) throw deniedAutofillIntent();
            const intentId = deps.autofillIntents.issue({
              tabId: caller.tabId,
              frameId: caller.frameId,
              documentId: caller.documentId,
              runtimeIncarnation: contentRuntimeIncarnation!,
              frameUrl: caller.url,
              cipherId: candidates[0]!.id,
              purpose: 'login',
              channel: 'page-load',
              sessionLease,
              accountLease,
              policyLease: authorization.policyLease,
            });
            return { ok: true, data: { intentId } };
          }
          case 'autofill.redeemPageLoadIntent': {
            const intent = redeemAutofillIntent(
              deps,
              request.intentId,
              'login',
              'page-load',
              context,
              contentRuntimeIncarnation!,
            );
            if (!intent) throw deniedAutofillIntent();
            responseSessionLease = intent.sessionLease;
            responseFinalAssert = () => assertAutofillIntentLeases(deps, intent);
            responseReleaseLease = deps.vaultReleaseGate?.capture(intent.sessionLease);
            if (!deps.vault.findAutofillCandidates) throw new Error('vault.findAutofillCandidates is not wired');
            if (!deps.vault.getAutofillLoginData) throw new Error('vault.getAutofillLoginData is not wired');
            try {
              assertAutofillIntentLeases(deps, intent);
              const authorization = await authorizeAutofill(deps, intent.canonicalFrameUrl, 'page-load', 'pageLoadFill', intent.policyLease);
              const candidates = await deps.vault.findAutofillCandidates(
                intent.canonicalFrameUrl,
                authorization.defaultStrategy,
                'login',
                'page-load',
                authorization.settings.pageLoadFillDefault,
              );
              assertAutofillIntentLeases(deps, intent);
              if (candidates.length !== 1 || candidates[0]!.id !== intent.cipherId || candidates[0]!.reprompt) {
                throw deniedAutofillIntent();
              }
              const login = await deps.vault.getAutofillLoginData(
                intent.cipherId,
                intent.canonicalFrameUrl,
                authorization.defaultStrategy,
                {
                  requireUnique: true,
                  channel: 'page-load',
                  pageLoadFillDefault: authorization.settings.pageLoadFillDefault,
                },
                bindVaultFinalAuthority,
              );
              assertAutofillIntentLeases(deps, intent);
              const loginReadAuthorities = Object.freeze([...vaultFinalAuthorities]);
              const totpCopyAckId = authorization.settings.autoCopyTotp
                ? await issueAutofillTotpCopyAck(deps, {
                    owner: {
                      tabId: intent.tabId,
                      frameId: intent.frameId,
                      documentId: intent.documentId,
                    },
                    cipherId: intent.cipherId,
                    frameUrl: intent.canonicalFrameUrl,
                    defaultStrategy: authorization.defaultStrategy,
                    assertCurrent: () => assertAutofillIntentLeases(deps, intent),
                  })
                : undefined;
              const clientEventAckId = await issueClientEventAck(
                deps,
                contentClientEventOwner(intent.tabId, intent.frameId, intent.documentId),
                { type: ClientEventType.Cipher_ClientAutofilled, cipherId: intent.cipherId },
                () => assertAutofillIntentLeases(deps, intent),
                loginReadAuthorities,
              );
              assertAutofillIntentLeases(deps, intent);
              return {
                ok: true,
                data: {
                  login,
                  ...(clientEventAckId ? { clientEventAckId } : {}),
                  ...(totpCopyAckId ? { totpCopyAckId } : {}),
                },
              };
            } catch (error) {
              return rethrowAutofillIntentReadError(deps, intent, error);
            }
          }
          case 'autofill.captureSubmission': {
            const caller = requireContent(context);
            if (!caller.documentId || !sessionLease) throw deniedAutofillIntent();
            if (!deps.saveCaptureCoordinator || !deps.getSessionBindingId
                || !contentRuntimeIncarnation) {
              throw new Error('Pending save capture is not wired');
            }
            const submitted = parseCapturedSubmission(request);
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofillActions(deps, caller.url, ['save', 'update']);
            const leases = { sessionLease, accountLease, policyLease: authorization.policyLease };
            const stageContext = await usernameStageContext(
              deps,
              caller,
              sessionLease,
              accountLease,
              authorization.policyLease,
              contentRuntimeIncarnation,
            );
            if (!('password' in submitted)) {
              await deps.saveCaptureCoordinator.stageUsername({
                ...stageContext,
                username: submitted.username,
              });
              assertPendingSaveLeases(deps, leases);
              return { ok: true, data: null };
            }
            // A password step always drains the one-shot username stage. Its value is used only when
            // this submission has no username of its own, preventing stale stages from contaminating
            // a later password-only flow.
            const stagedUsername = await deps.saveCaptureCoordinator.consumeUsername(stageContext);
            assertPendingSaveLeases(deps, leases);
            const effectiveCredentials: AutofillPendingSaveCredentials = Object.freeze({
              ...(submitted.username ?? stagedUsername
                ? { username: submitted.username ?? stagedUsername! }
                : {}),
              password: submitted.password,
            });
            const documentContext = await pendingSaveDocumentContext(
              deps,
              caller,
              leases,
              contentRuntimeIncarnation,
            );
            const ownedUserKey = await loadPendingSaveUserKey(deps, leases);
            await deps.saveCaptureCoordinator.stage({
              tabId: documentContext.tabId,
              frameId: documentContext.frameId,
              sourceDocumentId: documentContext.documentId,
              runtimeIncarnation: documentContext.runtimeIncarnation,
              sourceUrl: documentContext.frameUrl,
              origin: documentContext.origin,
              sessionGeneration: documentContext.sessionGeneration,
              sessionBindingId: documentContext.sessionBindingId,
              serverGeneration: documentContext.serverGeneration,
              accountGeneration: documentContext.accountGeneration,
              serverUrl: documentContext.serverUrl,
              accountIdentity: documentContext.accountIdentity,
              policyGeneration: documentContext.policyGeneration,
              enterprisePolicyGeneration: documentContext.enterprisePolicyGeneration,
              enterprisePolicyRawGeneration: documentContext.enterprisePolicyRawGeneration,
            }, effectiveCredentials, ownedUserKey, submitted.submission);
            assertPendingSaveLeases(deps, leases);
            return { ok: true, data: null };
          }
          case 'autofill.claimSavePrompt': {
            const caller = requireContent(context);
            const captureId = strictClaimCaptureId(request);
            if (!caller.documentId || !sessionLease || !deps.saveCaptureCoordinator) throw deniedAutofillIntent();
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofillActions(deps, caller.url, ['save', 'update']);
            const leases = { sessionLease, accountLease, policyLease: authorization.policyLease };
            const documentContext = await pendingSaveDocumentContext(
              deps,
              caller,
              leases,
              contentRuntimeIncarnation!,
            );
            const ownedUserKey = await loadPendingSaveUserKey(deps, leases);
            const prompt = await deps.saveCaptureCoordinator.claimPendingSave(
              documentContext,
              ownedUserKey,
              (credentials, sourceUrl) => evaluatePendingSave(
                deps,
                credentials,
                sourceUrl,
                authorization,
                leases,
              ),
              captureId,
            );
            assertPendingSaveLeases(deps, leases);
            return prompt.action === 'retry'
              ? { ok: true, data: { action: 'none', retryAfterMs: prompt.retryAfterMs } }
              : { ok: true, data: prompt };
          }
          case 'autofill.commitSavePrompt': {
            const caller = requireContent(context);
            const promptId = strictSavePromptId(request, 'autofill.commitSavePrompt');
            if (!caller.documentId || !sessionLease || !deps.saveCaptureCoordinator) throw deniedAutofillIntent();
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofillActions(deps, caller.url, ['save', 'update']);
            const leases = { sessionLease, accountLease, policyLease: authorization.policyLease };
            const documentContext = await pendingSaveDocumentContext(
              deps,
              caller,
              leases,
              contentRuntimeIncarnation!,
            );
            const ownedUserKey = await loadPendingSaveUserKey(deps, leases);
            const taken = await deps.saveCaptureCoordinator.takePendingSave(
              promptId,
              documentContext,
              ownedUserKey,
            );
            if (!taken) throw deniedAutofillIntent();
            assertPendingSaveLeases(deps, leases);
            await authorizeAutofill(
              deps,
              taken.sourceUrl,
              taken.decision.action === 'save' ? 'save' : 'update',
              undefined,
              authorization.policyLease,
            );
            assertPendingSaveLeases(deps, leases);
            const assertCurrent = (): void => assertPendingSaveLeases(deps, leases);
            if (!deps.vault.commitCapturedLogin) {
              throw new Error('vault.commitCapturedLogin is not wired');
            }
            return { ok: true, data: await deps.vault.commitCapturedLogin(
              taken.sourceUrl,
              taken.credentials,
              authorization.defaultStrategy,
              taken.decision,
              assertCurrent,
            ) };
          }
          case 'autofill.dismissSavePrompt': {
            const caller = requireContent(context);
            const promptId = strictSavePromptId(request, 'autofill.dismissSavePrompt');
            if (!caller.documentId || !sessionLease || !deps.saveCaptureCoordinator) throw deniedAutofillIntent();
            const accountLease = deps.accountGate.capture();
            const authorization = await authorizeAutofillActions(deps, caller.url, ['save', 'update']);
            const leases = { sessionLease, accountLease, policyLease: authorization.policyLease };
            const documentContext = await pendingSaveDocumentContext(
              deps,
              caller,
              leases,
              contentRuntimeIncarnation!,
            );
            if (!(await deps.saveCaptureCoordinator.dismissPendingSave(promptId, documentContext))) {
              throw deniedAutofillIntent();
            }
            assertPendingSaveLeases(deps, leases);
            return { ok: true, data: null };
          }
          case 'autofill.getTabSuggestions': {
            requireExtensionPage(context);
            if (!deps.tabAutofill) throw new Error('tabAutofill is not wired');
            return { ok: true, data: { outcome: await deps.tabAutofill.getSuggestions(request.tabId) } };
          }
          case 'autofill.manual.prepare': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.manualAutofill) {
              throw new AppError('denied', 'Manual autofill is unavailable.');
            }
            return { ok: true, data: await deps.manualAutofill.prepare(caller.documentId, request) };
          }
          case 'autofill.manual.cancel': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.manualAutofill) {
              throw new AppError('denied', 'Manual autofill is unavailable.');
            }
            if (!deps.manualAutofill.cancel(caller.documentId, request)) {
              throw new AppError('denied', 'Manual autofill authorization is invalid or expired.');
            }
            return { ok: true, data: null };
          }
          case 'autofill.manual.commit': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.manualAutofill) {
              throw new AppError('denied', 'Manual autofill is unavailable.');
            }
            let outcome: Promise<Awaited<ReturnType<typeof deps.manualAutofill.commit>>>;
            try {
              outcome = deps.manualAutofill.commit(caller.documentId, request);
            } finally {
              request.masterPassword = '';
            }
            return { ok: true, data: { outcome: await outcome } };
          }
          case 'autofill.continuation.status': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.autofillContinuation) throw deniedRepromptAutofill();
            return { ok: true, data: await deps.autofillContinuation.status(caller.documentId) };
          }
          case 'autofill.continuation.cancel': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.autofillContinuation
                || !await deps.autofillContinuation.cancel(caller.documentId, request.continuationId)) {
              throw deniedRepromptAutofill();
            }
            return { ok: true, data: null };
          }
          case 'autofill.continuation.resumeUnlock': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.autofillContinuation) throw deniedRepromptAutofill();
            return {
              ok: true,
              data: await deps.autofillContinuation.resumeUnlock(caller.documentId, request.continuationId),
            };
          }
          case 'autofill.continuation.authorizeReprompt': {
            const caller = requirePopupPage(context);
            if (!caller.documentId || !deps.autofillContinuation
                || typeof request.masterPassword !== 'string'
                || request.masterPassword.length < 1
                || request.masterPassword.length > 4_096) throw deniedRepromptAutofill();
            let pending: Promise<Awaited<ReturnType<typeof deps.autofillContinuation.authorizeReprompt>>>;
            try {
              pending = deps.autofillContinuation.authorizeReprompt(
                caller.documentId,
                request.continuationId,
                request.masterPassword,
              );
            } finally {
              request.masterPassword = '';
            }
            return { ok: true, data: await pending };
          }
          case 'autofill.authorizeRepromptFill': {
            const caller = requirePopupPage(context);
            if (
              !caller.documentId
              || !sessionLease
              || !deps.auth.verifyMasterPassword
              || !deps.vault.findAutofillCandidates
              || !deps.vault.findFillItems
              || !deps.tabAutofill?.resolveRepromptBinding
              || !deps.repromptAutofillGrants
              || typeof request.masterPassword !== 'string'
              || request.masterPassword.length < 1
              || request.masterPassword.length > 4_096
              || typeof request.cipherId !== 'string'
              || request.cipherId.length < 1
              || request.cipherId.length > 4_096
              || !Number.isSafeInteger(request.tabId)
              || request.tabId < 0
            ) {
              throw deniedRepromptAutofill();
            }
            const accountLease = deps.accountGate.capture();
            const policyLease = captureAutofillAuthorizationPolicy(
              autofillAuthorizationPolicyGates(deps),
            );
            let verification: Promise<boolean>;
            try {
              verification = deps.auth.verifyMasterPassword(request.masterPassword);
            } finally {
              request.masterPassword = '';
            }
            const verified = await verification;
            const grantLeases = { sessionLease, accountLease, policyLease };
            assertRepromptGrantLeases(deps, grantLeases);
            if (!verified) return { ok: true, data: { verified: false } };

            const firstBinding = await deps.tabAutofill.resolveRepromptBinding(request.tabId, request.target);
            assertRepromptGrantLeases(deps, grantLeases);
            if (!firstBinding) return { ok: true, data: { verified: true } };

            let authorization: AutofillAuthorization;
            try {
              authorization = await authorizeAutofill(
                deps,
                firstBinding.frameUrl,
                'intent',
                undefined,
                policyLease,
              );
            } catch (error) {
              assertRepromptGrantLeases(deps, grantLeases);
              if (error instanceof AppError && error.code === 'denied') {
                return { ok: true, data: { verified: true } };
              }
              throw error;
            }
            const candidates = request.target.kind === 'login'
              ? await deps.vault.findAutofillCandidates(
                  firstBinding.frameUrl,
                  authorization.defaultStrategy,
                  'login',
                )
              : await deps.vault.findFillItems(request.target.kind);
            assertRepromptGrantLeases(deps, grantLeases);
            const candidate = candidates.find((entry) => entry.id === request.cipherId);
            if (!candidate?.reprompt) return { ok: true, data: { verified: true } };

            const finalBinding = await deps.tabAutofill.resolveRepromptBinding(request.tabId, request.target);
            assertRepromptGrantLeases(deps, grantLeases);
            if (!finalBinding || !sameRepromptBinding(firstBinding, finalBinding)) {
              return { ok: true, data: { verified: true } };
            }
            try {
              const grant = deps.repromptAutofillGrants.issue({
                ...repromptGrantBinding(caller.documentId, request.cipherId, finalBinding),
                ...grantLeases,
              });
              return { ok: true, data: { verified: true, authorization: grant } };
            } catch {
              assertRepromptGrantLeases(deps, grantLeases);
              return { ok: true, data: { verified: true } };
            }
          }
          case 'autofill.fillTabSuggestion': {
            const caller = requirePopupPage(context);
            if (!deps.tabAutofill) throw new Error('tabAutofill is not wired');
            if (request.repromptAuthorizationId === undefined) {
              return { ok: true, data: { outcome: await deps.tabAutofill.fill(request.tabId, request.cipherId, request.target) } };
            }
            const resolved = deps.tabAutofill.resolveRepromptBinding
              ? await deps.tabAutofill.resolveRepromptBinding(request.tabId, request.target)
              : undefined;
            const binding: RepromptAutofillGrantBinding = resolved && caller.documentId
              ? repromptGrantBinding(caller.documentId, request.cipherId, resolved)
              : {
                  popupDocumentId: caller.documentId ?? '',
                  cipherId: request.cipherId,
                  tabId: request.tabId,
                  frameId: request.target.frameId,
                  targetDocumentId: request.target.documentId,
                  topUrl: 'https://invalid.invalid/',
                  frameUrl: 'https://invalid.invalid/',
                  targetKey: 'invalid',
                };
            const grant = deps.repromptAutofillGrants?.redeem(
              request.repromptAuthorizationId,
              binding,
            );
            if (!grant) throw deniedRepromptAutofill();
            assertRepromptGrantCurrent(deps, grant);
            return {
              ok: true,
              data: {
                outcome: await deps.tabAutofill.fill(
                  request.tabId,
                  request.cipherId,
                  request.target,
                  undefined,
                  { assertCurrent: () => assertRepromptGrantCurrent(deps, grant) },
                ),
              },
            };
          }
          default: {
            // Exhaustiveness guard + runtime safety: an unknown/removed type (e.g. version skew with an
            // old tab's content script) gets a structured error instead of resolving `undefined`, which
            // would make callers reading response.ok/.data throw a TypeError.
            const unknown: never = request;
            return { ok: false, error: { code: 'error', message: `unknown message type: ${(unknown as { type?: string }).type ?? ''}` } };
          }
          }
        })();
        if (activityLease && activitySucceeded(request, response)) {
          await deps.vaultTimeout?.recordActivity(activityLease);
        }
        const assertResponseCurrent = (): void => {
          (responseFinalAssert ?? (() => deps.sessionGate.assert(responseSessionLease!)))();
          for (const assertVaultCurrent of vaultFinalAuthorities) assertVaultCurrent();
        };
        // Finish asynchronous cleanup before the final release checkpoint. Runtime authority is
        // synchronously revocable, so neither the checkpoint nor cleanup can make an earlier
        // document observation authorize a response after runtime replacement or session lock.
        await deps.vaultTimeout?.settlePendingAction?.();
        if (response.ok && responseReleaseLease && deps.vaultReleaseGate) {
          const releaseProof = await deps.vaultReleaseGate.checkpoint(responseReleaseLease);
          deps.vaultReleaseGate.assertAuthorities(
            releaseProof,
            () => {
              assertResponseCurrent();
              contentRuntimeAuthority?.assertCurrent();
            },
          );
          deps.vaultReleaseGate.assert(releaseProof);
        } else {
          if (responseSessionLease) assertResponseCurrent();
          contentRuntimeAuthority?.assertCurrent();
        }
        return response;
      } catch (err) {
        let caught = err;
        try {
          await deps.vaultTimeout?.settlePendingAction?.();
        } catch (actionError) {
          caught = actionError;
        }
        if (committedSecretMutation) {
          return {
            ok: false,
            error: {
              code: 'committed_unsynced',
              message: 'The Send was saved, but its secret result was withheld. Unlock and sync before continuing.',
            },
          };
        }
        if (caught instanceof AppError) {
          return { ok: false, error: { code: caught.code, message: caught.message } };
        }
        return { ok: false, error: { code: 'error', message: caught instanceof Error ? caught.message : String(caught) } };
      }
    },
  };
}

function narrowInteractiveLoginProjection(
  value: AutofillInteractiveLoginData,
  plan: LoginCustomTargetPlan,
): AutofillInteractiveLoginData | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const unsafeLogin: unknown = value.login;
  if (typeof unsafeLogin !== 'object' || unsafeLogin === null || Array.isArray(unsafeLogin)) return undefined;
  const record = unsafeLogin as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== 'username' && key !== 'password')) return undefined;
  if ((record.username !== undefined && typeof record.username !== 'string')
      || (record.password !== undefined && typeof record.password !== 'string')) return undefined;
  const login = {
    ...(typeof record.username === 'string' ? { username: record.username } : {}),
    ...(typeof record.password === 'string' ? { password: record.password } : {}),
  };
  const customAssignments = parseLoginCustomAssignments(value.customAssignments);
  if (!customAssignments) return undefined;
  const targets = new Map(plan.targets.map((target) => [target.fieldId, target.controlType]));
  if (customAssignments.some((assignment) => {
    const controlType = targets.get(assignment.fieldId);
    return !controlType || ('checked' in assignment ? controlType !== 'checkbox' : controlType === 'checkbox');
  })) return undefined;
  return { login, customAssignments };
}

function parseContentStructuredAutofillTarget(value: unknown): ContentStructuredAutofillTarget | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => ![
    'kind', 'runtimeIncarnation', 'formId', 'generation', 'roles',
  ].includes(key))) return undefined;
  const kind = record.kind;
  if (kind !== 'card' && kind !== 'identity') return undefined;
  if (
    typeof record.formId !== 'string'
    || runtimeIncarnation(record.runtimeIncarnation) !== record.runtimeIncarnation
    || record.formId.length === 0
    || record.formId.length > 4_096
    || record.formId.trim() !== record.formId
    || !Number.isSafeInteger(record.generation)
    || (record.generation as number) < 0
  ) return undefined;
  if (!Array.isArray(record.roles)) return undefined;
  const unsafeRoles = record.roles;
  if (kind === 'card') {
    const roles = normalizeFillRoles('card', unsafeRoles);
    if (!roles || roles.length !== unsafeRoles.length
        || roles.some((role, index) => role !== unsafeRoles[index])) return undefined;
    return Object.freeze({
      kind,
      runtimeIncarnation: record.runtimeIncarnation as string,
      formId: record.formId,
      generation: record.generation as number,
      roles: Object.freeze([...roles]),
    });
  }
  const roles = normalizeFillRoles('identity', unsafeRoles);
  if (!roles || roles.length !== unsafeRoles.length
      || roles.some((role, index) => role !== unsafeRoles[index])) return undefined;
  return Object.freeze({
    kind,
    runtimeIncarnation: record.runtimeIncarnation as string,
    formId: record.formId,
    generation: record.generation as number,
    roles: Object.freeze([...roles]),
  });
}

/** Pick a deterministic purpose so even malformed redemptions consume any supplied capability. */
function structuredPurposeForRedemption(value: unknown): 'card' | 'identity' {
  return typeof value === 'object'
    && value !== null
    && !Array.isArray(value)
    && (value as Record<string, unknown>).kind === 'identity'
    ? 'identity'
    : 'card';
}
