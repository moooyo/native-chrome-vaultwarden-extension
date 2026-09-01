import browser from 'webextension-polyfill';
import type { Runtime } from 'webextension-polyfill';
import { ApiClient } from '../core/api/client.js';
import { AuthService, type SessionTransitionEvent } from '../core/session/auth-service.js';
import {
  SessionManager,
  type SessionLease,
  type SessionState,
  type TokenStorageMoveReceipt,
} from '../core/session/session-manager.js';
import {
  VaultService,
  type ManualAutofillVaultAuthority,
  type VaultListing,
} from '../core/vault/vault-service.js';
import { VaultMutationCoordinator } from '../core/vault/vault-mutation-coordinator.js';
import { createVaultDirtyStore } from '../core/vault/vault-dirty-store.js';
import {
  VaultTransferSessionManager,
} from '../core/vault/vault-transfer-session.js';
import { createVaultTransferJournalStore } from '../core/vault/vault-transfer-journal.js';
import { createBrowserStore, hardenStorageAccessLevels } from '../platform/store.js';
import { createRouter } from './router.js';
import { createRequestContext, isMessageAllowed } from './sender-guard.js';
import {
  createSettingsService,
  sanitizeWebsitePasskeySettings,
  SHOW_MATCHING_LOGIN_COUNT_KEY,
} from './settings.js';
import {
  createHttpAuthSettingsService,
} from './http-auth-settings.js';
import { createIdleLock, ensureIdleLockAlarm, IDLE_LOCK_ALARM } from './idle-lock.js';
import { createClipboard, CLIPBOARD_CLEAR_ALARM } from './clipboard.js';
import { createContextMenu, shouldRefreshMenu } from './context-menu.js';
import {
  CommandCoordinator,
  type SecretExtensionCommand,
} from './commands.js';
import { createTabAutofillCoordinator, parseBrowserFrame } from './tab-autofill.js';
import { createHostAccessCheck } from './host-access.js';
import type { RequestMessage, ResponseMessage } from '../messaging/protocol.js';
import { initLocale, t } from '../ui/i18n/index.js';
import { SessionGate } from './session-gate.js';
import {
  AccountLeaseGate,
  type AccountLease,
  type ServerLease,
} from '../core/session/account-gate.js';
import {
  AccountTransitionCoordinator,
  settleVaultAccountAdmission,
} from './account-transition.js';
import {
  createRotationPendingStore,
  initializeAfterPendingRotationRecovery,
  type RotationPendingIdentity,
} from '../core/session/rotation-pending-store.js';
import {
  PasswordChangePendingStore,
  recoverPendingPasswordChangeOnStartup,
} from '../core/session/forced-password-change-pending-store.js';
import {
  createVaultSyncScheduler,
  VAULT_SYNC_ALARM,
} from './vault-sync-scheduler.js';
import { AutofillIntentRegistry } from './autofill-intent-registry.js';
import { AutofillPolicyGate } from './autofill-policy-gate.js';
import {
  assertAutofillAuthorizationPolicy,
  captureAutofillAuthorizationPolicy,
  isAutofillAuthorizationPolicyCurrent,
  resolveAutofillAuthorizationUriMatchDefault,
  type AutofillAuthorizationPolicyLease,
} from './autofill-authorization-policy.js';
import {
  VaultExportGrantRegistry,
  type RedeemedVaultExportGrant,
} from './vault-export-grant-registry.js';
import { RepromptAutofillGrantRegistry } from './reprompt-autofill-grant-registry.js';
import { ManualAutofillGrantRegistry } from './manual-autofill-grant-registry.js';
import { createManualAutofillCoordinator } from './manual-autofill-coordinator.js';
import { AutofillContinuationStore } from './autofill-continuation-store.js';
import {
  AutofillContinuationCoordinator,
  digestAutofillContinuationPolicy,
  type AutofillContinuationBrowserSource,
} from './autofill-continuation-coordinator.js';
import {
  AUTOFILL_PENDING_SAVE_ALARM,
  AutofillPendingSaveStore,
  type AutofillUnconfirmedSaveMetadata,
} from './autofill-pending-save-store.js';
import {
  AUTOFILL_SAVE_CAPTURE_ALARM,
  AutofillSaveCaptureCoordinator,
} from './autofill-save-capture-coordinator.js';
import {
  registerAutofillSaveCaptureBrowserListeners,
  type AutofillSaveCaptureChromeApi,
} from './autofill-save-capture-browser.js';
import { AutofillKeyboardGrantRegistry } from './autofill-keyboard-grant-registry.js';
import { AutofillUsernameStageStore } from './autofill-username-stage-store.js';
import { PageLoadFillDeduper } from './page-load-fill-deduper.js';
import { decideAutofillPolicy, normalizeAutofillBlocklist, type AutofillPolicyAction } from '../core/vault/autofill-policy.js';
import { AppError } from '../core/errors.js';
import { SsoRequiredCache } from '../core/session/sso-required-cache.js';
import { normalizeSsoEmail } from '../core/session/sso-login.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import {
  EnterprisePolicyGate,
  type PolicyLease,
} from '../core/policy/effective-enterprise-policy.js';
import {
  applyEnterprisePolicySideEffects,
  invalidatesEnterprisePolicy,
} from './enterprise-policy-lifecycle.js';
import {
  isLocalCloseLogoutEnabled,
  resolveEffectiveVaultTimeout,
} from './vault-timeout-policy.js';
import {
  initializeVaultTimeoutAndReadFreshState,
  VaultTimeoutController,
  VAULT_TIMEOUT_ALARM,
} from './vault-timeout-controller.js';
import { refreshVaultTimeoutSettingsAfterWrite } from './vault-timeout-settings-lifecycle.js';
import { VaultReleaseGate } from './vault-release-gate.js';
import { recoverVaultTimeoutBrowserSession, VaultTimeoutStateStore } from './vault-timeout-state.js';
import { VaultTransferController } from './vault-transfer-controller.js';
import { VaultTransferPortHandler } from './vault-transfer-port-handler.js';
import {
  createVaultTransferLeaseBindings,
  createVaultTransferLifecycle,
  createVaultTransferReadiness,
  type VaultTransferAccountSessionLeases,
} from './vault-transfer-lifecycle.js';
import {
  ServerCapabilityManager,
  authorizeCipherArchive,
  authorizeCollectionNameOnlyUpdate,
  authorizeOrganizationDataOwnershipTransport,
  authorizeSshCipherType5Write,
  authorizeTwoFactorRecovery,
} from './server-capability-manager.js';
import {
  PRODUCTION_SERVER_CAPABILITY_DECLARATION,
  fetchFixedServerConfig,
} from './server-capability-production.js';
import {
  DeviceLoginApprovalBadgeController,
  createVaultNotificationProductionRuntime,
  deviceLoginApprovalTransitionAction,
  hasActiveNotificationAccount,
  isDeviceLoginAlarmName,
  resolveDeviceLoginNotificationsUrl,
  restoreDeviceLoginProductionRuntime,
} from './vault-notification-production.js';
import { VAULT_NOTIFICATIONS_RECONNECT_ALARM } from './vault-notifications.js';
import { DeviceLoginStateStore } from './device-login-state-store.js';
import {
  isPendingLoginContinuationExpirationAlarm,
  pendingLoginContinuationExpirationAttemptId,
  PendingLoginStateStore,
} from './pending-login-state-store.js';
import { createDeviceLoginNotifications } from './device-login-notifications.js';
import {
  DeviceLoginCoordinator,
} from './device-login-coordinator.js';
import { AccountPasskeyAttemptRegistry } from './account-passkey-attempt-registry.js';
import { SsoAttemptStore } from './sso-attempt-store.js';
import { SsoBrowserCoordinator } from './sso-browser.js';
import { DuoAttemptStore } from './duo-attempt-store.js';
import { DuoBrowserCoordinator } from './duo-browser.js';
import { authorizeSsoLaunch } from './sso-capability.js';
import { AccountPasskeyCoordinator } from './account-passkey-coordinator.js';
import {
  AccountPasskeyBrowserOrchestrator,
  type AccountPasskeyBrowserApi,
} from './account-passkey-browser.js';
import { createDeviceLoginApprovalService } from './device-login-approval-service.js';
import {
  createDeviceLoginApprovalNotificationController,
  DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
  type DeviceLoginApprovalNotificationBrowser,
} from './device-login-approval-notifications.js';
import { PasskeyCeremonyRegistry } from './passkey-ceremony-registry.js';
import { WebsitePasskeyLockedContinuationStore } from './website-passkey-locked-continuation-store.js';
import { WebsitePasskeyCoordinator } from './website-passkey-coordinator.js';
import { WebsitePasskeyPortHandler } from './website-passkey-port-handler.js';
import { WebsitePasskeyPolicyGate } from './website-passkey-policy.js';
import {
  WebsitePasskeyDocumentGate,
  type WebsitePasskeyBrowserFrameRecord,
} from './website-passkey-document-gate.js';
import { WebsitePasskeyPermissionsPolicyResolver } from './website-passkey-permissions-policy.js';
import {
  WebsitePasskeyFeaturePolicyProbeClient,
  WebsitePasskeyFeaturePolicyProbeRegistry,
  type WebsitePasskeyFeaturePolicyProbeClientDeps,
} from './website-passkey-feature-policy-probe.js';
import {
  WebsitePasskeyPermissionGate,
  type WebsitePasskeyPermissionGateDeps,
} from './website-passkey-permission-gate.js';
import {
  WebsitePasskeyScriptManager,
  type WebsitePasskeyScriptingAdapter,
} from './website-passkey-script-manager.js';
import { createWebsitePasskeyLifecycle } from './website-passkey-lifecycle.js';
import {
  createWebsitePasskeyAvailabilityAdapter,
  createWebsitePasskeySecurityAdapter,
  createWebsitePasskeyVaultAdapter,
} from './website-passkey-production.js';
import {
  createBackgroundPortDispatcher,
  createWebsitePasskeyTopFrameNotifier,
  type BackgroundPortHandler,
  type WebsitePasskeyBrowserLike,
} from './website-passkey-browser.js';
import { HttpAuthTombstoneStore } from './http-auth-tombstone-store.js';
import { HttpAuthBroker } from './http-auth-broker.js';
import {
  registerHttpAuthBrowserListeners,
  type HttpAuthChromeApi,
} from './http-auth-browser.js';
import {
  InteractiveTwoFactorBrowser,
  type InteractiveTwoFactorBrowserDeps,
  type InteractiveTwoFactorConnectorDocument,
} from './interactive-two-factor-browser.js';
import {
  CLIENT_EVENT_UPLOAD_ALARM,
  createClientEventProduction,
} from './client-event-production.js';
import { ClientEventFillRecorder } from './client-event-fill-recorder.js';
import { bestEffortClientEvent } from './client-event-best-effort.js';
import { ClientEventAuthLogoutLifecycle } from './client-event-auth-logout.js';
import { ClientEventAckRegistry } from './client-event-ack-registry.js';
import { ClientEventType } from '../core/events/client-event.js';
import { AutofillTotpCopyAckRegistry } from './autofill-totp-copy-ack-registry.js';
import {
  createGeneratorHistoryAuthorityProvider,
  GeneratorHistoryProductionService,
  type GeneratorHistorySecurityBinding,
} from './generator-history-production.js';
import { InlineGeneratorTrackTokenRegistry } from './inline-generator-track-token-registry.js';
import { createGeneratorPolicySnapshot } from '../core/generator/enterprise-password-policy.js';
import {
  createPasswordGenerationAction,
  GENERATOR_PREFS_STORAGE_KEY,
} from './password-generation-action.js';
import { createContextMenuCreateIntent } from '../messaging/context-menu-create.js';
import {
  ToolbarStateController,
  reduceToolbarAuthTransition,
  type ToolbarActionApi,
  type ToolbarStateCopy,
} from './toolbar-state.js';
import {
  ToolbarMatchCountController,
  type ToolbarMatchContribution,
} from './toolbar-match-count.js';

const localStore = createBrowserStore('local');
const sessionStore = createBrowserStore('session');
const settings = createSettingsService(localStore);
const toolbarState = new ToolbarStateController({
  action: browser.action as unknown as ToolbarActionApi,
  logger: { warn: (event) => console.warn(event) },
});
let toolbarAuthState: SessionState = 'loggedOut';
let toolbarPendingApprovalCount = 0;
let toolbarShowMatchingLoginCount = true;
let toolbarTransitionId = 0;
let toolbarSettingsRevision = 0;
const toolbarMatches = new Map<number, { readonly url: string; readonly count: number }>();
const vaultTimeoutState = new VaultTimeoutStateStore({ localStore, sessionStore });
const httpAuthSettings = createHttpAuthSettingsService(localStore);
const httpAuthTombstones = new HttpAuthTombstoneStore({ store: sessionStore });
// Authentication is committed conservatively until the effective timeout policy is known. A lock
// policy may promote the active account to local storage during the serialized timeout reconcile.
const session = new SessionManager({ localStore, sessionStore, defaultTokenStorage: 'session' });
const rotationPending = createRotationPendingStore(localStore);
const passwordChangePending = new PasswordChangePendingStore(localStore);
const sessionGate = new SessionGate();
const accountGate = new AccountLeaseGate();
const enterprisePolicyGate = new EnterprisePolicyGate();
const autofillPolicyGate = new AutofillPolicyGate();
const websitePasskeyPolicyGate = new WebsitePasskeyPolicyGate();
const websitePasskeyPermissionGate = new WebsitePasskeyPermissionGate({
  permissions: browser.permissions as unknown as WebsitePasskeyPermissionGateDeps['permissions'],
});
const websitePasskeyFeaturePolicyProbeRegistry = new WebsitePasskeyFeaturePolicyProbeRegistry();
const websitePasskeyFeaturePolicyProbe = new WebsitePasskeyFeaturePolicyProbeClient({
  tabs: browser.tabs as unknown as WebsitePasskeyFeaturePolicyProbeClientDeps['tabs'],
  registry: websitePasskeyFeaturePolicyProbeRegistry,
});
const websitePasskeyPermissionsPolicy = new WebsitePasskeyPermissionsPolicyResolver({
  getAllFrames: async (tabId) => (
    await browser.webNavigation.getAllFrames({ tabId })
  ) as unknown as readonly WebsitePasskeyBrowserFrameRecord[] | null,
  featurePolicyProbe: websitePasskeyFeaturePolicyProbe,
});
const websitePasskeyDocumentGate = new WebsitePasskeyDocumentGate({
  getAllFrames: async (tabId) => (
    await browser.webNavigation.getAllFrames({ tabId })
  ) as unknown as readonly WebsitePasskeyBrowserFrameRecord[] | null,
  permissionsPolicy: websitePasskeyPermissionsPolicy,
});
type WebsitePasskeyHeadersReceivedDetails = {
  readonly tabId?: unknown;
  readonly frameId?: unknown;
  readonly documentId?: unknown;
  readonly url?: unknown;
  readonly type?: unknown;
  readonly responseHeaders?: readonly unknown[];
};
const websitePasskeyWebRequest = browser.webRequest as unknown as {
  readonly onHeadersReceived: {
    addListener(
      listener: (details: WebsitePasskeyHeadersReceivedDetails) => void,
      filter: { readonly urls: readonly string[]; readonly types: readonly string[] },
      extraInfoSpec: readonly string[],
    ): void;
  };
};
websitePasskeyWebRequest.onHeadersReceived.addListener((details) => {
  if (!Number.isSafeInteger(details.tabId) || (details.tabId as number) < 0
      || !Number.isSafeInteger(details.frameId) || (details.frameId as number) < 0) return;
  const type = details.type === 'main_frame' || details.type === 'sub_frame'
    ? details.type
    : ((details.frameId as number) === 0 ? 'main_frame' : 'sub_frame');
  const responseHeaders = Array.isArray(details.responseHeaders)
    ? details.responseHeaders.map((value) => {
        const header = typeof value === 'object' && value !== null
          ? value as { readonly name?: unknown; readonly value?: unknown }
          : {};
        return Object.freeze({
          ...(typeof header.name === 'string' ? { name: header.name } : {}),
          ...(typeof header.value === 'string' ? { value: header.value } : {}),
        });
      })
    : [];
  websitePasskeyPermissionsPolicy.recordResponse({
    tabId: details.tabId as number,
    frameId: details.frameId as number,
    documentId: typeof details.documentId === 'string' ? details.documentId : '',
    url: typeof details.url === 'string' ? details.url : '',
    type,
    responseHeaders,
  });
}, {
  urls: ['http://*/*', 'https://*/*'],
  types: ['main_frame', 'sub_frame'],
}, ['responseHeaders']);
const websitePasskeyScripts = new WebsitePasskeyScriptManager({
  scripting: browser.scripting as unknown as WebsitePasskeyScriptingAdapter,
  notifyOpenTopFrames: createWebsitePasskeyTopFrameNotifier(
    browser as unknown as WebsitePasskeyBrowserLike,
  ),
});
const websitePasskeyLifecycle = createWebsitePasskeyLifecycle({
  settings,
  policy: websitePasskeyPolicyGate,
  scripts: websitePasskeyScripts,
});
let websitePasskeyPolicyMutationEpoch = 0;
let websitePasskeyPolicyMutationsInFlight = 0;
let websitePasskeyStorageRefreshPending = false;
let handledWebsitePasskeySettingsFingerprint: string | undefined;
const isSessionLeaseCurrent = (lease: SessionLease): boolean => {
  try { sessionGate.assert(lease); return true; } catch { return false; }
};
const isAccountLeaseCurrent = (lease: AccountLease): boolean => {
  try { accountGate.assert(lease); return true; } catch { return false; }
};
const autofillAuthorizationPolicyGates = {
  autofill: autofillPolicyGate,
  enterprise: enterprisePolicyGate,
} as const;
const isPolicyLeaseCurrent = (lease: AutofillAuthorizationPolicyLease): boolean => (
  isAutofillAuthorizationPolicyCurrent(autofillAuthorizationPolicyGates, lease)
);
const isEnterprisePolicyLeaseCurrent = (lease: PolicyLease): boolean => {
  try { enterprisePolicyGate.assert(lease); return true; } catch { return false; }
};
const vaultExportGrants = new VaultExportGrantRegistry<SessionLease, AccountLease, PolicyLease>({
  isSessionLeaseCurrent,
  isAccountLeaseCurrent,
  isPolicyLeaseCurrent: isEnterprisePolicyLeaseCurrent,
});
const repromptAutofillGrants = new RepromptAutofillGrantRegistry<
  SessionLease,
  AccountLease,
  AutofillAuthorizationPolicyLease
>({
  isSessionLeaseCurrent,
  isAccountLeaseCurrent,
  isPolicyLeaseCurrent,
  now: () => Date.now(),
});
const manualAutofillGrants = new ManualAutofillGrantRegistry<
  SessionLease,
  AccountLease,
  AutofillAuthorizationPolicyLease,
  PolicyLease,
  ManualAutofillVaultAuthority
>({
  isSessionLeaseCurrent,
  isAccountLeaseCurrent,
  isAutofillPolicyLeaseCurrent: isPolicyLeaseCurrent,
  isEnterprisePolicyLeaseCurrent,
  isVaultAuthorityCurrent: (authority) => {
    try { authority.assertCurrent(); return true; } catch { return false; }
  },
  now: () => Date.now(),
});
type TransferAccountSessionLeases = VaultTransferAccountSessionLeases<
  AccountLease,
  SessionLease
>;
type TransferExportAuthorization = RedeemedVaultExportGrant<SessionLease, AccountLease, PolicyLease>;
const vaultTransferLeaseBindings = createVaultTransferLeaseBindings(
  accountGate,
  sessionGate,
  enterprisePolicyGate,
);
const autofillIntents = new AutofillIntentRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>({
  isSessionLeaseCurrent,
  isAccountLeaseCurrent,
  isPolicyLeaseCurrent,
});
const keyboardGrants = new AutofillKeyboardGrantRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>({
  isSessionLeaseCurrent,
  isAccountLeaseCurrent,
  isPolicyLeaseCurrent,
});
const autofillContinuationStore = new AutofillContinuationStore({ store: sessionStore });
const autofillContinuationWorkerId = crypto.randomUUID();
const loadOwnedAutofillStorageUserKey = async () => {
  const loaded = await session.loadUserKey();
  if (!loaded) return undefined;
  try {
    return { encKey: loaded.encKey.slice(), macKey: loaded.macKey.slice() };
  } finally {
    loaded.encKey.fill(0);
    loaded.macKey.fill(0);
  }
};
const pendingSaves = new AutofillPendingSaveStore({
  store: sessionStore,
  scheduler: {
    schedule: (when) => browser.alarms.create(AUTOFILL_PENDING_SAVE_ALARM, { when }),
    cancel: async () => { await browser.alarms.clear(AUTOFILL_PENDING_SAVE_ALARM); },
  },
});
const usernameStages = new AutofillUsernameStageStore({
  store: sessionStore,
  loadUserKey: loadOwnedAutofillStorageUserKey,
});
function assertSaveCaptureCurrent(metadata: AutofillUnconfirmedSaveMetadata): void {
  const sessionLease = sessionGate.capture();
  const accountLease = accountGate.capture();
  const policyLease = captureAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates);
  if (sessionLease.generation !== metadata.sessionGeneration
      || accountLease.serverGeneration !== metadata.serverGeneration
      || accountLease.accountGeneration !== metadata.accountGeneration
      || accountLease.serverUrl !== metadata.serverUrl
      || accountLease.accountIdentity !== metadata.accountIdentity
      || policyLease.autofill.generation !== metadata.policyGeneration
      || policyLease.enterprise.generation !== metadata.enterprisePolicyGeneration
      || policyLease.enterprise.rawGeneration !== metadata.enterprisePolicyRawGeneration) {
    throw new AppError('denied', 'Pending save authority changed');
  }
}
const saveCaptureCoordinator = new AutofillSaveCaptureCoordinator({
  store: sessionStore,
  captures: pendingSaves,
  usernameStages,
  assertCurrent: assertSaveCaptureCurrent,
  loadUserKey: async (metadata) => {
    assertSaveCaptureCurrent(metadata);
    const active = await session.getActiveAuth();
    assertSaveCaptureCurrent(metadata);
    if (active?.sessionBindingId !== metadata.sessionBindingId) return undefined;
    return loadOwnedAutofillStorageUserKey();
  },
  onConfirmed: async (metadata) => {
    const rawFrame = await browser.webNavigation.getFrame({
      tabId: metadata.tabId,
      frameId: metadata.frameId,
    });
    const frame = rawFrame === null ? undefined : parseBrowserFrame(rawFrame);
    if (!frame?.documentId) throw new Error('Save-capture target document is unavailable');
    const response: unknown = await browser.tabs.sendMessage(metadata.tabId, {
      type: 'autofill.saveCaptureConfirmed',
      captureId: metadata.captureId,
    }, {
      frameId: metadata.frameId,
      documentId: frame.documentId,
    } as { frameId: number; documentId: string });
    if (typeof response !== 'object' || response === null
        || Reflect.ownKeys(response).length !== 1
        || (response as { readonly status?: unknown }).status !== 'displayed') {
      throw new Error('Save-capture content document is not ready');
    }
  },
  scheduler: {
    schedule: (when) => browser.alarms.create(AUTOFILL_SAVE_CAPTURE_ALARM, { when }),
    cancel: async () => { await browser.alarms.clear(AUTOFILL_SAVE_CAPTURE_ALARM); },
  },
});
const pageLoadFillDeduper = new PageLoadFillDeduper({ store: sessionStore });

async function authorizeBackgroundAutofill(
  frameUrl: string,
  action: AutofillPolicyAction,
): Promise<{
  assertCurrent(): void;
  defaultStrategy: UriMatchStrategySetting;
  autoCopyTotp: boolean;
}> {
  const policyLease = captureAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates);
  let policySettings;
  try {
    policySettings = await settings.getAutofillPolicySettings();
  } catch {
    throw new AppError('denied', 'Autofill is disabled for this site');
  }
  assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, policyLease);
  const decision = decideAutofillPolicy(
    normalizeAutofillBlocklist(policySettings.blockedDomains),
    { action, url: frameUrl },
  );
  if (!decision.allowed) throw new AppError('denied', 'Autofill is disabled for this site');
  const effectiveDefault = resolveAutofillAuthorizationUriMatchDefault(
    autofillAuthorizationPolicyGates,
    policyLease,
    policySettings.defaultUriMatchStrategy,
  );
  return {
    assertCurrent: () => {
      assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, policyLease);
    },
    defaultStrategy: effectiveDefault.value,
    autoCopyTotp: policySettings.autoCopyTotp,
  };
}

async function authorizeManualAutofillSave(
  url: string,
  policyLease: AutofillAuthorizationPolicyLease,
): Promise<{ assertCurrent(): void }> {
  let policySettings;
  try {
    policySettings = await settings.getAutofillPolicySettings();
  } catch {
    throw new AppError('denied', 'Saving this site is disabled.');
  }
  assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, policyLease);
  const globallyAllowed = decideAutofillPolicy(
    normalizeAutofillBlocklist(policySettings.blockedDomains),
    { action: 'update', url },
  ).allowed;
  const captureAllowed = decideAutofillPolicy(
    normalizeAutofillBlocklist(policySettings.savePromptExcludedDomains),
    { action: 'update', url },
  ).allowed;
  if (!policySettings.updatePromptEnabled || !globallyAllowed || !captureAllowed) {
    throw new AppError('denied', 'Saving this site is disabled.');
  }
  return {
    assertCurrent: () => {
      assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, policyLease);
    },
  };
}
const vaultDirtyStore = createVaultDirtyStore(localStore);
const vaultCoordinator = new VaultMutationCoordinator<
  string, AccountLease, VaultListing, string, string
>({
  captureLease: (account) => {
    const lease = accountGate.capture();
    if (`${lease.serverUrl}\n${lease.accountIdentity}` !== account) {
      throw new Error('Vault coordinator account does not match the active account');
    }
    return lease;
  },
  assertLease: (account, lease) => {
    accountGate.assert(lease);
    if (`${lease.serverUrl}\n${lease.accountIdentity}` !== account) {
      throw new Error('Vault coordinator account changed');
    }
  },
  dirtyAdapter: vaultDirtyStore,
});
const accountTransitions = new AccountTransitionCoordinator(accountGate, async () => {
  const [serverUrl, persistedAuth] = await Promise.all([
    settings.getServerUrl(),
    session.getPersistedAuth(),
  ]);
  if (!serverUrl) return undefined;
  return {
    serverUrl,
    ...(persistedAuth
      ? { accountIdentity: persistedAuth.email.trim().toLowerCase() }
      : {}),
  };
});
const transitionAccounts = new Map<number, string>();
const handleAccountTransition = async (event: SessionTransitionEvent): Promise<void> => {
  if (event.phase === 'start') {
    await Promise.allSettled([
      usernameStages.clear(),
      pendingSaves.clear(),
      saveCaptureCoordinator.clear(),
    ]);
    if (invalidatesEnterprisePolicy(event.reason)) enterprisePolicyGate.invalidate();
    const current = accountGate.current();
    const oldAccount = current?.accountIdentity
      ? `${current.serverUrl}\n${current.accountIdentity}`
      : undefined;
    await accountTransitions.handle(event);
    if (oldAccount && invalidatesEnterprisePolicy(event.reason)) {
      transitionAccounts.set(event.transitionId, oldAccount);
      vaultCoordinator.invalidateAccount(oldAccount);
    }
    return;
  }
  const transitionedAccount = transitionAccounts.get(event.transitionId);
  await accountTransitions.handle(event);
  transitionAccounts.delete(event.transitionId);
  settleVaultAccountAdmission(
    event,
    accountGate.current(),
    vaultCoordinator,
    transitionedAccount,
  );
};
let identityEpoch = 0;
let clearVaultCache = async (): Promise<void> => {};
let purgeDecryptedVaultCache = async (): Promise<void> => {};
let refreshContextMenu = async (): Promise<void> => {};
let refreshAutofillClients = async (): Promise<void> => {};
let notifyEnterprisePolicyClients = async (_phase: 'revoke' | 'refresh'): Promise<void> => {};
let reconcileGlobalLocalCloseLogoutOwners = async (): Promise<void> => {};
let clearOwnedClipboardOnSessionTransition = async (): Promise<void> => {};
let startVaultTimeoutTransition = (): void => {};
let settleVaultTimeoutTransition = async (_event: SessionTransitionEvent): Promise<void> => {};
let revokeVaultTransfers = (): void => {};
let reconcileVaultTransfers = async (): Promise<void> => {};
let handleVaultNotificationTransition = (_event: SessionTransitionEvent): void => {};
let clearDeviceLoginApprovalBadge = (): void => {};
let refreshDeviceLoginApprovalBadge = async (): Promise<void> => {};
let handleToolbarSessionTransition = (_event: SessionTransitionEvent): void => {};
let refreshToolbarActiveTabs = async (): Promise<void> => {};
let revokeToolbarMatches = (): void => {};
let closeInteractiveTwoFactorConnector = async (
  _document: InteractiveTwoFactorConnectorDocument,
): Promise<void> => {};
let cancelSsoLogin = async (): Promise<boolean> => false;
let cancelDuoLogin = async (): Promise<boolean> => false;
let synchronizeClientEventBinding = async (): Promise<void> => {};
let reconcileClientEventRuntime = async (_state: SessionState): Promise<void> => {};
let logoutWithClientEvents = async (): Promise<void> => {};
let handleClientEventLogoutTransition = async (_event: SessionTransitionEvent): Promise<void> => {};
let reconcileClientEventLogoutMarkers = async (): Promise<void> => {};
let clearClientEventsForServer = async (_serverUrl: string): Promise<void> => {};
let revokeClientEventAcks = (): void => {};
let revokeAutofillTotpCopies = (): void => {};
let revokeCommandCycles = (): void => {};
let runContinuedCommand = async (
  _command: SecretExtensionCommand,
  _tab: { readonly id: number; readonly windowId: number },
  _assertCurrent: () => void,
  _expectedSource: {
    readonly documentId: string;
    readonly runtimeIncarnation: string;
    readonly url: string;
  },
): Promise<void> => {};
let clearGeneratorHistoryForServerAfterRotation = async (_serverUrl: string): Promise<void> => {};
let clearGeneratorHistoryForAccount = async (_identity: RotationPendingIdentity): Promise<void> => {};
let clearGeneratorHistoryForServer = async (_serverUrl: string): Promise<void> => {};
const generatorHistoryLifecycle: {
  current?: Pick<GeneratorHistoryProductionService, 'lockActiveScope' | 'unlockCurrent'>;
} = {};
const api = new ApiClient({
  serverUrlProvider: async () => {
    const serverUrl = await settings.getServerUrl();
    if (!serverUrl) throw new Error('serverUrl is not configured');
    return serverUrl;
  },
  localStore,
});
const serverCapabilities = new ServerCapabilityManager<AccountLease>({
  captureIdentity: () => {
    const lease = accountGate.capture();
    return Object.freeze({
      identity: Object.freeze({
        serverUrl: lease.serverUrl,
        accountIdentity: lease.accountIdentity,
      }),
      lease,
    });
  },
  assertIdentityCurrent: (lease) => accountGate.assert(lease),
  fetchConfig: (request) => fetchFixedServerConfig(api, request),
  clientDeclaration: PRODUCTION_SERVER_CAPABILITY_DECLARATION,
});
const preLoginServerCapabilities = new ServerCapabilityManager<ServerLease>({
  captureIdentity: () => {
    const lease = accountGate.captureServer();
    return Object.freeze({
      identity: Object.freeze({ serverUrl: lease.serverUrl }),
      lease,
    });
  },
  assertIdentityCurrent: (lease) => accountGate.assertServer(lease),
  fetchConfig: (request) => fetchFixedServerConfig(api, request),
  clientDeclaration: PRODUCTION_SERVER_CAPABILITY_DECLARATION,
});
const pendingLoginStore = new PendingLoginStateStore(sessionStore, {
  alarms: {
    create: (name, options) => browser.alarms.create(name, options),
    clear: (name) => browser.alarms.clear(name),
  },
});
const ssoAttemptStore = new SsoAttemptStore(sessionStore);
const duoAttemptStore = new DuoAttemptStore(sessionStore);
const ssoRequiredCache = new SsoRequiredCache(localStore);

async function isSsoRequiredForCurrentServer(
  emailInput: string,
  expectedServerUrl?: string,
): Promise<boolean> {
  let email: string;
  try { email = normalizeSsoEmail(emailInput); } catch { return false; }
  const serverLease = accountGate.captureServer();
  accountGate.assertServer(serverLease);
  if (expectedServerUrl !== undefined && serverLease.serverUrl !== expectedServerUrl) {
    throw new AppError('session_expired', 'The configured server changed before sign-in.');
  }
  await preLoginServerCapabilities.resolve();
  accountGate.assertServer(serverLease);
  const capabilityLease = preLoginServerCapabilities.capture();
  const snapshot = preLoginServerCapabilities.assert(capabilityLease);
  const webVaultUrl = snapshot.capabilities.config.environment.vault;
  if (snapshot.availability !== 'available' || !webVaultUrl) return false;
  const required = await ssoRequiredCache.has({ email, webVaultUrl });
  accountGate.assertServer(serverLease);
  preLoginServerCapabilities.assert(capabilityLease);
  return required;
}

const auth: AuthService = new AuthService({
  api,
  session,
  sessionGate,
  accountGate,
  enterprisePolicyGate,
  assertPasswordLoginAllowed: async (email, expectedServerUrl) => {
    if (await isSsoRequiredForCurrentServer(email, expectedServerUrl)) {
      throw new AppError('denied', 'Your organization requires SSO sign-in.');
    }
  },
  authorizeSsoContinuation: async (expected) => {
    const authorization = await authorizeSsoLaunch({
      manager: preLoginServerCapabilities,
      api,
      captureServerLease: () => accountGate.captureServer(),
      assertServerLease: (lease) => accountGate.assertServer(lease),
    });
    authorization.assertCurrent();
    if (
      authorization.serverUrl !== expected.serverUrl
      || authorization.identityUrl !== expected.identityUrl
      || authorization.emailTwoFactorMode !== expected.emailTwoFactorMode
      || new URL('sso-connector.html', authorization.vaultUrl).toString() !== expected.redirectUri
    ) throw new AppError('session_expired', 'The SSO server environment changed.');
    return Object.freeze({ assertCurrent: authorization.assertCurrent });
  },
  rotationBarrier: {
    run: (account, task) => vaultCoordinator.forAccount(account).runTerminal(task),
  },
  rotationPending,
  clearGeneratorHistoryForServerAfterRotation: (serverUrl) => (
    clearGeneratorHistoryForServerAfterRotation(serverUrl)
  ),
  clearClientEventsAfterRotation: (identity) => clearClientEventsForServer(identity.serverUrl),
  clearGeneratorHistoryForAccount: (identity) => clearGeneratorHistoryForAccount(identity),
  clearGeneratorHistoryForServer: (serverUrl) => clearGeneratorHistoryForServer(serverUrl),
  passwordChangePending,
  pendingLoginStore,
  closeInteractiveTwoFactorConnector: (document) => closeInteractiveTwoFactorConnector(document),
  serverUrlProvider: () => settings.getServerUrl(),
  onIdentityChanged: async () => {
    identityEpoch++;
    await clearVaultCache();
  },
  onSessionTransition: (event): Promise<void> => {
    const revokeDeviceLogin: Promise<void> = deviceLoginCoordinator.revokeForSessionTransition(event);
    // Invalidate secret operations before any asynchronous transition work starts.
    if (event.phase === 'start') startVaultTimeoutTransition();
    if (event.phase === 'start') generatorHistoryLifecycle.current?.lockActiveScope();
    sessionGate.handleTransition(event);
    handleToolbarSessionTransition(event);
    if (event.phase === 'start') {
      revokeClientEventAcks();
      revokeAutofillTotpCopies();
      inlineGeneratorTracks.revokeAll();
      revokeCommandCycles();
      if (event.reason !== 'login') {
        void cancelSsoLogin().catch(() => false);
        void cancelDuoLogin().catch(() => false);
      }
      void notifyEnterprisePolicyClients('revoke');
      vaultExportGrants.revokeAll();
      repromptAutofillGrants.revokeAll();
      manualAutofillGrants.revokeAll();
      keyboardGrants.revokeAll();
      if (event.reason !== 'unlock' && event.reason !== 'pinUnlock') {
        void autofillContinuation.revokeAll();
      }
      vault.revokeOrganizationDataOwnershipGrants();
    }
    handleVaultNotificationTransition(event);
    const deviceLoginApprovalAction = deviceLoginApprovalTransitionAction(event);
    if (deviceLoginApprovalAction === 'clear') clearDeviceLoginApprovalBadge();
    else if (deviceLoginApprovalAction === 'refresh') void refreshDeviceLoginApprovalBadge();
    const preservesLockedContinuation = event.reason === 'unlock' || event.reason === 'pinUnlock';
    if (event.phase === 'start') {
      if (!preservesLockedContinuation) websitePasskeyLifecycle.invalidate();
      void websitePasskeyLifecycle.reconcile('locked')
        .then(() => preservesLockedContinuation
          ? undefined
          : websitePasskeys.handleAuthorizationChange())
        .catch((error: unknown) => {
          console.error('website passkey transition refresh failed', error);
        });
    } else {
      void websitePasskeyLifecycle.reconcile(event.state)
        .then(() => preservesLockedContinuation && event.succeeded
          ? event.state === 'unlocked'
            ? websitePasskeys.resumeConditionalAfterUnlock().then(() => undefined)
            : undefined
          : websitePasskeys.handleAuthorizationChange())
        .catch((error: unknown) => {
          console.error('website passkey settlement refresh failed', error);
        });
    }
    if (event.phase === 'start') revokeVaultTransfers();
    autofillPolicyGate.invalidate();
    void refreshAutofillClients().catch(() => {});
    if (event.phase === 'settled') {
      void notifyEnterprisePolicyClients('refresh');
      if (event.succeeded && event.state === 'unlocked') {
        void generatorHistoryLifecycle.current?.unlockCurrent().catch(() => {
          console.warn('generator_history_unlock_failed');
        });
      }
      void refreshContextMenu().catch(() => {});
      void vaultSyncScheduler?.sessionSettled(event).catch((error: unknown) => {
        console.error('vault session sync failed', error);
      });
      if (event.succeeded && event.state !== 'loggedOut') {
        void reconcileVaultTransfers().catch((error: unknown) => {
          console.error('vault transfer reconciliation failed', error);
        });
      }
    }
    return revokeDeviceLogin;
  },
  onSerializedSessionTransition: async (event) => {
    if (event.reason === 'logout') {
      await handleClientEventLogoutTransition(event);
    }
    if (event.phase === 'settled' && event.succeeded) {
      if (
        event.reason === 'lock'
        || event.reason === 'logout'
        || event.reason === 'switchAccount'
        || event.reason === 'removeAccount'
        || event.reason === 'serverChange'
        || event.reason === 'keyRotation'
        || (event.reason === 'login' && event.identityChanged)
      ) {
        await clearOwnedClipboardOnSessionTransition();
      }
    }
    await handleAccountTransition(event);
    if (event.phase === 'settled') {
      if (event.succeeded && event.reason === 'serverChange') {
        await vault.resetSecurityStampBaselines();
      }
      if (event.succeeded) await reconcileGlobalLocalCloseLogoutOwners();
      await settleVaultTimeoutTransition(event);
      if (event.succeeded && event.state !== 'loggedOut') {
        // Do not await network work from inside AuthService's serialized transition queue.
        void Promise.resolve()
          .then(() => reconcileClientEventRuntime(event.state))
          .catch(() => console.warn('client_event_transition_reconcile_failed'));
      }
    }
  },
  onLock: () => purgeDecryptedVaultCache(),
});
logoutWithClientEvents = () => auth.logout();

const sso = new SsoBrowserCoordinator({
  store: ssoAttemptStore,
  authorize: () => authorizeSsoLaunch({
    manager: preLoginServerCapabilities,
    api,
    captureServerLease: () => accountGate.captureServer(),
    assertServerLease: (lease) => accountGate.assertServer(lease),
  }),
  auth,
  browser: {
    action: { openPopup: () => browser.action.openPopup() },
    runtime: {
      getContexts: (input) => browser.runtime.getContexts(input as never) as never,
    },
    tabs: {
      create: (input) => browser.tabs.create(input),
      query: (input) => browser.tabs.query(input),
      get: (tabId) => browser.tabs.get(tabId),
      remove: (tabId) => browser.tabs.remove(tabId),
      update: (tabId, input) => browser.tabs.update(tabId, input),
    },
    windows: { update: (windowId, input) => browser.windows.update(windowId, input) },
    webNavigation: {
      getFrame: (input) => browser.webNavigation.getFrame(input),
    },
    scripting: {
      executeScript: (input) => browser.scripting.executeScript(input),
    },
  },
  popupUrl: browser.runtime.getURL('ui/popup/popup.html'),
});
cancelSsoLogin = () => sso.cancelCurrent();

async function reconcileSsoRequiredCache(): Promise<void> {
  const accountLease = accountGate.capture();
  const policyLease = enterprisePolicyGate.capture();
  const policy = enterprisePolicyGate.assert(policyLease);
  accountGate.assert(accountLease);
  if (
    policy.scope.serverUrl !== accountLease.serverUrl
    || policy.scope.accountIdentity !== accountLease.accountIdentity
  ) throw new AppError('denied', 'The Require SSO policy belongs to another account.');
  await serverCapabilities.resolve();
  accountGate.assert(accountLease);
  enterprisePolicyGate.assert(policyLease);
  const capabilityLease = serverCapabilities.capture();
  const capabilities = serverCapabilities.assert(capabilityLease);
  const webVaultUrl = capabilities.capabilities.config.environment.vault;
  if (capabilities.availability !== 'available' || !webVaultUrl) {
    throw new AppError('denied', 'The trusted Web Vault environment is unavailable.');
  }
  await ssoRequiredCache.reconcile({
    email: accountLease.accountIdentity,
    webVaultUrl,
  }, policy.requireSso);
  accountGate.assert(accountLease);
  enterprisePolicyGate.assert(policyLease);
  serverCapabilities.assert(capabilityLease);
}

async function readEffectiveVaultTimeout() {
  const [lockTimeout, onIdleAction] = await Promise.all([
    settings.getLockTimeout(),
    settings.getOnIdleAction(),
  ]);
  try {
    const lease = enterprisePolicyGate.capture();
    return resolveEffectiveVaultTimeout(lockTimeout, onIdleAction, {
      kind: 'available',
      policy: enterprisePolicyGate.assert(lease).maximumVaultTimeoutPolicy,
    });
  } catch {
    return resolveEffectiveVaultTimeout(lockTimeout, onIdleAction, { kind: 'unavailable' });
  }
}

reconcileGlobalLocalCloseLogoutOwners = async (): Promise<void> => {
  const [serverUrl, lockTimeout, onIdleAction] = await Promise.all([
    settings.getServerUrl(),
    settings.getLockTimeout(),
    settings.getOnIdleAction(),
  ]);
  const enabled = isLocalCloseLogoutEnabled(lockTimeout, onIdleAction);
  if (enabled) await session.moveAllTokensToSession();
  else await session.restoreLocalLogoutTokensToLocal();
  const accounts = await session.listAccounts();
  await vaultTimeoutState.reconcileLocalCloseLogoutOwners({
    ...(serverUrl ? { serverUrl } : {}),
    emails: accounts.map((account) => account.email),
    enabled,
  });
};

const vaultTimeout = new VaultTimeoutController({
  state: vaultTimeoutState,
  alarms: {
    create: (name, options) => browser.alarms.create(name, options),
    clear: (name) => browser.alarms.clear(name),
  },
  getContext: async () => {
    const [state, serverUrl, activeSnapshot] = await Promise.all([
      auth.getState(),
      settings.getServerUrl(),
      session.getActiveAuthSnapshot(),
    ]);
    const active = activeSnapshot?.auth;
    if (!serverUrl || !active) return { state };
    const email = active.email.trim().toLowerCase();
    return {
      state,
      accountKey: serverUrl + '\n' + email,
      email,
      credentialId: activeSnapshot.tokenLease.credentialId,
      tokenRevision: activeSnapshot.tokenLease.tokenRevision,
      ...(active.sessionBindingId ? { sessionBindingId: active.sessionBindingId } : {}),
    };
  },
  getConfig: readEffectiveVaultTimeout,
  reconcileTokenStorage: async (expected, target, reason) => {
    const current = accountGate.current();
    if (
      !current?.accountIdentity
      || current.serverUrl + '\n' + current.accountIdentity !== expected.accountKey
    ) throw new Error('Active account changed during token storage reconciliation');
    if (!await session.reconcileActiveTokenStorage(expected, target, reason)) {
      throw new Error('Active session changed during token storage reconciliation');
    }
  },
  applyAction: async (expected, action) => {
    const active = await session.getActiveAuth();
    const current = accountGate.current();
    if (
      active?.email !== expected.email
      || active.sessionBindingId !== expected.sessionBindingId
      || !current?.accountIdentity
      || current.serverUrl + '\n' + current.accountIdentity !== expected.accountKey
    ) return;
    await (action === 'logout' ? logoutWithClientEvents() : auth.lock());
  },
  monotonicNow: () => performance.now(),
  logger: { warn: (event) => console.warn(event) },
});
const vaultReleaseGate = new VaultReleaseGate(vaultTimeout, sessionGate);
startVaultTimeoutTransition = () => vaultTimeout.transitionStarted();
settleVaultTimeoutTransition = (event) => event.phase === 'settled'
  ? vaultTimeout.transitionSettled(event.succeeded, event.state)
  : Promise.resolve();
sessionGate.setPreflight(() => vaultTimeout.preflight());

const vault = new VaultService({
  api,
  auth,
  session,
  localStore,
  sessionStore,
  sessionGate,
  accountGate,
  policyGate: enterprisePolicyGate,
  coordinator: vaultCoordinator,
  authorizeCipherArchive: () => authorizeCipherArchive(serverCapabilities),
  authorizeCollectionNameOnlyUpdate: () => authorizeCollectionNameOnlyUpdate(serverCapabilities),
  authorizeOrganizationDataOwnershipTransport: () => (
    authorizeOrganizationDataOwnershipTransport(serverCapabilities)
  ),
  authorizeSshCipherType5Write: () => authorizeSshCipherType5Write(serverCapabilities),
  onPolicySnapshotPublished: () => applyEnterprisePolicySideEffects({
    applyVaultTimeout: () => vaultTimeout.reconfigure(),
    invalidateAutofill: async () => {
      manualAutofillGrants.revokeAll();
      keyboardGrants.revokeAll();
      revokeCommandCycles();
      revokeToolbarMatches();
      autofillPolicyGate.invalidate();
      await autofillContinuation.reconcilePolicy();
    },
    clearPendingSaves: async () => {
      await Promise.all([pendingSaves.clear(), saveCaptureCoordinator.clear()]);
    },
    clearUsernameStages: () => usernameStages.clear(),
    enforceSessionPolicy: async () => {
      await auth.enforceCurrentEnterprisePolicy();
      await reconcileSsoRequiredCache();
    },
    refreshIdleDetection: () => idleLock.applyDetection(),
    refreshAutofill: async () => {
      await Promise.all([
        refreshAutofillClients(),
        notifyEnterprisePolicyClients('refresh'),
        refreshToolbarActiveTabs(),
      ]);
    },
    refreshContextMenu: () => refreshContextMenu(),
    warn: (effect, error) => console.warn('enterprise_policy_side_effect_failed', effect, error),
  }),
  onSyncSuccess: async (identity) => {
    try {
      await vaultSyncScheduler?.recordSuccessfulSync(identity);
      await Promise.all([refreshContextMenu(), refreshToolbarActiveTabs()]);
    } finally {
      await synchronizeClientEventBinding();
    }
  },
  onSecurityStampMismatch: async (authority) => {
    const { accountLease, tokenLease } = authority;
    accountGate.assert(accountLease);
    const current = await session.getActiveAuthSnapshot();
    accountGate.assert(accountLease);
    if (!current
      || current.auth.email !== accountLease.accountIdentity
      || current.tokenLease.email !== tokenLease.email
      || current.tokenLease.credentialId !== tokenLease.credentialId) return;
    const resetAllAccounts = authority.failure.kind === 'state_unavailable';
    const revoked = await auth.revokeForSecurityStampFailure(
      current.tokenLease,
      resetAllAccounts ? 'allAccounts' : 'currentCredential',
    );
    if (resetAllAccounts && revoked) {
      try {
        await vault.clearCache();
      } finally {
        await vault.resetSecurityStampBaselines();
      }
    }
  },
  onMutationSyncRequired: () => {
    vaultSyncScheduler?.mutation();
    void refreshToolbarActiveTabs();
  },
  getIdentityEpoch: () => identityEpoch,
  getVaultIdentity: async () => {
    const [serverUrl, persistedAuth] = await Promise.all([
      settings.getServerUrl(),
      session.getPersistedAuth(),
    ]);
    if (!serverUrl || !persistedAuth) return undefined;
    return `${serverUrl}\n${persistedAuth.email.trim().toLowerCase()}`;
  },
});

function currentToolbarCopy(): ToolbarStateCopy {
  return Object.freeze({
    unlocked: t('toolbar.title.unlocked'),
    locked: t('toolbar.title.locked'),
    signedOut: t('toolbar.title.signedOut'),
    pendingApprovals: (count: number) => t('toolbar.title.pendingApprovals', { count }),
    matchingLogins: (count: number) => t('toolbar.title.matchingLogins', { count }),
  });
}

async function renderToolbar(tabId?: number, currentUrl?: string): Promise<void> {
  await initLocale();
  const storedMatch = tabId === undefined ? undefined : toolbarMatches.get(tabId);
  const match = currentUrl !== undefined && storedMatch?.url === currentUrl
    ? storedMatch
    : undefined;
  await toolbarState.apply({
    authState: toolbarAuthState,
    copy: currentToolbarCopy(),
    pendingApprovalCount: toolbarPendingApprovalCount,
    matchingLoginCount: match?.count ?? 0,
    showMatchingLoginCount: toolbarShowMatchingLoginCount,
  }, tabId);
}

async function renderToolbarAcrossActiveTabs(): Promise<void> {
  const tabs = await browser.tabs.query({ active: true });
  await Promise.allSettled([
    renderToolbar(),
    ...tabs.flatMap((tab) => (
      tab.id === undefined || tab.url === undefined ? [] : [renderToolbar(tab.id, tab.url)]
    )),
  ]);
}

const toolbarMatchCounter = new ToolbarMatchCountController({
  hasHostAccess: createHostAccessCheck((permissions) => browser.permissions.contains(permissions)),
  countMatches: async (url, bindFinalAuthority) => {
    const authorization = await authorizeBackgroundAutofill(url, 'candidate');
    let vaultAuthority: (() => void) | undefined;
    const count = await vault.countAutofillLoginMatches(
      url,
      authorization.defaultStrategy,
      (assertCurrent) => { vaultAuthority = assertCurrent; },
    );
    if (!vaultAuthority) throw new AppError('denied', 'Toolbar match authority is unavailable.');
    bindFinalAuthority(() => {
      authorization.assertCurrent();
      vaultAuthority!();
    });
    return count;
  },
  publish: async (contribution: ToolbarMatchContribution) => {
    toolbarMatches.set(contribution.tabId, Object.freeze({
      url: contribution.url,
      count: contribution.count,
    }));
    await renderToolbar(contribution.tabId, contribution.url);
  },
  forget: (tabId) => {
    toolbarMatches.delete(tabId);
    toolbarState.forgetTab(tabId);
  },
  logger: { warn: (event) => console.warn(event) },
});

async function refreshToolbarTab(tabId: number): Promise<void> {
  try {
    const tab = await browser.tabs.get(tabId);
    const url = tab.url;
    if (!tab.active || typeof url !== 'string') {
      toolbarMatches.delete(tabId);
      await renderToolbar(tabId, url);
      return;
    }
    await toolbarMatchCounter.refresh(
      { id: tabId, url },
      toolbarAuthState,
      toolbarShowMatchingLoginCount,
    );
  } catch {
    toolbarMatchCounter.revokeTab(tabId);
  }
}

refreshToolbarActiveTabs = async (): Promise<void> => {
  const tabs = await browser.tabs.query({ active: true });
  await Promise.allSettled([
    renderToolbar(),
    ...tabs.flatMap((tab) => (
      tab.id === undefined || tab.url === undefined
        ? []
        : [toolbarMatchCounter.refresh(
            { id: tab.id, url: tab.url },
            toolbarAuthState,
            toolbarShowMatchingLoginCount,
          )]
    )),
  ]);
};

revokeToolbarMatches = (): void => {
  toolbarMatchCounter.revokeAll();
  toolbarMatches.clear();
};

handleToolbarSessionTransition = (event): void => {
  const reduced = reduceToolbarAuthTransition({
    transitionId: toolbarTransitionId,
    authState: toolbarAuthState,
  }, event);
  if (!reduced.accepted) return;
  toolbarTransitionId = reduced.transitionId;
  toolbarAuthState = reduced.authState;
  if (reduced.clearMatches) revokeToolbarMatches();
  if (reduced.clearApprovals) toolbarPendingApprovalCount = 0;
  if (reduced.refreshMatches) void refreshToolbarActiveTabs();
  else void renderToolbarAcrossActiveTabs();
};

async function initializeToolbar(state: SessionState): Promise<void> {
  toolbarAuthState = state;
  const revision = ++toolbarSettingsRevision;
  const enabled = await settings.getShowMatchingLoginCount();
  if (revision !== toolbarSettingsRevision) return;
  toolbarShowMatchingLoginCount = enabled;
  await refreshToolbarActiveTabs();
}

type GeneratorHistorySecurity = GeneratorHistorySecurityBinding<SessionLease, AccountLease, PolicyLease>;
const generatorHistory = new GeneratorHistoryProductionService({
  store: localStore,
  withCurrentAuthority: createGeneratorHistoryAuthorityProvider({
    captureSecurity: (): GeneratorHistorySecurity => {
      const sessionLease = sessionGate.capture();
      const accountLease = accountGate.capture();
      const policyLease = enterprisePolicyGate.capture();
      return Object.freeze({
        sessionLease,
        accountLease,
        policyLease,
        serverUrl: accountLease.serverUrl,
        accountIdentity: accountLease.accountIdentity,
        policyRevision: policyLease.generation,
      });
    },
    assertSecurity: (binding): void => {
      sessionGate.assert(binding.sessionLease);
      accountGate.assert(binding.accountLease);
      enterprisePolicyGate.assert(binding.policyLease);
      if (binding.policyLease.serverUrl !== binding.accountLease.serverUrl
        || binding.policyLease.accountIdentity !== binding.accountLease.accountIdentity
        || binding.serverUrl !== binding.accountLease.serverUrl
        || binding.accountIdentity !== binding.accountLease.accountIdentity
        || binding.policyRevision !== binding.policyLease.generation) {
        throw new AppError('denied', 'Generator history authority changed account');
      }
    },
    captureIdentity: () => vault.captureGeneratorHistoryIdentity(),
    loadUserKey: () => session.loadUserKey(),
  }),
});
const inlineGeneratorTracks = new InlineGeneratorTrackTokenRegistry({
  history: generatorHistory,
});
interface PasswordGenerationAuthority {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
}
const passwordGenerationAction = createPasswordGenerationAction<PasswordGenerationAuthority>({
  readPrefs: () => localStore.get<unknown>(GENERATOR_PREFS_STORAGE_KEY),
  captureAuthority: () => {
    const authority = Object.freeze({
      sessionLease: sessionGate.capture(),
      accountLease: accountGate.capture(),
      policyLease: enterprisePolicyGate.capture(),
    });
    sessionGate.assert(authority.sessionLease);
    accountGate.assert(authority.accountLease);
    enterprisePolicyGate.assert(authority.policyLease);
    return authority;
  },
  assertAuthority: (authority) => {
    accountGate.assert(authority.accountLease);
    enterprisePolicyGate.assert(authority.policyLease);
    sessionGate.assert(authority.sessionLease);
  },
  getPolicySnapshot: (authority) => createGeneratorPolicySnapshot(
    enterprisePolicyGate.assert(authority.policyLease).passwordGeneratorPolicy,
    authority.policyLease.generation,
  ),
  history: generatorHistory,
});
generatorHistoryLifecycle.current = generatorHistory;
clearGeneratorHistoryForServerAfterRotation = (serverUrl) => (
  generatorHistory.removeServerScopes(serverUrl).then(() => undefined)
);
clearGeneratorHistoryForAccount = (identity) => generatorHistory.removeExactAccount(
  identity.serverUrl,
  identity.accountId,
).then(() => undefined);
clearGeneratorHistoryForServer = (serverUrl) => generatorHistory.removeServerScopes(serverUrl)
  .then(() => undefined);
async function reconcileGeneratorHistoryRegistry(): Promise<void> {
  const [serverUrl, accounts] = await Promise.all([
    settings.getServerUrl(),
    session.listAccounts(),
  ]);
  await generatorHistory.reconcileRegisteredAccounts(serverUrl
    ? accounts.map((account) => Object.freeze({
        serverUrl,
        accountIdentity: account.email.trim().toLowerCase(),
      }))
    : []);
}
const clientEventRuntime = createClientEventProduction<AccountLease>({
  store: localStore,
  authority: {
    captureActive: () => vault.captureClientEventAuthorityProjection(),
  },
  alarms: {
    get: async (name) => {
      const alarm = await browser.alarms.get(name);
      return alarm ? { scheduledTime: alarm.scheduledTime } : undefined;
    },
    create: (name, options) => browser.alarms.create(name, options),
    clear: (name) => browser.alarms.clear(name),
  },
  captureAccountLease: () => accountGate.capture(),
  assertAccountLease: (lease) => accountGate.assert(lease),
  executeAuthenticatedRequest: (lease, rebuildRequest) => (
    auth.executeAuthenticatedRequest(lease, rebuildRequest)
  ),
  apiForServer: (serverUrl, assertCurrent) => (
    api.forServer(serverUrl).withRequestGuard(assertCurrent)
  ),
}, {
  onServiceError: (operation) => console.warn(`client_event_${operation}_failed`),
  onTransportError: () => console.warn('client_event_transport_failed'),
});
const clientEventLogoutLifecycle = new ClientEventAuthLogoutLifecycle(clientEventRuntime);
handleClientEventLogoutTransition = (event) => clientEventLogoutLifecycle.handle(event);
reconcileClientEventLogoutMarkers = async (): Promise<void> => {
  const [serverUrl, accounts] = await Promise.all([
    settings.getServerUrl(),
    session.listAccounts(),
  ]);
  const result = await bestEffortClientEvent(() => clientEventRuntime.reconcileLogoutDiscards(
    serverUrl
      ? accounts.map((account) => Object.freeze({
          serverUrl,
          accountIdentity: account.email,
        }))
      : [],
  ));
  if (!result || result.failed > 0) console.warn('client_event_logout_reconcile_failed');
};
clearClientEventsForServer = async (serverUrl): Promise<void> => {
  const result = await clientEventRuntime.discardServerScopes(serverUrl);
  if (result.failed > 0) throw new Error('Client event server cleanup failed');
};
synchronizeClientEventBinding = async (): Promise<void> => {
  const binding = await bestEffortClientEvent(
    () => clientEventRuntime.synchronizeActiveBinding(),
  );
  if (!binding) {
    console.warn('client_event_binding_sync_failed');
  }
};
reconcileClientEventRuntime = async (state): Promise<void> => {
  if (state === 'loggedOut') return;
  if (state === 'unlocked') await synchronizeClientEventBinding();
  try {
    await clientEventRuntime.flushActive();
  } catch {
    console.warn('client_event_reconcile_failed');
  }
};
logoutWithClientEvents = async (): Promise<void> => {
  await auth.logout();
};
const clientEventActions = Object.freeze({
  prepare: (request: Parameters<typeof clientEventRuntime.prepare>[0]) => (
    clientEventRuntime.prepare(request)
  ),
  commit: (receipt: Parameters<typeof clientEventRuntime.commit>[0]) => (
    clientEventRuntime.commit(receipt)
  ),
});
const clientEventAcks = new ClientEventAckRegistry({
  committer: clientEventActions,
  onError: () => console.warn('client_event_ack_failed'),
});
revokeClientEventAcks = () => {
  clientEventAcks.revokeAll();
};
const structuredFillEvents = new ClientEventFillRecorder(clientEventActions);

function supportsOrganizationDeclineEvents(): boolean {
  const snapshot = serverCapabilities.current();
  if (!snapshot || snapshot.availability !== 'available') return false;
  const config = snapshot.capabilities.config;
  return config.serverKind === 'bitwarden'
    || (config.serverName === undefined && config.protocolVersion !== undefined);
}

async function issuePersonalExportClientEventAck(
  documentId: string,
): Promise<string | undefined> {
  const sessionLease = sessionGate.capture();
  const accountLease = accountGate.capture();
  const assertCurrent = (): void => {
    sessionGate.assert(sessionLease);
    accountGate.assert(accountLease);
  };
  const receipt = await clientEventRuntime.prepare({
    type: ClientEventType.User_ClientExportedVault,
  });
  assertCurrent();
  return receipt
    ? clientEventAcks.issue({ kind: 'options', documentId }, receipt, assertCurrent)
    : undefined;
}

async function issueOrganizationExportClientEventAck(
  documentId: string,
  organizationId: string,
): Promise<string | undefined> {
  const sessionLease = sessionGate.capture();
  const accountLease = accountGate.capture();
  const assertCurrent = (): void => {
    sessionGate.assert(sessionLease);
    accountGate.assert(accountLease);
  };
  const receipt = await clientEventRuntime.prepare({
    type: ClientEventType.Organization_ClientExportedVault,
    organizationId,
  });
  assertCurrent();
  return receipt
    ? clientEventAcks.issue({ kind: 'options', documentId }, receipt, assertCurrent)
    : undefined;
}
const vaultTransferSessions = new VaultTransferSessionManager<
  AccountLease,
  SessionLease,
  PolicyLease
>({
  captureLeases: vaultTransferLeaseBindings.captureSecurity,
  assertLeasesCurrent: vaultTransferLeaseBindings.assertSecurity,
});
const vaultTransferJournal = createVaultTransferJournalStore(localStore);
const vaultTransferController = new VaultTransferController<
  AccountLease,
  SessionLease,
  PolicyLease,
  AccountLease,
  TransferAccountSessionLeases,
  TransferAccountSessionLeases,
  TransferExportAuthorization
>({
  sessions: vaultTransferSessions,
  journal: vaultTransferJournal,
  // Preview probes the active account and server generation. Commit obtains fresh authorizations
  // and reasserts them in request guards immediately before protected POSTs.
  getImportCapabilities: () => vault.getPortableVaultImportCapabilities(),
  validateImportSource: (source, capabilities) => (
    vault.validatePortableVaultImportSource(source, capabilities)
  ),
  inspectSource: (source, options, authority) => {
    return vault.inspectPortableVaultTransferSource(source, options ?? {}, {
      accountLease: authority.transferLeases.account,
      sessionLease: authority.transferLeases.session,
    });
  },
  captureAccountIdentity: () => {
    const lease = accountGate.capture();
    return Object.freeze({
      canonicalIdentity: `${lease.serverUrl}\n${lease.accountIdentity}`,
      lease,
    });
  },
  assertAccountIdentityCurrent: (snapshot) => {
    accountGate.assert(snapshot.lease);
    return snapshot.canonicalIdentity
      === `${snapshot.lease.serverUrl}\n${snapshot.lease.accountIdentity}`;
  },
  // Raw bytes remain bound to the preview policy by vaultTransferSessions. After those bytes are
  // consumed and zeroed, VaultService owns policy checks and may legitimately publish a new policy
  // generation during its final sync, so the controller's outer lease binds only account/session.
  captureTransferLeases: vaultTransferLeaseBindings.captureAccountSession,
  assertTransferLeasesCurrent: vaultTransferLeaseBindings.assertAccountSession,
  captureReconcileLeases: vaultTransferLeaseBindings.captureAccountSession,
  assertReconcileLeasesCurrent: vaultTransferLeaseBindings.assertAccountSession,
  commitImport: (input) => vault.commitPortableVaultImport(input),
  buildExport: (format, filePassword, authorization, target) => vault.buildPortableVaultExport(
    format,
    filePassword,
    {
      accountLease: authorization.accountLease,
      sessionLease: authorization.sessionLease,
    },
    target,
  ),
  redeemExportAuthorization: ({ authorizationId, format, encryptionType, target }) => (
    vaultExportGrants.redeem(authorizationId, format, encryptionType, target)
  ),
  reconcileCurrentAccount: async () => {
    await vault.sync('vault-transfer-reconcile', 'force');
  },
});
const vaultTransferLifecycle = createVaultTransferLifecycle(
  vaultTransferController,
  (phase, error) => console.error(`vault transfer ${phase} failed`, error),
);
revokeVaultTransfers = vaultTransferLifecycle.revokeAtTransitionStart;
reconcileVaultTransfers = vaultTransferLifecycle.reconcile;
const vaultSyncScheduler = createVaultSyncScheduler({
  getSessionContext: async () => {
    try {
      const lease = accountGate.capture();
      const identity = `${lease.serverUrl}\n${lease.accountIdentity}`;
      const state = await auth.getState();
      if (state === 'restricted') return { state, identity };
      try {
        sessionGate.capture();
        return { state: 'unlocked' as const, identity };
      } catch {
        return { state: 'locked' as const, identity };
      }
    } catch {
      return { state: 'loggedOut' as const };
    }
  },
  requestSync: (reason, policy) => vault.sync(reason, policy),
  rebuildCache: async (identity) => {
    const lease = accountGate.capture();
    if (`${lease.serverUrl}\n${lease.accountIdentity}` !== identity) return;
    await vault.rebuildCache();
  },
  isDirty: (identity) => vaultDirtyStore.readDirty(identity),
  metadataStore: localStore,
  alarms: {
    get: (name) => browser.alarms.get(name),
    create: (name, options) => { browser.alarms.create(name, options); },
  },
  onBackgroundError: (error) => console.error('vault background sync failed', error),
});
const deviceLoginAlarms = {
  create: (name: string, options: { when: number }) => { browser.alarms.create(name, options); },
  clear: (name: string) => browser.alarms.clear(name),
};
let handleDeviceLoginSignal = async (): Promise<void> => {};
const deviceLoginNotifications = createDeviceLoginNotifications({
  onSignal: () => handleDeviceLoginSignal(),
  alarms: deviceLoginAlarms,
  logger: { warn: (event) => console.warn(`device_login_notification_${event}`) },
});
const deviceLoginStateStore = new DeviceLoginStateStore(sessionStore);
const deviceLoginCoordinator: DeviceLoginCoordinator = new DeviceLoginCoordinator({
  api,
  serverGate: accountGate,
  stateStore: deviceLoginStateStore,
  notifications: deviceLoginNotifications,
  alarms: deviceLoginAlarms,
  activate: (input) => auth.completeDeviceLogin(input),
  getNotificationsUrl: (lease) => (
    resolveDeviceLoginNotificationsUrl(api, accountGate, lease)
  ),
  closeInteractiveTwoFactorConnector: (document) => closeInteractiveTwoFactorConnector(document),
});
const accountPasskeyAttempts = new AccountPasskeyAttemptRegistry(sessionStore);
const accountPasskeyCoordinator = new AccountPasskeyCoordinator({
  api,
  serverGate: accountGate,
  attempts: accountPasskeyAttempts,
  activate: (input) => auth.completeAccountPasskeyLogin(input),
});
const accountPasskeyBrowser = new AccountPasskeyBrowserOrchestrator({
  browser: browser as unknown as AccountPasskeyBrowserApi,
  coordinator: accountPasskeyCoordinator,
  attempts: accountPasskeyAttempts,
  getServerUrl: () => settings.getServerUrl(),
  getAuthState: () => auth.getState(),
  getPopupUrl: () => browser.runtime.getURL('ui/popup/popup.html'),
  logger: { warn: (event) => console.warn(`account_passkey_${event}`) },
});
const duo = new DuoBrowserCoordinator({
  store: duoAttemptStore,
  password: {
    prepare: async (input) => {
      if (input.flow !== 'password') throw new AppError('denied', 'Invalid Duo flow.');
      return auth.prepareDuoTwoFactor({
        provider: input.provider,
        continuationId: input.continuationId,
      });
    },
    complete: (input) => auth.completeDuoTwoFactor(input),
  },
  deviceLogin: {
    prepare: async (input) => {
      if (input.flow !== 'deviceLogin') throw new AppError('denied', 'Invalid Duo flow.');
      return deviceLoginCoordinator.prepareDuoTwoFactor({
        generation: input.generation,
        provider: input.provider,
      });
    },
    complete: (input) => deviceLoginCoordinator.completeDuoTwoFactor(input),
  },
  authorize: async (expectedServerUrl) => {
    const serverLease = accountGate.captureServer();
    accountGate.assertServer(serverLease);
    if (serverLease.serverUrl !== expectedServerUrl) {
      throw new AppError('session_expired', 'The Duo server changed.');
    }
    await preLoginServerCapabilities.resolve({ forceRefresh: true });
    accountGate.assertServer(serverLease);
    const capabilityLease = preLoginServerCapabilities.capture();
    const snapshot = preLoginServerCapabilities.assert(capabilityLease);
    const vaultUrl = snapshot.capabilities.config.environment.vault;
    if (snapshot.availability !== 'available' || !vaultUrl) {
      throw new AppError('denied', 'The trusted Web Vault connector is unavailable.');
    }
    const assertCurrent = (): void => {
      accountGate.assertServer(serverLease);
      const current = preLoginServerCapabilities.assert(capabilityLease);
      if (current.capabilities.config.environment.vault !== vaultUrl) {
        throw new AppError('session_expired', 'The Duo connector environment changed.');
      }
    };
    assertCurrent();
    return Object.freeze({ serverUrl: serverLease.serverUrl, vaultUrl, assertCurrent });
  },
  browser: {
    action: { openPopup: () => browser.action.openPopup() },
    runtime: {
      getContexts: (input) => browser.runtime.getContexts(input as never) as never,
    },
    tabs: {
      create: (input) => browser.tabs.create(input),
      query: (input) => browser.tabs.query(input),
      get: (tabId) => browser.tabs.get(tabId),
      update: (tabId, input) => browser.tabs.update(tabId, input),
      remove: (tabId) => browser.tabs.remove(tabId),
    },
    windows: { update: (windowId, input) => browser.windows.update(windowId, input) },
    webNavigation: { getFrame: (input) => browser.webNavigation.getFrame(input) },
    scripting: { executeScript: (input) => browser.scripting.executeScript(input) },
  },
  popupUrl: browser.runtime.getURL('ui/popup/popup.html'),
});
cancelDuoLogin = () => duo.cancelCurrent();
handleDeviceLoginSignal = async () => {
  await deviceLoginCoordinator.handleSignal();
};
const deviceLoginApprovals = createDeviceLoginApprovalService({
  api,
  session,
  auth,
  sessionGate,
  accountGate,
});
const deviceLoginApprovalSystemNotifications = createDeviceLoginApprovalNotificationController({
  listPending: () => deviceLoginApprovals.discover(),
  captureAccountLease: () => accountGate.capture(),
  assertAccountLease: (lease) => accountGate.assert(lease),
  browser: browser as unknown as DeviceLoginApprovalNotificationBrowser,
  alarms: deviceLoginAlarms,
  store: sessionStore,
  popupUrl: browser.runtime.getURL('ui/popup/popup.html'),
  iconUrl: browser.runtime.getURL('icons/icon128.png'),
  getCopy: async () => {
    await initLocale();
    return Object.freeze({
      title: t('auth.deviceLogin.notificationTitle'),
      message: t('auth.deviceLogin.notificationMessage'),
    });
  },
  logger: { warn: (event) => console.warn(`device_login_approval_notification_${event}`) },
});
const deviceLoginApprovalBadge = new DeviceLoginApprovalBadgeController({
  listPending: () => deviceLoginApprovals.discover(),
  publish: async (contribution) => {
    toolbarPendingApprovalCount = contribution.pendingCount;
    await renderToolbarAcrossActiveTabs();
  },
  logger: { warn: (event) => console.warn(`device_login_${event}`) },
});
clearDeviceLoginApprovalBadge = () => {
  deviceLoginApprovalBadge.clear();
  void deviceLoginApprovalSystemNotifications.clear();
};
refreshDeviceLoginApprovalBadge = async () => {
  await Promise.allSettled([
    deviceLoginApprovalBadge.refresh(),
    deviceLoginApprovalSystemNotifications.refresh(),
  ]);
};
deviceLoginApprovalBadge.clear();
const vaultNotificationRuntime = createVaultNotificationProductionRuntime({
  capabilities: serverCapabilities,
  api,
  auth: {
    getAccountAccessToken: (accountLease) => auth.getAccountAccessToken(accountLease),
    logout: () => logoutWithClientEvents(),
  },
  vault,
  syncScheduler: vaultSyncScheduler,
  captureAccountLease: () => accountGate.capture(),
  assertAccountLease: (lease) => accountGate.assert(lease),
  alarms: {
    create: (name, options) => { browser.alarms.create(name, options); },
    clear: (name) => browser.alarms.clear(name),
  },
  authRequest: async () => {
    if (hasActiveNotificationAccount(await auth.getState())) {
      await refreshDeviceLoginApprovalBadge();
    }
  },
  // Only this fixed event-code union reaches diagnostics; no transport error, URL, or token does.
  logger: { warn: (event) => console.warn(`vault_notification_${event}`) },
});
handleVaultNotificationTransition = (event) => {
  vaultNotificationRuntime.handleSessionTransition(event);
};
const transferAwareSyncScheduler = {
  manual: async (): Promise<void> => {
    await vaultSyncScheduler.manual();
    await reconcileVaultTransfers();
  },
  popupOpened: () => vaultSyncScheduler.popupOpened(),
  getLastSuccess: () => vaultSyncScheduler.getLastSuccess(),
  getSyncStatus: () => vaultSyncScheduler.getSyncStatus(),
};
clearVaultCache = () => vault.clearCache();
purgeDecryptedVaultCache = () => vault.purgeDecryptedCaches();

type DocumentMessageOptions = { frameId: number; documentId: string };
const documentTabs = browser.tabs as unknown as {
  sendMessage(tabId: number, message: unknown, options: DocumentMessageOptions): Promise<unknown>;
};

async function getKeyboardTopDocument(
  tabId: number,
): Promise<{ documentId: string; url: string; runtimeIncarnation?: string } | undefined> {
  const frame = await browser.webNavigation.getFrame({ tabId, frameId: 0 });
  const parsed = frame === null ? undefined : parseBrowserFrame(frame);
  if (parsed?.frameId !== 0 || !parsed.documentId) return undefined;
  const runtimeIncarnation = await saveCaptureCoordinator.getRuntimeIncarnation(
    tabId,
    0,
    parsed.documentId,
  );
  return {
    documentId: parsed.documentId,
    url: parsed.url,
    ...(runtimeIncarnation ? { runtimeIncarnation } : {}),
  };
}

refreshAutofillClients = async (): Promise<void> => {
  const tabs = await browser.tabs.query({});
  await Promise.allSettled(tabs.flatMap((tab) => {
    if (tab.id === undefined) return [];
    return [browser.webNavigation.getAllFrames({ tabId: tab.id }).then(async (frames) => {
      await Promise.allSettled((frames ?? []).flatMap((frame) => {
        const parsed = parseBrowserFrame(frame);
        return parsed?.documentId
          ? [documentTabs.sendMessage(
              tab.id!,
              { type: 'autofill.clientConfigChanged' },
              { frameId: parsed.frameId, documentId: parsed.documentId },
            )]
          : [];
      }));
    })];
  }));
};

notifyEnterprisePolicyClients = async (phase): Promise<void> => {
  try {
    await browser.runtime.sendMessage({ type: 'enterprisePolicy.clientChanged', phase });
  } catch {
    // Extension pages are ephemeral; no active receiver is the normal case.
  }
};

const contextMenu = createContextMenu({
  getState: () => auth.getState(),
  getActiveTabId: async () => {
    const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
    return tab?.id;
  },
  getTabSuggestions: (tabId) => tabAutofill.getSuggestions(tabId),
  fillTabSuggestion: (tabId, cipherId, target, assertCurrent) => (
    tabAutofill.fill(tabId, cipherId, target, assertCurrent)
  ),
  findFillItems: (kind) => vault.findFillItems(kind),
  getFillData: async (cipherId, kind, roles, bindFinalAuthority) => {
    const data = await vault.getFillData(
      cipherId,
      kind,
      roles,
      undefined,
      bindFinalAuthority,
    );
    await structuredFillEvents.prepare(cipherId, data);
    return data;
  },
  actions: {
    getCapabilities: async () => {
      const policyLease = enterprisePolicyGate.capture();
      const listing = await vault.listItems();
      const snapshot = createGeneratorPolicySnapshot(
        enterprisePolicyGate.assert(policyLease).passwordGeneratorPolicy,
        policyLease.generation,
      );
      enterprisePolicyGate.assert(policyLease);
      const canCreate = listing.personalCreationAllowed === true
        || listing.orgPermissions.some((organization) => organization.canCreateItems === true);
      return Object.freeze({
        copyUsername: true,
        copyPassword: true,
        copyTotp: true,
        generatePassword: !snapshot.malformed && snapshot.password.allowed
          && snapshot.forcedMode !== 'passphrase',
        createLogin: canCreate,
        createCard: canCreate,
        createIdentity: canCreate,
      });
    },
    readLoginCopyValue: async (cipherId, field, bindFinalAuthority) => {
      if (field === 'totp') {
        return (await vault.getTotpCode(cipherId, undefined, bindFinalAuthority))?.code;
      }
      if (field === 'username') {
        return vault.getLoginUsernameForCopy(cipherId, bindFinalAuthority);
      }
      return vault.getField(cipherId, field, undefined, bindFinalAuthority);
    },
    generatePasswordAndTrack: (bindFinalAuthority) => (
      passwordGenerationAction.generatePasswordAndTrack(bindFinalAuthority)
    ),
    clipboard: {
      writeSecretAndScheduleClear: (value, assertCurrent) => (
        clipboard.writeSecretAndScheduleClear(value, assertCurrent)
      ),
      writeTotpAndScheduleClear: (value, assertCurrent) => (
        clipboard.writeTotpAndScheduleClear(value, assertCurrent)
      ),
    },
    createCipher: async (kind, source, assertCurrent) => {
      if (!await contextMenuSourceCurrent(source, assertCurrent)) {
        throw new AppError('denied', 'The context-menu source is stale.');
      }
      assertCurrent();
      await browser.action.openPopup();
      assertCurrent();
      if (!await contextMenuSourceCurrent(source, assertCurrent)) {
        throw new AppError('denied', 'The context-menu source changed while opening the editor.');
      }
      const intent = createContextMenuCreateIntent(kind, source.topUrl);
      for (let attempt = 0; attempt < 4; attempt += 1) {
        if (!await contextMenuSourceCurrent(source, assertCurrent)) {
          throw new AppError('denied', 'The context-menu source changed before editor delivery.');
        }
        try {
          const response = await browser.runtime.sendMessage(intent);
          assertCurrent();
          if (isContextMenuCreateAccepted(response)) return;
        } catch {
          assertCurrent();
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 25));
        assertCurrent();
      }
      throw new AppError('denied', 'The create editor could not be opened.');
    },
  },
  authorizeFrame: (frameUrl, action) => authorizeBackgroundAutofill(frameUrl, action),
  getFrame: async (tabId, frameId) => {
    const frame = await browser.webNavigation.getFrame({ tabId, frameId });
    return frame === null ? undefined : parseBrowserFrame(frame);
  },
  getRuntimeIncarnation: (tabId, frameId, documentId) => (
    saveCaptureCoordinator.getRuntimeIncarnation(tabId, frameId, documentId)
  ),
  continuation: {
    stageLockedContext: (source) => autofillContinuation.stageLockedContext(source),
    stageContextLoginReprompt: (source, cipherId, target) => (
      autofillContinuation.stageContextLoginReprompt(source, cipherId, target)
    ),
    stageContextStructuredReprompt: (source, input) => (
      autofillContinuation.stageContextStructuredReprompt(source, input)
    ),
    stageContextCopyReprompt: (source, cipherId, field) => (
      autofillContinuation.stageContextCopyReprompt(source, cipherId, field)
    ),
  },
  captureSessionLease: async () => sessionGate.capture(),
  isSessionLeaseCurrent: async (lease: SessionLease) => {
    try {
      sessionGate.assert(lease);
      return true;
    } catch {
      return false;
    }
  },
  assertSessionLease: (lease: SessionLease) => sessionGate.assert(lease),
  captureAccountLease: async () => accountGate.capture(),
  isAccountLeaseCurrent: async (lease) => {
    try {
      accountGate.assert(lease);
      return true;
    } catch {
      return false;
    }
  },
  assertAccountLease: (lease) => accountGate.assert(lease),
  vaultTimeout,
  vaultReleaseGate,
  menus: {
    removeAll: () => browser.contextMenus.removeAll(),
    create: (props) => { browser.contextMenus.create(props as Parameters<typeof browser.contextMenus.create>[0]); },
  },
  tabs: {
    sendMessage: async (tabId, message, options) => {
      const payload = message.type === 'autofill.fill' ? message.data : undefined;
      const response = await documentTabs.sendMessage(tabId, message, options);
      await structuredFillEvents.settle(payload, response);
      return response;
    },
  },
});
refreshContextMenu = () => contextMenu.refresh();
const idleLock = createIdleLock({
  getConfig: async () => {
    const effective = await readEffectiveVaultTimeout();
    return {
      idleSeconds: effective.idleSeconds,
      lockOnSystemLock: effective.lockOnSystemLock,
      action: effective.onIdleAction,
    };
  },
  isUnlocked: async () => (await auth.getState()) === 'unlocked',
  lock: () => vaultTimeout.handleSystemLocked(),
  logout: () => vaultTimeout.handleSystemLocked(),
  queryState: (seconds) => browser.idle.queryState(seconds) as Promise<'active' | 'idle' | 'locked'>,
  setDetectionInterval: (seconds) => browser.idle.setDetectionInterval(seconds),
});
const offscreenApi = (globalThis as unknown as { chrome?: {
  offscreen?: { createDocument(o: { url: string; reasons: string[]; justification: string }): Promise<void>; closeDocument(): Promise<void> };
  runtime?: { getContexts?(o: { contextTypes: string[] }): Promise<unknown[]> };
} }).chrome;

const clipboard = createClipboard({
  getClearSeconds: () => settings.getClipboardClearSeconds(),
  createAlarm: (name, scheduledTime) => browser.alarms.create(name, { when: scheduledTime }),
  clearAlarm: (name) => { void browser.alarms.clear(name); },
  now: () => Date.now(),
  ensureOffscreen: async () => {
    const ctx = (await offscreenApi?.runtime?.getContexts?.({ contextTypes: ['OFFSCREEN_DOCUMENT'] })) ?? [];
    if (ctx.length === 0) {
      try { await offscreenApi?.offscreen?.createDocument({
        url: 'offscreen.html',
        reasons: ['CLIPBOARD'],
        justification: 'Write worker-authorized secrets and clear only clipboard content still owned by the extension',
      }); }
      catch { /* already exists */ }
    }
  },
  sendOffscreen: (msg) => browser.runtime.sendMessage(msg),
  writeOffscreen: (msg) => browser.runtime.sendMessage(msg),
  closeOffscreen: async () => { try { await offscreenApi?.offscreen?.closeDocument(); } catch { /* none open */ } },
});
clearOwnedClipboardOnSessionTransition = () => clipboard.clearOwnedOnSessionTransition();
const autofillTotpCopies = new AutofillTotpCopyAckRegistry({
  writer: clipboard,
  onError: () => console.warn('autofill_totp_copy_failed'),
});
revokeAutofillTotpCopies = () => {
  autofillTotpCopies.revokeAll();
};

const tabAutofill = createTabAutofillCoordinator({
  getTab: async (tabId) => {
    const tab = await browser.tabs.get(tabId);
    return tab.url === undefined ? { active: tab.active } : { active: tab.active, url: tab.url };
  },
  // Only consulted for cross-origin frames; the active tab and same-origin frames are already
  // covered by the activeTab grant implied by `getTab` exposing a `url` at all. The raw frame URL
  // is normalized to an `${origin}/*` match pattern (Chrome rejects a full path/query URL as a
  // host pattern) and non-HTTP(S) URLs fail closed without ever calling into permissions.
  hasHostAccess: createHostAccessCheck((permissions) => browser.permissions.contains(permissions)),
  getFrames: async (tabId) => {
    const frames = await browser.webNavigation.getAllFrames({ tabId });
    return (frames ?? []).flatMap((frame) => {
      const parsed = parseBrowserFrame(frame);
      return parsed ? [parsed] : [];
    });
  },
  getFrame: async (tabId, frameId) => {
    const frame = await browser.webNavigation.getFrame({ tabId, frameId });
    return frame === null ? undefined : parseBrowserFrame(frame);
  },
  sendToFrame: (tabId, target, message) => documentTabs.sendMessage(tabId, message, target),
  authorizeFrame: (frameUrl, action) => authorizeBackgroundAutofill(frameUrl, action),
  findCandidates: (frameUrl, defaultStrategy) => vault.findAutofillCandidates(frameUrl, defaultStrategy),
  findFillItems: (kind) => vault.findFillItems(kind),
  getLoginData: (
    cipherId, frameUrl, defaultStrategy, customPlan, assertRepromptAuthorized, bindFinalAuthority,
  ) => (
    vault.getInteractiveAutofillLoginData(
      cipherId,
      frameUrl,
      defaultStrategy,
      customPlan,
      assertRepromptAuthorized,
      bindFinalAuthority,
    )
  ),
  getManualLoginData: (
    cipherId, frameUrl, defaultStrategy, customPlan, expected,
    assertRepromptAuthorized, bindFinalAuthority,
  ) => vault.getManualAutofillLoginData(
    cipherId,
    frameUrl,
    defaultStrategy,
    customPlan,
    expected,
    assertRepromptAuthorized,
    bindFinalAuthority,
  ),
  getFillData: (cipherId, kind, roles, assertRepromptAuthorized, bindFinalAuthority) => (
    vault.getFillData(
      cipherId,
      kind,
      roles,
      assertRepromptAuthorized,
      bindFinalAuthority,
    )
  ),
  getTotpData: (
    cipherId, frameUrl, defaultStrategy, bindFinalAuthority, assertRepromptAuthorized,
  ) => vault.getAutofillTotpData(
    cipherId,
    frameUrl,
    defaultStrategy,
    bindFinalAuthority,
    assertRepromptAuthorized,
  ),
  sessionGate,
  accountGate,
  vaultReleaseGate,
  clientEvents: clientEventActions,
  totpCopies: autofillTotpCopies,
  now: () => Date.now(),
});
const manualAutofill = createManualAutofillCoordinator({
  grants: manualAutofillGrants,
  repromptGrants: repromptAutofillGrants,
  tabAutofill,
  vault,
  sessionGate,
  accountGate,
  capturePolicy: () => captureAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates),
  assertPolicy: (lease) => { assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, lease); },
  authorizeSave: (url, lease) => authorizeManualAutofillSave(url, lease),
  verifyMasterPassword: (password) => auth.verifyMasterPassword(password),
});
const autofillPopupUrl = browser.runtime.getURL('ui/popup/popup.html');
const autofillContinuation = new AutofillContinuationCoordinator({
  store: autofillContinuationStore,
  getState: () => auth.getState(),
  sessionGate,
  accountGate,
  capturePolicy: () => captureAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates),
  assertPolicy: (lease) => { assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, lease); },
  workerInstanceId: autofillContinuationWorkerId,
  getStablePolicyDigest: async () => digestAutofillContinuationPolicy(
    await settings.getAutofillPolicySettings(),
  ),
  verifyMasterPassword: (password) => auth.verifyMasterPassword(password),
  getTab: async (tabId) => {
    const tab = await browser.tabs.get(tabId);
    if (tab.id === undefined || tab.windowId === undefined) return undefined;
    return {
      id: tab.id,
      windowId: tab.windowId,
      active: tab.active,
      ...(tab.url === undefined ? {} : { url: tab.url }),
    };
  },
  getFrame: async (tabId, frameId) => {
    const frame = await browser.webNavigation.getFrame({ tabId, frameId });
    return frame === null ? undefined : parseBrowserFrame(frame);
  },
  isRuntimeCurrent: (tabId, frameId, documentId, runtimeIncarnation) => (
    saveCaptureCoordinator.isRuntimeCurrent(tabId, frameId, documentId, runtimeIncarnation)
  ),
  getRuntimeIncarnation: (tabId, frameId, documentId) => (
    saveCaptureCoordinator.getRuntimeIncarnation(tabId, frameId, documentId)
  ),
  focusSource: async (windowId, tabId) => {
    await browser.windows.update(windowId, { focused: true });
    await browser.tabs.update(tabId, { active: true });
  },
  openPopup: async () => { await browser.action.openPopup(); },
  openPopupFallback: async () => {
    await browser.windows.create({
      url: autofillPopupUrl,
      type: 'popup',
      focused: true,
      width: 420,
      height: 680,
    });
  },
  isPopupDocumentOpen: async (documentId) => {
    const runtime = browser.runtime as unknown as {
      getContexts?: (filter: { documentUrls: string[] }) => Promise<Array<{ documentId?: string }>>;
    };
    if (!runtime.getContexts) return true;
    const contexts = await runtime.getContexts({ documentUrls: [autofillPopupUrl] });
    return contexts.some((context) => context.documentId === documentId);
  },
  sendToDocument: async (tabId, frameId, documentId, command) => {
    const payload = command.type === 'autofill.resumeHeldFillTarget'
      ? command.data
      : undefined;
    const response = await documentTabs.sendMessage(tabId, command, { frameId, documentId });
    await structuredFillEvents.settle(payload, response);
    return response;
  },
  sendFocusedFill: (tabId, commandToken) => (
    browser.tabs.sendMessage(tabId, { type: 'autofill.focusedFill', commandToken })
  ),
  runCommand: (command, tab, assertCurrent, expectedSource) => (
    runContinuedCommand(command, tab, assertCurrent, expectedSource)
  ),
  keyboardGrants,
  tabAutofill,
  getFillData: async (
    cipherId,
    kind,
    roles,
    assertRepromptAuthorized,
    bindFinalAuthority,
  ) => {
    const data = await vault.getFillData(
      cipherId,
      kind,
      roles,
      assertRepromptAuthorized,
      bindFinalAuthority,
    );
    await structuredFillEvents.prepare(cipherId, data);
    return data;
  },
  readLoginCopyValue: async (
    cipherId,
    field,
    assertRepromptAuthorized,
    bindFinalAuthority,
  ) => {
    if (field === 'totp') {
      return (await vault.getTotpCode(
        cipherId,
        undefined,
        bindFinalAuthority,
        assertRepromptAuthorized,
      ))?.code;
    }
    return vault.getField(
      cipherId,
      'password',
      undefined,
      bindFinalAuthority,
      assertRepromptAuthorized,
    );
  },
  clipboard: {
    writeSecretAndScheduleClear: (value, assertCurrent) => (
      clipboard.writeSecretAndScheduleClear(value, assertCurrent)
    ),
    writeTotpAndScheduleClear: (value, assertCurrent) => (
      clipboard.writeTotpAndScheduleClear(value, assertCurrent)
    ),
  },
  vaultReleaseGate,
  recordActivity: async () => {
    const lease = vaultTimeout.captureActivity();
    await vaultTimeout.recordActivity(lease);
  },
  now: () => Date.now(),
});

async function commandContinuationSource(
  source: {
    readonly tabId: number;
    readonly windowId: number;
    readonly documentId: string;
    readonly runtimeIncarnation: string;
    readonly url: string;
  },
  target?: {
    readonly frameId: number;
    readonly documentId: string;
    readonly runtimeIncarnation: string;
  },
) {
  if (!(await saveCaptureCoordinator.isRuntimeCurrent(
    source.tabId,
    0,
    source.documentId,
    source.runtimeIncarnation,
  ))) return undefined;
  if (!target || target.frameId === 0) {
    if (target && (target.documentId !== source.documentId
        || target.runtimeIncarnation !== source.runtimeIncarnation)) return undefined;
    return Object.freeze({
      tabId: source.tabId,
      windowId: source.windowId,
      topDocumentId: source.documentId,
      topRuntimeIncarnation: source.runtimeIncarnation,
      topUrl: source.url,
      frameId: 0,
      frameDocumentId: source.documentId,
      frameRuntimeIncarnation: source.runtimeIncarnation,
      frameUrl: source.url,
    });
  }
  const rawFrame = await browser.webNavigation.getFrame({ tabId: source.tabId, frameId: target.frameId });
  const frame = rawFrame === null ? undefined : parseBrowserFrame(rawFrame);
  if (!frame?.documentId || frame.documentId !== target.documentId) return undefined;
  if (!(await saveCaptureCoordinator.isRuntimeCurrent(
    source.tabId,
    frame.frameId,
    frame.documentId,
    target.runtimeIncarnation,
  ))) return undefined;
  return Object.freeze({
    tabId: source.tabId,
    windowId: source.windowId,
    topDocumentId: source.documentId,
    topRuntimeIncarnation: source.runtimeIncarnation,
    topUrl: source.url,
    frameId: frame.frameId,
    frameDocumentId: frame.documentId,
    frameRuntimeIncarnation: target.runtimeIncarnation,
    frameUrl: frame.url,
  });
}

async function contextMenuSourceCurrent(
  source: AutofillContinuationBrowserSource,
  assertCurrent: () => void,
): Promise<boolean> {
  try {
    assertCurrent();
    const [tab, rawTop, rawFrame, topRuntimeCurrent, frameRuntimeCurrent] = await Promise.all([
      browser.tabs.get(source.tabId),
      browser.webNavigation.getFrame({ tabId: source.tabId, frameId: 0 }),
      source.frameId === 0
        ? browser.webNavigation.getFrame({ tabId: source.tabId, frameId: 0 })
        : browser.webNavigation.getFrame({ tabId: source.tabId, frameId: source.frameId }),
      saveCaptureCoordinator.isRuntimeCurrent(
        source.tabId,
        0,
        source.topDocumentId,
        source.topRuntimeIncarnation,
      ),
      saveCaptureCoordinator.isRuntimeCurrent(
        source.tabId,
        source.frameId,
        source.frameDocumentId,
        source.frameRuntimeIncarnation,
      ),
    ]);
    assertCurrent();
    const top = rawTop === null ? undefined : parseBrowserFrame(rawTop);
    const frame = rawFrame === null ? undefined : parseBrowserFrame(rawFrame);
    return tab.id === source.tabId
      && tab.windowId === source.windowId
      && tab.active === true
      && tab.url === source.topUrl
      && top?.frameId === 0
      && top.documentId === source.topDocumentId
      && top.url === source.topUrl
      && frame?.frameId === source.frameId
      && frame.documentId === source.frameDocumentId
      && frame.url === source.frameUrl
      && topRuntimeCurrent
      && frameRuntimeCurrent;
  } catch {
    return false;
  }
}

function isContextMenuCreateAccepted(value: unknown): value is { readonly accepted: true } {
  return typeof value === 'object'
    && value !== null
    && !Array.isArray(value)
    && Reflect.ownKeys(value).length === 1
    && Object.getOwnPropertyDescriptor(value, 'accepted')?.value === true;
}

const commandCoordinator = new CommandCoordinator<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>({
  tabs: { sendMessage: (tabId, message) => browser.tabs.sendMessage(tabId, message) },
  getTopDocument: getKeyboardTopDocument,
  getState: () => auth.getState(),
  captureSessionLease: () => {
    const lease = sessionGate.capture();
    if (!lease) throw new AppError('locked', 'Vault is locked.');
    return lease;
  },
  assertSessionLease: (lease) => sessionGate.assert(lease),
  beginLocked: (input) => autofillContinuation.stageLockedKeyboard(input),
  captureAccountLease: () => accountGate.capture(),
  assertAccountLease: (lease) => accountGate.assert(lease),
  capturePolicyLease: () => captureAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates),
  assertPolicyLease: (lease) => {
    assertAutofillAuthorizationPolicy(autofillAuthorizationPolicyGates, lease);
  },
  keyboardGrants,
  authorizeFrame: (frameUrl) => authorizeBackgroundAutofill(frameUrl, 'intent'),
  getTabSuggestions: (tabId) => tabAutofill.getSuggestions(tabId),
  fillTabSuggestion: (tabId, cipherId, target, assertCurrent) => (
    tabAutofill.fill(tabId, cipherId, target, assertCurrent)
  ),
  generatePasswordAndTrack: (bindFinalAuthority) => (
    passwordGenerationAction.generatePasswordAndTrack(bindFinalAuthority)
  ),
  clipboard: {
    writeSecretAndScheduleClear: (value, assertCurrent) => (
      clipboard.writeSecretAndScheduleClear(value, assertCurrent)
    ),
  },
  lockVault: () => auth.lock(),
  openPopup: () => browser.action.openPopup(),
  continuation: {
    stageLockedCommand: async (command, source) => {
      const continuationSource = await commandContinuationSource(source);
      if (!continuationSource) throw new AppError('denied', 'The command source is stale.');
      await autofillContinuation.stageLockedCommand(command, continuationSource);
    },
    stageRepromptCommand: async (input) => {
      const continuationSource = await commandContinuationSource(input.source, input.target);
      if (!continuationSource) throw new AppError('denied', 'The command source is stale.');
      await autofillContinuation.stageCommandFillReprompt(continuationSource, {
        command: input.command,
        cipherId: input.cipherId,
        target: input.target,
      });
    },
  },
  vaultReleaseGate,
  recordActivity: async () => {
    const lease = vaultTimeout.captureActivity();
    await vaultTimeout.recordActivity(lease);
  },
});
runContinuedCommand = (command, tab, assertCurrent, expectedSource) => commandCoordinator.handle(
  command,
  tab,
  assertCurrent,
  expectedSource,
);
revokeCommandCycles = () => commandCoordinator.revokeAll();

const httpAuthBroker = new HttpAuthBroker({
  ready: async () => { await securityReady; },
  readHttpAuthSettings: () => httpAuthSettings.get(),
  authorizeFrame: (url, action) => authorizeBackgroundAutofill(url, action),
  captureSessionLease: () => sessionGate.capture(),
  assertSessionLease: (lease) => sessionGate.assert(lease),
  captureAccountLease: () => accountGate.capture(),
  assertAccountLease: (lease) => accountGate.assert(lease),
  vaultReleaseGate,
  getHttpAuthLoginData: (url, defaultStrategy, bindFinalAuthority) => (
    vault.getHttpAuthLoginData(url, defaultStrategy, bindFinalAuthority)
  ),
  tombstones: httpAuthTombstones,
});

const interactiveTwoFactorBrowser = new InteractiveTwoFactorBrowser({
  tabs: {
    create: (input) => browser.tabs.create(input),
    remove: (tabId) => browser.tabs.remove(tabId),
  },
  webNavigation: {
    getFrame: async ({ tabId, frameId }) => {
      const frame = await browser.webNavigation.getFrame({ tabId, frameId });
      if (!frame) return null;
      const documentId = (frame as unknown as { readonly documentId?: unknown }).documentId;
      return typeof documentId === 'string'
        ? { url: frame.url, documentId }
        : { url: frame.url };
    },
    onCommitted: browser.webNavigation.onCommitted as unknown as (
      InteractiveTwoFactorBrowserDeps['webNavigation']['onCommitted']
    ),
  },
});
closeInteractiveTwoFactorConnector = async (document): Promise<void> => {
  await interactiveTwoFactorBrowser.closeAfterSettlement(document).catch((error: unknown) => {
    console.warn('fido2_connector_cleanup_failed', error);
    return false;
  });
};
const fido2Connector = {
  open: (url: string, replace?: InteractiveTwoFactorConnectorDocument) => (
    interactiveTwoFactorBrowser.open(url, replace)
  ),
  close: (document: InteractiveTwoFactorConnectorDocument) => (
    interactiveTwoFactorBrowser.close(document)
  ),
  async finish(
    document: InteractiveTwoFactorConnectorDocument,
    outcome: 'success' | 'error',
  ): Promise<void> {
    await closeInteractiveTwoFactorConnector(document);
    const popup = new URL(browser.runtime.getURL('ui/popup/popup.html'));
    popup.searchParams.set('fido2', outcome);
    await browser.windows.create({
      url: popup.toString(),
      type: 'popup',
      focused: true,
      width: 420,
      height: 680,
    });
  },
};

const websitePasskeySecurity = createWebsitePasskeySecurityAdapter({
  sessionGate,
  accountGate,
  enterprisePolicyGate,
  serverCapabilities,
  websitePolicyGate: websitePasskeyPolicyGate,
  permissionGate: websitePasskeyPermissionGate,
  documentGate: websitePasskeyDocumentGate,
  session,
});
const websitePasskeyAvailability = createWebsitePasskeyAvailabilityAdapter({
  accountGate,
  websitePolicyGate: websitePasskeyPolicyGate,
  permissionGate: websitePasskeyPermissionGate,
  documentGate: websitePasskeyDocumentGate,
  session,
});
const websitePasskeyVault = createWebsitePasskeyVaultAdapter(vault);
const websitePasskeyRegistry = new PasskeyCeremonyRegistry({ store: sessionStore });
const websitePasskeyLockedContinuations = new WebsitePasskeyLockedContinuationStore({
  store: sessionStore,
});
const websitePasskeys = new WebsitePasskeyCoordinator({
  registry: websitePasskeyRegistry,
  security: websitePasskeySecurity,
  availability: websitePasskeyAvailability,
  lockedContinuations: websitePasskeyLockedContinuations,
  vault: websitePasskeyVault,
  extensionBaseUrl: browser.runtime.getURL(''),
  windows: {
    async open(url) {
      const approvalWindow = await browser.windows.create({
        url,
        type: 'popup',
        focused: true,
        width: 420,
        height: 680,
      });
      if (approvalWindow.id === undefined) throw new Error('Browser did not return an approval window id');
      return approvalWindow.id;
    },
    close: (windowId) => browser.windows.remove(windowId),
    isOpen: async (windowId) => {
      try { return (await browser.windows.get(windowId)).id === windowId; }
      catch { return false; }
    },
  },
  excludeOrigin: async (origin) => {
    const parsed = new URL(origin);
    if (parsed.origin !== origin) throw new Error('Website passkey origin is not canonical');
    await settings.addWebsitePasskeyExcludedDomain(parsed.hostname);
  },
});

const router = createRouter({
  auth,
  logout: logoutWithClientEvents,
  vault,
  generatorHistory,
  settings,
  httpAuthSettings,
  sessionGate,
  accountGate,
  vaultTimeout,
  vaultReleaseGate,
  autofillPolicyGate,
  autofillIntents,
  pendingSaves,
  saveCaptureCoordinator,
  loadPendingSaveUserKey: loadOwnedAutofillStorageUserKey,
  keyboardGrants,
  getKeyboardTopDocument,
  getContentDocument: async (tabId, frameId) => {
    const frame = await browser.webNavigation.getFrame({ tabId, frameId });
    const parsed = frame === null ? undefined : parseBrowserFrame(frame);
    return parsed?.documentId
      ? { documentId: parsed.documentId, url: parsed.url }
      : undefined;
  },
  usernameStages,
  getSessionBindingId: async () => (await session.getActiveAuth())?.sessionBindingId,
  pageLoadFillDeduper,
  enterprisePolicyGate,
  exportGrants: vaultExportGrants,
  repromptAutofillGrants,
  manualAutofill,
  autofillContinuation,
  clientEvents: {
    ...clientEventActions,
    flushActive: () => clientEventRuntime.flushActive(),
    captureAccountRemoval: (accountIdentity) => (
      clientEventRuntime.captureAccountRemoval(accountIdentity)
    ),
    completeAccountRemoval: (receipt) => clientEventRuntime.completeAccountRemoval(receipt),
    captureServerChange: (serverUrl) => clientEventRuntime.captureServerChange(serverUrl),
    completeServerChange: (receipt) => clientEventRuntime.completeServerChange(receipt),
    supportsOrganizationDecline: supportsOrganizationDeclineEvents,
  },
  clientEventAcks,
  autofillTotpCopies,
  inlineGeneratorTracks,
  syncScheduler: transferAwareSyncScheduler,
  clipboard: {
    scheduleClear: (value) => clipboard.scheduleClear(value),
    cancelClear: () => clipboard.cancelClear(),
  },
  tabAutofill,
  fido2Connector,
  interactiveTwoFactor: {
    password: auth.interactiveTwoFactor,
    deviceLogin: deviceLoginCoordinator.interactiveTwoFactor,
  },
  accountPasskey: accountPasskeyBrowser,
  sso,
  duo,
  ssoRequirement: { isRequired: (email) => isSsoRequiredForCurrentServer(email) },
  websitePasskeys,
  websitePasskeyPermissionsPolicy,
  deviceLogin: deviceLoginCoordinator,
  deviceLoginApprovals,
  twoFactorRecovery: {
    async open(): Promise<void> {
      const authorization = await authorizeTwoFactorRecovery(preLoginServerCapabilities);
      authorization.assertCurrent();
      await browser.tabs.create({ url: authorization.url, active: true });
    },
  },
  onDeviceLoginApprovalDecision: () => refreshDeviceLoginApprovalBadge(),
  onDeviceLoginApprovalPopupOpened: () => deviceLoginApprovalSystemNotifications.popupOpened(),
});

browser.idle.onStateChanged.addListener((state) => {
  void securityReady
    .then(() => idleLock.onStateChanged(state as 'active' | 'idle' | 'locked'))
    .catch(() => {});
});

// Recreate the idle-lock backstop alarm if a prior worker eviction dropped it. onInstalled seeds it
// on first install; this covers every cold SW start, and onStartup covers browser restarts.
const idleAlarmScheduler = {
  get: (name: string) => browser.alarms.get(name),
  create: (name: string, options: { periodInMinutes: number }) => { browser.alarms.create(name, options); },
};

async function restoreDeviceLoginRuntime(initialState: SessionState): Promise<void> {
  await restoreDeviceLoginProductionRuntime(initialState, {
    getAuthState: () => auth.getState(),
    startupRequester: () => deviceLoginCoordinator.startup(),
    cancelRequester: () => deviceLoginCoordinator.cancelCurrent(),
    badge: deviceLoginApprovalBadge,
    systemNotifications: deviceLoginApprovalSystemNotifications,
    logger: { warn: (event) => console.warn(`device_login_${event}`) },
  });
}

async function handleDeviceLoginAlarm(alarm: { name: string; scheduledTime?: number }): Promise<void> {
  try {
    if (alarm.name === DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM) {
      await deviceLoginApprovalSystemNotifications.handleAlarm(alarm);
    } else {
      await deviceLoginCoordinator.handleAlarm(alarm);
    }
  } catch {
    console.warn('device_login_alarm_failed');
  }
}

async function recoverCloseLogoutOnStartup(): Promise<void> {
  await recoverVaultTimeoutBrowserSession(vaultTimeoutState, {
    getServerUrl: () => settings.getServerUrl(),
    listAccountEmails: async () => (await session.listAccounts()).map((account) => account.email),
    removeAccount: (email) => session.removeAccount(email),
    resetAllAccounts: () => session.resetAllAccounts(),
    clearDerivedState: () => vault.clearCache(),
  });
}

// Only invariants required before privileged messages belong in this gate. Menu rendering and
// maintenance alarms are recoverable conveniences: a missing first-sync cache must never disable
// login, sync, logout, or settings for the entire worker lifetime.
const securityReady = (async (): Promise<SessionState> => {
  await hardenStorageAccessLevels();
  await contextMenu.clearDerivedState();
  return recoverPendingPasswordChangeOnStartup(
    passwordChangePending,
    {
      removeAccount: async (identity) => {
        const configuredServer = await settings.getServerUrl();
        if (!configuredServer || new URL(configuredServer).toString() !== identity.serverUrl) return;
        await session.removeAccount(identity.accountId);
      },
      resetAllAccounts: () => session.resetAllAccounts(),
      clearVaultCache: () => vault.clearCache(),
    },
  ).then(() => initializeAfterPendingRotationRecovery(
    rotationPending,
    {
      resetAllAccounts: () => session.resetAllAccounts(),
      clearVaultCache: () => vault.clearCache(),
      clearGeneratorHistoryForServer: (serverUrl) => (
        generatorHistory.removeServerScopes(serverUrl).then(() => undefined)
      ),
      clearClientEvents: (identity) => clearClientEventsForServer(identity.serverUrl),
    },
    async () => {
      if (await session.recoverInvalidAccountRegistry()) await vault.clearCache();
      await recoverCloseLogoutOnStartup();
      await session.initialize();
      await reconcileClientEventLogoutMarkers();
      await reconcileGeneratorHistoryRegistry().catch(() => {
        console.warn('generator_history_startup_reconcile_failed');
      });
      await reconcileGlobalLocalCloseLogoutOwners();
      const [serverUrl, persistedAuth, state] = await Promise.all([
        settings.getServerUrl(),
        session.getPersistedAuth(),
        auth.getState(),
      ]);
      if (serverUrl) {
        accountGate.initialize({
          serverUrl,
          ...(persistedAuth
            ? { accountIdentity: persistedAuth.email.trim().toLowerCase() }
            : {}),
        });
      }
      sessionGate.initialize(state);
      if (state !== 'unlocked') {
        await saveCaptureCoordinator.clear();
        await pendingSaves.clear();
      }
      await sso.reconcileRestart();
      await duo.reconcileRestart();
      await vault.initializeCache();
      return initializeVaultTimeoutAndReadFreshState(vaultTimeout, () => auth.getState());
    },
  ));
})();
// Reconcile only after security initialization resolves. A confirmed capture wakes content, whose
// claim request itself waits for securityReady; awaiting that wake inside initialization deadlocks.
void securityReady
  .then((state) => state === 'unlocked'
    ? Promise.all([saveCaptureCoordinator.reconcile(), pendingSaves.reconcile()]).then(() => undefined)
    : undefined)
  .catch(() => console.warn('autofill_save_capture_startup_reconcile_failed'));
const httpAuthBrowserRegistered = registerHttpAuthBrowserListeners(
  (globalThis as unknown as { chrome?: HttpAuthChromeApi }).chrome,
  httpAuthBroker,
);
if (!httpAuthBrowserRegistered) console.warn('http_auth_listener_unavailable');
const saveCaptureBrowserRegistered = registerAutofillSaveCaptureBrowserListeners(
  (globalThis as unknown as { chrome?: AutofillSaveCaptureChromeApi }).chrome,
  saveCaptureCoordinator,
  { warn: (event) => console.warn(`autofill_save_capture_${event}_failed`) },
);
if (!saveCaptureBrowserRegistered) console.warn('autofill_save_capture_listener_unavailable');
const transferReady = createVaultTransferReadiness(securityReady, vaultTransferLifecycle);
const vaultTransferPortHandler = new VaultTransferPortHandler(
  vaultTransferController,
  transferReady,
  vaultReleaseGate,
  issuePersonalExportClientEventAck,
  issueOrganizationExportClientEventAck,
);
const websitePasskeyPortHandler = new WebsitePasskeyPortHandler(
  websitePasskeys,
  securityReady.then(() => undefined),
  Date.now,
  async (document) => {
    if (await websitePasskeyDocumentGate.isCurrent(document)) return;
    websitePasskeyDocumentGate.invalidateFrame(document.tabId, document.frameId);
    await websitePasskeys.handleBrowserDocumentChange(document.tabId);
  },
  vaultReleaseGate,
);
const backgroundPortDispatcher = createBackgroundPortDispatcher<Runtime.Port>({
  extensionBaseUrl: browser.runtime.getURL(''),
  extensionId: browser.runtime.id,
  vaultTransferHandler: vaultTransferPortHandler as unknown as BackgroundPortHandler<Runtime.Port>,
  websitePasskeyHandler: websitePasskeyPortHandler as unknown as BackgroundPortHandler<Runtime.Port>,
});
browser.runtime.onConnect.addListener(backgroundPortDispatcher);
void securityReady.then(async (state) => {
  await Promise.allSettled([
    initializeToolbar(state),
    contextMenu.refresh(),
    idleLock.applyDetection(),
    ensureIdleLockAlarm(idleAlarmScheduler),
    vaultSyncScheduler.startup(),
    vaultNotificationRuntime.startup(state),
    restoreDeviceLoginRuntime(state),
    accountPasskeyBrowser.startup(),
    pendingLoginStore.ensureExpirationAlarm(),
    reconcileWebsitePasskeyStartup(state),
    reconcileClientEventRuntime(state),
  ]);
}).catch((error: unknown) => {
  console.error('extension security initialization failed', error);
});

browser.runtime.onStartup.addListener(() => {
  void securityReady.then(async (state) => {
    await Promise.allSettled([
      initializeToolbar(state),
      vaultSyncScheduler.startup(),
      vaultNotificationRuntime.startup(state),
      restoreDeviceLoginRuntime(state),
      accountPasskeyBrowser.startup(),
      pendingLoginStore.ensureExpirationAlarm(),
      reconcileWebsitePasskeyStartup(state),
      reconcileClientEventRuntime(state),
    ]);
  }).catch(() => {});
});

browser.notifications.onClicked.addListener((notificationId) => (
  securityReady
    .then(() => deviceLoginApprovalSystemNotifications.handleClick(notificationId))
    .catch(() => undefined)
));

browser.windows.onRemoved.addListener((windowId) => {
  void websitePasskeys.handleWindowClosed(windowId).catch(() => {});
});
browser.windows.onFocusChanged.addListener((windowId) => {
  if (!Number.isSafeInteger(windowId) || windowId < 0) {
    void renderToolbar();
    return;
  }
  void securityReady
    .then(() => browser.tabs.query({ active: true, windowId }))
    .then((tabs) => Promise.allSettled(tabs.flatMap((tab) => (
      tab.id === undefined || tab.url === undefined
        ? []
        : [toolbarMatchCounter.refresh(
            { id: tab.id, url: tab.url },
            toolbarAuthState,
            toolbarShowMatchingLoginCount,
          )]
    ))))
    .catch(() => undefined);
});

const handleWebsitePasskeyDocumentNavigation = (
  details: { tabId: number; frameId: number; url?: string; documentId?: unknown },
  sameDocument: boolean,
): void => {
  if (!Number.isSafeInteger(details.tabId) || details.tabId < 0
    || !Number.isSafeInteger(details.frameId) || details.frameId < 0) return;
  if (typeof details.documentId === 'string' && typeof details.url === 'string') {
    const navigation = {
      tabId: details.tabId,
      frameId: details.frameId,
      documentId: details.documentId,
      url: details.url,
    };
    if (sameDocument) websitePasskeyDocumentGate.recordSameDocumentNavigation(navigation);
    else websitePasskeyDocumentGate.recordCommittedNavigation(navigation);
  } else {
    websitePasskeyDocumentGate.invalidateFrame(details.tabId, details.frameId);
  }
  manualAutofillGrants.revokeAll();
  autofillTotpCopies.revokeTab(details.tabId);
  inlineGeneratorTracks.revokeTab(details.tabId);
  keyboardGrants.revokeAll();
  commandCoordinator.revokeTab(details.tabId);
  if (details.frameId === 0) {
    toolbarMatches.delete(details.tabId);
    void securityReady
      .then(() => refreshToolbarTab(details.tabId))
      .catch(() => undefined);
  }
  void autofillContinuation.revokeTab(details.tabId);
  void websitePasskeys.handleBrowserDocumentChange(details.tabId).catch(() => {});
};
browser.webNavigation.onCommitted.addListener((details) => {
  handleWebsitePasskeyDocumentNavigation(details, false);
});
browser.webNavigation.onCommitted.addListener((details) => {
  const documentId = (details as typeof details & { readonly documentId?: unknown }).documentId;
  void saveCaptureCoordinator.noteDocumentNavigation(
    details.tabId,
    details.frameId,
    typeof documentId === 'string' ? documentId : undefined,
  ).catch(() => console.warn('autofill_runtime_navigation_fence_failed'));
  const navigation = {
    tabId: details.tabId,
    frameId: details.frameId,
    ...(typeof documentId === 'string' ? { documentId } : {}),
    url: details.url,
  };
  void securityReady
    .then(() => Promise.all([
      sso.handleNavigation(navigation),
      duo.handleNavigation(navigation),
    ]))
    .catch(() => undefined);
});
browser.webNavigation.onHistoryStateUpdated.addListener((details) => {
  handleWebsitePasskeyDocumentNavigation(details, true);
});
browser.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
  handleWebsitePasskeyDocumentNavigation(details, true);
});
browser.tabs.onActivated.addListener((activeInfo) => {
  manualAutofillGrants.revokeAll();
  toolbarMatches.delete(activeInfo.tabId);
  void securityReady
    .then(() => refreshToolbarTab(activeInfo.tabId))
    .catch(() => undefined);
});

browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (typeof changeInfo.url !== 'string' || !tab.active) return;
  toolbarMatches.delete(tabId);
  void securityReady
    .then(() => refreshToolbarTab(tabId))
    .catch(() => undefined);
});

browser.tabs.onRemoved.addListener((tabId) => {
  clientEventAcks.revokeTab(tabId);
  autofillTotpCopies.revokeTab(tabId);
  inlineGeneratorTracks.revokeTab(tabId);
  manualAutofillGrants.revokeAll();
  keyboardGrants.revokeAll();
  commandCoordinator.revokeTab(tabId);
  toolbarMatchCounter.revokeTab(tabId);
  void autofillContinuation.revokeTab(tabId);
  websitePasskeyDocumentGate.invalidateTab(tabId);
  void Promise.allSettled([
    usernameStages.clearTab(tabId),
    pendingSaves.clearTab(tabId),
    saveCaptureCoordinator.clearTab(tabId),
    accountPasskeyBrowser.handleTabRemoved(tabId),
    sso.handleTabRemoved(tabId),
    duo.handleTabRemoved(tabId),
    websitePasskeys.handleBrowserDocumentChange(tabId),
  ]);
});
browser.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
  clientEventAcks.revokeTab(removedTabId);
  clientEventAcks.revokeTab(addedTabId);
  autofillTotpCopies.revokeTab(removedTabId);
  autofillTotpCopies.revokeTab(addedTabId);
  inlineGeneratorTracks.revokeTab(removedTabId);
  inlineGeneratorTracks.revokeTab(addedTabId);
  keyboardGrants.revokeAll();
  commandCoordinator.revokeTab(removedTabId);
  commandCoordinator.revokeTab(addedTabId);
  toolbarMatchCounter.revokeTab(removedTabId);
  toolbarMatchCounter.revokeTab(addedTabId);
  websitePasskeyDocumentGate.invalidateTab(removedTabId);
  websitePasskeyDocumentGate.invalidateTab(addedTabId);
  void Promise.all([
    autofillContinuation.revokeTab(removedTabId),
    autofillContinuation.revokeTab(addedTabId),
    usernameStages.clearTab(removedTabId),
    usernameStages.clearTab(addedTabId),
    pendingSaves.clearTab(removedTabId),
    pendingSaves.clearTab(addedTabId),
    saveCaptureCoordinator.clearTab(removedTabId),
    saveCaptureCoordinator.clearTab(addedTabId),
    websitePasskeys.handleBrowserDocumentChange(removedTabId),
    websitePasskeys.handleBrowserDocumentChange(addedTabId),
    refreshToolbarTab(addedTabId),
  ]);
});

const handleWebsitePasskeyPermissionChange = (): void => {
  websitePasskeyPermissionGate.invalidate();
  websitePasskeyLifecycle.invalidate();
  void securityReady
    .then(() => auth.getState())
    .then((state) => websitePasskeyLifecycle.reconcile(state))
    .then(() => websitePasskeys.handleAuthorizationChange())
    .catch((error: unknown) => {
      console.error('website passkey permission refresh failed', error);
    });
  revokeToolbarMatches();
  void refreshToolbarActiveTabs();
};
browser.permissions.onAdded.addListener(handleWebsitePasskeyPermissionChange);
browser.permissions.onRemoved.addListener(handleWebsitePasskeyPermissionChange);

browser.contextMenus.onClicked.addListener((info, tab) => {
  // Capture before awaiting worker initialization so a later right-click cannot steal this target.
  const contextMenuClickTime = absoluteMonotonicNow();
  const clickedFrameUrl = info.frameUrl ?? info.pageUrl;
  const frameId = info.frameId;
  if (typeof frameId !== 'number' || typeof clickedFrameUrl !== 'string') return;
  void securityReady
    .then(() => contextMenu.handleClick(String(info.menuItemId), tab, frameId, clickedFrameUrl, contextMenuClickTime))
    .catch(() => {});
});

const rawContextMenus = (globalThis as unknown as { chrome?: {
  contextMenus?: {
    onShown?: { addListener(listener: (info: unknown, tab?: { id?: number }) => void): void };
    refresh?: () => void | Promise<void>;
  };
} }).chrome?.contextMenus;
rawContextMenus?.onShown?.addListener((_info, tab) => {
  if (typeof tab?.id !== 'number') return;
  void securityReady
    .then(() => contextMenu.refresh(tab.id))
    .then(() => rawContextMenus.refresh?.())
    .catch(() => {});
});

function absoluteMonotonicNow(): number {
  const now = performance.timeOrigin + performance.now();
  return Number.isFinite(now) ? now : Date.now();
}

browser.commands.onCommand.addListener((command, tab) => {
  void securityReady.then(() => commandCoordinator.handle(command, tab)).catch(() => undefined);
});

browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
  void hardenStorageAccessLevels().catch((error: unknown) => {
    console.error('storage access hardening failed', error);
  });
  void securityReady.then(() => contextMenu.refresh()).catch(() => {});
  void idleLock.applyDetection();
});

function websitePasskeySettingsFingerprint(value: unknown): string {
  if (value === undefined) return 'absent';
  try {
    const sanitized = sanitizeWebsitePasskeySettings(value);
    return `valid:${JSON.stringify([
      sanitized.schemaVersion,
      sanitized.enabled,
      sanitized.excludedDomains,
    ])}`;
  } catch {
    return 'invalid';
  }
}

async function reconcileWebsitePasskeyStartup(state: SessionState): Promise<void> {
  await websitePasskeyLifecycle.reconcile(state);
  const current = await settings.getWebsitePasskeySettings();
  handledWebsitePasskeySettingsFingerprint = websitePasskeySettingsFingerprint(current);
}

async function runWebsitePasskeyPolicyMutation(
  operation: () => Promise<ResponseMessage>,
): Promise<ResponseMessage> {
  const epoch = ++websitePasskeyPolicyMutationEpoch;
  websitePasskeyPolicyMutationsInFlight += 1;
  websitePasskeyLifecycle.invalidate();
  let response: ResponseMessage;
  let refreshFailed = false;
  try {
    response = await operation();
  } finally {
    try {
      do {
        if (epoch !== websitePasskeyPolicyMutationEpoch) break;
        websitePasskeyStorageRefreshPending = false;
        try {
          const current = await settings.getWebsitePasskeySettings();
          await websitePasskeyLifecycle.reconcile(await auth.getState());
          await websitePasskeys.handleAuthorizationChange();
          handledWebsitePasskeySettingsFingerprint = websitePasskeySettingsFingerprint(current);
        } catch (error) {
          refreshFailed = true;
          console.error('website passkey policy mutation refresh failed', error);
        }
      } while (websitePasskeyStorageRefreshPending);
    } finally {
      websitePasskeyPolicyMutationsInFlight -= 1;
    }
  }
  if (refreshFailed && response.ok) {
    return {
      ok: false,
      error: {
        code: 'error',
        message: 'Website passkey settings were saved, but browser integration could not be refreshed.',
      },
    };
  }
  return response;
}

browser.runtime.onMessage.addListener((message: unknown, sender: Runtime.MessageSender) => {
  const type = typeof message === 'object' && message !== null
    ? (message as { type?: unknown }).type
    : undefined;
  // Do not hijack the offscreen document's own responses.
  if (typeof type === 'string'
      && (type.startsWith('offscreen.') || type === 'contextMenu.openCreateCipher')) {
    return; // synchronous return, no Promise
  }
  const context = createRequestContext(sender, browser.runtime.getURL(''), browser.runtime.id);
  return (async () => {
    try {
      await securityReady;
    } catch {
      return { ok: false, error: { code: 'error', message: 'Extension security initialization failed' } };
    }
    if (typeof type !== 'string' || !context || !isMessageAllowed(type, context)) {
      return { ok: false, error: { code: 'denied', message: 'sender not permitted' } };
    }
    const capturesTimeoutSetting = type === 'settings.saveSecurity'
      || (type === 'settings.save' && Object.hasOwn(message as object, 'lockTimeout'));
    const timeoutSettingsBefore = capturesTimeoutSetting
      ? await Promise.all([settings.getLockTimeout(), settings.getOnIdleAction()])
      : undefined;
    const requested = message as Partial<RequestMessage> & {
      onIdleAction?: unknown;
      lockTimeout?: unknown;
    };
    const tightensTokenStorage = Boolean(timeoutSettingsBefore
      && (
        (type === 'settings.saveSecurity'
          && requested.onIdleAction === 'logout'
          && timeoutSettingsBefore[0] !== 'never')
        || (type === 'settings.save'
          && requested.lockTimeout !== undefined
          && requested.lockTimeout !== 'never'
          && timeoutSettingsBefore[1] === 'logout')
      ));
    // Tighten before the setting write so a worker/browser interruption cannot leave an effective
    // logout policy with tokens still persisted in local storage. A rejected write is conservative.
    let tokenStorageMove: TokenStorageMoveReceipt | undefined;
    if (tightensTokenStorage) {
      try {
        tokenStorageMove = await session.moveAllTokensToSession();
      } catch {
        await vaultTimeout.failClosed();
        return {
          ok: false,
          error: { code: 'error', message: 'Vault timeout token storage could not be tightened' },
        };
      }
    }
    const route = () => router.handle(message as RequestMessage, context);
    const response = type === 'settings.saveWebsitePasskeys' || type === 'websitePasskey.fallbackAlways'
      ? await runWebsitePasskeyPolicyMutation(route)
      : await route();
    if (tokenStorageMove) {
      try {
        const persisted = await Promise.all([
          settings.getLockTimeout(),
          settings.getOnIdleAction(),
        ]);
        if (!isLocalCloseLogoutEnabled(persisted[0], persisted[1])) {
          await session.rollbackTokenStorageMove(tokenStorageMove);
        }
      } catch {
        await vaultTimeout.failClosed();
        return {
          ok: false,
          error: { code: 'error', message: 'Vault timeout token storage could not be finalized' },
        };
      }
    }
    if (shouldRefreshMenu(type)) void contextMenu.refresh().catch(() => {});
    try {
      await refreshVaultTimeoutSettingsAfterWrite({
        readPersistedSettings: () => Promise.all([
          settings.getLockTimeout(),
          settings.getOnIdleAction(),
        ]),
        reconcileOwners: reconcileGlobalLocalCloseLogoutOwners,
        controller: vaultTimeout,
        applyIdleDetection: () => idleLock.applyDetection(),
      }, {
        before: timeoutSettingsBefore,
        timeoutSettingsRequest: capturesTimeoutSetting,
      });
    } catch {
      return { ok: false, error: { code: 'error', message: 'Vault timeout enforcement could not be refreshed' } };
    }
    if (type === 'settings.save') {
      const request = message as Partial<RequestMessage> & { autofillSettings?: unknown; defaultUriMatchStrategy?: unknown };
      if (request.autofillSettings !== undefined || request.defaultUriMatchStrategy !== undefined) {
        void refreshAutofillClients().catch(() => {});
      }
    }
    return response;
  })();
});

browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;
  if (changes[SHOW_MATCHING_LOGIN_COUNT_KEY]) {
    const revision = ++toolbarSettingsRevision;
    void settings.getShowMatchingLoginCount()
      .then(async (enabled) => {
        if (revision !== toolbarSettingsRevision) return;
        toolbarShowMatchingLoginCount = enabled;
        revokeToolbarMatches();
        await refreshToolbarActiveTabs();
      })
      .catch(() => undefined);
  }
  if (changes.websitePasskeySettings) {
    const nextFingerprint = websitePasskeySettingsFingerprint(
      changes.websitePasskeySettings.newValue,
    );
    if (nextFingerprint !== handledWebsitePasskeySettingsFingerprint) {
      websitePasskeyLifecycle.invalidate();
      if (websitePasskeyPolicyMutationsInFlight > 0) {
        websitePasskeyStorageRefreshPending = true;
      } else {
        const refreshEpoch = ++websitePasskeyPolicyMutationEpoch;
        void securityReady
          .then(async () => {
            if (refreshEpoch !== websitePasskeyPolicyMutationEpoch) return;
            await websitePasskeyLifecycle.reconcile(await auth.getState());
            if (refreshEpoch !== websitePasskeyPolicyMutationEpoch) return;
            await websitePasskeys.handleAuthorizationChange();
            if (refreshEpoch !== websitePasskeyPolicyMutationEpoch) return;
            const current = await settings.getWebsitePasskeySettings();
            handledWebsitePasskeySettingsFingerprint = websitePasskeySettingsFingerprint(current);
          })
          .catch((error: unknown) => {
            console.error('website passkey external settings refresh failed', error);
          });
      }
    }
  }
  if (changes.serverUrl) {
    websitePasskeyLifecycle.invalidate();
    void securityReady
      .then(() => auth.getState())
      .then((state) => websitePasskeyLifecycle.reconcile(state))
      .then(() => websitePasskeys.handleAuthorizationChange())
      .catch((error: unknown) => {
        console.error('website passkey settings refresh failed', error);
      });
  }
  if (changes.autofillPolicySettings || changes.autofillSettings || changes.defaultUriMatchStrategy) {
    manualAutofillGrants.revokeAll();
    keyboardGrants.revokeAll();
    commandCoordinator.revokeAll();
    void autofillContinuation.revokeAll();
    autofillPolicyGate.invalidate();
    void refreshAutofillClients().catch(() => {});
    websitePasskeyLifecycle.invalidate();
    void securityReady
      .then(() => auth.getState())
      .then((state) => websitePasskeyLifecycle.reconcile(state))
      .then(() => websitePasskeys.handleAuthorizationChange())
      .catch((error: unknown) => {
        console.error('website passkey interaction policy refresh failed', error);
      });
  }
  if (changes.httpAuthSettings) {
    manualAutofillGrants.revokeAll();
    autofillPolicyGate.invalidate();
  }
});

browser.alarms.onAlarm.addListener((alarm) => {
  return securityReady.then(async () => {
    if (alarm.name === VAULT_TIMEOUT_ALARM) await vaultTimeout.handleAlarm(alarm.name);
    else if (alarm.name === IDLE_LOCK_ALARM) await idleLock.onBackstopAlarm();
    else if (alarm.name === CLIPBOARD_CLEAR_ALARM) await clipboard.handleClipboardAlarm(alarm.scheduledTime);
    else if (alarm.name === VAULT_SYNC_ALARM) await vaultSyncScheduler?.handleAlarm(alarm);
    else if (alarm.name === AUTOFILL_SAVE_CAPTURE_ALARM) await saveCaptureCoordinator.reconcile();
    else if (alarm.name === AUTOFILL_PENDING_SAVE_ALARM) await pendingSaves.reconcile();
    else if (alarm.name === CLIENT_EVENT_UPLOAD_ALARM) {
      try {
        await clientEventRuntime.handleAlarm(alarm.name);
      } catch {
        console.warn('client_event_alarm_failed');
      }
    }
    else if (isPendingLoginContinuationExpirationAlarm(alarm.name)) {
      const attemptId = pendingLoginContinuationExpirationAttemptId(alarm.name);
      if (attemptId) auth.expirePendingLoginContinuation(attemptId);
      await pendingLoginStore.handleExpirationAlarm(alarm.name);
    }
    else if (alarm.name === VAULT_NOTIFICATIONS_RECONNECT_ALARM) {
      await vaultNotificationRuntime.handleAlarm(alarm);
    }
    else if (isDeviceLoginAlarmName(alarm.name)) {
      await handleDeviceLoginAlarm(alarm);
    }
  }).catch(() => {});
});
