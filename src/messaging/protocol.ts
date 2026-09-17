import browser from 'webextension-polyfill';
import type { AuthResult, RegistrationCompleteAuthResult, RegistrationStartAuthResult } from '../core/session/auth-service.js';
import type { PasswordHintResult } from '../core/api/client.js';
import type { PendingLoginPublicStatus } from '../core/session/pending-login-continuation.js';
import type { InteractiveTwoFactorOwner } from '../core/session/interactive-two-factor.js';
import type { SsoLoginPublicStatus } from '../core/session/sso-login.js';
import { pinConstraintMessage, pinConstraintViolation } from '../core/session/pin-constraints.js';
import type { SessionState, AccountSummary } from '../core/session/session-manager.js';
import type { CipherCreateTarget, CipherInput, CipherInputPurpose, CipherSummary, CollectionSummary, DecryptedCipher, FieldName, FolderSummary, SshKeyMetadataInput, SshKeyPublicDetails, TotpListEntry } from '../core/vault/models.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { TotpResult } from '../core/vault/totp.js';
import type { SendInput, SendSummary, UpdateSendInput } from '../core/vault/sends.js';
import type { PasswordHealthEntry } from '../core/vault/password-health.js';
import type {
  AutofillSettings,
  ClipboardClearSetting,
  LockTimeoutSetting,
  OnIdleAction,
} from '../background/settings.js';
import type { AppErrorCode } from '../core/errors.js';
import {
  isExactTwoFactorRecoveryRequest,
  type TwoFactorRecoveryRequest,
} from './two-factor-recovery.js';
import {
  isExactPasswordHintRequest,
  type PasswordHintRequest,
} from './password-hint.js';
import {
  isExactCipherFavoriteRequest,
  type CipherFavoriteRequest,
} from './cipher-favorite.js';
import type { OrgPermission } from '../core/vault/org-permissions.js';
import type { KdfConfig } from '../core/crypto/kdf.js';
import type { EffectiveVaultTimeoutMode } from '../background/vault-timeout-policy.js';
import type { VaultTransferExportTarget } from '../core/vault/vault-transfer-target.js';
import type { PasswordChangeRequirement } from '../core/policy/master-password-policy.js';
import type {
  GeneratorPolicySnapshot,
  PasswordGeneratorOptions,
} from '../core/generator/enterprise-password-policy.js';
import type { GeneratorHistoryEntry, GeneratorHistoryEntryType } from '../core/generator/history.js';
import type {
  CardFillRole,
  FillKind,
  FillRole,
  IdentityFillRole,
} from '../core/vault/fill-roles.js';
import type {
  LoginCustomAssignment,
  LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';
import type {
  WebsitePasskeyApprovalModel,
  WebsitePasskeyDecisionOutcome,
  WebsitePasskeySelection,
} from './website-passkey-port.js';
import type { VaultTransferExportFormat } from './vault-transfer-port.js';
import type { OrganizationDataOwnershipStatus } from '../core/vault/vault-service.js';
import type { WebsitePasskeyIframeInventoryRequest } from './website-passkey-iframe-inventory.js';

export { isContentTotpClipboardCode } from './totp-clipboard-code.js';
export { isExactPasswordHintRequest } from './password-hint.js';
export type { PasswordHintRequest } from './password-hint.js';
export { isExactCipherFavoriteRequest } from './cipher-favorite.js';
export type { CipherFavoriteRequest } from './cipher-favorite.js';

export type {
  CardFillRole,
  FillKind,
  FillRole,
  IdentityFillRole,
  StructuredFillRole,
} from '../core/vault/fill-roles.js';
export type {
  LoginCustomAssignment,
  LoginCustomControlType,
  LoginCustomTarget,
  LoginCustomTargetHint,
  LoginCustomTargetPlan,
} from '../core/vault/login-custom-fields.js';
export type { PendingLoginPublicStatus } from '../core/session/pending-login-continuation.js';

export interface AutofillCandidate {
  id: string;
  name: string;
  username?: string;
  matchedUri: string;
  matchType: UriMatchStrategySetting;
  favorite: boolean;
  /** Non-secret presence flag used by purpose-specific TOTP candidate flows. */
  hasTotp?: boolean;
  /** True when the item is master-password-reprompt protected; it cannot be filled inline. */
  reprompt?: boolean;
}

/** A card/identity candidate for the fill popover. Carries no secret — subtitle is brand/full name. */
export interface FillItemCandidate {
  id: string;
  name: string;
  subtitle?: string;
  favorite: boolean;
  /** True when reprompt-protected; cannot be filled inline (worker refuses). */
  reprompt?: boolean;
}

/** Fillable card fields. Number + code are sensitive; released only on explicit user selection. */
export interface CardFillData {
  cardholderName?: string;
  brand?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  code?: string;
}

/** Fillable identity fields. National-ID secrets (ssn/passport/license) are intentionally absent. */
export interface IdentityFillData {
  title?: string;
  firstName?: string;
  middleName?: string;
  lastName?: string;
  address1?: string;
  address2?: string;
  address3?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  company?: string;
  email?: string;
  phone?: string;
  username?: string;
}

/** Background → content: atomically reserve the latest trusted context-menu target before secrets are read. */
export interface ReserveFillTargetCommand {
  type: 'autofill.reserveFillTarget';
  reservationId: string;
  scope: 'form' | 'field';
  kind: FillKind;
  expectedFrameUrl: string;
  /** Absolute monotonic timestamp captured synchronously by the contextMenus.onClicked listener. */
  contextMenuClickTime: number;
}

/** Background -> content: consume the exact trusted right-click target and mark its login form as
 *  the current frame target. No vault item identifier or secret crosses this message. */
export interface ClaimContextLoginTargetCommand {
  type: 'autofill.claimContextLoginTarget';
  expectedFrameUrl: string;
  /** Absolute monotonic timestamp captured synchronously by the contextMenus.onClicked listener. */
  contextMenuClickTime: number;
}

export type ContextLoginTargetClaimResult =
  | {
      status: 'claimed';
      /** High-entropy content runtime that owned the trusted target. */
      runtimeIncarnation: string;
      /** Exact content-owned form snapshot selected by the trusted context-menu field. */
      formId: string;
      generation: number;
      customPlanDigest: string;
    }
  | { status: 'no_target' | 'page_changed' };

export interface SettingsGetData extends AutofillSettings {
  readonly serverUrl?: string;
  readonly defaultUriMatchStrategy: UriMatchStrategySetting;
  readonly pageLoadFillDefault: boolean;
  readonly lockTimeout: LockTimeoutSetting;
  readonly onIdleAction: OnIdleAction;
  readonly clipboardClearSeconds: ClipboardClearSetting;
  /** False means persisted autofill policy was malformed and every autofill action must fail closed. */
  readonly autofillPolicyValid: boolean;
  /** Website passkey interception is fail-closed when its persisted policy cannot be validated. */
  readonly websitePasskeys: {
    readonly enabled: boolean;
    readonly excludedDomains: readonly string[];
    readonly valid: boolean;
  };
  /** HTTP Basic authentication is separately opt-in and restricted to exact origins. */
  readonly httpAuth: {
    readonly enabled: boolean;
    readonly allowedOrigins: readonly string[];
    readonly valid: boolean;
  };
  /** Sanitized policy capabilities only; organization identifiers and raw policy data stay local. */
  readonly enterprisePolicy: {
    readonly pinUnlockAllowed: boolean;
    readonly maximumVaultTimeoutManaged: boolean;
    readonly maximumVaultTimeoutMode: EffectiveVaultTimeoutMode;
    readonly uriMatchDefaultManaged: boolean;
    readonly uriMatchDefaultMalformed: boolean;
    readonly activateAutofillManaged: boolean;
  };
  /** Bounded worker projection. Raw enterprise policy data never crosses this boundary. */
  readonly generator: GeneratorPolicySnapshot;
}

export interface PinStatusData {
  readonly enabled: boolean;
  readonly available: boolean;
  readonly allowed: boolean;
  readonly requireMasterPasswordOnRestart: boolean;
}

export interface DeviceLoginPublicContextData {
  readonly generation: number;
  readonly fingerprint: string;
  readonly serverOrigin: string;
  readonly email: string;
  readonly deviceName: string;
  readonly expiresAt: number;
}

export interface InteractiveTwoFactorChallengeData {
  readonly owner: InteractiveTwoFactorOwner;
}

export type AccountPasskeyStatusData =
  | { readonly status: 'none' }
  | { readonly status: 'waiting'; readonly attemptId: string; readonly expiresAt: number }
  | { readonly status: 'outcome_unknown'; readonly attemptId: string; readonly terminalAt: number };

export type AccountPasskeyBeginData =
  | Extract<AccountPasskeyStatusData, { status: 'waiting' | 'outcome_unknown' }>
  | {
      readonly status: 'unavailable';
      readonly reason:
        | 'host_access_unavailable'
        | 'connector_context_failed'
        | 'options_busy'
        | 'options_invalid_connector'
        | 'options_server_changed'
        | 'options_request_failed'
        | 'options_unavailable';
    };

export type DeviceLoginRequesterResultData =
  | { readonly status: 'none' | 'not_known_device' | 'denied' | 'expired' | 'restricted' | 'unlocked' }
  | ({ readonly status: 'pending' } & DeviceLoginPublicContextData)
  | ({
      readonly status: 'two_factor';
      readonly providers: readonly number[];
      readonly fido2?: InteractiveTwoFactorChallengeData;
    }
      & DeviceLoginPublicContextData)
  | ({
      readonly status: 'retry_required';
      readonly providers?: readonly number[];
      readonly fido2?: InteractiveTwoFactorChallengeData;
    }
      & DeviceLoginPublicContextData)
  | ({ readonly status: 'two_factor_unsupported'; readonly providers: readonly number[] }
      & DeviceLoginPublicContextData)
  | {
      readonly status: 'outcome_unknown';
      readonly generation: number;
      readonly serverOrigin: string;
      readonly createdAt: number;
      readonly expiresAt: number;
      readonly terminalAt: number;
    };

export interface DeviceLoginDecisionBindingData {
  readonly version: 1;
  readonly requestId: string;
  readonly publicKeyDigest: string;
  readonly requestDeviceIdentifier: string;
  readonly creationDate: string;
  readonly requestDeviceTypeValue: number;
  readonly nonce: string;
  readonly proof: string;
}

export interface DeviceLoginApprovalViewData {
  readonly id: string;
  readonly fingerprint: string;
  readonly requestDeviceType?: string;
  readonly requestDeviceTypeValue: number;
  readonly requestDeviceIdentifier: string;
  readonly requestIpAddress?: string;
  readonly requestCountryName?: string;
  readonly creationDate: string;
  readonly creationTime: number;
  readonly expiresAt: number;
  readonly requestDeviceId?: string;
  readonly origin?: string;
}

export interface BoundDeviceLoginApprovalData {
  readonly view: DeviceLoginApprovalViewData;
  readonly decisionBinding: DeviceLoginDecisionBindingData;
}

export interface DeviceLoginDecisionReceiptData {
  readonly requestId: string;
  readonly requestApproved: boolean;
  readonly responseDate: string;
}

export interface SettingsSaveRequest {
  readonly type: 'settings.save';
  readonly serverUrl?: string;
  readonly defaultUriMatchStrategy?: UriMatchStrategySetting;
  readonly lockTimeout?: LockTimeoutSetting;
  readonly showMatchingLoginCount?: boolean;
  /** Autofill policy is updated as one validated storage record, never as independent fields. */
  readonly autofillSettings?: AutofillSettings & { readonly pageLoadFillDefault: boolean };
}

/** Complete website-passkey policy snapshot. Partial writes are intentionally not representable. */
export interface SettingsSaveWebsitePasskeysRequest {
  readonly type: 'settings.saveWebsitePasskeys';
  readonly enabled: boolean;
  readonly excludedDomains: string[];
}

/** Complete HTTP-auth policy snapshot. Partial or implicit origin writes are not representable. */
export interface SettingsSaveHttpAuthRequest {
  readonly type: 'settings.saveHttpAuth';
  readonly enabled: boolean;
  readonly allowedOrigins: string[];
}

export type AutofillIntentPurpose = 'login' | 'totp';

/** Any purpose that can be carried by an opaque one-time autofill capability. */
export type AutofillSecretPurpose = AutofillIntentPurpose | FillKind;

export type ClientEventViewPurpose = 'view' | 'editor';
export type ClientEventSecretPurpose = 'reveal' | 'copy';

/** Login-purpose response. TOTP is structurally impossible on this channel. */
export interface AutofillLoginData {
  username?: string;
  password?: string;
}

/** Explicit-user-action login projection. Page-load remains structurally limited to AutofillLoginData. */
export interface AutofillInteractiveLoginData {
  readonly login: AutofillLoginData;
  readonly customAssignments: readonly LoginCustomAssignment[];
  readonly clientEventAckId?: string;
  readonly totpCopyAckId?: string;
}

/** TOTP-purpose response. Password and username are structurally impossible on this channel. */
export interface AutofillTotpData {
  code: string;
  period: number;
  remaining: number;
}

export interface AutofillClientConfig {
  readonly inlineSuggestions: boolean;
  readonly pageLoadFill: boolean;
  readonly saveAllowed: boolean;
  readonly updateAllowed: boolean;
  readonly generatorAllowed: boolean;
  /** Bounded worker projection. Raw enterprise policy data never enters the page world. */
  readonly generator: GeneratorPolicySnapshot;
}

export interface GeneratorHistoryListData {
  readonly entries: readonly GeneratorHistoryEntry[];
}

export interface GeneratorHistoryTrackData {
  readonly added: boolean;
}

export interface GeneratorHistoryTrackRequestData {
  readonly value: string;
  readonly type: GeneratorHistoryEntryType;
  readonly policyRevision: number;
}

export interface GeneratorHistoryClearData {
  readonly cleared: boolean;
}

export type AutofillSavePrompt =
  | { readonly action: 'none'; readonly retryAfterMs?: number }
  | { readonly action: 'save'; readonly promptId: string; readonly suggestedName: string }
  | { readonly action: 'update'; readonly promptId: string; readonly name: string }
  | { readonly action: 'addUri'; readonly promptId: string; readonly name: string };

export type AutofillSaveCaptureSubmission =
  | {
      readonly kind: 'native';
      readonly actionUrl: string;
      readonly method: 'POST' | 'PUT' | 'PATCH';
    }
  | { readonly kind: 'formless' };

export type FillTargetReservationResult =
  | { status: 'reserved'; runtimeIncarnation: string; roles: readonly FillRole[] }
  | { status: 'no_target' | 'page_changed' };

/** Background → content: silently release a reservation when credential retrieval cannot finish. */
export interface CancelFillTargetCommand {
  type: 'autofill.cancelFillTarget';
  reservationId: string;
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
}

/** Background → content: fill a detected form (scope 'form') or only the reserved field
 *  (scope 'field') with the chosen card/identity. Sent via tabs.sendMessage from the context menu. */
export interface FillCommand {
  type: 'autofill.fill';
  reservationId: string;
  scope: 'form' | 'field';
  kind: FillKind;
  /** Canonical roles returned by the content reservation and authorized before secret release. */
  roles: readonly FillRole[];
  /** Browser-authoritative frame URL captured when the user selected the context-menu item. */
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
  data: CardFillData | IdentityFillData;
}

export type ContextFillResult =
  | { status: 'filled' }
  | { status: 'no_target' | 'page_changed' | 'target_changed' };

export type HoldFillTargetResult =
  | { status: 'held' }
  | { status: 'no_target' | 'page_changed' };

/** Background → content: the chosen item could not be released inline (reprompt-protected). */
export interface FillErrorCommand {
  type: 'autofill.fillError';
  reservationId: string;
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
  code: 'reprompt_required';
}

/** Convert a short context-menu reservation into a longer, opaque reprompt hold. */
export interface HoldFillTargetCommand {
  type: 'autofill.holdFillTarget';
  reservationId: string;
  holdId: string;
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
}

/** Complete a held context-menu fill after Popup-owned master-password verification. */
export interface ResumeHeldFillTargetCommand {
  type: 'autofill.resumeHeldFillTarget';
  holdId: string;
  scope: 'form' | 'field';
  kind: FillKind;
  roles: readonly FillRole[];
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
  data: CardFillData | IdentityFillData;
}

export interface CancelHeldFillTargetCommand {
  type: 'autofill.cancelHeldFillTarget';
  holdId: string;
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
}

/** Ask the exact content document to redeem a previously held keyboard reprompt. */
export interface ResumeKeyboardRepromptCommand {
  type: 'autofill.resumeKeyboardReprompt';
  continuationId: string;
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
}

/** Resolve only after the exact source document has regained real browser focus. */
export interface AwaitAutofillFocusCommand {
  type: 'autofill.awaitFocus';
  requestId: string;
  expectedFrameUrl: string;
  expectedRuntimeIncarnation: string;
  expiresAt: number;
}

/** Background → content: fill the currently-focused field's form via the keyboard shortcut. */
export interface FocusedFillCommand {
  type: 'autofill.focusedFill';
  /** Browser-command capability. Page scripts cannot mint or observe this opaque value. */
  commandToken: string;
}

/** Background notification only. Content re-fetches URL-specific booleans before doing more work. */
export interface AutofillClientConfigChangedCommand {
  type: 'autofill.clientConfigChanged';
}

export interface AutofillSaveCaptureConfirmedCommand {
  type: 'autofill.saveCaptureConfirmed';
  captureId: string;
}

export type AutofillSaveCaptureWakeResult =
  | { readonly status: 'displayed' }
  | { readonly status: 'not_displayed' }
  | { readonly status: 'not_ready' };

/** Background → extension pages: revoke cached policy UI immediately, then refresh after settlement. */
export interface EnterprisePolicyClientChangedCommand {
  type: 'enterprisePolicy.clientChanged';
  phase: 'revoke' | 'refresh';
}

export type ContentCommand =
  | ReserveFillTargetCommand
  | ClaimContextLoginTargetCommand
  | CancelFillTargetCommand
  | FillCommand
  | FillErrorCommand
  | HoldFillTargetCommand
  | ResumeHeldFillTargetCommand
  | CancelHeldFillTargetCommand
  | ResumeKeyboardRepromptCommand
  | AwaitAutofillFocusCommand
  | FocusedFillCommand
  | AutofillClientConfigChangedCommand
  | AutofillSaveCaptureConfirmedCommand;

interface FrameFormBase {
  formId: string;
  visible: boolean;
  focusedAt?: number;
}

/** Metadata-only description of a detected login form in a single frame. Never carries field values. */
export interface FrameLoginForm extends FrameFormBase {
  kind: 'login';
  customPlan: LoginCustomTargetPlan;
}

export interface FrameCardForm extends FrameFormBase {
  kind: 'card';
  roles: readonly CardFillRole[];
}

export interface FrameIdentityForm extends FrameFormBase {
  kind: 'identity';
  roles: readonly IdentityFillRole[];
}

export type FrameAutofillForm = FrameLoginForm | FrameCardForm | FrameIdentityForm;

/** Metadata-only snapshot of live fill targets. `generation` changes with their structural shape. */
export interface FrameInspection {
  /** Changes on every content runtime start, including a persisted BFCache restore. */
  runtimeIncarnation: string;
  frameUrl: string;
  generation: number;
  forms: FrameAutofillForm[];
}

interface ContentStructuredAutofillTargetBase {
  runtimeIncarnation: string;
  formId: string;
  /** Structural generation returned by the frame controller for this exact browser document. */
  generation: number;
}

export interface ContentCardAutofillTarget extends ContentStructuredAutofillTargetBase {
  kind: 'card';
  roles: readonly CardFillRole[];
  /** Explicit user-selected canonical subset; `roles` still binds the complete form structure. */
  selectedRoles?: readonly CardFillRole[];
}

export interface ContentIdentityAutofillTarget extends ContentStructuredAutofillTargetBase {
  kind: 'identity';
  roles: readonly IdentityFillRole[];
  /** Explicit user-selected canonical subset; `roles` still binds the complete form structure. */
  selectedRoles?: readonly IdentityFillRole[];
}

/** Content-provided metadata that is bound into a one-time intent and re-inspected by the worker. */
export type ContentStructuredAutofillTarget =
  | ContentCardAutofillTarget
  | ContentIdentityAutofillTarget;

/** Target metadata captured by the focused content document while claiming a browser command. */
export type KeyboardAutofillClaimBinding =
  | { readonly purpose: 'login'; readonly customPlan: LoginCustomTargetPlan }
  | { readonly purpose: 'totp' }
  | {
      readonly purpose: 'card' | 'identity';
      readonly structuredTarget: ContentStructuredAutofillTarget;
    };

interface TabSuggestionTargetBase {
  frameId: number;
  formId: string;
  /** Chrome document identity used for both inspection and final credential delivery. */
  documentId: string;
  /** Content runtime that produced the inspected structural target. */
  runtimeIncarnation: string;
  /** Content structural snapshot that must still match before and after secret retrieval. */
  generation: number;
}

export interface TabLoginSuggestionTarget extends TabSuggestionTargetBase {
  kind: 'login';
  /** Digest of the metadata-only plan; the full plan is obtained by a fresh document inspection. */
  customPlanDigest: string;
}

export interface TabCardSuggestionTarget extends TabSuggestionTargetBase {
  kind: 'card';
  roles: readonly CardFillRole[];
  /** Optional narrowing of the release; it never replaces the inspected structural roles. */
  selectedRoles?: readonly CardFillRole[];
}

export interface TabIdentitySuggestionTarget extends TabSuggestionTargetBase {
  kind: 'identity';
  roles: readonly IdentityFillRole[];
  /** Optional narrowing of the release; it never replaces the inspected structural roles. */
  selectedRoles?: readonly IdentityFillRole[];
}

export type TabSuggestionTarget =
  | TabLoginSuggestionTarget
  | TabCardSuggestionTarget
  | TabIdentitySuggestionTarget;

export interface TabLoginSuggestion extends AutofillCandidate {
  kind: 'login';
  target?: TabLoginSuggestionTarget;
}

export interface TabCardSuggestion extends FillItemCandidate {
  kind: 'card';
  target: TabCardSuggestionTarget;
}

export interface TabIdentitySuggestion extends FillItemCandidate {
  kind: 'identity';
  target: TabIdentitySuggestionTarget;
}

/** Metadata-only candidates shown in the Popup. Secret fill data never crosses this response. */
export type TabAutofillSuggestion = TabLoginSuggestion | TabCardSuggestion | TabIdentitySuggestion;

export type TabSuggestionsOutcome =
  | { status: 'ready'; suggestions: TabAutofillSuggestion[] }
  | {
      status:
        | 'no_eligible_tab'
        | 'site_access_unavailable'
        | 'restricted_page'
        | 'content_script_unavailable';
      suggestions: [];
    };

export type TabFillOutcome =
  | { status: 'filled' }
  | { status: 'no_eligible_tab' }
  | { status: 'site_access_unavailable' }
  | { status: 'no_fillable_target' }
  | { status: 'reprompt_required' }
  | { status: 'vault_locked' }
  | { status: 'sync_required' }
  | { status: 'no_longer_matched' }
  | { status: 'target_changed' }
  | { status: 'fill_outcome_unknown' }
  | { status: 'restricted_page' }
  | { status: 'content_script_unavailable' };

/** Opaque, short-lived authorization for one Popup-owned reprompt login fill. */
export interface RepromptAutofillAuthorizationData {
  readonly authorizationId: string;
  readonly expiresAt: number;
}

export type AutofillContinuationStatusData =
  | { readonly status: 'none' }
  | {
      readonly status: 'unlock_required';
      readonly continuationId: string;
      readonly channel: 'context' | 'keyboard';
      readonly expiresAt: number;
    }
  | {
      readonly status: 'reprompt_required';
      readonly continuationId: string;
      readonly channel: 'context' | 'keyboard';
      readonly cipherId: string;
      readonly expiresAt: number;
    };

export type AutofillContinuationResumeData =
  | { readonly status: 'started' }
  | {
      readonly status: 'show_suggestions';
      readonly tabId: number;
      readonly outcome: TabSuggestionsOutcome;
    }
  | { readonly status: 'filled'; readonly outcome: TabFillOutcome }
  | { readonly status: 'stale' };

export type WebsitePasskeyLockedStatusData =
  | { readonly status: 'none' }
  | {
      readonly status: 'unlock_required';
      readonly continuationId: string;
      readonly expiresAt: number;
    };

export type WebsitePasskeyLockedResumeData = {
  readonly status: 'started' | 'stale';
};

export type ManualAutofillAction = 'fill_only' | 'fill_and_save';
export type ManualAutofillRisk = 'no_match' | 'never' | 'https_downgrade';

/** Safe Popup projection for one worker-resolved URI mismatch. No target or vault metadata crosses. */
export interface ManualAutofillWarningData {
  readonly risk: ManualAutofillRisk;
  readonly site: string;
  readonly recipientSite?: string;
  readonly canSave: boolean;
  readonly requiresReprompt: boolean;
}

export interface ManualAutofillAuthorizationData {
  readonly authorizationId: string;
  readonly expiresAt: number;
}

export interface ManualAutofillPreparationData {
  readonly warning: ManualAutofillWarningData;
  readonly authorization: ManualAutofillAuthorizationData;
}

export type ManualAutofillCommitOutcome =
  | TabFillOutcome
  | { readonly status: 'filled_and_saved' }
  | { readonly status: 'filled_but_save_failed' }
  | { readonly status: 'filled_but_save_conflict' }
  | { readonly status: 'filled_but_save_committed_unsynced' }
  | { readonly status: 'filled_but_save_outcome_unknown' };

/** Background → content: inspect live forms or commit after re-validating URL and structure. */
export type FrameAutofillMessage =
  | { type: 'autofill.inspectFrame' }
  | {
      type: 'autofill.commitLoginFill';
      formId: string;
      expectedFrameUrl: string;
      expectedRuntimeIncarnation: string;
      expectedGeneration: number;
      login: AutofillLoginData;
      customPlan: LoginCustomTargetPlan;
      customPlanDigest: string;
      customAssignments: readonly LoginCustomAssignment[];
    }
  | {
      type: 'autofill.commitStructuredFill';
      kind: 'card';
      formId: string;
      roles: readonly CardFillRole[];
      /** Only these roles may receive data when an explicit subset was selected. */
      selectedRoles?: readonly CardFillRole[];
      expectedFrameUrl: string;
      expectedRuntimeIncarnation: string;
      expectedGeneration: number;
      data: CardFillData;
    }
  | {
      type: 'autofill.commitStructuredFill';
      kind: 'identity';
      formId: string;
      roles: readonly IdentityFillRole[];
      /** Only these roles may receive data when an explicit subset was selected. */
      selectedRoles?: readonly IdentityFillRole[];
      expectedFrameUrl: string;
      expectedRuntimeIncarnation: string;
      expectedGeneration: number;
      data: IdentityFillData;
    };

type RequestMessageBody =
  | { type: 'generator.history.list' }
  | { type: 'generator.history.track'; entry: GeneratorHistoryTrackRequestData }
  | { type: 'generator.history.clear' }
  | { type: 'auth.getState' }
  | PasswordHintRequest
  | { type: 'auth.login'; email: string; masterPassword: string }
  | { type: 'auth.sso.begin'; email: string; organizationIdentifier?: string }
  | { type: 'auth.sso.requirement'; email: string }
  | { type: 'auth.sso.status'; attemptId?: string; generation?: number }
  | { type: 'auth.sso.cancel'; attemptId: string; generation: number }
  | { type: 'auth.pendingLogin.status' }
  | { type: 'auth.pendingLogin.cancel'; continuationId?: string }
  | { type: 'auth.newDeviceVerification.sendOtp'; attemptId: number; continuationId?: string }
  | { type: 'auth.newDeviceVerification.submit'; attemptId: number; code: string; continuationId?: string }
  | { type: 'auth.newDeviceVerification.cancel'; attemptId: number; continuationId?: string }
  | { type: 'auth.startRegistration'; email: string; name?: string }
  | {
      type: 'auth.register';
      attemptId: number;
      masterPassword: string;
      masterPasswordHint: string;
    }
  | { type: 'auth.cancelRegistration'; attemptId: number }
  | { type: 'auth.accountPasskey.begin' }
  | { type: 'auth.accountPasskey.status' }
  | { type: 'auth.accountPasskey.cancel' }
  | { type: 'auth.deviceLogin.begin'; email: string }
  | { type: 'auth.deviceLogin.status'; generation?: number }
  | { type: 'auth.deviceLogin.retry'; generation: number }
  | { type: 'auth.deviceLogin.submitTwoFactor'; generation: number; provider: number; code: string; remember?: boolean }
  | { type: 'auth.deviceLogin.sendEmailCode'; generation: number }
  | { type: 'auth.deviceLogin.cancel'; generation: number }
  | { type: 'auth.deviceLogin.approvals.list' }
  | { type: 'auth.deviceLogin.approvals.get'; requestId: string }
  | { type: 'auth.deviceLogin.approvals.approve'; decisionBinding: DeviceLoginDecisionBindingData }
  | { type: 'auth.deviceLogin.approvals.deny'; decisionBinding: DeviceLoginDecisionBindingData }
  | { type: 'auth.submitTwoFactor'; provider: number; code: string; remember?: boolean; continuationId?: string }
  | {
      type: 'auth.duo.begin';
      flow: 'password';
      provider: 2 | 6;
      continuationId: string;
      remember: boolean;
    }
  | {
      type: 'auth.duo.begin';
      flow: 'deviceLogin';
      provider: 2 | 6;
      generation: number;
      remember: boolean;
    }
  | { type: 'auth.duo.cancel'; flow: 'password'; continuationId: string }
  | {
      type: 'auth.duo.cancel';
      flow: 'deviceLogin';
      generation: number;
      provider: 2 | 6;
    }
  | { type: 'auth.beginFido2'; owner: InteractiveTwoFactorOwner; locale: 'zh-CN' | 'en' }
  | { type: 'auth.completeFido2'; token: string; remember: boolean }
  | { type: 'auth.sendEmailCode'; continuationId?: string }
  | TwoFactorRecoveryRequest
  | { type: 'auth.unlock'; masterPassword: string }
  | { type: 'auth.verifyMasterPassword'; masterPassword: string }
  | {
      type: 'auth.changePassword';
      currentPassword: string;
      newPassword: string;
      masterPasswordHint: string;
    }
  | { type: 'auth.changeForcedPassword'; currentPassword: string; newPassword: string }
  | { type: 'auth.changeKdf'; currentPassword: string; kdf: KdfConfig }
  | { type: 'auth.rotateAccountKey'; masterPassword: string }
  | { type: 'auth.unlockWithPin'; pin: string }
  | {
      type: 'auth.setPin';
      pin: string;
      requireMasterPasswordOnRestart: boolean;
    }
  | { type: 'auth.disablePin' }
  | { type: 'auth.pinStatus' }
  | { type: 'auth.lock' }
  | { type: 'auth.logout' }
  | { type: 'auth.listAccounts' }
  | { type: 'auth.switchAccount'; email: string }
  | { type: 'auth.removeAccount'; email: string }
  | { type: 'auth.forgetDevice'; email?: string }
  | { type: 'auth.isDeviceRemembered'; email?: string }
  | { type: 'vault.sync' }
  | { type: 'vault.popupOpened' }
  | { type: 'vault.getSyncStatus' }
  | {
      type: 'vault.authorizeExport';
      format: VaultTransferExportFormat;
      encryptionType?: 'account' | 'file';
      target?: VaultTransferExportTarget;
      masterPassword: string;
    }
  | { type: 'vault.listItems' }
  | { type: 'vault.getField'; id: string; field: FieldName; masterPassword?: string; clientEventPurpose?: ClientEventSecretPurpose }
  | { type: 'vault.getCustomField'; id: string; index: number; masterPassword?: string; clientEventPurpose?: ClientEventSecretPurpose }
  | { type: 'vault.getPasswordHistory'; id: string; masterPassword?: string }
  | { type: 'vault.getAttachment'; cipherId: string; attachmentId: string; masterPassword?: string }
  | { type: 'vault.addAttachment'; cipherId: string; fileName: string; dataB64: string; masterPassword?: string }
  | { type: 'vault.upgradeLegacyAttachment'; cipherId: string; attachmentId: string; masterPassword?: string }
  | { type: 'vault.deleteAttachment'; cipherId: string; attachmentId: string }
  | { type: 'vault.getSshKeyWriteAvailability' }
  | { type: 'vault.getSshKeyDetails'; id: string; masterPassword?: string }
  | { type: 'vault.revealSshPrivateKey'; id: string; masterPassword?: string }
  | { type: 'vault.createGeneratedSshKey'; metadata: SshKeyMetadataInput; target: CipherCreateTarget }
  | { type: 'vault.importSshKey'; metadata: SshKeyMetadataInput; privateKey: string; target: CipherCreateTarget }
  | { type: 'vault.replaceSshKey'; id: string; privateKey: string; masterPassword?: string }
  | { type: 'vault.updateSshKeyMetadata'; id: string; metadata: SshKeyMetadataInput; masterPassword?: string }
  | { type: 'vault.getCipherDetail'; id: string; masterPassword?: string; clientEventPurpose?: ClientEventViewPurpose }
  | { type: 'vault.getTotp'; id: string; masterPassword?: string }
  | { type: 'vault.getTotpCodes' }
  | { type: 'vault.getSkippedOrgCount' }
  | { type: 'vault.getOrganizationDataOwnershipStatus' }
  | {
      type: 'vault.migrateOrganizationDataOwnership';
      organizationId: string;
      collectionId: string;
      authorizationId: string;
      masterPassword: string;
    }
  | {
      type: 'vault.leaveOrganizationDataOwnership';
      organizationId: string;
      authorizationId: string;
    }
  | { type: 'vault.getPasswordHealth' }
  | { type: 'vault.checkPwned' }
  | { type: 'vault.createFolder'; name: string }
  | { type: 'vault.renameFolder'; id: string; name: string }
  | { type: 'vault.deleteFolder'; id: string }
  | { type: 'vault.createCollection'; organizationId: string; name: string }
  | { type: 'vault.renameCollection'; organizationId: string; id: string; name: string }
  | { type: 'vault.deleteCollection'; organizationId: string; id: string }
  | { type: 'vault.setCipherCollections'; id: string; collectionIds: string[] }
  | { type: 'vault.createCipher'; input: CipherInput; target: CipherCreateTarget }
  | { type: 'vault.updateCipher'; id: string; input: CipherInput }
  | CipherFavoriteRequest
  | { type: 'vault.deleteCipher'; id: string }
  | { type: 'vault.softDeleteCipher'; id: string }
  | { type: 'vault.restoreCipher'; id: string }
  | { type: 'vault.archiveCipher'; id: string; masterPassword?: string }
  | { type: 'vault.unarchiveCipher'; id: string; masterPassword?: string }
  | { type: 'vault.deletePasskey'; id: string; credentialId: string; masterPassword?: string }
  | { type: 'vault.shareCipher'; id: string; organizationId: string; collectionIds: string[]; masterPassword?: string }
  | { type: 'vault.getCipherInput'; id: string; cipherInputPurpose: CipherInputPurpose; masterPassword?: string; clientEventPurpose?: 'editor' }
  | { type: 'clientEvent.ack'; ackId: string }
  | { type: 'autofill.ackTotpCopy'; ackId: string }
  | { type: 'settings.get' }
  | SettingsSaveRequest
  | SettingsSaveWebsitePasskeysRequest
  | SettingsSaveHttpAuthRequest
  | { type: 'settings.saveSecurity'; onIdleAction: OnIdleAction; clipboardClearSeconds: ClipboardClearSetting }
  | { type: 'clipboard.scheduleClear'; value: string }
  | { type: 'websitePasskey.getApproval'; ceremonyId: string }
  | { type: 'websitePasskey.approve'; ceremonyId: string; selection: WebsitePasskeySelection }
  | { type: 'websitePasskey.fallbackOnce'; ceremonyId: string }
  | { type: 'websitePasskey.fallbackAlways'; ceremonyId: string }
  | { type: 'websitePasskey.cancel'; ceremonyId: string }
  | { type: 'websitePasskey.lockedStatus'; continuationId?: string }
  | { type: 'websitePasskey.resumeLocked'; continuationId: string }
  | { type: 'websitePasskey.cancelLocked'; continuationId: string }
  | WebsitePasskeyIframeInventoryRequest
  | { type: 'autofill.findCandidates'; purpose: AutofillIntentPurpose }
  | { type: 'autofill.findStructuredCandidates'; kind: FillKind }
  | { type: 'autofill.claimKeyboardGrant'; commandToken: string; binding: KeyboardAutofillClaimBinding }
  | { type: 'autofill.keyboard.findCandidates'; keyboardGrantId: string }
  | { type: 'autofill.keyboard.issueIntent'; keyboardGrantId: string; cipherId: string }
  | { type: 'autofill.continuation.redeemKeyboardReprompt'; continuationId: string }
  | { type: 'autofill.keyboard.redeemLoginIntent'; intentId: string }
  | { type: 'autofill.keyboard.redeemTotpIntent'; intentId: string }
  | { type: 'autofill.keyboard.redeemStructuredIntent'; intentId: string; target: ContentStructuredAutofillTarget }
  | {
      type: 'autofill.issueIntent';
      cipherId: string;
      purpose: 'login';
      customPlan: LoginCustomTargetPlan;
    }
  | { type: 'autofill.issueIntent'; cipherId: string; purpose: 'totp' }
  | { type: 'autofill.issueStructuredIntent'; cipherId: string; target: ContentStructuredAutofillTarget }
  | { type: 'autofill.redeemLoginIntent'; intentId: string }
  | { type: 'autofill.redeemTotpIntent'; intentId: string }
  | { type: 'autofill.redeemStructuredIntent'; intentId: string; target: ContentStructuredAutofillTarget }
  | { type: 'autofill.getClientConfig' }
  | {
      type: 'autofill.authorizeGeneratorUse';
      revision: number;
      options: PasswordGeneratorOptions;
    }
  | { type: 'autofill.trackGeneratedValue'; token: string; value: string }
  | { type: 'autofill.issuePageLoadIntent' }
  | { type: 'autofill.redeemPageLoadIntent'; intentId: string }
  | {
      type: 'autofill.activateRuntime';
      runtimeIncarnation: string;
      previousRuntimeIncarnation?: string;
    }
  | { type: 'sends.list' }
  | { type: 'sends.createText'; input: SendInput }
  | { type: 'sends.createFile'; input: SendInput; dataB64: string; fileName: string }
  | { type: 'sends.update'; id: string; input: UpdateSendInput }
  | { type: 'sends.delete'; id: string }
  | {
      type: 'autofill.captureSubmission';
      username: string;
      password?: never;
      submission?: never;
    }
  | {
      type: 'autofill.captureSubmission';
      username?: string;
      password: string;
      submission?: AutofillSaveCaptureSubmission;
    }
  | { type: 'autofill.claimSavePrompt'; captureId?: string }
  | { type: 'autofill.commitSavePrompt'; promptId: string }
  | { type: 'autofill.dismissSavePrompt'; promptId: string }
  | { type: 'autofill.getTabSuggestions'; tabId: number }
  | {
      type: 'autofill.authorizeRepromptFill';
      tabId: number;
      cipherId: string;
      target: TabSuggestionTarget;
      masterPassword: string;
    }
  | {
      type: 'autofill.fillTabSuggestion';
      tabId: number;
      cipherId: string;
      target: TabSuggestionTarget;
      repromptAuthorizationId?: string;
    }
  | { type: 'autofill.manual.prepare'; tabId: number; cipherId: string }
  | { type: 'autofill.manual.cancel'; authorizationId: string }
  | { type: 'autofill.continuation.status' }
  | { type: 'autofill.continuation.cancel'; continuationId: string }
  | { type: 'autofill.continuation.resumeUnlock'; continuationId: string }
  | {
      type: 'autofill.continuation.authorizeReprompt';
      continuationId: string;
      masterPassword: string;
    }
  | {
      type: 'autofill.manual.commit';
      authorizationId: string;
      action: ManualAutofillAction;
      masterPassword?: string;
    };

/**
 * Content autofill requests carry this field only on the wire. It is optional in the public request
 * shape so callers can attach it through the non-enumerable binding consumed by `sendRequest`.
 */
export type RequestMessage = RequestMessageBody & { readonly runtimeIncarnation?: string };

export type ResponseMessage =
  | {
      ok: true;
      data: { state: SessionState; restriction?: PasswordChangeRequirement };
    }
  | { ok: true; data: AuthResult }
  | { ok: true; data: RegistrationStartAuthResult }
  | { ok: true; data: RegistrationCompleteAuthResult }
  | { ok: true; data: PasswordHintResult }
  | { ok: true; data: PendingLoginPublicStatus }
  | { ok: true; data: SsoLoginPublicStatus }
  | { ok: true; data: { status: 'waiting' } }
  | { ok: true; data: { required: boolean } }
  | { ok: true; data: AccountPasskeyBeginData }
  | { ok: true; data: AccountPasskeyStatusData }
  | { ok: true; data: DeviceLoginRequesterResultData }
  | { ok: true; data: { cancelled: boolean } }
  | { ok: true; data: { approvals: readonly BoundDeviceLoginApprovalData[] } }
  | { ok: true; data: { approval: BoundDeviceLoginApprovalData } }
  | { ok: true; data: { decision: DeviceLoginDecisionReceiptData } }
  | { ok: true; data: { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[]; orgPermissions: OrgPermission[]; personalCreationAllowed?: boolean } }
  | { ok: true; data: { value?: string; clientEventAckId?: string } }
  | { ok: true; data: { cipher: DecryptedCipher | null; clientEventAckId?: string } }
  | { ok: true; data: { input: CipherInput | null; clientEventAckId?: string } }
  | { ok: true; data: { totp: TotpResult | null } }
  | { ok: true; data: { totpEntries: TotpListEntry[] } }
  | { ok: true; data: { count: number } }
  | { ok: true; data: OrganizationDataOwnershipStatus }
  | { ok: true; data: { identity?: string; lastSuccessfulSyncAt?: number; dirty: boolean; syncing: boolean } }
  | { ok: true; data: { entries: PasswordHealthEntry[] } }
  | { ok: true; data: { entries: Array<{ id: string; pwnedCount: number }> } }
  | { ok: true; data: { history: Array<{ password: string; lastUsedDate?: string }> } }
  | { ok: true; data: { fileName: string; dataB64: string } }
  | { ok: true; data: { available: boolean } }
  | { ok: true; data: { sshKey: SshKeyPublicDetails | null } }
  | { ok: true; data: { privateKey: string | null } }
  | { ok: true; data: PinStatusData }
  | { ok: true; data: { remembered: boolean } }
  | { ok: true; data: { verified: boolean; authorization?: RepromptAutofillAuthorizationData } }
  | { ok: true; data: { authorizationId: string; expiresAt: number } }
  | { ok: true; data: { approval: WebsitePasskeyApprovalModel | null } }
  | { ok: true; data: { outcome: WebsitePasskeyDecisionOutcome } }
  | { ok: true; data: { accounts: AccountSummary[] } }
  | { ok: true; data: SettingsGetData }
  | { ok: true; data: GeneratorHistoryListData }
  | { ok: true; data: GeneratorHistoryTrackData }
  | { ok: true; data: GeneratorHistoryClearData }
  | { ok: true; data: null }
  | { ok: true; data: AutofillCandidate[] }
  | { ok: true; data: FillItemCandidate[] }
  | { ok: true; data: { intentId: string } }
  | { ok: true; data: { keyboardGrantId: string } }
  | { ok: true; data: { status: 'active' } }
  | { ok: true; data: { repromptContinuationId: string } }
  | { ok: true; data: { login: AutofillLoginData; clientEventAckId?: string; totpCopyAckId?: string } }
  | { ok: true; data: AutofillInteractiveLoginData }
  | { ok: true; data: { totp: AutofillTotpData; clientEventAckId?: string } }
  | { ok: true; data: { copied: boolean } }
  | { ok: true; data: AutofillClientConfig }
  | { ok: true; data: { trackToken: string } }
  | { ok: true; data: AutofillSavePrompt }
  | { ok: true; data: { sends: SendSummary[] } }
  | { ok: true; data: { send: SendSummary } }
  | { ok: true; data: { outcome: TabSuggestionsOutcome } }
  | { ok: true; data: { outcome: TabFillOutcome } }
  | { ok: true; data: ManualAutofillPreparationData }
  | { ok: true; data: { outcome: ManualAutofillCommitOutcome } }
  | { ok: true; data: AutofillContinuationStatusData }
  | { ok: true; data: AutofillContinuationResumeData }
  | { ok: true; data: WebsitePasskeyLockedStatusData }
  | { ok: true; data: WebsitePasskeyLockedResumeData }
  | { ok: true; data: { verified: boolean; result?: AutofillContinuationResumeData } }
  | { ok: false; error: { code: AppErrorCode; message: string } };

export type ClientRequestMessage = RequestMessage;

const AUTOFILL_RUNTIME_BINDING_PROPERTY = '__miyuAutofillRuntimeIncarnation';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export async function sendRequest(request: ClientRequestMessage): Promise<ResponseMessage> {
  if (request.type === 'vault.setCipherFavorite' && !isExactCipherFavoriteRequest(request)) {
    return {
      ok: false,
      error: { code: 'denied', message: 'Invalid cipher favorite request.' },
    };
  }
  if (request.type === 'auth.requestPasswordHint' && !isExactPasswordHintRequest(request)) {
    return {
      ok: false,
      error: { code: 'denied', message: 'Invalid password hint request.' },
    };
  }
  if (request.type.startsWith('auth.sso.') && !isExactSsoRequest(request)) {
    return {
      ok: false,
      error: { code: 'denied', message: 'Invalid SSO request.' },
    };
  }
  if (request.type === 'auth.openTwoFactorRecovery' && !isExactTwoFactorRecoveryRequest(request)) {
    return {
      ok: false,
      error: { code: 'denied', message: 'Invalid two-step recovery request.' },
    };
  }
  if (request.type === 'auth.setPin' || request.type === 'auth.unlockWithPin') {
    const violation = pinConstraintViolation(request.pin);
    if (violation) {
      return { ok: false, error: { code: 'error', message: pinConstraintMessage(violation) } };
    }
  }
  // A content script orphaned by an extension reload / update / disable keeps running in an already-open
  // tab but loses its runtime connection: `browser.runtime` (or its `.id`) becomes undefined and any
  // sendMessage throws "Extension context invalidated". Fail closed with a typed error so callers see
  // `ok:false` instead of an uncaught promise rejection (and recurring surfaces stop hammering a dead
  // channel). In a live context (popup/options/valid content script) this is a plain sendMessage.
  const runtime = (browser as { runtime?: { id?: string; sendMessage(msg: unknown): Promise<unknown> } }).runtime;
  if (!runtime?.id) {
    return { ok: false, error: { code: 'error', message: 'Extension context invalidated' } };
  }
  try {
    return (await runtime.sendMessage(runtimeBoundWireRequest(request))) as ResponseMessage;
  } catch (cause) {
    return { ok: false, error: { code: 'error', message: cause instanceof Error ? cause.message : String(cause) } };
  }
}

function runtimeBoundWireRequest(request: ClientRequestMessage): ClientRequestMessage {
  const descriptor = Object.getOwnPropertyDescriptor(request, AUTOFILL_RUNTIME_BINDING_PROPERTY);
  if (!descriptor) return request;
  if (descriptor.enumerable || !('value' in descriptor)) {
    throw new TypeError('Autofill runtime binding is invalid');
  }
  if (typeof descriptor.value !== 'string' || !UUID_V4.test(descriptor.value)) {
    throw new TypeError('Autofill runtime incarnation is invalid');
  }
  return { ...request, runtimeIncarnation: descriptor.value };
}

function isExactSsoRequest(input: unknown): boolean {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return false;
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  const typeDescriptor = Object.getOwnPropertyDescriptor(input, 'type');
  if (!typeDescriptor?.enumerable || !('value' in typeDescriptor)) return false;
  const type = typeDescriptor.value;
  const expected = type === 'auth.sso.begin'
    ? ['type', 'email', ...(Object.hasOwn(input, 'organizationIdentifier')
      ? ['organizationIdentifier']
      : [])]
    : type === 'auth.sso.requirement'
      ? ['type', 'email']
    : type === 'auth.sso.status'
      ? ['type', ...(Object.hasOwn(input, 'attemptId') ? ['attemptId', 'generation'] : [])]
    : type === 'auth.sso.cancel'
      ? ['type', 'attemptId', 'generation']
      : [];
  if (expected.length === 0) return false;
  const keys = Reflect.ownKeys(input);
  if (keys.length !== expected.length || keys.some((key) => (
    typeof key !== 'string' || !expected.includes(key)
  ))) return false;
  const exactShape = keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
  if (!exactShape) return false;
  if (type === 'auth.sso.cancel' || type === 'auth.sso.status' && expected.length === 3) {
    const attemptId = Object.getOwnPropertyDescriptor(input, 'attemptId')?.value as unknown;
    const generation = Object.getOwnPropertyDescriptor(input, 'generation')?.value as unknown;
    return typeof attemptId === 'string'
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(attemptId)
      && Number.isSafeInteger(generation)
      && (generation as number) > 0;
  }
  return true;
}

/** Whether this (content-script) context still has a live connection to the extension. False once the
 *  extension is reloaded/updated and the current script is an orphan — callers can then go dormant. */
export function isExtensionContextAlive(): boolean {
  try {
    return Boolean((browser as { runtime?: { id?: string } }).runtime?.id);
  } catch {
    return false;
  }
}
