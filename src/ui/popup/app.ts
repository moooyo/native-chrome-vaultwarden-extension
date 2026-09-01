import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import {
  sendRequest,
  type AccountPasskeyBeginData,
  type AccountPasskeyStatusData,
  type AutofillContinuationResumeData,
  type AutofillContinuationStatusData,
  type DeviceLoginDecisionBindingData,
  type DeviceLoginRequesterResultData,
  type ManualAutofillAction,
  type ManualAutofillAuthorizationData,
  type ManualAutofillCommitOutcome,
  type ManualAutofillPreparationData,
  type ManualAutofillWarningData,
  type PendingLoginPublicStatus,
  type PinStatusData,
  type RepromptAutofillAuthorizationData,
  type ResponseMessage,
  type WebsitePasskeyLockedStatusData,
} from '../../messaging/protocol.js';
import type { AuthResult, Fido2TwoFactorChallenge, RegistrationStartAuthResult } from '../../core/session/auth-service.js';
import type { OrganizationDataOwnershipStatus } from '../../core/vault/vault-service.js';
import {
  createInteractiveTwoFactorOwner,
  sameInteractiveTwoFactorOwner,
} from '../../core/session/interactive-two-factor.js';
import { DEVICE_LOGIN_REQUEST_TTL_MS } from '../../core/session/device-login.js';
import type { SessionState } from '../../core/session/session-manager.js';
import type { SsoLoginPublicStatus } from '../../core/session/sso-login.js';
import {
  DEFAULT_MASTER_PASSWORD_MIN_LENGTH,
  MASTER_PASSWORD_HINT_MAX_LENGTH,
  masterPasswordHintValidationError,
  parsePasswordChangeRequirement,
  type PasswordChangeRequirement,
} from '../../core/policy/master-password-policy.js';
import {
  CARD_FIELDS,
  IDENTITY_FIELDS,
  isActiveCipher,
  isCipherInactive,
  isKnownCipherType,
} from '../../core/vault/models.js';
import type {
  CipherInput,
  CipherSummary,
  CollectionSummary,
  DecryptedCipher,
  DecryptedField,
  FieldName,
  FolderSummary,
  SshKeyPublicDetails,
  TotpListEntry,
} from '../../core/vault/models.js';
import type { OrgPermission } from '../../core/vault/org-permissions.js';
import {
  isPasswordProtectedField,
  summaryAllowsCipherAccess,
  type CipherAccessAction,
} from '../../core/vault/cipher-access.js';
import { NO_FOLDER } from '../../core/vault/search.js';
import type {
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionTarget,
  TabSuggestionsOutcome,
} from '../../messaging/protocol.js';
import { themeTokens, paletteTokens } from '../components/tokens.js';
import { getLocale, initLocale, t } from '../i18n/index.js';
import { initAppearance, AppearanceController } from '../theme.js';
import { getPrefs, initPrefs, subscribePrefs } from '../prefs.js';
import '../components/status-message.js';
import '../components/toast.js';
import './popup-frame.js';
import {
  preferredTwoFactorProvider,
  usableTwoFactorProviders,
} from './auth/auth-views.js';
import './auth/device-login-view.js';
import './vault/popup-header.js';
import './vault/vault-view.js';
import './vault/manual-autofill-confirmation.js';
import './vault/vault-filters.js';
import './vault/totp-view.js';
import './vault/sync-bar.js';
import './menus/tools-menu.js';
import './menus/account-menu.js';
import type { CategoryId } from './vault/vault-view.js';
import type { ManualAutofillActionDetail } from './vault/manual-autofill-confirmation.js';
import './item/item-detail.js';
import './item/reprompt-gate.js';
import './editor/type-picker.js';
import './editor/cipher-editor.js';
import './editor/ssh-key-editor.js';
import './passkey/website-passkey-view.js';
import './tools/generator-view.js';
import './tools/health-view.js';
import './tools/sends-view.js';
import './tools/account-security-view.js';
import './tools/pin-view.js';
import './tools/data-ownership-view.js';
import type {
  DataOwnershipLeaveDetail,
  DataOwnershipMigrationModel,
  DataOwnershipMigrationSubmitDetail,
} from './tools/data-ownership-view.js';
import { safeWebUrl, triggerDownload } from './utils.js';
import {
  parseContextMenuCreateIntent,
  type ContextMenuCreateIntent,
} from '../../messaging/context-menu-create.js';
import {
  parseGeneratorHistoryEntries,
  type GeneratorHistoryEntry,
} from '../../core/generator/history.js';
import {
  parseGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  type GeneratorPolicySnapshot,
} from '../../core/generator/enterprise-password-policy.js';
import type { AsyncState } from '../components/async-state.js';
import type {
  EmailTwoFactorCodeRequestDetail,
  EmailChangeDetail,
  DeviceLoginStartDetail,
  DuoTwoFactorStartDetail,
  Fido2TwoFactorStartDetail,
  ForcedPasswordChangeSubmitDetail,
  LoginSubmitDetail,
  NewDeviceVerificationSubmitDetail,
  PinUnlockSubmitDetail,
  RegisterFinishSubmitDetail,
  RegisterSubmitDetail,
  SsoLoginStartDetail,
  TwoFactorProviderChangeDetail,
  TwoFactorSubmitDetail,
  UnlockSubmitDetail,
} from './auth/auth-views.js';
import type {
  PasswordHintEmailDetail,
  PasswordHintStatus,
} from './auth/password-hint-view.js';
import type {
  DeviceLoginApprovalRequestDisplay,
  DeviceLoginApproverDetailViewModel,
  DeviceLoginApproverListViewModel,
  DeviceLoginFingerprint,
  DeviceLoginLabels,
  DeviceLoginRequestActionDetail,
  DeviceLoginRequesterViewModel,
} from './auth/device-login-view.js';
import type {
  AccountActionDetail,
  AccountInfo,
  AttachmentAddDetail,
  AttachmentRefDetail,
  CollectionMutateDetail,
  CloneItemDetail,
  CopyDetail,
  DeleteItemDetail,
  DetailErrorDetail,
  DetailExtras,
  DetailPresentationMetadata,
  DetailStatus,
  EditorCreateDefaults,
  FavoriteToggleDetail,
  FillResult,
  FilterChangeDetail,
  FolderMutateDetail,
  ItemLifecycleDetail,
  ItemOpenDetail,
  ItemRefDetail,
  PasskeyDeleteDetail,
  PopupBrowser,
  PopupClientEventPurpose,
  PopupRequest,
  PopupRoute,
  PopupSyncStatus,
  RepromptSubmitDetail,
  SecretRequestDetail,
  SshCreateGenerateDetail,
  SshCreateImportDetail,
  SshDetailExtras,
  SshReplaceKeyDetail,
  SshUpdateMetadataDetail,
  SuggestionFillDetail,
  SuggestionsViewState,
  ToolActionDetail,
  VaultMode,
  VaultModeChangeDetail,
} from './types.js';
import { PERSONAL_VAULT_FILTER_ID } from './types.js';
import type {
  ChangeKdfDetail,
  ChangePasswordDetail,
  GeneratorHistoryAddDetail,
  HealthEntry,
  PinSetDetail,
  PwnedState,
  RotateKeyDetail,
  SendCreateDetail,
  SendDeleteDetail,
  SendSummary,
  SendUpdateDetail,
} from './types.js';
import type {
  CipherCollectionsDetail,
  EditorContext,
  EditorSaveDetail,
  EditorShareDetail,
  EditorTotpCapture,
  EditorTypeDetail,
} from './editor/editor-types.js';
import { decodeTotpQr } from './editor/totp-capture.js';
import type {
  WebsitePasskeyApproveDetail,
  WebsitePasskeyCancelDetail,
  WebsitePasskeyDisplayChoice,
  WebsitePasskeyFallbackDetail,
  WebsitePasskeyViewModel,
} from './passkey/website-passkey-view.js';
import {
  parseWebsitePasskeyLockedStatus,
  parseWebsitePasskeyUnlockQuery,
  type WebsitePasskeyUnlockQuery,
} from './passkey/website-passkey-unlock-query.js';

const SYNC_STATUS_POLL_MS = 250;
const DEVICE_LOGIN_STATUS_POLL_MS = 5_000;
const VAULT_SYNC_METADATA_KEY = 'vaultSyncSchedulerMetadata';
const VAULT_SYNC_METADATA_SCHEMA_VERSION = 1;

interface VaultSyncMetadataChange {
  readonly oldValue?: unknown;
  readonly newValue?: unknown;
}

interface PendingVaultSyncSuccess {
  readonly lastSuccess: number;
  readonly refreshEvenIfStatusCaughtUp: boolean;
}

interface ExternalSyncRefresh {
  readonly workspaceGeneration: number;
  readonly identity: string;
  readonly lastSuccess: number;
}

interface SyncSuccessCursor extends ExternalSyncRefresh {
  readonly metadataObserved: boolean;
}

interface EditorWorkspaceSnapshot {
  readonly routeKey: string;
  readonly draftKey: string;
  readonly summary?: CipherSummary;
  readonly createDefaults?: EditorCreateDefaults;
  readonly returnRoute: PopupRoute;
  readonly returnVaultMode: VaultMode;
  readonly folders: readonly FolderSummary[];
  readonly collections: readonly CollectionSummary[];
  readonly orgPermissions: readonly OrgPermission[];
  readonly personalCreationAllowed: boolean;
}

interface EditorNavigationSetup {
  readonly createDefaults?: EditorCreateDefaults;
  readonly returnRoute: PopupRoute;
  readonly returnVaultMode: VaultMode;
  readonly preserveReprompt: boolean;
}

/** The auth-related route names `VwAuthViews` renders; everything else is out of this task's scope. */
type AuthRoute = Extract<PopupRoute, {
  name: 'login' | 'passwordHint' | 'register' | 'registrationFinish' | 'registrationCheckEmail' | 'newDeviceVerification' | 'twoFactor' | 'sso' | 'accountPasskey' | 'restricted' | 'unlock';
}>;

type WebsitePasskeyQuery =
  | { readonly kind: 'none' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'ceremony'; readonly ceremonyId: string };

const WEBSITE_PASSKEY_QUERY = 'websitePasskey';
const WEBSITE_PASSKEY_POPUP_PATH = '/ui/popup/popup.html';
const WEBSITE_PASSKEY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_ACKNOWLEDGED_CLIENT_EVENT_IDS = 256;

type AccountPasskeyPopupOutcome =
  | 'unlocked'
  | 'locked'
  | 'cancelled'
  | 'expired'
  | 'failed'
  | 'two_factor_unsupported'
  | 'outcome_unknown'
  | 'unavailable';

type AccountPasskeyQuery =
  | { readonly kind: 'none' | 'invalid' }
  | { readonly kind: 'outcome'; readonly outcome: AccountPasskeyPopupOutcome };

const ACCOUNT_PASSKEY_QUERY = 'accountPasskey';
const ACCOUNT_PASSKEY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACCOUNT_PASSKEY_OUTCOMES = new Set<AccountPasskeyPopupOutcome>([
  'unlocked',
  'locked',
  'cancelled',
  'expired',
  'failed',
  'two_factor_unsupported',
  'outcome_unknown',
  'unavailable',
]);
const DEVICE_LOGIN_APPROVAL_QUERY = 'deviceLoginApprovals';

function websitePasskeyQuery(href: string): WebsitePasskeyQuery {
  let url: URL;
  try { url = new URL(href); } catch { return { kind: 'none' }; }
  const entries = [...url.searchParams.entries()];
  if (!entries.some(([name]) => name === WEBSITE_PASSKEY_QUERY)) return { kind: 'none' };
  if (url.pathname !== WEBSITE_PASSKEY_POPUP_PATH || url.hash || entries.length !== 1) return { kind: 'invalid' };
  const [name, ceremonyId] = entries[0]!;
  return name === WEBSITE_PASSKEY_QUERY && WEBSITE_PASSKEY_ID.test(ceremonyId)
    ? { kind: 'ceremony', ceremonyId }
    : { kind: 'invalid' };
}

function accountPasskeyQuery(href: string): AccountPasskeyQuery {
  let url: URL;
  try { url = new URL(href); } catch { return { kind: 'none' }; }
  const entries = [...url.searchParams.entries()];
  if (!entries.some(([name]) => name === ACCOUNT_PASSKEY_QUERY)) return { kind: 'none' };
  if (url.pathname !== WEBSITE_PASSKEY_POPUP_PATH || url.hash || entries.length !== 1) {
    return { kind: 'invalid' };
  }
  const [name, rawOutcome] = entries[0]!;
  return name === ACCOUNT_PASSKEY_QUERY
    && ACCOUNT_PASSKEY_OUTCOMES.has(rawOutcome as AccountPasskeyPopupOutcome)
    ? { kind: 'outcome', outcome: rawOutcome as AccountPasskeyPopupOutcome }
    : { kind: 'invalid' };
}

function opensDeviceLoginApprovalList(href: string): boolean {
  let url: URL;
  try { url = new URL(href); } catch { return false; }
  const entries = [...url.searchParams.entries()];
  return url.pathname === WEBSITE_PASSKEY_POPUP_PATH
    && !url.hash
    && entries.length === 1
    && entries[0]?.[0] === DEVICE_LOGIN_APPROVAL_QUERY
    && entries[0]?.[1] === '1';
}

function accountPasskeyStatus(value: unknown): AccountPasskeyStatusData | AccountPasskeyBeginData | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.getPrototypeOf(record) !== Object.prototype && Object.getPrototypeOf(record) !== null) {
    return undefined;
  }
  if (record.status === 'none') {
    return Reflect.ownKeys(record).length === 1 ? record as AccountPasskeyStatusData : undefined;
  }
  if (record.status === 'unavailable') {
    const reasons = new Set([
      'host_access_unavailable',
      'connector_context_failed',
      'options_busy',
      'options_invalid_connector',
      'options_server_changed',
      'options_request_failed',
      'options_unavailable',
    ]);
    return Reflect.ownKeys(record).length === 2 && reasons.has(record.reason as string)
      ? record as AccountPasskeyBeginData
      : undefined;
  }
  if (record.status === 'waiting') {
    return Reflect.ownKeys(record).length === 3
      && typeof record.attemptId === 'string'
      && ACCOUNT_PASSKEY_ID.test(record.attemptId)
      && Number.isSafeInteger(record.expiresAt)
      && (record.expiresAt as number) >= 0
      ? record as unknown as AccountPasskeyStatusData
      : undefined;
  }
  if (record.status === 'outcome_unknown') {
    return Reflect.ownKeys(record).length === 3
      && typeof record.attemptId === 'string'
      && ACCOUNT_PASSKEY_ID.test(record.attemptId)
      && Number.isSafeInteger(record.terminalAt)
      && (record.terminalAt as number) >= 0
      ? record as unknown as AccountPasskeyStatusData
      : undefined;
  }
  return undefined;
}

function accountPasskeyCancelResult(value: unknown): boolean | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const prototype = Object.getPrototypeOf(record);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  return Reflect.ownKeys(record).length === 1 && typeof record.cancelled === 'boolean'
    ? record.cancelled
    : undefined;
}

function ownString(record: Record<string, unknown>, key: string, max: number): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(record, key)) return undefined;
  const value = record[key];
  return typeof value === 'string' && value.length > 0 && value.length <= max ? value : undefined;
}

function websitePasskeyChoices(value: unknown): WebsitePasskeyDisplayChoice[] | undefined {
  if (!Array.isArray(value) || value.length > 100) return undefined;
  const choices: WebsitePasskeyDisplayChoice[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return undefined;
    const record = item as Record<string, unknown>;
    const id = ownString(record, 'id', 4_096);
    const name = ownString(record, 'name', 1_000);
    if (!id || !name) return undefined;
    const usernameValue = record.username;
    if (usernameValue !== undefined && (typeof usernameValue !== 'string' || usernameValue.length > 1_000)) return undefined;
    choices.push({ id, name, ...(typeof usernameValue === 'string' ? { username: usernameValue } : {}) });
  }
  return choices;
}

/** Strictly project the coordinator DTO so unknown request/challenge/key fields are never retained. */
function websitePasskeyViewModel(value: unknown, expectedCeremonyId: string): WebsitePasskeyViewModel | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const ceremonyId = ownString(record, 'ceremonyId', 64);
  const origin = ownString(record, 'origin', 2_048);
  const rpId = ownString(record, 'rpId', 253);
  const state = record.state;
  if (ceremonyId !== expectedCeremonyId || !origin || !rpId || (state !== 'awaiting' && state !== 'executing')) return undefined;
  if (record.kind === 'get') {
    const candidates = websitePasskeyChoices(record.candidates);
    return candidates ? { ceremonyId, kind: 'get', origin, rpId, state, candidates } : undefined;
  }
  if (record.kind === 'create') {
    const targets = websitePasskeyChoices(record.targets);
    return targets ? { ceremonyId, kind: 'create', origin, rpId, state, targets } : undefined;
  }
  return undefined;
}

const DEVICE_LOGIN_REQUEST_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SSO_ATTEMPT_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DEVICE_LOGIN_BASE64URL = /^[A-Za-z0-9_-]+$/u;
const DEVICE_LOGIN_UNSAFE_TEXT = /[\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ufeff]/u;

function deviceLoginRecord(value: unknown, allowed: readonly string[]): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const keys = Reflect.ownKeys(value);
  if (keys.length > allowed.length || keys.some((key) => typeof key !== 'string' || !allowed.includes(key))) {
    return undefined;
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) return undefined;
  }
  return value as Record<string, unknown>;
}

function deviceLoginSafeText(value: unknown, maximum: number): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) return undefined;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return undefined;
  }
  return DEVICE_LOGIN_UNSAFE_TEXT.test(value) ? undefined : value;
}

function deviceLoginTimestamp(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function deviceLoginOrigin(value: unknown): string | undefined {
  const text = deviceLoginSafeText(value, 2_048);
  if (!text) return undefined;
  try {
    const parsed = new URL(text);
    return parsed.username || parsed.password || parsed.origin !== text ? undefined : text;
  } catch {
    return undefined;
  }
}

function deviceLoginFingerprint(value: unknown): DeviceLoginFingerprint | undefined {
  const text = deviceLoginSafeText(value, 512);
  if (!text) return undefined;
  const words = text.split('-');
  if (words.length !== 5 || words.some((word) => !deviceLoginSafeText(word, 64) || word.trim() !== word)) {
    return undefined;
  }
  return Object.freeze(words) as unknown as DeviceLoginFingerprint;
}

function deviceLoginProviders(value: unknown): readonly number[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) return undefined;
  const providers: number[] = [];
  for (const provider of value as unknown[]) {
    if (typeof provider !== 'number' || !Number.isSafeInteger(provider)
      || provider < 0 || provider > 255 || providers.includes(provider)) {
      return undefined;
    }
    providers.push(provider);
  }
  return Object.freeze(providers);
}

/** Accept only the metadata-only continuation projection. In particular, no password hash,
 * continuation token, KDF material, or FIDO request data is retained by the Popup. */
function pendingLoginStatus(value: unknown): PendingLoginPublicStatus | undefined {
  const record = deviceLoginRecord(value, [
    'status', 'attemptId', 'continuationId', 'providers', 'fido2', 'serverOrigin', 'email',
    'createdAt', 'expiresAt', 'terminalAt',
  ]);
  if (!record || typeof record.status !== 'string') return undefined;
  if (record.status === 'none') {
    return Reflect.ownKeys(record).length === 1 ? Object.freeze({ status: 'none' }) : undefined;
  }
  if (record.status === 'newDeviceVerification') {
    const attemptId = deviceLoginTimestamp(record.attemptId);
    const continuationId = deviceLoginSafeText(record.continuationId, 36);
    const expiresAt = deviceLoginTimestamp(record.expiresAt);
    return Reflect.ownKeys(record).length === 4
      && attemptId !== undefined && attemptId > 0
      && continuationId !== undefined && DEVICE_LOGIN_REQUEST_ID.test(continuationId)
      && expiresAt !== undefined && expiresAt > 0
      ? Object.freeze({ status: record.status, attemptId, continuationId, expiresAt })
      : undefined;
  }
  if (record.status === 'twoFactor') {
    const attemptId = deviceLoginTimestamp(record.attemptId);
    const continuationId = deviceLoginSafeText(record.continuationId, 36);
    const providers = deviceLoginProviders(record.providers);
    const expiresAt = deviceLoginTimestamp(record.expiresAt);
    const fido2 = record.fido2 === undefined
      ? undefined
      : parseInteractiveChallenge(record.fido2, 'password', attemptId, continuationId);
    const expectedKeys = record.fido2 === undefined ? 5 : 6;
    return Reflect.ownKeys(record).length === expectedKeys
      && attemptId !== undefined && attemptId > 0
      && continuationId !== undefined && DEVICE_LOGIN_REQUEST_ID.test(continuationId)
      && providers !== undefined
      && (record.fido2 === undefined || fido2 !== undefined)
      && expiresAt !== undefined && expiresAt > 0
      ? Object.freeze({
          status: record.status,
          attemptId,
          continuationId,
          providers,
          ...(fido2 ? { fido2 } : {}),
          expiresAt,
        })
      : undefined;
  }
  if (record.status !== 'outcome_unknown' || Reflect.ownKeys(record).length !== 6) return undefined;
  const serverOrigin = deviceLoginOrigin(record.serverOrigin);
  const email = deviceLoginSafeText(record.email, 254);
  const createdAt = deviceLoginTimestamp(record.createdAt);
  const expiresAt = deviceLoginTimestamp(record.expiresAt);
  const terminalAt = deviceLoginTimestamp(record.terminalAt);
  return serverOrigin && email && email.trim() === email && createdAt !== undefined
    && expiresAt !== undefined && expiresAt > createdAt
    && terminalAt !== undefined && terminalAt >= createdAt && terminalAt <= expiresAt
    ? Object.freeze({ status: record.status, serverOrigin, email, createdAt, expiresAt, terminalAt })
    : undefined;
}

function ssoLoginStatus(value: unknown): SsoLoginPublicStatus | undefined {
  const record = deviceLoginRecord(value, [
    'status', 'attemptId', 'generation', 'email', 'createdAt', 'expiresAt', 'terminalAt', 'message',
  ]);
  if (!record || typeof record.status !== 'string') return undefined;
  if (record.status === 'none') {
    return Reflect.ownKeys(record).length === 1 ? Object.freeze({ status: 'none' }) : undefined;
  }
  if (record.status === 'error') {
    const message = deviceLoginSafeText(record.message, 1_024);
    return Reflect.ownKeys(record).length === 2 && message
      ? Object.freeze({ status: record.status, message })
      : undefined;
  }
  const email = deviceLoginSafeText(record.email, 254);
  const attemptId = deviceLoginSafeText(record.attemptId, 36);
  const generation = deviceLoginTimestamp(record.generation);
  const expiresAt = deviceLoginTimestamp(record.expiresAt);
  if (!attemptId || !SSO_ATTEMPT_ID.test(attemptId) || generation === undefined || generation <= 0
      || !email || !email.includes('@') || email !== email.trim().toLowerCase()
      || expiresAt === undefined) {
    return undefined;
  }
  if (record.status === 'waiting' || record.status === 'processing') {
    return Reflect.ownKeys(record).length === 5
      ? Object.freeze({ status: record.status, attemptId, generation, email, expiresAt })
      : undefined;
  }
  if (record.status !== 'outcome_unknown' || Reflect.ownKeys(record).length !== 7) return undefined;
  const createdAt = deviceLoginTimestamp(record.createdAt);
  const terminalAt = deviceLoginTimestamp(record.terminalAt);
  return createdAt !== undefined && terminalAt !== undefined
    && createdAt <= terminalAt && terminalAt < expiresAt
    ? Object.freeze({ status: record.status, attemptId, generation, email, createdAt, expiresAt, terminalAt })
    : undefined;
}

function parseInteractiveChallenge(
  value: unknown,
  flow: 'password' | 'deviceLogin',
  generation: number | undefined,
  bindingId?: string,
): Fido2TwoFactorChallenge | undefined {
  if (generation === undefined) return undefined;
  const wrapper = deviceLoginRecord(value, ['owner']);
  const rawOwner = wrapper ? deviceLoginRecord(wrapper.owner, [
    'flow', 'generation', 'serverUrl', 'bindingId',
  ]) : undefined;
  if (!wrapper || Reflect.ownKeys(wrapper).length !== 1 || !rawOwner) return undefined;
  try {
    const owner = createInteractiveTwoFactorOwner(rawOwner as never);
    if (owner.flow !== flow || owner.generation !== generation
      || (bindingId !== undefined && owner.bindingId !== bindingId)) return undefined;
    return Object.freeze({ owner });
  } catch {
    return undefined;
  }
}

function deviceLoginLabels(): Readonly<DeviceLoginLabels> {
  return Object.freeze({
    requesterTitle: t('auth.deviceLogin.requesterTitle'),
    waitingTitle: t('auth.deviceLogin.waitingTitle'),
    waitingDescription: t('auth.deviceLogin.waitingDescription'),
    serverApprovalHint: t('auth.deviceLogin.serverApprovalHint'),
    compareFingerprintHint: t('auth.deviceLogin.compareFingerprintHint'),
    expiresIn: t('auth.deviceLogin.expiresIn'),
    expiredTitle: t('auth.deviceLogin.expiredTitle'),
    expiredDescription: t('auth.deviceLogin.expiredDescription'),
    expired: t('auth.deviceLogin.expired'),
    checkNow: t('auth.deviceLogin.checkNow'),
    approverListTitle: t('auth.deviceLogin.approverListTitle'),
    approverListDescription: t('auth.deviceLogin.approverListDescription'),
    approverDetailTitle: t('auth.deviceLogin.approverDetailTitle'),
    noRequests: t('auth.deviceLogin.noRequests'),
    deviceType: t('auth.deviceLogin.deviceType'),
    deviceIdentifier: t('auth.deviceLogin.deviceIdentifier'),
    ipAddress: t('auth.deviceLogin.ipAddress'),
    createdAt: t('auth.deviceLogin.createdAt'),
    approve: t('auth.deviceLogin.approve'),
    deny: t('auth.deviceLogin.deny'),
    unavailable: t('auth.deviceLogin.unavailable'),
    deviceName: t('auth.deviceLogin.deviceName'),
    notKnownTitle: t('auth.deviceLogin.notKnownTitle'),
    notKnownDescription: t('auth.deviceLogin.notKnownDescription'),
    deniedTitle: t('auth.deviceLogin.deniedTitle'),
    deniedDescription: t('auth.deviceLogin.deniedDescription'),
    twoFactorUnsupportedTitle: t('auth.deviceLogin.twoFactorUnsupportedTitle'),
    twoFactorUnsupportedDescription: t('auth.deviceLogin.twoFactorUnsupportedDescription'),
    retryRequiredTitle: t('auth.deviceLogin.retryRequiredTitle'),
    retryRequiredDescription: t('auth.deviceLogin.retryRequiredDescription'),
    outcomeUnknownTitle: t('auth.deviceLogin.outcomeUnknownTitle'),
    outcomeUnknownDescription: t('auth.deviceLogin.outcomeUnknownDescription'),
    errorTitle: t('auth.deviceLogin.errorTitle'),
    errorDescription: t('auth.deviceLogin.errorDescription'),
    retry: t('auth.deviceLogin.retry'),
    dismiss: t('auth.deviceLogin.dismiss'),
    checkAccountState: t('auth.deviceLogin.checkAccountState'),
  });
}

function deviceLoginRequesterResult(value: unknown): DeviceLoginRequesterResultData | undefined {
  const record = deviceLoginRecord(value, [
    'status', 'fingerprint', 'serverOrigin', 'email', 'deviceName', 'expiresAt', 'providers',
    'createdAt', 'terminalAt', 'generation', 'fido2',
  ]);
  if (!record || typeof record.status !== 'string') return undefined;
  const status = record.status;
  if (['none', 'not_known_device', 'denied', 'expired', 'restricted', 'unlocked'].includes(status)) {
    return Reflect.ownKeys(record).length === 1
      ? Object.freeze({ status }) as DeviceLoginRequesterResultData
      : undefined;
  }
  if (status === 'outcome_unknown') {
    if (Reflect.ownKeys(record).length !== 6) return undefined;
    const generation = deviceLoginGenerationValue(record.generation);
    const serverOrigin = deviceLoginOrigin(record.serverOrigin);
    const createdAt = deviceLoginTimestamp(record.createdAt);
    const expiresAt = deviceLoginTimestamp(record.expiresAt);
    const terminalAt = deviceLoginTimestamp(record.terminalAt);
    if (generation === undefined || !serverOrigin
      || createdAt === undefined || expiresAt === undefined || terminalAt === undefined
      || expiresAt <= createdAt || terminalAt < createdAt) return undefined;
    return Object.freeze({ status, generation, serverOrigin, createdAt, expiresAt, terminalAt });
  }
  if (status !== 'pending' && status !== 'two_factor'
    && status !== 'retry_required' && status !== 'two_factor_unsupported') return undefined;
  const generation = deviceLoginGenerationValue(record.generation);
  const fingerprint = deviceLoginFingerprint(record.fingerprint);
  const serverOrigin = deviceLoginOrigin(record.serverOrigin);
  const email = deviceLoginSafeText(record.email, 254);
  const deviceName = deviceLoginSafeText(record.deviceName, 128);
  const expiresAt = deviceLoginTimestamp(record.expiresAt);
  if (generation === undefined || !fingerprint || !serverOrigin
    || !email || !deviceName || expiresAt === undefined) return undefined;
  const context = {
    generation,
    fingerprint: fingerprint.join('-'),
    serverOrigin,
    email,
    deviceName,
    expiresAt,
  };
  const providers = record.providers === undefined ? undefined : deviceLoginProviders(record.providers);
  if ((status === 'two_factor' || status === 'two_factor_unsupported') && !providers) return undefined;
  if (status === 'pending' && (record.providers !== undefined || record.fido2 !== undefined)) return undefined;
  if (record.providers !== undefined && !providers) return undefined;
  let fido2: Fido2TwoFactorChallenge | undefined;
  if (record.fido2 !== undefined) {
    const wrapper = deviceLoginRecord(record.fido2, ['owner']);
    const rawOwner = wrapper ? deviceLoginRecord(wrapper.owner, [
      'flow', 'generation', 'serverUrl', 'bindingId',
    ]) : undefined;
    if (!wrapper || Reflect.ownKeys(wrapper).length !== 1 || !rawOwner) return undefined;
    try {
      const owner = createInteractiveTwoFactorOwner(rawOwner as never);
      if (owner.flow !== 'deviceLogin' || owner.generation !== generation) return undefined;
      fido2 = Object.freeze({ owner });
    } catch {
      return undefined;
    }
  }
  if (record.fido2 !== undefined && !fido2) return undefined;
  if (fido2 && (!providers?.includes(7) || status === 'two_factor_unsupported')) return undefined;
  const expectedKeys = 7 + (providers ? 1 : 0) + (fido2 ? 1 : 0);
  if (Reflect.ownKeys(record).length !== expectedKeys) return undefined;
  return Object.freeze({
    status,
    ...(providers ? { providers } : {}),
    ...(fido2 ? { fido2 } : {}),
    ...context,
  }) as DeviceLoginRequesterResultData;
}

function deviceLoginGenerationValue(value: unknown): number | undefined {
  return Number.isSafeInteger(value) && (value as number) > 0 ? value as number : undefined;
}

function deviceLoginBinding(value: unknown): DeviceLoginDecisionBindingData | undefined {
  const fields = [
    'version', 'requestId', 'publicKeyDigest', 'requestDeviceIdentifier', 'creationDate',
    'requestDeviceTypeValue', 'nonce', 'proof',
  ] as const;
  const record = deviceLoginRecord(value, fields);
  if (!record || Reflect.ownKeys(record).length !== fields.length || record.version !== 1) return undefined;
  const requestId = deviceLoginSafeText(record.requestId, 36);
  const publicKeyDigest = deviceLoginSafeText(record.publicKeyDigest, 43);
  const requestDeviceIdentifier = deviceLoginSafeText(record.requestDeviceIdentifier, 255);
  const creationDate = deviceLoginSafeText(record.creationDate, 64);
  const nonce = deviceLoginSafeText(record.nonce, 22);
  const proof = deviceLoginSafeText(record.proof, 43);
  const requestDeviceTypeValue = record.requestDeviceTypeValue;
  if (!requestId || !DEVICE_LOGIN_REQUEST_ID.test(requestId)
    || !publicKeyDigest || publicKeyDigest.length !== 43 || !DEVICE_LOGIN_BASE64URL.test(publicKeyDigest)
    || !requestDeviceIdentifier || !creationDate || !Number.isFinite(Date.parse(creationDate))
    || typeof requestDeviceTypeValue !== 'number' || !Number.isSafeInteger(requestDeviceTypeValue)
    || requestDeviceTypeValue < 0 || requestDeviceTypeValue > 255
    || !nonce || nonce.length !== 22 || !DEVICE_LOGIN_BASE64URL.test(nonce)
    || !proof || proof.length !== 43 || !DEVICE_LOGIN_BASE64URL.test(proof)) return undefined;
  return Object.freeze({
    version: 1,
    requestId: requestId.toLowerCase(),
    publicKeyDigest,
    requestDeviceIdentifier,
    creationDate,
    requestDeviceTypeValue,
    nonce,
    proof,
  });
}

interface ProjectedDeviceLoginApproval {
  readonly display: DeviceLoginApprovalRequestDisplay;
  readonly binding: DeviceLoginDecisionBindingData;
  readonly expiresAt: number;
}

function deviceLoginApproval(value: unknown, now = Date.now()): ProjectedDeviceLoginApproval | undefined {
  const wrapper = deviceLoginRecord(value, ['view', 'decisionBinding']);
  if (!wrapper || Reflect.ownKeys(wrapper).length !== 2) return undefined;
  const binding = deviceLoginBinding(wrapper.decisionBinding);
  const view = deviceLoginRecord(wrapper.view, [
    'id', 'fingerprint', 'requestDeviceType', 'requestDeviceTypeValue',
    'requestDeviceIdentifier', 'requestIpAddress', 'requestCountryName', 'creationDate',
    'creationTime', 'expiresAt', 'requestDeviceId', 'origin',
  ]);
  if (!binding || !view) return undefined;
  const id = deviceLoginSafeText(view.id, 36);
  const fingerprint = deviceLoginFingerprint(view.fingerprint);
  const deviceType = view.requestDeviceType === undefined
    ? ''
    : deviceLoginSafeText(view.requestDeviceType, 512);
  const deviceIdentifier = deviceLoginSafeText(view.requestDeviceIdentifier, 255);
  const ipAddress = view.requestIpAddress === undefined ? undefined : deviceLoginSafeText(view.requestIpAddress, 128);
  const country = view.requestCountryName === undefined ? undefined : deviceLoginSafeText(view.requestCountryName, 512);
  const creationDate = deviceLoginSafeText(view.creationDate, 64);
  const creationTime = deviceLoginTimestamp(view.creationTime);
  const expiresAt = deviceLoginTimestamp(view.expiresAt);
  const requestDeviceId = view.requestDeviceId === undefined ? undefined : deviceLoginSafeText(view.requestDeviceId, 36);
  const origin = view.origin === undefined ? undefined : deviceLoginSafeText(view.origin, 512);
  const requestDeviceTypeValue = view.requestDeviceTypeValue;
  if (!id || !DEVICE_LOGIN_REQUEST_ID.test(id) || !fingerprint || deviceType === undefined
    || !deviceIdentifier || (ipAddress === undefined && view.requestIpAddress !== undefined)
    || (country === undefined && view.requestCountryName !== undefined)
    || !creationDate || creationTime === undefined || expiresAt === undefined
    || Date.parse(creationDate) !== creationTime || expiresAt <= creationTime
    || expiresAt - creationTime !== DEVICE_LOGIN_REQUEST_TTL_MS
    || typeof requestDeviceTypeValue !== 'number' || !Number.isSafeInteger(requestDeviceTypeValue)
    || requestDeviceTypeValue < 0 || requestDeviceTypeValue > 255
    || (requestDeviceId !== undefined && !DEVICE_LOGIN_REQUEST_ID.test(requestDeviceId))
    || (origin === undefined && view.origin !== undefined)
    || id.toLowerCase() !== binding.requestId
    || binding.requestDeviceIdentifier !== deviceIdentifier
    || binding.creationDate !== creationDate
    || binding.requestDeviceTypeValue !== requestDeviceTypeValue) return undefined;
  const createdAt = new Intl.DateTimeFormat(getLocale(), {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(creationTime));
  const display: DeviceLoginApprovalRequestDisplay = Object.freeze({
    requestId: binding.requestId,
    status: now >= expiresAt ? 'expired' : 'pending',
    deviceType,
    deviceIdentifier,
    ...(ipAddress ? { ipAddress } : {}),
    ...(country ? { country } : {}),
    createdAt,
    fingerprint,
  });
  return Object.freeze({ display, binding, expiresAt });
}

function deviceLoginApprovalList(value: unknown): {
  readonly requests: readonly DeviceLoginApprovalRequestDisplay[];
  readonly bindings: ReadonlyMap<string, { readonly binding: DeviceLoginDecisionBindingData; readonly expiresAt: number }>;
} | undefined {
  if (!Array.isArray(value) || value.length > 100) return undefined;
  const requests: DeviceLoginApprovalRequestDisplay[] = [];
  const bindings = new Map<string, { readonly binding: DeviceLoginDecisionBindingData; readonly expiresAt: number }>();
  for (const item of value) {
    const projected = deviceLoginApproval(item);
    if (!projected) continue;
    if (bindings.has(projected.display.requestId)) return undefined;
    requests.push(projected.display);
    bindings.set(projected.display.requestId, Object.freeze({
      binding: projected.binding,
      expiresAt: projected.expiresAt,
    }));
  }
  return Object.freeze({ requests: Object.freeze(requests), bindings });
}

function validDeviceLoginDecisionReceipt(
  value: unknown,
  requestId: string,
  approved: boolean,
): boolean {
  const wrapper = deviceLoginRecord(value, ['decision']);
  if (!wrapper || Reflect.ownKeys(wrapper).length !== 1) return false;
  const decision = deviceLoginRecord(wrapper.decision, ['requestId', 'requestApproved', 'responseDate']);
  if (!decision || Reflect.ownKeys(decision).length !== 3) return false;
  const responseRequestId = deviceLoginSafeText(decision.requestId, 36);
  const responseDate = deviceLoginSafeText(decision.responseDate, 64);
  return Boolean(
    responseRequestId
    && responseRequestId.toLowerCase() === requestId
    && decision.requestApproved === approved
    && responseDate
    && Number.isFinite(Date.parse(responseDate)),
  );
}

function loginRoute(error?: string, notice?: string): PopupRoute {
  return {
    name: 'login',
    ...(error === undefined ? {} : { error }),
    ...(notice === undefined ? {} : { notice }),
  };
}

function registerRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'register' } : { name: 'register', error };
}

function passwordHintRoute(
  email: string,
  state: {
    readonly status?: PasswordHintStatus;
    readonly message?: string;
    readonly error?: string;
  } = {},
): PopupRoute {
  return {
    name: 'passwordHint',
    email,
    ...(state.status === undefined ? {} : { status: state.status }),
    ...(state.message === undefined ? {} : { message: state.message }),
    ...(state.error === undefined ? {} : { error: state.error }),
  };
}

function ssoRoute(status: Exclude<SsoLoginPublicStatus['status'], 'none'>, input?: {
  readonly attemptId?: string;
  readonly generation?: number;
  readonly email?: string;
  readonly error?: string;
}): PopupRoute {
  return {
    name: 'sso',
    status,
    ...(input?.attemptId ? { attemptId: input.attemptId } : {}),
    ...(input?.generation ? { generation: input.generation } : {}),
    ...(input?.email ? { email: input.email } : {}),
    ...(input?.error ? { error: input.error } : {}),
  };
}

function registrationFinishRoute(
  route: Extract<PopupRoute, { name: 'registrationFinish' }>,
  error?: string,
): PopupRoute {
  const { error: _error, ...base } = route;
  return error === undefined ? base : { ...base, error };
}

function parseOrganizationDataOwnershipStatus(value: unknown): OrganizationDataOwnershipStatus {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { status: 'unavailable' };
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if ((record.status === 'not_required'
        || record.status === 'compliant'
        || record.status === 'unavailable')
      && keys.length === 1 && keys[0] === 'status') {
    return { status: record.status };
  }
  if (record.status === 'reconciliation_required'
      && keys.join(',') === 'operation,reason,status'
      && (record.operation === 'migrate' || record.operation === 'leave')
      && (record.reason === 'outcome_unknown' || record.reason === 'committed_unsynced')) {
    return {
      status: record.status,
      operation: record.operation,
      reason: record.reason,
    };
  }
  const migrateAuthorization = parseOrganizationDataOwnershipAuthorization(
    record.migrateAuthorization,
  );
  const leaveAuthorization = parseOrganizationDataOwnershipAuthorization(
    record.leaveAuthorization,
  );
  if (record.status === 'migration_available'
      && keys.join(',') === 'collectionId,leaveAuthorization,migrateAuthorization,organizationId,personalItemCount,status'
      && typeof record.organizationId === 'string'
      && record.organizationId.length > 0
      && record.organizationId.length <= 4_096
      && typeof record.collectionId === 'string'
      && record.collectionId.length > 0
      && record.collectionId.length <= 4_096
      && migrateAuthorization !== undefined
      && leaveAuthorization !== undefined
      && Number.isSafeInteger(record.personalItemCount)
      && (record.personalItemCount as number) > 0) {
    return {
      status: 'migration_available',
      organizationId: record.organizationId,
      collectionId: record.collectionId,
      personalItemCount: record.personalItemCount as number,
      migrateAuthorization,
      leaveAuthorization,
    };
  }
  if (record.status === 'blocked'
      && keys.join(',') === 'leaveAuthorization,organizationId,personalItemCount,reason,status'
      && typeof record.organizationId === 'string'
      && record.organizationId.length > 0
      && record.organizationId.length <= 4_096
      && leaveAuthorization !== undefined
      && Number.isSafeInteger(record.personalItemCount)
      && (record.personalItemCount as number) > 0
      && (record.reason === 'target_unavailable'
        || record.reason === 'unsupported_items')) {
    return {
      status: 'blocked',
      organizationId: record.organizationId,
      personalItemCount: record.personalItemCount as number,
      reason: record.reason,
      leaveAuthorization,
    };
  }
  return { status: 'unavailable' };
}

function parseOrganizationDataOwnershipAuthorization(
  value: unknown,
): { readonly authorizationId: string; readonly expiresAt: number } | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'authorizationId,expiresAt'
      || typeof record.authorizationId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(record.authorizationId)
      || typeof record.expiresAt !== 'number'
      || !Number.isFinite(record.expiresAt)
      || record.expiresAt <= 0) return undefined;
  return Object.freeze({
    authorizationId: record.authorizationId,
    expiresAt: record.expiresAt,
  });
}

interface ManualAutofillConfirmationState {
  readonly cipherId: string;
  readonly tabId: number;
  readonly name: string;
  readonly warning: ManualAutofillWarningData;
  readonly authorization: ManualAutofillAuthorizationData;
  readonly action?: ManualAutofillAction;
}

type RepromptFillContinuation =
  | {
      readonly kind: 'matched';
      readonly cipherId: string;
      readonly tabId: number;
      readonly target: TabSuggestionTarget;
    }
  | { readonly kind: 'manual'; readonly cipherId: string };

function parseManualAutofillPreparation(value: unknown): ManualAutofillPreparationData | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'authorization,warning') return undefined;
  const authorization = parseOrganizationDataOwnershipAuthorization(record.authorization);
  if (!authorization || typeof record.warning !== 'object' || record.warning === null
      || Array.isArray(record.warning)) return undefined;
  const warning = record.warning as Record<string, unknown>;
  const warningKeys = Object.keys(warning).sort().join(',');
  if ((warningKeys !== 'canSave,requiresReprompt,risk,site'
        && warningKeys !== 'canSave,recipientSite,requiresReprompt,risk,site')
      || (warning.risk !== 'no_match'
        && warning.risk !== 'never'
        && warning.risk !== 'https_downgrade')
      || typeof warning.site !== 'string'
      || warning.site.length === 0
      || warning.site.length > 1_024
      || (warning.recipientSite !== undefined
        && (typeof warning.recipientSite !== 'string'
          || warning.recipientSite.length === 0
          || warning.recipientSite.length > 1_024))
      || typeof warning.canSave !== 'boolean'
      || typeof warning.requiresReprompt !== 'boolean') return undefined;
  return Object.freeze({
    warning: Object.freeze({
      risk: warning.risk,
      site: warning.site,
      ...(warning.recipientSite === undefined ? {} : { recipientSite: warning.recipientSite }),
      canSave: warning.canSave,
      requiresReprompt: warning.requiresReprompt,
    }),
    authorization,
  });
}

function parseAutofillContinuationStatus(
  value: unknown,
): Exclude<AutofillContinuationStatusData, { status: 'none' }> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const common = typeof record.continuationId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(record.continuationId)
    && (record.channel === 'context' || record.channel === 'keyboard')
    && Number.isSafeInteger(record.expiresAt)
    && (record.expiresAt as number) > Date.now();
  if (!common) return null;
  if (record.status === 'unlock_required'
      && Object.keys(record).sort().join(',') === 'channel,continuationId,expiresAt,status') {
    return Object.freeze({
      status: record.status,
      continuationId: record.continuationId as string,
      channel: record.channel as 'context' | 'keyboard',
      expiresAt: record.expiresAt as number,
    });
  }
  if (record.status === 'reprompt_required'
      && Object.keys(record).sort().join(',') === 'channel,cipherId,continuationId,expiresAt,status'
      && typeof record.cipherId === 'string' && record.cipherId.length > 0 && record.cipherId.length <= 4_096) {
    return Object.freeze({
      status: record.status,
      continuationId: record.continuationId as string,
      channel: record.channel as 'context' | 'keyboard',
      cipherId: record.cipherId,
      expiresAt: record.expiresAt as number,
    });
  }
  return null;
}

function unlockRoute(error?: string, notice?: string): PopupRoute {
  return {
    name: 'unlock',
    ...(error === undefined ? {} : { error }),
    ...(notice === undefined ? {} : { notice }),
  };
}

function restrictedRoute(
  requirement: PasswordChangeRequirement,
  error?: string,
): PopupRoute {
  return {
    name: 'restricted',
    requirement,
    ...(error === undefined ? {} : { error }),
  };
}

function restrictionFromStateData(value: unknown): PasswordChangeRequirement | undefined {
  if (typeof value !== 'object' || value === null || !('restriction' in value)) return undefined;
  try {
    return parsePasswordChangeRequirement((value as { restriction: unknown }).restriction);
  } catch {
    return undefined;
  }
}

function accountPasskeyRoute(
  status: Exclude<AccountPasskeyPopupOutcome, 'unlocked' | 'locked'> | 'waiting',
): PopupRoute {
  return { name: 'accountPasskey', status };
}

/** Copy only Popup-safe metadata out of a worker suggestion. This runtime projection prevents an
 *  accidental future response widening from retaining credential or structured-fill values. */
function toPopupSuggestion(suggestion: TabAutofillSuggestion): TabAutofillSuggestion | undefined {
  if (suggestion.kind === 'login') {
    return {
      kind: 'login',
      id: suggestion.id,
      name: suggestion.name,
      matchedUri: suggestion.matchedUri,
      matchType: suggestion.matchType,
      favorite: suggestion.favorite,
      ...(suggestion.username !== undefined ? { username: suggestion.username } : {}),
      ...(suggestion.hasTotp !== undefined ? { hasTotp: suggestion.hasTotp } : {}),
      ...(suggestion.reprompt !== undefined ? { reprompt: suggestion.reprompt } : {}),
      ...(suggestion.target !== undefined
        ? {
            target: {
              kind: 'login',
              frameId: suggestion.target.frameId,
              documentId: suggestion.target.documentId,
              runtimeIncarnation: suggestion.target.runtimeIncarnation,
              formId: suggestion.target.formId,
              generation: suggestion.target.generation,
              customPlanDigest: suggestion.target.customPlanDigest,
            },
          }
        : {}),
    };
  }
  const metadata = {
    id: suggestion.id,
    name: suggestion.name,
    favorite: suggestion.favorite,
    ...(suggestion.subtitle !== undefined ? { subtitle: suggestion.subtitle } : {}),
    ...(suggestion.reprompt !== undefined ? { reprompt: suggestion.reprompt } : {}),
  };
  if (suggestion.kind === 'card' && suggestion.target.kind === 'card') {
    return {
      kind: 'card',
      ...metadata,
      target: {
        kind: 'card',
        frameId: suggestion.target.frameId,
        documentId: suggestion.target.documentId,
        runtimeIncarnation: suggestion.target.runtimeIncarnation,
        formId: suggestion.target.formId,
        generation: suggestion.target.generation,
        roles: [...suggestion.target.roles],
      },
    };
  }
  if (suggestion.kind === 'identity' && suggestion.target.kind === 'identity') {
    return {
      kind: 'identity',
      ...metadata,
      target: {
        kind: 'identity',
        frameId: suggestion.target.frameId,
        documentId: suggestion.target.documentId,
        runtimeIncarnation: suggestion.target.runtimeIncarnation,
        formId: suggestion.target.formId,
        generation: suggestion.target.generation,
        roles: [...suggestion.target.roles],
      },
    };
  }
  return undefined;
}

function twoFactorRoute(
  providers: number[],
  fido2?: Fido2TwoFactorChallenge,
  error?: string,
  flow: 'password' | 'device' = 'password',
  continuationId?: string,
): PopupRoute {
  return {
    name: 'twoFactor',
    flow,
    providers,
    ...(fido2 ? { fido2 } : {}),
    ...(continuationId ? { continuationId } : {}),
    ...(error !== undefined ? { error } : {}),
  };
}

function newDeviceVerificationRoute(
  result: Extract<AuthResult, { kind: 'newDeviceVerification' }>,
): Extract<PopupRoute, { name: 'newDeviceVerification' }> | undefined {
  if (
    !Number.isSafeInteger(result.attemptId)
    || result.attemptId <= 0
    || !Number.isSafeInteger(result.expiresAt)
    || result.expiresAt <= 0
  ) return undefined;
  return {
    name: 'newDeviceVerification',
    attemptId: result.attemptId,
    ...(result.continuationId ? { continuationId: result.continuationId } : {}),
    expiresAt: result.expiresAt,
  };
}

function fillTargetKey(target: TabSuggestionTarget): string {
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

/** The real `PopupBrowser`, backed by `webextension-polyfill`. */
function createDefaultBrowser(): PopupBrowser {
  return {
    async getActiveTabId() {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      return tabs[0]?.id;
    },
    async getActiveTabUrl() {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      return tabs[0]?.url;
    },
    async captureVisibleTab() {
      return browser.tabs.captureVisibleTab(undefined, { format: 'png' });
    },
    async openOptions() {
      await browser.runtime.openOptionsPage();
    },
    async openReceive() {
      await browser.tabs.create({ url: browser.runtime.getURL('ui/receive/receive.html') });
    },
    async openUrl(url: string) {
      const normalized = url.includes('://') ? url : `https://${url}`;
      // Gate the (possibly org-shared/crafted) stored URI down to http/https before navigating — a
      // routine click must never open a file:/chrome:/javascript: scheme in a new tab.
      const safe = safeWebUrl(normalized);
      if (safe !== undefined) await browser.tabs.create({ url: safe });
    },
  };
}

function successfulSyncAdvances(change: VaultSyncMetadataChange): Map<string, number> {
  const previous = parseVaultSyncSuccesses(change.oldValue);
  const next = parseVaultSyncSuccesses(change.newValue);
  if (!next) return new Map();
  const advances = new Map<string, number>();
  for (const [identity, lastSuccess] of next) {
    if (lastSuccess > (previous?.get(identity) ?? -1)) advances.set(identity, lastSuccess);
  }
  return advances;
}

function parseVaultSyncSuccesses(value: unknown): Map<string, number> | undefined {
  if (!isVaultSyncRecord(value)
    || value.schemaVersion !== VAULT_SYNC_METADATA_SCHEMA_VERSION
    || !isVaultSyncRecord(value.identities)) return undefined;
  const successes = new Map<string, number>();
  for (const [identity, rawEntry] of Object.entries(value.identities)) {
    if (!identity || !isVaultSyncRecord(rawEntry) || !isVaultSyncTimestamp(rawEntry.lastAttempt)) return undefined;
    if (rawEntry.lastSuccess === undefined) continue;
    if (!isVaultSyncTimestamp(rawEntry.lastSuccess)) return undefined;
    successes.set(identity, rawEntry.lastSuccess);
  }
  return successes;
}

function isVaultSyncRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isVaultSyncTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function editorRouteKey(route: Extract<PopupRoute, { name: 'editor' }>): string {
  return `${route.mode}|${route.cipherId ?? ''}|${route.cipherType ?? ''}`;
}

/** Project only fields that a new cipher may inherit. Runtime-only ids, lifecycle metadata,
 * attachments, passkeys, and password history never cross this clone boundary. */
function cloneCipherInput(input: CipherInput): CipherInput {
  const clone: CipherInput = { type: input.type, name: input.name };
  if (input.notes !== undefined) clone.notes = input.notes;
  if (input.favorite !== undefined) clone.favorite = input.favorite;
  if (input.reprompt !== undefined) clone.reprompt = input.reprompt;
  if (input.folderId !== undefined) clone.folderId = input.folderId;
  if (input.fields !== undefined) {
    clone.fields = input.fields.map((field) => ({
      type: field.type,
      name: field.name,
      ...(field.value === undefined ? {} : { value: field.value }),
      ...(field.linkedId === undefined ? {} : { linkedId: field.linkedId }),
    }));
  }
  if (input.type === 1 && input.login !== undefined) {
    clone.login = {
      ...(input.login.username === undefined ? {} : { username: input.login.username }),
      ...(input.login.password === undefined ? {} : { password: input.login.password }),
      ...(input.login.totp === undefined ? {} : { totp: input.login.totp }),
      ...(input.login.uris === undefined
        ? {}
        : { uris: input.login.uris.map((uri) => ({ ...uri })) }),
      ...(input.login.autofillOnPageLoad === undefined
        ? {}
        : { autofillOnPageLoad: input.login.autofillOnPageLoad }),
    };
  } else if (input.type === 3 && input.card !== undefined) {
    clone.card = Object.fromEntries(CARD_FIELDS
      .filter((field) => input.card?.[field] !== undefined)
      .map((field) => [field, input.card![field]]));
  } else if (input.type === 4 && input.identity !== undefined) {
    clone.identity = Object.fromEntries(IDENTITY_FIELDS
      .filter((field) => input.identity?.[field] !== undefined)
      .map((field) => [field, input.identity![field]]));
  }
  return clone;
}

/**
 * The live Lit popup root. It owns routing, in-flight state, and ephemeral auth/vault/tool state.
 * Every worker request runs through the injectable `request` seam; child views receive plain props
 * and emit typed actions. `popup.ts` mounts this element and supplies the browser integration seam.
 */
export class VwPopupApp extends LitElement {
  static override properties = {
    route: { attribute: false },
    pending: { type: Boolean },
    pinEnabled: { type: Boolean },
    pinAllowed: { type: Boolean },
    pinRequireMasterPasswordOnRestart: { type: Boolean },
    deviceRemembered: { type: Boolean },
    deviceForgotten: { type: Boolean },
    ssoRequired: { type: Boolean },
    items: { attribute: false },
    folders: { attribute: false },
    collections: { attribute: false },
    orgPermissions: { attribute: false },
    personalCreationAllowed: { type: Boolean },
    skippedOrgCount: { type: Number },
    selectedFolderId: { attribute: false },
    selectedCollectionId: { attribute: false },
    selectedOrganizationId: { attribute: false },
    query: { type: String },
    vaultMode: { type: String },
    suggestionsState: { attribute: false },
    totpEntries: { attribute: false },
    fillResult: { attribute: false },
    accounts: { attribute: false },
    pinConfigured: { type: Boolean },
    vaultDeviceRemembered: { type: Boolean },
    detailCipher: { attribute: false },
    detailStatus: { attribute: false },
    repromptError: { attribute: false },
    editorInput: { attribute: false },
    editorStatus: { attribute: false },
    editorTotpCapture: { attribute: false },
    sshWriteAvailability: { type: String },
    sshKeyDetails: { attribute: false },
    sshEditorCipher: { attribute: false },
    sshEditorPublicDetails: { attribute: false },
    generatorHistory: { attribute: false },
    generatorPolicy: { attribute: false },
    healthReport: { attribute: false },
    pwnedState: { attribute: false },
    sendsState: { attribute: false },
    sendEncoding: { type: Boolean },
    toolStatus: { attribute: false },
    vaultScope: { type: String },
    selectedCipherId: { attribute: false },
    category: { type: String },
    syncStatus: { attribute: false },
    toastMessage: { type: String },
    websitePasskeyModel: { attribute: false },
    deviceLoginRequesterModel: { attribute: false },
    deviceLoginApprovalModel: { attribute: false },
    deviceLoginApprovalCount: { type: Number },
    organizationDataOwnershipStatus: { attribute: false },
    dataOwnershipError: { type: String },
  };

  declare route: PopupRoute;
  declare pending: boolean;
  declare pinEnabled: boolean;
  declare pinAllowed: boolean;
  declare pinRequireMasterPasswordOnRestart: boolean;
  declare deviceRemembered: boolean;
  declare deviceForgotten: boolean;
  declare ssoRequired: boolean;
  declare items: CipherSummary[];
  declare folders: FolderSummary[];
  declare collections: CollectionSummary[];
  declare orgPermissions: OrgPermission[];
  declare personalCreationAllowed: boolean;
  declare skippedOrgCount: number;
  declare selectedFolderId: string | null;
  declare selectedCollectionId: string | null;
  declare selectedOrganizationId: string | null;
  declare query: string;
  declare vaultMode: VaultMode;
  declare suggestionsState: SuggestionsViewState;
  declare totpEntries: TotpListEntry[];
  declare fillResult: FillResult;
  declare accounts: AccountInfo[];
  declare pinConfigured: boolean;
  declare vaultDeviceRemembered: boolean;
  /** The secret-stripped detail (structure/attachments/plain custom fields) for the open item, or
   *  `null` while loading or when no detail is open. Never carries a masked secret. */
  declare detailCipher: DecryptedCipher | null;
  /** Copy/reveal/attachment feedback banner the root drives on the open detail. */
  declare detailStatus: DetailStatus | undefined;
  /** The reprompt gate's error message (wrong/failed master-password verification). */
  declare repromptError: string | undefined;
  /** The reprompt-gated editable plaintext for the item open in the editor, or `null` while loading
   *  (or in create mode). Held only for the editor's lifetime; cleared on every navigation. */
  declare editorInput: CipherInput | null;
  /** Request-error/success banner the root drives on the open editor (save/collections/share). */
  declare editorStatus: DetailStatus | undefined;
  declare editorTotpCapture: EditorTotpCapture | undefined;
  declare sshWriteAvailability: 'idle' | 'loading' | 'available' | 'unavailable';
  declare sshKeyDetails: SshKeyPublicDetails | null | undefined;
  declare sshEditorCipher: DecryptedCipher | null;
  declare sshEditorPublicDetails: SshKeyPublicDetails | null | undefined;
  /** Decrypted worker history for the active unlocked generator view only. */
  declare generatorHistory: readonly GeneratorHistoryEntry[];
  declare generatorPolicy: GeneratorPolicySnapshot;
  /** The local password-health report, loaded on entry to the health route. */
  declare healthReport: AsyncState<HealthEntry[]>;
  /** The explicit HIBP breach-count result, loaded only on the user's `vw-health-check`. */
  declare pwnedState: PwnedState;
  /** The current account's Sends, loaded on entry to the sends route. */
  declare sendsState: AsyncState<SendSummary[]>;
  /** True while the Send view is reading and encoding a local file before it emits a request. */
  declare sendEncoding: boolean;
  /** Copy/create/update feedback banner the root drives on the open tool view (Sends, account
   *  security, PIN). Only one tool route is active at a time, so a single banner suffices. */
  declare toolStatus: DetailStatus | undefined;
  declare vaultScope: 'suggestions' | 'all';
  declare selectedCipherId: string | null;
  /** The active category-chip filter for the vault list. */
  declare category: CategoryId;
  /** Latest scheduler-owned sync snapshot, or null while the status is unknown. */
  declare syncStatus: PopupSyncStatus | null;
  /** Transient copy-confirmation toast text (empty = hidden). */
  declare toastMessage: string;
  declare websitePasskeyModel: WebsitePasskeyViewModel | undefined;
  declare deviceLoginRequesterModel: DeviceLoginRequesterViewModel | undefined;
  declare deviceLoginApprovalModel:
    | DeviceLoginApproverListViewModel
    | DeviceLoginApproverDetailViewModel
    | undefined;
  declare deviceLoginApprovalCount: number;
  declare organizationDataOwnershipStatus: OrganizationDataOwnershipStatus;
  declare dataOwnershipError: string | undefined;

  /** Injectable worker request function; defaults to the real messaging channel. */
  request: PopupRequest = sendRequest;

  /** Injectable browser seam; defaults to the real `webextension-polyfill`-backed implementation. */
  browser: PopupBrowser = createDefaultBrowser();

  /** The email last checked/shown by the login screen's remembered-device banner. */
  private deviceCheckEmail = '';

  /** Active TOTP countdown interval for an open login detail. Dormant in this task (no detail
   *  view exists yet) — reserved for the task that adds it; `navigate()` always clears it. */
  private totpTimer: number | undefined;

  /** Countdown interval for the 2FA (authenticator) view — ticks each code's `remaining` and refetches
   *  the batch when a code rolls over. Cleared whenever we navigate away from the totp route. */
  private totpListTimer: number | undefined;

  /** Master-password reprompt credential, held only for the duration of a reprompt-gated item's
   *  detail/editor view. Dormant in this task (no detail view sets it yet) — reserved for the
   *  task that adds it; `navigate()` and `disconnectedCallback()` always clear it. */
  private repromptCredential: { cipherId: string; masterPassword: string } | null = null;

  /** ACK ids are document-bound, one-shot capabilities. Keep them private to the root and suppress
   *  duplicate callbacks before sending so a repeated render cannot replay an acknowledgement. */
  private acknowledgedClientEventIds = new Set<string>();

  /** One background-issued capability for this Popup document and one exact fill target. */
  private repromptAutofillAuthorization: ({
    cipherId: string;
    tabId: number;
    targetKey: string;
  } & RepromptAutofillAuthorizationData) | null = null;
  private manualAutofillConfirmation: ManualAutofillConfirmationState | null = null;
  private repromptFillContinuation: RepromptFillContinuation | null = null;
  private autofillContinuation: Exclude<AutofillContinuationStatusData, { status: 'none' }> | null = null;
  private preserveManualAutofillOnNavigation = false;

  /** Memoized detail extras, keyed by cipher id + verified-credential presence, so the detail
   *  component gets a stable set of loaders across re-renders (avoids restarting TOTP on churn). */
  private detailExtrasCache: { key: string; extras: DetailExtras } | undefined;

  /** The active tab whose Suggestions are currently shown; the Fill target for `handleSuggestionFill`.
   *  Re-resolved on every vault entry — the popup never trusts a remembered tab across sessions. */
  private activeTabId: number | undefined;

  /** Monotonic counter incremented at the start of each `loadSuggestions`. A run only commits its
   *  result while it still holds the latest ticket, so an earlier request that resolves late (rapid
   *  enterVault / account-switch overlap) can never overwrite a newer one. */
  private latestSuggestionsSeq = 0;

  /** Last-writer-wins ticket for cache listing reads inside one workspace. */
  private latestListingSeq = 0;
  private latestGeneratorPolicySeq = 0;
  private latestGeneratorHistorySeq = 0;

  /** Invalidates late tool feedback so an older clipboard promise cannot overwrite a newer Send
   *  mutation result or a status belonging to a different tool route. */
  private toolStatusEpoch = 0;

  /** Invalidates every async result owned by a previous lock/account/workspace generation. */
  private workspaceGeneration = 0;

  /** Invalidates pending login results and connector messages from a previous authentication attempt. */
  private authAttemptGeneration = 0;
  /** Non-secret provider preference, retained only for one in-memory pending authentication attempt. */
  private twoFactorSelection: { readonly attemptKey: string; readonly provider: number } | undefined;
  private newDeviceVerificationExpiryTimer: number | undefined;

  /** Last-writer-wins ticket for overlapping sync-status reads in the same workspace. */
  private latestSyncStatusSeq = 0;

  /** Short-lived poll while the scheduler reports an active sync. It is revoked on every workspace
   *  transition so an old account can never update the new account's sync controls. */
  private syncStatusPollTimer: number | undefined;
  private syncSuccessCursor: SyncSuccessCursor | undefined;
  private pendingVaultSyncSuccesses = new Map<string, PendingVaultSyncSuccess>();
  private pendingExternalSyncRefresh: ExternalSyncRefresh | undefined;
  private externalSyncRefreshActive = false;

  /** Frozen editor inputs/list metadata; background refreshes update the vault without resetting a form. */
  private editorWorkspaceSnapshot: EditorWorkspaceSnapshot | undefined;
  private editorNavigationSetup: EditorNavigationSetup | undefined;
  private editorDraftSequence = 0;
  private newItemStartSequence = 0;
  private pendingContextMenuCreate: ContextMenuCreateIntent | undefined;
  private lastContextMenuCreateIntentId: string | undefined;
  private vaultDataReadyGeneration: number | undefined;

  /** Prevents duplicate open notifications if the same element is reconnected. */
  private popupOpenedSent = false;
  private openDeviceLoginApprovals = false;

  /** Invalidates detail data, secret loaders, and feedback owned by an earlier item/view. */
  private detailEpoch = 0;
  private favoriteMutationSequence = 0;

  /** Last-writer-wins ticket for SSH capability probes inside one workspace. */
  private sshAvailabilitySeq = 0;

  /** Stable private-key loader for the currently open SSH detail. */
  private sshDetailExtrasCache: { key: string; extras: SshDetailExtras } | undefined;

  private websitePasskeyQuery: WebsitePasskeyQuery = { kind: 'none' };
  private websitePasskeyUnlockQuery: WebsitePasskeyUnlockQuery = { kind: 'none' };
  private websitePasskeyLockedContinuation:
    | Extract<WebsitePasskeyLockedStatusData, { status: 'unlock_required' }>
    | undefined;
  private websitePasskeyLockedCleanupSent = false;
  private websitePasskeyGeneration = 0;
  private websitePasskeyActionGeneration = 0;
  private websitePasskeyCleanupEligible = false;
  private websitePasskeyCleanupSent = false;

  private deviceLoginGeneration = 0;
  private deviceLoginCountdownTimer: number | undefined;
  private deviceLoginStatusPollTimer: number | undefined;
  private deviceLoginExpiresAt: number | undefined;
  private deviceLoginApprovalGeneration = 0;
  private deviceLoginApprovalBindings = new Map<string, {
    readonly binding: DeviceLoginDecisionBindingData;
    readonly expiresAt: number;
    readonly workspaceGeneration: number;
  }>();

  private unsubscribePrefs: (() => void) | undefined;
  private vaultSyncMetadataListenerInstalled = false;
  private editorTotpCaptureRevision = 0;
  private dataOwnershipCheckPending = false;
  constructor() {
    super();
    this.route = { name: 'loading' };
    this.pending = false;
    this.pendingContextMenuCreate = undefined;
    this.lastContextMenuCreateIntentId = undefined;
    this.vaultDataReadyGeneration = undefined;
    this.pinEnabled = false;
    this.pinAllowed = false;
    this.pinRequireMasterPasswordOnRestart = true;
    this.deviceRemembered = false;
    this.deviceForgotten = false;
    this.ssoRequired = false;
    this.items = [];
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.personalCreationAllowed = false;
    this.skippedOrgCount = 0;
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
    this.selectedOrganizationId = null;
    this.query = '';
    this.vaultMode = 'active';
    this.suggestionsState = { status: 'loading' };
    this.totpEntries = [];
    this.fillResult = {};
    this.accounts = [];
    this.pinConfigured = false;
    this.vaultDeviceRemembered = false;
    this.detailCipher = null;
    this.detailStatus = undefined;
    this.repromptError = undefined;
    this.editorInput = null;
    this.editorStatus = undefined;
    this.editorTotpCapture = undefined;
    this.sshWriteAvailability = 'idle';
    this.sshKeyDetails = undefined;
    this.sshEditorCipher = null;
    this.sshEditorPublicDetails = undefined;
    this.generatorHistory = [];
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    this.healthReport = { status: 'idle' };
    this.pwnedState = { status: 'idle' };
    this.sendsState = { status: 'idle' };
    this.sendEncoding = false;
    this.toolStatus = undefined;
    this.vaultScope = 'suggestions';
    this.selectedCipherId = null;
    this.category = 'all';
    this.syncStatus = null;
    this.organizationDataOwnershipStatus = { status: 'unavailable' };
    this.dataOwnershipError = undefined;
    this.toastMessage = '';
    this.websitePasskeyModel = undefined;
    this.deviceLoginRequesterModel = undefined;
    this.deviceLoginApprovalModel = undefined;
    this.deviceLoginApprovalCount = 0;
  }

  get syncing(): boolean {
    return this.syncStatus?.syncing ?? false;
  }

  get lastSuccessfulSyncAt(): number | undefined {
    return this.syncStatus?.lastSuccessfulSyncAt;
  }

  get syncDirty(): boolean | undefined {
    return this.syncStatus?.dirty;
  }

  static override styles = [
    paletteTokens,
    themeTokens,
    css`
      :host {
        display: flex;
        flex-direction: column;
        width: 100%;
        height: 100%;
        min-height: 0;
      }
      .body {
        position: relative;
        flex: 1;
        min-height: 0;
        display: flex;
        flex-direction: column;
        /* Clip here (no scrollbar on the body); the routed view owns its own internal scroller (the
         * vault list, editor .scroll, etc.). Making the body itself scroll (overflow-y:auto) nests a
         * second scrollbar behind the list's — keep it hidden so the list is the only scrollbar. */
        overflow: hidden;
      }
      .body.sheet-open { overflow:visible; }
      .scrim {
        position:absolute;
        inset:0;
        z-index:10;
        background:rgba(0,0,0,.34);
        animation:mvIn .18s ease-out;
      }
      .sheet {
        position:absolute;
        left:0;
        right:0;
        bottom:0;
        z-index:11;
        max-height:100%;
        overflow:auto;
        border-radius:20px 20px 0 0;
        background:var(--vw-panel);
        box-shadow:var(--vw-dialog-shadow);
        animation:mvSheet .22s cubic-bezier(.2,.9,.3,1);
      }
      .sheet-open .scrim { bottom:-48px; }
      .sheet-open .sheet { bottom:-48px; max-height:calc(100% + 48px); }
      .sheet-handle {
        position:sticky;
        top:0;
        z-index:2;
        display:block;
        width:36px;
        height:4px;
        margin:8px auto 0;
        border-radius:2px;
        background:var(--vw-line-3);
      }
      .load-state {
        display:flex;
        flex:1;
        min-height:0;
        flex-direction:column;
        justify-content:center;
        gap:10px;
        padding:24px 14px;
      }
      .load-back {
        align-self:center;
        min-height:34px;
        padding:0 16px;
        border:0;
        border-radius:17px;
        background:var(--pc);
        color:var(--onpc);
        font:500 12px/1 var(--vw-font-ui);
        cursor:pointer;
      }
      .load-back:focus-visible { outline:none; box-shadow:var(--vw-focus); }
      .vault-shell {
        display:flex;
        flex:1;
        min-height:0;
        flex-direction:column;
        background:var(--vw-panel);
      }
      .vault-shell vw-vault-filters { flex:none; }
      .vault-shell vw-vault-view { flex:1; min-height:0; }
    `,
  ];

  /** Mirrors the theme + density prefs onto this root host so the palette re-themes at runtime. */
  private appearance = new AppearanceController(this);

  private readonly handleVaultSyncStorageChanged = (
    changes: Record<string, unknown>,
    areaName: string,
  ): void => {
    if (!this.isConnected || areaName !== 'local') return;
    const rawChange = changes[VAULT_SYNC_METADATA_KEY];
    if (!isVaultSyncRecord(rawChange)) return;
    const change: VaultSyncMetadataChange = {
      ...(Object.prototype.hasOwnProperty.call(rawChange, 'oldValue')
        ? { oldValue: rawChange.oldValue }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(rawChange, 'newValue')
        ? { newValue: rawChange.newValue }
        : {}),
    };
    const currentIdentity = this.syncStatus?.identity;
    for (const [identity, lastSuccess] of successfulSyncAdvances(change)) {
      const existing = this.pendingVaultSyncSuccesses.get(identity);
      this.pendingVaultSyncSuccesses.set(identity, {
        lastSuccess: Math.max(existing?.lastSuccess ?? lastSuccess, lastSuccess),
        refreshEvenIfStatusCaughtUp: existing?.refreshEvenIfStatusCaughtUp === true || !currentIdentity,
      });
    }
    this.processPendingVaultSyncSuccess();
    if (this.generatorSurfaceActive()) void this.loadGeneratorPolicy();
  };

  private readonly handleEnterprisePolicyClientChanged = (message: unknown): void => {
    if (
      typeof message !== 'object'
      || message === null
      || Array.isArray(message)
      || Object.keys(message).length !== 2
      || !Object.hasOwn(message, 'type')
      || !Object.hasOwn(message, 'phase')
      || (message as { type?: unknown }).type !== 'enterprisePolicy.clientChanged'
    ) return;
    const phase = (message as { phase?: unknown }).phase;
    if (phase !== 'revoke' && phase !== 'refresh') return;
    const unlocked = this.isUnlockedWorkspace() && this.route.name !== 'restricted';
    if (phase === 'revoke') {
      this.workspaceGeneration += 1;
      if (unlocked) {
        this.organizationDataOwnershipStatus = { status: 'unavailable' };
        this.dataOwnershipError = undefined;
        this.dataOwnershipCheckPending = true;
        this.navigate({ name: 'dataOwnership' });
      }
    }
    this.latestGeneratorPolicySeq += 1;
    this.latestGeneratorHistorySeq += 1;
    this.generatorHistory = [];
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    if (phase === 'refresh') {
      if (this.generatorSurfaceActive()) {
        void this.loadGeneratorPolicy();
        void this.loadGeneratorHistory();
      }
      if (unlocked) void this.loadListing(this.workspaceGeneration);
    }
  };

  private readonly handleContextMenuCreateIntent = (
    message: unknown,
    sender: { readonly id?: string; readonly url?: string; readonly tab?: unknown },
  ): Promise<{ readonly accepted: true }> | undefined => {
    const intent = parseContextMenuCreateIntent(message);
    if (!intent
        || sender.id !== browser.runtime.id
        || sender.tab !== undefined
        || sender.url !== browser.runtime.getURL('background.js')) return undefined;
    if (intent.intentId !== this.lastContextMenuCreateIntentId) {
      this.lastContextMenuCreateIntentId = intent.intentId;
      this.pendingContextMenuCreate = intent;
      this.openPendingContextMenuCreate();
    }
    return Promise.resolve({ accepted: true });
  };

  private installVaultSyncMetadataListener(): void {
    if (this.vaultSyncMetadataListenerInstalled) return;
    browser.storage.onChanged.addListener(this.handleVaultSyncStorageChanged);
    this.vaultSyncMetadataListenerInstalled = true;
  }

  private removeVaultSyncMetadataListener(): void {
    if (!this.vaultSyncMetadataListenerInstalled) return;
    browser.storage.onChanged.removeListener(this.handleVaultSyncStorageChanged);
    this.vaultSyncMetadataListenerInstalled = false;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    browser.runtime.onMessage.addListener(this.handleEnterprisePolicyClientChanged);
    browser.runtime.onMessage.addListener(this.handleContextMenuCreateIntent);
    this.websitePasskeyQuery = websitePasskeyQuery(window.location.href);
    this.websitePasskeyUnlockQuery = parseWebsitePasskeyUnlockQuery(window.location.href);
    if (this.websitePasskeyQuery.kind !== 'none') {
      this.websitePasskeyActionGeneration += 1;
      this.websitePasskeyCleanupEligible = false;
      this.websitePasskeyCleanupSent = false;
      this.websitePasskeyModel = undefined;
      this.route = { name: 'websitePasskey' };
      window.addEventListener('pagehide', this.handleWebsitePasskeyPageHide);
      void this.bootstrapWebsitePasskey();
      return;
    }
    if (this.websitePasskeyUnlockQuery.kind === 'continuation') {
      window.addEventListener('pagehide', this.handleWebsitePasskeyPageHide);
    }
    this.openDeviceLoginApprovals = opensDeviceLoginApprovalList(window.location.href);
    window.addEventListener('keydown', this.handleWindowKeydown);
    this.unsubscribePrefs = subscribePrefs(() => this.requestUpdate());
    this.installVaultSyncMetadataListener();
    this.notifyPopupOpened();
    void this.bootstrap();
  }

  /** Notify the scheduler once per popup element. This is deliberately fire-and-forget so scheduler
   *  reconciliation never delays auth routing or the first paint. Once it settles, refresh status to
   *  observe any sync it triggered. */
  private notifyPopupOpened(): void {
    if (this.popupOpenedSent) return;
    this.popupOpenedSent = true;
    void this.request({ type: 'vault.popupOpened' }).then(
      () => {
        if (this.isConnected && this.isUnlockedWorkspace()) void this.loadSyncStatus();
      },
      () => {
        // Opening the popup remains usable when the scheduler notification channel is unavailable.
      },
    );
  }

  private readonly handleWindowKeydown = (event: KeyboardEvent): void => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'l') {
      const unlocked = ![
        'loading', 'login', 'passwordHint', 'register', 'registrationFinish', 'registrationCheckEmail',
        'newDeviceVerification', 'twoFactor', 'sso',
        'accountPasskey', 'deviceLogin', 'unlock',
      ].includes(this.route.name);
      if (!unlocked) return;
      event.preventDefault();
      void this.handleAccountAction({ action: 'lock' });
      return;
    }
    if (event.key === 'Escape' && ['generator', 'health', 'editor'].includes(this.route.name)) {
      if (this.pending || this.sendEncoding) return;
      event.preventDefault();
      this.navigate({ name: 'vault', scope: 'suggestions' });
    }
  };

  /** Load persisted UI prefs (so the first paint is themed, localized, and configured), then route. */
  private async bootstrap(): Promise<void> {
    await Promise.all([initLocale(), initAppearance(), initPrefs()]);
    await this.init();
  }

  private async bootstrapWebsitePasskey(): Promise<void> {
    await Promise.all([initLocale(), initAppearance()]);
    if (!this.isConnected || this.route.name !== 'websitePasskey') return;
    if (this.websitePasskeyQuery.kind !== 'ceremony') {
      this.websitePasskeyModel = this.websitePasskeyErrorModel('', t('websitePasskey.invalidRequest'));
      return;
    }
    await this.loadWebsitePasskeyApproval(this.websitePasskeyQuery.ceremonyId);
  }

  private websitePasskeyErrorModel(ceremonyId: string, errorMessage: string): WebsitePasskeyViewModel {
    return { ceremonyId, kind: 'get', origin: '', rpId: '', state: 'error', errorMessage, candidates: [] };
  }

  private isCurrentWebsitePasskey(generation: number, ceremonyId: string): boolean {
    return this.isConnected
      && this.route.name === 'websitePasskey'
      && this.websitePasskeyQuery.kind === 'ceremony'
      && this.websitePasskeyQuery.ceremonyId === ceremonyId
      && this.websitePasskeyGeneration === generation;
  }

  private async loadWebsitePasskeyApproval(ceremonyId: string): Promise<void> {
    const generation = ++this.websitePasskeyGeneration;
    const response = await this.request({ type: 'websitePasskey.getApproval', ceremonyId });
    if (!this.isCurrentWebsitePasskey(generation, ceremonyId)) return;
    if (!response.ok) {
      this.websitePasskeyCleanupEligible = false;
      this.websitePasskeyModel = this.websitePasskeyErrorModel(ceremonyId, response.error.message);
      return;
    }
    const model = websitePasskeyViewModel((response.data as { approval?: unknown } | null)?.approval, ceremonyId);
    if (!model) {
      this.websitePasskeyCleanupEligible = false;
      this.websitePasskeyModel = this.websitePasskeyErrorModel(ceremonyId, t('websitePasskey.expired'));
      return;
    }
    this.websitePasskeyCleanupEligible = true;
    this.websitePasskeyModel = model;
  }

  private websitePasskeyFailure(message: string): void {
    const current = this.websitePasskeyModel;
    const ceremonyId = current?.ceremonyId ?? (this.websitePasskeyQuery.kind === 'ceremony'
      ? this.websitePasskeyQuery.ceremonyId
      : '');
    this.websitePasskeyCleanupEligible = false;
    this.websitePasskeyModel = current
      ? current.kind === 'get'
        ? { ...current, state: 'error', errorMessage: message, candidates: [] }
        : { ...current, state: 'error', errorMessage: message, targets: [] }
      : this.websitePasskeyErrorModel(ceremonyId, message);
  }

  private websitePasskeyOutcomeMessage(outcome: string): string {
    if (outcome === 'uncertain') return t('websitePasskey.outcomeUncertain');
    if (outcome === 'failed') return t('websitePasskey.outcomeFailed');
    return t('websitePasskey.expired');
  }

  private closeWebsitePasskeyPopup(): void {
    try { window.close(); } catch { /* closing is best effort */ }
  }

  private async resumeWebsitePasskeyAfterUnlock(): Promise<boolean> {
    const continuation = this.websitePasskeyLockedContinuation;
    if (!continuation) return false;
    this.websitePasskeyLockedCleanupSent = true;
    this.websitePasskeyLockedContinuation = undefined;
    let resumed = false;
    try {
      const response = await this.request({
        type: 'websitePasskey.resumeLocked',
        continuationId: continuation.continuationId,
      });
      const status = response.ok
        ? (response.data as { readonly status?: unknown }).status
        : undefined;
      resumed = status === 'started' || status === 'stale';
    } catch {
      // The exact window-close cancellation below remains the terminal fallback.
    }
    if (!resumed) {
      await this.request({
        type: 'websitePasskey.cancelLocked',
        continuationId: continuation.continuationId,
      }).catch(() => undefined);
    }
    this.closeWebsitePasskeyPopup();
    return true;
  }

  private async handleWebsitePasskeyApprove(detail: WebsitePasskeyApproveDetail): Promise<void> {
    const model = this.websitePasskeyModel;
    if (!model || model.state !== 'awaiting' || model.ceremonyId !== detail.ceremonyId) return;
    const generation = this.websitePasskeyGeneration;
    const action = ++this.websitePasskeyActionGeneration;
    this.websitePasskeyModel = { ...model, state: 'executing' };
    const response = await this.request({
      type: 'websitePasskey.approve',
      ceremonyId: detail.ceremonyId,
      selection: detail.selection,
    });
    if (!this.isCurrentWebsitePasskey(generation, detail.ceremonyId)
      || action !== this.websitePasskeyActionGeneration) return;
    if (!response.ok) {
      this.websitePasskeyFailure(response.error.message);
      return;
    }
    const outcome = (response.data as { outcome?: string } | null)?.outcome ?? 'unavailable';
    this.websitePasskeyCleanupEligible = false;
    if (outcome === 'completed' || outcome === 'fallback') this.closeWebsitePasskeyPopup();
    else this.websitePasskeyFailure(this.websitePasskeyOutcomeMessage(outcome));
  }

  private async handleWebsitePasskeyFallback(
    detail: WebsitePasskeyFallbackDetail,
    always: boolean,
  ): Promise<void> {
    const model = this.websitePasskeyModel;
    if (!model || model.state !== 'awaiting' || model.ceremonyId !== detail.ceremonyId) return;
    const generation = this.websitePasskeyGeneration;
    const action = ++this.websitePasskeyActionGeneration;
    this.websitePasskeyCleanupEligible = false;
    const response = await this.request({
      type: always ? 'websitePasskey.fallbackAlways' : 'websitePasskey.fallbackOnce',
      ceremonyId: detail.ceremonyId,
    });
    if (!this.isCurrentWebsitePasskey(generation, detail.ceremonyId)
      || action !== this.websitePasskeyActionGeneration) return;
    if (!response.ok) {
      this.websitePasskeyFailure(response.error.message);
      return;
    }
    const outcome = (response.data as { outcome?: string } | null)?.outcome ?? 'unavailable';
    if (outcome === 'fallback') this.closeWebsitePasskeyPopup();
    else this.websitePasskeyFailure(this.websitePasskeyOutcomeMessage(outcome));
  }

  private async handleWebsitePasskeyCancel(detail: WebsitePasskeyCancelDetail): Promise<void> {
    const model = this.websitePasskeyModel;
    if (!model || model.ceremonyId !== detail.ceremonyId) return;
    if (!detail.ceremonyId || model.state === 'error') {
      this.websitePasskeyCleanupEligible = false;
      this.closeWebsitePasskeyPopup();
      return;
    }
    const generation = this.websitePasskeyGeneration;
    const action = ++this.websitePasskeyActionGeneration;
    this.websitePasskeyCleanupEligible = false;
    const response = await this.request({ type: 'websitePasskey.cancel', ceremonyId: detail.ceremonyId });
    if (!this.isCurrentWebsitePasskey(generation, detail.ceremonyId)
      || action !== this.websitePasskeyActionGeneration) return;
    if (!response.ok) {
      this.websitePasskeyFailure(response.error.message);
      return;
    }
    this.closeWebsitePasskeyPopup();
  }

  override disconnectedCallback(): void {
    this.cleanupWebsitePasskey();
    this.clearDeviceLoginRequesterState();
    this.clearDeviceLoginApprovalState();
    this.clearNewDeviceVerificationExpiry();
    super.disconnectedCallback();
    this.websitePasskeyGeneration += 1;
    this.websitePasskeyActionGeneration += 1;
    this.authAttemptGeneration += 1;
    this.workspaceGeneration += 1;
    this.latestListingSeq += 1;
    this.clearSyncStatusPoll();
    this.resetExternalSyncRefreshState();
    this.pending = false;
    this.pendingContextMenuCreate = undefined;
    this.lastContextMenuCreateIntentId = undefined;
    this.vaultDataReadyGeneration = undefined;
    window.removeEventListener('keydown', this.handleWindowKeydown);
    window.removeEventListener('pagehide', this.handleWebsitePasskeyPageHide);
    this.removeVaultSyncMetadataListener();
    browser.runtime.onMessage.removeListener(this.handleEnterprisePolicyClientChanged);
    browser.runtime.onMessage.removeListener(this.handleContextMenuCreateIntent);
    this.unsubscribePrefs?.();
    this.unsubscribePrefs = undefined;
    this.clearEphemeralDetailState();
  }

  private readonly handleWebsitePasskeyPageHide = (): void => {
    this.cleanupWebsitePasskey();
  };

  private cleanupWebsitePasskey(): void {
    const locked = this.websitePasskeyLockedContinuation;
    if (locked && !this.websitePasskeyLockedCleanupSent) {
      this.websitePasskeyLockedCleanupSent = true;
      this.websitePasskeyLockedContinuation = undefined;
      void this.request({
        type: 'websitePasskey.cancelLocked',
        continuationId: locked.continuationId,
      });
    }
    if (!this.websitePasskeyCleanupEligible || this.websitePasskeyCleanupSent
      || this.websitePasskeyQuery.kind !== 'ceremony') return;
    this.websitePasskeyCleanupSent = true;
    this.websitePasskeyCleanupEligible = false;
    this.websitePasskeyActionGeneration += 1;
    void this.request({ type: 'websitePasskey.cancel', ceremonyId: this.websitePasskeyQuery.ceremonyId });
  }

  private clearEphemeralDetailState(): void {
    this.detailEpoch += 1;
    if (this.totpTimer !== undefined) {
      clearInterval(this.totpTimer);
      this.totpTimer = undefined;
    }
    // Also stop the 2FA-list countdown here so a programmatic detach (disconnectedCallback) while the
    // totp route is active can't leak the 1s interval — `navigate()` alone doesn't cover disconnects.
    this.stopTotpList();
    this.repromptCredential = null;
    this.repromptAutofillAuthorization = null;
    this.repromptFillContinuation = null;
    if (!this.preserveManualAutofillOnNavigation) this.discardManualAutofillConfirmation();
    this.detailExtrasCache = undefined;
    this.sshDetailExtrasCache = undefined;
    this.detailCipher = null;
    this.sshKeyDetails = undefined;
    this.detailStatus = undefined;
    this.repromptError = undefined;
    this.editorInput = null;
    this.sshEditorCipher = null;
    this.sshEditorPublicDetails = undefined;
    this.editorStatus = undefined;
    this.editorTotpCapture = undefined;
    this.editorWorkspaceSnapshot = undefined;
  }

  private discardManualAutofillConfirmation(): void {
    const confirmation = this.manualAutofillConfirmation;
    this.manualAutofillConfirmation = null;
    if (confirmation) {
      void this.request({
        type: 'autofill.manual.cancel',
        authorizationId: confirmation.authorization.authorizationId,
      });
    }
  }

  private isDeviceLoginRequesterRoute(route: PopupRoute): boolean {
    return route.name === 'deviceLogin'
      || (route.name === 'twoFactor' && route.flow === 'device');
  }

  private clearDeviceLoginCountdown(): void {
    if (this.deviceLoginCountdownTimer === undefined) return;
    clearInterval(this.deviceLoginCountdownTimer);
    this.deviceLoginCountdownTimer = undefined;
  }

  private clearDeviceLoginStatusPoll(): void {
    if (this.deviceLoginStatusPollTimer === undefined) return;
    clearTimeout(this.deviceLoginStatusPollTimer);
    this.deviceLoginStatusPollTimer = undefined;
  }

  private clearDeviceLoginRequesterState(): void {
    this.deviceLoginGeneration += 1;
    this.clearDeviceLoginCountdown();
    this.clearDeviceLoginStatusPoll();
    this.deviceLoginExpiresAt = undefined;
    this.deviceLoginRequesterModel = undefined;
  }

  private clearDeviceLoginApprovalInteraction(): void {
    this.deviceLoginApprovalGeneration += 1;
    this.deviceLoginApprovalBindings.clear();
    this.deviceLoginApprovalModel = undefined;
  }

  private clearDeviceLoginApprovalState(): void {
    this.clearDeviceLoginApprovalInteraction();
    this.deviceLoginApprovalCount = 0;
  }

  private clearNewDeviceVerificationExpiry(): void {
    if (this.newDeviceVerificationExpiryTimer === undefined) return;
    clearTimeout(this.newDeviceVerificationExpiryTimer);
    this.newDeviceVerificationExpiryTimer = undefined;
  }

  private startNewDeviceVerificationExpiry(
    route: Extract<PopupRoute, { name: 'newDeviceVerification' }>,
  ): void {
    this.clearNewDeviceVerificationExpiry();
    const delay = Math.max(0, route.expiresAt - Date.now());
    this.newDeviceVerificationExpiryTimer = window.setTimeout(() => {
      this.newDeviceVerificationExpiryTimer = undefined;
      if (
        this.route.name === 'newDeviceVerification'
        && this.route.attemptId === route.attemptId
        && this.route.expiresAt === route.expiresAt
      ) void this.handleNewDeviceVerificationCancel();
    }, delay);
  }

  /** Assigns the next route, clearing per-view ephemeral state that must not survive a
   *  navigation: the TOTP timer, the reprompt credential, and (when leaving their owning view)
   *  the remembered-device banner and PIN availability flag. */
  navigate(route: PopupRoute): void {
    if (this.isDataOwnershipNavigationConstrained() && !this.isDataOwnershipRouteAllowed(route)) {
      route = { name: 'dataOwnership' };
    }
    if (this.sendEncoding && route.name !== 'sends') return;
    const previousRoute = this.route;
    const previousEditorSnapshot = this.editorWorkspaceSnapshot;
    const previousVaultMode = this.vaultMode;
    const editorSetup = this.editorNavigationSetup;
    const preservedReprompt = editorSetup?.preserveReprompt === true
      && route.name === 'editor'
      && route.cipherId !== undefined
      && this.repromptCredential?.cipherId === route.cipherId
      ? this.repromptCredential
      : null;
    this.editorNavigationSetup = undefined;
    if (this.isDeviceLoginRequesterRoute(this.route) && !this.isDeviceLoginRequesterRoute(route)) {
      this.clearDeviceLoginRequesterState();
    }
    if (this.route.name === 'deviceLoginApprovals' && route.name !== 'deviceLoginApprovals') {
      this.clearDeviceLoginApprovalInteraction();
    }
    if ((this.route.name === 'passwordHint' && route.name !== 'passwordHint')
        || (this.route.name === 'twoFactor' && route.name !== 'twoFactor')
        || (this.route.name === 'sso' && route.name !== 'sso')
        || (this.route.name === 'newDeviceVerification' && route.name !== 'newDeviceVerification')) {
      this.authAttemptGeneration += 1;
      this.pending = false;
    }
    this.clearEphemeralDetailState();
    if (preservedReprompt) this.repromptCredential = preservedReprompt;
    if (route.name !== 'vault' && route.name !== 'detail') this.vaultMode = 'active';
    this.route = route;
    if (route.name === 'editor') {
      const continuesCreateDraft = editorSetup === undefined
        && previousRoute.name === 'editor'
        && previousRoute.mode === 'create'
        && route.mode === 'create'
        && previousEditorSnapshot !== undefined;
      if (continuesCreateDraft) {
        this.editorWorkspaceSnapshot = {
          ...previousEditorSnapshot,
          routeKey: editorRouteKey(route),
        };
      } else {
        const summary = route.cipherId === undefined
          ? undefined
          : this.items.find((item) => item.id === route.cipherId);
        const fallbackReturnRoute: PopupRoute = previousRoute.name === 'detail' || previousRoute.name === 'vault'
          ? previousRoute
          : { name: 'vault', scope: this.vaultScope };
        this.editorWorkspaceSnapshot = {
          routeKey: editorRouteKey(route),
          draftKey: `${this.workspaceGeneration}:${++this.editorDraftSequence}`,
          ...(summary ? { summary } : {}),
          ...(editorSetup?.createDefaults ? { createDefaults: editorSetup.createDefaults } : {}),
          returnRoute: editorSetup?.returnRoute ?? fallbackReturnRoute,
          returnVaultMode: editorSetup?.returnVaultMode ?? previousVaultMode,
          folders: [...this.folders],
          collections: [...this.collections],
          orgPermissions: [...this.orgPermissions],
          personalCreationAllowed: this.personalCreationAllowed,
        };
      }
    }
    if (route.name === 'newDeviceVerification') this.startNewDeviceVerificationExpiry(route);
    else this.clearNewDeviceVerificationExpiry();
    if (route.name === 'vault') {
      this.vaultScope = route.scope;
      this.selectedCipherId = null;
    } else if (route.name === 'detail') {
      this.selectedCipherId = route.cipherId;
    }
    if (route.name !== 'login') {
      this.deviceRemembered = false;
      this.deviceForgotten = false;
      this.ssoRequired = false;
      this.deviceCheckEmail = '';
    }
    if (route.name === 'unlock') {
      void this.refreshPinStatus();
    } else {
      this.pinEnabled = false;
    }
    if (route.name === 'detail') {
      const summary = this.items.find((item) => item.id === route.cipherId);
      // Every lifecycle state has a read-only detail view. Protected items must pass the exact-item
      // reprompt gate before even the secret-stripped detail loader crosses the worker boundary.
      if (summary && !summary.unsupported && !summary.undecryptable && !summary.reprompt) {
        void this.loadDetail(route.cipherId, this.detailEpoch, 'view');
      }
      if (summary?.type === 5 && !summary.deletedDate) void this.loadSshWriteAvailability();
    }
    if (route.name === 'editor' && route.mode !== 'create' && route.cipherId !== undefined) {
      const summary = this.items.find((item) => item.id === route.cipherId);
      // A protected item must clear the reprompt gate (which then triggers the load) before the
      // editor can reveal its editable plaintext; otherwise load it straight away.
      if (summary && this.canOpenItemEditor(summary)
        && !summary.unsupported && !summary.undecryptable && !summary.deletedDate
        && (!summary.reprompt || this.repromptCredential?.cipherId === route.cipherId)) {
        if (summary.type === 5 && route.mode === 'edit') {
          void this.loadSshEditorData(route.cipherId, this.detailEpoch, 'editor');
        } else if (summary.type !== 5) {
          void this.loadEditorInput(route.cipherId, route.mode === 'edit' ? 'editor' : undefined);
        }
      }
      if (summary?.type === 5 && !summary.deletedDate) void this.loadSshWriteAvailability();
    }
    if (route.name === 'editor' && route.mode === 'create') void this.loadSshWriteAvailability();
    if (route.name === 'generator' || route.name === 'health' || route.name === 'sends' || route.name === 'pin' || route.name === 'accountSecurity') {
      this.toolStatus = undefined;
    }
    if (route.name === 'health') void this.loadHealth();
    if (this.generatorSurfaceActive()) {
      void this.loadGeneratorPolicy();
      void this.loadGeneratorHistory();
    }
    if (route.name === 'sends') void this.loadSends();
    if (route.name === 'pin') void this.loadPinStatus();
    // The 2FA view owns a live countdown tick; load on entry, stop it whenever we leave.
    if (route.name === 'totp') void this.loadTotpCodes();
    else this.stopTotpList();
  }

  private isCurrentDeviceLogin(generation: number): boolean {
    return this.isConnected
      && generation === this.deviceLoginGeneration
      && (this.route.name === 'loading'
        || this.route.name === 'login'
        || this.isDeviceLoginRequesterRoute(this.route));
  }

  private startDeviceLoginCountdown(expiresAt: number, generation: number): void {
    this.clearDeviceLoginCountdown();
    this.deviceLoginExpiresAt = expiresAt;
    const tick = (): void => {
      if (!this.isCurrentDeviceLogin(generation) || this.deviceLoginExpiresAt !== expiresAt) {
        this.clearDeviceLoginCountdown();
        return;
      }
      const remainingSeconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1_000));
      const current = this.deviceLoginRequesterModel;
      if (current?.generation === generation && current.remainingSeconds !== remainingSeconds) {
        this.deviceLoginRequesterModel = Object.freeze({ ...current, remainingSeconds });
      }
      if (remainingSeconds > 0) return;
      this.clearDeviceLoginCountdown();
      this.deviceLoginExpiresAt = undefined;
      this.pending = false;
      this.deviceLoginRequesterModel = Object.freeze({
        kind: 'requester',
        generation,
        status: 'expired',
        busy: false,
        labels: deviceLoginLabels(),
      });
      this.navigate({ name: 'deviceLogin' });
    };
    tick();
    if (this.deviceLoginExpiresAt === expiresAt && this.isCurrentDeviceLogin(generation)) {
      this.deviceLoginCountdownTimer = window.setInterval(tick, 1_000);
    }
  }

  private scheduleDeviceLoginStatusPoll(generation: number): void {
    if (this.deviceLoginStatusPollTimer !== undefined
      || this.route.name !== 'deviceLogin'
      || this.deviceLoginRequesterModel?.status !== 'pending') return;
    this.deviceLoginStatusPollTimer = window.setTimeout(() => {
      this.deviceLoginStatusPollTimer = undefined;
      void this.pollDeviceLoginStatus(generation);
    }, DEVICE_LOGIN_STATUS_POLL_MS);
  }

  private async pollDeviceLoginStatus(generation: number): Promise<void> {
    const model = this.deviceLoginRequesterModel;
    if (!this.isCurrentDeviceLogin(generation) || this.route.name !== 'deviceLogin'
      || model?.generation !== generation || model.status !== 'pending') return;
    if (this.pending) {
      this.scheduleDeviceLoginStatusPoll(generation);
      return;
    }
    const route = this.route;
    this.pending = true;
    this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: true });
    try {
      if (model.ownerGeneration === undefined) return;
      const response = await this.request({
        type: 'auth.deviceLogin.status',
        generation: model.ownerGeneration,
      });
      if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
      if (!response.ok) {
        this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: false });
        return;
      }
      const result = deviceLoginRequesterResult(response.data);
      if (result) await this.applyDeviceLoginResult(result, generation);
      else this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
    } finally {
      if (generation === this.deviceLoginGeneration) {
        this.pending = false;
        const current = this.deviceLoginRequesterModel;
        if (current?.generation === generation && current.busy) {
          this.deviceLoginRequesterModel = Object.freeze({ ...current, busy: false });
        }
        this.scheduleDeviceLoginStatusPoll(generation);
      }
    }
  }

  private deviceLoginContextModel(
    result: Extract<DeviceLoginRequesterResultData, { fingerprint: string }>,
    generation: number,
    status: 'pending' | 'retry_required' | 'two_factor_unsupported',
  ): DeviceLoginRequesterViewModel | undefined {
    const fingerprint = deviceLoginFingerprint(result.fingerprint);
    if (!fingerprint) return undefined;
    return Object.freeze({
      kind: 'requester',
      generation,
      ownerGeneration: result.generation,
      status,
      fingerprint,
      remainingSeconds: Math.max(0, Math.ceil((result.expiresAt - Date.now()) / 1_000)),
      serverOrigin: result.serverOrigin,
      email: result.email,
      deviceName: result.deviceName,
      ...('providers' in result ? { providers: result.providers } : {}),
      busy: false,
      labels: deviceLoginLabels(),
    });
  }

  private async resolveDeviceLoginNone(generation: number): Promise<void> {
    if (!this.isCurrentDeviceLogin(generation)) return;
    const route = this.route;
    const response = await this.request({ type: 'auth.getState' });
    if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
    if (!response.ok) {
      this.setDeviceLoginError(generation, response.error.message);
      return;
    }
    const state = (response.data as { state?: SessionState } | null)?.state;
    this.pending = false;
    this.clearDeviceLoginRequesterState();
    if (state === 'unlocked') this.enterVault();
    else if (state === 'locked') this.navigate(unlockRoute());
    else if (state === 'restricted') {
      const requirement = restrictionFromStateData(response.data);
      this.navigate(requirement
        ? restrictedRoute(requirement)
        : loginRoute(t('common.error')));
    }
    else this.navigate(loginRoute());
  }

  private async applyDeviceLoginResult(
    result: DeviceLoginRequesterResultData,
    generation: number,
  ): Promise<void> {
    if (!this.isCurrentDeviceLogin(generation)) return;
    if (result.status === 'none') {
      await this.resolveDeviceLoginNone(generation);
      return;
    }
    if (result.status === 'unlocked') {
      this.pending = false;
      this.clearDeviceLoginRequesterState();
      this.enterVault();
      return;
    }
    if (result.status === 'restricted') {
      this.pending = false;
      this.clearDeviceLoginRequesterState();
      await this.reRouteFromState();
      return;
    }
    if (result.status === 'two_factor') {
      this.clearDeviceLoginStatusPoll();
      const context = this.deviceLoginContextModel(result, generation, 'pending');
      if (!context) {
        this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
        return;
      }
      this.deviceLoginRequesterModel = context;
      this.startDeviceLoginCountdown(result.expiresAt, generation);
      this.navigate(twoFactorRoute(
        [...result.providers],
        result.fido2,
        undefined,
        'device',
      ));
      return;
    }
    if (result.status === 'pending' || result.status === 'retry_required'
      || result.status === 'two_factor_unsupported') {
      const context = this.deviceLoginContextModel(result, generation, result.status);
      if (!context) {
        this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
        return;
      }
      this.deviceLoginRequesterModel = context;
      if (result.status === 'pending' || result.status === 'retry_required') {
        this.startDeviceLoginCountdown(result.expiresAt, generation);
      } else {
        this.clearDeviceLoginCountdown();
      }
      this.navigate({ name: 'deviceLogin' });
      if (result.status === 'pending') this.scheduleDeviceLoginStatusPoll(generation);
      else this.clearDeviceLoginStatusPoll();
      return;
    }
    this.clearDeviceLoginCountdown();
    this.clearDeviceLoginStatusPoll();
    this.deviceLoginExpiresAt = undefined;
    this.deviceLoginRequesterModel = Object.freeze({
      kind: 'requester',
      generation,
      ...(result.status === 'outcome_unknown'
        ? { ownerGeneration: result.generation }
        : {}),
      status: result.status,
      ...(result.status === 'outcome_unknown' ? { serverOrigin: result.serverOrigin } : {}),
      busy: false,
      labels: deviceLoginLabels(),
    });
    this.navigate({ name: 'deviceLogin' });
  }

  private setDeviceLoginError(generation: number, message: string): void {
    if (!this.isCurrentDeviceLogin(generation)) return;
    this.clearDeviceLoginCountdown();
    this.clearDeviceLoginStatusPoll();
    this.deviceLoginRequesterModel = Object.freeze({
      kind: 'requester',
      generation,
      status: 'error',
      errorMessage: message,
      busy: false,
      labels: deviceLoginLabels(),
    });
    this.navigate({ name: 'deviceLogin' });
  }

  private async init(): Promise<void> {
    const passkeyQuery = accountPasskeyQuery(window.location.href);
    const lockedContinuationResponse = this.websitePasskeyUnlockQuery.kind === 'continuation'
      ? this.request({
          type: 'websitePasskey.lockedStatus',
          continuationId: this.websitePasskeyUnlockQuery.continuationId,
        })
      : Promise.resolve(undefined);
    const [response, continuationResponse, lockedResponse] = await Promise.all([
      this.request({ type: 'auth.getState' }),
      this.request({ type: 'autofill.continuation.status' }),
      lockedContinuationResponse,
    ]);
    this.autofillContinuation = continuationResponse.ok
      ? parseAutofillContinuationStatus(continuationResponse.data)
      : null;
    const lockedStatus = lockedResponse?.ok
      ? parseWebsitePasskeyLockedStatus(lockedResponse.data)
      : undefined;
    this.websitePasskeyLockedContinuation = lockedStatus?.status === 'unlock_required'
      && (this.websitePasskeyUnlockQuery.kind !== 'continuation'
        || lockedStatus.continuationId === this.websitePasskeyUnlockQuery.continuationId)
      ? lockedStatus
      : undefined;
    if (!response.ok) {
      this.navigate(loginRoute(response.error.message));
      return;
    }
    const { state } = response.data as { state: SessionState };
    if (state === 'loggedOut') {
      const ssoStatusResponse = await this.request({ type: 'auth.sso.status' });
      if (ssoStatusResponse.ok) {
        const ssoStatus = ssoLoginStatus(ssoStatusResponse.data);
        if (ssoStatus && ssoStatus.status !== 'none') {
          this.navigate(ssoRoute(
            ssoStatus.status,
            ssoStatus.status === 'error'
              ? { error: ssoStatus.message }
              : {
                  attemptId: ssoStatus.attemptId,
                  generation: ssoStatus.generation,
                  email: ssoStatus.email,
                },
          ));
          return;
        }
      }
      if (passkeyQuery.kind === 'invalid') {
        this.navigate(accountPasskeyRoute('failed'));
        return;
      }
      if (passkeyQuery.kind === 'outcome') {
        this.navigate(accountPasskeyRoute(
          passkeyQuery.outcome === 'locked' || passkeyQuery.outcome === 'unlocked'
            ? 'outcome_unknown'
            : passkeyQuery.outcome,
        ));
        return;
      }
      const passkeyStatusResponse = await this.request({ type: 'auth.accountPasskey.status' });
      if (!passkeyStatusResponse.ok) {
        this.navigate(loginRoute(passkeyStatusResponse.error.message));
        return;
      }
      const passkeyStatus = accountPasskeyStatus(passkeyStatusResponse.data);
      if (!passkeyStatus) {
        this.navigate(accountPasskeyRoute('failed'));
        return;
      }
      if (passkeyStatus.status === 'waiting' || passkeyStatus.status === 'outcome_unknown') {
        this.navigate(accountPasskeyRoute(passkeyStatus.status));
        return;
      }
      const fido2Outcome = new URL(window.location.href).searchParams.get('fido2');
      const pendingStatusRoute = this.route;
      const pendingStatusGeneration = this.authAttemptGeneration;
      const pendingLoginResponse = await this.request({ type: 'auth.pendingLogin.status' });
      if (!this.isCurrentAuthAttempt(pendingStatusGeneration) || this.route !== pendingStatusRoute) return;
      if (!pendingLoginResponse.ok) {
        this.navigate(loginRoute(pendingLoginResponse.error.message));
        return;
      }
      const pendingLogin = pendingLoginStatus(pendingLoginResponse.data);
      if (!pendingLogin) {
        this.navigate(loginRoute(t('common.error')));
        return;
      }
      if (pendingLogin.status === 'newDeviceVerification') {
        this.navigate({
          name: 'newDeviceVerification',
          attemptId: pendingLogin.attemptId,
          continuationId: pendingLogin.continuationId,
          expiresAt: pendingLogin.expiresAt,
        });
        return;
      }
      if (pendingLogin.status === 'twoFactor') {
        this.navigate(twoFactorRoute(
          [...pendingLogin.providers],
          pendingLogin.fido2,
          pendingLogin.fido2 && fido2Outcome === 'error' ? t('auth.fido2.unknownResult') : undefined,
          'password',
          pendingLogin.continuationId,
        ));
        return;
      }
      if (pendingLogin.status === 'outcome_unknown') {
        this.navigate(loginRoute(t('auth.pendingLogin.outcomeUnknown')));
        return;
      }
      const generation = ++this.deviceLoginGeneration;
      const route = this.route;
      const deviceLogin = await this.request({ type: 'auth.deviceLogin.status' });
      if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
      if (!deviceLogin.ok) {
        this.navigate(loginRoute(deviceLogin.error.message));
        return;
      }
      const result = deviceLoginRequesterResult(deviceLogin.data);
      if (!result) {
        this.navigate(loginRoute(t('auth.deviceLogin.errorDescription')));
      } else if (result.status === 'none') {
        this.navigate(loginRoute(fido2Outcome === 'error' ? t('auth.fido2.unknownResult') : undefined));
      } else {
        await this.applyDeviceLoginResult(result, generation);
      }
    } else if (state === 'locked') {
      this.navigate(unlockRoute(
        this.websitePasskeyUnlockQuery.kind === 'invalid'
          ? t('websitePasskey.invalidRequest')
          : this.websitePasskeyUnlockQuery.kind === 'continuation'
            && !this.websitePasskeyLockedContinuation
            ? t('websitePasskey.expired')
            : undefined,
        this.websitePasskeyLockedContinuation
          ? t('websitePasskey.unlockNotice')
          : passkeyQuery.kind === 'outcome' && passkeyQuery.outcome === 'locked'
          ? t('auth.accountPasskey.success')
          : undefined,
      ));
    } else if (state === 'restricted') {
      const requirement = restrictionFromStateData(response.data);
      this.navigate(requirement
        ? restrictedRoute(requirement)
        : loginRoute(t('common.error')));
    } else {
      if (this.websitePasskeyLockedContinuation) {
        if (await this.resumeWebsitePasskeyAfterUnlock()) return;
      } else if (this.websitePasskeyUnlockQuery.kind === 'continuation') {
        this.closeWebsitePasskeyPopup();
        return;
      }
      const continuation = await this.resumeAutofillAfterUnlock();
      if (continuation === 'closed') return;
      this.enterVault(continuation);
      if (passkeyQuery.kind === 'outcome' && passkeyQuery.outcome === 'unlocked') {
        this.showToast(t('auth.accountPasskey.unlocked'));
      }
    }
  }

  private async refreshPinStatus(): Promise<void> {
    const response = await this.request({ type: 'auth.pinStatus' });
    if (this.route.name !== 'unlock') return; // navigated away while the request was in flight
    const status = response.ok ? response.data as PinStatusData : undefined;
    this.pinAllowed = status !== undefined && status.allowed !== false;
    this.pinEnabled = this.pinAllowed && status?.available === true;
    this.pinRequireMasterPasswordOnRestart = status?.requireMasterPasswordOnRestart !== false;
  }

  /** Routes an `AuthResult`/error exactly like the live popup's `handleAuthResult`: 2FA challenges
   *  go to the two-factor screen, failures stay on whichever auth screen raised them, and any
   *  other success goes to the vault's default (suggestions) scope. */
  private async routeAuthResult(
    response: ResponseMessage,
    generation = this.authAttemptGeneration,
  ): Promise<void> {
    if (!this.isCurrentAuthAttempt(generation)) return;
    if (!response.ok) {
      if (this.route.name === 'registrationFinish') {
        this.navigate(response.error.code === 'outcome_unknown'
          ? loginRoute(response.error.message)
          : response.error.code === 'session_expired'
            ? registerRoute(response.error.message)
            : registrationFinishRoute(this.route, response.error.message));
      } else if (response.error.code === 'session_expired') {
        // The sign-in session (pending 2FA) was lost — reset to the login screen to re-enter the password.
        this.navigate(loginRoute(response.error.message));
      } else if (this.route.name === 'twoFactor') {
        this.navigate(twoFactorRoute(
          this.route.providers,
          this.route.fido2,
          response.error.message,
          this.route.flow,
          this.route.continuationId,
        ));
      } else if (this.route.name === 'newDeviceVerification') {
        const { error: _error, notice: _notice, ...route } = this.route;
        this.navigate({ ...route, error: response.error.message });
      } else {
        this.navigate(loginRoute(response.error.message));
      }
      return;
    }
    const data = response.data as AuthResult;
    if (data.kind === 'newDeviceVerification') {
      const route = newDeviceVerificationRoute(data);
      if (!route) {
        this.navigate(loginRoute(t('common.error')));
        return;
      }
      this.navigate(route);
    } else if (data.kind === 'twoFactor') {
      this.navigate(twoFactorRoute(
        data.providers,
        data.fido2,
        undefined,
        'password',
        data.continuationId,
      ));
    } else if (data.kind === 'ssoRequired') {
      await this.startSsoLogin({
        email: data.email,
        organizationIdentifier: data.organizationIdentifier,
      }, generation);
    } else if (data.kind === 'locked') {
      this.navigate(unlockRoute());
    } else if (data.kind === 'restricted') {
      this.navigate(restrictedRoute(data.requirement));
    } else {
      this.enterVault();
    }
  }

  private async handleLoginSubmit(detail: LoginSubmitDetail): Promise<void> {
    if (this.pending) return;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const result = await this.request({ type: 'auth.login', email: detail.email, masterPassword: detail.masterPassword });
      await this.routeAuthResult(result, generation);
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleRegisterSubmit(detail: RegisterSubmitDetail): Promise<void> {
    if (this.pending) return;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const response = await this.request(
        detail.name !== undefined
          ? { type: 'auth.startRegistration', email: detail.email, name: detail.name }
          : { type: 'auth.startRegistration', email: detail.email },
      );
      if (!this.isCurrentAuthAttempt(generation)) return;
      if (!response.ok) {
        this.navigate(registerRoute(response.error.message));
        return;
      }
      const result = response.data as RegistrationStartAuthResult;
      if (result.kind === 'registrationEmailSent') {
        this.navigate({ name: 'registrationCheckEmail', email: result.email });
        return;
      }
      this.navigate({
        name: 'registrationFinish',
        attemptId: result.attemptId,
        email: result.email,
        expiresAt: result.expiresAt,
      });
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private handlePasswordHintStart(detail: PasswordHintEmailDetail): void {
    if (this.pending || this.route.name !== 'login') return;
    this.navigate(passwordHintRoute(detail.email));
  }

  private async handlePasswordHintSubmit(detail: PasswordHintEmailDetail): Promise<void> {
    if (this.pending || this.route.name !== 'passwordHint') return;
    const route = this.route;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.requestPasswordHint',
        email: detail.email,
      });
      if (!this.isCurrentAuthAttempt(generation) || this.route !== route) return;
      if (!response.ok) {
        this.navigate(passwordHintRoute(detail.email, { error: response.error.message }));
      } else {
        const result = exactPasswordHintResult(response);
        if (result) {
          this.navigate(passwordHintRoute(detail.email, result));
          return;
        }
        this.navigate(passwordHintRoute(detail.email, { error: t('common.error') }));
      }
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private handlePasswordHintBack(): void {
    if (this.pending || this.route.name !== 'passwordHint') return;
    this.navigate(loginRoute());
  }

  private async handleSsoStart(detail: SsoLoginStartDetail): Promise<void> {
    if (this.pending || this.route.name !== 'login') return;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      await this.startSsoLogin(detail, generation);
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async startSsoLogin(
    detail: SsoLoginStartDetail,
    generation: number,
  ): Promise<void> {
    if (!this.isCurrentAuthAttempt(generation) || this.route.name !== 'login') return;
    const response = await this.request(detail.organizationIdentifier
      ? {
          type: 'auth.sso.begin',
          email: detail.email,
          organizationIdentifier: detail.organizationIdentifier,
        }
      : { type: 'auth.sso.begin', email: detail.email });
    if (!this.isCurrentAuthAttempt(generation)) return;
    if (!response.ok) {
      this.navigate(loginRoute(response.error.message));
      return;
    }
    const status = ssoLoginStatus(response.data);
    if (!status || status.status === 'none' || status.status === 'error') {
      this.navigate(loginRoute(
        status?.status === 'error' ? status.message : t('auth.sso.failed'),
      ));
      return;
    }
    this.navigate(ssoRoute(status.status, {
      attemptId: status.attemptId,
      generation: status.generation,
      email: status.email,
    }));
  }

  private async handleSsoCancel(): Promise<void> {
    if (this.pending || this.route.name !== 'sso') return;
    if (!this.route.attemptId || this.route.generation === undefined) return;
    const attemptId = this.route.attemptId;
    const attemptGeneration = this.route.generation;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.sso.cancel',
        attemptId,
        generation: attemptGeneration,
      });
      if (!this.isCurrentAuthAttempt(generation)) return;
      if (!response.ok) {
        this.navigate(loginRoute(response.error.message));
        return;
      }
      if ((response.data as { cancelled?: unknown }).cancelled === true) {
        this.navigate(loginRoute());
        return;
      }
      const statusResponse = await this.request({
        type: 'auth.sso.status',
        attemptId,
        generation: attemptGeneration,
      });
      if (!this.isCurrentAuthAttempt(generation)) return;
      const status = statusResponse.ok ? ssoLoginStatus(statusResponse.data) : undefined;
      if (!status || status.status === 'none') {
        this.navigate(loginRoute(statusResponse.ok ? undefined : statusResponse.error.message));
        return;
      }
      this.navigate(ssoRoute(
        status.status,
        status.status === 'error'
          ? { error: status.message }
          : {
              attemptId: status.attemptId,
              generation: status.generation,
              email: status.email,
            },
      ));
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleRegisterFinishSubmit(detail: RegisterFinishSubmitDetail): Promise<void> {
    if (this.route.name !== 'registrationFinish') return;
    if (detail.masterPassword.length < DEFAULT_MASTER_PASSWORD_MIN_LENGTH) {
      this.navigate(registrationFinishRoute(this.route, t('auth.passwordMin', {
        min: DEFAULT_MASTER_PASSWORD_MIN_LENGTH,
      })));
      return;
    }
    if (detail.masterPassword !== detail.confirm) {
      this.navigate(registrationFinishRoute(this.route, t('auth.passwordMismatch')));
      return;
    }
    const hintError = masterPasswordHintValidationError(
      detail.masterPasswordHint,
      detail.masterPassword,
    );
    if (hintError === 'tooLong') {
      this.navigate(registrationFinishRoute(this.route, t('security.masterPasswordHintTooLong', {
        max: MASTER_PASSWORD_HINT_MAX_LENGTH,
      })));
      return;
    }
    if (hintError === 'matchesPassword') {
      this.navigate(registrationFinishRoute(this.route, t('security.masterPasswordHintMatches')));
      return;
    }
    if (this.pending) return;
    const route = this.route;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const result = await this.request({
        type: 'auth.register',
        attemptId: route.attemptId,
        masterPassword: detail.masterPassword,
        masterPasswordHint: detail.masterPasswordHint,
      });
      if (result.ok
          && (result.data as { kind?: string }).kind === 'registrationComplete') {
        this.navigate(loginRoute(undefined, t('auth.registrationCompleteLogin')));
        return;
      }
      await this.routeAuthResult(result, generation);
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleRegistrationCancel(): Promise<void> {
    if (this.pending) return;
    const route = this.route;
    const generation = ++this.authAttemptGeneration;
    if (route.name !== 'registrationFinish') {
      this.navigate(registerRoute());
      return;
    }
    this.pending = true;
    try {
      await this.request({ type: 'auth.cancelRegistration', attemptId: route.attemptId });
      if (generation === this.authAttemptGeneration) this.navigate(registerRoute());
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleTwoFactorSubmit(detail: TwoFactorSubmitDetail): Promise<void> {
    if (this.pending || detail.provider === 7) return;
    const activeRoute = this.route;
    if (activeRoute.name !== 'twoFactor'
        || this.selectedTwoFactorProvider(activeRoute) !== detail.provider) return;
    if (activeRoute.flow === 'device') {
      const model = this.deviceLoginRequesterModel;
      if (!model || model.ownerGeneration === undefined) return;
      const generation = model.generation;
      const route = activeRoute;
      this.pending = true;
      try {
        const response = await this.request({
          type: 'auth.deviceLogin.submitTwoFactor',
          generation: model.ownerGeneration,
          provider: detail.provider,
          code: detail.code,
          remember: detail.remember,
        });
        if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
        if (!response.ok) {
          this.navigate(twoFactorRoute(
            route.providers,
            route.fido2,
            response.error.message,
            'device',
          ));
          return;
        }
        const result = deviceLoginRequesterResult(response.data);
        if (result) await this.applyDeviceLoginResult(result, generation);
        else this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
      } finally {
        if (generation === this.deviceLoginGeneration) this.pending = false;
      }
      return;
    }
    const generation = this.authAttemptGeneration;
    this.pending = true;
    try {
      const result = await this.request({
        type: 'auth.submitTwoFactor',
        provider: detail.provider,
        code: detail.code,
        remember: detail.remember,
        ...(activeRoute.continuationId ? { continuationId: activeRoute.continuationId } : {}),
      });
      await this.routeAuthResult(result, generation);
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleDuoStart(detail: DuoTwoFactorStartDetail): Promise<void> {
    if (this.pending || this.route.name !== 'twoFactor') return;
    const route = this.route;
    if (this.selectedTwoFactorProvider(route) !== detail.provider) return;
    const request = route.flow === 'password'
      ? route.continuationId
        ? {
            type: 'auth.duo.begin' as const,
            flow: 'password' as const,
            provider: detail.provider,
            continuationId: route.continuationId,
            remember: detail.remember,
          }
        : undefined
      : this.deviceLoginRequesterModel?.ownerGeneration === undefined
        ? undefined
        : {
            type: 'auth.duo.begin' as const,
            flow: 'deviceLogin' as const,
            provider: detail.provider,
            generation: this.deviceLoginRequesterModel.ownerGeneration,
            remember: detail.remember,
          };
    if (!request) return;
    this.pending = true;
    try {
      const response = await this.request(request);
      if (this.route !== route) return;
      if (!response.ok) {
        this.navigate(twoFactorRoute(
          route.providers,
          route.fido2,
          response.error.message,
          route.flow,
          route.continuationId,
        ));
      }
    } finally {
      if (this.route === route) this.pending = false;
    }
  }

  private async handleForcedPasswordChange(
    detail: ForcedPasswordChangeSubmitDetail,
  ): Promise<void> {
    if (this.pending || this.route.name !== 'restricted') return;
    const route = this.route;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.changeForcedPassword',
        currentPassword: detail.currentPassword,
        newPassword: detail.newPassword,
      });
      if (!response.ok) {
        if (response.error.code === 'outcome_unknown') {
          this.resetVaultState();
          this.navigate(loginRoute(response.error.message));
        } else {
          this.navigate(restrictedRoute(route.requirement, response.error.message));
        }
        return;
      }
      this.resetVaultState();
      await this.reRouteFromState();
    } finally {
      this.pending = false;
    }
  }

  private async handleNewDeviceVerificationSendOtp(): Promise<void> {
    if (this.pending || this.route.name !== 'newDeviceVerification') return;
    const generation = this.authAttemptGeneration;
    const route = this.route;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.newDeviceVerification.sendOtp',
        attemptId: route.attemptId,
        ...(route.continuationId ? { continuationId: route.continuationId } : {}),
      });
      if (!this.isCurrentAuthAttempt(generation) || this.route !== route) return;
      const { error: _error, notice: _notice, ...base } = route;
      if (!response.ok) {
        if (response.error.code === 'session_expired') {
          this.navigate(loginRoute(response.error.message));
        } else {
          this.navigate({ ...base, error: response.error.message });
        }
        return;
      }
      this.navigate({ ...base, notice: t('auth.newDeviceVerification.codeSent') });
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleNewDeviceVerificationSubmit(
    detail: NewDeviceVerificationSubmitDetail,
  ): Promise<void> {
    if (this.pending || this.route.name !== 'newDeviceVerification') return;
    const generation = this.authAttemptGeneration;
    const route = this.route;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.newDeviceVerification.submit',
        attemptId: route.attemptId,
        code: detail.code,
        ...(route.continuationId ? { continuationId: route.continuationId } : {}),
      });
      if (!this.isCurrentAuthAttempt(generation) || this.route !== route) return;
      await this.routeAuthResult(response, generation);
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleNewDeviceVerificationCancel(): Promise<void> {
    if (this.route.name !== 'newDeviceVerification') return;
    const route = this.route;
    this.clearNewDeviceVerificationExpiry();
    const cancellation = this.request({
      type: 'auth.newDeviceVerification.cancel',
      attemptId: route.attemptId,
      ...(route.continuationId ? { continuationId: route.continuationId } : {}),
    });
    this.navigate(loginRoute());
    await cancellation;
  }

  private async handlePendingPasswordLoginCancel(): Promise<void> {
    if (this.route.name !== 'twoFactor' || this.route.flow !== 'password') return;
    const cancellation = this.request({
      type: 'auth.pendingLogin.cancel',
      ...(this.route.continuationId ? { continuationId: this.route.continuationId } : {}),
    });
    this.navigate(loginRoute());
    const generation = this.authAttemptGeneration;
    const loginRouteAfterCancel = this.route;
    const response = await cancellation;
    if (!this.isCurrentAuthAttempt(generation) || this.route !== loginRouteAfterCancel) return;
    if (!response.ok) {
      this.navigate(loginRoute(response.error.message));
      return;
    }
    if (accountPasskeyCancelResult(response.data) !== true) {
      this.navigate(loginRoute(t('auth.pendingLogin.outcomeUnknown')));
    }
  }

  private async handleAccountPasskeyStart(): Promise<void> {
    if (this.pending || this.route.name !== 'login') return;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.accountPasskey.begin' });
      if (!this.isCurrentAuthAttempt(generation)) return;
      if (!response.ok) {
        this.navigate(accountPasskeyRoute('unavailable'));
        return;
      }
      const status = accountPasskeyStatus(response.data);
      if (!status || status.status === 'none') {
        this.navigate(accountPasskeyRoute('failed'));
      } else if (status.status === 'unavailable') {
        this.navigate(accountPasskeyRoute('unavailable'));
      } else {
        this.navigate(accountPasskeyRoute(status.status));
      }
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleAccountPasskeyCancel(): Promise<void> {
    if (this.pending || this.route.name !== 'accountPasskey') return;
    const generation = ++this.authAttemptGeneration;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.accountPasskey.cancel' });
      if (!this.isCurrentAuthAttempt(generation)) return;
      if (!response.ok) {
        this.showToast(response.error.message);
        return;
      }
      const cancelled = accountPasskeyCancelResult(response.data);
      this.navigate(cancelled === true
        ? loginRoute()
        : accountPasskeyRoute('outcome_unknown'));
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleAccountPasskeyCheckState(): Promise<void> {
    if (this.pending || this.route.name !== 'accountPasskey'
        || this.route.status !== 'outcome_unknown') return;
    const generation = this.authAttemptGeneration;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.getState' });
      if (!this.isCurrentAuthAttempt(generation) || this.route.name !== 'accountPasskey') return;
      if (!response.ok) {
        this.showToast(response.error.message);
        return;
      }
      const state = (response.data as { state?: SessionState } | null)?.state;
      if (state === 'locked') {
        this.navigate(unlockRoute(undefined, t('auth.accountPasskey.success')));
      } else if (state === 'unlocked') {
        this.enterVault();
        this.showToast(t('auth.accountPasskey.unlocked'));
      } else if (state === 'restricted') {
        const requirement = restrictionFromStateData(response.data);
        if (requirement) this.navigate(restrictedRoute(requirement));
      }
    } finally {
      if (generation === this.authAttemptGeneration) this.pending = false;
    }
  }

  private async handleDeviceLoginStart(detail: DeviceLoginStartDetail): Promise<void> {
    if (this.pending || this.route.name !== 'login') return;
    this.clearDeviceLoginRequesterState();
    const generation = ++this.deviceLoginGeneration;
    const route = this.route;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.deviceLogin.begin', email: detail.email });
      if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
      if (!response.ok) {
        this.setDeviceLoginError(generation, response.error.message);
        return;
      }
      const result = deviceLoginRequesterResult(response.data);
      if (result) await this.applyDeviceLoginResult(result, generation);
      else this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
    } finally {
      if (generation === this.deviceLoginGeneration) {
        this.pending = false;
        const current = this.deviceLoginRequesterModel;
        if (current?.generation === generation && current.busy) {
          this.deviceLoginRequesterModel = Object.freeze({ ...current, busy: false });
        }
      }
    }
  }

  private async runDeviceLoginRequesterAction(
    action: 'status' | 'retry',
    expectedStatus: 'pending' | 'retry_required',
  ): Promise<void> {
    const model = this.deviceLoginRequesterModel;
    if (this.pending || this.route.name !== 'deviceLogin' || !model
      || model.status !== expectedStatus || model.ownerGeneration === undefined) return;
    const generation = model.generation;
    const route = this.route;
    this.pending = true;
    this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: true });
    try {
      const response = action === 'status'
        ? await this.request({
            type: 'auth.deviceLogin.status', generation: model.ownerGeneration,
          })
        : await this.request({
            type: 'auth.deviceLogin.retry', generation: model.ownerGeneration,
          });
      if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
      if (!response.ok) {
        this.setDeviceLoginError(generation, response.error.message);
        return;
      }
      const result = deviceLoginRequesterResult(response.data);
      if (result) await this.applyDeviceLoginResult(result, generation);
      else this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
    } finally {
      if (generation === this.deviceLoginGeneration) {
        this.pending = false;
        const current = this.deviceLoginRequesterModel;
        if (current?.generation === generation && current.busy) {
          this.deviceLoginRequesterModel = Object.freeze({ ...current, busy: false });
        }
      }
    }
  }

  private async handleDeviceLoginCancel(): Promise<void> {
    const model = this.deviceLoginRequesterModel;
    if (this.pending || !this.isDeviceLoginRequesterRoute(this.route) || !model) return;
    const generation = model.generation;
    const route = this.route;
    this.pending = true;
    this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: true });
    try {
      if (model.ownerGeneration === undefined) {
        this.clearDeviceLoginRequesterState();
        this.navigate(loginRoute());
        return;
      }
      const response = await this.request({
        type: 'auth.deviceLogin.cancel', generation: model.ownerGeneration,
      });
      if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
      if (!response.ok) {
        this.showToast(response.error.message);
        this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: false });
        return;
      }
      const cancelled = accountPasskeyCancelResult(response.data);
      if (cancelled !== true) {
        if (cancelled === undefined) {
          this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
          return;
        }
        const statusResponse = await this.request({
          type: 'auth.deviceLogin.status', generation: model.ownerGeneration,
        });
        if (!this.isCurrentDeviceLogin(generation) || this.route !== route) return;
        if (!statusResponse.ok) {
          this.showToast(statusResponse.error.message);
          this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: false });
          return;
        }
        const result = deviceLoginRequesterResult(statusResponse.data);
        if (result) await this.applyDeviceLoginResult(result, generation);
        else this.setDeviceLoginError(generation, t('auth.deviceLogin.errorDescription'));
        return;
      }
      this.pending = false;
      this.clearDeviceLoginRequesterState();
      this.navigate(loginRoute());
    } finally {
      if (generation === this.deviceLoginGeneration) this.pending = false;
    }
  }

  private async handleDeviceLoginCheckAuthState(): Promise<void> {
    const model = this.deviceLoginRequesterModel;
    if (this.pending || this.route.name !== 'deviceLogin'
      || model?.status !== 'outcome_unknown') return;
    const generation = model.generation;
    this.pending = true;
    this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: true });
    try {
      const response = await this.request({ type: 'auth.getState' });
      if (!this.isCurrentDeviceLogin(generation) || this.route.name !== 'deviceLogin') return;
      if (!response.ok) {
        this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: false });
        this.showToast(response.error.message);
        return;
      }
      const state = (response.data as { state?: SessionState } | null)?.state;
      if (state === 'unlocked') {
        this.pending = false;
        this.clearDeviceLoginRequesterState();
        this.enterVault();
      } else if (state === 'locked') {
        this.pending = false;
        this.clearDeviceLoginRequesterState();
        this.navigate(unlockRoute());
      } else if (state === 'restricted') {
        this.pending = false;
        this.clearDeviceLoginRequesterState();
        const requirement = restrictionFromStateData(response.data);
        if (requirement) this.navigate(restrictedRoute(requirement));
      } else {
        this.deviceLoginRequesterModel = Object.freeze({ ...model, busy: false });
      }
    } finally {
      if (generation === this.deviceLoginGeneration) this.pending = false;
    }
  }

  private async handleFido2Start(detail: Fido2TwoFactorStartDetail): Promise<void> {
    if (this.pending || this.route.name !== 'twoFactor') return;
    if (this.selectedTwoFactorProvider(this.route) !== 7) return;
    const challenge = this.route.fido2;
    if (!challenge || !sameInteractiveTwoFactorOwner(challenge.owner, detail.owner)) return;
    const route = this.route;
    const authGeneration = this.authAttemptGeneration;
    const deviceGeneration = this.deviceLoginGeneration;
    const workspaceGeneration = this.workspaceGeneration;
    const isCurrent = (): boolean => this.route === route
      && workspaceGeneration === this.workspaceGeneration
      && (route.flow === 'password'
        ? this.isCurrentAuthAttempt(authGeneration)
        : this.isCurrentDeviceLogin(deviceGeneration));
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.beginFido2',
        owner: detail.owner,
        locale: getLocale(),
      });
      if (!isCurrent()) return;
      if (!response.ok) {
        this.navigate(twoFactorRoute(
          route.providers,
          challenge,
          response.error.message,
          route.flow,
          route.continuationId,
        ));
      }
    } catch (error) {
      if (isCurrent()) {
        this.navigate(twoFactorRoute(
          route.providers,
          challenge,
          error instanceof Error ? error.message : t('auth.fido2.unknownResult'),
          route.flow,
          route.continuationId,
        ));
      }
    } finally {
      if (route.flow === 'password'
        ? authGeneration === this.authAttemptGeneration
        : deviceGeneration === this.deviceLoginGeneration) this.pending = false;
    }
  }

  private isCurrentAuthAttempt(generation: number): boolean {
    return this.isConnected && generation === this.authAttemptGeneration;
  }

  private twoFactorAttemptKey(route: Extract<PopupRoute, { name: 'twoFactor' }>): string {
    const generation = route.flow === 'password'
      ? this.authAttemptGeneration
      : this.deviceLoginGeneration;
    return `${route.flow}:${generation}`;
  }

  private selectedTwoFactorProvider(
    route: Extract<PopupRoute, { name: 'twoFactor' }>,
  ): number | undefined {
    const attemptKey = this.twoFactorAttemptKey(route);
    const usable = usableTwoFactorProviders(route.providers, route.fido2 !== undefined);
    const retained = this.twoFactorSelection;
    if (retained?.attemptKey === attemptKey && usable.includes(retained.provider)) {
      return retained.provider;
    }
    return preferredTwoFactorProvider(usable);
  }

  private handleTwoFactorProviderChange(detail: TwoFactorProviderChangeDetail): void {
    const route = this.route;
    if (!detail || !Number.isSafeInteger(detail.provider) || typeof detail.attemptKey !== 'string'
        || route.name !== 'twoFactor'
        || detail.attemptKey !== this.twoFactorAttemptKey(route)) return;
    const usable = usableTwoFactorProviders(route.providers, route.fido2 !== undefined);
    if (!usable.includes(detail.provider)) return;
    this.twoFactorSelection = Object.freeze({
      attemptKey: detail.attemptKey,
      provider: detail.provider,
    });
    const next = { ...route };
    delete next.error;
    delete next.notice;
    this.route = next;
  }

  private updateTwoFactorFeedback(
    route: Extract<PopupRoute, { name: 'twoFactor' }>,
    feedback: { readonly error?: string; readonly notice?: string },
  ): void {
    const next = { ...route };
    delete next.error;
    delete next.notice;
    this.navigate({ ...next, ...feedback });
  }

  private async handleSendEmailCode(detail: EmailTwoFactorCodeRequestDetail): Promise<void> {
    const route = this.route;
    if (!detail || typeof detail.attemptKey !== 'string' || typeof detail.automatic !== 'boolean'
        || this.pending || route.name !== 'twoFactor' || detail.provider !== 1
        || detail.attemptKey !== this.twoFactorAttemptKey(route)
        || this.selectedTwoFactorProvider(route) !== 1) return;
    const attemptKey = detail.attemptKey;
    const deviceOwnerGeneration = route.flow === 'device'
      ? this.deviceLoginRequesterModel?.ownerGeneration
      : undefined;
    if (route.flow === 'device' && deviceOwnerGeneration === undefined) return;

    this.pending = true;
    try {
      const response = route.flow === 'device'
        ? await this.request({
            type: 'auth.deviceLogin.sendEmailCode',
            generation: deviceOwnerGeneration!,
          })
        : await this.request({
            type: 'auth.sendEmailCode',
            ...(route.continuationId ? { continuationId: route.continuationId } : {}),
          });
      const current = this.route;
      if (!this.isConnected || current.name !== 'twoFactor'
          || this.twoFactorAttemptKey(current) !== attemptKey
          || this.selectedTwoFactorProvider(current) !== 1) return;
      if (!response.ok) {
        if (current.flow === 'password' && response.error.code === 'session_expired') {
          this.navigate(loginRoute(response.error.message));
        } else {
          this.updateTwoFactorFeedback(current, { error: response.error.message });
        }
      } else if (!detail.automatic) {
        this.updateTwoFactorFeedback(current, { notice: t('auth.twoFactor.emailCodeSent') });
      }
    } finally {
      const current = this.route;
      if (current.name === 'twoFactor' && this.twoFactorAttemptKey(current) === attemptKey) {
        this.pending = false;
      }
    }
  }

  private async handleTwoFactorRecovery(): Promise<void> {
    const route = this.route;
    if (this.pending || route.name !== 'twoFactor') return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.openTwoFactorRecovery' });
      if (this.route !== route || response.ok) return;
      this.navigate(twoFactorRoute(
        route.providers,
        route.fido2,
        response.error.message,
        route.flow,
        route.continuationId,
      ));
    } finally {
      this.pending = false;
    }
  }

  private async handleUnlockSubmit(detail: UnlockSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.unlock', masterPassword: detail.masterPassword });
      if (response.ok) {
        if (await this.resumeWebsitePasskeyAfterUnlock()) return;
        const continuation = await this.resumeAutofillAfterUnlock();
        if (continuation === 'closed') return;
        this.enterVault(continuation);
      }
      else this.navigate(unlockRoute(response.error.message));
    } finally {
      this.pending = false;
    }
  }

  private async handlePinUnlockSubmit(detail: PinUnlockSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.unlockWithPin', pin: detail.pin });
      if (response.ok) {
        if (await this.resumeWebsitePasskeyAfterUnlock()) return;
        const continuation = await this.resumeAutofillAfterUnlock();
        if (continuation === 'closed') return;
        this.enterVault(continuation);
      } else if (response.error.code === 'invalid_pin') {
        this.navigate(unlockRoute(t('auth.invalidPin')));
      } else if (response.error.code === 'pin_attempts_exceeded') {
        const state = await this.request({ type: 'auth.getState' });
        this.resetVaultState();
        if (state.ok && (state.data as { state?: SessionState }).state === 'locked') {
          this.navigate(unlockRoute(t('auth.tooManyInvalidPin')));
        } else {
          this.navigate(loginRoute(t('auth.tooManyInvalidPin')));
        }
      } else {
        this.navigate(unlockRoute(response.error.message));
      }
    } finally {
      this.pending = false;
    }
  }

  private async handleLogout(): Promise<void> {
    if (this.pending) return;
    if (typeof window !== 'undefined' && !window.confirm(t('auth.logoutConfirm'))) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.logout' });
      if (!response.ok) {
        this.showToast(response.error.message);
        return;
      }
      this.resetVaultState();
      await this.reRouteFromState();
    } finally {
      this.pending = false;
    }
  }

  private async handleEmailChange(email: string): Promise<void> {
    this.deviceCheckEmail = email;
    this.deviceForgotten = false;
    if (!email) {
      this.deviceRemembered = false;
      this.ssoRequired = false;
      return;
    }
    const [response, ssoResponse] = await Promise.all([
      this.request({ type: 'auth.isDeviceRemembered', email }),
      this.request({ type: 'auth.sso.requirement', email }),
    ]);
    if (this.deviceCheckEmail !== email) return; // superseded by a newer change
    this.deviceRemembered = response.ok && (response.data as { remembered: boolean }).remembered;
    this.ssoRequired = ssoResponse.ok
      && (ssoResponse.data as { required?: unknown }).required === true;
  }

  private async handleForgetDevice(): Promise<void> {
    const email = this.deviceCheckEmail;
    if (!email) return;
    const response = await this.request({ type: 'auth.forgetDevice', email });
    if (response.ok) {
      this.deviceRemembered = false;
      this.deviceForgotten = true;
    }
  }

  // --- Vault (unlocked) orchestration -------------------------------------------------------

  /** Enter the vault at its default (Suggestions) scope and kick off the reads it needs. Every
   *  navigation into the vault goes through here so listing, account, and Suggestions data are
   *  refreshed from the worker/browser rather than trusted from a prior session. */
  private enterVault(
    continuationSuggestions?: { readonly tabId: number; readonly outcome: TabSuggestionsOutcome },
  ): void {
    this.clearSyncStatusPoll();
    this.workspaceGeneration += 1;
    this.vaultDataReadyGeneration = undefined;
    this.latestListingSeq += 1;
    this.latestSyncStatusSeq += 1;
    this.resetExternalSyncRefreshState();
    this.sshAvailabilitySeq += 1;
    this.sshWriteAvailability = 'idle';
    this.syncStatus = null;
    this.vaultScope = 'suggestions';
    this.vaultMode = 'active';
    const route: PopupRoute = this.openDeviceLoginApprovals
      ? { name: 'deviceLoginApprovals', view: 'list' }
      : { name: 'vault', scope: 'suggestions' };
    this.openDeviceLoginApprovals = false;
    this.dataOwnershipCheckPending = true;
    this.navigate(route);
    void this.loadVaultData(continuationSuggestions);
  }

  private async resumeAutofillAfterUnlock(): Promise<
    { readonly tabId: number; readonly outcome: TabSuggestionsOutcome } | 'closed' | undefined
  > {
    const continuation = this.autofillContinuation;
    if (!continuation || continuation.status !== 'unlock_required') return undefined;
    this.autofillContinuation = null;
    const response = await this.request({
      type: 'autofill.continuation.resumeUnlock',
      continuationId: continuation.continuationId,
    });
    if (!response.ok) {
      this.showToast(response.error.message);
      return undefined;
    }
    const result = response.data as AutofillContinuationResumeData;
    if (result.status === 'show_suggestions') return { tabId: result.tabId, outcome: result.outcome };
    if (result.status === 'started') {
      try { window.close(); } catch { /* best effort */ }
      return 'closed';
    }
    this.showToast(t('fill.targetChanged'));
    return undefined;
  }

  private async loadVaultData(
    continuationSuggestions?: { readonly tabId: number; readonly outcome: TabSuggestionsOutcome },
  ): Promise<void> {
    const generation = this.workspaceGeneration;
    await Promise.all([
      this.loadListing(generation),
      this.loadAccounts(generation),
      this.loadDeviceLoginApprovals(generation),
      continuationSuggestions
        ? Promise.resolve(this.applyContinuationSuggestions(continuationSuggestions))
        : this.loadSuggestions(),
      this.loadSyncStatus(generation),
    ]);
    if (!this.isCurrentWorkspace(generation)) return;
    this.vaultDataReadyGeneration = generation;
    this.openPendingAutofillReprompt();
    this.openPendingContextMenuCreate();
  }

  private openPendingContextMenuCreate(): void {
    const intent = this.pendingContextMenuCreate;
    if (!intent || this.vaultDataReadyGeneration !== this.workspaceGeneration) return;
    if (!this.isUnlockedWorkspace()
        || this.route.name === 'restricted'
        || this.route.name === 'dataOwnership'
        || this.autofillContinuation !== null) {
      this.pendingContextMenuCreate = undefined;
      return;
    }
    const nextRoute = { name: 'editor', mode: 'create', cipherType: intent.cipherType } as const;
    if (!this.promptForDraftDiscard(nextRoute)) {
      this.pendingContextMenuCreate = undefined;
      return;
    }
    this.pendingContextMenuCreate = undefined;
    const defaults = this.currentFilterCreateDefaults();
    this.openEditor(nextRoute, {
      ...defaults,
      ...(intent.cipherType === 1 && intent.loginUri ? { loginUri: intent.loginUri } : {}),
    });
  }

  private applyContinuationSuggestions(input: {
    readonly tabId: number;
    readonly outcome: TabSuggestionsOutcome;
  }): void {
    this.latestSuggestionsSeq += 1;
    this.activeTabId = input.tabId;
    this.suggestionsState = input.outcome.status === 'ready'
      ? {
          status: 'ready',
          suggestions: input.outcome.suggestions
            .map(toPopupSuggestion)
            .filter((suggestion): suggestion is TabAutofillSuggestion => suggestion !== undefined),
        }
      : { status: 'unavailable', reason: input.outcome.status };
  }

  private openPendingAutofillReprompt(): void {
    const continuation = this.autofillContinuation;
    if (!continuation || continuation.status !== 'reprompt_required'
        || continuation.expiresAt <= Date.now() || this.route.name !== 'vault') return;
    const item = this.items.find((candidate) => (
      candidate.id === continuation.cipherId && candidate.reprompt === true
    ));
    if (!item) {
      this.cancelAutofillContinuation();
      return;
    }
    this.navigate({ name: 'detail', cipherId: continuation.cipherId });
    this.repromptError = t('fill.repromptRequired');
    this.requestUpdate();
  }

  private cancelAutofillContinuation(): void {
    const continuation = this.autofillContinuation;
    this.autofillContinuation = null;
    if (continuation) {
      void this.request({
        type: 'autofill.continuation.cancel',
        continuationId: continuation.continuationId,
      });
    }
  }

  private async loadSshWriteAvailability(): Promise<void> {
    if (this.sshWriteAvailability !== 'idle') return;
    const generation = this.workspaceGeneration;
    const seq = ++this.sshAvailabilitySeq;
    this.sshWriteAvailability = 'loading';
    const response = await this.request({ type: 'vault.getSshKeyWriteAvailability' });
    if (!this.isCurrentWorkspace(generation) || seq !== this.sshAvailabilitySeq) return;
    this.sshWriteAvailability = response.ok
      && Boolean((response.data as { available?: boolean } | null)?.available)
      ? 'available'
      : 'unavailable';
  }

  private async loadSyncStatus(generation = this.workspaceGeneration): Promise<void> {
    const seq = ++this.latestSyncStatusSeq;
    const response = await this.request({ type: 'vault.getSyncStatus' });
    if (!this.isCurrentWorkspace(generation) || seq !== this.latestSyncStatusSeq) return;
    if (!response.ok) {
      this.clearSyncStatusPoll();
      this.syncStatus = null;
      return;
    }
    const data = response.data as Partial<PopupSyncStatus> | null;
    if (!data || typeof data.dirty !== 'boolean' || typeof data.syncing !== 'boolean') {
      this.clearSyncStatusPoll();
      this.syncStatus = null;
      return;
    }
    this.syncStatus = {
      ...(typeof data.identity === 'string' ? { identity: data.identity } : {}),
      ...(typeof data.lastSuccessfulSyncAt === 'number' && Number.isFinite(data.lastSuccessfulSyncAt)
        ? { lastSuccessfulSyncAt: data.lastSuccessfulSyncAt }
        : {}),
      dirty: data.dirty,
      syncing: data.syncing,
    };
    this.processPendingVaultSyncSuccess();
    if (data.syncing) this.scheduleSyncStatusPoll(generation);
    else this.clearSyncStatusPoll();
  }

  private scheduleSyncStatusPoll(generation: number): void {
    if (this.syncStatusPollTimer !== undefined) return;
    this.syncStatusPollTimer = window.setTimeout(() => {
      this.syncStatusPollTimer = undefined;
      if (this.isCurrentWorkspace(generation) && this.syncing) {
        void this.loadSyncStatus(generation);
      }
    }, SYNC_STATUS_POLL_MS);
  }

  private clearSyncStatusPoll(): void {
    if (this.syncStatusPollTimer === undefined) return;
    clearTimeout(this.syncStatusPollTimer);
    this.syncStatusPollTimer = undefined;
  }

  private resetExternalSyncRefreshState(): void {
    this.syncSuccessCursor = undefined;
    this.pendingVaultSyncSuccesses.clear();
    this.pendingExternalSyncRefresh = undefined;
  }

  private processPendingVaultSyncSuccess(): void {
    const identity = this.syncStatus?.identity;
    if (!identity) return;
    for (const pendingIdentity of this.pendingVaultSyncSuccesses.keys()) {
      if (pendingIdentity !== identity) this.pendingVaultSyncSuccesses.delete(pendingIdentity);
    }
    const pending = this.pendingVaultSyncSuccesses.get(identity);
    const cursor = this.syncSuccessCursor;
    const cursorMatches = cursor?.workspaceGeneration === this.workspaceGeneration
      && cursor.identity === identity;
    const statusSuccess = this.syncStatus?.lastSuccessfulSyncAt ?? -1;
    if (!pending) {
      if (!cursorMatches) {
        this.syncSuccessCursor = {
          workspaceGeneration: this.workspaceGeneration,
          identity,
          lastSuccess: statusSuccess,
          metadataObserved: false,
        };
      }
      return;
    }

    this.pendingVaultSyncSuccesses.delete(identity);
    const baseline = cursorMatches ? cursor.lastSuccess : -1;
    if (pending.lastSuccess < baseline
      || (pending.lastSuccess === baseline && cursorMatches && cursor.metadataObserved)) return;
    this.queueExternalSyncRefresh({
      workspaceGeneration: this.workspaceGeneration,
      identity,
      lastSuccess: pending.lastSuccess,
    });
  }

  private queueExternalSyncRefresh(refresh: ExternalSyncRefresh): void {
    if (!this.isCurrentWorkspace(refresh.workspaceGeneration)
      || this.syncStatus?.identity !== refresh.identity) return;
    const queued = this.pendingExternalSyncRefresh;
    if (!queued
      || queued.workspaceGeneration !== refresh.workspaceGeneration
      || queued.identity !== refresh.identity
      || refresh.lastSuccess > queued.lastSuccess) {
      this.pendingExternalSyncRefresh = refresh;
    }
    if (this.externalSyncRefreshActive) return;
    this.externalSyncRefreshActive = true;
    void this.drainExternalSyncRefreshes().finally(() => {
      this.externalSyncRefreshActive = false;
      if (this.pendingExternalSyncRefresh && this.isConnected) {
        const next = this.pendingExternalSyncRefresh;
        this.pendingExternalSyncRefresh = undefined;
        this.queueExternalSyncRefresh(next);
      }
    });
  }

  private async drainExternalSyncRefreshes(): Promise<void> {
    while (this.pendingExternalSyncRefresh) {
      const refresh = this.pendingExternalSyncRefresh;
      this.pendingExternalSyncRefresh = undefined;
      if (!this.isCurrentWorkspace(refresh.workspaceGeneration)
        || this.syncStatus?.identity !== refresh.identity) return;
      await Promise.all([
        this.loadListing(refresh.workspaceGeneration),
        this.loadSuggestions(),
        this.loadSyncStatus(refresh.workspaceGeneration),
      ]);
      if (!this.isCurrentWorkspace(refresh.workspaceGeneration)
        || this.syncStatus?.identity !== refresh.identity) return;
      const current = this.syncSuccessCursor;
      this.syncSuccessCursor = {
        workspaceGeneration: refresh.workspaceGeneration,
        identity: refresh.identity,
        lastSuccess: Math.max(
          refresh.lastSuccess,
          this.syncStatus.lastSuccessfulSyncAt ?? -1,
          current?.workspaceGeneration === refresh.workspaceGeneration
            && current.identity === refresh.identity ? current.lastSuccess : -1,
        ),
        metadataObserved: true,
      };
    }
  }

  private applyListingData(
    data: {
      items: CipherSummary[];
      folders: FolderSummary[];
      collections: CollectionSummary[];
      orgPermissions: OrgPermission[];
      personalCreationAllowed?: boolean;
    } | null,
  ): void {
    this.items = data?.items ?? [];
    this.folders = data?.folders ?? [];
    this.collections = data?.collections ?? [];
    this.orgPermissions = data?.orgPermissions ?? [];
    this.personalCreationAllowed = data?.personalCreationAllowed === true;
    this.reconcileListingFilters();
  }

  /** Remove only facets that can no longer be resolved by the authoritative listing. */
  private reconcileListingFilters(): void {
    if (this.selectedFolderId !== null
      && this.selectedFolderId !== NO_FOLDER
      && this.folders.filter((folder) => folder.id === this.selectedFolderId).length !== 1) {
      this.selectedFolderId = null;
    }
    let organizationInvalidated = false;
    if (this.selectedOrganizationId !== null
      && this.selectedOrganizationId !== PERSONAL_VAULT_FILTER_ID
      && this.orgPermissions.filter((organization) => (
        organization.id === this.selectedOrganizationId
      )).length !== 1) {
      this.selectedOrganizationId = null;
      organizationInvalidated = true;
    }
    if (this.selectedCollectionId === null) return;
    const collections = this.collections.filter((collection) => collection.id === this.selectedCollectionId);
    const collectionOrganizationIsResolvable = collections.length === 1
      && this.orgPermissions.filter((organization) => (
        organization.id === collections[0]!.organizationId
      )).length === 1;
    if (collections.length !== 1
      || this.selectedOrganizationId === PERSONAL_VAULT_FILTER_ID
      || (this.selectedOrganizationId !== null
        && collections[0]!.organizationId !== this.selectedOrganizationId)
      || (organizationInvalidated && !collectionOrganizationIsResolvable)) {
      this.selectedCollectionId = null;
    }
  }

  private applyListingResponse(response: ResponseMessage): void {
    if (!response.ok) return;
    this.applyListingData(
      response.data as {
        items: CipherSummary[];
        folders: FolderSummary[];
        collections: CollectionSummary[];
        orgPermissions: OrgPermission[];
        personalCreationAllowed?: boolean;
      } | null,
    );
  }

  private async loadListing(generation = this.workspaceGeneration): Promise<void> {
    const seq = ++this.latestListingSeq;
    const guardPresentation = this.route.name === 'vault' || this.route.name === 'dataOwnership';
    if (guardPresentation) this.dataOwnershipCheckPending = true;
    const [listing, skipped, ownership] = await Promise.all([
      this.request({ type: 'vault.listItems' }),
      this.request({ type: 'vault.getSkippedOrgCount' }),
      this.request({ type: 'vault.getOrganizationDataOwnershipStatus' }),
    ]);
    if (!this.isCurrentWorkspace(generation) || seq !== this.latestListingSeq) return;
    if (guardPresentation) this.dataOwnershipCheckPending = false;
    this.applyListingResponse(listing);
    this.skippedOrgCount = skipped.ok ? ((skipped.data as { count?: number } | null)?.count ?? 0) : 0;
    this.organizationDataOwnershipStatus = ownership.ok
      ? parseOrganizationDataOwnershipStatus(ownership.data)
      : { status: 'unavailable' };
    if ((this.organizationDataOwnershipStatus.status === 'migration_available'
          || this.organizationDataOwnershipStatus.status === 'blocked'
          || this.organizationDataOwnershipStatus.status === 'reconciliation_required'
          || this.organizationDataOwnershipStatus.status === 'unavailable')
        && this.route.name !== 'dataOwnership') {
      this.dataOwnershipError = undefined;
      this.navigate({ name: 'dataOwnership' });
    } else if ((this.organizationDataOwnershipStatus.status === 'compliant'
        || this.organizationDataOwnershipStatus.status === 'not_required')
        && this.route.name === 'dataOwnership') {
      this.navigate({ name: 'vault', scope: 'all' });
    }
  }

  private async loadAccounts(generation = this.workspaceGeneration): Promise<void> {
    const [accounts, pin, remembered] = await Promise.all([
      this.request({ type: 'auth.listAccounts' }),
      this.request({ type: 'auth.pinStatus' }),
      this.request({ type: 'auth.isDeviceRemembered' }),
    ]);
    if (!this.isCurrentWorkspace(generation)) return;
    this.accounts = accounts.ok ? ((accounts.data as { accounts?: AccountInfo[] } | null)?.accounts ?? []) : [];
    const pinStatus = pin.ok ? pin.data as PinStatusData : undefined;
    this.pinAllowed = pinStatus !== undefined && pinStatus.allowed !== false;
    this.pinConfigured = this.pinAllowed && pinStatus?.enabled === true;
    this.pinRequireMasterPasswordOnRestart = pinStatus?.requireMasterPasswordOnRestart !== false;
    this.vaultDeviceRemembered = remembered.ok && Boolean((remembered.data as { remembered?: boolean } | null)?.remembered);
  }

  private async loadDeviceLoginApprovals(
    workspaceGeneration = this.workspaceGeneration,
    notice?: DeviceLoginApproverListViewModel['notice'],
  ): Promise<void> {
    const operation = ++this.deviceLoginApprovalGeneration;
    if (this.route.name === 'deviceLoginApprovals') {
      const currentRequests = this.deviceLoginApprovalModel?.kind === 'approver-list'
        ? this.deviceLoginApprovalModel.requests
        : [];
      this.deviceLoginApprovalModel = Object.freeze({
        kind: 'approver-list',
        requests: currentRequests,
        busy: true,
        labels: deviceLoginLabels(),
        ...(notice ? { notice } : {}),
      });
    }
    const response = await this.request({ type: 'auth.deviceLogin.approvals.list' });
    if (!this.isCurrentWorkspace(workspaceGeneration)
      || operation !== this.deviceLoginApprovalGeneration) return;
    const data = response.ok ? deviceLoginRecord(response.data, ['approvals']) : undefined;
    const projected = data && Reflect.ownKeys(data).length === 1
      ? deviceLoginApprovalList(data.approvals)
      : undefined;
    this.deviceLoginApprovalBindings.clear();
    if (!response.ok || !projected) {
      this.deviceLoginApprovalCount = 0;
      this.deviceLoginApprovalModel = Object.freeze({
        kind: 'approver-list',
        requests: Object.freeze([]),
        busy: false,
        labels: deviceLoginLabels(),
        notice: notice ?? Object.freeze({
          tone: 'danger',
          message: response.ok ? t('auth.deviceLogin.errorDescription') : response.error.message,
        }),
      });
      return;
    }
    this.deviceLoginApprovalCount = projected.requests.filter((request) => request.status === 'pending').length;
    this.deviceLoginApprovalModel = Object.freeze({
      kind: 'approver-list',
      requests: projected.requests,
      busy: false,
      labels: deviceLoginLabels(),
      ...(notice ? { notice } : {}),
    });
  }

  private async handleDeviceLoginApprovalSelect(
    detail: DeviceLoginRequestActionDetail,
  ): Promise<void> {
    const model = this.deviceLoginApprovalModel;
    if (this.pending || this.route.name !== 'deviceLoginApprovals' || this.route.view !== 'list'
      || model?.kind !== 'approver-list'
      || !model.requests.some((request) => request.requestId === detail.requestId
        && request.status === 'pending')) return;
    const workspaceGeneration = this.workspaceGeneration;
    const operation = ++this.deviceLoginApprovalGeneration;
    this.deviceLoginApprovalBindings.clear();
    this.pending = true;
    this.deviceLoginApprovalModel = Object.freeze({ ...model, busy: true });
    try {
      const response = await this.request({
        type: 'auth.deviceLogin.approvals.get',
        requestId: detail.requestId,
      });
      if (!this.isCurrentWorkspace(workspaceGeneration)
        || operation !== this.deviceLoginApprovalGeneration
        || this.route.name !== 'deviceLoginApprovals' || this.route.view !== 'list') return;
      const data = response.ok ? deviceLoginRecord(response.data, ['approval']) : undefined;
      const projected = data && Reflect.ownKeys(data).length === 1
        ? deviceLoginApproval(data.approval)
        : undefined;
      if (!response.ok || !projected || projected.display.requestId !== detail.requestId
        || projected.display.status !== 'pending') {
        this.deviceLoginApprovalModel = Object.freeze({
          ...model,
          busy: false,
          notice: Object.freeze({
            tone: 'danger',
            message: response.ok ? t('auth.deviceLogin.errorDescription') : response.error.message,
          }),
        });
        return;
      }
      this.deviceLoginApprovalBindings.set(detail.requestId, Object.freeze({
        binding: projected.binding,
        expiresAt: projected.expiresAt,
        workspaceGeneration,
      }));
      this.deviceLoginApprovalModel = Object.freeze({
        kind: 'approver-detail',
        request: projected.display,
        busy: false,
        labels: deviceLoginLabels(),
      });
      this.navigate({ name: 'deviceLoginApprovals', view: 'detail' });
    } finally {
      if (operation === this.deviceLoginApprovalGeneration) this.pending = false;
    }
  }

  private async handleDeviceLoginApprovalDecision(
    detail: DeviceLoginRequestActionDetail,
    approve: boolean,
  ): Promise<void> {
    const model = this.deviceLoginApprovalModel;
    const stored = this.deviceLoginApprovalBindings.get(detail.requestId);
    if (this.pending || this.route.name !== 'deviceLoginApprovals' || this.route.view !== 'detail'
      || model?.kind !== 'approver-detail' || model.request.requestId !== detail.requestId
      || !stored || stored.workspaceGeneration !== this.workspaceGeneration
      || stored.expiresAt <= Date.now()) return;
    const workspaceGeneration = this.workspaceGeneration;
    const operation = ++this.deviceLoginApprovalGeneration;
    this.deviceLoginApprovalBindings.delete(detail.requestId);
    this.pending = true;
    this.deviceLoginApprovalModel = Object.freeze({ ...model, busy: true });
    const response = await this.request({
      type: approve
        ? 'auth.deviceLogin.approvals.approve'
        : 'auth.deviceLogin.approvals.deny',
      decisionBinding: stored.binding,
    });
    if (!this.isCurrentWorkspace(workspaceGeneration)
      || operation !== this.deviceLoginApprovalGeneration
      || this.route.name !== 'deviceLoginApprovals' || this.route.view !== 'detail') return;
    let notice: DeviceLoginApproverListViewModel['notice'];
    if (response.ok && validDeviceLoginDecisionReceipt(response.data, detail.requestId, approve)) {
      notice = Object.freeze({
        tone: 'success',
        message: t(approve ? 'auth.deviceLogin.approved' : 'auth.deviceLogin.denied'),
      });
    } else if (!response.ok && response.error.code === 'outcome_unknown') {
      notice = Object.freeze({ tone: 'warning', message: t('auth.deviceLogin.approvalOutcomeUnknown') });
    } else {
      notice = Object.freeze({
        tone: 'danger',
        message: response.ok ? t('auth.deviceLogin.approvalOutcomeUnknown') : response.error.message,
      });
    }
    this.navigate({ name: 'deviceLoginApprovals', view: 'list' });
    await this.loadDeviceLoginApprovals(workspaceGeneration, notice);
    if (this.isCurrentWorkspace(workspaceGeneration)
      && this.route.name === 'deviceLoginApprovals') this.pending = false;
  }

  private async handleDeviceLoginApprovalBack(): Promise<void> {
    if (this.pending || this.route.name !== 'deviceLoginApprovals') return;
    const workspaceGeneration = this.workspaceGeneration;
    this.pending = true;
    this.navigate({ name: 'deviceLoginApprovals', view: 'list' });
    try {
      await this.loadDeviceLoginApprovals(workspaceGeneration);
    } finally {
      if (this.isCurrentWorkspace(workspaceGeneration)
        && this.route.name === 'deviceLoginApprovals') this.pending = false;
    }
  }

  /** Resolve the active tab, then ask the worker for its login suggestions. A missing tab is the
   *  explicit `no_eligible_tab` neutral state; unavailable outcomes map to their reason; only
   *  non-secret `TabAutofillSuggestion`s ever reach `suggestionsState`. */
  private async loadSuggestions(preferredTabId?: number): Promise<void> {
    const generation = this.workspaceGeneration;
    const seq = ++this.latestSuggestionsSeq;
    this.suggestionsState = { status: 'loading' };
    const tabId = preferredTabId ?? await this.browser.getActiveTabId();
    if (!this.isCurrentWorkspace(generation) || seq !== this.latestSuggestionsSeq) return;
    if (tabId === undefined) {
      this.activeTabId = undefined;
      this.suggestionsState = { status: 'unavailable', reason: 'no_eligible_tab' };
      return;
    }
    this.activeTabId = tabId;
    const response = await this.request({ type: 'autofill.getTabSuggestions', tabId });
    if (!this.isCurrentWorkspace(generation) || seq !== this.latestSuggestionsSeq) return;
    if (!response.ok) {
      this.suggestionsState = { status: 'error', message: response.error.message };
      return;
    }
    const { outcome } = response.data as { outcome: TabSuggestionsOutcome };
    this.suggestionsState = outcome.status === 'ready'
      ? {
          status: 'ready',
          suggestions: outcome.suggestions
            .map(toPopupSuggestion)
            .filter((suggestion): suggestion is TabAutofillSuggestion => suggestion !== undefined),
        }
      : { status: 'unavailable', reason: outcome.status };
  }

  private currentFillTarget(cipherId: string): {
    readonly tabId: number;
    readonly target: TabSuggestionTarget;
  } | undefined {
    if (this.activeTabId === undefined || this.suggestionsState.status !== 'ready') return undefined;
    const suggestion = this.suggestionsState.suggestions.find(
      (candidate) => candidate.id === cipherId && candidate.target !== undefined,
    );
    if (!suggestion?.target) return undefined;
    return { tabId: this.activeTabId, target: suggestion.target };
  }

  /** Fill the current tab from a suggestion. Sends only tabId/cipherId/target — never credentials —
   *  and maps both `ok:false` errors and every `TabFillOutcome` status to a local `fillResult`. */
  private async handleSuggestionFill(detail: SuggestionFillDetail): Promise<void> {
    const generation = this.workspaceGeneration;
    const tabId = this.activeTabId;
    if (tabId === undefined) {
      this.fillResult = { outcome: 'no_eligible_tab' };
      return;
    }
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    let repromptAuthorizationId: string | undefined;
    if (item?.reprompt) {
      const targetKey = fillTargetKey(detail.target);
      const authorization = this.repromptAutofillAuthorization;
      if (
        !authorization
        || authorization.cipherId !== detail.cipherId
        || authorization.tabId !== tabId
        || authorization.targetKey !== targetKey
        || authorization.expiresAt <= Date.now()
      ) {
        this.navigate({ name: 'detail', cipherId: detail.cipherId });
        this.repromptFillContinuation = {
          kind: 'matched',
          cipherId: detail.cipherId,
          tabId,
          target: detail.target,
        };
        this.repromptError = t('fill.repromptRequired');
        this.requestUpdate();
        return;
      }
      repromptAuthorizationId = authorization.authorizationId;
      this.repromptFillContinuation = null;
      this.clearEphemeralDetailState();
      this.requestUpdate();
    }
    const response = await this.request({
      type: 'autofill.fillTabSuggestion',
      tabId,
      cipherId: detail.cipherId,
      target: detail.target,
      ...(repromptAuthorizationId === undefined ? {} : { repromptAuthorizationId }),
    });
    if (!this.isCurrentWorkspace(generation) || this.activeTabId !== tabId) return;
    if (!response.ok) {
      this.fillResult = { error: response.error.message };
      this.showToast(response.error.message);
      return;
    }
    const { outcome } = response.data as { outcome: TabFillOutcome };
    this.fillResult = { outcome: outcome.status };
    this.showToast(outcome.status === 'filled' ? t('content.filled') : this.fillOutcomeMessage(outcome.status));
  }

  private fillOutcomeMessage(status: Exclude<TabFillOutcome['status'], 'filled'>): string {
    switch (status) {
      case 'no_eligible_tab': return t('fill.noEligibleTab');
      case 'site_access_unavailable': return t('fill.siteAccessUnavailable');
      case 'no_fillable_target': return t('fill.noFillableTarget');
      case 'reprompt_required': return t('fill.repromptRequired');
      case 'vault_locked': return t('fill.vaultLocked');
      case 'sync_required': return t('fill.syncRequired');
      case 'no_longer_matched': return t('fill.noLongerMatched');
      case 'target_changed': return t('fill.targetChanged');
      case 'fill_outcome_unknown': return t('fill.outcomeUnknown');
      case 'restricted_page': return t('fill.restrictedPage');
      case 'content_script_unavailable': return t('fill.contentScriptUnavailable');
    }
  }

  private handleScopeChange(id: string): void {
    if (id === 'suggestions' || id === 'all') {
      this.vaultMode = 'active';
      this.vaultScope = id;
      this.navigate({ name: 'vault', scope: id });
    }
  }

  /** Expand/collapse an item's inline detail card. Selecting clears any stale reprompt/extras cache. */
  private handleItemToggle(cipherId: string): void {
    if (cipherId && this.isUnsupportedItem(cipherId)) return;
    this.detailEpoch += 1;
    this.selectedCipherId = cipherId ? cipherId : null;
    this.detailStatus = undefined;
    this.detailExtrasCache = undefined;
  }

  private handleCategoryChange(category: CategoryId): void {
    this.category = category;
    this.handleItemToggle('');
  }

  /** Fill a matched suggestion directly or ask the worker to prepare one exact mismatched target. */
  private async handleItemFill(cipherId: string): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === cipherId);
    if (this.pending || !item || item.type !== 1
        || this.isUnsupportedItem(cipherId) || isCipherInactive(item)) return;
    const suggestion = this.suggestionsState.status === 'ready'
      ? this.suggestionsState.suggestions.find((s) => s.id === cipherId)
      : undefined;
    if (suggestion?.target) {
      await this.handleSuggestionFill({ cipherId, target: suggestion.target });
      return;
    }
    if (this.route.name === 'detail' && this.itemPrimaryAction(item) === 'open') {
      const uri = item.uris[0];
      if (uri) await this.browser.openUrl(uri);
      return;
    }
    await this.prepareManualAutofill(item);
  }

  private async prepareManualAutofill(item: CipherSummary): Promise<void> {
    const generation = this.workspaceGeneration;
    const tabId = await this.browser.getActiveTabId();
    if (!this.isCurrentWorkspace(generation) || tabId === undefined) {
      this.showToast(t('fill.noEligibleTab'));
      return;
    }
    this.discardManualAutofillConfirmation();
    this.pending = true;
    try {
      const response = await this.request({
        type: 'autofill.manual.prepare',
        tabId,
        cipherId: item.id,
      });
      if (!this.isCurrentWorkspace(generation)) return;
      if (!response.ok) {
        this.fillResult = { error: response.error.message };
        this.showToast(response.error.message);
        return;
      }
      const preparation = parseManualAutofillPreparation(response.data);
      if (!preparation) {
        this.showToast(t('common.error'));
        return;
      }
      this.manualAutofillConfirmation = {
        cipherId: item.id,
        tabId,
        name: item.name,
        warning: preparation.warning,
        authorization: preparation.authorization,
      };
      this.requestUpdate();
    } finally {
      this.pending = false;
    }
  }

  private async handleManualAutofillAction(detail: ManualAutofillActionDetail): Promise<void> {
    const confirmation = this.manualAutofillConfirmation;
    if (this.pending || !confirmation
        || (detail.action === 'fill_and_save' && !confirmation.warning.canSave)
        || confirmation.authorization.expiresAt <= Date.now()) return;
    const selected = { ...confirmation, action: detail.action } as const;
    this.manualAutofillConfirmation = selected;
    if (confirmation.warning.requiresReprompt) {
      this.preserveManualAutofillOnNavigation = true;
      try {
        this.navigate({ name: 'detail', cipherId: confirmation.cipherId });
      } finally {
        this.preserveManualAutofillOnNavigation = false;
      }
      this.repromptFillContinuation = { kind: 'manual', cipherId: confirmation.cipherId };
      this.repromptError = t('fill.repromptRequired');
      this.requestUpdate();
      return;
    }
    this.pending = true;
    try {
      await this.commitManualAutofill(selected);
    } finally {
      this.pending = false;
    }
  }

  private handleManualAutofillCancel(): void {
    if (this.pending) return;
    this.discardManualAutofillConfirmation();
    this.requestUpdate();
  }

  private async commitManualAutofill(
    confirmation: ManualAutofillConfirmationState & { readonly action: ManualAutofillAction },
    masterPassword?: string,
  ): Promise<void> {
    const generation = this.workspaceGeneration;
    this.manualAutofillConfirmation = null;
    this.repromptFillContinuation = null;
    const pendingResponse = this.request({
      type: 'autofill.manual.commit',
      authorizationId: confirmation.authorization.authorizationId,
      action: confirmation.action,
      ...(masterPassword === undefined ? {} : { masterPassword }),
    });
    const response = await pendingResponse;
    if (!this.isCurrentWorkspace(generation)) return;
    if (!response.ok) {
      this.fillResult = { error: response.error.message };
      if (this.route.name === 'detail') this.navigate({ name: 'vault', scope: this.vaultScope });
      this.showToast(t('fill.manual.retry'));
      return;
    }
    const outcome = (response.data as { outcome: ManualAutofillCommitOutcome }).outcome;
    switch (outcome.status) {
      case 'filled_and_saved':
        this.fillResult = {};
        this.showToast(t('fill.manual.filledAndSaved'));
        await this.loadListing(generation);
        break;
      case 'filled_but_save_failed':
        this.fillResult = {};
        this.showToast(t('fill.manual.filledButSaveFailed'));
        break;
      case 'filled_but_save_conflict':
        this.fillResult = {};
        this.showToast(t('fill.manual.filledButSaveConflict'));
        break;
      case 'filled_but_save_committed_unsynced':
        this.fillResult = {};
        this.showToast(t('fill.manual.filledButSaveCommittedUnsynced'));
        break;
      case 'filled_but_save_outcome_unknown':
        this.fillResult = {};
        this.showToast(t('fill.manual.filledButSaveOutcomeUnknown'));
        break;
      default:
        this.fillResult = { outcome: outcome.status };
        this.showToast(outcome.status === 'filled'
          ? t('content.filled')
          : this.fillOutcomeMessage(outcome.status));
        break;
    }
    if (this.route.name === 'detail') this.navigate({ name: 'vault', scope: this.vaultScope });
  }

  /** Request a manual sync, apply its listing, then refresh scheduler-owned status and suggestions. */
  private async syncVault(): Promise<void> {
    const generation = this.workspaceGeneration;
    const response = await this.request({ type: 'vault.sync' });
    if (!this.isCurrentWorkspace(generation)) return;
    if (!response.ok) {
      this.showToast(response.error.message);
      await this.loadSyncStatus(generation);
      return;
    }
    this.applyListingResponse(response);
    await Promise.all([this.loadSuggestions(), this.loadSyncStatus(generation)]);
  }

  /** Manual sync uses `pending` only as a duplicate-submit guard. Visual sync state comes solely
   *  from `vault.getSyncStatus`. */
  private async handleSync(): Promise<void> {
    if (this.syncing || this.pending || this.sendEncoding) return;
    this.pending = true;
    try {
      await this.syncVault();
    } finally {
      this.pending = false;
    }
  }

  /** Toggle the generator overlay from the top bar (returns to the vault list when already open). */
  private handleGeneratorToggle(): void {
    if (this.pending || this.sendEncoding) return;
    if (this.route.name === 'generator') this.userNavigate({ name: 'vault', scope: this.vaultScope });
    else this.userNavigate({ name: 'generator' });
  }

  /** Toggle the 2FA (authenticator) view from the top bar, back to the vault on a second press. */
  private handleTotpToggle(): void {
    if (this.pending || this.sendEncoding) return;
    if (this.route.name === 'totp') this.userNavigate({ name: 'vault', scope: this.vaultScope });
    else this.userNavigate({ name: 'totp' });
  }

  /** Load every login's live one-time code for the 2FA view, then start the local countdown tick. */
  private async loadTotpCodes(): Promise<void> {
    const generation = this.workspaceGeneration;
    const response = await this.request({ type: 'vault.getTotpCodes' });
    if (!this.isCurrentWorkspace(generation) || this.route.name !== 'totp') return;
    this.totpEntries = response.ok && response.data && 'totpEntries' in response.data ? response.data.totpEntries : [];
    this.startTotpListTick();
  }

  /** Tick each code's countdown down every second; when a code rolls over (all 30s periods roll
   *  together) refetch the batch so every code stays current. */
  private startTotpListTick(): void {
    this.stopTotpList();
    this.totpListTimer = window.setInterval(() => {
      let rolled = false;
      this.totpEntries = this.totpEntries.map((entry) => {
        const remaining = entry.remaining - 1;
        if (remaining <= 0) rolled = true;
        return { ...entry, remaining: Math.max(0, remaining) };
      });
      if (rolled) void this.loadTotpCodes();
    }, 1000);
  }

  private stopTotpList(): void {
    if (this.totpListTimer !== undefined) {
      clearInterval(this.totpListTimer);
      this.totpListTimer = undefined;
    }
  }

  /** Ids of the current tab's matching logins (from the suggestions), for the 2FA current-site group. */
  private currentSiteIds(): string[] {
    return this.suggestionsState.status === 'ready'
      ? this.suggestionsState.suggestions.filter((suggestion) => suggestion.kind === 'login').map((suggestion) => suggestion.id)
      : [];
  }

  private showToast(message: string): void {
    this.toastMessage = message;
  }

  private isUnlockedWorkspace(): boolean {
    return ![
      'loading', 'login', 'passwordHint', 'register', 'registrationFinish', 'registrationCheckEmail',
      'newDeviceVerification', 'twoFactor', 'sso',
      'accountPasskey', 'deviceLogin', 'unlock',
    ].includes(this.route.name);
  }

  private applyOrganizationFilter(value: unknown): void {
    if (value === null) {
      this.selectedOrganizationId = null;
      return;
    }
    const personal = value === PERSONAL_VAULT_FILTER_ID;
    if (!personal) {
      if (typeof value !== 'string') return;
      const organizations = this.orgPermissions.filter((organization) => organization.id === value);
      if (organizations.length !== 1) return;
    }

    if (this.selectedCollectionId !== null) {
      const collections = this.collections.filter((collection) => (
        collection.id === this.selectedCollectionId
      ));
      if (personal || collections.length !== 1 || collections[0]!.organizationId !== value) {
        this.selectedCollectionId = null;
      }
    }
    this.selectedOrganizationId = value;
  }

  private applyFilterPatch(patch: FilterChangeDetail): void {
    if ('folderId' in patch) {
      const folderId = patch.folderId;
      if (folderId === null
        || folderId === NO_FOLDER
        || (typeof folderId === 'string'
          && this.folders.filter((folder) => folder.id === folderId).length === 1)) {
        this.selectedFolderId = folderId;
      }
    }
    if ('collectionId' in patch) {
      const collectionId = patch.collectionId;
      if (collectionId === null) {
        this.selectedCollectionId = null;
        if ('organizationId' in patch) this.applyOrganizationFilter(patch.organizationId);
      } else if (typeof collectionId === 'string') {
        const matches = this.collections.filter((collection) => collection.id === collectionId);
        const collection = matches.length === 1 ? matches[0] : undefined;
        const requestedOrganizationId = 'organizationId' in patch
          ? patch.organizationId
          : collection?.organizationId;
        if (collection && requestedOrganizationId === collection.organizationId) {
          this.selectedCollectionId = collection.id;
          this.selectedOrganizationId = collection.organizationId;
        }
      }
    } else if ('organizationId' in patch) {
      this.applyOrganizationFilter(patch.organizationId);
    }
    if (patch.query !== undefined) this.query = patch.query;
    if (patch.mode !== undefined) this.vaultMode = patch.mode;
    this.handleItemToggle('');
  }

  private visibleVaultItems(): CipherSummary[] {
    return this.items.filter((item) => {
      if (this.vaultMode === 'trash') return Boolean(item.deletedDate);
      if (this.vaultMode === 'archive') return Boolean(item.archivedDate) && !item.deletedDate;
      if (isCipherInactive(item)) return false;
      if (this.selectedFolderId !== null) {
        const inFolder = this.selectedFolderId === NO_FOLDER
          ? item.folderId === undefined
          : item.folderId === this.selectedFolderId;
        if (!inFolder) return false;
      }
      if (this.selectedOrganizationId !== null) {
        const inOrganization = this.selectedOrganizationId === PERSONAL_VAULT_FILTER_ID
          ? !item.organizationId
          : item.organizationId === this.selectedOrganizationId;
        if (!inOrganization) return false;
      }
      if (this.selectedCollectionId !== null && !item.collectionIds?.includes(this.selectedCollectionId)) return false;
      return true;
    });
  }

  private isUnsupportedItem(cipherId: string): boolean {
    const item = this.items.find((candidate) => candidate.id === cipherId);
    return !item || item.unsupported === true || !isKnownCipherType(item.type);
  }

  private itemAllows(cipherId: string, action: CipherAccessAction): boolean {
    const item = this.items.find((candidate) => candidate.id === cipherId);
    return Boolean(item && summaryAllowsCipherAccess(item, action));
  }

  private canOpenItemEditor(item: CipherSummary): boolean {
    if (item.deletedDate || !summaryAllowsCipherAccess(item, 'edit')) return false;
    if (item.hasTotp && !summaryAllowsCipherAccess(item, 'viewTotp')) return false;
    return (item.type !== 1 && item.type !== 5)
      || summaryAllowsCipherAccess(item, 'viewPassword');
  }

  private validCreateOrganization(organizationId: string | undefined): OrgPermission | undefined {
    if (!organizationId || organizationId.length > 4_096) return undefined;
    const matches = this.orgPermissions.filter((organization) => (
      organization.id === organizationId
      && organization.isMember === true
      && organization.canCreateItems === true
    ));
    return matches.length === 1 ? matches[0] : undefined;
  }

  private validCreateFolder(folderId: string | undefined): string | undefined {
    if (!folderId || folderId === NO_FOLDER || folderId.length > 4_096) return undefined;
    return this.folders.filter((folder) => folder.id === folderId).length === 1 ? folderId : undefined;
  }

  private validCreateCollections(
    organizationId: string | undefined,
    collectionIds: readonly string[],
  ): string[] {
    if (!this.validCreateOrganization(organizationId)) return [];
    const requested = new Set(collectionIds.filter((id) => id.length > 0 && id.length <= 4_096));
    const seen = new Set<string>();
    return this.collections.filter((collection) => {
      if (seen.has(collection.id)
        || collection.organizationId !== organizationId
        || collection.canAssignItems !== true
        || !requested.has(collection.id)) return false;
      seen.add(collection.id);
      return true;
    }).map((collection) => collection.id);
  }

  private currentFilterCreateDefaults(): EditorCreateDefaults {
    const folderId = this.validCreateFolder(this.selectedFolderId ?? undefined);
    const requestedOrganizationId = this.selectedOrganizationId === PERSONAL_VAULT_FILTER_ID
      ? undefined
      : this.selectedOrganizationId ?? undefined;
    const organizationId = this.validCreateOrganization(requestedOrganizationId)?.id;
    const collectionIds = this.selectedCollectionId === null
      ? []
      : this.validCreateCollections(organizationId, [this.selectedCollectionId]);
    return {
      ...(folderId ? { folderId } : {}),
      ...(organizationId ? { organizationId } : {}),
      ...(collectionIds.length ? { collectionIds } : {}),
    };
  }

  private openEditor(
    route: Extract<PopupRoute, { name: 'editor' }>,
    createDefaults?: EditorCreateDefaults,
  ): void {
    this.editorNavigationSetup = {
      ...(createDefaults ? { createDefaults } : {}),
      returnRoute: this.route.name === 'detail' || this.route.name === 'vault'
        ? this.route
        : { name: 'vault', scope: this.vaultScope },
      returnVaultMode: this.vaultMode,
      preserveReprompt: route.mode === 'clone',
    };
    this.navigate(route);
  }

  private async startNewItem(): Promise<void> {
    if (this.pending || this.sendEncoding || this.isDataOwnershipConstrained()) return;
    if (!this.promptForDraftDiscard({ name: 'editor', mode: 'create' })) return;
    const sequence = ++this.newItemStartSequence;
    const workspace = this.workspaceGeneration;
    const ownerRoute = this.route;
    const defaults = this.currentFilterCreateDefaults();
    let loginUri: string | undefined;
    try {
      const rawUrl = await this.browser.getActiveTabUrl?.();
      if (rawUrl && rawUrl.length <= 2_048) loginUri = safeWebUrl(rawUrl);
    } catch {
      // Browser-owned tab context is optional; creation remains available without a URI prefill.
    }
    if (sequence !== this.newItemStartSequence
      || !this.isCurrentWorkspace(workspace)
      || this.route !== ownerRoute) return;
    this.openEditor(
      { name: 'editor', mode: 'create' },
      { ...defaults, ...(loginUri ? { loginUri } : {}) },
    );
  }

  private continueNewItem(detail: EditorTypeDetail): void {
    if (this.route.name !== 'editor' || this.route.mode !== 'create' || this.route.cipherType !== undefined) return;
    const type = detail?.type;
    if (type !== 1 && type !== 2 && type !== 3 && type !== 4 && type !== 5) return;
    if (type === 5 && this.sshWriteAvailability !== 'available') return;
    this.navigate({ name: 'editor', mode: 'create', cipherType: type });
  }

  private beginClone(detail: CloneItemDetail): void {
    if (this.pending
      || typeof detail?.cipherId !== 'string'
      || typeof detail?.passkeyWarningAcknowledged !== 'boolean') return;
    const source = this.items.find((item) => item.id === detail.cipherId);
    if (!source
      || source.deletedDate
      || source.unsupported
      || source.undecryptable
      || source.type === 5
      || !this.itemAllows(source.id, 'clone')
      || !this.canOpenItemEditor(source)
      || detail.passkeyWarningAcknowledged !== Boolean(source.hasPasskey)) return;
    const folderId = this.validCreateFolder(source.folderId);
    const organizationId = this.validCreateOrganization(source.organizationId)?.id;
    const collectionIds = this.validCreateCollections(organizationId, source.collectionIds ?? []);
    this.openEditor(
      { name: 'editor', mode: 'clone', cipherId: source.id },
      {
        ...(folderId ? { folderId } : {}),
        ...(organizationId ? { organizationId } : {}),
        ...(collectionIds.length ? { collectionIds } : {}),
      },
    );
  }

  private returnFromEditor(): void {
    const snapshot = this.editorWorkspaceSnapshot;
    if (!snapshot) {
      this.userNavigate({ name: 'vault', scope: 'all' });
      return;
    }
    if (this.userNavigate(snapshot.returnRoute)) this.vaultMode = snapshot.returnVaultMode;
  }

  private exitLifecycleView(detail: VaultModeChangeDetail = { mode: 'active' }): void {
    this.vaultMode = detail.mode;
    this.query = '';
    this.navigate({ name: 'vault', scope: 'all' });
  }

  private folderMutationRequest(detail: FolderMutateDetail): Promise<ResponseMessage> | undefined {
    if (detail.op === 'create' && detail.name !== undefined) return this.request({ type: 'vault.createFolder', name: detail.name });
    if (detail.op === 'rename' && detail.id !== undefined && detail.name !== undefined) return this.request({ type: 'vault.renameFolder', id: detail.id, name: detail.name });
    if (detail.op === 'delete' && detail.id !== undefined) return this.request({ type: 'vault.deleteFolder', id: detail.id });
    return undefined;
  }

  private async handleFolderMutate(detail: FolderMutateDetail): Promise<void> {
    if (this.pending) return;
    const pending = this.folderMutationRequest(detail);
    if (!pending) return;
    const generation = this.workspaceGeneration;
    this.pending = true;
    try {
      const response = await pending;
      if (!this.isCurrentWorkspace(generation)) return;
      if (!response.ok) {
        this.showToast(response.error.message);
        return;
      }
      if (detail.op === 'delete' && this.selectedFolderId === detail.id) this.selectedFolderId = null;
      this.applyListingResponse(response);
    } finally {
      this.pending = false;
    }
  }

  private collectionMutationRequest(detail: CollectionMutateDetail): Promise<ResponseMessage> | undefined {
    if (detail.op === 'create' && detail.name !== undefined) return this.request({ type: 'vault.createCollection', organizationId: detail.organizationId, name: detail.name });
    if (detail.op === 'rename' && detail.id !== undefined && detail.name !== undefined) return this.request({ type: 'vault.renameCollection', organizationId: detail.organizationId, id: detail.id, name: detail.name });
    if (detail.op === 'delete' && detail.id !== undefined) return this.request({ type: 'vault.deleteCollection', organizationId: detail.organizationId, id: detail.id });
    return undefined;
  }

  private async handleCollectionMutate(detail: CollectionMutateDetail): Promise<void> {
    if (this.pending) return;
    const pending = this.collectionMutationRequest(detail);
    if (!pending) return;
    const generation = this.workspaceGeneration;
    this.pending = true;
    try {
      const response = await pending;
      if (!this.isCurrentWorkspace(generation)) return;
      if (!response.ok) {
        this.showToast(response.error.message);
        return;
      }
      if (detail.op === 'delete' && this.selectedCollectionId === detail.id) this.selectedCollectionId = null;
      this.applyListingResponse(response);
    } finally {
      this.pending = false;
    }
  }

  /** Read the session state and route to the matching surface (used after switching/removing an
   *  account, where the resulting state can be logged-out, locked, or unlocked). */
  private async reRouteFromState(): Promise<void> {
    const response = await this.request({ type: 'auth.getState' });
    if (!response.ok) {
      this.navigate(loginRoute(response.error.message));
      return;
    }
    const { state } = response.data as { state: SessionState };
    if (state === 'loggedOut') this.navigate(loginRoute());
    else if (state === 'locked') this.navigate(unlockRoute());
    else if (state === 'restricted') {
      const requirement = restrictionFromStateData(response.data);
      this.navigate(requirement
        ? restrictedRoute(requirement)
        : loginRoute(t('common.error')));
    }
    else this.enterVault();
  }

  private resetVaultState(): void {
    this.clearSyncStatusPoll();
    this.clearDeviceLoginRequesterState();
    this.clearDeviceLoginApprovalState();
    this.workspaceGeneration += 1;
    this.latestListingSeq += 1;
    this.latestSyncStatusSeq += 1;
    this.resetExternalSyncRefreshState();
    this.sshAvailabilitySeq += 1;
    this.items = [];
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.personalCreationAllowed = false;
    this.organizationDataOwnershipStatus = { status: 'unavailable' };
    this.dataOwnershipError = undefined;
    this.dataOwnershipCheckPending = false;
    this.accounts = [];
    this.pinAllowed = false;
    this.pinConfigured = false;
    this.pinRequireMasterPasswordOnRestart = true;
    this.skippedOrgCount = 0;
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
    this.selectedOrganizationId = null;
    this.query = '';
    this.vaultMode = 'active';
    this.suggestionsState = { status: 'loading' };
    this.totpEntries = [];
    this.fillResult = {};
    this.vaultScope = 'suggestions';
    this.selectedCipherId = null;
    this.syncStatus = null;
    this.sshWriteAvailability = 'idle';
    this.activeTabId = undefined;
    this.clearToolState();
  }

  private isCurrentWorkspace(generation: number): boolean {
    return generation === this.workspaceGeneration && this.isUnlockedWorkspace();
  }

  /** Drop every tool-view value that must not survive a lock/logout/account switch: the in-memory
   *  generator history and the loaded health/HIBP/Sends state. */
  private clearToolState(): void {
    this.toolStatusEpoch += 1;
    this.latestGeneratorPolicySeq += 1;
    this.latestGeneratorHistorySeq += 1;
    this.generatorHistory = [];
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    this.healthReport = { status: 'idle' };
    this.pwnedState = { status: 'idle' };
    this.sendsState = { status: 'idle' };
    this.sendEncoding = false;
    this.toolStatus = undefined;
  }

  private async handleAccountAction(detail: AccountActionDetail): Promise<void> {
    if (this.isDataOwnershipConstrained()
        && detail.action !== 'switch-account'
        && detail.action !== 'lock'
        && detail.action !== 'logout') return;
    if (this.pending || this.syncing || this.sendEncoding) return;
    switch (detail.action) {
      case 'switch-account':
        if (detail.email !== undefined) {
          if (this.pending) return;
          if (!this.promptForDraftDiscard()) return;
          this.latestGeneratorPolicySeq += 1;
          this.latestGeneratorHistorySeq += 1;
          this.generatorHistory = [];
          this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
          this.pending = true;
          try {
            const response = await this.request({ type: 'auth.switchAccount', email: detail.email });
            if (response.ok) {
              // Drop the prior account's non-secret vault listing + Fill outcome before re-routing;
              // an unlocked destination reloads its own data via enterVault().
              this.resetVaultState();
              await this.reRouteFromState();
            } else {
              this.showToast(response.error.message);
            }
          } finally {
            this.pending = false;
          }
        }
        return;
      case 'remove-account':
        if (detail.email !== undefined) {
          if (this.pending) return;
          if (!this.promptForDraftDiscard()) return;
          this.pending = true;
          try {
            const response = await this.request({ type: 'auth.removeAccount', email: detail.email });
            if (response.ok) {
              // Drop the removed account's non-secret vault listing + Fill outcome before re-routing.
              this.resetVaultState();
              await this.reRouteFromState();
            } else {
              this.showToast(response.error.message);
            }
          } finally {
            this.pending = false;
          }
        }
        return;
      case 'add-account':
        this.userNavigate(loginRoute());
        return;
      case 'pin':
        if (this.pinAllowed) this.userNavigate({ name: 'pin' });
        return;
      case 'account-security':
        this.userNavigate({ name: 'accountSecurity' });
        return;
      case 'device-login-approvals':
        if (!this.promptForDraftDiscard()) return;
        this.pending = true;
        this.navigate({ name: 'deviceLoginApprovals', view: 'list' });
        try {
          await this.loadDeviceLoginApprovals(this.workspaceGeneration);
        } finally {
          if (this.route.name === 'deviceLoginApprovals') this.pending = false;
        }
        return;
      case 'options':
        if (!this.promptForDraftDiscard()) return;
        await this.browser.openOptions();
        return;
      case 'lock': {
        if (this.pending) return;
        if (!this.promptForDraftDiscard()) return;
        this.pending = true;
        try {
          const response = await this.request({ type: 'auth.lock' });
          // A lock must drop the unlocked vault's non-secret listing state (items/folders/
          // collections/org permissions/suggestions), not only the tool state.
          if (response.ok) { this.resetVaultState(); this.navigate(unlockRoute()); }
          else this.showToast(response.error.message); // surface the failure instead of an unread route error
        } finally {
          this.pending = false;
        }
        return;
      }
      case 'logout': {
        if (!this.promptForDraftDiscard()) return;
        await this.handleLogout();
        return;
      }
      case 'forget-device': {
        const response = await this.request({ type: 'auth.forgetDevice' });
        if (response.ok) this.vaultDeviceRemembered = false;
        else this.showToast(response.error.message);
        return;
      }
    }
  }

  private async handleToolAction(detail: ToolActionDetail): Promise<void> {
    if (this.isDataOwnershipConstrained() && detail.action !== 'sync') return;
    if (this.pending || this.sendEncoding) return;
    switch (detail.action) {
      case 'generator':
        this.userNavigate({ name: 'generator' });
        return;
      case 'health':
        this.userNavigate({ name: 'health' });
        return;
      case 'sends':
        if (this.route.name === 'sends') return;
        this.userNavigate({ name: 'sends' });
        return;
      case 'trash':
        if (!this.promptForDraftDiscard({ name: 'vault', scope: 'all' })) return;
        this.query = '';
        this.vaultMode = 'trash';
        this.navigate({ name: 'vault', scope: 'all' });
        return;
      case 'archive':
        if (!this.promptForDraftDiscard({ name: 'vault', scope: 'all' })) return;
        this.query = '';
        this.vaultMode = 'archive';
        this.navigate({ name: 'vault', scope: 'all' });
        return;
      case 'sync': {
        await this.handleSync();
        return;
      }
    }
  }

  // --- Vault tools orchestration ---------------------------------------------------------------

  /** The active account's email, used to prefill the generator's plus-addressed base email. */
  private activeAccountEmail(): string | undefined {
    return (this.accounts.find((account) => account.active) ?? this.accounts[0])?.email;
  }

  private generatorSurfaceActive(): boolean {
    return this.route.name === 'generator'
      || this.route.name === 'editor'
      || this.route.name === 'sends';
  }

  private async loadGeneratorPolicy(): Promise<void> {
    const workspace = this.workspaceGeneration;
    const sequence = ++this.latestGeneratorPolicySeq;
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    let response: ResponseMessage;
    try {
      response = await this.request({ type: 'settings.get' });
    } catch {
      response = { ok: false, error: { code: 'error', message: 'Generator policy unavailable' } };
    }
    if (
      !this.isCurrentWorkspace(workspace)
      || !this.generatorSurfaceActive()
      || sequence !== this.latestGeneratorPolicySeq
    ) return;
    const generator = response.ok && response.data && typeof response.data === 'object'
      ? parseGeneratorPolicySnapshot((response.data as { generator?: unknown }).generator)
      : null;
    this.generatorPolicy = generator ?? UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
  }

  private async loadGeneratorHistory(reset = true): Promise<void> {
    const workspace = this.workspaceGeneration;
    const sequence = ++this.latestGeneratorHistorySeq;
    if (reset) this.generatorHistory = [];
    let response: ResponseMessage;
    try {
      response = await this.request({ type: 'generator.history.list' });
    } catch {
      return;
    }
    if (!this.isCurrentWorkspace(workspace)
      || !this.generatorSurfaceActive()
      || sequence !== this.latestGeneratorHistorySeq) return;
    const data: unknown = response.ok ? response.data : undefined;
    if (!isExactRecord(data, ['entries'])) return;
    const entries = parseGeneratorHistoryEntries(data.entries);
    if (entries) this.generatorHistory = entries;
  }

  /** Shared clipboard copy: write the value, schedule the background clear, and report success/failure
   *  through the caller's status setter. Optionally raises the copy-confirmation toast. */
  private async copy(
    value: string,
    label: string,
    setStatus: (status: DetailStatus) => void,
    opts?: { toast?: boolean; clientEventAckId?: string },
  ): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      setStatus({ message: t('common.copyFailedLabel', { name: label }), tone: 'danger' });
      return false;
    }
    if (opts?.clientEventAckId !== undefined) {
      this.acknowledgeClientEvent(opts.clientEventAckId);
    }
    let clearScheduled = false;
    try {
      clearScheduled = (await this.request({ type: 'clipboard.scheduleClear', value })).ok;
    } catch {
      // The clipboard write already succeeded; report only the failed cleanup guarantee.
    }
    setStatus(clearScheduled
      ? { message: t('common.copiedLabel', { name: label }), tone: 'success' }
      : { message: t('common.copiedNoClearLabel', { name: label }), tone: 'warning' });
    if (opts?.toast) this.showToast(t(clearScheduled ? 'common.copiedToast' : 'common.copiedNoClear'));
    return true;
  }

  /** Copy a tool-generated value or Send link and schedule the background clipboard clear. */
  private copyToolValue(value: string, label: string): Promise<boolean> {
    const epoch = this.toolStatusEpoch;
    return this.copy(value, label, (status) => {
      if (epoch === this.toolStatusEpoch) this.toolStatus = status;
    });
  }

  private async handleGeneratorHistoryAdd(detail: GeneratorHistoryAddDetail): Promise<void> {
    const workspace = this.workspaceGeneration;
    if (!this.generatorSurfaceActive()
      || detail.policyRevision !== this.generatorPolicy.revision
      || !detail.value) return;
    let response: ResponseMessage;
    try {
      response = await this.request({
        type: 'generator.history.track',
        entry: detail,
      });
    } catch {
      return;
    }
    if (!this.isCurrentWorkspace(workspace)
      || !this.generatorSurfaceActive()
      || detail.policyRevision !== this.generatorPolicy.revision) return;
    const data: unknown = response.ok ? response.data : undefined;
    if (!isExactBooleanRecord(data, 'added')) return;
    await this.loadGeneratorHistory(false);
  }

  private async clearGeneratorHistory(): Promise<void> {
    const workspace = this.workspaceGeneration;
    const sequence = ++this.latestGeneratorHistorySeq;
    let response: ResponseMessage;
    try {
      response = await this.request({ type: 'generator.history.clear' });
    } catch {
      return;
    }
    if (!this.isCurrentWorkspace(workspace)
      || !this.generatorSurfaceActive()
      || sequence !== this.latestGeneratorHistorySeq) return;
    const data: unknown = response.ok ? response.data : undefined;
    if (isExactBooleanRecord(data, 'cleared')) this.generatorHistory = [];
  }

  private async loadHealth(): Promise<void> {
    const generation = this.workspaceGeneration;
    this.healthReport = { status: 'loading' };
    this.pwnedState = { status: 'idle' };
    const response = await this.request({ type: 'vault.getPasswordHealth' });
    if (!this.isCurrentWorkspace(generation) || this.route.name !== 'health') return;
    if (!response.ok) {
      this.healthReport = { status: 'error', message: response.error.message };
      return;
    }
    const entries = (response.data as { entries?: HealthEntry[] } | null)?.entries ?? [];
    this.healthReport = entries.length > 0 ? { status: 'ready', data: entries } : { status: 'empty' };
  }

  private async handleHealthCheck(): Promise<void> {
    if (this.pwnedState.status === 'loading') return;
    this.pwnedState = { status: 'loading' };
    const generation = this.workspaceGeneration;
    const response = await this.request({ type: 'vault.checkPwned' });
    if (!this.isCurrentWorkspace(generation) || this.route.name !== 'health') return;
    if (!response.ok) {
      this.pwnedState = { status: 'error', message: response.error.message };
      return;
    }
    const entries = (response.data as { entries?: Array<{ id: string; pwnedCount: number }> } | null)?.entries ?? [];
    const byId = new Map<string, number>();
    for (const entry of entries) byId.set(entry.id, entry.pwnedCount);
    this.pwnedState = { status: 'ready', data: byId };
  }

  private async loadSends(): Promise<void> {
    const generation = this.workspaceGeneration;
    this.sendsState = { status: 'loading' };
    const response = await this.request({ type: 'sends.list' });
    if (!this.isCurrentWorkspace(generation) || this.route.name !== 'sends') return;
    if (!response.ok) {
      this.sendsState = { status: 'error', message: response.error.message };
      return;
    }
    const sends = (response.data as { sends?: SendSummary[] } | null)?.sends ?? [];
    this.sendsState = sends.length > 0 ? { status: 'ready', data: sends } : { status: 'empty' };
  }

  private async handleSendCreate(detail: SendCreateDetail): Promise<void> {
    if (this.pending) return;
    const generation = this.workspaceGeneration;
    this.toolStatusEpoch += 1;
    this.pending = true;
    this.toolStatus = undefined;
    try {
      const response = detail.kind === 'text'
        ? await this.request({ type: 'sends.createText', input: detail.input })
        : await this.request({ type: 'sends.createFile', input: detail.input, dataB64: detail.dataB64, fileName: detail.fileName });
      if (!this.isCurrentWorkspace(generation) || this.route.name !== 'sends') return;
      if (!response.ok) {
        this.toolStatus = response.error.code === 'committed_unsynced'
          ? { message: t('send.savedResultWithheld'), tone: 'warning' }
          : { message: response.error.message, tone: 'danger' };
        return;
      }
      const send = (response.data as { send?: SendSummary } | null)?.send;
      if (send) {
        const copied = await this.copyToolValue(send.url, t('options.send.copyLink'));
        if (!this.isCurrentWorkspace(generation) || this.route.name !== 'sends') return;
        this.toolStatus = copied
          ? { message: t('send.createdCopied'), tone: 'success' }
          : { message: t('send.createdCopyFailed'), tone: 'warning' };
      } else {
        this.toolStatus = { message: t('send.created'), tone: 'success' };
      }
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleSendUpdate(detail: SendUpdateDetail): Promise<void> {
    if (this.pending) return;
    const generation = this.workspaceGeneration;
    this.toolStatusEpoch += 1;
    this.pending = true;
    this.toolStatus = undefined;
    try {
      const response = await this.request({ type: 'sends.update', id: detail.id, input: detail.input });
      if (!this.isCurrentWorkspace(generation) || this.route.name !== 'sends') return;
      if (!response.ok) {
        this.toolStatus = response.error.code === 'committed_unsynced'
          ? { message: t('send.savedResultWithheld'), tone: 'warning' }
          : { message: response.error.message, tone: 'danger' };
        return;
      }
      this.toolStatus = { message: t('send.updated'), tone: 'success' };
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleSendDelete(detail: SendDeleteDetail): Promise<void> {
    if (this.pending) return;
    const generation = this.workspaceGeneration;
    this.toolStatusEpoch += 1;
    this.pending = true;
    this.toolStatus = undefined;
    try {
      const response = await this.request({ type: 'sends.delete', id: detail.id });
      if (!this.isCurrentWorkspace(generation) || this.route.name !== 'sends') return;
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.toolStatus = { message: t('send.deleted'), tone: 'success' };
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async loadPinStatus(): Promise<void> {
    const response = await this.request({ type: 'auth.pinStatus' });
    if (this.route.name !== 'pin') return;
    const status = response.ok ? response.data as PinStatusData : undefined;
    this.pinAllowed = status !== undefined && status.allowed !== false;
    this.pinConfigured = this.pinAllowed && status?.enabled === true;
    this.pinRequireMasterPasswordOnRestart = status?.requireMasterPasswordOnRestart !== false;
  }

  private async handlePinSet(detail: PinSetDetail): Promise<void> {
    if (this.pending || !this.pinAllowed) return;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.setPin',
        pin: detail.pin,
        requireMasterPasswordOnRestart: detail.requireMasterPasswordOnRestart,
      });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.pinConfigured = true;
      this.pinRequireMasterPasswordOnRestart = detail.requireMasterPasswordOnRestart;
      this.toolStatus = { message: t('security.pinEnabled'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handlePinRemove(): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.disablePin' });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.pinConfigured = false;
      this.pinRequireMasterPasswordOnRestart = true;
      this.toolStatus = { message: t('security.pinRemoved'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleChangePassword(detail: ChangePasswordDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({
        type: 'auth.changePassword',
        currentPassword: detail.currentPassword,
        newPassword: detail.newPassword,
        masterPasswordHint: detail.masterPasswordHint,
      });
      if (!response.ok && response.error.code !== 'outcome_unknown') {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.resetVaultState();
      await this.reRouteFromState();
      if (!response.ok) this.showToast(response.error.message);
    } finally {
      this.pending = false;
    }
  }

  private async handleChangeKdf(detail: ChangeKdfDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.changeKdf', currentPassword: detail.currentPassword, kdf: detail.kdf });
      this.toolStatus = response.ok
        ? { message: t('security.kdfUpdated'), tone: 'success' }
        : { message: response.error.message, tone: 'danger' };
      const pin = await this.request({ type: 'auth.pinStatus' });
      if (pin.ok) {
        const status = pin.data as PinStatusData;
        this.pinAllowed = status.allowed;
        this.pinConfigured = status.allowed && status.enabled;
        this.pinRequireMasterPasswordOnRestart = status.requireMasterPasswordOnRestart;
      }
    } finally {
      this.pending = false;
    }
  }

  /** Two-step key rotation. On success the worker has already logged out this and every other
   *  session for the account, so the popup drops all vault/tool state and returns to login. */
  private async handleRotateKey(detail: RotateKeyDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.rotateAccountKey', masterPassword: detail.masterPassword });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.resetVaultState();
      this.navigate(loginRoute(t('security.keyRotated')));
    } finally {
      this.pending = false;
    }
  }

  // --- Item detail (dormant) orchestration --------------------------------------------------

  /** The verified reprompt master password for `id`, or `undefined`. Threaded into every on-demand
   *  secret request so the worker's reprompt gate is satisfied for the currently-open protected item. */
  private repromptMp(id: string): string | undefined {
    return this.repromptCredential?.cipherId === id ? this.repromptCredential.masterPassword : undefined;
  }

  private isCurrentDetailContext(id: string, generation: number, epoch: number): boolean {
    if (!this.isCurrentWorkspace(generation) || epoch !== this.detailEpoch) return false;
    if (this.route.name === 'detail') return this.route.cipherId === id;
    if (this.route.name === 'editor') return this.route.cipherId === id;
    return this.route.name === 'vault' && this.selectedCipherId === id;
  }

  private setDetailFailure(message: string): void {
    this.detailStatus = { message, tone: 'danger' };
    this.showToast(message);
  }

  private acknowledgeClientEvent(ackId: string): void {
    if (this.acknowledgedClientEventIds.has(ackId)) return;
    while (this.acknowledgedClientEventIds.size >= MAX_ACKNOWLEDGED_CLIENT_EVENT_IDS) {
      const oldest = this.acknowledgedClientEventIds.values().next().value as string | undefined;
      if (oldest === undefined) break;
      this.acknowledgedClientEventIds.delete(oldest);
    }
    this.acknowledgedClientEventIds.add(ackId);
    void this.request({ type: 'clientEvent.ack', ackId }).catch(() => {
      // The visible/copied action already succeeded. ACK delivery is best effort and must not alter UI.
    });
  }

  /** Fetch the secret-stripped detail for the open item. Guards against a stale response arriving
   *  after the user has navigated to a different item. */
  private async loadDetail(
    id: string,
    epoch = this.detailEpoch,
    clientEventPurpose?: Extract<PopupClientEventPurpose, 'view'>,
  ): Promise<void> {
    const summary = this.items.find((item) => item.id === id);
    const mp = this.repromptMp(id);
    // Keep this guard at the request boundary as well as in navigation/rendering. A protected item
    // must never issue a detail request until the credential belongs to this exact cipher.
    if (!summary || summary.unsupported || summary.undecryptable
      || (summary.reprompt && mp === undefined)) return;
    const generation = this.workspaceGeneration;
    const detailRequest = this.request({
      type: 'vault.getCipherDetail',
      id,
      ...(mp === undefined ? {} : { masterPassword: mp }),
      ...(clientEventPurpose === undefined ? {} : { clientEventPurpose }),
    });
    const sshRequest = summary.type === 5
      ? this.request(
          mp === undefined
            ? { type: 'vault.getSshKeyDetails', id }
            : { type: 'vault.getSshKeyDetails', id, masterPassword: mp },
        )
      : undefined;
    const [response, sshResponse] = await Promise.all([detailRequest, sshRequest]);
    if (!this.isCurrentDetailContext(id, generation, epoch) || this.route.name !== 'detail') return;
    if (!response.ok) {
      this.detailCipher = null;
      this.setDetailFailure(response.error.message);
      return;
    }
    const clientEventAckId = clientEventPurpose === undefined
      ? undefined
      : responseClientEventAckId(response);
    this.detailCipher = (response.data as { cipher: DecryptedCipher | null } | null)?.cipher ?? null;
    if (!this.detailCipher) {
      this.setDetailFailure(t('vault.itemUnavailable'));
      return;
    }
    if (summary.type === 5) {
      if (!sshResponse?.ok) {
        this.sshKeyDetails = null;
        this.setDetailFailure(sshResponse?.error.message ?? t('detail.sshUnavailable'));
        return;
      }
      this.sshKeyDetails = (sshResponse.data as { sshKey: SshKeyPublicDetails | null } | null)?.sshKey ?? null;
      if (!this.sshKeyDetails) {
        this.setDetailFailure(t('detail.sshUnavailable'));
        return;
      }
    }
    if (clientEventAckId !== undefined) {
      await this.updateComplete;
      const detail = this.renderRoot.querySelector<HTMLElement & { updateComplete: Promise<unknown> }>('vw-item-detail');
      await detail?.updateComplete;
      if (this.isCurrentDetailContext(id, generation, epoch)
        && this.route.name === 'detail'
        && detail !== null
        && this.renderRoot.querySelector('vw-item-detail') === detail) {
        this.acknowledgeClientEvent(clientEventAckId);
      }
    }
  }

  private dataOwnershipModel(): DataOwnershipMigrationModel | undefined {
    const status = this.organizationDataOwnershipStatus;
    if (status.status !== 'migration_available' && status.status !== 'blocked') return undefined;
    const organization = this.orgPermissions.find((entry) => entry.id === status.organizationId);
    const collection = status.status === 'migration_available'
      ? this.collections.find((entry) => entry.id === status.collectionId
          && entry.organizationId === status.organizationId)
      : undefined;
    return {
      organizationId: status.organizationId,
      ...(status.status === 'migration_available' ? { collectionId: status.collectionId } : {}),
      ...(status.status === 'migration_available'
        ? { migrateAuthorizationId: status.migrateAuthorization.authorizationId }
        : {}),
      leaveAuthorizationId: status.leaveAuthorization.authorizationId,
      personalItemCount: status.personalItemCount,
      organizationName: organization?.name ?? status.organizationId,
      ...(status.status === 'migration_available'
        ? { collectionName: collection?.name ?? status.collectionId }
        : {}),
      migrationAvailable: status.status === 'migration_available',
    };
  }

  private async handleDataOwnershipMigration(
    detail: DataOwnershipMigrationSubmitDetail,
  ): Promise<void> {
    const status = this.organizationDataOwnershipStatus;
    if (this.pending || this.route.name !== 'dataOwnership'
        || status.status !== 'migration_available'
        || status.organizationId !== detail.organizationId
        || status.collectionId !== detail.collectionId
        || status.migrateAuthorization.authorizationId !== detail.authorizationId) return;
    const generation = this.workspaceGeneration;
    this.pending = true;
    this.dataOwnershipError = undefined;
    try {
      const response = await this.request({
        type: 'vault.migrateOrganizationDataOwnership',
        organizationId: detail.organizationId,
        collectionId: detail.collectionId,
        authorizationId: detail.authorizationId,
        masterPassword: detail.masterPassword,
      });
      if (!this.isCurrentWorkspace(generation) || this.route.name !== 'dataOwnership') return;
      if (!response.ok) {
        this.dataOwnershipError = response.error.message;
        if (response.error.code === 'outcome_unknown'
            || response.error.code === 'committed_unsynced') {
          this.organizationDataOwnershipStatus = {
            status: 'reconciliation_required',
            operation: 'migrate',
            reason: response.error.code,
          };
        } else {
          await this.loadListing(generation);
        }
        return;
      }
      this.applyListingResponse(response);
      this.organizationDataOwnershipStatus = { status: 'unavailable' };
      await this.loadListing(generation);
      if (this.organizationDataOwnershipStatus.status === 'compliant'
          || this.organizationDataOwnershipStatus.status === 'not_required') {
        this.showToast(t('dataOwnership.completed'));
      }
    } finally {
      this.pending = false;
    }
  }

  private async handleDataOwnershipLeave(detail: DataOwnershipLeaveDetail): Promise<void> {
    const status = this.organizationDataOwnershipStatus;
    if (this.pending || this.route.name !== 'dataOwnership'
        || (status.status !== 'migration_available' && status.status !== 'blocked')
        || status.organizationId !== detail.organizationId
        || status.leaveAuthorization.authorizationId !== detail.authorizationId) return;
    const generation = this.workspaceGeneration;
    this.pending = true;
    this.dataOwnershipError = undefined;
    try {
      const response = await this.request({
        type: 'vault.leaveOrganizationDataOwnership',
        organizationId: detail.organizationId,
        authorizationId: detail.authorizationId,
      });
      if (!this.isCurrentWorkspace(generation) || this.route.name !== 'dataOwnership') return;
      if (!response.ok) {
        this.dataOwnershipError = response.error.message;
        if (response.error.code === 'outcome_unknown'
            || response.error.code === 'committed_unsynced') {
          this.organizationDataOwnershipStatus = {
            status: 'reconciliation_required',
            operation: 'leave',
            reason: response.error.code,
          };
        } else {
          await this.loadListing(generation);
        }
        return;
      }
      this.applyListingResponse(response);
      this.organizationDataOwnershipStatus = { status: 'unavailable' };
      await this.loadListing(generation);
      if (this.organizationDataOwnershipStatus.status !== 'unavailable') {
        this.showToast(t('dataOwnership.left'));
      }
    } finally {
      this.pending = false;
    }
  }

  private async retryDataOwnershipStatus(): Promise<void> {
    if (this.pending || this.route.name !== 'dataOwnership') return;
    const generation = this.workspaceGeneration;
    this.pending = true;
    this.dataOwnershipError = undefined;
    try {
      const sync = await this.request({ type: 'vault.sync' });
      if (!this.isCurrentWorkspace(generation) || this.route.name !== 'dataOwnership') return;
      if (!sync.ok) {
        this.dataOwnershipError = sync.error.message;
        return;
      }
      this.applyListingResponse(sync);
      await Promise.all([
        this.loadListing(generation),
        this.loadSyncStatus(generation),
      ]);
    } finally {
      this.pending = false;
    }
  }

  /** Build (memoized) the async loaders the detail invokes on explicit reveal. Every loader is a
   *  root closure — the detail never issues a worker request itself — and each surfaces its own
   *  error onto the shared status banner. */
  private detailExtras(id: string): DetailExtras {
    const mp = this.repromptMp(id);
    const key = `${id}|${mp === undefined ? '' : '1'}`;
    if (this.detailExtrasCache?.key === key) return this.detailExtrasCache.extras;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const extras: DetailExtras = {
      getField: async (field) => {
        const clientEventPurpose = isClientEventRevealField(field) ? 'reveal' as const : undefined;
        const response = await this.request({
          type: 'vault.getField',
          id,
          field,
          ...(mp === undefined ? {} : { masterPassword: mp }),
          ...(clientEventPurpose ? { clientEventPurpose } : {}),
        });
        if (!this.isCurrentDetailContext(id, generation, epoch)) return { ok: false };
        if (!response.ok) {
          this.setDetailFailure(response.error.message);
          return { ok: false };
        }
        const clientEventAckId = isClientEventRevealField(field)
          ? responseClientEventAckId(response)
          : undefined;
        return {
          ok: true,
          value: (response.data as { value?: string }).value,
          ...(clientEventAckId === undefined
            ? {}
            : { acknowledgeVisible: () => this.acknowledgeClientEvent(clientEventAckId) }),
        };
      },
      getCustomField: async (index) => {
        const response = await this.request({
          type: 'vault.getCustomField',
          id,
          index,
          ...(mp === undefined ? {} : { masterPassword: mp }),
          clientEventPurpose: 'reveal',
        });
        if (!this.isCurrentDetailContext(id, generation, epoch)) return { ok: false };
        if (!response.ok) {
          this.setDetailFailure(response.error.message);
          return { ok: false };
        }
        const clientEventAckId = this.detailCipher?.fields?.[index]?.type === 1
          ? responseClientEventAckId(response)
          : undefined;
        return {
          ok: true,
          value: (response.data as { value?: string }).value,
          ...(clientEventAckId === undefined
            ? {}
            : { acknowledgeVisible: () => this.acknowledgeClientEvent(clientEventAckId) }),
        };
      },
      getTotp: async () => {
        const response = await this.request(
          mp === undefined ? { type: 'vault.getTotp', id } : { type: 'vault.getTotp', id, masterPassword: mp },
        );
        if (!this.isCurrentDetailContext(id, generation, epoch)) return { ok: false };
        if (!response.ok) {
          this.setDetailFailure(response.error.message);
          return { ok: false };
        }
        return { ok: true, totp: (response.data as { totp: { code: string; period: number; remaining: number } | null }).totp };
      },
      getPasswordHistory: async () => {
        const response = await this.request(
          mp === undefined ? { type: 'vault.getPasswordHistory', id } : { type: 'vault.getPasswordHistory', id, masterPassword: mp },
        );
        if (!this.isCurrentDetailContext(id, generation, epoch)) return { ok: false };
        if (!response.ok) {
          this.setDetailFailure(response.error.message);
          return { ok: false };
        }
        return { ok: true, history: (response.data as { history: Array<{ password: string; lastUsedDate?: string }> }).history };
      },
    };
    this.detailExtrasCache = { key, extras };
    return extras;
  }

  private sshDetailExtras(id: string): SshDetailExtras {
    const mp = this.repromptMp(id);
    const key = `${id}|${mp === undefined ? '' : '1'}`;
    if (this.sshDetailExtrasCache?.key === key) return this.sshDetailExtrasCache.extras;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const extras: SshDetailExtras = {
      getPrivateKey: async () => {
        const response = await this.request(
          mp === undefined
            ? { type: 'vault.revealSshPrivateKey', id }
            : { type: 'vault.revealSshPrivateKey', id, masterPassword: mp },
        );
        if (!this.isCurrentDetailContext(id, generation, epoch) || this.route.name !== 'detail') return { ok: false };
        if (!response.ok) {
          this.setDetailFailure(response.error.message);
          return { ok: false };
        }
        return {
          ok: true,
          value: (response.data as { privateKey: string | null } | null)?.privateKey ?? undefined,
        };
      },
    };
    this.sshDetailExtrasCache = { key, extras };
    return extras;
  }

  /** Verify the reprompt master password and, on success, hold it in the single private root field
   *  for this cipher only. Cleared on every navigation, disconnect, lock, account switch, and logout. */
  private async handleReprompt(id: string, password: string): Promise<void> {
    if (this.pending || !password) return;
    const external = this.autofillContinuation;
    if (external?.status === 'reprompt_required' && external.cipherId === id) {
      this.pending = true;
      try {
        let pending: Promise<ResponseMessage>;
        try {
          pending = this.request({
            type: 'autofill.continuation.authorizeReprompt',
            continuationId: external.continuationId,
            masterPassword: password,
          });
        } finally {
          password = '';
        }
        const response = await pending;
        if (!response.ok) {
          this.repromptError = response.error.message;
          return;
        }
        const result = response.data as {
          readonly verified?: boolean;
          readonly result?: AutofillContinuationResumeData;
        };
        if (result.verified !== true) {
          this.repromptError = t('auth.wrongPassword');
          return;
        }
        this.autofillContinuation = null;
        if (result.result?.status === 'started') {
          try { window.close(); } catch { /* best effort */ }
          return;
        }
        this.navigate({ name: 'vault', scope: 'suggestions' });
        this.showToast(t('fill.targetChanged'));
      } finally {
        this.pending = false;
      }
      return;
    }
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const continuation = this.repromptFillContinuation?.cipherId === id
      ? this.repromptFillContinuation
      : null;
    const manual = continuation?.kind === 'manual'
      && this.manualAutofillConfirmation?.cipherId === id
      && this.manualAutofillConfirmation.action !== undefined
      ? this.manualAutofillConfirmation as ManualAutofillConfirmationState & {
          readonly action: ManualAutofillAction;
        }
      : undefined;
    if (manual) {
      this.pending = true;
      try {
        await this.commitManualAutofill(manual, password);
      } finally {
        this.pending = false;
      }
      return;
    }
    const fillTarget = continuation?.kind === 'matched'
      ? { tabId: continuation.tabId, target: continuation.target }
      : undefined;
    const requestedTargetKey = fillTarget ? fillTargetKey(fillTarget.target) : undefined;
    this.repromptAutofillAuthorization = null;
    this.pending = true;
    try {
      let responsePromise: Promise<ResponseMessage>;
      if (fillTarget) {
        try {
          responsePromise = this.request({
            type: 'autofill.authorizeRepromptFill',
            tabId: fillTarget.tabId,
            cipherId: id,
            target: fillTarget.target,
            masterPassword: password,
          });
        } finally {
          password = '';
        }
      } else {
        responsePromise = this.request({ type: 'auth.verifyMasterPassword', masterPassword: password });
      }
      const response = await responsePromise;
      if (!this.isCurrentDetailContext(id, generation, epoch)) return;
      if (!response.ok) {
        this.repromptError = response.error.message;
        this.showToast(response.error.message);
        return;
      }
      const verification = response.data as {
        verified: boolean;
        authorization?: RepromptAutofillAuthorizationData;
      };
      if (!verification.verified) {
        this.repromptError = t('auth.wrongPassword');
        return;
      }
      if (fillTarget) {
        if (!verification.authorization || requestedTargetKey === undefined) {
          this.repromptError = t('fill.repromptRequired');
          return;
        }
        this.repromptAutofillAuthorization = {
          ...verification.authorization,
          cipherId: id,
          tabId: fillTarget.tabId,
          targetKey: requestedTargetKey,
        };
        this.repromptFillContinuation = null;
        await this.handleSuggestionFill({ cipherId: id, target: fillTarget.target });
        return;
      }
      this.detailEpoch += 1;
      this.repromptCredential = { cipherId: id, masterPassword: password };
      this.repromptError = undefined;
      this.detailExtrasCache = undefined; // rebuild extras so they carry the newly-verified credential
      this.sshDetailExtrasCache = undefined;
      this.detailCipher = null;
      this.sshKeyDetails = undefined;
      this.requestUpdate();
      if (this.route.name === 'detail') void this.loadDetail(id, this.detailEpoch, 'view');
      // In the editor, the newly-verified credential unlocks the reprompt-gated editable plaintext.
      if (this.route.name === 'editor') {
        const summary = this.items.find((item) => item.id === id);
        if (summary?.type === 5 && this.route.mode === 'edit') {
          void this.loadSshEditorData(id, this.detailEpoch, 'editor');
        } else if (summary?.type !== 5) {
          void this.loadEditorInput(id, this.route.mode === 'edit' ? 'editor' : undefined);
        }
      }
    } finally {
      this.pending = false;
    }
  }

  /** Copy a plaintext value the detail already displays, then schedule the background clipboard clear. */
  private copyToClipboard(
    value: string,
    label: string,
    clientEventAckId?: string,
  ): Promise<boolean> {
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    return this.copy(value, label, (status) => {
      if (!this.isCurrentWorkspace(generation) || epoch !== this.detailEpoch) return;
      this.detailStatus = status;
      this.showToast(status.tone === 'success' ? t('common.copiedToast') : status.message);
    }, clientEventAckId === undefined ? undefined : { clientEventAckId });
  }

  private handleCopy(detail: CopyDetail): void {
    void this.copyToClipboard(detail.value, detail.label);
  }

  /** Fetch a masked secret and copy it straight to the clipboard — the plaintext never passes
   *  through the detail component. Keyed to the inline-expanded item in the vault list. */
  private async handleSecretRequest(detail: SecretRequestDetail): Promise<void> {
    const id = this.selectedCipherId;
    if (!id || this.isUnsupportedItem(id)) return;
    if ((detail.kind === 'customField'
      || (detail.kind === 'field' && isPasswordProtectedField(detail.field)))
      && !this.itemAllows(id, 'viewPassword')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const mp = this.repromptMp(id);
    const response = detail.kind === 'field'
      ? await this.request({
          type: 'vault.getField',
          id,
          field: detail.field,
          ...(mp === undefined ? {} : { masterPassword: mp }),
          ...(isClientEventCopyField(detail.field) ? { clientEventPurpose: 'copy' as const } : {}),
        })
      : await this.request({
          type: 'vault.getCustomField',
          id,
          index: detail.index,
          ...(mp === undefined ? {} : { masterPassword: mp }),
          clientEventPurpose: 'copy',
        });
    if (!this.isCurrentDetailContext(id, generation, epoch)) return;
    if (!response.ok) {
      this.setDetailFailure(response.error.message);
      return;
    }
    const value = (response.data as { value?: string }).value;
    if (!value) {
      this.setDetailFailure(t('detail.valueEmpty', { name: detail.label }));
      return;
    }
    const clientEventAckId = detail.kind === 'field'
      ? isClientEventCopyField(detail.field) ? responseClientEventAckId(response) : undefined
      : this.detailCipher?.fields?.[detail.index]?.type === 1
        ? responseClientEventAckId(response)
        : undefined;
    await this.copyToClipboard(value, detail.label, clientEventAckId);
  }

  private async handleAttachmentDownload(detail: AttachmentRefDetail): Promise<void> {
    if (this.pending || this.isUnsupportedItem(detail.cipherId)) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.getAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId }
          : { type: 'vault.getAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId, masterPassword: mp },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      const { fileName, dataB64 } = response.data as { fileName: string; dataB64: string };
      try {
        triggerDownload(dataB64, fileName);
      } catch {
        this.setDetailFailure(t('detail.downloadFailed', { name: fileName }));
        return;
      }
      this.detailStatus = { message: t('detail.downloaded', { name: fileName }), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleAttachmentAdd(detail: AttachmentAddDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || item.deletedDate || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'edit')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.addAttachment', cipherId: detail.cipherId, fileName: detail.fileName, dataB64: detail.dataB64 }
          : { type: 'vault.addAttachment', cipherId: detail.cipherId, fileName: detail.fileName, dataB64: detail.dataB64, masterPassword: mp },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.detailEpoch += 1;
      this.detailExtrasCache = undefined;
      this.detailCipher = null;
      this.detailStatus = { message: t('detail.uploaded', { name: detail.fileName }), tone: 'success' };
      await this.loadDetail(detail.cipherId, this.detailEpoch);
    } finally {
      this.pending = false;
    }
  }

  private async handleAttachmentUpgrade(detail: AttachmentRefDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || item.deletedDate || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'edit')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.upgradeLegacyAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId }
          : { type: 'vault.upgradeLegacyAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId, masterPassword: mp },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.detailEpoch += 1;
      this.detailExtrasCache = undefined;
      this.detailCipher = null;
      this.detailStatus = {
        message: t('detail.attachmentUpgraded', { name: detail.fileName }),
        tone: 'success',
      };
      await this.loadDetail(detail.cipherId, this.detailEpoch);
    } finally {
      this.pending = false;
    }
  }

  private async handleAttachmentDelete(detail: AttachmentRefDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || item.deletedDate || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'edit')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const response = await this.request({ type: 'vault.deleteAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId });
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.detailEpoch += 1;
      this.detailExtrasCache = undefined;
      this.detailCipher = null;
      this.detailStatus = { message: t('detail.attachmentDeleted', { name: detail.fileName }), tone: 'success' };
      await this.loadDetail(detail.cipherId, this.detailEpoch);
    } finally {
      this.pending = false;
    }
  }

  private async handleDeleteItem(detail: DeleteItemDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || detail.permanent !== Boolean(item.deletedDate)
      || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'delete')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const response = await this.request(
        detail.permanent ? { type: 'vault.deleteCipher', id: detail.cipherId } : { type: 'vault.softDeleteCipher', id: detail.cipherId },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.navigate({ name: 'vault', scope: 'all' });
      this.showToast(t(detail.permanent ? 'detail.deletedPermanently' : 'detail.movedToTrash'));
    } finally {
      this.pending = false;
    }
  }

  private cipherVaultMode(item: CipherSummary): VaultMode {
    if (item.deletedDate) return 'trash';
    if (item.archivedDate) return 'archive';
    return 'active';
  }

  /** Apply only an exact active-detail favorite intent, then trust the authoritative listing reply. */
  private async handleFavoriteToggle(detail: FavoriteToggleDetail): Promise<void> {
    if (this.pending
      || this.route.name !== 'detail'
      || typeof detail?.cipherId !== 'string'
      || typeof detail.favorite !== 'boolean'
      || this.route.cipherId !== detail.cipherId) return;
    const matches = this.items.filter((candidate) => candidate.id === detail.cipherId);
    const item = matches.length === 1 ? matches[0] : undefined;
    if (!item
      || !isActiveCipher(item)
      || item.unsupported === true
      || !isKnownCipherType(item.type)
      || detail.favorite === item.favorite) return;

    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const operation = ++this.favoriteMutationSequence;
    const previousFavorite = item.favorite;
    this.pending = true;
    this.detailStatus = undefined;
    try {
      const response = await this.request({
        type: 'vault.setCipherFavorite',
        id: detail.cipherId,
        favorite: detail.favorite,
      });
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)
        || this.route.name !== 'detail') return;
      const currentMatches = this.items.filter((candidate) => candidate.id === detail.cipherId);
      const current = currentMatches.length === 1 ? currentMatches[0] : undefined;
      if (!current
        || !isActiveCipher(current)
        || current.unsupported === true
        || !isKnownCipherType(current.type)
        || current.favorite !== previousFavorite) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
    } finally {
      if (operation === this.favoriteMutationSequence
        && this.isCurrentDetailContext(detail.cipherId, generation, epoch)
        && this.route.name === 'detail') {
        this.pending = false;
      }
    }
  }

  /** Commit an item lifecycle transition against the exact source state that emitted it. Archive
   *  metadata remains usable for unknown future cipher types, while restore stays permission-gated. */
  private async handleItemLifecycle(detail: ItemLifecycleDetail): Promise<void> {
    if (this.pending) return;
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (!item || this.cipherVaultMode(item) !== detail.sourceMode) return;
    if (detail.action === 'restore'
      && (this.isUnsupportedItem(detail.cipherId) || !this.itemAllows(detail.cipherId, 'restore'))) return;

    const masterPassword = this.repromptMp(detail.cipherId);
    if (detail.action !== 'restore' && item.reprompt && masterPassword === undefined) {
      this.navigate({ name: 'detail', cipherId: detail.cipherId });
      return;
    }

    const generation = this.workspaceGeneration;
    const route = this.route;
    this.pending = true;
    this.detailStatus = undefined;
    try {
      const response = detail.action === 'restore'
        ? await this.request({ type: 'vault.restoreCipher', id: detail.cipherId })
        : detail.action === 'archive'
          ? await this.request(masterPassword === undefined
              ? { type: 'vault.archiveCipher', id: detail.cipherId }
              : { type: 'vault.archiveCipher', id: detail.cipherId, masterPassword })
          : await this.request(masterPassword === undefined
              ? { type: 'vault.unarchiveCipher', id: detail.cipherId }
              : { type: 'vault.unarchiveCipher', id: detail.cipherId, masterPassword });
      if (!this.isCurrentWorkspace(generation) || this.route !== route) return;
      const current = this.items.find((candidate) => candidate.id === detail.cipherId);
      if (!current || this.cipherVaultMode(current) !== detail.sourceMode) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.vaultMode = detail.targetMode;
      this.query = '';
      this.navigate({ name: 'vault', scope: 'all' });
      const successKey = detail.action === 'archive'
        ? 'detail.archived'
        : detail.action === 'unarchive'
          ? 'detail.unarchived'
          : 'detail.restored';
      this.showToast(t(successKey));
    } finally {
      this.pending = false;
    }
  }

  private async handlePasskeyDelete(detail: PasskeyDeleteDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || this.route.name !== 'detail' || this.route.cipherId !== detail.cipherId
      || !item || item.type !== 1 || item.deletedDate || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'edit')
      || !this.itemAllows(detail.cipherId, 'viewPassword')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const masterPassword = this.repromptMp(detail.cipherId);
    this.pending = true;
    try {
      const response = await this.request(masterPassword === undefined
        ? { type: 'vault.deletePasskey', id: detail.cipherId, credentialId: detail.credentialId }
        : {
            type: 'vault.deletePasskey',
            id: detail.cipherId,
            credentialId: detail.credentialId,
            masterPassword,
          });
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.setDetailFailure(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.detailEpoch += 1;
      this.detailExtrasCache = undefined;
      this.detailCipher = null;
      this.detailStatus = { message: t('detail.passkeyDeleted'), tone: 'success' };
      await this.loadDetail(detail.cipherId, this.detailEpoch);
      this.showToast(t('detail.passkeyDeleted'));
    } finally {
      this.pending = false;
    }
  }

  // --- Editor (dormant) orchestration -------------------------------------------------------

  private async loadSshEditorData(
    id: string,
    epoch = this.detailEpoch,
    clientEventPurpose?: Extract<PopupClientEventPurpose, 'editor'>,
  ): Promise<void> {
    const summary = this.items.find((item) => item.id === id);
    const mp = this.repromptMp(id);
    if (!summary || !this.canOpenItemEditor(summary)
      || summary.unsupported || summary.undecryptable || summary.deletedDate || summary.type !== 5
      || (summary.reprompt && mp === undefined)) return;
    const generation = this.workspaceGeneration;
    const detailRequest = this.request({
      type: 'vault.getCipherDetail',
      id,
      ...(mp === undefined ? {} : { masterPassword: mp }),
      ...(clientEventPurpose === undefined ? {} : { clientEventPurpose }),
    });
    const publicRequest = this.request(
      mp === undefined
        ? { type: 'vault.getSshKeyDetails', id }
        : { type: 'vault.getSshKeyDetails', id, masterPassword: mp },
    );
    const [detailResponse, publicResponse] = await Promise.all([detailRequest, publicRequest]);
    if (!this.isCurrentDetailContext(id, generation, epoch) || this.route.name !== 'editor') return;
    if (!detailResponse.ok) {
      this.editorStatus = { message: detailResponse.error.message, tone: 'danger' };
      return;
    }
    const clientEventAckId = clientEventPurpose === undefined
      ? undefined
      : responseClientEventAckId(detailResponse);
    if (!publicResponse.ok) {
      this.editorStatus = { message: publicResponse.error.message, tone: 'danger' };
      return;
    }
    const cipher = (detailResponse.data as { cipher: DecryptedCipher | null } | null)?.cipher ?? null;
    const publicDetails = (publicResponse.data as { sshKey: SshKeyPublicDetails | null } | null)?.sshKey ?? null;
    if (!cipher || cipher.type !== 5 || !publicDetails) {
      this.editorStatus = { message: t('vault.itemUnavailable'), tone: 'danger' };
      return;
    }
    const fields = cipher.fields ?? [];
    if (fields.some((field) => field.type === 3)) {
      this.editorStatus = { message: t('ssh.error.linkedFieldUnsupported'), tone: 'danger' };
      return;
    }
    const hydratedFields = await Promise.all(fields.map(async (field, index): Promise<DecryptedField> => {
      if (field.type !== 1) return { ...field };
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.getCustomField', id, index }
          : { type: 'vault.getCustomField', id, index, masterPassword: mp },
      );
      if (!response.ok) throw new Error(response.error.message);
      return { ...field, value: (response.data as { value?: string } | null)?.value ?? '' };
    })).catch((error: unknown) => {
      if (this.isCurrentDetailContext(id, generation, epoch) && this.route.name === 'editor') {
        this.editorStatus = { message: error instanceof Error ? error.message : t('common.error'), tone: 'danger' };
      }
      return undefined;
    });
    if (!hydratedFields || !this.isCurrentDetailContext(id, generation, epoch) || this.route.name !== 'editor') return;
    this.sshEditorCipher = { ...cipher, fields: hydratedFields };
    this.sshEditorPublicDetails = publicDetails;
    if (clientEventAckId !== undefined) {
      await this.updateComplete;
      const editor = this.renderRoot.querySelector<HTMLElement & { updateComplete: Promise<unknown> }>('vw-ssh-key-editor');
      await editor?.updateComplete;
      if (this.isCurrentDetailContext(id, generation, epoch)
        && this.route.name === 'editor'
        && editor !== null
        && this.renderRoot.querySelector('vw-ssh-key-editor') === editor) {
        this.acknowledgeClientEvent(clientEventAckId);
      }
    }
  }

  private async handleSshCreateGenerate(detail: SshCreateGenerateDetail): Promise<void> {
    await this.handleSshCreate({
      type: 'vault.createGeneratedSshKey',
      metadata: detail.metadata,
      target: detail.target,
    });
  }

  private async handleSshCreateImport(detail: SshCreateImportDetail): Promise<void> {
    await this.handleSshCreate({
      type: 'vault.importSshKey',
      metadata: detail.metadata,
      privateKey: detail.privateKey,
      target: detail.target,
    });
  }

  private async handleSshCreate(
    request: Extract<Parameters<PopupRequest>[0], { type: 'vault.createGeneratedSshKey' | 'vault.importSshKey' }>,
  ): Promise<void> {
    if (this.pending || this.sshWriteAvailability !== 'available' || this.route.name !== 'editor'
      || this.route.mode !== 'create' || this.route.cipherType !== 5) return;
    const route = this.route;
    const generation = this.workspaceGeneration;
    this.pending = true;
    this.editorStatus = undefined;
    try {
      const response = await this.request(request);
      if (!this.isCurrentWorkspace(generation) || this.route !== route) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.applyListingResponse(response);
      this.navigate({ name: 'vault', scope: 'all' });
      this.showToast(t(request.type === 'vault.createGeneratedSshKey' ? 'ssh.generated' : 'ssh.imported'));
    } finally {
      this.pending = false;
    }
  }

  private async handleSshMetadataUpdate(detail: SshUpdateMetadataDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || this.sshWriteAvailability !== 'available' || this.route.name !== 'editor'
      || this.route.mode !== 'edit' || this.route.cipherId !== detail.cipherId
      || !item || item.deletedDate
      || !this.itemAllows(detail.cipherId, 'edit')
      || !this.itemAllows(detail.cipherId, 'viewPassword')) return;
    const route = this.route;
    const generation = this.workspaceGeneration;
    const mp = this.repromptMp(detail.cipherId);
    this.pending = true;
    this.editorStatus = undefined;
    try {
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.updateSshKeyMetadata', id: detail.cipherId, metadata: detail.metadata }
          : { type: 'vault.updateSshKeyMetadata', id: detail.cipherId, metadata: detail.metadata, masterPassword: mp },
      );
      if (!this.isCurrentWorkspace(generation) || this.route !== route) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.applyListingResponse(response);
      this.navigate({ name: 'detail', cipherId: detail.cipherId });
      this.showToast(t('ssh.metadataSaved'));
    } finally {
      this.pending = false;
    }
  }

  private async handleSshReplace(detail: SshReplaceKeyDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || this.sshWriteAvailability !== 'available' || this.route.name !== 'editor'
      || this.route.mode !== 'edit' || this.route.cipherId !== detail.cipherId
      || !item || item.deletedDate
      || !this.itemAllows(detail.cipherId, 'edit')
      || !this.itemAllows(detail.cipherId, 'viewPassword')) return;
    const route = this.route;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const mp = this.repromptMp(detail.cipherId);
    this.pending = true;
    this.editorStatus = undefined;
    try {
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.replaceSshKey', id: detail.cipherId, privateKey: detail.privateKey }
          : { type: 'vault.replaceSshKey', id: detail.cipherId, privateKey: detail.privateKey, masterPassword: mp },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch) || this.route !== route) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.applyListingResponse(response);
      this.detailEpoch += 1;
      this.sshEditorPublicDetails = undefined;
      this.editorStatus = { message: t('ssh.keyReplaced'), tone: 'success' };
      void this.loadSshEditorData(detail.cipherId, this.detailEpoch);
    } finally {
      this.pending = false;
    }
  }

  /** Fetch the reprompt-gated editable plaintext for the item open in the editor. Guards against a
   *  stale response arriving after the user navigated away from that editor. */
  private async loadEditorInput(
    id: string,
    clientEventPurpose?: Extract<PopupClientEventPurpose, 'editor'>,
  ): Promise<void> {
    const summary = this.items.find((item) => item.id === id);
    if (!summary || !this.canOpenItemEditor(summary)
      || summary.unsupported || summary.undecryptable || summary.type === 5) {
      this.editorStatus = { message: t('editor.typeUnsupported'), tone: 'danger' };
      return;
    }
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    const mp = this.repromptMp(id);
    const cipherInputPurpose = this.route.name === 'editor' && this.route.mode === 'clone'
      ? 'clone'
      : 'edit';
    const response = await this.request({
      type: 'vault.getCipherInput',
      id,
      cipherInputPurpose,
      ...(mp === undefined ? {} : { masterPassword: mp }),
      ...(clientEventPurpose === undefined ? {} : { clientEventPurpose }),
    });
    if (!this.isCurrentDetailContext(id, generation, epoch) || this.route.name !== 'editor') return;
    if (!response.ok) {
      this.editorStatus = { message: response.error.message, tone: 'danger' };
      this.showToast(response.error.message);
      return;
    }
    const input = (response.data as { input: CipherInput | null }).input;
    if (!input || input.type !== summary.type) {
      this.editorStatus = { message: t('editor.typeUnsupported'), tone: 'danger' };
      return;
    }
    this.editorInput = this.route.mode === 'clone' ? cloneCipherInput(input) : input;
    const clientEventAckId = clientEventPurpose === undefined
      ? undefined
      : responseClientEventAckId(response);
    if (clientEventAckId !== undefined) {
      await this.updateComplete;
      const editor = this.renderRoot.querySelector<HTMLElement & { updateComplete: Promise<unknown> }>('vw-cipher-editor');
      await editor?.updateComplete;
      if (this.isCurrentDetailContext(id, generation, epoch)
        && this.route.name === 'editor'
        && editor !== null
        && this.renderRoot.querySelector('vw-cipher-editor') === editor) {
        this.acknowledgeClientEvent(clientEventAckId);
      }
    }
  }

  /** Persist the editor's validated `CipherInput` (create or update), then reload and return to the
   *  list. A failed request stays in the editor with the error surfaced on its own status banner. */
  private async handleTotpCapture(): Promise<void> {
    if (this.pending || this.route.name !== 'editor') return;
    const route = this.route;
    const type = route.mode === 'create' ? route.cipherType : this.editorInput?.type;
    if (type !== 1) return;
    const generation = this.workspaceGeneration;
    this.pending = true;
    this.editorStatus = undefined;
    try {
      const screenshot = await this.browser.captureVisibleTab();
      const value = await decodeTotpQr(screenshot);
      if (!this.isCurrentWorkspace(generation) || this.route !== route) return;
      if (!value) {
        this.editorStatus = { message: t('editor.totpCaptureFailed'), tone: 'danger' };
        return;
      }
      this.editorTotpCapture = {
        revision: ++this.editorTotpCaptureRevision,
        value,
      };
      this.editorStatus = { message: t('editor.totpCaptured'), tone: 'success' };
    } catch {
      if (this.isCurrentWorkspace(generation) && this.route === route) {
        this.editorStatus = { message: t('editor.totpCaptureFailed'), tone: 'danger' };
      }
    } finally {
      this.pending = false;
    }
  }

  private async handleEditorSave(detail: EditorSaveDetail): Promise<void> {
    if (this.pending || this.route.name !== 'editor') return;
    const route = this.route;
    if (route.mode === 'edit' && route.cipherId !== undefined) {
      const item = this.items.find((candidate) => candidate.id === route.cipherId);
      if (!item || item.deletedDate || this.isUnsupportedItem(route.cipherId)
        || !this.itemAllows(route.cipherId, 'edit')) return;
    }
    const generation = this.workspaceGeneration;
    const { input } = detail;
    this.pending = true;
    try {
      const response = route.mode === 'edit' && route.cipherId !== undefined
        ? await this.request({ type: 'vault.updateCipher', id: route.cipherId, input })
        : detail.target === undefined
          ? { ok: false as const, error: { code: 'denied' as const, message: t('editor.chooseVaultError') } }
          : await this.request({ type: 'vault.createCipher', input, target: detail.target });
      if (!this.isCurrentWorkspace(generation) || this.route !== route) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        this.showToast(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  /** Assign an organization item to collections — a separate operation from the field save. Keeps the
   *  editor open (with the refreshed listing) so the user can continue editing. */
  private async handleCipherCollections(detail: CipherCollectionsDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || item.deletedDate || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'edit')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const response = await this.request({ type: 'vault.setCipherCollections', id: detail.cipherId, collectionIds: detail.collectionIds });
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        this.showToast(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.editorStatus = { message: t('editor.collectionsUpdated'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  /** Move a personal item into an organization ("share") — a separate operation from both the field
   *  save and collection assignment. The worker fails closed on passkey/history items; the editor also
   *  guards these client-side. */
  private async handleEditorShare(detail: EditorShareDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || item.deletedDate || item.archivedDate
      || this.isUnsupportedItem(detail.cipherId)) return;
    const editor = this.renderRoot.querySelector<HTMLElement & { hasUnsavedChanges?: boolean }>(
      'vw-cipher-editor, vw-ssh-key-editor',
    );
    if (this.route.name === 'editor' && this.route.mode === 'edit'
      && this.route.cipherId === detail.cipherId && editor?.hasUnsavedChanges === true) {
      this.editorStatus = { message: t('editor.saveBeforeMove'), tone: 'danger' };
      return;
    }
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.shareCipher', id: detail.cipherId, organizationId: detail.organizationId, collectionIds: detail.collectionIds }
          : { type: 'vault.shareCipher', id: detail.cipherId, organizationId: detail.organizationId, collectionIds: detail.collectionIds, masterPassword: mp },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        this.showToast(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  /** Delete the item open in the editor (soft delete to trash, or permanent), then reload and return
   *  to the list. Errors stay local to the editor's status banner. */
  private async handleEditorDelete(detail: DeleteItemDetail): Promise<void> {
    const item = this.items.find((candidate) => candidate.id === detail.cipherId);
    if (this.pending || !item || detail.permanent !== Boolean(item.deletedDate)
      || this.isUnsupportedItem(detail.cipherId)
      || !this.itemAllows(detail.cipherId, 'delete')) return;
    const generation = this.workspaceGeneration;
    const epoch = this.detailEpoch;
    this.pending = true;
    try {
      const response = await this.request(
        detail.permanent ? { type: 'vault.deleteCipher', id: detail.cipherId } : { type: 'vault.softDeleteCipher', id: detail.cipherId },
      );
      if (!this.isCurrentDetailContext(detail.cipherId, generation, epoch)) return;
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        this.showToast(response.error.message);
        return;
      }
      this.applyListingResponse(response);
      this.navigate({ name: 'vault', scope: 'all' });
      this.showToast(t(detail.permanent ? 'detail.deletedPermanently' : 'detail.movedToTrash'));
    } finally {
      this.pending = false;
    }
  }

  private renderLoading() {
    return html`<div class="load-state"><vw-status-message tone="info" .icon=${'refresh'} .message=${t('vault.loading')}></vw-status-message></div>`;
  }

  private renderAuth(route: AuthRoute) {
    const providers = route.name === 'twoFactor' ? route.providers : [];
    const fido2 = route.name === 'twoFactor' ? route.fido2 : undefined;
    const twoFactorAttemptKey = route.name === 'twoFactor'
      ? this.twoFactorAttemptKey(route)
      : '';
    const selectedProvider = route.name === 'twoFactor'
      ? this.selectedTwoFactorProvider(route)
      : undefined;
    const error = 'error' in route ? route.error : undefined;
    const notice = 'notice' in route ? route.notice : undefined;
    const accountPasskeyStatus = route.name === 'accountPasskey' ? route.status : undefined;
    const ssoStatus = route.name === 'sso' ? route.status : undefined;
    const passwordChangeRequirement = route.name === 'restricted'
      ? route.requirement
      : undefined;
    const newDeviceVerificationExpiresAt = route.name === 'newDeviceVerification'
      ? route.expiresAt
      : undefined;
    const registrationEmail = route.name === 'registrationFinish'
      || route.name === 'registrationCheckEmail'
      ? route.email
      : undefined;
    const passwordHintEmail = route.name === 'passwordHint' ? route.email : '';
    const passwordHintStatus = route.name === 'passwordHint' ? route.status : undefined;
    const passwordHintMessage = route.name === 'passwordHint' ? route.message : undefined;
    return html`
      <vw-auth-views
        .mode=${route.name}
        .error=${error}
        .notice=${notice}
        .pending=${this.pending}
        .providers=${providers}
        .selectedProvider=${selectedProvider}
        .twoFactorAttemptKey=${twoFactorAttemptKey}
        .fido2=${fido2}
        .pinEnabled=${this.pinEnabled}
        .deviceRemembered=${this.deviceRemembered}
        .deviceForgotten=${this.deviceForgotten}
        .accountPasskeyStatus=${accountPasskeyStatus}
        .ssoStatus=${ssoStatus}
        .ssoRequired=${this.ssoRequired}
        .passwordChangeRequirement=${passwordChangeRequirement}
        .newDeviceVerificationExpiresAt=${newDeviceVerificationExpiresAt}
        .registrationEmail=${registrationEmail}
        .passwordHintEmail=${passwordHintEmail}
        .passwordHintStatus=${passwordHintStatus}
        .passwordHintMessage=${passwordHintMessage}
        @vw-auth-login-submit=${(event: CustomEvent<LoginSubmitDetail>) => void this.handleLoginSubmit(event.detail)}
        @vw-auth-password-hint-start=${(event: CustomEvent<PasswordHintEmailDetail>) => this.handlePasswordHintStart(event.detail)}
        @vw-password-hint-submit=${(event: CustomEvent<PasswordHintEmailDetail>) => void this.handlePasswordHintSubmit(event.detail)}
        @vw-password-hint-back=${() => this.handlePasswordHintBack()}
        @vw-auth-sso-start=${(event: CustomEvent<SsoLoginStartDetail>) => void this.handleSsoStart(event.detail)}
        @vw-auth-sso-cancel=${() => void this.handleSsoCancel()}
        @vw-auth-forced-password-change=${(event: CustomEvent<ForcedPasswordChangeSubmitDetail>) => void this.handleForcedPasswordChange(event.detail)}
        @vw-auth-account-passkey-start=${() => void this.handleAccountPasskeyStart()}
        @vw-auth-account-passkey-cancel=${() => void this.handleAccountPasskeyCancel()}
        @vw-auth-account-passkey-check=${() => void this.handleAccountPasskeyCheckState()}
        @vw-auth-account-passkey-back=${() => {
          if (route.name === 'accountPasskey' && route.status === 'waiting') {
            void this.handleAccountPasskeyCancel();
          } else {
            this.navigate(loginRoute());
          }
        }}
        @vw-auth-device-login-start=${(event: CustomEvent<DeviceLoginStartDetail>) => void this.handleDeviceLoginStart(event.detail)}
        @vw-auth-register-submit=${(event: CustomEvent<RegisterSubmitDetail>) => void this.handleRegisterSubmit(event.detail)}
        @vw-auth-register-finish-submit=${(event: CustomEvent<RegisterFinishSubmitDetail>) => void this.handleRegisterFinishSubmit(event.detail)}
        @vw-auth-registration-cancel=${() => void this.handleRegistrationCancel()}
        @vw-auth-two-factor-provider-change=${(event: CustomEvent<TwoFactorProviderChangeDetail>) => this.handleTwoFactorProviderChange(event.detail)}
        @vw-auth-two-factor-submit=${(event: CustomEvent<TwoFactorSubmitDetail>) => void this.handleTwoFactorSubmit(event.detail)}
        @vw-auth-duo-start=${(event: CustomEvent<DuoTwoFactorStartDetail>) => void this.handleDuoStart(event.detail)}
        @vw-auth-new-device-verification-submit=${(event: CustomEvent<NewDeviceVerificationSubmitDetail>) => void this.handleNewDeviceVerificationSubmit(event.detail)}
        @vw-auth-new-device-verification-send-otp=${() => void this.handleNewDeviceVerificationSendOtp()}
        @vw-auth-new-device-verification-cancel=${() => void this.handleNewDeviceVerificationCancel()}
        @vw-auth-fido2-start=${(event: CustomEvent<Fido2TwoFactorStartDetail>) => void this.handleFido2Start(event.detail)}
        @vw-auth-unlock-submit=${(event: CustomEvent<UnlockSubmitDetail>) => void this.handleUnlockSubmit(event.detail)}
        @vw-auth-pin-unlock-submit=${(event: CustomEvent<PinUnlockSubmitDetail>) => void this.handlePinUnlockSubmit(event.detail)}
        @vw-auth-email-change=${(event: CustomEvent<EmailChangeDetail>) => void this.handleEmailChange(event.detail.email)}
        @vw-auth-forget-device=${() => void this.handleForgetDevice()}
        @vw-auth-send-email-code=${(event: CustomEvent<EmailTwoFactorCodeRequestDetail>) => void this.handleSendEmailCode(event.detail)}
        @vw-auth-two-factor-recovery=${() => void this.handleTwoFactorRecovery()}
        @vw-auth-go-register=${() => this.navigate({ name: 'register' })}
        @vw-auth-back-to-login=${() => {
          if (route.name === 'twoFactor' && route.flow === 'device') void this.handleDeviceLoginCancel();
          else if (route.name === 'twoFactor') void this.handlePendingPasswordLoginCancel();
          else if (route.name === 'sso' && route.status === 'waiting') void this.handleSsoCancel();
          else this.navigate(loginRoute());
        }}
        @vw-auth-open-settings=${() => void this.browser.openOptions()}
        @vw-auth-logout=${() => void this.handleLogout()}
      ></vw-auth-views>
    `;
  }

  private renderUnlocked(route: PopupRoute) {
    if (this.dataOwnershipCheckPending) return this.renderLoading();
    if (route.name === 'dataOwnership') {
      return html`
        <vw-popup-header
          .busy=${this.pending || this.syncing}
          @vw-lock=${() => void this.handleAccountAction({ action: 'lock' })}
        >
          <vw-account-menu
            slot="account"
            .accounts=${this.accounts}
            .pinEnabled=${this.pinConfigured}
            .pinAllowed=${this.pinAllowed}
            .deviceRemembered=${this.vaultDeviceRemembered}
            .deviceLoginApprovalCount=${this.deviceLoginApprovalCount}
            .constrained=${true}
            .disabled=${this.pending || this.syncing}
            @vw-account-action=${(event: CustomEvent<AccountActionDetail>) => void this.handleAccountAction(event.detail)}
          ></vw-account-menu>
        </vw-popup-header>
        <div class="body">${this.renderDataOwnership()}</div>
      `;
    }
    return html`
      <vw-popup-header
        .busy=${this.pending || this.syncing || this.sendEncoding}
        @vw-lock=${() => void this.handleAccountAction({ action: 'lock' })}
      >
        <vw-tools-menu
          slot="tools"
          .syncing=${this.syncing}
          .disabled=${this.pending || this.sendEncoding}
          @vw-tool-action=${(event: CustomEvent<ToolActionDetail>) => void this.handleToolAction(event.detail)}
        ></vw-tools-menu>
        <vw-account-menu
          slot="account"
          .accounts=${this.accounts}
          .pinEnabled=${this.pinConfigured}
          .pinAllowed=${this.pinAllowed}
          .deviceRemembered=${this.vaultDeviceRemembered}
          .deviceLoginApprovalCount=${this.deviceLoginApprovalCount}
          .disabled=${this.pending || this.syncing || this.sendEncoding}
          @vw-account-action=${(event: CustomEvent<AccountActionDetail>) => void this.handleAccountAction(event.detail)}
        ></vw-account-menu>
      </vw-popup-header>
      <div class="body ${this.isSheetRoute(route) ? 'sheet-open' : ''}">${this.renderBodyLayer(route)}</div>
      <vw-sync-bar
        .syncing=${this.syncing}
        .disabled=${this.pending || this.sendEncoding}
        .lastSuccessfulSyncAt=${this.lastSuccessfulSyncAt}
        .dirty=${this.syncDirty}
        .generatorActive=${route.name === 'generator'}
        .totpActive=${route.name === 'totp'}
        .healthActive=${route.name === 'health'}
        @vw-add=${() => void this.startNewItem()}
        @vw-open-totp=${() => this.handleTotpToggle()}
        @vw-generator-toggle=${() => this.handleGeneratorToggle()}
        @vw-open-health=${() => this.userNavigate({ name: 'health' })}
        @vw-open-settings=${() => {
          if (this.promptForDraftDiscard()) void this.browser.openOptions();
        }}
        @vw-sync-now=${() => void this.handleSync()}
      ></vw-sync-bar>
    `;
  }

  private renderBody(route: PopupRoute) {
    if (this.manualAutofillConfirmation && this.manualAutofillConfirmation.action === undefined) {
      return html`
        <vw-manual-autofill-confirmation
          .name=${this.manualAutofillConfirmation.name}
          .warning=${this.manualAutofillConfirmation.warning}
          .pending=${this.pending}
          @vw-manual-autofill-action=${(event: CustomEvent<ManualAutofillActionDetail>) => (
            void this.handleManualAutofillAction(event.detail)
          )}
          @vw-manual-autofill-cancel=${() => this.handleManualAutofillCancel()}
        ></vw-manual-autofill-confirmation>
      `;
    }
    switch (route.name) {
      case 'generator':
        return this.renderGenerator();
      case 'detail':
        return this.renderDetail(route);
      case 'editor':
        return this.renderEditor(route);
      case 'health':
        return this.renderHealth();
      case 'sends':
        return this.renderSends();
      case 'totp':
        return this.renderTotp();
      case 'accountSecurity':
        return this.renderAccountSecurity();
      case 'dataOwnership':
        return this.renderDataOwnership();
      case 'pin':
        return this.renderPin();
      case 'deviceLoginApprovals':
        return this.renderDeviceLoginApprovals();
      default:
        return this.renderVault();
    }
  }

  /** The single-column vault: search + category chips + list with inline-expanding detail cards. */
  private renderVault() {
    const items = this.visibleVaultItems();
    const selected = this.selectedCipherId
      ? items.find((item) => item.id === this.selectedCipherId)
      : undefined;
    const extras = selected && !selected.unsupported && !selected.undecryptable && isActiveCipher(selected)
      && (!selected.reprompt || this.repromptMp(selected.id) !== undefined)
      ? this.detailExtras(selected.id)
      : undefined;
    const filtersActive = this.selectedFolderId !== null
      || this.selectedCollectionId !== null
      || this.selectedOrganizationId !== null;
    const suggestionsState: SuggestionsViewState = this.vaultMode !== 'active' || filtersActive
      ? { status: 'ready', suggestions: [] }
      : this.suggestionsState;
    return html`
      <div class="vault-shell">
        ${this.vaultMode !== 'active'
          ? nothing
          : html`
              <vw-vault-filters
                .items=${this.items.filter(isActiveCipher)}
                .folders=${this.folders}
                .collections=${this.collections}
                .orgPermissions=${this.orgPermissions}
                .selectedFolderId=${this.selectedFolderId}
                .selectedCollectionId=${this.selectedCollectionId}
                .selectedOrganizationId=${this.selectedOrganizationId}
                .pending=${this.pending}
                @vw-filter-change=${(event: CustomEvent<FilterChangeDetail>) => this.applyFilterPatch(event.detail)}
                @vw-folder-mutate=${(event: CustomEvent<FolderMutateDetail>) => void this.handleFolderMutate(event.detail)}
                @vw-collection-mutate=${(event: CustomEvent<CollectionMutateDetail>) => void this.handleCollectionMutate(event.detail)}
              ></vw-vault-filters>
            `}
        <vw-vault-view
          .items=${items}
          .suggestionsState=${suggestionsState}
          .query=${this.query}
          .category=${this.category}
          .mode=${this.vaultMode}
          .pending=${this.pending}
          .selectedCipherId=${this.selectedCipherId}
          .extras=${extras}
          .status=${this.detailStatus}
          @vw-search-change=${(event: CustomEvent<{ query: string }>) => { this.query = event.detail.query; }}
          @vw-category-change=${(event: CustomEvent<{ category: CategoryId }>) => this.handleCategoryChange(event.detail.category)}
          @vw-item-toggle=${(event: CustomEvent<{ cipherId: string }>) => this.handleItemToggle(event.detail.cipherId)}
          @vw-item-open=${(event: CustomEvent<ItemOpenDetail>) => this.navigate({ name: 'detail', cipherId: event.detail.cipherId })}
          @vw-vault-mode-change=${(event: CustomEvent<VaultModeChangeDetail>) => this.exitLifecycleView(event.detail)}
          @vw-unarchive-item=${(event: CustomEvent<ItemLifecycleDetail>) => void this.handleItemLifecycle(event.detail)}
          @vw-suggestion-fill=${(event: CustomEvent<SuggestionFillDetail>) => void this.handleSuggestionFill(event.detail)}
          @vw-item-fill=${(event: CustomEvent<{ cipherId: string }>) => void this.handleItemFill(event.detail.cipherId)}
          @vw-copy=${(event: CustomEvent<CopyDetail>) => this.handleCopy(event.detail)}
          @vw-secret-request=${(event: CustomEvent<SecretRequestDetail>) => void this.handleSecretRequest(event.detail)}
          @vw-edit-item=${(event: CustomEvent<ItemRefDetail>) => {
            const item = this.items.find((candidate) => candidate.id === event.detail.cipherId);
            if (item && !this.isUnsupportedItem(event.detail.cipherId) && this.canOpenItemEditor(item)) {
              this.navigate({ name: 'editor', mode: 'edit', cipherId: event.detail.cipherId });
            }
          }}
          @vw-command=${(event: CustomEvent<{ action: string }>) => this.handleVaultCommand(event.detail.action)}
        ></vw-vault-view>
      </div>
    `;
  }

  private renderDeviceLoginRequester() {
    return this.deviceLoginRequesterModel
      ? html`
          <vw-device-login-view
            .model=${this.deviceLoginRequesterModel}
            @vw-device-login-check=${() => void this.runDeviceLoginRequesterAction('status', 'pending')}
            @vw-device-login-retry=${() => void this.runDeviceLoginRequesterAction('retry', 'retry_required')}
            @vw-device-login-cancel=${() => void this.handleDeviceLoginCancel()}
            @vw-device-login-dismiss=${() => void this.handleDeviceLoginCancel()}
            @vw-device-login-check-auth-state=${() => void this.handleDeviceLoginCheckAuthState()}
          ></vw-device-login-view>
        `
      : this.renderLoading();
  }

  private renderDeviceLoginApprovals() {
    return this.deviceLoginApprovalModel
      ? html`
          <vw-device-login-view
            .model=${this.deviceLoginApprovalModel}
            @vw-device-login-select=${(event: CustomEvent<DeviceLoginRequestActionDetail>) => void this.handleDeviceLoginApprovalSelect(event.detail)}
            @vw-device-login-approve=${(event: CustomEvent<DeviceLoginRequestActionDetail>) => void this.handleDeviceLoginApprovalDecision(event.detail, true)}
            @vw-device-login-deny=${(event: CustomEvent<DeviceLoginRequestActionDetail>) => void this.handleDeviceLoginApprovalDecision(event.detail, false)}
            @vw-device-login-back=${() => this.handleDeviceLoginApprovalBack()}
          ></vw-device-login-view>
        `
      : this.renderLoading();
  }

  private renderBodyLayer(route: PopupRoute) {
    if (!this.isSheetRoute(route)) return this.renderBody(route);
    return html`
      ${this.renderVault()}
      <div class="scrim" @click=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}></div>
      <section class="sheet" aria-modal="true">
        <span class="sheet-handle" aria-hidden="true"></span>
        ${this.renderBody(route)}
      </section>
    `;
  }

  private isSheetRoute(route: PopupRoute): boolean {
    return route.name === 'generator' || route.name === 'health' || route.name === 'editor';
  }

  private promptForSendDraftDiscard(nextRoute?: PopupRoute): boolean {
    if (this.route.name !== 'sends' || nextRoute?.name === 'sends') return true;
    return this.renderRoot.querySelector('vw-sends-view')?.promptForUnsavedEdits() ?? true;
  }

  private promptForEditorDraftDiscard(nextRoute?: PopupRoute): boolean {
    if (this.route.name !== 'editor' || nextRoute?.name === 'editor') return true;
    const editor = this.renderRoot.querySelector<HTMLElement & {
      promptForUnsavedEdits(): boolean;
    }>('vw-cipher-editor, vw-ssh-key-editor');
    return editor?.promptForUnsavedEdits() ?? true;
  }

  private promptForDraftDiscard(nextRoute?: PopupRoute): boolean {
    return this.promptForSendDraftDiscard(nextRoute) && this.promptForEditorDraftDiscard(nextRoute);
  }

  private userNavigate(route: PopupRoute): boolean {
    if (this.pending || this.sendEncoding) return false;
    if (!this.promptForDraftDiscard(route)) return false;
    const continuation = this.autofillContinuation;
    if (continuation?.status === 'reprompt_required'
        && this.route.name === 'detail'
        && this.route.cipherId === continuation.cipherId
        && (route.name !== 'detail' || route.cipherId !== continuation.cipherId)) {
      this.cancelAutofillContinuation();
    }
    this.navigate(route);
    return true;
  }

  private handleVaultCommand(action: string): void {
    if (this.isDataOwnershipConstrained() && action !== 'lock') return;
    if (this.pending || this.sendEncoding) return;
    this.query = '';
    switch (action) {
      case 'generator': this.userNavigate({ name: 'generator' }); break;
      case 'totp': this.userNavigate({ name: 'totp' }); break;
      case 'lock': void this.handleAccountAction({ action: 'lock' }); break;
      case 'new': void this.startNewItem(); break;
      case 'health': this.userNavigate({ name: 'health' }); break;
      case 'settings': if (this.promptForDraftDiscard()) void this.browser.openOptions(); break;
    }
  }

  private isDataOwnershipConstrained(): boolean {
    return this.dataOwnershipCheckPending
      || this.organizationDataOwnershipStatus.status === 'migration_available'
      || this.organizationDataOwnershipStatus.status === 'blocked'
      || this.organizationDataOwnershipStatus.status === 'reconciliation_required'
      || this.organizationDataOwnershipStatus.status === 'unavailable';
  }

  private isDataOwnershipNavigationConstrained(): boolean {
    if (this.organizationDataOwnershipStatus.status === 'compliant'
        || this.organizationDataOwnershipStatus.status === 'not_required') return false;
    if (this.route.name === 'dataOwnership') return true;
    if (this.dataOwnershipCheckPending) return false;
    return this.organizationDataOwnershipStatus.status === 'migration_available'
      || this.organizationDataOwnershipStatus.status === 'blocked'
      || this.organizationDataOwnershipStatus.status === 'reconciliation_required'
      || this.organizationDataOwnershipStatus.status === 'unavailable';
  }

  private isDataOwnershipRouteAllowed(route: PopupRoute): boolean {
    return route.name === 'dataOwnership'
      || route.name === 'loading'
      || route.name === 'login'
      || route.name === 'passwordHint'
      || route.name === 'register'
      || route.name === 'registrationFinish'
      || route.name === 'registrationCheckEmail'
      || route.name === 'newDeviceVerification'
      || route.name === 'twoFactor'
      || route.name === 'sso'
      || route.name === 'accountPasskey'
      || route.name === 'deviceLogin'
      || route.name === 'unlock'
      || route.name === 'restricted'
      || route.name === 'websitePasskey';
  }

  private detailBackRoute(): PopupRoute {
    return { name: 'vault', scope: this.vaultMode === 'active' ? this.vaultScope : 'all' };
  }

  private itemPrimaryAction(summary: CipherSummary): 'fill' | 'open' | 'none' {
    if (isCipherInactive(summary)) return 'none';
    if (this.currentFillTarget(summary.id)) return 'fill';
    return summary.type === 1 && summary.uris.length > 0 ? 'open' : 'none';
  }

  private detailPresentationMetadata(): DetailPresentationMetadata {
    return {
      organizations: this.orgPermissions.map(({ id, name }) => ({ id, name })),
      folders: this.folders.map(({ id, name }) => ({ id, name })),
      collections: this.collections.map(({ id, name, organizationId }) => ({
        id,
        name,
        organizationId,
      })),
    };
  }

  private renderDetail(route: Extract<PopupRoute, { name: 'detail' }>) {
    const summary = this.items.find((item) => item.id === route.cipherId);
    if (!summary) {
      return html`
        <div class="load-state">
          <vw-status-message tone="warning" .icon=${'alert'} .message=${t('vault.itemUnavailable')}></vw-status-message>
          <button type="button" class="load-back" @click=${() => this.userNavigate(this.detailBackRoute())}>${t('common.back')}</button>
        </div>
      `;
    }
    if (summary.reprompt && this.repromptCredential?.cipherId !== summary.id) {
      return html`
        <vw-reprompt-gate
          .name=${summary.name}
          .pending=${this.pending}
          .error=${this.repromptError}
          @vw-reprompt-submit=${(event: CustomEvent<RepromptSubmitDetail>) => void this.handleReprompt(summary.id, event.detail.password)}
          @vw-item-back=${() => this.userNavigate(this.detailBackRoute())}
        ></vw-reprompt-gate>
      `;
    }
    const detailMode = this.cipherVaultMode(summary);
    const extras = summary.undecryptable
      ? undefined
      : this.detailExtras(summary.id);
    const sshExtras = !summary.undecryptable && summary.type === 5
      ? this.sshDetailExtras(summary.id)
      : undefined;
    return html`
      <vw-item-detail
        .summary=${summary}
        .cipher=${this.detailCipher}
        .extras=${extras}
        .presentationMetadata=${this.detailPresentationMetadata()}
        .sshKey=${summary.type === 5 ? this.sshKeyDetails : undefined}
        .sshExtras=${sshExtras}
        .sshEditable=${summary.type === 5
          && !summary.deletedDate
          && this.sshWriteAvailability === 'available'
          && this.canOpenItemEditor(summary)}
        .status=${this.detailStatus}
        .pending=${this.pending}
        .mode=${detailMode}
        .primaryAction=${this.itemPrimaryAction(summary)}
        @vw-item-back=${() => this.userNavigate(this.detailBackRoute())}
        @vw-item-fill=${(event: CustomEvent<ItemRefDetail>) => void this.handleItemFill(event.detail.cipherId)}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => this.handleCopy(event.detail)}
        @vw-secret-request=${(event: CustomEvent<SecretRequestDetail>) => void this.handleSecretRequest(event.detail)}
        @vw-favorite-toggle=${(event: CustomEvent<FavoriteToggleDetail>) => void this.handleFavoriteToggle(event.detail)}
        @vw-edit-item=${(event: CustomEvent<ItemRefDetail>) => {
          const item = this.items.find((candidate) => candidate.id === event.detail.cipherId);
          if (item && !this.isUnsupportedItem(event.detail.cipherId) && this.canOpenItemEditor(item)) {
            this.navigate({ name: 'editor', mode: 'edit', cipherId: event.detail.cipherId });
          }
        }}
        @vw-clone-item=${(event: CustomEvent<CloneItemDetail>) => this.beginClone(event.detail)}
        @vw-attachment-download=${(event: CustomEvent<AttachmentRefDetail>) => void this.handleAttachmentDownload(event.detail)}
        @vw-attachment-add=${(event: CustomEvent<AttachmentAddDetail>) => void this.handleAttachmentAdd(event.detail)}
        @vw-attachment-upgrade=${(event: CustomEvent<AttachmentRefDetail>) => void this.handleAttachmentUpgrade(event.detail)}
        @vw-attachment-delete=${(event: CustomEvent<AttachmentRefDetail>) => void this.handleAttachmentDelete(event.detail)}
        @vw-passkey-delete=${(event: CustomEvent<PasskeyDeleteDetail>) => void this.handlePasskeyDelete(event.detail)}
        @vw-delete-item=${(event: CustomEvent<DeleteItemDetail>) => void this.handleDeleteItem(event.detail)}
        @vw-archive-item=${(event: CustomEvent<ItemLifecycleDetail>) => void this.handleItemLifecycle(event.detail)}
        @vw-unarchive-item=${(event: CustomEvent<ItemLifecycleDetail>) => void this.handleItemLifecycle(event.detail)}
        @vw-restore-item=${(event: CustomEvent<ItemLifecycleDetail>) => void this.handleItemLifecycle(event.detail)}
        @vw-detail-error=${(event: CustomEvent<DetailErrorDetail>) => this.showToast(event.detail.message)}
      ></vw-item-detail>
    `;
  }

  private renderEditor(route: Extract<PopupRoute, { name: 'editor' }>) {
    // Step one of "add item": no type chosen yet → show the type picker.
    if (route.mode === 'create' && route.cipherType === undefined) {
      return html`
        <vw-type-picker
          .sshAvailability=${this.sshWriteAvailability === 'available'
            ? 'available'
            : this.sshWriteAvailability === 'unavailable' ? 'unavailable' : 'loading'}
          @vw-editor-type=${(event: CustomEvent<EditorTypeDetail>) => this.continueNewItem(event.detail)}
          @vw-item-back=${() => this.returnFromEditor()}
        ></vw-type-picker>
      `;
    }
    const editorSnapshot = this.editorWorkspaceSnapshot?.routeKey === editorRouteKey(route)
      ? this.editorWorkspaceSnapshot
      : undefined;
    const summary = editorSnapshot
      ? editorSnapshot.summary
      : route.cipherId !== undefined ? this.items.find((item) => item.id === route.cipherId) : undefined;
    const editorFolders = editorSnapshot?.folders ?? this.folders;
    const editorCollections = editorSnapshot?.collections ?? this.collections;
    const editorOrgPermissions = editorSnapshot?.orgPermissions ?? this.orgPermissions;
    const editorPersonalCreationAllowed = editorSnapshot?.personalCreationAllowed ?? this.personalCreationAllowed;
    if (route.mode !== 'create' && route.cipherId !== undefined) {
      const id = route.cipherId;
      if (!summary) {
        return html`<div class="load-state"><vw-status-message tone="warning" .icon=${'alert'} .message=${t('vault.itemUnavailable')}></vw-status-message></div>`;
      }
      // A protected item must clear the master-password gate before the editor reveals its plaintext.
      if (summary.reprompt && this.repromptCredential?.cipherId !== id) {
        return html`
          <vw-reprompt-gate
            .name=${summary.name}
            .pending=${this.pending}
            .error=${this.repromptError}
            @vw-reprompt-submit=${(event: CustomEvent<RepromptSubmitDetail>) => void this.handleReprompt(id, event.detail.password)}
             @vw-item-back=${() => this.returnFromEditor()}
          ></vw-reprompt-gate>
        `;
      }
      if (!this.canOpenItemEditor(summary)) {
        return html`
          <div class="load-state">
            <vw-status-message tone="warning" .icon=${'alert'} .message=${t('filter.notPermitted')}></vw-status-message>
            <button type="button" class="load-back" @click=${() => this.returnFromEditor()}>${t('common.back')}</button>
          </div>
        `;
      }
      if (summary.type === 5 && route.mode === 'clone') {
        return html`
          <div class="load-state">
            <vw-status-message tone="warning" .icon=${'alert'} .message=${t('editor.typeUnsupported')}></vw-status-message>
            <button type="button" class="load-back" @click=${() => this.returnFromEditor()}>${t('common.back')}</button>
          </div>
        `;
      }
      if (summary.type === 5) {
        if (this.sshWriteAvailability === 'idle' || this.sshWriteAvailability === 'loading') return this.renderLoading();
        if (this.sshEditorCipher === null && this.editorStatus?.tone === 'danger') {
          return html`
            <div class="load-state">
              <vw-status-message tone="danger" .icon=${'alert'} .message=${this.editorStatus.message}></vw-status-message>
              <button type="button" class="load-back" @click=${() => this.returnFromEditor()}>${t('common.back')}</button>
            </div>
          `;
        }
        if (this.sshWriteAvailability === 'available' && !this.sshEditorCipher) return this.renderLoading();
        return this.renderSshEditor(route, summary, editorSnapshot);
      }
      if (!this.editorInput) {
        if (this.editorStatus?.tone === 'danger') {
          return html`
            <div class="load-state">
              <vw-status-message tone="danger" .icon=${'alert'} .message=${this.editorStatus.message}></vw-status-message>
              <button type="button" class="load-back" @click=${() => this.returnFromEditor()}>${t('common.back')}</button>
            </div>
          `;
        }
        return this.renderLoading();
      }
    }
    const type = route.mode === 'create' ? route.cipherType : this.editorInput?.type;
    if (type === undefined) return this.renderLoading();
    if (type === 5) {
      if (this.sshWriteAvailability === 'idle' || this.sshWriteAvailability === 'loading') return this.renderLoading();
      return this.renderSshEditor(route, summary, editorSnapshot);
    }
    const context: EditorContext = {
      mode: route.mode,
      draftKey: editorSnapshot?.draftKey ?? `${this.workspaceGeneration}:unbound`,
      type,
      ...(route.mode === 'edit' && route.cipherId !== undefined ? { cipherId: route.cipherId } : {}),
      ...(this.editorInput ? { input: this.editorInput } : {}),
      ...(editorSnapshot?.createDefaults ? { createDefaults: editorSnapshot.createDefaults } : {}),
      folders: editorFolders,
      collections: editorCollections,
      orgPermissions: editorOrgPermissions,
      personalCreationAllowed: editorPersonalCreationAllowed,
    };
    return html`
      <vw-cipher-editor
        .context=${context}
        .summary=${route.mode === 'edit' ? summary : undefined}
        .pending=${this.pending}
        .status=${this.editorStatus}
        .totpCapture=${this.editorTotpCapture}
        .generatorHistory=${this.generatorHistory}
        .generatorPolicy=${this.generatorPolicy}
        .generatorAccountEmail=${this.activeAccountEmail()}
        @vw-totp-capture=${() => void this.handleTotpCapture()}
        @vw-editor-save=${(event: CustomEvent<EditorSaveDetail>) => void this.handleEditorSave(event.detail)}
        @vw-cipher-collections=${(event: CustomEvent<CipherCollectionsDetail>) => void this.handleCipherCollections(event.detail)}
        @vw-editor-share=${(event: CustomEvent<EditorShareDetail>) => void this.handleEditorShare(event.detail)}
        @vw-delete-item=${(event: CustomEvent<DeleteItemDetail>) => void this.handleEditorDelete(event.detail)}
        @vw-history-add=${(event: CustomEvent<GeneratorHistoryAddDetail>) => void this.handleGeneratorHistoryAdd(event.detail)}
        @vw-history-clear=${() => void this.clearGeneratorHistory()}
        @vw-item-back=${() => this.returnFromEditor()}
      ></vw-cipher-editor>
    `;
  }

  private renderSshEditor(
    route: Extract<PopupRoute, { name: 'editor' }>,
    summary: CipherSummary | undefined,
    snapshot?: EditorWorkspaceSnapshot,
  ) {
    return html`
      <vw-ssh-key-editor
        .mode=${route.mode}
        .cipherId=${route.cipherId}
        .summary=${summary}
        .cipher=${route.mode === 'edit' ? this.sshEditorCipher : null}
        .publicDetails=${route.mode === 'edit' ? this.sshEditorPublicDetails : undefined}
        .folders=${snapshot?.folders ?? this.folders}
        .collections=${snapshot?.collections ?? this.collections}
        .orgPermissions=${snapshot?.orgPermissions ?? this.orgPermissions}
        .personalCreationAllowed=${snapshot?.personalCreationAllowed ?? this.personalCreationAllowed}
        .createDefaults=${snapshot?.createDefaults}
        .draftKey=${snapshot?.draftKey ?? `${this.workspaceGeneration}:unbound`}
        .pending=${this.pending}
        .status=${this.editorStatus}
        .available=${this.sshWriteAvailability === 'available'}
        @vw-ssh-create-generate=${(event: CustomEvent<SshCreateGenerateDetail>) => void this.handleSshCreateGenerate(event.detail)}
        @vw-ssh-create-import=${(event: CustomEvent<SshCreateImportDetail>) => void this.handleSshCreateImport(event.detail)}
        @vw-ssh-update-metadata=${(event: CustomEvent<SshUpdateMetadataDetail>) => void this.handleSshMetadataUpdate(event.detail)}
        @vw-ssh-replace-key=${(event: CustomEvent<SshReplaceKeyDetail>) => void this.handleSshReplace(event.detail)}
        @vw-cipher-collections=${(event: CustomEvent<CipherCollectionsDetail>) => void this.handleCipherCollections(event.detail)}
        @vw-editor-share=${(event: CustomEvent<EditorShareDetail>) => void this.handleEditorShare(event.detail)}
        @vw-item-back=${() => this.returnFromEditor()}
      ></vw-ssh-key-editor>
    `;
  }

  private renderGenerator() {
    const prefs = getPrefs();
    return html`
      <vw-generator-view
        .history=${this.generatorHistory}
        .generatorPolicy=${this.generatorPolicy}
        .accountEmail=${this.activeAccountEmail()}
        .defaultLength=${prefs.genLength}
        .defaultUppercase=${prefs.genUppercase}
        .defaultNumbers=${prefs.genNumbers}
        .defaultSymbols=${prefs.genSymbols}
        @vw-history-add=${(event: CustomEvent<GeneratorHistoryAddDetail>) => void this.handleGeneratorHistoryAdd(event.detail)}
        @vw-history-clear=${() => void this.clearGeneratorHistory()}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => void this.copyToolValue(event.detail.value, event.detail.label)}
        @vw-item-back=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-generator-view>
    `;
  }

  private renderHealth() {
    return html`
      <vw-health-view
        .report=${this.healthReport}
        .pwned=${this.pwnedState}
        @vw-health-check=${() => void this.handleHealthCheck()}
        @vw-item-open=${(event: CustomEvent<ItemOpenDetail>) => this.navigate({ name: 'detail', cipherId: event.detail.cipherId })}
        @vw-item-back=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-health-view>
    `;
  }

  private renderTotp() {
    return html`
      <vw-totp-view
        .entries=${this.totpEntries}
        .currentIds=${this.currentSiteIds()}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => this.handleCopy(event.detail)}
        @vw-item-back=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-totp-view>
    `;
  }

  private renderSends() {    return html`
      <vw-sends-view
        .sends=${this.sendsState}
        .pending=${this.pending}
        .status=${this.toolStatus}
        .generatorHistory=${this.generatorHistory}
        .generatorPolicy=${this.generatorPolicy}
        .generatorAccountEmail=${this.activeAccountEmail()}
        @vw-send-encoding=${(event: CustomEvent<{ encoding: boolean }>) => { this.sendEncoding = event.detail.encoding; }}
        @vw-send-create=${(event: CustomEvent<SendCreateDetail>) => void this.handleSendCreate(event.detail)}
        @vw-send-update=${(event: CustomEvent<SendUpdateDetail>) => void this.handleSendUpdate(event.detail)}
        @vw-send-delete=${(event: CustomEvent<SendDeleteDetail>) => void this.handleSendDelete(event.detail)}
        @vw-history-add=${(event: CustomEvent<GeneratorHistoryAddDetail>) => void this.handleGeneratorHistoryAdd(event.detail)}
        @vw-history-clear=${() => void this.clearGeneratorHistory()}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => void this.copyToolValue(event.detail.value, event.detail.label)}
        @vw-send-receive=${() => void this.browser.openReceive()}
        @vw-item-back=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-sends-view>
    `;
  }

  private renderAccountSecurity() {
    return html`
      <vw-account-security-view
        .pending=${this.pending}
        .status=${this.toolStatus}
        @vw-change-password=${(event: CustomEvent<ChangePasswordDetail>) => void this.handleChangePassword(event.detail)}
        @vw-change-kdf=${(event: CustomEvent<ChangeKdfDetail>) => void this.handleChangeKdf(event.detail)}
        @vw-rotate-key=${(event: CustomEvent<RotateKeyDetail>) => void this.handleRotateKey(event.detail)}
        @vw-item-back=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-account-security-view>
    `;
  }

  private renderPin() {
    return html`
      <vw-pin-view
        .enabled=${this.pinConfigured}
        .allowed=${this.pinAllowed}
        .requireMasterPasswordOnRestart=${this.pinRequireMasterPasswordOnRestart}
        .pending=${this.pending}
        .status=${this.toolStatus}
        @vw-pin-set=${(event: CustomEvent<PinSetDetail>) => void this.handlePinSet(event.detail)}
        @vw-pin-remove=${() => void this.handlePinRemove()}
        @vw-item-back=${() => this.userNavigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-pin-view>
    `;
  }

  private renderDataOwnership() {
    return html`
      <vw-data-ownership-view
        .model=${this.dataOwnershipModel()}
        .pending=${this.pending}
        .error=${this.dataOwnershipError}
        .reconciliation=${this.organizationDataOwnershipStatus.status === 'reconciliation_required'
          ? {
              operation: this.organizationDataOwnershipStatus.operation,
              reason: this.organizationDataOwnershipStatus.reason,
            }
          : undefined}
        @vw-data-ownership-migrate=${(event: CustomEvent<DataOwnershipMigrationSubmitDetail>) => void this.handleDataOwnershipMigration(event.detail)}
        @vw-data-ownership-leave=${(event: CustomEvent<DataOwnershipLeaveDetail>) => void this.handleDataOwnershipLeave(event.detail)}
        @vw-data-ownership-retry=${() => void this.retryDataOwnershipStatus()}
      ></vw-data-ownership-view>
    `;
  }

  private renderWebsitePasskey() {
    return html`
      <vw-popup-frame>
        ${this.websitePasskeyModel
          ? html`
              <vw-website-passkey-view
                .model=${this.websitePasskeyModel}
                @vw-website-passkey-approve=${(event: CustomEvent<WebsitePasskeyApproveDetail>) => void this.handleWebsitePasskeyApprove(event.detail)}
                @vw-website-passkey-fallback-once=${(event: CustomEvent<WebsitePasskeyFallbackDetail>) => void this.handleWebsitePasskeyFallback(event.detail, false)}
                @vw-website-passkey-fallback-always=${(event: CustomEvent<WebsitePasskeyFallbackDetail>) => void this.handleWebsitePasskeyFallback(event.detail, true)}
                @vw-website-passkey-cancel=${(event: CustomEvent<WebsitePasskeyCancelDetail>) => void this.handleWebsitePasskeyCancel(event.detail)}
              ></vw-website-passkey-view>
            `
          : this.renderLoading()}
      </vw-popup-frame>
    `;
  }

  protected override render() {
    const route = this.route;
    if (route.name === 'websitePasskey') return this.renderWebsitePasskey();
    const isAuth =
      route.name === 'loading' ||
      route.name === 'login' ||
      route.name === 'passwordHint' ||
      route.name === 'register' ||
      route.name === 'registrationFinish' ||
      route.name === 'registrationCheckEmail' ||
      route.name === 'newDeviceVerification' ||
      route.name === 'twoFactor' ||
      route.name === 'sso' ||
      route.name === 'accountPasskey' ||
      route.name === 'deviceLogin' ||
      route.name === 'restricted' ||
      route.name === 'unlock';
    return html`
      <vw-popup-frame>
        ${isAuth
          ? route.name === 'loading'
            ? this.renderLoading()
            : route.name === 'deviceLogin'
              ? this.renderDeviceLoginRequester()
              : this.renderAuth(route as AuthRoute)
          : this.renderUnlocked(route)}
        ${this.toastMessage
          ? html`<vw-toast
              .message=${this.toastMessage}
              .offset=${42}
              @vw-toast-dismiss=${() => { this.toastMessage = ''; }}
            ></vw-toast>`
          : nothing}
      </vw-popup-frame>
    `;
  }
}

function responseClientEventAckId(response: ResponseMessage): string | undefined {
  if (!response.ok || typeof response.data !== 'object' || response.data === null
    || Array.isArray(response.data)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(response.data, 'clientEventAckId');
  if (!descriptor?.enumerable || !('value' in descriptor)) return undefined;
  const value = descriptor.value;
  return typeof value === 'string' && value.length > 0 && value.length <= 4_096
    ? value
    : undefined;
}

function isClientEventRevealField(field: FieldName): boolean {
  return field === 'password' || field === 'card.number' || field === 'card.code';
}

function isClientEventCopyField(field: FieldName): boolean {
  return field === 'password' || field === 'card.code';
}

function isExactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string')) return false;
  const expected = new Set(keys);
  return ownKeys.every((key) => expected.has(key as string)) && keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function exactPasswordHintResult(value: ResponseMessage):
  | { readonly status: PasswordHintStatus; readonly message?: string }
  | undefined {
  if (!isExactRecord(value, ['ok', 'data']) || value.ok !== true) return undefined;
  const data: unknown = value.data;
  if (isExactRecord(data, ['status'])) {
    const status = data.status;
    return status === 'sent' || status === 'no_hint' || status === 'unavailable'
      ? { status }
      : undefined;
  }
  if (!isExactRecord(data, ['status', 'message'])) return undefined;
  const status = data.status;
  if (status === 'hint'
      && typeof data.message === 'string'
      && data.message.startsWith('Your password hint is: ')
      && data.message.length > 'Your password hint is: '.length
      && data.message.length <= 4 * 1024
      && data.message.trim() === data.message
      && !containsUnsafePasswordHintText(data.message)) {
    return { status, message: data.message };
  }
  return undefined;
}

function containsUnsafePasswordHintText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f
        || (code >= 0x7f && code <= 0x9f)
        || code === 0x061c
        || code === 0x200e
        || code === 0x200f
        || (code >= 0x2028 && code <= 0x202e)
        || (code >= 0x2066 && code <= 0x2069)
        || code === 0xfeff) return true;
  }
  return false;
}

function isExactBooleanRecord(value: unknown, key: string): value is Record<string, boolean> {
  return isExactRecord(value, [key]) && typeof value[key] === 'boolean';
}

customElements.define('vw-popup-app', VwPopupApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-app': VwPopupApp;
  }
}
