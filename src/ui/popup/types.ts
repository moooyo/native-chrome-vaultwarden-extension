import type {
  ClientEventViewPurpose,
  sendRequest,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionsOutcome,
  TabSuggestionTarget,
} from '../../messaging/protocol.js';
import type { CipherCreateTarget, FieldName, SshKeyMetadataInput } from '../../core/vault/models.js';
import type { SendInput, SendSummary, UpdateSendInput } from '../../core/vault/sends.js';
import type { KdfConfig } from '../../core/crypto/kdf.js';
import type { AsyncState } from '../components/async-state.js';
import type { StatusTone } from '../components/status-message.js';
import type { Fido2TwoFactorChallenge } from '../../core/session/auth-service.js';
import type { PasswordChangeRequirement } from '../../core/policy/master-password-policy.js';
import type { GeneratorHistoryEntryType } from '../../core/generator/history.js';
import type { PasswordHintStatus } from './auth/password-hint-view.js';

/** Popup geometry mode. Unlocked vault routes use two panes; auth and constrained routes use one. */
export type PopupLayoutMode = 'double' | 'single' | 'auth';

/** Root-authored, non-secret defaults for a create/clone editor. Every identifier is resolved again
 * against the frozen editor workspace before the child editor may use it. */
export interface EditorCreateDefaults {
  readonly folderId?: string;
  readonly organizationId?: string;
  readonly collectionIds?: readonly string[];
  readonly loginUri?: string;
}

/**
 * The dormant Lit popup's client-side router state. Every screen the popup can show is one
 * variant here; `VwPopupApp` owns the current value and hands it to feature views as props.
 */
export type PopupRoute =
  | { name: 'loading' }
  | { name: 'login'; error?: string; notice?: string }
  | { name: 'passwordHint'; email: string; status?: PasswordHintStatus; message?: string; error?: string }
  | { name: 'register'; error?: string }
  | {
      name: 'registrationFinish';
      attemptId: number;
      email: string;
      expiresAt: number;
      error?: string;
    }
  | { name: 'registrationCheckEmail'; email: string }
  | {
      name: 'newDeviceVerification';
      attemptId: number;
      continuationId?: string;
      expiresAt: number;
      error?: string;
      notice?: string;
    }
  | { name: 'twoFactor'; flow: 'password' | 'device'; providers: number[]; fido2?: Fido2TwoFactorChallenge; continuationId?: string; error?: string; notice?: string }
  | {
      name: 'sso';
      status: 'waiting' | 'processing' | 'outcome_unknown' | 'error';
      attemptId?: string;
      generation?: number;
      email?: string;
      error?: string;
    }
  | {
      name: 'accountPasskey';
      status: 'waiting' | 'outcome_unknown' | 'unavailable' | 'cancelled' | 'expired' | 'failed' | 'two_factor_unsupported';
    }
  | { name: 'deviceLogin' }
  | { name: 'unlock'; error?: string; notice?: string }
  | { name: 'restricted'; requirement: PasswordChangeRequirement; error?: string }
  | { name: 'websitePasskey' }
  | { name: 'dataOwnership' }
  | { name: 'deviceLoginApprovals'; view: 'list' | 'detail' }
  | { name: 'vault'; scope: 'suggestions' | 'all'; error?: string }
  | { name: 'detail'; cipherId: string }
  | { name: 'editor'; mode: 'create' | 'clone' | 'edit'; cipherId?: string; cipherType?: 1 | 2 | 3 | 4 | 5 }
  | { name: 'generator' | 'health' | 'sends' | 'archive' | 'trash' | 'accountSecurity' | 'pin' | 'totp' };

export type PopupClientEventPurpose = ClientEventViewPurpose;

/** The worker request function every popup surface is injected with; never called directly by
 *  feature/shared components — only `VwPopupApp` performs requests. */
export type PopupRequest = typeof sendRequest;

/** Thin seam around the few `webextension-polyfill` calls the popup root needs, so tests can
 *  inject a fake instead of touching real browser APIs. */
export interface PopupBrowser {
  getActiveTabId(): Promise<number | undefined>;
  /** Browser-owned active-tab URL. Page content never supplies this value. */
  getActiveTabUrl?(): Promise<string | undefined>;
  captureVisibleTab(): Promise<string>;
  openOptions(): Promise<void>;
  openReceive(): Promise<void>;
  openUrl(url: string): Promise<void>;
}

/** A logged-in account as surfaced by `auth.listAccounts`; non-secret display data only. */
export interface AccountInfo {
  email: string;
  active: boolean;
}

/** The closed vocabulary of account-menu actions. Components emit these — never arbitrary strings. */
export type AccountAction =
  | 'switch-account'
  | 'remove-account'
  | 'add-account'
  | 'pin'
  | 'account-security'
  | 'device-login-approvals'
  | 'options'
  | 'lock'
  | 'logout'
  | 'forget-device';

/** The closed vocabulary of tools-menu actions. */
export type ToolAction = 'generator' | 'health' | 'sends' | 'archive' | 'trash' | 'sync';

/** Mutually exclusive vault lifecycle surfaces. */
export type VaultMode = 'active' | 'archive' | 'trash';

/** `vw-vault-mode-change` detail. */
export interface VaultModeChangeDetail {
  mode: VaultMode;
}

/** `vw-account-action` detail. `email` is present only for the per-account switch/remove actions. */
export interface AccountActionDetail {
  action: AccountAction;
  email?: string;
}

/** `vw-tool-action` detail. */
export interface ToolActionDetail {
  action: ToolAction;
}

/** `vw-suggestion-fill` detail. Carries only the cipher id and browser-bound target metadata,
 *  including canonical structured-field roles when relevant; it never carries field values. */
export interface SuggestionFillDetail {
  cipherId: string;
  target: TabSuggestionTarget;
}

/** `vw-item-open` detail. */
export interface ItemOpenDetail {
  cipherId: string;
}

/** `vw-filter-change` detail: a sparse patch of the All-items filter state. A present key is the
 *  new value for that facet; an absent key leaves that facet unchanged. */
export const PERSONAL_VAULT_FILTER_ID = '__personal_vault__' as const;

export interface FilterChangeDetail {
  folderId?: string | null;
  collectionId?: string | null;
  /** `PERSONAL_VAULT_FILTER_ID` selects personal items; `null` clears the organization facet. */
  organizationId?: string | null;
  query?: string;
  mode?: VaultMode;
}

/** `vw-folder-mutate` detail: a folder CRUD request the root performs. `name`/`id` presence depends
 *  on `op` (create needs name; rename needs id+name; delete needs id). */
export interface FolderMutateDetail {
  op: 'create' | 'rename' | 'delete';
  id?: string;
  name?: string;
}

/** `vw-collection-mutate` detail: a collection CRUD request the root performs, always scoped to an
 *  organization the caller is gated to manage. */
export interface CollectionMutateDetail {
  op: 'create' | 'rename' | 'delete';
  organizationId: string;
  id?: string;
  name?: string;
}

/** The reasons Suggestions cannot be shown (every non-`ready` `TabSuggestionsOutcome` status). */
export type SuggestionsUnavailableReason = Exclude<TabSuggestionsOutcome['status'], 'ready'>;

/** The Suggestions sub-view state the root computes from `autofill.getTabSuggestions` and hands
 *  down as a prop. Never carries credentials — `TabAutofillSuggestion` is non-secret by design. */
export type SuggestionsViewState =
  | { status: 'loading' }
  | { status: 'ready'; suggestions: TabAutofillSuggestion[] }
  | { status: 'unavailable'; reason: SuggestionsUnavailableReason }
  | { status: 'error'; message: string };

/** The result of the most recent `autofill.fillTabSuggestion`, mapped by the root and handed down
 *  so the Suggestions view can render neutral guidance. `error` wins when the request failed
 *  (`ok:false`); otherwise `outcome` holds the `TabFillOutcome` status. */
export interface FillResult {
  outcome?: TabFillOutcome['status'];
  error?: string;
}

/** Scheduler-owned sync state. `null` at the root means the status is currently unknown. */
export interface PopupSyncStatus {
  identity?: string;
  lastSuccessfulSyncAt?: number;
  dirty: boolean;
  syncing: boolean;
}

// --- Item detail (dormant) --------------------------------------------------------------------

/** Result of an on-demand secret fetch the root performs for the detail on explicit reveal. `ok:false`
 *  carries no message — the root has already surfaced the error on its own status banner. */
export type SecretResult =
  | { ok: true; value: string | undefined; acknowledgeVisible?: () => void }
  | { ok: false };

/** A single verification-code snapshot (never a secret seed) the root pulls for TOTP display. */
export interface TotpSnapshot {
  code: string;
  period: number;
  remaining: number;
}

export type TotpFetchResult =
  | { ok: true; totp: TotpSnapshot | null }
  | { ok: false };

/** One decrypted previous password (fetched only on explicit history reveal). */
export interface PasswordHistoryEntry {
  password: string;
  lastUsedDate?: string;
}

export type HistoryFetchResult =
  | { ok: true; history: PasswordHistoryEntry[] }
  | { ok: false };

/**
 * The async loaders the root injects into the detail so the component can pull on-demand values
 * without ever issuing worker requests itself. Each function is a root closure over the current
 * cipher id and the verified reprompt credential; the detail invokes them only on explicit user
 * action (reveal password/hidden field, show TOTP, show history).
 */
export interface DetailExtras {
  getField(field: FieldName): Promise<SecretResult>;
  getCustomField(index: number): Promise<SecretResult>;
  getTotp(): Promise<TotpFetchResult>;
  getPasswordHistory(): Promise<HistoryFetchResult>;
}

/** Non-secret names used only to present an item's vault location. The detail resolves identifiers
 *  against these lists and never renders an unresolved identifier as a fallback. */
export interface DetailPresentationEntity {
  readonly id: string;
  readonly name: string;
}

export interface DetailPresentationCollection extends DetailPresentationEntity {
  readonly organizationId: string;
}

export interface DetailPresentationMetadata {
  readonly organizations?: readonly DetailPresentationEntity[];
  readonly folders?: readonly DetailPresentationEntity[];
  readonly collections?: readonly DetailPresentationCollection[];
}

/** `vw-secret-request` detail: the root fetches this masked secret and copies it straight to the
 *  clipboard, so the plaintext never passes through the detail component. */
export type SecretRequestDetail =
  | { kind: 'field'; field: FieldName; label: string }
  | { kind: 'customField'; index: number; label: string };

/** `vw-copy` detail: copy a plaintext value the detail already legitimately displays (username, a
 *  plain card/identity row, a revealed TOTP code, or a revealed history entry). */
export interface CopyDetail {
  value: string;
  label: string;
}

/** `vw-edit-item` detail. */
export interface ItemRefDetail {
  cipherId: string;
}

/** `vw-clone-item` detail. A passkey-bearing source is accepted only after the detail dialog records
 * the explicit omission warning acknowledgement. */
export interface CloneItemDetail extends ItemRefDetail {
  passkeyWarningAcknowledged: boolean;
}

/** `vw-favorite-toggle` detail. Favorite is per-user metadata and does not imply cipher edit access. */
export interface FavoriteToggleDetail {
  cipherId: string;
  favorite: boolean;
}

/** `vw-passkey-delete` detail. The credential ID is public WebAuthn metadata; no private key or
 * decrypted credential object crosses this event boundary. */
export interface PasskeyDeleteDetail {
  cipherId: string;
  credentialId: string;
}

/** Typed lifecycle commands emitted by Archive, Trash, and active item surfaces. */
export type ItemLifecycleDetail =
  | {
      action: 'archive';
      cipherId: string;
      sourceMode: 'active';
      targetMode: 'archive';
    }
  | {
      action: 'unarchive';
      cipherId: string;
      sourceMode: 'archive';
      targetMode: 'active';
    }
  | {
      action: 'restore';
      cipherId: string;
      sourceMode: 'trash';
      targetMode: 'active' | 'archive';
    };

/** `vw-delete-item` detail. `permanent` hard-deletes a trashed item; otherwise it soft-deletes to trash. */
export interface DeleteItemDetail {
  cipherId: string;
  permanent: boolean;
}

/** `vw-attachment-download` / `vw-attachment-delete` detail. */
export interface AttachmentRefDetail {
  cipherId: string;
  attachmentId: string;
  fileName: string;
}

/** `vw-attachment-add` detail: a chosen file already read to base64 by the detail component. */
export interface AttachmentAddDetail {
  cipherId: string;
  fileName: string;
  dataB64: string;
}

/** The status banner the root drives on the detail (copy/reveal/attachment feedback). */
export interface DetailStatus {
  message: string;
  tone: StatusTone;
}

/** Dedicated SSH private-key loader. Public material travels separately in `SshKeyPublicDetails`. */
export interface SshDetailExtras {
  getPrivateKey(): Promise<SecretResult>;
}

/** Dedicated SSH create and edit commands. Private key material exists only on import/replace. */
export interface SshCreateGenerateDetail {
  metadata: SshKeyMetadataInput;
  target: CipherCreateTarget;
}

export interface SshCreateImportDetail {
  metadata: SshKeyMetadataInput;
  privateKey: string;
  target: CipherCreateTarget;
}

export interface SshUpdateMetadataDetail {
  cipherId: string;
  metadata: SshKeyMetadataInput;
}

export interface SshReplaceKeyDetail {
  cipherId: string;
  privateKey: string;
}

/** `vw-detail-error` detail for local failures (for example, reading a chosen attachment). */
export interface DetailErrorDetail {
  message: string;
}

/** `vw-reprompt-submit` detail from the master-password reprompt gate. */
export interface RepromptSubmitDetail {
  password: string;
}

// --- Vault tools (dormant): generator, health, Sends, PIN, account security -------------------

/** `vw-history-add` detail emitted only after a non-empty value was freshly generated. */
export interface GeneratorHistoryAddDetail {
  readonly value: string;
  readonly type: GeneratorHistoryEntryType;
  readonly policyRevision: number;
}

/** A generated value selected for the currently open login editor. */
export interface GeneratorSelectionDetail {
  readonly target: 'username' | 'password';
  readonly value: string;
}

/** Non-secret local health metadata for one login with a password. */
export interface HealthEntry {
  id: string;
  name: string;
  weak: boolean;
  reuseCount: number;
}

/** The on-demand HIBP breach result the root loads via `vault.checkPwned`, keyed by cipher id.
 *  `idle` = not checked yet; `loading` = check in flight; `ready` carries the per-id breach counts. */
export type PwnedState = AsyncState<ReadonlyMap<string, number>>;

/** `vw-send-create` detail: a text or file Send the root creates. The file variant carries the
 *  already-read base64 bytes so the root only performs the worker request. */
export type SendCreateDetail =
  | { kind: 'text'; input: SendInput }
  | { kind: 'file'; input: SendInput; dataB64: string; fileName: string };

/** `vw-send-update` detail: an edit to an existing Send the root performs. */
export interface SendUpdateDetail {
  id: string;
  input: UpdateSendInput;
}

/** `vw-send-delete` detail. */
export interface SendDeleteDetail {
  id: string;
}

/** `vw-change-password` detail: a validated master-password change the root performs. */
export interface ChangePasswordDetail {
  currentPassword: string;
  newPassword: string;
  masterPasswordHint: string;
}

/** `vw-change-kdf` detail: validated PBKDF2 or Argon2id settings. */
export interface ChangeKdfDetail {
  currentPassword: string;
  kdf: KdfConfig;
}

/** `vw-rotate-key` detail: the confirmed encryption-key rotation the root performs. */
export interface RotateKeyDetail {
  masterPassword: string;
}

/** `vw-pin-set` detail: a validated new PIN (already >= 4 characters). */
export interface PinSetDetail {
  pin: string;
  requireMasterPasswordOnRestart: boolean;
}

/** Re-exported so tool components/tests reference a single Send type surface. */
export type { SendSummary };
