import type {
  sendRequest,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionsOutcome,
  TabSuggestionTarget,
} from '../../messaging/protocol.js';
import type { FieldName } from '../../core/vault/models.js';
import type { StatusTone } from '../components/status-message.js';

/**
 * The dormant Lit popup's client-side router state. Every screen the popup can show is one
 * variant here; `VwPopupApp` owns the current value and hands it to feature views as props.
 */
export type PopupRoute =
  | { name: 'loading' }
  | { name: 'login'; error?: string }
  | { name: 'register'; error?: string }
  | { name: 'twoFactor'; providers: number[]; error?: string }
  | { name: 'unlock'; error?: string }
  | { name: 'vault'; scope: 'suggestions' | 'all'; error?: string }
  | { name: 'detail'; cipherId: string }
  | { name: 'editor'; mode: 'create' | 'edit'; cipherId?: string; cipherType?: 1 | 2 | 3 | 4 }
  | { name: 'generator' | 'health' | 'sends' | 'trash' | 'accountSecurity' | 'pin' };

/** The worker request function every popup surface is injected with; never called directly by
 *  feature/shared components — only `VwPopupApp` performs requests. */
export type PopupRequest = typeof sendRequest;

/** Thin seam around the few `webextension-polyfill` calls the popup root needs, so tests can
 *  inject a fake instead of touching real browser APIs. */
export interface PopupBrowser {
  getActiveTabId(): Promise<number | undefined>;
  openOptions(): Promise<void>;
  openReceive(): Promise<void>;
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
  | 'options'
  | 'lock'
  | 'logout'
  | 'forget-device';

/** The closed vocabulary of tools-menu actions. */
export type ToolAction = 'health' | 'sends' | 'trash' | 'sync';

/** `vw-account-action` detail. `email` is present only for the per-account switch/remove actions. */
export interface AccountActionDetail {
  action: AccountAction;
  email?: string;
}

/** `vw-tool-action` detail. */
export interface ToolActionDetail {
  action: ToolAction;
}

/** `vw-suggestion-fill` detail. Carries only the ids needed for a direct Fill — never credentials. */
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
export interface FilterChangeDetail {
  folderId?: string | null;
  collectionId?: string | null;
  query?: string;
  trash?: boolean;
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

// --- Item detail (dormant) --------------------------------------------------------------------

/** Result of an on-demand secret fetch the root performs for the detail on explicit reveal. `ok:false`
 *  carries no message — the root has already surfaced the error on its own status banner. */
export type SecretResult =
  | { ok: true; value: string | undefined }
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

/** `vw-edit-item` / `vw-restore-item` detail. */
export interface ItemRefDetail {
  cipherId: string;
}

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

/** `vw-reprompt-submit` detail from the master-password reprompt gate. */
export interface RepromptSubmitDetail {
  password: string;
}
