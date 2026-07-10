import type {
  sendRequest,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionsOutcome,
  TabSuggestionTarget,
} from '../../messaging/protocol.js';

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
