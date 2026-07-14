import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import { sendRequest, type ResponseMessage } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { SessionState } from '../../core/session/session-manager.js';
import type { CipherInput, CipherSummary, CollectionSummary, DecryptedCipher, FolderSummary, TotpListEntry } from '../../core/vault/models.js';
import type { OrgPermission } from '../../core/vault/org-permissions.js';
import type { TabFillOutcome, TabSuggestionsOutcome } from '../../messaging/protocol.js';
import { themeTokens, paletteTokens } from '../components/tokens.js';
import { initLocale, t } from '../i18n/index.js';
import { initAppearance, AppearanceController } from '../theme.js';
import '../components/status-message.js';
import '../components/toast.js';
import './popup-frame.js';
import './auth/auth-views.js';
import './vault/popup-header.js';
import './vault/vault-view.js';
import './vault/totp-view.js';
import './vault/sync-bar.js';
import type { CategoryId } from './vault/vault-view.js';
import './item/reprompt-gate.js';
import './editor/type-picker.js';
import './editor/cipher-editor.js';
import './tools/generator-view.js';
import './tools/health-view.js';
import './tools/sends-view.js';
import './tools/account-security-view.js';
import './tools/pin-view.js';
import { safeWebUrl, triggerDownload } from './utils.js';
import { addPasswordToHistory } from '../../core/generator/history.js';
import type { AsyncState } from '../components/async-state.js';
import type {
  EmailChangeDetail,
  LoginSubmitDetail,
  PinUnlockSubmitDetail,
  RegisterSubmitDetail,
  TwoFactorSubmitDetail,
  UnlockSubmitDetail,
} from './auth/auth-views.js';
import type {
  AccountActionDetail,
  AccountInfo,
  AttachmentAddDetail,
  AttachmentRefDetail,
  CollectionMutateDetail,
  CopyDetail,
  DeleteItemDetail,
  DetailExtras,
  DetailStatus,
  FillResult,
  FilterChangeDetail,
  FolderMutateDetail,
  ItemOpenDetail,
  ItemRefDetail,
  PopupBrowser,
  PopupRequest,
  PopupRoute,
  RepromptSubmitDetail,
  SecretRequestDetail,
  SuggestionFillDetail,
  SuggestionsViewState,
  ToolActionDetail,
} from './types.js';
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
  EditorShareDetail,
  EditorTypeDetail,
} from './editor/editor-types.js';

/** The auth-related route names `VwAuthViews` renders; everything else is out of this task's scope. */
type AuthRoute = Extract<PopupRoute, { name: 'login' | 'register' | 'twoFactor' | 'unlock' }>;

function loginRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'login' } : { name: 'login', error };
}

function registerRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'register' } : { name: 'register', error };
}

function unlockRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'unlock' } : { name: 'unlock', error };
}

function twoFactorRoute(providers: number[], error?: string): PopupRoute {
  return error === undefined ? { name: 'twoFactor', providers } : { name: 'twoFactor', providers, error };
}

/** The real `PopupBrowser`, backed by `webextension-polyfill`. */
function createDefaultBrowser(): PopupBrowser {
  return {
    async getActiveTabId() {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      return tabs[0]?.id;
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

/**
 * The dormant Lit popup root. It owns the current `route`, the single in-flight `pending` flag,
 * and the small pieces of ephemeral auth UI state (PIN availability, remembered-device banner).
 * It performs every worker request itself (via the injectable `request`) and only ever hands
 * plain props down to `vw-auth-views`, reacting to that component's typed submit/action events.
 *
 * Not wired into `popup.html` yet — `src/ui/popup/popup.ts` remains the live entry point until a
 * later task replaces it.
 */
export class VwPopupApp extends LitElement {
  static override properties = {
    route: { attribute: false },
    pending: { type: Boolean },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
    deviceForgotten: { type: Boolean },
    items: { attribute: false },
    folders: { attribute: false },
    collections: { attribute: false },
    orgPermissions: { attribute: false },
    skippedOrgCount: { type: Number },
    selectedFolderId: { attribute: false },
    selectedCollectionId: { attribute: false },
    query: { type: String },
    showTrash: { type: Boolean },
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
    generatorHistory: { attribute: false },
    healthReport: { attribute: false },
    pwnedState: { attribute: false },
    sendsState: { attribute: false },
    toolStatus: { attribute: false },
    vaultScope: { type: String },
    selectedCipherId: { attribute: false },
    category: { type: String },
    syncing: { type: Boolean },
    lastSync: { type: Number },
    toastMessage: { type: String },
  };

  declare route: PopupRoute;
  declare pending: boolean;
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare deviceForgotten: boolean;
  declare items: CipherSummary[];
  declare folders: FolderSummary[];
  declare collections: CollectionSummary[];
  declare orgPermissions: OrgPermission[];
  declare skippedOrgCount: number;
  declare selectedFolderId: string | null;
  declare selectedCollectionId: string | null;
  declare query: string;
  declare showTrash: boolean;
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
  /** The in-memory generated-password history for the standalone generator. Held only for the popup
   *  session (never persisted), capped via `addPasswordToHistory`, and cleared on lock/logout/switch. */
  declare generatorHistory: string[];
  /** The local password-health report, loaded on entry to the health route. */
  declare healthReport: AsyncState<HealthEntry[]>;
  /** The explicit HIBP breach-count result, loaded only on the user's `vw-health-check`. */
  declare pwnedState: PwnedState;
  /** The current account's Sends, loaded on entry to the sends route. */
  declare sendsState: AsyncState<SendSummary[]>;
  /** Copy/create/update feedback banner the root drives on the open tool view (Sends, account
   *  security, PIN). Only one tool route is active at a time, so a single banner suffices. */
  declare toolStatus: DetailStatus | undefined;
  declare vaultScope: 'suggestions' | 'all';
  declare selectedCipherId: string | null;
  /** The active category-chip filter for the vault list. */
  declare category: CategoryId;
  /** True while a manual/auto vault sync is in flight (drives the sync-bar spinner). */
  declare syncing: boolean;
  /** Epoch-ms of the last successful sync, or undefined when never synced this session. */
  declare lastSync: number | undefined;
  /** Transient copy-confirmation toast text (empty = hidden). */
  declare toastMessage: string;

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

  constructor() {
    super();
    this.route = { name: 'loading' };
    this.pending = false;
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.deviceForgotten = false;
    this.items = [];
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.skippedOrgCount = 0;
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
    this.query = '';
    this.showTrash = false;
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
    this.generatorHistory = [];
    this.healthReport = { status: 'idle' };
    this.pwnedState = { status: 'idle' };
    this.sendsState = { status: 'idle' };
    this.toolStatus = undefined;
    this.vaultScope = 'suggestions';
    this.selectedCipherId = null;
    this.category = 'all';
    this.syncing = false;
    this.lastSync = undefined;
    this.toastMessage = '';
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
        flex: 1;
        min-height: 0;
        display: flex;
        flex-direction: column;
        /* Clip here (no scrollbar on the body); the routed view owns its own internal scroller (the
         * vault list, editor .scroll, etc.). Making the body itself scroll (overflow-y:auto) nests a
         * second scrollbar behind the list's — keep it hidden so the list is the only scrollbar. */
        overflow: hidden;
      }
    `,
  ];

  /** Mirrors the theme + density prefs onto this root host so the palette re-themes at runtime. */
  private appearance = new AppearanceController(this);

  override connectedCallback(): void {
    super.connectedCallback();
    void this.bootstrap();
  }

  /** Load persisted language + appearance prefs (so the first paint is themed/localized), then route. */
  private async bootstrap(): Promise<void> {
    await Promise.all([initLocale(), initAppearance()]);
    await this.init();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.clearEphemeralDetailState();
  }

  private clearEphemeralDetailState(): void {
    if (this.totpTimer !== undefined) {
      clearInterval(this.totpTimer);
      this.totpTimer = undefined;
    }
    // Also stop the 2FA-list countdown here so a programmatic detach (disconnectedCallback) while the
    // totp route is active can't leak the 1s interval — `navigate()` alone doesn't cover disconnects.
    this.stopTotpList();
    this.repromptCredential = null;
    this.detailExtrasCache = undefined;
    this.detailCipher = null;
    this.detailStatus = undefined;
    this.repromptError = undefined;
    this.editorInput = null;
    this.editorStatus = undefined;
  }

  /** Assigns the next route, clearing per-view ephemeral state that must not survive a
   *  navigation: the TOTP timer, the reprompt credential, and (when leaving their owning view)
   *  the remembered-device banner and PIN availability flag. */
  navigate(route: PopupRoute): void {
    this.clearEphemeralDetailState();
    this.route = route;
    if (route.name === 'vault') {
      this.vaultScope = route.scope;
      this.selectedCipherId = null;
    } else if (route.name === 'detail') {
      this.selectedCipherId = route.cipherId;
    }
    if (route.name !== 'login') {
      this.deviceRemembered = false;
      this.deviceForgotten = false;
      this.deviceCheckEmail = '';
    }
    if (route.name === 'unlock') {
      void this.refreshPinStatus();
    } else {
      this.pinEnabled = false;
    }
    if (route.name === 'detail') {
      void this.loadDetail(route.cipherId);
    }
    if (route.name === 'editor' && route.mode === 'edit' && route.cipherId !== undefined) {
      const summary = this.items.find((item) => item.id === route.cipherId);
      // A protected item must clear the reprompt gate (which then triggers the load) before the
      // editor can reveal its editable plaintext; otherwise load it straight away.
      if (!summary?.reprompt || this.repromptCredential?.cipherId === route.cipherId) {
        void this.loadEditorInput(route.cipherId);
      }
    }
    if (route.name === 'generator' || route.name === 'health' || route.name === 'sends' || route.name === 'pin' || route.name === 'accountSecurity') {
      this.toolStatus = undefined;
    }
    if (route.name === 'health') void this.loadHealth();
    if (route.name === 'sends') void this.loadSends();
    if (route.name === 'pin') void this.loadPinStatus();
    // The 2FA view owns a live countdown tick; load on entry, stop it whenever we leave.
    if (route.name === 'totp') void this.loadTotpCodes();
    else this.stopTotpList();
  }

  private async init(): Promise<void> {
    const response = await this.request({ type: 'auth.getState' });
    if (!response.ok) {
      this.navigate(loginRoute(response.error.message));
      return;
    }
    const { state } = response.data as { state: SessionState };
    if (state === 'loggedOut') {
      this.navigate(loginRoute());
    } else if (state === 'locked') {
      this.navigate(unlockRoute());
    } else {
      this.enterVault();
    }
  }

  private async refreshPinStatus(): Promise<void> {
    const response = await this.request({ type: 'auth.pinStatus' });
    if (this.route.name !== 'unlock') return; // navigated away while the request was in flight
    this.pinEnabled = response.ok && (response.data as { enabled: boolean }).enabled;
  }

  /** Routes an `AuthResult`/error exactly like the live popup's `handleAuthResult`: 2FA challenges
   *  go to the two-factor screen, failures stay on whichever auth screen raised them, and any
   *  other success goes to the vault's default (suggestions) scope. */
  private async routeAuthResult(response: ResponseMessage): Promise<void> {
    if (!response.ok) {
      if (response.error.code === 'session_expired') {
        // The sign-in session (pending 2FA) was lost — reset to the login screen to re-enter the password.
        this.navigate(loginRoute(response.error.message));
      } else if (this.route.name === 'twoFactor') {
        this.navigate(twoFactorRoute(this.route.providers, response.error.message));
      } else if (this.route.name === 'register') {
        this.navigate(registerRoute(response.error.message));
      } else {
        this.navigate(loginRoute(response.error.message));
      }
      return;
    }
    const data = response.data as AuthResult;
    if (data.kind === 'twoFactor') {
      this.navigate(twoFactorRoute(data.providers));
    } else {
      this.enterVault();
    }
  }

  private async handleLoginSubmit(detail: LoginSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const result = await this.request({ type: 'auth.login', email: detail.email, masterPassword: detail.masterPassword });
      await this.routeAuthResult(result);
    } finally {
      this.pending = false;
    }
  }

  private async handleRegisterSubmit(detail: RegisterSubmitDetail): Promise<void> {
    if (detail.masterPassword.length < 8) {
      this.navigate(registerRoute('Master password must be at least 8 characters'));
      return;
    }
    if (detail.masterPassword !== detail.confirm) {
      this.navigate(registerRoute('Passwords do not match'));
      return;
    }
    if (this.pending) return;
    this.pending = true;
    try {
      const result = await this.request(
        detail.name !== undefined
          ? { type: 'auth.register', email: detail.email, masterPassword: detail.masterPassword, name: detail.name }
          : { type: 'auth.register', email: detail.email, masterPassword: detail.masterPassword },
      );
      await this.routeAuthResult(result);
    } finally {
      this.pending = false;
    }
  }

  private async handleTwoFactorSubmit(detail: TwoFactorSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const result = await this.request({ type: 'auth.submitTwoFactor', provider: detail.provider, code: detail.code, remember: detail.remember });
      await this.routeAuthResult(result);
    } finally {
      this.pending = false;
    }
  }

  private async handleSendEmailCode(): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.sendEmailCode' });
      if (!response.ok) {
        if (response.error.code === 'session_expired') this.navigate(loginRoute(response.error.message));
        else if (this.route.name === 'twoFactor') this.navigate(twoFactorRoute(this.route.providers, response.error.message));
      }
    } finally {
      this.pending = false;
    }
  }

  private async handleUnlockSubmit(detail: UnlockSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.unlock', masterPassword: detail.masterPassword });
      if (response.ok) this.enterVault();
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
      if (response.ok) this.enterVault();
      else this.navigate(unlockRoute(response.error.message));
    } finally {
      this.pending = false;
    }
  }

  private async handleLogout(): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      await this.request({ type: 'auth.logout' });
      this.navigate(loginRoute());
    } finally {
      this.pending = false;
    }
  }

  private async handleEmailChange(email: string): Promise<void> {
    this.deviceCheckEmail = email;
    this.deviceForgotten = false;
    if (!email) {
      this.deviceRemembered = false;
      return;
    }
    const response = await this.request({ type: 'auth.isDeviceRemembered', email });
    if (this.deviceCheckEmail !== email) return; // superseded by a newer change
    this.deviceRemembered = response.ok && (response.data as { remembered: boolean }).remembered;
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
  private enterVault(): void {
    this.vaultScope = 'suggestions';
    this.navigate({ name: 'vault', scope: 'suggestions' });
    void this.loadVaultData();
  }

  private async loadVaultData(): Promise<void> {
    await Promise.all([this.loadListing(), this.loadAccounts(), this.loadSuggestions()]);
  }

  private applyListingData(
    data: { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[]; orgPermissions: OrgPermission[] } | null,
  ): void {
    this.items = data?.items ?? [];
    this.folders = data?.folders ?? [];
    this.collections = data?.collections ?? [];
    this.orgPermissions = data?.orgPermissions ?? [];
  }

  private applyListingResponse(response: ResponseMessage): void {
    if (!response.ok) return;
    this.applyListingData(
      response.data as { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[]; orgPermissions: OrgPermission[] } | null,
    );
  }

  private async loadListing(): Promise<void> {
    const [listing, skipped] = await Promise.all([
      this.request({ type: 'vault.listItems' }),
      this.request({ type: 'vault.getSkippedOrgCount' }),
    ]);
    this.applyListingResponse(listing);
    this.skippedOrgCount = skipped.ok ? ((skipped.data as { count?: number } | null)?.count ?? 0) : 0;
  }

  private async loadAccounts(): Promise<void> {
    const [accounts, pin, remembered] = await Promise.all([
      this.request({ type: 'auth.listAccounts' }),
      this.request({ type: 'auth.pinStatus' }),
      this.request({ type: 'auth.isDeviceRemembered' }),
    ]);
    this.accounts = accounts.ok ? ((accounts.data as { accounts?: AccountInfo[] } | null)?.accounts ?? []) : [];
    this.pinConfigured = pin.ok && Boolean((pin.data as { enabled?: boolean } | null)?.enabled);
    this.vaultDeviceRemembered = remembered.ok && Boolean((remembered.data as { remembered?: boolean } | null)?.remembered);
  }

  /** Resolve the active tab, then ask the worker for its login suggestions. A missing tab is the
   *  explicit `no_eligible_tab` neutral state; unavailable outcomes map to their reason; only
   *  non-secret `TabAutofillSuggestion`s ever reach `suggestionsState`. */
  private async loadSuggestions(): Promise<void> {
    const seq = ++this.latestSuggestionsSeq;
    this.suggestionsState = { status: 'loading' };
    const tabId = await this.browser.getActiveTabId();
    if (!this.isUnlockedWorkspace() || seq !== this.latestSuggestionsSeq) return;
    if (tabId === undefined) {
      this.activeTabId = undefined;
      this.suggestionsState = { status: 'unavailable', reason: 'no_eligible_tab' };
      return;
    }
    this.activeTabId = tabId;
    const response = await this.request({ type: 'autofill.getTabSuggestions', tabId });
    if (!this.isUnlockedWorkspace() || seq !== this.latestSuggestionsSeq) return;
    if (!response.ok) {
      this.suggestionsState = { status: 'error', message: response.error.message };
      return;
    }
    const { outcome } = response.data as { outcome: TabSuggestionsOutcome };
    this.suggestionsState = outcome.status === 'ready'
      ? { status: 'ready', suggestions: outcome.suggestions }
      : { status: 'unavailable', reason: outcome.status };
  }

  /** Fill the current tab from a suggestion. Sends only tabId/cipherId/target — never credentials —
   *  and maps both `ok:false` errors and every `TabFillOutcome` status to a local `fillResult`. */
  private async handleSuggestionFill(detail: SuggestionFillDetail): Promise<void> {
    if (this.activeTabId === undefined) {
      this.fillResult = { outcome: 'no_eligible_tab' };
      return;
    }
    const response = await this.request({
      type: 'autofill.fillTabSuggestion',
      tabId: this.activeTabId,
      cipherId: detail.cipherId,
      target: detail.target,
    });
    if (!response.ok) {
      this.fillResult = { error: response.error.message };
      return;
    }
    const { outcome } = response.data as { outcome: TabFillOutcome };
    this.fillResult = { outcome: outcome.status };
  }

  private handleScopeChange(id: string): void {
    if (id === 'suggestions' || id === 'all') {
      this.vaultScope = id;
      this.navigate({ name: 'vault', scope: id });
    }
  }

  /** Expand/collapse an item's inline detail card. Selecting clears any stale reprompt/extras cache. */
  private handleItemToggle(cipherId: string): void {
    this.selectedCipherId = cipherId ? cipherId : null;
    this.detailStatus = undefined;
    this.detailExtrasCache = undefined;
  }

  private handleCategoryChange(category: CategoryId): void {
    this.category = category;
    this.selectedCipherId = null;
  }

  /** "Open and fill" from the inline card: fill the current tab when this item is a live suggestion,
   *  otherwise open its first URL in a new tab. */
  private async handleItemFill(cipherId: string): Promise<void> {
    const suggestion = this.suggestionsState.status === 'ready'
      ? this.suggestionsState.suggestions.find((s) => s.id === cipherId)
      : undefined;
    if (suggestion?.target) {
      await this.handleSuggestionFill({ cipherId, target: suggestion.target });
      return;
    }
    const uri = this.items.find((item) => item.id === cipherId)?.uris[0];
    if (uri) await this.browser.openUrl(uri);
  }

  /** The shared vault-sync body: request a sync, apply the refreshed listing, stamp the last-synced
   *  time, and reload suggestions. Each caller owns its own in-flight guard (the sync-bar uses
   *  `syncing`; the tools menu uses `pending`). */
  private async syncVault(): Promise<void> {
    const response = await this.request({ type: 'vault.sync' });
    if (response.ok) {
      this.applyListingResponse(response);
      this.lastSync = Date.now();
      await this.loadSuggestions();
    }
  }

  /** Manual vault sync from the bottom sync bar: drives the spinner + last-synced label. */
  private async handleSync(): Promise<void> {
    if (this.syncing) return;
    this.syncing = true;
    try {
      await this.syncVault();
    } finally {
      this.syncing = false;
    }
  }

  /** Toggle the generator overlay from the top bar (returns to the vault list when already open). */
  private handleGeneratorToggle(): void {
    if (this.route.name === 'generator') this.navigate({ name: 'vault', scope: this.vaultScope });
    else this.navigate({ name: 'generator' });
  }

  /** Toggle the 2FA (authenticator) view from the top bar, back to the vault on a second press. */
  private handleTotpToggle(): void {
    if (this.route.name === 'totp') this.navigate({ name: 'vault', scope: this.vaultScope });
    else this.navigate({ name: 'totp' });
  }

  /** Load every login's live one-time code for the 2FA view, then start the local countdown tick. */
  private async loadTotpCodes(): Promise<void> {
    const response = await this.request({ type: 'vault.getTotpCodes' });
    if (this.route.name !== 'totp') return; // navigated away while the request was in flight
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
    return this.suggestionsState.status === 'ready' ? this.suggestionsState.suggestions.map((s) => s.id) : [];
  }

  private showToast(message: string): void {
    this.toastMessage = message;
  }

  private isUnlockedWorkspace(): boolean {
    return !['loading', 'login', 'register', 'twoFactor', 'unlock'].includes(this.route.name);
  }

  private applyFilterPatch(patch: FilterChangeDetail): void {
    if ('folderId' in patch) this.selectedFolderId = patch.folderId ?? null;
    if ('collectionId' in patch) this.selectedCollectionId = patch.collectionId ?? null;
    if (patch.query !== undefined) this.query = patch.query;
    if (patch.trash !== undefined) this.showTrash = patch.trash;
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
    this.pending = true;
    try {
      const response = await pending;
      if (response.ok) {
        if (detail.op === 'delete' && this.selectedFolderId === detail.id) this.selectedFolderId = null;
        this.applyListingResponse(response);
      }
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
    this.pending = true;
    try {
      const response = await pending;
      if (response.ok) {
        if (detail.op === 'delete' && this.selectedCollectionId === detail.id) this.selectedCollectionId = null;
        this.applyListingResponse(response);
      }
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
    else this.enterVault();
  }

  private resetVaultState(): void {
    this.items = [];
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.accounts = [];
    this.skippedOrgCount = 0;
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
    this.query = '';
    this.showTrash = false;
    this.suggestionsState = { status: 'loading' };
    this.totpEntries = [];
    this.fillResult = {};
    this.vaultScope = 'suggestions';
    this.selectedCipherId = null;
    this.activeTabId = undefined;
    this.clearToolState();
  }

  /** Drop every tool-view value that must not survive a lock/logout/account switch: the in-memory
   *  generator history and the loaded health/HIBP/Sends state. */
  private clearToolState(): void {
    this.generatorHistory = [];
    this.healthReport = { status: 'idle' };
    this.pwnedState = { status: 'idle' };
    this.sendsState = { status: 'idle' };
    this.toolStatus = undefined;
  }

  private async handleAccountAction(detail: AccountActionDetail): Promise<void> {
    switch (detail.action) {
      case 'switch-account':
        if (detail.email !== undefined) {
          if (this.pending) return;
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
        this.navigate(loginRoute());
        return;
      case 'pin':
        this.navigate({ name: 'pin' });
        return;
      case 'account-security':
        this.navigate({ name: 'accountSecurity' });
        return;
      case 'options':
        await this.browser.openOptions();
        return;
      case 'lock': {
        if (this.pending) return;
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
      case 'logout':
        await this.request({ type: 'auth.logout' });
        this.resetVaultState();
        this.navigate(loginRoute());
        return;
      case 'forget-device': {
        const response = await this.request({ type: 'auth.forgetDevice' });
        if (response.ok) this.vaultDeviceRemembered = false;
        return;
      }
    }
  }

  private async handleToolAction(detail: ToolActionDetail): Promise<void> {
    switch (detail.action) {
      case 'generator':
        this.navigate({ name: 'generator' });
        return;
      case 'health':
        this.navigate({ name: 'health' });
        return;
      case 'sends':
        this.navigate({ name: 'sends' });
        return;
      case 'trash':
        this.showTrash = true;
        this.navigate({ name: 'vault', scope: 'all' });
        return;
      case 'sync': {
        if (this.pending) return;
        this.pending = true;
        try {
          await this.syncVault();
        } finally {
          this.pending = false;
        }
        return;
      }
    }
  }

  // --- Vault tools (dormant) orchestration ------------------------------------------------------

  /** The active account's email, used to prefill the generator's plus-addressed base email. */
  private activeAccountEmail(): string | undefined {
    return (this.accounts.find((account) => account.active) ?? this.accounts[0])?.email;
  }

  /** Shared clipboard copy: write the value, schedule the background clear, and report success/failure
   *  through the caller's status setter. Optionally raises the copy-confirmation toast. */
  private async copy(
    value: string,
    label: string,
    setStatus: (status: DetailStatus) => void,
    opts?: { toast?: boolean },
  ): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      void this.request({ type: 'clipboard.scheduleClear' });
      setStatus({ message: `${label} copied to clipboard`, tone: 'success' });
      if (opts?.toast) this.showToast(t('common.copiedClear'));
    } catch {
      setStatus({ message: `Failed to copy ${label.toLowerCase()}`, tone: 'danger' });
    }
  }

  /** Copy a non-secret tool value (a generated password/username, or a Send link) and schedule the
   *  background clipboard clear. Feedback lands on the shared tool banner. */
  private copyToolValue(value: string, label: string): Promise<void> {
    return this.copy(value, label, (status) => { this.toolStatus = status; });
  }

  /** Record a freshly generated value into the in-memory (never persisted) generator history. */
  private handleGeneratorHistoryAdd(detail: GeneratorHistoryAddDetail): void {
    this.generatorHistory = addPasswordToHistory(this.generatorHistory, detail.value);
  }

  private async loadHealth(): Promise<void> {
    this.healthReport = { status: 'loading' };
    this.pwnedState = { status: 'idle' };
    const response = await this.request({ type: 'vault.getPasswordHealth' });
    if (this.route.name !== 'health') return;
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
    const response = await this.request({ type: 'vault.checkPwned' });
    if (this.route.name !== 'health') return;
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
    this.sendsState = { status: 'loading' };
    const response = await this.request({ type: 'sends.list' });
    if (this.route.name !== 'sends') return;
    if (!response.ok) {
      this.sendsState = { status: 'error', message: response.error.message };
      return;
    }
    const sends = (response.data as { sends?: SendSummary[] } | null)?.sends ?? [];
    this.sendsState = sends.length > 0 ? { status: 'ready', data: sends } : { status: 'empty' };
  }

  private async handleSendCreate(detail: SendCreateDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = detail.kind === 'text'
        ? await this.request({ type: 'sends.createText', input: detail.input })
        : await this.request({ type: 'sends.createFile', input: detail.input, dataB64: detail.dataB64, fileName: detail.fileName });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      const send = (response.data as { send?: SendSummary } | null)?.send;
      if (send) {
        await this.copyToolValue(send.url, 'Send link');
        this.toolStatus = { message: 'Send created. Link copied to clipboard.', tone: 'success' };
      }
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleSendUpdate(detail: SendUpdateDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'sends.update', id: detail.id, input: detail.input });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.toolStatus = { message: 'Send updated.', tone: 'success' };
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleSendDelete(detail: SendDeleteDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'sends.delete', id: detail.id });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async loadPinStatus(): Promise<void> {
    const response = await this.request({ type: 'auth.pinStatus' });
    if (this.route.name !== 'pin') return;
    this.pinConfigured = response.ok && Boolean((response.data as { enabled?: boolean } | null)?.enabled);
  }

  private async handlePinSet(detail: PinSetDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.setPin', pin: detail.pin });
      if (!response.ok) {
        this.toolStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.pinConfigured = true;
      this.toolStatus = { message: 'PIN unlock enabled.', tone: 'success' };
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
      this.toolStatus = { message: 'PIN unlock removed.', tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleChangePassword(detail: ChangePasswordDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.changePassword', currentPassword: detail.currentPassword, newPassword: detail.newPassword });
      this.toolStatus = response.ok
        ? { message: 'Master password changed.', tone: 'success' }
        : { message: response.error.message, tone: 'danger' };
    } finally {
      this.pending = false;
    }
  }

  private async handleChangeKdf(detail: ChangeKdfDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.changeKdf', currentPassword: detail.currentPassword, iterations: detail.iterations });
      this.toolStatus = response.ok
        ? { message: `KDF iterations changed to ${detail.iterations}.`, tone: 'success' }
        : { message: response.error.message, tone: 'danger' };
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
      this.navigate(loginRoute('Encryption key rotated — please sign in again.'));
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

  /** Fetch the secret-stripped detail for the open item. Guards against a stale response arriving
   *  after the user has navigated to a different item. */
  private async loadDetail(id: string): Promise<void> {
    const response = await this.request({ type: 'vault.getCipherDetail', id });
    if (this.route.name !== 'detail' || this.route.cipherId !== id) return;
    this.detailCipher = response.ok
      ? ((response.data as { cipher: DecryptedCipher | null } | null)?.cipher ?? null)
      : null;
  }

  /** Build (memoized) the async loaders the detail invokes on explicit reveal. Every loader is a
   *  root closure — the detail never issues a worker request itself — and each surfaces its own
   *  error onto the shared status banner. */
  private detailExtras(id: string): DetailExtras {
    const mp = this.repromptMp(id);
    const key = `${id}|${mp === undefined ? '' : '1'}`;
    if (this.detailExtrasCache?.key === key) return this.detailExtrasCache.extras;
    const extras: DetailExtras = {
      getField: async (field) => {
        const response = await this.request(
          mp === undefined ? { type: 'vault.getField', id, field } : { type: 'vault.getField', id, field, masterPassword: mp },
        );
        if (!response.ok) {
          this.detailStatus = { message: response.error.message, tone: 'danger' };
          return { ok: false };
        }
        return { ok: true, value: (response.data as { value?: string }).value };
      },
      getCustomField: async (index) => {
        const response = await this.request(
          mp === undefined ? { type: 'vault.getCustomField', id, index } : { type: 'vault.getCustomField', id, index, masterPassword: mp },
        );
        if (!response.ok) {
          this.detailStatus = { message: response.error.message, tone: 'danger' };
          return { ok: false };
        }
        return { ok: true, value: (response.data as { value?: string }).value };
      },
      getTotp: async () => {
        const response = await this.request(
          mp === undefined ? { type: 'vault.getTotp', id } : { type: 'vault.getTotp', id, masterPassword: mp },
        );
        if (!response.ok) {
          this.detailStatus = { message: response.error.message, tone: 'danger' };
          return { ok: false };
        }
        return { ok: true, totp: (response.data as { totp: { code: string; period: number; remaining: number } | null }).totp };
      },
      getPasswordHistory: async () => {
        const response = await this.request(
          mp === undefined ? { type: 'vault.getPasswordHistory', id } : { type: 'vault.getPasswordHistory', id, masterPassword: mp },
        );
        if (!response.ok) {
          this.detailStatus = { message: response.error.message, tone: 'danger' };
          return { ok: false };
        }
        return { ok: true, history: (response.data as { history: Array<{ password: string; lastUsedDate?: string }> }).history };
      },
    };
    this.detailExtrasCache = { key, extras };
    return extras;
  }

  /** Verify the reprompt master password and, on success, hold it in the single private root field
   *  for this cipher only. Cleared on every navigation, disconnect, lock, account switch, and logout. */
  private async handleReprompt(id: string, password: string): Promise<void> {
    if (this.pending || !password) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.verifyMasterPassword', masterPassword: password });
      if (!response.ok) {
        this.repromptError = response.error.message;
        return;
      }
      if (!(response.data as { verified: boolean }).verified) {
        this.repromptError = 'Incorrect master password';
        return;
      }
      this.repromptCredential = { cipherId: id, masterPassword: password };
      this.repromptError = undefined;
      this.detailExtrasCache = undefined; // rebuild extras so they carry the newly-verified credential
      this.requestUpdate();
      // In the editor, the newly-verified credential unlocks the reprompt-gated editable plaintext.
      if (this.route.name === 'editor') void this.loadEditorInput(id);
    } finally {
      this.pending = false;
    }
  }

  /** Copy a plaintext value the detail already displays, then schedule the background clipboard clear. */
  private copyToClipboard(value: string, label: string): Promise<void> {
    return this.copy(value, label, (status) => { this.detailStatus = status; }, { toast: true });
  }

  private handleCopy(detail: CopyDetail): void {
    void this.copyToClipboard(detail.value, detail.label);
  }

  /** Fetch a masked secret and copy it straight to the clipboard — the plaintext never passes
   *  through the detail component. Keyed to the inline-expanded item in the vault list. */
  private async handleSecretRequest(detail: SecretRequestDetail): Promise<void> {
    const id = this.selectedCipherId;
    if (!id) return;
    const mp = this.repromptMp(id);
    const response = detail.kind === 'field'
      ? await this.request(mp === undefined ? { type: 'vault.getField', id, field: detail.field } : { type: 'vault.getField', id, field: detail.field, masterPassword: mp })
      : await this.request(mp === undefined ? { type: 'vault.getCustomField', id, index: detail.index } : { type: 'vault.getCustomField', id, index: detail.index, masterPassword: mp });
    if (!response.ok) {
      this.detailStatus = { message: response.error.message, tone: 'danger' };
      return;
    }
    const value = (response.data as { value?: string }).value;
    if (!value) {
      this.detailStatus = { message: `${detail.label} is empty`, tone: 'danger' };
      return;
    }
    await this.copyToClipboard(value, detail.label);
  }

  private async handleAttachmentDownload(detail: AttachmentRefDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.getAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId }
          : { type: 'vault.getAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId, masterPassword: mp },
      );
      if (!response.ok) {
        this.detailStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      const { fileName, dataB64 } = response.data as { fileName: string; dataB64: string };
      triggerDownload(dataB64, fileName);
      this.detailStatus = { message: `Downloaded ${fileName}`, tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleAttachmentAdd(detail: AttachmentAddDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.addAttachment', cipherId: detail.cipherId, fileName: detail.fileName, dataB64: detail.dataB64 }
          : { type: 'vault.addAttachment', cipherId: detail.cipherId, fileName: detail.fileName, dataB64: detail.dataB64, masterPassword: mp },
      );
      if (!response.ok) {
        this.detailStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      await this.loadDetail(detail.cipherId);
      this.detailStatus = { message: `Uploaded ${detail.fileName}`, tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleAttachmentDelete(detail: AttachmentRefDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'vault.deleteAttachment', cipherId: detail.cipherId, attachmentId: detail.attachmentId });
      if (!response.ok) {
        this.detailStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      await this.loadDetail(detail.cipherId);
      this.detailStatus = { message: `Deleted ${detail.fileName}`, tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleDeleteItem(detail: DeleteItemDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request(
        detail.permanent ? { type: 'vault.deleteCipher', id: detail.cipherId } : { type: 'vault.softDeleteCipher', id: detail.cipherId },
      );
      if (!response.ok) {
        this.detailStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  private async handleRestoreItem(detail: ItemRefDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'vault.restoreCipher', id: detail.cipherId });
      if (!response.ok) {
        this.detailStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  // --- Editor (dormant) orchestration -------------------------------------------------------

  /** Fetch the reprompt-gated editable plaintext for the item open in the editor. Guards against a
   *  stale response arriving after the user navigated away from that editor. */
  private async loadEditorInput(id: string): Promise<void> {
    const mp = this.repromptMp(id);
    const response = await this.request(
      mp === undefined ? { type: 'vault.getCipherInput', id } : { type: 'vault.getCipherInput', id, masterPassword: mp },
    );
    if (this.route.name !== 'editor' || this.route.cipherId !== id) return;
    if (!response.ok) {
      this.editorStatus = { message: response.error.message, tone: 'danger' };
      return;
    }
    const input = (response.data as { input: CipherInput | null }).input;
    if (!input) {
      this.editorStatus = { message: t('editor.typeUnsupported'), tone: 'danger' };
      return;
    }
    this.editorInput = input;
  }

  /** Persist the editor's validated `CipherInput` (create or update), then reload and return to the
   *  list. A failed request stays in the editor with the error surfaced on its own status banner. */
  private async handleEditorSave(input: CipherInput): Promise<void> {
    if (this.pending || this.route.name !== 'editor') return;
    const route = this.route;
    this.pending = true;
    try {
      const response = route.mode === 'edit' && route.cipherId !== undefined
        ? await this.request({ type: 'vault.updateCipher', id: route.cipherId, input })
        : await this.request({ type: 'vault.createCipher', input });
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  /** Assign an organization item to collections — a separate operation from the field save. Keeps the
   *  editor open (with the refreshed listing) so the user can continue editing. */
  private async handleCipherCollections(detail: CipherCollectionsDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'vault.setCipherCollections', id: detail.cipherId, collectionIds: detail.collectionIds });
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      this.editorStatus = { message: t('editor.collectionsUpdated'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  /** Move a personal item into an organization ("share") — a separate operation from both the field
   *  save and collection assignment. The worker fails closed on passkey/history items; the editor also
   *  guards these client-side. */
  private async handleEditorShare(detail: EditorShareDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const mp = this.repromptMp(detail.cipherId);
      const response = await this.request(
        mp === undefined
          ? { type: 'vault.shareCipher', id: detail.cipherId, organizationId: detail.organizationId, collectionIds: detail.collectionIds }
          : { type: 'vault.shareCipher', id: detail.cipherId, organizationId: detail.organizationId, collectionIds: detail.collectionIds, masterPassword: mp },
      );
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  /** Delete the item open in the editor (soft delete to trash, or permanent), then reload and return
   *  to the list. Errors stay local to the editor's status banner. */
  private async handleEditorDelete(detail: DeleteItemDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request(
        detail.permanent ? { type: 'vault.deleteCipher', id: detail.cipherId } : { type: 'vault.softDeleteCipher', id: detail.cipherId },
      );
      if (!response.ok) {
        this.editorStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.loadListing();
      this.navigate({ name: 'vault', scope: 'all' });
    } finally {
      this.pending = false;
    }
  }

  private renderLoading() {
    return html`<vw-status-message tone="info" .icon=${'refresh'} message="Loading vault…"></vw-status-message>`;
  }

  private renderAuth(route: AuthRoute) {
    const providers = route.name === 'twoFactor' ? route.providers : [];
    const error = 'error' in route ? route.error : undefined;
    return html`
      <vw-auth-views
        .mode=${route.name}
        .error=${error}
        .pending=${this.pending}
        .providers=${providers}
        .pinEnabled=${this.pinEnabled}
        .deviceRemembered=${this.deviceRemembered}
        .deviceForgotten=${this.deviceForgotten}
        @vw-auth-login-submit=${(event: CustomEvent<LoginSubmitDetail>) => void this.handleLoginSubmit(event.detail)}
        @vw-auth-register-submit=${(event: CustomEvent<RegisterSubmitDetail>) => void this.handleRegisterSubmit(event.detail)}
        @vw-auth-two-factor-submit=${(event: CustomEvent<TwoFactorSubmitDetail>) => void this.handleTwoFactorSubmit(event.detail)}
        @vw-auth-unlock-submit=${(event: CustomEvent<UnlockSubmitDetail>) => void this.handleUnlockSubmit(event.detail)}
        @vw-auth-pin-unlock-submit=${(event: CustomEvent<PinUnlockSubmitDetail>) => void this.handlePinUnlockSubmit(event.detail)}
        @vw-auth-email-change=${(event: CustomEvent<EmailChangeDetail>) => void this.handleEmailChange(event.detail.email)}
        @vw-auth-forget-device=${() => void this.handleForgetDevice()}
        @vw-auth-send-email-code=${() => void this.handleSendEmailCode()}
        @vw-auth-go-register=${() => this.navigate({ name: 'register' })}
        @vw-auth-back-to-login=${() => this.navigate(loginRoute())}
        @vw-auth-open-settings=${() => void this.browser.openOptions()}
        @vw-auth-logout=${() => void this.handleLogout()}
      ></vw-auth-views>
    `;
  }

  private renderUnlocked(route: PopupRoute) {
    return html`
      <vw-popup-header
        .generatorActive=${route.name === 'generator'}
        .totpActive=${route.name === 'totp'}
        @vw-add=${() => this.navigate({ name: 'editor', mode: 'create' })}
        @vw-open-totp=${() => this.handleTotpToggle()}
        @vw-generator-toggle=${() => this.handleGeneratorToggle()}
        @vw-open-settings=${() => void this.browser.openOptions()}
        @vw-lock=${() => void this.handleAccountAction({ action: 'lock' })}
      ></vw-popup-header>
      <div class="body">${this.renderBody(route)}</div>
      <vw-sync-bar
        .syncing=${this.syncing}
        .lastSync=${this.lastSync}
        @vw-sync-now=${() => void this.handleSync()}
      ></vw-sync-bar>
    `;
  }

  private renderBody(route: PopupRoute) {
    switch (route.name) {
      case 'generator':
        return this.renderGenerator();
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
      case 'pin':
        return this.renderPin();
      default:
        return this.renderVault();
    }
  }

  /** The single-column vault: search + category chips + list with inline-expanding detail cards. */
  private renderVault() {
    const extras = this.selectedCipherId ? this.detailExtras(this.selectedCipherId) : undefined;
    return html`
      <vw-vault-view
        .items=${this.items}
        .suggestionsState=${this.suggestionsState}
        .query=${this.query}
        .category=${this.category}
        .selectedCipherId=${this.selectedCipherId}
        .extras=${extras}
        @vw-search-change=${(event: CustomEvent<{ query: string }>) => { this.query = event.detail.query; }}
        @vw-category-change=${(event: CustomEvent<{ category: CategoryId }>) => this.handleCategoryChange(event.detail.category)}
        @vw-item-toggle=${(event: CustomEvent<{ cipherId: string }>) => this.handleItemToggle(event.detail.cipherId)}
        @vw-suggestion-fill=${(event: CustomEvent<SuggestionFillDetail>) => void this.handleSuggestionFill(event.detail)}
        @vw-item-fill=${(event: CustomEvent<{ cipherId: string }>) => void this.handleItemFill(event.detail.cipherId)}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => this.handleCopy(event.detail)}
        @vw-secret-request=${(event: CustomEvent<SecretRequestDetail>) => void this.handleSecretRequest(event.detail)}
        @vw-edit-item=${(event: CustomEvent<ItemRefDetail>) => this.navigate({ name: 'editor', mode: 'edit', cipherId: event.detail.cipherId })}
      ></vw-vault-view>
    `;
  }

  private renderEditor(route: Extract<PopupRoute, { name: 'editor' }>) {
    // Step one of "add item": no type chosen yet → show the type picker.
    if (route.mode === 'create' && route.cipherType === undefined) {
      return html`
        <vw-type-picker
          @vw-editor-type=${(event: CustomEvent<EditorTypeDetail>) => this.navigate({ name: 'editor', mode: 'create', cipherType: event.detail.type })}
          @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'suggestions' })}
        ></vw-type-picker>
      `;
    }
    const summary = route.cipherId !== undefined ? this.items.find((item) => item.id === route.cipherId) : undefined;
    if (route.mode === 'edit' && route.cipherId !== undefined) {
      const id = route.cipherId;
      if (!summary) {
        return html`<vw-status-message tone="warning" .icon=${'alert'} message="This item is no longer available."></vw-status-message>`;
      }
      // A protected item must clear the master-password gate before the editor reveals its plaintext.
      if (summary.reprompt && this.repromptCredential?.cipherId !== id) {
        return html`
          <vw-reprompt-gate
            .name=${summary.name}
            .pending=${this.pending}
            .error=${this.repromptError}
            @vw-reprompt-submit=${(event: CustomEvent<RepromptSubmitDetail>) => void this.handleReprompt(id, event.detail.password)}
            @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'all' })}
          ></vw-reprompt-gate>
        `;
      }
      if (!this.editorInput) return this.renderLoading();
    }
    const type = route.mode === 'create' ? route.cipherType : this.editorInput?.type;
    if (type === undefined) return this.renderLoading();
    const context: EditorContext = {
      mode: route.mode,
      type,
      ...(route.cipherId !== undefined ? { cipherId: route.cipherId } : {}),
      ...(this.editorInput ? { input: this.editorInput } : {}),
      folders: this.folders,
      collections: this.collections,
      orgPermissions: this.orgPermissions,
    };
    return html`
      <vw-cipher-editor
        .context=${context}
        .summary=${summary}
        .pending=${this.pending}
        .status=${this.editorStatus}
        @vw-editor-save=${(event: CustomEvent<CipherInput>) => void this.handleEditorSave(event.detail)}
        @vw-cipher-collections=${(event: CustomEvent<CipherCollectionsDetail>) => void this.handleCipherCollections(event.detail)}
        @vw-editor-share=${(event: CustomEvent<EditorShareDetail>) => void this.handleEditorShare(event.detail)}
        @vw-delete-item=${(event: CustomEvent<DeleteItemDetail>) => void this.handleEditorDelete(event.detail)}
        @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'all' })}
      ></vw-cipher-editor>
    `;
  }

  private renderGenerator() {
    return html`
      <vw-generator-view
        .history=${this.generatorHistory}
        .accountEmail=${this.activeAccountEmail()}
        @vw-history-add=${(event: CustomEvent<GeneratorHistoryAddDetail>) => this.handleGeneratorHistoryAdd(event.detail)}
        @vw-history-clear=${() => { this.generatorHistory = []; }}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => void this.copyToolValue(event.detail.value, event.detail.label)}
        @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'suggestions' })}
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
        @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-health-view>
    `;
  }

  private renderTotp() {
    return html`
      <vw-totp-view
        .entries=${this.totpEntries}
        .currentIds=${this.currentSiteIds()}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => this.handleCopy(event.detail)}
      ></vw-totp-view>
    `;
  }

  private renderSends() {    return html`
      <vw-sends-view
        .sends=${this.sendsState}
        .pending=${this.pending}
        .status=${this.toolStatus}
        @vw-send-create=${(event: CustomEvent<SendCreateDetail>) => void this.handleSendCreate(event.detail)}
        @vw-send-update=${(event: CustomEvent<SendUpdateDetail>) => void this.handleSendUpdate(event.detail)}
        @vw-send-delete=${(event: CustomEvent<SendDeleteDetail>) => void this.handleSendDelete(event.detail)}
        @vw-copy=${(event: CustomEvent<CopyDetail>) => void this.copyToolValue(event.detail.value, event.detail.label)}
        @vw-send-receive=${() => void this.browser.openReceive()}
        @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'suggestions' })}
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
        @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-account-security-view>
    `;
  }

  private renderPin() {
    return html`
      <vw-pin-view
        .enabled=${this.pinConfigured}
        .pending=${this.pending}
        .status=${this.toolStatus}
        @vw-pin-set=${(event: CustomEvent<PinSetDetail>) => void this.handlePinSet(event.detail)}
        @vw-pin-remove=${() => void this.handlePinRemove()}
        @vw-item-back=${() => this.navigate({ name: 'vault', scope: 'suggestions' })}
      ></vw-pin-view>
    `;
  }

  protected override render() {
    const route = this.route;
    const isAuth =
      route.name === 'loading' ||
      route.name === 'login' ||
      route.name === 'register' ||
      route.name === 'twoFactor' ||
      route.name === 'unlock';
    return html`
      <vw-popup-frame>
        ${isAuth
          ? route.name === 'loading'
            ? this.renderLoading()
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

customElements.define('vw-popup-app', VwPopupApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-app': VwPopupApp;
  }
}
