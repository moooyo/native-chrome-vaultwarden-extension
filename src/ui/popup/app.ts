import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import { sendRequest, type ResponseMessage } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { SessionState } from '../../core/session/session-manager.js';
import type { CipherSummary, CollectionSummary, FolderSummary } from '../../core/vault/models.js';
import type { OrgPermission } from '../../core/vault/org-permissions.js';
import type { TabFillOutcome, TabSuggestionsOutcome } from '../../messaging/protocol.js';
import { themeTokens } from '../components/tokens.js';
import '../components/status-message.js';
import './auth/auth-views.js';
import './vault/popup-header.js';
import './vault/vault-view.js';
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
  CollectionMutateDetail,
  FillResult,
  FilterChangeDetail,
  FolderMutateDetail,
  ItemOpenDetail,
  PopupBrowser,
  PopupRequest,
  PopupRoute,
  SuggestionFillDetail,
  SuggestionsViewState,
  ToolActionDetail,
} from './types.js';

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
    fillResult: { attribute: false },
    accounts: { attribute: false },
    pinConfigured: { type: Boolean },
    vaultDeviceRemembered: { type: Boolean },
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
  declare fillResult: FillResult;
  declare accounts: AccountInfo[];
  declare pinConfigured: boolean;
  declare vaultDeviceRemembered: boolean;

  /** Injectable worker request function; defaults to the real messaging channel. */
  request: PopupRequest = sendRequest;

  /** Injectable browser seam; defaults to the real `webextension-polyfill`-backed implementation. */
  browser: PopupBrowser = createDefaultBrowser();

  /** The email last checked/shown by the login screen's remembered-device banner. */
  private deviceCheckEmail = '';

  /** Active TOTP countdown interval for an open login detail. Dormant in this task (no detail
   *  view exists yet) — reserved for the task that adds it; `navigate()` always clears it. */
  private totpTimer: number | undefined;

  /** Master-password reprompt credential, held only for the duration of a reprompt-gated item's
   *  detail/editor view. Dormant in this task (no detail view sets it yet) — reserved for the
   *  task that adds it; `navigate()` and `disconnectedCallback()` always clear it. */
  private repromptCredential: { cipherId: string; masterPassword: string } | null = null;

  /** The active tab whose Suggestions are currently shown; the Fill target for `handleSuggestionFill`.
   *  Re-resolved on every vault entry — the popup never trusts a remembered tab across sessions. */
  private activeTabId: number | undefined;

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
    this.fillResult = {};
    this.accounts = [];
    this.pinConfigured = false;
    this.vaultDeviceRemembered = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host {
        display: block;
        min-width: 320px;
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    void this.init();
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
    this.repromptCredential = null;
  }

  /** Assigns the next route, clearing per-view ephemeral state that must not survive a
   *  navigation: the TOTP timer, the reprompt credential, and (when leaving their owning view)
   *  the remembered-device banner and PIN availability flag. */
  navigate(route: PopupRoute): void {
    this.clearEphemeralDetailState();
    this.route = route;
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
      if (this.route.name === 'twoFactor') {
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
      if (!response.ok && this.route.name === 'twoFactor') {
        this.navigate(twoFactorRoute(this.route.providers, response.error.message));
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
    this.suggestionsState = { status: 'loading' };
    const tabId = await this.browser.getActiveTabId();
    if (this.route.name !== 'vault') return; // navigated away while resolving the tab
    if (tabId === undefined) {
      this.activeTabId = undefined;
      this.suggestionsState = { status: 'unavailable', reason: 'no_eligible_tab' };
      return;
    }
    this.activeTabId = tabId;
    const response = await this.request({ type: 'autofill.getTabSuggestions', tabId });
    if (this.route.name !== 'vault') return;
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
    if (id === 'suggestions' || id === 'all') this.navigate({ name: 'vault', scope: id });
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
    this.fillResult = {};
    this.activeTabId = undefined;
  }

  private async handleAccountAction(detail: AccountActionDetail): Promise<void> {
    switch (detail.action) {
      case 'switch-account':
        if (detail.email !== undefined) {
          const response = await this.request({ type: 'auth.switchAccount', email: detail.email });
          if (response.ok) await this.reRouteFromState();
        }
        return;
      case 'remove-account':
        if (detail.email !== undefined) {
          const response = await this.request({ type: 'auth.removeAccount', email: detail.email });
          if (response.ok) await this.reRouteFromState();
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
        const response = await this.request({ type: 'auth.lock' });
        if (response.ok) this.navigate(unlockRoute());
        else this.navigate({ name: 'vault', scope: 'suggestions', error: response.error.message });
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
          const response = await this.request({ type: 'vault.sync' });
          if (response.ok) {
            this.applyListingResponse(response);
            await this.loadSuggestions();
          }
        } finally {
          this.pending = false;
        }
        return;
      }
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
        @vw-auth-logout=${() => void this.handleLogout()}
      ></vw-auth-views>
    `;
  }

  private renderVault(route: Extract<PopupRoute, { name: 'vault' }>) {
    return html`
      <vw-popup-header
        .accounts=${this.accounts}
        .pinEnabled=${this.pinConfigured}
        .deviceRemembered=${this.vaultDeviceRemembered}
        @vw-add=${() => this.navigate({ name: 'editor', mode: 'create' })}
        @vw-generator=${() => this.navigate({ name: 'generator' })}
        @vw-account-action=${(event: CustomEvent<AccountActionDetail>) => void this.handleAccountAction(event.detail)}
        @vw-tool-action=${(event: CustomEvent<ToolActionDetail>) => void this.handleToolAction(event.detail)}
      ></vw-popup-header>
      <vw-vault-view
        .scope=${route.scope}
        .suggestionsState=${this.suggestionsState}
        .fill=${this.fillResult}
        .items=${this.items}
        .folders=${this.folders}
        .collections=${this.collections}
        .orgPermissions=${this.orgPermissions}
        .selectedFolderId=${this.selectedFolderId}
        .selectedCollectionId=${this.selectedCollectionId}
        .query=${this.query}
        .showTrash=${this.showTrash}
        .skippedOrgCount=${this.skippedOrgCount}
        @vw-tab-change=${(event: CustomEvent<{ id: string }>) => this.handleScopeChange(event.detail.id)}
        @vw-suggestion-fill=${(event: CustomEvent<SuggestionFillDetail>) => void this.handleSuggestionFill(event.detail)}
        @vw-item-open=${(event: CustomEvent<ItemOpenDetail>) => this.navigate({ name: 'detail', cipherId: event.detail.cipherId })}
        @vw-filter-change=${(event: CustomEvent<FilterChangeDetail>) => this.applyFilterPatch(event.detail)}
        @vw-folder-mutate=${(event: CustomEvent<FolderMutateDetail>) => void this.handleFolderMutate(event.detail)}
        @vw-collection-mutate=${(event: CustomEvent<CollectionMutateDetail>) => void this.handleCollectionMutate(event.detail)}
      ></vw-vault-view>
    `;
  }

  protected override render() {
    const route = this.route;
    switch (route.name) {
      case 'loading':
        return this.renderLoading();
      case 'login':
      case 'register':
      case 'twoFactor':
      case 'unlock':
        return this.renderAuth(route);
      case 'vault':
        return this.renderVault(route);
      default:
        // Detail/editor/generator/health/sends/accountSecurity/pin views are added by later tasks;
        // this root only routes to them for now.
        return nothing;
    }
  }
}

customElements.define('vw-popup-app', VwPopupApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-app': VwPopupApp;
  }
}
