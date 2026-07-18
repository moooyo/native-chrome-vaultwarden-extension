import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import type { SessionState, AccountSummary } from '../../core/session/session-manager.js';
import type { SendSummary } from '../../core/vault/sends.js';
import type { AsyncState } from '../components/async-state.js';
import { initLocale, t } from '../i18n/index.js';
import { initAppearance } from '../theme.js';
import { initPrefs } from '../prefs.js';
import './options-shell.js';
import type { OptionsNavItem } from './options-shell.js';
import './sections/connection-section.js';
import './sections/security-section.js';
import './sections/autofill-section.js';
import './sections/generator-section.js';
import './sections/send-section.js';
import './sections/appearance-section.js';
import './sections/data-section.js';
import './sections/about-section.js';
import type {
  AutofillSaveDetail,
  ChangePasswordDetail,
  ConnectionSaveDetail,
  ExportDetail,
  ImportFileDetail,
  ImportPasswordDetail,
  LoadedSettings,
  LockTimeoutSaveDetail,
  OptionsDeps,
  OptionsSectionId,
  SecuritySaveDetail,
  SectionStatus,
  SendCreateDetail,
  SendDeleteDetail,
} from './types.js';

const RAIL: OptionsNavItem[] = [
  { id: 'account', labelKey: 'options.nav.account', icon: 'user' },
  { id: 'security', labelKey: 'options.nav.security', icon: 'lock' },
  { id: 'autofill', labelKey: 'options.nav.autofill', icon: 'key' },
  { id: 'generator', labelKey: 'options.nav.generator', icon: 'wand' },
  { id: 'send', labelKey: 'options.nav.send', icon: 'link' },
  { id: 'appearance', labelKey: 'options.nav.appearance', icon: 'sun' },
  { id: 'data', labelKey: 'options.nav.data', icon: 'file' },
  { id: 'about', labelKey: 'options.nav.about', icon: 'alert' },
];

function isPasswordProtectedExport(content: string): boolean {
  return /"encrypted"\s*:\s*true/.test(content) && /"passwordProtected"\s*:\s*true/.test(content);
}

function createDefaultDeps(): OptionsDeps {
  return {
    request: sendRequest,
    async requestOrigins(origins) {
      return browser.permissions.request({ origins });
    },
    downloadText(content, fileName) {
      const url = URL.createObjectURL(new Blob([content], { type: 'application/json' }));
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = fileName;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    },
    async readFile(file) {
      return file.text();
    },
    extensionVersion() {
      return browser.runtime.getManifest().version;
    },
  };
}

/**
 * The MiYu options root. Owns loaded settings, the active section, vault lock state, the single
 * in-flight `pending` flag, per-section status banners, the Sends list, and the account identity for
 * the sidebar. Performs every worker request via the injectable `deps` and hands plain props to the
 * section components, reacting to their typed events. Appearance (theme/language/density) and the
 * UI-local preference toggles are managed by their sections directly via the appearance/prefs
 * modules, so they need no root handler.
 *
 * Connection/account is the sole section that can lead to a host-permission prompt: its save handler
 * requests the origin synchronously in the submit gesture (first await) before persisting.
 */
export class VwOptionsApp extends LitElement {
  static override properties = {
    selected: { type: String },
    settings: { attribute: false },
    locked: { type: Boolean },
    pending: { type: Boolean },
    awaitingImportPassword: { type: Boolean },
    connectionStatus: { attribute: false },
    securityStatus: { attribute: false },
    autofillStatus: { attribute: false },
    dataStatus: { attribute: false },
    aboutStatus: { attribute: false },
    sendsState: { attribute: false },
    sendStatus: { attribute: false },
    accountEmail: { type: String },
    accountName: { type: String },
    lastSync: { type: Number },
    syncing: { type: Boolean },
  };

  declare selected: OptionsSectionId;
  declare settings: LoadedSettings | undefined;
  declare locked: boolean;
  declare pending: boolean;
  declare awaitingImportPassword: boolean;
  declare connectionStatus: SectionStatus | undefined;
  declare securityStatus: SectionStatus | undefined;
  declare autofillStatus: SectionStatus | undefined;
  declare dataStatus: SectionStatus | undefined;
  declare aboutStatus: SectionStatus | undefined;
  declare sendsState: AsyncState<SendSummary[]>;
  declare sendStatus: SectionStatus | undefined;
  declare accountEmail: string;
  declare accountName: string;
  declare lastSync: number | undefined;
  declare syncing: boolean;

  deps: OptionsDeps = createDefaultDeps();

  private pendingImportContent: string | undefined;

  constructor() {
    super();
    this.selected = 'account';
    this.settings = undefined;
    this.locked = true;
    this.pending = false;
    this.awaitingImportPassword = false;
    this.connectionStatus = undefined;
    this.securityStatus = undefined;
    this.autofillStatus = undefined;
    this.dataStatus = undefined;
    this.aboutStatus = undefined;
    this.sendsState = { status: 'idle' };
    this.sendStatus = undefined;
    this.accountEmail = '';
    this.accountName = '';
    this.lastSync = undefined;
    this.syncing = false;
    this.pendingImportContent = undefined;
  }

  static override styles = css`
    :host { display: block; min-height: 100vh; }
  `;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.bootstrap();
  }

  private async bootstrap(): Promise<void> {
    await Promise.all([initLocale(), initAppearance(), initPrefs()]);
    await this.init();
  }

  private async init(): Promise<void> {
    const stateResponse = await this.deps.request({ type: 'auth.getState' });
    this.locked = stateResponse.ok ? (stateResponse.data as { state: SessionState }).state !== 'unlocked' : true;
    const settingsResponse = await this.deps.request({ type: 'settings.get' });
    if (settingsResponse.ok) this.settings = settingsResponse.data as LoadedSettings;
    const accountsResponse = await this.deps.request({ type: 'auth.listAccounts' });
    if (accountsResponse.ok) {
      const accounts = (accountsResponse.data as { accounts?: AccountSummary[] } | null)?.accounts ?? [];
      const active = accounts.find((a) => (a as { active?: boolean }).active) ?? accounts[0];
      this.accountEmail = active?.email ?? '';
      this.accountName = (active as { name?: string } | undefined)?.name ?? '';
    }
    if (!this.locked) void this.loadSends();
  }

  private onNav(event: CustomEvent<{ id: string }>): void {
    const id = event.detail.id;
    if (RAIL.some((item) => item.id === id)) this.selected = id as OptionsSectionId;
  }

  // --- account & sync ------------------------------------------------------------------------
  private async handleConnectionSave(event: CustomEvent<ConnectionSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = event.detail.serverUrl;
    const originPattern = `${new URL(serverUrl).origin}/*`;
    this.pending = true;
    this.connectionStatus = undefined;
    try {
      const granted = await this.deps.requestOrigins([originPattern]);
      if (!granted) {
        this.connectionStatus = { message: t('common.error'), tone: 'danger' };
        return;
      }
      const response = await this.deps.request({ type: 'settings.save', serverUrl });
      if (!response.ok) {
        this.connectionStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) this.settings = { ...this.settings, serverUrl };
      this.connectionStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleSync(): Promise<void> {
    if (this.syncing) return;
    this.syncing = true;
    try {
      const response = await this.deps.request({ type: 'vault.sync' });
      if (response.ok) this.lastSync = Date.now();
      else this.connectionStatus = { message: response.error.message, tone: 'danger' };
    } finally {
      this.syncing = false;
    }
  }

  // --- security ------------------------------------------------------------------------------
  private async handleAutofillSave(event: CustomEvent<AutofillSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = this.settings?.serverUrl;
    if (serverUrl === undefined) {
      this.autofillStatus = { message: t('options.account.serverDesc'), tone: 'danger' };
      return;
    }
    this.pending = true;
    this.autofillStatus = undefined;
    try {
      const response = await this.deps.request({
        type: 'settings.save',
        serverUrl,
        defaultUriMatchStrategy: event.detail.defaultUriMatchStrategy,
      });
      if (!response.ok) {
        this.autofillStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) this.settings = { ...this.settings, defaultUriMatchStrategy: event.detail.defaultUriMatchStrategy };
      this.autofillStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleLockTimeoutSave(event: CustomEvent<LockTimeoutSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = this.settings?.serverUrl;
    if (serverUrl === undefined) {
      this.securityStatus = { message: t('options.account.serverDesc'), tone: 'danger' };
      return;
    }
    this.pending = true;
    this.securityStatus = undefined;
    try {
      const response = await this.deps.request({ type: 'settings.save', serverUrl, lockTimeout: event.detail.lockTimeout });
      if (!response.ok) {
        this.securityStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) this.settings = { ...this.settings, lockTimeout: event.detail.lockTimeout };
      this.securityStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleSecuritySave(event: CustomEvent<SecuritySaveDetail>): Promise<void> {
    this.securityStatus = undefined;
    const response = await this.deps.request({
      type: 'settings.saveSecurity',
      onIdleAction: event.detail.onIdleAction,
      clipboardClearSeconds: event.detail.clipboardClearSeconds,
    });
    if (!response.ok) {
      this.securityStatus = { message: response.error.message, tone: 'danger' };
      return;
    }
    if (this.settings) {
      this.settings = { ...this.settings, onIdleAction: event.detail.onIdleAction, clipboardClearSeconds: event.detail.clipboardClearSeconds };
    }
  }

  private async handleChangePassword(event: CustomEvent<ChangePasswordDetail>): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    this.securityStatus = undefined;
    try {
      const response = await this.deps.request({
        type: 'auth.changePassword',
        currentPassword: event.detail.currentPassword,
        newPassword: event.detail.newPassword,
      });
      this.securityStatus = response.ok
        ? { message: t('common.done'), tone: 'success' }
        : { message: response.error.message, tone: 'danger' };
    } finally {
      this.pending = false;
    }
  }

  // --- Send ----------------------------------------------------------------------------------
  private async loadSends(): Promise<void> {
    this.sendsState = { status: 'loading' };
    const response = await this.deps.request({ type: 'sends.list' });
    if (!response.ok) {
      this.sendsState = { status: 'error', message: response.error.message };
      return;
    }
    const sends = (response.data as { sends?: SendSummary[] } | null)?.sends ?? [];
    this.sendsState = sends.length > 0 ? { status: 'ready', data: sends } : { status: 'empty' };
  }

  private async handleSendCreate(event: CustomEvent<SendCreateDetail>): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    this.sendStatus = undefined;
    try {
      const detail = event.detail;
      const response = detail.kind === 'text'
        ? await this.deps.request({ type: 'sends.createText', input: detail.input })
        : await this.deps.request({ type: 'sends.createFile', input: detail.input, dataB64: detail.dataB64, fileName: detail.fileName });
      if (!response.ok) {
        this.sendStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      const send = (response.data as { send?: SendSummary } | null)?.send;
      if (send) {
        await this.copyToClipboard(send.url);
        this.sendStatus = { message: t('options.send.linkCopied'), tone: 'success' };
      }
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleSendDelete(event: CustomEvent<SendDeleteDetail>): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.deps.request({ type: 'sends.delete', id: event.detail.id });
      if (!response.ok) this.sendStatus = { message: response.error.message, tone: 'danger' };
      else await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleCopy(event: CustomEvent<{ value: string }>): Promise<void> {
    await this.copyToClipboard(event.detail.value);
    this.sendStatus = { message: t('options.send.linkCopied'), tone: 'success' };
  }

  private async copyToClipboard(value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      void this.deps.request({ type: 'clipboard.scheduleClear' });
    } catch {
      /* clipboard unavailable */
    }
  }

  // --- data ----------------------------------------------------------------------------------
  private async handleExport(event: CustomEvent<ExportDetail>): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    this.dataStatus = undefined;
    try {
      const password = event.detail.password;
      const response = await this.deps.request(password === undefined ? { type: 'vault.export' } : { type: 'vault.export', password });
      if (!response.ok) {
        this.dataStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      const json = (response.data as { json: string }).json;
      const fileName = `miyu-export-${password === undefined ? '' : 'encrypted-'}vault.json`;
      this.deps.downloadText(json, fileName);
      this.dataStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleImportFile(event: CustomEvent<ImportFileDetail>): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    this.dataStatus = undefined;
    this.awaitingImportPassword = false;
    this.pendingImportContent = undefined;
    try {
      let content: string;
      try {
        content = await this.deps.readFile(event.detail.file);
      } catch {
        this.dataStatus = { message: t('common.error'), tone: 'danger' };
        return;
      }
      if (isPasswordProtectedExport(content)) {
        this.pendingImportContent = content;
        this.awaitingImportPassword = true;
        return;
      }
      await this.runImport(content);
    } finally {
      this.pending = false;
    }
  }

  private async handleImportPassword(event: CustomEvent<ImportPasswordDetail>): Promise<void> {
    if (this.pending) return;
    const content = this.pendingImportContent;
    if (content === undefined) return;
    this.pending = true;
    this.dataStatus = undefined;
    try {
      await this.runImport(content, event.detail.password);
    } finally {
      this.pending = false;
    }
  }

  private async runImport(content: string, password?: string): Promise<void> {
    const response = await this.deps.request(password === undefined ? { type: 'vault.import', content } : { type: 'vault.import', content, password });
    if (!response.ok) {
      this.dataStatus = { message: response.error.message, tone: 'danger' };
      return;
    }
    const imported = (response.data as { imported: number }).imported;
    this.awaitingImportPassword = false;
    this.pendingImportContent = undefined;
    this.dataStatus = { message: t('options.data.imported', { count: imported }), tone: 'success' };
  }

  private async handleDeleteLocal(): Promise<void> {
    if (this.pending) return;
    // Removing local data signs the account out on this device; the cloud vault is untouched.
    if (typeof window !== 'undefined' && !window.confirm(t('options.data.deleteLocalDesc'))) return;
    this.pending = true;
    try {
      await this.deps.request({ type: 'auth.logout' });
      this.locked = true;
      this.dataStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private handleCheckUpdate(): void {
    this.aboutStatus = { message: t('options.about.upToDate'), tone: 'info' };
  }

  /** Signs the account out from the sidebar footer control: clears the session on this device and
   *  drops the local account identity. The cloud vault is untouched. Guarded by a confirm, since
   *  re-authenticating a self-hosted vault means re-entering the server URL and credentials. */
  private async handleLogout(): Promise<void> {
    if (this.pending) return;
    if (typeof window !== 'undefined' && !window.confirm(t('options.footer.logoutConfirm'))) return;
    this.pending = true;
    try {
      await this.deps.request({ type: 'auth.logout' });
      this.locked = true;
      this.accountEmail = '';
      this.accountName = '';
    } finally {
      this.pending = false;
    }
  }

  private async handleLockNow(): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.deps.request({ type: 'auth.lock' });
      if (response.ok) this.locked = true;
      else this.securityStatus = { message: response.error.message, tone: 'danger' };
    } finally {
      this.pending = false;
    }
  }

  // --- render --------------------------------------------------------------------------------
  private renderSection() {
    switch (this.selected) {
      case 'account':
        return html`<vw-connection-section
          .serverUrl=${this.settings?.serverUrl ?? ''}
          .accountEmail=${this.accountEmail}
          .accountName=${this.accountName}
          .lastSync=${this.lastSync}
          .syncing=${this.syncing}
          ?pending=${this.pending}
          .status=${this.connectionStatus}
        ></vw-connection-section>`;
      case 'security':
        return html`<vw-security-section
          .lockTimeout=${this.settings?.lockTimeout ?? '15'}
          .onIdleAction=${this.settings?.onIdleAction ?? 'lock'}
          .clipboardClearSeconds=${this.settings?.clipboardClearSeconds ?? '60'}
          ?pending=${this.pending}
          .status=${this.securityStatus}
        ></vw-security-section>`;
      case 'autofill':
        return html`<vw-autofill-section
          .defaultUriMatchStrategy=${this.settings?.defaultUriMatchStrategy ?? 0}
          ?pending=${this.pending}
          .status=${this.autofillStatus}
        ></vw-autofill-section>`;
      case 'generator':
        return html`<vw-generator-section></vw-generator-section>`;
      case 'send':
        return html`<vw-send-section
          .sends=${this.sendsState}
          ?locked=${this.locked}
          ?pending=${this.pending}
          .status=${this.sendStatus}
        ></vw-send-section>`;
      case 'appearance':
        return html`<vw-appearance-section></vw-appearance-section>`;
      case 'data':
        return html`<vw-data-section
          ?locked=${this.locked}
          ?pending=${this.pending}
          .awaitingImportPassword=${this.awaitingImportPassword}
          .status=${this.dataStatus}
        ></vw-data-section>`;
      case 'about':
        return html`<vw-about-section .version=${this.deps.extensionVersion()} .status=${this.aboutStatus}></vw-about-section>`;
    }
  }

  protected override render() {
    return html`
      <vw-options-shell
        .items=${RAIL}
        .selected=${this.selected}
        .version=${this.deps.extensionVersion()}
        @vw-nav-change=${(e: CustomEvent<{ id: string }>) => this.onNav(e)}
        @vw-logout=${() => void this.handleLogout()}
        @vw-connection-save=${(e: CustomEvent<ConnectionSaveDetail>) => void this.handleConnectionSave(e)}
        @vw-sync-now=${() => void this.handleSync()}
        @vw-autofill-save=${(e: CustomEvent<AutofillSaveDetail>) => void this.handleAutofillSave(e)}
        @vw-lock-timeout-save=${(e: CustomEvent<LockTimeoutSaveDetail>) => void this.handleLockTimeoutSave(e)}
         @vw-security-save=${(e: CustomEvent<SecuritySaveDetail>) => void this.handleSecuritySave(e)}
         @vw-lock-now=${() => void this.handleLockNow()}
        @vw-change-password=${(e: CustomEvent<ChangePasswordDetail>) => void this.handleChangePassword(e)}
        @vw-send-create=${(e: CustomEvent<SendCreateDetail>) => void this.handleSendCreate(e)}
        @vw-send-delete=${(e: CustomEvent<SendDeleteDetail>) => void this.handleSendDelete(e)}
        @vw-copy=${(e: CustomEvent<{ value: string }>) => void this.handleCopy(e)}
        @vw-export=${(e: CustomEvent<ExportDetail>) => void this.handleExport(e)}
        @vw-import-file=${(e: CustomEvent<ImportFileDetail>) => void this.handleImportFile(e)}
        @vw-import-password=${(e: CustomEvent<ImportPasswordDetail>) => void this.handleImportPassword(e)}
        @vw-delete-local=${() => void this.handleDeleteLocal()}
        @vw-check-update=${() => this.handleCheckUpdate()}
      >
        ${this.renderSection() ?? nothing}
      </vw-options-shell>
    `;
  }
}

customElements.define('vw-options-app', VwOptionsApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-options-app': VwOptionsApp;
  }
}
