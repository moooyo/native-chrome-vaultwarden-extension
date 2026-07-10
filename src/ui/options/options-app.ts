import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import type { SessionState } from '../../core/session/session-manager.js';
import { themeTokens } from '../components/tokens.js';
import { controlStyles } from '../components/styles.js';
import type { SettingsRailItem } from '../components/page-shell.js';
import '../components/page-shell.js';
import './sections/connection-section.js';
import './sections/security-section.js';
import './sections/autofill-section.js';
import './sections/data-section.js';
import './sections/about-section.js';
import type {
  AutofillSaveDetail,
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
} from './types.js';

const RAIL: SettingsRailItem[] = [
  { id: 'connection', label: 'Connection', icon: 'globe' },
  { id: 'security', label: 'Security', icon: 'lock' },
  { id: 'autofill', label: 'Autofill', icon: 'key' },
  { id: 'data', label: 'Data', icon: 'note' },
  { id: 'about', label: 'About', icon: 'shield' },
];

const NARROW_QUERY = '(max-width: 640px)';

/** A password-protected Bitwarden export is a JSON document flagged both encrypted and
 *  password-protected; anything else (plain JSON, CSV) imports without a password. */
function isPasswordProtectedExport(content: string): boolean {
  return /"encrypted"\s*:\s*true/.test(content) && /"passwordProtected"\s*:\s*true/.test(content);
}

/** The real dependency seam, backed by `webextension-polyfill` and the DOM. */
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
 * The dormant Lit options root. It owns the loaded settings, the active rail section, the vault
 * lock state, a single in-flight `pending` flag, and per-section status banners. It performs every
 * worker request itself (via the injectable `deps`) and hands only plain props to the section
 * components, reacting to their typed events.
 *
 * Connection is the sole section that leads to a host-permission prompt: its save handler requests
 * the origin synchronously in the submit gesture (first await) before persisting. Autofill and the
 * lock timeout reuse the already-loaded server URL required by `settings.save` and never re-prompt.
 *
 * Not wired into `options.html` yet — `src/ui/options/options.ts` remains the live entry point
 * until a later task replaces it.
 */
export class VwOptionsApp extends LitElement {
  static override properties = {
    selected: { type: String },
    narrow: { type: Boolean, reflect: true },
    settings: { attribute: false },
    locked: { type: Boolean },
    pending: { type: Boolean },
    awaitingImportPassword: { type: Boolean },
    connectionStatus: { attribute: false },
    securityStatus: { attribute: false },
    autofillStatus: { attribute: false },
    dataStatus: { attribute: false },
  };

  declare selected: OptionsSectionId;
  declare narrow: boolean;
  declare settings: LoadedSettings | undefined;
  declare locked: boolean;
  declare pending: boolean;
  declare awaitingImportPassword: boolean;
  declare connectionStatus: SectionStatus | undefined;
  declare securityStatus: SectionStatus | undefined;
  declare autofillStatus: SectionStatus | undefined;
  declare dataStatus: SectionStatus | undefined;

  /** Injectable dependency seam; defaults to the real `webextension-polyfill`/DOM implementation. */
  deps: OptionsDeps = createDefaultDeps();

  /** The content of a password-protected import, held between reading the file and the user
   *  supplying its export password. Never a decrypted secret — just the ciphertext document. */
  private pendingImportContent: string | undefined;

  private mediaQuery: MediaQueryList | undefined;
  private readonly onNarrowChange = (event: MediaQueryListEvent): void => {
    this.narrow = event.matches;
  };

  constructor() {
    super();
    this.selected = 'connection';
    this.narrow = false;
    this.settings = undefined;
    this.locked = true;
    this.pending = false;
    this.awaitingImportPassword = false;
    this.connectionStatus = undefined;
    this.securityStatus = undefined;
    this.autofillStatus = undefined;
    this.dataStatus = undefined;
    this.pendingImportContent = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      this.mediaQuery = window.matchMedia(NARROW_QUERY);
      this.narrow = this.mediaQuery.matches;
      this.mediaQuery.addEventListener('change', this.onNarrowChange);
    }
    void this.init();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.mediaQuery?.removeEventListener('change', this.onNarrowChange);
  }

  private async init(): Promise<void> {
    const stateResponse = await this.deps.request({ type: 'auth.getState' });
    this.locked = stateResponse.ok
      ? (stateResponse.data as { state: SessionState }).state !== 'unlocked'
      : true;
    const settingsResponse = await this.deps.request({ type: 'settings.get' });
    if (settingsResponse.ok) {
      this.settings = settingsResponse.data as LoadedSettings;
    }
  }

  private onTab(event: CustomEvent<{ id: string }>): void {
    const id = event.detail.id;
    if (RAIL.some((item) => item.id === id)) {
      this.selected = id as OptionsSectionId;
    }
  }

  private async handleConnectionSave(event: CustomEvent<ConnectionSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = event.detail.serverUrl;
    // The detail is already a normalized URL; derive the origin pattern synchronously so the
    // permission request is the first await, still inside the user gesture.
    const originPattern = `${new URL(serverUrl).origin}/*`;
    this.pending = true;
    this.connectionStatus = undefined;
    try {
      const granted = await this.deps.requestOrigins([originPattern]);
      if (!granted) {
        this.connectionStatus = { message: 'Host permission was not granted.', tone: 'danger' };
        return;
      }
      const response = await this.deps.request({ type: 'settings.save', serverUrl });
      if (!response.ok) {
        this.connectionStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) {
        this.settings = { ...this.settings, serverUrl };
      }
      this.connectionStatus = { message: 'Connection saved.', tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleAutofillSave(event: CustomEvent<AutofillSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = this.settings?.serverUrl;
    if (serverUrl === undefined) {
      this.autofillStatus = { message: 'Set your server URL on the Connection tab first.', tone: 'danger' };
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
      if (this.settings) {
        this.settings = { ...this.settings, defaultUriMatchStrategy: event.detail.defaultUriMatchStrategy };
      }
      this.autofillStatus = { message: 'Autofill settings saved.', tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleLockTimeoutSave(event: CustomEvent<LockTimeoutSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = this.settings?.serverUrl;
    if (serverUrl === undefined) {
      this.securityStatus = { message: 'Set your server URL on the Connection tab first.', tone: 'danger' };
      return;
    }
    this.pending = true;
    this.securityStatus = undefined;
    try {
      const response = await this.deps.request({
        type: 'settings.save',
        serverUrl,
        lockTimeout: event.detail.lockTimeout,
      });
      if (!response.ok) {
        this.securityStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) {
        this.settings = { ...this.settings, lockTimeout: event.detail.lockTimeout };
      }
      this.securityStatus = { message: 'Lock timeout saved.', tone: 'success' };
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
      this.settings = {
        ...this.settings,
        onIdleAction: event.detail.onIdleAction,
        clipboardClearSeconds: event.detail.clipboardClearSeconds,
      };
    }
  }

  private async handleExport(event: CustomEvent<ExportDetail>): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    this.dataStatus = undefined;
    try {
      const password = event.detail.password;
      const response = await this.deps.request(
        password === undefined ? { type: 'vault.export' } : { type: 'vault.export', password },
      );
      if (!response.ok) {
        this.dataStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      const json = (response.data as { json: string }).json;
      const stamp = new Date().toISOString().slice(0, 10);
      const fileName = `vaultwarden-export-${password === undefined ? '' : 'encrypted-'}${stamp}.json`;
      this.deps.downloadText(json, fileName);
      this.dataStatus = {
        message: password === undefined
          ? 'Exported decrypted vault. Store the file securely.'
          : 'Exported an encrypted vault backup.',
        tone: 'success',
      };
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
        this.dataStatus = { message: 'Could not read the import file.', tone: 'danger' };
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
    const response = await this.deps.request(
      password === undefined ? { type: 'vault.import', content } : { type: 'vault.import', content, password },
    );
    if (!response.ok) {
      this.dataStatus = { message: response.error.message, tone: 'danger' };
      return;
    }
    const imported = (response.data as { imported: number }).imported;
    this.awaitingImportPassword = false;
    this.pendingImportContent = undefined;
    this.dataStatus = { message: `Imported ${imported} item${imported === 1 ? '' : 's'}.`, tone: 'success' };
  }

  private renderSection() {
    switch (this.selected) {
      case 'connection':
        return html`<vw-connection-section
          .serverUrl=${this.settings?.serverUrl ?? ''}
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
      case 'data':
        return html`<vw-data-section
          ?locked=${this.locked}
          ?pending=${this.pending}
          .awaitingImportPassword=${this.awaitingImportPassword}
          .status=${this.dataStatus}
        ></vw-data-section>`;
      case 'about':
        return html`<vw-about-section .version=${this.deps.extensionVersion()}></vw-about-section>`;
    }
  }

  protected override render() {
    return html`
      <vw-page-shell
        .items=${RAIL}
        .selected=${this.selected}
        .narrow=${this.narrow}
        @vw-tab-change=${(e: CustomEvent<{ id: string }>) => this.onTab(e)}
        @vw-connection-save=${(e: CustomEvent<ConnectionSaveDetail>) => void this.handleConnectionSave(e)}
        @vw-autofill-save=${(e: CustomEvent<AutofillSaveDetail>) => void this.handleAutofillSave(e)}
        @vw-lock-timeout-save=${(e: CustomEvent<LockTimeoutSaveDetail>) => void this.handleLockTimeoutSave(e)}
        @vw-security-save=${(e: CustomEvent<SecuritySaveDetail>) => void this.handleSecuritySave(e)}
        @vw-export=${(e: CustomEvent<ExportDetail>) => void this.handleExport(e)}
        @vw-import-file=${(e: CustomEvent<ImportFileDetail>) => void this.handleImportFile(e)}
        @vw-import-password=${(e: CustomEvent<ImportPasswordDetail>) => void this.handleImportPassword(e)}
      >
        ${this.renderSection() ?? nothing}
      </vw-page-shell>
    `;
  }
}

customElements.define('vw-options-app', VwOptionsApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-options-app': VwOptionsApp;
  }
}
