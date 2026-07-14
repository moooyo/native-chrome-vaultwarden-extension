import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/setting-card.js';
import '../../components/status-message.js';
import type { ExportDetail, ImportFileDetail, ImportPasswordDetail, SectionStatus } from '../types.js';

/**
 * Data settings, MiYu styling: import from a Bitwarden-compatible export, export an encrypted
 * archive, and delete the local vault cache. Every control is disabled while the vault is locked.
 * This section only collects input and emits — the root reads/classifies the file, runs the export,
 * and performs the delete. When the root classifies a password-protected import it flips
 * `awaitingImportPassword`, and the import card prompts for the export password.
 */
export class VwDataSection extends LitElement {
  static override properties = {
    locked: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    awaitingImportPassword: { type: Boolean },
    validationError: { state: true },
  };

  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare awaitingImportPassword: boolean;
  declare validationError: string | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.locked = false;
    this.pending = false;
    this.status = undefined;
    this.awaitingImportPassword = false;
    this.validationError = undefined;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }
      .btn-primary {
        display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 15px;
        border: none; border-radius: var(--vw-radius-input);
        background: var(--vw-primary-bg); color: var(--vw-primary-fg);
        font-family: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer;
      }
      .btn-primary:hover:not(:disabled) { background: var(--vw-primary-bg-hover); }
      .btn-primary svg { width: 14px; height: 14px; }
      .btn-outline {
        height: 32px; padding: 0 14px; border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-text-4);
        font-family: inherit; font-size: 12.5px; cursor: pointer;
      }
      .btn-outline:hover:not(:disabled) { background: var(--vw-row-hover); }
      .btn-danger {
        height: 32px; padding: 0 14px; border: 1px solid var(--vw-danger-border);
        border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-danger);
        font-family: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer;
      }
      .btn-danger:hover:not(:disabled) { background: var(--vw-danger-10); }
      .btn-primary:disabled, .btn-outline:disabled, .btn-danger:disabled { opacity: 0.5; cursor: default; }
      .pwd {
        height: 32px; width: 180px; box-sizing: border-box; padding: 0 11px;
        border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input);
        background: var(--vw-card); color: var(--vw-ink); font-family: inherit; font-size: 12px;
      }
      .pwd::placeholder { color: var(--vw-placeholder); }
      .pwd:focus { outline: none; border-color: var(--vw-accent); }
      .hidden-file { display: none; }
      button:focus-visible, input:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
  }

  private q<T extends HTMLElement>(sel: string): T | null {
    return this.renderRoot.querySelector<T>(sel);
  }

  private pickImportFile(): void {
    this.q<HTMLInputElement>('[data-import-file]')?.click();
  }

  private onImportFile(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    this.validationError = undefined;
    this.emit('vw-import-file', { file } satisfies ImportFileDetail);
  }

  private submitImportPassword(): void {
    if (this.pending) return;
    const password = this.q<HTMLInputElement>('[data-import-pwd]')?.value ?? '';
    if (!password) {
      this.validationError = t('options.data.importPasswordDesc');
      return;
    }
    this.validationError = undefined;
    this.emit('vw-import-password', { password } satisfies ImportPasswordDetail);
  }

  private exportEncrypted(): void {
    if (this.pending) return;
    const password = this.q<HTMLInputElement>('[data-export-pwd]')?.value ?? '';
    if (!password) {
      this.validationError = t('options.data.exportDesc');
      return;
    }
    this.validationError = undefined;
    this.emit('vw-export', { password } satisfies ExportDetail);
  }

  private deleteLocal(): void {
    if (this.locked || this.pending) return;
    this.emit('vw-delete-local');
  }

  private renderImportControl() {
    if (this.awaitingImportPassword) {
      return html`
        <input class="pwd" data-import-pwd type="password" autocomplete="off"
          placeholder=${t('options.data.importPassword')}
          @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); this.submitImportPassword(); } }} />
        <button type="button" class="btn-primary" data-import-go ?disabled=${this.pending} @click=${() => this.submitImportPassword()}>
          ${uiIcon('unlock')}<span>${t('options.data.import')}</span>
        </button>
      `;
    }
    return html`
      <button type="button" class="btn-outline" data-import ?disabled=${this.locked || this.pending} @click=${() => this.pickImportFile()}>
        ${t('options.data.chooseSource')}
      </button>
      <input class="hidden-file" data-import-file type="file" accept=".json,.csv,application/json,text/csv" @change=${(e: Event) => this.onImportFile(e)} />
    `;
  }

  private renderStatus() {
    if (this.validationError) {
      return html`<vw-status-message data-status tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    }
    if (this.status) {
      return html`<vw-status-message data-status .tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    }
    return nothing;
  }

  protected override render() {
    const heading = this.awaitingImportPassword ? t('options.data.importPassword') : t('options.data.import');
    const description = this.awaitingImportPassword ? t('options.data.importPasswordDesc') : t('options.data.importDesc');
    return html`
      <vw-setting-card heading=${heading} description=${description}>
        ${this.renderImportControl()}
      </vw-setting-card>

      <vw-setting-card heading=${t('options.data.export')} description=${t('options.data.exportDesc')}>
        <input class="pwd" data-export-pwd type="password" autocomplete="new-password"
          placeholder=${t('options.data.importPassword')} ?disabled=${this.locked || this.pending} />
        <button type="button" class="btn-primary" data-export ?disabled=${this.locked || this.pending} @click=${() => this.exportEncrypted()}>
          ${uiIcon('lock')}<span>${t('options.data.exportBtn')}</span>
        </button>
      </vw-setting-card>

      <vw-setting-card danger heading=${t('options.data.deleteLocal')} description=${t('options.data.deleteLocalDesc')}>
        <button type="button" class="btn-danger" data-delete-local ?disabled=${this.locked || this.pending} @click=${() => this.deleteLocal()}>
          ${uiIcon('trash')}<span>${t('options.data.deleteBtn')}</span>
        </button>
      </vw-setting-card>

      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-data-section', VwDataSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-data-section': VwDataSection;
  }
}
