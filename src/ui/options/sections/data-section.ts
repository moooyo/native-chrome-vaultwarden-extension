import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { ExportDetail, ImportFileDetail, ImportPasswordDetail, SectionStatus } from '../types.js';

/**
 * Data settings: export and import the vault. While the vault is locked every control is disabled
 * and the section explains how to unlock; nothing here can run against a locked vault. Export is a
 * deliberate two-step panel (encrypted with a password, or an explicit plaintext download); import
 * hands the chosen file to the root, which reads and classifies it and — only for a
 * password-protected export — flips `awaitingImportPassword` so this section prompts for it. All
 * requests, file reads and downloads happen in the root; this section only collects input and emits.
 */
export class VwDataSection extends LitElement {
  static override properties = {
    locked: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    awaitingImportPassword: { type: Boolean },
    view: { state: true },
    validationError: { state: true },
  };

  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare awaitingImportPassword: boolean;
  declare view: 'idle' | 'export';
  declare validationError: string | undefined;

  constructor() {
    super();
    this.locked = false;
    this.pending = false;
    this.status = undefined;
    this.awaitingImportPassword = false;
    this.view = 'idle';
    this.validationError = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; max-width: 760px; }
      h1 { margin: 0 0 4px; font-size: 28px; color:var(--vw-ink-strong); }
      p.lede { margin: 0 0 24px; color: var(--vw-muted); font-size: 14px; }
      .card { display: flex; flex-direction: column; gap: 10px; max-width: 620px; margin-bottom: 16px; border: 1px solid var(--vw-line); border-radius: var(--vw-radius-row); padding: 16px 12px; background:var(--vw-panel); }
      .card h2 { margin:-16px -12px 4px; padding:10px 12px; background:var(--vw-blue-weak); font-size:14px; }
      .card p { margin: 0; font-size: 12px; color: var(--vw-muted); }
      .locked { display: flex; gap: 8px; align-items: center; font-size: 13px; color: var(--vw-ink);
        border: 1px solid var(--vw-line); border-radius: var(--vw-radius-group); padding: 12px; margin-bottom: 16px; }
      .locked svg { width: 18px; height: 18px; flex: none; color: var(--vw-muted); }
      .input { width: 100%; box-sizing: border-box; }
      .block { width: 100%; }
      .hidden-file { display: none; }
      .status { margin-top: 8px; }
    `,
  ];

  private openExport(): void {
    this.validationError = undefined;
    this.view = 'export';
  }

  private exportEncrypted(): void {
    if (this.pending) return;
    const password = this.renderRoot.querySelector<HTMLInputElement>('[data-export-pwd]')?.value ?? '';
    if (!password) {
      this.validationError = 'Enter a password, or use the plaintext export.';
      return;
    }
    this.dispatchEvent(new CustomEvent<ExportDetail>('vw-export', { detail: { password }, bubbles: true, composed: true }));
  }

  private exportPlain(): void {
    if (this.pending) return;
    this.dispatchEvent(new CustomEvent<ExportDetail>('vw-export', { detail: {}, bubbles: true, composed: true }));
  }

  private pickImportFile(): void {
    this.renderRoot.querySelector<HTMLInputElement>('[data-import-file]')?.click();
  }

  private onImportFile(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    this.dispatchEvent(new CustomEvent<ImportFileDetail>('vw-import-file', { detail: { file }, bubbles: true, composed: true }));
  }

  private submitImportPassword(): void {
    if (this.pending) return;
    const password = this.renderRoot.querySelector<HTMLInputElement>('[data-import-pwd]')?.value ?? '';
    if (!password) {
      this.validationError = 'Enter the export password.';
      return;
    }
    this.dispatchEvent(new CustomEvent<ImportPasswordDetail>('vw-import-password', { detail: { password }, bubbles: true, composed: true }));
  }

  private renderStatus() {
    if (this.validationError) {
      return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    }
    if (this.status) {
      return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    }
    return nothing;
  }

  private renderExportPanel() {
    if (this.view !== 'export') {
      return html`<button type="button" class="button primary block" data-export ?disabled=${this.locked || this.pending} @click=${() => this.openExport()}>${uiIcon('lock')}<span>Export vault…</span></button>`;
    }
    return html`
      <input class="input" data-export-pwd type="password" autocomplete="new-password" placeholder="Password for encrypted export" />
      <button type="button" class="button primary block" data-export-encrypted ?disabled=${this.pending} @click=${() => this.exportEncrypted()}>${uiIcon('lock')}<span>Export encrypted</span></button>
      <button type="button" class="button block" data-export-plain ?disabled=${this.pending} @click=${() => this.exportPlain()}>${uiIcon('alert')}<span>Export plaintext (unencrypted)</span></button>
    `;
  }

  private renderImport() {
    if (this.awaitingImportPassword) {
      return html`
        <p>This export is password-protected. Enter its password to import it.</p>
        <input class="input" data-import-pwd type="password" autocomplete="off" placeholder="Export password"
          @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); this.submitImportPassword(); } }} />
        <button type="button" class="button primary block" data-import-go ?disabled=${this.pending} @click=${() => this.submitImportPassword()}>${uiIcon('unlock')}<span>Import</span></button>
      `;
    }
    return html`
      <button type="button" class="button block" data-import ?disabled=${this.locked || this.pending} @click=${() => this.pickImportFile()}>${uiIcon('unlock')}<span>Import vault…</span></button>
      <input class="hidden-file" data-import-file type="file" accept=".json,.csv,application/json,text/csv" @change=${(e: Event) => this.onImportFile(e)} />
    `;
  }

  protected override render() {
    return html`
      <h1>Data</h1>
      <p class="lede">Back up your vault or import from another Bitwarden-compatible export.</p>
      ${this.locked
        ? html`<div class="locked">${uiIcon('lock')}<span>Unlock your vault from the popup to import or export data.</span></div>`
        : nothing}
      <div class="card">
        <h2>Export</h2>
        <p>Encrypted exports need a password to restore. Plaintext exports are unprotected — store them securely.</p>
        ${this.renderExportPanel()}
      </div>
      <div class="card">
        <h2>Import</h2>
        <p>Import a Bitwarden-compatible JSON or CSV export.</p>
        ${this.renderImport()}
      </div>
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
