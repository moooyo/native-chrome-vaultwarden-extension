import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/setting-card.js';
import '../../components/status-message.js';
import '../../components/segmented.js';
import './import-preview.js';
import type { ExportDetail, ImportFileDetail, ImportPasswordDetail, SectionStatus } from '../types.js';
import {
  canClearVaultTransferRecovery,
  type VaultTransferExportFormat,
  type VaultTransferRecoveryStatus,
} from '../../../messaging/vault-transfer-port.js';
import type { SanitizedImportPreviewViewModel } from './import-preview.js';

export interface ExportOrganizationOption {
  readonly id: string;
  readonly name: string;
}

/**
 * Data settings, MiYu styling: import from a Bitwarden-compatible export, export an encrypted
 * archive, and delete the local vault cache. Every control is disabled while the vault is locked.
 * This section only collects input and emits. The root streams files through a privileged Port,
 * while the worker owns format detection and inspection. A password field is rendered only after
 * the worker returns `password_required` for that exact selected file.
 */
export class VwDataSection extends LitElement {
  static override properties = {
    locked: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    awaitingImportPassword: { type: Boolean },
    importPreview: { attribute: false },
    recoveryStatus: { attribute: false },
    recoveryPending: { type: Boolean },
    recoveryUnavailable: { type: Boolean },
    exportOrganizations: { attribute: false },
    exportFormat: { state: true },
    exportEncryptionType: { state: true },
    exportTarget: { state: true },
    validationError: { state: true },
    recoveryConfirmed: { state: true },
    csvConfirmed: { state: true },
  };

  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare awaitingImportPassword: boolean;
  declare importPreview: SanitizedImportPreviewViewModel | undefined;
  declare recoveryStatus: VaultTransferRecoveryStatus | undefined;
  declare recoveryPending: boolean;
  declare recoveryUnavailable: boolean;
  declare exportOrganizations: readonly ExportOrganizationOption[];
  declare exportFormat: VaultTransferExportFormat;
  declare exportEncryptionType: 'account' | 'file';
  declare exportTarget: 'personal' | string;
  declare validationError: string | undefined;
  declare recoveryConfirmed: boolean;
  declare csvConfirmed: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.locked = false;
    this.pending = false;
    this.status = undefined;
    this.awaitingImportPassword = false;
    this.importPreview = undefined;
    this.recoveryStatus = undefined;
    this.recoveryPending = false;
    this.recoveryUnavailable = false;
    this.exportOrganizations = [];
    this.exportFormat = 'encrypted-json';
    this.exportEncryptionType = 'account';
    this.exportTarget = 'personal';
    this.validationError = undefined;
    this.recoveryConfirmed = false;
    this.csvConfirmed = false;
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
      .recovery-actions { display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%; }
      .recovery-confirm { display: inline-flex; align-items: flex-start; gap: 8px; color: var(--vw-text-4); font-size: 12px; line-height: 1.45; }
      .recovery-confirm input { margin: 2px 0 0; flex: none; accent-color: var(--vw-danger); }
      .csv-confirm { display: inline-flex; align-items: flex-start; gap: 8px; color: var(--vw-text-4); font-size: 12px; line-height: 1.45; }
      .csv-confirm input { margin: 2px 0 0; flex: none; accent-color: var(--vw-accent); }
      .recovery-buttons { display: inline-flex; align-items: center; gap: 8px; flex: none; }
      .recovery-counts { display: flex; flex-wrap: wrap; gap: 8px 18px; color: var(--vw-text-3); font-size: 11.5px; }
      .import-password-controls { display: flex; align-items: center; gap: 8px; }
      .password-actions { display: inline-flex; align-items: center; gap: 8px; }
      .export-controls { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(160px, 220px) minmax(160px, 220px) auto; gap: 8px; align-items: center; width: 100%; }
      .export-encryption { display: grid; grid-template-columns: minmax(140px, auto) minmax(260px, 1fr); gap: 10px; align-items: center; }
      .export-encryption-label { color: var(--vw-text-3); font-size: 11.5px; font-weight: 600; }
      .export-target { display: grid; grid-template-columns: minmax(140px, auto) minmax(260px, 1fr); gap: 10px; align-items: center; }
      .export-target label { color: var(--vw-text-3); font-size: 11.5px; font-weight: 600; }
      .export-target select {
        min-width: 0; height: 32px; padding: 0 10px; border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-ink);
        font: inherit; font-size: 12px;
      }
      vw-segmented { min-width: 220px; }
      button:focus-visible, input:focus-visible, select:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      @media (max-width: 680px) {
        .export-controls { grid-template-columns: minmax(0, 1fr); }
        .export-encryption { grid-template-columns: minmax(0, 1fr); }
        .export-target { grid-template-columns: minmax(0, 1fr); }
        .import-password-controls { align-items: stretch; flex-direction: column; width: 100%; }
        .recovery-actions { align-items: stretch; flex-direction: column; }
        .recovery-buttons { justify-content: flex-end; }
        .password-actions { justify-content: flex-end; }
        .pwd, vw-segmented { width: 100%; min-width: 0; }
        .btn-primary { justify-content: center; }
      }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
  }

  private q<T extends HTMLElement>(sel: string): T | null {
    return this.renderRoot.querySelector<T>(sel);
  }

  private pickImportFile(): void {
    if (this.locked || this.pending || this.recoveryPending || this.recoveryUnavailable
      || this.hasRecoveryBarrier()) return;
    this.q<HTMLInputElement>('[data-import-file]')?.click();
  }

  private onImportFile(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (this.locked || this.pending || this.recoveryPending || this.recoveryUnavailable
      || this.hasRecoveryBarrier() || !file) return;
    this.validationError = undefined;
    this.emit('vw-import-file', { file } satisfies ImportFileDetail);
  }

  private submitImportPassword(): void {
    if (this.locked || this.pending) return;
    const password = this.q<HTMLInputElement>('[data-import-pwd]')?.value ?? '';
    if (!password) {
      this.validationError = t('options.data.importPasswordDesc');
      return;
    }
    this.validationError = undefined;
    const detail = { password } satisfies ImportPasswordDetail;
    const input = this.q<HTMLInputElement>('[data-import-pwd]');
    if (input) input.value = '';
    this.emit('vw-import-password', detail);
  }

  private selectExportFormat(format: string): void {
    if (format !== 'json' && format !== 'encrypted-json' && format !== 'csv' && format !== 'zip') return;
    if (format === 'zip' && this.exportTarget !== 'personal') return;
    this.exportFormat = format;
    this.csvConfirmed = false;
    this.validationError = undefined;
    for (const input of this.renderRoot.querySelectorAll<HTMLInputElement>('[data-export-secret]')) {
      input.value = '';
    }
  }

  private selectExportTarget(value: string): void {
    if (value !== 'personal' && !this.exportOrganizations.some((entry) => entry.id === value)) return;
    this.exportTarget = value;
    if (value !== 'personal' && this.exportFormat === 'zip') this.exportFormat = 'json';
    this.csvConfirmed = false;
    this.validationError = undefined;
  }

  private selectExportEncryptionType(type: string): void {
    if (type !== 'account' && type !== 'file') return;
    for (const input of this.renderRoot.querySelectorAll<HTMLInputElement>('[data-export-file-password]')) {
      input.value = '';
    }
    this.exportEncryptionType = type;
    this.validationError = undefined;
  }

  private exportVault(): void {
    if (this.locked || this.pending) return;
    const masterPasswordInput = this.q<HTMLInputElement>('[data-export-master-password]');
    const filePasswordInput = this.q<HTMLInputElement>('[data-export-file-password]');
    const masterPassword = masterPasswordInput?.value ?? '';
    const filePassword = filePasswordInput?.value ?? '';
    if (!masterPassword) {
      this.validationError = t('options.data.exportVerificationRequired');
      return;
    }
    if (this.exportFormat === 'encrypted-json' && this.exportEncryptionType === 'file' && !filePassword) {
      this.validationError = t('options.data.exportFilePasswordRequired');
      return;
    }
    if (this.exportFormat === 'csv' && !this.csvConfirmed) {
      this.validationError = t('options.data.exportCsvConfirmRequired');
      return;
    }
    this.validationError = undefined;
    const target = this.exportTarget === 'personal'
      ? { kind: 'personal' } as const
      : { kind: 'organization', organizationId: this.exportTarget } as const;
    const detail: ExportDetail = this.exportFormat === 'encrypted-json'
      ? this.exportEncryptionType === 'file'
        ? { format: this.exportFormat, encryptionType: 'file', masterPassword, filePassword, target }
        : { format: this.exportFormat, encryptionType: 'account', masterPassword, target }
      : { format: this.exportFormat, masterPassword, target };
    if (masterPasswordInput) masterPasswordInput.value = '';
    if (filePasswordInput) filePasswordInput.value = '';
    if (this.exportFormat === 'csv') this.csvConfirmed = false;
    this.emit('vw-export', detail);
  }

  private deleteLocal(): void {
    if (this.locked || this.pending || this.recoveryPending) return;
    this.emit('vw-delete-local');
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('recoveryStatus') || (changed.has('locked') && this.locked)) {
      this.recoveryConfirmed = false;
    }
    if (changed.has('locked') && this.locked && this.validationError !== undefined) {
      this.validationError = undefined;
    }
    if (changed.has('locked') && this.locked) this.csvConfirmed = false;
    if (changed.has('exportOrganizations')) {
      const current = this.exportTarget;
      if (current !== 'personal' && !this.exportOrganizations.some((entry) => entry.id === current)) {
        this.exportTarget = 'personal';
      }
    }
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (changed.has('recoveryStatus') || (changed.has('locked') && this.locked)) {
      const confirmation = this.q<HTMLInputElement>('[data-recovery-confirm]');
      if (confirmation) confirmation.checked = false;
    }
    if (changed.has('locked') && this.locked) {
      for (const input of this.renderRoot.querySelectorAll<HTMLInputElement>('.pwd, [data-import-file]')) input.value = '';
    }
  }

  private hasRecoveryBarrier(): boolean {
    return (this.recoveryStatus?.count ?? 0) > 0;
  }

  private canClearRecovery(): boolean {
    return this.recoveryStatus !== undefined
      && canClearVaultTransferRecovery(this.recoveryStatus);
  }

  private clearRecovery(): void {
    if (this.locked || this.pending || this.recoveryPending
      || !this.recoveryConfirmed || !this.canClearRecovery()) return;
    this.emit('vw-transfer-recovery-clear');
  }

  private cancelRecoveryClear(): void {
    this.recoveryConfirmed = false;
  }

  private renderRecovery() {
    const status = this.recoveryStatus;
    if (!status || status.count < 1) return nothing;
    const canClear = this.canClearRecovery();
    return html`
      <vw-setting-card
        stacked
        emphasized
        heading=${t('options.data.recovery.title')}
        description=${t('options.data.recovery.description')}
      >
        <div class="recovery-counts" data-recovery-counts>
          <span>${t('options.data.recovery.total', { count: status.count })}</span>
          <span>${t('options.data.recovery.unknown', { count: status.unresolvedUnknownCount })}</span>
          <span>${t('options.data.recovery.reconcile', { count: status.reconcileRequiredCount })}</span>
          ${status.omittedCount > 0
            ? html`<span>${t('options.data.recovery.omitted', { count: status.omittedCount })}</span>`
            : nothing}
        </div>
        <vw-status-message
          data-recovery-guidance
          tone=${canClear ? 'warning' : 'danger'}
          .icon=${'alert'}
          .message=${canClear
            ? t('options.data.recovery.clearable')
            : t('options.data.recovery.blocked')}
        ></vw-status-message>
        <div class="recovery-actions">
          <label class="recovery-confirm">
            <input
              data-recovery-confirm
              type="checkbox"
              .checked=${this.recoveryConfirmed}
              ?disabled=${this.locked || this.pending || this.recoveryPending || !canClear}
              @change=${(event: Event) => {
                this.recoveryConfirmed = (event.target as HTMLInputElement).checked;
              }}
            />
            <span>${t('options.data.recovery.confirm')}</span>
          </label>
          <span class="recovery-buttons">
            <button
              type="button"
              class="btn-outline"
              data-recovery-cancel
              ?disabled=${this.locked || this.pending || this.recoveryPending || !this.recoveryConfirmed}
              @click=${() => this.cancelRecoveryClear()}
            >${t('common.cancel')}</button>
            <button
              type="button"
              class="btn-danger"
              data-recovery-clear
              ?disabled=${this.locked || this.pending || this.recoveryPending || !canClear || !this.recoveryConfirmed}
              @click=${() => this.clearRecovery()}
            >${uiIcon('trash')}<span>${t('options.data.recovery.clear')}</span></button>
          </span>
        </div>
      </vw-setting-card>
    `;
  }

  private renderImportControl() {
    if (this.awaitingImportPassword) {
      return html`
        <div class="import-password-controls">
          <input class="pwd" data-import-pwd type="password" autocomplete="off" ?disabled=${this.locked || this.pending || this.recoveryPending}
            placeholder=${t('options.data.importPassword')}
            @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); this.submitImportPassword(); } }} />
          <span class="password-actions">
            <button type="button" class="btn-outline" data-import-cancel ?disabled=${this.locked || this.pending || this.recoveryPending} @click=${() => this.emit('vw-import-cancel')}>
              ${t('common.cancel')}
            </button>
            <button type="button" class="btn-primary" data-import-go ?disabled=${this.locked || this.pending || this.recoveryPending} @click=${() => this.submitImportPassword()}>
              ${uiIcon('unlock')}<span>${t('options.data.import')}</span>
            </button>
          </span>
        </div>
      `;
    }
    return html`
      <button type="button" class="btn-outline" data-import ?disabled=${this.locked || this.pending || this.recoveryPending || this.recoveryUnavailable || this.hasRecoveryBarrier()} @click=${() => this.pickImportFile()}>
        ${t('options.data.chooseSource')}
      </button>
      <input class="hidden-file" data-import-file type="file" accept=".json,.csv,.zip,application/json,text/csv,application/zip" @change=${(e: Event) => this.onImportFile(e)} />
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
    const transferBlocked = this.locked || this.pending || this.recoveryPending
      || this.awaitingImportPassword || this.importPreview !== undefined;
    const importBlocked = transferBlocked || this.recoveryUnavailable || this.hasRecoveryBarrier();
    return html`
      ${this.renderRecovery()}
      ${this.importPreview
        ? html`<vw-import-preview .preview=${this.importPreview} .pending=${this.pending}></vw-import-preview>`
        : html`
            <vw-setting-card heading=${heading} description=${description}>
              <span ?inert=${importBlocked} aria-disabled=${importBlocked ? 'true' : 'false'}>
                ${this.renderImportControl()}
              </span>
            </vw-setting-card>
          `}

      <vw-setting-card stacked heading=${t('options.data.export')} description=${t('options.data.exportDesc')}>
        ${this.exportOrganizations.length > 0
          ? html`<div class="export-target">
              <label for="data-export-target">${t('options.data.exportTarget')}</label>
              <select
                id="data-export-target"
                data-export-target
                .value=${this.exportTarget}
                ?disabled=${transferBlocked}
                @change=${(event: Event) => this.selectExportTarget((event.target as HTMLSelectElement).value)}
              >
                <option value="personal">${t('options.data.exportTargetPersonal')}</option>
                ${this.exportOrganizations.map((organization) => html`
                  <option value=${organization.id}>${organization.name}</option>
                `)}
              </select>
            </div>`
          : nothing}
        ${this.exportFormat === 'encrypted-json'
          ? nothing
          : html`<vw-status-message
              data-export-warning
              tone="warning"
              .icon=${'alert'}
              .message=${this.exportFormat === 'csv'
                ? this.exportTarget === 'personal'
                  ? t('options.data.exportCsvWarning')
                  : t('options.data.exportOrganizationCsvWarning')
                : this.exportTarget === 'personal'
                  ? t('options.data.exportPlaintextWarning')
                  : t('options.data.exportOrganizationPlaintextWarning')}
            ></vw-status-message>`}
        ${this.exportFormat === 'csv'
          ? html`<label class="csv-confirm">
              <input
                data-export-csv-confirm
                type="checkbox"
                .checked=${this.csvConfirmed}
                ?disabled=${transferBlocked}
                @change=${(event: Event) => {
                  this.csvConfirmed = (event.target as HTMLInputElement).checked;
                  this.validationError = undefined;
                }}
              />
              <span>${t('options.data.exportCsvConfirm')}</span>
            </label>`
          : nothing}
        ${this.exportFormat === 'encrypted-json'
          ? html`<div class="export-encryption" data-export-encryption-control>
              <span class="export-encryption-label">${t('options.data.exportEncryptionType')}</span>
              <vw-segmented
                data-export-encryption
                .options=${[
                  { id: 'account', label: t('options.data.exportEncryptionAccount') },
                  { id: 'file', label: t('options.data.exportEncryptionFile') },
                ]}
                .value=${this.exportEncryptionType}
                @vw-segmented-change=${(event: CustomEvent<{ id: string }>) => this.selectExportEncryptionType(event.detail.id)}
              ></vw-segmented>
            </div>`
          : nothing}
        <div class="export-controls" ?inert=${transferBlocked} aria-disabled=${transferBlocked ? 'true' : 'false'}>
          <vw-segmented
            data-export-format
            .options=${[
              { id: 'json', label: t('options.data.exportFormatJson') },
              { id: 'encrypted-json', label: t('options.data.exportFormatEncryptedJson') },
              { id: 'csv', label: t('options.data.exportFormatCsv') },
              {
                id: 'zip',
                label: t('options.data.exportFormatZip'),
                disabled: this.exportTarget !== 'personal',
              },
            ]}
            .value=${this.exportFormat}
            @vw-segmented-change=${(event: CustomEvent<{ id: string }>) => this.selectExportFormat(event.detail.id)}
          ></vw-segmented>
          <input class="pwd" data-export-secret data-export-master-password type="password" autocomplete="current-password"
            aria-label=${t('options.data.exportVerificationPassword')}
            placeholder=${t('options.data.exportVerificationPassword')} ?disabled=${transferBlocked} />
          ${this.exportFormat === 'encrypted-json' && this.exportEncryptionType === 'file'
            ? html`<input class="pwd" data-export-secret data-export-file-password type="password" autocomplete="new-password"
                aria-label=${t('options.data.exportFilePassword')}
                placeholder=${t('options.data.exportFilePassword')} ?disabled=${transferBlocked} />`
            : html`<span></span>`}
          <button type="button" class="btn-primary" data-export
            ?disabled=${transferBlocked || (this.exportFormat === 'csv' && !this.csvConfirmed)}
            @click=${() => this.exportVault()}>
            ${uiIcon('download')}<span>${t('options.data.exportBtn')}</span>
          </button>
        </div>
      </vw-setting-card>

      <vw-setting-card danger heading=${t('options.data.deleteLocal')} description=${t('options.data.deleteLocalDesc')}>
        <button type="button" class="btn-danger" data-delete-local ?disabled=${this.locked || this.pending || this.recoveryPending} @click=${() => this.deleteLocal()}>
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
