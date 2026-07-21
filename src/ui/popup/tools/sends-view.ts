import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { getLocale, LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';
import type { AsyncState } from '../../components/async-state.js';
import type { SendInput, UpdateSendInput } from '../../../core/vault/sends.js';
import { fileToBase64 } from '../utils.js';
import type {
  CopyDetail,
  DetailStatus,
  SendCreateDetail,
  SendDeleteDetail,
  SendSummary,
  SendUpdateDetail,
} from '../types.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024;

type SendMode = 'text' | 'file';

/**
 * The Sends surface: create text/file Sends, list/copy/delete existing ones, and edit a Send's
 * metadata and password. It emits typed create/update/delete commands (the file variant carries
 * already-read base64 bytes) and `vw-copy`/`vw-send-receive` — the root performs every worker
 * request, clipboard write, and receive-page open. Local input validation (empty text, the 100 MB
 * file cap) is shown inline before any command is emitted; request results arrive via `status`.
 */
export class VwSendsView extends LitElement {
  static override properties = {
    sends: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
    mode: { state: true },
    creating: { state: true },
    editingId: { state: true },
    validationError: { state: true },
    encoding: { state: true },
    confirmingDeleteId: { state: true },
  };

  declare sends: AsyncState<SendSummary[]>;
  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare mode: SendMode;
  declare creating: boolean;
  declare editingId: string | null;
  declare validationError: string | undefined;
  /** True while a chosen file is being base64-encoded on the main thread (before the create command
   *  is emitted). Drives the create button's disabled + spinner state so the popup never looks frozen. */
  declare encoding: boolean;
  declare confirmingDeleteId: string | null;

  private submitting: 'create' | 'edit' | null = null;
  private wasPending = false;
  private deleteTrigger: HTMLButtonElement | null = null;
  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.sends = { status: 'idle' };
    this.pending = false;
    this.status = undefined;
    this.mode = 'text';
    this.creating = false;
    this.editingId = null;
    this.validationError = undefined;
    this.encoding = false;
    this.confirmingDeleteId = null;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: flex;
        flex: 1;
        min-height: 0;
        flex-direction: column;
        background: var(--vw-panel);
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px 8px;
        flex: none;
      }
      .head h1 {
        margin: 0;
        font-size: 14px;
        font-weight: 600;
      }
      .content {
        display: flex;
        flex: 1;
        min-height: 0;
        flex-direction: column;
        gap: 10px;
        overflow-y: auto;
        padding: 2px 14px 14px;
        scrollbar-width: thin;
        scrollbar-color: var(--vw-scrollbar) transparent;
      }
      .content::-webkit-scrollbar { width: 6px; }
      .content::-webkit-scrollbar-thumb {
        border-radius: 3px;
        background: var(--vw-scrollbar);
      }
      .card {
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
        padding: 14px;
        background: var(--vw-card);
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .create-launch {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 11px 12px;
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
        background: var(--vw-card);
      }
      .launch-icon {
        width: 34px;
        height: 34px;
        display: grid;
        place-items: center;
        flex: none;
        border-radius: var(--vw-radius-control);
        background: var(--vw-teal-10);
        color: var(--vw-teal-text);
      }
      .launch-icon svg { width: 17px; height: 17px; }
      .launch-copy { flex: 1; min-width: 0; }
      .launch-title { display: block; color: var(--vw-ink); font-size: 12.5px; font-weight: 600; }
      .launch-sub { display: block; margin-top: 2px; color: var(--vw-muted); font-size: 10.5px; }
      .create-launch .btn { min-height: 32px; height: 32px; padding: 0 12px; font-size: 11.5px; }
      .card-head { display: flex; align-items: center; gap: 8px; }
      .card-head .section-label { flex: 1; }
      .section-label {
        font-size: 11px;
        font-weight: 600;
        color: var(--vw-muted);
      }
      .seal {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px;
        border-radius: var(--vw-radius-input);
        background: var(--vw-teal-10);
        color: var(--vw-teal-text);
        font-size: 11px;
      }
      .seal svg { width: 14px; height: 14px; flex: none; }
      .seg {
        display: flex;
        gap: 2px;
        padding: 3px;
        border-radius: var(--vw-radius-control);
        background: var(--vw-fill);
      }
      .seg-btn {
        flex: 1;
        height: 30px;
        border: 0;
        border-radius: var(--vw-radius-input);
        background: transparent;
        color: var(--vw-muted);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        cursor: pointer;
      }
      .seg-btn.is-active {
        background: var(--vw-panel);
        color: var(--vw-ink);
        box-shadow: var(--vw-seg-shadow);
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 5px;
        min-width: 0;
        font-size: 11px;
        color: var(--vw-muted);
      }
      textarea.input {
        min-height: 76px;
        height: auto;
        padding: 10px 12px;
        font-family: var(--vw-font-ui);
        resize: vertical;
      }
      .check {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        color: var(--vw-text-2);
      }
      .grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 8px;
      }
      .grid .input { height: 38px; padding: 0 9px; }
      .block { width: 100%; }
      .list { display: flex; flex-direction: column; gap: 8px; }
      .list-title { font-size: 11px; font-weight: 600; color: var(--vw-muted); padding: 2px; }
      .send-row {
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
        padding: 11px 12px;
        background: var(--vw-card);
        display: flex;
        flex-direction: column;
        gap: 7px;
      }
      .send-head {
        display: flex;
        align-items: center;
        gap: 9px;
      }
      .send-tile {
        width: 30px;
        height: 30px;
        display: grid;
        place-items: center;
        flex: none;
        border-radius: var(--vw-radius-control);
        background: var(--vw-teal-10);
        color: var(--vw-teal-text);
      }
      .send-tile svg { width: 15px; height: 15px; }
      .send-name {
        flex: 1;
        min-width: 0;
        font-size: 13px;
        font-weight: 600;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .send-sub {
        font-size: 11px;
        color: var(--vw-muted);
      }
      .badge {
        padding: 2px 7px;
        border-radius: var(--vw-radius-chip);
        background: var(--vw-fill);
        color: var(--vw-muted);
        font-size: 10px;
      }
      .send-url-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .send-url {
        flex: 1;
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font-family: var(--vw-font-mono);
        font-size: 10.5px;
        color: var(--vw-text-2);
      }
      .row-actions { display: inline-flex; align-items: center; gap: 2px; }
      .icon-btn:disabled { opacity:.45; cursor:default; }
      .delete-confirm {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 7px 9px;
        border-radius: var(--vw-radius-input);
        background: var(--vw-danger-10);
        color: var(--vw-danger);
        font-size: 11px;
      }
      .delete-confirm span { flex: 1; }
      .delete-confirm .btn { min-height: 28px; height: 28px; padding: 0 10px; font-size: 11px; }
      .empty-note {
        padding: 28px 16px;
        text-align: center;
        color: var(--vw-muted);
        font-size: 12px;
      }
      .status {
        flex: none;
      }
      svg {
        width: 16px;
        height: 16px;
      }
      .spin {
        display: inline-flex;
      }
      .spin svg {
        animation: mvSpin 0.8s linear infinite;
      }
      @keyframes mvSpin {
        to {
          transform: rotate(360deg);
        }
      }
      @media (prefers-reduced-motion: reduce) {
        .spin svg {
          animation: none;
        }
      }
      @media (max-width: 340px) {
        .grid { grid-template-columns: 1fr; }
      }
    `,
  ];

  protected override updated(changed: PropertyValues<this>): void {
    if (changed.has('pending')) {
      if (this.wasPending && !this.pending) this.onRequestComplete();
      this.wasPending = this.pending;
    }
  }

  /** After a create/update round-trip: reset the create form or exit edit mode unless it failed. */
  private onRequestComplete(): void {
    const failed = this.status?.tone === 'danger';
    if (!failed && this.submitting === 'create') this.resetCreateForm();
    if (!failed && this.submitting === 'edit') this.editingId = null;
    this.submitting = null;
  }

  private resetCreateForm(): void {
    const restoreFocus = this.creating;
    for (const sel of ['[data-name]', '[data-text]', '[data-file]']) {
      const el = this.renderRoot.querySelector<HTMLInputElement | HTMLTextAreaElement>(sel);
      if (el) el.value = '';
    }
    this.validationError = undefined;
    this.creating = false;
    if (restoreFocus) this.focusAfterRender('[data-new-send]', '[data-back]');
  }

  private openCreate(): void {
    this.creating = true;
    this.focusAfterRender('[data-name]');
  }

  private focusAfterRender(...selectors: string[]): void {
    void (async () => {
      await this.updateComplete;
      await this.updateComplete;
      for (const selector of selectors) {
        const target = this.renderRoot.querySelector<HTMLElement>(selector);
        if (target) {
          target.focus();
          return;
        }
      }
    })();
  }

  private readValue(sel: string): string {
    const el = this.renderRoot.querySelector<HTMLInputElement | HTMLTextAreaElement>(sel);
    return el?.value ?? '';
  }

  private readChecked(sel: string): boolean {
    return this.renderRoot.querySelector<HTMLInputElement>(sel)?.checked ?? false;
  }

  private back(): void {
    if (this.pending || this.encoding) return;
    emit(this, 'vw-item-back');
  }

  private receive(): void {
    if (this.pending || this.encoding) return;
    emit(this, 'vw-send-receive');
  }

  private copyUrl(url: string): void {
    emit<CopyDetail>(this, 'vw-copy', { value: url, label: t('options.send.copyLink') });
  }

  private deleteSend(id: string): void {
    this.confirmingDeleteId = null;
    this.deleteTrigger = null;
    this.focusAfterRender(this.creating ? '[data-name]' : '[data-new-send]', '[data-back]');
    emit<SendDeleteDetail>(this, 'vw-send-delete', { id });
  }

  private promptDelete(id: string, trigger: HTMLButtonElement): void {
    this.confirmingDeleteId = id;
    this.deleteTrigger = trigger;
    this.focusAfterRender('[data-delete-cancel]');
  }

  private cancelDelete(): void {
    const trigger = this.deleteTrigger;
    this.confirmingDeleteId = null;
    this.deleteTrigger = null;
    void (async () => {
      await this.updateComplete;
      trigger?.focus();
    })();
  }

  private baseInput(): SendInput {
    const input: SendInput = {
      name: this.readValue('[data-name]').trim() || t('send.defaultName'),
      deletionDays: Number(this.readValue('[data-deletion]')) || 7,
    };
    const password = this.readValue('[data-password]');
    if (password) input.password = password;
    const expiry = Number(this.readValue('[data-expiry]'));
    if (expiry > 0) input.expirationDays = expiry;
    const max = Number(this.readValue('[data-max]'));
    if (max > 0) input.maxAccessCount = max;
    return input;
  }

  private async create(): Promise<void> {
    if (this.pending || this.encoding) return;
    this.validationError = undefined;
    const base = this.baseInput();
    const rawName = this.readValue('[data-name]').trim();

    if (this.mode === 'file') {
      const file = this.renderRoot.querySelector<HTMLInputElement>('[data-file]')?.files?.[0];
      if (!file) { this.validationError = t('send.error.fileRequired'); return; }
      if (file.size > MAX_FILE_BYTES) { this.validationError = t('send.error.fileTooLarge', { max: '100 MB' }); return; }
      // base64-encoding a large file blocks the popup's main thread; flip the busy flag before the
      // first await so the button disables and shows a spinner rather than appearing frozen.
      this.encoding = true;
      emit(this, 'vw-send-encoding', { encoding: true });
      let dataB64: string;
      try {
        dataB64 = await fileToBase64(file);
      } catch {
        this.validationError = t('send.error.fileRead');
        return;
      } finally {
        this.encoding = false;
        emit(this, 'vw-send-encoding', { encoding: false });
      }
      this.submitting = 'create';
      emit<SendCreateDetail>(this, 'vw-send-create', { kind: 'file', input: { ...base, name: rawName || file.name }, dataB64, fileName: file.name });
      return;
    }

    const text = this.readValue('[data-text]');
    if (!text.trim()) { this.validationError = t('send.error.textRequired'); return; }
    this.submitting = 'create';
    emit<SendCreateDetail>(this, 'vw-send-create', { kind: 'text', input: { ...base, text, hidden: this.readChecked('[data-hidden]') } });
  }

  private saveEdit(send: SendSummary): void {
    if (this.pending) return;
    const input: UpdateSendInput = {
      name: this.readValue('[data-e-name]').trim() || t('send.defaultName'),
      disabled: this.readChecked('[data-e-disabled]'),
    };
    if (send.type === 0) {
      input.text = this.readValue('[data-e-text]');
      input.hidden = this.readChecked('[data-e-hidden]');
    }
    const max = Number(this.readValue('[data-e-max]'));
    input.maxAccessCount = max > 0 ? max : 0; // 0 clears the limit
    const expiry = Number(this.readValue('[data-e-expiry]'));
    if (expiry > 0) input.expirationDays = expiry;
    const deletion = Number(this.readValue('[data-e-deletion]'));
    if (deletion > 0) input.deletionDays = deletion;
    if (this.readChecked('[data-e-removepw]')) input.passwordMode = 'remove';
    else if (this.readValue('[data-e-password]')) { input.passwordMode = 'set'; input.newPassword = this.readValue('[data-e-password]'); }
    else input.passwordMode = 'keep';

    this.submitting = 'edit';
    emit<SendUpdateDetail>(this, 'vw-send-update', { id: send.id, input });
  }

  private renderStatus() {
    if (!this.status) return nothing;
    return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
  }

  private renderEdit(send: SendSummary) {
    const back = t('common.back');
    return html`
      <div class="head">
        <button type="button" class="icon-btn sm" data-back title=${back} aria-label=${back} ?disabled=${this.pending} @click=${() => { this.editingId = null; }}>${uiIcon('back')}</button>
        <h1>${t('send.editTitle')}</h1>
      </div>
      <div class="content">
        <div class="card">
          <span class="section-label">${send.type === 1 ? t('send.typeFile') : t('send.typeText')}${send.fileName ? ` · ${send.fileName}` : ''}</span>
          <label class="field"><span>${t('options.send.name')}</span><input class="input" data-e-name .value=${send.name} ?disabled=${this.pending} /></label>
          ${send.type === 0
            ? html`
                <label class="field"><span>${t('send.text')}</span><textarea class="input" data-e-text .value=${send.text ?? ''} ?disabled=${this.pending}></textarea></label>
                <label class="check"><input type="checkbox" data-e-hidden .checked=${send.hidden} ?disabled=${this.pending} /><span>${t('send.hideText')}</span></label>`
            : nothing}
          <label class="check"><input type="checkbox" data-e-disabled .checked=${send.disabled} ?disabled=${this.pending} /><span>${t('send.disabled')}</span></label>
          <input class="input" data-e-password type="password" placeholder=${t('send.passwordKeep')} autocomplete="new-password" ?disabled=${this.pending} />
          ${send.passwordProtected
            ? html`<label class="check"><input type="checkbox" data-e-removepw ?disabled=${this.pending} /><span>${t('send.removePassword')}</span></label>`
            : nothing}
          <div class="grid">
            <label class="field"><span>${t('send.expirationDays')}</span><input class="input" data-e-expiry type="number" min="0" ?disabled=${this.pending} /></label>
            <label class="field"><span>${t('send.deletionDays')}</span><input class="input" data-e-deletion type="number" min="1" ?disabled=${this.pending} /></label>
            <label class="field"><span>${t('send.maxViews')}</span><input class="input" data-e-max type="number" min="0" .value=${send.maxAccessCount != null ? String(send.maxAccessCount) : ''} ?disabled=${this.pending} /></label>
          </div>
          <button type="button" class="btn primary block" data-save ?disabled=${this.pending} @click=${() => this.saveEdit(send)}>${uiIcon('check')}<span>${t('common.save')}</span></button>
        </div>
        ${this.renderStatus()}
      </div>
    `;
  }

  private renderCreate() {
    if (!this.creating) {
      return html`
        <div class="create-launch">
          <span class="launch-icon">${uiIcon('lock')}</span>
          <span class="launch-copy">
            <span class="launch-title">${t('options.send.introTitle')}</span>
            <span class="launch-sub">${t('send.localEncryption')}</span>
          </span>
          <button type="button" class="btn primary" data-new-send @click=${() => this.openCreate()}>${uiIcon('plus')}<span>${t('common.add')}</span></button>
        </div>
        <button type="button" class="btn outline block" data-receive ?disabled=${this.pending || this.encoding} @click=${() => this.receive()}>${uiIcon('mail')}<span>${t('send.receive')}</span></button>
      `;
    }
    return html`
      <div class="card">
        <div class="card-head">
          <span class="section-label">${t('options.send.new')}</span>
          <button type="button" class="icon-btn sm" data-cancel-create title=${t('common.close')} aria-label=${t('common.close')} ?disabled=${this.pending || this.encoding} @click=${() => this.resetCreateForm()}>${uiIcon('close')}</button>
        </div>
        <div class="seal">${uiIcon('lock')}<span>${t('send.localEncryption')}</span></div>
        <div class="seg" role="tablist">
          <button type="button" class="seg-btn ${this.mode === 'text' ? 'is-active' : ''}" data-mode-text role="tab"
            aria-selected=${this.mode === 'text' ? 'true' : 'false'} @click=${() => { this.mode = 'text'; this.validationError = undefined; }}>${t('options.send.typeText')}</button>
          <button type="button" class="seg-btn ${this.mode === 'file' ? 'is-active' : ''}" data-mode-file role="tab"
            aria-selected=${this.mode === 'file' ? 'true' : 'false'} @click=${() => { this.mode = 'file'; this.validationError = undefined; }}>${t('options.send.typeFile')}</button>
        </div>
        <label class="field"><span>${t('options.send.name')}</span><input class="input" data-name placeholder=${t('options.send.namePlaceholder')} ?disabled=${this.pending || this.encoding} /></label>
        ${this.mode === 'text'
          ? html`
              <label class="field"><span>${t('send.textToShare')}</span><textarea class="input" data-text placeholder=${t('options.send.contentPlaceholder')} ?disabled=${this.pending || this.encoding}></textarea></label>
              <label class="check"><input type="checkbox" data-hidden ?disabled=${this.pending || this.encoding} /><span>${t('send.hideText')}</span></label>`
          : html`<label class="field"><span>${t('send.fileToShare')}</span><input class="input" data-file type="file" ?disabled=${this.pending || this.encoding} /></label>`}
        <input class="input" data-password type="password" placeholder=${t('send.passwordOptional')} autocomplete="new-password" ?disabled=${this.pending || this.encoding} />
        <div class="grid">
          <label class="field"><span>${t('send.expirationDays')}</span><input class="input" data-expiry type="number" min="0" placeholder="—" ?disabled=${this.pending || this.encoding} /></label>
          <label class="field"><span>${t('send.deletionDays')}</span><input class="input" data-deletion type="number" min="1" value="7" ?disabled=${this.pending || this.encoding} /></label>
          <label class="field"><span>${t('send.maxViews')}</span><input class="input" data-max type="number" min="0" placeholder="—" ?disabled=${this.pending || this.encoding} /></label>
        </div>
        ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
        <button type="button" class="btn primary block" data-create ?disabled=${this.pending || this.encoding} @click=${() => void this.create()}>
          ${this.encoding
            ? html`<span class="spin" data-encoding>${uiIcon('refresh')}</span><span>${t('send.encoding')}</span>`
            : html`${uiIcon('plus')}<span>${t('send.create')}</span>`}
        </button>
      </div>
    `;
  }

  private renderList() {
    const sends = this.sends;
    switch (sends.status) {
      case 'idle':
      case 'loading':
        return html`<vw-status-message class="status" tone="info" .icon=${'refresh'} .message=${t('send.loading')}></vw-status-message>`;
      case 'error':
        return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${sends.message}></vw-status-message>`;
      case 'empty':
        return html`<div class="empty-note">${t('options.send.empty')}</div>${this.renderStatus()}`;
      case 'ready':
        return html`
          <div class="list">
            <div class="list-title">${t('options.send.active')}</div>
            ${sends.data.map((send) => this.renderSendRow(send))}
          </div>
          ${this.renderStatus()}
        `;
    }
  }

  private renderSendRow(send: SendSummary) {
    const deletes = new Intl.DateTimeFormat(getLocale()).format(new Date(send.deletionDate));
    const confirming = this.confirmingDeleteId === send.id;
    return html`
      <div class="send-row" data-send=${send.id}>
        <div class="send-head">
          <span class="send-tile">${uiIcon(send.type === 1 ? 'file' : 'text')}</span>
          <span class="send-name">${send.name}</span>
          ${send.passwordProtected ? html`<span title=${t('options.send.accessPassword')}>${uiIcon('lock')}</span>` : nothing}
          ${send.disabled ? html`<span class="badge">${t('send.disabledBadge')}</span>` : nothing}
        </div>
        <span class="send-sub">
          ${send.type === 1 && send.fileName ? html`${send.fileName}${send.sizeName ? ` · ${send.sizeName}` : ''} · ` : nothing}${t('send.deletesOn', { date: deletes })}${send.maxAccessCount != null ? ` · ${t('send.viewsCount', { used: send.accessCount, max: send.maxAccessCount })}` : ''}
        </span>
        <div class="send-url-row">
          <code class="send-url">${send.url}</code>
          <span class="row-actions">
            <button type="button" class="icon-btn sm" data-copy title=${t('options.send.copyLink')} aria-label=${t('send.copyAria')} ?disabled=${this.pending || this.encoding} @click=${() => this.copyUrl(send.url)}>${uiIcon('copy')}</button>
            <button type="button" class="icon-btn sm" data-edit title=${t('common.edit')} aria-label=${t('send.editAria')} ?disabled=${this.pending || this.encoding} @click=${() => { this.editingId = send.id; this.validationError = undefined; }}>${uiIcon('edit')}</button>
            <button type="button" class="icon-btn sm" data-delete title=${t('common.delete')} aria-label=${t('send.deleteAria')} ?disabled=${this.pending || this.encoding} @click=${(event: Event) => this.promptDelete(send.id, event.currentTarget as HTMLButtonElement)}>${uiIcon('trash')}</button>
          </span>
        </div>
        ${confirming
          ? html`<div class="delete-confirm" role="region" aria-live="assertive" aria-label=${t('send.deleteConfirm')}>
              <span>${t('send.deleteConfirm')}</span>
              <button type="button" class="btn ghost" data-delete-cancel @click=${() => this.cancelDelete()}>${t('common.cancel')}</button>
              <button type="button" class="btn danger" data-delete-confirm ?disabled=${this.pending || this.encoding} @click=${() => this.deleteSend(send.id)}>${t('common.delete')}</button>
            </div>`
          : nothing}
      </div>
    `;
  }

  protected override render() {
    if (this.editingId !== null && this.sends.status === 'ready') {
      const editing = this.sends.data.find((send) => send.id === this.editingId);
      if (editing) return this.renderEdit(editing);
    }
    return html`
      <div class="head">
        <button type="button" class="icon-btn sm" data-back title=${t('common.back')} aria-label=${t('common.back')} ?disabled=${this.pending || this.encoding} @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>${t('popup.sends')}</h1>
      </div>
      <div class="content">
        ${this.renderCreate()}
        ${this.renderList()}
      </div>
    `;
  }
}

customElements.define('vw-sends-view', VwSendsView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-sends-view': VwSendsView;
  }
}
