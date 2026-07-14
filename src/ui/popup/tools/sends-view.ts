import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
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
    editingId: { state: true },
    validationError: { state: true },
    encoding: { state: true },
  };

  declare sends: AsyncState<SendSummary[]>;
  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare mode: SendMode;
  declare editingId: string | null;
  declare validationError: string | undefined;
  /** True while a chosen file is being base64-encoded on the main thread (before the create command
   *  is emitted). Drives the create button's disabled + spinner state so the popup never looks frozen. */
  declare encoding: boolean;

  private submitting: 'create' | 'edit' | null = null;
  private wasPending = false;

  constructor() {
    super();
    this.sends = { status: 'idle' };
    this.pending = false;
    this.status = undefined;
    this.mode = 'text';
    this.editingId = null;
    this.validationError = undefined;
    this.encoding = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0 12px;
      }
      .head h1 {
        margin: 0;
        font-size: 15px;
      }
      .card {
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        padding: 12px;
        margin-bottom: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .section-label {
        font-size: 12px;
        color: var(--vw-muted);
      }
      .seg {
        display: flex;
        gap: 4px;
      }
      .seg-btn {
        flex: 1;
        height: 30px;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        background: var(--vw-panel);
        color: var(--vw-muted);
        font-size: 13px;
        cursor: pointer;
      }
      .seg-btn.is-active {
        border-color: var(--vw-blue-600);
        color: var(--vw-blue-600);
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 4px;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .field .input,
      .field textarea {
        width: 100%;
        box-sizing: border-box;
      }
      textarea.input {
        min-height: 60px;
        padding: 8px;
        font-family: var(--vw-font-ui);
      }
      .check {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
        color: var(--vw-ink);
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr;
        gap: 6px;
      }
      .block {
        width: 100%;
      }
      .send-row {
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        padding: 8px 10px;
        margin-bottom: 6px;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .send-name {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 13px;
      }
      .send-sub {
        font-size: 11px;
        color: var(--vw-muted);
      }
      .send-url-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .send-url {
        flex: 1;
        min-width: 0;
        word-break: break-all;
        font-family: var(--vw-font-mono);
        font-size: 11px;
      }
      .status {
        margin-top: 10px;
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
    for (const sel of ['[data-name]', '[data-text]', '[data-file]']) {
      const el = this.renderRoot.querySelector<HTMLInputElement | HTMLTextAreaElement>(sel);
      if (el) el.value = '';
    }
    this.validationError = undefined;
  }

  private readValue(sel: string): string {
    const el = this.renderRoot.querySelector<HTMLInputElement | HTMLTextAreaElement>(sel);
    return el?.value ?? '';
  }

  private readChecked(sel: string): boolean {
    return this.renderRoot.querySelector<HTMLInputElement>(sel)?.checked ?? false;
  }

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private receive(): void {
    emit(this, 'vw-send-receive');
  }

  private copyUrl(url: string): void {
    emit<CopyDetail>(this, 'vw-copy', { value: url, label: 'Send link' });
  }

  private deleteSend(id: string): void {
    emit<SendDeleteDetail>(this, 'vw-send-delete', { id });
  }

  private baseInput(): SendInput {
    const input: SendInput = {
      name: this.readValue('[data-name]').trim() || 'Send',
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
      if (!file) { this.validationError = 'Choose a file to share'; return; }
      if (file.size > MAX_FILE_BYTES) { this.validationError = 'File is too large (max 100 MB)'; return; }
      // base64-encoding a large file blocks the popup's main thread; flip the busy flag before the
      // first await so the button disables and shows a spinner rather than appearing frozen.
      this.encoding = true;
      let dataB64: string;
      try {
        dataB64 = await fileToBase64(file);
      } finally {
        this.encoding = false;
      }
      this.submitting = 'create';
      emit<SendCreateDetail>(this, 'vw-send-create', { kind: 'file', input: { ...base, name: rawName || file.name }, dataB64, fileName: file.name });
      return;
    }

    const text = this.readValue('[data-text]');
    if (!text) { this.validationError = 'Enter the text to share'; return; }
    this.submitting = 'create';
    emit<SendCreateDetail>(this, 'vw-send-create', { kind: 'text', input: { ...base, text, hidden: this.readChecked('[data-hidden]') } });
  }

  private saveEdit(send: SendSummary): void {
    if (this.pending) return;
    const input: UpdateSendInput = {
      name: this.readValue('[data-e-name]').trim() || 'Send',
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
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => { this.editingId = null; }}>${uiIcon('back')}</button>
        <h1>Edit Send</h1>
      </div>
      <div class="card">
        <span class="section-label">${send.type === 1 ? 'File Send' : 'Text Send'}${send.fileName ? ` · ${send.fileName}` : ''}</span>
        <label class="field"><span>Name</span><input class="input" data-e-name .value=${send.name} /></label>
        ${send.type === 0
          ? html`
              <label class="field"><span>Text</span><textarea class="input" data-e-text .value=${send.text ?? ''}></textarea></label>
              <label class="check"><input type="checkbox" data-e-hidden .checked=${send.hidden} /><span>Hide text by default</span></label>`
          : nothing}
        <label class="check"><input type="checkbox" data-e-disabled .checked=${send.disabled} /><span>Disabled</span></label>
        <input class="input" data-e-password type="password" placeholder="Leave blank to keep current password" autocomplete="new-password" />
        ${send.passwordProtected
          ? html`<label class="check"><input type="checkbox" data-e-removepw /><span>Remove password</span></label>`
          : nothing}
        <div class="grid">
          <label class="field"><span>Expire days</span><input class="input" data-e-expiry type="number" min="0" /></label>
          <label class="field"><span>Delete days</span><input class="input" data-e-deletion type="number" min="0" /></label>
          <label class="field"><span>Max views</span><input class="input" data-e-max type="number" min="0" .value=${send.maxAccessCount != null ? String(send.maxAccessCount) : ''} /></label>
        </div>
        <button type="button" class="button primary block" data-save ?disabled=${this.pending} @click=${() => this.saveEdit(send)}>${uiIcon('check')}<span>Save changes</span></button>
      </div>
      ${this.renderStatus()}
    `;
  }

  private renderCreate() {
    return html`
      <div class="card">
        <span class="section-label">New Send</span>
        <div class="seg" role="tablist">
          <button type="button" class="seg-btn ${this.mode === 'text' ? 'is-active' : ''}" data-mode-text role="tab"
            aria-selected=${this.mode === 'text' ? 'true' : 'false'} @click=${() => { this.mode = 'text'; }}>Text</button>
          <button type="button" class="seg-btn ${this.mode === 'file' ? 'is-active' : ''}" data-mode-file role="tab"
            aria-selected=${this.mode === 'file' ? 'true' : 'false'} @click=${() => { this.mode = 'file'; }}>File</button>
        </div>
        <label class="field"><span>Name</span><input class="input" data-name placeholder="Name" /></label>
        ${this.mode === 'text'
          ? html`
              <label class="field"><span>Text to share</span><textarea class="input" data-text></textarea></label>
              <label class="check"><input type="checkbox" data-hidden /><span>Hide text by default</span></label>`
          : html`<label class="field"><span>File to share</span><input class="input" data-file type="file" /></label>`}
        <input class="input" data-password type="password" placeholder="Password (optional)" autocomplete="new-password" />
        <div class="grid">
          <label class="field"><span>Expire days</span><input class="input" data-expiry type="number" min="0" placeholder="—" /></label>
          <label class="field"><span>Delete days</span><input class="input" data-deletion type="number" min="1" value="7" /></label>
          <label class="field"><span>Max views</span><input class="input" data-max type="number" min="0" placeholder="—" /></label>
        </div>
        ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
        <button type="button" class="button primary block" data-create ?disabled=${this.pending || this.encoding} @click=${() => void this.create()}>
          ${this.encoding
            ? html`<span class="spin" data-encoding>${uiIcon('refresh')}</span><span>Encoding…</span>`
            : html`${uiIcon('plus')}<span>Create Send</span>`}
        </button>
      </div>
      <button type="button" class="button block" data-receive @click=${() => this.receive()}>${uiIcon('mail')}<span>Receive a Send</span></button>
    `;
  }

  private renderList() {
    const sends = this.sends;
    switch (sends.status) {
      case 'idle':
      case 'loading':
        return html`<vw-status-message class="status" tone="info" .icon=${'refresh'} message="Loading Sends…"></vw-status-message>`;
      case 'error':
        return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${sends.message}></vw-status-message>`;
      case 'empty':
        return html`<vw-status-message class="status" tone="info" .icon=${'mail'} message="No active Sends."></vw-status-message>`;
      case 'ready':
        return html`
          <div class="list">
            ${sends.data.map((send) => this.renderSendRow(send))}
          </div>
          ${this.renderStatus()}
        `;
    }
  }

  private renderSendRow(send: SendSummary) {
    const deletes = new Date(send.deletionDate).toLocaleDateString();
    return html`
      <div class="send-row" data-send=${send.id}>
        <span class="send-name">
          ${uiIcon('mail')}<span>${send.name}</span>
          ${send.passwordProtected ? html`<span>${uiIcon('lock')}</span>` : nothing}
          ${send.disabled ? html`<span class="send-sub">(disabled)</span>` : nothing}
        </span>
        <span class="send-sub">
          ${send.type === 1 && send.fileName ? html`${send.fileName}${send.sizeName ? ` · ${send.sizeName}` : ''} · ` : nothing}Deletes ${deletes}${send.maxAccessCount != null ? ` · ${send.accessCount}/${send.maxAccessCount} views` : ''}
        </span>
        <div class="send-url-row">
          <code class="send-url">${send.url}</code>
          <button type="button" class="icon-button" data-copy title="Copy link" aria-label="Copy Send link" @click=${() => this.copyUrl(send.url)}>${uiIcon('copy')}</button>
          <button type="button" class="icon-button" data-edit title="Edit" aria-label="Edit Send" @click=${() => { this.editingId = send.id; this.validationError = undefined; }}>${uiIcon('edit')}</button>
          <button type="button" class="icon-button" data-delete title="Delete" aria-label="Delete Send" ?disabled=${this.pending} @click=${() => this.deleteSend(send.id)}>${uiIcon('trash')}</button>
        </div>
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
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>Sends</h1>
      </div>
      ${this.renderCreate()}
      ${this.renderList()}
    `;
  }
}

customElements.define('vw-sends-view', VwSendsView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-sends-view': VwSendsView;
  }
}
