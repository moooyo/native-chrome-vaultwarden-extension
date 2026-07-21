import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { AsyncState } from '../../components/async-state.js';
import type { SendInput, SendSummary } from '../../../core/vault/sends.js';
import { bytesToBase64 } from '../../../core/crypto/encoding.js';
import '../../components/segmented.js';
import '../../components/select-menu.js';
import '../../components/toggle.js';
import '../../components/status-message.js';
import type { SectionStatus } from '../types.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024;

/**
 * Options Send section: an intro card + a "new Send" create form (text/file, name, content, expiry,
 * max access, optional password) and the active-Send list. Dumb — it emits `vw-send-create`,
 * `vw-send-delete`, and `vw-copy`; the root performs the `sends.*` requests. Compatible with the
 * Bitwarden/Vaultwarden Send protocol via the existing core.
 */
export class VwSendSection extends LitElement {
  static override properties = {
    sends: { attribute: false },
    locked: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    validationError: { state: true },
    encoding: { state: true },
  };

  declare sends: AsyncState<SendSummary[]>;
  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare validationError: string | undefined;
  declare encoding: boolean;

  private i18n = new LocalizeController(this);
  private formOpen = false;
  private kind: 'text' | 'file' = 'text';
  private passwordOn = false;
  private file: File | undefined;
  private submitted = false;
  private wasPending = false;

  constructor() {
    super();
    this.sends = { status: 'idle' };
    this.locked = false;
    this.pending = false;
    this.status = undefined;
    this.validationError = undefined;
    this.encoding = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }
      .card { background: var(--vw-card); border: 1px solid var(--vw-line-1); border-radius: var(--vw-radius-card); padding: 14px 16px; }
      .intro { display: flex; align-items: center; gap: 14px; }
      .intro .text { flex: 1; }
      .intro .title { font-size: 13.5px; font-weight: 600; }
      .intro .desc { font-size: 11.5px; color: var(--vw-muted); margin-top: 2px; }
      .btn-primary { display: inline-flex; align-items: center; gap: 6px; height: 32px; padding: 0 15px; border: none; border-radius: var(--vw-radius-input); background: var(--vw-primary-bg); color: var(--vw-primary-fg); font-family: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer; }
      .btn-primary:hover { background: var(--vw-primary-bg-hover); }
      .btn-primary svg { width: 13px; height: 13px; }
      .btn-outline { height: 32px; padding: 0 14px; border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-text-4); font-family: inherit; font-size: 12.5px; cursor: pointer; }
      .form { border-color: var(--vw-teal-25); display: flex; flex-direction: column; gap: 12px; animation: mvGrow .22s ease-out; transform-origin: top; }
      .form-head { display: flex; align-items: center; }
      .form-head .t { font-size: 12.5px; font-weight: 600; flex: 1; }
      .field { display: flex; flex-direction: column; gap: 4px; }
      .field label { font-size: 11px; color: var(--vw-text-3); }
      .field input, .field textarea {
        width: 100%; box-sizing: border-box; min-height: 32px; padding: 7px 10px; border: 1px solid var(--vw-line-2);
        border-radius: var(--vw-radius-input); background: var(--vw-fill-2); color: var(--vw-ink); font-family: inherit; font-size: 12px;
      }
      .field input:focus, .field textarea:focus { outline: none; border-color: var(--vw-accent); }
      .controls { display: flex; gap: 16px; flex-wrap: wrap; align-items: flex-end; }
      .controls .field { gap: 6px; }
      .row-toggle { display: flex; align-items: center; gap: 8px; }
      .actions { display: flex; gap: 8px; }
      .group-label { font-size: 11px; font-weight: 600; color: var(--vw-muted); padding: 8px 2px 0; }
      .send { display: flex; align-items: center; gap: 13px; padding: 12px 16px; background: var(--vw-card); border: 1px solid var(--vw-line-1); border-radius: var(--vw-radius-card); }
      .send.dead { opacity: 0.5; }
      .tile { width: 34px; height: 34px; border-radius: var(--vw-radius-control); background: var(--vw-teal-10); color: var(--vw-teal-text); display: grid; place-items: center; flex: none; }
      .tile svg { width: 17px; height: 17px; }
      .send .meta { flex: 1; min-width: 0; }
      .send .name { font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .send .sub { font-size: 11.5px; color: var(--vw-muted); }
      .icon-btn { width: 28px; height: 28px; border: none; border-radius: var(--vw-radius-chip); background: transparent; color: var(--vw-text-2); cursor: pointer; display: grid; place-items: center; }
      .icon-btn:hover { background: var(--vw-icon-hover); }
      .icon-btn.danger { color: var(--vw-danger); }
      .icon-btn.danger:hover { background: var(--vw-danger-10); }
      .icon-btn svg { width: 15px; height: 15px; }
      .footer { font-size: 11px; color: var(--vw-faint); padding: 4px 2px; }
      .empty { padding: 24px; text-align: center; color: var(--vw-muted); font-size: 12.5px; }
      .spin { display:inline-flex; }
      .spin svg { width:14px; height:14px; animation:mvSpin .8s linear infinite; }
      button:focus-visible, input:focus-visible, textarea:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      @media (prefers-reduced-motion: reduce) { .spin svg { animation:none; } }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
  }

  private q<T extends HTMLElement>(sel: string): T | null {
    return this.renderRoot.querySelector<T>(sel);
  }

  private openForm(): void { this.formOpen = true; this.requestUpdate(); }
  private resetFormState(): void {
    this.formOpen = false;
    this.file = undefined;
    this.passwordOn = false;
    this.kind = 'text';
    this.validationError = undefined;
    this.submitted = false;
    this.wasPending = false;
  }

  private closeForm(): void {
    this.resetFormState();
    this.requestUpdate();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (this.submitted && changed.has('status') && !this.pending && this.status && this.status.tone !== 'danger') {
      this.resetFormState();
      return;
    }
    if (!changed.has('pending')) return;
    if (this.wasPending && !this.pending && this.submitted) {
      if (this.status?.tone !== 'danger') this.resetFormState();
      this.submitted = false;
    }
    this.wasPending = this.pending;
  }

  private async create(): Promise<void> {
    if (this.pending || this.encoding) return;
    this.validationError = undefined;
    const rawName = (this.q<HTMLInputElement>('[data-name]')?.value ?? '').trim();
    const name = rawName || t('send.defaultName');
    const deletionDays = Number(this.q<HTMLSelectElement>('[data-expiry]')?.value ?? '7') || 7;
    const maxRaw = this.q<HTMLSelectElement>('[data-max]')?.value ?? '';
    const password = this.passwordOn ? (this.q<HTMLInputElement>('[data-pass]')?.value ?? '') : '';
    const base: SendInput = { name, deletionDays, expirationDays: deletionDays };
    if (maxRaw) base.maxAccessCount = Number(maxRaw);
    if (password) base.password = password;
    if (this.kind === 'file') {
      if (!this.file) { this.validationError = t('send.error.fileRequired'); return; }
      if (this.file.size > MAX_FILE_BYTES) { this.validationError = t('send.error.fileTooLarge', { max: '100 MB' }); return; }
      this.encoding = true;
      let dataB64: string;
      try {
        dataB64 = bytesToBase64(new Uint8Array(await this.file.arrayBuffer()));
      } catch {
        this.validationError = t('send.error.fileRead');
        return;
      } finally {
        this.encoding = false;
      }
      this.submitted = true;
      this.emit('vw-send-create', { kind: 'file', input: { ...base, name: rawName || this.file.name }, dataB64, fileName: this.file.name });
    } else {
      const text = this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '';
      if (!text.trim()) { this.validationError = t('send.error.textRequired'); return; }
      this.submitted = true;
      this.emit('vw-send-create', { kind: 'text', input: { ...base, text } });
    }
  }

  private meta(send: SendSummary): string {
    const parts: string[] = [];
    const now = Date.now();
    const dead = send.disabled || new Date(send.deletionDate).getTime() < now;
    if (dead) parts.push(t('options.send.expired'));
    else {
      const days = Math.max(0, Math.round((new Date(send.deletionDate).getTime() - now) / 86400000));
      parts.push(days <= 1 ? t('options.send.expiresTomorrow') : t('options.send.expiresInDays', { count: days }));
    }
    if (send.maxAccessCount != null) parts.push(t('options.send.accessed', { used: send.accessCount, max: send.maxAccessCount }));
    return parts.join(' · ');
  }

  protected override render() {
    return html`
      ${this.renderIntro()}
      ${this.formOpen ? this.renderForm() : nothing}
      ${this.status ? html`<vw-status-message .tone=${this.status.tone} message=${this.status.message}></vw-status-message>` : nothing}
      ${this.renderList()}
      <div class="footer">${t('options.send.footer')}</div>
    `;
  }

  private renderIntro() {
    return html`
      <div class="card intro">
        <div class="text">
          <div class="title">${t('options.send.introTitle')}</div>
          <div class="desc">${t('options.send.introDesc')}</div>
        </div>
        <button type="button" class="btn-primary" ?disabled=${this.locked || this.pending || this.encoding} @click=${() => this.openForm()}>
          ${uiIcon('plus')}${t('options.send.new')}
        </button>
      </div>
    `;
  }

  private renderForm() {
    const expiryOptions = [
      { value: '1', label: t('options.send.expiry.1d') },
      { value: '3', label: t('options.send.expiry.3d') },
      { value: '7', label: t('options.send.expiry.7d') },
      { value: '30', label: t('options.send.expiry.30d') },
    ];
    const maxOptions = [
      { value: '1', label: t('options.send.access.1') },
      { value: '5', label: t('options.send.access.5') },
      { value: '10', label: t('options.send.access.10') },
      { value: '', label: t('options.send.access.unlimited') },
    ];
    return html`
      <div class="card form">
        <div class="form-head">
          <span class="t">${t('options.send.formTitle')}</span>
          <vw-segmented
            style="width:172px"
            .options=${[{ id: 'text', label: t('options.send.typeText') }, { id: 'file', label: t('options.send.typeFile') }]}
            .value=${this.kind}
            .height=${25}
            @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => { this.kind = e.detail.id as 'text' | 'file'; this.requestUpdate(); }}
          ></vw-segmented>
        </div>
        <div class="field">
          <label>${t('options.send.name')}</label>
          <input data-name type="text" placeholder=${t('options.send.namePlaceholder')} ?disabled=${this.pending || this.encoding} />
        </div>
        <div class="field">
          <label>${this.kind === 'text' ? t('options.send.textContent') : t('options.send.fileContent')}</label>
          ${this.kind === 'text'
            ? html`<textarea data-content rows="3" placeholder=${t('options.send.contentPlaceholder')} ?disabled=${this.pending || this.encoding}></textarea>`
            : html`<input data-file type="file" ?disabled=${this.pending || this.encoding} @change=${(e: Event) => { this.file = (e.target as HTMLInputElement).files?.[0]; this.validationError = undefined; }} />`}
        </div>
        <div class="controls">
          <div class="field">
            <label>${t('options.send.expiry')}</label>
            <vw-select data-expiry .options=${expiryOptions} .value=${'7'} .label=${t('options.send.expiry')}></vw-select>
          </div>
          <div class="field">
            <label>${t('options.send.maxAccess')}</label>
            <vw-select data-max .options=${maxOptions} .value=${'5'} .label=${t('options.send.maxAccess')}></vw-select>
          </div>
          <div class="row-toggle">
            <span style="font-size:12px;color:var(--vw-text-4)">${t('options.send.accessPassword')}</span>
            <vw-toggle size="sm" .checked=${this.passwordOn} @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => { this.passwordOn = e.detail.checked; this.requestUpdate(); }}></vw-toggle>
          </div>
        </div>
        ${this.passwordOn ? html`<div class="field"><input data-pass type="password" placeholder=${t('options.send.accessPassword')} ?disabled=${this.pending || this.encoding} /></div>` : nothing}
        ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
        <div class="actions">
          <button type="button" class="btn-primary" ?disabled=${this.pending || this.encoding} @click=${() => void this.create()}>
            ${this.encoding ? html`<span class="spin">${uiIcon('refresh')}</span>${t('send.encoding')}` : t('options.send.create')}
          </button>
          <button type="button" class="btn-outline" ?disabled=${this.pending || this.encoding} @click=${() => this.closeForm()}>${t('common.cancel')}</button>
        </div>
      </div>
    `;
  }

  private renderList() {
    const state = this.sends;
    if (state.status === 'loading') return html`<div class="empty">${t('common.loading')}</div>`;
    if (state.status === 'empty' || state.status === 'idle') return html`<div class="group-label">${t('options.send.active')}</div><div class="empty">${t('options.send.empty')}</div>`;
    if (state.status === 'error') return html`<vw-status-message tone="danger" message=${state.message}></vw-status-message>`;
    return html`
      <div class="group-label">${t('options.send.active')}</div>
      ${state.data.map((send) => this.renderSend(send))}
    `;
  }

  private renderSend(send: SendSummary) {
    const dead = send.disabled || new Date(send.deletionDate).getTime() < Date.now();
    const isFile = send.type === 1;
    return html`
      <div class="send ${dead ? 'dead' : ''}">
        <div class="tile">${uiIcon(isFile ? 'file' : 'text')}</div>
        <div class="meta">
          <div class="name">${send.name}</div>
          <div class="sub">${this.meta(send)}</div>
        </div>
        <button type="button" class="icon-btn" title=${t('options.send.copyLink')} aria-label=${t('send.copyAria')} ?disabled=${this.pending || this.encoding} @click=${() => this.emit('vw-copy', { value: send.url })}>${uiIcon('link')}</button>
        <button type="button" class="icon-btn danger" title=${t('common.delete')} aria-label=${t('send.deleteAria')} ?disabled=${this.pending || this.encoding} @click=${() => this.emit('vw-send-delete', { id: send.id })}>${uiIcon('trash')}</button>
      </div>
    `;
  }
}

customElements.define('vw-send-section', VwSendSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-send-section': VwSendSection;
  }
}
