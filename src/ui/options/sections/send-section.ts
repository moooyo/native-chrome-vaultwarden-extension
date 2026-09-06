import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { AsyncState } from '../../components/async-state.js';
import {
  SEND_DATE_PRESET_HOURS,
  type SendInput,
  type SendSummary,
} from '../../../core/vault/sends.js';
import {
  normalizeSendDraft,
  sendDraftHasEdits,
  type SendDraftSnapshot,
} from '../../send-form-draft.js';
import '../../components/segmented.js';
import '../../components/select-menu.js';
import '../../components/toggle.js';
import '../../components/status-message.js';
import type { SectionStatus } from '../types.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/**
 * Options Send section: an intro card + a "new Send" create form (text/file, name, content, expiry,
 * max access, optional password, sender-email visibility) and the active-Send list. Dumb — it emits `vw-send-create`,
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
  };

  declare sends: AsyncState<SendSummary[]>;
  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare validationError: string | undefined;

  private i18n = new LocalizeController(this);
  private formOpen = false;
  private kind: 'text' | 'file' = 'text';
  private passwordOn = false;
  private file: File | undefined;
  private draftBaseline: SendDraftSnapshot | undefined;
  private draftRevision = 0;
  private submittedRevision: number | undefined;
  private wasPending = false;

  constructor() {
    super();
    this.sends = { status: 'idle' };
    this.locked = false;
    this.pending = false;
    this.status = undefined;
    this.validationError = undefined;
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
      button:focus-visible, input:focus-visible, textarea:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
  }

  private q<T extends HTMLElement>(sel: string): T | null {
    return this.renderRoot.querySelector<T>(sel);
  }

  override disconnectedCallback(): void {
    this.draftRevision += 1;
    this.submittedRevision = undefined;
    super.disconnectedCallback();
  }

  private selectValue(sel: string): string {
    return this.q<HTMLElement & { value: string }>(sel)?.value ?? '';
  }

  private toggleChecked(sel: string): boolean {
    return this.q<HTMLElement & { checked: boolean }>(sel)?.checked ?? false;
  }

  private createBaseline(): SendDraftSnapshot {
    return normalizeSendDraft({
      owner: 'create',
      type: 'text',
      passwordMode: 'none',
      expirationHours: SEND_DATE_PRESET_HOURS.sevenDays,
      deletionHours: SEND_DATE_PRESET_HOURS.sevenDays,
      maxAccessCount: null,
    });
  }

  private currentDraft(): SendDraftSnapshot | undefined {
    if (!this.formOpen) return undefined;
    const password = this.passwordOn ? (this.q<HTMLInputElement>('[data-pass]')?.value ?? '') : '';
    const expiry = this.selectValue('[data-expiry]');
    return normalizeSendDraft({
      owner: 'create',
      type: this.kind,
      name: this.q<HTMLInputElement>('[data-name]')?.value ?? '',
      text: this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '',
      ...(this.file ? { file: this.file } : {}),
      hideEmail: this.toggleChecked('[data-hide-email]'),
      passwordMode: password ? 'set' : 'none',
      password,
      expirationHours: expiry,
      deletionHours: expiry,
      maxAccessCount: this.selectValue('[data-max]'),
    });
  }

  /** Used by the options root before switching to another section. */
  sendFormHasEdits(): boolean {
    return sendDraftHasEdits(this.draftBaseline, this.currentDraft());
  }

  promptForUnsavedEdits(): boolean {
    if (this.formOpen && this.pending) return false;
    if (!this.sendFormHasEdits()) return true;
    return typeof window === 'undefined' || window.confirm(t('send.unsavedChanges'));
  }

  private changeKind(event: CustomEvent<{ id: string }>): void {
    const control = event.currentTarget as HTMLElement & { value: string };
    const next = event.detail.id as 'text' | 'file';
    if (this.pending || next === this.kind) {
      control.value = this.kind;
      return;
    }
    const variantHasValue = this.kind === 'text'
      ? (this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '') !== ''
      : this.file !== undefined;
    if (variantHasValue && typeof window !== 'undefined' && !window.confirm(t('send.unsavedChanges'))) {
      control.value = this.kind;
      return;
    }
    if (this.kind === 'file') this.file = undefined;
    this.kind = next;
    this.validationError = undefined;
    this.requestUpdate();
  }

  private changePasswordEnabled(event: CustomEvent<{ checked: boolean }>): void {
    const control = event.currentTarget as HTMLElement & { checked: boolean };
    if (this.pending) {
      control.checked = this.passwordOn;
      return;
    }
    if (!event.detail.checked && this.passwordOn) {
      const password = this.q<HTMLInputElement>('[data-pass]')?.value ?? '';
      if (password && typeof window !== 'undefined' && !window.confirm(t('send.unsavedChanges'))) {
        control.checked = true;
        return;
      }
    }
    this.passwordOn = event.detail.checked;
    this.requestUpdate();
  }

  private openForm(): void {
    if (this.locked || this.pending) return;
    this.draftRevision += 1;
    this.formOpen = true;
    this.draftBaseline = this.createBaseline();
    this.requestUpdate();
  }
  private resetFormState(): void {
    this.draftRevision += 1;
    this.formOpen = false;
    this.file = undefined;
    this.passwordOn = false;
    this.kind = 'text';
    this.draftBaseline = undefined;
    this.validationError = undefined;
    this.submittedRevision = undefined;
    this.wasPending = false;
  }

  private closeForm(): void {
    if (this.pending || !this.promptForUnsavedEdits()) return;
    this.resetFormState();
    this.requestUpdate();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('locked') && this.locked) {
      this.resetFormState();
      return;
    }
    if ((changed.has('pending') || changed.has('status')) && !this.pending
      && this.submittedRevision !== undefined && (this.wasPending || changed.has('status'))) {
      const revision = this.submittedRevision;
      this.submittedRevision = undefined;
      if (revision === this.draftRevision
        && (this.status?.tone === 'success' || this.status?.tone === 'warning')) {
        this.resetFormState();
        return;
      }
    }
    if (changed.has('pending')) this.wasPending = this.pending;
  }

  private create(): void {
    if (this.locked || this.pending || !this.isConnected) return;
    this.validationError = undefined;
    const rawName = (this.q<HTMLInputElement>('[data-name]')?.value ?? '').trim();
    const name = rawName || t('send.defaultName');
    const deletionHours = Number(this.q<HTMLSelectElement>('[data-expiry]')?.value)
      || SEND_DATE_PRESET_HOURS.sevenDays;
    const maxRaw = this.q<HTMLSelectElement>('[data-max]')?.value ?? '';
    const password = this.passwordOn ? (this.q<HTMLInputElement>('[data-pass]')?.value ?? '') : '';
    const base: SendInput = {
      name,
      deletionHours,
      expirationHours: deletionHours,
      hideEmail: this.toggleChecked('[data-hide-email]'),
    };
    if (maxRaw) base.maxAccessCount = Number(maxRaw);
    if (password) base.password = password;
    if (this.kind === 'file') {
      const file = this.file;
      if (!file) { this.validationError = t('send.error.fileRequired'); return; }
      if (file.size > MAX_FILE_BYTES) { this.validationError = t('send.error.fileTooLarge', { max: '100 MB' }); return; }
      this.submittedRevision = this.draftRevision;
      this.emit('vw-send-create', { kind: 'file', input: { ...base, name: rawName || file.name }, file, fileName: file.name });
    } else {
      const text = this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '';
      if (!text.trim()) { this.validationError = t('send.error.textRequired'); return; }
      this.submittedRevision = this.draftRevision;
      this.emit('vw-send-create', { kind: 'text', input: { ...base, text } });
    }
  }

  private meta(send: SendSummary): string {
    const parts: string[] = [];
    const now = Date.now();
    const deadline = this.effectiveDeadline(send);
    const dead = send.disabled || deadline <= now;
    if (dead) parts.push(t('options.send.expired'));
    else {
      const remaining = deadline - now;
      if (remaining < DAY_MS) {
        const hours = Math.max(1, Math.ceil(remaining / HOUR_MS));
        parts.push(hours === 1
          ? t('options.send.expiresInOneHour')
          : t('options.send.expiresInHours', { count: hours }));
      } else {
        parts.push(t('options.send.expiresInDays', { count: Math.ceil(remaining / DAY_MS) }));
      }
    }
    if (send.maxAccessCount != null) parts.push(t('options.send.accessed', { used: send.accessCount, max: send.maxAccessCount }));
    return parts.join(' · ');
  }

  private effectiveDeadline(send: SendSummary): number {
    const deletionTime = Date.parse(send.deletionDate);
    const expirationTime = send.expirationDate ? Date.parse(send.expirationDate) : Number.POSITIVE_INFINITY;
    return Number.isFinite(expirationTime)
      ? Math.min(deletionTime, expirationTime)
      : deletionTime;
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
        <button type="button" class="btn-primary" ?disabled=${this.locked || this.pending} @click=${() => this.openForm()}>
          ${uiIcon('plus')}${t('options.send.new')}
        </button>
      </div>
    `;
  }

  private renderForm() {
    const expiryOptions = [
      { value: String(SEND_DATE_PRESET_HOURS.oneHour), label: t('options.send.expiry.1h') },
      { value: String(SEND_DATE_PRESET_HOURS.oneDay), label: t('options.send.expiry.1d') },
      { value: String(SEND_DATE_PRESET_HOURS.twoDays), label: t('options.send.expiry.2d') },
      { value: String(SEND_DATE_PRESET_HOURS.threeDays), label: t('options.send.expiry.3d') },
      { value: String(SEND_DATE_PRESET_HOURS.sevenDays), label: t('options.send.expiry.7d') },
      { value: String(SEND_DATE_PRESET_HOURS.fourteenDays), label: t('options.send.expiry.14d') },
      { value: String(SEND_DATE_PRESET_HOURS.thirtyDays), label: t('options.send.expiry.30d') },
    ];
    const maxOptions = [
      { value: '1', label: t('options.send.access.1') },
      { value: '5', label: t('options.send.access.5') },
      { value: '10', label: t('options.send.access.10') },
      { value: '', label: t('options.send.access.unlimited') },
    ];
    return html`
      <div class="card form" ?inert=${this.pending}>
        <div class="form-head">
          <span class="t">${t('options.send.formTitle')}</span>
          <vw-segmented
            style="width:172px"
            .options=${[{ id: 'text', label: t('options.send.typeText') }, { id: 'file', label: t('options.send.typeFile') }]}
            .value=${this.kind}
            .height=${25}
            @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => this.changeKind(e)}
          ></vw-segmented>
        </div>
        <div class="field">
          <label>${t('options.send.name')}</label>
          <input data-name type="text" placeholder=${t('options.send.namePlaceholder')} ?disabled=${this.pending} />
        </div>
        <div class="field">
          <label>${this.kind === 'text' ? t('options.send.textContent') : t('options.send.fileContent')}</label>
          ${this.kind === 'text'
            ? html`<textarea data-content rows="3" placeholder=${t('options.send.contentPlaceholder')} ?disabled=${this.pending}></textarea>`
            : html`<input data-file type="file" ?disabled=${this.pending} @change=${(e: Event) => {
                if (this.pending) return;
                this.file = (e.target as HTMLInputElement).files?.[0];
                this.validationError = undefined;
              }} />`}
        </div>
        <div class="controls">
          <div class="field">
            <label>${t('options.send.expiry')}</label>
            <vw-select data-expiry .options=${expiryOptions} .value=${String(SEND_DATE_PRESET_HOURS.sevenDays)} .label=${t('options.send.expiry')}></vw-select>
          </div>
          <div class="field">
            <label>${t('options.send.maxAccess')}</label>
            <vw-select data-max .options=${maxOptions} .value=${''} .label=${t('options.send.maxAccess')}></vw-select>
          </div>
          <div class="row-toggle">
            <span style="font-size:12px;color:var(--vw-text-4)">${t('options.send.accessPassword')}</span>
            <vw-toggle size="sm" .checked=${this.passwordOn} .disabled=${this.pending}
              @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.changePasswordEnabled(e)}></vw-toggle>
          </div>
          <div class="row-toggle">
            <span style="font-size:12px;color:var(--vw-text-4)">${t('send.hideEmail')}</span>
            <vw-toggle data-hide-email size="sm" .disabled=${this.pending}></vw-toggle>
          </div>
        </div>
        ${this.passwordOn ? html`<div class="field"><input data-pass type="password" placeholder=${t('options.send.accessPassword')} ?disabled=${this.pending} /></div>` : nothing}
        ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
        <div class="actions">
          <button type="button" class="btn-primary" ?disabled=${this.pending} @click=${() => this.create()}>
            ${t('options.send.create')}
          </button>
          <button type="button" class="btn-outline" ?disabled=${this.pending} @click=${() => this.closeForm()}>${t('common.cancel')}</button>
        </div>
      </div>
    `;
  }

  private renderList() {
    if (this.locked) return html`<div class="empty">${t('options.locked')}</div>`;
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
    const dead = send.disabled || this.effectiveDeadline(send) <= Date.now();
    const isFile = send.type === 1;
    return html`
      <div class="send ${dead ? 'dead' : ''}">
        <div class="tile">${uiIcon(isFile ? 'file' : 'text')}</div>
        <div class="meta">
          <div class="name">${send.name}</div>
          <div class="sub">${this.meta(send)}</div>
        </div>
        <button type="button" class="icon-btn" title=${t('options.send.copyLink')} aria-label=${t('send.copyAria')} ?disabled=${this.locked || this.pending} @click=${() => this.emit('vw-copy', { value: send.url })}>${uiIcon('link')}</button>
        <button type="button" class="icon-btn danger" title=${t('common.delete')} aria-label=${t('send.deleteAria')} ?disabled=${this.locked || this.pending} @click=${() => this.emit('vw-send-delete', { id: send.id })}>${uiIcon('trash')}</button>
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
