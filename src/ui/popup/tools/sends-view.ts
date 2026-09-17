import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { getLocale, LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';
import type { AsyncState } from '../../components/async-state.js';
import {
  SEND_DATE_PRESET_HOURS,
  type SendInput,
  type UpdateSendInput,
} from '../../../core/vault/sends.js';
import type { GeneratorHistoryEntry } from '../../../core/generator/history.js';
import {
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  type GeneratorPolicySnapshot,
} from '../../../core/generator/enterprise-password-policy.js';
import {
  normalizeSendDraft,
  sendDraftHasEdits,
  type SendDraftSnapshot,
} from '../../send-form-draft.js';
import type {
  CopyDetail,
  DetailStatus,
  GeneratorSelectionDetail,
  SendCreateDetail,
  SendDeleteDetail,
  SendSummary,
  SendUpdateDetail,
} from '../types.js';
import './generator-view.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024;

type SendMode = 'text' | 'file';

type SendGeneratorOwner =
  | { readonly kind: 'create'; readonly revision: number }
  | { readonly kind: 'edit'; readonly revision: number; readonly id: string };

const SEND_DATE_PRESETS = [
  { hours: SEND_DATE_PRESET_HOURS.oneHour, label: 'options.send.expiry.1h' },
  { hours: SEND_DATE_PRESET_HOURS.oneDay, label: 'options.send.expiry.1d' },
  { hours: SEND_DATE_PRESET_HOURS.twoDays, label: 'options.send.expiry.2d' },
  { hours: SEND_DATE_PRESET_HOURS.threeDays, label: 'options.send.expiry.3d' },
  { hours: SEND_DATE_PRESET_HOURS.sevenDays, label: 'options.send.expiry.7d' },
  { hours: SEND_DATE_PRESET_HOURS.fourteenDays, label: 'options.send.expiry.14d' },
  { hours: SEND_DATE_PRESET_HOURS.thirtyDays, label: 'options.send.expiry.30d' },
] as const;

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
    generatorHistory: { attribute: false },
    generatorPolicy: { attribute: false },
    generatorAccountEmail: { attribute: false },
    generatorOwner: { state: true },
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
  declare generatorHistory: readonly GeneratorHistoryEntry[];
  declare generatorPolicy: GeneratorPolicySnapshot;
  declare generatorAccountEmail: string | undefined;
  declare generatorOwner: SendGeneratorOwner | null;

  private submitting: { kind: 'create' | 'edit'; revision: number; ownerId?: string } | null = null;
  private wasPending = false;
  private draftBaseline: SendDraftSnapshot | undefined;
  private draftRevision = 0;
  private editSource: SendSummary | undefined;
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
    this.generatorHistory = [];
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    this.generatorAccountEmail = undefined;
    this.generatorOwner = null;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        position: relative;
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
        padding: 14px 16px 12px;
        flex: none;
      }
      .head h1 {
        margin: 0;
        font-size: 17px;
        font-weight: 650;
        letter-spacing: -.3px;
      }
      .content {
        display: flex;
        flex: 1;
        min-height: 0;
        flex-direction: column;
        gap: 16px;
        overflow-y: auto;
        padding: 2px 16px 18px;
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
        gap: 16px;
      }
      .form-card { padding: 0; border: 0; border-radius: 0; background: transparent; }
      .form-section { display: flex; flex-direction: column; gap: 12px; min-width: 0; padding: 0 0 18px; border-bottom: 1px solid var(--vw-line-1); }
      .form-section h2 { margin: 0; color: var(--vw-ink); font-size: 13px; font-weight: 650; }
      .field-hint { margin: 0; color: var(--vw-muted); font-size: 11px; line-height: 1.6; }
      .private-notes { border-bottom: 1px solid var(--vw-line-1); padding-bottom: 16px; }
      .private-notes summary { color: var(--vw-text-2); font-size: 12px; cursor: pointer; }
      .private-notes[open] summary { margin-bottom: 12px; }
      .form-actions { position: sticky; bottom: -18px; padding: 12px 0 18px; background: var(--vw-panel); border-top: 1px solid var(--vw-line-1); }
      .create-launch {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 0 16px;
        border: 0;
        border-bottom: 1px solid var(--vw-line-1);
        border-radius: 0;
        background: transparent;
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
      .launch-title { display: block; color: var(--vw-ink); font-size: 13px; font-weight: 650; }
      .launch-sub { display: block; margin-top: 4px; color: var(--vw-muted); font-size: 11px; line-height: 1.5; }
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
        gap: 7px;
        min-width: 0;
        font-size: 12px;
        color: var(--vw-text-3);
      }
      .password-row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .password-row .input {
        flex: 1;
        min-width: 0;
      }
      .generator-overlay {
        position: absolute;
        z-index: 10;
        inset: 0;
        display: flex;
        min-height: 0;
        background: var(--vw-panel);
      }
      .generator-overlay vw-generator-view {
        flex: 1;
        min-height: 0;
      }
      textarea.input {
        min-height: 116px;
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
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 14px;
      }
      .grid .deletion-field { grid-column: 1 / -1; }
      .grid .input { height: 38px; padding: 0 9px; }
      .block { width: 100%; }
      .list { display: flex; flex-direction: column; gap: 0; }
      .list-title { display: flex; align-items: center; gap: 8px; margin: 0; font-size: 12px; font-weight: 650; color: var(--vw-text-3); padding: 0 0 10px; }
      .list-title span { color: var(--vw-muted); font-size: 11px; font-weight: 500; }
      .list-surface { overflow: hidden; border: 1px solid var(--vw-line-1); border-radius: var(--vw-radius-card); background: var(--vw-card); }
      .send-row {
        border: 0;
        border-radius: 0;
        padding: 14px;
        background: var(--vw-card);
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .send-row + .send-row { border-top: 1px solid var(--vw-line-1); }
      .send-row.ended .send-tile { background: var(--vw-fill); color: var(--vw-muted); }
      .send-row.ended .badge { background: var(--vw-fill); }
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
        line-height: 1.6;
        overflow-wrap: anywhere;
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
        justify-content: space-between;
      }
      .copy-link { min-height: 32px; padding: 5px 10px; font-size: 11px; }
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
        flex-wrap: wrap;
      }
      .delete-confirm .delete-copy { flex: 1 1 100%; font-size: 12px; overflow-wrap: anywhere; }
      .delete-copy .field-hint { margin-top: 5px; }
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

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('pending') || changed.has('status')) {
      if (!this.pending && this.submitting && (this.wasPending || changed.has('status'))) {
        this.onRequestComplete();
      }
      this.wasPending = this.pending;
    }
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (changed.has('creating') && this.creating) {
      const deletion = this.renderRoot.querySelector<HTMLSelectElement>('[data-deletion]');
      if (deletion) deletion.value = String(SEND_DATE_PRESET_HOURS.fourteenDays);
      const expiry = this.renderRoot.querySelector<HTMLSelectElement>('[data-expiry]');
      if (expiry) expiry.value = String(SEND_DATE_PRESET_HOURS.sevenDays);
    }
  }

  override disconnectedCallback(): void {
    this.draftRevision += 1;
    this.submitting = null;
    this.generatorOwner = null;
    super.disconnectedCallback();
  }

  /** After a matching create/update round-trip, discard the submitted draft only on explicit success. */
  private onRequestComplete(): void {
    const submission = this.submitting;
    this.submitting = null;
    if (!submission || submission.revision !== this.draftRevision) return;
    if (this.status?.tone !== 'success' && this.status?.tone !== 'warning') return;
    if (submission.kind === 'create' && this.creating) this.resetCreateForm();
    if (submission.kind === 'edit' && this.editSource?.id === submission.ownerId) this.resetEditForm();
  }

  private resetCreateForm(shouldRestoreFocus = true): void {
    const wasCreating = this.creating;
    for (const sel of ['[data-name]', '[data-notes]', '[data-text]', '[data-file]', '[data-password]']) {
      const el = this.renderRoot.querySelector<HTMLInputElement | HTMLTextAreaElement>(sel);
      if (el) el.value = '';
    }
    this.draftRevision += 1;
    this.draftBaseline = undefined;
    this.validationError = undefined;
    this.generatorOwner = null;
    this.creating = false;
    this.mode = 'text';
    if (shouldRestoreFocus && wasCreating) this.focusAfterRender('[data-new-send]', '[data-back]');
  }

  private openCreate(): void {
    if (this.pending || this.encoding) return;
    this.draftRevision += 1;
    this.mode = 'text';
    this.generatorOwner = null;
    this.creating = true;
    this.draftBaseline = this.createBaseline();
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
    const el = this.renderRoot.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(sel);
    return el?.value ?? '';
  }

  private readChecked(sel: string): boolean {
    return this.renderRoot.querySelector<HTMLInputElement>(sel)?.checked ?? false;
  }

  private createBaseline(): SendDraftSnapshot {
    return normalizeSendDraft({
      owner: 'create',
      type: 'text',
      passwordMode: 'none',
      expirationHours: SEND_DATE_PRESET_HOURS.sevenDays,
      deletionHours: SEND_DATE_PRESET_HOURS.fourteenDays,
    });
  }

  private currentCreateDraft(): SendDraftSnapshot {
    const password = this.readValue('[data-password]');
    const file = this.renderRoot.querySelector<HTMLInputElement>('[data-file]')?.files?.[0];
    return normalizeSendDraft({
      owner: 'create',
      type: this.mode,
      name: this.readValue('[data-name]'),
      notes: this.readValue('[data-notes]'),
      text: this.readValue('[data-text]'),
      ...(file ? { file } : {}),
      hidden: this.readChecked('[data-hidden]'),
      hideEmail: this.readChecked('[data-hide-email]'),
      passwordMode: password ? 'set' : 'none',
      password,
      expirationHours: this.readValue('[data-expiry]'),
      deletionHours: this.readValue('[data-deletion]'),
      maxAccessCount: this.readValue('[data-max]'),
    });
  }

  private editBaseline(send: SendSummary): SendDraftSnapshot {
    return normalizeSendDraft({
      owner: `edit:${send.id}`,
      type: send.type === 1 ? 'file' : 'text',
      name: send.name,
      notes: send.notesUnavailable ? '' : (send.notes ?? ''),
      text: send.type === 0 ? (send.text ?? '') : '',
      hidden: send.type === 0 && send.hidden,
      disabled: send.disabled,
      hideEmail: send.hideEmail,
      passwordMode: 'keep',
      maxAccessCount: send.maxAccessCount ?? null,
    });
  }

  private currentEditDraft(send: SendSummary): SendDraftSnapshot {
    const password = this.readValue('[data-e-password]');
    const removePassword = this.readChecked('[data-e-removepw]');
    return normalizeSendDraft({
      owner: `edit:${send.id}`,
      type: send.type === 1 ? 'file' : 'text',
      name: this.readValue('[data-e-name]'),
      notes: send.notesUnavailable ? '' : this.readValue('[data-e-notes]'),
      text: send.type === 0 ? this.readValue('[data-e-text]') : '',
      hidden: send.type === 0 && this.readChecked('[data-e-hidden]'),
      disabled: this.readChecked('[data-e-disabled]'),
      hideEmail: this.readChecked('[data-e-hide-email]'),
      passwordMode: removePassword ? 'remove' : password ? 'set' : 'keep',
      password,
      expirationHours: this.readValue('[data-e-expiry]'),
      deletionHours: this.readValue('[data-e-deletion]'),
      maxAccessCount: this.readValue('[data-e-max]'),
    });
  }

  private currentDraft(): SendDraftSnapshot | undefined {
    if (this.editSource) return this.currentEditDraft(this.editSource);
    if (this.creating) return this.currentCreateDraft();
    return undefined;
  }

  private openPasswordGenerator(kind: 'create' | 'edit', id?: string): void {
    if (this.pending || this.encoding) return;
    if (kind === 'create') {
      if (!this.creating || this.editSource) return;
      this.generatorOwner = { kind, revision: this.draftRevision };
      return;
    }
    if (!id || this.editSource?.id !== id || this.editingId !== id) return;
    this.generatorOwner = { kind, id, revision: this.draftRevision };
  }

  private closePasswordGenerator(event?: Event): void {
    event?.stopPropagation();
    this.generatorOwner = null;
  }

  private applyGeneratedPassword(event: CustomEvent<GeneratorSelectionDetail>): void {
    event.stopPropagation();
    const owner = this.generatorOwner;
    const { target, value } = event.detail;
    if (!owner
      || owner.revision !== this.draftRevision
      || target !== 'password'
      || typeof value !== 'string'
      || !value
      || value.length > 1_024) return;
    const selector = owner.kind === 'create' ? '[data-password]' : '[data-e-password]';
    if (owner.kind === 'edit'
      && (this.editSource?.id !== owner.id || this.editingId !== owner.id)) return;
    const input = this.renderRoot.querySelector<HTMLInputElement>(selector);
    if (!input) return;
    input.value = value;
    if (owner.kind === 'edit') {
      const remove = this.renderRoot.querySelector<HTMLInputElement>('[data-e-removepw]');
      if (remove) remove.checked = false;
    }
    this.closePasswordGenerator();
  }

  /** Used by the parent before user-initiated navigation away from the Send route. */
  sendFormHasEdits(): boolean {
    return sendDraftHasEdits(this.draftBaseline, this.currentDraft());
  }

  promptForUnsavedEdits(): boolean {
    if ((this.creating || this.editSource) && (this.pending || this.encoding)) return false;
    if (!this.sendFormHasEdits()) return true;
    return typeof window === 'undefined' || window.confirm(t('send.unsavedChanges'));
  }

  private resetEditForm(restoreFocus = true): void {
    const hadEdit = this.editSource !== undefined;
    this.draftRevision += 1;
    this.draftBaseline = undefined;
    this.editingId = null;
    this.editSource = undefined;
    this.validationError = undefined;
    this.generatorOwner = null;
    if (restoreFocus && hadEdit) this.focusAfterRender('[data-new-send]', '[data-back]');
  }

  private discardActiveDraft(): void {
    if (this.editSource) this.resetEditForm(false);
    if (this.creating) this.resetCreateForm(false);
  }

  private closeCreate(): void {
    if (this.pending || this.encoding || !this.promptForUnsavedEdits()) return;
    this.resetCreateForm();
  }

  private closeEdit(): void {
    if (this.pending || this.encoding || !this.promptForUnsavedEdits()) return;
    this.resetEditForm();
  }

  private openEdit(send: SendSummary): void {
    if (this.pending || this.encoding) return;
    if ((this.creating || this.editSource) && !this.promptForUnsavedEdits()) return;
    this.discardActiveDraft();
    const source = { ...send };
    this.draftRevision += 1;
    this.editingId = source.id;
    this.editSource = source;
    this.generatorOwner = null;
    this.draftBaseline = this.editBaseline(source);
    this.validationError = undefined;
  }

  private changeCreateMode(mode: SendMode): void {
    if (mode === this.mode || this.pending || this.encoding) return;
    const variantHasValue = this.mode === 'text'
      ? this.readValue('[data-text]') !== '' || this.readChecked('[data-hidden]')
      : Boolean(this.renderRoot.querySelector<HTMLInputElement>('[data-file]')?.files?.[0]);
    if (variantHasValue && typeof window !== 'undefined' && !window.confirm(t('send.unsavedChanges'))) return;
    this.mode = mode;
    this.validationError = undefined;
  }

  private back(): void {
    if (this.pending || this.encoding) return;
    if (!this.promptForUnsavedEdits()) return;
    this.discardActiveDraft();
    emit(this, 'vw-item-back');
  }

  private receive(): void {
    if (this.pending || this.encoding) return;
    if (!this.promptForUnsavedEdits()) return;
    this.discardActiveDraft();
    emit(this, 'vw-send-receive');
  }

  private copyUrl(url: string): void {
    if (this.pending || this.encoding) return;
    emit<CopyDetail>(this, 'vw-copy', { value: url, label: t('options.send.copyLink') });
  }

  private deleteSend(id: string): void {
    if (this.pending || this.encoding || this.confirmingDeleteId !== id) return;
    this.confirmingDeleteId = null;
    this.deleteTrigger = null;
    this.focusAfterRender(this.creating ? '[data-name]' : '[data-new-send]', '[data-back]');
    emit<SendDeleteDetail>(this, 'vw-send-delete', { id });
  }

  private promptDelete(id: string, trigger: HTMLButtonElement): void {
    if (this.pending || this.encoding) return;
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
      deletionHours: Number(this.readValue('[data-deletion]')) || SEND_DATE_PRESET_HOURS.fourteenDays,
      hideEmail: this.readChecked('[data-hide-email]'),
    };
    const notes = this.readValue('[data-notes]');
    if (notes) input.notes = notes;
    const password = this.readValue('[data-password]');
    if (password) input.password = password;
    const expiry = Number(this.readValue('[data-expiry]'));
    if (expiry > 0) input.expirationHours = expiry;
    const max = Number(this.readValue('[data-max]'));
    if (max > 0) input.maxAccessCount = max;
    return input;
  }

  private async create(): Promise<void> {
    if (this.pending || this.encoding) return;
    this.validationError = undefined;
    const base = this.baseInput();
    const rawName = this.readValue('[data-name]').trim();
    if (base.expirationHours !== undefined && base.expirationHours > base.deletionHours!) {
      this.validationError = t('send.dateOrderError');
      this.focusAfterRender('[data-expiry]');
      return;
    }

    if (this.mode === 'file') {
      const file = this.renderRoot.querySelector<HTMLInputElement>('[data-file]')?.files?.[0];
      if (!file) { this.validationError = t('send.error.fileRequired'); return; }
      const fileSize = file.size;
      if (!Number.isSafeInteger(fileSize) || fileSize < 0 || fileSize > MAX_FILE_BYTES) {
        this.validationError = t('send.error.fileTooLarge', { max: '100 MB' });
        return;
      }
      this.submitting = { kind: 'create', revision: this.draftRevision };
      emit<SendCreateDetail>(this, 'vw-send-create', { kind: 'file', input: { ...base, name: rawName || file.name }, file, fileName: file.name });
      return;
    }

    const text = this.readValue('[data-text]');
    if (!text.trim()) { this.validationError = t('send.error.textRequired'); return; }
    this.submitting = { kind: 'create', revision: this.draftRevision };
    emit<SendCreateDetail>(this, 'vw-send-create', { kind: 'text', input: { ...base, text, hidden: this.readChecked('[data-hidden]') } });
  }

  private saveEdit(send: SendSummary): void {
    if (this.pending) return;
    this.validationError = undefined;
    const input: UpdateSendInput = {
      name: this.readValue('[data-e-name]').trim() || t('send.defaultName'),
      disabled: this.readChecked('[data-e-disabled]'),
      hideEmail: this.readChecked('[data-e-hide-email]'),
    };
    if (!send.notesUnavailable) input.notes = this.readValue('[data-e-notes]');
    if (send.type === 0) {
      input.text = this.readValue('[data-e-text]');
      input.hidden = this.readChecked('[data-e-hidden]');
    }
    const max = Number(this.readValue('[data-e-max]'));
    input.maxAccessCount = max > 0 ? max : 0; // 0 clears the limit
    const expiry = Number(this.readValue('[data-e-expiry]'));
    if (expiry > 0) input.expirationHours = expiry;
    const deletion = Number(this.readValue('[data-e-deletion]'));
    if (deletion > 0) input.deletionHours = deletion;
    const now = Date.now();
    const expiresAt = expiry > 0 ? now + expiry * 3_600_000 : send.expirationDate ? Date.parse(send.expirationDate) : undefined;
    const deletesAt = deletion > 0 ? now + deletion * 3_600_000 : Date.parse(send.deletionDate);
    if (expiresAt !== undefined && expiresAt > deletesAt) {
      this.validationError = t('send.dateOrderError');
      this.focusAfterRender('[data-e-expiry]');
      return;
    }
    if (this.readChecked('[data-e-removepw]')) input.passwordMode = 'remove';
    else if (this.readValue('[data-e-password]')) { input.passwordMode = 'set'; input.newPassword = this.readValue('[data-e-password]'); }
    else input.passwordMode = 'keep';

    this.submitting = { kind: 'edit', revision: this.draftRevision, ownerId: send.id };
    emit<SendUpdateDetail>(this, 'vw-send-update', { id: send.id, input });
  }

  private renderStatus() {
    if (!this.status) return nothing;
    return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
  }

  private renderPasswordGeneratorOverlay() {
    if (!this.generatorOwner) return nothing;
    return html`
      <div class="generator-overlay" data-generator-overlay>
        <vw-generator-view
          .history=${this.generatorHistory}
          .generatorPolicy=${this.generatorPolicy}
          .accountEmail=${this.generatorAccountEmail}
          .selectionTarget=${'password'}
          @vw-generator-select=${(event: CustomEvent<GeneratorSelectionDetail>) => this.applyGeneratedPassword(event)}
          @vw-item-back=${(event: Event) => this.closePasswordGenerator(event)}
        ></vw-generator-view>
      </div>
    `;
  }

  private renderDatePresetOptions(blankLabel?: string, selectedHours?: number) {
    return html`
      ${blankLabel === undefined ? nothing : html`<option value="">${blankLabel}</option>`}
      ${SEND_DATE_PRESETS.map(({ hours, label }) => hours === selectedHours
        ? html`<option value=${String(hours)} selected>${t(label)}</option>`
        : html`<option value=${String(hours)}>${t(label)}</option>`)}
    `;
  }

  private renderEdit(send: SendSummary) {
    const back = t('common.back');
    return html`
      <div class="head">
        <button type="button" class="icon-btn sm" data-back title=${back} aria-label=${back} ?disabled=${this.pending || this.encoding} @click=${() => this.closeEdit()}>${uiIcon('back')}</button>
        <h1>${t('send.editTitle')}</h1>
      </div>
      <div class="content">
        <div class="card form-card">
          <section class="form-section" aria-labelledby="edit-content-title">
          <h2 id="edit-content-title">${t('send.formContent')}</h2>
          <span class="section-label">${send.type === 1 ? t('send.typeFile') : t('send.typeText')}${send.fileName ? ` · ${send.fileName}` : ''}</span>
          <label class="field"><span>${t('options.send.name')}</span><input class="input" data-e-name .value=${send.name} ?disabled=${this.pending} /></label>
          ${send.type === 0
            ? html`
                <label class="field"><span>${t('send.text')}</span><textarea class="input" data-e-text .value=${send.text ?? ''} ?disabled=${this.pending}></textarea></label>
                <label class="check"><input type="checkbox" data-e-hidden .checked=${send.hidden} ?disabled=${this.pending} /><span>${t('send.hideText')}</span></label>`
            : nothing}
          </section>
          <section class="form-section" aria-labelledby="edit-protection-title">
          <h2 id="edit-protection-title">${t('send.formProtection')}</h2>
          <label class="check"><input type="checkbox" data-e-hide-email .checked=${send.hideEmail} ?disabled=${this.pending} /><span>${t('send.hideEmail')}</span></label>
          <label class="field" for="edit-send-password">${t('options.send.accessPassword')}</label>
          <div class="password-row">
            <input class="input" id="edit-send-password" data-e-password type="password" placeholder=${t('send.passwordKeep')} autocomplete="new-password" ?disabled=${this.pending} />
            <button
              type="button"
              class="icon-btn sm"
              data-generate-password="edit"
              title=${t('editor.generatePassword')}
              aria-label=${t('editor.generatePassword')}
              ?disabled=${this.pending || this.encoding}
              @click=${() => this.openPasswordGenerator('edit', send.id)}
            >${uiIcon('wand')}</button>
          </div>
          ${send.passwordProtected
            ? html`<label class="check"><input type="checkbox" data-e-removepw ?disabled=${this.pending} /><span>${t('send.removePassword')}</span></label>`
            : nothing}
          <p class="field-hint">${t('send.passwordHint')}</p>
          </section>
          <section class="form-section" aria-labelledby="edit-limits-title">
          <h2 id="edit-limits-title">${t('send.formLimits')}</h2>
          <div class="grid">
            <label class="field"><span>${t('send.expirationDays')}</span><select class="input" data-e-expiry ?disabled=${this.pending}>${this.renderDatePresetOptions(t('send.keepCurrentDate'))}</select><span class="field-hint">${send.expirationDate ? this.formatDate(send.expirationDate) : t('send.noSeparateExpiration')}</span></label>
            <label class="field"><span>${t('send.maxViews')}</span><input class="input" data-e-max type="number" min="0" .value=${send.maxAccessCount != null ? String(send.maxAccessCount) : ''} ?disabled=${this.pending} /></label>
            <label class="field deletion-field"><span>${t('send.deletionDays')}</span><select class="input" data-e-deletion ?disabled=${this.pending}>${this.renderDatePresetOptions(t('send.keepCurrentDate'))}</select><span class="field-hint">${this.formatDate(send.deletionDate)} · ${t('send.deletionHint')}</span></label>
          </div>
          <label class="check"><input type="checkbox" data-e-disabled .checked=${send.disabled} ?disabled=${this.pending} /><span>${t('send.disabled')}</span></label>
          <p class="field-hint">${t('send.copiesRemain')}</p>
          </section>
          <details class="private-notes" ?open=${send.notesUnavailable}>
            <summary>${t('send.privateNotes')}</summary>
            ${send.notesUnavailable
              ? html`<vw-status-message tone="warning" .icon=${'alert'} .message=${t('send.notesUnavailable')}></vw-status-message>`
              : html`<label class="field"><span>${t('send.privateNotes')}</span><textarea class="input" data-e-notes .value=${send.notes ?? ''} ?disabled=${this.pending}></textarea></label>`}
          </details>
          ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
          <div class="form-actions"><button type="button" class="btn primary block" data-save ?disabled=${this.pending} @click=${() => this.saveEdit(send)}>${uiIcon('check')}<span>${t('common.save')}</span></button></div>
        </div>
        ${this.renderStatus()}
      </div>
      ${this.renderPasswordGeneratorOverlay()}
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
          <button type="button" class="btn primary" data-new-send ?disabled=${this.pending || this.encoding} @click=${() => this.openCreate()}>${uiIcon('plus')}<span>${t('common.add')}</span></button>
        </div>
        <button type="button" class="btn outline block" data-receive ?disabled=${this.pending || this.encoding} @click=${() => this.receive()}>${uiIcon('mail')}<span>${t('send.receive')}</span></button>
      `;
    }
    return html`
      <div class="card form-card">
        <div class="card-head">
          <span class="section-label">${t('options.send.new')}</span>
          <button type="button" class="icon-btn sm" data-cancel-create title=${t('common.close')} aria-label=${t('common.close')} ?disabled=${this.pending || this.encoding} @click=${() => this.closeCreate()}>${uiIcon('close')}</button>
        </div>
        <div class="seal">${uiIcon('lock')}<span>${t('send.localEncryption')}</span></div>
        <section class="form-section" aria-labelledby="create-content-title">
        <h2 id="create-content-title">${t('send.formContent')}</h2>
        <div class="seg" role="tablist">
          <button type="button" class="seg-btn ${this.mode === 'text' ? 'is-active' : ''}" data-mode-text role="tab"
            aria-selected=${this.mode === 'text' ? 'true' : 'false'} ?disabled=${this.pending || this.encoding}
            @click=${() => this.changeCreateMode('text')}>${t('options.send.typeText')}</button>
          <button type="button" class="seg-btn ${this.mode === 'file' ? 'is-active' : ''}" data-mode-file role="tab"
            aria-selected=${this.mode === 'file' ? 'true' : 'false'} ?disabled=${this.pending || this.encoding}
            @click=${() => this.changeCreateMode('file')}>${t('options.send.typeFile')}</button>
        </div>
        <label class="field"><span>${t('options.send.name')}</span><input class="input" data-name placeholder=${t('options.send.namePlaceholder')} ?disabled=${this.pending || this.encoding} /></label>
        ${this.mode === 'text'
          ? html`
              <label class="field"><span>${t('send.textToShare')}</span><textarea class="input" data-text placeholder=${t('options.send.contentPlaceholder')} ?disabled=${this.pending || this.encoding}></textarea></label>
              <label class="check"><input type="checkbox" data-hidden ?disabled=${this.pending || this.encoding} /><span>${t('send.hideText')}</span></label>`
          : html`<label class="field"><span>${t('send.fileToShare')}</span><input class="input" data-file type="file" ?disabled=${this.pending || this.encoding} /></label>`}
        </section>
        <section class="form-section" aria-labelledby="create-protection-title">
        <h2 id="create-protection-title">${t('send.formProtection')}</h2>
        <label class="check"><input type="checkbox" data-hide-email ?disabled=${this.pending || this.encoding} /><span>${t('send.hideEmail')}</span></label>
        <label class="field" for="create-send-password">${t('send.passwordOptional')}</label>
        <div class="password-row">
          <input class="input" id="create-send-password" data-password type="password" autocomplete="new-password" ?disabled=${this.pending || this.encoding} />
          <button
            type="button"
            class="icon-btn sm"
            data-generate-password="create"
            title=${t('editor.generatePassword')}
            aria-label=${t('editor.generatePassword')}
            ?disabled=${this.pending || this.encoding}
            @click=${() => this.openPasswordGenerator('create')}
          >${uiIcon('wand')}</button>
        </div>
        <p class="field-hint">${t('send.passwordHint')}</p>
        </section>
        <section class="form-section" aria-labelledby="create-limits-title">
        <h2 id="create-limits-title">${t('send.formLimits')}</h2>
        <div class="grid">
          <label class="field"><span>${t('send.expirationDays')}</span><select class="input" data-expiry ?disabled=${this.pending || this.encoding}>${this.renderDatePresetOptions(t('send.noSeparateExpiration'), SEND_DATE_PRESET_HOURS.sevenDays)}</select><span class="field-hint">${t('send.expirationHint')}</span></label>
          <label class="field"><span>${t('send.maxViews')}</span><input class="input" data-max type="number" min="0" placeholder="—" ?disabled=${this.pending || this.encoding} /></label>
          <label class="field deletion-field"><span>${t('send.deletionDays')}</span><select class="input" data-deletion ?disabled=${this.pending || this.encoding}>${this.renderDatePresetOptions(undefined, SEND_DATE_PRESET_HOURS.fourteenDays)}</select><span class="field-hint">${t('send.deletionHint')}</span></label>
        </div>
        <p class="field-hint">${t('send.copiesRemain')}</p>
        </section>
        <details class="private-notes"><summary>${t('send.privateNotes')}</summary><label class="field"><span>${t('send.privateNotes')}</span><textarea class="input" data-notes ?disabled=${this.pending || this.encoding}></textarea></label></details>
        ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
        <div class="form-actions"><button type="button" class="btn primary block" data-create ?disabled=${this.pending || this.encoding} @click=${() => void this.create()}>
          ${this.encoding
            ? html`<span class="spin" data-encoding>${uiIcon('refresh')}</span><span>${t('send.encoding')}</span>`
            : html`${uiIcon('plus')}<span>${t('send.create')}</span>`}
        </button></div>
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
      case 'ready': {
        const active = sends.data.filter((send) => !this.hasEnded(send));
        const ended = sends.data.filter((send) => this.hasEnded(send));
        return html`
          <section class="list" aria-labelledby="active-sends-title">
            <h2 class="list-title" id="active-sends-title">${t('options.send.active')} <span>${active.length}</span></h2>
            ${active.length ? html`<div class="list-surface">${active.map((send) => this.renderSendRow(send))}</div>` : html`<div class="empty-note">${t('options.send.empty')}</div>`}
          </section>
          ${ended.length ? html`<section class="list" aria-labelledby="ended-sends-title"><h2 class="list-title" id="ended-sends-title">${t('send.ended')} <span>${ended.length}</span></h2><div class="list-surface">${ended.map((send) => this.renderSendRow(send))}</div></section>` : nothing}
          ${this.renderStatus()}
        `;
      }
    }
  }

  private hasEnded(send: SendSummary): boolean {
    return send.disabled || Date.parse(send.deletionDate) <= Date.now()
      || Boolean(send.expirationDate && Date.parse(send.expirationDate) <= Date.now())
      || (send.maxAccessCount != null && send.accessCount >= send.maxAccessCount);
  }

  private formatDate(value: string | number): string {
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return '—';
    return new Intl.DateTimeFormat(getLocale(), { dateStyle: 'short', timeStyle: 'short' }).format(date);
  }

  private renderSendRow(send: SendSummary) {
    const deletionTime = Date.parse(send.deletionDate);
    const expirationTime = send.expirationDate ? Date.parse(send.expirationDate) : Number.POSITIVE_INFINITY;
    const expiresFirst = Number.isFinite(expirationTime) && expirationTime < deletionTime;
    const deadline = expiresFirst ? expirationTime : deletionTime;
    const formattedDeadline = this.formatDate(deadline);
    const ended = this.hasEnded(send);
    const endLabel = send.disabled ? t('send.disabledBadge')
      : deadline <= Date.now() ? t('options.send.expired') : t('send.limitReached');
    const confirming = this.confirmingDeleteId === send.id;
    return html`
      <div class="send-row ${ended ? 'ended' : ''}" data-send=${send.id}>
        <div class="send-head">
          <span class="send-tile">${uiIcon(send.type === 1 ? 'file' : 'text')}</span>
          <span class="send-name">${send.name}</span>
          ${send.passwordProtected ? html`<span title=${t('options.send.accessPassword')}>${uiIcon('lock')}</span>` : nothing}
          ${ended ? html`<span class="badge">${endLabel}</span>` : nothing}
        </div>
        <span class="send-sub">
          ${send.type === 1 && send.fileName ? html`${send.fileName}${send.sizeName ? ` · ${send.sizeName}` : ''} · ` : nothing}${t(expiresFirst ? 'send.expiresOn' : 'send.deletesOn', { date: formattedDeadline })} · ${send.maxAccessCount != null ? t('send.viewsCount', { used: send.accessCount, max: send.maxAccessCount }) : t('send.viewCount', { count: send.accessCount })}
        </span>
        <div class="send-url-row">
          <button type="button" class="btn outline copy-link" data-copy title=${t('options.send.copyLink')} aria-label=${t('send.copyAria')} ?disabled=${this.pending || this.encoding} @click=${() => this.copyUrl(send.url)}>${uiIcon('link')}<span>${t('options.send.copyLink')}</span></button>
          <span class="row-actions">
            <button type="button" class="icon-btn sm" data-edit title=${t('common.edit')} aria-label=${t('send.editAria')} ?disabled=${this.pending || this.encoding} @click=${() => this.openEdit(send)}>${uiIcon('edit')}</button>
            <button type="button" class="icon-btn sm" data-delete title=${t('common.delete')} aria-label=${t('send.deleteAria')} ?disabled=${this.pending || this.encoding} @click=${(event: Event) => this.promptDelete(send.id, event.currentTarget as HTMLButtonElement)}>${uiIcon('trash')}</button>
          </span>
        </div>
        ${confirming
          ? html`<div class="delete-confirm" role="region" aria-live="assertive" aria-label=${t('send.deleteNamed', { name: send.name })}>
              <div class="delete-copy"><strong>${t('send.deleteNamed', { name: send.name })}</strong><p class="field-hint">${t('send.deleteHint')}</p></div>
              <button type="button" class="btn ghost" data-delete-cancel ?disabled=${this.pending || this.encoding} @click=${() => this.cancelDelete()}>${t('common.cancel')}</button>
              <button type="button" class="btn danger" data-delete-confirm ?disabled=${this.pending || this.encoding} @click=${() => this.deleteSend(send.id)}>${t('common.delete')}</button>
            </div>`
          : nothing}
      </div>
    `;
  }

  protected override render() {
    if (this.editSource && this.editingId === this.editSource.id) return this.renderEdit(this.editSource);
    return html`
      <div class="head">
        <button type="button" class="icon-btn sm" data-back title=${t('common.back')} aria-label=${t('common.back')} ?disabled=${this.pending || this.encoding} @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>${t('popup.sends')}</h1>
      </div>
      <div class="content">
        ${this.renderCreate()}
        ${this.renderList()}
      </div>
      ${this.renderPasswordGeneratorOverlay()}
    `;
  }
}

customElements.define('vw-sends-view', VwSendsView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-sends-view': VwSendsView;
  }
}
