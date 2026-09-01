import { LitElement, css, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { emit } from '../../components/emit.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { isKnownCipherType } from '../../../core/vault/models.js';
import { linkedFieldOptionsForCipherType } from '../../../core/vault/linked-fields.js';
import {
  isPasswordProtectedField,
  summaryAllowsCipherAccess,
  type CipherAccessAction,
} from '../../../core/vault/cipher-access.js';
import type {
  CipherSummary,
  DecryptedAttachment,
  DecryptedCipher,
  DecryptedField,
  DecryptedIdentity,
  FieldName,
  SshKeyPublicDetails,
} from '../../../core/vault/models.js';
import type {
  AttachmentAddDetail,
  AttachmentRefDetail,
  CloneItemDetail,
  CopyDetail,
  DeleteItemDetail,
  DetailErrorDetail,
  DetailExtras,
  DetailPresentationCollection,
  DetailPresentationEntity,
  DetailPresentationMetadata,
  DetailStatus,
  FavoriteToggleDetail,
  ItemLifecycleDetail,
  ItemRefDetail,
  PasskeyDeleteDetail,
  PasswordHistoryEntry,
  SecretRequestDetail,
  SshDetailExtras,
  TotpSnapshot,
  VaultMode,
} from '../types.js';
import { fileToBase64, safeWebUrl } from '../utils.js';
import '../../components/dialog.js';
import '../../components/status-message.js';
import '../../components/totp-meter.js';
import type { VwDialog } from '../../components/dialog.js';
import { linkedFieldSourceLabel } from '../linked-field-label.js';

type Confirmation =
  | { kind: 'item'; permanent: boolean }
  | { kind: 'archive' }
  | { kind: 'clone' }
  | { kind: 'passkey'; credentialId: string; name: string }
  | { kind: 'attachment'; attachment: DecryptedAttachment };

export type ItemPrimaryAction = 'fill' | 'open' | 'none';

interface DetailRequestContext {
  cipherId: string;
  extras: DetailExtras;
  generation: number;
}

interface SshRequestContext {
  cipherId: string;
  extras: SshDetailExtras;
  generation: number;
}

const MASK = '••••••••';
// Attachment encryption adds at most 65 bytes before the worker's 128 MiB upload cap.
const MAX_ATTACHMENT_FILE_BYTES = (128 * 1024 * 1024) - 65;

const STATUS_ICON: Record<DetailStatus['tone'], IconName> = {
  info: 'refresh',
  success: 'checkCircle',
  warning: 'alert',
  danger: 'alert',
};

const EMPTY_SUMMARY: CipherSummary = {
  id: '',
  name: '',
  uris: [],
  loginUris: [],
  type: 1,
  favorite: false,
};

function linkedLabel(type: DecryptedCipher['type'], linkedId: number | undefined): string {
  const option = linkedFieldOptionsForCipherType(type).find(({ id }) => id === linkedId);
  return option ? t('detail.linkedTo', { name: linkedFieldSourceLabel(option.source) }) : t('detail.linkedField');
}

/**
 * Full-height presentation for one vault item. The host owns every worker request; this component
 * only emits typed commands or invokes the injected, item-scoped loaders. Secret-bearing results
 * are generation-scoped and are discarded when the item, loaders, vault mode, or connection changes.
 */
export class VwItemDetail extends LitElement {
  static override properties = {
    summary: { attribute: false },
    cipher: { attribute: false },
    extras: { attribute: false },
    presentationMetadata: { attribute: false },
    sshKey: { attribute: false },
    sshExtras: { attribute: false },
    sshEditable: { type: Boolean },
    status: { attribute: false },
    pending: { type: Boolean },
    mode: { type: String },
    primaryAction: { type: String },
  };

  declare summary: CipherSummary;
  declare cipher: DecryptedCipher | null;
  declare extras: DetailExtras | undefined;
  declare presentationMetadata: DetailPresentationMetadata | undefined;
  declare sshKey: SshKeyPublicDetails | null | undefined;
  declare sshExtras: SshDetailExtras | undefined;
  declare sshEditable: boolean;
  declare status: DetailStatus | undefined;
  declare pending: boolean;
  declare mode: VaultMode;
  declare primaryAction: ItemPrimaryAction;

  private i18n = new LocalizeController(this);
  private detailGeneration = 0;
  private revealed = new Map<string, string>();
  private loadingSecrets = new Set<string>();
  private history: PasswordHistoryEntry[] | null = null;
  private historyLoadingGeneration: number | undefined;
  private totp: TotpSnapshot | undefined;
  private totpLoadingGeneration: number | undefined;
  private totpStartedGeneration: number | undefined;
  private totpTimer: number | undefined;
  private encodingGeneration: number | undefined;
  private confirmation: Confirmation | null = null;
  private confirmationTrigger: HTMLElement | null = null;
  private localStatus: DetailStatus | undefined;
  private lifecycleSubmitted = false;

  constructor() {
    super();
    this.summary = EMPTY_SUMMARY;
    this.cipher = null;
    this.extras = undefined;
    this.presentationMetadata = undefined;
    this.sshKey = undefined;
    this.sshExtras = undefined;
    this.sshEditable = false;
    this.status = undefined;
    this.pending = false;
    this.mode = 'active';
    this.primaryAction = 'none';
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: flex;
        flex: 1;
        flex-direction: column;
        width: 100%;
        height: 100%;
        min-height: 0;
        background: var(--vw-panel);
      }
      .head {
        display: flex;
        flex: none;
        align-items: center;
        gap: 8px;
        min-height: 54px;
        padding: 7px 10px;
        border-bottom: 1px solid var(--vw-line-1);
      }
      .head .icon-btn { flex: none; }
      .head-copy { flex: 1; min-width: 0; }
      .favorite-toggle[aria-pressed='true'] { color: var(--vw-sync-amber); }
      .favorite-toggle[aria-pressed='true'] svg { fill: currentColor; }
      h1 {
        margin: 0;
        overflow: hidden;
        color: var(--vw-ink);
        font-size: 14px;
        font-weight: 600;
        line-height: 1.25;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .type { margin-top: 1px; color: var(--vw-muted); font-size: 10.5px; }
      .body {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        scrollbar-color: var(--vw-scrollbar) transparent;
        scrollbar-width: thin;
      }
      .body::-webkit-scrollbar { width: 6px; }
      .body::-webkit-scrollbar-thumb {
        border: 2px solid transparent;
        border-radius: 4px;
        background: var(--vw-scrollbar);
        background-clip: content-box;
      }
      .status { display: block; margin: 10px 12px 0; }
      .section { padding: 4px 14px 0; border-bottom: 1px solid var(--vw-line-1); }
      .section-title {
        display: flex;
        align-items: center;
        gap: 7px;
        min-height: 35px;
        margin: 0;
        color: var(--vw-muted);
        font-size: 11px;
        font-weight: 600;
      }
      .section-title svg { width: 14px; height: 14px; color: var(--vw-text-2); }
      .field {
        display: grid;
        grid-template-columns: minmax(84px, 32%) minmax(0, 1fr) auto;
        align-items: center;
        gap: 8px;
        min-height: 42px;
        padding: 6px 0;
        border-top: 1px solid var(--vw-line-1);
      }
      .field.multiline { align-items: start; }
      .label { color: var(--vw-muted); font-size: 11.5px; }
      .value {
        min-width: 0;
        overflow-wrap: anywhere;
        color: var(--vw-ink);
        font-size: 12.5px;
      }
      .value.mono { font-family: var(--vw-font-mono); font-size: 12px; }
      .value.masked {
        color: var(--vw-text-2);
        letter-spacing: 0.08em;
        user-select: none;
      }
      .value.pre { margin: 0; white-space: pre-wrap; }
      .field-actions { display: flex; align-items: center; gap: 2px; }
      .field-actions .icon-btn svg { width: 14px; height: 14px; }
      .location-field { grid-template-columns: minmax(84px, 32%) minmax(0, 1fr); }
      a.value { color: var(--vw-teal-text); text-decoration: none; }
      a.value:hover { text-decoration: underline; }
      .totp-wrap { min-width: 0; }
      .totp-placeholder, .empty, .loading { color: var(--vw-muted); font-size: 12px; }
      .passkey-list { display: flex; flex-direction: column; }
      .attachment-name { display: flex; min-width: 0; align-items: center; gap: 7px; }
      .attachment-name svg { width: 14px; height: 14px; flex: none; color: var(--vw-muted); }
      .attachment-name span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .history-field { grid-template-columns: minmax(0, 1fr) auto; }
      .history-entry { grid-template-columns: minmax(0, 1fr) auto auto; }
      .history-date { color: var(--vw-muted); font-size: 10.5px; white-space: nowrap; }
      .section-actions {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        min-height: 48px;
        border-top: 1px solid var(--vw-line-1);
      }
      .upload { position: relative; min-height: 34px; padding: 0 12px; font-size: 12px; }
      .upload.disabled { cursor: default; opacity: 0.5; }
      .file-input {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip: rect(0 0 0 0);
        clip-path: inset(50%);
        white-space: nowrap;
      }
      .primary-actions, .danger-zone, .lifecycle-actions {
        display: flex;
        gap: 8px;
        padding: 12px 14px;
      }
      .primary-actions .btn { flex: 1; min-width: 0; }
      .danger-zone { justify-content: flex-end; padding-top: 4px; }
      .danger-zone .btn { min-height: 34px; padding: 0 13px; font-size: 12px; }
      .inactive-panel {
        display: flex;
        min-height: 100%;
        flex-direction: column;
        justify-content: center;
        padding: 20px 14px;
      }
      .inactive-copy { margin: 0 auto 12px; color: var(--vw-muted); font-size: 12px; text-align: center; }
      .lifecycle-actions { flex-direction: column; padding: 0; }
      vw-dialog p { margin: 0; color: var(--vw-text-2); font-size: 12.5px; }
      vw-dialog .btn { min-height: 36px; padding: 0 14px; font-size: 12px; }
      @media (max-width: 340px) {
        .field { grid-template-columns: minmax(72px, 29%) minmax(0, 1fr) auto; }
        .primary-actions { flex-direction: column; }
      }
    `,
  ];

  override disconnectedCallback(): void {
    this.invalidateDetailState(true);
    super.disconnectedCallback();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (
      changed.has('summary') ||
      changed.has('cipher') ||
      changed.has('extras') ||
      changed.has('sshKey') ||
      changed.has('sshExtras') ||
      changed.has('mode')
    ) {
      this.lifecycleSubmitted = false;
      this.invalidateDetailState(false);
    }
    if (changed.has('pending') && changed.get('pending') === true && !this.pending) {
      this.lifecycleSubmitted = false;
    }
    if (changed.has('status')) this.lifecycleSubmitted = false;
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (
      changed.has('summary') ||
      changed.has('cipher') ||
      changed.has('extras') ||
      changed.has('sshKey') ||
      changed.has('sshExtras') ||
      changed.has('mode')
    ) {
      this.ensureTotpStarted();
    }
  }

  private get displayMode(): VaultMode {
    if (this.mode === 'trash' || this.summary.deletedDate) return 'trash';
    if (this.mode === 'archive' || this.summary.archivedDate) return 'archive';
    return 'active';
  }

  private get isInactive(): boolean {
    return this.displayMode !== 'active';
  }

  private get isDeleted(): boolean {
    return this.displayMode === 'trash';
  }

  private get isUnsupported(): boolean {
    return this.summary.unsupported === true || !isKnownCipherType(this.summary.type);
  }

  private get isBusy(): boolean {
    return this.pending
      || this.lifecycleSubmitted
      || this.encodingGeneration === this.detailGeneration;
  }

  private allows(action: CipherAccessAction): boolean {
    return summaryAllowsCipherAccess(this.summary, action);
  }

  private get canEditFullItem(): boolean {
    if (this.isDeleted || !this.allows('edit')) return false;
    if (this.summary.hasTotp && !this.allows('viewTotp')) return false;
    const containsPasswordLikeValue = this.summary.type === 1
      || this.summary.type === 5
      || this.cipher?.fields?.some((field) => field.type === 1);
    return !containsPasswordLikeValue || this.allows('viewPassword');
  }

  private get canCloneItem(): boolean {
    return !this.isDeleted
      && !this.isUnsupported
      && this.summary.type !== 5
      && this.allows('clone')
      && this.canEditFullItem;
  }

  private invalidateDetailState(requestUpdate: boolean): void {
    this.detailGeneration += 1;
    this.clearTotpTimer();
    this.revealed = new Map();
    this.loadingSecrets = new Set();
    this.history = null;
    this.historyLoadingGeneration = undefined;
    this.totp = undefined;
    this.totpLoadingGeneration = undefined;
    this.totpStartedGeneration = undefined;
    this.encodingGeneration = undefined;
    this.confirmation = null;
    this.confirmationTrigger = null;
    this.localStatus = undefined;
    if (requestUpdate) this.requestUpdate();
  }

  private requestContext(): DetailRequestContext | undefined {
    if (!this.summary.id || !this.extras || this.isUnsupported) return undefined;
    return {
      cipherId: this.summary.id,
      extras: this.extras,
      generation: this.detailGeneration,
    };
  }

  private isCurrent(context: DetailRequestContext): boolean {
    return (
      this.isConnected &&
      this.summary.id === context.cipherId &&
      this.extras === context.extras &&
      this.detailGeneration === context.generation
    );
  }

  private sshRequestContext(): SshRequestContext | undefined {
    if (!this.summary.id || !this.sshExtras || this.isUnsupported || this.summary.type !== 5) return undefined;
    return { cipherId: this.summary.id, extras: this.sshExtras, generation: this.detailGeneration };
  }

  private isCurrentSsh(context: SshRequestContext): boolean {
    return this.isConnected
      && this.summary.id === context.cipherId
      && this.summary.type === 5
      && this.sshExtras === context.extras
      && this.detailGeneration === context.generation;
  }

  private dispatch<T>(type: string, detail: T): void {
    emit<T>(this, type, detail);
  }

  private toggleFavorite(): void {
    if (this.isBusy || this.isInactive || this.isUnsupported || !this.summary.id) return;
    this.dispatch<FavoriteToggleDetail>('vw-favorite-toggle', {
      cipherId: this.summary.id,
      favorite: !this.summary.favorite,
    });
  }

  private leave(type: 'vw-item-back' | 'vw-edit-item'): void {
    if (type === 'vw-edit-item' && (this.isUnsupported || !this.canEditFullItem)) return;
    const cipherId = this.summary.id;
    this.invalidateDetailState(true);
    if (type === 'vw-item-back') emit(this, type);
    else this.dispatch<ItemRefDetail>(type, { cipherId });
  }

  private copyValue(value: string | undefined, label: string): void {
    if (!value || this.isUnsupported) return;
    this.dispatch<CopyDetail>('vw-copy', { value, label });
  }

  private requestSecretCopy(detail: SecretRequestDetail): void {
    if (this.isUnsupported) return;
    if (detail.kind === 'field'
      && isPasswordProtectedField(detail.field)
      && !this.allows('viewPassword')) return;
    if (detail.kind === 'customField' && !this.allows('viewPassword')) return;
    this.dispatch<SecretRequestDetail>('vw-secret-request', detail);
  }

  private setSecretLoading(key: string, loading: boolean): void {
    const next = new Set(this.loadingSecrets);
    if (loading) next.add(key);
    else next.delete(key);
    this.loadingSecrets = next;
    this.requestUpdate();
  }

  private hideReveal(key: string): boolean {
    if (!this.revealed.has(key)) return false;
    const next = new Map(this.revealed);
    next.delete(key);
    this.revealed = next;
    this.requestUpdate();
    return true;
  }

  private async toggleFieldReveal(key: string, field: FieldName): Promise<void> {
    if (this.hideReveal(key) || this.loadingSecrets.has(key) || this.pending) return;
    if (isPasswordProtectedField(field) && !this.allows('viewPassword')) return;
    const context = this.requestContext();
    if (!context) return;
    this.setSecretLoading(key, true);
    try {
      const result = await context.extras.getField(field);
      if (!this.isCurrent(context)) return;
      if (result.ok) {
        const next = new Map(this.revealed);
        next.set(key, result.value ?? '');
        this.revealed = next;
        this.requestUpdate();
        await this.updateComplete;
        if (this.isCurrent(context) && this.revealed.get(key) === (result.value ?? '')) {
          result.acknowledgeVisible?.();
        }
      }
    } finally {
      if (this.isCurrent(context)) this.setSecretLoading(key, false);
    }
  }

  private async toggleCustomReveal(index: number): Promise<void> {
    const key = `custom:${index}`;
    if (this.hideReveal(key) || this.loadingSecrets.has(key) || this.pending) return;
    if (!this.allows('viewPassword')) return;
    const context = this.requestContext();
    if (!context) return;
    this.setSecretLoading(key, true);
    try {
      const result = await context.extras.getCustomField(index);
      if (!this.isCurrent(context)) return;
      if (result.ok) {
        const next = new Map(this.revealed);
        next.set(key, result.value ?? '');
        this.revealed = next;
        this.requestUpdate();
        await this.updateComplete;
        if (this.isCurrent(context) && this.revealed.get(key) === (result.value ?? '')) {
          result.acknowledgeVisible?.();
        }
      }
    } finally {
      if (this.isCurrent(context)) this.setSecretLoading(key, false);
    }
  }

  private async toggleHistory(): Promise<void> {
    if (!this.allows('viewPassword')) return;
    if (this.history !== null) {
      this.history = null;
      this.requestUpdate();
      return;
    }
    const context = this.requestContext();
    if (!context || this.pending || this.historyLoadingGeneration === context.generation) return;
    this.historyLoadingGeneration = context.generation;
    this.requestUpdate();
    try {
      const result = await context.extras.getPasswordHistory();
      if (!this.isCurrent(context)) return;
      if (result.ok) this.history = result.history.map((entry) => ({ ...entry }));
    } finally {
      if (this.isCurrent(context) && this.historyLoadingGeneration === context.generation) {
        this.historyLoadingGeneration = undefined;
        this.requestUpdate();
      }
    }
  }

  private async toggleSshPrivateKey(): Promise<void> {
    const key = 'ssh:private';
    if (this.hideReveal(key) || this.loadingSecrets.has(key) || this.pending) return;
    if (!this.allows('viewPassword')) return;
    const context = this.sshRequestContext();
    if (!context) return;
    this.setSecretLoading(key, true);
    try {
      const result = await context.extras.getPrivateKey();
      if (!this.isCurrentSsh(context)) return;
      if (result.ok) {
        const next = new Map(this.revealed);
        next.set(key, result.value ?? '');
        this.revealed = next;
        this.requestUpdate();
      }
    } finally {
      if (this.isCurrentSsh(context)) this.setSecretLoading(key, false);
    }
  }

  private async copySshPrivateKey(): Promise<void> {
    if (this.pending || !this.allows('viewPassword')) return;
    const context = this.sshRequestContext();
    if (!context) return;
    const result = await context.extras.getPrivateKey();
    if (!this.isCurrentSsh(context) || !result.ok || !result.value) return;
    this.copyValue(result.value, t('ssh.privateKey'));
  }

  private ensureTotpStarted(): void {
    if (this.isInactive || this.isUnsupported || this.summary.type !== 1 || !this.summary.hasTotp
      || !this.allows('viewTotp') || !this.extras) return;
    if (this.totpStartedGeneration === this.detailGeneration) return;
    this.totpStartedGeneration = this.detailGeneration;
    void this.loadTotp();
  }

  private async loadTotp(): Promise<void> {
    const context = this.requestContext();
    if (!context || this.totpLoadingGeneration === context.generation) return;
    this.totpLoadingGeneration = context.generation;
    try {
      const result = await context.extras.getTotp();
      if (!this.isCurrent(context)) return;
      if (!result.ok || !result.totp) {
        this.clearTotpTimer();
        this.totp = undefined;
        this.requestUpdate();
        return;
      }
      this.totp = { ...result.totp };
      this.startTotpTimer(context);
      this.requestUpdate();
    } finally {
      if (this.isCurrent(context) && this.totpLoadingGeneration === context.generation) {
        this.totpLoadingGeneration = undefined;
      }
    }
  }

  private startTotpTimer(context: DetailRequestContext): void {
    this.clearTotpTimer();
    this.totpTimer = window.setInterval(() => {
      if (!this.isCurrent(context) || !this.totp) {
        this.clearTotpTimer();
        return;
      }
      if (this.totp.remaining <= 1) {
        this.totp = undefined;
        this.clearTotpTimer();
        this.requestUpdate();
        if (this.totpLoadingGeneration !== context.generation) void this.loadTotp();
        return;
      }
      this.totp = { ...this.totp, remaining: this.totp.remaining - 1 };
      this.requestUpdate();
    }, 1000);
  }

  private clearTotpTimer(): void {
    if (this.totpTimer === undefined) return;
    clearInterval(this.totpTimer);
    this.totpTimer = undefined;
  }

  private async onAttachmentFile(event: Event): Promise<void> {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    const context = this.requestContext();
    if (!file || !context || this.isBusy || this.isDeleted || !this.allows('edit')) return;
    if (this.cipher?.attachments?.some((attachment) => attachment.fileName === file.name)) {
      const message = t('detail.attachmentDuplicateName');
      this.localStatus = { message, tone: 'danger' };
      input.value = '';
      this.dispatch<DetailErrorDetail>('vw-detail-error', { message });
      this.requestUpdate();
      return;
    }
    this.encodingGeneration = context.generation;
    this.localStatus = undefined;
    this.requestUpdate();
    try {
      const dataB64 = await fileToBase64(file, MAX_ATTACHMENT_FILE_BYTES);
      if (!this.isCurrent(context)) return;
      this.dispatch<AttachmentAddDetail>('vw-attachment-add', {
        cipherId: context.cipherId,
        fileName: file.name,
        dataB64,
      });
    } catch {
      if (this.isCurrent(context)) {
        const message = t('detail.attachmentReadFailed');
        this.localStatus = { message, tone: 'danger' };
        this.dispatch<DetailErrorDetail>('vw-detail-error', { message });
      }
    } finally {
      input.value = '';
      if (this.isCurrent(context) && this.encodingGeneration === context.generation) {
        this.encodingGeneration = undefined;
        this.requestUpdate();
      }
    }
  }

  private openItemConfirmation(permanent: boolean, trigger: HTMLElement): void {
    if (this.pending || this.isUnsupported || !this.allows('delete')) return;
    if (permanent !== this.isDeleted) return;
    this.confirmation = { kind: 'item', permanent };
    this.confirmationTrigger = trigger;
    this.requestUpdate();
  }

  private openArchiveConfirmation(trigger: HTMLElement): void {
    if (this.isBusy || this.isUnsupported || this.displayMode !== 'active') return;
    this.confirmation = { kind: 'archive' };
    this.confirmationTrigger = trigger;
    this.requestUpdate();
  }

  private requestClone(trigger: HTMLElement): void {
    if (this.isBusy || !this.canCloneItem) return;
    if (this.summary.hasPasskey) {
      this.confirmation = { kind: 'clone' };
      this.confirmationTrigger = trigger;
      this.requestUpdate();
      return;
    }
    this.dispatch<CloneItemDetail>('vw-clone-item', {
      cipherId: this.summary.id,
      passkeyWarningAcknowledged: false,
    });
  }

  private openAttachmentConfirmation(attachment: DecryptedAttachment, trigger: HTMLElement): void {
    if (this.isBusy || this.isUnsupported || this.isDeleted || !this.allows('edit')) return;
    this.confirmation = { kind: 'attachment', attachment };
    this.confirmationTrigger = trigger;
    this.requestUpdate();
  }

  private openPasskeyConfirmation(
    credentialId: string,
    name: string,
    trigger: HTMLElement,
  ): void {
    if (this.isBusy || this.isUnsupported || this.isDeleted
      || this.summary.type !== 1 || !credentialId
      || !this.allows('edit') || !this.allows('viewPassword')) return;
    this.confirmation = { kind: 'passkey', credentialId, name };
    this.confirmationTrigger = trigger;
    this.requestUpdate();
  }

  private requestConfirmationClose(reason: 'dismiss' | 'confirm'): void {
    if (reason === 'confirm' && this.isBusy) return;
    this.renderRoot.querySelector<VwDialog>('vw-dialog')?.requestClose(reason);
  }

  private handleConfirmationClose(event: CustomEvent<{ reason: string }>): void {
    event.stopPropagation();
    const confirmation = this.confirmation;
    this.confirmation = null;
    const trigger = this.confirmationTrigger;
    this.confirmationTrigger = null;
    if (trigger?.isConnected) trigger.focus();
    if (event.detail.reason !== 'confirm' || !confirmation || this.isBusy) {
      this.requestUpdate();
      return;
    }
    this.commitConfirmation(confirmation);
  }

  private commitConfirmation(confirmation: Confirmation): void {
    if (confirmation.kind === 'archive') {
      this.submitLifecycle('vw-archive-item', {
        action: 'archive',
        cipherId: this.summary.id,
        sourceMode: 'active',
        targetMode: 'archive',
      });
      return;
    }
    if (confirmation.kind === 'clone') {
      if (!this.summary.hasPasskey || !this.canCloneItem) return;
      this.dispatch<CloneItemDetail>('vw-clone-item', {
        cipherId: this.summary.id,
        passkeyWarningAcknowledged: true,
      });
      return;
    }
    if (confirmation.kind === 'item') {
      if (!this.allows('delete')) return;
      const cipherId = this.summary.id;
      const permanent = confirmation.permanent;
      this.invalidateDetailState(true);
      this.dispatch<DeleteItemDetail>('vw-delete-item', { cipherId, permanent });
      return;
    }
    if (confirmation.kind === 'passkey') {
      if (this.isDeleted || !this.allows('edit') || !this.allows('viewPassword')) return;
      this.lifecycleSubmitted = true;
      this.invalidateDetailState(true);
      this.dispatch<PasskeyDeleteDetail>('vw-passkey-delete', {
        cipherId: this.summary.id,
        credentialId: confirmation.credentialId,
      });
      return;
    }
    if (this.isDeleted || !this.allows('edit')) return;
    this.dispatch<AttachmentRefDetail>('vw-attachment-delete', {
      cipherId: this.summary.id,
      attachmentId: confirmation.attachment.id,
      fileName: confirmation.attachment.fileName,
    });
    this.requestUpdate();
  }

  private submitLifecycle(type: 'vw-archive-item' | 'vw-unarchive-item' | 'vw-restore-item', detail: ItemLifecycleDetail): void {
    if (this.isBusy || this.isUnsupported || !this.summary.id) return;
    this.lifecycleSubmitted = true;
    this.invalidateDetailState(true);
    this.dispatch<ItemLifecycleDetail>(type, detail);
  }

  private typeLabel(): string {
    switch (this.summary.type) {
      case 1: return t('editor.typeLogin');
      case 2: return t('editor.typeNote');
      case 3: return t('editor.typeCard');
      case 4: return t('editor.typeIdentity');
      case 5: return t('detail.sshKey');
      default: return t('detail.unsupportedType', { type: this.summary.type });
    }
  }

  private renderHeader(): TemplateResult {
    const editable = !this.isDeleted
      && !this.isUnsupported
      && !this.summary.undecryptable
      && this.canEditFullItem
      && (this.summary.type !== 5 || this.sshEditable);
    const title = this.isUnsupported ? t('detail.unsupportedItem') : this.summary.name;
    const favoriteLabel = t(this.summary.favorite ? 'detail.removeFromFavorites' : 'detail.addToFavorites');
    const canToggleFavorite = !this.isInactive && !this.isUnsupported && Boolean(this.summary.id);
    return html`
      <header class="head">
        <button
          type="button"
          class="icon-btn"
          data-back
          title=${t('common.back')}
          aria-label=${t('common.back')}
          @click=${() => this.leave('vw-item-back')}
        >${uiIcon('back')}</button>
        <div class="head-copy">
          <h1>${title}</h1>
          <div class="type">${this.typeLabel()}</div>
        </div>
        ${canToggleFavorite
          ? html`
              <button
                type="button"
                class="icon-btn favorite-toggle"
                data-favorite-toggle
                title=${favoriteLabel}
                aria-label=${favoriteLabel}
                aria-pressed=${this.summary.favorite ? 'true' : 'false'}
                ?disabled=${this.isBusy}
                @click=${() => this.toggleFavorite()}
              >${uiIcon('star')}</button>
            `
          : nothing}
        ${this.canCloneItem
          ? html`
              <button
                type="button"
                class="icon-btn"
                data-clone
                title=${t('detail.clone')}
                aria-label=${t('detail.clone')}
                ?disabled=${this.isBusy}
                @click=${(event: Event) => this.requestClone(event.currentTarget as HTMLElement)}
              >${uiIcon('copy')}</button>
            `
          : nothing}
        ${editable
          ? html`
              <button
                type="button"
                class="icon-btn"
                data-edit
                title=${t('common.edit')}
                aria-label=${t('common.edit')}
                ?disabled=${this.pending}
                @click=${() => this.leave('vw-edit-item')}
              >${uiIcon('edit')}</button>
            `
          : nothing}
      </header>
    `;
  }

  private renderStatus(): TemplateResult | typeof nothing {
    const status = this.localStatus ?? this.status;
    if (!status) return nothing;
    return html`
      <vw-status-message
        class="status"
        tone=${status.tone}
        .icon=${STATUS_ICON[status.tone]}
        .message=${status.message}
      ></vw-status-message>
    `;
  }

  private renderSection(
    title: string,
    icon: IconName,
    body: TemplateResult | typeof nothing | Array<TemplateResult | typeof nothing>,
  ): TemplateResult {
    return html`
      <section class="section">
        <h2 class="section-title">${uiIcon(icon)}<span>${title}</span></h2>
        ${body}
      </section>
    `;
  }

  private renderPlainField(
    label: string,
    value: string | undefined,
    options: { mono?: boolean; multiline?: boolean; copy?: boolean } = {},
  ): TemplateResult | typeof nothing {
    if (!value) return nothing;
    const copy = options.copy !== false;
    return html`
      <div class="field ${options.multiline ? 'multiline' : ''}">
        <span class="label">${label}</span>
        ${options.multiline
          ? html`<pre class="value pre">${value}</pre>`
          : html`<span class="value ${options.mono ? 'mono' : ''}">${value}</span>`}
        ${copy
          ? html`
              <span class="field-actions">
                <button
                  type="button"
                  class="icon-btn xs"
                  title=${t('common.copy')}
                  aria-label=${`${t('common.copy')} ${label}`}
                  ?disabled=${this.pending}
                  @click=${() => this.copyValue(value, label)}
                >${uiIcon('copy')}</button>
              </span>
            `
          : nothing}
      </div>
    `;
  }

  private presentationEntityName(
    id: string,
    entities: readonly DetailPresentationEntity[] | undefined,
  ): string | undefined {
    const matches = (entities ?? []).filter((entity) => entity.id === id && entity.name.trim().length > 0);
    return matches.length === 1 ? matches[0]!.name.trim() : undefined;
  }

  private presentationCollectionName(
    id: string,
    organizationId: string | undefined,
    collections: readonly DetailPresentationCollection[] | undefined,
  ): string | undefined {
    if (!organizationId) return undefined;
    const matches = (collections ?? []).filter((collection) => (
      collection.id === id
      && collection.organizationId === organizationId
      && collection.name.trim().length > 0
    ));
    return matches.length === 1 ? matches[0]!.name.trim() : undefined;
  }

  private renderLocationField(kind: 'owner' | 'folder' | 'collections', label: string, value: string): TemplateResult {
    return html`
      <div class="field location-field" data-location=${kind}>
        <span class="label">${label}</span>
        <span class="value">${value}</span>
      </div>
    `;
  }

  private renderVaultLocation(): TemplateResult {
    const metadata = this.presentationMetadata;
    const organizationId = this.summary.organizationId;
    const owner = organizationId
      ? this.presentationEntityName(organizationId, metadata?.organizations)
        ?? t('detail.unknownOrganization')
      : t('detail.personalVault');
    const folder = this.summary.folderId
      ? this.presentationEntityName(this.summary.folderId, metadata?.folders)
        ?? t('detail.unknownFolder')
      : t('detail.noFolder');
    const collectionIds = this.summary.collectionIds ?? [];
    const collections = collectionIds.length === 0
      ? t('detail.noCollections')
      : collectionIds.map((id) => (
          this.presentationCollectionName(id, organizationId, metadata?.collections)
          ?? t('detail.unknownCollection')
        )).join(', ');
    return this.renderSection(t('detail.vaultLocation'), 'folder', [
      this.renderLocationField('owner', t('detail.owner'), owner),
      this.renderLocationField('folder', t('detail.folder'), folder),
      this.renderLocationField('collections', t('detail.collections'), collections),
    ]);
  }

  private renderUri(uri: string): TemplateResult {
    const safe = safeWebUrl(uri);
    return html`
      <div class="field">
        <span class="label">${t('detail.uri')}</span>
        ${safe && !this.isInactive
          ? html`<a class="value" data-uri href=${safe} target="_blank" rel="noreferrer">${uri}</a>`
          : html`<span class="value">${uri}</span>`}
        <span class="field-actions">
          <button
            type="button"
            class="icon-btn xs"
            title=${t('common.copy')}
            aria-label=${`${t('common.copy')} ${t('detail.uri')}`}
            ?disabled=${this.pending}
            @click=${() => this.copyValue(uri, t('detail.uri'))}
          >${uiIcon('copy')}</button>
        </span>
      </div>
    `;
  }

  private renderSecretField(
    label: string,
    field: FieldName,
    key = field,
  ): TemplateResult | typeof nothing {
    if (isPasswordProtectedField(field) && !this.allows('viewPassword')) return nothing;
    const shown = this.revealed.has(key);
    const loading = this.loadingSecrets.has(key);
    const value = shown ? this.revealed.get(key) ?? '' : MASK;
    const password = field === 'password';
    return html`
      <div class="field" data-secret-row>
        <span class="label">${label}</span>
        <code class="value mono ${shown ? '' : 'masked'}" ?data-password-value=${password}>${value}</code>
        <span class="field-actions">
          <button
            type="button"
            class="icon-btn xs"
            data-reveal=${field}
            ?data-toggle-password=${password}
            aria-pressed=${shown ? 'true' : 'false'}
            title=${t('detail.reveal')}
            aria-label=${`${t('detail.reveal')} ${label}`}
            ?disabled=${this.pending || loading}
            @click=${() => void this.toggleFieldReveal(key, field)}
          >${uiIcon(shown ? 'eyeOff' : 'eye')}</button>
          <button
            type="button"
            class="icon-btn xs"
            ?data-copy-password=${password}
            title=${t('common.copy')}
            aria-label=${`${t('common.copy')} ${label}`}
            ?disabled=${this.pending}
            @click=${() => this.requestSecretCopy({ kind: 'field', field, label })}
          >${uiIcon('copy')}</button>
        </span>
      </div>
    `;
  }

  private renderLogin(): TemplateResult {
    const username = this.cipher?.username ?? this.summary.username;
    const rows: Array<TemplateResult | typeof nothing> = [
      this.renderPlainField(t('detail.username'), username),
      this.allows('viewPassword')
        ? this.renderSecretField(t('detail.password'), 'password')
        : nothing,
      ...this.summary.uris.map((uri) => this.renderUri(uri)),
    ];
    if (!this.isInactive && this.summary.hasTotp && this.allows('viewTotp')) {
      rows.push(this.renderTotp());
    }
    return this.renderSection(t('editor.typeLogin'), 'user', rows);
  }

  private renderTotp(): TemplateResult {
    return html`
      <div class="field">
        <span class="label">${t('detail.totp')}</span>
        <span class="totp-wrap" data-totp>
          ${this.totp
            ? html`
                <vw-totp-meter
                  .code=${this.totp.code}
                  .period=${this.totp.period}
                  .remaining=${this.totp.remaining}
                ></vw-totp-meter>
              `
            : html`<span class="totp-placeholder">------</span>`}
        </span>
        ${this.totp
          ? html`
              <span class="field-actions">
                <button
                  type="button"
                  class="icon-btn xs"
                  data-copy-totp
                  title=${t('detail.copyCode')}
                  aria-label=${t('detail.copyCode')}
                  ?disabled=${this.pending}
                  @click=${() => this.copyValue(this.totp?.code, t('detail.totp'))}
                >${uiIcon('copy')}</button>
              </span>
            `
          : nothing}
      </div>
    `;
  }

  private renderCard(): TemplateResult {
    const card = this.cipher?.card;
    if (!card) return this.renderSection(t('editor.typeCard'), 'card', html`<p class="loading">${t('common.loading')}</p>`);
    const expiry = [card.expMonth, card.expYear].filter(Boolean).join(' / ');
    return this.renderSection(t('editor.typeCard'), 'card', [
      this.renderPlainField(t('detail.cardAlias'), card.brand),
      this.renderPlainField(t('detail.cardholder'), card.cardholderName),
      this.renderSecretField(t('detail.cardNumber'), 'card.number'),
      this.renderPlainField(t('detail.cardExpiry'), expiry),
      this.renderSecretField(t('detail.cardCode'), 'card.code'),
    ]);
  }

  private renderIdentity(): TemplateResult {
    const identity = this.cipher?.identity;
    if (!identity) return this.renderSection(t('editor.typeIdentity'), 'idcard', html`<p class="loading">${t('common.loading')}</p>`);
    const plainFields: ReadonlyArray<readonly [string, keyof DecryptedIdentity, boolean?]> = [
      [t('detail.identityTitle'), 'title'],
      [t('detail.firstName'), 'firstName'],
      [t('detail.middleName'), 'middleName'],
      [t('detail.lastName'), 'lastName'],
      [t('detail.username'), 'username'],
      [t('detail.company'), 'company'],
      [t('detail.email'), 'email'],
      [t('detail.phone'), 'phone'],
      [t('detail.address1'), 'address1', true],
      [t('detail.address2'), 'address2', true],
      [t('detail.address3'), 'address3', true],
      [t('detail.city'), 'city'],
      [t('detail.state'), 'state'],
      [t('detail.postalCode'), 'postalCode'],
      [t('detail.country'), 'country'],
    ];
    return this.renderSection(t('editor.typeIdentity'), 'idcard', [
      ...plainFields.map(([label, key, multiline]) => this.renderPlainField(label, identity[key], { multiline: Boolean(multiline) })),
      this.renderSecretField(t('detail.ssn'), 'identity.ssn'),
      this.renderSecretField(t('detail.passportNumber'), 'identity.passportNumber'),
      this.renderSecretField(t('detail.licenseNumber'), 'identity.licenseNumber'),
    ]);
  }

  private renderNote(): TemplateResult {
    if (!this.cipher) return this.renderSection(t('editor.typeNote'), 'note', html`<p class="loading">${t('common.loading')}</p>`);
    return this.renderSection(t('editor.typeNote'), 'note', [
      this.renderPlainField(t('detail.notes'), this.cipher.notes, { multiline: true }),
    ]);
  }

  private renderSsh(): TemplateResult {
    if (this.sshKey === undefined) {
      return this.renderSection(this.typeLabel(), 'key', html`<p class="loading">${t('common.loading')}</p>`);
    }
    if (this.sshKey === null) {
      return this.renderSection(this.typeLabel(), 'key', html`<p class="empty">${t('detail.sshUnavailable')}</p>`);
    }
    const shown = this.revealed.has('ssh:private');
    const loading = this.loadingSecrets.has('ssh:private');
    const privateValue = shown ? this.revealed.get('ssh:private') ?? '' : MASK;
    const privateRow = this.sshKey.hasPrivateKey && this.allows('viewPassword')
      ? html`
          <div class="field multiline" data-ssh-private>
            <span class="label">${t('ssh.privateKey')}</span>
            <pre class="value pre mono ${shown ? '' : 'masked'}">${privateValue}</pre>
            <span class="field-actions">
              <button type="button" class="icon-btn xs" data-reveal-ssh-private aria-pressed=${shown ? 'true' : 'false'} title=${t('detail.reveal')} aria-label=${`${t('detail.reveal')} ${t('ssh.privateKey')}`} ?disabled=${this.pending || loading} @click=${() => void this.toggleSshPrivateKey()}>${uiIcon(shown ? 'eyeOff' : 'eye')}</button>
              <button type="button" class="icon-btn xs" data-copy-ssh-private title=${t('common.copy')} aria-label=${`${t('common.copy')} ${t('ssh.privateKey')}`} ?disabled=${this.pending || loading} @click=${() => void this.copySshPrivateKey()}>${uiIcon('copy')}</button>
            </span>
          </div>
        `
      : html`<p class="empty">${t('ssh.privateKeyUnavailable')}</p>`;
    return this.renderSection(this.typeLabel(), 'key', [
      this.renderPlainField(t('ssh.publicKey'), this.sshKey.publicKey, { mono: true, multiline: true }),
      this.renderPlainField(t('ssh.fingerprint'), this.sshKey.keyFingerprint, { mono: true }),
      privateRow,
    ]);
  }

  private renderUnknownUnsupported(): TemplateResult {
    return this.renderSection(t('detail.unsupportedItem'), 'alert', [
      html`<p class="empty">${t('detail.unsupportedDescription')}</p>`,
    ]);
  }

  private renderCustomFields(): TemplateResult | typeof nothing {
    const fields = this.cipher?.fields;
    if (!fields?.length) return nothing;
    return this.renderSection(
      t('detail.customFields'),
      'sliders',
      fields.map((field, index) => this.renderCustomField(field, index)),
    );
  }

  private renderCustomField(field: DecryptedField, index: number): TemplateResult {
    const label = field.name || t('detail.field');
    if (field.type === 1) {
      const key = `custom:${index}`;
      const shown = this.revealed.has(key);
      const loading = this.loadingSecrets.has(key);
      return html`
        <div class="field" data-secret-row>
          <span class="label">${label}</span>
          <code class="value mono ${shown ? '' : 'masked'}">${shown ? this.revealed.get(key) ?? '' : MASK}</code>
          ${this.allows('viewPassword')
            ? html`
                <span class="field-actions">
                  <button
                    type="button"
                    class="icon-btn xs"
                    data-cf-reveal
                    aria-pressed=${shown ? 'true' : 'false'}
                    title=${t('detail.reveal')}
                    aria-label=${`${t('detail.reveal')} ${label}`}
                    ?disabled=${this.pending || loading}
                    @click=${() => void this.toggleCustomReveal(index)}
                  >${uiIcon(shown ? 'eyeOff' : 'eye')}</button>
                  <button
                    type="button"
                    class="icon-btn xs"
                    data-cf-copy
                    title=${t('common.copy')}
                    aria-label=${`${t('common.copy')} ${label}`}
                    ?disabled=${this.pending}
                    @click=${() => this.requestSecretCopy({ kind: 'customField', index, label })}
                  >${uiIcon('copy')}</button>
                </span>
              `
            : nothing}
        </div>
      `;
    }
    const value = field.type === 2
      ? t(field.value === 'true' ? 'common.yes' : 'common.no')
      : field.type === 3
        ? linkedLabel(
            this.cipher?.type ?? (isKnownCipherType(this.summary.type) ? this.summary.type : 1),
            field.linkedId,
          )
        : (field.value ?? '');
    return html`
      <div class="field">
        <span class="label">${label}</span>
        <span class="value ${field.type === 0 ? 'mono' : ''}">${value}</span>
        ${field.type === 0 && value
          ? html`
              <span class="field-actions">
                <button
                  type="button"
                  class="icon-btn xs"
                  title=${t('common.copy')}
                  aria-label=${`${t('common.copy')} ${label}`}
                  ?disabled=${this.pending}
                  @click=${() => this.copyValue(value, label)}
                >${uiIcon('copy')}</button>
              </span>
            `
          : nothing}
      </div>
    `;
  }

  private renderPasskeys(): TemplateResult | typeof nothing {
    const passkeys = this.cipher?.fido2Credentials;
    if (!this.summary.hasPasskey && !passkeys?.length) return nothing;
    const canDelete = !this.isDeleted
      && this.summary.type === 1
      && this.allows('edit')
      && this.allows('viewPassword');
    return this.renderSection(
      t('detail.passkeys'),
      'passkey',
      html`
        <div class="passkey-list">
          ${(passkeys?.length ? passkeys : [undefined]).map((credential) => {
            const name = credential?.rpName || credential?.rpId || t('detail.passkeySaved');
            return html`
              <div class="field">
                <span class="label">${t('detail.passkey')}</span>
                <span class="value">${name}</span>
                ${credential && canDelete
                  ? html`
                      <span class="field-actions">
                        <button
                          type="button"
                          class="icon-btn xs"
                          data-passkey-delete
                          title=${t('detail.deletePasskey')}
                          aria-label=${`${t('detail.deletePasskey')}: ${name}`}
                          ?disabled=${this.isBusy}
                          @click=${(event: Event) => this.openPasskeyConfirmation(
                            credential.credentialId,
                            name,
                            event.currentTarget as HTMLElement,
                          )}
                        >${uiIcon('trash')}</button>
                      </span>
                    `
                  : nothing}
              </div>
            `;
          })}
        </div>
      `,
    );
  }

  private renderAttachments(): TemplateResult | typeof nothing {
    if (!this.cipher) return nothing;
    const attachments = this.cipher.attachments ?? [];
    return this.renderSection(
      t('detail.attachments'),
      'file',
      html`
        ${attachments.length
          ? attachments.map((attachment) => html`
              <div class="field">
                <span class="label attachment-name">${uiIcon('file')}<span>${attachment.fileName}</span></span>
                <span class="value">${attachment.sizeName ?? attachment.size ?? ''}</span>
                <span class="field-actions">
                  ${attachment.fileName !== '(undecryptable)'
                    ? html`<button
                        type="button"
                        class="icon-btn xs"
                        data-att-download
                        title=${t('detail.download')}
                        aria-label=${t('detail.downloadNamed', { name: attachment.fileName })}
                        ?disabled=${this.isBusy}
                        @click=${() => this.dispatch<AttachmentRefDetail>('vw-attachment-download', {
                          cipherId: this.summary.id,
                          attachmentId: attachment.id,
                          fileName: attachment.fileName,
                        })}
                      >${uiIcon('download')}</button>`
                    : nothing}
                  ${attachment.legacy && !this.isDeleted && this.allows('edit')
                    ? html`<button
                            type="button"
                            class="icon-btn xs"
                            data-att-upgrade
                            title=${t('detail.upgradeAttachment')}
                            aria-label=${t('detail.upgradeAttachmentNamed', { name: attachment.fileName })}
                            ?disabled=${this.isBusy}
                            @click=${() => this.dispatch<AttachmentRefDetail>('vw-attachment-upgrade', {
                              cipherId: this.summary.id,
                              attachmentId: attachment.id,
                              fileName: attachment.fileName,
                            })}
                          >${uiIcon('refresh')}</button>`
                    : nothing}
                  ${!this.isDeleted && this.allows('edit')
                    ? html`
                        <button
                          type="button"
                          class="icon-btn xs"
                          data-att-delete
                          title=${t('common.delete')}
                          aria-label=${`${t('common.delete')} ${attachment.fileName}`}
                          ?disabled=${this.isBusy}
                          @click=${(event: Event) => this.openAttachmentConfirmation(
                            attachment,
                            event.currentTarget as HTMLElement,
                          )}
                        >${uiIcon('trash')}</button>
                      `
                    : nothing}
                </span>
              </div>
            `)
          : html`<div class="empty">${t('detail.noAttachments')}</div>`}
        ${!this.isDeleted && this.allows('edit') ? html`<div class="section-actions">
          <span class="empty">${attachments.length ? t('detail.fileCount', { count: attachments.length }) : ''}</span>
          <label class="btn outline upload ${this.isBusy ? 'disabled' : ''}">
            ${uiIcon('plus')}<span>${t(this.encodingGeneration === this.detailGeneration ? 'detail.readingFile' : 'detail.addAttachment')}</span>
            <input
              class="file-input"
              data-att-file
              type="file"
              aria-label=${t('detail.addAttachment')}
              ?disabled=${this.isBusy}
              @change=${(event: Event) => void this.onAttachmentFile(event)}
            />
          </label>
        </div>` : nothing}
      `,
    );
  }

  private renderHistory(): TemplateResult | typeof nothing {
    if (!this.allows('viewPassword')) return nothing;
    const count = this.summary.passwordHistoryCount ?? 0;
    if (!count) return nothing;
    const loading = this.historyLoadingGeneration === this.detailGeneration;
    return this.renderSection(
      t('detail.passwordHistory'),
      'clock',
      html`
        <div class="field history-field">
          <span class="value">${t('detail.previousPasswords', { count })}</span>
          <span class="field-actions">
            <button
              type="button"
              class="icon-btn xs"
              data-toggle-history
              aria-pressed=${this.history !== null ? 'true' : 'false'}
              title=${t('detail.reveal')}
              aria-label=${t('detail.passwordHistory')}
              ?disabled=${this.pending || loading}
              @click=${() => void this.toggleHistory()}
            >${uiIcon(this.history !== null ? 'eyeOff' : 'eye')}</button>
          </span>
        </div>
        ${this.history === null
          ? nothing
          : this.history.length
            ? this.history.map((entry) => html`
                <div class="field history-entry" data-history-entry>
                  <code class="value mono">${entry.password}</code>
                  <span class="history-date">${this.formatHistoryDate(entry.lastUsedDate)}</span>
                  <span class="field-actions">
                    <button
                      type="button"
                      class="icon-btn xs"
                      data-history-copy
                      title=${t('common.copy')}
                      aria-label=${t('detail.copyPreviousPassword')}
                      ?disabled=${this.pending}
                      @click=${() => this.copyValue(entry.password, t('detail.previousPassword'))}
                    >${uiIcon('copy')}</button>
                  </span>
                </div>
              `)
            : html`<div class="empty">${t('detail.noPreviousPasswords')}</div>`}
      `,
    );
  }

  private formatHistoryDate(value: string | undefined): string {
    if (!value) return '';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString();
  }

  private renderCommonNotes(): TemplateResult | typeof nothing {
    if (this.summary.type === 2 || !this.cipher?.notes) return nothing;
    return this.renderSection(
      t('detail.notes'),
      'note',
      this.renderPlainField(t('detail.notes'), this.cipher.notes, { multiline: true }),
    );
  }

  private renderPrimaryActions(): TemplateResult | typeof nothing {
    if (this.isInactive || this.primaryAction === 'none') return nothing;
    return html`
      <div class="primary-actions">
        <button
          type="button"
          class="btn primary"
          data-fill
          ?disabled=${this.pending}
          @click=${() => this.dispatch<ItemRefDetail>('vw-item-fill', { cipherId: this.summary.id })}
        >${uiIcon('globe')}<span>${t(this.primaryAction === 'fill'
          ? 'detail.fillCurrentPage'
          : 'detail.openWebsite')}</span></button>
      </div>
    `;
  }

  private renderDangerZone(): TemplateResult | typeof nothing {
    if (this.displayMode !== 'active' || this.isUnsupported) return nothing;
    return html`
      <div class="danger-zone">
        <button
          type="button"
          class="btn outline"
          data-archive
          ?disabled=${this.isBusy}
          title=${t('detail.archive')}
          aria-label=${t('detail.archive')}
          @click=${(event: Event) => this.openArchiveConfirmation(
            event.currentTarget as HTMLElement,
          )}
        >${uiIcon('folder')}<span>${t('detail.archive')}</span></button>
        ${this.allows('delete') ? html`<button
          type="button"
          class="btn danger"
          data-delete
          ?disabled=${this.isBusy}
          @click=${(event: Event) => this.openItemConfirmation(
            false,
            event.currentTarget as HTMLElement,
          )}
        >${uiIcon('trash')}<span>${t('detail.delete')}</span></button>` : nothing}
      </div>
    `;
  }

  private renderNormalBody(): TemplateResult {
    if (this.isUnsupported) return this.renderUnknownUnsupported();
    let main: TemplateResult;
    switch (this.summary.type) {
      case 1: main = this.renderLogin(); break;
      case 2: main = this.renderNote(); break;
      case 3: main = this.renderCard(); break;
      case 4: main = this.renderIdentity(); break;
      case 5: main = this.renderSsh(); break;
      default: return this.renderUnknownUnsupported();
    }
    return html`
      ${main}
      ${this.renderCommonNotes()}
      ${this.renderCustomFields()}
      ${this.renderPasskeys()}
      ${this.renderAttachments()}
      ${this.renderHistory()}
      ${this.renderPrimaryActions()}
      ${this.renderDangerZone()}
    `;
  }

  private renderArchiveBody(): TemplateResult {
    return html`
      <div class="inactive-panel">
        <p class="inactive-copy">${t('detail.inArchive')}</p>
        <div class="lifecycle-actions">
          <button
            type="button"
            class="btn primary"
            data-unarchive
            ?disabled=${this.isBusy}
            title=${t('detail.unarchive')}
            aria-label=${t('detail.unarchive')}
            @click=${() => this.submitLifecycle('vw-unarchive-item', {
              action: 'unarchive',
              cipherId: this.summary.id,
              sourceMode: 'archive',
              targetMode: 'active',
            })}
          >${uiIcon('refresh')}<span>${t('detail.unarchive')}</span></button>
          ${this.allows('delete') ? html`<button
            type="button"
            class="btn danger"
            data-delete
            ?disabled=${this.isBusy}
            @click=${(event: Event) => this.openItemConfirmation(
              false,
              event.currentTarget as HTMLElement,
            )}
          >${uiIcon('trash')}<span>${t('detail.delete')}</span></button>` : nothing}
        </div>
      </div>
    `;
  }

  private renderTrashBody(): TemplateResult {
    const targetMode = this.summary.archivedDate ? 'archive' : 'active';
    return html`
      <div class="inactive-panel">
        <p class="inactive-copy">${t('detail.inTrash')}</p>
        <div class="lifecycle-actions">
          ${this.allows('restore') ? html`<button
            type="button"
            class="btn primary"
            data-restore
            ?disabled=${this.isBusy}
            @click=${() => this.submitLifecycle('vw-restore-item', {
              action: 'restore',
              cipherId: this.summary.id,
              sourceMode: 'trash',
              targetMode,
            })}
          >${uiIcon('refresh')}<span>${t('detail.restore')}</span></button>` : nothing}
          ${this.allows('delete') ? html`<button
            type="button"
            class="btn danger"
            data-delete-permanent
            ?disabled=${this.isBusy}
            @click=${(event: Event) => this.openItemConfirmation(
              true,
              event.currentTarget as HTMLElement,
            )}
          >${uiIcon('trash')}<span>${t('detail.deletePermanently')}</span></button>` : nothing}
        </div>
      </div>
    `;
  }

  private renderConfirmation(): TemplateResult | typeof nothing {
    if (this.isUnsupported) return nothing;
    const confirmation = this.confirmation;
    if (!confirmation) return nothing;
    const attachment = confirmation.kind === 'attachment';
    const archive = confirmation.kind === 'archive';
    const clone = confirmation.kind === 'clone';
    const passkey = confirmation.kind === 'passkey';
    const permanent = confirmation.kind === 'item' && confirmation.permanent;
    const heading = attachment
      ? t('detail.deleteAttachment')
      : archive
        ? t('detail.archive')
      : clone
        ? t('detail.passkeyNotCopied')
      : passkey
        ? t('detail.deletePasskey')
      : permanent
        ? t('detail.deletePermanently')
        : t('detail.delete');
    const message = attachment
      ? t('detail.deleteAttachmentConfirm', { name: confirmation.attachment.fileName })
      : archive
        ? t('detail.archiveConfirm')
      : clone
        ? t('detail.passkeyNotCopiedConfirm')
      : passkey
        ? t('detail.deletePasskeyConfirm', { name: confirmation.name })
      : permanent
        ? t('detail.deletePermanentlyConfirm')
        : t('detail.moveToTrashConfirm');
    return html`
      <vw-dialog
        .open=${true}
        .heading=${heading}
        @vw-dialog-close=${(event: CustomEvent<{ reason: string }>) => this.handleConfirmationClose(event)}
      >
        <p>${message}</p>
        <button
          slot="actions"
          type="button"
          class="btn ghost"
          data-cancel-delete
          data-cancel-lifecycle
          @click=${() => this.requestConfirmationClose('dismiss')}
        >${t('common.cancel')}</button>
        <button
          slot="actions"
          type="button"
          class=${archive || clone ? 'btn primary' : 'btn danger'}
          data-confirm-delete=${archive || clone || passkey ? nothing : ''}
          data-confirm-archive=${archive ? '' : nothing}
          data-confirm-clone=${clone ? '' : nothing}
          data-confirm-passkey=${passkey ? '' : nothing}
          ?disabled=${this.isBusy}
          @click=${() => this.requestConfirmationClose('confirm')}
        >${archive
          ? t('detail.archive')
          : clone
            ? t('detail.clone')
          : passkey
            ? t('detail.deletePasskey')
            : t('common.delete')}</button>
      </vw-dialog>
    `;
  }

  protected override render(): TemplateResult {
    return html`
      ${this.renderHeader()}
      <main class="body">
        ${this.renderStatus()}
        ${this.renderVaultLocation()}
        ${this.isUnsupported
          ? this.renderUnknownUnsupported()
          : html`
              ${this.renderNormalBody()}
              ${this.displayMode === 'trash'
                ? this.renderTrashBody()
                : this.displayMode === 'archive'
                  ? this.renderArchiveBody()
                  : nothing}
            `}
      </main>
      ${this.renderConfirmation()}
    `;
  }
}

customElements.define('vw-item-detail', VwItemDetail);

declare global {
  interface HTMLElementTagNameMap {
    'vw-item-detail': VwItemDetail;
  }
}
