import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import '../../components/status-message.js';
import type { StatusTone } from '../../components/status-message.js';
import type {
  CipherSummary,
  DecryptedCipher,
  DecryptedField,
  FieldName,
} from '../../../core/vault/models.js';
import type {
  AttachmentAddDetail,
  AttachmentRefDetail,
  CopyDetail,
  DeleteItemDetail,
  DetailExtras,
  DetailStatus,
  ItemRefDetail,
  PasswordHistoryEntry,
  SecretRequestDetail,
  TotpSnapshot,
} from '../types.js';
import { fileToBase64, formatTotp, safeWebUrl } from '../utils.js';

/** Secret fields shown masked and fetched only on explicit reveal/copy (never in a prop or the DOM). */
type RevealableField = 'card.number' | 'card.code' | 'identity.ssn' | 'identity.passportNumber' | 'identity.licenseNumber';

const STATUS_ICON: Record<StatusTone, IconName> = {
  info: 'refresh',
  success: 'checkCircle',
  warning: 'alert',
  danger: 'alert',
};

/** Bitwarden LinkedId labels (login: 100 username, 101 password). */
function linkedLabel(linkedId: number | undefined): string {
  if (linkedId === 100) return 'Linked → Username';
  if (linkedId === 101) return 'Linked → Password';
  return 'Linked field';
}

/**
 * The dormant Lit item-detail view. It is props/events only: the root hands it a non-secret
 * `CipherSummary`, a secret-stripped `DecryptedCipher` (structure/attachments/plain custom fields),
 * and `extras` — async loaders the root owns for on-demand reveals. This component never issues a
 * worker request and never receives a secret in a prop. Masked values stay masked until an explicit
 * reveal calls an extra; masked copies leave via `vw-secret-request` so the plaintext is fetched and
 * copied entirely by the root. All ids travel only inside typed event details, never DOM attributes.
 */
export class VwItemDetail extends LitElement {
  static override properties = {
    summary: { attribute: false },
    cipher: { attribute: false },
    extras: { attribute: false },
    status: { attribute: false },
    revealed: { attribute: false },
    totpState: { attribute: false },
    history: { attribute: false },
    noteBody: { attribute: false },
    confirmingDelete: { type: Boolean },
    busy: { type: Boolean },
  };

  declare summary: CipherSummary;
  declare cipher: DecryptedCipher | null;
  declare extras: DetailExtras;
  declare status: DetailStatus | undefined;
  declare revealed: Record<string, string>;
  declare totpState: { code: string; remaining: number } | null;
  declare history: PasswordHistoryEntry[] | null;
  declare noteBody: string | undefined;
  declare confirmingDelete: boolean;
  declare busy: boolean;

  private loadedItemId: string | null = null;
  private totpLoadedFor: string | null = null;
  private noteLoadedFor: string | null = null;
  private totpTimer: number | undefined;

  constructor() {
    super();
    this.summary = { id: '', name: '', uris: [], loginUris: [], type: 1, favorite: false };
    this.cipher = null;
    this.extras = {
      getField: async () => ({ ok: false }),
      getCustomField: async () => ({ ok: false }),
      getTotp: async () => ({ ok: false }),
      getPasswordHistory: async () => ({ ok: false }),
    };
    this.status = undefined;
    this.revealed = {};
    this.totpState = null;
    this.history = null;
    this.noteBody = undefined;
    this.confirmingDelete = false;
    this.busy = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        flex: none;
        min-height: 52px;
        padding: 0 12px;
        border-bottom: 1px solid var(--vw-line);
      }
      .titles {
        flex: 1;
        min-width: 0;
      }
      .titles h1 {
        margin: 0;
        font-size: var(--vw-font-size-title);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .sub {
        font-size: 12px;
        color: var(--vw-muted);
      }
      .readout {
        padding: 8px 10px;
        border-top: 1px solid var(--vw-line-weak);
      }
      .readout:first-child {
        border-top: 0;
      }
      .k {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        color: var(--vw-blue-text);
        margin-bottom: 4px;
      }
      .k svg {
        width: 14px;
        height: 14px;
      }
      .v-row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .v {
        flex: 1;
        min-width: 0;
        font-size: var(--vw-font-size-body);
        word-break: break-word;
      }
      .note-body {
        margin: 0;
        white-space: pre-wrap;
        font-size: 13px;
      }
      .actions {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin: 12px 0;
      }
      .detail-scroll {
        flex: 1;
        min-height: 0;
        overflow: auto;
        padding: 12px;
        box-sizing: border-box;
      }
      .detail-fields {
        overflow: hidden;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-row);
        background: var(--vw-panel);
      }
      .block {
        width: 100%;
      }
      .section-head {
        font-size: 12px;
        color: var(--vw-muted);
        margin: 12px 0 6px;
      }
      .hist-row {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 4px 0;
      }
      .hist-when {
        font-size: 11px;
        color: var(--vw-muted);
      }
      .confirm {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 10px;
      }
      .confirm span {
        flex: 1;
        min-width: 0;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .danger {
        border-color: var(--vw-danger);
        color: var(--vw-danger);
      }
      .sm {
        height: 28px;
        padding: 0 10px;
        font-size: 12px;
      }
      svg {
        width: 16px;
        height: 16px;
      }
      .status {
        margin-top: 10px;
      }
    `,
  ];

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.clearTotpTimer();
    this.revealed = {};
    this.history = null;
    this.noteBody = undefined;
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('summary') && this.summary.id !== this.loadedItemId) {
      this.loadedItemId = this.summary.id;
      this.clearTotpTimer();
      this.revealed = {};
      this.history = null;
      this.totpState = null;
      this.noteBody = undefined;
      this.confirmingDelete = false;
      this.totpLoadedFor = null;
      this.noteLoadedFor = null;
    }
  }

  protected override updated(): void {
    const id = this.summary.id;
    if (!id) return;
    if (this.summary.type === 2 && this.noteLoadedFor !== id) {
      this.noteLoadedFor = id;
      void this.loadNote(id);
    }
    if (this.summary.hasTotp && this.totpLoadedFor !== id) {
      this.totpLoadedFor = id;
      void this.loadTotp(id);
    }
  }

  private clearTotpTimer(): void {
    if (this.totpTimer !== undefined) {
      clearInterval(this.totpTimer);
      this.totpTimer = undefined;
    }
  }

  private async loadNote(id: string): Promise<void> {
    const res = await this.extras.getField('notes');
    if (this.summary.id !== id) return;
    if (!res.ok) {
      this.noteBody = '';
      return;
    }
    this.noteBody = res.value && res.value.length ? res.value : 'No note content';
  }

  private async loadTotp(id: string): Promise<void> {
    const res = await this.extras.getTotp();
    if (this.summary.id !== id) return;
    if (!res.ok || !res.totp) {
      this.clearTotpTimer();
      this.totpState = null;
      return;
    }
    this.startTotpCountdown(res.totp);
  }

  private startTotpCountdown(snapshot: TotpSnapshot): void {
    this.clearTotpTimer();
    this.totpState = { code: snapshot.code, remaining: snapshot.remaining };
    this.totpTimer = window.setInterval(() => {
      const current = this.totpState;
      if (!current) {
        this.clearTotpTimer();
        return;
      }
      const remaining = current.remaining - 1;
      if (remaining <= 0) {
        this.clearTotpTimer();
        void this.loadTotp(this.summary.id);
        return;
      }
      this.totpState = { code: current.code, remaining };
    }, 1000);
  }

  private dispatch<T>(type: string, detail: T): void {
    this.dispatchEvent(new CustomEvent<T>(type, { detail, bubbles: true, composed: true }));
  }

  private emitBack(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private copyValue(value: string | undefined, label: string): void {
    if (!value) return;
    this.dispatch<CopyDetail>('vw-copy', { value, label });
  }

  private requestSecretCopy(detail: SecretRequestDetail): void {
    this.dispatch<SecretRequestDetail>('vw-secret-request', detail);
  }

  private async toggleReveal(key: string, field: FieldName): Promise<void> {
    if (this.busy) return;
    if (key in this.revealed) {
      const next = { ...this.revealed };
      delete next[key];
      this.revealed = next;
      return;
    }
    this.busy = true;
    try {
      const res = await this.extras.getField(field);
      if (res.ok && res.value) this.revealed = { ...this.revealed, [key]: res.value };
    } finally {
      this.busy = false;
    }
  }

  private async toggleCustomReveal(index: number): Promise<void> {
    const key = `cf:${index}`;
    if (this.busy) return;
    if (key in this.revealed) {
      const next = { ...this.revealed };
      delete next[key];
      this.revealed = next;
      return;
    }
    this.busy = true;
    try {
      const res = await this.extras.getCustomField(index);
      if (res.ok && res.value !== undefined) this.revealed = { ...this.revealed, [key]: res.value };
    } finally {
      this.busy = false;
    }
  }

  private async toggleHistory(): Promise<void> {
    if (this.busy) return;
    if (this.history) {
      this.history = null;
      return;
    }
    this.busy = true;
    try {
      const res = await this.extras.getPasswordHistory();
      if (res.ok) this.history = res.history;
    } finally {
      this.busy = false;
    }
  }

  private async onAttachmentFile(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file || this.busy) return;
    this.busy = true;
    try {
      const dataB64 = await fileToBase64(file);
      this.dispatch<AttachmentAddDetail>('vw-attachment-add', {
        cipherId: this.summary.id,
        fileName: file.name,
        dataB64,
      });
      input.value = '';
    } finally {
      this.busy = false;
    }
  }

  private confirmDelete(): void {
    this.dispatch<DeleteItemDetail>('vw-delete-item', {
      cipherId: this.summary.id,
      permanent: Boolean(this.summary.deletedDate),
    });
    this.confirmingDelete = false;
  }

  // --- Rendering ----------------------------------------------------------------------------

  private renderHeader() {
    const item = this.summary;
    const trashed = Boolean(item.deletedDate);
    const editable = !item.undecryptable && item.type !== 5 && !trashed;
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.emitBack()}>
          ${uiIcon('back')}
        </button>
        <div class="titles">
          <h1>${item.name}</h1>
          ${item.username ? html`<div class="sub">${item.username}</div>` : nothing}
        </div>
        ${trashed
          ? html`
              <button type="button" class="icon-button" data-restore title="Restore" aria-label="Restore"
                @click=${() => this.dispatch<ItemRefDetail>('vw-restore-item', { cipherId: item.id })}>
                ${uiIcon('refresh')}
              </button>
              <button type="button" class="icon-button" data-delete title="Delete forever" aria-label="Delete forever"
                @click=${() => (this.confirmingDelete = true)}>
                ${uiIcon('trash')}
              </button>
            `
          : editable
            ? html`
                <button type="button" class="icon-button" data-edit title="Edit" aria-label="Edit"
                  @click=${() => this.dispatch<ItemRefDetail>('vw-edit-item', { cipherId: item.id })}>
                  ${uiIcon('edit')}
                </button>
                <button type="button" class="icon-button" data-delete title="Delete" aria-label="Delete"
                  @click=${() => (this.confirmingDelete = true)}>
                  ${uiIcon('trash')}
                </button>
              `
            : nothing}
      </div>
    `;
  }

  private renderConfirmDelete() {
    if (!this.confirmingDelete) return nothing;
    const permanent = Boolean(this.summary.deletedDate);
    return html`
      <div class="confirm">
        <span>${permanent ? 'Delete this item forever? This cannot be undone.' : 'Move this item to trash?'}</span>
        <button type="button" class="button sm danger" data-confirm-delete @click=${() => this.confirmDelete()}>
          ${permanent ? 'Delete forever' : 'Move to trash'}
        </button>
        <button type="button" class="button sm" data-cancel-delete @click=${() => (this.confirmingDelete = false)}>Cancel</button>
      </div>
    `;
  }

  private renderStatus() {
    const status = this.status;
    if (!status) return nothing;
    return html`<vw-status-message class="status" tone=${status.tone} .icon=${STATUS_ICON[status.tone]} .message=${status.message}></vw-status-message>`;
  }

  private renderUris() {
    const uris = this.summary.uris;
    if (!uris.length) return nothing;
    return html`
      <div class="readout">
        <div class="k">${uiIcon('globe')} Website</div>
        ${uris.map((uri) => {
          const safe = safeWebUrl(uri);
          return safe
            ? html`<div class="v-row"><a class="v" data-uri href=${safe} target="_blank" rel="noreferrer">${uri}</a></div>`
            : html`<div class="v-row"><span class="v">${uri}</span></div>`;
        })}
      </div>
    `;
  }

  private renderMaskedRow(label: string, icon: IconName, key: string, revealed: string | undefined, onToggle: () => void) {
    const shown = revealed !== undefined;
    return html`
      <div class="readout">
        <div class="k">${uiIcon(icon)} ${label}</div>
        <div class="v-row">
          <code class="v mono" data-password-value>${shown ? revealed : '••••••••'}</code>
          <button type="button" class="icon-button" data-toggle-password aria-pressed=${shown ? 'true' : 'false'}
            title=${shown ? 'Hide' : 'Show'} aria-label=${shown ? `Hide ${label}` : `Show ${label}`}
            ?disabled=${this.busy} @click=${onToggle}>
            ${uiIcon(shown ? 'eyeOff' : 'eye')}
          </button>
        </div>
      </div>
    `;
  }

  private renderLogin() {
    const item = this.summary;
    return html`
      ${this.renderUris()}
      ${this.renderMaskedRow('Password', 'lock', 'password', this.revealed['password'], () => void this.toggleReveal('password', 'password'))}
      ${item.hasTotp
        ? html`
            <div class="readout">
              <div class="k">${uiIcon('key')} Verification code</div>
              <div class="v-row">
                <code class="v mono" data-totp>${this.totpState ? formatTotp(this.totpState.code) : '······'}</code>
                ${this.totpState ? html`<span class="hist-when" data-totp-remaining>${this.totpState.remaining}s</span>` : nothing}
                <button type="button" class="icon-button" data-copy-totp title="Copy code" aria-label="Copy verification code"
                  @click=${() => this.totpState && this.copyValue(this.totpState.code, 'Verification code')}>
                  ${uiIcon('copy')}
                </button>
              </div>
            </div>
          `
        : nothing}
      ${item.hasPasskey
        ? html`
            <div class="readout">
              <div class="k">${uiIcon('shield')} Passkey</div>
              <div class="v-row"><span class="v">Passkey saved — sign in with it on this site.</span></div>
            </div>
          `
        : nothing}
      ${item.passwordHistoryCount
        ? html`
            <div class="readout">
              <div class="k">${uiIcon('refresh')} Password history</div>
              <div class="v-row">
                <span class="v">${item.passwordHistoryCount} previous password${item.passwordHistoryCount > 1 ? 's' : ''}</span>
                <button type="button" class="icon-button" data-toggle-history aria-pressed=${this.history ? 'true' : 'false'}
                  title="View history" aria-label="View password history" ?disabled=${this.busy} @click=${() => void this.toggleHistory()}>
                  ${uiIcon(this.history ? 'eyeOff' : 'eye')}
                </button>
              </div>
              ${this.history ? this.renderHistory(this.history) : nothing}
            </div>
          `
        : nothing}
      ${this.renderCustomFields()}
      ${this.renderAttachments()}
      <div class="actions">
        <button type="button" class="button primary block" data-copy-password
          @click=${() => this.requestSecretCopy({ kind: 'field', field: 'password', label: 'Password' })}>
          ${uiIcon('copy')}<span>Copy password</span>
        </button>
        <button type="button" class="button block" data-copy-username @click=${() => this.copyValue(item.username, 'Username')}>
          ${uiIcon('user')}<span>Copy username</span>
        </button>
      </div>
    `;
  }

  private renderHistory(history: PasswordHistoryEntry[]) {
    if (!history.length) return html`<div class="sub">No previous passwords</div>`;
    return html`<div data-history>
      ${history.map((entry) => {
        const when = entry.lastUsedDate ? new Date(entry.lastUsedDate).toLocaleDateString() : '';
        return html`
          <div class="hist-row">
            <code class="v mono">${entry.password}</code>
            ${when ? html`<span class="hist-when">${when}</span>` : nothing}
            <button type="button" class="icon-button" data-history-copy title="Copy" aria-label="Copy previous password"
              @click=${() => this.copyValue(entry.password, 'Previous password')}>
              ${uiIcon('copy')}
            </button>
          </div>
        `;
      })}
    </div>`;
  }

  private renderNote() {
    return html`
      <div class="readout">
        <div class="k">${uiIcon('note')} Note</div>
        <pre class="note-body" data-note>${this.noteBody ?? 'Loading…'}</pre>
      </div>
      ${this.renderCustomFields()}
      ${this.renderAttachments()}
      <div class="actions">
        <button type="button" class="button primary block" data-copy-note
          @click=${() => this.copyValue(this.noteBody, 'Note')}>
          ${uiIcon('copy')}<span>Copy note</span>
        </button>
      </div>
    `;
  }

  private renderPlainRow(label: string, value: string) {
    return html`
      <div class="readout">
        <div class="k">${label}</div>
        <div class="v-row">
          <span class="v mono">${value}</span>
          <button type="button" class="icon-button" title=${`Copy ${label}`} aria-label=${`Copy ${label}`}
            @click=${() => this.copyValue(value, label)}>
            ${uiIcon('copy')}
          </button>
        </div>
      </div>
    `;
  }

  private renderSecretRow(label: string, field: RevealableField) {
    const key = field;
    const revealed = this.revealed[key];
    const shown = revealed !== undefined;
    return html`
      <div class="readout">
        <div class="k">${label}</div>
        <div class="v-row">
          <code class="v mono">${shown ? revealed : '••••••••'}</code>
          <button type="button" class="icon-button" data-reveal=${field} aria-pressed=${shown ? 'true' : 'false'}
            title=${shown ? `Hide ${label}` : `Show ${label}`} aria-label=${shown ? `Hide ${label}` : `Show ${label}`}
            ?disabled=${this.busy} @click=${() => void this.toggleReveal(key, field)}>
            ${uiIcon(shown ? 'eyeOff' : 'eye')}
          </button>
          <button type="button" class="icon-button" title=${`Copy ${label}`} aria-label=${`Copy ${label}`}
            @click=${() => this.requestSecretCopy({ kind: 'field', field, label })}>
            ${uiIcon('copy')}
          </button>
        </div>
      </div>
    `;
  }

  private renderCard() {
    const card = this.cipher?.card;
    if (!card) return html`<div class="sub">Loading…</div>`;
    const expiry = [card.expMonth, card.expYear].filter(Boolean).join(' / ');
    return html`
      ${card.brand ? this.renderPlainRow('Brand', card.brand) : nothing}
      ${card.cardholderName ? this.renderPlainRow('Cardholder name', card.cardholderName) : nothing}
      ${this.renderSecretRow('Number', 'card.number')}
      ${expiry ? this.renderPlainRow('Expires', expiry) : nothing}
      ${this.renderSecretRow('Security code', 'card.code')}
      ${this.renderCustomFields()}
      ${this.renderAttachments()}
    `;
  }

  private renderIdentity() {
    const identity = this.cipher?.identity;
    if (!identity) return html`<div class="sub">Loading…</div>`;
    const fullName = [identity.title, identity.firstName, identity.middleName, identity.lastName].filter(Boolean).join(' ');
    const address = [
      identity.address1,
      identity.address2,
      identity.address3,
      [identity.city, identity.state, identity.postalCode].filter(Boolean).join(', '),
      identity.country,
    ]
      .filter(Boolean)
      .join('\n');
    const plain: Array<[string, string | undefined]> = [
      ['Name', fullName || undefined],
      ['Username', identity.username],
      ['Company', identity.company],
      ['Email', identity.email],
      ['Phone', identity.phone],
      ['Address', address || undefined],
    ];
    return html`
      ${plain.filter(([, value]) => Boolean(value)).map(([label, value]) => this.renderPlainRow(label, value!))}
      ${this.renderSecretRow('SSN', 'identity.ssn')}
      ${this.renderSecretRow('Passport number', 'identity.passportNumber')}
      ${this.renderSecretRow('License number', 'identity.licenseNumber')}
      ${this.renderCustomFields()}
      ${this.renderAttachments()}
    `;
  }

  private renderCustomFields() {
    const fields = this.cipher?.fields;
    if (!fields?.length) return nothing;
    return html`
      <div class="section-head">Custom fields</div>
      ${fields.map((field, index) => this.renderCustomField(field, index))}
    `;
  }

  private renderCustomField(field: DecryptedField, index: number) {
    const label = field.name || 'Field';
    if (field.type === 1) {
      const key = `cf:${index}`;
      const revealed = this.revealed[key];
      const shown = revealed !== undefined;
      return html`
        <div class="readout">
          <div class="k">${label}</div>
          <div class="v-row">
            <code class="v mono">${shown ? revealed : '••••••••'}</code>
            <button type="button" class="icon-button" data-cf-reveal aria-pressed=${shown ? 'true' : 'false'}
              title=${shown ? `Hide ${label}` : `Show ${label}`} aria-label=${shown ? `Hide ${label}` : `Show ${label}`}
              ?disabled=${this.busy} @click=${() => void this.toggleCustomReveal(index)}>
              ${uiIcon(shown ? 'eyeOff' : 'eye')}
            </button>
            <button type="button" class="icon-button" data-cf-copy title=${`Copy ${label}`} aria-label=${`Copy ${label}`}
              @click=${() => this.requestSecretCopy({ kind: 'customField', index, label })}>
              ${uiIcon('copy')}
            </button>
          </div>
        </div>
      `;
    }
    const value = field.type === 2 ? (field.value === 'true' ? 'Yes' : 'No') : field.type === 3 ? linkedLabel(field.linkedId) : (field.value ?? '');
    return this.renderPlainRow(label, value);
  }

  private renderAttachments() {
    const cipher = this.cipher;
    if (!cipher) return nothing;
    const attachments = cipher.attachments ?? [];
    return html`
      <div class="section-head">Attachments</div>
      ${attachments.map(
        (att) => html`
          <div class="readout">
            <div class="k">${uiIcon('note')} ${att.fileName}</div>
            <div class="v-row">
              <span class="v">${att.sizeName ?? att.size ?? ''}</span>
              <button type="button" class="icon-button" data-att-download title="Download" aria-label="Download attachment"
                @click=${() => this.dispatch<AttachmentRefDetail>('vw-attachment-download', { cipherId: cipher.id, attachmentId: att.id, fileName: att.fileName })}>
                ${uiIcon('logout')}
              </button>
              <button type="button" class="icon-button" data-att-delete title="Delete" aria-label="Delete attachment"
                @click=${() => this.dispatch<AttachmentRefDetail>('vw-attachment-delete', { cipherId: cipher.id, attachmentId: att.id, fileName: att.fileName })}>
                ${uiIcon('trash')}
              </button>
            </div>
          </div>
        `,
      )}
      <label class="v-row">
        <input type="file" data-att-file ?disabled=${this.busy} @change=${(e: Event) => void this.onAttachmentFile(e)} />
      </label>
    `;
  }

  private renderBody() {
    switch (this.summary.type) {
      case 2:
        return this.renderNote();
      case 3:
        return this.renderCard();
      case 4:
        return this.renderIdentity();
      default:
        return this.renderLogin();
    }
  }

  protected override render() {
    return html`
      ${this.renderHeader()}
      <div class="detail-scroll" data-detail-scroll>
        <div class="detail-fields" data-field-group>${this.renderBody()}</div>
        ${this.renderConfirmDelete()}
        ${this.renderStatus()}
      </div>
    `;
  }
}

customElements.define('vw-item-detail', VwItemDetail);

declare global {
  interface HTMLElementTagNameMap {
    'vw-item-detail': VwItemDetail;
  }
}
