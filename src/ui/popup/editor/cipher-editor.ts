import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import '../../components/toggle.js';
import '../../components/select-menu.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type {
  CipherInput,
  CipherSummary,
  CustomFieldType,
  DecryptedField,
} from '../../../core/vault/models.js';
import type { LoginUri } from '../../../core/vault/uri-match.js';
import type { DeleteItemDetail, DetailStatus } from '../types.js';
import type { CipherCollectionsDetail, EditorContext, EditorShareDetail } from './editor-types.js';

// Card/identity field labels are resolved lazily via `t()` so they re-localize with the active locale.
const CARD_FORM: ReadonlyArray<readonly [keyof NonNullable<CipherInput['card']>, () => string]> = [
  ['cardholderName', () => t('detail.cardholder')],
  ['brand', () => '品牌'], // TODO i18n
  ['number', () => t('detail.cardNumber')],
  ['expMonth', () => '有效期（月）'], // TODO i18n
  ['expYear', () => '有效期（年）'], // TODO i18n
  ['code', () => t('detail.cardCode')],
];

const IDENTITY_FORM: ReadonlyArray<readonly [keyof NonNullable<CipherInput['identity']>, () => string]> = [
  ['title', () => '称谓'], // TODO i18n
  ['firstName', () => '名'], // TODO i18n
  ['middleName', () => '中间名'], // TODO i18n
  ['lastName', () => '姓'], // TODO i18n
  ['username', () => t('detail.username')],
  ['company', () => '公司'], // TODO i18n
  ['email', () => '邮箱'], // TODO i18n
  ['phone', () => '电话'], // TODO i18n
  ['address1', () => '地址 1'], // TODO i18n
  ['address2', () => '地址 2'], // TODO i18n
  ['address3', () => '地址 3'], // TODO i18n
  ['city', () => '城市'], // TODO i18n
  ['state', () => '省 / 州'], // TODO i18n
  ['postalCode', () => '邮编'], // TODO i18n
  ['country', () => '国家 / 地区'], // TODO i18n
  ['ssn', () => '社会安全号'], // TODO i18n
  ['passportNumber', () => '护照号'], // TODO i18n
  ['licenseNumber', () => '驾照号'], // TODO i18n
];

// Custom-field type labels have no catalog keys yet.
const CF_TYPES: ReadonlyArray<readonly [CustomFieldType, string]> = [
  [0, '文本'], // TODO i18n
  [1, '隐藏'], // TODO i18n
  [2, '布尔'], // TODO i18n
];

/** Bitwarden LinkedId labels (login: 100 username, 101 password) shown read-only for Linked fields. */
function linkedLabel(linkedId: number | undefined): string {
  if (linkedId === 100) return '关联 → 用户名'; // TODO i18n
  if (linkedId === 101) return '关联 → 密码'; // TODO i18n
  return '关联字段'; // TODO i18n
}

/** The controlled form state the editor owns; every derived from `context.input` on (re)initialization. */
interface FormState {
  name: string;
  notes: string;
  favorite: boolean;
  reprompt: boolean;
  folderId: string;
  username: string;
  password: string;
  totp: string;
  uris: LoginUri[];
  card: Record<string, string>;
  identity: Record<string, string>;
  fields: DecryptedField[];
  showPassword: boolean;
}

/**
 * The create/edit form for a cipher. It owns all form state (derived from the handed-down
 * `EditorContext`), validates locally, and emits exactly one complete `CipherInput` via
 * `vw-editor-save`; the root performs the request. Organization collection assignment
 * (`vw-cipher-collections`) and personal→organization move (`vw-editor-share`) are kept as separate
 * operations with their own events. Deletion emits `vw-delete-item`. The component never issues a
 * worker request, never receives a secret it did not already put in an editable input, and passes
 * every id inside a typed event detail — never an unsafe attribute.
 *
 * Reskinned to the MiYu design system: a single 372px column with a compact header (back + title +
 * ink Save), labeled fill-input field rows, `<vw-toggle>` flags, a `<vw-select>` folder picker, and a
 * danger delete action. All visible text goes through `t()`.
 */
export class VwCipherEditor extends LitElement {
  static override properties = {
    context: { attribute: false },
    summary: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
  };

  declare context: EditorContext;
  declare summary: CipherSummary | undefined;
  declare pending: boolean;
  declare status: DetailStatus | undefined;

  private i18n = new LocalizeController(this);
  private form: FormState = emptyForm();
  private collectionSel = new Set<string>();
  private localError: string | undefined;
  private confirmingDelete = false;
  private loadedKey: string | null = null;

  constructor() {
    super();
    this.context = { mode: 'create', type: 1, folders: [], collections: [], orgPermissions: [] };
    this.summary = undefined;
    this.pending = false;
    this.status = undefined;
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
        padding: 12px 14px 10px;
      }
      .title {
        flex: 1;
        min-width: 0;
        margin: 0;
        font-size: 15.5px;
        font-weight: 600;
        color: var(--vw-ink);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .save {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        flex: none;
        height: 30px;
        padding: 0 14px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: var(--vw-primary-bg);
        color: var(--vw-primary-fg);
        font-family: var(--vw-font-ui);
        font-size: 12.5px;
        font-weight: 600;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      .save:hover:not(:disabled) {
        background: var(--vw-primary-bg-hover);
      }
      .save:disabled {
        opacity: 0.5;
        cursor: default;
      }
      .save:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .save svg {
        width: 15px;
        height: 15px;
      }
      .scroll {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        padding: 4px 14px 16px;
        display: flex;
        flex-direction: column;
        gap: 12px;
        scrollbar-width: thin;
        scrollbar-color: var(--vw-scrollbar) transparent;
      }
      .scroll::-webkit-scrollbar {
        width: 8px;
      }
      .scroll::-webkit-scrollbar-thumb {
        background: var(--vw-scrollbar);
        border-radius: 4px;
        border: 2px solid transparent;
        background-clip: content-box;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .label {
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.05em;
        color: var(--vw-faint);
      }
      .row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .row .input {
        flex: 1;
        min-width: 0;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
      }
      .ta {
        width: 100%;
        min-height: 78px;
        padding: 9px 12px;
        border: 1px solid transparent;
        border-radius: var(--vw-radius-control);
        background: var(--vw-fill);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        line-height: 1.5;
        resize: vertical;
      }
      .ta::placeholder {
        color: var(--vw-placeholder);
      }
      .ta:focus {
        outline: none;
        border-color: var(--vw-accent);
      }
      .picker {
        align-self: flex-start;
      }
      .add {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        align-self: flex-start;
        height: 32px;
        padding: 0 12px;
        border: 1px dashed var(--vw-line-3);
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-text-2);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .add:hover:not(:disabled) {
        background: var(--vw-icon-hover);
        color: var(--vw-ink);
      }
      .add:disabled {
        opacity: 0.5;
        cursor: default;
      }
      .add:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .add svg {
        width: 14px;
        height: 14px;
      }
      .toggle-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        padding: 2px 0;
      }
      .toggle-row .t-label {
        font-size: 13px;
        color: var(--vw-text-4);
      }
      .cf-list {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .cf {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding-top: 10px;
        border-top: 1px solid var(--vw-line-1);
      }
      .cf:first-child {
        padding-top: 0;
        border-top: none;
      }
      .cf-head {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .cf-head .cf-name {
        flex: 1;
        min-width: 0;
      }
      .cf-sel {
        appearance: none;
        -webkit-appearance: none;
        flex: none;
        height: 36px;
        padding: 0 10px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input);
        background: var(--vw-card);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        cursor: pointer;
      }
      .cf-sel:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .cf-bool {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .cf-bool span {
        font-size: 13px;
        color: var(--vw-text-4);
      }
      .cf-linked {
        font-size: 12px;
        color: var(--vw-muted);
      }
      .org {
        gap: 8px;
      }
      .checks {
        display: flex;
        flex-direction: column;
        gap: 2px;
      }
      .check-row {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 5px 0;
        font-size: 13px;
        color: var(--vw-text-4);
        cursor: pointer;
      }
      .check-row input {
        width: 16px;
        height: 16px;
        accent-color: var(--vw-accent);
        cursor: pointer;
      }
      .hint {
        margin: 0;
        font-size: 12px;
        color: var(--vw-muted);
        line-height: 1.5;
      }
      .btn {
        width: auto;
      }
      .btn svg {
        width: 15px;
        height: 15px;
      }
      .wide {
        width: 100%;
      }
      .confirm {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .confirm > span {
        flex: 1;
        min-width: 0;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .status {
        margin-top: 2px;
      }
    `,
  ];

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (!changed.has('context') && !changed.has('summary')) return;
    const key = this.signature();
    if (key === this.loadedKey) return;
    this.loadedKey = key;
    this.form = this.initForm();
    this.collectionSel = new Set(this.summary?.collectionIds ?? []);
    this.localError = undefined;
    this.confirmingDelete = false;
  }

  private signature(): string {
    const c = this.context;
    return `${c.mode}|${c.type}|${c.cipherId ?? ''}|${c.input ? '1' : '0'}|${this.summary?.id ?? ''}`;
  }

  private initForm(): FormState {
    const input = this.context.input;
    const login = input?.login ?? {};
    return {
      name: input?.name ?? '',
      notes: input?.notes ?? '',
      favorite: input?.favorite ?? false,
      reprompt: input?.reprompt ?? false,
      folderId: input?.folderId ?? '',
      username: login.username ?? '',
      password: login.password ?? '',
      totp: login.totp ?? '',
      uris: login.uris?.length ? login.uris.map((u) => ({ ...u })) : [{ uri: '' }],
      card: { ...(input?.card ?? {}) } as Record<string, string>,
      identity: { ...(input?.identity ?? {}) } as Record<string, string>,
      fields: (input?.fields ?? []).map((f) => ({ ...f })),
      showPassword: false,
    };
  }

  private patch(patch: Partial<FormState>): void {
    this.form = { ...this.form, ...patch };
    this.requestUpdate();
  }

  // --- collection membership (organization items) -----------------------------------------------

  private get orgCollections() {
    const orgId = this.summary?.organizationId;
    if (!orgId) return [];
    return this.context.collections.filter((c) => c.organizationId === orgId);
  }

  private toggleCollection(id: string, checked: boolean): void {
    const next = new Set(this.collectionSel);
    if (checked) next.add(id);
    else next.delete(id);
    this.collectionSel = next;
    this.requestUpdate();
  }

  // --- custom fields ----------------------------------------------------------------------------

  private addField(): void {
    this.patch({ fields: [...this.form.fields, { type: 0, name: '' }] });
  }

  private removeField(index: number): void {
    this.patch({ fields: this.form.fields.filter((_, i) => i !== index) });
  }

  private updateField(index: number, changes: Partial<DecryptedField>): void {
    this.patch({ fields: this.form.fields.map((f, i) => (i === index ? { ...f, ...changes } : f)) });
  }

  private changeFieldType(index: number, type: CustomFieldType): void {
    // Switching type drops the old value control, so start its value fresh.
    this.patch({
      fields: this.form.fields.map((f, i) => (i === index ? { type, name: f.name } : f)),
    });
  }

  // --- collection / collect / emit --------------------------------------------------------------

  private collectFields(): DecryptedField[] {
    const out: DecryptedField[] = [];
    for (const f of this.form.fields) {
      if (f.type === 3) {
        const field: DecryptedField = { type: 3, name: f.name };
        if (f.linkedId !== undefined) field.linkedId = f.linkedId;
        out.push(field);
        continue;
      }
      const name = f.name.trim();
      if (!name) continue; // a Text/Hidden/Boolean field needs a name to be meaningful
      const value = f.type === 2 ? (f.value === 'true' ? 'true' : 'false') : (f.value ?? '');
      const field: DecryptedField = { type: f.type, name };
      if (value) field.value = value;
      out.push(field);
    }
    return out;
  }

  private collectInput(): CipherInput {
    const f = this.form;
    const type = this.context.type;
    const input: CipherInput = {
      type,
      name: f.name.trim(),
      favorite: f.favorite,
      reprompt: f.reprompt,
      folderId: f.folderId || null,
    };
    const notes = f.notes.trim() ? f.notes : '';
    if (notes) input.notes = notes;
    if (type === 1) {
      const login: NonNullable<CipherInput['login']> = {};
      if (f.username) login.username = f.username;
      if (f.password) login.password = f.password;
      if (f.totp) login.totp = f.totp;
      const uris = f.uris
        .map((u) => ({ uri: u.uri.trim(), match: u.match }))
        .filter((u) => u.uri.length > 0)
        .map((u) => (u.match !== undefined && u.match !== null ? { uri: u.uri, match: u.match } : { uri: u.uri }));
      if (uris.length) login.uris = uris;
      input.login = login;
    } else if (type === 3) {
      const card: Record<string, string> = {};
      for (const [key] of CARD_FORM) {
        const v = this.form.card[key];
        if (v) card[key] = v;
      }
      input.card = card;
    } else if (type === 4) {
      const identity: Record<string, string> = {};
      for (const [key] of IDENTITY_FORM) {
        const v = this.form.identity[key];
        if (v) identity[key] = v;
      }
      input.identity = identity;
    }
    input.fields = this.collectFields(); // always present so removing all fields clears them server-side
    return input;
  }

  private emit<T>(type: string, detail: T): void {
    this.dispatchEvent(new CustomEvent<T>(type, { detail, bubbles: true, composed: true }));
  }

  private save(): void {
    if (this.pending) return;
    const input = this.collectInput();
    if (!input.name) {
      this.localError = '请输入名称'; // TODO i18n
      this.requestUpdate();
      return;
    }
    this.localError = undefined;
    this.emit<CipherInput>('vw-editor-save', input);
  }

  private saveCollections(): void {
    if (this.pending || !this.context.cipherId) return;
    this.emit<CipherCollectionsDetail>('vw-cipher-collections', {
      cipherId: this.context.cipherId,
      collectionIds: [...this.collectionSel],
    });
  }

  private moveToOrg(): void {
    if (this.pending || !this.context.cipherId) return;
    const checked = [...this.renderRoot.querySelectorAll<HTMLInputElement>('[data-move-col]:checked')];
    if (!checked.length) {
      this.localError = '请至少选择一个集合'; // TODO i18n
      this.requestUpdate();
      return;
    }
    if (new Set(checked.map((c) => c.dataset.org)).size > 1) {
      this.localError = '所选集合必须属于同一组织'; // TODO i18n
      this.requestUpdate();
      return;
    }
    this.localError = undefined;
    this.emit<EditorShareDetail>('vw-editor-share', {
      cipherId: this.context.cipherId,
      organizationId: checked[0]!.dataset.org!,
      collectionIds: checked.map((c) => c.value),
    });
  }

  private confirmDelete(): void {
    if (this.pending || !this.context.cipherId) return;
    this.emit<DeleteItemDetail>('vw-delete-item', { cipherId: this.context.cipherId, permanent: false });
  }

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  // --- rendering --------------------------------------------------------------------------------

  private textField(label: string, value: string, onInput: (v: string) => void, opts: { mono?: boolean; field?: string } = {}) {
    return html`
      <div class="field">
        <span class="label">${label}</span>
        <input class="input ${opts.mono ? 'mono' : ''}" data-field=${opts.field ?? label} .value=${value} ?disabled=${this.pending}
          @input=${(e: Event) => onInput((e.target as HTMLInputElement).value)} />
      </div>
    `;
  }

  private renderLogin() {
    const f = this.form;
    const revealLabel = t('detail.reveal');
    return html`
      <div class="field">
        <span class="label">${t('detail.username')}</span>
        <input class="input" data-username .value=${f.username} ?disabled=${this.pending}
          @input=${(e: Event) => this.patch({ username: (e.target as HTMLInputElement).value })} />
      </div>
      <div class="field">
        <span class="label">${t('detail.password')}</span>
        <div class="row">
          <input class="input mono" data-password type=${f.showPassword ? 'text' : 'password'} .value=${f.password} ?disabled=${this.pending}
            @input=${(e: Event) => this.patch({ password: (e.target as HTMLInputElement).value })} />
          <button type="button" class="icon-btn" data-toggle-password aria-pressed=${f.showPassword ? 'true' : 'false'}
            title=${revealLabel} aria-label=${revealLabel}
            @click=${() => this.patch({ showPassword: !f.showPassword })}>${uiIcon(f.showPassword ? 'eyeOff' : 'eye')}</button>
        </div>
      </div>
      ${this.textField(t('detail.totp'), f.totp, (v) => this.patch({ totp: v }), { mono: true, field: 'totp' })}
      <div class="field">
        <span class="label">${t('detail.uri')}</span>
        ${f.uris.map(
          (u, i) => html`
            <div class="row">
              <input class="input mono" data-uri placeholder="https://example.com" .value=${u.uri} ?disabled=${this.pending}
                @input=${(e: Event) => this.updateUri(i, (e.target as HTMLInputElement).value)} />
            </div>
          `,
        )}
        <button type="button" class="add" data-add-uri ?disabled=${this.pending} @click=${() => this.addUri()}>${uiIcon('plus')}<span>${t('editor.addUri')}</span></button>
      </div>
    `;
  }

  private updateUri(index: number, uri: string): void {
    this.patch({ uris: this.form.uris.map((u, i) => (i === index ? { ...u, uri } : u)) });
  }

  private addUri(): void {
    this.patch({ uris: [...this.form.uris, { uri: '' }] });
  }

  private renderCard() {
    return html`${CARD_FORM.map(
      ([key, label]) => this.textField(label(), this.form.card[key] ?? '', (v) => this.patch({ card: { ...this.form.card, [key]: v } }), { field: `card.${key}` }),
    )}`;
  }

  private renderIdentity() {
    return html`<div class="grid">${IDENTITY_FORM.map(
      ([key, label]) => this.textField(label(), this.form.identity[key] ?? '', (v) => this.patch({ identity: { ...this.form.identity, [key]: v } }), { field: `identity.${key}` }),
    )}</div>`;
  }

  private renderTypeFields() {
    switch (this.context.type) {
      case 1:
        return this.renderLogin();
      case 3:
        return this.renderCard();
      case 4:
        return this.renderIdentity();
      default:
        return nothing;
    }
  }

  private renderCustomFields() {
    return html`
      <div class="field">
        <span class="label">${t('detail.customFields')}</span>
        <div class="cf-list" data-fields>${this.form.fields.map((f, i) => this.renderCustomField(f, i))}</div>
        <button type="button" class="add" data-add-field ?disabled=${this.pending} @click=${() => this.addField()}>${uiIcon('plus')}<span>${t('editor.addField')}</span></button>
      </div>
    `;
  }

  private renderCustomField(field: DecryptedField, index: number) {
    const removeLabel = t('common.remove');
    if (field.type === 3) {
      return html`
        <div class="cf" data-cf data-cf-type="3">
          <div class="cf-head">
            <input class="input cf-name" .value=${field.name} readonly />
            <button type="button" class="icon-btn sm" data-cf-remove title=${removeLabel} aria-label=${removeLabel} ?disabled=${this.pending} @click=${() => this.removeField(index)}>${uiIcon('trash')}</button>
          </div>
          <span class="cf-linked">${linkedLabel(field.linkedId)}</span>
        </div>
      `;
    }
    const valueControl = field.type === 2
      ? html`<div class="cf-bool">
          <span>${'值' /* TODO i18n */}</span>
          <vw-toggle data-cf-value .checked=${field.value === 'true'} ?disabled=${this.pending}
            @vw-toggle-change=${(e: Event) => this.updateField(index, { value: (e as CustomEvent<{ checked: boolean }>).detail.checked ? 'true' : 'false' })}></vw-toggle>
        </div>`
      : html`<input class="input cf-value ${field.type === 1 ? 'mono' : ''}" data-cf-value type=${field.type === 1 ? 'password' : 'text'} placeholder=${'值' /* TODO i18n */} .value=${field.value ?? ''} ?disabled=${this.pending}
          @input=${(e: Event) => this.updateField(index, { value: (e.target as HTMLInputElement).value })} />`;
    return html`
      <div class="cf" data-cf data-cf-type=${field.type}>
        <div class="cf-head">
          <select class="cf-sel" data-cf-type-sel aria-label=${'字段类型' /* TODO i18n */} ?disabled=${this.pending}
            @change=${(e: Event) => this.changeFieldType(index, Number((e.target as HTMLSelectElement).value) as CustomFieldType)}>
            ${CF_TYPES.map(([cfType, cfLabel]) => html`<option value=${cfType} ?selected=${cfType === field.type}>${cfLabel}</option>`)}
          </select>
          <input class="input cf-name" data-cf-name placeholder=${t('editor.name')} .value=${field.name} ?disabled=${this.pending}
            @input=${(e: Event) => this.updateField(index, { name: (e.target as HTMLInputElement).value })} />
          <button type="button" class="icon-btn sm" data-cf-remove title=${removeLabel} aria-label=${removeLabel} ?disabled=${this.pending} @click=${() => this.removeField(index)}>${uiIcon('trash')}</button>
        </div>
        ${valueControl}
      </div>
    `;
  }

  private renderCommon() {
    const f = this.form;
    const folderOptions = [
      { value: '', label: '无文件夹' /* TODO i18n */ },
      ...this.context.folders.map((folder) => ({ value: folder.id, label: folder.name })),
    ];
    return html`
      <div class="field">
        <span class="label">${t('detail.notes')}</span>
        <textarea class="ta" data-notes ?disabled=${this.pending}
          .value=${f.notes}
          @input=${(e: Event) => this.patch({ notes: (e.target as HTMLTextAreaElement).value })}></textarea>
      </div>
      <div class="field">
        <span class="label">${t('editor.folder')}</span>
        <vw-select class="picker" data-folder .options=${folderOptions} .value=${f.folderId} label=${t('editor.folder')}
          @vw-select-change=${(e: Event) => this.patch({ folderId: (e as CustomEvent<{ value: string }>).detail.value })}></vw-select>
      </div>
      <div class="toggle-row">
        <span class="t-label">${t('editor.favorite')}</span>
        <vw-toggle data-favorite .checked=${f.favorite} ?disabled=${this.pending}
          @vw-toggle-change=${(e: Event) => this.patch({ favorite: (e as CustomEvent<{ checked: boolean }>).detail.checked })}></vw-toggle>
      </div>
      <div class="toggle-row">
        <span class="t-label">${t('editor.reprompt')}</span>
        <vw-toggle data-reprompt .checked=${f.reprompt} ?disabled=${this.pending}
          @vw-toggle-change=${(e: Event) => this.patch({ reprompt: (e as CustomEvent<{ checked: boolean }>).detail.checked })}></vw-toggle>
      </div>
      ${this.renderCustomFields()}
    `;
  }

  private renderCollections() {
    const orgCollections = this.orgCollections;
    if (this.context.mode !== 'edit' || !this.context.cipherId || orgCollections.length === 0) return nothing;
    return html`
      <div class="field org" data-collections>
        <span class="label">${'集合' /* TODO i18n */}</span>
        <div class="checks">
          ${orgCollections.map(
            (c) => html`<label class="check-row"><input type="checkbox" data-collection value=${c.id} .checked=${this.collectionSel.has(c.id)} ?disabled=${this.pending}
              @change=${(e: Event) => this.toggleCollection(c.id, (e.target as HTMLInputElement).checked)} /><span>${c.name}</span></label>`,
          )}
        </div>
        <button type="button" class="btn outline wide" data-save-collections ?disabled=${this.pending} @click=${() => this.saveCollections()}>${uiIcon('check')}<span>${'更新集合' /* TODO i18n */}</span></button>
      </div>
    `;
  }

  private canMove(): boolean {
    return this.context.mode === 'edit'
      && !!this.context.cipherId
      && !!this.summary
      && !this.summary.organizationId
      && this.context.collections.length > 0;
  }

  private renderMove() {
    if (!this.canMove()) return nothing;
    const moveLabel = '移动到组织'; // TODO i18n
    // Fail-closed share guard: the worker refuses to move items carrying a passkey or password history
    // (those secrets aren't in the editable input and would be dropped), so the editor mirrors it.
    if (this.summary?.hasPasskey || this.summary?.passwordHistoryCount) {
      return html`
        <div class="field org" data-move-guard>
          <span class="label">${moveLabel}</span>
          <p class="hint">${'含通行密钥或密码历史的条目请从网页版密钥库移动，以避免数据丢失。' /* TODO i18n */}</p>
        </div>
      `;
    }
    return html`
      <div class="field org" data-move>
        <span class="label">${moveLabel}</span>
        <p class="hint">${'选择要移动到的集合，所选集合必须属于同一组织。' /* TODO i18n */}</p>
        <div class="checks">
          ${this.context.collections.map(
            (c) => html`<label class="check-row"><input type="checkbox" data-move-col value=${c.id} data-org=${c.organizationId} ?disabled=${this.pending} /><span>${c.name}</span></label>`,
          )}
        </div>
        <button type="button" class="btn outline wide" data-move-confirm ?disabled=${this.pending} @click=${() => this.moveToOrg()}>${uiIcon('folder')}<span>${moveLabel}</span></button>
      </div>
    `;
  }

  private renderDelete() {
    if (this.context.mode !== 'edit' || !this.context.cipherId) return nothing;
    if (this.confirmingDelete) {
      return html`
        <div class="confirm" data-delete-confirm>
          <span>${'将此条目移至回收站？' /* TODO i18n */}</span>
          <button type="button" class="btn danger" data-delete-yes ?disabled=${this.pending} @click=${() => this.confirmDelete()}>${'移至回收站' /* TODO i18n */}</button>
          <button type="button" class="btn ghost" data-delete-no ?disabled=${this.pending} @click=${() => { this.confirmingDelete = false; this.requestUpdate(); }}>${t('common.cancel')}</button>
        </div>
      `;
    }
    return html`
      <button type="button" class="btn danger wide" data-delete ?disabled=${this.pending} @click=${() => { this.confirmingDelete = true; this.requestUpdate(); }}>${uiIcon('trash')}<span>${t('common.delete')}</span></button>
    `;
  }

  protected override render() {
    const title = this.context.mode === 'create' ? t('editor.newTitle') : t('editor.editTitle');
    return html`
      <div class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1 class="title">${title}</h1>
        <button type="button" class="save" data-save ?disabled=${this.pending} @click=${() => this.save()}>${uiIcon('check')}<span>${t('common.save')}</span></button>
      </div>
      <div class="scroll" data-scroll>
        ${this.textField(t('editor.name'), this.form.name, (v) => this.patch({ name: v }), { field: 'name' })}
        ${this.renderTypeFields()}
        ${this.renderCommon()}
        ${this.renderCollections()}
        ${this.renderMove()}
        ${this.renderDelete()}
        ${this.localError
          ? html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.localError}></vw-status-message>`
          : this.status
          ? html`<vw-status-message class="status" .tone=${this.status.tone} .icon=${this.status.tone === 'success' ? 'checkCircle' : 'alert'} .message=${this.status.message}></vw-status-message>`
          : nothing}
      </div>
    `;
  }
}

function emptyForm(): FormState {
  return {
    name: '', notes: '', favorite: false, reprompt: false, folderId: '',
    username: '', password: '', totp: '', uris: [{ uri: '' }],
    card: {}, identity: {}, fields: [], showPassword: false,
  };
}

customElements.define('vw-cipher-editor', VwCipherEditor);

declare global {
  interface HTMLElementTagNameMap {
    'vw-cipher-editor': VwCipherEditor;
  }
}
