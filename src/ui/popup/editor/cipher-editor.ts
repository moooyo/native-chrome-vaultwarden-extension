import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type {
  CipherInput,
  CipherSummary,
  CustomFieldType,
  DecryptedField,
} from '../../../core/vault/models.js';
import type { LoginUri } from '../../../core/vault/uri-match.js';
import type { DeleteItemDetail, DetailStatus } from '../types.js';
import type { CipherCollectionsDetail, EditorContext, EditorShareDetail } from './editor-types.js';

const CIPHER_TYPE_NAMES: Record<1 | 2 | 3 | 4, string> = { 1: 'login', 2: 'secure note', 3: 'card', 4: 'identity' };

const CARD_FORM: ReadonlyArray<readonly [keyof NonNullable<CipherInput['card']>, string]> = [
  ['cardholderName', 'Cardholder name'],
  ['brand', 'Brand'],
  ['number', 'Number'],
  ['expMonth', 'Expiration month'],
  ['expYear', 'Expiration year'],
  ['code', 'Security code'],
];

const IDENTITY_FORM: ReadonlyArray<readonly [keyof NonNullable<CipherInput['identity']>, string]> = [
  ['title', 'Title'], ['firstName', 'First name'], ['middleName', 'Middle name'], ['lastName', 'Last name'],
  ['username', 'Username'], ['company', 'Company'], ['email', 'Email'], ['phone', 'Phone'],
  ['address1', 'Address 1'], ['address2', 'Address 2'], ['address3', 'Address 3'], ['city', 'City'],
  ['state', 'State'], ['postalCode', 'Postal code'], ['country', 'Country'], ['ssn', 'SSN'],
  ['passportNumber', 'Passport number'], ['licenseNumber', 'License number'],
];

const CF_TYPES: ReadonlyArray<readonly [CustomFieldType, string]> = [[0, 'Text'], [1, 'Hidden'], [2, 'Boolean']];

/** Bitwarden LinkedId labels (login: 100 username, 101 password) shown read-only for Linked fields. */
function linkedLabel(linkedId: number | undefined): string {
  if (linkedId === 100) return 'Linked → Username';
  if (linkedId === 101) return 'Linked → Password';
  return 'Linked field';
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
        display: block;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0 10px;
      }
      .head h1 {
        margin: 0;
        font-size: 15px;
      }
      .head svg {
        width: 16px;
        height: 16px;
      }
      .field {
        margin-bottom: 8px;
      }
      .label {
        display: block;
        font-size: 12px;
        color: var(--vw-muted);
        margin-bottom: 4px;
      }
      .input,
      .select,
      textarea.input {
        width: 100%;
        box-sizing: border-box;
      }
      textarea.input {
        min-height: 64px;
        padding: 6px 8px;
        resize: vertical;
        font-family: var(--vw-font-ui);
      }
      .row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .row .input {
        flex: 1;
        min-width: 0;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
      }
      .check {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
        margin-bottom: 8px;
      }
      .cf {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 6px;
      }
      .cf .input,
      .cf .select {
        min-width: 0;
      }
      .cf .cf-name {
        flex: 1;
      }
      .cf .cf-value {
        flex: 1;
      }
      .cf-linked {
        flex: 1;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .actions {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin: 12px 0;
      }
      .block {
        width: 100%;
      }
      .section-head {
        font-size: 12px;
        color: var(--vw-muted);
        margin: 12px 0 6px;
      }
      .danger {
        border-color: var(--vw-danger);
        color: var(--vw-danger);
      }
      .muted {
        color: var(--vw-muted);
        font-size: 12px;
      }
      .confirm {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .status {
        margin-top: 8px;
      }
      svg {
        width: 16px;
        height: 16px;
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
      this.localError = 'Name is required';
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
      this.localError = 'Select at least one collection';
      this.requestUpdate();
      return;
    }
    if (new Set(checked.map((c) => c.dataset.org)).size > 1) {
      this.localError = 'All collections must be in the same organization';
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
    return html`
      <div class="field">
        <span class="label">Username</span>
        <input class="input" data-username .value=${f.username} ?disabled=${this.pending}
          @input=${(e: Event) => this.patch({ username: (e.target as HTMLInputElement).value })} />
      </div>
      <div class="field">
        <span class="label">Password</span>
        <div class="row">
          <input class="input mono" data-password type=${f.showPassword ? 'text' : 'password'} .value=${f.password} ?disabled=${this.pending}
            @input=${(e: Event) => this.patch({ password: (e.target as HTMLInputElement).value })} />
          <button type="button" class="icon-button" data-toggle-password aria-pressed=${f.showPassword ? 'true' : 'false'}
            title=${f.showPassword ? 'Hide password' : 'Show password'} aria-label=${f.showPassword ? 'Hide password' : 'Show password'}
            @click=${() => this.patch({ showPassword: !f.showPassword })}>${uiIcon(f.showPassword ? 'eyeOff' : 'eye')}</button>
        </div>
      </div>
      ${this.textField('Authenticator key (TOTP)', f.totp, (v) => this.patch({ totp: v }), { mono: true, field: 'totp' })}
      <div class="field">
        <span class="label">Websites (URIs)</span>
        ${f.uris.map(
          (u, i) => html`
            <div class="row" style="margin-bottom:6px">
              <input class="input mono" data-uri placeholder="https://example.com" .value=${u.uri} ?disabled=${this.pending}
                @input=${(e: Event) => this.updateUri(i, (e.target as HTMLInputElement).value)} />
            </div>
          `,
        )}
        <button type="button" class="button" data-add-uri ?disabled=${this.pending} @click=${() => this.addUri()}>${uiIcon('plus')}<span>Add URI</span></button>
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
      ([key, label]) => this.textField(label, this.form.card[key] ?? '', (v) => this.patch({ card: { ...this.form.card, [key]: v } }), { field: `card.${key}` }),
    )}`;
  }

  private renderIdentity() {
    return html`<div class="grid">${IDENTITY_FORM.map(
      ([key, label]) => this.textField(label, this.form.identity[key] ?? '', (v) => this.patch({ identity: { ...this.form.identity, [key]: v } }), { field: `identity.${key}` }),
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
        <span class="label">Custom fields</span>
        <div data-fields>${this.form.fields.map((f, i) => this.renderCustomField(f, i))}</div>
        <button type="button" class="button" data-add-field ?disabled=${this.pending} @click=${() => this.addField()}>${uiIcon('plus')}<span>Add field</span></button>
      </div>
    `;
  }

  private renderCustomField(field: DecryptedField, index: number) {
    if (field.type === 3) {
      return html`
        <div class="cf" data-cf data-cf-type="3">
          <input class="input cf-name" .value=${field.name} readonly />
          <span class="cf-linked">${linkedLabel(field.linkedId)}</span>
          <button type="button" class="icon-button" data-cf-remove title="Remove field" aria-label="Remove field" ?disabled=${this.pending} @click=${() => this.removeField(index)}>${uiIcon('trash')}</button>
        </div>
      `;
    }
    const valueControl = field.type === 2
      ? html`<label class="cf-value"><input type="checkbox" data-cf-value .checked=${field.value === 'true'} ?disabled=${this.pending}
          @change=${(e: Event) => this.updateField(index, { value: (e.target as HTMLInputElement).checked ? 'true' : 'false' })} /></label>`
      : html`<input class="input cf-value" data-cf-value type=${field.type === 1 ? 'password' : 'text'} placeholder="Value" .value=${field.value ?? ''} ?disabled=${this.pending}
          @input=${(e: Event) => this.updateField(index, { value: (e.target as HTMLInputElement).value })} />`;
    return html`
      <div class="cf" data-cf data-cf-type=${field.type}>
        <select class="select" data-cf-type-sel aria-label="Field type" ?disabled=${this.pending}
          @change=${(e: Event) => this.changeFieldType(index, Number((e.target as HTMLSelectElement).value) as CustomFieldType)}>
          ${CF_TYPES.map(([t, l]) => html`<option value=${t} ?selected=${t === field.type}>${l}</option>`)}
        </select>
        <input class="input cf-name" data-cf-name placeholder="Name" .value=${field.name} ?disabled=${this.pending}
          @input=${(e: Event) => this.updateField(index, { name: (e.target as HTMLInputElement).value })} />
        ${valueControl}
        <button type="button" class="icon-button" data-cf-remove title="Remove field" aria-label="Remove field" ?disabled=${this.pending} @click=${() => this.removeField(index)}>${uiIcon('trash')}</button>
      </div>
    `;
  }

  private renderCommon() {
    const f = this.form;
    return html`
      <div class="field">
        <span class="label">Notes</span>
        <textarea class="input" data-notes ?disabled=${this.pending}
          .value=${f.notes}
          @input=${(e: Event) => this.patch({ notes: (e.target as HTMLTextAreaElement).value })}></textarea>
      </div>
      <div class="field">
        <span class="label">Folder</span>
        <select class="select" data-folder ?disabled=${this.pending} @change=${(e: Event) => this.patch({ folderId: (e.target as HTMLSelectElement).value })}>
          <option value="" ?selected=${f.folderId === ''}>No folder</option>
          ${this.context.folders.map((folder) => html`<option value=${folder.id} ?selected=${folder.id === f.folderId}>${folder.name}</option>`)}
        </select>
      </div>
      <label class="check"><input type="checkbox" data-favorite .checked=${f.favorite} ?disabled=${this.pending} @change=${(e: Event) => this.patch({ favorite: (e.target as HTMLInputElement).checked })} /><span>Favorite</span></label>
      <label class="check"><input type="checkbox" data-reprompt .checked=${f.reprompt} ?disabled=${this.pending} @change=${(e: Event) => this.patch({ reprompt: (e.target as HTMLInputElement).checked })} /><span>Require master password to view</span></label>
      ${this.renderCustomFields()}
    `;
  }

  private renderCollections() {
    const orgCollections = this.orgCollections;
    if (this.context.mode !== 'edit' || !this.context.cipherId || orgCollections.length === 0) return nothing;
    return html`
      <div class="field" data-collections>
        <span class="label">Collections</span>
        ${orgCollections.map(
          (c) => html`<label class="check"><input type="checkbox" data-collection value=${c.id} .checked=${this.collectionSel.has(c.id)} ?disabled=${this.pending}
            @change=${(e: Event) => this.toggleCollection(c.id, (e.target as HTMLInputElement).checked)} /><span>${c.name}</span></label>`,
        )}
        <button type="button" class="button block" data-save-collections ?disabled=${this.pending} @click=${() => this.saveCollections()}>${uiIcon('check')}<span>Update collections</span></button>
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
    // Fail-closed share guard: the worker refuses to move items carrying a passkey or password history
    // (those secrets aren't in the editable input and would be dropped), so the editor mirrors it.
    if (this.summary?.hasPasskey || this.summary?.passwordHistoryCount) {
      return html`
        <div class="field" data-move-guard>
          <span class="label">Move to organization</span>
          <p class="muted">Move items with passkeys or password history from the web vault to avoid data loss.</p>
        </div>
      `;
    }
    return html`
      <div class="field" data-move>
        <span class="label">Move to organization</span>
        <p class="muted">Select the collection(s) to move this item into. All must belong to the same organization.</p>
        ${this.context.collections.map(
          (c) => html`<label class="check"><input type="checkbox" data-move-col value=${c.id} data-org=${c.organizationId} ?disabled=${this.pending} /><span>${c.name}</span></label>`,
        )}
        <button type="button" class="button block" data-move-confirm ?disabled=${this.pending} @click=${() => this.moveToOrg()}>${uiIcon('folder')}<span>Move to organization</span></button>
      </div>
    `;
  }

  private renderActions() {
    const isEdit = this.context.mode === 'edit' && !!this.context.cipherId;
    return html`
      <div class="actions">
        <button type="button" class="button primary block" data-save ?disabled=${this.pending} @click=${() => this.save()}>${uiIcon('check')}<span>Save</span></button>
        ${isEdit
          ? this.confirmingDelete
            ? html`<div class="confirm" data-delete-confirm>
                <span class="muted">Move this item to trash?</span>
                <button type="button" class="button danger" data-delete-yes ?disabled=${this.pending} @click=${() => this.confirmDelete()}>Move to trash</button>
                <button type="button" class="button" data-delete-no ?disabled=${this.pending} @click=${() => { this.confirmingDelete = false; this.requestUpdate(); }}>Cancel</button>
              </div>`
            : html`<button type="button" class="button danger block" data-delete ?disabled=${this.pending} @click=${() => { this.confirmingDelete = true; this.requestUpdate(); }}>${uiIcon('trash')}<span>Delete</span></button>`
          : nothing}
      </div>
    `;
  }

  protected override render() {
    const title = `${this.context.mode === 'create' ? 'Add' : 'Edit'} ${CIPHER_TYPE_NAMES[this.context.type]}`;
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>${title}</h1>
      </div>
      ${this.textField('Name', this.form.name, (v) => this.patch({ name: v }), { field: 'name' })}
      ${this.renderTypeFields()}
      ${this.renderCommon()}
      ${this.renderCollections()}
      ${this.renderMove()}
      ${this.renderActions()}
      ${this.localError
        ? html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.localError}></vw-status-message>`
        : this.status
        ? html`<vw-status-message class="status" .tone=${this.status.tone} .icon=${this.status.tone === 'success' ? 'checkCircle' : 'alert'} .message=${this.status.message}></vw-status-message>`
        : nothing}
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
