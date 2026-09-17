import { LitElement, css, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import { live } from 'lit/directives/live.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type {
  CipherCreateTarget,
  CipherSummary,
  CustomFieldType,
  DecryptedCipher,
  DecryptedField,
  FolderSummary,
  SshKeyMetadataInput,
  SshKeyPublicDetails,
} from '../../../core/vault/models.js';
import type { CollectionSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type {
  DetailStatus,
  EditorCreateDefaults,
  SshCreateGenerateDetail,
  SshCreateImportDetail,
  SshReplaceKeyDetail,
  SshUpdateMetadataDetail,
} from '../types.js';
import type { CipherCollectionsDetail, EditorShareDetail } from './editor-types.js';
import '../../components/dialog.js';
import '../../components/segmented.js';
import '../../components/status-message.js';
import '../../components/toggle.js';
import type { VwDialog } from '../../components/dialog.js';

type SshFieldType = Exclude<CustomFieldType, 3>;
type SshField = DecryptedField & { type: SshFieldType };
type CreateMethod = 'generate' | 'import';
type CreateVaultSelection =
  | { readonly kind: 'personal' }
  | { readonly kind: 'organization'; readonly organizationId: string };

interface FormState {
  name: string;
  notes: string;
  folderId: string;
  favorite: boolean;
  reprompt: boolean;
  fields: SshField[];
}

const MAX_PRIVATE_KEY_FILE_BYTES = 16 * 1024;

function emptyForm(): FormState {
  return { name: '', notes: '', folderId: '', favorite: false, reprompt: false, fields: [] };
}

function editableFields(fields: readonly DecryptedField[] | undefined): SshField[] {
  return (fields ?? [])
    .filter((field): field is SshField => field.type === 0 || field.type === 1 || field.type === 2)
    .map((field) => ({ ...field }));
}

/** Dedicated type-5 editor. It never accepts or emits a generic CipherInput. */
export class VwSshKeyEditor extends LitElement {
  static override properties = {
    mode: { type: String },
    cipherId: { attribute: false },
    summary: { attribute: false },
    cipher: { attribute: false },
    publicDetails: { attribute: false },
    folders: { attribute: false },
    collections: { attribute: false },
    orgPermissions: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
    available: { type: Boolean },
    personalCreationAllowed: { type: Boolean },
    createDefaults: { attribute: false },
    draftKey: { type: String },
  };

  declare mode: 'create' | 'edit';
  declare cipherId: string | undefined;
  declare summary: CipherSummary | undefined;
  declare cipher: DecryptedCipher | null;
  declare publicDetails: SshKeyPublicDetails | null | undefined;
  declare folders: readonly FolderSummary[];
  declare collections: readonly CollectionSummary[];
  declare orgPermissions: readonly OrgPermission[];
  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare available: boolean;
  declare personalCreationAllowed: boolean;
  declare createDefaults: EditorCreateDefaults | undefined;
  declare draftKey: string;

  private i18n = new LocalizeController(this);
  private form: FormState = emptyForm();
  private baselineForm: FormState = emptyForm();
  private loadedKey: string | null = null;
  private createMethod: CreateMethod = 'generate';
  private validationError: string | undefined;
  private replaceConfirmationOpen = false;
  private fileReadGeneration: number | undefined;
  private generation = 0;
  private collectionSelection = new Set<string>();
  private moveSelection = new Set<string>();
  private createVault: CreateVaultSelection | undefined;
  private createCollectionSelection = new Set<string>();
  private validationFocus: string | undefined;

  constructor() {
    super();
    this.mode = 'create';
    this.cipherId = undefined;
    this.summary = undefined;
    this.cipher = null;
    this.publicDetails = undefined;
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.pending = false;
    this.status = undefined;
    this.available = false;
    this.personalCreationAllowed = false;
    this.createDefaults = undefined;
    this.draftKey = 'empty';
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display:flex; flex:1; min-height:0; flex-direction:column; background:var(--vw-panel); }
      .head { display:flex; align-items:center; gap:8px; flex:none; min-height:52px; padding:8px 14px; border-bottom:1px solid var(--vw-line-1); }
      .head h1 { margin:0; flex:1; min-width:0; font-size:16px; font-weight:600; color:var(--vw-ink); }
      .editor-form { display:flex; flex:1; flex-direction:column; min-height:0; margin:0; }
      .scroll { flex:1; min-height:0; overflow-y:auto; padding:18px 18px 24px; scrollbar-width:thin; scroll-padding:16px; }
      .section { padding:0 0 18px; margin:0 0 18px; border-bottom:1px solid var(--vw-line-1); }
      .section:last-child { margin-bottom:0; border-bottom:0; }
      .section-title { display:flex; align-items:center; gap:7px; margin:0 0 12px; color:var(--vw-ink); font-size:13px; font-weight:600; }
      .section-title svg { width:14px; height:14px; }
      .field { display:flex; flex-direction:column; gap:6px; margin-top:14px; }
      .field:first-of-type { margin-top:0; }
      .label { color:var(--vw-text-2); font-size:12px; }
      .input, .textarea, .field-type {
        width:100%; box-sizing:border-box; border:1px solid var(--vw-line-2); border-radius:var(--vw-radius-input);
        background:var(--vw-panel); color:var(--vw-ink); font:13px/1.5 var(--vw-font-ui);
      }
      .input, .field-type { min-height:38px; padding:0 11px; }
      .textarea { min-height:74px; resize:vertical; padding:8px 10px; }
      .textarea.key { min-height:112px; font-family:var(--vw-font-mono); overflow-wrap:anywhere; }
      .input:focus, .textarea:focus, .field-type:focus { outline:none; border-color:var(--vw-accent); box-shadow:var(--vw-focus); }
      .input[aria-invalid="true"], .textarea[aria-invalid="true"] { border-color:var(--vw-danger); }
      .toggle-row { display:flex; align-items:center; justify-content:space-between; gap:10px; min-height:44px; border-top:1px solid var(--vw-line-1); }
      .toggle-row:first-of-type { border-top:0; }
      .toggle-row span { color:var(--vw-text-3); font-size:12px; }
      vw-segmented { display:block; width:100%; margin-bottom:10px; }
      .key-preview { display:flex; flex-direction:column; gap:7px; padding:9px 10px; border:1px solid var(--vw-line-2); border-radius:var(--vw-radius-input); background:var(--vw-fill-2); }
      .key-preview code { overflow-wrap:anywhere; color:var(--vw-ink); font:11px/1.5 var(--vw-font-mono); }
      .key-preview .fingerprint { color:var(--vw-teal-text); }
      .hint { margin:8px 0 0; color:var(--vw-text-3); font-size:12px; line-height:1.5; }
      .actions { display:flex; gap:8px; margin-top:10px; }
      .actions .btn { flex:1; min-width:0; }
      .wide { width:100%; }
      .upload { position:relative; overflow:hidden; }
      .file-input { position:absolute; width:1px; height:1px; overflow:hidden; clip-path:inset(50%); }
      .custom-list { display:flex; flex-direction:column; gap:8px; }
      .custom { display:grid; grid-template-columns:88px minmax(0,1fr) auto 28px; gap:6px; align-items:center; }
      .field-order { display:inline-flex; gap:2px; }
      .field-order .move-up svg { transform:rotate(180deg); }
      .custom-value { grid-column:1 / -1; display:flex; align-items:center; gap:8px; }
      .custom-value .input { flex:1; min-width:0; }
      .custom-value vw-toggle { margin-left:auto; }
      .checks { display:flex; flex-direction:column; gap:7px; }
      .check { display:flex; align-items:center; gap:8px; color:var(--vw-text-3); font-size:12px; }
      .check input { width:15px; height:15px; accent-color:var(--vw-accent); }
      .status { display:block; margin-bottom:10px; }
      .disclosure { border-bottom:1px solid var(--vw-line-1); }
      .disclosure summary { display:flex; align-items:center; gap:10px; padding:16px 0; cursor:pointer; list-style:none; }
      .disclosure summary::-webkit-details-marker { display:none; }
      .disclosure summary > svg { flex:none; width:16px; height:16px; color:var(--vw-accent); }
      .disclosure summary .summary-copy { display:flex; flex:1; flex-direction:column; min-width:0; gap:3px; }
      .disclosure summary strong { color:var(--vw-ink); font-size:13px; font-weight:600; }
      .disclosure summary small { color:var(--vw-text-3); font-size:11px; line-height:1.5; overflow-wrap:anywhere; }
      .disclosure summary .disclosure-chevron { display:inline-flex; color:var(--vw-chevron); transition:transform var(--vw-dur-fast); }
      .disclosure summary .disclosure-chevron svg { width:16px; height:16px; }
      .disclosure[open] > summary .disclosure-chevron { transform:rotate(180deg); }
      .disclosure summary:focus-visible { outline:none; box-shadow:var(--vw-focus); border-radius:var(--vw-radius-small); }
      .disclosure-body { padding:0 0 18px; }
      .disclosure-body > .section { padding:0; margin:0; border:0; }
      .disclosure-body > .section-title, .disclosure-body > .section > .section-title { display:none; }
      .disclosure-body .btn { margin-top:12px; }
      .disclosure-body .actions .btn { margin-top:0; }
      .disclosure-body .hint + .checks { margin-top:12px; }
      .editor-footer { flex:none; padding:12px 18px; border-top:1px solid var(--vw-line-2); background:var(--vw-panel); }
      .footer-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; }
      .footer-actions .btn { min-height:38px; }
      .footer-note { flex:1; margin:0; color:var(--vw-text-3); font-size:11px; line-height:1.5; }
      .confirm-context { margin:16px 0; border-block:1px solid var(--vw-line-1); }
      .confirm-context div { display:grid; grid-template-columns:92px minmax(0,1fr); gap:12px; padding:10px 0; }
      .confirm-context dt { color:var(--vw-text-3); font-size:12px; }
      .confirm-context dd { margin:0; color:var(--vw-ink); font-size:12px; overflow-wrap:anywhere; }
      .confirm-context code { font:11px/1.5 var(--vw-font-mono); }
      .unavailable { padding:18px 14px; color:var(--vw-muted); font-size:12px; line-height:1.5; text-align:center; }
      vw-dialog p { margin:0; color:var(--vw-text-2); font-size:12.5px; line-height:1.5; }
      button:focus-visible { outline:none; box-shadow:var(--vw-focus); }
      @media (max-width:340px) { .custom { grid-template-columns:76px minmax(0,1fr) auto 28px; } }
      @media (max-width:420px) { .footer-actions { flex-wrap:wrap; } .footer-note { flex-basis:100%; } }
      @media (prefers-reduced-motion:reduce) { .disclosure summary .disclosure-chevron { transition:none; } }
    `,
  ];

  override disconnectedCallback(): void {
    this.invalidate();
    super.disconnectedCallback();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    const identityChanged = changed.has('mode')
      || changed.has('cipherId')
      || changed.has('cipher')
      || changed.has('summary')
      || changed.has('createDefaults')
      || changed.has('draftKey');
    if (identityChanged) {
      const key = this.signature();
      if (key !== this.loadedKey) {
        this.loadedKey = key;
        this.invalidate();
        const source = this.cipher;
        const initialForm = source
          ? {
              name: source.name,
              notes: source.notes ?? '',
              folderId: source.folderId ?? '',
              favorite: source.favorite,
              reprompt: Boolean(source.reprompt),
              fields: editableFields(source.fields),
            }
          : { ...emptyForm(), folderId: this.createDefaults?.folderId ?? '' };
        this.form = initialForm;
        this.baselineForm = cloneForm(initialForm);
        this.createMethod = 'generate';
        this.collectionSelection = new Set(this.summary?.collectionIds ?? []);
        this.initializeCreateTarget();
      }
    }
    if (changed.has('personalCreationAllowed')
        || changed.has('collections')
        || changed.has('orgPermissions')) {
      this.reconcileCreateTarget();
    }
  }

  protected override updated(): void {
    if (this.mode === 'create') {
      const value = this.createVault?.kind === 'personal'
        ? 'personal'
        : this.createVault?.organizationId ?? '';
      const select = this.renderRoot.querySelector<HTMLSelectElement>('[data-create-vault]');
      if (select && select.value !== value) select.value = value;
    }
    if (this.validationFocus) {
      const target = this.renderRoot.querySelector<HTMLElement>(this.validationFocus);
      this.validationFocus = undefined;
      if (target) {
        let ancestor = target.parentElement;
        while (ancestor) {
          if (ancestor instanceof HTMLDetailsElement) ancestor.open = true;
          ancestor = ancestor.parentElement;
        }
        target.focus();
        target.scrollIntoView?.({ block: 'nearest' });
      }
    }
  }

  private signature(): string {
    return `${this.draftKey}|${this.mode}|${this.cipherId ?? ''}|${this.cipher ? '1' : '0'}|${this.summary?.id ?? ''}`;
  }

  private invalidate(): void {
    this.generation += 1;
    this.fileReadGeneration = undefined;
    this.validationError = undefined;
    this.validationFocus = undefined;
    this.replaceConfirmationOpen = false;
    this.moveSelection = new Set();
    this.createVault = undefined;
    this.createCollectionSelection = new Set();
    this.clearPrivateInputs();
  }

  private clearPrivateInputs(): void {
    for (const input of this.renderRoot.querySelectorAll<HTMLTextAreaElement>('[data-private-key]')) input.value = '';
    for (const input of this.renderRoot.querySelectorAll<HTMLInputElement>('[data-key-file]')) input.value = '';
  }

  private patch(patch: Partial<FormState>): void {
    this.form = { ...this.form, ...patch };
    this.validationError = undefined;
    this.requestUpdate();
  }

  private reportValidationError(message: string, selector: string): void {
    this.validationError = message;
    this.validationFocus = selector;
    this.requestUpdate();
  }

  private eligibleCreateOrganizations(): readonly OrgPermission[] {
    const seen = new Set<string>();
    return this.orgPermissions.filter((organization) => {
      if (!organization.id
          || seen.has(organization.id)
          || organization.isMember !== true
          || organization.canCreateItems !== true) return false;
      seen.add(organization.id);
      return this.writableCreateCollections(organization.id).length > 0;
    });
  }

  private writableCreateCollections(organizationId: string): readonly CollectionSummary[] {
    const seen = new Set<string>();
    return this.collections.filter((collection) => {
      if (!collection.id
          || seen.has(collection.id)
          || collection.organizationId !== organizationId
          || collection.canAssignItems !== true) return false;
      seen.add(collection.id);
      return true;
    });
  }

  private initializeCreateTarget(): void {
    this.createCollectionSelection = new Set();
    if (this.mode !== 'create') {
      this.createVault = undefined;
      return;
    }
    const defaultOrganizationId = this.createDefaults?.organizationId;
    const defaultOrganization = defaultOrganizationId
      ? this.eligibleCreateOrganizations().find((organization) => organization.id === defaultOrganizationId)
      : undefined;
    if (defaultOrganization) {
      this.createVault = { kind: 'organization', organizationId: defaultOrganization.id };
      const writableIds = new Set(this.writableCreateCollections(defaultOrganization.id).map(({ id }) => id));
      this.createCollectionSelection = new Set(
        (this.createDefaults?.collectionIds ?? []).filter((id) => writableIds.has(id)),
      );
      if (this.createCollectionSelection.size === 0) this.selectDefaultCreateCollection();
      return;
    }
    if (this.personalCreationAllowed) {
      this.createVault = { kind: 'personal' };
      return;
    }
    const organizations = this.eligibleCreateOrganizations();
    this.createVault = organizations.length === 1
      ? { kind: 'organization', organizationId: organizations[0]!.id }
      : undefined;
    this.selectDefaultCreateCollection();
  }

  private reconcileCreateTarget(): void {
    if (this.mode !== 'create') return;
    const defaultOrganizationId = this.createDefaults?.organizationId;
    if (defaultOrganizationId
        && this.createVault?.kind !== 'organization'
        && this.eligibleCreateOrganizations().some((organization) => organization.id === defaultOrganizationId)) {
      this.initializeCreateTarget();
      return;
    }
    if (!this.createVault) {
      this.initializeCreateTarget();
      return;
    }
    if (this.createVault.kind === 'personal') {
      if (!this.personalCreationAllowed) this.initializeCreateTarget();
      return;
    }
    const organizationId = this.createVault.organizationId;
    if (!this.eligibleCreateOrganizations().some(
      (organization) => organization.id === organizationId,
    )) {
      this.initializeCreateTarget();
      return;
    }
    const valid = new Set(this.writableCreateCollections(
      organizationId,
    ).map((collection) => collection.id));
    this.createCollectionSelection = new Set(
      [...this.createCollectionSelection].filter((id) => valid.has(id)),
    );
  }

  private selectCreateVault(value: string): void {
    if (this.pending || this.mode !== 'create') return;
    if (value === 'personal') {
      if (!this.personalCreationAllowed) return;
      this.createVault = { kind: 'personal' };
      this.createCollectionSelection = new Set();
    } else if (this.eligibleCreateOrganizations().some((organization) => organization.id === value)) {
      this.createVault = { kind: 'organization', organizationId: value };
      this.createCollectionSelection = new Set();
      this.selectDefaultCreateCollection();
    } else {
      return;
    }
    this.validationError = undefined;
    this.requestUpdate();
  }

  private selectDefaultCreateCollection(): void {
    if (this.createVault?.kind !== 'organization') return;
    const defaults = this.writableCreateCollections(this.createVault.organizationId)
      .filter((collection) => collection.type === 1);
    if (defaults.length === 1) this.createCollectionSelection.add(defaults[0]!.id);
  }

  private toggleCreateCollection(id: string, checked: boolean): void {
    if (this.pending || this.createVault?.kind !== 'organization') return;
    if (!this.writableCreateCollections(this.createVault.organizationId)
      .some((collection) => collection.id === id)) return;
    const next = new Set(this.createCollectionSelection);
    if (checked) next.add(id); else next.delete(id);
    this.createCollectionSelection = next;
    this.validationError = undefined;
    this.requestUpdate();
  }

  private collectCreateTarget(): CipherCreateTarget | undefined {
    if (this.createVault?.kind === 'personal' && this.personalCreationAllowed) {
      return { kind: 'personal' };
    }
    if (this.createVault?.kind !== 'organization') {
      this.reportValidationError(t('editor.chooseVaultError'), '[data-create-vault]');
      return undefined;
    }
    const valid = this.writableCreateCollections(this.createVault.organizationId);
    const collectionIds = valid
      .filter((collection) => this.createCollectionSelection.has(collection.id))
      .map((collection) => collection.id);
    if (collectionIds.length === 0
        || collectionIds.length !== this.createCollectionSelection.size) {
      this.reportValidationError(t('editor.chooseCollectionError'), '[data-create-collections] input');
      return undefined;
    }
    return {
      kind: 'organization',
      organizationId: this.createVault.organizationId,
      collectionIds,
    };
  }

  /** Includes every persisted metadata field plus pending private-key input or file work. */
  get hasUnsavedChanges(): boolean {
    const metadataChanged = formFingerprint(this.form) !== formFingerprint(this.baselineForm);
    const privateKeyChanged = this.privateKeyValue().trim().length > 0
      || this.fileReadGeneration === this.generation;
    const createMethodChanged = this.mode === 'create' && this.createMethod !== 'generate';
    return metadataChanged || privateKeyChanged || createMethodChanged;
  }

  /** Used by the popup root before a user-initiated navigation discards this draft. */
  promptForUnsavedEdits(): boolean {
    return !this.hasUnsavedChanges || window.confirm(t('editor.unsavedChanges'));
  }

  private addField(): void {
    this.patch({ fields: [...this.form.fields, { type: 0, name: '', value: '' }] });
  }

  private updateField(index: number, patch: Partial<SshField>): void {
    this.patch({ fields: this.form.fields.map((field, fieldIndex) => fieldIndex === index ? { ...field, ...patch } : field) });
  }

  private changeFieldType(index: number, type: SshFieldType): void {
    const existing = this.form.fields[index];
    if (!existing) return;
    this.patch({
      fields: this.form.fields.map((field, fieldIndex) => fieldIndex === index
        ? { type, name: existing.name, value: type === 2 ? 'false' : '' }
        : field),
    });
  }

  private removeField(index: number): void {
    this.patch({ fields: this.form.fields.filter((_, fieldIndex) => fieldIndex !== index) });
  }

  private moveField(index: number, direction: -1 | 1): void {
    if (this.pending) return;
    const target = index + direction;
    if (index < 0 || index >= this.form.fields.length || target < 0 || target >= this.form.fields.length) return;
    const fields = [...this.form.fields];
    [fields[index], fields[target]] = [fields[target]!, fields[index]!];
    this.patch({ fields });
  }

  private collectMetadata(): SshKeyMetadataInput | undefined {
    const name = this.form.name.trim();
    if (!name) {
      this.reportValidationError(t('ssh.error.nameRequired'), '[data-name]');
      return undefined;
    }
    const fields: DecryptedField[] = [];
    for (const field of this.form.fields) {
      const fieldName = field.name.trim();
      if (!fieldName) continue;
      fields.push({
        type: field.type,
        name: fieldName,
        value: field.type === 2 ? (field.value === 'true' ? 'true' : 'false') : (field.value ?? ''),
      });
    }
    return {
      name,
      notes: this.form.notes,
      favorite: this.form.favorite,
      reprompt: this.form.reprompt,
      folderId: this.form.folderId || null,
      fields,
    };
  }

  private privateKeyValue(): string {
    return this.renderRoot.querySelector<HTMLTextAreaElement>('[data-private-key]')?.value ?? '';
  }

  private submitCreate(): void {
    if (this.pending || !this.available) return;
    const metadata = this.collectMetadata();
    if (!metadata) return;
    const target = this.collectCreateTarget();
    if (!target) {
      this.requestUpdate();
      return;
    }
    if (this.createMethod === 'generate') {
      emit<SshCreateGenerateDetail>(this, 'vw-ssh-create-generate', { metadata, target });
      return;
    }
    const privateKey = this.privateKeyValue();
    if (!privateKey.trim()) {
      this.reportValidationError(t('ssh.error.privateKeyRequired'), '[data-private-key]');
      return;
    }
    emit<SshCreateImportDetail>(this, 'vw-ssh-create-import', { metadata, privateKey, target });
    this.clearPrivateInputs();
  }

  private submitMetadata(): void {
    if (this.pending || !this.available || !this.cipherId) return;
    const metadata = this.collectMetadata();
    if (!metadata) return;
    emit<SshUpdateMetadataDetail>(this, 'vw-ssh-update-metadata', { cipherId: this.cipherId, metadata });
  }

  private openReplaceConfirmation(): void {
    if (this.pending || !this.available || !this.privateKeyValue().trim()) {
      if (!this.privateKeyValue().trim()) {
        this.reportValidationError(t('ssh.error.privateKeyRequired'), '[data-private-key]');
      }
      return;
    }
    this.validationError = undefined;
    this.replaceConfirmationOpen = true;
    this.requestUpdate();
  }

  private confirmReplacement(): void {
    const cipherId = this.cipherId;
    const privateKey = this.privateKeyValue();
    this.replaceConfirmationOpen = false;
    if (cipherId && privateKey.trim() && !this.pending && this.available) {
      emit<SshReplaceKeyDetail>(this, 'vw-ssh-replace-key', { cipherId, privateKey });
    }
    this.clearPrivateInputs();
    this.requestUpdate();
  }

  private closeReplacement(): void {
    this.replaceConfirmationOpen = false;
    this.clearPrivateInputs();
    this.requestUpdate();
  }

  private async readKeyFile(event: Event): Promise<void> {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file || this.pending) return;
    if (file.size > MAX_PRIVATE_KEY_FILE_BYTES) {
      this.reportValidationError(t('ssh.error.fileTooLarge'), '[data-choose-key-file]');
      input.value = '';
      this.requestUpdate();
      return;
    }
    const generation = this.generation;
    this.fileReadGeneration = generation;
    this.requestUpdate();
    try {
      const privateKey = await file.text();
      if (!this.isConnected || generation !== this.generation) return;
      const target = this.renderRoot.querySelector<HTMLTextAreaElement>('[data-private-key]');
      if (target) target.value = privateKey;
      this.validationError = undefined;
    } catch {
      if (this.isConnected && generation === this.generation) {
        this.reportValidationError(t('ssh.error.fileRead'), '[data-choose-key-file]');
      }
    } finally {
      input.value = '';
      if (this.isConnected && this.fileReadGeneration === generation) {
        this.fileReadGeneration = undefined;
        this.requestUpdate();
      }
    }
  }

  private toggleCollection(id: string, checked: boolean): void {
    if (!this.collections.some((collection) => (
      collection.id === id
      && collection.organizationId === this.summary?.organizationId
      && this.canChangeCollectionMembership(collection)
    ))) return;
    const next = new Set(this.collectionSelection);
    if (checked) next.add(id); else next.delete(id);
    this.collectionSelection = next;
    this.requestUpdate();
  }

  private canChangeCollectionMembership(collection: CollectionSummary): boolean {
    if (collection.canAssignItems !== true) return false;
    const currentIds = this.summary?.collectionIds ?? [];
    if (collection.type !== 1 || currentIds.includes(collection.id) || currentIds.length === 0) {
      return true;
    }
    return this.collections.some((candidate) => (
      candidate.organizationId === collection.organizationId
      && candidate.type === 1
      && currentIds.includes(candidate.id)
    ));
  }

  private saveCollections(): void {
    if (!this.cipherId || this.pending) return;
    emit<CipherCollectionsDetail>(this, 'vw-cipher-collections', {
      cipherId: this.cipherId,
      collectionIds: [...this.collectionSelection],
    });
  }

  private toggleMoveCollection(collection: CollectionSummary, checked: boolean): void {
    const next = new Set(this.moveSelection);
    if (checked) {
      for (const selected of next) {
        const candidate = this.collections.find((item) => item.id === selected);
        if (candidate?.organizationId !== collection.organizationId) next.delete(selected);
      }
      next.add(collection.id);
    } else {
      next.delete(collection.id);
    }
    this.moveSelection = next;
    this.requestUpdate();
  }

  private moveToOrganization(): void {
    if (!this.cipherId || this.pending || this.moveSelection.size === 0) return;
    if (this.hasUnsavedChanges) {
      this.reportValidationError(t('editor.saveBeforeMove'), '[data-save-ssh-metadata]');
      return;
    }
    const collectionIds = [...this.moveSelection];
    const organizationId = this.collections.find((collection) => collection.id === collectionIds[0])?.organizationId;
    if (!organizationId) return;
    emit<EditorShareDetail>(this, 'vw-editor-share', { cipherId: this.cipherId, organizationId, collectionIds });
  }

  private renderHeader(): TemplateResult {
    return html`
      <header class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => emit(this, 'vw-item-back')}>${uiIcon('back')}</button>
        <h1>${this.mode === 'create' ? t('ssh.createTitle') : t('ssh.editTitle')}</h1>
      </header>
    `;
  }

  private renderCreateTarget(): TemplateResult | typeof nothing {
    if (this.mode !== 'create') return nothing;
    const organizations = this.eligibleCreateOrganizations();
    const value = this.createVault?.kind === 'personal'
      ? 'personal'
      : this.createVault?.organizationId ?? '';
    const collections = this.createVault?.kind === 'organization'
      ? this.writableCreateCollections(this.createVault.organizationId)
      : [];
    return html`
      <section class="section" data-create-target>
        <h2 class="section-title">${uiIcon('folder')}<span>${t('editor.vault')}</span></h2>
        <label class="field">
          <span class="label">${t('editor.vault')}</span>
          <select
            class="field-type"
            data-create-vault
            .value=${live(value)}
            ?disabled=${this.pending}
            @change=${(event: Event) => this.selectCreateVault(
              (event.target as HTMLSelectElement).value,
            )}
          >
            <option value="" disabled ?selected=${value === ''}>${t('editor.chooseVault')}</option>
            ${this.personalCreationAllowed
              ? html`<option value="personal" ?selected=${value === 'personal'}>${t('editor.personalVault')}</option>`
              : nothing}
            ${organizations.map((organization) => html`
              <option value=${organization.id} ?selected=${value === organization.id}>${organization.name}</option>
            `)}
          </select>
        </label>
        ${this.createVault?.kind === 'organization'
          ? html`
              <div class="field">
                <span class="label">${t('editor.collections')}</span>
                <div class="checks" data-create-collections>
                  ${collections.map((collection) => html`
                    <label class="check">
                      <input
                        type="checkbox"
                        value=${collection.id}
                        .checked=${this.createCollectionSelection.has(collection.id)}
                        ?disabled=${this.pending}
                        @change=${(event: Event) => this.toggleCreateCollection(
                          collection.id,
                          (event.target as HTMLInputElement).checked,
                        )}
                      />
                      <span>${collection.name}</span>
                    </label>
                  `)}
                </div>
              </div>
            `
          : nothing}
      </section>
    `;
  }

  private renderMetadata(): TemplateResult {
    return html`
      <section class="section" data-metadata>
        <h2 class="section-title">${uiIcon('edit')}<span>${t('ssh.metadata')}</span></h2>
        <label class="field"><span class="label">${t('editor.name')} *</span><input class="input" data-name required aria-invalid=${this.validationError === t('ssh.error.nameRequired') ? 'true' : 'false'} .value=${this.form.name} ?disabled=${this.pending} @input=${(event: Event) => this.patch({ name: (event.target as HTMLInputElement).value })} /></label>
        <label class="field"><span class="label">${t('detail.notes')}</span><textarea class="textarea" data-notes .value=${this.form.notes} ?disabled=${this.pending} @input=${(event: Event) => this.patch({ notes: (event.target as HTMLTextAreaElement).value })}></textarea></label>
      </section>
    `;
  }

  private ownerLabel(): string {
    const organizationId = this.mode === 'create'
      ? this.createVault?.kind === 'organization' ? this.createVault.organizationId : undefined
      : this.summary?.organizationId;
    if (organizationId) {
      return this.orgPermissions.find((organization) => organization.id === organizationId)?.name
        ?? t('ssh.organization');
    }
    return this.mode === 'create' && !this.createVault ? t('editor.chooseVault') : t('editor.personalVault');
  }

  private renderSettings(): TemplateResult {
    const folders = [{ id: '', name: t('ssh.noFolder') }, ...this.folders];
    const folder = folders.find(({ id }) => id === this.form.folderId)?.name ?? t('ssh.noFolder');
    return html`
      <details class="disclosure" data-ssh-settings>
        <summary>${uiIcon('folder')}<span class="summary-copy"><strong>${t('ssh.settings')}</strong><small>${this.ownerLabel()} · ${folder}</small></span><span class="disclosure-chevron">${uiIcon('chevronDown')}</span></summary>
        <div class="disclosure-body">
        ${this.renderCreateTarget()}
        <label class="field"><span class="label">${t('editor.folder')}</span><select class="field-type" data-folder .value=${this.form.folderId} ?disabled=${this.pending} @change=${(event: Event) => this.patch({ folderId: (event.target as HTMLSelectElement).value })}>${folders.map((folder) => html`<option value=${folder.id}>${folder.name}</option>`)}</select></label>
        <div class="toggle-row"><span>${t('editor.favorite')}</span><vw-toggle data-favorite .checked=${this.form.favorite} ?disabled=${this.pending} @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.patch({ favorite: event.detail.checked })}></vw-toggle></div>
        <div class="toggle-row"><span>${t('editor.reprompt')}</span><vw-toggle data-reprompt .checked=${this.form.reprompt} ?disabled=${this.pending} @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.patch({ reprompt: event.detail.checked })}></vw-toggle></div>
        </div>
      </details>
    `;
  }

  private renderCustomFields(): TemplateResult {
    return html`
      <details class="disclosure" data-custom-fields>
        <summary>${uiIcon('sliders')}<span class="summary-copy"><strong>${t('detail.customFields')}</strong><small>${this.form.fields.length ? t('ssh.customFieldCount', { count: this.form.fields.length }) : t('ssh.customFieldsHint')}</small></span><span class="disclosure-chevron">${uiIcon('chevronDown')}</span></summary>
        <div class="disclosure-body">
        <div class="custom-list">
          ${this.form.fields.map((field, index) => html`
            <div class="custom" data-ssh-field data-field-type=${field.type}>
              <select class="field-type" data-field-type-select aria-label=${t('ssh.fieldType')} .value=${String(field.type)} ?disabled=${this.pending} @change=${(event: Event) => this.changeFieldType(index, Number((event.target as HTMLSelectElement).value) as SshFieldType)}>
                <option value="0">${t('ssh.fieldText')}</option>
                <option value="1">${t('ssh.fieldHidden')}</option>
                <option value="2">${t('ssh.fieldBoolean')}</option>
              </select>
              <input class="input" data-field-name .value=${field.name} placeholder=${t('editor.name')} ?disabled=${this.pending} @input=${(event: Event) => this.updateField(index, { name: (event.target as HTMLInputElement).value })} />
              <span class="field-order">
                <button
                  type="button"
                  class="icon-btn xs move-up"
                  data-field-move-up
                  title=${t('editor.moveFieldUp', { name: field.name.trim() || t('detail.field') })}
                  aria-label=${t('editor.moveFieldUp', { name: field.name.trim() || t('detail.field') })}
                  ?disabled=${this.pending || index === 0}
                  @click=${() => this.moveField(index, -1)}
                >${uiIcon('chevronDown')}</button>
                <button
                  type="button"
                  class="icon-btn xs"
                  data-field-move-down
                  title=${t('editor.moveFieldDown', { name: field.name.trim() || t('detail.field') })}
                  aria-label=${t('editor.moveFieldDown', { name: field.name.trim() || t('detail.field') })}
                  ?disabled=${this.pending || index === this.form.fields.length - 1}
                  @click=${() => this.moveField(index, 1)}
                >${uiIcon('chevronDown')}</button>
              </span>
              <button type="button" class="icon-btn xs" data-remove-field title=${t('ssh.removeField')} aria-label=${t('ssh.removeField')} ?disabled=${this.pending} @click=${() => this.removeField(index)}>${uiIcon('trash')}</button>
              <div class="custom-value">
                ${field.type === 2
                  ? html`<span class="label">${t('ssh.booleanValue')}</span><vw-toggle data-field-value .checked=${field.value === 'true'} ?disabled=${this.pending} @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.updateField(index, { value: event.detail.checked ? 'true' : 'false' })}></vw-toggle>`
                  : html`<input class="input" data-field-value type=${field.type === 1 ? 'password' : 'text'} autocomplete="off" .value=${field.value ?? ''} placeholder=${t('ssh.fieldValue')} ?disabled=${this.pending} @input=${(event: Event) => this.updateField(index, { value: (event.target as HTMLInputElement).value })} />`}
              </div>
            </div>
          `)}
        </div>
        <button type="button" class="btn outline" data-add-field ?disabled=${this.pending} @click=${() => this.addField()}>${uiIcon('plus')}<span>${t('editor.addField')}</span></button>
        </div>
      </details>
    `;
  }

  private renderPrivateInput(purpose: 'import' | 'replace'): TemplateResult {
    const reading = this.fileReadGeneration === this.generation;
    return html`
      <label class="field"><span class="label">${t('ssh.privateKey')}</span><textarea class="textarea key" data-private-key aria-invalid=${this.validationError === t('ssh.error.privateKeyRequired') ? 'true' : 'false'} autocomplete="off" spellcheck="false" ?disabled=${this.pending || reading} placeholder=${t('ssh.privateKeyPlaceholder')}></textarea></label>
      <div class="actions">
        <button type="button" class="btn outline upload" data-choose-key-file ?disabled=${this.pending || reading} @click=${() => this.renderRoot.querySelector<HTMLInputElement>('[data-key-file]')?.click()}>
          ${uiIcon('file')}<span>${reading ? t('ssh.readingKey') : t('ssh.chooseKeyFile')}</span>
        </button>
        <input class="file-input" data-key-file type="file" accept=".pem,.key,.openssh,text/plain" ?disabled=${this.pending || reading} @change=${(event: Event) => void this.readKeyFile(event)} />
        ${purpose === 'replace'
          ? html`<button type="button" class="btn danger" data-replace-key ?disabled=${this.pending || reading || !this.available} @click=${() => this.openReplaceConfirmation()}>${uiIcon('refresh')}<span>${t('ssh.replaceKey')}</span></button>`
          : nothing}
      </div>
      <p class="hint">${t('ssh.importFileHint')}</p>
      <p class="hint">${t(purpose === 'replace' ? 'ssh.replaceHint' : 'ssh.importHint')}</p>
      <button type="button" class="btn ghost" data-clear-private-key ?disabled=${this.pending || reading} @click=${() => {
        this.clearPrivateInputs();
        this.validationError = undefined;
        this.requestUpdate();
        this.renderRoot.querySelector<HTMLTextAreaElement>('[data-private-key]')?.focus();
      }}>${t('ssh.clearPrivateInput')}</button>
    `;
  }

  private renderCreateMethod(): TemplateResult {
    const options = [
      { id: 'generate', label: t('ssh.generateEd25519') },
      { id: 'import', label: t('ssh.importPrivateKey') },
    ];
    return html`
      <section class="section" data-create-method>
        <h2 class="section-title">${uiIcon('key')}<span>${t('ssh.keyMaterial')}</span></h2>
        <vw-segmented .options=${options} .value=${this.createMethod} .height=${36} @vw-segmented-change=${(event: CustomEvent<{ id: string }>) => {
          if (this.pending) return;
          this.createMethod = event.detail.id === 'import' ? 'import' : 'generate';
          this.validationError = undefined;
          this.clearPrivateInputs();
          this.requestUpdate();
        }}></vw-segmented>
        ${this.createMethod === 'generate'
          ? html`<p class="hint">${t('ssh.generateHint')}</p>`
          : this.renderPrivateInput('import')}
      </section>
    `;
  }

  private renderPublicPreview(): TemplateResult | typeof nothing {
    if (!this.publicDetails) return nothing;
    return html`
      <details class="disclosure" data-public-preview>
        <summary>${uiIcon('fingerprint')}<span class="summary-copy"><strong>${t('ssh.currentPublicKey')}</strong><small>${t('ssh.publicKeySummary')}</small></span><span class="disclosure-chevron">${uiIcon('chevronDown')}</span></summary>
        <div class="disclosure-body">
        <div class="key-preview">
          ${this.publicDetails.keyFingerprint ? html`<code class="fingerprint">${this.publicDetails.keyFingerprint}</code>` : nothing}
          ${this.publicDetails.publicKey ? html`<code>${this.publicDetails.publicKey}</code>` : nothing}
        </div>
        </div>
      </details>
    `;
  }

  private renderOrganization(): TemplateResult | typeof nothing {
    if (this.mode !== 'edit' || !this.summary || !this.cipherId) return nothing;
    if (this.summary.organizationId) {
      const options = this.collections.filter((collection) => collection.organizationId === this.summary!.organizationId);
      if (!options.length) return nothing;
      return html`
        <details class="disclosure" data-ssh-collections>
          <summary>${uiIcon('folder')}<span class="summary-copy"><strong>${t('ssh.collections')}</strong><small>${this.ownerLabel()}</small></span><span class="disclosure-chevron">${uiIcon('chevronDown')}</span></summary>
          <div class="disclosure-body">
          <div class="checks">${options.map((collection) => html`<label class="check"><input type="checkbox" value=${collection.id} .checked=${this.collectionSelection.has(collection.id)} ?disabled=${this.pending || !this.canChangeCollectionMembership(collection)} @change=${(event: Event) => this.toggleCollection(collection.id, (event.target as HTMLInputElement).checked)} /><span>${collection.name}</span></label>`)}</div>
          <button type="button" class="btn outline" data-save-ssh-collections ?disabled=${this.pending || !options.some((collection) => this.canChangeCollectionMembership(collection))} @click=${() => this.saveCollections()}>${uiIcon('check')}<span>${t('ssh.saveCollections')}</span></button>
          <p class="hint">${t('ssh.collectionsHint')}</p>
          </div>
        </details>
      `;
    }
    if (this.summary.archivedDate || this.summary.deletedDate) return nothing;
    if (!this.collections.length) return nothing;
    const orgNames = new Map(this.orgPermissions.map((org) => [org.id, org.name]));
    return html`
      <details class="disclosure" data-ssh-move>
        <summary>${uiIcon('folder')}<span class="summary-copy"><strong>${t('ssh.moveToOrganization')}</strong><small>${t('editor.personalVault')}</small></span><span class="disclosure-chevron">${uiIcon('chevronDown')}</span></summary>
        <div class="disclosure-body">
        <p class="hint">${t('ssh.moveHint')}</p>
        <div class="checks">${this.collections.map((collection) => html`<label class="check"><input type="checkbox" value=${collection.id} .checked=${this.moveSelection.has(collection.id)} ?disabled=${this.pending} @change=${(event: Event) => this.toggleMoveCollection(collection, (event.target as HTMLInputElement).checked)} /><span>${orgNames.get(collection.organizationId) ?? t('ssh.organization')} · ${collection.name}</span></label>`)}</div>
        <button type="button" class="btn outline" data-move-ssh ?disabled=${this.pending || this.moveSelection.size === 0} @click=${() => this.moveToOrganization()}>${uiIcon('folder')}<span>${t('ssh.moveKey')}</span></button>
        </div>
      </details>
    `;
  }

  private renderReplacement(): TemplateResult {
    return html`
      <details class="disclosure" data-replacement>
        <summary>${uiIcon('refresh')}<span class="summary-copy"><strong>${t('ssh.replaceKey')}</strong><small>${t('ssh.replacementSummary')}</small></span><span class="disclosure-chevron">${uiIcon('chevronDown')}</span></summary>
        <div class="disclosure-body">
        ${this.renderPrivateInput('replace')}
        </div>
      </details>
    `;
  }

  private renderConfirmation(): TemplateResult | typeof nothing {
    if (!this.replaceConfirmationOpen) return nothing;
    const itemName = this.summary?.name ?? this.cipher?.name ?? this.form.name;
    const selectedCollections = this.collections
      .filter((collection) => collection.organizationId === this.summary?.organizationId
        && this.summary?.collectionIds?.includes(collection.id))
      .map((collection) => collection.name)
      .join(', ');
    return html`
      <vw-dialog .open=${true} .heading=${t('ssh.replaceConfirmItem', { name: itemName })} @vw-dialog-close=${(event: CustomEvent<{ reason: string }>) => {
        event.stopPropagation();
        if (event.detail.reason === 'confirm') this.confirmReplacement(); else this.closeReplacement();
      }}>
        <p>${t('ssh.replaceConfirm')}</p>
        <dl class="confirm-context">
          <div><dt>${t('editor.name')}</dt><dd>${itemName}</dd></div>
          <div><dt>${t('editor.vault')}</dt><dd>${this.ownerLabel()}${selectedCollections ? html` · ${selectedCollections}` : nothing}</dd></div>
          ${this.publicDetails?.keyFingerprint ? html`<div><dt>${t('ssh.fingerprint')}</dt><dd><code>${this.publicDetails.keyFingerprint}</code></dd></div>` : nothing}
        </dl>
        <p>${t('ssh.replaceHint')}</p>
        <p class="hint">${t('ssh.deployHint')}</p>
        <button slot="actions" type="button" class="btn ghost" data-cancel-replace @click=${() => this.renderRoot.querySelector<VwDialog>('vw-dialog')?.requestClose('dismiss')}>${t('common.cancel')}</button>
        <button slot="actions" type="button" class="btn danger" data-confirm-replace ?disabled=${this.pending} @click=${() => this.renderRoot.querySelector<VwDialog>('vw-dialog')?.requestClose('confirm')}>${t('ssh.replaceConfirmAction', { name: itemName })}</button>
      </vw-dialog>
    `;
  }

  protected override render(): TemplateResult {
    if (!this.available) {
      return html`${this.renderHeader()}<p class="unavailable">${t('ssh.writeUnavailable')}</p>`;
    }
    return html`
      ${this.renderHeader()}
      <form class="editor-form" novalidate @submit=${(event: SubmitEvent) => {
        event.preventDefault();
        if (this.mode === 'create') this.submitCreate(); else this.submitMetadata();
      }}>
        <main class="scroll">
          ${this.renderMetadata()}
          ${this.mode === 'create' ? this.renderCreateMethod() : this.renderPublicPreview()}
          ${this.renderCustomFields()}
          ${this.renderSettings()}
          ${this.mode === 'edit' ? html`${this.renderOrganization()}${this.renderReplacement()}` : html`<p class="hint">${t('ssh.deployHint')}</p>`}
        </main>
        <footer class="editor-footer">
          ${this.status ? html`<vw-status-message class="status" .tone=${this.status.tone} .icon=${this.status.tone === 'success' ? 'checkCircle' : 'alert'} .message=${this.status.message}></vw-status-message>` : nothing}
          ${this.validationError ? html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
          <div class="footer-actions">
            <p class="footer-note">${this.mode === 'create' ? `${this.ownerLabel()} · ${t('ssh.unsavedDraft')}` : t('ssh.metadataOnlyHint')}</p>
            <button type="button" class="btn ghost" ?disabled=${this.pending} @click=${() => emit(this, 'vw-item-back')}>${t('common.cancel')}</button>
            ${this.mode === 'create'
              ? html`<button type="submit" class="btn primary" data-create-ssh ?disabled=${this.pending || this.fileReadGeneration === this.generation}>${uiIcon(this.createMethod === 'generate' ? 'wand' : 'key')}<span>${t(this.createMethod === 'generate' ? 'ssh.generateAndSave' : 'ssh.importAndSave')}</span></button>`
              : html`<button type="submit" class="btn primary" data-save-ssh-metadata ?disabled=${this.pending}>${uiIcon('check')}<span>${t('ssh.saveMetadata')}</span></button>`}
          </div>
        </footer>
      </form>
      ${this.renderConfirmation()}
    `;
  }
}

function cloneForm(form: FormState): FormState {
  return {
    ...form,
    fields: form.fields.map((field) => ({ ...field })),
  };
}

function formFingerprint(form: FormState): string {
  return JSON.stringify({
    name: form.name,
    notes: form.notes,
    folderId: form.folderId,
    favorite: form.favorite,
    reprompt: form.reprompt,
    fields: form.fields,
  });
}

customElements.define('vw-ssh-key-editor', VwSshKeyEditor);

declare global {
  interface HTMLElementTagNameMap {
    'vw-ssh-key-editor': VwSshKeyEditor;
  }
}
