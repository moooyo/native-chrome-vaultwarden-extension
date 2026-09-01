import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { live } from 'lit/directives/live.js';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import '../../components/toggle.js';
import '../../components/select-menu.js';
import type { SelectOption } from '../../components/select-menu.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type {
  CipherCreateTarget,
  CipherInput,
  CipherSummary,
  CollectionSummary,
  CustomFieldType,
  DecryptedField,
} from '../../../core/vault/models.js';
import type { GeneratorHistoryEntry } from '../../../core/generator/history.js';
import {
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  type GeneratorPolicySnapshot,
} from '../../../core/generator/enterprise-password-policy.js';
import {
  isSupportedLinkedFieldId,
  linkedFieldOptionsForCipherType,
} from '../../../core/vault/linked-fields.js';
import {
  UriMatchStrategy,
  isUriMatchStrategySetting,
  type LoginUri,
} from '../../../core/vault/uri-match.js';
import type { DeleteItemDetail, DetailStatus, GeneratorSelectionDetail } from '../types.js';
import type {
  CipherCollectionsDetail,
  EditorContext,
  EditorSaveDetail,
  EditorShareDetail,
  EditorTotpCapture,
} from './editor-types.js';
import { linkedFieldSourceLabel } from '../linked-field-label.js';
import { safeWebUrl } from '../utils.js';
import '../tools/generator-view.js';

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
  autofillOnPageLoad: boolean | null;
  card: Record<string, string>;
  identity: Record<string, string>;
  fields: DecryptedField[];
  showPassword: boolean;
}

interface ExistingFieldMetadata {
  readonly originalName: string;
}

type CreateVaultSelection =
  | { readonly kind: 'personal' }
  | { readonly kind: 'organization'; readonly organizationId: string };

/**
 * The create/edit form for a cipher. It owns all form state (derived from the handed-down
 * `EditorContext`), validates locally, and emits a complete `EditorSaveDetail` via
 * `vw-editor-save`; the root performs the request. Create events include an explicit personal or
 * organization target, while edit events keep the target undefined. Organization collection assignment
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
    totpCapture: { attribute: false },
    generatorHistory: { attribute: false },
    generatorPolicy: { attribute: false },
    generatorAccountEmail: { attribute: false },
    generatorTarget: { state: true },
  };

  declare context: EditorContext;
  declare summary: CipherSummary | undefined;
  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare totpCapture: EditorTotpCapture | undefined;
  declare generatorHistory: readonly GeneratorHistoryEntry[];
  declare generatorPolicy: GeneratorPolicySnapshot;
  declare generatorAccountEmail: string | undefined;
  declare generatorTarget: GeneratorSelectionDetail['target'] | null;

  private i18n = new LocalizeController(this);
  private form: FormState = emptyForm();
  private baselineForm: FormState = emptyForm();
  private collectionSel = new Set<string>();
  private createVault: CreateVaultSelection | undefined;
  private createCollectionSel = new Set<string>();
  private moveOrganizationId: string | undefined;
  private moveCollectionSel = new Set<string>();
  private localError: string | undefined;
  private confirmingDelete = false;
  private loadedKey: string | null = null;
  private appliedTotpCaptureRevision = -1;
  private existingFields = new WeakMap<DecryptedField, ExistingFieldMetadata>();

  constructor() {
    super();
    this.context = {
      mode: 'create',
      draftKey: 'empty',
      type: 1,
      personalCreationAllowed: false,
      folders: [],
      collections: [],
      orgPermissions: [],
    };
    this.summary = undefined;
    this.pending = false;
    this.status = undefined;
    this.totpCapture = undefined;
    this.generatorHistory = [];
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    this.generatorAccountEmail = undefined;
    this.generatorTarget = null;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        position: relative;
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
        font-size: 15px;
        font-weight: 500;
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
        height: 38px;
        padding: 0 17px;
        border: none;
        border-radius: 19px;
        background: var(--vw-primary-bg);
        color: var(--vw-primary-fg);
        font-family: var(--vw-font-ui);
        font-size: 12.5px;
        font-weight: 500;
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
        width: 6px;
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
        font-size: 11px;
        font-weight: 400;
        letter-spacing: 0;
        color: var(--vw-text-2);
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
      .uri-list {
        display: flex;
        flex-direction: column;
        gap: 9px;
      }
      .uri-entry {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding-top: 9px;
        border-top: 1px solid var(--vw-line-1);
      }
      .uri-entry:first-child {
        padding-top: 0;
        border-top: none;
      }
      .uri-controls {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .uri-match-label {
        font-size: 11px;
        color: var(--vw-muted);
      }
      .uri-match {
        flex: none;
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
        border: 1px solid var(--vw-line-3);
        border-radius: 10px;
        background: var(--vw-card);
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
      .cf-order {
        display: inline-flex;
        flex: none;
        gap: 2px;
      }
      .cf-order .move-up svg {
        transform: rotate(180deg);
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
      .cf-warning {
        font-size: 11.5px;
        line-height: 1.4;
        color: var(--vw-sync-amber);
      }
      .org {
        gap: 8px;
      }
      .create-target {
        min-inline-size: 0;
        margin: 0;
        padding: 0;
        border: 0;
      }
      .create-target > legend {
        margin-bottom: 6px;
        padding: 0;
      }
      .create-target + .create-target {
        margin-top: -2px;
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
    `,
  ];

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('context') || changed.has('summary')) {
      const key = this.signature();
      if (key === this.loadedKey) {
        if (changed.has('context') && this.context.mode !== 'edit') this.reconcileCreateTarget();
        this.reconcileMoveTarget();
      } else {
        this.loadedKey = key;
        const initialForm = this.initForm();
        this.form = initialForm;
        this.baselineForm = cloneForm(initialForm);
        this.collectionSel = new Set(this.summary?.collectionIds ?? []);
        this.initializeCreateTarget();
        this.initializeMoveTarget();
        this.generatorTarget = null;
        this.localError = undefined;
        this.confirmingDelete = false;
      }
    }
    const capture = this.totpCapture;
    if (capture && this.context.type === 1
      && capture.revision !== this.appliedTotpCaptureRevision) {
      this.appliedTotpCaptureRevision = capture.revision;
      this.form = { ...this.form, totp: capture.value };
      this.localError = undefined;
    }
  }

  private signature(): string {
    const c = this.context;
    return `${c.draftKey}|${c.mode}|${c.type}|${c.cipherId ?? ''}|${c.input ? '1' : '0'}|${this.summary?.id ?? ''}`;
  }

  private initForm(): FormState {
    const input = this.context.input;
    const login = input?.login ?? {};
    const fields = (input?.fields ?? []).map((field) => ({ ...field }));
    this.existingFields = new WeakMap();
    if (this.context.mode === 'edit') {
      for (const field of fields) {
        this.existingFields.set(field, { originalName: field.name });
      }
    }
    return {
      name: input?.name ?? '',
      notes: input?.notes ?? '',
      favorite: input?.favorite ?? false,
      reprompt: input?.reprompt ?? false,
      folderId: input?.folderId ?? this.context.createDefaults?.folderId ?? '',
      username: login.username ?? '',
      password: login.password ?? '',
      totp: login.totp ?? '',
      uris: login.uris?.length
        ? login.uris.map((u) => ({ ...u }))
        : [{ uri: this.context.createDefaults?.loginUri ?? '' }],
      autofillOnPageLoad: login.autofillOnPageLoad ?? null,
      card: { ...(input?.card ?? {}) } as Record<string, string>,
      identity: { ...(input?.identity ?? {}) } as Record<string, string>,
      fields,
      showPassword: false,
    };
  }

  private patch(patch: Partial<FormState>): void {
    this.form = { ...this.form, ...patch };
    this.requestUpdate();
  }

  /** Whether saving now would change any persisted cipher field. Display-only state is excluded. */
  get hasUnsavedChanges(): boolean {
    return formFingerprint(this.form) !== formFingerprint(this.baselineForm);
  }

  // --- create destination ----------------------------------------------------------------------

  private eligibleCreateOrganizations() {
    const seen = new Set<string>();
    return this.context.orgPermissions.filter((organization) => {
      if (
        !organization.id
        || seen.has(organization.id)
        || organization.isMember !== true
        || organization.canCreateItems !== true
      ) return false;
      seen.add(organization.id);
      return true;
    });
  }

  private writableCreateCollections(organizationId: string) {
    const seen = new Set<string>();
    return this.context.collections.filter((collection) => {
      if (
        !collection.id
        || seen.has(collection.id)
        || collection.organizationId !== organizationId
        || collection.canAssignItems !== true
      ) return false;
      seen.add(collection.id);
      return true;
    });
  }

  private eligibleMoveOrganizations() {
    return this.eligibleCreateOrganizations().filter(
      (organization) => this.writableCreateCollections(organization.id).length > 0,
    );
  }

  private initializeMoveTarget(): void {
    this.moveOrganizationId = undefined;
    this.moveCollectionSel = new Set();
    if (!this.canMove() || this.context.personalCreationAllowed) return;
    const organizations = this.eligibleMoveOrganizations();
    if (organizations.length !== 1) return;
    const organizationId = organizations[0]!.id;
    this.moveOrganizationId = organizationId;
    const defaultCollections = this.writableCreateCollections(organizationId)
      .filter((collection) => collection.type === 1);
    if (defaultCollections.length === 1) {
      this.moveCollectionSel.add(defaultCollections[0]!.id);
    }
  }

  private reconcileMoveTarget(): void {
    if (!this.canMove()) {
      this.moveOrganizationId = undefined;
      this.moveCollectionSel = new Set();
      return;
    }
    const organizationId = this.moveOrganizationId;
    const organizations = this.eligibleMoveOrganizations();
    if (!organizationId || !organizations.some((organization) => organization.id === organizationId)) {
      this.moveOrganizationId = undefined;
      this.moveCollectionSel = new Set();
      return;
    }
    const validIds = new Set(this.writableCreateCollections(organizationId).map((collection) => collection.id));
    this.moveCollectionSel = new Set([...this.moveCollectionSel].filter((id) => validIds.has(id)));
  }

  private selectMoveOrganization(organizationId: string): void {
    if (this.pending || !this.canMove()) return;
    if (!this.eligibleMoveOrganizations().some((organization) => organization.id === organizationId)) return;
    if (this.moveOrganizationId === organizationId) return;
    this.moveOrganizationId = organizationId;
    this.moveCollectionSel = new Set();
    this.localError = undefined;
    this.requestUpdate();
  }

  private toggleMoveCollection(id: string, checked: boolean): void {
    if (this.pending || !this.moveOrganizationId) return;
    if (!this.writableCreateCollections(this.moveOrganizationId).some((collection) => collection.id === id)) return;
    const next = new Set(this.moveCollectionSel);
    if (checked) next.add(id);
    else next.delete(id);
    this.moveCollectionSel = next;
    this.localError = undefined;
    this.requestUpdate();
  }

  private initializeCreateTarget(): void {
    this.createCollectionSel = new Set();
    if (this.context.mode === 'edit') {
      this.createVault = undefined;
      return;
    }
    const defaultOrganizationId = this.context.createDefaults?.organizationId;
    const defaultOrganization = defaultOrganizationId
      ? this.eligibleCreateOrganizations().find((organization) => organization.id === defaultOrganizationId)
      : undefined;
    if (defaultOrganization) {
      this.createVault = { kind: 'organization', organizationId: defaultOrganization.id };
      const writableIds = new Set(this.writableCreateCollections(defaultOrganization.id).map(({ id }) => id));
      this.createCollectionSel = new Set(
        (this.context.createDefaults?.collectionIds ?? []).filter((id) => writableIds.has(id)),
      );
      return;
    }
    if (this.context.personalCreationAllowed) {
      this.createVault = { kind: 'personal' };
      return;
    }
    const organizations = this.eligibleCreateOrganizations();
    this.createVault = organizations.length === 1
      ? { kind: 'organization', organizationId: organizations[0]!.id }
      : undefined;
  }

  private reconcileCreateTarget(): void {
    if (!this.createVault) {
      this.createCollectionSel = new Set();
      return;
    }
    if (this.createVault.kind === 'personal') {
      if (!this.context.personalCreationAllowed) this.createVault = undefined;
      this.createCollectionSel = new Set();
      return;
    }
    const organizationId = this.createVault.organizationId;
    if (!this.eligibleCreateOrganizations().some((organization) => organization.id === organizationId)) {
      this.createVault = undefined;
      this.createCollectionSel = new Set();
      return;
    }
    const validIds = new Set(this.writableCreateCollections(organizationId).map((collection) => collection.id));
    this.createCollectionSel = new Set([...this.createCollectionSel].filter((id) => validIds.has(id)));
  }

  private selectCreateVault(selection: CreateVaultSelection): void {
    if (this.pending || this.context.mode === 'edit') return;
    const permitted = selection.kind === 'personal'
      ? this.context.personalCreationAllowed
      : this.eligibleCreateOrganizations().some((organization) => organization.id === selection.organizationId);
    if (!permitted) return;
    if (
      this.createVault?.kind === selection.kind
      && (selection.kind === 'personal'
        || (this.createVault.kind === 'organization'
          && this.createVault.organizationId === selection.organizationId))
    ) return;
    this.createVault = selection;
    this.createCollectionSel = new Set();
    this.localError = undefined;
    this.requestUpdate();
  }

  private toggleCreateCollection(id: string, checked: boolean): void {
    if (this.pending || this.createVault?.kind !== 'organization') return;
    if (!this.writableCreateCollections(this.createVault.organizationId).some((collection) => collection.id === id)) return;
    const next = new Set(this.createCollectionSel);
    if (checked) next.add(id);
    else next.delete(id);
    this.createCollectionSel = next;
    this.localError = undefined;
    this.requestUpdate();
  }

  private collectCreateTarget(): CipherCreateTarget | undefined {
    const selection = this.createVault;
    if (!selection) {
      this.localError = t('editor.chooseVaultError');
      return undefined;
    }
    if (selection.kind === 'personal') {
      if (!this.context.personalCreationAllowed) {
        this.localError = t('editor.chooseVaultError');
        return undefined;
      }
      return { kind: 'personal' };
    }
    const permitted = this.eligibleCreateOrganizations()
      .some((organization) => organization.id === selection.organizationId);
    const collections = this.writableCreateCollections(selection.organizationId);
    const collectionIds = collections
      .filter((collection) => this.createCollectionSel.has(collection.id))
      .map((collection) => collection.id);
    if (!permitted) {
      this.localError = t('editor.chooseVaultError');
      return undefined;
    }
    if (collectionIds.length === 0 || collectionIds.length !== this.createCollectionSel.size) {
      this.localError = t('editor.chooseCollectionError');
      return undefined;
    }
    return {
      kind: 'organization',
      organizationId: selection.organizationId,
      collectionIds,
    };
  }

  // --- collection membership (organization items) -----------------------------------------------

  private get orgCollections() {
    const orgId = this.summary?.organizationId;
    if (!orgId) return [];
    return this.context.collections.filter((c) => c.organizationId === orgId);
  }

  private canChangeCollectionMembership(collection: CollectionSummary): boolean {
    if (collection.canAssignItems !== true) return false;
    const currentIds = this.summary?.collectionIds ?? [];
    if (collection.type !== 1 || currentIds.includes(collection.id) || currentIds.length === 0) {
      return true;
    }
    return this.orgCollections.some((candidate) => (
      candidate.type === 1 && currentIds.includes(candidate.id)
    ));
  }

  private toggleCollection(id: string, checked: boolean): void {
    if (!this.orgCollections.some((collection) => (
      collection.id === id && this.canChangeCollectionMembership(collection)
    ))) return;
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

  private moveField(index: number, direction: -1 | 1): void {
    if (this.pending) return;
    const target = index + direction;
    if (index < 0 || index >= this.form.fields.length || target < 0 || target >= this.form.fields.length) return;
    const fields = [...this.form.fields];
    [fields[index], fields[target]] = [fields[target]!, fields[index]!];
    this.patch({ fields });
  }

  private updateField(index: number, changes: Partial<DecryptedField>): void {
    this.patch({
      fields: this.form.fields.map((field, currentIndex) => {
        if (currentIndex !== index) return field;
        const updated = { ...field, ...changes };
        const metadata = this.existingFields.get(field);
        if (metadata) this.existingFields.set(updated, metadata);
        return updated;
      }),
    });
  }

  private changeFieldType(index: number, type: CustomFieldType): void {
    const current = this.form.fields[index];
    if (!current || this.existingFields.has(current)) return;
    if (!this.customFieldTypes().some(([candidate]) => candidate === type)) return;
    const linkedId = type === 3 ? this.linkedFieldOptions()[0]?.id : undefined;
    if (type === 3 && linkedId === undefined) return;
    const value = type === 2
      ? (current.value === 'true' || current.value === 'false' ? current.value : 'false')
      : (type === 0 || type === 1) && current.type !== 3
        ? current.value
        : undefined;
    this.patch({
      fields: this.form.fields.map((field, currentIndex) => (
        currentIndex === index
          ? {
              type,
              name: field.name,
              ...(value === undefined ? {} : { value }),
              ...(linkedId === undefined ? {} : { linkedId }),
            }
          : field
      )),
    });
  }

  private changeLinkedField(index: number, value: string): void {
    const linkedId = Number(value);
    if (!isSupportedLinkedFieldId(this.context.type, linkedId)) return;
    this.updateField(index, { linkedId });
  }

  private linkedFieldOptions() {
    return linkedFieldOptionsForCipherType(this.context.type);
  }

  private customFieldTypes(): ReadonlyArray<readonly [CustomFieldType, string]> {
    const types: Array<readonly [CustomFieldType, string]> = [
      [0, t('editor.customFieldText')],
      [1, t('editor.customFieldHidden')],
      [2, t('editor.customFieldBoolean')],
    ];
    if (this.linkedFieldOptions().length > 0) types.push([3, t('editor.customFieldLinked')]);
    return types;
  }

  // --- collection / collect / emit --------------------------------------------------------------

  private collectFields(): DecryptedField[] {
    const out: DecryptedField[] = [];
    for (const source of this.form.fields) {
      const name = this.existingFields.has(source) ? source.name : source.name.trim();
      if (source.type === 3) {
        const field: DecryptedField = { type: 3, name };
        if (source.linkedId !== undefined) field.linkedId = source.linkedId;
        out.push(field);
        continue;
      }
      const field: DecryptedField = { type: source.type, name };
      if (source.value !== undefined) field.value = source.value;
      out.push(field);
    }
    return out;
  }

  private preservesLegacyEmptyName(field: DecryptedField): boolean {
    const metadata = this.existingFields.get(field);
    return metadata !== undefined
      && !metadata.originalName.trim()
      && field.name === metadata.originalName;
  }

  private firstInvalidFieldName(): DecryptedField | undefined {
    return this.form.fields.find((field) => !field.name.trim() && !this.preservesLegacyEmptyName(field));
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
      login.autofillOnPageLoad = f.autofillOnPageLoad;
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
    emit<T>(this, type, detail);
  }

  private save(): void {
    if (this.pending) return;
    const input = this.collectInput();
    if (!input.name) {
      this.localError = '请输入名称'; // TODO i18n
      this.requestUpdate();
      return;
    }
    if (this.firstInvalidFieldName()) {
      this.localError = t('editor.customFieldNameRequired');
      this.requestUpdate();
      return;
    }
    const target = this.context.mode !== 'edit' ? this.collectCreateTarget() : undefined;
    if (this.context.mode !== 'edit' && !target) {
      this.requestUpdate();
      return;
    }
    this.localError = undefined;
    this.emit<EditorSaveDetail>('vw-editor-save', { input, target });
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
    if (this.hasUnsavedChanges) {
      this.localError = t('editor.saveBeforeMove');
      this.requestUpdate();
      return;
    }
    const organizationId = this.moveOrganizationId;
    if (!organizationId || !this.eligibleMoveOrganizations().some((organization) => organization.id === organizationId)) {
      this.moveOrganizationId = undefined;
      this.moveCollectionSel = new Set();
      this.localError = t('editor.chooseMoveOrganizationError');
      this.requestUpdate();
      return;
    }
    const collections = this.writableCreateCollections(organizationId);
    const collectionIds = collections
      .filter((collection) => this.moveCollectionSel.has(collection.id))
      .map((collection) => collection.id);
    if (collectionIds.length === 0 || collectionIds.length !== this.moveCollectionSel.size) {
      this.moveCollectionSel = new Set(collectionIds);
      this.localError = t('editor.chooseMoveCollectionError');
      this.requestUpdate();
      return;
    }
    this.localError = undefined;
    this.emit<EditorShareDetail>('vw-editor-share', {
      cipherId: this.context.cipherId,
      organizationId,
      collectionIds,
    });
  }

  private confirmDelete(): void {
    if (this.pending || !this.context.cipherId) return;
    this.emit<DeleteItemDetail>('vw-delete-item', { cipherId: this.context.cipherId, permanent: false });
  }

  private openGenerator(target: GeneratorSelectionDetail['target']): void {
    if (this.pending || this.context.type !== 1) return;
    this.generatorTarget = target;
  }

  private closeGenerator(event?: Event): void {
    event?.stopPropagation();
    this.generatorTarget = null;
  }

  private applyGeneratedValue(event: CustomEvent<GeneratorSelectionDetail>): void {
    event.stopPropagation();
    const { target, value } = event.detail;
    if (target !== this.generatorTarget || typeof value !== 'string' || !value || value.length > 1_024) {
      return;
    }
    if (target === 'username') this.patch({ username: value });
    else this.patch({ password: value });
    this.closeGenerator();
  }

  private generatorWebsiteUri(): string | undefined {
    for (const entry of this.form.uris) {
      const uri = safeWebUrl(entry.uri.trim());
      if (uri) return uri;
    }
    return undefined;
  }

  /** Used by the popup root before a user-initiated navigation discards this draft. */
  promptForUnsavedEdits(): boolean {
    return !this.hasUnsavedChanges || window.confirm(t('editor.unsavedChanges'));
  }

  private back(): void {
    emit(this, 'vw-item-back');
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
        <div class="row">
          <input class="input" data-username .value=${f.username} ?disabled=${this.pending}
            @input=${(e: Event) => this.patch({ username: (e.target as HTMLInputElement).value })} />
          <button
            type="button"
            class="icon-btn"
            data-generate-username
            title=${t('editor.generateUsername')}
            aria-label=${t('editor.generateUsername')}
            ?disabled=${this.pending}
            @click=${() => this.openGenerator('username')}
          >${uiIcon('wand')}</button>
        </div>
      </div>
      <div class="field">
        <span class="label">${t('detail.password')}</span>
        <div class="row">
          <input class="input mono" data-password type=${f.showPassword ? 'text' : 'password'} .value=${f.password} ?disabled=${this.pending}
            @input=${(e: Event) => this.patch({ password: (e.target as HTMLInputElement).value })} />
          <button
            type="button"
            class="icon-btn"
            data-generate-password
            title=${t('editor.generatePassword')}
            aria-label=${t('editor.generatePassword')}
            ?disabled=${this.pending}
            @click=${() => this.openGenerator('password')}
          >${uiIcon('wand')}</button>
          <button type="button" class="icon-btn" data-toggle-password aria-pressed=${f.showPassword ? 'true' : 'false'}
            title=${revealLabel} aria-label=${revealLabel}
            @click=${() => this.patch({ showPassword: !f.showPassword })}>${uiIcon(f.showPassword ? 'eyeOff' : 'eye')}</button>
        </div>
      </div>
      <div class="field">
        <span class="label">${t('detail.totp')}</span>
        <div class="row">
          <input
            class="input mono"
            data-field="totp"
            .value=${f.totp}
            ?disabled=${this.pending}
            @input=${(event: Event) => this.patch({
              totp: (event.target as HTMLInputElement).value,
            })}
          />
          <button
            type="button"
            class="icon-btn"
            data-capture-totp
            title=${t('editor.captureTotp')}
            aria-label=${t('editor.captureTotp')}
            ?disabled=${this.pending}
            @click=${() => emit(this, 'vw-totp-capture')}
          >${uiIcon('scan')}</button>
        </div>
      </div>
      <div class="field">
        <span class="label">${t('detail.uri')}</span>
        <div class="uri-list">
          ${f.uris.map(
            (u, i) => html`
              <div class="uri-entry" data-uri-entry=${i}>
                <div class="row">
                  <input class="input mono" data-uri=${i} placeholder="https://example.com" .value=${u.uri} ?disabled=${this.pending}
                    @input=${(e: Event) => this.updateUri(i, (e.target as HTMLInputElement).value)} />
                  <button
                    type="button"
                    class="icon-btn sm"
                    data-remove-uri=${i}
                    title=${t('editor.removeUri')}
                    aria-label=${t('editor.removeUri')}
                    ?disabled=${this.pending || f.uris.length === 1}
                    @click=${() => this.removeUri(i)}
                  >${uiIcon('trash')}</button>
                </div>
                <div class="uri-controls">
                  <span class="uri-match-label">${t('editor.uriMatch')}</span>
                  <vw-select
                    class="uri-match"
                    data-uri-match=${i}
                    ?inert=${this.pending}
                    aria-disabled=${this.pending ? 'true' : 'false'}
                    .options=${this.uriMatchOptions()}
                    .value=${u.match === undefined || u.match === null ? '' : String(u.match)}
                    .label=${t('editor.uriMatch')}
                    @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.updateUriMatch(i, e.detail.value)}
                  ></vw-select>
                </div>
              </div>
            `,
          )}
        </div>
        <button type="button" class="add" data-add-uri ?disabled=${this.pending} @click=${() => this.addUri()}>${uiIcon('plus')}<span>${t('editor.addUri')}</span></button>
      </div>
      <div class="field">
        <span class="label">${t('editor.pageLoadOverride')}</span>
        <vw-select
          data-page-load-override
          ?inert=${this.pending}
          aria-disabled=${this.pending ? 'true' : 'false'}
          .options=${this.pageLoadOptions()}
          .value=${f.autofillOnPageLoad === null ? 'inherit' : String(f.autofillOnPageLoad)}
          .label=${t('editor.pageLoadOverride')}
          @vw-select-change=${(event: CustomEvent<{ value: string }>) => this.updatePageLoadOverride(event.detail.value)}
        ></vw-select>
      </div>
    `;
  }

  private pageLoadOptions(): SelectOption[] {
    return [
      { value: 'inherit', label: t('editor.pageLoadInherit') },
      { value: 'true', label: t('common.yes') },
      { value: 'false', label: t('common.no') },
    ];
  }

  private updatePageLoadOverride(value: string): void {
    if (this.pending) return;
    if (value === 'inherit') this.patch({ autofillOnPageLoad: null });
    else if (value === 'true' || value === 'false') {
      this.patch({ autofillOnPageLoad: value === 'true' });
    }
  }

  private uriMatchOptions(): SelectOption[] {
    return [
      { value: '', label: t('editor.uriMatchInherit') },
      { value: String(UriMatchStrategy.Domain), label: t('editor.uriMatchDomain') },
      { value: String(UriMatchStrategy.Host), label: t('editor.uriMatchHost') },
      { value: String(UriMatchStrategy.StartsWith), label: t('editor.uriMatchStartsWith') },
      { value: String(UriMatchStrategy.Exact), label: t('editor.uriMatchExact') },
      { value: String(UriMatchStrategy.RegularExpression), label: t('editor.uriMatchRegex') },
      { value: String(UriMatchStrategy.Never), label: t('editor.uriMatchNever') },
    ];
  }

  private updateUri(index: number, uri: string): void {
    this.patch({ uris: this.form.uris.map((u, i) => (i === index ? { ...u, uri } : u)) });
  }

  private updateUriMatch(index: number, value: string): void {
    if (this.pending) return;
    if (value === '') {
      this.patch({ uris: this.form.uris.map((u, i) => (i === index ? { uri: u.uri } : u)) });
      return;
    }
    const match = Number(value);
    if (!isUriMatchStrategySetting(match)) return;
    this.patch({ uris: this.form.uris.map((u, i) => (i === index ? { ...u, match } : u)) });
  }

  private removeUri(index: number): void {
    if (this.form.uris.length <= 1) return;
    this.patch({ uris: this.form.uris.filter((_, i) => i !== index) });
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

  private renderCustomFieldActions(field: DecryptedField, index: number) {
    const fieldLabel = field.name.trim() || t('detail.field');
    const moveUpLabel = t('editor.moveFieldUp', { name: fieldLabel });
    const moveDownLabel = t('editor.moveFieldDown', { name: fieldLabel });
    return html`
      <span class="cf-order">
        <button
          type="button"
          class="icon-btn sm move-up"
          data-cf-move-up
          title=${moveUpLabel}
          aria-label=${moveUpLabel}
          ?disabled=${this.pending || index === 0}
          @click=${() => this.moveField(index, -1)}
        >${uiIcon('chevronDown')}</button>
        <button
          type="button"
          class="icon-btn sm"
          data-cf-move-down
          title=${moveDownLabel}
          aria-label=${moveDownLabel}
          ?disabled=${this.pending || index === this.form.fields.length - 1}
          @click=${() => this.moveField(index, 1)}
        >${uiIcon('chevronDown')}</button>
      </span>
      <button
        type="button"
        class="icon-btn sm"
        data-cf-remove
        title=${t('common.remove')}
        aria-label=${t('common.remove')}
        ?disabled=${this.pending}
        @click=${() => this.removeField(index)}
      >${uiIcon('trash')}</button>
    `;
  }

  private renderCustomField(field: DecryptedField, index: number) {
    const existing = this.existingFields.has(field);
    const preservesEmptyName = this.preservesLegacyEmptyName(field);
    const typeLockedTitle = existing ? t('editor.customFieldTypeLocked') : '';
    const emptyNameNotice = preservesEmptyName
      ? html`<span class="cf-warning" data-cf-empty-name>${t('editor.customFieldLegacyEmptyName')}</span>`
      : nothing;
    const supportedLinked = field.type === 3 && isSupportedLinkedFieldId(this.context.type, field.linkedId);
    if (field.type === 3 && !supportedLinked) {
      return html`
        <div class="cf" data-cf data-cf-type="3">
          <div class="cf-head">
            <input class="input cf-name" data-cf-name
              placeholder=${preservesEmptyName ? t('editor.customFieldLegacyEmptyNamePlaceholder') : t('editor.name')}
              .value=${field.name} ?disabled=${this.pending}
              @input=${(event: Event) => this.updateField(index, { name: (event.target as HTMLInputElement).value })} />
            ${this.renderCustomFieldActions(field, index)}
          </div>
          ${emptyNameNotice}
          <span class="cf-linked">${t('detail.linkedField')}</span>
        </div>
      `;
    }
    if (supportedLinked) {
      return html`
        <div class="cf" data-cf data-cf-type="3">
          <div class="cf-head">
            <select class="cf-sel" data-cf-type-sel aria-label=${t('editor.customFieldType')}
              title=${typeLockedTitle} ?disabled=${this.pending || existing} ?data-cf-type-locked=${existing}
              @change=${(e: Event) => this.changeFieldType(index, Number((e.target as HTMLSelectElement).value) as CustomFieldType)}>
              ${this.customFieldTypes().map(([cfType, cfLabel]) => html`<option value=${cfType} ?selected=${cfType === field.type}>${cfLabel}</option>`)}
            </select>
            <input class="input cf-name" data-cf-name
              placeholder=${preservesEmptyName ? t('editor.customFieldLegacyEmptyNamePlaceholder') : t('editor.name')}
              .value=${field.name} ?disabled=${this.pending}
              @input=${(e: Event) => this.updateField(index, { name: (e.target as HTMLInputElement).value })} />
            ${this.renderCustomFieldActions(field, index)}
          </div>
          ${emptyNameNotice}
          <select class="cf-sel wide" data-cf-linked aria-label=${t('editor.linkedTarget')} .value=${String(field.linkedId)} ?disabled=${this.pending}
            @change=${(e: Event) => this.changeLinkedField(index, (e.target as HTMLSelectElement).value)}>
            ${this.linkedFieldOptions().map((option) => html`<option value=${option.id}>${linkedFieldSourceLabel(option.source)}</option>`)}
          </select>
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
          <select class="cf-sel" data-cf-type-sel aria-label=${t('editor.customFieldType')}
            title=${typeLockedTitle} ?disabled=${this.pending || existing} ?data-cf-type-locked=${existing}
            @change=${(e: Event) => this.changeFieldType(index, Number((e.target as HTMLSelectElement).value) as CustomFieldType)}>
            ${this.customFieldTypes().map(([cfType, cfLabel]) => html`<option value=${cfType} ?selected=${cfType === field.type}>${cfLabel}</option>`)}
          </select>
          <input class="input cf-name" data-cf-name
            placeholder=${preservesEmptyName ? t('editor.customFieldLegacyEmptyNamePlaceholder') : t('editor.name')}
            .value=${field.name} ?disabled=${this.pending}
            @input=${(e: Event) => this.updateField(index, { name: (e.target as HTMLInputElement).value })} />
          ${this.renderCustomFieldActions(field, index)}
        </div>
        ${emptyNameNotice}
        ${valueControl}
      </div>
    `;
  }

  private renderCreateTarget() {
    if (this.context.mode === 'edit') return nothing;
    const organizations = this.eligibleCreateOrganizations();
    const optionCount = organizations.length + (this.context.personalCreationAllowed ? 1 : 0);
    const selectedOrganizationId = this.createVault?.kind === 'organization'
      ? this.createVault.organizationId
      : undefined;
    const collections = selectedOrganizationId
      ? this.writableCreateCollections(selectedOrganizationId)
      : [];
    return html`
      <fieldset class="field create-target" data-create-target ?disabled=${this.pending}>
        <legend class="label">${t('editor.vault')}</legend>
        <div class="checks">
          ${this.context.personalCreationAllowed
            ? html`
              <label class="check-row">
                <input
                  type="radio"
                  name="cipher-create-vault"
                  data-create-vault="personal"
                  .checked=${this.createVault?.kind === 'personal'}
                  @change=${(event: Event) => {
                    if ((event.target as HTMLInputElement).checked) this.selectCreateVault({ kind: 'personal' });
                  }}
                />
                <span>${t('editor.personalVault')}</span>
              </label>
            `
            : nothing}
          ${organizations.map((organization) => html`
            <label class="check-row">
              <input
                type="radio"
                name="cipher-create-vault"
                data-create-vault="organization"
                data-create-org=${organization.id}
                .checked=${selectedOrganizationId === organization.id}
                @change=${(event: Event) => {
                  if ((event.target as HTMLInputElement).checked) {
                    this.selectCreateVault({ kind: 'organization', organizationId: organization.id });
                  }
                }}
              />
              <span>${t('editor.organizationVault', { name: organization.name })}</span>
            </label>
          `)}
          ${optionCount === 0
            ? html`<p class="hint" data-no-create-target role="status">${t('editor.noCreateTargets')}</p>`
            : nothing}
        </div>
      </fieldset>
      ${selectedOrganizationId
        ? html`
          <fieldset class="field create-target" data-create-collections ?disabled=${this.pending}>
            <legend class="label">${t('editor.collections')}</legend>
            <p class="hint">${t('editor.chooseCollection')}</p>
            <div class="checks">
              ${collections.map((collection) => html`
                <label class="check-row">
                  <input
                    type="checkbox"
                    data-create-collection=${collection.id}
                    .checked=${this.createCollectionSel.has(collection.id)}
                    @change=${(event: Event) => this.toggleCreateCollection(
                      collection.id,
                      (event.target as HTMLInputElement).checked,
                    )}
                  />
                  <span>${collection.name}</span>
                </label>
              `)}
              ${collections.length === 0
                ? html`<p class="hint" data-no-writable-collections role="status">${t('editor.noWritableCollections')}</p>`
                : nothing}
            </div>
          </fieldset>
        `
        : nothing}
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
            (c) => html`<label class="check-row"><input type="checkbox" data-collection value=${c.id} .checked=${this.collectionSel.has(c.id)} ?disabled=${this.pending || !this.canChangeCollectionMembership(c)}
              @change=${(e: Event) => this.toggleCollection(c.id, (e.target as HTMLInputElement).checked)} /><span>${c.name}</span></label>`,
          )}
        </div>
        <button type="button" class="btn outline wide" data-save-collections ?disabled=${this.pending || !orgCollections.some((collection) => this.canChangeCollectionMembership(collection))} @click=${() => this.saveCollections()}>${uiIcon('check')}<span>${'更新集合' /* TODO i18n */}</span></button>
      </div>
    `;
  }

  private canMove(): boolean {
    return this.context.mode === 'edit'
      && !!this.context.cipherId
      && !!this.summary
      && !this.summary.archivedDate
      && !this.summary.deletedDate
      && !this.summary.organizationId
      && this.context.type === this.summary.type;
  }

  private renderMove() {
    if (!this.canMove()) return nothing;
    const organizations = this.eligibleMoveOrganizations();
    const selectedOrganizationId = this.moveOrganizationId;
    const collections = selectedOrganizationId
      ? this.writableCreateCollections(selectedOrganizationId)
      : [];
    const moveLabel = t('editor.moveToOrganization');
    return html`
      <div class="field org" data-move>
        <span class="label">${moveLabel}</span>
        <p class="hint">${t('editor.moveHint')}</p>
        ${organizations.length === 0
          ? html`<p class="hint" data-no-move-targets role="status">${t('editor.noMoveTargets')}</p>`
          : html`
              <fieldset class="create-target" data-move-organizations ?disabled=${this.pending}>
                <legend class="label">${t('editor.chooseMoveOrganization')}</legend>
                <div class="checks">
                  ${organizations.map((organization) => html`
                    <label class="check-row">
                      <input
                        type="radio"
                        name="cipher-move-organization"
                        data-move-org=${organization.id}
                        .checked=${live(selectedOrganizationId === organization.id)}
                        @change=${(event: Event) => {
                          if ((event.target as HTMLInputElement).checked) {
                            this.selectMoveOrganization(organization.id);
                          }
                        }}
                      />
                      <span>${organization.name}</span>
                    </label>
                  `)}
                </div>
              </fieldset>
              ${selectedOrganizationId
                ? html`
                    <fieldset class="create-target" data-move-collections ?disabled=${this.pending}>
                      <legend class="label">${t('editor.chooseMoveCollection')}</legend>
                      <div class="checks">
                        ${collections.map((collection) => html`
                          <label class="check-row">
                            <input
                              type="checkbox"
                              data-move-col=${collection.id}
                              value=${collection.id}
                              .checked=${live(this.moveCollectionSel.has(collection.id))}
                              @change=${(event: Event) => this.toggleMoveCollection(
                                collection.id,
                                (event.target as HTMLInputElement).checked,
                              )}
                            />
                            <span>${collection.name}</span>
                          </label>
                        `)}
                      </div>
                    </fieldset>
                  `
                : nothing}
              <button type="button" class="btn outline wide" data-move-confirm ?disabled=${this.pending} @click=${() => this.moveToOrg()}>${uiIcon('folder')}<span>${moveLabel}</span></button>
            `}
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

  private renderGeneratorOverlay() {
    if (!this.generatorTarget) return nothing;
    return html`
      <div class="generator-overlay" data-generator-overlay>
        <vw-generator-view
          .history=${this.generatorHistory}
          .generatorPolicy=${this.generatorPolicy}
          .accountEmail=${this.generatorAccountEmail}
          .selectionTarget=${this.generatorTarget}
          .websiteUri=${this.generatorWebsiteUri()}
          @vw-generator-select=${(event: CustomEvent<GeneratorSelectionDetail>) => this.applyGeneratedValue(event)}
          @vw-item-back=${(event: Event) => this.closeGenerator(event)}
        ></vw-generator-view>
      </div>
    `;
  }

  protected override render() {
    const title = this.context.mode === 'clone'
      ? t('editor.cloneTitle')
      : this.context.mode === 'create' ? t('editor.newTitle') : t('editor.editTitle');
    return html`
      <div class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1 class="title">${title}</h1>
        <button type="button" class="save" data-save ?disabled=${this.pending} @click=${() => this.save()}>${uiIcon('check')}<span>${t('common.save')}</span></button>
      </div>
      <div class="scroll" data-scroll>
        ${this.textField(t('editor.name'), this.form.name, (v) => this.patch({ name: v }), { field: 'name' })}
        ${this.renderCreateTarget()}
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
      ${this.renderGeneratorOverlay()}
    `;
  }
}

function emptyForm(): FormState {
  return {
    name: '', notes: '', favorite: false, reprompt: false, folderId: '',
    username: '', password: '', totp: '', uris: [{ uri: '' }], autofillOnPageLoad: null,
    card: {}, identity: {}, fields: [], showPassword: false,
  };
}

function cloneForm(form: FormState): FormState {
  return {
    ...form,
    uris: form.uris.map((uri) => ({ ...uri })),
    card: { ...form.card },
    identity: { ...form.identity },
    fields: form.fields.map((field) => ({ ...field })),
  };
}

function formFingerprint(form: FormState): string {
  return JSON.stringify({
    name: form.name,
    notes: form.notes,
    favorite: form.favorite,
    reprompt: form.reprompt,
    folderId: form.folderId,
    username: form.username,
    password: form.password,
    totp: form.totp,
    uris: form.uris,
    autofillOnPageLoad: form.autofillOnPageLoad,
    card: form.card,
    identity: form.identity,
    fields: form.fields,
  });
}

customElements.define('vw-cipher-editor', VwCipherEditor);

declare global {
  interface HTMLElementTagNameMap {
    'vw-cipher-editor': VwCipherEditor;
  }
}
