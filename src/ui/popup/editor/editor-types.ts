import type {
  CipherCreateTarget,
  CipherInput,
  CollectionSummary,
  FolderSummary,
} from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { EditorCreateDefaults } from '../types.js';

/**
 * Everything `vw-cipher-editor` needs to render a create/edit form, handed down whole by the root.
 * `input` prefills an edit (the reprompt-gated plaintext the worker returned); it is absent for a
 * create. `folders`/`collections`/`orgPermissions` are the same non-secret listing data the vault
 * views already use. The editor owns all form state derived from this and never issues a request.
 */
export interface EditorContext {
  mode: 'create' | 'clone' | 'edit';
  /** Stable root-authored identity for one editor draft; changing it must reset all local form state. */
  draftKey: string;
  type: 1 | 2 | 3 | 4;
  cipherId?: string;
  input?: CipherInput;
  createDefaults?: EditorCreateDefaults;
  /** Effective policy result for personal-vault creation. Missing/false must fail closed. */
  personalCreationAllowed: boolean;
  folders: readonly FolderSummary[];
  collections: readonly CollectionSummary[];
  orgPermissions: readonly OrgPermission[];
}

/** `vw-editor-type` detail: the type chosen from the add-item picker. */
export interface EditorTypeDetail {
  type: 1 | 2 | 3 | 4 | 5;
}

/** Complete editor save payload. `target` is always present for create and undefined for edit. */
export interface EditorSaveDetail {
  input: CipherInput;
  target: CipherCreateTarget | undefined;
}

/** A root-owned, one-shot TOTP QR capture applied to the currently open login editor. */
export interface EditorTotpCapture {
  revision: number;
  value: string;
}

/**
 * `vw-cipher-collections` detail: the organization item's desired collection membership. A separate
 * operation from the cipher save (`vault.setCipherCollections`), so the root sequences it on its own.
 */
export interface CipherCollectionsDetail {
  cipherId: string;
  collectionIds: string[];
}

/**
 * `vw-editor-share` detail: move a personal item into an organization (Bitwarden "share"), a distinct
 * operation from both saving fields and assigning collections. All chosen collections must belong to
 * the one `organizationId`.
 */
export interface EditorShareDetail {
  cipherId: string;
  organizationId: string;
  collectionIds: string[];
}
