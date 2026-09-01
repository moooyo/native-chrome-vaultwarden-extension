import type { LoginUri } from './uri-match.js';

export type KnownCipherType = 1 | 2 | 3 | 4 | 5;

export type CipherInputPurpose = 'edit' | 'clone';

export function isKnownCipherType(value: number): value is KnownCipherType {
  return value === 1 || value === 2 || value === 3 || value === 4 || value === 5;
}

export type FieldName =
  | 'username' | 'password' | 'totp' | 'notes'
  | 'card.number' | 'card.code'
  | 'identity.ssn' | 'identity.passportNumber' | 'identity.licenseNumber';

/** Non-secret, server-derived capabilities projected for organization-owned vault items. Personal
 * items omit this object because their ownership itself authorizes the corresponding operations. */
export interface CipherAccess {
  edit: boolean;
  viewPassword: boolean;
  /** UI projection only. Organization clone authorization is revalidated from raw collections. */
  clone?: boolean;
  delete: boolean;
  restore: boolean;
  autofillTotp: boolean;
  viewTotp: boolean;
}

interface CipherSummaryBase {
  id: string;
  name: string;
  username?: string;
  uris: string[];
  loginUris: LoginUri[];
  favorite: boolean;
  folderId?: string;
  /** Present for ciphers owned by an organization (decrypted with that organization's key). */
  organizationId?: string;
  /** Present only for organization items. The worker rechecks the raw response for every sensitive
   * operation; this projection exists solely to keep unavailable UI actions out of reach. */
  access?: CipherAccess;
  /** Collections (organization groupings) this cipher belongs to. */
  collectionIds?: string[];
  /** True when a login carries a TOTP secret. The secret itself never enters a summary. */
  hasTotp?: boolean;
  /** True when a login carries at least one stored passkey (FIDO2 credential). */
  hasPasskey?: boolean;
  /** Per-login automatic page-load override. null/undefined inherits the account default. */
  autofillOnPageLoad?: boolean | null;
  /** Non-sensitive list subtitle (e.g. card brand or identity full name). Never holds secrets. */
  subtitle?: string;
  /** True when the item is master-password-reprompt protected: secrets are released only after the
   *  master password is re-verified. The worker enforces this; the UI must gate access accordingly. */
  reprompt?: boolean;
  /** Number of retained previous passwords (non-secret count; the values are fetched on demand). */
  passwordHistoryCount?: number;
  /** Soft-delete timestamp; when set, the cipher is in the trash (excluded from the main list & autofill). */
  deletedDate?: string;
  /** Archive timestamp. Archived items remain in the vault but are inactive and must not be offered
   *  by credential, passkey, TOTP, or structured-fill surfaces. */
  archivedDate?: string;
}

/** A single lifecycle predicate shared by raw ciphers and decrypted summaries. Trash and archive
 *  have different UI semantics, but neither state is eligible for active credential workflows. */
export function isCipherInactive(cipher: {
  readonly deletedDate?: string | null;
  readonly archivedDate?: string | null;
}): boolean {
  return cipher.deletedDate != null || cipher.archivedDate != null;
}

export function isActiveCipher(cipher: {
  readonly deletedDate?: string | null;
  readonly archivedDate?: string | null;
}): boolean {
  return !isCipherInactive(cipher);
}

export interface KnownCipherSummary extends CipherSummaryBase {
  type: KnownCipherType;
  unsupported?: false;
  undecryptable?: boolean;
}

export interface UnsupportedCipherSummary extends CipherSummaryBase {
  /** Raw positive server type. Unknown values are retained without decrypting their payload. */
  type: number;
  /** The payload belongs to a newer cipher type this client cannot inspect. */
  unsupported: true;
  undecryptable: true;
}

export type CipherSummary = KnownCipherSummary | UnsupportedCipherSummary;

export interface DecryptedCard {
  cardholderName?: string;
  brand?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  code?: string;
}

export interface DecryptedIdentity {
  title?: string;
  firstName?: string;
  middleName?: string;
  lastName?: string;
  address1?: string;
  address2?: string;
  address3?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  company?: string;
  email?: string;
  phone?: string;
  ssn?: string;
  username?: string;
  passportNumber?: string;
  licenseNumber?: string;
}

/** Existing OpenSSH strings stored by Bitwarden. Core treats them as opaque text. */
export interface DecryptedSshKey {
  privateKey: string;
  publicKey?: string;
  keyFingerprint?: string;
}

/** Complete SSH key input after generation or import has derived and verified the public fields. */
export interface CompleteDecryptedSshKey extends DecryptedSshKey {
  publicKey: string;
  keyFingerprint: string;
}

/** Public SSH material that may cross the worker boundary. The private key is exposed only through
 *  the dedicated reveal command and is never a property of this DTO. */
export interface SshKeyPublicDetails {
  publicKey?: string;
  keyFingerprint?: string;
  hasPrivateKey: boolean;
}

/** Complete common metadata used by the dedicated SSH create and metadata-update commands. */
export interface SshKeyMetadataInput {
  name: string;
  notes: string;
  favorite: boolean;
  reprompt: boolean;
  folderId: string | null;
  fields: DecryptedField[];
}

/**
 * Card fields in canonical order. Single source of truth shared by encrypt.ts and decrypt.ts so the
 * two whitelists cannot drift; derived from the DecryptedCard model via `keyof`. The on-the-wire type
 * (CardCipherData) shares this exact key set, so the same list indexes both directions.
 */
export const CARD_FIELDS: ReadonlyArray<keyof DecryptedCard> = [
  'cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code',
];

/** Identity fields (all 18) in canonical order. Single source of truth for encrypt.ts / decrypt.ts;
 *  see CARD_FIELDS for the rationale. Derived from DecryptedIdentity via `keyof`. */
export const IDENTITY_FIELDS: ReadonlyArray<keyof DecryptedIdentity> = [
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
  'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn',
  'username', 'passportNumber', 'licenseNumber',
];

export interface DecryptedCipher extends KnownCipherSummary {
  password?: string;
  totp?: string;
  notes?: string;
  card?: DecryptedCard;
  identity?: DecryptedIdentity;
  sshKey?: DecryptedSshKey;
  fido2Credentials?: DecryptedFido2Credential[];
  fields?: DecryptedField[];
  attachments?: DecryptedAttachment[];
}

/** Non-secret attachment metadata for display. The encrypted blob is fetched/decrypted on demand. */
export interface DecryptedAttachment {
  id: string;
  fileName: string;
  size?: string;
  sizeName?: string;
  /** Present only for keyless legacy attachment data that should be upgraded before sharing. */
  legacy?: true;
}

/** Custom field types (Bitwarden FieldType): 0 Text, 1 Hidden, 2 Boolean, 3 Linked. */
export type CustomFieldType = 0 | 1 | 2 | 3;

/** A decrypted custom field. `value` holds plaintext for Text/Hidden and 'true'/'false' for Boolean;
 *  Linked fields carry no value, only a `linkedId` referencing a built-in field. */
export interface DecryptedField {
  type: CustomFieldType;
  name: string;
  value?: string;
  linkedId?: number;
}

/** A decrypted passkey. keyValue (PKCS#8 base64url private key) is sensitive — never send it to the UI. */
export interface DecryptedFido2Credential {
  credentialId: string;
  keyValue: string;
  rpId: string;
  counter: number;
  /** Resident/discoverable credentials may be selected when the RP omits allowCredentials. */
  discoverable: boolean;
  userHandle?: string;
  userName?: string;
  rpName?: string;
}

/** A candidate login item a new passkey can be saved into (display-only; carries no secrets). */
export interface PasskeyTarget {
  id: string;
  name: string;
  username?: string;
  /** The coordinator must obtain a fresh master-password proof before using this target. */
  requiresReprompt?: boolean;
}

/** A stored passkey matching a get() request, for the account picker (display-only; no key material).
 *  credentialId is a public WebAuthn identifier the bridge uses to sign with the chosen credential. */
export interface PasskeyCandidate {
  credentialId: string;
  name: string;
  username?: string;
  /** The credential is displayable but must never be signed without a fresh reprompt proof. */
  requiresReprompt?: boolean;
}

export interface PasskeyLookupRequest {
  readonly rpId: string;
  readonly origin: string;
  readonly allowedCredentialIds?: readonly string[];
}

export interface PasskeyAssertionRequest extends PasskeyLookupRequest {
  readonly challenge: string;
  /** Legacy, untrusted transport input. Vault-backed assertions intentionally ignore it. */
  readonly userVerified?: unknown;
  /** Set only by the browser-owned website passkey authorization adapter. */
  readonly crossOrigin?: boolean;
}

/** A login's live one-time code for the 2FA view (display-only; the TOTP secret never leaves the
 *  worker). `remaining` is whole seconds until the code rolls over at fetch time. */
export interface TotpListEntry {
  id: string;
  name: string;
  username?: string;
  code: string;
  period: number;
  remaining: number;
}

/** Plaintext cipher form input from the editor, before encryption into a write request. */
export interface CipherInput<TType extends KnownCipherType = 1 | 2 | 3 | 4> {
  type: TType;
  name: string;
  notes?: string;
  favorite?: boolean;
  /** Require master-password reprompt before this item's secrets are revealed/filled. */
  reprompt?: boolean;
  folderId?: string | null;
  login?: {
    username?: string;
    password?: string;
    totp?: string;
    uris?: LoginUri[];
    /** Per-item page-load autofill override: null uses the account default. */
    autofillOnPageLoad?: boolean | null;
    passwordRevisionDate?: string | null;
  };
  card?: DecryptedCard;
  identity?: DecryptedIdentity;
  sshKey?: CompleteDecryptedSshKey;
  /** Custom fields, round-tripped by the editor (Linked fields are preserved read-only). */
  fields?: DecryptedField[];
}

export type SshCipherInput = CipherInput<5> & { sshKey: CompleteDecryptedSshKey };
export type WritableCipherInput = CipherInput | SshCipherInput;

/** Explicit destination for a new cipher. Organization targets are validated again in the worker. */
export type CipherCreateTarget =
  | { readonly kind: 'personal' }
  | {
      readonly kind: 'organization';
      readonly organizationId: string;
      readonly collectionIds: readonly string[];
    };

export interface FolderSummary {
  id: string;
  name: string;
}

export interface CollectionSummary {
  id: string;
  name: string;
  organizationId: string;
  readOnly?: boolean;
  manage?: boolean;
  hidePasswords?: boolean;
  assigned?: boolean;
  type?: number;
  /** Plain display name for an offboarded user's former default collection. Its presence forbids rename. */
  defaultUserCollectionEmail?: string;
  /** Current-snapshot capabilities projected by the worker for display-only action gating. */
  canRename?: boolean;
  canDelete?: boolean;
  canAssignItems?: boolean;
}
