import type { KdfConfig } from '../crypto/kdf.js';
import type { MasterPasswordPolicy } from '../policy/master-password-policy.js';

export type KdfType = KdfConfig['kdf'];

export type PreloginResponse = KdfConfig;

export interface LoginSuccessResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  token_type: string;
  Key: string;
  PrivateKey?: string;
  Kdf?: KdfType;
  KdfIterations?: number;
  KdfMemory?: number;
  KdfParallelism?: number;
  /** SSO-only master-key salt projected from UserDecryptionOptions.MasterPasswordUnlock. */
  MasterKeySalt?: string;
  TwoFactorToken?: string;
  /** Present only when Identity explicitly requires the recovered account password to be changed. */
  forcePasswordReset?: true;
  masterPasswordPolicy?: MasterPasswordPolicy;
}

export interface TwoFactorRequiredResponse {
  error: 'invalid_grant';
  error_description: string;
  /** Real Vaultwarden returns an array of provider-id strings, e.g. ["0","1"].
   *  The object-map form (TwoFactorProviders2) may also be present; both shapes are handled. */
  TwoFactorProviders?: string[] | Record<string, unknown>;
  TwoFactorProviders2?: Record<string, unknown>;
  TwoFactorToken?: string;
  MasterPasswordPolicy?: unknown;
  masterPasswordPolicy?: unknown;
}

export interface RefreshTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  token_type: string;
}

/** Client-side account registration payload (RegisterData). All key material is derived locally. */
export type RegisterRequest = {
  email: string;
  name?: string;
  emailVerificationToken?: string;
  masterPasswordHash: string;
  masterPasswordHint: string;
  key: string;
  keys: { publicKey: string; encryptedPrivateKey: string };
} & KdfConfig;

export interface ApiKdfSettings {
  kdfType: KdfType;
  iterations: number;
  memory: number | null;
  parallelism: number | null;
}

export type ChangeKdfRequest = {
  masterPasswordHash: string;
  newMasterPasswordHash: string;
  key: string;
  kdf: KdfType;
  kdfIterations: number;
  kdfMemory: number | null;
  kdfParallelism: number | null;
  authenticationData: {
    salt: string;
    kdf: ApiKdfSettings;
    masterPasswordAuthenticationHash: string;
  };
  unlockData: {
    salt: string;
    kdf: ApiKdfSettings;
    masterKeyWrappedUserKey: string;
  };
};

export interface OrganizationResponse {
  /** Preserve server fields that this client does not interpret in the encrypted raw cache. */
  readonly [field: string]: unknown;
  id: string;
  /** RSA-OAEP wrapped organization symmetric key (encType=4), unwrapped with the account private key. */
  key?: string | null;
  name?: string | null;
  /** Org user type: 0 Owner, 1 Admin, 2 User, 3 Manager, 4 Custom.
   *  Vaultwarden remaps Manager→Custom(4) before serialization, so type 3 does not appear on Vaultwarden. */
  type?: number | null;
  /** Membership status: -1 Revoked, 0 Invited, 1 Accepted, 2 Confirmed, 3 Staged. */
  status?: number | null;
  /** Whether the organization and its policy entitlement are active for this membership. */
  enabled?: boolean | null;
  usePolicies?: boolean | null;
  usePasswordManager?: boolean | null;
  useMyItems?: boolean | null;
  /** Whether this direct membership collects client audit events. */
  useEvents?: boolean | null;
  /** Fine-grained permissions (Custom type). Owner/Admin have these all false yet can still manage. */
  permissions?: {
    readonly [permission: string]: unknown;
    createNewCollections?: boolean | null;
    editAnyCollection?: boolean | null;
    deleteAnyCollection?: boolean | null;
    manageCiphers?: boolean | null;
  } | null;
  userId?: string | null;
  organizationUserId?: string | null;
  resetPasswordEnrolled?: boolean | null;
  providerId?: string | null;
  providerName?: string | null;
  providerType?: number | null;
  limitCollectionCreation?: boolean | null;
  limitCollectionDeletion?: boolean | null;
  limitItemDeletion?: boolean | null;
  allowAdminAccessToAllCollectionItems?: boolean | null;
}

/** Provider-visible organizations use the same wire shape as direct memberships. */
export type ProviderOrganizationResponse = OrganizationResponse;

/** Provider metadata is not interpreted yet, but remains available to future policy features. */
export interface ProviderResponse {
  readonly [field: string]: unknown;
  id: string;
  name?: string | null;
  type?: number | null;
  key?: string | null;
  status?: number | null;
  enabled?: boolean | null;
  permissions?: {
    readonly [permission: string]: unknown;
    manageCiphers?: boolean | null;
  } | null;
  userId?: string | null;
}

/** Raw organization policy. Unknown policy types and data fields are intentionally retained. */
export interface PolicyResponse {
  readonly [field: string]: unknown;
  id: string;
  organizationId: string;
  type: number;
  data?: unknown;
  enabled: boolean;
  canToggleState?: boolean | null;
  revisionDate?: string | null;
}

export interface SyncProfile {
  /** Preserve server fields that this client does not interpret in the encrypted raw cache. */
  readonly [field: string]: unknown;
  id: string;
  email: string;
  /** Opaque server session-revocation generation. Never log or otherwise expose this value. */
  securityStamp?: string | null;
  name?: string | null;
  /** Personal premium entitlement in the raw sync profile (`Premium` server field). */
  premium?: boolean | null;
  premiumFromOrganization?: boolean | null;
  organizations?: OrganizationResponse[] | null;
  /** Accepted and confirmed memberships. When present, this supersedes `organizations`. */
  organizationsNew?: OrganizationResponse[] | null;
  providers?: ProviderResponse[] | null;
  /** Organizations managed through a Provider, including provider-only access. */
  providerOrganizations?: ProviderOrganizationResponse[] | null;
}

export interface LoginUriResponse {
  uri?: string | null;
  /** Encrypted standard-Base64 SHA-256 of the clear URI. */
  uriChecksum?: string | null;
  match?: number | null;
}

export interface LoginCipherData {
  /** Obsolete response alias for the first `uris` entry; never authoritative. */
  uri?: string | null;
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  uris?: LoginUriResponse[] | null;
  fido2Credentials?: Fido2CredentialData[] | null;
  /** Per-item page-load autofill override: null uses the account default. */
  autofillOnPageLoad?: boolean | null;
  /** Server-tracked timestamp of the last password change. Opaque to us; preserved across edits. */
  passwordRevisionDate?: string | null;
}

/** A stored passkey. String fields are EncStrings; creationDate is a clear ISO timestamp. */
export interface Fido2CredentialData {
  credentialId?: string | null;
  keyType?: string | null;
  keyAlgorithm?: string | null;
  keyCurve?: string | null;
  keyValue?: string | null;
  rpId?: string | null;
  userHandle?: string | null;
  userName?: string | null;
  counter?: string | null;
  rpName?: string | null;
  userDisplayName?: string | null;
  discoverable?: string | null;
  creationDate?: string | null;
}

/** Complete FIDO2 payload required when creating a cipher containing an imported passkey. */
export interface Fido2CredentialRequestData extends Fido2CredentialData {
  credentialId: string;
  keyType: string;
  keyAlgorithm: string;
  keyCurve: string;
  keyValue: string;
  rpId: string;
  counter: string;
  discoverable: string;
  creationDate: string;
}

/** All Card fields are EncStrings (encType=2), including brand/expMonth/expYear. */
export interface CardCipherData {
  cardholderName?: string | null;
  brand?: string | null;
  number?: string | null;
  expMonth?: string | null;
  expYear?: string | null;
  code?: string | null;
}

/** All 18 Identity fields are EncStrings (encType=2). */
export interface IdentityCipherData {
  title?: string | null;
  firstName?: string | null;
  middleName?: string | null;
  lastName?: string | null;
  address1?: string | null;
  address2?: string | null;
  address3?: string | null;
  city?: string | null;
  state?: string | null;
  postalCode?: string | null;
  country?: string | null;
  company?: string | null;
  email?: string | null;
  phone?: string | null;
  ssn?: string | null;
  username?: string | null;
  passportNumber?: string | null;
  licenseNumber?: string | null;
}

/** SSH key payload. All three values are encrypted independently as EncStrings. */
export interface SshKeyCipherData {
  privateKey: string;
  publicKey?: string | null;
  keyFingerprint?: string | null;
}

/** Complete SSH key payload required on create/update because this client does not derive fields. */
export interface SshKeyCipherRequestData {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
}

/** A custom field on a cipher. `name`/`value` are EncStrings (type 0/1/2/3). Opaque to us. */
export interface CipherFieldData {
  type?: number | null;
  name?: string | null;
  value?: string | null;
  linkedId?: number | null;
}

/** A prior password retained server-side. `password` is an EncString. Opaque to us. */
export interface CipherPasswordHistoryData {
  password?: string | null;
  lastUsedDate?: string | null;
}

/** A file attachment on a cipher. `fileName` and `key` are EncStrings; `key` wraps the per-attachment
 *  symmetric key (under the cipher key). `url` points to the encrypted blob. */
export interface AttachmentData {
  id: string;
  url?: string | null;
  fileName?: string | null;
  key?: string | null;
  size?: string | null;
  sizeName?: string | null;
}

/** Metadata used to allocate a two-phase attachment upload slot. */
export interface AttachmentUploadRequest {
  key: string;
  fileName: string;
  fileSize: number;
  adminRequest: false;
  lastKnownRevisionDate?: string | null;
}

/** Internal receipt for a slot allocated by POST /ciphers/{id}/attachment/v2. */
export type AttachmentUploadSlotReceipt =
  | {
      readonly attachmentId: string;
      readonly fileUploadType: 0;
      readonly cipherResponse: CipherResponse;
    }
  | {
      readonly attachmentId: string;
      readonly fileUploadType: 1;
      readonly url: string;
      readonly cipherResponse: CipherResponse;
    };

export interface CipherResponse {
  /** Preserve unrecognized encrypted type-specific fields exactly as received from the server. */
  readonly [field: string]: unknown;
  id: string;
  /** Positive integer on the wire. Consumers must classify it before decrypting type-specific data. */
  type: number;
  /** Canonical server-side CipherData JSON, redundant with the deprecated structured projection. */
  data?: string | null;
  /** Server-derived authorization metadata; validated and never exported as vault content. */
  permissions?: { delete?: boolean | null; restore?: boolean | null };
  /** Server-derived authorization for modifying an organization-owned cipher. */
  edit?: boolean;
  /** Server-derived authorization for directly revealing password-like values. */
  viewPassword?: boolean;
  /** Whether this account may generate TOTP codes for an organization-owned cipher. */
  organizationUseTotp?: boolean;
  attachments?: AttachmentData[] | null;
  name?: string | null;
  notes?: string | null;
  favorite?: boolean;
  organizationId?: string | null;
  folderId?: string | null;
  /** Collections this cipher belongs to (organization ciphers). Not encrypted. */
  collectionIds?: string[] | null;
  key?: string | null;
  login?: LoginCipherData | null;
  card?: CardCipherData | null;
  identity?: IdentityCipherData | null;
  sshKey?: SshKeyCipherData | null;
  /** Custom fields — not modeled by the editor; preserved verbatim across edits. */
  fields?: CipherFieldData[] | null;
  /** Server-retained password history — not modeled by the editor; preserved verbatim across edits. */
  passwordHistory?: CipherPasswordHistoryData[] | null;
  /** Master-password reprompt flag (0/1) — not modeled by the editor; preserved across edits. */
  reprompt?: number | null;
  /** Soft-delete timestamp; when set, the cipher lives in the trash. */
  deletedDate?: string | null;
  creationDate?: string | null;
  revisionDate?: string | null;
  archivedDate?: string | null;
}

export interface FolderResponse {
  id: string;
  name?: string | null;
}

/** Create/update cipher request body (camelCase). All field values are EncStrings. */
export interface CipherRequest {
  type: 1 | 2 | 3 | 4 | 5;
  name: string;
  notes?: string | null;
  favorite?: boolean;
  folderId?: string | null;
  organizationId?: string | null;
  login?: LoginCipherData | null;
  card?: CardCipherData | null;
  identity?: IdentityCipherData | null;
  sshKey?: SshKeyCipherRequestData | null;
  secureNote?: { type: number } | null;
  /** Per-cipher key, when the cipher has its own wrapped key. Preserved from the original on update. */
  key?: string | null;
  /** Custom fields preserved verbatim from the original cipher on update (the editor doesn't manage them). */
  fields?: CipherFieldData[] | null;
  /** Password history preserved verbatim from the original cipher on update. */
  passwordHistory?: CipherPasswordHistoryData[] | null;
  /** Existing attachment key/name metadata rewrapped during a legacy keyless cipher migration. */
  attachments2?: Record<string, { key: string; fileName: string }> | null;
  /** Master-password reprompt flag preserved from the original cipher on update. */
  reprompt?: number | null;
  /** Per-user archive timestamp. Supported on create/update; unlike creation/revision dates this is portable. */
  archivedDate?: string | null;
  /** Optimistic-concurrency token copied from the source cipher on every wholesale update. */
  lastKnownRevisionDate?: string | null;
}

/** Per-user cipher metadata update. The partial endpoint must never receive encrypted item data. */
export interface CipherPartialRequest {
  readonly folderId: string | null;
  readonly favorite: boolean;
}

/** Atomic create request for a cipher already encrypted for an organization. */
export interface OrganizationCipherCreateRequest {
  cipher: CipherRequest;
  collectionIds: string[];
}

/** Official bulk-share item: a complete encrypted cipher plus its current personal-vault id. */
export interface CipherWithIdRequest extends CipherRequest {
  readonly id: string;
  readonly organizationId: string;
  readonly encryptedFor: string;
}

/** PUT /api/ciphers/share body used by the organization-data-ownership migration. */
export interface CipherBulkShareRequest {
  readonly ciphers: readonly CipherWithIdRequest[];
  readonly collectionIds: readonly string[];
  /** Official clients repeat the acting user id at the envelope and per-cipher levels. */
  readonly encryptedFor: string;
}

export interface CipherBulkIdsRequest {
  ids: string[];
}

export interface CipherListResponse {
  readonly [field: string]: unknown;
  data: CipherResponse[];
  object?: string | null;
  continuationToken?: string | null;
}

/** Send text payload. `text` is an EncString under the (HKDF-derived) send key; `hidden` masks it. */
export interface SendTextData {
  text?: string | null;
  hidden?: boolean;
}

/** Send file metadata. `fileName` is an EncString under the send key. */
export interface SendFileData {
  id?: string | null;
  fileName?: string | null;
  size?: string | null;
  sizeName?: string | null;
}

/** A Send as returned by the server. `key` wraps the 16-byte send key under the account user key;
 *  `name`/text/file fields are EncStrings under the HKDF-derived send key. */
export interface SendResponse {
  id: string;
  accessId: string;
  type: number; // 0 text, 1 file
  name?: string | null;
  notes?: string | null;
  key: string;
  text?: SendTextData | null;
  file?: SendFileData | null;
  maxAccessCount?: number | null;
  accessCount?: number;
  expirationDate?: string | null;
  deletionDate: string;
  disabled?: boolean;
  password?: string | null;
  hideEmail?: boolean | null;
  /** Modern Send authentication mode: 0 Email, 1 Password, 2 None. */
  authType?: number | null;
  /** Comma-separated email-auth recipients. Edits are refused until this client can round-trip them. */
  emails?: string | null;
  revisionDate?: string | null;
}

/** Create/update Send request body (camelCase). All text fields are EncStrings. */
export interface SendRequest {
  type: number;
  name: string;
  notes?: string | null;
  key: string;
  text?: SendTextData | null;
  file?: SendFileData | null;
  fileLength?: number | null;
  maxAccessCount?: number | null;
  expirationDate?: string | null;
  deletionDate: string;
  password?: string | null;
  disabled?: boolean;
  hideEmail?: boolean | null;
  /** Preserve the server's modern Send authentication mode on whole-object updates. */
  authType?: number | null;
  /** Preserve email-auth recipients verbatim. Editing email-auth Sends remains unsupported. */
  emails?: string | null;
}

/** Response of POST /api/sends/file/v2: where to upload the encrypted blob, plus the created Send. */
export interface SendFileUploadResponse {
  url: string;
  fileUploadType?: number;
  sendResponse: SendResponse;
}

/** A collection groups organization ciphers. `name` is an EncString encrypted with the org key. */
export interface CollectionResponse {
  id: string;
  organizationId: string;
  name?: string | null;
  externalId?: string | null;
  readOnly?: boolean;
  manage?: boolean;
  hidePasswords?: boolean;
  /** True when the current direct member was explicitly assigned this collection. */
  assigned?: boolean;
  /** 0 SharedCollection, 1 DefaultUserCollection; future values remain round-trippable. */
  type?: number | null;
  defaultUserCollectionEmail?: string | null;
}

/** A collection's group/user access assignments — opaque to us, preserved verbatim across a rename. */
export interface CollectionAccess {
  groups: unknown[];
  users: unknown[];
}

/** Complete state that a collection update must round-trip. */
export interface CollectionUpdateAccess extends CollectionAccess {
  externalId: string | null;
}

/** `GET .../collections/{id}/details` payload (object: collectionAccessDetails). */
export interface CollectionAccessDetails extends CollectionUpdateAccess {
  id: string;
  organizationId: string;
  name?: string | null;
}

export interface SyncResponse {
  /** Preserve future top-level sync fields in the encrypted raw cache. */
  readonly [field: string]: unknown;
  profile: SyncProfile;
  ciphers: CipherResponse[];
  folders?: FolderResponse[];
  collections?: CollectionResponse[];
  /** Legacy confirmed-membership policy collection. */
  policies?: PolicyResponse[] | null;
  /** Accepted-and-confirmed policy collection. A non-empty value supersedes `policies`. */
  policiesNew?: PolicyResponse[] | null;
  /** User-defined equivalent-domain groups, when present (often null on self-hosted servers). */
  domains?: {
    equivalentDomains?: string[][] | null;
    /** Official global groups with per-group `excluded` flags reflecting the user's Domain Rules. */
    globalEquivalentDomains?: GlobalEquivalentDomainsGroup[] | null;
  } | null;
  /** Opaque account key-unlock control plane. Vault export validates its bounds and discards it. */
  userDecryption?: unknown;
}

/** One server global equivalent-domains group. `excluded` is true when the user has switched it off. */
export interface GlobalEquivalentDomainsGroup {
  type?: number;
  domains?: string[] | null;
  excluded?: boolean;
}

export interface RotateMasterPasswordUnlockData {
  kdfType: KdfType;
  kdfIterations: number;
  kdfParallelism: number | null;
  kdfMemory: number | null;
  email: string;
  masterKeyAuthenticationHash: string;
  masterKeyEncryptedUserKey: string;
}

export interface RotateOrgRecoveryData {
  organizationId: string;
  resetPasswordKey: string;
}

export type KeyRotationUnlockRecordState = 'empty' | 'present';

/**
 * Authoritative server-side inventory used before account-key rotation. This client does not yet
 * re-wrap passkey or trusted-device key sets, so only an explicit `empty` result is admissible.
 * Transport or schema uncertainty is represented by rejection, never by an optimistic default.
 */
export interface KeyRotationUnlockRecordsStatus {
  readonly passkeyUnlockData: KeyRotationUnlockRecordState;
  readonly deviceKeyUnlockData: KeyRotationUnlockRecordState;
}

export interface RotateKeyData {
  oldMasterKeyAuthenticationHash: string;
  accountUnlockData: {
    masterPasswordUnlockData: RotateMasterPasswordUnlockData;
    emergencyAccessUnlockData: unknown[];
    organizationAccountRecoveryUnlockData: RotateOrgRecoveryData[];
    /** Empty until this client can re-wrap every server-side WebAuthn PRF key set. */
    passkeyUnlockData: readonly [];
    /** Empty until this client can re-wrap every trusted-device key set. */
    deviceKeyUnlockData: readonly [];
  };
  accountKeys: {
    userKeyEncryptedAccountPrivateKey: string;
    accountPublicKey: string;
  };
  accountData: {
    ciphers: unknown[];
    folders: unknown[];
    sends: unknown[];
  };
}

export interface OrgPublicKeyResponse {
  publicKey: string;
}

export interface UserPublicKeyResponse {
  publicKey: string;
}

export interface EmergencyAccessGrant {
  id: string;
}
