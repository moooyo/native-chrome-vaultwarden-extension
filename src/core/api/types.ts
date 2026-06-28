export type KdfType = 0 | 1; // 0 PBKDF2, 1 Argon2id (read-only unsupported in M1-M3)

export interface PreloginResponse {
  kdf: KdfType;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
}

export interface LoginSuccessResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  token_type: string;
  Key: string;
  PrivateKey?: string;
  Kdf?: KdfType;
  KdfIterations?: number;
  TwoFactorToken?: string;
}

export interface TwoFactorRequiredResponse {
  error: 'invalid_grant';
  error_description: string;
  /** Real Vaultwarden returns an array of provider-id strings, e.g. ["0","1"].
   *  The object-map form (TwoFactorProviders2) may also be present; both shapes are handled. */
  TwoFactorProviders: string[] | Record<string, unknown>;
  TwoFactorProviders2?: Record<string, unknown>;
  TwoFactorToken?: string;
}

export interface RefreshTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  token_type: string;
}

/** Client-side account registration payload (RegisterData). All key material is derived locally. */
export interface RegisterRequest {
  email: string;
  name?: string;
  masterPasswordHash: string;
  masterPasswordHint?: string;
  key: string;
  keys: { publicKey: string; encryptedPrivateKey: string };
  kdf: number;
  kdfIterations: number;
}

export interface OrganizationResponse {
  id: string;
  /** RSA-OAEP wrapped organization symmetric key (encType=4), unwrapped with the account private key. */
  key: string;
  name?: string | null;
}

export interface SyncProfile {
  id: string;
  email: string;
  name?: string | null;
  organizations?: OrganizationResponse[] | null;
}

export interface LoginUriResponse {
  uri?: string | null;
  match?: number | null;
}

export interface LoginCipherData {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  uris?: LoginUriResponse[] | null;
  fido2Credentials?: Fido2CredentialData[] | null;
  /** Server-tracked timestamp of the last password change. Opaque to us; preserved across edits. */
  passwordRevisionDate?: string | null;
}

/** A stored passkey (FIDO2 credential). All values are EncStrings; keyValue is PKCS#8 base64url. */
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

export interface CipherResponse {
  id: string;
  type: 1 | 2 | 3 | 4 | 5;
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
  /** Custom fields — not modeled by the editor; preserved verbatim across edits. */
  fields?: CipherFieldData[] | null;
  /** Server-retained password history — not modeled by the editor; preserved verbatim across edits. */
  passwordHistory?: CipherPasswordHistoryData[] | null;
  /** Master-password reprompt flag (0/1) — not modeled by the editor; preserved across edits. */
  reprompt?: number | null;
  /** Soft-delete timestamp; when set, the cipher lives in the trash. */
  deletedDate?: string | null;
  revisionDate?: string | null;
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
  secureNote?: { type: number } | null;
  /** Per-cipher key, when the cipher has its own wrapped key. Preserved from the original on update. */
  key?: string | null;
  /** Custom fields preserved verbatim from the original cipher on update (the editor doesn't manage them). */
  fields?: CipherFieldData[] | null;
  /** Password history preserved verbatim from the original cipher on update. */
  passwordHistory?: CipherPasswordHistoryData[] | null;
  /** Master-password reprompt flag preserved from the original cipher on update. */
  reprompt?: number | null;
}

/** A collection groups organization ciphers. `name` is an EncString encrypted with the org key. */
export interface CollectionResponse {
  id: string;
  organizationId: string;
  name?: string | null;
  externalId?: string | null;
  readOnly?: boolean;
}

export interface SyncResponse {
  profile: SyncProfile;
  ciphers: CipherResponse[];
  folders?: FolderResponse[];
  collections?: CollectionResponse[];
  /** User-defined equivalent-domain groups, when present (often null on self-hosted servers). */
  domains?: {
    equivalentDomains?: string[][] | null;
    /** Official global groups with per-group `excluded` flags reflecting the user's Domain Rules. */
    globalEquivalentDomains?: GlobalEquivalentDomainsGroup[] | null;
  } | null;
}

/** One server global equivalent-domains group. `excluded` is true when the user has switched it off. */
export interface GlobalEquivalentDomainsGroup {
  type?: number;
  domains?: string[] | null;
  excluded?: boolean;
}
