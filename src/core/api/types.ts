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
}
