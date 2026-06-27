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

export interface SyncProfile {
  id: string;
  email: string;
  name?: string | null;
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

export interface CipherResponse {
  id: string;
  type: 1 | 2 | 3 | 4 | 5;
  name?: string | null;
  notes?: string | null;
  favorite?: boolean;
  organizationId?: string | null;
  folderId?: string | null;
  key?: string | null;
  login?: LoginCipherData | null;
  revisionDate?: string | null;
}

export interface FolderResponse {
  id: string;
  name?: string | null;
}

export interface SyncResponse {
  profile: SyncProfile;
  ciphers: CipherResponse[];
  folders?: FolderResponse[];
}
