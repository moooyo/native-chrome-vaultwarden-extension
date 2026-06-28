import type { LoginUri } from './uri-match.js';

export type FieldName = 'username' | 'password' | 'totp' | 'notes';

export interface CipherSummary {
  id: string;
  name: string;
  username?: string;
  uris: string[];
  loginUris: LoginUri[];
  type: 1 | 2 | 3 | 4 | 5;
  favorite: boolean;
  undecryptable?: boolean;
}

export interface DecryptedCipher extends CipherSummary {
  password?: string;
  totp?: string;
  notes?: string;
}
