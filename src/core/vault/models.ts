import type { LoginUri } from './uri-match.js';

export type FieldName =
  | 'username' | 'password' | 'totp' | 'notes'
  | 'card.number' | 'card.code'
  | 'identity.ssn' | 'identity.passportNumber' | 'identity.licenseNumber';

export interface CipherSummary {
  id: string;
  name: string;
  username?: string;
  uris: string[];
  loginUris: LoginUri[];
  type: 1 | 2 | 3 | 4 | 5;
  favorite: boolean;
  folderId?: string;
  /** Present for ciphers owned by an organization (decrypted with that organization's key). */
  organizationId?: string;
  /** Collections (organization groupings) this cipher belongs to. */
  collectionIds?: string[];
  /** True when a login carries a TOTP secret. The secret itself never enters a summary. */
  hasTotp?: boolean;
  /** Non-sensitive list subtitle (e.g. card brand or identity full name). Never holds secrets. */
  subtitle?: string;
  undecryptable?: boolean;
}

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

export interface DecryptedCipher extends CipherSummary {
  password?: string;
  totp?: string;
  notes?: string;
  card?: DecryptedCard;
  identity?: DecryptedIdentity;
}

export interface FolderSummary {
  id: string;
  name: string;
}

export interface CollectionSummary {
  id: string;
  name: string;
  organizationId: string;
}
