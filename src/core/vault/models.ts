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
  /** True when a login carries at least one stored passkey (FIDO2 credential). */
  hasPasskey?: boolean;
  /** Non-sensitive list subtitle (e.g. card brand or identity full name). Never holds secrets. */
  subtitle?: string;
  /** True when the item is master-password-reprompt protected: secrets are released only after the
   *  master password is re-verified. The worker enforces this; the UI must gate access accordingly. */
  reprompt?: boolean;
  /** Soft-delete timestamp; when set, the cipher is in the trash (excluded from the main list & autofill). */
  deletedDate?: string;
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
  fido2Credentials?: DecryptedFido2Credential[];
}

/** A decrypted passkey. keyValue (PKCS#8 base64url private key) is sensitive — never send it to the UI. */
export interface DecryptedFido2Credential {
  credentialId: string;
  keyValue: string;
  rpId: string;
  counter: number;
  userHandle?: string;
  userName?: string;
  rpName?: string;
}

/** Plaintext cipher form input from the editor, before encryption into a write request. */
export interface CipherInput {
  type: 1 | 2 | 3 | 4;
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
  };
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
