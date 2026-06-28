import type { CardCipherData, CipherResponse, FolderResponse, IdentityCipherData } from '../api/types.js';
import { decryptToText, EncStringMacError, UnsupportedEncTypeError } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import type { CipherSummary, DecryptedCard, DecryptedCipher, DecryptedIdentity, FolderSummary } from './models.js';
import type { LoginUri } from './uri-match.js';

const IDENTITY_FIELDS: Array<keyof IdentityCipherData> = [
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
  'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn',
  'username', 'passportNumber', 'licenseNumber',
];

const CARD_FIELDS: Array<keyof CardCipherData> = [
  'cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code',
];

export async function decryptCipher(
  cipher: CipherResponse,
  userKey: SymmetricKey,
): Promise<DecryptedCipher | undefined> {
  if (cipher.organizationId) return undefined;
  try {
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, userKey) : userKey;
    const name = await decryptRequired(cipher.name, key, '(no name)');
    const loginUris: LoginUri[] = [];
    for (const u of cipher.login?.uris ?? []) {
      if (u.uri) {
        const loginUri: LoginUri = { uri: await decryptToText(u.uri, key) };
        if (u.match !== undefined && u.match !== null) {
          loginUri.match = u.match;
        }
        loginUris.push(loginUri);
      }
    }
    const out: DecryptedCipher = {
      id: cipher.id,
      type: cipher.type,
      favorite: cipher.favorite ?? false,
      name,
      uris: loginUris.map((u) => u.uri),
      loginUris,
    };
    if (cipher.folderId) out.folderId = cipher.folderId;
    const username = await decryptOptional(cipher.login?.username, key);
    const password = await decryptOptional(cipher.login?.password, key);
    const totp = await decryptOptional(cipher.login?.totp, key);
    const notes = await decryptOptional(cipher.notes, key);
    if (username) out.username = username;
    if (password) out.password = password;
    if (totp) out.totp = totp;
    if (notes) out.notes = notes;
    if (cipher.card) out.card = await decryptCard(cipher.card, key);
    if (cipher.identity) out.identity = await decryptIdentity(cipher.identity, key);
    return out;
  } catch (err) {
    if (err instanceof EncStringMacError || err instanceof UnsupportedEncTypeError) {
      const undecryptable: CipherSummary = {
        id: cipher.id,
        type: cipher.type,
        favorite: cipher.favorite ?? false,
        name: '(error)',
        uris: [],
        loginUris: [],
        undecryptable: true,
      };
      if (cipher.folderId) undecryptable.folderId = cipher.folderId;
      return undecryptable;
    }
    throw err;
  }
}

/** Decrypt folder names (no per-folder key). Each failure degrades to a label, never aborts. */
export async function decryptFolders(
  folders: FolderResponse[] | undefined,
  userKey: SymmetricKey,
): Promise<FolderSummary[]> {
  const out: FolderSummary[] = [];
  for (const folder of folders ?? []) {
    out.push({ id: folder.id, name: await decryptFolderName(folder.name, userKey) });
  }
  return out;
}

async function decryptFolderName(name: string | null | undefined, userKey: SymmetricKey): Promise<string> {
  if (!name) return '(no name)';
  try {
    return await decryptToText(name, userKey);
  } catch (err) {
    if (err instanceof EncStringMacError || err instanceof UnsupportedEncTypeError) return '(undecryptable)';
    throw err;
  }
}

async function decryptCard(src: CardCipherData, key: SymmetricKey): Promise<DecryptedCard> {
  const card: DecryptedCard = {};
  for (const field of CARD_FIELDS) {
    const value = await decryptOptional(src[field], key);
    if (value) card[field] = value;
  }
  return card;
}

async function decryptIdentity(src: IdentityCipherData, key: SymmetricKey): Promise<DecryptedIdentity> {
  const identity: DecryptedIdentity = {};
  for (const field of IDENTITY_FIELDS) {
    const value = await decryptOptional(src[field], key);
    if (value) identity[field] = value;
  }
  return identity;
}

async function decryptRequired(
  value: string | null | undefined,
  key: SymmetricKey,
  fallback: string,
): Promise<string> {
  return value ? decryptToText(value, key) : fallback;
}

async function decryptOptional(
  value: string | null | undefined,
  key: SymmetricKey,
): Promise<string | undefined> {
  return value ? decryptToText(value, key) : undefined;
}
