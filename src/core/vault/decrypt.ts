import type { CardCipherData, CipherResponse, CollectionResponse, Fido2CredentialData, FolderResponse, IdentityCipherData, OrganizationResponse } from '../api/types.js';
import { decryptToText, EncStringMacError, UnsupportedEncTypeError } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey, unwrapRsaWrappedKey } from '../crypto/keys.js';
import type { CipherSummary, CollectionSummary, DecryptedCard, DecryptedCipher, DecryptedFido2Credential, DecryptedIdentity, FolderSummary } from './models.js';
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
  orgKeys?: Map<string, SymmetricKey>,
): Promise<DecryptedCipher | undefined> {
  // Organization ciphers are decrypted with that organization's key, not the account UserKey.
  // When the org key is unavailable (e.g. the account private key is locked) the cipher is skipped.
  const baseKey = cipher.organizationId ? orgKeys?.get(cipher.organizationId) : userKey;
  if (!baseKey) return undefined;
  try {
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, baseKey) : baseKey;
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
    if (cipher.organizationId) out.organizationId = cipher.organizationId;
    if (cipher.folderId) out.folderId = cipher.folderId;
    if (cipher.collectionIds?.length) out.collectionIds = cipher.collectionIds;
    const username = await decryptOptional(cipher.login?.username, key);
    const password = await decryptOptional(cipher.login?.password, key);
    const totp = await decryptOptional(cipher.login?.totp, key);
    const notes = await decryptOptional(cipher.notes, key);
    if (username) out.username = username;
    if (password) out.password = password;
    if (totp) out.totp = totp;
    if (notes) out.notes = notes;
    if (cipher.login?.fido2Credentials?.length) {
      const passkeys = await decryptFido2Credentials(cipher.login.fido2Credentials, key);
      if (passkeys.length) out.fido2Credentials = passkeys;
    }
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
      if (cipher.organizationId) undecryptable.organizationId = cipher.organizationId;
      if (cipher.folderId) undecryptable.folderId = cipher.folderId;
      if (cipher.collectionIds?.length) undecryptable.collectionIds = cipher.collectionIds;
      return undecryptable;
    }
    throw err;
  }
}

/**
 * Unwrap each organization's RSA-wrapped symmetric key into a map keyed by organization id.
 * Requires the decrypted account private key (PKCS8). Organizations whose key cannot be unwrapped
 * are skipped so a single bad key never blocks the rest of the vault.
 */
export async function buildOrgKeyMap(
  organizations: OrganizationResponse[] | null | undefined,
  privateKey: Uint8Array | undefined,
): Promise<Map<string, SymmetricKey>> {
  const map = new Map<string, SymmetricKey>();
  if (!privateKey || !organizations) return map;
  for (const org of organizations) {
    if (!org.id || !org.key) continue;
    try {
      map.set(org.id, await unwrapRsaWrappedKey(org.key, privateKey));
    } catch {
      // Skip organizations we cannot unwrap; their ciphers are counted as unsupported.
    }
  }
  return map;
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

/**
 * Decrypt collection names with their organization key. Collections whose org key is unavailable are
 * skipped (their ciphers are skipped too); a name that fails to decrypt degrades to a label.
 */
export async function decryptCollections(
  collections: CollectionResponse[] | undefined,
  orgKeys: Map<string, SymmetricKey>,
): Promise<CollectionSummary[]> {
  const out: CollectionSummary[] = [];
  for (const collection of collections ?? []) {
    if (!collection.id) continue;
    const key = orgKeys.get(collection.organizationId);
    if (!key) continue;
    out.push({
      id: collection.id,
      organizationId: collection.organizationId,
      name: await decryptFolderName(collection.name, key),
    });
  }
  return out;
}

/** Decrypt stored passkeys; a credential missing its key material or rpId is dropped. */
async function decryptFido2Credentials(src: Fido2CredentialData[], key: SymmetricKey): Promise<DecryptedFido2Credential[]> {
  const out: DecryptedFido2Credential[] = [];
  for (const fc of src) {
    const keyValue = await decryptOptional(fc.keyValue, key);
    const credentialId = await decryptOptional(fc.credentialId, key);
    const rpId = await decryptOptional(fc.rpId, key);
    if (!keyValue || !credentialId || !rpId) continue;
    const counter = Number(await decryptOptional(fc.counter, key));
    const cred: DecryptedFido2Credential = { credentialId, keyValue, rpId, counter: Number.isFinite(counter) ? counter : 0 };
    const userHandle = await decryptOptional(fc.userHandle, key);
    if (userHandle) cred.userHandle = userHandle;
    const userName = await decryptOptional(fc.userName, key);
    if (userName) cred.userName = userName;
    const rpName = await decryptOptional(fc.rpName, key);
    if (rpName) cred.rpName = rpName;
    out.push(cred);
  }
  return out;
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
