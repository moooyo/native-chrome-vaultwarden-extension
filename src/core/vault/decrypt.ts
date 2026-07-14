import type { AttachmentData, CardCipherData, CipherFieldData, CipherResponse, CollectionResponse, Fido2CredentialData, FolderResponse, IdentityCipherData, OrganizationResponse } from '../api/types.js';
import { decryptToText, EncStringMacError, UnsupportedEncTypeError } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey, unwrapRsaWrappedKey } from '../crypto/keys.js';
import { CARD_FIELDS, IDENTITY_FIELDS } from './models.js';
import type { CipherSummary, CollectionSummary, CustomFieldType, DecryptedAttachment, DecryptedCard, DecryptedCipher, DecryptedField, DecryptedFido2Credential, DecryptedIdentity, FolderSummary } from './models.js';
import type { LoginUri } from './uri-match.js';

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
    if (cipher.reprompt) out.reprompt = true;
    if (cipher.passwordHistory?.length) out.passwordHistoryCount = cipher.passwordHistory.length;
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
    if (cipher.fields?.length) {
      const fields = await decryptCustomFields(cipher.fields, key);
      if (fields.length) out.fields = fields;
    }
    if (cipher.attachments?.length) {
      const attachments = await decryptAttachments(cipher.attachments, key);
      if (attachments.length) out.attachments = attachments;
    }
    return out;
  } catch {
    // Any decrypt failure degrades to an undecryptable summary — not only a bad MAC or unsupported
    // encType, but also a malformed EncString (invalid base64) or a wrapped key of the wrong length,
    // which surface as a plain Error. Rethrowing those turned one corrupt cipher into an unhandled
    // throw on targeted reveal/download (decryptCipherById → decryptCipher); fail-close instead.
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
}

/**
 * Decrypt only what the vault list needs from a cipher: the display fields (name, login URIs,
 * username, and the card-brand / identity-name subtitle) plus the non-secret presence flags. Unlike
 * decryptCipher this NEVER decrypts the password, TOTP secret, notes, card number/code, identity
 * national-IDs, custom fields, attachment names, or the passkey PKCS#8 private key — so a large
 * vault's every-sync `decryptSummaries` pass does far less WebCrypto work and materializes far less
 * plaintext. Use decryptCipher for detail / reveal / edit / autofill flows that need the secrets.
 *
 * Presence flags (hasTotp / hasPasskey / passwordHistoryCount / reprompt) are derived from the
 * ENCRYPTED response shape. This preserves the prior "successful non-empty decrypt" semantics for
 * every stored item: the encrypt paths only ever write an optional secret when its plaintext is
 * non-empty (see encryptLogin / encryptFido2Credential), so a present ciphertext always decrypts to
 * a non-empty string. hasPasskey additionally requires credentialId + keyValue + rpId to all be
 * present, mirroring decryptFido2Credentials, which drops a credential missing any of the three.
 */
export async function decryptCipherSummary(
  cipher: CipherResponse,
  userKey: SymmetricKey,
  orgKeys?: Map<string, SymmetricKey>,
): Promise<CipherSummary | undefined> {
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
    const summary: CipherSummary = {
      id: cipher.id,
      type: cipher.type,
      favorite: cipher.favorite ?? false,
      name,
      uris: loginUris.map((u) => u.uri),
      loginUris,
    };
    if (cipher.organizationId) summary.organizationId = cipher.organizationId;
    if (cipher.folderId) summary.folderId = cipher.folderId;
    if (cipher.collectionIds?.length) summary.collectionIds = cipher.collectionIds;
    if (cipher.reprompt) summary.reprompt = true;
    if (cipher.passwordHistory?.length) summary.passwordHistoryCount = cipher.passwordHistory.length;
    const username = await decryptOptional(cipher.login?.username, key);
    if (username) summary.username = username;
    if (cipher.login?.totp) summary.hasTotp = true;
    if (cipher.login?.fido2Credentials?.some((fc) => fc.credentialId && fc.keyValue && fc.rpId)) {
      summary.hasPasskey = true;
    }
    const subtitle = await summarySubtitle(cipher, key);
    if (subtitle) summary.subtitle = subtitle;
    if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
    return summary;
  } catch {
    // Mirror decryptCipher: any decrypt failure (bad MAC, unsupported encType, malformed base64, or a
    // bad-length wrapped key) degrades to an undecryptable summary rather than propagating.
    return undecryptableSummary(cipher);
  }
}

/** The list subtitle: card brand (type 3) or identity full name (type 4). Decrypts ONLY those
 *  non-secret display fields — never the card number/code or identity national-ID secrets. */
async function summarySubtitle(cipher: CipherResponse, key: SymmetricKey): Promise<string | undefined> {
  if (cipher.type === 3 && cipher.card) {
    return decryptOptional(cipher.card.brand, key);
  }
  if (cipher.type === 4 && cipher.identity) {
    const first = await decryptOptional(cipher.identity.firstName, key);
    const last = await decryptOptional(cipher.identity.lastName, key);
    const name = [first, last].filter(Boolean).join(' ');
    return name || undefined;
  }
  return undefined;
}

/** The list summary for a cipher whose display fields cannot be decrypted (bad MAC / unsupported enc
 *  type, or an unexpected error). Carries only the non-secret envelope fields. */
export function undecryptableSummary(cipher: CipherResponse): CipherSummary {
  const summary: CipherSummary = {
    id: cipher.id,
    type: cipher.type,
    favorite: cipher.favorite ?? false,
    name: '(undecryptable)',
    uris: [],
    loginUris: [],
    undecryptable: true,
  };
  if (cipher.organizationId) summary.organizationId = cipher.organizationId;
  if (cipher.folderId) summary.folderId = cipher.folderId;
  if (cipher.collectionIds?.length) summary.collectionIds = cipher.collectionIds;
  if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
  return summary;
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

/** Decrypt custom fields. Text/Hidden/Boolean carry a decrypted value; Linked (type 3) carries only
 *  its linkedId. A field whose name or value fails to decrypt degrades just that field (empty name /
 *  dropped value) so one tampered custom field never marks the whole item undecryptable. */
async function decryptCustomFields(src: CipherFieldData[], key: SymmetricKey): Promise<DecryptedField[]> {
  const out: DecryptedField[] = [];
  for (const f of src) {
    const type = ((f.type ?? 0) as CustomFieldType);
    const field: DecryptedField = { type, name: (await decryptFieldOptional(f.name, key)) ?? '' };
    if (type === 3) {
      if (f.linkedId != null) field.linkedId = f.linkedId;
    } else {
      const value = await decryptFieldOptional(f.value, key);
      if (value !== undefined) field.value = value;
    }
    out.push(field);
  }
  return out;
}

/** Decrypt attachment metadata for display (fileName under the cipher key); a failed name degrades. */
async function decryptAttachments(src: AttachmentData[], key: SymmetricKey): Promise<DecryptedAttachment[]> {
  const out: DecryptedAttachment[] = [];
  for (const a of src) {
    if (!a.id) continue;
    let fileName = '(file)';
    if (a.fileName) {
      try { fileName = await decryptToText(a.fileName, key); } catch { fileName = '(undecryptable)'; }
    }
    const att: DecryptedAttachment = { id: a.id, fileName };
    if (a.size != null) att.size = a.size;
    if (a.sizeName != null) att.sizeName = a.sizeName;
    out.push(att);
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

/** Like decryptOptional, but a decrypt failure (bad MAC, malformed EncString, …) degrades to
 *  undefined instead of throwing — so one corrupt custom field never aborts the whole item. */
async function decryptFieldOptional(
  value: string | null | undefined,
  key: SymmetricKey,
): Promise<string | undefined> {
  if (!value) return undefined;
  try {
    return await decryptToText(value, key);
  } catch {
    return undefined;
  }
}
