import type { AttachmentData, CardCipherData, CipherFieldData, CipherResponse, CollectionResponse, Fido2CredentialData, FolderResponse, IdentityCipherData, OrganizationResponse, SshKeyCipherData, SyncProfile } from '../api/types.js';
import { isValidRawCipherType } from '../api/server-capabilities.js';
import { decryptToText, EncStringMacError, UnsupportedEncTypeError } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey, unwrapRsaWrappedKey } from '../crypto/keys.js';
import { CARD_FIELDS, IDENTITY_FIELDS, isKnownCipherType } from './models.js';
import type { CipherSummary, CollectionSummary, CustomFieldType, DecryptedAttachment, DecryptedCard, DecryptedCipher, DecryptedField, DecryptedFido2Credential, DecryptedIdentity, DecryptedSshKey, FolderSummary, KnownCipherType, KnownCipherSummary } from './models.js';
import type { LoginUri } from './uri-match.js';
import {
  assertValidatedRawSshCipherPayloadExclusivity,
  parseDecryptedSshKey,
  parseSshKeyCipherData,
  validateSshKeyPlaintextField,
} from './ssh-key.js';
import {
  DEFAULT_RAW_SYNC_CIPHER_COMPATIBILITY_LIMITS,
  validateRawSyncCipherCompatibility,
  type RawSyncCipherCompatibilityResult,
} from './vault-sync-cipher-compat.js';
import { projectValidatedCipherAccess } from './cipher-access.js';
import { selectOrganizationKeySources } from './organization-profile.js';

type ValidatedRawCipherCompatibility = Extract<
  RawSyncCipherCompatibilityResult,
  { readonly ok: true }
>;

type RawCipherReadAuthority =
  | {
    readonly kind: 'known';
    readonly type: KnownCipherType;
    readonly compatibility: ValidatedRawCipherCompatibility;
  }
  | { readonly kind: 'unsupported'; readonly metadata: UnsupportedCipherMetadata };

interface UnsupportedCipherMetadata {
  readonly id: string;
  readonly type: number;
  readonly favorite: boolean;
  readonly organizationId?: string;
  readonly folderId?: string;
  readonly collectionIds?: string[];
  readonly deletedDate?: string;
  readonly archivedDate?: string;
}

export async function decryptCipher(
  cipher: CipherResponse,
  userKey: SymmetricKey,
  orgKeys?: Map<string, SymmetricKey>,
): Promise<DecryptedCipher | undefined> {
  const authority = authorizeRawCipherRead(cipher);
  if (authority.kind === 'unsupported') return undefined;
  const type = authority.type;
  // Organization ciphers are decrypted with that organization's key, not the account UserKey.
  // When the org key is unavailable (e.g. the account private key is locked) the cipher is skipped.
  const baseKey = cipher.organizationId ? orgKeys?.get(cipher.organizationId) : userKey;
  if (!baseKey) return undefined;
  try {
    const sshKey = type === 5
      ? validatedSshKeyPayload(cipher, authority.compatibility)
      : undefined;
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, baseKey) : baseKey;
    const name = await decryptRequired(cipher.name, key, '(no name)');
    const loginUris: LoginUri[] = [];
    for (const u of type === 1 ? cipher.login?.uris ?? [] : []) {
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
      type,
      favorite: cipher.favorite ?? false,
      name,
      uris: loginUris.map((u) => u.uri),
      loginUris,
    };
    const access = projectValidatedCipherAccess(cipher);
    if (cipher.organizationId) {
      out.organizationId = cipher.organizationId;
      out.access = { ...access };
    }
    if (cipher.folderId) out.folderId = cipher.folderId;
    if (cipher.collectionIds?.length) out.collectionIds = cipher.collectionIds;
    if (cipher.deletedDate) out.deletedDate = cipher.deletedDate;
    if (cipher.archivedDate) out.archivedDate = cipher.archivedDate;
    if (type === 1 && cipher.login?.autofillOnPageLoad !== undefined) {
      out.autofillOnPageLoad = cipher.login.autofillOnPageLoad;
    }
    if (cipher.reprompt) out.reprompt = true;
    if (access.viewPassword && cipher.passwordHistory?.length) {
      out.passwordHistoryCount = cipher.passwordHistory.length;
    }
    const username = type === 1 ? await decryptOptional(cipher.login?.username, key) : undefined;
    const password = type === 1 ? await decryptOptional(cipher.login?.password, key) : undefined;
    const totp = type === 1 ? await decryptOptional(cipher.login?.totp, key) : undefined;
    const notes = await decryptOptional(cipher.notes, key);
    if (username) out.username = username;
    if (password) out.password = password;
    if (totp) out.totp = totp;
    if (notes) out.notes = notes;
    if (type === 1 && cipher.login?.fido2Credentials?.length) {
      const passkeys = await decryptFido2Credentials(cipher.login.fido2Credentials, key);
      if (passkeys.length) out.fido2Credentials = passkeys;
    }
    if (type === 3 && cipher.card) out.card = await decryptCard(cipher.card, key);
    if (type === 4 && cipher.identity) out.identity = await decryptIdentity(cipher.identity, key);
    if (sshKey) out.sshKey = await decryptSshKey(sshKey, key);
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
    return knownUndecryptableSummary(cipher, type, '(error)');
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
  const authority = authorizeRawCipherRead(cipher);
  if (authority.kind === 'unsupported') {
    return validatedUnsupportedCipherSummary(authority.metadata);
  }
  const type = authority.type;
  const baseKey = cipher.organizationId ? orgKeys?.get(cipher.organizationId) : userKey;
  if (!baseKey) return undefined;
  try {
    const sshKey = type === 5
      ? validatedSshKeyPayload(cipher, authority.compatibility)
      : undefined;
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, baseKey) : baseKey;
    const name = await decryptRequired(cipher.name, key, '(no name)');
    const loginUris: LoginUri[] = [];
    for (const u of type === 1 ? cipher.login?.uris ?? [] : []) {
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
      type,
      favorite: cipher.favorite ?? false,
      name,
      uris: loginUris.map((u) => u.uri),
      loginUris,
    };
    const access = projectValidatedCipherAccess(cipher);
    if (cipher.organizationId) {
      summary.organizationId = cipher.organizationId;
      summary.access = { ...access };
    }
    if (cipher.folderId) summary.folderId = cipher.folderId;
    if (cipher.collectionIds?.length) summary.collectionIds = cipher.collectionIds;
    if (cipher.reprompt) summary.reprompt = true;
    if (access.viewPassword && cipher.passwordHistory?.length) {
      summary.passwordHistoryCount = cipher.passwordHistory.length;
    }
    const username = type === 1 ? await decryptOptional(cipher.login?.username, key) : undefined;
    if (username) summary.username = username;
    if (type === 1 && cipher.login?.totp) summary.hasTotp = true;
    if (type === 1 && cipher.login?.fido2Credentials?.some((fc) => fc.credentialId && fc.keyValue && fc.rpId)) {
      summary.hasPasskey = true;
    }
    if (type === 1 && cipher.login?.autofillOnPageLoad !== undefined) {
      summary.autofillOnPageLoad = cipher.login.autofillOnPageLoad;
    }
    const subtitle = await summarySubtitle(cipher, type, key, sshKey);
    if (subtitle) summary.subtitle = subtitle;
    if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
    if (cipher.archivedDate) summary.archivedDate = cipher.archivedDate;
    return summary;
  } catch {
    // Mirror decryptCipher: any decrypt failure (bad MAC, unsupported encType, malformed base64, or a
    // bad-length wrapped key) degrades to an undecryptable summary rather than propagating.
    return knownUndecryptableSummary(cipher, type, '(undecryptable)');
  }
}

/** The list subtitle: card brand (type 3) or identity full name (type 4). Decrypts ONLY those
 *  non-secret display fields — never the card number/code or identity national-ID secrets. */
async function summarySubtitle(
  cipher: CipherResponse,
  type: KnownCipherType,
  key: SymmetricKey,
  sshKey?: SshKeyCipherData,
): Promise<string | undefined> {
  if (type === 3 && cipher.card) {
    return decryptOptional(cipher.card.brand, key);
  }
  if (type === 4 && cipher.identity) {
    const first = await decryptOptional(cipher.identity.firstName, key);
    const last = await decryptOptional(cipher.identity.lastName, key);
    const name = [first, last].filter(Boolean).join(' ');
    return name || undefined;
  }
  if (type === 5 && sshKey?.keyFingerprint) {
    return validateSshKeyPlaintextField(
      await decryptToText(sshKey.keyFingerprint, key),
      'keyFingerprint',
    );
  }
  return undefined;
}

function validatedSshKeyPayload(
  cipher: CipherResponse,
  compatibility: ValidatedRawCipherCompatibility,
): SshKeyCipherData {
  assertValidatedRawSshCipherPayloadExclusivity(cipher, compatibility);
  return parseSshKeyCipherData(cipher.sshKey);
}

/** The list summary for a cipher whose display fields cannot be decrypted (bad MAC / unsupported enc
 *  type, or an unexpected error). Carries only the non-secret envelope fields. */
export function undecryptableSummary(cipher: CipherResponse): CipherSummary {
  const authority = authorizeRawCipherRead(cipher);
  if (authority.kind === 'unsupported') {
    return validatedUnsupportedCipherSummary(authority.metadata);
  }
  return knownUndecryptableSummary(cipher, authority.type, '(undecryptable)');
}

function knownUndecryptableSummary(
  cipher: CipherResponse,
  type: KnownCipherType,
  placeholder: string,
): KnownCipherSummary {
  const summary: KnownCipherSummary = {
    id: cipher.id,
    type,
    favorite: cipher.favorite ?? false,
    name: placeholder,
    uris: [],
    loginUris: [],
    undecryptable: true,
  };
  if (cipher.organizationId) {
    summary.organizationId = cipher.organizationId;
    summary.access = { ...projectValidatedCipherAccess(cipher) };
  }
  if (cipher.folderId) summary.folderId = cipher.folderId;
  if (cipher.collectionIds?.length) summary.collectionIds = cipher.collectionIds;
  if (cipher.deletedDate) summary.deletedDate = cipher.deletedDate;
  if (cipher.archivedDate) summary.archivedDate = cipher.archivedDate;
  return summary;
}

/**
 * Metadata-only placeholder for a positive cipher type this client does not understand. This must
 * run before key unwrap or field access so no encrypted name, notes, fields, attachments, or future
 * type-specific payload is materialized under an accidental legacy interpretation.
 */
export function unsupportedCipherSummary(cipher: CipherResponse): CipherSummary {
  const authority = authorizeRawCipherRead(cipher);
  if (authority.kind === 'known') {
    throw new TypeError('Known cipher types must not use the unsupported placeholder');
  }
  return validatedUnsupportedCipherSummary(authority.metadata);
}

function validatedUnsupportedCipherSummary(
  metadata: UnsupportedCipherMetadata,
): CipherSummary {
  const summary: CipherSummary = {
    id: metadata.id,
    type: metadata.type,
    favorite: metadata.favorite,
    name: '(unsupported item)',
    uris: [],
    loginUris: [],
    unsupported: true,
    // Existing service-layer mutation gates already reject undecryptable items. Keep this second
    // marker until every caller can discriminate `unsupported` directly.
    undecryptable: true,
  };
  if (metadata.organizationId) summary.organizationId = metadata.organizationId;
  if (metadata.folderId) summary.folderId = metadata.folderId;
  if (metadata.collectionIds?.length) summary.collectionIds = metadata.collectionIds;
  if (metadata.deletedDate) summary.deletedDate = metadata.deletedDate;
  if (metadata.archivedDate) summary.archivedDate = metadata.archivedDate;
  return summary;
}

function authorizeRawCipherRead(cipher: CipherResponse): RawCipherReadAuthority {
  const compatibility = validateRawSyncCipherCompatibility(cipher);
  if (compatibility.ok) {
    const type = cipher.type;
    if (!isKnownCipherType(type)) {
      throw new TypeError('Validated cipher type is not supported');
    }
    return { kind: 'known', type, compatibility };
  }
  const unsupportedMetadata = readUnsupportedCipherMetadata(cipher);
  if (unsupportedMetadata) {
    return { kind: 'unsupported', metadata: unsupportedMetadata };
  }
  if (compatibility.code !== 'unsupported_cipher_type') {
    throw new TypeError(`Cannot read an incompatible cipher representation (${compatibility.code})`);
  }
  const typeEntry = ownEnumerableDataEntry(cipher, 'type');
  if (typeEntry?.present) {
    assertValidCipherType(typeEntry.value);
  }
  throw new TypeError('Cannot read an incompatible cipher representation (unsupported_cipher_type)');
}

/**
 * Unknown future types are metadata-only. Read their known envelope through own data descriptors so
 * an unrecognized payload (including accessors) is never materialized merely to render a placeholder.
 */
function readUnsupportedCipherMetadata(cipher: unknown): UnsupportedCipherMetadata | undefined {
  const typeEntry = ownEnumerableDataEntry(cipher, 'type');
  if (!typeEntry?.present || !isValidRawCipherType(typeEntry.value) || isKnownCipherType(typeEntry.value)) {
    return undefined;
  }
  const id = requiredUnsupportedString(cipher, 'id');
  const favoriteEntry = ownEnumerableDataEntry(cipher, 'favorite');
  if (!favoriteEntry) throw new TypeError('Unsupported cipher favorite metadata is invalid');
  const favorite = !favoriteEntry.present
    ? false
    : requireUnsupportedBoolean(favoriteEntry.value, 'favorite');
  const organizationId = optionalUnsupportedString(cipher, 'organizationId');
  const folderId = optionalUnsupportedString(cipher, 'folderId');
  const collectionIds = optionalUnsupportedStringArray(cipher, 'collectionIds');
  const deletedDate = optionalUnsupportedString(cipher, 'deletedDate');
  const archivedDate = optionalUnsupportedString(cipher, 'archivedDate');
  return {
    id,
    type: typeEntry.value,
    favorite,
    ...(organizationId ? { organizationId } : {}),
    ...(folderId ? { folderId } : {}),
    ...(collectionIds?.length ? { collectionIds } : {}),
    ...(deletedDate ? { deletedDate } : {}),
    ...(archivedDate ? { archivedDate } : {}),
  };
}

function ownEnumerableDataEntry(
  value: unknown,
  field: string,
): { readonly present: boolean; readonly value?: unknown } | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor) return { present: false };
    if (descriptor.enumerable !== true || !('value' in descriptor)) return undefined;
    return { present: true, value: descriptor.value };
  } catch {
    return undefined;
  }
}

function requiredUnsupportedString(value: unknown, field: string): string {
  const entry = ownEnumerableDataEntry(value, field);
  if (!entry?.present || typeof entry.value !== 'string' || entry.value.length === 0) {
    throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  }
  return entry.value;
}

function optionalUnsupportedString(value: unknown, field: string): string | undefined {
  const entry = ownEnumerableDataEntry(value, field);
  if (!entry) throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  if (!entry.present || entry.value === null || entry.value === undefined) return undefined;
  if (typeof entry.value !== 'string' || entry.value.length === 0) {
    throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  }
  return entry.value;
}

function requireUnsupportedBoolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  }
  return value;
}

function optionalUnsupportedStringArray(value: unknown, field: string): string[] | undefined {
  const entry = ownEnumerableDataEntry(value, field);
  if (!entry) throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  if (!entry.present || entry.value === null || entry.value === undefined) return undefined;
  const source = entry.value;
  if (!Array.isArray(source)) throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  try {
    if (Object.getPrototypeOf(source) !== Array.prototype) {
      throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(source, 'length');
    if (
      !lengthDescriptor
      || !('value' in lengthDescriptor)
      || !Number.isSafeInteger(lengthDescriptor.value)
      || (lengthDescriptor.value as number) > DEFAULT_RAW_SYNC_CIPHER_COMPATIBILITY_LIMITS.maxArrayLength
    ) {
      throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
    }
    const length = lengthDescriptor.value as number;
    const result: string[] = [];
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(source, String(index));
      if (
        !descriptor
        || descriptor.enumerable !== true
        || !('value' in descriptor)
        || typeof descriptor.value !== 'string'
        || descriptor.value.length === 0
      ) throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
      result.push(descriptor.value);
    }
    if (Reflect.ownKeys(source).length !== length + 1) {
      throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
    }
    return result;
  } catch {
    throw new TypeError(`Unsupported cipher ${field} metadata is invalid`);
  }
}

function assertValidCipherType(value: unknown): asserts value is number {
  if (!isValidRawCipherType(value)) throw new TypeError('Cipher type must be a positive safe integer');
}

/**
 * Unwrap each organization's RSA-wrapped symmetric key into a map keyed by organization id.
 * Requires the decrypted account private key (PKCS8). Organizations whose key cannot be unwrapped
 * are skipped so a single bad key never blocks the rest of the vault.
 */
export async function buildOrgKeyMap(
  organizations: readonly OrganizationResponse[] | null | undefined,
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

/**
 * Build every usable organization key from one sync profile. Direct organization and provider keys
 * are RSA-encapsulated to the account public key. Provider-organization keys are a distinct second
 * hop: an EncString wrapped by the matching provider key. `organizationsNew` is metadata-only and
 * intentionally never participates in key derivation.
 */
export async function buildSyncProfileOrgKeyMap(
  profile: SyncProfile | undefined,
  privateKey: Uint8Array | undefined,
): Promise<Map<string, SymmetricKey>> {
  if (!profile) return new Map();
  const sources = selectOrganizationKeySources(profile);
  const organizationKeys = await buildOrgKeyMap(sources.directOrganizations, privateKey);
  if (!privateKey) return organizationKeys;

  const providerKeys = await buildProviderKeyMap(sources.providers, privateKey);
  try {
    for (const organization of sources.providerOrganizations) {
      if (typeof organization.id !== 'string' || organization.id.length === 0) continue;

      // Official clients store provider entries after direct entries, so a provider projection is
      // authoritative for a duplicate organization id. Delete the direct key before attempting the
      // provider path; malformed provider material therefore fails closed instead of falling back.
      clearMappedKey(organizationKeys, organization.id);
      if (
        typeof organization.key !== 'string'
        || organization.key.length === 0
        || typeof organization.providerId !== 'string'
        || organization.providerId.length === 0
      ) continue;
      const providerKey = providerKeys.get(organization.providerId);
      if (!providerKey) continue;
      try {
        organizationKeys.set(
          organization.id,
          await unwrapSymmetricKey(organization.key, providerKey),
        );
      } catch {
        // One malformed provider organization must not prevent other organizations from loading.
      }
    }
  } finally {
    for (const key of providerKeys.values()) clearSymmetricKey(key);
    providerKeys.clear();
  }
  return organizationKeys;
}

async function buildProviderKeyMap(
  providers: readonly { readonly id: string; readonly key?: string | null }[],
  privateKey: Uint8Array,
): Promise<Map<string, SymmetricKey>> {
  const providerKeys = new Map<string, SymmetricKey>();
  for (const provider of providers) {
    if (!provider.id || !provider.key) continue;
    try {
      const key = await unwrapRsaWrappedKey(provider.key, privateKey);
      clearMappedKey(providerKeys, provider.id);
      providerKeys.set(provider.id, key);
    } catch {
      // Provider records are independent; retain every other successfully decoded key.
    }
  }
  return providerKeys;
}

function clearMappedKey(keys: Map<string, SymmetricKey>, id: string): void {
  const previous = keys.get(id);
  if (previous) clearSymmetricKey(previous);
  keys.delete(id);
}

function clearSymmetricKey(key: SymmetricKey): void {
  key.encKey.fill(0);
  key.macKey.fill(0);
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
    const decryptedName = await decryptFolderName(collection.name, key);
    const defaultUserCollectionEmail = typeof collection.defaultUserCollectionEmail === 'string'
      ? collection.defaultUserCollectionEmail
      : undefined;
    out.push({
      id: collection.id,
      organizationId: collection.organizationId,
      name: defaultUserCollectionEmail ?? decryptedName,
      ...(typeof collection.readOnly === 'boolean' ? { readOnly: collection.readOnly } : {}),
      ...(typeof collection.manage === 'boolean' ? { manage: collection.manage } : {}),
      ...(typeof collection.hidePasswords === 'boolean'
        ? { hidePasswords: collection.hidePasswords }
        : {}),
      ...(typeof collection.assigned === 'boolean' ? { assigned: collection.assigned } : {}),
      ...(typeof collection.type === 'number' ? { type: collection.type } : {}),
      ...(defaultUserCollectionEmail !== undefined
        ? { defaultUserCollectionEmail }
        : {}),
    });
  }
  return out;
}

/** Decrypt stored passkeys; a credential missing its key material or rpId is dropped. A missing,
 * malformed, or undecryptable discoverable flag fails closed to false while preserving exact-ID use. */
async function decryptFido2Credentials(src: Fido2CredentialData[], key: SymmetricKey): Promise<DecryptedFido2Credential[]> {
  const out: DecryptedFido2Credential[] = [];
  for (const fc of src) {
    const keyValue = await decryptOptional(fc.keyValue, key);
    const credentialId = await decryptOptional(fc.credentialId, key);
    const rpId = await decryptOptional(fc.rpId, key);
    if (!keyValue || !credentialId || !rpId) continue;
    const counter = Number(await decryptOptional(fc.counter, key));
    const discoverable = await decryptDiscoverable(fc.discoverable, key);
    const cred: DecryptedFido2Credential = {
      credentialId,
      keyValue,
      rpId,
      counter: Number.isFinite(counter) ? counter : 0,
      discoverable,
    };
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

async function decryptDiscoverable(
  value: string | null | undefined,
  key: SymmetricKey,
): Promise<boolean> {
  if (!value) return false;
  try {
    return await decryptToText(value, key) === 'true';
  } catch {
    return false;
  }
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
    if (a.key == null) att.legacy = true;
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

async function decryptSshKey(
  src: SshKeyCipherData,
  key: SymmetricKey,
): Promise<DecryptedSshKey> {
  const decrypted: DecryptedSshKey = {
    privateKey: await decryptToText(src.privateKey, key),
  };
  if (src.publicKey) decrypted.publicKey = await decryptToText(src.publicKey, key);
  if (src.keyFingerprint) {
    decrypted.keyFingerprint = await decryptToText(src.keyFingerprint, key);
  }
  return parseDecryptedSshKey(decrypted);
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
