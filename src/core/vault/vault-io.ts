// Vault export/import. Export produces decrypted plaintext (an explicit, user-initiated action) as
// Bitwarden unencrypted JSON, or a password-protected encrypted JSON. Import parses Bitwarden JSON
// (plaintext or encrypted), or a CSV (Bitwarden CSV / generic browser export), into CipherInput[].

import type { CipherInput, DecryptedCipher, DecryptedCard, DecryptedIdentity, FolderSummary } from './models.js';
import type { LoginUri } from './uri-match.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { deriveKdfMaterial, parseKdfConfig, stretchMasterKey, type KdfConfig } from '../crypto/kdf.js';
import { encryptToBytes, decryptToBytes, EncStringMacError } from '../crypto/encstring.js';
import { utf8ToBytes, bytesToBase64, bytesToUtf8 } from '../crypto/encoding.js';

interface ExportItem {
  id: string;
  organizationId: string | null;
  folderId: string | null;
  type: number;
  name: string;
  notes: string | null;
  favorite: boolean;
  collectionIds: string[] | null;
  login?: { username: string | null; password: string | null; totp: string | null; uris: Array<{ match: number | null; uri: string }> };
  card?: DecryptedCard;
  identity?: DecryptedIdentity;
  secureNote?: { type: number };
}

/** Serialize decrypted ciphers + folders to a Bitwarden-compatible unencrypted export. */
export function buildExportJson(ciphers: DecryptedCipher[], folders: FolderSummary[]): string {
  const items = ciphers.map<ExportItem>((c) => {
    const item: ExportItem = {
      id: c.id,
      organizationId: c.organizationId ?? null,
      folderId: c.folderId ?? null,
      type: c.type,
      name: c.name,
      notes: c.notes ?? null,
      favorite: c.favorite,
      collectionIds: c.collectionIds ?? null,
    };
    if (c.type === 1) {
      item.login = {
        username: c.username ?? null,
        password: c.password ?? null,
        totp: c.totp ?? null,
        uris: c.loginUris.map((u) => ({ match: u.match ?? null, uri: u.uri })),
      };
    } else if (c.type === 2) {
      item.secureNote = { type: 0 };
    } else if (c.type === 3 && c.card) {
      item.card = c.card;
    } else if (c.type === 4 && c.identity) {
      item.identity = c.identity;
    }
    return item;
  });
  return JSON.stringify({ encrypted: false, folders: folders.map((f) => ({ id: f.id, name: f.name })), items }, null, 2);
}

/** Parse a Bitwarden unencrypted JSON export into CipherInput[] ready for createCipher. Throws on
 *  malformed JSON. Items without a name, or of unsupported types, are skipped. folderIds are dropped
 *  (folders from another vault don't exist here). */
export function parseImportJson(json: string): CipherInput[] {
  const parsed = JSON.parse(json) as { items?: unknown };
  const rawItems = Array.isArray(parsed.items) ? parsed.items : [];
  const out: CipherInput[] = [];
  for (const raw of rawItems) {
    if (!isRecord(raw)) continue;
    const type = raw.type;
    if (type !== 1 && type !== 2 && type !== 3 && type !== 4) continue;
    const name = typeof raw.name === 'string' ? raw.name.trim() : '';
    if (!name) continue;
    const input: CipherInput = { type, name };
    if (typeof raw.notes === 'string' && raw.notes) input.notes = raw.notes;
    if (raw.favorite === true) input.favorite = true;
    if (type === 1 && isRecord(raw.login)) input.login = parseLogin(raw.login);
    if (type === 3 && isRecord(raw.card)) input.card = pickStrings(raw.card) as DecryptedCard;
    if (type === 4 && isRecord(raw.identity)) input.identity = pickStrings(raw.identity) as DecryptedIdentity;
    out.push(input);
  }
  return out;
}

export interface EncryptedExportDeps {
  randomBytes?: (n: number) => Uint8Array;
  newGuid?: () => string;
}

/**
 * Wrap already-serialized plaintext export JSON in a Bitwarden password-protected (account-independent)
 * encrypted export: derive a key from the password + a random salt (PBKDF2-SHA256), stretch it, and
 * encrypt the payload as encType=2. Decryptable by Bitwarden and by importEncryptedExport below.
 */
export async function buildEncryptedExportJson(
  plaintextJson: string,
  password: string,
  kdf: KdfConfig,
  deps: EncryptedExportDeps = {},
): Promise<string> {
  const randomBytes = deps.randomBytes ?? ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const newGuid = deps.newGuid ?? (() => globalThis.crypto.randomUUID());
  const saltBytes = randomBytes(16);
  let saltB64: string;
  try {
    saltB64 = bytesToBase64(saltBytes);
  } finally {
    saltBytes.fill(0);
  }
  const key = await deriveExportKey(password, saltB64, kdf);
  const validationBytes = utf8ToBytes(newGuid());
  const plaintextBytes = utf8ToBytes(plaintextJson);
  try {
    return JSON.stringify({
      encrypted: true,
      passwordProtected: true,
      salt: saltB64,
      kdfType: kdf.kdf,
      kdfIterations: kdf.kdfIterations,
      kdfMemory: kdf.kdf === 1 ? kdf.kdfMemory : null,
      kdfParallelism: kdf.kdf === 1 ? kdf.kdfParallelism : null,
      // Lets an importer verify the password before decrypting the payload.
      encKeyValidation_DO_NOT_EDIT: await encryptToBytes(validationBytes, key),
      data: await encryptToBytes(plaintextBytes, key),
    }, null, 2);
  } finally {
    validationBytes.fill(0);
    plaintextBytes.fill(0);
    destroySymmetricKey(key);
  }
}

/** True when the content is a Bitwarden password-protected encrypted export. */
export function isEncryptedExport(json: string): boolean {
  try {
    const p = JSON.parse(json) as Record<string, unknown>;
    return isRecord(p) && p.encrypted === true && p.passwordProtected === true;
  } catch {
    return false;
  }
}

/** Decrypt a password-protected export to its inner plaintext export JSON; throws on a wrong password. */
export async function decryptEncryptedExport(json: string, password: string): Promise<string> {
  const p = JSON.parse(json) as Record<string, unknown>;
  if (!isRecord(p) || p.encrypted !== true || p.passwordProtected !== true) {
    throw new Error('This is not a password-protected Bitwarden export');
  }
  if (
    typeof p.salt !== 'string'
    || p.salt.length === 0
    || typeof p.encKeyValidation_DO_NOT_EDIT !== 'string'
    || p.encKeyValidation_DO_NOT_EDIT.length === 0
    || typeof p.data !== 'string'
    || p.data.length === 0
  ) {
    throw new Error('This encrypted export is incomplete or malformed');
  }
  let kdf: KdfConfig;
  try {
    kdf = parseKdfConfig(p);
  } catch {
    throw new Error('This export is missing valid KDF parameters');
  }
  const key = await deriveExportKey(password, p.salt, kdf);
  try {
    try {
      const validation = await decryptToBytes(p.encKeyValidation_DO_NOT_EDIT, key);
      validation.fill(0); // password check (MAC)
    } catch (error) {
      if (error instanceof EncStringMacError) {
        throw new Error('Incorrect export password or damaged validation data', { cause: error });
      }
      throw new Error('This encrypted export has malformed validation data', { cause: error });
    }
    try {
      const plaintext = await decryptToBytes(p.data, key);
      try {
        return bytesToUtf8(plaintext);
      } finally {
        plaintext.fill(0);
      }
    } catch (error) {
      throw new Error('This encrypted export payload is corrupted', { cause: error });
    }
  } finally {
    destroySymmetricKey(key);
  }
}

/** Derive an export key from the base64 salt string, matching Bitwarden's encrypted-export format. */
async function deriveExportKey(password: string, saltB64: string, kdf: KdfConfig): Promise<SymmetricKey> {
  const passwordBytes = utf8ToBytes(password);
  const saltBytes = utf8ToBytes(saltB64);
  let masterKey: Uint8Array | undefined;
  try {
    masterKey = await deriveKdfMaterial(passwordBytes, saltBytes, kdf);
    return await stretchMasterKey(masterKey);
  } finally {
    passwordBytes.fill(0);
    saltBytes.fill(0);
    masterKey?.fill(0);
  }
}

function destroySymmetricKey(key: SymmetricKey): void {
  key.encKey.fill(0);
  key.macKey.fill(0);
}

/**
 * Parse any supported import content into CipherInput[]: Bitwarden JSON (plaintext or password-protected
 * encrypted, needs `password`) or CSV (Bitwarden CSV / generic browser export). Async because the
 * encrypted path must derive a key.
 */
export async function parseImport(content: string, password?: string): Promise<CipherInput[]> {
  if (content.trimStart().startsWith('{')) {
    const parsed = JSON.parse(content) as unknown;
    if (isRecord(parsed) && parsed.encrypted === true) {
      if (parsed.passwordProtected !== true) {
        throw new Error('Account-restricted encrypted exports are not supported yet');
      }
      if (!password) throw new Error('This export is password-protected; enter its password to import');
      return parseImportJson(await decryptEncryptedExport(content, password));
    }
    return parseImportJson(content);
  }
  return parseCsvImport(content);
}

/**
 * Parse a CSV import into CipherInput[]. Recognizes the Bitwarden CSV columns
 * (name, type, notes, login_username/password/uri/totp, favorite, reprompt) and the generic browser
 * export shape (name/title, url, username, password, note). Logins and secure notes are supported.
 */
export function parseCsvImport(csv: string): CipherInput[] {
  const rows = parseCsvRows(csv);
  if (rows.length < 2) return [];
  const header = rows[0]!.map((h) => h.trim().toLowerCase());
  const col = (row: string[], ...names: string[]): string => {
    for (const name of names) {
      const i = header.indexOf(name);
      if (i >= 0 && row[i] != null) return row[i]!.trim();
    }
    return '';
  };
  const out: CipherInput[] = [];
  for (const row of rows.slice(1)) {
    const name = col(row, 'name', 'title', 'account') || col(row, 'login_uri', 'url', 'uri');
    if (!name) continue;
    const typeRaw = col(row, 'type').toLowerCase();
    const isNote = typeRaw === '2' || typeRaw === 'note' || typeRaw === 'securenote' || typeRaw === 'secure note';
    const notes = col(row, 'notes', 'note', 'comments');
    const input: CipherInput = { type: isNote ? 2 : 1, name };
    if (notes) input.notes = notes;
    if (col(row, 'favorite') === '1' || col(row, 'favorite').toLowerCase() === 'true') input.favorite = true;
    if (col(row, 'reprompt') === '1') input.reprompt = true;
    if (!isNote) {
      const login: NonNullable<CipherInput['login']> = {};
      const username = col(row, 'login_username', 'username', 'user', 'email', 'login');
      const pwd = col(row, 'login_password', 'password', 'pass');
      const uri = col(row, 'login_uri', 'url', 'uri', 'website');
      const totp = col(row, 'login_totp', 'totp', 'otpauth');
      if (username) login.username = username;
      if (pwd) login.password = pwd;
      if (totp) login.totp = totp;
      if (uri) login.uris = [{ uri }];
      input.login = login;
    }
    out.push(input);
  }
  return out;
}

/** Minimal RFC 4180 CSV parser: handles quoted fields with embedded commas, quotes, and newlines. */
function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let hasContent = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
      } else field += c;
      continue;
    }
    if (c === '"') { inQuotes = true; hasContent = true; }
    else if (c === ',') { row.push(field); field = ''; hasContent = true; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      if (hasContent || field) { row.push(field); rows.push(row); }
      row = []; field = ''; hasContent = false;
    } else { field += c; hasContent = true; }
  }
  if (hasContent || field) { row.push(field); rows.push(row); }
  return rows;
}

function parseLogin(login: Record<string, unknown>): NonNullable<CipherInput['login']> {
  const out: NonNullable<CipherInput['login']> = {};
  if (typeof login.username === 'string' && login.username) out.username = login.username;
  if (typeof login.password === 'string' && login.password) out.password = login.password;
  if (typeof login.totp === 'string' && login.totp) out.totp = login.totp;
  if (Array.isArray(login.uris)) {
    const uris: LoginUri[] = [];
    for (const u of login.uris) {
      if (isRecord(u) && typeof u.uri === 'string' && u.uri) {
        uris.push(typeof u.match === 'number' ? { uri: u.uri, match: u.match } : { uri: u.uri });
      }
    }
    if (uris.length) out.uris = uris;
  }
  return out;
}

function pickStrings(src: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(src)) {
    if (typeof v === 'string' && v) out[k] = v;
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
