// Vault export/import. Export produces decrypted plaintext (an explicit, user-initiated action) as
// Bitwarden unencrypted JSON, or a password-protected encrypted JSON. Import parses Bitwarden JSON
// (plaintext or encrypted), or a CSV (Bitwarden CSV / generic browser export), into CipherInput[].

import type { CipherInput, DecryptedCipher, DecryptedCard, DecryptedIdentity, FolderSummary } from './models.js';
import type { LoginUri } from './uri-match.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { pbkdf2Sha256 } from '../crypto/primitives.js';
import { stretchMasterKey } from '../crypto/kdf.js';
import { encryptToText, decryptToText } from '../crypto/encstring.js';
import { utf8ToBytes, bytesToBase64 } from '../crypto/encoding.js';

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
  kdfIterations: number,
  deps: EncryptedExportDeps = {},
): Promise<string> {
  const randomBytes = deps.randomBytes ?? ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const newGuid = deps.newGuid ?? (() => globalThis.crypto.randomUUID());
  const saltB64 = bytesToBase64(randomBytes(16));
  const key = await deriveExportKey(password, saltB64, kdfIterations);
  return JSON.stringify({
    encrypted: true,
    passwordProtected: true,
    salt: saltB64,
    kdfType: 0,
    kdfIterations,
    kdfMemory: null,
    kdfParallelism: null,
    // Lets an importer verify the password before decrypting the payload.
    encKeyValidation_DO_NOT_EDIT: await encryptToText(newGuid(), key),
    data: await encryptToText(plaintextJson, key),
  }, null, 2);
}

/** True when the content is a Bitwarden password-protected encrypted export. */
export function isEncryptedExport(json: string): boolean {
  try {
    const p = JSON.parse(json) as Record<string, unknown>;
    return isRecord(p) && p.encrypted === true && p.passwordProtected === true && typeof p.data === 'string';
  } catch {
    return false;
  }
}

/** Decrypt a password-protected export to its inner plaintext export JSON; throws on a wrong password. */
export async function decryptEncryptedExport(json: string, password: string): Promise<string> {
  const p = JSON.parse(json) as Record<string, unknown>;
  if (p.kdfType !== undefined && p.kdfType !== null && p.kdfType !== 0) {
    throw new Error('This export uses Argon2 KDF, which is not supported');
  }
  const key = await deriveExportKey(password, String(p.salt ?? ''), Number(p.kdfIterations ?? 0));
  try {
    await decryptToText(String(p.encKeyValidation_DO_NOT_EDIT ?? ''), key); // password check (MAC)
  } catch {
    throw new Error('Incorrect export password');
  }
  return decryptToText(String(p.data ?? ''), key);
}

/** Derive the export encryption key: PBKDF2-SHA256(password, utf8(saltB64)) → stretch to enc+mac.
 *  The base64 salt string itself is the PBKDF2 salt input, matching Bitwarden's export format. */
async function deriveExportKey(password: string, saltB64: string, iterations: number): Promise<SymmetricKey> {
  const masterKey = await pbkdf2Sha256(utf8ToBytes(password), utf8ToBytes(saltB64), iterations, 32);
  return stretchMasterKey(masterKey);
}

/**
 * Parse any supported import content into CipherInput[]: Bitwarden JSON (plaintext or password-protected
 * encrypted, needs `password`) or CSV (Bitwarden CSV / generic browser export). Async because the
 * encrypted path must derive a key.
 */
export async function parseImport(content: string, password?: string): Promise<CipherInput[]> {
  if (content.trimStart().startsWith('{')) {
    if (isEncryptedExport(content)) {
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
