// Vault export/import in the Bitwarden unencrypted JSON format. Export produces decrypted plaintext
// (an explicit, user-initiated action); import parses a JSON export into CipherInput[] for creation.

import type { CipherInput, DecryptedCipher, DecryptedCard, DecryptedIdentity, FolderSummary } from './models.js';
import type { LoginUri } from './uri-match.js';

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
