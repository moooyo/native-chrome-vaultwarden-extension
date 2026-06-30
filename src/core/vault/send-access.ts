// Recipient-side Send access: parse a share link and decrypt the accessed Send with the URL send key.
// No vault secret is involved — the send key comes from the link, which is public to the recipient — so
// this runs in the receive page (not the service worker). Network functions take an injected fetch.

import { deriveSendKey, hashSendPassword } from './sends.js';
import { decryptToText } from '../crypto/encstring.js';
import { base64UrlToBytes } from '../crypto/encoding.js';
import { decryptAttachmentFile } from './attachments.js';
import type { SymmetricKey } from '../crypto/keys.js';

export interface ParsedSendUrl {
  serverUrl: string;
  accessId: string;
  sendKey: Uint8Array;
}

export interface AccessedSend {
  /** The send id from the access response — used for the file-download route (NOT the accessId). */
  id: string;
  type: number; // 0 text, 1 file
  name: string;
  text?: string;
  fileName?: string;
  fileId?: string;
  sizeName?: string;
}

export type SendAccessError = 'invalid_link' | 'password_required' | 'unavailable' | 'decrypt_failed';

export function sendAccessError(code: SendAccessError): Error & { code: SendAccessError } {
  return Object.assign(new Error(code), { code });
}

/** Parse `{server}/#/send/{accessId}/{base64url(16-byte sendKey)}`. Throws 'invalid_link' on any defect. */
export function parseSendUrl(link: string): ParsedSendUrl {
  const trimmed = link.trim();
  const marker = '#/send/';
  const at = trimmed.indexOf(marker);
  if (at < 0) throw sendAccessError('invalid_link');
  const serverUrl = trimmed.slice(0, at).replace(/\/$/, '');
  if (!/^https?:\/\/[^/]/.test(serverUrl)) throw sendAccessError('invalid_link');
  const [accessId, keyPart, ...extra] = trimmed.slice(at + marker.length).split('/');
  if (!accessId || !keyPart || extra.length) throw sendAccessError('invalid_link');
  let sendKey: Uint8Array;
  try { sendKey = base64UrlToBytes(keyPart); } catch { throw sendAccessError('invalid_link'); }
  if (sendKey.length !== 16) throw sendAccessError('invalid_link');
  return { serverUrl, accessId, sendKey };
}

/** The password hash a Send expects, from a plaintext password + the URL send key (PBKDF2, reused). */
export async function sendPasswordHash(password: string, sendKey: Uint8Array): Promise<string> {
  return hashSendPassword(password, sendKey);
}

/** Decrypt the accessed Send's name + text (type 0) or file name (type 1) with the URL send key. */
export async function decryptAccessedSend(raw: unknown, sendKey: Uint8Array): Promise<AccessedSend> {
  const r = (raw ?? {}) as {
    id?: string; type?: number; name?: string;
    text?: { text?: string } | null;
    file?: { fileName?: string; id?: string; sizeName?: string } | null;
  };
  const derived = await deriveSendKey(sendKey);
  const out: AccessedSend = {
    id: r.id ?? '',
    type: r.type ?? 0,
    name: r.name ? await safeDecrypt(r.name, derived) : '(no name)',
  };
  if (r.type === 0 && r.text?.text) out.text = await safeDecrypt(r.text.text, derived);
  if (r.type === 1 && r.file) {
    if (r.file.fileName) out.fileName = await safeDecrypt(r.file.fileName, derived);
    if (r.file.id) out.fileId = r.file.id;
    if (r.file.sizeName) out.sizeName = r.file.sizeName;
  }
  return out;
}

async function safeDecrypt(value: string, key: SymmetricKey): Promise<string> {
  try { return await decryptToText(value, key); } catch { return '(undecryptable)'; }
}

/** POST /api/sends/access/{accessId} (anonymous). 401 → password_required. Returns the raw JSON. */
export async function accessSend(fetchFn: typeof fetch, serverUrl: string, accessId: string, passwordHash?: string): Promise<unknown> {
  const res = await fetchFn(`${serverUrl}/api/sends/access/${encodeURIComponent(accessId)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(passwordHash ? { password: passwordHash } : {}),
  });
  if (res.status === 401) throw sendAccessError('password_required');
  if (!res.ok) throw sendAccessError('unavailable');
  return res.json();
}

/** POST /api/sends/{sendId}/access/file/{fileId} → the absolute, JWT-protected download URL. */
export async function requestFileDownloadUrl(fetchFn: typeof fetch, serverUrl: string, sendId: string, fileId: string, passwordHash?: string): Promise<string> {
  const res = await fetchFn(`${serverUrl}/api/sends/${encodeURIComponent(sendId)}/access/file/${encodeURIComponent(fileId)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(passwordHash ? { password: passwordHash } : {}),
  });
  if (res.status === 401) throw sendAccessError('password_required');
  if (!res.ok) throw sendAccessError('unavailable');
  const json = (await res.json()) as { url?: string };
  if (!json.url) throw sendAccessError('unavailable');
  return json.url;
}

/** GET the download URL (absolute from the server; relative is prefixed with serverUrl) and decrypt. */
export async function downloadAndDecryptFile(fetchFn: typeof fetch, downloadUrl: string, serverUrl: string, sendKey: Uint8Array): Promise<Uint8Array> {
  const url = /^https?:\/\//.test(downloadUrl) ? downloadUrl : `${serverUrl}${downloadUrl}`;
  const res = await fetchFn(url);
  if (!res.ok) throw sendAccessError('unavailable');
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    return await decryptAttachmentFile(buf, await deriveSendKey(sendKey));
  } catch {
    throw sendAccessError('decrypt_failed');
  }
}

