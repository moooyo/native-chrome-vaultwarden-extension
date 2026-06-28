// Bitwarden Send: ephemeral encrypted sharing. Each send has a random 16-byte send key, stored as an
// EncString wrapped under the account user key. The actual field-encryption key is derived from the
// send key via HKDF-Expand (derive_shareable_key(secret, "send") → 64 bytes = enc ‖ mac). The send key
// also rides in the share URL (base64url) so a recipient can re-derive and decrypt.

import { hkdfExpandSha256, pbkdf2Sha256 } from '../crypto/primitives.js';
import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import { encryptToText, encryptToBytes, decryptToText, decryptToBytes } from '../crypto/encstring.js';
import { bytesToBase64, bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import type { SendRequest, SendResponse } from '../api/types.js';

const SEND_PASSWORD_ITERATIONS = 100_000;
const DAY_MS = 86_400_000;

/** Plaintext input for creating a text send. */
export interface SendInput {
  name: string;
  text: string;
  /** Hide the text behind a reveal on the access page. */
  hidden?: boolean;
  password?: string;
  maxAccessCount?: number;
  /** Days until the send expires (optional). */
  expirationDays?: number;
  /** Days until the send is deleted (required by the server). */
  deletionDays: number;
}

/** A decrypted send for display, including its shareable access URL. */
export interface SendSummary {
  id: string;
  accessId: string;
  type: number;
  name: string;
  text?: string;
  hidden: boolean;
  url: string;
  deletionDate: string;
  expirationDate?: string;
  maxAccessCount?: number;
  accessCount: number;
  disabled: boolean;
  passwordProtected: boolean;
}

export interface SendCryptoDeps {
  randomBytes?: (n: number) => Uint8Array;
  now?: () => number;
}

/** Derive a send's field-encryption key: HKDF-Expand(PRK=sendKey, info="send", 64 bytes). */
export async function deriveSendKey(sendKey: Uint8Array): Promise<SymmetricKey> {
  return symmetricKeyFromBytes(await hkdfExpandSha256(sendKey, 'send', 64));
}

/** Hash a send password (PBKDF2-SHA256 over the password with the send key as salt). */
export async function hashSendPassword(password: string, sendKey: Uint8Array): Promise<string> {
  return bytesToBase64(await pbkdf2Sha256(utf8ToBytes(password), sendKey, SEND_PASSWORD_ITERATIONS, 32));
}

/** Build the recipient access URL: {server}/#/send/{accessId}/{base64url(sendKey)}. */
export function buildSendAccessUrl(serverUrl: string, accessId: string, sendKey: Uint8Array): string {
  return `${serverUrl.replace(/\/$/, '')}/#/send/${accessId}/${bytesToBase64Url(sendKey)}`;
}

/**
 * Build a create-text-send request: generate a send key, derive the field key, encrypt name + text
 * under it, wrap the send key under the user key, and hash the optional password. Returns the request
 * plus the raw send key (for the share URL).
 */
export async function buildTextSendRequest(
  input: SendInput,
  userKey: SymmetricKey,
  deps: SendCryptoDeps = {},
): Promise<{ request: SendRequest; sendKey: Uint8Array }> {
  const randomBytes = deps.randomBytes ?? ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const now = deps.now ?? Date.now;
  const sendKey = randomBytes(16);
  const derived = await deriveSendKey(sendKey);
  const request: SendRequest = {
    type: 0,
    name: await encryptToText(input.name || 'Send', derived),
    key: await encryptToBytes(sendKey, userKey),
    deletionDate: new Date(now() + clampDays(input.deletionDays, 1, 31) * DAY_MS).toISOString(),
    text: { text: await encryptToText(input.text, derived), hidden: input.hidden ?? false },
    disabled: false,
    hideEmail: false,
  };
  if (input.maxAccessCount && input.maxAccessCount > 0) request.maxAccessCount = Math.trunc(input.maxAccessCount);
  if (input.expirationDays && input.expirationDays > 0) {
    request.expirationDate = new Date(now() + input.expirationDays * DAY_MS).toISOString();
  }
  if (input.password) request.password = await hashSendPassword(input.password, sendKey);
  return { request, sendKey };
}

/** Decrypt a send for display: unwrap the send key, derive the field key, decrypt name/text, build URL. */
export async function decryptSend(send: SendResponse, userKey: SymmetricKey, serverUrl: string): Promise<SendSummary> {
  const sendKey = await decryptToBytes(send.key, userKey); // raw 16-byte send key
  const derived = await deriveSendKey(sendKey);
  const out: SendSummary = {
    id: send.id,
    accessId: send.accessId,
    type: send.type,
    name: send.name ? await safeDecrypt(send.name, derived) : '(no name)',
    hidden: Boolean(send.text?.hidden),
    url: buildSendAccessUrl(serverUrl, send.accessId, sendKey),
    deletionDate: send.deletionDate,
    accessCount: send.accessCount ?? 0,
    disabled: Boolean(send.disabled),
    passwordProtected: Boolean(send.password),
  };
  if (send.type === 0 && send.text?.text) out.text = await safeDecrypt(send.text.text, derived);
  if (send.expirationDate) out.expirationDate = send.expirationDate;
  if (send.maxAccessCount != null) out.maxAccessCount = send.maxAccessCount;
  return out;
}

async function safeDecrypt(value: string, key: SymmetricKey): Promise<string> {
  try {
    return await decryptToText(value, key);
  } catch {
    return '(undecryptable)';
  }
}

function clampDays(value: number, min: number, max: number): number {
  const n = Math.trunc(value) || min;
  return Math.max(min, Math.min(max, n));
}
