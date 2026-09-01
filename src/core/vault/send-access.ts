// Recipient-side Send access: parse a share link and decrypt the accessed Send with the URL send key.
// No vault secret is involved — the send key comes from the link, which is public to the recipient — so
// this runs in the receive page (not the service worker). Network functions take an injected fetch.

import { deriveSendKey, hashSendPassword } from './sends.js';
import { decryptToText } from '../crypto/encstring.js';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/encoding.js';
import { decryptAttachmentFile } from './attachments.js';
import type { SymmetricKey } from '../crypto/keys.js';

const API_TIMEOUT_MS = 15_000;
const FILE_TIMEOUT_MS = 120_000;
const MAX_API_RESPONSE_BYTES = 1024 * 1024;
const MAX_SEND_LINK_LENGTH = 8 * 1024;
const MAX_SERVER_URL_LENGTH = 2 * 1024;
const MAX_DOWNLOAD_URL_LENGTH = 16 * 1024;
const MAX_SEND_IDENTIFIER_LENGTH = 1_024;
const MAX_SEND_ACCESS_TOKEN_LENGTH = 16 * 1024;
const MAX_SEND_ACCESS_TOKEN_RESPONSE_BYTES = 64 * 1024;
const MAX_SEND_ACCESS_TOKEN_SECONDS = 24 * 60 * 60;
const MAX_SEND_ACCESS_EMAIL_LENGTH = 254;
const MAX_SEND_ACCESS_OTP_LENGTH = 256;
const MAX_OAUTH_ERROR_DESCRIPTION_LENGTH = 2 * 1024;
const SEND_EMAIL_AUTH_PROOF = Symbol('send-email-auth-proof');
const OFFICIAL_CLOUD_ENDPOINTS = Object.freeze({
  'https://send.bitwarden.com': Object.freeze({
    apiBaseUrl: 'https://api.bitwarden.com/',
    identityBaseUrl: 'https://identity.bitwarden.com/',
    vanityRoute: true,
  }),
  'https://vault.bitwarden.com': Object.freeze({
    apiBaseUrl: 'https://api.bitwarden.com/',
    identityBaseUrl: 'https://identity.bitwarden.com/',
    vanityRoute: false,
  }),
  'https://vault.bitwarden.eu': Object.freeze({
    apiBaseUrl: 'https://api.bitwarden.eu/',
    identityBaseUrl: 'https://identity.bitwarden.eu/',
    vanityRoute: false,
  }),
  'https://send.bitwarden-gov.com': Object.freeze({
    apiBaseUrl: 'https://api.bitwarden-gov.com/',
    identityBaseUrl: 'https://identity.bitwarden-gov.com/',
    vanityRoute: false,
  }),
  'https://vault.bitwarden-gov.com': Object.freeze({
    apiBaseUrl: 'https://api.bitwarden-gov.com/',
    identityBaseUrl: 'https://identity.bitwarden-gov.com/',
    vanityRoute: false,
  }),
} as const);
const OFFICIAL_CLOUD_SHARE_HOSTNAMES = new Set([
  'send.bitwarden.com',
  'vault.bitwarden.com',
  'vault.bitwarden.eu',
  'send.bitwarden-gov.com',
  'vault.bitwarden-gov.com',
]);
// File Sends created by this extension are capped at 100 MiB. AES-CBC padding and the
// EncArrayBuffer header add at most 65 bytes to the encrypted response.
const MAX_FILE_RESPONSE_BYTES = (100 * 1024 * 1024) + 65;

export interface ParsedSendUrl {
  readonly serverUrl: string;
  readonly serverOrigin: string;
  readonly originPattern: string;
  readonly endpoints: SendAccessEndpoints;
  readonly accessId: string;
  readonly sendKey: Uint8Array;
}

export interface SendAccessEndpoints {
  /** Canonical API service base, ending in `/`. */
  readonly apiBaseUrl: string;
  /** Canonical Identity service base, ending in `/`. */
  readonly identityBaseUrl: string;
  /** Base used only to resolve a same-server relative file URL. */
  readonly downloadBaseUrl: string;
  /** Exact origins required before any Send access network request. */
  readonly originPatterns: readonly string[];
  /** Stable in-memory authority binding for a minted Send token. */
  readonly binding: string;
}

export interface AccessedSend {
  /** The send id from the access response — used for the file-download route (NOT the accessId). */
  id: string;
  type: number; // 0 text, 1 file
  name: string;
  text?: string;
  /** Whether a text Send requires an explicit recipient reveal before its plaintext is displayed. */
  hidden?: boolean;
  fileName?: string;
  fileId?: string;
  sizeName?: string;
}

export interface SendRequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export interface SendDownloadOptions extends SendRequestOptions {
  /** The exact cross-origin target approved by the browser host-permission prompt. */
  allowedCrossOrigin?: string;
}

export interface SendDownloadTarget {
  url: string;
  origin: string;
  originPattern: string;
  isCrossOrigin: boolean;
}

/** Exactly one authentication shape is sent to the Send access grant. */
export type SendAccessCredentials =
  | Readonly<{ kind: 'none' }>
  | Readonly<{ kind: 'password'; passwordHashB64: string }>
  | Readonly<{ kind: 'email'; email: string; proof: SendEmailAuthProof }>
  | Readonly<{ kind: 'email_otp'; email: string; otp: string; proof: SendEmailAuthProof }>;

/** Opaque, in-memory evidence that this exact endpoint/access id emitted `email_required`. */
export interface SendEmailAuthProof {
  readonly endpointBinding: string;
  readonly accessId: string;
  readonly [SEND_EMAIL_AUTH_PROOF]: true;
}

const emailAuthProofs = new WeakSet<SendEmailAuthProof>();

export type SendAccessAuthorization =
  | Readonly<{
      kind: 'bearer';
      endpointBinding: string;
      token: string;
      expiresAt: number;
    }>
  | Readonly<{
      kind: 'legacy';
      endpointBinding: string;
      passwordHash?: string;
    }>;

export interface AccessedSendResult {
  kind: 'accessed';
  payload: unknown;
  authorization: SendAccessAuthorization;
}

/** A strictly parsed OAuth challenge. No email is sent before `email_required` is observed. */
export type SendAccessChallenge =
  | Readonly<{ kind: 'email_required'; endpointBinding: string; proof: SendEmailAuthProof }>
  | Readonly<{ kind: 'email_otp_required'; endpointBinding: string; proof: SendEmailAuthProof }>;

export type SendAccessResult = AccessedSendResult | SendAccessChallenge;

export type SendAccessError =
  | 'invalid_link'
  | 'invalid_credentials'
  | 'password_required'
  | 'password_invalid'
  | 'email_auth_unsupported'
  | 'authorization_rejected'
  | 'unavailable'
  | 'decrypt_failed'
  | 'network_failed'
  | 'timeout'
  | 'aborted'
  | 'response_too_large'
  | 'invalid_response'
  | 'server_error'
  | 'unsafe_download';

export function sendAccessError(code: SendAccessError): Error & { code: SendAccessError } {
  return Object.assign(new Error(code), { code });
}

/** Parse `{server}/#/send/{accessId}/{base64url(16-byte sendKey)}`. Throws 'invalid_link' on any defect. */
export function parseSendUrl(link: string): ParsedSendUrl {
  const input = strictInput(link, MAX_SEND_LINK_LENGTH, 'invalid_link', true);
  if (input.includes('\\') || input.includes('?')) throw sendAccessError('invalid_link');

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw sendAccessError('invalid_link');
  }
  if (!isAllowedNetworkUrl(url) || url.username || url.password || url.search || !url.hash) {
    throw sendAccessError('invalid_link');
  }

  const fragmentStart = input.indexOf('#');
  if (fragmentStart < 0) throw sendAccessError('invalid_link');
  const serverBase = parseServerBase(input.slice(0, fragmentStart), 'invalid_link');
  const cloud = serverBase.pathname === '/'
    ? OFFICIAL_CLOUD_ENDPOINTS[serverBase.origin as keyof typeof OFFICIAL_CLOUD_ENDPOINTS]
    : undefined;
  if (
    serverBase.origin === 'https://send.bitwarden.eu'
    || (OFFICIAL_CLOUD_SHARE_HOSTNAMES.has(serverBase.hostname) && cloud === undefined)
  ) {
    throw sendAccessError('invalid_link');
  }
  const route = parseSendFragment(url.hash);
  const segments = route.pathname.split('/');
  const vanityRoute = cloud?.vanityRoute === true
    && segments.length === 3
    && segments[0] === '';
  const standardRoute = segments.length === 4
    && segments[0] === ''
    && segments[1] === 'send';
  if (!vanityRoute && !standardRoute) throw sendAccessError('invalid_link');
  const accessId = strictBase64UrlSegment(segments[vanityRoute ? 1 : 2], 'invalid_link');
  const keyPart = strictBase64UrlSegment(segments[vanityRoute ? 2 : 3], 'invalid_link');

  let sendKey: Uint8Array;
  try { sendKey = base64UrlToBytes(keyPart); } catch { throw sendAccessError('invalid_link'); }
  if (sendKey.length !== 16 || bytesToBase64Url(sendKey) !== keyPart) throw sendAccessError('invalid_link');

  const serverUrl = serializeServerBase(serverBase);
  const endpoints = createSendAccessEndpoints(serverBase, cloud);
  return Object.freeze({
    serverUrl,
    serverOrigin: serverBase.origin,
    originPattern: `${serverBase.origin}/*`,
    endpoints,
    accessId,
    sendKey,
  });
}

function createSendAccessEndpoints(
  serverBase: URL,
  cloud: (typeof OFFICIAL_CLOUD_ENDPOINTS)[keyof typeof OFFICIAL_CLOUD_ENDPOINTS] | undefined,
): SendAccessEndpoints {
  const apiBaseUrl = cloud?.apiBaseUrl ?? new URL('api/', serverBase).toString();
  const identityBaseUrl = cloud?.identityBaseUrl ?? new URL('identity/', serverBase).toString();
  const downloadBaseUrl = cloud ? new URL(apiBaseUrl).origin : serializeServerBase(serverBase);
  const originPatterns = Object.freeze([...new Set([
    `${new URL(apiBaseUrl).origin}/*`,
    `${new URL(identityBaseUrl).origin}/*`,
  ])]);
  return Object.freeze({
    apiBaseUrl,
    identityBaseUrl,
    downloadBaseUrl,
    originPatterns,
    binding: JSON.stringify([apiBaseUrl, identityBaseUrl]),
  });
}

/** The password hash a Send expects, from a plaintext password + the URL send key (PBKDF2, reused). */
export async function sendPasswordHash(password: string, sendKey: Uint8Array): Promise<string> {
  return hashSendPassword(password, sendKey);
}

/** Decrypt the accessed Send's name + text (type 0) or file name (type 1) with the URL send key. */
export async function decryptAccessedSend(raw: unknown, sendKey: Uint8Array): Promise<AccessedSend> {
  if (!isRecord(raw)
    || typeof raw.id !== 'string' || !raw.id
    || (raw.type !== 0 && raw.type !== 1)
    || typeof raw.name !== 'string') {
    throw sendAccessError('invalid_response');
  }

  let text: string | undefined;
  let hidden: boolean | undefined;
  let fileName: string | undefined;
  let fileId: string | undefined;
  let sizeName: string | undefined;
  if (raw.type === 0) {
    if (!isRecord(raw.text)
      || typeof raw.text.text !== 'string'
      || (raw.text.hidden !== undefined && typeof raw.text.hidden !== 'boolean')) {
      throw sendAccessError('invalid_response');
    }
    text = raw.text.text;
    hidden = raw.text.hidden ?? false;
  } else {
    if (!isRecord(raw.file)
      || typeof raw.file.fileName !== 'string'
      || typeof raw.file.id !== 'string' || !raw.file.id
      || (raw.file.sizeName !== undefined && typeof raw.file.sizeName !== 'string')) {
      throw sendAccessError('invalid_response');
    }
    fileName = raw.file.fileName;
    fileId = raw.file.id;
    sizeName = raw.file.sizeName;
  }

  const derived = await deriveSendKey(sendKey);
  const out: AccessedSend = {
    id: raw.id,
    type: raw.type,
    name: await safeDecrypt(raw.name, derived),
  };
  if (text !== undefined) out.text = await safeDecrypt(text, derived);
  if (hidden !== undefined) out.hidden = hidden;
  if (fileName !== undefined) out.fileName = await safeDecrypt(fileName, derived);
  if (fileId !== undefined) out.fileId = fileId;
  if (sizeName !== undefined) out.sizeName = sizeName;
  return out;
}

async function safeDecrypt(value: string, key: SymmetricKey): Promise<string> {
  try { return await decryptToText(value, key); } catch { return '(undecryptable)'; }
}

/**
 * Exchange the link's access id for a Send-scoped bearer token, then fetch the encrypted Send.
 * Servers that explicitly do not support the modern grant use the legacy anonymous endpoint.
 */
export async function accessSend(
  fetchFn: typeof fetch,
  endpoints: SendAccessEndpoints,
  accessId: string,
  credentials: SendAccessCredentials,
  options: SendRequestOptions = {},
): Promise<SendAccessResult> {
  const checkedEndpoints = validateSendAccessEndpoints(endpoints);
  const grant = await requestSendAccessGrant(fetchFn, checkedEndpoints, accessId, credentials, options);
  if (grant.kind === 'email_required' || grant.kind === 'email_otp_required') return grant;
  if (grant.kind === 'legacy') {
    const payload = await accessLegacySend(
      fetchFn,
      checkedEndpoints,
      accessId,
      grant.passwordHash,
      options,
    );
    return Object.freeze({ kind: 'accessed', payload, authorization: grant });
  }

  const result = await boundedRequest(
    fetchFn,
    new URL('sends/access', checkedEndpoints.apiBaseUrl).toString(),
    {
      method: 'POST',
      headers: { authorization: `Bearer ${grant.token}` },
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    },
    options,
    API_TIMEOUT_MS,
    MAX_API_RESPONSE_BYTES,
  );
  throwForBearerHttpStatus(result.response);
  return Object.freeze({ kind: 'accessed', payload: parseJsonBody(result.body), authorization: grant });
}

/** Resolve a file URL through the modern Send-scoped grant, with an explicit legacy fallback. */
export async function requestFileDownloadUrl(
  fetchFn: typeof fetch,
  endpoints: SendAccessEndpoints,
  sendId: string,
  fileId: string,
  authorization: SendAccessAuthorization,
  options: SendRequestOptions = {},
): Promise<string> {
  const checkedEndpoints = validateSendAccessEndpoints(endpoints);
  if (authorization.endpointBinding !== checkedEndpoints.binding) throw sendAccessError('invalid_link');
  if (authorization.kind === 'legacy') {
    return requestLegacyFileDownloadUrl(
      fetchFn,
      checkedEndpoints,
      sendId,
      fileId,
      authorization.passwordHash,
      options,
    );
  }
  if (authorization.expiresAt <= Date.now() + 5_000) throw sendAccessError('authorization_rejected');

  const result = await boundedRequest(
    fetchFn,
    new URL(`sends/access/file/${encodeURIComponent(fileId)}`, checkedEndpoints.apiBaseUrl).toString(),
    {
      method: 'POST',
      headers: { authorization: `Bearer ${authorization.token}` },
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    },
    options,
    API_TIMEOUT_MS,
    MAX_SEND_ACCESS_TOKEN_RESPONSE_BYTES,
  );
  throwForBearerHttpStatus(result.response);
  const json = parseJsonBody(result.body);
  if (
    !isRecord(json)
    || typeof json.url !== 'string'
    || !json.url.trim()
    || (json.id !== undefined && json.id !== fileId)
  ) {
    throw sendAccessError('invalid_response');
  }
  return json.url;
}

async function requestSendAccessGrant(
  fetchFn: typeof fetch,
  endpoints: SendAccessEndpoints,
  accessId: string,
  credentials: SendAccessCredentials,
  options: SendRequestOptions,
): Promise<SendAccessAuthorization | SendAccessChallenge> {
  const validatedAccessId = strictBase64UrlSegment(accessId, 'invalid_link');
  if (
    credentials.kind !== 'none'
    && (!allowsSensitiveCredentialTransport(endpoints.identityBaseUrl)
      || !allowsSensitiveCredentialTransport(endpoints.apiBaseUrl))
  ) {
    throw sendAccessError(credentials.kind === 'password' ? 'invalid_credentials' : 'email_auth_unsupported');
  }
  const form = new URLSearchParams({
    grant_type: 'send_access',
    client_id: 'send',
    scope: 'api.send.access',
    send_id: validatedAccessId,
  });
  switch (credentials.kind) {
    case 'none':
      break;
    case 'password':
      form.set('password_hash_b64', strictInput(credentials.passwordHashB64, 1_024, 'invalid_credentials', false));
      break;
    case 'email':
      validateEmailAuthProof(credentials.proof, endpoints.binding, validatedAccessId);
      form.set('email', normalizeSendAccessEmail(credentials.email));
      break;
    case 'email_otp':
      validateEmailAuthProof(credentials.proof, endpoints.binding, validatedAccessId);
      form.set('email', normalizeSendAccessEmail(credentials.email));
      form.set('otp', normalizeSendAccessOtp(credentials.otp));
      break;
  }

  const result = await boundedRequest(
    fetchFn,
    new URL('connect/token', endpoints.identityBaseUrl).toString(),
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'cache-control': 'no-store',
        'content-type': 'application/x-www-form-urlencoded',
        pragma: 'no-cache',
      },
      body: form.toString(),
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    },
    options,
    API_TIMEOUT_MS,
    Math.min(positiveLimit(options.maxResponseBytes, MAX_SEND_ACCESS_TOKEN_RESPONSE_BYTES), MAX_SEND_ACCESS_TOKEN_RESPONSE_BYTES),
  );

  let body: unknown = undefined;
  try {
    if (result.body.byteLength > 0) body = parseJsonBody(result.body);
  } finally {
    result.body.fill(0);
  }

  if (!result.response.ok) {
    return classifySendGrantFailure(result.response.status, body, endpoints, validatedAccessId, credentials);
  }
  if (credentials.kind === 'email') throw sendAccessError('email_auth_unsupported');
  if (
    !isRecord(body)
    || typeof body.access_token !== 'string'
    || typeof body.token_type !== 'string'
    || body.token_type.toLowerCase() !== 'bearer'
    || typeof body.scope !== 'string'
    || !body.scope.split(/\s+/u).includes('api.send.access')
    || typeof body.expires_in !== 'number'
    || !Number.isSafeInteger(body.expires_in)
    || body.expires_in <= 0
    || body.expires_in > MAX_SEND_ACCESS_TOKEN_SECONDS
  ) {
    throw sendAccessError('invalid_response');
  }
  if (credentials.kind === 'email_otp') emailAuthProofs.delete(credentials.proof);
  return Object.freeze({
    kind: 'bearer',
    endpointBinding: endpoints.binding,
    token: strictInput(body.access_token, MAX_SEND_ACCESS_TOKEN_LENGTH, 'invalid_response', false),
    expiresAt: Date.now() + body.expires_in * 1_000,
  });
}

function classifySendGrantFailure(
  status: number,
  body: unknown,
  endpoints: SendAccessEndpoints,
  accessId: string,
  credentials: SendAccessCredentials,
): SendAccessAuthorization | SendAccessChallenge {
  if (!isRecord(body)) throw sendAccessError('server_error');

  const emailChallenge = classifyExactEmailChallenge(status, body, endpoints, accessId, credentials);
  if (emailChallenge) return emailChallenge;
  if (looksLikeEmailChallenge(body)) throw sendAccessError('email_auth_unsupported');

  const oauthError = typeof body.error === 'string' ? body.error : undefined;
  const legacyInvalidType = status === 400
    && body.object === 'error'
    && body.message === 'Invalid type'
    && body.error === ''
    && body.error_description === '';
  if (status === 400 && (oauthError === 'unsupported_grant_type' || legacyInvalidType)) {
    if (credentials.kind === 'email' || credentials.kind === 'email_otp') {
      throw sendAccessError('email_auth_unsupported');
    }
    return Object.freeze({
      kind: 'legacy',
      endpointBinding: endpoints.binding,
      ...(credentials.kind === 'password' ? { passwordHash: credentials.passwordHashB64 } : {}),
    });
  }

  const accessError = typeof body.send_access_error_type === 'string'
    ? body.send_access_error_type
    : undefined;
  if (accessError === 'password_hash_b64_required') throw sendAccessError('password_required');
  if (accessError === 'password_hash_b64_invalid') throw sendAccessError('password_invalid');
  if (accessError === 'send_id_invalid') throw sendAccessError('unavailable');
  throw sendAccessError('server_error');
}

function classifyExactEmailChallenge(
  status: number,
  body: Record<string, unknown>,
  endpoints: SendAccessEndpoints,
  accessId: string,
  credentials: SendAccessCredentials,
): SendAccessChallenge | undefined {
  if (status !== 400 || body.error !== 'invalid_request') return undefined;

  if (
    body.send_access_error_type === 'email_required'
    && validOAuthErrorDescription(body.error_description)
  ) {
    if (credentials.kind !== 'none' || !allowsSensitiveCredentialTransport(endpoints.identityBaseUrl)) {
      throw sendAccessError('email_auth_unsupported');
    }
    const proof = createEmailAuthProof(endpoints.binding, accessId);
    return Object.freeze({ kind: 'email_required', endpointBinding: endpoints.binding, proof });
  }

  if (
    body.send_access_error_type === 'email_and_otp_required'
    && validOAuthErrorDescription(body.error_description)
  ) {
    if (
      (credentials.kind !== 'email' && credentials.kind !== 'email_otp')
      || !allowsSensitiveCredentialTransport(endpoints.identityBaseUrl)
    ) {
      throw sendAccessError('email_auth_unsupported');
    }
    return Object.freeze({
      kind: 'email_otp_required',
      endpointBinding: endpoints.binding,
      proof: credentials.proof,
    });
  }
  return undefined;
}

function looksLikeEmailChallenge(body: Record<string, unknown>): boolean {
  return body.send_access_error_type === 'email_required'
    || body.send_access_error_type === 'email_and_otp_required';
}

function validOAuthErrorDescription(value: unknown): boolean {
  if (value === undefined) return true;
  if (typeof value !== 'string' || value.length > MAX_OAUTH_ERROR_DESCRIPTION_LENGTH) return false;
  for (const char of value) {
    const code = char.charCodeAt(0);
    const oauthText = (code >= 0x20 && code <= 0x21)
      || (code >= 0x23 && code <= 0x5b)
      || (code >= 0x5d && code <= 0x7e);
    if (!oauthText) return false;
  }
  return true;
}

function createEmailAuthProof(endpointBinding: string, accessId: string): SendEmailAuthProof {
  const proof: SendEmailAuthProof = Object.freeze({
    endpointBinding,
    accessId,
    [SEND_EMAIL_AUTH_PROOF]: true as const,
  });
  emailAuthProofs.add(proof);
  return proof;
}

function validateEmailAuthProof(proof: SendEmailAuthProof, endpointBinding: string, accessId: string): void {
  if (
    !isRecord(proof)
    || !emailAuthProofs.has(proof)
    || proof.endpointBinding !== endpointBinding
    || proof.accessId !== accessId
    || proof[SEND_EMAIL_AUTH_PROOF] !== true
  ) {
    throw sendAccessError('email_auth_unsupported');
  }
}

/** Normalize the recipient identifier exactly once before it reaches the OAuth form. */
export function normalizeSendAccessEmail(value: string): string {
  const email = value.trim().toLowerCase();
  const at = email.indexOf('@');
  if (
    !email
    || email.length > MAX_SEND_ACCESS_EMAIL_LENGTH
    || email.includes(' ')
    || at <= 0
    || at === email.length - 1
    || at !== email.lastIndexOf('@')
  ) {
    throw sendAccessError('invalid_credentials');
  }
  for (const char of email) {
    const code = char.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) throw sendAccessError('invalid_credentials');
  }
  return email;
}

export function normalizeSendAccessOtp(value: string): string {
  const otp = value.trim();
  if (!otp || otp.length > MAX_SEND_ACCESS_OTP_LENGTH) {
    throw sendAccessError('invalid_credentials');
  }
  for (const char of otp) {
    const code = char.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) throw sendAccessError('invalid_credentials');
  }
  return otp;
}

async function accessLegacySend(
  fetchFn: typeof fetch,
  endpoints: SendAccessEndpoints,
  accessId: string,
  passwordHash: string | undefined,
  options: SendRequestOptions,
): Promise<unknown> {
  if (passwordHash !== undefined && !allowsSensitiveCredentialTransport(endpoints.apiBaseUrl)) {
    throw sendAccessError('invalid_credentials');
  }
  const result = await boundedRequest(
    fetchFn,
    new URL(`sends/access/${encodeURIComponent(accessId)}`, endpoints.apiBaseUrl).toString(),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(passwordHash ? { password: passwordHash } : {}),
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    },
    options,
    API_TIMEOUT_MS,
    MAX_API_RESPONSE_BYTES,
  );
  throwForLegacyHttpStatus(result.response, result.body);
  return parseJsonBody(result.body);
}

async function requestLegacyFileDownloadUrl(
  fetchFn: typeof fetch,
  endpoints: SendAccessEndpoints,
  sendId: string,
  fileId: string,
  passwordHash: string | undefined,
  options: SendRequestOptions,
): Promise<string> {
  if (passwordHash !== undefined && !allowsSensitiveCredentialTransport(endpoints.apiBaseUrl)) {
    throw sendAccessError('invalid_credentials');
  }
  const result = await boundedRequest(
    fetchFn,
    new URL(
      `sends/${encodeURIComponent(sendId)}/access/file/${encodeURIComponent(fileId)}`,
      endpoints.apiBaseUrl,
    ).toString(),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(passwordHash ? { password: passwordHash } : {}),
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    },
    options,
    API_TIMEOUT_MS,
    MAX_API_RESPONSE_BYTES,
  );
  throwForLegacyHttpStatus(result.response, result.body);
  const json = parseJsonBody(result.body);
  if (
    !isRecord(json)
    || typeof json.url !== 'string'
    || !json.url.trim()
    || (json.id !== undefined && json.id !== fileId)
  ) {
    throw sendAccessError('invalid_response');
  }
  return json.url;
}

/** Resolve and validate a server-supplied file URL before requesting any additional host permission. */
export function resolveSendDownloadTarget(downloadUrl: string, serverUrl: string): SendDownloadTarget {
  const base = parseServerBase(serverUrl, 'unsafe_download');
  const input = strictInput(downloadUrl, MAX_DOWNLOAD_URL_LENGTH, 'unsafe_download', false);
  if (
    input.includes('\\')
    || input.includes('#')
    || input.startsWith('//')
    || hasMalformedAbsolutePrefix(input)
  ) {
    throw sendAccessError('unsafe_download');
  }
  let target: URL;
  try {
    // Treat both path-relative forms as relative to the configured server base. Vaultwarden
    // deployments behind a reverse-proxy prefix commonly return `/sends/...`; resolving that form
    // against URL.origin would silently discard the deployment prefix.
    const baseRelativeInput = input.startsWith('/') ? input.slice(1) : input;
    target = new URL(baseRelativeInput, base);
  } catch {
    throw sendAccessError('unsafe_download');
  }
  if (
    !isAllowedNetworkUrl(target)
    || (base.protocol === 'https:' && target.protocol !== 'https:')
    || target.username
    || target.password
    || target.hash
    || hasAuthorityUserInfo(input)
  ) {
    throw sendAccessError('unsafe_download');
  }
  const isCrossOrigin = target.origin !== base.origin;
  if (
    !isCrossOrigin
    && (!isWithinServerBasePath(target, base) || hasUnsafePathname(target.pathname))
  ) {
    throw sendAccessError('unsafe_download');
  }
  return {
    url: target.toString(),
    origin: target.origin,
    originPattern: `${target.origin}/*`,
    isCrossOrigin,
  };
}

/** GET a validated download URL with no ambient credentials or redirects, then decrypt it. */
export async function downloadAndDecryptFile(
  fetchFn: typeof fetch,
  downloadUrl: string,
  serverUrl: string,
  sendKey: Uint8Array,
  options: SendDownloadOptions = {},
): Promise<Uint8Array> {
  const target = resolveSendDownloadTarget(downloadUrl, serverUrl);
  if (target.isCrossOrigin && options.allowedCrossOrigin !== target.origin) {
    throw sendAccessError('unsafe_download');
  }
  const result = await boundedRequest(
    fetchFn,
    target.url,
    {
      method: 'GET',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    },
    options,
    FILE_TIMEOUT_MS,
    MAX_FILE_RESPONSE_BYTES,
    'unsafe_download',
  );
  throwForHttpStatus(result.response, false);
  try {
    return await decryptAttachmentFile(result.body, await deriveSendKey(sendKey));
  } catch {
    throw sendAccessError('decrypt_failed');
  }
}

interface BoundedResponse {
  response: Response;
  body: Uint8Array;
}

async function boundedRequest(
  fetchFn: typeof fetch,
  url: string,
  init: RequestInit,
  options: SendRequestOptions,
  defaultTimeoutMs: number,
  defaultMaxResponseBytes: number,
  finalUrlError: SendAccessError = 'server_error',
): Promise<BoundedResponse> {
  if (options.signal?.aborted) throw sendAccessError('aborted');

  const timeoutMs = positiveLimit(options.timeoutMs, defaultTimeoutMs);
  const maxResponseBytes = positiveLimit(options.maxResponseBytes, defaultMaxResponseBytes);
  const controller = new AbortController();
  let stoppedAs: 'timeout' | 'aborted' | undefined;
  let rejectStopped!: (error: Error) => void;
  const stopped = new Promise<never>((_resolve, reject) => { rejectStopped = reject; });
  const stop = (reason: 'timeout' | 'aborted') => {
    if (stoppedAs !== undefined) return;
    stoppedAs = reason;
    controller.abort(options.signal?.reason);
    rejectStopped(sendAccessError(reason));
  };
  const abortFromCaller = () => stop('aborted');
  options.signal?.addEventListener('abort', abortFromCaller, { once: true });
  const timer = setTimeout(() => stop('timeout'), timeoutMs);

  try {
    const response = await Promise.race([
      fetchFn(url, {
        ...init,
        credentials: 'omit',
        redirect: 'error',
        signal: controller.signal,
      }),
      stopped,
    ]);
    validateFinalResponseTarget(response, url, finalUrlError);
    const body = await readBoundedBody(response, maxResponseBytes, stopped);
    return { response, body };
  } catch (error) {
    if (isTaggedSendAccessError(error)) throw error;
    if (stoppedAs !== undefined) throw sendAccessError(stoppedAs);
    throw sendAccessError('network_failed');
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', abortFromCaller);
  }
}

async function readBoundedBody(
  response: Response,
  maxBytes: number,
  stopped: Promise<never>,
): Promise<Uint8Array> {
  const rawLength = response.headers.get('content-length');
  if (rawLength !== null) {
    const declaredLength = Number(rawLength);
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      if (response.body) void response.body.cancel().catch(() => undefined);
      throw sendAccessError('response_too_large');
    }
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), stopped]);
      if (done) break;
      if (!value) continue;
      length += value.byteLength;
      if (length > maxBytes) {
        throw sendAccessError('response_too_large');
      }
      chunks.push(value);
    }

    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return body;
  } catch (error) {
    if (response.body) {
      void reader.cancel().catch(() => undefined);
    }
    throw error;
  }
}

function validateSendAccessEndpoints(endpoints: SendAccessEndpoints): SendAccessEndpoints {
  if (!isRecord(endpoints)) throw sendAccessError('invalid_link');
  const apiBaseUrl = parseServerBase(endpoints.apiBaseUrl, 'invalid_link').toString();
  const identityBaseUrl = parseServerBase(endpoints.identityBaseUrl, 'invalid_link').toString();
  const downloadBaseUrl = serializeServerBase(parseServerBase(endpoints.downloadBaseUrl, 'invalid_link'));
  const originPatterns = [...new Set([
    `${new URL(apiBaseUrl).origin}/*`,
    `${new URL(identityBaseUrl).origin}/*`,
  ])];
  const binding = JSON.stringify([apiBaseUrl, identityBaseUrl]);
  if (
    endpoints.apiBaseUrl !== apiBaseUrl
    || endpoints.identityBaseUrl !== identityBaseUrl
    || endpoints.downloadBaseUrl !== downloadBaseUrl
    || endpoints.binding !== binding
    || !Array.isArray(endpoints.originPatterns)
    || endpoints.originPatterns.length !== originPatterns.length
    || endpoints.originPatterns.some((value, index) => value !== originPatterns[index])
  ) {
    throw sendAccessError('invalid_link');
  }
  return endpoints;
}

function allowsSensitiveCredentialTransport(identityBaseUrl: string): boolean {
  const target = new URL(identityBaseUrl);
  return target.protocol === 'https:' || isLoopbackHostname(target.hostname);
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost') || normalized === '[::1]') {
    return true;
  }
  const octets = normalized.split('.');
  return octets.length === 4 && octets[0] === '127' && octets.every((octet) => /^\d{1,3}$/u.test(octet));
}

function parseServerBase(serverUrl: string, errorCode: SendAccessError): URL {
  const input = strictInput(serverUrl, MAX_SERVER_URL_LENGTH, errorCode, false);
  if (input.includes('\\') || input.includes('?') || input.includes('#')) {
    throw sendAccessError(errorCode);
  }
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw sendAccessError(errorCode);
  }
  if (
    !isAllowedNetworkUrl(url)
    || !hasExplicitHttpAuthority(input)
    || url.username
    || url.password
    || url.origin === 'null'
    || url.search
    || url.hash
    || hasAuthorityUserInfo(input)
    || hasUnsafeBasePath(input)
  ) {
    throw sendAccessError(errorCode);
  }
  url.pathname = `${url.pathname.replace(/\/+$/u, '')}/`;
  return url;
}

function parseSendFragment(hash: string): URL {
  try {
    const route = new URL(hash.slice(1), 'https://send-route.invalid/');
    if (
      route.origin !== 'https://send-route.invalid'
      || route.search
      || route.hash
      || route.username
      || route.password
    ) {
      throw new Error('invalid route');
    }
    return route;
  } catch {
    throw sendAccessError('invalid_link');
  }
}

function strictBase64UrlSegment(value: string | undefined, errorCode: SendAccessError): string {
  if (
    value === undefined
    || value.length === 0
    || value.length > MAX_SEND_IDENTIFIER_LENGTH
    || value.includes('%')
    || !allBase64UrlCharacters(value)
  ) {
    throw sendAccessError(errorCode);
  }
  return value;
}

function allBase64UrlCharacters(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0);
    const alpha = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
    const digit = code >= 48 && code <= 57;
    if (!alpha && !digit && char !== '_' && char !== '-') return false;
  }
  return true;
}

function strictInput(
  value: string,
  maxLength: number,
  errorCode: SendAccessError,
  trimOuterWhitespace: boolean,
): string {
  const input = trimOuterWhitespace ? value.trim() : value;
  if (!input || input.length > maxLength || (!trimOuterWhitespace && input !== input.trim())) {
    throw sendAccessError(errorCode);
  }
  for (const char of input) {
    const code = char.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) throw sendAccessError(errorCode);
  }
  return input;
}

function hasUnsafeBasePath(input: string): boolean {
  const schemeEnd = input.indexOf('://');
  if (schemeEnd < 0) return true;
  const pathStart = input.indexOf('/', schemeEnd + 3);
  if (pathStart < 0) return false;
  for (const rawSegment of input.slice(pathStart).split('/')) {
    let segment: string;
    try {
      segment = decodeURIComponent(rawSegment);
    } catch {
      return true;
    }
    if (segment === '.' || segment === '..') return true;
    for (const char of segment) {
      const code = char.charCodeAt(0);
      if (char === '/' || char === '\\' || code === 0 || code === 10 || code === 13) return true;
    }
  }
  return false;
}

function hasUnsafePathname(pathname: string): boolean {
  for (const rawSegment of pathname.split('/')) {
    let segment: string;
    try {
      segment = decodeURIComponent(rawSegment);
    } catch {
      return true;
    }
    if (segment === '.' || segment === '..') return true;
    for (const char of segment) {
      const code = char.charCodeAt(0);
      if (char === '/' || char === '\\' || code === 0 || code === 10 || code === 13) return true;
    }
  }
  return false;
}

function hasMalformedAbsolutePrefix(input: string): boolean {
  const lower = input.toLowerCase();
  if (lower.startsWith('https://') || lower.startsWith('http://')) {
    return !hasExplicitHttpAuthority(input);
  }
  const colon = input.indexOf(':');
  if (colon < 0) return false;
  const slash = input.indexOf('/');
  const query = input.indexOf('?');
  const boundaries = [slash, query].filter((index) => index >= 0);
  const firstBoundary = boundaries.length === 0 ? input.length : Math.min(...boundaries);
  if (colon >= firstBoundary) return false;
  return true;
}

function hasExplicitHttpAuthority(input: string): boolean {
  const lower = input.toLowerCase();
  const prefixLength = lower.startsWith('https://') ? 8 : lower.startsWith('http://') ? 7 : 0;
  if (prefixLength === 0 || prefixLength >= input.length) return false;
  const first = input[prefixLength];
  return first !== '/' && first !== '?' && first !== '#';
}

function hasAuthorityUserInfo(input: string): boolean {
  const schemeEnd = input.indexOf('://');
  if (schemeEnd < 0) return false;
  const authorityStart = schemeEnd + 3;
  const pathStart = input.indexOf('/', authorityStart);
  const queryStart = input.indexOf('?', authorityStart);
  const fragmentStart = input.indexOf('#', authorityStart);
  const candidates = [pathStart, queryStart, fragmentStart].filter((index) => index >= 0);
  const authorityEnd = candidates.length === 0 ? input.length : Math.min(...candidates);
  return input.slice(authorityStart, authorityEnd).includes('@');
}

function isWithinServerBasePath(target: URL, base: URL): boolean {
  if (target.origin !== base.origin) return false;
  return base.pathname === '/'
    || target.pathname === base.pathname.slice(0, -1)
    || target.pathname.startsWith(base.pathname);
}

function serializeServerBase(base: URL): string {
  return base.pathname === '/'
    ? base.origin
    : `${base.origin}${base.pathname.replace(/\/+$/u, '')}`;
}

function validateFinalResponseTarget(response: Response, expectedUrl: string, errorCode: SendAccessError): void {
  if (response.redirected || response.type === 'opaqueredirect') throw sendAccessError(errorCode);
  if (!response.url) return;
  try {
    if (new URL(response.url).toString() !== new URL(expectedUrl).toString()) {
      throw sendAccessError(errorCode);
    }
  } catch (error) {
    if (isTaggedSendAccessError(error)) throw error;
    throw sendAccessError(errorCode);
  }
}

function throwForHttpStatus(response: Response, passwordPrompt: boolean): void {
  if (response.ok) return;
  if (passwordPrompt && response.status === 401) throw sendAccessError('password_required');
  if (response.status === 404 || response.status === 410) throw sendAccessError('unavailable');
  throw sendAccessError('server_error');
}

function throwForBearerHttpStatus(response: Response): void {
  if (response.ok) return;
  if (response.status === 401) throw sendAccessError('authorization_rejected');
  if (response.status === 404 || response.status === 410) throw sendAccessError('unavailable');
  throw sendAccessError('server_error');
}

function throwForLegacyHttpStatus(response: Response, body: Uint8Array): void {
  if (response.ok) return;
  if (response.status === 401) throw sendAccessError('password_required');
  if (response.status === 404 || response.status === 410) throw sendAccessError('unavailable');
  if (response.status === 400) {
    const message = readLegacyErrorMessage(body);
    if (message === 'Invalid password' || message === 'Invalid password.') {
      throw sendAccessError('password_invalid');
    }
    if (message === 'Could not locate send' || message === 'Could not locate send.') {
      throw sendAccessError('unavailable');
    }
  }
  throw sendAccessError('server_error');
}

function readLegacyErrorMessage(body: Uint8Array): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body)) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  const message = parsed.message ?? parsed.Message;
  return typeof message === 'string' ? message : undefined;
}

function parseJsonBody(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(body)) as unknown;
  } catch {
    throw sendAccessError('invalid_response');
  }
}

function positiveLimit(value: number | undefined, fallback: number): number {
  return value !== undefined && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function isHttpProtocol(protocol: string): boolean {
  return protocol === 'https:' || protocol === 'http:';
}

function isAllowedNetworkUrl(url: URL): boolean {
  return isHttpProtocol(url.protocol);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isTaggedSendAccessError(error: unknown): error is Error & { code: SendAccessError } {
  if (!(error instanceof Error) || !('code' in error) || typeof error.code !== 'string') return false;
  switch (error.code) {
    case 'invalid_link':
    case 'invalid_credentials':
    case 'password_required':
    case 'password_invalid':
    case 'email_auth_unsupported':
    case 'authorization_rejected':
    case 'unavailable':
    case 'decrypt_failed':
    case 'network_failed':
    case 'timeout':
    case 'aborted':
    case 'response_too_large':
    case 'invalid_response':
    case 'server_error':
    case 'unsafe_download':
      return true;
    default:
      return false;
  }
}

