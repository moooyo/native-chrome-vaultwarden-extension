import type { CardCipherData, CipherFieldData, CipherRequest, CipherResponse, IdentityCipherData, LoginCipherData, SshKeyCipherRequestData } from '../api/types.js';
import { encryptToText } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { CARD_FIELDS, IDENTITY_FIELDS } from './models.js';
import type { CipherInput, DecryptedField, WritableCipherInput } from './models.js';
import {
  assertSshCipherPayloadExclusivity,
  parseCompleteDecryptedSshKey,
  parseCompleteSshKeyCipherData,
} from './ssh-key.js';
import { computeLoginUriChecksum } from './login-uri-checksum.js';
import { isOptionalNullableIsoTimestamp } from './iso-date.js';

/**
 * Encrypt a plaintext cipher form into a write request. Every field is encrypted under the given
 * key (the account UserKey for personal ciphers) as an encType=2 EncString; empty fields are omitted.
 */
export async function encryptCipher(
  input: WritableCipherInput,
  key: SymmetricKey,
): Promise<CipherRequest> {
  const sshKey = input.type === 5 ? parseCompleteDecryptedSshKey(input.sshKey) : undefined;
  if (input.type === 5) assertSshCipherPayloadExclusivity(input);
  else if (input.sshKey !== undefined) throw new TypeError('Only SSH ciphers may contain sshKey data');

  const req: CipherRequest = {
    type: input.type,
    name: await encryptToText(input.name, key),
    favorite: input.favorite ?? false,
    folderId: input.folderId ?? null,
    reprompt: input.reprompt ? 1 : 0,
  };
  if (input.notes) req.notes = await encryptToText(input.notes, key);

  if (input.type === 1) {
    req.login = await encryptLogin(input.login ?? {}, key);
  } else if (input.type === 2) {
    req.secureNote = { type: 0 };
  } else if (input.type === 3) {
    req.card = (await encryptFields(input.card ?? {}, CARD_FIELDS, key)) as CardCipherData;
  } else if (input.type === 4) {
    req.identity = (await encryptFields(input.identity ?? {}, IDENTITY_FIELDS, key)) as IdentityCipherData;
  } else if (input.type === 5) {
    req.sshKey = await encryptSshKey(sshKey!, key);
  }
  // Present (even empty) means the editor owns custom fields: an empty array explicitly clears them.
  if (input.fields) req.fields = await encryptCustomFields(input.fields, key);
  return req;
}

async function encryptSshKey(
  sshKey: ReturnType<typeof parseCompleteDecryptedSshKey>,
  key: SymmetricKey,
): Promise<SshKeyCipherRequestData> {
  return parseCompleteSshKeyCipherData({
    privateKey: await encryptToText(sshKey.privateKey, key),
    publicKey: await encryptToText(sshKey.publicKey, key),
    keyFingerprint: await encryptToText(sshKey.keyFingerprint, key),
  });
}

/** Encrypt custom fields back into a request. Linked (type 3) fields carry only linkedId (no value);
 *  Text/Hidden/Boolean carry an encrypted value (Boolean stored as 'true'/'false'). */
async function encryptCustomFields(fields: DecryptedField[], key: SymmetricKey): Promise<CipherFieldData[]> {
  const out: CipherFieldData[] = [];
  for (const f of fields) {
    assertWritableCustomField(f);
    const field: CipherFieldData = { type: f.type, name: f.name ? await encryptToText(f.name, key) : null };
    if (f.type === 3) {
      field.value = null;
      field.linkedId = f.linkedId ?? null;
    } else {
      field.value = f.value != null && f.value !== '' ? await encryptToText(f.value, key) : null;
    }
    out.push(field);
  }
  return out;
}

/**
 * Carry forward the fields the editor does not model from the original (cached) cipher onto a freshly
 * encrypted update request, so a wholesale PUT does not silently wipe them server-side. Everything copied
 * is already an EncString (or an opaque flag), so no user key is needed. No-op on the create path.
 */
export function mergeServerManagedFields(request: CipherRequest, original: CipherResponse | undefined): CipherRequest {
  if (!original) return request;
  if (original.key != null) request.key = original.key;
  if (original.passwordHistory != null) request.passwordHistory = original.passwordHistory;
  // ArchivedDate is writable per-user state in the official request model. Omitting it from an
  // archived whole-cipher PUT unarchives the item on servers that deserialize absence as null.
  if (original.archivedDate != null) request.archivedDate = original.archivedDate;
  // NOTE: `fields` and `reprompt` are intentionally NOT carried forward here — the editor now models
  // them explicitly (encryptCipher writes them from the input), so the user can edit custom fields and
  // toggle the master-password reprompt flag. The editor round-trips Linked fields it cannot edit.
  // Login sub-fields the editor cannot represent (a stored passkey, the password-revision timestamp)
  // must ride along, or the wholesale PUT drops them. Only touch login on login ciphers.
  if (request.type === 1) {
    const carried: Partial<LoginCipherData> = {};
    if (original.login?.fido2Credentials != null) carried.fido2Credentials = original.login.fido2Credentials;
    if (!hasOwn(request.login, 'autofillOnPageLoad') && hasOwn(original.login, 'autofillOnPageLoad')) {
      const value = original.login!.autofillOnPageLoad;
      if (value !== undefined) carried.autofillOnPageLoad = value;
    }
    if (!hasOwn(request.login, 'passwordRevisionDate') && hasOwn(original.login, 'passwordRevisionDate')) {
      const value = original.login!.passwordRevisionDate;
      if (value !== undefined) carried.passwordRevisionDate = value;
    }
    if (Object.keys(carried).length) request.login = { ...(request.login ?? {}), ...carried };
  }
  return request;
}

async function encryptLogin(login: NonNullable<CipherInput['login']>, key: SymmetricKey): Promise<LoginCipherData> {
  const out: LoginCipherData = {};
  if (login.username) out.username = await encryptToText(login.username, key);
  if (login.password) out.password = await encryptToText(login.password, key);
  if (login.totp) out.totp = await encryptToText(login.totp, key);
  if (hasOwn(login, 'autofillOnPageLoad')) {
    const value = login.autofillOnPageLoad;
    if (value !== null && typeof value !== 'boolean') {
      throw new TypeError('autofillOnPageLoad must be a boolean or null');
    }
    out.autofillOnPageLoad = value;
  }
  if (hasOwn(login, 'passwordRevisionDate')) {
    const value = login.passwordRevisionDate;
    if (value === undefined || !isOptionalNullableIsoTimestamp(value)) {
      throw new TypeError('passwordRevisionDate must be a valid ISO-8601 timestamp or null');
    }
    out.passwordRevisionDate = value;
  }
  const uris = (login.uris ?? []).filter((u) => u.uri);
  if (uris.length) {
    out.uris = [];
    for (const u of uris) {
      const checksum = await computeLoginUriChecksum(u.uri);
      out.uris.push({
        uri: await encryptToText(u.uri, key),
        uriChecksum: await encryptToText(checksum, key),
        match: u.match ?? null,
      });
    }
  }
  return out;
}

function assertWritableCustomField(field: DecryptedField): void {
  const unsafe = field as unknown as { type?: unknown; name?: unknown; value?: unknown; linkedId?: unknown };
  if ((unsafe.type !== 0 && unsafe.type !== 1 && unsafe.type !== 2 && unsafe.type !== 3)
      || typeof unsafe.name !== 'string'
      || (unsafe.value !== undefined && typeof unsafe.value !== 'string')
      || (unsafe.linkedId !== undefined && (typeof unsafe.linkedId !== 'number' || !Number.isInteger(unsafe.linkedId)))) {
    throw new TypeError('Custom field is invalid');
  }
  if (unsafe.type === 3) {
    if ((unsafe.value as string | undefined) !== undefined && unsafe.value !== '') {
      throw new TypeError('Linked custom fields cannot store a value');
    }
    return;
  }
  if (unsafe.linkedId !== undefined) throw new TypeError('Only Linked custom fields can store a linkedId');
  if (unsafe.type === 2 && unsafe.value !== undefined && unsafe.value !== ''
      && unsafe.value !== 'true' && unsafe.value !== 'false') {
    throw new TypeError('Boolean custom field value is invalid');
  }
}

function hasOwn(value: object | null | undefined, key: string): boolean {
  return value != null && Object.prototype.hasOwnProperty.call(value, key);
}

async function encryptFields<T>(
  src: T,
  fields: ReadonlyArray<keyof T>,
  key: SymmetricKey,
): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const field of fields) {
    const value = src[field] as unknown as string | undefined;
    if (value) out[field as string] = await encryptToText(value, key);
  }
  return out;
}
