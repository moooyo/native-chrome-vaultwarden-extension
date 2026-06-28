import type { CardCipherData, CipherRequest, CipherResponse, IdentityCipherData, LoginCipherData } from '../api/types.js';
import { encryptToText } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { CipherInput, DecryptedCard, DecryptedIdentity } from './models.js';

const CARD_FIELDS: Array<keyof DecryptedCard> = ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'];
const IDENTITY_FIELDS: Array<keyof DecryptedIdentity> = [
  'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
  'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn',
  'username', 'passportNumber', 'licenseNumber',
];

/**
 * Encrypt a plaintext cipher form into a write request. Every field is encrypted under the given
 * key (the account UserKey for personal ciphers) as an encType=2 EncString; empty fields are omitted.
 */
export async function encryptCipher(input: CipherInput, key: SymmetricKey): Promise<CipherRequest> {
  const req: CipherRequest = {
    type: input.type,
    name: await encryptToText(input.name, key),
    favorite: input.favorite ?? false,
    folderId: input.folderId ?? null,
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
  }
  return req;
}

/**
 * Carry forward the fields the editor does not model from the original (cached) cipher onto a freshly
 * encrypted update request, so a wholesale PUT does not silently wipe them server-side. Everything copied
 * is already an EncString (or an opaque flag), so no user key is needed. No-op on the create path.
 */
export function mergeServerManagedFields(request: CipherRequest, original: CipherResponse | undefined): CipherRequest {
  if (!original) return request;
  if (original.key != null) request.key = original.key;
  if (original.fields != null) request.fields = original.fields;
  if (original.passwordHistory != null) request.passwordHistory = original.passwordHistory;
  if (original.reprompt != null) request.reprompt = original.reprompt;
  // Login sub-fields the editor cannot represent (a stored passkey, the password-revision timestamp)
  // must ride along, or the wholesale PUT drops them. Only touch login on login ciphers.
  if (request.type === 1) {
    const carried: Partial<LoginCipherData> = {};
    if (original.login?.fido2Credentials != null) carried.fido2Credentials = original.login.fido2Credentials;
    if (original.login?.passwordRevisionDate != null) carried.passwordRevisionDate = original.login.passwordRevisionDate;
    if (Object.keys(carried).length) request.login = { ...(request.login ?? {}), ...carried };
  }
  return request;
}

async function encryptLogin(login: NonNullable<CipherInput['login']>, key: SymmetricKey): Promise<LoginCipherData> {
  const out: LoginCipherData = {};
  if (login.username) out.username = await encryptToText(login.username, key);
  if (login.password) out.password = await encryptToText(login.password, key);
  if (login.totp) out.totp = await encryptToText(login.totp, key);
  const uris = (login.uris ?? []).filter((u) => u.uri);
  if (uris.length) {
    out.uris = [];
    for (const u of uris) {
      out.uris.push({ uri: await encryptToText(u.uri, key), match: u.match ?? null });
    }
  }
  return out;
}

async function encryptFields<T>(
  src: T,
  fields: Array<keyof T>,
  key: SymmetricKey,
): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const field of fields) {
    const value = src[field] as unknown as string | undefined;
    if (value) out[field as string] = await encryptToText(value, key);
  }
  return out;
}
