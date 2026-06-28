import type { CardCipherData, CipherRequest, IdentityCipherData, LoginCipherData } from '../api/types.js';
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
