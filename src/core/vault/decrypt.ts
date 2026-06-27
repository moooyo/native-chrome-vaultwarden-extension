import type { CipherResponse } from '../api/types.js';
import { decryptToText } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import type { DecryptedCipher } from './models.js';

export async function decryptCipher(
  cipher: CipherResponse,
  userKey: SymmetricKey,
): Promise<DecryptedCipher | undefined> {
  if (cipher.organizationId) return undefined;
  const key = cipher.key ? await unwrapSymmetricKey(cipher.key, userKey) : userKey;
  const name = await decryptRequired(cipher.name, key, '(no name)');
  const login = cipher.login ?? undefined;
  const uris = await Promise.all(
    (login?.uris ?? []).map(async (u) => (u.uri ? decryptToText(u.uri, key) : undefined)),
  );
  const out: DecryptedCipher = {
    id: cipher.id,
    type: cipher.type,
    favorite: cipher.favorite ?? false,
    name,
    uris: uris.filter((u): u is string => Boolean(u)),
  };
  const username = await decryptOptional(login?.username, key);
  const password = await decryptOptional(login?.password, key);
  const totp = await decryptOptional(login?.totp, key);
  const notes = await decryptOptional(cipher.notes, key);
  if (username) out.username = username;
  if (password) out.password = password;
  if (totp) out.totp = totp;
  if (notes) out.notes = notes;
  return out;
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
