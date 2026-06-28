import type { CipherResponse } from '../api/types.js';
import { decryptToText, EncStringMacError, UnsupportedEncTypeError } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import type { CipherSummary, DecryptedCipher } from './models.js';
import type { LoginUri } from './uri-match.js';

export async function decryptCipher(
  cipher: CipherResponse,
  userKey: SymmetricKey,
): Promise<DecryptedCipher | undefined> {
  if (cipher.organizationId) return undefined;
  try {
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, userKey) : userKey;
    const name = await decryptRequired(cipher.name, key, '(no name)');
    const loginUris: LoginUri[] = [];
    for (const u of cipher.login?.uris ?? []) {
      if (u.uri) {
        const loginUri: LoginUri = { uri: await decryptToText(u.uri, key) };
        if (u.match !== undefined && u.match !== null) {
          loginUri.match = u.match;
        }
        loginUris.push(loginUri);
      }
    }
    const out: DecryptedCipher = {
      id: cipher.id,
      type: cipher.type,
      favorite: cipher.favorite ?? false,
      name,
      uris: loginUris.map((u) => u.uri),
      loginUris,
    };
    const username = await decryptOptional(cipher.login?.username, key);
    const password = await decryptOptional(cipher.login?.password, key);
    const totp = await decryptOptional(cipher.login?.totp, key);
    const notes = await decryptOptional(cipher.notes, key);
    if (username) out.username = username;
    if (password) out.password = password;
    if (totp) out.totp = totp;
    if (notes) out.notes = notes;
    return out;
  } catch (err) {
    if (err instanceof EncStringMacError || err instanceof UnsupportedEncTypeError) {
      const undecryptable: CipherSummary = {
        id: cipher.id,
        type: cipher.type,
        favorite: cipher.favorite ?? false,
        name: '(error)',
        uris: [],
        loginUris: [],
        undecryptable: true,
      };
      return undecryptable;
    }
    throw err;
  }
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
