import { describe, it, expect } from 'vitest';
import { encryptCipher, mergeServerManagedFields } from './encrypt.js';
import { decryptCipher } from './decrypt.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes } from '../crypto/encoding.js';
import { USER_KEY_VECTOR } from '../../../test/vectors.js';
import type { CipherInput } from './models.js';
import type { CipherResponse } from '../api/types.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

/** Decrypt an encrypted request as if it were a synced cipher, to prove the round-trip. */
async function roundTrip(input: CipherInput) {
  const req = await encryptCipher(input, userKey);
  return { req, decrypted: await decryptCipher({ id: 'new', ...req } as CipherResponse, userKey) };
}

describe('encryptCipher', () => {
  it('encrypts a login cipher so it round-trips through decryptCipher', async () => {
    const input: CipherInput = {
      type: 1, name: 'GitHub', notes: 'my notes', favorite: true, folderId: 'f1',
      login: { username: 'octo', password: 's3cret', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://github.com', match: 0 }] },
    };
    const { req, decrypted } = await roundTrip(input);
    expect(req.name.startsWith('2.')).toBe(true);
    // No plaintext secret survives in the request body.
    expect(JSON.stringify(req)).not.toContain('s3cret');
    expect(JSON.stringify(req)).not.toContain('JBSWY3DPEHPK3PXP');
    expect(decrypted).toMatchObject({
      type: 1, name: 'GitHub', notes: 'my notes', favorite: true, folderId: 'f1',
      username: 'octo', password: 's3cret', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://github.com'],
      loginUris: [{ uri: 'https://github.com', match: 0 }],
    });
  });

  it('round-trips a login with multiple URIs and preserves each match (multi-URI editor data path)', async () => {
    const input: CipherInput = {
      type: 1, name: 'Multi',
      login: { password: 'p', uris: [{ uri: 'https://app.example.com', match: 0 }, { uri: 'https://example.com' }] },
    };
    const { decrypted } = await roundTrip(input);
    expect(decrypted?.loginUris).toEqual([{ uri: 'https://app.example.com', match: 0 }, { uri: 'https://example.com' }]);
  });

  it('encrypts a secure note with a secureNote.type marker and round-trips name/notes', async () => {
    const input: CipherInput = { type: 2, name: 'Recovery codes', notes: 'abc-123' };
    const { req, decrypted } = await roundTrip(input);
    expect(req.secureNote).toEqual({ type: 0 });
    expect(decrypted).toMatchObject({ type: 2, name: 'Recovery codes', notes: 'abc-123' });
  });

  it('encrypts a card cipher and round-trips its fields', async () => {
    const input: CipherInput = {
      type: 3, name: 'Visa',
      card: { cardholderName: 'A Holder', brand: 'Visa', number: '4111111111111111', expMonth: '12', expYear: '2030', code: '123' },
    };
    const { req, decrypted } = await roundTrip(input);
    expect(JSON.stringify(req)).not.toContain('4111111111111111');
    expect(decrypted?.card).toEqual({
      cardholderName: 'A Holder', brand: 'Visa', number: '4111111111111111', expMonth: '12', expYear: '2030', code: '123',
    });
  });

  it('encrypts an identity cipher and round-trips its fields', async () => {
    const input: CipherInput = {
      type: 4, name: 'Me',
      identity: { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.com', ssn: '123-45-6789' },
    };
    const { req, decrypted } = await roundTrip(input);
    expect(JSON.stringify(req)).not.toContain('123-45-6789');
    expect(decrypted?.identity).toMatchObject({ firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.com', ssn: '123-45-6789' });
  });

  it('omits empty optional fields and defaults favorite/folderId', async () => {
    const req = await encryptCipher({ type: 1, name: 'Bare', login: { username: 'u' } }, userKey);
    expect(req.favorite).toBe(false);
    expect(req.folderId).toBeNull();
    expect(req.notes == null).toBe(true);
    expect(req.login?.password == null).toBe(true);
    expect(req.login?.uris == null).toBe(true);
  });

  it('writes the master-password reprompt flag from the editor input (1 when set, 0 when not)', async () => {
    const on = await encryptCipher({ type: 1, name: 'Protected', reprompt: true, login: { password: 'x' } }, userKey);
    expect(on.reprompt).toBe(1);
    const off = await encryptCipher({ type: 1, name: 'Open', login: { password: 'x' } }, userKey);
    expect(off.reprompt).toBe(0);
  });
});

describe('mergeServerManagedFields', () => {
  it('preserves a passkey, custom fields, passwordHistory and cipher key from the original on update', async () => {
    const req = await encryptCipher({ type: 1, name: 'GitHub', login: { username: 'octo', password: 's3cret' } }, userKey);
    const original: CipherResponse = {
      id: 'c1', type: 1,
      key: '2.cipherkey==',
      reprompt: 1,
      fields: [{ type: 0, name: '2.fieldname==', value: '2.fieldvalue==' }],
      passwordHistory: [{ password: '2.oldpassword==', lastUsedDate: '2020-01-01T00:00:00.000Z' }],
      login: {
        username: '2.ignored==',
        fido2Credentials: [{ credentialId: '2.cid==', keyValue: '2.kv==', rpId: '2.rp==' }],
        passwordRevisionDate: '2020-01-01T00:00:00.000Z',
      },
    };
    const merged = mergeServerManagedFields(req, original);
    // The high-severity case: the passkey survives an edit.
    expect(merged.login?.fido2Credentials).toEqual(original.login!.fido2Credentials);
    // The editor's own login fields are not clobbered by the merge.
    expect(merged.login?.username).toBe(req.login!.username);
    expect(merged.login?.password).toBe(req.login!.password);
    expect(merged.login?.passwordRevisionDate).toBe('2020-01-01T00:00:00.000Z');
    // Non-login server-managed metadata is carried forward verbatim.
    expect(merged.fields).toEqual(original.fields);
    expect(merged.passwordHistory).toEqual(original.passwordHistory);
    // reprompt is now editor-controlled (encryptCipher writes it from the input); the merge must NOT
    // pull it from the original, so this update (input has no reprompt) clears the original's flag.
    expect(merged.reprompt).toBe(0);
    expect(merged.key).toBe('2.cipherkey==');
  });

  it('is a no-op on the create path (no original cipher)', async () => {
    const req = await encryptCipher({ type: 1, name: 'New', login: { password: 'x' } }, userKey);
    const merged = mergeServerManagedFields(req, undefined);
    expect(merged.login?.fido2Credentials == null).toBe(true);
    expect(merged.fields == null).toBe(true);
    expect(merged.passwordHistory == null).toBe(true);
    // encryptCipher always writes reprompt (0 here); the merge is a no-op on it.
    expect(merged.reprompt).toBe(0);
    expect(merged.key == null).toBe(true);
  });

  it('does not fabricate a login on non-login ciphers but still carries metadata', async () => {
    const req = await encryptCipher({ type: 2, name: 'Note' }, userKey);
    const original: CipherResponse = {
      id: 'c1', type: 2, reprompt: 1,
      fields: [{ type: 0, name: '2.n==', value: '2.v==' }],
    };
    const merged = mergeServerManagedFields(req, original);
    expect(merged.login == null).toBe(true);
    expect(merged.fields).toEqual(original.fields);
    // reprompt is editor-controlled now and not carried from the original.
    expect(merged.reprompt).toBe(0);
  });
});
