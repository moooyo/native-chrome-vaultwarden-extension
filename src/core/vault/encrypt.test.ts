import { describe, it, expect } from 'vitest';
import { encryptCipher } from './encrypt.js';
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
});
