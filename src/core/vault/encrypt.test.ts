import { describe, it, expect } from 'vitest';
import { encryptCipher, mergeServerManagedFields } from './encrypt.js';
import { decryptCipher } from './decrypt.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes } from '../crypto/encoding.js';
import { decryptToText } from '../crypto/encstring.js';
import { USER_KEY_VECTOR } from '../../../test/vectors.js';
import { CARD_FIELDS, IDENTITY_FIELDS } from './models.js';
import type { CipherInput, SshCipherInput, WritableCipherInput } from './models.js';
import type { CipherResponse } from '../api/types.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

/** Decrypt an encrypted request as if it were a synced cipher, to prove the round-trip. */
async function roundTrip(input: WritableCipherInput) {
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

  it('regenerates an encrypted Bitwarden checksum for every written URI', async () => {
    const req = await encryptCipher({
      type: 1,
      name: 'Checksums',
      login: { uris: [{ uri: 'https://example.com' }, { uri: 'example.org', match: 2 }] },
    }, userKey);

    expect(req.login?.uris).toHaveLength(2);
    await expect(decryptToText(req.login!.uris![0]!.uriChecksum!, userKey)).resolves.toBe(
      'EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=',
    );
    await expect(decryptToText(req.login!.uris![1]!.uriChecksum!, userKey)).resolves.toBe(
      'v6vDdDKViwYzYNOtZGHJxHNa5/jt1GWSpeDwFFKy5LU=',
    );
    expect(JSON.stringify(req)).not.toContain('EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=');
  });

  it.each([false, true, null] as const)(
    'writes the page-load autofill override without truthy coercion: %s',
    async (autofillOnPageLoad) => {
      const req = await encryptCipher({
        type: 1,
        name: 'Autofill override',
        login: { autofillOnPageLoad },
      }, userKey);
      expect(req.login).toHaveProperty('autofillOnPageLoad', autofillOnPageLoad);
    },
  );

  it('writes nullable password revision timestamps and rejects invalid ISO input', async () => {
    const timestamp = '2026-08-30T01:02:03.1234567+08:00';
    const dated = await encryptCipher({
      type: 1,
      name: 'Dated login',
      login: { passwordRevisionDate: timestamp },
    }, userKey);
    const reset = await encryptCipher({
      type: 1,
      name: 'Reset date',
      login: { passwordRevisionDate: null },
    }, userKey);
    expect(dated.login).toHaveProperty('passwordRevisionDate', timestamp);
    expect(reset.login).toHaveProperty('passwordRevisionDate', null);
    await expect(encryptCipher({
      type: 1,
      name: 'Invalid date',
      login: { passwordRevisionDate: '2026-02-30T01:02:03Z' },
    }, userKey)).rejects.toThrow(/ISO-8601/);
  });

  it('encrypts a complete SSH cipher and round-trips common fields without plaintext leakage', async () => {
    const input: SshCipherInput = {
      type: 5,
      name: 'Production deploy key',
      notes: 'Rotated quarterly',
      favorite: true,
      reprompt: true,
      sshKey: {
        privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n',
        publicKey: 'ssh-ed25519 AAAAPUBLIC deploy@example',
        keyFingerprint: 'SHA256:fingerprint',
      },
      fields: [{ type: 0, name: 'Environment', value: 'production' }],
    };

    const { req, decrypted } = await roundTrip(input);

    expect(req.type).toBe(5);
    expect(req.reprompt).toBe(1);
    expect(req.sshKey).toEqual({
      privateKey: expect.stringMatching(/^2\./),
      publicKey: expect.stringMatching(/^2\./),
      keyFingerprint: expect.stringMatching(/^2\./),
    });
    for (const plaintext of [
      'PRIVATE', 'AAAAPUBLIC', 'SHA256:fingerprint', 'Rotated quarterly', 'production',
    ]) expect(JSON.stringify(req)).not.toContain(plaintext);
    expect(decrypted).toMatchObject({
      type: 5,
      name: 'Production deploy key',
      notes: 'Rotated quarterly',
      favorite: true,
      reprompt: true,
      sshKey: input.sshKey,
      fields: [{ type: 0, name: 'Environment', value: 'production' }],
    });
  });

  it('round-trips an SSH private key at the exact guaranteed plaintext boundary', async () => {
    const privateKey = 'k'.repeat(3_695);
    const { req, decrypted } = await roundTrip({
      type: 5,
      name: 'Boundary key',
      sshKey: { privateKey, publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
    });

    expect(req.sshKey?.privateKey).toHaveLength(5_000);
    expect(decrypted?.sshKey?.privateKey).toBe(privateKey);
  });

  it('rejects incomplete, oversized, or type-confused SSH writer input', async () => {
    await expect(encryptCipher({
      type: 5,
      name: 'Missing public fields',
      sshKey: { privateKey: 'PRIVATE' },
    } as unknown as WritableCipherInput, userKey)).rejects.toThrow(/writer requires/i);
    await expect(encryptCipher({
      type: 5,
      name: 'Oversized',
      sshKey: { privateKey: 'k'.repeat(3_696), publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
    }, userKey)).rejects.toThrow(/bounded/i);
    await expect(encryptCipher({
      type: 5,
      name: 'Confused',
      login: { password: 'must-not-encrypt' },
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
    }, userKey)).rejects.toThrow(/must not contain login/i);
    await expect(encryptCipher({
      type: 5,
      name: 'Raw authority must not enter the writer',
      data: '{"Name":"plaintext-conflict"}',
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
    } as unknown as WritableCipherInput, userKey)).rejects.toThrow(/must not contain data/i);
    await expect(encryptCipher({
      type: 1,
      name: 'Login',
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x' },
    }, userKey)).rejects.toThrow(/only ssh ciphers/i);
  });

  it('omits empty optional fields and defaults favorite/folderId', async () => {
    const req = await encryptCipher({ type: 1, name: 'Bare', login: { username: 'u' } }, userKey);
    expect(req.favorite).toBe(false);
    expect(req.folderId).toBeNull();
    expect(req.notes == null).toBe(true);
    expect(req.login?.password == null).toBe(true);
    expect(req.login?.uris == null).toBe(true);
  });

  it('encrypts custom fields so they round-trip (and never leak plaintext values)', async () => {
    const input: CipherInput = {
      type: 1, name: 'Acct', login: { password: 'p' },
      fields: [
        { type: 0, name: 'Recovery', value: 'visible-text' },
        { type: 1, name: 'PIN', value: '9999' },
        { type: 2, name: 'Enrolled', value: 'true' },
        { type: 3, name: 'User', linkedId: 100 },
      ],
    };
    const { req, decrypted } = await roundTrip(input);
    expect(JSON.stringify(req)).not.toContain('9999');       // Hidden value encrypted
    expect(JSON.stringify(req)).not.toContain('visible-text'); // Text value encrypted too
    expect(decrypted?.fields).toEqual([
      { type: 0, name: 'Recovery', value: 'visible-text' },
      { type: 1, name: 'PIN', value: '9999' },
      { type: 2, name: 'Enrolled', value: 'true' },
      { type: 3, name: 'User', linkedId: 100 },
    ]);
  });

  it('writes an empty fields array to clear custom fields server-side', async () => {
    const req = await encryptCipher({ type: 1, name: 'X', fields: [], login: { password: 'p' } }, userKey);
    expect(req.fields).toEqual([]);
  });

  it('writes the master-password reprompt flag from the editor input (1 when set, 0 when not)', async () => {
    const on = await encryptCipher({ type: 1, name: 'Protected', reprompt: true, login: { password: 'x' } }, userKey);
    expect(on.reprompt).toBe(1);
    const off = await encryptCipher({ type: 1, name: 'Open', login: { password: 'x' } }, userKey);
    expect(off.reprompt).toBe(0);
  });
});

describe('mergeServerManagedFields', () => {
  it('preserves a passkey, passwordHistory and cipher key from the original on update', async () => {
    const req = await encryptCipher({ type: 1, name: 'GitHub', login: { username: 'octo', password: 's3cret' } }, userKey);
    const original: CipherResponse = {
      id: 'c1', type: 1,
      key: '2.cipherkey==',
      archivedDate: '2026-08-30T00:00:00.000Z',
      reprompt: 1,
      fields: [{ type: 0, name: '2.fieldname==', value: '2.fieldvalue==' }],
      passwordHistory: [{ password: '2.oldpassword==', lastUsedDate: '2020-01-01T00:00:00.000Z' }],
      login: {
        username: '2.ignored==',
        fido2Credentials: [{ credentialId: '2.cid==', keyValue: '2.kv==', rpId: '2.rp==' }],
        autofillOnPageLoad: false,
        passwordRevisionDate: '2020-01-01T00:00:00.000Z',
      },
    };
    const merged = mergeServerManagedFields(req, original);
    // The high-severity case: the passkey survives an edit.
    expect(merged.login?.fido2Credentials).toEqual(original.login!.fido2Credentials);
    // The editor's own login fields are not clobbered by the merge.
    expect(merged.login?.username).toBe(req.login!.username);
    expect(merged.login?.password).toBe(req.login!.password);
    expect(merged.login).toHaveProperty('autofillOnPageLoad', false);
    expect(merged.login?.passwordRevisionDate).toBe('2020-01-01T00:00:00.000Z');
    expect(merged.passwordHistory).toEqual(original.passwordHistory);
    // custom fields and reprompt are now editor-controlled (encryptCipher writes them); the merge must
    // NOT pull them from the original, so this update (input has neither) clears the original's values.
    expect(merged.fields).toBeUndefined();
    expect(merged.reprompt).toBe(0);
    expect(merged.key).toBe('2.cipherkey==');
    expect(merged.archivedDate).toBe('2026-08-30T00:00:00.000Z');
  });

  it('rejects unknown custom-field types and lossy field/type combinations', async () => {
    const base = { type: 1 as const, name: 'Invalid fields', login: { password: 'p' } };
    await expect(encryptCipher({
      ...base,
      fields: [{ type: 9, name: 'Future', value: 'secret' }],
    } as never, userKey)).rejects.toThrow('Custom field is invalid');
    await expect(encryptCipher({
      ...base,
      fields: [{ type: 2, name: 'Enabled', value: 'yes' }],
    }, userKey)).rejects.toThrow('Boolean custom field value is invalid');
    await expect(encryptCipher({
      ...base,
      fields: [{ type: 0, name: 'Text', value: 'safe', linkedId: 100 }],
    }, userKey)).rejects.toThrow('Only Linked custom fields can store a linkedId');
    await expect(encryptCipher({
      ...base,
      fields: [{ type: 3, name: 'Alias', value: 'must-not-be-dropped', linkedId: 100 }],
    }, userKey)).rejects.toThrow('Linked custom fields cannot store a value');
  });

  it('never overwrites explicit login metadata with carried server values', async () => {
    const req = await encryptCipher({
      type: 1,
      name: 'Explicit metadata',
      login: { autofillOnPageLoad: true, passwordRevisionDate: null },
    }, userKey);
    const original: CipherResponse = {
      id: 'c1',
      type: 1,
      login: {
        autofillOnPageLoad: false,
        passwordRevisionDate: '2020-01-01T00:00:00.000Z',
      },
    };

    mergeServerManagedFields(req, original);

    expect(req.login).toHaveProperty('autofillOnPageLoad', true);
    expect(req.login).toHaveProperty('passwordRevisionDate', null);
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

  it('does not fabricate a login on non-login ciphers and no longer carries editor-modeled fields', async () => {
    const req = await encryptCipher({ type: 2, name: 'Note' }, userKey);
    const original: CipherResponse = {
      id: 'c1', type: 2, reprompt: 1,
      fields: [{ type: 0, name: '2.n==', value: '2.v==' }],
    };
    const merged = mergeServerManagedFields(req, original);
    expect(merged.login == null).toBe(true);
    // custom fields and reprompt are editor-controlled now and not carried from the original.
    expect(merged.fields).toBeUndefined();
    expect(merged.reprompt).toBe(0);
  });
});

describe('shared card/identity field whitelists', () => {
  // Single source of truth in models.ts, imported by both encrypt.ts and decrypt.ts so they cannot drift.
  it('CARD_FIELDS lists every DecryptedCard field exactly once', () => {
    expect([...CARD_FIELDS].sort()).toEqual(
      ['brand', 'cardholderName', 'code', 'expMonth', 'expYear', 'number'].sort(),
    );
  });

  it('IDENTITY_FIELDS lists every DecryptedIdentity field exactly once', () => {
    expect([...IDENTITY_FIELDS].sort()).toEqual(
      [
        'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
        'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn',
        'username', 'passportNumber', 'licenseNumber',
      ].sort(),
    );
  });
});
