import { describe, expect, it } from 'vitest';

import type { Fido2CredentialData } from '../api/types.js';
import { bytesToBase64Url } from '../crypto/encoding.js';
import { decryptToText } from '../crypto/encstring.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import type {
  PersonalImportItemWrite,
  PersonalImportPasskeyWrite,
} from './vault-transfer-commit.js';
import {
  encryptPersonalImportItemWrite,
  PersonalImportCryptoError,
  type PersonalImportCryptoOptions,
  type PersonalImportPkcs8Crypto,
} from './vault-transfer-import-crypto.js';

const TARGET_KEY = symmetricKeyFromBytes(
  Uint8Array.from({ length: 64 }, (_, index) => (index * 7 + 3) & 0xff),
);
const CREDENTIAL_ID = bytesToBase64Url(new Uint8Array([1, 2, 3, 4]));
const USER_HANDLE = bytesToBase64Url(new Uint8Array([5, 6, 7]));
const UTC_DATE = '2025-01-02T03:04:05.1234567Z';

let generatedPkcs8: Promise<string> | undefined;

function validWrite(overrides: Partial<PersonalImportItemWrite> = {}): PersonalImportItemWrite {
  return {
    sourceIndex: 0,
    cipher: {
      type: 1,
      name: 'Imported login',
      login: {
        username: 'alice',
        password: 'current-password',
        passwordRevisionDate: UTC_DATE,
        uris: [{ uri: 'https://example.com', match: 0 }],
      },
    },
    ...overrides,
  };
}

async function validPasskey(
  overrides: Partial<PersonalImportPasskeyWrite> = {},
): Promise<PersonalImportPasskeyWrite> {
  return {
    credentialId: CREDENTIAL_ID,
    keyType: 'public-key',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: await p256Pkcs8(),
    rpId: 'example.com',
    counter: '4294967295',
    discoverable: 'true',
    userHandle: USER_HANDLE,
    userName: 'alice@example.com',
    rpName: 'Example',
    userDisplayName: 'Alice',
    creationDate: UTC_DATE,
    ...overrides,
  };
}

function syntheticPasskey(
  overrides: Partial<PersonalImportPasskeyWrite> = {},
): PersonalImportPasskeyWrite {
  return {
    credentialId: CREDENTIAL_ID,
    keyType: 'public-key',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: 'AQ',
    rpId: 'example.com',
    counter: '0',
    discoverable: 'false',
    creationDate: UTC_DATE,
    ...overrides,
  };
}

async function p256Pkcs8(): Promise<string> {
  generatedPkcs8 ??= globalThis.crypto.subtle
    .generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    .then(async (keyPair) => bytesToBase64Url(
      new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)),
    ));
  return generatedPkcs8;
}

const FAKE_P256_PRIVATE_KEY = {
  type: 'private',
  extractable: true,
  usages: ['sign'],
  algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
} as CryptoKey;

const acceptSyntheticKey: PersonalImportCryptoOptions = {
  pkcs8Crypto: {
    importPrivateKey: async () => FAKE_P256_PRIVATE_KEY,
    exportPrivateKey: async () => new Uint8Array([1]).buffer,
  },
};

async function decryptOptional(
  value: string | null | undefined,
): Promise<string | null | undefined> {
  return typeof value === 'string' ? decryptToText(value, TARGET_KEY) : value;
}

async function decryptPasskey(value: Fido2CredentialData): Promise<Record<string, unknown>> {
  const output: Record<string, unknown> = { creationDate: value.creationDate };
  for (const field of [
    'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
    'counter', 'discoverable', 'userHandle', 'userName', 'rpName', 'userDisplayName',
  ] as const) {
    if (Object.prototype.hasOwnProperty.call(value, field)) {
      output[field] = await decryptOptional(value[field]);
    }
  }
  return output;
}

describe('encryptPersonalImportItemWrite', () => {
  it('round-trips password history, login metadata, passkey fields, and archivedDate', async () => {
    const passkey = await validPasskey();
    const write = validWrite({
      passwordHistory: [
        { password: 'previous-one', lastUsedDate: '2024-01-02T03:04:05Z' },
        { password: 'previous-two', lastUsedDate: null },
        { password: 'previous-three' },
      ],
      fido2Credentials: [passkey],
      dates: { archivedDate: '2025-04-05T06:07:08.9000000Z' },
    });

    const request = await encryptPersonalImportItemWrite(write, TARGET_KEY);

    expect(request.type).toBe(1);
    expect(request.archivedDate).toBe('2025-04-05T06:07:08.9000000Z');
    expect(request.login?.passwordRevisionDate).toBe(UTC_DATE);
    expect(await decryptToText(request.name, TARGET_KEY)).toBe('Imported login');
    expect(await decryptToText(request.login!.username!, TARGET_KEY)).toBe('alice');
    expect(await decryptToText(request.login!.password!, TARGET_KEY)).toBe('current-password');

    const history = request.passwordHistory!;
    expect(await Promise.all(history.map((entry) => decryptToText(entry.password!, TARGET_KEY))))
      .toEqual(['previous-one', 'previous-two', 'previous-three']);
    expect(history.map((entry) => entry.lastUsedDate))
      .toEqual(['2024-01-02T03:04:05Z', null, undefined]);

    expect(request.login?.fido2Credentials).toHaveLength(1);
    expect(await decryptPasskey(request.login!.fido2Credentials![0]!)).toEqual(passkey);
  });

  it('preserves null and absent optional passkey fields without normalizing required values', async () => {
    const passkey = await validPasskey({
      counter: '0',
      discoverable: 'false',
      userHandle: null,
      userName: null,
      userDisplayName: '',
    });
    delete passkey.rpName;
    const request = await encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [passkey] }),
      TARGET_KEY,
    );
    const encrypted = request.login!.fido2Credentials![0]!;

    expect(encrypted.userHandle).toBeNull();
    expect(encrypted.userName).toBeNull();
    expect(encrypted).not.toHaveProperty('rpName');
    expect(await decryptToText(encrypted.userDisplayName!, TARGET_KEY)).toBe('');
    expect(await decryptToText(encrypted.counter!, TARGET_KEY)).toBe('0');
    expect(await decryptToText(encrypted.discoverable!, TARGET_KEY)).toBe('false');
  });

  it('uses the imported secure-note subtype when one is explicitly supplied', async () => {
    const request = await encryptPersonalImportItemWrite({
      sourceIndex: 1,
      cipher: { type: 2, name: 'Note' },
      secureNoteType: 7,
    }, TARGET_KEY);

    expect(request.secureNote).toEqual({ type: 7 });
  });

  it('rejects more than five password-history entries without encrypting them', async () => {
    const history = Array.from({ length: 6 }, (_, index) => ({ password: `old-${index}` }));
    await expect(encryptPersonalImportItemWrite(
      validWrite({ passwordHistory: history }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'password_history_limit_exceeded' });
  });

  it.each([
    ['empty password', { password: '' }],
    ['offset history date', { password: 'old', lastUsedDate: '2025-01-01T01:00:00+01:00' }],
    ['invalid history date', { password: 'old', lastUsedDate: '2025-02-30T00:00:00Z' }],
  ])('rejects invalid password history: %s', async (_label, entry) => {
    await expect(encryptPersonalImportItemWrite(
      validWrite({ passwordHistory: [entry] }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'invalid_password_history' });
  });

  it.each([
    ['key type', { keyType: 'private-key' }],
    ['algorithm', { keyAlgorithm: 'RSA' }],
    ['curve', { keyCurve: 'P-384' }],
    ['credential padding', { credentialId: 'AQ==' }],
    ['credential alphabet', { credentialId: 'AQ+' }],
    ['credential impossible length', { credentialId: 'A' }],
    ['counter sign', { counter: '-1' }],
    ['counter leading zero', { counter: '01' }],
    ['counter overflow', { counter: '4294967296' }],
    ['discoverable', { discoverable: 'yes' }],
    ['rp id', { rpId: 'https://example.com' }],
    ['uppercase rp id', { rpId: 'Example.com' }],
    ['public suffix rp id', { rpId: 'com' }],
    ['unsupported loopback rp id', { rpId: '127.0.0.2' }],
    ['offset creation date', { creationDate: '2025-01-01T01:00:00+01:00' }],
    ['noncanonical user handle', { userHandle: 'AQ==' }],
  ])('rejects an invalid passkey %s', async (_label, override) => {
    const passkey = syntheticPasskey(override);
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [passkey] }),
      TARGET_KEY,
      acceptSyntheticKey,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it('rejects a passkey without a creation date', async () => {
    const passkey = syntheticPasskey() as Partial<PersonalImportPasskeyWrite>;
    delete passkey.creationDate;
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [passkey as PersonalImportPasskeyWrite] }),
      TARGET_KEY,
      acceptSyntheticKey,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it('rejects a canonical base64url value that is not a P-256 PKCS#8 private key', async () => {
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey()] }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it.each(['localhost', '127.0.0.1'])('accepts the supported exact loopback RP ID %s', async (rpId) => {
    const request = await encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey({ rpId })] }),
      TARGET_KEY,
      acceptSyntheticKey,
    );
    expect(await decryptToText(request.login!.fido2Credentials![0]!.rpId!, TARGET_KEY)).toBe(rpId);
  });

  it('rejects a PKCS#8 encoding that WebCrypto re-exports differently', async () => {
    const noncanonical: PersonalImportCryptoOptions = {
      pkcs8Crypto: {
        importPrivateKey: async () => FAKE_P256_PRIVATE_KEY,
        exportPrivateKey: async () => new Uint8Array([2]).buffer,
      },
    };
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey()] }),
      TARGET_KEY,
      noncanonical,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it('rejects an oversized PKCS#8 string before invoking the crypto adapter', async () => {
    let imported = false;
    const pkcs8Crypto: PersonalImportPkcs8Crypto = {
      importPrivateKey: async () => {
        imported = true;
        return FAKE_P256_PRIVATE_KEY;
      },
      exportPrivateKey: async () => new ArrayBuffer(0),
    };
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey({ keyValue: 'A'.repeat(5_463) })] }),
      TARGET_KEY,
      { pkcs8Crypto },
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
    expect(imported).toBe(false);
  });

  it('rejects a key whose imported metadata is not an extractable P-256 signing private key', async () => {
    const wrongMetadata: PersonalImportCryptoOptions = {
      pkcs8Crypto: {
        importPrivateKey: async () => ({
          ...FAKE_P256_PRIVATE_KEY,
          algorithm: { name: 'ECDSA', namedCurve: 'P-384' },
        }) as CryptoKey,
        exportPrivateKey: async () => new Uint8Array([1]).buffer,
      },
    };
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey()] }),
      TARGET_KEY,
      wrongMetadata,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it('rejects duplicate passkey credential IDs and passkeys attached to a non-login item', async () => {
    const passkey = syntheticPasskey();
    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [passkey, { ...passkey }] }),
      TARGET_KEY,
      acceptSyntheticKey,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });

    await expect(encryptPersonalImportItemWrite({
      sourceIndex: 0,
      cipher: { type: 2, name: 'Note' },
      fido2Credentials: [passkey],
    }, TARGET_KEY, acceptSyntheticKey)).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it.each([
    ['archived date offset', { archivedDate: '2025-01-01T01:00:00+01:00' }],
    ['archived date invalid', { archivedDate: '2025-13-01T00:00:00Z' }],
  ])('rejects %s', async (_label, dates) => {
    await expect(encryptPersonalImportItemWrite(
      validWrite({ dates }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'invalid_archived_date' });
  });

  it('rejects explicit undefined instead of rewriting it to null', async () => {
    await expect(encryptPersonalImportItemWrite(
      validWrite({ dates: { archivedDate: undefined } as never }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'invalid_archived_date' });

    await expect(encryptPersonalImportItemWrite(
      validWrite({ passwordHistory: [{ password: 'old', lastUsedDate: undefined } as never] }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'invalid_password_history' });

    await expect(encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey({ userName: undefined } as never)] }),
      TARGET_KEY,
      acceptSyntheticKey,
    )).rejects.toMatchObject({ code: 'invalid_passkey' });
  });

  it('rejects accessor and symbol properties without evaluating imported secret getters', async () => {
    let getterRead = false;
    const entry = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(entry, 'password', {
      enumerable: true,
      get() {
        getterRead = true;
        return 'GETTER-SECRET';
      },
    });
    entry[Symbol('secret')] = 'SYMBOL-SECRET';

    await expect(encryptPersonalImportItemWrite(
      validWrite({ passwordHistory: [entry as never] }),
      TARGET_KEY,
    )).rejects.toMatchObject({ code: 'invalid_password_history' });
    expect(getterRead).toBe(false);
  });

  it('rejects non-UTC login passwordRevisionDate', async () => {
    await expect(encryptPersonalImportItemWrite(validWrite({
      cipher: {
        type: 1,
        name: 'Login',
        login: { passwordRevisionDate: '2025-01-01T01:00:00+01:00' },
      },
    }), TARGET_KEY)).rejects.toMatchObject({ code: 'invalid_write' });
  });

  it('clears decoded PKCS#8 bytes after successful validation', async () => {
    let imported: Uint8Array | undefined;
    let exported: Uint8Array | undefined;
    const pkcs8Crypto: PersonalImportPkcs8Crypto = {
      importPrivateKey: async (pkcs8) => {
        imported = pkcs8;
        return FAKE_P256_PRIVATE_KEY;
      },
      exportPrivateKey: async () => {
        const buffer = new ArrayBuffer(1);
        exported = new Uint8Array(buffer);
        exported[0] = 1;
        return buffer;
      },
    };
    await encryptPersonalImportItemWrite(
      validWrite({ fido2Credentials: [syntheticPasskey()] }),
      TARGET_KEY,
      { pkcs8Crypto },
    );

    expect(imported).toEqual(new Uint8Array(imported!.byteLength));
    expect(exported).toEqual(new Uint8Array(exported!.byteLength));
  });

  it('clears decoded PKCS#8 bytes and emits no secret when validation fails', async () => {
    const secret = 'DO-NOT-LEAK-PRIVATE-MATERIAL';
    let observed: Uint8Array | undefined;
    let error: unknown;
    try {
      await encryptPersonalImportItemWrite(
        validWrite({ fido2Credentials: [syntheticPasskey()] }),
        TARGET_KEY,
        {
          pkcs8Crypto: {
            importPrivateKey: async (pkcs8) => {
              observed = pkcs8;
              throw new Error(secret);
            },
            exportPrivateKey: async () => new ArrayBuffer(0),
          },
        },
      );
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(PersonalImportCryptoError);
    expect(error).toMatchObject({ code: 'invalid_passkey' });
    expect(String(error)).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
    expect(observed).toEqual(new Uint8Array(observed!.byteLength));
  });

  it('never includes invalid imported secret values in validation errors', async () => {
    const secret = 'PRIVATE-KEY-SECRET+=';
    let error: unknown;
    try {
      await encryptPersonalImportItemWrite(
        validWrite({ fido2Credentials: [syntheticPasskey({ keyValue: secret })] }),
        TARGET_KEY,
        acceptSyntheticKey,
      );
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(PersonalImportCryptoError);
    expect(String(error)).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
  });
});
