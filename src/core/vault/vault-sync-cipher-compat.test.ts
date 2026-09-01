import { describe, expect, it } from 'vitest';
import {
  RAW_SYNC_CIPHER_FIELDS,
  validateRawSyncCipherCompatibility,
  type RawSyncCipherCompatibilityErrorCode,
} from './vault-sync-cipher-compat.js';

const ENC = {
  name: '2.<redacted-name>',
  notes: '2.<redacted-notes>',
  username: '2.<redacted-username>',
  password: '2.<redacted-password>',
  totp: '2.<redacted-totp>',
  uri: '2.<redacted-uri>',
  fieldName: '2.<redacted-field-name>',
  fieldValue: '2.<redacted-field-value>',
  oldPassword: '2.<redacted-old-password>',
  credential: '2.<redacted-credential>',
  checksum: '2.<redacted-encrypted-checksum>',
} as const;
const CIPHER_ID = '00000000-0000-0000-0000-000000000001';

function fullLoginData(): Record<string, unknown> {
  return {
    Name: ENC.name,
    Notes: ENC.notes,
    Fields: [{ Type: 0, Name: ENC.fieldName, Value: ENC.fieldValue, LinkedId: null }],
    PasswordHistory: [{ Password: ENC.oldPassword, LastUsedDate: '2026-01-02T03:04:05.1234567Z' }],
    Uris: [{ Uri: ENC.uri, UriChecksum: ENC.checksum, Match: 2 }],
    Username: ENC.username,
    Password: ENC.password,
    PasswordRevisionDate: '2026-01-02T05:04:05.1234567+02:00',
    Totp: ENC.totp,
    AutofillOnPageLoad: false,
    Fido2Credentials: [{
      CredentialId: ENC.credential,
      KeyType: '2.<redacted-key-type>',
      KeyAlgorithm: '2.<redacted-key-algorithm>',
      KeyCurve: '2.<redacted-key-curve>',
      KeyValue: '2.<redacted-key-value>',
      RpId: '2.<redacted-rp-id>',
      RpName: null,
      UserHandle: '2.<redacted-user-handle>',
      UserName: null,
      UserDisplayName: '2.<redacted-display-name>',
      Counter: '2.<redacted-counter>',
      Discoverable: '2.<redacted-discoverable>',
      CreationDate: '2026-02-03T04:05:06Z',
    }],
  };
}

function fullLoginCipher(): Record<string, unknown> {
  return {
    id: CIPHER_ID,
    type: 1,
    permissions: { delete: true, restore: true },
    data: JSON.stringify(fullLoginData()),
    name: ENC.name,
    notes: ENC.notes,
    fields: [{ type: 0, name: ENC.fieldName, value: ENC.fieldValue, linkedId: null }],
    passwordHistory: [{ password: ENC.oldPassword, lastUsedDate: '2026-01-01T22:04:05.1234567-05:00' }],
    login: {
      uri: ENC.uri,
      uris: [{ uri: ENC.uri, uriChecksum: ENC.checksum, match: 2 }],
      username: ENC.username,
      password: ENC.password,
      passwordRevisionDate: '2026-01-02T03:04:05.1234567Z',
      totp: ENC.totp,
      autofillOnPageLoad: false,
      fido2Credentials: [{
        credentialId: ENC.credential,
        keyType: '2.<redacted-key-type>',
        keyAlgorithm: '2.<redacted-key-algorithm>',
        keyCurve: '2.<redacted-key-curve>',
        keyValue: '2.<redacted-key-value>',
        rpId: '2.<redacted-rp-id>',
        rpName: null,
        userHandle: '2.<redacted-user-handle>',
        userName: null,
        userDisplayName: '2.<redacted-display-name>',
        counter: '2.<redacted-counter>',
        discoverable: '2.<redacted-discoverable>',
        creationDate: '2026-02-02T23:05:06-05:00',
      }],
    },
  };
}

function expectFailure(value: unknown, code: RawSyncCipherCompatibilityErrorCode): void {
  const subject = typeof value === 'object' && value !== null && !Array.isArray(value)
    && !Object.prototype.hasOwnProperty.call(value, 'id')
    ? { id: CIPHER_ID, ...(value as Record<string, unknown>) }
    : value;
  const result = validateRawSyncCipherCompatibility(subject);
  expect(result).toEqual({ ok: false, code });
}

function withId<T extends Record<string, unknown>>(value: T): T & { id: string } {
  return { id: CIPHER_ID, ...value };
}

describe('Bitwarden 2026.8 raw sync cipher compatibility', () => {
  it('accepts a secret-stripped real-response login shape and compares every redundant field', () => {
    const cipher = fullLoginCipher();
    const result = validateRawSyncCipherCompatibility(cipher);
    expect(result).toEqual({ ok: true, dataMode: 'redundant-plain-data' });
    expect(JSON.stringify(result)).not.toContain('redacted');
  });

  it('accepts legacy responses with data absent or null after validating permissions', () => {
    const withoutData = { type: 1, name: ENC.name, login: {}, permissions: { delete: null } };
    expect(validateRawSyncCipherCompatibility(withId(withoutData))).toEqual({
      ok: true, dataMode: 'structured-only',
    });
    expect(validateRawSyncCipherCompatibility(withId({ ...withoutData, data: null }))).toEqual({
      ok: true, dataMode: 'structured-only',
    });
  });

  it('accepts a missing optional passkey discoverable field without relaxing projection equality', () => {
    const structured = fullLoginCipher();
    delete structured.data;
    delete ((structured.login as Record<string, unknown>)
      .fido2Credentials as Record<string, unknown>[])[0]!.discoverable;
    expect(validateRawSyncCipherCompatibility(structured)).toEqual({
      ok: true,
      dataMode: 'structured-only',
    });

    const redundant = fullLoginCipher();
    const data = fullLoginData();
    delete (data.Fido2Credentials as Record<string, unknown>[])[0]!.Discoverable;
    redundant.data = JSON.stringify(data);
    delete ((redundant.login as Record<string, unknown>)
      .fido2Credentials as Record<string, unknown>[])[0]!.discoverable;
    expect(validateRawSyncCipherCompatibility(redundant)).toEqual({
      ok: true,
      dataMode: 'redundant-plain-data',
    });

    const mismatch = fullLoginCipher();
    delete ((mismatch.login as Record<string, unknown>)
      .fido2Credentials as Record<string, unknown>[])[0]!.discoverable;
    expectFailure(mismatch, 'data_projection_mismatch');
  });

  it.each([
    [1, 'login'],
    [2, 'secureNote'],
    [3, 'card'],
    [4, 'identity'],
    [5, 'sshKey'],
  ] as const)('requires the type %i structured payload when data is absent', (type, payload) => {
    expectFailure({ type, name: ENC.name }, 'invalid_structured_projection');
    expectFailure({ type, name: ENC.name, [payload]: null }, 'invalid_structured_projection');
  });

  it('validates all current structured-only type payloads, including legacy sparse SSH fields', () => {
    const cases = [
      withId({
        type: 1,
        name: ENC.name,
        notes: null,
        fields: [{ type: 0, name: null, value: ENC.fieldValue, linkedId: null }],
        passwordHistory: [{ password: ENC.oldPassword, lastUsedDate: '2026-01-02T03:04:05Z' }],
        login: {
          uri: ENC.uri,
          uris: [{ uri: ENC.uri, uriChecksum: null, match: 2 }],
          username: null,
          autofillOnPageLoad: null,
        },
      }),
      withId({ type: 2, name: ENC.name, secureNote: { type: 0 } }),
      withId({ type: 3, name: ENC.name, card: { number: '2.number', code: null } }),
      withId({ type: 4, name: ENC.name, identity: { firstName: '2.first', ssn: null } }),
      withId({ type: 5, name: ENC.name, sshKey: { privateKey: '2.private' } }),
    ];
    for (const cipher of cases) {
      expect(validateRawSyncCipherCompatibility(cipher)).toEqual({
        ok: true, dataMode: 'structured-only',
      });
    }
  });

  it('accepts exact SecureNote, Card, Identity, and SSHKey casing projections', () => {
    const identityFields = [
      'Title', 'FirstName', 'MiddleName', 'LastName', 'Address1', 'Address2', 'Address3', 'City',
      'State', 'PostalCode', 'Country', 'Company', 'Email', 'Phone', 'SSN', 'Username',
      'PassportNumber', 'LicenseNumber',
    ];
    const identityData = Object.fromEntries(identityFields.map((field) => [field, `2.${field}`]));
    const identityProjection = Object.fromEntries(identityFields.map((field) => [
      field === 'SSN' ? 'ssn' : `${field[0]!.toLowerCase()}${field.slice(1)}`,
      `2.${field}`,
    ]));
    const cases: Record<string, unknown>[] = [
      {
        type: 2,
        data: JSON.stringify({ Name: ENC.name, Notes: null, Type: 0 }),
        name: ENC.name,
        secureNote: { type: 0 },
      },
      {
        type: 3,
        data: JSON.stringify({
          Name: ENC.name, CardholderName: '2.holder', Brand: null, Number: '2.number',
          ExpMonth: '2.month', ExpYear: '2.year', Code: '2.code',
        }),
        name: ENC.name,
        notes: null,
        card: {
          cardholderName: '2.holder', brand: null, number: '2.number',
          expMonth: '2.month', expYear: '2.year', code: '2.code',
        },
      },
      {
        type: 4,
        data: JSON.stringify({ Name: ENC.name, ...identityData }),
        name: ENC.name,
        identity: identityProjection,
      },
      {
        type: 5,
        data: JSON.stringify({ Name: ENC.name, PrivateKey: '2.private' }),
        name: ENC.name,
        sshKey: { privateKey: '2.private', publicKey: null, keyFingerprint: null },
      },
    ];
    for (const cipher of cases) {
      expect(validateRawSyncCipherCompatibility(withId(cipher))).toEqual({
        ok: true, dataMode: 'redundant-plain-data',
      });
    }
  });

  it('normalizes only missing and null while preserving arrays and empty strings', () => {
    const cipher = fullLoginCipher();
    const data = fullLoginData();
    delete data.Notes;
    delete data.Fields;
    cipher.data = JSON.stringify(data);
    cipher.notes = null;
    cipher.fields = null;
    expect(validateRawSyncCipherCompatibility(cipher).ok).toBe(true);

    cipher.fields = [];
    expectFailure(cipher, 'data_projection_mismatch');
    cipher.fields = null;
    cipher.notes = '';
    expectFailure(cipher, 'data_projection_mismatch');
  });

  it('compares ISO timestamps by exact instant, including seven-digit server fractions', () => {
    const equivalent = fullLoginCipher();
    expect(validateRawSyncCipherCompatibility(equivalent).ok).toBe(true);

    const mismatch = fullLoginCipher();
    (mismatch.login as Record<string, unknown>).passwordRevisionDate = '2026-01-02T03:04:05.1234566Z';
    expectFailure(mismatch, 'data_projection_mismatch');

    const invalid = fullLoginCipher();
    (invalid.login as Record<string, unknown>).passwordRevisionDate = '2026-02-30T03:04:05Z';
    expectFailure(invalid, 'invalid_structured_projection');
  });

  it('requires current password-history and passkey timestamps on both representations', () => {
    const missingHistoryData = fullLoginCipher();
    const historyData = fullLoginData();
    delete (historyData.PasswordHistory as Record<string, unknown>[])[0]!.LastUsedDate;
    missingHistoryData.data = JSON.stringify(historyData);
    expectFailure(missingHistoryData, 'invalid_data_shape');

    const nullHistoryProjection = fullLoginCipher();
    (nullHistoryProjection.passwordHistory as Record<string, unknown>[])[0]!.lastUsedDate = null;
    expectFailure(nullHistoryProjection, 'invalid_structured_projection');

    const missingPasskeyData = fullLoginCipher();
    const passkeyData = fullLoginData();
    delete (passkeyData.Fido2Credentials as Record<string, unknown>[])[0]!.CreationDate;
    missingPasskeyData.data = JSON.stringify(passkeyData);
    expectFailure(missingPasskeyData, 'invalid_data_shape');

    const nullPasskeyProjection = fullLoginCipher();
    const passkey = ((nullPasskeyProjection.login as Record<string, unknown>)
      .fido2Credentials as Record<string, unknown>[])[0]!;
    passkey.creationDate = null;
    expectFailure(nullPasskeyProjection, 'invalid_structured_projection');
  });

  it.each([
    '2026-01-01T00:00:00+14:01',
    '0001-01-01T00:00:00+14:00',
    '9999-12-31T23:59:59.9999999-14:00',
  ])('rejects a DateTime-incompatible or out-of-range instant %s', (date) => {
    const cipher = fullLoginCipher();
    const data = fullLoginData();
    data.PasswordRevisionDate = date;
    cipher.data = JSON.stringify(data);
    (cipher.login as Record<string, unknown>).passwordRevisionDate = date;
    expectFailure(cipher, 'invalid_data_shape');
  });
});

describe('raw permissions validation', () => {
  it.each(['edit', 'viewPassword', 'organizationUseTotp'] as const)(
    'rejects a non-boolean %s authorization field',
    (field) => {
      expectFailure({ type: 1, [field]: 'true' }, 'invalid_cipher');
      expectFailure({ type: 1, [field]: null }, 'invalid_cipher');
    },
  );

  it('accepts omitted authorization fields so personal ciphers remain backward compatible', () => {
    expect(validateRawSyncCipherCompatibility(withId({
      type: 1,
      name: ENC.name,
      login: {},
    }))).toEqual({ ok: true, dataMode: 'structured-only' });
  });

  it.each([
    [{ delete: true, restore: false, share: true }, 'extra key'],
    [{ delete: 'true' }, 'wrong value'],
    [null, 'null'],
    [undefined, 'present undefined'],
    [[], 'array'],
    [Object.create({ delete: true }), 'custom prototype'],
  ])('rejects a non-exact permissions record: %s', (permissions) => {
    expectFailure({ type: 1, permissions }, 'invalid_permissions');
  });

  it('rejects accessors, symbols, and non-enumerable properties without invoking accessors', () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'delete', {
      enumerable: true,
      get: () => {
        getterCalls++;
        return true;
      },
    });
    expectFailure({ type: 1, permissions: accessor }, 'invalid_permissions');
    expect(getterCalls).toBe(0);

    const symbol = { delete: true } as Record<PropertyKey, unknown>;
    symbol[Symbol('hidden')] = true;
    expectFailure({ type: 1, permissions: symbol }, 'invalid_permissions');

    const hidden = Object.defineProperty({}, 'delete', { value: true, enumerable: false });
    expectFailure({ type: 1, permissions: hidden }, 'invalid_permissions');
  });

  it('accepts a null-prototype exact record and does not return permission values', () => {
    const permissions = Object.create(null) as Record<string, unknown>;
    permissions.delete = true;
    permissions.restore = null;
    const result = validateRawSyncCipherCompatibility(withId({
      type: 1, name: ENC.name, login: {}, permissions,
    }));
    expect(result).toEqual({ ok: true, dataMode: 'structured-only' });
    expect(result).not.toHaveProperty('permissions');
  });
});

describe('raw cipher data rejection', () => {
  it('exports and enforces one exact top-level raw sync allowlist', () => {
    expect(RAW_SYNC_CIPHER_FIELDS.has('data')).toBe(true);
    expect(RAW_SYNC_CIPHER_FIELDS.has('permissions')).toBe(true);
    expect(RAW_SYNC_CIPHER_FIELDS.has('partialData')).toBe(false);
    expectFailure({
      type: 1, name: ENC.name, login: {}, partialData: '2.<redacted-partial>',
    }, 'invalid_cipher');
  });

  it('rejects top-level accessors, symbols, and non-enumerable wire fields without invoking accessors', () => {
    let getterCalls = 0;
    const accessor = withId({ type: 1, login: {} } as Record<string, unknown>);
    Object.defineProperty(accessor, 'name', {
      enumerable: true,
      get: () => {
        getterCalls++;
        return ENC.name;
      },
    });
    expectFailure(accessor, 'invalid_cipher');
    expect(getterCalls).toBe(0);

    const symbol = withId({ type: 1, name: ENC.name, login: {} }) as Record<PropertyKey, unknown>;
    symbol[Symbol('wire')] = ENC.password;
    expectFailure(symbol, 'invalid_cipher');

    const hidden = withId({ type: 1, name: ENC.name, login: {} });
    Object.defineProperty(hidden, 'favorite', { value: true, enumerable: false });
    expectFailure(hidden, 'invalid_cipher');
  });

  it('strictly validates structured-only nested data, URI aliases, and payload exclusivity', () => {
    expectFailure(withId({
      type: 1, name: ENC.name, login: { future: ENC.password },
    }), 'invalid_structured_projection');
    expectFailure(withId({
      type: 1, name: ENC.name, login: { uri: '2.one', uris: [{ uri: '2.two' }] },
    }), 'login_uri_alias_mismatch');
    expectFailure(withId({
      type: 1, name: ENC.name, login: {}, card: { number: '2.number' },
    }), 'invalid_structured_projection');
    expectFailure(withId({
      type: 1, name: ENC.name, login: {}, fields: [{ type: 0, future: ENC.password }],
    }), 'invalid_structured_projection');
    expectFailure(withId({
      type: 1, name: ENC.name, login: {}, passwordHistory: [{ password: ENC.oldPassword, lastUsedDate: 'not-a-date' }],
    }), 'invalid_structured_projection');
  });

  it('strictly validates non-secret response metadata and dense arrays', () => {
    expectFailure(withId({
      type: 1, name: ENC.name, login: {}, favorite: null,
    }), 'invalid_cipher');
    expectFailure(withId({
      type: 1, name: ENC.name, login: {}, creationDate: '2026-02-30T00:00:00Z',
    }), 'invalid_cipher');
    expectFailure(withId({
      type: 1, name: ENC.name, login: {}, attachments: [{ id: 'a1', future: true }],
    }), 'invalid_cipher');
    const sparseCollections = withId({ type: 1, name: ENC.name, login: {}, collectionIds: [] as unknown[] });
    sparseCollections.collectionIds.length = 2;
    expectFailure(sparseCollections, 'invalid_cipher');
  });

  it.each([
    [undefined, 'invalid_data_type'],
    [42, 'invalid_data_type'],
    ['{', 'malformed_data'],
    ['[]', 'invalid_data_root'],
    ['null', 'invalid_data_root'],
  ] as const)('rejects invalid data value %j', (data, code) => {
    expectFailure({ type: 1, data }, code);
  });

  it('classifies only the pinned case-sensitive format_version marker as a blob', () => {
    const field = 'format_version';
    const data = JSON.stringify({ Name: ENC.name, [field]: 1, wrapped_cek: 'x', envelope: 'y' });
    expectFailure({ type: 1, data, name: ENC.name, login: {} }, 'encrypted_data_blob');
  });

  it.each(['FORMAT_VERSION', 'Format_Version'])('rejects marker lookalike %s as an unknown legacy field', (field) => {
    const data = JSON.stringify({ Name: ENC.name, [field]: 1 });
    expectFailure({ type: 1, data, name: ENC.name, login: {} }, 'unknown_data_field');
  });

  it('rejects exact and case-insensitive duplicate JSON keys before projection comparison', () => {
    expectFailure({ type: 1, data: `{"Name":"${ENC.name}","Name":"${ENC.name}"}` }, 'duplicate_data_key');
    expectFailure({ type: 1, data: `{"Name":"${ENC.name}","name":"${ENC.name}"}` }, 'duplicate_data_key');
    expectFailure({
      type: 1,
      data: `{"Name":"${ENC.name}","Uris":[{"Uri":"${ENC.uri}","uri":"${ENC.uri}"}]}`,
    }, 'duplicate_data_key');
  });

  it('rejects unknown fields at root and every nested DTO boundary', () => {
    const root = fullLoginCipher();
    root.data = JSON.stringify({ ...fullLoginData(), FutureSecret: ENC.password });
    expectFailure(root, 'unknown_data_field');

    const nested = fullLoginData();
    (nested.Uris as Record<string, unknown>[])[0]!.Future = ENC.password;
    const cipher = fullLoginCipher();
    cipher.data = JSON.stringify(nested);
    expectFailure(cipher, 'unknown_data_field');
  });

  it('treats URI checksums as opaque EncStrings and compares their ciphertext exactly', () => {
    const valid = fullLoginCipher();
    expect(validateRawSyncCipherCompatibility(valid).ok).toBe(true);

    const mismatch = fullLoginCipher();
    ((mismatch.login as Record<string, unknown>).uris as Record<string, unknown>[])[0]!.uriChecksum =
      '2.<different-encrypted-checksum>';
    expectFailure(mismatch, 'data_projection_mismatch');
  });

  it('fails closed on mismatched arrays, passkeys, fields, and history without leaking values', () => {
    const cases = [
      (cipher: Record<string, unknown>) => {
        ((cipher.login as Record<string, unknown>).uris as unknown[]).reverse();
        ((cipher.login as Record<string, unknown>).uris as unknown[]).push({ uri: '2.extra' });
      },
      (cipher: Record<string, unknown>) => {
        const passkey = ((cipher.login as Record<string, unknown>).fido2Credentials as Record<string, unknown>[])[0]!;
        passkey.keyValue = '2.secret-mismatch';
      },
      (cipher: Record<string, unknown>) => {
        (cipher.fields as Record<string, unknown>[])[0]!.value = '2.secret-mismatch';
      },
      (cipher: Record<string, unknown>) => {
        (cipher.passwordHistory as Record<string, unknown>[])[0]!.password = '2.secret-mismatch';
      },
    ];
    for (const mutate of cases) {
      const cipher = fullLoginCipher();
      mutate(cipher);
      const result = validateRawSyncCipherCompatibility(cipher);
      expect(result).toEqual({ ok: false, code: 'data_projection_mismatch' });
      expect(JSON.stringify(result)).not.toContain('secret-mismatch');
    }
  });

  it('rejects unknown or malformed structured projection fields', () => {
    const unknown = fullLoginCipher();
    (unknown.login as Record<string, unknown>).future = ENC.password;
    expectFailure(unknown, 'invalid_structured_projection');

    const sparse = fullLoginCipher();
    const uris = ((sparse.login as Record<string, unknown>).uris as unknown[]);
    uris.length = 2;
    expectFailure(sparse, 'invalid_structured_projection');
  });

  it('rejects unsupported cipher types whether data is absent or present', () => {
    expectFailure({ type: 6 }, 'unsupported_cipher_type');
    expectFailure({ type: 99, data: '{}' }, 'unsupported_cipher_type');
  });
});

describe('bounded cipher data parser', () => {
  it('enforces character and UTF-8 byte limits before parsing', () => {
    const data = JSON.stringify({ Name: '密码' });
    expect(validateRawSyncCipherCompatibility(withId({ type: 1, data }), {
      limits: { maxDataChars: data.length - 1 },
    })).toEqual({ ok: false, code: 'data_too_large' });
    expect(validateRawSyncCipherCompatibility(withId({ type: 1, data }), {
      limits: { maxDataBytes: new TextEncoder().encode(data).byteLength - 1 },
    })).toEqual({ ok: false, code: 'data_too_large' });
  });

  it.each([
    [{ maxDepth: 2 }, { Name: ENC.name, Uris: [{ Uri: ENC.uri }] }],
    [{ maxNodes: 1 }, { Name: ENC.name }],
    [{ maxProperties: 1 }, { Name: ENC.name, Notes: null }],
    [{ maxArrayLength: 1 }, { Name: ENC.name, Fields: [{ Type: 0 }, { Type: 0 }] }],
  ])('enforces structural limit %j before semantic projection', (limits, value) => {
    expect(validateRawSyncCipherCompatibility(withId({ type: 1, data: JSON.stringify(value) }), {
      limits,
    })).toEqual({ ok: false, code: 'data_limit_exceeded' });
  });

  it('rejects invalid limit overrides as programmer errors', () => {
    expect(() => validateRawSyncCipherCompatibility(withId({ type: 1 }), {
      limits: { maxDepth: 0 },
    })).toThrow(RangeError);
  });
});
