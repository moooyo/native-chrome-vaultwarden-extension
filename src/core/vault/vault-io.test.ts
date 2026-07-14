import { describe, it, expect } from 'vitest';
import { buildExportJson, parseImportJson, buildEncryptedExportJson, decryptEncryptedExport, isEncryptedExport, parseCsvImport, parseImport } from './vault-io.js';
import type { DecryptedCipher, FolderSummary } from './models.js';

const login: DecryptedCipher = {
  id: 'c1', type: 1, favorite: true, name: 'GitHub', folderId: 'f1',
  username: 'octo', password: 's3cret', totp: 'JBSWY3DPEHPK3PXP', notes: 'note',
  uris: ['https://github.com'], loginUris: [{ uri: 'https://github.com', match: 0 }],
};
const card: DecryptedCipher = {
  id: 'c2', type: 3, favorite: false, name: 'Visa', uris: [], loginUris: [],
  card: { brand: 'Visa', number: '4111111111111111', code: '123' },
};
const folders: FolderSummary[] = [{ id: 'f1', name: 'Work' }];

describe('buildExportJson', () => {
  it('produces a Bitwarden-compatible unencrypted export', () => {
    const parsed = JSON.parse(buildExportJson([login, card], folders));
    expect(parsed.encrypted).toBe(false);
    expect(parsed.folders).toEqual([{ id: 'f1', name: 'Work' }]);
    expect(parsed.items[0]).toMatchObject({
      id: 'c1', type: 1, name: 'GitHub', favorite: true, folderId: 'f1', notes: 'note',
      login: { username: 'octo', password: 's3cret', totp: 'JBSWY3DPEHPK3PXP', uris: [{ match: 0, uri: 'https://github.com' }] },
    });
    expect(parsed.items[1]).toMatchObject({ id: 'c2', type: 3, card: { brand: 'Visa', number: '4111111111111111', code: '123' } });
  });
});

describe('parseImportJson', () => {
  it('round-trips items exported by buildExportJson into CipherInput[]', () => {
    const json = buildExportJson([login, card], folders);
    const inputs = parseImportJson(json);
    expect(inputs).toHaveLength(2);
    expect(inputs[0]).toMatchObject({
      type: 1, name: 'GitHub', favorite: true,
      login: { username: 'octo', password: 's3cret', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://github.com', match: 0 }] },
    });
    expect(inputs[1]).toMatchObject({ type: 3, name: 'Visa', card: { number: '4111111111111111' } });
  });

  it('skips items without a name and tolerates missing sections', () => {
    const inputs = parseImportJson(JSON.stringify({ items: [{ type: 1 }, { type: 2, name: 'Note', notes: 'x' }] }));
    expect(inputs).toEqual([{ type: 2, name: 'Note', notes: 'x' }]);
  });

  it('throws on malformed JSON', () => {
    expect(() => parseImportJson('not json')).toThrow();
  });

  it('drops the folderId on import (folders are not recreated)', () => {
    const inputs = parseImportJson(buildExportJson([login], folders));
    expect(inputs[0]!.folderId).toBeUndefined();
  });
});

describe('encrypted export', () => {
  // Deterministic salt/guid so the encrypted blob is stable across runs.
  const deps = { randomBytes: (n: number) => new Uint8Array(n).fill(0x11), newGuid: () => 'fixed-guid' };

  it('round-trips through buildEncryptedExportJson / decryptEncryptedExport with the right password', async () => {
    const plaintext = buildExportJson([login, card], folders);
    const enc = await buildEncryptedExportJson(plaintext, 'correct horse', 600_000, deps);
    const parsed = JSON.parse(enc);
    expect(parsed).toMatchObject({ encrypted: true, passwordProtected: true, kdfType: 0, kdfIterations: 600_000 });
    expect(typeof parsed.salt).toBe('string');
    expect(typeof parsed.data).toBe('string');
    expect(enc).not.toContain('s3cret'); // payload is encrypted
    expect(isEncryptedExport(enc)).toBe(true);
    await expect(decryptEncryptedExport(enc, 'correct horse')).resolves.toBe(plaintext);
  });

  it('rejects a wrong password (validation MAC) without leaking the payload', async () => {
    const enc = await buildEncryptedExportJson(buildExportJson([login], folders), 'right', 600_000, deps);
    await expect(decryptEncryptedExport(enc, 'wrong')).rejects.toThrow(/Incorrect export password/);
  });

  it('isEncryptedExport is false for a plaintext export', () => {
    expect(isEncryptedExport(buildExportJson([login], folders))).toBe(false);
  });

  it('rejects an export with invalid kdfIterations with a clear error (not an opaque crypto error)', async () => {
    for (const kdfIterations of [0, -1, 1.5, 'nope', null]) {
      const json = JSON.stringify({
        encrypted: true, passwordProtected: true, salt: 'AAAAAAAAAAAAAAAAAAAAAA==',
        kdfType: 0, kdfIterations, encKeyValidation_DO_NOT_EDIT: '2.a|b|c', data: '2.a|b|c',
      });
      await expect(decryptEncryptedExport(json, 'pw')).rejects.toThrow(/valid KDF parameters/);
    }
  });
});

describe('parseCsvImport', () => {
  it('parses the Bitwarden CSV column shape into login + note CipherInput[]', () => {
    const csv = [
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
      'Work,1,login,GitHub,,,1,https://github.com,octo,s3cret,JBSWY3DPEHPK3PXP',
      ',0,note,A note,the body,,0,,,,',
    ].join('\n');
    const inputs = parseCsvImport(csv);
    expect(inputs).toHaveLength(2);
    expect(inputs[0]).toMatchObject({
      type: 1, name: 'GitHub', favorite: true, reprompt: true,
      login: { username: 'octo', password: 's3cret', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://github.com' }] },
    });
    expect(inputs[1]).toMatchObject({ type: 2, name: 'A note', notes: 'the body' });
  });

  it('parses a generic browser CSV (name,url,username,password) as logins', () => {
    const csv = 'name,url,username,password\nExample,https://example.com,me@example.com,hunter2\n';
    expect(parseCsvImport(csv)).toEqual([
      { type: 1, name: 'Example', login: { username: 'me@example.com', password: 'hunter2', uris: [{ uri: 'https://example.com' }] } },
    ]);
  });

  it('handles quoted fields with embedded commas, quotes, and newlines', () => {
    const csv = 'name,login_username,login_password,notes\n"Acme, Inc.",user,"p,a""ss","line1\nline2"\n';
    const inputs = parseCsvImport(csv);
    expect(inputs[0]!.name).toBe('Acme, Inc.');
    expect(inputs[0]!.login!.password).toBe('p,a"ss');
    expect(inputs[0]!.notes).toBe('line1\nline2');
  });
});

describe('parseImport (format dispatch)', () => {
  it('routes plaintext JSON', async () => {
    const inputs = await parseImport(buildExportJson([login], folders));
    expect(inputs[0]).toMatchObject({ type: 1, name: 'GitHub' });
  });

  it('routes CSV when the content is not JSON', async () => {
    const inputs = await parseImport('name,url,username,password\nX,https://x.test,u,p\n');
    expect(inputs).toEqual([{ type: 1, name: 'X', login: { username: 'u', password: 'p', uris: [{ uri: 'https://x.test' }] } }]);
  });

  it('decrypts and routes an encrypted export when given its password', async () => {
    const enc = await buildEncryptedExportJson(buildExportJson([login], folders), 'pw', 600_000, { randomBytes: (n) => new Uint8Array(n).fill(2), newGuid: () => 'g' });
    const inputs = await parseImport(enc, 'pw');
    expect(inputs[0]).toMatchObject({ type: 1, name: 'GitHub', login: { password: 's3cret' } });
  });

  it('throws when an encrypted export is imported without a password', async () => {
    const enc = await buildEncryptedExportJson(buildExportJson([login], folders), 'pw', 600_000, { randomBytes: (n) => new Uint8Array(n).fill(3), newGuid: () => 'g' });
    await expect(parseImport(enc)).rejects.toThrow(/password-protected/);
  });
});
