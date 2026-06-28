import { describe, it, expect } from 'vitest';
import { buildExportJson, parseImportJson } from './vault-io.js';
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
