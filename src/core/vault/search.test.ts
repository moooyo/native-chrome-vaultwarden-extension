import { describe, it, expect } from 'vitest';
import { filterSummaries, filterByFolder, filterByCollection, filterSummariesByFolderAndQuery, filterSummariesByFolderCollectionAndQuery, NO_FOLDER, sortCipherSummaries } from './search.js';
import type { CipherSummary } from './models.js';

const items: CipherSummary[] = [
  { id: '1', type: 1, name: 'GitHub', username: 'octo', uris: ['https://github.com'], loginUris: [{ uri: 'https://github.com' }], favorite: false, folderId: 'work' },
  { id: '2', type: 1, name: 'Email', username: 'me@example.com', uris: ['https://mail.example.com'], loginUris: [{ uri: 'https://mail.example.com' }], favorite: true },
];

const collItems: CipherSummary[] = [
  { id: '1', type: 1, name: 'GitHub', uris: [], loginUris: [], favorite: false, folderId: 'work', collectionIds: ['eng'] },
  { id: '2', type: 1, name: 'Wiki', uris: [], loginUris: [], favorite: false, collectionIds: ['eng', 'ops'] },
  { id: '3', type: 1, name: 'Personal', uris: [], loginUris: [], favorite: false },
];

describe('filterSummaries', () => {
  it('returns all items for blank query', () => {
    expect(filterSummaries(items, '')).toEqual(items);
  });

  it('matches name, username, and uri case-insensitively', () => {
    expect(filterSummaries(items, 'git').map((i) => i.id)).toEqual(['1']);
    expect(filterSummaries(items, 'ME@').map((i) => i.id)).toEqual(['2']);
    expect(filterSummaries(items, 'github.com').map((i) => i.id)).toEqual(['1']);
  });

  it('requires every normalized term while allowing terms to match different targets', () => {
    expect(filterSummaries(items, 'octo github').map((i) => i.id)).toEqual(['1']);
    expect(filterSummaries(items, 'github octo').map((i) => i.id)).toEqual(['1']);
    expect(filterSummaries(items, 'github missing')).toEqual([]);
  });

  it('normalizes accents in both the query and summary targets', () => {
    const accented: CipherSummary[] = [{
      id: 'accent', type: 1, name: 'Caf\u00e9', username: 'r\u00e9sum\u00e9', uris: [], loginUris: [], favorite: false,
    }];
    expect(filterSummaries(accented, 'cafe').map((i) => i.id)).toEqual(['accent']);
    expect(filterSummaries(accented, 'resume').map((i) => i.id)).toEqual(['accent']);
    expect(filterSummaries(accented, 'caf\u00e9 r\u00e9sum\u00e9').map((i) => i.id)).toEqual(['accent']);
  });

  it('searches only URI hostnames, never paths, query strings, or fragments', () => {
    const withSecretUri: CipherSummary[] = [{
      id: 'uri', type: 1, name: 'Portal', uris: ['https://login.example/secret-path?token=hidden#private'],
      loginUris: [], favorite: false,
    }];
    expect(filterSummaries(withSecretUri, 'login.example').map((i) => i.id)).toEqual(['uri']);
    expect(filterSummaries(withSecretUri, 'secret-path')).toEqual([]);
    expect(filterSummaries(withSecretUri, 'hidden')).toEqual([]);
    expect(filterSummaries(withSecretUri, 'private')).toEqual([]);
  });

  it('matches an item id prefix only for terms of at least eight characters', () => {
    const identified: CipherSummary[] = [{
      id: 'abcdef12-3456-7890-abcd-ef1234567890', type: 1, name: 'Unrelated',
      uris: [], loginUris: [], favorite: false,
    }];
    expect(filterSummaries(identified, 'abcdef1')).toEqual([]);
    expect(filterSummaries(identified, 'ABCDEF12').map((i) => i.id)).toEqual([
      'abcdef12-3456-7890-abcd-ef1234567890',
    ]);
  });

  it('reuses normalized targets per item across repeated filters', () => {
    // A summary whose `name` getter counts reads: the targets are built by reading name/username/uris,
    // so a second filter that reuses the cache must not read the fields again.
    let nameReads = 0;
    const item = {
      id: 'x', type: 1, favorite: false, username: 'octo', uris: ['https://github.com'], loginUris: [],
      get name() { nameReads++; return 'GitHub'; },
    } as unknown as CipherSummary;
    const list = [item];

    expect(filterSummaries(list, 'git').map((i) => i.id)).toEqual(['x']);
    const afterFirst = nameReads;
    expect(afterFirst).toBeGreaterThan(0);

    expect(filterSummaries(list, 'hub').map((i) => i.id)).toEqual(['x']);
    // The second filter reused the cached targets, so it did not read the item fields again.
    expect(nameReads).toBe(afterFirst);
  });
});

describe('sortCipherSummaries', () => {
  const summary = (
    id: string,
    name: string,
    options: Partial<CipherSummary> = {},
  ): CipherSummary => ({
    id,
    type: 2,
    name,
    uris: [],
    loginUris: [],
    favorite: false,
    ...options,
  } as CipherSummary);

  it('uses locale-aware natural ordering without mutating the source array', () => {
    const source = [summary('10', 'Item 10'), summary('2', 'Item 2')];

    expect(sortCipherSummaries(source, 'en').map((item) => item.id)).toEqual(['2', '10']);
    expect(source.map((item) => item.id)).toEqual(['10', '2']);
  });

  it('uses base sensitivity and preserves stable order for equivalent non-login names', () => {
    const source = [summary('accented', 'Caf\u00e9'), summary('plain', 'cafe')];

    expect(sortCipherSummaries(source, 'en').map((item) => item.id)).toEqual([
      'accented',
      'plain',
    ]);
  });

  it('orders equal login names by username using the same collator', () => {
    const source = [
      summary('ten', 'Portal', { type: 1, username: 'user10' }),
      summary('two', 'portal', { type: 1, username: 'user2' }),
      summary('one', 'Portal', { type: 1, username: 'User1' }),
    ];

    expect(sortCipherSummaries(source, 'en').map((item) => item.id)).toEqual([
      'one',
      'two',
      'ten',
    ]);
  });

  it('keeps undecryptable placeholders ahead of readable items', () => {
    const source = [
      summary('readable', 'A readable item'),
      summary('broken-b', '(undecryptable)', { undecryptable: true }),
      summary('broken-a', '(undecryptable)', { undecryptable: true }),
    ];

    expect(sortCipherSummaries(source, 'en').map((item) => item.id)).toEqual([
      'broken-b',
      'broken-a',
      'readable',
    ]);
  });

  it('falls back without throwing for an invalid locale', () => {
    expect(() => sortCipherSummaries([
      summary('b', 'Beta'),
      summary('a', 'Alpha'),
    ], 'not_a_valid_locale!')).not.toThrow();
  });
});

describe('filterByFolder', () => {
  it('returns all items when folderId is null/undefined (All folders)', () => {
    expect(filterByFolder(items, null)).toEqual(items);
    expect(filterByFolder(items, undefined)).toEqual(items);
    expect(filterByFolder(items, '')).toEqual(items);
  });

  it('returns only items in a concrete folder', () => {
    expect(filterByFolder(items, 'work').map((i) => i.id)).toEqual(['1']);
  });

  it('returns only items with no folder for the NO_FOLDER sentinel', () => {
    expect(filterByFolder(items, NO_FOLDER).map((i) => i.id)).toEqual(['2']);
  });

  it('returns [] for an unknown folderId', () => {
    expect(filterByFolder(items, 'nope')).toEqual([]);
  });
});

describe('filterSummariesByFolderAndQuery', () => {
  it('composes folder and text filters', () => {
    expect(filterSummariesByFolderAndQuery(items, 'work', 'git').map((i) => i.id)).toEqual(['1']);
    expect(filterSummariesByFolderAndQuery(items, NO_FOLDER, 'git')).toEqual([]);
  });
});

describe('filterByCollection', () => {
  it('returns all items when collectionId is null/undefined/empty', () => {
    expect(filterByCollection(collItems, null)).toEqual(collItems);
    expect(filterByCollection(collItems, undefined)).toEqual(collItems);
    expect(filterByCollection(collItems, '')).toEqual(collItems);
  });

  it('returns only items that belong to a concrete collection', () => {
    expect(filterByCollection(collItems, 'eng').map((i) => i.id)).toEqual(['1', '2']);
    expect(filterByCollection(collItems, 'ops').map((i) => i.id)).toEqual(['2']);
  });

  it('returns [] for an unknown collectionId', () => {
    expect(filterByCollection(collItems, 'nope')).toEqual([]);
  });
});

describe('filterSummariesByFolderCollectionAndQuery', () => {
  it('composes folder, collection, and text filters', () => {
    expect(filterSummariesByFolderCollectionAndQuery(collItems, null, 'eng', '').map((i) => i.id)).toEqual(['1', '2']);
    expect(filterSummariesByFolderCollectionAndQuery(collItems, 'work', 'eng', '').map((i) => i.id)).toEqual(['1']);
    expect(filterSummariesByFolderCollectionAndQuery(collItems, null, 'eng', 'wiki').map((i) => i.id)).toEqual(['2']);
  });
});
