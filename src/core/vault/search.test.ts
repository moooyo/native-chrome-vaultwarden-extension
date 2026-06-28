import { describe, it, expect } from 'vitest';
import { filterSummaries, filterByFolder, filterSummariesByFolderAndQuery, NO_FOLDER } from './search.js';
import type { CipherSummary } from './models.js';

const items: CipherSummary[] = [
  { id: '1', type: 1, name: 'GitHub', username: 'octo', uris: ['https://github.com'], loginUris: [{ uri: 'https://github.com' }], favorite: false, folderId: 'work' },
  { id: '2', type: 1, name: 'Email', username: 'me@example.com', uris: ['https://mail.example.com'], loginUris: [{ uri: 'https://mail.example.com' }], favorite: true },
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
