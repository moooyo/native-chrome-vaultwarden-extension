import { describe, it, expect } from 'vitest';
import { filterSummaries } from './search.js';
import type { CipherSummary } from './models.js';

const items: CipherSummary[] = [
  { id: '1', type: 1, name: 'GitHub', username: 'octo', uris: ['https://github.com'], loginUris: [{ uri: 'https://github.com' }], favorite: false },
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
