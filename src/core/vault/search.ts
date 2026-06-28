import type { CipherSummary } from './models.js';

export const NO_FOLDER = '__none__';

export function filterSummaries(items: CipherSummary[], query: string): CipherSummary[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => {
    const haystack = [item.name, item.username ?? '', ...item.uris].join('\n').toLowerCase();
    return haystack.includes(q);
  });
}

/**
 * Filter by folder. null/undefined/'' = all folders; NO_FOLDER = items without a folder;
 * otherwise items in that folder.
 */
export function filterByFolder(items: CipherSummary[], folderId: string | null | undefined): CipherSummary[] {
  if (!folderId) return items;
  if (folderId === NO_FOLDER) return items.filter((i) => !i.folderId);
  return items.filter((i) => i.folderId === folderId);
}

export function filterSummariesByFolderAndQuery(
  items: CipherSummary[],
  folderId: string | null | undefined,
  query: string,
): CipherSummary[] {
  return filterSummaries(filterByFolder(items, folderId), query);
}
