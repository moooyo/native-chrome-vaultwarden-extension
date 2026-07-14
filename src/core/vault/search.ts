import type { CipherSummary } from './models.js';

export const NO_FOLDER = '__none__';

/**
 * Per-summary lowercased search blob (name + username + newline-joined uris), memoized so a
 * multi-keystroke search doesn't rebuild the same string for every item on every keystroke.
 * Summaries are rebuilt as fresh objects on every sync, so the entries fall out of the WeakMap
 * with the stale objects — no explicit invalidation is needed.
 */
const haystackCache = new WeakMap<CipherSummary, string>();

function haystackFor(item: CipherSummary): string {
  let haystack = haystackCache.get(item);
  if (haystack === undefined) {
    haystack = [item.name, item.username ?? '', ...item.uris].join('\n').toLowerCase();
    haystackCache.set(item, haystack);
  }
  return haystack;
}

export function filterSummaries(items: CipherSummary[], query: string): CipherSummary[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => haystackFor(item).includes(q));
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

/** Filter by collection. null/undefined/'' = all; otherwise items belonging to that collection. */
export function filterByCollection(items: CipherSummary[], collectionId: string | null | undefined): CipherSummary[] {
  if (!collectionId) return items;
  return items.filter((i) => i.collectionIds?.includes(collectionId));
}

export function filterSummariesByFolderAndQuery(
  items: CipherSummary[],
  folderId: string | null | undefined,
  query: string,
): CipherSummary[] {
  return filterSummaries(filterByFolder(items, folderId), query);
}

export function filterSummariesByFolderCollectionAndQuery(
  items: CipherSummary[],
  folderId: string | null | undefined,
  collectionId: string | null | undefined,
  query: string,
): CipherSummary[] {
  return filterSummaries(filterByCollection(filterByFolder(items, folderId), collectionId), query);
}
