import type { CipherSummary } from './models.js';

export const NO_FOLDER = '__none__';

/**
 * Per-summary normalized search targets. Full URI paths and query strings are deliberately omitted:
 * matching them is surprising and can make secrets embedded in saved URLs discoverable through the
 * search surface. Summaries are rebuilt after sync, so stale WeakMap entries are reclaimed naturally.
 */
const targetCache = new WeakMap<CipherSummary, readonly string[]>();

export type CipherSummaryComparator = (left: CipherSummary, right: CipherSummary) => number;

/**
 * Build the same locale-aware comparator used by the official client for the main vault list.
 * Undecryptable placeholders stay at the top so a corrupt item remains visible instead of being
 * buried among normally sorted entries. Returning zero for exact ties deliberately relies on the
 * stable Array#sort contract and preserves the server order of otherwise equivalent summaries.
 */
export function createCipherSummaryComparator(
  locale?: string | readonly string[],
): CipherSummaryComparator {
  let collator: Intl.Collator | undefined;
  try {
    collator = new Intl.Collator(locale as string | string[] | undefined, {
      numeric: true,
      sensitivity: 'base',
    });
  } catch {
    // An invalid or unsupported locale must not make a successfully decrypted vault unavailable.
  }

  const compare = (left: string, right: string): number => (
    collator?.compare(left, right) ?? left.localeCompare(right)
  );

  return (left, right) => {
    if (left.undecryptable !== right.undecryptable) return left.undecryptable ? -1 : 1;

    const byName = compare(left.name, right.name);
    if (byName !== 0 || left.type !== 1 || right.type !== 1) return byName;

    // The official comparator appends the username to the already-equal display name. Keeping the
    // name in this second comparison preserves its behavior for case/diacritic-equivalent names.
    return compare(left.name + (left.username ?? ''), right.name + (right.username ?? ''));
  };
}

export function sortCipherSummaries(
  items: readonly CipherSummary[],
  locale?: string | readonly string[],
): CipherSummary[] {
  return [...items].sort(createCipherSummaryComparator(locale));
}

function targetsFor(item: CipherSummary): readonly string[] {
  let targets = targetCache.get(item);
  if (targets === undefined) {
    targets = Object.freeze([
      item.name,
      item.username ?? '',
      item.subtitle ?? '',
      ...item.uris.map(searchableUriHostname),
    ].map(normalizeSearchText));
    targetCache.set(item, targets);
  }
  return targets;
}

/** Match official basic-search semantics: every whitespace-delimited term must match somewhere. */
export function filterSummaries(
  items: readonly CipherSummary[],
  query: string,
): CipherSummary[] {
  const terms = normalizeSearchText(query.trim()).split(/\s+/u).filter(Boolean);
  if (terms.length === 0) return [...items];
  return items.filter((item) => terms.every((term) => (
    targetsFor(item).some((target) => target.includes(term))
      || (term.length >= 8 && item.id.toLowerCase().startsWith(term))
  )));
}

function normalizeSearchText(value: string): string {
  return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/gu, '');
}

function searchableUriHostname(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return '';
  }
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
