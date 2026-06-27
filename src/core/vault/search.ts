import type { CipherSummary } from './models.js';

export function filterSummaries(items: CipherSummary[], query: string): CipherSummary[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => {
    const haystack = [item.name, item.username ?? '', ...item.uris].join('\n').toLowerCase();
    return haystack.includes(q);
  });
}
