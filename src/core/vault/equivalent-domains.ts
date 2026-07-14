// Equivalent domains: groups of registrable domains that autofill should treat as the same site
// (e.g. google.com / youtube.com). A curated subset of Bitwarden's global list, merged with any
// user-defined groups from /sync. Domains are compared as registrable base domains (eTLD+1).

export const BUILTIN_EQUIVALENT_DOMAINS: string[][] = [
  ['google.com', 'youtube.com', 'gmail.com', 'googlemail.com', 'google.co.uk'],
  ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.es', 'amazon.it', 'amazon.com.au', 'amazon.co.jp', 'amazon.in'],
  ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
  ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com', 'office365.com', 'microsoftonline.com'],
  ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.ca', 'ebay.com.au', 'ebay.fr', 'ebay.it', 'ebay.es'],
  ['paypal.com', 'paypal.me'],
  ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com'],
  ['yahoo.com', 'yahoo.co.uk', 'yahoo.co.jp', 'ymail.com', 'rocketmail.com'],
  ['atlassian.com', 'atlassian.net', 'jira.com', 'bitbucket.org', 'trello.com'],
  ['steampowered.com', 'steamcommunity.com'],
  ['discord.com', 'discordapp.com'],
  ['stackexchange.com', 'stackoverflow.com', 'superuser.com', 'serverfault.com', 'askubuntu.com'],
  ['wikipedia.org', 'wikimedia.org', 'wiktionary.org'],
  ['nytimes.com', 'nyt.com'],
];

/**
 * Build a domain -> group-id index from the built-in list plus any user-defined groups. Two domains
 * are equivalent when they share a group id. Groups that share any domain are merged (union-find) into
 * a single component, so a domain listed in more than one group ends up equivalent to every member of
 * every group it appears in — matching Bitwarden's "union all groups containing the domain" behavior.
 *
 * `excludedDomains` carries the domains of server global-equivalence groups the user has switched off
 * (globalEquivalentDomains[].excluded). Any built-in group containing such a domain is dropped, so the
 * client honors the server's Domain Rules. User-defined groups are always kept.
 */
export function buildEquivalentDomainIndex(userGroups: string[][] = [], excludedDomains: string[] = []): Map<string, number> {
  const excluded = new Set(excludedDomains.map((d) => d.toLowerCase()));
  const builtins = BUILTIN_EQUIVALENT_DOMAINS.filter((group) => !group.some((d) => excluded.has(d.toLowerCase())));
  const groups = [...builtins, ...userGroups];

  // Union-find over group indices: whenever a domain appears in two groups, union those groups so
  // overlapping groups collapse into one component with a single canonical id.
  const parent = groups.map((_, i) => i);
  const find = (x: number): number => {
    let root = x;
    while (parent[root] !== root) {
      const next = parent[root];
      if (next === undefined) break; // unreachable for valid indices; keeps strict indexing happy
      root = next;
    }
    return root;
  };
  const union = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[ra] = rb;
  };

  const firstSeenGroup = new Map<string, number>();
  groups.forEach((group, gi) => {
    for (const domain of group) {
      const d = domain.toLowerCase();
      const prev = firstSeenGroup.get(d);
      if (prev === undefined) firstSeenGroup.set(d, gi);
      else union(prev, gi);
    }
  });

  // Map every domain to its component's canonical id. A shared domain is written from each of its
  // groups, but all those groups now resolve to the same root, so the id is consistent.
  const index = new Map<string, number>();
  groups.forEach((group, gi) => {
    const id = find(gi);
    for (const domain of group) index.set(domain.toLowerCase(), id);
  });
  return index;
}

/** True when two registrable base domains are the same site (equal, or in the same equivalence group). */
export function areDomainsEquivalent(a: string, b: string, index: Map<string, number>): boolean {
  if (!a || !b) return false;
  const da = a.toLowerCase();
  const db = b.toLowerCase();
  if (da === db) return true;
  const ga = index.get(da);
  const gb = index.get(db);
  return ga !== undefined && ga === gb;
}
