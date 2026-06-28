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
  ['github.com', 'githubusercontent.com', 'github.io'],
  ['atlassian.com', 'atlassian.net', 'jira.com', 'bitbucket.org', 'trello.com'],
  ['steampowered.com', 'steamcommunity.com'],
  ['discord.com', 'discordapp.com'],
  ['stackexchange.com', 'stackoverflow.com', 'superuser.com', 'serverfault.com', 'askubuntu.com'],
  ['wikipedia.org', 'wikimedia.org', 'wiktionary.org'],
  ['nytimes.com', 'nyt.com'],
];

/**
 * Build a domain -> group-id index from the built-in list plus any user-defined groups. Two domains
 * are equivalent when they share a group id. (Groups are kept distinct; a domain listed in more than
 * one group takes the last group id — overlaps are rare in the curated list.)
 */
export function buildEquivalentDomainIndex(userGroups: string[][] = []): Map<string, number> {
  const index = new Map<string, number>();
  let groupId = 0;
  for (const group of [...BUILTIN_EQUIVALENT_DOMAINS, ...userGroups]) {
    const id = groupId++;
    for (const domain of group) index.set(domain.toLowerCase(), id);
  }
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
