export type PermissionsContains = (permissions: { origins: string[] }) => Promise<boolean>;

/** Reduces an HTTP(S) URL to a Chrome host match pattern (`${origin}/*`). Returns `undefined` for
 *  any non-HTTP(S) scheme (`about:`/`data:`/`blob:`/`file:`/`chrome:`/…) or unparseable input —
 *  those are never valid `permissions.contains` origin patterns, so callers must fail closed
 *  rather than hand Chrome a value it would reject. A full frame URL commonly carries a path,
 *  query, and fragment; only the origin is meaningful for a host permission. */
export function originMatchPattern(url: string): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return undefined;
  return `${parsed.origin}/*`;
}

/** Wraps `permissions.contains` so the coordinator can pass a raw browser-reported frame URL and
 *  still get a correct permanent-host-permission answer. The URL is normalized to an `${origin}/*`
 *  match pattern first; a non-HTTP(S)/unparseable URL fails closed (returns `false`) without ever
 *  calling `permissions.contains`, because Chrome rejects such patterns and a rejection would
 *  otherwise abort the whole tab Suggestions flow instead of just skipping the one bad frame. */
export function createHostAccessCheck(contains: PermissionsContains): (url: string) => Promise<boolean> {
  return async (url) => {
    const pattern = originMatchPattern(url);
    if (pattern === undefined) return false;
    return contains({ origins: [pattern] });
  };
}
