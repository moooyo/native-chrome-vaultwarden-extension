export const AUTOFILL_POLICY_ACTIONS = [
  'candidate',
  'intent',
  'page-load',
  'save',
  'update',
] as const;

export type AutofillPolicyAction = (typeof AUTOFILL_POLICY_ACTIONS)[number];
export type AutofillBlockMatch = 'exact' | 'host-and-subdomains';

/**
 * A string is the convenient persisted form and blocks the named host plus its subdomains.
 * The object form makes an exact-host/origin rule explicit. A pattern is either a bare hostname or
 * an HTTP(S) origin; paths, credentials, queries, and fragments are never accepted as policy input.
 */
export type AutofillBlocklistEntryInput = string | {
  readonly pattern: string;
  readonly match?: AutofillBlockMatch;
};

export type AutofillBlocklistErrorCode =
  | 'invalid_list'
  | 'too_many_entries'
  | 'invalid_entry'
  | 'invalid_match'
  | 'invalid_pattern'
  | 'unsupported_scheme';

export interface AutofillBlocklistError {
  readonly index?: number;
  readonly code: AutofillBlocklistErrorCode;
}

export type NormalizedAutofillBlockRule = Readonly<{
  kind: 'host';
  hostname: string;
  match: AutofillBlockMatch;
  pattern: string;
}> | Readonly<{
  kind: 'origin';
  scheme: 'http:' | 'https:';
  hostname: string;
  port: string;
  match: AutofillBlockMatch;
  pattern: string;
}>;

export interface NormalizedAutofillBlocklist {
  readonly valid: boolean;
  readonly rules: readonly NormalizedAutofillBlockRule[];
  readonly errors: readonly AutofillBlocklistError[];
}

export interface AutofillPolicyRequest {
  readonly action: AutofillPolicyAction;
  /** Browser-authoritative frame URL, not a page-provided URL. */
  readonly url: string;
}

export type AutofillPolicyDecision =
  | Readonly<{
      allowed: true;
      action: AutofillPolicyAction;
      url: string;
      origin: string;
    }>
  | Readonly<{
      allowed: false;
      reason: 'invalid_action' | 'invalid_policy' | 'invalid_url' | 'blocked';
      rule?: NormalizedAutofillBlockRule;
    }>;

export const MAX_AUTOFILL_BLOCKLIST_ENTRIES = 256;
const MAX_PATTERN_LENGTH = 2_048;
const MAX_TARGET_URL_LENGTH = 65_536;

/** Resolve the per-login tri-state without letting malformed values inherit permissively. */
export function pageLoadAutofillAllowed(
  itemOverride: unknown,
  effectiveDefault: boolean,
): boolean {
  if (itemOverride === true) return true;
  if (itemOverride === false) return false;
  return (itemOverride === null || itemOverride === undefined) && effectiveDefault === true;
}

/**
 * Canonicalize untrusted persisted blocklist data. Invalid entries are reported rather than silently
 * discarded; `decideAutofillPolicy` treats any such list as invalid and denies every action.
 */
export function normalizeAutofillBlocklist(value: unknown): NormalizedAutofillBlocklist {
  if (!Array.isArray(value)) return invalidList('invalid_list');
  if (value.length > MAX_AUTOFILL_BLOCKLIST_ENTRIES) return invalidList('too_many_entries');

  const errors: AutofillBlocklistError[] = [];
  const unique = new Map<string, NormalizedAutofillBlockRule>();
  for (let index = 0; index < value.length; index += 1) {
    let parsed: ReturnType<typeof normalizeEntry>;
    try {
      // Indexing rather than `forEach` makes a sparse slot an invalid entry instead of skipping it.
      parsed = normalizeEntry(value[index]);
    } catch {
      parsed = { code: 'invalid_entry' };
    }
    if ('code' in parsed) {
      errors.push(Object.freeze({ index, code: parsed.code }));
      continue;
    }
    unique.set(ruleKey(parsed), parsed);
  }

  const rules = [...unique.values()].sort((left, right) => compareText(ruleKey(left), ruleKey(right)));
  return Object.freeze({
    valid: errors.length === 0,
    rules: Object.freeze(rules),
    errors: Object.freeze(errors),
  });
}

/**
 * One policy decision for every autofill-related surface. Callers must normalize persisted policy
 * first, then use this for candidate discovery, intent issuance, page-load fill, save, and update.
 */
export function decideAutofillPolicy(
  blocklist: NormalizedAutofillBlocklist,
  request: AutofillPolicyRequest,
): AutofillPolicyDecision {
  if (!isAutofillPolicyAction(request?.action)) {
    return Object.freeze({ allowed: false, reason: 'invalid_action' });
  }
  if (!isUsableBlocklist(blocklist)) {
    return Object.freeze({ allowed: false, reason: 'invalid_policy' });
  }
  const target = normalizeTargetUrl(request.url);
  if (!target) return Object.freeze({ allowed: false, reason: 'invalid_url' });

  const matched = blocklist.rules.find((rule) => ruleMatches(rule, target));
  if (matched) return Object.freeze({ allowed: false, reason: 'blocked', rule: matched });
  return Object.freeze({
    allowed: true,
    action: request.action,
    url: target.url,
    origin: target.origin,
  });
}

function invalidList(code: AutofillBlocklistErrorCode): NormalizedAutofillBlocklist {
  return Object.freeze({
    valid: false,
    rules: Object.freeze([]),
    errors: Object.freeze([Object.freeze({ code })]),
  });
}

function normalizeEntry(
  value: unknown,
): NormalizedAutofillBlockRule | { readonly code: AutofillBlocklistErrorCode } {
  let pattern: unknown;
  let match: unknown = 'host-and-subdomains';
  if (typeof value === 'string') {
    pattern = value;
  } else if (isRecord(value)) {
    pattern = value.pattern;
    if (value.match !== undefined) match = value.match;
  } else {
    return { code: 'invalid_entry' };
  }
  if (match !== 'exact' && match !== 'host-and-subdomains') return { code: 'invalid_match' };
  if (typeof pattern !== 'string') return { code: 'invalid_pattern' };
  const trimmed = pattern.trim();
  if (!trimmed || trimmed.length > MAX_PATTERN_LENGTH) return { code: 'invalid_pattern' };

  if (/^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return { code: 'invalid_pattern' };
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return { code: 'unsupported_scheme' };
    if (
      url.username
      || url.password
      || !url.hostname
      || (url.pathname !== '' && url.pathname !== '/')
      || url.search
      || url.hash
    ) return { code: 'invalid_pattern' };
    const hostname = normalizeHostname(url.hostname);
    if (!hostname) return { code: 'invalid_pattern' };
    const scheme = url.protocol;
    const port = url.port;
    const canonicalPattern = `${scheme}//${hostname}${port ? `:${port}` : ''}`;
    return Object.freeze({ kind: 'origin', scheme, hostname, port, match, pattern: canonicalPattern });
  }

  if (/[\s/@?#]/.test(trimmed)) return { code: 'invalid_pattern' };
  let url: URL;
  try {
    url = new URL(`https://${trimmed}`);
  } catch {
    return { code: 'invalid_pattern' };
  }
  if (url.username || url.password || !url.hostname || url.port || url.pathname !== '/' || url.search || url.hash) {
    return { code: 'invalid_pattern' };
  }
  const hostname = normalizeHostname(url.hostname);
  if (!hostname) return { code: 'invalid_pattern' };
  return Object.freeze({ kind: 'host', hostname, match, pattern: hostname });
}

interface NormalizedTargetUrl {
  readonly url: string;
  readonly origin: string;
  readonly scheme: 'http:' | 'https:';
  readonly hostname: string;
  readonly port: string;
}

function normalizeTargetUrl(value: unknown): NormalizedTargetUrl | undefined {
  if (typeof value !== 'string' || !value || value.length > MAX_TARGET_URL_LENGTH) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return undefined;
  }
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
    || parsed.username
    || parsed.password
    || !parsed.hostname
  ) return undefined;
  const hostname = normalizeHostname(parsed.hostname);
  if (!hostname) return undefined;
  parsed.hostname = hostname;
  parsed.hash = '';
  return Object.freeze({
    url: parsed.href,
    origin: parsed.origin,
    scheme: parsed.protocol,
    hostname,
    port: parsed.port,
  });
}

function normalizeHostname(value: string): string | undefined {
  const lower = value.toLowerCase();
  const hostname = lower.endsWith('.') ? lower.slice(0, -1) : lower;
  if (!hostname || hostname.length > 253 || hostname.includes('*')) return undefined;
  if (hostname.startsWith('[') && hostname.endsWith(']')) return hostname;
  const labels = hostname.split('.');
  if (labels.some((label) => (
    !label
    || label.length > 63
    || !/^[a-z\d_](?:[a-z\d_-]*[a-z\d_])?$/i.test(label)
  ))) return undefined;
  return hostname;
}

function ruleMatches(rule: NormalizedAutofillBlockRule, target: NormalizedTargetUrl): boolean {
  if (rule.kind === 'origin' && (rule.scheme !== target.scheme || rule.port !== target.port)) return false;
  if (target.hostname === rule.hostname) return true;
  return rule.match === 'host-and-subdomains' && target.hostname.endsWith(`.${rule.hostname}`);
}

function ruleKey(rule: NormalizedAutofillBlockRule): string {
  const location = rule.kind === 'origin'
    ? `${rule.scheme}//${rule.hostname}:${rule.port}`
    : `*://${rule.hostname}:*`;
  return `${rule.kind}|${location}|${rule.match}`;
}

function isUsableBlocklist(value: unknown): value is NormalizedAutofillBlocklist {
  if (!isRecord(value) || value.valid !== true || !Array.isArray(value.rules) || !Array.isArray(value.errors)) return false;
  if (value.errors.length !== 0 || value.rules.length > MAX_AUTOFILL_BLOCKLIST_ENTRIES) return false;
  return value.rules.every(isNormalizedRule);
}

function isNormalizedRule(value: unknown): value is NormalizedAutofillBlockRule {
  if (!isRecord(value)) return false;
  if (value.kind !== 'host' && value.kind !== 'origin') return false;
  if (typeof value.hostname !== 'string' || normalizeHostname(value.hostname) !== value.hostname) return false;
  if (value.match !== 'exact' && value.match !== 'host-and-subdomains') return false;
  if (typeof value.pattern !== 'string') return false;
  if (value.kind === 'host') return value.pattern === value.hostname;
  if ((value.scheme !== 'http:' && value.scheme !== 'https:') || typeof value.port !== 'string') return false;
  return value.pattern === `${value.scheme}//${value.hostname}${value.port ? `:${value.port}` : ''}`;
}

function isAutofillPolicyAction(value: unknown): value is AutofillPolicyAction {
  return typeof value === 'string' && (AUTOFILL_POLICY_ACTIONS as readonly string[]).includes(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
