export const WEBSITE_PASSKEY_PERMISSIONS_POLICY_FEATURES = Object.freeze({
  create: 'publickey-credentials-create',
  get: 'publickey-credentials-get',
} as const);

export type WebsitePasskeyOperation = keyof typeof WEBSITE_PASSKEY_PERMISSIONS_POLICY_FEATURES;
export type WebsitePasskeyPermissionsPolicyFeature =
  (typeof WEBSITE_PASSKEY_PERMISSIONS_POLICY_FEATURES)[WebsitePasskeyOperation];

export type WebsitePasskeyPolicyAllowlistItem =
  | Readonly<{ type: 'self' | 'wildcard' }>
  | Readonly<{ type: 'origin'; value: string }>;

export type WebsitePasskeyResolvedPolicyAllowlistItem =
  | Readonly<{ type: 'wildcard' }>
  | Readonly<{ type: 'origin'; value: string }>;

export type WebsitePasskeyHeaderPolicy = Readonly<Partial<Record<
  WebsitePasskeyPermissionsPolicyFeature,
  readonly WebsitePasskeyPolicyAllowlistItem[]
>>>;

export type WebsitePasskeyContainerPolicy = Readonly<Partial<Record<
  WebsitePasskeyPermissionsPolicyFeature,
  readonly WebsitePasskeyResolvedPolicyAllowlistItem[]
>>>;

export type WebsitePasskeyPolicyParseResult<Value> =
  | Readonly<{ ok: true; value: Value }>
  | Readonly<{ ok: false }>;

const MAX_HEADER_BYTES = 16 * 1024;
const MAX_ALLOW_ATTRIBUTE_BYTES = 4 * 1024;
const MAX_DICTIONARY_MEMBERS = 128;
const MAX_ALLOWLIST_ITEMS = 64;
const FEATURES = new Set<WebsitePasskeyPermissionsPolicyFeature>(
  Object.values(WEBSITE_PASSKEY_PERMISSIONS_POLICY_FEATURES),
);

type LexedItem =
  | Readonly<{ kind: 'token' | 'string'; value: string }>
  | Readonly<{ kind: 'unknown' }>;

/** Parse the RFC 8941 dictionary subset used by the Permissions-Policy response header. */
export function parseWebsitePasskeyPermissionsPolicyHeader(
  headerValues: readonly string[],
): WebsitePasskeyPolicyParseResult<WebsitePasskeyHeaderPolicy> {
  if (!Array.isArray(headerValues) || headerValues.length > 16) return Object.freeze({ ok: false });
  if (headerValues.some((value) => typeof value !== 'string' || /[\r\n\0]/u.test(value))) {
    return Object.freeze({ ok: false });
  }
  const combined = headerValues.join(', ');
  if (utf8Length(combined) > MAX_HEADER_BYTES) return Object.freeze({ ok: false });
  if (combined.trim() === '') return Object.freeze({ ok: true, value: Object.freeze({}) });

  try {
    const members = new StructuredPolicyParser(combined).parse();
    const policy: Partial<Record<WebsitePasskeyPermissionsPolicyFeature, readonly WebsitePasskeyPolicyAllowlistItem[]>> = {};
    for (const member of members) {
      if (!FEATURES.has(member.feature as WebsitePasskeyPermissionsPolicyFeature)) continue;
      const feature = member.feature as WebsitePasskeyPermissionsPolicyFeature;
      if (member.items === null) return Object.freeze({ ok: false });
      const allowlist: WebsitePasskeyPolicyAllowlistItem[] = [];
      for (const item of member.items) {
        const parsed = headerAllowlistItem(item);
        if (!parsed) return Object.freeze({ ok: false });
        allowlist.push(parsed);
      }
      policy[feature] = Object.freeze(allowlist);
    }
    return Object.freeze({ ok: true, value: Object.freeze(policy) });
  } catch {
    return Object.freeze({ ok: false });
  }
}

/** Parse iframe allow and resolve self/src against browser-owned origins. */
export function parseWebsitePasskeyIframeAllowAttribute(
  raw: string,
  childOrigin: string,
  parentOrigin: string,
): WebsitePasskeyPolicyParseResult<WebsitePasskeyContainerPolicy> {
  if (typeof raw !== 'string' || /[\r\n\0]/u.test(raw) || utf8Length(raw) > MAX_ALLOW_ATTRIBUTE_BYTES) {
    return Object.freeze({ ok: false });
  }
  const child = canonicalOrigin(childOrigin);
  const parent = canonicalOrigin(parentOrigin);
  if (!child || child !== childOrigin || !parent || parent !== parentOrigin) return Object.freeze({ ok: false });

  const policy: Partial<Record<WebsitePasskeyPermissionsPolicyFeature, readonly WebsitePasskeyResolvedPolicyAllowlistItem[]>> = {};
  const directives = raw.split(';');
  if (directives.length > MAX_DICTIONARY_MEMBERS) return Object.freeze({ ok: false });
  for (const rawDirective of directives) {
    const directive = rawDirective.trim();
    if (!directive) continue;
    const tokens = directive.split(/\s+/u);
    const featureName = tokens.shift()?.toLowerCase();
    if (!featureName || !/^[a-z][a-z0-9-]*$/u.test(featureName) || tokens.length > MAX_ALLOWLIST_ITEMS) {
      return Object.freeze({ ok: false });
    }
    const allowlist: WebsitePasskeyResolvedPolicyAllowlistItem[] = [];
    const deny = tokens.includes("'none'");
    if (deny && tokens.some((token) => token !== "'none'")) return Object.freeze({ ok: false });
    if (!deny) {
      for (const token of tokens.length === 0 ? ["'src'"] : tokens) {
        const item = containerAllowlistItem(token, child, parent);
        if (!item) return Object.freeze({ ok: false });
        allowlist.push(item);
      }
    }
    if (FEATURES.has(featureName as WebsitePasskeyPermissionsPolicyFeature)) {
      policy[featureName as WebsitePasskeyPermissionsPolicyFeature] = Object.freeze(allowlist);
    }
  }
  return Object.freeze({ ok: true, value: Object.freeze(policy) });
}

interface ParsedMember {
  readonly feature: string;
  readonly items: readonly LexedItem[] | null;
}

class StructuredPolicyParser {
  #position = 0;

  constructor(private readonly input: string) {}

  parse(): readonly ParsedMember[] {
    const members: ParsedMember[] = [];
    this.#skipWhitespace();
    while (!this.#atEnd()) {
      if (members.length >= MAX_DICTIONARY_MEMBERS) throw new Error('too many policy members');
      members.push(this.#parseMember());
      this.#skipWhitespace();
      if (this.#atEnd()) break;
      this.#expect(',');
      this.#position += 1;
      this.#skipWhitespace();
      if (this.#atEnd()) throw new Error('trailing comma');
    }
    return Object.freeze(members);
  }

  #parseMember(): ParsedMember {
    const feature = this.#parseKey();
    let items: readonly LexedItem[] | null = null;
    if (this.input[this.#position] === '=') {
      this.#position += 1;
      items = this.input[this.#position] === '('
        ? this.#parseInnerList()
        : Object.freeze([this.#parseBareItemWithParameters()]);
    }
    this.#skipParameters();
    return Object.freeze({ feature, items });
  }

  #parseInnerList(): readonly LexedItem[] {
    this.#expect('(');
    this.#position += 1;
    const items: LexedItem[] = [];
    for (;;) {
      while (this.input[this.#position] === ' ') this.#position += 1;
      if (this.#atEnd()) throw new Error('unterminated inner list');
      if (this.input[this.#position] === ')') {
        this.#position += 1;
        return Object.freeze(items);
      }
      if (items.length >= MAX_ALLOWLIST_ITEMS) throw new Error('too many allowlist items');
      items.push(this.#parseBareItemWithParameters());
      const next = this.input[this.#position];
      if (next !== ' ' && next !== ')') throw new Error('invalid inner-list separator');
    }
  }

  #parseBareItemWithParameters(): LexedItem {
    const item = this.#parseBareItem();
    this.#skipParameters();
    return item;
  }

  #parseBareItem(): LexedItem {
    if (this.#atEnd()) throw new Error('missing item');
    const first = this.input[this.#position]!;
    if (first === '"') return this.#parseString();
    if (first === '*' || isAsciiAlpha(first)) return this.#parseToken();
    const start = this.#position;
    while (!this.#atEnd() && !',;) \t'.includes(this.input[this.#position]!)) this.#position += 1;
    if (this.#position === start) throw new Error('invalid item');
    return Object.freeze({ kind: 'unknown' });
  }

  #parseString(): LexedItem {
    this.#position += 1;
    let value = '';
    while (!this.#atEnd()) {
      const character = this.input[this.#position++]!;
      if (character === '"') return Object.freeze({ kind: 'string', value });
      if (character === '\\') {
        if (this.#atEnd()) throw new Error('dangling escape');
        const escaped = this.input[this.#position++]!;
        if (escaped !== '"' && escaped !== '\\') throw new Error('invalid escape');
        value += escaped;
        continue;
      }
      const code = character.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) throw new Error('invalid string character');
      value += character;
    }
    throw new Error('unterminated string');
  }

  #parseToken(): LexedItem {
    const start = this.#position++;
    while (!this.#atEnd() && /[A-Za-z0-9!#$%&'*+.^_`|~:/-]/u.test(this.input[this.#position]!)) {
      this.#position += 1;
    }
    return Object.freeze({ kind: 'token', value: this.input.slice(start, this.#position) });
  }

  #skipParameters(): void {
    while (this.input[this.#position] === ';') {
      this.#position += 1;
      this.#skipWhitespace();
      this.#parseKey();
      if (this.input[this.#position] === '=') {
        this.#position += 1;
        this.#parseBareItem();
      }
    }
  }

  #parseKey(): string {
    const first = this.input[this.#position];
    if (!first || !/[a-z*]/u.test(first)) throw new Error('invalid dictionary key');
    const start = this.#position++;
    while (!this.#atEnd() && /[a-z0-9_.*-]/u.test(this.input[this.#position]!)) this.#position += 1;
    return this.input.slice(start, this.#position);
  }

  #skipWhitespace(): void {
    while (this.input[this.#position] === ' ' || this.input[this.#position] === '\t') this.#position += 1;
  }

  #expect(value: string): void {
    if (this.input[this.#position] !== value) throw new Error(`expected ${value}`);
  }

  #atEnd(): boolean {
    return this.#position >= this.input.length;
  }
}

function headerAllowlistItem(item: LexedItem): WebsitePasskeyPolicyAllowlistItem | undefined {
  if (item.kind === 'token') {
    if (item.value === '*') return Object.freeze({ type: 'wildcard' });
    if (item.value === 'self') return Object.freeze({ type: 'self' });
    return undefined;
  }
  if (item.kind !== 'string') return undefined;
  const origin = canonicalOrigin(item.value);
  return origin ? Object.freeze({ type: 'origin', value: origin }) : undefined;
}

function containerAllowlistItem(
  token: string,
  childOrigin: string,
  parentOrigin: string,
): WebsitePasskeyResolvedPolicyAllowlistItem | undefined {
  if (token === '*') return Object.freeze({ type: 'wildcard' });
  if (token === "'self'") return Object.freeze({ type: 'origin', value: parentOrigin });
  if (token === "'src'") return Object.freeze({ type: 'origin', value: childOrigin });
  if (token.startsWith("'") || token.endsWith("'")) return undefined;
  const origin = canonicalOrigin(token);
  return origin ? Object.freeze({ type: 'origin', value: origin }) : undefined;
}

function canonicalOrigin(value: string): string | undefined {
  if (typeof value !== 'string' || !value || /[\s\0]/u.test(value)) return undefined;
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:')
      || url.username
      || url.password
      || url.hostname.includes('*')) return undefined;
    return url.origin === 'null' ? undefined : url.origin;
  } catch {
    return undefined;
  }
}

function isAsciiAlpha(value: string): boolean {
  return /[A-Za-z]/u.test(value);
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
