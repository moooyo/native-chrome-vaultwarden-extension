// Pure field classification for card and identity autofill. Maps a field's hints
// (autocomplete tokens first, then name/id/aria/placeholder text) to a card or
// identity role. No DOM access — callers extract FieldHints from the element.

import type { CardFillRole, IdentityFillRole } from '../core/vault/fill-roles.js';

export type CardRole = CardFillRole;
export type IdentityRole = IdentityFillRole;

const MAX_HINT_ATTRIBUTE_CHARACTERS = 1_024;
const MAX_HINT_ATTRIBUTE_BYTES = 1_024;
const MAX_HINT_ATTRIBUTES_BYTES = 4_096;
const MAX_SEMANTIC_LABELS = 8;
const MAX_SEMANTIC_LABEL_CHARACTERS = 256;
const MAX_SEMANTIC_LABEL_BYTES = 1_024;
const STRONG_OTP_HINT = /otp|one[-_ ]?time|mfa|2fa|two[-_ ]?factor|authenticator|auth[-_ ]?code/;

export interface FieldHints {
  autocomplete: string;
  name: string;
  id: string;
  ariaLabel: string;
  placeholder: string;
  type: string;
  /** Root-local text from associated labels and aria-labelledby references. */
  semanticLabels?: readonly string[];
  /** True when attributes or associated semantics could not be read completely within bounds. */
  semanticLabelsUnsafe?: boolean;
}

/** Lowercase autocomplete tokens, e.g. "billing cc-number" → ["billing","cc-number"]. */
function autocompleteTokens(hints: FieldHints): string[] {
  return hints.autocomplete.toLowerCase().split(/\s+/).filter(Boolean);
}

/** Combined lowercase attribute text for hint-based fallback. */
function hintText(hints: FieldHints): string {
  return `${hints.name} ${hints.id} ${hints.placeholder}`.toLowerCase().trim();
}

function hintsWithinBounds(hints: FieldHints): boolean {
  const attributes = [
    [hints.autocomplete, MAX_HINT_ATTRIBUTE_CHARACTERS],
    [hints.name, MAX_HINT_ATTRIBUTE_CHARACTERS],
    [hints.id, MAX_HINT_ATTRIBUTE_CHARACTERS],
    [hints.ariaLabel, MAX_SEMANTIC_LABEL_CHARACTERS],
    [hints.placeholder, MAX_HINT_ATTRIBUTE_CHARACTERS],
    [hints.type, MAX_HINT_ATTRIBUTE_CHARACTERS],
  ] as const;
  let attributeBytes = 0;
  for (const [value, maxCharacters] of attributes) {
    if (typeof value !== 'string' || value.length > maxCharacters) return false;
    const bytes = utf8ByteLength(value);
    if (
      bytes > MAX_HINT_ATTRIBUTE_BYTES
      || bytes > MAX_HINT_ATTRIBUTES_BYTES - attributeBytes
    ) return false;
    attributeBytes += bytes;
  }
  const labels = hints.semanticLabels ?? [];
  if (labels.length > MAX_SEMANTIC_LABELS) return false;
  let labelBytes = utf8ByteLength(hints.ariaLabel);
  for (const label of labels) {
    if (typeof label !== 'string' || label.length > MAX_SEMANTIC_LABEL_CHARACTERS) return false;
    const bytes = utf8ByteLength(label);
    if (
      bytes > MAX_SEMANTIC_LABEL_BYTES - labelBytes
    ) return false;
    labelBytes += bytes;
  }
  return true;
}

interface SemanticRole<Role extends string> {
  readonly role: Role | undefined;
  readonly matched: boolean;
  readonly conflicted: boolean;
}

function firstPatternRole<Role extends string>(
  value: string,
  patterns: readonly (readonly [RegExp, Role])[],
): Role | undefined {
  const text = value.toLowerCase();
  return patterns.find(([pattern]) => pattern.test(text))?.[1];
}

function semanticRole<Role extends string>(
  hints: FieldHints,
  patterns: readonly (readonly [RegExp, Role])[],
): SemanticRole<Role> {
  const roles = new Set<Role>();
  for (const value of [hints.ariaLabel, ...(hints.semanticLabels ?? [])]) {
    if (!value) continue;
    const text = value.toLowerCase();
    for (const [pattern, role] of patterns) {
      if (pattern.test(text)) roles.add(role);
    }
  }
  return {
    role: roles.size === 1 ? roles.values().next().value : undefined,
    matched: roles.size > 0,
    conflicted: roles.size > 1,
  };
}

function hasStrongOtpHint(hints: FieldHints): boolean {
  return [
    hints.name,
    hints.id,
    hints.ariaLabel,
    hints.placeholder,
    ...(hints.semanticLabels ?? []),
  ].some((value) => STRONG_OTP_HINT.test(value.toLowerCase()));
}

const CARD_AUTOCOMPLETE: Record<string, CardRole> = {
  'cc-name': 'cardholderName',
  'cc-given-name': 'cardholderName',
  'cc-family-name': 'cardholderName',
  'cc-type': 'brand',
  'cc-number': 'number',
  'cc-exp': 'exp',
  'cc-exp-month': 'expMonth',
  'cc-exp-year': 'expYear',
  'cc-csc': 'code',
};

const CARD_HINTS: Array<[RegExp, CardRole]> = [
  [/card.?holder|name.?on.?card|ccname|cc.?name/, 'cardholderName'],
  [/card.?brand|card.?type|payment.?network|cc.?type/, 'brand'],
  [/card.?number|cardnum|cc.?num|ccnumber|acctnum/, 'number'],
  [/exp.?month|expmonth|exp.?mm/, 'expMonth'],
  [/exp.?year|expyear|exp.?yy/, 'expYear'],
  [/expir|cc.?exp|card.?exp/, 'exp'],
  [/cvc|cvv|csc|security.?code|card.?code|verification.?value/, 'code'],
];

const CARD_SEMANTIC_HINTS: Array<[RegExp, CardRole]> = [
  [/card.?holder|name.?on.?card|ccname|cc.?name/, 'cardholderName'],
  [/card.?brand|card.?type|payment.?network|cc.?type/, 'brand'],
  [/card.?number|cardnum|cc.?num|ccnumber|acctnum/, 'number'],
  [/exp(?:iration|iry)?.?month|expmonth|exp.?mm/, 'expMonth'],
  [/exp(?:iration|iry)?.?year|expyear|exp.?yy/, 'expYear'],
  [/expir(?![^\n]*(?:month|year))|cc.?exp(?![^\n]*(?:month|year))|card.?exp(?![^\n]*(?:month|year))/, 'exp'],
  [/cvc|cvv|csc|security.?code|card.?code|verification.?value/, 'code'],
];

export function classifyCardField(hints: FieldHints): CardRole | undefined {
  if (!hintsWithinBounds(hints)) return undefined;
  const tokens = autocompleteTokens(hints);
  if (tokens.includes('one-time-code')) return undefined;
  for (const token of tokens) {
    const role = CARD_AUTOCOMPLETE[token];
    if (role) return role;
  }
  if (hasStrongOtpHint(hints)) return undefined;
  if (hints.semanticLabelsUnsafe) return undefined;
  const attributeRole = firstPatternRole(hintText(hints), CARD_HINTS);
  const semantic = semanticRole(hints, CARD_SEMANTIC_HINTS);
  if (semantic.conflicted || (attributeRole && semantic.role && attributeRole !== semantic.role)) {
    return undefined;
  }
  return attributeRole ?? semantic.role;
}

/** Card-like evidence remains an exclusion even when conflicting semantics prevent classification. */
export function hasCardFieldEvidence(hints: FieldHints): boolean {
  if (!hintsWithinBounds(hints)) return true;
  const tokens = autocompleteTokens(hints);
  if (tokens.some((token) => token.startsWith('cc-'))) return true;
  if (firstPatternRole(hintText(hints), CARD_HINTS)) return true;
  return semanticRole(hints, CARD_SEMANTIC_HINTS).matched;
}

export function hasCardNumberEvidence(hints: FieldHints): boolean {
  if (!hintsWithinBounds(hints)) return false;
  if (autocompleteTokens(hints).some((token) => CARD_AUTOCOMPLETE[token] === 'number')) return true;
  if (CARD_HINTS.some(([pattern, role]) => role === 'number' && pattern.test(hintText(hints)))) return true;
  return [hints.ariaLabel, ...(hints.semanticLabels ?? [])].some((value) => CARD_SEMANTIC_HINTS.some(
    ([pattern, role]) => role === 'number' && pattern.test(value.toLowerCase()),
  ));
}

const IDENTITY_AUTOCOMPLETE: Record<string, IdentityRole> = {
  'honorific-prefix': 'title',
  'given-name': 'firstName',
  'additional-name': 'middleName',
  'family-name': 'lastName',
  'name': 'fullName',
  'street-address': 'address',
  'address-line1': 'address1',
  'address-line2': 'address2',
  'address-line3': 'address3',
  'address-level2': 'city',
  'address-level1': 'state',
  'postal-code': 'postalCode',
  'country': 'country',
  'country-name': 'country',
  'organization': 'company',
  'email': 'email',
  'tel': 'phone',
  'tel-national': 'phone',
  'username': 'username',
};

// Specific roles before the generic \bname\b fullName fallback so "company name"
// resolves to company, not fullName. Username before "name" so "username" doesn't
// match the fullName \bname\b pattern.
const IDENTITY_HINTS: Array<[RegExp, IdentityRole]> = [
  [/first.?name|given.?name|forename|fname/, 'firstName'],
  [/middle.?name|additional.?name|mname/, 'middleName'],
  [/last.?name|family.?name|surname|lname/, 'lastName'],
  [/company|organi[sz]ation|business/, 'company'],
  [/address.?line.?1|addr.?1|address1/, 'address1'],
  [/address.?line.?2|addr.?2|address2|apt|suite|unit/, 'address2'],
  [/address.?line.?3|addr.?3|address3/, 'address3'],
  [/(?:street.?address|mailing.?address|billing.?address|shipping.?address|home.?address|physical.?address)(?![^\n]*line.?[123])|^address$/, 'address'],
  [/postal|zip|post.?code/, 'postalCode'],
  [/\bcity\b|town|locality/, 'city'],
  [/\bstate\b|province|region|county/, 'state'],
  [/\bcountry\b/, 'country'],
  [/e.?mail/, 'email'],
  [/phone|mobile|\btel\b/, 'phone'],
  [/prefix|salutation|honorific/, 'title'],
  [/\busername\b/, 'username'],
  [/full.?name|your.?name|\bname\b/, 'fullName'],
];

const IDENTITY_SEMANTIC_HINTS: Array<[RegExp, IdentityRole]> = [
  [/first.?name|given.?name|forename|fname/, 'firstName'],
  [/middle.?name|additional.?name|mname/, 'middleName'],
  [/last.?name|family.?name|surname|lname/, 'lastName'],
  [/company|organi[sz]ation|business/, 'company'],
  [/address.?line.?1|addr.?1|address1/, 'address1'],
  [/address.?line.?2|addr.?2|address2|apt|suite|unit/, 'address2'],
  [/address.?line.?3|addr.?3|address3/, 'address3'],
  [/(?:street.?address|mailing.?address|billing.?address|shipping.?address|home.?address|physical.?address)(?![^\n]*line.?[123])|^address$/, 'address'],
  [/postal|zip|post.?code/, 'postalCode'],
  [/\bcity\b|town|locality/, 'city'],
  [/\bstate\b|province|region|county/, 'state'],
  [/\bcountry\b/, 'country'],
  [/e.?mail/, 'email'],
  [/phone|mobile|\btel\b/, 'phone'],
  [/prefix|salutation|honorific/, 'title'],
  [/\busername\b/, 'username'],
  [/full.?name|your.?name|^name$/, 'fullName'],
];

export function classifyIdentityField(hints: FieldHints): IdentityRole | undefined {
  if (!hintsWithinBounds(hints)) return undefined;
  const tokens = autocompleteTokens(hints);
  if (tokens.includes('one-time-code') || tokens.some((token) => token.startsWith('cc-'))) {
    return undefined;
  }
  for (const token of tokens) {
    const role = IDENTITY_AUTOCOMPLETE[token];
    if (role) return role;
  }
  if (hasStrongOtpHint(hints)) return undefined;
  if (hints.semanticLabelsUnsafe) return undefined;
  const attributeRole = firstPatternRole(hintText(hints), IDENTITY_HINTS);
  const semantic = semanticRole(hints, IDENTITY_SEMANTIC_HINTS);
  if (semantic.conflicted || (attributeRole && semantic.role && attributeRole !== semantic.role)) {
    return undefined;
  }
  return attributeRole ?? semantic.role;
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first <= 0x7f) {
      bytes += 1;
    } else if (first <= 0x7ff) {
      bytes += 2;
    } else if (first >= 0xd800 && first <= 0xdbff && index + 1 < value.length) {
      const second = value.charCodeAt(index + 1);
      if (second >= 0xdc00 && second <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}
