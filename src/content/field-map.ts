// Pure field classification for card and identity autofill. Maps a field's hints
// (autocomplete tokens first, then name/id/aria/placeholder text) to a card or
// identity role. No DOM access — callers extract FieldHints from the element.

export type CardRole = 'cardholderName' | 'number' | 'exp' | 'expMonth' | 'expYear' | 'code';

export type IdentityRole =
  | 'title' | 'firstName' | 'middleName' | 'lastName' | 'fullName'
  | 'address1' | 'address2' | 'address3' | 'city' | 'state' | 'postalCode' | 'country'
  | 'company' | 'email' | 'phone' | 'username';

export interface FieldHints {
  autocomplete: string;
  name: string;
  id: string;
  ariaLabel: string;
  placeholder: string;
  type: string;
}

/** Lowercase autocomplete tokens, e.g. "billing cc-number" → ["billing","cc-number"]. */
function autocompleteTokens(hints: FieldHints): string[] {
  return hints.autocomplete.toLowerCase().split(/\s+/).filter(Boolean);
}

/** Combined lowercase name/id/aria/placeholder text for hint-based fallback. */
function hintText(hints: FieldHints): string {
  return `${hints.name} ${hints.id} ${hints.ariaLabel} ${hints.placeholder}`.toLowerCase();
}

const CARD_AUTOCOMPLETE: Record<string, CardRole> = {
  'cc-name': 'cardholderName',
  'cc-given-name': 'cardholderName',
  'cc-family-name': 'cardholderName',
  'cc-number': 'number',
  'cc-exp': 'exp',
  'cc-exp-month': 'expMonth',
  'cc-exp-year': 'expYear',
  'cc-csc': 'code',
};

const CARD_HINTS: Array<[RegExp, CardRole]> = [
  [/card.?holder|name.?on.?card|ccname|cc.?name/, 'cardholderName'],
  [/card.?number|cardnum|cc.?num|ccnumber|acctnum/, 'number'],
  [/exp.?month|expmonth|exp.?mm/, 'expMonth'],
  [/exp.?year|expyear|exp.?yy/, 'expYear'],
  [/expir|cc.?exp|card.?exp/, 'exp'],
  [/cvc|cvv|csc|security.?code|card.?code|verification.?value/, 'code'],
];

export function classifyCardField(hints: FieldHints): CardRole | undefined {
  for (const token of autocompleteTokens(hints)) {
    const role = CARD_AUTOCOMPLETE[token];
    if (role) return role;
  }
  const text = hintText(hints);
  for (const [re, role] of CARD_HINTS) if (re.test(text)) return role;
  return undefined;
}

const IDENTITY_AUTOCOMPLETE: Record<string, IdentityRole> = {
  'honorific-prefix': 'title',
  'given-name': 'firstName',
  'additional-name': 'middleName',
  'family-name': 'lastName',
  'name': 'fullName',
  'street-address': 'address1',
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
  [/street|address.?line.?1|addr.?1|address1/, 'address1'],
  [/address.?line.?2|addr.?2|address2|apt|suite|unit/, 'address2'],
  [/address.?line.?3|addr.?3|address3/, 'address3'],
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

export function classifyIdentityField(hints: FieldHints): IdentityRole | undefined {
  for (const token of autocompleteTokens(hints)) {
    const role = IDENTITY_AUTOCOMPLETE[token];
    if (role) return role;
  }
  const text = hintText(hints);
  for (const [re, role] of IDENTITY_HINTS) if (re.test(text)) return role;
  return undefined;
}
