import type { CardFillData, IdentityFillData } from '../messaging/protocol.js';
import { isFillableField, type DetectedFillForm, type FillFieldElement } from './field-detection.js';
import type { CardRole, IdentityRole } from './field-map.js';
import { nativeSetValue, setElementValue } from './native-set-value.js';
import { createStagedFillCommit, type StagedFillCommit } from './staged-fill.js';

export function fillCardForm(
  form: DetectedFillForm,
  data: CardFillData,
  staged: StagedFillCommit = createStagedFillCommit(),
): boolean {
  let filled = false;
  const set = (role: CardRole, value: string | undefined, candidates?: string[]) => {
    if (!value || staged.stale) return;
    const el = form.fields.get(role);
    if (!el) return;
    const write = role === 'expMonth' && el instanceof HTMLSelectElement
      ? () => setExpiryMonthSelect(el, value, candidates ?? expiryCandidates(role, value))
      : () => setFieldValue(el, value, candidates ?? expiryCandidates(role, value));
    if (staged.write(write)) filled = true;
  };
  set('cardholderName', data.cardholderName);
  set('brand', data.brand, data.brand ? brandCandidates(data.brand) : undefined);
  set('number', data.number);
  set('code', data.code);
  set('expMonth', data.expMonth);
  set('expYear', data.expYear);
  const expEl = form.fields.get('exp');
  if (!staged.stale && expEl && data.expMonth && data.expYear) {
    const candidates = combinedExpiryCandidates(expEl, data.expMonth, data.expYear);
    if (candidates.length > 0 && staged.write(() => setFieldValue(expEl, candidates[0]!, candidates))) {
      filled = true;
    }
  }
  return filled;
}

export function fillIdentityForm(
  form: DetectedFillForm,
  data: IdentityFillData,
  staged: StagedFillCommit = createStagedFillCommit(),
): boolean {
  let filled = false;
  const set = (role: IdentityRole, value: string | undefined) => {
    if (!value || staged.stale) return;
    const el = form.fields.get(role);
    if (el && staged.write(() => setFieldValue(el, value))) filled = true;
  };
  set('title', data.title);
  set('firstName', data.firstName);
  set('middleName', data.middleName);
  set('lastName', data.lastName);
  set('address1', data.address1);
  set('address2', data.address2);
  set('address3', data.address3);
  set('city', data.city);
  set('state', data.state);
  set('postalCode', data.postalCode);
  set('country', data.country);
  set('company', data.company);
  set('email', data.email);
  set('phone', data.phone);
  set('username', data.username);
  const addressEl = form.fields.get('address');
  if (!staged.stale && addressEl) {
    const address = combinedAddressValue(addressEl, data);
    if (address && staged.write(() => setFieldValue(addressEl, address))) filled = true;
  }
  const fullEl = form.fields.get('fullName');
  if (!staged.stale && fullEl) {
    const full = [data.firstName, data.middleName, data.lastName].filter(Boolean).join(' ');
    if (full && staged.write(() => setFieldValue(fullEl, full))) filled = true;
  }
  return filled;
}

type ExpiryFormat =
  | 'MM/YY'
  | 'MM-YY'
  | 'MM/YYYY'
  | 'MM-YYYY'
  | 'YYYY-MM'
  | 'YYYY/MM'
  | 'MMYY'
  | 'MMYYYY'
  | 'YYYYMM';

function combinedExpiryCandidates(el: FillFieldElement, month: string, year: string): string[] {
  const normalized = normalizeExpiry(month, year);
  if (!normalized) return [];
  const values = expiryValues(normalized);
  if (el instanceof HTMLSelectElement) {
    return dedupe([
      values['MM/YY'], values['MM-YY'], values['MM/YYYY'], values['MM-YYYY'],
      values['YYYY-MM'], values['YYYY/MM'], values.MMYY, values.MMYYYY, values.YYYYMM,
    ]);
  }
  const format = expiryFormatFor(el);
  if (!format) return [];
  const value = values[format];
  return el.maxLength > 0 && value.length > el.maxLength ? [] : [value];
}

function normalizeExpiry(
  month: string,
  year: string,
): { readonly mm: string; readonly yy: string; readonly yyyy: string } | undefined {
  const rawMonth = month.trim();
  const rawYear = year.trim();
  if (!/^\d{1,2}$/.test(rawMonth) || !/^(?:\d{2}|\d{4})$/.test(rawYear)) return undefined;
  const monthNumber = Number(rawMonth);
  if (!Number.isInteger(monthNumber) || monthNumber < 1 || monthNumber > 12) return undefined;
  const yy = rawYear.slice(-2);
  return {
    mm: String(monthNumber).padStart(2, '0'),
    yy,
    yyyy: rawYear.length === 4 ? rawYear : `20${yy}`,
  };
}

function expiryValues(parts: { readonly mm: string; readonly yy: string; readonly yyyy: string }): Record<ExpiryFormat, string> {
  return {
    'MM/YY': `${parts.mm}/${parts.yy}`,
    'MM-YY': `${parts.mm}-${parts.yy}`,
    'MM/YYYY': `${parts.mm}/${parts.yyyy}`,
    'MM-YYYY': `${parts.mm}-${parts.yyyy}`,
    'YYYY-MM': `${parts.yyyy}-${parts.mm}`,
    'YYYY/MM': `${parts.yyyy}/${parts.mm}`,
    MMYY: `${parts.mm}${parts.yy}`,
    MMYYYY: `${parts.mm}${parts.yyyy}`,
    YYYYMM: `${parts.yyyy}${parts.mm}`,
  };
}

function expiryFormatFor(el: Exclude<FillFieldElement, HTMLSelectElement>): ExpiryFormat | undefined {
  if (el instanceof HTMLInputElement && el.type === 'month') return 'YYYY-MM';
  const explicit = [
    el.getAttribute('placeholder'),
    el.getAttribute('aria-label'),
    el.getAttribute('name'),
    el.getAttribute('id'),
  ].flatMap((hint): ExpiryFormat[] => {
    const compact = hint?.toUpperCase().replace(/\s+/g, '') ?? '';
    if (!compact) return [];
    if (compact.includes('YYYY-MM')) return ['YYYY-MM'];
    if (compact.includes('YYYY/MM')) return ['YYYY/MM'];
    if (compact.includes('MM/YYYY')) return ['MM/YYYY'];
    if (compact.includes('MM-YYYY')) return ['MM-YYYY'];
    if (compact.includes('MM/YY')) return ['MM/YY'];
    if (compact.includes('MM-YY')) return ['MM-YY'];
    if (compact.includes('YYYYMM')) return ['YYYYMM'];
    if (compact.includes('MMYYYY')) return ['MMYYYY'];
    if (compact.includes('MMYY')) return ['MMYY'];
    return [];
  });
  if (explicit.length > 0) return explicit[0];
  const maxLength = el.maxLength;
  if (maxLength === 4) return 'MMYY';
  if (maxLength === 5) return 'MM/YY';
  if (maxLength === 7) return 'MM/YYYY';
  if ((maxLength > 0 && maxLength < 5) || maxLength === 6) return undefined;
  return 'MM/YY';
}

function combinedAddressValue(el: FillFieldElement, data: IdentityFillData): string {
  const lines = [data.address1, data.address2, data.address3]
    .map((line) => line?.trim() ?? '')
    .filter(Boolean);
  return lines.join(el instanceof HTMLTextAreaElement ? '\n' : ', ');
}

function brandCandidates(value: string): string[] {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, '');
  const aliases: Record<string, readonly string[]> = {
    americanexpress: ['American Express', 'Amex', 'american-express'],
    dinersclub: ['Diners Club', 'diners-club'],
    mastercard: ['Mastercard', 'MasterCard', 'master-card'],
    unionpay: ['UnionPay', 'Union Pay', 'union-pay'],
  };
  return dedupe([value, ...(aliases[normalized] ?? [])]);
}

function setFieldValue(el: FillFieldElement, value: string, candidates: string[] = [value]): boolean {
  if (!isFillableField(el)) return false;
  if (el instanceof HTMLSelectElement) return setSelectValue(el, candidates);
  setElementValue(el, value);
  return true;
}

/**
 * Candidate strings to match a card <select> option by. The vault stores expiry unpadded (month "3",
 * year "2027") while sites use zero-padded months ("01".."12") and 2- or 4-digit years, so an exact
 * match silently fails. Widen expMonth to padded/unpadded and expYear to 4-/2-digit forms; other roles
 * (and non-numeric values like "September") match as-is.
 */
function expiryCandidates(role: CardRole, value: string): string[] {
  const trimmed = value.trim();
  if (role === 'expMonth' && /^\d{1,2}$/.test(trimmed)) {
    const n = String(Number(trimmed));
    return dedupe([trimmed, n, n.padStart(2, '0')]);
  }
  if (role === 'expYear' && /^(\d{2}|\d{4})$/.test(trimmed)) {
    const two = trimmed.slice(-2);
    const four = trimmed.length === 4 ? trimmed : `20${two}`;
    return dedupe([trimmed, four, two]);
  }
  return [trimmed];
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function setSelectValue(select: HTMLSelectElement, candidates: string[]): boolean {
  const options = Array.from(select.options);
  for (const candidate of candidates) {
    const target = candidate.trim().toLowerCase();
    const option = options.find(
      (o) => o.value.trim().toLowerCase() === target || o.text.trim().toLowerCase() === target,
    );
    if (!option) continue;
    return commitSelectOption(select, option);
  }
  return false;
}

function setExpiryMonthSelect(
  select: HTMLSelectElement,
  value: string,
  candidates: string[],
): boolean {
  const month = Number(value.trim());
  if (Number.isInteger(month) && month >= 1 && month <= 12) {
    const numericOptions = Array.from(select.options).filter((option) => /^\d{1,2}$/.test(option.value.trim()));
    const values = numericOptions.map((option) => Number(option.value.trim()));
    if (numericOptions.length === 12
        && new Set(values).size === 12
        && values.every((candidate) => candidate >= 0 && candidate <= 11)) {
      const option = numericOptions.find((candidate) => Number(candidate.value.trim()) === month - 1);
      if (option) return commitSelectOption(select, option);
    }
  }
  return setSelectValue(select, candidates);
}

function commitSelectOption(select: HTMLSelectElement, option: HTMLOptionElement): true {
  nativeSetValue(select, option.value);
  select.dispatchEvent(new Event('input', { bubbles: true }));
  select.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}
