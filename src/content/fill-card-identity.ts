import type { CardFillData, IdentityFillData } from '../messaging/protocol.js';
import type { DetectedFillForm, FillFieldElement } from './field-detection.js';
import type { CardRole, IdentityRole } from './field-map.js';
import { nativeSetValue, setElementValue } from './native-set-value.js';

export function fillCardForm(form: DetectedFillForm, data: CardFillData): boolean {
  let filled = false;
  const set = (role: CardRole, value: string | undefined) => {
    if (!value) return;
    const el = form.fields.get(role);
    if (el && setFieldValue(el, value, expiryCandidates(role, value))) filled = true;
  };
  set('cardholderName', data.cardholderName);
  set('number', data.number);
  set('code', data.code);
  set('expMonth', data.expMonth);
  set('expYear', data.expYear);
  const expEl = form.fields.get('exp');
  if (expEl && data.expMonth && data.expYear) {
    if (setFieldValue(expEl, formatExp(expEl, data.expMonth, data.expYear))) filled = true;
  }
  return filled;
}

export function fillIdentityForm(form: DetectedFillForm, data: IdentityFillData): boolean {
  let filled = false;
  const set = (role: IdentityRole, value: string | undefined) => {
    if (!value) return;
    const el = form.fields.get(role);
    if (el && setFieldValue(el, value)) filled = true;
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
  const fullEl = form.fields.get('fullName');
  if (fullEl) {
    const full = [data.title, data.firstName, data.middleName, data.lastName].filter(Boolean).join(' ');
    if (full && setFieldValue(fullEl, full)) filled = true;
  }
  return filled;
}

/** Format a combined expiry value as MM/YY, or MM/YYYY when the field looks four-digit. */
function formatExp(el: FillFieldElement, month: string, year: string): string {
  const mm = month.padStart(2, '0').slice(-2);
  const placeholder = el.getAttribute('placeholder') ?? '';
  const wantsFour = /y{4}/i.test(placeholder) || (el instanceof HTMLInputElement && el.maxLength >= 7);
  const yy = wantsFour
    ? (year.length >= 4 ? year.slice(-4) : `20${year.padStart(2, '0').slice(-2)}`)
    : year.slice(-2);
  return `${mm}/${yy}`;
}

function setFieldValue(el: FillFieldElement, value: string, candidates: string[] = [value]): boolean {
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
    nativeSetValue(select, option.value);
    select.dispatchEvent(new Event('input', { bubbles: true }));
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }
  return false;
}
