import type { CardFillData, IdentityFillData } from '../messaging/protocol.js';
import type { DetectedFillForm, FillFieldElement } from './field-detection.js';
import type { CardRole, IdentityRole } from './field-map.js';
import { nativeSetValue, setElementValue } from './native-set-value.js';

export function fillCardForm(form: DetectedFillForm, data: CardFillData): boolean {
  let filled = false;
  const set = (role: CardRole, value: string | undefined) => {
    if (!value) return;
    const el = form.fields.get(role);
    if (el && setFieldValue(el, value)) filled = true;
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

function setFieldValue(el: FillFieldElement, value: string): boolean {
  if (el instanceof HTMLSelectElement) return setSelectValue(el, value);
  setElementValue(el, value);
  return true;
}

function setSelectValue(select: HTMLSelectElement, value: string): boolean {
  const target = value.trim().toLowerCase();
  const option = Array.from(select.options).find(
    (o) => o.value.trim().toLowerCase() === target || o.text.trim().toLowerCase() === target,
  );
  if (!option) return false;
  nativeSetValue(select, option.value);
  select.dispatchEvent(new Event('input', { bubbles: true }));
  select.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}
