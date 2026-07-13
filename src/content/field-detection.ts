import { isFillableInput, isVisibleInTree } from './form-detection.js';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole, type FieldHints } from './field-map.js';

export type FillFieldElement = HTMLInputElement | HTMLSelectElement;

export interface DetectedFillForm {
  kind: 'card' | 'identity';
  id: string;
  fields: Map<CardRole | IdentityRole, FillFieldElement>;
  anchor: HTMLElement;
}

let nextFillId = 0;

export function detectCardForms(root: ParentNode = document, exclude: Set<Element> = new Set()): DetectedFillForm[] {
  return detectForms(root, exclude, 'card');
}

export function detectIdentityForms(root: ParentNode = document, exclude: Set<Element> = new Set()): DetectedFillForm[] {
  return detectForms(root, exclude, 'identity');
}

function detectForms(root: ParentNode, exclude: Set<Element>, kind: 'card' | 'identity'): DetectedFillForm[] {
  const classify = kind === 'card' ? classifyCardField : classifyIdentityField;
  const fillable = Array.from(root.querySelectorAll<FillFieldElement>('input, select'))
    .filter(isFillableField)
    .filter((el) => !exclude.has(el));

  // Group by wrapping <form> or nearest container; first element per role wins.
  const groups = new Map<ParentNode, Map<CardRole | IdentityRole, FillFieldElement>>();
  for (const el of fillable) {
    const role = classify(hintsFor(el)) as CardRole | IdentityRole | undefined;
    if (!role) continue;
    const container = el.closest('form') ?? nearestContainer(el);
    let map = groups.get(container);
    if (!map) { map = new Map(); groups.set(container, map); }
    if (!map.has(role)) map.set(role, el);
  }

  const forms: DetectedFillForm[] = [];
  for (const fields of groups.values()) {
    if (!meetsThreshold(kind, fields)) continue;
    const anchor = anchorFor(kind, fields);
    if (!anchor) continue;
    forms.push({ kind, id: assignFillId(anchor), fields, anchor });
  }
  return forms;
}

function meetsThreshold(kind: 'card' | 'identity', fields: Map<string, FillFieldElement>): boolean {
  if (kind === 'card') return fields.has('number');
  if (fields.has('address1') || fields.has('postalCode')) return true;
  return fields.has('firstName') && fields.has('lastName');
}

function anchorFor(kind: 'card' | 'identity', fields: Map<string, FillFieldElement>): HTMLElement | undefined {
  const order = kind === 'card'
    ? ['number', 'cardholderName', 'exp', 'expMonth', 'code']
    : ['address1', 'firstName', 'lastName', 'fullName', 'postalCode', 'email'];
  for (const role of order) { const el = fields.get(role); if (el) return el; }
  return fields.values().next().value;
}

/** Visible + editable input or select; reuses the login detector's input rule for inputs. */
export function isFillableField(el: FillFieldElement): boolean {
  if (el instanceof HTMLInputElement) return isFillableInput(el);
  return !el.disabled && !el.hidden && isVisibleInTree(el);
}

function hintsFor(el: FillFieldElement): FieldHints {
  return {
    autocomplete: el.getAttribute('autocomplete') ?? '',
    name: el.getAttribute('name') ?? '',
    id: el.id,
    ariaLabel: el.getAttribute('aria-label') ?? '',
    placeholder: el.getAttribute('placeholder') ?? '',
    type: el instanceof HTMLInputElement ? el.type : 'select',
  };
}

function nearestContainer(el: Element): ParentNode {
  return el.closest('form, section, main, article') ?? document;
}

function assignFillId(el: HTMLElement): string {
  const existing = el.dataset.vwFillId;
  if (existing) return existing;
  const id = `vw-fill-${nextFillId++}`;
  el.dataset.vwFillId = id;
  return id;
}
