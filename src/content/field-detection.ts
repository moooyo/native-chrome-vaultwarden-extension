import {
  captureControlOwner,
  composedSlotPath,
  hasConflictingSecurityCodeAutocomplete,
  hasSameControlOwner,
  isElementInteractable,
  isFillableInput,
  isNewPasswordField,
  isVisibleInTree,
  type ControlOwnerSnapshot,
} from './form-detection.js';
import { isAutofillIgnored } from './autofill-ignore.js';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole, type FieldHints } from './field-map.js';
import { collectFieldHints } from './semantic-hints.js';

export type FillFieldElement = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

export interface DetectedFillForm {
  kind: 'card' | 'identity';
  id: string;
  fields: Map<CardRole | IdentityRole, FillFieldElement>;
  anchor: HTMLElement;
}

let nextFillId = 0;
interface FillIdentity {
  readonly scope: ParentNode;
  readonly root: Node;
  readonly slotPath: readonly HTMLSlotElement[];
  readonly fields: ReadonlyMap<CardRole | IdentityRole, FillFieldElement>;
  readonly fieldOwners: readonly (readonly [CardRole | IdentityRole, FillFieldElement, ControlOwnerSnapshot])[];
  readonly id: string;
}
const cardFillIds = new WeakMap<HTMLElement, FillIdentity>();
const identityFillIds = new WeakMap<HTMLElement, FillIdentity>();

export function detectCardForms(root: ParentNode = document, exclude: Set<Element> = new Set()): DetectedFillForm[] {
  return detectForms(root, exclude, 'card');
}

export function detectIdentityForms(root: ParentNode = document, exclude: Set<Element> = new Set()): DetectedFillForm[] {
  return detectForms(root, exclude, 'identity');
}

function detectForms(root: ParentNode, exclude: Set<Element>, kind: 'card' | 'identity'): DetectedFillForm[] {
  const classify = kind === 'card' ? classifyCardField : classifyIdentityField;
  const fillable = Array.from(root.querySelectorAll<FillFieldElement>('input, select, textarea'))
    .filter(isFillableField)
    .filter((el) => !exclude.has(el));

  // Native form ownership is authoritative and includes external `form=id` controls. Form-less
  // controls are grouped only inside their own tree root; fields never cross a shadow boundary.
  const groups: Array<{
    readonly scope: ParentNode;
    readonly fields: Map<CardRole | IdentityRole, FillFieldElement>;
    readonly formlessOwner?: ControlOwnerSnapshot;
  }> = [];
  const nativeForms = new Set(fillable.map((el) => el.form).filter((form): form is HTMLFormElement => form !== null));
  for (const form of nativeForms) {
    const group = { scope: form, fields: new Map<CardRole | IdentityRole, FillFieldElement>() };
    groups.push(group);
    addGroup(
      group.fields,
      Array.from(form.elements)
        .filter((control): control is FillFieldElement => (
          control instanceof HTMLInputElement
          || control instanceof HTMLSelectElement
          || control instanceof HTMLTextAreaElement
        ))
        .filter((control) => control.form === form && control.getRootNode() === form.getRootNode())
        .filter(isFillableField)
        .filter((control) => !exclude.has(control)),
    );
  }
  for (const el of fillable.filter((candidate) => candidate.form === null)) {
    const owner = captureControlOwner(el);
    let group = groups.find((candidate) => (
      candidate.formlessOwner !== undefined && hasSameControlOwner(candidate.formlessOwner, owner)
    ));
    if (!group) {
      group = { scope: owner.composedContainer, fields: new Map(), formlessOwner: owner };
      groups.push(group);
    }
    addGroup(group.fields, [el]);
  }

  function addGroup(
    fields: Map<CardRole | IdentityRole, FillFieldElement>,
    elements: readonly FillFieldElement[],
  ): void {
    for (const el of elements) {
      if (el instanceof HTMLInputElement && hasConflictingSecurityCodeAutocomplete(el)) continue;
      if (kind === 'identity' && el instanceof HTMLInputElement && isNewPasswordField(el)) continue;
      const role = classify(hintsFor(el)) as CardRole | IdentityRole | undefined;
      if (!role) continue;
      if (!fields.has(role)) fields.set(role, el);
    }
  }

  const forms: DetectedFillForm[] = [];
  for (const { scope, fields } of groups) {
    if (!meetsThreshold(kind, fields)) continue;
    const anchor = anchorFor(kind, fields);
    if (!anchor) continue;
    forms.push({ kind, id: assignFillId(kind, anchor, scope, fields), fields, anchor });
  }
  return forms;
}

function meetsThreshold(kind: 'card' | 'identity', fields: Map<string, FillFieldElement>): boolean {
  if (kind === 'card') return fields.has('number');
  if (fields.has('address') || fields.has('address1') || fields.has('postalCode')) return true;
  return fields.has('firstName') && fields.has('lastName');
}

function anchorFor(kind: 'card' | 'identity', fields: Map<string, FillFieldElement>): HTMLElement | undefined {
  const order = kind === 'card'
    ? ['number', 'cardholderName', 'brand', 'exp', 'expMonth', 'code']
    : ['address', 'address1', 'firstName', 'lastName', 'fullName', 'postalCode', 'email'];
  for (const role of order) { const el = fields.get(role); if (el) return el; }
  return fields.values().next().value;
}

/** Visible + editable input, select, or textarea; reuses the login detector's input rule. */
export function isFillableField(el: FillFieldElement): boolean {
  if (isAutofillIgnored(el)) return false;
  if (el instanceof HTMLInputElement) return isFillableInput(el);
  return !el.disabled
    && !el.matches(':disabled')
    && !el.hidden
    && (!(el instanceof HTMLTextAreaElement) || !el.readOnly)
    && isElementInteractable(el);
}

function hintsFor(el: FillFieldElement): FieldHints {
  return collectFieldHints(el, isVisibleInTree);
}

function assignFillId(
  kind: 'card' | 'identity',
  el: HTMLElement,
  scope: ParentNode,
  fields: ReadonlyMap<CardRole | IdentityRole, FillFieldElement>,
): string {
  const identities = kind === 'card' ? cardFillIds : identityFillIds;
  const existing = identities.get(el);
  const root = el.getRootNode();
  const slotPath = composedSlotPath(el);
  const fieldOwners = [...fields].map(([role, field]) => [role, field, captureControlOwner(field)] as const);
  if (
    existing?.scope === scope
    && existing.root === root
    && sameSlots(existing.slotPath, slotPath)
    && sameFields(existing.fields, fields)
    && sameFieldOwners(existing.fieldOwners, fieldOwners)
  ) return existing.id;
  const id = `vw-fill-${nextFillId++}`;
  identities.set(el, { scope, root, slotPath, fields: new Map(fields), fieldOwners, id });
  return id;
}

function sameFields(
  first: ReadonlyMap<CardRole | IdentityRole, FillFieldElement>,
  second: ReadonlyMap<CardRole | IdentityRole, FillFieldElement>,
): boolean {
  return first.size === second.size && [...first].every(([role, field]) => second.get(role) === field);
}

function sameSlots(first: readonly HTMLSlotElement[], second: readonly HTMLSlotElement[]): boolean {
  return first.length === second.length && first.every((slot, index) => slot === second[index]);
}

function sameFieldOwners(
  first: readonly (readonly [CardRole | IdentityRole, FillFieldElement, ControlOwnerSnapshot])[],
  second: readonly (readonly [CardRole | IdentityRole, FillFieldElement, ControlOwnerSnapshot])[],
): boolean {
  return first.length === second.length && first.every(([role, field, owner], index) => {
    const current = second[index];
    return current !== undefined
      && role === current[0]
      && field === current[1]
      && hasSameControlOwner(owner, current[2]);
  });
}
