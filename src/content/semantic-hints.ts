import type { FieldHints } from './field-map.js';

export type SemanticHintControl = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

const MAX_SEMANTIC_SOURCES = 8;
const MAX_ARIA_LABELLEDBY_LENGTH = 1_024;
const MAX_ARIA_REFERENCE_LENGTH = 256;
const MAX_SEMANTIC_SOURCE_NODES = 128;
const MAX_SEMANTIC_SOURCE_RAW_CHARACTERS = 1_024;
const MAX_SEMANTIC_LABEL_CHARACTERS = 256;
const MAX_SEMANTIC_LABEL_BYTES = 1_024;
const MAX_FIELD_ATTRIBUTE_CHARACTERS = 1_024;
const MAX_FIELD_ATTRIBUTE_BYTES = 1_024;
const MAX_FIELD_ATTRIBUTES_BYTES = 4_096;

type SemanticSourceCheck = (element: HTMLElement) => boolean;

export interface SemanticHintBudget {
  claimHintBytes(bytes: number): boolean;
  claimSemanticSource(): boolean;
  claimSemanticNode(): boolean;
  markExceeded(kind: 'hint_bytes' | 'semantic_sources' | 'semantic_nodes'): void;
}

interface TextBudget {
  visitedNodes: number;
}

interface SemanticLabels {
  readonly values: readonly string[];
  readonly unsafe: boolean;
}

interface CollectedText {
  readonly value?: string;
  readonly overflowed: boolean;
}

interface NodeFrame {
  readonly nodes: NodeListOf<ChildNode>;
  readonly length: number;
  index: number;
}

interface BoundedFieldAttributes {
  readonly autocomplete: string;
  readonly name: string;
  readonly id: string;
  readonly ariaLabel: string;
  readonly placeholder: string;
  readonly inputType: string;
  readonly unsafe: boolean;
}

const EMPTY_LABELS = Object.freeze([] as string[]);
const NATIVE_INPUT_LABELS = inheritedAccessor(HTMLInputElement.prototype, 'labels');
const NATIVE_SELECT_LABELS = inheritedAccessor(HTMLSelectElement.prototype, 'labels');
const NATIVE_TEXTAREA_LABELS = inheritedAccessor(HTMLTextAreaElement.prototype, 'labels');
const NATIVE_GET_ATTRIBUTE = inheritedMethod(Element.prototype, 'getAttribute');
const NATIVE_HAS_ATTRIBUTE = inheritedMethod(Element.prototype, 'hasAttribute');
const NATIVE_GET_ROOT_NODE = inheritedMethod(Node.prototype, 'getRootNode');
const NATIVE_CHILD_NODES = inheritedAccessor(Node.prototype, 'childNodes');
const NATIVE_TEXT_DATA = inheritedAccessor(Text.prototype, 'data');
const NATIVE_DOCUMENT_GET_ELEMENT_BY_ID = inheritedMethod(Document.prototype, 'getElementById');
const NATIVE_FRAGMENT_GET_ELEMENT_BY_ID = inheritedMethod(DocumentFragment.prototype, 'getElementById');
const NATIVE_SHADOW_HOST = inheritedAccessor(ShadowRoot.prototype, 'host');
const NATIVE_NODE_LIST_LENGTH = inheritedAccessor(NodeList.prototype, 'length');
const NATIVE_NODE_LIST_ITEM = inheritedMethod(NodeList.prototype, 'item');

/**
 * Collect bounded, root-local field semantics without mutating the page or reading control values.
 * Native label accessors are invoked from their prototypes so page-defined instance getters are not
 * evaluated. `aria-labelledby` references are resolved only inside the control's own tree root.
 */
export function collectFieldHints(
  control: SemanticHintControl,
  isSemanticSourceAvailable: SemanticSourceCheck,
  budget?: SemanticHintBudget,
): FieldHints {
  const attributes = boundedFieldAttributes(control, budget);
  const semantic = attributes.unsafe
    ? unsafeLabels()
    : collectSemanticLabels(
        control,
        isSemanticSourceAvailable,
        utf8ByteLength(attributes.ariaLabel),
        budget,
      );
  return Object.freeze({
    autocomplete: attributes.autocomplete,
    name: attributes.name,
    id: attributes.id,
    ariaLabel: attributes.ariaLabel,
    placeholder: attributes.placeholder,
    type: control instanceof HTMLInputElement
      ? (attributes.inputType.trim().toLowerCase() || 'text')
      : control instanceof HTMLTextAreaElement ? 'textarea' : 'select',
    semanticLabels: semantic.values,
    semanticLabelsUnsafe: attributes.unsafe || semantic.unsafe,
  });
}

function collectSemanticLabels(
  control: SemanticHintControl,
  isSemanticSourceAvailable: SemanticSourceCheck,
  initialBytes: number,
  budget?: SemanticHintBudget,
): SemanticLabels {
  const root = semanticRoot(control);
  if (!root) return unsafeLabels();

  const sources: HTMLElement[] = [];
  const seenSources = new Set<HTMLElement>();
  const labels = associatedLabelsFor(control, budget);
  if (!labels || labels.length > MAX_SEMANTIC_SOURCES) return unsafeLabels();
  for (let index = 0; index < labels.length; index += 1) {
    const label = labels[index];
    if (!label || nativeRoot(label) !== root) return unsafeLabels();
    if (seenSources.has(label)) continue;
    if (budget && !budget.claimSemanticSource()) return unsafeLabels();
    seenSources.add(label);
    sources.push(label);
  }

  const ariaLabelledby = attribute(control, 'aria-labelledby');
  if (ariaLabelledby === undefined) return unsafeLabels();
  if (
    ariaLabelledby.length > MAX_ARIA_LABELLEDBY_LENGTH
    || utf8ByteLength(ariaLabelledby) > MAX_FIELD_ATTRIBUTE_BYTES
  ) {
    budget?.markExceeded('hint_bytes');
    return unsafeLabels();
  }
  if (budget && !budget.claimHintBytes(utf8ByteLength(ariaLabelledby))) return unsafeLabels();
  const references = ariaLabelledby.trim().split(/[\t\n\f\r ]+/u).filter(Boolean);
  if (references.length > MAX_SEMANTIC_SOURCES) {
    budget?.markExceeded('semantic_sources');
    return unsafeLabels();
  }
  for (const reference of references) {
    if (reference.length > MAX_ARIA_REFERENCE_LENGTH) {
      budget?.markExceeded('hint_bytes');
      return unsafeLabels();
    }
    const target = elementById(root, reference);
    if (!(target instanceof HTMLElement) || target === control || nativeRoot(target) !== root) {
      return unsafeLabels();
    }
    if (seenSources.has(target)) continue;
    if (budget && !budget.claimSemanticSource()) return unsafeLabels();
    seenSources.add(target);
    sources.push(target);
    if (sources.length > MAX_SEMANTIC_SOURCES) {
      budget?.markExceeded('semantic_sources');
      return unsafeLabels();
    }
  }

  const textBudget: TextBudget = { visitedNodes: 0 };
  const values: string[] = [];
  const seenValues = new Set<string>();
  let totalBytes = initialBytes;
  for (const source of sources) {
    if (sourceAvailable(source, isSemanticSourceAvailable) !== true) return unsafeLabels();
    const collected = boundedSemanticText(source, isSemanticSourceAvailable, textBudget, budget);
    if (collected.overflowed) return unsafeLabels();
    const value = collected.value;
    if (!value || seenValues.has(value)) continue;
    const bytes = utf8ByteLength(value);
    if (bytes > MAX_SEMANTIC_LABEL_BYTES - totalBytes) {
      budget?.markExceeded('hint_bytes');
      return unsafeLabels();
    }
    if (budget && !budget.claimHintBytes(bytes)) return unsafeLabels();
    totalBytes += bytes;
    seenValues.add(value);
    values.push(value);
  }
  return Object.freeze({ values: Object.freeze(values), unsafe: false });
}

function unsafeLabels(): SemanticLabels {
  return Object.freeze({ values: EMPTY_LABELS, unsafe: true });
}

function boundedFieldAttributes(element: Element, budget?: SemanticHintBudget): BoundedFieldAttributes {
  const names = ['autocomplete', 'name', 'id', 'aria-label', 'placeholder', 'type'] as const;
  const values = new Map<typeof names[number], string>();
  let totalBytes = 0;
  for (const name of names) {
    const raw = attribute(element, name);
    if (raw === undefined) return emptyFieldAttributes(true);
    if (raw.length > MAX_FIELD_ATTRIBUTE_CHARACTERS) {
      budget?.markExceeded('hint_bytes');
      return emptyFieldAttributes(true);
    }
    const value = name === 'aria-label' ? raw.replace(/\s+/gu, ' ').trim() : raw;
    const characters = name === 'aria-label'
      ? MAX_SEMANTIC_LABEL_CHARACTERS
      : MAX_FIELD_ATTRIBUTE_CHARACTERS;
    if (value.length > characters) {
      budget?.markExceeded('hint_bytes');
      return emptyFieldAttributes(true);
    }
    const bytes = utf8ByteLength(raw);
    if (
      bytes > MAX_FIELD_ATTRIBUTE_BYTES
      || bytes > MAX_FIELD_ATTRIBUTES_BYTES - totalBytes
    ) {
      budget?.markExceeded('hint_bytes');
      return emptyFieldAttributes(true);
    }
    if (budget && !budget.claimHintBytes(bytes)) return emptyFieldAttributes(true);
    totalBytes += bytes;
    values.set(name, value);
  }
  return {
    autocomplete: values.get('autocomplete')!,
    name: values.get('name')!,
    id: values.get('id')!,
    ariaLabel: values.get('aria-label')!,
    placeholder: values.get('placeholder')!,
    inputType: values.get('type')!,
    unsafe: false,
  };
}

function emptyFieldAttributes(unsafe: boolean): BoundedFieldAttributes {
  return {
    autocomplete: '',
    name: '',
    id: '',
    ariaLabel: '',
    placeholder: '',
    inputType: '',
    unsafe,
  };
}

function boundedSemanticText(
  source: HTMLElement,
  isSemanticSourceAvailable: SemanticSourceCheck,
  textBudget: TextBudget,
  projectionBudget?: SemanticHintBudget,
): CollectedText {
  const parts: string[] = [];
  let rawCharacters = 0;
  const stack: NodeFrame[] = [];
  const initial = childNodes(source);
  if (!initial) return { overflowed: true };
  const initialFrame = nodeFrame(initial);
  if (!initialFrame) return { overflowed: true };
  stack.push(initialFrame);

  while (stack.length > 0) {
    const frame = stack.at(-1)!;
    if (frame.index >= frame.length) {
      if (nativeNodeListLength(frame.nodes) !== frame.length) {
        projectionBudget?.markExceeded('semantic_nodes');
        return { overflowed: true };
      }
      stack.pop();
      continue;
    }
    const node = nativeNodeListItem(frame.nodes, frame.index);
    frame.index += 1;
    if (!node) return { overflowed: true };
    textBudget.visitedNodes += 1;
    if (textBudget.visitedNodes > MAX_SEMANTIC_SOURCE_NODES) {
      projectionBudget?.markExceeded('semantic_nodes');
      return { overflowed: true };
    }
    if (projectionBudget && !projectionBudget.claimSemanticNode()) return { overflowed: true };

    if (node instanceof Text) {
      const value = textData(node);
      if (value === undefined) return { overflowed: true };
      if (projectionBudget && !projectionBudget.claimHintBytes(utf8ByteLength(value))) {
        return { overflowed: true };
      }
      rawCharacters += value.length;
      if (rawCharacters > MAX_SEMANTIC_SOURCE_RAW_CHARACTERS) {
        projectionBudget?.markExceeded('hint_bytes');
        return { overflowed: true };
      }
      parts.push(value);
      continue;
    }
    if (node instanceof Element && !(node instanceof HTMLElement)) {
      const hidden = foreignElementIsHidden(node);
      if (hidden === undefined) return { overflowed: true };
      if (hidden) continue;
      return { overflowed: true };
    }
    if (!(node instanceof HTMLElement) || excludedTextSubtree(node)) continue;
    const available = sourceAvailable(node, isSemanticSourceAvailable);
    if (available === undefined) return { overflowed: true };
    if (!available) continue;
    const children = childNodes(node);
    if (!children) return { overflowed: true };
    const nextFrame = nodeFrame(children);
    if (!nextFrame) return { overflowed: true };
    stack.push(nextFrame);
  }

  const value = parts.join(' ').replace(/\s+/gu, ' ').trim();
  if (value.length > MAX_SEMANTIC_LABEL_CHARACTERS) {
    projectionBudget?.markExceeded('hint_bytes');
    return { overflowed: true };
  }
  return { value, overflowed: false };
}

function excludedTextSubtree(element: HTMLElement): boolean {
  return element instanceof HTMLInputElement
    || element instanceof HTMLSelectElement
    || element instanceof HTMLTextAreaElement
    || element instanceof HTMLButtonElement
    || element instanceof HTMLScriptElement
    || element instanceof HTMLStyleElement
    || element instanceof HTMLTemplateElement;
}

function sourceAvailable(element: HTMLElement, check: SemanticSourceCheck): boolean | undefined {
  try {
    return check(element);
  } catch {
    return undefined;
  }
}

function foreignElementIsHidden(element: Element): boolean | undefined {
  const ariaHidden = attribute(element, 'aria-hidden');
  const hidden = hasAttribute(element, 'hidden');
  if (ariaHidden === undefined || hidden === undefined) return undefined;
  return hidden || ariaHidden.trim().toLowerCase() === 'true';
}

/** Read native label associations without consulting an instance-defined `labels` getter. */
export function associatedLabelsFor(
  control: SemanticHintControl,
  budget?: SemanticHintBudget,
): readonly HTMLLabelElement[] | undefined {
  const getter = control instanceof HTMLInputElement
    ? NATIVE_INPUT_LABELS
    : control instanceof HTMLSelectElement
      ? NATIVE_SELECT_LABELS
      : NATIVE_TEXTAREA_LABELS;
  if (!getter) return undefined;
  try {
    const labels = Reflect.apply(getter, control, []) as unknown;
    if (!labels || typeof labels !== 'object') return undefined;
    const length = nativeNodeListLength(labels);
    if (length === undefined) return undefined;
    if (length > MAX_SEMANTIC_SOURCES) {
      budget?.markExceeded('semantic_sources');
      return undefined;
    }
    const result: HTMLLabelElement[] = [];
    for (let index = 0; index < length; index += 1) {
      const label = nativeNodeListItem(labels, index);
      if (!(label instanceof HTMLLabelElement)) return undefined;
      result.push(label);
    }
    return Object.freeze(result);
  } catch {
    return undefined;
  }
}

function attribute(element: Element, name: string): string | undefined {
  if (!NATIVE_GET_ATTRIBUTE) return undefined;
  try {
    const value = Reflect.apply(NATIVE_GET_ATTRIBUTE, element, [name]) as unknown;
    return value === null || typeof value === 'string' ? value ?? '' : undefined;
  } catch {
    return undefined;
  }
}

function hasAttribute(element: Element, name: string): boolean | undefined {
  if (!NATIVE_HAS_ATTRIBUTE) return undefined;
  try {
    const value = Reflect.apply(NATIVE_HAS_ATTRIBUTE, element, [name]) as unknown;
    return typeof value === 'boolean' ? value : undefined;
  } catch {
    return undefined;
  }
}

function nativeRoot(node: Node): Node | undefined {
  if (!NATIVE_GET_ROOT_NODE) return undefined;
  try {
    const root = Reflect.apply(NATIVE_GET_ROOT_NODE, node, []) as unknown;
    return root instanceof Node ? root : undefined;
  } catch {
    return undefined;
  }
}

function semanticRoot(node: Node): Document | ShadowRoot | undefined {
  const root = nativeRoot(node);
  if (!root) return undefined;
  if (root.nodeType === Node.DOCUMENT_NODE) return root as Document;
  if (root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE || !NATIVE_SHADOW_HOST) return undefined;
  try {
    const host = Reflect.apply(NATIVE_SHADOW_HOST, root, []) as unknown;
    return host instanceof Element ? root as ShadowRoot : undefined;
  } catch {
    return undefined;
  }
}

function childNodes(node: Node): NodeListOf<ChildNode> | undefined {
  if (!NATIVE_CHILD_NODES) return undefined;
  try {
    const nodes = Reflect.apply(NATIVE_CHILD_NODES, node, []) as unknown;
    return nodes && typeof nodes === 'object'
      ? nodes as NodeListOf<ChildNode>
      : undefined;
  } catch {
    return undefined;
  }
}

function textData(node: Text): string | undefined {
  if (!NATIVE_TEXT_DATA) return undefined;
  try {
    const value = Reflect.apply(NATIVE_TEXT_DATA, node, []) as unknown;
    return typeof value === 'string' ? value : undefined;
  } catch {
    return undefined;
  }
}

function elementById(root: Document | ShadowRoot, id: string): Element | null {
  const method = root.nodeType === Node.DOCUMENT_NODE
    ? NATIVE_DOCUMENT_GET_ELEMENT_BY_ID
    : NATIVE_FRAGMENT_GET_ELEMENT_BY_ID;
  if (!method) return null;
  try {
    const value = Reflect.apply(method, root, [id]) as unknown;
    return value instanceof Element ? value : null;
  } catch {
    return null;
  }
}

function nodeFrame(nodes: NodeListOf<ChildNode>): NodeFrame | undefined {
  const length = nativeNodeListLength(nodes);
  return length === undefined ? undefined : { nodes, length, index: 0 };
}

function nativeNodeListLength(nodes: object): number | undefined {
  if (!NATIVE_NODE_LIST_LENGTH) return undefined;
  try {
    const value = Reflect.apply(NATIVE_NODE_LIST_LENGTH, nodes, []) as unknown;
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}

function nativeNodeListItem(nodes: object, index: number): Node | null | undefined {
  if (!NATIVE_NODE_LIST_ITEM) return undefined;
  try {
    const value = Reflect.apply(NATIVE_NODE_LIST_ITEM, nodes, [index]) as unknown;
    return value === null || value instanceof Node ? value : undefined;
  } catch {
    return undefined;
  }
}

function inheritedAccessor(prototype: object, property: string): ((this: object) => unknown) | undefined {
  for (let current: object | null = prototype; current; current = Object.getPrototypeOf(current) as object | null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (typeof descriptor?.get === 'function') return descriptor.get;
  }
  return undefined;
}

function inheritedMethod(prototype: object, property: string): ((this: object, ...args: unknown[]) => unknown) | undefined {
  for (let current: object | null = prototype; current; current = Object.getPrototypeOf(current) as object | null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (typeof descriptor?.value === 'function') {
      return descriptor.value as (this: object, ...args: unknown[]) => unknown;
    }
  }
  return undefined;
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
