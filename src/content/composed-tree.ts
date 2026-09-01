export type ComposedTreeRoot = Document | ShadowRoot;

export const DEFAULT_COMPOSED_TREE_MAX_ROOTS = 256;
export const DEFAULT_COMPOSED_TREE_MAX_VISITED_ELEMENTS = 100_000;
export const DEFAULT_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS = 1_000;
export const MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS = 100;
export const MAX_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS = 10_000;

const MAX_CONFIGURED_ROOTS = 4_096;
const MAX_CONFIGURED_VISITED_ELEMENTS = 1_000_000;
const extensionOwnedRoots = new WeakSet<ShadowRoot>();

/** Attributes that can change whether a control is detectable, classifiable, or fillable. */
export const COMPOSED_TREE_AUTOFILL_ATTRIBUTE_FILTER = Object.freeze([
  'aria-hidden',
  'aria-label',
  'aria-labelledby',
  'autocomplete',
  'class',
  'data-bwignore',
  'disabled',
  'form',
  'for',
  'hidden',
  'id',
  'inert',
  'inputmode',
  'maxlength',
  'name',
  'open',
  'pattern',
  'placeholder',
  'readonly',
  'role',
  'slot',
  'style',
  'type',
] as const);

export interface ComposedTreeScanOptions {
  readonly maxRoots?: number;
  readonly maxVisitedElements?: number;
  /** Test/platform adapter for a possibly closed root. Public open roots are always checked first. */
  readonly getShadowRoot?: ComposedTreeShadowRootGetter;
}

export type ComposedTreeShadowRootGetter = (element: Element) => unknown;

export interface ComposedTreeSnapshot {
  /** Document/ShadowRoot discovery order. The base root is always first. */
  readonly roots: readonly ComposedTreeRoot[];
  readonly visitedElements: number;
  /** True when a configured root or element limit stopped discovery. */
  readonly truncated: boolean;
}

export interface ComposedTreeObserverOptions extends ComposedTreeScanOptions {
  readonly rediscoveryIntervalMs?: number;
}

export interface ComposedTreeChange {
  readonly reason: 'mutation' | 'roots';
  readonly records: readonly MutationRecord[];
  readonly snapshot: ComposedTreeSnapshot;
}

export interface ComposedTreeObserverHandle {
  snapshot(): ComposedTreeSnapshot;
  /** Force immediate root re-discovery; useful after a caller-controlled DOM operation. */
  refresh(): ComposedTreeSnapshot;
  disconnect(): void;
}

interface NormalizedScanOptions {
  readonly maxRoots: number;
  readonly maxVisitedElements: number;
  readonly getShadowRoot: (element: Element) => ShadowRoot | null;
}

/**
 * Return an element's public root or a strictly validated root exposed by Chrome's extension-only DOM
 * API. Invalid brands, owners, hosts, and platform failures all collapse to no root.
 */
export function getShadowRoot(element: Element): ShadowRoot | null {
  return resolveShadowRoot(element, chromeOpenOrClosedShadowRoot);
}

/** Exclude one extension-owned surface without exposing a forgeable marker to the page. */
export function registerExtensionOwnedShadowRoot(root: ShadowRoot): void {
  let host: Element;
  try {
    host = root.host;
  } catch {
    throw new TypeError('extension-owned root must be a ShadowRoot');
  }
  if (!isOwnedShadowRoot(root, host)) {
    throw new TypeError('extension-owned root must be a ShadowRoot');
  }
  extensionOwnedRoots.add(root);
}

/**
 * Discover a document and every nested accessible shadow root. Discovery is breadth-first and
 * identity-deduplicated, so repeated scans have stable root ordering for an unchanged DOM. Limits
 * make periodic use predictable on adversarial pages. Without Chrome's DOM API this remains open-only.
 */
export function scanOpenComposedRoots(
  baseRoot: ComposedTreeRoot,
  options: ComposedTreeScanOptions = {},
): ComposedTreeSnapshot {
  assertComposedRoot(baseRoot);
  return scanComposedRoots(baseRoot, normalizeScanOptions(options));
}

function scanComposedRoots(
  baseRoot: ComposedTreeRoot,
  limits: NormalizedScanOptions,
): ComposedTreeSnapshot {
  const roots: ComposedTreeRoot[] = [baseRoot];
  const seen = new Set<ComposedTreeRoot>(roots);
  let visitedElements = 0;
  let truncated = false;
  const ownerDocument = documentForRoot(baseRoot);

  for (let rootIndex = 0; rootIndex < roots.length; rootIndex += 1) {
    const root = roots[rootIndex]!;
    const walker = ownerDocument.createTreeWalker(root, 1);
    let node = walker.nextNode();
    while (node) {
      visitedElements += 1;
      if (visitedElements > limits.maxVisitedElements) {
        truncated = true;
        return freezeSnapshot(roots, limits.maxVisitedElements, truncated);
      }
      const shadowRoot = limits.getShadowRoot(node as Element);
      if (shadowRoot && !seen.has(shadowRoot)) {
        if (roots.length >= limits.maxRoots) {
          truncated = true;
          return freezeSnapshot(roots, visitedElements, truncated);
        }
        seen.add(shadowRoot);
        roots.push(shadowRoot);
      }
      node = walker.nextNode();
    }
  }
  return freezeSnapshot(roots, visitedElements, truncated);
}

/**
 * Observe mutations in every discovered accessible root. Native MutationObserver catches added hosts
 * and nested DOM changes; bounded periodic scans catch attachShadow() calls on connected hosts.
 * Removed roots are disconnected on the next refresh, and disconnect() tears down all resources.
 */
export function observeOpenComposedTree(
  baseRoot: ComposedTreeRoot,
  onChange: (change: ComposedTreeChange) => void,
  options: ComposedTreeObserverOptions = {},
): ComposedTreeObserverHandle {
  assertComposedRoot(baseRoot);
  if (typeof onChange !== 'function') throw new TypeError('onChange must be a function');
  const scanOptions = normalizeScanOptions(options);
  const rediscoveryIntervalMs = boundedInteger(
    options.rediscoveryIntervalMs ?? DEFAULT_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
    MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
    MAX_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
    'rediscoveryIntervalMs',
  );
  let currentSnapshot = scanComposedRoots(baseRoot, scanOptions);
  let disconnected = false;
  const rootObservers = new Map<ComposedTreeRoot, MutationObserver>();

  const syncObservers = (next: ComposedTreeSnapshot): void => {
    const nextRoots = new Set(next.roots);
    for (const [root, observer] of rootObservers) {
      if (nextRoots.has(root)) continue;
      observer.disconnect();
      rootObservers.delete(root);
    }
    for (const root of next.roots) {
      if (rootObservers.has(root)) continue;
      const observer = new (mutationObserverForRoot(baseRoot))((records) => {
        refreshFrom(records);
      });
      observer.observe(root, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: [...COMPOSED_TREE_AUTOFILL_ATTRIBUTE_FILTER],
      });
      rootObservers.set(root, observer);
    }
  };

  const disconnect = (): void => {
    if (disconnected) return;
    disconnected = true;
    clearInterval(rediscoveryTimer);
    for (const observer of rootObservers.values()) observer.disconnect();
    rootObservers.clear();
  };

  const refreshFrom = (records: readonly MutationRecord[]): ComposedTreeSnapshot => {
    if (disconnected) return currentSnapshot;
    if (!baseRootIsConnected(baseRoot)) {
      disconnect();
      return currentSnapshot;
    }
    // Attribute changes affect classification/visibility but cannot add or remove a shadow root.
    // Reuse the inventory for those hot-path mutations; child-list changes and periodic refreshes
    // still perform bounded discovery so connected hosts and late attachShadow() calls are found.
    const requiresDiscovery = records.length === 0 || records.some((record) => record.type === 'childList');
    const next = requiresDiscovery ? scanComposedRoots(baseRoot, scanOptions) : currentSnapshot;
    const rootsChanged = !sameRoots(currentSnapshot.roots, next.roots)
      || currentSnapshot.truncated !== next.truncated;
    currentSnapshot = next;
    syncObservers(next);
    if (rootsChanged || records.length > 0) {
      onChange(Object.freeze({
        reason: rootsChanged ? 'roots' : 'mutation',
        records: Object.freeze([...records]),
        snapshot: next,
      }));
    }
    return next;
  };

  syncObservers(currentSnapshot);
  const rediscoveryTimer = setInterval(() => {
    refreshFrom([]);
  }, rediscoveryIntervalMs);

  return Object.freeze({
    snapshot: () => currentSnapshot,
    refresh: () => refreshFrom([]),
    disconnect,
  });
}

function normalizeScanOptions(options: ComposedTreeScanOptions): NormalizedScanOptions {
  const platformGetter = options.getShadowRoot ?? chromeOpenOrClosedShadowRoot;
  return Object.freeze({
    maxRoots: boundedInteger(
      options.maxRoots ?? DEFAULT_COMPOSED_TREE_MAX_ROOTS,
      1,
      MAX_CONFIGURED_ROOTS,
      'maxRoots',
    ),
    maxVisitedElements: boundedInteger(
      options.maxVisitedElements ?? DEFAULT_COMPOSED_TREE_MAX_VISITED_ELEMENTS,
      1,
      MAX_CONFIGURED_VISITED_ELEMENTS,
      'maxVisitedElements',
    ),
    getShadowRoot: (element: Element) => resolveShadowRoot(element, platformGetter),
  });
}

function resolveShadowRoot(
  element: Element,
  platformGetter: ComposedTreeShadowRootGetter,
): ShadowRoot | null {
  let publicRoot: unknown;
  try {
    publicRoot = element.shadowRoot;
  } catch {
    // A platform root may still be available when a realm-specific public getter fails.
  }
  if (isOwnedShadowRoot(publicRoot, element)) {
    return extensionOwnedRoots.has(publicRoot) ? null : publicRoot;
  }

  try {
    const candidate = platformGetter(element);
    return isOwnedShadowRoot(candidate, element) && !extensionOwnedRoots.has(candidate)
      ? candidate
      : null;
  } catch {
    return null;
  }
}

function chromeOpenOrClosedShadowRoot(element: Element): unknown {
  try {
    const chromeValue = Reflect.get(globalThis as object, 'chrome') as unknown;
    if (!isObject(chromeValue)) return null;
    const dom = Reflect.get(chromeValue, 'dom') as unknown;
    if (!isObject(dom)) return null;
    const method = Reflect.get(dom, 'openOrClosedShadowRoot') as unknown;
    return typeof method === 'function' ? Reflect.apply(method, dom, [element]) : null;
  } catch {
    return null;
  }
}

function isOwnedShadowRoot(value: unknown, element: Element): value is ShadowRoot {
  if (!isObject(value)) return false;
  try {
    const ownerDocument = element.ownerDocument;
    const ShadowRootConstructor = ownerDocument.defaultView?.ShadowRoot ?? globalThis.ShadowRoot;
    return typeof ShadowRootConstructor === 'function'
      && value instanceof ShadowRootConstructor
      && value.nodeType === 11
      && value.ownerDocument === ownerDocument
      && value.host === element;
  } catch {
    return false;
  }
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function freezeSnapshot(
  roots: readonly ComposedTreeRoot[],
  visitedElements: number,
  truncated: boolean,
): ComposedTreeSnapshot {
  return Object.freeze({
    roots: Object.freeze([...roots]),
    visitedElements,
    truncated,
  });
}

function sameRoots(first: readonly ComposedTreeRoot[], second: readonly ComposedTreeRoot[]): boolean {
  return first.length === second.length && first.every((root, index) => root === second[index]);
}

function baseRootIsConnected(root: ComposedTreeRoot): boolean {
  return root.nodeType === 9 || ('host' in root && root.host.isConnected);
}

function assertComposedRoot(root: ComposedTreeRoot): void {
  if (!root || (root.nodeType !== 9 && root.nodeType !== 11)) {
    throw new TypeError('baseRoot must be a Document or ShadowRoot');
  }
  if (root.nodeType === 11 && (!('host' in root) || !root.ownerDocument)) {
    throw new TypeError('baseRoot must be a Document or ShadowRoot');
  }
}

function documentForRoot(root: ComposedTreeRoot): Document {
  if (root.nodeType === 9) return root as Document;
  const ownerDocument = root.ownerDocument;
  if (!ownerDocument) throw new TypeError('ShadowRoot must have an owner document');
  return ownerDocument;
}

function mutationObserverForRoot(root: ComposedTreeRoot): typeof MutationObserver {
  return documentForRoot(root).defaultView?.MutationObserver ?? MutationObserver;
}

function boundedInteger(value: number, minimum: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}
