import {
  observeOpenComposedTree,
  scanOpenComposedRoots,
  type ComposedTreeChange,
  type ComposedTreeObserverHandle,
  type ComposedTreeObserverOptions,
  type ComposedTreeRoot,
  type ComposedTreeSnapshot,
} from './composed-tree.js';

export type RootBinding = (root: ComposedTreeRoot) => void | (() => void);

export interface AutofillDocumentControllerOptions extends ComposedTreeObserverOptions {
  readonly onChange?: (change: ComposedTreeChange) => void;
  /** Defaults to true. Autofill starts paused until its client feature policy is known. */
  readonly observeInitially?: boolean;
}

export interface AutofillDocumentController {
  readonly ownerDocument: Document;
  snapshot(): ComposedTreeSnapshot;
  roots(): readonly ComposedTreeRoot[];
  refresh(): ComposedTreeSnapshot;
  isObserving(): boolean;
  resumeObservation(): ComposedTreeSnapshot;
  pauseObservation(): void;
  /** Keep one listener/resource binding installed on every currently discovered root. */
  bindRoots(binding: RootBinding): () => void;
  /** Follow currently discovered shadow roots to the deepest active element without entering frames. */
  deepActiveElement(): Element | null;
  disconnect(): void;
}

/**
 * Owns the bounded inventory of a document and its nested accessible shadow roots. Closed roots are
 * included only when Chrome exposes them through its extension-only DOM API; discovery never patches
 * or replaces attachShadow().
 */
export function createAutofillDocumentController(
  ownerDocument: Document,
  options: AutofillDocumentControllerOptions = {},
): AutofillDocumentController {
  const bindings = new Set<RootBinding>();
  const cleanups = new Map<RootBinding, Map<ComposedTreeRoot, () => void>>();
  let disconnected = false;
  let observer: ComposedTreeObserverHandle | undefined;
  let currentSnapshot: ComposedTreeSnapshot = Object.freeze({
    roots: Object.freeze([ownerDocument]),
    visitedElements: 0,
    truncated: false,
  });

  const syncBinding = (binding: RootBinding, roots: readonly ComposedTreeRoot[]): void => {
    let byRoot = cleanups.get(binding);
    if (!byRoot) {
      byRoot = new Map();
      cleanups.set(binding, byRoot);
    }
    const nextRoots = new Set(roots);
    for (const [root, cleanup] of byRoot) {
      if (nextRoots.has(root)) continue;
      cleanup();
      byRoot.delete(root);
    }
    for (const root of roots) {
      if (byRoot.has(root)) continue;
      const cleanup = binding(root);
      byRoot.set(root, typeof cleanup === 'function' ? cleanup : () => undefined);
    }
  };

  const syncAllBindings = (snapshot: ComposedTreeSnapshot): void => {
    for (const binding of bindings) syncBinding(binding, snapshot.roots);
  };

  const startObservation = (notifyInitialChange: boolean): ComposedTreeSnapshot => {
    if (disconnected || observer) return currentSnapshot;
    const previous = currentSnapshot;
    const nextObserver = observeOpenComposedTree(ownerDocument, (change) => {
      currentSnapshot = change.snapshot;
      syncAllBindings(change.snapshot);
      options.onChange?.(change);
    }, options);
    observer = nextObserver;
    currentSnapshot = nextObserver.snapshot();
    syncAllBindings(currentSnapshot);
    if (notifyInitialChange && !sameSnapshotRoots(previous, currentSnapshot)) {
      options.onChange?.(Object.freeze({
        reason: 'roots',
        records: Object.freeze([]),
        snapshot: currentSnapshot,
      }));
    }
    return currentSnapshot;
  };

  const resumeObservation = (): ComposedTreeSnapshot => startObservation(true);

  const pauseObservation = (): void => {
    if (!observer) return;
    currentSnapshot = observer.snapshot();
    observer.disconnect();
    observer = undefined;
  };

  const refresh = (): ComposedTreeSnapshot => {
    if (disconnected) return currentSnapshot;
    if (observer) {
      currentSnapshot = observer.refresh();
      syncAllBindings(currentSnapshot);
      return currentSnapshot;
    }
    const previous = currentSnapshot;
    currentSnapshot = scanOpenComposedRoots(ownerDocument, options);
    syncAllBindings(currentSnapshot);
    if (!sameSnapshotRoots(previous, currentSnapshot)) {
      options.onChange?.(Object.freeze({
        reason: 'roots',
        records: Object.freeze([]),
        snapshot: currentSnapshot,
      }));
    }
    return currentSnapshot;
  };

  const disconnect = (): void => {
    if (disconnected) return;
    disconnected = true;
    observer?.disconnect();
    observer = undefined;
    for (const byRoot of cleanups.values()) {
      for (const cleanup of byRoot.values()) cleanup();
      byRoot.clear();
    }
    cleanups.clear();
    bindings.clear();
  };

  if (options.observeInitially !== false) startObservation(false);

  return Object.freeze({
    ownerDocument,
    snapshot: () => currentSnapshot,
    roots: () => currentSnapshot.roots,
    refresh,
    isObserving: () => observer !== undefined,
    resumeObservation,
    pauseObservation,
    bindRoots(binding: RootBinding) {
      if (disconnected) return () => undefined;
      bindings.add(binding);
      syncBinding(binding, currentSnapshot.roots);
      return () => {
        if (!bindings.delete(binding)) return;
        const byRoot = cleanups.get(binding);
        if (!byRoot) return;
        for (const cleanup of byRoot.values()) cleanup();
        cleanups.delete(binding);
      };
    },
    deepActiveElement: () => deepActiveElement(ownerDocument, currentSnapshot.roots),
    disconnect,
  });
}

function sameSnapshotRoots(first: ComposedTreeSnapshot, second: ComposedTreeSnapshot): boolean {
  return first.truncated === second.truncated
    && first.roots.length === second.roots.length
    && first.roots.every((root, index) => root === second.roots[index]);
}

export function deepActiveElement(
  ownerDocument: Document,
  knownRoots: readonly ComposedTreeRoot[] = scanOpenComposedRoots(ownerDocument).roots,
): Element | null {
  const rootsByHost = new Map<Element, ShadowRoot>();
  for (const root of knownRoots) {
    if (root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) continue;
    const shadowRoot = root as ShadowRoot;
    try {
      if (shadowRoot.ownerDocument === ownerDocument && shadowRoot.host.ownerDocument === ownerDocument) {
        rootsByHost.set(shadowRoot.host, shadowRoot);
      }
    } catch {
      // Only roots from the controller's validated inventory are eligible.
    }
  }
  let active: Element | null = ownerDocument.activeElement;
  const seen = new Set<Element>();
  while (active && !seen.has(active)) {
    seen.add(active);
    const shadow = rootsByHost.get(active);
    const nested = shadow?.activeElement ?? null;
    if (!nested) break;
    active = nested;
  }
  return active;
}

/** Use the original target of a trusted composed event instead of its retargeted host. */
export function trustedComposedTarget(event: Event): EventTarget | null {
  if (!event.isTrusted) return null;
  const path = event.composedPath();
  return path[0] ?? null;
}

export function rootForElement(element: Element): Document | ShadowRoot | undefined {
  const root = element.getRootNode();
  if (root.nodeType === Node.DOCUMENT_NODE) return root as Document;
  if (root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && 'host' in root) return root as ShadowRoot;
  return undefined;
}
