export type ComposedTreeRoot = Document | ShadowRoot;

export const DEFAULT_COMPOSED_TREE_MAX_ROOTS = 256;
export const DEFAULT_COMPOSED_TREE_MAX_VISITED_ELEMENTS = 100_000;
export const DEFAULT_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS = 1_000;
export const MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS = 100;
export const MAX_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS = 10_000;

const MAX_CONFIGURED_ROOTS = 4_096;
const MAX_CONFIGURED_VISITED_ELEMENTS = 1_000_000;
const MUTATION_DISCOVERY_MAX_ELEMENTS = 2_048;
const IDLE_SWEEP_MAX_ELEMENTS_PER_SLICE = 512;
const IDLE_SWEEP_MAX_ELEMENTS_AFTER_TIMEOUT = 256;
const IDLE_SWEEP_MIN_REMAINING_MS = 1;
const IDLE_SWEEP_TIMEOUT_MS = 250;
const DOCUMENT_POSITION_PRECEDING = 2;
const DOCUMENT_POSITION_FOLLOWING = 4;
const NODE_FILTER_ACCEPT = 1;
const NODE_FILTER_REJECT = 2;
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
  /** Elements covered by the current bounded discovery accounting. */
  readonly visitedElements: number;
  /** True when a configured limit or pending continuation makes the inventory incomplete. */
  readonly truncated: boolean;
}

export interface ComposedTreeObserverOptions extends ComposedTreeScanOptions {
  /** Initial delay between complete late-shadow sweeps. Empty sweeps back off up to the maximum. */
  readonly rediscoveryIntervalMs?: number;
}

export interface ComposedTreeChange {
  readonly reason: 'mutation' | 'roots';
  readonly records: readonly MutationRecord[];
  readonly snapshot: ComposedTreeSnapshot;
}

export interface ComposedTreeObserverHandle {
  snapshot(): ComposedTreeSnapshot;
  /** Force an immediate authoritative, bounded root scan after a caller-controlled DOM operation. */
  refresh(): ComposedTreeSnapshot;
  disconnect(): void;
}

interface NormalizedScanOptions {
  readonly maxRoots: number;
  readonly maxVisitedElements: number;
  readonly getShadowRoot: (element: Element) => ShadowRoot | null;
}

interface IdleDeadlineLike {
  readonly didTimeout: boolean;
  timeRemaining(): number;
}

type ScheduledIdleWork =
  | { readonly kind: 'idle'; readonly handle: unknown }
  | { readonly kind: 'microtask' };

interface ComposedTreeSweep {
  readonly roots: ComposedTreeRoot[];
  readonly seenRoots: Set<ComposedTreeRoot>;
  readonly elements: WeakSet<Element>;
  readonly mutationGeneration: number;
  rootIndex: number;
  walker: TreeWalker | undefined;
  visitedElements: number;
  discoveredNewRoot: boolean;
}

interface IncrementalDiscoveryResult {
  readonly visitedElements: number;
  readonly truncated: boolean;
}

interface RemovedElementResult {
  readonly forgottenElements: number;
  readonly truncated: boolean;
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
  elements?: WeakSet<Element>,
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
      const element = node as Element;
      elements?.add(element);
      const shadowRoot = limits.getShadowRoot(element);
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
 * and nested DOM changes without re-scanning the existing tree. Bounded, resumable idle sweeps catch
 * attachShadow() calls on already-connected hosts. Removed roots are pruned after each mutation batch,
 * and disconnect() tears down observers plus every scheduled sweep resource.
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
  let knownElements = new WeakSet<Element>();
  let currentSnapshot = scanComposedRoots(baseRoot, scanOptions, knownElements);
  let disconnected = false;
  let currentRediscoveryDelayMs = rediscoveryIntervalMs;
  let knownElementCount = currentSnapshot.visitedElements;
  let treeMutationGeneration = 0;
  const rootObservers = new Map<ComposedTreeRoot, MutationObserver>();
  const knownRoots = new Set<ComposedTreeRoot>(currentSnapshot.roots);
  const rootAdmissionOrder = new Map<ComposedTreeRoot, number>();
  let nextRootAdmissionOrder = 0;
  for (const root of currentSnapshot.roots) rootAdmissionOrder.set(root, nextRootAdmissionOrder++);
  const pendingMutationRecords: MutationRecord[] = [];
  let mutationFlushQueued = false;
  let rediscoveryDelayTimer: ReturnType<typeof setTimeout> | undefined;
  let rediscoveryDelayDeadline: number | undefined;
  let scheduledIdleWork: ScheduledIdleWork | undefined;
  let sweep: ComposedTreeSweep | undefined;
  let sweepScheduleGeneration = 0;

  const rememberRoot = (root: ComposedTreeRoot): boolean => {
    if (knownRoots.has(root)) return false;
    knownRoots.add(root);
    rootAdmissionOrder.set(root, nextRootAdmissionOrder++);
    return true;
  };

  const replaceKnownRoots = (roots: readonly ComposedTreeRoot[]): void => {
    const nextRoots = new Set(roots);
    for (const root of knownRoots) {
      if (nextRoots.has(root)) continue;
      knownRoots.delete(root);
      rootAdmissionOrder.delete(root);
    }
    for (const root of roots) rememberRoot(root);
  };

  const pruneKnownRoots = (): { readonly roots: readonly ComposedTreeRoot[]; readonly truncated: boolean } => {
    const orderedRoots = orderedReachableRoots(baseRoot, knownRoots, rootAdmissionOrder);
    const rootLimitExceeded = orderedRoots.length > scanOptions.maxRoots;
    const roots = rootLimitExceeded
      ? orderedRoots.slice(0, scanOptions.maxRoots)
      : orderedRoots;
    const reachableRoots = new Set(roots);
    for (const root of knownRoots) {
      if (reachableRoots.has(root)) continue;
      knownRoots.delete(root);
      rootAdmissionOrder.delete(root);
    }
    return Object.freeze({ roots, truncated: rootLimitExceeded });
  };

  const snapshotKnownRoots = (visitedElements: number, truncated: boolean): ComposedTreeSnapshot => {
    const pruned = pruneKnownRoots();
    return freezeSnapshot(pruned.roots, visitedElements, truncated || pruned.truncated);
  };

  const syncObservers = (next: ComposedTreeSnapshot): void => {
    const nextRoots = new Set(next.roots);
    for (const [root, observer] of rootObservers) {
      if (nextRoots.has(root)) continue;
      observer.disconnect();
      rootObservers.delete(root);
    }
    for (const root of next.roots) {
      if (rootObservers.has(root)) continue;
      const observer = new (mutationObserverForRoot(root))((records) => {
        if (disconnected || records.length === 0) return;
        pendingMutationRecords.push(...records);
        if (mutationFlushQueued) return;
        mutationFlushQueued = true;
        queueMicrotask(() => {
          mutationFlushQueued = false;
          if (disconnected || pendingMutationRecords.length === 0) return;
          const batch = pendingMutationRecords.splice(0, pendingMutationRecords.length);
          refreshFrom(batch);
        });
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

  const publish = (
    next: ComposedTreeSnapshot,
    records: readonly MutationRecord[],
  ): ComposedTreeSnapshot => {
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

  const clearScheduledSweep = (): void => {
    sweepScheduleGeneration += 1;
    if (rediscoveryDelayTimer !== undefined) {
      clearTimeout(rediscoveryDelayTimer);
      rediscoveryDelayTimer = undefined;
      rediscoveryDelayDeadline = undefined;
    }
    if (scheduledIdleWork) {
      cancelIdleWork(scheduledIdleWork);
      scheduledIdleWork = undefined;
    }
  };

  const scheduleSweepSlice = (delayMs: number): void => {
    if (disconnected || rediscoveryDelayTimer !== undefined || scheduledIdleWork) return;
    const generation = sweepScheduleGeneration;
    rediscoveryDelayDeadline = Date.now() + delayMs;
    rediscoveryDelayTimer = setTimeout(() => {
      if (generation !== sweepScheduleGeneration) return;
      rediscoveryDelayTimer = undefined;
      rediscoveryDelayDeadline = undefined;
      if (disconnected) return;
      scheduledIdleWork = requestIdleWork((deadline) => {
        if (generation !== sweepScheduleGeneration) return;
        scheduledIdleWork = undefined;
        runSweepSlice(deadline);
      });
    }, delayMs);
  };

  const restartSweep = (): void => {
    clearScheduledSweep();
    sweep = undefined;
    currentRediscoveryDelayMs = rediscoveryIntervalMs;
    scheduleSweepSlice(currentRediscoveryDelayMs);
  };

  const resetSweepBackoffAfterMutation = (): void => {
    treeMutationGeneration += 1;
    currentRediscoveryDelayMs = rediscoveryIntervalMs;
    if (sweep || scheduledIdleWork) return;
    const desiredDeadline = Date.now() + rediscoveryIntervalMs;
    if (rediscoveryDelayTimer !== undefined
        && rediscoveryDelayDeadline !== undefined
        && rediscoveryDelayDeadline <= desiredDeadline) return;
    clearScheduledSweep();
    scheduleSweepSlice(rediscoveryIntervalMs);
  };

  const disconnect = (): void => {
    if (disconnected) return;
    disconnected = true;
    clearScheduledSweep();
    sweep = undefined;
    pendingMutationRecords.length = 0;
    for (const observer of rootObservers.values()) observer.disconnect();
    rootObservers.clear();
  };

  const drainMutationRecords = (): MutationRecord[] => {
    const records = pendingMutationRecords.splice(0, pendingMutationRecords.length);
    for (const observer of rootObservers.values()) records.push(...observer.takeRecords());
    return records;
  };

  const refreshFrom = (records: readonly MutationRecord[]): ComposedTreeSnapshot => {
    if (disconnected) return currentSnapshot;
    if (!baseRootIsConnected(baseRoot)) {
      disconnect();
      return currentSnapshot;
    }
    const hasChildListMutation = records.some((record) => record.type === 'childList');
    let visitedElements = currentSnapshot.visitedElements;
    let truncated = currentSnapshot.truncated;
    if (hasChildListMutation) {
      resetSweepBackoffAfterMutation();
      const reachableRoots = new Set(orderedReachableRoots(baseRoot, knownRoots, rootAdmissionOrder));
      const removed = forgetRemovedElements(records, reachableRoots, scanOptions, knownElements);
      knownElementCount = Math.max(
        0,
        knownElementCount - removed.forgottenElements,
      );
      truncated ||= removed.truncated;
      const pruned = pruneKnownRoots();
      truncated ||= pruned.truncated;
      const remainingVisitedElements = Math.max(
        0,
        Math.min(
          MUTATION_DISCOVERY_MAX_ELEMENTS,
          scanOptions.maxVisitedElements - knownElementCount,
        ),
      );
      const result = discoverRootsFromAddedNodes(
        records,
        knownRoots,
        scanOptions,
        remainingVisitedElements,
        knownElements,
        rememberRoot,
      );
      knownElementCount = Math.min(
        scanOptions.maxVisitedElements,
        knownElementCount + result.visitedElements,
      );
      visitedElements = knownElementCount;
      truncated ||= result.truncated;
    }
    return publish(snapshotKnownRoots(visitedElements, truncated), records);
  };

  const refresh = (): ComposedTreeSnapshot => {
    if (disconnected) return currentSnapshot;
    if (!baseRootIsConnected(baseRoot)) {
      disconnect();
      return currentSnapshot;
    }
    const records = drainMutationRecords();
    if (records.some((record) => record.type === 'childList')) treeMutationGeneration += 1;
    restartSweep();
    const nextElements = new WeakSet<Element>();
    const next = scanComposedRoots(baseRoot, scanOptions, nextElements);
    replaceKnownRoots(next.roots);
    knownElements = nextElements;
    knownElementCount = next.visitedElements;
    return publish(next, records);
  };

  const finishSweep = (truncated: boolean): void => {
    const completed = sweep;
    if (!completed) return;
    sweep = undefined;
    const stable = completed.mutationGeneration === treeMutationGeneration;
    if (stable) {
      replaceKnownRoots(completed.roots);
      knownElements = completed.elements;
      knownElementCount = completed.visitedElements;
    }
    const next = snapshotKnownRoots(
      stable ? completed.visitedElements : knownElementCount,
      truncated || (!stable && currentSnapshot.truncated),
    );
    publish(next, []);
    currentRediscoveryDelayMs = !stable || completed.discoveredNewRoot
      ? rediscoveryIntervalMs
      : Math.min(
          MAX_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
          currentRediscoveryDelayMs * 2,
        );
    scheduleSweepSlice(currentRediscoveryDelayMs);
  };

  const runSweepSlice = (deadline: IdleDeadlineLike): void => {
    if (disconnected) return;
    if (!baseRootIsConnected(baseRoot)) {
      disconnect();
      return;
    }
    sweep ??= {
      roots: [baseRoot],
      seenRoots: new Set([baseRoot]),
      elements: new WeakSet<Element>(),
      mutationGeneration: treeMutationGeneration,
      rootIndex: 0,
      walker: undefined,
      visitedElements: 0,
      discoveredNewRoot: false,
    };
    const activeSweep = sweep;
    let workUnitsThisSlice = 0;
    let discoveredThisSlice = false;
    const sliceLimit = deadline.didTimeout
      ? IDLE_SWEEP_MAX_ELEMENTS_AFTER_TIMEOUT
      : IDLE_SWEEP_MAX_ELEMENTS_PER_SLICE;

    while (workUnitsThisSlice < sliceLimit) {
      if (!deadline.didTimeout
          && workUnitsThisSlice > 0
          && idleTimeRemaining(deadline) <= IDLE_SWEEP_MIN_REMAINING_MS) break;
      workUnitsThisSlice += 1;
      if (!activeSweep.walker) {
        const root = activeSweep.roots[activeSweep.rootIndex];
        if (!root) {
          finishSweep(false);
          return;
        }
        activeSweep.walker = documentForRoot(root).createTreeWalker(root, 1);
      }
      const currentRoot = activeSweep.roots[activeSweep.rootIndex];
      if (currentRoot !== baseRoot && currentRoot && !knownRoots.has(currentRoot)) {
        activeSweep.walker = undefined;
        activeSweep.rootIndex += 1;
        continue;
      }
      const node = activeSweep.walker.nextNode();
      if (!node) {
        activeSweep.walker = undefined;
        activeSweep.rootIndex += 1;
        continue;
      }
      if (activeSweep.visitedElements >= scanOptions.maxVisitedElements) {
        finishSweep(true);
        return;
      }
      activeSweep.visitedElements += 1;
      const element = node as Element;
      activeSweep.elements.add(element);
      if (!knownElements.has(element)) {
        knownElements.add(element);
        knownElementCount = Math.min(scanOptions.maxVisitedElements, knownElementCount + 1);
      }
      const shadowRoot = scanOptions.getShadowRoot(element);
      if (!shadowRoot || activeSweep.seenRoots.has(shadowRoot)) continue;
      if (activeSweep.seenRoots.size >= scanOptions.maxRoots) {
        finishSweep(true);
        return;
      }
      activeSweep.seenRoots.add(shadowRoot);
      activeSweep.roots.push(shadowRoot);
      if (rememberRoot(shadowRoot)) {
        activeSweep.discoveredNewRoot = true;
        discoveredThisSlice = true;
      }
    }

    if (discoveredThisSlice) {
      publish(snapshotKnownRoots(knownElementCount, true), []);
    }
    scheduleSweepSlice(0);
  };

  syncObservers(currentSnapshot);
  scheduleSweepSlice(currentRediscoveryDelayMs);

  return Object.freeze({
    snapshot: () => currentSnapshot,
    refresh,
    disconnect,
  });
}

function discoverRootsFromAddedNodes(
  records: readonly MutationRecord[],
  knownRoots: ReadonlySet<ComposedTreeRoot>,
  limits: NormalizedScanOptions,
  remainingVisitedElements: number,
  knownElements: WeakSet<Element>,
  rememberRoot: (root: ComposedTreeRoot) => boolean,
): IncrementalDiscoveryResult {
  const pendingRoots: ShadowRoot[] = [];
  const queuedNodes = new Set<Node>();
  const seenElements = new Set<Element>();
  let recordIndex = 0;
  let addedNodeIndex = 0;
  let pendingRootIndex = 0;
  let inspectedAddedNodes = 0;
  let visitedElements = 0;
  let processedElements = 0;
  let truncated = false;
  let stopped = false;

  const enqueueRoot = (root: ShadowRoot): void => {
    if (queuedNodes.has(root)) return;
    queuedNodes.add(root);
    pendingRoots.push(root);
  };

  const nextPendingNode = (): Node | undefined => {
    while (recordIndex < records.length) {
      const record = records[recordIndex]!;
      if (record.type !== 'childList' || addedNodeIndex >= record.addedNodes.length) {
        recordIndex += 1;
        addedNodeIndex = 0;
        continue;
      }
      if (inspectedAddedNodes >= MUTATION_DISCOVERY_MAX_ELEMENTS) {
        truncated = true;
        stopped = true;
        return undefined;
      }
      const node = record.addedNodes[addedNodeIndex++]!;
      inspectedAddedNodes += 1;
      if (node.nodeType !== 1 || queuedNodes.has(node)) continue;
      queuedNodes.add(node);
      return node;
    }
    return pendingRoots[pendingRootIndex++];
  };

  const visitElement = (element: Element): boolean => {
    if (seenElements.has(element)) return true;
    if (processedElements >= MUTATION_DISCOVERY_MAX_ELEMENTS) {
      truncated = true;
      stopped = true;
      return false;
    }
    processedElements += 1;
    seenElements.add(element);
    if (!knownElements.has(element)) {
      if (visitedElements >= remainingVisitedElements) {
        truncated = true;
        stopped = true;
        return false;
      }
      knownElements.add(element);
      visitedElements += 1;
    }
    const shadowRoot = limits.getShadowRoot(element);
    if (!shadowRoot || knownRoots.has(shadowRoot)) return true;
    if (knownRoots.size >= limits.maxRoots) truncated = true;
    rememberRoot(shadowRoot);
    enqueueRoot(shadowRoot);
    return true;
  };

  while (!stopped) {
    const pending = nextPendingNode();
    if (!pending) break;
    if (pending.nodeType === 1) {
      if (seenElements.has(pending as Element)) continue;
      let containingRoot: Node;
      try {
        containingRoot = pending.getRootNode();
      } catch {
        continue;
      }
      if (!knownRoots.has(containingRoot as ComposedTreeRoot)) continue;
      if (!visitElement(pending as Element)) break;
    } else if (!knownRoots.has(pending as ComposedTreeRoot)) {
      continue;
    }

    const walker = documentForNode(pending).createTreeWalker(pending, 1, {
      acceptNode: (node) => seenElements.has(node as Element)
        ? NODE_FILTER_REJECT
        : NODE_FILTER_ACCEPT,
    });
    let node = walker.nextNode();
    while (node) {
      if (!visitElement(node as Element)) break;
      node = walker.nextNode();
    }
  }

  return Object.freeze({ visitedElements, truncated });
}

function forgetRemovedElements(
  records: readonly MutationRecord[],
  reachableRoots: ReadonlySet<ComposedTreeRoot>,
  limits: NormalizedScanOptions,
  knownElements: WeakSet<Element>,
): RemovedElementResult {
  const pendingRoots: ShadowRoot[] = [];
  const queuedNodes = new Set<Node>();
  const seenElements = new Set<Element>();
  let recordIndex = 0;
  let removedNodeIndex = 0;
  let pendingRootIndex = 0;
  let inspectedNodes = 0;
  let visitedElements = 0;
  let forgottenElements = 0;
  let truncated = false;
  let stopped = false;

  const enqueueRoot = (root: ShadowRoot): void => {
    if (queuedNodes.has(root)) return;
    queuedNodes.add(root);
    pendingRoots.push(root);
  };

  const nextPendingNode = (): Node | undefined => {
    while (recordIndex < records.length) {
      const record = records[recordIndex]!;
      if (record.type !== 'childList' || removedNodeIndex >= record.removedNodes.length) {
        recordIndex += 1;
        removedNodeIndex = 0;
        continue;
      }
      if (inspectedNodes >= MUTATION_DISCOVERY_MAX_ELEMENTS) {
        truncated = true;
        stopped = true;
        return undefined;
      }
      const node = record.removedNodes[removedNodeIndex++]!;
      inspectedNodes += 1;
      if (node.nodeType !== 1 || queuedNodes.has(node)) continue;
      queuedNodes.add(node);
      return node;
    }
    return pendingRoots[pendingRootIndex++];
  };

  const forgetElement = (element: Element): boolean => {
    if (seenElements.has(element)) return true;
    if (visitedElements >= MUTATION_DISCOVERY_MAX_ELEMENTS) {
      truncated = true;
      stopped = true;
      return false;
    }
    seenElements.add(element);
    visitedElements += 1;
    if (knownElements.delete(element)) forgottenElements += 1;
    const shadowRoot = limits.getShadowRoot(element);
    if (shadowRoot) enqueueRoot(shadowRoot);
    return true;
  };

  while (!stopped) {
    const pending = nextPendingNode();
    if (!pending) break;
    if (pending.nodeType === 1) {
      if (seenElements.has(pending as Element)) continue;
      let currentRoot: Node;
      try {
        currentRoot = pending.getRootNode();
      } catch {
        continue;
      }
      if (reachableRoots.has(currentRoot as ComposedTreeRoot)) continue;
      if (!forgetElement(pending as Element)) break;
    }

    const walker = documentForNode(pending).createTreeWalker(pending, 1, {
      acceptNode: (node) => seenElements.has(node as Element)
        ? NODE_FILTER_REJECT
        : NODE_FILTER_ACCEPT,
    });
    let node = walker.nextNode();
    while (node) {
      if (!forgetElement(node as Element)) break;
      node = walker.nextNode();
    }
  }

  return Object.freeze({ forgottenElements, truncated });
}

function orderedReachableRoots(
  baseRoot: ComposedTreeRoot,
  knownRoots: ReadonlySet<ComposedTreeRoot>,
  admissionOrder: ReadonlyMap<ComposedTreeRoot, number>,
): readonly ComposedTreeRoot[] {
  const children = new Map<ComposedTreeRoot, ShadowRoot[]>();
  for (const root of knownRoots) {
    if (root === baseRoot || root.nodeType !== 11) continue;
    const shadowRoot = root as ShadowRoot;
    let host: Element;
    let parent: Node;
    try {
      host = shadowRoot.host;
      if (!isOwnedShadowRoot(shadowRoot, host) || extensionOwnedRoots.has(shadowRoot)) continue;
      parent = host.getRootNode();
    } catch {
      continue;
    }
    if (!knownRoots.has(parent as ComposedTreeRoot)) continue;
    const parentRoot = parent as ComposedTreeRoot;
    const siblings = children.get(parentRoot) ?? [];
    siblings.push(shadowRoot);
    children.set(parentRoot, siblings);
  }

  for (const siblings of children.values()) {
    siblings.sort((first, second) => compareShadowRootHosts(first, second, admissionOrder));
  }

  const ordered: ComposedTreeRoot[] = [baseRoot];
  const seen = new Set<ComposedTreeRoot>(ordered);
  for (let index = 0; index < ordered.length; index += 1) {
    for (const root of children.get(ordered[index]!) ?? []) {
      if (seen.has(root)) continue;
      seen.add(root);
      ordered.push(root);
    }
  }
  return ordered;
}

function compareShadowRootHosts(
  first: ShadowRoot,
  second: ShadowRoot,
  admissionOrder: ReadonlyMap<ComposedTreeRoot, number>,
): number {
  try {
    const position = first.host.compareDocumentPosition(second.host);
    if ((position & DOCUMENT_POSITION_FOLLOWING) !== 0) return -1;
    if ((position & DOCUMENT_POSITION_PRECEDING) !== 0) return 1;
  } catch {
    // Fall through to the stable admission order when the platform cannot compare the hosts.
  }
  return (admissionOrder.get(first) ?? 0) - (admissionOrder.get(second) ?? 0);
}

function requestIdleWork(callback: (deadline: IdleDeadlineLike) => void): ScheduledIdleWork {
  try {
    const request = Reflect.get(globalThis as object, 'requestIdleCallback') as unknown;
    if (typeof request === 'function') {
      const handle = Reflect.apply(request, globalThis, [callback, { timeout: IDLE_SWEEP_TIMEOUT_MS }]);
      return { kind: 'idle', handle };
    }
  } catch {
    // The delay timer already yielded; use a bounded microtask slice when idle work is unavailable.
  }
  queueMicrotask(() => {
    callback({ didTimeout: true, timeRemaining: () => 0 });
  });
  return { kind: 'microtask' };
}

function cancelIdleWork(work: ScheduledIdleWork): void {
  if (work.kind === 'microtask') return;
  try {
    const cancel = Reflect.get(globalThis as object, 'cancelIdleCallback') as unknown;
    if (typeof cancel === 'function') Reflect.apply(cancel, globalThis, [work.handle]);
  } catch {
    // A stale platform callback is also fenced by the observer's disconnected state.
  }
}

function idleTimeRemaining(deadline: IdleDeadlineLike): number {
  try {
    const remaining = deadline.timeRemaining();
    return Number.isFinite(remaining) ? Math.max(0, remaining) : 0;
  } catch {
    return 0;
  }
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

function documentForNode(node: Node): Document {
  if (node.nodeType === 9) return node as Document;
  const ownerDocument = node.ownerDocument;
  if (!ownerDocument) throw new TypeError('Node must have an owner document');
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
