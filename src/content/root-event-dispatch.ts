import {
  trustedComposedTarget,
  type AutofillDocumentController,
} from './autofill-document-controller.js';

export type TrustedRootTargetHandler = (target: EventTarget) => void;

/**
 * Bind one trusted event type to every discovered composed-tree root in the capture phase.
 *
 * Open roots expose their original target to the document listener, so the first observation can be
 * handled immediately. Chrome retargets closed-root events to the host, and a deeper listener is not
 * reliable across every privileged-wrapper lifecycle. For those events, synchronously resolve the
 * browser hit-tested or focused element from the bound root before page handlers can mutate the DOM.
 * A microtask fallback preserves events that originated on the host itself. Callers must use the captured
 * target instead of reading composedPath() after dispatch. Precise targets are delivered synchronously;
 * only a host fallback is delivered asynchronously.
 */
export function bindTrustedRootCaptureEvent<K extends keyof GlobalEventHandlersEventMap>(
  controller: Pick<AutofillDocumentController, 'bindRoots'>,
  type: K,
  onTarget: TrustedRootTargetHandler,
): () => void {
  const shadowRootsByHost = new Map<EventTarget, ShadowRoot>();
  const handledEvents = new WeakSet<Event>();
  const pendingHostTargets = new WeakMap<Event, EventTarget>();
  const scheduledFallbacks = new WeakSet<Event>();
  let activeRootBindings = 0;
  let stopped = false;

  const dispatch = (event: Event): void => {
    if (stopped || activeRootBindings === 0 || handledEvents.has(event)) return;
    const composedTarget = trustedComposedTarget(event);
    if (!composedTarget) return;
    const target = resolveRetargetedShadowTarget(event, composedTarget, shadowRootsByHost)
      ?? composedTarget;

    if (target === composedTarget && shadowRootsByHost.has(composedTarget)) {
      pendingHostTargets.set(event, composedTarget);
      if (scheduledFallbacks.has(event)) return;
      scheduledFallbacks.add(event);
      queueMicrotask(() => {
        scheduledFallbacks.delete(event);
        const fallbackTarget = pendingHostTargets.get(event);
        pendingHostTargets.delete(event);
        if (stopped || activeRootBindings === 0 || handledEvents.has(event) || !fallbackTarget) return;
        handledEvents.add(event);
        onTarget(fallbackTarget);
      });
      return;
    }

    handledEvents.add(event);
    pendingHostTargets.delete(event);
    onTarget(target);
  };

  const listener: EventListener = (event) => dispatch(event);
  const stopRootListeners = controller.bindRoots((root) => {
    let bound = true;
    activeRootBindings += 1;
    const host = root.nodeType === Node.DOCUMENT_FRAGMENT_NODE
      ? (root as ShadowRoot).host
      : undefined;
    if (host) {
      shadowRootsByHost.set(host, root as ShadowRoot);
    }
    root.addEventListener(type, listener, true);
    return () => {
      if (!bound) return;
      bound = false;
      root.removeEventListener(type, listener, true);
      if (host) shadowRootsByHost.delete(host);
      activeRootBindings -= 1;
    };
  });

  return () => {
    if (stopped) return;
    stopped = true;
    stopRootListeners();
    shadowRootsByHost.clear();
  };
}

function resolveRetargetedShadowTarget(
  event: Event,
  target: EventTarget,
  rootsByHost: ReadonlyMap<EventTarget, ShadowRoot>,
): Element | undefined {
  if (!(target instanceof Element)) return undefined;
  const boundary = rootsByHost.get(target);
  if (!boundary) return undefined;
  const candidate = rootLocalTarget(boundary, event);
  if (!candidate || !isComposedDescendant(candidate, boundary)) return undefined;

  let resolved = candidate;
  const seen = new Set<Element>();
  while (!seen.has(resolved)) {
    seen.add(resolved);
    const nested = rootsByHost.get(resolved);
    if (!nested) break;
    const deeper = rootLocalTarget(nested, event);
    if (!deeper || !isComposedDescendant(deeper, nested)) break;
    resolved = deeper;
  }
  return resolved;
}

function rootLocalTarget(root: ShadowRoot, event: Event): Element | undefined {
  try {
    if (event.type === 'focusin') return root.activeElement ?? undefined;
    if (event instanceof MouseEvent) {
      if (event.type === 'contextmenu' && event.button === -1) {
        return root.activeElement ?? undefined;
      }
      return root.elementFromPoint(event.clientX, event.clientY) ?? undefined;
    }
  } catch {
    // The host fallback remains available when privileged root inspection fails.
  }
  return undefined;
}

function isComposedDescendant(element: Element, boundary: ShadowRoot): boolean {
  let current: Element = element;
  const seen = new Set<Node>();
  while (!seen.has(current)) {
    seen.add(current);
    let root: Node;
    try {
      root = current.getRootNode();
    } catch {
      return false;
    }
    if (root === boundary) return true;
    if (root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE || !('host' in root)) return false;
    current = (root as ShadowRoot).host;
  }
  return false;
}
