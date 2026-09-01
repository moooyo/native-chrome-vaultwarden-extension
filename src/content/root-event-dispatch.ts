import {
  trustedComposedTarget,
  type AutofillDocumentController,
} from './autofill-document-controller.js';

export type TrustedRootTargetHandler = (target: EventTarget) => void;

/**
 * Bind one trusted event type to every discovered composed-tree root in the capture phase.
 *
 * Open roots expose their original target to the document listener, so the first observation can be
 * handled immediately. Closed roots expose only a shadow host outside their boundary. Host-only
 * observations are held until the current dispatch reaches a deeper bound root. A microtask fallback
 * preserves events that originated on the host itself without letting an outer observation suppress a
 * more precise inner target. The target is always captured during dispatch; callers must use that target
 * instead of reading composedPath() again when a host fallback runs. Precise targets are delivered
 * synchronously; only a host fallback is delivered asynchronously.
 */
export function bindTrustedRootCaptureEvent<K extends keyof GlobalEventHandlersEventMap>(
  controller: Pick<AutofillDocumentController, 'bindRoots'>,
  type: K,
  onTarget: TrustedRootTargetHandler,
): () => void {
  const shadowHosts = new Set<EventTarget>();
  const handledEvents = new WeakSet<Event>();
  const pendingHostTargets = new WeakMap<Event, EventTarget>();
  const scheduledFallbacks = new WeakSet<Event>();
  let activeRootBindings = 0;
  let stopped = false;

  const dispatch = (event: Event): void => {
    if (stopped || activeRootBindings === 0 || handledEvents.has(event)) return;
    const target = trustedComposedTarget(event);
    if (!target) return;

    if (shadowHosts.has(target)) {
      pendingHostTargets.set(event, target);
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
    if (host) shadowHosts.add(host);
    root.addEventListener(type, listener, true);
    return () => {
      if (!bound) return;
      bound = false;
      root.removeEventListener(type, listener, true);
      if (host) shadowHosts.delete(host);
      activeRootBindings -= 1;
    };
  });

  return () => {
    if (stopped) return;
    stopped = true;
    stopRootListeners();
    shadowHosts.clear();
  };
}
