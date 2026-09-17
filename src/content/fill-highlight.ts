// A restrained blue wash flashes over an input the moment it is
// autofilled, then fades — signalling "this field was just filled". Implemented with the Web Animations
// API so it never permanently touches the input's own styles; feature-guarded because Element.animate is
// absent in the happy-dom test environment, and skipped under prefers-reduced-motion.
//
// The handoff's companion mvType (per-character value reveal) is intentionally NOT implemented: a native
// <input>'s value is a single atomic text string, so its characters cannot be animated in one by one.

const activeHighlights = new WeakMap<HTMLElement, Animation>();
const activeChecks = new WeakMap<HTMLElement, () => void>();

/** Flash a fill highlight over a just-filled input. `delayMs` staggers sequential fields (the handoff
 *  fills the username first, then the password ~0.13s later). No-op where animation isn't available. */
export function flashFill(input: HTMLElement, delayMs = 0): void {
  activeHighlights.get(input)?.cancel?.();
  activeHighlights.delete(input);
  if (typeof input.animate !== 'function') return; // e.g. the happy-dom test environment
  try {
    if (globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  } catch {
    /* matchMedia unavailable — proceed */
  }
  const tinted = 'inset 0 0 0 999px rgba(21,94,215,.09), 0 0 0 2px rgba(21,94,215,.26)';
  const clear = 'inset 0 0 0 999px rgba(21,94,215,0), 0 0 0 2px rgba(21,94,215,0)';
  const animation = input.animate(
    [
      { boxShadow: tinted, offset: 0 },
      { boxShadow: tinted, offset: 0.5 },
      { boxShadow: clear, offset: 1 },
    ],
    { duration: 600, delay: delayMs, easing: 'ease-out' },
  );
  if (!animation?.finished) return;
  activeHighlights.set(input, animation);
  const clearAnimation = (): void => {
    if (activeHighlights.get(input) === animation) activeHighlights.delete(input);
  };
  void animation.finished.then(clearAnimation, clearAnimation);
}

/** mvPop: a small primary-color check badge that pops in at the just-filled
 *  input's top-right corner as post-fill confirmation, then fades and tears itself down. Overlay-only
 *  (position:fixed, pointer-events:none), feature-guarded and reduced-motion-aware like flashFill. */
export function flashFillCheck(input: HTMLElement): void {
  activeChecks.get(input)?.();
  if (typeof input.animate !== 'function' || typeof input.getBoundingClientRect !== 'function') return;
  try {
    if (globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  } catch {
    /* matchMedia unavailable — proceed */
  }
  const rect = input.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const badge = document.createElement('div');
  badge.setAttribute('aria-hidden', 'true');
  badge.style.cssText =
    'position:fixed; z-index:2147483647; width:22px; height:22px; border-radius:6px; background:#155ed7;'
    + ' color:#fff; display:grid; place-items:center; pointer-events:none; box-shadow:0 2px 6px rgba(24,56,87,.12);'
    + ' font:700 13px/1 system-ui,-apple-system,sans-serif;';
  badge.textContent = '✓';
  badge.style.left = `${Math.round(rect.right - 24)}px`;
  badge.style.top = `${Math.round(rect.top + 2)}px`;
  (document.body ?? document.documentElement).appendChild(badge);
  const entrance = badge.animate(
    [
      { transform: 'scale(.9)', opacity: 0, offset: 0 },
      { transform: 'scale(1)', opacity: 1, offset: 1 },
    ],
    { duration: 160, easing: 'ease-out' },
  );
  if (!entrance?.finished) { badge.remove(); return; }
  const cleanup = (): void => {
    if (retireTimer !== undefined) window.clearTimeout(retireTimer);
    entrance.cancel?.();
    badge.remove();
    if (activeChecks.get(input) === cleanup) activeChecks.delete(input);
  };
  void entrance.finished.catch(() => undefined);
  activeChecks.set(input, cleanup);
  const retireTimer = window.setTimeout(() => {
    if (!input.isConnected) { cleanup(); return; }
    const fadeOut = badge.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 200, easing: 'ease-out' });
    void fadeOut.finished.then(cleanup, cleanup);
  }, 1500);
}
