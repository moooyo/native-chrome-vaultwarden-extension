// mvFill (animations-handoff.md): a moss-green wash that flashes over an input the moment it is
// autofilled, then fades — signalling "this field was just filled". Implemented with the Web Animations
// API so it never permanently touches the input's own styles; feature-guarded because Element.animate is
// absent in the happy-dom test environment, and skipped under prefers-reduced-motion.
//
// The handoff's companion mvType (per-character value reveal) is intentionally NOT implemented: a native
// <input>'s value is a single atomic text string, so its characters cannot be animated in one by one.

/** Flash a fill highlight over a just-filled input. `delayMs` staggers sequential fields (the handoff
 *  fills the username first, then the password ~0.13s later). No-op where animation isn't available. */
export function flashFill(input: HTMLElement, delayMs = 0): void {
  if (typeof input.animate !== 'function') return; // e.g. the happy-dom test environment
  try {
    if (globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  } catch {
    /* matchMedia unavailable — proceed */
  }
  const tinted = 'inset 0 0 0 999px rgba(14,138,114,.20), 0 0 0 2px rgba(14,138,114,.45)';
  const clear = 'inset 0 0 0 999px rgba(14,138,114,0), 0 0 0 2px rgba(14,138,114,0)';
  input.animate(
    [
      { boxShadow: tinted, offset: 0 },
      { boxShadow: tinted, offset: 0.5 },
      { boxShadow: clear, offset: 1 },
    ],
    { duration: 600, delay: delayMs, easing: 'ease-out' },
  );
}
