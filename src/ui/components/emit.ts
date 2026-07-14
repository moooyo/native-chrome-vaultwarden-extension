// Shared event-dispatch helper for MiYu's Lit views. Every view-to-host event crosses the shadow-DOM
// boundary, so it must be both `bubbles` (climb the ancestor chain) and `composed` (escape the shadow
// root). Centralizing that invariant here keeps ~50 call sites from re-declaring it (and getting it
// subtly wrong). `detail` is omitted when undefined so listeners observe the native `null` default.

/** Dispatch a bubbling, shadow-crossing CustomEvent from `el`. */
export function emit<T>(el: EventTarget, type: string, detail?: T): void {
  const init: CustomEventInit<T> = { bubbles: true, composed: true };
  if (detail !== undefined) init.detail = detail;
  el.dispatchEvent(new CustomEvent<T>(type, init));
}
