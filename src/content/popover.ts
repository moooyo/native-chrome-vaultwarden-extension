// The autofill hover popover: a Vaultwarden shield anchored to a detected login/card/identity form.
// The visible surface is the closed-shadow Lit element `vw-autofill-popover`; this factory owns only
// the positioned host, the anchor-relative placement, and the small imperative handle the autofill
// controller drives (open / show status / show candidates / remove). The page can neither read the
// element's state nor forge its callbacks (closed root + Event.isTrusted gating live in the element).

import { mountClosedSurface } from './ui/closed-surface.js';
import { VwAutofillPopover, type PopoverCandidate, type PopoverKind } from './ui/autofill-popover-element.js';

export type { PopoverCandidate } from './ui/autofill-popover-element.js';

export interface AutofillPopover {
  /** The positioned host element in the page tree (its shadow root is closed — `.shadowRoot` is null). */
  element: HTMLElement;
  /** The closed shadow root the element is mounted in (not reachable via `element.shadowRoot`). */
  root: ShadowRoot;
  /** Programmatically open the panel (runs the same onOpen path as a trusted shield click). */
  open(): void;
  showStatus(message: string): void;
  showCandidates(candidates: PopoverCandidate[]): void;
  remove(): void;
}

export interface AutofillPopoverOptions {
  anchor: HTMLElement;
  kind?: PopoverKind;
  onOpen(): void;
  onSelect(cipherId: string): void;
}

export function createAutofillPopover(options: AutofillPopoverOptions): AutofillPopover {
  const kind = options.kind ?? 'login';
  const surface = mountClosedSurface<VwAutofillPopover>('vw-autofill-popover', (element) => {
    element.kind = kind;
    element.view = 'trigger';
    element.onOpen = options.onOpen;
    element.onSelect = options.onSelect;
  });
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Re-place after each render so the panel tracks the anchor as its size changes (trigger →
  // status/list). `updateComplete` resolves once the element's next render has flushed.
  const place = (): void => reposition(host, options.anchor);
  void surface.element.updateComplete.then(place);

  return {
    element: host,
    root: surface.root,
    open() {
      options.onOpen();
    },
    showStatus(message: string) {
      surface.element.statusMessage = message;
      surface.element.view = 'status';
      void surface.element.updateComplete.then(place);
    },
    showCandidates(candidates: PopoverCandidate[]) {
      surface.element.candidates = candidates;
      surface.element.view = 'list';
      void surface.element.updateComplete.then(place);
    },
    remove() {
      surface.remove();
    },
  };
}

/** Position the popover under the anchor, flipping above and clamping to the
 *  viewport when there isn't room — so it stays usable at any zoom or window size. */
function reposition(host: HTMLElement, anchor: HTMLElement): void {
  const rect = anchor.getBoundingClientRect();
  const vw = window.innerWidth || document.documentElement.clientWidth || 0;
  const vh = window.innerHeight || document.documentElement.clientHeight || 0;
  const width = host.offsetWidth || 240;
  const height = host.offsetHeight || 0;
  const gap = 4;

  let left = rect.left;
  if (vw) left = Math.min(Math.max(8, left), Math.max(8, vw - width - 8));

  const spaceBelow = vh ? vh - rect.bottom : Infinity;
  const placeAbove = height > 0 && spaceBelow < height + gap && rect.top > height + gap;
  const top = placeAbove ? rect.top - height - gap : rect.bottom + gap;

  host.style.left = `${left + window.scrollX}px`;
  host.style.top = `${Math.max(8, top) + window.scrollY}px`;
}
