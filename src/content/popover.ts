// The autofill hover popover: a 密屿 (MiYu) mini-logo anchored to a detected login/card/identity form.
// The visible surface is the closed-shadow Lit element `vw-autofill-popover`; this factory owns only
// the positioned host, the anchor-relative placement, and the small imperative handle the autofill
// controller drives (open / show status / show candidates / remove). The page can neither read the
// element's state nor forge its callbacks (closed root + Event.isTrusted gating live in the element).

import { mountRenderSurface } from './ui/render-surface.js';
import {
  POPOVER_STYLES,
  renderPopover,
  type PopoverCandidate,
  type PopoverHandlers,
  type PopoverKind,
  type PopoverState,
} from './ui/autofill-popover-element.js';

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
  const state: PopoverState = { kind, view: 'trigger', statusMessage: '', candidates: [] };
  const handlers: PopoverHandlers = { onOpen: options.onOpen, onSelect: options.onSelect };
  const surface = mountRenderSurface(POPOVER_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place under the anchor. `render()` is synchronous, so the surface's size is final
  // by the time we measure it — the panel tracks the anchor as its content grows (trigger → status/list).
  const draw = (): void => {
    surface.render(renderPopover(state, handlers));
    reposition(host, options.anchor);
  };
  draw();

  return {
    element: host,
    root: surface.root,
    open() {
      options.onOpen();
    },
    showStatus(message: string) {
      state.statusMessage = message;
      state.view = 'status';
      draw();
    },
    showCandidates(candidates: PopoverCandidate[]) {
      state.candidates = candidates;
      state.view = 'list';
      draw();
    },
    remove() {
      surface.remove();
    },
  };
}

/** Position a surface under the anchor, flipping above and clamping to the
 *  viewport when there isn't room — so it stays usable at any zoom or window size. Shared by the
 *  login/card/identity popover and the 2FA / generate panels. */
export function reposition(host: HTMLElement, anchor: HTMLElement): void {
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
