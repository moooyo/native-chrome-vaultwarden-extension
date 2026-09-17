// The autofill hover popover: a 密屿 (MiYu) mini-logo anchored to a detected login/card/identity form.
// The visible surface is the closed-shadow Lit element `vw-autofill-popover`; this factory owns only
// the positioned host, the anchor-relative placement, and the small imperative handle the autofill
// controller drives (open / show status / show candidates / remove). The page can neither read the
// element's state nor forge its callbacks (closed root + Event.isTrusted gating live in the element).

import { mountRenderSurface } from './ui/render-surface.js';
import { repositionSidePanel } from './ui/side-panel.js';
import {
  POPOVER_STYLES,
  renderPopover,
  type PopoverCandidate,
  type PopoverDismissReason,
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
  /** Programmatically open the panel (runs the same onOpen path as a trusted shield click). Pass an
   *  anchor to re-position the panel next to a specific field (card/identity open beside the focused
   *  field); omit it to keep the current anchor (login stays on its form anchor). */
  open(anchor?: HTMLElement, options?: { focusList?: boolean }): void;
  showStatus(message: string): void;
  showCandidates(candidates: PopoverCandidate[]): void;
  /** Show the post-fill 已填充 confirmation (login side panel, design 2c). */
  showFilled(): (() => boolean) | void;
  /** Collapse the side panel back to nothing (dismiss-on-click-away); reopens on the next focus. */
  hide(): void;
  remove(): void;
}

export interface AutofillPopoverOptions {
  anchor: HTMLElement;
  kind?: PopoverKind;
  /** Login autofill (2c) mounts as a right-side panel with a connector and shows matches directly; card
   *  / identity keep the compact below-field trigger popover. */
  sidePanel?: boolean;
  /** Matches to show immediately (side-panel login opens straight into the list). */
  candidates?: PopoverCandidate[];
  onOpen(): void;
  onSelect(cipherId: string): void;
  /** Optional one-shot cancellation hook for keyboard-owned pickers. */
  onDismiss?(reason: PopoverDismissReason): void;
  /** Register controller state before restoring page focus; return cleanup for a no-op focus. */
  beforeFocusRestore?(anchor: HTMLElement): () => void;
}

export function createAutofillPopover(options: AutofillPopoverOptions): AutofillPopover {
  const kind = options.kind ?? 'login';
  const sidePanel = options.sidePanel ?? false;
  const state: PopoverState = {
    kind,
    view: sidePanel ? 'hidden' : 'trigger',
    statusMessage: '',
    candidates: options.candidates ?? [],
    activeIndex: -1,
    sidePanel,
    siteLabel: window.location.hostname,
  };
  const surface = mountRenderSurface(POPOVER_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place. `render()` is synchronous, so the surface's size is final by the time we
  // measure it. The login side panel hangs to the right with a connector; card/identity drop below.
  // `anchor` is mutable so open(el) can re-mount the panel beside a freshly focused field.
  let anchor = options.anchor;
  let requestedListFocus = false;
  let requestedListFocusOwner: Element | null = null;
  let suppressedOpenAnchor: HTMLElement | null = null;
  let tabDismissTimer: number | undefined;
  let viewRevision = 0;
  const place = sidePanel ? repositionSidePanel : reposition;
  const focusList = (): void => {
    const list = surface.root.querySelector<HTMLElement>('[role="listbox"]');
    if (!list) return;
    list.focus({ preventScroll: true });
    const option = surface.root.getElementById(`vw-autofill-option-${state.activeIndex}`);
    const scroll = (option as HTMLElement | null)?.scrollIntoView;
    if (typeof scroll === 'function') scroll.call(option, { block: 'nearest' });
  };
  const draw = (preserveSurfaceFocus = false): void => {
    const hadSurfaceFocus = preserveSurfaceFocus && surface.root.activeElement !== null;
    surface.render(renderPopover(state, handlers));
    place(host, anchor);
    if (state.view === 'list' && state.candidates.length > 0 && hadSurfaceFocus) focusList();
  };
  const focusAnchor = (): void => {
    if (!anchor.isConnected || document.activeElement === anchor) return;
    const clearControllerSuppression = options.beforeFocusRestore?.(anchor);
    if (!clearControllerSuppression) suppressedOpenAnchor = anchor;
    try {
      anchor.focus({ preventScroll: true });
    } finally {
      clearControllerSuppression?.();
    }
    if (document.activeElement !== anchor) suppressedOpenAnchor = null;
  };
  const clearTabDismiss = (): void => {
    if (tabDismissTimer === undefined) return;
    window.clearTimeout(tabDismissTimer);
    tabDismissTimer = undefined;
  };
  const dismiss = (reason: PopoverDismissReason): void => {
    viewRevision += 1;
    clearTabDismiss();
    state.view = 'hidden';
    state.activeIndex = -1;
    draw();
    if (reason === 'escape') focusAnchor();
    options.onDismiss?.(reason);
  };
  const handlers: PopoverHandlers = {
    onOpen: options.onOpen,
    onSelect: options.onSelect,
    onActiveIndexChange(index) {
      if (state.view !== 'list' || index < 0 || index >= state.candidates.length) return;
      state.activeIndex = index;
      draw(true);
    },
    onKeyboardSelect(index) {
      if (state.view !== 'list') return;
      const candidate = state.candidates[index];
      if (!candidate) return;
      focusAnchor();
      options.onSelect(candidate.id);
    },
    onDismiss(reason) {
      if (reason === 'tab') {
        clearTabDismiss();
        tabDismissTimer = window.setTimeout(() => {
          tabDismissTimer = undefined;
          if (state.view === 'list') dismiss('tab');
        }, 0);
        return;
      }
      dismiss(reason);
    },
  };
  draw();

  return {
    element: host,
    root: surface.root,
    open(nextAnchor?: HTMLElement, openOptions?: { focusList?: boolean }) {
      viewRevision += 1;
      const openingAnchor = nextAnchor ?? anchor;
      if (suppressedOpenAnchor === openingAnchor) {
        suppressedOpenAnchor = null;
        return;
      }
      if (nextAnchor) anchor = nextAnchor;
      clearTabDismiss();
      requestedListFocus = openOptions?.focusList === true;
      requestedListFocusOwner = requestedListFocus ? document.activeElement : null;
      options.onOpen();
    },
    showStatus(message: string) {
      viewRevision += 1;
      requestedListFocus = false;
      requestedListFocusOwner = null;
      state.statusMessage = message;
      state.view = 'status';
      state.activeIndex = -1;
      draw();
    },
    showCandidates(candidates: PopoverCandidate[]) {
      viewRevision += 1;
      const hadSurfaceFocus = surface.root.activeElement !== null;
      const honorRequestedFocus = requestedListFocus && document.activeElement === requestedListFocusOwner;
      requestedListFocus = false;
      requestedListFocusOwner = null;
      state.candidates = candidates;
      state.view = 'list';
      state.activeIndex = candidates.length > 0 ? 0 : -1;
      draw();
      if (candidates.length > 0 && (hadSurfaceFocus || honorRequestedFocus)) focusList();
    },
    showFilled() {
      const receiptRevision = ++viewRevision;
      requestedListFocus = false;
      requestedListFocusOwner = null;
      state.view = 'filled';
      state.activeIndex = -1;
      draw();
      return () => state.view === 'filled' && receiptRevision === viewRevision;
    },
    hide() {
      viewRevision += 1;
      clearTabDismiss();
      requestedListFocus = false;
      requestedListFocusOwner = null;
      state.view = 'hidden';
      state.activeIndex = -1;
      draw();
    },
    remove() {
      viewRevision += 1;
      clearTabDismiss();
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
