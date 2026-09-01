// Factory for the 密屿/MiYu 2FA fill panel (design 3a). Owns the positioned closed-shadow host and
// the small imperative handle the autofill controller drives (update the live code / mark filled /
// show a status / remove). The page can neither read the surface's state nor forge its callbacks —
// the closed root and `Event.isTrusted` gating live in the element view module.

import { mountRenderSurface } from './ui/render-surface.js';
import {
  TOTP_PANEL_STYLES,
  renderTotpPanel,
  type TotpPanelHandlers,
  type TotpPanelCandidate,
  type TotpPanelState,
} from './ui/totp-panel-element.js';
import { repositionSidePanel } from './ui/side-panel.js';

export interface TotpPanel {
  element: HTMLElement;
  root: ShadowRoot;
  /** Refresh the item + live one-time code + remaining seconds. */
  update(data: { itemName: string; itemUser: string; code: string; remaining: number }): void;
  showCandidates(data: {
    candidates: readonly TotpPanelCandidate[];
    overflowCount: number;
    loadingKey?: string;
    statusMessage?: string;
  }): void;
  showFilled(): void;
  showStatus(message: string): void;
  remove(): void;
}

export interface TotpPanelOptions {
  anchor: HTMLElement;
  onSelect(candidateKey: string): void;
  onChooseOther(): void;
  onFill(): void;
  onCopy(): void;
  onUndo(): void;
}

export function createTotpPanel(options: TotpPanelOptions): TotpPanel {
  const state: TotpPanelState = {
    view: 'candidates',
    candidates: [],
    overflowCount: 0,
    loadingKey: '',
    itemName: '',
    itemUser: '',
    code: '',
    remaining: 30,
    statusMessage: '',
  };
  const handlers: TotpPanelHandlers = {
    onSelect: options.onSelect,
    onChooseOther: options.onChooseOther,
    onFill: options.onFill,
    onCopy: options.onCopy,
    onUndo: options.onUndo,
  };
  const surface = mountRenderSurface(TOTP_PANEL_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place as a side panel to the right of the code field. `render()` is synchronous, so
  // the surface's size is final by the time we measure it — the panel tracks the field as the code ticks.
  const draw = (): void => {
    surface.render(renderTotpPanel(state, handlers));
    repositionSidePanel(host, options.anchor);
  };
  draw();

  return {
    element: host,
    root: surface.root,
    showCandidates(data) {
      state.view = 'candidates';
      state.candidates = [...data.candidates];
      state.overflowCount = data.overflowCount;
      state.loadingKey = data.loadingKey ?? '';
      state.statusMessage = data.statusMessage ?? '';
      state.code = '';
      draw();
    },
    update(data) {
      state.view = 'panel';
      state.itemName = data.itemName;
      state.itemUser = data.itemUser;
      state.code = data.code;
      state.remaining = data.remaining;
      draw();
    },
    showFilled() {
      state.view = 'filled';
      draw();
    },
    showStatus(message) {
      state.statusMessage = message;
      state.view = 'status';
      draw();
    },
    remove() {
      surface.remove();
    },
  };
}
