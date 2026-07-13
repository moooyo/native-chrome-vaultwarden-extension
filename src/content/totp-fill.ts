// Factory for the 密屿/MiYu 2FA fill panel (design 3a). Owns the positioned closed-shadow host and
// the small imperative handle the autofill controller drives (update the live code / mark filled /
// show a status / remove). The page can neither read the surface's state nor forge its callbacks —
// the closed root and `Event.isTrusted` gating live in the element view module.

import { mountRenderSurface } from './ui/render-surface.js';
import {
  TOTP_PANEL_STYLES,
  renderTotpPanel,
  type TotpPanelHandlers,
  type TotpPanelState,
} from './ui/totp-panel-element.js';
import { reposition } from './popover.js';

export interface TotpPanel {
  element: HTMLElement;
  root: ShadowRoot;
  /** Refresh the item + live one-time code + remaining seconds. */
  update(data: { itemName: string; itemUser: string; code: string; remaining: number }): void;
  showFilled(): void;
  showStatus(message: string): void;
  remove(): void;
}

export interface TotpPanelOptions {
  anchor: HTMLElement;
  onFill(): void;
  onCopy(): void;
  onUndo(): void;
}

export function createTotpPanel(options: TotpPanelOptions): TotpPanel {
  const state: TotpPanelState = {
    view: 'panel',
    itemName: '',
    itemUser: '',
    code: '',
    remaining: 30,
    statusMessage: '',
  };
  const handlers: TotpPanelHandlers = { onFill: options.onFill, onCopy: options.onCopy, onUndo: options.onUndo };
  const surface = mountRenderSurface(TOTP_PANEL_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place under the anchor. `render()` is synchronous, so the surface's size is final
  // by the time we measure it — the panel tracks the anchor as the code ticks or the view changes.
  const draw = (): void => {
    surface.render(renderTotpPanel(state, handlers));
    reposition(host, options.anchor);
  };
  draw();

  return {
    element: host,
    root: surface.root,
    update(data) {
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
