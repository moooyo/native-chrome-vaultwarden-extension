// Factory for the 密屿/MiYu 2FA fill panel (design 3a). Owns the positioned closed-shadow host and
// the small imperative handle the autofill controller drives (update the live code / mark filled /
// show a status / remove). The page can neither read the element's state nor forge its callbacks —
// the closed root and `Event.isTrusted` gating live in the element.

import { mountClosedSurface } from './ui/closed-surface.js';
import { VwTotpPanel } from './ui/totp-panel-element.js';
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
  const surface = mountClosedSurface<VwTotpPanel>('vw-totp-panel', (element) => {
    element.view = 'panel';
    element.onFill = options.onFill;
    element.onCopy = options.onCopy;
    element.onUndo = options.onUndo;
  });
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  const place = (): void => reposition(host, options.anchor);
  void surface.element.updateComplete.then(place);

  return {
    element: host,
    root: surface.root,
    update(data) {
      surface.element.itemName = data.itemName;
      surface.element.itemUser = data.itemUser;
      surface.element.code = data.code;
      surface.element.remaining = data.remaining;
      void surface.element.updateComplete.then(place);
    },
    showFilled() {
      surface.element.view = 'filled';
      void surface.element.updateComplete.then(place);
    },
    showStatus(message) {
      surface.element.statusMessage = message;
      surface.element.view = 'status';
      void surface.element.updateComplete.then(place);
    },
    remove() {
      surface.remove();
    },
  };
}
