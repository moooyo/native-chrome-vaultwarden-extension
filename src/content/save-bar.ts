// A top-of-page bar offering to save a newly entered login or update a changed password. The visible
// surface is a render-based lit-html template in a closed shadow root (no custom element — content
// scripts run in an isolated world with no custom-element registry, Chromium 41118431). This factory
// owns the state/handlers and removes the bar after the user's choice. Mirrors the popover's isolation:
// the page can neither read nor forge it, only trusted clicks act, and nothing is saved until the user
// explicitly confirms.

import { mountRenderSurface } from './ui/render-surface.js';
import {
  SAVE_BAR_STYLES,
  renderSaveBar,
  type SaveBarHandlers,
  type SaveBarState,
} from './ui/save-bar-element.js';

export interface SaveBar {
  remove(): void;
}

export interface SaveBarOptions {
  /** Plain-text message (no HTML); bound with `${}` so site data can't inject markup. */
  message: string;
  actionLabel: string;
  onAction(): void;
  onDismiss?(): void;
}

export function createSaveBar(options: SaveBarOptions): SaveBar {
  const state: SaveBarState = { message: options.message, actionLabel: options.actionLabel };
  const surface = mountRenderSurface(SAVE_BAR_STYLES);
  const handlers: SaveBarHandlers = {
    onAction: () => {
      options.onAction();
      surface.remove();
    },
    onDismiss: () => {
      options.onDismiss?.();
      surface.remove();
    },
  };

  // The bar positions itself via fixed CSS (top-center), so there is nothing to measure or reposition;
  // rendering is synchronous, so the DOM is final on return.
  const draw = (): void => {
    surface.render(renderSaveBar(state, handlers));
  };
  draw();

  return { remove: () => surface.remove() };
}
