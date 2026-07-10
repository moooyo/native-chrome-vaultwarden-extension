// A top-of-page bar offering to save a newly entered login or update a changed password. The visible
// surface is the closed-shadow Lit element `vw-save-bar`; this factory only mounts it and removes it
// after the user's choice. Mirrors the popover's isolation: the page can neither read nor forge it,
// only trusted clicks act, and nothing is saved until the user explicitly confirms.

import { mountClosedSurface } from './ui/closed-surface.js';
import { VwSaveBar } from './ui/save-bar-element.js';

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
  const surface = mountClosedSurface<VwSaveBar>('vw-save-bar', (element) => {
    element.message = options.message;
    element.actionLabel = options.actionLabel;
  });
  surface.element.onAction = () => {
    options.onAction();
    surface.remove();
  };
  surface.element.onDismiss = () => {
    options.onDismiss?.();
    surface.remove();
  };
  return { remove: () => surface.remove() };
}
