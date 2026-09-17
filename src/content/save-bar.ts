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
  onAction(): Promise<boolean>;
  onDismiss?(): void;
  successMessage?: string;
  uncertainMessage?: string;
}

export function createSaveBar(options: SaveBarOptions): SaveBar {
  const state: SaveBarState = {
    view: 'prompt',
    message: options.message,
    actionLabel: options.actionLabel,
    statusMessage: '',
  };
  const surface = mountRenderSurface(SAVE_BAR_STYLES);
  let removed = false;
  let removeTimer: number | undefined;

  const remove = (): void => {
    if (removed) return;
    removed = true;
    if (removeTimer !== undefined) window.clearTimeout(removeTimer);
    surface.remove();
  };

  const handlers: SaveBarHandlers = {
    onAction: () => {
      void commit();
    },
    onDismiss: () => {
      options.onDismiss?.();
      remove();
    },
  };

  // The bar positions itself via fixed CSS (top-right), so there is nothing to measure or reposition;
  // rendering is synchronous, so the DOM is final on return.
  const draw = (): void => {
    surface.render(renderSaveBar(state, handlers));
  };
  draw();

  async function commit(): Promise<void> {
    if (state.view !== 'prompt') return;
    state.view = 'saving';
    state.statusMessage = '正在保存到密屿…';
    draw();
    let confirmed = false;
    try {
      confirmed = await options.onAction();
    } catch {
      // An unknown transport outcome must not be retried because the vault write may have succeeded.
    }
    if (removed) return;
    if (!confirmed) {
      state.view = 'uncertain';
      state.statusMessage = options.uncertainMessage ?? '无法确认保存结果。请在密屿中检查。';
      draw();
      return;
    }
    state.view = 'saved';
    state.statusMessage = options.successMessage ?? '已保存到密屿';
    draw();
    removeTimer = window.setTimeout(remove, 3000);
  }

  return { remove };
}
