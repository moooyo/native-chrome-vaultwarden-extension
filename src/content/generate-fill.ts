// Factory for the 密屿/MiYu inline password-generation panel (design 2e). Owns the positioned
// closed-shadow host and the imperative handle the autofill controller drives (push generated
// state / mark saved / remove). Closed root + `Event.isTrusted` gating live in the render module.

import { mountRenderSurface } from './ui/render-surface.js';
import {
  GENERATE_PANEL_STYLES,
  renderGeneratePanel,
  type GeneratePanelHandlers,
  type GeneratePanelViewState,
} from './ui/generate-panel-element.js';
import { reposition } from './popover.js';

export interface GeneratePanelState {
  password: string;
  strength: string;
  length: number;
  numbers: boolean;
  symbols: boolean;
}

export interface GeneratePanel {
  element: HTMLElement;
  root: ShadowRoot;
  update(state: GeneratePanelState): void;
  showSaved(info: { name: string; user: string }): void;
  remove(): void;
}

export interface GeneratePanelOptions {
  anchor: HTMLElement;
  onRegenerate(): void;
  onLength(length: number): void;
  onNumbers(on: boolean): void;
  onSymbols(on: boolean): void;
  onUse(): void;
  onUndo(): void;
}

export function createGeneratePanel(options: GeneratePanelOptions): GeneratePanel {
  const state: GeneratePanelViewState = {
    view: 'panel',
    password: '',
    strength: '极强',
    length: 18,
    numbers: true,
    symbols: true,
    savedName: '',
    savedUser: '',
  };
  const handlers: GeneratePanelHandlers = {
    onRegenerate: options.onRegenerate,
    onLength: options.onLength,
    onNumbers: options.onNumbers,
    onSymbols: options.onSymbols,
    onUse: options.onUse,
    onUndo: options.onUndo,
  };
  const surface = mountRenderSurface(GENERATE_PANEL_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place under the anchor. `render()` is synchronous, so the surface's size is final
  // by the time we measure it — the panel tracks the anchor as its content changes (panel → saved).
  const draw = (): void => {
    surface.render(renderGeneratePanel(state, handlers));
    reposition(host, options.anchor);
  };
  draw();

  return {
    element: host,
    root: surface.root,
    update(next) {
      state.password = next.password;
      state.strength = next.strength;
      state.length = next.length;
      state.numbers = next.numbers;
      state.symbols = next.symbols;
      draw();
    },
    showSaved(info) {
      state.savedName = info.name;
      state.savedUser = info.user;
      state.view = 'saved';
      draw();
    },
    remove() {
      surface.remove();
    },
  };
}
