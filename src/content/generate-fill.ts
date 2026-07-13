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
import { repositionSidePanel } from './ui/side-panel.js';

export interface GeneratePanelState {
  username: string;
  password: string;
  strength: string;
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  minNumbers: number;
  minSymbols: number;
  avoidAmbiguous: boolean;
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
  onUsername(value: string): void;
  onRegenerate(): void;
  onLength(length: number): void;
  onUppercase(on: boolean): void;
  onLowercase(on: boolean): void;
  onNumbers(on: boolean): void;
  onSymbols(on: boolean): void;
  onMinNumbers(n: number): void;
  onMinSymbols(n: number): void;
  onAvoidAmbiguous(on: boolean): void;
  onUse(): void;
  onUndo(): void;
}

export function createGeneratePanel(options: GeneratePanelOptions): GeneratePanel {
  const state: GeneratePanelViewState = {
    view: 'panel',
    username: '',
    password: '',
    strength: '极强',
    length: 18,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    minNumbers: 1,
    minSymbols: 0,
    avoidAmbiguous: true,
    savedName: '',
    savedUser: '',
  };
  const handlers: GeneratePanelHandlers = {
    onUsername: options.onUsername,
    onRegenerate: options.onRegenerate,
    onLength: options.onLength,
    onUppercase: options.onUppercase,
    onLowercase: options.onLowercase,
    onNumbers: options.onNumbers,
    onSymbols: options.onSymbols,
    onMinNumbers: options.onMinNumbers,
    onMinSymbols: options.onMinSymbols,
    onAvoidAmbiguous: options.onAvoidAmbiguous,
    onUse: options.onUse,
    onUndo: options.onUndo,
  };
  const surface = mountRenderSurface(GENERATE_PANEL_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place as a side panel to the right of the new-password field. `render()` is
  // synchronous, so the surface's size is final by the time we measure it (panel → saved).
  const draw = (): void => {
    surface.render(renderGeneratePanel(state, handlers));
    repositionSidePanel(host, options.anchor);
  };
  draw();

  return {
    element: host,
    root: surface.root,
    update(next) {
      state.username = next.username;
      state.password = next.password;
      state.strength = next.strength;
      state.length = next.length;
      state.uppercase = next.uppercase;
      state.lowercase = next.lowercase;
      state.numbers = next.numbers;
      state.symbols = next.symbols;
      state.minNumbers = next.minNumbers;
      state.minSymbols = next.minSymbols;
      state.avoidAmbiguous = next.avoidAmbiguous;
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
