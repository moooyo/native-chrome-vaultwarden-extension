// Factory for the 密屿/MiYu inline password-generation panel (design 2e). Owns the positioned
// closed-shadow host and the imperative handle the autofill controller drives (push generated
// state / mark filled / remove). Closed root + `Event.isTrusted` gating live in the render module.

import { mountRenderSurface } from './ui/render-surface.js';
import {
  GENERATE_PANEL_STYLES,
  renderGeneratePanel,
  type GeneratePanelHandlers,
  type GeneratePanelViewState,
} from './ui/generate-panel-element.js';
import { repositionSidePanel } from './ui/side-panel.js';

export interface GeneratePanelState {
  mode: 'password' | 'passphrase';
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
  words: number;
  capitalize: boolean;
  includeNumber: boolean;
  managed: boolean;
  disabledReason: string;
}

export interface GeneratePanel {
  element: HTMLElement;
  root: ShadowRoot;
  update(state: GeneratePanelState): void;
  showFilled(info: { user: string }): void;
  remove(): void;
}

export interface GeneratePanelOptions {
  anchor: HTMLElement;
  onMode?(mode: 'password' | 'passphrase'): void;
  onDismiss?(): void;
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
  onWords(words: number): void;
  onCapitalize(on: boolean): void;
  onIncludeNumber(on: boolean): void;
  onUse(): void;
}

export function createGeneratePanel(options: GeneratePanelOptions): GeneratePanel {
  const state: GeneratePanelViewState = {
    view: 'panel',
    mode: 'password',
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
    words: 6,
    capitalize: false,
    includeNumber: false,
    managed: false,
    disabledReason: '',
    filledUser: '',
    siteLabel: window.location.hostname,
  };
  const handlers: GeneratePanelHandlers = {
    ...(options.onMode ? { onMode: options.onMode } : {}),
    onDismiss: () => {
      options.onDismiss?.();
      surface.remove();
    },
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
    onWords: options.onWords,
    onCapitalize: options.onCapitalize,
    onIncludeNumber: options.onIncludeNumber,
    onUse: options.onUse,
  };
  const surface = mountRenderSurface(GENERATE_PANEL_STYLES);
  const host = surface.host;
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';

  // Render, then re-place as a side panel to the right of the new-password field. `render()` is
  // synchronous, so the surface's size is final by the time we measure it (panel -> filled).
  const draw = (): void => {
    surface.render(renderGeneratePanel(state, handlers));
    repositionSidePanel(host, options.anchor);
  };
  surface.root.addEventListener('toggle', () => repositionSidePanel(host, options.anchor), true);
  draw();

  return {
    element: host,
    root: surface.root,
    update(next) {
      state.mode = next.mode;
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
      state.words = next.words;
      state.capitalize = next.capitalize;
      state.includeNumber = next.includeNumber;
      state.managed = next.managed;
      state.disabledReason = next.disabledReason;
      state.view = 'panel';
      draw();
    },
    showFilled(info) {
      state.filledUser = info.user;
      state.view = 'filled';
      draw();
    },
    remove() {
      surface.remove();
    },
  };
}
