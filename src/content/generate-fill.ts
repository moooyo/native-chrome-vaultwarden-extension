// Factory for the 密屿/MiYu inline password-generation panel (design 2e). Owns the positioned
// closed-shadow host and the imperative handle the autofill controller drives (push generated
// state / mark saved / remove). Closed root + `Event.isTrusted` gating live in the element.

import { mountClosedSurface } from './ui/closed-surface.js';
import { VwGeneratePanel } from './ui/generate-panel-element.js';
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
  const surface = mountClosedSurface<VwGeneratePanel>('vw-generate-panel', (element) => {
    element.view = 'panel';
    element.onRegenerate = options.onRegenerate;
    element.onLength = options.onLength;
    element.onNumbers = options.onNumbers;
    element.onSymbols = options.onSymbols;
    element.onUse = options.onUse;
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
    update(state) {
      surface.element.password = state.password;
      surface.element.strength = state.strength;
      surface.element.length = state.length;
      surface.element.numbers = state.numbers;
      surface.element.symbols = state.symbols;
      void surface.element.updateComplete.then(place);
    },
    showSaved(info) {
      surface.element.savedName = info.name;
      surface.element.savedUser = info.user;
      surface.element.view = 'saved';
      void surface.element.updateComplete.then(place);
    },
    remove() {
      surface.remove();
    },
  };
}
