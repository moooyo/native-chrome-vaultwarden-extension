// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';
import {
  GENERATE_PANEL_STYLES,
  renderGeneratePanel,
  type GeneratePanelHandlers,
  type GeneratePanelViewState,
} from './generate-panel-element.js';

// The generate panel is a render-based surface (no custom element — content scripts run in an isolated
// world with no custom-element registry, Chromium 41118431). Tests render its template into a container
// and assert on the produced DOM, exactly as the factory renders it into a closed shadow root.

let container: HTMLElement | undefined;

afterEach(() => {
  container?.remove();
  container = undefined;
});

function mount(over: Partial<GeneratePanelViewState> = {}, handlers: GeneratePanelHandlers = {}): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  const state: GeneratePanelViewState = {
    view: 'panel',
    username: '',
    password: 'Ab3$xz9K',
    strength: '极强',
    length: 18,
    numbers: true,
    symbols: true,
    savedName: '',
    savedUser: '',
    ...over,
  };
  render(renderGeneratePanel(state, handlers), container);
  return container;
}

function trustedClick(el: Element): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el.dispatchEvent(event);
}

describe('generate panel surface', () => {
  it('renders the suggestion with digit + symbol coloring and the meta', () => {
    const root = mount();
    expect(root.querySelector('.suggest')!.textContent).toBe('Ab3$xz9K');
    expect(root.querySelectorAll('.suggest .d').length).toBeGreaterThan(0); // digits
    expect(root.querySelectorAll('.suggest .s').length).toBeGreaterThan(0); // symbols
    expect(root.querySelector('.meta')!.textContent).toContain('18 字符');
    expect(root.querySelector('.meta')!.textContent).toContain('含符号');
  });

  it('reflects the rule pills and emits toggles on trusted click', () => {
    const onNumbers = vi.fn();
    const root = mount({}, { onNumbers });
    const pills = root.querySelectorAll('.pill');
    expect(pills[0]!.classList.contains('on')).toBe(true);
    trustedClick(pills[0]!);
    expect(onNumbers).toHaveBeenCalledWith(false);
  });

  it('emits length on slider input and regenerate on trusted refresh', () => {
    const onLength = vi.fn();
    const onRegenerate = vi.fn();
    const root = mount({}, { onLength, onRegenerate });
    const range = root.querySelector('input[type="range"]') as HTMLInputElement;
    range.value = '24';
    const evt = new Event('input', { bubbles: true });
    Object.defineProperty(evt, 'isTrusted', { value: true });
    range.dispatchEvent(evt);
    expect(onLength).toHaveBeenCalledWith(24);
    trustedClick(root.querySelector('.refresh')!);
    expect(onRegenerate).toHaveBeenCalledTimes(1);
  });

  it('uses the password on a trusted click only', () => {
    const onUse = vi.fn();
    const root = mount({}, { onUse });
    root.querySelector('.use')!.dispatchEvent(new MouseEvent('click', { bubbles: true })); // untrusted
    expect(onUse).not.toHaveBeenCalled();
    trustedClick(root.querySelector('.use')!);
    expect(onUse).toHaveBeenCalledTimes(1);
  });

  it('shows the editable username row and emits edits on trusted input', () => {
    const onUsername = vi.fn();
    const root = mount({ username: 'zhang@orbit.mail' }, { onUsername });
    const userInput = root.querySelector('.user input') as HTMLInputElement;
    expect(userInput.value).toBe('zhang@orbit.mail');
    userInput.value = 'new@quill.app';
    const evt = new Event('input', { bubbles: true });
    Object.defineProperty(evt, 'isTrusted', { value: true });
    userInput.dispatchEvent(evt);
    expect(onUsername).toHaveBeenCalledWith('new@quill.app');
  });

  it('shows the saved confirmation in the saved view', () => {
    const root = mount({ view: 'saved', savedName: 'quill.app', savedUser: 'me@x.dev' });
    expect(root.querySelector('.saved .t')!.textContent).toContain('已保存到密屿');
    expect(root.querySelector('.saved .s')!.textContent).toContain('me@x.dev');
  });

  it('declares dark and reduced-motion tokens', () => {
    expect(GENERATE_PANEL_STYLES).toContain('prefers-color-scheme: dark');
    expect(GENERATE_PANEL_STYLES).toContain('prefers-reduced-motion: reduce');
  });
});
