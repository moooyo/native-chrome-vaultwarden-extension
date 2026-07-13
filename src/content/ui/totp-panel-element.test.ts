// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';
import {
  TOTP_PANEL_STYLES,
  renderTotpPanel,
  type TotpPanelHandlers,
  type TotpPanelState,
} from './totp-panel-element.js';

// The 2FA panel is a render-based surface (no custom element — content scripts run in an isolated world
// with no custom-element registry, Chromium 41118431). Tests render its template into a container and
// assert on the produced DOM, exactly as the factory renders it into a closed shadow root.

let container: HTMLElement | undefined;

afterEach(() => {
  container?.remove();
  container = undefined;
});

function mount(over: Partial<TotpPanelState> = {}, handlers: TotpPanelHandlers = {}): HTMLElement {
  container = document.createElement('div');
  document.body.append(container);
  const state: TotpPanelState = {
    view: 'panel',
    itemName: 'Forge',
    itemUser: 'zhihang-z',
    code: '123456',
    remaining: 15,
    statusMessage: '',
    ...over,
  };
  render(renderTotpPanel(state, handlers), container);
  return container;
}

function trustedClick(el: Element): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el.dispatchEvent(event);
}

describe('totp panel surface', () => {
  it('renders the item, grouped code, seconds, and a draining ring', () => {
    const root = mount();
    expect(root.textContent).toContain('Forge');
    expect(root.querySelector('.code')!.textContent!.replace(/\s/g, '')).toBe('123456');
    expect(root.querySelectorAll('.code .grp').length).toBe(2);
    expect(root.querySelector('.secs')!.textContent).toContain('15s');
    // Circular countdown: at 15/30s remaining the arc is half-drained (dashoffset ≈ half the circumference).
    const arc = root.querySelector('.cd-arc') as SVGCircleElement;
    const circ = Number(arc.getAttribute('stroke-dasharray'));
    const offset = Number(arc.getAttribute('stroke-dashoffset'));
    expect(circ).toBeGreaterThan(0);
    expect(offset).toBeCloseTo(circ / 2, 1);
  });

  it('fills only on a trusted click', () => {
    const onFill = vi.fn();
    const root = mount({}, { onFill });
    const btn = root.querySelector('.btn-primary')!;
    btn.dispatchEvent(new MouseEvent('click', { bubbles: true })); // untrusted
    expect(onFill).not.toHaveBeenCalled();
    trustedClick(btn);
    expect(onFill).toHaveBeenCalledTimes(1);
  });

  it('copies the code on a trusted click', () => {
    const onCopy = vi.fn();
    const root = mount({}, { onCopy });
    trustedClick(root.querySelector('.icon-btn')!);
    expect(onCopy).toHaveBeenCalledTimes(1);
  });

  it('shows the filled badge + undo in the filled view', () => {
    const onUndo = vi.fn();
    const root = mount({ view: 'filled' }, { onUndo });
    expect(root.querySelector('.badge')!.textContent).toContain('已填充验证码');
    trustedClick(root.querySelector('.undo')!);
    expect(onUndo).toHaveBeenCalledTimes(1);
  });

  it('shows a status message in the status view', () => {
    const root = mount({ view: 'status', statusMessage: '无匹配' });
    expect(root.querySelector('.status-msg')!.textContent).toContain('无匹配');
  });

  it('declares dark and reduced-motion tokens', () => {
    expect(TOTP_PANEL_STYLES).toContain('prefers-color-scheme: dark');
    expect(TOTP_PANEL_STYLES).toContain('prefers-reduced-motion: reduce');
  });
});
