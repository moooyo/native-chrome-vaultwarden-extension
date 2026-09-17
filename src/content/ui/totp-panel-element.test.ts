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
    candidates: [{ key: 'candidate-0', name: 'Forge', username: 'zhihang-z', reprompt: false }],
    overflowCount: 0,
    loadingKey: '',
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
    expect(root.querySelector('.code')!.getAttribute('aria-label')).toBe('验证码 123456');
    expect(root.querySelectorAll('.code .grp').length).toBe(2);
    expect(root.querySelector('.secs')!.textContent).toContain('15s');
    expect(root.querySelector('.secs')!.getAttribute('aria-label')).toBe('15 秒后更新');
    expect(root.querySelector('.icon-btn')!.getAttribute('aria-label')).toBe('复制验证码');
    expect(root.querySelector('.tile')!.getAttribute('aria-hidden')).toBe('true');
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
    expect(root.querySelector('.filled')!.getAttribute('role')).toBe('status');
    expect(root.querySelector('.filled')!.getAttribute('aria-live')).toBe('polite');
    expect(root.querySelector('.filled')!.getAttribute('aria-atomic')).toBe('true');
    trustedClick(root.querySelector('.undo')!);
    expect(onUndo).toHaveBeenCalledTimes(1);
  });

  it('shows a status message in the status view', () => {
    const root = mount({ view: 'status', statusMessage: '无匹配' });
    expect(root.querySelector('.status-msg')!.textContent).toContain('无匹配');
    expect(root.querySelector('.status')!.getAttribute('role')).toBe('status');
    expect(root.querySelector('.status')!.getAttribute('aria-live')).toBe('polite');
    expect(root.querySelector('.status')!.getAttribute('aria-atomic')).toBe('true');
  });

  it('uses the actual code period for the countdown and disables expired-code actions', () => {
    const root = mount({ period: 60, remaining: 15 });
    const arc = root.querySelector('.cd-arc')!;
    const circumference = Number(arc.getAttribute('stroke-dasharray'));
    expect(Number(arc.getAttribute('stroke-dashoffset'))).toBeCloseTo(circumference * .75, 1);
    const expired = mount({ code: '', remaining: 0 });
    expect(expired.querySelector<HTMLButtonElement>('.btn-primary')!.disabled).toBe(true);
    expect(expired.querySelector<HTMLButtonElement>('.icon-btn')!.disabled).toBe(true);
  });

  it('moves candidate focus on trusted arrow keys and leaves untrusted events inert', () => {
    const root = mount({ view: 'candidates', candidates: [
      { key: 'candidate-0', name: 'Forge', username: 'ada@example.com', reprompt: false },
      { key: 'candidate-1', name: 'Forge', username: 'grace@example.com', reprompt: false },
    ] });
    const rows = root.querySelectorAll<HTMLButtonElement>('.candidate');
    rows[0]!.focus();
    rows[0]!.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    expect(document.activeElement).toBe(rows[0]);
    const event = new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true });
    Object.defineProperty(event, 'isTrusted', { value: true });
    rows[0]!.dispatchEvent(event);
    expect(document.activeElement).toBe(rows[1]);
  });

  it('renders same-name candidates with usernames, overflow, and trusted selection', () => {
    const onSelect = vi.fn();
    const root = mount({
      view: 'candidates',
      code: '',
      candidates: [
        { key: 'candidate-0', name: 'Forge', username: 'ada@example.com', reprompt: false },
        { key: 'candidate-1', name: 'Forge', username: 'grace@example.com', reprompt: true },
      ],
      overflowCount: 2,
    }, { onSelect });
    expect(root.querySelector('.code')).toBeNull();
    expect(root.querySelectorAll('.candidate')).toHaveLength(2);
    expect(root.textContent).toContain('ada@example.com');
    expect(root.textContent).toContain('grace@example.com');
    expect(root.textContent).toContain('另有 2 个匹配项未显示');
    const second = root.querySelector('[data-candidate-key="candidate-1"]')!;
    second.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onSelect).not.toHaveBeenCalled();
    trustedClick(second);
    expect(onSelect).toHaveBeenCalledWith('candidate-1');
  });

  it('offers a trusted account switch only after a multi-candidate selection', () => {
    const onChooseOther = vi.fn();
    const root = mount({
      candidates: [
        { key: 'candidate-0', name: 'Forge', username: 'ada@example.com', reprompt: false },
        { key: 'candidate-1', name: 'Forge', username: 'grace@example.com', reprompt: false },
      ],
    }, { onChooseOther });
    trustedClick(root.querySelector('.change-candidate')!);
    expect(onChooseOther).toHaveBeenCalledOnce();
  });

  it('declares dark and reduced-motion tokens', () => {
    expect(TOTP_PANEL_STYLES).toContain('prefers-color-scheme: dark');
    expect(TOTP_PANEL_STYLES).toContain('prefers-reduced-motion: reduce');
  });
});
