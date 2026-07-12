// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './totp-panel-element.js';
import type { VwTotpPanel } from './totp-panel-element.js';

function trustedClick(el: Element): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el.dispatchEvent(event);
}

async function mount(over: Partial<VwTotpPanel> = {}): Promise<VwTotpPanel> {
  const el = document.createElement('vw-totp-panel') as VwTotpPanel;
  el.itemName = 'Forge';
  el.itemUser = 'zhihang-z';
  el.code = '123456';
  el.remaining = 15;
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => document.body.replaceChildren());

describe('vw-totp-panel', () => {
  it('renders the item, grouped code, seconds, and a draining meter', async () => {
    const el = await mount();
    const root = el.shadowRoot!;
    expect(root.textContent).toContain('Forge');
    expect(root.querySelector('.code')!.textContent).toBe('123 456');
    expect(root.querySelector('.secs')!.textContent).toContain('15s');
    expect((root.querySelector('.fill-bar') as HTMLElement).getAttribute('style')).toContain('width:50%');
  });

  it('fills only on a trusted click', async () => {
    const onFill = vi.fn();
    const el = await mount({ onFill });
    const btn = el.shadowRoot!.querySelector('.btn-primary')!;
    btn.dispatchEvent(new MouseEvent('click', { bubbles: true })); // untrusted
    expect(onFill).not.toHaveBeenCalled();
    trustedClick(btn);
    expect(onFill).toHaveBeenCalledTimes(1);
  });

  it('copies the code on a trusted click', async () => {
    const onCopy = vi.fn();
    const el = await mount({ onCopy });
    trustedClick(el.shadowRoot!.querySelector('.icon-btn')!);
    expect(onCopy).toHaveBeenCalledTimes(1);
  });

  it('shows the filled badge + undo in the filled view', async () => {
    const onUndo = vi.fn();
    const el = await mount({ view: 'filled', onUndo });
    expect(el.shadowRoot!.querySelector('.badge')!.textContent).toContain('已填充验证码');
    trustedClick(el.shadowRoot!.querySelector('.undo')!);
    expect(onUndo).toHaveBeenCalledTimes(1);
  });

  it('shows a status message in the status view', async () => {
    const el = await mount({ view: 'status', statusMessage: '无匹配' });
    expect(el.shadowRoot!.querySelector('.status-msg')!.textContent).toContain('无匹配');
  });
});
