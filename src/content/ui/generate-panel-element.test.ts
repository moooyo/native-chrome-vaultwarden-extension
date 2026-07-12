// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './generate-panel-element.js';
import type { VwGeneratePanel } from './generate-panel-element.js';

function trustedClick(el: Element): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el.dispatchEvent(event);
}

async function mount(over: Partial<VwGeneratePanel> = {}): Promise<VwGeneratePanel> {
  const el = document.createElement('vw-generate-panel') as VwGeneratePanel;
  el.password = 'Ab3$xz9K';
  el.length = 18;
  el.numbers = true;
  el.symbols = true;
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => document.body.replaceChildren());

describe('vw-generate-panel', () => {
  it('renders the suggestion with digit + symbol coloring and the meta', async () => {
    const el = await mount();
    const root = el.shadowRoot!;
    expect(root.querySelector('.suggest')!.textContent).toBe('Ab3$xz9K');
    expect(root.querySelectorAll('.suggest .d').length).toBeGreaterThan(0); // digits
    expect(root.querySelectorAll('.suggest .s').length).toBeGreaterThan(0); // symbols
    expect(root.querySelector('.meta')!.textContent).toContain('18 字符');
    expect(root.querySelector('.meta')!.textContent).toContain('含符号');
  });

  it('reflects the rule pills and emits toggles on trusted click', async () => {
    const onNumbers = vi.fn();
    const el = await mount({ onNumbers });
    const pills = el.shadowRoot!.querySelectorAll('.pill');
    expect(pills[0]!.classList.contains('on')).toBe(true);
    trustedClick(pills[0]!);
    expect(onNumbers).toHaveBeenCalledWith(false);
  });

  it('emits length on slider input and regenerate on trusted refresh', async () => {
    const onLength = vi.fn();
    const onRegenerate = vi.fn();
    const el = await mount({ onLength, onRegenerate });
    const range = el.shadowRoot!.querySelector('input[type="range"]') as HTMLInputElement;
    range.value = '24';
    const evt = new Event('input', { bubbles: true });
    Object.defineProperty(evt, 'isTrusted', { value: true });
    range.dispatchEvent(evt);
    expect(onLength).toHaveBeenCalledWith(24);
    trustedClick(el.shadowRoot!.querySelector('.refresh')!);
    expect(onRegenerate).toHaveBeenCalledTimes(1);
  });

  it('uses the password on a trusted click', async () => {
    const onUse = vi.fn();
    const el = await mount({ onUse });
    el.shadowRoot!.querySelector('.use')!.dispatchEvent(new MouseEvent('click', { bubbles: true })); // untrusted
    expect(onUse).not.toHaveBeenCalled();
    trustedClick(el.shadowRoot!.querySelector('.use')!);
    expect(onUse).toHaveBeenCalledTimes(1);
  });

  it('shows the saved confirmation in the saved view', async () => {
    const el = await mount({ view: 'saved', savedName: 'quill.app', savedUser: 'me@x.dev' });
    const root = el.shadowRoot!;
    expect(root.querySelector('.saved .t')!.textContent).toContain('已保存到密屿');
    expect(root.querySelector('.saved .s')!.textContent).toContain('me@x.dev');
  });
});
