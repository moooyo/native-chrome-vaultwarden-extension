// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './segmented.js';
import type { VwSegmented } from './segmented.js';

async function mount(): Promise<VwSegmented> {
  const el = document.createElement('vw-segmented') as VwSegmented;
  el.options = [
    { id: 'a', label: 'A' },
    { id: 'b', label: 'B' },
    { id: 'c', label: 'C' },
  ];
  el.value = 'a';
  el.label = 'Mode';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function press(target: HTMLElement, key: string): KeyboardEvent {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}

afterEach(() => document.body.replaceChildren());

describe('vw-segmented', () => {
  it('marks the active tab', async () => {
    const el = await mount();
    const tabs = el.shadowRoot!.querySelectorAll('button');
    expect(tabs[0]!.getAttribute('aria-selected')).toBe('true');
    expect(tabs[1]!.getAttribute('aria-selected')).toBe('false');
    expect([...tabs].map((tab) => tab.tabIndex)).toEqual([0, -1, -1]);
    expect(el.shadowRoot!.querySelector('[role="tablist"]')?.getAttribute('aria-label')).toBe('Mode');
  });

  it('emits vw-segmented-change on selecting another tab', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-segmented-change', fired);
    el.shadowRoot!.querySelectorAll('button')[1]!.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 'b' } }));
  });

  it('moves focus, selects, and emits once with horizontal arrow keys', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-segmented-change', fired);
    const first = el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')[0]!;
    first.focus();

    const event = press(first, 'ArrowRight');
    await el.updateComplete;
    const tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];

    expect(event.defaultPrevented).toBe(true);
    expect(el.value).toBe('b');
    expect(tabs.map((tab) => tab.tabIndex)).toEqual([-1, 0, -1]);
    expect(el.shadowRoot!.activeElement).toBe(tabs[1]);
    expect(fired).toHaveBeenCalledTimes(1);
    expect((fired.mock.calls[0]![0] as CustomEvent).detail).toEqual({ id: 'b' });
  });

  it('wraps and supports Home and End without emitting for the current tab', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-segmented-change', fired);
    let tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];

    press(tabs[0]!, 'ArrowLeft');
    await el.updateComplete;
    expect(el.value).toBe('c');

    tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];
    press(tabs[2]!, 'Home');
    await el.updateComplete;
    expect(el.value).toBe('a');

    tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];
    press(tabs[0]!, 'End');
    await el.updateComplete;
    expect(el.value).toBe('c');
    press(el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')[2]!, 'End');
    expect(fired).toHaveBeenCalledTimes(3);
  });

  it('skips disabled options and never selects them', async () => {
    const el = await mount();
    el.options = [
      { id: 'a', label: 'A' },
      { id: 'b', label: 'B', disabled: true },
      { id: 'c', label: 'C' },
    ];
    await el.updateComplete;
    const fired = vi.fn();
    el.addEventListener('vw-segmented-change', fired);
    let tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];

    expect(tabs[1]!.disabled).toBe(true);
    tabs[1]!.click();
    expect(fired).not.toHaveBeenCalled();
    press(tabs[0]!, 'ArrowRight');
    await el.updateComplete;
    tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];
    expect(el.value).toBe('c');
    expect(el.shadowRoot!.activeElement).toBe(tabs[2]);
    expect(fired).toHaveBeenCalledTimes(1);
  });

  it('removes every tab stop and blocks changes when the control is disabled', async () => {
    const el = await mount();
    el.disabled = true;
    await el.updateComplete;
    const fired = vi.fn();
    el.addEventListener('vw-segmented-change', fired);
    const tabs = [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')];

    expect(tabs.every((tab) => tab.disabled && tab.tabIndex === -1)).toBe(true);
    expect(el.shadowRoot!.querySelector('[role="tablist"]')?.getAttribute('aria-disabled')).toBe('true');
    tabs[1]!.click();
    press(tabs[0]!, 'ArrowRight');
    expect(el.value).toBe('a');
    expect(fired).not.toHaveBeenCalled();
  });
});
