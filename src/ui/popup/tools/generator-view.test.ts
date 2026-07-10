// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './generator-view.js';
import type { VwGeneratorView } from './generator-view.js';

async function mount(): Promise<VwGeneratorView> {
  const el = document.createElement('vw-generator-view') as VwGeneratorView;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwGeneratorView, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

function output(el: VwGeneratorView): string {
  return q<HTMLElement>(el, '[data-output]').textContent ?? '';
}

async function setInput(el: VwGeneratorView, sel: string, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, sel);
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function click(el: VwGeneratorView, sel: string): Promise<void> {
  q<HTMLButtonElement>(el, sel).click();
  await el.updateComplete;
}

describe('vw-generator-view modes', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('starts in password mode with a generated value', async () => {
    const el = await mount();
    expect(q<HTMLButtonElement>(el, '[data-mode-password]').getAttribute('aria-selected')).toBe('true');
    expect(output(el).length).toBeGreaterThanOrEqual(4);
  });

  it('switches to passphrase mode and produces separator-joined words', async () => {
    const el = await mount();
    await click(el, '[data-mode-passphrase]');
    expect(q<HTMLButtonElement>(el, '[data-mode-passphrase]').getAttribute('aria-selected')).toBe('true');
    expect(output(el).split('-').length).toBeGreaterThanOrEqual(3);
  });

  it('switches to username mode', async () => {
    const el = await mount();
    await click(el, '[data-mode-username]');
    expect(q<HTMLButtonElement>(el, '[data-mode-username]').getAttribute('aria-selected')).toBe('true');
    expect(q(el, '[data-ut-plus]')).toBeTruthy();
  });
});

describe('vw-generator-view option limits', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('clamps password length to a maximum of 128', async () => {
    const el = await mount();
    await setInput(el, '[data-length]', '500');
    expect(output(el).length).toBe(128);
  });

  it('clamps password length to a minimum of 4', async () => {
    const el = await mount();
    await setInput(el, '[data-length]', '1');
    expect(output(el).length).toBe(4);
  });

  it('clamps passphrase word count to a maximum of 20', async () => {
    const el = await mount();
    await click(el, '[data-mode-passphrase]');
    await setInput(el, '[data-separator]', '-');
    await setInput(el, '[data-words]', '99');
    // includeNumber appends a digit to one word, never a separator, so word count is preserved.
    expect(output(el).split('-').length).toBe(20);
  });

  it('clamps username random length to a maximum of 32', async () => {
    const el = await mount();
    await click(el, '[data-mode-username]');
    await setInput(el, '[data-base]', 'you@example.com');
    await setInput(el, '[data-un-len]', '99');
    const match = /^you\+([a-z0-9]+)@example\.com$/.exec(output(el));
    expect(match).not.toBeNull();
    expect(match?.[1]?.length).toBe(32);
  });
});

describe('vw-generator-view history and copy', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('records the replaced value on explicit regenerate', async () => {
    const el = await mount();
    const before = output(el);
    const recorded = vi.fn();
    el.addEventListener('vw-history-add', (e) => recorded((e as CustomEvent).detail));
    await click(el, '[data-regenerate]');
    expect(recorded).toHaveBeenCalledWith({ value: before });
  });

  it('copies the current value with the mode label and records it', async () => {
    const el = await mount();
    const current = output(el);
    const copied = vi.fn();
    const recorded = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    el.addEventListener('vw-history-add', (e) => recorded((e as CustomEvent).detail));
    await click(el, '[data-copy]');
    expect(copied).toHaveBeenCalledWith({ value: current, label: 'Password' });
    expect(recorded).toHaveBeenCalledWith({ value: current });
  });

  it('renders injected history with per-entry copy labelled Password', async () => {
    const el = await mount();
    el.history = ['old-secret'];
    await el.updateComplete;
    const copied = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    await click(el, '[data-copy-hist]');
    expect(copied).toHaveBeenCalledWith({ value: 'old-secret', label: 'Password' });
  });

  it('emits vw-history-clear from the Clear control', async () => {
    const el = await mount();
    el.history = ['a', 'b'];
    await el.updateComplete;
    const cleared = vi.fn();
    el.addEventListener('vw-history-clear', cleared);
    await click(el, '[data-clear]');
    expect(cleared).toHaveBeenCalledTimes(1);
  });
});

describe('vw-generator-view account-email prefill', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('prefills the plus-addressed base email from the injected account email', async () => {
    const el = await mount();
    el.accountEmail = 'me@example.com';
    await click(el, '[data-mode-username]');
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-base]').value).toBe('me@example.com');
    expect(output(el)).toMatch(/^me\+[a-z0-9]+@example\.com$/);
  });
});
