// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The redesigned view composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so — like auth-views.test.ts — we stub it. LocalizeController only subscribes on
// connect; no storage call happens at mount, but the stub covers the surface it could touch.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

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

async function setRange(el: VwGeneratorView, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, '[data-length]');
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function setMode(el: VwGeneratorView, id: string): Promise<void> {
  q(el, '[data-mode]').dispatchEvent(
    new CustomEvent('vw-segmented-change', { detail: { id }, bubbles: true, composed: true }),
  );
  await el.updateComplete;
}

async function setToggle(el: VwGeneratorView, marker: string, checked: boolean): Promise<void> {
  q(el, `[data-toggle='${marker}']`).dispatchEvent(
    new CustomEvent('vw-toggle-change', { detail: { checked }, bubbles: true, composed: true }),
  );
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

  it('starts in random mode with a value at the default length', async () => {
    const el = await mount();
    expect(q<HTMLElement & { value: string }>(el, '[data-mode]').value).toBe('random');
    // Random default length is 14 (within the 8–40 slider range); output length matches exactly.
    expect(output(el).length).toBe(14);
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('14');
  });

  it('produces a passphrase of separator-joined words in memorable mode', async () => {
    const el = await mount();
    await setMode(el, 'memorable');
    // numWords tracks the length slider (default 14, clamped to 3–20); one digit is appended to a
    // single word by includeNumber, never a separator, so the word count is preserved.
    expect(output(el).split('-').length).toBe(14);
  });

  it('produces a numeric-only value in PIN mode', async () => {
    const el = await mount();
    await setMode(el, 'pin');
    expect(output(el)).toMatch(/^[0-9]+$/);
    expect(output(el).length).toBe(14);
  });
});

describe('vw-generator-view length + toggles', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('regenerates the random password to the chosen slider length', async () => {
    const el = await mount();
    await setRange(el, '40');
    expect(output(el).length).toBe(40);
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('40');
    await setRange(el, '8');
    expect(output(el).length).toBe(8);
  });

  it('clamps memorable word count to a maximum of 20', async () => {
    const el = await mount();
    await setMode(el, 'memorable');
    await setRange(el, '40');
    expect(output(el).split('-').length).toBe(20);
  });

  it('yields only lowercase letters when every character-set toggle is off', async () => {
    const el = await mount();
    await setToggle(el, 'upper', false);
    await setToggle(el, 'number', false);
    await setToggle(el, 'symbol', false);
    // Lowercase is always on, so the pool is never empty and the value is all-lowercase.
    expect(output(el)).toMatch(/^[a-z]+$/);
  });

  it('adds digits back to the random password when the numbers toggle is on', async () => {
    const el = await mount();
    await setToggle(el, 'upper', false);
    await setToggle(el, 'symbol', false);
    await setRange(el, '40');
    // lowercase + numbers only.
    expect(output(el)).toMatch(/^[a-z0-9]+$/);
    expect(output(el)).toMatch(/[0-9]/);
  });
});

describe('vw-generator-view strength', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  function strengthLabel(el: VwGeneratorView): string {
    return q<HTMLElement>(el, '[data-strength]').textContent?.trim() ?? '';
  }

  it('labels strength by output length', async () => {
    const el = await mount();
    // default length 14 → 强
    expect(strengthLabel(el)).toBe('强');
    await setRange(el, '40');
    expect(strengthLabel(el)).toBe('极强');
    await setRange(el, '10');
    expect(strengthLabel(el)).toBe('中等');
    await setRange(el, '8');
    expect(strengthLabel(el)).toBe('较弱');
  });
});

describe('vw-generator-view copy, history and back', () => {
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

  it('copies the current value with the password label and records it', async () => {
    const el = await mount();
    const current = output(el);
    const copied = vi.fn();
    const recorded = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    el.addEventListener('vw-history-add', (e) => recorded((e as CustomEvent).detail));
    await click(el, '[data-copy]');
    expect(copied).toHaveBeenCalledWith({ value: current, label: '密码' });
    expect(recorded).toHaveBeenCalledWith({ value: current });
  });

  it('copies a PIN with the PIN label', async () => {
    const el = await mount();
    await setMode(el, 'pin');
    const current = output(el);
    const copied = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    await click(el, '[data-copy]');
    expect(copied).toHaveBeenCalledWith({ value: current, label: 'PIN' });
  });

  it('emits vw-item-back from the close control', async () => {
    const el = await mount();
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    await click(el, '[data-close]');
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('accepts injected history/accountEmail without rendering a history list', async () => {
    const el = await mount();
    el.history = ['old-secret'];
    el.accountEmail = 'me@example.com';
    await el.updateComplete;
    // The redesigned view has no history UI; the props remain part of the public contract.
    expect(output(el).length).toBeGreaterThan(0);
  });
});
