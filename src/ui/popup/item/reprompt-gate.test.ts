// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The component composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so we stub it. LocalizeController only subscribes on connect; no storage call happens
// at mount, but the stub covers the surface it could touch.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

import './reprompt-gate.js';
import type { VwRepromptGate } from './reprompt-gate.js';
import type { VwStatusMessage } from '../../components/status-message.js';
import type { RepromptSubmitDetail } from '../types.js';

async function mount(props: Partial<VwRepromptGate> = {}): Promise<VwRepromptGate> {
  const el = document.createElement('vw-reprompt-gate') as VwRepromptGate;
  el.name = props.name ?? 'Bank card';
  if (props.pending !== undefined) el.pending = props.pending;
  if (props.error !== undefined) el.error = props.error;
  el.identity = props.identity;
  el.contextKey = props.contextKey ?? '';
  el.fieldLabel = props.fieldLabel ?? '';
  el.actionLabel = props.actionLabel ?? '';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwRepromptGate, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-reprompt-gate', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the protected action with a password input, verify and back controls', async () => {
    const el = await mount();
    expect(q(el, 'vw-logo')?.getAttribute('variant')).toBe('header');
    expect(q(el, 'input[type="password"]')).toBeTruthy();
    expect(q(el, '[data-unlock]')).toBeTruthy();
    expect(q(el, '[data-back]')).toBeTruthy();
  });

  it('shows the protected item name', async () => {
    const el = await mount({ name: 'Secret note' });
    expect(el.shadowRoot?.textContent).toContain('Secret note');
  });

  it('emits vw-reprompt-submit with the typed password', async () => {
    const el = await mount();
    const submit = vi.fn();
    el.addEventListener('vw-reprompt-submit', (e) => submit((e as CustomEvent<RepromptSubmitDetail>).detail));
    q<HTMLInputElement>(el, 'input[type="password"]').value = 'hunter2';
    q<HTMLInputElement>(el, 'input[type="password"]').dispatchEvent(new Event('input', { bubbles: true }));
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-unlock]').click();
    expect(submit).toHaveBeenCalledWith({ password: 'hunter2' });
    expect(q<HTMLInputElement>(el, 'input[type="password"]').value).toBe('');
  });

  it('submits on Enter in the password field', async () => {
    const el = await mount();
    const submit = vi.fn();
    el.addEventListener('vw-reprompt-submit', (e) => submit((e as CustomEvent<RepromptSubmitDetail>).detail));
    const input = q<HTMLInputElement>(el, 'input[type="password"]');
    input.value = 'hunter2';
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(submit).toHaveBeenCalledWith({ password: 'hunter2' });
  });

  it('does not emit for an empty password', async () => {
    const el = await mount();
    const submit = vi.fn();
    el.addEventListener('vw-reprompt-submit', submit);
    q<HTMLButtonElement>(el, '[data-unlock]').click();
    expect(submit).not.toHaveBeenCalled();
  });

  it('emits vw-item-back from the back link', async () => {
    const el = await mount();
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    q<HTMLButtonElement>(el, '[data-back]').click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('renders an error message when provided', async () => {
    const el = await mount({ error: 'Incorrect master password' });
    const status = el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message');
    expect(status?.getAttribute('tone')).toBe('danger');
    expect(status?.message).toBe('Incorrect master password');
  });

  it('keeps the requested field and vault identity separate from the item name', async () => {
    const el = await mount({ name: 'Bank card', fieldLabel: 'Card number', actionLabel: 'copy', identity: {
      email: 'vault@example.com', server: 'https://vault.example.net', owner: 'Personal vault',
    } });
    const content = el.shadowRoot!.textContent;
    for (const value of ['Bank card', 'Card number', 'copy', 'vault@example.com', 'https://vault.example.net', 'Personal vault']) {
      expect(content).toContain(value);
    }
    expect(q<HTMLButtonElement>(el, '[data-unlock]').disabled).toBe(true);
  });

  it('clears a typed password when the protected field or account changes', async () => {
    const el = await mount({ fieldLabel: 'Card number', identity: { email: 'one@example.com' } });
    const input = q<HTMLInputElement>(el, 'input[type="password"]');
    input.value = 'sensitive-input';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    await el.updateComplete;
    el.fieldLabel = 'Security code';
    await el.updateComplete;
    expect(input.value).toBe('');
    expect(q<HTMLButtonElement>(el, '[data-unlock]').disabled).toBe(true);
    input.value = 'second-sensitive-input';
    el.identity = { email: 'two@example.com' };
    await el.updateComplete;
    expect(input.value).toBe('');
  });

  it('distinguishes same-name items without exposing their request identifiers', async () => {
    const el = await mount({ contextKey: 'opaque-item-A', name: 'Shared name' });
    const input = q<HTMLInputElement>(el, 'input[type="password"]');
    input.value = 'sensitive-input';
    el.contextKey = 'opaque-item-B';
    await el.updateComplete;
    expect(input.value).toBe('');
    expect(el.shadowRoot!.innerHTML).not.toContain('opaque-item-');
    expect(el.outerHTML).not.toContain('opaque-item-');
  });
});
