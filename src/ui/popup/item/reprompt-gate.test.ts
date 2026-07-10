// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './reprompt-gate.js';
import type { VwRepromptGate } from './reprompt-gate.js';
import type { VwStatusMessage } from '../../components/status-message.js';

async function mount(props: Partial<VwRepromptGate> = {}): Promise<VwRepromptGate> {
  const el = document.createElement('vw-reprompt-gate') as VwRepromptGate;
  el.name = props.name ?? 'Bank card';
  if (props.pending !== undefined) el.pending = props.pending;
  if (props.error !== undefined) el.error = props.error;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-reprompt-gate', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows the protected item name', async () => {
    const el = await mount({ name: 'Secret note' });
    expect(el.shadowRoot?.textContent).toContain('Secret note');
  });

  it('emits vw-reprompt-submit with the typed password', async () => {
    const el = await mount();
    const submit = vi.fn();
    el.addEventListener('vw-reprompt-submit', submit);
    const input = el.shadowRoot!.querySelector<HTMLInputElement>('input[type="password"]')!;
    input.value = 'hunter2';
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-unlock]')!.click();
    expect(submit).toHaveBeenCalledWith(expect.objectContaining({ detail: { password: 'hunter2' } }));
  });

  it('does not emit for an empty password', async () => {
    const el = await mount();
    const submit = vi.fn();
    el.addEventListener('vw-reprompt-submit', submit);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-unlock]')!.click();
    expect(submit).not.toHaveBeenCalled();
  });

  it('emits vw-item-back from the back button', async () => {
    const el = await mount();
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-back]')!.click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('renders an error message when provided', async () => {
    const el = await mount({ error: 'Incorrect master password' });
    const status = el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message');
    expect(status?.getAttribute('tone')).toBe('danger');
    expect(status?.message).toBe('Incorrect master password');
  });
});
