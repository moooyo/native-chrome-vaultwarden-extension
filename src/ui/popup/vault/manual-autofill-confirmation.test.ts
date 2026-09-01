// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './manual-autofill-confirmation.js';
import type { VwManualAutofillConfirmation } from './manual-autofill-confirmation.js';

async function mount(canSave: boolean): Promise<VwManualAutofillConfirmation> {
  const element = document.createElement(
    'vw-manual-autofill-confirmation',
  ) as VwManualAutofillConfirmation;
  element.name = 'Work account';
  element.warning = {
    risk: 'no_match',
    site: 'app.example',
    recipientSite: 'accounts.example',
    canSave,
    requiresReprompt: false,
  };
  document.body.append(element);
  await element.updateComplete;
  return element;
}

afterEach(() => document.body.replaceChildren());

describe('vw-manual-autofill-confirmation', () => {
  it('shows the page and credential recipient and emits all three choices when writable', async () => {
    const element = await mount(true);
    expect(element.shadowRoot?.textContent).toContain('app.example');
    expect(element.shadowRoot?.textContent).toContain('accounts.example');
    const action = vi.fn();
    const cancel = vi.fn();
    element.addEventListener('vw-manual-autofill-action', action);
    element.addEventListener('vw-manual-autofill-cancel', cancel);
    const buttons = [...element.shadowRoot!.querySelectorAll('button')];
    expect(buttons).toHaveLength(3);
    buttons[0]!.click();
    buttons[1]!.click();
    buttons[2]!.click();
    expect(action).toHaveBeenNthCalledWith(1, expect.objectContaining({
      detail: { action: 'fill_only' },
    }));
    expect(action).toHaveBeenNthCalledWith(2, expect.objectContaining({
      detail: { action: 'fill_and_save' },
    }));
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('never renders save for a read-only item and disables every action while pending', async () => {
    const element = await mount(false);
    expect(element.shadowRoot?.textContent).not.toContain('Autofill and save this site');
    expect(element.shadowRoot?.querySelectorAll('button')).toHaveLength(2);
    element.pending = true;
    await element.updateComplete;
    expect([...element.shadowRoot!.querySelectorAll('button')].every((button) => button.disabled))
      .toBe(true);
  });
});
