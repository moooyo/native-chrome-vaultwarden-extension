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

import './data-ownership-view.js';
import type { VwDataOwnershipView } from './data-ownership-view.js';

async function mount(): Promise<VwDataOwnershipView> {
  const element = document.createElement('vw-data-ownership-view') as VwDataOwnershipView;
  element.model = {
    organizationId: 'org-engineering',
    collectionId: 'collection-my-items',
    migrateAuthorizationId: '11111111-1111-4111-8111-111111111111',
    leaveAuthorizationId: '22222222-2222-4222-8222-222222222222',
    personalItemCount: 3,
    organizationName: 'Engineering',
    collectionName: 'My Items',
    migrationAvailable: true,
  };
  document.body.append(element);
  await element.updateComplete;
  return element;
}

afterEach(() => document.body.replaceChildren());

describe('vw-data-ownership-view', () => {
  it('shows the exact destination and emits a scrubbed master-password submission', async () => {
    const element = await mount();
    expect(element.shadowRoot?.textContent).toContain('Engineering');
    expect(element.shadowRoot?.textContent).toContain('My Items');
    expect(element.shadowRoot?.textContent).toContain('3');
    const password = element.shadowRoot!.querySelector<HTMLInputElement>('[data-master-password]')!;
    password.value = 'master-secret';
    const submitted = vi.fn();
    element.addEventListener('vw-data-ownership-migrate', submitted);
    element.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', {
      cancelable: true,
    }));

    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        masterPassword: 'master-secret',
        organizationId: 'org-engineering',
        collectionId: 'collection-my-items',
        authorizationId: '11111111-1111-4111-8111-111111111111',
      },
    }));
    expect(password.value).toBe('');
  });

  it('requires a second confirmation before emitting leave and disables commands while pending', async () => {
    const element = await mount();
    const leave = vi.fn();
    element.addEventListener('vw-data-ownership-leave', leave);
    const buttons = [...element.shadowRoot!.querySelectorAll('button')];
    buttons[0]!.click();
    await element.updateComplete;
    expect(leave).not.toHaveBeenCalled();
    const confirmationButtons = [...element.shadowRoot!.querySelectorAll('button')];
    confirmationButtons[1]!.click();
    expect(leave).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        organizationId: 'org-engineering',
        authorizationId: '22222222-2222-4222-8222-222222222222',
      },
    }));

    element.pending = true;
    await element.updateComplete;
    expect([...element.shadowRoot!.querySelectorAll('button')].every((button) => button.disabled))
      .toBe(true);
  });

  it('offers only the confirmed leave path when migration is blocked', async () => {
    const element = await mount();
    element.model = {
      organizationId: 'org-engineering',
      leaveAuthorizationId: '33333333-3333-4333-8333-333333333333',
      personalItemCount: 2,
      organizationName: 'Engineering',
      migrationAvailable: false,
    };
    await element.updateComplete;

    expect(element.shadowRoot!.querySelector('form')).toBeNull();
    expect(element.shadowRoot?.textContent).toContain('2');
    expect(element.shadowRoot!.querySelectorAll('button')).toHaveLength(1);
  });

  it('emits one leave request before the host reports pending', async () => {
    const element = await mount();
    const leave = vi.fn();
    element.addEventListener('vw-data-ownership-leave', leave);
    element.shadowRoot!.querySelector<HTMLButtonElement>('button[type="button"]')!.click();
    await element.updateComplete;
    const confirm = element.shadowRoot!.querySelector<HTMLButtonElement>('[data-confirm-leave]')!;

    confirm.click();
    confirm.click();

    expect(leave).toHaveBeenCalledTimes(1);
    await element.updateComplete;
    expect(confirm.disabled).toBe(true);
  });

  it('rejects an old leave confirmation immediately after its authorization changes', async () => {
    const element = await mount();
    const leave = vi.fn();
    element.addEventListener('vw-data-ownership-leave', leave);
    element.shadowRoot!.querySelector<HTMLButtonElement>('button[type="button"]')!.click();
    await element.updateComplete;
    const confirm = element.shadowRoot!.querySelector<HTMLButtonElement>('[data-confirm-leave]')!;

    element.model = {
      ...element.model!,
      leaveAuthorizationId: '66666666-6666-4666-8666-666666666666',
    };
    confirm.click();

    expect(leave).not.toHaveBeenCalled();
    await element.updateComplete;
    expect(element.shadowRoot!.querySelector('[data-confirm-leave]')).toBeNull();
  });

  it('scrubs password and cancels leave confirmation when an authorization changes', async () => {
    const element = await mount();
    const password = element.shadowRoot!.querySelector<HTMLInputElement>('[data-master-password]')!;
    password.value = 'must-not-survive';
    element.model = {
      ...element.model!,
      migrateAuthorizationId: '44444444-4444-4444-8444-444444444444',
    };
    await element.updateComplete;
    expect(element.shadowRoot!.querySelector<HTMLInputElement>('[data-master-password]')!.value).toBe('');

    element.shadowRoot!.querySelector<HTMLButtonElement>('button[type="button"]')!.click();
    await element.updateComplete;
    expect(element.shadowRoot!.querySelector('form')).toBeNull();

    element.model = {
      ...element.model!,
      leaveAuthorizationId: '55555555-5555-4555-8555-555555555555',
    };
    await element.updateComplete;

    expect(element.shadowRoot!.querySelector('form')).not.toBeNull();
    expect(element.shadowRoot!.querySelector<HTMLInputElement>('[data-master-password]')!.value).toBe('');
  });

  it('shows only full sync while an ownership action needs reconciliation', async () => {
    const element = await mount();
    element.model = undefined;
    element.reconciliation = { operation: 'migrate', reason: 'outcome_unknown' };
    await element.updateComplete;

    expect(element.shadowRoot!.querySelector('form')).toBeNull();
    expect(element.shadowRoot!.querySelectorAll('button')).toHaveLength(1);
    expect(element.shadowRoot!.querySelector('[data-full-sync]')?.textContent)
      .toContain('全量同步');
  });
});
