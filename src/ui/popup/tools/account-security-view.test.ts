// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './account-security-view.js';
import type { VwAccountSecurityView } from './account-security-view.js';
import type { VwStatusMessage } from '../../components/status-message.js';
import type { ChangeKdfDetail, ChangePasswordDetail, RotateKeyDetail } from '../types.js';

async function mount(): Promise<VwAccountSecurityView> {
  const el = document.createElement('vw-account-security-view') as VwAccountSecurityView;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwAccountSecurityView, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

function set(el: VwAccountSecurityView, sel: string, value: string): void {
  q<HTMLInputElement>(el, sel).value = value;
}

function text(el: VwAccountSecurityView): string {
  const own = el.shadowRoot!.textContent ?? '';
  const messages = [...el.shadowRoot!.querySelectorAll('vw-status-message')]
    .map((node) => (node as VwStatusMessage).message ?? '')
    .join(' ');
  return `${own} ${messages}`.toLowerCase();
}

describe('vw-account-security-view password change', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('requires the current and new password', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('enter your current and new password');
  });

  it('rejects a new password shorter than 8 characters', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', 'short');
    set(el, '[data-confirm]', 'short');
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('at least 8 characters');
  });

  it('rejects mismatched confirmation', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', 'longenough');
    set(el, '[data-confirm]', 'different1');
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('do not match');
  });

  it('emits a validated password change', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', (e) => changed((e as CustomEvent<ChangePasswordDetail>).detail));
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', 'longenough');
    set(el, '[data-confirm]', 'longenough');
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    expect(changed).toHaveBeenCalledWith({ currentPassword: 'current', newPassword: 'longenough' });
  });
});

describe('vw-account-security-view KDF change', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('enforces a PBKDF2 minimum of 600000 iterations', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', changed);
    set(el, '[data-kdf-current]', 'current');
    set(el, '[data-iterations]', '500000');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('at least 600000');
  });

  it('emits a KDF change at or above the minimum', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', (e) => changed((e as CustomEvent<ChangeKdfDetail>).detail));
    set(el, '[data-kdf-current]', 'current');
    set(el, '[data-iterations]', '600000');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    expect(changed).toHaveBeenCalledWith({ currentPassword: 'current', iterations: 600000 });
  });
});

describe('vw-account-security-view key rotation', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows a two-step warning before allowing rotation', async () => {
    const el = await mount();
    // The main view must not expose a confirm control directly.
    expect(q<HTMLButtonElement>(el, '[data-rotate]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-rotate-confirm]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-rotate]').click();
    await el.updateComplete;
    expect(text(el)).toContain("can't be undone");
    expect(el.shadowRoot!.querySelector('[data-rotate-confirm]')).toBeTruthy();
  });

  it('requires the master password to confirm rotation', async () => {
    const el = await mount();
    q<HTMLButtonElement>(el, '[data-rotate]').click();
    await el.updateComplete;
    const rotated = vi.fn();
    el.addEventListener('vw-rotate-key', rotated);
    q<HTMLButtonElement>(el, '[data-rotate-confirm]').click();
    await el.updateComplete;
    expect(rotated).not.toHaveBeenCalled();
    expect(text(el)).toContain('enter your current master password');
  });

  it('emits the rotation with the confirmed password', async () => {
    const el = await mount();
    q<HTMLButtonElement>(el, '[data-rotate]').click();
    await el.updateComplete;
    const rotated = vi.fn();
    el.addEventListener('vw-rotate-key', (e) => rotated((e as CustomEvent<RotateKeyDetail>).detail));
    set(el, '[data-rotate-current]', 'masterpw');
    q<HTMLButtonElement>(el, '[data-rotate-confirm]').click();
    expect(rotated).toHaveBeenCalledWith({ masterPassword: 'masterpw' });
  });
});
