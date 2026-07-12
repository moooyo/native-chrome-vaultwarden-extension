// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } },
  },
}));

import './security-section.js';
import type { VwSecuritySection } from './security-section.js';
import type { ChangePasswordDetail, LockTimeoutSaveDetail, SecuritySaveDetail } from '../types.js';

async function mount(props: Partial<VwSecuritySection> = {}): Promise<VwSecuritySection> {
  const el = document.createElement('vw-security-section') as VwSecuritySection;
  el.lockTimeout = '15';
  el.onIdleAction = 'lock';
  el.clipboardClearSeconds = '60';
  Object.assign(el, props);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwSecuritySection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

function selectChange(el: VwSecuritySection, sel: string, value: string): void {
  q(el, sel).dispatchEvent(new CustomEvent('vw-select-change', { detail: { value }, bubbles: true, composed: true }));
}

describe('vw-security-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('emits vw-lock-timeout-save when the lock timeout changes', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));
    selectChange(el, '[data-lock-select]', '30');
    expect(saved).toHaveBeenCalledWith({ lockTimeout: '30' });
  });

  it('ignores an invalid lock timeout value', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', saved);
    selectChange(el, '[data-lock-select]', 'bogus');
    expect(saved).not.toHaveBeenCalled();
  });

  it('emits vw-security-save when the idle action changes, preserving the clipboard window', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-security-save', (e) => saved((e as CustomEvent<SecuritySaveDetail>).detail));
    selectChange(el, '[data-idle-select]', 'logout');
    expect(saved).toHaveBeenCalledWith({ onIdleAction: 'logout', clipboardClearSeconds: '60' });
  });

  it('emits vw-security-save when the clipboard window changes, preserving the idle action', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-security-save', (e) => saved((e as CustomEvent<SecuritySaveDetail>).detail));
    selectChange(el, '[data-clip-select]', '120');
    expect(saved).toHaveBeenCalledWith({ onIdleAction: 'lock', clipboardClearSeconds: '120' });
  });

  it('renders a biometric-unlock toggle', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('vw-toggle')).not.toBeNull();
  });

  it('emits vw-change-password with the current and new passwords when the form is valid', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', (e) => changed((e as CustomEvent<ChangePasswordDetail>).detail));
    q<HTMLInputElement>(el, '[data-current-password]').value = 'old-pass';
    q<HTMLInputElement>(el, '[data-new-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-confirm-password]').value = 'new-pass';
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    expect(changed).toHaveBeenCalledWith({ currentPassword: 'old-pass', newPassword: 'new-pass' });
  });

  it('blocks the change when the new password and confirmation differ', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    q<HTMLInputElement>(el, '[data-current-password]').value = 'old-pass';
    q<HTMLInputElement>(el, '[data-new-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-confirm-password]').value = 'different';
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(el.shadowRoot!.querySelector('.pw-error')).not.toBeNull();
  });

  it('blocks the change when the new password is empty', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    expect(changed).not.toHaveBeenCalled();
  });
});
