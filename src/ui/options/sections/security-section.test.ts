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
import { setLocale } from '../../i18n/index.js';

async function mount(props: Partial<VwSecuritySection> = {}): Promise<VwSecuritySection> {
  const el = document.createElement('vw-security-section') as VwSecuritySection;
  el.lockTimeout = '15';
  el.onIdleAction = 'lock';
  el.clipboardClearSeconds = '60';
  el.locked = false;
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
    setLocale('zh-CN', false);
    document.body.replaceChildren();
  });

  it('emits vw-lock-timeout-save when the lock timeout changes', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));
    selectChange(el, '[data-lock-select]', '30');
    expect(saved).toHaveBeenCalledWith({ lockTimeout: '30' });
  });

  it.each(['immediate', 'onLocked'] as const)('emits the built-in %s mode directly', async (value) => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));

    selectChange(el, '[data-lock-select]', value);

    expect(saved).toHaveBeenCalledWith({ lockTimeout: value });
  });

  it('continues emitting automatic setting changes while another action is pending', async () => {
    const el = await mount({ pending: true });
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));
    selectChange(el, '[data-lock-select]', '30');
    selectChange(el, '[data-lock-select]', 'onClose');
    expect(saved.mock.calls).toEqual([[{ lockTimeout: '30' }], [{ lockTimeout: 'onClose' }]]);
  });

  it('offers on-close instead of never and ignores a forged legacy selection', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', saved);
    const select = q<HTMLElement & { options: Array<{ value: string; label: string }> }>(el, '[data-lock-select]');

    expect(select.options.map(({ value }) => value)).toEqual([
      'immediate', '1', '5', '15', '30', 'onLocked', 'onClose', 'custom',
    ]);
    expect(select.options.find(({ value }) => value === 'onClose')?.label).toContain('浏览器关闭');
    expect(select.options.at(-1)?.label).toContain('自定义');
    selectChange(el, '[data-lock-select]', 'never');
    expect(saved).not.toHaveBeenCalled();
    expect(el.lockTimeout).toBe('15');
  });

  it('ignores an invalid lock timeout value', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', saved);
    selectChange(el, '[data-lock-select]', 'bogus');
    expect(saved).not.toHaveBeenCalled();
  });

  it('shows, validates, and one-shot saves canonical custom minutes', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));
    selectChange(el, '[data-lock-select]', 'custom');
    await el.updateComplete;
    const input = q<HTMLInputElement>(el, '[data-custom-lock-minutes]');
    const save = q<HTMLButtonElement>(el, '[data-save-custom-lock]');

    expect(input.type).toBe('number');
    expect(input.min).toBe('1');
    expect(input.max).toBe('43200');
    expect(input.step).toBe('1');
    expect(input.getAttribute('aria-describedby')).toBe('custom-lock-help custom-lock-error');
    input.value = '17';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    save.click();
    save.click();

    expect(saved).toHaveBeenCalledTimes(1);
    expect(saved).toHaveBeenCalledWith({ lockTimeout: '17' });
    await el.updateComplete;
    expect(q<HTMLButtonElement>(el, '[data-save-custom-lock]').disabled).toBe(true);
  });

  it.each(['0', '01', '+1', '-1', '1.5', '1e3', '43201', ' 15 '])(
    'rejects invalid custom minutes with an accessible error: %j',
    async (value) => {
      const el = await mount();
      const saved = vi.fn();
      el.addEventListener('vw-lock-timeout-save', saved);
      selectChange(el, '[data-lock-select]', 'custom');
      await el.updateComplete;
      const input = q<HTMLInputElement>(el, '[data-custom-lock-minutes]');
      input.value = value;
      input.dispatchEvent(new Event('input', { bubbles: true }));

      q<HTMLButtonElement>(el, '[data-save-custom-lock]').click();
      await el.updateComplete;

      expect(saved).not.toHaveBeenCalled();
      expect(q<HTMLInputElement>(el, '[data-custom-lock-minutes]').getAttribute('aria-invalid')).toBe('true');
      expect(el.shadowRoot!.querySelector('[role="alert"]')?.textContent).toContain('43200');
    },
  );

  it('restores an existing custom value and submits it with Enter', async () => {
    const el = await mount({ lockTimeout: '37' });
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));
    const select = q<HTMLElement & { value: string }>(el, '[data-lock-select]');
    const input = q<HTMLInputElement>(el, '[data-custom-lock-minutes]');

    expect(select.value).toBe('custom');
    expect(input.value).toBe('37');
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));

    expect(saved).toHaveBeenCalledWith({ lockTimeout: '37' });
  });

  it('disables custom editing and saving while pending', async () => {
    const el = await mount({ lockTimeout: '37', pending: true });
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', saved);

    expect(q<HTMLInputElement>(el, '[data-custom-lock-minutes]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-save-custom-lock]').disabled).toBe(true);
    q<HTMLButtonElement>(el, '[data-save-custom-lock]').click();
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

  it('localizes every clipboard duration in English', async () => {
    setLocale('en', false);
    const el = await mount();
    const select = q<HTMLElement & { options: Array<{ value: string; label: string }> }>(el, '[data-clip-select]');
    expect(select.options).toEqual([
      { value: 'never', label: 'Never' },
      { value: '30', label: '30 seconds' },
      { value: '60', label: '1 minute' },
      { value: '120', label: '2 minutes' },
      { value: '300', label: '5 minutes' },
    ]);
  });

  it('localizes the special and custom timeout choices in English', async () => {
    setLocale('en', false);
    const el = await mount();
    const select = q<HTMLElement & { options: Array<{ value: string; label: string }> }>(el, '[data-lock-select]');
    expect(select.options.find(({ value }) => value === 'immediate')?.label).toBe('Immediately');
    expect(select.options.find(({ value }) => value === 'onLocked')?.label).toBe('When the system locks');
    expect(select.options.find(({ value }) => value === 'onClose')?.label).toBe('When the browser closes');
    expect(select.options.find(({ value }) => value === 'custom')?.label).toBe('Custom…');
  });

  it('shows effective values and removes timeout controls when organization-managed', async () => {
    const el = await mount({ timeoutManaged: true, lockTimeout: '5', onIdleAction: 'logout' });
    expect(el.shadowRoot!.querySelector('[data-timeout-managed]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-timeout-value]')?.textContent).toContain('5 分钟');
    expect(el.shadowRoot!.querySelector('[data-lock-select]')).toBeNull();
    expect(el.shadowRoot!.querySelector('[data-idle-select]')).toBeNull();
  });

  it('shows an exact custom organization-managed value without exposing custom controls', async () => {
    const el = await mount({ timeoutManaged: true, lockTimeout: '17' });
    expect(el.shadowRoot!.querySelector('[data-timeout-value]')?.textContent).toContain('17 分钟');
    expect(el.shadowRoot!.querySelector('[data-custom-lock-minutes]')).toBeNull();
    expect(el.shadowRoot!.querySelector('[data-save-custom-lock]')).toBeNull();
  });

  it('labels a system-lock-only managed mode without showing a numeric timeout', async () => {
    const el = await mount({ timeoutManaged: true, timeoutMode: 'systemLock', lockTimeout: '30' });
    const value = el.shadowRoot!.querySelector('[data-timeout-value]')?.textContent ?? '';
    expect(value).toContain('系统锁定时');
    expect(value).not.toContain('30 分钟');
  });

  it('shows organization-managed PIN status when PIN unlock is denied', async () => {
    const el = await mount({ pinUnlockAllowed: false });
    const status = el.shadowRoot!.querySelector<HTMLElement & { message: string }>('[data-pin-managed]');
    expect(status).not.toBeNull();
    expect(status?.message).toContain('组织策略');
  });

  it('does not advertise biometric unlock without a biometric backend', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('vw-toggle')).toBeNull();
  });

  it('gives each master-password input a stable accessible name', async () => {
    setLocale('en', false);
    const el = await mount();
    expect(q<HTMLInputElement>(el, '[data-current-password]').getAttribute('aria-label'))
      .toBe('Current master password');
    expect(q<HTMLInputElement>(el, '[data-new-password]').getAttribute('aria-label'))
      .toBe('New master password');
    expect(q<HTMLInputElement>(el, '[data-confirm-password]').getAttribute('aria-label'))
      .toBe('Confirm new master password');
    expect(q<HTMLInputElement>(el, '[data-master-password-hint]').getAttribute('aria-label'))
      .toBe('Master password hint (optional)');
  });

  it('emits vw-change-password with the current and new passwords when the form is valid', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', (e) => changed((e as CustomEvent<ChangePasswordDetail>).detail));
    q<HTMLInputElement>(el, '[data-current-password]').value = 'old-pass';
    q<HTMLInputElement>(el, '[data-new-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-confirm-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-master-password-hint]').value = '';
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    expect(changed).toHaveBeenCalledWith({
      currentPassword: 'old-pass',
      newPassword: 'new-pass',
      masterPasswordHint: '',
    });
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
    const input = q<HTMLInputElement>(el, '[data-confirm-password]');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(input.getAttribute('aria-describedby')).toBe('password-change-error');
    expect(q(el, '#password-change-error').textContent).toContain('确认');
  });

  it('blocks the change when the new password is empty', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    expect(changed).not.toHaveBeenCalled();
  });

  it('blocks a hint equal to the new password without normalizing either value', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    q<HTMLInputElement>(el, '[data-current-password]').value = 'old-pass';
    q<HTMLInputElement>(el, '[data-new-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-confirm-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-master-password-hint]').value = 'new-pass';

    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;

    expect(changed).not.toHaveBeenCalled();
    expect(q<HTMLInputElement>(el, '[data-master-password-hint]').getAttribute('aria-invalid'))
      .toBe('true');
  });

  it('clears and disables master-password inputs when the vault locks', async () => {
    const el = await mount();
    q<HTMLInputElement>(el, '[data-current-password]').value = 'old-pass';
    q<HTMLInputElement>(el, '[data-new-password]').value = 'new-pass';
    q<HTMLInputElement>(el, '[data-confirm-password]').value = 'new-pass';
    el.locked = true;
    await el.updateComplete;
    for (const input of el.shadowRoot!.querySelectorAll<HTMLInputElement>('.pw-input')) {
      expect(input.value).toBe('');
      expect(input.disabled).toBe(true);
    }
    expect(q<HTMLButtonElement>(el, '[data-change-password]').disabled).toBe(true);
  });
});
