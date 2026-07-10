// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './security-section.js';
import type { VwSecuritySection } from './security-section.js';
import type { LockTimeoutSaveDetail, SecuritySaveDetail } from '../types.js';

async function mount(): Promise<VwSecuritySection> {
  const el = document.createElement('vw-security-section') as VwSecuritySection;
  el.lockTimeout = '15';
  el.onIdleAction = 'lock';
  el.clipboardClearSeconds = '60';
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwSecuritySection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-security-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('emits the chosen lock timeout on save', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-lock-timeout-save', (e) => saved((e as CustomEvent<LockTimeoutSaveDetail>).detail));
    const select = q<HTMLSelectElement>(el, '[data-lock-timeout]');
    select.value = '30';
    q<HTMLButtonElement>(el, '[data-lock-save]').click();
    expect(saved).toHaveBeenCalledWith({ lockTimeout: '30' });
  });

  it('saves security settings immediately when the idle action changes', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-security-save', (e) => saved((e as CustomEvent<SecuritySaveDetail>).detail));
    const idle = q<HTMLSelectElement>(el, '[data-idle]');
    idle.value = 'logout';
    idle.dispatchEvent(new Event('change', { bubbles: true }));
    expect(saved).toHaveBeenCalledWith({ onIdleAction: 'logout', clipboardClearSeconds: '60' });
  });

  it('saves security settings immediately when the clipboard window changes', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-security-save', (e) => saved((e as CustomEvent<SecuritySaveDetail>).detail));
    const clip = q<HTMLSelectElement>(el, '[data-clipboard]');
    clip.value = '120';
    clip.dispatchEvent(new Event('change', { bubbles: true }));
    expect(saved).toHaveBeenCalledWith({ onIdleAction: 'lock', clipboardClearSeconds: '120' });
  });

  it('warns that logout ends the session on every idle timeout', async () => {
    const el = await mount();
    const idle = q<HTMLSelectElement>(el, '[data-idle]');
    idle.value = 'logout';
    idle.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;
    expect(el.shadowRoot!.textContent?.toLowerCase()).toContain('log out');
  });
});
