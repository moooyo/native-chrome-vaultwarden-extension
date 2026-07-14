// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The reskinned view composes the (frozen) MiYu design system, whose i18n module imports
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

/** Own shadow text plus every child status-message's `.message` property (which lives in that
 *  element's own shadow root, so it is invisible to `textContent`). */
function text(el: VwAccountSecurityView): string {
  const own = el.shadowRoot!.textContent ?? '';
  const messages = [...el.shadowRoot!.querySelectorAll('vw-status-message')]
    .map((node) => (node as VwStatusMessage).message ?? '')
    .join(' ');
  return `${own} ${messages}`;
}

describe('vw-account-security-view structure', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the header and the three security sections as setting cards', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('[data-back]')).toBeTruthy();
    expect(el.shadowRoot!.textContent).toContain('账户安全'); // popup.accountSecurity
    expect(el.shadowRoot!.querySelectorAll('vw-setting-card')).toHaveLength(3);
    expect(q(el, '[data-change-password]')).toBeTruthy();
    expect(q(el, '[data-change-kdf]')).toBeTruthy();
    expect(q(el, '[data-rotate]')).toBeTruthy();
  });

  it('emits vw-item-back from the back button', async () => {
    const el = await mount();
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    q<HTMLButtonElement>(el, '[data-back]').click();
    expect(back).toHaveBeenCalledTimes(1);
  });
});

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
    expect(text(el)).toContain('当前主密码和新主密码');
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
    expect(text(el)).toContain('8 个字符');
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
    expect(text(el)).toContain('不一致');
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
    expect(text(el)).toContain('600000');
  });

  it('requires the current password before changing KDF', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', changed);
    set(el, '[data-iterations]', '600000');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('请输入当前主密码');
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

  it('rejects an iteration count above the safe maximum', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', changed);
    set(el, '[data-kdf-current]', 'current');
    set(el, '[data-iterations]', '100000000');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('2000000');
  });

  it('accepts the exact safe maximum', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', (e) => changed((e as CustomEvent<ChangeKdfDetail>).detail));
    set(el, '[data-kdf-current]', 'current');
    set(el, '[data-iterations]', '2000000');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    expect(changed).toHaveBeenCalledWith({ currentPassword: 'current', iterations: 2000000 });
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
    expect(text(el)).toContain('无法撤销'); // can't be undone
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
    expect(text(el)).toContain('请输入当前主密码');
  });

  it('returns to the main view when rotation is cancelled', async () => {
    const el = await mount();
    q<HTMLButtonElement>(el, '[data-rotate]').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-rotate-cancel]').click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-rotate-confirm]')).toBeNull();
    expect(q(el, '[data-change-password]')).toBeTruthy();
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
