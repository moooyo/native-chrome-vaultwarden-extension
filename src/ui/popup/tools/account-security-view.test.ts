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
import { DEFAULT_MASTER_PASSWORD_MIN_LENGTH } from '../../../core/policy/master-password-policy.js';
import { t } from '../../i18n/index.js';

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

  it('gives every security-sensitive input a stable accessible name', async () => {
    const el = await mount();
    for (const [selector, label] of [
      ['[data-current]', t('security.currentPassword')],
      ['[data-new]', t('security.newPassword')],
      ['[data-confirm]', t('security.confirmPassword')],
      ['[data-hint]', t('security.masterPasswordHint')],
      ['[data-kdf-current]', t('security.currentPassword')],
      ['[data-iterations]', t('security.pbkdf2Iterations')],
    ] as const) {
      expect(q<HTMLInputElement>(el, selector).getAttribute('aria-label')).toBe(label);
    }

    const segmented = q<HTMLElement & { label: string }>(el, 'vw-segmented');
    expect(segmented.label).toBe(t('security.kdfType'));
    segmented.dispatchEvent(new CustomEvent(
      'vw-segmented-change',
      { detail: { id: 'argon2id' }, bubbles: true, composed: true },
    ));
    await el.updateComplete;
    for (const selector of [
      '[data-argon-iterations]',
      '[data-argon-memory]',
      '[data-argon-parallelism]',
    ]) {
      expect(q<HTMLInputElement>(el, selector).closest('label')?.textContent?.trim()).not.toBe('');
    }

    q<HTMLButtonElement>(el, '[data-rotate]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-rotate-current]').getAttribute('aria-label'))
      .toBe(t('security.currentPassword'));
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
    const input = q<HTMLInputElement>(el, '[data-current]');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(input.getAttribute('aria-describedby')).toBe('account-security-validation-error');
    expect(q(el, '#account-security-validation-error').textContent).toContain('当前主密码');
  });

  it('rejects an 11-character new password using the shared default', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', 'a'.repeat(11));
    set(el, '[data-confirm]', 'a'.repeat(11));
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain(t('auth.passwordMin', { min: DEFAULT_MASTER_PASSWORD_MIN_LENGTH }));
    expect(q<HTMLInputElement>(el, '[data-new]').minLength).toBe(DEFAULT_MASTER_PASSWORD_MIN_LENGTH);
  });

  it('rejects mismatched confirmation', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', 'long-enough-1');
    set(el, '[data-confirm]', 'long-enough-2');
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;
    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain('不一致');
    expect(q<HTMLInputElement>(el, '[data-confirm]').getAttribute('aria-invalid')).toBe('true');
    expect(q<HTMLInputElement>(el, '[data-confirm]').getAttribute('aria-describedby'))
      .toBe('account-security-validation-error');
  });

  it('accepts an exact 12-character new password', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', (e) => changed((e as CustomEvent<ChangePasswordDetail>).detail));
    set(el, '[data-current]', 'current');
    const password = 'TwelveChars!';
    expect(password).toHaveLength(DEFAULT_MASTER_PASSWORD_MIN_LENGTH);
    set(el, '[data-new]', password);
    set(el, '[data-confirm]', password);
    set(el, '[data-hint]', 'Helpful phrase');
    q<HTMLButtonElement>(el, '[data-change-password]').click();
    expect(changed).toHaveBeenCalledWith({
      currentPassword: 'current',
      newPassword: password,
      masterPasswordHint: 'Helpful phrase',
    });
  });

  it.each([
    ['TwelveChars!', 'TwelveChars!', t('security.masterPasswordHintMatches')],
    ['TwelveChars!', 'x'.repeat(51), t('security.masterPasswordHintTooLong', { max: 50 })],
  ])('rejects an invalid master-password hint', async (password, hint, message) => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', changed);
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', password);
    set(el, '[data-confirm]', password);
    set(el, '[data-hint]', hint);

    q<HTMLButtonElement>(el, '[data-change-password]').click();
    await el.updateComplete;

    expect(changed).not.toHaveBeenCalled();
    expect(text(el)).toContain(message);
    expect(q<HTMLInputElement>(el, '[data-hint]').getAttribute('aria-invalid')).toBe('true');
  });

  it('uses raw case-sensitive hint comparison without trimming', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-password', (event) => {
      changed((event as CustomEvent<ChangePasswordDetail>).detail);
    });
    set(el, '[data-current]', 'current');
    set(el, '[data-new]', 'TwelveChars!');
    set(el, '[data-confirm]', 'TwelveChars!');
    set(el, '[data-hint]', ' twelvechars! ');

    q<HTMLButtonElement>(el, '[data-change-password]').click();

    expect(changed).toHaveBeenCalledWith(expect.objectContaining({
      masterPasswordHint: ' twelvechars! ',
    }));
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
    expect(q<HTMLInputElement>(el, '[data-iterations]').getAttribute('aria-invalid')).toBe('true');
    expect(q<HTMLInputElement>(el, '[data-iterations]').getAttribute('aria-describedby'))
      .toBe('account-security-validation-error');
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
    expect(changed).toHaveBeenCalledWith({
      currentPassword: 'current',
      kdf: { kdf: 0, kdfIterations: 600000 },
    });
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
    expect(changed).toHaveBeenCalledWith({
      currentPassword: 'current',
      kdf: { kdf: 0, kdfIterations: 2000000 },
    });
  });

  it('offers Argon2id with the recommended 6/32/4 defaults', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', (e) => changed((e as CustomEvent<ChangeKdfDetail>).detail));
    set(el, '[data-kdf-current]', 'current');
    el.shadowRoot!.querySelector('vw-segmented')!.dispatchEvent(new CustomEvent(
      'vw-segmented-change',
      { detail: { id: 'argon2id' }, bubbles: true, composed: true },
    ));
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-argon-iterations]').value).toBe('6');
    expect(q<HTMLInputElement>(el, '[data-argon-memory]').value).toBe('32');
    expect(q<HTMLInputElement>(el, '[data-argon-parallelism]').value).toBe('4');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    expect(changed).toHaveBeenCalledWith({
      currentPassword: 'current',
      kdf: { kdf: 1, kdfIterations: 6, kdfMemory: 32, kdfParallelism: 4 },
    });
  });

  it('rejects every out-of-range Argon2id cost field', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-change-kdf', changed);
    set(el, '[data-kdf-current]', 'current');
    el.shadowRoot!.querySelector('vw-segmented')!.dispatchEvent(new CustomEvent(
      'vw-segmented-change',
      { detail: { id: 'argon2id' }, bubbles: true, composed: true },
    ));
    await el.updateComplete;

    set(el, '[data-argon-iterations]', '1');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    await el.updateComplete;
    expect(text(el)).toContain('2');

    set(el, '[data-argon-iterations]', '4');
    set(el, '[data-argon-memory]', '2048');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    await el.updateComplete;
    expect(text(el)).toContain('1024');

    set(el, '[data-argon-memory]', '32');
    set(el, '[data-argon-parallelism]', '0');
    q<HTMLButtonElement>(el, '[data-change-kdf]').click();
    await el.updateComplete;
    expect(text(el)).toContain('16');
    expect(changed).not.toHaveBeenCalled();
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
    const input = q<HTMLInputElement>(el, '[data-rotate-current]');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(input.getAttribute('aria-describedby')).toBe('account-security-validation-error');
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
