// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The component now composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so — like app.test.ts — we stub it. LocalizeController only subscribes on connect;
// no storage call happens at mount, but the stub covers the surface it could touch.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './auth-views.js';
import type {
  DeviceLoginStartDetail,
  DuoTwoFactorStartDetail,
  EmailTwoFactorCodeRequestDetail,
  Fido2TwoFactorStartDetail,
  ForcedPasswordChangeSubmitDetail,
  NewDeviceVerificationSubmitDetail,
  SsoLoginStartDetail,
  VwAuthViews,
} from './auth-views.js';
import type { VwStatusMessage } from '../../components/status-message.js';
import { setLocale, t } from '../../i18n/index.js';
import { MAX_PIN_UTF16_CODE_UNITS } from '../../../core/session/pin-constraints.js';
import { DEFAULT_MASTER_PASSWORD_MIN_LENGTH } from '../../../core/policy/master-password-policy.js';
const FIDO_OWNER = Object.freeze({
  flow: 'password' as const,
  generation: 41,
  serverUrl: 'https://vault.example/',
  bindingId: 'password-continuation-41',
});
const FIDO_CHALLENGE = Object.freeze({ owner: FIDO_OWNER });

async function mount(mode: VwAuthViews['mode']): Promise<VwAuthViews> {
  const el = document.createElement('vw-auth-views') as VwAuthViews;
  el.mode = mode;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function input(el: VwAuthViews, id: string): HTMLInputElement {
  const node = el.shadowRoot?.getElementById(id);
  if (!(node instanceof HTMLInputElement)) throw new Error(`missing input #${id}`);
  return node;
}

function select(el: VwAuthViews, id: string): HTMLSelectElement {
  const node = el.shadowRoot?.getElementById(id);
  if (!(node instanceof HTMLSelectElement)) throw new Error(`missing select #${id}`);
  return node;
}

function buttons(el: VwAuthViews): HTMLButtonElement[] {
  return Array.from(el.shadowRoot?.querySelectorAll('button') ?? []);
}

/** Finds a button by a localized substring of its rendered text. */
function button(el: VwAuthViews, text: string): HTMLButtonElement {
  const found = buttons(el).find((b) => b.textContent?.includes(text));
  if (!found) throw new Error(`missing button with text "${text}"`);
  return found;
}

function hasButton(el: VwAuthViews, text: string): boolean {
  return buttons(el).some((b) => b.textContent?.includes(text));
}

async function selectFido(el: VwAuthViews): Promise<void> {
  el.providers = [0, 7];
  el.fido2 = FIDO_CHALLENGE;
  await el.updateComplete;
  select(el, 'provider').value = '7';
  select(el, 'provider').dispatchEvent(new Event('change'));
  await el.updateComplete;
}

describe('vw-auth-views', () => {
  afterEach(() => {
    document.body.replaceChildren();
    setLocale('zh-CN', false);
  });

  it('mounts every mode from props without throwing', async () => {
    for (const mode of [
      'login', 'passwordHint', 'register', 'registrationFinish', 'registrationCheckEmail',
      'newDeviceVerification', 'twoFactor', 'sso', 'accountPasskey', 'unlock',
    ] as const) {
      const el = await mount(mode);
      expect(el.shadowRoot).not.toBeNull();
      el.remove();
    }
  });

  // --- new-device verification ---------------------------------------------------------------

  it('renders only the OTP surface and emits submit, send, and cancel actions', async () => {
    const el = await mount('newDeviceVerification');
    el.newDeviceVerificationExpiresAt = Date.now() + 5 * 60_000;
    await el.updateComplete;
    expect(el.shadowRoot!.getElementById('email')).toBeNull();
    expect(el.shadowRoot!.getElementById('password')).toBeNull();
    const code = input(el, 'newDeviceVerificationCode');
    expect(code.autocomplete).toBe('one-time-code');
    expect(code.maxLength).toBe(256);
    code.value = '123456';

    const submitted = vi.fn<(event: CustomEvent<NewDeviceVerificationSubmitDetail>) => void>();
    const sent = vi.fn();
    const cancelled = vi.fn();
    el.addEventListener(
      'vw-auth-new-device-verification-submit',
      submitted as unknown as EventListener,
    );
    el.addEventListener('vw-auth-new-device-verification-send-otp', sent);
    el.addEventListener('vw-auth-new-device-verification-cancel', cancelled);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    button(el, t('auth.newDeviceVerification.sendCode')).click();
    button(el, t('common.cancel')).click();

    expect(submitted.mock.calls[0]![0].detail).toEqual({ code: '123456' });
    expect(sent).toHaveBeenCalledOnce();
    expect(cancelled).toHaveBeenCalledOnce();
  });

  it('shows an honest expired state without an active OTP form', async () => {
    const el = await mount('newDeviceVerification');
    el.newDeviceVerificationExpiresAt = Date.now() - 1;
    await el.updateComplete;

    expect(el.shadowRoot!.querySelector('form')).toBeNull();
    expect(el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message')?.message)
      .toBe(t('auth.newDeviceVerification.expired'));
    expect(hasButton(el, t('common.back'))).toBe(true);
  });

  // --- login ---------------------------------------------------------------------------------

  it('renders the login form and emits vw-auth-login-submit with email + password', async () => {
    const el = await mount('login');
    expect(el.shadowRoot!.querySelector('form')).not.toBeNull();
    input(el, 'email').value = 'user@example.com';
    input(el, 'password').value = 'hunter2';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-login-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
  });

  it('opens password hint from login with email only', async () => {
    const el = await mount('login');
    input(el, 'email').value = '  User@Example.COM  ';
    input(el, 'password').value = 'must-stay-private';
    const opened = vi.fn();
    const submitted = vi.fn();
    el.addEventListener('vw-auth-password-hint-start', opened);
    el.addEventListener('vw-auth-login-submit', submitted);

    el.shadowRoot?.querySelector<HTMLButtonElement>('[data-password-hint]')?.click();

    const detail = (opened.mock.calls.at(0)?.at(0) as CustomEvent).detail;
    expect(detail).toEqual({ email: 'User@Example.COM' });
    expect(Reflect.ownKeys(detail)).toEqual(['email']);
    expect(JSON.stringify(detail)).not.toContain('must-stay-private');
    expect(submitted).not.toHaveBeenCalled();
  });

  it('renders password-hint state through property-only bindings', async () => {
    const el = await mount('passwordHint');
    el.passwordHintEmail = 'user@example.com';
    el.passwordHintStatus = 'sent';
    await el.updateComplete;
    const hint = el.shadowRoot?.querySelector('vw-password-hint-view');
    await hint?.updateComplete;

    expect(hint?.email).toBe('user@example.com');
    expect(hint?.status).toBe('sent');
    expect(hint?.hasAttribute('email')).toBe(false);
    expect(hint?.hasAttribute('status')).toBe(false);
  });

  it('starts SSO with only the trimmed valid email and never submits the password form', async () => {
    const el = await mount('login');
    const email = input(el, 'email');
    email.value = '  user@example.com  ';
    input(el, 'password').value = 'must-not-leave-the-form';
    const started = vi.fn<(detail: SsoLoginStartDetail) => void>();
    const passwordSubmitted = vi.fn();
    el.addEventListener('vw-auth-sso-start', (event) => {
      started((event as CustomEvent<SsoLoginStartDetail>).detail);
      el.pending = true;
    });
    el.addEventListener('vw-auth-login-submit', passwordSubmitted);
    const sso = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-sso-login]')!;

    expect(sso.type).toBe('button');
    expect(sso.textContent).toContain(t('auth.sso.start'));
    expect(sso.querySelector('svg')).not.toBeNull();
    sso.click();
    sso.click();

    expect(started).toHaveBeenCalledTimes(1);
    expect(started).toHaveBeenCalledWith({ email: 'user@example.com' });
    expect(Object.keys(started.mock.calls[0]![0])).toEqual(['email']);
    expect(passwordSubmitted).not.toHaveBeenCalled();
    expect(email.value).toBe('user@example.com');
  });

  it('makes SSO the only login action when RequireSso applies, including form submission', async () => {
    const el = await mount('login');
    el.ssoRequired = true;
    await el.updateComplete;

    expect(el.shadowRoot!.getElementById('password')).toBeNull();
    expect(el.shadowRoot!.querySelector('[data-account-passkey]')).toBeNull();
    expect(el.shadowRoot!.querySelector('[data-device-login]')).toBeNull();
    expect(hasButton(el, t('auth.goRegister'))).toBe(false);
    const sso = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-sso-login]')!;
    expect(sso.classList.contains('primary')).toBe(true);

    input(el, 'email').value = '  required@example.com  ';
    const started = vi.fn<(detail: SsoLoginStartDetail) => void>();
    const passwordSubmitted = vi.fn();
    el.addEventListener('vw-auth-sso-start', (event) => {
      started((event as CustomEvent<SsoLoginStartDetail>).detail);
    });
    el.addEventListener('vw-auth-login-submit', passwordSubmitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));

    expect(started).toHaveBeenCalledWith({ email: 'required@example.com' });
    expect(passwordSubmitted).not.toHaveBeenCalled();
  });

  it('renders every SSO lifecycle state honestly and only allows cancellation while waiting', async () => {
    const el = await mount('sso');
    const cases = [
      ['waiting', t('auth.sso.waiting'), 'info', true],
      ['processing', t('auth.sso.processing'), 'info', false],
      ['outcome_unknown', t('auth.sso.outcomeUnknown'), 'danger', false],
      ['error', 'Identity provider rejected the request', 'danger', false],
    ] as const;

    for (const [status, message, tone, cancellable] of cases) {
      el.ssoStatus = status;
      el.error = status === 'error' ? message : undefined;
      await el.updateComplete;
      const banner = el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message')!;
      expect(banner.message).toBe(message);
      expect(banner.getAttribute('tone')).toBe(tone);
      expect(hasButton(el, t('common.cancel'))).toBe(cancellable);
    }

    el.ssoStatus = 'waiting';
    el.error = undefined;
    await el.updateComplete;
    const cancelled = vi.fn();
    el.addEventListener('vw-auth-sso-cancel', cancelled);
    button(el, t('common.cancel')).click();
    expect(cancelled).toHaveBeenCalledOnce();
  });

  it('starts device login with only a trimmed valid email and never submits the password form', async () => {
    const el = await mount('login');
    const email = input(el, 'email');
    email.value = '  user@example.com  ';
    input(el, 'password').value = 'must-not-leave-the-form';
    const started = vi.fn();
    const passwordSubmitted = vi.fn();
    el.addEventListener('vw-auth-device-login-start', (event) => {
      started((event as CustomEvent<DeviceLoginStartDetail>).detail);
      el.pending = true;
    });
    el.addEventListener('vw-auth-login-submit', passwordSubmitted);
    const deviceLogin = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-device-login]')!;

    expect(deviceLogin.tagName).toBe('BUTTON');
    expect(deviceLogin.type).toBe('button');
    expect(deviceLogin.tabIndex).toBe(0);
    expect(deviceLogin.textContent).toContain(t('auth.deviceLogin.start'));
    expect(deviceLogin.closest('form')).not.toBeNull();
    expect(deviceLogin.querySelector('svg')).not.toBeNull();
    deviceLogin.click();
    deviceLogin.click();

    expect(started).toHaveBeenCalledTimes(1);
    expect(started).toHaveBeenCalledWith({ email: 'user@example.com' });
    expect(Object.keys(started.mock.calls[0]![0])).toEqual(['email']);
    expect(started.mock.calls[0]![0]).not.toHaveProperty('password');
    expect(started.mock.calls[0]![0]).not.toHaveProperty('masterPassword');
    expect(passwordSubmitted).not.toHaveBeenCalled();
    expect(email.value).toBe('user@example.com');
  });

  it('starts account passkey login without reading email or password fields', async () => {
    const el = await mount('login');
    input(el, 'email').value = 'must-not-be-read@example.com';
    input(el, 'password').value = 'must-not-leave-the-form';
    const started = vi.fn();
    const passwordSubmitted = vi.fn();
    el.addEventListener('vw-auth-account-passkey-start', started);
    el.addEventListener('vw-auth-login-submit', passwordSubmitted);

    const passkey = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-account-passkey]')!;
    expect(passkey.type).toBe('button');
    expect(passkey.textContent).toContain(t('auth.accountPasskey.start'));
    expect(passkey.querySelector('svg')).not.toBeNull();
    passkey.click();

    expect(started).toHaveBeenCalledOnce();
    expect((started.mock.calls[0]![0] as CustomEvent).detail).toBeNull();
    expect(passwordSubmitted).not.toHaveBeenCalled();
  });

  it('renders honest account passkey terminal states and actions', async () => {
    const el = await mount('accountPasskey');
    el.accountPasskeyStatus = 'outcome_unknown';
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message')?.message)
      .toBe(t('auth.accountPasskey.outcomeUnknown'));
    const checked = vi.fn();
    el.addEventListener('vw-auth-account-passkey-check', checked);
    button(el, t('auth.accountPasskey.checkState')).click();
    expect(checked).toHaveBeenCalledOnce();

    el.accountPasskeyStatus = 'two_factor_unsupported';
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message')?.message)
      .toBe(t('auth.accountPasskey.twoFactorUnsupported'));
    expect(hasButton(el, t('auth.accountPasskey.checkState'))).toBe(false);
  });

  it('uses native email validity and emits no device-login event for invalid input', async () => {
    const el = await mount('login');
    const email = input(el, 'email');
    const reportValidity = vi.spyOn(email, 'reportValidity');
    const started = vi.fn();
    el.addEventListener('vw-auth-device-login-start', started);
    const deviceLogin = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-device-login]')!;

    email.value = '';
    deviceLogin.click();
    email.value = 'not-an-email';
    deviceLogin.click();

    expect(reportValidity).toHaveBeenCalledTimes(2);
    expect(started).not.toHaveBeenCalled();
  });

  it('renders a settings entry on the login screen only, emitting vw-auth-open-settings', async () => {
    const el = await mount('login');
    const gear = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-open-settings]');
    expect(gear).not.toBeNull();
    const opened = vi.fn();
    el.addEventListener('vw-auth-open-settings', opened);
    gear!.click();
    expect(opened).toHaveBeenCalledTimes(1);

    // Scoped to login: it must not appear on the unlock or register screens.
    for (const mode of ['unlock', 'register'] as const) {
      el.mode = mode;
      await el.updateComplete;
      expect(el.shadowRoot!.querySelector('[data-open-settings]')).toBeNull();
    }
  });

  it('emits vw-auth-go-register when the register link is clicked from login', async () => {
    const el = await mount('login');
    const goRegister = vi.fn();
    el.addEventListener('vw-auth-go-register', goRegister);
    button(el, t('auth.goRegister')).click();
    expect(goRegister).toHaveBeenCalledTimes(1);
  });

  it('emits vw-auth-email-change with the trimmed email on the login email change event', async () => {
    const el = await mount('login');
    const changed = vi.fn();
    el.addEventListener('vw-auth-email-change', changed);
    input(el, 'email').value = '  user@example.com  ';
    input(el, 'email').dispatchEvent(new Event('change'));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { email: 'user@example.com' } }));
  });

  it('shows the forget-device control only when deviceRemembered is true, and emits vw-auth-forget-device', async () => {
    const el = await mount('login');
    expect(hasButton(el, t('auth.forgetDevice'))).toBe(false);
    el.deviceRemembered = true;
    await el.updateComplete;
    const forgotten = vi.fn();
    el.addEventListener('vw-auth-forget-device', forgotten);
    button(el, t('auth.forgetDevice')).click();
    expect(forgotten).toHaveBeenCalledTimes(1);
  });

  it('shows a "no longer remembered" message when deviceForgotten is true', async () => {
    const el = await mount('login');
    el.deviceForgotten = true;
    await el.updateComplete;
    expect(el.shadowRoot!.textContent).toContain('此设备已不再被记住');
  });

  it('renders a danger vw-status-message when error is set, with its icon actually reaching the component', async () => {
    const el = await mount('login');
    el.error = 'Invalid credentials';
    await el.updateComplete;
    const status = el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message');
    expect(status?.getAttribute('tone')).toBe('danger');
    // `icon` is a property-only (attribute: false) prop on vw-status-message, so this only
    // passes if it's bound with `.icon=`, not a plain `icon="..."` attribute.
    await status?.updateComplete;
    expect(status?.shadowRoot?.querySelector('svg')).not.toBeNull();
  });

  it('disables submit controls while pending', async () => {
    const el = await mount('login');
    const started = vi.fn();
    el.addEventListener('vw-auth-device-login-start', started);
    el.pending = true;
    await el.updateComplete;
    expect(input(el, 'email').disabled).toBe(true);
    expect(input(el, 'password').disabled).toBe(true);
    expect(el.shadowRoot!.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(true);
    const deviceLogin = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-device-login]')!;
    expect(deviceLogin.disabled).toBe(true);
    expect(el.shadowRoot!.querySelector<HTMLButtonElement>('[data-password-hint]')?.disabled).toBe(true);
    deviceLogin.click();
    expect(started).not.toHaveBeenCalled();
  });

  // --- register ------------------------------------------------------------------------------

  it('renders the registration start form without password fields and emits trimmed identity data', async () => {
    const el = await mount('register');
    expect(el.shadowRoot?.getElementById('regPassword')).toBeNull();
    expect(el.shadowRoot?.getElementById('regConfirm')).toBeNull();
    input(el, 'regEmail').value = '  new@example.com  ';
    input(el, 'regName').value = '  Ada  ';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-register-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        email: 'new@example.com',
        name: 'Ada',
      },
    }));
  });

  it('omits name from the register submit detail when left blank', async () => {
    const el = await mount('register');
    input(el, 'regEmail').value = 'new@example.com';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-register-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: { email: 'new@example.com' },
    }));
  });

  it('collects the master password only on the bound finish screen', async () => {
    const el = await mount('registrationFinish');
    el.registrationEmail = 'new@example.com';
    await el.updateComplete;
    expect(input(el, 'regPassword').minLength).toBe(DEFAULT_MASTER_PASSWORD_MIN_LENGTH);
    expect(input(el, 'regConfirm').minLength).toBe(DEFAULT_MASTER_PASSWORD_MIN_LENGTH);
    expect(input(el, 'regPasswordHint').maxLength).toBe(50);
    expect(el.shadowRoot?.textContent).toContain('new@example.com');
    input(el, 'regPassword').value = 'correct horse battery staple';
    input(el, 'regConfirm').value = 'correct horse battery staple';
    input(el, 'regPasswordHint').value = 'four words';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-register-finish-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        masterPassword: 'correct horse battery staple',
        confirm: 'correct horse battery staple',
        masterPasswordHint: 'four words',
      },
    }));
  });

  it('shows the email-required state without password inputs and can restart', async () => {
    const el = await mount('registrationCheckEmail');
    el.registrationEmail = 'new@example.com';
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).toContain('new@example.com');
    expect(el.shadowRoot?.querySelector('input')).toBeNull();
    const cancelled = vi.fn();
    el.addEventListener('vw-auth-registration-cancel', cancelled);
    button(el, t('auth.startOver')).click();
    expect(cancelled).toHaveBeenCalledOnce();
  });

  it('emits vw-auth-back-to-login from the register screen', async () => {
    const el = await mount('register');
    const back = vi.fn();
    el.addEventListener('vw-auth-back-to-login', back);
    button(el, t('auth.goLogin')).click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  // --- two-factor ----------------------------------------------------------------------------

  it('lists code, Duo, and validated FIDO2 providers in the two-factor dropdown', async () => {
    const el = await mount('twoFactor');
    el.providers = [0, 1, 2, 3, 6, 7];
    await el.updateComplete;
    const options = Array.from(select(el, 'provider').querySelectorAll('option')).map((o) => o.value);
    expect(options).toEqual(['0', '1', '2', '3', '6']);
  });

  it('launches Duo without presenting it as a manually entered code', async () => {
    const el = await mount('twoFactor');
    el.providers = [2, 6];
    await el.updateComplete;
    const launched = vi.fn<(event: CustomEvent<DuoTwoFactorStartDetail>) => void>();
    el.addEventListener('vw-auth-duo-start', launched as unknown as EventListener);
    (el.shadowRoot!.getElementById('tfRemember') as HTMLInputElement).checked = true;
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-duo-start]')!.click();

    expect(el.shadowRoot!.querySelector('form')).toBeNull();
    expect(el.shadowRoot!.getElementById('code')).toBeNull();
    expect(launched.mock.calls[0]?.[0].detail).toEqual({ provider: 6, remember: true });
  });

  it.each([
    ['supported provider', [0]],
    ['Duo providers', [2, 6]],
  ] as const)('offers the Web Vault recovery action for %s', async (_label, providers) => {
    const el = await mount('twoFactor');
    el.providers = [...providers];
    await el.updateComplete;
    const requested = vi.fn();
    el.addEventListener('vw-auth-two-factor-recovery', requested);

    const recovery = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-two-factor-recovery]');
    expect(recovery?.textContent).toContain(t('auth.twoFactorRecovery'));
    recovery?.click();

    expect(requested).toHaveBeenCalledOnce();
  });

  it('shows unsupported-method messaging and no form when only FIDO2 (7) is offered', async () => {
    const el = await mount('twoFactor');
    el.providers = [7];
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('form')).toBeNull();
    // vw-status-message renders its "message" prop inside its own shadow root, so assert on the
    // attribute we bind rather than walking the outer element's (non-piercing) textContent.
    const status = el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message');
    expect(status?.message).toContain(t('auth.twoFactor.provider.fido2'));
    await status?.updateComplete;
    expect(status?.shadowRoot?.querySelector('svg')).not.toBeNull();
    const back = vi.fn();
    el.addEventListener('vw-auth-back-to-login', back);
    button(el, t('common.back')).click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('renders provider 7 only with a validated owner and never mounts an iframe', async () => {
    const el = await mount('twoFactor');
    await selectFido(el);

    expect(el.shadowRoot!.querySelector('[data-fido2-start]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('iframe')).toBeNull();
    expect(el.shadowRoot!.getElementById('code')).toBeNull();
    expect(el.shadowRoot!.getElementById('tfRemember')).toBeNull();
  });

  it('emits the current provider 7 owner when the fallback button is clicked', async () => {
    const el = await mount('twoFactor');
    await selectFido(el);
    const submitted = vi.fn<(event: CustomEvent<Fido2TwoFactorStartDetail>) => void>();
    el.addEventListener('vw-auth-fido2-start', submitted as unknown as EventListener);

    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-fido2-start]')!.click();
    expect(submitted).toHaveBeenCalledOnce();
    expect(submitted.mock.calls[0]![0].detail).toEqual({ owner: FIDO_OWNER });
  });

  it('switches cleanly between code and fallback providers', async () => {
    const el = await mount('twoFactor');
    await selectFido(el);
    select(el, 'provider').value = '0';
    select(el, 'provider').dispatchEvent(new Event('change'));
    await el.updateComplete;
    expect(el.shadowRoot!.getElementById('code')).not.toBeNull();
    expect(el.shadowRoot!.getElementById('tfRemember')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-fido2-start]')).toBeNull();

    select(el, 'provider').value = '7';
    select(el, 'provider').dispatchEvent(new Event('change'));
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-fido2-start]')).not.toBeNull();
    expect(el.shadowRoot!.getElementById('code')).toBeNull();
  });

  it('shows a stable pending state while the background opens the fallback tab', async () => {
    const el = await mount('twoFactor');
    el.providers = [7];
    el.fido2 = FIDO_CHALLENGE;
    el.pending = true;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-fido2-start]')).toBeNull();
    expect(el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message')?.message)
      .toBe(t('auth.fido2.verifying'));
  });

  it('emits vw-auth-two-factor-submit with provider, code, and remember', async () => {
    const el = await mount('twoFactor');
    el.providers = [0, 1];
    await el.updateComplete;
    select(el, 'provider').value = '1';
    select(el, 'provider').dispatchEvent(new Event('change'));
    input(el, 'code').value = '123456';
    (el.shadowRoot!.getElementById('tfRemember') as HTMLInputElement).checked = true;
    const submitted = vi.fn();
    el.addEventListener('vw-auth-two-factor-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: { provider: 1, code: '123456', remember: true },
    }));
  });

  it('uses official provider priority and retains an explicit choice while it remains available', async () => {
    const el = await mount('twoFactor');
    el.providers = [0, 1, 2, 3, 6, 7];
    el.fido2 = FIDO_CHALLENGE;
    await el.updateComplete;
    expect(select(el, 'provider').value).toBe('6');

    select(el, 'provider').value = '1';
    select(el, 'provider').dispatchEvent(new Event('change'));
    await el.updateComplete;
    el.providers = [0, 1, 3, 6];
    await el.updateComplete;
    expect(select(el, 'provider').value).toBe('1');
  });

  it('auto-sends email once per attempt and exposes an explicit resend only for provider 1', async () => {
    const el = await mount('twoFactor');
    const sent = vi.fn<(event: CustomEvent<EmailTwoFactorCodeRequestDetail>) => void>();
    el.addEventListener('vw-auth-send-email-code', sent as unknown as EventListener);
    el.twoFactorAttemptKey = 'password:4';
    el.providers = [1];
    await el.updateComplete;
    expect(sent.mock.calls[0]?.[0].detail).toEqual({
      provider: 1,
      attemptKey: 'password:4',
      automatic: true,
    });
    expect(hasButton(el, t('auth.twoFactor.resendEmailCode'))).toBe(true);

    el.providers = [1];
    await el.updateComplete;
    expect(sent).toHaveBeenCalledTimes(1);
    button(el, t('auth.twoFactor.resendEmailCode')).click();
    expect(sent.mock.calls[1]?.[0].detail).toEqual({
      provider: 1,
      attemptKey: 'password:4',
      automatic: false,
    });

    el.providers = [0, 1];
    el.selectedProvider = 0;
    await el.updateComplete;
    expect(hasButton(el, t('auth.twoFactor.resendEmailCode'))).toBe(false);
  });

  it('submits only the provider selected after leaving the email method', async () => {
    const el = await mount('twoFactor');
    el.twoFactorAttemptKey = 'password:7';
    el.providers = [0, 1];
    el.selectedProvider = 1;
    await el.updateComplete;
    select(el, 'provider').value = '0';
    select(el, 'provider').dispatchEvent(new Event('change'));
    await el.updateComplete;
    input(el, 'code').value = '654321';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-two-factor-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: { provider: 0, code: '654321', remember: false },
    }));
  });

  it('renders provider copy in English without Chinese fallbacks', async () => {
    setLocale('en', false);
    const el = await mount('twoFactor');
    el.providers = [0, 1, 2, 3, 6];
    await el.updateComplete;
    const text = el.shadowRoot?.textContent ?? '';
    expect(text).toContain('Duo (organization)');
    expect(text).not.toMatch(/[\u3400-\u9fff]/u);
  });

  // --- forced password change ----------------------------------------------------------------

  it('uses the stronger of the shared default and organization minimum', async () => {
    const el = await mount('restricted');
    el.passwordChangeRequirement = {
      schemaVersion: 1,
      reason: 'weakMasterPassword',
      policy: {
        minComplexity: 0,
        minLength: 20,
        requireUpper: false,
        requireLower: false,
        requireNumbers: false,
        requireSpecial: false,
        enforceOnLogin: true,
      },
    };
    await el.updateComplete;
    expect(input(el, 'restrictedNewPassword').minLength).toBe(20);
    expect(input(el, 'restrictedConfirmPassword').minLength).toBe(20);
    input(el, 'restrictedCurrentPassword').value = 'current-password';
    input(el, 'restrictedNewPassword').value = 'a'.repeat(19);
    input(el, 'restrictedConfirmPassword').value = 'a'.repeat(19);
    const submitted = vi.fn<(event: CustomEvent<ForcedPasswordChangeSubmitDetail>) => void>();
    el.addEventListener(
      'vw-auth-forced-password-change',
      submitted as unknown as EventListener,
    );

    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).not.toHaveBeenCalled();

    input(el, 'restrictedNewPassword').value = 'a'.repeat(20);
    input(el, 'restrictedConfirmPassword').value = 'a'.repeat(20);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted.mock.calls[0]![0].detail).toEqual({
      currentPassword: 'current-password',
      newPassword: 'a'.repeat(20),
    });
  });

  it('uses the shared 12-character default when no organization minimum is present', async () => {
    const el = await mount('restricted');
    el.passwordChangeRequirement = {
      schemaVersion: 1,
      reason: 'adminForcePasswordReset',
    };
    await el.updateComplete;

    expect(input(el, 'restrictedNewPassword').minLength)
      .toBe(DEFAULT_MASTER_PASSWORD_MIN_LENGTH);
  });

  // --- unlock (locked screen) ----------------------------------------------------------------

  it('renders the unlock form and emits vw-auth-unlock-submit with the password', async () => {
    const el = await mount('unlock');
    input(el, 'unlockPassword').value = 'my-master-password';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-unlock-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { masterPassword: 'my-master-password' } }));
  });

  it('emits vw-auth-logout when the log-out control is clicked on the unlock screen', async () => {
    const el = await mount('unlock');
    const loggedOut = vi.fn();
    el.addEventListener('vw-auth-logout', loggedOut);
    button(el, t('auth.logout')).click();
    expect(loggedOut).toHaveBeenCalledTimes(1);
  });

  it('only shows the PIN field when pinEnabled is true, and preserves every PIN character', async () => {
    const el = await mount('unlock');
    expect(el.shadowRoot!.getElementById('pinUnlockInput')).toBeNull();
    el.pinEnabled = true;
    await el.updateComplete;
    input(el, 'pinUnlockInput').value = ' 4321 ';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-pin-unlock-submit', submitted);
    (el.shadowRoot!.querySelector('.pin-btn') as HTMLButtonElement).click();
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { pin: ' 4321 ' } }));
  });

  it('submits the PIN when Enter is pressed in the PIN field', async () => {
    const el = await mount('unlock');
    el.pinEnabled = true;
    await el.updateComplete;
    input(el, 'pinUnlockInput').value = '1234';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-pin-unlock-submit', submitted);
    input(el, 'pinUnlockInput').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { pin: '1234' } }));
  });

  it('does not emit vw-auth-pin-unlock-submit for a blank PIN', async () => {
    const el = await mount('unlock');
    el.pinEnabled = true;
    await el.updateComplete;
    input(el, 'pinUnlockInput').value = '   ';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-pin-unlock-submit', submitted);
    (el.shadowRoot!.querySelector('.pin-btn') as HTMLButtonElement).click();
    expect(submitted).not.toHaveBeenCalled();
  });

  it('does not submit an oversized PIN even when the DOM value is assigned programmatically', async () => {
    const el = await mount('unlock');
    el.pinEnabled = true;
    await el.updateComplete;
    const pin = input(el, 'pinUnlockInput');
    expect(pin.maxLength).toBe(MAX_PIN_UTF16_CODE_UNITS);
    pin.value = 'a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1);
    const submitted = vi.fn();
    el.addEventListener('vw-auth-pin-unlock-submit', submitted);

    (el.shadowRoot!.querySelector('.pin-btn') as HTMLButtonElement).click();

    expect(submitted).not.toHaveBeenCalled();
  });
});
