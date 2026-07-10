// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './auth-views.js';
import type { VwAuthViews } from './auth-views.js';
import type { VwStatusMessage } from '../../components/status-message.js';

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

function button(el: VwAuthViews, text: string): HTMLButtonElement {
  const buttons = Array.from(el.shadowRoot?.querySelectorAll('button') ?? []);
  const found = buttons.find((b) => b.textContent?.includes(text));
  if (!found) throw new Error(`missing button with text "${text}"`);
  return found;
}

describe('vw-auth-views', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('never imports or calls sendRequest', async () => {
    // The module graph for this component must stay network-free; importing it must not touch
    // webextension-polyfill (unmocked here) or throw.
    await mount('login');
  });

  it('renders the login form and emits vw-auth-login-submit with email + password', async () => {
    const el = await mount('login');
    input(el, 'email').value = 'user@example.com';
    input(el, 'password').value = 'hunter2';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-login-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: { email: 'user@example.com', masterPassword: 'hunter2' },
    }));
  });

  it('emits vw-auth-go-register when "Create account" is clicked from login', async () => {
    const el = await mount('login');
    const goRegister = vi.fn();
    el.addEventListener('vw-auth-go-register', goRegister);
    button(el, 'Create account').click();
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

  it('shows the forget-device link only when deviceRemembered is true, and emits vw-auth-forget-device', async () => {
    const el = await mount('login');
    expect(el.shadowRoot!.querySelector('.link-button')).toBeNull();
    el.deviceRemembered = true;
    await el.updateComplete;
    const forgotten = vi.fn();
    el.addEventListener('vw-auth-forget-device', forgotten);
    (el.shadowRoot!.querySelector('.link-button') as HTMLButtonElement).click();
    expect(forgotten).toHaveBeenCalledTimes(1);
  });

  it('shows a "no longer remembered" message when deviceForgotten is true', async () => {
    const el = await mount('login');
    el.deviceForgotten = true;
    await el.updateComplete;
    expect(el.shadowRoot!.textContent).toContain('no longer remembered');
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
    el.pending = true;
    await el.updateComplete;
    expect(input(el, 'email').disabled).toBe(true);
    expect(input(el, 'password').disabled).toBe(true);
  });

  it('renders the register form and emits vw-auth-register-submit with trimmed email/name and confirm', async () => {
    const el = await mount('register');
    input(el, 'regEmail').value = '  new@example.com  ';
    input(el, 'regName').value = '  Ada  ';
    input(el, 'regPassword').value = 'correct horse battery staple';
    input(el, 'regConfirm').value = 'correct horse battery staple';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-register-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        email: 'new@example.com',
        name: 'Ada',
        masterPassword: 'correct horse battery staple',
        confirm: 'correct horse battery staple',
      },
    }));
  });

  it('omits name from the register submit detail when left blank', async () => {
    const el = await mount('register');
    input(el, 'regEmail').value = 'new@example.com';
    input(el, 'regPassword').value = 'correct horse battery staple';
    input(el, 'regConfirm').value = 'correct horse battery staple';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-register-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({
      detail: { email: 'new@example.com', masterPassword: 'correct horse battery staple', confirm: 'correct horse battery staple' },
    }));
  });

  it('emits vw-auth-back-to-login from the register screen', async () => {
    const el = await mount('register');
    const back = vi.fn();
    el.addEventListener('vw-auth-back-to-login', back);
    button(el, 'Back to sign in').click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('lists only the code-based providers in the two-factor dropdown', async () => {
    const el = await mount('twoFactor');
    el.providers = [0, 1, 2, 3, 6, 7];
    await el.updateComplete;
    const options = Array.from(select(el, 'provider').querySelectorAll('option')).map((o) => o.value);
    expect(options).toEqual(['0', '1', '2', '3', '6']);
  });

  it('shows unsupported-method messaging and no form when only FIDO2 (7) is offered', async () => {
    const el = await mount('twoFactor');
    el.providers = [7];
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('form')).toBeNull();
    // vw-status-message renders its "message" prop inside its own shadow root, so assert on the
    // attribute we bind rather than walking the outer element's (non-piercing) textContent.
    const status = el.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message');
    expect(status?.getAttribute('message')).toContain('Security key (FIDO2)');
    await status?.updateComplete;
    expect(status?.shadowRoot?.querySelector('svg')).not.toBeNull();
    const back = vi.fn();
    el.addEventListener('vw-auth-back-to-login', back);
    button(el, 'Back to login').click();
    expect(back).toHaveBeenCalledTimes(1);
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

  it('only renders "Send email code" when provider 1 is offered, and it emits vw-auth-send-email-code', async () => {
    const el = await mount('twoFactor');
    el.providers = [0];
    await el.updateComplete;
    expect(el.shadowRoot!.textContent).not.toContain('Send email code');
    el.providers = [0, 1];
    await el.updateComplete;
    const sent = vi.fn();
    el.addEventListener('vw-auth-send-email-code', sent);
    button(el, 'Send email code').click();
    expect(sent).toHaveBeenCalledTimes(1);
  });

  it('renders the unlock form and emits vw-auth-unlock-submit with the password', async () => {
    const el = await mount('unlock');
    input(el, 'unlockPassword').value = 'my-master-password';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-unlock-submit', submitted);
    el.shadowRoot!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { masterPassword: 'my-master-password' } }));
  });

  it('emits vw-auth-logout when "Log out" is clicked on the unlock screen', async () => {
    const el = await mount('unlock');
    const loggedOut = vi.fn();
    el.addEventListener('vw-auth-logout', loggedOut);
    button(el, 'Log out').click();
    expect(loggedOut).toHaveBeenCalledTimes(1);
  });

  it('only shows the PIN field when pinEnabled is true, and emits vw-auth-pin-unlock-submit with a trimmed pin', async () => {
    const el = await mount('unlock');
    expect(el.shadowRoot!.getElementById('pinUnlockInput')).toBeNull();
    el.pinEnabled = true;
    await el.updateComplete;
    input(el, 'pinUnlockInput').value = ' 4321 ';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-pin-unlock-submit', submitted);
    button(el, 'Unlock with PIN').click();
    expect(submitted).toHaveBeenCalledWith(expect.objectContaining({ detail: { pin: '4321' } }));
  });

  it('does not emit vw-auth-pin-unlock-submit for a blank PIN', async () => {
    const el = await mount('unlock');
    el.pinEnabled = true;
    await el.updateComplete;
    input(el, 'pinUnlockInput').value = '   ';
    const submitted = vi.fn();
    el.addEventListener('vw-auth-pin-unlock-submit', submitted);
    button(el, 'Unlock with PIN').click();
    expect(submitted).not.toHaveBeenCalled();
  });
});
