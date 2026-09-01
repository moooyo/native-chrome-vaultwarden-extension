// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  detectLoginForms,
  isFillableInput,
  isNewPasswordField,
  isTotpCandidate,
  resolveTotpInputs,
} from './form-detection.js';

function rect(overrides: Partial<DOMRect> = {}): DOMRect {
  return {
    x: 10,
    y: 10,
    top: 10,
    right: 210,
    bottom: 42,
    left: 10,
    width: 200,
    height: 32,
    toJSON: () => ({}),
    ...overrides,
  } as DOMRect;
}

describe('form detection', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('detects a visible login form with username and password fields', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username" value="">
        <input type="password" autocomplete="current-password" value="">
      </form>
    `;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.type).toBe('email');
    expect(forms[0]?.passwordInput?.type).toBe('password');
  });

  it('uses clipped accessibility labels for login and new-password semantics', () => {
    const screenReaderOnly = 'position:absolute;clip:rect(0 0 0 0);width:1px;height:1px;overflow:hidden';
    document.body.innerHTML = `
      <form id="login">
        <label for="field-a" style="${screenReaderOnly}">Email address</label>
        <input id="field-a" type="text">
        <input id="field-b" type="password">
      </form>
      <form id="registration">
        <label for="field-c" style="${screenReaderOnly}">New password</label>
        <input id="field-c" type="password">
      </form>`;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput).toBe(document.getElementById('field-a'));
    expect(forms[0]?.passwordInput).toBe(document.getElementById('field-b'));
  });

  it('uses an unhinted text field immediately before a password in the same native form', () => {
    document.body.innerHTML = '<form><input type="text"><input type="password"></form>';
    const [identifier] = Array.from(document.querySelectorAll<HTMLInputElement>('input'));

    expect(detectLoginForms()[0]?.usernameInput).toBe(identifier);
  });

  it('prefers a strong username hint over a nearer generic fallback', () => {
    document.body.innerHTML = `
      <form>
        <input id="hinted" name="login_identifier" type="text">
        <input id="generic" type="text">
        <input type="password">
      </form>`;

    expect(detectLoginForms()[0]?.usernameInput?.id).toBe('hinted');
  });

  it('uses an explicitly associated label as a username hint', () => {
    document.body.innerHTML = `
      <form>
        <label for="account">Account email</label>
        <input id="account" type="text">
        <input type="password">
      </form>`;

    expect(detectLoginForms()[0]?.usernameInput?.id).toBe('account');
  });

  it('uses root-local aria-labelledby text inside a shadow form', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form>
        <span id="account-label">Username</span>
        <input id="account" aria-labelledby="account-label">
        <input type="password">
      </form>`;
    document.body.append(host);

    expect(detectLoginForms(shadow)[0]?.usernameInput).toBe(shadow.getElementById('account'));
  });

  it('never selects a hinted card field as the login username', () => {
    document.body.innerHTML = `
      <form>
        <input id="cardholder" name="username" autocomplete="cc-name">
        <input id="password" type="password" autocomplete="current-password">
      </form>`;

    expect(detectLoginForms()[0]?.usernameInput).toBeUndefined();
  });

  it('keeps a label-only card field excluded from username fallback', () => {
    document.body.innerHTML = `
      <form>
        <label for="number">Card number</label>
        <input id="number">
        <input type="password">
      </form>`;

    expect(detectLoginForms()[0]?.usernameInput).toBeUndefined();
  });

  it('does not emit passwordless card or one-time-code fields as username steps', () => {
    document.body.innerHTML = `
      <form><label>Card number <input name="username"></label></form>
      <form>
        <input id="otp" name="username" autocomplete="one-time-code">
        <button>Verify</button>
      </form>`;

    const forms = detectLoginForms();
    expect(forms.some((form) => form.usernameInput !== undefined)).toBe(false);
    expect(forms.find((form) => form.totpInput?.id === 'otp')?.usernameInput).toBeUndefined();
  });

  it('uses the nearest safe unhinted identifier before the password', () => {
    document.body.innerHTML = `
      <form>
        <input id="first" type="text">
        <input id="nearest" type="tel">
        <input type="password">
      </form>`;

    expect(detectLoginForms()[0]?.usernameInput?.id).toBe('nearest');
  });

  it('does not treat explicit search fields as native-form username fallbacks', () => {
    document.body.innerHTML = `
      <form>
        <input id="identifier" type="text">
        <input id="native-search" type="search">
        <input id="query" name="siteQuery" type="text">
        <input type="password">
      </form>`;

    expect(detectLoginForms()[0]?.usernameInput?.id).toBe('identifier');
  });

  it('does not use fields from another native form as username fallbacks', () => {
    document.body.innerHTML = `
      <form id="other"><input id="other-field" type="text"></form>
      <form id="login"><input id="password" type="password"></form>`;
    const password = document.getElementById('password') as HTMLInputElement;
    const login = detectLoginForms().find((form) => form.passwordInput === password);

    expect(login?.usernameInput).toBeUndefined();
  });

  it('does not use an unhinted field from another composed root as a username fallback', () => {
    document.body.innerHTML = '<input type="text">';
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input type="password"></form>';
    document.body.append(host);

    expect(detectLoginForms(shadow)[0]?.usernameInput).toBeUndefined();
  });

  it('does not use a username candidate after the password', () => {
    document.body.innerHTML = `
      <form><input id="password" type="password"><input name="username" type="text"></form>`;
    const password = document.getElementById('password') as HTMLInputElement;
    const login = detectLoginForms().find((form) => form.passwordInput === password);

    expect(login?.usernameInput).toBeUndefined();
  });

  it('does not use hidden, disabled, readonly, or ignored username fallbacks', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" hidden>
        <input type="text" disabled>
        <input type="text" readonly>
        <input type="text" data-bwignore>
        <input id="password" type="password">
      </form>`;
    const password = document.getElementById('password') as HTMLInputElement;
    const login = detectLoginForms().find((form) => form.passwordInput === password);

    expect(login?.usernameInput).toBeUndefined();
  });

  it('keeps unhinted username fallback disabled for formless password scopes', () => {
    document.body.innerHTML = `
      <section><input type="text"><input id="password" type="password"></section>`;
    const password = document.getElementById('password') as HTMLInputElement;
    const login = detectLoginForms().find((form) => form.passwordInput === password);

    expect(login?.usernameInput).toBeUndefined();
  });

  it('ignores hidden, disabled, and readonly password fields', () => {
    document.body.innerHTML = `
      <input type="password" hidden>
      <input type="password" disabled>
      <input type="password" readonly>
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('uses a nearby username field when inputs are not inside a form element', () => {
    document.body.innerHTML = `
      <section>
        <input type="text" name="user">
        <div><input type="password" name="pass"></div>
      </section>
    `;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.name).toBe('user');
  });

  it('checks fillable input state directly', () => {
    const input = document.createElement('input');
    input.type = 'password';
    expect(isFillableInput(input)).toBe(false);
    document.body.appendChild(input);
    expect(isFillableInput(input)).toBe(true);
    input.readOnly = true;
    expect(isFillableInput(input)).toBe(false);
  });

  it('ignores inputs hidden by CSS display:none', () => {
    document.body.innerHTML = `
      <input type="password" style="display:none">
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('ignores inputs hidden by a CSS-hidden ancestor', () => {
    document.body.innerHTML = `
      <form style="display:none">
        <input type="email">
        <input type="password">
      </form>
    `;

    expect(detectLoginForms()).toEqual([]);
  });

  it('does not treat masked card-code or OTP controls as login passwords', () => {
    document.body.innerHTML = `
      <form><label>Card CVC <input type="password" name="cvv"></label></form>
      <form><label>Authenticator code <input type="password" name="otp"></label></form>`;

    expect(detectLoginForms()).toEqual([]);
  });

  it('ignores login and TOTP controls carrying data-bwignore', () => {
    document.body.innerHTML = `
      <form>
        <input name="username" data-bwignore="false">
        <input type="password" data-bwignore>
        <input autocomplete="one-time-code" data-bwignore>
        <button>Verify</button>
      </form>`;

    expect(detectLoginForms()).toEqual([]);
  });

  it('honors data-bwignore inside an open shadow root', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form>
        <input name="username" data-bwignore>
        <input type="password" data-bwignore>
      </form>`;
    document.body.append(host);

    expect(detectLoginForms(shadow)).toEqual([]);
  });

  it('continues visibility checks through open shadow hosts', () => {
    const host = document.createElement('div');
    host.style.display = 'none';
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input type="email"><input type="password"></form>';
    document.body.append(host);

    expect(detectLoginForms(shadow)).toEqual([]);
  });

  it('rejects controls under inert and aria-hidden shadow hosts', () => {
    for (const attribute of ['inert', 'aria-hidden']) {
      const host = document.createElement('div');
      host.setAttribute(attribute, attribute === 'aria-hidden' ? 'true' : '');
      const shadow = host.attachShadow({ mode: 'open' });
      shadow.innerHTML = '<form><input type="password"></form>';
      document.body.append(host);
      expect(detectLoginForms(shadow)).toEqual([]);
      host.remove();
    }
  });

  it('follows assigned slots when checking composed visibility', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<div style="display:none"><slot></slot></div>';
    const slot = shadow.querySelector<HTMLSlotElement>('slot')!;
    const input = document.createElement('input');
    input.type = 'password';
    host.append(input);
    document.body.append(host);
    // happy-dom does not currently populate assignedSlot during slot distribution.
    Object.defineProperty(input, 'assignedSlot', { configurable: true, value: slot });
    expect(isFillableInput(input)).toBe(false);
  });

  it('keeps a style-only fallback in DOM implementations without layout', () => {
    const input = document.createElement('input');
    document.body.append(input);

    expect(input.getBoundingClientRect()).toMatchObject({ width: 0, height: 0 });
    expect(isFillableInput(input)).toBe(true);
  });

  it('rejects low-opacity, collapsed, clipped, and zero-scale fields', () => {
    for (const style of [
      'opacity:0.05',
      'visibility:collapse',
      'clip-path:inset(50%)',
      'position:absolute;clip:rect(0px, 0px, 0px, 0px)',
      'transform:scale(0)',
    ]) {
      document.body.innerHTML = `<input style="${style}">`;
      expect(isFillableInput(document.querySelector('input')!)).toBe(false);
    }
  });

  it('rejects undersized screen-reader-only and offscreen honeypot fields', () => {
    document.body.innerHTML = '<input id="sr"><input id="honeypot">';
    const screenReaderOnly = document.getElementById('sr') as HTMLInputElement;
    const honeypot = document.getElementById('honeypot') as HTMLInputElement;
    vi.spyOn(screenReaderOnly, 'getBoundingClientRect').mockReturnValue(rect({
      right: 11,
      bottom: 11,
      width: 1,
      height: 1,
    }));
    vi.spyOn(honeypot, 'getBoundingClientRect').mockReturnValue(rect({
      x: -10_000,
      left: -10_000,
      right: -9_800,
    }));

    expect(isFillableInput(screenReaderOnly)).toBe(false);
    expect(isFillableInput(honeypot)).toBe(false);
  });

  it('rejects a field covered at its center point', () => {
    document.body.innerHTML = '<input id="target"><div id="cover"></div>';
    const target = document.getElementById('target') as HTMLInputElement;
    const cover = document.getElementById('cover')!;
    vi.spyOn(target, 'getBoundingClientRect').mockReturnValue(rect());
    vi.spyOn(document, 'elementFromPoint').mockReturnValue(cover);

    expect(isFillableInput(target)).toBe(false);
  });

  it('accepts center hits on the field or its label but rejects an ordinary wrapper', () => {
    document.body.innerHTML = `
      <form id="owner">
        <label for="target"><span id="label-text">Account</span></label>
        <input id="target">
      </form>`;
    const target = document.getElementById('target') as HTMLInputElement;
    const hit = vi.spyOn(document, 'elementFromPoint');
    vi.spyOn(target, 'getBoundingClientRect').mockReturnValue(rect());

    for (const element of [
      target,
      document.querySelector('label')!,
      document.getElementById('label-text')!,
    ]) {
      hit.mockReturnValue(element);
      expect(isFillableInput(target)).toBe(true);
    }

    target.style.pointerEvents = 'none';
    hit.mockReturnValue(document.getElementById('owner'));
    expect(isFillableInput(target)).toBe(false);
  });

  it('uses an open shadow root for center-point occlusion checks', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<input id="target"><div id="cover"></div>';
    document.body.append(host);
    const target = shadow.getElementById('target') as HTMLInputElement;
    const cover = shadow.getElementById('cover')!;
    const elementFromPoint = vi.fn<(x: number, y: number) => Element | null>();
    Object.defineProperty(shadow, 'elementFromPoint', {
      configurable: true,
      value: elementFromPoint,
    });
    vi.spyOn(target, 'getBoundingClientRect').mockReturnValue(rect());

    elementFromPoint.mockReturnValue(cover);
    expect(isFillableInput(target)).toBe(false);
    elementFromPoint.mockReturnValue(target);
    expect(isFillableInput(target)).toBe(true);
    expect(elementFromPoint).toHaveBeenCalledWith(110, 26);
  });

  it('does not pair formless login fields from different composed slot owners', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<section><slot name="username"></slot><slot name="password"></slot></section>';
    const username = document.createElement('input');
    username.name = 'username';
    const password = document.createElement('input');
    password.type = 'password';
    Object.defineProperty(username, 'assignedSlot', {
      configurable: true,
      value: shadow.querySelector<HTMLSlotElement>('slot[name=username]')!,
    });
    Object.defineProperty(password, 'assignedSlot', {
      configurable: true,
      value: shadow.querySelector<HTMLSlotElement>('slot[name=password]')!,
    });
    host.append(username, password);
    document.body.append(host);

    const passwordForm = detectLoginForms().find((form) => form.passwordInput === password);
    expect(passwordForm?.usernameInput).toBeUndefined();
    expect(detectLoginForms().some((form) => (
      form.usernameInput === username && form.passwordInput === password
    ))).toBe(false);
  });

  it('uses external form=id controls but never borrows a username from another root', () => {
    document.body.innerHTML = `
      <input id="external" type="email" form="login">
      <form id="login"><input type="password"></form>`;
    const external = document.getElementById('external') as HTMLInputElement;
    expect(detectLoginForms(document)[0]?.usernameInput).toBe(external);

    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input type="password"></form>';
    document.body.append(host);
    const shadowLogin = detectLoginForms(shadow)[0];
    expect(shadowLogin?.usernameInput).toBeUndefined();
  });

  it('ignores inputs hidden by visibility:hidden even when they have layout', () => {
    document.body.innerHTML = `
      <form style="visibility:hidden">
        <input type="email">
        <input type="password">
      </form>
    `;
    for (const input of document.querySelectorAll('input')) {
      Object.defineProperty(input, 'offsetParent', { configurable: true, value: document.body });
    }

    expect(detectLoginForms()).toEqual([]);
  });

  it('detects a username-first login step that has no password field yet', () => {
    document.body.innerHTML = `
      <form><input type="email" autocomplete="username"><button>Next</button></form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.usernameInput?.type).toBe('email');
    expect(forms[0]?.passwordInput).toBeUndefined();
  });

  it('does not treat a lone non-login text field as a login step', () => {
    document.body.innerHTML = `<div><input type="search" name="q"></div>`;
    expect(detectLoginForms()).toEqual([]);
  });

  it('does not treat contenteditable or a custom form-associated surface as an input', () => {
    document.body.innerHTML = `
      <div contenteditable="true" autocomplete="current-password">secret</div>
      <password-field name="password"></password-field>`;
    expect(detectLoginForms()).toEqual([]);
  });

  it('requires a submit affordance for a non-form username-only step', () => {
    document.body.innerHTML = `<section><input type="text" name="username"></section>`;
    expect(detectLoginForms()).toEqual([]);

    document.body.innerHTML = `<section><input type="text" name="username"><button>Continue</button></section>`;
    expect(detectLoginForms()).toHaveLength(1);
  });

  it('collapses a change-password form to one form whose passwordInput is the current password', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" autocomplete="current-password" id="cur">
        <input type="password" autocomplete="new-password" id="new">
        <input type="password" autocomplete="new-password" id="confirm">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.id).toBe('cur');
  });

  it('recognizes a section-prefixed current-password token as authoritative', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" id="unhinted">
        <input type="password" autocomplete="section-account current-password" id="cur">
      </form>`;

    const forms = detectLoginForms();

    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.id).toBe('cur');
  });

  it('keeps current-password authoritative over contradictory new-password text', () => {
    document.body.innerHTML = `
      <form><input id="current" type="password" autocomplete="current-password" name="newPassword"></form>`;
    const current = document.getElementById('current') as HTMLInputElement;

    expect(isNewPasswordField(current)).toBe(false);
    expect(detectLoginForms()[0]?.passwordInput).toBe(current);
  });

  it('identifies the current password by name hints when autocomplete is absent', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="oldPassword">
        <input type="password" name="newPassword">
        <input type="password" name="confirmPassword">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.getAttribute('name')).toBe('oldPassword');
  });

  it('still detects an ordinary single-password login with a defined passwordInput', () => {
    document.body.innerHTML = `
      <form><input type="email" autocomplete="username"><input type="password" autocomplete="current-password"></form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.type).toBe('password');
    expect(forms[0]?.usernameInput?.type).toBe('email');
  });

  it('emits no fillable password form when every password field is a new-password field (sign-up)', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username">
        <input type="password" autocomplete="new-password" id="pw">
        <input type="password" autocomplete="new-password" id="confirm">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms.some((f) => f.passwordInput)).toBe(false);
  });

  it('emits no password form for a single new-password reset field', () => {
    document.body.innerHTML = `<form><input type="password" autocomplete="new-password" name="newPassword"></form>`;
    expect(detectLoginForms()).toEqual([]);
  });

  it('does not select a new-password field as current when current-password is also present', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="newPassword">
        <input type="password" autocomplete="current-password" id="cur">
        <input type="password" name="confirmPassword">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.id).toBe('cur');
  });

  it('emits one form per password for formless multi-login blocks sharing an ancestor', () => {
    document.body.innerHTML = `<main>
      <div><input type="text" name="user1"><input type="password" name="pass1"></div>
      <div><input type="text" name="user2"><input type="password" name="pass2"></div>
    </main>`;
    const forms = detectLoginForms();
    expect(forms.map((f) => f.passwordInput?.getAttribute('name')).sort()).toEqual(['pass1', 'pass2']);
  });

  it('attaches a one-time-code field within a login form as totpInput', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username">
        <input type="password" autocomplete="current-password">
        <input type="text" autocomplete="one-time-code" name="otp">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.passwordInput?.type).toBe('password');
    expect(forms[0]?.totpInput?.getAttribute('name')).toBe('otp');
  });

  it('matches a TOTP field by name hint when autocomplete is absent', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username">
        <input type="password" autocomplete="current-password">
        <input type="tel" name="verificationCode">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.totpInput?.getAttribute('name')).toBe('verificationCode');
  });

  it('matches a TOTP field through a wrapping label', () => {
    document.body.innerHTML = `
      <form>
        <label>Authenticator code <input id="otp" type="text"></label>
        <button>Verify</button>
      </form>`;

    expect(detectLoginForms()[0]?.totpInput?.id).toBe('otp');
  });

  it('does not borrow unassociated neighboring text as a TOTP hint', () => {
    document.body.innerHTML = `
      <form>
        <span>One-time code</span>
        <input id="ordinary" type="text">
        <button>Verify</button>
      </form>`;

    expect(detectLoginForms()).toEqual([]);
  });

  it('fails closed for conflicting semantic OTP and card-code labels', () => {
    document.body.innerHTML = `
      <form>
        <label for="code">One-time code</label>
        <label for="code">Card CVC</label>
        <input id="code" type="text">
        <button>Verify</button>
      </form>`;
    const code = document.getElementById('code') as HTMLInputElement;

    expect(isTotpCandidate(code)).toBe(false);
    expect(detectLoginForms()).toEqual([]);
  });

  it('rejects strong standalone card-code semantics even when another hint says OTP', () => {
    document.body.innerHTML = `
      <form>
        <label for="code">Card CVC</label>
        <input id="code" name="otp">
        <button>Verify</button>
      </form>
      <form>
        <input id="value" name="securityCode" aria-label="Card verification value">
        <button>Verify</button>
      </form>`;

    expect(isTotpCandidate(document.getElementById('code') as HTMLInputElement)).toBe(false);
    expect(isTotpCandidate(document.getElementById('value') as HTMLInputElement)).toBe(false);
    expect(detectLoginForms()).toEqual([]);
  });

  it('detects a standalone verification-code step with no username or password', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" inputmode="numeric" autocomplete="one-time-code" name="totp">
        <button>Verify</button>
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.totpInput?.getAttribute('name')).toBe('totp');
    expect(forms[0]?.passwordInput).toBeUndefined();
    expect(forms[0]?.usernameInput).toBeUndefined();
  });

  it('keeps a standalone textual security-code field as TOTP', () => {
    document.body.innerHTML = `
      <form><input id="security" name="securityCode"><button>Verify</button></form>`;
    const securityCode = document.getElementById('security') as HTMLInputElement;

    expect(isTotpCandidate(securityCode)).toBe(true);
    expect(detectLoginForms()[0]?.totpInput).toBe(securityCode);
  });

  it('does not treat a textual card security code beside a card number as TOTP', () => {
    document.body.innerHTML = `
      <form>
        <input id="number" name="cardNumber">
        <input id="security" name="securityCode">
        <button>Pay</button>
      </form>`;
    const securityCode = document.getElementById('security') as HTMLInputElement;

    expect(isTotpCandidate(securityCode)).toBe(false);
    expect(detectLoginForms().some((form) => form.totpInput === securityCode)).toBe(false);
  });

  it('keeps a generic security code out of TOTP when card-number context is unsafe', () => {
    document.body.innerHTML = `
      <form>
        <input name="cardNumber" aria-labelledby="missing-card-label" readonly>
        <input id="security" name="securityCode">
        <button>Pay</button>
      </form>`;

    expect(isTotpCandidate(document.getElementById('security') as HTMLInputElement)).toBe(false);
  });

  it('uses a readonly card number as context but ignores a CSS-hidden card-number decoy', () => {
    document.body.innerHTML = `
      <form>
        <input name="cardNumber" readonly>
        <input id="card-security" name="securityCode">
      </form>
      <form>
        <input name="cardNumber" style="display:none">
        <input id="standalone-security" name="securityCode">
        <button>Verify</button>
      </form>`;

    expect(isTotpCandidate(document.getElementById('card-security') as HTMLInputElement)).toBe(false);
    expect(isTotpCandidate(document.getElementById('standalone-security') as HTMLInputElement)).toBe(true);
  });

  it('keeps explicit one-time-code and cc-csc autocomplete tokens authoritative', () => {
    document.body.innerHTML = `
      <form>
        <input name="cardNumber">
        <input id="otp" name="securityCode" autocomplete="one-time-code">
      </form>
      <form><input id="cvc" name="securityCode" autocomplete="cc-csc"></form>`;

    expect(isTotpCandidate(document.getElementById('otp') as HTMLInputElement)).toBe(true);
    expect(isTotpCandidate(document.getElementById('cvc') as HTMLInputElement)).toBe(false);
  });

  it('retains a safe split-code group in stable DOM order', () => {
    document.body.innerHTML = `
      <form>
        <div id="otp-group">
          <input id="digit-1" autocomplete="one-time-code" inputmode="numeric" maxlength="1">
          <input id="digit-2" inputmode="numeric" maxlength="1">
          <input id="digit-3" inputmode="numeric" maxlength="1">
          <input id="digit-4" inputmode="numeric" maxlength="1">
          <input id="digit-5" inputmode="numeric" maxlength="1">
          <input id="digit-6" inputmode="numeric" maxlength="1">
        </div>
        <button>Verify</button>
      </form>`;

    const form = detectLoginForms()[0]!;
    expect(form.totpInput?.id).toBe('digit-1');
    expect(form.totpInputs?.map((input) => input.id)).toEqual([
      'digit-1', 'digit-2', 'digit-3', 'digit-4', 'digit-5', 'digit-6',
    ]);
    expect(resolveTotpInputs(document.getElementById('digit-4') as HTMLInputElement))
      .toEqual(form.totpInputs);
  });

  it('does not combine split-code inputs across native forms', () => {
    document.body.innerHTML = `
      <form id="first"><button>Verify first</button></form>
      <form id="second"><button>Verify second</button></form>
      <div>
        <input id="first-digit" form="first" autocomplete="one-time-code" maxlength="1">
        <input id="second-digit" form="second" autocomplete="one-time-code" maxlength="1">
      </div>`;

    expect(resolveTotpInputs(document.getElementById('first-digit') as HTMLInputElement)?.map((input) => input.id))
      .toEqual(['first-digit']);
    expect(resolveTotpInputs(document.getElementById('second-digit') as HTMLInputElement)?.map((input) => input.id))
      .toEqual(['second-digit']);
  });

  it('fails closed when a split-code cluster contains a hidden or readonly member', () => {
    document.body.innerHTML = `
      <form>
        <div>
          <input id="digit-1" autocomplete="one-time-code" maxlength="1">
          <input id="digit-2" maxlength="1" hidden>
          <input id="digit-3" maxlength="1" readonly>
        </div>
        <button>Verify</button>
      </form>`;

    expect(resolveTotpInputs(document.getElementById('digit-1') as HTMLInputElement)).toBeUndefined();
    expect(detectLoginForms()[0]?.totpInputs).toEqual([]);
  });

  it('does not group light-DOM OTP boxes assigned to different slots', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<section><slot name="first"></slot><slot name="second"></slot></section>';
    const firstSlot = shadow.querySelector<HTMLSlotElement>('slot[name=first]')!;
    const secondSlot = shadow.querySelector<HTMLSlotElement>('slot[name=second]')!;
    const inputs = Array.from({ length: 6 }, (_, index) => {
      const input = document.createElement('input');
      input.maxLength = 1;
      if (index === 0) input.autocomplete = 'one-time-code';
      Object.defineProperty(input, 'assignedSlot', {
        configurable: true,
        value: index < 3 ? firstSlot : secondSlot,
      });
      host.append(input);
      return input;
    });
    document.body.append(host);

    expect(resolveTotpInputs(inputs[0]!)).toBeUndefined();
  });

  it('never treats contenteditable or custom OTP surfaces as split-code inputs', () => {
    document.body.innerHTML = `
      <form>
        <div contenteditable="true" autocomplete="one-time-code">1</div>
        <otp-input autocomplete="one-time-code"></otp-input>
        <button>Verify</button>
      </form>`;

    expect(detectLoginForms()).toEqual([]);
  });

  it('does not treat an ordinary text field as a TOTP field', () => {
    document.body.innerHTML = `
      <form>
        <input type="email" autocomplete="username">
        <input type="password" autocomplete="current-password">
        <input type="text" name="fullname">
      </form>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.totpInput).toBeUndefined();
  });

  it('does not also emit a username-only step for a standalone OTP field', () => {
    document.body.innerHTML = `
      <section><input type="text" name="otp" autocomplete="one-time-code"><button>Verify</button></section>
    `;
    const forms = detectLoginForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.totpInput?.getAttribute('name')).toBe('otp');
  });
});
