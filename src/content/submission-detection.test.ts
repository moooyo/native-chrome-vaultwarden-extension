// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import {
  detectFormlessSubmission,
  detectFormlessUsernameSubmission,
  detectNativeFormSubmission,
  detectNativeUsernameSubmission,
} from './submission-detection.js';

afterEach(() => document.body.replaceChildren());

describe('native form submission detection', () => {
  it('captures an explicit username-only first step but not a single-page login', () => {
    const firstStep = renderForm(`
      <input type="email" autocomplete="username" value="alice@example.com">
      <button type="submit">Continue</button>
    `);
    expect(detectNativeUsernameSubmission(firstStep)).toEqual({ username: 'alice@example.com' });

    const singlePage = renderForm(`
      <input type="email" autocomplete="username" value="alice@example.com">
      <input type="password" value="">
    `);
    expect(detectNativeUsernameSubmission(singlePage)).toBeUndefined();
  });

  it('fails closed for ambiguous username-only steps', () => {
    const form = renderForm(`
      <input type="email" autocomplete="username" value="first@example.com">
      <input type="email" autocomplete="username" value="second@example.com">
    `);
    expect(detectNativeUsernameSubmission(form)).toBeUndefined();
  });

  it('captures the current password from an ordinary login', () => {
    const form = renderForm(`
      <input type="email" autocomplete="username" value="alice@example.com">
      <input type="password" autocomplete="current-password" value="login-secret">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({
      username: 'alice@example.com',
      password: 'login-secret',
    });
  });

  it('captures the primary new password from a registration form', () => {
    const form = renderForm(`
      <input type="email" autocomplete="email" value="new@example.com">
      <input type="password" name="password" autocomplete="new-password" value="brand-new">
      <input type="password" name="confirm-password" autocomplete="new-password" value="brand-new">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({
      username: 'new@example.com',
      password: 'brand-new',
    });
  });

  it('captures the primary new password instead of the old password in a change form', () => {
    const form = renderForm(`
      <input type="password" autocomplete="current-password" value="old-secret">
      <input type="password" name="newPassword" autocomplete="new-password" value="new-secret">
      <input type="password" name="confirmPassword" autocomplete="new-password" value="new-secret">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({ password: 'new-secret' });
  });

  it('infers one unlabeled primary only when a confirmation field makes the new-password flow clear', () => {
    const form = renderForm(`
      <input type="password" name="password" value="brand-new">
      <input type="password" name="password_confirmation" value="brand-new">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({ password: 'brand-new' });
  });

  it('recognizes a confirmation hint after the word password', () => {
    const form = renderForm(`
      <input type="password" name="passwordNew" value="brand-new">
      <input type="password" name="passwordConfirmation" value="brand-new">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({ password: 'brand-new' });
  });

  it('allows an empty confirmation but rejects a non-empty mismatch', () => {
    const form = renderForm(`
      <input type="password" name="newPassword" value="brand-new">
      <input type="password" name="confirmPassword" value="">
    `);
    expect(detectNativeFormSubmission(form)).toEqual({ password: 'brand-new' });

    (form.elements.namedItem('confirmPassword') as HTMLInputElement).value = 'different';
    expect(detectNativeFormSubmission(form)).toBeUndefined();
  });

  it('uses an associated label to distinguish the confirmation field', () => {
    const form = renderForm(`
      <label for="primary">Choose password</label>
      <input id="primary" type="password" autocomplete="new-password" value="brand-new">
      <label for="copy">Confirm password</label>
      <input id="copy" type="password" autocomplete="new-password" value="brand-new">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({ password: 'brand-new' });
  });

  it('rejects contradictory current and new-password hints', () => {
    const form = renderForm('<input type="password" name="newPassword" autocomplete="current-password" value="secret">');

    expect(detectNativeFormSubmission(form)).toBeUndefined();
  });

  it('fails closed when multiple primary new-password fields are plausible', () => {
    const form = renderForm(`
      <input type="password" id="first" autocomplete="new-password" value="first">
      <input type="password" id="second" autocomplete="new-password" value="second">
    `);

    expect(detectNativeFormSubmission(form)).toBeUndefined();
  });

  it('fails closed when an ordinary form has multiple unclassified passwords', () => {
    const form = renderForm(`
      <input type="password" value="first">
      <input type="password" value="second">
    `);

    expect(detectNativeFormSubmission(form)).toBeUndefined();
  });

  it('never captures payment security fields', () => {
    const autocomplete = renderForm('<input type="password" autocomplete="cc-csc" value="123">');
    expect(detectNativeFormSubmission(autocomplete)).toBeUndefined();

    const named = renderForm('<input type="password" name="securityCode" value="456">');
    expect(detectNativeFormSubmission(named)).toBeUndefined();

    const contextual = renderForm(`
      <input autocomplete="cc-number" value="4111111111111111">
      <input type="password" name="code" inputmode="numeric" maxlength="3" value="789">
    `);
    expect(detectNativeFormSubmission(contextual)).toBeUndefined();
  });

  it('never captures a password-shaped one-time code as an account password', () => {
    const native = renderForm(`
      <input type="email" autocomplete="username" value="alice@example.com">
      <input type="password" autocomplete="one-time-code" value="123456">
    `);
    expect(detectNativeFormSubmission(native)).toBeUndefined();

    document.body.innerHTML = `
      <section>
        <input type="email" autocomplete="username" value="alice@example.com">
        <input id="otp" type="password" autocomplete="one-time-code" value="654321">
        <button type="submit">Verify</button>
      </section>`;
    expect(detectFormlessSubmission(document.getElementById('otp') as HTMLInputElement)).toBeUndefined();
  });

  it('uses form.elements for controls associated through form=id', () => {
    document.body.innerHTML = `
      <form id="account"><button type="submit">Continue</button></form>
      <input form="account" type="email" autocomplete="username" value="outside@example.com">
      <input form="account" type="password" autocomplete="new-password" value="outside-secret">
    `;
    const form = document.querySelector<HTMLFormElement>('#account')!;
    form.querySelectorAll = () => { throw new Error('the detector must not query the form subtree'); };

    expect(detectNativeFormSubmission(form)).toEqual({
      username: 'outside@example.com',
      password: 'outside-secret',
    });
  });

  it('does not borrow a username owned by another form', () => {
    document.body.innerHTML = `
      <form id="login"><input type="password" value="secret"></form>
      <form id="profile"><input type="email" value="other@example.com"></form>
    `;

    expect(detectNativeFormSubmission(document.querySelector<HTMLFormElement>('#login')!))
      .toEqual({ password: 'secret' });
  });

  it('omits an ambiguous username instead of guessing', () => {
    const form = renderForm(`
      <input type="email" value="first@example.com">
      <input type="email" value="second@example.com">
      <input type="password" value="secret">
    `);

    expect(detectNativeFormSubmission(form)).toEqual({ password: 'secret' });
  });
});

describe('form-less submission detection', () => {
  it('captures a username-only step inside a narrow explicit section', () => {
    document.body.innerHTML = `<main>
      <section><input id="username" type="email" autocomplete="username" value="alice@example.com"><button id="continue">Continue</button></section>
      <section><input type="email" value="other@example.com"></section>
    </main>`;
    expect(detectFormlessUsernameSubmission(document.querySelector('#continue')!))
      .toEqual({ username: 'alice@example.com' });
  });

  it('does not use body or a scope containing a password for username staging', () => {
    document.body.innerHTML = '<input id="body-user" autocomplete="username" value="body@example.com"><button id="body-next">Next</button>';
    expect(detectFormlessUsernameSubmission(document.querySelector('#body-next')!)).toBeUndefined();

    document.body.innerHTML = '<section><input autocomplete="username" value="single@example.com"><input type="password"><button id="login">Login</button></section>';
    expect(detectFormlessUsernameSubmission(document.querySelector('#login')!)).toBeUndefined();
  });

  it('keeps the username and password inside the triggering credential block', () => {
    document.body.innerHTML = `<main>
      <div><input name="username" value="first"><input id="first" type="password" value="first-pass"></div>
      <div><input name="username" value="second"><input id="second" type="password" value="second-pass"></div>
    </main>`;

    expect(detectFormlessSubmission(document.querySelector<HTMLInputElement>('#second')!))
      .toEqual({ username: 'second', password: 'second-pass' });
  });

  it('uses an explicit safe scope and observes a sibling confirmation field', () => {
    document.body.innerHTML = `<section>
      <input type="email" value="new@example.com">
      <div><input id="primary" type="password" autocomplete="new-password" value="new-secret"></div>
      <input type="password" name="confirmPassword" value="different">
    </section>`;

    expect(detectFormlessSubmission(document.querySelector<HTMLInputElement>('#primary')!)).toBeUndefined();
  });

  it('does not use body as a credential scope', () => {
    document.body.innerHTML = `
      <input type="email" value="unrelated@example.com">
      <input id="password" type="password" value="secret">
    `;

    expect(detectFormlessSubmission(document.querySelector<HTMLInputElement>('#password')!)).toBeUndefined();
  });
});

function renderForm(controls: string): HTMLFormElement {
  document.body.innerHTML = `<form>${controls}</form>`;
  return document.querySelector('form')!;
}
