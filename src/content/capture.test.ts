// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { snapshotLogin, startSaveCapture, type CapturedLogin } from './capture.js';
import { createAutofillDocumentController } from './autofill-document-controller.js';

const FORMLESS_SUBMISSION = Object.freeze({ kind: 'formless' as const });

afterEach(() => { document.body.innerHTML = ''; });

describe('snapshotLogin', () => {
  it('reads the username and password from a filled login form', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" value="alice@example.com" />
        <input type="password" name="password" value="s3cret" />
        <button type="submit">Sign in</button>
      </form>`;
    expect(snapshotLogin(onlyForm())).toEqual({ username: 'alice@example.com', password: 's3cret' });
  });

  it('captures a password-only form (no username field)', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="password" value="only-pass" />
        <button type="submit">Go</button>
      </form>`;
    expect(snapshotLogin(onlyForm())).toEqual({ password: 'only-pass' });
  });

  it('returns undefined when the password is empty', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" value="alice" />
        <input type="password" name="password" value="" />
        <button type="submit">Go</button>
      </form>`;
    expect(snapshotLogin(onlyForm())).toBeUndefined();
  });

  it('captures the primary password from a registration form', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="email" value="new@example.com" />
        <input type="password" name="new-password" autocomplete="new-password" value="brandnew" />
        <button type="submit">Create account</button>
      </form>`;
    expect(snapshotLogin(onlyForm())).toEqual({
      username: 'new@example.com',
      password: 'brandnew',
    });
  });

  it('does not capture a password-shaped payment security code', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" value="4111111111111111" />
        <input type="password" autocomplete="cc-csc" value="123" />
        <button type="submit">Pay</button>
      </form>`;
    expect(snapshotLogin(onlyForm())).toBeUndefined();
  });
});

describe('startSaveCapture', () => {
  it('stages a username-only first step without treating it as a saved credential', () => {
    document.body.innerHTML = `<form id="first-step">
      <input type="email" autocomplete="username" value="alice@example.com">
      <button type="submit">Continue</button>
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const onUsernameStage = vi.fn<(input: { username: string }) => void>();
    const stop = startSaveCapture(onCapture, undefined, onUsernameStage);

    trustedDispatch(document.querySelector('#first-step')!, new Event('submit', { bubbles: true }));

    expect(onCapture).not.toHaveBeenCalled();
    expect(onUsernameStage).toHaveBeenCalledOnce();
    expect(onUsernameStage).toHaveBeenCalledWith({ username: 'alice@example.com' });
    stop();
  });

  it('does not stage a username while an empty password belongs to the same form', () => {
    document.body.innerHTML = `<form id="login">
      <input type="email" autocomplete="username" value="alice@example.com">
      <input type="password" value="">
      <button type="submit">Continue</button>
    </form>`;
    const onUsernameStage = vi.fn<(input: { username: string }) => void>();
    const stop = startSaveCapture(vi.fn(), undefined, onUsernameStage);

    trustedDispatch(document.querySelector('#login')!, new Event('submit', { bubbles: true }));

    expect(onUsernameStage).not.toHaveBeenCalled();
    stop();
  });

  it('captures only the form that emitted a trusted submit', () => {
    document.body.innerHTML = twoLoginForms();
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector<HTMLFormElement>('#second')!, new Event('submit', { bubbles: true, cancelable: true }));

    expect(onCapture).toHaveBeenCalledOnce();
    expect(onCapture).toHaveBeenCalledWith(
      { username: 'second@example.com', password: 'second-pass' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('binds a native mutation submission to its canonical action and method', () => {
    document.body.innerHTML = `<form id="login" method="post" action="https://api.example.com/session?flow=1">
      <input type="email" value="alice@example.com">
      <input type="password" value="secret">
      <button type="submit">Sign in</button>
    </form>`;
    const onCapture = vi.fn();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.getElementById('login')!, new Event('submit', { bubbles: true }));

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'alice@example.com', password: 'secret' },
      {
        kind: 'native',
        actionUrl: 'https://api.example.com/session?flow=1',
        method: 'POST',
      },
    );
    stop();
  });

  it('captures a pure registration submission', () => {
    document.body.innerHTML = `<form id="signup">
      <input type="email" autocomplete="email" value="new@example.com">
      <input type="password" name="password" autocomplete="new-password" value="brand-new">
      <input type="password" name="confirmPassword" autocomplete="new-password" value="brand-new">
      <button type="submit">Create</button>
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector<HTMLFormElement>('#signup')!, new Event('submit', { bubbles: true }));

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'new@example.com', password: 'brand-new' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('captures the new password from a password-change submission', () => {
    document.body.innerHTML = `<form id="change">
      <input type="password" autocomplete="current-password" value="old-secret">
      <input type="password" autocomplete="new-password" name="newPassword" value="new-secret">
      <input type="password" autocomplete="new-password" name="confirmPassword" value="new-secret">
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector<HTMLFormElement>('#change')!, new Event('submit', { bubbles: true }));

    expect(onCapture).toHaveBeenCalledWith({ password: 'new-secret' }, FORMLESS_SUBMISSION);
    stop();
  });

  it('binds a nested click target to its native submit button and form owner', async () => {
    document.body.innerHTML = `${twoLoginForms()}<button type="submit" form="second" id="outside"><span>Continue</span></button>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector('#outside span')!, new MouseEvent('click', { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'second@example.com', password: 'second-pass' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('captures form=id controls through an external submit button', async () => {
    document.body.innerHTML = `
      <form id="outside-form"></form>
      <input form="outside-form" type="email" autocomplete="username" value="outside@example.com">
      <input form="outside-form" type="password" value="outside-pass">
      <button form="outside-form" type="submit" id="outside"><span>Continue</span></button>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector('#outside span')!, new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'outside@example.com', password: 'outside-pass' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('binds Enter from a form=id external input to its owner form', async () => {
    document.body.innerHTML = `
      <form id="outside-form"></form>
      <input form="outside-form" type="email" autocomplete="username" value="outside@example.com">
      <input form="outside-form" id="outside-password" type="password" value="outside-pass">`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector('#outside-password')!, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'outside@example.com', password: 'outside-pass' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('binds an explicitly marked role=button click to its containing native form', async () => {
    document.body.innerHTML = `<form id="login">
      <input type="email" value="alice@example.com">
      <input type="password" value="secret">
      <div role="button" type="submit" id="submit"><span>Continue</span></div>
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector('#submit span')!, new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'alice@example.com', password: 'secret' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('ignores ordinary role buttons used for password reveal or help', () => {
    document.body.innerHTML = `<form id="login">
      <input type="email" value="alice@example.com">
      <input type="password" value="secret">
      <div role="button" id="reveal"><span>Show password</span></div>
      <div role="button" id="help"><span>Help</span></div>
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector('#reveal span')!, new MouseEvent('click', { bubbles: true }));
    trustedDispatch(document.querySelector('#help span')!, new MouseEvent('click', { bubbles: true }));

    expect(onCapture).not.toHaveBeenCalled();
    stop();
  });

  it('binds Enter to the triggering input instead of the first login on the page', async () => {
    document.body.innerHTML = twoLoginForms();
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector<HTMLInputElement>('#second input[type="password"]')!, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'second@example.com', password: 'second-pass' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('deduplicates click activation followed by the native submit event', async () => {
    document.body.innerHTML = `<form id="login">
      <input type="email" value="alice@example.com">
      <input type="password" value="secret">
      <button type="submit" id="submit">Continue</button>
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);
    const form = document.getElementById('login')!;

    trustedDispatch(document.getElementById('submit')!, new MouseEvent('click', { bubbles: true }));
    trustedDispatch(form, new Event('submit', { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledOnce();
    expect(onCapture).toHaveBeenCalledWith(
      { username: 'alice@example.com', password: 'secret' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('deduplicates Enter activation followed by the native submit event', async () => {
    document.body.innerHTML = `<form id="login">
      <input type="email" value="alice@example.com">
      <input type="password" id="password" value="secret">
    </form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.getElementById('password')!, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    trustedDispatch(document.getElementById('login')!, new Event('submit', { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect(onCapture).toHaveBeenCalledOnce();
    expect(onCapture).toHaveBeenCalledWith(
      { username: 'alice@example.com', password: 'secret' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });

  it('ignores untrusted, reset, composing, repeated, and modified triggers', () => {
    document.body.innerHTML = `${twoLoginForms()}<button type="reset" form="second" id="reset">Reset</button>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);
    const password = document.querySelector<HTMLInputElement>('#second input[type="password"]')!;

    document.querySelector<HTMLFormElement>('#second')!.dispatchEvent(new Event('submit', { bubbles: true }));
    trustedDispatch(document.querySelector('#reset')!, new MouseEvent('click', { bubbles: true }));
    trustedDispatch(password, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, isComposing: true }));
    trustedDispatch(password, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, repeat: true }));
    trustedDispatch(password, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, ctrlKey: true }));

    expect(onCapture).not.toHaveBeenCalled();
    stop();
  });

  it('does not borrow credentials from another form when the submitted form has none', () => {
    document.body.innerHTML = `${twoLoginForms()}<form id="unrelated"><input name="search"><button>Search</button></form>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector<HTMLFormElement>('#unrelated')!, new Event('submit', { bubbles: true }));

    expect(onCapture).not.toHaveBeenCalled();
    stop();
  });

  it('captures non-composed submit events in dynamically discovered open roots and tears down', () => {
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const controller = createAutofillDocumentController(document);
    const stop = startSaveCapture(onCapture, controller);
    const host = document.createElement('div');
    document.body.append(host);
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input type="email" value="shadow@example.com"><input type="password" value="secret"></form>';
    controller.refresh();
    const form = shadow.querySelector<HTMLFormElement>('form')!;

    trustedDispatch(form, new Event('submit', { bubbles: true, composed: false }));
    expect(onCapture).toHaveBeenCalledWith(
      { username: 'shadow@example.com', password: 'secret' },
      FORMLESS_SUBMISSION,
    );

    stop();
    trustedDispatch(form, new Event('submit', { bubbles: true, composed: false }));
    expect(onCapture).toHaveBeenCalledTimes(1);
    controller.disconnect();
  });

  it('pairs a formless password only with the username in its narrow credential block', () => {
    document.body.innerHTML = `<main>
      <div><input type="text" name="user1" value="first"><input type="password" name="pass1" value="first-pass"></div>
      <div><input type="text" name="user2" value="second"><input type="password" name="pass2" value="second-pass"></div>
    </main>`;
    const onCapture = vi.fn<(login: CapturedLogin) => void>();
    const stop = startSaveCapture(onCapture);

    trustedDispatch(document.querySelector<HTMLInputElement>('[name="pass1"]')!, new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));

    expect(onCapture).toHaveBeenCalledWith(
      { username: 'first', password: 'first-pass' },
      FORMLESS_SUBMISSION,
    );
    stop();
  });
});

function onlyForm(): HTMLFormElement {
  const forms = document.querySelectorAll<HTMLFormElement>('form');
  expect(forms).toHaveLength(1);
  return forms[0]!;
}

function twoLoginForms(): string {
  return `
    <form id="first">
      <input type="email" name="username" value="first@example.com" />
      <input type="password" name="password" value="first-pass" />
      <button type="submit">Sign in</button>
    </form>
    <form id="second">
      <input type="email" name="username" value="second@example.com" />
      <input type="password" name="password" value="second-pass" />
      <button type="submit">Sign in</button>
    </form>`;
}

function trustedDispatch(target: EventTarget, event: Event): void {
  Object.defineProperty(event, 'isTrusted', { value: true });
  target.dispatchEvent(event);
}
