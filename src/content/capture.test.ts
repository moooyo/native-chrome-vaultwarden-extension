// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { snapshotLogin } from './capture.js';

afterEach(() => { document.body.innerHTML = ''; });

describe('snapshotLogin', () => {
  it('reads the username and password from a filled login form', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" value="alice@example.com" />
        <input type="password" name="password" value="s3cret" />
        <button type="submit">Sign in</button>
      </form>`;
    expect(snapshotLogin()).toEqual({ username: 'alice@example.com', password: 's3cret' });
  });

  it('captures a password-only form (no username field)', () => {
    document.body.innerHTML = `
      <form>
        <input type="password" name="password" value="only-pass" />
        <button type="submit">Go</button>
      </form>`;
    expect(snapshotLogin()).toEqual({ password: 'only-pass' });
  });

  it('returns undefined when the password is empty', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="username" value="alice" />
        <input type="password" name="password" value="" />
        <button type="submit">Go</button>
      </form>`;
    expect(snapshotLogin()).toBeUndefined();
  });

  it('does not capture from a registration form (new-password only)', () => {
    document.body.innerHTML = `
      <form>
        <input type="text" name="email" value="new@example.com" />
        <input type="password" name="new-password" autocomplete="new-password" value="brandnew" />
        <button type="submit">Create account</button>
      </form>`;
    // A pure new-password form yields no fillable/capturable current-password field.
    expect(snapshotLogin()).toBeUndefined();
  });
});
