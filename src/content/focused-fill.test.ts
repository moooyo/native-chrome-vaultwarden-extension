// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { computeFillExclusion, resolveFocusedFill } from './focused-fill.js';
import {
  FOCUSED_FILL_CYCLE_TTL_MS,
  FocusedFillCycle,
  runFocusedFill,
  NOTICE_FOCUS,
  NOTICE_PAGE_CHANGED,
  type FocusedFillDeps,
} from './focused-fill.js';

describe('resolveFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('classifies a focused login password field as login', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    pw.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'login' });
  });

  it('returns no focused target from a truncated composed-tree snapshot', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;

    expect(resolveFocusedFill(password, {
      roots: [document],
      visitedElements: 3,
      truncated: true,
    })).toEqual({ kind: 'none' });
  });

  it('classifies an unhinted native-form identifier and password as the same login target', () => {
    document.body.innerHTML = '<form><input id="identifier" type="text"><input id="password" type="password"></form>';
    const identifier = document.getElementById('identifier') as HTMLInputElement;
    const password = document.getElementById('password') as HTMLInputElement;
    const identifierTarget = resolveFocusedFill(identifier);
    const passwordTarget = resolveFocusedFill(password);

    expect(identifierTarget).toMatchObject({ kind: 'login', input: identifier });
    expect(passwordTarget).toMatchObject({ kind: 'login', input: password });
    if (identifierTarget.kind !== 'login' || passwordTarget.kind !== 'login') {
      throw new Error('expected login targets');
    }
    expect(identifierTarget.form.usernameInput).toBe(identifier);
    expect(passwordTarget.form.id).toBe(identifierTarget.form.id);
  });

  it('classifies a focused one-time-code field as a dedicated TOTP target', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"><input autocomplete="one-time-code"></form>';
    const totp = document.querySelector<HTMLInputElement>('input[autocomplete="one-time-code"]')!;
    totp.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'totp', input: totp });
  });

  it('classifies a password-shaped explicit one-time-code field as TOTP, never login', () => {
    document.body.innerHTML = `
      <form><input id="otp" type="password" autocomplete="one-time-code"><button>Verify</button></form>`;
    const otp = document.getElementById('otp') as HTMLInputElement;

    expect(resolveFocusedFill(otp)).toMatchObject({ kind: 'totp', input: otp });
  });

  it('never treats an isolated explicit cc-csc password field as login', () => {
    document.body.innerHTML = '<form><input id="cvc" type="password" autocomplete="cc-csc"></form>';

    expect(resolveFocusedFill(document.getElementById('cvc'))).toEqual({ kind: 'none' });
    expect(computeFillExclusion().loginForms).toEqual([]);
  });

  it('fails closed for conflicting one-time-code and cc-csc autocomplete tokens', () => {
    document.body.innerHTML = `
      <form><input name="cardNumber"><input id="conflict" type="password" autocomplete="one-time-code cc-csc"></form>`;

    expect(resolveFocusedFill(document.getElementById('conflict'))).toEqual({ kind: 'none' });
  });

  it('never selects card fields as a generic login username fallback', () => {
    document.body.innerHTML = `
      <form>
        <input id="number" autocomplete="cc-number">
        <input id="cvc" autocomplete="cc-csc">
        <input id="password" type="password" autocomplete="current-password">
      </form>`;
    const password = document.getElementById('password') as HTMLInputElement;
    const cvc = document.getElementById('cvc') as HTMLInputElement;
    const login = resolveFocusedFill(password);

    expect(login).toMatchObject({ kind: 'login', input: password });
    if (login.kind !== 'login') throw new Error('expected login target');
    expect(login.form.usernameInput).toBeUndefined();
    expect(resolveFocusedFill(cvc)).toMatchObject({ kind: 'card' });
  });

  it('classifies every member of a safe split-code group as the same TOTP target', () => {
    document.body.innerHTML = `
      <form><div>
        <input id="digit-1" autocomplete="one-time-code" maxlength="1">
        <input id="digit-2" maxlength="1"><input id="digit-3" maxlength="1">
        <input id="digit-4" maxlength="1"><input id="digit-5" maxlength="1"><input id="digit-6" maxlength="1">
      </div><button>Verify</button></form>`;
    const first = document.getElementById('digit-1') as HTMLInputElement;
    const later = document.getElementById('digit-4') as HTMLInputElement;

    expect(resolveFocusedFill(first)).toMatchObject({ kind: 'totp', input: first });
    expect(resolveFocusedFill(later)).toMatchObject({ kind: 'totp', input: later });
    const firstTarget = resolveFocusedFill(first);
    const laterTarget = resolveFocusedFill(later);
    if (firstTarget.kind !== 'totp' || laterTarget.kind !== 'totp') throw new Error('expected TOTP targets');
    expect(laterTarget.form.id).toBe(firstTarget.form.id);
  });

  it('does not expose an unsafe split-code cluster as a focused TOTP target', () => {
    document.body.innerHTML = `
      <form><div>
        <input id="otp" autocomplete="one-time-code" maxlength="1">
        <input maxlength="1" hidden><input maxlength="1">
      </div><button>Verify</button></form>`;

    expect(resolveFocusedFill(document.getElementById('otp'))).toEqual({ kind: 'none' });
  });

  it('classifies a focused card-number field as card', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"></form>';
    const num = document.querySelector<HTMLInputElement>('input[autocomplete="cc-number"]')!;
    num.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
  });

  it('classifies a focused address field as identity', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"><input autocomplete="postal-code"></form>';
    const addr = document.querySelector<HTMLInputElement>('input[autocomplete="street-address"]')!;
    addr.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'identity' });
  });

  it('classifies a focused street-address textarea as identity', () => {
    document.body.innerHTML = '<form><textarea autocomplete="street-address" id="address"></textarea></form>';
    const address = document.getElementById('address') as HTMLTextAreaElement;
    address.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'identity' });
  });

  it('returns none for a fillable-but-unrecognized field and for the body', () => {
    document.body.innerHTML = '<input type="search">';
    document.querySelector<HTMLInputElement>('input')!.focus();
    expect(resolveFocusedFill(document.activeElement)).toEqual({ kind: 'none' });
    document.body.innerHTML = '';
    expect(resolveFocusedFill(document.body)).toEqual({ kind: 'none' });
  });

  it('returns none for login, TOTP, card, and identity targets carrying data-bwignore', () => {
    document.body.innerHTML = `
      <form><input type="password" id="password" data-bwignore></form>
      <form><input autocomplete="one-time-code" id="otp" data-bwignore><button>Verify</button></form>
      <form><input autocomplete="cc-number" id="card" data-bwignore></form>
      <form><input autocomplete="street-address" id="identity" data-bwignore></form>`;

    for (const id of ['password', 'otp', 'card', 'identity']) {
      expect(resolveFocusedFill(document.getElementById(id))).toEqual({ kind: 'none' });
    }
  });

  it('resolves a CVC-rendered-as-password field to card, not login (carve-out)', () => {
    document.body.innerHTML = '<form><input autocomplete="username" name="u"><input autocomplete="cc-number" name="c"><input type="password" autocomplete="cc-csc" name="cvc"><button type="submit">Pay</button></form>';
    const cvc = document.querySelector<HTMLInputElement>('input[name="cvc"]')!;
    cvc.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
  });

  it('resolves a textual security code beside a card number to card, not TOTP', () => {
    document.body.innerHTML = `
      <form>
        <input name="cardNumber">
        <input id="security" name="securityCode">
        <button>Pay</button>
      </form>`;
    const securityCode = document.getElementById('security') as HTMLInputElement;

    expect(resolveFocusedFill(securityCode)).toMatchObject({
      kind: 'card',
      form: { fields: expect.any(Map) },
    });
  });

  it('keeps a standalone textual security-code field as TOTP', () => {
    document.body.innerHTML = `
      <form><input id="security" name="security-code"><button>Verify</button></form>`;
    const securityCode = document.getElementById('security') as HTMLInputElement;

    expect(resolveFocusedFill(securityCode)).toMatchObject({ kind: 'totp', input: securityCode });
  });

  it('keeps login and textual card-code roles separate inside one native form', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="username">
        <input id="password" type="password" autocomplete="current-password">
        <input name="cardNumber">
        <input id="security" name="securityCode">
      </form>`;
    const password = document.getElementById('password') as HTMLInputElement;
    const securityCode = document.getElementById('security') as HTMLInputElement;

    expect(resolveFocusedFill(password)).toMatchObject({ kind: 'login', input: password });
    expect(resolveFocusedFill(securityCode)).toMatchObject({ kind: 'card' });
    expect(computeFillExclusion().loginForms[0]?.totpInput).toBeUndefined();
  });

  it('arbitrates textual card codes within, but never across, open shadow roots', () => {
    document.body.innerHTML = '<input name="cardNumber">';
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form id="payment"><input name="cardNumber"><input id="card-code" name="securityCode"></form>
      <form id="verification"><input id="otp" name="securityCode"><button>Verify</button></form>`;
    document.body.append(host);
    const cardCode = shadow.getElementById('card-code') as HTMLInputElement;
    const otp = shadow.getElementById('otp') as HTMLInputElement;

    expect(resolveFocusedFill(cardCode, [document, shadow])).toMatchObject({ kind: 'card' });
    expect(resolveFocusedFill(otp, [document, shadow])).toMatchObject({ kind: 'totp', input: otp });
  });

  it('resolves a deeply focused open-shadow login without crossing roots', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><input type="email"><input type="password"></form>';
    document.body.append(host);
    const password = shadow.querySelector<HTMLInputElement>('input[type="password"]')!;
    expect(resolveFocusedFill(password, [document, shadow])).toMatchObject({
      kind: 'login',
      form: { passwordInput: password },
    });
  });
});

describe('computeFillExclusion', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('excludes real login fields but drops a CVC-as-password login form', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const { loginForms, exclude } = computeFillExclusion();
    expect(loginForms).toHaveLength(1);
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    expect(exclude.has(pw)).toBe(true);
  });

  it('keeps an email field in a strong identity form instead of treating it as a username step', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"><input autocomplete="email" id="email"></form>';
    const email = document.getElementById('email')!;
    const { loginForms, exclude } = computeFillExclusion();

    expect(loginForms).toHaveLength(0);
    expect(exclude.has(email)).toBe(false);
    const focused = resolveFocusedFill(email);
    expect(focused.kind).toBe('identity');
    if (focused.kind !== 'identity') throw new Error('expected identity target');
    expect(focused.form.fields.get('email')).toBe(email);
  });
});

function makeDeps(over: Partial<FocusedFillDeps> = {}): FocusedFillDeps {
  return {
    frameUrl: () => 'https://ex.com',
    runtimeEpoch: () => 1,
    now: () => 1_000,
    isTargetCurrent: () => true,
    cycle: new FocusedFillCycle(),
    loginCandidates: async () => ({ ok: true, data: [] }),
    issueIntent: async (cipherId) => ({ ok: true, data: cipherId }),
    redeemLoginIntent: async () => ({ ok: true, data: { username: 'u', password: 'p' } }),
    redeemTotpIntent: async () => ({ ok: true, data: { code: '123456', period: 30, remaining: 10 } }),
    fillItems: async () => ({ ok: true, data: [] }),
    fillStructured: async () => ({ ok: true, data: undefined }),
    fillLogin: vi.fn(() => true),
    fillTotp: vi.fn(() => true),
    openPicker: vi.fn(),
    notify: vi.fn(),
    ...over,
  };
}
describe('runFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('notifies to focus a field when target is none', async () => {
    const deps = makeDeps();
    await runFocusedFill({ kind: 'none' }, deps);
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_FOCUS);
  });

  it('fills a login directly on a single URL match', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' } as never] }),
      redeemLoginIntent: async () => ({ ok: true, data: { password: 'secret' } }),
    });
    await runFocusedFill(target, deps);
    expect(deps.fillLogin).toHaveBeenCalledTimes(1);
    expect(deps.openPicker).not.toHaveBeenCalled();
  });

  it('cycles login candidates in stable order and wraps to the first candidate', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }, { id: 'c' }] as never }),
      issueIntent,
    });

    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);

    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'b', 'c', 'a']);
    expect(deps.fillLogin).toHaveBeenCalledTimes(4);
    expect(deps.openPicker).not.toHaveBeenCalled();
  });

  it('does not advance the login cycle when the DOM fill reports failure', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const fillLogin = vi.fn()
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(true);
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }),
      issueIntent,
      fillLogin,
    });

    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);

    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'a']);
    expect(fillLogin).toHaveBeenCalledTimes(2);
  });

  it('resets on candidate-order changes, including an A-B-A candidate-set transition', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    let candidateIds = ['a', 'b'];
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const deps = makeDeps({
      loginCandidates: async () => ({
        ok: true,
        data: candidateIds.map((id) => ({ id })) as never,
      }),
      issueIntent,
    });

    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);
    candidateIds = ['b', 'a'];
    await runFocusedFill(target, deps);
    candidateIds = ['a', 'b'];
    await runFocusedFill(target, deps);

    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'b', 'b', 'a']);
  });

  it('resets on exact URL, runtime epoch, and TTL changes', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    let url = 'https://ex.com/a';
    let epoch = 1;
    let now = 1_000;
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const deps = makeDeps({
      frameUrl: () => url,
      runtimeEpoch: () => epoch,
      now: () => now,
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }),
      issueIntent,
    });

    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);
    url = 'https://ex.com/b';
    await runFocusedFill(target, deps);
    url = 'https://ex.com/a';
    await runFocusedFill(target, deps);
    epoch = 2;
    await runFocusedFill(target, deps);
    now += FOCUSED_FILL_CYCLE_TTL_MS + 1;
    await runFocusedFill(target, deps);

    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'b', 'a', 'a', 'a', 'a']);
  });

  it('resets when the detector assigns a new form generation to the same focused anchor', async () => {
    document.body.innerHTML = '<form><input type="email" id="username"><input type="password" id="password"></form>';
    const password = document.getElementById('password') as HTMLInputElement;
    const firstTarget = resolveFocusedFill(password);
    if (firstTarget.kind !== 'login') throw new Error('expected login target');
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }),
      issueIntent,
    });

    await runFocusedFill(firstTarget, deps);
    const replacement = document.createElement('input');
    replacement.type = 'email';
    document.getElementById('username')!.replaceWith(replacement);
    const nextTarget = resolveFocusedFill(password);
    if (nextTarget.kind !== 'login') throw new Error('expected login target');
    await runFocusedFill(nextTarget, deps);

    expect(firstTarget.form.id).not.toBe(nextTarget.form.id);
    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'a']);
  });

  it('does not redeem a candidate after the target detaches during discovery', async () => {
    document.body.innerHTML = '<form id="login"><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const deps = makeDeps({
      loginCandidates: async () => {
        document.getElementById('login')!.remove();
        return { ok: true, data: [{ id: 'a' }] as never };
      },
      issueIntent,
    });

    await runFocusedFill(target, deps);

    expect(issueIntent).not.toHaveBeenCalled();
    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('does not redeem an issued intent after the target detaches', async () => {
    document.body.innerHTML = '<form id="login"><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    const redeemLoginIntent = vi.fn(async () => ({ ok: true as const, data: { password: 'must-not-read' } }));
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }] as never }),
      issueIntent: async () => {
        document.getElementById('login')!.remove();
        return { ok: true, data: 'one-time-intent' };
      },
      redeemLoginIntent,
    });

    await runFocusedFill(target, deps);

    expect(redeemLoginIntent).not.toHaveBeenCalled();
    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('rejects a focused-target A-B-A transition before writing a redeemed secret', async () => {
    document.body.innerHTML = `
      <form><input type="email"><input type="password" id="a"></form>
      <form><input type="email"><input type="password" id="b"></form>`;
    const firstInput = document.getElementById('a') as HTMLInputElement;
    const otherInput = document.getElementById('b') as HTMLInputElement;
    const target = resolveFocusedFill(firstInput);
    if (target.kind !== 'login') throw new Error('expected login target');
    const cycle = new FocusedFillCycle();
    const deps = makeDeps({
      cycle,
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }] as never }),
      redeemLoginIntent: async () => {
        cycle.noteFocusedElement(otherInput);
        cycle.noteFocusedElement(firstInput);
        return { ok: true, data: { password: 'must-not-fill' } };
      },
    });

    await runFocusedFill(target, deps);

    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('does not advance the cursor when purpose-specific redemption fails', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    let shouldFail = true;
    const redeemLoginIntent = vi.fn(async (id: string) => {
      if (shouldFail) return { ok: false as const, message: 'denied' };
      return { ok: true as const, data: { username: id } };
    });
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }),
      redeemLoginIntent,
    });

    await runFocusedFill(target, deps);
    shouldFail = false;
    await runFocusedFill(target, deps);

    expect(redeemLoginIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'a']);
    expect(deps.fillLogin).toHaveBeenCalledTimes(1);
  });

  it('notifies "No matching logins" on zero login matches', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    const deps = makeDeps({ loginCandidates: async () => ({ ok: true, data: [] }) });
    await runFocusedFill(target, deps);
    expect(deps.notify).toHaveBeenCalledWith('No matching logins');
  });

  it('aborts a login fill if the frame URL changed during the round-trip', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('input[type="password"]'));
    if (target.kind !== 'login') throw new Error('expected login target');
    let url = 'https://ex.com';
    const deps = makeDeps({
      frameUrl: () => url,
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      redeemLoginIntent: async () => { url = 'https://evil.com'; return { ok: true, data: { password: 'secret' } }; },
      fillLogin: vi.fn(() => true),
    });
    await runFocusedFill(target, deps);
    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('aborts a login fill if the password field is reclassified during the round-trip', async () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    const target = resolveFocusedFill(password);
    if (target.kind !== 'login') throw new Error('expected login target');
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      redeemLoginIntent: async () => {
        password.type = 'text';
        return { ok: true, data: { password: 'must-not-fill' } };
      },
    });

    await runFocusedFill(target, deps);

    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('fills a focused TOTP field without reading login data', async () => {
    document.body.innerHTML = '<form><input autocomplete="one-time-code" id="otp"><button>Verify</button></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    const target = resolveFocusedFill(input);
    if (target.kind !== 'totp') throw new Error('expected TOTP target');
    const redeemLoginIntent = vi.fn(async () => ({ ok: true as const, data: { password: 'must-not-read' } }));
    const redeemTotpIntent = vi.fn(async () => ({ ok: true as const, data: { code: '654321', period: 30, remaining: 20 } }));
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const loginCandidates = vi.fn(async () => ({ ok: true as const, data: [{ id: 'c1' }] as never }));
    const deps = makeDeps({ loginCandidates, issueIntent, redeemLoginIntent, redeemTotpIntent });

    await runFocusedFill(target, deps);

    expect(loginCandidates).toHaveBeenCalledWith('totp');
    expect(issueIntent).toHaveBeenCalledWith('c1', 'totp');
    expect(redeemTotpIntent).toHaveBeenCalledWith('c1');
    expect(redeemLoginIntent).not.toHaveBeenCalled();
    expect(deps.fillTotp).toHaveBeenCalledWith(input, { code: '654321', period: 30, remaining: 20 });
    expect(deps.fillLogin).not.toHaveBeenCalled();
  });

  it('rejects a redeemed split TOTP after the intact group moves to another form', async () => {
    document.body.innerHTML = `
      <form id="first"><div id="otp-group">
        <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
        <input maxlength="1"><input maxlength="1"><input maxlength="1">
      </div></form>
      <form id="second"></form>`;
    const group = document.getElementById('otp-group')!;
    const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('input'));
    const target = resolveFocusedFill(inputs[3]!);
    if (target.kind !== 'totp') throw new Error('expected TOTP target');
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      redeemTotpIntent: async () => {
        document.getElementById('second')!.append(group);
        return { ok: true, data: { code: '123456', period: 30, remaining: 20 } };
      },
    });

    await runFocusedFill(target, deps);

    expect(deps.fillTotp).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('rejects a redeemed split TOTP after the intact surface moves to another open root', async () => {
    document.body.replaceChildren();
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    const firstRoot = firstHost.attachShadow({ mode: 'open' });
    const secondRoot = secondHost.attachShadow({ mode: 'open' });
    firstRoot.innerHTML = `
      <div id="otp-surface"><div id="otp-group">
          <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
          <input maxlength="1"><input maxlength="1"><input maxlength="1">
        </div><button>Verify</button></div>`;
    document.body.append(firstHost, secondHost);
    const surface = firstRoot.getElementById('otp-surface')!;
    const inputs = Array.from(surface.querySelectorAll<HTMLInputElement>('input'));
    const target = resolveFocusedFill(inputs[3]!, [document, firstRoot, secondRoot]);
    if (target.kind !== 'totp') throw new Error('expected TOTP target');
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      redeemTotpIntent: async () => {
        secondRoot.append(surface);
        return { ok: true, data: { code: '123456', period: 30, remaining: 20 } };
      },
    });

    await runFocusedFill(target, deps);

    expect(deps.fillTotp).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('rejects a detected split-TOTP root A-B-A transition before writing a redeemed code', async () => {
    document.body.replaceChildren();
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    const firstRoot = firstHost.attachShadow({ mode: 'open' });
    const secondRoot = secondHost.attachShadow({ mode: 'open' });
    firstRoot.innerHTML = `
      <div id="otp-surface"><div>
          <input autocomplete="one-time-code" maxlength="1"><input maxlength="1"><input maxlength="1">
          <input maxlength="1"><input maxlength="1"><input maxlength="1">
        </div><button>Verify</button></div>`;
    document.body.append(firstHost, secondHost);
    const surface = firstRoot.getElementById('otp-surface')!;
    const inputs = Array.from(surface.querySelectorAll<HTMLInputElement>('input'));
    const target = resolveFocusedFill(inputs[3]!, [document, firstRoot, secondRoot]);
    if (target.kind !== 'totp') throw new Error('expected TOTP target');
    let intermediateFormId: string | undefined;
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      redeemTotpIntent: async () => {
        secondRoot.append(surface);
        const intermediate = resolveFocusedFill(inputs[3]!, [document, firstRoot, secondRoot]);
        if (intermediate.kind !== 'totp') throw new Error('expected intermediate TOTP target');
        intermediateFormId = intermediate.form.id;
        firstRoot.append(surface);
        return { ok: true, data: { code: '123456', period: 30, remaining: 20 } };
      },
    });

    await runFocusedFill(target, deps);

    expect(intermediateFormId).not.toBe(target.form.id);
    expect(deps.fillTotp).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('cycles multiple TOTP candidates through independent purpose-specific reads', async () => {
    document.body.innerHTML = '<form><input autocomplete="one-time-code" id="otp"><button>Verify</button></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    const target = resolveFocusedFill(input);
    if (target.kind !== 'totp') throw new Error('expected TOTP target');
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const redeemTotpIntent = vi.fn(async (id: string) => ({ ok: true as const, data: { code: id, period: 30, remaining: 10 } }));
    const redeemLoginIntent = vi.fn(async () => ({ ok: true as const, data: { password: 'must-not-read' } }));
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }),
      issueIntent,
      redeemLoginIntent,
      redeemTotpIntent,
    });

    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);

    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'b']);
    expect(redeemTotpIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'b']);
    expect(deps.fillTotp).toHaveBeenNthCalledWith(1, input, { code: 'a', period: 30, remaining: 10 });
    expect(deps.fillTotp).toHaveBeenNthCalledWith(2, input, { code: 'b', period: 30, remaining: 10 });
    expect(redeemLoginIntent).not.toHaveBeenCalled();
  });

  it('does not advance the TOTP cycle when the DOM fill reports failure', async () => {
    document.body.innerHTML = '<form><input autocomplete="one-time-code" id="otp"><button>Verify</button></form>';
    const input = document.getElementById('otp') as HTMLInputElement;
    const target = resolveFocusedFill(input);
    if (target.kind !== 'totp') throw new Error('expected TOTP target');
    const issueIntent = vi.fn(async (id: string) => ({ ok: true as const, data: id }));
    const fillTotp = vi.fn()
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(true);
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }),
      issueIntent,
      redeemTotpIntent: async (id) => ({ ok: true, data: { code: id, period: 30, remaining: 10 } }),
      fillTotp,
    });

    await runFocusedFill(target, deps);
    await runFocusedFill(target, deps);

    expect(issueIntent.mock.calls.map(([id]) => id)).toEqual(['a', 'a']);
    expect(fillTotp).toHaveBeenCalledTimes(2);
  });

  it('fills the single card and passes reprompt errors through as notices', async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]'));
    if (target.kind !== 'card') throw new Error('expected card target');
    const fillStructured = vi.fn(async () => ({ ok: true as const, data: undefined }));
    const ok = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' } as never] }), fillStructured });
    await runFocusedFill(target, ok);
    expect(fillStructured).toHaveBeenCalledWith('x', target.form);

    const deniedFill = vi.fn(async () => ({
      ok: false as const,
      message: 'Protected item — open the extension to verify',
      repromptContinuationId: '11111111-1111-4111-8111-111111111111',
    }));
    const deferReprompt = vi.fn();
    const reprompt = makeDeps({
      fillItems: async () => ({ ok: true, data: [{ id: 'x' } as never] }),
      fillStructured: deniedFill,
      deferReprompt,
    });
    await runFocusedFill(target, reprompt);
    expect(reprompt.notify).toHaveBeenCalledWith('Protected item — open the extension to verify');
    expect(deniedFill).toHaveBeenCalledOnce();
    expect(deferReprompt).toHaveBeenCalledWith(
      '11111111-1111-4111-8111-111111111111',
      target,
    );
  });

  it('opens the same inline picker for multiple structured candidates without issuing a secret read', async () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('[autocomplete="street-address"]'));
    if (target.kind !== 'identity') throw new Error('expected identity target');
    const fillStructured = vi.fn(async () => ({ ok: true as const, data: undefined }));
    const deps = makeDeps({
      fillItems: async () => ({ ok: true, data: [{ id: 'one' }, { id: 'two' }] as never }),
      fillStructured,
    });

    await runFocusedFill(target, deps);

    expect(deps.openPicker).toHaveBeenCalledWith(target.form, [{ id: 'one' }, { id: 'two' }]);
    expect(fillStructured).not.toHaveBeenCalled();
  });

  it('notifies "No saved cards" / "No saved identities" on empty vault', async () => {
    document.body.innerHTML = `
      <form id="card"><input autocomplete="cc-number"></form>
      <form id="identity"><input autocomplete="given-name"><input autocomplete="family-name"><input autocomplete="street-address"></form>`;
    const card = makeDeps({ fillItems: async () => ({ ok: true, data: [] }) });
    const cardTarget = resolveFocusedFill(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]'));
    if (cardTarget.kind !== 'card') throw new Error('expected card target');
    await runFocusedFill(cardTarget, card);
    expect(card.notify).toHaveBeenCalledWith('No saved cards');
    const id = makeDeps({ fillItems: async () => ({ ok: true, data: [] }) });
    const identityTarget = resolveFocusedFill(document.querySelector<HTMLInputElement>('[autocomplete="street-address"]'));
    if (identityTarget.kind !== 'identity') throw new Error('expected identity target');
    await runFocusedFill(identityTarget, id);
    expect(id.notify).toHaveBeenCalledWith('No saved identities');
  });

  it('aborts a card fill if the form fields detached during the round-trip', async () => {
    const field = document.createElement('input'); // never appended → isConnected false
    const form = { kind: 'card', id: 'c9', fields: new Map([['number', field]]), anchor: field };
    const fillStructured = vi.fn(async () => ({ ok: true as const, data: undefined }));
    const deps = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' }] as never }), fillStructured });
    await runFocusedFill({ kind: 'card', form: form as never }, deps);
    expect(fillStructured).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('aborts a card fill if the frame URL changed during the round-trip', async () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
    const target = resolveFocusedFill(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]'));
    if (target.kind !== 'card') throw new Error('expected card target');
    let url = 'https://ex.com';
    const fillStructured = vi.fn(async () => ({ ok: true as const, data: undefined }));
    const deps = makeDeps({
      frameUrl: () => url,
      fillItems: async () => { url = 'https://evil.com'; return { ok: true, data: [{ id: 'x' }] as never }; },
      fillStructured,
    });
    await runFocusedFill(target, deps);
    expect(fillStructured).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });
});
