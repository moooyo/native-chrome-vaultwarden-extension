// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { computeFillExclusion, resolveFocusedFill } from './focused-fill.js';
import { runFocusedFill, NOTICE_FOCUS, NOTICE_PAGE_CHANGED, type FocusedFillDeps } from './focused-fill.js';

describe('resolveFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('classifies a focused login password field as login', () => {
    document.body.innerHTML = '<form><input type="email"><input type="password"></form>';
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    pw.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'login' });
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

  it('returns none for a fillable-but-unrecognized field and for the body', () => {
    document.body.innerHTML = '<input type="search">';
    document.querySelector<HTMLInputElement>('input')!.focus();
    expect(resolveFocusedFill(document.activeElement)).toEqual({ kind: 'none' });
    document.body.innerHTML = '';
    expect(resolveFocusedFill(document.body)).toEqual({ kind: 'none' });
  });

  it('resolves a CVC-rendered-as-password field to card, not login (carve-out)', () => {
    document.body.innerHTML = '<form><input autocomplete="username" name="u"><input autocomplete="cc-number" name="c"><input type="password" autocomplete="cc-csc" name="cvc"><button type="submit">Pay</button></form>';
    const cvc = document.querySelector<HTMLInputElement>('input[name="cvc"]')!;
    cvc.focus();
    expect(resolveFocusedFill(document.activeElement)).toMatchObject({ kind: 'card' });
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
});

function makeDeps(over: Partial<FocusedFillDeps> = {}): FocusedFillDeps {
  return {
    frameUrl: () => 'https://ex.com',
    loginCandidates: async () => ({ ok: true, data: [] }),
    loginCredentials: async () => ({ ok: true, data: { username: 'u', password: 'p' } }),
    fillItems: async () => ({ ok: true, data: [] }),
    fillData: async () => ({ ok: true, data: {} }),
    fillLogin: vi.fn(),
    fillCard: vi.fn(),
    fillIdentity: vi.fn(),
    openPicker: vi.fn(),
    notify: vi.fn(),
    ...over,
  };
}
const liveInput = () => { const i = document.createElement('input'); document.body.append(i); return i; };

describe('runFocusedFill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('notifies to focus a field when target is none', async () => {
    const deps = makeDeps();
    await runFocusedFill({ kind: 'none' }, deps);
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_FOCUS);
  });

  it('fills a login directly on a single URL match', async () => {
    const pw = liveInput();
    const form = { id: 'f1', form: null, passwordInput: pw, anchor: pw };
    const deps = makeDeps({
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' } as never] }),
      loginCredentials: async () => ({ ok: true, data: { password: 'secret' } }),
    });
    await runFocusedFill({ kind: 'login', form: form as never }, deps);
    expect(deps.fillLogin).toHaveBeenCalledTimes(1);
    expect(deps.openPicker).not.toHaveBeenCalled();
  });

  it('opens the picker when a login has multiple matches', async () => {
    const deps = makeDeps({ loginCandidates: async () => ({ ok: true, data: [{ id: 'a' }, { id: 'b' }] as never }) });
    await runFocusedFill({ kind: 'login', form: { id: 'f2' } as never }, deps);
    expect(deps.openPicker).toHaveBeenCalledWith('f2');
    expect(deps.fillLogin).not.toHaveBeenCalled();
  });

  it('notifies "No matching logins" on zero login matches', async () => {
    const deps = makeDeps({ loginCandidates: async () => ({ ok: true, data: [] }) });
    await runFocusedFill({ kind: 'login', form: { id: 'f3' } as never }, deps);
    expect(deps.notify).toHaveBeenCalledWith('No matching logins');
  });

  it('aborts a login fill if the frame URL changed during the round-trip', async () => {
    const pw = liveInput();
    let url = 'https://ex.com';
    const deps = makeDeps({
      frameUrl: () => url,
      loginCandidates: async () => ({ ok: true, data: [{ id: 'c1' }] as never }),
      loginCredentials: async () => { url = 'https://evil.com'; return { ok: true, data: { password: 'secret' } }; },
      fillLogin: vi.fn(),
    });
    await runFocusedFill({ kind: 'login', form: { id: 'f4', passwordInput: pw, anchor: pw, form: null } as never }, deps);
    expect(deps.fillLogin).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });

  it('fills the single card and passes reprompt errors through as notices', async () => {
    const field = liveInput();
    const form = { kind: 'card', id: 'card1', fields: new Map([['number', field]]), anchor: field };
    const ok = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' } as never] }), fillData: async () => ({ ok: true, data: { number: '4111' } }) });
    await runFocusedFill({ kind: 'card', form: form as never }, ok);
    expect(ok.fillCard).toHaveBeenCalledTimes(1);

    const reprompt = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' } as never] }), fillData: async () => ({ ok: false, message: 'Protected item — open the extension to verify' }) });
    await runFocusedFill({ kind: 'card', form: form as never }, reprompt);
    expect(reprompt.notify).toHaveBeenCalledWith('Protected item — open the extension to verify');
    expect(reprompt.fillCard).not.toHaveBeenCalled();
  });

  it('notifies "No saved cards" / "No saved identities" on empty vault', async () => {
    const card = makeDeps({ fillItems: async () => ({ ok: true, data: [] }) });
    await runFocusedFill({ kind: 'card', form: { id: 'c', kind: 'card', fields: new Map(), anchor: document.createElement('div') } as never }, card);
    expect(card.notify).toHaveBeenCalledWith('No saved cards');
    const id = makeDeps({ fillItems: async () => ({ ok: true, data: [] }) });
    await runFocusedFill({ kind: 'identity', form: { id: 'i', kind: 'identity', fields: new Map(), anchor: document.createElement('div') } as never }, id);
    expect(id.notify).toHaveBeenCalledWith('No saved identities');
  });

  it('aborts a card fill if the form fields detached during the round-trip', async () => {
    const field = document.createElement('input'); // never appended → isConnected false
    const form = { kind: 'card', id: 'c9', fields: new Map([['number', field]]), anchor: field };
    const deps = makeDeps({ fillItems: async () => ({ ok: true, data: [{ id: 'x' }] as never }), fillData: async () => ({ ok: true, data: { number: '4111' } }) });
    await runFocusedFill({ kind: 'card', form: form as never }, deps);
    expect(deps.fillCard).not.toHaveBeenCalled();
    expect(deps.notify).toHaveBeenCalledWith(NOTICE_PAGE_CHANGED);
  });
});
