// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The component composes the MiYu i18n module, which imports webextension-polyfill; that throws
// outside an extension, so stub it (matching the project's test convention).
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './vault-view.js';
import { setLocale } from '../../i18n/index.js';
import type { VwVaultView, CategoryId } from './vault-view.js';
import type { DetailExtras, SuggestionsViewState, TotpFetchResult } from '../types.js';
import type { CipherSummary } from '../../../core/vault/models.js';
import { EMPTY_LOGIN_CUSTOM_PLAN_DIGEST } from '../../../core/vault/login-custom-fields.js';

const TARGET_RUNTIME_INCARNATION = 'a0b1c2d3-e4f5-4a6b-8c9d-0123456789ab';

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function detailExtras(over: Partial<DetailExtras> = {}): DetailExtras {
  return {
    getField: async () => ({ ok: false }),
    getCustomField: async () => ({ ok: false }),
    getTotp: async () => ({ ok: true, totp: null }),
    getPasswordHistory: async () => ({ ok: true, history: [] }),
    ...over,
  };
}

async function flushAsync(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function login(over: Partial<CipherSummary> = {}): CipherSummary {
  return {
    id: 'c1', name: 'Nebula', username: 'me@x.dev', uris: ['https://nebula.dev'], loginUris: [],
    type: 1, favorite: false, ...over,
  };
}

async function mount(over: Partial<VwVaultView> = {}): Promise<VwVaultView> {
  const el = document.createElement('vw-vault-view') as VwVaultView;
  el.items = [login()];
  el.suggestionsState = { status: 'ready', suggestions: [] } as SuggestionsViewState;
  el.query = '';
  el.category = 'all';
  el.mode = 'active';
  el.pending = false;
  el.selectedCipherId = null;
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-vault-view', () => {
  beforeEach(() => setLocale('en', false));
  afterEach(() => document.body.replaceChildren());

  it('renders the search box and every stable item-type category (2FA has its own view)', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('input[type="search"]')).not.toBeNull();
    expect(el.shadowRoot?.querySelectorAll('.chip')).toHaveLength(7);
    expect(el.shadowRoot?.textContent).toContain('Favorites');
    expect(el.shadowRoot?.textContent).not.toContain('2FA');
    expect(el.shadowRoot?.textContent).toContain('SSH keys');
  });

  it('emits vw-search-change on input', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-search-change', fired);
    const input = el.shadowRoot!.querySelector<HTMLInputElement>('input[type="search"]')!;
    input.value = 'neb';
    input.dispatchEvent(new Event('input'));
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { query: 'neb' } }));
  });

  it('uses normalized multi-term search across name, username, subtitle, and URI hostname', async () => {
    const items: CipherSummary[] = [
      login({ id: 'name', name: 'Named Match', uris: [] }),
      login({ id: 'username', name: 'Username Item', username: 'account-owner', uris: [] }),
      login({ id: 'uri', name: 'URI Item', uris: ['https://portal.example/path'] }),
      { id: 'card', name: 'Travel Card', subtitle: 'Premium Visa', uris: [], loginUris: [], type: 3, favorite: false },
      { id: 'identity', name: 'Personal Identity', subtitle: 'Mina Chen', uris: [], loginUris: [], type: 4, favorite: false },
      { id: 'ssh', name: 'Deploy Key', subtitle: 'SHA256:AbCd123', uris: [], loginUris: [], type: 5, favorite: false },
    ];
    const el = await mount({ items });
    const visibleNames = async (query: string): Promise<string[]> => {
      el.query = query;
      await el.updateComplete;
      return [...el.shadowRoot!.querySelectorAll<HTMLElement>('.title')]
        .map((title) => title.textContent ?? '');
    };

    expect(await visibleNames('named match')).toEqual(['Named Match']);
    expect(await visibleNames('ACCOUNT-OWNER')).toEqual(['Username Item']);
    expect(await visibleNames('portal.example')).toEqual(['URI Item']);
    expect(await visibleNames('  pReMiUm ViSa  ')).toEqual(['Travel Card']);
    expect(await visibleNames('mina chen')).toEqual(['Personal Identity']);
    expect(await visibleNames('sha256:abcd123')).toEqual(['Deploy Key']);
    expect(await visibleNames('portal uri')).toEqual(['URI Item']);
    expect(await visibleNames('portal missing')).toEqual([]);
    expect(await visibleNames('portal.example path')).toEqual([]);
    expect(await visibleNames('   ')).toEqual([
      'Deploy Key',
      'Named Match',
      'Personal Identity',
      'Travel Card',
      'URI Item',
      'Username Item',
    ]);
  });

  it('sorts the vault naturally by localized name and then login username', async () => {
    const el = await mount({
      items: [
        login({ id: 'ten', name: 'Item 10', username: 'zeta' }),
        login({ id: 'two-z', name: 'Item 2', username: 'user10' }),
        login({ id: 'two-a', name: 'item 2', username: 'user2' }),
      ],
    });

    expect([...el.shadowRoot!.querySelectorAll<HTMLElement>('.title')]
      .map((title) => title.textContent)).toEqual(['item 2', 'Item 2', 'Item 10']);
    expect([...el.shadowRoot!.querySelectorAll<HTMLElement>('.sub')]
      .map((subtitle) => subtitle.textContent)).toEqual(['user2', 'user10', 'zeta']);
  });

  it('emits vw-category-change when a chip is clicked', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-category-change', fired);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-category="login"]')!.click();
    const detail = fired.mock.calls[0]![0].detail as { category: CategoryId };
    expect(detail.category).toBe('login');
  });

  it('filters the stable SSH key item type from its category chip', async () => {
    const items: CipherSummary[] = [
      login({ id: 'login', name: 'Login' }),
      { id: 'ssh', name: 'Deploy key', uris: [], loginUris: [], type: 5, favorite: false },
    ];
    const el = await mount({ items, category: 'ssh' });

    expect([...el.shadowRoot!.querySelectorAll<HTMLElement>('.title')]
      .map((title) => title.textContent)).toEqual(['Deploy key']);
  });

  it('filters favorites through the existing category state without root integration', async () => {
    const items: CipherSummary[] = [
      login({ id: 'favorite-login', name: 'Favorite login', favorite: true }),
      login({ id: 'ordinary-login', name: 'Ordinary login', favorite: false }),
      { id: 'favorite-card', name: 'Favorite card', uris: [], loginUris: [], type: 3, favorite: true },
    ];
    const el = await mount({ items, category: 'favorite' });

    expect([...el.shadowRoot!.querySelectorAll<HTMLElement>('.title')]
      .map((title) => title.textContent)).toEqual(['Favorite card', 'Favorite login']);
    expect(el.shadowRoot?.querySelector('[data-category="favorite"]')?.getAttribute('aria-selected')).toBe('true');
  });

  it('renders a non-interactive accessible favorite marker without displacing a long title', async () => {
    const longName = `Favorite ${'segment '.repeat(50)}`.trim();
    const el = await mount({
      items: [
        login({ id: 'favorite', name: longName, favorite: true }),
        login({ id: 'ordinary', name: 'Ordinary', favorite: false }),
      ],
    });
    const markers = [...el.shadowRoot!.querySelectorAll<HTMLElement>('.favorite-marker')];

    expect(markers).toHaveLength(1);
    expect(markers[0]?.tagName).toBe('SPAN');
    expect(markers[0]?.getAttribute('role')).toBe('img');
    expect(markers[0]?.getAttribute('aria-label')).toBe('Favorite item');
    expect(markers[0]?.title).toBe('Favorite item');
    expect(markers[0]?.hasAttribute('tabindex')).toBe(false);
    const title = markers[0]?.nextElementSibling as HTMLElement;
    expect(title.classList.contains('title')).toBe(true);
    expect(title.textContent).toBe(longName);
  });

  it('renders an item row and toggles it open on click', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-item-toggle', fired);
    const row = el.shadowRoot!.querySelector<HTMLButtonElement>('.row-main')!;
    expect(row.textContent).toContain('Nebula');
    expect(row.getAttribute('aria-expanded')).toBe('false');
    row.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'c1' } }));
  });

  it('shows an unknown cipher as a non-expandable placeholder without secret or mutation controls', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, value: 'future-secret' }));
    const item: CipherSummary = {
      id: 'future-6',
      type: 6,
      name: 'encrypted-name-must-not-display',
      uris: [],
      loginUris: [],
      favorite: false,
      unsupported: true,
      undecryptable: true,
    };
    const el = await mount({
      items: [item],
      selectedCipherId: 'future-6',
      extras: detailExtras({ getField }),
    });
    const opened = vi.fn();
    const toggled = vi.fn();
    const edited = vi.fn();
    const secret = vi.fn();
    el.addEventListener('vw-item-open', opened);
    el.addEventListener('vw-item-toggle', toggled);
    el.addEventListener('vw-edit-item', edited);
    el.addEventListener('vw-secret-request', secret);

    const row = el.shadowRoot!.querySelector<HTMLElement>('.row-main')!;
    expect(row.textContent).toContain('Unsupported item');
    expect(row.textContent).toContain('Unsupported type 6');
    expect(row.textContent).not.toContain('encrypted-name-must-not-display');
    expect(row.tagName).toBe('DIV');
    expect(row.getAttribute('aria-disabled')).toBe('true');
    expect(row.hasAttribute('aria-expanded')).toBe(false);
    expect(el.shadowRoot?.querySelector('.card')).toBeNull();
    expect(el.shadowRoot?.querySelector('.row-copy')).toBeNull();
    expect(el.shadowRoot?.querySelector('.fill-pill')).toBeNull();
    expect(el.shadowRoot?.querySelector('.chev')).toBeNull();

    row.click();
    expect(opened).not.toHaveBeenCalled();
    expect(toggled).not.toHaveBeenCalled();
    expect(edited).not.toHaveBeenCalled();
    expect(secret).not.toHaveBeenCalled();
    expect(getField).not.toHaveBeenCalled();
  });

  it('uses a native button for keyboard expansion and only offers password copy for logins', async () => {
    const card: CipherSummary = { id: 'card-1', name: 'Card', uris: [], loginUris: [], type: 3, favorite: false, subtitle: '•••• 4242' };
    const el = await mount({ items: [card] });
    const row = el.shadowRoot!.querySelector('.row-main');
    expect(row?.tagName).toBe('BUTTON');
    expect(el.shadowRoot!.querySelector('.row-copy')).toBeNull();
    el.selectedCipherId = 'card-1';
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.btn-primary')).toBeNull();
    expect(el.shadowRoot!.querySelector('.btn-outline')).not.toBeNull();
  });

  it('does not render denied organization password, TOTP, or edit controls', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, value: 'must-not-load' }));
    const getTotp = vi.fn(async (): Promise<TotpFetchResult> => ({
      ok: true,
      totp: { code: '123456', period: 30, remaining: 20 },
    }));
    const item = login({
      organizationId: 'org-1',
      hasTotp: true,
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: true,
        viewTotp: false,
      },
    });
    const el = await mount({
      items: [item],
      selectedCipherId: item.id,
      extras: detailExtras({ getField, getTotp }),
    });
    await flushAsync();
    await el.updateComplete;

    expect(el.shadowRoot?.querySelector('.icon-sm.eye')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-copy-password]')).toBeNull();
    expect(el.shadowRoot?.querySelector('vw-totp-meter')).toBeNull();
    expect(el.shadowRoot?.querySelector('.btn-outline')).not.toBeNull();
    expect([...el.shadowRoot!.querySelectorAll('.btn-outline')]
      .some((button) => button.textContent?.trim() === 'Edit')).toBe(false);
    expect(el.shadowRoot?.querySelector('.btn-primary')).not.toBeNull();
    expect(getField).not.toHaveBeenCalled();
    expect(getTotp).not.toHaveBeenCalled();
  });

  it('shows the passkey marker only for items with a passkey', async () => {
    const withPk = await mount({ items: [login({ hasPasskey: true })] });
    expect(withPk.shadowRoot?.querySelector('.pk')).not.toBeNull();
    withPk.remove();
    const without = await mount({ items: [login()] });
    expect(without.shadowRoot?.querySelector('.pk')).toBeNull();
  });

  it('shows a Fill pill for current-site suggestions and emits vw-suggestion-fill', async () => {
    const el = await mount({
      suggestionsState: {
        status: 'ready',
        suggestions: [{
          kind: 'login', id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false,
          target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 3, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
        }],
      },
    });
    const fired = vi.fn();
    el.addEventListener('vw-suggestion-fill', fired);
    const pill = el.shadowRoot!.querySelector<HTMLButtonElement>('.fill-pill')!;
    expect(pill).not.toBeNull();
    pill.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        cipherId: 'c1',
        target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 3, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
      },
    }));
  });

  it('renders structured suggestion metadata and preserves its target for fill while detail stays available', async () => {
    const el = await mount({
      items: [
        login(),
        { id: 'card-1', name: 'Travel Card', uris: [], loginUris: [], type: 3, favorite: false, subtitle: 'Visa' },
        { id: 'identity-1', name: 'Personal', uris: [], loginUris: [], type: 4, favorite: false, subtitle: 'Mina Chen' },
      ],
      suggestionsState: {
        status: 'ready',
        suggestions: [
          {
            kind: 'card', id: 'card-1', name: 'Travel Card', subtitle: 'Visa', favorite: false,
            target: {
              kind: 'card', frameId: 0, formId: 'payment', documentId: 'doc-0',
              runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 4,
              roles: ['cardholderName', 'number'],
            },
          },
          {
            kind: 'identity', id: 'identity-1', name: 'Personal', subtitle: 'Mina Chen', favorite: false,
            target: {
              kind: 'identity', frameId: 0, formId: 'profile', documentId: 'doc-0',
              runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 4,
              roles: ['firstName', 'lastName'],
            },
          },
        ],
      },
    });
    const fill = vi.fn();
    const open = vi.fn();
    el.addEventListener('vw-suggestion-fill', fill);
    el.addEventListener('vw-item-open', open);

    const rows = el.shadowRoot!.querySelectorAll<HTMLElement>('.hero-account');
    expect(rows).toHaveLength(2);
    expect(rows[0]?.dataset.kind).toBe('card');
    expect(rows[0]?.textContent).toContain('Visa');
    expect(rows[0]?.textContent).toContain('Card');
    expect(rows[1]?.dataset.kind).toBe('identity');
    expect(rows[1]?.textContent).toContain('Mina Chen');
    expect(rows[1]?.textContent).toContain('Identities');

    rows[0]!.querySelector<HTMLButtonElement>('.fill-pill')!.click();
    expect(fill).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        cipherId: 'card-1',
        target: {
          kind: 'card', frameId: 0, formId: 'payment', documentId: 'doc-0',
          runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 4,
          roles: ['cardholderName', 'number'],
        },
      },
    }));
    rows[1]!.querySelector<HTMLButtonElement>('.hero-account-main')!.click();
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'identity-1' } }));
  });

  it('renders every list row without a delayed entrance', async () => {
    const items = Array.from({ length: 15 }, (_, i) => login({ id: `c${i}`, name: `Item ${i}` }));
    const el = await mount({ items });
    const rows = el.shadowRoot!.querySelectorAll<HTMLElement>('.row');
    expect(rows).toHaveLength(15);
    expect([...rows].every((row) => !(row.getAttribute('style') ?? '').includes('animation-delay'))).toBe(true);
  });

  it('opens workspace details without expanding or loading inline secrets', async () => {
    const getTotp = vi.fn(async () => ({ ok: true as const, totp: null }));
    const el = await mount({
      compactDetails: false,
      selectedCipherId: 'c1',
      items: [login({ hasTotp: true })],
      extras: detailExtras({ getTotp }),
    });
    const open = vi.fn();
    const toggle = vi.fn();
    el.addEventListener('vw-item-open', open);
    el.addEventListener('vw-item-toggle', toggle);
    el.shadowRoot!.querySelector<HTMLButtonElement>('.row-main')!.click();
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'c1' } }));
    expect(toggle).not.toHaveBeenCalled();
    expect(el.shadowRoot!.querySelector('.card')).toBeNull();
    expect(el.shadowRoot!.querySelector('.row-main')?.getAttribute('aria-current')).toBe('true');
    expect(getTotp).not.toHaveBeenCalled();
  });

  it('shows a copy shortcut only for the item that owns the selected detail loaders', async () => {
    const el = await mount({
      selectedCipherId: 'second',
      items: [login({ id: 'first', name: 'Alpha' }), login({ id: 'second', name: 'Beta' })],
    });
    const rows = el.shadowRoot!.querySelectorAll<HTMLElement>('.row');
    expect(rows[0]!.querySelector('.row-copy')).toBeNull();
    expect(rows[1]!.querySelector('.row-copy')).not.toBeNull();
  });

  it('renders detail feedback owned by the popup root', async () => {
    const el = await mount({
      selectedCipherId: 'c1',
      status: { message: 'Copy failed', tone: 'danger' },
    });
    const status = el.shadowRoot!.querySelector<HTMLElement & { message: string }>('vw-status-message');
    expect(status?.getAttribute('tone')).toBe('danger');
    expect(status?.message).toBe('Copy failed');
  });

  it('clears a revealed password before rendering a newly selected item', async () => {
    const firstExtras = detailExtras({
      getField: async () => ({ ok: true, value: 'alpha-secret' }),
    });
    const secondExtras = detailExtras({
      getField: async () => ({ ok: true, value: 'bravo-secret' }),
    });
    const el = await mount({
      items: [
        login({ id: 'a', name: 'Alpha' }),
        login({ id: 'b', name: 'Bravo' }),
      ],
      selectedCipherId: 'a',
      extras: firstExtras,
    });

    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    await flushAsync();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.field-val.mono')?.textContent).toBe('alpha-secret');

    el.selectedCipherId = 'b';
    el.extras = secondExtras;
    await el.updateComplete;

    const secondPassword = el.shadowRoot!.querySelector('.field-val.mono')!;
    expect(secondPassword.textContent).not.toContain('alpha-secret');
    expect(secondPassword.classList.contains('masked')).toBe(true);
  });

  it('acknowledges inline reveal once only after the visible password is rendered', async () => {
    const acknowledgeVisible = vi.fn();
    const el = await mount({
      selectedCipherId: 'c1',
      extras: detailExtras({
        getField: async () => ({
          ok: true,
          value: 'visible-secret',
          acknowledgeVisible,
        }),
      }),
    });

    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    expect(acknowledgeVisible).not.toHaveBeenCalled();
    await flushAsync();
    await el.updateComplete;

    const password = el.shadowRoot!.querySelector<HTMLElement>('.field-val.mono');
    expect(password?.classList.contains('masked')).toBe(false);
    expect(password?.textContent).toBe('visible-secret');
    expect(acknowledgeVisible).toHaveBeenCalledOnce();
    await flushAsync();
    expect(acknowledgeVisible).toHaveBeenCalledOnce();
  });

  it('does not acknowledge an inline reveal whose selection changes before render completion', async () => {
    const acknowledgeVisible = vi.fn();
    const render = deferred<boolean>();
    const el = await mount({
      items: [login({ id: 'a', name: 'Alpha' }), login({ id: 'b', name: 'Bravo' })],
      selectedCipherId: 'a',
      extras: detailExtras({
        getField: async () => ({ ok: true, value: 'alpha-secret', acknowledgeVisible }),
      }),
    });
    Object.defineProperty(el, 'updateComplete', {
      configurable: true,
      get: () => render.promise,
    });

    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    await Promise.resolve();
    el.selectedCipherId = 'b';
    render.resolve(true);
    await flushAsync();

    expect(acknowledgeVisible).not.toHaveBeenCalled();
  });

  it('does not acknowledge an inline reveal after the component disconnects', async () => {
    const acknowledgeVisible = vi.fn();
    const render = deferred<boolean>();
    const el = await mount({
      selectedCipherId: 'c1',
      extras: detailExtras({
        getField: async () => ({ ok: true, value: 'secret', acknowledgeVisible }),
      }),
    });
    Object.defineProperty(el, 'updateComplete', {
      configurable: true,
      get: () => render.promise,
    });

    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    await Promise.resolve();
    el.remove();
    render.resolve(true);
    await flushAsync();

    expect(acknowledgeVisible).not.toHaveBeenCalled();
  });

  it('ignores a password response that arrives after the selection changes', async () => {
    const pendingPassword = deferred<{ ok: true; value: string }>();
    const firstGetField = vi.fn(() => pendingPassword.promise);
    const el = await mount({
      items: [
        login({ id: 'a', name: 'Alpha' }),
        login({ id: 'b', name: 'Bravo' }),
      ],
      selectedCipherId: 'a',
      extras: detailExtras({ getField: firstGetField }),
    });

    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    expect(firstGetField).toHaveBeenCalledTimes(1);
    el.selectedCipherId = 'b';
    el.extras = detailExtras();
    await el.updateComplete;

    pendingPassword.resolve({ ok: true, value: 'late-alpha-secret' });
    await flushAsync();
    await el.updateComplete;

    const password = el.shadowRoot!.querySelector('.field-val.mono')!;
    expect(password.textContent).not.toContain('late-alpha-secret');
    expect(password.classList.contains('masked')).toBe(true);
  });

  it('ignores a password response from replaced extras for the same selection', async () => {
    const pendingPassword = deferred<{ ok: true; value: string }>();
    const staleExtras = detailExtras({ getField: () => pendingPassword.promise });
    const currentExtras = detailExtras({
      getField: async () => ({ ok: true, value: 'current-secret' }),
    });
    const el = await mount({ selectedCipherId: 'c1', extras: staleExtras });

    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    el.extras = currentExtras;
    await el.updateComplete;
    pendingPassword.resolve({ ok: true, value: 'stale-secret' });
    await flushAsync();
    await el.updateComplete;

    expect(el.shadowRoot!.querySelector('.field-val.mono')?.textContent).not.toContain('stale-secret');
    el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!.click();
    await flushAsync();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.field-val.mono')?.textContent).toBe('current-secret');
  });

  it('guards concurrent TOTP loads with an in-flight flag', async () => {
    let calls = 0;
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => { release = r; });
    const extras = {
      getField: async () => ({ ok: false }),
      getCustomField: async () => ({ ok: false }),
      getTotp: async () => { calls++; await gate; return { ok: true, totp: null }; },
      getPasswordHistory: async () => ({ ok: true, history: [] }),
    } as unknown as VwVaultView['extras'];
    const el = await mount({ selectedCipherId: 'c1', extras });
    // Two overlapping loads: the second must early-return while the first is still awaiting.
    const first = (el as unknown as { loadTotp(): Promise<void> }).loadTotp();
    const second = (el as unknown as { loadTotp(): Promise<void> }).loadTotp();
    expect(calls).toBe(1);
    release();
    await Promise.all([first, second]);
  });

  it('keeps a loaded TOTP visible after starting its countdown timer', async () => {
    const el = await mount({
      items: [login({ hasTotp: true })],
      selectedCipherId: 'c1',
      extras: detailExtras({
        getTotp: async () => ({ ok: true, totp: { code: '123456', period: 30, remaining: 28 } }),
      }),
    });

    await flushAsync();
    await el.updateComplete;

    const meter = el.shadowRoot!.querySelector<HTMLElement & { code: string }>('vw-totp-meter');
    expect(meter).not.toBeNull();
    expect(meter!.code).toBe('123456');
  });

  it('lets B load TOTP while A is pending and ignores A when it later resolves', async () => {
    const pendingFirst = deferred<TotpFetchResult>();
    const firstGetTotp = vi.fn(() => pendingFirst.promise);
    const secondGetTotp = vi.fn(async () => ({
      ok: true as const,
      totp: { code: '222222', period: 30, remaining: 25 },
    }));
    const el = await mount({
      items: [
        login({ id: 'a', name: 'Alpha', hasTotp: true }),
        login({ id: 'b', name: 'Bravo', hasTotp: true }),
      ],
      selectedCipherId: 'a',
      extras: detailExtras({ getTotp: firstGetTotp }),
    });
    expect(firstGetTotp).toHaveBeenCalledTimes(1);

    el.selectedCipherId = 'b';
    el.extras = detailExtras({ getTotp: secondGetTotp });
    await el.updateComplete;
    await flushAsync();
    await el.updateComplete;

    expect(secondGetTotp).toHaveBeenCalledTimes(1);
    let meter = el.shadowRoot!.querySelector<HTMLElement & { code: string }>('vw-totp-meter');
    expect(meter?.code).toBe('222222');

    pendingFirst.resolve({ ok: true, totp: { code: '111111', period: 30, remaining: 24 } });
    await flushAsync();
    await el.updateComplete;

    meter = el.shadowRoot!.querySelector<HTMLElement & { code: string }>('vw-totp-meter');
    expect(meter?.code).toBe('222222');
  });

  it('does not retain a late TOTP or restart its timer after disconnect', async () => {
    const pending = deferred<TotpFetchResult>();
    const el = await mount({
      items: [login({ hasTotp: true })],
      selectedCipherId: 'c1',
      extras: detailExtras({ getTotp: () => pending.promise }),
    });
    el.remove();
    pending.resolve({ ok: true, totp: { code: '123456', period: 30, remaining: 25 } });
    await flushAsync();
    const state = el as unknown as { totp: unknown; totpTimer: number | undefined };
    expect(state.totp).toBeUndefined();
    expect(state.totpTimer).toBeUndefined();
  });

  it('surfaces a status banner when revealing a secret is refused (no silent failure)', async () => {
    const extras = {
      getField: async () => ({ ok: false }),
      getCustomField: async () => ({ ok: false }),
      getTotp: async () => ({ ok: true, totp: null }),
      getPasswordHistory: async () => ({ ok: true, history: [] }),
    } as unknown as VwVaultView['extras'];
    const el = await mount({ selectedCipherId: 'c1', extras });
    expect(el.shadowRoot!.querySelector('vw-status-message')).toBeNull();
    const eye = el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!;
    expect(eye).not.toBeNull();
    eye.click();
    // reveal() awaits getField, then sets the status and requests an update.
    await new Promise((r) => setTimeout(r));
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('vw-status-message')).not.toBeNull();
  });

  it('keeps an explicit Fill continuation but hides copy for a reprompt-protected suggestion', async () => {
    const el = await mount({
      items: [login({ id: 'c1', reprompt: true })],
      suggestionsState: {
        status: 'ready',
        suggestions: [{
          kind: 'login', id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false, reprompt: true,
          target: { kind: 'login', frameId: 0, formId: 'f1', documentId: 'doc-0', runtimeIncarnation: TARGET_RUNTIME_INCARNATION, generation: 1, customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST },
        }],
      },
    });
    const fill = vi.fn();
    el.addEventListener('vw-suggestion-fill', fill);
    el.shadowRoot!.querySelector<HTMLButtonElement>('.fill-pill')!.click();
    expect(fill).toHaveBeenCalledWith(expect.objectContaining({ detail: {
      cipherId: 'c1',
      target: expect.objectContaining({ formId: 'f1' }),
    } }));
    expect(el.shadowRoot!.querySelector('.row-copy')).toBeNull();
    // The row itself still opens detail without creating a fill continuation.
    expect(el.shadowRoot!.querySelector('.chev')).not.toBeNull();
  });

  it('opens reprompt items in the full detail flow instead of creating inline loaders', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, value: 'must-not-load' }));
    const el = await mount({ items: [login({ reprompt: true })], extras: detailExtras({ getField }) });
    const opened = vi.fn();
    el.addEventListener('vw-item-open', opened);
    el.shadowRoot!.querySelector<HTMLButtonElement>('.row-main')!.click();
    expect(opened).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'c1' } }));
    expect(getField).not.toHaveBeenCalled();
  });

  it('shows only deleted items in trash mode and exposes a way back', async () => {
    const el = await mount({
      mode: 'trash',
      items: [login({ id: 'live' }), login({ id: 'deleted', name: 'Deleted', deletedDate: '2026-01-01T00:00:00Z' })],
      suggestionsState: {
        status: 'ready',
        suggestions: [{ kind: 'login', id: 'live', name: 'Live', matchedUri: 'https://example.test', matchType: 0, favorite: false }],
      },
    });
    expect(el.shadowRoot?.textContent).toContain('Deleted');
    expect(el.shadowRoot?.textContent).not.toContain('Nebula');
    expect(el.shadowRoot?.querySelector('.chips')).toBeNull();
    expect(el.shadowRoot?.querySelector('.hero')).toBeNull();
    expect(el.shadowRoot?.querySelector('.row-copy')).toBeNull();
    const back = vi.fn();
    el.addEventListener('vw-vault-mode-change', back);
    el.shadowRoot!.querySelector<HTMLButtonElement>('.mode-back')!.click();
    expect(back).toHaveBeenCalledWith(expect.objectContaining({ detail: { mode: 'active' } }));
  });

  it('partitions active, archived, and deleted items into mutually exclusive modes', async () => {
    const archived = login({
      id: 'archived',
      name: 'Archived',
      archivedDate: '2026-08-30T00:00:00Z',
    });
    const deletedArchived = login({
      id: 'deleted-archived',
      name: 'Deleted archived',
      archivedDate: '2026-08-29T00:00:00Z',
      deletedDate: '2026-08-30T00:00:00Z',
    });
    const el = await mount({ items: [login({ id: 'live', name: 'Live' }), archived, deletedArchived] });
    expect(el.renderRoot.textContent).toContain('Live');
    expect(el.renderRoot.textContent).not.toContain('Archived');
    expect(el.renderRoot.textContent).not.toContain('Deleted archived');

    el.mode = 'archive';
    await el.updateComplete;
    expect(el.renderRoot.textContent).toContain('Archived');
    expect(el.renderRoot.textContent).not.toContain('Deleted archived');

    el.mode = 'trash';
    await el.updateComplete;
    expect(el.renderRoot.textContent).toContain('Deleted archived');
    expect(el.renderRoot.textContent).not.toContain('Live');
  });

  it('offers a typed one-shot unarchive action without loading archived secrets', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, value: 'must-not-load' }));
    const getTotp = vi.fn(async () => ({
      ok: true as const,
      totp: { code: '123456', period: 30, remaining: 20 },
    }));
    const el = await mount({
      mode: 'archive',
      items: [login({
        id: 'archived',
        name: 'Archived',
        archivedDate: '2026-08-30T00:00:00Z',
        hasTotp: true,
      })],
      selectedCipherId: 'archived',
      extras: detailExtras({ getField, getTotp }),
      status: { message: 'Server rejected unarchive', tone: 'danger' },
      suggestionsState: {
        status: 'ready',
        suggestions: [{
          kind: 'login', id: 'archived', name: 'Archived', matchedUri: 'https://example.test', matchType: 0, favorite: false,
        }],
      },
    });
    const unarchive = vi.fn();
    el.addEventListener('vw-unarchive-item', unarchive);
    const button = el.shadowRoot!.querySelector<HTMLButtonElement>('[data-unarchive]')!;
    button.click();
    button.click();

    expect(unarchive).toHaveBeenCalledTimes(1);
    expect(unarchive).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        action: 'unarchive',
        cipherId: 'archived',
        sourceMode: 'archive',
        targetMode: 'active',
      },
    }));
    expect(getField).not.toHaveBeenCalled();
    expect(getTotp).not.toHaveBeenCalled();
    expect(el.shadowRoot?.querySelector<HTMLElement & { message: string }>('.mode-status')?.message)
      .toBe('Server rejected unarchive');
    expect(el.shadowRoot?.querySelector('.chips')).toBeNull();
    expect(el.shadowRoot?.querySelector('.hero')).toBeNull();
    expect(el.shadowRoot?.querySelector('.commands')).toBeNull();
  });
});
