// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './item-detail.js';
import type { VwItemDetail } from './item-detail.js';
import type { CipherSummary, DecryptedCipher } from '../../../core/vault/models.js';
import type { DetailExtras } from '../types.js';

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return {
    id: 'cipher-1',
    name: 'GitHub',
    uris: ['https://github.com'],
    loginUris: [{ uri: 'https://github.com' }],
    type: 1,
    favorite: false,
    ...overrides,
  };
}

function detail(overrides: Partial<DecryptedCipher> = {}): DecryptedCipher {
  return { ...summary(), ...overrides };
}

function stubExtras(overrides: Partial<DetailExtras> = {}): DetailExtras {
  return {
    getField: vi.fn(async () => ({ ok: true, value: undefined })),
    getCustomField: vi.fn(async () => ({ ok: true, value: undefined })),
    getTotp: vi.fn(async () => ({ ok: true, totp: null })),
    getPasswordHistory: vi.fn(async () => ({ ok: true, history: [] })),
    ...overrides,
  };
}

async function mount(
  s: CipherSummary,
  cipher: DecryptedCipher | null = null,
  extras: DetailExtras = stubExtras(),
): Promise<VwItemDetail> {
  const el = document.createElement('vw-item-detail') as VwItemDetail;
  el.summary = s;
  el.cipher = cipher;
  el.extras = extras;
  document.body.append(el);
  await el.updateComplete;
  await Promise.resolve();
  await el.updateComplete;
  return el;
}

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function q<T extends Element>(el: VwItemDetail, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-item-detail login', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders the name, username subtitle and a safe website link', async () => {
    const el = await mount(summary({ username: 'octocat' }));
    expect(el.shadowRoot?.textContent).toContain('GitHub');
    expect(el.shadowRoot?.textContent).toContain('octocat');
    const link = q<HTMLAnchorElement>(el, 'a[data-uri]');
    expect(link.href).toBe('https://github.com/');
  });

  it('renders a dedicated detail scroll region and field groups', async () => {
    const el = await mount(summary({ username: 'octocat' }));
    expect(el.shadowRoot!.querySelector('[data-detail-scroll]')).not.toBeNull();
    expect(el.shadowRoot!.querySelectorAll('[data-field-group]').length).toBeGreaterThan(0);
  });

  it('renders a javascript: uri as plain text, never a link', async () => {
    const el = await mount(summary({ uris: ['javascript:alert(1)'] }));
    expect(el.shadowRoot?.querySelector('a[data-uri]')).toBeNull();
    expect(el.shadowRoot?.querySelector('a[href*="javascript"]')).toBeNull();
    expect(el.shadowRoot?.textContent).toContain('javascript:alert(1)');
  });

  it('keeps the password masked until an explicit reveal', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, value: 's3cret' }));
    const el = await mount(summary(), null, stubExtras({ getField }));
    const code = q<HTMLElement>(el, '[data-password-value]');
    expect(code.textContent).not.toContain('s3cret');
    expect(getField).not.toHaveBeenCalled();

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await flush();
    await el.updateComplete;
    expect(getField).toHaveBeenCalledWith('password');
    expect(q<HTMLElement>(el, '[data-password-value]').textContent).toContain('s3cret');

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await el.updateComplete;
    expect(q<HTMLElement>(el, '[data-password-value]').textContent).not.toContain('s3cret');
  });

  it('requests the root fetch+copy the password without holding it', async () => {
    const el = await mount(summary());
    const req = vi.fn();
    el.addEventListener('vw-secret-request', req);
    q<HTMLButtonElement>(el, '[data-copy-password]').click();
    expect(req).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { kind: 'field', field: 'password', label: 'Password' } }),
    );
  });

  it('copies a non-secret username via vw-copy', async () => {
    const el = await mount(summary({ username: 'octocat' }));
    const copy = vi.fn();
    el.addEventListener('vw-copy', copy);
    q<HTMLButtonElement>(el, '[data-copy-username]').click();
    expect(copy).toHaveBeenCalledWith(expect.objectContaining({ detail: { value: 'octocat', label: 'Username' } }));
  });

  it('shows a passkey notice when the login carries one', async () => {
    const el = await mount(summary({ hasPasskey: true }));
    expect(el.shadowRoot?.textContent?.toLowerCase()).toContain('passkey');
  });
});

describe('vw-item-detail TOTP', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    document.body.replaceChildren();
  });

  async function settle(el: VwItemDetail): Promise<void> {
    await vi.advanceTimersByTimeAsync(0);
    await el.updateComplete;
  }

  it('loads, formats and refreshes the code at expiry, and clears the timer on disconnect', async () => {
    const getTotp = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, totp: { code: '081804', period: 30, remaining: 2 } })
      .mockResolvedValue({ ok: true, totp: { code: '222333', period: 30, remaining: 30 } });
    const el = await mount(summary({ hasTotp: true }), null, stubExtras({ getTotp }));
    await settle(el);
    expect(q<HTMLElement>(el, '[data-totp]').textContent).toContain('081 804');
    expect(el.shadowRoot?.textContent).toContain('2s');

    await vi.advanceTimersByTimeAsync(1000);
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).toContain('1s');

    await vi.advanceTimersByTimeAsync(1000);
    await el.updateComplete;
    expect(getTotp).toHaveBeenCalledTimes(2);
    expect(q<HTMLElement>(el, '[data-totp]').textContent).toContain('222 333');

    el.remove();
    getTotp.mockClear();
    await vi.advanceTimersByTimeAsync(5000);
    expect(getTotp).not.toHaveBeenCalled();
  });
});

describe('vw-item-detail history', () => {
  afterEach(() => document.body.replaceChildren());

  it('reveals decrypted history on demand and copies an entry', async () => {
    const getPasswordHistory = vi.fn(async () => ({
      ok: true as const,
      history: [{ password: 'old-pass', lastUsedDate: '2024-01-01T00:00:00Z' }],
    }));
    const el = await mount(summary({ passwordHistoryCount: 1 }), null, stubExtras({ getPasswordHistory }));
    expect(el.shadowRoot?.textContent).not.toContain('old-pass');
    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    await flush();
    await el.updateComplete;
    expect(getPasswordHistory).toHaveBeenCalledTimes(1);
    expect(el.shadowRoot?.textContent).toContain('old-pass');

    const copy = vi.fn();
    el.addEventListener('vw-copy', copy);
    q<HTMLButtonElement>(el, '[data-history-copy]').click();
    expect(copy).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { value: 'old-pass', label: 'Previous password' } }),
    );
  });
});

describe('vw-item-detail secure note', () => {
  afterEach(() => document.body.replaceChildren());

  it('auto-loads and displays the note body', async () => {
    const getField = vi.fn(async () => ({ ok: true as const, value: 'the note body' }));
    const el = await mount(summary({ type: 2, name: 'Note' }), detail({ type: 2, name: 'Note' }), stubExtras({ getField }));
    await flush();
    await el.updateComplete;
    expect(getField).toHaveBeenCalledWith('notes');
    expect(q<HTMLElement>(el, '[data-note]').textContent).toContain('the note body');
  });
});

describe('vw-item-detail custom fields', () => {
  afterEach(() => document.body.replaceChildren());

  it('shows plain fields inline and masks hidden fields until reveal', async () => {
    const cipher = detail({
      fields: [
        { type: 0, name: 'Account', value: 'acct-123' },
        { type: 2, name: 'Enabled', value: 'true' },
        { type: 1, name: 'Recovery' },
      ],
    });
    const getCustomField = vi.fn(async () => ({ ok: true as const, value: 'hidden-secret' }));
    const el = await mount(summary(), cipher, stubExtras({ getCustomField }));
    expect(el.shadowRoot?.textContent).toContain('acct-123');
    expect(el.shadowRoot?.textContent).toContain('Yes');
    expect(el.shadowRoot?.textContent).not.toContain('hidden-secret');

    q<HTMLButtonElement>(el, '[data-cf-reveal]').click();
    await flush();
    await el.updateComplete;
    expect(getCustomField).toHaveBeenCalledWith(2);
    expect(el.shadowRoot?.textContent).toContain('hidden-secret');
  });

  it('requests root fetch+copy for a hidden custom field', async () => {
    const cipher = detail({ fields: [{ type: 1, name: 'Recovery' }] });
    const el = await mount(summary(), cipher);
    const req = vi.fn();
    el.addEventListener('vw-secret-request', req);
    q<HTMLButtonElement>(el, '[data-cf-copy]').click();
    expect(req).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { kind: 'customField', index: 0, label: 'Recovery' } }),
    );
  });
});

describe('vw-item-detail card and identity', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders card plain fields and masks secret fields until reveal', async () => {
    const cipher = detail({
      type: 3,
      card: { brand: 'Visa', cardholderName: 'A Cardholder', expMonth: '04', expYear: '27' },
    });
    const getField = vi.fn(async () => ({ ok: true as const, value: '4111111111111111' }));
    const el = await mount(summary({ type: 3, name: 'My Card' }), cipher, stubExtras({ getField }));
    expect(el.shadowRoot?.textContent).toContain('Visa');
    expect(el.shadowRoot?.textContent).toContain('A Cardholder');
    expect(el.shadowRoot?.textContent).toContain('04 / 27');
    expect(el.shadowRoot?.textContent).not.toContain('4111111111111111');

    q<HTMLButtonElement>(el, '[data-reveal="card.number"]').click();
    await flush();
    await el.updateComplete;
    expect(getField).toHaveBeenCalledWith('card.number');
    expect(el.shadowRoot?.textContent).toContain('4111111111111111');
  });

  it('renders identity plain fields and masks the SSN', async () => {
    const cipher = detail({
      type: 4,
      identity: { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.test' },
    });
    const el = await mount(summary({ type: 4, name: 'Me' }), cipher);
    expect(el.shadowRoot?.textContent).toContain('Ada Lovelace');
    expect(el.shadowRoot?.textContent).toContain('ada@example.test');
    expect(el.shadowRoot?.querySelector('[data-reveal="identity.ssn"]')).not.toBeNull();
  });
});

describe('vw-item-detail attachments', () => {
  afterEach(() => document.body.replaceChildren());

  it('emits download and delete with the ids only in the event detail', async () => {
    const cipher = detail({ attachments: [{ id: 'att-9', fileName: 'notes.txt', sizeName: '1 KB' }] });
    const el = await mount(summary(), cipher);
    expect(el.shadowRoot?.innerHTML).not.toContain('att-9');

    const download = vi.fn();
    const del = vi.fn();
    el.addEventListener('vw-attachment-download', download);
    el.addEventListener('vw-attachment-delete', del);
    q<HTMLButtonElement>(el, '[data-att-download]').click();
    q<HTMLButtonElement>(el, '[data-att-delete]').click();
    expect(download).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { cipherId: 'cipher-1', attachmentId: 'att-9', fileName: 'notes.txt' } }),
    );
    expect(del).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { cipherId: 'cipher-1', attachmentId: 'att-9', fileName: 'notes.txt' } }),
    );
  });

  it('reads a chosen file to base64 and emits vw-attachment-add', async () => {
    const cipher = detail({ attachments: [] });
    const el = await mount(summary(), cipher);
    const add = vi.fn();
    el.addEventListener('vw-attachment-add', add);
    const input = q<HTMLInputElement>(el, 'input[type="file"]');
    const file = new File([new Uint8Array([104, 105])], 'hi.txt');
    Object.defineProperty(input, 'files', { value: [file], configurable: true });
    input.dispatchEvent(new Event('change'));
    await flush();
    expect(add).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { cipherId: 'cipher-1', fileName: 'hi.txt', dataB64: btoa('hi') } }),
    );
  });
});

describe('vw-item-detail actions', () => {
  afterEach(() => document.body.replaceChildren());

  it('emits vw-edit-item', async () => {
    const el = await mount(summary());
    const edit = vi.fn();
    el.addEventListener('vw-edit-item', edit);
    q<HTMLButtonElement>(el, '[data-edit]').click();
    expect(edit).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'cipher-1' } }));
  });

  it('requires a confirm step before emitting vw-delete-item (soft delete)', async () => {
    const el = await mount(summary());
    const del = vi.fn();
    el.addEventListener('vw-delete-item', del);
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await el.updateComplete;
    expect(del).not.toHaveBeenCalled();
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    expect(del).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { cipherId: 'cipher-1', permanent: false } }),
    );
  });

  it('offers restore and permanent delete for a trashed item', async () => {
    const el = await mount(summary({ deletedDate: '2024-01-01T00:00:00Z' }));
    expect(el.shadowRoot?.querySelector('[data-edit]')).toBeNull();
    const restore = vi.fn();
    const del = vi.fn();
    el.addEventListener('vw-restore-item', restore);
    el.addEventListener('vw-delete-item', del);
    q<HTMLButtonElement>(el, '[data-restore]').click();
    expect(restore).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'cipher-1' } }));
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    expect(del).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { cipherId: 'cipher-1', permanent: true } }),
    );
  });

  it('emits vw-item-back from the header', async () => {
    const el = await mount(summary());
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    q<HTMLButtonElement>(el, '[data-back]').click();
    expect(back).toHaveBeenCalledTimes(1);
  });
});
