// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './item-detail.js';
import type { VwDialog } from '../../components/dialog.js';
import { setLocale } from '../../i18n/index.js';
import type { CipherSummary, DecryptedCipher, KnownCipherSummary, SshKeyPublicDetails } from '../../../core/vault/models.js';
import type {
  DetailExtras,
  DetailPresentationMetadata,
  FavoriteToggleDetail,
  HistoryFetchResult,
  SecretResult,
  SshDetailExtras,
  TotpFetchResult,
  VaultMode,
} from '../types.js';
import type { ItemPrimaryAction, VwItemDetail } from './item-detail.js';

const MAX_ATTACHMENT_FILE_BYTES = (128 * 1024 * 1024) - 65;

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function summary(overrides: Partial<KnownCipherSummary> = {}): KnownCipherSummary {
  return {
    id: 'cipher-1',
    name: 'GitHub',
    username: 'octocat',
    uris: ['https://github.com'],
    loginUris: [{ uri: 'https://github.com' }],
    type: 1,
    favorite: false,
    ...overrides,
  };
}

function detail(base: KnownCipherSummary, overrides: Partial<DecryptedCipher> = {}): DecryptedCipher {
  return { ...base, ...overrides };
}

function extras(overrides: Partial<DetailExtras> = {}): DetailExtras {
  return {
    getField: vi.fn(async () => ({ ok: true, value: undefined })),
    getCustomField: vi.fn(async () => ({ ok: true, value: undefined })),
    getTotp: vi.fn(async () => ({ ok: true, totp: null })),
    getPasswordHistory: vi.fn(async () => ({ ok: true, history: [] })),
    ...overrides,
  };
}

async function mount(options: {
  summary?: CipherSummary;
  cipher?: DecryptedCipher | null;
  extras?: DetailExtras;
  presentationMetadata?: DetailPresentationMetadata;
  mode?: VaultMode;
  pending?: boolean;
  sshKey?: SshKeyPublicDetails | null;
  sshExtras?: SshDetailExtras;
  sshEditable?: boolean;
  primaryAction?: ItemPrimaryAction;
} = {}): Promise<VwItemDetail> {
  const item = options.summary ?? summary();
  const el = document.createElement('vw-item-detail') as VwItemDetail;
  el.summary = item;
  el.cipher = options.cipher === undefined
    ? item.unsupported ? null : detail(item)
    : options.cipher;
  el.extras = options.extras ?? extras();
  el.presentationMetadata = options.presentationMetadata;
  el.mode = options.mode ?? 'active';
  el.pending = options.pending ?? false;
  el.sshKey = options.sshKey;
  el.sshExtras = options.sshExtras;
  el.sshEditable = options.sshEditable ?? false;
  el.primaryAction = options.primaryAction
    ?? (item.type === 1 && item.uris.length > 0 ? 'open' : 'none');
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwItemDetail, selector: string): T {
  return el.shadowRoot!.querySelector<T>(selector)!;
}

async function flush(el?: VwItemDetail): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  if (el) await el.updateComplete;
}

async function settleDialog(el: VwItemDetail): Promise<VwDialog> {
  await el.updateComplete;
  const dialog = q<VwDialog>(el, 'vw-dialog');
  await dialog.updateComplete;
  return dialog;
}

beforeEach(() => setLocale('en', false));
afterEach(() => {
  document.body.replaceChildren();
  vi.useRealTimers();
});

describe('vw-item-detail presentation and events', () => {
  it('renders a full-height header with back, name, type and edit controls', async () => {
    const el = await mount();
    expect(q(el, '[data-back]')).toBeTruthy();
    expect(q(el, '[data-edit]')).toBeTruthy();
    expect(q(el, 'h1').textContent).toBe('GitHub');
    expect(q(el, '.type').textContent).toBe('Login');
    expect(q(el, '.body')).toBeTruthy();
    expect(el.shadowRoot?.querySelector('.card')).toBeNull();
    expect(q(el, '[data-section="credentials"] [data-copy-password]')).toBeTruthy();
    expect(q(el, '[data-section="websites"] [data-uri]')).toBeTruthy();
    expect(q(el, '.body').contains(q(el, '[data-fill]'))).toBe(false);
  });

  it('offers clone for active and archived editable items and emits a typed direct intent', async () => {
    const active = await mount();
    const cloned = vi.fn();
    active.addEventListener('vw-clone-item', cloned);
    q<HTMLButtonElement>(active, '[data-clone]').click();
    expect(cloned).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', passkeyWarningAcknowledged: false },
    }));

    const archivedItem = summary({ archivedDate: '2026-08-30T00:00:00Z' });
    const archived = await mount({
      summary: archivedItem,
      cipher: detail(archivedItem),
      mode: 'archive',
    });
    expect(archived.shadowRoot?.querySelector('[data-clone]')).not.toBeNull();
  });

  it('requires an explicit passkey omission acknowledgement before cloning', async () => {
    const item = summary({ hasPasskey: true });
    const el = await mount({ summary: item, cipher: detail(item) });
    const cloned = vi.fn();
    el.addEventListener('vw-clone-item', cloned);

    q<HTMLButtonElement>(el, '[data-clone]').click();
    const dialog = await settleDialog(el);
    expect(dialog.heading).toBe('Passkey will not be copied');
    expect(cloned).not.toHaveBeenCalled();
    q<HTMLButtonElement>(el, '[data-confirm-clone]').click();
    await flush(el);

    expect(cloned).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', passkeyWarningAcknowledged: true },
    }));
  });

  it('does not offer clone for trash, SSH keys, or items without full read permission', async () => {
    const deletedItem = summary({ deletedDate: '2026-08-30T00:00:00Z' });
    const deleted = await mount({ summary: deletedItem, cipher: detail(deletedItem), mode: 'trash' });
    expect(deleted.shadowRoot?.querySelector('[data-clone]')).toBeNull();

    const sshItem = summary({ type: 5, uris: [], loginUris: [] });
    const ssh = await mount({ summary: sshItem, cipher: detail(sshItem) });
    expect(ssh.shadowRoot?.querySelector('[data-clone]')).toBeNull();

    const restrictedItem = summary({
      organizationId: 'org-1',
      access: {
        edit: true,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const restricted = await mount({ summary: restrictedItem, cipher: detail(restrictedItem) });
    expect(restricted.shadowRoot?.querySelector('[data-clone]')).toBeNull();
  });

  it('requires an explicit clone projection for organization items', async () => {
    const baseAccess = {
      edit: true, viewPassword: true, delete: false, restore: false,
      autofillTotp: false, viewTotp: false,
    };
    const denied = await mount({
      summary: summary({ organizationId: 'org-1', access: { ...baseAccess, clone: false } }),
    });
    expect(denied.shadowRoot?.querySelector('[data-clone]')).toBeNull();

    const allowed = await mount({
      summary: summary({ organizationId: 'org-1', access: { ...baseAccess, clone: true } }),
    });
    expect(allowed.shadowRoot?.querySelector('[data-clone]')).not.toBeNull();
  });

  it('emits a typed favorite intent without optimistically changing the summary', async () => {
    const el = await mount();
    const toggled = vi.fn<(event: CustomEvent<FavoriteToggleDetail>) => void>();
    el.addEventListener('vw-favorite-toggle', ((event: Event) => {
      toggled(event as CustomEvent<FavoriteToggleDetail>);
    }) as EventListener);
    const button = q<HTMLButtonElement>(el, '[data-favorite-toggle]');

    expect(button.getAttribute('aria-pressed')).toBe('false');
    expect(button.getAttribute('aria-label')).toBe('Add to favorites');
    expect(button.title).toBe('Add to favorites');
    button.click();

    expect(toggled).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', favorite: true },
      bubbles: true,
      composed: true,
    }));
    expect(el.summary.favorite).toBe(false);
    expect(button.getAttribute('aria-pressed')).toBe('false');

    const authoritative = summary({ favorite: true });
    el.summary = authoritative;
    el.cipher = detail(authoritative);
    await el.updateComplete;
    const updated = q<HTMLButtonElement>(el, '[data-favorite-toggle]');
    expect(updated.getAttribute('aria-pressed')).toBe('true');
    expect(updated.getAttribute('aria-label')).toBe('Remove from favorites');
    toggled.mockClear();
    updated.click();
    expect(toggled).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', favorite: false },
    }));
    expect(el.summary.favorite).toBe(true);
  });

  it('allows a read-only organization member to toggle per-user favorite metadata', async () => {
    const item = summary({
      organizationId: 'org-1',
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const el = await mount({ summary: item, cipher: detail(item) });
    const toggled = vi.fn();
    el.addEventListener('vw-favorite-toggle', toggled);

    expect(el.shadowRoot?.querySelector('[data-edit]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-favorite-toggle]').click();
    expect(toggled).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', favorite: true },
    }));
  });

  it('disables pending favorite changes and suppresses a second click once the root marks pending', async () => {
    const pending = await mount({ pending: true });
    const blocked = vi.fn();
    pending.addEventListener('vw-favorite-toggle', blocked);
    const disabled = q<HTMLButtonElement>(pending, '[data-favorite-toggle]');
    expect(disabled.disabled).toBe(true);
    disabled.click();
    expect(blocked).not.toHaveBeenCalled();

    pending.remove();
    const active = await mount();
    const toggled = vi.fn((event: Event) => {
      expect((event as CustomEvent<FavoriteToggleDetail>).detail.favorite).toBe(true);
      active.pending = true;
    });
    active.addEventListener('vw-favorite-toggle', toggled);
    const button = q<HTMLButtonElement>(active, '[data-favorite-toggle]');
    button.click();
    button.click();
    expect(toggled).toHaveBeenCalledTimes(1);
  });

  it('does not offer favorite mutation for archive, trash, or unsupported items', async () => {
    const archivedItem = summary({ archivedDate: '2026-08-30T00:00:00Z' });
    const archived = await mount({ summary: archivedItem, cipher: detail(archivedItem), mode: 'archive' });
    expect(archived.shadowRoot?.querySelector('[data-favorite-toggle]')).toBeNull();

    const trashedItem = summary({ deletedDate: '2026-08-30T00:00:00Z' });
    const trashed = await mount({ summary: trashedItem, cipher: detail(trashedItem), mode: 'trash' });
    expect(trashed.shadowRoot?.querySelector('[data-favorite-toggle]')).toBeNull();

    const unsupportedSummary: CipherSummary = {
      id: 'future', name: '(unsupported item)', uris: [], loginUris: [], type: 6,
      favorite: true, unsupported: true, undecryptable: true,
    };
    const unsupported = await mount({ summary: unsupportedSummary, cipher: null });
    expect(unsupported.shadowRoot?.querySelector('[data-favorite-toggle]')).toBeNull();
  });

  it('keeps a long title in the flexible header copy beside the fixed favorite action', async () => {
    const name = `Long title ${'segment '.repeat(50)}`.trim();
    const item = summary({ name, favorite: true });
    const el = await mount({ summary: item, cipher: detail(item) });

    expect(q(el, '.head-copy h1').textContent).toBe(name);
    expect(q<HTMLButtonElement>(el, '[data-favorite-toggle]').getAttribute('aria-pressed')).toBe('true');
    expect(q(el, '.head-copy').nextElementSibling).toBe(q(el, '[data-favorite-toggle]'));
  });

  it('renders personal owner and folder names from non-secret presentation metadata', async () => {
    const item = summary({ folderId: 'folder-work' });
    const el = await mount({
      summary: item,
      cipher: detail(item),
      presentationMetadata: {
        folders: [{ id: 'folder-work', name: 'Work accounts' }],
      },
    });

    expect(q(el, '[data-location="owner"] .value').textContent).toBe('Personal vault');
    expect(q(el, '[data-location="folder"] .value').textContent).toBe('Work accounts');
    expect(q(el, '[data-location="collections"] .value').textContent).toBe('No collections');
    expect(el.shadowRoot?.textContent).toContain('Vault location');
  });

  it('renders an organization owner and only same-organization collection names', async () => {
    const item = summary({
      organizationId: 'org-acme',
      folderId: 'folder-work',
      collectionIds: ['collection-engineering', 'collection-legal'],
    });
    const el = await mount({
      summary: item,
      cipher: detail(item),
      presentationMetadata: {
        organizations: [{ id: 'org-acme', name: 'Acme' }],
        folders: [{ id: 'folder-work', name: 'Work accounts' }],
        collections: [
          { id: 'collection-engineering', name: 'Engineering', organizationId: 'org-acme' },
          { id: 'collection-legal', name: 'Legal', organizationId: 'org-acme' },
          { id: 'collection-engineering', name: 'Wrong tenant', organizationId: 'org-other' },
        ],
      },
    });

    expect(q(el, '[data-location="owner"] .value').textContent).toBe('Acme');
    expect(q(el, '[data-location="folder"] .value').textContent).toBe('Work accounts');
    expect(q(el, '[data-location="collections"] .value').textContent).toBe('Engineering, Legal');
    expect(el.shadowRoot?.textContent).not.toContain('Wrong tenant');
  });

  it('uses generic fallbacks for unknown or ambiguous ids and never renders the raw ids', async () => {
    const item = summary({
      organizationId: 'raw-organization-id',
      folderId: 'raw-folder-id',
      collectionIds: ['raw-collection-id'],
    });
    const el = await mount({
      summary: item,
      cipher: detail(item),
      presentationMetadata: {
        organizations: [
          { id: 'raw-organization-id', name: 'First name' },
          { id: 'raw-organization-id', name: 'Conflicting name' },
        ],
        folders: [
          { id: 'raw-folder-id', name: 'First folder' },
          { id: 'raw-folder-id', name: 'Conflicting folder' },
        ],
        collections: [{
          id: 'raw-collection-id',
          name: 'Wrong organization collection',
          organizationId: 'other-organization',
        }],
      },
    });
    const markup = el.shadowRoot?.innerHTML ?? '';

    expect(q(el, '[data-location="owner"] .value').textContent).toBe('Unknown organization');
    expect(q(el, '[data-location="folder"] .value').textContent).toBe('Unknown folder');
    expect(q(el, '[data-location="collections"] .value').textContent).toBe('Unknown collection');
    for (const rawId of ['raw-organization-id', 'raw-folder-id', 'raw-collection-id']) {
      expect(markup).not.toContain(rawId);
    }
    expect(markup).not.toContain('First name');
    expect(markup).not.toContain('Conflicting name');
    expect(markup).not.toContain('First folder');
    expect(markup).not.toContain('Conflicting folder');
    expect(markup).not.toContain('Wrong organization collection');
  });

  it('keeps long presentation names readable without substituting identifiers', async () => {
    const ownerName = `Long owner ${'segment '.repeat(40)}`.trim();
    const collectionName = `Long collection ${'part '.repeat(40)}`.trim();
    const item = summary({ organizationId: 'org-long', collectionIds: ['collection-long'] });
    const el = await mount({
      summary: item,
      cipher: detail(item),
      presentationMetadata: {
        organizations: [{ id: 'org-long', name: ownerName }],
        collections: [{ id: 'collection-long', name: collectionName, organizationId: 'org-long' }],
      },
    });

    expect(q(el, '[data-location="owner"] .value').textContent).toBe(ownerName);
    expect(q(el, '[data-location="collections"] .value').textContent).toBe(collectionName);
    expect(el.shadowRoot?.innerHTML).not.toContain('collection-long');
  });

  it('hides denied organization actions while leaving controlled autofill available', async () => {
    const item = summary({
      organizationId: 'org-1',
      hasTotp: true,
      passwordHistoryCount: 2,
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: true,
        viewTotp: false,
      },
    });
    const getField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'must-not-load' }));
    const getCustomField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'must-not-load' }));
    const getTotp = vi.fn(async (): Promise<TotpFetchResult> => ({
      ok: true,
      totp: { code: '123456', period: 30, remaining: 20 },
    }));
    const el = await mount({
      summary: item,
      cipher: detail(item, {
        fields: [{ type: 1, name: 'Hidden', value: 'must-not-render' }],
        attachments: [{ id: 'a1', fileName: 'shared.txt' }],
      }),
      extras: extras({ getField, getCustomField, getTotp }),
    });
    await flush(el);

    for (const selector of [
      '[data-edit]', '[data-toggle-password]', '[data-copy-password]', '[data-totp]',
      '[data-cf-reveal]', '[data-cf-copy]', '[data-toggle-history]', '[data-att-delete]',
      '[data-att-file]', '[data-delete]',
    ]) {
      expect(el.shadowRoot?.querySelector(selector)).toBeNull();
    }
    expect(el.shadowRoot?.querySelector('[data-fill]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-download]')).not.toBeNull();
    expect(el.shadowRoot?.textContent).not.toContain('must-not-render');
    expect(getField).not.toHaveBeenCalled();
    expect(getCustomField).not.toHaveBeenCalled();
    expect(getTotp).not.toHaveBeenCalled();
  });

  it('shows only independently granted trash actions for an organization item', async () => {
    const item = summary({
      organizationId: 'org-1',
      deletedDate: '2026-08-30T00:00:00.000Z',
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: true,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const el = await mount({ summary: item, cipher: null, mode: 'trash' });

    expect(el.shadowRoot?.querySelector('[data-restore]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-delete-permanent]')).toBeNull();
  });

  it('emits composed typed navigation and fill events', async () => {
    const el = await mount({ primaryAction: 'fill' });
    const edit = vi.fn();
    const fill = vi.fn();
    el.addEventListener('vw-edit-item', edit);
    el.addEventListener('vw-item-fill', fill);
    q<HTMLButtonElement>(el, '[data-fill]').click();
    expect(fill).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1' }, bubbles: true, composed: true,
    }));
    expect(q<HTMLButtonElement>(el, '[data-fill]').textContent).toContain('Fill current page');
    q<HTMLButtonElement>(el, '[data-edit]').click();
    expect(edit).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'cipher-1' } }));

    const second = await mount();
    const back = vi.fn();
    second.addEventListener('vw-item-back', back);
    q<HTMLButtonElement>(second, '[data-back]').click();
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('labels opening separately and exposes structured fill only for an explicit current target', async () => {
    const opening = await mount({ primaryAction: 'open' });
    expect(q<HTMLButtonElement>(opening, '[data-fill]').textContent).toContain('Open website');

    const card = summary({ type: 3, uris: [], loginUris: [] });
    const hidden = await mount({ summary: card, cipher: detail(card) });
    expect(hidden.shadowRoot?.querySelector('[data-fill]')).toBeNull();

    const fillable = await mount({ summary: card, cipher: detail(card), primaryAction: 'fill' });
    expect(q<HTMLButtonElement>(fillable, '[data-fill]').textContent).toContain('Fill current page');
  });

  it('routes plaintext and secret copies through their typed events', async () => {
    const el = await mount();
    const copy = vi.fn();
    const secret = vi.fn();
    el.addEventListener('vw-copy', copy);
    el.addEventListener('vw-secret-request', secret);
    q<HTMLButtonElement>(el, '[aria-label="Copy Username"]').click();
    q<HTMLButtonElement>(el, '[data-copy-password]').click();
    expect(copy).toHaveBeenCalledWith(expect.objectContaining({ detail: { value: 'octocat', label: 'Username' } }));
    expect(secret).toHaveBeenCalledWith(expect.objectContaining({
      detail: { kind: 'field', field: 'password', label: 'Password' },
    }));
  });

  it('uses the shared status component', async () => {
    const el = await mount();
    el.status = { message: 'Download failed', tone: 'danger' };
    await el.updateComplete;
    const status = q<HTMLElement & { message: string }>(el, 'vw-status-message');
    expect(status.getAttribute('tone')).toBe('danger');
    expect(status.message).toBe('Download failed');
  });

  it('renders SSH public material and loads private material only after an explicit action', async () => {
    const item = summary({
      type: 5,
      username: 'must-not-render-as-login',
      uris: [],
      loginUris: [],
      hasTotp: true,
      subtitle: 'ED25519',
    });
    const getField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'must-not-load' }));
    const getTotp = vi.fn(async (): Promise<TotpFetchResult> => ({
      ok: true,
      totp: { code: '654321', period: 30, remaining: 20 },
    }));
    const getPrivateKey = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'PRIVATE-SSH-SECRET' }));
    const el = await mount({
      summary: item,
      cipher: detail(item),
      extras: extras({ getField, getTotp }),
      sshKey: { publicKey: 'ssh-ed25519 AAAATEST', keyFingerprint: 'SHA256:test', hasPrivateKey: true },
      sshExtras: { getPrivateKey },
      sshEditable: true,
    });
    await flush(el);

    expect(el.shadowRoot?.textContent).toContain('SSH key');
    expect(el.shadowRoot?.textContent).toContain('ssh-ed25519 AAAATEST');
    expect(el.shadowRoot?.textContent).toContain('SHA256:test');
    expect(el.shadowRoot?.textContent).not.toContain('PRIVATE-SSH-SECRET');
    expect(el.shadowRoot?.textContent).not.toContain('must-not-render-as-login');
    expect(el.shadowRoot?.querySelector('[data-secret-row]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-totp]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-fill]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-edit]')).not.toBeNull();
    expect(getField).not.toHaveBeenCalled();
    expect(getTotp).not.toHaveBeenCalled();

    q<HTMLButtonElement>(el, '[data-reveal-ssh-private]').click();
    await flush(el);
    expect(getPrivateKey).toHaveBeenCalledTimes(1);
    expect(el.shadowRoot?.textContent).toContain('PRIVATE-SSH-SECRET');

    q<HTMLButtonElement>(el, '[data-reveal-ssh-private]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).not.toContain('PRIVATE-SSH-SECRET');
  });

  it('renders an unknown cipher as a metadata-only placeholder with no secret or mutation actions', async () => {
    const item: CipherSummary = {
      id: 'future-6',
      type: 6,
      name: '(unsupported item)',
      favorite: false,
      uris: [],
      loginUris: [],
      unsupported: true,
      undecryptable: true,
      deletedDate: '2026-08-30T00:00:00Z',
    };
    const getField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'future-secret' }));
    const getCustomField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'future-hidden' }));
    const getTotp = vi.fn(async (): Promise<TotpFetchResult> => ({
      ok: true,
      totp: { code: '654321', period: 30, remaining: 20 },
    }));
    const getPasswordHistory = vi.fn(async (): Promise<HistoryFetchResult> => ({
      ok: true,
      history: [{ password: 'future-history' }],
    }));
    const el = await mount({
      summary: item,
      mode: 'trash',
      cipher: {
        ...item,
        notes: 'future-notes',
        fields: [{ type: 0, name: 'Future field', value: 'future-value' }],
        attachments: [{ id: 'future-attachment', fileName: 'future.txt' }],
      } as unknown as DecryptedCipher,
      extras: extras({ getField, getCustomField, getTotp, getPasswordHistory }),
    });
    await flush(el);

    expect(q(el, 'h1').textContent).toBe('Unsupported item');
    expect(q(el, '.type').textContent).toBe('Unsupported type 6');
    expect(el.shadowRoot?.textContent).toContain('This encrypted item was preserved');
    for (const secret of ['future-secret', 'future-hidden', 'future-history', 'future-notes', 'future-value', 'future.txt']) {
      expect(el.shadowRoot?.textContent).not.toContain(secret);
    }
    for (const selector of [
      '[data-edit]', '[data-fill]', '[data-secret-row]', '[data-att-file]', '[data-toggle-history]',
      '[data-archive]', '[data-unarchive]', '[data-delete]', '[data-restore]',
      '[data-delete-permanent]', '[data-confirm-delete]',
    ]) {
      expect(el.shadowRoot?.querySelector(selector)).toBeNull();
    }
    expect(getField).not.toHaveBeenCalled();
    expect(getCustomField).not.toHaveBeenCalled();
    expect(getTotp).not.toHaveBeenCalled();
    expect(getPasswordHistory).not.toHaveBeenCalled();
  });

  it('keeps a trashed SSH key read-only while allowing explicit key reveal', async () => {
    const item = summary({ type: 5, deletedDate: '2026-08-30T00:00:00Z', uris: [], loginUris: [] });
    const getPrivateKey = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'PRIVATE' }));
    const el = await mount({
      summary: item,
      cipher: null,
      mode: 'trash',
      sshKey: { publicKey: 'PUBLIC', keyFingerprint: 'FP', hasPrivateKey: true },
      sshExtras: { getPrivateKey },
      sshEditable: true,
    });
    expect(el.shadowRoot?.textContent).toContain('PUBLIC');
    expect(el.shadowRoot?.querySelector('[data-edit]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-reveal-ssh-private]').click();
    await flush(el);
    expect(getPrivateKey).toHaveBeenCalledOnce();
    expect(el.shadowRoot?.textContent).toContain('PRIVATE');
    expect(el.shadowRoot?.querySelector('[data-restore]')).not.toBeNull();
  });
});

describe('vw-item-detail secret lifecycle', () => {
  it('acknowledges a reveal only after the fetched value is visible and never on hide', async () => {
    const acknowledgeVisible = vi.fn();
    const getField = vi.fn(async (): Promise<SecretResult> => ({
      ok: true,
      value: 'visible-password',
      acknowledgeVisible,
    }));
    const el = await mount({ extras: extras({ getField }) });

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    expect(acknowledgeVisible).not.toHaveBeenCalled();
    await flush(el);

    expect(el.shadowRoot?.textContent).toContain('visible-password');
    expect(acknowledgeVisible).toHaveBeenCalledTimes(1);

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).not.toContain('visible-password');
    expect(acknowledgeVisible).toHaveBeenCalledTimes(1);
  });

  it('does not invalidate an in-flight secret loader when presentation metadata changes', async () => {
    const pending = deferred<SecretResult>();
    const getField = vi.fn(() => pending.promise);
    const el = await mount({
      extras: extras({ getField }),
      presentationMetadata: { folders: [] },
    });

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await el.updateComplete;
    el.presentationMetadata = {
      organizations: [{ id: 'unrelated', name: 'Updated presentation data' }],
      folders: [],
      collections: [],
    };
    await el.updateComplete;
    pending.resolve({ ok: true, value: 'still-current-secret' });
    await flush(el);

    expect(getField).toHaveBeenCalledOnce();
    expect(el.shadowRoot?.textContent).toContain('still-current-secret');
  });

  it('ignores secret-looking props until an explicit loader reveal', async () => {
    const item = summary();
    const getField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'loaded-password' }));
    const el = await mount({
      summary: item,
      cipher: detail(item, { password: 'prop-password' }),
      extras: extras({ getField }),
    });

    expect(el.shadowRoot?.textContent).not.toContain('prop-password');
    expect(el.shadowRoot?.textContent).not.toContain('loaded-password');
    expect(getField).not.toHaveBeenCalled();

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await flush(el);
    expect(getField).toHaveBeenCalledWith('password');
    expect(el.shadowRoot?.textContent).toContain('loaded-password');

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).not.toContain('loaded-password');
  });

  it('never renders a Hidden custom-field prop and clears its revealed value on hide', async () => {
    const item = summary();
    const getCustomField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'loaded-hidden' }));
    const el = await mount({
      summary: item,
      cipher: detail(item, { fields: [{ type: 1, name: 'Recovery', value: 'prop-hidden' }] }),
      extras: extras({ getCustomField }),
    });
    expect(el.shadowRoot?.textContent).not.toContain('prop-hidden');
    expect(el.shadowRoot?.textContent).not.toContain('loaded-hidden');

    q<HTMLButtonElement>(el, '[data-cf-reveal]').click();
    await flush(el);
    expect(getCustomField).toHaveBeenCalledWith(0);
    expect(el.shadowRoot?.textContent).toContain('loaded-hidden');

    q<HTMLButtonElement>(el, '[data-cf-reveal]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).not.toContain('loaded-hidden');
  });

  it('labels official Linked targets for Login, Card, and Identity items without resolving a value', async () => {
    const login = summary();
    const loginEl = await mount({
      summary: login,
      cipher: detail(login, { fields: [{ type: 3, name: 'Alias', linkedId: 101 }] }),
    });
    expect(loginEl.shadowRoot?.textContent).toContain('Linked to Password');
    loginEl.remove();

    const card = summary({ type: 3, uris: [], loginUris: [] });
    const cardEl = await mount({
      summary: card,
      cipher: detail(card, { fields: [{ type: 3, name: 'PAN alias', linkedId: 305 }] }),
    });
    expect(cardEl.shadowRoot?.textContent).toContain('Linked to Card number');
    cardEl.remove();

    const identity = summary({ type: 4, uris: [], loginUris: [] });
    const identityEl = await mount({
      summary: identity,
      cipher: detail(identity, { fields: [{ type: 3, name: 'Name alias', linkedId: 418 }] }),
    });
    expect(identityEl.shadowRoot?.textContent).toContain('Linked to Full name');
  });

  it('loads password history explicitly and clears state and DOM when hidden', async () => {
    const item = summary({ passwordHistoryCount: 1 });
    const getPasswordHistory = vi.fn(async (): Promise<HistoryFetchResult> => ({
      ok: true,
      history: [{ password: 'previous-secret', lastUsedDate: '2024-01-01T00:00:00Z' }],
    }));
    const el = await mount({ summary: item, cipher: detail(item), extras: extras({ getPasswordHistory }) });
    expect(getPasswordHistory).not.toHaveBeenCalled();
    expect(el.shadowRoot?.textContent).not.toContain('previous-secret');

    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    await flush(el);
    expect(el.shadowRoot?.textContent).toContain('previous-secret');

    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.textContent).not.toContain('previous-secret');
    expect((el as unknown as { history: unknown }).history).toBeNull();
  });

  it('scrubs already-rendered secrets from its DOM after disconnect', async () => {
    const item = summary({ hasTotp: true, passwordHistoryCount: 1 });
    const el = await mount({
      summary: item,
      cipher: detail(item, { fields: [{ type: 1, name: 'Recovery', value: 'prop-hidden' }] }),
      extras: extras({
        getField: async () => ({ ok: true, value: 'visible-password' }),
        getCustomField: async () => ({ ok: true, value: 'visible-hidden' }),
        getTotp: async () => ({
          ok: true,
          totp: { code: '112233', period: 30, remaining: 20 },
        }),
        getPasswordHistory: async () => ({
          ok: true,
          history: [{ password: 'visible-history' }],
        }),
      }),
    });
    await flush(el);
    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    q<HTMLButtonElement>(el, '[data-cf-reveal]').click();
    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    await flush(el);

    expect(el.shadowRoot?.textContent).toContain('visible-password');
    expect(el.shadowRoot?.textContent).toContain('visible-hidden');
    expect(el.shadowRoot?.textContent).toContain('visible-history');
    expect(q<HTMLElement & { code: string }>(el, 'vw-totp-meter').code).toBe('112233');

    el.remove();
    await el.updateComplete;

    expect(el.shadowRoot?.textContent).not.toContain('visible-password');
    expect(el.shadowRoot?.textContent).not.toContain('visible-hidden');
    expect(el.shadowRoot?.textContent).not.toContain('visible-history');
    expect(el.shadowRoot?.querySelector('vw-totp-meter')).toBeNull();
  });
});

describe('vw-item-detail generation guards', () => {
  it('rejects an A response after A to B to A and accepts the current A loader', async () => {
    const stale = deferred<SecretResult>();
    const a = summary({ id: 'a', name: 'Alpha' });
    const b = summary({ id: 'b', name: 'Bravo' });
    const currentGetField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'current-alpha' }));
    const el = await mount({ summary: a, cipher: detail(a), extras: extras({ getField: () => stale.promise }) });

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    el.summary = b;
    el.cipher = detail(b);
    el.extras = extras();
    await el.updateComplete;
    el.summary = { ...a };
    el.cipher = detail(a);
    el.extras = extras({ getField: currentGetField });
    await el.updateComplete;

    stale.resolve({ ok: true, value: 'stale-alpha' });
    await flush(el);
    expect(el.shadowRoot?.textContent).not.toContain('stale-alpha');

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await flush(el);
    expect(currentGetField).toHaveBeenCalledTimes(1);
    expect(el.shadowRoot?.textContent).toContain('current-alpha');
  });

  it('rejects a late response when loaders are replaced for the same item', async () => {
    const stale = deferred<SecretResult>();
    const currentGetField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'new-secret' }));
    const el = await mount({ extras: extras({ getField: () => stale.promise }) });
    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    el.extras = extras({ getField: currentGetField });
    await el.updateComplete;
    stale.resolve({ ok: true, value: 'old-secret' });
    await flush(el);
    expect(el.shadowRoot?.textContent).not.toContain('old-secret');

    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await flush(el);
    expect(el.shadowRoot?.textContent).toContain('new-secret');
  });

  it('discards late field and history results after disconnect', async () => {
    const field = deferred<SecretResult>();
    const history = deferred<HistoryFetchResult>();
    const item = summary({ passwordHistoryCount: 1 });
    const el = await mount({
      summary: item,
      cipher: detail(item),
      extras: extras({ getField: () => field.promise, getPasswordHistory: () => history.promise }),
    });
    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    el.remove();
    field.resolve({ ok: true, value: 'late-field' });
    history.resolve({ ok: true, history: [{ password: 'late-history' }] });
    await flush();

    const state = el as unknown as { revealed: Map<string, string>; history: unknown };
    expect(state.revealed.size).toBe(0);
    expect(state.history).toBeNull();
    expect(el.shadowRoot?.textContent).not.toContain('late-field');
    expect(el.shadowRoot?.textContent).not.toContain('late-history');
  });
});

describe('vw-item-detail TOTP', () => {
  beforeEach(() => vi.useFakeTimers());

  async function settle(el: VwItemDetail): Promise<void> {
    await vi.advanceTimersByTimeAsync(0);
    await el.updateComplete;
  }

  it('renders with the shared meter, refreshes at expiry and clears its timer on disconnect', async () => {
    const getTotp = vi
      .fn<() => Promise<TotpFetchResult>>()
      .mockResolvedValueOnce({ ok: true, totp: { code: '081804', period: 30, remaining: 2 } })
      .mockResolvedValue({ ok: true, totp: { code: '222333', period: 30, remaining: 30 } });
    const item = summary({ hasTotp: true });
    const el = await mount({ summary: item, cipher: detail(item), extras: extras({ getTotp }) });
    await settle(el);

    let meter = q<HTMLElement & { code: string; remaining: number }>(el, 'vw-totp-meter');
    expect(meter.code).toBe('081804');
    expect(meter.remaining).toBe(2);

    await vi.advanceTimersByTimeAsync(2000);
    await el.updateComplete;
    meter = q(el, 'vw-totp-meter');
    expect(getTotp).toHaveBeenCalledTimes(2);
    expect(meter.code).toBe('222333');

    el.remove();
    const state = el as unknown as { totp: unknown; totpTimer: number | undefined };
    expect(state.totp).toBeUndefined();
    expect(state.totpTimer).toBeUndefined();
  });

  it('does not retain a TOTP result that arrives after disconnect', async () => {
    const pending = deferred<TotpFetchResult>();
    const item = summary({ hasTotp: true });
    const el = await mount({ summary: item, cipher: detail(item), extras: extras({ getTotp: () => pending.promise }) });
    el.remove();
    pending.resolve({ ok: true, totp: { code: '123456', period: 30, remaining: 25 } });
    await vi.advanceTimersByTimeAsync(0);
    const state = el as unknown as { totp: unknown; totpTimer: number | undefined };
    expect(state.totp).toBeUndefined();
    expect(state.totpTimer).toBeUndefined();
  });

  it('removes an expired code and its copy action while the next snapshot is loading', async () => {
    const rollover = deferred<TotpFetchResult>();
    const getTotp = vi
      .fn<() => Promise<TotpFetchResult>>()
      .mockResolvedValueOnce({ ok: true, totp: { code: '111222', period: 30, remaining: 1 } })
      .mockImplementationOnce(() => rollover.promise);
    const item = summary({ hasTotp: true });
    const el = await mount({ summary: item, cipher: detail(item), extras: extras({ getTotp }) });
    await settle(el);

    expect(q<HTMLElement & { code: string }>(el, 'vw-totp-meter').code).toBe('111222');
    expect(el.shadowRoot?.querySelector('[data-copy-totp]')).not.toBeNull();

    await vi.advanceTimersByTimeAsync(1000);
    await el.updateComplete;

    expect(getTotp).toHaveBeenCalledTimes(2);
    expect(el.shadowRoot?.querySelector('vw-totp-meter')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-copy-totp]')).toBeNull();

    rollover.resolve({ ok: true, totp: { code: '333444', period: 30, remaining: 30 } });
    await settle(el);

    expect(q<HTMLElement & { code: string }>(el, 'vw-totp-meter').code).toBe('333444');
    expect(el.shadowRoot?.querySelector('[data-copy-totp]')).not.toBeNull();
  });
});

describe('vw-item-detail fields and attachments', () => {
  it('confirms deletion of one passkey using only its public credential ID', async () => {
    const item = summary({ hasPasskey: true });
    const el = await mount({
      summary: item,
      cipher: detail(item, {
        fido2Credentials: [{
          credentialId: 'public-credential-id',
          keyValue: '',
          rpId: 'github.com',
          rpName: 'GitHub',
          counter: 0,
          discoverable: true,
        }],
      }),
    });
    const remove = vi.fn();
    el.addEventListener('vw-passkey-delete', remove);
    expect(el.shadowRoot?.innerHTML).not.toContain('public-credential-id');

    q<HTMLButtonElement>(el, '[data-passkey-delete]').click();
    const dialog = await settleDialog(el);
    expect(dialog.heading).toBe('Delete passkey');
    expect(dialog.textContent).toContain('GitHub');
    expect(q(el, '[data-confirmation-item]').textContent).toBe('GitHub');
    expect(q(el, '[data-confirmation-owner]').textContent).toBe('Personal vault');
    expect(q(el, '[data-confirmation-target]').textContent).toBe('GitHub');
    q<HTMLButtonElement>(el, '[data-confirm-passkey]').click();
    await flush(el);

    expect(remove).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', credentialId: 'public-credential-id' },
      bubbles: true,
      composed: true,
    }));
  });

  it('hides passkey deletion without both edit and password-view access', async () => {
    const item = summary({
      hasPasskey: true,
      organizationId: 'org-1',
      access: {
        edit: true,
        viewPassword: false,
        delete: true,
        restore: true,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const el = await mount({
      summary: item,
      cipher: detail(item, {
        fido2Credentials: [{
          credentialId: 'public-credential-id',
          keyValue: '',
          rpId: 'github.com',
          counter: 0,
          discoverable: true,
        }],
      }),
    });

    expect(el.shadowRoot?.querySelector('[data-passkey-delete]')).toBeNull();
  });

  it('renders card and identity fields as flat rows while keeping their secrets masked', async () => {
    const cardItem = summary({ id: 'card', name: 'Card', type: 3, uris: [] });
    delete cardItem.username;
    const card = await mount({
      summary: cardItem,
      cipher: detail(cardItem, {
        card: {
          brand: 'Visa', cardholderName: 'Ada', expMonth: '04', expYear: '27',
          number: 'prop-number', code: 'prop-code',
        },
      }),
    });
    expect(card.shadowRoot?.textContent).toContain('Visa');
    expect(card.shadowRoot?.textContent).toContain('04 / 27');
    expect(card.shadowRoot?.textContent).not.toContain('prop-number');
    expect(card.shadowRoot?.textContent).not.toContain('prop-code');
    expect(card.shadowRoot?.querySelector('[data-reveal="card.number"]')).toBeTruthy();

    const identityItem = summary({ id: 'identity', name: 'Identity', type: 4, uris: [] });
    delete identityItem.username;
    const identity = await mount({
      summary: identityItem,
      cipher: detail(identityItem, {
        identity: { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.test', ssn: 'prop-ssn' },
      }),
    });
    expect(identity.shadowRoot?.textContent).toContain('Ada');
    expect(identity.shadowRoot?.textContent).toContain('ada@example.test');
    expect(identity.shadowRoot?.textContent).not.toContain('prop-ssn');
    expect(identity.shadowRoot?.querySelector('[data-reveal="identity.ssn"]')).toBeTruthy();
  });

  it('hides protected card and identity controls without viewPassword', async () => {
    const deniedAccess = {
      edit: false,
      viewPassword: false,
      delete: false,
      restore: false,
      autofillTotp: false,
      viewTotp: false,
    } as const;
    const cardItem = summary({
      id: 'org-card',
      name: 'Shared card',
      type: 3,
      organizationId: 'org-1',
      access: deniedAccess,
      uris: [],
      loginUris: [],
    });
    const card = await mount({
      summary: cardItem,
      cipher: detail(cardItem, {
        card: { brand: 'Visa', number: 'prop-number', code: 'prop-code' },
      }),
    });
    expect(card.shadowRoot?.textContent).toContain('Visa');
    expect(card.shadowRoot?.querySelector('[data-reveal="card.number"]')).toBeNull();
    expect(card.shadowRoot?.querySelector('[data-reveal="card.code"]')).toBeNull();

    const identityItem = summary({
      id: 'org-identity',
      name: 'Shared identity',
      type: 4,
      organizationId: 'org-1',
      access: deniedAccess,
      uris: [],
      loginUris: [],
    });
    const identity = await mount({
      summary: identityItem,
      cipher: detail(identityItem, {
        identity: { firstName: 'Ada', ssn: 'prop-ssn', passportNumber: 'prop-passport' },
      }),
    });
    expect(identity.shadowRoot?.textContent).toContain('Ada');
    expect(identity.shadowRoot?.querySelector('[data-reveal="identity.ssn"]')).toBeNull();
    expect(identity.shadowRoot?.querySelector('[data-reveal="identity.passportNumber"]')).toBeNull();
  });

  it('emits attachment download/delete without placing attachment ids in the DOM', async () => {
    const item = summary();
    const el = await mount({
      summary: item,
      cipher: detail(item, { attachments: [{ id: 'attachment-secret-id', fileName: 'notes.txt', sizeName: '1 KB' }] }),
    });
    expect(el.shadowRoot?.innerHTML).not.toContain('attachment-secret-id');
    const download = vi.fn();
    const remove = vi.fn();
    el.addEventListener('vw-attachment-download', download);
    el.addEventListener('vw-attachment-delete', remove);

    q<HTMLButtonElement>(el, '[data-att-download]').click();
    expect(download).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', attachmentId: 'attachment-secret-id', fileName: 'notes.txt' },
    }));
    q<HTMLButtonElement>(el, '[data-att-delete]').click();
    await settleDialog(el);
    expect(el.shadowRoot?.querySelector('vw-dialog')).toBeTruthy();
    expect(q(el, '[data-confirmation-item]').textContent).toBe('GitHub');
    expect(q(el, '[data-confirmation-target]').textContent).toBe('notes.txt');
    expect(remove).not.toHaveBeenCalled();
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    await flush(el);
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', attachmentId: 'attachment-secret-id', fileName: 'notes.txt' },
    }));
  });

  it('offers a legacy encryption upgrade without taking away the existing download', async () => {
    const item = summary();
    const el = await mount({
      summary: item,
      cipher: detail(item, {
        attachments: [{
          id: 'legacy-secret-id',
          fileName: 'legacy.txt',
          sizeName: '2 KB',
          legacy: true,
        }],
      }),
    });
    const download = vi.fn();
    const upgrade = vi.fn();
    el.addEventListener('vw-attachment-download', download);
    el.addEventListener('vw-attachment-upgrade', upgrade);

    q<HTMLButtonElement>(el, '[data-att-download]').click();
    expect(download).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        cipherId: 'cipher-1',
        attachmentId: 'legacy-secret-id',
        fileName: 'legacy.txt',
      },
    }));
    q<HTMLButtonElement>(el, '[data-att-upgrade]').click();
    expect(upgrade).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        cipherId: 'cipher-1',
        attachmentId: 'legacy-secret-id',
        fileName: 'legacy.txt',
      },
    }));
    expect(el.shadowRoot?.innerHTML).not.toContain('legacy-secret-id');
  });

  it('does not offer an upgrade for an undecryptable or read-only legacy attachment', async () => {
    const readOnly = summary({
      organizationId: 'org-1',
      access: {
        edit: false,
        viewPassword: true,
        delete: false,
        restore: false,
        autofillTotp: true,
        viewTotp: true,
      },
    });
    const el = await mount({
      summary: readOnly,
      cipher: detail(readOnly, {
        attachments: [{ id: 'legacy', fileName: '(undecryptable)', legacy: true }],
      }),
    });

    expect(el.shadowRoot?.querySelector('[data-att-upgrade]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-download]')).toBeNull();
  });

  it('allows a read-only member to download a decryptable legacy attachment', async () => {
    const readOnly = summary({
      organizationId: 'org-1',
      access: {
        edit: false,
        viewPassword: true,
        delete: false,
        restore: false,
        autofillTotp: true,
        viewTotp: true,
      },
    });
    const el = await mount({
      summary: readOnly,
      cipher: detail(readOnly, {
        attachments: [{ id: 'legacy-read-only', fileName: 'legacy.txt', legacy: true }],
      }),
    });
    const download = vi.fn();
    el.addEventListener('vw-attachment-download', download);

    expect(el.shadowRoot?.querySelector('[data-att-upgrade]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-att-download]').click();
    expect(download).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        cipherId: 'cipher-1',
        attachmentId: 'legacy-read-only',
        fileName: 'legacy.txt',
      },
    }));
  });

  it('forwards the selected attachment without reading the whole file', async () => {
    const el = await mount();
    const add = vi.fn();
    el.addEventListener('vw-attachment-add', add);
    const input = q<HTMLInputElement>(el, '[data-att-file]');
    const file = new File([new Uint8Array([104, 105])], 'hi.txt');
    const read = vi.spyOn(file, 'arrayBuffer');
    Object.defineProperty(input, 'files', {
      value: [file],
      configurable: true,
    });
    input.dispatchEvent(new Event('change'));
    await flush(el);
    expect(add).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', fileName: 'hi.txt', file },
    }));
    expect(read).not.toHaveBeenCalled();
  });

  it.each([
    { label: 'zero', size: 0 },
    { label: 'limit - 1', size: MAX_ATTACHMENT_FILE_BYTES - 1 },
    { label: 'limit', size: MAX_ATTACHMENT_FILE_BYTES },
  ])('forwards an attachment at $label bytes without reading it', async ({ size }) => {
    const el = await mount();
    const add = vi.fn();
    el.addEventListener('vw-attachment-add', add);
    const input = q<HTMLInputElement>(el, '[data-att-file]');
    const file = new File([new Uint8Array([104, 105])], 'boundary.txt');
    Object.defineProperty(file, 'size', { value: size });
    const read = vi.spyOn(file, 'arrayBuffer');
    Object.defineProperty(input, 'files', { value: [file], configurable: true });

    input.dispatchEvent(new Event('change'));
    await flush(el);

    expect(read).not.toHaveBeenCalled();
    expect(add).toHaveBeenCalledOnce();
  });

  it('rejects an attachment at limit + 1 before reading it', async () => {
    const el = await mount();
    const add = vi.fn();
    const localError = vi.fn();
    el.addEventListener('vw-attachment-add', add);
    el.addEventListener('vw-detail-error', localError);
    const input = q<HTMLInputElement>(el, '[data-att-file]');
    const file = new File([new Uint8Array([104, 105])], 'too-large.txt');
    Object.defineProperty(file, 'size', { value: MAX_ATTACHMENT_FILE_BYTES + 1 });
    const read = vi.spyOn(file, 'arrayBuffer');
    Object.defineProperty(input, 'files', { value: [file], configurable: true });

    input.dispatchEvent(new Event('change'));
    await flush(el);

    expect(read).not.toHaveBeenCalled();
    expect(add).not.toHaveBeenCalled();
    expect(localError).toHaveBeenCalledWith(expect.objectContaining({
      detail: { message: 'Could not read the attachment' },
    }));
  });

  it('rejects a visible duplicate attachment name before reading or emitting the file', async () => {
    const item = summary();
    const el = await mount({
      summary: item,
      cipher: detail(item, { attachments: [{ id: 'existing', fileName: 'hi.txt' }] }),
    });
    const add = vi.fn();
    const localError = vi.fn();
    el.addEventListener('vw-attachment-add', add);
    el.addEventListener('vw-detail-error', localError);
    const input = q<HTMLInputElement>(el, '[data-att-file]');
    const file = new File([new Uint8Array([104, 105])], 'hi.txt');
    const read = vi.spyOn(file, 'arrayBuffer');
    Object.defineProperty(input, 'files', {
      value: [file],
      configurable: true,
    });

    input.dispatchEvent(new Event('change'));
    await flush(el);

    expect(add).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
    expect(localError).toHaveBeenCalledWith(expect.objectContaining({
      detail: { message: 'An attachment with this file name already exists.' },
    }));
  });
});

describe('vw-item-detail lifecycle modes', () => {
  it('disables lifecycle submission while an authoritative request is pending', async () => {
    const el = await mount({ pending: true });
    const archived = vi.fn();
    el.addEventListener('vw-archive-item', archived);
    const button = q<HTMLButtonElement>(el, '[data-archive]');

    expect(button.disabled).toBe(true);
    button.click();
    expect(archived).not.toHaveBeenCalled();
  });

  it('confirms a typed archive command without depending on edit or delete permission', async () => {
    const item = summary({
      organizationId: 'org-1',
      access: {
        edit: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const el = await mount({ summary: item, cipher: detail(item) });
    const archived = vi.fn();
    el.addEventListener('vw-archive-item', archived);

    expect(el.shadowRoot?.querySelector('[data-edit]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-delete]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-archive]').click();
    await settleDialog(el);
    const confirm = q<HTMLButtonElement>(el, '[data-confirm-archive]');
    confirm.click();
    confirm.click();
    await flush(el);

    expect(archived).toHaveBeenCalledTimes(1);
    expect(archived).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        action: 'archive',
        cipherId: 'cipher-1',
        sourceMode: 'active',
        targetMode: 'archive',
      },
    }));
  });

  it('renders archived details with explicit secret reads, edit, delete, and unarchive actions', async () => {
    const getField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'archive-password' }));
    const getCustomField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'archive-hidden' }));
    const getTotp = vi.fn(async (): Promise<TotpFetchResult> => ({
      ok: true,
      totp: { code: '123456', period: 30, remaining: 20 },
    }));
    const getPasswordHistory = vi.fn(async (): Promise<HistoryFetchResult> => ({
      ok: true,
      history: [{ password: 'archive-history' }],
    }));
    const item = summary({
      name: 'Archived login',
      archivedDate: '2026-08-30T00:00:00Z',
      hasTotp: true,
      hasPasskey: true,
      passwordHistoryCount: 1,
    });
    const el = await mount({
      summary: item,
      mode: 'archive',
      cipher: detail(item, {
        password: 'prop-password',
        fields: [{ type: 1, name: 'Hidden', value: 'prop-hidden' }],
        fido2Credentials: [{
          credentialId: 'archived-credential',
          keyValue: '',
          rpId: 'example.com',
          counter: 0,
          discoverable: true,
        }],
        attachments: [{ id: 'archived-attachment', fileName: 'archive.txt' }],
      }),
      extras: extras({ getField, getCustomField, getTotp, getPasswordHistory }),
    });
    const unarchive = vi.fn();
    el.addEventListener('vw-unarchive-item', unarchive);

    expect(el.shadowRoot?.textContent).toContain('Archived login');
    expect(el.shadowRoot?.textContent).not.toContain('prop-password');
    expect(el.shadowRoot?.querySelector('[data-edit]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-fill]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-totp]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-secret-row]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-delete]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-passkey-delete]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-delete]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-file]')).not.toBeNull();
    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    q<HTMLButtonElement>(el, '[data-cf-reveal]').click();
    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    await flush(el);
    expect(getField).toHaveBeenCalledOnce();
    expect(getCustomField).toHaveBeenCalledOnce();
    expect(getPasswordHistory).toHaveBeenCalledOnce();
    expect(getTotp).not.toHaveBeenCalled();
    expect(el.shadowRoot?.textContent).toContain('archive-password');
    expect(el.shadowRoot?.textContent).toContain('archive-hidden');
    expect(el.shadowRoot?.textContent).toContain('archive-history');
    const button = q<HTMLButtonElement>(el, '[data-unarchive]');
    button.click();
    button.click();

    expect(unarchive).toHaveBeenCalledTimes(1);
    expect(unarchive).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        action: 'unarchive',
        cipherId: 'cipher-1',
        sourceMode: 'archive',
        targetMode: 'active',
      },
    }));
  });

  it('confirms a normal soft delete through the shared dialog', async () => {
    const el = await mount();
    const remove = vi.fn();
    el.addEventListener('vw-delete-item', remove);
    q<HTMLButtonElement>(el, '[data-delete]').click();
    const dialog = await settleDialog(el);
    const closed = vi.fn();
    dialog.addEventListener('vw-dialog-close', closed);
    expect(el.shadowRoot?.querySelector('vw-dialog')).toBeTruthy();
    expect(remove).not.toHaveBeenCalled();
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    await flush(el);
    expect(closed).toHaveBeenCalledWith(expect.objectContaining({ detail: { reason: 'confirm' } }));
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', permanent: false },
    }));
  });

  it('keeps an organization card and its owner in the deletion confirmation', async () => {
    const item = summary({
      id: 'card-finance',
      name: 'Travel card',
      type: 3,
      uris: [],
      loginUris: [],
      organizationId: 'organization-finance',
      access: {
        edit: true,
        viewPassword: true,
        delete: true,
        restore: true,
        autofillTotp: false,
        viewTotp: false,
      },
    });
    const el = await mount({
      summary: item,
      cipher: detail(item, { card: { brand: 'Visa' } }),
      presentationMetadata: { organizations: [{ id: 'organization-finance', name: 'Finance team' }] },
    });
    const remove = vi.fn();
    el.addEventListener('vw-delete-item', remove);

    q<HTMLButtonElement>(el, '[data-delete]').click();
    const dialog = await settleDialog(el);

    expect(q(el, '[data-confirmation-item]').textContent).toBe('Travel card');
    expect(q(el, '[data-confirmation-owner]').textContent).toBe('Finance team');
    expect(dialog.textContent).not.toContain('GitHub');
    expect(dialog.innerHTML).not.toContain('organization-finance');
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    await flush(el);
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'card-finance', permanent: false },
    }));
  });

  it('allows an archived item to move to trash but never emits permanent delete', async () => {
    const item = summary({ archivedDate: '2026-08-30T00:00:00Z' });
    const el = await mount({ summary: item, cipher: detail(item), mode: 'archive' });
    const remove = vi.fn();
    el.addEventListener('vw-delete-item', remove);

    expect(el.shadowRoot?.querySelector('[data-delete-permanent]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await settleDialog(el);
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    await flush(el);

    expect(remove).toHaveBeenCalledOnce();
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', permanent: false },
    }));
  });

  it('closes a canceled confirmation through vw-dialog and restores the trigger focus', async () => {
    const el = await mount();
    const trigger = q<HTMLButtonElement>(el, '[data-delete]');
    trigger.focus();
    expect(el.shadowRoot?.activeElement).toBe(trigger);
    trigger.click();
    const dialog = await settleDialog(el);
    const closed = vi.fn();
    dialog.addEventListener('vw-dialog-close', closed);

    q<HTMLButtonElement>(el, '[data-cancel-delete]').click();
    await flush(el);

    expect(closed).toHaveBeenCalledWith(expect.objectContaining({ detail: { reason: 'dismiss' } }));
    expect(el.shadowRoot?.querySelector('vw-dialog')).toBeNull();
    expect(el.shadowRoot?.activeElement).toBe(trigger);
  });

  it('renders trash as read-only detail with explicit secret reads and only trash mutations', async () => {
    const getField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'trash-password' }));
    const getCustomField = vi.fn(async (): Promise<SecretResult> => ({ ok: true, value: 'trash-hidden' }));
    const getTotp = vi.fn(async (): Promise<TotpFetchResult> => ({
      ok: true, totp: { code: '123456', period: 30, remaining: 20 },
    }));
    const getPasswordHistory = vi.fn(async (): Promise<HistoryFetchResult> => ({
      ok: true, history: [{ password: 'trash-history' }],
    }));
    const item = summary({ deletedDate: '2024-01-01T00:00:00Z', hasTotp: true, passwordHistoryCount: 1 });
    const el = await mount({
      summary: item,
      mode: 'trash',
      cipher: detail(item, {
        password: 'prop-password',
        fields: [{ type: 1, name: 'Hidden', value: 'prop-hidden' }],
        attachments: [{ id: 'att-id', fileName: 'file.txt' }],
      }),
      extras: extras({ getField, getCustomField, getTotp, getPasswordHistory }),
    });

    expect(el.shadowRoot?.querySelector('[data-restore]')).toBeTruthy();
    expect(el.shadowRoot?.querySelector('[data-delete-permanent]')).toBeTruthy();
    expect(el.shadowRoot?.querySelector('[data-edit]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-fill]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-totp]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-secret-row]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-file]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-delete]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-att-download]')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('[data-passkey-delete]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-archive]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-unarchive]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-delete]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-uri]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-toggle-history]')).not.toBeNull();
    expect(el.shadowRoot?.textContent).not.toContain('prop-password');
    expect(el.shadowRoot?.textContent).not.toContain('prop-hidden');
    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    q<HTMLButtonElement>(el, '[data-cf-reveal]').click();
    q<HTMLButtonElement>(el, '[data-toggle-history]').click();
    await flush(el);
    expect(getField).toHaveBeenCalledOnce();
    expect(getCustomField).toHaveBeenCalledOnce();
    expect(getPasswordHistory).toHaveBeenCalledOnce();
    expect(getTotp).not.toHaveBeenCalled();
    expect(el.shadowRoot?.textContent).toContain('trash-password');
    expect(el.shadowRoot?.textContent).toContain('trash-hidden');
    expect(el.shadowRoot?.textContent).toContain('trash-history');
  });

  it('emits restore and permanent delete for a trashed item', async () => {
    const item = summary({ deletedDate: '2024-01-01T00:00:00Z' });
    const el = await mount({ summary: item, cipher: detail(item), mode: 'trash' });
    const restore = vi.fn();
    const remove = vi.fn();
    el.addEventListener('vw-restore-item', restore);
    el.addEventListener('vw-delete-item', remove);
    const restoreButton = q<HTMLButtonElement>(el, '[data-restore]');
    restoreButton.click();
    restoreButton.click();
    expect(restore).toHaveBeenCalledTimes(1);
    expect(restore).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        action: 'restore',
        cipherId: 'cipher-1',
        sourceMode: 'trash',
        targetMode: 'active',
      },
    }));

    // Model the root's authoritative request lifecycle before exercising a separate command.
    el.pending = true;
    await el.updateComplete;
    el.pending = false;
    await el.updateComplete;

    q<HTMLButtonElement>(el, '[data-delete-permanent]').click();
    await settleDialog(el);
    q<HTMLButtonElement>(el, '[data-confirm-delete]').click();
    await flush(el);
    expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'cipher-1', permanent: true },
    }));
  });

  it('marks an archived-and-deleted restore to return to Archive', async () => {
    const item = summary({
      archivedDate: '2026-08-29T00:00:00Z',
      deletedDate: '2026-08-30T00:00:00Z',
    });
    const el = await mount({ summary: item, cipher: detail(item), mode: 'trash' });
    const restore = vi.fn();
    el.addEventListener('vw-restore-item', restore);

    const restoreButton = q<HTMLButtonElement>(el, '[data-restore]');
    restoreButton.click();
    restoreButton.click();

    expect(restore).toHaveBeenCalledTimes(1);
    expect(restore).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        action: 'restore',
        cipherId: 'cipher-1',
        sourceMode: 'trash',
        targetMode: 'archive',
      },
    }));
  });
});
