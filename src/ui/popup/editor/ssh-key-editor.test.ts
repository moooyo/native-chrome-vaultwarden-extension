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

import './ssh-key-editor.js';
import { setLocale } from '../../i18n/index.js';
import type { DecryptedCipher, KnownCipherSummary } from '../../../core/vault/models.js';
import type { VwSshKeyEditor } from './ssh-key-editor.js';

function sshSummary(overrides: Partial<KnownCipherSummary> = {}): KnownCipherSummary {
  return { id: 'ssh-1', type: 5, name: 'Deploy key', uris: [], loginUris: [], favorite: false, ...overrides };
}

async function mount(
  mode: 'create' | 'edit' = 'create',
  editFields: NonNullable<DecryptedCipher['fields']> = [
    { type: 1, name: 'Host', value: 'hidden-host' },
  ],
): Promise<VwSshKeyEditor> {
  const el = document.createElement('vw-ssh-key-editor') as VwSshKeyEditor;
  el.mode = mode;
  el.available = true;
  el.personalCreationAllowed = true;
  el.folders = [{ id: 'folder-1', name: 'Servers' }];
  el.collections = [];
  el.orgPermissions = [];
  if (mode === 'edit') {
    const summary = sshSummary();
    el.cipherId = summary.id;
    el.summary = summary;
    el.cipher = {
      ...summary,
      notes: 'Production',
      fields: editFields,
    } as DecryptedCipher;
    el.publicDetails = { publicKey: 'ssh-ed25519 AAAATEST', keyFingerprint: 'SHA256:test', hasPrivateKey: true };
  }
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwSshKeyEditor, selector: string): T {
  return el.shadowRoot!.querySelector<T>(selector)!;
}

function input(el: VwSshKeyEditor, selector: string, value: string): void {
  const target = q<HTMLInputElement | HTMLTextAreaElement>(el, selector);
  target.value = value;
  target.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
}

async function flush(el: VwSshKeyEditor): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  await el.updateComplete;
}

beforeEach(() => setLocale('en', false));
afterEach(() => document.body.replaceChildren());

describe('vw-ssh-key-editor create', () => {
  it('keeps saving outside the scroll area and focuses the missing required name', async () => {
    const el = await mount();
    const save = q<HTMLButtonElement>(el, '[data-create-ssh]');
    expect(save.closest('footer')).not.toBeNull();
    expect(save.closest('main')).toBeNull();
    expect(el.shadowRoot!.querySelectorAll('form')).toHaveLength(1);
    save.click();
    await el.updateComplete;
    expect(el.shadowRoot!.activeElement).toBe(q(el, '[data-name]'));
    expect(q(el, '[data-name]').getAttribute('aria-invalid')).toBe('true');
    expect(q(el, 'footer vw-status-message')).not.toBeNull();
  });

  it('opens saved-location settings when an available vault must be chosen', async () => {
    const el = await mount();
    el.personalCreationAllowed = false;
    await el.updateComplete;
    input(el, '[data-name]', 'Deploy key');
    expect(q<HTMLDetailsElement>(el, '[data-ssh-settings]').open).toBe(false);
    q<HTMLButtonElement>(el, '[data-create-ssh]').click();
    await el.updateComplete;
    expect(q<HTMLDetailsElement>(el, '[data-ssh-settings]').open).toBe(true);
    expect(el.shadowRoot!.activeElement).toBe(q(el, '[data-create-vault]'));
  });

  it('emits a dedicated generate command without private key material', async () => {
    const el = await mount();
    input(el, '[data-name]', 'Deploy key');
    const received = vi.fn();
    el.addEventListener('vw-ssh-create-generate', received);
    q<HTMLButtonElement>(el, '[data-create-ssh]').click();
    expect(received).toHaveBeenCalledWith(expect.objectContaining({
      detail: {
        metadata: { name: 'Deploy key', notes: '', favorite: false, reprompt: false, folderId: null, fields: [] },
        target: { kind: 'personal' },
      },
    }));
    expect(JSON.stringify(received.mock.calls[0])).not.toContain('privateKey');
  });

  it('imports only after explicit paste and clears the private textarea immediately', async () => {
    const el = await mount();
    input(el, '[data-name]', 'Imported key');
    q(el, 'vw-segmented').dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'import' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;
    input(el, '[data-private-key]', 'PRIVATE-IMPORT');
    const received = vi.fn();
    el.addEventListener('vw-ssh-create-import', received);
    q<HTMLButtonElement>(el, '[data-create-ssh]').click();
    expect(received).toHaveBeenCalledWith(expect.objectContaining({
      detail: expect.objectContaining({ privateKey: 'PRIVATE-IMPORT', target: { kind: 'personal' } }),
    }));
    expect(q<HTMLTextAreaElement>(el, '[data-private-key]').value).toBe('');
  });

  it('emits an organization target directly when personal creation is disabled', async () => {
    const el = await mount();
    el.personalCreationAllowed = false;
    el.orgPermissions = [{
      id: 'org-1',
      name: 'Platform',
      canCreateCollections: false,
      canEditCollections: false,
      canDeleteCollections: false,
      canManageCollections: false,
      isMember: true,
      canCreateItems: true,
    }];
    el.collections = [{
      id: 'my-items',
      name: 'My Items',
      organizationId: 'org-1',
      assigned: true,
      readOnly: false,
      type: 1,
      canAssignItems: true,
    }];
    el.folders = [{ id: 'folder-1', name: 'Infrastructure' }];
    await el.updateComplete;
    input(el, '[data-name]', 'Organization deploy key');
    const folder = q<HTMLSelectElement>(el, '[data-folder]');
    folder.value = 'folder-1';
    folder.dispatchEvent(new Event('change'));
    const received = vi.fn();
    el.addEventListener('vw-ssh-create-generate', received);
    q<HTMLButtonElement>(el, '[data-create-ssh]').click();

    expect(q<HTMLSelectElement>(el, '[data-create-vault]').value).toBe('org-1');
    expect(q<HTMLInputElement>(el, '[data-create-collections] input').checked).toBe(true);
    expect(q<HTMLSelectElement>(el, '[data-folder]').disabled).toBe(false);
    expect(received).toHaveBeenCalledWith(expect.objectContaining({
      detail: expect.objectContaining({
        metadata: expect.objectContaining({ folderId: 'folder-1' }),
        target: {
          kind: 'organization',
          organizationId: 'org-1',
          collectionIds: ['my-items'],
        },
      }),
    }));
  });

  it('inherits root-authored folder and organization defaults for a new SSH key', async () => {
    const el = await mount();
    el.draftKey = 'ssh-defaults';
    el.createDefaults = {
      folderId: 'folder-1',
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
    };
    el.orgPermissions = [{
      id: 'org-1',
      name: 'Platform',
      canCreateCollections: false,
      canEditCollections: false,
      canDeleteCollections: false,
      canManageCollections: false,
      isMember: true,
      canCreateItems: true,
    }];
    el.collections = [{
      id: 'collection-1',
      name: 'Team',
      organizationId: 'org-1',
      canAssignItems: true,
    }];
    await el.updateComplete;

    expect(q<HTMLSelectElement>(el, '[data-folder]').value).toBe('folder-1');
    expect(q<HTMLSelectElement>(el, '[data-create-vault]').value).toBe('org-1');
    expect(q<HTMLInputElement>(el, '[data-create-collections] input').checked).toBe(true);
  });

  it('fails closed when neither a personal nor writable organization target exists', async () => {
    const el = await mount();
    el.personalCreationAllowed = false;
    await el.updateComplete;
    input(el, '[data-name]', 'No target');
    const received = vi.fn();
    el.addEventListener('vw-ssh-create-generate', received);
    q<HTMLButtonElement>(el, '[data-create-ssh]').click();
    await el.updateComplete;

    expect(received).not.toHaveBeenCalled();
    expect((el.shadowRoot?.querySelector('vw-status-message') as unknown as { message?: string })?.message)
      .toBe('Select a vault before saving.');
  });

  it('never exposes Linked custom fields', async () => {
    const el = await mount();
    q<HTMLButtonElement>(el, '[data-add-field]').click();
    await el.updateComplete;
    expect([...q<HTMLSelectElement>(el, '[data-field-type-select]').options].map((option) => option.value))
      .toEqual(['0', '1', '2']);
  });

  it('tracks generated and imported create state without treating display-only churn as saved', async () => {
    const generated = await mount();
    expect(generated.hasUnsavedChanges).toBe(false);
    input(generated, '[data-name]', 'Generated key');
    expect(generated.hasUnsavedChanges).toBe(true);
    generated.remove();

    const imported = await mount();
    q(imported, 'vw-segmented').dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'import' }, bubbles: true, composed: true,
    }));
    await imported.updateComplete;
    expect(imported.hasUnsavedChanges).toBe(true);
    input(imported, '[data-private-key]', 'PRIVATE-IMPORT');
    expect(imported.hasUnsavedChanges).toBe(true);
  });
});

describe('vw-ssh-key-editor edit', () => {
  it('names the persisted item, owner, and fingerprint in replacement confirmation', async () => {
    const el = await mount('edit');
    el.summary = sshSummary({ organizationId: 'org-1', collectionIds: ['collection-1'] });
    el.collections = [{ id: 'collection-1', name: 'Infrastructure', organizationId: 'org-1', canAssignItems: true }];
    el.orgPermissions = [{ id: 'org-1', name: 'Platform', canCreateCollections: false, canEditCollections: false, canDeleteCollections: false, canManageCollections: false }];
    await el.updateComplete;
    input(el, '[data-name]', 'Unsaved new name');
    input(el, '[data-private-key]', 'PRIVATE-REPLACEMENT');
    q<HTMLButtonElement>(el, '[data-replace-key]').click();
    await el.updateComplete;
    const dialog = q<HTMLElement & { heading: string }>(el, 'vw-dialog');
    expect(dialog.heading).toBe('Replace the key for Deploy key?');
    expect(dialog.textContent).toContain('Platform');
    expect(dialog.textContent).toContain('Infrastructure');
    expect(dialog.textContent).toContain('SHA256:test');
    expect(dialog.textContent).not.toContain('PRIVATE-REPLACEMENT');
    expect(dialog.textContent).not.toContain('Unsaved new name');
    expect(q<HTMLButtonElement>(el, '[data-confirm-replace]').textContent).toBe('Replace key for Deploy key');
  });

  it('emits metadata without any private key property', async () => {
    const el = await mount('edit');
    const received = vi.fn();
    el.addEventListener('vw-ssh-update-metadata', received);
    q<HTMLButtonElement>(el, '[data-save-ssh-metadata]').click();
    const detail = received.mock.calls[0]![0].detail;
    expect(detail).toMatchObject({ cipherId: 'ssh-1', metadata: { name: 'Deploy key', notes: 'Production' } });
    expect(JSON.stringify(detail)).not.toContain('privateKey');
    expect(detail.metadata.fields).toEqual([{ type: 1, name: 'Host', value: 'hidden-host' }]);
  });

  it('reorders custom fields and emits metadata in the new order', async () => {
    const fields: NonNullable<DecryptedCipher['fields']> = [
      { type: 0, name: 'Text field', value: 'alpha' },
      { type: 1, name: 'Hidden field', value: 'bravo' },
      { type: 2, name: 'Boolean field', value: 'true' },
    ];
    const el = await mount('edit', fields);

    expect([...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('[data-field-move-up]')])
      .toHaveLength(3);
    expect([...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('[data-field-move-down]')])
      .toHaveLength(3);
    expect(q<HTMLButtonElement>(el, '[data-field-move-up]').disabled).toBe(true);
    expect([...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('[data-field-move-down]')][2]!.disabled)
      .toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-field-move-down]').title)
      .toBe(q<HTMLButtonElement>(el, '[data-field-move-down]').getAttribute('aria-label'));

    el.pending = true;
    await el.updateComplete;
    expect([...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('[data-field-move-up], [data-field-move-down]')]
      .every((button) => button.disabled)).toBe(true);
    el.pending = false;
    await el.updateComplete;

    q<HTMLButtonElement>(el, '[data-field-move-down]').click();
    await el.updateComplete;
    expect([...el.shadowRoot!.querySelectorAll<HTMLInputElement>('[data-field-name]')].map((input) => input.value))
      .toEqual(['Hidden field', 'Text field', 'Boolean field']);
    [...el.shadowRoot!.querySelectorAll<HTMLButtonElement>('[data-field-move-up]')][2]!.click();
    await el.updateComplete;
    expect([...el.shadowRoot!.querySelectorAll<HTMLInputElement>('[data-field-name]')].map((input) => input.value))
      .toEqual(['Hidden field', 'Boolean field', 'Text field']);
    expect(el.hasUnsavedChanges).toBe(true);

    const received = vi.fn();
    el.addEventListener('vw-ssh-update-metadata', received);
    q<HTMLButtonElement>(el, '[data-save-ssh-metadata]').click();
    expect(received.mock.calls[0]![0].detail.metadata.fields)
      .toEqual([fields[1], fields[2], fields[0]]);
  });

  it('requires confirmation for replacement and scrubs the textarea after confirm', async () => {
    const el = await mount('edit');
    input(el, '[data-private-key]', 'PRIVATE-REPLACEMENT');
    const received = vi.fn();
    el.addEventListener('vw-ssh-replace-key', received);
    q<HTMLButtonElement>(el, '[data-replace-key]').click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('vw-dialog')).not.toBeNull();
    q<HTMLButtonElement>(el, '[data-confirm-replace]').click();
    await flush(el);
    expect(received).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'ssh-1', privateKey: 'PRIVATE-REPLACEMENT' },
    }));
    expect(q<HTMLTextAreaElement>(el, '[data-private-key]').value).toBe('');
    el.status = { message: 'replacement failed', tone: 'danger' };
    await el.updateComplete;
    expect(q<HTMLTextAreaElement>(el, '[data-private-key]').value).toBe('');
  });

  it('scrubs unsubmitted private material on disconnect', async () => {
    const el = await mount('edit');
    input(el, '[data-private-key]', 'PRIVATE-UNSAVED');
    const textarea = q<HTMLTextAreaElement>(el, '[data-private-key]');
    el.remove();
    expect(textarea.value).toBe('');
  });

  it('reuses the existing collection and organization move events', async () => {
    const el = await mount('edit');
    el.collections = [{
      id: 'collection-1', name: 'Deploy', organizationId: 'org-1', canAssignItems: true,
    }];
    el.orgPermissions = [{ id: 'org-1', name: 'Platform', canCreateCollections: false, canEditCollections: false, canDeleteCollections: false, canManageCollections: false }];
    await el.updateComplete;
    const moved = vi.fn();
    el.addEventListener('vw-editor-share', moved);
    q<HTMLInputElement>(el, '[data-ssh-move] input').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-move-ssh]').click();
    expect(moved).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'ssh-1', organizationId: 'org-1', collectionIds: ['collection-1'] },
    }));

    el.summary = sshSummary({ organizationId: 'org-1', collectionIds: [] });
    await el.updateComplete;
    const collections = vi.fn();
    el.addEventListener('vw-cipher-collections', collections);
    q<HTMLInputElement>(el, '[data-ssh-collections] input').click();
    q<HTMLButtonElement>(el, '[data-save-ssh-collections]').click();
    expect(collections).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'ssh-1', collectionIds: ['collection-1'] },
    }));
  });

  it('hides organization move for archived personal keys but retains archived org collections', async () => {
    const personal = await mount('edit');
    personal.collections = [{
      id: 'collection-1', name: 'Deploy', organizationId: 'org-1', canAssignItems: true,
    }];
    personal.summary = sshSummary({ archivedDate: '2026-08-30T00:00:00Z' });
    await personal.updateComplete;
    expect(personal.shadowRoot!.querySelector('[data-ssh-move]')).toBeNull();

    const organization = await mount('edit');
    organization.collections = [{
      id: 'collection-1', name: 'Deploy', organizationId: 'org-1', canAssignItems: true,
    }];
    organization.summary = sshSummary({
      organizationId: 'org-1',
      archivedDate: '2026-08-30T00:00:00Z',
    });
    await organization.updateComplete;
    expect(organization.shadowRoot!.querySelector('[data-ssh-collections]')).not.toBeNull();
  });

  it('blocks move for every unsaved SSH metadata and private-key input path', async () => {
    const cases: Array<{ name: string; mutate(el: VwSshKeyEditor): void | Promise<void> }> = [
      { name: 'name', mutate: (el) => input(el, '[data-name]', 'Renamed') },
      { name: 'notes', mutate: (el) => input(el, '[data-notes]', 'Changed notes') },
      { name: 'folder', mutate: (el) => {
        const select = q<HTMLSelectElement>(el, '[data-folder]');
        select.value = 'folder-1';
        select.dispatchEvent(new Event('change'));
      } },
      { name: 'favorite', mutate: (el) => q(el, '[data-favorite]').dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: true } })) },
      { name: 'reprompt', mutate: (el) => q(el, '[data-reprompt]').dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: true } })) },
      { name: 'field name', mutate: (el) => input(el, '[data-field-name]', 'Server') },
      { name: 'field value', mutate: (el) => input(el, '[data-field-value]', 'new-hidden-host') },
      { name: 'field type', mutate: (el) => {
        const select = q<HTMLSelectElement>(el, '[data-field-type-select]');
        select.value = '2';
        select.dispatchEvent(new Event('change'));
      } },
      { name: 'field removal', mutate: (el) => q<HTMLButtonElement>(el, '[data-remove-field]').click() },
      { name: 'field addition', mutate: (el) => q<HTMLButtonElement>(el, '[data-add-field]').click() },
      { name: 'private key paste', mutate: (el) => input(el, '[data-private-key]', 'PRIVATE-REPLACEMENT') },
      { name: 'private key file', mutate: async (el) => {
        const fileInput = q<HTMLInputElement>(el, '[data-key-file]');
        Object.defineProperty(fileInput, 'files', {
          configurable: true,
          value: [new File(['PRIVATE-FILE'], 'deploy.key', { type: 'text/plain' })],
        });
        fileInput.dispatchEvent(new Event('change'));
        await flush(el);
      } },
    ];

    for (const testCase of cases) {
      const el = await mount('edit');
      el.collections = [{
        id: 'collection-1', name: 'Deploy', organizationId: 'org-1', canAssignItems: true,
      }];
      await el.updateComplete;
      await testCase.mutate(el);
      await el.updateComplete;
      expect(el.hasUnsavedChanges, testCase.name).toBe(true);
      q<HTMLInputElement>(el, '[data-ssh-move] input').click();
      await el.updateComplete;
      const moved = vi.fn();
      el.addEventListener('vw-editor-share', moved);
      q<HTMLButtonElement>(el, '[data-move-ssh]').click();
      await el.updateComplete;
      expect(moved, testCase.name).not.toHaveBeenCalled();
      expect((el.shadowRoot!.querySelector('vw-status-message') as unknown as { message: string }).message)
        .toBe('Save your item changes before moving it to an organization.');
      el.remove();
    }
  });

  it('preserves dirty SSH metadata and private key input across a same-item summary refresh', async () => {
    const el = await mount('edit');
    input(el, '[data-name]', 'Unsaved name');
    input(el, '[data-private-key]', 'PRIVATE-UNSAVED');
    el.summary = sshSummary({ favorite: true });
    await el.updateComplete;

    expect(q<HTMLInputElement>(el, '[data-name]').value).toBe('Unsaved name');
    expect(q<HTMLTextAreaElement>(el, '[data-private-key]').value).toBe('PRIVATE-UNSAVED');
    expect(el.hasUnsavedChanges).toBe(true);
  });

  it('renders no actionable writes when capability is unavailable', async () => {
    const el = await mount('edit');
    el.available = false;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-save-ssh-metadata]')).toBeNull();
    expect(el.shadowRoot!.textContent).toContain('cannot safely write SSH keys');
  });
});
