// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The reskinned editor composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so we stub it before importing the component.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

import './cipher-editor.js';
import type { VwCipherEditor } from './cipher-editor.js';
import type { VwSelect } from '../../components/select-menu.js';
import type { CipherInput, CipherSummary, CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { EditorContext, EditorSaveDetail, EditorShareDetail } from './editor-types.js';
import { createGeneratorPolicySnapshot } from '../../../core/generator/enterprise-password-policy.js';

function statusText(el: VwCipherEditor): string {
  const node = el.shadowRoot!.querySelector('vw-status-message');
  return node ? ((node as unknown as { message: string }).message ?? '') : '';
}

function ctx(overrides: Partial<EditorContext> = {}): EditorContext {
  return {
    mode: 'create',
    draftKey: 'test-draft',
    type: 1,
    personalCreationAllowed: true,
    folders: [] as FolderSummary[],
    collections: [] as CollectionSummary[],
    orgPermissions: [] as OrgPermission[],
    ...overrides,
  };
}

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return { id: 'c1', name: 'Item', uris: [], loginUris: [], type: 1, favorite: false, ...overrides };
}

function createOrg(id: string, name: string, overrides: Partial<OrgPermission> = {}): OrgPermission {
  return {
    id,
    name,
    canCreateCollections: false,
    canEditCollections: false,
    canDeleteCollections: false,
    canManageCollections: false,
    isMember: true,
    canCreateItems: true,
    ...overrides,
  };
}

async function mount(context: EditorContext, s?: CipherSummary): Promise<VwCipherEditor> {
  const el = document.createElement('vw-cipher-editor') as VwCipherEditor;
  el.context = {
    ...context,
    collections: context.collections.map((collection) => ({
      ...collection,
      canAssignItems: collection.canAssignItems
        ?? (collection.manage === true
          || (collection.readOnly === false && collection.assigned !== false)),
    })),
  };
  el.summary = s;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwCipherEditor, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

function qa<T extends Element>(el: VwCipherEditor, sel: string): T[] {
  return [...el.shadowRoot!.querySelectorAll<T>(sel)];
}

async function setInput(el: VwCipherEditor, sel: string, value: string): Promise<void> {
  const input = q<HTMLInputElement | HTMLTextAreaElement>(el, sel);
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

/** The reskin swaps native flag checkboxes for `<vw-toggle>`; drive it through its custom event. */
async function toggle(el: VwCipherEditor, sel: string, checked: boolean): Promise<void> {
  q(el, sel).dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked }, bubbles: true, composed: true }));
  await el.updateComplete;
}

/** The folder picker is now a `<vw-select>`; drive it through its custom event. */
async function selectValue(el: VwCipherEditor, sel: string, value: string): Promise<void> {
  q(el, sel).dispatchEvent(new CustomEvent('vw-select-change', { detail: { value }, bubbles: true, composed: true }));
  await el.updateComplete;
}

function saveDetail(el: VwCipherEditor): Promise<CipherInput> {
  return new Promise((resolve) => {
    el.addEventListener('vw-editor-save', (e) => resolve((e as CustomEvent<EditorSaveDetail>).detail.input), { once: true });
    q<HTMLButtonElement>(el, '[data-save]').click();
  });
}

function editorSaveDetail(el: VwCipherEditor): Promise<EditorSaveDetail> {
  return new Promise((resolve) => {
    el.addEventListener('vw-editor-save', (event) => {
      resolve((event as CustomEvent<EditorSaveDetail>).detail);
    }, { once: true });
    q<HTMLButtonElement>(el, '[data-save]').click();
  });
}

it('lays out a scroll region under a header with back + save controls', async () => {
  const el = await mount(ctx());
  expect(el.shadowRoot!.querySelector('[data-scroll]')).not.toBeNull();
  expect(el.shadowRoot!.querySelector('[data-back]')).not.toBeNull();
  expect(el.shadowRoot!.querySelector('[data-save]')).not.toBeNull();
});

describe('vw-cipher-editor login', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders login-specific fields for type 1', async () => {
    const el = await mount(ctx({ type: 1 }));
    expect(q(el, '[data-username]')).toBeTruthy();
    expect(q(el, '[data-password]')).toBeTruthy();
    expect(q(el, '[data-field="totp"]')).toBeTruthy();
    expect(q(el, '[data-uri]')).toBeTruthy();
  });

  it('opens the shared generator selector and writes selected username and password into the draft', async () => {
    const el = await mount(ctx({
      type: 1,
      input: {
        type: 1,
        name: 'Generated login',
        login: { uris: [{ uri: 'https://accounts.example.com/login' }] },
      },
    }));
    el.generatorPolicy = createGeneratorPolicySnapshot(null, 4);
    await el.updateComplete;

    q<HTMLButtonElement>(el, '[data-generate-username]').click();
    await el.updateComplete;
    let generator = q<HTMLElement & { selectionTarget: string; websiteUri?: string }>(el, 'vw-generator-view');
    expect(generator.selectionTarget).toBe('username');
    expect(generator.websiteUri).toBe('https://accounts.example.com/login');
    generator.dispatchEvent(new CustomEvent('vw-generator-select', {
      detail: { target: 'username', value: 'generated-user' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-username]').value).toBe('generated-user');

    q<HTMLButtonElement>(el, '[data-generate-password]').click();
    await el.updateComplete;
    generator = q(el, 'vw-generator-view');
    expect(generator.selectionTarget).toBe('password');
    generator.dispatchEvent(new CustomEvent('vw-generator-select', {
      detail: { target: 'password', value: 'generated-secret' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;

    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('generated-secret');
    expect(el.hasUnsavedChanges).toBe(true);
    expect((await saveDetail(el)).login).toEqual(expect.objectContaining({
      username: 'generated-user',
      password: 'generated-secret',
    }));
  });

  it('keeps the draft intact when the generator selector is closed', async () => {
    const el = await mount(ctx({ type: 1 }));
    await setInput(el, '[data-username]', 'manual-user');
    q<HTMLButtonElement>(el, '[data-generate-username]').click();
    await el.updateComplete;
    q(el, 'vw-generator-view').dispatchEvent(new CustomEvent('vw-item-back', {
      bubbles: true, composed: true,
    }));
    await el.updateComplete;

    expect(el.shadowRoot?.querySelector('[data-generator-overlay]')).toBeNull();
    expect(q<HTMLInputElement>(el, '[data-username]').value).toBe('manual-user');
  });

  it('emits a TOTP capture command and applies each root-owned capture once', async () => {
    const el = await mount(ctx({ type: 1 }));
    const capture = vi.fn();
    el.addEventListener('vw-totp-capture', capture);
    q<HTMLButtonElement>(el, '[data-capture-totp]').click();
    expect(capture).toHaveBeenCalledOnce();

    el.totpCapture = {
      revision: 1,
      value: 'otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP',
    };
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-field="totp"]').value)
      .toBe('otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP');

    await setInput(el, '[data-field="totp"]', 'manual-edit');
    el.requestUpdate();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-field="totp"]').value).toBe('manual-edit');
  });

  it('emits a complete CipherInput with login, uris and flags on save', async () => {
    const el = await mount(ctx({ type: 1, folders: [{ id: 'f1', name: 'Work' }] }));
    await setInput(el, '[data-field="name"]', 'GitHub');
    await setInput(el, '[data-username]', 'octocat');
    await setInput(el, '[data-password]', 's3cret');
    await setInput(el, '[data-field="totp"]', 'OTPSEED');
    await setInput(el, '[data-uri]', 'https://github.com');
    await toggle(el, '[data-favorite]', true);
    await toggle(el, '[data-reprompt]', true);
    await selectValue(el, '[data-folder]', 'f1');

    const detail = await saveDetail(el);
    expect(detail).toEqual({
      type: 1,
      name: 'GitHub',
      favorite: true,
      reprompt: true,
      folderId: 'f1',
      login: {
        username: 'octocat',
        password: 's3cret',
        totp: 'OTPSEED',
        uris: [{ uri: 'https://github.com' }],
        autofillOnPageLoad: null,
      },
      fields: [],
    });
  });

  it('preserves multiple URIs and their per-URI match strategy through a round trip', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Multi',
      login: { uris: [{ uri: 'https://a.com', match: 0 }, { uri: 'https://b.com' }] },
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    const uris = qa<HTMLInputElement>(el, '[data-uri]');
    expect(uris.map((u) => u.value)).toEqual(['https://a.com', 'https://b.com']);
    expect(qa<VwSelect>(el, '[data-uri-match]').map((select) => select.value)).toEqual(['0', '']);
    const detail = await saveDetail(el);
    expect(detail.login?.uris).toEqual([{ uri: 'https://a.com', match: 0 }, { uri: 'https://b.com' }]);
  });

  it('round-trips inherit, enabled, and disabled page-load overrides', async () => {
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input: { type: 1, name: 'Page load', login: { autofillOnPageLoad: false } },
    }), summary());
    const picker = q<VwSelect>(el, '[data-page-load-override]');
    expect(picker.value).toBe('false');
    expect(picker.options.map((option) => option.value)).toEqual(['inherit', 'true', 'false']);
    expect((await saveDetail(el)).login?.autofillOnPageLoad).toBe(false);

    await selectValue(el, '[data-page-load-override]', 'true');
    expect((await saveDetail(el)).login?.autofillOnPageLoad).toBe(true);
    await selectValue(el, '[data-page-load-override]', 'inherit');
    expect((await saveDetail(el)).login?.autofillOnPageLoad).toBeNull();
  });

  it('offers inherit plus all six URI strategies and emits the selected strategy', async () => {
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input: { type: 1, name: 'Match', login: { uris: [{ uri: 'https://example.com', match: 4 }] } },
    }), summary());
    const picker = q<VwSelect>(el, '[data-uri-match="0"]');
    expect(picker.value).toBe('4');
    expect(picker.options.map((option) => option.value)).toEqual(['', '0', '1', '2', '3', '4', '5']);

    await selectValue(el, '[data-uri-match="0"]', '5');
    expect((await saveDetail(el)).login?.uris).toEqual([{ uri: 'https://example.com', match: 5 }]);
  });

  it('clears a per-URI strategy when inherit/default is selected', async () => {
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input: { type: 1, name: 'Match', login: { uris: [{ uri: 'https://example.com', match: 3 }] } },
    }), summary());
    await selectValue(el, '[data-uri-match="0"]', '');
    expect((await saveDetail(el)).login?.uris).toEqual([{ uri: 'https://example.com' }]);
  });

  it('adds a new empty URI row', async () => {
    const el = await mount(ctx({ type: 1 }));
    expect(qa(el, '[data-uri]')).toHaveLength(1);
    q<HTMLButtonElement>(el, '[data-add-uri]').click();
    await el.updateComplete;
    expect(qa(el, '[data-uri]')).toHaveLength(2);
    expect(qa<VwSelect>(el, '[data-uri-match]').map((select) => select.value)).toEqual(['', '']);
  });

  it('removes a URI without changing the remaining row or match strategy', async () => {
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input: {
        type: 1,
        name: 'Multi',
        login: { uris: [{ uri: 'https://remove.example', match: 2 }, { uri: 'https://keep.example', match: 3 }] },
      },
    }), summary());
    q<HTMLButtonElement>(el, '[data-remove-uri="0"]').click();
    await el.updateComplete;
    expect(qa<HTMLInputElement>(el, '[data-uri]').map((input) => input.value)).toEqual(['https://keep.example']);
    expect((await saveDetail(el)).login?.uris).toEqual([{ uri: 'https://keep.example', match: 3 }]);
  });

  it('always retains one URI row', async () => {
    const el = await mount(ctx({ type: 1 }));
    const remove = q<HTMLButtonElement>(el, '[data-remove-uri="0"]');
    expect(remove.disabled).toBe(true);
    remove.click();
    await el.updateComplete;
    expect(qa(el, '[data-uri]')).toHaveLength(1);
  });

  it('requires a name and does not emit save when missing', async () => {
    const el = await mount(ctx({ type: 1 }));
    const handler = vi.fn();
    el.addEventListener('vw-editor-save', handler);
    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;
    expect(handler).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('请输入名称');
  });

  it('toggles password visibility without leaking the value into an attribute', async () => {
    const el = await mount(ctx({ type: 1 }));
    const pw = q<HTMLInputElement>(el, '[data-password]');
    expect(pw.type).toBe('password');
    q<HTMLButtonElement>(el, '[data-toggle-password]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-password]').type).toBe('text');
  });
});

describe('vw-cipher-editor other types', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders only name/notes/common fields for a secure note (type 2)', async () => {
    const el = await mount(ctx({ type: 2 }));
    expect(el.shadowRoot!.querySelector('[data-username]')).toBeNull();
    expect(q(el, '[data-notes]')).toBeTruthy();
    await setInput(el, '[data-field="name"]', 'Note');
    await setInput(el, '[data-notes]', 'secret memo');
    const detail = await saveDetail(el);
    expect(detail).toEqual({ type: 2, name: 'Note', favorite: false, reprompt: false, folderId: null, notes: 'secret memo', fields: [] });
  });

  it('collects card fields for type 3', async () => {
    const el = await mount(ctx({ type: 3 }));
    await setInput(el, '[data-field="name"]', 'Visa');
    await setInput(el, '[data-field="card.number"]', '4111111111111111');
    await setInput(el, '[data-field="card.code"]', '123');
    const detail = await saveDetail(el);
    expect(detail.card).toEqual({ number: '4111111111111111', code: '123' });
  });

  it('collects identity fields for type 4', async () => {
    const el = await mount(ctx({ type: 4 }));
    await setInput(el, '[data-field="name"]', 'Me');
    await setInput(el, '[data-field="identity.firstName"]', 'Ada');
    await setInput(el, '[data-field="identity.ssn"]', '123-45-6789');
    const detail = await saveDetail(el);
    expect(detail.identity).toEqual({ firstName: 'Ada', ssn: '123-45-6789' });
  });
});

describe('vw-cipher-editor custom fields', () => {
  afterEach(() => document.body.replaceChildren());

  it('collects newly named Text/Hidden/Boolean fields and preserves a supported Linked field', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Item',
      fields: [
        { type: 0, name: 'Text field', value: 'hello' },
        { type: 3, name: 'Linked user', linkedId: 100 },
      ],
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    const linkedRow = q<HTMLElement>(el, '[data-cf-type="3"]');
    expect(linkedRow.querySelector<HTMLSelectElement>('[data-cf-type-sel]')?.disabled).toBe(true);
    expect(linkedRow.querySelector<HTMLSelectElement>('[data-cf-linked]')!.value).toBe('100');

    // Add a Boolean field and turn it on.
    q<HTMLButtonElement>(el, '[data-add-field]').click();
    await el.updateComplete;
    const newSel = qa<HTMLSelectElement>(el, '[data-cf-type-sel]').at(-1)!;
    newSel.value = '2';
    newSel.dispatchEvent(new Event('change'));
    await el.updateComplete;
    const boolRows = qa<HTMLElement>(el, '[data-cf-type="2"]');
    const boolName = boolRows.at(-1)!.querySelector<HTMLInputElement>('[data-cf-name]')!;
    boolName.value = 'Enabled';
    boolName.dispatchEvent(new Event('input'));
    await el.updateComplete;
    // The boolean value control is now a <vw-toggle>; drive it through its custom event.
    const boolToggle = qa<HTMLElement>(el, '[data-cf-type="2"]').at(-1)!.querySelector<HTMLElement>('[data-cf-value]')!;
    boolToggle.dispatchEvent(new CustomEvent('vw-toggle-change', { detail: { checked: true }, bubbles: true, composed: true }));
    await el.updateComplete;

    const detail = await saveDetail(el);
    expect(detail.fields).toEqual([
      { type: 0, name: 'Text field', value: 'hello' },
      { type: 3, name: 'Linked user', linkedId: 100 },
      { type: 2, name: 'Enabled', value: 'true' },
    ]);
  });

  it('locks every existing field type and round-trips names and values without normalization', async () => {
    const fields: NonNullable<CipherInput['fields']> = [
      { type: 0, name: '  spaced text  ', value: '' },
      { type: 1, name: 'Hidden payload', value: '<img src=x onerror=alert(1)>' },
      { type: 2, name: 'Legacy boolean', value: 'TRUE' },
      { type: 3, name: 'Linked username', linkedId: 100 },
    ];
    const input: CipherInput = { type: 1, name: 'Legacy item', fields };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());

    const typeSelectors = qa<HTMLSelectElement>(el, '[data-cf-type-sel]');
    expect(typeSelectors).toHaveLength(4);
    expect(typeSelectors.every((selector) => selector.disabled && selector.hasAttribute('data-cf-type-locked')))
      .toBe(true);
    typeSelectors[0]!.value = '1';
    typeSelectors[0]!.dispatchEvent(new Event('change'));
    await el.updateComplete;

    expect(qa<HTMLElement>(el, '[data-cf]').map((row) => row.dataset.cfType)).toEqual(['0', '1', '2', '3']);
    expect(q<HTMLInputElement>(el, '[data-cf-type="1"] [data-cf-value]').value)
      .toBe('<img src=x onerror=alert(1)>');
    expect(el.hasUnsavedChanges).toBe(false);
    expect((await saveDetail(el)).fields).toEqual(fields);
  });

  it('preserves legacy empty labels and optional values while making every empty label explicit', async () => {
    const fields: NonNullable<CipherInput['fields']> = [
      { type: 0, name: '', value: '' },
      { type: 1, name: '   ', value: 'hidden-secret' },
      { type: 2, name: '' },
      { type: 3, name: '', linkedId: 999 },
    ];
    const input: CipherInput = { type: 1, name: 'Imported legacy item', fields };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());

    expect(qa(el, '[data-cf-empty-name]')).toHaveLength(4);
    expect(qa<HTMLInputElement>(el, '[data-cf-name]').map((field) => field.value)).toEqual(['', '   ', '', '']);
    expect(qa<HTMLInputElement>(el, '[data-cf-name]')[0]!.placeholder).toContain('未命名');
    expect(el.hasUnsavedChanges).toBe(false);
    expect((await saveDetail(el)).fields).toEqual(fields);
  });

  it('allows repairing an empty legacy label without changing its Hidden value or field type', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Imported legacy item',
      fields: [{ type: 1, name: '', value: 'do-not-reset' }],
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    expect(q<HTMLSelectElement>(el, '[data-cf-type-sel]').disabled).toBe(true);

    await setInput(el, '[data-cf-name]', 'Recovered label');
    expect(el.shadowRoot!.querySelector('[data-cf-empty-name]')).toBeNull();
    expect(q<HTMLSelectElement>(el, '[data-cf-type-sel]').disabled).toBe(true);
    expect((await saveDetail(el)).fields).toEqual([
      { type: 1, name: 'Recovered label', value: 'do-not-reset' },
    ]);
  });

  it('does not normalize a legacy Boolean until the user explicitly changes its toggle', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Imported legacy item',
      fields: [{ type: 2, name: 'Legacy boolean', value: 'not-a-canonical-boolean' }],
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    expect((await saveDetail(el)).fields).toEqual(input.fields);

    q(el, '[data-cf-value]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: true },
      bubbles: true,
      composed: true,
    }));
    await el.updateComplete;
    expect((await saveDetail(el)).fields).toEqual([
      { type: 2, name: 'Legacy boolean', value: 'true' },
    ]);
  });

  it('blocks a new empty or whitespace-only label instead of silently dropping the field', async () => {
    const el = await mount(ctx({ mode: 'create', type: 1 }));
    await setInput(el, '[data-field="name"]', 'New item');
    q<HTMLButtonElement>(el, '[data-add-field]').click();
    await el.updateComplete;
    await setInput(el, '[data-cf-name]', '   ');
    const saved = vi.fn();
    el.addEventListener('vw-editor-save', saved);

    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;

    expect(saved).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('请为每个自定义字段填写名称');
    expect(qa(el, '[data-cf]')).toHaveLength(1);

    q<HTMLButtonElement>(el, '[data-cf-remove]').click();
    await el.updateComplete;
    const detail = await saveDetail(el);
    expect(detail.fields).toEqual([]);
  });

  it('does not treat a prefilled create-mode field as a legacy exemption', async () => {
    const el = await mount(ctx({
      mode: 'create',
      type: 1,
      input: { type: 1, name: 'Prefilled create', fields: [{ type: 1, name: '', value: 'secret' }] },
    }));
    const saved = vi.fn();
    el.addEventListener('vw-editor-save', saved);

    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;

    expect(saved).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('请为每个自定义字段填写名称');
    expect(q<HTMLInputElement>(el, '[data-cf-value]').value).toBe('secret');
  });

  it('rejects clearing a previously named field unless the user explicitly removes it', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Existing item',
      fields: [{ type: 0, name: 'Required label', value: 'keep me' }],
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    await setInput(el, '[data-cf-name]', '');
    const saved = vi.fn();
    el.addEventListener('vw-editor-save', saved);

    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;

    expect(saved).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('请为每个自定义字段填写名称');
    expect(q<HTMLInputElement>(el, '[data-cf-value]').value).toBe('keep me');
  });

  it('creates a Linked field only from the official targets for the current cipher type', async () => {
    const el = await mount(ctx({ mode: 'create', type: 1 }), undefined);
    q<HTMLButtonElement>(el, '[data-add-field]').click();
    await el.updateComplete;
    const typeSelect = q<HTMLSelectElement>(el, '[data-cf-type-sel]');
    expect(Array.from(typeSelect.options, (option) => option.value)).toEqual(['0', '1', '2', '3']);
    typeSelect.value = '3';
    typeSelect.dispatchEvent(new Event('change'));
    await el.updateComplete;

    const row = q<HTMLElement>(el, '[data-cf-type="3"]');
    const name = row.querySelector<HTMLInputElement>('[data-cf-name]')!;
    name.value = 'Account password';
    name.dispatchEvent(new Event('input'));
    const target = row.querySelector<HTMLSelectElement>('[data-cf-linked]')!;
    expect(Array.from(target.options, (option) => option.value)).toEqual(['100', '101']);
    target.value = '101';
    target.dispatchEvent(new Event('change'));
    await el.updateComplete;

    await setInput(el, '[data-field="name"]', 'Linked login');
    expect((await saveDetail(el)).fields).toEqual([
      { type: 3, name: 'Account password', linkedId: 101 },
    ]);
  });

  it('uses the official Card and Identity linked target catalogs and omits Linked for notes', async () => {
    const card = await mount(ctx({ mode: 'create', type: 3 }), undefined);
    q<HTMLButtonElement>(card, '[data-add-field]').click();
    await card.updateComplete;
    expect(Array.from(q<HTMLSelectElement>(card, '[data-cf-type-sel]').options, (option) => option.value))
      .toEqual(['0', '1', '2', '3']);
    const cardType = q<HTMLSelectElement>(card, '[data-cf-type-sel]');
    cardType.value = '3';
    cardType.dispatchEvent(new Event('change'));
    await card.updateComplete;
    expect(Array.from(q<HTMLSelectElement>(card, '[data-cf-linked]').options, (option) => option.value))
      .toEqual(['300', '305', '304', '301', '302', '303']);
    card.remove();

    const identity = await mount(ctx({ mode: 'create', type: 4 }), undefined);
    q<HTMLButtonElement>(identity, '[data-add-field]').click();
    await identity.updateComplete;
    const identityType = q<HTMLSelectElement>(identity, '[data-cf-type-sel]');
    identityType.value = '3';
    identityType.dispatchEvent(new Event('change'));
    await identity.updateComplete;
    expect(Array.from(q<HTMLSelectElement>(identity, '[data-cf-linked]').options, (option) => option.value))
      .toEqual(['400', '416', '401', '418', '417', '413', '409', '412', '414', '415', '410', '411', '402', '403', '404', '405', '406', '407', '408']);
    identity.remove();

    const note = await mount(ctx({ mode: 'create', type: 2 }), undefined);
    q<HTMLButtonElement>(note, '[data-add-field]').click();
    await note.updateComplete;
    expect(Array.from(q<HTMLSelectElement>(note, '[data-cf-type-sel]').options, (option) => option.value))
      .toEqual(['0', '1', '2']);
  });

  it('keeps an unknown or cross-type Linked target read-only and preserves it verbatim', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Legacy item',
      fields: [{ type: 3, name: 'Future target', linkedId: 999 }],
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    const row = q<HTMLElement>(el, '[data-cf-type="3"]');
    expect(row.querySelector('[data-cf-type-sel]')).toBeNull();
    expect(row.querySelector('[data-cf-linked]')).toBeNull();
    expect((await saveDetail(el)).fields).toEqual([
      { type: 3, name: 'Future target', linkedId: 999 },
    ]);
  });

  it('reorders every custom-field rendering branch and saves the new order', async () => {
    const fields: NonNullable<CipherInput['fields']> = [
      { type: 0, name: 'Text field', value: 'alpha' },
      { type: 3, name: 'Linked field', linkedId: 100 },
      { type: 3, name: 'Future field', linkedId: 999 },
    ];
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input: {
      type: 1,
      name: 'Ordered fields',
      fields,
    } }), summary());

    expect(qa<HTMLButtonElement>(el, '[data-cf-move-up]')).toHaveLength(3);
    expect(qa<HTMLButtonElement>(el, '[data-cf-move-down]')).toHaveLength(3);
    expect(qa<HTMLButtonElement>(el, '[data-cf-move-up]')[0]!.disabled).toBe(true);
    expect(qa<HTMLButtonElement>(el, '[data-cf-move-down]')[2]!.disabled).toBe(true);
    expect(qa<HTMLButtonElement>(el, '[data-cf-move-down]')[0]!.title)
      .toBe(qa<HTMLButtonElement>(el, '[data-cf-move-down]')[0]!.getAttribute('aria-label'));

    el.pending = true;
    await el.updateComplete;
    expect(qa<HTMLButtonElement>(el, '[data-cf-move-up], [data-cf-move-down]')
      .every((button) => button.disabled)).toBe(true);
    el.pending = false;
    await el.updateComplete;

    qa<HTMLButtonElement>(el, '[data-cf-move-down]')[0]!.click();
    await el.updateComplete;
    expect(qa<HTMLInputElement>(el, '[data-cf-name]').map((input) => input.value))
      .toEqual(['Linked field', 'Text field', 'Future field']);

    qa<HTMLButtonElement>(el, '[data-cf-move-up]')[2]!.click();
    await el.updateComplete;
    expect(qa<HTMLInputElement>(el, '[data-cf-name]').map((input) => input.value))
      .toEqual(['Linked field', 'Future field', 'Text field']);
    expect(qa<HTMLSelectElement>(el, '[data-cf-type-sel]').every((select) => select.disabled))
      .toBe(true);
    expect(el.hasUnsavedChanges).toBe(true);
    expect((await saveDetail(el)).fields).toEqual([fields[1], fields[2], fields[0]]);
  });

  it('removes a custom field row', async () => {
    const input: CipherInput = { type: 1, name: 'Item', fields: [{ type: 0, name: 'A', value: '1' }] };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    q<HTMLButtonElement>(el, '[data-cf-remove]').click();
    await el.updateComplete;
    const detail = await saveDetail(el);
    expect(detail.fields).toEqual([]);
  });
});

describe('vw-cipher-editor create destination', () => {
  afterEach(() => document.body.replaceChildren());

  const writable = (id: string, name: string, organizationId: string, assigned?: boolean): CollectionSummary => ({
    id,
    name,
    organizationId,
    readOnly: false,
    ...(assigned === undefined ? {} : { assigned }),
  });

  it('defaults to an allowed personal vault and emits an explicit personal target', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: true,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [writable('col1', 'Team', 'org1', true)],
    }));
    const personal = q<HTMLInputElement>(el, '[data-create-vault="personal"]');
    const organization = q<HTMLInputElement>(el, '[data-create-org="org1"]');
    expect(personal.checked).toBe(true);
    expect(organization.checked).toBe(false);
    expect(personal.closest('label')?.textContent).toContain('个人 Vault');
    expect(q<HTMLFieldSetElement>(el, '[data-create-target]').querySelector('legend')?.textContent).toContain('Vault');

    await setInput(el, '[data-field="name"]', 'Personal login');
    const detail = await editorSaveDetail(el);
    expect(detail.input.name).toBe('Personal login');
    expect(detail.target).toEqual({ kind: 'personal' });
  });

  it('applies validated folder, organization, collection, and login URI create defaults', async () => {
    const el = await mount(ctx({
      folders: [{ id: 'folder-1', name: 'Current folder' }],
      personalCreationAllowed: true,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [writable('col1', 'Engineering', 'org1', true)],
      createDefaults: {
        folderId: 'folder-1',
        organizationId: 'org1',
        collectionIds: ['col1'],
        loginUri: 'https://active.example/path',
      },
    }));

    expect(q<VwSelect>(el, '[data-folder]').value).toBe('folder-1');
    expect(q<HTMLInputElement>(el, '[data-uri]').value).toBe('https://active.example/path');
    expect(q<HTMLInputElement>(el, '[data-create-org="org1"]').checked).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-create-collection="col1"]').checked).toBe(true);
    await setInput(el, '[data-field="name"]', 'Inherited login');
    expect((await editorSaveDetail(el)).target).toEqual({
      kind: 'organization',
      organizationId: 'org1',
      collectionIds: ['col1'],
    });
  });

  it('treats clone as an editable create draft with no source mutation controls', async () => {
    const el = await mount(ctx({
      mode: 'clone',
      draftKey: 'clone-1',
      type: 1,
      input: {
        type: 1,
        name: 'Source login',
        folderId: 'folder-1',
        login: { username: 'alice', password: 'secret' },
      },
      folders: [{ id: 'folder-1', name: 'Folder' }],
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [writable('col1', 'Engineering', 'org1', true)],
      createDefaults: { organizationId: 'org1', collectionIds: ['col1'] },
    }));

    expect(q<HTMLInputElement>(el, '[data-field="name"]').value).toBe('Source login');
    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('secret');
    expect(el.shadowRoot?.querySelector('[data-delete]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-collections]')).toBeNull();
    expect(el.shadowRoot?.querySelector('[data-move]')).toBeNull();
    const detail = await editorSaveDetail(el);
    expect(detail.target).toEqual({
      kind: 'organization',
      organizationId: 'org1',
      collectionIds: ['col1'],
    });
  });

  it('asks before discarding a dirty editor draft', async () => {
    const el = await mount(ctx());
    const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(true);
    Object.defineProperty(window, 'confirm', { value: confirm, configurable: true });
    await setInput(el, '[data-field="name"]', 'Unsaved');

    expect(el.promptForUnsavedEdits()).toBe(false);
    expect(el.promptForUnsavedEdits()).toBe(true);
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it('shows an honest unavailable state and refuses save when no destination is permitted', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: false,
      orgPermissions: [
        createOrg('not-member', 'Provider only', { isMember: false }),
        createOrg('no-create', 'Read only member', { canCreateItems: false }),
      ],
    }));
    expect(qa(el, '[data-create-vault]')).toHaveLength(0);
    expect(q<HTMLElement>(el, '[data-no-create-target]').textContent).toContain('没有可用于新建');

    await setInput(el, '[data-field="name"]', 'Blocked');
    const saved = vi.fn();
    el.addEventListener('vw-editor-save', saved);
    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;
    expect(saved).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('请先选择保存位置');
  });

  it('defaults a sole eligible organization but requires a writable collection', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [writable('col1', 'Engineering', 'org1', true)],
    }));
    const organization = q<HTMLInputElement>(el, '[data-create-org="org1"]');
    const collection = q<HTMLInputElement>(el, '[data-create-collection="col1"]');
    expect(organization.checked).toBe(true);
    expect(collection.checked).toBe(false);
    expect(collection.closest('label')?.textContent).toContain('Engineering');

    await setInput(el, '[data-field="name"]', 'Org login');
    const saved = vi.fn();
    el.addEventListener('vw-editor-save', saved);
    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;
    expect(saved).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('至少选择一个可写集合');

    collection.click();
    await el.updateComplete;
    const detail = await editorSaveDetail(el);
    expect(detail.target).toEqual({
      kind: 'organization',
      organizationId: 'org1',
      collectionIds: ['col1'],
    });
  });

  it('requires an explicit organization choice when personal creation is denied and several are eligible', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme'), createOrg('org2', 'Beta')],
      collections: [
        writable('col1', 'Acme Team', 'org1', true),
        writable('col2', 'Beta Team', 'org2', true),
      ],
    }));
    expect(qa<HTMLInputElement>(el, '[data-create-vault]').every((radio) => !radio.checked)).toBe(true);
    expect(el.shadowRoot!.querySelector('[data-create-collections]')).toBeNull();

    q<HTMLInputElement>(el, '[data-create-org="org2"]').click();
    await el.updateComplete;
    expect(qa<HTMLInputElement>(el, '[data-create-collection]').map((box) => box.dataset.createCollection))
      .toEqual(['col2']);
    q<HTMLInputElement>(el, '[data-create-collection="col2"]').click();
    await setInput(el, '[data-field="name"]', 'Beta login');
    expect((await editorSaveDetail(el)).target).toEqual({
      kind: 'organization',
      organizationId: 'org2',
      collectionIds: ['col2'],
    });
  });

  it('shows only same-organization assigned writable collections', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [
        writable('assigned', 'Assigned', 'org1', true),
        writable('legacy', 'Legacy assignment', 'org1'),
        writable('unassigned', 'Unassigned', 'org1', false),
        { id: 'readonly', name: 'Read only', organizationId: 'org1', assigned: true, readOnly: true },
        { id: 'unknown-access', name: 'Unknown access', organizationId: 'org1', assigned: true },
        writable('other-org', 'Other', 'org2', true),
      ],
    }));
    expect(qa<HTMLInputElement>(el, '[data-create-collection]').map((box) => box.dataset.createCollection))
      .toEqual(['assigned', 'legacy']);
  });

  it('explains when an eligible organization has no writable assigned collection', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [
        { id: 'readonly', name: 'Read only', organizationId: 'org1', assigned: true, readOnly: true },
      ],
    }));
    expect(qa(el, '[data-create-collection]')).toHaveLength(0);
    expect(q<HTMLElement>(el, '[data-no-writable-collections]').textContent)
      .toContain('没有已分配且可写的集合');
  });

  it('clears collection choices whenever the vault changes', async () => {
    const el = await mount(ctx({
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme'), createOrg('org2', 'Beta')],
      collections: [
        writable('col1', 'Acme Team', 'org1', true),
        writable('col2', 'Beta Team', 'org2', true),
      ],
    }));
    q<HTMLInputElement>(el, '[data-create-org="org1"]').click();
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-create-collection="col1"]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-create-collection="col1"]').checked).toBe(true);

    q<HTMLInputElement>(el, '[data-create-org="org2"]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-create-collection="col2"]').checked).toBe(false);
    q<HTMLInputElement>(el, '[data-create-org="org1"]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-create-collection="col1"]').checked).toBe(false);
  });

  it('does not render destination controls in edit mode and keeps target undefined', async () => {
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input: { type: 1, name: 'Existing' },
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme')],
    }), summary());
    expect(el.shadowRoot!.querySelector('[data-create-target]')).toBeNull();
    const detail = await editorSaveDetail(el);
    expect(detail.input.name).toBe('Existing');
    expect(detail).toHaveProperty('target', undefined);
  });
});

describe('vw-cipher-editor collections and sharing', () => {
  afterEach(() => document.body.replaceChildren());

  const orgCollections: CollectionSummary[] = [
    { id: 'col1', name: 'Team', organizationId: 'org1', assigned: true, readOnly: false },
    { id: 'col2', name: 'Ops', organizationId: 'org1', assigned: true, readOnly: false },
  ];
  const orgPermissions = [createOrg('org1', 'Acme')];

  it('shows collection assignment for an org item and emits vw-cipher-collections separately', async () => {
    const input: CipherInput = { type: 1, name: 'Shared' };
    const el = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections }),
      summary({ organizationId: 'org1', collectionIds: ['col1'] }),
    );
    const boxes = qa<HTMLInputElement>(el, '[data-collection]');
    expect(boxes.map((b) => b.checked)).toEqual([true, false]);
    boxes[1]!.click();
    await el.updateComplete;
    const detail = await new Promise<{ cipherId: string; collectionIds: string[] }>((resolve) => {
      el.addEventListener('vw-cipher-collections', (e) => resolve((e as CustomEvent).detail), { once: true });
      q<HTMLButtonElement>(el, '[data-save-collections]').click();
    });
    expect(detail.cipherId).toBe('c1');
    expect(detail.collectionIds.sort()).toEqual(['col1', 'col2']);
  });

  it('offers move-to-organization for a personal item and emits vw-editor-share', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const el = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections, orgPermissions }),
      summary(),
    );
    expect(qa(el, '[data-move-col]')).toHaveLength(0);
    q<HTMLInputElement>(el, '[data-move-org="org1"]').click();
    await el.updateComplete;
    const move = qa<HTMLInputElement>(el, '[data-move-col]');
    expect(move).toHaveLength(2);
    move[0]!.click();
    const detail = await new Promise<{ cipherId: string; organizationId: string; collectionIds: string[] }>((resolve) => {
      el.addEventListener('vw-editor-share', (e) => resolve((e as CustomEvent).detail), { once: true });
      q<HTMLButtonElement>(el, '[data-move-confirm]').click();
    });
    expect(detail).toEqual({ cipherId: 'c1', organizationId: 'org1', collectionIds: ['col1'] });
  });

  it('hides organization move for archived personal items while retaining archived org collections', async () => {
    const input: CipherInput = { type: 1, name: 'Archived' };
    const personal = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections }),
      summary({ archivedDate: '2026-08-30T00:00:00Z' }),
    );
    expect(personal.shadowRoot!.querySelector('[data-move]')).toBeNull();

    const organization = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections }),
      summary({
        organizationId: 'org1',
        collectionIds: ['col1'],
        archivedDate: '2026-08-30T00:00:00Z',
      }),
    );
    expect(organization.shadowRoot!.querySelector('[data-collections]')).not.toBeNull();
  });

  it('blocks move-to-organization until unsaved item fields are saved', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Personal',
      notes: 'Original',
      login: { username: 'alice', password: 'old-secret', uris: [{ uri: 'https://old.example' }] },
    };
    const el = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections, orgPermissions }),
      summary(),
    );
    await setInput(el, '[data-password]', 'new-secret');
    expect(el.hasUnsavedChanges).toBe(true);
    q<HTMLInputElement>(el, '[data-move-org="org1"]').click();
    await el.updateComplete;
    qa<HTMLInputElement>(el, '[data-move-col]')[0]!.click();
    const moved = vi.fn();
    el.addEventListener('vw-editor-share', moved);
    q<HTMLButtonElement>(el, '[data-move-confirm]').click();
    await el.updateComplete;

    expect(moved).not.toHaveBeenCalled();
    expect(statusText(el)).toBe('请先保存条目修改，再将其移动到组织。');
  });

  it('keeps collection membership independently writable while item fields are dirty', async () => {
    const input: CipherInput = { type: 1, name: 'Shared', notes: 'Original' };
    const el = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections }),
      summary({ organizationId: 'org1', collectionIds: ['col1'] }),
    );
    await setInput(el, '[data-notes]', 'Unsaved metadata');
    expect(el.hasUnsavedChanges).toBe(true);
    qa<HTMLInputElement>(el, '[data-collection]')[1]!.click();
    const collections = vi.fn();
    el.addEventListener('vw-cipher-collections', collections);
    q<HTMLButtonElement>(el, '[data-save-collections]').click();

    expect(collections).toHaveBeenCalledWith(expect.objectContaining({
      detail: { cipherId: 'c1', collectionIds: ['col1', 'col2'] },
    }));
  });

  it('offers the worker-backed move for items with a passkey or password history', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const el = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections, orgPermissions }),
      summary({ hasPasskey: true, passwordHistoryCount: 2 }),
    );
    expect(el.shadowRoot!.querySelector('[data-move-confirm]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-move-guard]')).toBeNull();
  });

  it('shows collections only after choosing one organization and clears them when the organization changes', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const multiOrg: CollectionSummary[] = [
      { id: 'col1', name: 'A', organizationId: 'org1', assigned: true, readOnly: false },
      { id: 'colX', name: 'B', organizationId: 'org2', assigned: true, readOnly: false },
    ];
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input,
      collections: multiOrg,
      orgPermissions: [createOrg('org1', 'Acme'), createOrg('org2', 'Beta')],
    }), summary());
    expect(qa(el, '[data-move-col]')).toHaveLength(0);

    q<HTMLInputElement>(el, '[data-move-org="org1"]').click();
    await el.updateComplete;
    expect(qa<HTMLInputElement>(el, '[data-move-col]').map((field) => field.value)).toEqual(['col1']);
    q<HTMLInputElement>(el, '[data-move-col="col1"]').click();

    q<HTMLInputElement>(el, '[data-move-org="org2"]').click();
    await el.updateComplete;
    expect(qa<HTMLInputElement>(el, '[data-move-col]').map((field) => field.value)).toEqual(['colX']);
    expect(q<HTMLInputElement>(el, '[data-move-col="colX"]').checked).toBe(false);
  });

  it('offers only confirmed, assigned, writable collections from the selected organization', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const collections: CollectionSummary[] = [
      { id: 'assigned', name: 'Assigned', organizationId: 'org1', assigned: true, readOnly: false },
      { id: 'legacy', name: 'Legacy assignment', organizationId: 'org1', readOnly: false },
      { id: 'unassigned', name: 'Unassigned', organizationId: 'org1', assigned: false, readOnly: false },
      { id: 'readonly', name: 'Read only', organizationId: 'org1', assigned: true, readOnly: true },
      { id: 'unknown', name: 'Unknown access', organizationId: 'org1', assigned: true },
      { id: 'other', name: 'Other organization', organizationId: 'org2', assigned: true, readOnly: false },
    ];
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input,
      collections,
      orgPermissions: [createOrg('org1', 'Acme'), createOrg('org2', 'Beta')],
    }), summary());

    q<HTMLInputElement>(el, '[data-move-org="org1"]').click();
    await el.updateComplete;

    expect(qa<HTMLInputElement>(el, '[data-move-col]').map((field) => field.value))
      .toEqual(['assigned', 'legacy']);
    expect(el.shadowRoot!.textContent).not.toContain('Unassigned');
    expect(el.shadowRoot!.textContent).not.toContain('Read only');
    expect(el.shadowRoot!.textContent).not.toContain('Unknown access');
    expect(el.shadowRoot!.textContent).not.toContain('Other organization');
  });

  it('clears a move selection when the organization permission snapshot changes', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const collections: CollectionSummary[] = [
      {
        id: 'col1', name: 'Acme Team', organizationId: 'org1', assigned: true, readOnly: false,
        canAssignItems: true,
      },
      {
        id: 'col2', name: 'Beta Team', organizationId: 'org2', assigned: true, readOnly: false,
        canAssignItems: true,
      },
    ];
    const initial = ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input,
      collections,
      orgPermissions: [createOrg('org1', 'Acme'), createOrg('org2', 'Beta')],
    });
    const el = await mount(initial, summary());
    q<HTMLInputElement>(el, '[data-move-org="org1"]').click();
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-move-col="col1"]').click();
    await el.updateComplete;

    el.context = {
      ...initial,
      orgPermissions: [
        createOrg('org1', 'Acme', { canCreateItems: false }),
        createOrg('org2', 'Beta'),
      ],
    };
    await el.updateComplete;

    expect(el.shadowRoot!.querySelector('[data-move-org="org1"]')).toBeNull();
    expect(q<HTMLInputElement>(el, '[data-move-org="org2"]').checked).toBe(false);
    expect(el.shadowRoot!.querySelector('[data-move-collections]')).toBeNull();
    const moved = vi.fn();
    el.addEventListener('vw-editor-share', moved);
    q<HTMLButtonElement>(el, '[data-move-confirm]').click();
    await el.updateComplete;
    expect(moved).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('请选择一个当前可用的组织');
  });

  it('preselects the sole type-1 My Items collection for a sole ODO organization', async () => {
    const input: CipherInput = { type: 1, name: 'ODO legacy item' };
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input,
      personalCreationAllowed: false,
      orgPermissions: [createOrg('org1', 'Acme')],
      collections: [
        { id: 'my-items', name: 'My Items', organizationId: 'org1', assigned: true, readOnly: false, type: 1 },
        { id: 'team', name: 'Team', organizationId: 'org1', assigned: true, readOnly: false, type: 0 },
      ],
    }), summary());

    expect(q<HTMLInputElement>(el, '[data-move-org="org1"]').checked).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-move-col="my-items"]').checked).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-move-col="team"]').checked).toBe(false);
    const detail = await new Promise<EditorShareDetail>((resolve) => {
      el.addEventListener('vw-editor-share', (event) => {
        resolve((event as CustomEvent<EditorShareDetail>).detail);
      }, { once: true });
      q<HTMLButtonElement>(el, '[data-move-confirm]').click();
    });
    expect(detail).toEqual({
      cipherId: 'c1',
      organizationId: 'org1',
      collectionIds: ['my-items'],
    });
  });

  it('shows an explicit unavailable state when no organization has a valid move target', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const el = await mount(ctx({
      mode: 'edit',
      type: 1,
      cipherId: 'c1',
      input,
      orgPermissions: [
        createOrg('denied', 'Denied', { canCreateItems: false }),
        createOrg('readonly', 'Read only organization'),
      ],
      collections: [
        { id: 'denied-col', name: 'Denied collection', organizationId: 'denied', assigned: true, readOnly: false },
        { id: 'readonly-col', name: 'Read only', organizationId: 'readonly', assigned: true, readOnly: true },
        { id: 'unassigned', name: 'Unassigned', organizationId: 'readonly', assigned: false, readOnly: false },
      ],
    }), summary());

    expect(q<HTMLElement>(el, '[data-no-move-targets]').textContent).toContain('没有');
    expect(qa(el, '[data-move-org]')).toHaveLength(0);
    expect(qa(el, '[data-move-col]')).toHaveLength(0);
    expect(el.shadowRoot!.querySelector('[data-move-confirm]')).toBeNull();
  });
});

describe('vw-cipher-editor delete, pending and status', () => {
  afterEach(() => document.body.replaceChildren());

  it('emits a soft delete after confirmation in edit mode', async () => {
    const input: CipherInput = { type: 1, name: 'Item' };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await el.updateComplete;
    const detail = await new Promise<{ cipherId: string; permanent: boolean }>((resolve) => {
      el.addEventListener('vw-delete-item', (e) => resolve((e as CustomEvent).detail), { once: true });
      q<HTMLButtonElement>(el, '[data-delete-yes]').click();
    });
    expect(detail).toEqual({ cipherId: 'c1', permanent: false });
  });

  it('has no delete control in create mode', async () => {
    const el = await mount(ctx({ mode: 'create', type: 1 }));
    expect(el.shadowRoot!.querySelector('[data-delete]')).toBeNull();
  });

  it('disables controls while pending', async () => {
    const el = await mount(ctx({ type: 1 }));
    el.pending = true;
    await el.updateComplete;
    expect(q<HTMLButtonElement>(el, '[data-save]').disabled).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-username]').disabled).toBe(true);
    expect(q<VwSelect>(el, '[data-uri-match="0"]').hasAttribute('inert')).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-remove-uri="0"]').disabled).toBe(true);
    expect(q<HTMLFieldSetElement>(el, '[data-create-target]').disabled).toBe(true);
  });

  it('renders a root-provided status message', async () => {
    const el = await mount(ctx({ type: 1 }));
    el.status = { message: 'Server said no', tone: 'danger' };
    await el.updateComplete;
    expect(statusText(el)).toContain('Server said no');
  });
});
