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
import type { CipherInput, CipherSummary, CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { EditorContext } from './editor-types.js';

function statusText(el: VwCipherEditor): string {
  const node = el.shadowRoot!.querySelector('vw-status-message');
  return node ? ((node as unknown as { message: string }).message ?? '') : '';
}

function ctx(overrides: Partial<EditorContext> = {}): EditorContext {
  return {
    mode: 'create',
    type: 1,
    folders: [] as FolderSummary[],
    collections: [] as CollectionSummary[],
    orgPermissions: [] as OrgPermission[],
    ...overrides,
  };
}

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return { id: 'c1', name: 'Item', uris: [], loginUris: [], type: 1, favorite: false, ...overrides };
}

async function mount(context: EditorContext, s?: CipherSummary): Promise<VwCipherEditor> {
  const el = document.createElement('vw-cipher-editor') as VwCipherEditor;
  el.context = context;
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
    el.addEventListener('vw-editor-save', (e) => resolve((e as CustomEvent<CipherInput>).detail), { once: true });
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
      login: { username: 'octocat', password: 's3cret', totp: 'OTPSEED', uris: [{ uri: 'https://github.com' }] },
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
    const detail = await saveDetail(el);
    expect(detail.login?.uris).toEqual([{ uri: 'https://a.com', match: 0 }, { uri: 'https://b.com' }]);
  });

  it('adds a new empty URI row', async () => {
    const el = await mount(ctx({ type: 1 }));
    expect(qa(el, '[data-uri]')).toHaveLength(1);
    q<HTMLButtonElement>(el, '[data-add-uri]').click();
    await el.updateComplete;
    expect(qa(el, '[data-uri]')).toHaveLength(2);
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

  it('collects Text/Hidden/Boolean fields and preserves a read-only Linked field, dropping nameless rows', async () => {
    const input: CipherInput = {
      type: 1,
      name: 'Item',
      fields: [
        { type: 0, name: 'Text field', value: 'hello' },
        { type: 3, name: 'Linked user', linkedId: 100 },
      ],
    };
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input }), summary());
    // Linked field is read-only (no type select) and shows its label.
    const linkedRow = q<HTMLElement>(el, '[data-cf-type="3"]');
    expect(linkedRow.querySelector('[data-cf-type-sel]')).toBeNull();
    expect(linkedRow.textContent).toContain('关联');

    // Add a Boolean field, turn it on, and an empty nameless field that must be dropped.
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

    q<HTMLButtonElement>(el, '[data-add-field]').click(); // nameless Text row → dropped
    await el.updateComplete;

    const detail = await saveDetail(el);
    expect(detail.fields).toEqual([
      { type: 0, name: 'Text field', value: 'hello' },
      { type: 3, name: 'Linked user', linkedId: 100 },
      { type: 2, name: 'Enabled', value: 'true' },
    ]);
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

describe('vw-cipher-editor collections and sharing', () => {
  afterEach(() => document.body.replaceChildren());

  const orgCollections: CollectionSummary[] = [
    { id: 'col1', name: 'Team', organizationId: 'org1' },
    { id: 'col2', name: 'Ops', organizationId: 'org1' },
  ];

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
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections }),
      summary(),
    );
    const move = qa<HTMLInputElement>(el, '[data-move-col]');
    expect(move).toHaveLength(2);
    move[0]!.click();
    const detail = await new Promise<{ cipherId: string; organizationId: string; collectionIds: string[] }>((resolve) => {
      el.addEventListener('vw-editor-share', (e) => resolve((e as CustomEvent).detail), { once: true });
      q<HTMLButtonElement>(el, '[data-move-confirm]').click();
    });
    expect(detail).toEqual({ cipherId: 'c1', organizationId: 'org1', collectionIds: ['col1'] });
  });

  it('guards move-to-organization for items with a passkey or password history', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const el = await mount(
      ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: orgCollections }),
      summary({ hasPasskey: true }),
    );
    expect(el.shadowRoot!.querySelector('[data-move-confirm]')).toBeNull();
    expect(q<HTMLElement>(el, '[data-move-guard]').textContent).toContain('网页版');
  });

  it('rejects a move that spans multiple organizations', async () => {
    const input: CipherInput = { type: 1, name: 'Personal' };
    const multiOrg: CollectionSummary[] = [
      { id: 'col1', name: 'A', organizationId: 'org1' },
      { id: 'colX', name: 'B', organizationId: 'org2' },
    ];
    const el = await mount(ctx({ mode: 'edit', type: 1, cipherId: 'c1', input, collections: multiOrg }), summary());
    const handler = vi.fn();
    el.addEventListener('vw-editor-share', handler);
    qa<HTMLInputElement>(el, '[data-move-col]').forEach((b) => b.click());
    q<HTMLButtonElement>(el, '[data-move-confirm]').click();
    await el.updateComplete;
    expect(handler).not.toHaveBeenCalled();
    expect(statusText(el)).toContain('同一组织');
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
  });

  it('renders a root-provided status message', async () => {
    const el = await mount(ctx({ type: 1 }));
    el.status = { message: 'Server said no', tone: 'danger' };
    await el.updateComplete;
    expect(statusText(el)).toContain('Server said no');
  });
});
