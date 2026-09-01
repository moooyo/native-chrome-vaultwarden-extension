// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './sends-view.js';
import type { VwSendsView } from './sends-view.js';
import type { SendSummary } from '../types.js';
import type { SendCreateDetail, SendUpdateDetail } from '../types.js';
import { setLocale } from '../../i18n/index.js';
import { createGeneratorPolicySnapshot } from '../../../core/generator/enterprise-password-policy.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024;

beforeEach(() => {
  setLocale('en', false);
  Object.defineProperty(window, 'confirm', { value: vi.fn(() => true), configurable: true, writable: true });
});

async function mount(): Promise<VwSendsView> {
  const el = document.createElement('vw-sends-view') as VwSendsView;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

async function openCreate(el: VwSendsView): Promise<void> {
  q<HTMLButtonElement>(el, '[data-new-send]').click();
  await el.updateComplete;
  await el.updateComplete;
}

function q<T extends Element>(el: VwSendsView, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

async function setValue(el: VwSendsView, sel: string, value: string): Promise<void> {
  const input = q<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(el, sel);
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

function send(overrides: Partial<SendSummary> = {}): SendSummary {
  return {
    id: 's1',
    accessId: 'acc',
    type: 0,
    name: 'My send',
    hidden: false,
    url: 'https://vault/#/send/acc/key',
    deletionDate: '2026-08-01T00:00:00.000Z',
    accessCount: 0,
    disabled: false,
    hideEmail: false,
    passwordProtected: false,
    ...overrides,
  };
}

describe('vw-sends-view create', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('starts with the compact create launcher so active Sends remain visible', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('[data-new-send]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-create]')).toBeNull();
  });

  it('moves focus into the create form and restores it when the form closes', async () => {
    const el = await mount();
    await openCreate(el);
    expect(el.shadowRoot!.activeElement).toBe(q(el, '[data-name]'));
    q<HTMLButtonElement>(el, '[data-cancel-create]').click();
    await el.updateComplete;
    await el.updateComplete;
    expect(el.shadowRoot!.activeElement).toBe(q(el, '[data-new-send]'));
  });

  it('emits a text Send create with the collected input', async () => {
    const el = await mount();
    await openCreate(el);
    const created = vi.fn();
    el.addEventListener('vw-send-create', (e) => created((e as CustomEvent<SendCreateDetail>).detail));
    await setValue(el, '[data-name]', 'Note');
    await setValue(el, '[data-notes]', 'private note');
    await setValue(el, '[data-text]', 'secret text');
    q<HTMLInputElement>(el, '[data-hide-email]').checked = true;
    q<HTMLButtonElement>(el, '[data-create]').click();
    expect(created).toHaveBeenCalledTimes(1);
    const detail = created.mock.calls[0]![0] as SendCreateDetail;
    expect(detail.kind).toBe('text');
    expect(detail.input.name).toBe('Note');
    expect(detail.input.notes).toBe('private note');
    expect(detail.input.hideEmail).toBe(true);
    expect((detail as { input: { text?: string } }).input.text).toBe('secret text');
  });

  it('uses the shared generator selector for a new Send password and preserves it as a dirty draft', async () => {
    const el = await mount();
    el.generatorPolicy = createGeneratorPolicySnapshot(null, 3);
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-generate-password="create"]').click();
    await el.updateComplete;
    const generator = q<HTMLElement & { selectionTarget: string }>(el, 'vw-generator-view');
    expect(generator.selectionTarget).toBe('password');
    generator.dispatchEvent(new CustomEvent('vw-generator-select', {
      detail: { target: 'password', value: 'generated-create-password' },
      bubbles: true,
      composed: true,
    }));
    await el.updateComplete;

    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('generated-create-password');
    expect(el.sendFormHasEdits()).toBe(true);
    await setValue(el, '[data-text]', 'secret text');
    const created = vi.fn();
    el.addEventListener('vw-send-create', (event) => created((event as CustomEvent<SendCreateDetail>).detail));
    q<HTMLButtonElement>(el, '[data-create]').click();
    expect((created.mock.calls[0]![0] as SendCreateDetail).input.password)
      .toBe('generated-create-password');
  });

  it('closes the password generator without changing the current Send draft', async () => {
    const el = await mount();
    await openCreate(el);
    await setValue(el, '[data-password]', 'manual-password');
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    q<HTMLButtonElement>(el, '[data-generate-password="create"]').click();
    await el.updateComplete;
    q(el, 'vw-generator-view').dispatchEvent(new CustomEvent('vw-item-back', {
      bubbles: true,
      composed: true,
    }));
    await el.updateComplete;

    expect(el.shadowRoot?.querySelector('[data-generator-overlay]')).toBeNull();
    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('manual-password');
    expect(back).not.toHaveBeenCalled();
  });

  it('offers every official date preset and emits the one-hour preset as integer hours', async () => {
    const el = await mount();
    await openCreate(el);
    const deletion = q<HTMLSelectElement>(el, '[data-deletion]');
    expect(Array.from(deletion.options, (option) => option.value)).toEqual([
      '1', '24', '48', '72', '168', '336', '720',
    ]);
    expect(deletion.value).toBe('168');

    await setValue(el, '[data-deletion]', '1');
    await setValue(el, '[data-expiry]', '1');
    await setValue(el, '[data-text]', 'expires quickly');
    const created = vi.fn();
    el.addEventListener('vw-send-create', (event) => {
      created((event as CustomEvent<SendCreateDetail>).detail);
    });
    q<HTMLButtonElement>(el, '[data-create]').click();

    const detail = created.mock.calls[0]![0] as SendCreateDetail;
    expect(detail.input).toMatchObject({ deletionHours: 1, expirationHours: 1 });
    expect(detail.input).not.toHaveProperty('deletionDays');
    expect(detail.input).not.toHaveProperty('expirationDays');
  });

  it('blocks an empty text Send with an inline error', async () => {
    const el = await mount();
    await openCreate(el);
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    q<HTMLButtonElement>(el, '[data-create]').click();
    await el.updateComplete;
    expect(created).not.toHaveBeenCalled();
    expect((el.validationError ?? '').toLowerCase()).toContain('enter the text to share');
  });

  it('updates visible copy and validation when the locale changes', async () => {
    const el = await mount();
    setLocale('zh-CN', false);
    await el.updateComplete;
    expect(el.shadowRoot!.textContent).toContain('内容在此设备上加密');
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-create]').click();
    await el.updateComplete;
    expect(el.validationError).toBe('请输入要分享的文本');
  });

  it.each([
    { label: 'zero', size: 0 },
    { label: 'limit - 1', size: MAX_FILE_BYTES - 1 },
    { label: 'limit', size: MAX_FILE_BYTES },
  ])('reads a file Send at $label bytes', async ({ size }) => {
    const el = await mount();
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    const fileInput = q<HTMLInputElement>(el, '[data-file]');
    const file = new File(['hi'], 'boundary.bin');
    Object.defineProperty(file, 'size', { value: size });
    const read = vi.spyOn(file, 'arrayBuffer');
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });

    q<HTMLButtonElement>(el, '[data-create]').click();
    await new Promise((resolve) => setTimeout(resolve));
    await el.updateComplete;

    expect(read).toHaveBeenCalledOnce();
    expect(created).toHaveBeenCalledOnce();
  });

  it('rejects a file Send at limit + 1 before reading or emitting', async () => {
    const el = await mount();
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    const fileInput = q<HTMLInputElement>(el, '[data-file]');
    const file = new File([''], 'big.bin');
    Object.defineProperty(file, 'size', { value: MAX_FILE_BYTES + 1 });
    const read = vi.spyOn(file, 'arrayBuffer');
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
    q<HTMLButtonElement>(el, '[data-create]').click();
    await el.updateComplete;
    expect(read).not.toHaveBeenCalled();
    expect(created).not.toHaveBeenCalled();
    expect(el.validationError).toBe('File is too large (max 100 MB)');
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an unsafe file Send size (%s) before reading',
    async (size) => {
      const el = await mount();
      await openCreate(el);
      q<HTMLButtonElement>(el, '[data-mode-file]').click();
      await el.updateComplete;
      const fileInput = q<HTMLInputElement>(el, '[data-file]');
      const file = new File(['hi'], 'unsafe.bin');
      Object.defineProperty(file, 'size', { value: size });
      const read = vi.spyOn(file, 'arrayBuffer');
      Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });

      q<HTMLButtonElement>(el, '[data-create]').click();
      await el.updateComplete;

      expect(read).not.toHaveBeenCalled();
      expect(el.validationError).toBe('File is too large (max 100 MB)');
    },
  );

  it('emits a file Send create with base64 bytes for a valid file', async () => {
    const el = await mount();
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    const detailPromise = new Promise<SendCreateDetail>((resolve) => {
      el.addEventListener('vw-send-create', (e) => resolve((e as CustomEvent<SendCreateDetail>).detail), { once: true });
    });
    const fileInput = q<HTMLInputElement>(el, '[data-file]');
    const file = new File(['hi'], 'note.txt');
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
    q<HTMLButtonElement>(el, '[data-create]').click();
    const detail = await detailPromise;
    expect(detail.kind).toBe('file');
    expect((detail as { fileName: string }).fileName).toBe('note.txt');
    expect((detail as { dataB64: string }).dataB64).toBe(btoa('hi'));
  });

  it('enters the encoding state synchronously when a file create starts', async () => {
    const el = await mount();
    await openCreate(el);
    const busy: boolean[] = [];
    el.addEventListener('vw-send-encoding', (event) => busy.push((event as CustomEvent<{ encoding: boolean }>).detail.encoding));
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    const fileInput = q<HTMLInputElement>(el, '[data-file]');
    const file = new File(['hi'], 'note.txt');
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
    // The base64 encode runs on the popup main thread; the busy flag must be set before the first
    // await so the button can disable / show a spinner rather than appear frozen.
    q<HTMLButtonElement>(el, '[data-create]').click();
    expect(el.encoding).toBe(true);
    // Let the encode + emit settle; the flag clears once the bytes are ready.
    await new Promise((r) => setTimeout(r));
    await el.updateComplete;
    expect(el.encoding).toBe(false);
    expect(busy).toEqual([true, false]);
  });

  it('disables the create button and shows a spinner while encoding', async () => {
    const el = await mount();
    await openCreate(el);
    el.encoding = true;
    await el.updateComplete;
    expect(q<HTMLButtonElement>(el, '[data-create]').disabled).toBe(true);
    expect(el.shadowRoot!.querySelector('[data-encoding]')).not.toBeNull();
  });
});

describe('vw-sends-view list actions', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('copies a Send link', async () => {
    const el = await mount();
    el.sends = { status: 'ready', data: [send()] };
    await el.updateComplete;
    const copied = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    q<HTMLButtonElement>(el, '[data-copy]').click();
    expect(copied).toHaveBeenCalledWith({ value: 'https://vault/#/send/acc/key', label: 'Copy link' });
  });

  it('deletes a Send', async () => {
    const el = await mount();
    el.sends = { status: 'ready', data: [send()] };
    await el.updateComplete;
    const deleted = vi.fn();
    el.addEventListener('vw-send-delete', (e) => deleted((e as CustomEvent).detail));
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await el.updateComplete;
    expect(deleted).not.toHaveBeenCalled();
    q<HTMLButtonElement>(el, '[data-delete-confirm]').click();
    expect(deleted).toHaveBeenCalledWith({ id: 's1' });
  });

  it('cancels a pending Send deletion without emitting', async () => {
    const el = await mount();
    el.sends = { status: 'ready', data: [send()] };
    await el.updateComplete;
    const deleted = vi.fn();
    el.addEventListener('vw-send-delete', deleted);
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await el.updateComplete;
    await el.updateComplete;
    expect(el.shadowRoot!.activeElement).toBe(q(el, '[data-delete-cancel]'));
    q<HTMLButtonElement>(el, '[data-delete-cancel]').click();
    await el.updateComplete;
    expect(deleted).not.toHaveBeenCalled();
    expect(el.shadowRoot!.querySelector('[data-delete-confirm]')).toBeNull();
    expect(el.shadowRoot!.activeElement).toBe(q(el, '[data-delete]'));
  });

  it('disables list mutations and copy while a file is encoding', async () => {
    const el = await mount();
    el.sends = { status: 'ready', data: [send()] };
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-delete]').click();
    await el.updateComplete;
    el.encoding = true;
    await el.updateComplete;
    for (const selector of ['[data-back]', '[data-copy]', '[data-edit]', '[data-delete]']) {
      expect(q<HTMLButtonElement>(el, selector).disabled).toBe(true);
    }
    expect(q<HTMLButtonElement>(el, '[data-delete-confirm]').disabled).toBe(true);
  });

  it('opens the receive page', async () => {
    const el = await mount();
    const received = vi.fn();
    el.addEventListener('vw-send-receive', received);
    q<HTMLButtonElement>(el, '[data-receive]').click();
    expect(received).toHaveBeenCalledTimes(1);
  });
});

describe('vw-sends-view edit password modes', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  async function openEdit(el: VwSendsView, s: SendSummary): Promise<void> {
    el.sends = { status: 'ready', data: [s] };
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-edit]').click();
    await el.updateComplete;
  }

  it('keeps the password when none is entered', async () => {
    const el = await mount();
    await openEdit(el, send());
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (e) => updated((e as CustomEvent<SendUpdateDetail>).detail));
    q<HTMLButtonElement>(el, '[data-save]').click();
    const detail = updated.mock.calls[0]![0] as SendUpdateDetail;
    expect(detail.input.passwordMode).toBe('keep');
  });

  it('loads and updates the hide-email setting', async () => {
    const el = await mount();
    await openEdit(el, send({ hideEmail: true }));
    const control = q<HTMLInputElement>(el, '[data-e-hide-email]');
    expect(control.checked).toBe(true);
    control.checked = false;
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (event) => {
      updated((event as CustomEvent<SendUpdateDetail>).detail);
    });
    q<HTMLButtonElement>(el, '[data-save]').click();
    expect((updated.mock.calls[0]![0] as SendUpdateDetail).input.hideEmail).toBe(false);
  });

  it('emits explicit one-hour date resets while blank presets preserve existing dates', async () => {
    const el = await mount();
    await openEdit(el, send());
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (event) => {
      updated((event as CustomEvent<SendUpdateDetail>).detail);
    });

    q<HTMLButtonElement>(el, '[data-save]').click();
    expect((updated.mock.calls[0]![0] as SendUpdateDetail).input).not.toHaveProperty('deletionHours');
    expect((updated.mock.calls[0]![0] as SendUpdateDetail).input).not.toHaveProperty('expirationHours');

    await setValue(el, '[data-e-deletion]', '1');
    await setValue(el, '[data-e-expiry]', '1');
    q<HTMLButtonElement>(el, '[data-save]').click();
    expect((updated.mock.calls[1]![0] as SendUpdateDetail).input).toMatchObject({
      deletionHours: 1,
      expirationHours: 1,
    });
  });

  it('round-trips editable private notes and omits them when decryption failed', async () => {
    const el = await mount();
    await openEdit(el, send({ notes: 'original note' }));
    expect(q<HTMLTextAreaElement>(el, '[data-e-notes]').value).toBe('original note');
    await setValue(el, '[data-e-notes]', 'updated note');
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (event) => updated((event as CustomEvent<SendUpdateDetail>).detail));
    q<HTMLButtonElement>(el, '[data-save]').click();
    expect((updated.mock.calls[0]![0] as SendUpdateDetail).input.notes).toBe('updated note');

    const unavailable = await mount();
    await openEdit(unavailable, send({ notesUnavailable: true }));
    expect(unavailable.shadowRoot!.querySelector('[data-e-notes]')).toBeNull();
    const preserved = vi.fn();
    unavailable.addEventListener('vw-send-update', (event) => preserved((event as CustomEvent<SendUpdateDetail>).detail));
    q<HTMLButtonElement>(unavailable, '[data-save]').click();
    expect((preserved.mock.calls[0]![0] as SendUpdateDetail).input).not.toHaveProperty('notes');
  });

  it('sets a new password when one is entered', async () => {
    const el = await mount();
    await openEdit(el, send());
    await setValue(el, '[data-e-password]', 'newpw');
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (e) => updated((e as CustomEvent<SendUpdateDetail>).detail));
    q<HTMLButtonElement>(el, '[data-save]').click();
    const detail = updated.mock.calls[0]![0] as SendUpdateDetail;
    expect(detail.input.passwordMode).toBe('set');
    expect(detail.input.newPassword).toBe('newpw');
  });

  it('removes the password when the remove box is checked', async () => {
    const el = await mount();
    await openEdit(el, send({ passwordProtected: true }));
    const remove = q<HTMLInputElement>(el, '[data-e-removepw]');
    remove.checked = true;
    remove.dispatchEvent(new Event('change'));
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (e) => updated((e as CustomEvent<SendUpdateDetail>).detail));
    q<HTMLButtonElement>(el, '[data-save]').click();
    const detail = updated.mock.calls[0]![0] as SendUpdateDetail;
    expect(detail.input.passwordMode).toBe('remove');
  });

  it('turns a generated edit password into an explicit replacement even when remove was selected', async () => {
    const el = await mount();
    el.generatorPolicy = createGeneratorPolicySnapshot(null, 5);
    await openEdit(el, send({ passwordProtected: true }));
    const remove = q<HTMLInputElement>(el, '[data-e-removepw]');
    remove.checked = true;
    q<HTMLButtonElement>(el, '[data-generate-password="edit"]').click();
    await el.updateComplete;
    q(el, 'vw-generator-view').dispatchEvent(new CustomEvent('vw-generator-select', {
      detail: { target: 'password', value: 'generated-edit-password' },
      bubbles: true,
      composed: true,
    }));
    await el.updateComplete;

    expect(remove.checked).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-e-password]').value).toBe('generated-edit-password');
    expect(el.sendFormHasEdits()).toBe(true);
    const updated = vi.fn();
    el.addEventListener('vw-send-update', (event) => updated((event as CustomEvent<SendUpdateDetail>).detail));
    q<HTMLButtonElement>(el, '[data-save]').click();
    const detail = updated.mock.calls[0]![0] as SendUpdateDetail;
    expect(detail.input.passwordMode).toBe('set');
    expect(detail.input.newPassword).toBe('generated-edit-password');
  });
});

describe('vw-sends-view unsaved draft protection', () => {
  afterEach(() => {
    document.body.replaceChildren();
    vi.restoreAllMocks();
  });

  async function openEditForDraft(el: VwSendsView, value = send({ passwordProtected: true, notes: 'note' })): Promise<void> {
    el.sends = { status: 'ready', data: [value] };
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-edit]').click();
    await el.updateComplete;
  }

  it('counts every create field and returns to clean when normalized values match the baseline', async () => {
    const mutations: Array<(el: VwSendsView) => Promise<void> | void> = [
      (el) => setValue(el, '[data-name]', 'name'),
      (el) => setValue(el, '[data-notes]', 'note'),
      (el) => setValue(el, '[data-text]', 'text'),
      (el) => { q<HTMLInputElement>(el, '[data-hidden]').checked = true; },
      (el) => { q<HTMLInputElement>(el, '[data-hide-email]').checked = true; },
      (el) => setValue(el, '[data-password]', 'password'),
      (el) => setValue(el, '[data-expiry]', '24'),
      (el) => setValue(el, '[data-deletion]', '24'),
      (el) => setValue(el, '[data-max]', '10'),
      async (el) => { q<HTMLButtonElement>(el, '[data-mode-file]').click(); await el.updateComplete; },
    ];
    for (const mutate of mutations) {
      const el = await mount();
      await openCreate(el);
      expect(el.sendFormHasEdits()).toBe(false);
      await mutate(el);
      expect(el.sendFormHasEdits()).toBe(true);
      el.remove();
    }

    const normalized = await mount();
    await openCreate(normalized);
    await setValue(normalized, '[data-name]', '   ');
    expect(normalized.sendFormHasEdits()).toBe(false);
  });

  it('keeps a dirty create draft when close is canceled and discards it only after confirmation', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    await openCreate(el);
    await setValue(el, '[data-text]', 'keep this draft');
    q<HTMLButtonElement>(el, '[data-cancel-create]').click();
    await el.updateComplete;
    expect(q<HTMLTextAreaElement>(el, '[data-text]').value).toBe('keep this draft');
    expect(confirm).toHaveBeenCalledWith('Discard your unsaved Send changes?');

    confirm.mockReturnValue(true);
    q<HTMLButtonElement>(el, '[data-cancel-create]').click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-create]')).toBeNull();
  });

  it('guards the route back action but never prompts for an untouched form', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const clean = await mount();
    await openCreate(clean);
    const cleanBack = vi.fn();
    clean.addEventListener('vw-item-back', cleanBack);
    q<HTMLButtonElement>(clean, '[data-back]').click();
    expect(cleanBack).toHaveBeenCalledOnce();
    expect(confirm).not.toHaveBeenCalled();
    clean.remove();

    const dirty = await mount();
    await openCreate(dirty);
    await setValue(dirty, '[data-text]', 'draft');
    const dirtyBack = vi.fn();
    dirty.addEventListener('vw-item-back', dirtyBack);
    q<HTMLButtonElement>(dirty, '[data-back]').click();
    expect(dirtyBack).not.toHaveBeenCalled();
    expect(q<HTMLTextAreaElement>(dirty, '[data-text]').value).toBe('draft');
    confirm.mockReturnValue(true);
    q<HTMLButtonElement>(dirty, '[data-back]').click();
    expect(dirtyBack).toHaveBeenCalledOnce();
  });

  it('guards create-to-edit and variant switches before destroying conditional fields', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    el.sends = { status: 'ready', data: [send()] };
    await el.updateComplete;
    await openCreate(el);
    await setValue(el, '[data-text]', 'draft text');

    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    expect(el.mode).toBe('text');
    expect(q<HTMLTextAreaElement>(el, '[data-text]').value).toBe('draft text');

    q<HTMLButtonElement>(el, '[data-edit]').click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-e-name]')).toBeNull();
    expect(q<HTMLTextAreaElement>(el, '[data-text]').value).toBe('draft text');

    confirm.mockReturnValue(true);
    q<HTMLButtonElement>(el, '[data-edit]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-e-name]').value).toBe('My send');
  });

  it('keeps generated password edits under the existing variant-switch and close confirmations', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    await openCreate(el);
    await setValue(el, '[data-text]', 'text that would be discarded');
    q<HTMLButtonElement>(el, '[data-generate-password="create"]').click();
    await el.updateComplete;
    q(el, 'vw-generator-view').dispatchEvent(new CustomEvent('vw-generator-select', {
      detail: { target: 'password', value: 'generated-password' },
      bubbles: true,
      composed: true,
    }));
    await el.updateComplete;

    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    expect(el.mode).toBe('text');
    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('generated-password');
    q<HTMLButtonElement>(el, '[data-cancel-create]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.querySelector('[data-create]')).not.toBeNull();
    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('generated-password');

    confirm.mockReturnValue(true);
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    expect(el.mode).toBe('file');
    expect(q<HTMLInputElement>(el, '[data-password]').value).toBe('generated-password');
    q<HTMLButtonElement>(el, '[data-cancel-create]').click();
    await el.updateComplete;
    expect(el.shadowRoot?.querySelector('[data-create]')).toBeNull();
  });

  it('does not retain a hidden file after confirming a file-to-text switch', async () => {
    vi.mocked(window.confirm).mockReturnValue(true);
    const el = await mount();
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    const fileInput = q<HTMLInputElement>(el, '[data-file]');
    Object.defineProperty(fileInput, 'files', { value: [new File(['old'], 'old.txt')], configurable: true });
    q<HTMLButtonElement>(el, '[data-mode-text]').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-create]').click();
    await el.updateComplete;
    expect(el.validationError).toBe('Choose a file to share');
  });

  it('counts every editable field in an existing Send', async () => {
    const mutations: Array<(el: VwSendsView) => Promise<void> | void> = [
      (el) => setValue(el, '[data-e-name]', 'changed'),
      (el) => setValue(el, '[data-e-notes]', 'changed note'),
      (el) => setValue(el, '[data-e-text]', 'changed text'),
      (el) => { q<HTMLInputElement>(el, '[data-e-hidden]').checked = true; },
      (el) => { q<HTMLInputElement>(el, '[data-e-disabled]').checked = true; },
      (el) => { q<HTMLInputElement>(el, '[data-e-hide-email]').checked = true; },
      (el) => setValue(el, '[data-e-password]', 'new password'),
      (el) => { q<HTMLInputElement>(el, '[data-e-removepw]').checked = true; },
      (el) => setValue(el, '[data-e-expiry]', '24'),
      (el) => setValue(el, '[data-e-deletion]', '24'),
      (el) => setValue(el, '[data-e-max]', '10'),
    ];
    for (const mutate of mutations) {
      const el = await mount();
      await openEditForDraft(el);
      expect(el.sendFormHasEdits()).toBe(false);
      await mutate(el);
      expect(el.sendFormHasEdits()).toBe(true);
      el.remove();
    }
  });

  it('keeps a dirty edit and its immutable target snapshot across cancel and list refreshes', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    await openEditForDraft(el);
    await setValue(el, '[data-e-name]', 'local draft');
    el.sends = { status: 'loading' };
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-e-name]').value).toBe('local draft');

    q<HTMLButtonElement>(el, '[data-back]').click();
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-e-name]').value).toBe('local draft');
    confirm.mockReturnValue(true);
    q<HTMLButtonElement>(el, '[data-back]').click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-e-name]')).toBeNull();
  });

  it('does not let a late success for an abandoned submission clear a newer draft', async () => {
    vi.mocked(window.confirm).mockReturnValue(true);
    const el = await mount();
    await openCreate(el);
    await setValue(el, '[data-text]', 'first');
    q<HTMLButtonElement>(el, '[data-create]').click();
    q<HTMLButtonElement>(el, '[data-cancel-create]').click();
    await el.updateComplete;
    await openCreate(el);
    await setValue(el, '[data-text]', 'second');

    el.status = { tone: 'success', message: 'Created' };
    await el.updateComplete;
    expect(q<HTMLTextAreaElement>(el, '[data-text]').value).toBe('second');
    expect(el.sendFormHasEdits()).toBe(true);
  });

  it('keeps a failed submission and clears only the matching successful draft', async () => {
    const el = await mount();
    await openCreate(el);
    await setValue(el, '[data-text]', 'retry me');
    q<HTMLButtonElement>(el, '[data-create]').click();
    el.pending = true;
    await el.updateComplete;
    el.status = { tone: 'danger', message: 'Rejected' };
    el.pending = false;
    await el.updateComplete;
    expect(q<HTMLTextAreaElement>(el, '[data-text]').value).toBe('retry me');

    q<HTMLButtonElement>(el, '[data-create]').click();
    el.pending = true;
    await el.updateComplete;
    el.status = { tone: 'success', message: 'Created' };
    el.pending = false;
    await el.updateComplete;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-create]')).toBeNull();
  });
});
