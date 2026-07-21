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

beforeEach(() => setLocale('en', false));

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
  const input = q<HTMLInputElement | HTMLTextAreaElement>(el, sel);
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
    await setValue(el, '[data-text]', 'secret text');
    q<HTMLButtonElement>(el, '[data-create]').click();
    expect(created).toHaveBeenCalledTimes(1);
    const detail = created.mock.calls[0]![0] as SendCreateDetail;
    expect(detail.kind).toBe('text');
    expect(detail.input.name).toBe('Note');
    expect((detail as { input: { text?: string } }).input.text).toBe('secret text');
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

  it('rejects a file larger than 100 MB without emitting', async () => {
    const el = await mount();
    await openCreate(el);
    q<HTMLButtonElement>(el, '[data-mode-file]').click();
    await el.updateComplete;
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    const fileInput = q<HTMLInputElement>(el, '[data-file]');
    const file = new File([''], 'big.bin');
    Object.defineProperty(file, 'size', { value: 101 * 1024 * 1024 });
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
    q<HTMLButtonElement>(el, '[data-create]').click();
    await el.updateComplete;
    expect(created).not.toHaveBeenCalled();
    expect((el.validationError ?? '').toLowerCase()).toContain('too large');
  });

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
});
