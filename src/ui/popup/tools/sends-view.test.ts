// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './sends-view.js';
import type { VwSendsView } from './sends-view.js';
import type { SendSummary } from '../types.js';
import type { SendCreateDetail, SendUpdateDetail } from '../types.js';

async function mount(): Promise<VwSendsView> {
  const el = document.createElement('vw-sends-view') as VwSendsView;
  document.body.append(el);
  await el.updateComplete;
  return el;
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

  it('emits a text Send create with the collected input', async () => {
    const el = await mount();
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
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    q<HTMLButtonElement>(el, '[data-create]').click();
    await el.updateComplete;
    expect(created).not.toHaveBeenCalled();
    expect((el.validationError ?? '').toLowerCase()).toContain('enter the text to share');
  });

  it('rejects a file larger than 100 MB without emitting', async () => {
    const el = await mount();
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
    expect(copied).toHaveBeenCalledWith({ value: 'https://vault/#/send/acc/key', label: 'Send link' });
  });

  it('deletes a Send', async () => {
    const el = await mount();
    el.sends = { status: 'ready', data: [send()] };
    await el.updateComplete;
    const deleted = vi.fn();
    el.addEventListener('vw-send-delete', (e) => deleted((e as CustomEvent).detail));
    q<HTMLButtonElement>(el, '[data-delete]').click();
    expect(deleted).toHaveBeenCalledWith({ id: 's1' });
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
