// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './send-section.js';
import type { VwSendSection } from './send-section.js';
import type { SendSummary } from '../../../core/vault/sends.js';
import { setLocale } from '../../i18n/index.js';

beforeEach(() => {
  setLocale('en', false);
  Object.defineProperty(window, 'confirm', { value: vi.fn(() => true), configurable: true, writable: true });
});

function send(over: Partial<SendSummary> = {}): SendSummary {
  return { id: 's1', accessId: 'a', type: 0, name: '交接凭据', hidden: false, url: 'https://s', deletionDate: new Date(Date.now() + 3 * 86400000).toISOString(), accessCount: 2, maxAccessCount: 5, disabled: false, hideEmail: false, passwordProtected: false, ...over };
}

async function mount(over: Partial<VwSendSection> = {}): Promise<VwSendSection> {
  const el = document.createElement('vw-send-section') as VwSendSection;
  el.sends = { status: 'ready', data: [send()] };
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe('vw-send-section', () => {
  it('renders the intro card and the active Send list', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('.intro')).not.toBeNull();
    expect(el.shadowRoot!.querySelectorAll('.send')).toHaveLength(1);
  });

  it('opens the create form and emits vw-send-create', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    const fired = vi.fn();
    el.addEventListener('vw-send-create', fired);
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'secret text';
    (el.shadowRoot!.querySelector('[data-hide-email]') as HTMLElement & { checked: boolean }).checked = true;
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(fired).toHaveBeenCalled();
    const detail = fired.mock.calls[0]![0].detail;
    expect(detail.kind).toBe('text');
    expect(detail.input).toMatchObject({ deletionHours: 336, expirationHours: 168 });
    expect(detail.input.hideEmail).toBe(true);
    expect(detail.input).not.toHaveProperty('maxAccessCount');
  });

  it('defaults max access to unlimited and still emits an explicit selected limit', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    const max = el.shadowRoot!.querySelector('[data-max]') as HTMLElement & { value: string };
    expect(max.value).toBe('');
    expect(el.sendFormHasEdits()).toBe(false);

    max.value = '5';
    expect(el.sendFormHasEdits()).toBe(true);
    max.value = '';
    expect(el.sendFormHasEdits()).toBe(false);
    max.value = '10';
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'limited';
    const fired = vi.fn();
    el.addEventListener('vw-send-create', fired);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    expect(fired.mock.calls[0]![0].detail.input.maxAccessCount).toBe(10);
  });

  it('offers the official hour-based presets and emits the one-hour selection', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    const expiry = el.shadowRoot!.querySelector('[data-expiry]') as HTMLElement & {
      options: Array<{ value: string; label: string }>;
      value: string;
    };
    expect(expiry.options.map((option) => option.value)).toEqual([
      '1', '24', '48', '72', '168', '336', '720',
    ]);
    expiry.value = '1';
    const fired = vi.fn();
    el.addEventListener('vw-send-create', fired);
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'short lived';
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    const detail = fired.mock.calls[0]![0].detail;
    expect(detail.input).toMatchObject({ deletionHours: 336, expirationHours: 1 });
    expect(detail.input).not.toHaveProperty('deletionDays');
  });

  it('treats the earlier expiration as the effective deadline, inclusive of the boundary', async () => {
    const now = Date.parse('2026-08-31T12:00:00.000Z');
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const el = await mount({
      sends: {
        status: 'ready',
        data: [send({
          deletionDate: new Date(now + 24 * 3_600_000).toISOString(),
          expirationDate: new Date(now).toISOString(),
        })],
      },
    });
    expect(el.shadowRoot!.querySelector('.send')?.classList.contains('dead')).toBe(true);
    expect(el.shadowRoot!.querySelector('.send .sub')?.textContent).toContain('Expired');
  });

  it('shows an hour-scale countdown for a one-hour Send', async () => {
    const now = Date.parse('2026-08-31T12:00:00.000Z');
    vi.spyOn(Date, 'now').mockReturnValue(now);
    const el = await mount({
      sends: {
        status: 'ready',
        data: [send({ deletionDate: new Date(now + 3_600_000).toISOString() })],
      },
    });
    expect(el.shadowRoot!.querySelector('.send .sub')?.textContent).toContain('Expires in 1 hour');
  });

  it('emits vw-copy and vw-send-delete from a list row', async () => {
    const el = await mount();
    const copy = vi.fn();
    const del = vi.fn();
    el.addEventListener('vw-copy', copy);
    el.addEventListener('vw-send-delete', del);
    const buttons = el.shadowRoot!.querySelectorAll<HTMLButtonElement>('.send .icon-btn');
    buttons[0]!.click();
    buttons[1]!.click();
    await el.updateComplete;
    expect(del).not.toHaveBeenCalled();
    (el.shadowRoot!.querySelector('[data-delete-confirm]') as HTMLButtonElement).click();
    expect(copy).toHaveBeenCalledWith(expect.objectContaining({ detail: { value: 'https://s' } }));
    expect(del).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 's1' } }));
  });

  it('keeps access expiration separate from deletion and blocks reversed dates', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    const expiry = el.shadowRoot!.querySelector('[data-expiry]') as HTMLElement & { value: string };
    const deletion = el.shadowRoot!.querySelector('[data-deletion]') as HTMLElement & { value: string };
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'keep until deletion';
    deletion.value = '24';
    expect(el.sendFormHasEdits()).toBe(true);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    expect(created).not.toHaveBeenCalled();
    expect(el.validationError).toBeTruthy();
    expiry.value = '1';
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    expect(created.mock.calls[0]![0].detail.input).toMatchObject({ expirationHours: 1, deletionHours: 24 });
  });

  it('cancels a named deletion without emitting and restores focus', async () => {
    const el = await mount();
    const deleted = vi.fn();
    el.addEventListener('vw-send-delete', deleted);
    const trigger = el.shadowRoot!.querySelector('[data-delete]') as HTMLButtonElement;
    trigger.click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.delete-confirm')?.textContent).toContain('交接凭据');
    (el.shadowRoot!.querySelector('[data-delete-cancel]') as HTMLButtonElement).click();
    await el.updateComplete;
    expect(deleted).not.toHaveBeenCalled();
    expect(el.shadowRoot!.activeElement).toBe(trigger);
  });

  it('places disabled and access-limited Sends in the ended group', async () => {
    const el = await mount({ sends: { status: 'ready', data: [send(), send({ id: 'disabled', disabled: true }), send({ id: 'limited', accessCount: 5 })] } });
    const active = el.shadowRoot!.querySelector('[aria-labelledby="send-active-title"]');
    const ended = el.shadowRoot!.querySelector('[aria-labelledby="send-ended-title"]');
    expect(active?.querySelectorAll('[data-send]')).toHaveLength(1);
    expect(ended?.querySelectorAll('[data-send]')).toHaveLength(2);
    expect(ended?.textContent).toContain('Access limit reached');
  });

  it('keeps the form and entered text after a failed create request', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    const content = el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement;
    content.value = 'keep me';
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    el.pending = true;
    await el.updateComplete;
    el.status = { tone: 'danger', message: 'Server rejected the Send' };
    el.pending = false;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).not.toBeNull();
    expect((el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value).toBe('keep me');
  });

  it('closes the form only after a successful create request', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'share me';
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    el.pending = true;
    await el.updateComplete;
    el.status = { tone: 'success', message: 'Created' };
    el.pending = false;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).toBeNull();
  });

  it('blocks an empty text Send with an inline validation error', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    const fired = vi.fn();
    el.addEventListener('vw-send-create', fired);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    expect(fired).not.toHaveBeenCalled();
    expect(el.validationError).toBeTruthy();
  });

  it('disables existing Send actions while a file upload is pending', async () => {
    const el = await mount();
    el.pending = true;
    await el.updateComplete;
    for (const button of el.shadowRoot!.querySelectorAll<HTMLButtonElement>('.send .icon-btn')) {
      expect(button.disabled).toBe(true);
    }
  });

  it('drops the list and an open sensitive form when the vault locks', async () => {
    const el = await mount();
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'do not retain';
    el.locked = true;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).toBeNull();
    expect(el.shadowRoot!.querySelector('.send')).toBeNull();
    expect((el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('vw-send-section unsaved draft protection', () => {
  async function openForm(el: VwSendSection): Promise<void> {
    (el.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
  }

  function changeKind(el: VwSendSection, id: 'text' | 'file'): void {
    const segmented = el.shadowRoot!.querySelector('vw-segmented')!;
    segmented.dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id },
      bubbles: true,
      composed: true,
    }));
  }

  function changePassword(el: VwSendSection, checked: boolean): void {
    const toggle = el.shadowRoot!.querySelector('vw-toggle')!;
    toggle.dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked },
      bubbles: true,
      composed: true,
    }));
  }

  it('counts every editable Options create field without marking an untouched form dirty', async () => {
    const mutations: Array<(el: VwSendSection) => Promise<void> | void> = [
      (el) => { (el.shadowRoot!.querySelector('[data-name]') as HTMLInputElement).value = 'name'; },
      (el) => { (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'text'; },
      (el) => { (el.shadowRoot!.querySelector('[data-expiry]') as HTMLElement & { value: string }).value = '24'; },
      (el) => { (el.shadowRoot!.querySelector('[data-max]') as HTMLElement & { value: string }).value = '10'; },
      (el) => { (el.shadowRoot!.querySelector('[data-hide-email]') as HTMLElement & { checked: boolean }).checked = true; },
      async (el) => { changePassword(el, true); await el.updateComplete; (el.shadowRoot!.querySelector('[data-pass]') as HTMLInputElement).value = 'password'; },
      async (el) => { changeKind(el, 'file'); await el.updateComplete; },
    ];
    for (const mutate of mutations) {
      const el = await mount();
      await openForm(el);
      expect(el.sendFormHasEdits()).toBe(false);
      await mutate(el);
      expect(el.sendFormHasEdits()).toBe(true);
      el.remove();
    }
  });

  it('keeps a dirty form when Cancel is declined and closes it only after confirmation', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    await openForm(el);
    const content = el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement;
    content.value = 'keep this';
    (el.shadowRoot!.querySelector('.form .btn-outline') as HTMLButtonElement).click();
    await el.updateComplete;
    expect((el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value).toBe('keep this');
    expect(confirm).toHaveBeenCalledWith('Discard your unsaved Send changes?');

    confirm.mockReturnValue(true);
    (el.shadowRoot!.querySelector('.form .btn-outline') as HTMLButtonElement).click();
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).toBeNull();
  });

  it('does not prompt when Cancel closes an untouched form', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    await openForm(el);
    (el.shadowRoot!.querySelector('.form .btn-outline') as HTMLButtonElement).click();
    await el.updateComplete;
    expect(confirm).not.toHaveBeenCalled();
    expect(el.shadowRoot!.querySelector('.form')).toBeNull();
  });

  it('guards text/file and password switches before discarding hidden branch values', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const el = await mount();
    await openForm(el);
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'draft';
    changeKind(el, 'file');
    await el.updateComplete;
    expect((el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value).toBe('draft');

    confirm.mockReturnValue(true);
    changeKind(el, 'file');
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-file]')).not.toBeNull();
    changePassword(el, true);
    await el.updateComplete;
    (el.shadowRoot!.querySelector('[data-pass]') as HTMLInputElement).value = 'secret';
    confirm.mockReturnValue(false);
    changePassword(el, false);
    await el.updateComplete;
    expect((el.shadowRoot!.querySelector('[data-pass]') as HTMLInputElement).value).toBe('secret');
    confirm.mockReturnValue(true);
    changePassword(el, false);
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-pass]')).toBeNull();
  });

  it('never uploads a previously selected file after it becomes invisible', async () => {
    vi.mocked(window.confirm).mockReturnValue(true);
    const el = await mount();
    await openForm(el);
    changeKind(el, 'file');
    await el.updateComplete;
    const fileInput = el.shadowRoot!.querySelector('[data-file]') as HTMLInputElement;
    const oldFile = new File(['old'], 'old.txt');
    Object.defineProperty(fileInput, 'files', { value: [oldFile], configurable: true });
    fileInput.dispatchEvent(new Event('change'));

    changeKind(el, 'text');
    await el.updateComplete;
    changeKind(el, 'file');
    await el.updateComplete;
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    await el.updateComplete;
    expect(created).not.toHaveBeenCalled();
    expect(el.validationError).toBe('Choose a file to share');
  });

  it('emits the selected File without reading or encoding it and preserves it after upload failure', async () => {
    const file = new File(['payload'], 'payload.bin');
    const readWholeFile = vi.fn(() => { throw new Error('The whole file must not be read'); });
    Object.defineProperty(file, 'arrayBuffer', { value: readWholeFile });
    const slice = vi.spyOn(file, 'slice');
    const el = await mount();
    await openForm(el);
    changeKind(el, 'file');
    await el.updateComplete;
    const fileInput = el.shadowRoot!.querySelector('[data-file]') as HTMLInputElement;
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
    fileInput.dispatchEvent(new Event('change'));
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    expect(created).toHaveBeenCalledOnce();
    expect(created.mock.calls[0]![0].detail).toEqual({
      kind: 'file',
      input: { name: 'payload.bin', deletionHours: 336, expirationHours: 168, hideEmail: false },
      file,
      fileName: 'payload.bin',
    });
    expect(readWholeFile).not.toHaveBeenCalled();
    expect(slice).not.toHaveBeenCalled();

    el.pending = true;
    await el.updateComplete;
    expect(el.promptForUnsavedEdits()).toBe(false);
    expect(fileInput.disabled).toBe(true);
    el.pending = false;
    el.status = { tone: 'danger', message: 'Upload failed' };
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).not.toBeNull();
    expect(fileInput.files?.[0]).toBe(file);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    expect(created).toHaveBeenCalledTimes(2);
    expect(created.mock.calls[1]![0].detail.file).toBe(file);
    el.status = { tone: 'success', message: 'Created' };
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).toBeNull();
  });

  it.each([
    { size: 100 * 1024 * 1024, accepted: true },
    { size: 100 * 1024 * 1024 + 1, accepted: false },
  ])('preserves the 100 MiB file limit for $size bytes without reading the file', async ({ size, accepted }) => {
    const file = new File(['payload'], 'payload.bin');
    Object.defineProperty(file, 'size', { value: size });
    const readWholeFile = vi.fn(() => { throw new Error('The whole file must not be read'); });
    Object.defineProperty(file, 'arrayBuffer', { value: readWholeFile });
    const el = await mount();
    await openForm(el);
    changeKind(el, 'file');
    await el.updateComplete;
    const fileInput = el.shadowRoot!.querySelector('[data-file]') as HTMLInputElement;
    Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });
    fileInput.dispatchEvent(new Event('change'));
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();

    expect(created).toHaveBeenCalledTimes(accepted ? 1 : 0);
    expect(readWholeFile).not.toHaveBeenCalled();
    if (!accepted) expect(el.validationError).toContain('100 MB');
  });

  it('clears the selected file when lock invalidates a pending upload draft', async () => {
    const el = await mount();
    await openForm(el);
    changeKind(el, 'file');
    await el.updateComplete;
    const fileInput = el.shadowRoot!.querySelector('[data-file]') as HTMLInputElement;
    Object.defineProperty(fileInput, 'files', { value: [new File(['old'], 'old.txt')], configurable: true });
    fileInput.dispatchEvent(new Event('change'));
    const created = vi.fn();
    el.addEventListener('vw-send-create', created);
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    el.pending = true;
    await el.updateComplete;
    el.locked = true;
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.form')).toBeNull();

    el.pending = false;
    el.locked = false;
    await el.updateComplete;
    await openForm(el);
    changeKind(el, 'file');
    await el.updateComplete;
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    expect(created).toHaveBeenCalledOnce();
    expect(el.validationError).toBe('Choose a file to share');
  });

  it('does not let a late success for an abandoned submission clear a newer draft', async () => {
    vi.mocked(window.confirm).mockReturnValue(true);
    const el = await mount();
    await openForm(el);
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'first';
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    (el.shadowRoot!.querySelector('.form .btn-outline') as HTMLButtonElement).click();
    await el.updateComplete;
    await openForm(el);
    (el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'second';

    el.status = { tone: 'success', message: 'Created' };
    await el.updateComplete;
    expect((el.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value).toBe('second');
    expect(el.sendFormHasEdits()).toBe(true);
  });
});
