// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } } } }));
import './data-section.js';
import type { VwDataSection } from './data-section.js';
import type { ExportDetail, ImportFileDetail, ImportPasswordDetail } from '../types.js';

async function mount(locked = false): Promise<VwDataSection> {
  const el = document.createElement('vw-data-section') as VwDataSection;
  el.locked = locked;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwDataSection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-data-section locked state', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('disables import, export, and delete while locked', async () => {
    const el = await mount(true);
    expect(q<HTMLButtonElement>(el, '[data-import]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-export]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-delete-local]').disabled).toBe(true);
  });
});

describe('vw-data-section export', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('requires a password for the encrypted export', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', exported);
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).not.toHaveBeenCalled();
  });

  it('emits an encrypted export with the entered password', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (e) => exported((e as CustomEvent<ExportDetail>).detail));
    q<HTMLInputElement>(el, '[data-export-pwd]').value = 's3cret';
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).toHaveBeenCalledWith({ password: 's3cret' });
  });
});

describe('vw-data-section import', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('emits the chosen file for the root to read and classify', async () => {
    const el = await mount(false);
    const imported = vi.fn();
    el.addEventListener('vw-import-file', (e) => imported((e as CustomEvent<ImportFileDetail>).detail));
    const file = new File(['[]'], 'vault.json', { type: 'application/json' });
    const input = q<HTMLInputElement>(el, '[data-import-file]');
    Object.defineProperty(input, 'files', { value: [file], configurable: true });
    input.dispatchEvent(new Event('change', { bubbles: true }));
    expect(imported).toHaveBeenCalledWith({ file });
  });

  it('prompts for and emits the export password when awaiting an encrypted import', async () => {
    const el = await mount(false);
    el.awaitingImportPassword = true;
    await el.updateComplete;
    const done = vi.fn();
    el.addEventListener('vw-import-password', (e) => done((e as CustomEvent<ImportPasswordDetail>).detail));
    q<HTMLInputElement>(el, '[data-import-pwd]').value = 'exportpw';
    q<HTMLButtonElement>(el, '[data-import-go]').click();
    expect(done).toHaveBeenCalledWith({ password: 'exportpw' });
  });
});

describe('vw-data-section delete', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('emits delete-local with no detail', async () => {
    const el = await mount(false);
    const deleted = vi.fn();
    el.addEventListener('vw-delete-local', (e) => deleted((e as CustomEvent).detail));
    q<HTMLButtonElement>(el, '[data-delete-local]').click();
    expect(deleted).toHaveBeenCalledTimes(1);
    expect(deleted).toHaveBeenCalledWith(null);
  });
});
