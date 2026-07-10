// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
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

  it('disables import/export and explains how to unlock while locked', async () => {
    const el = await mount(true);
    expect(el.shadowRoot!.textContent?.toLowerCase()).toContain('unlock');
    expect(q<HTMLButtonElement>(el, '[data-export]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-import]').disabled).toBe(true);
  });
});

describe('vw-data-section export', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('requires a password for an encrypted export', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', exported);
    q<HTMLButtonElement>(el, '[data-export]').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-export-encrypted]').click();
    await el.updateComplete;
    expect(exported).not.toHaveBeenCalled();
    expect(el.shadowRoot!.textContent?.toLowerCase()).toContain('password');
  });

  it('emits an encrypted export with the entered password', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (e) => exported((e as CustomEvent<ExportDetail>).detail));
    q<HTMLButtonElement>(el, '[data-export]').click();
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-export-pwd]').value = 's3cret';
    q<HTMLButtonElement>(el, '[data-export-encrypted]').click();
    expect(exported).toHaveBeenCalledWith({ password: 's3cret' });
  });

  it('emits a plaintext export as an explicit second action', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (e) => exported((e as CustomEvent<ExportDetail>).detail));
    // No plaintext control is exposed until the export panel is opened.
    expect(el.shadowRoot!.querySelector('[data-export-plain]')).toBeNull();
    q<HTMLButtonElement>(el, '[data-export]').click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-export-plain]').click();
    expect(exported).toHaveBeenCalledWith({});
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

  it('prompts for the export password when the root flags an encrypted import', async () => {
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
