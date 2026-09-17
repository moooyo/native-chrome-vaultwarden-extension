// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } } } }));
import './data-section.js';
import type { VwDataSection } from './data-section.js';
import type { ExportDetail, ImportFileDetail, ImportPasswordDetail } from '../types.js';
import type { SanitizedImportPreviewViewModel } from './import-preview.js';
import type { VaultTransferRecoveryStatus } from '../../../messaging/vault-transfer-port.js';

const clearableRecovery: VaultTransferRecoveryStatus = {
  count: 1,
  unresolvedUnknownCount: 1,
  reconcileRequiredCount: 0,
  omittedCount: 0,
  barriers: [{
    transferId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    reason: 'outcome_unknown',
    reconciled: true,
    clearable: true,
  }],
};

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

  it('clears export and pending-import passwords when the vault locks', async () => {
    const el = await mount(false);
    el.awaitingImportPassword = true;
    await el.updateComplete;
    q<HTMLElement>(el, '[data-export-encryption]').dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'file' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-import-pwd]').value = 'import-secret';
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'master-secret';
    q<HTMLInputElement>(el, '[data-export-file-password]').value = 'export-secret';
    el.locked = true;
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-import-pwd]').value).toBe('');
    expect(q<HTMLInputElement>(el, '[data-export-master-password]').value).toBe('');
    expect(q<HTMLInputElement>(el, '[data-export-file-password]').value).toBe('');
    expect(q<HTMLInputElement>(el, '[data-import-pwd]').disabled).toBe(true);
  });
});

describe('vw-data-section export', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('requires user verification for the default account-bound encrypted export', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', exported);
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).not.toHaveBeenCalled();
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'master-secret';
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).toHaveBeenCalledOnce();
  });

  it('emits account-bound encrypted export without a file password', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (event) => exported((event as CustomEvent<ExportDetail>).detail));
    expect(q<HTMLElement & { value: string }>(el, '[data-export-encryption]').value).toBe('account');
    expect(el.shadowRoot!.querySelector('[data-export-file-password]')).toBeNull();
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'master-secret';
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).toHaveBeenCalledWith({
      format: 'encrypted-json', encryptionType: 'account', masterPassword: 'master-secret',
      target: { kind: 'personal' },
    });
  });

  it('emits an encrypted export with separate verification and file passwords', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (e) => exported((e as CustomEvent<ExportDetail>).detail));
    q<HTMLElement>(el, '[data-export-encryption]').dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'file' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'master-secret';
    q<HTMLInputElement>(el, '[data-export-file-password]').value = 'file-secret';
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).toHaveBeenCalledWith({
      format: 'encrypted-json', encryptionType: 'file',
      masterPassword: 'master-secret', filePassword: 'file-secret',
      target: { kind: 'personal' },
    });
    expect(q<HTMLInputElement>(el, '[data-export-master-password]').value).toBe('');
    expect(q<HTMLInputElement>(el, '[data-export-file-password]').value).toBe('');
  });

  it('warns about plaintext JSON and ZIP while still requiring user verification', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (e) => exported((e as CustomEvent<ExportDetail>).detail));
    const segmented = q<HTMLElement>(el, '[data-export-format]');

    segmented.dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'json' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('[data-export-file-password]')).toBeNull();
    expect(q<HTMLElement & { message: string }>(el, '[data-export-warning]').message)
      .toContain('未加密');
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'json-master';
    q<HTMLButtonElement>(el, '[data-export]').click();

    segmented.dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'zip' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'zip-master';
    q<HTMLButtonElement>(el, '[data-export]').click();

    expect(exported).toHaveBeenNthCalledWith(1, {
      format: 'json', masterPassword: 'json-master',
      target: { kind: 'personal' },
    });
    expect(exported).toHaveBeenNthCalledWith(2, {
      format: 'zip', masterPassword: 'zip-master',
      target: { kind: 'personal' },
    });
  });

  it('discloses CSV omissions and requires explicit acknowledgement without a file password', async () => {
    const el = await mount(false);
    const exported = vi.fn();
    el.addEventListener('vw-export', (event) => {
      exported((event as CustomEvent<ExportDetail>).detail);
    });
    q<HTMLElement>(el, '[data-export-format]').dispatchEvent(new CustomEvent('vw-segmented-change', {
      detail: { id: 'csv' }, bubbles: true, composed: true,
    }));
    await el.updateComplete;

    const warning = q<HTMLElement & { message: string }>(el, '[data-export-warning]').message;
    expect(warning).toContain('银行卡');
    expect(warning).toContain('身份');
    expect(warning).toContain('SSH');
    expect(warning).toContain('通行密钥');
    expect(warning).toContain('附件');
    expect(el.shadowRoot!.querySelector('[data-export-file-password]')).toBeNull();
    expect(q<HTMLButtonElement>(el, '[data-export]').disabled).toBe(true);

    const confirm = q<HTMLInputElement>(el, '[data-export-csv-confirm]');
    confirm.checked = true;
    confirm.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'csv-master';
    q<HTMLButtonElement>(el, '[data-export]').click();

    expect(exported).toHaveBeenCalledWith({
      format: 'csv', masterPassword: 'csv-master', target: { kind: 'personal' },
    });
    expect(exported.mock.calls[0]?.[0]).not.toHaveProperty('filePassword');
  });

  it('binds an organization selection and disables the unsupported ZIP format', async () => {
    const el = await mount(false);
    const organizationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    el.exportOrganizations = [{ id: organizationId, name: 'Managed organization' }];
    await el.updateComplete;
    const target = q<HTMLSelectElement>(el, '[data-export-target]');
    target.value = organizationId;
    target.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;

    const format = q<HTMLElement & { options: Array<{ id: string; disabled?: boolean }> }>(
      el,
      '[data-export-format]',
    );
    expect(format.options.find((option) => option.id === 'zip')?.disabled).toBe(true);

    const exported = vi.fn();
    el.addEventListener('vw-export', (event) => {
      exported((event as CustomEvent<ExportDetail>).detail);
    });
    q<HTMLInputElement>(el, '[data-export-master-password]').value = 'master-secret';
    q<HTMLButtonElement>(el, '[data-export]').click();
    expect(exported).toHaveBeenCalledWith({
      format: 'encrypted-json',
      encryptionType: 'account',
      masterPassword: 'master-secret',
      target: { kind: 'organization', organizationId },
    });
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
    expect(q<HTMLInputElement>(el, '[data-import-pwd]').value).toBe('');
  });

  it('renders an aggregate preview and emits explicit confirm and cancel intents', async () => {
    const el = await mount(false);
    const preview: SanitizedImportPreviewViewModel = {
      format: 'bitwarden-zip',
      scope: 'personal',
      counts: { folders: 1, collections: 2, items: 3, attachments: 4 },
      diagnostics: { errors: [], warnings: [], unsupported: [] },
      organizationTargetRequired: false,
      hasUnknownOutcome: false,
      canCommit: true,
    };
    el.importPreview = preview;
    await el.updateComplete;
    const surface = q<HTMLElement>(el, 'vw-import-preview');
    await (surface as HTMLElement & { updateComplete: Promise<boolean> }).updateComplete;
    const confirmed = vi.fn();
    const cancelled = vi.fn();
    el.addEventListener('vw-import-preview-confirm', confirmed);
    el.addEventListener('vw-import-preview-cancel', cancelled);
    surface.shadowRoot!.querySelector<HTMLButtonElement>('[data-confirm]')!.click();
    surface.shadowRoot!.querySelector<HTMLButtonElement>('[data-cancel]')!.click();
    expect(confirmed).toHaveBeenCalledTimes(1);
    expect(cancelled).toHaveBeenCalledTimes(1);
    expect(q<HTMLButtonElement>(el, '[data-export]').disabled).toBe(true);
    expect(q<HTMLElement>(el, '.export-controls').hasAttribute('inert')).toBe(true);
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

describe('vw-data-section import progress and results', () => {
  afterEach(() => document.body.replaceChildren());

  it('keeps the requested import password usable while export remains unavailable', async () => {
    const el = await mount(false);
    el.awaitingImportPassword = true;
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-import-pwd]').closest('[inert]')).toBeNull();
    expect(q<HTMLButtonElement>(el, '[data-import-go]').disabled).toBe(false);
    expect(q<HTMLButtonElement>(el, '[data-export]').disabled).toBe(true);
  });

  it('derives terminal headings and counts from the current authoritative import result', async () => {
    const el = await mount(false);
    el.importResult = {
      version: 1, type: 'import.result', phase: 'completed',
      transferId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', status: 'partial',
      counts: { committed: 119, rejected: 2, skipped: 5, outcomeUnknown: 1 },
      mustSyncBeforeRetry: true,
    };
    await el.updateComplete;
    expect(q<HTMLElement>(el, '[data-import-result]').getAttribute('heading')).toBe('核对未知导入结果');
    expect(q(el, '[data-result-committed]').textContent).toBe('119');
    el.importResult = { ...el.importResult, status: 'completed',
      counts: { committed: 7, rejected: 0, skipped: 0, outcomeUnknown: 0 }, mustSyncBeforeRetry: false };
    await el.updateComplete;
    expect(q<HTMLElement>(el, '[data-import-result]').getAttribute('heading')).toBe('导入完成');
    expect(q(el, '[data-result-committed]').textContent).toBe('7');
    expect(q(el, '[data-result-unknown]').textContent).toBe('0');
  });

  it('offers sync and preserves uncertain recovery records without retrying writes', async () => {
    const el = await mount(false);
    el.recoveryStatus = clearableRecovery;
    await el.updateComplete;
    const sync = vi.fn();
    const clear = vi.fn();
    el.addEventListener('vw-transfer-recovery-sync', sync);
    el.addEventListener('vw-transfer-recovery-clear', clear);
    q<HTMLButtonElement>(el, '[data-recovery-sync]').click();
    expect(sync).toHaveBeenCalledOnce();
    const confirmation = q<HTMLInputElement>(el, '[data-recovery-confirm]');
    confirmation.checked = true;
    confirmation.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-recovery-keep]').click();
    await el.updateComplete;
    expect(clear).not.toHaveBeenCalled();
    expect(q<HTMLInputElement>(el, '[data-recovery-confirm]').checked).toBe(false);
    expect(q<HTMLButtonElement>(el, '[data-import]').disabled).toBe(true);
  });
});

describe('vw-data-section transfer recovery', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows aggregate lost-result status and blocks import before reconciliation', async () => {
    const el = await mount(false);
    el.recoveryStatus = {
      ...clearableRecovery,
      reconcileRequiredCount: 1,
      barriers: [{ ...clearableRecovery.barriers[0]!, reconciled: false, clearable: false }],
    };
    await el.updateComplete;

    expect(q<HTMLElement>(el, '[data-recovery-counts]').textContent).toContain('恢复记录 1');
    expect(q<HTMLElement>(el, '[data-recovery-counts]').textContent).toContain('结果未知 1');
    expect(q<HTMLButtonElement>(el, '[data-import]').disabled).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-recovery-confirm]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-recovery-clear]').disabled).toBe(true);
  });

  it('keeps import disabled while recovery status is unavailable', async () => {
    const el = await mount(false);
    el.recoveryUnavailable = true;
    await el.updateComplete;

    expect(q<HTMLButtonElement>(el, '[data-import]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-export]').disabled).toBe(false);
  });

  it('requires a checked explicit confirmation before emitting clear', async () => {
    const el = await mount(false);
    el.recoveryStatus = clearableRecovery;
    await el.updateComplete;
    const cleared = vi.fn();
    el.addEventListener('vw-transfer-recovery-clear', cleared);
    const button = q<HTMLButtonElement>(el, '[data-recovery-clear]');

    expect(button.disabled).toBe(true);
    button.click();
    expect(cleared).not.toHaveBeenCalled();

    const confirmation = q<HTMLInputElement>(el, '[data-recovery-confirm]');
    confirmation.checked = true;
    confirmation.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;
    expect(button.disabled).toBe(false);
    button.click();
    expect(cleared).toHaveBeenCalledTimes(1);
  });

  it('cancels only the local confirmation and never requests a clear', async () => {
    const el = await mount(false);
    el.recoveryStatus = clearableRecovery;
    await el.updateComplete;
    const cleared = vi.fn();
    el.addEventListener('vw-transfer-recovery-clear', cleared);
    const confirmation = q<HTMLInputElement>(el, '[data-recovery-confirm]');
    confirmation.checked = true;
    confirmation.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;

    q<HTMLButtonElement>(el, '[data-recovery-cancel]').click();
    await el.updateComplete;

    expect(q<HTMLInputElement>(el, '[data-recovery-confirm]').checked).toBe(false);
    expect(q<HTMLButtonElement>(el, '[data-recovery-clear]').disabled).toBe(true);
    expect(cleared).not.toHaveBeenCalled();
  });

  it('erases confirmation when recovery status or session changes', async () => {
    const el = await mount(false);
    el.recoveryStatus = clearableRecovery;
    await el.updateComplete;
    const confirmation = q<HTMLInputElement>(el, '[data-recovery-confirm]');
    confirmation.checked = true;
    confirmation.dispatchEvent(new Event('change', { bubbles: true }));
    await el.updateComplete;

    el.recoveryStatus = { ...clearableRecovery, unresolvedUnknownCount: 0 };
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-recovery-confirm]').checked).toBe(false);

    const next = q<HTMLInputElement>(el, '[data-recovery-confirm]');
    next.checked = true;
    next.dispatchEvent(new Event('change', { bubbles: true }));
    el.locked = true;
    await el.updateComplete;
    expect(q<HTMLInputElement>(el, '[data-recovery-confirm]').checked).toBe(false);
  });
});
