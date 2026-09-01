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

import { setLocale } from '../../i18n/index.js';
import type { VwStatusMessage } from '../../components/status-message.js';
import './import-preview.js';
import type {
  SanitizedImportPreviewDiagnostic,
  SanitizedImportPreviewViewModel,
  VwImportPreview,
} from './import-preview.js';

function model(overrides: Partial<SanitizedImportPreviewViewModel> = {}): SanitizedImportPreviewViewModel {
  return {
    format: 'bitwarden-json',
    scope: 'personal',
    counts: { folders: 2, collections: 1, items: 7, attachments: 3 },
    diagnostics: { errors: [], warnings: [], unsupported: [] },
    organizationTargetRequired: false,
    hasUnknownOutcome: false,
    canCommit: true,
    ...overrides,
  };
}

async function mount(preview = model()): Promise<VwImportPreview> {
  const element = document.createElement('vw-import-preview') as VwImportPreview;
  element.preview = preview;
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function q<T extends Element>(element: VwImportPreview, selector: string): T {
  return element.shadowRoot!.querySelector<T>(selector)!;
}

function status(element: VwImportPreview, selector: string): VwStatusMessage {
  return q<VwStatusMessage>(element, selector);
}

describe('vw-import-preview', () => {
  beforeEach(() => setLocale('zh-CN', false));

  afterEach(() => {
    document.body.replaceChildren();
    setLocale('zh-CN', false);
  });

  it('renders only the sanitized plan summary and diagnostic locations', async () => {
    const preview = model({
      diagnostics: {
        errors: [{ code: 'missing_folder', message: '找不到引用的文件夹', sourceIndex: 6, path: '$.items[6].folderId' }],
        warnings: [{ code: 'csv_lossy', message: 'CSV 不能表示所有字段' }],
        unsupported: [{ code: 'future_type', message: '此条目类型暂不支持', sourceIndex: 8 }],
      },
    });
    const element = await mount(preview);

    expect(q(element, '[data-format]').textContent).toBe('Bitwarden JSON');
    expect(q(element, '[data-scope]').textContent).toBe('个人密码库');
    expect(q(element, '[data-folder-count]').textContent).toBe('2');
    expect(q(element, '[data-collection-count]').textContent).toBe('1');
    expect(q(element, '[data-item-count]').textContent).toBe('7');
    expect(q(element, '[data-attachment-count]').textContent).toBe('3');
    expect(q(element, '[data-diagnostic-group="errors"]').textContent).toContain('来源索引 6');
    expect(q(element, '[data-diagnostic-group="errors"]').textContent).toContain('路径 $.items[6].folderId');
    expect(element.shadowRoot!.querySelectorAll('[data-diagnostic-group]')).toHaveLength(3);
  });

  it('never traverses or renders extra raw secret fields on the supplied object', async () => {
    const unsafeRuntimeObject = {
      ...model(),
      raw: { login: { password: 'DO-NOT-RENDER' } },
      diagnostics: {
        errors: [{ code: 'safe_code', message: 'Sanitized summary', rawSecret: 'ALSO-SECRET' }],
        warnings: [],
        unsupported: [],
      },
    } as unknown as SanitizedImportPreviewViewModel;
    const element = await mount(unsafeRuntimeObject);
    const markup = element.shadowRoot!.innerHTML;
    expect(markup).not.toContain('DO-NOT-RENDER');
    expect(markup).not.toContain('ALSO-SECRET');
    expect(markup).toContain('Sanitized summary');
  });

  it('limits every diagnostic group and reports how many entries were omitted', async () => {
    const errors: SanitizedImportPreviewDiagnostic[] = Array.from({ length: 7 }, (_, index) => ({
      code: `error_${index}`,
      message: `Visible candidate ${index}`,
      sourceIndex: index,
    }));
    const element = await mount(model({
      canCommit: false,
      diagnostics: { errors, warnings: [], unsupported: [] },
    }));

    const group = q(element, '[data-diagnostic-group="errors"]');
    expect(group.querySelectorAll('[data-diagnostic]')).toHaveLength(4);
    expect(group.textContent).toContain('另有 3 项未显示');
    expect(group.textContent).not.toContain('Visible candidate 4');
    expect(group.textContent).not.toContain('Visible candidate 6');
  });

  it('renders Port diagnostic categories as fixed localized aggregate messages', async () => {
    const element = await mount(model({
      diagnostics: {
        errors: [],
        warnings: [{ code: 'limit_exceeded', message: 'DO-NOT-RENDER', count: 7 }],
        unsupported: [],
      },
    }));
    const group = q(element, '[data-diagnostic-group="warnings"]');
    expect(group.textContent).toContain('警告 (7)');
    expect(group.textContent).toContain('存档超出安全处理限制');
    expect(group.textContent).toContain('×7');
    expect(group.textContent).not.toContain('DO-NOT-RENDER');
  });

  it('enables confirm only when canCommit is true and always leaves cancel available', async () => {
    const blocked = await mount(model({ canCommit: false }));
    const confirmed = vi.fn();
    const cancelled = vi.fn();
    blocked.addEventListener('vw-import-preview-confirm', confirmed);
    blocked.addEventListener('vw-import-preview-cancel', cancelled);

    expect(q<HTMLButtonElement>(blocked, '[data-confirm]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(blocked, '[data-cancel]').disabled).toBe(false);
    q<HTMLButtonElement>(blocked, '[data-confirm]').click();
    q<HTMLButtonElement>(blocked, '[data-cancel]').click();
    expect(confirmed).not.toHaveBeenCalled();
    expect(cancelled).toHaveBeenCalledTimes(1);

    blocked.preview = model({ canCommit: true });
    await blocked.updateComplete;
    expect(q<HTMLButtonElement>(blocked, '[data-confirm]').disabled).toBe(false);
    q<HTMLButtonElement>(blocked, '[data-confirm]').click();
    expect(confirmed).toHaveBeenCalledTimes(1);
  });

  it('states organization-target and unknown-outcome safety requirements explicitly', async () => {
    const element = await mount(model({
      scope: 'organization',
      organizationTargetRequired: true,
      hasUnknownOutcome: true,
      canCommit: false,
    }));

    expect(status(element, '[data-organization-required]').message).toContain('明确选择目标组织');
    expect(status(element, '[data-unknown-outcome]').message).toContain('结果未知');
    expect(status(element, '[data-unknown-outcome]').message).toContain('切勿重新导入整个存档');
    expect(status(element, '[data-retry-policy]').message).toContain('不要重试整个存档');
    expect(q<HTMLButtonElement>(element, '[data-cancel]').disabled).toBe(false);
  });

  it('shows safe zeroes for invalid count values', async () => {
    const element = await mount(model({ counts: { folders: -1, collections: -2, items: Number.NaN, attachments: 2.5 } }));
    expect(q(element, '[data-folder-count]').textContent).toBe('0');
    expect(q(element, '[data-collection-count]').textContent).toBe('0');
    expect(q(element, '[data-item-count]').textContent).toBe('0');
    expect(q(element, '[data-attachment-count]').textContent).toBe('0');
  });

  it('reacts to locale changes with complete English and Chinese preview copy', async () => {
    const element = await mount(model({ format: 'bitwarden-zip', scope: 'organization' }));
    setLocale('en', false);
    await element.updateComplete;
    expect(q(element, 'h2').textContent).toBe('Review import plan');
    expect(q(element, '[data-format]').textContent).toBe('Bitwarden ZIP');
    expect(q(element, '[data-scope]').textContent).toBe('Organization vault');
    expect(status(element, '[data-retry-policy]').message).toContain('Do not retry the whole archive');

    setLocale('zh-CN', false);
    await element.updateComplete;
    expect(q(element, 'h2').textContent).toBe('检查导入计划');
    expect(q(element, '[data-scope]').textContent).toBe('组织密码库');
  });
});
