// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: { get: async () => ({}), set: async () => {} }, onChanged: { addListener: () => {} } } } }));
import './autofill-section.js';
import { VwAutofillSection } from './autofill-section.js';
import type {
  AutofillSaveDetail,
  HttpAuthSaveDetail,
  ToolbarBadgeSaveDetail,
  WebsitePasskeySaveDetail,
} from '../types.js';
import { setLocale } from '../../i18n/index.js';

async function mount(overrides: Partial<VwAutofillSection> = {}): Promise<VwAutofillSection> {
  const el = document.createElement('vw-autofill-section') as VwAutofillSection;
  el.defaultUriMatchStrategy = 0;
  el.uriMatchDefaultManaged = false;
  el.uriMatchDefaultMalformed = false;
  el.inlineSuggestions = true;
  el.pageLoadFill = false;
  el.autoCopyTotp = true;
  el.showMatchingLoginCount = true;
  el.savePromptEnabled = true;
  el.updatePromptEnabled = true;
  el.savePromptExcludedDomains = [];
  el.blockedDomains = [];
  el.autofillPolicyValid = true;
  el.websitePasskeyEnabled = false;
  el.websitePasskeyExcludedDomains = [];
  el.websitePasskeyPolicyValid = true;
  el.websitePasskeyPending = false;
  el.httpAuthEnabled = false;
  el.httpAuthAllowedOrigins = [];
  el.httpAuthPolicyValid = true;
  el.httpAuthPending = false;
  el.shortcut = 'Ctrl+Shift+F';
  Object.assign(el, overrides);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwAutofillSection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-autofill-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
    setLocale('zh-CN', false);
  });

  it('renders the complete controlled policy', async () => {
    const el = await mount({ inlineSuggestions: false, pageLoadFill: true });
    expect(q(el, '[data-strategy]')).toBeTruthy();
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-inline]').checked).toBe(false);
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-page-load]').checked).toBe(true);
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-save-prompt]').checked).toBe(true);
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-update-prompt]').checked).toBe(true);
    expect(q<HTMLElement>(el, '[data-shortcut]').textContent).toBe('Ctrl+Shift+F');
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-website-passkeys]').checked).toBe(false);
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-http-auth]').checked).toBe(false);
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-auto-copy-totp]').checked).toBe(true);
    expect(q<HTMLElement & { checked: boolean }>(el, '[data-toolbar-count]').checked).toBe(true);
    expect(el.shadowRoot!.querySelectorAll('vw-toggle')).toHaveLength(9);
  });

  it('renders an explicit unassigned state and emits a shortcut-settings intent', async () => {
    const el = await mount({ shortcut: '' });
    expect(q<HTMLElement>(el, '[data-shortcut]').textContent).toBe('未分配');
    const changed = vi.fn();
    el.addEventListener('vw-shortcut-change', changed);
    q<HTMLButtonElement>(el, '[data-shortcut-change]').click();
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it('emits the chosen strategy when the dropdown changes', async () => {
    const el = await mount({ blockedDomains: ['blocked.example'] });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (e) => saved((e as CustomEvent<AutofillSaveDetail>).detail));
    const select = q<HTMLElement>(el, '[data-strategy]');
    select.dispatchEvent(new CustomEvent('vw-select-change', { detail: { value: '1' }, bubbles: true, composed: true }));
    expect(saved).toHaveBeenCalledWith({
      defaultUriMatchStrategy: 1,
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['blocked.example'],
    });
  });

  it('reflects the loaded strategy as the select value', async () => {
    const el = await mount({ defaultUriMatchStrategy: 5 });
    expect(q<HTMLElement & { value: string }>(el, '[data-strategy]').value).toBe('5');
  });

  it('disables an organization-managed strategy while leaving other autofill controls writable', async () => {
    const el = await mount({
      defaultUriMatchStrategy: 3,
      uriMatchDefaultManaged: true,
    });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => {
      saved((event as CustomEvent<AutofillSaveDetail>).detail);
    });

    const select = q<HTMLElement & { disabled: boolean; inert: boolean }>(el, '[data-strategy]');
    expect(select.disabled).toBe(true);
    expect(select.inert).toBe(true);
    expect(q<HTMLElement & { message: string }>(el, '[data-uri-match-managed]').message)
      .toContain('组织管理');

    select.dispatchEvent(new CustomEvent('vw-select-change', {
      detail: { value: '0' }, bubbles: true, composed: true,
    }));
    expect(saved).not.toHaveBeenCalled();

    q(el, '[data-inline]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    expect(saved).toHaveBeenCalledWith(expect.objectContaining({
      defaultUriMatchStrategy: 3,
      inlineSuggestions: false,
    }));
  });

  it('explains a malformed managed strategy and keeps it disabled', async () => {
    const el = await mount({
      defaultUriMatchStrategy: 5,
      uriMatchDefaultManaged: true,
      uriMatchDefaultMalformed: true,
    });
    const status = q<HTMLElement & { message: string; tone: string }>(el, '[data-uri-match-managed]');
    expect(status.tone).toBe('danger');
    expect(status.message).toContain('无效');
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-strategy]').disabled).toBe(true);
  });

  it('keeps the type-11 total switch managed while leaving its item default independent', async () => {
    const el = await mount({
      pageLoadFill: false,
      pageLoadFillDefault: false,
      activateAutofillManaged: true,
    });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => {
      saved((event as CustomEvent<AutofillSaveDetail>).detail);
    });
    const total = q<HTMLElement & { checked: boolean; disabled: boolean; inert: boolean }>(el, '[data-page-load]');
    expect(total.checked).toBe(true);
    expect(total.disabled).toBe(true);
    expect(total.inert).toBe(true);
    expect(q<HTMLElement & { message: string }>(el, '[data-page-load-managed]').message)
      .toContain('组织');

    total.dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    expect(saved).not.toHaveBeenCalled();

    q(el, '[data-page-load-default]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: true }, bubbles: true, composed: true,
    }));
    expect(saved).toHaveBeenCalledWith(expect.objectContaining({
      pageLoadFill: false,
      pageLoadFillDefault: true,
    }));
  });

  it('emits a complete snapshot when either behavior toggle changes', async () => {
    const el = await mount({ blockedDomains: ['private.example'] });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => saved((event as CustomEvent<AutofillSaveDetail>).detail));

    q(el, '[data-inline]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    q(el, '[data-page-load]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: true }, bubbles: true, composed: true,
    }));

    expect(saved).toHaveBeenNthCalledWith(1, {
      defaultUriMatchStrategy: 0,
      inlineSuggestions: false,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['private.example'],
    });
    expect(saved).toHaveBeenNthCalledWith(2, {
      defaultUriMatchStrategy: 0,
      inlineSuggestions: true,
      pageLoadFill: true,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['private.example'],
    });
  });

  it('emits independent save and update prompt decisions in complete snapshots', async () => {
    const el = await mount({
      savePromptEnabled: true,
      updatePromptEnabled: false,
      savePromptExcludedDomains: ['never.example'],
    });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => saved((event as CustomEvent<AutofillSaveDetail>).detail));

    q(el, '[data-save-prompt]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    q(el, '[data-update-prompt]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: true }, bubbles: true, composed: true,
    }));

    expect(saved).toHaveBeenNthCalledWith(1, {
      defaultUriMatchStrategy: 0,
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: false,
      updatePromptEnabled: false,
      savePromptExcludedDomains: ['never.example'],
      blockedDomains: [],
    });
    expect(saved).toHaveBeenNthCalledWith(2, {
      defaultUriMatchStrategy: 0,
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: ['never.example'],
      blockedDomains: [],
    });
  });

  it('renders loaded blocked domains and an explicit empty state', async () => {
    const populated = await mount({ blockedDomains: ['example.com', 'accounts.example.org'] });
    expect(q<HTMLTextAreaElement>(populated, '[data-blocked-domains]').value).toBe('example.com\naccounts.example.org');
    expect(populated.shadowRoot!.querySelectorAll('[data-domain-list] li')).toHaveLength(2);
    populated.remove();

    const empty = await mount();
    expect(q<HTMLElement>(empty, '[data-domain-empty]').textContent).toContain('尚未阻止');
  });

  it('normalizes and de-duplicates valid domains before emitting a save', async () => {
    const el = await mount({ pageLoadFill: true });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => saved((event as CustomEvent<AutofillSaveDetail>).detail));
    const textarea = q<HTMLTextAreaElement>(el, '[data-blocked-domains]');
    textarea.value = ' Example.COM \nexample.com.\nHTTPS://Login.Example.ORG:443/';
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;

    expect(el.shadowRoot!.querySelectorAll('[data-domain-list] li')).toHaveLength(2);
    q<HTMLButtonElement>(el, '[data-save-domains]').click();
    expect(saved).toHaveBeenCalledWith({
      defaultUriMatchStrategy: 0,
      inlineSuggestions: true,
      pageLoadFill: true,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['example.com', 'https://login.example.org'],
    });
  });

  it('normalizes save-prompt exclusions without changing the global blocklist', async () => {
    const el = await mount({ blockedDomains: ['autofill-blocked.example'] });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => saved((event as CustomEvent<AutofillSaveDetail>).detail));
    const textarea = q<HTMLTextAreaElement>(el, '[data-save-prompt-domains]');
    textarea.value = ' Never.Example.COM.\nnever.example.com\nHTTPS://Login.Example.ORG:443/';
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;

    expect(el.shadowRoot!.querySelectorAll('[data-save-prompt-domain-list] li')).toHaveLength(2);
    q<HTMLButtonElement>(el, '[data-save-prompt-domains-save]').click();
    expect(saved).toHaveBeenCalledWith({
      defaultUriMatchStrategy: 0,
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: ['never.example.com', 'https://login.example.org'],
      blockedDomains: ['autofill-blocked.example'],
    });
  });

  it('keeps an invalid save-prompt exclusion draft editable and blocks its save', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', saved);
    const textarea = q<HTMLTextAreaElement>(el, '[data-save-prompt-domains]');
    textarea.value = 'example.com\nhttps://wrong.example/path';
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;

    expect(q<HTMLElement>(el, '[data-save-prompt-domain-error]').textContent)
      .toContain('https://wrong.example/path');
    expect(q<HTMLButtonElement>(el, '[data-save-prompt-domains-save]').disabled).toBe(true);
    expect(textarea.value).toContain('https://wrong.example/path');
    expect(saved).not.toHaveBeenCalled();
  });

  it('blocks invalid domain input without discarding the editable draft', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', saved);
    const textarea = q<HTMLTextAreaElement>(el, '[data-blocked-domains]');
    textarea.value = 'example.com\nhttps://wrong.example/path';
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;

    expect(q<HTMLElement>(el, '[data-domain-error]').textContent).toContain('https://wrong.example/path');
    expect(q<HTMLButtonElement>(el, '[data-save-domains]').disabled).toBe(true);
    expect(textarea.value).toContain('https://wrong.example/path');
    expect(saved).not.toHaveBeenCalled();
  });

  it('offers a safe repair snapshot when persisted policy validation failed', async () => {
    const el = await mount({
      defaultUriMatchStrategy: 5,
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['bad.example'],
      autofillPolicyValid: false,
    });
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => saved((event as CustomEvent<AutofillSaveDetail>).detail));

    expect(q<HTMLElement>(el, '[data-policy-warning]').textContent).toContain('安全默认值');
    q<HTMLButtonElement>(el, '[data-restore-policy]').click();
    expect(saved).toHaveBeenCalledWith({
      defaultUriMatchStrategy: 0,
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: [],
    });
  });

  it('defaults TOTP copying on and emits an explicit opt-out', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-autofill-save', (event) => {
      saved((event as CustomEvent<AutofillSaveDetail>).detail);
    });

    const toggle = q<HTMLElement & { checked: boolean }>(el, '[data-auto-copy-totp]');
    expect(toggle.checked).toBe(true);
    toggle.dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    expect(saved).toHaveBeenCalledWith(expect.objectContaining({ autoCopyTotp: false }));
  });

  it('defaults the toolbar match counter on and emits an independent display save', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-toolbar-badge-save', (event) => {
      saved((event as CustomEvent<ToolbarBadgeSaveDetail>).detail);
    });

    const toggle = q<HTMLElement & { checked: boolean }>(el, '[data-toolbar-count]');
    expect(toggle.checked).toBe(true);
    toggle.dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: false }, bubbles: true, composed: true,
    }));
    expect(saved).toHaveBeenCalledWith({ showMatchingLoginCount: false });
  });

  it('emits complete website passkey snapshots for enable and explicit exclusion saves', async () => {
    const el = await mount({
      websitePasskeyEnabled: false,
      websitePasskeyExcludedDomains: ['keep.example'],
    });
    const saved = vi.fn();
    el.addEventListener('vw-website-passkey-save', (event) => {
      saved((event as CustomEvent<WebsitePasskeySaveDetail>).detail);
    });

    q(el, '[data-website-passkeys]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: true }, bubbles: true, composed: true,
    }));
    expect(saved).toHaveBeenNthCalledWith(1, {
      enabled: true,
      excludedDomains: ['keep.example'],
    });

    const textarea = q<HTMLTextAreaElement>(el, '[data-website-passkey-domains]');
    textarea.value = ' Z.example\nz.example.\naccounts.example.com ';
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-save-website-passkey-domains]').click();
    expect(saved).toHaveBeenNthCalledWith(2, {
      enabled: false,
      excludedDomains: ['accounts.example.com', 'z.example'],
    });
  });

  it.each([
    'https://example.com',
    'example.com/path',
    'example.com:443',
    '*.example.com',
  ])('rejects non-host passkey exclusion %s without emitting a save', async (invalid) => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-website-passkey-save', saved);
    const textarea = q<HTMLTextAreaElement>(el, '[data-website-passkey-domains]');
    textarea.value = `valid.example\n${invalid}`;
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;

    expect(q<HTMLElement>(el, '[data-website-passkey-domain-error]').textContent).toContain(invalid);
    expect(q<HTMLButtonElement>(el, '[data-save-website-passkey-domains]').disabled).toBe(true);
    expect(saved).not.toHaveBeenCalled();
  });

  it('fails closed on invalid persisted passkey settings while keeping repair controls available', async () => {
    const el = await mount({
      websitePasskeyEnabled: false,
      websitePasskeyExcludedDomains: [],
      websitePasskeyPolicyValid: false,
    });
    expect(q<HTMLElement>(el, '[data-website-passkey-policy-warning]').textContent)
      .toContain('保持关闭');
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-website-passkeys]').disabled).toBe(false);
    expect(q<HTMLTextAreaElement>(el, '[data-website-passkey-domains]').disabled).toBe(false);
  });

  it('emits complete canonical HTTP auth snapshots from explicit controls', async () => {
    const el = await mount({
      httpAuthEnabled: false,
      httpAuthAllowedOrigins: ['https://keep.example'],
    });
    const saved = vi.fn();
    el.addEventListener('vw-http-auth-save', (event) => {
      saved((event as CustomEvent<HttpAuthSaveDetail>).detail);
    });
    q(el, '[data-http-auth]').dispatchEvent(new CustomEvent('vw-toggle-change', {
      detail: { checked: true }, bubbles: true, composed: true,
    }));
    expect(saved).toHaveBeenNthCalledWith(1, {
      enabled: true,
      allowedOrigins: ['https://keep.example'],
    });

    const textarea = q<HTMLTextAreaElement>(el, '[data-http-auth-origins]');
    textarea.value = ' HTTPS://Z.example:443/\nhttps://z.example\nhttp://127.0.0.2:8080 ';
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-save-http-auth-origins]').click();
    expect(saved).toHaveBeenNthCalledWith(2, {
      enabled: false,
      allowedOrigins: ['http://127.0.0.2:8080', 'https://z.example'],
    });
  });

  it.each([
    'http://remote.example',
    'https://example.com/login',
    'https://user@example.com',
    'https://*.example.com',
  ])('rejects unsafe HTTP auth origin %s without emitting a save', async (invalid) => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-http-auth-save', saved);
    const textarea = q<HTMLTextAreaElement>(el, '[data-http-auth-origins]');
    textarea.value = `https://valid.example\n${invalid}`;
    textarea.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    await el.updateComplete;
    expect(q<HTMLElement>(el, '[data-http-auth-origin-error]').textContent).toContain(invalid);
    expect(q<HTMLButtonElement>(el, '[data-save-http-auth-origins]').disabled).toBe(true);
    expect(saved).not.toHaveBeenCalled();
  });

  it('fails closed on invalid persisted HTTP auth settings and offers a disabled repair', async () => {
    const el = await mount({
      httpAuthEnabled: false,
      httpAuthAllowedOrigins: [],
      httpAuthPolicyValid: false,
    });
    const saved = vi.fn();
    el.addEventListener('vw-http-auth-save', (event) => {
      saved((event as CustomEvent<HttpAuthSaveDetail>).detail);
    });
    expect(q<HTMLElement>(el, '[data-http-auth-policy-warning]').textContent).toContain('保持关闭');
    q<HTMLButtonElement>(el, '[data-restore-http-auth-policy]').click();
    expect(saved).toHaveBeenCalledWith({ enabled: false, allowedOrigins: [] });
  });

  it('uses a dedicated pending state and keeps the 320px layout shrinkable', async () => {
    const el = await mount({ websitePasskeyPending: true });
    el.style.width = '320px';
    await el.updateComplete;
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-website-passkeys]').disabled).toBe(true);
    expect(q<HTMLTextAreaElement>(el, '[data-website-passkey-domains]').disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-inline]').disabled).toBe(false);
    const styles = (VwAutofillSection.styles as unknown[]).join(' ');
    expect(styles).toContain('min-width: 0');
    expect(styles).toContain('max-width: 100%');
  });

  it('disables only HTTP auth controls while its save is pending', async () => {
    const el = await mount({ httpAuthPending: true });
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-http-auth]').disabled).toBe(true);
    expect(q<HTMLTextAreaElement>(el, '[data-http-auth-origins]').disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-inline]').disabled).toBe(false);
  });

  it('disables mutable policy controls while a save is pending', async () => {
    const el = await mount({ pending: true });
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-inline]').disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-page-load]').disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-toolbar-count]').disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-save-prompt]').disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, '[data-update-prompt]').disabled).toBe(true);
    expect(q<HTMLTextAreaElement>(el, '[data-save-prompt-domains]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-save-prompt-domains-save]').disabled).toBe(true);
    expect(q<HTMLTextAreaElement>(el, '[data-blocked-domains]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-save-domains]').disabled).toBe(true);
  });

  it('provides complete English policy states', async () => {
    setLocale('en', false);
    const el = await mount({ autofillPolicyValid: false });
    const headings = Array.from(el.shadowRoot!.querySelectorAll<HTMLElement & { heading: string }>('vw-setting-card'))
      .map((card) => card.heading);
    expect(headings).toContain('Inline suggestions');
    expect(headings).toContain('Show matching login count');
    expect(headings).toContain('Fill on page load');
    expect(headings).toContain('Offer to save new logins');
    expect(headings).toContain('Offer to update saved logins');
    expect(headings).toContain('Never ask to save on these websites');
    expect(headings).toContain('Use vault passkeys on websites');
    expect(headings).toContain('HTTP Basic authentication');
    expect(el.shadowRoot!.textContent).toContain('No websites are blocked');
    const passkeyCard = Array.from(el.shadowRoot!.querySelectorAll<HTMLElement & {
      heading: string;
      description: string;
    }>('vw-setting-card')).find((card) => card.heading === 'Use vault passkeys on websites');
    expect(passkeyCard?.description).toContain('Requests requiring user verification');
    expect(el.shadowRoot!.textContent).toContain('Restore safe defaults');
    const strategy = q<HTMLElement & { options: Array<{ label: string }> }>(el, '[data-strategy]');
    expect(strategy.options.map((option) => option.label)).toContain('Base domain');
  });
});
