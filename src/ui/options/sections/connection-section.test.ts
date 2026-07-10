// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './connection-section.js';
import type { VwConnectionSection } from './connection-section.js';
import type { ConnectionSaveDetail } from '../types.js';

async function mount(serverUrl = ''): Promise<VwConnectionSection> {
  const el = document.createElement('vw-connection-section') as VwConnectionSection;
  el.serverUrl = serverUrl;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwConnectionSection, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

describe('vw-connection-section', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('shows the loaded server URL', async () => {
    const el = await mount('http://10.0.1.20:8080/');
    expect(q<HTMLInputElement>(el, '[data-server-url]').value).toBe('http://10.0.1.20:8080/');
  });

  it('emits a normalized server URL on submit', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-connection-save', (e) => saved((e as CustomEvent<ConnectionSaveDetail>).detail));
    q<HTMLInputElement>(el, '[data-server-url]').value = 'http://example.com';
    q<HTMLButtonElement>(el, '[data-save]').click();
    expect(saved).toHaveBeenCalledWith({ serverUrl: 'http://example.com/' });
  });

  it('rejects a malformed URL without emitting', async () => {
    const el = await mount();
    const saved = vi.fn();
    el.addEventListener('vw-connection-save', saved);
    q<HTMLInputElement>(el, '[data-server-url]').value = 'not a url';
    q<HTMLButtonElement>(el, '[data-save]').click();
    await el.updateComplete;
    expect(saved).not.toHaveBeenCalled();
    const status = el.shadowRoot!.querySelector('vw-status-message');
    expect((status as { message?: string } | null)?.message?.toLowerCase()).toContain('valid');
  });

  it('is the only section that renders a host-permission notice', async () => {
    const el = await mount();
    expect(el.shadowRoot!.textContent?.toLowerCase()).toContain('permission');
  });

  it('renders connection controls as workbench rows with a stable primary action', async () => {
    const el = await mount();
    expect(el.shadowRoot!.querySelector('[data-setting-row]')).not.toBeNull();
    expect(el.shadowRoot!.querySelector('[data-primary-action]')?.textContent).toContain('Save connection');
  });
});
