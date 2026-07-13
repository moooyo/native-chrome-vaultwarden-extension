// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './status-message.js';
import type { VwStatusMessage } from './status-message.js';

async function mount(): Promise<VwStatusMessage> {
  const el = document.createElement('vw-status-message') as VwStatusMessage;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-status-message', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });


  it('renders nothing when there is no message', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('[role]')).toBeNull();
  });

  it('renders a polite status region for info/success tones', async () => {
    const el = await mount();
    el.tone = 'success';
    el.message = 'Vault unlocked';
    await el.updateComplete;
    const region = el.shadowRoot?.querySelector('[role]');
    expect(region?.getAttribute('role')).toBe('status');
    expect(region?.getAttribute('aria-live')).toBe('polite');
    expect(region?.textContent).toContain('Vault unlocked');
  });

  it('renders an assertive alert region for the danger tone', async () => {
    const el = await mount();
    el.tone = 'danger';
    el.message = 'Sync failed';
    await el.updateComplete;
    const region = el.shadowRoot?.querySelector('[role]');
    expect(region?.getAttribute('role')).toBe('alert');
    expect(region?.getAttribute('aria-live')).toBe('assertive');
  });

  it('never interpolates the message as HTML', async () => {
    const el = await mount();
    el.message = '<img src=x onerror=alert(1)>';
    await el.updateComplete;
    const region = el.shadowRoot?.querySelector('[role]');
    expect(region?.querySelector('img')).toBeNull();
    expect(region?.textContent).toContain('<img src=x onerror=alert(1)>');
  });
});
