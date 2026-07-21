// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import './send-section.js';
import type { VwSendSection } from './send-section.js';
import type { SendSummary } from '../../../core/vault/sends.js';

function send(over: Partial<SendSummary> = {}): SendSummary {
  return { id: 's1', accessId: 'a', type: 0, name: '交接凭据', hidden: false, url: 'https://s', deletionDate: new Date(Date.now() + 3 * 86400000).toISOString(), accessCount: 2, maxAccessCount: 5, disabled: false, passwordProtected: false, ...over };
}

async function mount(over: Partial<VwSendSection> = {}): Promise<VwSendSection> {
  const el = document.createElement('vw-send-section') as VwSendSection;
  el.sends = { status: 'ready', data: [send()] };
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

afterEach(() => document.body.replaceChildren());

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
    (el.shadowRoot!.querySelector('.form .btn-primary') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(fired).toHaveBeenCalled();
    const detail = fired.mock.calls[0]![0].detail;
    expect(detail.kind).toBe('text');
    expect(detail.input.deletionDays).toBe(7);
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
    expect(copy).toHaveBeenCalledWith(expect.objectContaining({ detail: { value: 'https://s' } }));
    expect(del).toHaveBeenCalledWith(expect.objectContaining({ detail: { id: 's1' } }));
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

  it('disables existing Send actions while a file is encoding', async () => {
    const el = await mount();
    el.encoding = true;
    await el.updateComplete;
    for (const button of el.shadowRoot!.querySelectorAll<HTMLButtonElement>('.send .icon-btn')) {
      expect(button.disabled).toBe(true);
    }
  });
});
