// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      onChanged: { addListener: () => {} },
    },
  },
}));

import { setLocale } from '../../i18n/index.js';
import '../../components/status-message.js';
import {
  type VwWebsitePasskeyView,
  type WebsitePasskeyApproveDetail,
  type WebsitePasskeyCancelDetail,
  type WebsitePasskeyFallbackDetail,
  type WebsitePasskeyViewModel,
} from './website-passkey-view.js';
import type { VwStatusMessage } from '../../components/status-message.js';

function getModel(overrides: Partial<Extract<WebsitePasskeyViewModel, { kind: 'get' }>> = {}): Extract<WebsitePasskeyViewModel, { kind: 'get' }> {
  return {
    kind: 'get',
    ceremonyId: 'ceremony-secret-id',
    origin: 'https://login.example.com',
    rpId: 'example.com',
    state: 'awaiting',
    candidates: [{ id: 'credential-secret-id', name: 'Work account', username: 'alice@example.com' }],
    ...overrides,
  };
}

function createModel(overrides: Partial<Extract<WebsitePasskeyViewModel, { kind: 'create' }>> = {}): Extract<WebsitePasskeyViewModel, { kind: 'create' }> {
  return {
    kind: 'create',
    ceremonyId: 'create-ceremony-secret-id',
    origin: 'https://signup.example.com',
    rpId: 'example.com',
    state: 'awaiting',
    targets: [{ id: 'cipher-secret-id', name: 'Existing login', username: 'alice@example.com' }],
    ...overrides,
  };
}

async function mount(model: WebsitePasskeyViewModel): Promise<VwWebsitePasskeyView> {
  const element = document.createElement('vw-website-passkey-view') as VwWebsitePasskeyView;
  element.model = model;
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function choices(element: VwWebsitePasskeyView): HTMLButtonElement[] {
  return [...element.shadowRoot!.querySelectorAll<HTMLButtonElement>('button.choice')];
}

afterEach(() => {
  document.body.replaceChildren();
  setLocale('zh-CN', false);
});

describe('vw-website-passkey-view get ceremony', () => {
  it('shows source and account display data but requires an explicit click even for one candidate', async () => {
    const element = await mount(getModel());
    const approved = vi.fn();
    element.addEventListener('vw-website-passkey-approve', (event) => {
      approved((event as CustomEvent<WebsitePasskeyApproveDetail>).detail);
    });

    expect(element.shadowRoot!.textContent).toContain('https://login.example.com');
    expect(element.shadowRoot!.textContent).toContain('example.com');
    expect(element.shadowRoot!.textContent).toContain('Work account');
    expect(element.shadowRoot!.textContent).toContain('alice@example.com');
    expect(approved).not.toHaveBeenCalled();

    choices(element)[0]!.click();
    expect(approved).toHaveBeenCalledWith({
      ceremonyId: 'ceremony-secret-id',
      selection: { kind: 'credential', credentialId: 'credential-secret-id' },
    });
    expect(element.model?.state).toBe('executing');
  });

  it('claims approval synchronously so a rapid double click emits only once', async () => {
    const element = await mount(getModel());
    const approved = vi.fn();
    element.addEventListener('vw-website-passkey-approve', approved);
    const first = choices(element)[0]!;
    first.click();
    first.click();
    expect(approved).toHaveBeenCalledTimes(1);
    expect(element.model?.state).toBe('executing');
  });

  it('maps a multi-candidate click through its closure index instead of rendering an identifier', async () => {
    const element = await mount(getModel({
      candidates: [
        { id: 'credential-A-secret', name: 'Personal', username: 'alice' },
        { id: 'credential-B-secret', name: 'Work', username: 'alice@work.example' },
      ],
    }));
    const approved = vi.fn();
    element.addEventListener('vw-website-passkey-approve', (event) => {
      approved((event as CustomEvent<WebsitePasskeyApproveDetail>).detail);
    });

    choices(element)[1]!.click();
    expect(approved).toHaveBeenCalledWith({
      ceremonyId: 'ceremony-secret-id',
      selection: { kind: 'credential', credentialId: 'credential-B-secret' },
    });
    expect(element.shadowRoot!.innerHTML).not.toContain('credential-A-secret');
    expect(element.shadowRoot!.innerHTML).not.toContain('credential-B-secret');
  });

  it('shows a non-actionable empty state when no credential candidate exists', async () => {
    const element = await mount(getModel({ candidates: [] }));
    const approved = vi.fn();
    element.addEventListener('vw-website-passkey-approve', approved);

    expect(choices(element)).toHaveLength(0);
    expect(element.shadowRoot!.textContent).toContain('没有可用于此请求的通行密钥');
    expect(approved).not.toHaveBeenCalled();
  });
});

describe('vw-website-passkey-view create ceremony', () => {
  it('emits an explicit create-new selection without touching vault or messaging code', async () => {
    const element = await mount(createModel());
    const approved = vi.fn();
    element.addEventListener('vw-website-passkey-approve', (event) => {
      approved((event as CustomEvent<WebsitePasskeyApproveDetail>).detail);
    });

    choices(element)[0]!.click();
    expect(approved).toHaveBeenCalledWith({
      ceremonyId: 'create-ceremony-secret-id',
      selection: { kind: 'new' },
    });
  });

  it('maps an existing target row back to its in-memory cipher id', async () => {
    const element = await mount(createModel({
      targets: [
        { id: 'cipher-A-secret', name: 'Personal login' },
        { id: 'cipher-B-secret', name: 'Work login', username: 'alice@work.example' },
      ],
    }));
    const approved = vi.fn();
    element.addEventListener('vw-website-passkey-approve', (event) => {
      approved((event as CustomEvent<WebsitePasskeyApproveDetail>).detail);
    });

    choices(element)[2]!.click();
    expect(approved).toHaveBeenCalledWith({
      ceremonyId: 'create-ceremony-secret-id',
      selection: { kind: 'target', cipherId: 'cipher-B-secret' },
    });
    expect(element.shadowRoot!.innerHTML).not.toContain('cipher-A-secret');
    expect(element.shadowRoot!.innerHTML).not.toContain('cipher-B-secret');
  });
});

describe('vw-website-passkey-view state and privacy', () => {
  it('never renders ceremony, credential, cipher, or unknown secret fields into DOM', async () => {
    const element = await mount({
      ...createModel(),
      targets: [{
        id: 'cipher-private-id',
        name: 'Visible name',
        username: 'visible-user',
        password: 'do-not-render-password',
        keyValue: 'do-not-render-private-key',
      } as unknown as Extract<WebsitePasskeyViewModel, { kind: 'create' }>['targets'][number]],
    });
    const markup = `${element.outerHTML}\n${element.shadowRoot!.innerHTML}`;

    expect(markup).not.toContain('create-ceremony-secret-id');
    expect(markup).not.toContain('cipher-private-id');
    expect(markup).not.toContain('do-not-render-password');
    expect(markup).not.toContain('do-not-render-private-key');
    expect(markup).toContain('Visible name');
    expect(markup).toContain('visible-user');
  });

  it('allows explicit execution cancellation without exposing browser fallback actions', async () => {
    const element = await mount(getModel({ state: 'executing' }));
    const approved = vi.fn();
    const cancelled = vi.fn();
    element.addEventListener('vw-website-passkey-approve', approved);
    element.addEventListener('vw-website-passkey-cancel', cancelled);
    const cancel = element.shadowRoot!.querySelector<HTMLButtonElement>('[data-cancel]')!;

    expect(element.shadowRoot!.querySelector('[role="dialog"]')?.getAttribute('aria-busy')).toBe('true');
    expect(element.shadowRoot!.textContent).toContain('请保持此窗口打开');
    expect(cancel.disabled).toBe(false);
    expect(element.shadowRoot!.querySelector('[data-fallback-once]')).toBeNull();
    expect(element.shadowRoot!.querySelector('[data-fallback-always]')).toBeNull();
    cancel.click();
    expect(approved).not.toHaveBeenCalled();
    expect(cancelled).toHaveBeenCalledWith(expect.objectContaining({ detail: { ceremonyId: 'ceremony-secret-id' } }));
  });

  it('emits distinct single-use browser fallback decisions only while awaiting approval', async () => {
    const once = await mount(getModel());
    const onceEvent = vi.fn();
    once.addEventListener('vw-website-passkey-fallback-once', (event) => {
      onceEvent((event as CustomEvent<WebsitePasskeyFallbackDetail>).detail);
    });
    const onceButton = once.shadowRoot!.querySelector<HTMLButtonElement>('[data-fallback-once]')!;
    onceButton.click();
    onceButton.click();
    expect(onceEvent).toHaveBeenCalledTimes(1);
    expect(onceEvent).toHaveBeenCalledWith({ ceremonyId: 'ceremony-secret-id' });

    const always = await mount(createModel());
    const alwaysEvent = vi.fn();
    always.addEventListener('vw-website-passkey-fallback-always', (event) => {
      alwaysEvent((event as CustomEvent<WebsitePasskeyFallbackDetail>).detail);
    });
    always.shadowRoot!.querySelector<HTMLButtonElement>('[data-fallback-always]')!.click();
    expect(alwaysEvent).toHaveBeenCalledWith({ ceremonyId: 'create-ceremony-secret-id' });
  });

  it('maps Escape to safe cancellation in both awaiting and executing states', async () => {
    for (const state of ['awaiting', 'executing'] as const) {
      const element = await mount(getModel({ state }));
      const cancelled = vi.fn();
      element.addEventListener('vw-website-passkey-cancel', cancelled);
      const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true, cancelable: true });
      element.dispatchEvent(event);
      expect(event.defaultPrevented).toBe(true);
      expect(cancelled).toHaveBeenCalledTimes(1);
      expect(element.shadowRoot!.querySelector('[data-fallback-once]') !== null).toBe(state === 'awaiting');
    }
  });

  it('renders an accessible error and keeps an explicit cancel path', async () => {
    const element = await mount(getModel({ state: 'error', errorMessage: 'Request expired' }));
    const cancelled = vi.fn();
    element.addEventListener('vw-website-passkey-cancel', (event) => {
      cancelled((event as CustomEvent<WebsitePasskeyCancelDetail>).detail);
    });
    const status = element.shadowRoot!.querySelector<VwStatusMessage>('vw-status-message')!;
    const cancel = element.shadowRoot!.querySelector<HTMLButtonElement>('[data-cancel]')!;

    expect(status.getAttribute('tone')).toBe('danger');
    expect(status.message).toBe('Request expired');
    expect(cancel.disabled).toBe(false);
    cancel.click();
    expect(cancelled).toHaveBeenCalledWith({ ceremonyId: 'ceremony-secret-id' });
  });

  it('uses dialog semantics, focuses the first explicit action, and switches all copy to English', async () => {
    setLocale('en', false);
    const element = await mount(getModel());
    const dialog = element.shadowRoot!.querySelector<HTMLElement>('[role="dialog"]')!;
    const first = choices(element)[0]!;

    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(dialog.getAttribute('aria-labelledby')).toBe('website-passkey-title');
    expect(dialog.getAttribute('aria-describedby')).toBe('website-passkey-description');
    expect(element.shadowRoot!.activeElement).toBe(first);
    expect(element.shadowRoot!.textContent).toContain('Sign in with a passkey');
    expect(element.shadowRoot!.textContent).toContain('Use browser once');
    expect(element.shadowRoot!.textContent).toContain('Always use browser for this site');
  });
});
