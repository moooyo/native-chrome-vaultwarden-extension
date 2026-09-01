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
import {
  VwPasswordHintView,
  type PasswordHintEmailDetail,
  type PasswordHintStatus,
} from './password-hint-view.js';

interface MountOptions {
  readonly email?: string;
  readonly pending?: boolean;
  readonly error?: string;
  readonly status?: PasswordHintStatus;
  readonly message?: string;
}

async function mount(options: MountOptions = {}): Promise<VwPasswordHintView> {
  const element = document.createElement('vw-password-hint-view') as VwPasswordHintView;
  if (options.email !== undefined) element.email = options.email;
  if (options.pending !== undefined) element.pending = options.pending;
  if (options.error !== undefined) element.error = options.error;
  if (options.status !== undefined) element.status = options.status;
  if (options.message !== undefined) element.message = options.message;
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function emailInput(element: VwPasswordHintView): HTMLInputElement {
  return element.shadowRoot!.querySelector<HTMLInputElement>('#password-hint-email')!;
}

function form(element: VwPasswordHintView): HTMLFormElement {
  return element.shadowRoot!.querySelector<HTMLFormElement>('form')!;
}

function buttons(element: VwPasswordHintView): {
  readonly submit: HTMLButtonElement;
  readonly back: HTMLButtonElement;
} {
  return {
    submit: element.shadowRoot!.querySelector<HTMLButtonElement>('button[type="submit"]')!,
    back: element.shadowRoot!.querySelector<HTMLButtonElement>('button[type="button"]')!,
  };
}

function changeEmail(element: VwPasswordHintView, value: string): void {
  const input = emailInput(element);
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
}

function submit(element: VwPasswordHintView): boolean {
  return form(element).dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
}

async function statusMessage(element: VwPasswordHintView) {
  const status = element.shadowRoot!.querySelector('vw-status-message');
  expect(status).not.toBeNull();
  await status!.updateComplete;
  return status!;
}

function datasetEntries(element: VwPasswordHintView): string[] {
  return [element, ...element.shadowRoot!.querySelectorAll<HTMLElement>('*')]
    .flatMap((node) => Object.entries(node.dataset).map(([key, value]) => `${key}=${value}`));
}

beforeEach(() => setLocale('en', false));
afterEach(() => {
  document.body.replaceChildren();
  setLocale('zh-CN', false);
});

describe('vw-password-hint-view', () => {
  it('prefills a private email property and exposes an accessible email form', async () => {
    const privateEmail = 'User@Example.COM';
    const element = await mount({ email: privateEmail });
    const input = emailInput(element);
    const label = element.shadowRoot!.querySelector<HTMLLabelElement>('label');
    const surface = element.shadowRoot!.querySelector<HTMLElement>('section');

    expect(input.value).toBe(privateEmail);
    expect(input.type).toBe('email');
    expect(input.autocomplete).toBe('email');
    expect(input.inputMode).toBe('email');
    expect(input.maxLength).toBe(254);
    expect(label?.htmlFor).toBe(input.id);
    expect(surface?.getAttribute('aria-labelledby')).toBe('password-hint-title');
    expect(input.getAttribute('aria-describedby')).toContain('password-hint-description');
    expect(element.hasAttribute('email')).toBe(false);
    expect(input.hasAttribute('value')).toBe(false);
    expect(datasetEntries(element)).toEqual([]);
  });

  it('emits one canonical submit event and locks rapid duplicate submissions', async () => {
    const element = await mount();
    const received = vi.fn();
    element.addEventListener('vw-password-hint-submit', received);
    changeEmail(element, '  USER@Example.COM  ');

    expect(submit(element)).toBe(false);
    submit(element);

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0]![0] as CustomEvent<PasswordHintEmailDetail>;
    expect(event.detail).toEqual({ email: 'user@example.com' });
    expect(event.bubbles).toBe(true);
    expect(event.composed).toBe(true);
    await element.updateComplete;
    expect(emailInput(element).value).toBe('user@example.com');
    expect(buttons(element).submit.disabled).toBe(true);
    expect(buttons(element).back.disabled).toBe(true);
  });

  it('submits with Enter through the same canonical one-shot path', async () => {
    const element = await mount();
    const received = vi.fn();
    element.addEventListener('vw-password-hint-submit', received);
    changeEmail(element, 'Keyboard@Example.COM');
    const keydown = new KeyboardEvent('keydown', {
      key: 'Enter',
      bubbles: true,
      cancelable: true,
      composed: true,
    });

    emailInput(element).dispatchEvent(keydown);
    emailInput(element).dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));

    expect(keydown.defaultPrevented).toBe(true);
    expect(received).toHaveBeenCalledTimes(1);
    expect((received.mock.calls[0]![0] as CustomEvent<PasswordHintEmailDetail>).detail)
      .toEqual({ email: 'keyboard@example.com' });
  });

  it('validates locally without emitting and announces the error', async () => {
    const element = await mount();
    const received = vi.fn();
    element.addEventListener('vw-password-hint-submit', received);
    changeEmail(element, 'not-an-email');

    submit(element);
    await element.updateComplete;
    const status = await statusMessage(element);

    expect(received).not.toHaveBeenCalled();
    expect(emailInput(element).getAttribute('aria-invalid')).toBe('true');
    expect(status.shadowRoot!.querySelector('[role="alert"]')?.textContent)
      .toContain('Enter a valid email address.');
    expect(buttons(element).submit.disabled).toBe(false);
  });

  it('disables every action while pending and exposes a polite busy status', async () => {
    const element = await mount({ email: 'user@example.com', pending: true });
    const submitted = vi.fn();
    const backed = vi.fn();
    element.addEventListener('vw-password-hint-submit', submitted);
    element.addEventListener('vw-password-hint-back', backed);

    submit(element);
    buttons(element).back.click();
    const status = await statusMessage(element);

    expect(submitted).not.toHaveBeenCalled();
    expect(backed).not.toHaveBeenCalled();
    expect(emailInput(element).disabled).toBe(true);
    expect(buttons(element).submit.disabled).toBe(true);
    expect(buttons(element).back.disabled).toBe(true);
    expect(element.shadowRoot!.querySelector('section')?.getAttribute('aria-busy')).toBe('true');
    expect(status.shadowRoot!.querySelector('[role="status"]')?.textContent)
      .toContain('Requesting a master password hint');
  });

  it('emits a canonical back event once without requiring a valid email', async () => {
    const element = await mount();
    const received = vi.fn();
    element.addEventListener('vw-password-hint-back', received);
    changeEmail(element, '  PARTIAL  ');

    buttons(element).back.click();
    buttons(element).back.click();

    expect(received).toHaveBeenCalledTimes(1);
    expect((received.mock.calls[0]![0] as CustomEvent<PasswordHintEmailDetail>).detail)
      .toEqual({ email: 'partial' });
  });

  it('uses one non-enumerating success message and never echoes the email', async () => {
    const element = await mount({ email: 'private@example.com', status: 'sent' });
    const status = await statusMessage(element);
    const text = status.shadowRoot!.textContent ?? '';

    expect(status.shadowRoot!.querySelector('[role="status"]')).not.toBeNull();
    expect(text).toContain('If the account exists and the server supports password hints');
    expect(text).not.toContain('private@example.com');
    expect(element.hasAttribute('status')).toBe(false);
    expect(emailInput(element).disabled).toBe(true);
    expect(buttons(element).submit.disabled).toBe(true);
    expect(buttons(element).back.disabled).toBe(false);
  });

  it.each([
    ['hint', 'Your password hint is: favorite constellation', 'Your password hint is: favorite constellation'],
    ['no_hint', undefined, 'No master password hint is available'],
    ['unavailable', undefined, 'This server is not configured to provide password hints'],
  ] as const)('renders the typed %s outcome without echoing the email', async (
    status,
    message,
    expected,
  ) => {
    const element = await mount({
      email: 'private@example.com', status, ...(message ? { message } : {}),
    });
    const banner = await statusMessage(element);

    expect(banner.shadowRoot?.textContent).toContain(expected);
    expect(banner.shadowRoot?.textContent).not.toContain('private@example.com');
    expect(buttons(element).submit.disabled).toBe(true);
    expect(buttons(element).back.disabled).toBe(false);
  });

  it('renders a long server error as inert wrapping text', async () => {
    const error = `<img src=x onerror=alert(1)>${'X'.repeat(8_192)}`;
    const element = await mount({ error, status: 'sent' });
    const status = await statusMessage(element);

    expect(status.shadowRoot!.querySelector('[role="alert"]')?.textContent.trim()).toBe(error);
    expect(status.shadowRoot!.querySelector('img')).toBeNull();
    expect(element.shadowRoot!.querySelector('.feedback')).not.toBeNull();
    expect(element.shadowRoot!.textContent).not.toContain('If the account exists');
    expect(datasetEntries(element)).toEqual([]);
  });

  it('keeps the Chinese catalog complete with the same generic success semantics', async () => {
    setLocale('zh-CN', false);
    const element = await mount({ status: 'sent' });
    const status = await statusMessage(element);

    expect(element.shadowRoot!.querySelector('h1')?.textContent).toBe('获取主密码提示');
    expect(status.shadowRoot!.textContent).toContain('若账户存在且服务器支持密码提示');
  });
});
