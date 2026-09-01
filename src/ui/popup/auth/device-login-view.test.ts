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
  VwDeviceLoginView,
  type DeviceLoginApprovalRequestDisplay,
  type DeviceLoginApproverDetailViewModel,
  type DeviceLoginApproverListViewModel,
  type DeviceLoginLabels,
  type DeviceLoginRequestActionDetail,
  type DeviceLoginRequesterViewModel,
  type DeviceLoginViewModel,
} from './device-login-view.js';

const FINGERPRINT = Object.freeze([
  'amber',
  'cedar',
  'harbor',
  'lunar',
  'velvet',
] as const);

const LABELS: Readonly<DeviceLoginLabels> = Object.freeze({
  requesterTitle: 'Log in with device',
  waitingTitle: 'Waiting for approval',
  waitingDescription: 'Approve this login from another signed-in device.',
  serverApprovalHint: 'Open the server approval prompt on a trusted device.',
  compareFingerprintHint: 'Verify that all five words match on both devices before approving.',
  expiresIn: 'Expires in',
  expiredTitle: 'Request expired',
  expiredDescription: 'Start a new device login request.',
  expired: 'Expired',
  checkNow: 'Check now',
  approverListTitle: 'Device login requests',
  approverListDescription: 'Review a pending device before making a decision.',
  approverDetailTitle: 'Review device login',
  noRequests: 'No pending requests',
  deviceType: 'Device type',
  deviceIdentifier: 'Device identifier',
  ipAddress: 'IP address',
  createdAt: 'Created',
  approve: 'Approve',
  deny: 'Deny',
  unavailable: 'Unavailable',
  deviceName: 'This device',
  notKnownTitle: 'Device not recognized',
  notKnownDescription: 'Use a password first.',
  deniedTitle: 'Request denied',
  deniedDescription: 'The request was denied.',
  twoFactorUnsupportedTitle: 'Two-step login unsupported',
  twoFactorUnsupportedDescription: 'Use password login instead.',
  retryRequiredTitle: 'Verification needs attention',
  retryRequiredDescription: 'Retry the current request.',
  outcomeUnknownTitle: 'Login result unknown',
  outcomeUnknownDescription: 'Check account state before starting again.',
  errorTitle: 'Device login unavailable',
  errorDescription: 'The request could not be completed safely.',
  retry: 'Retry',
  dismiss: 'Back to login',
  checkAccountState: 'Check account state',
});

function requester(
  overrides: Partial<DeviceLoginRequesterViewModel> = {},
): DeviceLoginRequesterViewModel {
  return Object.freeze({
    kind: 'requester',
    generation: 1,
    status: 'pending',
    fingerprint: FINGERPRINT,
    remainingSeconds: 185,
    busy: false,
    labels: LABELS,
    ...overrides,
  });
}

function approvalRequest(
  overrides: Partial<DeviceLoginApprovalRequestDisplay> = {},
): DeviceLoginApprovalRequestDisplay {
  return Object.freeze({
    requestId: 'approval-private-id',
    status: 'pending',
    deviceType: 'Chrome extension',
    deviceIdentifier: 'Windows workstation',
    ipAddress: '203.0.113.20',
    country: 'Canada',
    createdAt: 'Aug 30, 2026, 10:30',
    fingerprint: FINGERPRINT,
    ...overrides,
  });
}

function approverList(
  overrides: Partial<DeviceLoginApproverListViewModel> = {},
): DeviceLoginApproverListViewModel {
  return Object.freeze({
    kind: 'approver-list',
    requests: Object.freeze([approvalRequest()]),
    busy: false,
    labels: LABELS,
    ...overrides,
  });
}

function approverDetail(
  overrides: Partial<DeviceLoginApproverDetailViewModel> = {},
): DeviceLoginApproverDetailViewModel {
  return Object.freeze({
    kind: 'approver-detail',
    request: approvalRequest(),
    busy: false,
    labels: LABELS,
    ...overrides,
  });
}

async function mount(model: DeviceLoginViewModel): Promise<VwDeviceLoginView> {
  const element = document.createElement('vw-device-login-view') as VwDeviceLoginView;
  element.model = model;
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function button(element: VwDeviceLoginView, action: string): HTMLButtonElement {
  return element.shadowRoot!.querySelector<HTMLButtonElement>(`[data-action="${action}"]`)!;
}

function markup(element: VwDeviceLoginView): string {
  return `${element.outerHTML}\n${element.shadowRoot!.innerHTML}`;
}

function datasetValues(element: VwDeviceLoginView): string[] {
  return [...element.shadowRoot!.querySelectorAll<HTMLElement>('*')]
    .flatMap((node) => Object.values(node.dataset))
    .filter((value): value is string => value !== undefined);
}

beforeEach(() => setLocale('en', false));
afterEach(() => {
  document.body.replaceChildren();
  setLocale('zh-CN', false);
});

describe('vw-device-login-view requester', () => {
  it('renders the safe five-word phrase and omits every secret-bearing field from DOM', async () => {
    const model = Object.freeze({
      ...requester(),
      requestId: 'requester-private-id',
      accessCode: 'ACCESS-CODE-MUST-STAY-PRIVATE',
      publicKey: 'PUBLIC-KEY-MUST-STAY-PRIVATE',
      key: 'WRAPPED-KEY-MUST-STAY-PRIVATE',
    }) as unknown as DeviceLoginRequesterViewModel;
    const element = await mount(model);
    const html = markup(element);

    expect(element.shadowRoot!.querySelectorAll('.fingerprint-word')).toHaveLength(5);
    expect([...element.shadowRoot!.querySelectorAll('.word-value')].map((node) => node.textContent))
      .toEqual(FINGERPRINT);
    expect(element.shadowRoot!.textContent).toContain(LABELS.serverApprovalHint);
    expect(element.shadowRoot!.textContent).toContain(LABELS.compareFingerprintHint);
    expect(element.shadowRoot!.querySelector('[role="timer"]')?.textContent).toBe('3:05');
    for (const secret of [
      'requester-private-id',
      'ACCESS-CODE-MUST-STAY-PRIVATE',
      'PUBLIC-KEY-MUST-STAY-PRIVATE',
      'WRAPPED-KEY-MUST-STAY-PRIVATE',
    ]) {
      expect(html).not.toContain(secret);
      expect(datasetValues(element)).not.toContain(secret);
    }
  });

  it('emits one payload-free check for rapid repeated clicks without mutating the model', async () => {
    const model = requester();
    const element = await mount(model);
    const received = vi.fn();
    element.addEventListener('vw-device-login-check', received);
    const check = button(element, 'check');

    check.click();
    check.click();

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0]![0] as CustomEvent<unknown>;
    expect(event.detail).toBeNull();
    expect(event.bubbles).toBe(true);
    expect(event.composed).toBe(true);
    expect(element.model).toBe(model);
    await element.updateComplete;
    expect(button(element, 'check').disabled).toBe(true);
    expect(button(element, 'cancel').disabled).toBe(true);
  });

  it('emits cancel once with no payload', async () => {
    const element = await mount(requester());
    const received = vi.fn();
    element.addEventListener('vw-device-login-cancel', received);

    button(element, 'cancel').click();
    button(element, 'cancel').click();

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0]![0] as CustomEvent<unknown>;
    expect(event.detail).toBeNull();
  });

  it('fails closed at expiry and disables every action while busy', async () => {
    const expired = await mount(requester({ status: 'expired', remainingSeconds: -7 }));
    const checked = vi.fn();
    expired.addEventListener('vw-device-login-check', checked);
    expect(expired.shadowRoot!.querySelector('[data-action="check"]')).toBeNull();
    expect(button(expired, 'dismiss').disabled).toBe(false);
    expect(expired.shadowRoot!.querySelector('[role="alert"]')?.textContent)
      .toContain(LABELS.expiredTitle);
    expect(expired.shadowRoot!.querySelector('[role="timer"]')?.textContent).toBe('0:00');
    expect(checked).not.toHaveBeenCalled();

    const busy = await mount(requester({ busy: true }));
    expect(busy.shadowRoot!.querySelector('.surface')?.getAttribute('aria-busy')).toBe('true');
    expect(button(busy, 'check').disabled).toBe(true);
    expect(button(busy, 'cancel').disabled).toBe(true);
    expect(busy.shadowRoot!.textContent).toContain('Loading');
  });

  it('updates a host-owned countdown without unlocking an in-flight action', async () => {
    const element = await mount(requester({ remainingSeconds: 61 }));
    const received = vi.fn();
    element.addEventListener('vw-device-login-check', received);
    expect(element.shadowRoot!.querySelector('[role="timer"]')?.textContent).toBe('1:01');

    button(element, 'check').click();
    element.model = requester({ remainingSeconds: 60 });
    await element.updateComplete;
    expect(element.shadowRoot!.querySelector('[role="timer"]')?.textContent).toBe('1:00');
    button(element, 'check').click();
    expect(received).toHaveBeenCalledTimes(1);

    element.model = requester({ remainingSeconds: 59, busy: true });
    await element.updateComplete;
    element.model = requester({ remainingSeconds: 58, busy: false });
    await element.updateComplete;
    button(element, 'check').click();
    expect(received).toHaveBeenCalledTimes(2);
  });

  it('updates the visible timer every second but announces only meaningful thresholds', async () => {
    const element = await mount(requester({ remainingSeconds: 65 }));
    const visualValues: string[] = [];
    const announcementValues: string[] = [];

    for (let remainingSeconds = 65; remainingSeconds >= 55; remainingSeconds--) {
      element.model = requester({ remainingSeconds });
      await element.updateComplete;
      const timer = element.shadowRoot!.querySelector('[role="timer"]')!;
      const announcement = element.shadowRoot!.querySelector('[data-countdown-announcement]')!;
      visualValues.push(timer.textContent ?? '');
      announcementValues.push(announcement.textContent ?? '');
      expect(timer.getAttribute('aria-live')).toBe('off');
      expect(announcement.getAttribute('aria-live')).toBe('polite');
      expect(announcement.getAttribute('aria-atomic')).toBe('true');
    }

    expect(visualValues).toEqual([
      '1:05', '1:04', '1:03', '1:02', '1:01', '1:00',
      '0:59', '0:58', '0:57', '0:56', '0:55',
    ]);
    expect([...new Set(announcementValues)]).toEqual([
      `${LABELS.expiresIn} 1:05`,
      `${LABELS.expiresIn} 1:00`,
    ]);

    for (const remainingSeconds of [31, 30, 29, 11, 10, 9, 1, 0]) {
      element.model = requester({ remainingSeconds });
      await element.updateComplete;
      announcementValues.push(
        element.shadowRoot!.querySelector('[data-countdown-announcement]')?.textContent ?? '',
      );
    }
    expect([...new Set(announcementValues)]).toEqual([
      `${LABELS.expiresIn} 1:05`,
      `${LABELS.expiresIn} 1:00`,
      `${LABELS.expiresIn} 0:30`,
      `${LABELS.expiresIn} 0:10`,
      `${LABELS.expiresIn} 0:00`,
    ]);
  });

  it('rejects an old visible control after a replacement model is assigned', async () => {
    const element = await mount(requester({ generation: 11 }));
    const staleCheck = button(element, 'check');
    const received = vi.fn();
    element.addEventListener('vw-device-login-check', received);

    element.model = requester({ generation: 12 });
    staleCheck.click();
    expect(received).not.toHaveBeenCalled();

    await element.updateComplete;
    button(element, 'check').click();
    expect(received).toHaveBeenCalledTimes(1);
    expect((received.mock.calls[0]![0] as CustomEvent<unknown>).detail).toBeNull();
  });

  it.each([
    ['not_known_device', LABELS.notKnownTitle],
    ['denied', LABELS.deniedTitle],
    ['expired', LABELS.expiredTitle],
    ['two_factor_unsupported', LABELS.twoFactorUnsupportedTitle],
    ['retry_required', LABELS.retryRequiredTitle],
    ['outcome_unknown', LABELS.outcomeUnknownTitle],
    ['error', LABELS.errorTitle],
  ] as const)('renders the honest %s requester state', async (status, title) => {
    const element = await mount(requester({ status }));
    expect(element.shadowRoot!.textContent).toContain(title);
  });

  it('keeps outcome-unknown distinct and exposes only payload-free recovery actions', async () => {
    const element = await mount(Object.freeze({
      kind: 'requester',
      generation: 9,
      status: 'outcome_unknown',
      serverOrigin: 'https://vault.example',
      busy: false,
      labels: LABELS,
    }));
    const checked = vi.fn();
    element.addEventListener('vw-device-login-check-auth-state', checked);

    expect(element.shadowRoot!.textContent).toContain(LABELS.outcomeUnknownDescription);
    expect(element.shadowRoot!.textContent).not.toContain(LABELS.expiredDescription);
    expect(element.shadowRoot!.querySelector('[data-action="retry"]')).toBeNull();
    button(element, 'check-auth').click();

    expect(checked).toHaveBeenCalledTimes(1);
    expect((checked.mock.calls[0]![0] as CustomEvent<unknown>).detail).toBeNull();
  });
});

describe('vw-device-login-view approver list', () => {
  it('renders explicit device metadata as escaped text and keeps capabilities and keys out of DOM', async () => {
    const request = Object.freeze({
      ...approvalRequest({ deviceIdentifier: '<img src=x onerror=alert(1)>' }),
      accessCode: 'APPROVER-ACCESS-CODE',
      publicKey: 'APPROVER-PUBLIC-KEY',
      key: 'APPROVER-WRAPPED-KEY',
    }) as unknown as DeviceLoginApprovalRequestDisplay;
    const element = await mount(approverList({ requests: Object.freeze([request]) }));
    const html = markup(element);

    expect(element.shadowRoot!.textContent).toContain('Chrome extension');
    expect(element.shadowRoot!.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(element.shadowRoot!.textContent).toContain('203.0.113.20');
    expect(element.shadowRoot!.textContent).toContain('Canada');
    expect(element.shadowRoot!.textContent).toContain('Aug 30, 2026, 10:30');
    expect(element.shadowRoot!.querySelector('img')).toBeNull();
    for (const secret of [
      'approval-private-id',
      'APPROVER-ACCESS-CODE',
      'APPROVER-PUBLIC-KEY',
      'APPROVER-WRAPPED-KEY',
    ]) {
      expect(html).not.toContain(secret);
      expect(datasetValues(element)).not.toContain(secret);
    }
  });

  it('selects a pending row once and emits only its request capability', async () => {
    const pending = approvalRequest({ requestId: 'pending-private-id' });
    const expired = approvalRequest({
      requestId: 'expired-private-id',
      status: 'expired',
      deviceIdentifier: 'Old device',
    });
    const element = await mount(approverList({ requests: Object.freeze([pending, expired]) }));
    const received = vi.fn();
    element.addEventListener('vw-device-login-select', received);
    const rows = [...element.shadowRoot!.querySelectorAll<HTMLButtonElement>('.request-row')];

    expect(rows).toHaveLength(2);
    expect(rows[0]!.disabled).toBe(false);
    expect(rows[1]!.disabled).toBe(true);
    rows[0]!.click();
    rows[0]!.click();

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0]![0] as CustomEvent<DeviceLoginRequestActionDetail>;
    expect(event.detail).toEqual({ requestId: 'pending-private-id' });
    expect(Object.keys(event.detail)).toEqual(['requestId']);
    expect(markup(element)).not.toContain('pending-private-id');
    expect(markup(element)).not.toContain('expired-private-id');
  });

  it('renders an empty state and disables every request row while busy', async () => {
    const empty = await mount(approverList({ requests: Object.freeze([]) }));
    expect(empty.shadowRoot!.querySelector('.empty')?.textContent).toBe(LABELS.noRequests);

    const busy = await mount(approverList({ busy: true }));
    expect([...busy.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')]
      .every((candidate) => candidate.disabled)).toBe(true);
  });
});

describe('vw-device-login-view approver detail', () => {
  it('shows the same numbered phrase plus device, IP, country, and creation metadata', async () => {
    const requesterView = await mount(requester());
    const detailView = await mount(approverDetail());
    const phrase = (element: VwDeviceLoginView) => (
      [...element.shadowRoot!.querySelectorAll('.word-value')].map((node) => node.textContent)
    );

    expect(phrase(detailView)).toEqual(phrase(requesterView));
    expect(phrase(detailView)).toEqual(FINGERPRINT);
    expect(detailView.shadowRoot!.textContent).toContain('Chrome extension');
    expect(detailView.shadowRoot!.textContent).toContain('Windows workstation');
    expect(detailView.shadowRoot!.textContent).toContain('203.0.113.20');
    expect(detailView.shadowRoot!.textContent).toContain('Canada');
    expect(detailView.shadowRoot!.textContent).toContain('Aug 30, 2026, 10:30');
    expect(detailView.shadowRoot!.textContent).toContain(LABELS.compareFingerprintHint);
    expect(markup(detailView)).not.toContain('approval-private-id');
  });

  it.each([
    ['approve', 'vw-device-login-approve'],
    ['deny', 'vw-device-login-deny'],
  ] as const)('emits one minimal %s decision under rapid repeated clicks', async (action, type) => {
    const model = approverDetail();
    const element = await mount(model);
    const received = vi.fn();
    element.addEventListener(type, received);

    button(element, action).click();
    button(element, action).click();

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0]![0] as CustomEvent<DeviceLoginRequestActionDetail>;
    expect(event.detail).toEqual({ requestId: 'approval-private-id' });
    expect(Object.keys(event.detail)).toEqual(['requestId']);
    expect(element.model).toBe(model);
  });

  it('emits one payload-free back event', async () => {
    const element = await mount(approverDetail());
    const received = vi.fn();
    element.addEventListener('vw-device-login-back', received);

    button(element, 'back').click();
    button(element, 'back').click();

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0]![0] as CustomEvent<unknown>;
    expect(event.detail).toBeNull();
    expect(event.bubbles).toBe(true);
    expect(event.composed).toBe(true);
  });

  it('never applies an old visible decision button to a replacement request', async () => {
    const element = await mount(approverDetail({
      request: approvalRequest({ requestId: 'approval-A' }),
    }));
    const staleApprove = button(element, 'approve');
    const received = vi.fn();
    element.addEventListener('vw-device-login-approve', received);

    element.model = approverDetail({
      request: approvalRequest({ requestId: 'approval-B' }),
    });
    staleApprove.click();
    expect(received).not.toHaveBeenCalled();

    await element.updateComplete;
    button(element, 'approve').click();
    expect(received).toHaveBeenCalledTimes(1);
    expect((received.mock.calls[0]![0] as CustomEvent<DeviceLoginRequestActionDetail>).detail)
      .toEqual({ requestId: 'approval-B' });
  });

  it('disables decisions for expired or malformed phrases and all actions while busy', async () => {
    const expired = await mount(approverDetail({
      request: approvalRequest({ status: 'expired' }),
    }));
    expect(button(expired, 'approve').disabled).toBe(true);
    expect(button(expired, 'deny').disabled).toBe(true);
    expect(button(expired, 'back').disabled).toBe(false);
    expect(expired.shadowRoot!.querySelector('[role="alert"]')?.textContent)
      .toContain(LABELS.expiredTitle);

    const malformed = approvalRequest({
      fingerprint: Object.freeze(['one', 'two', 'three', 'four']) as unknown as typeof FINGERPRINT,
    });
    const invalid = await mount(approverDetail({ request: malformed }));
    expect(invalid.shadowRoot!.querySelector('.fingerprint-unavailable')?.textContent)
      .toBe(LABELS.unavailable);
    expect(button(invalid, 'approve').disabled).toBe(true);
    expect(button(invalid, 'deny').disabled).toBe(true);

    const busy = await mount(approverDetail({ busy: true }));
    expect([...busy.shadowRoot!.querySelectorAll<HTMLButtonElement>('button')]
      .every((candidate) => candidate.disabled)).toBe(true);
  });
});

describe('vw-device-login-view narrow layout contract', () => {
  it('uses bounded columns, one scroll region, responsive actions, and no nested cards', async () => {
    const styleGroups = VwDeviceLoginView.styles as unknown as readonly { cssText: string }[];
    const cssText = styleGroups.map((group) => group.cssText).join('\n');

    expect(cssText).toContain('min-width: 0');
    expect(cssText).toContain('minmax(0, 1fr)');
    expect(cssText).toContain('overflow-x: hidden');
    expect(cssText).toContain('overflow-y: auto');
    expect(cssText).toMatch(/@media\s*\(max-width:\s*340px\)/);
    expect(cssText).toMatch(/\.fingerprint-panel\s*\{[^}]*border-radius:\s*8px/s);
    expect(cssText).toMatch(/\.request-row\s*\{[^}]*border-radius:\s*8px/s);
    expect(cssText).not.toMatch(/\b\d+(?:\.\d+)?v(?:w|h|min|max)\b/);

    for (const width of [320, 372]) {
      const element = await mount(requester());
      element.style.width = `${width}px`;
      element.style.height = '600px';
      await element.updateComplete;
      const surface = element.shadowRoot!.querySelector<HTMLElement>('.surface')!;
      const content = element.shadowRoot!.querySelector<HTMLElement>('.content')!;
      const footer = element.shadowRoot!.querySelector<HTMLElement>('.footer')!;
      expect(content.parentElement).toBe(surface);
      expect(footer.parentElement).toBe(surface);
      expect(element.shadowRoot!.querySelector('.fingerprint-panel .fingerprint-panel')).toBeNull();
      expect(element.shadowRoot!.querySelector('.request-row .fingerprint-panel')).toBeNull();
    }
  });
});
