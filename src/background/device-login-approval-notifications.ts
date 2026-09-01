import { bytesToBase64Url, utf8ToBytes } from '../core/crypto/encoding.js';
import type { AccountLease } from '../core/session/account-gate.js';
import type { KeyValueStore } from '../platform/store.js';

export const DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX = 'device-login-approval:';
export const DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM =
  'device-login-approval-notification-expiry';
export const DEVICE_LOGIN_APPROVAL_POPUP_PATH = '/ui/popup/popup.html';
export const DEVICE_LOGIN_APPROVAL_POPUP_QUERY = 'deviceLoginApprovals';
export const DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY =
  'deviceLoginApprovalNotificationState';

const NOTIFICATION_DIGEST_LENGTH = 43;
const MAX_COPY_LENGTH = 256;
const MAX_STATE_ENTRIES = 4_096;
const DELIVERY_RETRY_DELAY_MS = 5_000;
const NOTIFICATION_STATE_SCHEMA_VERSION = 2 as const;
const POPUP_WIDTH = 420;
const POPUP_HEIGHT = 680;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const UNSAFE_COPY = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

export type DeviceLoginApprovalNotificationLogEvent =
  | 'alarm_failed'
  | 'click_failed'
  | 'notification_failed'
  | 'popup_query_failed'
  | 'refresh_failed';

export interface DeviceLoginApprovalNotificationCopy {
  readonly title: string;
  readonly message: string;
}

export interface DeviceLoginApprovalNotificationContext {
  readonly contextType: 'BACKGROUND' | 'POPUP' | 'SIDE_PANEL' | 'TAB';
  readonly documentUrl?: string;
  readonly windowId: number;
}

export interface DeviceLoginApprovalPopupCandidate {
  readonly notificationId: string;
  readonly expiresAt: number;
}

export interface DeviceLoginApprovalNotificationBrowser {
  readonly notifications: {
    create(notificationId: string, options: {
      readonly type: 'basic';
      readonly iconUrl: string;
      readonly title: string;
      readonly message: string;
      readonly isClickable: true;
    }): PromiseLike<string>;
    clear(notificationId: string): PromiseLike<boolean>;
    getAll(): PromiseLike<Readonly<Record<string, unknown>>>;
  };
  readonly runtime: {
    getContexts(filter: {
      readonly contextTypes: readonly ('POPUP' | 'TAB')[];
      readonly documentUrls: readonly string[];
    }): PromiseLike<readonly DeviceLoginApprovalNotificationContext[]>;
  };
  readonly windows: {
    create(options: {
      readonly url: string;
      readonly type: 'popup';
      readonly focused: true;
      readonly width: number;
      readonly height: number;
    }): PromiseLike<unknown>;
    update(windowId: number, options: { readonly focused: true }): PromiseLike<unknown>;
  };
}

export interface DeviceLoginApprovalNotificationAlarmScheduler {
  create(name: string, options: { readonly when: number }): void | PromiseLike<void>;
  clear(name: string): boolean | PromiseLike<boolean>;
}

export interface DeviceLoginApprovalNotificationDeps {
  readonly listPending: () => PromiseLike<readonly unknown[]>;
  readonly captureAccountLease: () => AccountLease;
  readonly assertAccountLease: (lease: AccountLease) => void;
  readonly browser: DeviceLoginApprovalNotificationBrowser;
  readonly alarms: DeviceLoginApprovalNotificationAlarmScheduler;
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly popupUrl: string;
  readonly iconUrl: string;
  readonly getCopy: () => DeviceLoginApprovalNotificationCopy | PromiseLike<DeviceLoginApprovalNotificationCopy>;
  /** Notifies an open popup to re-read its authoritative pending list. */
  readonly onPopupPending?: (
    candidates: readonly DeviceLoginApprovalPopupCandidate[],
  ) => void | PromiseLike<void>;
  readonly now?: () => number;
  readonly logger?: { warn(event: DeviceLoginApprovalNotificationLogEvent): void };
}

interface PendingCandidate {
  readonly requestId: string;
  readonly expiresAt: number;
}

interface NotificationCandidate extends PendingCandidate {
  readonly notificationId: string;
}

interface RefreshRequest {
  readonly generation: number;
  readonly forcePopupOpen?: boolean;
}

/**
 * Reconciles generic system notifications from an authoritative pending-request read. Notification
 * ids are one-way stable identities; clicks are re-authorized against a fresh request list before
 * the fixed extension popup can open.
 */
export class DeviceLoginApprovalNotificationController {
  readonly #now: () => number;
  readonly #popupUrl: string;
  readonly #approvalPopupUrl: string;
  readonly #iconUrl: string;
  #generation = 0;
  #mutationTail: Promise<void> = Promise.resolve();
  #refreshInFlight: Promise<void> | undefined;
  #refreshQueued = false;
  #requestedRefresh: RefreshRequest | undefined;

  constructor(private readonly deps: DeviceLoginApprovalNotificationDeps) {
    this.#now = deps.now ?? Date.now;
    const urls = approvalPopupUrls(deps.popupUrl, deps.iconUrl);
    this.#popupUrl = urls.popupUrl;
    this.#approvalPopupUrl = urls.approvalPopupUrl;
    this.#iconUrl = urls.iconUrl;
  }

  refresh(): Promise<void> {
    return this.#refresh();
  }

  clear(): Promise<void> {
    ++this.#generation;
    this.#refreshQueued = false;
    this.#requestedRefresh = undefined;
    return this.#queueMutation(async () => {
      await this.#clearManaged(true);
    }).catch(() => {
      this.#report('notification_failed');
    });
  }

  popupOpened(): Promise<void> {
    return this.#refresh(true);
  }

  handleAlarm(alarm: string | { readonly name: string }): Promise<void> {
    const name = typeof alarm === 'string' ? alarm : alarm.name;
    if (name !== DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM) return Promise.resolve();
    return this.#refresh();
  }

  async handleClick(notificationId: unknown): Promise<void> {
    if (!isManagedNotificationId(notificationId)) return;
    const generation = ++this.#generation;
    try {
      await this.#queueMutation(async () => {
        this.#assertGeneration(generation);
        const lease = this.deps.captureAccountLease();
        const candidates = await this.#readCandidates(lease, generation);
        const expected = await this.#withNotificationIds(candidates, lease, generation);
        this.#assertCurrent(generation, lease);
        const seen = await this.#loadSeen();
        this.#assertCurrent(generation, lease);
        const candidate = expected.find((entry) => entry.notificationId === notificationId);
        if (!candidate || seen.get(notificationId) !== candidate.expiresAt
            || candidate.expiresAt <= this.#currentTime()) return;

        await this.#openOrFocusApprovalPopup(candidate.expiresAt);
        this.#assertCurrent(generation, lease);
        await this.#clearManaged(false);
        this.#assertCurrent(generation, lease);
      });
    } catch {
      this.#report('click_failed');
    }
  }

  #refresh(forcePopupOpen?: boolean): Promise<void> {
    const generation = ++this.#generation;
    this.#requestedRefresh = Object.freeze({
      generation,
      ...(forcePopupOpen === undefined ? {} : { forcePopupOpen }),
    });
    if (this.#refreshInFlight) {
      this.#refreshQueued = true;
      return this.#refreshInFlight;
    }
    this.#refreshInFlight = (async () => {
      try {
        do {
          this.#refreshQueued = false;
          const request = this.#requestedRefresh;
          this.#requestedRefresh = undefined;
          if (request) await this.#runRefresh(request);
        } while (this.#refreshQueued);
      } finally {
        this.#refreshInFlight = undefined;
      }
    })();
    return this.#refreshInFlight;
  }

  async #runRefresh(request: RefreshRequest): Promise<void> {
    const { generation } = request;
    let earliestExpiry: number | undefined;
    try {
      await this.#queueMutation(async () => {
        this.#assertGeneration(generation);
        const lease = this.deps.captureAccountLease();
        const candidates = await this.#readCandidates(lease, generation);
        earliestExpiry = earliestCandidateExpiry(candidates);
        const notifications = await this.#withNotificationIds(candidates, lease, generation);
        const popupOpen = request.forcePopupOpen ?? await this.#isPopupOpen(lease, generation);
        this.#assertCurrent(generation, lease);
        await this.#reconcile(notifications, popupOpen, lease, generation);
      });
    } catch {
      if (generation !== this.#generation) return;
      this.#report('refresh_failed');
      await this.#queueMutation(async () => {
        this.#assertGeneration(generation);
        // A transient list/context/browser failure is not evidence that a previously delivered
        // request settled. Keep the last confirmed notification and its seen marker visible while
        // scheduling a bounded retry. Account transitions and explicit clear() remain the only
        // operations allowed to revoke delivery without an authoritative empty candidate list.
        await this.#scheduleExpiry(this.#retryDeadline(earliestExpiry));
        this.#assertGeneration(generation);
      }).catch(() => {
          this.#report('notification_failed');
      });
    }
  }

  async #readCandidates(lease: AccountLease, generation: number): Promise<PendingCandidate[]> {
    const raw = await this.deps.listPending();
    this.#assertCurrent(generation, lease);
    if (!Array.isArray(raw)) throw new Error('Pending device login approvals are invalid');
    const now = this.#currentTime();
    return raw.flatMap((entry) => {
      const candidate = projectPendingCandidate(entry);
      return candidate && candidate.expiresAt > now ? [candidate] : [];
    });
  }

  async #withNotificationIds(
    candidates: readonly PendingCandidate[],
    lease: AccountLease,
    generation: number,
  ): Promise<NotificationCandidate[]> {
    const output: NotificationCandidate[] = [];
    const seen = new Set<string>();
    for (const candidate of candidates) {
      const notificationId = await notificationIdFor(lease, candidate.requestId);
      this.#assertCurrent(generation, lease);
      if (seen.has(notificationId)) continue;
      seen.add(notificationId);
      output.push(Object.freeze({ ...candidate, notificationId }));
    }
    return output;
  }

  async #isPopupOpen(lease: AccountLease, generation: number): Promise<boolean> {
    let contexts: readonly DeviceLoginApprovalNotificationContext[];
    try {
      contexts = await this.deps.browser.runtime.getContexts({
        contextTypes: ['POPUP', 'TAB'],
        documentUrls: [this.#popupUrl, this.#approvalPopupUrl],
      });
    } catch {
      this.#report('popup_query_failed');
      throw new Error('Popup state is unavailable');
    }
    this.#assertCurrent(generation, lease);
    return contexts.some((context) => (
      (context.contextType === 'POPUP' || context.contextType === 'TAB')
      && (context.documentUrl === this.#popupUrl || context.documentUrl === this.#approvalPopupUrl)
    ));
  }

  async #reconcile(
    candidates: readonly NotificationCandidate[],
    popupOpen: boolean,
    lease: AccountLease,
    generation: number,
  ): Promise<void> {
    this.#assertCurrent(generation, lease);
    const visible = await this.deps.browser.notifications.getAll();
    this.#assertCurrent(generation, lease);
    const desired = new Map(candidates.map((candidate) => [candidate.notificationId, candidate]));
    const visibleIds = new Set(Object.keys(visible));
    const seen = await this.#loadSeen();
    this.#assertCurrent(generation, lease);
    const now = this.#currentTime();
    let needsRetry = false;
    for (const [notificationId, expiresAt] of seen) {
      const candidate = desired.get(notificationId);
      if (!candidate || expiresAt !== candidate.expiresAt || expiresAt <= now) {
        seen.delete(notificationId);
      }
    }

    if (popupOpen) {
      await this.#deliverToPopup(candidates, lease, generation);
      needsRetry = candidates.some((candidate) => !seen.has(candidate.notificationId));
    } else {
      const unconfirmed = candidates.filter((candidate) => !seen.has(candidate.notificationId));
      if (unconfirmed.length > 0) {
        const copy = validateCopy(await this.deps.getCopy());
        this.#assertCurrent(generation, lease);
        for (const candidate of unconfirmed) {
          try {
            const created = await this.deps.browser.notifications.create(candidate.notificationId, {
              type: 'basic',
              iconUrl: this.#iconUrl,
              title: copy.title,
              message: copy.message,
              isClickable: true,
            });
            this.#assertCurrent(generation, lease);
            if (created !== candidate.notificationId) throw new Error('Notification id changed');
            if (candidate.expiresAt <= this.#currentTime()) {
              await this.#clearNotification(candidate.notificationId);
              this.#assertCurrent(generation, lease);
              continue;
            }
            seen.set(candidate.notificationId, candidate.expiresAt);
          } catch {
            this.#assertCurrent(generation, lease);
            this.#report('notification_failed');
            needsRetry = true;
          }
        }
      }
    }

    const commitTime = this.#currentTime();
    for (const [notificationId, expiresAt] of seen) {
      const candidate = desired.get(notificationId);
      if (!candidate || expiresAt !== candidate.expiresAt || expiresAt <= commitTime) {
        seen.delete(notificationId);
      }
    }
    this.#assertCurrent(generation, lease);
    await this.#saveSeen(seen);
    this.#assertCurrent(generation, lease);

    for (const notificationId of visibleIds) {
      if (!isManagedNotificationId(notificationId)
          || (!popupOpen && desired.has(notificationId))) continue;
      if (!await this.#clearNotification(notificationId)) needsRetry = true;
      this.#assertCurrent(generation, lease);
    }

    const earliestExpiry = earliestCandidateExpiry(candidates);
    await this.#scheduleExpiry(
      needsRetry ? this.#retryDeadline(earliestExpiry) : earliestExpiry,
    );
    this.#assertCurrent(generation, lease);
  }

  async #deliverToPopup(
    candidates: readonly NotificationCandidate[],
    lease: AccountLease,
    generation: number,
  ): Promise<void> {
    const deliver = this.deps.onPopupPending;
    if (!deliver || candidates.length === 0) return;
    try {
      const projected = Object.freeze(candidates.map((candidate) => Object.freeze({
        notificationId: candidate.notificationId,
        expiresAt: candidate.expiresAt,
      })));
      await deliver(projected);
      this.#assertCurrent(generation, lease);
    } catch {
      this.#assertCurrent(generation, lease);
      this.#report('notification_failed');
    }
  }

  async #clearManaged(clearSeen: boolean): Promise<void> {
    let visible: Readonly<Record<string, unknown>> = {};
    try {
      visible = await this.deps.browser.notifications.getAll();
    } catch {
      this.#report('notification_failed');
    }
    for (const notificationId of Object.keys(visible)) {
      if (isManagedNotificationId(notificationId)) await this.#clearNotification(notificationId);
    }
    if (clearSeen) {
      try {
        await this.deps.store.remove(DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY);
      } catch {
        this.#report('notification_failed');
      }
    }
    await this.#scheduleExpiry(undefined);
  }

  async #loadSeen(): Promise<Map<string, number>> {
    const raw = await this.deps.store.get<unknown>(DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY);
    return parseSeenState(raw);
  }

  async #saveSeen(seen: ReadonlyMap<string, number>): Promise<void> {
    if (seen.size === 0) {
      await this.deps.store.remove(DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY);
      return;
    }
    const entries = [...seen]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([notificationId, expiresAt]) => Object.freeze({ notificationId, expiresAt }));
    await this.deps.store.set(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY,
      Object.freeze({
        schemaVersion: NOTIFICATION_STATE_SCHEMA_VERSION,
        entries: Object.freeze(entries),
      }),
    );
  }

  async #clearNotification(notificationId: string): Promise<boolean> {
    try {
      await this.deps.browser.notifications.clear(notificationId);
      return true;
    } catch {
      this.#report('notification_failed');
      return false;
    }
  }

  async #scheduleExpiry(when: number | undefined): Promise<void> {
    try {
      if (when === undefined) {
        await this.deps.alarms.clear(DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM);
      } else {
        await this.deps.alarms.create(DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM, { when });
      }
    } catch {
      this.#report('alarm_failed');
    }
  }

  async #openOrFocusApprovalPopup(expiresAt: number): Promise<void> {
    const assertNotExpired = (): void => {
      if (expiresAt <= this.#currentTime()) throw new Error('Approval notification expired');
    };
    assertNotExpired();
    let contexts: readonly DeviceLoginApprovalNotificationContext[] = [];
    try {
      contexts = await this.deps.browser.runtime.getContexts({
        contextTypes: ['POPUP', 'TAB'],
        documentUrls: [this.#approvalPopupUrl],
      });
    } catch {
      this.#report('popup_query_failed');
    }
    assertNotExpired();
    const existing = contexts.find((context) => (
      context.documentUrl === this.#approvalPopupUrl
      && (context.contextType === 'POPUP' || context.contextType === 'TAB')
      && Number.isInteger(context.windowId)
      && context.windowId >= 0
    ));
    if (existing) {
      try {
        assertNotExpired();
        await this.deps.browser.windows.update(existing.windowId, { focused: true });
        return;
      } catch {
        // A context can disappear between discovery and focus; create the fixed popup instead.
      }
    }
    assertNotExpired();
    await this.deps.browser.windows.create({
      url: this.#approvalPopupUrl,
      type: 'popup',
      focused: true,
      width: POPUP_WIDTH,
      height: POPUP_HEIGHT,
    });
  }

  #assertCurrent(generation: number, lease: AccountLease): void {
    this.#assertGeneration(generation);
    this.deps.assertAccountLease(lease);
  }

  #assertGeneration(generation: number): void {
    if (generation !== this.#generation) throw new Error('Approval notification lifecycle changed');
  }

  #retryDeadline(expiresAt: number | undefined): number {
    const retryAt = this.#currentTime() + DELIVERY_RETRY_DELAY_MS;
    if (!Number.isSafeInteger(retryAt)) throw new Error('Approval notification retry time is invalid');
    return expiresAt === undefined ? retryAt : Math.min(retryAt, expiresAt);
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('Approval notification clock is invalid');
    return now;
  }

  #queueMutation(operation: () => void | PromiseLike<void>): Promise<void> {
    const run = this.#mutationTail.then(operation, operation).then(() => undefined);
    this.#mutationTail = run.catch(() => undefined);
    return run;
  }

  #report(event: DeviceLoginApprovalNotificationLogEvent): void {
    try { this.deps.logger?.warn(event); } catch { /* Diagnostics are best-effort. */ }
  }
}

export function createDeviceLoginApprovalNotificationController(
  deps: DeviceLoginApprovalNotificationDeps,
): DeviceLoginApprovalNotificationController {
  return new DeviceLoginApprovalNotificationController(deps);
}

function projectPendingCandidate(input: unknown): PendingCandidate | undefined {
  const direct = exactDataRecord(input, ['requestId', 'expiresAt']);
  const record = direct ? undefined : plainRecord(input);
  const view = record ? plainRecord(ownData(record, 'view')) : undefined;
  const requestId = direct ? ownData(direct, 'requestId') : view ? ownData(view, 'id') : undefined;
  const expiresAt = direct ? ownData(direct, 'expiresAt') : view ? ownData(view, 'expiresAt') : undefined;
  if (
    typeof requestId !== 'string'
    || requestId.length !== 36
    || !UUID_PATTERN.test(requestId)
    || !Number.isSafeInteger(expiresAt)
    || (expiresAt as number) < 0
  ) return undefined;
  return Object.freeze({ requestId, expiresAt: expiresAt as number });
}

function parseSeenState(input: unknown): Map<string, number> {
  if (input === undefined) return new Map();
  const record = exactDataRecord(input, ['schemaVersion', 'entries']);
  const entries = record ? ownData(record, 'entries') : undefined;
  if (
    ownData(record ?? {}, 'schemaVersion') !== NOTIFICATION_STATE_SCHEMA_VERSION
    || !Array.isArray(entries)
    || entries.length > MAX_STATE_ENTRIES
  ) return new Map();
  const output = new Map<string, number>();
  for (const inputEntry of entries) {
    const entry = exactDataRecord(inputEntry, ['notificationId', 'expiresAt']);
    const notificationId = entry ? ownData(entry, 'notificationId') : undefined;
    const expiresAt = entry ? ownData(entry, 'expiresAt') : undefined;
    if (
      !isManagedNotificationId(notificationId)
      || !Number.isSafeInteger(expiresAt)
      || (expiresAt as number) < 0
      || output.has(notificationId)
    ) return new Map();
    output.set(notificationId, expiresAt as number);
  }
  return output;
}

function earliestCandidateExpiry(
  candidates: readonly Pick<PendingCandidate, 'expiresAt'>[],
): number | undefined {
  return candidates.reduce<number | undefined>(
    (current, candidate) => current === undefined
      ? candidate.expiresAt
      : Math.min(current, candidate.expiresAt),
    undefined,
  );
}

async function notificationIdFor(lease: AccountLease, requestId: string): Promise<string> {
  const payload = utf8ToBytes(JSON.stringify([
    2,
    lease.serverGeneration,
    lease.accountGeneration,
    lease.serverUrl,
    lease.accountIdentity,
    requestId,
  ]));
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', payload as BufferSource));
    try {
      return `${DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX}${bytesToBase64Url(digest)}`;
    } finally {
      digest.fill(0);
    }
  } finally {
    payload.fill(0);
  }
}

function isManagedNotificationId(value: unknown): value is string {
  return typeof value === 'string'
    && value.length === DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX.length + NOTIFICATION_DIGEST_LENGTH
    && value.startsWith(DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX)
    && BASE64URL_PATTERN.test(value.slice(DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX.length));
}

function approvalPopupUrls(popupInput: string, iconInput: string): {
  readonly popupUrl: string;
  readonly approvalPopupUrl: string;
  readonly iconUrl: string;
} {
  const popup = new URL(popupInput);
  if (
    (popup.protocol !== 'chrome-extension:' && popup.protocol !== 'moz-extension:')
    || popup.username
    || popup.password
    || popup.pathname !== DEVICE_LOGIN_APPROVAL_POPUP_PATH
    || popup.search
    || popup.hash
  ) throw new TypeError('The approval popup URL is invalid');
  const icon = new URL(iconInput);
  if (
    icon.protocol !== popup.protocol
    || icon.host !== popup.host
    || icon.username
    || icon.password
    || icon.search
    || icon.hash
  ) {
    throw new TypeError('The approval notification icon URL is invalid');
  }
  const approval = new URL(popup);
  approval.searchParams.set(DEVICE_LOGIN_APPROVAL_POPUP_QUERY, '1');
  return Object.freeze({
    popupUrl: popup.toString(),
    approvalPopupUrl: approval.toString(),
    iconUrl: icon.toString(),
  });
}

function validateCopy(input: DeviceLoginApprovalNotificationCopy): DeviceLoginApprovalNotificationCopy {
  if (!safeCopy(input?.title) || !safeCopy(input?.message)) {
    throw new Error('Approval notification copy is invalid');
  }
  return Object.freeze({ title: input.title, message: input.message });
}

function safeCopy(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_COPY_LENGTH
    && value.trim() === value
    && !UNSAFE_COPY.test(value);
}

function plainRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null
    ? value as Record<string, unknown>
    : undefined;
}

function exactDataRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> | undefined {
  const record = plainRecord(value);
  if (!record) return undefined;
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== expectedKeys.length
    || keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
  ) return undefined;
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) return undefined;
  }
  return record;
}

function ownData(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}
