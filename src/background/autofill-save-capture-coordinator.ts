import type { SymmetricKey } from '../core/crypto/keys.js';
import { getBaseDomain } from '../core/vault/domain.js';
import type { KeyValueStore } from '../platform/store.js';
import type { AutofillSaveCaptureSubmission } from '../messaging/protocol.js';
import {
  MAX_AUTOFILL_PENDING_SAVE_TTL_MS,
  type AutofillPendingSaveCredentials,
  type AutofillPendingSaveInput,
  type AutofillUnconfirmedSaveMetadata,
  type AutofillPendingSaveStore,
} from './autofill-pending-save-store.js';

export const AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY = 'autofillSaveCaptureNetworkJournal';
export const AUTOFILL_SAVE_CAPTURE_ALARM = 'autofillSaveCaptureNetwork';
export const AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION = 1 as const;
export const DEFAULT_SAVE_CAPTURE_BEFORE_WINDOW_MS = 2_000;
export const DEFAULT_SAVE_CAPTURE_AFTER_WINDOW_MS = 1_500;
export const DEFAULT_SAVE_CAPTURE_NETWORK_TTL_MS = 30_000;
export const DEFAULT_SAVE_CAPTURE_NETWORK_CAPACITY = 64;
export const MAX_SAVE_CAPTURE_NETWORK_CAPACITY = 128;
export const AUTOFILL_SAVE_CAPTURE_NETWORK_MAX_UTF8_BYTES = 512 * 1_024;

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const REQUEST_TYPES = new Set(['main_frame', 'sub_frame', 'xmlhttprequest']);
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_REQUEST_ID_LENGTH = 4_096;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 16 * 1_024;
const MAX_REDIRECTS = 10;
const CONFIRMED_NOTIFICATION_RETRY_MS = 1_000;
const URL_FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/u;
const DOCUMENT_URL_FINGERPRINT_DOMAIN = 'miyu/autofill-save-capture/document-url/v1';
const REQUEST_URL_FINGERPRINT_DOMAIN = 'miyu/autofill-save-capture/request-url/v1';

export type { AutofillSaveCaptureSubmission } from '../messaging/protocol.js';

export interface AutofillSaveCaptureBeforeRequest {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  /** Browser-owned initiating document URL; never use a navigation target's documentUrl here. */
  readonly sourceDocumentUrl: string;
  readonly initiator: string;
  readonly url: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly timeStamp: number;
}

export interface AutofillSaveCaptureCompletedRequest {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly statusCode: number;
  readonly timeStamp: number;
}

export interface AutofillSaveCaptureRedirectRequest {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly redirectUrl: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly statusCode: number;
  readonly timeStamp: number;
}

export interface AutofillSaveCaptureErrorRequest {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly timeStamp: number;
}

export interface AutofillSaveCaptureAlarmScheduler {
  schedule(when: number): void | Promise<void>;
  cancel(): void | Promise<void>;
}

export interface AutofillSaveCaptureCoordinatorOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set'>;
  readonly captures: Pick<
    AutofillPendingSaveStore,
    | 'putUnconfirmed'
    | 'confirmUnconfirmed'
    | 'discardCapture'
    | 'captureState'
    | 'captureMetadata'
    | 'listUnconfirmed'
  >;
  /** Returns a fresh owned key copy. The capture store consumes and zeroes it. */
  readonly loadUserKey: (metadata: AutofillUnconfirmedSaveMetadata) => Promise<SymmetricKey | undefined>;
  readonly assertCurrent?: (metadata: AutofillUnconfirmedSaveMetadata) => void;
  readonly onConfirmed?: (metadata: AutofillUnconfirmedSaveMetadata) => void | Promise<void>;
  readonly scheduler?: AutofillSaveCaptureAlarmScheduler;
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly beforeWindowMs?: number;
  readonly afterWindowMs?: number;
  readonly networkTtlMs?: number;
  readonly maxRequests?: number;
  readonly maxJournalBytes?: number;
}

interface CaptureBinding {
  readonly captureId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly sourceOrigin: string;
  readonly sourceSite: string;
  readonly sourceUrlFingerprint: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

type StoredSubmission =
  | {
      readonly kind: 'native';
      readonly actionOrigin: string;
      readonly actionSite: string;
      readonly actionUrlFingerprint: string;
      readonly method: 'POST' | 'PUT' | 'PATCH';
    }
  | { readonly kind: 'formless' };

interface CaptureRecord {
  readonly binding: CaptureBinding;
  readonly submission: StoredSubmission;
  phase: 'unconfirmed' | 'confirmed';
  metadata?: AutofillUnconfirmedSaveMetadata;
}

interface RequestRecord {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly documentOrigin: string;
  readonly documentSite: string;
  readonly documentUrlFingerprint: string;
  readonly initialOrigin: string;
  readonly initialSite: string;
  readonly initialUrlFingerprint: string;
  currentOrigin: string;
  currentSite: string;
  currentUrlFingerprint: string;
  readonly method: 'POST' | 'PUT' | 'PATCH';
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly startedAt: number;
  readonly expiresAt: number;
  phase: 'started' | 'redirected' | 'succeeded' | 'failed';
  redirectCount: number;
}

interface TerminalOutcome {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly urlFingerprint: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly completedAt: number;
  readonly expiresAt: number;
  readonly phase: 'succeeded' | 'failed';
}

interface PreparedRedirect {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly urlFingerprint: string;
  readonly redirectOrigin: string;
  readonly redirectSite: string;
  readonly redirectUrlFingerprint: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly timeStamp: number;
  readonly expiresAt: number;
}

interface PreparedTerminal {
  readonly requestId: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly urlFingerprint: string;
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
  readonly timeStamp: number;
  readonly expiresAt: number;
}

interface JournalState {
  revision: number;
  blockedUntil: number;
  captures: CaptureRecord[];
  requests: RequestRecord[];
  outcomes: TerminalOutcome[];
}

interface StoredJournal {
  readonly schemaVersion: typeof AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION;
  readonly revision: number;
  readonly blockedUntil: number;
  readonly captures: readonly CaptureRecord[];
  readonly requests: readonly RequestRecord[];
  readonly outcomes: readonly TerminalOutcome[];
}

interface ParsedJournal extends JournalState {
  dirty: boolean;
}

/**
 * Correlates encrypted content captures with browser-owned request outcomes. The journal contains
 * only bounded request metadata; credentials remain encrypted inside AutofillPendingSaveStore.
 */
export class AutofillSaveCaptureCoordinator {
  readonly #store: AutofillSaveCaptureCoordinatorOptions['store'];
  readonly #captures: AutofillSaveCaptureCoordinatorOptions['captures'];
  readonly #loadUserKey: AutofillSaveCaptureCoordinatorOptions['loadUserKey'];
  readonly #assertCurrent: (metadata: AutofillUnconfirmedSaveMetadata) => void;
  readonly #onConfirmed: (metadata: AutofillUnconfirmedSaveMetadata) => void | Promise<void>;
  readonly #scheduler: AutofillSaveCaptureAlarmScheduler;
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #beforeWindowMs: number;
  readonly #afterWindowMs: number;
  readonly #networkTtlMs: number;
  readonly #maxRequests: number;
  readonly #maxJournalBytes: number;
  #tail = Promise.resolve();
  #highWaterRevision = 0;

  constructor(options: AutofillSaveCaptureCoordinatorOptions) {
    if (!options || typeof options.store?.get !== 'function' || typeof options.store?.set !== 'function'
        || typeof options.captures?.putUnconfirmed !== 'function'
        || typeof options.captures?.confirmUnconfirmed !== 'function'
        || typeof options.captures?.discardCapture !== 'function'
        || typeof options.captures?.captureState !== 'function'
        || typeof options.captures?.captureMetadata !== 'function'
        || typeof options.captures?.listUnconfirmed !== 'function'
        || typeof options.loadUserKey !== 'function') {
      throw new TypeError('Save-capture coordinator dependencies are invalid');
    }
    this.#store = options.store;
    this.#captures = options.captures;
    this.#loadUserKey = options.loadUserKey;
    this.#assertCurrent = options.assertCurrent ?? (() => {});
    this.#onConfirmed = options.onConfirmed ?? (() => {});
    this.#scheduler = options.scheduler ?? { schedule: () => {}, cancel: () => {} };
    this.#storageKey = boundedString(
      options.storageKey ?? AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY,
      256,
      'storageKey',
    );
    this.#now = options.now ?? Date.now;
    this.#beforeWindowMs = boundedPositiveInteger(
      options.beforeWindowMs ?? DEFAULT_SAVE_CAPTURE_BEFORE_WINDOW_MS,
      10_000,
      'beforeWindowMs',
    );
    this.#afterWindowMs = boundedPositiveInteger(
      options.afterWindowMs ?? DEFAULT_SAVE_CAPTURE_AFTER_WINDOW_MS,
      10_000,
      'afterWindowMs',
    );
    this.#networkTtlMs = boundedPositiveInteger(
      options.networkTtlMs ?? DEFAULT_SAVE_CAPTURE_NETWORK_TTL_MS,
      5 * 60_000,
      'networkTtlMs',
    );
    this.#maxRequests = boundedPositiveInteger(
      options.maxRequests ?? DEFAULT_SAVE_CAPTURE_NETWORK_CAPACITY,
      MAX_SAVE_CAPTURE_NETWORK_CAPACITY,
      'maxRequests',
    );
    this.#maxJournalBytes = boundedPositiveInteger(
      options.maxJournalBytes ?? AUTOFILL_SAVE_CAPTURE_NETWORK_MAX_UTF8_BYTES,
      AUTOFILL_SAVE_CAPTURE_NETWORK_MAX_UTF8_BYTES,
      'maxJournalBytes',
      256,
    );
  }

  async stage(
    input: AutofillPendingSaveInput,
    credentials: AutofillPendingSaveCredentials,
    ownedUserKey: SymmetricKey,
    submissionInput: AutofillSaveCaptureSubmission,
  ): Promise<AutofillUnconfirmedSaveMetadata> {
    let submission: AutofillSaveCaptureSubmission;
    try {
      submission = parseSubmission(submissionInput);
    } catch (error) {
      zeroOwnedUserKey(ownedUserKey);
      throw error;
    }
    const metadata = await this.#captures.putUnconfirmed(input, credentials, ownedUserKey);
    try {
      const captureRecord = await createCaptureRecord(metadata, submission);
      await this.#serialize(async () => {
        const state = await this.#read();
        const existingIndex = state.captures.findIndex((capture) => (
          sameCaptureSlot(capture.binding, captureRecord.binding)
        ));
        if (existingIndex >= 0) {
          const [replaced] = state.captures.splice(existingIndex, 1);
          if (replaced) await this.#captures.discardCapture(replaced.binding.captureId);
        }
        state.captures.push(captureRecord);
        await this.#reconcileCaptureStore(state);
        while (state.captures.length > this.#maxRequests) {
          const removed = state.captures.shift();
          if (removed) await this.#captures.discardCapture(removed.binding.captureId);
        }
        await this.#evaluate(state);
        await this.#write(state);
        await this.#notifyConfirmed(state);
        await this.#write(state);
        this.#reschedule(state);
      });
      return metadata;
    } catch (error) {
      await this.#captures.discardCapture(metadata.captureId).catch(() => false);
      throw error;
    }
  }

  async observeBeforeRequest(input: AutofillSaveCaptureBeforeRequest): Promise<void> {
    const request = await parseBeforeRequest(input, this.#networkTtlMs);
    return this.#mutate(async (state) => {
      const existing = state.requests.find((candidate) => candidate.requestId === request.requestId);
      if (existing) {
        if (!sameStartedRequest(existing, request)) await this.#blockAll(state, request.expiresAt);
        return;
      }
      if (state.requests.length >= this.#maxRequests) {
        await this.#blockAll(state, request.expiresAt);
        return;
      }
      const outcomeIndex = state.outcomes.findIndex((candidate) => candidate.requestId === request.requestId);
      const outcome = outcomeIndex >= 0 ? state.outcomes.splice(outcomeIndex, 1)[0] : undefined;
      if (outcome) {
        request.phase = terminalMatchesRequest(outcome, request) ? outcome.phase : 'failed';
      }
      state.requests.push(request);
    });
  }

  async observeRedirect(input: AutofillSaveCaptureRedirectRequest): Promise<void> {
    const redirect = await parseRedirectRequest(input, this.#networkTtlMs);
    return this.#mutate(async (state) => {
      const request = state.requests.find((candidate) => candidate.requestId === redirect.requestId);
      if (!request || !terminalIdentityMatches(redirect, request)
          || redirect.type !== request.type
          || redirect.urlFingerprint !== request.currentUrlFingerprint
          || redirect.timeStamp < request.startedAt
          || request.redirectCount >= MAX_REDIRECTS
          || !sameSiteBinding(
            request.documentOrigin,
            request.documentSite,
            redirect.redirectOrigin,
            redirect.redirectSite,
          )) {
        if (request) request.phase = 'failed';
        else if (MUTATION_METHODS.has(redirect.method)) this.#upsertOutcome(state, {
          requestId: redirect.requestId,
          tabId: redirect.tabId,
          frameId: redirect.frameId,
          documentId: redirect.documentId,
          urlFingerprint: redirect.urlFingerprint,
          method: redirect.method,
          type: redirect.type,
          completedAt: redirect.timeStamp,
          expiresAt: redirect.expiresAt,
          phase: 'failed',
        });
        return;
      }
      request.currentOrigin = redirect.redirectOrigin;
      request.currentSite = redirect.redirectSite;
      request.currentUrlFingerprint = redirect.redirectUrlFingerprint;
      request.redirectCount += 1;
      request.phase = 'redirected';
    });
  }

  async observeCompleted(input: AutofillSaveCaptureCompletedRequest): Promise<void> {
    const completed = await parseCompletedRequest(input, this.#networkTtlMs);
    return this.#mutate(async (state) => {
      const request = state.requests.find((candidate) => candidate.requestId === completed.requestId);
      const phase = completed.statusCode >= 200 && completed.statusCode < 300
        ? 'succeeded' as const
        : 'failed' as const;
      if (!request) {
        if (MUTATION_METHODS.has(completed.method)) {
          this.#upsertOutcome(state, terminalOutcome(completed, phase));
        }
        return;
      }
      request.phase = terminalMatchesRequest({
        ...completed,
        completedAt: completed.timeStamp,
        phase,
      }, request) ? phase : 'failed';
    });
  }

  async observeError(input: AutofillSaveCaptureErrorRequest): Promise<void> {
    const failed = await parseErrorRequest(input, this.#networkTtlMs);
    return this.#mutate(async (state) => {
      const request = state.requests.find((candidate) => candidate.requestId === failed.requestId);
      if (!request) {
        if (MUTATION_METHODS.has(failed.method)) {
          this.#upsertOutcome(state, terminalOutcome(failed, 'failed'));
        }
        return;
      }
      if (terminalIdentityMatches(failed, request) && failed.timeStamp >= request.startedAt) {
        request.phase = 'failed';
      } else {
        await this.#blockAll(state, failed.expiresAt);
      }
    });
  }

  reconcile(): Promise<void> {
    return this.#mutate(async () => {});
  }

  clearTab(tabIdInput: number): Promise<void> {
    const tabId = nonNegativeInteger(tabIdInput, 'tabId');
    return this.#mutate(async (state) => {
      const captures = state.captures.filter((capture) => capture.binding.tabId === tabId);
      for (const capture of captures) await this.#captures.discardCapture(capture.binding.captureId);
      state.captures = state.captures.filter((capture) => capture.binding.tabId !== tabId);
      state.requests = state.requests.filter((request) => request.tabId !== tabId);
      state.outcomes = state.outcomes.filter((outcome) => outcome.tabId !== tabId);
    });
  }

  discardUnconfirmedDocument(tabIdInput: number, frameIdInput: number, documentIdInput: string): Promise<void> {
    const tabId = nonNegativeInteger(tabIdInput, 'tabId');
    const frameId = nonNegativeInteger(frameIdInput, 'frameId');
    const documentId = opaqueId(documentIdInput, 'documentId', MAX_DOCUMENT_ID_LENGTH);
    return this.#mutate(async (state) => {
      for (const capture of [...state.captures]) {
        if (capture.phase === 'unconfirmed'
            && capture.binding.tabId === tabId
            && capture.binding.frameId === frameId
            && capture.binding.documentId === documentId) {
          await this.#discardCapture(state, capture);
        }
      }
    });
  }

  invalidateNetworkWindow(timeStampInput: number): Promise<void> {
    const timeStamp = timestamp(timeStampInput, 'timeStamp');
    return this.#mutate((state) => this.#blockAll(
      state,
      safeDeadline(timeStamp, this.#networkTtlMs),
    ));
  }

  clear(): Promise<void> {
    return this.#serialize(async () => {
      const state = await this.#read();
      for (const capture of state.captures) {
        await this.#captures.discardCapture(capture.binding.captureId);
      }
      for (const orphan of await this.#captures.listUnconfirmed()) {
        await this.#captures.discardCapture(orphan.captureId);
      }
      const empty = emptyJournal(Math.max(state.revision, this.#highWaterRevision));
      await this.#write(empty);
      this.#reschedule(empty);
    });
  }

  #mutate(mutation: (state: JournalState) => void | Promise<void>): Promise<void> {
    return this.#serialize(async () => {
      const state = await this.#read();
      await this.#reconcileCaptureStore(state);
      await mutation(state);
      await this.#evaluate(state);
      await this.#write(state);
      await this.#notifyConfirmed(state);
      await this.#write(state);
      this.#reschedule(state);
    });
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.#tail.then(operation, operation);
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async #read(): Promise<JournalState> {
    const now = this.#time();
    const raw = await this.#store.get<unknown>(this.#storageKey);
    if (raw === undefined) return emptyJournal(this.#highWaterRevision);
    const parsed = parseJournal(raw, now, this.#maxRequests);
    if (!parsed) {
      return {
        ...emptyJournal(this.#highWaterRevision),
        blockedUntil: safeDeadline(now, this.#networkTtlMs),
      };
    }
    this.#highWaterRevision = Math.max(this.#highWaterRevision, parsed.revision);
    return parsed;
  }

  async #write(state: JournalState): Promise<void> {
    const revision = Math.max(state.revision, this.#highWaterRevision);
    if (!Number.isSafeInteger(revision) || revision >= Number.MAX_SAFE_INTEGER) {
      throw new Error('Save-capture journal revision is exhausted');
    }
    const envelope: StoredJournal = Object.freeze({
      schemaVersion: AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION,
      revision: revision + 1,
      blockedUntil: state.blockedUntil,
      captures: Object.freeze(state.captures.map(freezeCaptureRecord)),
      requests: Object.freeze(state.requests.map(freezeRequestRecord)),
      outcomes: Object.freeze(state.outcomes.map((outcome) => Object.freeze({ ...outcome }))),
    });
    if (utf8Size(this.#storageKey, envelope) > this.#maxJournalBytes) {
      await this.#blockAll(state, safeDeadline(this.#time(), this.#networkTtlMs));
      const blockedEnvelope: StoredJournal = Object.freeze({
        schemaVersion: AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION,
        revision: revision + 1,
        blockedUntil: state.blockedUntil,
        captures: Object.freeze([]),
        requests: Object.freeze([]),
        outcomes: Object.freeze([]),
      });
      await this.#store.set(this.#storageKey, blockedEnvelope);
      state.revision = blockedEnvelope.revision;
      this.#highWaterRevision = blockedEnvelope.revision;
      throw new Error('Save-capture journal capacity was exceeded');
    }
    await this.#store.set(this.#storageKey, envelope);
    state.revision = envelope.revision;
    this.#highWaterRevision = envelope.revision;
  }

  async #reconcileCaptureStore(state: JournalState): Promise<void> {
    const journalIds = new Set(state.captures.map((capture) => capture.binding.captureId));
    for (const orphan of await this.#captures.listUnconfirmed()) {
      if (!journalIds.has(orphan.captureId)) await this.#captures.discardCapture(orphan.captureId);
    }
    for (let index = state.captures.length - 1; index >= 0; index -= 1) {
      const capture = state.captures[index]!;
      const metadata = await this.#captures.captureMetadata(capture.binding.captureId);
      if (!metadata || !await captureBindingMatches(capture.binding, metadata)) {
        if (metadata) await this.#captures.discardCapture(capture.binding.captureId);
        state.captures.splice(index, 1);
        continue;
      }
      capture.metadata = metadata;
      const captureState = await this.#captures.captureState(capture.binding.captureId);
      if (captureState === undefined) state.captures.splice(index, 1);
      else capture.phase = captureState;
    }
  }

  async #evaluate(state: JournalState): Promise<void> {
    const now = this.#time();
    state.requests = state.requests.filter((request) => request.expiresAt > now);
    state.outcomes = state.outcomes.filter((outcome) => outcome.expiresAt > now);
    state.captures = state.captures.filter((capture) => capture.binding.expiresAt > now);
    if (state.blockedUntil > now) {
      for (const capture of state.captures.filter((candidate) => candidate.phase === 'unconfirmed')) {
        await this.#discardCapture(state, capture);
      }
      return;
    }
    if (state.blockedUntil !== 0) state.blockedUntil = 0;

    const activeCaptures = state.captures.filter((capture) => capture.phase === 'unconfirmed');
    const matches = new Map<CaptureRecord, RequestRecord[]>();
    const reverse = new Map<RequestRecord, CaptureRecord[]>();
    for (const capture of activeCaptures) {
      const candidates = state.requests.filter((request) => this.#requestMatches(capture, request));
      matches.set(capture, candidates);
      for (const request of candidates) {
        const owners = reverse.get(request) ?? [];
        owners.push(capture);
        reverse.set(request, owners);
      }
    }

    for (const capture of [...activeCaptures]) {
      if (!state.captures.includes(capture)) continue;
      const candidates = matches.get(capture) ?? [];
      if (candidates.some((request) => request.phase === 'failed')
          || candidates.length > 1
          || candidates.some((request) => (reverse.get(request)?.length ?? 0) > 1)) {
        await this.#discardCapture(state, capture);
        continue;
      }
      const [request] = candidates;
      if (!request || request.phase !== 'succeeded') continue;
      if (now < safeDeadline(capture.binding.createdAt, this.#afterWindowMs)) continue;
      await this.#confirmCapture(capture);
    }
  }

  #requestMatches(capture: CaptureRecord, request: RequestRecord): boolean {
    const binding = capture.binding;
    if (request.tabId !== binding.tabId
        || request.frameId !== binding.frameId
        || request.documentId !== binding.documentId
        || request.documentOrigin !== binding.sourceOrigin
        || request.documentSite !== binding.sourceSite
        || request.documentUrlFingerprint !== binding.sourceUrlFingerprint
        || request.startedAt < binding.createdAt - this.#beforeWindowMs
        || request.startedAt > binding.createdAt + this.#afterWindowMs
        || !sameSiteBinding(
          binding.sourceOrigin,
          binding.sourceSite,
          request.initialOrigin,
          request.initialSite,
        )) return false;
    if (capture.submission.kind === 'native') {
      return request.method === capture.submission.method
        && request.initialOrigin === capture.submission.actionOrigin
        && request.initialSite === capture.submission.actionSite
        && request.initialUrlFingerprint === capture.submission.actionUrlFingerprint;
    }
    return request.type === 'xmlhttprequest';
  }

  async #confirmCapture(capture: CaptureRecord): Promise<void> {
    const metadata = capture.metadata;
    if (!metadata) return;
    let key: SymmetricKey | undefined;
    try {
      this.#assertCurrent(metadata);
      key = await this.#loadUserKey(metadata);
      this.#assertCurrent(metadata);
      if (!key) return;
      const confirmed = await this.#captures.confirmUnconfirmed(metadata, key);
      key = undefined;
      this.#assertCurrent(metadata);
      if (confirmed || await this.#captures.captureState(capture.binding.captureId) === 'confirmed') {
        capture.phase = 'confirmed';
      }
    } catch {
      zeroOwnedUserKey(key);
    }
  }

  async #discardCapture(state: JournalState, capture: CaptureRecord): Promise<void> {
    await this.#captures.discardCapture(capture.binding.captureId);
    const index = state.captures.indexOf(capture);
    if (index >= 0) state.captures.splice(index, 1);
  }

  async #notifyConfirmed(state: JournalState): Promise<void> {
    for (const capture of [...state.captures]) {
      if (capture.phase !== 'confirmed') continue;
      const metadata = capture.metadata;
      if (!metadata) continue;
      try {
        this.#assertCurrent(metadata);
      } catch {
        await this.#discardCapture(state, capture);
        continue;
      }
      try {
        await this.#onConfirmed(metadata);
        const index = state.captures.indexOf(capture);
        if (index >= 0) state.captures.splice(index, 1);
      } catch {
        // A durable confirmed capture remains claimable; retry only the non-secret notification.
      }
    }
  }

  #upsertOutcome(state: JournalState, outcome: TerminalOutcome): void {
    const existing = state.outcomes.find((candidate) => candidate.requestId === outcome.requestId);
    if (existing) {
      if (!sameTerminalOutcome(existing, outcome)) {
        state.blockedUntil = Math.max(state.blockedUntil, outcome.expiresAt);
      }
      return;
    }
    if (state.outcomes.length >= this.#maxRequests) {
      state.blockedUntil = Math.max(state.blockedUntil, outcome.expiresAt);
      state.requests = [];
      state.outcomes = [];
      return;
    }
    state.outcomes.push(outcome);
  }

  async #blockAll(state: JournalState, until: number): Promise<void> {
    state.blockedUntil = Math.max(state.blockedUntil, until);
    state.requests = [];
    state.outcomes = [];
    for (const capture of [...state.captures]) await this.#discardCapture(state, capture);
  }

  #reschedule(state: JournalState): void {
    const now = this.#time();
    const candidates: number[] = [];
    if (state.blockedUntil > now) candidates.push(state.blockedUntil);
    for (const capture of state.captures) {
      candidates.push(capture.binding.expiresAt);
      if (capture.phase === 'confirmed') candidates.push(safeDeadline(now, CONFIRMED_NOTIFICATION_RETRY_MS));
      else {
        const closesAt = safeDeadline(capture.binding.createdAt, this.#afterWindowMs);
        if (closesAt > now) candidates.push(closesAt);
      }
    }
    for (const request of state.requests) candidates.push(request.expiresAt);
    for (const outcome of state.outcomes) candidates.push(outcome.expiresAt);
    const next = candidates.filter((value) => value > now).sort((left, right) => left - right)[0];
    try {
      if (next === undefined) void Promise.resolve(this.#scheduler.cancel()).catch(() => undefined);
      else void Promise.resolve(this.#scheduler.schedule(next)).catch(() => undefined);
    } catch {
      // Alarm failures reduce availability but never make an unconfirmed capture claimable.
    }
  }

  #time(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Save-capture clock is invalid');
    return now;
  }
}

async function createCaptureRecord(
  metadata: AutofillUnconfirmedSaveMetadata,
  submission: AutofillSaveCaptureSubmission,
): Promise<CaptureRecord> {
  const source = await documentUrlBinding(metadata.sourceUrl);
  let storedSubmission: StoredSubmission;
  if (submission.kind === 'formless') {
    storedSubmission = Object.freeze({ kind: 'formless' });
  } else {
    const action = await requestUrlBinding(submission.actionUrl, 'actionUrl');
    storedSubmission = Object.freeze({
      kind: 'native',
      actionOrigin: action.origin,
      actionSite: action.site,
      actionUrlFingerprint: action.fingerprint,
      method: submission.method,
    });
  }
  return {
    binding: Object.freeze({
      captureId: metadata.captureId,
      tabId: metadata.tabId,
      frameId: metadata.frameId,
      documentId: metadata.sourceDocumentId,
      sourceOrigin: source.documentOrigin,
      sourceSite: source.documentSite,
      sourceUrlFingerprint: source.documentUrlFingerprint,
      createdAt: metadata.createdAt,
      expiresAt: metadata.expiresAt,
    }),
    submission: storedSubmission,
    phase: 'unconfirmed',
    metadata,
  };
}

async function captureBindingMatches(
  binding: CaptureBinding,
  metadata: AutofillUnconfirmedSaveMetadata,
): Promise<boolean> {
  const source = await documentUrlBinding(metadata.sourceUrl);
  return binding.captureId === metadata.captureId
    && binding.tabId === metadata.tabId
    && binding.frameId === metadata.frameId
    && binding.documentId === metadata.sourceDocumentId
    && binding.sourceOrigin === metadata.origin
    && binding.sourceOrigin === source.documentOrigin
    && binding.sourceSite === source.documentSite
    && binding.sourceUrlFingerprint === source.documentUrlFingerprint
    && binding.createdAt === metadata.createdAt
    && binding.expiresAt === metadata.expiresAt;
}

function parseSubmission(value: unknown): AutofillSaveCaptureSubmission {
  if (!isPlainRecord(value)) throw new TypeError('Save-capture submission is invalid');
  if (dataValue(value, 'kind') === 'formless' && hasExactDataKeys(value, ['kind'])) {
    return Object.freeze({ kind: 'formless' });
  }
  if (dataValue(value, 'kind') !== 'native'
      || !hasExactDataKeys(value, ['kind', 'actionUrl', 'method'])) {
    throw new TypeError('Save-capture submission is invalid');
  }
  const method = mutationMethod(dataValue(value, 'method'));
  return Object.freeze({
    kind: 'native',
    actionUrl: canonicalRequestUrl(dataValue(value, 'actionUrl'), 'actionUrl'),
    method,
  });
}

async function parseBeforeRequest(value: unknown, ttlMs: number): Promise<RequestRecord> {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId', 'sourceDocumentUrl', 'initiator',
    'url', 'method', 'type', 'timeStamp',
  ], 'before-request');
  const tabId = nonNegativeInteger(dataValue(record, 'tabId'), 'tabId');
  const frameId = nonNegativeInteger(dataValue(record, 'frameId'), 'frameId');
  const type = dataValue(record, 'type');
  if (typeof type !== 'string' || !REQUEST_TYPES.has(type)
      || (type === 'main_frame' && frameId !== 0)
      || (type === 'sub_frame' && frameId === 0)) {
    throw new TypeError('Save-capture request type is invalid');
  }
  const startedAt = timestamp(dataValue(record, 'timeStamp'), 'timeStamp');
  const documentUrl = canonicalRequestUrl(
    dataValue(record, 'sourceDocumentUrl'),
    'sourceDocumentUrl',
  );
  const initiator = canonicalOrigin(dataValue(record, 'initiator'));
  if (new URL(documentUrl).origin !== initiator) {
    throw new TypeError('Save-capture initiator does not own the document URL');
  }
  const url = canonicalRequestUrl(dataValue(record, 'url'), 'url');
  const documentBinding = await documentUrlBinding(documentUrl);
  const requestBinding = await requestUrlBinding(url, 'url');
  return {
    requestId: opaqueId(dataValue(record, 'requestId'), 'requestId', MAX_REQUEST_ID_LENGTH),
    tabId,
    frameId,
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    documentOrigin: documentBinding.documentOrigin,
    documentSite: documentBinding.documentSite,
    documentUrlFingerprint: documentBinding.documentUrlFingerprint,
    initialOrigin: requestBinding.origin,
    initialSite: requestBinding.site,
    initialUrlFingerprint: requestBinding.fingerprint,
    currentOrigin: requestBinding.origin,
    currentSite: requestBinding.site,
    currentUrlFingerprint: requestBinding.fingerprint,
    method: mutationMethod(dataValue(record, 'method')),
    type: type as RequestRecord['type'],
    startedAt,
    expiresAt: safeDeadline(startedAt, ttlMs),
    phase: 'started',
    redirectCount: 0,
  };
}

async function parseCompletedRequest(
  value: unknown,
  ttlMs: number,
): Promise<PreparedTerminal & { readonly statusCode: number }> {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId', 'url', 'method', 'type',
    'statusCode', 'timeStamp',
  ], 'completed request');
  const timeStamp = timestamp(dataValue(record, 'timeStamp'), 'timeStamp');
  const statusCode = dataValue(record, 'statusCode');
  if (!Number.isSafeInteger(statusCode) || (statusCode as number) < 100 || (statusCode as number) > 599) {
    throw new TypeError('Save-capture statusCode is invalid');
  }
  return Object.freeze({
    ...terminalIdentityWithoutUrl(record),
    ...terminalTransport(record),
    urlFingerprint: await urlFingerprint(
      canonicalRequestUrl(dataValue(record, 'url'), 'url'),
      REQUEST_URL_FINGERPRINT_DOMAIN,
    ),
    statusCode: statusCode as number,
    timeStamp,
    expiresAt: safeDeadline(timeStamp, ttlMs),
  });
}

async function parseRedirectRequest(
  value: unknown,
  ttlMs: number,
): Promise<PreparedRedirect> {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId', 'url', 'redirectUrl',
    'method', 'type', 'statusCode', 'timeStamp',
  ], 'redirect request');
  const timeStamp = timestamp(dataValue(record, 'timeStamp'), 'timeStamp');
  const statusCode = dataValue(record, 'statusCode');
  if (!Number.isSafeInteger(statusCode) || (statusCode as number) < 300 || (statusCode as number) >= 400) {
    throw new TypeError('Save-capture redirect statusCode is invalid');
  }
  const url = canonicalRequestUrl(dataValue(record, 'url'), 'url');
  const redirectUrl = canonicalRequestUrl(dataValue(record, 'redirectUrl'), 'redirectUrl');
  const redirectBinding = await requestUrlBinding(redirectUrl, 'redirectUrl');
  return Object.freeze({
    ...terminalIdentityWithoutUrl(record),
    ...terminalTransport(record),
    urlFingerprint: await urlFingerprint(url, REQUEST_URL_FINGERPRINT_DOMAIN),
    redirectOrigin: redirectBinding.origin,
    redirectSite: redirectBinding.site,
    redirectUrlFingerprint: redirectBinding.fingerprint,
    timeStamp,
    expiresAt: safeDeadline(timeStamp, ttlMs),
  });
}

async function parseErrorRequest(
  value: unknown,
  ttlMs: number,
): Promise<PreparedTerminal> {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId', 'url', 'method', 'type', 'timeStamp',
  ], 'failed request');
  const timeStamp = timestamp(dataValue(record, 'timeStamp'), 'timeStamp');
  return Object.freeze({
    ...terminalIdentityWithoutUrl(record),
    ...terminalTransport(record),
    urlFingerprint: await urlFingerprint(
      canonicalRequestUrl(dataValue(record, 'url'), 'url'),
      REQUEST_URL_FINGERPRINT_DOMAIN,
    ),
    timeStamp,
    expiresAt: safeDeadline(timeStamp, ttlMs),
  });
}

function terminalIdentityWithoutUrl(record: Record<string, unknown>) {
  return {
    requestId: opaqueId(dataValue(record, 'requestId'), 'requestId', MAX_REQUEST_ID_LENGTH),
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
  };
}

function terminalTransport(record: Record<string, unknown>): {
  readonly method: string;
  readonly type: 'main_frame' | 'sub_frame' | 'xmlhttprequest';
} {
  const method = boundedString(dataValue(record, 'method'), 32, 'method').toUpperCase();
  if (!/^[A-Z]+$/u.test(method)) throw new TypeError('Save-capture terminal method is invalid');
  const type = dataValue(record, 'type');
  if (typeof type !== 'string' || !REQUEST_TYPES.has(type)) {
    throw new TypeError('Save-capture terminal type is invalid');
  }
  return { method, type: type as 'main_frame' | 'sub_frame' | 'xmlhttprequest' };
}

function terminalOutcome(
  input: PreparedTerminal,
  phase: 'succeeded' | 'failed',
): TerminalOutcome {
  return {
    requestId: input.requestId,
    tabId: input.tabId,
    frameId: input.frameId,
    documentId: input.documentId,
    urlFingerprint: input.urlFingerprint,
    method: input.method,
    type: input.type,
    completedAt: input.timeStamp,
    expiresAt: input.expiresAt,
    phase,
  };
}

function terminalIdentityMatches(
  terminal: Pick<TerminalOutcome, 'requestId' | 'tabId' | 'frameId' | 'documentId'>,
  request: RequestRecord,
): boolean {
  return terminal.requestId === request.requestId
    && terminal.tabId === request.tabId
    && terminal.frameId === request.frameId
    && (request.type !== 'xmlhttprequest' || terminal.documentId === request.documentId);
}

function terminalMatchesRequest(outcome: TerminalOutcome, request: RequestRecord): boolean {
  return terminalIdentityMatches(outcome, request)
    && outcome.urlFingerprint === request.currentUrlFingerprint
    && outcome.type === request.type
    && (request.redirectCount === 0
      ? outcome.method === request.method
      : outcome.method === request.method || outcome.method === 'GET')
    && outcome.completedAt >= request.startedAt;
}

function sameStartedRequest(left: RequestRecord, right: RequestRecord): boolean {
  return left.requestId === right.requestId
    && left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.documentOrigin === right.documentOrigin
    && left.documentSite === right.documentSite
    && left.documentUrlFingerprint === right.documentUrlFingerprint
    && left.initialOrigin === right.initialOrigin
    && left.initialSite === right.initialSite
    && left.initialUrlFingerprint === right.initialUrlFingerprint
    && left.method === right.method
    && left.type === right.type
    && left.startedAt === right.startedAt;
}

function sameTerminalOutcome(left: TerminalOutcome, right: TerminalOutcome): boolean {
  return left.requestId === right.requestId
    && left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.urlFingerprint === right.urlFingerprint
    && left.method === right.method
    && left.type === right.type
    && left.completedAt === right.completedAt
    && left.phase === right.phase;
}

function sameCaptureSlot(
  left: CaptureBinding,
  right: CaptureBinding,
): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.sourceUrlFingerprint === right.sourceUrlFingerprint;
}

function sameSiteBinding(
  leftOrigin: string,
  leftSite: string,
  rightOrigin: string,
  rightSite: string,
): boolean {
  if (leftOrigin === rightOrigin) return true;
  return new URL(leftOrigin).protocol === new URL(rightOrigin).protocol && leftSite === rightSite;
}

async function documentUrlBinding(value: string): Promise<{
  readonly documentOrigin: string;
  readonly documentSite: string;
  readonly documentUrlFingerprint: string;
}> {
  const url = canonicalRequestUrl(value, 'documentUrl');
  const origin = new URL(url).origin;
  return Object.freeze({
    documentOrigin: origin,
    documentSite: siteForUrl(url),
    documentUrlFingerprint: await urlFingerprint(url, DOCUMENT_URL_FINGERPRINT_DOMAIN),
  });
}

async function requestUrlBinding(value: string, name: string): Promise<{
  readonly origin: string;
  readonly site: string;
  readonly fingerprint: string;
}> {
  const url = canonicalRequestUrl(value, name);
  return Object.freeze({
    origin: new URL(url).origin,
    site: siteForUrl(url),
    fingerprint: await urlFingerprint(url, REQUEST_URL_FINGERPRINT_DOMAIN),
  });
}

function siteForUrl(value: string): string {
  const hostname = new URL(value).hostname;
  const site = getBaseDomain(hostname);
  if (!site) throw new TypeError('Save-capture URL site is invalid');
  return site;
}

async function urlFingerprint(value: string, domain: string): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify([domain, canonicalRequestUrl(value, 'URL')]));
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', payload as BufferSource));
    try {
      return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    } finally {
      digest.fill(0);
    }
  } finally {
    payload.fill(0);
  }
}

function parseJournal(value: unknown, now: number, capacity: number): ParsedJournal | undefined {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, [
    'schemaVersion', 'revision', 'blockedUntil', 'captures', 'requests', 'outcomes',
  ])) return undefined;
  if (dataValue(value, 'schemaVersion') !== AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION) return undefined;
  const revision = dataValue(value, 'revision');
  const blockedUntil = dataValue(value, 'blockedUntil');
  const rawCaptures = dataValue(value, 'captures');
  const rawRequests = dataValue(value, 'requests');
  const rawOutcomes = dataValue(value, 'outcomes');
  if (!Number.isSafeInteger(revision) || (revision as number) < 0
      || !Number.isSafeInteger(blockedUntil) || (blockedUntil as number) < 0
      || !Array.isArray(rawCaptures) || !denseArray(rawCaptures) || rawCaptures.length > capacity
      || !Array.isArray(rawRequests) || !denseArray(rawRequests) || rawRequests.length > capacity
      || !Array.isArray(rawOutcomes) || !denseArray(rawOutcomes) || rawOutcomes.length > capacity) return undefined;
  try {
    const captures = rawCaptures.map(parseCaptureRecord);
    const requests = rawRequests.map(parseStoredRequest);
    const outcomes = rawOutcomes.map(parseStoredOutcome);
    if (new Set(captures.map((capture) => capture.binding.captureId)).size !== captures.length
        || new Set(requests.map((request) => request.requestId)).size !== requests.length
        || new Set(outcomes.map((outcome) => outcome.requestId)).size !== outcomes.length) return undefined;
    return {
      revision: revision as number,
      blockedUntil: blockedUntil as number,
      captures: captures.filter((capture) => capture.binding.expiresAt > now),
      requests: requests.filter((request) => request.expiresAt > now),
      outcomes: outcomes.filter((outcome) => outcome.expiresAt > now),
      dirty: captures.some((capture) => capture.binding.expiresAt <= now)
        || requests.some((request) => request.expiresAt <= now)
        || outcomes.some((outcome) => outcome.expiresAt <= now),
    };
  } catch {
    return undefined;
  }
}

function parseCaptureRecord(value: unknown): CaptureRecord {
  const record = strictRecord(value, ['binding', 'submission', 'phase'], 'capture record');
  const binding = parseCaptureBinding(dataValue(record, 'binding'));
  const phase = dataValue(record, 'phase');
  if (phase !== 'unconfirmed' && phase !== 'confirmed') {
    throw new TypeError('Save-capture phase is invalid');
  }
  return { binding, submission: parseStoredSubmission(dataValue(record, 'submission')), phase };
}

function parseCaptureBinding(value: unknown): CaptureBinding {
  const record = strictRecord(value, [
    'captureId', 'tabId', 'frameId', 'documentId', 'sourceOrigin', 'sourceSite',
    'sourceUrlFingerprint', 'createdAt', 'expiresAt',
  ], 'capture binding');
  const sourceOrigin = canonicalOrigin(dataValue(record, 'sourceOrigin'));
  const sourceSite = site(dataValue(record, 'sourceSite'), 'sourceSite');
  if (!siteMatchesOrigin(sourceSite, sourceOrigin)) throw new TypeError('Capture site is invalid');
  const createdAt = timestamp(dataValue(record, 'createdAt'), 'createdAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  if (expiresAt <= createdAt || expiresAt - createdAt > MAX_AUTOFILL_PENDING_SAVE_TTL_MS) {
    throw new TypeError('Capture expiry is invalid');
  }
  return Object.freeze({
    captureId: uuid(dataValue(record, 'captureId'), 'captureId'),
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(record, 'frameId'), 'frameId'),
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    sourceOrigin,
    sourceSite,
    sourceUrlFingerprint: fingerprint(dataValue(record, 'sourceUrlFingerprint')),
    createdAt,
    expiresAt,
  });
}

function parseStoredSubmission(value: unknown): StoredSubmission {
  if (!isPlainRecord(value)) throw new TypeError('Stored submission is invalid');
  if (dataValue(value, 'kind') === 'formless' && hasExactDataKeys(value, ['kind'])) {
    return Object.freeze({ kind: 'formless' });
  }
  const record = strictRecord(value, [
    'kind', 'actionOrigin', 'actionSite', 'actionUrlFingerprint', 'method',
  ], 'stored native submission');
  if (dataValue(record, 'kind') !== 'native') throw new TypeError('Stored submission kind is invalid');
  const actionOrigin = canonicalOrigin(dataValue(record, 'actionOrigin'));
  const actionSite = site(dataValue(record, 'actionSite'), 'actionSite');
  if (!siteMatchesOrigin(actionSite, actionOrigin)) throw new TypeError('Stored action site is invalid');
  return Object.freeze({
    kind: 'native',
    actionOrigin,
    actionSite,
    actionUrlFingerprint: fingerprint(dataValue(record, 'actionUrlFingerprint')),
    method: mutationMethod(dataValue(record, 'method')),
  });
}

function parseStoredRequest(value: unknown): RequestRecord {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId',
    'documentOrigin', 'documentSite', 'documentUrlFingerprint',
    'initialOrigin', 'initialSite', 'initialUrlFingerprint',
    'currentOrigin', 'currentSite', 'currentUrlFingerprint',
    'method', 'type', 'startedAt', 'expiresAt', 'phase', 'redirectCount',
  ], 'request record');
  const startedAt = timestamp(dataValue(record, 'startedAt'), 'startedAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  const redirectCount = dataValue(record, 'redirectCount');
  const phase = dataValue(record, 'phase');
  const type = dataValue(record, 'type');
  if (expiresAt <= startedAt
      || !Number.isSafeInteger(redirectCount) || (redirectCount as number) < 0 || (redirectCount as number) > MAX_REDIRECTS
      || (phase !== 'started' && phase !== 'redirected' && phase !== 'succeeded' && phase !== 'failed')
      || typeof type !== 'string' || !REQUEST_TYPES.has(type)) throw new TypeError('Request record is invalid');
  const documentOrigin = canonicalOrigin(dataValue(record, 'documentOrigin'));
  const documentSite = site(dataValue(record, 'documentSite'), 'documentSite');
  const initialOrigin = canonicalOrigin(dataValue(record, 'initialOrigin'));
  const initialSite = site(dataValue(record, 'initialSite'), 'initialSite');
  const currentOrigin = canonicalOrigin(dataValue(record, 'currentOrigin'));
  const currentSite = site(dataValue(record, 'currentSite'), 'currentSite');
  const frameId = nonNegativeInteger(dataValue(record, 'frameId'), 'frameId');
  if (!siteMatchesOrigin(documentSite, documentOrigin)
      || !siteMatchesOrigin(initialSite, initialOrigin)
      || !siteMatchesOrigin(currentSite, currentOrigin)
      || !sameSiteBinding(documentOrigin, documentSite, initialOrigin, initialSite)
      || !sameSiteBinding(documentOrigin, documentSite, currentOrigin, currentSite)
      || expiresAt - startedAt > 5 * 60_000
      || (type === 'main_frame' && frameId !== 0)
      || (type === 'sub_frame' && frameId === 0)
      || (phase === 'redirected' && redirectCount === 0)) {
    throw new TypeError('Request record binding is invalid');
  }
  return {
    requestId: opaqueId(dataValue(record, 'requestId'), 'requestId', MAX_REQUEST_ID_LENGTH),
    tabId: nonNegativeInteger(dataValue(record, 'tabId'), 'tabId'),
    frameId,
    documentId: opaqueId(dataValue(record, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    documentOrigin,
    documentSite,
    documentUrlFingerprint: fingerprint(dataValue(record, 'documentUrlFingerprint')),
    initialOrigin,
    initialSite,
    initialUrlFingerprint: fingerprint(dataValue(record, 'initialUrlFingerprint')),
    currentOrigin,
    currentSite,
    currentUrlFingerprint: fingerprint(dataValue(record, 'currentUrlFingerprint')),
    method: mutationMethod(dataValue(record, 'method')),
    type: type as RequestRecord['type'],
    startedAt,
    expiresAt,
    phase,
    redirectCount: redirectCount as number,
  };
}

function parseStoredOutcome(value: unknown): TerminalOutcome {
  const record = strictRecord(value, [
    'requestId', 'tabId', 'frameId', 'documentId', 'urlFingerprint',
    'method', 'type', 'completedAt', 'expiresAt', 'phase',
  ], 'terminal outcome');
  const phase = dataValue(record, 'phase');
  const completedAt = timestamp(dataValue(record, 'completedAt'), 'completedAt');
  const expiresAt = timestamp(dataValue(record, 'expiresAt'), 'expiresAt');
  if ((phase !== 'succeeded' && phase !== 'failed') || expiresAt <= completedAt) {
    throw new TypeError('Terminal outcome is invalid');
  }
  return {
    ...terminalIdentityWithoutUrl(record),
    ...terminalTransport(record),
    urlFingerprint: fingerprint(dataValue(record, 'urlFingerprint')),
    completedAt,
    expiresAt,
    phase,
  };
}

function freezeCaptureRecord(record: CaptureRecord): CaptureRecord {
  return Object.freeze({
    binding: Object.freeze({ ...record.binding }),
    submission: Object.freeze({ ...record.submission }),
    phase: record.phase,
  });
}

function freezeRequestRecord(record: RequestRecord): RequestRecord {
  return Object.freeze({ ...record });
}

function emptyJournal(revision: number): JournalState {
  return { revision, blockedUntil: 0, captures: [], requests: [], outcomes: [] };
}

function canonicalRequestUrl(value: unknown, name: string, preserveFragment = false): string {
  if (typeof value !== 'string' || !value || value.length > MAX_URL_LENGTH
      || value.trim() !== value || hasControl(value)) throw new TypeError(`Save-capture ${name} is invalid`);
  let url: URL;
  try { url = new URL(value); } catch { throw new TypeError(`Save-capture ${name} is invalid`); }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
    throw new TypeError(`Save-capture ${name} is invalid`);
  }
  if (!preserveFragment) url.hash = '';
  return url.href;
}

function canonicalOrigin(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > MAX_URL_LENGTH
      || value.trim() !== value || hasControl(value)) throw new TypeError('Save-capture origin is invalid');
  let url: URL;
  try { url = new URL(value); } catch { throw new TypeError('Save-capture origin is invalid'); }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.origin !== value) {
    throw new TypeError('Save-capture origin is invalid');
  }
  return url.origin;
}

function site(value: unknown, name: string): string {
  return boundedString(value, 253, name).toLowerCase();
}

function fingerprint(value: unknown): string {
  if (typeof value !== 'string' || !URL_FINGERPRINT_PATTERN.test(value)) {
    throw new TypeError('Save-capture URL fingerprint is invalid');
  }
  return value;
}

function siteMatchesOrigin(siteValue: string, origin: string): boolean {
  return getBaseDomain(new URL(origin).hostname) === siteValue;
}

function mutationMethod(value: unknown): 'POST' | 'PUT' | 'PATCH' {
  if (typeof value !== 'string') throw new TypeError('Save-capture method is invalid');
  const method = value.toUpperCase();
  if (!MUTATION_METHODS.has(method)) throw new TypeError('Save-capture method is invalid');
  return method as 'POST' | 'PUT' | 'PATCH';
}

function strictRecord(value: unknown, keys: readonly string[], name: string): Record<string, unknown> {
  if (!isPlainRecord(value) || !hasExactDataKeys(value, keys)) {
    throw new TypeError(`Save-capture ${name} is invalid`);
  }
  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactDataKeys(record: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedSet = new Set(expected);
  return keys.every((key) => expectedSet.has(key as string)) && expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function dataValue(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function denseArray(values: unknown[]): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (!Object.hasOwn(values, index)) return false;
  }
  return true;
}

function uuid(value: unknown, name: string): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) {
    throw new TypeError(`Save-capture ${name} is invalid`);
  }
  return value;
}

function opaqueId(value: unknown, name: string, maximum: number): string {
  return boundedString(value, maximum, name);
}

function boundedString(value: unknown, maximum: number, name: string): string {
  if (typeof value !== 'string' || !value || value.length > maximum
      || value.trim() !== value || hasControl(value)) {
    throw new TypeError(`Save-capture ${name} is invalid`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`Save-capture ${name} is invalid`);
  }
  return value as number;
}

function timestamp(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new TypeError(`Save-capture ${name} is invalid`);
  }
  return Math.trunc(value);
}

function boundedPositiveInteger(value: number, maximum: number, name: string, minimum = 1): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`Save-capture ${name} is invalid`);
  }
  return value;
}

function safeDeadline(start: number, duration: number): number {
  const deadline = start + duration;
  return Number.isSafeInteger(deadline) ? deadline : Number.MAX_SAFE_INTEGER;
}

function hasControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function utf8Size(storageKey: string, value: unknown): number {
  return new TextEncoder().encode(storageKey).byteLength
    + new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function zeroOwnedUserKey(key: SymmetricKey | undefined): void {
  try { key?.encKey.fill(0); } catch { /* best effort */ }
  try { key?.macKey.fill(0); } catch { /* best effort */ }
}
